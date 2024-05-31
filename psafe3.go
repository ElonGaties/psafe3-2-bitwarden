package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"os"
	"time"

	"github.com/gofrs/uuid/v5"
	"golang.org/x/crypto/twofish"
)

type Cipher struct {
	Block1     [16]byte
	Block2     [16]byte
	Block3     [16]byte
	Block4     [16]byte
	InitialVec [16]byte
}

type Header struct {
	Magic  [4]byte
	Salt   [32]byte
	Iter   uint32
	Hash   [32]byte
	Cipher Cipher
}

type Vault struct {
	Header    Header
	Records   []Record
	reader    *bytes.Reader
	checker   hash.Hash
	decryptor cipher.BlockMode
}

type Record struct {
	uuid         uuid.UUID
	group        string
	title        string
	user         string
	notes        string
	password     string
	lastModified time.Time
	url          string
}

type Field struct {
	rawLength uint32
	rawType   byte
	rawValue  []byte
}

func VaultFromFile(inputFile string, password string) (*Vault, error) {
	var vault Vault

	data, err := os.ReadFile(inputFile)
	if err != nil {
		return nil, err
	}

	vault.reader = bytes.NewReader(data)

	binary.Read(vault.reader, binary.LittleEndian, &vault.Header)

	if err = vault.validateMagic(); err != nil {
		return nil, err
	}
	streched_key, err := vault.validatePassword(password)
	if err != nil {
		return nil, err
	}
	if err := vault.createDecrypterAndChecker(streched_key); err != nil {
		return nil, err
	}
	if err := vault.readRecords(); err != nil {
		return nil, err
	}
	if err := vault.validateHMAC(); err != nil {
		return nil, err
	}

	return &vault, nil
}

func (v *Vault) validateMagic() error {
	if string(v.Header.Magic[:]) != "PWS3" {
		return errors.New("psafe3: invalid magic")
	}
	return nil
}

func (v *Vault) validatePassword(password string) ([]byte, error) {
	streched_key := v.strechKey(password)

	hasher := sha256.New()
	hasher.Write(streched_key)
	hash := hasher.Sum(nil)

	if string(v.Header.Hash[:]) != string(hash) {
		return streched_key, errors.New("psafe3: invalid password")
	}

	return streched_key, nil
}

func (v *Vault) strechKey(password string) []byte {
	salt := string(v.Header.Salt[:])
	hasher := sha256.New()
	hasher.Write([]byte(password + salt))
	sum := hasher.Sum(nil)
	hasher.Reset()

	iter := int(v.Header.Iter)
	for range iter {
		hasher.Write(sum)
		sum = hasher.Sum(nil)
		hasher.Reset()
	}

	return sum
}

func (v *Vault) createDecrypterAndChecker(streched_key []byte) error {
	block, err := twofish.NewCipher(streched_key)
	if err != nil {
		return err
	}

	b1d := make([]byte, 16)
	b2d := make([]byte, 16)
	b3d := make([]byte, 16)
	b4d := make([]byte, 16)
	block.Decrypt(b1d, v.Header.Cipher.Block1[:])
	block.Decrypt(b2d, v.Header.Cipher.Block2[:])
	block.Decrypt(b3d, v.Header.Cipher.Block3[:])
	block.Decrypt(b4d, v.Header.Cipher.Block4[:])

	key_k := []byte(string(b1d) + string(b2d))
	key_l := []byte(string(b3d) + string(b4d))

	v.checker = hmac.New(sha256.New, key_l)

	block, err = twofish.NewCipher(key_k)
	if err != nil {
		return err
	}

	v.decryptor = cipher.NewCBCDecrypter(block, v.Header.Cipher.InitialVec[:])

	return nil
}

func (r *Record) addRawField(rawField Field) error {
	switch rawField.rawType {
	case 0x01:
		id, err := uuid.FromBytes(rawField.rawValue)
		if err != nil {
			return err
		}
		r.uuid = id
	case 0x02:
		r.group = string(rawField.rawValue)
	case 0x03:
		r.title = string(rawField.rawValue)
	case 0x04:
		r.user = string(rawField.rawValue)
	case 0x05:
		r.notes = string(rawField.rawValue)
	case 0x06:
		r.password = string(rawField.rawValue)
	case 0x0c:
		r.lastModified = time.Unix(int64(binary.LittleEndian.Uint32(rawField.rawValue)), 0)
	case 0x0d:
		r.url = string(rawField.rawValue)
	}

	return nil
}

func (v *Vault) readField() (*Field, error) {
	data := make([]byte, 16)
	err := binary.Read(v.reader, binary.LittleEndian, data)
	if err != nil {
		return nil, err
	}

	if string(data) == "PWS3-EOFPWS3-EOF" {
		return nil, nil
	}

	decrypt := make([]byte, 16)
	v.decryptor.CryptBlocks(decrypt, data)

	raw_len := binary.LittleEndian.Uint32(decrypt[:4])
	raw_type := decrypt[4]
	raw_value := decrypt[5:]
	if raw_len > 11 {
		for range (raw_len + 4) / 16 {
			data := make([]byte, 16)
			if binary.Read(v.reader, binary.LittleEndian, data) != nil {
				return nil, err
			}
			decrypt := make([]byte, 16)
			v.decryptor.CryptBlocks(decrypt, data)

			raw_value = []byte(string(raw_value) + string(decrypt))
		}
	}
	raw_value = raw_value[:raw_len]

	field := Field{rawLength: raw_len, rawType: raw_type, rawValue: raw_value}
	return &field, nil
}

func (v *Vault) readRecords() error {
	// Reading header fields
	for {
		field, err := v.readField()
		if err != nil {
			return err
		}

		if field == nil {
			break
		}
		if field.rawType == 0xff {
			break
		}

		v.checker.Write(field.rawValue)
	}

	// Reading actual fields and creating records
	var cur_record Record
	for {
		field, err := v.readField()
		if err != nil {
			return err
		}

		if field == nil {
			break
		}

		if field.rawType == 0xff {
			v.Records = append(v.Records, cur_record)
			cur_record = Record{}
		} else {
			v.checker.Write(field.rawValue)
			cur_record.addRawField(*field)
		}
	}

	return nil
}

func (v *Vault) validateHMAC() error {
	vault_hmac := make([]byte, 32)
	err := binary.Read(v.reader, binary.LittleEndian, vault_hmac)
	if err != nil {
		return err
	}

	data_hmac := v.checker.Sum(nil)

	if string(vault_hmac) != string(data_hmac) {
		return errors.New("psafe3: file integrity check failed")
	}

	return nil
}
