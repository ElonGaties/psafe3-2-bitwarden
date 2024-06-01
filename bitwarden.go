package main

import (
	"time"
)

type Folder struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Field struct {
	Name     string  `json:"name"`
	Value    string  `json:"value"`
	Type     int     `json:"type"`
	LinkedID *string `json:"linkedId"`
}

type Uri struct {
	Match *string `json:"match"`
	URI   string  `json:"uri"`
}

type Item struct {
	PasswordHistory []struct {
		LastUsedDate time.Time `json:"lastUsedDate"`
		Password     string    `json:"password"`
	} `json:"passwordHistory"`
	RevisionDate   time.Time  `json:"revisionDate"`
	CreationDate   time.Time  `json:"creationDate"`
	DeletedDate    *time.Time `json:"deletedDate"`
	ID             string     `json:"id"`
	OrganizationID *string    `json:"organizationId"`
	FolderID       *string    `json:"folderId"`
	Type           int        `json:"type"`
	Reprompt       int        `json:"reprompt"`
	Name           string     `json:"name"`
	Notes          string     `json:"notes"`
	Favorite       bool       `json:"favorite"`
	Login          struct {
		Fido2Credentials *string `json:"fido2Credentials"`
		Uris             []Uri   `json:"uris"`
		Username         string  `json:"username"`
		Password         string  `json:"password"`
		Totp             *string `json:"totp"`
	} `json:"login,omitempty"`
	CollectionIds string  `json:"collectionIds"`
	Fields        []Field `json:"fields,omitempty"`
	SecureNote    *struct {
		Type int `json:"type"`
	} `json:"secureNote,omitempty"`
}

type Base struct {
	Encrypted bool      `json:"encrypted"`
	Folders   *[]Folder `json:"folders,omitempty"`
	Items     []Item    `json:"items"`
}

func BitwardenFromPSafe3(psafe3 *Vault) (*Base, error) {
	var bitwarden Base

	bitwarden.Encrypted = false
	for _, record := range psafe3.Records {
		var item Item

		item.Type = 1
		item.ID = string(record.uuid.String())
		item.Name = record.title
		item.Login.Username = record.user
		item.Notes = record.notes
		item.Login.Password = record.password
		item.RevisionDate = record.lastModified
		item.CreationDate = record.lastModified

		uri := Uri{Match: nil, URI: record.url}
		item.Login.Uris = append(item.Login.Uris, uri)

		email := Field{Name: "Email", Value: record.email, Type: 0x0}
		item.Fields = append(item.Fields, email)

		item.Reprompt = int(record.protectedRecord)

		bitwarden.Items = append(bitwarden.Items, item)
	}

	return &bitwarden, nil
}
