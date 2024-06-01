package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"syscall"

	"golang.org/x/term"
)

func main() {
	var file string
	var outfile string

	flag.StringVar(&file, "f", "example.psafe3", "Filepath for psafe3 file")
	flag.StringVar(&outfile, "o", "bitwarden.json", "Output filepath for bitwarden file")

	flag.Parse()

	fmt.Print("Password (test123): ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		panic(err)
	}

	var password string
	password = "test123"
	if len(bytePassword) != 0 {
		password = string(bytePassword)
	}

	vault, err := VaultFromFile(file, password)
	if err != nil {
		panic(err)
	}

	bitwarden, err := BitwardenFromPSafe3(vault)
	if err != nil {
		panic(err)
	}

	b, err := json.Marshal(bitwarden)
	if err != nil {
		panic(err)
	}

	f, err := os.Create(outfile)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	n, err := f.Write(b)
	if err != nil || n != len(b) {
		log.Fatal(err)
	}
}
