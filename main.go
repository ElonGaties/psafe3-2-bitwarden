package main

import (
	"log"
)

func main() {
	vault, err := VaultFromFile("example.psafe3", "test123")
	if err != nil {
		panic(err)
	}
	log.Printf("%#v", vault.Records)
}
