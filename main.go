package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
)

func main() {
	var file string
	var password string
	var outfile string

	flag.StringVar(&file, "f", "example.psafe3", "Filepath for psafe3 file")
	flag.StringVar(&password, "p", "test123", "Password for psafe3 file")
	flag.StringVar(&outfile, "o", "bitwarden.json", "Output filepath for bitwarden file")

	flag.Parse()

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
