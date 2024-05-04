package main

import (
	"log"

	"github.com/edatts/go-massa"
)

func main() {

	wallet := massa.NewWallet()

	if err := wallet.Init(); err != nil {
		log.Fatal(err)
	}

	// Empty password will result in a user prompt for a password
	password := ""
	addr, err := wallet.GenerateAccount(password)
	if err != nil {
		log.Fatal(err)
	}

	acc, err := wallet.GetAccount(addr)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Account: %+v", acc)

}
