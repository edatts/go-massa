package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/edatts/go-massa"
)

func main() {

	// Get custom home
	wd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	customHome := filepath.Join(wd, "exampleStorage", "wallet")

	wallet := massa.NewWallet(massa.WithCustomHome(customHome))
	if err := wallet.Init(); err != nil {
		log.Fatal(err)
	}

	// Empty password will result in a user prompt for a password
	password := "password"
	_, err = wallet.GenerateAccount(password)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Accounts: %v", wallet.ListUnlockedAccounts())

}
