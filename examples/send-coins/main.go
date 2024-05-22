package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/edatts/go-massa"
)

func main() {

	var (
		// Don't hardcode secrets in your applications...
		senderSecretKey = "S11JcqZoz6XXbRjN2nrw2CsuKNfcfqwX6Po2EsiwG6jHnhuVLzo"

		// Empty password will prompt for user input.
		senderPassword = "password"

		// Amount must be in nanoMAS
		amount uint64 = 1_000_000_000 // 1 MAS

		jsonRpcApi    = "https://buildnet.massa.net/api/v2"
		recipientAddr = "AU12oLjNkH8ywGaeqWuSE1CxdWLhG7hsCW8zZgasax1Csn3tW1mni"
	)

	// Get custom home
	wd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	customHome := filepath.Join(wd, "exampleStorage", "massaHome")

	massaClient := massa.NewClient(massa.WithHome(customHome))

	if err := massaClient.Init(jsonRpcApi); err != nil {
		log.Fatal(err)
	}

	senderAddr, err := massaClient.ImportFromPriv(senderSecretKey, senderPassword)
	if err != nil {
		log.Fatal(err)
	}

	opId, err := massaClient.SendTransaction(senderAddr, recipientAddr, amount)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Operation ID: %s", opId)

	// wallet := massa.NewWallet(massa.WithWalletHome(customHome))
	// if err := wallet.Init(); err != nil {
	// 	log.Fatal(err)
	// }

	// apiClient := massa.NewApiClient()
	// if err := apiClient.Init(wallet, jsonRpcApi); err != nil {
	// 	log.Fatal(err)
	// }

	// senderAddr, err := wallet.ImportFromPriv(senderSecretKey, senderPassword)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// opId, err := apiClient.SendTransaction(senderAddr, recipientAddr, amount)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// log.Printf("Operation ID: %s", opId)
}
