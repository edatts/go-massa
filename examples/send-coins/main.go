package main

import (
	"log"

	"github.com/edatts/go-massa"
)

func main() {

	var (
		// Don't hardcode secrets in your applications...
		senderSecretKey = "S11JcqZoz6XXbRjN2nrw2CsuKNfcfqwX6Po2EsiwG6jHnhuVLzo"

		// Empty password will prompt for user input.
		senderPassword = ""

		// Amount must be in nanoMAS
		amount uint64 = 1_000_000_000 // 1 MAS

		jsonRpcApi    = "https://buildnet.massa.net/api/v2"
		recipientAddr = "AU12oLjNkH8ywGaeqWuSE1CxdWLhG7hsCW8zZgasax1Csn3tW1mni"
	)

	apiClient := massa.NewApiClient()
	if err := apiClient.Init(jsonRpcApi); err != nil {
		log.Fatal(err)
	}

	wallet := massa.NewWallet()
	if err := wallet.Init(); err != nil {
		log.Fatal(err)
	}

	senderAddr, err := wallet.ImportAccount(senderSecretKey, senderPassword)
	if err != nil {
		log.Fatal(err)
	}

	senderAcc, err := wallet.GetAccount(senderAddr)
	if err != nil {
		log.Fatal(err)
	}

	opId, err := apiClient.SendTransaction(senderAcc, recipientAddr, amount)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Operation ID: %s", opId)
}
