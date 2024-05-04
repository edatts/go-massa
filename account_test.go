package massa

import (
	"log"
	"testing"
)

// func TestGenerateAccounts(t *testing.T) {
// 	// tbh it's tricky to test properly because we can't
// 	// access the entropy used by an official wallet to
// 	// generate accounts and make comparisons...
// }

func TestImportAccounts(t *testing.T) {

	// First test will be generate some accounts and then
	// attempt to import them, accounts should be the same
	// after import. Some failure cases should be included.

	// Second test will be to import accounts that were generated
	// externally using an official massa wallet or the massa-client
	var importTests = []struct {
		massaPriv string
		massaPub  string
		massaAddr string
	}{
		{
			"S11JcqZoz6XXbRjN2nrw2CsuKNfcfqwX6Po2EsiwG6jHnhuVLzo",
			"P1hF36KDK8YJzqhA5Q88UY33dPMnUe9U2hrt9PGR9A3zXinhdvv",
			"AU12AEq7KqnJTTrUdTeqMVBicBk4FYbgqiwppdvYij6ZzWfqQvo97",
		},
		{
			"S1oVi6FLwJvbW8Z9kzmHgtnzhXSVUEYaAeKLWNsUB7AqbzDsuM1",
			"P1gFVDUzuLJS1iHQnMx5k6f1tA76QXCPbcgfrtvVyQaTM6WQPby",
			"AU12oLjNkH8ywGaeqWuSE1CxdWLhG7hsCW8zZgasax1Csn3tW1mni",
		},
		{
			"S12cwSBNbSU1gWK31xu2UaeqzywcQ3BRfZkzqxwEirKdhZGYJux1",
			"P1CdoXHFWztLy9BexY4caDz9T3WxF67gYRHXTn2WGNfuW34YwFx",
			"AU12ai5Yz7Z2CJLbcHP5ssQ1fJHGLYqm6rMk1ejmoAiB3dojt3qK3",
		},
		{
			"S1NGwdzym1bjHnxvVFQwTDfibSN7xAqsM984nLTwUyY1B6o37Cm",
			"P19M4j4NxnZuT5Xj1JafSPFZRdu38UMRtidUXPHSHGVNwt3YGrL",
			"AU12KcEiJHsS9mjBziza3dDNMMGQan6L2KVBXRsF6ypHKaZnnP9V5",
		},
	}

	for i, testCase := range importTests {

		// Import Account
		acc, err := accountFromPriv(testCase.massaPriv)
		if err != nil {
			t.Errorf("failed importing account: %s", err)
		}

		// Check account
		if acc.priv.Encoded != testCase.massaPriv {
			log.Printf("failed test number %d", i)
			t.Errorf("incorrect massa private key, got (%s), expected (%s)", acc.priv.Encoded, testCase.massaPriv)
		}

		if acc.pub.Encoded != testCase.massaPub {
			log.Printf("failed test number %d", i)
			t.Errorf("incorrect massa pub key, got (%s), expected (%s)", acc.pub.Encoded, testCase.massaPub)
		}

		if acc.addr.Encoded != testCase.massaAddr {
			log.Printf("failed test number %d", i)
			t.Errorf("incorrect massa Address, got (%s), expected (%s)", acc.addr.Encoded, testCase.massaAddr)
		}

	}

}

// func TestAccountsErrors(t *testing.T) {

// 	// Failed decoding priv key err

// 	// Unexpected key version err

// }
