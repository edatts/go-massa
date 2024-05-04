package massa

import (
	"errors"
	"log"
	"os"
	"path/filepath"
	"testing"
)

type testCase struct {
	acc      MassaAccount
	password string
}

func testingKeystorePath() string {
	workDir, err := os.Getwd()
	if err != nil {
		log.Fatal("Failed getting working dir...")
	}

	testingKeystorePath := filepath.Join(workDir, "testStorage", "keys")

	return testingKeystorePath
}

func testCases() []testCase {

	testCases := []testCase{}

	testKeys := []struct {
		MassaPrivEnc string
		MassaPubEnc  string
		MassaAddrEnc string
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

	for _, keys := range testKeys {
		acc, err := accountFromPriv(keys.MassaPrivEnc)
		if err != nil {
			log.Fatal("failed to import keys to accounts for test cases")
		}

		tCase := testCase{
			acc:      acc,
			password: "testPassword",
		}
		testCases = append(testCases, tCase)
	}

	return testCases
}

func TestKeystoreFiles(t *testing.T) {

	// End-to-end test:
	//	- Create Account
	//	- Save as keystore file
	//	- Load from Keystore file
	//	- Assert keys are the same

	for _, tCase := range testCases() {

		// Persist the account
		err := persistAccount(tCase.acc, tCase.password, testingKeystorePath())
		if err != nil {
			t.Errorf("failed persisting account: %s", err)
		}

		// Load the account
		acc, err := getAccountFromKeystore(tCase.acc.addr.Encoded, tCase.password, testingKeystorePath())
		if err != nil {
			t.Errorf("failed getting account from keystore: %s", err)
		}

		// Assert priv, pub, and addr are same as expected
		if acc.addr.Encoded != tCase.acc.addr.Encoded {
			t.Errorf("wrong address after loading keystore, got (%s), expected (%s)", acc.addr.Encoded, tCase.acc.addr.Encoded)
		}

		if acc.priv.Encoded != tCase.acc.priv.Encoded {
			t.Errorf("wrong priv key after loading keystore, got (%s), expected (%s)", acc.priv.Encoded, tCase.acc.priv.Encoded)
		}

		if acc.pub.Encoded != tCase.acc.pub.Encoded {
			t.Errorf("wrong pub key after loading keystore, got (%s), expected (%s)", acc.pub.Encoded, tCase.acc.pub.Encoded)
		}

	}

}

func TestWrongPassword(t *testing.T) {

	for _, tCase := range testCases() {

		err := persistAccount(tCase.acc, tCase.password, testingKeystorePath())
		if err != nil {
			t.Errorf("failed persisting account: %s", err)
		}

		// Assert decrypting keystore fails with wrong password
		wrongPassword := "wrongPassword"
		_, err = getAccountFromKeystore(tCase.acc.addr.Encoded, wrongPassword, testingKeystorePath())
		if err != nil {
			if errors.Is(err, ErrWrongMac) {
				continue
			}
			t.Errorf("enexpected error: %s", err)
		}
		t.Error("expected ErrWrongMac, got nil")
	}

}

// TODO: Test error cases...
