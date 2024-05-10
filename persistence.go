package massa

import (
	"log"
	"os"
	"path/filepath"
)

func defaultKeystoreDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("could not get user home path: %s", err)
	}

	return filepath.Join(home, ".go-massa", "wallet", "keys")
}

// Encrypts a secret key with a password and saves the
// resulting yaml file to disk.
//
// Returns the file path where the account was persisted.
func persistAccount(acc MassaAccount, password string, keystoreDir string) (string, error) {
	return persistAccountv2(acc, password, keystoreDir)
}

func loadAccountFromKeystore(filePath, password string) (MassaAccount, error) {
	return loadAccountFromKeystoreV2(filePath, password)
}
