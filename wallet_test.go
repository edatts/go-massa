package massa

import (
	"log"
	"os"
	"path/filepath"
	"testing"
)

func testingWalletHome() string {
	workDir, err := os.Getwd()
	if err != nil {
		log.Fatal("Failed getting working dir...")
	}

	return filepath.Join(workDir, "testStorage", "massaHome", "wallet")
}

func testingRegistryPath() string {
	workDir, err := os.Getwd()
	if err != nil {
		log.Fatal("Failed getting working dir...")
	}

	testingRegistryPath := filepath.Join(workDir, "testStorage", "wallet")

	return testingRegistryPath
}

func TestSaveAndLoadRegistry(t *testing.T) {
	var (
		// regPassword      = "password"
		// wrongPassword    = "wrongPassword"
		registryDir      = testingRegistryPath()
		registryFilePath = filepath.Join(registryDir, registry_file_name)
		reg              = NewRegistry(registryDir)
	)

	// Mock accounts
	regAcc0, regAcc1 := RegisteredAccount{
		// Name:             "testAccount-0",
		Address:          "addr-0", // Probably shouldn't allow invalid addrs...
		KeystoreFilePath: "/definitely/a/real/file-path",
	}, RegisteredAccount{
		// Name:             "testAccount-1",
		Address:          "addr-1",
		KeystoreFilePath: "/probably/a/real/file-path",
	}

	reg.RegisteredAccounts[regAcc0.Address] = regAcc0
	reg.RegisteredAccounts[regAcc1.Address] = regAcc1

	// Test save
	if err := reg.save(); err != nil {
		t.Errorf("failed saving registry to disk: %s", err)
	}

	// Assert file exists
	if _, err := os.Stat(registryFilePath); err != nil {
		t.Errorf("failed stating registry file: %s", err)
	}

	// Manually clear registered accounts
	reg.RegisteredAccounts = make(map[string]RegisteredAccount)

	// Test load
	// if err := reg.load(regPassword); err != nil {
	if err := reg.load(); err != nil {
		t.Errorf("failed loading registry from file: %s", err)
	}

	// Assert acc-0
	expected := regAcc0.KeystoreFilePath
	got := reg.RegisteredAccounts[regAcc0.Address].KeystoreFilePath
	if got != expected {
		t.Errorf("wrong keystore path for account (%s), expected (%s), got (%s)", regAcc0.Address, expected, got)
	}

	// Assert acc-1
	expected = regAcc1.KeystoreFilePath
	got = reg.RegisteredAccounts[regAcc1.Address].KeystoreFilePath
	if got != expected {
		t.Errorf("wrong keystore path for account (%s), expected (%s), got (%s)", regAcc0.Address, expected, got)
	}

	// Test load with wrong password error
	// if err := reg.load(wrongPassword); err == nil {
	// 	t.Errorf("expected error for wrong password, got nil")
	// }
}

func TestGeneratingAccounts(t *testing.T) {

}

func TestImportingAccounts(t *testing.T) {

}
