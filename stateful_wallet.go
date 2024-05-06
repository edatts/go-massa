package massa

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// An improvement to the current wallet would be to persist it's
// state to disk so that the user does not have to load previously
// generated or imported wallets manually.
//
// Implementation steps:
//	- Design wallet state file and add persistence funcs ---DONE---
//	- Password encrypt wallet state file? ---DONE---
//	- Locate wallet state file on Init(), create if not present. ---DONE---
//	- Replace LoadAccount method with UnlockAccount ("loading" will
//	  become "unlocking")
//	- Replace ImportAccount with ImportAccountFromPriv
//	- Replace LoadAccountFromPriv with ImportAccount
//

const (
	registry_file_name string = "registry.encrypted"
)

type statefulWalletOpts struct {
	homeDir string
	// registryDir string
}

func defaultStatefulWalletOpts() *statefulWalletOpts {
	return &statefulWalletOpts{
		homeDir: defaultWalletHome(),
	}
}

type statefulWalletOptFunc func(opts *statefulWalletOpts)

func WithCustomHome(dir string) statefulWalletOptFunc {
	return func(opts *statefulWalletOpts) {
		opts.homeDir = dir
	}
}

// TODO: Add configuration for locking idle wallets...
type StatefulWallet struct {
	homeDir  string // Registry file name: homeDir + "registry.encrypted"
	registry *registry
	// unlockedAccounts map[string]*UnlockedAccount
	unlockedAccounts map[string]MassaAccount
	mu               sync.RWMutex
}

// Registry keeps track of all imported accounts and marshals
// to JSON which is then saved to disk.
type registry struct {
	RegistryDir        string
	FileName           string
	RegisteredAccounts map[string]*RegisteredAccount
}

type RegisteredAccount struct {
	// Name             string
	Address          string
	KeystoreFilePath string
}

type UnlockedAccount struct {
	// Name string
	*MassaAccount
}

func NewStatefulWallet(optFns ...statefulWalletOptFunc) *StatefulWallet {
	opts := defaultStatefulWalletOpts()
	for _, fn := range optFns {
		fn(opts)
	}
	return &StatefulWallet{
		homeDir:  opts.homeDir,
		registry: NewRegistry(opts.homeDir),
	}
}

func (s *StatefulWallet) Init() error {

	// Check for registry file
	if err := s.registry.ensureFile(); err != nil {
		return fmt.Errorf("failed ensuring registry file: %w", err)
	}

	// password := ""
	if err := s.registry.load(); err != nil {
		return fmt.Errorf("failed loading registry from disk: %w", err)
	}

	// Should we load encrypted versions of each wallet into
	// memory on init? Or should we just leave them on disk
	// until they are unlocked?
	//
	// For now leave them on disk until they are unlocked.

	return nil
}

// TODO: Implement...
func (s *StatefulWallet) GenerateAccount(accountPassword string) (string, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return "", fmt.Errorf("failed generating keypair: %w", err)
	}

	acc := newMassaAccount(priv, pub)

	filePath, err := s.persistAccount(acc, accountPassword)
	if err != nil {
		return "", fmt.Errorf("failed persisting account: %w", err)
	}

	// Register account
	if err := s.registry.registerAccount(acc, filePath); err != nil {
		return "", fmt.Errorf("failed registering account: %w", err)
	}

	s.mu.Lock()
	s.unlockedAccounts[acc.Addr()] = acc
	s.mu.Unlock()

	log.Printf("Generated account with address: %s", acc.addr.Encoded)

	return acc.addr.Encoded, nil
}

func (s *StatefulWallet) ImportFromPriv(privEncoded, password string) (addr string, err error) {
	acc, err := accountFromPriv(privEncoded)
	if err != nil {
		return "", fmt.Errorf("failed deriving account from private key: %w", err)
	}

	filePath, err := s.persistAccount(acc, password)
	if err != nil {
		return "", fmt.Errorf("failed persisting account: %w", err)
	}

	if err := s.registry.registerAccount(acc, filePath); err != nil {
		return "", fmt.Errorf("failed registering account: %w", err)
	}

	s.mu.Lock()
	s.unlockedAccounts[acc.Addr()] = acc
	s.mu.Unlock()

	log.Printf("Imported account with address: %s", acc.Addr())

	return acc.Addr(), nil
}

func (s *StatefulWallet) ImportFromFile(filePath, password string) (addr string, err error) {

	acc, err := loadAccountFromKeystore(filePath, password)
	if err != nil {
		return
	}

	if err := s.registry.registerAccount(acc, filePath); err != nil {
		return "", fmt.Errorf("failed registering account: %w", err)
	}

	s.mu.Lock()
	s.unlockedAccounts[acc.Addr()] = acc
	s.mu.Unlock()

	log.Printf("Imported account with address: %s", acc.Addr())

	return acc.Addr(), nil
}

// TODO: Implement...
func (s *StatefulWallet) UnlockAccount() {}
func (s *StatefulWallet) GetAccount() {
	// Get Account should return an error if the requested
	// account is not registered, and should prompt the
	// user to unlock the account if it is locked.
}

func (s *StatefulWallet) GetWalletHome() string {
	return s.homeDir
}

func (s *StatefulWallet) KeystoreDir() string {
	return filepath.Join(s.homeDir, "keys")
}

func (s *StatefulWallet) persistAccount(acc MassaAccount, password string) (string, error) {
	return persistAccountV2(acc, password, s.KeystoreDir())
}

func NewRegistry(registryDir string) *registry {
	return &registry{
		RegistryDir:        registryDir,
		FileName:           registry_file_name,
		RegisteredAccounts: map[string]*RegisteredAccount{},
	}
}

func (r *registry) registerAccount(acc MassaAccount, keystoreFilePath string) error {

	// This probably doesn't need to be an error, could just
	// return nil. Just wondering what to do in the case where
	// the account is already registered but with a different
	// keystore file...
	if _, ok := r.RegisteredAccounts[acc.Addr()]; ok {
		return fmt.Errorf("account alreday registered")
	}

	r.RegisteredAccounts[acc.Addr()] = &RegisteredAccount{
		// Name:             name,
		Address:          acc.Addr(),
		KeystoreFilePath: keystoreFilePath,
	}

	if err := r.save(); err != nil {
		return fmt.Errorf("failed saving registry file: %w", err)
	}

	return nil
}

func (r *registry) removeAccount(addr string) error {
	delete(r.RegisteredAccounts, addr)

	if err := r.save(); err != nil {
		return fmt.Errorf("failed saving registry file: %w", err)
	}

	return nil
}

// Save should be called whenever a new account is imported
// or when an account is removed/deleted from the registry.
func (r *registry) save() error {

	// if password == "" {
	// 	passwordBytes, err := readPassword()
	// 	if err != nil {
	// 		return fmt.Errorf("failed reading password from user input: %w", err)
	// 	}
	// 	password = string(passwordBytes)
	// }

	// JSON marshal registry
	marshalled, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("failed marshalling registry: %w", err)
	}

	// Password encrypt registry
	// encrypted, err := passwordEncrypt(password, marshalled)
	// if err != nil {
	// 	return fmt.Errorf("failed encrypting registry file: %w", err)
	// }

	// Write encrypted file to disk
	if err := writeFile(r.FilePath(), marshalled); err != nil {
		return fmt.Errorf("failed writing registry to disk: %w", err)
	}

	return nil
}

// Load is called on initialization of the stateful wallet.
func (r *registry) load() error {

	// if password == "" {
	// 	passwordBytes, err := readPassword()
	// 	if err != nil {
	// 		return fmt.Errorf("failed reading password from user input: %w", err)
	// 	}
	// 	password = string(passwordBytes)
	// }

	// Read file
	jsonFile, err := readFile(r.FilePath())
	if err != nil {
		return fmt.Errorf("failed reading registry file: %w", err)
	}

	// Decrypt file
	// jsonFile, err := passwordDecrypt(password, encryptedFile)
	// if err != nil {
	// 	return fmt.Errorf("failed decrypting registry file: %w", err)
	// }

	// Unmarshal file
	if err := json.Unmarshal(jsonFile, r); err != nil {
		return fmt.Errorf("failed unmarshalling json file: %w", err)
	}

	return nil
}

func (r *registry) ensureFile() error {

	// Ensure registry dir
	if err := ensureDir(r.RegistryDir); err != nil {
		return fmt.Errorf("failed ensuring dir: %w", err)
	}

	// Check if file exists
	exists, err := fileExists(r.FilePath())
	if err != nil {
		return fmt.Errorf("failed ensuring file: %w", err)
	}

	if !exists {
		file, err := os.Create(r.FilePath())
		if err != nil {
			return fmt.Errorf("failed creating file: %w", err)
		}
		file.Close()
	}

	return nil
}

func (r *registry) FilePath() string {
	return filepath.Join(r.RegistryDir, r.FileName)
}
