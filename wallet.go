// Package massa implements utilities for interacting with
// the Massa blockchain.
//
// Features include wallet generation and management, as
// well as an API Client that wraps functionality of the
// public JSON-RPC and gRPC APIs.
package massa

import (
	"crypto/ed25519"
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
//	- Design wallet state file and add persistence funcs
//	- Password encrypt wallet state file?
//	- Locate wallet state file on Init(), create if not present.
//	- Replace LoadAccount method with UnlockAccount ("loading" will
//	  become "unlocking")
//	- Replace ImportAccount with ImportAccountFromPriv
//	- Replace LoadAccountFromPriv with ImportAccount
//

// We can also add support for the creation and management of HD
// (Heirarchical Deterministic) wallets by implementing a new
// wallet type as per the SLIP-10 standard. This would also
// include support for seed phrases as per the BIP-39 standard.
//

func defaultWalletHome() string {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("could not get user home path: %s", err)
	}

	return filepath.Join(home, ".go-massa", "wallet")
}

// Wallet embeds some configuration options and holds
// an account manager which executes the underlying
// account management functionality exported by the
// Wallet.
type Wallet struct {
	accountManager *accountManager
	*walletOpts
}

type walletOpts struct {
	home string
}

func defaultWalletOpts() *walletOpts {
	return &walletOpts{
		home: defaultWalletHome(),
	}
}

type walletOptFn func(*walletOpts)

// Configuration function that sets a custom home for
// the wallet client, the provided path must be an
// absolute path.
func WithCustomWalletHome(path string) walletOptFn {
	return func(opts *walletOpts) {
		if !filepath.IsAbs(path) {
			log.Fatal("custom home must be absolute path")
		}
		opts.home = path
	}
}

// Returns a pointer to a Wallet, configurable with
// the provided Wallet configuration functions.
func NewWallet(optFns ...walletOptFn) *Wallet {
	opts := defaultWalletOpts()
	for _, fn := range optFns {
		fn(opts)
	}

	return &Wallet{
		accountManager: newAccountManager(opts.home),
		walletOpts:     opts,
	}
}

// This function creates the wallet home directory if it is
// not already present and then initializes the account
// manager, which in turn creates the keystore directory if
// it is not already present.
func (w *Wallet) Init() error {
	exists, err := dirExists(w.home)
	if err != nil {
		return err
	}

	if exists {
		log.Printf("Found home dir at '%s'", w.home)
		return w.accountManager.init()
	}

	if err := os.MkdirAll(w.home, os.ModePerm); err != nil {
		return fmt.Errorf("failed creating home dir: %w", err)
	}

	log.Printf("Created home dir at '%s'", w.home)

	return w.accountManager.init()
}

// Gets an account from the account manager. Returns
// ErrAccountNotFound if the account is not present
// in the account manager's memory.
//
// Maybe this doesn't need to be a user facing func.
// The user can just deal with addresses and the
// corresponding MassaAccount structs can just be
// unexported and handled natively... Update: This
// will not work becase the ApiClient does not have
// access to the account amanger, we would need a
// pointer to the wallet or account manager in the
// apiClient. I'd rather not throw around pointers
// everywhere so will instead encapsulate everything
// in a top level client later that can call all the
// necessary methods of each component.
func (w *Wallet) GetAccount(addr string) (MassaAccount, error) {
	return w.accountManager.getAccount(addr)
}

// Generates a new Massa Account and saves the keystore file
// to the account managers keystore path.
//
// In the case where an empty string "" is provided as the
// password, the user will be prompted to imput a password.
//
// Returns the address of the generated account and an error.
func (w *Wallet) GenerateAccount(password string) (addr string, err error) {
	return w.accountManager.generateAccount(password)
}

// Derives a single account from the prefixed and base58 encoded
// private key, persists it to disk, and loads it into memory.
//
// In the case where an empty string "" is provided as the
// password, the user will be prompted to imput a password.
//
// Returns the address of the imported account and an error.
func (w *Wallet) ImportAccount(priv, password string) (addr string, err error) {
	return w.accountManager.importAccount(priv, password)
}

// Loads the account from the local keystore into memory, if
// and empty string, "", is provided for the password then
// the user will be prompted for a password to unlock the
// keystore file.
func (w *Wallet) LoadAccount(address, password string) error {
	return w.accountManager.loadAccount(address, password)
}

// Derives a Massa Account from the provided private key and
// loads it into memory but does not import it into the wallet.
func (w *Wallet) LoadAccountFromPriv(priv string) error {
	return w.accountManager.loadAccountFromPriv(priv)
}

// Returns the current wallet home path.
func (w *Wallet) GetWalletHome() string {
	return w.home
}

type accountManager struct {
	keystoreDir string
	accounts    map[string]MassaAccount
	mu          sync.RWMutex
}

func newAccountManager(walletHome string) *accountManager {
	return &accountManager{
		keystoreDir: filepath.Join(walletHome, "keys"),
		accounts:    map[string]MassaAccount{},
		mu:          sync.RWMutex{},
	}
}

func (a *accountManager) init() error {
	if exists, err := dirExists(a.keystoreDir); err != nil {
		return err
	} else if exists {
		log.Printf("Found keystore dir at '%s'", a.keystoreDir)
		return nil
	}

	if err := os.MkdirAll(a.keystoreDir, os.ModePerm); err != nil {
		return fmt.Errorf("failed creating keystore dir: %w", err)
	}

	log.Printf("Created keystore dir at '%s'", a.keystoreDir)

	return nil
}

func (a *accountManager) generateAccount(password string) (addr string, err error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return "", fmt.Errorf("failed generating keypair: %w", err)
	}

	acc := newMassaAccount(priv, pub)

	if err := a.persistAccount(acc, password); err != nil {
		return "", fmt.Errorf("failed persisting account: %w", err)
	}

	a.mu.Lock()
	a.accounts[acc.addr.Encoded] = acc
	a.mu.Unlock()

	log.Printf("Generated account with address: %s", acc.addr.Encoded)

	return acc.addr.Encoded, nil
}

func (a *accountManager) importAccount(privEncoded string, password string) (addr string, err error) {

	acc, err := accountFromPriv(privEncoded)
	if err != nil {
		return "", fmt.Errorf("failed deriving account from private key: %w", err)
	}

	if err := a.persistAccount(acc, password); err != nil {
		return "", fmt.Errorf("failed persisting account: %w", err)
	}

	a.mu.Lock()
	a.accounts[acc.addr.Encoded] = acc
	a.mu.Unlock()

	log.Printf("Imported account with address: %s", acc.addr.Encoded)

	return acc.addr.Encoded, nil
}

func (a *accountManager) loadAccount(addr string, password string) error {
	acc, err := getAccountFromKeystore(addr, password, a.keystoreDir)
	if err != nil {
		return fmt.Errorf("failed getting account from keystore: %w", err)
	}

	a.mu.Lock()
	a.accounts[acc.pub.Encoded] = acc
	a.mu.Unlock()

	return nil
}

func (a *accountManager) loadAccountFromPriv(privEncoded string) error {

	acc, err := accountFromPriv(privEncoded)
	if err != nil {
		return fmt.Errorf("failed deriving account from private key: %w", err)
	}

	a.mu.Lock()
	a.accounts[acc.addr.Encoded] = acc
	a.mu.Unlock()

	return nil
}

// Get account returns an account with the specified address
// from the AccountManagers memory, if the requested account
// is not present an error will be returned.
func (a *accountManager) getAccount(addr string) (MassaAccount, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	acc, ok := a.accounts[addr]
	if !ok {
		return MassaAccount{}, ErrAccountNotFound
	}

	return acc, nil
}

func accountFromPriv(privEncoded string) (MassaAccount, error) {

	// Here the decoded private key returns only the first 32
	// bytes of the ed25519 "PrivateKey" which the package
	// refers to as the seed.
	seed, version, err := decodePriv(privEncoded)
	if err != nil {
		return MassaAccount{}, fmt.Errorf("failed decoding private key: %w", err)
	}

	if version != KEYS_VERSION_NUMBER {
		return MassaAccount{}, fmt.Errorf("unexpected keys version, expected (%d), got (%d)", KEYS_VERSION_NUMBER, version)
	}

	priv := ed25519.NewKeyFromSeed(seed)

	var pub = ed25519.PublicKey(make([]byte, 32))
	copy(pub, priv[32:])

	return newMassaAccount(priv, pub), nil
}

func (a *accountManager) persistAccount(acc MassaAccount, password string) error {
	return persistAccount(acc, password, a.keystoreDir)
}
