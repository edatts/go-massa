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

const (
	registry_file_name string = "registry.encrypted"
)

type walletOpts struct {
	homeDir string
	// registryDir string
	requireApproval bool
}

func defaultwalletOpts() *walletOpts {
	return &walletOpts{
		homeDir:         defaultWalletHome(),
		requireApproval: true,
	}
}

type walletOptFunc func(opts *walletOpts)

func WithCustomHome(dir string) walletOptFunc {
	return func(opts *walletOpts) {
		opts.homeDir = dir
	}
}

type Wallet struct {
	homeDir string // Registry file name: homeDir + "registry.encrypted"

	registry *registry

	unlockedAccounts map[string]MassaAccount
	mu               sync.RWMutex

	sigReqCh chan signatureRequest
	opReqCh  chan serializeOperationRequest
}

type signatureRequest struct {
	accountAddr string
	payload     []byte
	resultCh    chan MassaSignature
	errCh       chan error
}

type serializeOperationRequest struct {
	callerAddr   string
	opData       OperationData
	expiryPeriod uint64
	chainId      uint64
	resultCh     chan serializeOperationResult
	errCh        chan error
}

type serializeOperationResult struct {
	serializedOp []byte
	opId         string
}

// Registry keeps track of all imported accounts and marshals
// to JSON which is then saved to disk.
type registry struct {
	filePath           string
	RegisteredAccounts map[string]RegisteredAccount
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

func NewWallet(optFns ...walletOptFunc) *Wallet {
	opts := defaultwalletOpts()
	for _, fn := range optFns {
		fn(opts)
	}
	return &Wallet{
		homeDir:          opts.homeDir,
		registry:         NewRegistry(opts.homeDir),
		unlockedAccounts: map[string]MassaAccount{},
		mu:               sync.RWMutex{},
		sigReqCh:         make(chan signatureRequest, 10),
		opReqCh:          make(chan serializeOperationRequest, 10),
	}
}

// This function creates the wallet home directory if it is
// not already present, creates a registry file that keeps
// track of which accounts have been previously imported, and
// starts the signing and operation serialization loops.
func (s *Wallet) Init() error {

	// Ensure home and keystore dirs
	if err := s.ensureDirs(); err != nil {
		return fmt.Errorf("failed ensuring dir: %w", err)
	}

	// Check for registry file
	if exists, err := s.registry.fileExists(); err != nil {
		return fmt.Errorf("failed checking if file exists: %w", err)
	} else if !exists {
		if err := s.registry.save(); err != nil {
			return fmt.Errorf("failed saving registry: %w", err)
		}
	} else {
		// password := ""
		if err := s.registry.load(); err != nil {
			return fmt.Errorf("failed loading registry from disk: %w", err)
		}
	}

	go s.startSigRequestLoop()
	go s.startSerializeOperationRequestLoop()

	return nil
}

func (s *Wallet) startSigRequestLoop() {
	for req := range s.sigReqCh {
		acc, err := s.getAccount(req.accountAddr)
		if err != nil {
			req.errCh <- fmt.Errorf("failed getting account for addr (%s): %w", req.accountAddr, err)
			continue
		}

		req.resultCh <- acc.sign(req.payload)
	}
}

func (s *Wallet) startSerializeOperationRequestLoop() {
	for req := range s.opReqCh {
		acc, err := s.getAccount(req.callerAddr)
		if err != nil {
			req.errCh <- fmt.Errorf("failed getting account for addr (%s): %w", req.callerAddr, err)
			continue
		}

		serializedOp, opId, err := serializeOperation(acc, req.opData, req.expiryPeriod, req.chainId)
		if err != nil {
			req.errCh <- fmt.Errorf("failed serializing operation: %w", err)
			continue
		}

		req.resultCh <- serializeOperationResult{
			serializedOp: serializedOp,
			opId:         opId,
		}
	}
}

// TODO: Unit tests...
// Generates a new Massa Account, saves the keystore file, and
// registers the account with the wallet registry.
//
// In the case where an empty string "" is provided as the
// password, the user will be prompted to imput a password.
//
// Returns the address of the generated account and an error.
func (s *Wallet) GenerateAccount(accountPassword string) (string, error) {
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

// TODO: Unit tests...
// Derives a single account from the prefixed and base58 encoded
// private key, persists it to disk, registers it with the wallet
// registry and unlocks the wallet.
//
// In the case where an empty string "" is provided as the
// password, the user will be prompted to imput a password.
//
// Returns the address of the imported account and an error.
func (s *Wallet) ImportFromPriv(privEncoded, password string) (addr string, err error) {
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

// TODO: Unit tests...
// Derives a single account from the keystore file, registers
// the account with the wallet registry, and unlocks the
// account.
//
// In the case where an empty string "" is provided as the
// password, the user will be prompted to imput a password.
//
// Returns the address of the imported account and an error.
func (s *Wallet) ImportFromFile(filePath, password string) (addr string, err error) {

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

// TODO: Unit tests...
// Unlocks the account corresponding to the provided address.
// If the account is not registered or the wallet file is not
// present an error will be returned.
func (s *Wallet) UnlockAccount(addr, password string) error {

	if _, ok := s.unlockedAccounts[addr]; ok {
		return nil
	}

	if !s.registry.hasAccount(addr) {
		return ErrRegAccountNotFound
	}

	regAcc, err := s.registry.getRegisteredAccount(addr)
	if err != nil {
		return err
	}

	acc, err := loadAccountFromKeystore(regAcc.KeystoreFilePath, password)
	if err != nil {
		return fmt.Errorf("failed loading account from keystore: %w", err)
	}

	s.unlockedAccounts[addr] = acc

	return nil
}

func (w *Wallet) ListUnlockedAccounts() (addrs []string) {
	for addr := range w.unlockedAccounts {
		addrs = append(addrs, addr)
	}
	return addrs
}

func (s *Wallet) GetWalletHome() string {
	return s.homeDir
}

func (s *Wallet) KeystoreDir() string {
	return filepath.Join(s.homeDir, "keys")
}

func (s *Wallet) getAccount(addr string) (MassaAccount, error) {
	if acc, ok := s.unlockedAccounts[addr]; !ok {
		return MassaAccount{}, ErrAccountNotFound
	} else {
		return acc, nil
	}
}

func (w *Wallet) ensureDirs() error {
	if err := ensureDir(w.homeDir); err != nil {
		return fmt.Errorf("failed ensuring home dir: %w", err)
	}

	if err := ensureDir(w.KeystoreDir()); err != nil {
		return fmt.Errorf("failed ensuring keystsore dir: %w", err)
	}

	return nil
}

func (s *Wallet) persistAccount(acc MassaAccount, password string) (string, error) {
	return persistAccount(acc, password, s.KeystoreDir())
}

func requestSignature(addr string, payload []byte, sigRequestCh chan signatureRequest) (MassaSignature, error) {
	var (
		resultCh = make(chan MassaSignature)
		errCh    = make(chan error)
	)

	sigRequestCh <- signatureRequest{
		accountAddr: addr,
		payload:     payload,
		resultCh:    resultCh,
		errCh:       errCh,
	}

	select {
	case massaSig := <-resultCh:
		return massaSig, nil
	case err := <-errCh:
		return MassaSignature{}, err
	}
}

func NewRegistry(homeDir string) *registry {
	return &registry{
		filePath:           filepath.Join(homeDir, registry_file_name),
		RegisteredAccounts: map[string]RegisteredAccount{},
	}
}

func (r *registry) registerAccount(acc MassaAccount, keystoreFilePath string) error {

	// This probably doesn't need to be an error, could just
	// return nil. Just wondering what to do in the case where
	// the account is already registered but with a different
	// keystore file...
	if _, ok := r.RegisteredAccounts[acc.Addr()]; ok {
		log.Printf("could not register account, account already registered")
		return nil
	}

	r.RegisteredAccounts[acc.Addr()] = RegisteredAccount{
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
		return fmt.Errorf("failed unmarshalling registry file: %w", err)
	}

	return nil
}

// func (r *registry) ensureFile() error {

// 	// Ensure registry dir
// 	if err := ensureDir(r.RegistryDir); err != nil {
// 		return fmt.Errorf("failed ensuring dir: %w", err)
// 	}

// 	// Check if file exists
// 	exists, err := fileExists(r.FilePath())
// 	if err != nil {
// 		return fmt.Errorf("failed ensuring file: %w", err)
// 	}

// 	if !exists {
// 		file, err := os.Create(r.FilePath())
// 		if err != nil {
// 			return fmt.Errorf("failed creating file: %w", err)
// 		}
// 		file.Close()
// 	}

// 	return nil
// }

func (r *registry) fileExists() (bool, error) {
	exists, err := fileExists(r.FilePath())
	if err != nil {
		return false, fmt.Errorf("failed ensuring file: %w", err)
	}
	return exists, nil
}

func (r *registry) FilePath() string {
	return r.filePath
}

func (r *registry) hasAccount(addr string) bool {
	if _, ok := r.RegisteredAccounts[addr]; ok {
		return true
	}
	return false
}

func (r *registry) getRegisteredAccount(addr string) (RegisteredAccount, error) {
	if !r.hasAccount(addr) {
		return RegisteredAccount{}, ErrRegAccountNotFound
	}
	return r.RegisteredAccounts[addr], nil
}

func defaultWalletHome() string {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("could not get user home path: %s", err)
	}

	return filepath.Join(home, ".go-massa", "wallet")
}
