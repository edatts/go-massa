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
// More work is required on this implementation to improve
// how signing is carried out and how accounts are handled
//
// Additional work:
//	- Re-design such that accounts are never passed to other
//	  components of the SDK.
//	- Implement signing requests. The idea here is that the
//	  api client and other components will be able to request
//	  signatures from the wallet, this way keys always stay
//	  within the wallet and the wallet can reject requests.
//	- Refactor ApiClient to make signing requests with the
//	  wallet instead of getting an account from the wallet
//	  and doing the signing inside the api client.
//

const (
	registry_file_name string = "registry.encrypted"
)

type statefulWalletOpts struct {
	homeDir string
	// registryDir string
	requireApproval bool
}

func defaultStatefulWalletOpts() *statefulWalletOpts {
	return &statefulWalletOpts{
		homeDir:         defaultWalletHome(),
		requireApproval: true,
	}
}

type statefulWalletOptFunc func(opts *statefulWalletOpts)

func WithCustomHome(dir string) statefulWalletOptFunc {
	return func(opts *statefulWalletOpts) {
		opts.homeDir = dir
	}
}

type StatefulWallet struct {
	homeDir         string // Registry file name: homeDir + "registry.encrypted"
	requireApproval bool

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
	RegistryDir        string
	FileName           string
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

func NewStatefulWallet(optFns ...statefulWalletOptFunc) *StatefulWallet {
	opts := defaultStatefulWalletOpts()
	for _, fn := range optFns {
		fn(opts)
	}
	return &StatefulWallet{
		homeDir:          opts.homeDir,
		requireApproval:  opts.requireApproval,
		registry:         NewRegistry(opts.homeDir),
		unlockedAccounts: map[string]MassaAccount{},
		mu:               sync.RWMutex{},
		sigReqCh:         make(chan signatureRequest, 10),
		opReqCh:          make(chan serializeOperationRequest, 10),
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

	go s.startSigRequestLoop()
	go s.startSerializeOperationRequestLoop()

	return nil
}

func (s *StatefulWallet) startSigRequestLoop() {
	for req := range s.sigReqCh {
		acc, err := s.getAccount(req.accountAddr)
		if err != nil {
			req.errCh <- fmt.Errorf("failed getting account for addr (%s): %w", req.accountAddr, err)
			continue
		}

		req.resultCh <- acc.sign(req.payload)
	}
}

func (s *StatefulWallet) startSerializeOperationRequestLoop() {
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

// TODO: Unit tests...
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

// TODO: Unit tests...
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

// TODO: Unit tests...
func (s *StatefulWallet) UnlockAccount(addr, password string) error {

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

// TODO: Deprecate GetAccount() and refactor the wallet such
// that accounts are not passed outside of the waller and all
// signing is carried out inside the wallet. Other components
// of the SDK should make signing requests to the wallet
// which should only be approved if require approval is turned
// off or if the request is properly authenticated using the
// account password or a long-lived access token.
func (s *StatefulWallet) GetAccount(addr string) (MassaAccount, error) {

	if !s.registry.hasAccount(addr) {
		return MassaAccount{}, ErrRegAccountNotFound
	}

	return MassaAccount{}, nil
}

func (s *StatefulWallet) GetWalletHome() string {
	return s.homeDir
}

func (s *StatefulWallet) KeystoreDir() string {
	return filepath.Join(s.homeDir, "keys")
}

func (s *StatefulWallet) getAccount(addr string) (MassaAccount, error) {
	if acc, ok := s.unlockedAccounts[addr]; !ok {
		return MassaAccount{}, ErrAccountNotFound
	} else {
		return acc, nil
	}
}

func (s *StatefulWallet) persistAccount(acc MassaAccount, password string) (string, error) {
	return persistAccountV2(acc, password, s.KeystoreDir())
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

func NewRegistry(registryDir string) *registry {
	return &registry{
		RegistryDir:        registryDir,
		FileName:           registry_file_name,
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