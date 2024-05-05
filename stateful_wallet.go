package massa

import (
	"fmt"
	"os"
	"path/filepath"
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

type StatefulWallet struct {
	homeDir          string // Registry file name: homeDir + "registry.encrypted"
	registry         *Registry
	unlockedAccounts map[string]*MassaAccount
}

// Registry keeps track of all imported accounts and marshalls
// to JSON which is then encrypted before being saved to disk.
type Registry struct {
	registeredAccounts map[string]*RegisteredAccount
}

type RegisteredAccount struct {
	AccountName      string
	KeystoreFilePath string
}

func NewStatefulWallet(optFns ...statefulWalletOptFunc) *StatefulWallet {
	opts := defaultStatefulWalletOpts()
	for _, fn := range optFns {
		fn(opts)
	}
	return &StatefulWallet{
		homeDir: opts.homeDir,
		// registry: NewRegistry(),
	}
}

func (s *StatefulWallet) LoadRegistry(password string) error {

	// Check for file
	if err := ensureRegistryFile(s.homeDir); err != nil {
		return fmt.Errorf("failed ensuring registry file: %w", err)
	}

	// Read encrypted file

	s.registry = reg

}

func NewRegistry() *Registry {
	return &Registry{
		registeredAccounts: map[string]*RegisteredAccount{},
	}
}

func (s *StatefulWallet) Init() error {

	// Check for registry file
	if err := ensureRegistryFile(s.homeDir); err != nil {
		return fmt.Errorf("failed ensuring registry file: %w", err)
	}

	// Create registry file if not exists

	// Load registry file

	return nil
}

func saveRegistryFile(path, password string, file *Registry) error {

}

func loadRegistryFile(path, password string) (*Registry, error) {

}

func ensureRegistryFile(registryDir string) error {
	var fileName string = "registry.encrypted"

	// Ensure registry dir
	if err := ensureDir(registryDir); err != nil {
		return fmt.Errorf("failed ensuring dir: %w", err)
	}

	// Check if file exists
	fullPath := filepath.Join(registryDir, fileName)
	exists, err := fileExists(fullPath)
	if err != nil {
		return fmt.Errorf("failed ensuring file: %w", err)
	}

	if !exists {
		file, err := os.Create(fullPath)
		if err != nil {
			return fmt.Errorf("failed creating file: %w", err)
		}
		file.Close()
	}

	return nil
}
