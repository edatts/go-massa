package massa

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"path/filepath"
	"time"

	"golang.org/x/crypto/pbkdf2"
	"gopkg.in/yaml.v3"
)

// Here is where we will persist our accounts to disk.
// We will achieve this by encrypting the private key
// using a combination of CTR mode encrypton and a
// key derivation function such that the user can
// decrypt the private key using only a password.
//
// We then need to decide how we want it to be stored
// on disk, we could save it to disk as a blob with the
// IV used for encryption and the KDF details concatenated
// onto the front of the blob, or we could encode and save
// the encrypted private key into a JSON keystore file
// that includes relevant KDF details and the IV used for
// encryption.
//
// Keystore file structure:
//	{
//		"address": "<ADDRESS>"
//		"crypto": {
//			"ciphertext": "<CIPHERTEXT>",
//			"cipherparams": {
//				"iv": "<INITIALIZATION_VECTOR>"
//			},
//			"cipher": "CTR",
//			"kdf": "scrypt",
//			"kdfparams": {
//				"keylen": 32,
//				"salt": "<SALT>",
//				"n": 1048576,
//				"r": 8,
//				"p": 1
//			},
//			"mac": "<MAC>"
//		}
//	}
//
//
// Note: The recommended format for key storage as per the
// Massa Standard is YAML. Additionally, the recommended
// mode of encryption is AES-GCM and the recommended
// key derivation function is PBKDF2, scrypt is similar
// but we should adopt the Massa Standard before
// producing a stable release.
//
// YAML example format:
//
// ---
// Version: 1
// Nickname: Savings
// Address: AU12...
// Salt: [57, 125, 102, 235, 118, 62, 21, 145, 126, 197, 242, 54, 145, 50, 178, 98]
// Nonce: [119, 196, 31, 33, 211, 243, 26, 58, 102, 180, 47, 57]
// CipheredData: [17, 42, ...]
// PublicKey: [0, 21, 126, ...]
//
//
// TODO: Implement Massa Standard for encryption and
// 		 storage of keys on disk.
//

// func defaultKeystoreDir() string {
// 	home, err := os.UserHomeDir()
// 	if err != nil {
// 		log.Fatalf("could not get user home path: %s", err)
// 	}

// 	return filepath.Join(home, ".go-massa", "wallet", "keys")
// }

type kdfParams struct {
	iter   int
	keyLen int
}

type keystoreYaml struct {
	Version      int
	Nickname     string
	Address      string
	Salt         []byte `yaml:",flow"`
	Nonce        []byte `yaml:",flow"`
	CipheredData []byte `yaml:",flow"`
	PublicKey    []byte `yaml:",flow"`
}

// The same as persistAccount() but also returns the
// file path where the account was persisted.
//
// Will replace the original func fully once the stateful
// wallet is finished and tested.
func persistAccountv2(acc MassaAccount, password string, keystoreDir string) (string, error) {

	// Create keystore file
	kf, err := createKeystoreFileV2(acc, password)
	if err != nil {
		return "", fmt.Errorf("failed creating keystore file: %w", err)
	}

	// Marshal to YAML
	marshalled, err := yaml.Marshal(kf)
	if err != nil {
		return "", fmt.Errorf("failed marshalling yaml: %w", err)
	}

	// Generate keystore name
	fileName := generateKeystoreFileName(kf.Address)
	filePath := filepath.Join(keystoreDir, fileName)

	// Save to disk
	if err := writeFile(filePath, marshalled); err != nil {
		return "", fmt.Errorf("failed writing file: %w", err)
	}

	return filePath, nil
}

func createKeystoreFileV2(acc MassaAccount, password string) (keystoreYaml, error) {
	var passwordBytes []byte

	// Prompt user for password if not present
	if password == "" {
		fmt.Println("Please input a password for the account: ")
		password, err := readPassword()
		if err != nil {
			return keystoreYaml{}, fmt.Errorf("failed accepting user input: %w", err)
		}
		passwordBytes = password

		// This one doesn't hide user input on the screen...
		// if _, err := fmt.Scanln(&password); err != nil {
		// 	return KeystoreFile{}, fmt.Errorf("failed accepting user input")
		// }
	} else {
		passwordBytes = []byte(password)
	}

	// Derive cipher encryption/decryption key using pbkdf2
	var params = defaultKdfParams()
	encryptionKey, salt, err := deriveKeyFromPasswordV2(passwordBytes, nil, params)
	if err != nil {
		return keystoreYaml{}, fmt.Errorf("failed deriving encryption key from password: %w", err)
	}

	var serializedPriv []byte
	serializedPriv = binary.AppendUvarint(serializedPriv, acc.priv.Version)
	serializedPriv = append(serializedPriv, acc.priv.Key[:32]...)

	// Encrypt private key
	ciphertext, nonce, err := encryptPrivateKeyV2(serializedPriv, encryptionKey)
	if err != nil {
		return keystoreYaml{}, fmt.Errorf("failed encrypting private key: %w", err)
	}

	var serializedPub []byte
	serializedPub = binary.AppendUvarint(serializedPub, acc.pub.Version)
	serializedPub = append(serializedPub, acc.pub.Key...)

	ky := keystoreYaml{
		Version:      1,
		Nickname:     acc.Addr(),
		Address:      acc.Addr(),
		Salt:         salt,
		Nonce:        nonce,
		CipheredData: ciphertext,
		PublicKey:    serializedPub,
	}

	return ky, nil
}

func loadAccountFromKeystoreV2(filePath, password string) (MassaAccount, error) {

	if !filepath.IsAbs(filePath) {
		return MassaAccount{}, fmt.Errorf("provide file path must be absolute")
	}

	fileBytes, err := readFile(filePath)
	if err != nil {
		return MassaAccount{}, fmt.Errorf("failed reading file: %w", err)
	}

	var ky keystoreYaml
	if err = yaml.Unmarshal(fileBytes, &ky); err != nil {
		return MassaAccount{}, fmt.Errorf("failed unmarshalling keystore yaml: %w", err)
	}

	// Derive AES key
	params := defaultKdfParams()
	aesKey, _, err := deriveKeyFromPasswordV2([]byte(password), ky.Salt, params)
	if err != nil {
		return MassaAccount{}, fmt.Errorf("failed deriving key from password: %w", err)
	}

	// Decrypt Massa priv key
	massaKeyBytes, err := decryptPrivateKeyV2(ky.CipheredData, aesKey, ky.Nonce)
	if err != nil {
		return MassaAccount{}, fmt.Errorf("failed decrypting massa private key: %w", err)
	}

	log.Printf("massakaybytes: %v", massaKeyBytes)
	log.Printf("massaKeyByteslen: %v", len(massaKeyBytes))

	version, n := binary.Uvarint(massaKeyBytes)
	encodedPriv := encodePriv(massaKeyBytes[n:], version)

	log.Printf("encodedPriv: %v", encodedPriv)

	return accountFromPriv(encodedPriv)
}

func deriveKeyFromPasswordV2(password []byte, salt []byte, params kdfParams) ([]byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, 16) // 16 byte salt
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, fmt.Errorf("failed generating salt")
		}
	}

	key := pbkdf2.Key(password, salt, params.iter, params.keyLen, sha256.New)

	return key, salt, nil
}

func defaultKdfParams() kdfParams {
	return kdfParams{
		iter:   DEFAULT_KDF_ITER,
		keyLen: DEFAULT_KDF_KEY_LEN,
	}
}

func encryptPrivateKeyV2(plaintext []byte, encryptionKey []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed creating cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed instantiating gcm: %w", err)
	}

	var nonce = make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, nil, fmt.Errorf("failed generating nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	return ciphertext, nonce, nil
}

func decryptPrivateKeyV2(ciphertext []byte, decryptionKey []byte, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(decryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed generating new cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed instantiating gcm: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed decrypting ciphertext: %w", err)
	}

	return plaintext, nil
}

func generateKeystoreFileName(addr string) string {
	return fmt.Sprintf("keystore-%s-%d.yaml", addr, time.Now().UnixNano())
}
