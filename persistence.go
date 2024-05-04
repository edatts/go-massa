package massa

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/njones/base58"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
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
// TODO: Implement Massa Standard for encryption and
// 		 storage of keys on disk.
//

func defaultKeystoreDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("could not get user home path: %s", err)
	}

	return filepath.Join(home, ".go-massa", "wallet", "keys")
}

type ScryptParams struct {
	N      int
	r      int
	p      int
	keyLen int
}

type KeystoreFile struct {
	Address string `json:"address"`
	Crypto  Crypto `json:"crypto"`
}

type Crypto struct {
	Cipher       string       `json:"cipher"`
	Cipherparams CipherParams `json:"cipherparams"`
	Ciphertext   string       `json:"ciphertext"`
	Kdf          string       `json:"kdf"`
	Kdfparams    KdfParams    `json:"kdfparams"`
	Mac          string       `json:"mac"`
}

type CipherParams struct {
	Iv string `json:"iv"`
}

type KdfParams struct {
	Keylen int    `json:"keylen"`
	Salt   string `json:"salt"`
	N      int    `json:"n"`
	R      int    `json:"r"`
	P      int    `json:"p"`
}

func persistAccount(acc MassaAccount, password string, keystoreDir string) error {

	// Create keystore file
	kf, err := createKeystoreFile(acc, password)
	if err != nil {
		return fmt.Errorf("failed creating keystore file: %w", err)
	}

	// Marshal to JSON
	jsonBytes, err := json.Marshal(kf)
	if err != nil {
		return fmt.Errorf("failed marshalling json: %w", err)
	}

	// Check if file exists
	fileName := fmt.Sprintf("keystore-%s.json", acc.Addr())
	filePath := filepath.Join(keystoreDir, fileName)
	if exists, err := fileExists(filePath); err != nil {
		log.Printf("cloud not persist account: %s", err)
		return nil
	} else if exists {
		log.Printf("could not persist account: keystore file already exists for address (%s)", acc.Addr())
		return nil
	}

	// Save to disk
	f, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed creating file: %w", err)
	}
	defer f.Close()

	_, err = f.Write(jsonBytes)
	if err != nil {
		return fmt.Errorf("failed writing file: %w", err)
	}

	return nil
}

func createKeystoreFile(acc MassaAccount, password string) (KeystoreFile, error) {
	var passwordBytes []byte

	// Prompt user for password if not present
	if password == "" {
		fmt.Println("No password provided, please input a password: ")
		// password, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		password, err := readPassword()
		if err != nil {
			return KeystoreFile{}, fmt.Errorf("failed accepting user input: %w", err)
		}
		passwordBytes = password

		// This one doesn't hide user input on the screen...
		// if _, err := fmt.Scanln(&password); err != nil {
		// 	return KeystoreFile{}, fmt.Errorf("failed accepting user input")
		// }
	} else {
		passwordBytes = []byte(password)
	}

	// Derive cipher encryption/decryption key using scrypt
	var params = getDefaultScryptParams()
	encryptionKey, salt, err := deriveKeyFromPassword(passwordBytes, nil, params)
	if err != nil {
		return KeystoreFile{}, fmt.Errorf("failed deriving encryption key from password: %w", err)
	}

	// Encrypt private key
	ciphertext, iv, err := encryptPrivateKey([]byte(acc.priv.Encoded), encryptionKey)
	if err != nil {
		return KeystoreFile{}, fmt.Errorf("failed encrypting massa private key: %w", err)
	}

	// Derive mac
	// We must encrypt-then-mac, we must also concat the IV onto
	// the ciphertext before generating the MAC.
	hash := hmac.New(sha256.New, encryptionKey)
	hash.Write(ciphertext)
	hash.Write(iv)
	mac := hash.Sum(nil)

	// Encode ciphertext, iv, salt, mac
	encodedCipherText := base58.BitcoinEncoding.EncodeToString(ciphertext)
	encodedIV := base58.BitcoinEncoding.EncodeToString(iv)
	encodedSalt := base58.BitcoinEncoding.EncodeToString(salt)
	encodedMAC := base58.BitcoinEncoding.EncodeToString(mac)

	// Build keystore file
	keystoreFile := KeystoreFile{
		Address: acc.addr.Encoded,
		Crypto: Crypto{
			Cipher: "CTR",
			Cipherparams: CipherParams{
				Iv: encodedIV,
			},
			Ciphertext: encodedCipherText,
			Kdf:        "scrypt",
			Kdfparams: KdfParams{
				Keylen: params.keyLen,
				Salt:   encodedSalt,
				N:      params.N,
				R:      params.r,
				P:      params.p,
			},
			Mac: encodedMAC,
		},
	}

	return keystoreFile, nil
}

func getAccountFromKeystore(addr string, password string, keystoreDir string) (MassaAccount, error) {

	// Find corresponding keystore file
	fileName := fmt.Sprintf("keystore-%s.json", addr)
	fullPath := filepath.Join(keystoreDir, fileName)
	f, err := os.Open(fullPath)
	if err != nil {
		return MassaAccount{}, fmt.Errorf("failed opening keystore file: %w", err)
	}
	defer f.Close()

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(f)
	if err != nil {
		return MassaAccount{}, fmt.Errorf("failed reading from file: %w", err)
	}

	var kf KeystoreFile
	if err = json.Unmarshal(buf.Bytes(), &kf); err != nil {
		return MassaAccount{}, fmt.Errorf("failed unmarshalling keystore json: %w", err)
	}

	// Decode encoded keystore fields
	var ciphertext, iv, salt, expectedMac []byte
	if ciphertext, err = base58.BitcoinEncoding.DecodeString(kf.Crypto.Ciphertext); err != nil {
		return MassaAccount{}, fmt.Errorf("failed decoding ciphertext: %w", err)
	}
	if iv, err = base58.BitcoinEncoding.DecodeString(kf.Crypto.Cipherparams.Iv); err != nil {
		return MassaAccount{}, fmt.Errorf("failed decoding iv: %w", err)
	}
	if salt, err = base58.BitcoinEncoding.DecodeString(kf.Crypto.Kdfparams.Salt); err != nil {
		return MassaAccount{}, fmt.Errorf("failed decoding salt: %w", err)
	}
	if expectedMac, err = base58.BitcoinEncoding.DecodeString(kf.Crypto.Mac); err != nil {
		return MassaAccount{}, fmt.Errorf("failed decoding expected mac: %w", err)
	}

	// Derive AES key
	scryptParams := getScryptParamsFromKeystoreFile(kf)
	aesKey, _, err := deriveKeyFromPassword([]byte(password), salt, scryptParams)
	if err != nil {
		return MassaAccount{}, fmt.Errorf("failed deriving key from password: %w", err)
	}

	// Verify MAC
	hash := hmac.New(sha256.New, aesKey)
	hash.Write(ciphertext)
	hash.Write(iv)
	mac := hash.Sum(nil)

	if !hmac.Equal(mac, expectedMac) {
		return MassaAccount{}, ErrWrongMac
		// return MassaAccount{}, fmt.Errorf("derived mac does not match mac in keystore file")
	}

	// Decrypt Massa priv key
	massaKeyBytes, err := decryptPrivateKey(ciphertext, aesKey, iv)
	if err != nil {
		return MassaAccount{}, fmt.Errorf("failed decrypting massa private key: %w", err)
	}

	return accountFromPriv(string(massaKeyBytes))
}

func deriveKeyFromPassword(password []byte, salt []byte, params ScryptParams) ([]byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, fmt.Errorf("failed generating salt")
		}
	}

	key, err := scrypt.Key(password, salt, params.N, params.r, params.p, params.keyLen)
	if err != nil {
		return nil, nil, fmt.Errorf("failed deriving key: %w", err)
	}

	return key, salt, nil
}

func getDefaultScryptParams() ScryptParams {
	return ScryptParams{
		N:      DEFAULT_KDF_N,
		r:      DEFAULT_KDF_R,
		p:      DEFAULT_KDF_P,
		keyLen: DEFAULT_KDF_KEY_LEN,
	}
}

func getScryptParamsFromKeystoreFile(kf KeystoreFile) ScryptParams {
	return ScryptParams{
		N:      kf.Crypto.Kdfparams.N,
		r:      kf.Crypto.Kdfparams.R,
		p:      kf.Crypto.Kdfparams.P,
		keyLen: kf.Crypto.Kdfparams.Keylen,
	}
}

func encryptPrivateKey(plaintext []byte, encryptionKey []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed generating new cipher block: %w", err)
	}

	iv := make([]byte, block.BlockSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, fmt.Errorf("failed generating iv: %w", err)
	}

	stream := cipher.NewCTR(block, iv)
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	return ciphertext, iv, nil
}

func decryptPrivateKey(ciphertext []byte, decryptionKey []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(decryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed generating new cipher block: %w", err)
	}

	stream := cipher.NewCTR(block, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

func readPassword() ([]byte, error) {
	stdin := int(syscall.Stdin)
	oldState, err := term.GetState(stdin)
	if err != nil {
		return nil, err
	}
	defer term.Restore(stdin, oldState)

	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, os.Interrupt)
	go func() {
		for range sigch {
			term.Restore(stdin, oldState)
			os.Exit(1)
		}
	}()

	password, err := term.ReadPassword(stdin)
	if err != nil {
		close(sigch)
		return nil, err
	}
	close(sigch)

	return password, nil
}
