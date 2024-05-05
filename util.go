package massa

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"

	"github.com/zeebo/blake3"
)

func dirExists(path string) (bool, error) {
	fi, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed stating path: %w", err)
	}

	if !fi.IsDir() {
		return false, fmt.Errorf("'%s' exists but is not a dir", fi.Name())
	}

	return true, nil
}

func fileExists(path string) (bool, error) {
	fi, err := os.Stat(path)
	if err == nil {
		if fi.IsDir() {
			return false, ErrIsDir
		}
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("failed stating path: %w", err)
}

func ensureDir(dirPath string) error {
	_, err := os.Stat(dirPath)
	if err != nil {
		if os.IsNotExist(err) {
			return os.MkdirAll(dirPath, 0700)
		}
		return fmt.Errorf("failed stating dir: %w", err)
	}
	return nil
}

func writeFile(path string, payload []byte) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("failed opening file: %w", err)
	}
	defer f.Close()

	_, err = f.Write(payload)
	if err != nil {
		return fmt.Errorf("failed writing to file at (%s): %w", path, err)
	}

	return nil
}

func readFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed opening file: %w", err)
	}
	defer f.Close()
	return io.ReadAll(f)
}

func passwordEncrypt(password string, payload []byte) ([]byte, error) {
	var encrypted []byte

	// No err because key length is guaranteed by hash func
	block, _ := aes.NewCipher(hashSha256([]byte(password)))
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed instantiating GCM cipher mode: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed generating nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, payload, nil)

	// Append nonce and ciphertext to result
	encrypted = append(encrypted, nonce...)
	encrypted = append(encrypted, ciphertext...)

	return encrypted, nil
}

func passwordDecrypt(password string, payload []byte) ([]byte, error) {

}

func hashSha256(payload []byte) []byte {
	hash := sha256.New()
	hash.Write(payload)
	return hash.Sum(nil)
}

func hashBlake3(payload []byte) []byte {
	hasher := blake3.New()
	hasher.Write(payload)
	return hasher.Sum(nil)
}
