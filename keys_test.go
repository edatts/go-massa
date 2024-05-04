package massa

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

// Test sign and verify
// func TestSignAndVerify(t *testing.T) {

// }

func TestKeyEncodings(t *testing.T) {
	// Generate new keys, encode them, assert prefixes, decode
	// priv, and assert it is the same as original.

	var numTestRuns = 100

	for i := 0; i < numTestRuns; i++ {

		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Errorf("failed generating keys: %s", err)
		}

		// log.Printf("Priv bytes: %v", priv)

		massaPub := newMassaPubKey(pub)
		massaPriv := newMassaPrivKey(priv)
		massaAddr := newMassaAddress(massaPub)

		if !strings.HasPrefix(massaPub.Encoded, PUBLIC_KEY_PREFIX) {
			t.Errorf("incorrect pubkey prefix, expected (%s), actual pubkey: (%s)", PUBLIC_KEY_PREFIX, massaPub.Encoded)
		}

		if !strings.HasPrefix(massaPriv.Encoded, SECRET_KEY_PREFIX) {
			t.Errorf("incorrect private key prefix, expected (%s), actual private key: (%s)", SECRET_KEY_PREFIX, massaPriv.Encoded)
		}

		if !strings.HasPrefix(massaAddr.Encoded, ADDRESS_USER_PREFIX) {
			t.Errorf("incorrect address prefix expected (%s), actual address: (%s)", ADDRESS_USER_PREFIX, massaAddr.Encoded)
		}

		// log.Printf("Encoded private key: %s", massaPriv.encoded)

		decodedPriv, version, err := decodePriv(massaPriv.Encoded)
		if err != nil {
			t.Errorf("failed decoding private key: %s", err)
		}

		// log.Printf("Decoded priv bytes: %v", decodedPriv)

		if version != KEYS_VERSION_NUMBER {
			t.Errorf("wrong version number, got (%d), expected (%d)", version, KEYS_VERSION_NUMBER)
		}

		if string(decodedPriv) != string(priv[:32]) {
			t.Errorf("wrong decoded private key bytes")
		}

	}

}

// Test keys errors
// func TestKeysDecodeErrors(t *testing.T) {

// 	// Invalid Massa priv err

// 	// Base58 decode err

// 	// Read uvarint err

// 	// Privlength err

// }
