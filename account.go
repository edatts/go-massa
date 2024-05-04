package massa

import (
	"crypto/ed25519"
	"fmt"
	//
	// Imports for supporting seed phrases and implementing
	// heirarchical deterministic wallets:
	// "github.com/tyler-smith/go-bip39"
	// slip10 "github.com/vegaprotocol/go-slip10" // Use different slip10 module
)

type MassaAccount struct {
	priv massaPrivKey
	pub  massaPubKey
	addr massaAddress
}

func (m *MassaAccount) Sign(msg []byte) []byte {
	return m.priv.sign(msg)
}

func (m *MassaAccount) Verify(msg, sig []byte) bool {
	return m.pub.verify(msg, sig)
}

func (m *MassaAccount) Addr() string {
	return m.addr.Encoded
}

// Generates a Massa Account and saves the corresponding keystore
// file to defaultKeystorePath(). The user will be prompted
// for a password.
//
// Returns the generated account.
func GenerateAccount() (MassaAccount, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return MassaAccount{}, fmt.Errorf("failed generating keypair: %w", err)
	}

	acc := newMassaAccount(priv, pub)

	if err := persistAccount(acc, "", defaultKeystorePath()); err != nil {
		return MassaAccount{}, fmt.Errorf("failed saving account to file: %w", err)
	}

	return acc, nil
}

// Imports the account into the wallet at the default keystore
// location (see defaultKeystorePath()). The user will be prompted
// for a password.
//
// Returns the imported account.
func ImportAccount(privEncoded string) (MassaAccount, error) {

	acc, err := accountFromPriv(privEncoded)
	if err != nil {
		return MassaAccount{}, fmt.Errorf("failed deriving account from private key: %w", err)
	}

	if err := persistAccount(acc, "", defaultKeystorePath()); err != nil {
		return MassaAccount{}, fmt.Errorf("failed saving account to file: %s", err)
	}

	return acc, nil
}

func newMassaAccount(priv ed25519.PrivateKey, pub ed25519.PublicKey) MassaAccount {
	massaPriv := newMassaPrivKey(priv)
	massaPub := newMassaPubKey(pub)

	return MassaAccount{
		priv: massaPriv,
		pub:  massaPub,
		addr: newMassaAddress(massaPub),
	}
}
