package massa

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/njones/base58"
	"github.com/zeebo/blake3"
)

// MassaPrivateKey contains the crypto ed25519.PrivateKey,
// the bas58 encoded secret key, and the key Version.
type massaPrivKey struct {
	Key     ed25519.PrivateKey
	Encoded string // base58 encoded string with version
	Version uint64
}

func (p massaPrivKey) sign(msg []byte) []byte {
	return ed25519.Sign(p.Key, msg)
}

type massaPubKey struct {
	Key     ed25519.PublicKey
	Encoded string
	Version uint64
}

func (p massaPubKey) verify(msg, sig []byte) bool {
	return ed25519.Verify(p.Key, msg, sig)
}

type massaAddress struct {
	Encoded string
	Version uint64
	Bytes   []byte
	IsUser  bool
}

type MassaSignature struct {
	PublicKey  string
	Serialized []byte
	Encoded    string
}

func newMassaPrivKey(key ed25519.PrivateKey) massaPrivKey {
	return massaPrivKey{
		Key:     key,
		Encoded: encodePriv(key[:32], KEYS_VERSION_NUMBER),
		Version: KEYS_VERSION_NUMBER,
	}
}

func encodePriv(priv ed25519.PrivateKey, version uint64) string {
	body := encodeBytes([]byte(priv), version)
	return fmt.Sprintf("%s%s", SECRET_KEY_PREFIX, body)
}

func decodePriv(encoded string) (ed25519.PrivateKey, uint64, error) {
	encoded, ok := strings.CutPrefix(encoded, SECRET_KEY_PREFIX)
	if !ok {
		return nil, 0, ErrInvalidMassaPriv
	}

	decoded, err := base58.BitcoinEncoding.DecodeString(encoded)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %s", ErrDecodeFailed, err)
	}

	version, n := binary.Uvarint(decoded)
	if n <= 0 {
		return nil, 0, ErrReadUvarint
	}

	if len(decoded[n:]) != 32 {
		return nil, 0, ErrPrivLength
	}

	priv := ed25519.PrivateKey(decoded[n:])

	return priv, version, nil
}

func newMassaPubKey(key ed25519.PublicKey) massaPubKey {
	return massaPubKey{
		Key:     key,
		Encoded: encodePub(key, KEYS_VERSION_NUMBER),
		Version: KEYS_VERSION_NUMBER,
	}
}

func encodePub(pub ed25519.PublicKey, version uint64) string {
	body := encodeBytes([]byte(pub), version)
	return fmt.Sprintf("%s%s", PUBLIC_KEY_PREFIX, body)
}

// TODO: Implement...
func decodePub(encoded string) (ed25519.PublicKey, uint64, error) {

	return nil, 0, nil
}

func encodeBytes(bytes []byte, version uint64) string {
	var buf []byte
	buf = binary.AppendUvarint(buf, version)
	buf = append(buf, bytes...)
	return base58.BitcoinEncoding.EncodeToString(buf)
}

func newMassaAddress(massaPub massaPubKey) massaAddress {
	var versionBuf []byte
	versionBuf = binary.AppendUvarint(versionBuf, massaPub.Version)

	var toHashBuf []byte
	toHashBuf = binary.AppendUvarint(toHashBuf, massaPub.Version)
	toHashBuf = append(toHashBuf, []byte(massaPub.Key)...)

	hasher := blake3.New()
	hasher.Write(toHashBuf)
	hash := hasher.Sum(nil)

	var toEncode []byte
	toEncode = append(toEncode, versionBuf...)
	toEncode = append(toEncode, hash...)

	encoded := base58.BitcoinEncoding.EncodeToString(toEncode)

	addressCategory := 0

	addrBytes := []byte{byte(addressCategory)}
	addrBytes = append(addrBytes, toEncode...)

	return massaAddress{
		Encoded: fmt.Sprintf("%s%s", ADDRESS_USER_PREFIX, encoded),
		Bytes:   addrBytes,
		Version: massaPub.Version,
		IsUser:  true,
	}
}

func addressToBytes(addr string, isUser bool) ([]byte, error) {
	var addrBytes = []byte{}
	var cutAddr string

	// Remove prefix
	switch isUser {
	case true:

		after, ok := strings.CutPrefix(addr, ADDRESS_USER_PREFIX)
		if !ok {
			return nil, fmt.Errorf("user address prefix not found in provided address")
		}

		cutAddr = after

		addrBytes = append(addrBytes, 0)

	case false:

		after, ok := strings.CutPrefix(addr, ADDRESS_CONTRACT_PREFIX)
		if !ok {
			return nil, fmt.Errorf("contract address prefix not found in provided address")
		}

		cutAddr = after

		addrBytes = append(addrBytes, 1)

	}

	decoded, err := base58.BitcoinEncoding.DecodeString(cutAddr)
	if err != nil {
		return nil, fmt.Errorf("failed decoding user address: %w", err)
	}

	addrBytes = append(addrBytes, decoded...)

	return addrBytes, nil
}

// TODO: Implement...
func encodedPubToBytes(encodedPub string) ([]byte, error) {

	return nil, nil
}

func addressIsContract(addr string) bool {
	return strings.HasPrefix(addr, ADDRESS_CONTRACT_PREFIX)
}

func addressIsUser(addr string) bool {
	return strings.HasPrefix(addr, ADDRESS_USER_PREFIX)
}
