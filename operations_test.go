package massa

import (
	"log"
	"os"
	"path/filepath"
	"testing"
)

func testingHome() string {
	workDir, err := os.Getwd()
	if err != nil {
		log.Fatal("Failed getting working dir...")
	}

	return filepath.Join(workDir, "testStorage", "massaHome")
}

func TestSerializeTransactionOperation(t *testing.T) {

	//// ---------- From Docs ---------- ////
	// https://docs.massa.net/docs/learn/operation-format-execution#example-of-legal-operation-with-valid-signature
	//
	// Chain id: 77658383
	// Sender Secret key in text format: S1CkpvD4WMjJWxR2WZcrDEkJ1kWG2kKe1e3Afe8miqmskHqovvA
	// Sender Public key in text format: P1t4JZwHhWNLt4xYabCbukyVNxSbhYPdF6wCYuRmDuHD784juxd
	// Sender Address in text format: AU12m1gXHUGxBZsDF4veeWfYaRmpztBCieHhPBaqf3fcRF2LdAuZ7
	// Operation fee: 0.001
	// Operation expiry period: 1000
	// Operation type: Transaction
	// Transaction operation payload:
	// Destination address in text format: AU12v83xmHg2UrLM8GLsXRMrm7LQgn3DZVT6kUeFsuFyhZKLkbQtY
	// Amount: 3.1
	//
	// Resulting operation ID in text format: O12CRpeqSW1NenBZ7pN79ZZz454xkbeQBGspyu4gKVXcYndm8gxw
	//
	// Raw bytes in hexadecimal representation of the binary serialization of the operation:
	// 00 FE C0 79 BE 60 05 EF D4 2A 1D 6A 03 0D D3 FB
	// 99 56 F9 FC C7 C8 78 9B 11 8D 25 1A 58 72 16 4F
	// 10 48 51 F2 57 20 FD 48 F9 FD 24 C3 6D 5B D3 16
	// 47 E9 B7 05 E2 DE F8 6C F3 B5 CE BA D2 9F 86 26
	// 0A 00 73 EE 58 D3 51 9D 54 03 E9 8F EF 60 35 4C
	// DE 6C 7D A1 73 C1 6C 8C 6C 58 CF C8 6E E5 21 51
	// 3C A6 C0 84 3D E8 07 00 00 00 FC 50 AB 9B 1B 78
	// 4A B1 93 0E 5C F3 84 3E 8A E6 7C 59 42 1B 01 55
	// 10 82 B0 25 90 91 4B 4C 2A 0A 80 FE 98 C6 0B

	expectedOpId := "O12CRpeqSW1NenBZ7pN79ZZz454xkbeQBGspyu4gKVXcYndm8gxw"

	expectedBytes := []byte{
		0x00, 0xFE, 0xC0, 0x79, 0xBE, 0x60, 0x05, 0xEF, 0xD4, 0x2A, 0x1D, 0x6A, 0x03, 0x0D, 0xD3, 0xFB,
		0x99, 0x56, 0xF9, 0xFC, 0xC7, 0xC8, 0x78, 0x9B, 0x11, 0x8D, 0x25, 0x1A, 0x58, 0x72, 0x16, 0x4F,
		0x10, 0x48, 0x51, 0xF2, 0x57, 0x20, 0xFD, 0x48, 0xF9, 0xFD, 0x24, 0xC3, 0x6D, 0x5B, 0xD3, 0x16,
		0x47, 0xE9, 0xB7, 0x05, 0xE2, 0xDE, 0xF8, 0x6C, 0xF3, 0xB5, 0xCE, 0xBA, 0xD2, 0x9F, 0x86, 0x26,
		0x0A, 0x00, 0x73, 0xEE, 0x58, 0xD3, 0x51, 0x9D, 0x54, 0x03, 0xE9, 0x8F, 0xEF, 0x60, 0x35, 0x4C,
		0xDE, 0x6C, 0x7D, 0xA1, 0x73, 0xC1, 0x6C, 0x8C, 0x6C, 0x58, 0xCF, 0xC8, 0x6E, 0xE5, 0x21, 0x51,
		0x3C, 0xA6, 0xC0, 0x84, 0x3D, 0xE8, 0x07, 0x00, 0x00, 0x00, 0xFC, 0x50, 0xAB, 0x9B, 0x1B, 0x78,
		0x4A, 0xB1, 0x93, 0x0E, 0x5C, 0xF3, 0x84, 0x3E, 0x8A, 0xE6, 0x7C, 0x59, 0x42, 0x1B, 0x01, 0x55,
		0x10, 0x82, 0xB0, 0x25, 0x90, 0x91, 0x4B, 0x4C, 0x2A, 0x0A, 0x80, 0xFE, 0x98, 0xC6, 0x0B,
	}

	var (
		priv     = "S1CkpvD4WMjJWxR2WZcrDEkJ1kWG2kKe1e3Afe8miqmskHqovvA"
		password = "password"
	)

	wallet := NewWallet(WithWalletHome(testingWalletHome()))
	if err := wallet.Init(); err != nil {
		t.Errorf("failed initializing wallet: %s", err)
	}

	addr, err := wallet.ImportFromPriv(priv, password)
	if err != nil {
		t.Errorf("failed importing private key: %s", err)
	}

	// Build TxData
	var (
		fee           uint64 = 0.001 * 1e9
		amount        uint64 = 3.1 * 1e9
		recipientAddr        = "AU12v83xmHg2UrLM8GLsXRMrm7LQgn3DZVT6kUeFsuFyhZKLkbQtY"
	)

	txData := TxData{
		fee:           fee,
		amount:        amount,
		recipientAddr: recipientAddr,
	}

	var (
		expiryPeriod uint64 = 1000
		chainId      uint64 = 77658383
	)

	opContent, err := compactBytesForOperation(txData, expiryPeriod)
	if err != nil {
		t.Errorf("failed compacting operation bytes: %s", err)
	}

	op := Operation{
		from:         addr,
		expiryPeriod: expiryPeriod,
		chainId:      chainId,
		opData:       txData,
		content:      opContent,
	}

	op, err = wallet.SignOperation(op)
	if err != nil {
		t.Errorf("failed signing operation: %s", err)
	}

	serializedOp, opId, err := op.Serialize()
	if err != nil {
		t.Errorf("failed serializing transaction operation: %s", err)
	}

	if len(serializedOp) != len(expectedBytes) {
		t.Errorf("serialized operation is wrong length, expected (%d), got (%d)", len(expectedBytes), len(serializedOp))
		return
	}

	// Assert serialized op
	for i, b := range serializedOp {
		if b != expectedBytes[i] {
			t.Errorf("wrong byte at index (%d), expected (%b), got (%b)", i, expectedBytes[i], b)
			continue
		}
	}

	if opId != expectedOpId {
		t.Errorf("wrong operation id, expected (%s), got (%s)", expectedOpId, opId)
	}

}
