package massa

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"testing"
	"time"
	// apipb "github.com/edatts/massa-wallet/protos/massa/api/v1"
	// "github.com/njones/base58"
	// "github.com/zeebo/blake3"
	// massapb "github.com/edatts/massa-wallet/protos/massa/model/v1"
)

const (
	BUILDNET_JSON_RPC_ADDR = "https://buildnet.massa.net/api/v2"

	DUSA_FACTORY_CONTRACT_BUILDNET = "AS125Y3UWiMoEx3w71jf7iq1RwkxXdwkEVdoucBTAmvyzGh2KUqXS"

	WMAS_CONTRACT_BUILDNET = "AS12FW5Rs5YN2zdpEnqwj4iHUUPt9R4Eqjq2qtpJFNKW3mn33RuLU"
	USDC_CONTRACT_BUILDNET = "AS12N76WPYB3QNYKGhV2jZuQs1djdhNJLQgnm7m52pHWecvvj1fCQ"
	DAI_CONTRACT_BUILDNET  = "AS124FuWHWqiWurCvobu5ovTGucWJPa6ouHbGLQ9e7kMwWt2Xsm84"
	WETH_CONTRACT_BUILDNET = "AS12rcqHGQ3bPPhnjBZsYiANv9TZxYp96M7r49iTMUrX8XCJQ8Wrk"

	MAINNET_JSON_RPC_ADDR = "https://mainnet.massa.net/api/v2"

	DUSA_FACTORY_CONTRACT_MAINNET = "AS1rahehbQkvtynTomfoeLmwRgymJYgktGv5xd1jybRtiJMdu8XX"

	WMAS_CONTRACT_MAINNET = "AS12U4TZfNK7qoLyEERBBRDMu8nm5MKoRzPXDXans4v9wdATZedz9"
	USDC_CONTRACT_MAINNET = "AS1hCJXjndR4c9vekLWsXGnrdigp4AaZ7uYG3UKFzzKnWVsrNLPJ"
	DAI_CONTRACT_MAINNET  = "AS1ZGF1upwp9kPRvDKLxFAKRebgg7b3RWDnhgV7VvdZkZsUL7Nuv"
	WETH_CONTRACT_MAINNET = "AS124vf3YfAJCSCQVYKczzuWWpXrximFpbTmX4rheLs5uNSftiiRY"
)

// func TestJsonRpcCall(t *testing.T) {

// 	addr := "https://mainnet.massa.net/api/v2"

// 	publicJsonRpcGetStatus(addr)

// }

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

	// Create account
	acc, err := accountFromPriv("S1CkpvD4WMjJWxR2WZcrDEkJ1kWG2kKe1e3Afe8miqmskHqovvA")
	if err != nil {
		t.Errorf("failed getting account from priv key: %s", err)
	}

	// Build TxData
	txData := TxData{
		fee:           0.001 * 1e9,
		amount:        3.1 * 1e9,
		recipientAddr: "AU12v83xmHg2UrLM8GLsXRMrm7LQgn3DZVT6kUeFsuFyhZKLkbQtY",
	}

	var (
		expiryPeriod uint64 = 1000
		chainId      uint64 = 77658383
	)

	serializedOp, opId, err := serializeOperation(acc, txData, uint64(expiryPeriod), uint64(chainId))
	if err != nil {
		t.Errorf("failed serializing transaction operation")
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

	// opContentBytes, err := compactBytesForOperation(txData, expiryPeriod)
	// if err != nil {
	// 	t.Errorf("failed compacting bytes for operation: %s", err)
	// }

	// var serializedPub []byte
	// serializedPub = binary.AppendUvarint(serializedPub, acc.priv.Version)
	// serializedPub = append(serializedPub, acc.pub.Key...)

	// hasher := blake3.New()
	// hasher.Write(getBytesToHash(chainId, serializedPub, opContentBytes))
	// digest := hasher.Sum(nil)

	// var serializedOpId []byte
	// serializedOpId = binary.AppendUvarint(serializedOpId, acc.priv.Version)
	// serializedOpId = append(serializedOpId, digest...)

	// opId := OPERATION_ID_PREFIX + base58.BitcoinEncoding.EncodeToString(serializedOpId)

	if opId != expectedOpId {
		t.Errorf("wrong operation id, expected (%s), got (%s)", expectedOpId, opId)
	}

}

// We're going to need to test a few things on buildernet
//	- Send MAS Transaction
//	- Read Smart Contract
//	- Call Smart Contract

func TestReadSC(t *testing.T) {

	// Need to use a funded account on buildnet becase Fee and
	// CallerAddress are not optional when using gRPC public API
	testAcc := getBuildnetTestAccount()

	wallet := NewWallet(WithCustomHome(testingWalletHome()))
	if err := wallet.Init(); err != nil {
		t.Errorf("failed initializing wallet: %s", err)
	}

	// Create and init api client
	apiClient := NewApiClient()
	if err := apiClient.Init(wallet, BUILDNET_JSON_RPC_ADDR); err != nil {
		t.Errorf("failed initializing api client: %s", err)
	}

	// Call the `getAllLBPairs` method on the Dusa Factory
	// contract on buildnet.

	// Serialize params
	wmasAddrBytes := []byte(WMAS_CONTRACT_BUILDNET)
	usdcAddrBytes := []byte(USDC_CONTRACT_BUILDNET)

	var params []byte
	params = binary.LittleEndian.AppendUint32(params, uint32(len(wmasAddrBytes)))
	params = append(params, wmasAddrBytes...)
	params = binary.LittleEndian.AppendUint32(params, uint32(len(usdcAddrBytes)))
	params = append(params, usdcAddrBytes...)

	callData := CallData{
		Fee:            10_000_000,
		MaxGas:         10_000_000,
		Coins:          0,
		TargetAddress:  DUSA_FACTORY_CONTRACT_BUILDNET,
		TargetFunction: "getAllLBPairs",
		Parameter:      params,
	}

	res, err := apiClient.ReadSC(testAcc.addr.Encoded, callData)
	if err != nil {
		t.Errorf("failed reading smart contract: %s", err)
	}

	if len(res) == 0 {
		t.Errorf("no bytes received from contract read")
	}

}

func TestCallSC(t *testing.T) {

	// Test flow:
	//	- Check test wallet WMAS balance.
	// 	- Call the `deposit` method on the WMAS contract.
	//	- Assert that WMAS balance increased.

	// Expected storage cost 96 * 100_000 nMAS
	//	96_000_000 nMAS

	testAcc := getBuildnetTestAccount()

	wallet := NewWallet(WithCustomHome(testingWalletHome()))
	if err := wallet.Init(); err != nil {
		t.Errorf("failed initializing wallet: %s", err)
	}

	testAddr, err := wallet.ImportFromPriv(testAcc.priv.Encoded, "password")
	if err != nil {
		t.Errorf("failed importing test account: %s", err)
	}

	var (
		amountToWrap uint64 = 100_000_000 // in nMAS
		storageCost  uint64 = 9_600_000
	)

	// Create and init api client
	apiClient := NewApiClient()
	if err := apiClient.Init(wallet, BUILDNET_JSON_RPC_ADDR); err != nil {
		t.Errorf("failed initializing api client: %s", err)
	}

	// Get initial balance
	initialBalance, err := getWMABalance(apiClient, testAcc.addr.Encoded)
	if err != nil {
		t.Errorf("failed getting initial wmas balance: %s", err)
	}

	callData := CallData{
		Fee:            10_000_000,
		MaxGas:         10_000_000,
		Coins:          amountToWrap,
		TargetAddress:  WMAS_CONTRACT_BUILDNET,
		TargetFunction: "deposit",
	}

	_, err = apiClient.CallSC(testAddr, callData)
	if err != nil {
		t.Errorf("failed calling contract: %s", err)
	}

	// Sleep to give time for network to see tx
	time.Sleep(20 * time.Second)

	newBalance, err := getWMABalance(apiClient, testAcc.addr.Encoded)
	if err != nil {
		t.Errorf("failed getting new balance: %s", err)
	}

	var expectedBalanceDiff uint64
	if initialBalance.Cmp(big.NewInt(0)) == 0 {
		// Factor in storage cost
		expectedBalanceDiff = amountToWrap - storageCost
	} else {
		// Ignore storage cost
		expectedBalanceDiff = amountToWrap
	}

	balanceDiff := big.NewInt(0).Sub(newBalance, initialBalance).Uint64()

	if balanceDiff != expectedBalanceDiff {
		t.Errorf("enexpected balance diff, expected (%d), got (%d)", expectedBalanceDiff, balanceDiff)
	}
}

// func TestGetContractDatastoreKeys(t *testing.T) {

// 	// Create and init api client
// 	apiClient := NewApiClient()
// 	// if err := apiClient.Init([]string{BUILDNET_JSON_RPC_ADDR}); err != nil {
// 	if err := apiClient.Init([]string{MAINNET_JSON_RPC_ADDR}); err != nil {
// 		t.Errorf("failed initializing api client: %s", err)
// 	}

// 	// testAcc := GetBuildnetTestAccount()

// 	// apiClient.getContractDatastoreKeys(DUSA_FACTORY_CONTRACT_BUILDNET)
// 	// apiClient.getContractDatastoreKeys(WMAS_CONTRACT_BUILDNET)
// 	apiClient.getContractDatastoreKeys(USDC_CONTRACT_MAINNET)
// }

// This function uses fake entropy to generate the same
// account every time it is called. Useful for running
// tests that require gas and for read only calls
// through the gRPC API.
func getBuildnetTestAccount() MassaAccount {
	// Expected Addr:
	//	AU12gVQnvkJhYJkkoFXsqqyYbKHYaiM4t3zmJVDrDGkaGasENRDBJ

	var fakeEntropy = rand.New(rand.NewSource(888))
	pub, priv, err := ed25519.GenerateKey(fakeEntropy)
	if err != nil {
		log.Fatalf("failed generating ed25519 keys")
	}

	return newMassaAccount(priv, pub)
}

// Checks the candidate value because we don't care about
// finality for testing.
func getWMABalance(apiClient *ApiClient, addr string) (*big.Int, error) {

	key := fmt.Sprintf("%s%s", "BALANCE", addr) // `BALANCE<ADDRESS>`
	entry, err := apiClient.getDataStoreEntry(WMAS_CONTRACT_BUILDNET, key)
	if err != nil {
		return big.NewInt(0), fmt.Errorf("failed getting datastore entry: %s", err)
	}

	// log.Printf("Key bytes length: %d", len([]byte(key)))
	// log.Printf("Datastore key: %s Entry: %v", key, entry)
	// log.Printf("Entry candidate val: %v", entry.CandidateValue)
	// log.Printf("Entry final val: %v", entry.FinalValue)
	// log.Printf("Value (little-endian): %v", entry.FinalValue)

	// Convert to big-endian
	arr, last := entry.CandidateValue, len(entry.CandidateValue)-1
	for i := 0; i < len(entry.CandidateValue)/2; i++ {
		arr[i], arr[last-i] = arr[last-i], arr[i]
	}

	return big.NewInt(0).SetBytes(arr), nil
}

// TODO: Add tests for reconnect logic...
//	- Will need to simulate an API failure by manually
//	  injecting a bad publicApiSvc into the client struct.

func TestGetDatastoreKeys(t *testing.T) {

}
