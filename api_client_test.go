package massa

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"testing"
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

// We're going to need to test a few things on buildernet
//	- Send MAS Transaction
//	- Read Smart Contract
//	- Call Smart Contract

func TestReadSC(t *testing.T) {

	// Need to use a funded account on buildnet becase Fee and
	// CallerAddress are not optional when using gRPC public API
	testAcc := getBuildnetTestAccount()

	wallet := NewWallet(WithWalletHome(testingWalletHome()))
	if err := wallet.Init(); err != nil {
		t.Errorf("failed initializing wallet: %s", err)
	}

	// Create and init api client
	apiClient := NewApiClient()
	if err := apiClient.Init(BUILDNET_JSON_RPC_ADDR); err != nil {
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
