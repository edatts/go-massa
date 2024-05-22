package massa

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// Just for keeping track of public methods.
type IMassaClient interface {

	// Wallet functionality
	GetAccount()
	GenerateAccount()
	ImportAccount()
	LoadAccount()
	LoadAccountFromPriv()
	GetWalletHome()
	SignOperation()
	SignMessage()

	// ApiClient functionality
	NewOperation()
	SendOperation()
	GetOperations()
	ReadSC()
	// Datastore methods...

	// MassaClient Functionality
	SendTransaction()
	CallSC()
}

// type massaOpts struct {
// }

type MassaClient struct {
	home   string
	wallet *Wallet
	api    *ApiClient
}

type massaClientOpts struct {
	home string
}

func defaultMassaClientOpts() *massaClientOpts {
	return &massaClientOpts{
		home: defaultHome(),
	}
}

func defaultHome() string {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("could not get user home dir: %s", err)
	}

	return filepath.Join(home, ".go-massa")
}

type massaClientOptFunc func(opts *massaClientOpts)

func WithHome(home string) massaClientOptFunc {
	return func(opts *massaClientOpts) {
		opts.home = home
	}
}

func NewClient(optFns ...massaClientOptFunc) *MassaClient {
	opts := defaultMassaClientOpts()
	for _, fn := range optFns {
		fn(opts)
	}

	return &MassaClient{
		home:   opts.home,
		wallet: NewWallet(WithWalletHome(filepath.Join(opts.home, "wallet"))),
		api:    NewApiClient(),
	}
}

func (c *MassaClient) Init(jsonRpcUrls ...string) error {

	if err := ensureDir(c.home); err != nil {
		return fmt.Errorf("failed ensureing home dir: %w", err)
	}

	if err := c.api.Init(jsonRpcUrls...); err != nil { // TODO: Add Api URLs...
		return fmt.Errorf("failed initializing api client: %w", err)
	}

	if err := c.wallet.Init(); err != nil {
		return fmt.Errorf("failed initializing api client: %w", err)
	}

	return nil
}

// Sends a transaction from the sender address to the
// recipient address.
//
// The amount argument should be a value in nanoMassa.
//
// Returns the operationId of the transacton as well as
// an error on failure.
func (c *MassaClient) SendTransaction(sender, recipientAddr string, amount uint64) (opId string, err error) {
	txData := NewTxData(amount, recipientAddr)
	return c.buildAndSendOperation(sender, txData)
}

// Calls a target smart contract with the provided call data
// from the caller address.
//
// Returns the operationId of the call, as well as an error
// in the event of failure.
func (c *MassaClient) CallSC(callerAddr, targetAddr, targetFunc string, params []byte, coins uint64) (opId string, err error) {
	callData, err := NewCallData(targetAddr, targetFunc, params, coins)
	if err != nil {
		return opId, fmt.Errorf("failed building call data: %w", err)
	}

	return c.buildAndSendOperation(callerAddr, callData)
}

func (c *MassaClient) buildAndSendOperation(from string, opData OperationData) (opId string, err error) {
	op, err := c.api.NewOperation(from, opData)
	if err != nil {
		return opId, fmt.Errorf("failed creating new operation: %w", err)
	}

	signedOp, err := c.wallet.SignOperation(op)
	if err != nil {
		return opId, fmt.Errorf("failed signing operation")
	}

	opId, err = c.api.SendOperation(signedOp)
	if err != nil {
		return opId, fmt.Errorf("failed sending operation: %w", err)
	}

	return opId, nil
}

func (c *MassaClient) ImportFromPriv(privEncoded, password string) (addr string, err error) {
	return c.wallet.ImportFromPriv(privEncoded, password)
}
