package massa

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	apipb "github.com/edatts/go-massa/protos/massa/api/v1"
	massapb "github.com/edatts/go-massa/protos/massa/model/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
)

// RpcType is an enum that represents one of two types
// of RPC that is available on each ApiProvider
type RpcType int

const (
	JSON_RPC RpcType = iota
	GRPC
)

func (r RpcType) String() string {
	return []string{
		"JSON-RPC",
		"gRPC",
	}[r]
}

// A request that is used to asynchronously get an
// ApiProvider from the api manager.
type GetProviderRequest struct {
	RpcType  RpcType
	Retries  uint32
	ResultCh chan apiProvider
	ErrorCh  chan error
}

// ApiClient embeds an api manager that handles automatic
// api discovery, api reconnects, and getting api
// endpoints.
//
// Exports methods for interacting with the blockchain
// through the JSON-RPC and gRPC APIs.
type ApiClient struct {
	publicApiSvc apipb.PublicServiceClient
	*apiManager
}

type apiClientOptFn func(*apiClientOpts)

type apiClientOpts struct {
	*apiManagerOpts
}

func defaultApiClientOpts() *apiClientOpts {
	return &apiClientOpts{
		apiManagerOpts: &apiManagerOpts{
			targetNumAvailGrpc:       DEFAULT_TARGET_NUM_GRPC_AVAILABLE,
			getProviderRetryInterval: DEFAULT_GET_PROVIDER_RETRY_INTERVAL,
			getProviderMaxRetries:    DEFAULT_GET_PROVIDER_MAX_RETRIES,
		},
	}
}

// Configuration function to set the target number of
// gRPC APIs that should be available at any one time.
// If not enough APIs are accessible then the embedded
// apiManager will attempt to discover more.
func WithNumAvailable(val uint32) apiClientOptFn {
	return func(opts *apiClientOpts) {
		opts.targetNumAvailGrpc = val
	}
}

// COnfiguration function that sets the amount of time
// to wait after a failed getProvider request before
// trying again.
func WithRetryInterval(val time.Duration) apiClientOptFn {
	return func(opts *apiClientOpts) {
		opts.getProviderRetryInterval = val
	}
}

// Configuration function that sets the maximum number
// of retries before a getProvider request will return
// an error.
func WithMaxRetries(val uint32) apiClientOptFn {
	return func(opts *apiClientOpts) {
		opts.getProviderMaxRetries = val
	}
}

// Returns a pointer to a new ApiClient, configurable with
// the provided configuration functions.
func NewApiClient(optFns ...apiClientOptFn) *ApiClient {
	opts := defaultApiClientOpts()
	for _, fn := range optFns {
		fn(opts)
	}
	return &ApiClient{
		apiManager: newApiManager(opts.apiManagerOpts),
	}
}

// Init carries out the following steps: Starts initial
// endpoint discovery, waits for an available gRPC
// endpoint, and instantiates public grpc service client.
//
// Returns error on failure to instantiate client
func (a *ApiClient) Init(ApiUrls ...string) error {

	if err := a.initApiManager(ApiUrls); err != nil {
		return fmt.Errorf("failed initializing api manager: %s", err)
	}

	grpcAddr, err := a.awaitGrpcAddr()
	if err != nil {
		return fmt.Errorf("failed awaiting grpc address: %w", err)
	}

	a.setNewPublicApiSvcClient(grpcAddr)

	return nil
}

// Awaiting an address can be useful for reconnect logic.
func (a *ApiClient) awaitGrpcAddr() (string, error) {

	successCh, errorCh := a.makeGetProviderRequest(GRPC)

	select {
	case provider := <-successCh:
		return provider.grpcAddr, nil
	case err := <-errorCh:
		return "", fmt.Errorf("failed to get provider: %w", err)
	}
}

func (a *ApiClient) makeGetProviderRequest(rpcType RpcType) (chan apiProvider, chan error) {
	var resultCh = make(chan apiProvider)
	var errorCh = make(chan error)

	req := &GetProviderRequest{
		RpcType:  rpcType,
		Retries:  0,
		ResultCh: resultCh,
		ErrorCh:  errorCh,
	}

	a.getProviderCh <- req

	return resultCh, errorCh
}

func (a *ApiClient) NewOperation(from string, opData OperationData) (Operation, error) {
	nodeStatus, err := a.nodeStatus()
	if err != nil {
		return Operation{}, fmt.Errorf("failed getting node status: %w", err)
	}

	expiryPeriod := nodeStatus.LastExecutedSpeculativeSlot.Period + DEFAULT_PERIOD_OFFSET
	chainId := nodeStatus.ChainId

	opContent, err := compactBytesForOperation(opData, expiryPeriod)
	if err != nil {
		return Operation{}, fmt.Errorf("failed compacting operation bytes: %w", err)
	}

	return Operation{
		from:         from,
		expiryPeriod: expiryPeriod,
		chainId:      chainId,
		opData:       opData,
		content:      opContent,
	}, nil
}

func (a *ApiClient) SendOperation(op Operation) (string, error) {

	serializedOp, opId, err := op.Serialize()
	if err != nil {
		return "", fmt.Errorf("failed serializing operation: %w", err)
	}

	stream, err := a.publicApiSvc.SendOperations(context.Background())
	if err != nil {
		a.onPublicApiSvcError()
		return "", fmt.Errorf("failed getting send operations stream: %w", err)
	}

	// We're loosing an error to the void here...
	// TODO: Wrap it in a func to log it when we implement
	// 		 a proper logger...
	defer stream.CloseSend()

	req := &apipb.SendOperationsRequest{
		Operations: [][]byte{serializedOp},
	}

	if err := stream.Send(req); err != nil {
		return "", fmt.Errorf("failed sending operation on stream: %w", err)
	}

	res, err := stream.Recv()
	if err != nil {
		return "", fmt.Errorf("failed receiving response from stream: %w", err)
	}

	switch res.Result.(type) {
	case *apipb.SendOperationsResponse_Error:
		err = errors.New(res.GetError().GetMessage())
		return opId, fmt.Errorf("operation (%s) failed: %w", opId, err)
	case *apipb.SendOperationsResponse_OperationIds:
		if len(res.GetOperationIds().GetOperationIds()) == 0 {
			return opId, fmt.Errorf("no operation ids in response")
		}
		if res.GetOperationIds().GetOperationIds()[0] != opId {
			return opId, fmt.Errorf("send operation response has different opId, expected (%s), got (%s)", opId, res.GetOperationIds().GetOperationIds()[0])
		}
	}

	return opId, nil
}

// Issues a read-only contract call using the provided
// callData.
//
// Returns the call result as a slice of bytes as well
// as an error in the event of failure.
func (a *ApiClient) ReadSC(caller string, callData CallData) ([]byte, error) {

	if callData.Fee == 0 {
		callData.Fee = DEFAULT_READ_ONLY_CALL_FEE
	}

	req := &apipb.ExecuteReadOnlyCallRequest{
		Call: &massapb.ReadOnlyExecutionCall{
			MaxGas: callData.MaxGas,
			CallerAddress: &wrapperspb.StringValue{
				Value: caller,
			},
			Fee: &massapb.NativeAmount{
				Mantissa: callData.Fee,
				Scale:    MANTISSA_SCALE,
			},
			Target: &massapb.ReadOnlyExecutionCall_FunctionCall{
				FunctionCall: &massapb.FunctionCall{
					TargetAddress:  callData.TargetAddress,
					TargetFunction: callData.TargetFunction,
					Parameter:      callData.Parameter,
					Coins: &massapb.NativeAmount{
						Mantissa: callData.Coins,
						Scale:    MANTISSA_SCALE,
					},
				},
			},
		},
	}

	res, err := a.publicApiSvc.ExecuteReadOnlyCall(context.Background(), req)
	if err != nil {
		a.onPublicApiSvcError()
		return nil, fmt.Errorf("failed executing read only call: %w", err)
	}

	return res.Output.CallResult, nil
}

// Gets the associated operations for the provided ids.
//
// Returns an error if the request was not successful.
func (a *ApiClient) GetOperations(opIds ...string) ([]*massapb.OperationWrapper, error) {
	req := &apipb.GetOperationsRequest{
		OperationIds: opIds,
	}

	res, err := a.publicApiSvc.GetOperations(context.Background(), req)
	if err != nil {
		return nil, fmt.Errorf("failed getting operations: %w", err)
	}

	return res.GetWrappedOperations(), nil
}

func (a *ApiClient) nodeStatus() (*massapb.PublicStatus, error) {

	res, err := a.publicApiSvc.GetStatus(context.Background(), &apipb.GetStatusRequest{})
	if err != nil {
		a.onPublicApiSvcError()

		return &massapb.PublicStatus{}, fmt.Errorf("failed to get status: %w", err)
	}

	return res.Status, nil

}

// TODO: Finish and implement as user facing function...
func (a *ApiClient) getContractDatastoreKeys(contractAddr string) {

	var item = &apipb.ExecutionQueryRequestItem{
		RequestItem: &apipb.ExecutionQueryRequestItem_AddressDatastoreKeysFinal{
			AddressDatastoreKeysFinal: &apipb.AddressDatastoreKeysFinal{
				Address: contractAddr,
				Prefix:  []byte{},
			},
		},
	}

	var queries []*apipb.ExecutionQueryRequestItem
	queries = append(queries, item)

	req := &apipb.QueryStateRequest{
		Queries: queries,
	}

	res, err := a.publicApiSvc.QueryState(context.Background(), req)
	if err != nil {
		a.onPublicApiSvcError()
		log.Fatalf("failed querying state: %s", err)
	}

	// log.Printf("Query Res: %v", res)

	for _, queryRes := range res.Responses {
		switch res := queryRes.Response.(type) {
		case *apipb.ExecutionQueryResponse_Result:
			log.Printf("Result: %v", res.Result.ResponseItem)
		case *apipb.ExecutionQueryResponse_Error:
			log.Printf("Error: %v", res.Error)
		}
	}

}

func (a *ApiClient) getDataStoreEntry(addr, key string) (*massapb.DatastoreEntry, error) {

	// Serialize key
	var serializedKey = []byte(key)

	req := &apipb.GetDatastoreEntriesRequest{
		Filters: []*apipb.GetDatastoreEntryFilter{
			{
				Filter: &apipb.GetDatastoreEntryFilter_AddressKey{
					AddressKey: &massapb.AddressKeyEntry{
						Address: addr,
						Key:     serializedKey,
					},
				},
			},
		},
	}

	res, err := a.publicApiSvc.GetDatastoreEntries(context.Background(), req)
	if err != nil {
		a.onPublicApiSvcError()
		return &massapb.DatastoreEntry{}, fmt.Errorf("failed getting datastore entry: %w", err)
	}

	if len(res.DatastoreEntries) != 1 {
		return &massapb.DatastoreEntry{}, fmt.Errorf("unexpected number of rentries returned")
	}

	return res.DatastoreEntries[0], nil
}

// Gets a new gRPC API and instantiates a new
// public api service client.
func (a *ApiClient) onPublicApiSvcError() {

	addr, err := a.awaitGrpcAddr()
	if err != nil {
		log.Printf("failed getting gRPC endpoint: %s", err)
		return
	}

	a.setNewPublicApiSvcClient(addr)

}

func (a *ApiClient) setNewPublicApiSvcClient(grpcAddr string) {

	conn, err := grpc.Dial(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Printf("failed dialing gRPC endpoint: %s", err)
		return
	}

	a.publicApiSvc = apipb.NewPublicServiceClient(conn)
}
