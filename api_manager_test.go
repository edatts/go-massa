package massa

import (
	"testing"
	"time"
)

// Well now, we have a lot of testing to conduct for this one:
//	- Test that we can discover APIs correctly
// 	- Test that discovery stops when we hit targetNumAvail
// 	- Test invalid URLs
//	- Test that IPv6 and IPv4 both work
//	- Test concurrent getProviderRequests
//	- Test that getProvider retries work properly

const (
	TEST_ADDR = "https://mainnet.massa.net/api/v2"
)

func TestInit(t *testing.T) {

	addrs := []string{TEST_ADDR}

	opts := defaultApiClientOpts().apiManagerOpts
	am := newApiManager(opts)

	if err := am.initApiManager(addrs); err != nil {
		t.Errorf("failed initializing api manager: %s", err)
	}

	// Wait for search
	time.Sleep(time.Second * 10)

	// Assert that num available providers correct
	var numGrpcAvailable int
	for provider, isAvail := range am.providers {
		if isAvail && provider.grpcAddr != "" {
			numGrpcAvailable++
		}
	}

	if numGrpcAvailable < int(am.targetNumAvailGrpc) {
		t.Error("not enough available grpc addresses")
	}

}

func TestBadInitialAddrs(t *testing.T) {

	addrs := []string{
		"notValidAddress",
		"https://notreal.fake",
		"github.com/massalabs/massa",
	}

	opts := defaultApiClientOpts().apiManagerOpts
	am := newApiManager(opts)

	if err := am.initApiManager(addrs); err == nil {
		t.Error("expected non-nil err, not nil error")
	}

}

func TestGetProvider(t *testing.T) {

	addrs := []string{TEST_ADDR}

	opts := defaultApiClientOpts()
	WithMaxRetries(5)(opts)
	WithNumAvailable(7)(opts)

	am := newApiManager(opts.apiManagerOpts)

	if err := am.initApiManager(addrs); err != nil {
		t.Errorf("failed initializing api manager: %s", err)
	}

	// Sleep to wait for gRPC discovery
	time.Sleep(5 * time.Second)

	provider, ok := am.getProvider(JSON_RPC)
	if !ok {
		t.Errorf("failed to get provider")
	}

	// Assert that returned provider is available
	provider, ok = am.testJsonRpcAddr(provider.jsonRpcAddr)
	if !ok {
		t.Error("provider failed test after getting")
	}

	provider, ok = am.getProvider(GRPC)
	if !ok {
		t.Errorf("failed to get provider")
	}

	// Assert that returned provider is available
	provider, ok = am.testGrpcAddr(provider.grpcAddr)
	if !ok {
		t.Error("provider failed test after getting")
	}

}

func TestGetProviderRetries(t *testing.T) {

	opts := defaultApiClientOpts().apiManagerOpts
	am := newApiManager(opts)

	go am.startGetProviderLoop()

	var resultCh = make(chan apiProvider)
	var errorCh = make(chan error)

	req := &GetProviderRequest{
		RpcType:  GRPC,
		Retries:  0,
		ResultCh: resultCh,
		ErrorCh:  errorCh,
	}

	am.getProviderCh <- req

	// Assert that too many retries leads to failure
	select {
	case <-resultCh:
		t.Error("received on result channe, expected to recv on error channel")
	case err := <-errorCh:
		if err == nil {
			t.Error("got nil error, expected non-nil error")
		}
	}

}
