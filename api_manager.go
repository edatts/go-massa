package massa

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	apipb "github.com/edatts/go-massa/protos/massa/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type apiProvider struct {
	ip          string
	grpcAddr    string
	jsonRpcAddr string
}

type apiManagerOpts struct {
	targetNumAvailGrpc       uint32
	getProviderRetryInterval time.Duration
	getProviderMaxRetries    uint32
}

type isAvailable = bool

type apiManager struct {
	providers map[apiProvider]isAvailable
	mu        sync.RWMutex

	isDiscovering bool

	getProviderCh chan *GetProviderRequest

	// The target number of gRPC APIs that the apiManager
	// will attempt to keep available.
	targetNumAvailGrpc uint32

	getProviderRetryInterval time.Duration
	getProviderMaxRetries    uint32
}

// TODO: Have configuration passed down from ApiClient...
func newApiManager(opts *apiManagerOpts) *apiManager {
	return &apiManager{
		providers: map[apiProvider]isAvailable{},
		mu:        sync.RWMutex{},

		getProviderCh: make(chan *GetProviderRequest, 10),

		targetNumAvailGrpc:       opts.targetNumAvailGrpc,
		getProviderRetryInterval: opts.getProviderRetryInterval,
		getProviderMaxRetries:    opts.getProviderMaxRetries,
	}
}

// TODO: Include ticker to trigger discovery sub-routine.
func (a *apiManager) initApiManager(apiAddrs []string) error {

	if len(apiAddrs) == 0 {
		apiAddrs = append(apiAddrs, DEFAULT_MAINNET_JSON_RPC)
	}

	// Test Urls
	var numFails int
	for _, url := range apiAddrs {
		if provider, ok := a.testApiUrl(url); ok {
			a.addProvider(provider)
			continue
		}
		numFails++
	}

	if numFails >= len(apiAddrs) {
		return ErrBadInitialAddrs
	}

	go a.discoverApis()
	go a.startGetProviderLoop()

	return nil
}

type worker struct {
	pool   chan chan string
	ipCh   chan string
	quitCh chan struct{}
}

func (w *worker) quit() {
	w.quitCh <- struct{}{}
}

// Performs breadth first search until we have at least
// targetNumAvail gRPC APIs or until we run out of IPs
// to test.
func (a *apiManager) discoverApis() {
	if a.isDiscovering {
		return
	}
	a.isDiscovering = true
	defer func() {
		a.isDiscovering = false
	}()

	var numGrpcAvailable uint32
	// If this channel fills up then the whole routine will hang
	//
	var ipsToCheck = make(chan string, 1000000)
	var checked = map[string]struct{}{}
	var cMu = sync.RWMutex{}

	// Start by testing and counting known providers
	a.mu.Lock()
	for provider := range a.providers {
		if provider.ip != "" {
			ipsToCheck <- provider.ip
		}

		if provider.jsonRpcAddr != "" {
			// Find peer Ips
			ips, ok := getPeerIps(provider.jsonRpcAddr)
			if ok {
				for _, ip := range ips {
					ipsToCheck <- ip
				}
			}
		}

		if provider.grpcAddr != "" {
			if _, ok := a.testGrpcAddr(provider.grpcAddr); ok {
				a.providers[provider] = true
				numGrpcAvailable++
			}
			// else {
			// 	a.providers[provider] = false
			// }
		}
	}
	a.mu.Unlock()

	if numGrpcAvailable >= a.targetNumAvailGrpc {
		return
	}

	log.Printf("Starting search for providers.")

	// If not enough providers, begin search

	var limit int = 20
	var workers = []*worker{}
	var workerPool = make(chan chan string, limit)

	// Create workers
	for i := 0; i < limit; i++ {
		var worker = &worker{
			pool:   workerPool,
			ipCh:   make(chan string),
			quitCh: make(chan struct{}),
		}

		workers = append(workers, worker)

		go func() {
			for {
				workerPool <- worker.ipCh

				select {
				case ip := <-worker.ipCh:

					// log.Printf("Testing IP: %s", ip)
					provider, peerIps, ok := a.testIp(ip)
					if ok {
						// log.Printf("Found new provider: %+v", provider)
						a.addProvider(provider)
						if provider.grpcAddr != "" {
							atomic.AddUint32(&numGrpcAvailable, 1)
						}
					}

					cMu.Lock()
					checked[ip] = struct{}{}
					for _, peerIp := range peerIps {
						if _, ok := checked[peerIp]; !ok {
							ipsToCheck <- peerIp
						}
					}
					cMu.Unlock()

				case <-worker.quitCh:
					return
				}

			}
		}()
	}

	for ip := range ipsToCheck {

		// De-queue ipCh from pool
		ipCh := <-workerPool

		// Send ip to worker
		ipCh <- ip

		if atomic.LoadUint32(&numGrpcAvailable) >= a.targetNumAvailGrpc {
			// log.Printf("Found (%d) available grpc providers, ending search.", numGrpcAvailable)
			for _, worker := range workers {
				worker.quit()
			}
			break
		}
	}

	// log.Printf("Finished search, found providers: %+v", a.providers)
	log.Printf("Finished search, found (%d) providers", len(a.providers))

	//----------------------------------//

}

// This loop enables goroutine-safe getting of providers while also
// allowing the getter to await a response while the apiManager
// tests registered providers and discovers new ones in the event
// that none are available.
//
// Currently this is only implemented by the
// ApiClient.makeGetProviderRequest() method.
func (a *apiManager) startGetProviderLoop() {
	// Wait for a request on the chan
	for req := range a.getProviderCh {

		if req.Retries >= a.getProviderMaxRetries {
			req.ErrorCh <- ErrTooManyRetries
			continue
		}

		// Get a provider and test it before returning it
		if provider, ok := a.getProvider(req.RpcType); ok {
			req.ResultCh <- provider
			continue
		}

		// Retry
		// log.Printf("failed to find available %s provider, retrying...", req.RpcType.String())
		time.AfterFunc(a.getProviderRetryInterval, func() {
			req.Retries++
			a.getProviderCh <- req
		})
	}
}

func (a *apiManager) addProvider(provider apiProvider) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.providers[provider] = true
}

// Gets a provider from the registered providers in memory while
// also testing that provider to ensure it is still available
// before returning it to the caller. Returns a boolean to
// indicate whether the selected provider passed it's most
// recent test or not.
func (a *apiManager) getProvider(rpcType RpcType) (apiProvider, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	switch rpcType {
	case GRPC:
		for p, isAvailable := range a.providers {
			if isAvailable && p.grpcAddr != "" {
				if _, ok := a.testGrpcAddr(p.grpcAddr); !ok {
					return apiProvider{}, false
				}
				return p, true
			}
		}
	case JSON_RPC:
		for p, isAvailable := range a.providers {
			if isAvailable && p.jsonRpcAddr != "" {
				if _, ok := a.testJsonRpcAddr(p.jsonRpcAddr); !ok {
					return apiProvider{}, false
				}
				return p, true
			}
		}
	}

	return apiProvider{}, false
}

// Tests the URL as both a gRPC and JSON-RPC endpoint.
// Returns an apiProvider as well as a boolean to indicate
// success or failure.
func (a *apiManager) testApiUrl(url string) (apiProvider, bool) {

	provider, ok := a.testGrpcAddr(url)
	if ok {
		return provider, true
	}

	provider, ok = a.testJsonRpcAddr(url)
	if ok {
		return provider, true
	}

	return apiProvider{}, false
}

// Tests the provided IP by calling the get_status method on
// default public gRPC and JSON-RPC ports. Used in the
// discovery of new public endpoints.
func (a *apiManager) testIp(ip string) (provider apiProvider, peerIps []string, success bool) {
	// provider = apiProvider{ip: ip}

	netIp := net.ParseIP(ip)
	ip4 := netIp.To4().String()
	provider = apiProvider{ip: ip4}

	// Test gRPC
	if grpcAddr, ok := a.testIpForGrpc(ip4); ok {
		provider.grpcAddr = grpcAddr
		success = true
	}

	// Test JSON-RPC
	if jsonRpcAddr, ips, ok := a.testIpForJsonRpc(ip4); ok {
		provider.jsonRpcAddr = jsonRpcAddr
		success = true
		peerIps = ips
	}

	// log.Printf("Finished testing IP. Success: %v. Built provider: %+v", success, provider)

	return provider, peerIps, success
}

func (a *apiManager) testIpForGrpc(ip string) (string, bool) {
	addr := fmt.Sprintf("%s:%s", ip, DEFAULT_GRPC_PORT)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	conn, err := grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		// log.Printf("error dialing addr (%s): %s", addr, err)
		return "", false
	}

	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	svc := apipb.NewPublicServiceClient(conn)
	_, err = svc.GetStatus(ctx, &apipb.GetStatusRequest{})
	if err != nil {
		// gRPC API found
		return "", false
	}

	return addr, true
}

func (a *apiManager) testIpForJsonRpc(ip string) (string, []string, bool) {
	addr := fmt.Sprintf("http://%s:%s", ip, DEFAULT_JSON_RPC_PORT)

	ips, ok := getPeerIps(addr)
	if !ok {
		return "", nil, false
	}

	return addr, ips, true
}

func (a *apiManager) testGrpcAddr(addr string) (apiProvider, bool) {

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	conn, err := grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		// log.Printf("error dialing gRPC address (%s) : %s", addr, err)
		return apiProvider{}, false
	}

	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	svc := apipb.NewPublicServiceClient(conn)
	_, err = svc.GetStatus(ctx, &apipb.GetStatusRequest{})
	if err != nil {
		// log.Printf("error calling GetStatus on gRPC: %s", err)
		return apiProvider{}, false
	}

	return apiProvider{grpcAddr: addr}, true
}

func (a *apiManager) testJsonRpcAddr(addr string) (apiProvider, bool) {
	res, err := publicJsonRpcGetStatus(addr)
	if err != nil {
		return apiProvider{}, false
	}

	// Check error field in response
	if res.Error != (jsonRpcError{}) {
		return apiProvider{}, false
	}

	return apiProvider{jsonRpcAddr: addr}, true
}

type getStatusReq struct {
	JsonRpc string        `json:"jsonrpc"`
	Id      int           `json:"id"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
}

type getStatusResponse struct {
	JsonRpc string          `json:"jsonrpc"`
	Id      int             `json:"id"`
	Result  getStatusResult `json:"result"`
	Error   jsonRpcError    `json:"error"`
}

type jsonRpcError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

type getStatusResult struct {
	NodeId         string          `json:"node_id"`
	ConnectedNodes map[string]node `json:"connected_nodes"`
	// ConnectedNodes map[string]*json.RawMessage `json:"connected_nodes"`
}

type node struct {
	ip        string
	isInbound bool
}

func (n *node) UnmarshalJSON(bytes []byte) error {
	arr := []interface{}{}
	err := json.Unmarshal(bytes, &arr)
	if err != nil {
		return fmt.Errorf("failed unmarshalling node bytes: %w", err)
	}

	ip, ok := arr[0].(string)
	if !ok {
		return fmt.Errorf("fail to assert 0th element as string")
	}

	isInbound, ok := arr[1].(bool)
	if !ok {
		return fmt.Errorf("fail to assert element at index one as bool")
	}

	n.ip = ip
	n.isInbound = isInbound

	return nil
}

func publicJsonRpcGetStatus(addr string) (getStatusResponse, error) {
	var buf = new(bytes.Buffer)

	client := http.Client{
		Timeout: 2 * time.Second,
	}

	req := getStatusReq{
		JsonRpc: "2.0",
		Id:      1,
		Method:  "get_status",
		Params:  []interface{}{},
	}

	bytes, err := json.Marshal(req)

	if err != nil {
		return getStatusResponse{}, fmt.Errorf("failed marshalling request to bytes: %w", err)
	}

	_, err = buf.Write(bytes)
	if err != nil {
		return getStatusResponse{}, fmt.Errorf("failed writing request to buffer: %w", err)
	}

	// res, err := http.Post(addr, "application/json", buf)
	res, err := client.Post(addr, "application/json", buf)
	if err != nil {
		return getStatusResponse{}, fmt.Errorf("failed making post request to (%s): %w", addr, err)
	}

	buf.Reset()

	_, err = buf.ReadFrom(res.Body)
	if err != nil {
		return getStatusResponse{}, fmt.Errorf("failed reading request body: %w", err)
	}

	getStatusRes := getStatusResponse{}
	json.Unmarshal(buf.Bytes(), &getStatusRes)

	// log.Printf("Get_Status response: %+v", getStatusRes)

	return getStatusRes, nil
}

func getPeerIps(jsonRpcAddr string) ([]string, bool) {
	var ips = []string{}

	res, err := publicJsonRpcGetStatus(jsonRpcAddr)
	if err != nil {
		// log.Printf("error calling addr (%s): %s", jsonRpcAddr, err)
		return nil, false
	}

	// Check error field in response
	if res.Error != (jsonRpcError{}) {
		// log.Printf("error response from jsonRpcAddr (%s): %+v", jsonRpcAddr, res.Error)
		return nil, false
	}

	// log.Printf("Get_Status result: %+v", res.Result)

	for _, node := range res.Result.ConnectedNodes {
		ips = append(ips, node.ip)
	}

	return ips, true
}
