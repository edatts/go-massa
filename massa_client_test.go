package massa

import ()

// TODO: Refactor to use massaClient instead of apiClient
// func TestCallSC(t *testing.T) {

// 	// Test flow:
// 	//	- Check test wallet WMAS balance.
// 	// 	- Call the `deposit` method on the WMAS contract.
// 	//	- Assert that WMAS balance increased.

// 	// Expected storage cost 96 * 100_000 nMAS
// 	//	96_000_000 nMAS

// 	testAcc := getBuildnetTestAccount()

// 	wallet := NewWallet(WithCustomHome(testingWalletHome()))
// 	if err := wallet.Init(); err != nil {
// 		t.Errorf("failed initializing wallet: %s", err)
// 	}

// 	testAddr, err := wallet.ImportFromPriv(testAcc.priv.Encoded, "password")
// 	if err != nil {
// 		t.Errorf("failed importing test account: %s", err)
// 	}

// 	var (
// 		amountToWrap uint64 = 100_000_000 // in nMAS
// 		storageCost  uint64 = 9_600_000
// 	)

// 	// Create and init api client
// 	apiClient := NewApiClient()
// 	if err := apiClient.Init(wallet, BUILDNET_JSON_RPC_ADDR); err != nil {
// 		t.Errorf("failed initializing api client: %s", err)
// 	}

// 	// Get initial balance
// 	initialBalance, err := getWMABalance(apiClient, testAcc.addr.Encoded)
// 	if err != nil {
// 		t.Errorf("failed getting initial wmas balance: %s", err)
// 	}

// 	callData := CallData{
// 		Fee:            10_000_000,
// 		MaxGas:         10_000_000,
// 		Coins:          amountToWrap,
// 		TargetAddress:  WMAS_CONTRACT_BUILDNET,
// 		TargetFunction: "deposit",
// 	}

// 	_, err = apiClient.CallSC(testAddr, callData)
// 	if err != nil {
// 		t.Errorf("failed calling contract: %s", err)
// 	}

// 	// Sleep to give time for network to see tx
// 	time.Sleep(20 * time.Second)

// 	newBalance, err := getWMABalance(apiClient, testAcc.addr.Encoded)
// 	if err != nil {
// 		t.Errorf("failed getting new balance: %s", err)
// 	}

// 	var expectedBalanceDiff uint64
// 	if initialBalance.Cmp(big.NewInt(0)) == 0 {
// 		// Factor in storage cost
// 		expectedBalanceDiff = amountToWrap - storageCost
// 	} else {
// 		// Ignore storage cost
// 		expectedBalanceDiff = amountToWrap
// 	}

// 	balanceDiff := big.NewInt(0).Sub(newBalance, initialBalance).Uint64()

// 	if balanceDiff != expectedBalanceDiff {
// 		t.Errorf("enexpected balance diff, expected (%d), got (%d)", expectedBalanceDiff, balanceDiff)
// 	}
// }
