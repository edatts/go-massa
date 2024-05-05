## Go-Massa ##

Go-Massa is an SDK for the Massa blockchain. It allows you to generate and manage wallets, make native MAS transfers, and interact with Smart Contracts on the Massa network.

This SDK is a work in progress and is early in it's development lifecycle. It is not currently funded and is being built as a learning exercise. As such, there are no garuntees that it will reach a stable release and development may be sporadic or cease entirely at any time. Additionally, the public facing api is likely to change significantly as the design evolves.

### Current Features ###
- Generate Massa accounts.
- Import existing Massa accounts from secret keys.
- Securely persist secret keys to disk with a password using AES-CTR mode encryption, Scrypt key derivation function, and sha256-HMAC.
- Automatic public API discovery and reconnection.
- Initiate native MAS transfers.
- Read smart contracts.
- Call smart contracts.


### Planned Work / In Progress ###
- Add more examples.
- Improve test coverage.
- Add structured logger.
- Top level functions for sending transactions.
- Implement [Massa Standard](https://github.com/massalabs/massa-standards/blob/main/wallet/file-format.md) for wallet files.
- Add support for seed phrases as per [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki).
- Add support for Heirarchical Deterministic wallets as per [SLIP-10](https://github.com/satoshilabs/slips/blob/master/slip-0010.md).
- Replace current wallet/accountManager model with a stateful wallet implementation.
- API discovery improvements.
- API service redundancy and transaction broadcast retries.
- Utility for serializing smart contract parameters.
- Read datastore keys and values.
- Get native balances.
- Deploy WASM bytecode.
- Custom configuration improvements.
- Unify all functionality under a "`MassaClient`".
- Get Operations.
- Get staking info.
- ApiClient chain event streams.

### Future Work ###
- Investigate go-massa as a node client.


### Usage ###

#### Wallet ####

Generating accounts:
```
wallet := massa.NewWallet()

if err := wallet.Init(); err != nil {
    log.Fatal(err)
}

// Empty password will result in a user prompt for a password
password := ""
addr, err := wallet.GenerateAccount(password)
if err != nil {
    log.Fatal(err)
}

acc, err := wallet.GetAccount(addr)
if err != nil {
    log.Fatal(err)
}

log.Printf("Account: %+v", acc)
```

#### ApiClient ####

Sending MAS to another account:
```
var (
    // Don't hardcode secrets in your applications...
    senderSecretKey = "S11JcqZoz6XXbRjN2nrw2CsuKNfcfqwX6Po2EsiwG6jHnhuVLzo"

    // Empty password will prompt for user input.
    senderPassword = ""

    // Amount must be in nanoMAS
    amount uint64 = 1_000_000_000 // 1 MAS

    jsonRpcApi = "https://buildnet.massa.net/api/v2"
    recipientAddr = "AU12oLjNkH8ywGaeqWuSE1CxdWLhG7hsCW8zZgasax1Csn3tW1mni"
)

apiClient := massa.NewApiClient()
if err := apiClient.Init(jsonRpcApi); err != nil {
    log.Fatal(err)
}

wallet := massa.NewWallet()
if err := wallet.Init(); err != nil {
    log.Fatal(err)
}

senderAddr, err := wallet.ImportAccount(senderSecretKey, senderPassword)
if err != nil {
    log.Fatal(err)
}

senderAcc, err := wallet.GetAccount(senderAddr)
if err != nil {
    log.Fatal(err)
}

opId, err := apiClient.SendTransaction(senderAcc, recipientAddr, amount)
if err != nil {
    log.Fatal(err)
}

log.Printf("Operation ID: %s", opId)
```