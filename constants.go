package massa

import "time"

const (
	// Public API ports
	DEFAULT_GRPC_PORT     = "33037"
	DEFAULT_JSON_RPC_PORT = "33035"

	DEFAULT_PERIOD_OFFSET      uint64 = 5
	DEFAULT_READ_ONLY_CALL_FEE uint64 = 0.01 * 1e9
	MANTISSA_SCALE             uint32 = 9

	DEFAULT_TARGET_NUM_GRPC_AVAILABLE   uint32        = 3
	DEFAULT_GET_PROVIDER_MAX_RETRIES    uint32        = 3
	DEFAULT_GET_PROVIDER_RETRY_INTERVAL time.Duration = 5 * time.Second

	DEFAULT_KDF_ITER    = 600_000
	DEFAULT_KDF_KEY_LEN = 32

	SECRET_KEY_PREFIX              = "S"
	PUBLIC_KEY_PREFIX              = "P"
	ADDRESS_USER_PREFIX            = "AU"
	ADDRESS_CONTRACT_PREFIX        = "AS"
	OPERATION_ID_PREFIX            = "O"
	ADDRESS_PREIX_LENGTH    uint64 = 2
	KEYS_VERSION_NUMBER     uint64 = 0

	MAX_BLOCK_GAS = 4_294_967_295

	DEFAULT_MAINNET_JSON_RPC = "https://mainnet.massa.net/api/v2"
)
