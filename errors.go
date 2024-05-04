package massa

import "errors"

var (
	ErrWrongMac         = errors.New("derived mac does not match expected mac")
	ErrBadInitialAddrs  = errors.New("no available endpoints in initial API addresses")
	ErrTooManyRetries   = errors.New("too many retries on get provider request")
	ErrInvalidMassaPriv = errors.New("invalid massa private key")
	ErrPrivLength       = errors.New("private key has wrong length")
	ErrDecodeFailed     = errors.New("failed decoding private key")
	ErrReadUvarint      = errors.New("failed reading version uvarint")
	ErrAccountNotFound  = errors.New("account not found for address")
)
