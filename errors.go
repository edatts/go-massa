package massa

import "errors"

var (
	ErrWrongMac           = errors.New("derived mac does not match expected mac")
	ErrBadInitialAddrs    = errors.New("no available endpoints in initial API addresses")
	ErrTooManyRetries     = errors.New("too many retries on get provider request")
	ErrInvalidMassaPriv   = errors.New("invalid massa private key")
	ErrInvalidMassaPub    = errors.New("invalid massa public key")
	ErrPrivLength         = errors.New("private key has wrong length")
	ErrReadUvarint        = errors.New("failed reading version uvarint")
	ErrAccountNotFound    = errors.New("account not found for address")
	ErrRegAccountNotFound = errors.New("account not found in registry, please import account")
	ErrIsDir              = errors.New("provide path to file is directory path")
)
