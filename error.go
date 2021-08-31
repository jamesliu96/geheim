package geheim

import "errors"

var (
	errSigVer  = errors.New("signature verification failed")
	errMalHead = errors.New("malformed header")
	errInvArg  = errors.New("invalid argument")
)
