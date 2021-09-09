package geheim

import (
	"errors"
	"fmt"
)

var (
	errSigVer    = errors.New("signature verification failed")
	errMalHead   = errors.New("malformed header")
	errInvArg    = errors.New("invalid argument")
	errInvCipher = fmt.Errorf("invalid cipher (%s)", GetCipherString())
	errInvKDF    = fmt.Errorf("invalid key derivation function (%s)", GetKDFString())
	errInvMode   = fmt.Errorf("invalid stream mode (%s)", GetModeString())
	errInvMD     = fmt.Errorf("invalid message digest (%s)", GetMDString())
	errInvMAC    = fmt.Errorf("invalid message authentication (%s)", GetMACString())
	errInvSF     = fmt.Errorf("invalid security level (%d~%d)", MinSec, MaxSec)
)
