package geheim

import (
	"errors"
	"fmt"
	"math"
)

var (
	errSigVer     = errors.New("signature verification failed")
	errMalHead    = errors.New("malformed header")
	errInvArg     = errors.New("invalid argument")
	errInvCipher  = fmt.Errorf("invalid cipher (%s)", GetCipherString())
	errInvKDF     = fmt.Errorf("invalid key derivation function (%s)", GetKDFString())
	errInvMode    = fmt.Errorf("invalid cipher block mode (%s)", GetModeString())
	errInvMD      = fmt.Errorf("invalid message digest (%s)", GetMDString())
	errInvKeyIter = fmt.Errorf("invalid key iteration (%d~%d)", DefaultKeyIter, math.MaxUint32)
)
