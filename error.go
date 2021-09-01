package geheim

import (
	"errors"
	"fmt"
)

var (
	errSigVer     = errors.New("signature verification failed")
	errMalHead    = errors.New("malformed header")
	errInvArg     = errors.New("invalid argument")
	errInvMode    = fmt.Errorf("invalid cipher block mode (%s)", GetModeString())
	errInvMd      = fmt.Errorf("invalid message digest (%s)", GetMdString())
	errInvKeyIter = fmt.Errorf("invalid key iteration (minimum %d)", DefaultKeyIter)
)
