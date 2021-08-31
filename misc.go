package geheim

import (
	"fmt"
	"io"
)

func checkArgs(in io.Reader, out io.Writer, pass []byte) error {
	if in == nil || out == nil || pass == nil {
		return errInvArg
	}
	return nil
}

type PrintFunc func(Mode, Md, int, []byte, []byte, []byte)

func ValidateConfig(mode Mode, md Md, keyIter int) (err error) {
	switch mode {
	case ModeCTR:
	case ModeCFB:
	case ModeOFB:
		break
	default:
		err = fmt.Errorf("invalid cipher block mode (%s)", GetModeString())
	}
	switch md {
	case SHA3_224:
	case SHA3_256:
	case SHA3_384:
	case SHA3_512:
	case SHA_224:
	case SHA_256:
	case SHA_384:
	case SHA_512:
	case SHA_512_224:
	case SHA_512_256:
		break
	default:
		err = fmt.Errorf("invalid message digest (%s)", GetMdString())
	}
	if keyIter < DefaultKeyIter {
		err = fmt.Errorf("invalid key iteration (minimum %d)", DefaultKeyIter)
	}
	return
}
