package geheim

import (
	"io"
)

type PrintFunc func(Mode, Md, int, []byte, []byte, []byte)

func checkArgs(in io.Reader, out io.Writer, pass []byte) error {
	if in == nil || out == nil || pass == nil {
		return errInvArg
	}
	return nil
}

func ValidateConfig(mode Mode, md Md, keyIter int) (err error) {
	err = errInvMode
	for _, m := range modes {
		if m == mode {
			err = nil
			break
		}
	}
	if err != nil {
		return
	}
	err = errInvMd
	for _, m := range mds {
		if m == md {
			err = nil
			break
		}
	}
	if err != nil {
		return
	}
	if keyIter < DefaultKeyIter {
		err = errInvKeyIter
	}
	return
}
