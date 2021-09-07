package geheim

import (
	"io"
)

type PrintFunc func(Cipher, KDF, Mode, Md, int, []byte, []byte, []byte) error

func checkArgs(in io.Reader, out io.Writer, pass []byte) error {
	if in == nil || out == nil || pass == nil {
		return errInvArg
	}
	return nil
}

func ValidateConfig(cipher Cipher, kdf KDF, mode Mode, md Md, keyIter int) (err error) {
	err = errInvCipher
	for _, c := range ciphers {
		if c == cipher {
			err = nil
			break
		}
	}
	if err != nil {
		return
	}
	err = errInvKDF
	for _, k := range kdfs {
		if k == kdf {
			err = nil
			break
		}
	}
	if err != nil {
		return
	}
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
