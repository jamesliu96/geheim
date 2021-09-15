package geheim

import (
	"crypto/subtle"
	"io"
)

type sumWriter interface {
	io.Writer
	Sum([]byte) []byte
}

type PrintFunc func(int, Cipher, Mode, KDF, MAC, MD, int, []byte, []byte, []byte) error

func checkArgs(args ...interface{}) error {
	for _, arg := range args {
		if arg == nil {
			return errInvArg
		}
	}
	return nil
}

func ValidateConfig(cipher Cipher, mode Mode, kdf KDF, mac MAC, md MD, sec int) (err error) {
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
	err = errInvMAC
	for _, m := range macs {
		if m == mac {
			err = nil
			break
		}
	}
	if err != nil {
		return
	}
	err = errInvMD
	for _, m := range mds {
		if m == md {
			err = nil
			break
		}
	}
	if err != nil {
		return
	}
	if sec < MinSec || sec > MaxSec {
		err = errInvSL
	}
	return
}

func equal(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
