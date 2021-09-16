package geheim

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
)

const (
	CipherDesc = "cipher"
	ModeDesc   = "stream mode"
	KDFDesc    = "key derivation"
	MACDesc    = "message authentication"
	MDDesc     = "message digest"
	SecDesc    = "security level"
)

type sumWriter interface {
	io.Writer
	Sum([]byte) []byte
}

type PrintFunc func(int, Cipher, Mode, KDF, MAC, MD, int, []byte, []byte, []byte) error

func checkArgs(args ...interface{}) error {
	for _, arg := range args {
		if arg == nil {
			return errors.New("invalid argument")
		}
	}
	return nil
}

func ValidateConfig(cipher Cipher, mode Mode, kdf KDF, mac MAC, md MD, sec int) (err error) {
	err = fmt.Errorf("invalid %s (%s)", CipherDesc, GetCipherString())
	for _, c := range ciphers {
		if c == cipher {
			err = nil
			break
		}
	}
	if err != nil {
		return
	}
	err = fmt.Errorf("invalid %s (%s)", ModeDesc, GetModeString())
	for _, m := range modes {
		if m == mode {
			err = nil
			break
		}
	}
	if err != nil {
		return
	}
	err = fmt.Errorf("invalid %s (%s)", KDFDesc, GetKDFString())
	for _, k := range kdfs {
		if k == kdf {
			err = nil
			break
		}
	}
	if err != nil {
		return
	}
	err = fmt.Errorf("invalid %s (%s)", MACDesc, GetMACString())
	for _, m := range macs {
		if m == mac {
			err = nil
			break
		}
	}
	if err != nil {
		return
	}
	err = fmt.Errorf("invalid %s (%s)", MDDesc, GetMDString())
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
		err = fmt.Errorf("invalid %s (%d~%d)", SecDesc, MinSec, MaxSec)
	}
	return
}

func equal(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
