package geheim

import (
	"crypto/subtle"
	"fmt"
)

const (
	CipherDesc = "cipher"
	ModeDesc   = "stream mode"
	KDFDesc    = "key derivation"
	MACDesc    = "message authentication"
	MDDesc     = "message digest"
	SecDesc    = "security level"
)

type PrintFunc func(version int, cipher Cipher, mode Mode, kdf KDF, mac MAC, md MD, sec int, pass, salt, iv, key []byte) error

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
