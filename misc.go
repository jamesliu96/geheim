package geheim

import (
	"io"
	"math"
)

type PrintFunc func(int, Cipher, KDF, Mode, MD, MAC, int, []byte, []byte, []byte) error

func checkArgs(in io.Reader, out io.Writer, pass []byte) error {
	if in == nil || out == nil || pass == nil {
		return errInvArg
	}
	return nil
}

func ValidateConfig(cipher Cipher, kdf KDF, mode Mode, md MD, mac MAC, sec int) (err error) {
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
	if sec < MinSec || sec > MaxSec && sec < 100000 || sec > math.MaxUint32 {
		err = errInvSF
	}
	return
}
