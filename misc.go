package geheim

import (
	"fmt"
	"io"
	"math"
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

func Validate(cipher Cipher, mode Mode, kdf KDF, mac MAC, md MD, sec int) (err error) {
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

func FormatSize(n int64) string {
	var unit string
	nn := float64(n)
	f := "%.2f"
	switch {
	case n >= 1<<60:
		nn /= 1 << 60
		unit = "E"
	case n >= 1<<50:
		nn /= 1 << 50
		unit = "P"
	case n >= 1<<40:
		nn /= 1 << 40
		unit = "T"
	case n >= 1<<30:
		nn /= 1 << 30
		unit = "G"
	case n >= 1<<20:
		nn /= 1 << 20
		unit = "M"
	case n >= 1<<10:
		nn /= 1 << 10
		unit = "K"
	default:
		f = "%.f"
	}
	return fmt.Sprintf("%s%sB", fmt.Sprintf(f, math.Max(0, nn)), unit)
}

func NewPrintFunc(w io.Writer) PrintFunc {
	return func(version int, cipher Cipher, mode Mode, kdf KDF, mac MAC, md MD, sec int, pass, salt, iv, key []byte) error {
		fmt.Fprintf(w, "%-8s%d\n", "VERSION", version)
		fmt.Fprintf(w, "%-8s%s(%d)\n", "CIPHER", CipherNames[cipher], cipher)
		if cipher == AES {
			fmt.Fprintf(w, "%-8s%s(%d)\n", "MODE", ModeNames[mode], mode)
		}
		fmt.Fprintf(w, "%-8s%s(%d)\n", "KDF", KDFNames[kdf], kdf)
		fmt.Fprintf(w, "%-8s%s(%d)\n", "MAC", MACNames[mac], mac)
		if kdf == PBKDF2 || mac == HMAC {
			fmt.Fprintf(w, "%-8s%s(%d)\n", "MD", MDNames[md], md)
		}
		iter, memory, sec := GetSecIterMemory(sec)
		if kdf == PBKDF2 {
			fmt.Fprintf(w, "%-8s%d(%d)\n", "SEC", sec, iter)
		} else {
			fmt.Fprintf(w, "%-8s%d(%s)\n", "SEC", sec, FormatSize(int64(memory)))
		}
		fmt.Fprintf(w, "%-8s%s(%x)\n", "PASS", pass, pass)
		fmt.Fprintf(w, "%-8s%x\n", "SALT", salt)
		fmt.Fprintf(w, "%-8s%x\n", "IV", iv)
		fmt.Fprintf(w, "%-8s%x\n", "KEY", key)
		return nil
	}
}
