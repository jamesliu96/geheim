package geheim

import (
	"bufio"
	"crypto/hmac"
	"io"
)

const (
	saltSize = 16
	keySize  = 32
)

const (
	DefaultCipher = AES
	DefaultKDF    = PBKDF2
	DefaultMode   = CTR
	DefaultMD     = SHA_256
	DefaultMAC    = HMAC
	MinSec        = 1
	MaxSec        = 10
)

func Encrypt(in io.Reader, out io.Writer, pass []byte, cipher Cipher, kdf KDF, mode Mode, md MD, mac MAC, sec int, printFn PrintFunc) (sign []byte, err error) {
	err = checkArgs(in, out, pass)
	if err != nil {
		return
	}
	r := bufio.NewReader(in)
	w := bufio.NewWriter(out)
	defer (func() {
		if err == nil {
			err = w.Flush()
		}
	})()
	err = ValidateConfig(cipher, kdf, mode, md, mac, sec)
	if err != nil {
		return
	}
	salt := make([]byte, saltSize)
	err = randRead(salt)
	if err != nil {
		return
	}
	iv := make([]byte, ivSizes[cipher])
	err = randRead(iv)
	if err != nil {
		return
	}
	sm, mode := getStreamMode(mode, false)
	mdfn, md := getMD(md)
	dk, kdf, err := deriveKey(kdf, pass, salt, sec, mdfn)
	if err != nil {
		return
	}
	s, cipher, err := getStream(cipher, dk, iv, sm)
	if err != nil {
		return
	}
	h, mac := getMAC(mac, mdfn, dk)
	meta := newMeta()
	err = meta.Write(w)
	if err != nil {
		return
	}
	header, err := meta.GetHeader()
	if err != nil {
		return
	}
	if printFn != nil {
		err = printFn(header.Version(), cipher, kdf, mode, md, mac, sec, salt, iv, dk)
		if err != nil {
			return
		}
	}
	header.Set(cipher, kdf, mode, md, mac, sec, salt, iv)
	err = header.Write(w)
	if err != nil {
		return
	}
	_, err = io.Copy(io.MultiWriter(newStreamWriter(s, w), h), r)
	if err != nil {
		return
	}
	sign = h.Sum(nil)
	return
}

func Decrypt(in io.Reader, out io.Writer, pass []byte, printFn PrintFunc) (sign []byte, err error) {
	err = checkArgs(in, out, pass)
	if err != nil {
		return
	}
	r := bufio.NewReader(in)
	w := bufio.NewWriter(out)
	defer (func() {
		if err == nil {
			err = w.Flush()
		}
	})()
	meta := &meta{}
	err = meta.Read(r)
	if err != nil {
		return
	}
	header, err := meta.GetHeader()
	if err != nil {
		return
	}
	err = header.Read(r)
	if err != nil {
		return
	}
	cipher, kdf, mode, md, mac, sec, salt, iv := header.Get()
	err = ValidateConfig(cipher, kdf, mode, md, mac, sec)
	if err != nil {
		return
	}
	sm, mode := getStreamMode(mode, true)
	mdfn, md := getMD(md)
	dk, kdf, err := deriveKey(kdf, pass, salt, sec, mdfn)
	if err != nil {
		return
	}
	s, cipher, err := getStream(cipher, dk, iv, sm)
	if err != nil {
		return
	}
	h, mac := getMAC(mac, mdfn, dk)
	if printFn != nil {
		err = printFn(header.Version(), cipher, kdf, mode, md, mac, sec, salt, iv, dk)
		if err != nil {
			return
		}
	}
	_, err = io.Copy(io.MultiWriter(w, h), newStreamReader(s, r))
	if err != nil {
		return
	}
	sign = h.Sum(nil)
	return
}

func DecryptVerify(in io.Reader, out io.Writer, pass []byte, printFn PrintFunc, vSign []byte) (sign []byte, err error) {
	sign, err = Decrypt(in, out, pass, printFn)
	if err != nil {
		return
	}
	if vSign != nil {
		if !hmac.Equal(vSign, sign) {
			err = errSigVer
		}
	}
	return
}
