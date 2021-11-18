package geheim

import (
	"bufio"
	"crypto/hmac"
	"errors"
	"io"
)

const (
	DefaultCipher = AES
	DefaultMode   = CTR
	DefaultKDF    = Argon2
	DefaultMAC    = HMAC
	DefaultMD     = SHA_256
	DefaultSec    = 10
)

func Encrypt(in io.Reader, out io.Writer, pass []byte, cipher Cipher, mode Mode, kdf KDF, mac MAC, md MD, sec int, printFn PrintFunc) (signed []byte, err error) {
	r := bufio.NewReader(in)
	w := bufio.NewWriter(out)
	defer (func() {
		if err == nil {
			err = w.Flush()
		}
	})()
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
	dk, kdf, err := deriveKey(kdf, pass, salt, sec, mdfn, keySizes[cipher])
	if err != nil {
		return
	}
	s, cipher, err := newCipherStream(cipher, dk, iv, sm)
	if err != nil {
		return
	}
	h, mac := getMAC(mac, mdfn, dk)
	meta := newMeta()
	header, err := meta.Header()
	if err != nil {
		return
	}
	header.Set(cipher, mode, kdf, mac, md, sec, salt, iv)
	if printFn != nil {
		err = printFn(header.Version(), cipher, mode, kdf, mac, md, sec, pass, salt, iv, dk)
		if err != nil {
			return
		}
	}
	err = meta.Write(w)
	if err != nil {
		return
	}
	err = header.Write(w)
	if err != nil {
		return
	}
	_, err = io.Copy(io.MultiWriter(newCipherStreamWriter(s, w), h), r)
	if err != nil {
		return
	}
	signed = h.Sum(nil)
	return
}

func Decrypt(in io.Reader, out io.Writer, pass []byte, printFn PrintFunc) (signed []byte, err error) {
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
	header, err := meta.Header()
	if err != nil {
		return
	}
	err = header.Read(r)
	if err != nil {
		return
	}
	cipher, mode, kdf, mac, md, sec, salt, iv := header.Get()
	err = ValidateConfig(cipher, mode, kdf, mac, md, sec)
	if err != nil {
		return
	}
	sm, mode := getStreamMode(mode, true)
	mdfn, md := getMD(md)
	dk, kdf, err := deriveKey(kdf, pass, salt, sec, mdfn, keySizes[cipher])
	if err != nil {
		return
	}
	s, cipher, err := newCipherStream(cipher, dk, iv, sm)
	if err != nil {
		return
	}
	h, mac := getMAC(mac, mdfn, dk)
	if printFn != nil {
		err = printFn(header.Version(), cipher, mode, kdf, mac, md, sec, pass, salt, iv, dk)
		if err != nil {
			return
		}
	}
	_, err = io.Copy(io.MultiWriter(w, h), newCipherStreamReader(s, r))
	if err != nil {
		return
	}
	signed = h.Sum(nil)
	return
}

var ErrSigVer = errors.New("signature verification failed")

func DecryptVerify(in io.Reader, out io.Writer, pass []byte, signex []byte, printFn PrintFunc) (signed []byte, err error) {
	signed, err = Decrypt(in, out, pass, printFn)
	if err != nil {
		return
	}
	if signex != nil {
		if !hmac.Equal(signex, signed) {
			err = ErrSigVer
		}
	}
	return
}
