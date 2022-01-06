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

func Encrypt(r io.Reader, w io.Writer, pass []byte, cipher Cipher, mode Mode, kdf KDF, mac MAC, md MD, sec int, printFn PrintFunc) (sign []byte, err error) {
	br := bufio.NewReader(r)
	bw := bufio.NewWriter(w)
	defer (func() {
		if err == nil {
			err = bw.Flush()
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
	err = Validate(cipher, mode, kdf, mac, md, sec)
	if err != nil {
		return
	}
	sm, mode := getStreamMode(mode, false)
	mdfn, md := getMD(md)
	dk, kdf, sec, err := deriveKey(kdf, pass, salt, sec, mdfn, keySizes[cipher])
	if err != nil {
		return
	}
	s, cipher, err := newCipherStream(cipher, dk, iv, sm)
	if err != nil {
		return
	}
	h, mac := getMAC(mac, mdfn, dk)
	meta := NewMeta(HeaderVersion)
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
	err = meta.Write(bw)
	if err != nil {
		return
	}
	err = header.Write(bw)
	if err != nil {
		return
	}
	_, err = io.Copy(io.MultiWriter(newCipherStreamWriter(s, bw), h), br)
	if err != nil {
		return
	}
	sign = h.Sum(nil)
	return
}

func Decrypt(r io.Reader, w io.Writer, pass []byte, printFn PrintFunc) (sign []byte, err error) {
	br := bufio.NewReader(r)
	bw := bufio.NewWriter(w)
	defer (func() {
		if err == nil {
			err = bw.Flush()
		}
	})()
	meta := &Meta{}
	err = meta.Read(br)
	if err != nil {
		return
	}
	header, err := meta.Header()
	if err != nil {
		return
	}
	err = header.Read(br)
	if err != nil {
		return
	}
	cipher, mode, kdf, mac, md, sec, salt, iv := header.Get()
	err = Validate(cipher, mode, kdf, mac, md, sec)
	if err != nil {
		return
	}
	sm, mode := getStreamMode(mode, true)
	mdfn, md := getMD(md)
	dk, kdf, sec, err := deriveKey(kdf, pass, salt, sec, mdfn, keySizes[cipher])
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
	_, err = io.Copy(io.MultiWriter(bw, h), newCipherStreamReader(s, br))
	if err != nil {
		return
	}
	sign = h.Sum(nil)
	return
}

var ErrSigVer = errors.New("signature verification failed")

func DecryptVerify(r io.Reader, w io.Writer, pass []byte, signex []byte, printFn PrintFunc) (sign []byte, err error) {
	sign, err = Decrypt(r, w, pass, printFn)
	if err != nil {
		return
	}
	if signex != nil {
		if !hmac.Equal(signex, sign) {
			err = ErrSigVer
		}
	}
	return
}
