package geheim

import (
	"bufio"
	"crypto/hmac"
	"errors"
	"io"
)

const (
	DefaultCipher = AES_256
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
		if e := bw.Flush(); err == nil {
			err = e
		}
	})()
	salt := make([]byte, saltSize)
	if err = randRead(salt); err != nil {
		return
	}
	iv := make([]byte, ivSizes[cipher])
	if err = randRead(iv); err != nil {
		return
	}
	if err = Validate(cipher, mode, kdf, mac, md, sec); err != nil {
		return
	}
	sm, mode := getStreamMode(mode, false)
	mdfn, md := getMD(md)
	keyCipher, keyMAC, kdf, sec, err := deriveKeys(kdf, pass, salt, sec, mdfn, keySizesCipher[cipher], keySizesMAC[mac])
	if err != nil {
		return
	}
	stream, cipher, err := newCipherStream(cipher, keyCipher, iv, sm)
	if err != nil {
		return
	}
	mw, mac := getMAC(mac, mdfn, keyMAC)
	meta := NewMeta(HeaderVersion)
	header, err := meta.Header()
	if err != nil {
		return
	}
	header.Set(cipher, mode, kdf, mac, md, sec, salt, iv)
	if printFn != nil {
		err = printFn(header.Version(), cipher, mode, kdf, mac, md, sec, pass, salt, iv, keyCipher, keyMAC)
		if err != nil {
			return
		}
	}
	if err = meta.Write(bw); err != nil {
		return
	}
	if err = header.Write(bw); err != nil {
		return
	}
	if _, err = io.Copy(newCipherStreamWriter(stream, io.MultiWriter(bw, mw)), br); err != nil {
		return
	}
	sign = mw.Sum(nil)
	return
}

func Decrypt(r io.Reader, w io.Writer, pass []byte, printFn PrintFunc) (sign []byte, err error) {
	br := bufio.NewReader(r)
	bw := bufio.NewWriter(w)
	defer (func() {
		if e := bw.Flush(); err == nil {
			err = e
		}
	})()
	meta := &Meta{}
	if err = meta.Read(br); err != nil {
		return
	}
	header, err := meta.Header()
	if err != nil {
		return
	}
	if err = header.Read(br); err != nil {
		return
	}
	cipher, mode, kdf, mac, md, sec, salt, iv := header.Get()
	if err = Validate(cipher, mode, kdf, mac, md, sec); err != nil {
		return
	}
	sm, mode := getStreamMode(mode, true)
	mdfn, md := getMD(md)
	keyCipher, keyMAC, kdf, sec, err := deriveKeys(kdf, pass, salt, sec, mdfn, keySizesCipher[cipher], keySizesMAC[mac])
	if err != nil {
		return
	}
	stream, cipher, err := newCipherStream(cipher, keyCipher, iv, sm)
	if err != nil {
		return
	}
	mw, mac := getMAC(mac, mdfn, keyMAC)
	if printFn != nil {
		err = printFn(header.Version(), cipher, mode, kdf, mac, md, sec, pass, salt, iv, keyCipher, keyMAC)
		if err != nil {
			return
		}
	}
	if _, err = io.Copy(bw, newCipherStreamReader(stream, io.TeeReader(br, mw))); err != nil {
		return
	}
	sign = mw.Sum(nil)
	return
}

var ErrSigVer = errors.New("signature verification failed")

func DecryptVerify(r io.Reader, w io.Writer, pass []byte, signex []byte, printFn PrintFunc) (sign []byte, err error) {
	if sign, err = Decrypt(r, w, pass, printFn); err != nil {
		return
	}
	if signex != nil {
		if !hmac.Equal(signex, sign) {
			err = ErrSigVer
		}
	}
	return
}
