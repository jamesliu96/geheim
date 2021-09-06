package geheim

import (
	"bufio"
	"crypto/aes"
	"crypto/hmac"
	"io"
)

const (
	sizeSalt = 16
	sizeIV   = aes.BlockSize
	sizeKey  = 32
)

const (
	DefaultCipher  = AES
	DefaultKDF     = PBKDF2
	DefaultMode    = CTR
	DefaultMd      = SHA_256
	DefaultKeyIter = 100000
)

func Encrypt(in io.Reader, out io.Writer, pass []byte, cipher Cipher, kdf KDF, mode Mode, md Md, keyIter int, printFn PrintFunc) (sign []byte, err error) {
	err = checkArgs(in, out, pass)
	if err != nil {
		return
	}
	err = ValidateConfig(cipher, kdf, mode, md, keyIter)
	if err != nil {
		return
	}
	salt := make([]byte, sizeSalt)
	err = randRead(salt)
	if err != nil {
		return
	}
	iv := make([]byte, sizeIV)
	err = randRead(iv)
	if err != nil {
		return
	}
	sm, mode := getCipherStreamMode(mode, false)
	mdfn, md := getMd(md)
	dk, kdf := deriveKey(kdf, pass, salt, keyIter, mdfn)
	if printFn != nil {
		printFn(cipher, kdf, mode, md, keyIter, salt, iv, dk)
	}
	r := bufio.NewReader(in)
	w := bufio.NewWriter(out)
	defer (func() {
		if err == nil {
			err = w.Flush()
		}
	})()
	meta := newMeta()
	err = meta.Write(w)
	if err != nil {
		return
	}
	header, err := meta.GetHeader()
	if err != nil {
		return
	}
	header.Set(cipher, kdf, mode, md, keyIter, salt, iv)
	err = header.Write(w)
	if err != nil {
		return
	}
	block, err := newAESCipherBlock(dk)
	if err != nil {
		return
	}
	s := sm(block, iv)
	sw := newCipherStreamWriter(s, w)
	h := hmac.New(mdfn, dk)
	_, err = io.Copy(io.MultiWriter(sw, h), r)
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
	cipher, kdf, mode, md, keyIter, salt, iv := header.Get()
	err = ValidateConfig(cipher, kdf, mode, md, keyIter)
	if err != nil {
		return
	}
	sm, mode := getCipherStreamMode(mode, true)
	mdfn, md := getMd(md)
	dk, kdf := deriveKey(kdf, pass, salt, keyIter, mdfn)
	if printFn != nil {
		printFn(cipher, kdf, mode, md, keyIter, salt, iv, dk)
	}
	w := bufio.NewWriter(out)
	defer (func() {
		if err == nil {
			err = w.Flush()
		}
	})()
	block, err := newAESCipherBlock(dk)
	if err != nil {
		return
	}
	s := sm(block, iv)
	sr := newCipherStreamReader(s, r)
	h := hmac.New(mdfn, dk)
	_, err = io.Copy(io.MultiWriter(w, h), sr)
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
