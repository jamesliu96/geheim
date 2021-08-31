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
	DefaultMode    = ModeCTR
	DefaultMd      = SHA_256
	DefaultKeyIter = 100000
)

func Encrypt(in io.Reader, out io.Writer, pass []byte, mode Mode, md Md, keyIter int, printFn PrintFunc) (sign []byte, err error) {
	err = checkArgs(in, out, pass)
	if err != nil {
		return
	}
	err = ValidateConfig(mode, md, keyIter)
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
	dk := deriveKey(pass, salt, keyIter, mdfn)
	if printFn != nil {
		printFn(mode, md, keyIter, salt, iv, dk)
	}
	r := bufio.NewReader(in)
	w := bufio.NewWriter(out)
	defer (func() {
		if err == nil {
			err = w.Flush()
		}
	})()
	err = newHeader(uint16(mode), uint16(md), uint32(keyIter), salt, iv).write(w)
	if err != nil {
		return
	}
	block, err := newCipherBlock(dk)
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
	header := &header{}
	err = header.read(r)
	if err != nil {
		return
	}
	mode := Mode(header.Mode)
	md := Md(header.Md)
	keyIter := int(header.KeyIter)
	err = ValidateConfig(mode, md, keyIter)
	if err != nil {
		return
	}
	salt := header.Salt[:]
	iv := header.IV[:]
	sm, mode := getCipherStreamMode(mode, true)
	mdfn, md := getMd(md)
	dk := deriveKey(pass, salt, keyIter, mdfn)
	if printFn != nil {
		printFn(mode, md, keyIter, salt, iv, dk)
	}
	w := bufio.NewWriter(out)
	defer (func() {
		if err == nil {
			err = w.Flush()
		}
	})()
	block, err := newCipherBlock(dk)
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
