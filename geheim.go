package geheim

import (
	"bufio"
	"crypto/hmac"
	"io"
)

const (
	DefaultCipher = AES_256
	DefaultMode   = CTR
	DefaultKDF    = Argon2id
	DefaultMAC    = HMAC
	DefaultMD     = SHA_256
	DefaultSec    = 10
)

func Encrypt(r io.Reader, w io.Writer, pass []byte, cipher Cipher, mode Mode, kdf KDF, mac MAC, md MD, sec int, printFn PrintFunc) (sign []byte, err error) {
	br := bufio.NewReader(r)
	bw := bufio.NewWriter(w)
	defer func() {
		if e := bw.Flush(); err == nil {
			err = e
		}
	}()
	salt := make([]byte, saltSizes[kdf])
	if err = randRead(salt); err != nil {
		return
	}
	iv := make([]byte, ivSizes[cipher])
	if err = randRead(iv); err != nil {
		return
	}
	sm, err := getStreamMode(mode, false)
	if err != nil {
		return
	}
	mdfn, err := getMD(md)
	if err != nil {
		return
	}
	keyCipher, keyMAC, err := deriveKeys(kdf, pass, salt, sec, keySizesCipher[cipher], keySizesMAC[mac])
	if err != nil {
		return
	}
	stream, err := newCipherStream(cipher, keyCipher, iv, sm)
	if err != nil {
		return
	}
	mw, err := getMAC(mac, mdfn, keyMAC)
	if err != nil {
		return
	}
	meta := newMeta()
	header, err := meta.Header()
	if err != nil {
		return
	}
	header.Set(cipher, mode, kdf, mac, md, sec, salt, iv)
	if printFn != nil {
		err = printFn(int(meta.Version), header, pass, keyCipher, keyMAC)
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
	if _, err = io.Copy(newStreamWriter(stream, io.MultiWriter(bw, mw)), br); err != nil {
		return
	}
	sign = mw.Sum(nil)
	return
}

func Decrypt(r io.Reader, w io.Writer, pass []byte, printFn PrintFunc) (sign []byte, err error) {
	br := bufio.NewReader(r)
	bw := bufio.NewWriter(w)
	defer func() {
		if e := bw.Flush(); err == nil {
			err = e
		}
	}()
	meta := newMeta()
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
	sm, err := getStreamMode(mode, true)
	if err != nil {
		return
	}
	mdfn, err := getMD(md)
	if err != nil {
		return
	}
	keyCipher, keyMAC, err := deriveKeys(kdf, pass, salt, sec, keySizesCipher[cipher], keySizesMAC[mac])
	if err != nil {
		return
	}
	stream, err := newCipherStream(cipher, keyCipher, iv, sm)
	if err != nil {
		return
	}
	mw, err := getMAC(mac, mdfn, keyMAC)
	if err != nil {
		return
	}
	if printFn != nil {
		err = printFn(int(meta.Version), header, pass, keyCipher, keyMAC)
		if err != nil {
			return
		}
	}
	if _, err = io.Copy(bw, newStreamReader(stream, io.TeeReader(br, mw))); err != nil {
		return
	}
	sign = mw.Sum(nil)
	return
}

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
