package geheim

import (
	"crypto/rand"
	"fmt"
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

func Encrypt(r io.Reader, w io.Writer, key []byte, cipher Cipher, mode Mode, kdf KDF, mac MAC, md MD, sec int, printFunc PrintFunc) (sign []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%+v", r)
		}
	}()
	salt := make([]byte, saltSizes[kdf])
	if _, err = rand.Read(salt); err != nil {
		return
	}
	nonce := make([]byte, nonceSizes[cipher])
	if _, err = rand.Read(nonce); err != nil {
		return
	}
	mdfn, err := getMD(md)
	if err != nil {
		return
	}
	keyCipher, keyMAC, err := deriveKeys(kdf, mdfn, sec, keySizesCipher[cipher], keySizesMAC[mac], key, salt)
	if err != nil {
		return
	}
	stream, err := newCipherStream(cipher, mode, false, keyCipher, nonce)
	if err != nil {
		return
	}
	mw, err := getMAC(mac, mdfn, keyMAC)
	if err != nil {
		return
	}
	meta := NewMeta()
	header, err := meta.Header()
	if err != nil {
		return
	}
	header.Set(cipher, mode, kdf, mac, md, sec, salt, nonce)
	if printFunc != nil {
		err = printFunc(int(meta.Version), header, key, keyCipher, keyMAC)
		if err != nil {
			return
		}
	}
	if err = meta.Write(w); err != nil {
		return
	}
	if err = header.Write(w); err != nil {
		return
	}
	if _, err = io.Copy(newStreamWriter(stream, io.MultiWriter(w, mw)), r); err != nil {
		return
	}
	sign = mw.Sum(nil)
	return
}

func Decrypt(r io.Reader, w io.Writer, key []byte, printFunc PrintFunc) (sign []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%+v", r)
		}
	}()
	meta := NewMeta()
	if err = meta.Read(r); err != nil {
		return
	}
	header, err := meta.Header()
	if err != nil {
		return
	}
	if err = header.Read(r); err != nil {
		return
	}
	cipher, mode, kdf, mac, md, sec, salt, nonce := header.Get()
	mdfn, err := getMD(md)
	if err != nil {
		return
	}
	keyCipher, keyMAC, err := deriveKeys(kdf, mdfn, sec, keySizesCipher[cipher], keySizesMAC[mac], key, salt)
	if err != nil {
		return
	}
	stream, err := newCipherStream(cipher, mode, true, keyCipher, nonce)
	if err != nil {
		return
	}
	mw, err := getMAC(mac, mdfn, keyMAC)
	if err != nil {
		return
	}
	if printFunc != nil {
		err = printFunc(int(meta.Version), header, key, keyCipher, keyMAC)
		if err != nil {
			return
		}
	}
	if _, err = io.Copy(w, newStreamReader(stream, io.TeeReader(r, mw))); err != nil {
		return
	}
	sign = mw.Sum(nil)
	return
}

func DecryptVerify(r io.Reader, w io.Writer, key []byte, signex []byte, printFunc PrintFunc) (sign []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%+v", r)
		}
	}()
	if sign, err = Decrypt(r, w, key, printFunc); err != nil {
		return
	}
	if signex != nil {
		err = Verify(signex, sign)
	}
	return
}

func EncryptArchive(r io.Reader, w io.Writer, key []byte, size int64, cipher Cipher, mode Mode, kdf KDF, mac MAC, md MD, sec int, printFunc PrintFunc) (sign []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%+v", r)
		}
	}()
	dataSize := Overhead + size
	if err = writeBEN(w, dataSize); err != nil {
		return
	}
	if sign, err = Encrypt(io.LimitReader(r, size), w, key, cipher, mode, kdf, mac, md, sec, printFunc); err != nil {
		return
	}
	if err = writeBEN(w, int64(len(sign))); err != nil {
		return
	}
	_, err = w.Write(sign)
	return
}

func DecryptArchive(r io.Reader, w io.Writer, key []byte, printFunc PrintFunc) (sign []byte, signex []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%+v", r)
		}
	}()
	dataSize, err := readBEN[int64](r)
	if err != nil {
		return
	}
	if sign, err = Decrypt(io.LimitReader(r, dataSize), w, key, printFunc); err != nil {
		return
	}
	signexSize, err := readBEN[int64](r)
	if err != nil {
		return
	}
	if signex, err = io.ReadAll(io.LimitReader(r, signexSize)); err != nil {
		return
	}
	err = Verify(signex, sign)
	return
}
