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

func Encrypt(r io.Reader, w io.Writer, pass []byte, cipher Cipher, mode Mode, kdf KDF, mac MAC, md MD, sec int, printFunc PrintFunc) (sign []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%+v", r)
		}
	}()
	salt := make([]byte, saltSizes[kdf])
	if _, err = rand.Read(salt); err != nil {
		return
	}
	iv := make([]byte, ivSizes[cipher])
	if _, err = rand.Read(iv); err != nil {
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
	meta := NewMeta()
	header, err := meta.Header()
	if err != nil {
		return
	}
	header.Set(cipher, mode, kdf, mac, md, sec, salt, iv)
	if printFunc != nil {
		err = printFunc(int(meta.Version), header, pass, keyCipher, keyMAC)
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

func Decrypt(r io.Reader, w io.Writer, pass []byte, printFunc PrintFunc) (sign []byte, err error) {
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
	if printFunc != nil {
		err = printFunc(int(meta.Version), header, pass, keyCipher, keyMAC)
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

func DecryptVerify(r io.Reader, w io.Writer, pass []byte, signex []byte, printFunc PrintFunc) (sign []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%+v", r)
		}
	}()
	if sign, err = Decrypt(r, w, pass, printFunc); err != nil {
		return
	}
	if signex != nil {
		err = Verify(signex, sign)
	}
	return
}

func EncryptArchive(r io.Reader, w io.Writer, pass []byte, size int64, cipher Cipher, mode Mode, kdf KDF, mac MAC, md MD, sec int, printFunc PrintFunc) (sign []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%+v", r)
		}
	}()
	dataSize := OverheadSize + size
	if err = writeBEInt64(w, dataSize); err != nil {
		return
	}
	pw := NewProgressWriter(dataSize)
	if sign, err = Encrypt(io.LimitReader(r, size), io.MultiWriter(w, pw), pass, cipher, mode, kdf, mac, md, sec, printFunc); err != nil {
		return
	}
	if err = pw.Close(); err != nil {
		return
	}
	if err = writeBEInt64(w, int64(len(sign))); err != nil {
		return
	}
	_, err = w.Write(sign)
	return
}

func DecryptArchive(r io.Reader, w io.Writer, pass []byte, printFunc PrintFunc) (sign []byte, signex []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%+v", r)
		}
	}()
	dataSize, err := readBEInt64(r)
	if err != nil {
		return
	}
	if sign, err = Decrypt(io.LimitReader(r, dataSize), w, pass, printFunc); err != nil {
		return
	}
	signexSize, err := readBEInt64(r)
	if err != nil {
		return
	}
	if signex, err = io.ReadAll(io.LimitReader(r, signexSize)); err != nil {
		return
	}
	err = Verify(signex, sign)
	return
}
