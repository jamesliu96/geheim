package geheim

import (
	"crypto/rand"
	"fmt"
	"io"
)

const (
	DefaultCipher = AES_256_CTR
	DefaultKDF    = Argon2id
	DefaultHash   = SHA_256
	DefaultSec    = 10
)

func Encrypt(r io.Reader, w io.Writer, key []byte, cipher Cipher, hash Hash, kdf KDF, sec int, printFunc PrintFunc) (auth []byte, err error) {
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
	h, err := getHash(hash)
	if err != nil {
		return
	}
	keyCipher, keyHMAC, err := deriveKeys(kdf, h, sec, keySizesCipher[cipher], keyHMACSize, key, salt)
	if err != nil {
		return
	}
	stream, err := newCipherStream(cipher, keyCipher, nonce)
	if err != nil {
		return
	}
	mw := newHMAC(h, keyHMAC)
	meta := NewMeta()
	header, err := meta.Header()
	if err != nil {
		return
	}
	header.Set(cipher, hash, kdf, sec, salt, nonce)
	if printFunc != nil {
		err = printFunc(int(meta.Version), header, key)
		if err != nil {
			return
		}
	}
	nw := io.MultiWriter(w, mw)
	if err = meta.Write(nw); err != nil {
		return
	}
	if err = header.Write(nw); err != nil {
		return
	}
	if _, err = io.Copy(newStreamWriter(stream, nw), r); err != nil {
		return
	}
	auth = mw.Sum(nil)
	return
}

func Decrypt(r io.Reader, w io.Writer, key []byte, printFunc PrintFunc) (auth []byte, err error) {
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
	cipher, hash, kdf, sec, salt, nonce := header.Get()
	h, err := getHash(hash)
	if err != nil {
		return
	}
	keyCipher, keyHMAC, err := deriveKeys(kdf, h, sec, keySizesCipher[cipher], keyHMACSize, key, salt)
	if err != nil {
		return
	}
	stream, err := newCipherStream(cipher, keyCipher, nonce)
	if err != nil {
		return
	}
	mw := newHMAC(h, keyHMAC)
	if printFunc != nil {
		err = printFunc(int(meta.Version), header, key)
		if err != nil {
			return
		}
	}
	if err = meta.Write(mw); err != nil {
		return
	}
	if err = header.Write(mw); err != nil {
		return
	}
	if _, err = io.Copy(w, newStreamReader(stream, io.TeeReader(r, mw))); err != nil {
		return
	}
	auth = mw.Sum(nil)
	return
}

func DecryptVerify(r io.Reader, w io.Writer, key, authex []byte, printFunc PrintFunc) (auth []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%+v", r)
		}
	}()
	if auth, err = Decrypt(r, w, key, printFunc); err != nil {
		return
	}
	if authex != nil {
		err = Verify(authex, auth)
	}
	return
}

func EncryptArchive(r io.Reader, w io.Writer, key []byte, size int64, cipher Cipher, hash Hash, kdf KDF, sec int, printFunc PrintFunc) (auth []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%+v", r)
		}
	}()
	dataSize := OverheadSize + size
	if err = writeBEN(w, dataSize); err != nil {
		return
	}
	if auth, err = Encrypt(io.LimitReader(r, size), w, key, cipher, hash, kdf, sec, printFunc); err != nil {
		return
	}
	if err = writeBEN(w, int64(len(auth))); err != nil {
		return
	}
	_, err = w.Write(auth)
	return
}

func DecryptArchive(r io.Reader, w io.Writer, key []byte, printFunc PrintFunc) (auth, authex []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%+v", r)
		}
	}()
	dataSize, err := readBEN[int64](r)
	if err != nil {
		return
	}
	if auth, err = Decrypt(io.LimitReader(r, dataSize), w, key, printFunc); err != nil {
		return
	}
	authexSize, err := readBEN[int64](r)
	if err != nil {
		return
	}
	if authex, err = io.ReadAll(io.LimitReader(r, authexSize)); err != nil {
		return
	}
	err = Verify(authex, auth)
	return
}
