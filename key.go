package geheim

import (
	"math"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

const saltSize = 32

type KDF uint8

const (
	PBKDF2 KDF = 1 + iota
	Argon2
	Scrypt
)

var KDFNames = map[KDF]string{
	PBKDF2: "PBKDF2",
	Argon2: "Argon2",
	Scrypt: "Scrypt",
}

var kdfs = [...]KDF{PBKDF2, Argon2, Scrypt}

func GetKDFString() string {
	return getString(kdfs[:], KDFNames)
}

const (
	MinSec = 0
	MaxSec = 20
)

func GetSecIterMemory(sec int) (int, int64, int) {
	sec = int(math.Min(MaxSec, math.Max(MinSec, float64(sec))))
	iter := 1e6 * sec
	memory := int64(1 << (20 + sec))
	return iter, memory, sec
}

func deriveKey(kdf KDF, pass, salt []byte, sec int, mdfn MDFunc, size int) ([]byte, KDF, int, error) {
	iter, memory, sec := GetSecIterMemory(sec)
	switch kdf {
	case PBKDF2:
		return pbkdf2.Key(pass, salt, iter, size, mdfn), PBKDF2, sec, nil
	case Argon2:
		return argon2.IDKey(pass, salt, 1, uint32(memory/1024), 128, uint32(size)), Argon2, sec, nil
	case Scrypt:
		const r, p = 8, 1
		key, err := scrypt.Key(pass, salt, int(memory/128/r/p), r, p, size)
		return key, Scrypt, sec, err
	}
	return deriveKey(DefaultKDF, pass, salt, sec, mdfn, size)
}

func deriveKeys(kdf KDF, pass, salt []byte, sec int, mdfn MDFunc, sizeCipher, sizeMAC int) ([]byte, []byte, KDF, int, error) {
	key, kdf, sec, err := deriveKey(kdf, pass, salt, sec, mdfn, sizeCipher+sizeMAC)
	if err != nil {
		return nil, nil, kdf, sec, err
	}
	return key[:sizeCipher], key[sizeCipher : sizeCipher+sizeMAC], kdf, sec, err
}
