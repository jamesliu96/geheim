package geheim

import (
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

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

var saltSizes = map[KDF]int{
	PBKDF2: 32,
	Argon2: 32,
	Scrypt: 32,
}

var kdfs = [...]KDF{PBKDF2, Argon2, Scrypt}

var KDFString = getOptionString(kdfs[:], KDFNames)

const (
	MinSec = 0
	MaxSec = 20
)

func GetSecIterMemory(sec int) (iter int, memory int64) {
	iter = 1e6 * sec
	memory = int64(1 << (20 + sec))
	return
}

func deriveKey(kdf KDF, pass, salt []byte, sec int, mdfn MDFunc, size int) ([]byte, error) {
	if err := checkBytesSize(saltSizes, kdf, salt, "salt"); err != nil {
		return nil, err
	}
	iter, memory := GetSecIterMemory(sec)
	switch kdf {
	case PBKDF2:
		return pbkdf2.Key(pass, salt, iter, size, mdfn), nil
	case Argon2:
		return argon2.IDKey(pass, salt, 1, uint32(memory/1024), 128, uint32(size)), nil
	case Scrypt:
		const r, p = 8, 1
		key, err := scrypt.Key(pass, salt, int(memory/128/r/p), r, p, size)
		return key, err
	}
	return nil, ErrInvKDF
}

func deriveKeys(kdf KDF, pass, salt []byte, sec int, mdfn MDFunc, sizeCipher, sizeMAC int) (keyCipher, keyMAC []byte, err error) {
	key, err := deriveKey(kdf, pass, salt, sec, mdfn, sizeCipher+sizeMAC)
	keyCipher, keyMAC = key[:sizeCipher], key[sizeCipher:sizeCipher+sizeMAC]
	return
}
