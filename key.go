package geheim

import (
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

type KDF uint8

const (
	_ KDF = 1 + iota
	Argon2id
	Scrypt
)

var KDFNames = map[KDF]string{
	Argon2id: "Argon2id",
	Scrypt:   "Scrypt",
}

var saltSizes = map[KDF]int{
	Argon2id: 32,
	Scrypt:   32,
}

var kdfs = [...]KDF{
	Argon2id,
	Scrypt,
}

var KDFString = getOptionString(kdfs[:], KDFNames)

const (
	MinSec = 0
	MaxSec = 20
)

func GetMemory(sec int) int64 { return 1 << (20 + sec) }

func deriveKey(kdf KDF, pass, salt []byte, sec int, size int) ([]byte, error) {
	if len(pass) == 0 {
		return nil, ErrEptPass
	}
	if err := checkBytesSize(saltSizes, kdf, salt, "salt"); err != nil {
		return nil, err
	}
	if sec < MinSec || sec > MaxSec {
		return nil, ErrInvSec
	}
	memory := GetMemory(sec)
	switch kdf {
	case Argon2id:
		return argon2.IDKey(pass, salt, 1, uint32(memory/1024), 128, uint32(size)), nil
	case Scrypt:
		const r, p = 8, 1
		key, err := scrypt.Key(pass, salt, int(memory/128/r/p), r, p, size)
		return key, err
	}
	return nil, ErrInvKDF
}

func deriveKeys(kdf KDF, pass, salt []byte, sec int, sizeCipher, sizeMAC int) (keyCipher, keyMAC []byte, err error) {
	key, err := deriveKey(kdf, pass, salt, sec, sizeCipher+sizeMAC)
	if err != nil {
		return
	}
	keyCipher, keyMAC = key[:sizeCipher], key[sizeCipher:sizeCipher+sizeMAC]
	return
}
