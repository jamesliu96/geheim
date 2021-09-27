package geheim

import (
	"errors"
	"fmt"
	"hash"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

const saltSize = 16

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
	d := make([]string, len(kdfs))
	for i, kdf := range kdfs {
		d[i] = fmt.Sprintf("%d:%s", kdf, KDFNames[kdf])
	}
	return strings.Join(d, ", ")
}

const (
	MinSec = 1
	MaxSec = 20
)

func GetSecIterMemory(sec int) (iter int, memory int64) {
	iter = 1e6 * sec
	memory = 1 << (20 + sec)
	return
}

func checkSaltSize(salt []byte) error {
	if saltSize != len(salt) {
		return errors.New("invalid salt size")
	}
	return nil
}

func deriveKey(kdf KDF, pass, salt []byte, sec int, mdfn func() hash.Hash, size int) ([]byte, KDF, error) {
	if err := checkSaltSize(salt); err != nil {
		return nil, kdf, err
	}
	iter, memory := GetSecIterMemory(sec)
	switch kdf {
	case PBKDF2:
		return pbkdf2.Key(pass, salt, iter, size, mdfn), PBKDF2, nil
	case Argon2:
		const threads = 128
		return argon2.IDKey(pass, salt, 1, uint32(memory/1024), threads, uint32(size)), Argon2, nil
	case Scrypt:
		const r, p = 8, 1
		N := int(memory / 128 / r / p)
		key, err := scrypt.Key(pass, salt, N, r, p, size)
		return key, Scrypt, err
	}
	return deriveKey(DefaultKDF, pass, salt, sec, mdfn, size)
}
