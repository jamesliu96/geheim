package geheim

import (
	"fmt"
	"hash"
	"runtime"
	"strings"

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

func GetSecIterMemory(sec int) (int, int) {
	return 100000 * sec, 1 << (20 + sec)
}

func deriveKey(kdf KDF, pass, salt []byte, sec int, mdfn func() hash.Hash, size int) ([]byte, KDF, error) {
	iter, memory := GetSecIterMemory(sec)
	switch kdf {
	case PBKDF2:
		return pbkdf2.Key(pass, salt, iter, size, mdfn), PBKDF2, nil
	case Argon2:
		return argon2.IDKey(pass, salt, 1, uint32(memory/1024), uint8(runtime.NumCPU()), uint32(size)), Argon2, nil
	case Scrypt:
		r, p := 8, 1
		N := memory / 128 / r / p
		key, err := scrypt.Key(pass, salt, N, r, p, size)
		return key, Scrypt, err
	}
	return deriveKey(DefaultKDF, pass, salt, sec, mdfn, size)
}
