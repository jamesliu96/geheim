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

func deriveKey(kdf KDF, pass, salt []byte, iter int, md func() hash.Hash) ([]byte, KDF, error) {
	switch kdf {
	case PBKDF2:
		return pbkdf2.Key(pass, salt, iter, keySize, md), PBKDF2, nil
	case Argon2:
		r := float64(iter) / DefaultKeyIter
		return argon2.IDKey(pass, salt, uint32(4*r), uint32(65536*r), uint8(runtime.NumCPU()), keySize), Argon2, nil
	case Scrypt:
		r := float64(iter) / DefaultKeyIter
		key, err := scrypt.Key(pass, salt, int(32768*r), 8, 1, keySize)
		return key, Scrypt, err
	}
	return deriveKey(DefaultKDF, pass, salt, iter, md)
}

var KDFNames = map[KDF]string{
	PBKDF2: "PBKDF2",
	Argon2: "Argon2",
	Scrypt: "Scrypt",
}

var kdfs = [...]KDF{PBKDF2, Argon2, Scrypt}

func GetKDFString() string {
	d := []string{}
	for _, kdf := range kdfs {
		d = append(d, fmt.Sprintf("%d:%s", kdf, KDFNames[kdf]))
	}
	return strings.Join(d, ", ")
}
