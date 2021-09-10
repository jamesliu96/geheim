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

func getSecParam(sec int) (int, uint32, uint32, int, int, int) {
	switch sec {
	case 1:
		return 100000,
			1, 65535,
			32768, 8, 1
	case 2:
		return 200000,
			1, 65535 * 2,
			32768, 8, 2
	case 3:
		return 300000,
			2, 65535,
			32768, 16, 1
	case 4:
		return 400000,
			2, 65535 * 2,
			32768, 16, 2
	case 5:
		return 500000,
			3, 65535,
			32768, 32, 2
	case 6:
		return 600000,
			3, 65535 * 2,
			32768 * 2, 8, 1
	case 7:
		return 700000,
			4, 65535,
			32768 * 2, 8, 2
	case 8:
		return 800000,
			4, 65535 * 2,
			32768 * 2, 16, 1
	case 9:
		return 900000,
			5, 65535,
			32768 * 2, 16, 2
	case 10:
		return 1000000,
			5, 65535 * 2,
			32768 * 2, 32, 2
	}
	return getSecParam(MinSec)
}

func deriveKey(kdf KDF, pass, salt []byte, sec int, mdfn func() hash.Hash, size int) ([]byte, KDF, error) {
	iter, time, memory, N, p, r := getSecParam(sec)
	switch kdf {
	case PBKDF2:
		return pbkdf2.Key(pass, salt, iter, size, mdfn), PBKDF2, nil
	case Argon2:
		return argon2.IDKey(pass, salt, time, memory, uint8(runtime.NumCPU()), uint32(size)), Argon2, nil
	case Scrypt:
		key, err := scrypt.Key(pass, salt, N, p, r, size)
		return key, Scrypt, err
	}
	return deriveKey(DefaultKDF, pass, salt, sec, mdfn, size)
}
