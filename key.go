package geheim

import (
	"crypto/hkdf"
	"fmt"
	"hash"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

type KDF int

const (
	HKDF KDF = 1 + iota
	Argon2id
	Scrypt
)

var KDFNames = map[KDF]string{
	HKDF:     "HKDF",
	Argon2id: "Argon2id",
	Scrypt:   "Scrypt",
}

var saltSizes = map[KDF]int{
	HKDF:     32,
	Argon2id: 32,
	Scrypt:   32,
}

var kdfs = [...]KDF{
	HKDF,
	Argon2id,
	Scrypt,
}

var KDFString = getOptionString(kdfs[:], KDFNames)

const (
	infoCIP = "CIP"
	infoMAC = "MAC"
)

const keyMasterSize = 32

const (
	MinSec = 0
	MaxSec = 20
)

func GetMemory(sec int) int64 { return 1 << (20 + sec) }

var SecString = func() string {
	d := make([]string, MaxSec-MinSec+1)
	for i := MinSec; i <= MaxSec; i++ {
		d[i] = fmt.Sprintf("%d:%s", i, FormatSize(GetMemory(i), 0))
	}
	return strings.Join(d, ", ")
}()

func deriveKey(kdf KDF, sec, size int, key, salt []byte) ([]byte, error) {
	if sec < MinSec || sec > MaxSec {
		return nil, ErrSec
	}
	memory := GetMemory(sec)
	switch kdf {
	case Argon2id:
		return argon2.IDKey(key, salt, 1, uint32(memory/1024), 128, uint32(size)), nil
	case Scrypt:
		const r, p = 8, 1
		key, err := scrypt.Key(key, salt, int(memory/128/r/p), r, p, size)
		return key, err
	}
	return nil, ErrKDF
}

func deriveKeys(kdf KDF, h func() hash.Hash, sec, sizeCipher, sizeMAC int, key, salt []byte) ([]byte, []byte, error) {
	if len(key) == 0 {
		return nil, nil, ErrKey
	}
	if err := checkBytesSize(saltSizes, kdf, salt, "salt"); err != nil {
		return nil, nil, err
	}
	keyMaster := key
	if kdf != HKDF {
		var err error
		if keyMaster, err = deriveKey(kdf, sec, keyMasterSize, key, salt); err != nil {
			return nil, nil, err
		}
	}
	keyCipher, err := hkdf.Key(h, keyMaster, salt, infoCIP, sizeCipher)
	if err != nil {
		return nil, nil, err
	}
	keyMAC, err := hkdf.Key(h, keyMaster, salt, infoMAC, sizeMAC)
	if err != nil {
		return nil, nil, err
	}
	return keyCipher, keyMAC, nil
}
