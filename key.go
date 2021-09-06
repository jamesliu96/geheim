package geheim

import (
	"fmt"
	"hash"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

type KDF uint8

const (
	PBKDF2 KDF = 1 + iota
)

func deriveKey(kdf KDF, pass, salt []byte, iter int, md func() hash.Hash) ([]byte, KDF) {
	switch kdf {
	case PBKDF2:
		return pbkdf2.Key(pass, salt, iter, sizeKey, md), PBKDF2
	}
	return deriveKey(DefaultKDF, pass, salt, iter, md)
}

var KDFNames = map[KDF]string{
	PBKDF2: "PBKDF2",
}

var kdfs = [...]KDF{PBKDF2}

func GetKDFString() string {
	d := []string{}
	for _, kdf := range kdfs {
		d = append(d, fmt.Sprintf("%d:%s", kdf, KDFNames[kdf]))
	}
	return strings.Join(d, ", ")
}
