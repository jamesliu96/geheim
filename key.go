package geheim

import (
	"hash"

	"golang.org/x/crypto/pbkdf2"
)

func deriveKey(pass, salt []byte, iter int, md func() hash.Hash) []byte {
	return pbkdf2.Key(pass, salt, iter, sizeKey, md)
}
