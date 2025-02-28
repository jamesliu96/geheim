package geheim

import (
	"crypto/hmac"
	"hash"
)

const keySizeHMAC = 64

func newHMAC(mdfn MDFunc, key []byte) hash.Hash {
	return hmac.New(mdfn, key)
}
