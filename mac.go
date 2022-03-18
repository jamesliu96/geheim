package geheim

import (
	"crypto/hmac"
	"hash"
)

type MAC uint8

const (
	HMAC MAC = 1 + iota
)

var MACNames = map[MAC]string{
	HMAC: "HMAC",
}

var macs = [...]MAC{HMAC}

func GetMACString() string {
	return getString(macs[:], MACNames)
}

func getMAC(mac MAC, mdfn func() hash.Hash, key []byte) (hash.Hash, MAC) {
	switch mac {
	case HMAC:
		return hmac.New(mdfn, key), HMAC
	}
	return getMAC(DefaultMAC, mdfn, key)
}
