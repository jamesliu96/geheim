package geheim

import (
	"crypto/hmac"
	"hash"
)

type MAC int

const (
	HMAC MAC = 1 + iota
)

var MACNames = map[MAC]string{
	HMAC: "HMAC",
}

var keySizesMAC = map[MAC]int{
	HMAC: 64,
}

var macs = [...]MAC{
	HMAC,
}

var MACString = getOptionString(macs[:], MACNames)

func getMAC(mac MAC, mdfn MDFunc, key []byte) (hash.Hash, error) {
	switch mac {
	case HMAC:
		return hmac.New(mdfn, key), nil
	}
	return nil, ErrMAC
}
