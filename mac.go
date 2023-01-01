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

var keySizesMAC = map[MAC]int{
	HMAC: 64,
}

var macs = [...]MAC{HMAC}

var MACString = getOptionString(macs[:], MACNames)

func checkKeySizeMAC(mac MAC, key []byte) error {
	return checkBytesSize(keySizesMAC, mac, key, "mac key")
}

func getMAC(mac MAC, mdfn MDFunc, key []byte) (hash.Hash, error) {
	if err := checkKeySizeMAC(mac, key); err != nil {
		return nil, err
	}
	switch mac {
	case HMAC:
		return hmac.New(mdfn, key), nil
	}
	return nil, ErrInvMAC
}
