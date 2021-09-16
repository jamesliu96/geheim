package geheim

import (
	"crypto/hmac"
	"fmt"
	"hash"
	"strings"
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
	d := make([]string, len(macs))
	for i, mac := range macs {
		d[i] = fmt.Sprintf("%d:%s", mac, MACNames[mac])
	}
	return strings.Join(d, ", ")
}

func getMAC(mac MAC, mdfn func() hash.Hash, key []byte) (sumWriter, MAC) {
	switch mac {
	case HMAC:
		return hmac.New(mdfn, key), HMAC
	}
	return getMAC(DefaultMAC, mdfn, key)
}
