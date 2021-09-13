package geheim

import (
	"crypto/hmac"
	"fmt"
	"hash"
	"io"
	"strings"

	"golang.org/x/crypto/poly1305"
)

type MAC uint8

const (
	HMAC MAC = 1 + iota
	Poly1305
)

var MACNames = map[MAC]string{
	HMAC:     "HMAC",
	Poly1305: "Poly1305",
}

var macs = [...]MAC{HMAC, Poly1305}

func GetMACString() string {
	d := make([]string, len(macs))
	for i, mac := range macs {
		d[i] = fmt.Sprintf("%d:%s", mac, MACNames[mac])
	}
	return strings.Join(d, ", ")
}

type messageAuth interface {
	io.Writer
	Sum([]byte) []byte
}

func getMAC(mac MAC, mdfn func() hash.Hash, key []byte) (messageAuth, MAC) {
	switch mac {
	case HMAC:
		return hmac.New(mdfn, key), HMAC
	case Poly1305:
		return poly1305.New((*[32]byte)(key)), Poly1305
	}
	return getMAC(DefaultMAC, mdfn, key)
}
