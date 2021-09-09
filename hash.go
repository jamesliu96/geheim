package geheim

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
	"strings"

	"golang.org/x/crypto/poly1305"
	"golang.org/x/crypto/sha3"
)

type MD uint8

const (
	SHA3_224 MD = 1 + iota
	SHA3_256
	SHA3_384
	SHA3_512
	SHA_224
	SHA_256
	SHA_384
	SHA_512
	SHA_512_224
	SHA_512_256
)

var MDNames = map[MD]string{
	SHA3_224:    "SHA3-224",
	SHA3_256:    "SHA3-256",
	SHA3_384:    "SHA3-384",
	SHA3_512:    "SHA3-512",
	SHA_224:     "SHA-224",
	SHA_256:     "SHA-256",
	SHA_384:     "SHA-384",
	SHA_512:     "SHA-512",
	SHA_512_224: "SHA-512-224",
	SHA_512_256: "SHA-512-256",
}

var mds = [...]MD{SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHA_224, SHA_256, SHA_384, SHA_512, SHA_512_224, SHA_512_256}

func GetMDString() string {
	d := make([]string, len(mds))
	for i, md := range mds {
		d[i] = fmt.Sprintf("%d:%s", md, MDNames[md])
	}
	return strings.Join(d, ", ")
}

func getMD(md MD) (func() hash.Hash, MD) {
	switch md {
	case SHA3_224:
		return sha3.New224, SHA3_224
	case SHA3_256:
		return sha3.New256, SHA3_256
	case SHA3_384:
		return sha3.New384, SHA3_384
	case SHA3_512:
		return sha3.New512, SHA3_512
	case SHA_224:
		return sha256.New224, SHA_224
	case SHA_256:
		return sha256.New, SHA_256
	case SHA_384:
		return sha512.New384, SHA_384
	case SHA_512:
		return sha512.New, SHA_512
	case SHA_512_224:
		return sha512.New512_224, SHA_512_224
	case SHA_512_256:
		return sha512.New512_256, SHA_512_256
	}
	return getMD(DefaultMD)
}

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
