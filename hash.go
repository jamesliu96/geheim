package geheim

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
)

type MD int

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
	BLAKE2b_256
	BLAKE2b_384
	BLAKE2b_512
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
	SHA_512_224: "SHA-512/224",
	SHA_512_256: "SHA-512/256",
	BLAKE2b_256: "BLAKE2b-256",
	BLAKE2b_384: "BLAKE2b-384",
	BLAKE2b_512: "BLAKE2b-512",
}

var mds = [...]MD{
	SHA3_224,
	SHA3_256,
	SHA3_384,
	SHA3_512,
	SHA_224,
	SHA_256,
	SHA_384,
	SHA_512,
	SHA_512_224,
	SHA_512_256,
	BLAKE2b_256,
	BLAKE2b_384,
	BLAKE2b_512,
}

var MDString = getOptionString(mds[:], MDNames)

func getMD(md MD) (MDFunc, error) {
	switch md {
	case SHA3_224:
		return sha3.New224, nil
	case SHA3_256:
		return sha3.New256, nil
	case SHA3_384:
		return sha3.New384, nil
	case SHA3_512:
		return sha3.New512, nil
	case SHA_224:
		return sha256.New224, nil
	case SHA_256:
		return sha256.New, nil
	case SHA_384:
		return sha512.New384, nil
	case SHA_512:
		return sha512.New, nil
	case SHA_512_224:
		return sha512.New512_224, nil
	case SHA_512_256:
		return sha512.New512_256, nil
	case BLAKE2b_256:
		return func() hash.Hash {
			h, _ := blake2b.New256(nil)
			return h
		}, nil
	case BLAKE2b_384:
		return func() hash.Hash {
			h, _ := blake2b.New384(nil)
			return h
		}, nil
	case BLAKE2b_512:
		return func() hash.Hash {
			h, _ := blake2b.New512(nil)
			return h
		}, nil
	}
	return nil, ErrMD
}
