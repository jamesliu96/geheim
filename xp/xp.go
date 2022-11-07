package xp

import (
	"crypto/rand"

	"golang.org/x/crypto/curve25519"
)

func P() (private, public []byte, err error) {
	private = make([]byte, curve25519.ScalarSize)
	if _, err = rand.Read(private); err != nil {
		return
	}
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64
	public, err = X(private, nil)
	return
}

func X(scalar, point []byte) (product []byte, err error) {
	if point == nil {
		point = curve25519.Basepoint
	}
	return curve25519.X25519(scalar, point)
}
