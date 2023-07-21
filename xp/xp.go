package xp

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

const Size = curve25519.PointSize

var Base = curve25519.Basepoint

func P() (private, public []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%+v", r)
		}
	}()
	private = make([]byte, Size)
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
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%+v", r)
		}
	}()
	if point == nil {
		point = Base
	}
	return curve25519.X25519(scalar, point)
}
