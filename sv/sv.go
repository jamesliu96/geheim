package sv

import (
	"crypto/ed25519"
	"fmt"
)

const (
	PrivateSize   = ed25519.PrivateKeySize
	PublicSize    = ed25519.PublicKeySize
	SignatureSize = ed25519.SignatureSize
)

func G() (private, public []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%+v", r)
		}
	}()
	public, private, err = ed25519.GenerateKey(nil)
	return
}

func S(message, private []byte) (signature []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%+v", r)
		}
	}()
	signature = ed25519.Sign(private, message)
	return
}

func V(message, public, signature []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%+v", r)
		}
	}()
	err = ed25519.VerifyWithOptions(public, message, signature, &ed25519.Options{})
	return
}
