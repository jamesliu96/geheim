package geheim

import (
	"fmt"
	"io"
)

type Header interface {
	Read(io.Reader) error
	Write(io.Writer) error
	Get() (cipher Cipher, hash Hash, kdf KDF, sec int, salt, nonce []byte)
	Set(cipher Cipher, hash Hash, kdf KDF, sec int, salt, nonce []byte)
}

const Magic = 1195920895

const (
	_ = 1 + iota
	_
	_
	_
	_
	_
	_
	v8
)

const Version = v8

type Meta struct {
	Magic, Version uint32
}

func NewMeta() *Meta { return &Meta{Magic, Version} }

func (m *Meta) Read(r io.Reader) error {
	if err := readBE(r, m); err != nil {
		return err
	}
	return m.check()
}

func (m *Meta) Write(w io.Writer) error {
	if err := m.check(); err != nil {
		return err
	}
	return writeBE(w, m)
}

func (m *Meta) Header() (Header, error) {
	switch m.Version {
	case v8:
		return new(headerV8), nil
	}
	return nil, fmt.Errorf("geheim: unsupported version %d", m.Version)
}

func (m *Meta) check() error {
	if m.Magic != Magic {
		return ErrHeader
	}
	return nil
}

type headerV8 struct {
	Cipher, Hash, KDF, Sec, SaltSize, NonceSize, _, _ uint8
	Salt                                              [32]byte
	Nonce                                             [16]byte
}

func (v *headerV8) Read(r io.Reader) error { return readBE(r, v) }

func (v *headerV8) Write(w io.Writer) error { return writeBE(w, v) }

func (v *headerV8) Get() (cipher Cipher, hash Hash, kdf KDF, sec int, salt, nonce []byte) {
	cipher = Cipher(v.Cipher)
	hash = Hash(v.Hash)
	kdf = KDF(v.KDF)
	sec = int(v.Sec)
	salt = v.Salt[:min(int(v.SaltSize), len(v.Salt))]
	nonce = v.Nonce[:min(int(v.NonceSize), len(v.Nonce))]
	return
}

func (v *headerV8) Set(cipher Cipher, hash Hash, kdf KDF, sec int, salt, nonce []byte) {
	v.Cipher = uint8(cipher)
	v.Hash = uint8(hash)
	v.KDF = uint8(kdf)
	v.Sec = uint8(sec)
	v.SaltSize = uint8(copy(v.Salt[:], salt))
	v.NonceSize = uint8(copy(v.Nonce[:], nonce))
}
