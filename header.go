package geheim

import (
	"fmt"
	"io"
)

type Header interface {
	Read(io.Reader) error
	Write(io.Writer) error
	Get() (cipher Cipher, mode Mode, kdf KDF, mac MAC, md MD, sec int, salt, nonce []byte)
	Set(cipher Cipher, mode Mode, kdf KDF, mac MAC, md MD, sec int, salt, nonce []byte)
}

const Magic = 1195920895

const (
	_ = 1 + iota
	_
	_
	_
	_
	_
	v7
)

const Version = v7

type Meta struct {
	Magic   uint32
	Version uint32
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
	case v7:
		return new(headerV7), nil
	}
	return nil, fmt.Errorf("geheim: unsupported version %d", m.Version)
}

func (m *Meta) check() error {
	if m.Magic != Magic {
		return ErrHeader
	}
	return nil
}

type headerV7 struct {
	Cipher, Mode, KDF, MAC       uint8
	MD, Sec, SaltSize, NonceSize uint8
	Salt                         [32]byte
	Nonce                        [16]byte
}

func (v *headerV7) Read(r io.Reader) error { return readBE(r, v) }

func (v *headerV7) Write(w io.Writer) error { return writeBE(w, v) }

func (v *headerV7) Get() (cipher Cipher, mode Mode, kdf KDF, mac MAC, md MD, sec int, salt, nonce []byte) {
	cipher = Cipher(v.Cipher)
	mode = Mode(v.Mode)
	kdf = KDF(v.KDF)
	mac = MAC(v.MAC)
	md = MD(v.MD)
	sec = int(v.Sec)
	salt = v.Salt[:min(int(v.SaltSize), len(v.Salt))]
	nonce = v.Nonce[:min(int(v.NonceSize), len(v.Nonce))]
	return
}

func (v *headerV7) Set(cipher Cipher, mode Mode, kdf KDF, mac MAC, md MD, sec int, salt, nonce []byte) {
	v.Cipher = uint8(cipher)
	v.Mode = uint8(mode)
	v.KDF = uint8(kdf)
	v.MAC = uint8(mac)
	v.MD = uint8(md)
	v.Sec = uint8(sec)
	v.SaltSize = uint8(copy(v.Salt[:], salt))
	v.NonceSize = uint8(copy(v.Nonce[:], nonce))
}
