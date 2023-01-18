package geheim

import (
	"io"
)

type Header interface {
	Read(io.Reader) error
	Write(io.Writer) error
	Get() (cipher Cipher, mode Mode, kdf KDF, mac MAC, md MD, sec int, salt, iv []byte)
	Set(cipher Cipher, mode Mode, kdf KDF, mac MAC, md MD, sec int, salt, iv []byte)
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

type meta struct {
	Magic   uint32
	Version uint32
}

func newMeta() *meta {
	return &meta{Magic: Magic, Version: Version}
}

func (m *meta) Read(r io.Reader) error {
	if err := readBE(r, m); err != nil {
		return err
	}
	return m.check()
}

func (m *meta) Write(w io.Writer) error {
	if err := m.check(); err != nil {
		return err
	}
	return writeBE(w, m)
}

func (m *meta) Header() (Header, error) {
	switch m.Version {
	case v7:
		return &headerV7{}, nil
	}
	return nil, ErrMfmHdr
}

func (m *meta) check() error {
	if m.Magic != Magic {
		return ErrMfmHdr
	}
	return nil
}

type headerV7 struct {
	Cipher, Mode, KDF, MAC    uint8
	MD, Sec, SaltSize, IVSize uint8
	Salt                      [32]byte
	IV                        [16]byte
}

func (v *headerV7) Read(r io.Reader) error {
	return readBE(r, v)
}

func (v *headerV7) Write(w io.Writer) error {
	return writeBE(w, v)
}

func (v *headerV7) Get() (cipher Cipher, mode Mode, kdf KDF, mac MAC, md MD, sec int, salt, iv []byte) {
	cipher = Cipher(v.Cipher)
	mode = Mode(v.Mode)
	kdf = KDF(v.KDF)
	mac = MAC(v.MAC)
	md = MD(v.MD)
	sec = int(v.Sec)
	salt = v.Salt[:v.SaltSize]
	iv = v.IV[:v.IVSize]
	return
}

func (v *headerV7) Set(cipher Cipher, mode Mode, kdf KDF, mac MAC, md MD, sec int, salt, iv []byte) {
	v.Cipher = uint8(cipher)
	v.Mode = uint8(mode)
	v.KDF = uint8(kdf)
	v.MAC = uint8(mac)
	v.MD = uint8(md)
	v.Sec = uint8(sec)
	v.SaltSize = uint8(copy(v.Salt[:], salt))
	v.IVSize = uint8(copy(v.IV[:], iv))
}
