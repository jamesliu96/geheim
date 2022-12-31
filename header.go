package geheim

import (
	"errors"
	"fmt"
	"io"
	"math"
)

type Header interface {
	Version() int
	Read(io.Reader) error
	Write(io.Writer) error
	Get() (Cipher, Mode, KDF, MAC, MD, int, []byte, []byte)
	Set(Cipher, Mode, KDF, MAC, MD, int, []byte, []byte)
}

const padding uint32 = 0x47484dff

const (
	headerVer1 uint32 = 1 + iota
	headerVer2
	headerVer3
	headerVer4
	headerVer5
	headerVer6
	headerVer7
)

const HeaderVersion = headerVer7

func getHeader(ver uint32) (Header, error) {
	switch ver {
	case headerVer7:
		return &headerV7{}, nil
	}
	return nil, fmt.Errorf("unsupported header version: %d", ver)
}

type Meta struct {
	Padding uint32
	Version uint32
}

func (m *Meta) Read(r io.Reader) error {
	if err := readBE(r, m); err != nil {
		return err
	}
	return m.checkPadding()
}

func (m *Meta) Write(w io.Writer) error {
	if err := m.checkPadding(); err != nil {
		return err
	}
	return writeBE(w, m)
}

func (m *Meta) Header() (Header, error) {
	return getHeader(m.Version)
}

func (m *Meta) checkPadding() error {
	if m.Padding != padding {
		return errors.New("malformed header")
	}
	return nil
}

func NewMeta(version uint32) *Meta {
	return &Meta{padding, version}
}

type headerV7 struct {
	Cipher, Mode, KDF, MAC    uint8
	MD, Sec, SaltSize, IVSize uint8
	Salt                      [32]byte
	IV                        [16]byte
}

func (v *headerV7) Version() int {
	return int(headerVer7)
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
	salt = v.Salt[:int(math.Min(float64(v.SaltSize), float64(len(v.Salt))))]
	iv = v.IV[:int(math.Min(float64(v.IVSize), float64(len(v.IV))))]
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
