package geheim

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

type Header interface {
	Version() int
	Read(io.Reader) error
	Write(io.Writer) error
	Set(cipher Cipher, mode Mode, kdf KDF, mac MAC, md MD, sec int, salt, iv []byte)
	Get() (cipher Cipher, mode Mode, kdf KDF, mac MAC, md MD, sec int, salt, iv []byte)
}

const padding uint32 = 0x47484dff

const (
	headerVer1 uint32 = 1 + iota
	headerVer2
	headerVer3
	headerVer4
	headerVer5
	headerVer6
)

const HeaderVersion = headerVer6

func readHeader(r io.Reader, v any) error {
	return binary.Read(r, binary.BigEndian, v)
}

func writeHeader(w io.Writer, v any) error {
	return binary.Write(w, binary.BigEndian, v)
}

func getHeader(ver uint32) (Header, error) {
	switch ver {
	case headerVer5:
		return &headerV5{}, nil
	case headerVer6:
		return &headerV6{}, nil
	}
	return nil, fmt.Errorf("unsupported header version: %d", ver)
}

type Meta struct {
	Padding uint32
	Version uint32
}

func (m *Meta) Read(r io.Reader) error {
	err := readHeader(r, m)
	if err != nil {
		return err
	}
	if m.Padding != padding {
		return errors.New("malformed header")
	}
	return nil
}

func (m *Meta) Write(w io.Writer) error {
	return writeHeader(w, m)
}

func (m *Meta) Header() (Header, error) {
	return getHeader(m.Version)
}

func NewMeta(ver uint32) *Meta {
	return &Meta{padding, ver}
}

type headerV5 struct {
	Cipher, Mode, KDF, MAC    uint8
	MD, Sec, SaltSize, IVSize uint8
	Salt                      [16]byte
	IV                        [16]byte
}

func (v *headerV5) Version() int {
	return int(headerVer5)
}

func (v *headerV5) Read(r io.Reader) error {
	return readHeader(r, v)
}

func (v *headerV5) Write(w io.Writer) error {
	return writeHeader(w, v)
}

func (v *headerV5) Set(cipher Cipher, mode Mode, kdf KDF, mac MAC, md MD, sec int, salt []byte, iv []byte) {
	v.Cipher = uint8(cipher)
	v.Mode = uint8(mode)
	v.KDF = uint8(kdf)
	v.MAC = uint8(mac)
	v.MD = uint8(md)
	v.Sec = uint8(sec)
	v.SaltSize = uint8(copy(v.Salt[:], salt))
	v.IVSize = uint8(copy(v.IV[:], iv))
}

func (v *headerV5) Get() (cipher Cipher, mode Mode, kdf KDF, mac MAC, md MD, sec int, salt []byte, iv []byte) {
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

type headerV6 struct {
	Cipher, Mode, KDF, MAC    uint8
	MD, Sec, SaltSize, IVSize uint8
	Salt                      [32]byte
	IV                        [16]byte
}

func (v *headerV6) Version() int {
	return int(headerVer6)
}

func (v *headerV6) Read(r io.Reader) error {
	return readHeader(r, v)
}

func (v *headerV6) Write(w io.Writer) error {
	return writeHeader(w, v)
}

func (v *headerV6) Set(cipher Cipher, mode Mode, kdf KDF, mac MAC, md MD, sec int, salt []byte, iv []byte) {
	v.Cipher = uint8(cipher)
	v.Mode = uint8(mode)
	v.KDF = uint8(kdf)
	v.MAC = uint8(mac)
	v.MD = uint8(md)
	v.Sec = uint8(sec)
	v.SaltSize = uint8(copy(v.Salt[:], salt))
	v.IVSize = uint8(copy(v.IV[:], iv))
}

func (v *headerV6) Get() (cipher Cipher, mode Mode, kdf KDF, mac MAC, md MD, sec int, salt []byte, iv []byte) {
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
