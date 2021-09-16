package geheim

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

type header interface {
	Version() int
	Read(io.Reader) error
	Write(io.Writer) error
	Set(Cipher, Mode, KDF, MAC, MD, int, []byte, []byte)
	Get() (Cipher, Mode, KDF, MAC, MD, int, []byte, []byte)
}

const padding uint32 = 0x47484dff

const (
	headerVer1 uint32 = 1 + iota
	headerVer2
	headerVer3
	headerVer4
	headerVer5
)

const version = headerVer5

var headerByteOrder binary.ByteOrder = binary.BigEndian

func readHeader(r io.Reader, v interface{}) error {
	return binary.Read(r, headerByteOrder, v)
}

func writeHeader(w io.Writer, v interface{}) error {
	return binary.Write(w, headerByteOrder, v)
}

func getHeader(ver uint32) (header, error) {
	switch ver {
	case headerVer4:
		return &headerV4{}, nil
	case headerVer5:
		return &headerV5{}, nil
	}
	return nil, fmt.Errorf("unsupported header version: %d", ver)
}

type meta struct {
	Padding uint32
	Version uint32
}

func (m *meta) Read(r io.Reader) error {
	err := readHeader(r, m)
	if err != nil {
		return err
	}
	if m.Padding != padding {
		return errors.New("malformed header")
	}
	return nil
}

func (m *meta) Write(w io.Writer) error {
	return writeHeader(w, m)
}

func (m *meta) GetHeader() (header, error) {
	return getHeader(m.Version)
}

func newMeta() *meta {
	return &meta{Padding: padding, Version: version}
}

type headerV4 struct {
	Cipher, Mode, KDF, MD, MAC, Sec, SaltSize, IVSize uint8
	Salt                                              [16]byte
	IV                                                [16]byte
}

func (v *headerV4) Version() int {
	return int(headerVer4)
}

func (v *headerV4) Read(r io.Reader) error {
	return readHeader(r, v)
}

func (v *headerV4) Write(w io.Writer) error {
	return writeHeader(w, v)
}

func (v *headerV4) Set(cipher Cipher, mode Mode, kdf KDF, mac MAC, md MD, sec int, salt []byte, iv []byte) {
	v.Cipher = uint8(cipher)
	v.Mode = uint8(mode)
	v.KDF = uint8(kdf)
	v.MAC = uint8(mac)
	v.MD = uint8(md)
	v.Sec = uint8(sec)
	v.SaltSize = uint8(copy(v.Salt[:], salt))
	v.IVSize = uint8(copy(v.IV[:], iv))
}

func (v *headerV4) Get() (cipher Cipher, mode Mode, kdf KDF, mac MAC, md MD, sec int, salt []byte, iv []byte) {
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

type headerV5 struct {
	Cipher, Mode, KDF, MAC, MD, Sec, SaltSize, IVSize uint8
	Salt                                              [16]byte
	IV                                                [16]byte
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
	salt = v.Salt[:v.SaltSize]
	iv = v.IV[:v.IVSize]
	return
}
