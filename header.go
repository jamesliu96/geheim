package geheim

import (
	"encoding/binary"
	"io"
)

type header interface {
	Version() int
	Read(io.Reader) error
	Write(io.Writer) error
	Set(Cipher, Mode, KDF, MD, MAC, int, []byte, []byte)
	Get() (Cipher, Mode, KDF, MD, MAC, int, []byte, []byte)
}

const padding uint32 = 0x47484dff

const (
	headerVer1 uint32 = 1 + iota
	headerVer2
	headerVer3
)

const version = headerVer3

var headerByteOrder binary.ByteOrder = binary.BigEndian

func readHeader(r io.Reader, v interface{}) error {
	return binary.Read(r, headerByteOrder, v)
}

func writeHeader(w io.Writer, v interface{}) error {
	return binary.Write(w, headerByteOrder, v)
}

func getHeader(ver uint32) (header, error) {
	switch ver {
	case headerVer3:
		return &headerV3{}, nil
	}
	return nil, errMalHead
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
		return errMalHead
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

type headerV3 struct {
	Cipher, Mode, KDF, MD, MAC, Sec, _, _ uint8
	Salt                                  [16]byte
	IV                                    [16]byte
}

func (v *headerV3) Version() int {
	return int(headerVer3)
}

func (v *headerV3) Read(r io.Reader) error {
	return readHeader(r, v)
}

func (v *headerV3) Write(w io.Writer) error {
	return writeHeader(w, v)
}

func (v *headerV3) Set(cipher Cipher, mode Mode, kdf KDF, md MD, mac MAC, sec int, salt []byte, iv []byte) {
	v.Cipher = uint8(cipher)
	v.Mode = uint8(mode)
	v.KDF = uint8(kdf)
	v.MD = uint8(md)
	v.MAC = uint8(mac)
	v.Sec = uint8(sec)
	copy(v.Salt[:], salt)
	copy(v.IV[:ivSizes[cipher]], iv)
}

func (v *headerV3) Get() (cipher Cipher, mode Mode, kdf KDF, md MD, mac MAC, sec int, salt []byte, iv []byte) {
	cipher = Cipher(v.Cipher)
	mode = Mode(v.Mode)
	kdf = KDF(v.KDF)
	md = MD(v.MD)
	mac = MAC(v.MAC)
	sec = int(v.Sec)
	salt = v.Salt[:]
	iv = v.IV[:ivSizes[cipher]]
	return
}
