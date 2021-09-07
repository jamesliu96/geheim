package geheim

import (
	"encoding/binary"
	"io"
)

type header interface {
	Read(io.Reader) error
	Write(io.Writer) error
	Set(Cipher, KDF, Mode, Md, int, []byte, []byte)
	Get() (Cipher, KDF, Mode, Md, int, []byte, []byte)
}

var headerByteOrder binary.ByteOrder = binary.BigEndian

const padding uint32 = 0x47484dff

const (
	headerVer1 uint32 = 1 + iota
	headerVer2
)

const version = headerVer2

func readHeader(r io.Reader, v interface{}) error {
	return binary.Read(r, headerByteOrder, v)
}

func writeHeader(w io.Writer, v interface{}) error {
	return binary.Write(w, headerByteOrder, v)
}

func getHeader(ver uint32) (header, error) {
	switch ver {
	case headerVer1:
		return &headerV1{}, nil
	case headerVer2:
		return &headerV2{}, nil
	}
	return nil, errMalHead
}

type meta struct {
	Pad uint32
	Ver uint32
}

func (m *meta) Read(r io.Reader) error {
	err := readHeader(r, m)
	if err != nil {
		return err
	}
	if m.Pad != padding {
		return errMalHead
	}
	return nil
}

func (m *meta) Write(w io.Writer) error {
	if m.Pad != padding || m.Ver != version {
		return errMalHead
	}
	return writeHeader(w, m)
}

func (m *meta) GetHeader() (header, error) {
	return getHeader(m.Ver)
}

func newMeta() *meta {
	return &meta{Pad: padding, Ver: version}
}

type headerV1 struct {
	Mode, Md uint16
	KeyIter  uint32
	Salt     [sizeSalt]byte
	IV       [sizeIV]byte
}

func (v *headerV1) Read(r io.Reader) error {
	return readHeader(r, v)
}

func (v *headerV1) Write(w io.Writer) error {
	return writeHeader(w, v)
}

func (v *headerV1) Set(_ Cipher, _ KDF, mode Mode, md Md, keyIter int, salt []byte, iv []byte) {
	v.Mode = uint16(mode)
	v.Md = uint16(md)
	v.KeyIter = uint32(keyIter)
	copy(v.Salt[:], salt)
	copy(v.IV[:], iv)
}

func (v *headerV1) Get() (cipher Cipher, kdf KDF, mode Mode, md Md, keyIter int, salt []byte, iv []byte) {
	cipher = DefaultCipher
	kdf = DefaultKDF
	mode = Mode(v.Mode)
	md = Md(v.Md)
	keyIter = int(v.KeyIter)
	salt = v.Salt[:]
	iv = v.IV[:]
	return
}

type headerV2 struct {
	Cipher, KDF, Mode, Md uint8
	KeyIter               uint32
	Salt                  [sizeSalt]byte
	IV                    [sizeIV]byte
}

func (v *headerV2) Read(r io.Reader) error {
	return readHeader(r, v)
}

func (v *headerV2) Write(w io.Writer) error {
	return writeHeader(w, v)
}

func (v *headerV2) Set(cipher Cipher, kdf KDF, mode Mode, md Md, keyIter int, salt []byte, iv []byte) {
	v.Cipher = uint8(cipher)
	v.KDF = uint8(kdf)
	v.Mode = uint8(mode)
	v.Md = uint8(md)
	v.KeyIter = uint32(keyIter)
	copy(v.Salt[:], salt)
	copy(v.IV[:], iv)
}

func (v *headerV2) Get() (cipher Cipher, kdf KDF, mode Mode, md Md, keyIter int, salt []byte, iv []byte) {
	cipher = Cipher(v.Cipher)
	kdf = KDF(v.KDF)
	mode = Mode(v.Mode)
	md = Md(v.Md)
	keyIter = int(v.KeyIter)
	salt = v.Salt[:]
	iv = v.IV[:]
	return
}
