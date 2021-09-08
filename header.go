package geheim

import (
	"encoding/binary"
	"io"
)

type header interface {
	Version() int
	Read(io.Reader) error
	Write(io.Writer) error
	Set(Cipher, KDF, Mode, MD, MAC, int, []byte, []byte)
	Get() (Cipher, KDF, Mode, MD, MAC, int, []byte, []byte)
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
	case headerVer1:
		return &headerV1{}, nil
	case headerVer2:
		return &headerV2{}, nil
	case headerVer3:
		return &headerV3{}, nil
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
	Mode, MD uint16
	Sec      uint32
	Salt     [16]byte
	IV       [16]byte
}

func (v *headerV1) Version() int {
	return int(headerVer1)
}

func (v *headerV1) Read(r io.Reader) error {
	return readHeader(r, v)
}

func (v *headerV1) Write(w io.Writer) error {
	return writeHeader(w, v)
}

func (v *headerV1) Set(_ Cipher, _ KDF, mode Mode, md MD, _ MAC, sec int, salt []byte, iv []byte) {
	v.Mode = uint16(mode)
	v.MD = uint16(md)
	v.Sec = uint32(sec)
	copy(v.Salt[:], salt)
	copy(v.IV[:], iv)
}

func (v *headerV1) Get() (cipher Cipher, kdf KDF, mode Mode, md MD, mac MAC, sec int, salt []byte, iv []byte) {
	cipher = AES
	kdf = PBKDF2
	mode = Mode(v.Mode)
	md = MD(v.MD)
	mac = HMAC
	sec = int(v.Sec)
	salt = v.Salt[:]
	iv = v.IV[:]
	return
}

type headerV2 struct {
	Cipher, KDF, Mode, MD uint8
	Sec                   uint32
	Salt                  [16]byte
	IV                    [16]byte
}

func (v *headerV2) Version() int {
	return int(headerVer2)
}

func (v *headerV2) Read(r io.Reader) error {
	return readHeader(r, v)
}

func (v *headerV2) Write(w io.Writer) error {
	return writeHeader(w, v)
}

func (v *headerV2) Set(cipher Cipher, kdf KDF, mode Mode, md MD, _ MAC, sec int, salt []byte, iv []byte) {
	v.Cipher = uint8(cipher)
	v.KDF = uint8(kdf)
	v.Mode = uint8(mode)
	v.MD = uint8(md)
	v.Sec = uint32(sec)
	copy(v.Salt[:], salt)
	copy(v.IV[:ivSizes[cipher]], iv)
}

func (v *headerV2) Get() (cipher Cipher, kdf KDF, mode Mode, md MD, mac MAC, sec int, salt []byte, iv []byte) {
	cipher = Cipher(v.Cipher)
	kdf = KDF(v.KDF)
	mode = Mode(v.Mode)
	md = MD(v.MD)
	mac = HMAC
	sec = int(v.Sec)
	salt = v.Salt[:]
	iv = v.IV[:ivSizes[cipher]]
	return
}

type headerV3 struct {
	Cipher, KDF uint8
	Mode, MD    uint8
	MAC, Sec    uint8
	_           [2]byte
	Salt        [16]byte
	IV          [16]byte
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

func (v *headerV3) Set(cipher Cipher, kdf KDF, mode Mode, md MD, mac MAC, sec int, salt []byte, iv []byte) {
	v.Cipher = uint8(cipher)
	v.KDF = uint8(kdf)
	v.Mode = uint8(mode)
	v.MD = uint8(md)
	v.MAC = uint8(mac)
	v.Sec = uint8(sec)
	copy(v.Salt[:], salt)
	copy(v.IV[:ivSizes[cipher]], iv)
}

func (v *headerV3) Get() (cipher Cipher, kdf KDF, mode Mode, md MD, mac MAC, sec int, salt []byte, iv []byte) {
	cipher = Cipher(v.Cipher)
	kdf = KDF(v.KDF)
	mode = Mode(v.Mode)
	md = MD(v.MD)
	mac = MAC(v.MAC)
	sec = int(v.Sec)
	salt = v.Salt[:]
	iv = v.IV[:ivSizes[cipher]]
	return
}
