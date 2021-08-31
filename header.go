package geheim

import (
	"encoding/binary"
	"io"
)

var headerByteOrder binary.ByteOrder = binary.BigEndian

const (
	pad uint32 = 0x47484DFF
	ver uint32 = 0x00000001
)

type header struct {
	Pad      uint32
	Ver      uint32
	Mode, Md uint16
	KeyIter  uint32
	Salt     [sizeSalt]byte
	IV       [sizeIV]byte
}

func (p *header) verify() error {
	if !(p.Pad == pad && p.Ver == ver) {
		return errMalHead
	}
	return nil
}

func (p *header) read(r io.Reader) (err error) {
	err = binary.Read(r, headerByteOrder, p)
	if err != nil {
		return
	}
	err = p.verify()
	return
}

func (p *header) write(w io.Writer) error {
	err := p.verify()
	if err != nil {
		return err
	}
	return binary.Write(w, headerByteOrder, p)
}

func newHeader(mode, md uint16, keyIter uint32, salt []byte, iv []byte) *header {
	h := &header{Pad: pad, Ver: ver, Mode: mode, Md: md, KeyIter: keyIter}
	copy(h.Salt[:], salt)
	copy(h.IV[:], iv)
	return h
}
