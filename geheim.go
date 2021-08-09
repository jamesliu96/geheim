package geheim

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"hash"
	"io"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
)

type Mode uint16

const (
	ModeCTR Mode = 1 + iota
	ModeCFB
	ModeOFB
)

type KeyMd uint16

const (
	Sha3224 KeyMd = 1 + iota
	Sha3256
	Sha3384
	Sha3512
)

const (
	DMode    = ModeCTR
	DKeyMd   = Sha3224
	DKeyIter = 100000
)

var pad = [4]byte{'G', 'H', 'M', '_'}

const ver uint32 = 1

const (
	sizeSalt = 16
	sizeIV   = aes.BlockSize
	sizeKey  = 32
)

var headerByteOrder binary.ByteOrder = binary.BigEndian

type header struct {
	Pad         [4]byte
	Ver         uint32
	Mode, KeyMd uint16
	KeyIter     uint32
	Salt        [sizeSalt]byte
	IV          [sizeIV]byte
}

func (p *header) verify() error {
	if !(p.Pad == pad && p.Ver == ver) {
		return errors.New("malformed header")
	}
	err := Validate(int(p.Mode), int(p.KeyMd), int(p.KeyIter))
	if err != nil {
		return err
	}
	return nil
}

func (p *header) read(r io.Reader) error {
	err := binary.Read(r, headerByteOrder, p)
	if err != nil {
		return err
	}
	return p.verify()
}

func (p *header) write(w io.Writer) error {
	err := p.verify()
	if err != nil {
		return err
	}
	return binary.Write(w, headerByteOrder, p)
}

func newHeader(mode, keyMd uint16, keyIter uint32, salt []byte, iv []byte) *header {
	h := &header{Pad: pad, Ver: ver, Mode: mode, KeyMd: keyMd, KeyIter: keyIter}
	copy(h.Salt[:], salt)
	copy(h.IV[:], iv)
	return h
}

type PrintFunc func(Mode, KeyMd, int, []byte, []byte, []byte)

func Validate(mode, keyMd, keyIter int) (err error) {
	switch mode {
	case int(ModeCTR):
	case int(ModeCFB):
	case int(ModeOFB):
		break
	default:
		err = errors.New("invalid cipher mode")
	}
	switch keyMd {
	case int(Sha3224):
	case int(Sha3256):
	case int(Sha3384):
	case int(Sha3512):
		break
	default:
		err = errors.New("invalid key message digest")
	}
	if keyIter < DKeyIter {
		err = errors.New("invalid key iteration")
	}
	return
}

func getCipherStreamMode(mode Mode, decrypt bool) func(cipher.Block, []byte) cipher.Stream {
	switch mode {
	case ModeCTR:
		return cipher.NewCTR
	case ModeCFB:
		if decrypt {
			return cipher.NewCFBDecrypter
		} else {
			return cipher.NewCFBEncrypter
		}
	case ModeOFB:
		return cipher.NewOFB
	}
	return getCipherStreamMode(DMode, decrypt)
}

func getKeyMd(keyMd KeyMd) func() hash.Hash {
	switch keyMd {
	case Sha3224:
		return sha3.New224
	case Sha3256:
		return sha3.New256
	case Sha3384:
		return sha3.New384
	case Sha3512:
		return sha3.New512
	}
	return getKeyMd(DKeyMd)
}

func newCipherBlock(key []byte) (cipher.Block, error) {
	return aes.NewCipher(key)
}

func newCipherStreamReader(stream cipher.Stream, r io.Reader) io.Reader {
	return &cipher.StreamReader{S: stream, R: r}
}

func newCipherStreamWriter(stream cipher.Stream, w io.Writer) io.Writer {
	return &cipher.StreamWriter{S: stream, W: w}
}

func deriveKey(pass, salt []byte, iter int, md func() hash.Hash) []byte {
	return pbkdf2.Key(pass, salt, iter, sizeKey, md)
}

func readBuf(r io.Reader, buf []byte) (err error) {
	_, err = r.Read(buf)
	return
}

func readRand(buf []byte) error {
	return readBuf(rand.Reader, buf)
}

func Enc(input io.Reader, output io.Writer, pass []byte, mode Mode, keyMd KeyMd, keyIter int, printFn PrintFunc) (err error) {
	r := bufio.NewReader(input)
	w := bufio.NewWriter(output)
	defer (func() {
		if err == nil {
			err = w.Flush()
		}
	})()
	salt := make([]byte, sizeSalt)
	err = readRand(salt)
	if err != nil {
		return
	}
	iv := make([]byte, sizeIV)
	err = readRand(iv)
	if err != nil {
		return
	}
	dk := deriveKey(pass, salt, keyIter, getKeyMd(keyMd))
	if printFn != nil {
		printFn(mode, keyMd, keyIter, salt, iv, dk)
	}
	err = newHeader(uint16(mode), uint16(keyMd), uint32(keyIter), salt, iv).write(w)
	if err != nil {
		return
	}
	block, err := newCipherBlock(dk)
	if err != nil {
		return
	}
	stream := getCipherStreamMode(mode, false)(block, iv)
	streamWriter := newCipherStreamWriter(stream, w)
	_, err = io.Copy(streamWriter, r)
	return
}

func Dec(input io.Reader, output io.Writer, pass []byte, printFn PrintFunc) (err error) {
	r := bufio.NewReader(input)
	w := bufio.NewWriter(output)
	defer (func() {
		if err == nil {
			err = w.Flush()
		}
	})()
	header := &header{}
	err = header.read(r)
	if err != nil {
		return
	}
	mode := Mode(header.Mode)
	keyMd := KeyMd(header.KeyMd)
	keyIter := int(header.KeyIter)
	salt := header.Salt[:]
	iv := header.IV[:]
	dk := deriveKey(pass, salt, keyIter, getKeyMd(keyMd))
	if printFn != nil {
		printFn(mode, keyMd, keyIter, salt, iv, dk)
	}
	block, err := newCipherBlock(dk)
	if err != nil {
		return
	}
	stream := getCipherStreamMode(mode, true)(block, iv)
	streamReader := newCipherStreamReader(stream, r)
	_, err = io.Copy(w, streamReader)
	return
}

type Encrypter struct {
	Input   io.Reader
	Output  io.Writer
	Pass    []byte
	Mode    Mode
	KeyMd   KeyMd
	KeyIter int
	PrintFn PrintFunc
}

func (p *Encrypter) Enc() error {
	return Enc(p.Input, p.Output, p.Pass, p.Mode, p.KeyMd, p.KeyIter, p.PrintFn)
}

func NewEncrypter(input io.Reader, output io.Writer, pass []byte, mode Mode, keyMd KeyMd, keyIter int, printFn PrintFunc) *Encrypter {
	return &Encrypter{input, output, pass, mode, keyMd, keyIter, printFn}
}

type Decrypter struct {
	Input   io.Reader
	Output  io.Writer
	Pass    []byte
	PrintFn PrintFunc
}

func (p *Decrypter) Dec() error {
	return Dec(p.Input, p.Output, p.Pass, p.PrintFn)
}

func NewDecrypter(input io.Reader, output io.Writer, pass []byte, printFn PrintFunc) *Decrypter {
	return &Decrypter{input, output, pass, printFn}
}
