package geheim

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
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

type Md uint16

const (
	Sha3224 Md = 1 + iota
	Sha3256
	Sha3384
	Sha3512
)

const (
	DMode    = ModeCTR
	DMd      = Sha3224
	DKeyIter = 100000
)

var pad = [4]byte{'G', 'H', 'M', 0xff}

const ver uint32 = 1

const (
	sizeSalt = 16
	sizeIV   = aes.BlockSize
	sizeKey  = 32
)

var headerByteOrder binary.ByteOrder = binary.BigEndian

type header struct {
	Pad      [len(pad)]byte
	Ver      uint32
	Mode, Md uint16
	KeyIter  uint32
	Salt     [sizeSalt]byte
	IV       [sizeIV]byte
}

func (p *header) verify() error {
	if !(p.Pad == pad && p.Ver == ver) {
		return errors.New("malformed header")
	}
	return nil
}

func (p *header) read(r io.Reader) error {
	err := binary.Read(r, headerByteOrder, p)
	if err != nil {
		return err
	}
	err = p.verify()
	if err != nil {
		return err
	}
	return ValidateConfigs(int(p.Mode), int(p.Md), int(p.KeyIter))
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

func ValidateConfigs(mode, md, keyIter int) (err error) {
	switch mode {
	case int(ModeCTR):
	case int(ModeCFB):
	case int(ModeOFB):
		break
	default:
		err = errors.New("invalid cipher mode")
	}
	switch md {
	case int(Sha3224):
	case int(Sha3256):
	case int(Sha3384):
	case int(Sha3512):
		break
	default:
		err = errors.New("invalid key message digest")
	}
	if keyIter < DKeyIter {
		err = fmt.Errorf("key iteration too few (minimum %d)", DKeyIter)
	}
	return
}

func checkArgs(in io.Reader, out io.Writer, pass []byte) error {
	if in == nil {
		return errors.New("in is not nilable")
	}
	if out == nil {
		return errors.New("out is not nilable")
	}
	if pass == nil {
		return errors.New("pass is not nilable")
	}
	return nil
}

func getCipherStreamMode(mode Mode, decrypt bool) (func(cipher.Block, []byte) cipher.Stream, Mode) {
	switch mode {
	case ModeCTR:
		return cipher.NewCTR, ModeCTR
	case ModeCFB:
		if decrypt {
			return cipher.NewCFBDecrypter, ModeCFB
		} else {
			return cipher.NewCFBEncrypter, ModeCFB
		}
	case ModeOFB:
		return cipher.NewOFB, ModeOFB
	}
	return getCipherStreamMode(DMode, decrypt)
}

func getMd(md Md) (func() hash.Hash, Md) {
	switch md {
	case Sha3224:
		return sha3.New224, Sha3224
	case Sha3256:
		return sha3.New256, Sha3256
	case Sha3384:
		return sha3.New384, Sha3384
	case Sha3512:
		return sha3.New512, Sha3512
	}
	return getMd(DMd)
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

type PrintFunc func(Mode, Md, int, []byte, []byte, []byte)

func Encrypt(in io.Reader, out io.Writer, pass []byte, mode Mode, md Md, keyIter int, printFn PrintFunc) (sign []byte, err error) {
	err = checkArgs(in, out, pass)
	if err != nil {
		return
	}
	r := bufio.NewReader(in)
	w := bufio.NewWriter(out)
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
	sm, mode := getCipherStreamMode(mode, false)
	mdfn, md := getMd(md)
	dk := deriveKey(pass, salt, keyIter, mdfn)
	if printFn != nil {
		printFn(mode, md, keyIter, salt, iv, dk)
	}
	err = newHeader(uint16(mode), uint16(md), uint32(keyIter), salt, iv).write(w)
	if err != nil {
		return
	}
	block, err := newCipherBlock(dk)
	if err != nil {
		return
	}
	s := sm(block, iv)
	sw := newCipherStreamWriter(s, w)
	h := hmac.New(mdfn, dk)
	_, err = io.Copy(io.MultiWriter(sw, h), r)
	if err != nil {
		return
	}
	sign = h.Sum(nil)
	return
}

func Decrypt(in io.Reader, out io.Writer, pass []byte, printFn PrintFunc) (sign []byte, err error) {
	err = checkArgs(in, out, pass)
	if err != nil {
		return
	}
	r := bufio.NewReader(in)
	w := bufio.NewWriter(out)
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
	md := Md(header.Md)
	keyIter := int(header.KeyIter)
	salt := header.Salt[:]
	iv := header.IV[:]
	sm, mode := getCipherStreamMode(mode, true)
	mdfn, md := getMd(md)
	dk := deriveKey(pass, salt, keyIter, mdfn)
	if printFn != nil {
		printFn(mode, md, keyIter, salt, iv, dk)
	}
	block, err := newCipherBlock(dk)
	if err != nil {
		return
	}
	s := sm(block, iv)
	sr := newCipherStreamReader(s, r)
	h := hmac.New(mdfn, dk)
	_, err = io.Copy(io.MultiWriter(w, h), sr)
	if err != nil {
		return
	}
	sign = h.Sum(nil)
	return
}

var VerifySign = hmac.Equal

type Encrypter struct {
	In      io.Reader
	Out     io.Writer
	Pass    []byte
	Mode    Mode
	Md      Md
	KeyIter int
	PrintFn PrintFunc
}

func (p *Encrypter) Encrypt() ([]byte, error) {
	return Encrypt(p.In, p.Out, p.Pass, p.Mode, p.Md, p.KeyIter, p.PrintFn)
}

func NewEncrypter(in io.Reader, out io.Writer, pass []byte, mode Mode, md Md, keyIter int, printFn PrintFunc) *Encrypter {
	return &Encrypter{in, out, pass, mode, md, keyIter, printFn}
}

type Decrypter struct {
	In      io.Reader
	Out     io.Writer
	Pass    []byte
	PrintFn PrintFunc
}

func (p *Decrypter) Decrypt() ([]byte, error) {
	return Decrypt(p.In, p.Out, p.Pass, p.PrintFn)
}

func NewDecrypter(in io.Reader, out io.Writer, pass []byte, printFn PrintFunc) *Decrypter {
	return &Decrypter{in, out, pass, printFn}
}
