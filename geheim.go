package geheim

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
)

type Mode uint16

const (
	ModeCTR Mode = 1 + iota
	ModeCFB
	ModeOFB
)

var ModeNames = map[Mode]string{
	ModeCTR: "CTR",
	ModeCFB: "CFB",
	ModeOFB: "OFB",
}

var modes = [...]Mode{ModeCTR, ModeCFB, ModeOFB}

func GetModeString() string {
	d := []string{}
	for _, mode := range modes {
		d = append(d, fmt.Sprintf("%d:%s", mode, ModeNames[mode]))
	}
	return strings.Join(d, ", ")
}

type Md uint16

const (
	SHA3_224 Md = 1 + iota
	SHA3_256
	SHA3_384
	SHA3_512
	SHA_224
	SHA_256
	SHA_384
	SHA_512
	SHA_512_224
	SHA_512_256
)

var MdNames = map[Md]string{
	SHA3_224:    "SHA3-224",
	SHA3_256:    "SHA3-256",
	SHA3_384:    "SHA3-384",
	SHA3_512:    "SHA3-512",
	SHA_224:     "SHA-224",
	SHA_256:     "SHA-256",
	SHA_384:     "SHA-384",
	SHA_512:     "SHA-512",
	SHA_512_224: "SHA-512-224",
	SHA_512_256: "SHA-512-256",
}

var mds = [...]Md{SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHA_224, SHA_256, SHA_384, SHA_512, SHA_512_224, SHA_512_256}

func GetMdString() string {
	d := []string{}
	for _, md := range mds {
		d = append(d, fmt.Sprintf("%d:%s", md, MdNames[md]))
	}
	return strings.Join(d, ", ")
}

const (
	DMode    = ModeCTR
	DMd      = SHA_256
	DKeyIter = 100000
)

const (
	pad uint32 = 0x47484DFF
	ver uint32 = 0x00000001
)

const (
	sizeSalt = 16
	sizeIV   = aes.BlockSize
	sizeKey  = 32
)

var headerByteOrder binary.ByteOrder = binary.BigEndian

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
		return errors.New("malformed header")
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

func ValidateConfigs(mode Mode, md Md, keyIter int) (err error) {
	switch mode {
	case ModeCTR:
	case ModeCFB:
	case ModeOFB:
		break
	default:
		err = fmt.Errorf("invalid cipher block mode (%s)", GetModeString())
	}
	switch md {
	case SHA3_224:
	case SHA3_256:
	case SHA3_384:
	case SHA3_512:
	case SHA_224:
	case SHA_256:
	case SHA_384:
	case SHA_512:
	case SHA_512_224:
	case SHA_512_256:
		break
	default:
		err = fmt.Errorf("invalid message digest (%s)", GetMdString())
	}
	if keyIter < DKeyIter {
		err = fmt.Errorf("invalid key iteration (minimum %d)", DKeyIter)
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
	case SHA3_224:
		return sha3.New224, SHA3_224
	case SHA3_256:
		return sha3.New256, SHA3_256
	case SHA3_384:
		return sha3.New384, SHA3_384
	case SHA3_512:
		return sha3.New512, SHA3_512
	case SHA_224:
		return sha256.New224, SHA_224
	case SHA_256:
		return sha256.New, SHA_256
	case SHA_384:
		return sha512.New384, SHA_384
	case SHA_512:
		return sha512.New, SHA_512
	case SHA_512_224:
		return sha512.New512_224, SHA_512_224
	case SHA_512_256:
		return sha512.New512_256, SHA_512_256
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

func readRand(buf []byte) (err error) {
	_, err = rand.Reader.Read(buf)
	return
}

type PrintFunc func(Mode, Md, int, []byte, []byte, []byte)

func Encrypt(in io.Reader, out io.Writer, pass []byte, mode Mode, md Md, keyIter int, printFn PrintFunc) (sign []byte, err error) {
	err = checkArgs(in, out, pass)
	if err != nil {
		return
	}
	err = ValidateConfigs(mode, md, keyIter)
	if err != nil {
		return
	}
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
	r := bufio.NewReader(in)
	w := bufio.NewWriter(out)
	defer (func() {
		if err == nil {
			err = w.Flush()
		}
	})()
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
	header := &header{}
	err = header.read(r)
	if err != nil {
		return
	}
	mode := Mode(header.Mode)
	md := Md(header.Md)
	keyIter := int(header.KeyIter)
	err = ValidateConfigs(mode, md, keyIter)
	if err != nil {
		return
	}
	salt := header.Salt[:]
	iv := header.IV[:]
	sm, mode := getCipherStreamMode(mode, true)
	mdfn, md := getMd(md)
	dk := deriveKey(pass, salt, keyIter, mdfn)
	if printFn != nil {
		printFn(mode, md, keyIter, salt, iv, dk)
	}
	w := bufio.NewWriter(out)
	defer (func() {
		if err == nil {
			err = w.Flush()
		}
	})()
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

func VerifySign(a, b []byte) bool {
	return hmac.Equal(a, b)
}

func DecryptVerify(in io.Reader, out io.Writer, pass []byte, printFn PrintFunc, vSign []byte) (sign []byte, err error) {
	sign, err = Decrypt(in, out, pass, printFn)
	if err != nil {
		return
	}
	if vSign != nil {
		if !VerifySign(vSign, sign) {
			err = errors.New("signature verification failed")
		}
	}
	return
}
