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

const (
	ModeCTR uint16 = 1 << iota
	ModeCFB
	ModeOFB
)

const (
	Sha3224 uint16 = 1 << iota
	Sha3256
	Sha3384
	Sha3512
)

const (
	DMode    = ModeCTR
	DKeyMd   = Sha3224
	DKeyIter = 100000
)

const ver = uint32(1)

var ghm_ = [4]byte{'G', 'H', 'M', '_'}

const (
	sizeSalt = 16
	sizeIV   = aes.BlockSize
	sizeKey  = 32
)

var headerByteOrder = binary.BigEndian

type header struct {
	GHM_    [4]byte
	Ver     uint32
	Mode    uint16
	KeyMd   uint16
	KeyIter uint32
	Salt    [sizeSalt]byte
	IV      [sizeIV]byte
}

func newHeader(mode uint16, keyMd uint16, keyIter uint32, salt []byte, iv []byte) *header {
	h := &header{GHM_: ghm_, Ver: ver, Mode: mode, KeyMd: keyMd, KeyIter: keyIter}
	copy(h.Salt[:], salt)
	copy(h.IV[:], iv)
	return h
}

func (p *header) verify() {
	if err := CheckConfig(int(p.Mode), int(p.KeyMd), int(p.KeyIter)); p.GHM_ != ghm_ || p.Ver != ver || len(p.Salt) != sizeSalt || len(p.IV) != sizeIV || err != nil {
		panic(errors.New("malformed header"))
	}
}

func (p *header) read(r io.Reader) {
	if err := binary.Read(r, headerByteOrder, p); err != nil {
		panic(err)
	}
	p.verify()
}

func (p *header) write(w io.Writer) {
	p.verify()
	if err := binary.Write(w, headerByteOrder, p); err != nil {
		panic(err)
	}
}

func CheckConfig(mode, keyMd, keyIter int) (err error) {
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

func getCipherStreamMode(mode uint16, decrypt bool) func(cipher.Block, []byte) cipher.Stream {
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

func getKeyMd(keyMd uint16) func() hash.Hash {
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

func newCipherBlock(key []byte) cipher.Block {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return block
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

func readBuf(r io.Reader, buf []byte) {
	if _, err := r.Read(buf); err != nil {
		panic(err)
	}
}

func readRand(buf []byte) {
	readBuf(rand.Reader, buf)
}

func Enc(input io.Reader, output io.Writer, pass []byte, mode, keyMd uint16, keyIter int, dbg func(uint16, uint16, int, []byte, []byte, []byte)) {
	r := bufio.NewReader(input)
	w := bufio.NewWriter(output)
	defer (func() {
		err := w.Flush()
		if err != nil {
			panic(err)
		}
	})()
	salt := make([]byte, sizeSalt)
	readRand(salt)
	iv := make([]byte, sizeIV)
	readRand(iv)
	dk := deriveKey(pass, salt, keyIter, getKeyMd(keyMd))
	if dbg != nil {
		dbg(mode, keyMd, keyIter, salt, iv, dk)
	}
	newHeader(mode, keyMd, uint32(keyIter), salt, iv).write(w)
	block := newCipherBlock(dk)
	stream := getCipherStreamMode(mode, false)(block, iv)
	streamWriter := newCipherStreamWriter(stream, w)
	if _, err := io.Copy(streamWriter, r); err != nil {
		panic(err)
	}
}

func Dec(input io.Reader, output io.Writer, pass []byte, dbg func(uint16, uint16, int, []byte, []byte, []byte)) {
	r := bufio.NewReader(input)
	w := bufio.NewWriter(output)
	defer (func() {
		err := w.Flush()
		if err != nil {
			panic(err)
		}
	})()
	header := &header{}
	header.read(r)
	mode := header.Mode
	keyMd := header.KeyMd
	keyIter := int(header.KeyIter)
	salt := header.Salt[:]
	iv := header.IV[:]
	dk := deriveKey(pass, salt, keyIter, getKeyMd(keyMd))
	if dbg != nil {
		dbg(mode, keyMd, keyIter, salt, iv, dk)
	}
	block := newCipherBlock(dk)
	stream := getCipherStreamMode(mode, true)(block, iv)
	streamReader := newCipherStreamReader(stream, r)
	if _, err := io.Copy(w, streamReader); err != nil {
		panic(err)
	}
}
