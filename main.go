package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
	"golang.org/x/term"
)

const ver = uint32(1)

var ghm_ = [4]byte{'G', 'H', 'M', '_'}

const (
	sizeSalt = 16
	sizeIV   = aes.BlockSize
	sizeKey  = 32
)

const (
	modeCTR uint16 = 1 << iota
	modeCFB
	modeOFB
)

const (
	sha3224 uint16 = 1 << iota
	sha3256
	sha3384
	sha3512
)

const (
	dMode    = modeCTR
	dKeyMd   = sha3224
	dKeyIter = 100000
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
	if err := checkConfig(int(p.Mode), int(p.KeyMd), int(p.KeyIter)); p.GHM_ != ghm_ || p.Ver != ver || len(p.Salt) != sizeSalt || len(p.IV) != sizeIV || err != nil {
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

func checkConfig(mode, keyMd, keyIter int) (err error) {
	switch mode {
	case int(modeCTR):
	case int(modeCFB):
	case int(modeOFB):
		break
	default:
		err = errors.New("invalid cipher mode")
	}
	switch keyMd {
	case int(sha3224):
	case int(sha3256):
	case int(sha3384):
	case int(sha3512):
		break
	default:
		err = errors.New("invalid key message digest")
	}
	if keyIter < dKeyIter {
		err = errors.New("invalid key iteration")
	}
	return
}

var (
	fDecrypt   bool
	fMode      int
	fKeyMd     int
	fKeyIter   int
	fInput     string
	fOutput    string
	fPass      string
	fOverwrite bool
	fVerbose   bool
)

func flagsSet() (inSet, outSet, passSet bool) {
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "in" {
			inSet = true
		}
		if f.Name == "out" {
			outSet = true
		}
		if f.Name == "pass" {
			passSet = true
		}
	})
	return
}

func checkFlags() {
	if err := checkConfig(fMode, fKeyMd, fKeyIter); err != nil {
		panic(err)
	}
}

func main() {
	flag.BoolVar(&fDecrypt, "d", false, "decrypt (encrypt if not set)")
	flag.StringVar(&fInput, "in", "", "input path (default `stdin`)")
	flag.StringVar(&fOutput, "out", "", "output path (default `stdout`)")
	flag.StringVar(&fPass, "pass", "", "password (password must be specified if stdin is used as input)")
	flag.BoolVar(&fOverwrite, "y", false, "allow overwrite")
	flag.BoolVar(&fVerbose, "v", false, "verbose")
	flag.IntVar(&fMode, "m", int(dMode), "[encrypt] cipher mode (1:CTR, 2:CFB, 4:OFB)")
	flag.IntVar(&fKeyMd, "md", int(dKeyMd), "[encrypt] key message digest (1:SHA3-224, 2:SHA3-256, 4:SHA3-384, 8:SHA3-512)")
	flag.IntVar(&fKeyIter, "iter", dKeyIter, "[encrypt] key iteration (minimum 100000)")
	if len(os.Args) < 2 {
		flag.Usage()
		return
	}
	flag.Parse()
	inSet, outSet, passSet := flagsSet()
	if !fDecrypt {
		checkFlags()
	}
	input, output := getIO(inSet, outSet)
	defer (func() {
		if err := input.Close(); err != nil {
			panic(err)
		}
		if err := output.Close(); err != nil {
			panic(err)
		}
	})()
	if !passSet && input == os.Stdin {
		panic(errors.New("password must be specified if stdin is used as input"))
	}
	pass := getPass()
	if fDecrypt {
		dec(input, output, pass)
	} else {
		enc(input, output, pass)
	}
}

func getIO(inSet, outSet bool) (input, output *os.File) {
	if inSet {
		file, err := os.Open(fInput)
		if err != nil {
			panic(err)
		}
		if fi, err := file.Stat(); err != nil {
			panic(err)
		} else if !fi.Mode().IsRegular() {
			panic(errors.New("input file is not regular"))
		}
		input = file
	} else {
		input = os.Stdin
	}
	if outSet {
		if !fOverwrite {
			if _, err := os.Stat(fOutput); err == nil {
				panic(errors.New("output exists, use `-y` to overwrite"))
			}
		}
		file, err := os.Create(fOutput)
		if err != nil {
			panic(err)
		}
		output = file
	} else {
		output = os.Stdout
	}
	return
}

func printfStderr(format string, v ...interface{}) {
	fmt.Fprintf(os.Stderr, format, v...)
}

func getPass() []byte {
	if fPass != "" {
		return []byte(fPass)
	}
	stdinFd := int(os.Stdin.Fd())
	printfStderr("enter password: ")
	bPass, err := term.ReadPassword(stdinFd)
	if err != nil {
		panic(err)
	}
	printfStderr("\n")
	if string(bPass) == "" {
		panic(errors.New("empty password"))
	}
	if fDecrypt {
		return bPass
	}
	printfStderr("verify password: ")
	bvPass, err := term.ReadPassword(stdinFd)
	if err != nil {
		panic(err)
	}
	printfStderr("\n")
	if string(bPass) != string(bvPass) {
		panic(errors.New("password verification failed"))
	}
	return bPass
}

func getCipherStreamMode(mode uint16, decrypt bool) func(cipher.Block, []byte) cipher.Stream {
	switch mode {
	case modeCTR:
		return cipher.NewCTR
	case modeCFB:
		if decrypt {
			return cipher.NewCFBDecrypter
		} else {
			return cipher.NewCFBEncrypter
		}
	case modeOFB:
		return cipher.NewOFB
	}
	return getCipherStreamMode(dMode, decrypt)
}

func getKeyMd(keyMd uint16) func() hash.Hash {
	switch keyMd {
	case sha3224:
		return sha3.New224
	case sha3256:
		return sha3.New256
	case sha3384:
		return sha3.New384
	case sha3512:
		return sha3.New512
	}
	return getKeyMd(dKeyMd)
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

func dbg(mode, keyMd uint16, keyIter int, salt, iv, key []byte) {
	printfStderr("Mode\t%d\n", mode)
	printfStderr("KeyMd\t%d\n", keyMd)
	printfStderr("KeyIter\t%d\n", keyIter)
	printfStderr("Salt\t%s\n", hex.EncodeToString(salt))
	printfStderr("IV\t%s\n", hex.EncodeToString(iv))
	printfStderr("Key\t%s\n", hex.EncodeToString(key))
}

func enc(input io.Reader, output io.Writer, pass []byte) {
	mode := uint16(fMode)
	keyMd := uint16(fKeyMd)
	keyIter := fKeyIter
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
	if fVerbose {
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

func dec(input io.Reader, output io.Writer, pass []byte) {
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
	if fVerbose {
		dbg(mode, keyMd, keyIter, salt, iv, dk)
	}
	block := newCipherBlock(dk)
	stream := getCipherStreamMode(mode, true)(block, iv)
	streamReader := newCipherStreamReader(stream, r)
	if _, err := io.Copy(w, streamReader); err != nil {
		panic(err)
	}
}
