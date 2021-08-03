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

const (
	g   = uint8('G')
	ver = uint32(1)
)

var gggg = [4]byte{g, g, g, g}

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
	GGGG    [4]byte
	Ver     uint32
	Mode    uint16
	KeyMd   uint16
	KeyIter uint32
	Salt    [sizeSalt]byte
	IV      [sizeIV]byte
}

func newHeader(mode uint16, keyMd uint16, keyIter uint32, salt []byte, iv []byte) *header {
	h := &header{GGGG: gggg, Ver: ver, Mode: mode, KeyMd: keyMd, KeyIter: keyIter}
	copy(h.Salt[:], salt)
	copy(h.IV[:], iv)
	return h
}

func (p *header) verify() {
	if p.GGGG != gggg || p.Ver != ver {
		panic(errors.New("invalid header"))
	}
}

func (p *header) read(r io.Reader) {
	if err := binary.Read(r, headerByteOrder, p); err != nil {
		panic(err)
	}
}

func (p *header) write(w io.Writer) {
	if err := binary.Write(w, headerByteOrder, p); err != nil {
		panic(err)
	}
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

func checkFlags() {
	switch fMode {
	case int(modeCTR):
	case int(modeCFB):
	case int(modeOFB):
		break
	default:
		panic(errors.New("invalid cipher mode"))
	}
	switch fKeyMd {
	case int(sha3224):
	case int(sha3256):
	case int(sha3384):
	case int(sha3512):
		break
	default:
		panic(errors.New("invalid key message digest"))
	}
	if fKeyIter < dKeyIter {
		panic(errors.New("invalid key iteration"))
	}
}

func main() {
	flag.BoolVar(&fDecrypt, "d", false, "decrypt (encrypt if not set)")
	flag.StringVar(&fInput, "in", "", "input path")
	flag.StringVar(&fOutput, "out", "", "output path")
	flag.StringVar(&fPass, "pass", "", "password")
	flag.BoolVar(&fOverwrite, "y", false, "allow overwrite")
	flag.BoolVar(&fVerbose, "v", false, "verbose")
	flag.IntVar(&fMode, "m", int(dMode), "[encrypt] cipher mode (1:CTR, 2:CFB, 4:OFB)")
	flag.IntVar(&fKeyMd, "md", int(dKeyMd), "[encrypt] key message digest (1:SHA3-224, 2:SHA3-256, 4:SHA3-384, 8:SHA3-512)")
	flag.IntVar(&fKeyIter, "iter", dKeyIter, "[encrypt] key iteration (minimum 100000)")
	if len(os.Args) == 1 {
		flag.Usage()
		return
	}
	flag.Parse()
	if !fDecrypt {
		checkFlags()
	}
	input, output := getIO(fInput, fOutput, fOverwrite)
	defer (func() {
		if err := input.Close(); err != nil {
			panic(err)
		}
		if err := output.Close(); err != nil {
			panic(err)
		}
	})()
	if input == os.Stdin && fPass == "" {
		panic(errors.New("password must be specified if stdin is used as input"))
	}
	var pass []byte
	if fPass == "" {
		pass = getPass(!fDecrypt)
	} else {
		pass = []byte(fPass)
	}
	if fDecrypt {
		dec(input, output, pass, fVerbose)
		return
	}
	enc(input, output, pass, fVerbose, uint16(fMode), uint16(fKeyMd), fKeyIter)
}

func getIO(inPath, outPath string, overwrite bool) (input, output *os.File) {
	if inPath == "" {
		input = os.Stdin
	} else {
		file, err := os.Open(inPath)
		if err != nil {
			panic(err)
		}
		if fi, err := file.Stat(); err != nil {
			panic(err)
		} else if !fi.Mode().IsRegular() {
			panic(errors.New("input file is not regular"))
		}
		input = file
	}
	if outPath == "" {
		output = os.Stdout
	} else {
		if !overwrite {
			if _, err := os.Stat(outPath); err == nil {
				panic(errors.New("output exists, use `-y` to overwrite"))
			}
		}
		file, err := os.Create(outPath)
		if err != nil {
			panic(err)
		}
		output = file
	}
	return
}

func printfStderr(format string, v ...interface{}) {
	fmt.Fprintf(os.Stderr, format, v...)
}

func getPass(verify bool) []byte {
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
	if !verify {
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

func enc(input io.Reader, output io.Writer, pass []byte, print bool, mode, keyMd uint16, keyIter int) {
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
	if print {
		dbg(mode, keyMd, keyIter, salt, iv, dk)
	}
	header := newHeader(mode, keyMd, uint32(keyIter), salt, iv)
	header.write(w)
	block := newCipherBlock(dk)
	stream := getCipherStreamMode(mode, false)(block, iv)
	streamWriter := newCipherStreamWriter(stream, w)
	if _, err := io.Copy(streamWriter, r); err != nil {
		panic(err)
	}
}

func dec(input io.Reader, output io.Writer, pass []byte, print bool) {
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
	header.verify()
	mode := header.Mode
	keyMd := header.KeyMd
	keyIter := int(header.KeyIter)
	salt := header.Salt[:]
	iv := header.IV[:]
	dk := deriveKey(pass, salt, keyIter, getKeyMd(keyMd))
	if print {
		dbg(mode, keyMd, keyIter, salt, iv, dk)
	}
	block := newCipherBlock(dk)
	stream := getCipherStreamMode(mode, true)(block, iv)
	streamReader := newCipherStreamReader(stream, r)
	if _, err := io.Copy(w, streamReader); err != nil {
		panic(err)
	}
}
