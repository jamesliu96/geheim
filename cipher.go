package geheim

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"strings"
)

type Mode uint16

const (
	ModeCTR Mode = 1 + iota
	ModeCFB
	ModeOFB
)

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
	return getCipherStreamMode(DefaultMode, decrypt)
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
