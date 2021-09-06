package geheim

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"strings"
)

type Cipher uint8

const (
	AES Cipher = 1 + iota
)

var CipherNames = map[Cipher]string{
	AES: "AES",
}

var ciphers = [...]Cipher{AES}

func GetCipherString() string {
	d := []string{}
	for _, cipher := range ciphers {
		d = append(d, fmt.Sprintf("%d:%s", cipher, CipherNames[cipher]))
	}
	return strings.Join(d, ", ")
}

type Mode uint8

const (
	CTR Mode = 1 + iota
	CFB
	OFB
)

func getCipherStreamMode(mode Mode, decrypt bool) (func(cipher.Block, []byte) cipher.Stream, Mode) {
	switch mode {
	case CTR:
		return cipher.NewCTR, CTR
	case CFB:
		if decrypt {
			return cipher.NewCFBDecrypter, CFB
		} else {
			return cipher.NewCFBEncrypter, CFB
		}
	case OFB:
		return cipher.NewOFB, OFB
	}
	return getCipherStreamMode(DefaultMode, decrypt)
}

func newAESCipherBlock(key []byte) (cipher.Block, error) {
	return aes.NewCipher(key)
}

func newCipherStreamReader(stream cipher.Stream, r io.Reader) io.Reader {
	return &cipher.StreamReader{S: stream, R: r}
}

func newCipherStreamWriter(stream cipher.Stream, w io.Writer) io.Writer {
	return &cipher.StreamWriter{S: stream, W: w}
}

var ModeNames = map[Mode]string{
	CTR: "CTR",
	CFB: "CFB",
	OFB: "OFB",
}

var modes = [...]Mode{CTR, CFB, OFB}

func GetModeString() string {
	d := []string{}
	for _, mode := range modes {
		d = append(d, fmt.Sprintf("%d:%s", mode, ModeNames[mode]))
	}
	return strings.Join(d, ", ")
}
