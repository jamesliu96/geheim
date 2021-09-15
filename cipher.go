package geheim

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20"
)

type Cipher uint8

const (
	AES Cipher = 1 + iota
	Chacha20
)

var CipherNames = map[Cipher]string{
	AES:      "AES",
	Chacha20: "Chacha20",
}

var ivSizes = map[Cipher]int{
	AES:      aes.BlockSize,
	Chacha20: chacha20.NonceSize,
}

var ciphers = [...]Cipher{AES, Chacha20}

func GetCipherString() string {
	d := make([]string, len(ciphers))
	for i, cipher := range ciphers {
		d[i] = fmt.Sprintf("%d:%s", cipher, CipherNames[cipher])
	}
	return strings.Join(d, ", ")
}

func getStream(cipher Cipher, key []byte, iv []byte, sm func(cipher.Block, []byte) cipher.Stream) (cipher.Stream, Cipher, error) {
	switch cipher {
	case AES:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, AES, err
		}
		return sm(block, iv), AES, nil
	case Chacha20:
		stream, err := chacha20.NewUnauthenticatedCipher(key, iv)
		return stream, Chacha20, err
	}
	return getStream(DefaultCipher, key, iv, sm)
}

type Mode uint8

const (
	CTR Mode = 1 + iota
	OFB
)

var ModeNames = map[Mode]string{
	CTR: "CTR",
	OFB: "OFB",
}

var modes = [...]Mode{CTR, OFB}

func GetModeString() string {
	d := make([]string, len(modes))
	for i, mode := range modes {
		d[i] = fmt.Sprintf("%d:%s", mode, ModeNames[mode])
	}
	return strings.Join(d, ", ")
}

func getStreamMode(mode Mode) (func(cipher.Block, []byte) cipher.Stream, Mode) {
	switch mode {
	case CTR:
		return cipher.NewCTR, CTR
	case OFB:
		return cipher.NewOFB, OFB
	}
	return getStreamMode(DefaultMode)
}

func newStreamReader(stream cipher.Stream, r io.Reader) io.Reader {
	return &cipher.StreamReader{S: stream, R: r}
}

func newStreamWriter(stream cipher.Stream, w io.Writer) io.Writer {
	return &cipher.StreamWriter{S: stream, W: w}
}
