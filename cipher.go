package geheim

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"

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

var keySizes = map[Cipher]int{
	AES:      32,
	Chacha20: chacha20.KeySize,
}

var ciphers = [...]Cipher{AES, Chacha20}

func GetCipherString() string {
	return getString(ciphers[:], CipherNames)
}

type Mode uint8

const (
	CTR Mode = 1 + iota
	CFB
	OFB
)

var ModeNames = map[Mode]string{
	CTR: "CTR",
	CFB: "CFB",
	OFB: "OFB",
}

var modes = [...]Mode{CTR, CFB, OFB}

func GetModeString() string {
	return getString(modes[:], ModeNames)
}

func getStreamMode(mode Mode, decrypt bool) (func(cipher.Block, []byte) cipher.Stream, Mode) {
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
	return getStreamMode(DefaultMode, decrypt)
}

func checkKeySize(cipher Cipher, key []byte) error {
	expected := keySizes[cipher]
	if expected != len(key) {
		return errors.New("invalid key size")
	}
	return nil
}

func checkIVSize(cipher Cipher, iv []byte) error {
	expected := ivSizes[cipher]
	if expected != len(iv) {
		return errors.New("invalid nonce size")
	}
	return nil
}

func newCipherStream(cipher Cipher, key []byte, iv []byte, sm func(cipher.Block, []byte) cipher.Stream) (cipher.Stream, Cipher, error) {
	if err := checkKeySize(cipher, key); err != nil {
		return nil, cipher, err
	}
	if err := checkIVSize(cipher, iv); err != nil {
		return nil, cipher, err
	}
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
	return newCipherStream(DefaultCipher, key, iv, sm)
}

func newCipherStreamReader(stream cipher.Stream, r io.Reader) io.Reader {
	return &cipher.StreamReader{S: stream, R: r}
}

func newCipherStreamWriter(stream cipher.Stream, w io.Writer) io.Writer {
	return &cipher.StreamWriter{S: stream, W: w}
}
