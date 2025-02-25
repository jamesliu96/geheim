package geheim

import (
	"crypto/aes"
	"crypto/cipher"
	"io"

	"golang.org/x/crypto/chacha20"
)

type Cipher int

const (
	AES_256 Cipher = 1 + iota
	ChaCha20
)

var CipherNames = map[Cipher]string{
	AES_256:  "AES-256",
	ChaCha20: "ChaCha20",
}

var nonceSizes = map[Cipher]int{
	AES_256:  aes.BlockSize,
	ChaCha20: chacha20.NonceSize,
}

var keySizesCipher = map[Cipher]int{
	AES_256:  32,
	ChaCha20: chacha20.KeySize,
}

var ciphers = [...]Cipher{
	AES_256,
	ChaCha20,
}

var CipherString = getOptionString(ciphers[:], CipherNames)

type Mode int

const (
	CTR Mode = 1 + iota
)

var ModeNames = map[Mode]string{
	CTR: "CTR",
}

var modes = [...]Mode{
	CTR,
}

var ModeString = getOptionString(modes[:], ModeNames)

func getStreamMode(mode Mode) (StreamMode, error) {
	switch mode {
	case CTR:
		return cipher.NewCTR, nil
	}
	return nil, ErrMode
}

func newCipherStream(cipher Cipher, mode Mode, key, nonce []byte) (cipher.Stream, error) {
	if err := checkBytesSize(nonceSizes, cipher, nonce, "nonce"); err != nil {
		return nil, err
	}
	switch cipher {
	case AES_256:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		sm, err := getStreamMode(mode)
		if err != nil {
			return nil, err
		}
		return sm(block, nonce), nil
	case ChaCha20:
		stream, err := chacha20.NewUnauthenticatedCipher(key, nonce)
		return stream, err
	}
	return nil, ErrCipher
}

func newStreamReader(stream cipher.Stream, r io.Reader) io.Reader {
	return &cipher.StreamReader{S: stream, R: r}
}

func newStreamWriter(stream cipher.Stream, w io.Writer) io.Writer {
	return &cipher.StreamWriter{S: stream, W: w}
}
