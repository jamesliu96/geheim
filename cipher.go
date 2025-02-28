package geheim

import (
	"crypto/aes"
	"crypto/cipher"
	"io"

	"golang.org/x/crypto/chacha20"
)

type Cipher int

const (
	AES_256_CTR Cipher = 1 + iota
	ChaCha20
)

var CipherNames = map[Cipher]string{
	AES_256_CTR: "AES-256-CTR",
	ChaCha20:    "ChaCha20",
}

var nonceSizes = map[Cipher]int{
	AES_256_CTR: aes.BlockSize,
	ChaCha20:    chacha20.NonceSize,
}

var keySizesCipher = map[Cipher]int{
	AES_256_CTR: 32,
	ChaCha20:    chacha20.KeySize,
}

var ciphers = [...]Cipher{
	AES_256_CTR,
	ChaCha20,
}

var CipherString = getOptionString(ciphers[:], CipherNames)

var newCTR = cipher.NewCTR

func newCipherStream(cipher Cipher, key, nonce []byte) (cipher.Stream, error) {
	if err := checkBytesSize(nonceSizes, cipher, nonce, "nonce"); err != nil {
		return nil, err
	}
	switch cipher {
	case AES_256_CTR:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return newCTR(block, nonce), nil
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
