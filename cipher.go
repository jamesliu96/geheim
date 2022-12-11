package geheim

import (
	"crypto/aes"
	"crypto/cipher"
	"io"

	"golang.org/x/crypto/chacha20"
)

type Cipher uint8

const (
	AES_256 Cipher = 1 + iota
	ChaCha20
)

var CipherNames = map[Cipher]string{
	AES_256:  "AES-256",
	ChaCha20: "ChaCha20",
}

var ivSizes = map[Cipher]int{
	AES_256:  aes.BlockSize,
	ChaCha20: chacha20.NonceSize,
}

var keySizesCipher = map[Cipher]int{
	AES_256:  32,
	ChaCha20: chacha20.KeySize,
}

var ciphers = [...]Cipher{AES_256, ChaCha20}

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

type StreamMode func(cipher.Block, []byte) cipher.Stream

func getStreamMode(mode Mode, decrypt bool) (StreamMode, Mode) {
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

func checkKeySizeCipher(cipher Cipher, key []byte) error {
	return checkBytesSize(keySizesCipher, cipher, key, "cipher key")
}

func checkIVSize(cipher Cipher, iv []byte) error {
	return checkBytesSize(ivSizes, cipher, iv, "nonce")
}

func newCipherStream(cipher Cipher, key []byte, iv []byte, sm StreamMode) (cipher.Stream, Cipher, error) {
	if err := checkKeySizeCipher(cipher, key); err != nil {
		return nil, cipher, err
	}
	if err := checkIVSize(cipher, iv); err != nil {
		return nil, cipher, err
	}
	switch cipher {
	case AES_256:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, AES_256, err
		}
		return sm(block, iv), AES_256, nil
	case ChaCha20:
		stream, err := chacha20.NewUnauthenticatedCipher(key, iv)
		return stream, ChaCha20, err
	}
	return newCipherStream(DefaultCipher, key, iv, sm)
}

func newCipherStreamReader(stream cipher.Stream, r io.Reader) io.Reader {
	return &cipher.StreamReader{S: stream, R: r}
}

func newCipherStreamWriter(stream cipher.Stream, w io.Writer) io.Writer {
	return &cipher.StreamWriter{S: stream, W: w}
}
