package geheim

import (
	"crypto/cipher"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
)

const (
	CipherDesc = "cipher"
	ModeDesc   = "stream mode"
	KDFDesc    = "key derivation"
	MACDesc    = "message authentication"
	MDDesc     = "message digest"
	SecDesc    = "security level"
)

type PrintFunc func(version int, header Header, pass, keyCipher, keyMAC []byte) error

type MDFunc func() hash.Hash

type StreamMode func(cipher.Block, []byte) cipher.Stream

var (
	ErrEptPass = errors.New("geheim: empty passcode")
	ErrMfmHdr  = errors.New("geheim: malformed header")
	ErrSigVer  = errors.New("geheim: signature verification failed")

	ErrInvCipher = fmt.Errorf("geheim: invalid %s (%s)", CipherDesc, CipherString)
	ErrInvMode   = fmt.Errorf("geheim: invalid %s (%s)", ModeDesc, ModeString)
	ErrInvKDF    = fmt.Errorf("geheim: invalid %s (%s)", KDFDesc, KDFString)
	ErrInvMAC    = fmt.Errorf("geheim: invalid %s (%s)", MACDesc, MACString)
	ErrInvMD     = fmt.Errorf("geheim: invalid %s (%s)", MDDesc, MDString)
	ErrInvSec    = fmt.Errorf("geheim: invalid %s (%d~%d)", SecDesc, MinSec, MaxSec)

	ErrPrgWtr = errors.New("geheim.ProgressWriter: incorrect bytes written")
)

func Verify(x, y []byte) error {
	if !hmac.Equal(x, y) {
		return ErrSigVer
	}
	return nil
}

var (
	meta      = NewMeta()
	header, _ = meta.Header()

	MetaSize   = int64(binary.Size(meta))
	HeaderSize = int64(binary.Size(header))
	Overhead   = MetaSize + HeaderSize
)

func NewDefaultPrintFunc(w io.Writer) PrintFunc {
	printf := func(format string, a ...any) { fmt.Fprintf(w, format, a...) }
	return func(version int, header Header, pass, keyCipher, keyMAC []byte) error {
		cipher, mode, kdf, mac, md, sec, salt, nonce := header.Get()
		printf("%-8s%d\n", "VERSION", version)
		if cipher == AES_256 {
			printf("%-8s%s-%s(%d,%d)\n", "CIPHER", CipherNames[cipher], ModeNames[mode], cipher, mode)
		} else {
			printf("%-8s%s(%d)\n", "CIPHER", CipherNames[cipher], cipher)
		}
		printf("%-8s%s(%d)\n", "KDF", KDFNames[kdf], kdf)
		printf("%-8s%s(%d)\n", "MAC", MACNames[mac], mac)
		printf("%-8s%s(%d)\n", "MD", MDNames[md], md)
		printf("%-8s%s(%d)\n", "SEC", FormatSize(GetMemory(sec)), sec)
		printf("%-8s%x\n", "SALT", salt)
		printf("%-8s%x\n", "NONCE", nonce)
		printf("%-8s%s(%x)\n", "PASS", pass, pass)
		printf("%-8s%x\n", "CIPKEY", keyCipher)
		printf("%-8s%x\n", "MACKEY", keyMAC)
		return nil
	}
}

func FormatSize(n int64) string {
	var unit string
	nn := float64(n)
	f := "%.2f"
	switch {
	case nn >= 1<<60:
		nn /= 1 << 60
		unit = "E"
	case nn >= 1<<50:
		nn /= 1 << 50
		unit = "P"
	case nn >= 1<<40:
		nn /= 1 << 40
		unit = "T"
	case nn >= 1<<30:
		nn /= 1 << 30
		unit = "G"
	case nn >= 1<<20:
		nn /= 1 << 20
		unit = "M"
	case nn >= 1<<10:
		nn /= 1 << 10
		unit = "K"
	default:
		f = "%.f"
	}
	return fmt.Sprintf("%s%sB", fmt.Sprintf(f, nn), unit)
}

type ProgressWriter struct {
	TotalBytes int64

	bytesWritten     int64
	lastBytesWritten int64
	initTime         time.Time
	lastTime         time.Time
}

var _ io.Writer = (*ProgressWriter)(nil)

func NewProgressWriter(total int64) *ProgressWriter { return &ProgressWriter{TotalBytes: total} }

func (w *ProgressWriter) Write(p []byte) (n int, err error) {
	n = len(p)
	w.bytesWritten += int64(n)
	return
}

func (w *ProgressWriter) Reset() {
	w.bytesWritten = 0
	w.lastBytesWritten = 0
	w.initTime = time.Time{}
	w.lastTime = time.Time{}
}

func (w *ProgressWriter) Progress(duration time.Duration, done <-chan struct{}) {
	w.initTime = time.Now()
	var stop bool
	for {
		select {
		case <-done:
			stop = true
		default:
		}
		n := time.Now()
		w.print(stop)
		w.lastBytesWritten = w.bytesWritten
		w.lastTime = n
		if stop {
			break
		}
		time.Sleep(duration - time.Since(n))
	}
}

const (
	leftBracket  = " ["
	rightBracket = "] "
)

func (w *ProgressWriter) print(last bool) {
	hasTotalPerc := w.TotalBytes > 0
	var perc float64
	var totalPerc string
	if hasTotalPerc {
		perc = float64(w.bytesWritten) / float64(w.TotalBytes)
		totalPerc = fmt.Sprintf("/%s (%.f%%)", FormatSize(w.TotalBytes), perc*100)
	}
	left := fmt.Sprintf("%s%s", FormatSize(w.bytesWritten), totalPerc)
	right := fmt.Sprintf("%s/s", FormatSize(int64(float64(w.bytesWritten-w.lastBytesWritten)/float64(time.Since(w.lastTime))/time.Nanosecond.Seconds())))
	if last {
		right = fmt.Sprintf("%s/s", FormatSize(int64(float64(w.bytesWritten)/float64(time.Since(w.initTime))/time.Nanosecond.Seconds())))
	}
	width, _, _ := term.GetSize(int(os.Stderr.Fd()))
	middleWidth := width - len(left) - len(right)
	var middle string
	if hasTotalPerc {
		barsWidth := middleWidth - len(leftBracket) - len(rightBracket)
		if barsWidth >= 0 {
			complete := int(float64(barsWidth) * perc)
			bars := make([]byte, barsWidth)
			for i := range bars {
				if i < complete {
					bars[i] = '='
				} else if i != 0 && i == complete {
					bars[i] = '>'
				} else {
					bars[i] = '-'
				}
			}
			middle = fmt.Sprintf("%s%s%s", leftBracket, bars, rightBracket)
		}
	}
	middle = fmt.Sprintf(fmt.Sprintf("%%%ds", middleWidth-len(middle)), middle)
	var newline string
	if last {
		newline = "\n"
	}
	fmt.Fprintf(os.Stderr, "\r%s%s%s%s", left, middle, right, newline)
}

func readBE(r io.Reader, v any) error { return binary.Read(r, binary.BigEndian, v) }

func writeBE(w io.Writer, v any) error { return binary.Write(w, binary.BigEndian, v) }

func readBEN[T any](r io.Reader) (n T, err error) {
	err = readBE(r, &n)
	return
}

func writeBEN[T any](w io.Writer, n T) error { return writeBE(w, n) }

func getOptionString[T comparable](values []T, names map[T]string) string {
	d := make([]string, len(values))
	for i, item := range values {
		d[i] = fmt.Sprintf("%v:%s", item, names[item])
	}
	return strings.Join(d, ", ")
}

func checkBytesSize[T comparable](sizes map[T]int, key T, value []byte, name string) error {
	if sizes[key] != len(value) {
		return fmt.Errorf("geheim: invalid %s size", name)
	}
	return nil
}
