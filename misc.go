package geheim

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
)

type PrintFunc func(version int, header Header, key []byte) error

const (
	CipherDesc = "cipher"
	KDFDesc    = "key derivation"
	HashDesc   = "hash"
	SecDesc    = "security"
)

var (
	meta      = NewMeta()
	header, _ = meta.Header()

	MetaSize     = int64(binary.Size(meta))
	HeaderSize   = int64(binary.Size(header))
	OverheadSize = MetaSize + HeaderSize
)

var (
	ErrKey    = errors.New("geheim: empty key")
	ErrHeader = errors.New("geheim: malformed header")
	ErrAuth   = errors.New("geheim: authentication verification failed")

	ErrCipher = fmt.Errorf("geheim: invalid %s (%s)", CipherDesc, CipherString)
	ErrKDF    = fmt.Errorf("geheim: invalid %s (%s)", KDFDesc, KDFString)
	ErrHash   = fmt.Errorf("geheim: invalid %s (%s)", HashDesc, HashString)
	ErrSec    = fmt.Errorf("geheim: invalid %s (%s)", SecDesc, SecString)
)

func Verify(x, y []byte) error {
	if !hmac.Equal(x, y) {
		return ErrAuth
	}
	return nil
}

func NewDefaultPrintFunc(w io.Writer) PrintFunc {
	printf := func(format string, a ...any) { fmt.Fprintf(w, format, a...) }
	return func(version int, header Header, key []byte) error {
		cipher, hash, kdf, sec, salt, nonce := header.Get()
		printf("%-8s%d\n", "VERSION", version)
		printf("%-8s%s(%d)\n", "CIPHER", CipherNames[cipher], cipher)
		printf("%-8s%s(%d)\n", "HASH", HashNames[hash], hash)
		var hkdf string
		if kdf != HKDF {
			hkdf = "+HKDF"
		}
		printf("%-8s%s%s-%s(%d)\n", "KDF", KDFNames[kdf], hkdf, HashNames[hash], kdf)
		printf("%-8sHMAC-%s\n", "MAC", HashNames[hash])
		if kdf != HKDF {
			printf("%-8s%s(%d)\n", "SEC", FormatSize(GetMemory(sec), 0), sec)
		}
		printf("%-8s%x\n", "SALT", salt)
		printf("%-8s%x\n", "NONCE", nonce)
		if kdf == HKDF {
			printf("%-8s%x\n", "KEY", key)
		} else {
			printf("%-8s%s(%x)\n", "KEY", key, key)
		}
		return nil
	}
}

func FormatSize(n int64, dec uint) string {
	var unit string
	nn := float64(n)
	f := fmt.Sprintf("%%.%df", dec)
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
		totalPerc = fmt.Sprintf("/%s (%.f%%)", FormatSize(w.TotalBytes, 2), perc*100)
	}
	left := fmt.Sprintf("%s%s", FormatSize(w.bytesWritten, 2), totalPerc)
	right := fmt.Sprintf("%s/s", FormatSize(int64(float64(w.bytesWritten-w.lastBytesWritten)/float64(time.Since(w.lastTime))/time.Nanosecond.Seconds()), 2))
	if last {
		right = fmt.Sprintf("%s/s", FormatSize(int64(float64(w.bytesWritten)/float64(time.Since(w.initTime))/time.Nanosecond.Seconds()), 2))
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
