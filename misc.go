package geheim

import (
	"crypto/rand"
	"fmt"
	"io"
	"math"
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

type PrintFunc func(version int, cipher Cipher, mode Mode, kdf KDF, mac MAC, md MD, sec int, pass, salt, iv, key []byte) error

func Validate(cipher Cipher, mode Mode, kdf KDF, mac MAC, md MD, sec int) (err error) {
	err = fmt.Errorf("invalid %s (%s)", CipherDesc, GetCipherString())
	for _, c := range ciphers {
		if c == cipher {
			err = nil
			break
		}
	}
	if err != nil {
		return
	}
	err = fmt.Errorf("invalid %s (%s)", ModeDesc, GetModeString())
	for _, m := range modes {
		if m == mode {
			err = nil
			break
		}
	}
	if err != nil {
		return
	}
	err = fmt.Errorf("invalid %s (%s)", KDFDesc, GetKDFString())
	for _, k := range kdfs {
		if k == kdf {
			err = nil
			break
		}
	}
	if err != nil {
		return
	}
	err = fmt.Errorf("invalid %s (%s)", MACDesc, GetMACString())
	for _, m := range macs {
		if m == mac {
			err = nil
			break
		}
	}
	if err != nil {
		return
	}
	err = fmt.Errorf("invalid %s (%s)", MDDesc, GetMDString())
	for _, m := range mds {
		if m == md {
			err = nil
			break
		}
	}
	if err != nil {
		return
	}
	if sec < MinSec || sec > MaxSec {
		err = fmt.Errorf("invalid %s (%d~%d)", SecDesc, MinSec, MaxSec)
	}
	return
}

func FormatSize(n int64) string {
	var unit string
	nn := float64(n)
	f := "%.2f"
	switch {
	case n >= 1<<60:
		nn /= 1 << 60
		unit = "E"
	case n >= 1<<50:
		nn /= 1 << 50
		unit = "P"
	case n >= 1<<40:
		nn /= 1 << 40
		unit = "T"
	case n >= 1<<30:
		nn /= 1 << 30
		unit = "G"
	case n >= 1<<20:
		nn /= 1 << 20
		unit = "M"
	case n >= 1<<10:
		nn /= 1 << 10
		unit = "K"
	default:
		f = "%.f"
	}
	return fmt.Sprintf("%s%sB", fmt.Sprintf(f, math.Max(0, nn)), unit)
}

func NewPrintFunc(w io.Writer) PrintFunc {
	return func(version int, cipher Cipher, mode Mode, kdf KDF, mac MAC, md MD, sec int, pass, salt, iv, key []byte) error {
		fmt.Fprintf(w, "%-8s%d\n", "VERSION", version)
		fmt.Fprintf(w, "%-8s%s(%d)\n", "CIPHER", CipherNames[cipher], cipher)
		if cipher == AES {
			fmt.Fprintf(w, "%-8s%s(%d)\n", "MODE", ModeNames[mode], mode)
		}
		fmt.Fprintf(w, "%-8s%s(%d)\n", "KDF", KDFNames[kdf], kdf)
		fmt.Fprintf(w, "%-8s%s(%d)\n", "MAC", MACNames[mac], mac)
		if kdf == PBKDF2 || mac == HMAC {
			fmt.Fprintf(w, "%-8s%s(%d)\n", "MD", MDNames[md], md)
		}
		iter, memory, sec := GetSecIterMemory(sec)
		if kdf == PBKDF2 {
			fmt.Fprintf(w, "%-8s%d(%d)\n", "SEC", sec, iter)
		} else {
			fmt.Fprintf(w, "%-8s%d(%s)\n", "SEC", sec, FormatSize(int64(memory)))
		}
		fmt.Fprintf(w, "%-8s%s(%x)\n", "PASS", pass, pass)
		fmt.Fprintf(w, "%-8s%x\n", "SALT", salt)
		fmt.Fprintf(w, "%-8s%x\n", "IV", iv)
		fmt.Fprintf(w, "%-8s%x\n", "KEY", key)
		return nil
	}
}

func randRead(buf []byte) (err error) {
	_, err = rand.Read(buf)
	return
}

func getString[T comparable](list []T, names map[T]string) string {
	d := make([]string, len(list))
	for i, item := range list {
		d[i] = fmt.Sprintf("%v:%s", item, names[item])
	}
	return strings.Join(d, ", ")
}

type ProgressWriter struct {
	TotalBytes       int64
	bytesWritten     int64
	lastBytesWritten int64
	lastTime         time.Time
}

func (w *ProgressWriter) Write(p []byte) (n int, err error) {
	n = len(p)
	w.bytesWritten += int64(n)
	return
}

func (w *ProgressWriter) Progress(done <-chan struct{}, d time.Duration) {
	var stop bool
	for {
		n := time.Now()
		select {
		case <-done:
			stop = true
		default:
			w.print(false)
			w.lastBytesWritten = w.bytesWritten
			w.lastTime = time.Now()
		}
		if stop {
			w.print(true)
			break
		}
		time.Sleep(d - time.Since(n))
	}
}

func (w *ProgressWriter) print(last bool) {
	hasTotalPerc := w.TotalBytes > 0
	var perc float64
	var totalPerc string
	if hasTotalPerc {
		perc = math.Min(float64(w.bytesWritten)/float64(w.TotalBytes), 1)
		totalPerc = fmt.Sprintf("/%s (%.f%%)", FormatSize(w.TotalBytes), perc*100)
	}
	left, right :=
		fmt.Sprintf("%s%s", FormatSize(w.bytesWritten), totalPerc),
		fmt.Sprintf("%s/s", FormatSize(int64(math.Max(float64(w.bytesWritten-w.lastBytesWritten), 0)/float64(time.Since(w.lastTime))/time.Nanosecond.Seconds())))
	width, _, _ := term.GetSize(int(os.Stderr.Fd()))
	var middle string
	if hasTotalPerc {
		leftBracket, rightBracket := " [", "] "
		space := width - len(left) - len(right) - len(leftBracket) - len(rightBracket)
		activeSpace := int(float64(space) * perc)
		activeBars := strings.Repeat("=", activeSpace)
		if activeSpace > 0 && activeSpace < space {
			activeBars = activeBars[:len(activeBars)-1] + ">"
		}
		bars := fmt.Sprintf(fmt.Sprintf("%%-%ds", space), activeBars)
		middle = fmt.Sprintf("%s%s%s", leftBracket, bars, rightBracket)
	}
	middle = fmt.Sprintf(fmt.Sprintf("%%%ds", width-len(left)-len(middle)-len(right)), middle)
	var newline string
	if last {
		newline = "\n"
	}
	fmt.Fprintf(os.Stderr, "\r%s%s%s%s", left, middle, right, newline)
}
