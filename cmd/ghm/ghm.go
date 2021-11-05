package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"runtime"
	"time"

	"github.com/jamesliu96/geheim"
	"golang.org/x/term"
)

const app = "ghm"

var gitTag = "*"
var gitRev = "*"

var (
	fDecrypt   bool
	fCipher    int
	fMode      int
	fKDF       int
	fMAC       int
	fMD        int
	fSL        int
	fIn        string
	fOut       string
	fSign      string
	fPass      string
	fOverwrite bool
	fVerbose   bool
	fProgress  bool
	fVersion   bool
	fDry       bool
	fGen       int
)

func flagsSet() map[string]bool {
	flags := map[string]bool{}
	flag.Visit(func(f *flag.Flag) {
		flags[f.Name] = true
	})
	return flags
}

func printf(format string, v ...interface{}) {
	fmt.Fprintf(os.Stderr, format, v...)
}

func check(errs ...error) (goterr bool) {
	for _, err := range errs {
		if err != nil && !errors.Is(err, errDry) {
			printf("error: %s\n", err)
			goterr = true
		}
	}
	if goterr {
		os.Exit(1)
	}
	return
}

func readPass(p *[]byte, question string) error {
	for len(*p) == 0 {
		printf(question)
		password, err := term.ReadPassword(int(os.Stdin.Fd()))
		printf("\n")
		if err != nil {
			return err
		}
		*p = password
	}
	return nil
}

func getPass(passset bool) ([]byte, error) {
	if passset {
		return []byte(fPass), nil
	}
	var pass []byte
	err := readPass(&pass, "enter passcode: ")
	if err != nil {
		return nil, err
	}
	if !fDecrypt {
		var vpass []byte
		err := readPass(&vpass, "verify passcode: ")
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(pass, vpass) {
			return nil, errors.New("passcode verification failed")
		}
	}
	return pass, nil
}

func getIO(inset, outset, signset bool) (in, out, sign *os.File, inbytes int64, err error) {
	if inset {
		in, err = os.Open(fIn)
		if err != nil {
			return
		}
		if fi, e := in.Stat(); e != nil {
			err = e
			return
		} else {
			if fi.IsDir() {
				err = fmt.Errorf("input file `%s` is a directory", fIn)
				return
			}
			inbytes = fi.Size()
		}
	} else {
		in = os.Stdin
	}
	if outset {
		if !fOverwrite {
			if _, e := os.Stat(fOut); e == nil {
				err = fmt.Errorf("output file `%s` exists, use -f to overwrite", fOut)
				return
			}
		}
		out, err = os.Create(fOut)
		if err != nil {
			return
		}
	} else {
		out = os.Stdout
	}
	if fVerbose {
		printf("%-8s%s\n", "INPUT", in.Name())
		printf("%-8s%s\n", "OUTPUT", out.Name())
	}
	if signset {
		if fDecrypt {
			sign, err = os.Open(fSign)
			if err != nil {
				return
			}
			if fi, e := sign.Stat(); e != nil {
				err = e
				return
			} else if fi.IsDir() {
				err = fmt.Errorf("signature file `%s` is a directory", fSign)
				return
			}
		} else {
			if !fOverwrite {
				if _, e := os.Stat(fSign); e == nil {
					err = fmt.Errorf("signature file `%s` exists, use -f to overwrite", fSign)
					return
				}
			}
			sign, err = os.Create(fSign)
			if err != nil {
				return
			}
		}
		if fVerbose {
			printf("%-8s%s\n", "SIGN", sign.Name())
		}
	}
	return
}

func formatSize(n int64) string {
	var unit byte
	nn := float64(n)
	f := "%.2f"
	switch {
	case n >= 1<<60:
		nn /= 1 << 60
		unit = 'E'
	case n >= 1<<50:
		nn /= 1 << 50
		unit = 'P'
	case n >= 1<<40:
		nn /= 1 << 40
		unit = 'T'
	case n >= 1<<30:
		nn /= 1 << 30
		unit = 'G'
	case n >= 1<<20:
		nn /= 1 << 20
		unit = 'M'
	case n >= 1<<10:
		nn /= 1 << 10
		unit = 'K'
	default:
		f = "%.f"
	}
	return fmt.Sprintf("%s%cB", fmt.Sprintf(f, math.Max(0, nn)), unit)
}

type progressWriter struct {
	TotalBytes       int64
	bytesWritten     int64
	lastBytesWritten int64
	lastTime         time.Time
}

func (w *progressWriter) Write(p []byte) (n int, err error) {
	n = len(p)
	w.bytesWritten += int64(n)
	return
}

func (w *progressWriter) Progress(done <-chan struct{}, d time.Duration) {
	stop := false
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

func (w *progressWriter) print(last bool) {
	totalPerc := ""
	if w.TotalBytes != 0 {
		totalPerc = fmt.Sprintf("/%s (%.f%%)", formatSize(w.TotalBytes), float64(w.bytesWritten)/float64(w.TotalBytes)*100)
	}
	left := fmt.Sprintf("%s%s", formatSize(w.bytesWritten), totalPerc)
	right := fmt.Sprintf("%s/s", formatSize(int64(float64(w.bytesWritten-w.lastBytesWritten)/float64(time.Since(w.lastTime))/time.Nanosecond.Seconds())))
	width, _, _ := term.GetSize(int(os.Stderr.Fd()))
	f := fmt.Sprintf("\r%%-%ds%%s", width-len(right))
	printf(f, left, right)
	if last {
		printf("\n")
	}
}

var errDry = errors.New("dry run")

var dbg geheim.PrintFunc = func(version int, cipher geheim.Cipher, mode geheim.Mode, kdf geheim.KDF, mac geheim.MAC, md geheim.MD, sec int, pass, salt, iv, key []byte) error {
	if fVerbose {
		printf("%-8s%d\n", "VERSION", version)
		printf("%-8s%s(%d)\n", "CIPHER", geheim.CipherNames[cipher], cipher)
		if cipher == geheim.AES {
			printf("%-8s%s(%d)\n", "MODE", geheim.ModeNames[mode], mode)
		}
		printf("%-8s%s(%d)\n", "KDF", geheim.KDFNames[kdf], kdf)
		printf("%-8s%s(%d)\n", "MAC", geheim.MACNames[mac], mac)
		if kdf == geheim.PBKDF2 || mac == geheim.HMAC {
			printf("%-8s%s(%d)\n", "MD", geheim.MDNames[md], md)
		}
		iter, memory := geheim.GetSecIterMemory(sec)
		if kdf == geheim.PBKDF2 {
			printf("%-8s%d(%d)\n", "SEC", sec, iter)
		}
		if kdf == geheim.Argon2 || kdf == geheim.Scrypt {
			printf("%-8s%d(%s)\n", "SEC", sec, formatSize(int64(memory)))
		}
		printf("%-8s%s\n", "PASS", pass)
		printf("%-8s%x\n", "SALT", salt)
		printf("%-8s%x\n", "IV", iv)
		printf("%-8s%x\n", "KEY", key)
	}
	if fDry {
		return errDry
	}
	return nil
}

const progressDuration = time.Second

func wrapProgress(r io.Reader, total int64, progress bool) (wrapped io.Reader, done chan<- struct{}) {
	wrapped = r
	d := make(chan struct{})
	if progress {
		p := &progressWriter{TotalBytes: total}
		go p.Progress(d, progressDuration)
		wrapped = io.TeeReader(r, p)
		done = d
	}
	return
}

func doneProgress(done chan<- struct{}) {
	if done != nil {
		done <- struct{}{}
	}
}

func enc(in, out, sign *os.File, inbytes int64, pass []byte) (err error) {
	wrapped, done := wrapProgress(in, inbytes, fProgress)
	signed, err := geheim.Encrypt(wrapped, out, pass, geheim.Cipher(fCipher), geheim.Mode(fMode), geheim.KDF(fKDF), geheim.MAC(fMAC), geheim.MD(fMD), fSL, dbg)
	doneProgress(done)
	if err != nil {
		return
	}
	if fVerbose {
		printf("%-8s%x\n", "SIGNED", signed)
	}
	if sign != nil {
		_, err = sign.Write(signed)
	}
	return
}

func dec(in, out, sign *os.File, inbytes int64, pass []byte) (err error) {
	var signex []byte
	if sign != nil {
		signex, err = io.ReadAll(sign)
		if err != nil {
			return
		}
		if fVerbose {
			printf("%-8s%x\n", "SIGNEX", signex)
		}
	}
	wrapped, done := wrapProgress(in, inbytes, fProgress)
	signed, err := geheim.DecryptVerify(wrapped, out, pass, signex, dbg)
	doneProgress(done)
	if err != nil && !errors.Is(err, geheim.ErrSigVer) {
		return
	}
	if fVerbose {
		printf("%-8s%x\n", "SIGNED", signed)
	}
	return
}

func main() {
	flag.Usage = func() {
		printf("usage: %s [option]...\noptions:\n", app)
		flag.PrintDefaults()
	}
	flag.StringVar(&fIn, "i", "", "input `path` (default `stdin`)")
	flag.StringVar(&fOut, "o", "", "output `path` (default `stdout`)")
	flag.StringVar(&fSign, "s", "", "signature `path`")
	flag.StringVar(&fPass, "p", "", "`passcode`")
	flag.BoolVar(&fOverwrite, "f", false, "allow overwrite to existing destination")
	flag.BoolVar(&fDecrypt, "d", false, "decrypt")
	flag.BoolVar(&fVerbose, "v", false, "verbose")
	flag.BoolVar(&fProgress, "P", false, "show progress")
	flag.BoolVar(&fVersion, "V", false, "print version")
	flag.BoolVar(&fDry, "j", false, "dry run")
	flag.IntVar(&fGen, "G", 0, "generate random string of `length`")
	flag.IntVar(&fCipher, "c", int(geheim.DefaultCipher),
		fmt.Sprintf("[enc] %s (%s)", geheim.CipherDesc, geheim.GetCipherString()),
	)
	flag.IntVar(&fMode, "m", int(geheim.DefaultMode),
		fmt.Sprintf("[enc] %s (%s)", geheim.ModeDesc, geheim.GetModeString()),
	)
	flag.IntVar(&fKDF, "k", int(geheim.DefaultKDF),
		fmt.Sprintf("[enc] %s (%s)", geheim.KDFDesc, geheim.GetKDFString()),
	)
	flag.IntVar(&fMAC, "a", int(geheim.DefaultMAC),
		fmt.Sprintf("[enc] %s (%s)", geheim.MACDesc, geheim.GetMACString()),
	)
	flag.IntVar(&fMD, "h", int(geheim.DefaultMD),
		fmt.Sprintf("[enc] %s (%s)", geheim.MDDesc, geheim.GetMDString()),
	)
	flag.IntVar(&fSL, "e", geheim.DefaultSec,
		fmt.Sprintf("[enc] %s (%d~%d)", geheim.SecDesc, geheim.MinSec, geheim.MaxSec),
	)
	if len(os.Args) <= 1 {
		flag.Usage()
		return
	}
	flag.Parse()
	if flag.NArg() != 0 {
		flag.Usage()
		return
	}
	if fVersion {
		printf("%s [%s] %s (%s)\n", app, runtime.GOARCH, gitTag, gitRev)
		return
	}
	flags := flagsSet()
	if flags["G"] && fGen > 0 {
		if s, err := geheim.RandASCIIString(fGen); check(err) {
			return
		} else {
			fmt.Print(s)
		}
		return
	}
	if !fDecrypt {
		if check(geheim.ValidateConfig(geheim.Cipher(fCipher), geheim.Mode(fMode), geheim.KDF(fKDF), geheim.MAC(fMAC), geheim.MD(fMD), fSL)) {
			return
		}
	}
	in, out, sign, inbytes, err := getIO(flags["i"], flags["o"], flags["s"])
	if check(err) {
		return
	}
	defer (func() {
		errs := []error{in.Close(), out.Close()}
		if sign != nil {
			errs = append(errs, sign.Close())
		}
		check(errs...)
	})()
	pass, err := getPass(flags["p"])
	if check(err) {
		return
	}
	if fDecrypt {
		err = dec(in, out, sign, inbytes, pass)
	} else {
		err = enc(in, out, sign, inbytes, pass)
	}
	check(err)
}
