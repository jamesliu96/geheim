package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/jamesliu96/geheim"
	"golang.org/x/sys/cpu"
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
	fSignHex   string
	fPass      string
	fOverwrite bool
	fVerbose   bool
	fProgress  bool
	fVersion   bool
	fDry       bool
	fGen       int
)

func registerFlags() {
	flag.BoolVar(&fVersion, "V", false, "print version")
	flag.BoolVar(&fProgress, "P", false, "show progress")
	flag.IntVar(&fGen, "G", 0, "generate random string of `length`")
	flag.StringVar(&fIn, "i", os.Stdin.Name(), "input `path`")
	flag.StringVar(&fOut, "o", os.Stdout.Name(), "output `path`")
	flag.StringVar(&fSign, "s", "", "signature `path`")
	flag.StringVar(&fSignHex, "x", "", "[dec] signature `hex`")
	flag.StringVar(&fPass, "p", "", "`passcode`")
	flag.BoolVar(&fOverwrite, "f", false, "allow overwrite to existing destination")
	flag.BoolVar(&fDecrypt, "d", false, "decrypt")
	flag.BoolVar(&fVerbose, "v", false, "verbose")
	flag.BoolVar(&fDry, "j", false, "dry run")
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
}

var flags = map[string]bool{}

func setFlags(flags map[string]bool) {
	flag.Visit(func(f *flag.Flag) {
		flags[f.Name] = true
	})
}

func printf(format string, v ...interface{}) {
	fmt.Fprintf(os.Stderr, format, v...)
}

var errDry = errors.New("dry run")

var excludes = []error{errDry}

func contains(slice []error, item error) bool {
	for _, value := range slice {
		if value == item {
			return true
		}
	}
	return false
}

func check(errs ...error) (goterr bool) {
	for _, err := range errs {
		if err != nil && !contains(excludes, err) {
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
	for {
		if err := readPass(&pass, "enter passcode: "); err != nil {
			return nil, err
		}
		if !fDecrypt {
			var vpass []byte
			if err := readPass(&vpass, "confirm passcode: "); err != nil {
				return nil, err
			}
			if !bytes.Equal(pass, vpass) {
				pass = nil
				continue
			}
		}
		break
	}
	return pass, nil
}

func checkTerminal(fds ...uintptr) error {
	for _, fd := range fds {
		if term.IsTerminal(int(fd)) {
			return errors.New("invalid terminal i/o")
		}
	}
	return nil
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
				err = fmt.Errorf("input file \"%s\" is a directory", fi.Name())
				return
			}
			inbytes = fi.Size()
		}
	} else {
		in = os.Stdin
	}
	if outset {
		if !fOverwrite {
			if fi, e := os.Stat(fOut); e == nil {
				err = fmt.Errorf("output file \"%s\" exists, use -f to overwrite", fi.Name())
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
	fds := []uintptr{in.Fd(), out.Fd()}
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
				err = fmt.Errorf("signature file \"%s\" is a directory", fi.Name())
				return
			}
		} else {
			if !fOverwrite {
				if fi, e := os.Stat(fSign); e == nil {
					err = fmt.Errorf("signature file \"%s\" exists, use -f to overwrite", fi.Name())
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
		fds = append(fds, sign.Fd())
	}
	err = checkTerminal(fds...)
	return
}

func getCPUFeatures() (d []string) {
	var v interface{}
	switch runtime.GOARCH {
	case "386":
		fallthrough
	case "amd64":
		v = cpu.X86
	case "arm":
		v = cpu.ARM
	case "arm64":
		v = cpu.ARM64
	case "mips64":
		fallthrough
	case "mips64le":
		v = cpu.MIPS64X
	case "ppc64":
		fallthrough
	case "ppc64le":
		v = cpu.PPC64
	case "s390x":
		v = cpu.S390X
	default:
		return
	}
	ks := reflect.TypeOf(v)
	vs := reflect.ValueOf(v)
	for i := 0; i < ks.NumField(); i++ {
		k := ks.Field(i)
		v := vs.Field(i)
		if k.Type.Kind() == reflect.Bool && v.Bool() {
			name := strings.TrimPrefix(k.Name, "Has")
			if name == k.Name {
				name = strings.TrimPrefix(k.Name, "Is")
			}
			d = append(d, name)
		}
	}
	return
}

func formatSize(n int64) string {
	unit := ""
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
	newline := ""
	if last {
		newline = "\n"
	}
	f := fmt.Sprintf("\r%%-%ds%%s%s", width-len(right), newline)
	printf(f, left, right)
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
		} else {
			printf("%-8s%d(%s)\n", "SEC", sec, formatSize(int64(memory)))
		}
		printf("%-8s%s(%x)\n", "PASS", pass, pass)
		printf("%-8s%x\n", "SALT", salt)
		printf("%-8s%x\n", "IV", iv)
		printf("%-8s%x\n", "KEY", key)
	}
	if fDry {
		return errDry
	}
	return nil
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
	} else if flags["x"] {
		signex, err = hex.DecodeString(fSignHex)
		if err != nil {
			return
		}
	}
	if signex != nil {
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
	registerFlags()
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
		if fVerbose {
			printf("%s [%s-%s] %s (%s) %s\n", app, runtime.GOOS, runtime.GOARCH, gitTag, gitRev, getCPUFeatures())
		} else {
			printf("%s %s (%s)\n", app, gitTag, gitRev[:int(math.Min((float64(len(gitRev))), 7))])
		}
		return
	}
	setFlags(flags)
	if fGen > 0 {
		if s, err := geheim.RandASCIIString(fGen); !check(err) {
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
