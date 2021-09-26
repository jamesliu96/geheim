package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
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

func printfStderr(format string, v ...interface{}) {
	fmt.Fprintf(os.Stderr, format, v...)
}

func checkErr(errs ...error) (gotErr bool) {
	for _, err := range errs {
		if err != nil && !errors.Is(err, errDry) {
			printfStderr("error: %s\n", err)
			gotErr = true
		}
	}
	if gotErr {
		os.Exit(1)
	}
	return
}

func readPass(p *[]byte, question string) error {
	for len(*p) == 0 {
		printfStderr(question)
		password, err := term.ReadPassword(int(os.Stdin.Fd()))
		printfStderr("\n")
		if err != nil {
			return err
		}
		*p = password
	}
	return nil
}

func getPass(passSet bool) ([]byte, error) {
	if passSet {
		return []byte(fPass), nil
	}
	var pass []byte
	err := readPass(&pass, "enter passphrase: ")
	if err != nil {
		return nil, err
	}
	if !fDecrypt {
		var vpass []byte
		err := readPass(&vpass, "verify passphrase: ")
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(pass, vpass) {
			return nil, errors.New("passphrase verification failed")
		}
	}
	return pass, nil
}

func getIO(inSet, outSet, signSet bool) (in, out, sign *os.File, inSize int64, err error) {
	if inSet {
		in, err = os.Open(fIn)
		if err != nil {
			return
		}
		if fi, e := in.Stat(); e != nil {
			err = e
			return
		} else {
			inSize = fi.Size()
			if fi.IsDir() {
				err = fmt.Errorf("input file `%s` is a directory", fIn)
				return
			}
		}
	} else {
		in = os.Stdin
	}
	if outSet {
		if !fOverwrite {
			if _, e := os.Stat(fOut); e == nil {
				err = fmt.Errorf("output file `%s` exists, use -f to overwrite", fOut)
				return
			}
		}
		out, err = os.Create(fOut)
	} else {
		out = os.Stdout
	}
	if signSet {
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
		}
	}
	if fVerbose {
		printfStderr("%-8s%s\n", "INPUT", in.Name())
		printfStderr("%-8s%s\n", "OUTPUT", out.Name())
	}
	return
}

func formatSize(n int64) string {
	var unit byte
	nn := float64(n)
	f := "%.f"
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
	}
	if nn < 10 {
		f = "%.1f"
	}
	return fmt.Sprintf("%s%cB", fmt.Sprintf(f, nn), unit)
}

func now() int64 {
	return time.Now().UnixNano()
}

type progressWriter struct {
	TotalBytes       int64
	bytesWritten     int64
	lastBytesWritten int64
	lastTimeWritten  int64
}

func (w *progressWriter) Write(p []byte) (n int, err error) {
	n = len(p)
	w.bytesWritten += int64(n)
	return
}

func (w *progressWriter) Progress(done <-chan struct{}, d time.Duration) {
	stop := false
	for {
		n := now()
		select {
		case <-done:
			stop = true
		default:
			w.printProgress(false)
			w.lastBytesWritten = w.bytesWritten
			w.lastTimeWritten = now()
		}
		if stop {
			w.printProgress(true)
			break
		}
		time.Sleep(d - time.Duration(now()-n))
	}
}

func (w *progressWriter) printProgress(last bool) {
	printfStderr("\033[2K\r%s", formatSize(w.bytesWritten))
	if w.TotalBytes != 0 {
		printfStderr("/%s(%.f%%)", formatSize(w.TotalBytes), float64(w.bytesWritten)/float64(w.TotalBytes)*100)
	}
	printfStderr(" | %s/s", formatSize(int64(float64(w.bytesWritten-w.lastBytesWritten)/float64(now()-w.lastTimeWritten)/time.Nanosecond.Seconds())))
	if last {
		printfStderr("\n")
	}
}

var errDry = errors.New("dry run")

var dbg geheim.PrintFunc = func(version int, cipher geheim.Cipher, mode geheim.Mode, kdf geheim.KDF, mac geheim.MAC, md geheim.MD, sec int, pass, salt, iv, key []byte) error {
	if fVerbose {
		printfStderr("%-8s%d\n", "VERSION", version)
		printfStderr("%-8s%s(%d)\n", "CIPHER", geheim.CipherNames[cipher], cipher)
		if cipher == geheim.AES {
			printfStderr("%-8s%s(%d)\n", "MODE", geheim.ModeNames[mode], mode)
		}
		printfStderr("%-8s%s(%d)\n", "KDF", geheim.KDFNames[kdf], kdf)
		printfStderr("%-8s%s(%d)\n", "MAC", geheim.MACNames[mac], mac)
		if kdf == geheim.PBKDF2 || mac == geheim.HMAC {
			printfStderr("%-8s%s(%d)\n", "MD", geheim.MDNames[md], md)
		}
		iter, memory := geheim.GetSecIterMemory(sec)
		if kdf == geheim.PBKDF2 {
			printfStderr("%-8s%d(%d)\n", "SEC", sec, iter)
		}
		if kdf == geheim.Argon2 || kdf == geheim.Scrypt {
			printfStderr("%-8s%d(%s)\n", "SEC", sec, formatSize(int64(memory)))
		}
		printfStderr("%-8s%s\n", "PASS", pass)
		printfStderr("%-8s%x\n", "SALT", salt)
		printfStderr("%-8s%x\n", "IV", iv)
		printfStderr("%-8s%x\n", "KEY", key)
	}
	if fDry {
		return errDry
	}
	return nil
}

const progressDuration = time.Second

func enc(in, out, s *os.File, inSize int64, pass []byte) (err error) {
	done := make(chan struct{})
	var pin io.Reader = in
	if fProgress {
		p := &progressWriter{TotalBytes: inSize}
		pin = io.TeeReader(in, p)
		go p.Progress(done, progressDuration)
	}
	sign, err := geheim.Encrypt(pin, out, pass, geheim.Cipher(fCipher), geheim.Mode(fMode), geheim.KDF(fKDF), geheim.MAC(fMAC), geheim.MD(fMD), fSL, dbg)
	if fProgress {
		done <- struct{}{}
	}
	if fVerbose {
		if sign != nil {
			printfStderr("%-8s%x\n", "SIGN", sign)
		}
	}
	if err != nil {
		return
	}
	if s != nil {
		_, err = s.Write(sign)
	}
	return
}

func dec(in, out, s *os.File, inSize int64, pass []byte) (err error) {
	var esign []byte
	if s != nil {
		esign, err = io.ReadAll(s)
		if err != nil {
			return
		}
	}
	done := make(chan struct{})
	var pin io.Reader = in
	if fProgress {
		p := &progressWriter{TotalBytes: inSize}
		pin = io.TeeReader(in, p)
		go p.Progress(done, progressDuration)
	}
	sign, err := geheim.DecryptVerify(pin, out, pass, dbg, esign)
	if fProgress {
		done <- struct{}{}
	}
	if fVerbose {
		if esign != nil {
			printfStderr("%-8s%x\n", "ESIGN", esign)
		}
		if sign != nil {
			printfStderr("%-8s%x\n", "SIGN", sign)
		}
	}
	return
}

func main() {
	flag.Usage = func() {
		printfStderr("usage: %s [option]...\noptions:\n", app)
		flag.PrintDefaults()
	}
	flag.StringVar(&fIn, "i", "", "input `path` (default `stdin`)")
	flag.StringVar(&fOut, "o", "", "output `path` (default `stdout`)")
	flag.StringVar(&fSign, "s", "", "signature `path`")
	flag.StringVar(&fPass, "p", "", "`passphrase`")
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
		printfStderr("%s %s (%s)\n", app, gitTag, gitRev)
		return
	}
	flags := flagsSet()
	if flags["G"] && fGen > 0 {
		if s, err := geheim.RandASCIIString(fGen); checkErr(err) {
			return
		} else {
			fmt.Print(s)
		}
		return
	}
	if !fDecrypt {
		if checkErr(geheim.ValidateConfig(geheim.Cipher(fCipher), geheim.Mode(fMode), geheim.KDF(fKDF), geheim.MAC(fMAC), geheim.MD(fMD), fSL)) {
			return
		}
	}
	in, out, sign, inSize, err := getIO(flags["i"], flags["o"], flags["s"])
	if checkErr(err) {
		return
	}
	defer (func() {
		errs := []error{in.Close(), out.Close()}
		if sign != nil {
			errs = append(errs, sign.Close())
		}
		checkErr(errs...)
	})()
	pass, err := getPass(flags["p"])
	if checkErr(err) {
		return
	}
	if fDecrypt {
		err = dec(in, out, sign, inSize, pass)
	} else {
		err = enc(in, out, sign, inSize, pass)
	}
	checkErr(err)
}
