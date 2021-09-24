package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

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
	fVersion   bool
	fDry       bool
	fGen       int
)

func flagsSet() (inSet, outSet, signSet, passSet bool) {
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "i" {
			inSet = true
		}
		if f.Name == "o" {
			outSet = true
		}
		if f.Name == "s" {
			signSet = true
		}
		if f.Name == "p" {
			passSet = true
		}
	})
	return
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

func getIO(inSet, outSet, signSet bool) (in, out, sign *os.File, err error) {
	if inSet {
		in, err = os.Open(fIn)
		if err != nil {
			return
		}
		if fi, e := in.Stat(); e != nil {
			err = e
			return
		} else if fi.IsDir() {
			err = fmt.Errorf("input file `%s` is a directory", fIn)
			return
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
	switch {
	case n >= 1<<60:
		n /= 1 << 60
		unit = 'E'
	case n >= 1<<50:
		n /= 1 << 50
		unit = 'P'
	case n >= 1<<40:
		n /= 1 << 40
		unit = 'T'
	case n >= 1<<30:
		n /= 1 << 30
		unit = 'G'
	case n >= 1<<20:
		n /= 1 << 20
		unit = 'M'
	case n >= 1<<10:
		n /= 1 << 10
		unit = 'K'
	}
	return fmt.Sprintf("%d%cB", n, unit)
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

func enc(in, out, s *os.File, pass []byte) (err error) {
	sign, err := geheim.Encrypt(in, out, pass, geheim.Cipher(fCipher), geheim.Mode(fMode), geheim.KDF(fKDF), geheim.MAC(fMAC), geheim.MD(fMD), fSL, dbg)
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

func dec(in, out, s *os.File, pass []byte) (err error) {
	var eSign []byte
	if s != nil {
		eSign, err = io.ReadAll(s)
		if err != nil {
			return
		}
	}
	sign, err := geheim.DecryptVerify(in, out, pass, dbg, eSign)
	if fVerbose {
		if eSign != nil {
			printfStderr("%-8s%x\n", "ESIGN", eSign)
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
	flag.StringVar(&fSign, "s", "", "signature `path` (bypass if omitted)")
	flag.StringVar(&fPass, "p", "", "`passphrase` (must be specified if `stdin` is used as input)")
	flag.BoolVar(&fOverwrite, "f", false, "allow overwrite to existing file")
	flag.BoolVar(&fDecrypt, "d", false, "decrypt")
	flag.BoolVar(&fVerbose, "v", false, "verbose")
	flag.BoolVar(&fVersion, "V", false, "print version")
	flag.BoolVar(&fDry, "j", false, "dry run")
	flag.IntVar(&fGen, "G", 0, "generate random string of `length`")
	flag.IntVar(&fCipher, "c", int(geheim.DefaultCipher),
		fmt.Sprintf("[encrypt] %s (%s)", geheim.CipherDesc, geheim.GetCipherString()),
	)
	flag.IntVar(&fMode, "m", int(geheim.DefaultMode),
		fmt.Sprintf("[encrypt] %s (%s)", geheim.ModeDesc, geheim.GetModeString()),
	)
	flag.IntVar(&fKDF, "k", int(geheim.DefaultKDF),
		fmt.Sprintf("[encrypt] %s (%s)", geheim.KDFDesc, geheim.GetKDFString()),
	)
	flag.IntVar(&fMAC, "a", int(geheim.DefaultMAC),
		fmt.Sprintf("[encrypt] %s (%s)", geheim.MACDesc, geheim.GetMACString()),
	)
	flag.IntVar(&fMD, "h", int(geheim.DefaultMD),
		fmt.Sprintf("[encrypt] %s (%s)", geheim.MDDesc, geheim.GetMDString()),
	)
	flag.IntVar(&fSL, "e", geheim.DefaultSec,
		fmt.Sprintf("[encrypt] %s (%d~%d)", geheim.SecDesc, geheim.MinSec, geheim.MaxSec),
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
	if fGen > 0 {
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
	inSet, outSet, signSet, passSet := flagsSet()
	if !passSet && !inSet {
		if checkErr(errors.New("passphrase must be specified if `stdin` is used as input")) {
			return
		}
	}
	in, out, sign, err := getIO(inSet, outSet, signSet)
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
	pass, err := getPass(passSet)
	if checkErr(err) {
		return
	}
	if fDecrypt {
		err = dec(in, out, sign, pass)
	} else {
		err = enc(in, out, sign, pass)
	}
	checkErr(err)
}
