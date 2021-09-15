package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/jamesliu96/geheim"
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
		printfStderr("Input   %s\n", in.Name())
		printfStderr("Output  %s\n", out.Name())
	}
	return
}

var errDry = errors.New("dry run")

var dbg geheim.PrintFunc = func(version int, cipher geheim.Cipher, mode geheim.Mode, kdf geheim.KDF, mac geheim.MAC, md geheim.MD, sec int, salt, iv, key []byte) error {
	if fVerbose {
		printfStderr("Version %d\n", version)
		printfStderr("Cipher  %s(%d)\n", geheim.CipherNames[cipher], cipher)
		if cipher == geheim.AES {
			printfStderr("Mode    %s(%d)\n", geheim.ModeNames[mode], mode)
		}
		printfStderr("KDF     %s(%d)\n", geheim.KDFNames[kdf], kdf)
		printfStderr("MAC     %s(%d)\n", geheim.MACNames[mac], mac)
		if kdf == geheim.PBKDF2 || mac == geheim.HMAC {
			printfStderr("MD      %s(%d)\n", geheim.MDNames[md], md)
		}
		printfStderr("Sec     %d\n", sec)
		printfStderr("Salt    %x\n", salt)
		printfStderr("IV      %x\n", iv)
		printfStderr("Key     %x\n", key)
	}
	if fDry {
		return errDry
	}
	return nil
}

func enc(in, out, signOut *os.File, pass []byte) (err error) {
	sign, err := geheim.Encrypt(in, out, pass, geheim.Cipher(fCipher), geheim.Mode(fMode), geheim.KDF(fKDF), geheim.MAC(fMAC), geheim.MD(fMD), fSL, dbg)
	if fVerbose {
		if sign != nil {
			printfStderr("Sign    %x\n", sign)
		}
	}
	if err != nil {
		return
	}
	if signOut != nil {
		_, err = signOut.Write(sign)
	}
	return
}

func dec(in, out, signIn *os.File, pass []byte) (err error) {
	var eSign []byte
	if signIn != nil {
		eSign, err = io.ReadAll(signIn)
		if err != nil {
			return
		}
	}
	sign, err := geheim.DecryptVerify(in, out, pass, dbg, eSign)
	if fVerbose {
		if eSign != nil {
			printfStderr("ESign   %x\n", eSign)
		}
		if sign != nil {
			printfStderr("Sign    %x\n", sign)
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
		fmt.Sprintf("[encrypt] cipher (%s)", geheim.GetCipherString()),
	)
	flag.IntVar(&fMode, "m", int(geheim.DefaultMode),
		fmt.Sprintf("[encrypt] stream mode (%s)", geheim.GetModeString()),
	)
	flag.IntVar(&fKDF, "k", int(geheim.DefaultKDF),
		fmt.Sprintf("[encrypt] key derivation function (%s)", geheim.GetKDFString()),
	)
	flag.IntVar(&fMAC, "a", int(geheim.DefaultMAC),
		fmt.Sprintf("[encrypt] message authentication (%s)", geheim.GetMACString()),
	)
	flag.IntVar(&fMD, "h", int(geheim.DefaultMD),
		fmt.Sprintf("[encrypt] message digest (%s)", geheim.GetMDString()),
	)
	flag.IntVar(&fSL, "e", geheim.MinSec,
		fmt.Sprintf("[encrypt] security level (%d~%d)", geheim.MinSec, geheim.MaxSec),
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
