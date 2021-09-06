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
	fKDF       int
	fMode      int
	fMd        int
	fKeyIter   int
	fIn        string
	fOut       string
	fSign      string
	fPass      string
	fOverwrite bool
	fVerbose   bool
	fVersion   bool
	fGen       int
)

func flagsSet() (inSet, outSet, signSet, passSet bool) {
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "in" {
			inSet = true
		}
		if f.Name == "out" {
			outSet = true
		}
		if f.Name == "sign" {
			signSet = true
		}
		if f.Name == "pass" {
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
		if err != nil {
			printfStderr("error: %s\n", err)
			os.Exit(1)
			gotErr = true
		}
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
		} else if !fi.Mode().IsRegular() {
			err = fmt.Errorf("input file `%s` is not regular", fIn)
			return
		}
	} else {
		in = os.Stdin
	}
	if outSet {
		if !fOverwrite {
			if _, e := os.Stat(fOut); e == nil {
				err = fmt.Errorf("output file `%s` exists, use -y to overwrite", fOut)
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
			} else if !fi.Mode().IsRegular() {
				err = fmt.Errorf("signature file `%s` is not regular", fSign)
				return
			}
		} else {
			if !fOverwrite {
				if _, e := os.Stat(fSign); e == nil {
					err = fmt.Errorf("signature file `%s` exists, use -y to overwrite", fSign)
					return
				}
			}
			sign, err = os.Create(fSign)
		}
	}
	return
}

func dbg(cipher geheim.Cipher, kdf geheim.KDF, mode geheim.Mode, md geheim.Md, keyIter int, salt, iv, key []byte) {
	if fVerbose {
		printfStderr("Cipher\t%s(%d)\n", geheim.CipherNames[cipher], cipher)
		printfStderr("KDF\t%s(%d)\n", geheim.KDFNames[kdf], kdf)
		printfStderr("Mode\t%s(%d)\n", geheim.ModeNames[mode], mode)
		printfStderr("Md\t%s(%d)\n", geheim.MdNames[md], md)
		printfStderr("KeyIter\t%d\n", keyIter)
		printfStderr("Salt\t%x\n", salt)
		printfStderr("IV\t%x\n", iv)
		printfStderr("Key\t%x\n", key)
	}
}

func enc(in, out, signOut *os.File, pass []byte) (err error) {
	sign, err := geheim.Encrypt(in, out, pass, geheim.Cipher(fCipher), geheim.KDF(fKDF), geheim.Mode(fMode), geheim.Md(fMd), fKeyIter, dbg)
	if fVerbose {
		if sign != nil {
			printfStderr("Sign\t%x\n", sign)
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
	var vSign []byte
	if signIn != nil {
		vSign, err = io.ReadAll(signIn)
		if err != nil {
			return
		}
	}
	sign, err := geheim.DecryptVerify(in, out, pass, dbg, vSign)
	if fVerbose {
		if vSign != nil {
			printfStderr("VSign\t%x\n", vSign)
		}
		if sign != nil {
			printfStderr("Sign\t%x\n", sign)
		}
	}
	return
}

func main() {
	flag.Usage = func() {
		printfStderr("Usage: %s [OPTION]...\nOptions:\n", app)
		flag.PrintDefaults()
	}
	flag.StringVar(&fIn, "in", "", "input `path` (default `stdin`)")
	flag.StringVar(&fOut, "out", "", "output `path` (default `stdout`)")
	flag.StringVar(&fSign, "sign", "", "signature `path` (bypass if omitted)")
	flag.StringVar(&fPass, "pass", "", "passphrase `string` (must be specified if `stdin` is used as input)")
	flag.BoolVar(&fOverwrite, "f", false, "allow overwrite to existing file")
	flag.BoolVar(&fDecrypt, "d", false, "decrypt")
	flag.BoolVar(&fVerbose, "v", false, "verbose")
	flag.BoolVar(&fVersion, "V", false, "print version")
	flag.IntVar(&fGen, "G", 0, "generate random string of `length`")
	flag.IntVar(&fCipher, "c", int(geheim.DefaultCipher),
		fmt.Sprintf("[encrypt] cipher (%s)", geheim.GetCipherString()),
	)
	flag.IntVar(&fKDF, "k", int(geheim.DefaultKDF),
		fmt.Sprintf("[encrypt] key derivation function (%s)", geheim.GetKDFString()),
	)
	flag.IntVar(&fMode, "m", int(geheim.DefaultMode),
		fmt.Sprintf("[encrypt] cipher block mode (%s)", geheim.GetModeString()),
	)
	flag.IntVar(&fMd, "md", int(geheim.DefaultMd),
		fmt.Sprintf("[encrypt] message digest (%s)", geheim.GetMdString()),
	)
	flag.IntVar(&fKeyIter, "iter", geheim.DefaultKeyIter,
		fmt.Sprintf("[encrypt] key iteration (minimum %d)", geheim.DefaultKeyIter),
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
		if checkErr(geheim.ValidateConfig(geheim.Cipher(fCipher), geheim.KDF(fKDF), geheim.Mode(fMode), geheim.Md(fMd), fKeyIter)) {
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
		checkErr(dec(in, out, sign, pass))
	} else {
		checkErr(enc(in, out, sign, pass))
	}
}
