package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/jamesliu96/geheim"
	"golang.org/x/term"
)

var app = "ghm"

var gitTag = "*"
var gitRev = "*"

var (
	fDecrypt   bool
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
)

func flagsSet() (inSet, outSet, signSet, passSet bool) {
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "in" {
			inSet = true
		}
		if f.Name == "out" {
			outSet = true
		}
		if f.Name == "s" {
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

func getPass(passSet bool) ([]byte, error) {
	if passSet {
		return []byte(fPass), nil
	}
	stdinFd := int(os.Stdin.Fd())
	printfStderr("enter passphrase: ")
	bPass, err := term.ReadPassword(stdinFd)
	if err != nil {
		return nil, err
	}
	printfStderr("\n")
	if string(bPass) == "" {
		return nil, errors.New("empty passphrase")
	}
	if !fDecrypt {
		printfStderr("verify passphrase: ")
		bvPass, err := term.ReadPassword(stdinFd)
		if err != nil {
			return nil, err
		}
		printfStderr("\n")
		if string(bPass) != string(bvPass) {
			return nil, errors.New("passphrase verification failed")
		}
	}
	return bPass, nil
}

func dbg(mode geheim.Mode, md geheim.Md, keyIter int, salt, iv, key []byte) (err error) {
	if !fVerbose {
		return
	}
	printfStderr("Mode\t%s(%d)\n", geheim.ModeNames[mode], mode)
	printfStderr("Md\t%s(%d)\n", geheim.MdNames[md], md)
	printfStderr("KeyIter\t%d\n", keyIter)
	printfStderr("Salt\t%x\n", salt)
	printfStderr("IV\t%x\n", iv)
	printfStderr("Key\t%x\n", key)
	return
}

func printUsage() {
	printfStderr("usage of %s:\n", app)
	flag.PrintDefaults()
}

func enc(in, out, signOut *os.File, pass []byte) (err error) {
	mode := geheim.Mode(fMode)
	md := geheim.Md(fMd)
	keyIter := fKeyIter
	sign, err := geheim.Encrypt(in, out, pass, mode, md, keyIter, dbg)
	if err != nil {
		return
	}
	if fVerbose {
		printfStderr("Sign\t%x\n", sign)
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
		if fVerbose {
			printfStderr("VSign\t%x\n", vSign)
		}
	}
	decrypter, err := geheim.NewDecrypter(in, out, pass, vSign, dbg)
	if err != nil {
		return
	}
	sign, err := decrypter.Decrypt()
	if err != nil {
		return
	}
	if fVerbose {
		printfStderr("Sign\t%x\n", sign)
	}
	return
}

func main() {
	flag.StringVar(&fIn, "in", "", "`input` path (default: `stdin`)")
	flag.StringVar(&fOut, "out", "", "`output` path (default: `stdout`)")
	flag.StringVar(&fSign, "s", "", "`signature` path (bypass if omitted)")
	flag.StringVar(&fPass, "pass", "", "`passphrase` (must be specified if `stdin` is used as input)")
	flag.BoolVar(&fOverwrite, "y", false, "allow overwrite to existing file")
	flag.BoolVar(&fDecrypt, "d", false, "decrypt (encrypt if omitted)")
	flag.BoolVar(&fVerbose, "v", false, "verbose")
	flag.BoolVar(&fVersion, "V", false, "print version")
	flag.IntVar(&fMode, "m", int(geheim.DMode),
		fmt.Sprintf("[encryption] cipher block mode (%s)", geheim.GetModeString()),
	)
	flag.IntVar(&fMd, "md", int(geheim.DMd),
		fmt.Sprintf("[encryption] message digest (%s)", geheim.GetMdString()),
	)
	flag.IntVar(&fKeyIter, "iter", geheim.DKeyIter,
		fmt.Sprintf("[encryption] key iteration (minimum %d)", geheim.DKeyIter),
	)
	if len(os.Args) <= 1 {
		printUsage()
		return
	}
	flag.Parse()
	if flag.NArg() != 0 {
		printUsage()
		return
	}
	if fVersion {
		printfStderr("%s %s (%s)\n", app, gitTag, gitRev)
		return
	}
	if !fDecrypt {
		if checkErr(geheim.ValidateConfigs(fMode, fMd, fKeyIter)) {
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
		if checkErr(in.Close(), out.Close()) {
			return
		}
		if sign != nil {
			if checkErr(sign.Close()) {
				return
			}
		}
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
