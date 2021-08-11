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

var (
	fDecrypt   bool
	fMode      int
	fMd        int
	fKeyIter   int
	fInput     string
	fOutput    string
	fSign      string
	fPass      string
	fOverwrite bool
	fVerbose   bool
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

func getIO(inSet, outSet, signSet bool) (input, output, sign *os.File, err error) {
	if inSet {
		input, err = os.Open(fInput)
		if err != nil {
			return
		}
		if fi, e := input.Stat(); e != nil {
			err = e
			return
		} else if !fi.Mode().IsRegular() {
			err = errors.New("input file is not regular")
			return
		}
	} else {
		input = os.Stdin
	}
	if outSet {
		if !fOverwrite {
			if _, e := os.Stat(fOutput); e == nil {
				err = errors.New("output file exists, use `-y` to overwrite")
				return
			}
		}
		output, err = os.Create(fOutput)
	} else {
		output = os.Stdout
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
				err = errors.New("sign file is not regular")
				return
			}
		} else {
			if !fOverwrite {
				if _, e := os.Stat(fSign); e == nil {
					err = errors.New("sign file exists, use `-y` to overwrite")
					return
				}
			}
			sign, err = os.Create(fSign)
		}
	}
	return
}

func getPass() ([]byte, error) {
	if fPass != "" {
		return []byte(fPass), nil
	}
	stdinFd := int(os.Stdin.Fd())
	printfStderr("enter password: ")
	bPass, err := term.ReadPassword(stdinFd)
	if err != nil {
		return nil, err
	}
	printfStderr("\n")
	if string(bPass) == "" {
		return nil, errors.New("empty password")
	}
	if !fDecrypt {
		printfStderr("verify password: ")
		bvPass, err := term.ReadPassword(stdinFd)
		if err != nil {
			return nil, err
		}
		printfStderr("\n")
		if string(bPass) != string(bvPass) {
			return nil, errors.New("password verification failed")
		}
	}
	return bPass, nil
}

func dbg(mode geheim.Mode, md geheim.Md, keyIter int, salt, iv, key []byte) {
	if !fVerbose {
		return
	}
	printfStderr("Mode\t%d\n", mode)
	printfStderr("Md\t%d\n", md)
	printfStderr("KeyIter\t%d\n", keyIter)
	printfStderr("Salt\t%x\n", salt)
	printfStderr("IV\t%x\n", iv)
	printfStderr("Key\t%x\n", key)
}

func enc(input, output, signOutput *os.File, pass []byte) (err error) {
	mode := geheim.Mode(fMode)
	md := geheim.Md(fMd)
	keyIter := fKeyIter
	sign, err := geheim.Encrypt(input, output, pass, mode, md, keyIter, dbg)
	if err != nil {
		return
	}
	if fVerbose {
		printfStderr("Sign\t%x\n", sign)
	}
	if signOutput != nil {
		_, err = signOutput.Write(sign)
	}
	return
}

func dec(input, output, signInput *os.File, pass []byte) error {
	sign, err := geheim.Decrypt(input, output, pass, dbg)
	if err != nil {
		return err
	}
	if fVerbose {
		printfStderr("Sign\t%x\n", sign)
	}
	if signInput != nil {
		eSign, err := io.ReadAll(signInput)
		if fVerbose {
			printfStderr("ESign\t%x\n", eSign)
		}
		if err != nil {
			return err
		}
		if !geheim.VerifySign(eSign, sign) {
			return errors.New("signature verification failed")
		}
	}
	return nil
}

func main() {
	flag.BoolVar(&fDecrypt, "d", false, "decrypt (encrypt if not set)")
	flag.StringVar(&fInput, "in", "", "input path (default `stdin`)")
	flag.StringVar(&fOutput, "out", "", "output path (default `stdout`)")
	flag.StringVar(&fSign, "s", "", "signature path (ignore if not set)")
	flag.StringVar(&fPass, "pass", "", "password (must be specified if `stdin` is used as input)")
	flag.BoolVar(&fOverwrite, "y", false, "allow overwrite to existing file")
	flag.BoolVar(&fVerbose, "v", false, "verbose")
	flag.IntVar(&fMode, "m", int(geheim.DMode), fmt.Sprintf("[encrypt] cipher block mode (%d:CTR, %d:CFB, %d:OFB)", geheim.ModeCTR, geheim.ModeCFB, geheim.ModeOFB))
	flag.IntVar(&fMd, "md", int(geheim.DMd), fmt.Sprintf("[encrypt] key message digest (%d:SHA3-224, %d:SHA3-256, %d:SHA3-384, %d:SHA3-512)", geheim.Sha3224, geheim.Sha3256, geheim.Sha3384, geheim.Sha3512))
	flag.IntVar(&fKeyIter, "iter", geheim.DKeyIter, fmt.Sprintf("[encrypt] key iteration (minimum %d)", geheim.DKeyIter))
	if len(os.Args) < 2 {
		flag.Usage()
		return
	}
	flag.Parse()
	inSet, outSet, signSet, passSet := flagsSet()
	if !fDecrypt {
		if checkErr(geheim.ValidateConfigs(fMode, fMd, fKeyIter)) {
			return
		}
	}
	input, output, sign, err := getIO(inSet, outSet, signSet)
	if checkErr(err) {
		return
	}
	defer (func() {
		if checkErr(input.Close(), output.Close()) {
			return
		}
		if sign != nil {
			if checkErr(sign.Close()) {
				return
			}
		}
	})()
	if !passSet && input == os.Stdin {
		if checkErr(errors.New("password must be specified if `stdin` is used as input")) {
			return
		}
	}
	pass, err := getPass()
	if checkErr(err) {
		return
	}
	if fDecrypt {
		checkErr(dec(input, output, sign, pass))
	} else {
		checkErr(enc(input, output, sign, pass))
	}
}
