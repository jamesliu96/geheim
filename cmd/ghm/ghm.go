package main

import (
	"encoding/hex"
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
	fKeyMd     int
	fKeyIter   int
	fInput     string
	fOutput    string
	fPass      string
	fOverwrite bool
	fVerbose   bool
)

func flagsSet() (inSet, outSet, passSet bool) {
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "in" {
			inSet = true
		}
		if f.Name == "out" {
			outSet = true
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

func getIO(inSet, outSet bool) (input, output *os.File, err error) {
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
				err = errors.New("output exists, use `-y` to overwrite")
				return
			}
		}
		output, err = os.Create(fOutput)
	} else {
		output = os.Stdout
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

func dbg(mode, keyMd uint16, keyIter int, salt, iv, key []byte) {
	if !fVerbose {
		return
	}
	printfStderr("Mode\t%d\n", mode)
	printfStderr("KeyMd\t%d\n", keyMd)
	printfStderr("KeyIter\t%d\n", keyIter)
	printfStderr("Salt\t%s\n", hex.EncodeToString(salt))
	printfStderr("IV\t%s\n", hex.EncodeToString(iv))
	printfStderr("Key\t%s\n", hex.EncodeToString(key))
}

func enc(input io.Reader, output io.Writer, pass []byte) error {
	mode := uint16(fMode)
	keyMd := uint16(fKeyMd)
	keyIter := fKeyIter
	return geheim.Enc(input, output, pass, mode, keyMd, keyIter, dbg)
}

func dec(input io.Reader, output io.Writer, pass []byte) error {
	return geheim.Dec(input, output, pass, dbg)
}

func main() {
	flag.BoolVar(&fDecrypt, "d", false, "decrypt (encrypt if not set)")
	flag.StringVar(&fInput, "in", "", "input path (default `stdin`)")
	flag.StringVar(&fOutput, "out", "", "output path (default `stdout`)")
	flag.StringVar(&fPass, "pass", "", "password (must be specified if `stdin` is used as input)")
	flag.BoolVar(&fOverwrite, "y", false, "allow overwrite to existing file")
	flag.BoolVar(&fVerbose, "v", false, "verbose")
	flag.IntVar(&fMode, "m", int(geheim.DMode), "[encrypt] cipher mode (1:CTR, 2:CFB, 4:OFB)")
	flag.IntVar(&fKeyMd, "md", int(geheim.DKeyMd), "[encrypt] key message digest (1:SHA3-224, 2:SHA3-256, 4:SHA3-384, 8:SHA3-512)")
	flag.IntVar(&fKeyIter, "iter", geheim.DKeyIter, "[encrypt] key iteration (minimum 100000)")
	if len(os.Args) < 2 {
		flag.Usage()
		return
	}
	flag.Parse()
	inSet, outSet, passSet := flagsSet()
	if !fDecrypt {
		if checkErr(geheim.CheckConfig(fMode, fKeyMd, fKeyIter)) {
			return
		}
	}
	input, output, err := getIO(inSet, outSet)
	if checkErr(err) {
		return
	}
	defer (func() {
		errI := input.Close()
		errO := output.Close()
		checkErr(errI, errO)
	})()
	if !passSet && input == os.Stdin {
		if checkErr(errors.New("password must be specified if stdin is used as input")) {
			return
		}
	}
	pass, err := getPass()
	if checkErr(err) {
		return
	}
	if fDecrypt {
		checkErr(dec(input, output, pass))
	} else {
		checkErr(enc(input, output, pass))
	}
}
