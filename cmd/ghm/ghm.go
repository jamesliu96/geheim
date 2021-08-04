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

func checkFlags() {
	if err := geheim.CheckConfig(fMode, fKeyMd, fKeyIter); err != nil {
		panic(err)
	}
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
		checkFlags()
	}
	input, output := getIO(inSet, outSet)
	defer (func() {
		if err := input.Close(); err != nil {
			panic(err)
		}
		if err := output.Close(); err != nil {
			panic(err)
		}
	})()
	if !passSet && input == os.Stdin {
		panic(errors.New("password must be specified if stdin is used as input"))
	}
	pass := getPass()
	if fDecrypt {
		dec(input, output, pass)
	} else {
		enc(input, output, pass)
	}
}

func getIO(inSet, outSet bool) (input, output *os.File) {
	if inSet {
		file, err := os.Open(fInput)
		if err != nil {
			panic(err)
		}
		if fi, err := file.Stat(); err != nil {
			panic(err)
		} else if !fi.Mode().IsRegular() {
			panic(errors.New("input file is not regular"))
		}
		input = file
	} else {
		input = os.Stdin
	}
	if outSet {
		if !fOverwrite {
			if _, err := os.Stat(fOutput); err == nil {
				panic(errors.New("output exists, use `-y` to overwrite"))
			}
		}
		file, err := os.Create(fOutput)
		if err != nil {
			panic(err)
		}
		output = file
	} else {
		output = os.Stdout
	}
	return
}

func printfStderr(format string, v ...interface{}) {
	fmt.Fprintf(os.Stderr, format, v...)
}

func getPass() []byte {
	if fPass != "" {
		return []byte(fPass)
	}
	stdinFd := int(os.Stdin.Fd())
	printfStderr("enter password: ")
	bPass, err := term.ReadPassword(stdinFd)
	if err != nil {
		panic(err)
	}
	printfStderr("\n")
	if string(bPass) == "" {
		panic(errors.New("empty password"))
	}
	if fDecrypt {
		return bPass
	}
	printfStderr("verify password: ")
	bvPass, err := term.ReadPassword(stdinFd)
	if err != nil {
		panic(err)
	}
	printfStderr("\n")
	if string(bPass) != string(bvPass) {
		panic(errors.New("password verification failed"))
	}
	return bPass
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

func enc(input io.Reader, output io.Writer, pass []byte) {
	mode := uint16(fMode)
	keyMd := uint16(fKeyMd)
	keyIter := fKeyIter
	geheim.Enc(input, output, pass, mode, keyMd, keyIter, dbg)
}

func dec(input io.Reader, output io.Writer, pass []byte) {
	geheim.Dec(input, output, pass, dbg)
}
