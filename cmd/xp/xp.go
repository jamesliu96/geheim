package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/jamesliu96/geheim/xp"
	"golang.org/x/term"
)

const app = "xp"

var (
	gitTag = "*"
	gitRev = "*"
)

func printf(format string, a ...any) { fmt.Fprintf(os.Stderr, format, a...) }

func check(err error) {
	if err != nil {
		printf("error: %s\n", err)
		os.Exit(1)
	}
}

const p = "p"
const x = "x"

func usage() {
	printf(`%s %s (%s)
usage: %s %s                  # pair
       %s %s <scalar> [point] # mult
`, app, gitTag, gitRev, app, p, app, x)
	os.Exit(0)
}

func isTerminal(file *os.File) bool {
	if runtime.GOOS == "js" {
		return true
	}
	return term.IsTerminal(int(file.Fd()))
}

var (
	stdoutTerm = isTerminal(os.Stdout)
	stdinTerm  = isTerminal(os.Stdin)
)

func main() {
	argc := len(os.Args)
	if argc < 2 {
		usage()
	}
	switch os.Args[1] {
	case p:
		priv, pub, err := xp.P()
		check(err)
		if stdoutTerm {
			fmt.Printf("%-5s%x\n%-5s%x\n", "priv", priv, "pub", pub)
		} else {
			os.Stdout.Write(priv)
			printf("%-5s%x\n%-5s%x\n", "priv", priv, "pub", pub)
		}
	case x:
		var scalar []byte
		var point []byte
		var err error
		if stdinTerm {
			if argc < 3 {
				usage()
			}
			scalar, err = hex.DecodeString(os.Args[2])
			check(err)
			if argc > 3 {
				point, err = hex.DecodeString(os.Args[3])
				check(err)
			}
		} else {
			scalar, err = io.ReadAll(os.Stdin)
			check(err)
			if argc > 2 {
				point, err = hex.DecodeString(os.Args[2])
				check(err)
			}
		}
		product, err := xp.X(scalar, point)
		check(err)
		if stdoutTerm {
			fmt.Printf("%x\n", product)
		} else {
			os.Stdout.Write(product)
			printf("%x\n", product)
		}
	default:
		usage()
	}
}
