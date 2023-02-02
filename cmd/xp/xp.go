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

const p = "p"
const x = "x"

func printf(format string, v ...any) {
	fmt.Fprintf(os.Stderr, format, v...)
}

func check(err error) {
	if err != nil {
		printf("error: %s\n", err)
		os.Exit(1)
	}
}

func usage() {
	printf("%s %s (%s)\nusage: %s %s                      # pair\n       %s %s <scalar> [point]     # mult\n       %s %s > priv.key           # privkey\n       %s %s < priv.key > pub.key # pubkey\n", app, gitTag, gitRev, app, p, app, x, app, p, app, x)
	os.Exit(0)
}

func isTerminal(file *os.File) bool {
	if runtime.GOOS == "js" {
		return true
	}
	return term.IsTerminal(int(file.Fd()))
}

var stdoutTerm = isTerminal(os.Stdout)
var stdinTerm = isTerminal(os.Stdin)

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
			fmt.Printf("priv %x\npub  %x\n", priv, pub)
		} else {
			os.Stdout.Write(priv)
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
		} else {
			scalar, err = io.ReadAll(os.Stdin)
		}
		check(err)
		if stdinTerm {
			if argc > 3 {
				point, err = hex.DecodeString(os.Args[3])
			}
		}
		check(err)
		product, err := xp.X(scalar, point)
		check(err)
		if stdoutTerm {
			fmt.Printf("%x\n", product)
		} else {
			os.Stdout.Write(product)
		}
	default:
		usage()
	}
}
