package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/jamesliu96/geheim/sv"
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

const (
	p = "p"
	x = "x"
	g = "g"
	s = "s"
	v = "v"
)

func usage() {
	printf(`%s %s (%s)
usage: %s %s                                            # dh pair
       %s %s > private.key                              # dh pair
       %s %s <scalar_hex> [point_hex]                   # dh exchange
       %s %s [point_hex] < scalar.key                   # dh exchange
       %s %s                                            # dsa pair
       %s %s > private.key                              # dsa pair
       %s %s <message_bin> <private_hex>                # dsa sign
       %s %s <message_bin> < private.key                # dsa sign
       %s %s <message_bin> <public_hex> <signature_hex> # dsa verify
       %s %s <message_bin> <signature_hex> < public.key # dsa verify
`, app, gitTag, gitRev, app, p, app, p, app, x, app, x, app, g, app, g, app, s, app, s, app, v, app, v)
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
		private, public, err := xp.P()
		check(err)
		if stdoutTerm {
			fmt.Printf("%-5s%x\n%-5s%x\n", "priv", private, "pub", public)
		} else {
			os.Stdout.Write(private)
			printf("%-5s%x\n%-5s%x\n", "priv", private, "pub", public)
		}
	case x:
		var (
			scalar, point []byte
			err           error
		)
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
			scalar = make([]byte, xp.Size)
			_, err = io.ReadFull(os.Stdin, scalar)
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
	case g:
		private, public, err := sv.G()
		check(err)
		if stdoutTerm {
			fmt.Printf("%-5s%x\n%-5s%x\n", "priv", private, "pub", public)
		} else {
			os.Stdout.Write(private)
			printf("%-5s%x\n%-5s%x\n", "priv", private, "pub", public)
		}
	case s:
		var (
			message, private []byte
			err              error
		)
		if stdinTerm {
			if argc < 4 {
				usage()
			}
			message = []byte(os.Args[2])
			private, err = hex.DecodeString(os.Args[3])
			check(err)
		} else {
			if argc < 3 {
				usage()
			}
			message = []byte(os.Args[2])
			private = make([]byte, sv.PrivateSize)
			_, err = io.ReadFull(os.Stdin, private)
			check(err)
		}
		signature, err := sv.S(message, private)
		check(err)
		if stdoutTerm {
			fmt.Printf("%x\n", signature)
		} else {
			os.Stdout.Write(signature)
			printf("%x\n", signature)
		}
	case v:
		var (
			message, public, signature []byte
			err                        error
		)
		if stdinTerm {
			if argc < 5 {
				usage()
			}
			message = []byte(os.Args[2])
			public, err = hex.DecodeString(os.Args[3])
			check(err)
			signature, err = hex.DecodeString(os.Args[4])
			check(err)
		} else {
			if argc < 4 {
				usage()
			}
			message = []byte(os.Args[2])
			public = make([]byte, sv.PublicSize)
			_, err = io.ReadFull(os.Stdin, public)
			check(err)
			signature, err = hex.DecodeString(os.Args[3])
			check(err)
		}
		err = sv.V(message, public, signature)
		check(err)
	default:
		usage()
	}
}
