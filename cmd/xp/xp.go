package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/jamesliu96/geheim/xp"
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

func fatalf(err error) {
	printf("%s\n", err)
	os.Exit(1)
}

func usage() {
	printf(
		"%s %s (%s)\nusage: %s %s                  # pair\n       %s %s <scalar> [point] # mult\n",
		app, gitTag, gitRev, app, p, app, x,
	)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}
	directive := os.Args[1]
	if directive == p {
		priv, pub, err := xp.P()
		if err != nil {
			fatalf(err)
		}
		fmt.Printf("%-4s %s\n%-4s %s\n", "priv", hex.EncodeToString(priv), "pub", hex.EncodeToString(pub))
	} else if directive == x {
		if len(os.Args) < 3 {
			usage()
			return
		}
		scalar, err := hex.DecodeString(os.Args[2])
		if err != nil {
			fatalf(err)
		}
		var point []byte
		if len(os.Args) > 3 {
			if point, err = hex.DecodeString(os.Args[3]); err != nil {
				fatalf(err)
			}
		}
		product, err := xp.X(scalar, point)
		if err != nil {
			fatalf(err)
		}
		fmt.Println(hex.EncodeToString(product))
	} else {
		usage()
	}
}
