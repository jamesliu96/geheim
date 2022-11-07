package main

import (
	"encoding/hex"
	"fmt"
	"math"
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

func usage() {
	fmt.Fprintf(os.Stderr, "%s %s (%s)\nusage: %s %s                  # pair\n       %s %s <scalar> [point] # mult\n", app, gitTag, gitRev[:int(math.Min(float64(len(gitRev)), 7))], app, p, app, x)
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
			panic(err)
		}
		fmt.Printf("%-4s %s\n%-4s %s\n", "priv", hex.EncodeToString(priv), "pub", hex.EncodeToString(pub))
	} else if directive == x {
		if len(os.Args) < 3 {
			usage()
			return
		}
		scalar, err := hex.DecodeString(os.Args[2])
		if err != nil {
			panic(err)
		}
		var point []byte
		if len(os.Args) > 3 {
			if point, err = hex.DecodeString(os.Args[3]); err != nil {
				panic(err)
			}
		}
		product, err := xp.X(scalar, point)
		if err != nil {
			panic(err)
		}
		fmt.Println(hex.EncodeToString(product))
	} else {
		usage()
	}
}
