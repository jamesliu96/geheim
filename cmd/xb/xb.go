package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"os"
)

const app = "xb"

var (
	gitTag = "*"
	gitRev = "*"
)

const b = "b"
const x = "x"

func usage() {
	fmt.Fprintf(os.Stderr, "%s %s (%s)\nusage: %s %s # bin => hex\n       %s %s # hex => bin\n", app, gitTag, gitRev[:int(math.Min(float64(len(gitRev)), 7))], app, b, app, x)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}
	directive := os.Args[1]
	if directive == b {
		if _, err := io.Copy(hex.NewEncoder(os.Stdout), os.Stdin); err != nil {
			panic(err)
		}
	} else if directive == x {
		if _, err := io.Copy(os.Stdout, hex.NewDecoder(os.Stdin)); err != nil {
			panic(err)
		}
		return
	} else {
		usage()
	}
}
