package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/jamesliu96/geheim"
	"golang.org/x/sys/cpu"
	"golang.org/x/term"
)

const app = "ghm"

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

var (
	fDecrypt      = flag.Bool("d", false, "decrypt")
	fInput        = flag.String("i", os.Stdin.Name(), "input `path`")
	fOutput       = flag.String("o", os.Stdout.Name(), "output `path`")
	fKey          = flag.String("p", "", "`key`")
	fAuth         = flag.String("s", "", "authentication `path`")
	fVerAuthHex   = flag.String("x", "", "verify authentication `hex`")
	fOverwrite    = flag.Bool("f", false, "overwrite")
	fVerbose      = flag.Bool("v", false, "verbose")
	fProgress     = flag.Bool("P", false, "progress")
	fVersion      = flag.Bool("V", false, "version")
	fPrintAuthHex = flag.Bool("X", false, "print authentication hex")
	fArchive      = flag.Bool("z", false, "archive")

	fCipher = flag.Int("c", int(geheim.DefaultCipher), fmt.Sprintf("%s (%s)", geheim.CipherDesc, geheim.CipherString))
	fKDF    = flag.Int("k", int(geheim.DefaultKDF), fmt.Sprintf("%s (%s)", geheim.KDFDesc, geheim.KDFString))
	fHash   = flag.Int("h", int(geheim.DefaultHash), fmt.Sprintf("%s (%s)", geheim.HashDesc, geheim.HashString))
	fSec    = flag.Int("e", geheim.DefaultSec, fmt.Sprintf("%s (%s)", geheim.SecDesc, geheim.SecString))
)

var flags = make(map[string]bool)

func readKey(question string) (key []byte, err error) {
	for len(key) == 0 {
		printf("%s", question)
		key, err = term.ReadPassword(int(os.Stdin.Fd()))
		printf("\n")
		if err != nil {
			return
		}
	}
	return
}

func getKey() (key []byte, err error) {
	if flags["p"] {
		key = []byte(*fKey)
	} else {
		for {
			if key, err = readKey("enter key: "); err != nil {
				return
			}
			if !*fDecrypt {
				var vkey []byte
				if vkey, err = readKey("verify key: "); err != nil {
					return
				}
				if !bytes.Equal(key, vkey) {
					key = nil
					continue
				}
			}
			break
		}
	}
	return
}

func getIO() (inputFile, outputFile, authFile *os.File, size int64, err error) {
	if flags["i"] {
		if inputFile, err = os.Open(*fInput); err != nil {
			return
		}
		var fi fs.FileInfo
		if fi, err = inputFile.Stat(); err != nil {
			return
		}
		if fi.IsDir() {
			err = errors.New("ghm: input file is a directory")
			return
		}
		size = fi.Size()
	} else {
		inputFile = os.Stdin
	}
	if flags["o"] {
		if !*fOverwrite {
			if _, e := os.Stat(*fOutput); e == nil {
				err = errors.New("ghm: output file exists, use -f to overwrite")
				return
			}
		}
		if outputFile, err = os.Create(*fOutput); err != nil {
			return
		}
	} else {
		outputFile = os.Stdout
	}
	if flags["s"] {
		if *fDecrypt {
			if authFile, err = os.Open(*fAuth); err != nil {
				return
			}
			var fi fs.FileInfo
			if fi, err = authFile.Stat(); err != nil {
				return
			} else if fi.IsDir() {
				err = errors.New("ghm: authentication file is a directory")
				return
			}
		} else {
			if !*fOverwrite {
				if _, e := os.Stat(*fAuth); e == nil {
					err = errors.New("ghm: authentication file exists, use -f to overwrite")
					return
				}
			}
			if authFile, err = os.Create(*fAuth); err != nil {
				return
			}
		}
	}
	for _, file := range []*os.File{inputFile, outputFile, authFile} {
		if file != nil && term.IsTerminal(int(file.Fd())) {
			err = errors.New("ghm: invalid terminal i/o")
			break
		}
	}
	return
}

func cpuFeatures() (d []string) {
	var arch any
	switch runtime.GOARCH {
	case "386", "amd64":
		arch = cpu.X86
	case "arm":
		arch = cpu.ARM
	case "arm64":
		arch = cpu.ARM64
	case "mips64", "mips64le":
		arch = cpu.MIPS64X
	case "ppc64", "ppc64le":
		arch = cpu.PPC64
	case "s390x":
		arch = cpu.S390X
	default:
		return
	}
	ks := reflect.TypeOf(arch)
	vs := reflect.ValueOf(arch)
	for i := range ks.NumField() {
		k := ks.Field(i)
		v := vs.Field(i)
		if k.Type.Kind() == reflect.Bool && v.Bool() {
			name := strings.TrimPrefix(k.Name, "Has")
			if name == k.Name {
				name = strings.TrimPrefix(k.Name, "Is")
			}
			d = append(d, name)
		}
	}
	return
}

func main() {
	flag.Usage = func() {
		printf(`usage: %s [option]...
options:
`, app)
		flag.PrintDefaults()
		os.Exit(0)
	}
	if len(os.Args) < 2 {
		flag.Usage()
	}
	flag.Parse()
	flag.Visit(func(f *flag.Flag) { flags[f.Name] = true })
	if *fVersion {
		if *fVerbose {
			printf("%s [%s-%s] [%s] {%d} %s (%s) %s\n", app, runtime.GOOS, runtime.GOARCH, runtime.Version(), runtime.NumCPU(), gitTag, gitRev, cpuFeatures())
		} else {
			printf("%s %s (%s)\n", app, gitTag, gitRev)
		}
		os.Exit(0)
	}
	if *fVerbose {
		if *fArchive {
			printf("%-8s%s\n", "MODE", "ARCHIVE")
		} else {
			printf("%-8s%s\n", "MODE", "ISOLATE")
		}
	}
	inputFile, outputFile, authFile, size, err := getIO()
	check(err)
	if *fVerbose {
		printf("%-8s%s\n", "INPUT", inputFile.Name())
		printf("%-8s%s\n", "OUTPUT", outputFile.Name())
		if authFile != nil {
			printf("%-8s%s\n", "AUTH", authFile.Name())
		}
	}
	key, err := getKey()
	check(err)
	var authex []byte
	if *fDecrypt && !*fArchive {
		if authFile != nil {
			authex, err = io.ReadAll(authFile)
			check(err)
		}
		if flags["x"] {
			authex, err = hex.DecodeString(*fVerAuthHex)
			check(err)
		}
	}
	input, output := io.Reader(inputFile), io.Writer(outputFile)
	var pw *geheim.ProgressWriter
	if *fProgress {
		pw = geheim.NewProgressWriter(size)
		input = io.TeeReader(input, pw)
		go pw.Progress(context.Background(), time.Second)
	}
	var printFunc geheim.PrintFunc
	if *fVerbose {
		printFunc = geheim.NewDefaultPrintFunc(os.Stderr)
	}
	var auth []byte
	if *fArchive {
		if *fDecrypt {
			auth, authex, err = geheim.DecryptArchive(input, output, key, printFunc)
		} else {
			auth, err = geheim.EncryptArchive(input, output, key, size, geheim.Cipher(*fCipher), geheim.Hash(*fHash), geheim.KDF(*fKDF), *fSec, printFunc)
		}
	} else {
		if *fDecrypt {
			auth, err = geheim.DecryptVerify(input, output, key, authex, printFunc)
		} else {
			auth, err = geheim.Encrypt(input, output, key, geheim.Cipher(*fCipher), geheim.Hash(*fHash), geheim.KDF(*fKDF), *fSec, printFunc)
		}
	}
	if pw != nil {
		pw.Print(true)
	}
	if *fVerbose {
		if authex != nil {
			printf("%-8s%x\n", "AUTHEX", authex)
		}
	}
	if *fVerbose || *fPrintAuthHex {
		if auth != nil {
			printf("%-8s%x\n", "AUTHED", auth)
		}
	}
	check(err)
	if !*fDecrypt {
		if authFile != nil {
			_, err = authFile.Write(auth)
			check(err)
		}
	}
}
