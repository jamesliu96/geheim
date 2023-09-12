package main

import (
	"bytes"
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
	fPass         = flag.String("p", "", "`passcode`")
	fSign         = flag.String("s", "", "signature `path`")
	fVerSignHex   = flag.String("x", "", "verify signature `hex`")
	fOverwrite    = flag.Bool("f", false, "overwrite")
	fVerbose      = flag.Bool("v", false, "verbose")
	fProgress     = flag.Bool("P", false, "progress")
	fVersion      = flag.Bool("V", false, "version")
	fPrintSignHex = flag.Bool("X", false, "print signature hex")
	fArchive      = flag.Bool("z", false, "archive")

	fCipher = flag.Int("c", int(geheim.DefaultCipher), fmt.Sprintf("%s (%s)", geheim.CipherDesc, geheim.CipherString))
	fMode   = flag.Int("m", int(geheim.DefaultMode), fmt.Sprintf("%s (%s)", geheim.ModeDesc, geheim.ModeString))
	fKDF    = flag.Int("k", int(geheim.DefaultKDF), fmt.Sprintf("%s (%s)", geheim.KDFDesc, geheim.KDFString))
	fMAC    = flag.Int("a", int(geheim.DefaultMAC), fmt.Sprintf("%s (%s)", geheim.MACDesc, geheim.MACString))
	fMD     = flag.Int("h", int(geheim.DefaultMD), fmt.Sprintf("%s (%s)", geheim.MDDesc, geheim.MDString))
	fSec    = flag.Int("e", geheim.DefaultSec, fmt.Sprintf("%s (%d~%d)", geheim.SecDesc, geheim.MinSec, geheim.MaxSec))
)

var flags = make(map[string]bool)

func readPass(question string) (pass []byte, err error) {
	for len(pass) == 0 {
		printf(question)
		pass, err = term.ReadPassword(int(os.Stdin.Fd()))
		printf("\n")
		if err != nil {
			return
		}
	}
	return
}

func getPass() (pass []byte, err error) {
	if flags["p"] {
		pass = []byte(*fPass)
	} else {
		for {
			if pass, err = readPass("enter passcode: "); err != nil {
				return
			}
			if !*fDecrypt {
				var vpass []byte
				if vpass, err = readPass("verify passcode: "); err != nil {
					return
				}
				if !bytes.Equal(pass, vpass) {
					pass = nil
					continue
				}
			}
			break
		}
	}
	return
}

func getIO() (inputFile, outputFile, signFile *os.File, size int64, err error) {
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
			if signFile, err = os.Open(*fSign); err != nil {
				return
			}
			var fi fs.FileInfo
			if fi, err = signFile.Stat(); err != nil {
				return
			} else if fi.IsDir() {
				err = errors.New("ghm: signature file is a directory")
				return
			}
		} else {
			if !*fOverwrite {
				if _, e := os.Stat(*fSign); e == nil {
					err = errors.New("ghm: signature file exists, use -f to overwrite")
					return
				}
			}
			if signFile, err = os.Create(*fSign); err != nil {
				return
			}
		}
	}
	for _, file := range []*os.File{inputFile, outputFile, signFile} {
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
	for i := 0; i < ks.NumField(); i++ {
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
	inputFile, outputFile, signFile, size, err := getIO()
	check(err)
	defer func() {
		check(inputFile.Close())
		check(outputFile.Close())
		if signFile != nil {
			check(signFile.Close())
		}
	}()
	if *fVerbose {
		printf("%-8s%s\n", "INPUT", inputFile.Name())
		printf("%-8s%s\n", "OUTPUT", outputFile.Name())
		if signFile != nil {
			printf("%-8s%s\n", "SIGN", signFile.Name())
		}
	}
	pass, err := getPass()
	check(err)
	var signex []byte
	if *fDecrypt && !*fArchive {
		if signFile != nil {
			signex, err = io.ReadAll(signFile)
			check(err)
		}
		if flags["x"] {
			signex, err = hex.DecodeString(*fVerSignHex)
			check(err)
		}
	}
	input := io.Reader(inputFile)
	output := io.Writer(outputFile)
	var done chan struct{}
	if *fProgress {
		pw := geheim.NewProgressWriter(size)
		input = io.TeeReader(input, pw)
		done = make(chan struct{})
		go pw.Progress(time.Second, done)
	}
	var printFunc geheim.PrintFunc
	if *fVerbose {
		printFunc = geheim.NewDefaultPrintFunc(os.Stderr)
	}
	var sign []byte
	if *fArchive {
		if *fDecrypt {
			sign, signex, err = geheim.DecryptArchive(input, output, pass, printFunc)
		} else {
			sign, err = geheim.EncryptArchive(input, output, pass, size, geheim.Cipher(*fCipher), geheim.Mode(*fMode), geheim.KDF(*fKDF), geheim.MAC(*fMAC), geheim.MD(*fMD), *fSec, printFunc)
		}
	} else {
		if *fDecrypt {
			sign, err = geheim.DecryptVerify(input, output, pass, signex, printFunc)
		} else {
			sign, err = geheim.Encrypt(input, output, pass, geheim.Cipher(*fCipher), geheim.Mode(*fMode), geheim.KDF(*fKDF), geheim.MAC(*fMAC), geheim.MD(*fMD), *fSec, printFunc)
		}
	}
	if done != nil {
		done <- struct{}{}
	}
	if *fVerbose {
		if signex != nil {
			printf("%-8s%x\n", "SIGNEX", signex)
		}
	}
	if *fVerbose || *fPrintSignHex {
		if sign != nil {
			printf("%-8s%x\n", "SIGNED", sign)
		}
	}
	check(err)
	if !*fDecrypt {
		if signFile != nil {
			_, err = signFile.Write(sign)
			check(err)
		}
	}
}
