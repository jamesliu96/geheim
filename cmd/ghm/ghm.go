package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
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

var (
	fDecrypt      = flag.Bool("d", false, "decrypt")
	fCipher       = flag.Int("c", int(geheim.DefaultCipher), fmt.Sprintf("[enc] %s (%s)", geheim.CipherDesc, geheim.CipherString))
	fMode         = flag.Int("m", int(geheim.DefaultMode), fmt.Sprintf("[enc] %s (%s)", geheim.ModeDesc, geheim.ModeString))
	fKDF          = flag.Int("k", int(geheim.DefaultKDF), fmt.Sprintf("[enc] %s (%s)", geheim.KDFDesc, geheim.KDFString))
	fMAC          = flag.Int("a", int(geheim.DefaultMAC), fmt.Sprintf("[enc] %s (%s)", geheim.MACDesc, geheim.MACString))
	fMD           = flag.Int("h", int(geheim.DefaultMD), fmt.Sprintf("[enc] %s (%s)", geheim.MDDesc, geheim.MDString))
	fSec          = flag.Int("e", geheim.DefaultSec, fmt.Sprintf("[enc] %s (%d~%d)", geheim.SecDesc, geheim.MinSec, geheim.MaxSec))
	fInput        = flag.String("i", os.Stdin.Name(), "input `path`")
	fOutput       = flag.String("o", os.Stdout.Name(), "output `path`")
	fSign         = flag.String("s", "", "signature `path`")
	fSignHex      = flag.String("x", "", "[dec] signature `hex`")
	fPass         = flag.String("p", "", "`passcode`")
	fOverwrite    = flag.Bool("f", false, "allow overwrite")
	fVerbose      = flag.Bool("v", false, "verbose")
	fProgress     = flag.Bool("P", false, "show progress")
	fVersion      = flag.Bool("V", false, "print version")
	fPrintSignHex = flag.Bool("X", false, "print signature hex")
	fDry          = flag.Bool("j", false, "dry run")
)

var flags = map[string]bool{}

func printf(format string, v ...any) {
	fmt.Fprintf(os.Stderr, format, v...)
}

var errDry = errors.New("ghm: dry run")

func check(err error) {
	if err != nil && !errors.Is(err, errDry) {
		printf("error: %s\n", err)
		os.Exit(1)
	}
}

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

func getIO() (in, out, sign *os.File, inputSize int64, err error) {
	if flags["i"] {
		if in, err = os.Open(*fInput); err != nil {
			return
		}
		if fi, e := in.Stat(); e != nil {
			err = e
			return
		} else {
			if fi.IsDir() {
				err = fmt.Errorf("ghm: input file \"%s\" is a directory", fi.Name())
				return
			}
			inputSize = fi.Size()
		}
	} else {
		in = os.Stdin
	}
	if flags["o"] {
		if !*fOverwrite {
			if fi, e := os.Stat(*fOutput); e == nil {
				err = fmt.Errorf("ghm: output file \"%s\" exists, use -f to overwrite", fi.Name())
				return
			}
		}
		if out, err = os.Create(*fOutput); err != nil {
			return
		}
	} else {
		out = os.Stdout
	}
	if *fVerbose {
		printf("%-8s%s\n", "INPUT", in.Name())
		printf("%-8s%s\n", "OUTPUT", out.Name())
	}
	files := []*os.File{in, out}
	if flags["s"] {
		if *fDecrypt {
			if sign, err = os.Open(*fSign); err != nil {
				return
			}
			if fi, e := sign.Stat(); e != nil {
				err = e
				return
			} else if fi.IsDir() {
				err = fmt.Errorf("ghm: signature file \"%s\" is a directory", fi.Name())
				return
			}
		} else {
			if !*fOverwrite {
				if fi, e := os.Stat(*fSign); e == nil {
					err = fmt.Errorf("ghm: signature file \"%s\" exists, use -f to overwrite", fi.Name())
					return
				}
			}
			if sign, err = os.Create(*fSign); err != nil {
				return
			}
		}
		if *fVerbose {
			printf("%-8s%s\n", "SIGN", sign.Name())
		}
		files = append(files, sign)
	}
	for _, file := range files {
		if term.IsTerminal(int(file.Fd())) {
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

func wrapProgress(r io.Reader, total int64) (wrapped io.Reader, done chan<- struct{}) {
	if *fProgress {
		d := make(chan struct{})
		pw := geheim.NewProgressWriter(total)
		go pw.Progress(time.Second, d)
		wrapped = io.TeeReader(r, pw)
		done = d
	} else {
		wrapped = r
	}
	return
}

func doneProgress(done chan<- struct{}) {
	if done != nil {
		done <- struct{}{}
	}
}

var defaultPrintFunc = geheim.NewDefaultPrintFunc(os.Stderr)

var printFunc geheim.PrintFunc = func(version int, header geheim.Header, pass, keyCipher, keyMAC []byte) (err error) {
	if *fDry {
		err = errDry
	}
	if *fVerbose {
		if e := defaultPrintFunc(version, header, pass, keyCipher, keyMAC); err == nil {
			err = e
		}
	}
	return
}

func enc(input io.Reader, output io.Writer, sign *os.File, pass []byte, inputSize int64) (err error) {
	input, done := wrapProgress(input, inputSize)
	signed, err := geheim.Encrypt(input, output, pass, geheim.Cipher(*fCipher), geheim.Mode(*fMode), geheim.KDF(*fKDF), geheim.MAC(*fMAC), geheim.MD(*fMD), *fSec, printFunc)
	doneProgress(done)
	if err != nil {
		return
	}
	if *fVerbose || *fPrintSignHex {
		printf("%-8s%x\n", "SIGNED", signed)
	}
	if sign != nil {
		_, err = sign.Write(signed)
	}
	return
}

func dec(input io.Reader, output io.Writer, sign *os.File, pass []byte, inputSize int64) (err error) {
	var signex []byte
	if flags["x"] {
		if signex, err = hex.DecodeString(*fSignHex); err != nil {
			return
		}
	} else if sign != nil {
		if signex, err = io.ReadAll(sign); err != nil {
			return
		}
	}
	if signex != nil {
		if *fVerbose {
			printf("%-8s%x\n", "SIGNEX", signex)
		}
	}
	input, done := wrapProgress(input, inputSize)
	signed, err := geheim.DecryptVerify(input, output, pass, signex, printFunc)
	doneProgress(done)
	if err != nil && !errors.Is(err, geheim.ErrSigVer) {
		return
	}
	if *fVerbose || *fPrintSignHex {
		printf("%-8s%x\n", "SIGNED", signed)
	}
	return
}

func main() {
	flag.Usage = func() {
		printf("usage: %s [option]...\noptions:\n", app)
		flag.PrintDefaults()
		os.Exit(0)
	}
	if len(os.Args) < 2 {
		flag.Usage()
	}
	flag.Parse()
	flag.Visit(func(f *flag.Flag) {
		flags[f.Name] = true
	})
	if *fVersion {
		if *fVerbose {
			printf("%s [%s-%s] [%s] {%d} %s (%s) %s\n", app, runtime.GOOS, runtime.GOARCH, runtime.Version(), runtime.NumCPU(), gitTag, gitRev, cpuFeatures())
		} else {
			printf("%s %s (%s)\n", app, gitTag, gitRev)
		}
		return
	}
	input, output, sign, inputSize, err := getIO()
	check(err)
	defer func() {
		check(input.Close())
		check(output.Close())
		if sign != nil {
			check(sign.Close())
		}
	}()
	pass, err := getPass()
	check(err)
	if *fDecrypt {
		err = dec(input, output, sign, pass, inputSize)
	} else {
		err = enc(input, output, sign, pass, inputSize)
	}
	check(err)
}
