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
	fDecrypt = flag.Bool("d", false, "decrypt")
	fCipher  = flag.Int("c", int(geheim.DefaultCipher),
		fmt.Sprintf("[enc] %s (%s)", geheim.CipherDesc, geheim.CipherString),
	)
	fMode = flag.Int("m", int(geheim.DefaultMode),
		fmt.Sprintf("[enc] %s (%s)", geheim.ModeDesc, geheim.ModeString),
	)
	fKDF = flag.Int("k", int(geheim.DefaultKDF),
		fmt.Sprintf("[enc] %s (%s)", geheim.KDFDesc, geheim.KDFString),
	)
	fMAC = flag.Int("a", int(geheim.DefaultMAC),
		fmt.Sprintf("[enc] %s (%s)", geheim.MACDesc, geheim.MACString),
	)
	fMD = flag.Int("h", int(geheim.DefaultMD),
		fmt.Sprintf("[enc] %s (%s)", geheim.MDDesc, geheim.MDString),
	)
	fSL = flag.Int("e", geheim.DefaultSec,
		fmt.Sprintf("[enc] %s (%d~%d)", geheim.SecDesc, geheim.MinSec, geheim.MaxSec),
	)
	fIn           = flag.String("i", os.Stdin.Name(), "input `path`")
	fOut          = flag.String("o", os.Stdout.Name(), "output `path`")
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

func setFlags(flags map[string]bool) {
	flag.Visit(func(f *flag.Flag) {
		flags[f.Name] = true
	})
}

func printf(format string, v ...any) {
	fmt.Fprintf(os.Stderr, format, v...)
}

var errDry = errors.New("dry run")

func check(errs ...error) (goterr bool) {
	for _, err := range errs {
		if err != nil && err != errDry {
			printf("error: %s\n", err)
			goterr = true
		}
	}
	if goterr {
		os.Exit(1)
	}
	return
}

func readPass(p *[]byte, question string) error {
	for len(*p) == 0 {
		printf(question)
		password, err := term.ReadPassword(int(os.Stdin.Fd()))
		printf("\n")
		if err != nil {
			return err
		}
		*p = password
	}
	return nil
}

func getPass(passset bool) ([]byte, error) {
	if passset {
		return []byte(*fPass), nil
	}
	var pass []byte
	for {
		if err := readPass(&pass, "enter passcode: "); err != nil {
			return nil, err
		}
		if !*fDecrypt {
			var vpass []byte
			if err := readPass(&vpass, "verify passcode: "); err != nil {
				return nil, err
			}
			if !bytes.Equal(pass, vpass) {
				pass = nil
				continue
			}
		}
		break
	}
	return pass, nil
}

func checkTerminal(fds ...uintptr) error {
	for _, fd := range fds {
		if term.IsTerminal(int(fd)) {
			return errors.New("invalid terminal i/o")
		}
	}
	return nil
}

func getIO(inset, outset, signset bool) (in, out, sign *os.File, inbytes int64, err error) {
	if inset {
		if in, err = os.Open(*fIn); err != nil {
			return
		}
		if fi, e := in.Stat(); e != nil {
			err = e
			return
		} else {
			if fi.IsDir() {
				err = fmt.Errorf("input file \"%s\" is a directory", fi.Name())
				return
			}
			inbytes = fi.Size()
		}
	} else {
		in = os.Stdin
	}
	if outset {
		if !*fOverwrite {
			if fi, e := os.Stat(*fOut); e == nil {
				err = fmt.Errorf("output file \"%s\" exists, use -f to overwrite", fi.Name())
				return
			}
		}
		if out, err = os.Create(*fOut); err != nil {
			return
		}
	} else {
		out = os.Stdout
	}
	if *fVerbose {
		printf("%-8s%s\n", "INPUT", in.Name())
		printf("%-8s%s\n", "OUTPUT", out.Name())
	}
	fds := []uintptr{in.Fd(), out.Fd()}
	if signset {
		if *fDecrypt {
			if sign, err = os.Open(*fSign); err != nil {
				return
			}
			if fi, e := sign.Stat(); e != nil {
				err = e
				return
			} else if fi.IsDir() {
				err = fmt.Errorf("signature file \"%s\" is a directory", fi.Name())
				return
			}
		} else {
			if !*fOverwrite {
				if fi, e := os.Stat(*fSign); e == nil {
					err = fmt.Errorf("signature file \"%s\" exists, use -f to overwrite", fi.Name())
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
		fds = append(fds, sign.Fd())
	}
	err = checkTerminal(fds...)
	return
}

func getCPUFeatures() (d []string) {
	var arch any
	switch runtime.GOARCH {
	case "386":
		fallthrough
	case "amd64":
		arch = cpu.X86
	case "arm":
		arch = cpu.ARM
	case "arm64":
		arch = cpu.ARM64
	case "mips64":
		fallthrough
	case "mips64le":
		arch = cpu.MIPS64X
	case "ppc64":
		fallthrough
	case "ppc64le":
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

func wrapProgress(r io.Reader, total int64, progress bool) (wrapped io.Reader, done chan<- struct{}) {
	if progress {
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

var printFunc geheim.PrintFunc = func(header geheim.Header, pass, keyCipher, keyMAC []byte) (err error) {
	if *fDry {
		err = errDry
	}
	if *fVerbose {
		if e := defaultPrintFunc(header, pass, keyCipher, keyMAC); err == nil {
			err = e
		}
	}
	return
}

func enc(in io.Reader, out io.Writer, sign *os.File, pass []byte, inbytes int64) (err error) {
	in, done := wrapProgress(in, inbytes, *fProgress)
	signed, err := geheim.Encrypt(in, out, pass, geheim.Cipher(*fCipher), geheim.Mode(*fMode), geheim.KDF(*fKDF), geheim.MAC(*fMAC), geheim.MD(*fMD), *fSL, printFunc)
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

func dec(in io.Reader, out io.Writer, sign *os.File, pass []byte, inbytes int64) (err error) {
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
	in, done := wrapProgress(in, inbytes, *fProgress)
	signed, err := geheim.DecryptVerify(in, out, pass, signex, printFunc)
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
	}
	if len(os.Args) <= 1 {
		flag.Usage()
		return
	}
	flag.Parse()
	if flag.NArg() != 0 {
		flag.Usage()
		return
	}
	if *fVersion {
		if *fVerbose {
			printf("%s [%s-%s] [%s] {%d} %s (%s) %s\n", app, runtime.GOOS, runtime.GOARCH, runtime.Version(), runtime.NumCPU(), gitTag, gitRev, getCPUFeatures())
		} else {
			printf("%s %s (%s)\n", app, gitTag, gitRev)
		}
		return
	}
	setFlags(flags)
	in, out, sign, inbytes, err := getIO(flags["i"], flags["o"], flags["s"])
	if check(err) {
		return
	}
	defer func() {
		errs := []error{in.Close(), out.Close()}
		if sign != nil {
			errs = append(errs, sign.Close())
		}
		check(errs...)
	}()
	pass, err := getPass(flags["p"])
	if check(err) {
		return
	}
	if *fDecrypt {
		err = dec(in, out, sign, pass, inbytes)
	} else {
		err = enc(in, out, sign, pass, inbytes)
	}
	check(err)
}
