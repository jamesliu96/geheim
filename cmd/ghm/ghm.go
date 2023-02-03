package main

import (
	"bytes"
	"encoding/binary"
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

func printf(format string, a ...any) { fmt.Fprintf(os.Stderr, format, a...) }

func check(err error) {
	if err != nil {
		printf("error: %s\n", err)
		os.Exit(1)
	}
}

var errDry = errors.New("ghm: dry run")

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
	fPass         = flag.String("p", "", "`passcode`")
	fSign         = flag.String("s", "", "signature `path`")
	fVerSignHex   = flag.String("x", "", "[dec] verify signature `hex`")
	fOverwrite    = flag.Bool("f", false, "overwrite")
	fVerbose      = flag.Bool("v", false, "verbose")
	fProgress     = flag.Bool("P", false, "progress")
	fVersion      = flag.Bool("V", false, "version")
	fDry          = flag.Bool("j", false, "dry run")
	fPrintSignHex = flag.Bool("X", false, "print signature hex")
	fArchive      = flag.Bool("z", false, "archive")
)

var flags = make(map[string]bool)

func readBEInt64(r io.Reader) (n int64, err error) {
	err = binary.Read(r, binary.BigEndian, &n)
	return
}

func writeBEInt64(w io.Writer, n int64) error { return binary.Write(w, binary.BigEndian, n) }

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

func getIO() (inputFile, outputFile, signFile *os.File, inputSize int64, err error) {
	if flags["i"] {
		if inputFile, err = os.Open(*fInput); err != nil {
			return
		}
		if fi, e := inputFile.Stat(); e != nil {
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
		inputFile = os.Stdin
	}
	if flags["o"] {
		if !*fOverwrite {
			if fi, e := os.Stat(*fOutput); e == nil {
				err = fmt.Errorf("ghm: output file \"%s\" exists, use -f to overwrite", fi.Name())
				return
			}
		}
		if outputFile, err = os.Create(*fOutput); err != nil {
			return
		}
	} else {
		outputFile = os.Stdout
	}
	if *fVerbose {
		printf("%-8s%s\n", "INPUT", inputFile.Name())
		printf("%-8s%s\n", "OUTPUT", outputFile.Name())
	}
	files := []*os.File{inputFile, outputFile}
	if flags["s"] {
		if *fDecrypt {
			if signFile, err = os.Open(*fSign); err != nil {
				return
			}
			if fi, e := signFile.Stat(); e != nil {
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
			if signFile, err = os.Create(*fSign); err != nil {
				return
			}
		}
		if *fVerbose {
			printf("%-8s%s\n", "SIGN", signFile.Name())
		}
		files = append(files, signFile)
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

func encrypt(input io.Reader, output io.Writer, signFile *os.File, pass []byte, inputSize int64) (sign []byte, err error) {
	if sign, err = geheim.Encrypt(input, output, pass, geheim.Cipher(*fCipher), geheim.Mode(*fMode), geheim.KDF(*fKDF), geheim.MAC(*fMAC), geheim.MD(*fMD), *fSec, printFunc); err != nil {
		return
	}
	if signFile != nil {
		_, err = signFile.Write(sign)
	}
	return
}

func decrypt(input io.Reader, output io.Writer, signFile *os.File, pass []byte, inputSize int64) (sign []byte, err error) {
	var signex []byte
	if flags["x"] {
		if signex, err = hex.DecodeString(*fVerSignHex); err != nil {
			return
		}
	} else if signFile != nil {
		if signex, err = io.ReadAll(signFile); err != nil {
			return
		}
	}
	if signex != nil {
		if *fVerbose {
			printf("%-8s%x\n", "SIGNEX", signex)
		}
	}
	sign, err = geheim.DecryptVerify(input, output, pass, signex, printFunc)
	return
}

func encryptArchive(input io.Reader, output io.Writer, pass []byte, inputSize int64) (sign []byte, err error) {
	input = io.LimitReader(input, inputSize)
	meta := geheim.NewMeta()
	header, _ := meta.Header()
	if err = writeBEInt64(output, int64(binary.Size(meta))+int64(binary.Size(header))+inputSize); err != nil {
		return
	}
	if sign, err = geheim.Encrypt(input, output, pass, geheim.Cipher(*fCipher), geheim.Mode(*fMode), geheim.KDF(*fKDF), geheim.MAC(*fMAC), geheim.MD(*fMD), *fSec, printFunc); err != nil {
		return
	}
	if err = writeBEInt64(output, int64(len(sign))); err != nil {
		return
	}
	_, err = output.Write(sign)
	return
}

func decryptArchive(input io.Reader, output io.Writer, pass []byte, inputSize int64) (sign []byte, err error) {
	dataSize, err := readBEInt64(input)
	if err != nil {
		return
	}
	if sign, err = geheim.Decrypt(io.LimitReader(input, dataSize), output, pass, printFunc); err != nil {
		return
	}
	signexSize, err := readBEInt64(input)
	if err != nil {
		return
	}
	signex, err := io.ReadAll(io.LimitReader(input, signexSize))
	if err != nil {
		return
	}
	if *fVerbose {
		printf("%-8s%x\n", "SIGNEX", signex)
	}
	err = geheim.Verify(signex, sign)
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
	inputFile, outputFile, signFile, inputSize, err := getIO()
	check(err)
	defer func() {
		check(inputFile.Close())
		check(outputFile.Close())
		if signFile != nil {
			check(signFile.Close())
		}
	}()
	pass, err := getPass()
	check(err)
	var done chan struct{}
	var input io.Reader = inputFile
	if *fProgress {
		done = make(chan struct{})
		pw := geheim.NewProgressWriter(inputSize)
		input = io.TeeReader(input, pw)
		go pw.Progress(time.Second, done)
	}
	var sign []byte
	if *fArchive {
		if *fDecrypt {
			sign, err = decryptArchive(input, outputFile, pass, inputSize)
		} else {
			sign, err = encryptArchive(input, outputFile, pass, inputSize)
		}
	} else {
		if *fDecrypt {
			sign, err = decrypt(input, outputFile, signFile, pass, inputSize)
		} else {
			sign, err = encrypt(input, outputFile, signFile, pass, inputSize)
		}
	}
	if done != nil {
		done <- struct{}{}
	}
	if errors.Is(err, errDry) {
		os.Exit(0)
	}
	if !errors.Is(err, geheim.ErrSigVer) {
		check(err)
	}
	if *fVerbose || *fPrintSignHex {
		printf("%-8s%x\n", "SIGNED", sign)
	}
}
