package main

import (
	"crypto/mlkem"
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
		panic(err)
	}
}

const (
	q = "q"
	z = "z"
	e = "e"
	d = "d"
	p = "p"
	x = "x"
	g = "g"
	s = "s"
	v = "v"
)

func usage() {
	printf(`%s %s (%s)
usage: %s %s > private.key                               # mlkem pair
       %s %s <private_hex> > public.key                  # mlkem public
       %s %s < private.key > public.key                  # mlkem public
       %s %s <public_hex> > ciphertext.bin               # mlkem encapsulate
       %s %s < public.key > ciphertext.bin               # mlkem encapsulate
       %s %s <private_hex> <ciphertext_hex> > shared.key # mlkem decapsulate
       %s %s <private_hex> < ciphertext.bin > shared.key # mlkem decapsulate
       %s %s <ciphertext_hex> < private.key > shared.key # mlkem decapsulate
       %s %s < private.key < ciphertext.bin > shared.key # mlkem decapsulate
       %s %s > private.key                               # ecdh pair
       %s %s <private_hex> [public_hex] > shared.key     # ecdh exchange
       %s %s [public_hex] < private.key > shared.key     # ecdh exchange
       %s %s > private.key                               # ecdsa pair
       %s %s <message> <private_hex> > signature.bin     # ecdsa sign
       %s %s <message> < private.key > signature.bin     # ecdsa sign
       %s %s < private.key < message.bin > signature.bin # ecdsa sign
       %s %s <message> <public_hex> <signature_hex>      # ecdsa verify
       %s %s <message> <public_hex> < signature.bin      # ecdsa verify
       %s %s <public_hex> < signature.bin < message.bin  # ecdsa verify
`, app, gitTag, gitRev, app, q, app, z, app, z, app, e, app, e, app, d, app, d, app, d, app, d, app, p, app, x, app, x, app, g, app, s, app, s, app, s, app, v, app, v, app, v)
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
		return
	}
	switch os.Args[1] {
	case q:
		dk, err := mlkem.GenerateKey768()
		dkBytes := dk.Bytes()
		check(err)
		ekBytes := dk.EncapsulationKey().Bytes()
		if stdoutTerm {
			fmt.Printf("%-5s%x\n%-5s%x\n", "priv", dkBytes, "pub", ekBytes)
		} else {
			os.Stdout.Write(dkBytes)
			printf("%-5s%x\n%-5s%x\n", "priv", dkBytes, "pub", ekBytes)
		}
	case z:
		var (
			dkBytes []byte
			err     error
		)
		if stdinTerm {
			if argc < 3 {
				usage()
				return
			}
			dkBytes, err = hex.DecodeString(os.Args[2])
			check(err)
		} else {
			dkBytes = make([]byte, mlkem.SeedSize)
			_, err = io.ReadFull(os.Stdin, dkBytes)
			check(err)
		}
		dk, err := mlkem.NewDecapsulationKey768(dkBytes)
		check(err)
		ekBytes := dk.EncapsulationKey().Bytes()
		if stdoutTerm {
			fmt.Printf("%-5s%x\n%-5s%x\n", "priv", dkBytes, "pub", ekBytes)
		} else {
			os.Stdout.Write(ekBytes)
			printf("%-5s%x\n%-5s%x\n", "priv", dkBytes, "pub", ekBytes)
		}
	case e:
		var (
			ekBytes []byte
			err     error
		)
		if stdinTerm {
			if argc < 3 {
				usage()
				return
			}
			ekBytes, err = hex.DecodeString(os.Args[2])
			check(err)
		} else {
			ekBytes = make([]byte, mlkem.EncapsulationKeySize768)
			_, err = io.ReadFull(os.Stdin, ekBytes)
			check(err)
		}
		ek, err := mlkem.NewEncapsulationKey768(ekBytes)
		check(err)
		sk, ct := ek.Encapsulate()
		if stdoutTerm {
			fmt.Printf("%-3s%x\n%-3s%x\n", "sk", sk, "ct", ct)
		} else {
			os.Stdout.Write(ct)
			printf("%-3s%x\n%-3s%x\n", "sk", sk, "ct", ct)
		}
	case d:
		var (
			dkBytes, ct []byte
			err         error
		)
		if stdinTerm {
			if argc < 4 {
				usage()
				return
			}
			dkBytes, err = hex.DecodeString(os.Args[2])
			check(err)
			ct, err = hex.DecodeString(os.Args[3])
			check(err)
		} else {
			if argc > 3 {
				dkOrCtBytes, err := hex.DecodeString(os.Args[2])
				check(err)
				if len(dkOrCtBytes) == mlkem.SeedSize {
					dkBytes = dkOrCtBytes
					ct = make([]byte, mlkem.CiphertextSize768)
					_, err = io.ReadFull(os.Stdin, ct)
					check(err)
				} else {
					dkBytes = make([]byte, mlkem.SeedSize)
					_, err = io.ReadFull(os.Stdin, dkBytes)
					check(err)
					ct = dkOrCtBytes
				}
			} else {
				dkBytes = make([]byte, mlkem.SeedSize)
				_, err = io.ReadFull(os.Stdin, dkBytes)
				check(err)
				ct = make([]byte, mlkem.CiphertextSize768)
				_, err = io.ReadFull(os.Stdin, ct)
				check(err)
			}
		}
		dk, err := mlkem.NewDecapsulationKey768(dkBytes)
		check(err)
		sk, err := dk.Decapsulate(ct)
		check(err)
		if stdoutTerm {
			fmt.Printf("%-3s%x\n%-3s%x\n", "sk", sk, "ct", ct)
		} else {
			os.Stdout.Write(sk)
			printf("%-3s%x\n%-3s%x\n", "sk", sk, "ct", ct)
		}
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
				return
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
				return
			}
			message = []byte(os.Args[2])
			private, err = hex.DecodeString(os.Args[3])
			check(err)
		} else {
			private = make([]byte, sv.PrivateSize)
			_, err = io.ReadFull(os.Stdin, private)
			check(err)
			if argc > 2 {
				message = []byte(os.Args[2])
			} else {
				message, err = io.ReadAll(os.Stdin)
				check(err)
			}
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
				return
			}
			message = []byte(os.Args[2])
			public, err = hex.DecodeString(os.Args[3])
			check(err)
			signature, err = hex.DecodeString(os.Args[4])
			check(err)
		} else {
			if argc < 3 {
				usage()
				return
			}
			signature = make([]byte, sv.SignatureSize)
			_, err = io.ReadFull(os.Stdin, signature)
			check(err)
			if argc > 3 {
				message = []byte(os.Args[2])
				public, err = hex.DecodeString(os.Args[3])
				check(err)
			} else {
				message, err = io.ReadAll(os.Stdin)
				check(err)
				public, err = hex.DecodeString(os.Args[2])
				check(err)
			}
		}
		err = sv.V(message, public, signature)
		check(err)
	default:
		usage()
	}
}
