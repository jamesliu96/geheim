package main

import (
	"bytes"
	"encoding/gob"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/jamesliu96/geheim"
	"github.com/jamesliu96/geheim/xp"
	"golang.org/x/sys/cpu"
	"golang.org/x/term"
)

const app = "saly"

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
	fNode = flag.Bool("x", false, "node mode")

	fBeaconAddr = flag.String("r", "", "beacon address")
	fNodeAddr   = flag.String("n", "", "node address")
	fBufSize    = flag.Int("b", 64*1024, "buffer size")
	fPass       = flag.String("p", "", "passcode")
	fVerbose    = flag.Bool("v", false, "verbose")
	fVersion    = flag.Bool("V", false, "version")

	fCipher = flag.Int("c", int(geheim.DefaultCipher), fmt.Sprintf("%s (%s)", geheim.CipherDesc, geheim.CipherString))
	fMode   = flag.Int("m", int(geheim.DefaultMode), fmt.Sprintf("%s (%s)", geheim.ModeDesc, geheim.ModeString))
	fKDF    = flag.Int("k", int(geheim.DefaultKDF), fmt.Sprintf("%s (%s)", geheim.KDFDesc, geheim.KDFString))
	fMAC    = flag.Int("a", int(geheim.DefaultMAC), fmt.Sprintf("%s (%s)", geheim.MACDesc, geheim.MACString))
	fMD     = flag.Int("h", int(geheim.DefaultMD), fmt.Sprintf("%s (%s)", geheim.MDDesc, geheim.MDString))
	fSec    = flag.Int("e", geheim.DefaultSec, fmt.Sprintf("%s (%d~%d)", geheim.SecDesc, geheim.MinSec, geheim.MaxSec))
)

type nodes map[string][]byte

func (p nodes) Keys() []string {
	keys := make([]string, 0)
	for node := range p {
		keys = append(keys, node)
	}
	sort.Strings(keys)
	return keys
}

func (p *nodes) FromBytes(b []byte, pass string) {
	buf := bytes.NewBuffer(b)
	if len(pass) > 0 {
		out := bytes.NewBuffer(nil)
		if _, _, err := geheim.DecryptArchive(buf, out, []byte(pass), nil); err == nil {
			buf = out
		}
	}
	dec := gob.NewDecoder(buf)
	dec.Decode(p)
}

func (p nodes) Broadcast(conn net.PacketConn, pass string) {
	buf := bytes.NewBuffer(nil)
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(p); err != nil {
		return
	}
	b := buf.Bytes()
	if len(pass) > 0 {
		out := bytes.NewBuffer(nil)
		if _, err := geheim.EncryptArchive(buf, out, []byte(pass), int64(buf.Len()), geheim.Cipher(*fCipher), geheim.Mode(*fMode), geheim.KDF(*fKDF), geheim.MAC(*fMAC), geheim.MD(*fMD), *fSec, nil); err == nil {
			b = out.Bytes()
		}
	}
	for node := range p {
		r, err := net.ResolveUDPAddr("udp", node)
		if err != nil {
			continue
		}
		conn.WriteTo(b, r)
	}
}

func listen(conn net.PacketConn, beaconAddr net.Addr, peers nodes, priv []byte, writeFn func(m string, p string)) {
	for {
		buf := make([]byte, *fBufSize)
		n, peerAddr, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}
		payload := buf[:n]
		if peerAddr.String() == beaconAddr.String() {
			peers.FromBytes(payload, *fPass)
			continue
		}
		peerPub, ok := peers[peerAddr.String()]
		if !ok {
			continue
		}
		shared, err := xp.X(priv, peerPub)
		if err != nil {
			continue
		}
		out := bytes.NewBuffer(nil)
		if _, _, err := geheim.DecryptArchive(bytes.NewBuffer(payload), out, shared, nil); err != nil {
			continue
		}
		writeFn(out.String(), peerAddr.String())
	}
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
	flag.Parse()
	if *fVersion {
		if *fVerbose {
			printf("%s [%s-%s] [%s] {%d} %s (%s) %s\n", app, runtime.GOOS, runtime.GOARCH, runtime.Version(), runtime.NumCPU(), gitTag, gitRev, cpuFeatures())
		} else {
			printf("%s %s (%s)\n", app, gitTag, gitRev)
		}
		os.Exit(0)
	}
	if *fNode {
		if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
			check(errors.New("stdin/stdout should be terminal"))
		}
		beaconAddr, err := net.ResolveUDPAddr("udp", *fBeaconAddr)
		check(err)
		conn, err := net.ListenPacket("udp", *fNodeAddr)
		check(err)
		priv, pub, err := xp.P()
		check(err)
		oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
		check(err)
		defer term.Restore(int(os.Stdin.Fd()), oldState)
		term := term.NewTerminal(struct {
			io.Reader
			io.Writer
		}{os.Stdin, os.Stdout}, "> ")
		peers := make(nodes)
		go listen(conn, beaconAddr, peers, priv, func(m, p string) {
			fmt.Fprintf(term, "%s%s%s %s%s%s %s\n", term.Escape.Cyan, time.Now().Format(time.RFC3339), term.Escape.Reset, term.Escape.Yellow, p, term.Escape.Reset, m)
		})
		_, err = conn.WriteTo(pub, beaconAddr)
		check(err)
		for {
			line, err := term.ReadLine()
			if err != nil {
				break
			}
			if len(line) == 0 {
				fmt.Fprintln(term, peers.Keys())
				continue
			}
			dstMsg := strings.Split(strings.Trim(line, " "), " ")
			if len(dstMsg) < 2 {
				fmt.Fprintln(term, peers.Keys())
				continue
			}
			dst := dstMsg[0]
			peerPub, ok := peers[dst]
			if !ok {
				fmt.Fprintln(term, peers.Keys())
				continue
			}
			peerAddr, err := net.ResolveUDPAddr("udp", dst)
			if err != nil {
				fmt.Fprintln(term, peers.Keys())
				continue
			}
			shared, err := xp.X(priv, peerPub)
			if err != nil {
				fmt.Fprintln(term, peers.Keys())
				continue
			}
			msg := strings.Join(dstMsg[1:], " ")
			out := bytes.NewBuffer(nil)
			if _, err := geheim.EncryptArchive(bytes.NewBuffer([]byte(msg)), out, shared, int64(len(msg)), geheim.Cipher(*fCipher), geheim.Mode(*fMode), geheim.KDF(*fKDF), geheim.MAC(*fMAC), geheim.MD(*fMD), *fSec, nil); err != nil {
				continue
			}
			conn.WriteTo(out.Bytes(), peerAddr)
		}
	} else {
		peers := make(nodes)
		conn, err := net.ListenPacket("udp", *fBeaconAddr)
		check(err)
		for {
			buf := make([]byte, *fBufSize)
			n, peerAddr, err := conn.ReadFrom(buf)
			if err != nil {
				continue
			}
			pubkey := buf[:n]
			if len(pubkey) != xp.Size {
				continue
			}
			peers[peerAddr.String()] = pubkey
			go peers.Broadcast(conn, *fPass)
		}
	}
}
