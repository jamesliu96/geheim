package main

import (
	"bytes"
	"encoding/gob"
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/jamesliu96/geheim"
	"github.com/jamesliu96/geheim/xp"
)

var (
	fBeaconAddr = flag.String("r", ":9595", "beacon address")
	fBufSize    = flag.Int("b", 1024, "buffer size")
	fPass       = flag.String("p", "", "passcode")

	fCipher = flag.Int("c", int(geheim.DefaultCipher), fmt.Sprintf("%s (%s)", geheim.CipherDesc, geheim.CipherString))
	fMode   = flag.Int("m", int(geheim.DefaultMode), fmt.Sprintf("%s (%s)", geheim.ModeDesc, geheim.ModeString))
	fKDF    = flag.Int("k", int(geheim.DefaultKDF), fmt.Sprintf("%s (%s)", geheim.KDFDesc, geheim.KDFString))
	fMAC    = flag.Int("a", int(geheim.DefaultMAC), fmt.Sprintf("%s (%s)", geheim.MACDesc, geheim.MACString))
	fMD     = flag.Int("h", int(geheim.DefaultMD), fmt.Sprintf("%s (%s)", geheim.MDDesc, geheim.MDString))
	fSec    = flag.Int("e", geheim.DefaultSec, fmt.Sprintf("%s (%d~%d)", geheim.SecDesc, geheim.MinSec, geheim.MaxSec))
)

type nodes map[string][]byte

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

func main() {
	flag.Parse()
	peers := make(nodes)
	conn, err := net.ListenPacket("udp", *fBeaconAddr)
	if err != nil {
		log.Fatalln(err)
	}
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
