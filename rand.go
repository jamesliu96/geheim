package geheim

import "crypto/rand"

func RandASCIIString(n int) string {
	pass := make([]byte, n)
	rand.Read(pass)
	for i, b := range pass {
		pass[i] = byte('!' + (b % ('~' - '!' + 1)))
	}
	return string(pass)
}

func randRead(buf []byte) (err error) {
	_, err = rand.Read(buf)
	return
}
