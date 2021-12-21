package geheim

import "crypto/rand"

func randRead(buf []byte) (err error) {
	_, err = rand.Read(buf)
	return
}
