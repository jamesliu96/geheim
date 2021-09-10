package geheim

import "crypto/rand"

func RandASCIIString(n int) (s string, err error) {
	pass := make([]byte, n)
	if err = randRead(pass); err != nil {
		return
	}
	for i, b := range pass {
		pass[i] = '!' + byte(('~'-'!')*(float64(b)/255))
	}
	s = string(pass)
	return
}

func randRead(buf []byte) (err error) {
	_, err = rand.Read(buf)
	return
}
