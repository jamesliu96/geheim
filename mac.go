package geheim

import (
	"crypto/hmac"
)

const keyHMACSize = 32

var newHMAC = hmac.New
