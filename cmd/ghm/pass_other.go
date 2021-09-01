//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !zos && !windows && !solaris && !plan9
// +build !aix,!darwin,!dragonfly,!freebsd,!linux,!netbsd,!openbsd,!zos,!windows,!solaris,!plan9

package main

import "errors"

func getPass(passSet bool) ([]byte, error) {
	if passSet {
		return []byte(fPass), nil
	}
	return nil, errors.New("passphrase must be specified")
}
