//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || zos || windows || solaris || plan9
// +build aix darwin dragonfly freebsd linux netbsd openbsd zos windows solaris plan9

package main

import (
	"errors"
	"os"

	"golang.org/x/term"
)

func getPass(passSet bool) ([]byte, error) {
	if passSet {
		return []byte(fPass), nil
	}
	stdinFd := int(os.Stdin.Fd())
	printfStderr("enter passphrase: ")
	bPass, err := term.ReadPassword(stdinFd)
	if err != nil {
		return nil, err
	}
	printfStderr("\n")
	if string(bPass) == "" {
		return nil, errors.New("empty passphrase")
	}
	if !fDecrypt {
		printfStderr("verify passphrase: ")
		bvPass, err := term.ReadPassword(stdinFd)
		if err != nil {
			return nil, err
		}
		printfStderr("\n")
		if string(bPass) != string(bvPass) {
			return nil, errors.New("passphrase verification failed")
		}
	}
	return bPass, nil
}
