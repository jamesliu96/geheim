#!/bin/sh
rm -rf build
pkg=github.com/jamesliu96/geheim/cmd/ghm
GOOS=darwin GOARCH=amd64 \
  go build -trimpath -o build/ghm_darwin_amd64 $pkg
GOOS=darwin GOARCH=arm64 \
  go build -trimpath -o build/ghm_darwin_arm64 $pkg
GOOS=linux GOARCH=amd64 \
  go build -trimpath -o build/ghm_linux_amd64 $pkg
GOOS=windows GOARCH=amd64 \
  go build -trimpath -o build/ghm_windows_amd64.exe $pkg
GOOS=android GOARCH=arm64 \
  go build -trimpath -o build/ghm_android_arm64 $pkg