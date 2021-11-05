#!/bin/bash

set -e

tag=$(git describe --tags --always)
rev=$(git rev-list -1 HEAD)
pkg=github.com/jamesliu96/geheim/cmd/ghm
ldflags="-X main.gitTag=$tag -X main.gitRev=$rev"

if [[ $1 = "build" ]]; then
  rm -rf build
  ldflags="$ldflags -s -w"
  osarchs=(
    "linux amd64"
    "linux arm64"
    "darwin amd64"
    "darwin arm64"
    "windows amd64"
    "windows arm64"
    "js wasm"
  )
  for i in "${osarchs[@]}"; do
    osarch=($i)
    os=${osarch[0]}
    arch=${osarch[1]}
    suffix=""
    if [[ $os = "windows" ]]; then
      suffix=".exe"
    fi
    if [[ $arch = "wasm" ]]; then
      suffix=".wasm"
    fi
    GOOS=$os GOARCH=$arch \
      go build -trimpath -ldflags="$ldflags" -o build/ghm_${os}_${arch}${suffix} $pkg
  done
else
  go run -trimpath -ldflags="$ldflags" $pkg $@
fi