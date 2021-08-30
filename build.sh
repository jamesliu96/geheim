#!/bin/bash

set -e

rm -rf build

tag=$(git describe --tags --always)
rev=$(git rev-list -1 HEAD)
ldflags="-X main.app=ghm -X main.gitTag=$tag -X main.gitRev=$rev"
pkg=github.com/jamesliu96/geheim/cmd/ghm
osarchs=(
  "linux amd64"
  "linux arm64"
  "android arm64"
  "js wasm"
  "darwin amd64"
  "darwin arm64"
  "windows amd64"
  "windows arm64"
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