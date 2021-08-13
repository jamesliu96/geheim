#!/bin/sh
tag=$(git describe --tags --always)
rev=$(git rev-list -1 HEAD)
ldflags="-X main.gitTag=$tag -X main.gitRev=$rev"
pkg=github.com/jamesliu96/geheim/cmd/ghm
go run -trimpath -ldflags="$ldflags" $pkg $@