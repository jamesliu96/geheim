pkg=github.com/jamesliu96/geheim/cmd/$app
tag=$(git describe --tags --always)
rev=$(git rev-list -1 HEAD)
ldflags="-X main.app=$app -X main.gitTag=$tag -X main.gitRev=$rev"
outdir=build
echo "# $pkg $tag $rev" 1>&2

if [[ $1 == "-build" ]]; then
  if [[ $2 == "-clean" ]]; then
    printf "removing \"$outdir\" ... "
    rm -rf $outdir \
      && echo "SUCCEEDED" \
      || echo "FAILED"
  fi
  ldflags="$ldflags -s -w"
  osarchs=$(go tool dist list)
  for s in $osarchs; do
    osarch=(${s//\// })
    os=${osarch[0]}
    arch=${osarch[1]}
    suffix=
    [[ $os = "android" || $os = "ios" ]] && continue
    [[ $os = "windows" ]] && suffix=".exe"
    [[ $arch = "wasm" ]] && suffix=".wasm"
    out="${outdir}/${app}_${os}_$arch$suffix"
    printf "building \"$out\" ... "
    CGO_ENABLED=0 \
    GOOS=$os GOARCH=$arch \
      go build -trimpath -ldflags="$ldflags" -o $out $pkg \
        && echo "SUCCEEDED" \
        || echo "FAILED"
  done
else
  go run -trimpath -ldflags="$ldflags" $pkg $@
fi