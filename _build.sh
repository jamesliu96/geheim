pkg=github.com/jamesliu96/geheim/cmd/$app
tag=$(git describe --tags --always)
rev=$(git rev-list -1 HEAD)
buildflags=(-trimpath "-ldflags=-X main.gitTag=$tag -X main.gitRev=$rev -s -w")
outdir=build
echo "# $pkg $tag $rev" 1>&2

if [[ $1 == "-build" ]]; then
  if [[ $2 == "-clean" ]]; then
    printf "removing \"$outdir\" ... "
    rm -rf $outdir \
      && echo "SUCCEEDED" \
      || echo "FAILED"
  fi
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
      go build "${buildflags[@]}" -o $out $pkg \
        && echo "SUCCEEDED" \
        || echo "FAILED"
  done
else
  go run "${buildflags[@]}" $pkg $@
fi