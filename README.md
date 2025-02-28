# geheim

[![Go Reference](https://pkg.go.dev/badge/github.com/jamesliu96/geheim.svg)](https://pkg.go.dev/github.com/jamesliu96/geheim)

the cipher utility

## usage

```sh
$ ghm
usage: ghm [option]...
options:
  -P    progress
  -V    version
  -X    print signature hex
  -c int
        cipher (1:AES-256-CTR, 2:ChaCha20) (default 1)
  -d    decrypt
  -e int
        security (0~20) (default 12)
  -f    overwrite
  -h int
        message digest (1:SHA3-224, 2:SHA3-256, 3:SHA3-384, 4:SHA3-512, 5:SHA-224, 6:SHA-256, 7:SHA-384, 8:SHA-512, 9:SHA-512/224, 10:SHA-512/256) (default 6)
  -i path
        input path (default "/dev/stdin")
  -k int
        key derivation (1:HKDF, 2:Argon2id, 3:Scrypt) (default 2)
  -o path
        output path (default "/dev/stdout")
  -p key
        key
  -s path
        signature path
  -v    verbose
  -x hex
        verify signature hex
  -z    archive
```

```sh
$ xp
usage: xp p                  # pair
       xp x <scalar> [point] # mult
```
