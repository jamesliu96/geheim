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
  -X    print authentication hex
  -c int
        cipher (1:AES-256-CTR, 2:ChaCha20) (default 1)
  -d    decrypt
  -e int
        security (0:1MB, 1:2MB, 2:4MB, 3:8MB, 4:16MB, 5:32MB, 6:64MB, 7:128MB, 8:256MB, 9:512MB, 10:1GB, 11:2GB, 12:4GB, 13:8GB, 14:16GB, 15:32GB, 16:64GB, 17:128GB, 18:256GB, 19:512GB, 20:1TB) (default 10)
  -f    overwrite
  -h int
        hash (1:SHA3-224, 2:SHA3-256, 3:SHA3-384, 4:SHA3-512, 5:SHA-224, 6:SHA-256, 7:SHA-384, 8:SHA-512, 9:SHA-512/224, 10:SHA-512/256) (default 6)
  -i path
        input path (default "/dev/stdin")
  -k int
        key derivation (1:HKDF, 2:Argon2id, 3:Scrypt) (default 2)
  -o path
        output path (default "/dev/stdout")
  -p key
        key
  -s path
        authentication path
  -v    verbose
  -x hex
        verify authentication hex
  -z    archive
```

```sh
$ xp
usage: xp q > private.key                               # mlkem pair
       xp z <private_hex> > public.key                  # mlkem public
       xp z < private.key > public.key                  # mlkem public
       xp e <public_hex> > ciphertext.bin               # mlkem encapsulate
       xp e < public.key > ciphertext.bin               # mlkem encapsulate
       xp d <private_hex> <ciphertext_hex> > shared.key # mlkem decapsulate
       xp d <private_hex> < ciphertext.bin > shared.key # mlkem decapsulate
       xp d <ciphertext_hex> < private.key > shared.key # mlkem decapsulate
       xp d < private.key < ciphertext.bin > shared.key # mlkem decapsulate
       xp p > private.key                               # ecdh pair
       xp x <private_hex> [public_hex] > shared.key     # ecdh exchange
       xp x [public_hex] < private.key > shared.key     # ecdh exchange
       xp g > private.key                               # ecdsa pair
       xp s <message> <private_hex> > signature.bin     # ecdsa sign
       xp s <message> < private.key > signature.bin     # ecdsa sign
       xp s < private.key < message.bin > signature.bin # ecdsa sign
       xp v <message> <public_hex> <signature_hex>      # ecdsa verify
       xp v <message> <public_hex> < signature.bin      # ecdsa verify
       xp v <public_hex> < signature.bin < message.bin  # ecdsa verify
```
