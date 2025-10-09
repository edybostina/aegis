# Aegis

![Build](https://github.com/edybostina/aegis/actions/workflows/build.yml/badge.svg)
![License](https://img.shields.io/github/license/edybostina/aegis)

An easy-to-use file encryption tool.

Prereqs: CMake >= 3.12, a C++17 compiler, libsodium dev package, zlib1g-dev.

- Ubuntu/Debian: sudo apt-get install libsodium-dev cmake g++ zlib1g-dev
- macOS (Homebrew): brew install libsodium cmake zlib
- Windows (vcpkg): vcpkg install libsodium:x64-windows zlib:x64-windows
  then configure CMake toolchain to use vcpkg

## Build:

```bash
git clone https://github.com/edybostina/aegis.git
cd aegis
chmod +x build.sh
./build.sh
```

## Usage

To encrypt a file:

```bash
./aegis enc -i secret.txt -o secret.txt.aegis
```

To decrypt a file:

```bash
./aegis dec -i secret.txt.aegis -o secret.txt
```

To verify a file (decrypts in memory, no output):

```bash
./aegis verify -i secret.txt.aegis
```

All of the above commands support `-p passphrase` to provide a passphrase on the command line.
If -p is omitted, you will be prompted for a passphrase (input hidden).

To generate a random key and save it to a file:

```bash
./aegis genkey -o keyfile
```

To use a key file for encryption/decryption instead of a passphrase, use `-k keyfile`:

```bash
./aegis enc -i secret.txt -o secret.txt.aegis -k keyfile
./aegis dec -i secret.txt.aegis -o secret.txt -k keyfile
``` 

To compress data before encryption, use `-z`:

```bash
./aegis enc -i secret.txt -o secret.txt.aegis -z
./aegis dec -i secret.txt.aegis -o secret.txt -z
```
When using compression, the `-z` flag must be specified for both encryption and decryption.
If `-z` is not specified during decryption, you will get garbage output.

## File Format

- magic(6): 'AEGIS\x00'
- version(1): 0x01
- salt(16): Argon2id salt
- header(24): libsodium secretstream header
- ciphertext: stream of AEAD-encrypted chunks

## Security Notes

- Uses Argon2id (libsodium pwhash) with INTERACTIVE limits by default.
- For archival-strength, consider MODERATE or SENSITIVE params.
- XChaCha20-Poly1305 via secretstream provides chunked encryption with built-in integrity and an authenticated end-of-stream tag.
- Passphrase quality and KDF parameters critically affect security.
