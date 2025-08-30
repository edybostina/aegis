# Aegis

An easy-to-use file encryption tool.

Prereqs: CMake >= 3.16, a C++20 compiler, libsodium dev package.

- Ubuntu/Debian: sudo apt-get install libsodium-dev cmake g++
- macOS (Homebrew): brew install libsodium cmake
- Windows (vcpkg): vcpkg install libsodium:x64-windows
  then configure CMake toolchain to use vcpkg

## Build:

```bash
mkdir build && cd build
cmake ..
cmake --build . --config Release
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

If -p is omitted, you will be prompted for a passphrase (input hidden).

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
