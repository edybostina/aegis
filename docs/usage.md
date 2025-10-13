# Usage

The following instructions assume you have already built the `aegis` executable. If you haven't done so, please refer to the [Getting Started](getting_started.md) guide.

## Contents

- [File Format](#file-format)
- [Security Notes](#security-notes)
- [Arguments](#arguments)
- [Encrypting a file](#encrypting-a-file)
- [Decrypting a file](#decrypting-a-file)
- [Verifying a file](#verifying-a-file)
- [Generating a key](#generating-a-key)

## File Format

The encrypted file format consists of a header followed by the ciphertext and authentication tag. The header includes metadata such as magic bytes, version, compression flag, salt, nonce, and chunk size (for streaming mode).

- magic(6): 'AEGIS\x00'
- version(1): at present, 0x02
- compress(1): 0x00 (no compression) or 0x01 (compressed)
- salt(16): Argon2id salt
- header(24): libsodium secretstream header
- ciphertext: stream of AEAD-encrypted chunks

## Security Notes

- Always use a strong, unique passphrase or key file for encryption.
- Keep your key files secure and do not share them.
- Ensure that you use the `-z` flag consistently during both encryption and decryption if compression is enabled.
- Regularly update your encryption keys and passphrases to maintain security.

## Arguments

The first positional argument specifies the mode of operation. The supported modes are:

- `enc`: Encrypt a file.
- `dec`: Decrypt a file.
- `verify`: Verify the integrity of an encrypted file (decrypts in memory, no output).
- `keygen`: Generate a new encryption key.

The `aegis` command supports the following arguments:

- `-i <input_file>`: Specifies the input file to be processed.
- `-o <output_file>`: Specifies the output file to write the result to.
- `-p <passphrase>`: Provides a passphrase for encryption/decryption. If omitted, you will be prompted to enter it (input hidden).
- `-k <keyfile>`: Specifies a key file to use for encryption/decryption instead of a passphrase.
- `-z`: Enables compression before encryption. Must be used during both encryption and decryption.
- `-r`: Enables recursive processing of directories.
- `-h or --help`: Displays help information about the command and its arguments.
- `--version`: Displays the version of the `aegis` tool.

## Encrypting a file

The mode for encrypting a file is `enc`. The basic command to encrypt a file is:

```bash
./aegis enc -i <input_file> -o <output_file>
```

The encryption mode supports additional options, such as:

- `-p <passphrase>`: Provide a passphrase for encryption.
- `-k <keyfile>`: Use a key file for encryption instead of a passphrase.
- `-z`: Enable compression before encryption.
- `-r`: Encrypt files in a directory recursively.
  Example:

```bash
./aegis enc -i secret.txt -o secret.txt.aegis -p mysecretpass -z
```

This command compresses and encrypts `secret.txt` using the passphrase `mysecretpass`, and writes the output to `secret.txt.aegis`.

## Decrypting a file

The mode for decrypting a file is `dec`. The basic command to decrypt a file is:

```bash
./aegis dec -i <input_file> -o <output_file>
```

The decryption mode supports additional options, such as:

- `-p <passphrase>`: Provide a passphrase for decryption.
- `-k <keyfile>`: Use a key file for decryption instead of a passphrase.
- `-z`: Enable decompression after decryption (must match the encryption setting).
- `-r`: Decrypt files in a directory recursively.
  Example:

```bash
./aegis dec -i secret.txt.aegis -o secret.txt -p mysecretpass -z
```

This command decrypts and decompresses `secret.txt.aegis` using the passphrase `mysecretpass`, and writes the output to `secret.txt`.

## Verifying a file

The mode for verifying a file is `verify`. The basic command to verify a file is:

```bash
./aegis verify -i <input_file>
```

The verify mode supports additional options, such as:

- `-p <passphrase>`: Provide a passphrase for verification.
- `-k <keyfile>`: Use a key file for verification instead of a passphrase.
  Example:

```bash
./aegis verify -i secret.txt.aegis -p mysecretpass
```

This command verifies the integrity of `secret.txt.aegis` using the passphrase `mysecretpass`.

## Generating a key

The mode for generating a key is `keygen`. The basic command to generate a key is:

```bash
./aegis keygen -o <keyfile>
```

The keygen mode supports the following option:

- `-o <keyfile>`: Specifies the output file to write the generated key to
  Example:

```bash
./aegis keygen -o mykeyfile
```

This command generates a random encryption key and saves it to `mykeyfile`.
A keyfile is a binary file containing 32 random bytes suitable for use as an encryption key.
