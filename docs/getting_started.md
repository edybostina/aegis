# Getting Started with Aegis

Welcome! This guide will help you get started with Aegis, a lightweight library for encrypting and decrypting data.

## Installation

To install Aegis, follow these steps:

1. Go to the [Aegis GitHub repository](https://github.com/edybostina/aegis).
2. Download the latest release for your platform.

If you wish to build from source, follow these steps:

1. Ensure you have these prerequisites installed, check out [prerequisites](#prerequisites).

2. `git clone https://github.com/edybostina/aegis.git`

3. `cd aegis`
    - If you wish to build an older version, checkout the desired tag.

4. `chmod +x build.sh`

5. `./build.sh`
    - The default build directory is `build/`. You can change it by running `./build.sh <build_dir>`.

Notes:
- The build script uses CMake to configure and build the project.
- The resulting executable will be located in the specified build directory.
- If you encounter any issues, please refer to the [troubleshooting section](#troubleshooting).

## Basic Usage

To encrypt a file:

```bash
./aegis enc -i secret.txt -o secret.txt.aegis
````

To decrypt a file:

```bash
./aegis dec -i secret.txt.aegis -o secret.txt
```

To verify a file (decrypts in memory, no output):

```bash
./aegis verify -i secret.txt.aegis
```

All of the above commands support `-p passphrase` to provide a passphrase on the command line. If `-p` is omitted, you will be prompted for a passphrase (input hidden).

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

For more detailed information, refer to the [Aegis documentation](docs/usage.md).

## Prerequisites

Depending on your platform, you may need to install the following dependencies:

- Ubuntu/Debian:

```bash
  sudo apt-get install libsodium-dev cmake g++ zlib1g-dev
```

- macOS (Homebrew):

```bash
  brew install libsodium cmake zlib
```

- Windows (vcpkg): coming soon...

## Troubleshooting
If you encounter issues during installation, consider the following steps:
- Ensure all prerequisites are installed correctly.
- Most issues arise from missing dependencies or improper library linking by CMake.
- Review the build output for any error messages and address them accordingly.
- Ensure you have the necessary permissions to read/write files in the specified directories.
- If you built from source, ensure that the build completed successfully without errors.
- If you encounter issues with the `aegis` command not found, ensure that you are in the correct build directory and that the executable was created.
- For further assistance, consider opening an issue on the [Aegis GitHub repository](https://github.com/edybostina/aegis/issues).
