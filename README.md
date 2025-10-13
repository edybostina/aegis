# Aegis

![Build](https://github.com/edybostina/aegis/actions/workflows/build.yml/badge.svg)
![License](https://img.shields.io/github/license/edybostina/aegis)
![Release](https://img.shields.io/github/v/release/edybostina/aegis)
![Last commit](https://img.shields.io/github/last-commit/edybostina/aegis)
![Platforms](https://img.shields.io/badge/platform-linux%20%7C%20macOS-lightgrey)



An easy-to-use file encryption tool using modern AEAD algorithms.

## Features

- Secure file encryption using modern AEAD algorithms (e.g., XChaCha20-Poly1305).
- Support for both passphrase-based and keyfile-based encryption.
- Optional compression before encryption to save space.
- Recursive directory processing for batch encryption/decryption.
- Cross-platform support (Linux, macOS, and Windows in the near future).
- Simple command-line interface for ease of use.
- Open-source and auditable codebase.

## Installation

To install Aegis, follow the instructions in the [Getting Started](docs/getting_started.md#installation) guide.

## Usage

For detailed usage instructions, refer to the [Usage](docs/usage.md) guide.

## Layout

```
└── aegis
    ├── CMakeLists.txt          # CMake build configuration
    ├── build.sh                # Build script for Unix-like systems
    ├── LICENSE                 # License file
    ├── README.md               # This file
    ├── docs                    # Documentation files
    │   ├── getting_started.md  # Installation and getting started guide
    │   └── usage.md            # Usage instructions and examples
    └── src                     # Source code files
        ├── cli/                # Command-line interface implementation
        │   └── main.cpp        # Main entry point
        ├── crypto/             # Cryptographic functions and algorithms
        └── core/               # Core functionality
    └── tests                   # Test cases and test data
        └── test_roundtrip.cpp  # Example test case
    
```
## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
