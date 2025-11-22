# Security Features and Best Practices

## Overview

Aegis implements multiple security layers to protect your encrypted data. This document outlines the security features, threat model, and best practices.

## Cryptographic Primitives

### Encryption
- **Algorithm**: XChaCha20-Poly1305 (AEAD cipher)
- **Key Derivation**: Argon2id (password hashing)
- **Library**: libsodium (audited, widely-used crypto library)
- **Streaming**: Uses libsodium's secretstream for large file support

### Key Derivation Parameters
- **Memory**: 64 MB (crypto_pwhash_MEMLIMIT_INTERACTIVE)
- **Operations**: 2 (crypto_pwhash_OPSLIMIT_INTERACTIVE)
- **Algorithm**: Argon2id (resistant to both side-channel and GPU attacks)

## Security Features

### 1. Memory Security
- **Secure Memory Wiping**: All sensitive data (keys, passphrases) is wiped from memory using `sodium_memzero()` after use
- **SecureString Class**: Automatically wipes string data on destruction to prevent data leakage
- **No Plaintext Copies**: Keys and passphrases are not copied unnecessarily

### 2. Constant-Time Operations
- **Magic Byte Comparison**: Uses `sodium_memcmp()` for constant-time comparison to prevent timing attacks
- **Authentication**: All cryptographic operations use constant-time implementations from libsodium

### 3. Input Validation
- **Passphrase Strength**: Warns users about weak passphrases (< 8 characters)
- **Path Traversal Prevention**: Validates file paths to prevent directory traversal attacks
- **File Size Checks**: Prevents processing of excessively large files

### 4. File Permissions
- **Key Files**: Created with mode 0600 (owner read/write only) on Unix-like systems
- **Permission Warnings**: Alerts users if key files have overly permissive permissions
- **Temporary Files**: Created with restrictive permissions (0600)

### 5. Secure Temporary File Handling
- **Unpredictable Names**: Uses cryptographic random number generator for temp file names
- **Restrictive Permissions**: Temp files created with 0600 mode
- **Automatic Cleanup**: Temp files are removed after use

### 6. Error Message Security
- **No Information Leakage**: Authentication failures use generic error messages
- **Unified Errors**: "Wrong password" and "corrupt file" produce the same error message
- **Timing Resistance**: Operations complete in consistent time regardless of failure reason

### 7. Authenticated Encryption
- **AEAD**: XChaCha20-Poly1305 provides both confidentiality and authenticity
- **Tag Verification**: Every chunk is authenticated; tampering is detected immediately
- **No Partial Decryption**: Decryption fails completely if any chunk is modified

## Threat Model

### Protected Against

**Brute Force Attacks**: Argon2id makes password cracking computationally expensive  
**Timing Attacks**: Constant-time comparisons prevent information leakage  
**Memory Dumps**: Sensitive data is wiped from memory after use  
**File Tampering**: AEAD tags detect any modification to encrypted data  
**Chosen Plaintext Attacks**: XChaCha20-Poly1305 is resistant to CPA  
**Replay Attacks**: Each encryption uses a unique random nonce  
**Dictionary Attacks**: Strong KDF parameters slow down password guessing  

### Not Protected Against

**Keyloggers**: If passphrase is captured during entry, encryption is compromised  
**Compromised System**: Malware on the system can capture keys in memory  
**Rubber Hose Cryptanalysis**: Cannot protect against coercion  
**Quantum Computers**: XChaCha20-Poly1305 is not post-quantum secure  
**Side-Channel Attacks**: Limited protection; assumes trusted execution environment  
**File Metadata Leakage**: File sizes and access patterns are not hidden  

## Best Practices

### For Users

1. **Use Strong Passphrases**
   - Minimum 12 characters (16+ recommended)
   - Mix of uppercase, lowercase, numbers, and symbols
   - Use a passphrase generator or password manager
   - Never reuse passphrases from other services

2. **Protect Key Files**
   - Store key files on secure, encrypted storage
   - Use `chmod 600 keyfile` to restrict permissions
   - Never transmit key files over insecure channels
   - Consider using hardware security modules (HSM) for high-value keys

3. **Verify File Integrity**
   - Use `aegis verify` to check encrypted files periodically
   - Store checksums separately for additional verification
   - Test decryption before deleting original files

4. **Secure Your System**
   - Keep your OS and software up-to-date
   - Use full-disk encryption for additional protection
   - Run Aegis on trusted, malware-free systems
   - Be cautious when entering passphrases on shared systems

5. **Backup Strategy**
   - Keep multiple copies of encrypted files
   - Store backups in different physical locations
   - **IMPORTANT**: Backup your key files and remember your passphrases
   - Test restoration procedures regularly

### For Developers

1. **Code Review**
   - All cryptographic code should be reviewed by security experts
   - Follow secure coding practices
   - Use static analysis tools (clang-tidy, cppcheck)

2. **Dependency Management**
   - Keep libsodium updated to the latest stable version
   - Monitor security advisories for all dependencies
   - Verify library signatures and checksums

3. **Testing**
   - Run fuzzing tests on file parsing code
   - Test with invalid/malformed inputs
   - Verify constant-time properties of critical functions
   - Memory leak detection (valgrind, AddressSanitizer)


**Recommendations**:
- Only use compression for non-sensitive or uniformly random data
- If compression ratio reveals sensitive information, disable it with the `-z` flag
- Consider using authenticated compression or compress-then-encrypt patterns

## File Format Security

### Header Structure
```
[Magic: 6 bytes] [Version: 1 byte] [Compress: 1 byte] 
[Salt: 16 bytes] [Stream Header: 24 bytes] [Encrypted Data...]
```

### Security Properties
- **Magic Bytes**: Identifies Aegis files (not secret, aids in format detection)
- **Version**: Allows for future format upgrades and compatibility
- **Salt**: Random 128-bit salt for key derivation (unique per file)
- **Stream Header**: libsodium secretstream header (includes unique nonce)
- **Encrypted Data**: Chunked AEAD-encrypted content

### What's Not Encrypted
- Magic bytes (AEGIS\x00)
- Version number
- Compression flag
- Salt
- Stream header

**Why**: These are necessary for decryption and do not reveal plaintext content.

## Reporting Security Issues

If you discover a security vulnerability in Aegis:

1. **DO NOT** open a public GitHub issue
2. Email: egbostina.dev@gmail.com
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if available)

I will try to respond within 48 hours and work with you to address the issue.

## Security Audit Status

- **Last Audit**: Not yet audited
- **Recommendation**: Use for personal data; conduct professional audit before enterprise use
- **Crypto Implementation**: Relies on well-audited libsodium library

## Future Security Enhancements

Planned improvements:
- [ ] Memory locking (`sodium_mlock`) for sensitive data
- [ ] HSM/PKCS#11 support for key storage
- [ ] Post-quantum cryptography options
- [ ] Metadata encryption (filenames, timestamps)
- [ ] Plausible deniability features
- [ ] Hardware security key (YubiKey) support
- [ ] Secure key sharing using threshold cryptography
- [ ] Formal security audit by third-party experts

## References

- [libsodium Documentation](https://doc.libsodium.org/)
- [Argon2 Specification](https://github.com/P-H-C/phc-winner-argon2)
- [XChaCha20-Poly1305 RFC](https://tools.ietf.org/html/draft-irtf-cfrg-xchacha)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
