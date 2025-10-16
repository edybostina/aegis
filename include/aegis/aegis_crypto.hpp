#pragma once

#include <cstddef>
#include <string>
#include <filesystem>

#include <sodium.h>
#include <zlib.h>

namespace
{
    constexpr const char *MAGIC = "AEGIS\x00"; // 6 bytes, includes null sentinel
    constexpr unsigned char VERSION = 2;
}

namespace aegis
{
    struct KdfParams
    {
        unsigned long long ops_limit; // crypto_pwhash_OPSLIMIT_INTERACTIVE
        size_t mem_limit;             // crypto_pwhash_MEMLIMIT_INTERACTIVE
    };

    // Initialize crypto library; throws std::runtime_error on failure
    void init_crypto();

    // Derive a 32-byte key from a passphrase using Argon2id with random salt.
    // Returns raw key bytes and writes salt to out parameter.
    std::array<unsigned char, crypto_secretbox_KEYBYTES> derive_key_from_passphrase_enc(
        const std::string &passphrase,
        std::array<unsigned char, 16> &out_salt,
        const KdfParams &params);

    // Derive a 32-byte key from a passphrase with a given salt (for decryption)
    std::array<unsigned char, crypto_secretbox_KEYBYTES> derive_key_from_passphrase_dec(
        const std::string &passphrase,
        const std::array<unsigned char, 16> &salt,
        const KdfParams &params);

    // Encrypt a file using XChaCha20-Poly1305 secretstream with key derived
    // from passphrase. The output format is:
    // magic(6) | version(1) | salt(16) | header(crypto_secretstream_xchacha20poly1305_HEADERBYTES)
    // | ciphertext...
    void encrypt_file(const std::filesystem::path &in,
                      const std::filesystem::path &out,
                      const std::string &passphrase,
                      const KdfParams &params,
                      const std::array<unsigned char, crypto_secretbox_KEYBYTES> &key_override,
                      bool keyfile_used = false,
                      bool compress = false,
                      bool verbose = false);

    // Decrypt a file created by encrypt_file()
    void decrypt_file(const std::filesystem::path &in,
                      const std::filesystem::path &out,
                      const std::string &passphrase,
                      const KdfParams &params,
                      const std::array<unsigned char, crypto_secretbox_KEYBYTES> &key_override,
                      bool keyfile_used = false,
                      bool compress = false,
                      bool verbose = false);

    // Verify if the file can be decrypted with the given passphrase/key
    bool verify_file(const std::filesystem::path &in,
                     const std::string &passphrase,
                     const KdfParams &params,
                     const std::array<unsigned char, crypto_secretbox_KEYBYTES> &key_override,
                     bool keyfile_used = false,
                     bool verbose = false);

    // Encrypt all files in a directory (recursively)               
    void encrypt_directory(const std::filesystem::path &in_dir,
                           const std::filesystem::path &out_dir,
                           const std::string &passphrase,
                           const KdfParams &params,
                           const std::array<unsigned char, crypto_secretbox_KEYBYTES> &key_override,
                           bool keyfile_used = false,
                           bool compress = false,
                           bool verbose = false);

    // Decrypt all files in a directory (recursively)
    void decrypt_directory(const std::filesystem::path &in_dir,
                           const std::filesystem::path &out_dir,
                           const std::string &passphrase,
                           const KdfParams &params,
                           const std::array<unsigned char, crypto_secretbox_KEYBYTES> &key_override,
                           bool keyfile_used = false,
                           bool compress = false,
                           bool verbose = false);

    // Compress file
    void compress_file(const std::filesystem::path &in, const std::filesystem::path &out);

    // Decompress file
    void decompress_file(const std::filesystem::path &in, const std::filesystem::path &out);

    // Generate a new random key file
    void generate_key_file(const std::filesystem::path &keyfile);

}