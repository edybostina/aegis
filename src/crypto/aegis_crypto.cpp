#include "../../include/aegis/aegis_crypto.hpp"
#include "../../include/aegis/file_io.hpp"
#include "../../include/aegis/utils.hpp"
#include <array>
#include <vector>
#include <stdexcept>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>

namespace
{
    constexpr const char *MAGIC = "AEGIS\x00"; // 6 bytes, includes null sentinel
    constexpr unsigned char VERSION = 1;
}

namespace aegis
{
    void init_crypto()
    {
        if (sodium_init() < 0)
            throw std::runtime_error("libsodium initialization failed");
    }

    std::array<unsigned char, 32> derive_key_from_passphrase_enc(
        const std::string &passphrase,
        std::array<unsigned char, 16> &out_salt,
        const KdfParams &params)
    {
        randombytes_buf(out_salt.data(), out_salt.size());
        std::array<unsigned char, 32> key{};
        if (crypto_pwhash(key.data(), key.size(), passphrase.c_str(), passphrase.size(),
                          out_salt.data(), params.ops_limit, params.mem_limit,
                          crypto_pwhash_ALG_DEFAULT) != 0)
        {
            throw std::runtime_error("Out of memory in pwhash");
        }
        return key;
    }

    std::array<unsigned char, 32> derive_key_from_passphrase_dec(
        const std::string &passphrase,
        const std::array<unsigned char, 16> &salt,
        const KdfParams &params)
    {
        std::array<unsigned char, 32> key{};
        if (crypto_pwhash(key.data(), key.size(), passphrase.c_str(), passphrase.size(),
                          salt.data(), params.ops_limit, params.mem_limit,
                          crypto_pwhash_ALG_DEFAULT) != 0)
        {
            throw std::runtime_error("Out of memory in pwhash");
        }
        return key;
    }

    void encrypt_file(const std::filesystem::path &in,
                      const std::filesystem::path &out,
                      const std::string &passphrase,
                      const KdfParams &params,
                      const std::array<unsigned char, crypto_secretbox_KEYBYTES> &key_override,
                      bool keyfile_used)
    {
        int fd_in = io::open_readonly(in);
        int fd_out = io::open_readwrite(out);

        // write the header
        // format : magic | version | salt | stream header
        io::write_all(fd_out, reinterpret_cast<const unsigned char *>(MAGIC), 6);
        io::write_all(fd_out, &VERSION, 1);

        std::array<unsigned char, 16> salt{};
        auto key = keyfile_used
                       ? key_override
                       : derive_key_from_passphrase_enc(passphrase, salt, params);

        io::write_all(fd_out, salt.data(), salt.size());

        crypto_secretstream_xchacha20poly1305_state state{};
        std::array<unsigned char, crypto_secretstream_xchacha20poly1305_HEADERBYTES> header{};
        if (crypto_secretstream_xchacha20poly1305_init_push(&state, header.data(), key.data()) != 0)
            throw std::runtime_error("secretstream init_push failed");
        sodium_memzero(key.data(), key.size());

        io::write_all(fd_out, header.data(), header.size());

        const size_t CHUNK = 64 * 1024;
        std::vector<unsigned char> buf;
        while (true)
        {
            buf = io::read_chunk(fd_in, CHUNK);
            if (buf.empty())
                break;
            unsigned char tag = 0;
            if (buf.size() < CHUNK)
                tag = crypto_secretstream_xchacha20poly1305_TAG_FINAL;
            std::vector<unsigned char> outbuf(buf.size() + crypto_secretstream_xchacha20poly1305_ABYTES);
            unsigned long long outlen = 0ULL;
            if (crypto_secretstream_xchacha20poly1305_push(&state, outbuf.data(), &outlen,
                                                           buf.data(), buf.size(), nullptr, 0, tag) != 0)
                throw std::runtime_error("secretstream push failed");
            io::write_all(fd_out, outbuf.data(), static_cast<size_t>(outlen));
        }
        close(fd_in);
        close(fd_out);
    }

    void decrypt_file(const std::filesystem::path &in,
                      const std::filesystem::path &out,
                      const std::string &passphrase,
                      const KdfParams &params,
                      const std::array<unsigned char, crypto_secretbox_KEYBYTES> &key_override,
                      bool keyfile_used)
    {
        int fd_in = io::open_readonly(in);
        int fd_out = io::open_readwrite(out);

        // Read header
        std::array<unsigned char, 6> magic{};
        auto m = io::read_chunk(fd_in, magic.size());
        if (m.size() != magic.size() || std::memcmp(m.data(), MAGIC, 6) != 0)
            throw std::runtime_error("Not an Aegis file (bad magic)");

        auto ver = io::read_chunk(fd_in, 1);
        if (ver.size() != 1 || ver[0] != VERSION)
            throw std::runtime_error("Unsupported Aegis version");

        std::array<unsigned char, 16> salt{};
        auto saltv = io::read_chunk(fd_in, salt.size());
        if (saltv.size() != salt.size())
            throw std::runtime_error("Truncated salt");
        std::memcpy(salt.data(), saltv.data(), salt.size());

        std::array<unsigned char, crypto_secretbox_KEYBYTES> key = keyfile_used
                                                                      ? key_override
                                                                      : derive_key_from_passphrase_dec(passphrase, salt, params);

        std::array<unsigned char, crypto_secretstream_xchacha20poly1305_HEADERBYTES> header{};
        auto hv = io::read_chunk(fd_in, header.size());
        if (hv.size() != header.size())
            throw std::runtime_error("Truncated header");
        std::memcpy(header.data(), hv.data(), header.size());

        crypto_secretstream_xchacha20poly1305_state state{};
        if (crypto_secretstream_xchacha20poly1305_init_pull(&state, header.data(), key.data()) != 0)
            throw std::runtime_error("secretstream init_pull failed");
        sodium_memzero(key.data(), key.size());

        const size_t CHUNK = 64 * 1024 + crypto_secretstream_xchacha20poly1305_ABYTES;
        bool done = false;
        while (!done)
        {
            std::vector<unsigned char> enc = io::read_chunk(fd_in, CHUNK);
            if (enc.empty())
                break; // graceful end
            std::vector<unsigned char> outbuf(enc.size());
            unsigned long long outlen = 0ULL;
            unsigned char tag = 0;
            if (crypto_secretstream_xchacha20poly1305_pull(&state, outbuf.data(), &outlen, &tag,
                                                           enc.data(), enc.size(), nullptr, 0) != 0)
                throw std::runtime_error("Decryption failed (corrupt or wrong passphrase)");
            if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL)
                done = true;
            io::write_all(fd_out, outbuf.data(), static_cast<size_t>(outlen));
        }
        close(fd_in);
        close(fd_out);
    }

    void generate_key_file(const std::filesystem::path &keyfile)
    {
        int fd = io::open_readwrite(keyfile);
        std::array<unsigned char, crypto_secretbox_KEYBYTES> key{};
        randombytes_buf(key.data(), key.size());
        io::write_all(fd, key.data(), key.size());
        close(fd);
    }

}