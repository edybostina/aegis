#include "aegis/aegis_crypto.hpp"
#include "aegis/file_io.hpp"
#include "aegis/utils.hpp"
#include <array>
#include <vector>
#include <stdexcept>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>

namespace aegis
{
    void init_crypto()
    {
        if (sodium_init() < 0)
            throw std::runtime_error("libsodium initialization failed");
    }

    std::array<unsigned char, crypto_secretbox_KEYBYTES> derive_key_from_passphrase_enc(
        const std::string &passphrase,
        std::array<unsigned char, 16> &out_salt,
        const KdfParams &params)
    {
        randombytes_buf(out_salt.data(), out_salt.size());
        std::array<unsigned char, crypto_secretbox_KEYBYTES> key{};
        if (crypto_pwhash(key.data(), key.size(), passphrase.c_str(), passphrase.size(),
                          out_salt.data(), params.ops_limit, params.mem_limit,
                          crypto_pwhash_ALG_DEFAULT) != 0)
        {
            throw std::runtime_error("Out of memory in pwhash");
        }
        return key;
    }

    std::array<unsigned char, crypto_secretbox_KEYBYTES> derive_key_from_passphrase_dec(
        const std::string &passphrase,
        const std::array<unsigned char, 16> &salt,
        const KdfParams &params)
    {
        std::array<unsigned char, crypto_secretbox_KEYBYTES> key{};
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
                      bool keyfile_used,
                      bool compress,
                      bool verbose)
    {
        if (verbose)
            utils::Logger::log(utils::Logger::Level::INFO, "Starting the encryption process...");

        int fd_in = io::open_readonly(in);
        int fd_out = io::open_readwrite(out);

        if (verbose)
        {
            utils::Logger::log(utils::Logger::Level::INFO, "Input file: " + in.string());
            utils::Logger::log(utils::Logger::Level::INFO, "Output file: " + out.string());
            utils::Logger::log(utils::Logger::Level::INFO, std::string("Compression: ") + (compress ? "enabled" : "disabled"));
            utils::Logger::log(utils::Logger::Level::INFO, std::string("Key source: ") + (keyfile_used ? "keyfile" : "passphrase"));
        }

        if (compress)
        {
            // create a temporary compressed file
            std::string temp_compressed = out.string() + ".compressed_tmp";
            if (verbose)
                utils::Logger::log(utils::Logger::Level::INFO, "Compressing input file to temporary file: " + temp_compressed);
            compress_file(in, temp_compressed);
            close(fd_in);
            fd_in = io::open_readonly(temp_compressed);
            std::filesystem::remove(temp_compressed);

            if (verbose)
                utils::Logger::log(utils::Logger::Level::INFO, "Compression completed.");
        }

        // write the header
        // format : magic | version | compress | salt | stream header
        io::write_all(fd_out, reinterpret_cast<const unsigned char *>(MAGIC), 6);
        io::write_all(fd_out, &VERSION, 1);
        io::write_all(fd_out, reinterpret_cast<const unsigned char *>(compress ? "\x01" : "\x00"), 1); // 1 byte compress flag

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

        const size_t total_size_estimate = std::filesystem::file_size(in);
        size_t current_encrypted_size = 0;

        if (verbose)
            utils::Logger::log(utils::Logger::Level::INFO, "Encrypting data stream...");

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
            current_encrypted_size += static_cast<size_t>(outlen);
            // print progress
            if (total_size_estimate > 0)
            {
                int percent = static_cast<int>(100.0 * current_encrypted_size / total_size_estimate);
                percent = std::min(percent, 99); // cap at 99%
                utils::progress_bar(percent, "Encrypting:", "");
            }
        }
        utils::progress_bar(100, "Encrypting:", ""); // ensure 100% at end

        close(fd_in);
        close(fd_out);

        if (verbose)
            utils::Logger::log(utils::Logger::Level::INFO, "Encryption completed.");
    }

    void decrypt_file(const std::filesystem::path &in,
                      const std::filesystem::path &out,
                      const std::string &passphrase,
                      const KdfParams &params,
                      const std::array<unsigned char, crypto_secretbox_KEYBYTES> &key_override,
                      bool keyfile_used,
                      bool compress,
                      bool verbose)
    {
        if (verbose)
            utils::Logger::log(utils::Logger::Level::INFO, "Starting the decryption process...");

        int fd_in = io::open_readonly(in);
        int fd_out = io::open_readwrite(out);

        if (verbose)
        {
            utils::Logger::log(utils::Logger::Level::INFO, "Input file: " + in.string());
            utils::Logger::log(utils::Logger::Level::INFO, "Output file: " + out.string());
            utils::Logger::log(utils::Logger::Level::INFO, std::string("Compression: ") + (compress ? "enabled" : "disabled"));
            utils::Logger::log(utils::Logger::Level::INFO, std::string("Key source: ") + (keyfile_used ? "keyfile" : "passphrase"));
        }

        // Read header
        std::array<unsigned char, 6> magic{};
        auto m = io::read_chunk(fd_in, magic.size());
        if (m.size() != magic.size() || std::memcmp(m.data(), MAGIC, 6) != 0)
            throw std::runtime_error("Not an Aegis file (bad magic)");

        auto ver = io::read_chunk(fd_in, 1);
        if (ver.size() != 1 || ver[0] != VERSION)
            throw std::runtime_error("Unsupported Aegis version");

        auto comp = io::read_chunk(fd_in, 1);
        if (comp.size() != 1 || (comp[0] != 0x00 && comp[0] != 0x01))
            throw std::runtime_error("Unsupported compression flag");
        bool file_compressed = (comp[0] == 0x01);
        if (file_compressed != compress)
            throw std::runtime_error("Compression flag mismatch (use -z if needed)");

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

        const size_t total_size_estimate = std::filesystem::file_size(in);
        size_t current_decrypted_size = 0;

        if (verbose)
            utils::Logger::log(utils::Logger::Level::INFO, "Decrypting data stream...");

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
            current_decrypted_size += static_cast<size_t>(outlen);
            // print progress
            if (total_size_estimate > 0)
            {
                int percent = static_cast<int>(100.0 * current_decrypted_size / total_size_estimate);
                percent = std::min(percent, 99); // cap at 99%
                utils::progress_bar(percent, "Decrypting:", "");
            }
        }
        utils::progress_bar(100, "Decrypting:", ""); // ensure 100% at end

        if (compress && file_compressed)
        {
            // decompress the output file in place
            close(fd_out);
            if (verbose)
                utils::Logger::log(utils::Logger::Level::INFO, "Decompressing output file in place...");
            decompress_file(out, out.string() + ".decompressed_tmp");
            std::filesystem::remove(out);
            std::filesystem::rename(out.string() + ".decompressed_tmp", out);
            if (verbose)
                utils::Logger::log(utils::Logger::Level::INFO, "Decompression completed.");
        }
        close(fd_in);
        close(fd_out);
        if (verbose)
            utils::Logger::log(utils::Logger::Level::INFO, "Decryption completed.");
    }

    bool verify_file(const std::filesystem::path &in,
                     const std::string &passphrase,
                     const KdfParams &params,
                     const std::array<unsigned char, crypto_secretbox_KEYBYTES> &key_override,
                     bool keyfile_used,
                     bool verbose)
    {
        if (verbose)
            utils::Logger::log(utils::Logger::Level::INFO, "Starting the verification process...");
        // Same as decrypt_file but without writing output
        int fd_in = io::open_readonly(in);

        if (verbose)
        {
            utils::Logger::log(utils::Logger::Level::INFO, "Input file: " + in.string());
            utils::Logger::log(utils::Logger::Level::INFO, std::string("Key source: ") + (keyfile_used ? "keyfile" : "passphrase"));
        }

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
        size_t current_decrypted_size = 0;
        const size_t total_size_estimate = std::filesystem::file_size(in);

        if (verbose)
            utils::Logger::log(utils::Logger::Level::INFO, "Verifying data stream...");

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
                return false; // Decryption failed (corrupt or wrong passphrase)
            if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL)
                done = true;

            current_decrypted_size += static_cast<size_t>(outlen);
            // print progress
            if (total_size_estimate > 0)
            {
                int percent = static_cast<int>(100.0 * current_decrypted_size / total_size_estimate);
                percent = std::min(percent, 99); // cap at 99%
                utils::progress_bar(percent, "Verifying:", "");
            }
        }
        utils::progress_bar(100, "Verifying:", ""); // ensure 100% at end
        close(fd_in);
        return true;
    }

    void encrypt_directory(const std::filesystem::path &in_dir,
                           const std::filesystem::path &out_dir,
                           const std::string &passphrase,
                           const KdfParams &params,
                           const std::array<unsigned char, crypto_secretbox_KEYBYTES> &key_override,
                           bool keyfile_used,
                           bool compress,
                           bool verbose)
    {
        if (!std::filesystem::exists(in_dir) || !std::filesystem::is_directory(in_dir))
            throw std::runtime_error("Input directory does not exist or is not a directory");

        if (!std::filesystem::exists(out_dir))
        {
            std::filesystem::create_directories(out_dir);
            if (verbose)
                utils::Logger::log(utils::Logger::Level::INFO, "Created output directory: " + out_dir.string());
        }

        for (const auto &entry : std::filesystem::recursive_directory_iterator(in_dir))
        {
            if (entry.is_regular_file())
            {
                auto relative_path = std::filesystem::relative(entry.path(), in_dir);
                auto out_path = out_dir / relative_path;
                auto out_parent = out_path.parent_path();
                if (!std::filesystem::exists(out_parent))
                    std::filesystem::create_directories(out_parent);

                utils::Logger::log(utils::Logger::Level::INFO, "Encrypting: " + entry.path().string() + " -> " + out_path.string());
                encrypt_file(entry.path(), out_path, passphrase, params, key_override, keyfile_used, compress, verbose);
            }
        }
    }

    void decrypt_directory(const std::filesystem::path &in_dir,
                           const std::filesystem::path &out_dir,
                           const std::string &passphrase,
                           const KdfParams &params,
                           const std::array<unsigned char, crypto_secretbox_KEYBYTES> &key_override,
                           bool keyfile_used,
                           bool compress,
                           bool verbose)
    {
        if (!std::filesystem::exists(in_dir) || !std::filesystem::is_directory(in_dir))
            throw std::runtime_error("Input directory does not exist or is not a directory");

        if (!std::filesystem::exists(out_dir))
        {
            std::filesystem::create_directories(out_dir);
            if (verbose)
                utils::Logger::log(utils::Logger::Level::INFO, "Created output directory: " + out_dir.string());
        }

        for (const auto &entry : std::filesystem::recursive_directory_iterator(in_dir))
        {
            if (entry.is_regular_file())
            {
                auto relative_path = std::filesystem::relative(entry.path(), in_dir);
                auto out_path = out_dir / relative_path;
                auto out_parent = out_path.parent_path();
                if (!std::filesystem::exists(out_parent))
                    std::filesystem::create_directories(out_parent);

                utils::Logger::log(utils::Logger::Level::INFO, "Decrypting: " + entry.path().string() + " -> " + out_path.string());
                decrypt_file(entry.path(), out_path, passphrase, params, key_override, keyfile_used, compress, verbose);
            }
        }
    }

    void compress_file(const std::filesystem::path &in, const std::filesystem::path &out)
    {
        int fd_in = io::open_readonly(in);
        int fd_out = io::open_readwrite(out);

        const size_t CHUNK = 64 * 1024;
        std::vector<unsigned char> inbuf(CHUNK);
        std::vector<unsigned char> outbuf(compressBound(CHUNK));

        z_stream strm{};
        if (deflateInit(&strm, Z_DEFAULT_COMPRESSION) != Z_OK)
            throw std::runtime_error("deflateInit failed");

        while (true)
        {
            auto r = io::read_chunk(fd_in, CHUNK);
            if (r.empty())
                break;
            strm.avail_in = r.size();
            strm.next_in = r.data();

            do
            {
                strm.avail_out = outbuf.size();
                strm.next_out = outbuf.data();
                if (deflate(&strm, Z_NO_FLUSH) == Z_STREAM_ERROR)
                {
                    deflateEnd(&strm);
                    throw std::runtime_error("deflate failed");
                }
                size_t have = outbuf.size() - strm.avail_out;
                if (have > 0)
                    io::write_all(fd_out, outbuf.data(), have);
            } while (strm.avail_out == 0);
        }

        // finish compression
        int ret;
        do
        {
            strm.avail_out = outbuf.size();
            strm.next_out = outbuf.data();
            ret = deflate(&strm, Z_FINISH);
            if (ret == Z_STREAM_ERROR)
            {
                deflateEnd(&strm);
                throw std::runtime_error("deflate finish failed");
            }
            size_t have = outbuf.size() - strm.avail_out;
            if (have > 0)
                io::write_all(fd_out, outbuf.data(), have);
        } while (ret != Z_STREAM_END);

        deflateEnd(&strm);
        close(fd_in);
        close(fd_out);
    }

    void decompress_file(const std::filesystem::path &in, const std::filesystem::path &out)
    {
        int fd_in = io::open_readonly(in);
        int fd_out = io::open_readwrite(out);

        const size_t CHUNK = 64 * 1024;
        std::vector<unsigned char> inbuf(CHUNK);
        std::vector<unsigned char> outbuf(CHUNK);

        z_stream strm{};
        if (inflateInit(&strm) != Z_OK)
            throw std::runtime_error("inflateInit failed");

        while (true)
        {
            auto r = io::read_chunk(fd_in, CHUNK);
            if (r.empty())
                break;
            strm.avail_in = r.size();
            strm.next_in = r.data();

            do
            {
                strm.avail_out = outbuf.size();
                strm.next_out = outbuf.data();
                if (inflate(&strm, Z_NO_FLUSH) == Z_STREAM_ERROR)
                {
                    inflateEnd(&strm);
                    throw std::runtime_error("inflate failed");
                }
                size_t have = outbuf.size() - strm.avail_out;
                if (have > 0)
                    io::write_all(fd_out, outbuf.data(), have);
            } while (strm.avail_out == 0);
        }

        inflateEnd(&strm);
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