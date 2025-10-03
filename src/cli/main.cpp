#include "../../include/aegis/aegis_crypto.hpp"
#include "../../include/aegis/utils.hpp"
#include <iostream>
#include <filesystem>
#include <fstream>
#include <sodium.h>
#include <algorithm>

using namespace aegis;

static void usage()
{
    std::cout << "Aegis v0." << (int)VERSION << ".0 — file encryption (XChaCha20-Poly1305 via libsodium)\n";
    std::cout << "Usage:\n";
    std::cout << "  aegis <mode> [options]\n";
    std::cout << "Modes:\n";
    std::cout << "  enc      Encrypt a file\n";
    std::cout << "  dec      Decrypt a file\n";
    std::cout << "  keygen   Generate a random key file\n";
    std::cout << "  verify   Verify integrity of an encrypted file\n";
    std::cout << "Options:\n";
    std::cout << "  -i <file>    Input file (required for enc/dec/verify)\n";
    std::cout << "  -o <file>    Output file (required for enc/dec/keygen)\n";
    std::cout << "  -p <pass>    Passphrase (if omitted, will prompt; not needed if -k is used)\n";
    std::cout << "  -k <file>    Key file (32 random bytes; if used, -p is not needed)\n";
    std::cout << "  -z           Compress/Decompress file (before encryption / after decryption)\n";
    std::cout << "  -h, --help   Show this help message\n";
    std::cout << "  --version    Show version information\n";
    std::cout << "Exit codes:\n";
    std::cout << "  0   Success\n";
    std::cout << "  1   Invalid usage or arguments\n";
    std::cout << "  2   Runtime error (e.g. file I/O error, decryption failed)\n";
}

static void handle_basic_cases(int argc, char **argv)
{
    if (argc <= 2)
    {
        if (argc == 2 && (std::string(argv[1]) == "-h" || std::string(argv[1]) == "--help"))
        {
            usage();
            exit(0);
        }
        if (argc == 2 && std::string(argv[1]) == "--version")
        {
            std::cout << "Aegis version 0." << (int)VERSION << ".0\n";
            exit(0);
        }
        usage();
        exit(1);
    }
}

static void handle_mode_type(const std::string &mode)
{
    const std::array<std::string, 4> modes = {"enc", "dec", "keygen", "verify"};
    if (std::find(std::begin(modes), std::end(modes), mode) == std::end(modes))
    {
        usage();
        exit(1);
    }
}

int main(int argc, char **argv)
{
    try
    {
        handle_basic_cases(argc, argv);
        std::string mode = argv[1];
        handle_mode_type(mode);

        std::string in, out, pass;
        std::array<unsigned char, crypto_secretbox_KEYBYTES> key_override = {};
        bool keyfile_used = false;
        bool compress = false;

        for (int i = 2; i < argc; ++i)
        {
            std::string arg = argv[i];
            if (arg == "-i" && i + 1 < argc)
            {
                in = argv[++i];
            }
            else if (arg == "-o" && i + 1 < argc)
            {
                out = argv[++i];
            }
            else if (arg == "-p" && i + 1 < argc)
            {
                pass = argv[++i];
            }
            else if (arg == "-k" && i + 1 < argc)
            {
                std::string keyfile = argv[++i];
                if (!utils::file_exists(keyfile))
                {
                    std::cerr << "Key file does not exist: " << keyfile << "\n";
                    return 1;
                }
                std::ifstream kf(keyfile, std::ios::binary);
                kf.read(reinterpret_cast<char *>(key_override.data()), key_override.size());
                if (!kf || kf.gcount() != static_cast<std::streamsize>(key_override.size()))
                {
                    std::cerr << "Failed to read key file or invalid size: " << keyfile << "\n";
                    return 1;
                }
                keyfile_used = true;
            }
            else if (arg == "-z")
            {
                compress = true;
            }
            else
            {
                usage();
                return 1;
            }
        }

        if ((mode == "enc" || mode == "dec") && in.empty())
        {
            std::cerr << "Input file is required for mode " << mode << "\n";
            return 1;
        }
        if ((mode == "enc" || mode == "dec") && out.empty())
        {
            std::cerr << "Output file is required for mode " << mode << "\n";
            return 1;
        }
        if (!keyfile_used && pass.empty() && (mode == "enc" || mode == "dec"))
        {
            pass = utils::prompt_line("Enter passphrase: ", false);
            if (pass.empty())
            {
                std::cerr << "Passphrase cannot be empty\n";
                return 1;
            }
        }
        aegis::init_crypto();
        aegis::KdfParams kdf_params{crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE};

        if (mode == "enc")
        {
            if (compress)
            {
                std::string temp_compressed = out + ".compressed_tmp";
                aegis::compress_file(in, temp_compressed);
                aegis::encrypt_file(temp_compressed, out, pass, kdf_params, key_override, keyfile_used);
                std::filesystem::remove(temp_compressed);
            }
            else
            {
                aegis::encrypt_file(in, out, pass, kdf_params, key_override, keyfile_used);
            }
            std::cout << "File encrypted successfully: " << out << "\n";
        }
        else if (mode == "dec")
        {
            if (compress)
            {
                std::string temp_decrypted = out + ".decrypted_tmp";
                aegis::decrypt_file(in, temp_decrypted, pass, kdf_params, key_override, keyfile_used);
                aegis::decompress_file(temp_decrypted, out);
                std::filesystem::remove(temp_decrypted);
            }
            else
            {
                aegis::decrypt_file(in, out, pass, kdf_params, key_override, keyfile_used);
            }
            std::cout << "File decrypted successfully: " << out << "\n";
        }
        else if (mode == "keygen")
        {
            if (out.empty())
            {
                std::cerr << "Output key file is required for keygen mode\n";
                return 1;
            }

            if (utils::file_exists(out))
            {
                std::cout << "Key file already exists. Overwrite? (y/N): ";
                std::string resp;
                std::getline(std::cin, resp);
                if (resp != "y" && resp != "Y")
                {
                    std::cout << "Aborting key generation.\n";
                    return 0;
                }
                std::cout << "Overwriting key file: " << out << "\n";
            }

            aegis::generate_key_file(out);
            std::cout << "Key file generated successfully: " << out << "\n";
            return 0;
        }
        else if (mode == "verify")
        {
            bool valid = aegis::verify_file(in, pass, kdf_params, key_override, keyfile_used);
            if (valid)
                std::cout << "File integrity verified successfully.\n";
            else
                std::cout << "File integrity verification failed (corrupt or wrong passphrase/key).\n";
            return valid ? 0 : 3;
        }

        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << "\n";
        return 2;
    }
}