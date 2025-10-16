#include "../../include/aegis/aegis_crypto.hpp"
#include "../../include/aegis/utils.hpp"
#include <iostream>
#include <filesystem>
#include <fstream>
#include <sodium.h>
#include <algorithm>

using namespace aegis;

enum ExitCodes
{
    SUCCESS = 0,
    INVALID_USAGE = 1,
    RUNTIME_ERROR = 2,
    VERIFY_FAILED = 3
};

static void usage()
{
    utils::Logger::log(utils::Logger::Level::INFO, "Aegis v0." + std::to_string((int)VERSION) + ".0 — file encryption (XChaCha20-Poly1305 via libsodium)");
    utils::Logger::log(utils::Logger::Level::INFO, "Usage:");
    utils::Logger::log(utils::Logger::Level::INFO, "  aegis <mode> [options]");
    utils::Logger::log(utils::Logger::Level::INFO, "Modes:");
    utils::Logger::log(utils::Logger::Level::INFO, "  enc      Encrypt a file/directory");
    utils::Logger::log(utils::Logger::Level::INFO, "  dec      Decrypt a file/directory");
    utils::Logger::log(utils::Logger::Level::INFO, "  keygen   Generate a random key file");
    utils::Logger::log(utils::Logger::Level::INFO, "  verify   Verify integrity of an encrypted file");
    utils::Logger::log(utils::Logger::Level::INFO, "Options:");
    utils::Logger::log(utils::Logger::Level::INFO, "  -i <file>    Input file (required for enc/dec/verify)");
    utils::Logger::log(utils::Logger::Level::INFO, "  -o <file>    Output file (required for enc/dec/keygen)");
    utils::Logger::log(utils::Logger::Level::INFO, "  -p <pass>    Passphrase (if omitted, will prompt; not needed if -k is used)");
    utils::Logger::log(utils::Logger::Level::INFO, "  -k <file>    Key file (32 random bytes; if used, -p is not needed)");
    utils::Logger::log(utils::Logger::Level::INFO, "  -z           Compress/Decompress file (before encryption / after decryption)");
    utils::Logger::log(utils::Logger::Level::INFO, "  -r           Recursive (for directory encryption/decryption)");
    utils::Logger::log(utils::Logger::Level::INFO, "  -v           Verbose output (extra logging)");
    utils::Logger::log(utils::Logger::Level::INFO, "  -h, --help   Show this help message");
    utils::Logger::log(utils::Logger::Level::INFO, "  --version    Show version information");
    utils::Logger::log(utils::Logger::Level::INFO, "Exit codes:");
    utils::Logger::log(utils::Logger::Level::INFO, "  0   Success");
    utils::Logger::log(utils::Logger::Level::INFO, "  1   Invalid usage or arguments");
    utils::Logger::log(utils::Logger::Level::INFO, "  2   Runtime error (e.g. file I/O error, decryption failed)");
    utils::Logger::log(utils::Logger::Level::INFO, "  3   Verification failed (file corrupt or wrong passphrase/key)");
}

static void handle_basic_cases(int argc, char **argv)
{
    if (argc <= 2)
    {
        if (argc == 2 && (std::string(argv[1]) == "-h" || std::string(argv[1]) == "--help"))
        {
            usage();
            exit(SUCCESS);
        }
        if (argc == 2 && std::string(argv[1]) == "--version")
        {
            utils::Logger::log(utils::Logger::Level::INFO, "Aegis version 0." + std::to_string((int)VERSION) + ".0");
            exit(SUCCESS);
        }
        usage();
        exit(INVALID_USAGE);
    }
}

static void handle_mode_type(const std::string &mode)
{
    const std::array<std::string, 4> modes = {"enc", "dec", "keygen", "verify"};
    if (std::find(std::begin(modes), std::end(modes), mode) == std::end(modes))
    {
        usage();
        exit(INVALID_USAGE);
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
        bool recursive = false;
        bool verbose = false;

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
                    utils::Logger::log(utils::Logger::Level::ERROR, "Key file does not exist: " + keyfile);
                    return INVALID_USAGE;
                }
                std::ifstream kf(keyfile, std::ios::binary);
                kf.read(reinterpret_cast<char *>(key_override.data()), key_override.size());
                if (!kf || kf.gcount() != static_cast<std::streamsize>(key_override.size()))
                {
                    utils::Logger::log(utils::Logger::Level::ERROR, "Failed to read key file or invalid size: " + keyfile);
                    return RUNTIME_ERROR;
                }
                keyfile_used = true;
            }
            else if (arg == "-z")
            {
                compress = true;
            }
            else if (arg == "-r")
            {
                recursive = true;
            }
            else if (arg == "-v")
            {
                verbose = true;
            }
            else
            {
                usage();
                return INVALID_USAGE;
            }
        }

        if ((mode == "enc" || mode == "dec") && in.empty())
        {
            utils::Logger::log(utils::Logger::Level::ERROR, "Input file is required for mode " + mode);
            return INVALID_USAGE;
        }
        if ((mode == "enc" || mode == "dec") && out.empty())
        {
            utils::Logger::log(utils::Logger::Level::ERROR, "Output file is required for mode " + mode);
            return INVALID_USAGE;
        }
        if (!keyfile_used && pass.empty() && (mode == "enc" || mode == "dec"))
        {
            pass = utils::prompt_line("Enter passphrase: ", false);
            if (pass.empty())
            {
                utils::Logger::log(utils::Logger::Level::ERROR, "Passphrase cannot be empty");
                return INVALID_USAGE;
            }
        }
        aegis::init_crypto();
        aegis::KdfParams kdf_params{crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE};

        if (mode == "enc")
        {
            std::filesystem::path in_path(in);
            std::filesystem::path out_path(out);
            if (std::filesystem::is_directory(in_path))
            {
                if (!recursive)
                {
                    utils::Logger::log(utils::Logger::Level::ERROR, "Input is a directory; use -r for recursive encryption");
                    return INVALID_USAGE;
                }
                aegis::encrypt_directory(in_path, out_path, pass, kdf_params, key_override, keyfile_used, compress, verbose);
            }
            else
            {
                aegis::encrypt_file(in_path, out_path, pass, kdf_params, key_override, keyfile_used, compress, verbose);
                utils::Logger::log(utils::Logger::Level::INFO, "File encrypted successfully: " + out);
            }
        }
        else if (mode == "dec")
        {

            std::filesystem::path in_path(in);
            std::filesystem::path out_path(out);
            if (std::filesystem::is_directory(in_path))
            {
                if (!recursive)
                {
                    utils::Logger::log(utils::Logger::Level::ERROR, "Input is a directory; use -r for recursive decryption");
                    return INVALID_USAGE;
                }
                aegis::decrypt_directory(in_path, out_path, pass, kdf_params, key_override, keyfile_used, compress, verbose);
            }
            else
            {
                aegis::decrypt_file(in_path, out_path, pass, kdf_params, key_override, keyfile_used, compress, verbose);
                utils::Logger::log(utils::Logger::Level::INFO, "File decrypted successfully: " + out);
            }
        }
        else if (mode == "keygen")
        {
            if (out.empty())
            {
                utils::Logger::log(utils::Logger::Level::ERROR, "Output key file is required for keygen mode");
                return INVALID_USAGE;
            }

            if (utils::file_exists(out))
            {
                utils::Logger::log(utils::Logger::Level::WARNING, "Key file already exists: " + out);
                std::cout << "Overwrite? (y/N): ";
                std::string resp;
                std::getline(std::cin, resp);
                if (resp != "y" && resp != "Y")
                {
                    utils::Logger::log(utils::Logger::Level::INFO, "Aborting key file generation.");
                    return SUCCESS;
                }
                utils::Logger::log(utils::Logger::Level::INFO, "Overwriting existing key file.");
            }

            aegis::generate_key_file(out);
            utils::Logger::log(utils::Logger::Level::INFO, "Key file generated successfully: " + out);
            return SUCCESS;
        }
        else if (mode == "verify")
        {
            bool valid = aegis::verify_file(in, pass, kdf_params, key_override, keyfile_used, verbose);
            if (valid)
                utils::Logger::log(utils::Logger::Level::INFO, "File integrity verified successfully.");
            else
                utils::Logger::log(utils::Logger::Level::ERROR, "File integrity verification failed (corrupt or wrong passphrase/key).");
            return valid ? SUCCESS : VERIFY_FAILED;
        }

        return SUCCESS;
    }
    catch (const std::exception &e)
    {
        utils::Logger::log(utils::Logger::Level::ERROR, std::string(e.what()));
        return RUNTIME_ERROR;
    }
}