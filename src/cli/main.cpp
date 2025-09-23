#include "../../include/aegis/aegis_crypto.hpp"
#include "../../include/aegis/utils.hpp"
#include <iostream>
#include <filesystem>
#include <fstream>
#include <sodium.h>

using namespace aegis;

static void usage()
{
    std::cout << "Aegis v0.1 — file encryption (XChaCha20-Poly1305 via libsodium)\n";
    std::cout << "Usage:\n";
    std::cout << " aegis -h | --help\n";
    std::cout << " aegis enc -i <input> -o <output> [-p <passphrase> or -k <key_file>]\n";
    std::cout << " aegis dec -i <input> -o <output> [-p <passphrase> or -k <key_file>]\n";
    std::cout << " aegis keygen -o <key_file>\n";
    // std::cout << " aegis verify -i <input> [-p <passphrase> or -k <key_file>]\n"; // future
    std::cout << "If -p is omitted, you will be prompted (input hidden).\n";
}

int main(int argc, char **argv)
{
    try
    {
        if (argc < 2)
        {
            usage();
            return 1;
        }
        std::string mode = argv[1];
        std::string in, out, pass;
        std::array<unsigned char, crypto_secretbox_KEYBYTES> key_override = {};

        for (int i = 2; i < argc; ++i)
        {
            std::string a = argv[i];
            if (a == "-i" && i + 1 < argc)
                in = argv[++i];
            else if (a == "-o" && i + 1 < argc)
                out = argv[++i];
            else if ((a == "-p" || a == "-k") && (i + 1 < argc))
                if (a == "-p")
                    pass = argv[++i];
                else
                {
                    std::string keyfile = argv[++i];
                    std::cout << "Using key file: " << keyfile << "\n";
                    if (!utils::file_exists(keyfile))
                        throw std::runtime_error("Key file does not exist");
                    std::ifstream kf(keyfile);
                    if (!kf)
                        throw std::runtime_error("Failed to open key file");
                    std::getline(kf, pass);
                    kf.close();
                    if (pass.size() != crypto_secretbox_KEYBYTES)
                        throw std::runtime_error("Invalid key file size");
                    std::memcpy(key_override.data(), pass.data(), crypto_secretbox_KEYBYTES);
                    pass.clear(); // clear pass to avoid confusion
                }
            else if (a == "-h" || a == "--help")
            {
                usage();
                return 0;
            }
        }

        if (mode == "keygen")
        {
            std::string keyfile = out;
            if (keyfile.empty())
            {
                usage();
                return 1;
            }
            if (utils::file_exists(keyfile))
            {
                std::string resp = utils::prompt_line("Key file exists. Overwrite? (y/N): ", true);
                if (resp != "y" && resp != "Y")
                {
                    std::cout << "Aborted.\n";
                    return 0;
                }
            }
            generate_key_file(keyfile);
            std::cout << "Key file generated: " << keyfile << "\n";
            return 0;
        }

        if (in.empty() || out.empty())
        {
            usage();
            return 1;
        }

        init_crypto();
        KdfParams params{crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE};
        if (pass.empty() && utils::key_override_provided(key_override) == false)
            pass = utils::prompt_line("Passphrase: ", false); // hide the input

        if (mode == "enc")
        {
            encrypt_file(in, out, pass, params, key_override);
            std::cout << "Encrypted -> " << out << "\n";
        }
        else if (mode == "dec")
        {
            decrypt_file(in, out, pass, params, key_override);
            std::cout << "Decrypted -> " << out << "\n";
        }
        else
        {
            usage();
            return 1;
        }
        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << "\n";
        return 2;
    }
}