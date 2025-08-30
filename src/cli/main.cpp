#include "../../include/aegis/aegis_crypto.hpp"
#include "../../include/aegis/utils.hpp"
#include <iostream>
#include <filesystem>
#include <sodium.h>

using namespace aegis;

static void usage()
{
    std::cout << "Aegis v0.1 — file encryption (XChaCha20-Poly1305 via libsodium)\n";
    std::cout << "Usage:\n";
    std::cout << " aegis -h | --help\n";
    std::cout << " aegis enc -i <input> -o <output> [-p <passphrase>]\n";
    std::cout << " aegis dec -i <input> -o <output> [-p <passphrase>]\n";
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
        for (int i = 2; i < argc; ++i)
        {
            std::string a = argv[i];
            if (a == "-i" && i + 1 < argc)
                in = argv[++i];
            else if (a == "-o" && i + 1 < argc)
                out = argv[++i];
            else if (a == "-p" && i + 1 < argc)
                pass = argv[++i];
            else if (a == "-h" || a == "--help")
            {
                usage();
                return 0;
            }
        }
        if (in.empty() || out.empty())
        {
            usage();
            return 1;
        }

        init_crypto();
        KdfParams params{crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE};

        if (pass.empty())
            pass = utils::prompt_line("Passphrase: ", false); // hide the input

        if (mode == "enc")
        {
            encrypt_file(in, out, pass, params);
            std::cout << "Encrypted -> " << out << "\n";
        }
        else if (mode == "dec")
        {
            decrypt_file(in, out, pass, params);
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