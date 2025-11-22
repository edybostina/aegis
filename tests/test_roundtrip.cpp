#include "aegis/aegis_crypto.hpp"
#include <fstream>
#include <string>
#include <cstdio>
#include <sodium.h>
#include <iostream>
#include <array>
#include <filesystem>

int main()
{
    using namespace aegis;
    init_crypto();
    KdfParams params{crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_MEMLIMIT_MIN};
    const std::string pass = "testpass";

    // Use cross-platform temporary directory
    auto temp_dir = std::filesystem::temp_directory_path();
    auto in_file = temp_dir / "aegis_in.txt";
    auto enc_file = temp_dir / "aegis_in.txt.enc";
    auto out_file = temp_dir / "aegis_out.txt";

    std::ofstream f(in_file);
    f << "hello aegis";
    f.close();

    std::array<unsigned char, 32> empty_key{};
    bool keyfile_used = false;

    encrypt_file(in_file, enc_file, pass, params, empty_key, keyfile_used, false);
    decrypt_file(enc_file, out_file, pass, params, empty_key, keyfile_used, false);

    std::ifstream g(out_file);
    std::string out;
    std::getline(g, out);
    if (out != "hello aegis")
    {
        std::cerr << "Decrypted output does not match original input" << std::endl;
        return 1;
    }

    std::filesystem::remove(in_file);
    std::filesystem::remove(enc_file);
    std::filesystem::remove(out_file);
    std::cout << "Roundtrip test passed" << std::endl;
    return 0;
}