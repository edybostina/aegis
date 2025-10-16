#include "aegis/aegis_crypto.hpp"
#include <fstream>
#include <string>
#include <cstdio>
#include <sodium.h>
#include <iostream>
#include <array>

int main()
{
    using namespace aegis;
    init_crypto();
    KdfParams params{crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_MEMLIMIT_MIN};
    const std::string pass = "testpass";

    std::ofstream f("/tmp/aegis_in.txt");
    f << "hello aegis";
    f.close();

    std::array<unsigned char, 32> empty_key{};
    bool keyfile_used = false;

    encrypt_file("/tmp/aegis_in.txt", "/tmp/aegis_in.txt.enc", pass, params, empty_key, keyfile_used, true);
    decrypt_file("/tmp/aegis_in.txt.enc", "/tmp/aegis_out.txt", pass, params, empty_key, keyfile_used, true);

    std::ifstream g("/tmp/aegis_out.txt");
    std::string out;
    std::getline(g, out);
    if (out != "hello aegis")
    {
        std::cerr << "Decrypted output does not match original input" << std::endl;
        return 1;
    }

    std::remove("/tmp/aegis_in.txt");
    std::remove("/tmp/aegis_in.txt.enc");
    std::remove("/tmp/aegis_out.txt");
    std::cout << "Roundtrip test passed" << std::endl;
    return 0;
}