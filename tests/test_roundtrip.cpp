#include "aegis/aegis_crypto.hpp"
#include <fstream>
#include <string>
#include <cstdio>
#include <sodium.h>
#include <iostream>
#include <array>
#include <filesystem>
#include <vector>
#include <cstring>

using namespace aegis;

// Test counter
int tests_run = 0;
int tests_passed = 0;

#define TEST(name)                                           \
    std::cout << "Running: " << name << "..." << std::flush; \
    tests_run++;                                             \
    try                                                      \
    {

#define END_TEST                                         \
    tests_passed++;                                      \
    std::cout << " PASS" << std::endl;                   \
    }                                                    \
    catch (const std::exception &e)                      \
    {                                                    \
        std::cout << " FAIL: " << e.what() << std::endl; \
    }

#define ASSERT(condition, message)         \
    if (!(condition))                      \
    {                                      \
        throw std::runtime_error(message); \
    }

bool files_equal(const std::filesystem::path &f1, const std::filesystem::path &f2)
{
    std::ifstream file1(f1, std::ios::binary);
    std::ifstream file2(f2, std::ios::binary);

    if (!file1.is_open() || !file2.is_open())
        return false;

    std::vector<char> buf1((std::istreambuf_iterator<char>(file1)), std::istreambuf_iterator<char>());
    std::vector<char> buf2((std::istreambuf_iterator<char>(file2)), std::istreambuf_iterator<char>());

    return buf1 == buf2;
}

void create_test_file(const std::filesystem::path &path, const std::string &content)
{
    std::ofstream f(path, std::ios::binary);
    f << content;
    f.close();
}

void create_binary_file(const std::filesystem::path &path, size_t size)
{
    std::ofstream f(path, std::ios::binary);
    std::vector<unsigned char> data(size);
    randombytes_buf(data.data(), size);
    f.write(reinterpret_cast<const char *>(data.data()), size);
    f.close();
}

int main()
{
    init_crypto();
    KdfParams params{crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_MEMLIMIT_MIN};
    auto temp_dir = std::filesystem::temp_directory_path();
    std::array<unsigned char, 32> empty_key{};

    std::cout << "=== Aegis Test Suite ===" << std::endl;
    std::cout << "Temp directory: " << temp_dir << std::endl
              << std::endl;

    // basic passphrase encryption/decryption
    TEST("Basic passphrase encryption/decryption")
    auto in1 = temp_dir / "test1_in.txt";
    auto enc1 = temp_dir / "test1.enc";
    auto out1 = temp_dir / "test1_out.txt";

    create_test_file(in1, "hello aegis");
    encrypt_file(in1, enc1, "testpass", params, empty_key, false, false);
    decrypt_file(enc1, out1, "testpass", params, empty_key, false, false);

    ASSERT(files_equal(in1, out1), "Decrypted file doesn't match original");
    ASSERT(std::filesystem::file_size(enc1) > 0, "Encrypted file is empty");

    std::filesystem::remove(in1);
    std::filesystem::remove(enc1);
    std::filesystem::remove(out1);
    END_TEST

    // encryption with compression
    TEST("Encryption with compression")
    auto in2 = temp_dir / "test2_in.txt";
    auto enc2 = temp_dir / "test2.enc";
    auto out2 = temp_dir / "test2_out.txt";

    std::string compressible;
    for (int i = 0; i < 1000; i++)
        compressible += "This is a test of compression. ";
    create_test_file(in2, compressible);

    encrypt_file(in2, enc2, "testpass", params, empty_key, false, true);
    decrypt_file(enc2, out2, "testpass", params, empty_key, false, true);

    ASSERT(files_equal(in2, out2), "Decrypted file doesn't match original");

    std::filesystem::remove(in2);
    std::filesystem::remove(enc2);
    std::filesystem::remove(out2);
    END_TEST

    // key file encryption/decryption
    TEST("Key file encryption/decryption")
    auto in3 = temp_dir / "test3_in.txt";
    auto enc3 = temp_dir / "test3.enc";
    auto out3 = temp_dir / "test3_out.txt";
    auto keyfile = temp_dir / "test3.key";

    create_test_file(in3, "secret data");

    // generate key file
    generate_key_file(keyfile);

    // read key file
    std::ifstream kf(keyfile, std::ios::binary);
    std::array<unsigned char, 32> key{};
    kf.read(reinterpret_cast<char *>(key.data()), 32);
    kf.close();

    encrypt_file(in3, enc3, "", params, key, true, false);
    decrypt_file(enc3, out3, "", params, key, true, false);

    ASSERT(files_equal(in3, out3), "Decrypted file doesn't match original");

    std::filesystem::remove(in3);
    std::filesystem::remove(enc3);
    std::filesystem::remove(out3);
    std::filesystem::remove(keyfile);
    END_TEST

    // empty file encryption/decryption
    TEST("Empty file encryption/decryption")
    auto in4 = temp_dir / "test4_in.txt";
    auto enc4 = temp_dir / "test4.enc";
    auto out4 = temp_dir / "test4_out.txt";

    create_test_file(in4, "");
    encrypt_file(in4, enc4, "testpass", params, empty_key, false, false);
    decrypt_file(enc4, out4, "testpass", params, empty_key, false, false);

    ASSERT(std::filesystem::file_size(out4) == 0, "Empty file not preserved");

    std::filesystem::remove(in4);
    std::filesystem::remove(enc4);
    std::filesystem::remove(out4);
    END_TEST

    // binary file encryption/decryption
    TEST("Binary file encryption/decryption")
    auto in5 = temp_dir / "test5_in.bin";
    auto enc5 = temp_dir / "test5.enc";
    auto out5 = temp_dir / "test5_out.bin";

    create_binary_file(in5, 1024);
    encrypt_file(in5, enc5, "testpass", params, empty_key, false, false);
    decrypt_file(enc5, out5, "testpass", params, empty_key, false, false);

    ASSERT(files_equal(in5, out5), "Decrypted binary file doesn't match original");

    std::filesystem::remove(in5);
    std::filesystem::remove(enc5);
    std::filesystem::remove(out5);
    END_TEST

    // large file encryption/decryption
    TEST("Large file encryption/decryption")
    auto in6 = temp_dir / "test6_in.bin";
    auto enc6 = temp_dir / "test6.enc";
    auto out6 = temp_dir / "test6_out.bin";

    create_binary_file(in6, 1024 * 1024);
    encrypt_file(in6, enc6, "testpass", params, empty_key, false, false);
    decrypt_file(enc6, out6, "testpass", params, empty_key, false, false);

    ASSERT(files_equal(in6, out6), "Decrypted large file doesn't match original");

    std::filesystem::remove(in6);
    std::filesystem::remove(enc6);
    std::filesystem::remove(out6);
    END_TEST

    // verify function
    TEST("Verify function")
    auto in7 = temp_dir / "test7_in.txt";
    auto enc7 = temp_dir / "test7.enc";

    create_test_file(in7, "verify test");
    encrypt_file(in7, enc7, "testpass", params, empty_key, false, false);

    bool verified = verify_file(enc7, "testpass", params, empty_key, false);
    ASSERT(verified, "Verify should succeed with correct password");

    std::filesystem::remove(in7);
    std::filesystem::remove(enc7);
    END_TEST

    // wrong password detection
    TEST("Wrong password detection")
    auto in8 = temp_dir / "test8_in.txt";
    auto enc8 = temp_dir / "test8.enc";
    auto out8 = temp_dir / "test8_out.txt";

    create_test_file(in8, "test data");
    encrypt_file(in8, enc8, "correct", params, empty_key, false, false);

    bool failed = false;
    try
    {
        decrypt_file(enc8, out8, "wrong", params, empty_key, false, false);
    }
    catch (const std::exception &)
    {
        failed = true;
    }

    ASSERT(failed, "Should fail with wrong password");

    std::filesystem::remove(in8);
    std::filesystem::remove(enc8);
    if (std::filesystem::exists(out8))
        std::filesystem::remove(out8);
    END_TEST

    // multiline text file
    TEST("Multiline text file")
    auto in9 = temp_dir / "test9_in.txt";
    auto enc9 = temp_dir / "test9.enc";
    auto out9 = temp_dir / "test9_out.txt";

    std::string multiline = "Line 1\nLine 2\nLine 3\n\nLine 5";
    create_test_file(in9, multiline);
    encrypt_file(in9, enc9, "testpass", params, empty_key, false, false);
    decrypt_file(enc9, out9, "testpass", params, empty_key, false, false);

    ASSERT(files_equal(in9, out9), "Multiline file doesn't match");

    std::filesystem::remove(in9);
    std::filesystem::remove(enc9);
    std::filesystem::remove(out9);
    END_TEST

    // special characters in content
    TEST("Special characters in content")
    auto in10 = temp_dir / "test10_in.txt";
    auto enc10 = temp_dir / "test10.enc";
    auto out10 = temp_dir / "test10_out.txt";

    std::string special = "Special chars: !@#$%^&*(){}[]<>?/\\|`~\n";
    special += "Unicode: \xE2\x9C\x93 \xE2\x9D\x8C\n";
    special += "Null bytes: ";
    special += '\0';
    special += '\0';
    special += " end";

    create_test_file(in10, special);
    encrypt_file(in10, enc10, "testpass", params, empty_key, false, false);
    decrypt_file(enc10, out10, "testpass", params, empty_key, false, false);

    ASSERT(files_equal(in10, out10), "Special characters not preserved");

    std::filesystem::remove(in10);
    std::filesystem::remove(enc10);
    std::filesystem::remove(out10);
    END_TEST

    // summary
    std::cout << std::endl;
    std::cout << "=== Test Summary ===" << std::endl;
    std::cout << "Tests run: " << tests_run << std::endl;
    std::cout << "Tests passed: " << tests_passed << std::endl;
    std::cout << "Tests failed: " << (tests_run - tests_passed) << std::endl;

    if (tests_passed == tests_run)
    {
        std::cout << "All tests PASSED!" << std::endl;
        return 0;
    }
    else
    {
        std::cout << "Some tests FAILED!" << std::endl;
        return 1;
    }
}