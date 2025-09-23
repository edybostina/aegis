#pragma once
#include <string>
#include <array>
#include <sodium.h>

namespace aegis::utils {
[[nodiscard]] bool file_exists(const std::string &p);
std::string prompt_line(const std::string &label, bool echo=true);
bool key_override_provided(const std::array<unsigned char, crypto_secretbox_KEYBYTES> &key_override);
}