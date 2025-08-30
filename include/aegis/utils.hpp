#pragma once
#include <string>

namespace aegis::utils {
[[nodiscard]] bool file_exists(const std::string &p);
std::string prompt_line(const std::string &label, bool echo=true);
}