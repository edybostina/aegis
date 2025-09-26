#pragma once
#include <string>
#include <array>
#include <sodium.h>

namespace aegis::utils {
[[nodiscard]] bool file_exists(const std::string &p);
std::string prompt_line(const std::string &label, bool echo=true);
void progress_bar(int percent, const std::string &prefix="", const std::string &suffix="");
}