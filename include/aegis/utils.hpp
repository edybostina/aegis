#pragma once
#include <string>
#include <array>
#include <filesystem>
#include <sodium.h>

namespace aegis::utils
{
    [[nodiscard]] bool file_exists(const std::string &p);
    std::string prompt_line(const std::string &label, bool echo = true);
    void progress_bar(int percent, const std::string &prefix = "", const std::string &suffix = "");

    [[nodiscard]] bool validate_passphrase_strength(const std::string &passphrase);
    [[nodiscard]] bool is_secure_path(const std::filesystem::path &path);
    void check_file_permissions(const std::filesystem::path &path, bool should_be_private = true);
    std::filesystem::path create_secure_temp_file(const std::string &prefix = "aegis_tmp");

    class Logger
    {
    public:
        enum class Level
        {
            DEBUG,
            INFO,
            WARNING,
            ERROR
        };

        [[maybe_unused]] static void log(Level level, const std::string &message);
    };
}