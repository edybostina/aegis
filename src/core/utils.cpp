#include "aegis/utils.hpp"
#include <iostream>
#include <filesystem>
#include <fstream>
#include <system_error>
#include <fcntl.h>
#include <sodium.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <termios.h>
#endif

namespace aegis::utils
{
    bool file_exists(const std::string &p)
    {
        return std::filesystem::exists(p);
    }

    static std::string prompt_hidden(const std::string &label)
    {
        std::cerr << label;
        std::cerr.flush();

        // why is this still here
#ifdef _WIN32
        HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
        DWORD mode = 0;
        GetConsoleMode(hStdin, &mode);

        SetConsoleMode(hStdin, mode & ~ENABLE_ECHO_INPUT);

        std::string s;
        std::getline(std::cin, s);
        SetConsoleMode(hStdin, mode);
        std::cerr << "\n";
        return s;
#else
        termios oldt{};
        tcgetattr(STDIN_FILENO, &oldt);

        termios newt = oldt;
        newt.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);

        std::string s;
        std::getline(std::cin, s);

        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        std::cerr << "\n";
        return s;

#endif
    }

    std::string prompt_line(const std::string &label, bool echo)
    {
        if (echo)
        {
            std::cerr << label;
            std::cerr.flush();
            std::string s;
            std::getline(std::cin, s);
            return s;
        }
        return prompt_hidden(label);
    }

    void Logger::log(Level level, const std::string &message)
    {
        const char *levelStr = "";
        switch (level)
        {
        case Level::DEBUG:
            levelStr = "DEBUG";
            break;
        case Level::INFO:
            levelStr = "INFO";
            break;
        case Level::WARNING:
            levelStr = "WARNING";
            break;
        case Level::ERROR:
            levelStr = "ERROR";
            break;
        }

        std::cerr << "[" << levelStr << "] " << message << "\n";
    }

    void progress_bar(int percent, const std::string &prefix, const std::string &suffix)
    {
        const int barWidth = 50;
        std::cout << "\r" << prefix << " [";
        int pos = barWidth * percent / 100;
        for (int i = 0; i < barWidth; ++i)
        {
            if (i < pos)
                std::cout << "=";
            else if (i == pos)
                std::cout << ">";
            else
                std::cout << " ";
        }
        std::cout << "] " << percent << "% " << suffix;
        std::cout.flush();
        if (percent >= 100)
            std::cout << "\n";
    }

    bool validate_passphrase_strength(const std::string &passphrase)
    {
        // Basic strength validation
        if (passphrase.length() < 8)
        {
            Logger::log(Logger::Level::WARNING, "Passphrase is weak: minimum 8 characters recommended");
            return false;
        }
        if (passphrase.length() < 12)
        {
            Logger::log(Logger::Level::WARNING, "Passphrase could be stronger: 12+ characters recommended");
        }
        return true;
    }

    bool is_secure_path(const std::filesystem::path &path)
    {
        std::string path_str = path.string();
        if (path_str.find("..") != std::string::npos)
        {
            Logger::log(Logger::Level::ERROR, "Potential path traversal detected in: " + path_str);
            return false;
        }
        return true;
    }

    void check_file_permissions(const std::filesystem::path &path, bool should_be_private)
    {
#ifndef _WIN32
        auto perms = std::filesystem::status(path).permissions();
        using std::filesystem::perms;

        bool world_readable = (perms & perms::others_read) != perms::none;
        bool world_writable = (perms & perms::others_write) != perms::none;
        bool group_readable = (perms & perms::group_read) != perms::none;
        bool group_writable = (perms & perms::group_write) != perms::none;

        if (should_be_private && (world_readable || world_writable || group_readable || group_writable))
        {
            Logger::log(Logger::Level::WARNING,
                        "Security warning: " + path.string() + " has overly permissive permissions.");
            Logger::log(Logger::Level::WARNING,
                        "Consider running: chmod 600 " + path.string());
        }
#endif
    }

    std::filesystem::path create_secure_temp_file(const std::string &prefix)
    {
        auto temp_dir = std::filesystem::temp_directory_path();
        std::string temp_name = prefix + "_" + std::to_string(randombytes_random()) + ".tmp";
        auto temp_path = temp_dir / temp_name;

#ifndef _WIN32
        int fd = ::open(temp_path.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600);
        if (fd < 0)
            throw std::system_error(errno, std::generic_category(), "Failed to create secure temp file");
        ::close(fd);
#else
        std::ofstream f(temp_path, std::ios::binary);
        f.close();
#endif

        return temp_path;
    }
}