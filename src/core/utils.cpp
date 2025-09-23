#include "../../include/aegis/utils.hpp"
#include <iostream>
#include <filesystem>
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

    bool key_override_provided(const std::array<unsigned char, crypto_secretbox_KEYBYTES> &key_override) {
        for (unsigned char byte : key_override) {
            if (byte != 0) {
                return true;
            }
        }
        return false;
    }

    static std::string prompt_hidden(const std::string &label)
    {
        std::cerr << label;
        std::cerr.flush();

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
}