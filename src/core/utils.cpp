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

    void progress_bar(int percent, const std::string &prefix, const std::string &suffix)
    {
        const int barWidth = 50;
        std::cerr << "\r" << prefix << " [";
        int pos = barWidth * percent / 100;
        for (int i = 0; i < barWidth; ++i)
        {
            if (i < pos)
                std::cerr << "=";
            else if (i == pos)
                std::cerr << ">";
            else
                std::cerr << " ";
        }
        std::cerr << "] " << percent << "% " << suffix;
        std::cerr.flush();
        if (percent >= 100)
            std::cerr << "\n";
    }
}