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
}