#pragma once 

#include <cstddef>
#include <vector>
#include <string>
#include <filesystem>

namespace aegis::io
{
    std::vector<unsigned char> read_chunk(int fd, size_t max_bytes);
    void write_all(int fd, const unsigned char * data, size_t length);
    int open_readonly(const std::filesystem::path &path);
    int open_readwrite(const std::filesystem::path &path);
}

