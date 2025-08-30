#include "../../include/aegis/file_io.hpp"
#include <stdexcept>
#include <system_error>
#include <fcntl.h>
#include <unistd.h>

namespace aegis::io
{

    std::vector<unsigned char> read_chunk(int fd, size_t max_bytes)
    {
        std::vector<unsigned char> buf(max_bytes);
        ssize_t n = ::read(fd, buf.data(), buf.size());
        if (n < 0)
            throw std::system_error(errno, std::generic_category(), "read failed");
        buf.resize(static_cast<size_t>(n));
        return buf;
    }

    void write_all(int fd, const unsigned char *data, size_t len)
    {
        size_t written = 0;
        while (written < len)
        {
            ssize_t n = ::write(fd, data + written, len - written);
            if (n < 0)
                throw std::system_error(errno, std::generic_category(), "write failed");
            written += static_cast<size_t>(n);
        }
    }

    int open_readonly(const std::filesystem::path &p)
    {
        int fd = ::open(p.c_str(), O_RDONLY);
        if (fd < 0)
            throw std::system_error(errno, std::generic_category(), "open for read failed");
        return fd;
    }

    int open_readwrite(const std::filesystem::path &p)
    {
        int fd = ::open(p.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0600);
        if (fd < 0)
            throw std::system_error(errno, std::generic_category(), "open for read/write failed");
        return fd;
    }

}