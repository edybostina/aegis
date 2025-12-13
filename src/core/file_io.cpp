#include "aegis/file_io.hpp"
#include <stdexcept>
#include <system_error>
#include <fcntl.h>

#ifdef _WIN32
#include <io.h>
#include <windows.h>
#define O_RDONLY _O_RDONLY
#define O_RDWR _O_RDWR
#define O_CREAT _O_CREAT
#define O_TRUNC _O_TRUNC
#define O_BINARY _O_BINARY
#define open _open
#define close _close
#define read _read
#define write _write
typedef int ssize_t;
#else
#include <unistd.h>
#endif

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
#ifdef _WIN32
        int fd = ::open(p.string().c_str(), O_RDONLY | O_BINARY);
#else
        int fd = ::open(p.c_str(), O_RDONLY);
#endif
        if (fd < 0)
            throw std::system_error(errno, std::generic_category(), "open for read failed");
        return fd;
    }

    int open_readwrite(const std::filesystem::path &p)
    {
#ifdef _WIN32
        int fd = ::open(p.string().c_str(), O_RDWR | O_CREAT | O_TRUNC | O_BINARY, _S_IREAD | _S_IWRITE);
#else
        int fd = ::open(p.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0600);
#endif
        if (fd < 0)
            throw std::system_error(errno, std::generic_category(), "open for read/write failed");
        return fd;
    }

}