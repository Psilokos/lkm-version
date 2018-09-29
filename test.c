#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "version.h"

#define SYSERR(opname) do { \
    fprintf(stderr, \
            "error: " #opname "() L%u failed (%s)\n", \
            __LINE__, strerror(errno)); \
    return 1; \
} while (0)

static inline int
version_modified(int fd, bool *p_vermod)
{
    if (ioctl(fd, VERSION_MODIFIED, p_vermod) == -1)
        SYSERR(ioctl);
    return 0;
}

static inline
int version_reset(int fd)
{
    if (ioctl(fd, VERSION_RESET) == -1)
        SYSERR(ioctl);
    return 0;
}

static int
reset_version(int fd)
{
    bool vermod;
    if (version_modified(fd, &vermod) ||
        (vermod && version_reset(fd)))
        return 1;
    assert(!vermod || (!version_modified(fd, &vermod) && !vermod));
    return 0;
}

#ifndef READ_SIZE
# define READ_SIZE  capacity
#endif

static int
get_version(int fd, char *version, size_t capacity)
{
    int rdsz, sz = 0;
    do {
        if (sz >= capacity)
        {
            fprintf(stderr, "version string too long\n");
            return 1;
        }
        rdsz = read(fd, version + sz, READ_SIZE);
        if (rdsz == -1)
            SYSERR(read);
        sz += rdsz;
    } while (rdsz != 0);
    assert(sz < 64);
    version[sz] = 0;
    return -sz;
}

static int
set_version(int fd, char *vstr)
{
    if (write(fd, vstr, strlen(vstr)) == -1)
        SYSERR(write);
    return 0;
}

int
main(int argc, char **argv)
{
    assert(argc >= 3);

    errno = 0;
    bool vermod;
    char vstr[64];
    ssize_t vstr_sz;
    int fd = open("/dev/version", O_RDWR);
    if (fd == -1)
        SYSERR(open);

    if (!version_modified(fd, &vermod) && vermod)
        reset_version(fd);
    assert(!version_modified(fd, &vermod) && !vermod);
    assert(!set_version(fd, argv[1]));
    assert(-get_version(fd, vstr, 0xDeadBabe) != -1);
    assert(!strcmp(vstr, argv[1]));
    if (close(fd) == -1)
        SYSERR(close);
    fd = open("/dev/version", O_RDWR | O_APPEND);
    if (fd == -1)
        SYSERR(open);
    assert(!set_version(fd, argv[2]));
    assert(lseek(fd, 0, SEEK_SET) != -1);
    assert(-get_version(fd, vstr, 64) != -1);
    puts(vstr);
    assert(!strncmp(vstr, argv[1], strlen(argv[1])) &&
           !strcmp(vstr + strlen(argv[1]), argv[2]));

    assert(!version_modified(fd, &vermod) && vermod);
    assert(!reset_version(fd));
    assert(!version_modified(fd, &vermod) && !vermod);

    assert(lseek(fd, 0, SEEK_SET) != -1);
    assert(-get_version(fd, vstr, 64) != -1);
    if (close(fd) == -1)
        SYSERR(close);
    puts(vstr);

    return 0;
}
