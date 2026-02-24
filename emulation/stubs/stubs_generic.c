/*
 * stubs_generic.c — Generic LD_PRELOAD stub library for firmware emulation.
 *
 * Provides MTD flash stubs, wireless ioctl passthrough, and /proc access
 * tracing. Safe for most embedded Linux firmware — no vendor-specific logic.
 *
 * Intercepted:
 *   - MTD functions: mtd_open, get_mtd_num, get_mtd_size, get_flash_type,
 *     flash_read, flash_write (with /tmp backing), erase_mtd, flash_lock/unlock
 *   - ioctl: returns 0 for wireless ioctls (0x8B00-0x8BFF), passes all
 *     others through to the kernel via raw syscall
 *   - open: traces /proc accesses to /tmp/open_trace.log
 *
 * Compiled with -nostdlib (no compile-time libc dependency). Runtime libc
 * functions (read, write, close, lseek) are resolved by the dynamic linker.
 *
 * Build (cross-compile, e.g. for mipsel):
 *   mipsel-linux-gnu-gcc -nostdlib -fPIC -shared -Wl,--hash-style=sysv \
 *       -o stubs_generic_mipsel.so stubs_generic.c
 */

/* ----- libc functions resolved at runtime by dynamic linker ----- */
typedef long ssize_t;
typedef unsigned int mode_t;
typedef long off_t;

extern ssize_t read(int fd, void *buf, unsigned long count);
extern ssize_t write(int fd, const void *buf, unsigned long count);
extern int close(int fd);
extern off_t lseek(int fd, off_t offset, int whence);

/*
 * errno access — __errno_location() is provided by glibc, musl, and uclibc.
 * Returns a pointer to the thread-local errno variable.
 */
extern int *__errno_location(void);

/* ----- platform-specific constants ----- */
#define _O_RDONLY 0
#define _O_WRONLY 1
#define _O_RDWR   2
#define _O_TRUNC  0x0200

#if defined(__mips__) || defined(__mips64)
#define _O_CREAT  0x0100
#else
#define _O_CREAT  0x0040
#endif

#define _SEEK_SET 0

/* ===== Raw syscall for ioctl passthrough ===== */

#if defined(__mips__) && !defined(__mips64)
#define __NR_ioctl 4054

static long _raw_ioctl(int fd, unsigned long request, void *arg)
{
    register long a0 __asm__("$4") = (long)fd;
    register long a1 __asm__("$5") = (long)request;
    register long a2 __asm__("$6") = (long)arg;
    register long v0 __asm__("$2");
    register long a3 __asm__("$7");
    long ret;
    long err;
    __asm__ volatile(
        ".set noreorder\n\t"
        "li $2, %2\n\t"
        "syscall\n\t"
        ".set reorder"
        : "=r"(v0), "=r"(a3)
        : "i"(__NR_ioctl), "r"(a0), "r"(a1), "r"(a2)
        : "memory", "$1", "$3", "$8", "$9", "$10", "$11", "$12",
          "$13", "$14", "$15", "$24", "$25", "hi", "lo"
    );
    ret = v0;
    err = a3;
    if (err != 0) {
        *__errno_location() = (int)ret;
        return -1;
    }
    return ret;
}

#elif defined(__arm__)
#define __NR_ioctl 54

static long _raw_ioctl(int fd, unsigned long request, void *arg)
{
    register long r0 __asm__("r0") = (long)fd;
    register long r1 __asm__("r1") = (long)request;
    register long r2 __asm__("r2") = (long)arg;
    register long r7 __asm__("r7") = __NR_ioctl;
    long ret;
    __asm__ volatile(
        "swi #0"
        : "+r"(r0)
        : "r"(r1), "r"(r2), "r"(r7)
        : "memory"
    );
    ret = r0;
    if (ret < 0 && ret > -4096) {
        *__errno_location() = (int)(-ret);
        return -1;
    }
    return ret;
}

#elif defined(__aarch64__)
#define __NR_ioctl 29

static long _raw_ioctl(int fd, unsigned long request, void *arg)
{
    register long x0 __asm__("x0") = (long)fd;
    register long x1 __asm__("x1") = (long)request;
    register long x2 __asm__("x2") = (long)arg;
    register long x8 __asm__("x8") = __NR_ioctl;
    long ret;
    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x8)
        : "memory"
    );
    ret = x0;
    if (ret < 0 && ret > -4096) {
        *__errno_location() = (int)(-ret);
        return -1;
    }
    return ret;
}

#else
#error "Unsupported architecture for raw ioctl syscall"
#endif

/* ===== Raw open/write/close syscalls for tracing ===== */

#if defined(__mips__) && !defined(__mips64)
#define __NR_open  4005
#define __NR_write 4004
#define __NR_close 4006
#define _O_APPEND 0x0008
#elif defined(__arm__)
#define __NR_open  5
#define __NR_write 4
#define __NR_close 6
#define _O_APPEND 0x0400
#elif defined(__aarch64__)
#define __NR_openat 56
#define __NR_write  64
#define __NR_close  57
#define _O_APPEND   0x0400
#define AT_FDCWD    -100
#endif

#if defined(__mips__) && !defined(__mips64)
static int _raw_open(const char *path, int flags, int mode)
{
    register long a0 __asm__("$4") = (long)path;
    register long a1 __asm__("$5") = (long)flags;
    register long a2 __asm__("$6") = (long)mode;
    register long v0 __asm__("$2");
    register long a3 __asm__("$7");
    long ret, err;
    __asm__ volatile(
        ".set noreorder\n\t"
        "li $2, %2\n\t"
        "syscall\n\t"
        ".set reorder"
        : "=r"(v0), "=r"(a3)
        : "i"(__NR_open), "r"(a0), "r"(a1), "r"(a2)
        : "memory", "$1", "$3", "$8", "$9", "$10", "$11", "$12",
          "$13", "$14", "$15", "$24", "$25", "hi", "lo"
    );
    ret = v0; err = a3;
    if (err != 0) { *__errno_location() = (int)ret; return -1; }
    return (int)ret;
}

static long _raw_write(int fd, const void *buf, unsigned long count)
{
    register long a0 __asm__("$4") = (long)fd;
    register long a1 __asm__("$5") = (long)buf;
    register long a2 __asm__("$6") = (long)count;
    register long v0 __asm__("$2");
    register long a3 __asm__("$7");
    long ret, err;
    __asm__ volatile(
        ".set noreorder\n\t"
        "li $2, %2\n\t"
        "syscall\n\t"
        ".set reorder"
        : "=r"(v0), "=r"(a3)
        : "i"(__NR_write), "r"(a0), "r"(a1), "r"(a2)
        : "memory", "$1", "$3", "$8", "$9", "$10", "$11", "$12",
          "$13", "$14", "$15", "$24", "$25", "hi", "lo"
    );
    ret = v0; err = a3;
    if (err != 0) return -1;
    return ret;
}

static int _raw_close(int fd)
{
    register long a0 __asm__("$4") = (long)fd;
    register long v0 __asm__("$2");
    register long a3 __asm__("$7");
    long ret, err;
    __asm__ volatile(
        ".set noreorder\n\t"
        "li $2, %2\n\t"
        "syscall\n\t"
        ".set reorder"
        : "=r"(v0), "=r"(a3)
        : "i"(__NR_close), "r"(a0)
        : "memory", "$1", "$3", "$8", "$9", "$10", "$11", "$12",
          "$13", "$14", "$15", "$24", "$25", "hi", "lo"
    );
    ret = v0; err = a3;
    if (err != 0) return -1;
    return (int)ret;
}

#elif defined(__arm__)
static int _raw_open(const char *path, int flags, int mode)
{
    register long r0 __asm__("r0") = (long)path;
    register long r1 __asm__("r1") = (long)flags;
    register long r2 __asm__("r2") = (long)mode;
    register long r7 __asm__("r7") = __NR_open;
    long ret;
    __asm__ volatile("swi #0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r7) : "memory");
    ret = r0;
    if (ret < 0 && ret > -4096) { *__errno_location() = (int)(-ret); return -1; }
    return (int)ret;
}

static long _raw_write(int fd, const void *buf, unsigned long count)
{
    register long r0 __asm__("r0") = (long)fd;
    register long r1 __asm__("r1") = (long)buf;
    register long r2 __asm__("r2") = (long)count;
    register long r7 __asm__("r7") = __NR_write;
    long ret;
    __asm__ volatile("swi #0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r7) : "memory");
    ret = r0;
    if (ret < 0 && ret > -4096) return -1;
    return ret;
}

static int _raw_close(int fd)
{
    register long r0 __asm__("r0") = (long)fd;
    register long r7 __asm__("r7") = __NR_close;
    long ret;
    __asm__ volatile("swi #0" : "+r"(r0) : "r"(r7) : "memory");
    ret = r0;
    if (ret < 0 && ret > -4096) return -1;
    return (int)ret;
}

#elif defined(__aarch64__)
static int _raw_open(const char *path, int flags, int mode)
{
    register long x0 __asm__("x0") = AT_FDCWD;
    register long x1 __asm__("x1") = (long)path;
    register long x2 __asm__("x2") = (long)flags;
    register long x3 __asm__("x3") = (long)mode;
    register long x8 __asm__("x8") = __NR_openat;
    long ret;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x8) : "memory");
    ret = x0;
    if (ret < 0 && ret > -4096) { *__errno_location() = (int)(-ret); return -1; }
    return (int)ret;
}

static long _raw_write(int fd, const void *buf, unsigned long count)
{
    register long x0 __asm__("x0") = (long)fd;
    register long x1 __asm__("x1") = (long)buf;
    register long x2 __asm__("x2") = (long)count;
    register long x8 __asm__("x8") = __NR_write;
    long ret;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
    ret = x0;
    if (ret < 0 && ret > -4096) return -1;
    return ret;
}

static int _raw_close(int fd)
{
    register long x0 __asm__("x0") = (long)fd;
    register long x8 __asm__("x8") = __NR_close;
    long ret;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory");
    ret = x0;
    if (ret < 0 && ret > -4096) return -1;
    return (int)ret;
}
#endif

/* Helper: compare string prefix */
static int _str_starts_with(const char *s, const char *prefix)
{
    while (*prefix) {
        if (*s != *prefix) return 0;
        s++; prefix++;
    }
    return 1;
}

/* Helper: string length */
static int _str_len(const char *s)
{
    int n = 0;
    while (s[n]) n++;
    return n;
}

/* ===== open() wrapper: traces /proc accesses ===== */
int open(const char *pathname, int flags, ...)
{
    int mode = 0;
    __builtin_va_list ap;
    __builtin_va_start(ap, flags);
    mode = __builtin_va_arg(ap, int);
    __builtin_va_end(ap);

    int fd = _raw_open(pathname, flags, mode);

    /* Log any /proc access to /tmp/open_trace.log */
    if (_str_starts_with(pathname, "/proc/")) {
        int log_fd = _raw_open("/tmp/open_trace.log",
                               _O_WRONLY | _O_CREAT | _O_APPEND, 0644);
        if (log_fd >= 0) {
            _raw_write(log_fd, pathname, _str_len(pathname));
            _raw_write(log_fd, "\n", 1);
            _raw_close(log_fd);
        }
    }

    return fd;
}

/* ===== ioctl wrapper ===== */
/*
 * Intercepts all ioctl calls. Returns 0 for wireless extension ioctls
 * (SIOCIWFIRST 0x8B00 through SIOCIWLAST 0x8BFF) to prevent failures
 * in firmware that queries WiFi interfaces. All other ioctls pass through.
 */
int ioctl(int fd, unsigned long request, ...)
{
    void *arg;
    __builtin_va_list ap;
    __builtin_va_start(ap, request);
    arg = __builtin_va_arg(ap, void *);
    __builtin_va_end(ap);

    /* Wireless extension ioctls: 0x8B00 - 0x8BFF */
    if ((request & 0xFF00) == 0x8B00)
        return 0;

    /* All other ioctls: pass through to kernel */
    return (int)_raw_ioctl(fd, request, arg);
}

/* ----- inline string helpers (no libc) ----- */

static int _str_eq(const char *a, const char *b)
{
    if (!a || !b)
        return 0;
    while (*a && *b) {
        if (*a != *b)
            return 0;
        a++;
        b++;
    }
    return *a == *b;
}

static void _memfill(void *dst, unsigned char val, unsigned long n)
{
    unsigned char *p = (unsigned char *)dst;
    while (n--)
        *p++ = val;
}

static void _str_copy(char *dst, const char *src)
{
    while (*src)
        *dst++ = *src++;
    *dst = '\0';
}

/*
 * Build backing file path: /tmp/fake_mtd_<name>.bin
 * Buffer must be at least 256 bytes.
 */
static void _build_backing_path(const char *name, char *path)
{
    const char *prefix = "/tmp/fake_mtd_";
    const char *suffix = ".bin";
    char *p = path;

    _str_copy(p, prefix);
    p += _str_len(prefix);

    /* Copy partition name (bounded) */
    int i = 0;
    while (name[i] && i < 64) {
        *p++ = name[i++];
    }
    *p = '\0';

    _str_copy(p, suffix);
}

/* ----- partition table ----- */

struct mtd_part {
    const char *name;
    int         num;
    int         size;    /* bytes */
};

/*
 * Generic embedded partition layout — realistic defaults.
 * Exact values don't matter since firmware typically only checks that size > 0.
 */
static const struct mtd_part partitions[] = {
    { "boot",      0,  0x00020000 },   /* 128 KB  — bootloader         */
    { "CFG",       1,  0x00010000 },   /* 64 KB   — config             */
    { "CFG_BAK",   2,  0x00010000 },   /* 64 KB   — config backup      */
    { "firmware",  3,  0x00780000 },   /* ~7.5 MB — firmware image      */
    { "rootfs",    4,  0x00600000 },   /* 6 MB    — root filesystem     */
    { "kernel",    5,  0x00180000 },   /* 1.5 MB  — kernel              */
    { "ART",       6,  0x00010000 },   /* 64 KB   — radio calibration   */
    { "art",       6,  0x00010000 },   /* alias (lowercase)             */
    { "radio",     7,  0x00010000 },   /* 64 KB   — radio (alt name)    */
    { "nvram",     8,  0x00010000 },   /* 64 KB   — nvram               */
    { "config",    9,  0x00010000 },   /* 64 KB   — generic config      */
    { "factory",  10,  0x00010000 },   /* 64 KB   — factory data        */
    { "romfile",  11,  0x00010000 },   /* 64 KB   — rom file            */
    { 0, 0, 0 }
};

/* ===== MTD core functions ===== */

int mtd_open(const char *name, int flags)
{
    (void)name;
    (void)flags;
    return open("/dev/null", _O_RDWR);
}

int get_mtd_num(const char *name)
{
    const struct mtd_part *p;
    for (p = partitions; p->name; p++) {
        if (_str_eq(name, p->name))
            return p->num;
    }
    return -1;
}

int get_mtd_size(const char *name)
{
    const struct mtd_part *p;
    for (p = partitions; p->name; p++) {
        if (_str_eq(name, p->name))
            return p->size;
    }
    return 0x00010000;
}

unsigned int get_flash_type(void)
{
    return 3;  /* NOR flash */
}

/* ===== Flash read/write/erase with backing storage ===== */

int flash_read(const char *name, void *buf, int offset_hi, int offset_lo,
               unsigned int len)
{
    char path[256];
    int fd;
    ssize_t n;

    (void)offset_hi;

    if (!buf || len == 0)
        return 0;

    _build_backing_path(name, path);
    fd = open(path, _O_RDONLY);
    if (fd < 0) {
        /* No backing file — return erased flash (0xFF) */
        _memfill(buf, 0xFF, (unsigned long)len);
        return 0;
    }

    if (offset_lo > 0)
        lseek(fd, (off_t)offset_lo, _SEEK_SET);

    n = read(fd, buf, (unsigned long)len);
    close(fd);

    /* Pad any unread remainder with 0xFF */
    if (n < 0) n = 0;
    if ((unsigned long)n < len)
        _memfill((char *)buf + n, 0xFF, len - (unsigned long)n);

    return 0;
}

int flash_write(const char *name, const void *data, int offset_hi,
                int offset_lo, unsigned int len)
{
    char path[256];
    int fd;

    (void)offset_hi;

    if (!data || len == 0)
        return 0;

    _build_backing_path(name, path);
    fd = open(path, _O_WRONLY | _O_CREAT | _O_TRUNC, 0644);
    if (fd < 0)
        return -1;

    if (offset_lo > 0)
        lseek(fd, (off_t)offset_lo, _SEEK_SET);

    write(fd, data, (unsigned long)len);
    close(fd);
    return 0;
}

int erase_mtd(const char *name)
{
    (void)name;
    return 1;  /* success */
}

int flash_lock(int fd)
{
    (void)fd;
    return 0;
}

int flash_unlock(int fd)
{
    (void)fd;
    return 0;
}
