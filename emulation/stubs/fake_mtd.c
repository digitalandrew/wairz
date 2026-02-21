/*
 * fake_mtd.c — LD_PRELOAD stub for MTD flash, wireless ioctl, and
 * process monitor functions.
 *
 * Many embedded firmware daemons (e.g., Tenda cfmd, httpd) call MTD functions
 * from libcommon.so, which internally do ioctl(MEMGETINFO) on /dev/mtdN.
 * QEMU system-mode emulation with a generic kernel has no MTD support, so
 * these calls fail and daemons exit. Additionally, httpd calls wireless
 * extension ioctls (0x8B00-0x8BFF) on wlan interfaces that don't exist
 * in QEMU, causing InitConutryCode to fail.
 *
 * This library intercepts:
 *   - MTD functions: mtd_open, get_mtd_num, get_mtd_size, get_flash_type,
 *     flash_read, flash_write (with /tmp backing), erase_mtd, flash_lock/unlock
 *   - ioctl: returns 0 for wireless ioctls (0x8B00-0x8BFF), passes all
 *     others through to the kernel via raw syscall
 *   - Process monitor: monitor_system_network_ok, ugw_proc_send_msg
 *
 * Compiled with -nostdlib (no compile-time libc dependency). Runtime libc
 * functions (open, read, write, close, lseek) are resolved by the dynamic
 * linker since the firmware's libc is already loaded when LD_PRELOAD takes
 * effect. The ioctl wrapper uses raw syscalls to avoid infinite recursion.
 *
 * Build (cross-compile, e.g. for mipsel):
 *   mipsel-linux-gnu-gcc -nostdlib -fPIC -shared -Wl,--hash-style=sysv \
 *       -o fake_mtd_mipsel.so fake_mtd.c
 *
 * Usage:
 *   export LD_PRELOAD=/opt/stubs/fake_mtd.so
 *   /bin/cfmd &
 */

/* ----- libc functions resolved at runtime by dynamic linker ----- */
typedef long ssize_t;
typedef unsigned int mode_t;
typedef long off_t;

extern int open(const char *pathname, int flags, ...);
extern ssize_t read(int fd, void *buf, unsigned long count);
extern ssize_t write(int fd, const void *buf, unsigned long count);
extern int close(int fd);
extern off_t lseek(int fd, off_t offset, int whence);

/* ----- platform-specific constants ----- */
/*
 * O_CREAT differs between MIPS (0x100) and generic (0x40).
 * O_TRUNC, O_RDONLY, O_WRONLY, O_RDWR are the same on all Linux archs.
 */
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
/*
 * We intercept ioctl globally via LD_PRELOAD. For non-wireless ioctls,
 * we must call the real kernel ioctl via raw syscall to avoid recursion
 * (we can't call libc's ioctl — that's us).
 */

#if defined(__mips__) && !defined(__mips64)
/* MIPS o32 ABI: syscall number in $v0, args in $a0-$a2, error flag in $a3 */
#define __NR_ioctl 4054

static long _raw_ioctl(int fd, unsigned long request, void *arg)
{
    register long v0 __asm__("$2") = __NR_ioctl;
    register long a0 __asm__("$4") = (long)fd;
    register long a1 __asm__("$5") = (long)request;
    register long a2 __asm__("$6") = (long)arg;
    register long a3 __asm__("$7");
    __asm__ volatile(
        "syscall"
        : "+r"(v0), "=r"(a3)
        : "r"(a0), "r"(a1), "r"(a2)
        : "memory", "$1", "$3", "$8", "$9", "$10", "$11", "$12",
          "$13", "$14", "$15", "$24", "$25", "hi", "lo"
    );
    if (a3 != 0) return -1;
    return v0;
}

#elif defined(__arm__)
/* ARM EABI: syscall number in r7, args in r0-r2 */
#define __NR_ioctl 54

static long _raw_ioctl(int fd, unsigned long request, void *arg)
{
    register long r0 __asm__("r0") = (long)fd;
    register long r1 __asm__("r1") = (long)request;
    register long r2 __asm__("r2") = (long)arg;
    register long r7 __asm__("r7") = __NR_ioctl;
    __asm__ volatile(
        "swi #0"
        : "+r"(r0)
        : "r"(r1), "r"(r2), "r"(r7)
        : "memory"
    );
    /* ARM returns -errno on error (negative value) */
    return r0;
}

#elif defined(__aarch64__)
/* AArch64: syscall number in x8, args in x0-x2 */
#define __NR_ioctl 29

static long _raw_ioctl(int fd, unsigned long request, void *arg)
{
    register long x0 __asm__("x0") = (long)fd;
    register long x1 __asm__("x1") = (long)request;
    register long x2 __asm__("x2") = (long)arg;
    register long x8 __asm__("x8") = __NR_ioctl;
    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x8)
        : "memory"
    );
    return x0;
}

#else
#error "Unsupported architecture for raw ioctl syscall"
#endif

/* ===== ioctl wrapper ===== */
/*
 * Intercepts all ioctl calls. Returns 0 for wireless extension ioctls
 * (SIOCIWFIRST 0x8B00 through SIOCIWLAST 0x8BFF) to prevent httpd's
 * InitConutryCode from failing. All other ioctls pass through to the
 * kernel via raw syscall.
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

static int _str_len(const char *s)
{
    int n = 0;
    while (*s++) n++;
    return n;
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
 * Common Tenda / Realtek / generic embedded partition layout.
 * Sizes are realistic defaults; exact values don't matter since
 * firmware typically only checks that size > 0.
 */
static const struct mtd_part partitions[] = {
    { "boot",      0,  0x00020000 },   /* 128 KB  — bootloader         */
    { "CFG",       1,  0x00010000 },   /* 64 KB   — config (cfmd key)  */
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

/*
 * mtd_open(const char *name, int flags) → int
 *
 * Original parses /proc/mtd to find device number, then opens /dev/mtdN.
 * Since QEMU has no MTD, returns a valid fd by opening /dev/null.
 */
int mtd_open(const char *name, int flags)
{
    (void)name;
    (void)flags;
    return open("/dev/null", _O_RDWR);
}

/*
 * get_mtd_num(const char *name) → int
 * Parses /proc/mtd to find MTD number by partition name.
 * Returns: MTD number (0-N) or -1 if not found.
 */
int get_mtd_num(const char *name)
{
    const struct mtd_part *p;
    for (p = partitions; p->name; p++) {
        if (_str_eq(name, p->name))
            return p->num;
    }
    return -1;
}

/*
 * get_mtd_size(const char *name) → int
 * Original calls mtd_open() then ioctl(MEMGETINFO).
 * Returns: partition size in bytes, or default 64KB for unknown.
 */
int get_mtd_size(const char *name)
{
    const struct mtd_part *p;
    for (p = partitions; p->name; p++) {
        if (_str_eq(name, p->name))
            return p->size;
    }
    return 0x00010000;
}

/*
 * get_flash_type(void) → unsigned int
 * Original calls mtd_open() on a hardcoded partition, then ioctl(MEMGETINFO).
 * Returns first byte of mtd_info (flash type).
 * MTD_NORFLASH=3, MTD_NANDFLASH=4.
 */
unsigned int get_flash_type(void)
{
    return 3;  /* NOR flash */
}

/* ===== Flash read/write/erase with backing storage ===== */

/*
 * flash_read(name, buf, offset_hi, offset_lo, len) → int
 *
 * 5-parameter signature (confirmed via Ghidra decompilation of libcommon.so):
 *   param_1: const char *name    — partition name
 *   param_2: void *buf           — output buffer
 *   param_3: int offset_hi       — high 32 bits of 64-bit offset
 *   param_4: int offset_lo       — low 32 bits of 64-bit offset
 *   param_5: unsigned int len    — bytes to read
 *
 * Reads from /tmp/fake_mtd_<name>.bin backing file. If no backing file
 * exists (no prior write), returns 0xFF (erased flash). This ensures
 * write-then-verify patterns work: cfmd writes config, reads it back
 * to check CRC, and the data matches.
 */
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

/*
 * flash_write(name, data, offset_hi, offset_lo, len) → int
 *
 * 5-parameter signature matching flash_read.
 * Writes to /tmp/fake_mtd_<name>.bin backing file so subsequent
 * flash_read calls return the written data (CRC verification works).
 */
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

/*
 * erase_mtd(const char *name) → int
 * Original calls mtd_open(name, O_RDWR) then loops ioctl(MEMERASE).
 * Returns 1 for success, 0 for failure (note: NOT 0/-1).
 */
int erase_mtd(const char *name)
{
    (void)name;
    return 1;  /* success */
}

/*
 * flash_lock(int fd) → int
 * flash_unlock(int fd) → int
 * Original does ioctl on MTD fd. Stub returns success.
 */
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

/* ===== Process monitor stubs ===== */

/*
 * monitor_system_network_ok(void) → void
 * Called by cfmd to signal the process monitor via /var/pm_socket.
 * Without the monitor daemon, the connect() fails. No-op stub.
 */
void monitor_system_network_ok(void)
{
    return;
}

/*
 * ugw_proc_send_msg(int *msg, int socket_path) → long
 * Connects to a UNIX socket and sends a message.
 * Stub: pretend we wrote all bytes (msg[0] + 4 header bytes).
 * Returns -1 if msg is NULL.
 */
long ugw_proc_send_msg(int *msg, int socket_path)
{
    (void)socket_path;
    if (!msg)
        return -1;
    return msg[0] + 4;
}
