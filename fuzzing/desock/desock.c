/*
 * desock.c — Minimal desocketing library for AFL++ fuzzing of network daemons.
 *
 * When loaded via AFL_PRELOAD, intercepts socket/bind/listen/accept and
 * redirects network I/O to stdin/stdout so AFL++ can feed fuzz data to
 * binaries that normally read from network connections.
 *
 * Compiled as a cross-architecture shared library (one per target arch).
 * Does NOT use -nostdlib — needs libc's dup(), read(), write() which
 * resolve at runtime from the firmware's libc via QEMU_LD_PREFIX.
 *
 * Build:
 *   <cross-gcc> -fPIC -shared -Wl,--hash-style=sysv -o desock_<arch>.so desock.c
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <poll.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/*
 * State tracking: accept() succeeds exactly once per AFL++ execution,
 * returning a dup of stdin. The second accept() call terminates the
 * process with _exit(0) — this is critical because most daemons retry
 * accept() on error, so returning -1 just causes an infinite loop.
 * _exit(0) forces the forked child to terminate cleanly after processing
 * one connection, allowing AFL++ to fork a new child for the next input.
 */
static int g_accepted = 0;

/* ---------- socket lifecycle ---------- */

int socket(int domain, int type, int protocol) {
    (void)domain; (void)type; (void)protocol;
    return dup(0);  /* return a copy of stdin fd */
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    (void)sockfd; (void)addr; (void)addrlen;
    return 0;
}

int listen(int sockfd, int backlog) {
    (void)sockfd; (void)backlog;
    return 0;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    (void)sockfd;

    /* Only accept one connection per fuzz iteration.
     * _exit(0) terminates the child — returning -1 doesn't work because
     * daemons retry accept() on error and loop forever. */
    if (g_accepted) {
        _exit(0);
    }
    g_accepted = 1;

    if (addr)
        memset(addr, 0, sizeof(struct sockaddr));
    if (addrlen)
        *addrlen = sizeof(struct sockaddr);
    return dup(0);  /* AFL++ data comes through stdin */
}

int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
    (void)flags;
    return accept(sockfd, addr, addrlen);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    (void)sockfd; (void)addr; (void)addrlen;
    return 0;
}

/* ---------- I/O redirection ---------- */

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
    (void)flags;
    return read(sockfd, buf, len);
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen) {
    (void)flags; (void)src_addr; (void)addrlen;
    return read(sockfd, buf, len);
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    (void)flags;
    return write(sockfd, buf, len);
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen) {
    (void)flags; (void)dest_addr; (void)addrlen;
    return write(sockfd, buf, len);
}

/* ---------- socket options / info (no-ops) ---------- */

int setsockopt(int sockfd, int level, int optname,
               const void *optval, socklen_t optlen) {
    (void)sockfd; (void)level; (void)optname;
    (void)optval; (void)optlen;
    return 0;
}

int getsockopt(int sockfd, int level, int optname,
               void *optval, socklen_t *optlen) {
    (void)sockfd; (void)level; (void)optname;
    (void)optval; (void)optlen;
    return 0;
}

int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    (void)sockfd;
    if (addr)
        memset(addr, 0, sizeof(struct sockaddr));
    if (addrlen)
        *addrlen = sizeof(struct sockaddr);
    return 0;
}

int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    (void)sockfd;
    if (addr)
        memset(addr, 0, sizeof(struct sockaddr));
    if (addrlen)
        *addrlen = sizeof(struct sockaddr);
    return 0;
}

/* ---------- I/O multiplexing (prevent blocking) ---------- */

int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    (void)timeout;
    nfds_t i;
    for (i = 0; i < nfds; i++) {
        fds[i].revents = fds[i].events;  /* mark all requested events as ready */
    }
    return (int)nfds;
}

int select(int nfds, fd_set *readfds, fd_set *writefds,
           fd_set *exceptfds, struct timeval *timeout) {
    (void)timeout;
    /* Return immediately: all fds are "ready". Count is approximate. */
    int count = 0;
    if (readfds)  count += nfds;
    if (writefds) count += nfds;
    if (exceptfds) {
        FD_ZERO(exceptfds);  /* no exceptions */
    }
    return count > 0 ? count : 1;
}
