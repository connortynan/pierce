/* PAL implementation for POSIX systems (Linux, macOS, BSDs). */
#if !defined(_WIN32)

#if defined(__linux__) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE
#endif

#include "pal.h"

#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/eventfd.h>
#include <sys/random.h>
#endif

int pal_init(void) { return PIERCE_OK; }
void pal_shutdown(void) {}

uint64_t pal_now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

static int urandom_read(void *buf, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return PIERCE_ERR_PLATFORM;
    uint8_t *p = (uint8_t *)buf;
    while (len > 0) {
        ssize_t r = read(fd, p, len);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) { close(fd); return PIERCE_ERR_PLATFORM; }
        p += r;
        len -= (size_t)r;
    }
    close(fd);
    return PIERCE_OK;
}

int pal_random(void *buf, size_t len)
{
#if defined(__APPLE__) || defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__NetBSD__)
    arc4random_buf(buf, len);
    return PIERCE_OK;
#elif defined(__linux__)
    uint8_t *p = (uint8_t *)buf;
    while (len > 0) {
        ssize_t r = getrandom(p, len, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            if (errno == ENOSYS) return urandom_read(p, len);
            return PIERCE_ERR_PLATFORM;
        }
        p += r;
        len -= (size_t)r;
    }
    return PIERCE_OK;
#else
    return urandom_read(buf, len);
#endif
}

/* ---- address conversion ---- */

static socklen_t to_sockaddr(const pierce_addr *a, struct sockaddr_storage *ss)
{
    memset(ss, 0, sizeof(*ss));
    if (a->family == PIERCE_AF_INET) {
        struct sockaddr_in *s4 = (struct sockaddr_in *)ss;
        s4->sin_family = AF_INET;
        s4->sin_port = htons(a->port);
        memcpy(&s4->sin_addr, a->addr, 4);
        return (socklen_t)sizeof(*s4);
    }
    if (a->family == PIERCE_AF_INET6) {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ss;
        s6->sin6_family = AF_INET6;
        s6->sin6_port = htons(a->port);
        s6->sin6_scope_id = a->scope_id;
        memcpy(&s6->sin6_addr, a->addr, 16);
        return (socklen_t)sizeof(*s6);
    }
    return 0;
}

static void from_sockaddr(const struct sockaddr *sa, pierce_addr *a)
{
    memset(a, 0, sizeof(*a));
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)sa;
        a->family = PIERCE_AF_INET;
        a->port = ntohs(s4->sin_port);
        memcpy(a->addr, &s4->sin_addr, 4);
    } else if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)sa;
        const uint8_t *b = (const uint8_t *)&s6->sin6_addr;
        static const uint8_t v4mapped[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
        if (memcmp(b, v4mapped, 12) == 0) {
            a->family = PIERCE_AF_INET;
            memcpy(a->addr, b + 12, 4);
        } else {
            a->family = PIERCE_AF_INET6;
            memcpy(a->addr, b, 16);
            a->scope_id = s6->sin6_scope_id;
        }
        a->port = ntohs(s6->sin6_port);
    }
}

static int set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) return -1;
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    return 0;
}

static int would_block(int e)
{
    return e == EAGAIN || e == EWOULDBLOCK || e == ENOBUFS || e == EINTR;
}

static int open_socket(uint32_t family, int type, int *out)
{
    int af = family == PIERCE_AF_INET6 ? AF_INET6 : AF_INET;
    int fd = socket(af, type, 0);
    if (fd < 0) return PIERCE_ERR_PLATFORM;
    if (set_nonblock(fd) < 0) { close(fd); return PIERCE_ERR_PLATFORM; }
    if (af == AF_INET6) {
        int on = 1;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
    }
#ifdef SO_NOSIGPIPE
    { int on = 1; setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on)); }
#endif
    *out = fd;
    return PIERCE_OK;
}

static int bind_any(int fd, uint32_t family, uint16_t port)
{
    pierce_addr any;
    struct sockaddr_storage ss;
    memset(&any, 0, sizeof(any));
    any.family = family;
    any.port = port;
    socklen_t sl = to_sockaddr(&any, &ss);
    return bind(fd, (struct sockaddr *)&ss, sl) == 0 ? 0 : -1;
}

int pal_udp_open(uint32_t family, uint16_t port, pal_sock *out)
{
    int fd, rc = open_socket(family, SOCK_DGRAM, &fd);
    if (rc) return rc;
    int buf = 1 << 20;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
    if (bind_any(fd, family, port) < 0) { close(fd); return PIERCE_ERR_PLATFORM; }
    *out = (pal_sock)fd;
    return PIERCE_OK;
}

int pal_udp_send(pal_sock s, const pierce_addr *to, const void *data, size_t len)
{
    struct sockaddr_storage ss;
    socklen_t sl = to_sockaddr(to, &ss);
    if (sl == 0) return PIERCE_ERR_INVALID_ARG;
    ssize_t r = sendto((int)s, data, len, 0, (struct sockaddr *)&ss, sl);
    if (r >= 0) return PIERCE_OK;
    return would_block(errno) ? PIERCE_ERR_WOULD_BLOCK : PIERCE_ERR_PLATFORM;
}

int pal_udp_recv(pal_sock s, void *buf, size_t cap, pierce_addr *from)
{
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    ssize_t r = recvfrom((int)s, buf, cap, 0, (struct sockaddr *)&ss, &sl);
    if (r < 0) return would_block(errno) || errno == ECONNREFUSED
               ? PIERCE_ERR_WOULD_BLOCK : PIERCE_ERR_PLATFORM;
    from_sockaddr((struct sockaddr *)&ss, from);
    return (int)r;
}

int pal_sock_local_addr(pal_sock s, pierce_addr *out)
{
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    if (getsockname((int)s, (struct sockaddr *)&ss, &sl) < 0) return PIERCE_ERR_PLATFORM;
    from_sockaddr((struct sockaddr *)&ss, out);
    return PIERCE_OK;
}

void pal_sock_close(pal_sock s)
{
    if (s != PAL_INVALID_SOCK) close((int)s);
}

/* ---- TCP ---- */

int pal_tcp_connect(const pierce_addr *to, pal_sock *out)
{
    int fd, rc = open_socket(to->family, SOCK_STREAM, &fd);
    if (rc) return rc;
    int on = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
    struct sockaddr_storage ss;
    socklen_t sl = to_sockaddr(to, &ss);
    if (connect(fd, (struct sockaddr *)&ss, sl) < 0 && errno != EINPROGRESS) {
        close(fd);
        return PIERCE_ERR_PLATFORM;
    }
    *out = (pal_sock)fd;
    return PIERCE_OK;
}

int pal_tcp_connect_result(pal_sock s)
{
    struct pollfd p;
    p.fd = (int)s;
    p.events = POLLOUT;
    p.revents = 0;
    if (poll(&p, 1, 0) <= 0) return 0;
    int err = 0;
    socklen_t el = sizeof(err);
    if (getsockopt((int)s, SOL_SOCKET, SO_ERROR, &err, &el) < 0 || err != 0)
        return PIERCE_ERR_PLATFORM;
    return 1;
}

int pal_tcp_listen(uint32_t family, uint16_t port, pal_sock *out)
{
    int fd, rc = open_socket(family, SOCK_STREAM, &fd);
    if (rc) return rc;
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (bind_any(fd, family, port) < 0 || listen(fd, 128) < 0) {
        close(fd);
        return PIERCE_ERR_PLATFORM;
    }
    *out = (pal_sock)fd;
    return PIERCE_OK;
}

int pal_tcp_accept(pal_sock listener, pal_sock *out, pierce_addr *peer)
{
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    int fd = accept((int)listener, (struct sockaddr *)&ss, &sl);
    if (fd < 0) return would_block(errno) || errno == ECONNABORTED
                ? PIERCE_ERR_WOULD_BLOCK : PIERCE_ERR_PLATFORM;
    if (set_nonblock(fd) < 0) { close(fd); return PIERCE_ERR_PLATFORM; }
    int on = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
#ifdef SO_NOSIGPIPE
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#endif
    if (peer) from_sockaddr((struct sockaddr *)&ss, peer);
    *out = (pal_sock)fd;
    return PIERCE_OK;
}

int pal_tcp_send(pal_sock s, const void *data, size_t len)
{
#ifdef MSG_NOSIGNAL
    ssize_t r = send((int)s, data, len, MSG_NOSIGNAL);
#else
    ssize_t r = send((int)s, data, len, 0);
#endif
    if (r >= 0) return (int)r;
    return would_block(errno) ? PIERCE_ERR_WOULD_BLOCK : PIERCE_ERR_PLATFORM;
}

int pal_tcp_recv(pal_sock s, void *buf, size_t cap)
{
    ssize_t r = recv((int)s, buf, cap, 0);
    if (r >= 0) return (int)r;
    return would_block(errno) ? PIERCE_ERR_WOULD_BLOCK : PIERCE_ERR_PLATFORM;
}

/* ---- wait ---- */

int pal_wait(pal_pollfd *fds, uint32_t n, int32_t timeout_ms)
{
    struct pollfd stackp[16];
    struct pollfd *p = n <= 16 ? stackp : (struct pollfd *)malloc(n * sizeof(*p));
    if (!p) return PIERCE_ERR_NO_MEMORY;
    for (uint32_t i = 0; i < n; i++) {
        p[i].fd = (int)fds[i].sock;
        p[i].events = (short)(POLLIN | (fds[i].want_write ? POLLOUT : 0));
        p[i].revents = 0;
    }
    int r;
    do {
        r = poll(p, (nfds_t)n, timeout_ms < 0 ? -1 : timeout_ms);
    } while (r < 0 && errno == EINTR);
    for (uint32_t i = 0; i < n; i++) {
        fds[i].readable = (p[i].revents & POLLIN) != 0;
        fds[i].writable = (p[i].revents & POLLOUT) != 0;
        fds[i].failed = (p[i].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0;
    }
    if (p != stackp) free(p);
    return r < 0 ? PIERCE_ERR_PLATFORM : r;
}

/* ---- wake ---- */

int pal_wake_open(pal_wakeup *w)
{
#if defined(__linux__)
    int fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (fd < 0) return PIERCE_ERR_PLATFORM;
    w->rd = w->wr = (pal_sock)fd;
#else
    int p[2];
    if (pipe(p) < 0) return PIERCE_ERR_PLATFORM;
    set_nonblock(p[0]);
    set_nonblock(p[1]);
    w->rd = (pal_sock)p[0];
    w->wr = (pal_sock)p[1];
#endif
    return PIERCE_OK;
}

void pal_wake_signal(pal_wakeup *w)
{
#if defined(__linux__)
    uint64_t one = 1;
    ssize_t r = write((int)w->wr, &one, sizeof(one));
#else
    uint8_t one = 1;
    ssize_t r = write((int)w->wr, &one, 1);
#endif
    (void)r;
}

void pal_wake_drain(pal_wakeup *w)
{
    uint8_t buf[64];
    while (read((int)w->rd, buf, sizeof(buf)) > 0) {
    }
}

void pal_wake_close(pal_wakeup *w)
{
    if (w->rd != PAL_INVALID_SOCK) close((int)w->rd);
    if (w->wr != w->rd && w->wr != PAL_INVALID_SOCK) close((int)w->wr);
    w->rd = w->wr = PAL_INVALID_SOCK;
}

/* ---- interfaces / resolution ---- */

int pal_interfaces(pierce_addr *out, uint32_t cap, int include_loopback)
{
    struct ifaddrs *ifs, *it;
    uint32_t n = 0;
    if (getifaddrs(&ifs) < 0) return 0;
    for (it = ifs; it && n < cap; it = it->ifa_next) {
        if (!it->ifa_addr || !(it->ifa_flags & IFF_UP)) continue;
        if ((it->ifa_flags & IFF_LOOPBACK) && !include_loopback) continue;
        int fam = it->ifa_addr->sa_family;
        if (fam != AF_INET && fam != AF_INET6) continue;
        pierce_addr a;
        from_sockaddr(it->ifa_addr, &a);
        a.port = 0;
        if (a.family == PIERCE_AF_INET) {
            if (a.addr[0] == 169 && a.addr[1] == 254) continue;   /* link-local */
            if (a.addr[0] == 127 && !include_loopback) continue;
        } else {
            if (a.addr[0] == 0xfe && (a.addr[1] & 0xc0) == 0x80) continue; /* fe80::/10 */
            static const uint8_t lo6[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
            if (memcmp(a.addr, lo6, 16) == 0 && !include_loopback) continue;
            a.scope_id = 0;
        }
        out[n++] = a;
    }
    freeifaddrs(ifs);
    return (int)n;
}

int pal_resolve(const char *host, uint16_t port, pierce_addr *out, uint32_t cap)
{
    struct addrinfo hints, *res, *it;
    char portstr[8];
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_ADDRCONFIG;
    snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return 0;
    uint32_t n = 0;
    for (it = res; it && n < cap; it = it->ai_next) {
        if (it->ai_family != AF_INET && it->ai_family != AF_INET6) continue;
        from_sockaddr(it->ai_addr, &out[n]);
        n++;
    }
    freeaddrinfo(res);
    return (int)n;
}

/* ---- mutex ---- */

int pal_mutex_init(pal_mutex *m)
{
    return pthread_mutex_init(&m->m, NULL) == 0 ? PIERCE_OK : PIERCE_ERR_PLATFORM;
}
void pal_mutex_lock(pal_mutex *m) { pthread_mutex_lock(&m->m); }
void pal_mutex_unlock(pal_mutex *m) { pthread_mutex_unlock(&m->m); }
void pal_mutex_destroy(pal_mutex *m) { pthread_mutex_destroy(&m->m); }

#else
typedef int pal_posix_unused; /* ISO C forbids an empty translation unit */
#endif /* !_WIN32 */
