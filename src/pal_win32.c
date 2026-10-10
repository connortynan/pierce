/* PAL implementation for Windows (Winsock 2, IP Helper, CNG). */
#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600   /* Vista: WSAPoll, SRW locks */
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <bcrypt.h>
#include <mstcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pal.h"

#if defined(_MSC_VER)
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "bcrypt.lib")
#endif

#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif

static volatile LONG init_count;

int pal_init(void)
{
    if (InterlockedIncrement(&init_count) == 1) {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            InterlockedDecrement(&init_count);
            return PIERCE_ERR_PLATFORM;
        }
    }
    return PIERCE_OK;
}

void pal_shutdown(void)
{
    if (InterlockedDecrement(&init_count) == 0) WSACleanup();
}

uint64_t pal_now_us(void)
{
    static LARGE_INTEGER freq;
    LARGE_INTEGER now;
    if (!freq.QuadPart) QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&now);
    /* Split to avoid overflow of now * 1e6. */
    uint64_t sec = (uint64_t)now.QuadPart / (uint64_t)freq.QuadPart;
    uint64_t rem = (uint64_t)now.QuadPart % (uint64_t)freq.QuadPart;
    return sec * 1000000u + rem * 1000000u / (uint64_t)freq.QuadPart;
}

int pal_random(void *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf;
    while (len > 0) {
        ULONG chunk = len > 0x40000000u ? 0x40000000u : (ULONG)len;
        if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, p, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
            return PIERCE_ERR_PLATFORM;
        p += chunk;
        len -= chunk;
    }
    return PIERCE_OK;
}

/* ---- address conversion ---- */

static int to_sockaddr(const pierce_addr *a, struct sockaddr_storage *ss)
{
    memset(ss, 0, sizeof(*ss));
    if (a->family == PIERCE_AF_INET) {
        struct sockaddr_in *s4 = (struct sockaddr_in *)ss;
        s4->sin_family = AF_INET;
        s4->sin_port = htons(a->port);
        memcpy(&s4->sin_addr, a->addr, 4);
        return (int)sizeof(*s4);
    }
    if (a->family == PIERCE_AF_INET6) {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ss;
        s6->sin6_family = AF_INET6;
        s6->sin6_port = htons(a->port);
        s6->sin6_scope_id = a->scope_id;
        memcpy(&s6->sin6_addr, a->addr, 16);
        return (int)sizeof(*s6);
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

static int would_block(int e)
{
    /* WSAECONNRESET on UDP is an ICMP port-unreachable echo: treat as noise. */
    return e == WSAEWOULDBLOCK || e == WSAEINTR || e == WSAENOBUFS || e == WSAECONNRESET ||
           e == WSAEMSGSIZE;
}

static int open_socket(uint32_t family, int type, SOCKET *out)
{
    int af = family == PIERCE_AF_INET6 ? AF_INET6 : AF_INET;
    SOCKET s = socket(af, type, type == SOCK_DGRAM ? IPPROTO_UDP : IPPROTO_TCP);
    if (s == INVALID_SOCKET) return PIERCE_ERR_PLATFORM;
    u_long nb = 1;
    if (ioctlsocket(s, FIONBIO, &nb) != 0) {
        closesocket(s);
        return PIERCE_ERR_PLATFORM;
    }
    if (af == AF_INET6) {
        DWORD on = 1;
        setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&on, sizeof(on));
    }
    *out = s;
    return PIERCE_OK;
}

static int bind_any(SOCKET s, uint32_t family, uint16_t port)
{
    pierce_addr any;
    struct sockaddr_storage ss;
    memset(&any, 0, sizeof(any));
    any.family = family;
    any.port = port;
    int sl = to_sockaddr(&any, &ss);
    return bind(s, (struct sockaddr *)&ss, sl) == 0 ? 0 : -1;
}

int pal_udp_open(uint32_t family, uint16_t port, pal_sock *out)
{
    SOCKET s;
    int rc = open_socket(family, SOCK_DGRAM, &s);
    if (rc) return rc;
    /* Without this, an ICMP port unreachable makes the next recvfrom fail. */
    BOOL off = FALSE;
    DWORD bytes = 0;
    WSAIoctl(s, SIO_UDP_CONNRESET, &off, sizeof(off), NULL, 0, &bytes, NULL, NULL);
    int buf = 1 << 20;
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, (const char *)&buf, sizeof(buf));
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, (const char *)&buf, sizeof(buf));
    if (bind_any(s, family, port) < 0) {
        closesocket(s);
        return PIERCE_ERR_PLATFORM;
    }
    *out = (pal_sock)s;
    return PIERCE_OK;
}

int pal_udp_send(pal_sock s, const pierce_addr *to, const void *data, size_t len)
{
    struct sockaddr_storage ss;
    int sl = to_sockaddr(to, &ss);
    if (sl == 0) return PIERCE_ERR_INVALID_ARG;
    int r = sendto((SOCKET)s, (const char *)data, (int)len, 0, (struct sockaddr *)&ss, sl);
    if (r != SOCKET_ERROR) return PIERCE_OK;
    return would_block(WSAGetLastError()) ? PIERCE_ERR_WOULD_BLOCK : PIERCE_ERR_PLATFORM;
}

int pal_udp_recv(pal_sock s, void *buf, size_t cap, pierce_addr *from)
{
    struct sockaddr_storage ss;
    int sl = (int)sizeof(ss);
    int r = recvfrom((SOCKET)s, (char *)buf, (int)cap, 0, (struct sockaddr *)&ss, &sl);
    if (r == SOCKET_ERROR)
        return would_block(WSAGetLastError()) ? PIERCE_ERR_WOULD_BLOCK : PIERCE_ERR_PLATFORM;
    from_sockaddr((struct sockaddr *)&ss, from);
    return r;
}

int pal_sock_local_addr(pal_sock s, pierce_addr *out)
{
    struct sockaddr_storage ss;
    int sl = (int)sizeof(ss);
    if (getsockname((SOCKET)s, (struct sockaddr *)&ss, &sl) != 0) return PIERCE_ERR_PLATFORM;
    from_sockaddr((struct sockaddr *)&ss, out);
    return PIERCE_OK;
}

void pal_sock_close(pal_sock s)
{
    if (s != PAL_INVALID_SOCK) closesocket((SOCKET)s);
}

/* ---- TCP ---- */

int pal_tcp_connect(const pierce_addr *to, pal_sock *out)
{
    SOCKET s;
    int rc = open_socket(to->family, SOCK_STREAM, &s);
    if (rc) return rc;
    BOOL on = TRUE;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof(on));
    struct sockaddr_storage ss;
    int sl = to_sockaddr(to, &ss);
    if (connect(s, (struct sockaddr *)&ss, sl) == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) {
        closesocket(s);
        return PIERCE_ERR_PLATFORM;
    }
    *out = (pal_sock)s;
    return PIERCE_OK;
}

int pal_tcp_connect_result(pal_sock s)
{
    WSAPOLLFD p;
    p.fd = (SOCKET)s;
    p.events = POLLWRNORM;
    p.revents = 0;
    if (WSAPoll(&p, 1, 0) <= 0) return 0;
    int err = 0, el = (int)sizeof(err);
    if (getsockopt((SOCKET)s, SOL_SOCKET, SO_ERROR, (char *)&err, &el) != 0 || err != 0)
        return PIERCE_ERR_PLATFORM;
    return (p.revents & (POLLERR | POLLHUP)) ? PIERCE_ERR_PLATFORM : 1;
}

int pal_tcp_listen(uint32_t family, uint16_t port, pal_sock *out)
{
    SOCKET s;
    int rc = open_socket(family, SOCK_STREAM, &s);
    if (rc) return rc;
    BOOL excl = TRUE;   /* Windows SO_REUSEADDR would allow port theft */
    setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&excl, sizeof(excl));
    if (bind_any(s, family, port) < 0 || listen(s, 128) != 0) {
        closesocket(s);
        return PIERCE_ERR_PLATFORM;
    }
    *out = (pal_sock)s;
    return PIERCE_OK;
}

int pal_tcp_accept(pal_sock listener, pal_sock *out, pierce_addr *peer)
{
    struct sockaddr_storage ss;
    int sl = (int)sizeof(ss);
    SOCKET s = accept((SOCKET)listener, (struct sockaddr *)&ss, &sl);
    if (s == INVALID_SOCKET)
        return would_block(WSAGetLastError()) ? PIERCE_ERR_WOULD_BLOCK : PIERCE_ERR_PLATFORM;
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
    BOOL on = TRUE;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof(on));
    if (peer) from_sockaddr((struct sockaddr *)&ss, peer);
    *out = (pal_sock)s;
    return PIERCE_OK;
}

int pal_tcp_send(pal_sock s, const void *data, size_t len)
{
    int r = send((SOCKET)s, (const char *)data, (int)len, 0);
    if (r != SOCKET_ERROR) return r;
    int e = WSAGetLastError();
    return (e == WSAEWOULDBLOCK || e == WSAEINTR) ? PIERCE_ERR_WOULD_BLOCK : PIERCE_ERR_PLATFORM;
}

int pal_tcp_recv(pal_sock s, void *buf, size_t cap)
{
    int r = recv((SOCKET)s, (char *)buf, (int)cap, 0);
    if (r != SOCKET_ERROR) return r;
    int e = WSAGetLastError();
    return (e == WSAEWOULDBLOCK || e == WSAEINTR) ? PIERCE_ERR_WOULD_BLOCK : PIERCE_ERR_PLATFORM;
}

/* ---- wait ---- */

int pal_wait(pal_pollfd *fds, uint32_t n, int32_t timeout_ms)
{
    WSAPOLLFD stackp[16];
    WSAPOLLFD *p = n <= 16 ? stackp : (WSAPOLLFD *)malloc(n * sizeof(*p));
    if (!p) return PIERCE_ERR_NO_MEMORY;
    for (uint32_t i = 0; i < n; i++) {
        p[i].fd = (SOCKET)fds[i].sock;
        p[i].events = (SHORT)(POLLRDNORM | (fds[i].want_write ? POLLWRNORM : 0));
        p[i].revents = 0;
    }
    int r = WSAPoll(p, (ULONG)n, timeout_ms < 0 ? -1 : timeout_ms);
    for (uint32_t i = 0; i < n; i++) {
        fds[i].readable = (p[i].revents & (POLLRDNORM | POLLHUP)) != 0;
        fds[i].writable = (p[i].revents & POLLWRNORM) != 0;
        fds[i].failed = (p[i].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0;
    }
    if (p != stackp) free(p);
    return r == SOCKET_ERROR ? PIERCE_ERR_PLATFORM : r;
}

/* ---- wake: a loopback UDP pair (WSAPoll only waits on sockets) ---- */

int pal_wake_open(pal_wakeup *w)
{
    SOCKET rd = INVALID_SOCKET, wr = INVALID_SOCKET;
    pierce_addr lo;
    struct sockaddr_storage ss;
    memset(&lo, 0, sizeof(lo));
    lo.family = PIERCE_AF_INET;
    lo.addr[0] = 127;
    lo.addr[3] = 1;
    if (open_socket(PIERCE_AF_INET, SOCK_DGRAM, &rd) != PIERCE_OK) return PIERCE_ERR_PLATFORM;
    int sl = to_sockaddr(&lo, &ss);
    if (bind(rd, (struct sockaddr *)&ss, sl) != 0) goto fail;
    if (pal_sock_local_addr((pal_sock)rd, &lo) != PIERCE_OK) goto fail;
    if (open_socket(PIERCE_AF_INET, SOCK_DGRAM, &wr) != PIERCE_OK) goto fail;
    sl = to_sockaddr(&lo, &ss);
    if (connect(wr, (struct sockaddr *)&ss, sl) != 0) goto fail;
    w->rd = (pal_sock)rd;
    w->wr = (pal_sock)wr;
    return PIERCE_OK;
fail:
    if (rd != INVALID_SOCKET) closesocket(rd);
    if (wr != INVALID_SOCKET) closesocket(wr);
    return PIERCE_ERR_PLATFORM;
}

void pal_wake_signal(pal_wakeup *w)
{
    char one = 1;
    send((SOCKET)w->wr, &one, 1, 0);
}

void pal_wake_drain(pal_wakeup *w)
{
    char buf[64];
    while (recv((SOCKET)w->rd, buf, sizeof(buf), 0) > 0) {
    }
}

void pal_wake_close(pal_wakeup *w)
{
    if (w->rd != PAL_INVALID_SOCK) closesocket((SOCKET)w->rd);
    if (w->wr != PAL_INVALID_SOCK) closesocket((SOCKET)w->wr);
    w->rd = w->wr = PAL_INVALID_SOCK;
}

/* ---- interfaces / resolution ---- */

int pal_interfaces(pierce_addr *out, uint32_t cap, int include_loopback)
{
    ULONG size = 16 * 1024;
    IP_ADAPTER_ADDRESSES *list = NULL;
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG rc;
    for (int tries = 0; tries < 3; tries++) {
        list = (IP_ADAPTER_ADDRESSES *)malloc(size);
        if (!list) return 0;
        rc = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, list, &size);
        if (rc == ERROR_SUCCESS) break;
        free(list);
        list = NULL;
        if (rc != ERROR_BUFFER_OVERFLOW) return 0;
    }
    if (!list) return 0;
    uint32_t n = 0;
    for (IP_ADAPTER_ADDRESSES *ad = list; ad && n < cap; ad = ad->Next) {
        if (ad->OperStatus != IfOperStatusUp) continue;
        if (ad->IfType == IF_TYPE_SOFTWARE_LOOPBACK && !include_loopback) continue;
        for (IP_ADAPTER_UNICAST_ADDRESS *ua = ad->FirstUnicastAddress; ua && n < cap; ua = ua->Next) {
            pierce_addr a;
            from_sockaddr(ua->Address.lpSockaddr, &a);
            a.port = 0;
            if (a.family == PIERCE_AF_INET) {
                if (a.addr[0] == 169 && a.addr[1] == 254) continue;
                if (a.addr[0] == 127 && !include_loopback) continue;
            } else if (a.family == PIERCE_AF_INET6) {
                if (a.addr[0] == 0xfe && (a.addr[1] & 0xc0) == 0x80) continue;
                /* Skip temporary (privacy) addresses: they rotate. */
                if (ua->SuffixOrigin == IpSuffixOriginRandom) continue;
                a.scope_id = 0;
            } else {
                continue;
            }
            out[n++] = a;
        }
    }
    free(list);
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

/* ---- mutex: SRWLOCK is a single pointer, stored in pal_mutex ---- */

int pal_mutex_init(pal_mutex *m)
{
    InitializeSRWLock((PSRWLOCK)&m->srw);
    return PIERCE_OK;
}
void pal_mutex_lock(pal_mutex *m) { AcquireSRWLockExclusive((PSRWLOCK)&m->srw); }
void pal_mutex_unlock(pal_mutex *m) { ReleaseSRWLockExclusive((PSRWLOCK)&m->srw); }
void pal_mutex_destroy(pal_mutex *m) { (void)m; }

#else
typedef int pal_win32_unused; /* ISO C forbids an empty translation unit */
#endif /* _WIN32 */
