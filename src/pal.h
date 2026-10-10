/*
 * Platform Abstraction Layer. The only place platform differences live.
 * Implemented by pal_posix.c and pal_win32.c (each compiles to nothing on
 * the other platform, so compiling every file in src/ works everywhere).
 */
#ifndef PIERCE_PAL_H
#define PIERCE_PAL_H

#include <stddef.h>
#include <stdint.h>

#include "pierce.h"

#if !defined(_WIN32)
#include <pthread.h>
#endif

typedef pierce_socket pal_sock;
#define PAL_INVALID_SOCK ((pal_sock)~(uintptr_t)0)

/* Process-wide setup (WSAStartup on Windows). Reference counted. */
int  pal_init(void);
void pal_shutdown(void);

/* Monotonic clock, microseconds. */
uint64_t pal_now_us(void);

/* OS CSPRNG. Returns PIERCE_OK or PIERCE_ERR_PLATFORM. Never falls back to a
   weak source. */
int pal_random(void *buf, size_t len);

/* ---- UDP (non-blocking) ---- */
int  pal_udp_open(uint32_t family, uint16_t port, pal_sock *out);
/* 0, PIERCE_ERR_WOULD_BLOCK, or PIERCE_ERR_PLATFORM. */
int  pal_udp_send(pal_sock s, const pierce_addr *to, const void *data, size_t len);
/* Length received, PIERCE_ERR_WOULD_BLOCK, or PIERCE_ERR_PLATFORM. */
int  pal_udp_recv(pal_sock s, void *buf, size_t cap, pierce_addr *from);
int  pal_sock_local_addr(pal_sock s, pierce_addr *out);
void pal_sock_close(pal_sock s);

/* ---- TCP (non-blocking) ---- */
int pal_tcp_connect(const pierce_addr *to, pal_sock *out);
/* 1 connected, 0 still pending, <0 failed. */
int pal_tcp_connect_result(pal_sock s);
int pal_tcp_listen(uint32_t family, uint16_t port, pal_sock *out);
int pal_tcp_accept(pal_sock listener, pal_sock *out, pierce_addr *peer);
/* Bytes moved (>0), 0 = peer closed (recv only), WOULD_BLOCK, or error. */
int pal_tcp_send(pal_sock s, const void *data, size_t len);
int pal_tcp_recv(pal_sock s, void *buf, size_t cap);

/* ---- readiness wait ---- */
typedef struct {
    pal_sock sock;
    uint8_t  want_write;
    uint8_t  readable;   /* out */
    uint8_t  writable;   /* out */
    uint8_t  failed;     /* out: error or hangup */
} pal_pollfd;

/* Returns number of ready entries, 0 on timeout, <0 on error.
   timeout_ms < 0 blocks indefinitely. */
int pal_wait(pal_pollfd *fds, uint32_t n, int32_t timeout_ms);

/* ---- wake mechanism (backs pierce_wake) ---- */
typedef struct {
    pal_sock rd;   /* include in pal_wait */
    pal_sock wr;
} pal_wakeup;

int  pal_wake_open(pal_wakeup *w);
void pal_wake_signal(pal_wakeup *w);   /* thread-safe */
void pal_wake_drain(pal_wakeup *w);
void pal_wake_close(pal_wakeup *w);

/* ---- interfaces and names ---- */
/* Usable unicast addresses of up interfaces (port 0). Link-local addresses
   are excluded; loopback only if include_loopback. Returns count. */
int pal_interfaces(pierce_addr *out, uint32_t cap, int include_loopback);
/* getaddrinfo wrapper (may block). Returns count of addresses written. */
int pal_resolve(const char *host, uint16_t port, pierce_addr *out, uint32_t cap);

/* ---- mutex ---- */
#if defined(_WIN32)
typedef struct { void *srw; } pal_mutex;     /* SRWLOCK storage */
#else
typedef struct { pthread_mutex_t m; } pal_mutex;
#endif

int  pal_mutex_init(pal_mutex *m);
void pal_mutex_lock(pal_mutex *m);
void pal_mutex_unlock(pal_mutex *m);
void pal_mutex_destroy(pal_mutex *m);

/* ---- atomics ---- */
#if defined(_MSC_VER) && !defined(__clang__)
#include <intrin.h>
static __inline uint32_t pal_atomic_load(volatile uint32_t *p)
{
    return (uint32_t)_InterlockedOr((volatile long *)p, 0);
}
static __inline void pal_atomic_store(volatile uint32_t *p, uint32_t v)
{
    _InterlockedExchange((volatile long *)p, (long)v);
}
/* Returns the new value. */
static __inline uint32_t pal_atomic_add(volatile uint32_t *p, int32_t d)
{
    return (uint32_t)(_InterlockedExchangeAdd((volatile long *)p, (long)d) + d);
}
static __inline uint32_t pal_atomic_exchange(volatile uint32_t *p, uint32_t v)
{
    return (uint32_t)_InterlockedExchange((volatile long *)p, (long)v);
}
#else
static __inline__ uint32_t pal_atomic_load(volatile uint32_t *p)
{
    return __atomic_load_n(p, __ATOMIC_ACQUIRE);
}
static __inline__ void pal_atomic_store(volatile uint32_t *p, uint32_t v)
{
    __atomic_store_n(p, v, __ATOMIC_RELEASE);
}
static __inline__ uint32_t pal_atomic_add(volatile uint32_t *p, int32_t d)
{
    return __atomic_add_fetch(p, (uint32_t)d, __ATOMIC_ACQ_REL);
}
static __inline__ uint32_t pal_atomic_exchange(volatile uint32_t *p, uint32_t v)
{
    return __atomic_exchange_n(p, v, __ATOMIC_ACQ_REL);
}
#endif

#endif /* PIERCE_PAL_H */
