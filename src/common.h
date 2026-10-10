/* Internal helpers shared by every module above the PAL. */
#ifndef PIERCE_COMMON_H
#define PIERCE_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "pierce.h"

#define PC_MIN(a, b) ((a) < (b) ? (a) : (b))
#define PC_MAX(a, b) ((a) > (b) ? (a) : (b))
#define PC_ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

/* Largest UDP payload Pierce ever sends (spec 6: conservative MTU). */
#define PC_MTU 1200

/* ---- allocation ---- */

typedef struct {
    void *(*alloc)(size_t size, void *user);
    void (*free)(void *ptr, void *user);
    void *user;
} pc_allocator;

void pc_allocator_init(pc_allocator *a, const pierce_allocator *user);
void *pc_alloc(const pc_allocator *a, size_t size);    /* zeroed */
void pc_free(const pc_allocator *a, void *p);
/* Grow-only array reallocation (copies, frees old). */
void *pc_realloc(const pc_allocator *a, void *p, size_t old_size, size_t new_size);

/* Random bytes from the OS. Aborts the process if the OS source fails:
   continuing without randomness would be a security failure. */
void pc_random(void *buf, size_t len);
uint64_t pc_random_u64(void);

/* ---- refcounted message buffers ---- */

typedef struct pc_msg {
    volatile uint32_t refs;
    uint32_t len;
    pc_allocator alloc;
    uint8_t data[1];        /* actually len bytes */
} pc_msg;

pc_msg *pc_msg_new(const pc_allocator *a, const void *data, uint32_t len);
void pc_msg_ref(pc_msg *m);
void pc_msg_unref(pc_msg *m);

/* ---- byte order ---- */

static inline void pc_put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static inline void pc_put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}
static inline void pc_put64(uint8_t *p, uint64_t v) { pc_put32(p, (uint32_t)(v >> 32)); pc_put32(p + 4, (uint32_t)v); }
static inline uint16_t pc_get16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static inline uint32_t pc_get32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static inline uint64_t pc_get64(const uint8_t *p) { return ((uint64_t)pc_get32(p) << 32) | pc_get32(p + 4); }

/* ---- bounded writer / reader ----
   Errors are sticky: once a write overflows or a read underflows, every
   later call is a no-op and `err` stays set. Check once at the end. */

typedef struct {
    uint8_t *p;
    size_t len, cap;
    int err;
} pc_wbuf;

typedef struct {
    const uint8_t *p;
    size_t len, pos;
    int err;
} pc_rbuf;

static inline void pc_wbuf_init(pc_wbuf *w, uint8_t *p, size_t cap) { w->p = p; w->len = 0; w->cap = cap; w->err = 0; }
static inline void pc_rbuf_init(pc_rbuf *r, const uint8_t *p, size_t len) { r->p = p; r->len = len; r->pos = 0; r->err = 0; }
static inline size_t pc_rbuf_left(const pc_rbuf *r) { return r->err ? 0 : r->len - r->pos; }

void pc_w_u8(pc_wbuf *w, uint8_t v);
void pc_w_u16(pc_wbuf *w, uint16_t v);
void pc_w_u32(pc_wbuf *w, uint32_t v);
void pc_w_u64(pc_wbuf *w, uint64_t v);
void pc_w_bytes(pc_wbuf *w, const void *p, size_t n);
void pc_w_zeros(pc_wbuf *w, size_t n);
void pc_w_varint(pc_wbuf *w, uint64_t v);
void pc_w_addr(pc_wbuf *w, const pierce_addr *a);   /* 19 bytes */

uint8_t pc_r_u8(pc_rbuf *r);
uint16_t pc_r_u16(pc_rbuf *r);
uint32_t pc_r_u32(pc_rbuf *r);
uint64_t pc_r_u64(pc_rbuf *r);
void pc_r_bytes(pc_rbuf *r, void *out, size_t n);
const uint8_t *pc_r_ptr(pc_rbuf *r, size_t n);       /* NULL on underflow */
uint64_t pc_r_varint(pc_rbuf *r);
void pc_r_addr(pc_rbuf *r, pierce_addr *a);

/* QUIC-style varint: 1, 2, 4 or 8 bytes; values < 2^62. */
size_t pc_varint_size(uint64_t v);

#define PC_ADDR_WIRE_SIZE 19

/* ---- addresses ---- */

int pc_addr_eq(const pierce_addr *a, const pierce_addr *b);   /* family, ip, port */
int pc_addr_ip_eq(const pierce_addr *a, const pierce_addr *b); /* family, ip */
int pc_addr_is_private(const pierce_addr *a);

#endif /* PIERCE_COMMON_H */
