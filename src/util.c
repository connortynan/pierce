#include "common.h"

#include <stdio.h>
#include <stdlib.h>

#include "pal.h"

/* ---- allocation ---- */

static void *default_alloc(size_t size, void *user) { (void)user; return malloc(size); }
static void default_free(void *p, void *user) { (void)user; free(p); }

void pc_allocator_init(pc_allocator *a, const pierce_allocator *user)
{
    if (user && user->alloc && user->free) {
        a->alloc = user->alloc;
        a->free = user->free;
        a->user = user->user;
    } else {
        a->alloc = default_alloc;
        a->free = default_free;
        a->user = NULL;
    }
}

void *pc_alloc(const pc_allocator *a, size_t size)
{
    void *p = a->alloc(size ? size : 1, a->user);
    if (p) memset(p, 0, size);
    return p;
}

void pc_free(const pc_allocator *a, void *p)
{
    if (p) a->free(p, a->user);
}

void *pc_realloc(const pc_allocator *a, void *p, size_t old_size, size_t new_size)
{
    void *n = pc_alloc(a, new_size);
    if (!n) return NULL;
    if (p) {
        memcpy(n, p, PC_MIN(old_size, new_size));
        pc_free(a, p);
    }
    return n;
}

void pc_random(void *buf, size_t len)
{
    if (pal_random(buf, len) != PIERCE_OK) {
        fprintf(stderr, "pierce: OS random number generator failed; aborting\n");
        abort();
    }
}

uint64_t pc_random_u64(void)
{
    uint8_t b[8];
    pc_random(b, 8);
    return pc_get64(b);
}

/* ---- messages ---- */

pc_msg *pc_msg_new(const pc_allocator *a, const void *data, uint32_t len)
{
    pc_msg *m = (pc_msg *)a->alloc(offsetof(pc_msg, data) + (len ? len : 1), a->user);
    if (!m) return NULL;
    m->refs = 1;
    m->len = len;
    m->alloc = *a;
    if (data && len) memcpy(m->data, data, len);
    return m;
}

void pc_msg_ref(pc_msg *m)
{
    pal_atomic_add(&m->refs, 1);
}

void pc_msg_unref(pc_msg *m)
{
    if (m && pal_atomic_add(&m->refs, -1) == 0) {
        pc_allocator a = m->alloc;
        a.free(m, a.user);
    }
}

/* ---- writer ---- */

static uint8_t *w_reserve(pc_wbuf *w, size_t n)
{
    if (w->err || w->cap - w->len < n) { w->err = 1; return NULL; }
    uint8_t *p = w->p + w->len;
    w->len += n;
    return p;
}

void pc_w_u8(pc_wbuf *w, uint8_t v) { uint8_t *p = w_reserve(w, 1); if (p) *p = v; }
void pc_w_u16(pc_wbuf *w, uint16_t v) { uint8_t *p = w_reserve(w, 2); if (p) pc_put16(p, v); }
void pc_w_u32(pc_wbuf *w, uint32_t v) { uint8_t *p = w_reserve(w, 4); if (p) pc_put32(p, v); }
void pc_w_u64(pc_wbuf *w, uint64_t v) { uint8_t *p = w_reserve(w, 8); if (p) pc_put64(p, v); }

void pc_w_bytes(pc_wbuf *w, const void *src, size_t n)
{
    uint8_t *p = w_reserve(w, n);
    if (p && n) memcpy(p, src, n);
}

void pc_w_zeros(pc_wbuf *w, size_t n)
{
    uint8_t *p = w_reserve(w, n);
    if (p && n) memset(p, 0, n);
}

size_t pc_varint_size(uint64_t v)
{
    if (v < 0x40) return 1;
    if (v < 0x4000) return 2;
    if (v < 0x40000000) return 4;
    return 8;
}

void pc_w_varint(pc_wbuf *w, uint64_t v)
{
    switch (pc_varint_size(v)) {
    case 1: pc_w_u8(w, (uint8_t)v); break;
    case 2: pc_w_u16(w, (uint16_t)(0x4000 | v)); break;
    case 4: pc_w_u32(w, (uint32_t)(0x80000000u | v)); break;
    default:
        if (v >= ((uint64_t)1 << 62)) { w->err = 1; return; }
        pc_w_u64(w, 0xC000000000000000ull | v);
    }
}

void pc_w_addr(pc_wbuf *w, const pierce_addr *a)
{
    pc_w_u8(w, (uint8_t)a->family);
    pc_w_u16(w, a->port);
    pc_w_bytes(w, a->addr, 16);
}

/* ---- reader ---- */

static const uint8_t *r_take(pc_rbuf *r, size_t n)
{
    if (r->err || r->len - r->pos < n) { r->err = 1; return NULL; }
    const uint8_t *p = r->p + r->pos;
    r->pos += n;
    return p;
}

uint8_t pc_r_u8(pc_rbuf *r) { const uint8_t *p = r_take(r, 1); return p ? p[0] : 0; }
uint16_t pc_r_u16(pc_rbuf *r) { const uint8_t *p = r_take(r, 2); return p ? pc_get16(p) : 0; }
uint32_t pc_r_u32(pc_rbuf *r) { const uint8_t *p = r_take(r, 4); return p ? pc_get32(p) : 0; }
uint64_t pc_r_u64(pc_rbuf *r) { const uint8_t *p = r_take(r, 8); return p ? pc_get64(p) : 0; }

void pc_r_bytes(pc_rbuf *r, void *out, size_t n)
{
    const uint8_t *p = r_take(r, n);
    if (p) memcpy(out, p, n);
    else memset(out, 0, n);
}

const uint8_t *pc_r_ptr(pc_rbuf *r, size_t n) { return r_take(r, n); }

uint64_t pc_r_varint(pc_rbuf *r)
{
    if (r->err || r->pos >= r->len) { r->err = 1; return 0; }
    uint8_t first = r->p[r->pos];
    switch (first >> 6) {
    case 0: return pc_r_u8(r) & 0x3f;
    case 1: return pc_r_u16(r) & 0x3fff;
    case 2: return pc_r_u32(r) & 0x3fffffffu;
    default: return pc_r_u64(r) & 0x3fffffffffffffffull;
    }
}

void pc_r_addr(pc_rbuf *r, pierce_addr *a)
{
    memset(a, 0, sizeof(*a));
    a->family = pc_r_u8(r);
    a->port = pc_r_u16(r);
    pc_r_bytes(r, a->addr, 16);
    if (a->family != PIERCE_AF_INET && a->family != PIERCE_AF_INET6 && a->family != PIERCE_AF_NONE)
        r->err = 1;
    if (a->family == PIERCE_AF_INET) memset(a->addr + 4, 0, 12);
}

/* ---- addresses ---- */

int pc_addr_ip_eq(const pierce_addr *a, const pierce_addr *b)
{
    if (a->family != b->family) return 0;
    if (a->family == PIERCE_AF_INET) return memcmp(a->addr, b->addr, 4) == 0;
    if (a->family == PIERCE_AF_INET6) return memcmp(a->addr, b->addr, 16) == 0;
    if (a->family == PIERCE_AF_CUSTOM) return a->custom == b->custom;
    return 1;
}

int pc_addr_eq(const pierce_addr *a, const pierce_addr *b)
{
    return pc_addr_ip_eq(a, b) && a->port == b->port;
}

int pc_addr_is_private(const pierce_addr *a)
{
    const uint8_t *p = a->addr;
    if (a->family == PIERCE_AF_INET)
        return p[0] == 10 || p[0] == 127 || (p[0] == 172 && (p[1] & 0xf0) == 16) ||
               (p[0] == 192 && p[1] == 168) || (p[0] == 100 && (p[1] & 0xc0) == 64);
    if (a->family == PIERCE_AF_INET6)
        return (p[0] & 0xfe) == 0xfc || (p[0] == 0xfe && (p[1] & 0xc0) == 0x80);
    return 0;
}

/* ---- public address helpers ---- */

static int parse_ipv4(const char *s, size_t n, uint8_t out[4])
{
    unsigned part = 0, digits = 0, idx = 0;
    for (size_t i = 0; i <= n; i++) {
        char c = i < n ? s[i] : '.';
        if (c >= '0' && c <= '9') {
            part = part * 10 + (unsigned)(c - '0');
            if (++digits > 3 || part > 255) return -1;
        } else if (c == '.') {
            if (!digits || idx >= 4) return -1;
            out[idx++] = (uint8_t)part;
            part = digits = 0;
        } else {
            return -1;
        }
    }
    return idx == 4 ? 0 : -1;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_ipv6(const char *s, size_t n, uint8_t out[16])
{
    uint16_t head[8], tail[8];
    int nh = 0, nt = 0, gap = 0;
    size_t i = 0;
    if (n >= 2 && s[0] == ':' && s[1] == ':') { gap = 1; i = 2; }
    while (i < n) {
        /* Embedded IPv4 in the last 32 bits. */
        size_t j = i;
        while (j < n && s[j] != ':') j++;
        int has_dot = 0;
        for (size_t k = i; k < j; k++) if (s[k] == '.') has_dot = 1;
        if (has_dot) {
            uint8_t v4[4];
            if (j != n || parse_ipv4(s + i, j - i, v4) < 0) return -1;
            uint16_t *dst = gap ? tail : head;
            int *cnt = gap ? &nt : &nh;
            if (*cnt + 2 > 8) return -1;
            dst[(*cnt)++] = (uint16_t)((v4[0] << 8) | v4[1]);
            dst[(*cnt)++] = (uint16_t)((v4[2] << 8) | v4[3]);
            i = n;
            break;
        }
        if (j == i || j - i > 4) return -1;
        unsigned v = 0;
        for (size_t k = i; k < j; k++) {
            int h = hexval(s[k]);
            if (h < 0) return -1;
            v = (v << 4) | (unsigned)h;
        }
        if (gap) { if (nt >= 8) return -1; tail[nt++] = (uint16_t)v; }
        else { if (nh >= 8) return -1; head[nh++] = (uint16_t)v; }
        i = j;
        if (i < n) {
            i++; /* skip ':' */
            if (i < n && s[i] == ':') {
                if (gap) return -1;
                gap = 1;
                i++;
            } else if (i == n) {
                return -1;
            }
        }
    }
    if (gap ? nh + nt > 7 : nh != 8) return -1;
    memset(out, 0, 16);
    for (int k = 0; k < nh; k++) { out[2 * k] = (uint8_t)(head[k] >> 8); out[2 * k + 1] = (uint8_t)head[k]; }
    for (int k = 0; k < nt; k++) {
        int pos = 8 - nt + k;
        out[2 * pos] = (uint8_t)(tail[k] >> 8);
        out[2 * pos + 1] = (uint8_t)tail[k];
    }
    return 0;
}

static int parse_port(const char *s, uint16_t *out)
{
    unsigned v = 0;
    if (!*s) return -1;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return -1;
        v = v * 10 + (unsigned)(*s - '0');
        if (v > 65535) return -1;
    }
    *out = (uint16_t)v;
    return 0;
}

int pierce_addr_parse(const char *str, pierce_addr *out)
{
    if (!str || !out) return PIERCE_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));
    if (str[0] == '[') {
        const char *end = strchr(str, ']');
        if (!end || end[1] != ':') return PIERCE_ERR_INVALID_ARG;
        const char *pct = memchr(str + 1, '%', (size_t)(end - str - 1));
        size_t iplen = (size_t)((pct ? pct : end) - (str + 1));
        if (parse_ipv6(str + 1, iplen, out->addr) < 0) return PIERCE_ERR_INVALID_ARG;
        if (pct) {
            unsigned z = 0;
            for (const char *p = pct + 1; p < end; p++) {
                if (*p < '0' || *p > '9') return PIERCE_ERR_INVALID_ARG;
                z = z * 10 + (unsigned)(*p - '0');
            }
            out->scope_id = z;
        }
        if (parse_port(end + 2, &out->port) < 0) return PIERCE_ERR_INVALID_ARG;
        out->family = PIERCE_AF_INET6;
        return PIERCE_OK;
    }
    const char *colon = strrchr(str, ':');
    if (!colon) return PIERCE_ERR_INVALID_ARG;
    if (parse_ipv4(str, (size_t)(colon - str), out->addr) < 0) return PIERCE_ERR_INVALID_ARG;
    if (parse_port(colon + 1, &out->port) < 0) return PIERCE_ERR_INVALID_ARG;
    out->family = PIERCE_AF_INET;
    return PIERCE_OK;
}

int pierce_addr_format(const pierce_addr *a, char *buf, uint32_t cap)
{
    char tmp[64];
    int n;
    if (!a || !buf) return PIERCE_ERR_INVALID_ARG;
    if (a->family == PIERCE_AF_INET) {
        n = snprintf(tmp, sizeof(tmp), "%u.%u.%u.%u:%u", a->addr[0], a->addr[1], a->addr[2],
                     a->addr[3], a->port);
    } else if (a->family == PIERCE_AF_INET6) {
        /* RFC 5952: compress the longest run of two or more zero groups. */
        uint16_t g[8];
        int best = -1, bestlen = 0;
        for (int i = 0; i < 8; i++) g[i] = (uint16_t)((a->addr[2 * i] << 8) | a->addr[2 * i + 1]);
        for (int i = 0; i < 8;) {
            if (g[i]) { i++; continue; }
            int j = i;
            while (j < 8 && !g[j]) j++;
            if (j - i > bestlen && j - i >= 2) { best = i; bestlen = j - i; }
            i = j;
        }
        n = 0;
        tmp[n++] = '[';
        for (int i = 0; i < 8; i++) {
            if (i == best) {
                n += snprintf(tmp + n, sizeof(tmp) - (size_t)n, "::");
                i += bestlen - 1;
                continue;
            }
            if (i && !(best >= 0 && i == best + bestlen)) tmp[n++] = ':';
            n += snprintf(tmp + n, sizeof(tmp) - (size_t)n, "%x", g[i]);
        }
        if (a->scope_id) n += snprintf(tmp + n, sizeof(tmp) - (size_t)n, "%%%u", a->scope_id);
        n += snprintf(tmp + n, sizeof(tmp) - (size_t)n, "]:%u", a->port);
    } else if (a->family == PIERCE_AF_CUSTOM) {
        n = snprintf(tmp, sizeof(tmp), "custom:%llu", (unsigned long long)a->custom);
    } else {
        n = snprintf(tmp, sizeof(tmp), "none");
    }
    if ((uint32_t)n + 1 > cap) return PIERCE_ERR_BUFFER_TOO_SMALL;
    memcpy(buf, tmp, (size_t)n + 1);
    return n;
}

const char *pierce_strerror(int code)
{
    switch (code) {
    case PIERCE_OK: return "ok";
    case PIERCE_ERR_INVALID_ARG: return "invalid argument";
    case PIERCE_ERR_NO_MEMORY: return "out of memory";
    case PIERCE_ERR_NO_SUCH_CONN: return "no such connection";
    case PIERCE_ERR_WOULD_BLOCK: return "send queue full";
    case PIERCE_ERR_NOT_SUPPORTED: return "not supported";
    case PIERCE_ERR_PLATFORM: return "platform error";
    case PIERCE_ERR_CRYPTO: return "cryptographic failure";
    case PIERCE_ERR_TIMEOUT: return "timed out";
    case PIERCE_ERR_VERSION: return "version mismatch";
    case PIERCE_ERR_CLOSED: return "connection closed";
    case PIERCE_ERR_REJECTED: return "rejected by peer";
    case PIERCE_ERR_UNREACHABLE: return "peer unreachable";
    case PIERCE_ERR_BUFFER_TOO_SMALL: return "buffer too small";
    case PIERCE_ERR_STATE: return "invalid state for this call";
    default: return "unknown error";
    }
}
