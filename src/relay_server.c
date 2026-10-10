#include "relay_server.h"

#include <stdlib.h>

#include "wire.h"

#define NBUCKETS 4096

typedef struct pc_rs_alloc {
    struct pc_rs_alloc *next_id, *next_ep;
    uint8_t id[PC_RELAY_ID_LEN];
    pc_rs_ep ep;
    uint64_t expires_us;
    uint32_t max_kbps;
    uint64_t budget;           /* bytes, token bucket */
    uint64_t last_us;
} pc_rs_alloc;

struct pc_relay_server {
    pc_allocator a;
    uint8_t secret[64];
    uint32_t secret_len;
    int open;
    uint32_t max_allocs, lifetime_s, default_kbps;
    uint8_t server_id[8];
    uint32_t count;
    pc_rs_alloc *by_id[NBUCKETS];
    pc_rs_alloc *by_ep[NBUCKETS];
};

static uint32_t hash_bytes(const uint8_t *p, size_t n, uint32_t h)
{
    for (size_t i = 0; i < n; i++) h = (h ^ p[i]) * 16777619u;
    return h;
}

static uint32_t hash_id(const uint8_t id[PC_RELAY_ID_LEN]) { return hash_bytes(id, PC_RELAY_ID_LEN, 2166136261u) % NBUCKETS; }

static uint32_t hash_ep(const pc_rs_ep *e)
{
    uint8_t b[8];
    uint32_t h = hash_bytes(e->addr.addr, 16, 2166136261u);
    pc_put16(b, e->addr.port);
    h = hash_bytes(b, 2, h);
    pc_put64(b, e->tcp_id);
    return hash_bytes(b, 8, h) % NBUCKETS;
}

static int ep_eq(const pc_rs_ep *a, const pc_rs_ep *b)
{
    if (a->tcp_id || b->tcp_id) return a->tcp_id == b->tcp_id;
    return pc_addr_eq(&a->addr, &b->addr);
}

pc_relay_server *pc_rs_create(const pc_rs_config *cfg)
{
    pc_allocator a;
    pc_allocator_init(&a, NULL);
    pc_relay_server *rs = (pc_relay_server *)pc_alloc(&a, sizeof(*rs));
    if (!rs) return NULL;
    rs->a = a;
    if (cfg->secret && cfg->secret_len) {
        rs->secret_len = PC_MIN(cfg->secret_len, 64u);
        memcpy(rs->secret, cfg->secret, rs->secret_len);
    }
    rs->open = cfg->open;
    rs->max_allocs = cfg->max_allocs ? cfg->max_allocs : 10000;
    rs->lifetime_s = cfg->lifetime_s ? cfg->lifetime_s : 600;
    rs->default_kbps = cfg->default_kbps;
    pc_random(rs->server_id, 8);
    return rs;
}

static void unlink_alloc(pc_relay_server *rs, pc_rs_alloc *al)
{
    pc_rs_alloc **l = &rs->by_id[hash_id(al->id)];
    while (*l && *l != al) l = &(*l)->next_id;
    if (*l) *l = al->next_id;
    l = &rs->by_ep[hash_ep(&al->ep)];
    while (*l && *l != al) l = &(*l)->next_ep;
    if (*l) *l = al->next_ep;
    rs->count--;
}

void pc_rs_destroy(pc_relay_server *rs)
{
    if (!rs) return;
    for (uint32_t b = 0; b < NBUCKETS; b++) {
        pc_rs_alloc *al = rs->by_id[b];
        while (al) {
            pc_rs_alloc *n = al->next_id;
            pc_free(&rs->a, al);
            al = n;
        }
    }
    pc_allocator a = rs->a;
    pc_free(&a, rs);
}

static pc_rs_alloc *find_id(pc_relay_server *rs, const uint8_t id[PC_RELAY_ID_LEN])
{
    for (pc_rs_alloc *al = rs->by_id[hash_id(id)]; al; al = al->next_id)
        if (memcmp(al->id, id, PC_RELAY_ID_LEN) == 0) return al;
    return NULL;
}

static pc_rs_alloc *find_ep(pc_relay_server *rs, const pc_rs_ep *ep)
{
    for (pc_rs_alloc *al = rs->by_ep[hash_ep(ep)]; al; al = al->next_ep)
        if (ep_eq(&al->ep, ep)) return al;
    return NULL;
}

static void reply_err(const pc_rs_ep *to, const uint8_t txid[PC_TXID_LEN], uint8_t code,
                      pc_rs_send_fn send, void *user)
{
    uint8_t b[1 + PC_TXID_LEN + 1];
    b[0] = PC_RLY_ALLOC_ERR;
    memcpy(b + 1, txid, PC_TXID_LEN);
    b[1 + PC_TXID_LEN] = code;
    send(user, to, b, sizeof(b));
}

static void reply_ok(pc_relay_server *rs, const pc_rs_alloc *al, const uint8_t txid[PC_TXID_LEN],
                     pc_rs_send_fn send, void *user)
{
    uint8_t b[1 + PC_TXID_LEN + 8 + PC_RELAY_ID_LEN + 2 + PC_ADDR_WIRE_SIZE];
    pc_wbuf w;
    pc_wbuf_init(&w, b, sizeof(b));
    pc_w_u8(&w, PC_RLY_ALLOC_OK);
    pc_w_bytes(&w, txid, PC_TXID_LEN);
    pc_w_bytes(&w, rs->server_id, 8);
    pc_w_bytes(&w, al->id, PC_RELAY_ID_LEN);
    pc_w_u16(&w, (uint16_t)PC_MIN(rs->lifetime_s, 65535u));
    pc_w_addr(&w, &al->ep.addr);
    send(user, &al->ep, b, w.len);
}

static void handle_alloc(pc_relay_server *rs, uint64_t now_us, uint64_t now_unix, const pc_rs_ep *from,
                         const uint8_t *p, size_t len, pc_rs_send_fn send, void *user)
{
    pc_rbuf r;
    uint8_t txid[PC_TXID_LEN], id[PC_RELAY_ID_LEN];
    if (len < PC_RLY_ALLOC_REQ_MIN) return;    /* unpadded: amplification guard */
    pc_rbuf_init(&r, p, len);
    pc_r_u8(&r);
    pc_r_bytes(&r, txid, PC_TXID_LEN);
    uint8_t flags = pc_r_u8(&r);
    pc_r_bytes(&r, id, PC_RELAY_ID_LEN);
    uint16_t tlen = pc_r_u16(&r);
    const uint8_t *tok = pc_r_ptr(&r, tlen);
    if (r.err) return;

    if (flags & 1) {   /* refresh */
        pc_rs_alloc *al = find_id(rs, id);
        if (!al || !ep_eq(&al->ep, from)) {
            reply_err(from, txid, PC_RLY_ERR_UNKNOWN, send, user);
            return;
        }
        al->expires_us = now_us + (uint64_t)rs->lifetime_s * 1000000;
        reply_ok(rs, al, txid, send, user);
        return;
    }

    pc_rs_alloc *al = find_ep(rs, from);
    if (al) {          /* retransmitted request: same allocation */
        al->expires_us = now_us + (uint64_t)rs->lifetime_s * 1000000;
        reply_ok(rs, al, txid, send, user);
        return;
    }
    uint32_t kbps = rs->default_kbps;
    if (tlen || !rs->open) {
        if (!rs->secret_len) {
            reply_err(from, txid, PC_RLY_ERR_BAD_TOKEN, send, user);
            return;
        }
        int rc = pc_token_verify(rs->secret, rs->secret_len, tok, tlen, now_unix, &kbps);
        if (rc) {
            reply_err(from, txid, (uint8_t)rc, send, user);
            return;
        }
    }
    if (rs->count >= rs->max_allocs) {
        reply_err(from, txid, PC_RLY_ERR_FULL, send, user);
        return;
    }
    al = (pc_rs_alloc *)pc_alloc(&rs->a, sizeof(*al));
    if (!al) {
        reply_err(from, txid, PC_RLY_ERR_FULL, send, user);
        return;
    }
    do {
        pc_random(al->id, PC_RELAY_ID_LEN);
    } while (find_id(rs, al->id));
    al->ep = *from;
    al->expires_us = now_us + (uint64_t)rs->lifetime_s * 1000000;
    al->max_kbps = kbps;
    al->last_us = now_us;
    al->budget = kbps ? (uint64_t)kbps * 125 : 0;   /* one second of burst */
    uint32_t hi = hash_id(al->id), he = hash_ep(&al->ep);
    al->next_id = rs->by_id[hi];
    rs->by_id[hi] = al;
    al->next_ep = rs->by_ep[he];
    rs->by_ep[he] = al;
    rs->count++;
    reply_ok(rs, al, txid, send, user);
}

static int rate_ok(pc_rs_alloc *al, uint64_t now_us, size_t len)
{
    if (!al->max_kbps) return 1;
    uint64_t cap = (uint64_t)al->max_kbps * 125;    /* bytes per second */
    al->budget += (now_us - al->last_us) * cap / 1000000;
    if (al->budget > cap) al->budget = cap;
    al->last_us = now_us;
    if (al->budget < len) return 0;
    al->budget -= len;
    return 1;
}

void pc_rs_input(pc_relay_server *rs, uint64_t now_us, uint64_t now_unix, const pc_rs_ep *from,
                 const uint8_t *data, size_t len, pc_rs_send_fn send, void *user)
{
    if (len == 0) return;
    /* The relay doubles as a STUN server. */
    if (pc_stun_is_stun(data, len)) {
        if (pc_get16(data) == 0x0001 && !from->tcp_id) {
            uint8_t resp[64];
            size_t n = pc_stun_binding_response(resp, sizeof(resp), data, len, &from->addr);
            if (n) send(user, from, resp, n);
        }
        return;
    }
    switch (data[0]) {
    case PC_RLY_ALLOC_REQ:
        handle_alloc(rs, now_us, now_unix, from, data, len, send, user);
        break;
    case PC_RLY_SEND: {
        if (len < 1 + PC_RELAY_ID_LEN + 1 || len > PC_MTU + 1 + PC_RELAY_ID_LEN) return;
        pc_rs_alloc *src = find_ep(rs, from);
        if (!src || src->expires_us < now_us) return;
        pc_rs_alloc *dst = find_id(rs, data + 1);
        if (!dst || dst->expires_us < now_us) return;
        if (!rate_ok(src, now_us, len)) return;
        uint8_t buf[PC_MTU + 1 + PC_RELAY_ID_LEN];
        buf[0] = PC_RLY_DATA;
        memcpy(buf + 1, src->id, PC_RELAY_ID_LEN);
        memcpy(buf + 1 + PC_RELAY_ID_LEN, data + 1 + PC_RELAY_ID_LEN, len - 1 - PC_RELAY_ID_LEN);
        send(user, &dst->ep, buf, len);
        break;
    }
    case PC_RLY_FREE: {
        if (len < 1 + PC_RELAY_ID_LEN) return;
        pc_rs_alloc *al = find_id(rs, data + 1);
        if (!al || !ep_eq(&al->ep, from)) return;
        unlink_alloc(rs, al);
        pc_free(&rs->a, al);
        break;
    }
    default:
        break;
    }
}

void pc_rs_tick(pc_relay_server *rs, uint64_t now_us)
{
    for (uint32_t b = 0; b < NBUCKETS; b++) {
        pc_rs_alloc *al = rs->by_id[b];
        while (al) {
            pc_rs_alloc *n = al->next_id;
            if (al->expires_us < now_us) {
                unlink_alloc(rs, al);
                pc_free(&rs->a, al);
            }
            al = n;
        }
    }
}

void pc_rs_tcp_closed(pc_relay_server *rs, uint64_t tcp_id)
{
    for (uint32_t b = 0; b < NBUCKETS; b++) {
        pc_rs_alloc *al = rs->by_id[b];
        while (al) {
            pc_rs_alloc *n = al->next_id;
            if (al->ep.tcp_id == tcp_id) {
                unlink_alloc(rs, al);
                pc_free(&rs->a, al);
            }
            al = n;
        }
    }
}

uint32_t pc_rs_alloc_count(const pc_relay_server *rs) { return rs->count; }
void pc_rs_server_id(const pc_relay_server *rs, uint8_t out[8]) { memcpy(out, rs->server_id, 8); }
