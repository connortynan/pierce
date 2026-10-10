#include "wire.h"

#include "crypto.h"

static const uint8_t invite_magic[2] = {'P', 'I'};
static const uint8_t signal_magic[2] = {'P', 'S'};

int pc_cand_eq(const pc_cand *a, const pc_cand *b)
{
    if (a->type == PC_CAND_RELAY || b->type == PC_CAND_RELAY)
        return a->type == b->type && memcmp(a->relay_server, b->relay_server, 8) == 0 &&
               memcmp(a->relay_id, b->relay_id, PC_RELAY_ID_LEN) == 0;
    return pc_addr_eq(&a->addr, &b->addr);
}

/* ---- invite ---- */

int pc_blob_is_invite(const uint8_t *p, size_t len)
{
    return len >= 2 && p[0] == invite_magic[0] && p[1] == invite_magic[1];
}

int pc_invite_encode(const pc_invite *in, uint8_t *out, size_t cap)
{
    pc_wbuf w;
    pc_wbuf_init(&w, out, cap);
    pc_w_bytes(&w, invite_magic, 2);
    pc_w_u8(&w, PC_PROTOCOL_VERSION);
    pc_w_u8(&w, 0);                      /* flags */
    pc_w_bytes(&w, in->key, 32);
    pc_w_u8(&w, (uint8_t)in->naddr);
    for (uint32_t i = 0; i < in->naddr; i++) pc_w_addr(&w, &in->addrs[i]);
    return w.err ? PIERCE_ERR_BUFFER_TOO_SMALL : (int)w.len;
}

int pc_invite_decode(const uint8_t *p, size_t len, pc_invite *out)
{
    pc_rbuf r;
    uint8_t magic[2];
    memset(out, 0, sizeof(*out));
    pc_rbuf_init(&r, p, len);
    pc_r_bytes(&r, magic, 2);
    if (r.err || memcmp(magic, invite_magic, 2) != 0) return PIERCE_ERR_INVALID_ARG;
    if (pc_r_u8(&r) != PC_PROTOCOL_VERSION) return PIERCE_ERR_VERSION;
    pc_r_u8(&r);                         /* flags: none defined */
    pc_r_bytes(&r, out->key, 32);
    out->naddr = pc_r_u8(&r);
    if (out->naddr > PC_MAX_INVITE_ADDRS) return PIERCE_ERR_INVALID_ARG;
    for (uint32_t i = 0; i < out->naddr; i++) pc_r_addr(&r, &out->addrs[i]);
    return r.err ? PIERCE_ERR_INVALID_ARG : PIERCE_OK;
}

/* ---- offer / answer / candidates ---- */

static void w_cand(pc_wbuf *w, const pc_cand *c)
{
    pc_w_u8(w, c->type);
    if (c->type == PC_CAND_RELAY) {
        pc_w_bytes(w, c->relay_server, 8);
        pc_w_bytes(w, c->relay_id, PC_RELAY_ID_LEN);
    } else {
        pc_w_addr(w, &c->addr);
    }
}

static void r_cand(pc_rbuf *r, pc_cand *c)
{
    memset(c, 0, sizeof(*c));
    c->type = pc_r_u8(r);
    if (c->type == PC_CAND_RELAY) {
        pc_r_bytes(r, c->relay_server, 8);
        pc_r_bytes(r, c->relay_id, PC_RELAY_ID_LEN);
    } else if (c->type >= PC_CAND_HOST && c->type <= PC_CAND_PRFLX) {
        pc_r_addr(r, &c->addr);
        if (c->addr.family != PIERCE_AF_INET && c->addr.family != PIERCE_AF_INET6) r->err = 1;
    } else {
        r->err = 1;
    }
}

int pc_signal_encode(const pc_signal *s, uint8_t *out, size_t cap)
{
    pc_wbuf w;
    pc_wbuf_init(&w, out, cap);
    pc_w_bytes(&w, signal_magic, 2);
    pc_w_u8(&w, PC_PROTOCOL_VERSION);
    pc_w_u8(&w, s->kind);
    pc_w_bytes(&w, s->session, PC_SESSION_LEN);
    if (s->kind == PC_SIG_OFFER || s->kind == PC_SIG_ANSWER) pc_w_bytes(&w, s->secret, 32);
    if (s->kind == PC_SIG_OFFER) pc_w_bytes(&w, s->host_hint, 8);
    pc_w_u8(&w, s->flags);
    pc_w_u8(&w, (uint8_t)s->ncand);
    for (uint32_t i = 0; i < s->ncand; i++) w_cand(&w, &s->cands[i]);
    return w.err ? PIERCE_ERR_BUFFER_TOO_SMALL : (int)w.len;
}

int pc_signal_decode(const uint8_t *p, size_t len, pc_signal *s)
{
    pc_rbuf r;
    uint8_t magic[2];
    memset(s, 0, sizeof(*s));
    pc_rbuf_init(&r, p, len);
    pc_r_bytes(&r, magic, 2);
    if (r.err || memcmp(magic, signal_magic, 2) != 0) return PIERCE_ERR_INVALID_ARG;
    if (pc_r_u8(&r) != PC_PROTOCOL_VERSION) return PIERCE_ERR_VERSION;
    s->kind = pc_r_u8(&r);
    if (s->kind < PC_SIG_OFFER || s->kind > PC_SIG_CANDIDATES) return PIERCE_ERR_INVALID_ARG;
    pc_r_bytes(&r, s->session, PC_SESSION_LEN);
    if (s->kind == PC_SIG_OFFER || s->kind == PC_SIG_ANSWER) pc_r_bytes(&r, s->secret, 32);
    if (s->kind == PC_SIG_OFFER) pc_r_bytes(&r, s->host_hint, 8);
    s->flags = pc_r_u8(&r);
    s->ncand = pc_r_u8(&r);
    if (s->ncand > PC_MAX_BLOB_CANDS) return PIERCE_ERR_INVALID_ARG;
    for (uint32_t i = 0; i < s->ncand; i++) r_cand(&r, &s->cands[i]);
    return r.err || pc_rbuf_left(&r) ? PIERCE_ERR_INVALID_ARG : PIERCE_OK;
}

/* ---- STUN ---- */

#define STUN_MAGIC 0x2112A442u
#define STUN_BINDING_REQUEST 0x0001
#define STUN_BINDING_SUCCESS 0x0101
#define STUN_ATTR_MAPPED 0x0001
#define STUN_ATTR_XOR_MAPPED 0x0020

int pc_stun_is_stun(const uint8_t *p, size_t len)
{
    return len >= 20 && (p[0] & 0xc0) == 0 && pc_get32(p + 4) == STUN_MAGIC &&
           (size_t)pc_get16(p + 2) + 20 == len;
}

size_t pc_stun_binding_request(uint8_t out[20], const uint8_t txid[PC_STUN_TXID_LEN])
{
    pc_put16(out, STUN_BINDING_REQUEST);
    pc_put16(out + 2, 0);
    pc_put32(out + 4, STUN_MAGIC);
    memcpy(out + 8, txid, PC_STUN_TXID_LEN);
    return 20;
}

int pc_stun_parse_response(const uint8_t *p, size_t len, uint8_t txid_out[PC_STUN_TXID_LEN],
                           pierce_addr *mapped)
{
    if (!pc_stun_is_stun(p, len) || pc_get16(p) != STUN_BINDING_SUCCESS) return -1;
    memcpy(txid_out, p + 8, PC_STUN_TXID_LEN);
    int found = 0;
    size_t pos = 20;
    while (pos + 4 <= len) {
        uint16_t type = pc_get16(p + pos), alen = pc_get16(p + pos + 2);
        const uint8_t *v = p + pos + 4;
        if (pos + 4 + alen > len) return -1;
        if ((type == STUN_ATTR_XOR_MAPPED || (type == STUN_ATTR_MAPPED && !found)) && alen >= 8) {
            int x = type == STUN_ATTR_XOR_MAPPED;
            pierce_addr a;
            memset(&a, 0, sizeof(a));
            a.port = (uint16_t)(pc_get16(v + 2) ^ (x ? (STUN_MAGIC >> 16) : 0));
            if (v[1] == 0x01) {
                a.family = PIERCE_AF_INET;
                uint32_t ip = pc_get32(v + 4) ^ (x ? STUN_MAGIC : 0);
                pc_put32(a.addr, ip);
            } else if (v[1] == 0x02 && alen >= 20) {
                a.family = PIERCE_AF_INET6;
                memcpy(a.addr, v + 4, 16);
                if (x) {
                    uint8_t mask[16];
                    pc_put32(mask, STUN_MAGIC);
                    memcpy(mask + 4, p + 8, 12);
                    for (int i = 0; i < 16; i++) a.addr[i] ^= mask[i];
                }
            } else {
                goto next;
            }
            *mapped = a;
            found = x ? 2 : 1;
        }
    next:
        pos += 4 + (size_t)((alen + 3) & ~3);
    }
    return found ? 0 : -1;
}

size_t pc_stun_binding_response(uint8_t *out, size_t cap, const uint8_t *req, size_t req_len,
                                const pierce_addr *mapped)
{
    size_t alen = mapped->family == PIERCE_AF_INET6 ? 20 : 8;
    if (req_len < 20 || cap < 20 + 4 + alen) return 0;
    pc_put16(out, STUN_BINDING_SUCCESS);
    pc_put16(out + 2, (uint16_t)(4 + alen));
    pc_put32(out + 4, STUN_MAGIC);
    memcpy(out + 8, req + 8, PC_STUN_TXID_LEN);
    uint8_t *a = out + 20;
    pc_put16(a, STUN_ATTR_XOR_MAPPED);
    pc_put16(a + 2, (uint16_t)alen);
    a[4] = 0;
    a[5] = mapped->family == PIERCE_AF_INET6 ? 0x02 : 0x01;
    pc_put16(a + 6, (uint16_t)(mapped->port ^ (STUN_MAGIC >> 16)));
    if (mapped->family == PIERCE_AF_INET6) {
        uint8_t mask[16];
        pc_put32(mask, STUN_MAGIC);
        memcpy(mask + 4, req + 8, 12);
        for (int i = 0; i < 16; i++) a[8 + i] = mapped->addr[i] ^ mask[i];
    } else {
        pc_put32(a + 8, pc_get32(mapped->addr) ^ STUN_MAGIC);
    }
    return 20 + 4 + alen;
}

/* ---- relay tokens ---- */

int pierce_relay_token_create(const uint8_t *secret, uint32_t secret_len,
                              uint64_t expiry_unix_s, uint32_t max_kbps,
                              uint8_t *out, uint32_t cap)
{
    if (!secret || !secret_len || !out) return PIERCE_ERR_INVALID_ARG;
    if (cap < PIERCE_RELAY_TOKEN_SIZE) return PIERCE_ERR_BUFFER_TOO_SMALL;
    out[0] = PC_TOKEN_TYPE_SHARED;
    pc_put64(out + 1, expiry_unix_s);
    pc_put32(out + 9, max_kbps);
    pc_mac16(out + 13, secret, secret_len, out, 13);
    return PIERCE_RELAY_TOKEN_SIZE;
}

int pc_token_verify(const uint8_t *secret, size_t secret_len, const uint8_t *tok, size_t len,
                    uint64_t now_unix, uint32_t *max_kbps)
{
    uint8_t mac[16];
    if (len != PIERCE_RELAY_TOKEN_SIZE || tok[0] != PC_TOKEN_TYPE_SHARED) return PC_RLY_ERR_BAD_TOKEN;
    pc_mac16(mac, secret, secret_len, tok, 13);
    if (!pc_ct_eq16(mac, tok + 13)) return PC_RLY_ERR_BAD_TOKEN;
    if (pc_get64(tok + 1) < now_unix) return PC_RLY_ERR_EXPIRED;
    if (max_kbps) *max_kbps = pc_get32(tok + 9);
    return 0;
}
