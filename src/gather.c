/* Candidate gathering: host interfaces, STUN, relay allocations (spec 5). */
#include <stdio.h>
#include <stdlib.h>

#include "core.h"

#define STUN_REFRESH_US (60ull * 1000000)
#define STUN_RETRY_US (30ull * 1000000)
#define STUN_TRIES 5
#define RELAY_TRIES 6
#define RELAY_RETRY_US (30ull * 1000000)

/* ---- "host:port" / "[v6]:port" / "tcp://host:port" ---- */
static int split_hostport(const char *s, char *host, size_t hostcap, uint16_t *port, int *tcp)
{
    *tcp = 0;
    if (strncmp(s, "tcp://", 6) == 0) {
        *tcp = 1;
        s += 6;
    } else if (strncmp(s, "udp://", 6) == 0) {
        s += 6;
    }
    const char *colon;
    size_t hl;
    if (s[0] == '[') {
        const char *end = strchr(s, ']');
        if (!end || end[1] != ':') return -1;
        hl = (size_t)(end - s - 1);
        if (hl >= hostcap) return -1;
        memcpy(host, s + 1, hl);
        colon = end + 1;
    } else {
        colon = strrchr(s, ':');
        if (!colon) return -1;
        hl = (size_t)(colon - s);
        if (hl == 0 || hl >= hostcap) return -1;
        memcpy(host, s, hl);
    }
    host[hl] = 0;
    char *endp;
    long p = strtol(colon + 1, &endp, 10);
    if (*endp || p <= 0 || p > 65535) return -1;
    *port = (uint16_t)p;
    return 0;
}

static int family_enabled(pierce_ctx *ctx, uint32_t fam)
{
    if (fam == PIERCE_AF_INET) {
        if (ctx->flags & PIERCE_CFG_NO_IPV4) return 0;
        return (ctx->flags & PIERCE_CFG_NO_BUILTIN_UDP) || ctx->sock4 != PAL_INVALID_SOCK;
    }
    if (fam == PIERCE_AF_INET6) {
        if (ctx->flags & PIERCE_CFG_NO_IPV6) return 0;
        return (ctx->flags & PIERCE_CFG_NO_BUILTIN_UDP) || ctx->sock6 != PAL_INVALID_SOCK;
    }
    return 0;
}

/* Numeric addresses resolve without DNS, so custom-transport and test
   setups never touch the resolver. */
static int resolve(const char *host, uint16_t port, pierce_addr *out, uint32_t cap)
{
    char buf[300];
    pierce_addr a;
    if (strchr(host, ':')) snprintf(buf, sizeof(buf), "[%s]:%u", host, (unsigned)port);
    else snprintf(buf, sizeof(buf), "%s:%u", host, (unsigned)port);
    if (pierce_addr_parse(buf, &a) == PIERCE_OK) {
        out[0] = a;
        return 1;
    }
    return pal_resolve(host, port, out, cap);
}

/* ===================================================================== */
/* Candidate list                                                        */
/* ===================================================================== */

static int cand_list_add(pc_cand *list, uint32_t *n, const pc_cand *c)
{
    for (uint32_t i = 0; i < *n; i++)
        if (list[i].type == c->type && pc_cand_eq(&list[i], c)) return 0;
    if (c->type != PC_CAND_RELAY)
        for (uint32_t i = 0; i < *n; i++)
            if (list[i].type != PC_CAND_RELAY && pc_addr_eq(&list[i].addr, &c->addr)) return 0;
    if (*n >= PC_MAX_LOCAL_CANDS) return 0;
    list[(*n)++] = *c;
    return 1;
}

static void rebuild_cands(pierce_ctx *ctx, int rescan)
{
    pc_cand nl[PC_MAX_LOCAL_CANDS];
    uint32_t n = 0;
    pc_cand c;
    int hide = (ctx->flags & PIERCE_CFG_RELAY_ONLY) != 0;
    (void)rescan;

    if (!hide) {
        /* Host: interfaces (builtin UDP only), then explicit addresses. */
        if (!(ctx->flags & PIERCE_CFG_NO_BUILTIN_UDP)) {
            pierce_addr ifs[PC_MAX_LOCAL_CANDS];
            int k = pal_interfaces(ifs, PC_MAX_LOCAL_CANDS,
                                   (ctx->flags & PIERCE_CFG_INCLUDE_LOOPBACK) != 0);
            for (int i = 0; i < k; i++) {
                if (!family_enabled(ctx, ifs[i].family)) continue;
                memset(&c, 0, sizeof(c));
                c.type = PC_CAND_HOST;
                c.addr = ifs[i];
                c.addr.port = ifs[i].family == PIERCE_AF_INET ? ctx->port4 : ctx->port6;
                cand_list_add(nl, &n, &c);
            }
        }
        for (uint32_t i = 0; i < ctx->nlocal_addrs; i++) {
            memset(&c, 0, sizeof(c));
            c.type = PC_CAND_HOST;
            c.addr = ctx->local_addrs[i];
            cand_list_add(nl, &n, &c);
        }
        /* Server-reflexive: STUN results and relay-observed addresses. */
        for (uint32_t i = 0; i < ctx->nstun; i++) {
            if (!ctx->stun[i].has_mapped) continue;
            memset(&c, 0, sizeof(c));
            c.type = PC_CAND_SRFLX;
            c.addr = ctx->stun[i].mapped;
            cand_list_add(nl, &n, &c);
        }
        for (uint32_t i = 0; i < ctx->nrelays; i++) {
            pc_relay *r = ctx->relays[i];
            if (r->state != PC_RELAY_ALLOCATED || r->tcp || r->reflexive.family == PIERCE_AF_NONE) continue;
            memset(&c, 0, sizeof(c));
            c.type = PC_CAND_SRFLX;
            c.addr = r->reflexive;
            cand_list_add(nl, &n, &c);
        }
    }
    for (uint32_t i = 0; i < ctx->nrelays; i++) {
        pc_relay *r = ctx->relays[i];
        if (r->state != PC_RELAY_ALLOCATED) continue;
        memset(&c, 0, sizeof(c));
        c.type = PC_CAND_RELAY;
        c.addr = r->addr;
        memcpy(c.relay_server, r->server_id, 8);
        memcpy(c.relay_id, r->relay_id, PC_RELAY_ID_LEN);
        cand_list_add(nl, &n, &c);
    }

    /* Trickle-friendly: if the old list is a prefix, only new entries are
       signaled; otherwise start a new epoch and resend everything. */
    int prefix = n >= ctx->ncands;
    for (uint32_t i = 0; prefix && i < ctx->ncands; i++)
        if (nl[i].type != ctx->cands[i].type || !pc_cand_eq(&nl[i], &ctx->cands[i])) prefix = 0;
    int changed = !prefix || n != ctx->ncands;
    memcpy(ctx->cands, nl, n * sizeof(pc_cand));
    ctx->ncands = n;
    if (!prefix) ctx->cands_epoch++;
    if (changed) pc_conn_cands_changed(ctx);
}

/* ===================================================================== */
/* STUN client                                                           */
/* ===================================================================== */

static void stun_send(pierce_ctx *ctx, pc_stun *s, uint64_t now)
{
    uint8_t req[20];
    if (s->tries == 0) pc_random(s->txid, PC_STUN_TXID_LEN);
    pc_stun_binding_request(req, s->txid);
    pc_send_direct(ctx, &s->addr, req, sizeof(req));
    s->tries++;
    s->next_tx_us = now + (500000ull << PC_MIN(s->tries - 1, 4u));
}

static void stun_timers(pierce_ctx *ctx, uint64_t now, uint64_t *next)
{
    for (uint32_t i = 0; i < ctx->nstun; i++) {
        pc_stun *s = &ctx->stun[i];
        if (now >= s->next_tx_us) {
            if (s->tries >= STUN_TRIES) {
                s->tries = 0;
                s->next_tx_us = now + STUN_RETRY_US;
                if (s->has_mapped) {
                    s->has_mapped = 0;
                    rebuild_cands(ctx, 0);
                }
            } else {
                stun_send(ctx, s, now);
            }
        }
        if (!*next || s->next_tx_us < *next) *next = s->next_tx_us;
    }
}

static int stun_input(pierce_ctx *ctx, const uint8_t *p, size_t len)
{
    uint8_t txid[PC_STUN_TXID_LEN];
    pierce_addr mapped;
    if (pc_stun_parse_response(p, len, txid, &mapped) < 0) return 1;
    for (uint32_t i = 0; i < ctx->nstun; i++) {
        pc_stun *s = &ctx->stun[i];
        if (s->tries == 0 || memcmp(s->txid, txid, PC_STUN_TXID_LEN) != 0) continue;
        int changed = !s->has_mapped || !pc_addr_eq(&s->mapped, &mapped);
        s->mapped = mapped;
        s->has_mapped = 1;
        s->tries = 0;
        s->next_tx_us = pc_now(ctx) + STUN_REFRESH_US;
        if (changed) {
            char a[64];
            pierce_addr_format(&mapped, a, sizeof(a));
            pc_log(ctx, PIERCE_LOG_DEBUG, "STUN mapped address %s", a);
            rebuild_cands(ctx, 0);
        }
        break;
    }
    return 1;
}

/* ===================================================================== */
/* Relay client                                                          */
/* ===================================================================== */

static void relay_transmit(pierce_ctx *ctx, pc_relay *r, const uint8_t *data, size_t len)
{
    if (!r->tcp) {
        pc_send_direct(ctx, &r->addr, data, len);
        return;
    }
    if (r->sock == PAL_INVALID_SOCK || r->state == PC_RELAY_CONNECTING) return;
    if (r->txlen + 2 + len > r->txcap) {
        uint32_t nc = PC_MAX(r->txcap * 2, r->txlen + 2 + (uint32_t)len + 4096);
        if (nc > (1u << 22)) return;   /* peer is not draining: drop rather than grow */
        uint8_t *n = (uint8_t *)pc_realloc(&ctx->alloc, r->tx, r->txcap, nc);
        if (!n) return;
        r->tx = n;
        r->txcap = nc;
    }
    pc_put16(r->tx + r->txlen, (uint16_t)len);
    memcpy(r->tx + r->txlen + 2, data, len);
    r->txlen += 2 + (uint32_t)len;
    /* Opportunistic write; the rest goes out when the socket is writable. */
    int n = pal_tcp_send(r->sock, r->tx, r->txlen);
    if (n > 0) {
        memmove(r->tx, r->tx + n, r->txlen - (uint32_t)n);
        r->txlen -= (uint32_t)n;
    }
}

static void relay_send_alloc(pierce_ctx *ctx, pc_relay *r, uint64_t now)
{
    uint8_t buf[PC_RLY_ALLOC_REQ_MIN + 300];
    pc_wbuf w;
    int refresh = r->state == PC_RELAY_ALLOCATED;
    if (r->tries == 0) pc_random(r->txid, PC_TXID_LEN);
    pc_wbuf_init(&w, buf, sizeof(buf));
    pc_w_u8(&w, PC_RLY_ALLOC_REQ);
    pc_w_bytes(&w, r->txid, PC_TXID_LEN);
    pc_w_u8(&w, refresh ? 1 : 0);
    if (refresh) pc_w_bytes(&w, r->relay_id, PC_RELAY_ID_LEN);
    else pc_w_zeros(&w, PC_RELAY_ID_LEN);
    pc_w_u16(&w, (uint16_t)r->token_len);
    pc_w_bytes(&w, r->token, r->token_len);
    if (w.len < PC_RLY_ALLOC_REQ_MIN) pc_w_zeros(&w, PC_RLY_ALLOC_REQ_MIN - w.len);
    relay_transmit(ctx, r, buf, w.len);
    r->tries++;
    r->next_tx_us = now + (250000ull << PC_MIN(r->tries - 1, 4u));
}

static void relay_reset(pierce_ctx *ctx, pc_relay *r, uint64_t retry_at)
{
    int was = r->state == PC_RELAY_ALLOCATED;
    if (r->tcp && r->sock != PAL_INVALID_SOCK) {
        pal_sock_close(r->sock);
        r->sock = PAL_INVALID_SOCK;
    }
    r->rxlen = r->txlen = 0;
    r->state = PC_RELAY_FAILED;
    r->tries = 0;
    r->next_tx_us = retry_at;
    if (was) rebuild_cands(ctx, 0);
}

static void relay_start(pierce_ctx *ctx, pc_relay *r, uint64_t now)
{
    r->tries = 0;
    if (!r->resolved) {
        pierce_addr a[4];
        int n = resolve(r->host, r->port, a, 4);
        for (int i = 0; i < n; i++) {
            if (family_enabled(ctx, a[i].family) || r->tcp) {
                r->addr = a[i];
                r->resolved = 1;
                break;
            }
        }
        if (!r->resolved) {
            pc_log(ctx, PIERCE_LOG_WARN, "relay %s: cannot resolve", r->host);
            r->state = PC_RELAY_FAILED;
            r->next_tx_us = now + RELAY_RETRY_US;
            return;
        }
    }
    if (r->tcp) {
        if (ctx->flags & PIERCE_CFG_NO_BUILTIN_UDP) {
            r->state = PC_RELAY_FAILED;
            r->next_tx_us = UINT64_MAX;    /* TCP needs builtin sockets */
            return;
        }
        if (pal_tcp_connect(&r->addr, &r->sock) != PIERCE_OK) {
            relay_reset(ctx, r, now + RELAY_RETRY_US);
            return;
        }
        r->state = PC_RELAY_CONNECTING;
        r->next_tx_us = now + 10000000ull;   /* connect timeout */
        return;
    }
    r->state = PC_RELAY_ALLOCATING;
    relay_send_alloc(ctx, r, now);
}

static uint64_t relay_refresh_interval(pierce_ctx *ctx, const pc_relay *r)
{
    uint64_t life = (uint64_t)(r->lifetime_s ? r->lifetime_s : 600) * 1000000 / 3;
    /* Refreshes double as NAT keepalives for the relay mapping. */
    return PC_MIN(life, ctx->keepalive_us);
}

static void relay_timers(pierce_ctx *ctx, uint64_t now, uint64_t *next)
{
    for (uint32_t i = 0; i < ctx->nrelays; i++) {
        pc_relay *r = ctx->relays[i];
        if (now >= r->next_tx_us) {
            switch (r->state) {
            case PC_RELAY_IDLE:
            case PC_RELAY_FAILED:
                relay_start(ctx, r, now);
                break;
            case PC_RELAY_CONNECTING:
                relay_reset(ctx, r, now + RELAY_RETRY_US);
                break;
            case PC_RELAY_ALLOCATING:
            case PC_RELAY_ALLOCATED:
                if (r->tries >= RELAY_TRIES) {
                    pc_log(ctx, PIERCE_LOG_WARN, "relay %s: no response", r->host);
                    relay_reset(ctx, r, now + RELAY_RETRY_US);
                } else {
                    relay_send_alloc(ctx, r, now);
                }
                break;
            }
        }
        if (!*next || r->next_tx_us < *next) *next = r->next_tx_us;
    }
}

static void relay_control(pierce_ctx *ctx, pc_relay *r, const uint8_t *p, size_t len)
{
    pc_rbuf rb;
    uint8_t txid[PC_TXID_LEN];
    pc_rbuf_init(&rb, p, len);
    uint8_t type = pc_r_u8(&rb);
    pc_r_bytes(&rb, txid, PC_TXID_LEN);
    if (rb.err || r->tries == 0 || memcmp(txid, r->txid, PC_TXID_LEN) != 0) return;
    uint64_t now = pc_now(ctx);
    if (type == PC_RLY_ALLOC_OK) {
        uint8_t server[8], id[PC_RELAY_ID_LEN];
        pierce_addr refl;
        pc_r_bytes(&rb, server, 8);
        pc_r_bytes(&rb, id, PC_RELAY_ID_LEN);
        uint16_t life = pc_r_u16(&rb);
        pc_r_addr(&rb, &refl);
        if (rb.err) return;
        int changed = r->state != PC_RELAY_ALLOCATED || memcmp(r->server_id, server, 8) != 0 ||
                      memcmp(r->relay_id, id, PC_RELAY_ID_LEN) != 0 ||
                      !pc_addr_eq(&r->reflexive, &refl);
        memcpy(r->server_id, server, 8);
        memcpy(r->relay_id, id, PC_RELAY_ID_LEN);
        r->lifetime_s = life;
        r->reflexive = refl;
        r->state = PC_RELAY_ALLOCATED;
        r->tries = 0;
        r->next_tx_us = now + relay_refresh_interval(ctx, r);
        if (changed) {
            pc_log(ctx, PIERCE_LOG_DEBUG, "relay %s: allocated", r->host);
            rebuild_cands(ctx, 0);
        }
    } else if (type == PC_RLY_ALLOC_ERR) {
        uint8_t code = pc_r_u8(&rb);
        pc_log(ctx, PIERCE_LOG_WARN, "relay %s: allocation refused (code %u)", r->host, code);
        if (code == PC_RLY_ERR_UNKNOWN && r->state == PC_RELAY_ALLOCATED) {
            /* Server lost our allocation: start over. */
            r->state = PC_RELAY_ALLOCATING;
            r->tries = 0;
            relay_send_alloc(ctx, r, now);
            rebuild_cands(ctx, 0);
        } else {
            relay_reset(ctx, r, now + RELAY_RETRY_US);
        }
    }
}

/* Relay DATA unwrapped: deliver the inner Pierce packet with a relay path. */
static void relay_deliver(pierce_ctx *ctx, uint32_t idx, const uint8_t *p, size_t len)
{
    if (len < 1 + PC_RELAY_ID_LEN + 1) return;
    pc_path path;
    memset(&path, 0, sizeof(path));
    path.kind = PC_PATH_KIND_RELAY;
    path.relay = idx;
    memcpy(path.peer_relay_id, p + 1, PC_RELAY_ID_LEN);
    pc_input_packet(ctx, &path, (uint8_t *)p + 1 + PC_RELAY_ID_LEN, len - 1 - PC_RELAY_ID_LEN);
}

void pc_relay_send(pierce_ctx *ctx, uint32_t relay, const uint8_t peer_id[PC_RELAY_ID_LEN],
                   const uint8_t *data, size_t len)
{
    uint8_t buf[PC_MTU + 16];
    if (relay >= ctx->nrelays || len > PC_MTU) return;
    pc_relay *r = ctx->relays[relay];
    if (r->state != PC_RELAY_ALLOCATED) return;
    buf[0] = PC_RLY_SEND;
    memcpy(buf + 1, peer_id, PC_RELAY_ID_LEN);
    memcpy(buf + 1 + PC_RELAY_ID_LEN, data, len);
    relay_transmit(ctx, r, buf, 1 + PC_RELAY_ID_LEN + len);
}

int pc_relay_index_by_server(pierce_ctx *ctx, const uint8_t server_id[8])
{
    for (uint32_t i = 0; i < ctx->nrelays; i++)
        if (ctx->relays[i]->state == PC_RELAY_ALLOCATED && memcmp(ctx->relays[i]->server_id, server_id, 8) == 0)
            return (int)i;
    return -1;
}

void pc_relay_tcp_io(pierce_ctx *ctx, uint32_t idx, int readable, int writable, int failed)
{
    pc_relay *r = ctx->relays[idx];
    uint64_t now = pc_now(ctx);
    if (r->sock == PAL_INVALID_SOCK) return;
    if (r->state == PC_RELAY_CONNECTING) {
        int res = pal_tcp_connect_result(r->sock);
        if (res < 0 || (failed && res == 0)) {
            relay_reset(ctx, r, now + RELAY_RETRY_US);
            return;
        }
        if (res == 0) return;
        r->state = PC_RELAY_ALLOCATING;
        r->tries = 0;
        relay_send_alloc(ctx, r, now);
        return;
    }
    if (writable && r->txlen) {
        int n = pal_tcp_send(r->sock, r->tx, r->txlen);
        if (n > 0) {
            memmove(r->tx, r->tx + n, r->txlen - (uint32_t)n);
            r->txlen -= (uint32_t)n;
        } else if (n < 0 && n != PIERCE_ERR_WOULD_BLOCK) {
            relay_reset(ctx, r, now + RELAY_RETRY_US);
            return;
        }
    }
    if (!readable && !failed) return;
    for (;;) {
        int n = pal_tcp_recv(r->sock, r->rx + r->rxlen, sizeof(r->rx) - r->rxlen);
        if (n == PIERCE_ERR_WOULD_BLOCK) break;
        if (n <= 0) {
            pc_log(ctx, PIERCE_LOG_WARN, "relay %s: TCP connection lost", r->host);
            relay_reset(ctx, r, now + 1000000);
            return;
        }
        r->rxlen += (uint32_t)n;
        uint32_t off = 0;
        while (r->rxlen - off >= 2) {
            uint32_t flen = pc_get16(r->rx + off);
            if (r->rxlen - off < 2 + flen) break;
            const uint8_t *f = r->rx + off + 2;
            if (flen > 0) {
                if (f[0] == PC_RLY_DATA) relay_deliver(ctx, idx, f, flen);
                else if (f[0] == PC_RLY_ALLOC_OK || f[0] == PC_RLY_ALLOC_ERR) relay_control(ctx, r, f, flen);
            }
            off += 2 + flen;
            if (r->sock == PAL_INVALID_SOCK) return;   /* reset during dispatch */
        }
        memmove(r->rx, r->rx + off, r->rxlen - off);
        r->rxlen -= off;
    }
}

/* ===================================================================== */
/* Entry points                                                          */
/* ===================================================================== */

int pc_gather_input(pierce_ctx *ctx, const pierce_addr *src, const uint8_t *data, size_t len,
                    uint32_t *relay_out, const uint8_t **payload, size_t *plen,
                    uint8_t peer_relay_id[PC_RELAY_ID_LEN])
{
    if (pc_stun_is_stun(data, len)) {
        for (uint32_t i = 0; i < ctx->nstun; i++)
            if (pc_addr_eq(&ctx->stun[i].addr, src)) return stun_input(ctx, data, len);
        return 1;   /* unsolicited STUN: ignore */
    }
    if (data[0] < PC_RLY_ALLOC_REQ || data[0] > PC_RLY_FREE) return 0;
    for (uint32_t i = 0; i < ctx->nrelays; i++) {
        pc_relay *r = ctx->relays[i];
        if (r->tcp || !r->resolved || !pc_addr_eq(&r->addr, src)) continue;
        if (data[0] == PC_RLY_DATA) {
            if (len < 1 + PC_RELAY_ID_LEN + 1 || r->state != PC_RELAY_ALLOCATED) return 1;
            *relay_out = i;
            memcpy(peer_relay_id, data + 1, PC_RELAY_ID_LEN);
            *payload = data + 1 + PC_RELAY_ID_LEN;
            *plen = len - 1 - PC_RELAY_ID_LEN;
            return 2;
        }
        if (data[0] == PC_RLY_ALLOC_OK || data[0] == PC_RLY_ALLOC_ERR) relay_control(ctx, r, data, len);
        return 1;
    }
    return 1;   /* relay protocol from a stranger */
}

int pc_gather_init(pierce_ctx *ctx, const pierce_config *cfg)
{
    char host[256];
    uint16_t port;
    int tcp;
    uint64_t now = pc_now(ctx);

    for (uint32_t i = 0; i < cfg->stun_server_count; i++) {
        if (!cfg->stun_servers || !cfg->stun_servers[i]) return PIERCE_ERR_INVALID_ARG;
        if (split_hostport(cfg->stun_servers[i], host, sizeof(host), &port, &tcp) < 0 || tcp)
            return PIERCE_ERR_INVALID_ARG;
        pierce_addr a[4];
        int n = resolve(host, port, a, 4);
        if (n <= 0) pc_log(ctx, PIERCE_LOG_WARN, "STUN server %s: cannot resolve", host);
        for (int k = 0; k < n && ctx->nstun < PC_MAX_STUN; k++) {
            if (!family_enabled(ctx, a[k].family)) continue;
            pc_stun *s = &ctx->stun[ctx->nstun++];
            memset(s, 0, sizeof(*s));
            s->addr = a[k];
            s->next_tx_us = now;
        }
    }

    if (cfg->relay_server_count > PC_MAX_RELAYS) return PIERCE_ERR_INVALID_ARG;
    for (uint32_t i = 0; i < cfg->relay_server_count; i++) {
        if (!cfg->relay_servers || !cfg->relay_servers[i]) return PIERCE_ERR_INVALID_ARG;
        if (split_hostport(cfg->relay_servers[i], host, sizeof(host), &port, &tcp) < 0)
            return PIERCE_ERR_INVALID_ARG;
        pc_relay *r = (pc_relay *)pc_alloc(&ctx->alloc, sizeof(pc_relay));
        if (!r) return PIERCE_ERR_NO_MEMORY;
        strcpy(r->host, host);
        r->port = port;
        r->tcp = (uint8_t)tcp;
        r->sock = PAL_INVALID_SOCK;
        r->next_tx_us = now;
        int has_tokens = cfg->struct_size >= offsetof(pierce_config, relay_token_lens) + sizeof(void *);
        if (has_tokens && cfg->relay_tokens && cfg->relay_token_lens && cfg->relay_tokens[i]) {
            if (cfg->relay_token_lens[i] > sizeof(r->token)) {
                pc_free(&ctx->alloc, r);
                return PIERCE_ERR_INVALID_ARG;
            }
            memcpy(r->token, cfg->relay_tokens[i], cfg->relay_token_lens[i]);
            r->token_len = cfg->relay_token_lens[i];
        }
        ctx->relays[ctx->nrelays++] = r;
    }
    rebuild_cands(ctx, 1);
    return PIERCE_OK;
}

int pc_gather_set_token(pierce_ctx *ctx, uint32_t index, const uint8_t *token, uint32_t len)
{
    if (index >= ctx->nrelays || len > sizeof(ctx->relays[0]->token) || (len && !token))
        return PIERCE_ERR_INVALID_ARG;
    pc_relay *r = ctx->relays[index];
    if (len) memcpy(r->token, token, len);
    r->token_len = len;
    if (r->state == PC_RELAY_FAILED) r->next_tx_us = pc_now(ctx);   /* retry with the new token */
    return PIERCE_OK;
}

void pc_gather_free(pierce_ctx *ctx)
{
    for (uint32_t i = 0; i < ctx->nrelays; i++) {
        pc_relay *r = ctx->relays[i];
        if (r->sock != PAL_INVALID_SOCK) pal_sock_close(r->sock);
        pc_free(&ctx->alloc, r->tx);
        pc_free(&ctx->alloc, r);
    }
    ctx->nrelays = 0;
}

void pc_gather_destroy_notify(pierce_ctx *ctx)
{
    for (uint32_t i = 0; i < ctx->nrelays; i++) {
        pc_relay *r = ctx->relays[i];
        if (r->state != PC_RELAY_ALLOCATED) continue;
        uint8_t buf[1 + PC_RELAY_ID_LEN];
        buf[0] = PC_RLY_FREE;
        memcpy(buf + 1, r->relay_id, PC_RELAY_ID_LEN);
        relay_transmit(ctx, r, buf, sizeof(buf));
    }
}

void pc_gather_refresh(pierce_ctx *ctx)
{
    uint64_t now = pc_now(ctx);
    for (uint32_t i = 0; i < ctx->nstun; i++) {
        ctx->stun[i].tries = 0;
        ctx->stun[i].next_tx_us = now;
    }
    for (uint32_t i = 0; i < ctx->nrelays; i++) {
        pc_relay *r = ctx->relays[i];
        if (r->tcp && r->state != PC_RELAY_IDLE) {
            relay_reset(ctx, r, now);       /* the TCP connection likely died with the network */
        } else if (r->state == PC_RELAY_ALLOCATED || r->state == PC_RELAY_FAILED) {
            r->tries = 0;
            r->next_tx_us = now;
        }
    }
    rebuild_cands(ctx, 1);
}

void pc_gather_cands_rebuild(pierce_ctx *ctx) { rebuild_cands(ctx, 0); }

uint64_t pc_gather_next(pierce_ctx *ctx)
{
    uint64_t t = 0;
    for (uint32_t i = 0; i < ctx->nstun; i++)
        if (!t || ctx->stun[i].next_tx_us < t) t = ctx->stun[i].next_tx_us;
    for (uint32_t i = 0; i < ctx->nrelays; i++)
        if (ctx->relays[i]->next_tx_us != UINT64_MAX && (!t || ctx->relays[i]->next_tx_us < t))
            t = ctx->relays[i]->next_tx_us;
    return t;
}

void pc_gather_timers(pierce_ctx *ctx, uint64_t now, uint64_t *next)
{
    stun_timers(ctx, now, next);
    relay_timers(ctx, now, next);
}
