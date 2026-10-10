/* Connection lifecycle: signaling, probing (hole punching), handshake,
   accept/reject, close (spec 4.2-4.4, 5.1, 8.6). */
#include "core.h"
#include "crypto.h"

#define HS_INIT_HDR (1 + 1 + 1 + 1 + PC_CID_LEN + PC_SESSION_LEN + 1)
#define HS_RETRY_US 250000
#define HS_RETRY_MAX_US 2000000
#define PROBE_MAX_INTERVAL_US 1000000
#define COOKIE_BUCKET_US (60ull * 1000000)
#define RATE_BURST 20
#define RATE_PER_SEC 10

/* Birthday punching: the hard side opens BDAY_SOCKETS mappings, the easy
   side probes random ports. P(hit) per probe ~ BDAY_SOCKETS / 64512; with
   2048 probes that is ~1 - e^-8 > 99.9% (fewer sockets: still ~98% at 128). */
#define BDAY_DELAY_US 1000000        /* give ordinary punching a head start */
#define BDAY_WINDOW_US 10000000
#define BDAY_SOCKETS 256
#define BDAY_SCAN_MAX 2048
#define BDAY_SCAN_INTERVAL_US 4000   /* 250 probes per second */

static const uint8_t zero_session[PC_SESSION_LEN];

static uint64_t backoff(uint64_t base, uint32_t tries, uint64_t cap)
{
    uint64_t d = base << PC_MIN(tries, 16u);
    return d > cap ? cap : d;
}

/* ===================================================================== */
/* Teardown                                                              */
/* ===================================================================== */

static void finish(pc_conn *c, int32_t error)
{
    pierce_ctx *ctx = c->ctx;
    if (c->state == PC_ST_CLOSED) return;
    c->state = PC_ST_CLOSED;
    pc_free(&ctx->alloc, c->bday_tried);
    c->bday_tried = NULL;
    pc_xsock_release(ctx, c, 0);
    pc_slot_close(c);
    pc_tr_free(c);
    pc_noise_wipe(&c->hs);
    if (c->app_visible) {
        pc_event *ev = pc_event_new(ctx, PIERCE_EV_DISCONNECTED);
        if (ev) {
            ev->error = error;
            ev->reason = c->close_reason;
            pc_emit(c, ev);
        }
    } else {
        pc_conn_schedule_free(c);
    }
}

void pc_conn_fail(pc_conn *c, int32_t error)
{
    finish(c, error);
}

void pc_conn_close(pc_conn *c, uint32_t reason, int rejected, int32_t error)
{
    if (c->state == PC_ST_CLOSED) return;
    c->close_reason = reason;
    c->close_rejected = (uint8_t)rejected;
    /* Two copies: a single loss would otherwise leave the peer waiting for
       its idle timeout. */
    pc_tr_send_close(c);
    pc_tr_send_close(c);
    finish(c, error);
}

/* ===================================================================== */
/* Signaling                                                             */
/* ===================================================================== */

static void emit_signal(pc_conn *c, uint8_t kind)
{
    pierce_ctx *ctx = c->ctx;
    pc_signal s;
    uint8_t buf[2048];
    memset(&s, 0, sizeof(s));
    s.kind = kind;
    memcpy(s.session, c->session, PC_SESSION_LEN);
    memcpy(s.secret, c->my_secret, 32);
    if (kind == PC_SIG_OFFER && c->has_peer_key) memcpy(s.host_hint, c->peer_key, 8);
    s.flags = pc_gather_sig_flags(ctx);
    uint32_t from = (kind == PC_SIG_CANDIDATES && c->cands_epoch == ctx->cands_epoch) ? c->cands_sent : 0;
    for (uint32_t i = from; i < ctx->ncands && s.ncand < PC_MAX_BLOB_CANDS; i++)
        s.cands[s.ncand++] = ctx->cands[i];
    c->cands_sent = ctx->ncands;
    c->cands_epoch = ctx->cands_epoch;
    if (kind == PC_SIG_CANDIDATES && s.ncand == 0 && s.flags == c->flags_sent) return;
    c->flags_sent = s.flags;
    int n = pc_signal_encode(&s, buf, sizeof(buf));
    if (n < 0) return;
    pc_event *ev = pc_event_new(ctx, PIERCE_EV_SIGNAL_OUT);
    if (!ev) return;
    ev->msg = pc_msg_new(&ctx->alloc, buf, (uint32_t)n);
    if (!ev->msg) {
        pc_free(&ctx->alloc, ev);
        return;
    }
    c->sent_first_signal = 1;
    pc_emit(c, ev);
}

static int path_usable_direct(pierce_ctx *ctx, const pierce_addr *a)
{
    if (ctx->flags & PIERCE_CFG_RELAY_ONLY) return 0;
    if (a->family == PIERCE_AF_INET) {
        if (ctx->flags & PIERCE_CFG_NO_IPV4) return 0;
        return (ctx->flags & PIERCE_CFG_NO_BUILTIN_UDP) || ctx->sock4 != PAL_INVALID_SOCK;
    }
    if (a->family == PIERCE_AF_INET6) {
        if (ctx->flags & PIERCE_CFG_NO_IPV6) return 0;
        return (ctx->flags & PIERCE_CFG_NO_BUILTIN_UDP) || ctx->sock6 != PAL_INVALID_SOCK;
    }
    return 0;
}

static pc_pair *pair_find(pc_conn *c, const pc_path *p)
{
    for (uint32_t i = 0; i < c->npairs; i++)
        if (pc_path_eq(&c->pairs[i].path, p)) return &c->pairs[i];
    return NULL;
}

static pc_pair *pair_add(pc_conn *c, const pc_path *p, uint32_t remote_index)
{
    pc_pair *pr = pair_find(c, p);
    if (pr) return pr;
    if (c->npairs >= PC_MAX_PAIRS) return NULL;
    if (c->npairs == c->cappairs) {
        uint32_t nc = c->cappairs ? c->cappairs * 2 : 16;
        if (nc > PC_MAX_PAIRS) nc = PC_MAX_PAIRS;
        pc_pair *n = (pc_pair *)pc_realloc(&c->ctx->alloc, c->pairs, c->cappairs * sizeof(pc_pair),
                                           nc * sizeof(pc_pair));
        if (!n) return NULL;
        c->pairs = n;
        c->cappairs = nc;
    }
    pr = &c->pairs[c->npairs++];
    memset(pr, 0, sizeof(*pr));
    pr->path = *p;
    pr->remote_index = remote_index;
    uint64_t now = pc_now(c->ctx);
    pr->next_tx_us = p->kind == PC_PATH_KIND_RELAY ? now + PC_RELAY_PROBE_DELAY_US : now;
    return pr;
}

/* Build pairs for every remote candidate we can reach. Called again when a
   local relay allocation appears. */
static void pairs_refresh(pc_conn *c)
{
    pierce_ctx *ctx = c->ctx;
    for (uint32_t i = 0; i < c->nremote; i++) {
        const pc_cand *rc = &c->remote[i];
        pc_path p;
        memset(&p, 0, sizeof(p));
        if (rc->type == PC_CAND_RELAY) {
            int rl = pc_relay_index_by_server(ctx, rc->relay_server);
            if (rl < 0) continue;
            p.kind = PC_PATH_KIND_RELAY;
            p.relay = (uint32_t)rl;
            memcpy(p.peer_relay_id, rc->relay_id, PC_RELAY_ID_LEN);
        } else {
            if (!path_usable_direct(ctx, &rc->addr)) continue;
            p.kind = PC_PATH_KIND_DIRECT;
            p.remote = rc->addr;
        }
        pair_add(c, &p, i);
    }
}

static int remote_add(pc_conn *c, const pc_cand *cand)
{
    for (uint32_t i = 0; i < c->nremote; i++)
        if (pc_cand_eq(&c->remote[i], cand)) return (int)i;
    if (c->nremote >= PC_MAX_REMOTE_CANDS) return -1;
    c->remote[c->nremote] = *cand;
    return (int)c->nremote++;
}

static void add_remote_cands(pc_conn *c, const pc_signal *s)
{
    for (uint32_t i = 0; i < s->ncand; i++) remote_add(c, &s->cands[i]);
    if (c->has_probe_key) pairs_refresh(c);
}

static void derive_probe_key(pc_conn *c)
{
    uint8_t h[64];
    const uint8_t *offer = c->initiator ? c->my_secret : c->peer_secret;
    const uint8_t *answer = c->initiator ? c->peer_secret : c->my_secret;
    pc_hash2(h, offer, 32, answer, 32);
    memcpy(c->probe_key, h, 32);
    c->has_probe_key = 1;
    pc_wipe(h, sizeof(h));
}

static void start_probing(pc_conn *c)
{
    uint64_t now = pc_now(c->ctx);
    c->state = PC_ST_PROBING;
    c->probe_start_us = now;
    c->deadline_us = now + c->ctx->connect_us;
    pairs_refresh(c);
}

int pc_conn_signal_in(pierce_ctx *ctx, const pc_signal *s, pc_conn **out)
{
    pc_conn *c = pc_conn_by_session(ctx, s->session);
    *out = NULL;
    if (c) c->peer_flags = s->flags;
    switch (s->kind) {
    case PC_SIG_OFFER: {
        if (c) {                                 /* duplicate offer */
            if (c->initiator) return PIERCE_ERR_INVALID_ARG;
            add_remote_cands(c, s);
            *out = c;
            return PIERCE_OK;
        }
        if (!ctx->listening) return PIERCE_ERR_STATE;
        static const uint8_t zero8[8];
        if (memcmp(s->host_hint, zero8, 8) != 0 && memcmp(s->host_hint, ctx->pk, 8) != 0)
            return PIERCE_ERR_INVALID_ARG;       /* offer meant for a different host */
        c = pc_conn_alloc(ctx, 0, &ctx->listen_opt);
        if (!c) return PIERCE_ERR_NO_MEMORY;
        memcpy(c->session, s->session, PC_SESSION_LEN);
        c->has_session = 1;
        c->peer_flags = s->flags;
        memcpy(c->peer_secret, s->secret, 32);
        c->has_peer_secret = 1;
        pc_random(c->my_secret, 32);
        derive_probe_key(c);
        c->app_visible = 1;                      /* the app holds the ID from signal_in */
        for (uint32_t i = 0; i < s->ncand; i++) remote_add(c, &s->cands[i]);
        start_probing(c);
        emit_signal(c, PC_SIG_ANSWER);
        *out = c;
        return PIERCE_OK;
    }
    case PC_SIG_ANSWER:
        if (!c || !c->initiator) return PIERCE_ERR_NO_SUCH_CONN;
        if (c->state == PC_ST_SIGNALING) {
            memcpy(c->peer_secret, s->secret, 32);
            c->has_peer_secret = 1;
            derive_probe_key(c);
            for (uint32_t i = 0; i < s->ncand; i++) remote_add(c, &s->cands[i]);
            start_probing(c);
        } else if (memcmp(c->peer_secret, s->secret, 32) == 0) {
            add_remote_cands(c, s);              /* duplicate answer */
        } else {
            return PIERCE_ERR_INVALID_ARG;
        }
        *out = c;
        return PIERCE_OK;
    case PC_SIG_CANDIDATES:
        if (!c) return PIERCE_ERR_NO_SUCH_CONN;
        add_remote_cands(c, s);
        *out = c;
        return PIERCE_OK;
    }
    return PIERCE_ERR_INVALID_ARG;
}

void pc_conn_cands_changed(pierce_ctx *ctx)
{
    for (pc_conn *c = ctx->conns; c; c = c->next) {
        if (c->state == PC_ST_CLOSED) continue;
        if (c->has_probe_key) pairs_refresh(c);
        if (!c->has_session || !c->sent_first_signal) continue;
        if (c->state > PC_ST_HANDSHAKE) continue;
        if (c->cands_epoch != ctx->cands_epoch || ctx->ncands > c->cands_sent ||
            pc_gather_sig_flags(ctx) != c->flags_sent)
            emit_signal(c, PC_SIG_CANDIDATES);
    }
}

/* ===================================================================== */
/* Probes                                                                */
/* ===================================================================== */

static void send_probe(pc_conn *c, pc_pair *pr, uint64_t now)
{
    uint8_t p[PC_PROBE_LEN];
    uint8_t slot = pr->txpos++ % 4;
    pc_random(pr->txid[slot], PC_TXID_LEN);
    pr->tx_us[slot] = now;
    p[0] = PC_PKT_PROBE;
    memcpy(p + 1, c->session, PC_SESSION_LEN);
    memcpy(p + 1 + PC_SESSION_LEN, pr->txid[slot], PC_TXID_LEN);
    p[1 + PC_SESSION_LEN + PC_TXID_LEN] = c->initiator ? 1 : 0;
    pc_mac16(p + PC_PROBE_LEN - 16, c->probe_key, 32, p, PC_PROBE_LEN - 16);
    pc_send_path(c->ctx, &pr->path, p, sizeof(p));
    pr->last_tx_us = now;
    pr->tries++;
    uint64_t iv = backoff(50000, pr->tries > 3 ? pr->tries - 3 : 0, PROBE_MAX_INTERVAL_US);
    pr->next_tx_us = now + iv;
}

static void probe_pairs(pc_conn *c, uint64_t now, int direct_only)
{
    for (uint32_t i = 0; i < c->npairs; i++) {
        pc_pair *pr = &c->pairs[i];
        if (pr->validated || pr->dead) continue;
        if (direct_only && pr->path.kind != PC_PATH_KIND_DIRECT) continue;
        if (now >= pr->next_tx_us) send_probe(c, pr, now);
    }
}

static uint64_t probe_next(pc_conn *c, int direct_only)
{
    uint64_t t = 0;
    for (uint32_t i = 0; i < c->npairs; i++) {
        pc_pair *pr = &c->pairs[i];
        if (pr->validated || pr->dead) continue;
        if (direct_only && pr->path.kind != PC_PATH_KIND_DIRECT) continue;
        if (!t || pr->next_tx_us < t) t = pr->next_tx_us;
    }
    return t;
}

/* ===================================================================== */
/* Birthday punching                                                     */
/* ===================================================================== */

static void bday_txid(const pc_conn *c, uint16_t port, uint8_t out[PC_TXID_LEN])
{
    uint8_t in[6] = {'b', 'd', 'a', 'y', (uint8_t)(port >> 8), (uint8_t)port};
    uint8_t mac[16];
    pc_mac16(mac, c->probe_key, 32, in, sizeof(in));
    memcpy(out, mac, PC_TXID_LEN);
}

/* Stop: close every extra socket except the one the connection uses. */
static void bday_finish(pc_conn *c)
{
    if (!c->bday_role || c->bday_done) return;
    c->bday_done = 1;
    uint16_t keep = c->has_path && c->path.kind == PC_PATH_KIND_DIRECT ? c->path.local : 0;
    pc_xsock_release(c->ctx, c, keep);
    for (uint32_t i = 0; i < c->npairs; i++)
        if (c->pairs[i].path.kind == PC_PATH_KIND_DIRECT && c->pairs[i].path.local &&
            c->pairs[i].path.local != keep)
            c->pairs[i].dead = 1;
    pc_free(&c->ctx->alloc, c->bday_tried);
    c->bday_tried = NULL;
    int won = keep || (c->has_path && c->path.kind == PC_PATH_KIND_DIRECT);
    if (c->bday_role == 2)
        pc_log(c->ctx, PIERCE_LOG_DEBUG, "conn %llu: birthday punching %s after %u probes",
               (unsigned long long)c->id, won ? "succeeded" : "gave up", c->bday_sent);
    else
        pc_log(c->ctx, PIERCE_LOG_DEBUG, "conn %llu: birthday punching %s; extra sockets closed",
               (unsigned long long)c->id, won ? "succeeded" : "gave up");
}

static const pc_cand *peer_srflx4(const pc_conn *c)
{
    for (uint32_t i = 0; i < c->nremote; i++)
        if (c->remote[i].type == PC_CAND_SRFLX && c->remote[i].addr.family == PIERCE_AF_INET) return &c->remote[i];
    return NULL;
}

static int direct_validated(const pc_conn *c)
{
    for (uint32_t i = 0; i < c->npairs; i++)
        if (c->pairs[i].validated && c->pairs[i].path.kind == PC_PATH_KIND_DIRECT) return 1;
    return 0;
}

/* Decide once, a moment into probing, whether this pair needs it. */
static void bday_maybe_start(pc_conn *c, uint64_t now)
{
    pierce_ctx *ctx = c->ctx;
    if (c->bday_role || !c->has_probe_key || !c->probe_start_us) return;
    if (now < c->probe_start_us + BDAY_DELAY_US) return;
    if (ctx->flags & (PIERCE_CFG_NO_BIRTHDAY | PIERCE_CFG_RELAY_ONLY | PIERCE_CFG_NO_IPV4)) return;
    if (direct_validated(c)) return;
    uint8_t mine = ctx->nat_class, theirs = c->peer_flags & PC_SIG_FLAG_NAT_MASK;
    if ((pc_gather_sig_flags(ctx) | c->peer_flags) & PC_SIG_FLAG_MAPPED) return;   /* a mapping beats guessing */
    const pc_cand *target = peer_srflx4(c);
    if (!target) return;
    uint8_t role = mine == PC_NAT_HARD && theirs == PC_NAT_EASY ? 1 : mine == PC_NAT_EASY && theirs == PC_NAT_HARD ? 2 : 0;
    if (!role) return;
    c->bday_role = role;
    c->bday_start_us = now;
    c->bday_end_us = now + BDAY_WINDOW_US;
    c->bday_target = target->addr;
    if (role == 1) {
        /* Spray: many sockets, each a new mapping on our symmetric NAT,
           all aimed at the peer's (stable) public address. */
        int opened = 0;
        for (int i = 0; i < BDAY_SOCKETS; i++) {
            uint16_t local = pc_xsock_open(ctx, c);
            if (!local) break;
            pc_path p;
            memset(&p, 0, sizeof(p));
            p.kind = PC_PATH_KIND_DIRECT;
            p.local = local;
            p.remote = target->addr;
            if (!pair_add(c, &p, (uint32_t)(target - c->remote))) {
                pc_xsock_close(ctx, local);
                break;
            }
            opened++;
        }
        pc_log(ctx, PIERCE_LOG_INFO, "conn %llu: peer behind an easy NAT, we are symmetric: birthday punching from %d sockets",
               (unsigned long long)c->id, opened);
        if (!opened) c->bday_done = 1;
    } else {
        c->bday_tried = (uint8_t *)pc_alloc(&ctx->alloc, 65536 / 8);
        if (!c->bday_tried) {
            c->bday_done = 1;
            return;
        }
        pc_log(ctx, PIERCE_LOG_INFO, "conn %llu: peer behind a symmetric NAT: birthday punching its ports",
               (unsigned long long)c->id);
    }
}

static void bday_scan(pc_conn *c, uint64_t now)
{
    uint32_t due = (uint32_t)((now - c->bday_start_us) / BDAY_SCAN_INTERVAL_US) + 1;
    if (due > BDAY_SCAN_MAX) due = BDAY_SCAN_MAX;
    for (int burst = 0; c->bday_sent < due && burst < 32; burst++) {
        uint16_t port;
        do {
            port = (uint16_t)(1024 + pc_random_u64() % (65536 - 1024));
        } while (c->bday_tried[port / 8] & (1u << (port % 8)));
        c->bday_tried[port / 8] |= (uint8_t)(1u << (port % 8));
        uint8_t p[PC_PROBE_LEN];
        p[0] = PC_PKT_PROBE;
        memcpy(p + 1, c->session, PC_SESSION_LEN);
        bday_txid(c, port, p + 1 + PC_SESSION_LEN);
        p[1 + PC_SESSION_LEN + PC_TXID_LEN] = c->initiator ? 1 : 0;
        pc_mac16(p + PC_PROBE_LEN - 16, c->probe_key, 32, p, PC_PROBE_LEN - 16);
        pierce_addr to = c->bday_target;
        to.port = port;
        pc_send_direct(c->ctx, &to, p, sizeof(p));
        c->bday_sent++;
    }
}

static void bday_timers(pc_conn *c, uint64_t now)
{
    if (c->state < PC_ST_PROBING || c->state == PC_ST_CLOSED) return;
    if (!c->bday_role) {
        if (c->state == PC_ST_PROBING || (c->has_path && c->path.kind == PC_PATH_KIND_RELAY))
            bday_maybe_start(c, now);
        return;
    }
    if (c->bday_done) return;
    /* Done once a direct path is in use, or when the window closes. */
    int direct_in_use = c->has_path && c->path.kind == PC_PATH_KIND_DIRECT && c->state >= PC_ST_AWAIT_APP;
    if (direct_in_use || now >= c->bday_end_us) {
        bday_finish(c);
        return;
    }
    if (c->bday_role == 2 && c->bday_sent < BDAY_SCAN_MAX && !direct_validated(c)) bday_scan(c, now);
}

static uint64_t bday_next(const pc_conn *c)
{
    if (c->state < PC_ST_PROBING || c->state == PC_ST_CLOSED) return 0;
    if (!c->bday_role) {
        if (!c->probe_start_us || c->bday_done) return 0;
        if (c->state != PC_ST_PROBING && !(c->has_path && c->path.kind == PC_PATH_KIND_RELAY)) return 0;
        uint64_t t = c->probe_start_us + BDAY_DELAY_US;
        return t < c->probe_start_us + c->ctx->connect_us ? t : 0;
    }
    if (c->bday_done) return 0;
    uint64_t t = c->bday_end_us;
    if (c->bday_role == 2 && c->bday_sent < BDAY_SCAN_MAX) {
        uint64_t s = c->bday_start_us + (uint64_t)c->bday_sent * BDAY_SCAN_INTERVAL_US;
        if (s < t) t = s;
    }
    if (c->bday_role == 1 || c->state >= PC_ST_AWAIT_APP) {
        /* Release sockets promptly once connected. */
        if (c->has_path && c->path.kind == PC_PATH_KIND_DIRECT && c->state >= PC_ST_AWAIT_APP) t = pc_now(c->ctx);
    }
    return t;
}

static void send_hs_init(pc_conn *c, const pc_path *only);
static int initiator_begin_handshake(pc_conn *c);

static void select_path(pc_conn *c, pc_pair *pr, uint64_t now)
{
    c->path = pr->path;
    c->has_path = 1;
    pc_log(c->ctx, PIERCE_LOG_DEBUG, "conn %llu: path selected (%s), rtt %llu us",
           (unsigned long long)c->id, pr->path.kind == PC_PATH_KIND_RELAY ? "relay" : "direct",
           (unsigned long long)pr->rtt_us);
    c->state = PC_ST_HANDSHAKE;
    c->hs_tries = 0;
    c->hs_next_tx_us = now;
    if (initiator_begin_handshake(c) < 0) {
        finish(c, PIERCE_ERR_CRYPTO);
        return;
    }
    send_hs_init(c, &c->path);
}

void pc_conn_input_probe(pierce_ctx *ctx, const pc_path *path, const uint8_t *p, size_t len)
{
    uint8_t mac[16];
    if (len < 1 + PC_SESSION_LEN) return;
    pc_conn *c = pc_conn_by_session(ctx, p + 1);
    if (!c || !c->has_probe_key || c->state == PC_ST_CLOSED) return;
    uint64_t now = pc_now(ctx);

    if (p[0] == PC_PKT_PROBE) {
        if (len != PC_PROBE_LEN) return;
        pc_mac16(mac, c->probe_key, 32, p, PC_PROBE_LEN - 16);
        if (!pc_ct_eq16(mac, p + PC_PROBE_LEN - 16)) return;
        uint8_t role = p[1 + PC_SESSION_LEN + PC_TXID_LEN];
        if (role == (c->initiator ? 1 : 0)) return;          /* our own probe reflected */
        /* Learn peer-reflexive candidates (e.g. a symmetric NAT mapping). */
        pc_pair *pr = pair_find(c, path);
        if (!pr && path->kind == PC_PATH_KIND_DIRECT && path_usable_direct(ctx, &path->remote)) {
            pc_cand cand;
            memset(&cand, 0, sizeof(cand));
            cand.type = PC_CAND_PRFLX;
            cand.addr = path->remote;
            int idx = remote_add(c, &cand);
            if (idx >= 0) pr = pair_add(c, path, (uint32_t)idx);
        } else if (!pr && path->kind == PC_PATH_KIND_RELAY) {
            pr = pair_add(c, path, 0);
        }
        if (pr) {
            pr->rx_ok = 1;
            /* Triggered check: probe back right away (ICE-style). */
            if (!pr->validated && pr->tries < 3) pr->next_tx_us = now;
        }
        uint8_t a[PC_PROBE_ACK_LEN];
        pc_wbuf w;
        pc_wbuf_init(&w, a, sizeof(a));
        pc_w_u8(&w, PC_PKT_PROBE_ACK);
        pc_w_bytes(&w, c->session, PC_SESSION_LEN);
        pc_w_bytes(&w, p + 1 + PC_SESSION_LEN, PC_TXID_LEN);
        pierce_addr obs;
        memset(&obs, 0, sizeof(obs));
        if (path->kind == PC_PATH_KIND_DIRECT) obs = path->remote;
        pc_w_addr(&w, &obs);
        pc_mac16(a + w.len, c->probe_key, 32, a, w.len);
        pc_send_path(ctx, path, a, sizeof(a));
        if (pr && !pr->validated && pr->tries == 0) send_probe(c, pr, now);
        return;
    }

    if (p[0] == PC_PKT_PROBE_ACK) {
        if (len != PC_PROBE_ACK_LEN) return;
        pc_mac16(mac, c->probe_key, 32, p, PC_PROBE_ACK_LEN - 16);
        if (!pc_ct_eq16(mac, p + PC_PROBE_ACK_LEN - 16)) return;
        const uint8_t *txid = p + 1 + PC_SESSION_LEN;
        pc_pair *pr = NULL;
        uint64_t sent = 0;
        for (uint32_t i = 0; i < c->npairs && !pr; i++)
            for (int k = 0; k < 4; k++)
                if (c->pairs[i].tries && memcmp(c->pairs[i].txid[k], txid, PC_TXID_LEN) == 0) {
                    pr = &c->pairs[i];
                    sent = pr->tx_us[k];
                    break;
                }
        if (!pr && c->bday_role == 2 && path->kind == PC_PATH_KIND_DIRECT && path->local == 0 &&
            pc_addr_ip_eq(&path->remote, &c->bday_target)) {
            /* A scan probe found one of the peer's mappings: the txid is a
               MAC of the port we probed, so it vouches for this source. */
            uint8_t want[PC_TXID_LEN];
            bday_txid(c, path->remote.port, want);
            if (memcmp(want, txid, PC_TXID_LEN) != 0) return;
            pc_cand cand;
            memset(&cand, 0, sizeof(cand));
            cand.type = PC_CAND_PRFLX;
            cand.addr = path->remote;
            int idx = remote_add(c, &cand);
            if (idx < 0) return;
            pr = pair_add(c, path, (uint32_t)idx);
            if (!pr) return;
            sent = 0;
            pc_log(ctx, PIERCE_LOG_DEBUG, "conn %llu: birthday hit after %u probes", (unsigned long long)c->id,
                   c->bday_sent);
        }
        /* The ack must come back over the path the probe went out on. */
        if (!pr || !pc_path_eq(&pr->path, path) || pr->validated || pr->dead) return;
        pr->validated = 1;
        pr->rtt_us = sent ? now - sent : 0;
        if (!c->initiator) return;
        if (c->state == PC_ST_PROBING) {
            select_path(c, pr, now);
        } else if (c->state >= PC_ST_HANDSHAKE && c->state <= PC_ST_CONNECTED &&
                   c->has_path && c->path.kind == PC_PATH_KIND_RELAY &&
                   pr->path.kind == PC_PATH_KIND_DIRECT && c->keys_ready) {
            /* Upgrade from relay to a direct path; the peer follows once an
               authenticated packet arrives from the new address. */
            pc_conn_path_update(c, &pr->path);
            c->ping_pending = 1;
        }
    }
}

/* ===================================================================== */
/* Handshake                                                             */
/* ===================================================================== */

static void prologue(const pc_conn *c, uint8_t out[8 + PC_SESSION_LEN])
{
    memcpy(out, "pierce/1", 8);
    memcpy(out + 8, c->has_session ? c->session : zero_session, PC_SESSION_LEN);
}

/* The initiator's intro: version, channel table, app payload. */
static int build_intro(pc_conn *c, uint8_t *out, size_t cap, size_t *len)
{
    pc_wbuf w;
    pc_wbuf_init(&w, out, cap);
    pc_w_u8(&w, PC_PROTOCOL_VERSION);
    pc_tr_channels_encode(c, &w);
    pc_w_varint(&w, c->hs_payload_len);
    pc_w_bytes(&w, c->hs_payload, c->hs_payload_len);
    *len = w.len;
    return w.err ? -1 : 0;
}

static void send_hs_init(pc_conn *c, const pc_path *only)
{
    pierce_ctx *ctx = c->ctx;
    uint8_t *p = ctx->pkt;
    pc_wbuf w;
    pc_wbuf_init(&w, p, PC_MTU);
    pc_w_u8(&w, PC_PKT_HS_INIT);
    pc_w_u8(&w, PC_PROTOCOL_VERSION);
    pc_w_u8(&w, PC_SUITE_NOISE_25519_CHACHAPOLY_BLAKE2B);
    pc_w_u8(&w, c->pattern);
    pc_w_bytes(&w, c->local_cid, PC_CID_LEN);
    pc_w_bytes(&w, c->has_session ? c->session : zero_session, PC_SESSION_LEN);
    pc_w_u8(&w, c->has_cookie ? PC_COOKIE_LEN : 0);
    if (c->has_cookie) pc_w_bytes(&w, c->cookie, PC_COOKIE_LEN);
    pc_w_u16(&w, c->hs_msg_len);
    pc_w_bytes(&w, c->hs_msg, c->hs_msg_len);
    if (w.err) return;
    /* Pad to the full MTU: proves the path carries it, and gives the
       responder an amplification budget. */
    memset(p + w.len, 0, PC_MTU - w.len);
    if (only) {
        pc_send_path(ctx, only, p, PC_MTU);
    } else {
        for (uint32_t i = 0; i < c->nremote; i++) {
            if (!path_usable_direct(ctx, &c->remote[i].addr)) continue;
            pc_send_direct(ctx, &c->remote[i].addr, p, PC_MTU);
        }
    }
    uint64_t now = pc_now(ctx);
    c->hs_sent_us = now;
    c->hs_next_tx_us = now + backoff(HS_RETRY_US, c->hs_tries, HS_RETRY_MAX_US);
    c->hs_tries++;
    c->hs_pkt_type = PC_PKT_HS_INIT;
}

static void send_hs_resp(pc_conn *c)
{
    uint8_t *p = c->ctx->pkt;
    pc_wbuf w;
    pc_wbuf_init(&w, p, PC_MTU);
    pc_w_u8(&w, PC_PKT_HS_RESP);
    pc_w_bytes(&w, c->remote_cid, PC_CID_LEN);
    pc_w_bytes(&w, c->local_cid, PC_CID_LEN);
    pc_w_u16(&w, c->hs_msg_len);
    pc_w_bytes(&w, c->hs_msg, c->hs_msg_len);
    if (!w.err) pc_send_path(c->ctx, &c->path, p, w.len);
}

static void send_hs_final(pc_conn *c)
{
    uint8_t *p = c->ctx->pkt;
    pc_wbuf w;
    pc_wbuf_init(&w, p, PC_MTU);
    pc_w_u8(&w, PC_PKT_HS_FINAL);
    pc_w_bytes(&w, c->remote_cid, PC_CID_LEN);
    pc_w_u16(&w, c->hs_msg_len);
    pc_w_bytes(&w, c->hs_msg, c->hs_msg_len);
    if (w.err) return;
    pc_send_path(c->ctx, &c->path, p, w.len);
    uint64_t now = pc_now(c->ctx);
    c->hs_next_tx_us = now + backoff(HS_RETRY_US, c->hs_tries, HS_RETRY_MAX_US);
    c->hs_tries++;
    c->hs_pkt_type = PC_PKT_HS_FINAL;
}

static int noise_write(pc_conn *c, const uint8_t *payload, size_t plen)
{
    size_t n;
    if (pc_noise_write(&c->hs, payload, plen, c->hs_msg, sizeof(c->hs_msg), &n) < 0) return -1;
    c->hs_msg_len = (uint16_t)n;
    return 0;
}

static void split_keys(pc_conn *c)
{
    uint8_t i2r[32], r2i[32];
    pc_noise_split(&c->hs, i2r, r2i);
    if (c->initiator) pc_tr_keys(c, i2r, r2i);
    else pc_tr_keys(c, r2i, i2r);
    pc_wipe(i2r, 32);
    pc_wipe(r2i, 32);
}

static uint64_t hs_rtt_estimate(pc_conn *c)
{
    for (uint32_t i = 0; i < c->npairs; i++)
        if (c->pairs[i].validated && pc_path_eq(&c->pairs[i].path, &c->path)) return c->pairs[i].rtt_us;
    return 0;
}

int pc_conn_start_initiator(pc_conn *c, const pc_invite *inv, int have_invite)
{
    uint8_t pro[8 + PC_SESSION_LEN];
    c->pattern = have_invite ? PC_NOISE_IK : PC_NOISE_XX;
    if (have_invite) {
        memcpy(c->peer_key, inv->key, 32);
        c->has_peer_key = 1;
    }
    if (have_invite && inv->naddr > 0) {
        /* Direct connect: no signaling, handshake straight to the invite
           addresses (spec 10: a server is a peer with a public address). */
        c->direct = 1;
        for (uint32_t i = 0; i < inv->naddr; i++) {
            pc_cand cand;
            memset(&cand, 0, sizeof(cand));
            cand.type = PC_CAND_HOST;
            cand.addr = inv->addrs[i];
            remote_add(c, &cand);
        }
        prologue(c, pro);
        if (pc_noise_init(&c->hs, c->pattern, 1, pro, sizeof(pro), c->ctx->sk, c->peer_key) < 0)
            return PIERCE_ERR_CRYPTO;
        uint8_t intro[1200];
        size_t ilen;
        if (build_intro(c, intro, sizeof(intro), &ilen) < 0) return PIERCE_ERR_INVALID_ARG;
        if (noise_write(c, intro, ilen) < 0) return PIERCE_ERR_INVALID_ARG;
        if (HS_INIT_HDR + 2 + c->hs_msg_len > PC_MTU) return PIERCE_ERR_INVALID_ARG;
        c->state = PC_ST_HANDSHAKE;
        c->deadline_us = pc_now(c->ctx) + c->ctx->connect_us;
        send_hs_init(c, NULL);
        return PIERCE_OK;
    }
    pc_random(c->session, PC_SESSION_LEN);
    c->has_session = 1;
    pc_random(c->my_secret, 32);
    c->state = PC_ST_SIGNALING;
    emit_signal(c, PC_SIG_OFFER);
    return PIERCE_OK;
}

/* Called when the initiator is about to send its first handshake message. */
static int initiator_begin_handshake(pc_conn *c)
{
    uint8_t pro[8 + PC_SESSION_LEN];
    prologue(c, pro);
    if (pc_noise_init(&c->hs, c->pattern, 1, pro, sizeof(pro), c->ctx->sk,
                      c->has_peer_key ? c->peer_key : NULL) < 0)
        return -1;
    if (c->pattern == PC_NOISE_IK) {
        uint8_t intro[1200];
        size_t ilen;
        if (build_intro(c, intro, sizeof(intro), &ilen) < 0) return -1;
        return noise_write(c, intro, ilen);
    }
    return noise_write(c, NULL, 0);
}

static void send_retry(pierce_ctx *ctx, const pc_path *path, const uint8_t cid[PC_CID_LEN],
                       const uint8_t cookie[PC_COOKIE_LEN])
{
    uint8_t p[1 + PC_CID_LEN + 1 + PC_COOKIE_LEN];
    p[0] = PC_PKT_HS_RETRY;
    memcpy(p + 1, cid, PC_CID_LEN);
    p[1 + PC_CID_LEN] = PC_COOKIE_LEN;
    memcpy(p + 2 + PC_CID_LEN, cookie, PC_COOKIE_LEN);
    pc_send_path(ctx, path, p, sizeof(p));
}

static void make_cookie(pierce_ctx *ctx, uint32_t bucket, const pc_path *path,
                        const uint8_t cid[PC_CID_LEN], uint8_t out[PC_COOKIE_LEN])
{
    uint8_t in[4 + PC_ADDR_WIRE_SIZE + PC_CID_LEN];
    pc_wbuf w;
    pc_wbuf_init(&w, in, sizeof(in));
    pc_w_u32(&w, bucket);
    pc_w_addr(&w, &path->remote);
    pc_w_bytes(&w, cid, PC_CID_LEN);
    pc_put32(out, bucket);
    pc_mac16(out + 4, ctx->cookie_secret, 32, in, sizeof(in));
}

static int cookie_valid(pierce_ctx *ctx, const pc_path *path, const uint8_t cid[PC_CID_LEN],
                        const uint8_t *cookie, size_t len)
{
    if (len != PC_COOKIE_LEN) return 0;
    uint32_t now_b = (uint32_t)(pc_now(ctx) / COOKIE_BUCKET_US), b = pc_get32(cookie);
    if (b != now_b && b + 1 != now_b) return 0;
    uint8_t expect[PC_COOKIE_LEN];
    make_cookie(ctx, b, path, cid, expect);
    return pc_ct_eq16(expect + 4, cookie + 4);
}

static int rate_allow(pierce_ctx *ctx, const pierce_addr *a)
{
    uint32_t h = 2166136261u;
    for (int i = 0; i < 16; i++) h = (h ^ a->addr[i]) * 16777619u;
    pc_ratebucket *b = &ctx->rate[h % PC_RATE_BUCKETS];
    uint64_t now = pc_now(ctx);
    if (b->family != a->family || memcmp(b->ip, a->addr, 16) != 0) {
        b->family = a->family;
        memcpy(b->ip, a->addr, 16);
        b->tokens = RATE_BURST * 1000;
        b->last_us = now;
    }
    uint64_t refill = (now - b->last_us) * RATE_PER_SEC / 1000;  /* milli-tokens */
    b->tokens = (uint32_t)PC_MIN((uint64_t)RATE_BURST * 1000, b->tokens + refill);
    b->last_us = now;
    if (b->tokens < 1000) return 0;
    b->tokens -= 1000;
    return 1;
}

/* Responder: the initiator's intro arrived (IK msg 1 or XX msg 3). */
static void intro_received(pc_conn *c, const uint8_t *payload, size_t len)
{
    pierce_ctx *ctx = c->ctx;
    pc_rbuf r;
    pierce_channel_config ch[PIERCE_MAX_CHANNELS];
    uint32_t nch = 0;
    pc_rbuf_init(&r, payload, len);
    uint8_t ver = pc_r_u8(&r);
    if (r.err || ver != PC_PROTOCOL_VERSION || pc_tr_channels_decode(&r, ch, &nch) < 0) {
        pc_conn_close(c, PIERCE_REASON_PROTOCOL, 1, PIERCE_ERR_CLOSED);
        return;
    }
    uint64_t alen = pc_r_varint(&r);
    const uint8_t *app = pc_r_ptr(&r, (size_t)alen);
    if (r.err || alen > PC_MAX_HS_PAYLOAD) {
        pc_conn_close(c, PIERCE_REASON_PROTOCOL, 1, PIERCE_ERR_CLOSED);
        return;
    }
    if (ctx->listen_has_table &&
        !pc_tr_channels_equal(ctx->listen_ch, ctx->listen_opt.channel_count, ch, nch)) {
        pc_log(ctx, PIERCE_LOG_INFO, "rejecting peer: channel table mismatch");
        pc_conn_close(c, PIERCE_REASON_CHANNEL_MISMATCH, 1, PIERCE_OK);
        return;
    }
    pc_tr_setup_channels(c, ch, nch);
    pc_slot_set_channels(c);
    c->peer_payload = pc_msg_new(&ctx->alloc, app, (uint32_t)alen);
    memcpy(c->peer_key, c->hs.rs, 32);
    c->has_peer_key = 1;
    c->state = PC_ST_AWAIT_APP;
    c->deadline_us = pc_now(ctx) + ctx->connect_us;
    c->app_visible = 1;
    pc_event *ev = pc_event_new(ctx, PIERCE_EV_PEER_REQUEST);
    if (ev) {
        memcpy(ev->peer_key, c->peer_key, 32);
        ev->has_peer_key = 1;
        if (c->peer_payload) {
            pc_msg_ref(c->peer_payload);
            ev->msg = c->peer_payload;
        }
        pc_emit(c, ev);
    }
}

static void responder_hs_init(pierce_ctx *ctx, const pc_path *path, const uint8_t *p, size_t len)
{
    pc_rbuf r;
    uint8_t cid[PC_CID_LEN], session[PC_SESSION_LEN], cookie[PC_COOKIE_LEN];
    pc_rbuf_init(&r, p, len);
    pc_r_u8(&r);
    uint8_t ver = pc_r_u8(&r), suite = pc_r_u8(&r), pattern = pc_r_u8(&r);
    pc_r_bytes(&r, cid, PC_CID_LEN);
    pc_r_bytes(&r, session, PC_SESSION_LEN);
    uint8_t clen = pc_r_u8(&r);
    if (clen && clen != PC_COOKIE_LEN) return;
    if (clen) pc_r_bytes(&r, cookie, PC_COOKIE_LEN);
    uint16_t nlen = pc_r_u16(&r);
    const uint8_t *noise = pc_r_ptr(&r, nlen);
    if (r.err || ver != PC_PROTOCOL_VERSION || suite != PC_SUITE_NOISE_25519_CHACHAPOLY_BLAKE2B)
        return;
    if (pattern != PC_NOISE_IK && pattern != PC_NOISE_XX) return;

    pc_conn *c;
    int signaled = memcmp(session, zero_session, PC_SESSION_LEN) != 0;
    if (signaled) {
        c = pc_conn_by_session(ctx, session);
        if (!c || c->initiator || c->state == PC_ST_CLOSED) return;
        if (c->state != PC_ST_PROBING) {
            /* Retransmitted HS_INIT: our HS_RESP was lost. */
            if (c->has_remote_cid && memcmp(c->remote_cid, cid, PC_CID_LEN) == 0 && c->hs_msg_len &&
                c->state >= PC_ST_HANDSHAKE)
                send_hs_resp(c);
            return;
        }
        /* Address validation: this path must have delivered a valid probe. */
        pc_pair *pr = pair_find(c, path);
        if (!pr || !pr->rx_ok) return;
    } else {
        if (!ctx->listening) return;
        c = pc_conn_by_remote_cid(ctx, cid, path);
        if (c) {
            if (c->hs_msg_len && c->state >= PC_ST_HANDSHAKE && c->state != PC_ST_CLOSED) send_hs_resp(c);
            return;
        }
        if (!clen || !cookie_valid(ctx, path, cid, cookie, clen)) {
            uint8_t ck[PC_COOKIE_LEN];
            if (!rate_allow(ctx, &path->remote)) return;
            make_cookie(ctx, (uint32_t)(pc_now(ctx) / COOKIE_BUCKET_US), path, cid, ck);
            send_retry(ctx, path, cid, ck);
            return;
        }
        if (!rate_allow(ctx, &path->remote)) return;
        c = NULL;
    }

    /* Run Noise before committing any state: a message we cannot decrypt
       (stale invite, wrong key, garbage) must not cost a connection slot. */
    pc_noise hs;
    uint8_t pro[8 + PC_SESSION_LEN];
    uint8_t payload[1200];
    size_t plen;
    memcpy(pro, "pierce/1", 8);
    memcpy(pro + 8, session, PC_SESSION_LEN);
    if (pc_noise_init(&hs, pattern, 0, pro, sizeof(pro), ctx->sk, NULL) < 0 ||
        pc_noise_read(&hs, noise, nlen, payload, sizeof(payload), &plen) < 0) {
        pc_noise_wipe(&hs);
        pc_log(ctx, PIERCE_LOG_DEBUG, "dropping undecryptable handshake (stale invite or wrong key?)");
        return;
    }
    if (!c) {
        c = pc_conn_alloc(ctx, 0, &ctx->listen_opt);
        if (!c) {
            pc_noise_wipe(&hs);
            pc_log(ctx, PIERCE_LOG_WARN, "connection table full; dropping handshake");
            return;
        }
        c->deadline_us = pc_now(ctx) + ctx->connect_us;
    }
    c->hs = hs;
    pc_noise_wipe(&hs);
    c->pattern = pattern;
    memcpy(c->remote_cid, cid, PC_CID_LEN);
    c->has_remote_cid = 1;
    c->path = *path;
    c->has_path = 1;
    c->last_rx_us = pc_now(ctx);
    if (noise_write(c, NULL, 0) < 0) {
        pc_conn_close(c, PIERCE_REASON_PROTOCOL, 0, PIERCE_ERR_CRYPTO);
        return;
    }
    send_hs_resp(c);
    pc_tr_init_recovery(c, hs_rtt_estimate(c));
    if (pattern == PC_NOISE_IK) {
        split_keys(c);
        intro_received(c, payload, plen);
    } else {
        c->state = PC_ST_HANDSHAKE;
    }
}

void pc_conn_input_handshake(pierce_ctx *ctx, const pc_path *path, const uint8_t *p, size_t len)
{
    uint8_t type = p[0];
    if (type == PC_PKT_HS_INIT) {
        if (len < HS_INIT_HDR + 2) return;
        responder_hs_init(ctx, path, p, len);
        return;
    }
    if (len < 1 + PC_CID_LEN) return;
    pc_conn *c = pc_conn_by_cid(ctx, p + 1);
    if (!c || c->state == PC_ST_CLOSED) return;
    uint64_t now = pc_now(ctx);

    if (type == PC_PKT_HS_RETRY) {
        if (!c->initiator || c->state != PC_ST_HANDSHAKE || !c->direct) return;
        if (len != 1 + PC_CID_LEN + 1 + PC_COOKIE_LEN || p[1 + PC_CID_LEN] != PC_COOKIE_LEN) return;
        memcpy(c->cookie, p + 2 + PC_CID_LEN, PC_COOKIE_LEN);
        c->has_cookie = 1;
        c->path.kind = PC_PATH_KIND_DIRECT;
        c->path.remote = path->remote;
        c->has_path = 1;
        c->hs_tries = 0;
        send_hs_init(c, &c->path);
        return;
    }

    if (type == PC_PKT_HS_RESP) {
        if (!c->initiator || c->state != PC_ST_HANDSHAKE) return;
        pc_rbuf r;
        uint8_t src[PC_CID_LEN], payload[1200];
        size_t plen;
        pc_rbuf_init(&r, p + 1 + PC_CID_LEN, len - 1 - PC_CID_LEN);
        pc_r_bytes(&r, src, PC_CID_LEN);
        uint16_t nlen = pc_r_u16(&r);
        const uint8_t *noise = pc_r_ptr(&r, nlen);
        if (r.err) return;
        pc_noise saved = c->hs;
        if (pc_noise_read(&c->hs, noise, nlen, payload, sizeof(payload), &plen) < 0) {
            c->hs = saved;          /* forged or corrupt: keep waiting */
            return;
        }
        pc_wipe(&saved, sizeof(saved));
        memcpy(c->remote_cid, src, PC_CID_LEN);
        c->has_remote_cid = 1;
        if (c->direct || !c->has_path) {
            c->path.kind = PC_PATH_KIND_DIRECT;
            c->path.remote = path->remote;
            c->has_path = 1;
        }
        c->last_rx_us = now;
        uint64_t rtt = hs_rtt_estimate(c);
        /* Without probes (direct connect), an unambiguous sample exists only
           if HS_INIT went out once since the last cookie. */
        if (!rtt && c->hs_tries == 1) rtt = now - c->hs_sent_us;
        pc_tr_init_recovery(c, rtt);
        c->hs_pkt_type = 0;
        if (c->pattern == PC_NOISE_IK) {
            split_keys(c);
            c->state = PC_ST_AWAIT_ACCEPT;
            c->deadline_us = now + ctx->connect_us;
        } else {
            memcpy(c->peer_key, c->hs.rs, 32);
            c->has_peer_key = 1;
            c->state = PC_ST_PEER_VERIFY;
            c->deadline_us = now + ctx->connect_us;
            pc_event *ev = pc_event_new(ctx, PIERCE_EV_PEER_REQUEST);
            if (ev) {
                memcpy(ev->peer_key, c->peer_key, 32);
                ev->has_peer_key = 1;
                pc_emit(c, ev);
            }
        }
        return;
    }

    if (type == PC_PKT_HS_FINAL) {
        if (c->initiator || c->state != PC_ST_HANDSHAKE || c->pattern != PC_NOISE_XX) return;
        pc_rbuf r;
        uint8_t payload[1200];
        size_t plen;
        pc_rbuf_init(&r, p + 1 + PC_CID_LEN, len - 1 - PC_CID_LEN);
        uint16_t nlen = pc_r_u16(&r);
        const uint8_t *noise = pc_r_ptr(&r, nlen);
        if (r.err) return;
        pc_noise saved = c->hs;
        if (pc_noise_read(&c->hs, noise, nlen, payload, sizeof(payload), &plen) < 0) {
            c->hs = saved;
            return;
        }
        pc_wipe(&saved, sizeof(saved));
        c->last_rx_us = now;
        split_keys(c);
        intro_received(c, payload, plen);
    }
}

/* ===================================================================== */
/* App decisions                                                         */
/* ===================================================================== */

void pc_conn_set_connected(pc_conn *c)
{
    if (c->state == PC_ST_CONNECTED) return;
    c->state = PC_ST_CONNECTED;
    c->deadline_us = 0;
    pc_event *ev = pc_event_new(c->ctx, PIERCE_EV_CONNECTED);
    if (ev) {
        memcpy(ev->peer_key, c->peer_key, 32);
        ev->has_peer_key = 1;
        ev->addr = c->path.kind == PC_PATH_KIND_DIRECT ? c->path.remote : ev->addr;
        ev->flags = c->path.kind == PC_PATH_KIND_RELAY ? PIERCE_PATH_RELAY : PIERCE_PATH_DIRECT;
        pc_emit(c, ev);
    }
}

int pc_conn_app_accept(pc_conn *c, uint64_t user_data)
{
    if (c->state == PC_ST_AWAIT_APP) {
        c->user_data = user_data;
        c->accept_pending = 1;
        pc_conn_set_connected(c);
        return PIERCE_OK;
    }
    if (c->state == PC_ST_PEER_VERIFY) {
        uint8_t intro[1200];
        size_t ilen;
        c->user_data = user_data;
        if (build_intro(c, intro, sizeof(intro), &ilen) < 0 || noise_write(c, intro, ilen) < 0) {
            finish(c, PIERCE_ERR_CRYPTO);
            return PIERCE_ERR_CRYPTO;
        }
        split_keys(c);
        c->state = PC_ST_AWAIT_ACCEPT;
        c->deadline_us = pc_now(c->ctx) + c->ctx->connect_us;
        c->hs_tries = 0;
        send_hs_final(c);
        return PIERCE_OK;
    }
    return PIERCE_ERR_STATE;
}

int pc_conn_app_reject(pc_conn *c, uint32_t reason)
{
    if (c->state == PC_ST_AWAIT_APP) {
        pc_conn_close(c, reason, 1, PIERCE_OK);
        return PIERCE_OK;
    }
    if (c->state == PC_ST_PEER_VERIFY) {
        c->close_reason = reason;
        finish(c, PIERCE_OK);   /* no keys yet: nothing to tell the peer */
        return PIERCE_OK;
    }
    return PIERCE_ERR_STATE;
}

void pc_conn_path_update(pc_conn *c, const pc_path *path)
{
    int changed = c->has_path && !pc_path_eq(&c->path, path);
    c->path = *path;
    c->has_path = 1;
    if (!changed) return;
    /* New path, new congestion state (RFC 9002 9.4). */
    c->cc.cwnd = 10 * PC_MTU;
    c->cc.ssthresh = UINT64_MAX;
    c->cc.in_recovery_valid = 0;
    if (c->state == PC_ST_CONNECTED && c->app_visible) {
        pc_event *ev = pc_event_new(c->ctx, PIERCE_EV_PATH_CHANGED);
        if (ev) {
            if (path->kind == PC_PATH_KIND_DIRECT) ev->addr = path->remote;
            ev->flags = path->kind == PC_PATH_KIND_RELAY ? PIERCE_PATH_RELAY : PIERCE_PATH_DIRECT;
            pc_emit(c, ev);
        }
    }
}

/* ===================================================================== */
/* Timers                                                                */
/* ===================================================================== */

/* While on a relay path and still inside the connect window, both sides keep
   probing direct pairs: the responder's probes keep its NAT open, and the
   initiator switches paths when one validates. */
static int upgrade_probing(const pc_conn *c)
{
    return c->has_path && c->path.kind == PC_PATH_KIND_RELAY && c->has_probe_key &&
           c->probe_start_us && pc_now(c->ctx) < c->probe_start_us + c->ctx->connect_us;
}

uint64_t pc_conn_next_timer(pc_conn *c)
{
    uint64_t t = 0;
#define TMIN(x) do { uint64_t v_ = (x); if (v_ && (!t || v_ < t)) t = v_; } while (0)
    pierce_ctx *ctx = c->ctx;
    switch (c->state) {
    case PC_ST_CLOSED:
    case PC_ST_SIGNALING:
        return 0;
    case PC_ST_PROBING:
        TMIN(probe_next(c, 0));
        break;
    case PC_ST_HANDSHAKE:
        if (c->initiator) TMIN(c->hs_next_tx_us);
        break;
    case PC_ST_AWAIT_ACCEPT:
        if (c->hs_pkt_type == PC_PKT_HS_FINAL) TMIN(c->hs_next_tx_us);
        break;
    default:
        break;
    }
    if (c->state != PC_ST_CONNECTED) TMIN(c->deadline_us);
    if (c->keys_ready) {
        TMIN(pc_tr_next_timer(c));
        TMIN(c->last_rx_us + ctx->idle_us);
        if (c->state == PC_ST_CONNECTED)
            TMIN(PC_MAX(c->last_eliciting_tx_us, c->last_rx_us) + ctx->keepalive_us);
    }
    if (c->state != PC_ST_PROBING && upgrade_probing(c)) TMIN(probe_next(c, 1));
    TMIN(bday_next(c));
#undef TMIN
    return t;
}

void pc_conn_timers(pc_conn *c, uint64_t now)
{
    pierce_ctx *ctx = c->ctx;
    if (c->state == PC_ST_CLOSED || c->state == PC_ST_SIGNALING) return;

    if (c->state != PC_ST_CONNECTED && c->deadline_us && now >= c->deadline_us) {
        switch (c->state) {
        case PC_ST_PROBING:
            {
                /* Say why, in terms an app can show a user. */
                uint8_t mine = ctx->nat_class, theirs = c->peer_flags & PC_SIG_FLAG_NAT_MASK;
                const char *why;
                if (mine == PC_NAT_HARD && theirs == PC_NAT_HARD)
                    why = "both sides are behind symmetric NATs, which only a relay (or IPv6) can bridge";
                else if (mine == PC_NAT_HARD || theirs == PC_NAT_HARD)
                    why = "one side is behind a symmetric NAT and birthday punching did not get through";
                else if (!c->nremote)
                    why = "no candidates arrived from the peer (check the signaling)";
                else
                    why = "the networks block the direct paths tried (firewall, UDP filtering)";
                pc_log(ctx, PIERCE_LOG_WARN, "conn %llu: no path found: %s%s", (unsigned long long)c->id, why,
                       ctx->nrelays ? "" : "; no relay is configured");
            }
            finish(c, PIERCE_ERR_UNREACHABLE);
            return;
        case PC_ST_AWAIT_APP:
            pc_conn_close(c, PIERCE_REASON_TIMEOUT, 1, PIERCE_ERR_TIMEOUT);
            return;
        default:
            if (c->state == PC_ST_HANDSHAKE && c->direct && !c->has_path) finish(c, PIERCE_ERR_UNREACHABLE);
            else finish(c, PIERCE_ERR_TIMEOUT);
            return;
        }
    }

    switch (c->state) {
    case PC_ST_PROBING:
        probe_pairs(c, now, 0);
        break;
    case PC_ST_HANDSHAKE:
        if (c->initiator && now >= c->hs_next_tx_us) {
            if (!c->hs_msg_len && initiator_begin_handshake(c) < 0) {
                finish(c, PIERCE_ERR_CRYPTO);
                return;
            }
            send_hs_init(c, c->direct && !c->has_cookie ? NULL : &c->path);
        }
        break;
    case PC_ST_AWAIT_ACCEPT:
        if (c->hs_pkt_type == PC_PKT_HS_FINAL && now >= c->hs_next_tx_us) send_hs_final(c);
        break;
    default:
        break;
    }

    if (c->keys_ready) {
        if (now >= c->last_rx_us + ctx->idle_us) {
            pc_log(ctx, PIERCE_LOG_INFO, "conn %llu: idle timeout", (unsigned long long)c->id);
            finish(c, PIERCE_ERR_TIMEOUT);
            return;
        }
        pc_tr_timers(c, now);
        if (c->state == PC_ST_CONNECTED &&
            now >= PC_MAX(c->last_eliciting_tx_us, c->last_rx_us) + ctx->keepalive_us)
            c->ping_pending = 1;
    }
    if (c->state != PC_ST_PROBING && upgrade_probing(c)) probe_pairs(c, now, 1);
    bday_timers(c, now);
}
