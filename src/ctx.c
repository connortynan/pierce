/* Context lifecycle, connection table, poll loop, events, public API. */
#include <stdarg.h>
#include <stdio.h>

#include "../vendor/monocypher/src/monocypher.h"
#include "core.h"
#include "crypto.h"

#define IO_BATCH 256          /* datagrams read per socket per loop pass */

/* struct_size of the original v1 config (fields up to `allocator`). */
#define CFG_V1_MIN (offsetof(pierce_config, allocator) + sizeof(void *))
#define OPT_V1_MIN (offsetof(pierce_conn_options, channel_count) + sizeof(uint32_t))
#define HAS_FIELD(s, type, field) ((s)->struct_size >= offsetof(type, field) + sizeof((s)->field))

/* ===================================================================== */
/* Small public helpers                                                  */
/* ===================================================================== */

void pierce_config_init(pierce_config *cfg)
{
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));
    cfg->struct_size = sizeof(*cfg);
    cfg->log_level = PIERCE_LOG_OFF;
}

void pierce_conn_options_init(pierce_conn_options *opt)
{
    if (!opt) return;
    memset(opt, 0, sizeof(*opt));
    opt->struct_size = sizeof(*opt);
}

void pierce_channel_config_init(pierce_channel_config *ch)
{
    if (!ch) return;
    memset(ch, 0, sizeof(*ch));
    ch->struct_size = sizeof(*ch);
}

int pierce_keygen(uint8_t secret_out[32])
{
    if (!secret_out) return PIERCE_ERR_INVALID_ARG;
    if (pal_random(secret_out, 32) != PIERCE_OK) return PIERCE_ERR_PLATFORM;
    return PIERCE_OK;
}

int pierce_public_key(const uint8_t secret[32], uint8_t public_out[32])
{
    if (!secret || !public_out) return PIERCE_ERR_INVALID_ARG;
    crypto_x25519_public_key(public_out, secret);
    return PIERCE_OK;
}

int pierce_fingerprint(const uint8_t public_key[32], uint8_t out[32])
{
    if (!public_key || !out) return PIERCE_ERR_INVALID_ARG;
    crypto_blake2b(out, 32, public_key, 32);
    return PIERCE_OK;
}

int pc_path_eq(const pc_path *a, const pc_path *b)
{
    if (a->kind != b->kind) return 0;
    if (a->kind == PC_PATH_KIND_DIRECT) return a->local == b->local && pc_addr_eq(&a->remote, &b->remote);
    return a->relay == b->relay && memcmp(a->peer_relay_id, b->peer_relay_id, PC_RELAY_ID_LEN) == 0;
}

/* ===================================================================== */
/* Clock, logging, events                                                */
/* ===================================================================== */

/* Test clock: a process-wide override (so contexts see simulated time from
   the moment they are created) and a per-context one. */
static uint64_t test_global_now;
static int test_global_clock;

uint64_t pc_now(pierce_ctx *ctx)
{
    if (ctx && ctx->manual_clock) return ctx->now_us;
    if (test_global_clock) return test_global_now;
    return pal_now_us();
}

void pierce__test_set_time(pierce_ctx *ctx, uint64_t now_us)
{
    ctx->manual_clock = 1;
    ctx->now_us = now_us;
}

void pierce__test_set_global_time(uint64_t now_us);
void pierce__test_set_global_time(uint64_t now_us)
{
    test_global_clock = 1;
    test_global_now = now_us;
}

pc_event *pc_event_new(pierce_ctx *ctx, uint32_t type)
{
    pc_event *ev = (pc_event *)pc_alloc(&ctx->alloc, sizeof(*ev));
    if (!ev) return NULL;
    ev->type = type;
    ev->timestamp_us = pc_now(ctx);
    return ev;
}

static void evq_push(pc_evq *q, pc_event *ev)
{
    ev->next = NULL;
    if (q->tail) q->tail->next = ev;
    else q->head = ev;
    q->tail = ev;
    q->count++;
}

static pc_event *evq_pop(pc_evq *q)
{
    pc_event *ev = q->head;
    if (!ev) return NULL;
    q->head = ev->next;
    if (!q->head) q->tail = NULL;
    q->count--;
    return ev;
}

static void event_free(pierce_ctx *ctx, pc_event *ev)
{
    if (ev->msg) pc_msg_unref(ev->msg);
    pc_free(&ctx->alloc, ev);
}

void pc_emit_global(pierce_ctx *ctx, pc_event *ev)
{
    ev->conn_id = PIERCE_CONN_NONE;
    evq_push(&ctx->global_q, ev);
}

void pc_emit(pc_conn *c, pc_event *ev)
{
    pierce_ctx *ctx = c->ctx;
    ev->conn_id = c->id;
    ev->user_data = c->user_data;
    evq_push(&c->evq, ev);
    if (!c->in_ready) {
        c->in_ready = 1;
        c->ready_next = NULL;
        if (ctx->ready_tail) ctx->ready_tail->ready_next = c;
        else ctx->ready_head = c;
        ctx->ready_tail = c;
    }
}

void pc_log(pierce_ctx *ctx, uint32_t level, const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    if (level > ctx->log_level || level == PIERCE_LOG_OFF) return;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n >= sizeof(buf)) n = (int)sizeof(buf) - 1;
    pc_event *ev = pc_event_new(ctx, PIERCE_EV_LOG);
    if (!ev) return;
    /* Store a NUL after the text for convenience; data_len excludes it. */
    ev->msg = pc_msg_new(&ctx->alloc, buf, (uint32_t)n + 1);
    if (!ev->msg) {
        pc_free(&ctx->alloc, ev);
        return;
    }
    ev->msg->len = (uint32_t)n;
    ev->flags = level;
    pc_emit_global(ctx, ev);
}

/* ===================================================================== */
/* Datagram output                                                       */
/* ===================================================================== */

void pc_send_direct(pierce_ctx *ctx, const pierce_addr *to, const uint8_t *data, size_t len)
{
    pc_send_from(ctx, 0, to, data, len);
}

void pc_send_from(pierce_ctx *ctx, uint16_t local, const pierce_addr *to, const uint8_t *data, size_t len)
{
    if (local && (!ctx->xsocks || local > PC_MAX_XSOCKS || !ctx->xsocks[local - 1].used)) return;
    if (ctx->flags & PIERCE_CFG_NO_BUILTIN_UDP) {
        pc_event *ev = pc_event_new(ctx, PIERCE_EV_TRANSMIT);
        if (!ev) return;
        ev->msg = pc_msg_new(&ctx->alloc, data, (uint32_t)len);
        if (!ev->msg) {
            pc_free(&ctx->alloc, ev);
            return;
        }
        ev->addr = *to;
        ev->channel = local;   /* which local endpoint to send from */
        pc_emit_global(ctx, ev);
        return;
    }
    if (local) {
        if (to->family == PIERCE_AF_INET) pal_udp_send(ctx->xsocks[local - 1].sock, to, data, len);
        return;
    }
    pal_sock s = to->family == PIERCE_AF_INET6 ? ctx->sock6 : ctx->sock4;
    if (s == PAL_INVALID_SOCK) return;
    pal_udp_send(s, to, data, len);   /* datagram semantics: failures look like loss */
}

void pc_send_path(pierce_ctx *ctx, const pc_path *path, const uint8_t *data, size_t len)
{
    if (path->kind == PC_PATH_KIND_RELAY) pc_relay_send(ctx, path->relay, path->peer_relay_id, data, len);
    else pc_send_from(ctx, path->local, &path->remote, data, len);
}

/* ---- extra sockets ---- */

uint16_t pc_xsock_open(pierce_ctx *ctx, pc_conn *owner)
{
    if (!ctx->xsocks) {
        ctx->xsocks = (pc_xsock *)pc_alloc(&ctx->alloc, PC_MAX_XSOCKS * sizeof(pc_xsock));
        if (!ctx->xsocks) return 0;
    }
    if (ctx->flags & PIERCE_CFG_NO_IPV4) return 0;
    for (uint32_t i = 0; i < PC_MAX_XSOCKS; i++) {
        pc_xsock *x = &ctx->xsocks[i];
        if (x->used) continue;
        x->sock = PAL_INVALID_SOCK;
        if (!(ctx->flags & PIERCE_CFG_NO_BUILTIN_UDP) && pal_udp_open(PIERCE_AF_INET, 0, &x->sock) != PIERCE_OK)
            return 0;   /* out of descriptors: work with what we have */
        x->used = 1;
        x->owner = owner;
        ctx->nxsocks_used++;
        return (uint16_t)(i + 1);
    }
    return 0;
}

void pc_xsock_close(pierce_ctx *ctx, uint16_t local)
{
    if (!ctx->xsocks || local == 0 || local > PC_MAX_XSOCKS) return;
    pc_xsock *x = &ctx->xsocks[local - 1];
    if (!x->used) return;
    pal_sock_close(x->sock);
    x->sock = PAL_INVALID_SOCK;
    x->used = 0;
    x->owner = NULL;
    ctx->nxsocks_used--;
}

void pc_xsock_release(pierce_ctx *ctx, pc_conn *owner, uint16_t keep)
{
    if (!ctx->xsocks) return;
    for (uint32_t i = 0; i < PC_MAX_XSOCKS; i++)
        if (ctx->xsocks[i].used && ctx->xsocks[i].owner == owner && i + 1 != keep)
            pc_xsock_close(ctx, (uint16_t)(i + 1));
}

/* ===================================================================== */
/* Connection table                                                      */
/* ===================================================================== */

static pc_slot *slot_of(pierce_ctx *ctx, pierce_conn_id id, uint32_t *gen_out)
{
    uint32_t idx = (uint32_t)(id & 0xffffffffu), gen = (uint32_t)(id >> 32);
    if (!ctx || idx >= ctx->nslots || gen == 0 || gen > PC_GEN_MAX || (id >> 53)) return NULL;
    if (gen_out) *gen_out = gen;
    return &ctx->slots[idx];
}

pc_conn *pc_conn_lookup(pierce_ctx *ctx, pierce_conn_id id)
{
    uint32_t gen;
    pc_slot *s = slot_of(ctx, id, &gen);
    if (!s || !s->conn || s->last_gen != gen) return NULL;
    return s->conn;
}

pc_conn *pc_conn_by_cid(pierce_ctx *ctx, const uint8_t cid[PC_CID_LEN])
{
    uint32_t idx = pc_get32(cid);
    if (idx >= ctx->nslots) return NULL;
    pc_conn *c = ctx->slots[idx].conn;
    if (!c || memcmp(c->local_cid, cid, PC_CID_LEN) != 0) return NULL;
    return c;
}

pc_conn *pc_conn_by_session(pierce_ctx *ctx, const uint8_t session[PC_SESSION_LEN])
{
    for (pc_conn *c = ctx->conns; c; c = c->next)
        if (c->has_session && memcmp(c->session, session, PC_SESSION_LEN) == 0) return c;
    return NULL;
}

pc_conn *pc_conn_by_remote_cid(pierce_ctx *ctx, const uint8_t cid[PC_CID_LEN], const pc_path *path)
{
    for (pc_conn *c = ctx->conns; c; c = c->next)
        if (!c->initiator && c->has_remote_cid && memcmp(c->remote_cid, cid, PC_CID_LEN) == 0 &&
            c->has_path && pc_path_eq(&c->path, path))
            return c;
    return NULL;
}

static int validate_opts(const pierce_conn_options *opt)
{
    if (!opt) return PIERCE_OK;
    if (opt->struct_size < OPT_V1_MIN) return PIERCE_ERR_VERSION;
    if (opt->channel_count && !opt->channels) return PIERCE_ERR_INVALID_ARG;
    int rc = pc_tr_validate_channels(opt->channels, opt->channel_count);
    if (rc) return rc;
    if (HAS_FIELD(opt, pierce_conn_options, handshake_payload_len)) {
        if (opt->handshake_payload_len > PC_MAX_HS_PAYLOAD) return PIERCE_ERR_INVALID_ARG;
        if (opt->handshake_payload_len && !opt->handshake_payload) return PIERCE_ERR_INVALID_ARG;
    }
    return PIERCE_OK;
}

pc_conn *pc_conn_alloc(pierce_ctx *ctx, int initiator, const pierce_conn_options *opt)
{
    uint32_t idx, gen;
    for (;;) {
        if (ctx->free_head == UINT32_MAX) return NULL;
        idx = ctx->free_head;
        ctx->free_head = ctx->slots[idx].next_free;
        if (ctx->slots[idx].last_gen < PC_GEN_MAX) break;
        ctx->slots[idx].retired = 1;   /* generations exhausted: never reuse */
    }
    pc_slot *s = &ctx->slots[idx];
    pc_conn *c = (pc_conn *)pc_alloc(&ctx->alloc, sizeof(pc_conn));
    if (!c) {
        s->next_free = ctx->free_head;
        ctx->free_head = idx;
        return NULL;
    }
    gen = s->last_gen + 1;
    s->last_gen = gen;
    uint64_t now = pc_now(ctx);
    c->ctx = ctx;
    c->slot = idx;
    c->id = ((uint64_t)gen << 32) | idx;
    c->initiator = (uint8_t)initiator;
    c->created_us = now;
    c->last_rx_us = now;
    pc_put32(c->local_cid, idx);
    pc_random(c->local_cid + 4, PC_CID_LEN - 4);
    pc_tr_init_recovery(c, 0);
    if (opt) {
        c->user_data = opt->user_data;
        if (initiator || ctx->listen_has_table) pc_tr_setup_channels(c, opt->channels, opt->channel_count);
        if (initiator && HAS_FIELD(opt, pierce_conn_options, handshake_payload_len) &&
            opt->handshake_payload_len) {
            c->hs_payload = (uint8_t *)pc_alloc(&ctx->alloc, opt->handshake_payload_len);
            if (!c->hs_payload) {
                pc_free(&ctx->alloc, c);
                s->next_free = ctx->free_head;
                ctx->free_head = idx;
                return NULL;
            }
            memcpy(c->hs_payload, opt->handshake_payload, opt->handshake_payload_len);
            c->hs_payload_len = opt->handshake_payload_len;
        }
    } else if (initiator) {
        pc_tr_setup_channels(c, NULL, 0);
    }
    if (!initiator && !ctx->listen_has_table) c->ch_agreed = 0;

    pal_mutex_lock(&s->lock);
    s->open = 1;
    s->blocked = 0;
    s->queued_bytes = 0;
    s->limit = ctx->sendbuf;
    s->ch_known = 0;
    s->q_head = s->q_tail = NULL;
    pal_atomic_store(&s->q_count, 0);
    pal_mutex_unlock(&s->lock);
    pal_atomic_store(&s->gen, gen);
    s->conn = c;
    if (c->ch_agreed) pc_slot_set_channels(c);

    c->next = ctx->conns;
    ctx->conns = c;
    ctx->nconns++;
    return c;
}

void pc_slot_set_channels(pc_conn *c)
{
    pc_slot *s = &c->ctx->slots[c->slot];
    pal_mutex_lock(&s->lock);
    s->nch = c->nch;
    for (uint32_t i = 0; i < c->nch; i++) {
        s->ch_ids[i] = c->ch[i].cfg.id;
        s->ch_max[i] = c->ch[i].cfg.max_message_size;
    }
    s->ch_known = 1;
    pal_mutex_unlock(&s->lock);
}

void pc_slot_close(pc_conn *c)
{
    pc_slot *s = &c->ctx->slots[c->slot];
    pc_sendreq *q;
    pal_mutex_lock(&s->lock);
    s->open = 0;
    q = s->q_head;
    s->q_head = s->q_tail = NULL;
    s->queued_bytes = 0;
    pal_atomic_store(&s->q_count, 0);
    pal_mutex_unlock(&s->lock);
    while (q) {
        pc_sendreq *n = q->next;
        pc_msg_unref(q->msg);
        pc_free(&c->ctx->alloc, q);
        q = n;
    }
}

void pc_conn_schedule_free(pc_conn *c)
{
    pierce_ctx *ctx = c->ctx;
    for (uint32_t i = 0; i < ctx->nto_free; i++)
        if (ctx->to_free[i] == c) return;
    if (ctx->nto_free == ctx->capto_free) {
        uint32_t nc = ctx->capto_free ? ctx->capto_free * 2 : 16;
        pc_conn **n = (pc_conn **)pc_realloc(&ctx->alloc, ctx->to_free,
                                            ctx->capto_free * sizeof(pc_conn *), nc * sizeof(pc_conn *));
        if (!n) return;   /* leaks the conn until ctx destroy, which frees every conn */
        ctx->to_free = n;
        ctx->capto_free = nc;
    }
    ctx->to_free[ctx->nto_free++] = c;
}

static void conn_free(pierce_ctx *ctx, pc_conn *c)
{
    pc_slot *s = &ctx->slots[c->slot];
    pc_conn **link = &ctx->conns;
    while (*link && *link != c) link = &(*link)->next;
    if (*link) {
        *link = c->next;
        ctx->nconns--;
    }
    if (c->in_ready) {
        pc_conn **r = &ctx->ready_head, *prev = NULL;
        while (*r && *r != c) {
            prev = *r;
            r = &(*r)->ready_next;
        }
        if (*r) {
            *r = c->ready_next;
            if (ctx->ready_tail == c) ctx->ready_tail = prev;
        }
    }
    pc_event *ev;
    while ((ev = evq_pop(&c->evq))) event_free(ctx, ev);
    if (c->state != PC_ST_CLOSED) {
        pc_slot_close(c);
        pc_tr_free(c);
    }
    if (c->peer_payload) pc_msg_unref(c->peer_payload);
    pc_free(&ctx->alloc, c->hs_payload);
    pc_free(&ctx->alloc, c->pairs);
    pc_xsock_release(ctx, c, 0);
    pc_noise_wipe(&c->hs);

    /* Spec 7.1: bump (here: clear) the generation under the slot lock, then
       recycle the slot. A racing pierce_send either queued before this
       (and was discarded by pc_slot_close) or sees the mismatch. */
    pal_mutex_lock(&s->lock);
    pal_atomic_store(&s->gen, 0);
    s->open = 0;
    pal_mutex_unlock(&s->lock);
    s->conn = NULL;
    if (s->last_gen >= PC_GEN_MAX) {
        s->retired = 1;
    } else {
        s->next_free = ctx->free_head;
        ctx->free_head = c->slot;
    }
    pc_free(&ctx->alloc, c);
}

static void process_frees(pierce_ctx *ctx)
{
    for (uint32_t i = 0; i < ctx->nto_free; i++) conn_free(ctx, ctx->to_free[i]);
    ctx->nto_free = 0;
}

/* ===================================================================== */
/* Context                                                               */
/* ===================================================================== */

static int open_sockets(pierce_ctx *ctx, uint16_t port)
{
    int want4 = !(ctx->flags & PIERCE_CFG_NO_IPV4), want6 = !(ctx->flags & PIERCE_CFG_NO_IPV6);
    pierce_addr la;
    if (want4 && pal_udp_open(PIERCE_AF_INET, port, &ctx->sock4) == PIERCE_OK) {
        if (pal_sock_local_addr(ctx->sock4, &la) == PIERCE_OK) ctx->port4 = la.port;
    }
    if (want6) {
        uint16_t p6 = port ? port : ctx->port4;   /* same port on both families when possible */
        if (pal_udp_open(PIERCE_AF_INET6, p6, &ctx->sock6) != PIERCE_OK && p6 && !port)
            pal_udp_open(PIERCE_AF_INET6, 0, &ctx->sock6);
        if (ctx->sock6 != PAL_INVALID_SOCK && pal_sock_local_addr(ctx->sock6, &la) == PIERCE_OK)
            ctx->port6 = la.port;
    }
    if (ctx->sock4 == PAL_INVALID_SOCK && ctx->sock6 == PAL_INVALID_SOCK) return PIERCE_ERR_PLATFORM;
    return PIERCE_OK;
}

int pierce_ctx_create(const pierce_config *cfg, pierce_ctx **out)
{
    pc_allocator a;
    if (!cfg || !out) return PIERCE_ERR_INVALID_ARG;
    *out = NULL;
    if (cfg->struct_size < CFG_V1_MIN) return PIERCE_ERR_VERSION;
    if ((cfg->flags & PIERCE_CFG_NO_IPV4) && (cfg->flags & PIERCE_CFG_NO_IPV6)) return PIERCE_ERR_INVALID_ARG;
    if (cfg->flags & ~0xffu) return PIERCE_ERR_INVALID_ARG;
    if (pal_init() != PIERCE_OK) return PIERCE_ERR_PLATFORM;

    pc_allocator_init(&a, cfg->allocator);
    pierce_ctx *ctx = (pierce_ctx *)pc_alloc(&a, sizeof(pierce_ctx));
    if (!ctx) {
        pal_shutdown();
        return PIERCE_ERR_NO_MEMORY;
    }
    ctx->alloc = a;
    ctx->flags = cfg->flags;
    ctx->sock4 = ctx->sock6 = PAL_INVALID_SOCK;
    ctx->wake.rd = ctx->wake.wr = PAL_INVALID_SOCK;
    ctx->free_head = UINT32_MAX;

    if (cfg->identity_secret_key) memcpy(ctx->sk, cfg->identity_secret_key, 32);
    else if (pal_random(ctx->sk, 32) != PIERCE_OK) goto fail_platform;
    crypto_x25519_public_key(ctx->pk, ctx->sk);
    pc_random(ctx->cookie_secret, 32);

    ctx->keepalive_us = (uint64_t)(cfg->keepalive_interval_ms ? cfg->keepalive_interval_ms : PC_DEFAULT_KEEPALIVE_MS) * 1000;
    ctx->idle_us = PC_DEFAULT_IDLE_MS * 1000ull;
    ctx->connect_us = PC_DEFAULT_CONNECT_MS * 1000ull;
    ctx->sendbuf = PC_DEFAULT_SENDBUF;
    ctx->recvbuf = PC_DEFAULT_RECVBUF;
    uint16_t port = 0;
    if (HAS_FIELD(cfg, pierce_config, bind_port)) {
        if (cfg->bind_port > 65535) goto fail_arg;
        port = (uint16_t)cfg->bind_port;
    }
    if (HAS_FIELD(cfg, pierce_config, idle_timeout_ms) && cfg->idle_timeout_ms)
        ctx->idle_us = cfg->idle_timeout_ms * 1000ull;
    if (HAS_FIELD(cfg, pierce_config, connect_timeout_ms) && cfg->connect_timeout_ms)
        ctx->connect_us = cfg->connect_timeout_ms * 1000ull;
    if (HAS_FIELD(cfg, pierce_config, send_buffer_bytes) && cfg->send_buffer_bytes)
        ctx->sendbuf = cfg->send_buffer_bytes;
    if (HAS_FIELD(cfg, pierce_config, recv_buffer_bytes) && cfg->recv_buffer_bytes)
        ctx->recvbuf = cfg->recv_buffer_bytes;
    if (HAS_FIELD(cfg, pierce_config, log_level)) ctx->log_level = cfg->log_level;
    if (ctx->keepalive_us >= ctx->idle_us) ctx->keepalive_us = ctx->idle_us / 2;

    ctx->nslots = cfg->max_connections ? cfg->max_connections : PC_DEFAULT_MAX_CONNS;
    if (ctx->nslots > (1u << 24)) goto fail_arg;
    ctx->slots = (pc_slot *)pc_alloc(&a, ctx->nslots * sizeof(pc_slot));
    if (!ctx->slots) goto fail_mem;
    for (uint32_t i = ctx->nslots; i-- > 0;) {
        if (pal_mutex_init(&ctx->slots[i].lock) != PIERCE_OK) {
            for (uint32_t j = i + 1; j < ctx->nslots; j++) pal_mutex_destroy(&ctx->slots[j].lock);
            pc_free(&a, ctx->slots);
            ctx->slots = NULL;
            goto fail_platform;
        }
        ctx->slots[i].next_free = ctx->free_head;
        ctx->free_head = i;
    }

    if (pal_wake_open(&ctx->wake) != PIERCE_OK) goto fail_platform;
    if (!(ctx->flags & PIERCE_CFG_NO_BUILTIN_UDP) && open_sockets(ctx, port) != PIERCE_OK) {
        pc_log(ctx, PIERCE_LOG_ERROR, "cannot open UDP sockets");
        goto fail_platform;
    }
    int rc = pc_gather_init(ctx, cfg);
    if (rc != PIERCE_OK) {
        pierce_ctx_destroy(ctx);
        return rc;
    }
    *out = ctx;
    return PIERCE_OK;

fail_arg:
    pierce_ctx_destroy(ctx);
    return PIERCE_ERR_INVALID_ARG;
fail_mem:
    pierce_ctx_destroy(ctx);
    return PIERCE_ERR_NO_MEMORY;
fail_platform:
    pierce_ctx_destroy(ctx);
    return PIERCE_ERR_PLATFORM;
}

static void release_lent(pierce_ctx *ctx)
{
    for (uint32_t i = 0; i < ctx->nlent; i++) pc_msg_unref(ctx->lent[i]);
    ctx->nlent = 0;
}

void pierce_ctx_destroy(pierce_ctx *ctx)
{
    if (!ctx) return;
    pc_allocator a = ctx->alloc;
    /* Best-effort goodbyes so peers don't wait for their idle timeout. */
    for (pc_conn *c = ctx->conns; c; c = c->next) {
        if (c->state == PC_ST_CLOSED) continue;
        c->close_reason = PIERCE_REASON_SHUTDOWN;
        c->close_rejected = 0;
        pc_tr_send_close(c);
    }
    pc_gather_destroy_notify(ctx);
    pc_portmap_free(ctx);
    while (ctx->conns) conn_free(ctx, ctx->conns);
    pc_event *ev;
    while ((ev = evq_pop(&ctx->global_q))) event_free(ctx, ev);
    release_lent(ctx);
    pc_free(&a, ctx->lent);
    pc_free(&a, ctx->lent_keys);
    pc_free(&a, ctx->to_free);
    if (ctx->slots) {
        for (uint32_t i = 0; i < ctx->nslots; i++) pal_mutex_destroy(&ctx->slots[i].lock);
        pc_free(&a, ctx->slots);
    }
    pc_gather_free(ctx);
    if (ctx->xsocks) {
        for (uint32_t i = 0; i < PC_MAX_XSOCKS; i++) pc_xsock_close(ctx, (uint16_t)(i + 1));
        pc_free(&a, ctx->xsocks);
    }
    pal_sock_close(ctx->sock4);
    pal_sock_close(ctx->sock6);
    pal_wake_close(&ctx->wake);
    pc_wipe(ctx->sk, 32);
    pc_wipe(ctx->cookie_secret, 32);
    pc_free(&a, ctx);
    pal_shutdown();
}

int pierce_ctx_public_key(pierce_ctx *ctx, uint8_t out[32])
{
    if (!ctx || !out) return PIERCE_ERR_INVALID_ARG;
    memcpy(out, ctx->pk, 32);
    return PIERCE_OK;
}

int pierce_add_local_address(pierce_ctx *ctx, const pierce_addr *addr)
{
    if (!ctx || !addr) return PIERCE_ERR_INVALID_ARG;
    if (addr->family != PIERCE_AF_INET && addr->family != PIERCE_AF_INET6) return PIERCE_ERR_INVALID_ARG;
    for (uint32_t i = 0; i < ctx->nlocal_addrs; i++)
        if (pc_addr_eq(&ctx->local_addrs[i], addr)) return PIERCE_OK;
    if (ctx->nlocal_addrs >= PC_MAX_LOCAL_ADDRS) return PIERCE_ERR_NO_MEMORY;
    pierce_addr a = *addr;
    /* Port 0 means "the port this context is bound to". */
    if (!a.port) a.port = a.family == PIERCE_AF_INET ? ctx->port4 : ctx->port6;
    ctx->local_addrs[ctx->nlocal_addrs++] = a;
    pc_gather_cands_rebuild(ctx);
    return PIERCE_OK;
}

int pierce_set_relay_token(pierce_ctx *ctx, uint32_t index, const uint8_t *token, uint32_t len)
{
    if (!ctx) return PIERCE_ERR_INVALID_ARG;
    return pc_gather_set_token(ctx, index, token, len);
}

/* ===================================================================== */
/* Connections                                                           */
/* ===================================================================== */

int pierce_connect(pierce_ctx *ctx, const pierce_conn_options *opt, const uint8_t *invite,
                   uint32_t invite_len, pierce_conn_id *out)
{
    pc_invite inv;
    int rc;
    if (!ctx || !out) return PIERCE_ERR_INVALID_ARG;
    *out = PIERCE_CONN_NONE;
    if ((rc = validate_opts(opt))) return rc;
    if (invite && invite_len) {
        if ((rc = pc_invite_decode(invite, invite_len, &inv))) return rc;
    }
    pc_conn *c = pc_conn_alloc(ctx, 1, opt);
    if (!c) return PIERCE_ERR_NO_MEMORY;
    c->app_visible = 1;
    rc = pc_conn_start_initiator(c, &inv, invite && invite_len);
    if (rc) {
        conn_free(ctx, c);
        return rc;
    }
    *out = c->id;
    return PIERCE_OK;
}

int pierce_listen(pierce_ctx *ctx, const pierce_conn_options *opt)
{
    int rc;
    if (!ctx) return PIERCE_ERR_INVALID_ARG;
    if ((rc = validate_opts(opt))) return rc;
    pierce_conn_options_init(&ctx->listen_opt);
    ctx->listen_has_table = 0;
    if (opt) {
        ctx->listen_opt.user_data = opt->user_data;
        if (opt->channel_count) {
            memcpy(ctx->listen_ch, opt->channels, opt->channel_count * sizeof(pierce_channel_config));
            ctx->listen_opt.channels = ctx->listen_ch;
            ctx->listen_opt.channel_count = opt->channel_count;
            ctx->listen_has_table = 1;
        }
    }
    ctx->listening = 1;
    return PIERCE_OK;
}

int pierce_accept(pierce_ctx *ctx, pierce_conn_id id, uint64_t user_data)
{
    pc_conn *c = pc_conn_lookup(ctx, id);
    if (!c) return PIERCE_ERR_NO_SUCH_CONN;
    return pc_conn_app_accept(c, user_data);
}

int pierce_reject(pierce_ctx *ctx, pierce_conn_id id, uint32_t reason)
{
    pc_conn *c = pc_conn_lookup(ctx, id);
    if (!c) return PIERCE_ERR_NO_SUCH_CONN;
    return pc_conn_app_reject(c, reason);
}

int pierce_close(pierce_ctx *ctx, pierce_conn_id id, uint32_t reason)
{
    pc_conn *c = pc_conn_lookup(ctx, id);
    if (!c) return PIERCE_ERR_NO_SUCH_CONN;
    if (c->state == PC_ST_CLOSED) return PIERCE_ERR_CLOSED;
    pc_conn_close(c, reason, 0, PIERCE_OK);
    return PIERCE_OK;
}

int pierce_conn_channels(pierce_ctx *ctx, pierce_conn_id id, pierce_channel_config *out, uint32_t cap)
{
    pc_conn *c = pc_conn_lookup(ctx, id);
    if (!c) return PIERCE_ERR_NO_SUCH_CONN;
    if (!c->ch_agreed) return 0;
    for (uint32_t i = 0; i < c->nch && i < cap && out; i++) out[i] = c->ch[i].cfg;
    return (int)c->nch;
}

int pierce_conn_info_get(pierce_ctx *ctx, pierce_conn_id id, pierce_conn_info *out)
{
    pc_conn *c = pc_conn_lookup(ctx, id);
    if (!c) return PIERCE_ERR_NO_SUCH_CONN;
    if (!out || out->struct_size < sizeof(pierce_conn_info)) return PIERCE_ERR_VERSION;
    memset(out, 0, sizeof(*out));
    out->struct_size = sizeof(*out);
    if (c->has_path) {
        out->path = c->path.kind == PC_PATH_KIND_RELAY ? PIERCE_PATH_RELAY : PIERCE_PATH_DIRECT;
        if (c->path.kind == PC_PATH_KIND_DIRECT) out->remote = c->path.remote;
        else if (c->path.relay < ctx->nrelays) out->remote = ctx->relays[c->path.relay]->addr;
    }
    if (c->has_peer_key) memcpy(out->peer_key, c->peer_key, 32);
    out->rtt_us = c->srtt;
    out->cwnd_bytes = c->cc.cwnd;
    out->bytes_in_flight = c->bytes_in_flight;
    out->packets_sent = c->packets_sent;
    out->packets_lost = c->packets_lost;
    out->packets_received = c->packets_received;
    pc_slot *s = &ctx->slots[c->slot];
    pal_mutex_lock(&s->lock);
    out->send_queue_bytes = (uint32_t)PC_MIN(s->queued_bytes, (uint64_t)UINT32_MAX);
    pal_mutex_unlock(&s->lock);
    return PIERCE_OK;
}

int pierce_get_invite(pierce_ctx *ctx, uint8_t *buf, uint32_t cap)
{
    pc_invite inv;
    if (!ctx || !buf) return PIERCE_ERR_INVALID_ARG;
    memset(&inv, 0, sizeof(inv));
    memcpy(inv.key, ctx->pk, 32);
    for (uint32_t i = 0; i < ctx->nlocal_addrs && inv.naddr < PC_MAX_INVITE_ADDRS; i++)
        inv.addrs[inv.naddr++] = ctx->local_addrs[i];
    return pc_invite_encode(&inv, buf, cap);
}

int pierce_signal_in(pierce_ctx *ctx, const uint8_t *data, uint32_t len, pierce_conn_id *out_id)
{
    pc_signal s;
    pc_conn *c;
    if (out_id) *out_id = PIERCE_CONN_NONE;
    if (!ctx || !data) return PIERCE_ERR_INVALID_ARG;
    if (pc_blob_is_invite(data, len)) return PIERCE_ERR_INVALID_ARG;   /* invites go to pierce_connect */
    int rc = pc_signal_decode(data, len, &s);
    if (rc) return rc;
    rc = pc_conn_signal_in(ctx, &s, &c);
    if (rc) return rc;
    if (out_id && c) *out_id = c->id;
    return PIERCE_OK;
}

/* ===================================================================== */
/* Sending (thread-safe)                                                 */
/* ===================================================================== */

static void wake_poller(pierce_ctx *ctx)
{
    if (pal_atomic_exchange(&ctx->wake_pending, 1) == 0) pal_wake_signal(&ctx->wake);
}

/* Queue one reference of m on a connection. Takes a ref on success. */
static int queue_send(pierce_ctx *ctx, pierce_conn_id id, uint32_t channel, pc_msg *m)
{
    uint32_t gen;
    pc_slot *s = slot_of(ctx, id, &gen);
    if (!s) return PIERCE_ERR_NO_SUCH_CONN;
    pc_sendreq *rq = (pc_sendreq *)pc_alloc(&ctx->alloc, sizeof(*rq));
    if (!rq) return PIERCE_ERR_NO_MEMORY;
    int rc = PIERCE_OK;
    pal_mutex_lock(&s->lock);
    if (pal_atomic_load(&s->gen) != gen) {
        rc = PIERCE_ERR_NO_SUCH_CONN;
    } else if (!s->open) {
        rc = PIERCE_ERR_CLOSED;
    } else {
        if (s->ch_known) {
            uint32_t i;
            for (i = 0; i < s->nch && s->ch_ids[i] != channel; i++) {
            }
            if (i == s->nch || m->len > s->ch_max[i]) rc = PIERCE_ERR_INVALID_ARG;
        }
        if (rc == PIERCE_OK && s->queued_bytes && s->queued_bytes + m->len > s->limit) {
            s->blocked = 1;
            rc = PIERCE_ERR_WOULD_BLOCK;
        }
        if (rc == PIERCE_OK) {
            pc_msg_ref(m);
            rq->msg = m;
            rq->channel = channel;
            if (s->q_tail) s->q_tail->next = rq;
            else s->q_head = rq;
            s->q_tail = rq;
            s->queued_bytes += m->len;
            pal_atomic_add(&s->q_count, 1);
        }
    }
    pal_mutex_unlock(&s->lock);
    if (rc != PIERCE_OK) pc_free(&ctx->alloc, rq);
    return rc;
}

int pierce_send(pierce_ctx *ctx, pierce_conn_id id, uint32_t channel, const uint8_t *data,
                uint32_t len, uint32_t flags)
{
    if (!ctx || (len && !data) || flags) return PIERCE_ERR_INVALID_ARG;
    pc_msg *m = pc_msg_new(&ctx->alloc, data, len);
    if (!m) return PIERCE_ERR_NO_MEMORY;
    int rc = queue_send(ctx, id, channel, m);
    pc_msg_unref(m);
    if (rc == PIERCE_OK) wake_poller(ctx);
    return rc;
}

int pierce_send_many(pierce_ctx *ctx, const pierce_conn_id *ids, uint32_t n, uint32_t channel,
                     const uint8_t *data, uint32_t len, uint32_t flags)
{
    if (!ctx || (n && !ids) || (len && !data) || flags) return PIERCE_ERR_INVALID_ARG;
    pc_msg *m = pc_msg_new(&ctx->alloc, data, len);
    if (!m) return PIERCE_ERR_NO_MEMORY;
    int queued = 0;
    for (uint32_t i = 0; i < n; i++)
        if (queue_send(ctx, ids[i], channel, m) == PIERCE_OK) queued++;
    pc_msg_unref(m);
    if (queued) wake_poller(ctx);
    return queued;
}

/* Move cross-thread sends into transport queues and settle accounting. */
static void drain_sendqs(pierce_ctx *ctx)
{
    for (pc_conn *c = ctx->conns; c; c = c->next) {
        if (c->state == PC_ST_CLOSED) continue;
        pc_slot *s = &ctx->slots[c->slot];
        pc_sendreq *q = NULL;
        int low = 0;
        /* A push that lands after this check is followed by a wake, so the
           next loop pass picks it up. */
        if (!c->release_bytes && !pal_atomic_load(&s->q_count)) continue;
        pal_mutex_lock(&s->lock);
        if (c->release_bytes) {
            s->queued_bytes = c->release_bytes > s->queued_bytes ? 0 : s->queued_bytes - c->release_bytes;
            c->release_bytes = 0;
            if (s->blocked && s->queued_bytes <= s->limit / 2) {
                s->blocked = 0;
                low = 1;
            }
        }
        if (c->ch_agreed) {
            q = s->q_head;
            s->q_head = s->q_tail = NULL;
            pal_atomic_store(&s->q_count, 0);
        }
        pal_mutex_unlock(&s->lock);
        while (q) {
            pc_sendreq *n = q->next;
            pc_tr_enqueue(c, q->channel, q->msg);   /* takes the msg reference */
            pc_free(&ctx->alloc, q);
            q = n;
        }
        if (low) {
            pc_event *ev = pc_event_new(ctx, PIERCE_EV_SEND_BUFFER_LOW);
            if (ev) pc_emit(c, ev);
        }
    }
}

/* ===================================================================== */
/* Input                                                                 */
/* ===================================================================== */

void pc_input_packet(pierce_ctx *ctx, const pc_path *path, uint8_t *data, size_t len)
{
    if (len == 0) return;
    switch (data[0]) {
    case PC_PKT_PROBE:
    case PC_PKT_PROBE_ACK:
        pc_conn_input_probe(ctx, path, data, len);
        break;
    case PC_PKT_HS_INIT:
    case PC_PKT_HS_RETRY:
    case PC_PKT_HS_RESP:
    case PC_PKT_HS_FINAL:
        pc_conn_input_handshake(ctx, path, data, len);
        break;
    case PC_PKT_DATA:
        pc_tr_input(ctx, path, data, len);
        break;
    default:
        break;
    }
}

static void input_datagram(pierce_ctx *ctx, uint16_t local, const pierce_addr *src, uint8_t *data, size_t len)
{
    uint32_t relay;
    const uint8_t *payload;
    size_t plen;
    uint8_t peer_id[PC_RELAY_ID_LEN];
    pc_path path;
    if (len == 0 || len > PC_MTU + 32) return;
    /* Extra sockets only ever carry peer traffic. */
    int r = local ? 0 : pc_gather_input(ctx, src, data, len, &relay, &payload, &plen, peer_id);
    if (r == 1) return;
    memset(&path, 0, sizeof(path));
    if (r == 2) {
        path.kind = PC_PATH_KIND_RELAY;
        path.relay = relay;
        memcpy(path.peer_relay_id, peer_id, PC_RELAY_ID_LEN);
        pc_input_packet(ctx, &path, (uint8_t *)payload, plen);
        return;
    }
    path.kind = PC_PATH_KIND_DIRECT;
    path.local = local;
    path.remote = *src;
    pc_input_packet(ctx, &path, data, len);
}

int pierce_transport_in_ex(pierce_ctx *ctx, uint32_t local, const pierce_addr *src, const uint8_t *data,
                           uint32_t len)
{
    if (!ctx || !src || (len && !data)) return PIERCE_ERR_INVALID_ARG;
    if (len > sizeof(ctx->rxbuf) || local > PC_MAX_XSOCKS) return PIERCE_ERR_INVALID_ARG;
    if (local && (!ctx->xsocks || !ctx->xsocks[local - 1].used)) return PIERCE_OK;   /* closed: drop */
    memcpy(ctx->rxbuf, data, len);
    input_datagram(ctx, (uint16_t)local, src, ctx->rxbuf, len);
    return PIERCE_OK;
}

int pierce_transport_in(pierce_ctx *ctx, const pierce_addr *src, const uint8_t *data, uint32_t len)
{
    return pierce_transport_in_ex(ctx, 0, src, data, len);
}

static void io_receive(pierce_ctx *ctx)
{
    pal_sock socks[2] = {ctx->sock4, ctx->sock6};
    for (int k = 0; k < 2; k++) {
        if (socks[k] == PAL_INVALID_SOCK) continue;
        for (int i = 0; i < IO_BATCH; i++) {
            pierce_addr from;
            int n = pal_udp_recv(socks[k], ctx->rxbuf, sizeof(ctx->rxbuf), &from);
            if (n < 0) break;
            input_datagram(ctx, 0, &from, ctx->rxbuf, (size_t)n);
        }
    }
    for (uint32_t i = 0; ctx->nxsocks_used && i < PC_MAX_XSOCKS; i++) {
        if (!ctx->xsocks[i].used || ctx->xsocks[i].sock == PAL_INVALID_SOCK) continue;
        for (int k = 0; k < 16; k++) {
            pierce_addr from;
            int n = pal_udp_recv(ctx->xsocks[i].sock, ctx->rxbuf, sizeof(ctx->rxbuf), &from);
            if (n < 0) break;
            input_datagram(ctx, (uint16_t)(i + 1), &from, ctx->rxbuf, (size_t)n);
            if (!ctx->xsocks[i].used) break;   /* closed while handling */
        }
    }
    for (uint32_t i = 0; i < ctx->nrelays; i++)
        if (ctx->relays[i]->tcp && ctx->relays[i]->sock != PAL_INVALID_SOCK)
            pc_relay_tcp_io(ctx, i, 1, 1, 0);
    pc_portmap_io(ctx);
}

/* ===================================================================== */
/* Poll                                                                  */
/* ===================================================================== */

static uint64_t next_timer(pierce_ctx *ctx)
{
    if (ctx->suspended) return 0;
    uint64_t t = pc_gather_next(ctx);
    for (pc_conn *c = ctx->conns; c; c = c->next) {
        uint64_t v = pc_conn_next_timer(c);
        if (v && (!t || v < t)) t = v;
    }
    return t;
}

static void run_timers(pierce_ctx *ctx, uint64_t now)
{
    uint64_t dummy = 0;
    if (ctx->suspended) return;
    pc_gather_timers(ctx, now, &dummy);
    for (pc_conn *c = ctx->conns; c;) {
        pc_conn *n = c->next;
        uint64_t t = pc_conn_next_timer(c);
        if (t && t <= now) pc_conn_timers(c, now);
        c = n;
    }
}

static void flush_all(pierce_ctx *ctx, uint64_t now)
{
    for (pc_conn *c = ctx->conns; c; c = c->next) pc_tr_flush(c, now);
}

static int events_pending(pierce_ctx *ctx)
{
    if (ctx->global_q.count) return 1;
    for (pc_conn *c = ctx->ready_head; c; c = c->ready_next)
        if (c->evq.count) return 1;
    return 0;
}

static int ensure_lent(pierce_ctx *ctx, uint32_t max)
{
    if (ctx->caplent < max) {
        pc_msg **n = (pc_msg **)pc_realloc(&ctx->alloc, ctx->lent, ctx->caplent * sizeof(pc_msg *),
                                           max * sizeof(pc_msg *));
        if (!n) return -1;
        ctx->lent = n;
        ctx->caplent = max;
    }
    if (ctx->caplent_keys < max) {
        uint8_t(*k)[32] = (uint8_t(*)[32])pc_realloc(&ctx->alloc, ctx->lent_keys,
                                                     ctx->caplent_keys * 32, (size_t)max * 32);
        if (!k) return -1;
        ctx->lent_keys = k;
        ctx->caplent_keys = max;
    }
    return 0;
}

static void fill_event(pierce_ctx *ctx, pc_event *ev, pierce_event *o, uint32_t i)
{
    memset(o, 0, sizeof(*o));
    o->struct_size = sizeof(*o);
    o->type = ev->type;
    o->conn_id = ev->conn_id;
    o->user_data = ev->user_data;
    o->channel = ev->channel;
    o->flags = ev->flags;
    o->timestamp_us = ev->timestamp_us;
    o->error = ev->error;
    o->reason = ev->reason;
    o->addr = ev->addr;
    if (ev->msg) {
        o->data = ev->msg->data;
        o->data_len = ev->msg->len;
        o->msg_handle = ev->msg;
        ctx->lent[ctx->nlent++] = ev->msg;   /* our reference, dropped next poll */
        ev->msg = NULL;
    }
    if (ev->has_peer_key) {
        memcpy(ctx->lent_keys[i], ev->peer_key, 32);
        o->peer_key = ctx->lent_keys[i];
    }
}

/* Events from one connection, after it has been popped. */
static void account_popped(pierce_ctx *ctx, pc_conn *c, pc_event *ev)
{
    if (ev->type == PIERCE_EV_MESSAGE && ev->msg) {
        uint32_t l = ev->msg->len;
        c->rx_buffered = c->rx_buffered > l ? c->rx_buffered - l : 0;
    }
    if (ev->type == PIERCE_EV_DISCONNECTED) pc_conn_schedule_free(c);
    (void)ctx;
}

/* Output arrays are often uninitialized, so their struct_size cannot be
   trusted as input. The v1 layout is the stride for pierce_poll forever;
   later fields would arrive through a new entry point. */
static size_t event_stride(pierce_event *out)
{
    (void)out;
    return sizeof(pierce_event);
}

static int collect(pierce_ctx *ctx, pierce_event *out, uint32_t max)
{
    if (!max) return 0;
    size_t stride = event_stride(out);
    if (ensure_lent(ctx, max) < 0) return PIERCE_ERR_NO_MEMORY;
    uint32_t n = 0;
    while (n < max) {
        pc_event *ev = NULL;
        pc_conn *c = NULL;
        /* Alternate the global queue with connections (round-robin). */
        if (ctx->global_q.count && (ctx->global_turn || !ctx->ready_head)) {
            ev = evq_pop(&ctx->global_q);
        } else {
            while (ctx->ready_head && !ctx->ready_head->evq.count) {
                pc_conn *h = ctx->ready_head;
                ctx->ready_head = h->ready_next;
                if (!ctx->ready_head) ctx->ready_tail = NULL;
                h->in_ready = 0;
            }
            if (ctx->ready_head) {
                c = ctx->ready_head;
                ev = evq_pop(&c->evq);
                ctx->ready_head = c->ready_next;
                if (!ctx->ready_head) ctx->ready_tail = NULL;
                c->in_ready = 0;
                if (c->evq.count) {          /* back of the line */
                    c->in_ready = 1;
                    c->ready_next = NULL;
                    if (ctx->ready_tail) ctx->ready_tail->ready_next = c;
                    else ctx->ready_head = c;
                    ctx->ready_tail = c;
                }
            } else if (ctx->global_q.count) {
                ev = evq_pop(&ctx->global_q);
            }
        }
        ctx->global_turn ^= 1;
        if (!ev) break;
        if (c) account_popped(ctx, c, ev);
        fill_event(ctx, ev, (pierce_event *)((uint8_t *)out + n * stride), n);
        event_free(ctx, ev);
        n++;
    }
    return (int)n;
}

static void begin_call(pierce_ctx *ctx)
{
    release_lent(ctx);
    process_frees(ctx);
}

static void build_wait_set(pierce_ctx *ctx, pal_pollfd *fds, uint32_t *n, int32_t *relay_idx)
{
    *n = 0;
    if (ctx->sock4 != PAL_INVALID_SOCK) { fds[*n].sock = ctx->sock4; fds[*n].want_write = 0; relay_idx[(*n)++] = -1; }
    if (ctx->sock6 != PAL_INVALID_SOCK) { fds[*n].sock = ctx->sock6; fds[*n].want_write = 0; relay_idx[(*n)++] = -1; }
    fds[*n].sock = ctx->wake.rd;
    fds[*n].want_write = 0;
    relay_idx[(*n)++] = -2;
    for (uint32_t i = 0; i < ctx->nrelays; i++) {
        pc_relay *r = ctx->relays[i];
        if (!r->tcp || r->sock == PAL_INVALID_SOCK) continue;
        fds[*n].sock = r->sock;
        fds[*n].want_write = (uint8_t)(r->state == PC_RELAY_CONNECTING || r->txlen > 0);
        relay_idx[(*n)++] = (int32_t)i;
    }
    for (uint32_t i = 0; ctx->nxsocks_used && i < PC_MAX_XSOCKS; i++) {
        if (!ctx->xsocks[i].used || ctx->xsocks[i].sock == PAL_INVALID_SOCK) continue;
        fds[*n].sock = ctx->xsocks[i].sock;
        fds[*n].want_write = 0;
        relay_idx[(*n)++] = -1;
    }
    *n += pc_portmap_wait_set(ctx, fds + *n, relay_idx + *n);
}

int pierce_poll(pierce_ctx *ctx, pierce_event *out, uint32_t max, int32_t timeout_ms)
{
    if (!ctx || (max && !out)) return PIERCE_ERR_INVALID_ARG;
    if (ctx->in_poll) return PIERCE_ERR_STATE;
    ctx->in_poll = 1;
    begin_call(ctx);
    if (ctx->manual_clock || test_global_clock) timeout_ms = 0;
    uint64_t start = pc_now(ctx);
    uint64_t deadline = timeout_ms > 0 ? start + (uint64_t)timeout_ms * 1000 : 0;
    int n = 0;
    for (;;) {
        uint64_t now = pc_now(ctx);
        /* Connections the app never saw (failed or refused handshakes) are
           released here too, not only when the app calls poll again: a
           server blocked in pierce_poll(-1) would otherwise hoard slots.
           Anything scheduled earlier in this call is app-invisible, since
           popped DISCONNECTEDs are only scheduled as the call returns. */
        process_frees(ctx);
        pal_atomic_store(&ctx->wake_pending, 0);
        pal_wake_drain(&ctx->wake);
        if (!(ctx->flags & PIERCE_CFG_NO_BUILTIN_UDP)) io_receive(ctx);
        drain_sendqs(ctx);
        run_timers(ctx, now);
        drain_sendqs(ctx);
        flush_all(ctx, now);
        drain_sendqs(ctx);
        if (pal_atomic_exchange(&ctx->app_wake, 0)) timeout_ms = 0;
        if (events_pending(ctx) || timeout_ms == 0 || (deadline && now >= deadline)) {
            n = collect(ctx, out, max);
            break;
        }
        /* Block until I/O, a wake, the next timer, or the caller's deadline. */
        uint64_t t = next_timer(ctx);
        int64_t wait_us = -1;
        if (t) wait_us = t > now ? (int64_t)(t - now) : 0;
        if (deadline) {
            int64_t left = (int64_t)(deadline - now);
            if (wait_us < 0 || left < wait_us) wait_us = left;
        }
        int32_t wait_ms = wait_us < 0 ? -1 : (int32_t)((wait_us + 999) / 1000);
        pal_pollfd fds[PC_WAIT_SET_MAX];
        int32_t ridx[PC_WAIT_SET_MAX];
        uint32_t nf;
        build_wait_set(ctx, fds, &nf, ridx);
        int r = pal_wait(fds, nf, wait_ms);
        if (r < 0) {
            n = PIERCE_ERR_PLATFORM;
            break;
        }
        /* pierce_wake (not the internal wake from pierce_send) ends a
           blocking poll after one more processing pass. */
        if (pal_atomic_exchange(&ctx->app_wake, 0)) timeout_ms = 0;
        for (uint32_t i = 0; i < nf; i++) {
            if (!(fds[i].readable || fds[i].writable || fds[i].failed)) continue;
            if (ridx[i] >= 0) pc_relay_tcp_io(ctx, (uint32_t)ridx[i], fds[i].readable, fds[i].writable, fds[i].failed);
            else if (ridx[i] == -3) pc_portmap_io(ctx);
        }
    }
    ctx->in_poll = 0;
    return n;
}

int pierce_poll_conn(pierce_ctx *ctx, pierce_conn_id id, pierce_event *out, uint32_t max)
{
    if (!ctx || (max && !out)) return PIERCE_ERR_INVALID_ARG;
    if (ctx->in_poll) return PIERCE_ERR_STATE;
    begin_call(ctx);
    pc_conn *c = pc_conn_lookup(ctx, id);
    if (!c) return PIERCE_ERR_NO_SUCH_CONN;
    if (!max) return 0;
    if (ensure_lent(ctx, max) < 0) return PIERCE_ERR_NO_MEMORY;
    size_t stride = event_stride(out);
    uint32_t n = 0;
    pc_event *ev;
    while (n < max && (ev = evq_pop(&c->evq))) {
        account_popped(ctx, c, ev);
        fill_event(ctx, ev, (pierce_event *)((uint8_t *)out + n * stride), n);
        event_free(ctx, ev);
        n++;
    }
    return (int)n;
}

int pierce_flush(pierce_ctx *ctx)
{
    if (!ctx) return PIERCE_ERR_INVALID_ARG;
    if (ctx->in_poll) return PIERCE_ERR_STATE;
    uint64_t now = pc_now(ctx);
    drain_sendqs(ctx);
    flush_all(ctx, now);
    return PIERCE_OK;
}

void pierce_wake(pierce_ctx *ctx)
{
    if (!ctx) return;
    pal_atomic_store(&ctx->app_wake, 1);
    wake_poller(ctx);
}

int pierce_next_timeout_ms(pierce_ctx *ctx)
{
    if (!ctx) return PIERCE_ERR_INVALID_ARG;
    if (events_pending(ctx)) return 0;
    uint64_t t = next_timer(ctx), now = pc_now(ctx);
    if (!t) return -1;
    if (t <= now) return 0;
    uint64_t ms = (t - now + 999) / 1000;
    return ms > INT32_MAX ? INT32_MAX : (int)ms;
}

/* ===================================================================== */
/* Message retention                                                     */
/* ===================================================================== */

void *pierce_msg_retain(const pierce_event *ev)
{
    if (!ev || !ev->msg_handle) return NULL;
    pc_msg_ref((pc_msg *)ev->msg_handle);
    return ev->msg_handle;
}

void pierce_msg_release(void *handle)
{
    if (handle) pc_msg_unref((pc_msg *)handle);
}

const uint8_t *pierce_msg_data(void *handle, uint32_t *len_out)
{
    pc_msg *m = (pc_msg *)handle;
    if (!m) return NULL;
    if (len_out) *len_out = m->len;
    return m->data;
}

int pierce_event_copy(const pierce_event *ev, uint8_t *dst, uint32_t cap)
{
    if (!ev || (ev->data_len && !dst)) return PIERCE_ERR_INVALID_ARG;
    if (ev->data_len > cap) return PIERCE_ERR_BUFFER_TOO_SMALL;
    if (ev->data_len) memcpy(dst, ev->data, ev->data_len);
    return (int)ev->data_len;
}

/* ===================================================================== */
/* Lifecycle hooks                                                       */
/* ===================================================================== */

void pierce_net_changed(pierce_ctx *ctx)
{
    if (!ctx) return;
    pc_gather_refresh(ctx);
    /* Speak first from the new network: the peer migrates to whatever
       address an authenticated packet arrives from. */
    for (pc_conn *c = ctx->conns; c; c = c->next)
        if (c->state == PC_ST_CONNECTED) c->ping_pending = 1;
}

void pierce_suspend(pierce_ctx *ctx)
{
    if (ctx) ctx->suspended = 1;
}

void pierce_resume(pierce_ctx *ctx)
{
    if (!ctx || !ctx->suspended) return;
    ctx->suspended = 0;
    uint64_t now = pc_now(ctx);
    for (pc_conn *c = ctx->conns; c; c = c->next) {
        if (c->state == PC_ST_CLOSED) continue;
        c->last_rx_us = now;               /* the pause was not the peer's fault */
        if (c->deadline_us) c->deadline_us = now + ctx->connect_us;
        if (c->state == PC_ST_CONNECTED) c->ping_pending = 1;
    }
    pc_gather_refresh(ctx);
}

int pierce_get_fds(pierce_ctx *ctx, pierce_socket *fds, uint32_t cap)
{
    if (!ctx || (cap && !fds)) return PIERCE_ERR_INVALID_ARG;
    pal_pollfd all[PC_WAIT_SET_MAX];
    int32_t idx[PC_WAIT_SET_MAX];
    uint32_t n;
    build_wait_set(ctx, all, &n, idx);
    for (uint32_t i = 0; i < n && i < cap; i++) fds[i] = all[i].sock;
    return (int)n;
}
