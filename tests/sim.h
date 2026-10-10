/* Deterministic in-process network simulator (spec 12).
   Nodes are pierce contexts in custom-transport mode on a manual clock.
   The simulator routes TRANSMIT events through emulated NATs, a STUN
   server, and the real relay server core, with configurable impairments. */
#ifndef PIERCE_SIM_H
#define PIERCE_SIM_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/core.h"
#include "../src/relay_server.h"

void pierce__test_set_rekey_packets(uint64_t n);
void pierce__test_set_global_time(uint64_t now_us);

#define SIM_MAX_NODES 512
#define SIM_MAX_NATS 512
#define SIM_MAX_MAPS 32
#define SIM_MAX_PERMS 16

enum { NAT_NONE = 0, NAT_FULL_CONE, NAT_RESTRICTED, NAT_PORT_RESTRICTED, NAT_SYMMETRIC };

static const char *nat_name(int t)
{
    switch (t) {
    case NAT_NONE: return "public";
    case NAT_FULL_CONE: return "full-cone";
    case NAT_RESTRICTED: return "restricted";
    case NAT_PORT_RESTRICTED: return "port-restricted";
    case NAT_SYMMETRIC: return "symmetric";
    }
    return "?";
}

typedef struct {
    pierce_addr priv, dest;
    uint16_t pub_port;
    pierce_addr perms[SIM_MAX_PERMS];
    int nperm;
} sim_map;

typedef struct {
    int type;
    uint8_t ip[4];
    sim_map maps[SIM_MAX_MAPS];
    int nmaps;
    uint16_t next_port;
} sim_nat;

typedef struct {
    pierce_conn_id conn;
    uint32_t channel;
    uint32_t len;
    uint8_t *data;
    uint64_t at;
} sim_msg;

typedef struct {
    pierce_ctx *ctx;
    pierce_addr priv;
    int nat;                     /* -1 = public */
    int signal_to;               /* node that receives our SIGNAL_OUTs (clients) */
    pierce_conn_id peer_conn[SIM_MAX_NODES];   /* server: conn id -> client node */
    int peer_node[SIM_MAX_NODES];
    int npeer;
    int auto_accept;
    uint32_t reject_reason;      /* nonzero: reject PEER_REQUESTs with this */
    int connected, disconnected, peer_requests, path_changes, low_events;
    int32_t last_error;
    uint32_t last_reason;
    pierce_conn_id last_conn;
    uint32_t last_path;          /* path flags of the last CONNECTED */
    uint8_t last_peer_key[32];
    uint8_t last_payload[1024];      /* data of the last PEER_REQUEST */
    uint32_t last_payload_len;
    pierce_conn_id last_request_conn;
    uint64_t last_user_data;         /* user_data of the last CONNECTED */
    uint64_t accept_user_data;       /* passed to pierce_accept when nonzero */
    sim_msg *msgs;
    int nmsgs, capmsgs;
    uint64_t sent_direct, sent_relay;  /* datagrams by destination kind */
} sim_node;

typedef struct sim_pkt {
    struct sim_pkt *next;
    uint64_t at;
    pierce_addr src, dst;
    uint32_t len;
    uint8_t data[1600];
} sim_pkt;

typedef struct sim_sig {
    struct sim_sig *next;
    uint64_t at;
    int from, to;
    pierce_conn_id from_conn;
    uint32_t len;
    uint8_t data[2048];
} sim_sig;

typedef struct {
    uint64_t now;
    sim_node nodes[SIM_MAX_NODES];
    int nnodes;
    sim_nat nats[SIM_MAX_NATS];
    int nnats;
    sim_pkt *q;
    sim_sig *sigq;
    uint32_t loss_ppm, dup_ppm;
    uint64_t delay_us, jitter_us, sig_delay_us;
    uint64_t rng;
    int has_stun;
    pierce_addr stun_addr;
    pc_relay_server *relay;
    pierce_addr relay_addr;
    int verbose;
    int drop_all;               /* blackhole everything */
    int block_direct;           /* blackhole peer-to-peer traffic (relay/STUN still work) */
    uint64_t delivered, dropped;
} sim;

static uint64_t sim_rand(sim *s)
{
    s->rng ^= s->rng << 13;
    s->rng ^= s->rng >> 7;
    s->rng ^= s->rng << 17;
    return s->rng;
}

static pierce_addr sim_ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port)
{
    pierce_addr x;
    memset(&x, 0, sizeof(x));
    x.family = PIERCE_AF_INET;
    x.addr[0] = a; x.addr[1] = b; x.addr[2] = c; x.addr[3] = d;
    x.port = port;
    return x;
}

static void sim_init(sim *s, uint64_t seed)
{
    memset(s, 0, sizeof(*s));
    s->rng = seed ? seed : 88172645463325252ull;
    s->now = 1000000;   /* t = 1 s: keeps "0 = unset" timers meaningful */
    pierce__test_set_global_time(s->now);
    s->delay_us = 10000;
    s->sig_delay_us = 50000;
    s->verbose = getenv("PIERCE_SIM_VERBOSE") != NULL;
}

static void sim_enable_stun(sim *s)
{
    s->has_stun = 1;
    s->stun_addr = sim_ip(198, 51, 100, 1, 3478);
}

static void sim_enable_relay(sim *s, const uint8_t *secret, uint32_t secret_len)
{
    pc_rs_config rc;
    memset(&rc, 0, sizeof(rc));
    rc.secret = secret;
    rc.secret_len = secret_len;
    rc.open = secret == NULL;
    s->relay = pc_rs_create(&rc);
    s->relay_addr = sim_ip(198, 51, 100, 2, 3478);
}

static int sim_add_nat(sim *s, int type)
{
    int i = s->nnats++;
    sim_nat *n = &s->nats[i];
    memset(n, 0, sizeof(*n));
    n->type = type;
    n->ip[0] = 203; n->ip[1] = 0; n->ip[2] = (uint8_t)(113 + i / 250); n->ip[3] = (uint8_t)(1 + i % 250);
    n->next_port = 40000;
    return i;
}

/* ---- NAT translation ---- */

static sim_map *nat_out(sim_nat *n, const pierce_addr *priv, const pierce_addr *dst)
{
    for (int i = 0; i < n->nmaps; i++) {
        sim_map *m = &n->maps[i];
        if (!pc_addr_eq(&m->priv, priv)) continue;
        if (n->type == NAT_SYMMETRIC && !pc_addr_eq(&m->dest, dst)) continue;
        return m;
    }
    if (n->nmaps >= SIM_MAX_MAPS) return NULL;
    sim_map *m = &n->maps[n->nmaps++];
    memset(m, 0, sizeof(*m));
    m->priv = *priv;
    m->dest = *dst;
    m->pub_port = n->next_port++;
    return m;
}

static void map_permit(sim_map *m, const pierce_addr *dst)
{
    for (int i = 0; i < m->nperm; i++)
        if (pc_addr_eq(&m->perms[i], dst)) return;
    if (m->nperm < SIM_MAX_PERMS) m->perms[m->nperm++] = *dst;
}

static int map_allows(const sim_nat *n, const sim_map *m, const pierce_addr *src)
{
    switch (n->type) {
    case NAT_FULL_CONE:
        return 1;
    case NAT_RESTRICTED:
        for (int i = 0; i < m->nperm; i++)
            if (pc_addr_ip_eq(&m->perms[i], src)) return 1;
        return 0;
    case NAT_PORT_RESTRICTED:
        for (int i = 0; i < m->nperm; i++)
            if (pc_addr_eq(&m->perms[i], src)) return 1;
        return 0;
    case NAT_SYMMETRIC:
        return pc_addr_eq(&m->dest, src);
    }
    return 1;
}

/* Clear all mappings: the next packet gets a new public port (rebinding). */
static void sim_nat_rebind(sim *s, int nat)
{
    s->nats[nat].nmaps = 0;
    s->nats[nat].next_port += 1000;
}

/* ---- packet movement ---- */

static void sim_enqueue(sim *s, const pierce_addr *src, const pierce_addr *dst, const uint8_t *data,
                        uint32_t len, uint64_t extra_delay)
{
    sim_pkt *p = (sim_pkt *)calloc(1, sizeof(*p));
    p->src = *src;
    p->dst = *dst;
    p->len = len;
    memcpy(p->data, data, len);
    uint64_t j = s->jitter_us ? sim_rand(s) % (s->jitter_us + 1) : 0;
    p->at = s->now + s->delay_us + j + extra_delay;
    /* Sorted insert, stable for equal times. */
    sim_pkt **l = &s->q;
    while (*l && (*l)->at <= p->at) l = &(*l)->next;
    p->next = *l;
    *l = p;
}

/* Send from an internal endpoint (node priv address, or a server). */
static void sim_route_out(sim *s, int node, const pierce_addr *src_priv, const pierce_addr *dst,
                          const uint8_t *data, uint32_t len)
{
    if (s->drop_all || (s->loss_ppm && sim_rand(s) % 1000000 < s->loss_ppm)) {
        s->dropped++;
        return;
    }
    if (s->block_direct && node >= 0 && !(s->relay && pc_addr_eq(dst, &s->relay_addr)) &&
        !(s->has_stun && pc_addr_eq(dst, &s->stun_addr))) {
        s->dropped++;
        return;
    }
    pierce_addr src = *src_priv;
    if (node >= 0 && s->nodes[node].nat >= 0) {
        sim_nat *n = &s->nats[s->nodes[node].nat];
        sim_map *m = nat_out(n, src_priv, dst);
        if (!m) return;
        map_permit(m, dst);
        src = sim_ip(n->ip[0], n->ip[1], n->ip[2], n->ip[3], m->pub_port);
    }
    sim_enqueue(s, &src, dst, data, len, 0);
    if (s->dup_ppm && sim_rand(s) % 1000000 < s->dup_ppm) sim_enqueue(s, &src, dst, data, len, 3000);
}

static void relay_send_cb(void *user, const pc_rs_ep *to, const uint8_t *data, size_t len)
{
    sim *s = (sim *)user;
    sim_route_out(s, -1, &s->relay_addr, &to->addr, data, (uint32_t)len);
}

static int sim_node_by_priv(sim *s, const pierce_addr *a)
{
    for (int i = 0; i < s->nnodes; i++)
        if (pc_addr_eq(&s->nodes[i].priv, a)) return i;
    return -1;
}

static void sim_deliver(sim *s, sim_pkt *p)
{
    if (s->has_stun && pc_addr_eq(&p->dst, &s->stun_addr)) {
        uint8_t resp[64];
        size_t n = pc_stun_binding_response(resp, sizeof(resp), p->data, p->len, &p->src);
        if (n && pc_get16(p->data) == 0x0001) sim_route_out(s, -1, &s->stun_addr, &p->src, resp, (uint32_t)n);
        return;
    }
    if (s->relay && pc_addr_eq(&p->dst, &s->relay_addr)) {
        pc_rs_ep ep;
        memset(&ep, 0, sizeof(ep));
        ep.addr = p->src;
        pc_rs_input(s->relay, s->now, 1700000000ull + s->now / 1000000, &ep, p->data, p->len,
                    relay_send_cb, s);
        return;
    }
    int target = -1;
    pierce_addr src = p->src;
    for (int i = 0; i < s->nnats && target < 0; i++) {
        sim_nat *n = &s->nats[i];
        if (memcmp(n->ip, p->dst.addr, 4) != 0) continue;
        for (int k = 0; k < n->nmaps; k++) {
            sim_map *m = &n->maps[k];
            if (m->pub_port != p->dst.port) continue;
            if (!map_allows(n, m, &src)) {
                s->dropped++;
                return;
            }
            target = sim_node_by_priv(s, &m->priv);
            break;
        }
        if (target < 0) {
            s->dropped++;
            return;   /* no mapping: NAT drops it */
        }
    }
    if (target < 0) {
        target = sim_node_by_priv(s, &p->dst);
        if (target >= 0 && s->nodes[target].nat >= 0) target = -1;   /* private: unreachable */
    }
    if (target < 0) {
        s->dropped++;
        return;
    }
    s->delivered++;
    pierce__test_set_time(s->nodes[target].ctx, s->now);
    pierce_transport_in(s->nodes[target].ctx, &src, p->data, p->len);
}

/* ---- nodes ---- */

typedef void (*sim_cfg_fn)(pierce_config *cfg, void *user);

static int sim_add_node_cfg(sim *s, int nat, sim_cfg_fn fn, void *user)
{
    int i = s->nnodes++;
    sim_node *n = &s->nodes[i];
    memset(n, 0, sizeof(*n));
    n->nat = nat;
    n->signal_to = -1;
    n->auto_accept = 1;
    if (nat >= 0) n->priv = sim_ip(10, (uint8_t)(i / 250), (uint8_t)(i % 250), 2, 5000);
    else n->priv = sim_ip(192, 0, (uint8_t)(2 + i / 250), (uint8_t)(1 + i % 250), 5000);

    pierce_config cfg;
    pierce_config_init(&cfg);
    cfg.flags = PIERCE_CFG_NO_BUILTIN_UDP | PIERCE_CFG_NO_IPV6;
    char stun[64], relay[64];
    const char *stuns[1], *relays[1];
    if (s->has_stun) {
        pierce_addr_format(&s->stun_addr, stun, sizeof(stun));
        stuns[0] = stun;
        cfg.stun_servers = stuns;
        cfg.stun_server_count = 1;
    }
    if (s->relay) {
        pierce_addr_format(&s->relay_addr, relay, sizeof(relay));
        relays[0] = relay;
        cfg.relay_servers = relays;
        cfg.relay_server_count = 1;
    }
    cfg.log_level = s->verbose ? PIERCE_LOG_DEBUG : PIERCE_LOG_OFF;
    if (fn) fn(&cfg, user);
    int rc = pierce_ctx_create(&cfg, &n->ctx);
    if (rc != PIERCE_OK) {
        fprintf(stderr, "sim: ctx_create failed: %s\n", pierce_strerror(rc));
        abort();
    }
    pierce__test_set_time(n->ctx, s->now);
    pierce_add_local_address(n->ctx, &n->priv);
    return i;
}

static int sim_add_node(sim *s, int nat) { return sim_add_node_cfg(s, nat, NULL, NULL); }

static int sim_node_for_conn(sim_node *n, pierce_conn_id id)
{
    for (int i = 0; i < n->npeer; i++)
        if (n->peer_conn[i] == id) return n->peer_node[i];
    return -1;
}

static void sim_signal(sim *s, int from, pierce_conn_id conn, const uint8_t *data, uint32_t len)
{
    sim_node *n = &s->nodes[from];
    int to = n->signal_to >= 0 ? n->signal_to : sim_node_for_conn(n, conn);
    if (to < 0) return;
    sim_sig *g = (sim_sig *)calloc(1, sizeof(*g));
    g->at = s->now + s->sig_delay_us;
    g->from = from;
    g->to = to;
    g->from_conn = conn;
    g->len = len;
    memcpy(g->data, data, len);
    sim_sig **l = &s->sigq;
    while (*l && (*l)->at <= g->at) l = &(*l)->next;
    g->next = *l;
    *l = g;
}

static void sim_handle_event(sim *s, int idx, const pierce_event *ev)
{
    sim_node *n = &s->nodes[idx];
    switch (ev->type) {
    case PIERCE_EV_TRANSMIT: {
        int is_relay = s->relay && pc_addr_eq(&ev->addr, &s->relay_addr);
        int is_stun = s->has_stun && pc_addr_eq(&ev->addr, &s->stun_addr);
        if (is_relay) n->sent_relay++;
        else if (!is_stun) n->sent_direct++;
        sim_route_out(s, idx, &n->priv, &ev->addr, ev->data, ev->data_len);
        break;
    }
    case PIERCE_EV_SIGNAL_OUT:
        sim_signal(s, idx, ev->conn_id, ev->data, ev->data_len);
        break;
    case PIERCE_EV_PEER_REQUEST:
        n->peer_requests++;
        n->last_request_conn = ev->conn_id;
        if (ev->peer_key) memcpy(n->last_peer_key, ev->peer_key, 32);
        n->last_payload_len = ev->data_len < sizeof(n->last_payload) ? ev->data_len : 0;
        if (n->last_payload_len) memcpy(n->last_payload, ev->data, n->last_payload_len);
        if (n->reject_reason) pierce_reject(n->ctx, ev->conn_id, n->reject_reason);
        else if (n->auto_accept)
            pierce_accept(n->ctx, ev->conn_id, n->accept_user_data ? n->accept_user_data : ev->user_data);
        break;
    case PIERCE_EV_CONNECTED:
        n->connected++;
        n->last_conn = ev->conn_id;
        n->last_user_data = ev->user_data;
        n->last_path = ev->flags;
        if (ev->peer_key) memcpy(n->last_peer_key, ev->peer_key, 32);
        break;
    case PIERCE_EV_DISCONNECTED:
        n->disconnected++;
        n->last_error = ev->error;
        n->last_reason = ev->reason;
        break;
    case PIERCE_EV_PATH_CHANGED:
        n->path_changes++;
        break;
    case PIERCE_EV_SEND_BUFFER_LOW:
        n->low_events++;
        break;
    case PIERCE_EV_MESSAGE:
        if (n->nmsgs == n->capmsgs) {
            n->capmsgs = n->capmsgs ? n->capmsgs * 2 : 64;
            n->msgs = (sim_msg *)realloc(n->msgs, (size_t)n->capmsgs * sizeof(sim_msg));
        }
        n->msgs[n->nmsgs].conn = ev->conn_id;
        n->msgs[n->nmsgs].channel = ev->channel;
        n->msgs[n->nmsgs].len = ev->data_len;
        n->msgs[n->nmsgs].at = s->now;
        n->msgs[n->nmsgs].data = (uint8_t *)malloc(ev->data_len ? ev->data_len : 1);
        memcpy(n->msgs[n->nmsgs].data, ev->data, ev->data_len);
        n->nmsgs++;
        break;
    case PIERCE_EV_LOG:
        if (s->verbose) fprintf(stderr, "[%8.3f node %d] %.*s\n", s->now / 1e6, idx, (int)ev->data_len, ev->data);
        break;
    }
}

static void sim_poll_node(sim *s, int idx)
{
    pierce_event evs[32];
    sim_node *n = &s->nodes[idx];
    if (!n->ctx) return;
    pierce__test_set_time(n->ctx, s->now);
    for (;;) {
        int k = pierce_poll(n->ctx, evs, 32, 0);
        if (k <= 0) break;
        for (int i = 0; i < k; i++) sim_handle_event(s, idx, &evs[i]);
    }
}

static void sim_step(sim *s, uint64_t dt)
{
    s->now += dt;
    pierce__test_set_global_time(s->now);
    while (s->q && s->q->at <= s->now) {
        sim_pkt *p = s->q;
        s->q = p->next;
        sim_deliver(s, p);
        free(p);
    }
    while (s->sigq && s->sigq->at <= s->now) {
        sim_sig *g = s->sigq;
        s->sigq = g->next;
        sim_node *to = &s->nodes[g->to];
        if (to->ctx) {
            pierce_conn_id out = 0;
            pierce__test_set_time(to->ctx, s->now);
            int rc = pierce_signal_in(to->ctx, g->data, g->len, &out);
            if (rc == PIERCE_OK && out && to->signal_to < 0 && sim_node_for_conn(to, out) < 0 &&
                to->npeer < SIM_MAX_NODES) {
                to->peer_conn[to->npeer] = out;
                to->peer_node[to->npeer] = g->from;
                to->npeer++;
            }
        }
        free(g);
    }
    if (s->relay) pc_rs_tick(s->relay, s->now);
    for (int i = 0; i < s->nnodes; i++) sim_poll_node(s, i);
}

static void sim_run(sim *s, uint64_t duration_us)
{
    uint64_t end = s->now + duration_us;
    while (s->now < end) sim_step(s, 1000);
}

/* Run until cond(s, user) is true or the time limit passes. */
typedef int (*sim_cond_fn)(sim *s, void *user);
static int sim_run_until(sim *s, uint64_t limit_us, sim_cond_fn cond, void *user)
{
    uint64_t end = s->now + limit_us;
    while (s->now < end) {
        sim_step(s, 1000);
        if (cond(s, user)) return 1;
    }
    return 0;
}

enum {
    SIM_XX = 0,       /* no invite: XX over signaling */
    SIM_IK = 1,       /* key-only invite: IK over signaling */
    SIM_DIRECT = 2    /* invite with the server's addresses: no signaling */
};

/* Client node connects to server node. */
static pierce_conn_id sim_connect(sim *s, int client, int server, const pierce_conn_options *opt, int mode)
{
    uint8_t inv[256];
    int ilen = 0;
    pierce_conn_id id = 0;
    pierce__test_set_time(s->nodes[server].ctx, s->now);
    pierce__test_set_time(s->nodes[client].ctx, s->now);
    if (mode != SIM_XX) ilen = pierce_get_invite(s->nodes[server].ctx, inv, sizeof(inv));
    if (mode == SIM_IK) {
        /* Strip the address list: magic(2) ver(1) flags(1) key(32) naddr(1). */
        inv[36] = 0;
        ilen = 37;
    }
    s->nodes[client].signal_to = server;
    int rc = pierce_connect(s->nodes[client].ctx, opt, mode != SIM_XX ? inv : NULL,
                            mode != SIM_XX ? (uint32_t)ilen : 0, &id);
    if (rc != PIERCE_OK) {
        fprintf(stderr, "sim: connect failed: %s\n", pierce_strerror(rc));
        return 0;
    }
    return id;
}

static void sim_free(sim *s)
{
    for (int i = 0; i < s->nnodes; i++) {
        if (s->nodes[i].ctx) pierce_ctx_destroy(s->nodes[i].ctx);
        for (int k = 0; k < s->nodes[i].nmsgs; k++) free(s->nodes[i].msgs[k].data);
        free(s->nodes[i].msgs);
    }
    while (s->q) {
        sim_pkt *p = s->q;
        s->q = p->next;
        free(p);
    }
    while (s->sigq) {
        sim_sig *g = s->sigq;
        s->sigq = g->next;
        free(g);
    }
    if (s->relay) pc_rs_destroy(s->relay);
}

#endif
