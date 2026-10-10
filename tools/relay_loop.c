#include "relay_loop.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../src/common.h"
#include "../src/pal.h"
#include "../src/relay_server.h"

#define MAX_TCP 1024
#define TCP_TX_MAX (1u << 20)

typedef struct {
    pal_sock sock;
    uint64_t id;
    pierce_addr peer;
    uint8_t rx[2 + 65535];
    uint32_t rxlen;
    uint8_t *tx;
    uint32_t txlen, txcap;
} tcp_conn;

typedef struct {
    pal_sock udp4, udp6, tcp4;
    tcp_conn *tcp[MAX_TCP];
    uint32_t ntcp;
    uint64_t next_id;
    pc_relay_server *rs;
    int verbose;
} loop_state;

static tcp_conn *tcp_find(loop_state *st, uint64_t id)
{
    for (uint32_t i = 0; i < st->ntcp; i++)
        if (st->tcp[i]->id == id) return st->tcp[i];
    return NULL;
}

static void tcp_flush(tcp_conn *t)
{
    while (t->txlen) {
        int n = pal_tcp_send(t->sock, t->tx, t->txlen);
        if (n <= 0) return;
        memmove(t->tx, t->tx + n, t->txlen - (uint32_t)n);
        t->txlen -= (uint32_t)n;
    }
}

static void send_cb(void *user, const pc_rs_ep *to, const uint8_t *data, size_t len)
{
    loop_state *st = (loop_state *)user;
    if (to->tcp_id) {
        tcp_conn *t = tcp_find(st, to->tcp_id);
        if (!t || t->txlen + 2 + len > TCP_TX_MAX) return;   /* slow reader: drop like UDP */
        if (t->txlen + 2 + len > t->txcap) {
            uint32_t nc = t->txcap ? t->txcap * 2 : 8192;
            while (nc < t->txlen + 2 + len) nc *= 2;
            uint8_t *n = (uint8_t *)realloc(t->tx, nc);
            if (!n) return;
            t->tx = n;
            t->txcap = nc;
        }
        pc_put16(t->tx + t->txlen, (uint16_t)len);
        memcpy(t->tx + t->txlen + 2, data, len);
        t->txlen += 2 + (uint32_t)len;
        tcp_flush(t);
        return;
    }
    pal_sock s = to->addr.family == PIERCE_AF_INET6 ? st->udp6 : st->udp4;
    if (s != PAL_INVALID_SOCK) pal_udp_send(s, &to->addr, data, len);
}

static void tcp_close(loop_state *st, uint32_t idx)
{
    tcp_conn *t = st->tcp[idx];
    pc_rs_tcp_closed(st->rs, t->id);
    pal_sock_close(t->sock);
    free(t->tx);
    free(t);
    st->tcp[idx] = st->tcp[--st->ntcp];
}

/* Returns 0 to keep the connection, -1 to close it. */
static int tcp_read(loop_state *st, tcp_conn *t, uint64_t now_us)
{
    for (;;) {
        int n = pal_tcp_recv(t->sock, t->rx + t->rxlen, sizeof(t->rx) - t->rxlen);
        if (n == PIERCE_ERR_WOULD_BLOCK) return 0;
        if (n <= 0) return -1;
        t->rxlen += (uint32_t)n;
        uint32_t off = 0;
        while (t->rxlen - off >= 2) {
            uint32_t flen = pc_get16(t->rx + off);
            if (t->rxlen - off < 2 + flen) break;
            pc_rs_ep ep;
            memset(&ep, 0, sizeof(ep));
            ep.addr = t->peer;
            ep.tcp_id = t->id;
            pc_rs_input(st->rs, now_us, (uint64_t)time(NULL), &ep, t->rx + off + 2, flen, send_cb, st);
            off += 2 + flen;
        }
        memmove(t->rx, t->rx + off, t->rxlen - off);
        t->rxlen -= off;
    }
}

int relay_loop_run(relay_loop_opts *o, volatile uint32_t *stop)
{
    loop_state st;
    pierce_addr la;
    memset(&st, 0, sizeof(st));
    st.udp4 = st.udp6 = st.tcp4 = PAL_INVALID_SOCK;
    st.next_id = 1;
    st.verbose = o->verbose;
    if (pal_init() != PIERCE_OK) goto fail;

    pc_rs_config rc;
    memset(&rc, 0, sizeof(rc));
    rc.secret = o->secret;
    rc.secret_len = o->secret_len;
    rc.open = o->open;
    rc.max_allocs = o->max_allocs;
    rc.default_kbps = o->default_kbps;
    st.rs = pc_rs_create(&rc);
    if (!st.rs) goto fail;

    if (pal_udp_open(PIERCE_AF_INET, o->udp_port, &st.udp4) != PIERCE_OK) goto fail;
    pal_sock_local_addr(st.udp4, &la);
    o->bound_udp_port = la.port;
    if (o->enable_ipv6) pal_udp_open(PIERCE_AF_INET6, la.port, &st.udp6);
    if (o->enable_tcp) {
        if (pal_tcp_listen(PIERCE_AF_INET, o->tcp_port, &st.tcp4) != PIERCE_OK) goto fail;
        pal_sock_local_addr(st.tcp4, &la);
        o->bound_tcp_port = la.port;
    }
    pal_atomic_store(&o->ready, 1);
    if (o->verbose)
        fprintf(stderr, "pierce-relay: udp %u%s, tcp %s%u, %s\n", o->bound_udp_port,
                st.udp6 != PAL_INVALID_SOCK ? " (v4+v6)" : "", o->enable_tcp ? "" : "off ",
                o->enable_tcp ? o->bound_tcp_port : 0, o->open ? "open" : "token required");

    uint8_t buf[2048];
    uint64_t last_tick = pal_now_us();
    while (!pal_atomic_load(stop)) {
        pal_pollfd fds[3 + MAX_TCP];
        uint32_t n = 0;
        if (st.udp4 != PAL_INVALID_SOCK) { memset(&fds[n], 0, sizeof(fds[n])); fds[n++].sock = st.udp4; }
        if (st.udp6 != PAL_INVALID_SOCK) { memset(&fds[n], 0, sizeof(fds[n])); fds[n++].sock = st.udp6; }
        if (st.tcp4 != PAL_INVALID_SOCK) { memset(&fds[n], 0, sizeof(fds[n])); fds[n++].sock = st.tcp4; }
        uint32_t tcp_base = n;
        for (uint32_t i = 0; i < st.ntcp; i++) {
            memset(&fds[n], 0, sizeof(fds[n]));
            fds[n].sock = st.tcp[i]->sock;
            fds[n].want_write = st.tcp[i]->txlen > 0;
            n++;
        }
        if (pal_wait(fds, n, 200) < 0) break;
        uint64_t now = pal_now_us();

        for (uint32_t i = 0; i < tcp_base; i++) {
            if (!fds[i].readable) continue;
            if (fds[i].sock == st.tcp4) {
                pal_sock s;
                pierce_addr peer;
                while (pal_tcp_accept(st.tcp4, &s, &peer) == PIERCE_OK) {
                    if (st.ntcp >= MAX_TCP) {
                        pal_sock_close(s);
                        continue;
                    }
                    tcp_conn *t = (tcp_conn *)calloc(1, sizeof(*t));
                    if (!t) {
                        pal_sock_close(s);
                        continue;
                    }
                    t->sock = s;
                    t->peer = peer;
                    t->id = st.next_id++;
                    st.tcp[st.ntcp++] = t;
                }
                continue;
            }
            for (int k = 0; k < 256; k++) {
                pierce_addr from;
                int r = pal_udp_recv(fds[i].sock, buf, sizeof(buf), &from);
                if (r < 0) break;
                pc_rs_ep ep;
                memset(&ep, 0, sizeof(ep));
                ep.addr = from;
                pc_rs_input(st.rs, now, (uint64_t)time(NULL), &ep, buf, (size_t)r, send_cb, &st);
            }
        }
        /* TCP connections (iterate backwards: closing swaps in the last). */
        for (uint32_t i = st.ntcp; i-- > 0;) {
            tcp_conn *t = st.tcp[i];
            pal_pollfd *f = NULL;
            for (uint32_t k = tcp_base; k < n; k++)
                if (fds[k].sock == t->sock) f = &fds[k];
            if (!f) continue;
            if (f->writable) tcp_flush(t);
            if ((f->readable || f->failed) && tcp_read(&st, t, now) < 0) tcp_close(&st, i);
        }
        if (now - last_tick > 1000000) {
            pc_rs_tick(st.rs, now);
            last_tick = now;
        }
    }

    while (st.ntcp) tcp_close(&st, st.ntcp - 1);
    pal_sock_close(st.udp4);
    pal_sock_close(st.udp6);
    pal_sock_close(st.tcp4);
    pc_rs_destroy(st.rs);
    pal_shutdown();
    return 0;

fail:
    pal_atomic_store(&o->ready, 2);
    pal_sock_close(st.udp4);
    pal_sock_close(st.udp6);
    pal_sock_close(st.tcp4);
    if (st.rs) pc_rs_destroy(st.rs);
    return 1;
}
