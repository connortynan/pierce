/* Integration over real sockets on loopback: builtin UDP, the reference
   relay over UDP and TCP, and the cross-thread send path (spec 7). */
#if defined(_WIN32)
int main(void) { return 0; }   /* POSIX threads below; Windows CI runs test_sim */
#else

#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <sched.h>
#include <time.h>

#include "../src/pal.h"
#include "../tools/relay_loop.h"
#include "pierce.h"
#include "test.h"

typedef struct peer {
    pierce_ctx *ctx;
    struct peer *other;         /* signaling partner */
    int connected, disconnected;
    int32_t last_error;
    uint32_t path;
    pierce_conn_id conn;
    volatile uint32_t msgs;     /* atomic: read across threads in test_threads */
    uint64_t bytes;
    uint32_t next_seq[8];       /* per-sender ordering checks */
    int order_ok;
} peer;

static void sleep_ms(int ms)
{
    struct timespec ts = {ms / 1000, (long)(ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

static pierce_ctx *make_ctx(uint32_t flags, const char *relay)
{
    pierce_config cfg;
    pierce_ctx *ctx = NULL;
    const char *relays[1] = {relay};
    pierce_config_init(&cfg);
    cfg.flags = flags | PIERCE_CFG_INCLUDE_LOOPBACK | PIERCE_CFG_NO_IPV6;
    if (relay) {
        cfg.relay_servers = relays;
        cfg.relay_server_count = 1;
    }
    if (pierce_ctx_create(&cfg, &ctx) != PIERCE_OK) return NULL;
    return ctx;
}

static void handle(peer *p, const pierce_event *ev)
{
    switch (ev->type) {
    case PIERCE_EV_SIGNAL_OUT:
        if (p->other) {
            pierce_conn_id id;
            pierce_signal_in(p->other->ctx, ev->data, ev->data_len, &id);
        }
        break;
    case PIERCE_EV_PEER_REQUEST:
        pierce_accept(p->ctx, ev->conn_id, 0);
        break;
    case PIERCE_EV_CONNECTED:
        p->connected++;
        p->conn = ev->conn_id;
        p->path = ev->flags;
        break;
    case PIERCE_EV_DISCONNECTED:
        p->disconnected++;
        p->last_error = ev->error;
        break;
    case PIERCE_EV_MESSAGE:
        pal_atomic_add(&p->msgs, 1);
        p->bytes += ev->data_len;
        if (ev->data_len >= 8) {
            uint32_t who = ev->data[0], seq = ((uint32_t)ev->data[4] << 24) | ((uint32_t)ev->data[5] << 16) |
                                              ((uint32_t)ev->data[6] << 8) | ev->data[7];
            if (who < 8) {
                if (seq != p->next_seq[who]) p->order_ok = 0;
                p->next_seq[who] = seq + 1;
            }
        }
        break;
    }
}

static void pump(peer **ps, int n, int ms)
{
    pierce_event ev[64];
    for (int i = 0; i < n; i++) {
        int k = pierce_poll(ps[i]->ctx, ev, 64, ms);
        for (int j = 0; j < k; j++) handle(ps[i], &ev[j]);
    }
}

typedef int (*cond_fn)(peer **ps);
static int pump_until(peer **ps, int n, int timeout_ms, cond_fn cond)
{
    for (int t = 0; t < timeout_ms; t += 2 * n) {
        pump(ps, n, 2);
        if (cond(ps)) return 1;
    }
    return 0;
}

static int both_up(peer **ps) { return ps[0]->connected && ps[1]->connected; }
static int got_1000(peer **ps) { return ps[0]->msgs >= 1000; }

static void exchange(peer *srv, peer *cli)
{
    peer *ps[2] = {srv, cli};
    uint8_t buf[200000];
    memset(buf, 0xab, sizeof(buf));
    for (uint32_t i = 0; i < 1000; i++) {
        uint32_t len = i == 500 ? 200000 : 8 + i % 1000;
        buf[0] = 0;
        buf[4] = (uint8_t)(i >> 24); buf[5] = (uint8_t)(i >> 16); buf[6] = (uint8_t)(i >> 8); buf[7] = (uint8_t)i;
        while (pierce_send(cli->ctx, cli->conn, 0, buf, len, 0) == PIERCE_ERR_WOULD_BLOCK) pump(ps, 2, 1);
    }
    CHECK(pump_until(ps, 2, 20000, got_1000));
    CHECK_EQ(srv->msgs, 1000);
    CHECK(srv->order_ok);
}

static void test_udp_direct(void)
{
    peer srv = {0}, cli = {0};
    srv.order_ok = cli.order_ok = 1;
    srv.ctx = make_ctx(0, NULL);
    cli.ctx = make_ctx(0, NULL);
    REQUIRE(srv.ctx && cli.ctx);
    pierce_addr lo;
    pierce_addr_parse("127.0.0.1:0", &lo);
    CHECK(pierce_add_local_address(srv.ctx, &lo) == PIERCE_OK);   /* port 0 = our bound port */
    CHECK(pierce_listen(srv.ctx, NULL) == PIERCE_OK);
    uint8_t inv[128];
    int ilen = pierce_get_invite(srv.ctx, inv, sizeof(inv));
    REQUIRE(ilen > 0);
    REQUIRE(pierce_connect(cli.ctx, NULL, inv, (uint32_t)ilen, &cli.conn) == PIERCE_OK);
    peer *ps[2] = {&srv, &cli};
    REQUIRE(pump_until(ps, 2, 5000, both_up));
    CHECK_EQ(cli.path, PIERCE_PATH_DIRECT);
    exchange(&srv, &cli);
    pierce_ctx_destroy(cli.ctx);
    pierce_ctx_destroy(srv.ctx);
}

static void test_udp_signaling(void)
{
    peer srv = {0}, cli = {0};
    srv.order_ok = cli.order_ok = 1;
    srv.ctx = make_ctx(0, NULL);
    cli.ctx = make_ctx(0, NULL);
    REQUIRE(srv.ctx && cli.ctx);
    srv.other = &cli;
    cli.other = &srv;
    pierce_listen(srv.ctx, NULL);
    uint8_t inv[128];
    int ilen = pierce_get_invite(srv.ctx, inv, sizeof(inv));   /* key only: no local addresses */
    REQUIRE(ilen == 37);
    REQUIRE(pierce_connect(cli.ctx, NULL, inv, (uint32_t)ilen, &cli.conn) == PIERCE_OK);
    peer *ps[2] = {&srv, &cli};
    REQUIRE(pump_until(ps, 2, 5000, both_up));
    exchange(&srv, &cli);
    pierce_ctx_destroy(cli.ctx);
    pierce_ctx_destroy(srv.ctx);
}

static volatile uint32_t relay_stop;

static void *relay_thread(void *arg)
{
    relay_loop_run((relay_loop_opts *)arg, &relay_stop);
    return NULL;
}

static void relay_case(const char *scheme, relay_loop_opts *o)
{
    char addr[64];
    uint16_t port = strcmp(scheme, "tcp://") == 0 ? o->bound_tcp_port : o->bound_udp_port;
    snprintf(addr, sizeof(addr), "%s127.0.0.1:%u", scheme, port);
    peer srv = {0}, cli = {0};
    srv.order_ok = cli.order_ok = 1;
    srv.ctx = make_ctx(PIERCE_CFG_RELAY_ONLY, addr);
    cli.ctx = make_ctx(PIERCE_CFG_RELAY_ONLY, addr);
    REQUIRE(srv.ctx && cli.ctx);
    srv.other = &cli;
    cli.other = &srv;
    pierce_listen(srv.ctx, NULL);
    peer *ps[2] = {&srv, &cli};
    pump(ps, 2, 300);                      /* let both allocate */
    pump(ps, 2, 300);
    REQUIRE(pierce_connect(cli.ctx, NULL, NULL, 0, &cli.conn) == PIERCE_OK);   /* XX */
    int ok = pump_until(ps, 2, 8000, both_up);
    if (!ok) fprintf(stderr, "  relay %s: no connection\n", addr);
    CHECK(ok);
    if (ok) {
        CHECK_EQ(cli.path, PIERCE_PATH_RELAY);
        exchange(&srv, &cli);
    }
    pierce_ctx_destroy(cli.ctx);
    pierce_ctx_destroy(srv.ctx);
}

static void test_relay_udp_and_tcp(void)
{
    relay_loop_opts o;
    memset(&o, 0, sizeof(o));
    o.open = 1;
    o.enable_tcp = 1;
    pthread_t th;
    pal_atomic_store(&relay_stop, 0);
    REQUIRE(pthread_create(&th, NULL, relay_thread, &o) == 0);
    for (int i = 0; i < 1000 && !pal_atomic_load(&o.ready); i++) sleep_ms(1);
    REQUIRE(pal_atomic_load(&o.ready) == 1);
    relay_case("", &o);
    relay_case("tcp://", &o);
    pal_atomic_store(&relay_stop, 1);
    pthread_join(th, NULL);
}

/* ---- threading: sends from many threads, blocking poll, wake ---- */

#define SENDERS 4
#define PER_SENDER 3000

typedef struct {
    pierce_ctx *ctx;
    pierce_conn_id conn;
    int who;
} sender_arg;

static void *sender(void *arg)
{
    sender_arg *a = (sender_arg *)arg;
    uint8_t buf[64];
    memset(buf, 0, sizeof(buf));
    buf[0] = (uint8_t)a->who;
    for (uint32_t i = 0; i < PER_SENDER; i++) {
        buf[4] = (uint8_t)(i >> 24); buf[5] = (uint8_t)(i >> 16); buf[6] = (uint8_t)(i >> 8); buf[7] = (uint8_t)i;
        int rc;
        while ((rc = pierce_send(a->ctx, a->conn, 0, buf, sizeof(buf), 0)) == PIERCE_ERR_WOULD_BLOCK)
            sched_yield();
        if (rc != PIERCE_OK) {
            fprintf(stderr, "sender %d: %s\n", a->who, pierce_strerror(rc));
            return NULL;
        }
    }
    return NULL;
}

typedef struct {
    peer *p;
    volatile uint32_t done;     /* atomic */
    int wakeups;
} poller_arg;

static void *poller(void *arg)
{
    poller_arg *a = (poller_arg *)arg;
    pierce_event ev[64];
    while (!pal_atomic_load(&a->done)) {
        int k = pierce_poll(a->p->ctx, ev, 64, -1);   /* block until events or a wake */
        if (k == 0) a->wakeups++;
        for (int j = 0; j < k; j++) handle(a->p, &ev[j]);
    }
    return NULL;
}

static void test_threads(void)
{
    peer srv = {0}, cli = {0};
    srv.order_ok = cli.order_ok = 1;
    srv.ctx = make_ctx(0, NULL);
    cli.ctx = make_ctx(0, NULL);
    REQUIRE(srv.ctx && cli.ctx);
    pierce_addr lo;
    pierce_addr_parse("127.0.0.1:0", &lo);
    pierce_add_local_address(srv.ctx, &lo);
    pierce_listen(srv.ctx, NULL);
    uint8_t inv[128];
    int ilen = pierce_get_invite(srv.ctx, inv, sizeof(inv));
    REQUIRE(pierce_connect(cli.ctx, NULL, inv, (uint32_t)ilen, &cli.conn) == PIERCE_OK);
    peer *ps[2] = {&srv, &cli};
    REQUIRE(pump_until(ps, 2, 5000, both_up));

    /* Server ctx is now owned by its own thread, blocked in pierce_poll(-1). */
    poller_arg pa = {&srv, 0, 0};
    pthread_t pt, st[SENDERS];
    sender_arg sa[SENDERS];
    REQUIRE(pthread_create(&pt, NULL, poller, &pa) == 0);
    for (int i = 0; i < SENDERS; i++) {
        sa[i].ctx = cli.ctx;
        sa[i].conn = cli.conn;
        sa[i].who = i + 1;
        REQUIRE(pthread_create(&st[i], NULL, sender, &sa[i]) == 0);
    }
    /* Main thread owns the client ctx and drives it while senders push. */
    pierce_event ev[64];
    for (int t = 0; t < 30000 && pal_atomic_load(&srv.msgs) < SENDERS * PER_SENDER; t++) {
        int k = pierce_poll(cli.ctx, ev, 64, 1);
        for (int j = 0; j < k; j++) handle(&cli, &ev[j]);
    }
    for (int i = 0; i < SENDERS; i++) pthread_join(st[i], NULL);
    CHECK_EQ(srv.msgs, SENDERS * PER_SENDER);
    CHECK(srv.order_ok);   /* each sender's messages arrive in its own order */

    /* pierce_wake unblocks the poller with zero events. */
    pal_atomic_store(&pa.done, 1);
    pierce_wake(srv.ctx);
    pthread_join(pt, NULL);
    CHECK(pa.wakeups >= 1);

    /* Retained messages outlive the poll and the context, released on
       another thread (spec 8.4). */
    pierce_ctx_destroy(cli.ctx);
    pierce_ctx_destroy(srv.ctx);
}

static void *release_on_thread(void *h)
{
    pierce_msg_release(h);
    return NULL;
}

static void test_retain(void)
{
    peer srv = {0}, cli = {0};
    srv.order_ok = cli.order_ok = 1;
    srv.ctx = make_ctx(0, NULL);
    cli.ctx = make_ctx(0, NULL);
    pierce_addr lo;
    pierce_addr_parse("127.0.0.1:0", &lo);
    pierce_add_local_address(srv.ctx, &lo);
    pierce_listen(srv.ctx, NULL);
    uint8_t inv[128];
    int ilen = pierce_get_invite(srv.ctx, inv, sizeof(inv));
    pierce_connect(cli.ctx, NULL, inv, (uint32_t)ilen, &cli.conn);
    peer *ps[2] = {&srv, &cli};
    REQUIRE(pump_until(ps, 2, 5000, both_up));
    pierce_send(cli.ctx, cli.conn, 0, (const uint8_t *)"keep me", 7, 0);
    void *h = NULL;
    pierce_event ev[16];
    for (int t = 0; t < 2000 && !h; t++) {
        pump(&ps[1], 1, 1);
        int k = pierce_poll(srv.ctx, ev, 16, 1);
        for (int j = 0; j < k; j++) {
            if (ev[j].type == PIERCE_EV_MESSAGE) {
                h = pierce_msg_retain(&ev[j]);
                uint8_t copy[16];
                CHECK_EQ(pierce_event_copy(&ev[j], copy, sizeof(copy)), 7);
                CHECK_EQ(pierce_event_copy(&ev[j], copy, 3), PIERCE_ERR_BUFFER_TOO_SMALL);
            } else {
                handle(&srv, &ev[j]);
            }
        }
    }
    REQUIRE(h);
    pierce_poll(srv.ctx, ev, 16, 0);       /* would invalidate borrowed data */
    pierce_ctx_destroy(cli.ctx);
    pierce_ctx_destroy(srv.ctx);
    uint32_t len;
    const uint8_t *d = pierce_msg_data(h, &len);
    CHECK(len == 7 && memcmp(d, "keep me", 7) == 0);
    pthread_t th;
    pthread_create(&th, NULL, release_on_thread, h);
    pthread_join(th, NULL);
}

static void test_get_fds_and_timeout(void)
{
    pierce_ctx *ctx = make_ctx(0, NULL);
    REQUIRE(ctx);
    pierce_socket fds[8];
    int n = pierce_get_fds(ctx, fds, 8);
    CHECK(n >= 2);                          /* one UDP socket (v4 only here) + wake */
    CHECK_EQ(pierce_next_timeout_ms(ctx), -1);
    /* A bounded poll with nothing to do returns after about the timeout. */
    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    pierce_event ev[4];
    CHECK_EQ(pierce_poll(ctx, ev, 4, 50), 0);
    clock_gettime(CLOCK_MONOTONIC, &b);
    long ms = (b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1000000;
    CHECK(ms >= 45 && ms < 500);
    pierce_ctx_destroy(ctx);
}

int main(void)
{
    RUN(test_udp_direct);
    RUN(test_udp_signaling);
    RUN(test_relay_udp_and_tcp);
    RUN(test_threads);
    RUN(test_retain);
    RUN(test_get_fds_and_timeout);
    TEST_MAIN_END();
}
#endif
