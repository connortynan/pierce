/* Integration over real sockets on loopback: builtin UDP, the reference
   relay over UDP and TCP, and the cross-thread send path (spec 7). */
#if defined(_WIN32)
int main(void) { return 0; }   /* POSIX threads below; Windows CI runs test_sim */
#else

#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <sched.h>
#include <time.h>

#include "../src/core.h"
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
    /* Tests stay on loopback: no public STUN servers, never the real router. */
    cfg.flags = flags | PIERCE_CFG_INCLUDE_LOOPBACK | PIERCE_CFG_NO_IPV6 | PIERCE_CFG_NO_DEFAULT_STUN |
                PIERCE_CFG_NO_PORT_MAPPING;
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

/* ---- UPnP against a fake router on loopback ---- */

void pierce__test_set_gateway(pierce_ctx *ctx, const pierce_addr *gw);
void pierce__test_set_ssdp(pierce_ctx *ctx, const pierce_addr *target);

typedef struct {
    pal_sock udp, tcp;
    uint16_t udp_port, tcp_port;
    volatile uint32_t stop;
    volatile uint32_t adds, deletes, ssdp_seen;   /* atomic: read by the test thread */
    char last_add[2048];
    char deleted_port[16];
} fake_igd;

static void igd_reply(pal_sock c, int status, int chunked, const char *body)
{
    char buf[4096];
    int n;
    if (chunked) {
        /* Split the body into two chunks to exercise de-chunking. */
        size_t bl = strlen(body), half = bl / 2;
        n = snprintf(buf, sizeof(buf),
                     "HTTP/1.1 %d OK\r\nContent-Type: text/xml\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                     "%zx\r\n%.*s\r\n%zx\r\n%s\r\n0\r\n\r\n",
                     status, half, (int)half, body, bl - half, body + half);
    } else {
        n = snprintf(buf, sizeof(buf),
                     "HTTP/1.1 %d %s\r\nContent-Type: text/xml\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
                     status, status == 200 ? "OK" : "Internal Server Error", strlen(body), body);
    }
    for (int off = 0; off < n;) {
        int k = pal_tcp_send(c, buf + off, (size_t)(n - off));
        if (k > 0) off += k;
        else if (k != PIERCE_ERR_WOULD_BLOCK) break;
        else sleep_ms(1);
    }
}

static void igd_handle(fake_igd *g, pal_sock c)
{
    char req[8192];
    int len = 0;
    for (int t = 0; t < 2000 && len < (int)sizeof(req) - 1; t++) {
        int k = pal_tcp_recv(c, req + len, sizeof(req) - 1 - (size_t)len);
        if (k > 0) {
            len += k;
            req[len] = 0;
            char *he = strstr(req, "\r\n\r\n");
            if (he) {
                char *cl = strstr(req, "Content-Length: ");
                int want = cl ? atoi(cl + 16) : 0;
                if ((int)(len - (he + 4 - req)) >= want) break;
            }
        } else if (k == 0) {
            break;
        } else {
            sleep_ms(1);
        }
    }
    req[len] = 0;
    if (!strncmp(req, "GET /rootDesc.xml", 17)) {
        igd_reply(c, 200, 1,
                  "<?xml version=\"1.0\"?><root><device><deviceList><device><deviceList><device>"
                  "<serviceList><service><serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>"
                  "<controlURL>/ctl/CmnIfCfg</controlURL></service>"
                  "<service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>"
                  "<controlURL>/ctl/IPConn</controlURL></service></serviceList>"
                  "</device></deviceList></device></deviceList></device></root>");
    } else if (strstr(req, "#GetExternalIPAddress")) {
        igd_reply(c, 200, 0,
                  "<s:Envelope><s:Body><u:GetExternalIPAddressResponse>"
                  "<NewExternalIPAddress>203.0.113.77</NewExternalIPAddress>"
                  "</u:GetExternalIPAddressResponse></s:Body></s:Envelope>");
    } else if (strstr(req, "#AddPortMapping")) {
        pal_atomic_add(&g->adds, 1);
        size_t rl = strlen(req) < sizeof(g->last_add) - 1 ? strlen(req) : sizeof(g->last_add) - 1;
        memcpy(g->last_add, req, rl);
        g->last_add[rl] = 0;
        if (pal_atomic_load(&g->adds) == 1)   /* the first attempt collides with another device's mapping */
            igd_reply(c, 500, 0, "<s:Envelope><s:Body><s:Fault><detail><UPnPError><errorCode>718</errorCode>"
                                 "</UPnPError></detail></s:Fault></s:Body></s:Envelope>");
        else
            igd_reply(c, 200, 0, "<s:Envelope><s:Body><u:AddPortMappingResponse/></s:Body></s:Envelope>");
    } else if (strstr(req, "#DeletePortMapping")) {
        char *p = strstr(req, "<NewExternalPort>");
        if (p) snprintf(g->deleted_port, sizeof(g->deleted_port), "%.*s", (int)strcspn(p + 17, "<"), p + 17);
        pal_atomic_add(&g->deletes, 1);   /* after deleted_port: the test reads it once this is set */
        igd_reply(c, 200, 0, "<s:Envelope><s:Body><u:DeletePortMappingResponse/></s:Body></s:Envelope>");
    } else {
        igd_reply(c, 500, 0, "");
    }
    pal_sock_close(c);
}

static void *igd_thread(void *arg)
{
    fake_igd *g = (fake_igd *)arg;
    char buf[1500];
    while (!pal_atomic_load(&g->stop)) {
        pal_pollfd f[2];
        memset(f, 0, sizeof(f));
        f[0].sock = g->udp;
        f[1].sock = g->tcp;
        if (pal_wait(f, 2, 20) <= 0) continue;
        if (f[0].readable) {
            pierce_addr from;
            int n = pal_udp_recv(g->udp, buf, sizeof(buf) - 1, &from);
            if (n > 0) {
                buf[n] = 0;
                if (strstr(buf, "M-SEARCH")) {
                    pal_atomic_add(&g->ssdp_seen, 1);
                    char r[300];
                    int rl = snprintf(r, sizeof(r),
                                      "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\n"
                                      "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
                                      "USN: uuid:fake-igd\r\nLocation: http://127.0.0.1:%u/rootDesc.xml\r\n\r\n",
                                      g->tcp_port);
                    pal_udp_send(g->udp, &from, r, (size_t)rl);
                }
            }
        }
        if (f[1].readable) {
            pal_sock c;
            while (pal_tcp_accept(g->tcp, &c, NULL) == PIERCE_OK) igd_handle(g, c);
        }
    }
    return NULL;
}

static void test_upnp(void)
{
    fake_igd g;
    memset(&g, 0, sizeof(g));
    pierce_addr la;
    REQUIRE(pal_udp_open(PIERCE_AF_INET, 0, &g.udp) == PIERCE_OK);
    REQUIRE(pal_tcp_listen(PIERCE_AF_INET, 0, &g.tcp) == PIERCE_OK);
    pal_sock_local_addr(g.udp, &la);
    g.udp_port = la.port;
    pal_sock_local_addr(g.tcp, &la);
    g.tcp_port = la.port;
    pthread_t th;
    REQUIRE(pthread_create(&th, NULL, igd_thread, &g) == 0);

    pierce_config cfg;
    pierce_config_init(&cfg);
    cfg.flags = PIERCE_CFG_NO_IPV6 | PIERCE_CFG_NO_DEFAULT_STUN;   /* port mapping stays on */
    pierce_ctx *ctx;
    REQUIRE(pierce_ctx_create(&cfg, &ctx) == PIERCE_OK);
    /* Point discovery at the fake. PCP goes to a dead loopback port, so the
       real router is never contacted. */
    pierce_addr gw, ssdp;
    pierce_addr_parse("127.0.0.1:0", &gw);
    pierce_addr_parse("127.0.0.1:1", &ssdp);
    ssdp.port = g.udp_port;
    pierce__test_set_gateway(ctx, &gw);
    pierce__test_set_ssdp(ctx, &ssdp);

    pierce_event ev[16];
    int mapped = 0;
    for (int t = 0; t < 400 && !mapped; t++) {
        pierce_poll(ctx, ev, 16, 10);
        mapped = (pc_gather_sig_flags(ctx) & PC_SIG_FLAG_MAPPED) != 0;
    }
    CHECK(mapped);
    CHECK(pal_atomic_load(&g.ssdp_seen) >= 1);
    CHECK_EQ(pal_atomic_load(&g.adds), 2);                       /* conflict, then success on another port */
    char want[64];
    snprintf(want, sizeof(want), "<NewInternalPort>%u</NewInternalPort>", ctx->port4);
    CHECK(strstr(g.last_add, want) != NULL);
    CHECK(strstr(g.last_add, "<NewInternalClient>127.0.0.1</NewInternalClient>") != NULL);
    CHECK(strstr(g.last_add, "<NewProtocol>UDP</NewProtocol>") != NULL);
    /* The mapped address is offered to peers as a candidate. */
    int found = 0;
    uint16_t ext_port = 0;
    for (uint32_t i = 0; i < ctx->ncands; i++)
        if (ctx->cands[i].addr.family == PIERCE_AF_INET && ctx->cands[i].addr.addr[0] == 203 &&
            ctx->cands[i].addr.addr[3] == 77) {
            found = 1;
            ext_port = ctx->cands[i].addr.port;
        }
    CHECK(found);
    CHECK(ext_port != 0 && ext_port != ctx->port4);   /* the retry picked a different port */

    /* Clean exit removes the mapping from the router. */
    pierce_ctx_destroy(ctx);
    for (int t = 0; t < 200 && !pal_atomic_load(&g.deletes); t++) sleep_ms(5);
    CHECK_EQ(pal_atomic_load(&g.deletes), 1);
    CHECK_EQ(atoi(g.deleted_port), ext_port);
    pal_atomic_store(&g.stop, 1);
    pthread_join(th, NULL);
    pal_sock_close(g.udp);
    pal_sock_close(g.tcp);
}

int main(void)
{
    RUN(test_udp_direct);
    RUN(test_udp_signaling);
    RUN(test_relay_udp_and_tcp);
    RUN(test_threads);
    RUN(test_retain);
    RUN(test_get_fds_and_timeout);
    RUN(test_upnp);
    TEST_MAIN_END();
}
#endif
