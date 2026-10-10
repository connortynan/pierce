/* End-to-end behaviour over the simulated network. */
#include "sim.h"
#include "test.h"

static sim S;

static int both_connected(sim *s, void *u)
{
    int *ab = (int *)u;
    return s->nodes[ab[0]].connected && s->nodes[ab[1]].connected;
}

static int any_disconnected(sim *s, void *u)
{
    int *ab = (int *)u;
    return s->nodes[ab[0]].disconnected || s->nodes[ab[1]].disconnected;
}

static int both_disconnected(sim *s, void *u)
{
    int *ab = (int *)u;
    return s->nodes[ab[0]].disconnected && s->nodes[ab[1]].disconnected;
}

static int has_msgs(sim *s, void *u)
{
    int *nm = (int *)u;   /* node, count */
    return s->nodes[nm[0]].nmsgs >= nm[1];
}

static void cfg_flags(pierce_config *cfg, void *u) { cfg->flags |= *(uint32_t *)u; }
static void cfg_idle(pierce_config *cfg, void *u)
{
    cfg->idle_timeout_ms = *(uint32_t *)u;
    cfg->keepalive_interval_ms = *(uint32_t *)u / 3;
}
static void cfg_sendbuf(pierce_config *cfg, void *u) { cfg->send_buffer_bytes = *(uint32_t *)u; }

typedef struct {
    const uint8_t *token;
    uint32_t len;
    uint32_t flags;
} token_cfg;
static void cfg_token(pierce_config *cfg, void *u)
{
    static const uint8_t *toks[1];
    static uint32_t lens[1];
    token_cfg *t = (token_cfg *)u;
    toks[0] = t->token;
    lens[0] = t->len;
    cfg->relay_tokens = toks;
    cfg->relay_token_lens = lens;
    cfg->flags |= t->flags;
}

/* Pair of public nodes, connected. Returns the client's conn id. */
static pierce_conn_id setup_pair(int mode, const pierce_conn_options *opt, int *srv, int *cli)
{
    *srv = sim_add_node(&S, -1);
    *cli = sim_add_node(&S, -1);
    pierce_listen(S.nodes[*srv].ctx, NULL);
    pierce_conn_id id = sim_connect(&S, *cli, *srv, opt, mode);
    int ab[2] = {*srv, *cli};
    if (!sim_run_until(&S, 10000000, both_connected, ab)) return 0;
    return id;
}

/* ---------------------------------------------------------------------- */

static void test_connect_modes(void)
{
    for (int mode = SIM_XX; mode <= SIM_DIRECT; mode++) {
        int srv, cli;
        sim_init(&S, 1 + (uint64_t)mode);
        pierce_conn_id id = setup_pair(mode, NULL, &srv, &cli);
        REQUIRE(id != 0);
        CHECK_EQ(S.nodes[srv].peer_requests, 1);
        CHECK_EQ(S.nodes[cli].peer_requests, mode == SIM_XX ? 1 : 0);   /* XX: client verifies host */

        uint8_t pk_srv[32], pk_cli[32];
        pierce_ctx_public_key(S.nodes[srv].ctx, pk_srv);
        pierce_ctx_public_key(S.nodes[cli].ctx, pk_cli);
        CHECK(memcmp(S.nodes[cli].last_peer_key, pk_srv, 32) == 0);
        CHECK(memcmp(S.nodes[srv].last_peer_key, pk_cli, 32) == 0);

        CHECK(pierce_send(S.nodes[cli].ctx, id, 0, (const uint8_t *)"hello", 5, 0) == PIERCE_OK);
        CHECK(pierce_send(S.nodes[srv].ctx, S.nodes[srv].last_conn, 0, (const uint8_t *)"world", 5, 0) == PIERCE_OK);
        int nm[2] = {srv, 1}, nm2[2] = {cli, 1};
        CHECK(sim_run_until(&S, 2000000, has_msgs, nm));
        CHECK(sim_run_until(&S, 2000000, has_msgs, nm2));
        CHECK(S.nodes[srv].nmsgs == 1 && memcmp(S.nodes[srv].msgs[0].data, "hello", 5) == 0);
        CHECK(S.nodes[cli].nmsgs == 1 && memcmp(S.nodes[cli].msgs[0].data, "world", 5) == 0);

        pierce_conn_info info;
        info.struct_size = sizeof(info);
        CHECK(pierce_conn_info_get(S.nodes[cli].ctx, id, &info) == PIERCE_OK);
        CHECK_EQ(info.path, PIERCE_PATH_DIRECT);
        if (!(info.rtt_us >= 20000 && info.rtt_us < 50000)) fprintf(stderr, "  rtt %llu us\n", (unsigned long long)info.rtt_us);
        CHECK(info.rtt_us >= 20000 && info.rtt_us < 50000);   /* 2 x 10 ms link, plus ack delay */
        sim_free(&S);
    }
}

static int expect_direct(int a, int b)
{
    /* Pairs that hole punching cannot handle without a relay. */
    if (a == NAT_SYMMETRIC && b == NAT_SYMMETRIC) return 0;
    if ((a == NAT_SYMMETRIC && b == NAT_PORT_RESTRICTED) || (b == NAT_SYMMETRIC && a == NAT_PORT_RESTRICTED))
        return 0;
    return 1;
}

static void test_nat_matrix(void)
{
    for (int with_relay = 0; with_relay <= 1; with_relay++) {
        for (int a = NAT_NONE; a <= NAT_SYMMETRIC; a++) {
            for (int b = NAT_NONE; b <= NAT_SYMMETRIC; b++) {
                sim_init(&S, 100 + (uint64_t)(a * 7 + b));
                sim_enable_stun(&S);
                if (with_relay) sim_enable_relay(&S, NULL, 0);
                int srv = sim_add_node(&S, a == NAT_NONE ? -1 : sim_add_nat(&S, a));
                int cli = sim_add_node(&S, b == NAT_NONE ? -1 : sim_add_nat(&S, b));
                pierce_listen(S.nodes[srv].ctx, NULL);
                sim_run(&S, 1500000);   /* let STUN and relay allocation finish */
                pierce_conn_id id = sim_connect(&S, cli, srv, NULL, SIM_IK);
                int ab[2] = {srv, cli};
                int ok = sim_run_until(&S, 20000000, both_connected, ab);
                int want = with_relay || expect_direct(a, b);
                if (ok != want)
                    fprintf(stderr, "  NAT %s <- %s (relay %d): connected=%d expected=%d\n",
                            nat_name(a), nat_name(b), with_relay, ok, want);
                CHECK_EQ(ok, want);
                if (ok) {
                    /* Relay only when hole punching cannot work. */
                    uint32_t want_path = expect_direct(a, b) ? PIERCE_PATH_DIRECT : PIERCE_PATH_RELAY;
                    if (S.nodes[cli].last_path != want_path)
                        fprintf(stderr, "  NAT %s <- %s (relay %d): path %u expected %u\n", nat_name(a),
                                nat_name(b), with_relay, S.nodes[cli].last_path, want_path);
                    CHECK_EQ(S.nodes[cli].last_path, want_path);
                    pierce_send(S.nodes[cli].ctx, id, 0, (const uint8_t *)"x", 1, 0);
                    int nm[2] = {srv, 1};
                    CHECK(sim_run_until(&S, 3000000, has_msgs, nm));
                } else {
                    CHECK(S.nodes[cli].disconnected == 1 && S.nodes[cli].last_error == PIERCE_ERR_UNREACHABLE);
                }
                sim_free(&S);
            }
        }
    }
}

static void test_reject(void)
{
    sim_init(&S, 3);
    int srv = sim_add_node(&S, -1), cli = sim_add_node(&S, -1);
    pierce_listen(S.nodes[srv].ctx, NULL);
    S.nodes[srv].reject_reason = PIERCE_REASON_APP_BASE + 7;
    sim_connect(&S, cli, srv, NULL, SIM_IK);
    int ab[2] = {srv, cli};
    CHECK(sim_run_until(&S, 5000000, both_disconnected, ab));
    CHECK_EQ(S.nodes[cli].connected, 0);
    CHECK_EQ(S.nodes[cli].last_error, PIERCE_ERR_REJECTED);
    CHECK_EQ(S.nodes[cli].last_reason, PIERCE_REASON_APP_BASE + 7);
    CHECK_EQ(S.nodes[srv].last_error, PIERCE_OK);
    sim_free(&S);
}

static void test_client_rejects_host_key(void)
{
    sim_init(&S, 4);
    int srv = sim_add_node(&S, -1), cli = sim_add_node(&S, -1);
    pierce_listen(S.nodes[srv].ctx, NULL);
    S.nodes[cli].reject_reason = PIERCE_REASON_POLICY;
    sim_connect(&S, cli, srv, NULL, SIM_XX);
    int ab[2] = {cli, cli};
    CHECK(sim_run_until(&S, 5000000, any_disconnected, ab));
    CHECK_EQ(S.nodes[cli].peer_requests, 1);
    CHECK_EQ(S.nodes[cli].last_error, PIERCE_OK);
    CHECK_EQ(S.nodes[srv].connected, 0);
    sim_free(&S);
}

static void test_channel_mismatch(void)
{
    pierce_channel_config a[2], b[2];
    for (int i = 0; i < 2; i++) {
        pierce_channel_config_init(&a[i]);
        pierce_channel_config_init(&b[i]);
        a[i].id = b[i].id = (uint32_t)i;
    }
    a[0].flags = b[0].flags = PIERCE_CHANNEL_RELIABLE | PIERCE_CHANNEL_ORDERED;
    a[1].flags = PIERCE_CHANNEL_SEQUENCED;
    b[1].flags = PIERCE_CHANNEL_RELIABLE;
    pierce_conn_options lo, co;
    pierce_conn_options_init(&lo);
    pierce_conn_options_init(&co);
    lo.channels = a;
    lo.channel_count = 2;
    co.channels = b;
    co.channel_count = 2;

    sim_init(&S, 5);
    int srv = sim_add_node(&S, -1), cli = sim_add_node(&S, -1);
    pierce_listen(S.nodes[srv].ctx, &lo);
    sim_connect(&S, cli, srv, &co, SIM_IK);
    int ab[2] = {cli, cli};
    CHECK(sim_run_until(&S, 5000000, any_disconnected, ab));
    CHECK_EQ(S.nodes[cli].last_error, PIERCE_ERR_REJECTED);
    CHECK_EQ(S.nodes[cli].last_reason, PIERCE_REASON_CHANNEL_MISMATCH);
    CHECK_EQ(S.nodes[srv].peer_requests, 0);
    sim_free(&S);

    /* Matching tables connect, and both sides agree on the table. */
    sim_init(&S, 6);
    srv = sim_add_node(&S, -1);
    cli = sim_add_node(&S, -1);
    pierce_listen(S.nodes[srv].ctx, &lo);
    co.channels = a;
    pierce_conn_id id = sim_connect(&S, cli, srv, &co, SIM_IK);
    int cc[2] = {srv, cli};
    CHECK(sim_run_until(&S, 5000000, both_connected, cc));
    pierce_channel_config got[4];
    CHECK_EQ(pierce_conn_channels(S.nodes[srv].ctx, S.nodes[srv].last_conn, got, 4), 2);
    CHECK_EQ(pierce_conn_channels(S.nodes[cli].ctx, id, got, 4), 2);
    sim_free(&S);
}

/* Channel payloads carry a 4-byte sequence number then filler. */
static uint32_t msg_seq(const sim_msg *m) { return pc_get32(m->data); }

static void send_seq(pierce_ctx *ctx, pierce_conn_id id, uint32_t ch, uint32_t seq, uint32_t len)
{
    uint8_t *buf = (uint8_t *)malloc(len < 4 ? 4 : len);
    pc_put32(buf, seq);
    for (uint32_t i = 4; i < len; i++) buf[i] = (uint8_t)(seq * 31 + i);
    int rc = pierce_send(ctx, id, ch, buf, len < 4 ? 4 : len, 0);
    if (rc != PIERCE_OK) fprintf(stderr, "send_seq: %s\n", pierce_strerror(rc));
    free(buf);
}

static int payload_ok(const sim_msg *m)
{
    uint32_t seq = msg_seq(m);
    for (uint32_t i = 4; i < m->len; i++)
        if (m->data[i] != (uint8_t)(seq * 31 + i)) return 0;
    return 1;
}

static pierce_channel_config chans[4];
static pierce_conn_options chan_opts(void)
{
    pierce_conn_options o;
    for (int i = 0; i < 4; i++) {
        pierce_channel_config_init(&chans[i]);
        chans[i].id = (uint32_t)i;
    }
    chans[0].flags = PIERCE_CHANNEL_RELIABLE | PIERCE_CHANNEL_ORDERED;
    chans[1].flags = PIERCE_CHANNEL_RELIABLE;
    chans[2].flags = PIERCE_CHANNEL_SEQUENCED;
    chans[2].priority = 10;
    chans[3].flags = 0;
    chans[0].max_message_size = 1u << 20;
    chans[1].max_message_size = 1u << 20;
    pierce_conn_options_init(&o);
    o.channels = chans;
    o.channel_count = 4;
    return o;
}

static void test_reliable_under_loss(void)
{
    int srv, cli;
    sim_init(&S, 7);
    pierce_conn_options o = chan_opts();
    pierce_conn_id id = setup_pair(SIM_IK, &o, &srv, &cli);
    REQUIRE(id != 0);
    S.loss_ppm = 100000;      /* 10% */
    S.jitter_us = 20000;      /* reordering */
    S.dup_ppm = 20000;
    const uint32_t N = 300;
    for (uint32_t i = 0; i < N; i++) {
        uint32_t len = (i % 50 == 7) ? 100000 : 10 + (i * 37) % 3000;  /* some fragmented */
        send_seq(S.nodes[cli].ctx, id, 0, i, len);
    }
    int nm[2] = {srv, (int)N};
    CHECK(sim_run_until(&S, 120000000, has_msgs, nm));
    sim_run(&S, 2000000);
    CHECK_EQ(S.nodes[srv].nmsgs, N);   /* exactly once */
    int in_order = 1, intact = 1;
    for (int i = 0; i < S.nodes[srv].nmsgs; i++) {
        if (msg_seq(&S.nodes[srv].msgs[i]) != (uint32_t)i) in_order = 0;
        if (!payload_ok(&S.nodes[srv].msgs[i])) intact = 0;
    }
    CHECK(in_order);
    CHECK(intact);
    pierce_conn_info info;
    info.struct_size = sizeof(info);
    pierce_conn_info_get(S.nodes[cli].ctx, id, &info);
    CHECK(info.packets_lost > 0);
    sim_free(&S);
}

static void test_reliable_unordered(void)
{
    int srv, cli;
    sim_init(&S, 8);
    pierce_conn_options o = chan_opts();
    pierce_conn_id id = setup_pair(SIM_IK, &o, &srv, &cli);
    REQUIRE(id != 0);
    S.loss_ppm = 50000;
    S.jitter_us = 30000;
    const uint32_t N = 200;
    for (uint32_t i = 0; i < N; i++) send_seq(S.nodes[cli].ctx, id, 1, i, 50 + (i % 5) * 900);
    int nm[2] = {srv, (int)N};
    CHECK(sim_run_until(&S, 60000000, has_msgs, nm));
    sim_run(&S, 2000000);
    CHECK_EQ(S.nodes[srv].nmsgs, N);
    uint8_t seen[200];
    memset(seen, 0, sizeof(seen));
    int dup = 0, ooo = 0;
    for (int i = 0; i < S.nodes[srv].nmsgs; i++) {
        uint32_t q = msg_seq(&S.nodes[srv].msgs[i]);
        if (q < N && seen[q]++) dup = 1;
        if (q != (uint32_t)i) ooo = 1;
    }
    CHECK(!dup);
    CHECK(ooo);   /* with jitter, unordered delivery really is unordered */
    sim_free(&S);
}

static void test_sequenced(void)
{
    /* Phase 1: heavy reordering (jitter far above the send interval). A
       sequenced channel must never deliver an older message after a newer
       one, which means it drops most of them here. */
    for (int phase = 0; phase < 2; phase++) {
        int srv, cli;
        sim_init(&S, 9 + (uint64_t)phase);
        pierce_conn_options o = chan_opts();
        pierce_conn_id id = setup_pair(SIM_IK, &o, &srv, &cli);
        REQUIRE(id != 0);
        S.loss_ppm = phase == 0 ? 50000 : 10000;
        S.jitter_us = phase == 0 ? 30000 : 1000;
        for (uint32_t i = 0; i < 500; i++) {
            send_seq(S.nodes[cli].ctx, id, 2, i, i % 10 == 0 ? 3000 : 100);
            sim_run(&S, 5000);
        }
        sim_run(&S, 2000000);
        int increasing = 1;
        uint32_t last = 0;
        for (int i = 0; i < S.nodes[srv].nmsgs; i++) {
            uint32_t q = msg_seq(&S.nodes[srv].msgs[i]);
            if (i && q <= last) increasing = 0;
            last = q;
        }
        CHECK(increasing);
        /* Phase 2: realistic jitter and 1% loss. Losses, plus snapshots
           superseded while a 3-fragment message waits for congestion
           window, cost a few deliveries. */
        if (phase == 1) {
            if (S.nodes[srv].nmsgs < 450) fprintf(stderr, "  sequenced: %d of 500\n", S.nodes[srv].nmsgs);
            CHECK(S.nodes[srv].nmsgs >= 450 && S.nodes[srv].nmsgs < 500);
        }
        sim_free(&S);
    }
}

static void test_rekey(void)
{
    int srv, cli;
    pierce__test_set_rekey_packets(40);
    sim_init(&S, 10);
    pierce_conn_id id = setup_pair(SIM_IK, NULL, &srv, &cli);
    REQUIRE(id != 0);
    S.jitter_us = 15000;
    S.loss_ppm = 20000;
    const uint32_t N = 400;
    for (uint32_t i = 0; i < N; i++) {
        send_seq(S.nodes[cli].ctx, id, 0, i, 200);
        send_seq(S.nodes[srv].ctx, S.nodes[srv].last_conn, 0, i, 200);
        sim_run(&S, 2000);
    }
    int nm[2] = {srv, (int)N}, nm2[2] = {cli, (int)N};
    CHECK(sim_run_until(&S, 30000000, has_msgs, nm));
    CHECK(sim_run_until(&S, 30000000, has_msgs, nm2));
    pierce__test_set_rekey_packets(0);
    sim_free(&S);
}

static void test_migration(void)
{
    sim_init(&S, 11);
    sim_enable_stun(&S);
    int srv = sim_add_node(&S, -1);
    int nat = sim_add_nat(&S, NAT_FULL_CONE);
    int cli = sim_add_node(&S, nat);
    pierce_listen(S.nodes[srv].ctx, NULL);
    sim_run(&S, 1000000);
    pierce_conn_id id = sim_connect(&S, cli, srv, NULL, SIM_DIRECT);
    int ab[2] = {srv, cli};
    REQUIRE(sim_run_until(&S, 5000000, both_connected, ab));
    send_seq(S.nodes[cli].ctx, id, 0, 0, 10);
    sim_run(&S, 500000);
    sim_nat_rebind(&S, nat);   /* client's public port changes */
    for (uint32_t i = 1; i <= 20; i++) {
        send_seq(S.nodes[cli].ctx, id, 0, i, 10);
        send_seq(S.nodes[srv].ctx, S.nodes[srv].last_conn, 0, i, 10);
        sim_run(&S, 50000);
    }
    sim_run(&S, 2000000);
    CHECK_EQ(S.nodes[srv].nmsgs, 21);
    CHECK_EQ(S.nodes[cli].nmsgs, 20);
    CHECK_EQ(S.nodes[srv].path_changes, 1);
    CHECK_EQ(S.nodes[srv].disconnected + S.nodes[cli].disconnected, 0);
    sim_free(&S);
}

static void test_idle_timeout(void)
{
    uint32_t idle = 3000;
    sim_init(&S, 12);
    int srv = sim_add_node_cfg(&S, -1, cfg_idle, &idle);
    int cli = sim_add_node_cfg(&S, -1, cfg_idle, &idle);
    pierce_listen(S.nodes[srv].ctx, NULL);
    sim_connect(&S, cli, srv, NULL, SIM_IK);
    int ab[2] = {srv, cli};
    REQUIRE(sim_run_until(&S, 5000000, both_connected, ab));
    /* Keepalives hold an idle connection open well past the idle timeout. */
    sim_run(&S, 10000000);
    CHECK_EQ(S.nodes[srv].disconnected + S.nodes[cli].disconnected, 0);
    S.drop_all = 1;
    uint64_t t0 = S.now;
    CHECK(sim_run_until(&S, 10000000, both_disconnected, ab));
    /* The idle clock runs from the last packet received, which is at most
       one keepalive interval (1 s) before the blackout began. */
    CHECK(S.now - t0 >= 2000000 && S.now - t0 <= 3100000);
    CHECK_EQ(S.nodes[srv].last_error, PIERCE_ERR_TIMEOUT);
    CHECK_EQ(S.nodes[cli].last_error, PIERCE_ERR_TIMEOUT);
    sim_free(&S);
}

static void test_close(void)
{
    int srv, cli;
    sim_init(&S, 13);
    pierce_conn_id id = setup_pair(SIM_IK, NULL, &srv, &cli);
    REQUIRE(id != 0);
    CHECK(pierce_close(S.nodes[cli].ctx, id, PIERCE_REASON_APP_BASE + 1) == PIERCE_OK);
    CHECK(pierce_send(S.nodes[cli].ctx, id, 0, (const uint8_t *)"x", 1, 0) == PIERCE_ERR_CLOSED);
    int ab[2] = {srv, cli};
    CHECK(sim_run_until(&S, 2000000, both_disconnected, ab));
    CHECK_EQ(S.nodes[srv].last_error, PIERCE_ERR_CLOSED);
    CHECK_EQ(S.nodes[srv].last_reason, PIERCE_REASON_APP_BASE + 1);
    CHECK_EQ(S.nodes[cli].last_error, PIERCE_OK);
    sim_run(&S, 10000);
    /* After DISCONNECTED was polled, the ID is stale. */
    CHECK(pierce_send(S.nodes[cli].ctx, id, 0, (const uint8_t *)"x", 1, 0) == PIERCE_ERR_NO_SUCH_CONN);
    sim_free(&S);
}

static void test_backpressure(void)
{
    uint32_t buf = 8000;
    sim_init(&S, 14);
    int srv = sim_add_node(&S, -1);
    int cli = sim_add_node_cfg(&S, -1, cfg_sendbuf, &buf);
    pierce_listen(S.nodes[srv].ctx, NULL);
    pierce_conn_id id = sim_connect(&S, cli, srv, NULL, SIM_IK);
    int ab[2] = {srv, cli};
    REQUIRE(sim_run_until(&S, 5000000, both_connected, ab));
    uint8_t data[1000];
    memset(data, 7, sizeof(data));
    int sent = 0, rc;
    while ((rc = pierce_send(S.nodes[cli].ctx, id, 0, data, sizeof(data), 0)) == PIERCE_OK) sent++;
    CHECK_EQ(rc, PIERCE_ERR_WOULD_BLOCK);
    CHECK(sent >= 7 && sent <= 8);
    int nm[2] = {srv, sent};
    CHECK(sim_run_until(&S, 5000000, has_msgs, nm));
    sim_run(&S, 200000);
    CHECK_EQ(S.nodes[cli].low_events, 1);
    CHECK(pierce_send(S.nodes[cli].ctx, id, 0, data, sizeof(data), 0) == PIERCE_OK);
    sim_free(&S);
}

static void test_relay_only(void)
{
    uint32_t fl = PIERCE_CFG_RELAY_ONLY;
    sim_init(&S, 15);
    sim_enable_stun(&S);
    sim_enable_relay(&S, NULL, 0);
    int srv = sim_add_node_cfg(&S, sim_add_nat(&S, NAT_FULL_CONE), cfg_flags, &fl);
    int cli = sim_add_node_cfg(&S, sim_add_nat(&S, NAT_FULL_CONE), cfg_flags, &fl);
    pierce_listen(S.nodes[srv].ctx, NULL);
    sim_run(&S, 1000000);
    pierce_conn_id id = sim_connect(&S, cli, srv, NULL, SIM_IK);
    int ab[2] = {srv, cli};
    REQUIRE(sim_run_until(&S, 10000000, both_connected, ab));
    CHECK_EQ(S.nodes[cli].last_path, PIERCE_PATH_RELAY);
    send_seq(S.nodes[cli].ctx, id, 0, 1, 3000);
    int nm[2] = {srv, 1};
    CHECK(sim_run_until(&S, 3000000, has_msgs, nm));
    /* Never a datagram straight to the peer, so the peer never learns our address. */
    CHECK_EQ(S.nodes[cli].sent_direct, 0);
    CHECK_EQ(S.nodes[srv].sent_direct, 0);
    CHECK(S.nodes[cli].sent_relay > 0);
    sim_free(&S);
}

static void test_relay_tokens(void)
{
    static const uint8_t secret[] = "relay-shared-secret";
    uint8_t good[PIERCE_RELAY_TOKEN_SIZE], bad[PIERCE_RELAY_TOKEN_SIZE];
    uint64_t expiry = 1700000000ull + 3600;
    CHECK_EQ(pierce_relay_token_create(secret, sizeof(secret), expiry, 0, good, sizeof(good)),
             PIERCE_RELAY_TOKEN_SIZE);
    memcpy(bad, good, sizeof(bad));
    bad[20] ^= 1;
    token_cfg tg = {good, sizeof(good), PIERCE_CFG_RELAY_ONLY};
    token_cfg tb = {bad, sizeof(bad), PIERCE_CFG_RELAY_ONLY};

    sim_init(&S, 16);
    sim_enable_relay(&S, secret, sizeof(secret));
    int srv = sim_add_node_cfg(&S, sim_add_nat(&S, NAT_SYMMETRIC), cfg_token, &tg);
    int cli = sim_add_node_cfg(&S, sim_add_nat(&S, NAT_SYMMETRIC), cfg_token, &tg);
    int evil = sim_add_node_cfg(&S, sim_add_nat(&S, NAT_SYMMETRIC), cfg_token, &tb);
    pierce_listen(S.nodes[srv].ctx, NULL);
    sim_run(&S, 1000000);
    CHECK_EQ(pc_rs_alloc_count(S.relay), 2);   /* the bad token was refused */
    sim_connect(&S, cli, srv, NULL, SIM_IK);
    int ab[2] = {srv, cli};
    CHECK(sim_run_until(&S, 10000000, both_connected, ab));
    sim_connect(&S, evil, srv, NULL, SIM_IK);
    int ev[2] = {evil, evil};
    CHECK(sim_run_until(&S, 20000000, any_disconnected, ev));
    CHECK_EQ(S.nodes[evil].last_error, PIERCE_ERR_UNREACHABLE);
    sim_free(&S);
}

static void test_lifetime_abandon(void)
{
    pierce_channel_config ch;
    pierce_channel_config_init(&ch);
    ch.flags = PIERCE_CHANNEL_RELIABLE | PIERCE_CHANNEL_ORDERED;
    ch.max_lifetime_ms = 200;
    pierce_conn_options o;
    pierce_conn_options_init(&o);
    o.channels = &ch;
    o.channel_count = 1;
    int srv, cli;
    sim_init(&S, 17);
    pierce_conn_id id = setup_pair(SIM_IK, &o, &srv, &cli);
    REQUIRE(id != 0);
    /* Messages 0-4 sent into a black hole expire; 5-9 must still arrive in
       order once the network returns (the receiver skips the abandoned seqs). */
    S.drop_all = 1;
    for (uint32_t i = 0; i < 5; i++) send_seq(S.nodes[cli].ctx, id, 0, i, 20);
    sim_run(&S, 1500000);
    S.drop_all = 0;
    for (uint32_t i = 5; i < 10; i++) send_seq(S.nodes[cli].ctx, id, 0, i, 20);
    int nm[2] = {srv, 5};
    CHECK(sim_run_until(&S, 10000000, has_msgs, nm));
    sim_run(&S, 1000000);
    CHECK_EQ(S.nodes[srv].nmsgs, 5);
    for (int i = 0; i < S.nodes[srv].nmsgs; i++) CHECK_EQ(msg_seq(&S.nodes[srv].msgs[i]), 5 + i);
    sim_free(&S);
}

static int path_is_direct(sim *s, void *u)
{
    int *nc = (int *)u;   /* node, conn index unused */
    pierce_conn_info info;
    info.struct_size = sizeof(info);
    if (pierce_conn_info_get(s->nodes[nc[0]].ctx, s->nodes[nc[0]].last_conn, &info) != PIERCE_OK) return 0;
    return info.path == PIERCE_PATH_DIRECT;
}

static void test_relay_upgrade(void)
{
    sim_init(&S, 23);
    sim_enable_stun(&S);
    sim_enable_relay(&S, NULL, 0);
    int srv = sim_add_node(&S, sim_add_nat(&S, NAT_PORT_RESTRICTED));
    int cli = sim_add_node(&S, sim_add_nat(&S, NAT_RESTRICTED));
    pierce_listen(S.nodes[srv].ctx, NULL);
    sim_run(&S, 1000000);
    S.block_direct = 1;              /* e.g. a firewall that relents later */
    pierce_conn_id id = sim_connect(&S, cli, srv, NULL, SIM_IK);
    int ab[2] = {srv, cli};
    REQUIRE(sim_run_until(&S, 10000000, both_connected, ab));
    CHECK_EQ(S.nodes[cli].last_path, PIERCE_PATH_RELAY);
    sim_run(&S, 1000000);
    S.block_direct = 0;
    int nc[2] = {cli, 0}, ns[2] = {srv, 0};
    CHECK(sim_run_until(&S, 10000000, path_is_direct, nc));
    send_seq(S.nodes[cli].ctx, id, 0, 1, 50);   /* server follows on the next packet */
    CHECK(sim_run_until(&S, 2000000, path_is_direct, ns));
    CHECK(S.nodes[cli].path_changes >= 1);
    CHECK(S.nodes[srv].path_changes >= 1);
    int nm[2] = {srv, 1};
    CHECK(sim_run_until(&S, 2000000, has_msgs, nm));
    CHECK_EQ(S.nodes[srv].disconnected + S.nodes[cli].disconnected, 0);
    sim_free(&S);
}

static int all_clients_connected(sim *s, void *u)
{
    int n = *(int *)u;
    return s->nodes[0].connected >= n;
}

static void test_many_clients(void)
{
    const int N = 200;
    sim_init(&S, 18);
    sim_enable_stun(&S);
    int srv = sim_add_node(&S, -1);
    pierce_listen(S.nodes[srv].ctx, NULL);
    for (int i = 0; i < N; i++) sim_add_node(&S, sim_add_nat(&S, i % 2 ? NAT_PORT_RESTRICTED : NAT_SYMMETRIC));
    sim_run(&S, 1000000);
    pierce_conn_id ids[200];
    for (int i = 0; i < N; i++) ids[i] = sim_connect(&S, 1 + i, srv, NULL, SIM_DIRECT);
    int n = N;
    CHECK(sim_run_until(&S, 20000000, all_clients_connected, &n));
    CHECK_EQ(S.nodes[srv].connected, N);
    for (int i = 0; i < N; i++) send_seq(S.nodes[1 + i].ctx, ids[i], 0, (uint32_t)i, 64);
    int nm[2] = {srv, N};
    CHECK(sim_run_until(&S, 5000000, has_msgs, nm));

    /* Fan-out with send_many: one call, every client gets it. */
    pierce_conn_id sids[200];
    int ns = 0;
    for (pierce_conn_id k = 0; k < 2000 && ns < N; k++) {
        /* Collect the server-side IDs from the messages it received. */
        if (k < (pierce_conn_id)S.nodes[srv].nmsgs) sids[ns++] = S.nodes[srv].msgs[k].conn;
    }
    CHECK_EQ(pierce_send_many(S.nodes[srv].ctx, sids, (uint32_t)ns, 0, (const uint8_t *)"all", 3, 0), N);
    sim_run(&S, 1000000);
    int got = 0;
    for (int i = 0; i < N; i++) got += S.nodes[1 + i].nmsgs == 1;
    CHECK_EQ(got, N);
    sim_free(&S);
}

static void test_fuzz_input(void)
{
    int srv, cli;
    sim_init(&S, 19);
    pierce_conn_id id = setup_pair(SIM_IK, NULL, &srv, &cli);
    REQUIRE(id != 0);
    pierce_ctx *ctx = S.nodes[srv].ctx;
    pierce_addr from = S.nodes[cli].priv;   /* even from the real peer's address */
    uint8_t buf[1400];
    uint8_t types[] = {0x00, 0x01, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x60, 0x61, 0x64, 0xff};
    for (int i = 0; i < 200000; i++) {
        uint32_t len = (uint32_t)(sim_rand(&S) % sizeof(buf));
        for (uint32_t k = 0; k < len; k++) buf[k] = (uint8_t)sim_rand(&S);
        if (len) buf[0] = types[sim_rand(&S) % sizeof(types)];
        if (len > 10 && buf[0] == 0x56) {
            buf[1] = 8;
            memcpy(buf + 2, S.nodes[srv].ctx->conns->local_cid, 8);   /* hit a real connection */
        }
        pierce__test_set_time(ctx, S.now);
        pierce_transport_in(ctx, &from, buf, len);
        if (i % 1000 == 0) sim_step(&S, 1000);
    }
    /* The connection survives garbage. */
    send_seq(S.nodes[cli].ctx, id, 0, 42, 100);
    int nm[2] = {srv, 1};
    CHECK(sim_run_until(&S, 3000000, has_msgs, nm));
    CHECK_EQ(S.nodes[srv].disconnected, 0);

    /* And signal_in with garbage. */
    for (int i = 0; i < 50000; i++) {
        uint32_t len = (uint32_t)(sim_rand(&S) % 600);
        for (uint32_t k = 0; k < len; k++) buf[k] = (uint8_t)sim_rand(&S);
        if (len > 2) { buf[0] = 'P'; buf[1] = 'S'; buf[2] = 1; }
        pierce_conn_id out;
        pierce_signal_in(ctx, buf, len, &out);
    }
    sim_free(&S);
}

static void test_api_errors(void)
{
    pierce_config cfg;
    pierce_ctx *ctx;
    pierce_config_init(&cfg);
    cfg.flags = PIERCE_CFG_NO_BUILTIN_UDP;
    REQUIRE(pierce_ctx_create(&cfg, &ctx) == PIERCE_OK);
    CHECK(pierce_send(ctx, 12345, 0, (const uint8_t *)"x", 1, 0) == PIERCE_ERR_NO_SUCH_CONN);
    CHECK(pierce_send(ctx, ((uint64_t)1 << 53) | 1, 0, (const uint8_t *)"x", 1, 0) == PIERCE_ERR_NO_SUCH_CONN);
    CHECK(pierce_accept(ctx, 99, 0) == PIERCE_ERR_NO_SUCH_CONN);
    pierce_conn_id id;
    CHECK(pierce_connect(ctx, NULL, (const uint8_t *)"garbage", 7, &id) == PIERCE_ERR_INVALID_ARG);
    pierce_channel_config bad;
    pierce_channel_config_init(&bad);
    bad.flags = PIERCE_CHANNEL_RELIABLE | PIERCE_CHANNEL_SEQUENCED;
    pierce_conn_options o;
    pierce_conn_options_init(&o);
    o.channels = &bad;
    o.channel_count = 1;
    CHECK(pierce_connect(ctx, &o, NULL, 0, &id) == PIERCE_ERR_INVALID_ARG);
    /* Offers are refused unless listening. */
    pierce_ctx *other;
    REQUIRE(pierce_ctx_create(&cfg, &other) == PIERCE_OK);
    pierce_event ev[8];
    CHECK(pierce_connect(other, NULL, NULL, 0, &id) == PIERCE_OK);
    int n = pierce_poll(other, ev, 8, 0);
    CHECK(n == 1 && ev[0].type == PIERCE_EV_SIGNAL_OUT);
    CHECK(pierce_signal_in(ctx, ev[0].data, ev[0].data_len, NULL) == PIERCE_ERR_STATE);
    CHECK(ev[0].conn_id < ((uint64_t)1 << 53));
    /* Sends before the connection is up are queued, not refused. */
    CHECK(pierce_send(other, id, 0, (const uint8_t *)"early", 5, 0) == PIERCE_OK);
    CHECK(pierce_send(other, id, 9, (const uint8_t *)"x", 1, 0) == PIERCE_ERR_INVALID_ARG);
    pierce_ctx_destroy(other);
    pierce_ctx_destroy(ctx);
}

static void test_early_send_delivered(void)
{
    sim_init(&S, 20);
    int srv = sim_add_node(&S, -1), cli = sim_add_node(&S, -1);
    pierce_listen(S.nodes[srv].ctx, NULL);
    pierce_conn_id id = sim_connect(&S, cli, srv, NULL, SIM_IK);
    for (uint32_t i = 0; i < 10; i++) send_seq(S.nodes[cli].ctx, id, 0, i, 100);
    int nm[2] = {srv, 10};
    CHECK(sim_run_until(&S, 5000000, has_msgs, nm));
    for (int i = 0; i < S.nodes[srv].nmsgs; i++) CHECK_EQ(msg_seq(&S.nodes[srv].msgs[i]), i);
    sim_free(&S);
}

static void test_stale_invite_costs_nothing(void)
{
    sim_init(&S, 24);
    int srv = sim_add_node(&S, -1), cli = sim_add_node(&S, -1);
    pierce_listen(S.nodes[srv].ctx, NULL);
    uint8_t inv[128];
    int ilen = pierce_get_invite(S.nodes[srv].ctx, inv, sizeof(inv));
    inv[10] ^= 0xff;   /* key from some other (e.g. restarted) server */
    pierce_conn_id id;
    S.nodes[cli].signal_to = srv;
    REQUIRE(pierce_connect(S.nodes[cli].ctx, NULL, inv, (uint32_t)ilen, &id) == PIERCE_OK);
    uint32_t max_conns = 0;
    for (int i = 0; i < 20000; i++) {   /* 20 s: through every retransmit and the timeout */
        sim_step(&S, 1000);
        if (S.nodes[srv].ctx->nconns > max_conns) max_conns = S.nodes[srv].ctx->nconns;
    }
    CHECK_EQ(max_conns, 0);                 /* never allocated a slot */
    CHECK_EQ(S.nodes[srv].peer_requests, 0);
    CHECK_EQ(S.nodes[cli].last_error, PIERCE_ERR_TIMEOUT);
    sim_free(&S);
}

static int got_request(sim *s, void *u) { return s->nodes[*(int *)u].peer_requests > 0; }

static void test_handshake_payload(void)
{
    sim_init(&S, 21);
    int srv = sim_add_node(&S, -1), cli = sim_add_node(&S, -1);
    pierce_conn_options lo;
    pierce_conn_options_init(&lo);
    lo.user_data = 5;                       /* listener default before accept */
    pierce_listen(S.nodes[srv].ctx, &lo);
    S.nodes[srv].auto_accept = 0;
    pierce_conn_options o;
    pierce_conn_options_init(&o);
    o.handshake_payload = (const uint8_t *)"token:abc123";
    o.handshake_payload_len = 12;
    o.user_data = 77;
    sim_connect(&S, cli, srv, &o, SIM_IK);
    CHECK(sim_run_until(&S, 3000000, got_request, &srv));
    /* The app's credentials arrive with the request, encrypted in transit. */
    CHECK_EQ(S.nodes[srv].last_payload_len, 12);
    CHECK(memcmp(S.nodes[srv].last_payload, "token:abc123", 12) == 0);
    /* Not connected until the app decides. */
    sim_run(&S, 500000);
    CHECK_EQ(S.nodes[cli].connected, 0);
    CHECK(pierce_accept(S.nodes[srv].ctx, S.nodes[srv].last_request_conn, 4242) == PIERCE_OK);
    CHECK(pierce_accept(S.nodes[srv].ctx, S.nodes[srv].last_request_conn, 1) == PIERCE_ERR_STATE);
    int ab[2] = {srv, cli};
    CHECK(sim_run_until(&S, 3000000, both_connected, ab));
    CHECK_EQ(S.nodes[srv].last_user_data, 4242);   /* accept replaced the listener default */
    CHECK_EQ(S.nodes[cli].last_user_data, 77);
    sim_free(&S);
}

static void test_accept_timeout(void)
{
    sim_init(&S, 22);
    int srv = sim_add_node(&S, -1), cli = sim_add_node(&S, -1);
    pierce_listen(S.nodes[srv].ctx, NULL);
    S.nodes[srv].auto_accept = 0;          /* the app never answers */
    sim_connect(&S, cli, srv, NULL, SIM_IK);
    int ab[2] = {srv, cli};
    CHECK(sim_run_until(&S, 40000000, both_disconnected, ab));
    CHECK_EQ(S.nodes[cli].last_error, PIERCE_ERR_REJECTED);
    CHECK_EQ(S.nodes[cli].last_reason, PIERCE_REASON_TIMEOUT);
    CHECK_EQ(S.nodes[srv].last_error, PIERCE_ERR_TIMEOUT);
    sim_free(&S);
}

int main(void)
{
    RUN(test_connect_modes);
    RUN(test_nat_matrix);
    RUN(test_reject);
    RUN(test_client_rejects_host_key);
    RUN(test_channel_mismatch);
    RUN(test_reliable_under_loss);
    RUN(test_reliable_unordered);
    RUN(test_sequenced);
    RUN(test_rekey);
    RUN(test_migration);
    RUN(test_idle_timeout);
    RUN(test_close);
    RUN(test_backpressure);
    RUN(test_relay_only);
    RUN(test_relay_tokens);
    RUN(test_relay_upgrade);
    RUN(test_lifetime_abandon);
    RUN(test_many_clients);
    RUN(test_fuzz_input);
    RUN(test_api_errors);
    RUN(test_early_send_delivered);
    RUN(test_handshake_payload);
    RUN(test_accept_timeout);
    RUN(test_stale_invite_costs_nothing);
    TEST_MAIN_END();
}
