/*
 * tofu_chat: peer-to-peer chat with copy-paste signaling and
 * trust-on-first-use identities (spec 4.3).
 *
 *   host:  tofu_chat host --name alice
 *   join:  tofu_chat join --name bob <invite>
 *
 * The host prints an invite. The joiner prints an offer; the host prints an
 * answer; extra candidate lines may follow. Paste every "pierce:..." line
 * into the other side's terminal (any channel works: chat, email, QR code).
 * Anything else you type is sent as a chat message.
 *
 * Identity and trust live here in the app, not in the library: the secret
 * key is a 32-byte file, and known peers are "name hexkey" lines. A peer
 * name seen before with a different key is refused.
 *
 * Options: --key FILE (default tofu_chat.key), --known FILE (default
 * tofu_chat.known), --stun host:port, --relay host:port, --verbose.
 */
#if defined(_WIN32)
#include <stdio.h>
int main(void)
{
    fprintf(stderr, "tofu_chat uses POSIX stdin polling; see examples/echo_*.c on Windows\n");
    return 1;
}
#else

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <unistd.h>

#include "pierce.h"

/* ---- base64 (blobs are binary; the terminal wants text) ---- */

static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void b64_encode(const uint8_t *in, uint32_t n, char *out)
{
    uint32_t i, o = 0;
    for (i = 0; i + 2 < n; i += 3) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        out[o++] = b64[v >> 18]; out[o++] = b64[(v >> 12) & 63]; out[o++] = b64[(v >> 6) & 63]; out[o++] = b64[v & 63];
    }
    if (i < n) {
        uint32_t v = (uint32_t)in[i] << 16 | (i + 1 < n ? (uint32_t)in[i + 1] << 8 : 0);
        out[o++] = b64[v >> 18];
        out[o++] = b64[(v >> 12) & 63];
        out[o++] = i + 1 < n ? b64[(v >> 6) & 63] : '=';
        out[o++] = '=';
    }
    out[o] = 0;
}

static int b64_decode(const char *in, uint8_t *out, uint32_t cap)
{
    uint32_t v = 0, bits = 0, n = 0;
    for (; *in && *in != '='; in++) {
        const char *p = strchr(b64, *in);
        if (!p || !*in) return -1;
        v = (v << 6) | (uint32_t)(p - b64);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (n >= cap) return -1;
            out[n++] = (uint8_t)(v >> bits);
        }
    }
    return (int)n;
}

/* ---- identity: a 32-byte secret in a file the app owns ---- */

static int load_or_create_key(const char *path, uint8_t sk[32])
{
    FILE *f = fopen(path, "rb");
    if (f) {
        size_t n = fread(sk, 1, 32, f);
        fclose(f);
        return n == 32 ? 0 : -1;
    }
    if (pierce_keygen(sk) != PIERCE_OK) return -1;
    umask(077);
    f = fopen(path, "wb");
    if (!f || fwrite(sk, 1, 32, f) != 32) {
        if (f) fclose(f);
        return -1;
    }
    fclose(f);
    fprintf(stderr, "created new identity in %s\n", path);
    return 0;
}

static void hex(const uint8_t *k, char out[65])
{
    for (int i = 0; i < 32; i++) sprintf(out + 2 * i, "%02x", k[i]);
}

/* TOFU: 1 = known and matches, 0 = new (now recorded), -1 = MISMATCH. */
static int tofu_check(const char *path, const char *name, const uint8_t key[32])
{
    char want[65], line[256];
    hex(key, want);
    FILE *f = fopen(path, "r");
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            char n[128], k[80];
            if (sscanf(line, "%127s %79s", n, k) != 2 || strcmp(n, name) != 0) continue;
            fclose(f);
            return strcmp(k, want) == 0 ? 1 : -1;
        }
        fclose(f);
    }
    f = fopen(path, "a");
    if (f) {
        fprintf(f, "%s %s\n", name, want);
        fclose(f);
    }
    return 0;
}

static void usage(void)
{
    fprintf(stderr, "usage: tofu_chat host --name NAME [options]\n"
                    "       tofu_chat join --name NAME [options] INVITE\n"
                    "options: --key FILE --known FILE --stun HOST:PORT --relay HOST:PORT --verbose\n");
    exit(2);
}

int main(int argc, char **argv)
{
    const char *mode, *keyfile = "tofu_chat.key", *known = "tofu_chat.known";
    const char *name = NULL, *invite_text = NULL, *stun = NULL, *relay = NULL;
    int verbose = 0;
    if (argc < 2) usage();
    mode = argv[1];
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--key") && i + 1 < argc) keyfile = argv[++i];
        else if (!strcmp(argv[i], "--known") && i + 1 < argc) known = argv[++i];
        else if (!strcmp(argv[i], "--name") && i + 1 < argc) name = argv[++i];
        else if (!strcmp(argv[i], "--stun") && i + 1 < argc) stun = argv[++i];
        else if (!strcmp(argv[i], "--relay") && i + 1 < argc) relay = argv[++i];
        else if (!strcmp(argv[i], "--verbose")) verbose = 1;
        else if (argv[i][0] != '-' && !invite_text) invite_text = argv[i];
        else usage();
    }
    int hosting = !strcmp(mode, "host");
    if (!name || (!hosting && (strcmp(mode, "join") || !invite_text))) usage();

    uint8_t sk[32];
    if (load_or_create_key(keyfile, sk) < 0) {
        fprintf(stderr, "cannot read or create %s\n", keyfile);
        return 1;
    }

    pierce_config cfg;
    pierce_config_init(&cfg);
    cfg.identity_secret_key = sk;
    const char *stuns[1] = {stun ? stun : "stun.l.google.com:19302"};
    cfg.stun_servers = stuns;
    cfg.stun_server_count = 1;
    const char *relays[1] = {relay};
    if (relay) {
        cfg.relay_servers = relays;
        cfg.relay_server_count = 1;
    }
    /* Humans relay the blobs by hand, which can take a while: give
       traversal two minutes instead of the default 15 seconds. */
    cfg.connect_timeout_ms = 120000;
    cfg.log_level = verbose ? PIERCE_LOG_DEBUG : PIERCE_LOG_WARN;
    pierce_ctx *ctx;
    int rc = pierce_ctx_create(&cfg, &ctx);
    if (rc != PIERCE_OK) {
        fprintf(stderr, "pierce_ctx_create: %s\n", pierce_strerror(rc));
        return 1;
    }

    /* The handshake payload carries our display name to the host. */
    pierce_conn_options opt;
    pierce_conn_options_init(&opt);
    opt.handshake_payload = (const uint8_t *)name;
    opt.handshake_payload_len = (uint32_t)strlen(name);

    uint8_t buf[2048];
    char text[4096];
    pierce_conn_id conn = PIERCE_CONN_NONE;
    if (hosting) {
        pierce_listen(ctx, NULL);
        int n = pierce_get_invite(ctx, buf, sizeof(buf));
        b64_encode(buf, (uint32_t)n, text);
        printf("Give this invite to your peer:\n  %s\n", text);
    } else {
        /* Give STUN (and the relay) a moment so the offer already carries our
           public address, instead of trickling it as an extra line. */
        pierce_event ev[16];
        for (int t = 0; t < 15; t++) {
            int k = pierce_poll(ctx, ev, 16, 100);
            for (int i = 0; i < k; i++)
                if (ev[i].type == PIERCE_EV_LOG) fprintf(stderr, "[pierce] %.*s\n", (int)ev[i].data_len, ev[i].data);
        }
        int n = b64_decode(invite_text, buf, sizeof(buf));
        if (n <= 0 || (rc = pierce_connect(ctx, &opt, buf, (uint32_t)n, &conn)) != PIERCE_OK) {
            fprintf(stderr, "bad invite: %s\n", n <= 0 ? "not base64" : pierce_strerror(rc));
            return 1;
        }
    }
    fflush(stdout);

    char line[4096];
    int running = 1;
    while (running) {
        pierce_event ev[32];
        int k = pierce_poll(ctx, ev, 32, 50);
        for (int i = 0; i < k; i++) {
            pierce_event *e = &ev[i];
            switch (e->type) {
            case PIERCE_EV_SIGNAL_OUT:
                b64_encode(e->data, e->data_len, text);
                printf("Paste into your peer's terminal:\n  pierce:%s\n", text);
                break;
            case PIERCE_EV_PEER_REQUEST: {
                char peer[129];
                uint32_t n = e->data_len < 128 ? e->data_len : 128;
                memcpy(peer, e->data, n);
                peer[n] = 0;
                int t = tofu_check(known, peer, e->peer_key);
                if (t < 0) {
                    printf("!! %s presented a DIFFERENT key than last time. Refusing.\n", peer);
                    pierce_reject(ctx, e->conn_id, PIERCE_REASON_POLICY);
                } else {
                    printf("%s %s (%s)\n", t ? "known peer" : "new peer, trusting on first use:",
                           peer, t ? "key matches" : "recorded");
                    pierce_accept(ctx, e->conn_id, 0);
                    conn = e->conn_id;
                }
                break;
            }
            case PIERCE_EV_CONNECTED: {
                char fp[65];
                uint8_t f[32];
                pierce_fingerprint(e->peer_key, f);
                hex(f, fp);
                conn = e->conn_id;
                printf("connected (%s). peer fingerprint %.16s...\n",
                       e->flags == PIERCE_PATH_RELAY ? "via relay" : "direct", fp);
                break;
            }
            case PIERCE_EV_MESSAGE:
                printf("> %.*s\n", (int)e->data_len, (const char *)e->data);
                break;
            case PIERCE_EV_DISCONNECTED:
                /* A refused impostor doesn't end the session; our peer leaving does. */
                if (e->conn_id == conn || !hosting) {
                    printf("disconnected: %s\n", pierce_strerror(e->error));
                    running = 0;
                }
                break;
            case PIERCE_EV_LOG:
                fprintf(stderr, "[pierce] %.*s\n", (int)e->data_len, (const char *)e->data);
                break;
            case PIERCE_EV_PATH_CHANGED:
                printf("(path changed: %s)\n", e->flags == PIERCE_PATH_RELAY ? "relay" : "direct");
                break;
            }
        }
        fflush(stdout);

        /* Stdin without blocking the event loop. */
        fd_set rd;
        struct timeval tv = {0, 0};
        FD_ZERO(&rd);
        FD_SET(0, &rd);
        if (select(1, &rd, NULL, NULL, &tv) > 0) {
            if (!fgets(line, sizeof(line), stdin)) break;
            line[strcspn(line, "\r\n")] = 0;
            char *s = line;
            while (*s == ' ') s++;
            if (!strncmp(s, "pierce:", 7)) {
                int n = b64_decode(s + 7, buf, sizeof(buf));
                pierce_conn_id id;
                rc = n > 0 ? pierce_signal_in(ctx, buf, (uint32_t)n, &id) : PIERCE_ERR_INVALID_ARG;
                if (rc != PIERCE_OK) printf("(that blob was not accepted: %s)\n", pierce_strerror(rc));
                (void)id;   /* the conversation starts at PEER_REQUEST / CONNECTED */
            } else if (*s && conn) {
                rc = pierce_send(ctx, conn, 0, (const uint8_t *)s, (uint32_t)strlen(s), 0);
                if (rc != PIERCE_OK) printf("(send failed: %s)\n", pierce_strerror(rc));
            }
        }
    }
    pierce_ctx_destroy(ctx);
    return 0;
}
#endif
