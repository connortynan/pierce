/* pierce-relay: reference relay server (spec 5.3).
 *
 *   pierce-relay [--port 3478] [--tcp-port 443] [--secret HEX | --open]
 *                [--ipv6] [--max-allocs N] [--kbps N] [--quiet]
 *   pierce-relay token --secret HEX [--ttl SECONDS] [--kbps N]
 *
 * The relay forwards encrypted Pierce datagrams between allocations and
 * answers STUN binding requests. It never sees plaintext.
 */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "pierce.h"
#include "relay_loop.h"

static volatile uint32_t stop_flag;   /* written by the signal handler */

static void on_signal(int sig)
{
    (void)sig;
    stop_flag = 1;
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t cap)
{
    size_t n = strlen(hex);
    if (n % 2 || n / 2 > cap || n == 0) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return (int)(n / 2);
}

static void usage(void)
{
    fprintf(stderr,
            "usage: pierce-relay [--port N] [--tcp-port N] [--secret HEX | --open] [--ipv6]\n"
            "                    [--max-allocs N] [--kbps N] [--quiet]\n"
            "       pierce-relay token --secret HEX [--ttl SECONDS] [--kbps N]\n");
}

static int cmd_token(int argc, char **argv)
{
    uint8_t secret[64], tok[PIERCE_RELAY_TOKEN_SIZE];
    int slen = -1;
    long ttl = 3600, kbps = 0;
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--secret") && i + 1 < argc) slen = hex_to_bytes(argv[++i], secret, sizeof(secret));
        else if (!strcmp(argv[i], "--ttl") && i + 1 < argc) ttl = strtol(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--kbps") && i + 1 < argc) kbps = strtol(argv[++i], NULL, 10);
        else {
            usage();
            return 2;
        }
    }
    if (slen <= 0 || ttl <= 0 || kbps < 0) {
        usage();
        return 2;
    }
    int n = pierce_relay_token_create(secret, (uint32_t)slen, (uint64_t)time(NULL) + (uint64_t)ttl,
                                      (uint32_t)kbps, tok, sizeof(tok));
    if (n < 0) return 1;
    for (int i = 0; i < n; i++) printf("%02x", tok[i]);
    printf("\n");
    return 0;
}

int main(int argc, char **argv)
{
    relay_loop_opts o;
    uint8_t secret[64];
    memset(&o, 0, sizeof(o));
    o.udp_port = 3478;
    o.verbose = 1;
    if (argc > 1 && !strcmp(argv[1], "token")) return cmd_token(argc, argv);
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--port") && i + 1 < argc) {
            o.udp_port = (uint16_t)atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--tcp-port") && i + 1 < argc) {
            o.tcp_port = (uint16_t)atoi(argv[++i]);
            o.enable_tcp = 1;
        } else if (!strcmp(argv[i], "--secret") && i + 1 < argc) {
            int n = hex_to_bytes(argv[++i], secret, sizeof(secret));
            if (n <= 0) {
                fprintf(stderr, "pierce-relay: --secret wants up to 64 bytes of hex\n");
                return 2;
            }
            o.secret = secret;
            o.secret_len = (uint32_t)n;
        } else if (!strcmp(argv[i], "--open")) {
            o.open = 1;
        } else if (!strcmp(argv[i], "--ipv6")) {
            o.enable_ipv6 = 1;
        } else if (!strcmp(argv[i], "--max-allocs") && i + 1 < argc) {
            o.max_allocs = (uint32_t)atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--kbps") && i + 1 < argc) {
            o.default_kbps = (uint32_t)atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--quiet")) {
            o.verbose = 0;
        } else {
            usage();
            return 2;
        }
    }
    if (!o.secret && !o.open) {
        fprintf(stderr, "pierce-relay: refusing to run without --secret or an explicit --open\n");
        return 2;
    }
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    int rc = relay_loop_run(&o, &stop_flag);
    if (rc) fprintf(stderr, "pierce-relay: could not open sockets\n");
    return rc;
}
