/*
 * echo_client: connects to echo_server with its invite, sends a few
 * messages, and measures the round trip.
 *
 *   echo_client INVITE_HEX [COUNT]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pierce.h"

static int unhex(const char *s, uint8_t *out, int cap)
{
    int n = (int)strlen(s) / 2;
    if (n > cap) return -1;
    for (int i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return n;
}

int main(int argc, char **argv)
{
    uint8_t inv[256];
    int ilen = argc >= 2 ? unhex(argv[1], inv, sizeof(inv)) : -1;
    int count = argc >= 3 ? atoi(argv[2]) : 5;
    if (ilen <= 0) {
        fprintf(stderr, "usage: echo_client INVITE_HEX [COUNT]\n");
        return 2;
    }
    pierce_config cfg;
    pierce_config_init(&cfg);
    pierce_ctx *ctx;
    int rc = pierce_ctx_create(&cfg, &ctx);
    if (rc != PIERCE_OK) {
        fprintf(stderr, "pierce_ctx_create: %s\n", pierce_strerror(rc));
        return 1;
    }
    pierce_conn_id conn;
    rc = pierce_connect(ctx, NULL, inv, (uint32_t)ilen, &conn);
    if (rc != PIERCE_OK) {
        fprintf(stderr, "pierce_connect: %s\n", pierce_strerror(rc));
        return 1;
    }
    int sent = 0, echoed = 0, done = 0;
    while (!done) {
        pierce_event ev[16];
        int k = pierce_poll(ctx, ev, 16, 1000);
        if (k < 0) break;
        for (int i = 0; i < k; i++) {
            pierce_event *e = &ev[i];
            if (e->type == PIERCE_EV_CONNECTED) {
                printf("connected\n");
                for (; sent < count; sent++) {
                    char msg[64];
                    int n = snprintf(msg, sizeof(msg), "ping %d", sent);
                    pierce_send(ctx, conn, 0, (const uint8_t *)msg, (uint32_t)n, 0);
                }
            } else if (e->type == PIERCE_EV_MESSAGE) {
                printf("echo: %.*s\n", (int)e->data_len, (const char *)e->data);
                if (++echoed == count) {
                    pierce_conn_info info;
                    info.struct_size = sizeof(info);
                    pierce_conn_info_get(ctx, conn, &info);
                    printf("rtt %.2f ms\n", info.rtt_us / 1000.0);
                    pierce_close(ctx, conn, PIERCE_REASON_NONE);
                }
            } else if (e->type == PIERCE_EV_DISCONNECTED) {
                if (e->error) printf("disconnected: %s\n", pierce_strerror(e->error));
                done = 1;
            }
        }
    }
    pierce_ctx_destroy(ctx);
    return echoed == count ? 0 : 1;
}
