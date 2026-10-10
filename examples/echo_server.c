/*
 * echo_server: dedicated-server mode (spec 10). A server is a peer with a
 * public address; clients connect straight to it from an invite, no
 * signaling needed. Every message is echoed back on the same channel.
 *
 *   echo_server PUBLIC_IP:PORT
 *
 * Prints the invite as hex; pass it to echo_client.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pierce.h"

/* PIERCE_LOCAL_ONLY=1 keeps a run on this machine (used by the smoke
   tests): no public STUN servers, no router port mapping, loopback offered. */
static uint32_t local_only_flags(void)
{
    const char *e = getenv("PIERCE_LOCAL_ONLY");
    if (!e || !*e || *e == '0') return 0;
    return PIERCE_CFG_NO_DEFAULT_STUN | PIERCE_CFG_NO_PORT_MAPPING | PIERCE_CFG_INCLUDE_LOOPBACK;
}

int main(int argc, char **argv)
{
    pierce_addr pub;
    if (argc != 2 || pierce_addr_parse(argv[1], &pub) != PIERCE_OK) {
        fprintf(stderr, "usage: echo_server PUBLIC_IP:PORT   (e.g. 127.0.0.1:7777)\n");
        return 2;
    }
    pierce_config cfg;
    pierce_config_init(&cfg);
    cfg.flags |= local_only_flags();
    cfg.bind_port = pub.port;
    cfg.max_connections = 4096;
    pierce_ctx *ctx;
    int rc = pierce_ctx_create(&cfg, &ctx);
    if (rc != PIERCE_OK) {
        fprintf(stderr, "pierce_ctx_create: %s\n", pierce_strerror(rc));
        return 1;
    }
    pierce_add_local_address(ctx, &pub);   /* goes into the invite */
    pierce_listen(ctx, NULL);

    uint8_t inv[256];
    int n = pierce_get_invite(ctx, inv, sizeof(inv));
    printf("invite: ");
    for (int i = 0; i < n; i++) printf("%02x", inv[i]);
    printf("\n");
    fflush(stdout);

    for (;;) {
        pierce_event ev[64];
        int k = pierce_poll(ctx, ev, 64, -1);
        if (k < 0) break;
        for (int i = 0; i < k; i++) {
            pierce_event *e = &ev[i];
            if (e->type == PIERCE_EV_PEER_REQUEST) {
                pierce_accept(ctx, e->conn_id, 0);   /* real servers check e->data / e->peer_key */
            } else if (e->type == PIERCE_EV_CONNECTED) {
                char a[64];
                pierce_addr_format(&e->addr, a, sizeof(a));
                printf("client %llu connected from %s\n", (unsigned long long)e->conn_id, a);
            } else if (e->type == PIERCE_EV_MESSAGE) {
                pierce_send(ctx, e->conn_id, e->channel, e->data, e->data_len, 0);
            } else if (e->type == PIERCE_EV_DISCONNECTED) {
                printf("client %llu gone: %s\n", (unsigned long long)e->conn_id, pierce_strerror(e->error));
            }
        }
        fflush(stdout);
    }
    pierce_ctx_destroy(ctx);
    return 0;
}
