/* Reference relay server core (spec 5.3), sans-I/O: the caller moves bytes.
   Used by tools/pierce_relay.c and the network simulator in tests. */
#ifndef PIERCE_RELAY_SERVER_H
#define PIERCE_RELAY_SERVER_H

#include "common.h"

/* Where a message came from / goes to: a UDP address, or a TCP connection
   (tcp_id != 0; addr is then the TCP peer address). */
typedef struct {
    pierce_addr addr;
    uint64_t tcp_id;
} pc_rs_ep;

typedef void (*pc_rs_send_fn)(void *user, const pc_rs_ep *to, const uint8_t *data, size_t len);

typedef struct {
    const uint8_t *secret;      /* shared token secret; NULL with open = 1 */
    uint32_t secret_len;
    int open;                   /* accept allocations without a token */
    uint32_t max_allocs;        /* 0 = 10000 */
    uint32_t lifetime_s;        /* 0 = 600 */
    uint32_t default_kbps;      /* for open relays; 0 = unlimited */
} pc_rs_config;

typedef struct pc_relay_server pc_relay_server;

pc_relay_server *pc_rs_create(const pc_rs_config *cfg);
void pc_rs_destroy(pc_relay_server *rs);
void pc_rs_input(pc_relay_server *rs, uint64_t now_us, uint64_t now_unix, const pc_rs_ep *from,
                 const uint8_t *data, size_t len, pc_rs_send_fn send, void *user);
void pc_rs_tick(pc_relay_server *rs, uint64_t now_us);
void pc_rs_tcp_closed(pc_relay_server *rs, uint64_t tcp_id);
uint32_t pc_rs_alloc_count(const pc_relay_server *rs);
void pc_rs_server_id(const pc_relay_server *rs, uint8_t out[8]);

#endif
