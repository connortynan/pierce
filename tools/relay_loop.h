/* Socket loop around the sans-I/O relay core: UDP (v4 + v6) and framed TCP.
   Shared by the pierce-relay tool and the integration tests. */
#ifndef PIERCE_RELAY_LOOP_H
#define PIERCE_RELAY_LOOP_H

#include <stdint.h>

typedef struct {
    uint16_t udp_port;          /* 0 = ephemeral */
    uint16_t tcp_port;          /* 0 = ephemeral; ignored unless enable_tcp */
    int enable_tcp;
    int enable_ipv6;
    const uint8_t *secret;
    uint32_t secret_len;
    int open;
    uint32_t max_allocs;
    uint32_t default_kbps;
    int verbose;
    /* outputs: ports are valid once `ready` (atomic) is 1; 2 = setup failed */
    volatile uint32_t ready;
    uint16_t bound_udp_port;
    uint16_t bound_tcp_port;
} relay_loop_opts;

/* Runs until *stop (atomic) becomes nonzero. Returns 0, or nonzero on setup
   failure. */
int relay_loop_run(relay_loop_opts *opts, volatile uint32_t *stop);

#endif
