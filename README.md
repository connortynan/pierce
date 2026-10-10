# Pierce

Peers, pierced through. A C99 library for encrypted, channel-based
connections that work through NATs without port forwarding: UDP hole
punching first, relay fallback second, dedicated servers on the same API.

- **Identity is a key.** Every peer has an X25519 key; connections are Noise
  IK/XX handshakes. No accounts, no central authority on the data path.
- **Channels.** Reliable ordered, reliable unordered, sequenced (newest
  wins) and unreliable, with priorities, lifetimes, retransmit limits and
  fragmentation, over one congestion-controlled connection (NewReno).
- **Traversal.** Host, STUN-reflexive, peer-reflexive and relay candidates,
  trickled over a signaling channel you provide (anything that carries a
  few hundred bytes). Relay paths upgrade to direct ones when possible.
- **One event loop.** No callbacks out, no library threads. `pierce_send` is
  thread-safe; everything else belongs to the thread that polls.
- **Small.** One dependency, [Monocypher](https://monocypher.org) (X25519,
  ChaCha20-Poly1305, BLAKE2b), as a git submodule pinned to 4.0.2. Beyond
  that: the C standard library, POSIX sockets/pthreads, or on Windows
  `ws2_32`, `iphlpapi` and `bcrypt`.

Design: [spec.md](spec.md). Wire format: [docs/wire.md](docs/wire.md).
API: [include/pierce.h](include/pierce.h).

## Build

```sh
git clone --recursive <repo>        # or, in an existing clone:
git submodule update --init
cmake -S . -B build && cmake --build build
ctest --test-dir build
```

Or without CMake, from the repository root:

```sh
cc -std=c99 -O2 -Iinclude -c src/*.c vendor/monocypher/src/monocypher.c
```

Windows links `ws2_32 iphlpapi bcrypt`; POSIX links pthreads.

## Use

```c
pierce_config cfg;
pierce_config_init(&cfg);
const char *stun[] = {"stun.l.google.com:19302"};
cfg.stun_servers = stun;
cfg.stun_server_count = 1;
pierce_ctx *ctx;
pierce_ctx_create(&cfg, &ctx);

/* Host: listen and hand out an invite (it holds the host's public key). */
pierce_listen(ctx, NULL);
uint8_t invite[256];
int n = pierce_get_invite(ctx, invite, sizeof invite);

/* Client: connect with the invite. */
pierce_conn_id id;
pierce_connect(ctx, NULL, invite, n, &id);

for (;;) {
    pierce_event ev[64];
    int k = pierce_poll(ctx, ev, 64, -1);
    for (int i = 0; i < k; i++) switch (ev[i].type) {
    case PIERCE_EV_SIGNAL_OUT:   /* deliver ev[i].data to the peer, any way you like; */
        break;                   /* the peer passes it to pierce_signal_in */
    case PIERCE_EV_PEER_REQUEST: /* check ev[i].peer_key / ev[i].data */
        pierce_accept(ctx, ev[i].conn_id, 0);
        break;
    case PIERCE_EV_CONNECTED:
        pierce_send(ctx, ev[i].conn_id, 0, (const uint8_t *)"hi", 2, 0);
        break;
    case PIERCE_EV_MESSAGE:      /* ev[i].data is valid until the next poll */
        break;
    }
}
```

A server with a public address adds it with `pierce_add_local_address`; its
invites then let clients connect directly, with no signaling at all.

Examples:

- [examples/echo_server.c](examples/echo_server.c) and
  [examples/echo_client.c](examples/echo_client.c): dedicated server.
- [examples/tofu_chat.c](examples/tofu_chat.c): peer-to-peer chat with
  copy-paste signaling and trust-on-first-use identities.

## Relay

```sh
build/pierce-relay --port 3478 --tcp-port 443 --secret $(openssl rand -hex 32)
build/pierce-relay token --secret <same hex> --ttl 3600   # issue a client token
```

Clients list it as `"relay.example.com:3478"` (UDP) or
`"tcp://relay.example.com:443"` and pass the token in
`pierce_config.relay_tokens`. The relay only ever sees ciphertext.
`PIERCE_CFG_RELAY_ONLY` hides a peer's addresses from the other side.

## Testing

- `test_crypto`: Noise IK/XX against the published cacophony vectors, RFC
  8439, HMAC-BLAKE2b, and the codecs.
- `test_sim`: a deterministic in-process network with a full-cone,
  restricted, port-restricted and symmetric NAT matrix, loss, reordering,
  duplication, migration, rekeying, 200-client fan-in, and fuzzing.
- `test_udp`: real sockets on loopback, the relay over UDP and TCP, and
  cross-thread sends.

Configure with `-DPIERCE_SANITIZE=ON` (ASan + UBSan) or `-DPIERCE_TSAN=ON`.

## Status

v1 implements the spec's roadmap steps 1–5 as a C library.

- **Platforms:** Linux is built and tested. The Windows and macOS platform
  layers compile and link, cross-built with Zig, but have not been run.
- **Not yet:** language wrappers, mobile ports, WASM, path-MTU discovery,
  connection-ID rotation, signed relay tokens, and a standards-compliant
  ICE mode are later steps.
