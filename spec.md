# Pierce: Design Spec (Draft v0.4)

> Peers, pierced through. A low-level C library for NAT-traversing, encrypted, channel-based connections. Serverless peer-to-peer first, dedicated server mode second.

Status: draft. License: MIT. Items marked **[OPEN]** are unresolved decisions. Items marked **[DEFER]** are intentionally out of v1.

---

## 1. Goals and Non-Goals

### Goals

- C99 library with a stable C ABI. Other languages bind through thin wrappers.
- Peer-to-peer connections that work **without port forwarding**, using NAT hole punching with relay fallback.
- No central authority for **authentication or the data path**. Identity is public-key based.
- One connection model that serves **real-time games** (latency-sensitive, unreliable) and **chat / message servers** (reliable, fan-out).
- Dedicated-server mode (many clients on one socket) behind the same API.
- No third-party dependencies beyond the OS and one crypto library. Every dependency is a git submodule.
- Targets at launch: **Linux, macOS, Windows**. Mobile and WASM are designed for but not shipped in v1.

### Non-Goals

- Matchmaking, accounts, lobbies, rooms, presence, message history, offline delivery, push notifications. These are application layers.
- Anti-cheat, global bans, or any global identity system.
- TLS or general web requests in the core. The one exception is a minimal HTTP client that only ever talks to the local router, for UPnP port mapping (section 5.5).
- Browser WebRTC interoperability (browsers connect through an app-provided gateway).
- Interoperability with standard STUN/TURN/ICE implementations in v1 (a standards-compliant mode is **[DEFER]**, see section 5.4).

### What the library does not do (and who does)

| Need | Who provides it |
|---|---|
| Mapping a code to a host's candidates (signaling) | The application, using any channel it likes |
| STUN server | Any public STUN server, or one the app runs |
| Relay server | Reference relay shipped with Pierce, or the app's own |
| Accounts, trust policy, bans | The application, via the peer-request flow |

---

## 2. Architecture

```
+--------------------------------------------------------+
|  Public C API (pierce.h): context, connections,        |
|  channels, events                                       |
+--------------------------------------------------------+
|  Session / topology: host-star, mesh, listener          |
+--------------------------------------------------------+
|  Transport channels: reliability, ordering, priority,   |
|  fragmentation, congestion control                      |
+--------------------------------------------------------+
|  Secure channel: Noise handshake, AEAD, rekeying        |
+--------------------------------------------------------+
|  Traversal: candidate gathering, hole punch, relay      |
+--------------------------------------------------------+
|  Datagram transports: UDP (built in), TCP framing,      |
|  app-supplied (WASM / custom)                           |
+--------------------------------------------------------+
|  Platform Abstraction Layer (PAL, ~15-20 functions)     |
+--------------------------------------------------------+
```

Design rules:

1. **Sans-I/O core.** Layers above the PAL never touch a socket or clock directly. They consume datagrams and timestamps, and produce datagrams and events.
2. **No callbacks out of the library.** Everything the library wants to tell the app arrives as an event from `pierce_poll`. Everything it needs arrives as a function call.
3. **One thread owns a context.** The only cross-thread entry points are listed in section 7.
4. **Portable code has no `#ifdef`.** Platform differences live only in the PAL.

---

## 3. Platform Abstraction Layer (PAL)

A single internal header (`pal.h`) implemented once per platform. Everything above it is portable C99.

| Function group | POSIX | Windows | Notes |
|---|---|---|---|
| UDP/TCP sockets, non-blocking | `socket`, `sendto`, `recvfrom` | Winsock (`WSAStartup`, `closesocket`, `ioctlsocket`) | Abstract error codes |
| Readiness wait | `poll` (later `epoll` / `kqueue`) | `WSAPoll` | Includes the wake fd |
| Wake mechanism | `eventfd` / pipe | loopback UDP socket | Backs `pierce_wake` |
| Interface enumeration | `getifaddrs` | `GetAdaptersAddresses` | Filter link-local, VPN, temporary IPv6 |
| Monotonic clock | `clock_gettime(CLOCK_MONOTONIC)` | `QueryPerformanceCounter` | Microsecond resolution |
| Secure random | `getrandom` / `arc4random_buf` / `/dev/urandom` | `BCryptGenRandom` | **Cannot be vendored. Fail hard if unavailable.** |
| Atomics | C11 `<stdatomic.h>` or builtins | `Interlocked*` | For refcounts |
| Allocation | `malloc` / `free` | same | Overridable via config |
| Name resolution | `getaddrinfo` | same | Required for iOS NAT64 correctness |

Rules:

- All address handling goes through `getaddrinfo`. No hardcoded IPv4 literals for STUN or relay hosts.
- Dual-stack IPv4/IPv6 from day one.
- A port to a new platform means implementing `pal.h` and nothing else.

---

## 4. Cryptography and Identity

### 4.1 Crypto primitives

Use **Monocypher** core (public domain, single `monocypher.c` / `.h`, a git submodule at `vendor/monocypher` pinned to a release tag): X25519, ChaCha20-Poly1305 (IETF variant, as Noise requires), BLAKE2b. Do not write primitives. Do not modify them. The optional `monocypher-ed25519.c` is not needed in v1.

### 4.2 Handshake

- Noise suite `Noise_IK_25519_ChaChaPoly_BLAKE2b` / `Noise_XX_25519_ChaChaPoly_BLAKE2b`, implemented on top of the primitives and **validated against published Noise test vectors**.
- **IK** is the normal path: the initiator learns the responder's static key from the invite (section 8.6). **XX** is used only when the initiator connects without an invite.
- Handshake runs *over* whatever path traversal selected, so authentication is independent of how the path was found.
- **Mandatory encryption in v1.** There is no way to turn it off.
- **[DEFER]** An explicit insecure mode for LAN/dev. The v1 wire format leaves room for it so it can be added without breaking compatibility: the first handshake message carries a **suite byte** (v1 defines only the Noise suite above). If added, insecure mode must be opted into by both sides (`PIERCE_CFG_INSECURE`), and a secure peer must refuse it rather than be downgraded. A key-log export hook (like `SSLKEYLOGFILE`) is the preferred way to inspect traffic in Wireshark without it.

### 4.3 Identity model

- Every peer has one **X25519 static keypair**. The **public key (or its BLAKE2b hash, the fingerprint) is the peer's identity**. `identity_secret_key` in the config is this X25519 secret.
- No signing key in v1. If signed invites or signed relay tokens are needed later, an Ed25519 key is added as a separate optional config field **[DEFER]**.
- Invites carry the host's public key. Trust comes from the key, not from the short code.
- Policy lives in the app: persistent keys with trust-on-first-use, ephemeral keys, or app-supplied credentials presented during the handshake payload.
- **Pierce never stores keys or trust decisions.** It has no filesystem access and no known-peers database. It provides key helpers (`pierce_keygen`, `pierce_public_key`, `pierce_fingerprint`, `pierce_ctx_public_key`) so every language binding agrees on the key and fingerprint format. Persisting the secret (file, keychain, secrets manager) and checking peers against a stored list are the app's job.
- The API default is an ephemeral key (`identity_secret_key = NULL`). The documented happy path is TOFU, shown in an example program (`examples/tofu_chat.c`) rather than built into the core. App credentials get a separate guide.
- The library surfaces `PIERCE_EV_PEER_REQUEST` (with the remote public key and any handshake payload) and the app answers with `pierce_accept` or `pierce_reject`. Responders always get this event. Initiators get it only for XX connections (no invite), since they have no prior key to check against.

### 4.3.1 Trust root

The invite is the root of trust. Pierce guarantees that the peer on the other end holds the private key matching the invite's public key, and nothing more:

- If the invite reaches the client intact, a man-in-the-middle on the signaling path or the network cannot impersonate the host. Tampered candidates or probe secrets at worst cause the connection to fail; the Noise IK handshake still fails against an impostor.
- If an attacker can **substitute the invite**, they can substitute their own key. Apps must deliver invites over a channel they trust as much as they need to trust the peer (QR code in person, an authenticated account system, a pinned key, and so on).
- XX connections (no invite) are unauthenticated until the app checks the key in `PIERCE_EV_PEER_REQUEST`.

### 4.4 DoS resistance

- Server-side handshake begins with a **stateless cookie challenge** so spoofed sources cannot force expensive crypto or allocate state.
- Responses never exceed the size of the request until the source address is validated (amplification limit).
- Per-source rate limiting on handshake initiation.

### 4.5 Packet protection

- AEAD per packet with a monotonically increasing nonce counter and a replay window.
- Periodic rekeying (by packet count and time).
- Connection ID in the clear (needed for demux), everything else authenticated and encrypted.
- In v1 the wire connection ID is **fixed for the life of a connection**. This means an on-path observer can link a peer's old and new addresses across a migration (section 9), and a relay can link sessions by ID.
- **[DEFER]** Connection-ID rotation (QUIC-style spare IDs issued over the encrypted channel). The v1 header is designed so rotation can be added without breaking compatibility: the packet header carries an explicit CID length byte and a CID sequence number field (always 0 in v1), and receivers must accept any CID they have issued rather than one fixed value.

---

## 5. Traversal

### 5.1 Overview

Pierce uses a **simplified ICE-like scheme** (not full RFC 8445):

1. **Gather** host candidates (per interface, IPv4 and IPv6) and a server-reflexive candidate from a STUN-style binding request.
2. **Exchange** candidate lists through the app-provided signaling path (events out, function calls in).
3. **Probe**: both sides simultaneously send authenticated probe packets across all candidate pairs (this is the hole punch). Probes are MACed with a per-connection **probe key** derived as `BLAKE2b(offer_secret || answer_secret)`, where each side contributes a fresh 32-byte random secret in its signaling blob (section 8.6). This is the role ICE's ufrag/pwd plays: it stops off-path hosts from spoofing or triggering probe responses. It is not peer authentication; that is the Noise handshake's job (section 4.3.1).
4. **Select**: the first pair that completes a round trip wins. The Noise handshake runs on it.
5. **Maintain**: keepalives hold the NAT mapping. Path liveness is checked continuously.
6. **Migrate**: if the path dies or the network changes, re-gather and re-probe (see section 9).

### 5.2 Trickle candidates

Candidates may be sent as they are discovered, not as one batch. This is optional but meaningfully reduces connection time.

### 5.3 Relay fallback

- Symmetric NATs and carrier-grade NAT defeat hole punching for an estimated 10-20% of pairs. A relay is required for those.
- Pierce defines its own **dumb encrypted forwarder** protocol. The relay sees only ciphertext and connection IDs.
- Relay is also the "hide my IP" mode for games. It hides addresses from the other peer, not from the relay operator, and in v1 the fixed connection ID lets the relay link a session over time (section 4.5).
- Ships with a reference relay server. Apps may run their own.
- Relay over TCP (port 443) is the fallback for firewall-hostile networks. This is **plain framed TCP, not TLS**, since TLS is a non-goal. It gets through firewalls that only filter by port, but networks that inspect traffic and require a real TLS handshake on 443 will block it. **[DEFER]** TLS or TLS-lookalike framing for the relay link.

### 5.3.1 Relay protocol

- Peers allocate a relay slot, receive a relay-scoped ID, and exchange it via signaling. Message formats, lifetimes and refresh rules are in [docs/wire.md](docs/wire.md) section 6.
- Relay forwards opaque datagrams by ID. Authentication to the relay is separate from peer authentication.

### 5.3.2 Relay authentication

Clients present a **relay token** when allocating a slot. The app's backend issues tokens. Pierce passes them through and the relay verifies them. Every token starts with a **token-type byte** so new schemes can be added without breaking compatibility:

| Type | Scheme | Status |
|---|---|---|
| `1` | **Shared secret.** The backend and the relay share a secret. Token = expiry, permitted usage (such as a bandwidth or slot cap), and a keyed BLAKE2b MAC over both. This is the same idea as TURN REST credentials. | v1 |
| `2` | **Signed.** The backend signs the token with Ed25519, so a relay only needs the backend's public key and cannot mint tokens itself. This makes third-party relays safe. Requires the deferred Ed25519 key (section 4.3). | **[DEFER]** |

The reference relay is configured with which types it accepts. An unset token is allowed only if the relay is configured as open.

### 5.4 Standards compatibility

Because both ends run Pierce, the scheme does not need RFC-compliant ICE. v1 uses the custom scheme, and browser peers connect through an app-provided gateway. Tradeoffs:

| | Custom (current plan) | Standard ICE/TURN |
|---|---|---|
| Effort | Weeks | Months |
| Browser peers | No (gateway) | Yes |
| Off-the-shelf TURN | No | Yes |
| Dependencies | None | TLS for TURN-over-TLS |

**[DEFER]** Standards-compliant mode, possibly via an optional libjuice-backed module.

---

### 5.5 Connectivity ladder: everything on by default

Principle: when two people say "let's connect", the library tries every technique it has, with no flags, arguments or extra builds needed. Techniques run in parallel, cheapest first. The first working path wins, and better paths found later still replace it (relay to direct). Apps opt out with config flags; they never opt in.

| # | Technique | When it helps | Opt out |
|---|---|---|---|
| 1 | Host candidates (LAN) | Same network | `PIERCE_CFG_RELAY_ONLY` |
| 2 | IPv6 | Both sides have IPv6: no NAT at all | `PIERCE_CFG_NO_IPV6` |
| 3 | STUN hole punching, with built-in public STUN servers (Google, Cloudflare) when the app configures none | Most home NATs | `PIERCE_CFG_NO_DEFAULT_STUN` |
| 4 | Router port mapping: PCP, then NAT-PMP, with UPnP-IGD in parallel | The router cooperates; makes that side reachable by anyone, even from a symmetric NAT | `PIERCE_CFG_NO_PORT_MAPPING` |
| 5 | NAT classification: compare what two STUN servers saw, and signal "easy" or "hard" (and "mapped") in the blob flags | Lets both sides pick a strategy and explain failures | — |
| 6 | Birthday-paradox punching | One side symmetric ("hard"), the other endpoint-independent ("easy") | `PIERCE_CFG_NO_BIRTHDAY` |
| 7 | Relay over UDP, then TCP/443 | Everything else; needs a relay the app developer configures | — |

Rules:

- **Port mapping.**
  - Leases are 2 h, refreshed at half-life and removed on clean exit. Only Pierce's UDP port is mapped.
  - A mapping is advertised only if the router's external address is public *and* agrees with STUN; otherwise the router sits behind another NAT (double NAT, carrier-grade NAT) and the mapping is useless.
  - The UPnP client is non-blocking, IPv4 only, and talks only to the router found by SSDP.
- **Birthday punching.**
  - Starts 1 s into probing, only when classification predicts success and neither side has a port mapping.
  - The hard side opens up to 256 extra sockets, each a separate NAT mapping aimed at the easy side.
  - The easy side probes random ports on the hard side's public IP at about 250 per second, up to 2048. Success is above 99% with 256 sockets.
  - Probes are authenticated like all probes. The transaction ID is a MAC of the target port, so any answering port can be verified without storing state.
  - Losing sockets close as soon as a path is chosen or after 10 s.
- **Failure diagnosis.** When no path is found, a warning log says why in plain terms (for example "both sides are behind symmetric NATs, which only a relay (or IPv6) can bridge; no relay is configured"), so an app can show something better than a timeout.
- **What only infrastructure can fix.** Symmetric NATs on both sides without IPv6, or networks that block UDP entirely, need a relay. That is the app developer's one-time configuration, never the end user's.

## 6. Channels and Delivery Semantics

A connection carries multiple **channels**, fixed for the life of the connection.

**Channel table agreement.** The initiator proposes the table:

- The client's `pierce_conn_options.channels` is sent in the handshake payload.
- If the listener's `pierce_conn_options.channels` is non-NULL, the library compares the two tables and automatically rejects a mismatch with `PIERCE_REASON_CHANNEL_MISMATCH`. The app never sees a `PEER_REQUEST` for it.
- If the listener's table is NULL, any proposal reaches `PIERCE_EV_PEER_REQUEST`. The app inspects it with `pierce_conn_channels` and accepts or rejects.
- Both sides then use the agreed table, so mismatched delivery semantics are caught at connect time rather than showing up as silently dropped or misordered messages.

| Property | Values |
|---|---|
| Reliability | reliable / unreliable |
| Ordering | ordered / unordered / **sequenced** (drop anything older than the last delivered) |
| Partial reliability | optional max lifetime (ms) or max retransmits |
| Priority | integer; higher priority channels are scheduled first |
| Max message size | per-channel, with transparent fragmentation and reassembly |

Typical configurations:

| Use | Channel config |
|---|---|
| Game state snapshots | unreliable + sequenced, high priority |
| Game events | reliable + ordered |
| Chat | reliable + ordered |
| File / bulk transfer | reliable + unordered, low priority |

Internals:

- One **congestion controller per connection** with per-channel scheduling on top, so bulk transfers cannot starve latency-sensitive traffic.
- Congestion control: **NewReno**, following QUIC's loss detection and recovery design (RFC 9002). It sits behind an internal controller interface (on-sent, on-acked, on-lost, can-send), so Cubic or a delay-based controller can be added later without an API change **[DEFER]**.
- MTU: conservative default (about 1200 bytes) with optional path-MTU discovery **[DEFER]**.

---

## 7. Threading Model

- A `pierce_ctx` is **single-owner**: one thread calls everything on it.
- **Thread-safe entry points** (the complete list):
  - `pierce_send` / `pierce_send_many` (internally queue and signal the wake fd)
  - `pierce_wake`
  - `pierce_msg_release`
- `pierce_msg_retain` is **not** callable from any thread. It must be called on the owning thread, before the next `pierce_poll` / `pierce_poll_conn`, because that is when the borrowed `data` expires. The handle it returns can then be passed to and released on any thread.
- `pierce_poll` runs receive, timers, and transmit. Users can run it on the main thread (game loop, timeout 0) or a dedicated thread (blocking, timeout -1).
- No library-owned threads in the core. A convenience I/O-thread wrapper may be offered later on top of this API.
- Protocol state is only ever mutated by the poll thread.

### 7.1 Cross-thread send synchronization

`pierce_send` must validate a connection ID and check queue space without racing the poll thread recycling that slot:

- The connection table is a fixed-capacity array of slots allocated at context creation (capacity from config), so it never moves or reallocates.
- Each slot holds an **atomic generation** and a **send-queue lock**. The send queue (and its byte count) is the only per-connection state other threads touch.
- `pierce_send`: take the slot's queue lock, compare the slot's generation to the ID's generation (mismatch returns `PIERCE_ERR_NO_SUCH_CONN`), check capacity (full returns `PIERCE_ERR_WOULD_BLOCK`), push, unlock, signal wake.
- The poll thread frees a connection by taking the same lock, bumping the generation, discarding the queue, and unlocking. Only after that does it return the slot to the free list. A send racing a close therefore either lands in the queue before the close (and is discarded) or sees the new generation and fails cleanly.

---

## 8. Public C API

### 8.1 Conventions

- Prefix `pierce_` for functions and types, `PIERCE_` for constants and macros. Types do not use a `_t` suffix (POSIX reserves it).
- Opaque handles for contexts. **Integer IDs for connections** (never pointers), carried as `uint64_t`.
- Connection ID = 32-bit slot index + 21-bit generation counter, so a recycled slot never aliases an old ID. Stale IDs return `PIERCE_ERR_NO_SUCH_CONN`.
- **IDs are always below 2^53**, so they are exact in JavaScript Numbers and doubles in every binding. When a slot's generation would wrap, the slot is retired for the life of the context instead of reused.
- Generation starts at 1, so `PIERCE_CONN_NONE` (0) is never a valid ID.
- Every config/event struct begins with `uint32_t struct_size` for ABI versioning. Only append fields. Small value structs embedded in other structs (`pierce_addr`) have a **frozen layout** instead and include reserved bytes for future use.
- No varargs, no struct-by-value returns, no unions, no bitfields.
- Integer error codes (negative) plus `pierce_strerror(code)`.
- Close and reject **reason codes** are `uint32_t`. Values `0x0000`-`0xFFFF` are reserved for the library (`PIERCE_REASON_*`). Values from `PIERCE_REASON_APP_BASE` (`0x10000`) up belong to the application and pass through to the peer unchanged.
- Library never calls out to the app. Exception: optional allocator hooks, invoked synchronously.

### 8.2 Header sketch

```c
#include <stdint.h>
#include <stddef.h>

#define PIERCE_API_VERSION 1

typedef struct pierce_ctx pierce_ctx;
typedef uint64_t pierce_conn_id;          /* always < 2^53 */
typedef uintptr_t pierce_socket;          /* POSIX fd or Windows SOCKET */

#define PIERCE_CONN_NONE ((pierce_conn_id)0)

/* ---- errors ---- */
enum {
    PIERCE_OK                  =  0,
    PIERCE_ERR_INVALID_ARG     = -1,
    PIERCE_ERR_NO_MEMORY       = -2,
    PIERCE_ERR_NO_SUCH_CONN    = -3,
    PIERCE_ERR_WOULD_BLOCK     = -4,  /* send queue full */
    PIERCE_ERR_NOT_SUPPORTED   = -5,
    PIERCE_ERR_PLATFORM        = -6,
    PIERCE_ERR_CRYPTO          = -7,
    PIERCE_ERR_TIMEOUT         = -8,
    PIERCE_ERR_VERSION         = -9,
    PIERCE_ERR_CLOSED          = -10, /* peer closed; see event.reason */
    PIERCE_ERR_REJECTED        = -11, /* peer rejected; see event.reason */
    PIERCE_ERR_UNREACHABLE     = -12, /* traversal and relay both failed */
    PIERCE_ERR_BUFFER_TOO_SMALL = -13
};
const char *pierce_strerror(int code);

/* ---- close / reject reasons ---- */
enum {
    PIERCE_REASON_NONE         = 0,
    PIERCE_REASON_SHUTDOWN     = 1,   /* local ctx destroyed */
    PIERCE_REASON_POLICY       = 2,   /* generic app rejection */
    PIERCE_REASON_SERVER_FULL  = 3,
    PIERCE_REASON_PROTOCOL     = 4,   /* peer violated protocol */
    PIERCE_REASON_CHANNEL_MISMATCH = 5, /* proposed channel table refused */
    PIERCE_REASON_APP_BASE     = 0x10000
};

/* ---- addresses (frozen layout, no struct_size) ---- */
enum {
    PIERCE_AF_NONE   = 0,
    PIERCE_AF_INET   = 1,
    PIERCE_AF_INET6  = 2,
    PIERCE_AF_CUSTOM = 3              /* app transport; endpoint in `custom` */
};

typedef struct {
    uint32_t family;
    uint32_t scope_id;                /* IPv6 zone; 0 otherwise */
    uint8_t  addr[16];                /* IPv4 uses the first 4 bytes */
    uint16_t port;                    /* host byte order */
    uint8_t  reserved[6];
    uint64_t custom;                  /* app-defined endpoint for PIERCE_AF_CUSTOM */
} pierce_addr;                        /* 40 bytes */

/* ---- allocator (optional) ---- */
typedef struct {
    void *(*alloc)(size_t size, void *user);
    void  (*free)(void *ptr, void *user);
    void  *user;
} pierce_allocator;

/* ---- context ---- */
typedef struct {
    uint32_t struct_size;
    const uint8_t *identity_secret_key;   /* 32-byte X25519 secret, or NULL to generate ephemeral */
    uint32_t max_connections;             /* connection table capacity; 0 = default */
    const char **stun_servers;            /* "host:port" strings */
    uint32_t stun_server_count;
    const char **relay_servers;
    uint32_t relay_server_count;
    uint32_t keepalive_interval_ms;       /* 0 = default */
    uint32_t flags;                       /* e.g. PIERCE_CFG_NO_BUILTIN_UDP */
    const pierce_allocator *allocator;    /* NULL = malloc/free */
} pierce_config;

int  pierce_ctx_create(const pierce_config *cfg, pierce_ctx **out);
void pierce_ctx_destroy(pierce_ctx *ctx);

/* ---- keys (no storage; the app persists the secret however it likes) ---- */
int pierce_keygen(uint8_t secret_out[32]);                  /* PAL secure random */
int pierce_public_key(const uint8_t secret[32], uint8_t public_out[32]);
int pierce_fingerprint(const uint8_t public_key[32], uint8_t out[32]); /* BLAKE2b-256 */
int pierce_ctx_public_key(pierce_ctx *ctx, uint8_t out[32]); /* incl. ephemeral keys */

/* ---- channels ---- */
typedef struct {
    uint32_t struct_size;
    uint32_t id;
    uint32_t flags;           /* RELIABLE, ORDERED, SEQUENCED */
    uint32_t priority;
    uint32_t max_lifetime_ms; /* 0 = none */
    uint32_t max_retransmits; /* 0 = none */
    uint32_t max_message_size;
} pierce_channel_config;

/* ---- connections ---- */
typedef struct {
    uint32_t struct_size;
    uint64_t user_data;                   /* returned in every event; see 8.3 */
    const pierce_channel_config *channels;
    uint32_t channel_count;
} pierce_conn_options;

/* Begin outbound. invite = blob from the host's pierce_get_invite (IK),
   or NULL/0 to connect without one (XX; verify via PEER_REQUEST). */
int pierce_connect(pierce_ctx *ctx, const pierce_conn_options *opt,
                   const uint8_t *invite, uint32_t invite_len,
                   pierce_conn_id *out);
/* Accept incoming connections. opt applies to each new connection;
   opt->user_data is their initial user_data until pierce_accept. */
int pierce_listen(pierce_ctx *ctx, const pierce_conn_options *opt);
/* user_data replaces the listener's default for this connection. */
int pierce_accept(pierce_ctx *ctx, pierce_conn_id id, uint64_t user_data);
int pierce_reject(pierce_ctx *ctx, pierce_conn_id id, uint32_t reason);
int pierce_close(pierce_ctx *ctx, pierce_conn_id id, uint32_t reason);
/* Agreed (or, during PEER_REQUEST, proposed) channel table.
   Returns the channel count; writes up to cap entries. */
int pierce_conn_channels(pierce_ctx *ctx, pierce_conn_id id,
                         pierce_channel_config *out, uint32_t cap);

/* ---- signaling (inputs; outputs arrive as PIERCE_EV_SIGNAL_OUT) ---- */
/* Static, reusable invite: format version + host public key.
   Returns length written, or PIERCE_ERR_BUFFER_TOO_SMALL. */
int pierce_get_invite(pierce_ctx *ctx, uint8_t *buf, uint32_t cap);
/* Feed any blob received from a remote peer. Blobs identify their own
   session; the library routes them. On success *out_id is the connection
   the blob applied to. A new offer on a listening context creates a
   connection and returns its new ID. */
int pierce_signal_in(pierce_ctx *ctx, const uint8_t *data, uint32_t len,
                     pierce_conn_id *out_id);

/* ---- data (thread-safe) ---- */
int pierce_send(pierce_ctx *ctx, pierce_conn_id id, uint32_t channel,
                const uint8_t *data, uint32_t len, uint32_t flags);
int pierce_send_many(pierce_ctx *ctx, const pierce_conn_id *ids, uint32_t n,
                     uint32_t channel, const uint8_t *data, uint32_t len,
                     uint32_t flags);

/* ---- event loop ---- */
enum {
    PIERCE_EV_NONE = 0,
    PIERCE_EV_PEER_REQUEST,       /* incoming handshake; accept or reject */
    PIERCE_EV_CONNECTED,
    PIERCE_EV_DISCONNECTED,
    PIERCE_EV_MESSAGE,
    PIERCE_EV_SIGNAL_OUT,         /* app must deliver to the remote peer */
    PIERCE_EV_TRANSMIT,           /* only when builtin UDP is disabled */
    PIERCE_EV_PATH_CHANGED,
    PIERCE_EV_SEND_BUFFER_LOW,
    PIERCE_EV_LOG
};

typedef struct {
    uint32_t struct_size;
    uint32_t type;
    pierce_conn_id conn_id;
    uint64_t user_data;
    uint32_t channel;
    uint32_t flags;           /* delivery flags as received */
    uint64_t timestamp_us;
    const uint8_t *data;      /* borrowed: valid until next poll / poll_conn, or retained */
    uint32_t data_len;
    int32_t  error;           /* for disconnects and failures */
    void    *msg_handle;      /* for pierce_msg_retain */
    uint32_t reason;          /* DISCONNECTED: peer- or library-supplied reason */
    pierce_addr addr;         /* TRANSMIT: destination; PATH_CHANGED: new remote */
    const uint8_t *peer_key;  /* 32-byte remote public key (PEER_REQUEST, CONNECTED);
                                 same lifetime as data */
} pierce_event;

int  pierce_poll(pierce_ctx *ctx, pierce_event *out, uint32_t max,
                 int32_t timeout_ms);                    /* returns count or <0 */
int  pierce_poll_conn(pierce_ctx *ctx, pierce_conn_id id,
                      pierce_event *out, uint32_t max);  /* optional filtered drain */
int  pierce_flush(pierce_ctx *ctx);                      /* transmit only */
void pierce_wake(pierce_ctx *ctx);                       /* thread-safe */
int  pierce_next_timeout_ms(pierce_ctx *ctx);            /* for external loops */

/* ---- zero-copy retention (thread-safe) ---- */
void *pierce_msg_retain(const pierce_event *ev);
void  pierce_msg_release(void *handle);
int   pierce_event_copy(const pierce_event *ev, uint8_t *dst, uint32_t cap);

/* ---- custom transports (sans-I/O) ---- */
int pierce_transport_in(pierce_ctx *ctx, const pierce_addr *src,
                        const uint8_t *data, uint32_t len);

/* ---- lifecycle hooks the host feeds in ---- */
void pierce_net_changed(pierce_ctx *ctx);
void pierce_suspend(pierce_ctx *ctx);
void pierce_resume(pierce_ctx *ctx);

/* ---- event-loop integration (optional) ---- */
int pierce_get_fds(pierce_ctx *ctx, pierce_socket *fds, uint32_t cap);
```

Exact signatures are provisional. The shape (ID-based, event-driven, no outbound callbacks) is the commitment.

The v1 header, [include/pierce.h](include/pierce.h), is authoritative. Beyond this sketch it adds:
- `*_init` helpers for the config, option and channel structs.
- `pierce_add_local_address`, for public server addresses, port forwards and custom-transport endpoints.
- `pierce_set_relay_token`, plus relay tokens in the config.
- `pierce_conn_info_get`, `pierce_msg_data`, `pierce_addr_parse` and `pierce_addr_format`.
- A handshake payload in `pierce_conn_options`, capped at 768 bytes so `HS_INIT` fits one datagram.
- `bind_port`, timeouts, buffer sizes and a log level in `pierce_config`.
- `PIERCE_ERR_STATE`.

### 8.3 Event model details

- `pierce_poll` returns an array of events, each tagged with `conn_id` and the app's `user_data`. One global stream; no per-connection readiness scanning.
- `user_data` on an incoming connection is the listener's `pierce_conn_options.user_data` until the app calls `pierce_accept`, and the value passed to `pierce_accept` from then on. Events for an outbound connection carry the value given to `pierce_connect`.
- Events not tied to a connection (`PIERCE_EV_LOG`, context-level errors) have `conn_id = PIERCE_CONN_NONE`.
- `PIERCE_EV_DISCONNECTED` sets `error` to the cause (`PIERCE_ERR_CLOSED`, `PIERCE_ERR_REJECTED`, `PIERCE_ERR_TIMEOUT`, `PIERCE_ERR_UNREACHABLE`, ...) and `reason` to the reason code the peer or library supplied.
- Each event is delivered exactly once, whether drained by `pierce_poll` or `pierce_poll_conn`.
- `timeout_ms`: `0` non-blocking, `-1` block until an event or wake, `>0` bounded wait. The library clamps the wait to its next internal timer.
- Internally each connection has a **bounded receive queue**, drained round-robin, so one flooding peer cannot starve others or grow memory without limit. Overflow drops on unreliable channels and applies flow control on reliable ones.

### 8.4 Data lifetime

1. **Default**: `data` (and `peer_key`) are borrowed and valid until the next call to **either** `pierce_poll` or `pierce_poll_conn` on that context, whichever comes first. Draining one connection with `pierce_poll_conn` therefore invalidates borrowed data from an earlier `pierce_poll`, and the reverse. Wrappers copy immediately.
2. **Opt-in zero-copy**: `pierce_msg_retain` increments an atomic refcount and returns a handle. It must be called on the owning thread before borrowed data expires (section 7). `pierce_msg_release` decrements it from any thread; the last release frees (or recycles) the buffer.
3. **Convenience**: `pierce_event_copy` copies into a caller buffer.

Buffers are pooled. Allocator hooks must be thread-safe if the app retains messages across threads (default `malloc`/`free` is).

### 8.5 Sending

- `pierce_send` copies into a per-connection queue and returns. It never touches the socket.
- Packets go out during `pierce_poll`, or on demand via `pierce_flush`.
- Backpressure: `PIERCE_ERR_WOULD_BLOCK` and a `PIERCE_EV_SEND_BUFFER_LOW` event.
- `pierce_send_many` crosses the FFI boundary once and copies the payload once, into a single refcounted buffer that each target connection's queue references. Like `pierce_send`, it does no crypto; each peer's copy is encrypted under its own keys at transmit time during `pierce_poll` / `pierce_flush`. If some targets fail (stale ID, queue full), the rest are still queued; the return value is the number queued, or negative if the call itself was invalid.

### 8.6 Signaling flow

Signaling is deliberately outside the library. The app carries opaque blobs between peers by any means (HTTP, a chat message, a QR code, copy-paste). There are three blob kinds:

| Blob | Produced by | Contents | Lifetime |
|---|---|---|---|
| **Invite** | `pierce_get_invite` (host) | format version, host public key, and any addresses added with `pierce_add_local_address` | Static; reusable for any number of clients. Safe to print as a QR code. An invite with addresses connects directly, with no offer or answer (section 10). |
| **Offer** | `PIERCE_EV_SIGNAL_OUT` on the client | session ID, client candidates, client probe secret | Per connection |
| **Answer** | `PIERCE_EV_SIGNAL_OUT` on the host | session ID, host candidates, host probe secret | Per connection |

Further trickled candidates (section 5.2) are sent as additional blobs carrying the same session ID.

Flow:

1. Host calls `pierce_listen` and publishes its invite (`pierce_get_invite`) by any channel. See section 4.3.1 for what that channel must guarantee.
2. Client calls `pierce_connect` with the invite. It gets a conn ID right away and emits an **offer** as `PIERCE_EV_SIGNAL_OUT`.
3. App delivers the offer to the host. The host app calls `pierce_signal_in`, which creates a new connection and returns its ID in `out_id`. The host app records which signaling route that ID came from.
4. Host emits an **answer** (`PIERCE_EV_SIGNAL_OUT` tagged with that conn ID). The app sends it back on the recorded route; the client app calls `pierce_signal_in`.
5. Both sides probe (section 5.1), then run the Noise handshake on the selected path.
6. Host gets `PIERCE_EV_PEER_REQUEST` (client public key plus any handshake payload) and calls `pierce_accept` or `pierce_reject`.
7. `PIERCE_EV_CONNECTED` fires on both sides. On rejection, the client gets `PIERCE_EV_DISCONNECTED` with `PIERCE_ERR_REJECTED` and the host's reason.

Because blobs carry their own session ID, apps never have to parse them: every received blob goes straight into `pierce_signal_in`. Blobs for unknown or expired sessions return `PIERCE_ERR_NO_SUCH_CONN`.

---

## 9. Mobile and Network Mobility

v1 ships desktop only, but the API includes mobile-ready hooks from the start:

| Hook | Purpose |
|---|---|
| `pierce_net_changed` | Wrapper calls on connectivity change; triggers re-gather and re-probe |
| `pierce_suspend` / `pierce_resume` | Pause timers and keepalives; re-validate paths on resume |
| Configurable keepalive interval | Cellular NAT timeouts can be 30 s or less; app tunes against battery |

Design consequences already built in:

- Connection ID in every packet lets a session **survive IP changes** (NAT rebinding, Wi-Fi to cellular). The peer updates the remote address after authenticating a packet from the new one. Because the v1 connection ID is fixed, an on-path observer can link the old and new addresses; rotation is deferred but the wire format leaves room for it (section 4.5).
- Path re-validation (an "ICE restart" equivalent) is part of the traversal layer.
- Mobile-to-mobile pairs frequently require relay.

Platform notes for later ports:

- **Android**: `getifaddrs` is API 24+ and may be restricted by version; fall back to the connect-a-UDP-socket trick for the default route address. `getrandom` availability varies; fall back to `/dev/urandom`. JNI and `ConnectivityManager` live in the wrapper, not the core.
- **iOS**: Local Network permission prompt (iOS 14+) affects LAN candidates and must degrade gracefully. Must work on IPv6-only NAT64 networks. Packaging as XCFramework with a module map.
- Backgrounded chat delivery requires push notifications and a store-and-forward server, outside the library's scope.

---

## 10. Server Mode

- At the API level there is **no distinction** between host and dedicated server. A server is a peer with a public address where traversal trivially succeeds.
- The listener is a **distinct scalable implementation**: one UDP socket demultiplexed by connection ID, `epoll` / `kqueue` behind the PAL wait function (an optimization that does not change the API), and optionally `recvmmsg` / `sendmmsg` batching.
- Scale target for v1: **hundreds of clients per listener** (designed for about 1000). Plain `poll` on one socket is sufficient at this scale. `epoll` / `kqueue` and `recvmmsg` / `sendmmsg` are optimizations, not requirements. Thousands-plus (per-core sharding, mandatory batching) is **[DEFER]**.
- Relay server is the same listener design with a forward-only handler.
- **Host migration [DEFER]**: in v1 a game whose host leaves has to rebuild its session itself using mesh connections and `pierce_connect` to a new host. A library-level host-migration helper (choosing the new host, re-pointing connections) is planned after v1. Moving game state stays the app's job.

---

## 11. Wrapper Guidance

- Primary integration surface is the event stream. Wrappers convert it into callbacks, async iterators, channels, or per-connection queues as idiomatic.
- Copy payloads immediately in GC'd languages; do not rely on finalizers to release retained buffers.
- Rust / C++: wrap retained buffers in an RAII type for safe zero-copy.
- Connection IDs are guaranteed below 2^53, so they map to plain integers in every language, including JavaScript Numbers (no BigInt needed). `user_data` is a full 64 bits; JS wrappers should store only object indexes below 2^53 in it.
- First wrapper targets, in order: **C++** (thin RAII header), **Python** (validates the copy-immediately rules for GC'd languages), **Rust** (RAII zero-copy; stress-tests the threading rules).

---

## 12. Testing Strategy

- **Deterministic simulation**: inject time and recorded or synthetic datagrams (sans-I/O makes this possible). Loss, reordering, duplication, delay.
- **Noise test vectors** for the handshake. Fuzz all packet parsers.
- **NAT matrix**: a lab (network namespaces / containers) emulating full-cone, restricted, port-restricted, and symmetric NATs, plus CGNAT and hairpin cases.
- **Real-world field tests** across ISPs and mobile carriers (the hard part).
- Soak tests for the listener: connection churn, floods, malformed handshakes.
- Sanitizers (ASan/UBSan/TSan) in CI on all three desktop platforms.

---

## 13. Roadmap

1. **Vertical slice**: two peers behind NAT, STUN-style gathering, probe-based punch, Noise handshake, three channel types, poll-based C API.
2. **Transport abstraction proof**: add TCP framing fallback and show the same channel API works over both.
3. **Relay**: reference relay server and allocation protocol.
4. **Listener**: connection-ID demux server with bounded queues and cookie handshake.
5. **Congestion control and scheduling**: mixed bulk and real-time traffic.
6. **Wrappers**: C++, then Python, then Rust, driving API revisions.
7. **Mobile ports**, then WASM (app-supplied transport), then optional standards-compliant ICE module.
8. **Post-v1 features**: host-migration helper, signed relay tokens, connection-ID rotation, alternative congestion controllers.

---

## 14. Open Questions

This is the complete list. Every inline **[OPEN]** marker refers to a number here. The remaining item is work to do, not a design decision.

12. Name collisions: check crates.io, PyPI, npm, GitHub for `pierce`; likely repo name `libpierce`.

### Resolved in v0.2

Numbers are kept so older references still make sense.

- **Q1 Wrappers:** C++, then Python, then Rust (section 11).
- **Q2 Server scale:** hundreds per listener in v1; thousands-plus deferred (section 10).
- **Q3 Standards and browsers:** custom traversal in v1 with a gateway for browser peers; a standards-compliant mode is deferred (sections 1, 5.4).
- **Q4 Reference relay:** shipped with Pierce; apps may still run their own (section 5.3).
- **Q5 Identity default:** the API defaults to ephemeral keys, the docs use TOFU as the happy path, and key storage and trust policy belong to the app. The library provides key helpers only (sections 4.3, 8.2).
- **Q6 Encryption:** always on in v1; an insecure mode is deferred, with a suite byte reserved in the handshake (section 4.2).
- **Q7 Time:** the public `pierce_poll` reads the monotonic clock. Internally the core takes `now_us` as an explicit input, so simulation tests stay deterministic (section 12).
- **Q8 Channel table:** the initiator proposes it in the handshake; the listener auto-checks it or the app inspects it (section 6).
- **Q9 Congestion control:** NewReno per RFC 9002, behind an internal interface (section 6).
- **Q10 Host migration:** a library helper planned after v1; v1 apps handle it themselves (section 10).
- **Q11 License:** MIT.
- **Identity key:** X25519 only; no signing key in v1 (section 4.3).
- **Connection IDs:** capped below 2^53 for exact representation in every language (section 8.1).
- **Connection-ID rotation:** deferred, with the wire format designed to allow it later (section 4.5).
- **Relay authentication:** typed tokens. Shared-secret MAC tokens ship in v1; signed tokens are deferred (section 5.3.2).

### Resolved in v0.4

- **Connectivity defaults:** built-in public STUN servers, router port mapping (PCP/NAT-PMP/UPnP) and birthday punching are all on by default, with opt-out flags (section 5.5). UPnP's HTTP is allowed in the core because it only talks to the local router.

### Resolved in v0.3 (during implementation)

- **Q13 Relay allocation protocol:** specified in docs/wire.md section 6. Allocations are bound to the source address or TCP connection, refreshed by the client every `min(lifetime / 3, keepalive)`, and expire after 600 s by default. Peers may use each other's relay candidates only when both hold allocations on the same relay instance (matched by server id); the relay is never an open proxy to arbitrary addresses.

---

## 15. Naming

**Pierce** works three ways: it punches through NATs, it sounds like *peers*, and it is short enough to be a comfortable symbol prefix. Suggested branding: *"Pierce: because it connects peers, and punches through NATs."* Supporting component names (optional): **Pierce Relay** for the relay server, and themed names like *Eye* (signaling interface) if a consistent theme is wanted.