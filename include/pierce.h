/*
 * Pierce: NAT-traversing, encrypted, channel-based connections.
 * Public C API, version 1. See spec.md for the design.
 *
 * Conventions:
 *   - Functions return PIERCE_OK (0) or a negative PIERCE_ERR_* code unless
 *     documented otherwise.
 *   - Every config/event struct starts with struct_size. Set it with the
 *     *_init helpers (or to sizeof the struct) before use.
 *   - A pierce_ctx is owned by one thread. Only the functions marked
 *     "thread-safe" may be called from other threads.
 */
#ifndef PIERCE_H
#define PIERCE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(PIERCE_SHARED)
#  ifdef PIERCE_BUILD
#    define PIERCE_API __declspec(dllexport)
#  else
#    define PIERCE_API __declspec(dllimport)
#  endif
#elif defined(__GNUC__) && defined(PIERCE_BUILD)
#  define PIERCE_API __attribute__((visibility("default")))
#else
#  define PIERCE_API
#endif

#define PIERCE_API_VERSION 1
#define PIERCE_KEY_SIZE 32          /* X25519 keys and fingerprints */
#define PIERCE_MAX_CHANNELS 32

typedef struct pierce_ctx pierce_ctx;
typedef uint64_t pierce_conn_id;    /* always < 2^53 */
typedef uintptr_t pierce_socket;    /* POSIX fd or Windows SOCKET */

#define PIERCE_CONN_NONE ((pierce_conn_id)0)

/* ---- errors ---- */
enum {
    PIERCE_OK                   =  0,
    PIERCE_ERR_INVALID_ARG      = -1,
    PIERCE_ERR_NO_MEMORY        = -2,
    PIERCE_ERR_NO_SUCH_CONN     = -3,
    PIERCE_ERR_WOULD_BLOCK      = -4,  /* send queue full */
    PIERCE_ERR_NOT_SUPPORTED    = -5,
    PIERCE_ERR_PLATFORM         = -6,
    PIERCE_ERR_CRYPTO           = -7,
    PIERCE_ERR_TIMEOUT          = -8,
    PIERCE_ERR_VERSION          = -9,
    PIERCE_ERR_CLOSED           = -10, /* connection closed; see event.reason */
    PIERCE_ERR_REJECTED         = -11, /* peer rejected; see event.reason */
    PIERCE_ERR_UNREACHABLE      = -12, /* traversal and relay both failed */
    PIERCE_ERR_BUFFER_TOO_SMALL = -13,
    PIERCE_ERR_STATE            = -14  /* call not valid in the current state */
};
PIERCE_API const char *pierce_strerror(int code);

/* ---- close / reject reasons ---- */
enum {
    PIERCE_REASON_NONE             = 0,
    PIERCE_REASON_SHUTDOWN         = 1,  /* local ctx destroyed */
    PIERCE_REASON_POLICY           = 2,  /* generic app rejection */
    PIERCE_REASON_SERVER_FULL      = 3,
    PIERCE_REASON_PROTOCOL         = 4,  /* peer violated protocol */
    PIERCE_REASON_CHANNEL_MISMATCH = 5,  /* proposed channel table refused */
    PIERCE_REASON_TIMEOUT          = 6,  /* peer request not answered in time */
    PIERCE_REASON_APP_BASE         = 0x10000
};

/* ---- addresses (frozen layout, no struct_size) ---- */
enum {
    PIERCE_AF_NONE   = 0,
    PIERCE_AF_INET   = 1,
    PIERCE_AF_INET6  = 2,
    PIERCE_AF_CUSTOM = 3               /* app transport; endpoint in `custom` */
};

typedef struct {
    uint32_t family;
    uint32_t scope_id;                 /* IPv6 zone; 0 otherwise */
    uint8_t  addr[16];                 /* IPv4 uses the first 4 bytes */
    uint16_t port;                     /* host byte order */
    uint8_t  reserved[6];
    uint64_t custom;                   /* app-defined endpoint for PIERCE_AF_CUSTOM */
} pierce_addr;                         /* 40 bytes */

/* Parse "1.2.3.4:5678", "[::1]:5678" (numeric only, no DNS). */
PIERCE_API int pierce_addr_parse(const char *str, pierce_addr *out);
/* Format as above. Returns length written (excluding NUL) or an error. */
PIERCE_API int pierce_addr_format(const pierce_addr *addr, char *buf, uint32_t cap);

/* ---- allocator (optional) ----
 * Must be thread-safe if messages are retained and released on other
 * threads. */
typedef struct {
    void *(*alloc)(size_t size, void *user);
    void  (*free)(void *ptr, void *user);
    void  *user;
} pierce_allocator;

/* ---- keys (no storage; the app persists the secret however it likes) ---- */
PIERCE_API int pierce_keygen(uint8_t secret_out[32]);
PIERCE_API int pierce_public_key(const uint8_t secret[32], uint8_t public_out[32]);
PIERCE_API int pierce_fingerprint(const uint8_t public_key[32], uint8_t out[32]);

/* ---- context ---- */
enum {
    PIERCE_CFG_NO_BUILTIN_UDP      = 1u << 0, /* app moves datagrams: TRANSMIT / transport_in */
    PIERCE_CFG_NO_IPV6             = 1u << 1,
    PIERCE_CFG_NO_IPV4             = 1u << 2,
    PIERCE_CFG_RELAY_ONLY          = 1u << 3, /* never reveal local or reflexive addresses */
    PIERCE_CFG_INCLUDE_LOOPBACK    = 1u << 4  /* offer loopback host candidates (testing) */
};

enum {
    PIERCE_LOG_OFF   = 0,
    PIERCE_LOG_ERROR = 1,
    PIERCE_LOG_WARN  = 2,
    PIERCE_LOG_INFO  = 3,
    PIERCE_LOG_DEBUG = 4
};

typedef struct {
    uint32_t struct_size;
    const uint8_t *identity_secret_key;    /* 32-byte X25519 secret, or NULL to generate ephemeral */
    uint32_t max_connections;              /* connection table capacity; 0 = 1024 */
    const char *const *stun_servers;       /* "host:port" strings */
    uint32_t stun_server_count;
    const char *const *relay_servers;      /* "host:port" (UDP) or "tcp://host:port" */
    uint32_t relay_server_count;
    uint32_t keepalive_interval_ms;        /* 0 = 15000 */
    uint32_t flags;                        /* PIERCE_CFG_* */
    const pierce_allocator *allocator;     /* NULL = malloc/free */
    /* -- appended in v1 -- */
    uint32_t bind_port;                    /* builtin UDP port; 0 = ephemeral */
    uint32_t idle_timeout_ms;              /* 0 = 30000 */
    uint32_t connect_timeout_ms;           /* traversal + handshake + accept; 0 = 15000 */
    uint32_t send_buffer_bytes;            /* per connection; 0 = 1 MiB */
    uint32_t recv_buffer_bytes;            /* per connection, undelivered; 0 = 1 MiB */
    uint32_t log_level;                    /* PIERCE_LOG_*; delivered as PIERCE_EV_LOG */
    const uint8_t *const *relay_tokens;    /* parallel to relay_servers; entries may be NULL */
    const uint32_t *relay_token_lens;
} pierce_config;

PIERCE_API void pierce_config_init(pierce_config *cfg);
PIERCE_API int  pierce_ctx_create(const pierce_config *cfg, pierce_ctx **out);
PIERCE_API void pierce_ctx_destroy(pierce_ctx *ctx);
PIERCE_API int  pierce_ctx_public_key(pierce_ctx *ctx, uint8_t out[32]); /* incl. ephemeral */

/* Declare an address this context is reachable at (a public server address,
   a port forward, or the local endpoint of a custom transport). Included in
   invites and offered as a candidate. */
PIERCE_API int pierce_add_local_address(pierce_ctx *ctx, const pierce_addr *addr);
/* Replace the token for relay_servers[index] (tokens expire). */
PIERCE_API int pierce_set_relay_token(pierce_ctx *ctx, uint32_t index,
                                      const uint8_t *token, uint32_t len);

/* ---- channels ---- */
enum {
    PIERCE_CHANNEL_RELIABLE  = 1u << 0,
    PIERCE_CHANNEL_ORDERED   = 1u << 1,
    PIERCE_CHANNEL_SEQUENCED = 1u << 2   /* unreliable; drop anything older than the last delivered */
};

typedef struct {
    uint32_t struct_size;
    uint32_t id;               /* the number passed to pierce_send; unique per table */
    uint32_t flags;            /* PIERCE_CHANNEL_* */
    uint32_t priority;         /* higher is scheduled first */
    uint32_t max_lifetime_ms;  /* 0 = none */
    uint32_t max_retransmits;  /* 0 = none (reliable channels retry forever) */
    uint32_t max_message_size; /* 0 = 256 KiB */
} pierce_channel_config;

PIERCE_API void pierce_channel_config_init(pierce_channel_config *ch);

/* ---- connections ---- */
typedef struct {
    uint32_t struct_size;
    uint64_t user_data;                    /* returned in every event */
    const pierce_channel_config *channels; /* NULL/0 = one reliable ordered channel, id 0 */
    uint32_t channel_count;
    /* -- appended in v1 -- */
    const uint8_t *handshake_payload;      /* sent encrypted to the responder (credentials) */
    uint32_t handshake_payload_len;        /* max 768 */
} pierce_conn_options;

PIERCE_API void pierce_conn_options_init(pierce_conn_options *opt);

/* Begin outbound. invite = blob from the host's pierce_get_invite (IK),
   or NULL/0 to connect without one (XX; verify via PEER_REQUEST).
   If the invite contains addresses, the connection is made directly and no
   signaling is needed. */
PIERCE_API int pierce_connect(pierce_ctx *ctx, const pierce_conn_options *opt,
                              const uint8_t *invite, uint32_t invite_len,
                              pierce_conn_id *out);
/* Accept incoming connections. opt applies to each new connection;
   opt->user_data is their initial user_data until pierce_accept. A non-NULL
   channel table makes the library reject proposals that differ. */
PIERCE_API int pierce_listen(pierce_ctx *ctx, const pierce_conn_options *opt);
/* Answer a PIERCE_EV_PEER_REQUEST. user_data replaces the previous value. */
PIERCE_API int pierce_accept(pierce_ctx *ctx, pierce_conn_id id, uint64_t user_data);
PIERCE_API int pierce_reject(pierce_ctx *ctx, pierce_conn_id id, uint32_t reason);
/* Immediate close: queued data is discarded. A PIERCE_EV_DISCONNECTED
   (error PIERCE_OK) follows; the ID stays valid until it is polled. */
PIERCE_API int pierce_close(pierce_ctx *ctx, pierce_conn_id id, uint32_t reason);
/* Agreed (or, during PEER_REQUEST, proposed) channel table.
   Returns the channel count; writes up to cap entries. */
PIERCE_API int pierce_conn_channels(pierce_ctx *ctx, pierce_conn_id id,
                                    pierce_channel_config *out, uint32_t cap);

enum {
    PIERCE_PATH_NONE   = 0,
    PIERCE_PATH_DIRECT = 1,
    PIERCE_PATH_RELAY  = 2
};

typedef struct {
    uint32_t struct_size;
    uint32_t path;             /* PIERCE_PATH_* */
    pierce_addr remote;        /* remote address (relay server for relayed paths) */
    uint8_t  peer_key[32];     /* zero until the handshake reveals it */
    uint64_t rtt_us;           /* smoothed RTT */
    uint64_t cwnd_bytes;
    uint64_t bytes_in_flight;
    uint64_t packets_sent;
    uint64_t packets_lost;
    uint64_t packets_received;
    uint32_t send_queue_bytes;
} pierce_conn_info;

PIERCE_API int pierce_conn_info_get(pierce_ctx *ctx, pierce_conn_id id, pierce_conn_info *out);

/* ---- signaling (inputs; outputs arrive as PIERCE_EV_SIGNAL_OUT) ---- */
/* Static, reusable invite: format version + host public key + any addresses
   added with pierce_add_local_address. Returns length written. */
PIERCE_API int pierce_get_invite(pierce_ctx *ctx, uint8_t *buf, uint32_t cap);
/* Feed any blob received from a remote peer. Blobs identify their own
   session; the library routes them. On success *out_id (may be NULL) is the
   connection the blob applied to. A new offer on a listening context
   creates a connection and returns its new ID. */
PIERCE_API int pierce_signal_in(pierce_ctx *ctx, const uint8_t *data, uint32_t len,
                                pierce_conn_id *out_id);

/* ---- data (thread-safe) ---- */
/* Copies data into the connection's send queue. flags: reserved, pass 0.
   May be called before the connection is established; data is held until
   it is. */
PIERCE_API int pierce_send(pierce_ctx *ctx, pierce_conn_id id, uint32_t channel,
                           const uint8_t *data, uint32_t len, uint32_t flags);
/* Copies once, queues on each connection. Returns the number queued, or <0
   if the call itself was invalid. */
PIERCE_API int pierce_send_many(pierce_ctx *ctx, const pierce_conn_id *ids, uint32_t n,
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
    uint32_t flags;           /* MESSAGE: channel flags; LOG: level; PATH_CHANGED: path */
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

/* Returns the number of events written to out, or <0. timeout_ms: 0 = never
   block, -1 = block until an event or pierce_wake, >0 = bounded wait. */
PIERCE_API int  pierce_poll(pierce_ctx *ctx, pierce_event *out, uint32_t max,
                            int32_t timeout_ms);
/* Drain only one connection's events (no I/O). */
PIERCE_API int  pierce_poll_conn(pierce_ctx *ctx, pierce_conn_id id,
                                 pierce_event *out, uint32_t max);
PIERCE_API int  pierce_flush(pierce_ctx *ctx);                   /* transmit only */
PIERCE_API void pierce_wake(pierce_ctx *ctx);                    /* thread-safe */
PIERCE_API int  pierce_next_timeout_ms(pierce_ctx *ctx);         /* -1 = no timer */

/* ---- zero-copy retention ---- */
/* Owning thread only, before the next poll. Returns NULL if the event has no
   data. */
PIERCE_API void *pierce_msg_retain(const pierce_event *ev);
PIERCE_API void  pierce_msg_release(void *handle);              /* thread-safe */
PIERCE_API const uint8_t *pierce_msg_data(void *handle, uint32_t *len_out);
/* Copies event data. Returns length, or PIERCE_ERR_BUFFER_TOO_SMALL. */
PIERCE_API int   pierce_event_copy(const pierce_event *ev, uint8_t *dst, uint32_t cap);

/* ---- custom transports (sans-I/O) ---- */
PIERCE_API int pierce_transport_in(pierce_ctx *ctx, const pierce_addr *src,
                                   const uint8_t *data, uint32_t len);

/* ---- lifecycle hooks the host feeds in ---- */
PIERCE_API void pierce_net_changed(pierce_ctx *ctx);
PIERCE_API void pierce_suspend(pierce_ctx *ctx);
PIERCE_API void pierce_resume(pierce_ctx *ctx);

/* ---- event-loop integration (optional) ----
   Returns the total number of sockets (may exceed cap). */
PIERCE_API int pierce_get_fds(pierce_ctx *ctx, pierce_socket *fds, uint32_t cap);

/* ---- relay tokens (for the app's backend) ----
   Type-1 shared-secret token. Returns length written (29) or an error. */
#define PIERCE_RELAY_TOKEN_SIZE 29
PIERCE_API int pierce_relay_token_create(const uint8_t *secret, uint32_t secret_len,
                                         uint64_t expiry_unix_s, uint32_t max_kbps,
                                         uint8_t *out, uint32_t cap);

#ifdef __cplusplus
}
#endif

#endif /* PIERCE_H */
