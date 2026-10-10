/* Core state shared by ctx.c, gather.c, conn.c and transport.c.
   Everything here is owned by the poll thread except pc_slot's locked
   fields (spec 7.1). */
#ifndef PIERCE_CORE_H
#define PIERCE_CORE_H

#include "common.h"
#include "noise.h"
#include "pal.h"
#include "wire.h"

/* ---- limits and defaults ---- */
#define PC_DEFAULT_MAX_CONNS      1024
#define PC_DEFAULT_KEEPALIVE_MS   15000
#define PC_DEFAULT_IDLE_MS        30000
#define PC_DEFAULT_CONNECT_MS     15000
#define PC_DEFAULT_SENDBUF        (1u << 20)
#define PC_DEFAULT_RECVBUF        (1u << 20)
#define PC_DEFAULT_MAX_MSG        (256u * 1024)
#define PC_MAX_HS_PAYLOAD         768   /* must fit HS_INIT in one 1200-byte datagram */
#define PC_MAX_LOCAL_CANDS        24
#define PC_MAX_REMOTE_CANDS       32
#define PC_MAX_STUN               8
#define PC_MAX_RELAYS             4
#define PC_MAX_LOCAL_ADDRS        8
#define PC_MAX_ACK_RANGES         32
#define PC_REPLAY_WINDOW          256
#define PC_MAX_ACK_DELAY_US       25000
#define PC_REKEY_PACKETS          (1ull << 24)
#define PC_REKEY_INTERVAL_US      (600ull * 1000000)
#define PC_RELAY_PROBE_DELAY_US   300000

/* ---- events ---- */
typedef struct pc_event {
    struct pc_event *next;
    uint32_t type;
    pierce_conn_id conn_id;
    uint64_t user_data;
    uint32_t channel;
    uint32_t flags;
    uint64_t timestamp_us;
    pc_msg *msg;
    int32_t error;
    uint32_t reason;
    pierce_addr addr;
    uint8_t peer_key[32];
    uint8_t has_peer_key;
} pc_event;

typedef struct {
    pc_event *head, *tail;
    uint32_t count;
} pc_evq;

/* ---- paths ---- */
enum { PC_PATH_KIND_DIRECT = 1, PC_PATH_KIND_RELAY = 2 };

typedef struct {
    uint8_t kind;
    pierce_addr remote;                  /* direct: peer address */
    uint32_t relay;                      /* relay: local relay index */
    uint8_t peer_relay_id[PC_RELAY_ID_LEN];
} pc_path;

int pc_path_eq(const pc_path *a, const pc_path *b);

/* ---- send side ---- */
typedef struct pc_outmsg {
    struct pc_outmsg *next;          /* channel pending queue */
    pc_msg *msg;
    uint64_t seq;
    uint32_t refs;                   /* pending queue + sent packets + rtx entries */
    uint32_t nfrag;
    uint32_t next_frag;              /* next never-sent fragment */
    uint32_t nacked;
    uint8_t *acked;                  /* nfrag bytes (1 = acked) */
    uint8_t acked_inline;
    uint32_t retransmits;
    uint64_t expiry_us;              /* 0 = none */
    uint8_t reliable;
    uint8_t finished;                /* acked, abandoned, or fully sent if unreliable */
    uint8_t in_pending;
    uint32_t channel;                /* index into conn->ch */
} pc_outmsg;

typedef struct pc_rtx {
    struct pc_rtx *next;
    pc_outmsg *m;
    uint32_t frag;
} pc_rtx;

typedef struct {
    uint32_t channel_id;
    uint64_t seq;
} pc_abandon;

typedef struct pc_sentpkt {
    struct pc_sentpkt *next;
    uint64_t pn;
    uint64_t time_sent;
    uint32_t size;
    uint8_t ack_eliciting;
    uint8_t has_accept;
    uint16_t nfrags;
    uint16_t nabandons;
    pc_rtx *frags;                   /* list of (msg, frag) carried */
    pc_abandon *abandons;
} pc_sentpkt;

/* ---- receive side ---- */
typedef struct pc_reasm {
    struct pc_reasm *next;           /* sorted by seq */
    uint64_t seq;
    uint32_t total;
    uint32_t nfrag;
    uint32_t got;
    uint8_t *have;                   /* nfrag bytes */
    pc_msg *buf;
    uint8_t complete;
    uint8_t skipped;                 /* abandoned by the sender */
    uint64_t first_us;
} pc_reasm;

typedef struct {
    pierce_channel_config cfg;
    /* send */
    uint64_t next_seq;
    pc_outmsg *pend_head, *pend_tail;
    pc_rtx *rtx_head, *rtx_tail;
    /* receive */
    uint64_t rx_next;                /* ordered: next to deliver; sequenced: last+1; unordered: base */
    pc_reasm *reasm;
    uint32_t nreasm;
    uint64_t *done;                  /* reliable unordered: delivered seqs >= rx_next */
    uint32_t ndone, capdone;
} pc_channel;

/* ---- congestion control (NewReno, RFC 9002 appendix B) ---- */
typedef struct {
    uint64_t cwnd;
    uint64_t ssthresh;
    uint64_t recovery_start_us;
    uint64_t acked_accum;            /* congestion-avoidance byte counter */
    uint8_t in_recovery_valid;
} pc_cc;

/* ---- traversal ---- */
typedef struct {
    pc_path path;
    uint32_t remote_index;
    /* Recent probes: each gets a fresh txid so an ack yields an exact RTT. */
    uint8_t txid[4][PC_TXID_LEN];
    uint64_t tx_us[4];
    uint8_t txpos;
    uint64_t next_tx_us;
    uint64_t last_tx_us;
    uint32_t tries;
    uint8_t validated;
    uint8_t rx_ok;                   /* a valid probe arrived from this path */
    uint64_t rtt_us;
} pc_pair;

#define PC_MAX_PAIRS (PC_MAX_REMOTE_CANDS + 8)

enum {
    PC_ST_SIGNALING = 1,  /* initiator: waiting for the answer */
    PC_ST_PROBING,        /* hole punching */
    PC_ST_HANDSHAKE,      /* Noise in progress */
    PC_ST_PEER_VERIFY,    /* XX initiator: app checks the responder key */
    PC_ST_AWAIT_APP,      /* responder: PEER_REQUEST outstanding */
    PC_ST_AWAIT_ACCEPT,   /* initiator: handshake done, waiting for ACCEPT */
    PC_ST_CONNECTED,
    PC_ST_CLOSED          /* DISCONNECTED queued; freed once polled */
};

typedef struct {
    uint64_t start, end;             /* inclusive */
} pc_range;

typedef struct pc_conn {
    struct pierce_ctx *ctx;
    struct pc_conn *next;            /* ctx->conns */
    uint32_t slot;
    pierce_conn_id id;
    uint64_t user_data;
    uint8_t initiator;
    uint8_t state;
    uint8_t direct;                  /* initiator connecting straight to invite addresses */
    uint8_t pattern;

    /* signaling + probing */
    uint8_t session[PC_SESSION_LEN];
    uint8_t has_session;
    uint8_t my_secret[32], peer_secret[32];
    uint8_t has_peer_secret;
    uint8_t probe_key[32];
    uint8_t has_probe_key;
    uint8_t sent_first_signal;
    uint32_t cands_sent;             /* prefix of ctx->cands already signaled */
    uint32_t cands_epoch;
    pc_cand remote[PC_MAX_REMOTE_CANDS];
    uint32_t nremote;
    pc_pair pairs[PC_MAX_PAIRS];
    uint32_t npairs;
    uint64_t probe_start_us;
    uint64_t deadline_us;            /* connect deadline; 0 = none yet */

    /* path */
    pc_path path;
    uint8_t has_path;

    /* identity */
    uint8_t peer_key[32];
    uint8_t has_peer_key;

    /* handshake */
    pc_noise hs;
    uint8_t local_cid[PC_CID_LEN], remote_cid[PC_CID_LEN];
    uint8_t has_remote_cid;
    uint8_t hs_msg[256];             /* our last Noise message, for retransmission */
    uint16_t hs_msg_len;
    uint8_t hs_pkt_type;
    uint8_t cookie[PC_COOKIE_LEN];
    uint8_t has_cookie;
    uint64_t hs_next_tx_us;
    uint64_t hs_sent_us;
    uint32_t hs_tries;
    uint8_t app_visible;             /* the app knows this ID: owe it a DISCONNECTED */
    pc_msg *peer_payload;            /* responder: initiator's app payload */
    uint8_t *hs_payload;             /* initiator: our app payload */
    uint32_t hs_payload_len;

    /* packet protection */
    uint8_t tx_key[32], rx_key[32], rx_prev_key[32];
    uint8_t keys_ready;
    uint8_t rx_prev_valid;
    uint8_t tx_phase, rx_phase;
    uint64_t tx_pn;
    uint64_t tx_rekey_pn, tx_rekey_us;
    uint64_t rx_phase_start_pn;
    uint64_t rx_prev_expire_us;
    uint64_t rx_largest;
    uint8_t rx_any;
    uint64_t rx_window[PC_REPLAY_WINDOW / 64];

    /* acks we owe */
    pc_range ackr[PC_MAX_ACK_RANGES];  /* descending by start */
    uint32_t nackr;
    uint8_t ack_pending;
    uint32_t ack_eliciting_unacked;
    uint64_t ack_deadline_us;
    uint64_t largest_rx_time_us;

    /* loss recovery (RFC 9002) */
    pc_sentpkt *sent_head, *sent_tail;
    uint64_t bytes_in_flight;
    uint64_t largest_acked;
    uint8_t any_acked;
    uint64_t loss_time_us;
    uint32_t pto_count;
    uint64_t last_eliciting_tx_us;
    uint32_t probes_to_send;
    uint64_t latest_rtt, srtt, rttvar, min_rtt;
    uint8_t has_rtt;
    pc_cc cc;

    /* channels */
    pc_channel ch[PIERCE_MAX_CHANNELS];
    uint32_t nch;
    uint8_t ch_order[PIERCE_MAX_CHANNELS];   /* indices sorted by priority desc */
    uint32_t sched_rr;
    uint8_t ch_agreed;

    /* control frames */
    uint8_t accept_pending;
    uint8_t accept_acked;
    pc_abandon *abandons;            /* pending ABANDON frames */
    uint32_t nabandons, capabandons;
    uint8_t ping_pending;
    uint32_t close_reason;
    uint8_t close_rejected;

    /* timers */
    uint64_t last_rx_us;
    uint64_t created_us;

    /* events */
    pc_evq evq;
    struct pc_conn *ready_next;
    uint8_t in_ready;
    uint64_t rx_buffered;            /* MESSAGE bytes not yet polled */
    uint64_t reasm_bytes;

    /* send-queue accounting released under the slot lock */
    uint64_t release_bytes;
    uint8_t low_wanted;

    /* stats */
    uint64_t packets_sent, packets_lost, packets_received;
} pc_conn;

/* ---- connection table slots ---- */
typedef struct pc_sendreq {
    struct pc_sendreq *next;
    pc_msg *msg;
    uint32_t channel;
} pc_sendreq;

typedef struct {
    pal_mutex lock;
    volatile uint32_t gen;           /* atomic; 0 = slot free */
    /* under lock */
    uint8_t open;                    /* accepts sends */
    uint8_t blocked;                 /* a send hit the limit since the last LOW event */
    uint8_t ch_known;
    uint32_t nch;
    uint32_t ch_ids[PIERCE_MAX_CHANNELS];
    uint32_t ch_max[PIERCE_MAX_CHANNELS];
    pc_sendreq *q_head, *q_tail;
    volatile uint32_t q_count;       /* atomic: lets the poll thread skip idle slots without the lock */
    uint64_t queued_bytes;
    uint64_t limit;
    /* poll thread only */
    pc_conn *conn;
    uint32_t last_gen;               /* generation of the most recent occupant */
    uint32_t next_free;
    uint8_t retired;
} pc_slot;

#define PC_GEN_BITS 21
#define PC_GEN_MAX ((1u << PC_GEN_BITS) - 1)

/* ---- gathering ---- */
typedef struct {
    pierce_addr addr;
    uint8_t txid[PC_STUN_TXID_LEN];
    uint64_t next_tx_us;
    uint32_t tries;
    uint8_t has_mapped;
    pierce_addr mapped;
} pc_stun;

enum { PC_RELAY_IDLE = 0, PC_RELAY_CONNECTING, PC_RELAY_ALLOCATING, PC_RELAY_ALLOCATED, PC_RELAY_FAILED };

typedef struct {
    char host[256];
    uint16_t port;
    uint8_t tcp;
    pierce_addr addr;
    uint8_t resolved;
    uint8_t token[256];
    uint32_t token_len;
    uint8_t state;
    uint8_t txid[PC_TXID_LEN];
    uint64_t next_tx_us;
    uint32_t tries;
    uint8_t server_id[8];
    uint8_t relay_id[PC_RELAY_ID_LEN];
    uint32_t lifetime_s;
    pierce_addr reflexive;
    /* TCP framing */
    pal_sock sock;
    uint8_t rx[2 + 65535];
    uint32_t rxlen;
    uint8_t *tx;
    uint32_t txlen, txcap;
} pc_relay;

typedef struct {
    uint8_t ip[16];
    uint32_t family;
    uint32_t tokens;                 /* scaled by 1000 */
    uint64_t last_us;
} pc_ratebucket;

#define PC_RATE_BUCKETS 256

struct pierce_ctx {
    pc_allocator alloc;
    uint32_t flags;
    uint8_t sk[32], pk[32];

    /* timing configuration */
    uint64_t keepalive_us, idle_us, connect_us;
    uint64_t sendbuf, recvbuf;
    uint32_t log_level;

    /* clock */
    uint64_t now_us;
    uint8_t manual_clock;            /* tests */

    /* sockets */
    pal_sock sock4, sock6;
    uint16_t port4, port6;
    pal_wakeup wake;
    volatile uint32_t wake_pending;  /* wake fd signaled and not yet drained */
    volatile uint32_t app_wake;      /* pierce_wake called: poll must return */

    /* slots */
    pc_slot *slots;
    uint32_t nslots;
    uint32_t free_head;              /* UINT32_MAX = none */
    pc_conn *conns;
    uint32_t nconns;

    /* listening */
    uint8_t listening;
    pierce_conn_options listen_opt;
    pierce_channel_config listen_ch[PIERCE_MAX_CHANNELS];
    uint8_t listen_has_table;

    /* candidates */
    pierce_addr local_addrs[PC_MAX_LOCAL_ADDRS];
    uint32_t nlocal_addrs;
    pc_cand cands[PC_MAX_LOCAL_CANDS];
    uint32_t ncands;
    uint32_t cands_epoch;
    pc_stun stun[PC_MAX_STUN];
    uint32_t nstun;
    pc_relay *relays[PC_MAX_RELAYS];
    uint32_t nrelays;

    /* listener protection */
    uint8_t cookie_secret[32];       /* cookies carry a time bucket, so no rotation */
    pc_ratebucket rate[PC_RATE_BUCKETS];

    /* events */
    pc_evq global_q;
    pc_conn *ready_head, *ready_tail;
    uint8_t global_turn;

    /* data lent to the app until the next poll */
    pc_msg **lent;
    uint32_t nlent, caplent;
    uint8_t (*lent_keys)[32];
    uint32_t caplent_keys;
    pc_conn **to_free;
    uint32_t nto_free, capto_free;

    uint8_t suspended;
    uint8_t in_poll;

    /* scratch: pkt is for building outgoing datagrams, rxbuf for incoming
       ones (decrypted in place), so input handlers can send while parsing */
    uint8_t pkt[PC_MTU + 64];
    uint8_t rxbuf[2048];
};

/* ---- ctx.c ---- */
uint64_t pc_now(pierce_ctx *ctx);
void pc_log(pierce_ctx *ctx, uint32_t level, const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 3, 4)))
#endif
    ;
pc_event *pc_event_new(pierce_ctx *ctx, uint32_t type);
void pc_emit_global(pierce_ctx *ctx, pc_event *ev);
void pc_emit(pc_conn *c, pc_event *ev);
/* Sends a datagram on a path (direct socket or via relay). */
void pc_send_path(pierce_ctx *ctx, const pc_path *path, const uint8_t *data, size_t len);
void pc_send_direct(pierce_ctx *ctx, const pierce_addr *to, const uint8_t *data, size_t len);
pc_conn *pc_conn_alloc(pierce_ctx *ctx, int initiator, const pierce_conn_options *opt);
pc_conn *pc_conn_by_cid(pierce_ctx *ctx, const uint8_t cid[PC_CID_LEN]);
pc_conn *pc_conn_by_session(pierce_ctx *ctx, const uint8_t session[PC_SESSION_LEN]);
pc_conn *pc_conn_by_remote_cid(pierce_ctx *ctx, const uint8_t cid[PC_CID_LEN], const pc_path *path);
pc_conn *pc_conn_lookup(pierce_ctx *ctx, pierce_conn_id id);
void pc_slot_set_channels(pc_conn *c);
void pc_slot_close(pc_conn *c);
void pc_conn_schedule_free(pc_conn *c);

/* ---- gather.c ---- */
int pc_gather_init(pierce_ctx *ctx, const pierce_config *cfg);
void pc_gather_free(pierce_ctx *ctx);
void pc_gather_refresh(pierce_ctx *ctx);      /* rebuild host candidates, restart STUN */
void pc_gather_timers(pierce_ctx *ctx, uint64_t now, uint64_t *next);
/* Returns 1 if the datagram was consumed (STUN / relay control). For relay
   DATA, *relay_out and the unwrapped payload are set and 2 is returned. */
int pc_gather_input(pierce_ctx *ctx, const pierce_addr *src, const uint8_t *data, size_t len,
                    uint32_t *relay_out, const uint8_t **payload, size_t *plen,
                    uint8_t peer_relay_id[PC_RELAY_ID_LEN]);
void pc_relay_send(pierce_ctx *ctx, uint32_t relay, const uint8_t peer_id[PC_RELAY_ID_LEN],
                   const uint8_t *data, size_t len);
void pc_relay_tcp_io(pierce_ctx *ctx, uint32_t relay, int readable, int writable, int failed);
int pc_relay_index_by_server(pierce_ctx *ctx, const uint8_t server_id[8]);
void pc_gather_destroy_notify(pierce_ctx *ctx);
void pc_gather_cands_rebuild(pierce_ctx *ctx);
uint64_t pc_gather_next(pierce_ctx *ctx);
int pc_gather_set_token(pierce_ctx *ctx, uint32_t index, const uint8_t *token, uint32_t len);
void pc_input_packet(pierce_ctx *ctx, const pc_path *path, uint8_t *data, size_t len);

/* ---- conn.c ---- */
int pc_conn_start_initiator(pc_conn *c, const pc_invite *inv, int have_invite);
int pc_conn_signal_in(pierce_ctx *ctx, const pc_signal *s, pc_conn **out);
void pc_conn_cands_changed(pierce_ctx *ctx);
void pc_conn_input_handshake(pierce_ctx *ctx, const pc_path *path, const uint8_t *p, size_t len);
void pc_conn_input_probe(pierce_ctx *ctx, const pc_path *path, const uint8_t *p, size_t len);
void pc_conn_timers(pc_conn *c, uint64_t now);
uint64_t pc_conn_next_timer(pc_conn *c);
int pc_conn_app_accept(pc_conn *c, uint64_t user_data);
int pc_conn_app_reject(pc_conn *c, uint32_t reason);
void pc_conn_close(pc_conn *c, uint32_t reason, int rejected, int32_t error);
void pc_conn_fail(pc_conn *c, int32_t error);
void pc_conn_set_connected(pc_conn *c);
void pc_conn_path_update(pc_conn *c, const pc_path *path);

/* ---- transport.c ---- */
int pc_tr_setup_channels(pc_conn *c, const pierce_channel_config *ch, uint32_t n);
int pc_tr_channels_encode(const pc_conn *c, pc_wbuf *w);
int pc_tr_channels_decode(pc_rbuf *r, pierce_channel_config *out, uint32_t *n);
int pc_tr_channels_equal(const pierce_channel_config *a, uint32_t na,
                         const pierce_channel_config *b, uint32_t nb);
int pc_tr_validate_channels(const pierce_channel_config *ch, uint32_t n);
void pc_tr_keys(pc_conn *c, const uint8_t tx[32], const uint8_t rx[32]);
void pc_tr_input(pierce_ctx *ctx, const pc_path *path, uint8_t *p, size_t len);
void pc_tr_enqueue(pc_conn *c, uint32_t channel_id, pc_msg *m);
void pc_tr_flush(pc_conn *c, uint64_t now);
void pc_tr_timers(pc_conn *c, uint64_t now);
uint64_t pc_tr_next_timer(pc_conn *c);
void pc_tr_send_close(pc_conn *c);
void pc_tr_free(pc_conn *c);
void pc_tr_init_recovery(pc_conn *c, uint64_t initial_rtt);

/* test hooks (exported from the internal library only) */
void pierce__test_set_time(pierce_ctx *ctx, uint64_t now_us);

#endif
