/* Wire formats: packet types, signaling blobs, STUN, relay protocol.
   Documented in docs/wire.md. */
#ifndef PIERCE_WIRE_H
#define PIERCE_WIRE_H

#include "common.h"

#define PC_PROTOCOL_VERSION 1
#define PC_SUITE_NOISE_25519_CHACHAPOLY_BLAKE2B 1

#define PC_CID_LEN 8
#define PC_SESSION_LEN 16
#define PC_TXID_LEN 8
#define PC_COOKIE_LEN 20
#define PC_RELAY_ID_LEN 8

/* ---- packet types (first byte of a Pierce datagram) ---- */
enum {
    PC_PKT_PROBE      = 0x50,
    PC_PKT_PROBE_ACK  = 0x51,
    PC_PKT_HS_INIT    = 0x52,
    PC_PKT_HS_RETRY   = 0x53,
    PC_PKT_HS_RESP    = 0x54,
    PC_PKT_HS_FINAL   = 0x55,
    PC_PKT_DATA       = 0x56,

    /* relay protocol (client <-> relay server) */
    PC_RLY_ALLOC_REQ  = 0x60,
    PC_RLY_ALLOC_OK   = 0x61,
    PC_RLY_ALLOC_ERR  = 0x62,
    PC_RLY_SEND       = 0x63,
    PC_RLY_DATA       = 0x64,
    PC_RLY_FREE       = 0x65
};

/* DATA packet header: type, cid_len, cid, cid_seq (u16), flags, pn (u64). */
#define PC_DATA_HDR_LEN (1 + 1 + PC_CID_LEN + 2 + 1 + 8)
#define PC_DATA_FLAG_KEY_PHASE 0x01
/* Largest frame payload in one DATA packet. */
#define PC_DATA_PAYLOAD_MAX (PC_MTU - PC_DATA_HDR_LEN - 16)

/* ---- frames (inside DATA) ---- */
enum {
    PC_FR_PADDING = 0x00,
    PC_FR_PING    = 0x01,
    PC_FR_ACK     = 0x02,
    PC_FR_MSG     = 0x03,
    PC_FR_CLOSE   = 0x04,
    PC_FR_ACCEPT  = 0x05,
    PC_FR_ABANDON = 0x06
};
#define PC_CLOSE_FLAG_REJECTED 0x01

/* Fixed fragment size: every fragment but the last carries exactly this. */
#define PC_FRAG_UNIT 1100

/* ---- probes ---- */
#define PC_PROBE_LEN (1 + PC_SESSION_LEN + PC_TXID_LEN + 1 + 16)
#define PC_PROBE_ACK_LEN (1 + PC_SESSION_LEN + PC_TXID_LEN + PC_ADDR_WIRE_SIZE + 16)

/* ---- candidates ---- */
enum {
    PC_CAND_HOST  = 1,
    PC_CAND_SRFLX = 2,
    PC_CAND_PRFLX = 3,
    PC_CAND_RELAY = 4
};

typedef struct {
    uint8_t type;
    pierce_addr addr;                      /* direct candidates */
    uint8_t relay_server[8];               /* relay: server instance id */
    uint8_t relay_id[PC_RELAY_ID_LEN];     /* relay: allocation id */
} pc_cand;

int pc_cand_eq(const pc_cand *a, const pc_cand *b);

/* ---- signaling blobs ---- */
#define PC_MAX_BLOB_CANDS 24
#define PC_MAX_INVITE_ADDRS 8

enum { PC_SIG_OFFER = 1, PC_SIG_ANSWER = 2, PC_SIG_CANDIDATES = 3 };

typedef struct {
    uint8_t key[32];
    uint32_t naddr;
    pierce_addr addrs[PC_MAX_INVITE_ADDRS];
} pc_invite;

typedef struct {
    uint8_t kind;
    uint8_t session[PC_SESSION_LEN];
    uint8_t secret[32];          /* offer / answer */
    uint8_t host_hint[8];        /* offer: first bytes of the host key; zero = unknown */
    uint8_t flags;
    uint32_t ncand;
    pc_cand cands[PC_MAX_BLOB_CANDS];
} pc_signal;

int pc_invite_encode(const pc_invite *in, uint8_t *out, size_t cap);   /* len or <0 */
int pc_invite_decode(const uint8_t *p, size_t len, pc_invite *out);
int pc_signal_encode(const pc_signal *s, uint8_t *out, size_t cap);
int pc_signal_decode(const uint8_t *p, size_t len, pc_signal *out);
int pc_blob_is_invite(const uint8_t *p, size_t len);

/* ---- STUN (RFC 5389 binding only) ---- */
#define PC_STUN_TXID_LEN 12
int pc_stun_is_stun(const uint8_t *p, size_t len);
size_t pc_stun_binding_request(uint8_t out[20], const uint8_t txid[PC_STUN_TXID_LEN]);
/* Parses a binding success response. Returns 0 and fills mapped if the
   transaction id matches. */
int pc_stun_parse_response(const uint8_t *p, size_t len, uint8_t txid_out[PC_STUN_TXID_LEN],
                           pierce_addr *mapped);
/* Builds a binding success response (used by tests and the relay tool). */
size_t pc_stun_binding_response(uint8_t *out, size_t cap, const uint8_t *request,
                                size_t req_len, const pierce_addr *mapped);

/* ---- relay tokens ---- */
#define PC_TOKEN_TYPE_SHARED 1
#define PC_TOKEN_TYPE_SIGNED 2   /* reserved, deferred */
int pc_token_verify(const uint8_t *secret, size_t secret_len, const uint8_t *tok, size_t len,
                    uint64_t now_unix, uint32_t *max_kbps);

/* ---- relay protocol ---- */
enum {
    PC_RLY_ERR_BAD_TOKEN = 1,
    PC_RLY_ERR_EXPIRED   = 2,
    PC_RLY_ERR_FULL      = 3,
    PC_RLY_ERR_RATE      = 4,
    PC_RLY_ERR_UNKNOWN   = 5    /* refresh of an allocation the server lost */
};
/* ALLOC_REQ is padded to at least this size (anti-amplification). */
#define PC_RLY_ALLOC_REQ_MIN 64

#endif
