# Pierce wire format, version 1

This document is the byte-level reference for everything Pierce puts on the
wire or into signaling blobs. `spec.md` explains the design; this file is what
an independent implementation would need to interoperate.

Conventions: integers are big-endian unless noted. `varint` is the QUIC
variable-length integer (2-bit length prefix: 1, 2, 4 or 8 bytes, values
below 2^62). `addr` is 19 bytes: `family u8` (1 = IPv4, 2 = IPv6, 0 = none),
`port u16`, `ip [16]` (IPv4 in the first 4 bytes, the rest zero).

All Pierce datagrams are at most **1200 bytes**.

## 1. Datagram demultiplexing

One UDP socket carries everything. The first byte decides:

| First byte | Meaning |
|---|---|
| `0x00`–`0x3F` with STUN magic cookie at bytes 4–7 | STUN (binding only) |
| `0x50`–`0x56` | Pierce peer packets (section 3) |
| `0x60`–`0x65` | Relay protocol (section 6), only from/to a configured relay |

Anything else is dropped.

## 2. Signaling blobs

Blobs are opaque to applications. They are binary; apps encode them however
their channel needs (the examples use base64).

### 2.1 Invite (`pierce_get_invite`)

```
'P' 'I'        magic
u8 version     1
u8 flags       0
[32] key       host X25519 public key
u8 naddr       0..8
addr * naddr   public addresses (pierce_add_local_address)
```

An invite with addresses makes `pierce_connect` connect directly (section
3.4) with no offer/answer. An invite without addresses (37 bytes) starts the
signaling flow. No invite at all means Noise XX.

### 2.2 Offer, answer, candidates

```
'P' 'S'           magic
u8 version        1
u8 kind           1 = offer, 2 = answer, 3 = candidates
[16] session      random, chosen by the initiator; routes every later blob
[32] secret       offer and answer only: random per connection
[8] host_hint     offer only: first 8 bytes of the host key, or zero (XX)
u8 flags          bits 0-1: sender's NAT class (0 unknown, 1 easy, 2 hard/symmetric)
                  bit 2: sender has a router port mapping (reachable by anyone)
u8 ncand          0..24
cand * ncand
```

A candidate is `u8 type` followed by:

| type | body |
|---|---|
| 1 host, 2 server-reflexive, 3 peer-reflexive | `addr` |
| 4 relay | `[8] relay server id`, `[8] relay allocation id` |

A host refuses an offer whose non-zero `host_hint` does not match its key.
A candidates blob with no candidates is sent when only the flags changed.

**Probe key.** `probe_key = BLAKE2b-512(offer_secret || answer_secret)[0..32]`.

## 3. Peer packets

### 3.1 Probes (hole punching)

```
PROBE      0x50  [16] session  [8] txid  u8 role (1 = initiator)  [16] mac
PROBE_ACK  0x51  [16] session  [8] txid  addr observed            [16] mac
```

`mac = BLAKE2b-keyed(key = probe_key, out = 16, data = all preceding bytes)`.
A PROBE whose role equals the receiver's own is a reflection and is dropped.
`observed` is the source address the PROBE arrived from (zero for relayed
probes). Each probe uses a fresh txid; an ack must arrive on the path the
probe left on. A valid PROBE from an unknown address creates a peer-reflexive
candidate.

**Birthday punching.** Scan probes, sent by the easy side to random ports on
the hard side's IP, use `txid = BLAKE2b-keyed(probe_key, 16, "bday" || u16 port)[0..8]`.
An ack whose txid matches the MAC of its own source port is valid, even
though no state was kept for that port.

### 3.2 Handshake

Noise suite: `Noise_IK_25519_ChaChaPoly_BLAKE2b` (pattern 1) or
`Noise_XX_25519_ChaChaPoly_BLAKE2b` (pattern 2).
Prologue: `"pierce/1" || session` (16 zero bytes for direct connects).

```
HS_INIT   0x52  u8 version(1) u8 suite(1) u8 pattern [8] initiator_cid [16] session
                u8 cookie_len (0 or 20) [cookie] u16 noise_len [noise msg 1]
                zero padding to exactly 1200 bytes
HS_RETRY  0x53  [8] initiator_cid u8 cookie_len(20) [20] cookie
HS_RESP   0x54  [8] initiator_cid [8] responder_cid u16 noise_len [noise msg 2]
HS_FINAL  0x55  [8] responder_cid u16 noise_len [noise msg 3]        (XX only)
```

The **initiator intro** is the payload of IK message 1 or XX message 3:

```
u8 version (1)
u8 nchannels (1..32)
per channel: varint id, u8 flags, varint priority, varint max_lifetime_ms,
             varint max_retransmits, varint max_message_size
varint app_len (<= 768)
[app_len] handshake_payload
```

All other Noise payloads are empty. After the last Noise message both sides
`Split()`: the first key encrypts initiator-to-responder.

**Address validation.**
- Signaled connections: the responder accepts `HS_INIT` only on a path from
  which it has received a valid PROBE.
- Direct connections (session all zero): the responder answers `HS_INIT`
  without a valid cookie with `HS_RETRY` (30 bytes for a 1200-byte request).
  `cookie = u32 bucket || BLAKE2b-keyed(ctx_secret, 16, bucket || addr src || initiator_cid)`,
  `bucket = monotonic_seconds / 60`; the current and previous bucket are
  accepted. Handshake initiations are rate limited per source IP (burst 20,
  10 per second).

### 3.3 Data packets

```
DATA  0x56  u8 cid_len(8) [8] dest_cid u16 cid_seq(0) u8 flags u64 pn  ciphertext  [16] tag
```

- `dest_cid` is the CID the receiver chose. In v1 a CID is
  `u32 slot index || [4] random`.
- `cid_seq` is reserved for connection-ID rotation and is always 0 in v1.
- `flags` bit 0 is the key phase.
- The AEAD is ChaCha20-Poly1305 (RFC 8439) with nonce `0x00000000 || pn (64-bit little-endian)`
  and associated data = the 21 header bytes.
- `pn` counts up from 0 per direction and never repeats under a key.
  Receivers keep a 256-packet replay window.
- **Rekey.** A sender switches keys every 2^24 packets or 10 minutes:
  `k' = ChaChaPoly-Encrypt(k, nonce = 2^64-1, ad = "", 32 zero bytes)[0..32]`
  (Noise `REKEY`), and flips the key phase. A receiver seeing the other
  phase tries `REKEY(current)`. It keeps the previous key for 3 PTO to
  decrypt late packets with `pn` below the switch point.
- **Migration.** An authenticated packet with the highest `pn` so far from a
  new address moves the connection there.

### 3.4 Frames (inside DATA)

| Type | Body | Ack-eliciting |
|---|---|---|
| `0x00` PADDING | rest of packet | no |
| `0x01` PING | none | yes |
| `0x02` ACK | `varint largest, varint delay (µs >> 3), varint range_count, varint first_range, (varint gap, varint range) * range_count` (QUIC encoding) | no |
| `0x03` MSG | `varint channel, varint seq, varint total_len, varint offset, varint len, [len] data` | yes |
| `0x04` CLOSE | `varint reason, u8 flags (bit 0 = rejected)` | no |
| `0x05` ACCEPT | none | yes |
| `0x06` ABANDON | `varint channel, varint seq` | yes |

- **Fragmentation.** Messages are cut into 1100-byte fragments: `offset` is a
  multiple of 1100, and every fragment except the last is exactly 1100 bytes.
- **Sequence numbers.** `seq` counts per channel from 0.
- **ABANDON.** A sender that gives up on a reliable message (lifetime or
  retransmit limit) sends ABANDON so the receiver skips that `seq`.
- **ACCEPT.** The responder sends ACCEPT reliably when the app accepts. A
  MSG frame from the responder also counts as acceptance.
- **CLOSE.** CLOSE is sent twice and never acknowledged.

## 4. Router port mapping

All IPv4, all for Pierce's primary UDP port, lease 7200 s (refreshed at half-life,
deleted with lifetime 0 / `DeletePortMapping` on exit).

- **PCP** (RFC 6887): a MAP request (opcode 1, protocol 17) to the default
  gateway on port 5351, sent from the primary socket.
- **NAT-PMP** (RFC 6886): used when PCP gets "unsupported version" or no answer.
  Sends an external-address request (opcode 0) and a UDP map request (opcode 1).
- **UPnP-IGD**, in parallel with the above:
  1. SSDP `M-SEARCH` to `239.255.255.250:1900` for `InternetGatewayDevice:1` and
     `WANIPConnection:1`.
  2. HTTP GET of the `LOCATION` description; take the `controlURL` of
     `WANIPConnection` (else `WANPPPConnection`).
  3. SOAP `GetExternalIPAddress`, then `AddPortMapping`. On conflicts (718),
     retry up to three random ports. Fall back to a permanent lease on 725.

The resulting public address is offered as a server-reflexive candidate and
sets flag bit 2. It is never offered if the router's external address is
private or carrier-grade (100.64/10), or if a STUN result shows a different
public IP (double NAT).

## 5. STUN

Pierce sends RFC 5389 Binding Requests (20 bytes, no attributes) and reads
`XOR-MAPPED-ADDRESS` (preferred) or `MAPPED-ADDRESS` from Binding Success
responses. Nothing else of STUN is implemented. The reference relay also
answers Binding Requests.

## 6. Relay protocol

Messages between a client and the relay server, over UDP or over TCP with
each message prefixed by its length (`u16`).

```
ALLOC_REQ  0x60  [8] txid u8 flags (bit 0 = refresh) [8] relay_id (refresh) or zero
                 u16 token_len [token]  zero padding to at least 64 bytes
ALLOC_OK   0x61  [8] txid [8] server_id [8] relay_id u16 lifetime_s addr reflexive
ALLOC_ERR  0x62  [8] txid u8 code
SEND       0x63  [8] dest relay_id  [payload: a Pierce peer packet]
DATA       0x64  [8] src relay_id   [payload]
FREE       0x65  [8] relay_id
```

**Allocations.**
- An allocation is bound to the client's source address (UDP) or connection
  (TCP).
- A repeated ALLOC_REQ from the same endpoint returns the same allocation.
- Refreshes need no token. Clients refresh every `min(lifetime / 3, keepalive)`,
  which also keeps the NAT mapping to the relay open. Allocations expire
  after `lifetime_s` (default 600) without a refresh.
- `server_id` identifies the relay instance. Two peers can use relay
  candidates only if they hold allocations on the same instance.
- `reflexive` is the client's address as the relay sees it; clients also use
  it as a server-reflexive candidate.

**Forwarding.** A SEND from an endpoint without an allocation is dropped.
Otherwise the relay forwards it as DATA to the endpoint holding
`dest relay_id`. It applies the allocation's bandwidth limit, if any.

**Error codes.**

| Code | Meaning |
|---|---|
| 1 | bad token |
| 2 | expired token |
| 3 | server full |
| 4 | rate limited |
| 5 | unknown allocation (refresh after the server lost it: allocate again) |

**Tokens** (type byte first):

| Type | Layout | Status |
|---|---|---|
| 1 shared secret | `u8 1, u64 expiry (Unix seconds), u32 max_kbps (0 = unlimited), [16] BLAKE2b-keyed(secret, 16, first 13 bytes)` (29 bytes) | v1 |
| 2 signed | Ed25519 | reserved |

## 7. Constants

| Name | Value |
|---|---|
| MTU (max datagram) | 1200 |
| Fragment size | 1100 |
| Max channels | 32 |
| Max handshake payload | 768 bytes |
| Max ack delay | 25 ms |
| Initial / minimum congestion window | 12000 / 2400 bytes |
| Default keepalive / idle / connect timeout | 15 s / 30 s / 15 s |
| Relay probe head start for direct paths | 300 ms |
| Birthday: start delay / window / sockets / scan rate / max probes | 1 s / 10 s / 256 / 250 per s / 2048 |
| Port mapping lease | 7200 s |
