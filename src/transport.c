/* Transport: packet protection, frames, acks, loss recovery, congestion
   control, channels (spec 4.5, 6). */
#include <stdlib.h>

#include "core.h"
#include "crypto.h"

#define MDS PC_MTU                       /* max datagram size for CC */
#define CC_MIN_WINDOW (2 * MDS)
#define CC_INITIAL_WINDOW (10 * MDS)
#define K_PACKET_THRESHOLD 3
#define K_GRANULARITY_US 1000
#define K_INITIAL_RTT_US 333000
#define ACK_DELAY_EXPONENT 3
#define MAX_RANGES_IN 64
#define UNREL_REASM_MAX 64
#define UNREL_REASM_TIMEOUT_US 5000000

static uint64_t rekey_packets = PC_REKEY_PACKETS;

void pierce__test_set_rekey_packets(uint64_t n);
void pierce__test_set_rekey_packets(uint64_t n) { rekey_packets = n ? n : PC_REKEY_PACKETS; }

enum { MODE_REL_ORD, MODE_REL_UNORD, MODE_SEQ, MODE_UNREL };

static int ch_mode(const pierce_channel_config *cfg)
{
    if (cfg->flags & PIERCE_CHANNEL_RELIABLE)
        return (cfg->flags & PIERCE_CHANNEL_ORDERED) ? MODE_REL_ORD : MODE_REL_UNORD;
    if (cfg->flags & (PIERCE_CHANNEL_SEQUENCED | PIERCE_CHANNEL_ORDERED)) return MODE_SEQ;
    return MODE_UNREL;
}

static int ch_index(const pc_conn *c, uint32_t id)
{
    for (uint32_t i = 0; i < c->nch; i++)
        if (c->ch[i].cfg.id == id) return (int)i;
    return -1;
}

/* ===================================================================== */
/* Channel tables                                                        */
/* ===================================================================== */

int pc_tr_validate_channels(const pierce_channel_config *ch, uint32_t n)
{
    if (n > PIERCE_MAX_CHANNELS) return PIERCE_ERR_INVALID_ARG;
    for (uint32_t i = 0; i < n; i++) {
        if (ch[i].struct_size < sizeof(pierce_channel_config)) return PIERCE_ERR_VERSION;
        if ((ch[i].flags & PIERCE_CHANNEL_SEQUENCED) && (ch[i].flags & PIERCE_CHANNEL_RELIABLE))
            return PIERCE_ERR_INVALID_ARG;
        if (ch[i].flags & ~7u) return PIERCE_ERR_INVALID_ARG;
        if (ch[i].max_message_size > (64u << 20)) return PIERCE_ERR_INVALID_ARG;
        for (uint32_t j = 0; j < i; j++)
            if (ch[j].id == ch[i].id) return PIERCE_ERR_INVALID_ARG;
    }
    return PIERCE_OK;
}

static void normalize(pierce_channel_config *c)
{
    c->struct_size = sizeof(*c);
    if (!c->max_message_size) c->max_message_size = PC_DEFAULT_MAX_MSG;
}

int pc_tr_setup_channels(pc_conn *c, const pierce_channel_config *ch, uint32_t n)
{
    pierce_channel_config def;
    if (n == 0) {
        pierce_channel_config_init(&def);
        def.flags = PIERCE_CHANNEL_RELIABLE | PIERCE_CHANNEL_ORDERED;
        ch = &def;
        n = 1;
    }
    for (uint32_t i = 0; i < n; i++) {
        memset(&c->ch[i], 0, sizeof(c->ch[i]));
        c->ch[i].cfg = ch[i];
        normalize(&c->ch[i].cfg);
        c->ch_order[i] = (uint8_t)i;
    }
    c->nch = n;
    /* Stable insertion sort by priority, highest first. */
    for (uint32_t i = 1; i < n; i++) {
        uint8_t v = c->ch_order[i];
        uint32_t j = i;
        while (j > 0 && c->ch[c->ch_order[j - 1]].cfg.priority < c->ch[v].cfg.priority) {
            c->ch_order[j] = c->ch_order[j - 1];
            j--;
        }
        c->ch_order[j] = v;
    }
    c->ch_agreed = 1;
    return PIERCE_OK;
}

int pc_tr_channels_encode(const pc_conn *c, pc_wbuf *w)
{
    pc_w_u8(w, (uint8_t)c->nch);
    for (uint32_t i = 0; i < c->nch; i++) {
        const pierce_channel_config *k = &c->ch[i].cfg;
        pc_w_varint(w, k->id);
        pc_w_u8(w, (uint8_t)k->flags);
        pc_w_varint(w, k->priority);
        pc_w_varint(w, k->max_lifetime_ms);
        pc_w_varint(w, k->max_retransmits);
        pc_w_varint(w, k->max_message_size);
    }
    return w->err ? -1 : 0;
}

int pc_tr_channels_decode(pc_rbuf *r, pierce_channel_config *out, uint32_t *n)
{
    uint32_t cnt = pc_r_u8(r);
    if (cnt == 0 || cnt > PIERCE_MAX_CHANNELS) return -1;
    for (uint32_t i = 0; i < cnt; i++) {
        pierce_channel_config_init(&out[i]);
        uint64_t id = pc_r_varint(r), pri, life, rtx, max;
        out[i].flags = pc_r_u8(r);
        pri = pc_r_varint(r);
        life = pc_r_varint(r);
        rtx = pc_r_varint(r);
        max = pc_r_varint(r);
        if (id > UINT32_MAX || pri > UINT32_MAX || life > UINT32_MAX || rtx > UINT32_MAX ||
            max > UINT32_MAX)
            return -1;
        out[i].id = (uint32_t)id;
        out[i].priority = (uint32_t)pri;
        out[i].max_lifetime_ms = (uint32_t)life;
        out[i].max_retransmits = (uint32_t)rtx;
        out[i].max_message_size = (uint32_t)max;
    }
    if (r->err || pc_tr_validate_channels(out, cnt) != PIERCE_OK) return -1;
    *n = cnt;
    return 0;
}

int pc_tr_channels_equal(const pierce_channel_config *a, uint32_t na,
                         const pierce_channel_config *b, uint32_t nb)
{
    if (na != nb) return 0;
    for (uint32_t i = 0; i < na; i++) {
        const pierce_channel_config *x = &a[i], *y = NULL;
        for (uint32_t j = 0; j < nb; j++)
            if (b[j].id == x->id) y = &b[j];
        if (!y) return 0;
        uint32_t xm = x->max_message_size ? x->max_message_size : PC_DEFAULT_MAX_MSG;
        uint32_t ym = y->max_message_size ? y->max_message_size : PC_DEFAULT_MAX_MSG;
        if (x->flags != y->flags || x->priority != y->priority ||
            x->max_lifetime_ms != y->max_lifetime_ms || x->max_retransmits != y->max_retransmits ||
            xm != ym)
            return 0;
    }
    return 1;
}

/* ===================================================================== */
/* Keys and recovery state                                               */
/* ===================================================================== */

void pc_tr_keys(pc_conn *c, const uint8_t tx[32], const uint8_t rx[32])
{
    memcpy(c->tx_key, tx, 32);
    memcpy(c->rx_key, rx, 32);
    c->keys_ready = 1;
    c->tx_pn = 0;
    c->tx_rekey_pn = 0;
    c->tx_rekey_us = pc_now(c->ctx);
    c->tx_phase = c->rx_phase = 0;
    c->rx_prev_valid = 0;
    c->rx_any = 0;
}

void pc_tr_init_recovery(pc_conn *c, uint64_t initial_rtt)
{
    c->cc.cwnd = CC_INITIAL_WINDOW;
    c->cc.ssthresh = UINT64_MAX;
    c->cc.in_recovery_valid = 0;
    if (initial_rtt) {
        c->latest_rtt = c->srtt = c->min_rtt = initial_rtt;
        c->rttvar = initial_rtt / 2;
        c->has_rtt = 1;
    } else {
        c->srtt = K_INITIAL_RTT_US;
        c->rttvar = K_INITIAL_RTT_US / 2;
        c->has_rtt = 0;
    }
}

static uint64_t pto_duration(const pc_conn *c)
{
    uint64_t var = PC_MAX(4 * c->rttvar, (uint64_t)K_GRANULARITY_US);
    return c->srtt + var + PC_MAX_ACK_DELAY_US;
}

/* ===================================================================== */
/* Outgoing message bookkeeping                                          */
/* ===================================================================== */

static void om_unref(pc_conn *c, pc_outmsg *m)
{
    if (--m->refs) return;
    if (m->acked != &m->acked_inline) pc_free(&c->ctx->alloc, m->acked);
    pc_msg_unref(m->msg);
    pc_free(&c->ctx->alloc, m);
}

static void om_finish(pc_conn *c, pc_outmsg *m)
{
    if (m->finished) return;
    m->finished = 1;
    c->release_bytes += m->msg->len;
}

static void push_abandon(pc_conn *c, uint32_t channel_id, uint64_t seq)
{
    if (c->nabandons == c->capabandons) {
        uint32_t nc = c->capabandons ? c->capabandons * 2 : 8;
        pc_abandon *n = (pc_abandon *)pc_realloc(&c->ctx->alloc, c->abandons,
                                                 c->capabandons * sizeof(pc_abandon),
                                                 nc * sizeof(pc_abandon));
        if (!n) return;   /* receiver will stall on this seq; connection likely dying anyway */
        c->abandons = n;
        c->capabandons = nc;
    }
    c->abandons[c->nabandons].channel_id = channel_id;
    c->abandons[c->nabandons].seq = seq;
    c->nabandons++;
}

static void om_abandon(pc_conn *c, pc_outmsg *m)
{
    if (m->finished) return;
    om_finish(c, m);
    if (m->reliable) push_abandon(c, c->ch[m->channel].cfg.id, m->seq);
}

static void rtx_push(pc_conn *c, pc_channel *ch, pc_outmsg *m, uint32_t frag)
{
    pc_rtx *r = (pc_rtx *)pc_alloc(&c->ctx->alloc, sizeof(*r));
    if (!r) return;
    r->m = m;
    r->frag = frag;
    m->refs++;
    if (ch->rtx_tail) ch->rtx_tail->next = r;
    else ch->rtx_head = r;
    ch->rtx_tail = r;
}

void pc_tr_enqueue(pc_conn *c, uint32_t channel_id, pc_msg *msg)
{
    int idx = ch_index(c, channel_id);
    if (idx < 0) {
        pc_log(c->ctx, PIERCE_LOG_WARN, "send on unknown channel %u dropped", channel_id);
        c->release_bytes += msg->len;
        pc_msg_unref(msg);
        return;
    }
    pc_channel *ch = &c->ch[idx];
    if (msg->len > ch->cfg.max_message_size) {
        pc_log(c->ctx, PIERCE_LOG_WARN, "message larger than channel %u maximum dropped", channel_id);
        c->release_bytes += msg->len;
        pc_msg_unref(msg);
        return;
    }
    if (ch_mode(&ch->cfg) == MODE_SEQ) {
        /* Newest wins: anything not yet started is superseded. A message
           with fragments already on the wire is allowed to finish, or the
           bandwidth spent on it would be wasted. */
        pc_outmsg **link = &ch->pend_head, *last = NULL;
        while (*link) {
            pc_outmsg *o = *link;
            if (o->next_frag == 0) {
                *link = o->next;
                om_finish(c, o);
                o->in_pending = 0;
                o->next = NULL;
                om_unref(c, o);
            } else {
                last = o;
                link = &o->next;
            }
        }
        ch->pend_tail = last;
    }
    pc_outmsg *m = (pc_outmsg *)pc_alloc(&c->ctx->alloc, sizeof(*m));
    if (!m) {
        c->release_bytes += msg->len;
        pc_msg_unref(msg);
        return;
    }
    m->msg = msg;
    m->seq = ch->next_seq++;
    m->nfrag = msg->len ? (msg->len + PC_FRAG_UNIT - 1) / PC_FRAG_UNIT : 1;
    if (m->nfrag == 1) {
        m->acked = &m->acked_inline;
    } else {
        m->acked = (uint8_t *)pc_alloc(&c->ctx->alloc, m->nfrag);
        if (!m->acked) {
            c->release_bytes += msg->len;
            pc_msg_unref(msg);
            pc_free(&c->ctx->alloc, m);
            return;
        }
    }
    m->reliable = (ch->cfg.flags & PIERCE_CHANNEL_RELIABLE) != 0;
    m->channel = (uint32_t)idx;
    if (ch->cfg.max_lifetime_ms) m->expiry_us = pc_now(c->ctx) + (uint64_t)ch->cfg.max_lifetime_ms * 1000;
    m->refs = 1;
    m->in_pending = 1;
    if (ch->pend_tail) ch->pend_tail->next = m;
    else ch->pend_head = m;
    ch->pend_tail = m;
}

/* ===================================================================== */
/* Congestion control: NewReno                                           */
/* ===================================================================== */

static void cc_on_ack(pc_conn *c, uint64_t bytes, uint64_t sent_us, uint64_t flight_before)
{
    pc_cc *cc = &c->cc;
    if (cc->in_recovery_valid && sent_us <= cc->recovery_start_us) return;
    /* Only grow when the window was actually being used (RFC 9002 7.8). */
    if (flight_before * 2 < cc->cwnd) return;
    if (cc->cwnd < cc->ssthresh) {
        cc->cwnd += bytes;
    } else {
        cc->acked_accum += bytes;
        if (cc->acked_accum >= cc->cwnd) {
            cc->acked_accum -= cc->cwnd;
            cc->cwnd += MDS;
        }
    }
}

static void cc_on_congestion(pc_conn *c, uint64_t sent_us, uint64_t now)
{
    pc_cc *cc = &c->cc;
    if (cc->in_recovery_valid && sent_us <= cc->recovery_start_us) return;
    cc->recovery_start_us = now;
    cc->in_recovery_valid = 1;
    cc->ssthresh = PC_MAX(cc->cwnd / 2, (uint64_t)CC_MIN_WINDOW);
    cc->cwnd = cc->ssthresh;
    cc->acked_accum = 0;
}

/* ===================================================================== */
/* Sent packets, acks and loss                                           */
/* ===================================================================== */

static void sentpkt_free(pc_conn *c, pc_sentpkt *p)
{
    pc_rtx *r = p->frags;
    while (r) {
        pc_rtx *n = r->next;
        om_unref(c, r->m);
        pc_free(&c->ctx->alloc, r);
        r = n;
    }
    pc_free(&c->ctx->alloc, p->abandons);
    pc_free(&c->ctx->alloc, p);
}

static void on_packet_acked(pc_conn *c, pc_sentpkt *p)
{
    for (pc_rtx *r = p->frags; r; r = r->next) {
        pc_outmsg *m = r->m;
        if (m->finished || m->acked[r->frag]) continue;
        m->acked[r->frag] = 1;
        if (++m->nacked == m->nfrag) om_finish(c, m);
    }
    if (p->has_accept) c->accept_acked = 1;
}

static void on_packet_lost(pc_conn *c, pc_sentpkt *p, uint64_t now)
{
    c->packets_lost++;
    for (pc_rtx *r = p->frags; r; r = r->next) {
        pc_outmsg *m = r->m;
        if (!m->reliable || m->finished || m->acked[r->frag]) continue;
        pc_channel *ch = &c->ch[m->channel];
        m->retransmits++;
        if ((ch->cfg.max_retransmits && m->retransmits > ch->cfg.max_retransmits) ||
            (m->expiry_us && now >= m->expiry_us)) {
            om_abandon(c, m);
            continue;
        }
        rtx_push(c, ch, m, r->frag);
    }
    if (p->has_accept && !c->accept_acked) c->accept_pending = 1;
    for (uint16_t i = 0; i < p->nabandons; i++) push_abandon(c, p->abandons[i].channel_id, p->abandons[i].seq);
}

static void update_rtt(pc_conn *c, uint64_t latest, uint64_t ack_delay)
{
    c->latest_rtt = latest;
    if (!c->has_rtt) {
        c->min_rtt = c->srtt = latest;
        c->rttvar = latest / 2;
        c->has_rtt = 1;
        return;
    }
    if (latest < c->min_rtt) c->min_rtt = latest;
    if (ack_delay > PC_MAX_ACK_DELAY_US) ack_delay = PC_MAX_ACK_DELAY_US;
    uint64_t adjusted = latest;
    if (latest >= c->min_rtt + ack_delay) adjusted = latest - ack_delay;
    uint64_t diff = c->srtt > adjusted ? c->srtt - adjusted : adjusted - c->srtt;
    c->rttvar = (3 * c->rttvar + diff) / 4;
    c->srtt = (7 * c->srtt + adjusted) / 8;
}

static void detect_lost(pc_conn *c, uint64_t now)
{
    uint64_t rtt = PC_MAX(c->latest_rtt, c->srtt);
    uint64_t loss_delay = PC_MAX(rtt + rtt / 8, (uint64_t)K_GRANULARITY_US);
    uint64_t lost_before = now > loss_delay ? now - loss_delay : 0;
    uint64_t latest_lost_sent = 0;
    int any_lost = 0;
    pc_sentpkt *prev = NULL, *p = c->sent_head;
    c->loss_time_us = 0;
    while (p && c->any_acked && p->pn <= c->largest_acked) {
        pc_sentpkt *next = p->next;
        if (p->time_sent <= lost_before || c->largest_acked >= p->pn + K_PACKET_THRESHOLD) {
            if (prev) prev->next = next;
            else c->sent_head = next;
            if (c->sent_tail == p) c->sent_tail = prev;
            if (p->ack_eliciting) {
                c->bytes_in_flight -= p->size;
                any_lost = 1;
                if (p->time_sent > latest_lost_sent) latest_lost_sent = p->time_sent;
            }
            on_packet_lost(c, p, now);
            sentpkt_free(c, p);
        } else {
            uint64_t t = p->time_sent + loss_delay;
            if (!c->loss_time_us || t < c->loss_time_us) c->loss_time_us = t;
            prev = p;
        }
        p = next;
    }
    if (any_lost) cc_on_congestion(c, latest_lost_sent, now);
}

static int in_ranges(uint64_t pn, const pc_range *r, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++)
        if (pn >= r[i].start && pn <= r[i].end) return 1;
    return 0;
}

static void on_ack(pc_conn *c, const pc_range *ranges, uint32_t n, uint64_t ack_delay, uint64_t now)
{
    uint64_t largest = ranges[0].end;
    if (largest >= c->tx_pn) return;   /* acks a packet never sent: ignore */
    int newly = 0;
    pc_sentpkt *prev = NULL, *p = c->sent_head, *largest_pkt_sent = NULL;
    uint64_t flight_before = c->bytes_in_flight;
    uint64_t largest_time = 0;
    int largest_eliciting = 0;
    while (p) {
        pc_sentpkt *next = p->next;
        if (p->pn > largest) break;
        if (in_ranges(p->pn, ranges, n)) {
            if (prev) prev->next = next;
            else c->sent_head = next;
            if (c->sent_tail == p) c->sent_tail = prev;
            newly = 1;
            if (p->pn == largest) {
                largest_pkt_sent = p;
                largest_time = p->time_sent;
                largest_eliciting = p->ack_eliciting;
            }
            if (p->ack_eliciting) {
                c->bytes_in_flight -= p->size;
                cc_on_ack(c, p->size, p->time_sent, flight_before);
            }
            on_packet_acked(c, p);
            sentpkt_free(c, p);
        } else {
            prev = p;
        }
        p = next;
    }
    if (!newly) return;
    if (!c->any_acked || largest > c->largest_acked) {
        c->largest_acked = largest;
        c->any_acked = 1;
    }
    if (largest_pkt_sent && largest_eliciting && now >= largest_time)
        update_rtt(c, now - largest_time, ack_delay);
    detect_lost(c, now);
    c->pto_count = 0;
}

/* ===================================================================== */
/* Ack ranges we owe                                                     */
/* ===================================================================== */

static void ack_record(pc_conn *c, uint64_t pn)
{
    pc_range *r = c->ackr;
    uint32_t n = c->nackr, i;
    for (i = 0; i < n; i++) {
        if (pn >= r[i].start && pn <= r[i].end) return;
        if (pn == r[i].end + 1) {
            r[i].end = pn;
            if (i > 0 && r[i - 1].start == pn + 1) {   /* merge with the higher range */
                r[i - 1].start = r[i].start;
                memmove(&r[i], &r[i + 1], (n - i - 1) * sizeof(*r));
                c->nackr--;
            }
            return;
        }
        if (r[i].start && pn == r[i].start - 1) {
            r[i].start = pn;
            if (i + 1 < n && r[i + 1].end + 1 == pn) {
                r[i].start = r[i + 1].start;
                memmove(&r[i + 1], &r[i + 2], (n - i - 2) * sizeof(*r));
                c->nackr--;
            }
            return;
        }
        if (pn > r[i].end) break;
    }
    if (n == PC_MAX_ACK_RANGES) {
        if (i == n) return;            /* older than everything we track */
        n--;                           /* drop the oldest range */
    }
    memmove(&r[i + 1], &r[i], (n - i) * sizeof(*r));
    r[i].start = r[i].end = pn;
    c->nackr = n + 1;
}

static void write_ack(pc_conn *c, pc_wbuf *w, size_t max, uint64_t now)
{
    size_t start = w->len;
    uint64_t delay = now > c->largest_rx_time_us ? now - c->largest_rx_time_us : 0;
    uint32_t n = c->nackr;
    /* Shrink the range count until the frame fits in max bytes. */
    while (n > 0) {
        size_t sz = 1 + pc_varint_size(c->ackr[0].end) + pc_varint_size(delay >> ACK_DELAY_EXPONENT) +
                    pc_varint_size(n - 1) + pc_varint_size(c->ackr[0].end - c->ackr[0].start);
        for (uint32_t i = 1; i < n; i++)
            sz += pc_varint_size(c->ackr[i - 1].start - c->ackr[i].end - 2) +
                  pc_varint_size(c->ackr[i].end - c->ackr[i].start);
        if (sz <= max) break;
        n--;
    }
    if (n == 0) return;
    pc_w_u8(w, PC_FR_ACK);
    pc_w_varint(w, c->ackr[0].end);
    pc_w_varint(w, delay >> ACK_DELAY_EXPONENT);
    pc_w_varint(w, n - 1);
    pc_w_varint(w, c->ackr[0].end - c->ackr[0].start);
    for (uint32_t i = 1; i < n; i++) {
        pc_w_varint(w, c->ackr[i - 1].start - c->ackr[i].end - 2);
        pc_w_varint(w, c->ackr[i].end - c->ackr[i].start);
    }
    if (w->err) w->len = start;
}

static int read_ack(pc_rbuf *r, pc_range *out, uint32_t *n, uint64_t *delay_us)
{
    uint64_t largest = pc_r_varint(r);
    uint64_t delay = pc_r_varint(r);
    uint64_t count = pc_r_varint(r);
    uint64_t first = pc_r_varint(r);
    if (r->err || first > largest) return -1;
    *delay_us = delay << ACK_DELAY_EXPONENT;
    out[0].end = largest;
    out[0].start = largest - first;
    uint32_t k = 1;
    uint64_t low = out[0].start;
    for (uint64_t i = 0; i < count; i++) {
        uint64_t gap = pc_r_varint(r), len = pc_r_varint(r);
        if (r->err || low < gap + 2) return -1;
        uint64_t end = low - gap - 2;
        if (len > end) return -1;
        if (k < MAX_RANGES_IN) {
            out[k].end = end;
            out[k].start = end - len;
            k++;
        }
        low = end - len;
    }
    *n = k;
    return r->err ? -1 : 0;
}

/* ===================================================================== */
/* Receiving messages                                                    */
/* ===================================================================== */

static void deliver(pc_conn *c, pc_channel *ch, pc_msg *buf)
{
    pc_event *ev = pc_event_new(c->ctx, PIERCE_EV_MESSAGE);
    if (!ev) {
        pc_msg_unref(buf);
        return;
    }
    ev->channel = ch->cfg.id;
    ev->flags = ch->cfg.flags;
    ev->msg = buf;
    c->rx_buffered += buf->len;
    pc_emit(c, ev);
}

static void reasm_free(pc_conn *c, pc_reasm *e)
{
    if (e->buf) {
        c->reasm_bytes -= e->buf->len;
        pc_msg_unref(e->buf);
    }
    pc_free(&c->ctx->alloc, e->have);
    pc_free(&c->ctx->alloc, e);
}

static pc_reasm *reasm_find(pc_channel *ch, uint64_t seq, pc_reasm ***link_out)
{
    pc_reasm **link = &ch->reasm;
    while (*link && (*link)->seq < seq) link = &(*link)->next;
    if (link_out) *link_out = link;
    return (*link && (*link)->seq == seq) ? *link : NULL;
}

static pc_reasm *reasm_get(pc_conn *c, pc_channel *ch, uint64_t seq, uint32_t total, uint32_t nfrag)
{
    pc_reasm **link;
    pc_reasm *e = reasm_find(ch, seq, &link);
    if (e) return e;
    e = (pc_reasm *)pc_alloc(&c->ctx->alloc, sizeof(*e));
    if (!e) return NULL;
    e->seq = seq;
    e->total = total;
    e->nfrag = nfrag;
    e->first_us = pc_now(c->ctx);
    e->have = (uint8_t *)pc_alloc(&c->ctx->alloc, nfrag);
    e->buf = pc_msg_new(&c->ctx->alloc, NULL, total);
    if (!e->have || !e->buf) {
        pc_free(&c->ctx->alloc, e->have);
        if (e->buf) pc_msg_unref(e->buf);
        pc_free(&c->ctx->alloc, e);
        return NULL;
    }
    c->reasm_bytes += total;
    e->next = *link;
    *link = e;
    ch->nreasm++;
    return e;
}

static void reasm_unlink(pc_channel *ch, pc_reasm *e)
{
    pc_reasm **link = &ch->reasm;
    while (*link && *link != e) link = &(*link)->next;
    if (*link) {
        *link = e->next;
        ch->nreasm--;
    }
}

/* Take the completed buffer out of a reassembly entry. */
static pc_msg *reasm_take(pc_conn *c, pc_reasm *e)
{
    pc_msg *b = e->buf;
    e->buf = NULL;
    c->reasm_bytes -= b->len;
    return b;
}

static void ordered_drain(pc_conn *c, pc_channel *ch)
{
    while (ch->reasm && ch->reasm->seq == ch->rx_next && (ch->reasm->complete || ch->reasm->skipped)) {
        pc_reasm *e = ch->reasm;
        ch->reasm = e->next;
        ch->nreasm--;
        if (e->complete && e->buf) deliver(c, ch, reasm_take(c, e));
        reasm_free(c, e);
        ch->rx_next++;
    }
}

static int done_contains(const pc_channel *ch, uint64_t seq)
{
    for (uint32_t i = 0; i < ch->ndone; i++)
        if (ch->done[i] == seq) return 1;
    return 0;
}

static void unordered_mark_done(pc_conn *c, pc_channel *ch, uint64_t seq)
{
    if (seq == ch->rx_next) {
        ch->rx_next++;
        int moved = 1;
        while (moved) {
            moved = 0;
            for (uint32_t i = 0; i < ch->ndone; i++) {
                if (ch->done[i] == ch->rx_next) {
                    ch->done[i] = ch->done[--ch->ndone];
                    ch->rx_next++;
                    moved = 1;
                    break;
                }
            }
        }
        return;
    }
    if (done_contains(ch, seq)) return;
    if (ch->ndone == ch->capdone) {
        uint32_t nc = ch->capdone ? ch->capdone * 2 : 16;
        uint64_t *n = (uint64_t *)pc_realloc(&c->ctx->alloc, ch->done, ch->capdone * 8, nc * 8);
        if (!n) return;
        ch->done = n;
        ch->capdone = nc;
    }
    ch->done[ch->ndone++] = seq;
}

/* Returns 0 accepted (ack it), 1 rejected for flow control (do not ack),
   -1 protocol violation. */
static int rx_msg(pc_conn *c, uint32_t chan_id, uint64_t seq, uint64_t total, uint64_t offset,
                  const uint8_t *data, uint64_t len)
{
    int idx = ch_index(c, chan_id);
    if (idx < 0) return -1;
    pc_channel *ch = &c->ch[idx];
    int mode = ch_mode(&ch->cfg);
    if (total > ch->cfg.max_message_size) return -1;
    uint32_t nfrag = total ? (uint32_t)((total + PC_FRAG_UNIT - 1) / PC_FRAG_UNIT) : 1;
    if (offset % PC_FRAG_UNIT) return -1;
    uint32_t frag = (uint32_t)(offset / PC_FRAG_UNIT);
    if (frag >= nfrag) return -1;
    uint64_t expect = frag == nfrag - 1 ? total - offset : PC_FRAG_UNIT;
    if (len != expect) return -1;

    /* Duplicates and stale messages. */
    if ((mode == MODE_REL_ORD || mode == MODE_SEQ) && seq < ch->rx_next) return 0;
    if (mode == MODE_REL_UNORD && (seq < ch->rx_next || done_contains(ch, seq))) return 0;

    pc_reasm *e = reasm_find(ch, seq, NULL);
    if (e && (e->total != total || e->nfrag != nfrag)) return -1;
    if (e && (e->skipped || e->complete || e->have[frag])) return 0;

    /* Flow control: bound undelivered plus reassembling bytes. */
    if (!e) {
        uint64_t used = c->rx_buffered + c->reasm_bytes;
        if (used && used + total > c->ctx->recvbuf) {
            return (mode == MODE_REL_ORD || mode == MODE_REL_UNORD) ? 1 : 0;
        }
    }

    /* Fast path: a whole message that can be delivered right away. */
    if (!e && nfrag == 1 &&
        (mode != MODE_REL_ORD || seq == ch->rx_next)) {
        pc_msg *b = pc_msg_new(&c->ctx->alloc, data, (uint32_t)len);
        if (!b) return 1;
        deliver(c, ch, b);
        if (mode == MODE_REL_ORD) {
            ch->rx_next++;
            ordered_drain(c, ch);
        } else if (mode == MODE_REL_UNORD) {
            unordered_mark_done(c, ch, seq);
        } else if (mode == MODE_SEQ) {
            ch->rx_next = seq + 1;
            while (ch->reasm && ch->reasm->seq < ch->rx_next) {
                pc_reasm *x = ch->reasm;
                ch->reasm = x->next;
                ch->nreasm--;
                reasm_free(c, x);
            }
        }
        return 0;
    }

    if (!e) {
        if (mode == MODE_UNREL || mode == MODE_SEQ) {
            /* Bound partial unreliable reassemblies. */
            uint64_t now = pc_now(c->ctx);
            pc_reasm **link = &ch->reasm;
            while (*link) {
                pc_reasm *x = *link;
                if (now - x->first_us > UNREL_REASM_TIMEOUT_US || ch->nreasm >= UNREL_REASM_MAX) {
                    *link = x->next;
                    ch->nreasm--;
                    reasm_free(c, x);
                } else {
                    link = &x->next;
                }
            }
        }
        e = reasm_get(c, ch, seq, (uint32_t)total, nfrag);
        if (!e) return 1;
    }
    memcpy(e->buf->data + offset, data, (size_t)len);
    e->have[frag] = 1;
    if (++e->got < e->nfrag) return 0;
    e->complete = 1;

    switch (mode) {
    case MODE_REL_ORD:
        ordered_drain(c, ch);
        break;
    case MODE_REL_UNORD:
        reasm_unlink(ch, e);
        deliver(c, ch, reasm_take(c, e));
        reasm_free(c, e);
        unordered_mark_done(c, ch, seq);
        break;
    case MODE_SEQ:
        reasm_unlink(ch, e);
        deliver(c, ch, reasm_take(c, e));
        reasm_free(c, e);
        ch->rx_next = seq + 1;
        while (ch->reasm && ch->reasm->seq < ch->rx_next) {
            pc_reasm *x = ch->reasm;
            ch->reasm = x->next;
            ch->nreasm--;
            reasm_free(c, x);
        }
        break;
    default:
        reasm_unlink(ch, e);
        deliver(c, ch, reasm_take(c, e));
        reasm_free(c, e);
    }
    return 0;
}

static int rx_abandon(pc_conn *c, uint32_t chan_id, uint64_t seq)
{
    int idx = ch_index(c, chan_id);
    if (idx < 0) return -1;
    pc_channel *ch = &c->ch[idx];
    int mode = ch_mode(&ch->cfg);
    if (mode == MODE_REL_ORD) {
        if (seq < ch->rx_next) return 0;
        pc_reasm **link;
        pc_reasm *e = reasm_find(ch, seq, &link);
        if (!e) {
            e = (pc_reasm *)pc_alloc(&c->ctx->alloc, sizeof(*e));
            if (!e) return 1;
            e->seq = seq;
            e->next = *link;
            *link = e;
            ch->nreasm++;
        }
        if (e->buf) {
            c->reasm_bytes -= e->buf->len;
            pc_msg_unref(e->buf);
            e->buf = NULL;
        }
        e->skipped = 1;
        e->complete = 0;
        ordered_drain(c, ch);
    } else if (mode == MODE_REL_UNORD) {
        if (seq < ch->rx_next || done_contains(ch, seq)) return 0;
        pc_reasm *e = reasm_find(ch, seq, NULL);
        if (e) {
            reasm_unlink(ch, e);
            reasm_free(c, e);
        }
        unordered_mark_done(c, ch, seq);
    }
    return 0;
}

/* ===================================================================== */
/* Packet input                                                          */
/* ===================================================================== */

static int replay_check(const pc_conn *c, uint64_t pn)
{
    if (!c->rx_any || pn > c->rx_largest) return 1;
    uint64_t d = c->rx_largest - pn;
    if (d >= PC_REPLAY_WINDOW) return 0;
    return !(c->rx_window[d / 64] & (1ull << (d % 64)));
}

static void replay_mark(pc_conn *c, uint64_t pn)
{
    if (!c->rx_any) {
        memset(c->rx_window, 0, sizeof(c->rx_window));
        c->rx_largest = pn;
        c->rx_window[0] = 1;
        c->rx_any = 1;
        return;
    }
    if (pn > c->rx_largest) {
        uint64_t shift = pn - c->rx_largest;
        if (shift >= PC_REPLAY_WINDOW) {
            memset(c->rx_window, 0, sizeof(c->rx_window));
        } else {
            /* Shift the bitmap left by `shift` bits (bit d = largest - d). */
            const int words = PC_REPLAY_WINDOW / 64;
            uint64_t ws = shift / 64, bs = shift % 64;
            for (int i = words - 1; i >= 0; i--) {
                uint64_t v = 0;
                if ((uint64_t)i >= ws) {
                    v = c->rx_window[i - ws] << bs;
                    if (bs && (uint64_t)i > ws) v |= c->rx_window[i - ws - 1] >> (64 - bs);
                }
                c->rx_window[i] = v;
            }
        }
        c->rx_largest = pn;
        c->rx_window[0] |= 1;
    } else {
        uint64_t d = c->rx_largest - pn;
        c->rx_window[d / 64] |= 1ull << (d % 64);
    }
}

static int try_decrypt(pc_conn *c, uint8_t phase, uint64_t pn, uint8_t *p, size_t len, int *new_phase)
{
    const uint8_t *ad = p;
    uint8_t *body = p + PC_DATA_HDR_LEN;
    size_t blen = len - PC_DATA_HDR_LEN;
    *new_phase = 0;
    if (phase == c->rx_phase) {
        if (pc_aead_decrypt(c->rx_key, pn, ad, PC_DATA_HDR_LEN, body, blen, body) == 0) return 0;
        return -1;
    }
    /* Other phase: either a late packet under the previous key, or the
       peer's first packet under the next key. */
    if (c->rx_prev_valid && pn < c->rx_phase_start_pn)
        return pc_aead_decrypt(c->rx_prev_key, pn, ad, PC_DATA_HDR_LEN, body, blen, body);
    uint8_t next[32];
    memcpy(next, c->rx_key, 32);
    pc_rekey(next);
    if (pc_aead_decrypt(next, pn, ad, PC_DATA_HDR_LEN, body, blen, body) == 0) {
        memcpy(c->rx_prev_key, c->rx_key, 32);
        memcpy(c->rx_key, next, 32);
        c->rx_prev_valid = 1;
        c->rx_phase = phase;
        c->rx_phase_start_pn = pn;
        c->rx_prev_expire_us = pc_now(c->ctx) + 3 * pto_duration(c);
        *new_phase = 1;
        pc_wipe(next, 32);
        return 0;
    }
    pc_wipe(next, 32);
    return -1;
}

void pc_tr_input(pierce_ctx *ctx, const pc_path *path, uint8_t *p, size_t len)
{
    if (len < PC_DATA_HDR_LEN + 16 || p[1] != PC_CID_LEN) return;
    pc_conn *c = pc_conn_by_cid(ctx, p + 2);
    if (!c || !c->keys_ready || c->state == PC_ST_CLOSED) return;
    uint8_t flags = p[1 + 1 + PC_CID_LEN + 2];
    uint64_t pn = pc_get64(p + 1 + 1 + PC_CID_LEN + 2 + 1);
    if (!replay_check(c, pn)) return;
    int new_phase;
    if (try_decrypt(c, flags & PC_DATA_FLAG_KEY_PHASE, pn, p, len, &new_phase) < 0) return;
    uint64_t now = pc_now(ctx);
    int highest = !c->rx_any || pn > c->rx_largest;
    replay_mark(c, pn);
    c->last_rx_us = now;
    c->packets_received++;

    /* Initiator: the first authenticated packet ends HS_FINAL retransmits. */
    if (c->initiator && c->hs_pkt_type == PC_PKT_HS_FINAL) c->hs_pkt_type = 0;

    /* Connection migration: follow the peer to a new address once a packet
       from it authenticates, but only for the newest packet. */
    if (highest && (!c->has_path || !pc_path_eq(path, &c->path))) pc_conn_path_update(c, path);

    pc_rbuf r;
    pc_rbuf_init(&r, p + PC_DATA_HDR_LEN, len - PC_DATA_HDR_LEN - 16);
    int eliciting = 0, reject = 0;
    while (pc_rbuf_left(&r) > 0) {
        uint8_t type = pc_r_u8(&r);
        switch (type) {
        case PC_FR_PADDING:
            r.pos = r.len;
            break;
        case PC_FR_PING:
            eliciting = 1;
            break;
        case PC_FR_ACK: {
            pc_range ranges[MAX_RANGES_IN];
            uint32_t n;
            uint64_t delay;
            if (read_ack(&r, ranges, &n, &delay) < 0) goto protocol_error;
            on_ack(c, ranges, n, delay, now);
            break;
        }
        case PC_FR_MSG: {
            uint64_t chan = pc_r_varint(&r), seq = pc_r_varint(&r), total = pc_r_varint(&r);
            uint64_t off = pc_r_varint(&r), mlen = pc_r_varint(&r);
            const uint8_t *data = pc_r_ptr(&r, (size_t)mlen);
            if (r.err || chan > UINT32_MAX) goto protocol_error;
            eliciting = 1;
            if (c->initiator && c->state == PC_ST_AWAIT_ACCEPT) pc_conn_set_connected(c);
            if (c->state != PC_ST_CONNECTED) {
                reject = 1;   /* not accepted yet: make the peer retransmit later */
                break;
            }
            int rc = rx_msg(c, (uint32_t)chan, seq, total, off, data, mlen);
            if (rc < 0) goto protocol_error;
            if (rc > 0) reject = 1;
            break;
        }
        case PC_FR_CLOSE: {
            uint64_t reason = pc_r_varint(&r);
            uint8_t fl = pc_r_u8(&r);
            if (r.err) goto protocol_error;
            c->close_reason = reason > UINT32_MAX ? PIERCE_REASON_PROTOCOL : (uint32_t)reason;
            pc_conn_fail(c, (fl & PC_CLOSE_FLAG_REJECTED) ? PIERCE_ERR_REJECTED : PIERCE_ERR_CLOSED);
            return;
        }
        case PC_FR_ACCEPT:
            eliciting = 1;
            if (c->initiator && c->state == PC_ST_AWAIT_ACCEPT) pc_conn_set_connected(c);
            break;
        case PC_FR_ABANDON: {
            uint64_t chan = pc_r_varint(&r), seq = pc_r_varint(&r);
            if (r.err || chan > UINT32_MAX) goto protocol_error;
            eliciting = 1;
            if (c->state != PC_ST_CONNECTED) {
                reject = 1;
                break;
            }
            int rc = rx_abandon(c, (uint32_t)chan, seq);
            if (rc < 0) goto protocol_error;
            if (rc > 0) reject = 1;
            break;
        }
        default:
            goto protocol_error;
        }
        if (c->state == PC_ST_CLOSED) return;
    }
    if (r.err) goto protocol_error;

    if (eliciting && !reject) {
        ack_record(c, pn);
        if (highest) c->largest_rx_time_us = now;
        c->ack_eliciting_unacked++;
        if (!c->ack_pending) {
            c->ack_pending = 1;
            c->ack_deadline_us = now + PC_MAX_ACK_DELAY_US;
        }
        if (c->ack_eliciting_unacked >= 2 || !highest) c->ack_deadline_us = now;
    } else if (!eliciting) {
        ack_record(c, pn);   /* keep ranges contiguous; does not trigger an ack */
    }
    (void)new_phase;
    return;

protocol_error:
    pc_log(ctx, PIERCE_LOG_WARN, "protocol violation from peer; closing");
    pc_conn_close(c, PIERCE_REASON_PROTOCOL, 0, PIERCE_ERR_CLOSED);
}

/* ===================================================================== */
/* Sending                                                               */
/* ===================================================================== */

static size_t msg_frame_size(uint32_t chan_id, const pc_outmsg *m, uint32_t frag)
{
    uint32_t off = frag * PC_FRAG_UNIT;
    uint32_t len = PC_MIN((uint32_t)PC_FRAG_UNIT, m->msg->len - off);
    if (m->msg->len == 0) len = 0;
    return 1 + pc_varint_size(chan_id) + pc_varint_size(m->seq) + pc_varint_size(m->msg->len) +
           pc_varint_size(off) + pc_varint_size(len) + len;
}

static void write_msg_frame(pc_wbuf *w, uint32_t chan_id, const pc_outmsg *m, uint32_t frag)
{
    uint32_t off = frag * PC_FRAG_UNIT;
    uint32_t len = m->msg->len ? PC_MIN((uint32_t)PC_FRAG_UNIT, m->msg->len - off) : 0;
    pc_w_u8(w, PC_FR_MSG);
    pc_w_varint(w, chan_id);
    pc_w_varint(w, m->seq);
    pc_w_varint(w, m->msg->len);
    pc_w_varint(w, off);
    pc_w_varint(w, len);
    pc_w_bytes(w, m->msg->data + off, len);
}

static int channel_has_data(pc_conn *c, pc_channel *ch, uint64_t now)
{
    (void)c;
    for (pc_rtx *r = ch->rtx_head; r; r = r->next)
        if (!r->m->finished && !r->m->acked[r->frag]) return 1;
    for (pc_outmsg *m = ch->pend_head; m; m = m->next)
        if (!m->finished && !(m->expiry_us && now >= m->expiry_us)) return 1;
    return 0;
}

static int has_data(pc_conn *c, uint64_t now)
{
    if (c->state != PC_ST_CONNECTED) return 0;
    for (uint32_t i = 0; i < c->nch; i++)
        if (channel_has_data(c, &c->ch[i], now)) return 1;
    return 0;
}

static void frag_record(pc_conn *c, pc_rtx **list, pc_outmsg *m, uint32_t frag)
{
    pc_rtx *r = (pc_rtx *)pc_alloc(&c->ctx->alloc, sizeof(*r));
    if (!r) return;
    r->m = m;
    r->frag = frag;
    m->refs++;
    r->next = *list;
    *list = r;
}

static void pend_pop(pc_conn *c, pc_channel *ch)
{
    pc_outmsg *m = ch->pend_head;
    ch->pend_head = m->next;
    if (!ch->pend_head) ch->pend_tail = NULL;
    m->next = NULL;
    m->in_pending = 0;
    om_unref(c, m);
}

/* Fills data frames from one channel. Returns 1 if the packet is full. */
static int fill_channel(pc_conn *c, pc_channel *ch, pc_wbuf *w, size_t limit, pc_rtx **frags,
                        uint16_t *nfrags, uint64_t now)
{
    while (ch->rtx_head) {
        pc_rtx *r = ch->rtx_head;
        pc_outmsg *m = r->m;
        if (m->finished || m->acked[r->frag]) {
            ch->rtx_head = r->next;
            if (!ch->rtx_head) ch->rtx_tail = NULL;
            om_unref(c, m);
            pc_free(&c->ctx->alloc, r);
            continue;
        }
        if (w->len + msg_frame_size(ch->cfg.id, m, r->frag) > limit) return 1;
        write_msg_frame(w, ch->cfg.id, m, r->frag);
        frag_record(c, frags, m, r->frag);
        (*nfrags)++;
        ch->rtx_head = r->next;
        if (!ch->rtx_head) ch->rtx_tail = NULL;
        om_unref(c, m);
        pc_free(&c->ctx->alloc, r);
    }
    while (ch->pend_head) {
        pc_outmsg *m = ch->pend_head;
        if (m->finished) {
            pend_pop(c, ch);
            continue;
        }
        if (m->expiry_us && now >= m->expiry_us) {
            /* A reliable seq was assigned, so the receiver must be told to
               skip it even if no fragment ever went out. */
            if (m->reliable) om_abandon(c, m);
            else om_finish(c, m);
            pend_pop(c, ch);
            continue;
        }
        if (w->len + msg_frame_size(ch->cfg.id, m, m->next_frag) > limit) return 1;
        write_msg_frame(w, ch->cfg.id, m, m->next_frag);
        frag_record(c, frags, m, m->next_frag);
        (*nfrags)++;
        m->next_frag++;
        if (m->next_frag == m->nfrag) {
            if (!m->reliable) om_finish(c, m);
            pend_pop(c, ch);
        }
    }
    return 0;
}

static void fill_data(pc_conn *c, pc_wbuf *w, size_t limit, pc_rtx **frags, uint16_t *nfrags,
                      uint64_t now)
{
    uint32_t i = 0;
    while (i < c->nch) {
        /* Group of equal priority: rotate the starting channel. */
        uint32_t pri = c->ch[c->ch_order[i]].cfg.priority, j = i;
        while (j < c->nch && c->ch[c->ch_order[j]].cfg.priority == pri) j++;
        uint32_t n = j - i;
        for (uint32_t k = 0; k < n; k++) {
            pc_channel *ch = &c->ch[c->ch_order[i + (k + c->sched_rr) % n]];
            if (fill_channel(c, ch, w, limit, frags, nfrags, now)) {
                c->sched_rr++;
                return;
            }
        }
        i = j;
    }
    c->sched_rr++;
}

static void maybe_rekey(pc_conn *c, uint64_t now)
{
    if (c->tx_pn - c->tx_rekey_pn >= rekey_packets || now - c->tx_rekey_us >= PC_REKEY_INTERVAL_US) {
        pc_rekey(c->tx_key);
        c->tx_phase ^= 1;
        c->tx_rekey_pn = c->tx_pn;
        c->tx_rekey_us = now;
    }
}

/* Encrypts frames already written at ctx->pkt + header and sends. */
static size_t seal_and_send(pc_conn *c, size_t payload_len)
{
    uint8_t *p = c->ctx->pkt;
    p[0] = PC_PKT_DATA;
    p[1] = PC_CID_LEN;
    memcpy(p + 2, c->remote_cid, PC_CID_LEN);
    pc_put16(p + 2 + PC_CID_LEN, 0);                         /* cid sequence: always 0 in v1 */
    p[2 + PC_CID_LEN + 2] = c->tx_phase ? PC_DATA_FLAG_KEY_PHASE : 0;
    pc_put64(p + 2 + PC_CID_LEN + 3, c->tx_pn);
    pc_aead_encrypt(c->tx_key, c->tx_pn, p, PC_DATA_HDR_LEN, p + PC_DATA_HDR_LEN, payload_len,
                    p + PC_DATA_HDR_LEN);
    size_t total = PC_DATA_HDR_LEN + payload_len + 16;
    if (c->has_path) pc_send_path(c->ctx, &c->path, p, total);
    c->tx_pn++;
    c->packets_sent++;
    return total;
}

void pc_tr_send_close(pc_conn *c)
{
    if (!c->keys_ready || !c->has_path || !c->has_remote_cid) return;
    pc_wbuf w;
    pc_wbuf_init(&w, c->ctx->pkt + PC_DATA_HDR_LEN, PC_DATA_PAYLOAD_MAX);
    pc_w_u8(&w, PC_FR_CLOSE);
    pc_w_varint(&w, c->close_reason);
    pc_w_u8(&w, c->close_rejected ? PC_CLOSE_FLAG_REJECTED : 0);
    seal_and_send(c, w.len);
}

void pc_tr_flush(pc_conn *c, uint64_t now)
{
    if (!c->keys_ready || !c->has_remote_cid || !c->has_path) return;
    if (c->state == PC_ST_CLOSED) return;
    for (int guard = 0; guard < 1024; guard++) {
        maybe_rekey(c, now);
        pc_wbuf w;
        pc_wbuf_init(&w, c->ctx->pkt + PC_DATA_HDR_LEN, PC_DATA_PAYLOAD_MAX);
        int eliciting = 0, has_accept = 0;
        pc_rtx *frags = NULL;
        uint16_t nfrags = 0;
        pc_abandon *abandons = NULL;
        uint16_t nab = 0;

        int cwnd_ok = c->probes_to_send > 0 || c->bytes_in_flight + PC_MTU <= c->cc.cwnd;
        int data = cwnd_ok && has_data(c, now);
        int ack_now = c->ack_pending && (c->ack_deadline_us <= now || data || c->ping_pending ||
                                         c->accept_pending || c->nabandons);
        if (ack_now) write_ack(c, &w, data ? 36 : PC_DATA_PAYLOAD_MAX, now);
        int wrote_ack = w.len > 0;

        if (cwnd_ok) {
            if (c->accept_pending) {
                pc_w_u8(&w, PC_FR_ACCEPT);
                c->accept_pending = 0;
                has_accept = eliciting = 1;
            }
            if (c->nabandons) {
                uint16_t can = 0;
                size_t save = w.len;
                for (uint32_t i = 0; i < c->nabandons && can < 64; i++) {
                    size_t sz = 1 + pc_varint_size(c->abandons[i].channel_id) +
                                pc_varint_size(c->abandons[i].seq);
                    if (w.len + sz > PC_DATA_PAYLOAD_MAX) break;
                    pc_w_u8(&w, PC_FR_ABANDON);
                    pc_w_varint(&w, c->abandons[i].channel_id);
                    pc_w_varint(&w, c->abandons[i].seq);
                    can++;
                }
                if (can) {
                    abandons = (pc_abandon *)pc_alloc(&c->ctx->alloc, can * sizeof(pc_abandon));
                    if (abandons) {
                        memcpy(abandons, c->abandons, can * sizeof(pc_abandon));
                        memmove(c->abandons, c->abandons + can, (c->nabandons - can) * sizeof(pc_abandon));
                        c->nabandons -= can;
                        nab = can;
                        eliciting = 1;
                    } else {
                        w.len = save;
                    }
                }
            }
            if (data) fill_data(c, &w, PC_DATA_PAYLOAD_MAX, &frags, &nfrags, now);
            if (nfrags) eliciting = 1;
            if ((c->ping_pending || c->probes_to_send) && !eliciting) {
                pc_w_u8(&w, PC_FR_PING);
                eliciting = 1;
            }
            if (eliciting) c->ping_pending = 0;
        }

        if (w.len == 0) break;
        size_t size = seal_and_send(c, w.len);
        uint64_t pn = c->tx_pn - 1;
        if (wrote_ack) {
            c->ack_pending = 0;
            c->ack_eliciting_unacked = 0;
        }
        if (eliciting) {
            pc_sentpkt *sp = (pc_sentpkt *)pc_alloc(&c->ctx->alloc, sizeof(*sp));
            if (sp) {
                sp->pn = pn;
                sp->time_sent = now;
                sp->size = (uint32_t)size;
                sp->ack_eliciting = 1;
                sp->has_accept = (uint8_t)has_accept;
                sp->frags = frags;
                sp->nfrags = nfrags;
                sp->abandons = abandons;
                sp->nabandons = nab;
                if (c->sent_tail) c->sent_tail->next = sp;
                else c->sent_head = sp;
                c->sent_tail = sp;
                c->bytes_in_flight += size;
            } else {
                for (pc_rtx *r = frags; r;) {
                    pc_rtx *n = r->next;
                    om_unref(c, r->m);
                    pc_free(&c->ctx->alloc, r);
                    r = n;
                }
                pc_free(&c->ctx->alloc, abandons);
            }
            c->last_eliciting_tx_us = now;
            if (c->probes_to_send) c->probes_to_send--;
        }
        if (!eliciting && !c->ack_pending) break;
    }
}

/* ===================================================================== */
/* Timers                                                                */
/* ===================================================================== */

static uint64_t loss_or_pto_time(const pc_conn *c)
{
    if (c->loss_time_us) return c->loss_time_us;
    if (!c->bytes_in_flight) return 0;
    uint64_t d = pto_duration(c) << PC_MIN(c->pto_count, 10u);
    return c->last_eliciting_tx_us + d;
}

uint64_t pc_tr_next_timer(pc_conn *c)
{
    uint64_t t = 0;
    if (!c->keys_ready) return 0;
    if (c->ack_pending) t = c->ack_deadline_us;
    uint64_t l = loss_or_pto_time(c);
    if (l && (!t || l < t)) t = l;
    return t;
}

void pc_tr_timers(pc_conn *c, uint64_t now)
{
    if (!c->keys_ready) return;
    if (c->rx_prev_valid && now >= c->rx_prev_expire_us) {
        c->rx_prev_valid = 0;
        pc_wipe(c->rx_prev_key, 32);
    }
    uint64_t l = loss_or_pto_time(c);
    if (l && now >= l) {
        if (c->loss_time_us) {
            detect_lost(c, now);
        } else {
            c->pto_count++;
            c->probes_to_send = 2;
            if (c->pto_count >= 3) c->cc.cwnd = CC_MIN_WINDOW;   /* persistent congestion */
            /* Retransmit the oldest outstanding data in the probes. */
            pc_sentpkt *p = c->sent_head;
            if (p) {
                for (pc_rtx *r = p->frags; r; r = r->next) {
                    pc_outmsg *m = r->m;
                    if (m->reliable && !m->finished && !m->acked[r->frag])
                        rtx_push(c, &c->ch[m->channel], m, r->frag);
                }
            }
        }
    }
}

/* ===================================================================== */
/* Teardown                                                              */
/* ===================================================================== */

void pc_tr_free(pc_conn *c)
{
    const pc_allocator *a = &c->ctx->alloc;
    pc_sentpkt *p = c->sent_head;
    while (p) {
        pc_sentpkt *n = p->next;
        sentpkt_free(c, p);
        p = n;
    }
    c->sent_head = c->sent_tail = NULL;
    for (uint32_t i = 0; i < c->nch; i++) {
        pc_channel *ch = &c->ch[i];
        while (ch->rtx_head) {
            pc_rtx *r = ch->rtx_head;
            ch->rtx_head = r->next;
            om_unref(c, r->m);
            pc_free(a, r);
        }
        while (ch->pend_head) pend_pop(c, ch);
        while (ch->reasm) {
            pc_reasm *e = ch->reasm;
            ch->reasm = e->next;
            reasm_free(c, e);
        }
        pc_free(a, ch->done);
        ch->done = NULL;
    }
    pc_free(a, c->abandons);
    c->abandons = NULL;
    c->nabandons = c->capabandons = 0;
    pc_wipe(c->tx_key, 32);
    pc_wipe(c->rx_key, 32);
    pc_wipe(c->rx_prev_key, 32);
}
