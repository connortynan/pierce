#include "noise.h"

#include <string.h>

#include "../vendor/monocypher/src/monocypher.h"
#include "common.h"
#include "crypto.h"

/* Message tokens. */
enum { T_E = 1, T_S, T_EE, T_ES, T_SE, T_SS, T_END = 0 };

static const uint8_t ik_msgs[2][5] = {
    {T_E, T_ES, T_S, T_SS, T_END},
    {T_E, T_EE, T_SE, T_END},
};
static const uint8_t xx_msgs[3][5] = {
    {T_E, T_END},
    {T_E, T_EE, T_S, T_ES, T_END},
    {T_S, T_SE, T_END},
};

static const uint8_t *tokens(int pattern, int step)
{
    if (pattern == PC_NOISE_IK) return step < 2 ? ik_msgs[step] : NULL;
    return step < 3 ? xx_msgs[step] : NULL;
}

static int msg_count(int pattern) { return pattern == PC_NOISE_IK ? 2 : 3; }

static void mix_hash(pc_noise *hs, const uint8_t *data, size_t len)
{
    pc_hash2(hs->h, hs->h, PC_HASHLEN, data, len);
}

static void mix_key(pc_noise *hs, const uint8_t *ikm, size_t len)
{
    uint8_t k[PC_HASHLEN];
    pc_hkdf2(hs->ck, ikm, len, hs->ck, k);
    memcpy(hs->k, k, 32);
    hs->n = 0;
    hs->has_k = 1;
    pc_wipe(k, sizeof(k));
}

/* out gets len (+16 if keyed) bytes. */
static void encrypt_and_hash(pc_noise *hs, const uint8_t *pt, size_t len, uint8_t *out, size_t *outlen)
{
    if (hs->has_k) {
        pc_aead_encrypt(hs->k, hs->n++, hs->h, PC_HASHLEN, pt, len, out);
        *outlen = len + PC_TAGLEN;
    } else {
        if (len) memmove(out, pt, len);
        *outlen = len;
    }
    mix_hash(hs, out, *outlen);
}

static int decrypt_and_hash(pc_noise *hs, const uint8_t *in, size_t len, uint8_t *out, size_t *outlen)
{
    uint8_t h[PC_HASHLEN];
    memcpy(h, hs->h, PC_HASHLEN);
    mix_hash(hs, in, len);
    if (hs->has_k) {
        if (len < PC_TAGLEN) return -1;
        if (pc_aead_decrypt(hs->k, hs->n++, h, PC_HASHLEN, in, len, out) < 0) return -1;
        *outlen = len - PC_TAGLEN;
    } else {
        if (len) memmove(out, in, len);
        *outlen = len;
    }
    return 0;
}

static int dh(pc_noise *hs, const uint8_t sk[32], const uint8_t pk[32])
{
    uint8_t shared[32], zero[32];
    crypto_x25519(shared, sk, pk);
    memset(zero, 0, sizeof(zero));
    /* Reject low-order points: an all-zero shared secret means the peer
       sent a key with no secret contribution. */
    int bad = pc_ct_eq32(shared, zero);
    mix_key(hs, shared, 32);
    pc_wipe(shared, sizeof(shared));
    return bad ? -1 : 0;
}

static int do_dh(pc_noise *hs, int token)
{
    /* Initiator perspective; responder swaps which local key is used. */
    int i = hs->initiator;
    switch (token) {
    case T_EE: return dh(hs, hs->e_sk, hs->re);
    case T_SS: return dh(hs, hs->s_sk, hs->rs);
    case T_ES: return i ? dh(hs, hs->e_sk, hs->rs) : dh(hs, hs->s_sk, hs->re);
    case T_SE: return i ? dh(hs, hs->s_sk, hs->re) : dh(hs, hs->e_sk, hs->rs);
    }
    return -1;
}

int pc_noise_init(pc_noise *hs, int pattern, int initiator,
                  const uint8_t *prologue, size_t prologue_len,
                  const uint8_t s_sk[32], const uint8_t *rs)
{
    const char *name = pattern == PC_NOISE_IK ? "Noise_IK_25519_ChaChaPoly_BLAKE2b"
                                              : "Noise_XX_25519_ChaChaPoly_BLAKE2b";
    if (pattern != PC_NOISE_IK && pattern != PC_NOISE_XX) return -1;
    if (pattern == PC_NOISE_IK && initiator && !rs) return -1;
    memset(hs, 0, sizeof(*hs));
    hs->pattern = pattern;
    hs->initiator = initiator;
    memcpy(hs->h, name, strlen(name));          /* name fits in HASHLEN: zero padded */
    memcpy(hs->ck, hs->h, PC_HASHLEN);
    mix_hash(hs, prologue, prologue_len);
    memcpy(hs->s_sk, s_sk, 32);
    crypto_x25519_public_key(hs->s_pk, s_sk);
    if (rs) {
        memcpy(hs->rs, rs, 32);
        hs->has_rs = 1;
    }
    if (pattern == PC_NOISE_IK) {
        /* Pre-message: <- s */
        mix_hash(hs, initiator ? hs->rs : hs->s_pk, 32);
    }
    return 0;
}

void pc_noise_set_ephemeral(pc_noise *hs, const uint8_t e_sk[32])
{
    memcpy(hs->e_sk, e_sk, 32);
    crypto_x25519_public_key(hs->e_pk, e_sk);
    hs->has_e = 1;
}

int pc_noise_is_my_turn(const pc_noise *hs)
{
    /* Even steps are written by the initiator. */
    return (hs->step % 2 == 0) == (hs->initiator != 0);
}

int pc_noise_done(const pc_noise *hs) { return hs->step >= msg_count(hs->pattern); }

size_t pc_noise_overhead(int pattern, int step)
{
    const uint8_t *t = tokens(pattern, step);
    size_t n = 0;
    int keyed = 0;
    if (!t) return 0;
    /* Whether a key exists before this message: true once any DH happened. */
    for (int s = 0; s < step; s++) {
        const uint8_t *p = tokens(pattern, s);
        for (; *p; p++) if (*p >= T_EE) keyed = 1;
    }
    for (; *t; t++) {
        if (*t == T_E) n += 32;
        else if (*t == T_S) n += keyed ? 48 : 32;
        else keyed = 1;
    }
    return n + (keyed ? PC_TAGLEN : 0);
}

int pc_noise_write(pc_noise *hs, const uint8_t *payload, size_t plen,
                   uint8_t *out, size_t cap, size_t *outlen)
{
    const uint8_t *t = tokens(hs->pattern, hs->step);
    size_t pos = 0, n;
    if (!t || !pc_noise_is_my_turn(hs)) return -1;
    if (pc_noise_overhead(hs->pattern, hs->step) + plen > cap) return -1;
    for (; *t; t++) {
        switch (*t) {
        case T_E:
            if (!hs->has_e) {
                uint8_t sk[32];
                pc_random(sk, 32);
                pc_noise_set_ephemeral(hs, sk);
                pc_wipe(sk, 32);
            }
            memcpy(out + pos, hs->e_pk, 32);
            mix_hash(hs, hs->e_pk, 32);
            pos += 32;
            break;
        case T_S:
            encrypt_and_hash(hs, hs->s_pk, 32, out + pos, &n);
            pos += n;
            break;
        default:
            if (do_dh(hs, *t) < 0) return -1;
        }
    }
    encrypt_and_hash(hs, payload, plen, out + pos, &n);
    *outlen = pos + n;
    hs->step++;
    return 0;
}

int pc_noise_read(pc_noise *hs, const uint8_t *msg, size_t len,
                  uint8_t *payload, size_t cap, size_t *plen)
{
    const uint8_t *t = tokens(hs->pattern, hs->step);
    size_t pos = 0, n;
    if (!t || pc_noise_is_my_turn(hs)) return -1;
    for (; *t; t++) {
        switch (*t) {
        case T_E:
            if (len - pos < 32) return -1;
            memcpy(hs->re, msg + pos, 32);
            hs->has_re = 1;
            mix_hash(hs, hs->re, 32);
            pos += 32;
            break;
        case T_S: {
            size_t need = hs->has_k ? 48 : 32;
            if (len - pos < need) return -1;
            if (decrypt_and_hash(hs, msg + pos, need, hs->rs, &n) < 0) return -1;
            hs->has_rs = 1;
            pos += need;
            break;
        }
        default:
            if (do_dh(hs, *t) < 0) return -1;
        }
    }
    size_t rest = len - pos;
    if (rest > cap + (hs->has_k ? PC_TAGLEN : 0)) return -1;
    if (hs->has_k && rest < PC_TAGLEN) return -1;
    {
        uint8_t tmp[2048];
        if (rest > sizeof(tmp)) return -1;
        if (decrypt_and_hash(hs, msg + pos, rest, tmp, &n) < 0) return -1;
        if (n > cap) return -1;
        memcpy(payload, tmp, n);
        pc_wipe(tmp, n);
    }
    *plen = n;
    hs->step++;
    return 0;
}

void pc_noise_split(pc_noise *hs, uint8_t k_i2r[32], uint8_t k_r2i[32])
{
    uint8_t a[PC_HASHLEN], b[PC_HASHLEN];
    pc_hkdf2(hs->ck, NULL, 0, a, b);
    memcpy(k_i2r, a, 32);
    memcpy(k_r2i, b, 32);
    pc_wipe(a, sizeof(a));
    pc_wipe(b, sizeof(b));
}

void pc_noise_wipe(pc_noise *hs) { pc_wipe(hs, sizeof(*hs)); }
