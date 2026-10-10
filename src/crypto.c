#include "crypto.h"

#include <string.h>

#include "../vendor/monocypher/src/monocypher.h"

#define BLOCKLEN 128

void pc_hash2(uint8_t out[PC_HASHLEN], const void *a, size_t alen, const void *b, size_t blen)
{
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, PC_HASHLEN);
    if (alen) crypto_blake2b_update(&ctx, (const uint8_t *)a, alen);
    if (blen) crypto_blake2b_update(&ctx, (const uint8_t *)b, blen);
    crypto_blake2b_final(&ctx, out);
}

void pc_hmac(uint8_t out[PC_HASHLEN], const uint8_t *key, size_t keylen,
             const uint8_t *data, size_t dlen)
{
    uint8_t k[BLOCKLEN], pad[BLOCKLEN], inner[PC_HASHLEN];
    crypto_blake2b_ctx ctx;
    memset(k, 0, sizeof(k));
    if (keylen > BLOCKLEN) crypto_blake2b(k, PC_HASHLEN, key, keylen);
    else memcpy(k, key, keylen);

    for (int i = 0; i < BLOCKLEN; i++) pad[i] = k[i] ^ 0x36;
    crypto_blake2b_init(&ctx, PC_HASHLEN);
    crypto_blake2b_update(&ctx, pad, BLOCKLEN);
    crypto_blake2b_update(&ctx, data, dlen);
    crypto_blake2b_final(&ctx, inner);

    for (int i = 0; i < BLOCKLEN; i++) pad[i] = k[i] ^ 0x5c;
    crypto_blake2b_init(&ctx, PC_HASHLEN);
    crypto_blake2b_update(&ctx, pad, BLOCKLEN);
    crypto_blake2b_update(&ctx, inner, PC_HASHLEN);
    crypto_blake2b_final(&ctx, out);

    crypto_wipe(k, sizeof(k));
    crypto_wipe(pad, sizeof(pad));
    crypto_wipe(inner, sizeof(inner));
}

void pc_hkdf2(const uint8_t ck[PC_HASHLEN], const uint8_t *ikm, size_t ikmlen,
              uint8_t out1[PC_HASHLEN], uint8_t out2[PC_HASHLEN])
{
    uint8_t temp[PC_HASHLEN], buf[PC_HASHLEN + 1];
    pc_hmac(temp, ck, PC_HASHLEN, ikm, ikmlen);
    buf[0] = 0x01;
    pc_hmac(out1, temp, PC_HASHLEN, buf, 1);
    memcpy(buf, out1, PC_HASHLEN);
    buf[PC_HASHLEN] = 0x02;
    pc_hmac(out2, temp, PC_HASHLEN, buf, PC_HASHLEN + 1);
    crypto_wipe(temp, sizeof(temp));
    crypto_wipe(buf, sizeof(buf));
}

void pc_mac16(uint8_t out[16], const uint8_t *key, size_t keylen, const uint8_t *data, size_t dlen)
{
    uint8_t k[64];
    if (keylen > 64) {
        crypto_blake2b(k, 64, key, keylen);
        key = k;
        keylen = 64;
    }
    crypto_blake2b_keyed(out, 16, key, keylen, data, dlen);
    crypto_wipe(k, sizeof(k));
}

static void noise_nonce(uint8_t n[12], uint64_t counter)
{
    memset(n, 0, 4);
    for (int i = 0; i < 8; i++) n[4 + i] = (uint8_t)(counter >> (8 * i));
}

/* A fresh crypto_aead_ctx per message: one ietf-initialised write is exactly
   RFC 8439 (Monocypher ratchets the key only for *subsequent* writes). */
void pc_aead_encrypt(const uint8_t key[32], uint64_t nonce, const uint8_t *ad, size_t adlen,
                     const uint8_t *pt, size_t len, uint8_t *out)
{
    crypto_aead_ctx ctx;
    uint8_t n[12];
    noise_nonce(n, nonce);
    crypto_aead_init_ietf(&ctx, key, n);
    crypto_aead_write(&ctx, out, out + len, ad, adlen, pt, len);
    crypto_wipe(&ctx, sizeof(ctx));
}

int pc_aead_decrypt(const uint8_t key[32], uint64_t nonce, const uint8_t *ad, size_t adlen,
                    const uint8_t *in, size_t inlen, uint8_t *out)
{
    crypto_aead_ctx ctx;
    uint8_t n[12];
    uint8_t tag[PC_TAGLEN];
    if (inlen < PC_TAGLEN) return -1;
    size_t len = inlen - PC_TAGLEN;
    memcpy(tag, in + len, PC_TAGLEN);   /* out may alias in */
    noise_nonce(n, nonce);
    crypto_aead_init_ietf(&ctx, key, n);
    int r = crypto_aead_read(&ctx, out, tag, ad, adlen, in, len);
    crypto_wipe(&ctx, sizeof(ctx));
    return r ? -1 : 0;
}

void pc_rekey(uint8_t key[32])
{
    uint8_t zeros[32], out[32 + PC_TAGLEN];
    memset(zeros, 0, sizeof(zeros));
    pc_aead_encrypt(key, UINT64_MAX, NULL, 0, zeros, 32, out);
    memcpy(key, out, 32);
    crypto_wipe(out, sizeof(out));
}

void pc_wipe(void *p, size_t n) { crypto_wipe(p, n); }
int pc_ct_eq16(const uint8_t a[16], const uint8_t b[16]) { return crypto_verify16(a, b) == 0; }
int pc_ct_eq32(const uint8_t a[32], const uint8_t b[32]) { return crypto_verify32(a, b) == 0; }
