/* Constructions over Monocypher primitives (spec 4.1). No primitives here. */
#ifndef PIERCE_CRYPTO_H
#define PIERCE_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define PC_HASHLEN 64
#define PC_TAGLEN 16

/* BLAKE2b-512 of a || b. */
void pc_hash2(uint8_t out[PC_HASHLEN], const void *a, size_t alen, const void *b, size_t blen);
/* HMAC-BLAKE2b (block length 128), as Noise requires. */
void pc_hmac(uint8_t out[PC_HASHLEN], const uint8_t *key, size_t keylen,
             const uint8_t *data, size_t dlen);
/* Noise HKDF with two outputs. */
void pc_hkdf2(const uint8_t ck[PC_HASHLEN], const uint8_t *ikm, size_t ikmlen,
              uint8_t out1[PC_HASHLEN], uint8_t out2[PC_HASHLEN]);
/* Keyed BLAKE2b with a 16-byte output (probe MACs, cookies, relay tokens). */
void pc_mac16(uint8_t out[16], const uint8_t *key, size_t keylen, const uint8_t *data, size_t dlen);

/* RFC 8439 ChaCha20-Poly1305 with Noise nonce encoding (32 zero bits then
   the 64-bit counter little-endian). out = ciphertext || tag; out may equal pt. */
void pc_aead_encrypt(const uint8_t key[32], uint64_t nonce, const uint8_t *ad, size_t adlen,
                     const uint8_t *pt, size_t len, uint8_t *out);
/* in = ciphertext || tag (inlen >= 16). Returns 0 or -1. out may equal in. */
int pc_aead_decrypt(const uint8_t key[32], uint64_t nonce, const uint8_t *ad, size_t adlen,
                    const uint8_t *in, size_t inlen, uint8_t *out);
/* Noise REKEY(k). */
void pc_rekey(uint8_t key[32]);

void pc_wipe(void *p, size_t n);
int pc_ct_eq16(const uint8_t a[16], const uint8_t b[16]);   /* constant time, 1 if equal */
int pc_ct_eq32(const uint8_t a[32], const uint8_t b[32]);

#endif
