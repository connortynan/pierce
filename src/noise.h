/* Noise IK / XX over 25519, ChaChaPoly, BLAKE2b (spec 4.2). */
#ifndef PIERCE_NOISE_H
#define PIERCE_NOISE_H

#include <stddef.h>
#include <stdint.h>

enum { PC_NOISE_IK = 1, PC_NOISE_XX = 2 };

typedef struct {
    uint8_t ck[64], h[64], k[32];
    uint64_t n;
    int has_k;
    int pattern, initiator, step;
    uint8_t s_sk[32], s_pk[32];
    uint8_t e_sk[32], e_pk[32];
    uint8_t rs[32], re[32];
    int has_e, has_rs, has_re;
} pc_noise;

/* rs: responder static key, required for an IK initiator, else NULL. */
int pc_noise_init(pc_noise *hs, int pattern, int initiator,
                  const uint8_t *prologue, size_t prologue_len,
                  const uint8_t s_sk[32], const uint8_t *rs);
/* Test hook: use a fixed ephemeral key instead of a random one. */
void pc_noise_set_ephemeral(pc_noise *hs, const uint8_t e_sk[32]);

/* Writes the next handshake message. Returns 0 or -1. */
int pc_noise_write(pc_noise *hs, const uint8_t *payload, size_t plen,
                   uint8_t *out, size_t cap, size_t *outlen);
/* Reads the next handshake message. Returns 0 or -1 (state is then unusable). */
int pc_noise_read(pc_noise *hs, const uint8_t *msg, size_t len,
                  uint8_t *payload, size_t cap, size_t *plen);

int pc_noise_is_my_turn(const pc_noise *hs);
int pc_noise_done(const pc_noise *hs);
/* After done: initiator->responder and responder->initiator keys. */
void pc_noise_split(pc_noise *hs, uint8_t k_i2r[32], uint8_t k_r2i[32]);
void pc_noise_wipe(pc_noise *hs);

/* Overhead added to the payload by the message at index `step`. */
size_t pc_noise_overhead(int pattern, int step);

#endif
