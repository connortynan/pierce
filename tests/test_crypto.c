/* Crypto constructions and Noise, against published vectors. */
#include "../src/common.h"
#include "../src/crypto.h"
#include "../src/noise.h"
#include "test.h"
#include "vectors_noise.h"

/* pc_aead_* round trip: tags bind the nonce, the AD and the ciphertext.
   (The RFC 8439 vector's nonce starts 07000000, which a Noise nonce can
   never produce, so exact conformance is checked through Monocypher in
   test_rfc8439_exact and through pc_aead_* by the Noise vectors.) */
static void test_aead_round_trip(void)
{
    uint8_t key[32], pt[114], ct[114 + 16], back[114];
    uint8_t ad[12] = {0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7};
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(0x80 + i);
    memcpy(pt, "Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
               "for the future, sunscreen would be it.", 114);
    pc_aead_encrypt(key, 42, ad, sizeof(ad), pt, sizeof(pt), ct);
    CHECK(pc_aead_decrypt(key, 42, ad, sizeof(ad), ct, sizeof(ct), back) == 0);
    CHECK(memcmp(back, pt, sizeof(pt)) == 0);
    CHECK(pc_aead_decrypt(key, 43, ad, sizeof(ad), ct, sizeof(ct), back) < 0);
    ad[0] ^= 1;
    CHECK(pc_aead_decrypt(key, 42, ad, sizeof(ad), ct, sizeof(ct), back) < 0);
    ad[0] ^= 1;
    ct[5] ^= 1;
    CHECK(pc_aead_decrypt(key, 42, ad, sizeof(ad), ct, sizeof(ct), back) < 0);
}

/* RFC 8439 2.8.2 checked exactly, through Monocypher directly, so the
   per-message init_ietf usage is proven RFC-conformant. */
#include "../vendor/monocypher/src/monocypher.h"
static void test_rfc8439_exact(void)
{
    uint8_t key[32], nonce[12] = {0x07, 0, 0, 0, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47};
    uint8_t ad[12] = {0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7};
    uint8_t pt[114], ct[114], mac[16], expect_ct[114], expect_tag[16];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(0x80 + i);
    memcpy(pt, "Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
               "for the future, sunscreen would be it.", 114);
    hex_decode("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
               "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
               "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
               "3ff4def08e4b7a9de576d26586cec64b6116", expect_ct, sizeof(expect_ct));
    hex_decode("1ae10b594f09e26a7e902ecbd0600691", expect_tag, sizeof(expect_tag));
    crypto_aead_ctx ctx;
    crypto_aead_init_ietf(&ctx, key, nonce);
    crypto_aead_write(&ctx, ct, mac, ad, sizeof(ad), pt, sizeof(pt));
    CHECK(memcmp(ct, expect_ct, sizeof(ct)) == 0);
    CHECK(memcmp(mac, expect_tag, 16) == 0);
}

static void test_hmac_blake2b(void)
{
    /* Expected values from Python: hmac.new(key, msg, hashlib.blake2b). */
    uint8_t out[64], expect[64], longkey[200];
    const char *msg = "The quick brown fox jumps over the lazy dog";
    pc_hmac(out, (const uint8_t *)"key", 3, (const uint8_t *)msg, strlen(msg));
    hex_decode("92294f92c0dfb9b00ec9ae8bd94d7e7d8a036b885a499f149dfe2fd2199394aa"
               "af6b8894a1730cccb2cd050f9bcf5062a38b51b0dab33207f8ef35ae2c9df51b",
               expect, sizeof(expect));
    CHECK(memcmp(out, expect, 64) == 0);
    memset(longkey, 'k', sizeof(longkey));   /* longer than the block: hashed first */
    pc_hmac(out, longkey, sizeof(longkey), NULL, 0);
    hex_decode("71cbd2883472b537c70b41e6d164491d7e53258042d760c96d6379ac63a8a3e4"
               "d28e4904062db715948c267e8ebf58534e03d972926778f24ae7493a68394828",
               expect, sizeof(expect));
    CHECK(memcmp(out, expect, 64) == 0);
}

static void run_vector(const noise_vector *v)
{
    uint8_t prologue[64], i_s[32], i_e[32], i_rs[32], r_s[32], r_e[32], hh[64];
    size_t plen = hex_decode(v->prologue, prologue, sizeof(prologue));
    hex_decode(v->init_static, i_s, 32);
    hex_decode(v->init_ephemeral, i_e, 32);
    hex_decode(v->resp_static, r_s, 32);
    hex_decode(v->resp_ephemeral, r_e, 32);
    hex_decode(v->handshake_hash, hh, 64);
    if (v->init_remote_static) hex_decode(v->init_remote_static, i_rs, 32);

    pc_noise ini, rsp;
    REQUIRE(pc_noise_init(&ini, v->pattern, 1, prologue, plen, i_s,
                          v->init_remote_static ? i_rs : NULL) == 0);
    REQUIRE(pc_noise_init(&rsp, v->pattern, 0, prologue, plen, r_s, NULL) == 0);
    pc_noise_set_ephemeral(&ini, i_e);
    pc_noise_set_ephemeral(&rsp, r_e);

    uint8_t k_i2r[2][32], k_r2i[2][32];
    uint64_t n_i2r = 0, n_r2i = 0;
    int handshaking = 1;
    for (int m = 0; m < v->msg_count; m++) {
        uint8_t payload[256], expect[512], out[512], got[512];
        size_t pl = hex_decode(v->msgs[m].payload, payload, sizeof(payload));
        size_t el = hex_decode(v->msgs[m].ciphertext, expect, sizeof(expect));
        int from_init = (m % 2) == 0;
        pc_noise *w = from_init ? &ini : &rsp, *r = from_init ? &rsp : &ini;
        size_t ol = 0, gl = 0;
        if (handshaking) {
            REQUIRE(pc_noise_write(w, payload, pl, out, sizeof(out), &ol) == 0);
            CHECK_EQ(ol, el);
            CHECK(memcmp(out, expect, el) == 0);
            REQUIRE(pc_noise_read(r, out, ol, got, sizeof(got), &gl) == 0);
            CHECK_EQ(gl, pl);
            CHECK(memcmp(got, payload, pl) == 0);
            CHECK_EQ(pc_noise_overhead(v->pattern, m) + pl, el);
            if (pc_noise_done(&ini) && pc_noise_done(&rsp)) {
                CHECK(memcmp(ini.h, hh, 64) == 0);
                CHECK(memcmp(rsp.h, hh, 64) == 0);
                pc_noise_split(&ini, k_i2r[0], k_r2i[0]);
                pc_noise_split(&rsp, k_i2r[1], k_r2i[1]);
                CHECK(memcmp(k_i2r[0], k_i2r[1], 32) == 0);
                CHECK(memcmp(k_r2i[0], k_r2i[1], 32) == 0);
                handshaking = 0;
            }
        } else {
            const uint8_t *k = from_init ? k_i2r[0] : k_r2i[0];
            uint64_t n = from_init ? n_i2r++ : n_r2i++;
            pc_aead_encrypt(k, n, NULL, 0, payload, pl, out);
            CHECK_EQ(pl + 16, el);
            CHECK(memcmp(out, expect, el) == 0);
            CHECK(pc_aead_decrypt(k, n, NULL, 0, out, pl + 16, got) == 0);
            CHECK(memcmp(got, payload, pl) == 0);
        }
    }
    CHECK(!handshaking);
}

static void test_noise_vectors(void)
{
    for (size_t i = 0; i < sizeof(noise_vectors) / sizeof(noise_vectors[0]); i++)
        run_vector(&noise_vectors[i]);
}

static void test_noise_ik_wrong_key_fails(void)
{
    uint8_t is[32], rs[32], wrong_pk[32], wrong_sk[32];
    pc_random(is, 32);
    pc_random(rs, 32);
    pc_random(wrong_sk, 32);
    crypto_x25519_public_key(wrong_pk, wrong_sk);
    pc_noise ini, rsp;
    pc_noise_init(&ini, PC_NOISE_IK, 1, NULL, 0, is, wrong_pk);
    pc_noise_init(&rsp, PC_NOISE_IK, 0, NULL, 0, rs, NULL);
    uint8_t m[256], p[64];
    size_t ml, pl;
    REQUIRE(pc_noise_write(&ini, (const uint8_t *)"hi", 2, m, sizeof(m), &ml) == 0);
    CHECK(pc_noise_read(&rsp, m, ml, p, sizeof(p), &pl) < 0);
}

static void test_noise_low_order_rejected(void)
{
    uint8_t is[32], zero_pk[32];
    pc_random(is, 32);
    memset(zero_pk, 0, 32);
    pc_noise ini;
    pc_noise_init(&ini, PC_NOISE_IK, 1, NULL, 0, is, zero_pk);
    uint8_t m[256];
    size_t ml;
    CHECK(pc_noise_write(&ini, NULL, 0, m, sizeof(m), &ml) < 0);
}

static void test_rekey(void)
{
    uint8_t a[32], b[32];
    pc_random(a, 32);
    memcpy(b, a, 32);
    pc_rekey(a);
    CHECK(memcmp(a, b, 32) != 0);
    pc_rekey(b);
    CHECK(memcmp(a, b, 32) == 0);
}

static void test_varint_and_bufs(void)
{
    uint8_t buf[64];
    pc_wbuf w;
    pc_wbuf_init(&w, buf, sizeof(buf));
    uint64_t vals[] = {0, 63, 64, 16383, 16384, 1073741823, 1073741824, ((uint64_t)1 << 62) - 1};
    for (size_t i = 0; i < PC_ARRAY_LEN(vals); i++) pc_w_varint(&w, vals[i]);
    CHECK(!w.err);
    pc_rbuf r;
    pc_rbuf_init(&r, buf, w.len);
    for (size_t i = 0; i < PC_ARRAY_LEN(vals); i++) CHECK(pc_r_varint(&r) == vals[i]);
    CHECK(!r.err && pc_rbuf_left(&r) == 0);
    pc_r_u8(&r);
    CHECK(r.err);

    pc_wbuf_init(&w, buf, 3);
    pc_w_u32(&w, 1);
    CHECK(w.err);
}

static void test_addr_parse_format(void)
{
    pierce_addr a;
    char s[64];
    CHECK(pierce_addr_parse("192.168.1.20:3478", &a) == 0);
    CHECK_EQ(a.family, PIERCE_AF_INET);
    CHECK_EQ(a.port, 3478);
    CHECK(pierce_addr_format(&a, s, sizeof(s)) > 0 && strcmp(s, "192.168.1.20:3478") == 0);
    CHECK(pierce_addr_parse("[2001:db8::1]:443", &a) == 0);
    CHECK_EQ(a.family, PIERCE_AF_INET6);
    CHECK(a.addr[0] == 0x20 && a.addr[1] == 0x01 && a.addr[15] == 1);
    CHECK(pierce_addr_format(&a, s, sizeof(s)) > 0 && strcmp(s, "[2001:db8::1]:443") == 0);
    CHECK(pierce_addr_parse("[::1]:1", &a) == 0 && a.addr[15] == 1);
    CHECK(pierce_addr_format(&a, s, sizeof(s)) > 0 && strcmp(s, "[::1]:1") == 0);
    CHECK(pierce_addr_parse("[::ffff:1.2.3.4]:9", &a) == 0 && a.addr[10] == 0xff && a.addr[15] == 4);
    CHECK(pierce_addr_parse("[fe80::1%3]:9", &a) == 0 && a.scope_id == 3);
    CHECK(pierce_addr_parse("1.2.3:4", &a) < 0);
    CHECK(pierce_addr_parse("1.2.3.4", &a) < 0);
    CHECK(pierce_addr_parse("1.2.3.4:70000", &a) < 0);
    CHECK(pierce_addr_parse("[1:2:3:4:5:6:7:8:9]:1", &a) < 0);
    CHECK(pierce_addr_parse("example.com:80", &a) < 0);
}

int main(void)
{
    RUN(test_rfc8439_exact);
    RUN(test_aead_round_trip);
    RUN(test_hmac_blake2b);
    RUN(test_noise_vectors);
    RUN(test_noise_ik_wrong_key_fails);
    RUN(test_noise_low_order_rejected);
    RUN(test_rekey);
    RUN(test_varint_and_bufs);
    RUN(test_addr_parse_format);
    TEST_MAIN_END();
}
