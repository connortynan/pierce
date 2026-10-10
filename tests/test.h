/* Minimal test harness: each test file is its own executable. */
#ifndef PIERCE_TEST_H
#define PIERCE_TEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int test_failures;
static int test_checks;

#define CHECK(cond)                                                              \
    do {                                                                         \
        test_checks++;                                                           \
        if (!(cond)) {                                                           \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
            test_failures++;                                                     \
        }                                                                        \
    } while (0)

#define CHECK_EQ(a, b)                                                           \
    do {                                                                         \
        long long va_ = (long long)(a), vb_ = (long long)(b);                    \
        test_checks++;                                                           \
        if (va_ != vb_) {                                                        \
            fprintf(stderr, "%s:%d: CHECK_EQ failed: %s == %s (%lld vs %lld)\n", \
                    __FILE__, __LINE__, #a, #b, va_, vb_);                       \
            test_failures++;                                                     \
        }                                                                        \
    } while (0)

#define REQUIRE(cond)                                                            \
    do {                                                                         \
        test_checks++;                                                           \
        if (!(cond)) {                                                           \
            fprintf(stderr, "%s:%d: REQUIRE failed: %s\n", __FILE__, __LINE__, #cond); \
            test_failures++;                                                     \
            return;                                                              \
        }                                                                        \
    } while (0)

#define RUN(fn)                                                                  \
    do {                                                                         \
        int before_ = test_failures;                                             \
        fn();                                                                    \
        fprintf(stderr, "%s %s\n", test_failures == before_ ? "  ok  " : " FAIL ", #fn); \
    } while (0)

#define TEST_MAIN_END()                                                          \
    do {                                                                         \
        fprintf(stderr, "%d checks, %d failures\n", test_checks, test_failures); \
        return test_failures ? 1 : 0;                                            \
    } while (0)

static size_t hex_decode(const char *hex, unsigned char *out, size_t cap)
{
    size_t n = strlen(hex) / 2;
    if (n > cap) { fprintf(stderr, "hex_decode: buffer too small\n"); abort(); }
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (unsigned char)v;
    }
    return n;
}

#endif
