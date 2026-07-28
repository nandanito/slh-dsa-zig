/*
 * PQClean `clean` SLH-DSA timing harness.
 *
 * Produces the reference side of the project's 2x performance gate
 * (CLAUDE.md discipline table; bench/README.md). Deliberately mirrors
 * bench/bench.zig's methodology so the two sides are comparable:
 *
 *   - Monotonic clock sampled immediately around the operation under test.
 *   - Median of N per-iteration samples is the headline; mean/min/max also
 *     reported. Median index is samples[N/2] on the ascending sort, matching
 *     bench.zig::computeStats.
 *   - Fixed 64-byte message of 0x42.
 *   - keygen draws fresh key material from the real CSPRNG each iteration.
 *   - sign/verify reuse one deterministic keypair, derived from the same
 *     seed bytes bench.zig uses, so both sides sign under the same key.
 *   - Results are folded into a volatile sink so nothing can be elided.
 *
 * One methodology difference is unavoidable and is reported rather than
 * papered over: PQClean's crypto_sign_signature draws its `optrand`
 * randomiser *inside* the call (sign.c), so its sign timing includes one
 * n-byte CSPRNG draw. bench.zig hoists that draw out of the timed loop.
 * The `randombytes` op below measures that draw so the reader can confirm
 * it is negligible against a signing operation.
 *
 * Built per parameter set by run.sh, which passes the PQClean symbol prefix:
 *
 *   cc -O3 -DPQC_PREFIX=PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_ ...
 *
 * Output is CSV on stdout: impl,param_set,op,iters,median_ns,mean_ns,min_ns,max_ns
 *
 * Lane: Lane A (bench infrastructure). Not part of the Zig build graph.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "api.h"
#include "randombytes.h"

/* Two-level indirection so PQC_PREFIX expands before the ## paste. */
#define XCAT(a, b) a##b
#define CAT(a, b) XCAT(a, b)
#define F(sym) CAT(PQC_PREFIX, sym)

#define SK_BYTES   F(CRYPTO_SECRETKEYBYTES)
#define PK_BYTES   F(CRYPTO_PUBLICKEYBYTES)
#define SIG_BYTES  F(CRYPTO_BYTES)
#define SEED_BYTES F(CRYPTO_SEEDBYTES)

/* PQClean's seed for crypto_sign_seed_keypair is [SK_SEED || SK_PRF || PUB_SEED]. */
#define N_BYTES (SEED_BYTES / 3)

#define MSG_LEN 64

/* Sink: keeps every result observable so no operation can be elided. The
 * PQClean routines live in a separately compiled archive (no LTO), so this
 * is belt-and-braces rather than load-bearing -- except in verify, where the
 * return value is folded in *before* the clock stops, matching bench.zig. */
static volatile uint8_t sink = 0;

static void keep(const void *p, size_t len) {
    const uint8_t *b = (const uint8_t *)p;
    uint8_t acc = 0;
    for (size_t i = 0; i < len; i++) {
        acc = (uint8_t)(acc ^ b[i]);
    }
    sink = (uint8_t)(sink ^ acc);
}

static uint64_t now_ns(void) {
    struct timespec ts;
    /* CLOCK_MONOTONIC_RAW: monotonic, not slewed by NTP. Nanosecond
     * resolution on Darwin and Linux. */
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static void report(const char *param_set, const char *op, uint64_t *ns, size_t iters) {
    qsort(ns, iters, sizeof(uint64_t), cmp_u64);

    /* Sum in the widest integer available; iters is small so u64 cannot
     * plausibly overflow, but be explicit. */
    unsigned long long sum = 0;
    for (size_t i = 0; i < iters; i++) {
        sum += (unsigned long long)ns[i];
    }

    printf("pqclean-clean,%s,%s,%zu,%llu,%llu,%llu,%llu\n",
           param_set,
           op,
           iters,
           (unsigned long long)ns[iters / 2],
           sum / (unsigned long long)iters,
           (unsigned long long)ns[0],
           (unsigned long long)ns[iters - 1]);
    fflush(stdout);
}

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr,
                "usage: %s <param-set-label> <keygen-iters> <sign-iters> <verify-iters>\n",
                argv[0]);
        return 2;
    }

    const char *label = argv[1];
    const size_t keygen_iters = (size_t)strtoul(argv[2], NULL, 10);
    const size_t sign_iters = (size_t)strtoul(argv[3], NULL, 10);
    const size_t verify_iters = (size_t)strtoul(argv[4], NULL, 10);

    const size_t max_iters =
        keygen_iters > sign_iters
            ? (keygen_iters > verify_iters ? keygen_iters : verify_iters)
            : (sign_iters > verify_iters ? sign_iters : verify_iters);
    if (max_iters == 0) {
        fprintf(stderr, "error: all iteration counts are zero\n");
        return 2;
    }

    uint64_t *ns = (uint64_t *)malloc(max_iters * sizeof(uint64_t));
    uint8_t *sig = (uint8_t *)malloc(SIG_BYTES);
    if (ns == NULL || sig == NULL) {
        fprintf(stderr, "error: out of memory\n");
        free(ns);
        free(sig);
        return 1;
    }

    uint8_t pk[PK_BYTES];
    uint8_t sk[SK_BYTES];

    uint8_t msg[MSG_LEN];
    memset(msg, 0x42, sizeof(msg));

    /* ---- keygen: fresh CSPRNG key material each iteration ---- */
    if (keygen_iters > 0) {
        for (size_t i = 0; i < keygen_iters; i++) {
            const uint64_t start = now_ns();
            (void)F(crypto_sign_keypair)(pk, sk);
            const uint64_t end = now_ns();
            keep(pk, PK_BYTES);
            ns[i] = end - start;
        }
        report(label, "keygen", ns, keygen_iters);
    }

    /* ---- deterministic keypair shared by sign and verify ----
     * Same seed bytes as bench.zig, so both implementations exercise the
     * same key. Key choice does not affect timing, but matching removes a
     * free variable from the comparison. */
    uint8_t seed[SEED_BYTES];
    for (size_t i = 0; i < N_BYTES; i++) {
        seed[i] = (uint8_t)(0x11 + i);               /* SK_SEED  */
        seed[N_BYTES + i] = (uint8_t)(0x55 + i);     /* SK_PRF   */
        seed[2 * N_BYTES + i] = (uint8_t)(0x99 + i); /* PUB_SEED */
    }
    if (F(crypto_sign_seed_keypair)(pk, sk, seed) != 0) {
        fprintf(stderr, "error: seed_keypair failed\n");
        free(ns);
        free(sig);
        return 1;
    }

    size_t siglen = 0;

    /* ---- sign ---- */
    if (sign_iters > 0) {
        for (size_t i = 0; i < sign_iters; i++) {
            const uint64_t start = now_ns();
            (void)F(crypto_sign_signature)(sig, &siglen, msg, MSG_LEN, sk);
            const uint64_t end = now_ns();
            keep(sig, siglen);
            ns[i] = end - start;
        }
        report(label, "sign", ns, sign_iters);
    }

    /* ---- verify ---- */
    if (verify_iters > 0) {
        if (F(crypto_sign_signature)(sig, &siglen, msg, MSG_LEN, sk) != 0) {
            fprintf(stderr, "error: signature generation failed\n");
            free(ns);
            free(sig);
            return 1;
        }
        for (size_t i = 0; i < verify_iters; i++) {
            const uint64_t start = now_ns();
            const int rc = F(crypto_sign_verify)(sig, siglen, msg, MSG_LEN, pk);
            /* Fold the result in before stopping the clock, so the verifier
             * cannot drift outside the timed region (bench.zig does the same). */
            sink = (uint8_t)(sink ^ (uint8_t)(rc == 0));
            const uint64_t end = now_ns();
            ns[i] = end - start;
        }
        report(label, "verify", ns, verify_iters);
    }

    /* ---- randombytes probe ----
     * Quantifies the one methodology difference described in the file header:
     * PQClean's sign draws n bytes of `optrand` inside the timed call. */
    {
        const size_t probe_iters = 200;
        uint8_t probe[64];
        for (size_t i = 0; i < probe_iters; i++) {
            const uint64_t start = now_ns();
            randombytes(probe, N_BYTES);
            const uint64_t end = now_ns();
            keep(probe, N_BYTES);
            ns[i % max_iters] = end - start;
        }
        const size_t n = probe_iters < max_iters ? probe_iters : max_iters;
        report(label, "randombytes", ns, n);
    }

    free(ns);
    free(sig);
    return (int)sink & 0; /* always 0; keeps `sink` live to the very end */
}
