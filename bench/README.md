# Benchmarks

Performance harness for slh-dsa-zig. Measures keygen / sign / verify for
each of the 12 parameter sets and reports median nanoseconds per operation
plus the derived ops/second.

## Running

```sh
zig build bench                                  # all ops, all parameter sets
zig build bench -- --op sign                     # only signing
zig build bench -- --param-set SLH-DSA-SHAKE-128s
zig build bench -- --op verify --iters 1000
zig build bench -- --csv                         # machine-readable
```

The human-readable table goes to stderr; `--csv` writes
`impl,param_set,op,iters,median_ns,mean_ns,min_ns,max_ns` rows to stdout, so
a run can be piped straight into the comparison tooling below. The PQClean
reference harness emits the same schema and the same parameter-set spelling,
so the two join on `(param_set, op)`.

The bench binary is always built in `ReleaseFast` unless you override it —
Debug-mode numbers are meaningless:

```sh
zig build bench -Dbench-optimize=ReleaseSafe
```

The printed header records the optimize mode actually used, so a pasted
result is self-describing.

## Methodology

- Each measurement times `N` iterations with `std.Io.Clock.awake` (a
  monotonic clock) sampled immediately around the operation under test.
- The reported `median` is the headline number; `mean` is shown for
  reference but is sensitive to outliers (page faults, scheduler jitter).
- **Iteration budgets are speed-class aware.** The "small-signature" (`s`)
  parameter sets sign ~20–100× slower than their "fast" (`f`) siblings, so a
  uniform budget would make a no-arg run take minutes. Defaults:

  | class | keygen | sign | verify |
  |-------|:------:|:----:|:------:|
  | `f`   |   50   |  50  |  500   |
  | `s`   |   20   |   5  |  500   |

  A no-arg `zig build bench` (all ops × all 12 sets) completes in tens of
  seconds. For a tighter median on one set, pass a larger `--iters`.
- **keygen** draws fresh key material from the real CSPRNG each iteration —
  the cost a caller actually pays. **sign** and **verify** reuse a single
  deterministic keypair (`KeyPair.fromSeeds`, no entropy needed) and a fixed
  message, so they measure steady-state cost, not first-touch effects. Sign
  uses a fixed per-signature randomiser, so it reflects the randomised
  (default) signing path without charging RNG cost to the timed loop.
- Every result is kept live with `std.mem.doNotOptimizeAway` so the
  optimiser cannot DCE the operation.

## The 2× performance gate

The project's discipline (CLAUDE.md, README "Cryptographic discipline"
item 6) targets **within 2× of PQClean's C reference on equivalent
hardware**. PQClean ships two implementations per parameter set and the gate
must name which one, or it gets relitigated at measurement time (issue #10):

- **`clean`** — portable C, no intrinsics. **This is the gated baseline.**
  SLH-DSA throughput is dominated by the SHA-256 / SHAKE-256 cores, and
  Zig's stdlib implementations are competitive with portable C, so 2× is a
  realistic, honest target.
- **`avx2`** — hand-vectorised Keccak / SHA-NI paths. Beating a pure-Zig
  implementation against this without our own vectorised cores is not
  realistic today. **We report AVX2 numbers alongside for honesty, but never
  gate on them.**

### Reproducing a comparison

The comparison is scripted, in `bench/pqclean/`:

```sh
./bench/pqclean/compare.sh > results.csv     # both sides, interleaved
./bench/pqclean/table.sh < results.csv       # markdown table + gate check
```

`compare.sh` clones PQClean at a pinned commit, builds the `clean` variant of
each parameter set with PQClean's own `-O3` Makefile, and runs a C harness
(`harness.c`) that mirrors `bench.zig`'s methodology line for line — same
monotonic clock placement, same median-of-N, same 64-byte message, same
deterministic keypair seeds, same iteration budgets.

`table.sh` is the gate check, not only a formatter:

| exit | meaning |
|---|---|
| 0 | a complete result set, every measurement within the gate |
| 1 | at least one measurement exceeded the gate |
| 2 | the input could not be gated — see below |

Exit 2 covers the failures that would otherwise *look* like a pass: a CSV
with no comparable pairs, a `(param_set, op)` carrying one side's row but not
the other, or fewer measurements than expected. That last one matters more
than it sounds — a sweep interrupted at a parameter-set boundary leaves every
surviving pair perfectly intact, so pair-level validation alone would print a
few green rows and exit 0. `table.sh` therefore requires all 36 measurements
(12 sets × 3 ops) by default. Gate a deliberate subset by saying so:

```sh
EXPECT=3 ./bench/pqclean/table.sh < one-param-set.csv
GATE=1.5 ./bench/pqclean/table.sh < results.csv     # tighter than the project gate
```

Two design points worth knowing:

- **The two sides are interleaved per parameter set** — zig, then PQClean,
  then the next set. Running one implementation to completion and then the
  other would measure the second on a machine the first had already heated,
  and on a laptop that difference is larger than several of the ratios being
  reported.
- **These scripts are not part of the Zig build graph.** `zig build` never
  invokes them and the repo needs no C toolchain; they exist only to
  reproduce a published number.

When publishing, record all four so it is reproducible: the PQClean commit,
the PQClean build settings, the Zig version and optimize mode, and the
machine. `compare.sh` and `run.sh` print all of these to stderr.

## Results

Measured 2026-07-28. **The gate passes on this machine: all 36 measurements
are at or below 1.15×, against a limit of 2×.**

| | |
|---|---|
| PQClean commit | `202a8f96315f9ed219387a50f7e40d04af037ea8` |
| PQClean build | `clean` variant, `-O3`, Apple clang 21.0.0 |
| Zig | 0.16.0, `ReleaseFast`, native target |
| Machine | Apple M3 Pro (6P + 6E), macOS 26.5 (Darwin 25.5.0), arm64 |
| Frequency scaling | not pinned — laptop, on AC power, otherwise idle |
| Iteration budgets | `f` sets 100/100/1000, `s` sets 30/20/1000 (keygen/sign/verify) |

Ratio is Zig ÷ PQClean, so **lower is better** and the gate is ≤ 2.00×.

| param set | op | iters | slh-dsa-zig | PQClean `clean` | ratio | gate |
|---|---|---:|---:|---:|---:|:---:|
| SLH-DSA-SHA2-128s | keygen | 30 | 13.95 ms | 53.56 ms | 0.26× | pass |
| SLH-DSA-SHA2-128s | sign | 20 | 109.51 ms | 403.33 ms | 0.27× | pass |
| SLH-DSA-SHA2-128s | verify | 1000 | 94.50 µs | 378.33 µs | 0.25× | pass |
| SLH-DSA-SHA2-128f | keygen | 100 | 245.08 µs | 857.71 µs | 0.29× | pass |
| SLH-DSA-SHA2-128f | sign | 100 | 5.27 ms | 19.41 ms | 0.27× | pass |
| SLH-DSA-SHA2-128f | verify | 1000 | 313.96 µs | 1.09 ms | 0.29× | pass |
| SLH-DSA-SHA2-192s | keygen | 30 | 24.46 ms | 75.54 ms | 0.32× | pass |
| SLH-DSA-SHA2-192s | sign | 20 | 335.68 ms | 708.14 ms | 0.47× | pass |
| SLH-DSA-SHA2-192s | verify | 1000 | 314.25 µs | 575.46 µs | 0.55× | pass |
| SLH-DSA-SHA2-192f | keygen | 100 | 384.04 µs | 1.22 ms | 0.32× | pass |
| SLH-DSA-SHA2-192f | sign | 100 | 13.35 ms | 31.02 ms | 0.43× | pass |
| SLH-DSA-SHA2-192f | verify | 1000 | 647.96 µs | 1.65 ms | 0.39× | pass |
| SLH-DSA-SHA2-256s | keygen | 30 | 13.63 ms | 49.94 ms | 0.27× | pass |
| SLH-DSA-SHA2-256s | sign | 20 | 336.99 ms | 606.07 ms | 0.56× | pass |
| SLH-DSA-SHA2-256s | verify | 1000 | 397.29 µs | 866.08 µs | 0.46× | pass |
| SLH-DSA-SHA2-256f | keygen | 100 | 880.79 µs | 3.18 ms | 0.28× | pass |
| SLH-DSA-SHA2-256f | sign | 100 | 25.95 ms | 64.93 ms | 0.40× | pass |
| SLH-DSA-SHA2-256f | verify | 1000 | 661.88 µs | 1.71 ms | 0.39× | pass |
| SLH-DSA-SHAKE-128s | keygen | 30 | 48.06 ms | 53.54 ms | 0.90× | pass |
| SLH-DSA-SHAKE-128s | sign | 20 | 368.35 ms | 394.53 ms | 0.93× | pass |
| SLH-DSA-SHAKE-128s | verify | 1000 | 358.00 µs | 371.71 µs | 0.96× | pass |
| SLH-DSA-SHAKE-128f | keygen | 100 | 760.54 µs | 833.50 µs | 0.91× | pass |
| SLH-DSA-SHAKE-128f | sign | 100 | 18.68 ms | 19.57 ms | 0.95× | pass |
| SLH-DSA-SHAKE-128f | verify | 1000 | 1.05 ms | 1.12 ms | 0.94× | pass |
| SLH-DSA-SHAKE-192s | keygen | 30 | 70.64 ms | 76.27 ms | 0.93× | pass |
| SLH-DSA-SHAKE-192s | sign | 20 | 697.45 ms | 709.26 ms | 0.98× | pass |
| SLH-DSA-SHAKE-192s | verify | 1000 | 539.42 µs | 605.08 µs | 0.89× | pass |
| SLH-DSA-SHAKE-192f | keygen | 100 | 1.14 ms | 1.24 ms | 0.92× | pass |
| SLH-DSA-SHAKE-192f | sign | 100 | 37.31 ms | 34.24 ms | 1.09× | pass |
| SLH-DSA-SHAKE-192f | verify | 1000 | 1.63 ms | 1.78 ms | 0.91× | pass |
| SLH-DSA-SHAKE-256s | keygen | 30 | 48.91 ms | 55.05 ms | 0.89× | pass |
| SLH-DSA-SHAKE-256s | sign | 20 | 743.10 ms | 648.44 ms | 1.15× | pass |
| SLH-DSA-SHAKE-256s | verify | 1000 | 904.83 µs | 849.88 µs | 1.06× | pass |
| SLH-DSA-SHAKE-256f | keygen | 100 | 3.01 ms | 3.24 ms | 0.93× | pass |
| SLH-DSA-SHAKE-256f | sign | 100 | 61.33 ms | 65.99 ms | 0.93× | pass |
| SLH-DSA-SHAKE-256f | verify | 1000 | 1.67 ms | 1.77 ms | 0.94× | pass |

Worst ratio: **1.15×** (SLH-DSA-SHAKE-256s sign).

### Reading these numbers honestly

The two hash families tell completely different stories, and the headline
"comfortably inside 2×" is only true for one of them on its own merits.

**SHAKE sets (0.89×–1.15×) are the real apples-to-apples result.** Neither
side has a vectorised or hardware Keccak — Zig's `std.crypto` Keccak-p is
portable Zig, PQClean's `fips202.c` is portable C. Parity here is a genuine
statement about the implementation.

**SHA-2 sets (0.25×–0.56×) are flattered by hardware.** Zig's
`std.crypto.hash.sha2` takes an ARMv8 crypto-extension path on this CPU
(`sha256h` and friends, `std/crypto/sha2.zig`), while PQClean `clean` is
portable C by definition. That 2–4× win is the M3's SHA-256 unit, not
better code.

Disabling the extensions (`zig build bench -Dcpu=apple_m3-sha2`) isolates the
algorithmic comparison, and it inverts:

| param set | op | zig (portable) | PQClean `clean` | ratio |
|---|---|---:|---:|---:|
| SLH-DSA-SHA2-128s | keygen | 103.77 ms | 50.82 ms | 2.04× |
| SLH-DSA-SHA2-128s | sign | 769.60 ms | 381.08 ms | 2.02× |
| SLH-DSA-SHA2-128s | verify | 726.38 µs | 383.88 µs | 1.89× |
| SLH-DSA-SHA2-128f | keygen | 1.61 ms | 885.58 µs | 1.82× |
| SLH-DSA-SHA2-128f | sign | 36.80 ms | 18.08 ms | 2.04× |
| SLH-DSA-SHA2-128f | verify | 2.19 ms | 1.03 ms | 2.13× |
| SLH-DSA-SHA2-192s | keygen | 148.66 ms | 72.10 ms | 2.06× |
| SLH-DSA-SHA2-192s | sign | 1385.53 ms | 677.97 ms | 2.04× |
| SLH-DSA-SHA2-192s | verify | 1.10 ms | 551.33 µs | 1.99× |
| SLH-DSA-SHA2-192f | keygen | 2.32 ms | 1.20 ms | 1.93× |
| SLH-DSA-SHA2-192f | sign | 60.69 ms | 30.61 ms | 1.98× |
| SLH-DSA-SHA2-192f | verify | 3.25 ms | 1.69 ms | 1.92× |
| SLH-DSA-SHA2-256s | keygen | 103.10 ms | 48.07 ms | 2.14× |
| SLH-DSA-SHA2-256s | sign | 1218.13 ms | 594.06 ms | 2.05× |
| SLH-DSA-SHA2-256s | verify | 1.60 ms | 821.96 µs | 1.95× |
| SLH-DSA-SHA2-256f | keygen | 6.08 ms | 3.07 ms | 1.98× |
| SLH-DSA-SHA2-256f | sign | 125.48 ms | 62.37 ms | 2.01× |
| SLH-DSA-SHA2-256f | verify | 3.27 ms | 1.77 ms | 1.85× |

So Zig's *portable* SHA-256 is roughly half the speed of PQClean's portable
C SHA-256, and on hardware without SHA-2 acceleration the SHA-2 parameter
sets would sit exactly on the gate boundary — eight of these eighteen
measurements are over 2.00×. **The gate passes as measured, on the machine
and target it was measured on; it is not a claim that it passes everywhere.**
This is a `std.crypto` property rather than something this library controls,
but it is the honest caveat on the headline number, and it is the reason to
re-measure on x86-64 before treating the gate as settled. Tracked as
[issue #40](https://github.com/nandanito/slh-dsa-zig/issues/40).

### Caveats on this run

- **No AVX2 column.** The gate never depended on it, but the policy above
  promises AVX2 numbers "alongside, for honesty" and this run cannot provide
  them: PQClean's `avx2` variants are x86-64 only and the measuring machine
  is arm64. Anyone reproducing on x86-64 should report them.
- **PQClean's sign includes its own randomiser draw.** `crypto_sign_signature`
  calls `randombytes(optrand, n)` inside the timed call; `bench.zig` hoists
  that draw out of the loop. The harness measures the draw so it can be
  sized: **208 ns**, against signing operations of 5–740 ms. That is at most
  0.004% and does not move any ratio in the third decimal place.
- **PQClean implements SPHINCS+ v3.1, not FIPS 205.** The two differ in
  message-randomiser domain separation, not in structure: identical `h`, `d`,
  `a`, `k`, `w`, and identical hash-call counts. The comparison is valid for
  performance; it is not a conformance statement, and PQClean is never used
  as a correctness oracle here (that is what the ACVP vectors are for).
- **Frequency scaling is not pinned.** Interleaving the two sides bounds the
  damage, and medians over 20–1000 iterations absorb the rest, but these are
  laptop numbers. Treat the third significant figure as noise.

## Comparison points

SLH-DSA is intentionally not fast: it is the conservative,
hash-only-assumptions sibling of ML-DSA. These benchmarks exist to catch
regressions inside this library and to check the 2× gate — not to advertise
speed. Other useful external references for sanity-checking absolute numbers:

- **liboqs** — <https://github.com/open-quantum-safe/liboqs> — published
  per-platform benchmark tables.
- **NIST round-3 submission** — the original SPHINCS+ team's reference
  numbers (now superseded but useful for relative ordering between
  parameter sets).
