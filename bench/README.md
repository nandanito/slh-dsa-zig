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
item 6) targets **within 2× of PQClean's portable `clean` C reference, both
sides built without hardware hash acceleration**.

That wording is deliberate, and it is narrower than the "equivalent hardware"
it replaced (issue #40). Two decisions are baked into it.

**The gate is measured portable-against-portable.** PQClean `clean` is portable
C by definition — it cannot use SHA-NI or ARMv8 crypto extensions. Comparing a
hardware-accelerated Zig build against it is apples-to-oranges: it measures the
CPU's hash unit, not this library's code. Worse, it is a gate that *cannot fail
for the right reason* — the SLH-DSA machinery around the hash (tree traversal,
WOTS chains, address handling) could regress badly and the hardware speedup
would hide it. The accelerated numbers are published because they are what
users actually get; they are not what the gate is checked against.

**The baseline target is named, not argued about later.** On x86-64 the gate is
measured at `-Dcpu=x86_64_v3` — AVX2 present, SHA-NI absent — which is the same
CPU baseline the ctgrind workflow pins (issue #6). "Equivalent hardware" was
unfalsifiable; a named target is reproducible.

PQClean ships two implementations per parameter set and the gate must name
which one, or it gets relitigated at measurement time (issue #10):

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

### The x86-64 leg

The gated numbers below come from `.github/workflows/bench.yml` — manually
triggered, never gating a PR, because a shared runner is too noisy to fail a
build on. It exists because the original arm64 run measured the SHA-2 sets with
ARMv8 crypto extensions on, which made the CPU rather than the code responsible
for that half of the result (issue #40).

It measures three things:

| leg | build | role |
|---|---|---|
| portable | `-Dcpu=x86_64_v3` (AVX2, no SHA-NI) | like-for-like against portable C |
| accelerated | `-Dcpu=x86_64_v3+sha` | what the hardware path buys |
| `avx2` | `PQCLEAN_VARIANT=avx2` | reported alongside, never gated |

`x86_64_v3` rather than the runner's native CPU: native varies between runners,
which would make consecutive runs incomparable, and it matches the baseline the
ctgrind workflow pins (issue #6).

Zig's SHA-2 dispatch is a **comptime** check on the target features, not a
runtime probe — `std/crypto/sha2.zig` takes its x86-64 SHA-NI path only when the
target has both `sha` and `avx2`. So the two Zig legs genuinely compile
different code, and a binary built for a baseline target will not opportunistically
use SHA-NI on a CPU that has it.

Two knobs exist for this:

```sh
PQCLEAN_VARIANT=avx2 ./bench/pqclean/run.sh          # x86-64 only; errors elsewhere
PORTABLE_NOTE="SHA-NI disabled" ./bench/pqclean/table.sh < results.csv
```

`PORTABLE_NOTE` captions the supplementary table. It exists because the caption
names what was disabled to produce the portable build, that differs by target,
and the caption is quoted into this file verbatim — a table headed "ARMv8 crypto
extensions disabled" on an x86-64 run would be worse than a vague one.

## Results

Two published runs. The **x86-64 run is the gated one**, because it is the only
one that measures both sides without hardware hash acceleration. The arm64 run
is kept for the accelerated numbers and because it is what surfaced the problem.

**Headline: 35 of 36 gated measurements are within 2×. One exceeds it —
`SLH-DSA-SHA2-256s keygen` at 2.06×** — and the SHAKE control below establishes
that the excess is `std.crypto`'s SHA-256, not this library's SLH-DSA code.

### x86-64 — the gated run

Measured 2026-07-30 by `.github/workflows/bench.yml`
([run 30443828338](https://github.com/nandanito/slh-dsa-zig/actions/runs/30443828338)).

| | |
|---|---|
| PQClean commit | `202a8f96315f9ed219387a50f7e40d04af037ea8` |
| PQClean build | `clean` variant, `-O3`, gcc 13.3.0 (Ubuntu 24.04) |
| Zig | 0.16.0, `ReleaseFast`, **`-Dcpu=x86_64_v3`** (AVX2, no SHA-NI) |
| Machine | AMD EPYC 9V74, Linux 6.17 (Azure), x86-64 — `sha_ni` present but not compiled in |
| Frequency scaling | not pinned — shared CI runner |
| Iteration budgets | `f` sets 100/100/1000, `s` sets 30/20/1000 (keygen/sign/verify) |

Ratio is Zig ÷ PQClean, **lower is better**, gate is ≤ 2.00×.

| param set | op | zig (portable) | PQClean `clean` | ratio | gate |
|---|---|---:|---:|---:|:---:|
| SLH-DSA-SHA2-128s | keygen | 163.68 ms | 94.84 ms | 1.73× | pass |
| SLH-DSA-SHA2-128s | sign | 1247.76 ms | 720.25 ms | 1.73× | pass |
| SLH-DSA-SHA2-128s | verify | 1.13 ms | 637.48 µs | 1.77× | pass |
| SLH-DSA-SHA2-128f | keygen | 2.56 ms | 1.44 ms | 1.78× | pass |
| SLH-DSA-SHA2-128f | sign | 59.91 ms | 33.65 ms | 1.78× | pass |
| SLH-DSA-SHA2-128f | verify | 3.51 ms | 2.03 ms | 1.73× | pass |
| SLH-DSA-SHA2-192s | keygen | 238.46 ms | 121.63 ms | 1.96× | pass |
| SLH-DSA-SHA2-192s | sign | 2215.37 ms | 1167.22 ms | 1.90× | pass |
| SLH-DSA-SHA2-192s | verify | 1.76 ms | 972.34 µs | 1.81× | pass |
| SLH-DSA-SHA2-192f | keygen | 3.73 ms | 1.89 ms | 1.97× | pass |
| SLH-DSA-SHA2-192f | sign | 97.36 ms | 51.24 ms | 1.90× | pass |
| SLH-DSA-SHA2-192f | verify | 5.17 ms | 2.72 ms | 1.90× | pass |
| SLH-DSA-SHA2-256s | keygen | 161.72 ms | 78.61 ms | **2.06×** | **FAIL** |
| SLH-DSA-SHA2-256s | sign | 1881.36 ms | 1026.87 ms | 1.83× | pass |
| SLH-DSA-SHA2-256s | verify | 2.52 ms | 1.44 ms | 1.75× | pass |
| SLH-DSA-SHA2-256f | keygen | 9.73 ms | 4.89 ms | 1.99× | pass |
| SLH-DSA-SHA2-256f | sign | 195.25 ms | 102.83 ms | 1.90× | pass |
| SLH-DSA-SHA2-256f | verify | 5.14 ms | 2.76 ms | 1.87× | pass |
| SLH-DSA-SHAKE-128s | keygen | 143.46 ms | 147.79 ms | 0.97× | pass |
| SLH-DSA-SHAKE-128s | sign | 1087.25 ms | 1132.06 ms | 0.96× | pass |
| SLH-DSA-SHAKE-128s | verify | 1.01 ms | 1.16 ms | 0.87× | pass |
| SLH-DSA-SHAKE-128f | keygen | 2.25 ms | 2.32 ms | 0.97× | pass |
| SLH-DSA-SHAKE-128f | sign | 52.07 ms | 54.09 ms | 0.96× | pass |
| SLH-DSA-SHAKE-128f | verify | 3.05 ms | 3.28 ms | 0.93× | pass |
| SLH-DSA-SHAKE-192s | keygen | 209.95 ms | 215.35 ms | 0.97× | pass |
| SLH-DSA-SHAKE-192s | sign | 1856.31 ms | 1942.39 ms | 0.96× | pass |
| SLH-DSA-SHAKE-192s | verify | 1.52 ms | 1.59 ms | 0.96× | pass |
| SLH-DSA-SHAKE-192f | keygen | 3.27 ms | 3.37 ms | 0.97× | pass |
| SLH-DSA-SHAKE-192f | sign | 84.33 ms | 87.22 ms | 0.97× | pass |
| SLH-DSA-SHAKE-192f | verify | 4.55 ms | 4.67 ms | 0.97× | pass |
| SLH-DSA-SHAKE-256s | keygen | 139.21 ms | 143.76 ms | 0.97× | pass |
| SLH-DSA-SHAKE-256s | sign | 1624.13 ms | 1707.74 ms | 0.95× | pass |
| SLH-DSA-SHAKE-256s | verify | 2.19 ms | 2.28 ms | 0.96× | pass |
| SLH-DSA-SHAKE-256f | keygen | 8.66 ms | 8.88 ms | 0.98× | pass |
| SLH-DSA-SHAKE-256f | sign | 172.47 ms | 178.58 ms | 0.97× | pass |
| SLH-DSA-SHAKE-256f | verify | 4.60 ms | 4.78 ms | 0.96× | pass |

Worst ratio: **2.06×** (`SLH-DSA-SHA2-256s keygen`). SHA-2 mean 1.85×, SHAKE
mean 0.96×.

#### Alongside: the same machine with SHA-NI compiled in

Not the gate. This is what a default `-Dcpu=native` build produces on this CPU,
and it is included because it is what users actually run.

| family | ratio range | over 2× |
|---|---|---:|
| SHA-2 (`-Dcpu=x86_64_v3+sha`) | 0.33×–0.63× | 0 / 18 |
| SHAKE (unchanged — no hardware path) | 0.87×–1.00× | 0 / 18 |

All 36 pass, worst 1.00×. The SHA-2 sets come out **2–3× faster than PQClean
`clean`**, which is a statement about the EPYC's SHA-256 unit against portable
C, not about the code.

Zig's dispatch here is a **comptime** check, not a runtime probe:
`std/crypto/sha2.zig` takes its x86-64 SHA-NI path only when the target has
both `sha` and `avx2`. A binary built for a baseline target will therefore
*not* opportunistically use SHA-NI on a CPU that has it — worth knowing if you
ship prebuilt artifacts.

#### Alongside: PQClean `avx2`

Reported for honesty, never gated — the arm64 run could not provide these at
all. PQClean's vectorised variant is **2.3×–4.3× faster than its own `clean`**
(mean 3.2×). Gating against it would be a materially different bar, which is
exactly why the gate is pinned to `clean`.

### arm64 — Apple M3 Pro

Measured 2026-07-28, and the run that surfaced the problem. Its headline —
"all 36 at or below 1.15×" — was measured with ARMv8 crypto extensions **on**,
so by the gate definition above it is an accelerated run, not a gated one.

| | |
|---|---|
| PQClean commit | `202a8f96315f9ed219387a50f7e40d04af037ea8` |
| PQClean build | `clean` variant, `-O3`, Apple clang 21.0.0 |
| Zig | 0.16.0, `ReleaseFast`, native target (ARMv8 crypto extensions **on**) |
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
C SHA-256 on this machine — nine of these eighteen measurements are over
2.00×. That is what prompted the x86-64 re-measure
([issue #40](https://github.com/nandanito/slh-dsa-zig/issues/40)).

### What the x86-64 run established

**The arm64 extrapolation was too pessimistic.** Issue #40 predicted, from the
table above, that a portable x86-64 run would put nine of eighteen SHA-2
measurements over the gate. The actual result is **one of eighteen**, mean
1.85×. Zig's portable SHA-256 trails PQClean's portable C by roughly 1.85× on
x86-64-v3, not the ~2.05× seen on Apple silicon. Different codegen, different
compiler on the reference side; the pessimistic reading did not survive
measurement.

**SHAKE is the control, and it exonerates the SLH-DSA code.** This is the part
worth dwelling on. In the portable run, both families use software hashing on
both sides — no hardware path is compiled in anywhere:

| family | what differs between the two sides | portable mean |
|---|---|---:|
| SHAKE | Keccak-p implementation only | **0.96×** |
| SHA-2 | SHA-256 implementation only | **1.85×** |

Everything *around* the hash is identical in both rows — the same hypertree
traversal, the same WOTS+ chains, the same FORS trees, the same address
handling. SHAKE landing at 0.96× is therefore direct evidence that this
library's SLH-DSA machinery is at parity with PQClean's. The entire SHA-2
delta is isolated to the SHA-256 primitive itself, which lives in
`std.crypto` and which #40 explicitly scopes out of this project.

That is a stronger claim than "36/36 passes," and it is the reason the single
2.06× is recorded as a **known, attributed exceedance** rather than a project
regression:

- **What fails:** `SLH-DSA-SHA2-256s keygen`, 2.06× against a 2.00× gate.
- **Why:** Zig's portable `std.crypto.hash.sha2` is slower than PQClean's
  portable C SHA-256. Not code in this repository.
- **Evidence it is the primitive, not the scheme:** SHAKE parity at 0.96×
  across all eighteen measurements, same structural code.
- **Disposition:** phase gate 4 is treated as satisfied with this exception
  named. It is not hidden behind an accelerated build.

Two things deliberately *not* claimed. This is one measurement, 30 iterations,
on the slowest parameter set's keygen, on a shared cloud runner — noise could
plausibly move it under 2.00×, and the run has not been repeated to find out,
because re-rolling until a published number passes is not a methodology.
And 1.99× would not have been more true than 2.06×; the interesting fact is
that portable SHA-2 sits *at* the boundary, which the table shows either way.

### Caveats on these runs

- **The arm64 run has no AVX2 column.** PQClean's `avx2` variants are x86-64
  only. The x86-64 run supplies them (2.3×–4.3× over `clean`), which closes
  the "AVX2 alongside, for honesty" half of the policy above.
- **The x86-64 run is on a shared CI runner**, unpinned and co-tenanted. The
  interleaving bounds the damage and medians absorb most of the rest, but treat
  the third significant figure as noise — which is precisely why the single
  2.06× is reported as a boundary result rather than a precise one.
- **PQClean's sign includes its own randomiser draw.** `crypto_sign_signature`
  calls `randombytes(optrand, n)` inside the timed call; `bench.zig` hoists
  that draw out of the loop. The harness measures the draw so it can be
  sized: **208 ns** on arm64, **721 ns** on the x86-64 runner, against signing
  operations of 5–2215 ms. That is at most 0.004% and does not move any ratio
  in the third decimal place on either machine.
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
