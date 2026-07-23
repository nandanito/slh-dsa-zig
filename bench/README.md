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
```

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

When publishing a comparison number, record all four so it is reproducible:

1. **PQClean commit** — the exact hash you built (`git -C PQClean rev-parse HEAD`).
2. **PQClean build** — `clean` variant, `-O3` (the ballpark of Zig's
   `ReleaseFast`), same machine.
3. **Zig version and optimize mode** — from `zig version` and the bench
   header line.
4. **Machine** — CPU model, and whether frequency scaling / turbo was pinned.

## Results

> No pinned comparison has been published yet. The harness produces real
> numbers (run it), but the gate is only meaningful once measured against a
> recorded PQClean `clean` commit on the same machine. This table is filled
> in when that first run happens.

| param set | op | Zig median (ns) | PQClean `clean` (ns) | ratio | PQClean commit |
|-----------|----|-----------------|----------------------|-------|----------------|
| _pending_ | —  | —               | —                    | —     | —              |

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
