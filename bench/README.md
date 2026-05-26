# Benchmarks

Performance harness for slh-dsa-zig, built on `std.time.Timer`.

## Running

```sh
zig build bench                                  # all ops, all parameter sets
zig build bench -- --op sign                     # only signing
zig build bench -- --param-set SLH-DSA-SHAKE-128s
zig build bench -- --op verify --iters 1000
```

The bench binary is always built in `ReleaseFast` unless you override:

```sh
zig build bench -Dbench-optimize=ReleaseSafe
```

> 🚧 **Skeleton.** The harness compiles and prints the table, but each
> per-op loop currently runs a do-nothing body so the numbers below are
> not meaningful. The loops will be wired to `KeyPair.generate`, `sign`,
> and `verify` as those land.

## Methodology

- Each measurement runs `N` iterations with `std.time.Timer.reset()` +
  `read()` around the operation under test.
- The reported `median` is the headline number; `mean` is shown for
  reference but is sensitive to outliers (page faults, scheduler jitter).
- The default iteration counts (`50` for keygen/sign, `500` for verify)
  are tuned so the slowest parameter set (`sha2_256s`) finishes in a few
  seconds. Override with `--iters` for tighter or looser bounds.
- The same secret key and message are reused inside a measurement loop;
  this measures steady-state cost, not first-touch effects. For
  first-touch numbers, set `--iters 1`.
- Inputs are kept live with `std.mem.doNotOptimizeAway` so the optimiser
  cannot DCE the operation.

## Comparison points

SLH-DSA is intentionally not fast: it is the conservative,
hash-only-assumptions sibling of ML-DSA. The benchmarks here exist to
catch regressions inside this library, not to advertise speed.

Useful external references for sanity-checking absolute numbers:

- **PQClean** — <https://github.com/PQClean/PQClean> — portable C
  reference, often used as the de-facto baseline.
- **liboqs** — <https://github.com/open-quantum-safe/liboqs> — published
  per-platform benchmark tables.
- **NIST round-3 submission** — the original SPHINCS+ team's reference
  numbers (now superseded but useful for relative ordering between
  parameter sets).

When this harness produces real numbers, the README's status table will
gain a "comparison" column citing one of these baselines.
