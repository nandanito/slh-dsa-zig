# slh-dsa-zig

[![CI](https://github.com/nandanito/slh-dsa-zig/actions/workflows/ci.yml/badge.svg)](https://github.com/nandanito/slh-dsa-zig/actions/workflows/ci.yml)
[![License: 0BSD](https://img.shields.io/badge/License-0BSD-blue.svg)](https://opensource.org/license/0bsd)
[![Zig](https://img.shields.io/badge/Zig-0.16.0-orange)](https://ziglang.org/)

A pure-Zig implementation of **SLH-DSA** ([FIPS 205](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf)) — the
stateless hash-based post-quantum signature scheme also known as SPHINCS+.

> 🚧 **EXPERIMENTAL — DO NOT USE IN PRODUCTION.**
>
> This library is under active development. The cryptographic core is **not yet implemented**,
> has **not been audited**, and is not constant-time verified. The repository is published
> openly to support deep learning, public review, and eventual upstream contribution. Do not
> use it to protect anything you care about.

## Why this exists

Zig's standard library already ships [ML-KEM (FIPS 203)](https://github.com/ziglang/zig/tree/master/lib/std/crypto/ml_kem)
and [ML-DSA (FIPS 204)](https://github.com/ziglang/zig/tree/master/lib/std/crypto/ml_dsa) in `std.crypto`.
It does **not** ship SLH-DSA. This project closes that gap, with two parallel goals:

1. **A usable standalone library** for projects that need hash-based PQ signatures *today* and
   are willing to accept "experimental" status, with a clear runway to production.
2. **A foundation for upstream contribution** to `std.crypto.sign.slh_dsa`. The
   [`upstream-candidate/`](upstream-candidate/) directory is reserved for that effort and
   follows a stricter authorship discipline (see [Lane A vs Lane B](#lane-a-vs-lane-b) below).

`slh-dsa-zig` is the first phase of [pq-zig](https://github.com/nandanito) — a multi-phase
post-quantum cryptography effort in Zig, and the direct successor to
[tweetnacl-zig](https://github.com/nandanito/tweetnacl-zig).

## Requirements

- **Zig 0.16.0** — the project tracks the latest stable Zig release.

## What works today

| Component | Spec reference | Status |
|---|---|---|
| Parameter sets (all 12) | FIPS 205 §11 Table 2 | ✅ Implemented |
| Hash adapters (SHA-2) | FIPS 205 §11.2 | ✅ Implemented |
| Hash adapters (SHAKE) | FIPS 205 §11.1 | ✅ Implemented |
| ADRS structure | FIPS 205 §4.3, §11.2 (ADRSc) | ✅ Implemented |
| WOTS+ | FIPS 205 §5 | 🚧 Skeleton |
| XMSS | FIPS 205 §6 | 🚧 Skeleton |
| Hypertree | FIPS 205 §7 | 🚧 Skeleton |
| FORS | FIPS 205 §8 | 🚧 Skeleton |
| SLH-DSA keygen / sign / verify | FIPS 205 §9–10 | 🚧 Skeleton |
| NIST ACVP KAT runner | — | 🚧 Skeleton |
| Benchmarks vs PQClean | — | 🚧 Skeleton |
| Constant-time verification | ctgrind / valgrind | ⏳ Planned |
| Fuzz harnesses | std.testing.fuzz | ⏳ Planned |

Legend: ✅ implemented and tested · 🚧 skeleton / in progress · ⏳ planned · ❌ not started

The foundation layers (parameters, utilities, ADRS, both hash-adapter families) are
implemented and unit-tested; KAT validation happens at scheme level once the tree above them
lands. The remaining cryptographic primitives are stubs that `@panic` with the FIPS 205
section reference until they are filled in under the discipline described below.

## Parameter sets

All 12 FIPS 205 parameter sets are configured at comptime:

| Family | Variant | Security | Signature size | Notes |
|---|---|---|---|---|
| `slh_dsa_sha2_128s` | small | NIST L1 (128-bit) | 7 856 B | Slowest signing, smallest sig |
| `slh_dsa_sha2_128f` | fast  | NIST L1 (128-bit) | 17 088 B | Faster signing, larger sig |
| `slh_dsa_sha2_192s` | small | NIST L3 (192-bit) | 16 224 B | |
| `slh_dsa_sha2_192f` | fast  | NIST L3 (192-bit) | 35 664 B | |
| `slh_dsa_sha2_256s` | small | NIST L5 (256-bit) | 29 792 B | |
| `slh_dsa_sha2_256f` | fast  | NIST L5 (256-bit) | 49 856 B | |
| `slh_dsa_shake_128s` | small | NIST L1 (128-bit) | 7 856 B | |
| `slh_dsa_shake_128f` | fast  | NIST L1 (128-bit) | 17 088 B | |
| `slh_dsa_shake_192s` | small | NIST L3 (192-bit) | 16 224 B | |
| `slh_dsa_shake_192f` | fast  | NIST L3 (192-bit) | 35 664 B | |
| `slh_dsa_shake_256s` | small | NIST L5 (256-bit) | 29 792 B | |
| `slh_dsa_shake_256f` | fast  | NIST L5 (256-bit) | 49 856 B | |

Sizes from FIPS 205 §11 Table 2. `s` variants are recommended for most uses; `f` variants
trade signature size for signing time.

## Installation

> Treat this as preview-only until status moves out of EXPERIMENTAL.

```sh
zig fetch --save git+https://github.com/nandanito/slh-dsa-zig.git
```

Wire it into your `build.zig`:

```zig
const slh_dsa_dep = b.dependency("slh_dsa", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("slh_dsa", slh_dsa_dep.module("slh_dsa"));
```

## Usage (planned API)

The public API is comptime-parameterised; you pick a parameter set and get back a namespace
with key/signature byte sizes and the three operations. This shape is locked, but the bodies
are not yet implemented.

```zig
const std = @import("std");
const slh_dsa = @import("slh_dsa");

pub fn main() !void {
    var io_buf: [16 * 1024]u8 = undefined;
    var io = std.Io.fixedBufferRandom(&io_buf); // illustration only — see std.Io

    // Pick a parameter set at comptime.
    const Scheme = slh_dsa.Slh_Dsa(.slh_dsa_shake_128s);

    // Key generation.
    const kp = try Scheme.KeyPair.generate(io);

    // Signing (deterministic; pass `null` for opt_rand to disable randomisation).
    const message = "attack at dawn";
    var sig: [Scheme.signature_length]u8 = undefined;
    try Scheme.sign(&sig, message, &kp.secret_key, null);

    // Verification.
    try Scheme.verify(&sig, message, &kp.public_key);
}
```

Compatibility target: **byte-for-byte identical signatures to the FIPS 205 reference and to
`std.crypto.sign.slh_dsa` once that exists**. Verified via NIST ACVP vectors (see
[`tests/vectors/README.md`](tests/vectors/README.md)).

## Building and testing

```sh
zig build                               # build the static library
zig build test                          # run the unit-test suite
zig build kat                           # run NIST ACVP KAT vectors (needs vectors fetched)
zig build kat -- --param-set 128s       # run KATs for a single parameter set
zig build bench -Doptimize=ReleaseFast  # run benchmarks
```

Run a single source file's tests:

```sh
zig test src/wots.zig
zig test src/fors.zig --test-filter "leaf"
```

## Lane A vs Lane B

This repository is one of two related codebases.

**Lane A** — the standalone library at the top level of this repo. AI-assisted development
is permitted. Issues, PRs, and reviews welcome.

**Lane B** — anything intended for upstream contribution to Zig's `std.crypto`. The Ziglang
community has a no-AI-generated-code policy for upstream contributions, and this project
respects it. Lane B work lives in [`upstream-candidate/`](upstream-candidate/) and follows a
stricter authorship discipline. See that directory's README for the rules.

The two lanes share a spec (FIPS 205) and a goal (correct SLH-DSA), but not source files.
Cross-checks happen via NIST ACVP KAT vectors, not by copying code.

## Cryptographic discipline

Every primitive in this library is built against the following defaults. These are not
aspirational; they are gates each component must pass before being declared functional.

1. **Constant-time** — no secret-dependent branches or memory accesses. Verified with
   ctgrind / valgrind in CI.
2. **No allocator in hot paths** — stack allocation and comptime sizing. Heap use is
   explicit and documented.
3. **Explicit secret zeroisation** — sensitive material zeroed before scope exit, with
   compiler barriers where the optimiser might otherwise drop the stores.
4. **KAT-validated** — passes NIST ACVP vectors for the relevant parameter set.
5. **Fuzzed** — every public deserialiser carries a fuzz harness running ≥24h in CI before
   the component moves out of skeleton status.
6. **Benchmarked** — performance compared against PQClean's C reference on the same hardware,
   target within 2×.

See [SECURITY.md](SECURITY.md) for the responsible-disclosure policy and current limitations.

## Roadmap

Phase 1 — `slh-dsa-zig` (this repo):

- [x] Repository scaffold and CI matrix (x86_64 / ARM64)
- [x] Parameter set definitions (all 12, comptime)
- [x] Hash adapters: SHA-2 (`MGF`, `PRF`, `H_msg`, `T_l`, `F`, `H`)
- [x] Hash adapters: SHAKE
- [x] ADRS structure and helpers
- [ ] WOTS+ chaining and signing (FIPS 205 §5)
- [ ] XMSS tree construction and signing (FIPS 205 §6)
- [ ] Hypertree signing and verification (FIPS 205 §7)
- [ ] FORS signing and verification (FIPS 205 §8)
- [ ] Top-level `slh_keygen`, `slh_sign`, `slh_verify` (FIPS 205 §9–10)
- [ ] NIST ACVP KAT pass for all 12 parameter sets
- [ ] Constant-time audit pass (ctgrind / valgrind)
- [ ] Fuzz harnesses + 24h CI fuzz job
- [ ] Benchmark suite + PQClean comparison
- [ ] First tagged release (`v0.1.0` — experimental)
- [ ] Upstream PR draft to `std.crypto.sign.slh_dsa`

Phases 2 and 3 (`pq-nacl`, `agez`) are tracked in the parent [pq-zig](https://github.com/nandanito)
organisation.

## Design and contributing

- **[ARCHITECTURE.md](ARCHITECTURE.md)** — module layering, ADRS encoding, hash-adapter
  contract, the comptime-parameterisation pattern.
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — how to build, test, and add a primitive; the Lane
  A vs Lane B distinction in practice; review expectations.

## Security

Found a bug that may affect security? Please follow the responsible disclosure procedure in
[SECURITY.md](SECURITY.md). Do not file a public issue.

## License

[0BSD](LICENSE) — same permissive licence Zig's standard library uses, and the same
philosophical posture as TweetNaCl: take the code, do what you want with it, just don't sue.
