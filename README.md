# slh-dsa-zig

[![CI](https://github.com/nandanito/slh-dsa-zig/actions/workflows/ci.yml/badge.svg)](https://github.com/nandanito/slh-dsa-zig/actions/workflows/ci.yml)
[![Code: 0BSD](https://img.shields.io/badge/Code-0BSD-blue.svg)](https://opensource.org/license/0bsd)
[![Docs: CC BY 4.0](https://img.shields.io/badge/Docs-CC%20BY%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by/4.0/)
[![Zig](https://img.shields.io/badge/Zig-0.16.0-orange)](https://ziglang.org/)

A pure-Zig implementation of **SLH-DSA** ([FIPS 205](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf)) — the
stateless hash-based post-quantum signature scheme also known as SPHINCS+.

> 🚧 **EXPERIMENTAL — DO NOT USE IN PRODUCTION.**
>
> This library is under active development. The cryptographic core is implemented and passes
> the NIST ACVP vectors for all 12 parameter sets, but it has **not been audited** by a third
> party. Constant-time verification now covers key generation and signing end-to-end under
> Valgrind, on x86-64 only and with AVX-512 paths excluded ([#6](https://github.com/nandanito/slh-dsa-zig/issues/6)).
> Passing KATs proves conformance to the spec, not resistance to an attacker. The repository is
> published openly to support deep learning and public review.
> Do not use it to protect anything you care about.

📖 **[Documentation site](https://nandan.me/slh-dsa-zig/)** — a learning-oriented
guide to SLH-DSA: why hash-based signatures exist, how each component works, per-module
walkthroughs mapped to FIPS 205, and a glossary. Built from [`docs/`](docs/).

## Why this exists

Zig's standard library already ships [ML-KEM (FIPS 203)](https://github.com/ziglang/zig/tree/master/lib/std/crypto/ml_kem)
and [ML-DSA (FIPS 204)](https://github.com/ziglang/zig/tree/master/lib/std/crypto/ml_dsa) in `std.crypto`.
It does **not** ship SLH-DSA. This project closes that gap, with two goals:

1. **A usable standalone library** for projects that need hash-based PQ signatures *today* and
   are willing to accept "experimental" status, with a clear runway to production. This is the
   primary goal and the one the roadmap is ordered around.
2. **A way to learn post-quantum cryptography properly**, in public. The
   [documentation site](https://nandan.me/slh-dsa-zig/) is written to teach the scheme rather
   than merely describe the code, and includes a
   [build-it-yourself study path](https://nandan.me/slh-dsa-zig/build-it-yourself/) for readers
   who want to derive SLH-DSA from FIPS 205 themselves.

The [`upstream-candidate/`](upstream-candidate/) directory remains reserved for a possible
future contribution to `std.crypto`, under a stricter authorship discipline (see
[Lane A vs Lane B](#lane-a-vs-lane-b) below). It is not on the roadmap — see
[Roadmap](#roadmap) for why.

`slh-dsa-zig` is the first phase of [pq-zig](https://github.com/pq-zig) — a multi-phase
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
| WOTS+ | FIPS 205 §5 | ✅ `chain`, `pkGen`, `sign`, `pkFromSig` (property-tested) |
| XMSS | FIPS 205 §6 | ✅ `node`, `sign`, `pkFromSig` (property-tested) |
| Hypertree | FIPS 205 §7 | ✅ `ht_sign`, `ht_verify` (property-tested) |
| FORS | FIPS 205 §8 | ✅ `skGen`, `node`, `sign`, `pkFromSig` (property-tested) |
| SLH-DSA key generation | FIPS 205 §9.1, §10.1 | ✅ ACVP keyGen KATs pass (120/120, all 12 sets) |
| SLH-DSA sign / verify | FIPS 205 §9.2–9.3, §10 | ✅ ACVP sigGen/sigVer KATs pass (all 12 sets, internal + external) · pre-hash deferred |
| NIST ACVP KAT runner | — | ✅ keyGen · sigGen · sigVer modes (pre-hash groups skipped) |
| Benchmarks vs PQClean | — | ✅ Gated portable-vs-portable on x86-64: **35/36 inside the 2× gate**, worst 2.06× (`SHA2-256s keygen`) (#10, #40) · SHAKE parity at 0.96× isolates the excess to the hash-adapter layer (`std.crypto`'s SHA-2 — SHA-512 at this security level, not SHA-256), not to this library's structural code · accelerated build passes 36/36, published alongside but not gated |
| Constant-time verification | ctgrind / valgrind | ✅ Key generation + signing verified constant-time in SK.seed/SK.prf under Valgrind, plus the WOTS+/FORS primitives in isolation (#34) · run on SHAKE/SHA2-128f + 192f, which cover every adapter code path (incl. the SHA-512 widening); other sets differ only in public tree geometry · x86-64-v3 only; AVX-512 paths open (#6) |
| Fuzz harnesses | std.testing.fuzz | 🚧 Harnesses wired (verify, ACVP parser); cumulative nightly fuzzing accruing toward the 24h gate (#9) |

Legend: ✅ implemented and tested · 🚧 skeleton / in progress · ⏳ planned · ❌ not started

Key generation is implemented end-to-end and passes the NIST ACVP keyGen vectors for all 12
parameter sets — which also exercises both hash-adapter families, the ADRS encodings, WOTS+
public-key generation, and XMSS tree hashing against external ground truth. The full signing
chain — WOTS+/XMSS sign, the hypertree, FORS, and the top-level `slh_sign` / `slh_verify`
(pure SLH-DSA with context strings, §9.2–9.3/§10.2–10.3) — is implemented and validated
against the NIST ACVP sigGen/sigVer vectors: sigGen reproduces the expected signatures
byte-for-byte and sigVer matches every accept/reject decision across all 12 parameter sets,
for both the internal and external (context-string) interfaces. That closes the formal
Milestone 2 exit gate (issue #25). The HashSLH-DSA pre-hash variants are deferred by decision
(issue #8), so those ACVP groups are skipped.

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

## Usage

The public API is comptime-parameterised; you pick a parameter set and get back a namespace
with key/signature byte sizes and the operations. Key generation, signing, and verification
are implemented (pure SLH-DSA with context strings); the HashSLH-DSA pre-hash variants are
deferred (issue #45).

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

    // Signing. Pass a params.n-byte buffer as opt_rand for randomised (hedged)
    // signing, or `null` for deterministic signing.
    const message = "attack at dawn";
    var sig: [Scheme.signature_length]u8 = undefined;
    try Scheme.sign(&sig, message, &kp.secret_key, null);

    // Verification.
    try Scheme.verify(&sig, message, &kp.public_key);

    // With a context string (max 255 bytes; > 255 → error.ContextTooLong):
    try Scheme.signWithContext(&sig, message, "my-app-v1", &kp.secret_key, null);
    try Scheme.verifyWithContext(&sig, message, "my-app-v1", &kp.public_key);
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
5. **Fuzzed** — every attacker-facing parser and the `verify` path carries a
   `std.testing.fuzz` harness. GitHub Actions caps a job at 6h, so the gate is
   *cumulative*: a nightly workflow fuzzes for a bounded window, persists the
   corpus, and accrues ≥24h total before the component moves out of skeleton
   status.
6. **Benchmarked** — performance within 2× of PQClean's portable `clean` C reference,
   **both sides built without hardware hash acceleration** (on x86-64, `-Dcpu=x86_64_v3`).
   Accelerated and AVX2 builds are published alongside but never gated: gating an
   accelerated build measures the CPU's hash unit rather than this library, and would
   let a regression in the surrounding SLH-DSA code hide behind it.
   Measured on x86-64: **35 of 36 pass**, worst 2.06× (`SHA2-256s keygen`). That one
   exceedance is in `std.crypto`'s SHA-2 implementations, not in code in this
   repository: the SHAKE sets sit at 0.96×, and both families run the same
   structural code — every layer above `hash.zig` is generic over the adapter. Note
   the exceedance is a `n = 32` set, where `H` and `T_l` are **SHA-512**, so it is
   not attributable to SHA-256 specifically. See
   [bench/README.md](bench/README.md) for the numbers and the reasoning.

See [SECURITY.md](SECURITY.md) for the responsible-disclosure policy and current limitations.

## Roadmap

Phase 1 — `slh-dsa-zig` (this repo), ordered so external KAT validation
arrives as early as possible (see issue #7):

**Milestone 1 — key generation (complete):**

- [x] Repository scaffold and CI matrix (x86_64 / ARM64)
- [x] Parameter set definitions (all 12, comptime)
- [x] Hash adapters: SHA-2 + SHAKE (FIPS 205 §11)
- [x] ADRS structure, compressed ADRSc + `expand()` (FIPS 205 §4.2–4.3, §11)
- [x] WOTS+ `chain` + `pkGen` (FIPS 205 §5, §5.1)
- [x] XMSS `node` (FIPS 205 §6.1)
- [x] `slh_keygen_internal` + `KeyPair.generate` (FIPS 205 §9.1, §10.1)
- [x] **NIST ACVP keyGen KAT pass, all 12 parameter sets**

**Milestone 2 — signing path:**

- [x] WOTS+ `sign` + `pkFromSig` (FIPS 205 §5.2–5.3)
- [x] XMSS `sign` + `pkFromSig` (FIPS 205 §6.2–6.3)
- [x] Hypertree signing and verification (FIPS 205 §7)
- [x] FORS signing and verification (FIPS 205 §8)
- [x] Context-string API decision (issue #8) + top-level `slh_sign`, `slh_verify`
- [x] **NIST ACVP sigGen + sigVer KAT pass, all 12 parameter sets** (issue #25)

**Milestone 3 — hardening and release:**

- [x] Fuzz harnesses + cumulative nightly fuzzing (issue #9) — harnesses and the
      nightly workflow are merged; the 24h cumulative accrual itself runs in CI
- [x] Constant-time audit pass (ctgrind / valgrind, issue #34) — component-level
      and whole-path (keygen + sign) taint tracking, both hash families, with a
      negative control against vacuity. Lifting the `x86-64-v3` pin so the
      AVX-512 paths are covered too is open as issue #6
- [x] Benchmark suite + pinned PQClean comparison (issues #10, #40) — gate pinned
      to PQClean `clean`, measured portable-vs-portable on x86-64: 35/36 inside 2×,
      worst 2.06×, with the excess attributed by the SHAKE control to the hash
      adapter (`std.crypto`'s SHA-2) rather than to this library's structural
      code. Accelerated (36/36) and PQClean AVX2 published alongside
- [x] **First tagged release — [`v0.1.0`](https://github.com/nandanito/slh-dsa-zig/releases/tag/v0.1.0)
      (2026-07-30, experimental).** Milestone 3 closes with it; phase gates 1
      (functional), 2 (constant-time), 4 (benchmark) and 5 (documentation)
      satisfied, gate 3 (fuzz) accruing nightly. The `🚧 EXPERIMENTAL` banner
      stays until a third-party audit — a tag is not an audit

**Next (post-v0.1.0):** issue #38 (iterative treehash for `xmss_sign` — the most
embedded-relevant item, and it moves the sign column on both hash families),
issue #45 (HashSLH-DSA pre-hash variants), issue #6 (lift the ctgrind AVX-512
pin, blocked externally on Valgrind).

Documentation is tracked separately: the learning-oriented
[documentation site](https://nandan.me/slh-dsa-zig/) (issue #36) covers the
design rationale, per-component walkthroughs, a glossary, and a
[build-it-yourself study path](https://nandan.me/slh-dsa-zig/build-it-yourself/).

**On upstreaming.** Contributing to `std.crypto` is no longer tracked as a
roadmap item. Ziglang's contribution policy tightened considerably during this
project's lifetime, and the two-lane arrangement was designed against an earlier,
narrower version of it; issue #11 records what changed. Nothing about that
diminishes the standalone library, which is what this repository is now optimised
for. Whether a Lane B effort ever happens is a separate decision, to be taken
deliberately rather than carried along as an assumption.

Phases 2 and 3 (`pq-nacl`, `agez`) are tracked in the parent
[pq-zig](https://github.com/pq-zig) organisation.

## Design and contributing

- **[ARCHITECTURE.md](ARCHITECTURE.md)** — module layering, ADRS encoding, hash-adapter
  contract, the comptime-parameterisation pattern.
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — how to build, test, and add a primitive; the Lane
  A vs Lane B distinction in practice; review expectations.

## Security

Found a bug that may affect security? Please follow the responsible disclosure procedure in
[SECURITY.md](SECURITY.md). Do not file a public issue.

## License

Split, deliberately.

**Code — [0BSD](LICENSE).** Everything under `src/`, `tests/`, `bench/`, `examples/`, and the
build files. The same permissive licence Zig's standard library uses, and the same
philosophical posture as TweetNaCl: take the code, do what you want with it, just don't sue.
No attribution required. Code samples inside a documentation page are code, and are 0BSD.

**Documentation — [CC BY 4.0](LICENSE-DOCS).** Everything under `docs/` and the top-level
prose. Reuse, adapt, translate, sell — the only condition is credit.

The split exists because 0BSD is the *"no strings at all"* licence: it deliberately drops
even the attribution clause that MIT and BSD-2 keep. That is right for cryptographic library
code, which should be as easy as possible to vendor and adapt. It is wrong for the prose —
the [How it works](https://nandan.me/slh-dsa-zig/concepts/) chapters and the
[study path](https://nandan.me/slh-dsa-zig/build-it-yourself/) are original explanatory work,
and if they help you build your own implementation, saying so is the ask. CC BY makes that
explicit instead of leaving it an unenforceable hope.
