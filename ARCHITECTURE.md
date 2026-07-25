# Architecture

This document describes the internal layering of `slh-dsa-zig`, the conventions each layer
follows, and the contracts between layers. It is the second document to read after the
[README](README.md) and is the entry point for anyone reviewing or contributing code.

## Spec mapping

The implementation follows [FIPS 205](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf)
section-by-section. Each source file declares the FIPS 205 section(s) it implements at the
top of the file, and individual functions cite the algorithm number they realise.

```
FIPS 205 §3    — Notation and conventions       src/util.zig
FIPS 205 §4.2  — ADRS type values               src/address.zig
FIPS 205 §4.3  — ADRS structure                 src/address.zig
FIPS 205 §5    — WOTS+                          src/wots.zig
FIPS 205 §6    — XMSS                           src/xmss.zig
FIPS 205 §7    — Hypertree                      src/hypertree.zig
FIPS 205 §8    — FORS                           src/fors.zig
FIPS 205 §9    — SLH-DSA (top-level scheme)     src/slh_dsa.zig
FIPS 205 §11   — Parameter sets                 src/params.zig
FIPS 205 §11.1 — Hash functions (SHAKE)         src/hash_shake.zig
FIPS 205 §11.2 — Hash functions (SHA-2)         src/hash_sha2.zig
```

## Layers

```
                 ┌─────────────────────────────────────────────────────┐
                 │  Public API  (src/root.zig, src/slh_dsa.zig)        │
                 │    Slh_Dsa(param_set).KeyPair / sign / verify       │
                 └────────────────────────┬────────────────────────────┘
                                          │
                 ┌────────────────────────▼────────────────────────────┐
                 │  Composition layer  (slh_dsa.zig)                   │
                 │    Drives hypertree + FORS for sign / verify        │
                 └─────┬───────────────────┬───────────────────────────┘
                       │                   │
       ┌───────────────▼────────┐  ┌───────▼───────────────┐
       │  Hypertree (hypertree) │  │  FORS  (fors.zig)     │
       │    Stack of XMSS trees │  │    Few-time signatures│
       └───────────────┬────────┘  └───────┬───────────────┘
                       │                   │
                ┌──────▼──────┐             │
                │ XMSS        │             │
                │ (xmss.zig)  │             │
                └──────┬──────┘             │
                       │                    │
                ┌──────▼──────┐             │
                │ WOTS+       │             │
                │ (wots.zig)  │             │
                └──────┬──────┘             │
                       │                    │
                  ┌────▼────────────────────▼────┐
                  │  Hash adapter   (hash.zig)   │
                  │    PRF, PRF_msg, H_msg,      │
                  │    F, H, T_l                 │
                  └────┬─────────────────────┬───┘
                       │                     │
              ┌────────▼─────────┐  ┌────────▼────────┐
              │  SHA-2 backend   │  │  SHAKE backend  │
              │  (hash_sha2.zig) │  │  (hash_shake.zig)│
              └──────────────────┘  └─────────────────┘
                       │                     │
                  ┌────▼─────────────────────▼────┐
                  │  std.crypto (Zig stdlib)      │
                  │  SHA-256, SHA-512, SHAKE-256  │
                  └───────────────────────────────┘

                  Cross-cutting:
                  ┌──────────────────────┐  ┌──────────────────┐
                  │  ADRS (address.zig)  │  │  util.zig        │
                  │  32-byte encoding    │  │  base_2b, etc.   │
                  └──────────────────────┘  └──────────────────┘
```

### Lower layers depend on higher layers? No.

Crypto layering rule: nothing in `wots.zig` may know about XMSS; nothing in `xmss.zig` may
know about the hypertree; nothing in `fors.zig` may know about the top-level scheme.
ADRS and the hash adapter are the only cross-cutting modules.

### Public API: internal vs external interface, and context strings

`Slh_Dsa(param_set)` exposes two tiers, following `std.crypto.ml_dsa` (the FIPS-204 sibling
with the same §10.2 context design — issue #8):

- **External interface** (FIPS 205 §10.2/§10.3) — what real callers use.
  - `sign(out, msg, sk, opt_rand)` / `verify(sig, msg, pk)` — pure SLH-DSA, empty context.
  - `signWithContext(out, msg, ctx, sk, opt_rand)` / `verifyWithContext(sig, msg, ctx, pk)` —
    with a context string. `ctx.len > 255` returns `error.ContextTooLong` (the canonical
    `std.crypto.errors` name). The message is domain-separated as
    `M' = toByte(0,1) ‖ toByte(|ctx|,1) ‖ ctx ‖ M` before internal signing.
- **Internal interface** (FIPS 205 §9.2/§9.3) — `signInternal` / `verifyInternal` sign `M`
  directly with no context prefix, symmetric with `KeyPair.fromSeeds`. Exposed for the ACVP
  internal-interface test mode.

`opt_rand` is the per-signature randomiser: a `params.n`-byte buffer for randomised (hedged)
signing, or `null` to fall back to `PK.seed` for deterministic signing (FIPS 205 §9.2).

To keep signing allocation-free for arbitrary-length messages, the `PRF_msg` / `H_msg`
adapters absorb the message as an ordered sequence of parts, so the context prefix is
prepended without copying `M`.

**HashSLH-DSA is deferred.** The pre-hash variants `hash_slh_sign` / `hash_slh_verify`
(FIPS 205 §10.2/§10.3 — domain separator `0x01` plus a per-hash OID over `PH(M)`) are a
deliberate future addition, not an omission (issue #8): `std.crypto` ships ML-DSA without
HashML-DSA, ACVP certifies pre-hash as a separate group, and adding it later is additive and
non-breaking. Until then this library implements only the pure variant.

## The comptime parameterisation pattern

SLH-DSA has 12 parameter sets. Rather than dispatching at runtime, the library uses
**comptime parameterisation**: you call `Slh_Dsa(.slh_dsa_shake_128s)` and get back a
namespace specialised for that parameter set, with all sizes — `public_key_length`,
`secret_key_length`, `signature_length`, internal block sizes — known at compile time.

This buys three things:

1. **No runtime parameter dispatch.** Hot paths have no branches on which parameter set
   we are running.
2. **Stack-allocated buffers everywhere.** Signatures, internal state, intermediate hash
   buffers are all `[N]u8` with `N` known at comptime. No allocator is needed in the
   crypto core.
3. **Compile-time validation.** Wrong-sized inputs are caught as compile errors, not
   runtime errors.

```zig
const Scheme = slh_dsa.Slh_Dsa(.slh_dsa_shake_128s);

// All of these are comptime constants:
_ = Scheme.public_key_length;     // 32
_ = Scheme.secret_key_length;     // 64
_ = Scheme.signature_length;      // 7856
_ = Scheme.params.n;              // 16
_ = Scheme.params.h;              // 63
// ... etc.
```

The internal helper modules — `Wots(params)`, `Xmss(params)`, `Hypertree(params)`,
`Fors(params)`, `Hash(params)` — follow the same pattern. Each one is a function returning
a `type`, parameterised by the same `Params` struct.

## ADRS encoding

`ADRS` (FIPS 205 §4.3) is the address structure that disambiguates each hash call. FIPS 205
defines two encodings:

- The **full ADRS** (32 bytes, FIPS 205 §4.2) — used by the SHAKE instantiations in §11.1.
- The **compressed ADRSc** (22 bytes, FIPS 205 §11.2) — used by the SHA-2 instantiations
  in §11.2.1 / §11.2.2.

`Adrs` in this library stores the 22-byte compressed form as the canonical representation
and exposes `Adrs.expand()` to produce the 32-byte full ADRS on demand for SHAKE consumers.
Compression is lossless from this storage form because none of the typed setters write to
the high-order bytes that ADRSc drops (the layer setter takes a `u8`, the tree setter a
`u64`, the type setter a `u8`). The SHA-2 backend hashes `Adrs.slice()` directly; the SHAKE
backend hashes `Adrs.expand()`. This keeps a single source of truth in memory and matches
the byte-exact contract of FIPS 205 §11.1 and §11.2.

The compressed structure is:

```
+--------+----------------------+--------+---------------------------------+
| Layer  |  Tree address        |  Type  |  Type-specific fields           |
| (1B)   |  (8B)                |  (1B)  |  (12B, varies by type)          |
+--------+----------------------+--------+---------------------------------+
0        1                      9        10                              22
```

(See `src/address.zig` and FIPS 205 §11.2 Figure 18.)

ADRS types per FIPS 205 §4.2 Table 1:

| Constant | Value | Used by |
|---|---|---|
| `WOTS_HASH` | 0 | WOTS+ chaining hashes |
| `WOTS_PK`   | 1 | WOTS+ public-key compression |
| `TREE`      | 2 | XMSS internal-node hashing |
| `FORS_TREE` | 3 | FORS internal-node hashing |
| `FORS_ROOTS`| 4 | FORS public-key compression |
| `WOTS_PRF`  | 5 | WOTS+ secret-key PRF |
| `FORS_PRF`  | 6 | FORS secret-key PRF |

## Hash-adapter contract

`Hash(params)` exposes six functions, all of which take a `pk_seed` (PK.seed) and an `adrs`,
mirroring FIPS 205 §11:

```zig
fn prf       (sk_seed: *const Seed, pk_seed: *const Seed, adrs: *const Adrs, out: *Seed) void;
fn prf_msg   (sk_prf: *const Seed, opt_rand: *const Rand, msg: []const u8, out: *MdSlice) void;
fn h_msg     (rand: *const Rand, pk_seed: *const Seed, pk_root: *const Seed, msg: []const u8, out: *DigestSlice) void;
fn f         (pk_seed: *const Seed, adrs: *const Adrs, msg: *const Seed, out: *Seed) void;
fn h         (pk_seed: *const Seed, adrs: *const Adrs, left: *const Seed, right: *const Seed, out: *Seed) void;
fn t_l       (pk_seed: *const Seed, adrs: *const Adrs, msg: []const u8, out: *Seed) void;
```

Two backends implement this contract:

- **`hash_sha2.zig`** — `H`, `T_l`, `H_msg` use SHA-256 (and SHA-512 for L3/L5 sets, per
  FIPS 205 §11.2). `F` uses SHA-256 for all sets. MGF1 is used for variable-length output.
- **`hash_shake.zig`** — All six functions are realised via SHAKE-256 with appropriate
  output lengths (FIPS 205 §11.1).

Backend selection happens at comptime based on the parameter set family.

## Constant-time discipline

Hot paths handling secret material follow these rules. Any deviation must be justified in
a code comment citing why the secret being accessed is not actually secret in that context.

- **No branches on secret values.** Compare-and-conditional-copy patterns from
  [`std.crypto.utils`](https://github.com/ziglang/zig/blob/master/lib/std/crypto/utils.zig)
  are used for selection.
- **No table indices derived from secret values.** WOTS+ chain lengths are derived from
  the *digest*, which is public after signing — but the per-leaf PRF outputs that feed
  chain bases are secret and never index a table.
- **No secret-dependent loop bounds.** WOTS+ chains run for a fixed number of iterations
  per parameter set, not a count derived from secret data.
- **Explicit zeroisation.** Sensitive buffers — WOTS+ secret keys, FORS secrets, intermediate
  PRF outputs — are zeroed before scope exit using `std.crypto.utils.secureZero`.

Verification: a separate CI job runs the test suite under `ctgrind`/`valgrind` with the
secret-data taint annotations and fails if any secret-dependent control flow or memory
access is observed.

## Test strategy

Three layers of tests, in order of importance:

1. **KAT vectors** — every parameter set passes the NIST ACVP test vectors for keygen, sign,
   and verify. This is the primary correctness gate. See
   [`tests/vectors/README.md`](tests/vectors/README.md) for how to fetch the vectors.
2. **Property tests** — round-trip (`sign` then `verify` succeeds), tamper detection
   (modified message or signature → `verify` fails), serialisation idempotence.
3. **Fuzz harnesses** — every public deserialiser carries a fuzz harness, focused on the
   verifier (which by construction handles attacker-controlled signatures).

Two structural notes on how the KAT gate is applied (issue #7):

- **No component-level NIST vectors exist.** ACVP only tests keyGen / sigGen / sigVer at
  scheme level. Components (WOTS+, XMSS, hypertree, FORS) are validated by (a) the
  scheme-level KATs that exercise them, (b) spec-derived property tests (e.g. chain
  composition, node/H consistency), and (c) — where a component is not yet reachable from
  a passing scheme-level KAT — intermediate fixtures extracted from the SPHINCS+/PQClean
  reference implementations (cross-validation only; never copied code).
- **Keygen-first ordering.** `slh_keygen_internal` needs only `chain`, `wots_pkgen`, and
  `xmss_node`, so the keyGen KATs deliver external byte-for-byte validation roughly halfway
  up the component tree before any signing code exists. The signing path is built against
  the already-KAT-validated bottom stack.

Unit tests at each layer (WOTS+, XMSS, hypertree, FORS) prefer the `f`-variant parameter
sets (small trees, h' ≤ 4) to keep the Debug test suite fast; the `s`-variants are covered
by the KAT runs.

## Build outputs

- `zig build` → `zig-out/lib/libslh_dsa.a` (static library).
- `zig build kat` → `zig-out/bin/slh-dsa-kat` (KAT runner CLI).
- `zig build bench` → `zig-out/bin/slh-dsa-bench` (benchmark runner).
- `zig build test` → runs unit tests in-tree.

No shared library. No DLL. No FFI surface. Use it from Zig.

The documentation site is built separately with mkdocs (docs-only Python tooling, pinned in
`docs/requirements.txt`; never imported by the library):

- `mkdocs build --strict` → `site/` (what CI publishes to GitHub Pages).
- `mkdocs serve` → local preview on `127.0.0.1:8000`.

**Division of responsibility:** this file is the authority on *code structure* — layering,
encodings, the hash-adapter contract. The [documentation site](https://nandanito.github.io/slh-dsa-zig/)
(`docs/`, issue #36) is the authority on *concepts* — why hash-based signatures exist, how each
component works, and the glossary. The site links here rather than restating the structure.

## Upstream-candidate tree

The `upstream-candidate/` directory is a separate Lane B work area. Its layout deliberately
**does not mirror** the standalone tree, so there is no temptation to copy code across the
boundary. See `upstream-candidate/README.md` for the rules that govern it.
