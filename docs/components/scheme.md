# The top-level scheme

**`src/slh_dsa.zig`** — FIPS 205 §9 (internal), §10 (external).

Concepts: [chapter 8](../concepts/assembly.md).

## The public surface

`Slh_Dsa(param_set)` returns a namespace with everything sized at compile time:

```zig
pub const public_key_length: usize = p.pk_bytes;   // 2n
pub const secret_key_length: usize = p.sk_bytes;   // 4n
pub const signature_length: usize = p.sig_bytes;

pub const PublicKey = [public_key_length]u8;   // PK.seed ‖ PK.root
pub const SecretKey = [secret_key_length]u8;   // SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root
pub const Signature = [signature_length]u8;    // R ‖ FORS_SIG ‖ HT_SIG
```

Keys are **plain arrays**, not structs. They are exactly the FIPS 205 byte
strings, so serialisation is a copy and there is no format to get wrong.

## The error set

```zig
pub const Error = error{
    InvalidSignature,   // did not verify
    InvalidInput,       // wrong length or malformed
    IoError,            // RNG failure
    ContextTooLong,     // ctx > 255 bytes (FIPS 205 §10.2)
    NotImplemented,
};
```

`ContextTooLong` deliberately matches `std.crypto.errors.ContextTooLongError`
rather than folding into `InvalidInput`. Using the canonical name means callers
can handle it uniformly across `std.crypto` algorithms — it is the same condition
ML-DSA reports.

## Digest parsing

The `H_msg` output is `m` bytes, cut into three fields. All lengths are comptime:

```zig
const md_bytes = Fors.md_bytes;                  // ceil(k·a / 8)
const tree_bytes = (p.h - p.h_prime + 7) / 8;    // ceil((h - h') / 8)
const leaf_bytes = (p.h_prime + 7) / 8;          // ceil(h' / 8)

const tree_bits = p.h - p.h_prime;
const leaf_bits = p.h_prime;
const tree_mask: u64 = if (tree_bits >= 64) maxInt(u64)
                       else (@as(u64, 1) << @intCast(tree_bits)) - 1;
const leaf_mask: u64 = (@as(u64, 1) << @intCast(leaf_bits)) - 1;

comptime {
    if (md_bytes + tree_bytes + leaf_bytes != p.m)
        @compileError("params: m != md_bytes + tree_bytes + leaf_bytes");
}
```

Then at use:

```zig
const md = digest[0..md_bytes];
const idx_tree = util.toInt(digest[md_bytes..][0..tree_bytes]) & tree_mask;
const idx_leaf: u32 = @intCast(util.toInt(digest[md_bytes + tree_bytes ..][0..leaf_bytes]) & leaf_mask);
```

!!! warning "The masks are not optional"

    The fields are cut on **byte** boundaries but carry **bit**-sized values.
    `idx_leaf` for `h' = 9` occupies 2 bytes = 16 bits, of which only 9 are
    meaningful. Without `& leaf_mask` the index could exceed `2^h'` and address a
    leaf that does not exist.

    The `tree_bits >= 64` guard on `tree_mask` avoids undefined behaviour from a
    64-bit shift. No standardised set reaches it (`h - h'` maxes out around 64),
    but a shift of exactly 64 is UB in Zig and the guard costs nothing at runtime
    since it resolves at comptime.

## Key generation

```zig
pub fn generate(io: std.Io) Error!KeyPair {
    var sk_seed: [p.n]u8 = undefined;
    var sk_prf: [p.n]u8 = undefined;
    var pk_seed: [p.n]u8 = undefined;
    defer std.crypto.secureZero(u8, &sk_seed);
    defer std.crypto.secureZero(u8, &sk_prf);
    io.randomSecure(&sk_seed) catch return Error.IoError;
    io.randomSecure(&sk_prf) catch return Error.IoError;
    io.randomSecure(&pk_seed) catch return Error.IoError;
    return fromSeeds(&sk_seed, &sk_prf, &pk_seed);
}
```

!!! danger "`randomSecure`, not `random`"

    `Io.random` **silently degrades** to a best-effort process-state seed when OS
    entropy is unavailable. For a long-lived signing key that is unacceptable — a
    weak `SK.seed` compromises every signature the key will ever produce, and the
    failure is invisible.

    `Io.randomSecure` has no fallback: entropy failure surfaces as
    `error.IoError`. A test pins this behaviour by generating against
    `std.Io.failing` and asserting the error, so a future refactor cannot quietly
    reintroduce the fallback.

    `pk_seed` is not scrubbed — it is public, and lives on in the keypair. The two
    secret seeds are.

`fromSeeds` implements §9.1 Algorithm 18 and is the deterministic entry point used
by KAT vectors:

```zig
var adrs = address.Adrs.init();
adrs.setLayer(@intCast(p.d - 1));                    // top layer
XmssTop.node(sk_seed, 0, p.h_prime, pk_seed, &adrs, &pk_root);
```

One `xmss_node` call on the top layer — the only expensive step, and `2^h'` rather
than `2^h` leaves thanks to [the hypertree](hypertree.md).

## `signCore` — the shared engine

Both interfaces route through one private function taking the message as **parts**:

```zig
fn signCore(
    out_sig: *Signature,
    msg_parts: []const []const u8,
    sk: *const SecretKey,
    opt_rand: ?*const [p.n]u8,
) void {
    const sk_seed = sk[0..p.n];
    const sk_prf  = sk[p.n .. 2 * p.n];
    const pk_seed = sk[2 * p.n .. 3 * p.n];
    const pk_root = sk[3 * p.n .. 4 * p.n];

    // R = PRF_msg(SK.prf, opt_rand ?? PK.seed, M') — written in place as sig[0..n]
    const randomizer = opt_rand orelse pk_seed;
    const r = out_sig[0..p.n];
    Hash.prf_msg(sk_prf, randomizer, msg_parts, r);

    var digest: [p.m]u8 = undefined;
    Hash.h_msg(r, pk_seed, pk_root, msg_parts, &digest);
    const md = digest[0..md_bytes];
    const idx_tree = util.toInt(digest[md_bytes..][0..tree_bytes]) & tree_mask;
    const idx_leaf: u32 = @intCast(util.toInt(digest[md_bytes + tree_bytes ..][0..leaf_bytes]) & leaf_mask);

    // FORS signs md, directly into the signature buffer.
    var adrs = address.Adrs.init();
    adrs.setTreeAddress(idx_tree);
    adrs.setType(.fors_tree);
    adrs.setKeyPairAddress(idx_leaf);
    const fors_sig = out_sig[p.n..][0..Fors.signature_bytes];
    Fors.sign(md, sk_seed, pk_seed, &adrs, fors_sig);

    // Recover the FORS public key for the hypertree to certify.
    var pk_fors: [p.n]u8 = undefined;
    var adrs_pk = address.Adrs.init();
    adrs_pk.setTreeAddress(idx_tree);
    adrs_pk.setType(.fors_tree);
    adrs_pk.setKeyPairAddress(idx_leaf);
    Fors.pkFromSig(fors_sig, md, pk_seed, &adrs_pk, &pk_fors);

    const ht_sig = out_sig[p.n + Fors.signature_bytes ..][0..Hypertree.signature_bytes];
    Hypertree.sign(&pk_fors, sk_seed, pk_seed, idx_tree, idx_leaf, ht_sig);
}
```

**`msg_parts` is the key design decision.** The external interface needs to hash
`0x00 ‖ len(ctx) ‖ ctx ‖ M` without materialising it — otherwise signing would
require an allocation or a bounded message length. Passing an ordered slice of
slices lets [the hash adapters](hashing.md#absorbing-the-message-without-copying-it)
absorb each part in sequence. The internal interface passes one part; the external
passes three. Same engine, no copy either way.

**Everything is written in place.** `R`, `FORS_SIG` and `HT_SIG` go straight into
their slices of `out_sig`. No intermediate signature buffer, no final assembly
copy — which matters when the signature is 49,856 bytes.

**A fresh `Adrs` for `pkFromSig`.** `Fors.sign` mutates the address it is given, so
reusing it would feed stale height/index fields into the reconstruction. Building a
second one is cheap (22 zeroed bytes) and unambiguous.

## The two interfaces

**External** (§10.2 Alg 22 / §10.3 Alg 24) — what applications use:

```zig
pub fn signWithContext(out_sig, msg, ctx: []const u8, sk, opt_rand) Error!void {
    if (ctx.len > 255) return Error.ContextTooLong;
    const prefix = [2]u8{ 0x00, @intCast(ctx.len) };
    signCore(out_sig, &[_][]const u8{ &prefix, ctx, msg }, sk, opt_rand);
}
```

`sign` / `verify` are wrappers with `ctx = ""`.

**Internal** (§9.2 Alg 19 / §9.3 Alg 20) — no prefix at all:

```zig
pub fn signInternal(out_sig, msg, sk, opt_rand) void {
    signCore(out_sig, &[_][]const u8{msg}, sk, opt_rand);
}
```

These exist because ACVP tests both interfaces separately. Application code should
use the external one.

!!! note "Domain separation is negatively tested"

    The test suite asserts that a pure signature (`0x00 ‖ 0x00`-prefixed) does
    **not** verify as an internal one, and vice versa. Confirming the separation
    *fails* when it should is what proves it exists — a positive round-trip test
    would pass even if the prefix were dropped entirely.

    Likewise: a signature under `ctx = "a"` must not verify under `ctx = "b"` or
    under `ctx = ""`.

`signInternal` and `verifyInternal` return `void`/`Error!void` with no
`ContextTooLong` case, since there is no context to be too long.

## Verification

```zig
fn verifyCore(sig, msg_parts, pk) Error!void {
    const pk_seed = pk[0..p.n];
    const pk_root = pk[p.n .. 2 * p.n];

    const r = sig[0..p.n];
    const fors_sig = sig[p.n..][0..Fors.signature_bytes];
    const ht_sig = sig[p.n + Fors.signature_bytes ..][0..Hypertree.signature_bytes];

    var digest: [p.m]u8 = undefined;
    Hash.h_msg(r, pk_seed, pk_root, msg_parts, &digest);
    // … parse md, idx_tree, idx_leaf exactly as signing does …

    var pk_fors: [p.n]u8 = undefined;
    Fors.pkFromSig(fors_sig, md, pk_seed, &adrs, &pk_fors);

    if (!Hypertree.verify(&pk_fors, ht_sig, pk_seed, idx_tree, idx_leaf, pk_root)) {
        return Error.InvalidSignature;
    }
}
```

Signature length is a **type invariant** — `sig: *const Signature` is a
`[signature_length]u8` pointer, so a wrong-length signature cannot be passed. That
removes a whole class of length-confusion bug at the type level, and it is why
`InvalidInput` never appears on this path.

There is exactly one accept condition: `Hypertree.verify` returning true.

## Constant-time posture

- **Verification handles no secrets.** Every input is public, so it has no
  constant-time obligations. It is instead the primary
  [fuzz target](../implementation/testing.md#fuzzing).
- **Signing handles `SK.seed` and `SK.prf`.** These flow into `PRF`/`PRF_msg` and
  never gate a branch. Local seed copies in `generate` are scrubbed; the
  caller-owned `KeyPair` retains them by design.
- **`digest`, `md`, `idx_tree`, `idx_leaf` are public** — recoverable from the
  signature. Branching on them is safe, and that is exactly why a whole-signing
  ctgrind run false-positives: see
  [constant-time discipline](../implementation/constant-time.md).

## Tests in this module

- Sizes match `params` for all twelve sets.
- Entropy failure → `IoError`, verified against `std.Io.failing`.
- `fromSeeds` determinism, and the SK/PK byte layout per §9.1.
- Round-trip with and without a context, plus deterministic signing
  (`opt_rand = null`) producing byte-identical signatures.
- Negatives: tampered `R`, tampered final HT byte, wrong message, wrong context,
  corrupted `PK.root`, cross-interface confusion.
- `ctx` of 256 bytes → `ContextTooLong`, on both sign and verify.

Plus the full ACVP suite — keyGen, sigGen and sigVer across all twelve sets, both
interfaces. See [how this is tested](../implementation/testing.md).
