# The hash interface

**`src/hash.zig`** (dispatcher), **`src/hash_shake.zig`** (§11.1),
**`src/hash_sha2.zig`** (§11.2).

## Six functions

SLH-DSA is defined against six keyed hash functions. Everything else in the
scheme is built from them:

| Function | Signature | Used for |
|---|---|---|
| `PRF` | `(sk_seed, pk_seed, ADRS) → n` | Derive a WOTS+ or FORS **secret** from its address |
| `PRF_msg` | `(sk_prf, opt_rand, M') → n` | The per-signature randomiser `R` |
| `H_msg` | `(R, pk_seed, pk_root, M') → m` | The message digest that picks `md`, `idx_tree`, `idx_leaf` |
| `F` | `(pk_seed, ADRS, one n-byte block) → n` | One WOTS+ chain step; one FORS leaf |
| `H` | `(pk_seed, ADRS, left, right) → n` | Compress two children into a Merkle parent |
| `T_l` | `(pk_seed, ADRS, l blocks) → n` | Compress `l` blocks — a WOTS+ pk, or `k` FORS roots |

`F`, `H` and `T_l` are all "compress some blocks", differing in arity. They are
separate functions because the **domain separation matters**: a `T_len` over a
WOTS+ public key must not be confusable with an `H` over two tree nodes, or
structures could be reinterpreted.

## The dispatcher

`hash.zig` is a comptime switch and nothing else:

```zig
pub fn Hash(comptime p: params_mod.Params) type {
    return switch (p.family) {
        .sha2  => sha2_backend.Sha2Adapter(p),
        .shake => shake_backend.ShakeAdapter(p),
    };
}
```

Family selection happens at compile time, so a `Slh_Dsa(.slh_dsa_shake_128s)`
binary contains no SHA-2 code and no dispatch branch. Both backends expose the
identical contract, documented as a comment block in `hash.zig` — the informal
interface that both must satisfy.

## SHAKE (§11.1) — one sponge, six uses

The SHAKE instantiation is almost trivially uniform. SHAKE-256 has arbitrary
output length, so every function is *absorb the inputs, squeeze `n` or `m` bytes*:

```
PRF(sk_seed, pk_seed, ADRS)     = SHAKE256(pk_seed ‖ ADRS ‖ sk_seed, 8n)
F(pk_seed, ADRS, M)             = SHAKE256(pk_seed ‖ ADRS ‖ M, 8n)
H(pk_seed, ADRS, left, right)   = SHAKE256(pk_seed ‖ ADRS ‖ left ‖ right, 8n)
T_l(pk_seed, ADRS, M)           = SHAKE256(pk_seed ‖ ADRS ‖ M, 8n)
PRF_msg(sk_prf, opt_rand, M')   = SHAKE256(sk_prf ‖ opt_rand ‖ M', 8n)
H_msg(R, pk_seed, pk_root, M')  = SHAKE256(R ‖ pk_seed ‖ pk_root ‖ M', 8m)
```

SHAKE-256 is used at every security level — there is no SHAKE-128 variant, and
`n` changes only the squeeze length.

**The `ADRS` here is the full 32 bytes**, reconstructed with `Adrs.expand()`. See
[the trap](adrs.md#the-22-versus-32-byte-trap).

## SHA-2 (§11.2) — considerably more structure

SHA-2 has a fixed output length, so the standard needs extra machinery, and the
result is genuinely intricate.

**Hash size varies by security category.** `n = 16` uses SHA-256 throughout.
`n = 24, 32` use SHA-512 for the message functions but **keep SHA-256 for `F`**:

```zig
const MsgHash = if (p.n == 16) Sha256 else Sha512;
const MsgHmac = if (p.n == 16) HmacSha256 else HmacSha512;
// … but F is Sha256 at every level.
```

!!! warning "`F` stays SHA-256 at every security level"

    This asymmetry is easy to miss — categories 3 and 5 look all-SHA-512 at a
    glance. `F` operates on a single `n`-byte block, and the standard keeps it on
    the smaller, cheaper compression function. Since `F` is invoked more than
    anything else in the scheme (every WOTS+ chain step), this is a deliberate
    performance choice, not an oversight. Implementing it as SHA-512 produces a
    library that fails every category-3/5 vector.

**`PRF_msg` is HMAC.** Not a bare hash: `Trunc_n(HMAC-SHA-X(SK.prf, opt_rand ‖ M'))`.
`SK.prf` is the HMAC key.

**`H_msg` is MGF1.** SHA-2 cannot emit `m` bytes directly, so §11.2 stretches it
with MGF1 (RFC 8017 §B.2.1) — repeated `Hash(seed ‖ I2OSP(counter, 4))` blocks,
counter from 0, final block truncated.

**The keyed functions pad to a block boundary.** `F`, `H` and `T_l` start with
`pk_seed`, then `toByte(0, block_len - n)` zero bytes, then the 22-byte `ADRSc`,
then the message:

```
F(pk_seed, ADRSc, M) = Trunc_n( SHA-256( pk_seed ‖ 0^(64-n) ‖ ADRSc ‖ M ) )
```

The zero padding fills the first compression block exactly, so an implementation
may precompute the midstate after `pk_seed ‖ padding` once per keypair and reuse
it for every call. It mirrors an HMAC-ipad-style precomputed state. This library
does not currently exploit that; it is a known optimisation avenue for the
[benchmark work](../implementation/testing.md#benchmarks).

## Absorbing the message without copying it

`PRF_msg` and `H_msg` hash `M'`, which is `0x00 ‖ len(ctx) ‖ ctx ‖ M` — and `M`
can be any length. Materialising that concatenation would mean either an
allocation or a bounded message size.

So the adapters take the message as an **ordered sequence of slices**:

```zig
PRF_msg(sk_prf, opt_rand, msg_parts: []const []const u8, out: *[n]u8) void
H_msg(rand, pk_seed, pk_root, msg_parts: []const []const u8, out: *[m]u8) void
```

The caller passes `&[_][]const u8{ &prefix, ctx, msg }` and the adapter absorbs
each part in order. Streaming hash APIs make this natural, and the result is that
the library signs arbitrarily long messages with **no allocation and no copy** of
the message body.

This is why `signCore` takes `msg_parts` rather than a message: it is the one
design decision that lets all three interfaces — internal, external, and
pre-hash — share an implementation without any of them copying.

The pre-hash interface is where that paid off. `M'` there is
`toByte(1,1) ‖ toByte(|ctx|,1) ‖ ctx ‖ OID ‖ PH_M`, four parts instead of three,
and adding it needed no change to this layer at all: the OID and the digest slot
in as two more slices exactly the way the context prefix slots in as the first.

## Constant-time properties

Both backends are constant-time by construction, and the reasons differ:

- **Keccak-f** (SHAKE) has no data-dependent branches or memory accesses at all.
- **SHA-256/SHA-512 and HMAC** compression functions likewise — no S-box tables,
  no secret-dependent indexing.

Neither has a table lookup indexed by secret data, which is the usual source of
hash-level timing leaks.

**Secret inputs** are `sk_seed` (into `PRF`), `sk_prf` (into `PRF_msg`), and the
WOTS+/FORS chain values fed to `F`. Those paths scrub their sponge or hash state
after use. `H`, `T_l` and `H_msg` see only public material.

This is verified rather than asserted: the
[ctgrind harness](../implementation/constant-time.md) taints `SK.seed` and runs
the secret-processing primitives under Valgrind for both families.
