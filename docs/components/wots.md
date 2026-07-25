# WOTS+

**`src/wots.zig`** — FIPS 205 §5, Algorithms 5–8.

Concepts: [chapter 2](../concepts/wots.md).

## Sizes

```zig
pub const w: usize     = 1 << lg_w;        // 16
pub const len_1: usize = p.len_1();        // ceil(8n / lg_w) = 2n
pub const len_2: usize = p.len_2();        // checksum digits
pub const len: usize   = len_1 + len_2;    // 35 / 51 / 67
pub const signature_bytes: usize = len * n;
```

| `n` | `len_1` | `len_2` | `len` | Signature |
|---|---|---|---|---|
| 16 | 32 | 3 | 35 | 560 B |
| 24 | 48 | 3 | 51 | 1,224 B |
| 32 | 64 | 3 | 67 | 2,144 B |

## `chain` — §5, Algorithm 5

```zig
pub fn chain(
    input: *const [n]u8,
    i: u32, s: u32,
    pk_seed: *const [n]u8,
    adrs: *address.Adrs,
    out: *[n]u8,
) void {
    var tmp: [n]u8 = input.*;
    var j: u32 = i;
    while (j < i + s) : (j += 1) {
        adrs.setHashAddress(j);
        Hash.f(pk_seed, adrs, &tmp, &tmp);
    }
    out.* = tmp;
}
```

Two details:

**`setHashAddress(j)` inside the loop.** Every step gets its own address, so step
5 of a chain uses a different tweak from step 6. Hoisting this out of the loop
would make all steps identical — and the resulting library still round-trips.

**`Hash.f(…, &tmp, &tmp)` writes in place.** Safe because both backends fully
absorb the input before touching the output buffer. It is called out in a comment
because it is exactly the kind of aliasing that is fine today and breaks silently
if a backend is ever rewritten to write incrementally.

!!! note "Constant-time status: safe, with a caveat worth understanding"

    `s` gates the loop, so **the number of iterations is observable**. That is
    fine, and the reason is worth internalising: at every WOTS+ call site in
    SLH-DSA, the message being signed is a *public* value — a FORS public key or
    an XMSS root — and the digits derived from it are recoverable from the
    signature anyway.

    The secret is `input` (the chain origin, from `PRF(SK.seed, …)`), and it never
    gates a branch or indexes memory. It only ever flows *through* `F`.

    This distinction — public step counts, secret chain values — is precisely why
    a whole-signature ctgrind run reports false positives, and why the
    [CT audit](../implementation/constant-time.md) is currently done at component
    granularity.

## `pkGen` — §5.1, Algorithm 6

Runs all `len` chains to the end and compresses the endpoints:

```zig
var sk_adrs = adrs.*;
sk_adrs.setType(.wots_prf);                    // secret DERIVATION address
sk_adrs.setKeyPairAddress(adrs.getKeyPairAddress());

var sk: [n]u8 = undefined;
defer std.crypto.secureZero(u8, &sk);          // ← secret material

var tmp: [len * n]u8 = undefined;               // endpoints: public
for (0..len) |i| {
    sk_adrs.setChainAddress(@intCast(i));
    Hash.prf(sk_seed, pk_seed, &sk_adrs, &sk);  // derive chain origin
    adrs.setChainAddress(@intCast(i));
    chain(&sk, 0, w - 1, pk_seed, adrs, tmp[i * n ..][0..n]);
}

var pk_adrs = adrs.*;
pk_adrs.setType(.wots_pk);                      // compression address
pk_adrs.setKeyPairAddress(adrs.getKeyPairAddress());
Hash.t_l(pk_seed, &pk_adrs, &tmp, out_pk);
```

Three things to notice.

**Three different address types in one function.** `.wots_prf` to derive secrets,
`.wots_hash` (inherited via `adrs`) for chain steps, `.wots_pk` to compress. Using
one type for all three would let an attacker relate values that must stay
unrelated.

**`setKeyPairAddress` is re-applied after `setType`.** Because
[`setType` zeroes the tail](adrs.md#the-22-versus-32-byte-trap) per §4.3, the
key-pair address must be restored afterwards. Getting this order wrong is a
classic ADRS bug.

**`sk` is scrubbed; `tmp` is not.** `sk` holds `PRF(SK.seed, …)` output — secret,
so `defer secureZero`. `tmp` holds chain endpoints, which *are* the public key —
scrubbing it would be pointless work. Being precise about which buffers are
actually secret is what keeps the zeroization discipline meaningful rather than
ritual.

## `baseWDigits` — the shared digit conversion

`wots_sign` (§5.2 Alg 7 lines 1–7) and `wots_pkFromSig` (§5.3 Alg 8 lines 1–7)
compute *identical* digits, so this library factors them into one private helper.
Duplicating it would be an opportunity for the two to disagree — and a signer and
verifier that disagree on digits produce a scheme that never validates.

```zig
fn baseWDigits(msg: *const [n]u8, out: *[len]u32) void {
    util.base_2b(msg, lg_w, out[0..len_1]);        // message digits

    const wm1: u32 = @intCast(w - 1);
    var csum: u32 = 0;
    for (out[0..len_1]) |d| csum += wm1 - d;       // the checksum

    const csum_shift: u6 = @intCast((8 - ((len_2 * lg_w) % 8)) % 8);
    var csum_bytes: [(len_2 * lg_w + 7) / 8]u8 = undefined;
    util.toByte(@as(u64, csum) << csum_shift, &csum_bytes);
    util.base_2b(&csum_bytes, lg_w, out[len_1..len]);
}
```

!!! warning "The checksum left-shift"

    `csum_shift` is the fiddliest line in the module. The checksum occupies
    `len_2 · lg_w` bits — 12 bits for `lg_w = 4`, `len_2 = 3` — but is written
    into a whole number of bytes (2), so it must be **left-aligned** in that field
    before `base_2b` cuts digits from the top.

    Omit the shift and the digits come out right-aligned: consistently wrong, and
    self-consistent between signer and verifier, so every round-trip test passes
    and every KAT fails. FIPS 205 §5.2 lines 6–7 specify it.

## `sign` — §5.2, Algorithm 7

For each chain, walk `digit[i]` steps from the origin:

```
sig[i] = chain(sk_i, 0, digit[i], …)
```

## `pkFromSig` — §5.3, Algorithm 8

For each chain, walk the *remaining* `w - 1 - digit[i]` steps and compress:

```
tmp[i] = chain(sig[i], digit[i], w - 1 - digit[i], …)
pk     = T_len(tmp)
```

Signing and verifying together traverse each chain exactly `w - 1` times, which is
the invariant that makes the endpoints match. The function **returns the
reconstructed public key** rather than a boolean — see
[why](index.md#conventions-across-every-module).

## Tests in this module

- Sizes match the FIPS 205 §11 derived values for all twelve sets.
- `chain` composition: `chain(x, 0, a)` then `chain(·, a, b)` equals
  `chain(x, 0, a+b)` — the property that makes signing and verifying meet.
- Round-trip: a genuine signature reconstructs to exactly `pkGen`'s output.
- Negative: a tampered signature reconstructs to something else.

There are no NIST vectors for WOTS+ in isolation, so component confidence comes
from these property tests plus the scheme-level ACVP KATs that exercise WOTS+
millions of times per run. See
[how this is tested](../implementation/testing.md).
