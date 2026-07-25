# Parameter sets

**`src/params.zig`** — FIPS 205 §11, Table 2.

## The twelve sets

SLH-DSA is standardised at three security levels (128, 192, 256 bits), two hash
families (SHA-2, SHAKE), and two speed/size trade-offs (`s`, `f`). Three × two ×
two = twelve.

```zig
pub const ParamSet = enum {
    slh_dsa_sha2_128s,  slh_dsa_sha2_128f,
    slh_dsa_sha2_192s,  slh_dsa_sha2_192f,
    slh_dsa_sha2_256s,  slh_dsa_sha2_256f,
    slh_dsa_shake_128s, slh_dsa_shake_128f,
    slh_dsa_shake_192s, slh_dsa_shake_192f,
    slh_dsa_shake_256s, slh_dsa_shake_256f,
};
```

The `s`/`f` suffix means "small signature" / "fast signing" — the
[hypertree trade](../concepts/hypertree.md#the-sf-split-finally-explained).
Full tables with every derived size are in
[Reference → parameter sets](../reference/parameter-sets.md).

## The `Params` struct

Twelve fields transcribed from Table 2, plus four derived values as methods:

| Field | Meaning |
|---|---|
| `n` | Security parameter **in bytes** (16/24/32) |
| `h` | Total hypertree height |
| `d` | Number of hypertree layers |
| `h_prime` | XMSS tree height — always `h / d` |
| `a` | FORS tree height |
| `k` | Number of FORS trees |
| `lg_w` | log₂ of the Winternitz parameter — **always 4** |
| `m` | `H_msg` output length |
| `pk_bytes`, `sk_bytes`, `sig_bytes` | Key and signature lengths |
| `family` | `.sha2` or `.shake` |

Derived at comptime rather than stored, since storing them would be a second
chance to get them wrong:

```zig
pub fn len_1(self: Params) u32   // ceil(8n / lg_w)  = 2n when lg_w = 4
pub fn len_2(self: Params) u32   // checksum digits — FIPS 205 §3.2 Alg 1
pub fn len(self: Params) u32     // len_1 + len_2
pub fn w(self: Params) u32       // 1 << lg_w = 16
```

`h_prime` is stored *and* checked against `h / d`. That is deliberate
redundancy — the transcription is from a printed table, and a wrong `h'` would
otherwise produce a subtly wrong tree shape rather than an error.

## The comptime self-check

This is the most valuable code in the file. A parameter table is pure
transcription from a PDF, and a single wrong digit yields a library that computes
confidently wrong signatures. So the file asserts the structural relations FIPS
205 requires, at compile time, for all twelve sets:

```zig
comptime {
    for (std.enums.values(ParamSet)) |ps| {
        const p = ps.params();

        if (p.h != p.h_prime * p.d)   @compileError("params: h != h_prime * d …");
        if (p.pk_bytes != 2 * p.n)    @compileError("params: pk_bytes != 2n …");
        if (p.sk_bytes != 4 * p.n)    @compileError("params: sk_bytes != 4n …");

        const expected_sig =
            p.n                          // R (randomiser)
            + p.k * (p.a + 1) * p.n      // FORS_SIG
            + (p.h + p.d * p.len()) * p.n; // HT_SIG
        if (p.sig_bytes != expected_sig) @compileError("params: sig_bytes mismatch …");
    }
}
```

The signature-size relation is the strong one. `sig_bytes` is printed in Table 2
as a standalone number, but it is also *derivable* from `n`, `k`, `a`, `h`, `d`
and `len`. Checking the printed value against the derived one cross-validates
**six independent fields at once** — if any of them is mistyped, the arithmetic
stops agreeing and the build fails.

!!! tip "Why this belongs in the build, not the test suite"

    A test that runs is a test someone can skip, or that runs only on one
    parameter set because the others were slow. `comptime` blocks execute during
    compilation of every build for every set, unconditionally. There is no
    configuration in which a mistranscribed parameter table produces a binary.

    This is the cheapest correctness win in the whole library, and it caught real
    errors during development.

## Selecting a set

`ParamSet.params()` is `comptime`-only, so resolution happens at compile time and
the returned struct's fields are compile-time constants:

```zig
pub fn params(comptime self: ParamSet) Params {
    return all_params.get(self);
}
```

Sets are stored in a `std.EnumArray`, so lookup is a static index rather than a
switch, and the compiler can verify all twelve are populated.

## `m` and digest parsing

`m` is `H_msg`'s output length, and it must be exactly large enough to hold three
fields:

```
m  =  ceil(k·a / 8)        FORS message digest (md)
   +  ceil((h - h') / 8)   idx_tree
   +  ceil(h' / 8)         idx_leaf
```

Worth checking by hand once. For SLH-DSA-128s (`k=14, a=12, h=63, h'=9`):

```
md_bytes   = ceil(168/8) = 21
tree_bytes = ceil( 54/8) =  7
leaf_bytes = ceil(  9/8) =  2
                          ── 
                           30  = m ✓
```

This relation is asserted in `slh_dsa.zig` rather than `params.zig`, because it
is where the split actually happens:

```zig
comptime {
    if (md_bytes + tree_bytes + leaf_bytes != p.m)
        @compileError("params: m != md_bytes + tree_bytes + leaf_bytes");
}
```

See [the top-level scheme](scheme.md#digest-parsing) for how the fields are cut
out of the digest.

## Reading the tables for design intent

Two patterns are worth noticing:

**`h` barely moves; `d` moves a lot.** All twelve sets have `h` between 63 and
68 — set by the `2^64` signature budget. `d` ranges from 7 to 22. The security
target fixes total height; the trade-off knob is how you slice it.

**`k` and `a` move in opposite directions.** `s` sets use fewer, taller FORS trees
(`128s`: `k=14, a=12`); `f` sets use more, shorter ones (`128f`: `k=33, a=6`).
Both reach the same security level by different routes — see
[chapter 6](../concepts/fors.md#reading-k-and-a-as-a-design-knob).
