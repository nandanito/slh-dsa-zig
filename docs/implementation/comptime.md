# Comptime parameterisation

SLH-DSA has twelve parameter sets. Handling that badly is the difference between
a library the compiler can check and one that checks itself at runtime.

## The pattern

Every module is a function from `Params` to a type:

```zig
pub fn Wots(comptime p: params_mod.Params) type {
    return struct {
        pub const len: usize = p.len();
        pub const signature_bytes: usize = len * n;
        // … functions using those constants …
    };
}
```

Instantiating `Slh_Dsa(.slh_dsa_shake_128s)` monomorphises the whole stack —
FORS, hypertree, XMSS, WOTS+, the hash adapter — with every size a compile-time
constant. Twelve call sites give twelve independent specialisations, sharing no
runtime dispatch.

```zig
const Small = slh_dsa.Slh_Dsa(.slh_dsa_shake_128s);   // 7,856-byte signatures
const Fast  = slh_dsa.Slh_Dsa(.slh_dsa_shake_128f);   // 17,088-byte signatures
```

These are **different types**. You cannot pass a `Small.Signature` where a
`Fast.Signature` is expected — the compiler rejects it, because they are
`[7856]u8` and `[17088]u8`.

## What this buys

### 1. Buffers are exactly sized, on the stack

```zig
var tmp: [len * n]u8 = undefined;              // wots.zig
var digest: [p.m]u8 = undefined;               // slh_dsa.zig
var indices: [k]u32 = undefined;               // fors.zig
```

No allocator, no `ArrayList`, no maximum-size buffer sized for the largest
parameter set and mostly wasted. A 128s build allocates 21 bytes for `md`; a 256s
build allocates 39. Neither carries the other's overhead.

This is the mechanism behind the "no allocation in the library" rule. It is not
discipline — there is genuinely nothing to allocate, because every size is known
before the program runs.

### 2. Structural invariants become compile errors

`params.zig` asserts FIPS 205's relations in a `comptime` block, so a
mistranscribed Table 2 value cannot produce a binary:

```zig
comptime {
    for (std.enums.values(ParamSet)) |ps| {
        const p = ps.params();
        if (p.h != p.h_prime * p.d) @compileError("params: h != h_prime * d …");
        // … plus pk_bytes, sk_bytes, and the full sig_bytes relation
    }
}
```

`slh_dsa.zig` adds the digest-parsing invariant:

```zig
comptime {
    if (md_bytes + tree_bytes + leaf_bytes != p.m)
        @compileError("params: m != md_bytes + tree_bytes + leaf_bytes");
}
```

!!! tip "Compile-time beats test-time for invariants"

    A test can be skipped, can run on one parameter set because the rest are slow,
    or can be deleted by someone fixing an unrelated failure. A `comptime` block
    runs during compilation of **every** build, for **every** parameter set, with
    no way to opt out. There is no configuration in which a wrong parameter table
    yields a working binary.

    For transcribed constants — where the entire risk is a typo — this is the
    highest-leverage checking available.

### 3. Loop bounds are constants

```zig
for (0..len) |i| { … }        // len = 35, known at compile time
for (0..k) |i| { … }          // k = 14
```

The compiler can unroll, hoist bounds checks, and specialise. More importantly for
this library, **a loop with a comptime bound cannot have a secret-dependent trip
count**, which removes an entire category of timing concern by construction rather
than by inspection.

### 4. Dead code does not ship

```zig
pub fn Hash(comptime p: params_mod.Params) type {
    return switch (p.family) {
        .sha2  => sha2_backend.Sha2Adapter(p),
        .shake => shake_backend.ShakeAdapter(p),
    };
}
```

A SHAKE-only binary contains no SHA-2 adapter, no HMAC, no MGF1, and no branch to
select between them. For embedded targets this is the difference between shipping
one hash family and shipping both.

## The costs

Being honest about them.

**Compile time and binary size scale with sets used.** Instantiating all twelve —
as the test suite and KAT runner do — means twelve copies of the whole stack. This
is real: the KAT runner is a noticeably larger binary than a single-set consumer.
Most applications use one set and pay nothing.

**No runtime agility, by design.** You cannot read a parameter set from a config
file and get a scheme. If you need that, write the dispatch yourself:

```zig
const sig = switch (chosen) {
    .shake_128s => try Slh_Dsa(.slh_dsa_shake_128s).sign(…),
    .shake_128f => try Slh_Dsa(.slh_dsa_shake_128f).sign(…),
    // … only the sets you actually support
};
```

Verbose, but the verbosity is informative: it makes the binary-size cost of
supporting many sets visible at the call site instead of hiding it in the library.

**Test times multiply.** Every property test that loops over all twelve sets
compiles and runs twelve times. The suite deliberately restricts the expensive
round-trip tests to `f` variants at the 128-bit level — `h' = 3` means 8-leaf trees
— and leaves full coverage of the `s` sets to the ACVP KAT runs, which are built in
release mode.

## Debug versus release

Worth knowing when running things locally: `s`-variant signing in a Debug build is
*extremely* slow. The full ACVP sigGen run over all twelve sets takes minutes even
optimised, because `s` sets do hundreds of times more work per signature than `f`
sets.

The unit suite is structured around this — fast property tests on small `f`
variants, exhaustive vector validation in the KAT runner. If a `zig build test` run
feels slow, it is not the comptime machinery; it is Keccak.

## Why it matters more here than usual

Generic programming often trades clarity for reuse. Here it buys something
specific: **the parameters are transcribed constants from a PDF, and the sizes
derived from them are load-bearing.** A wrong `len` means a wrong-sized signature
buffer. A wrong `md_bytes` means the digest is sliced at the wrong offset, which
means a valid-looking signature that no other implementation accepts.

Making the compiler responsible for all of that arithmetic is the single largest
correctness lever available, and it costs nothing at runtime.
