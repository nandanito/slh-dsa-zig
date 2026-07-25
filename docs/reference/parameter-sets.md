# Parameter set tables

FIPS 205 §11, Table 2, plus every value derived from it. Source of truth:
`src/params.zig`, where the relations below are
[asserted at compile time](../components/parameters.md#the-comptime-self-check).

The SHA-2 and SHAKE families share **identical** structural parameters at each
level — only the hash instantiation differs. So each row covers two parameter sets.

## Table 2 values

| Set | `n` | `h` | `d` | `h'` | `a` | `k` | `lg_w` | `m` |
|---|---|---|---|---|---|---|---|---|
| 128s | 16 | 63 | 7 | 9 | 12 | 14 | 4 | 30 |
| 128f | 16 | 66 | 22 | 3 | 6 | 33 | 4 | 34 |
| 192s | 24 | 63 | 7 | 9 | 14 | 17 | 4 | 39 |
| 192f | 24 | 66 | 22 | 3 | 8 | 33 | 4 | 42 |
| 256s | 32 | 64 | 8 | 8 | 14 | 22 | 4 | 47 |
| 256f | 32 | 68 | 17 | 4 | 9 | 35 | 4 | 49 |

## Key and signature sizes

| Set | Public key `2n` | Private key `4n` | Signature |
|---|---|---|---|
| 128s | 32 | 64 | **7,856** |
| 128f | 32 | 64 | **17,088** |
| 192s | 48 | 96 | **16,224** |
| 192f | 48 | 96 | **35,664** |
| 256s | 64 | 128 | **29,792** |
| 256f | 64 | 128 | **49,856** |

All in bytes. Note that public keys are tiny and constant within a security level —
SLH-DSA's cost is entirely in the signature.

## WOTS+ chain counts

`len_1 = ceil(8n / lg_w) = 2n`, `len_2` from
[`gen_len2`](../glossary.md#g), `len = len_1 + len_2`.

| `n` | `len_1` | `len_2` | `len` | WOTS+ signature `len·n` |
|---|---|---|---|---|
| 16 | 32 | 3 | 35 | 560 |
| 24 | 48 | 3 | 51 | 1,224 |
| 32 | 64 | 3 | 67 | 2,144 |

`len_2 = 3` at every security level, since `lg_w` is fixed at 4.

## Digest field widths

`H_msg` emits `m` bytes, split three ways. All widths are byte counts; the values
are then masked to their true bit widths.

| Set | `md`<br/>`ceil(k·a/8)` | `idx_tree`<br/>`ceil((h-h')/8)` | `idx_leaf`<br/>`ceil(h'/8)` | Sum | `m` |
|---|---|---|---|---|---|
| 128s | 21 | 7 | 2 | 30 | 30 ✓ |
| 128f | 25 | 8 | 1 | 34 | 34 ✓ |
| 192s | 30 | 7 | 2 | 39 | 39 ✓ |
| 192f | 33 | 8 | 1 | 42 | 42 ✓ |
| 256s | 39 | 7 | 1 | 47 | 47 ✓ |
| 256f | 40 | 8 | 1 | 49 | 49 ✓ |

The `Sum == m` column is the invariant `slh_dsa.zig` checks at compile time.

## Signature breakdown

```
sig_bytes = n  +  k·(a+1)·n  +  (h + d·len)·n
            R     FORS_SIG      HT_SIG
```

| Set | `R` | `FORS_SIG` | `HT_SIG` | Total | FORS share | HT share |
|---|---|---|---|---|---|---|
| 128s | 16 | 2,912 | 4,928 | 7,856 | 37% | 63% |
| 128f | 16 | 3,696 | 13,376 | 17,088 | 22% | 78% |
| 192s | 24 | 6,120 | 10,080 | 16,224 | 38% | 62% |
| 192f | 24 | 7,128 | 28,512 | 35,664 | 20% | 80% |
| 256s | 32 | 10,560 | 19,200 | 29,792 | 35% | 64% |
| 256f | 32 | 11,200 | 38,624 | 49,856 | 22% | 77% |

The hypertree dominates, and more so for `f` variants: `d = 22` layers each carry a
whole WOTS+ signature. That is the size cost of fast signing.

## Tree geometry

| Set | XMSS leaves per tree `2^h'` | Layers `d` | FORS trees `k` | FORS leaves per tree `2^a` | Total FORS leaves |
|---|---|---|---|---|---|
| 128s | 512 | 7 | 14 | 4,096 | 57,344 |
| 128f | 8 | 22 | 33 | 64 | 2,112 |
| 192s | 512 | 7 | 17 | 16,384 | 278,528 |
| 192f | 8 | 22 | 33 | 256 | 8,448 |
| 256s | 256 | 8 | 22 | 16,384 | 360,448 |
| 256f | 16 | 17 | 35 | 512 | 17,920 |

Reading the `s`/`f` contrast: `s` sets build few, large trees; `f` sets build many,
tiny ones. `128f`'s XMSS trees have **eight** leaves.

## Relative signing cost

Proportional to `d · 2^h'` — the XMSS leaves computed per signature — which is the
dominant term but not the whole story (FORS contributes `k · 2^a` leaves too, at a
much lower per-leaf cost).

| Set | XMSS leaves per signature `d·2^h'` | Relative to `f` |
|---|---|---|
| 128s | 3,584 | 20× |
| 128f | 176 | 1× |
| 192s | 3,584 | 20× |
| 192f | 176 | 1× |
| 256s | 2,048 | 8× |
| 256f | 272 | 1× |

This tracks measurement: on the maintainer's machine (ReleaseFast) SHAKE-128s
signing runs ≈426 ms against 128f's ≈20 ms — a factor of ~21 against the predicted
20×. 128f keygen is ≈0.22 ms and verify ≈0.37 ms.

!!! note "These are indicative, not the benchmark result"

    Figures above come from development runs on one Apple-Silicon machine and exist
    to show the *shape* of the trade-off. The project's actual performance gate —
    within 2× of PQClean's portable `clean` reference, measured and published on
    pinned hardware — is tracked in
    [issue #10](https://github.com/nandanito/slh-dsa-zig/issues/10) and reported in
    `bench/README.md`. Do not quote these numbers as the benchmark.

## Naming

```
slh_dsa_<family>_<level><variant>
         │         │       └─ s = small signature, f = fast signing
         │         └───────── 128 | 192 | 256 (bits; n = 16 | 24 | 32 bytes)
         └─────────────────── sha2 | shake
```

FIPS 205 writes these as `SLH-DSA-SHAKE-128s`; the Zig enum uses
`slh_dsa_shake_128s`. The KAT runner accepts the FIPS spelling.
