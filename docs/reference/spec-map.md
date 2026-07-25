# FIPS 205 map

Every algorithm in the standard, and where it lives.

!!! danger "Verify numbers against the final PDF"

    The final FIPS 205 (August 2024) inserted **`gen_len2` as Algorithm 1 (§3.2)**,
    which was absent from the initial public draft. Every later algorithm number
    shifted up by one, and the WOTS+ subsections were renumbered
    (`chain` → §5, `wots_pkGen` → §5.1, `wots_sign` → §5.2,
    `wots_pkFromSig` → §5.3).

    Any algorithm number from a draft-era paper, blog post, or pre-2024 codebase is
    very likely **one too low**. This project tracks the full draft→final mapping in
    [issue #16](https://github.com/nandanito/slh-dsa-zig/issues/16).

## Section to file

```
FIPS 205 §3    — Notation and conventions       src/util.zig
FIPS 205 §4.2  — ADRS type values               src/address.zig
FIPS 205 §4.3  — ADRS structure                 src/address.zig
FIPS 205 §5    — WOTS+                          src/wots.zig
FIPS 205 §6    — XMSS                           src/xmss.zig
FIPS 205 §7    — Hypertree                      src/hypertree.zig
FIPS 205 §8    — FORS                           src/fors.zig
FIPS 205 §9    — SLH-DSA (internal interface)   src/slh_dsa.zig
FIPS 205 §10   — SLH-DSA (external interface)   src/slh_dsa.zig
FIPS 205 §11   — Parameter sets                 src/params.zig
FIPS 205 §11.1 — Hash functions (SHAKE)         src/hash_shake.zig
FIPS 205 §11.2 — Hash functions (SHA-2)         src/hash_sha2.zig
```

## Algorithm to function

### Supporting functions — §3

| Alg | § | Name | Implementation |
|---|---|---|---|
| 1 | 3.2 | `gen_len2` | `Params.len_2()` — `src/params.zig` |
| 2 | 3.1 | `toInt` | `util.toInt` |
| 3 | 3.1 | `toByte` | `util.toByte` |
| 4 | 3.1 | `base_2b` | `util.base_2b` |

### WOTS+ — §5

| Alg | § | Name | Implementation |
|---|---|---|---|
| 5 | 5 | `chain` | `Wots(p).chain` — [notes](../components/wots.md#chain-5-algorithm-5) |
| 6 | 5.1 | `wots_pkGen` | `Wots(p).pkGen` |
| 7 | 5.2 | `wots_sign` | `Wots(p).sign` |
| 8 | 5.3 | `wots_pkFromSig` | `Wots(p).pkFromSig` |

### XMSS — §6

| Alg | § | Name | Implementation |
|---|---|---|---|
| 9 | 6.1 | `xmss_node` | `Xmss(p).node` — [notes](../components/xmss.md#node-61-algorithm-9) |
| 10 | 6.2 | `xmss_sign` | `Xmss(p).sign` |
| 11 | 6.3 | `xmss_pkFromSig` | `Xmss(p).pkFromSig` |

### Hypertree — §7

| Alg | § | Name | Implementation |
|---|---|---|---|
| 12 | 7.1 | `ht_sign` | `Hypertree(p).sign` |
| 13 | 7.2 | `ht_verify` | `Hypertree(p).verify` |

### FORS — §8

| Alg | § | Name | Implementation |
|---|---|---|---|
| 14 | 8.1 | `fors_skGen` | `Fors(p).skGen` |
| 15 | 8.2 | `fors_node` | `Fors(p).node` |
| 16 | 8.3 | `fors_sign` | `Fors(p).sign` |
| 17 | 8.4 | `fors_pkFromSig` | `Fors(p).pkFromSig` |

### Internal interface — §9

| Alg | § | Name | Implementation |
|---|---|---|---|
| 18 | 9.1 | `slh_keygen_internal` | `KeyPair.fromSeeds` |
| 19 | 9.2 | `slh_sign_internal` | `signInternal` → `signCore` |
| 20 | 9.3 | `slh_verify_internal` | `verifyInternal` → `verifyCore` |

### External interface — §10

| Alg | § | Name | Implementation |
|---|---|---|---|
| 21 | 10.1 | `slh_keygen` | `KeyPair.generate` |
| 22 | 10.2 | `slh_sign` | `signWithContext` (and `sign`, `ctx = ""`) |
| 23 | 10.2 | `hash_slh_sign` | **Deferred** — [decision](../concepts/assembly.md#context-strings) |
| 24 | 10.3 | `slh_verify` | `verifyWithContext` (and `verify`, `ctx = ""`) |
| 25 | 10.3 | `hash_slh_verify` | **Deferred** |

## The six hash functions — §11

Dispatched by `Hash(p)` in `src/hash.zig`; implemented in `hash_shake.zig` (§11.1)
and `hash_sha2.zig` (§11.2).

| Function | Signature | SHAKE (§11.1) | SHA-2 (§11.2) |
|---|---|---|---|
| `PRF` | `(sk_seed, pk_seed, ADRS) → n` | SHAKE256 absorb/squeeze | keyed SHA-2 with block padding |
| `PRF_msg` | `(sk_prf, opt_rand, M') → n` | SHAKE256 | **HMAC**-SHA-256/512 |
| `H_msg` | `(R, pk_seed, pk_root, M') → m` | SHAKE256, squeeze `m` | **MGF1** over SHA-256/512 |
| `F` | `(pk_seed, ADRS, 1 block) → n` | SHAKE256 | **SHA-256 at every level** |
| `H` | `(pk_seed, ADRS, l, r) → n` | SHAKE256 | SHA-256/512 |
| `T_l` | `(pk_seed, ADRS, l blocks) → n` | SHAKE256 | SHA-256/512 |

Two asymmetries worth re-reading:

- **SHAKE uses SHAKE-256 at every security level.** There is no SHAKE-128 variant;
  `n` changes only the squeeze length.
- **SHA-2 keeps `F` on SHA-256 at every level**, while the message functions move to
  SHA-512 for `n = 24, 32`. `F` is the most-invoked function in the scheme, so this
  is a deliberate performance choice. Implementing it as SHA-512 fails every
  category-3/5 vector.

Full detail: [the hash interface](../components/hashing.md).

## ADRS types — §4.2 Table 1

| Value | Name | Used for |
|---|---|---|
| 0 | `WOTS_HASH` | A step within a WOTS+ chain |
| 1 | `WOTS_PK` | Compressing a WOTS+ public key into a leaf |
| 2 | `TREE` | An internal XMSS node |
| 3 | `FORS_TREE` | A FORS tree node |
| 4 | `FORS_ROOTS` | Compressing the `k` FORS roots |
| 5 | `WOTS_PRF` | Deriving a WOTS+ secret |
| 6 | `FORS_PRF` | Deriving a FORS secret |

`src/address.zig` as `AdrsType`. Note the separate `_PRF` types for *deriving* a
secret versus *using* it — see [ADRS](../components/adrs.md#type-values).

## Not implemented

| Feature | Status |
|---|---|
| HashSLH-DSA (Algorithms 23, 25) | Deferred by recorded decision |
| Runtime parameter-set dispatch | [Deliberate non-goal](../implementation/index.md#deliberate-non-goals) |
| SIMD / vectorised Keccak | Deliberate non-goal; the bench gate is pinned to PQClean `clean` accordingly |
