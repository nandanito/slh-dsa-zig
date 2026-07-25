# FORS

**`src/fors.zig`** — FIPS 205 §8, Algorithms 14–17.

Concepts: [chapter 6](../concepts/fors.md).

## Sizes

```zig
pub const md_bytes: usize = (k * a + 7) / 8;      // packed k×a bits
pub const signature_bytes: usize = k * (a + 1) * n;
```

`md_bytes` is the FORS share of the `H_msg` output — see
[digest parsing](scheme.md#digest-parsing).

| Set | `k` | `a` | `md_bytes` | FORS signature |
|---|---|---|---|---|
| 128s | 14 | 12 | 21 | 2,912 B |
| 128f | 33 | 6 | 25 | 3,696 B |
| 256s | 22 | 14 | 39 | 10,560 B |

## `skGen` — §8.1, Algorithm 14

```zig
var sk_adrs = adrs.*;
sk_adrs.setType(.fors_prf);
sk_adrs.setKeyPairAddress(adrs.getKeyPairAddress());
sk_adrs.setTreeIndex(idx);
Hash.prf(sk_seed, pk_seed, &sk_adrs, out);
```

`.fors_prf` is the derivation type, distinct from `.fors_tree` used when the
value is consumed. `setTreeIndex(idx)` takes a **global** leaf index across the
whole forest, not an index within one tree — see the `leaf` computation in `sign`.

## `node` — §8.2, Algorithm 15

Structurally identical to [`xmss_node`](xmss.md#node-61-algorithm-9), with one
important difference in the base case:

```zig
if (z == 0) {
    var sk: [n]u8 = undefined;
    defer std.crypto.secureZero(u8, &sk);   // ← secret
    skGen(sk_seed, pk_seed, adrs, i, &sk);
    adrs.setTreeHeight(0);
    adrs.setTreeIndex(i);
    Hash.f(pk_seed, adrs, &sk, out);
} else {
    var lnode: [n]u8 = undefined;
    var rnode: [n]u8 = undefined;
    node(sk_seed, 2 * i,     z - 1, pk_seed, adrs, &lnode);
    node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs, &rnode);
    adrs.setTreeHeight(z);
    adrs.setTreeIndex(i);
    Hash.h(pk_seed, adrs, &lnode, &rnode, out);
}
```

**A FORS leaf is `F` over one derived secret.** An XMSS leaf is `T_len` over a
whole WOTS+ public key — `len` chains of up to `w-1` steps each, ~500 hashes. A
FORS leaf is **two** hash calls: one `PRF`, one `F`. FORS trees are therefore far
cheaper per leaf than XMSS trees of the same height, which is why `a` can be as
large as 14 while `h'` stays at 9.

**`sk` is scrubbed here but revealed in `sign`.** Same value, different lifetime.
When `node` computes an *internal* value the secret is an intermediate that must
not persist. When `sign` reveals a leaf it becomes part of the signature — public
by definition. Two call sites, two correct behaviours, and the comments in the
source say which is which.

!!! warning "This is the library's most secret-adjacent code"

    `skGen` and `node`'s base case are where `SK.seed` is expanded into leaf
    secrets, making them the primary target of the
    [ctgrind harness](../implementation/constant-time.md) — which taints
    `SK.seed` and runs `fors_node` under Valgrind for both hash families. A timing
    leak here would be a leak of key material, not of a public index.

## `sign` — §8.3, Algorithm 16

```zig
var indices: [k]u32 = undefined;
util.base_2b(md, a_bits, &indices);          // k indices of a bits each

const block = (a + 1) * n;
for (0..k) |i| {
    const base = i * block;
    const tree: u32 = @intCast(i);
    const leaf = tree * two_pow_a + indices[i];

    // The revealed secret goes straight into the signature buffer.
    skGen(sk_seed, pk_seed, adrs, leaf, out_sig[base..][0..n]);

    for (0..a) |j| {
        const s = (indices[i] >> @as(u5, @intCast(j))) ^ 1;
        const sib = tree * (two_pow_a >> @as(u5, @intCast(j))) + s;
        node(sk_seed, sib, @intCast(j), pk_seed, adrs, out_sig[base + (1 + j) * n ..][0..n]);
    }
}
```

**Global indexing across the forest.** `leaf = tree * 2^a + indices[i]` — the `k`
trees share one flat index space, so tree 3's leaf 7 and tree 4's leaf 7 get
different addresses and therefore different secrets. The sibling computation
`tree * (2^a >> j) + s` applies the same offsetting at height `j`, where the tree
has `2^a >> j` nodes.

**The revealed secret is written directly to `out_sig`.** No temporary, no
scrubbing — it is signature material. Contrast `node`'s base case above.

**Layout is `k` blocks of `(1 + a)` values**: the leaf secret, then `a`
authentication nodes bottom-up.

## `pkFromSig` — §8.4, Algorithm 17

For each tree: hash the revealed secret to a leaf, fold the auth path, collect the
root. Then compress all `k` roots:

```zig
// per tree i: node = F(revealed secret), then fold a auth nodes
// roots[i] = the reconstructed root of tree i

var pk_adrs = adrs.*;
pk_adrs.setType(.fors_roots);
pk_adrs.setKeyPairAddress(adrs.getKeyPairAddress());
Hash.t_l(pk_seed, &pk_adrs, &roots, out_pk);
```

`.fors_roots` is a fourth distinct address type, so compressing `k` FORS roots
cannot be confused with any other multi-block compression in the scheme.

Returns the reconstructed FORS public key. The
[top level](scheme.md) does not compare it to anything — it hands it to the
hypertree as the message to certify.

## Constant-time notes

The `indices` derived from `md` are **public**: `md` comes from `H_msg`, and a
verifier recomputes it from `R` and the message, both in the signature. So
branching and indexing on `indices` is safe, and the loop structure of `sign`
leaks nothing an attacker does not already hold.

What is secret is `sk_seed` and the derived leaf values at *unrevealed*
positions. Those flow only through `PRF` and `F`, never into a branch condition or
a memory index.

## Tests in this module

- `node` at `z = 1` checked by hand against `H(F(sk_0), F(sk_1))`, independent of
  the recursion.
- Round-trip: signing then reconstructing recovers the FORS public key.
- Negatives: tampering a revealed secret or an auth node changes the result.
- Distinctness: the same leaf index in different trees yields different secrets —
  verifying the global-index offsetting.
