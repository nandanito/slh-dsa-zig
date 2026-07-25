# XMSS

**`src/xmss.zig`** — FIPS 205 §6, Algorithms 9–11.

Concepts: [chapter 4](../concepts/xmss.md).

## Sizes

```zig
pub const tree_leaves: usize = 1 << h_prime;
pub const signature_bytes: usize = Wots.signature_bytes + h_prime * n;
```

An XMSS signature is a WOTS+ signature followed by `h'` authentication nodes. For
`n = 16, h' = 9`: 560 + 144 = 704 bytes.

## `node` — §6.1, Algorithm 9

The recursive core. Base case is a WOTS+ public key; inductive case hashes two
children:

```zig
pub fn node(sk_seed, i: u32, z: u32, pk_seed, adrs, out) void {
    std.debug.assert(z <= p.h_prime);
    std.debug.assert(i < @as(u32, 1) << @as(u5, @intCast(p.h_prime - z)));

    if (z == 0) {
        adrs.setType(.wots_hash);
        adrs.setKeyPairAddress(i);
        Wots.pkGen(sk_seed, pk_seed, adrs, out);
    } else {
        var lnode: [n]u8 = undefined;
        var rnode: [n]u8 = undefined;
        node(sk_seed, 2 * i,     z - 1, pk_seed, adrs, &lnode);
        node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs, &rnode);
        adrs.setType(.tree);
        adrs.setTreeHeight(z);
        adrs.setTreeIndex(i);
        Hash.h(pk_seed, adrs, &lnode, &rnode, out);
    }
}
```

**The asserts encode FIPS 205 §6.1's validity conditions** — `z ≤ h'` and
`i < 2^(h'-z)`. Both `z` and `i` are public (they come from tree geometry and the
message digest), so asserting on them is constant-time-safe. They are
`std.debug.assert`, so they vanish in release builds; their job is catching
caller bugs during development, not defending against attacker input.

**`setType` before hashing, every time.** The recursive calls leave the address's
type-specific fields set to whatever the children needed. Per
[§4.3](adrs.md#the-22-versus-32-byte-trap) `setType` clears them, and
`setTreeHeight`/`setTreeIndex` then set this node's own. Skipping the reset lets a
child's coordinates leak into the parent's tweak.

**`lnode`/`rnode` are not scrubbed.** They hold compressed WOTS+ public keys —
public by definition. Only `Wots.pkGen`'s internal `sk` buffer is secret, and it
scrubs itself.

### Performance note

The implementation is literally recursive, matching the standard's formulation.
Recursion depth is bounded by `h' ≤ 9` across all twelve parameter sets, so stack
use is a few hundred bytes — no concern even on constrained targets.

The reference SPHINCS+ implementation instead uses an **iterative treehash**: walk
leaves left to right, push each onto a stack, and merge whenever the top two nodes
are at the same height. The advantage is not memory but *work sharing* — see the
note under `sign` below. Adopting it is an open optimisation avenue, tracked with
the [benchmark work](../implementation/testing.md#benchmarks).

## `sign` — §6.2, Algorithm 10

```zig
const auth = out_sig[Wots.signature_bytes..];
for (0..h_prime) |j| {
    const k = (idx >> @as(u5, @intCast(j))) ^ 1;
    node(sk_seed, k, @intCast(j), pk_seed, adrs, auth[j * n ..][0..n]);
}

adrs.setType(.wots_hash);
adrs.setKeyPairAddress(idx);
Wots.sign(msg, sk_seed, pk_seed, adrs, out_sig[0..Wots.signature_bytes]);
```

**`(idx >> j) ^ 1` is the sibling index.** Shift right by `j` to get this node's
index at height `j`, then flip the low bit to get its sibling. That one expression
is the whole authentication path computation.

!!! warning "This is the naive `O(2^h')` path, deliberately"

    Each of the `h'` siblings is computed by a fresh `node` call, which rebuilds
    that sibling's **entire subtree** from scratch. The subtree at height `h'-1`
    alone is half the tree. Summed over all heights, `sign` computes roughly the
    whole tree's worth of leaves — and it recomputes leaves that earlier siblings
    already visited.

    An iterative treehash computes each leaf **once** and harvests all `h'`
    authentication nodes in a single left-to-right sweep, which is close to a 2×
    saving on the dominant cost of signing. This library takes the naive route
    because it matches the standard line for line and is much easier to argue
    correct; the optimisation is a known, measured-later improvement rather than
    an oversight.

**`setType` after the loop.** The auth-path loop leaves the address configured for
tree nodes; the WOTS+ signature needs `.wots_hash` and the leaf's key-pair
address.

## `pkFromSig` — §6.3, Algorithm 11

Reconstructs the root:

```zig
// Leaf from the WOTS+ signature.
adrs.setType(.wots_hash);
adrs.setKeyPairAddress(idx);
Wots.pkFromSig(sig_wots, msg, pk_seed, adrs, &wots_pk);
adrs.setType(.wots_pk);
adrs.setKeyPairAddress(idx);
Hash.t_l(pk_seed, adrs, &wots_pk, &node0);

// Fold the authentication path upward.
adrs.setType(.tree);
for (0..h_prime) |j| {
    adrs.setTreeHeight(j + 1);
    if ((idx >> j) & 1 == 0) {
        adrs.setTreeIndex(adrs.getTreeIndex() / 2);
        Hash.h(pk_seed, adrs, &node0, auth_j, &node0);   // we are the left child
    } else {
        adrs.setTreeIndex((adrs.getTreeIndex() - 1) / 2);
        Hash.h(pk_seed, adrs, auth_j, &node0, &node0);   // we are the right child
    }
}
```

**Bit `j` of `idx` decides the order.** Zero means this node is the left child, so
it goes first; one means it goes second. Reversing this computes a wrong root that
is perfectly self-consistent — and only KATs will tell you.

**The tree index halves each level**, with the `-1` on the odd branch. This is the
kind of index arithmetic that is easy to get subtly wrong and impossible to detect
without vectors.

The function **returns the root** rather than comparing it. In the hypertree, that
returned root becomes the message for the layer above — see
[hypertree](hypertree.md).

## Tests in this module

- `node` at `z = 1` checked by hand against `H(pkGen(0), pkGen(1))`, verifying the
  inductive case independently of the recursion.
- Round-trip: an XMSS signature on any leaf reconstructs to `node(0, h')`.
- Negatives: tampered WOTS+ portion, tampered auth path, and wrong leaf index all
  produce a different root.
