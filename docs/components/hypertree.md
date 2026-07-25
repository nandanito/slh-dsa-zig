# Hypertree

**`src/hypertree.zig`** — FIPS 205 §7, Algorithms 12–13.

Concepts: [chapter 7](../concepts/hypertree.md).

## Sizes

```zig
pub const signature_bytes: usize = d * Xmss.signature_bytes;
```

`d` XMSS signatures back to back — `d · (len·n + h'·n)` = `(h + d·len)·n` bytes.
For 128s: 7 × 704 = 4,928 bytes, 63% of the whole signature.

## The index arithmetic

Two comptime constants drive everything:

```zig
const h_prime_shift: u6 = @intCast(p.h_prime);
const leaf_mask: u64 = (@as(u64, 1) << h_prime_shift) - 1;
```

Climbing one layer consumes `h'` bits of `idx_tree`:

```zig
const leaf: u32 = @intCast(tree & leaf_mask);  // low h' bits → leaf at this layer
tree >>= h_prime_shift;                        // the rest → which tree
```

After `d` iterations `tree` is zero — one tree at the top, its root being
`PK.root`. That this works out exactly is why `h = h' · d` must hold, and why
`params.zig` [asserts it at compile time](parameters.md#the-comptime-self-check).

## `sign` — §7.1, Algorithm 12

```zig
var adrs = address.Adrs.init();
adrs.setTreeAddress(idx_tree);

// Layer 0 signs the actual message (the FORS public key).
const bottom = out_sig[0..Xmss.signature_bytes];
Xmss.sign(msg, sk_seed, idx_leaf, pk_seed, &adrs, bottom);

var root: [n]u8 = undefined;
Xmss.pkFromSig(idx_leaf, bottom, msg, pk_seed, &adrs, &root);

// Layers 1..d-1 each sign the root below.
var tree = idx_tree;
var j: usize = 1;
while (j < d) : (j += 1) {
    const leaf: u32 = @intCast(tree & leaf_mask);
    tree >>= h_prime_shift;
    adrs.setLayer(@intCast(j));
    adrs.setTreeAddress(tree);

    const layer = out_sig[j * Xmss.signature_bytes ..][0..Xmss.signature_bytes];
    Xmss.sign(&root, sk_seed, leaf, pk_seed, &adrs, layer);

    if (j < d - 1) {
        var next_root: [n]u8 = undefined;
        Xmss.pkFromSig(leaf, layer, &root, pk_seed, &adrs, &next_root);
        root = next_root;
    }
}
```

Three points worth dwelling on.

**Signing calls `pkFromSig` to get the root.** It could instead call
`Xmss.node(sk_seed, 0, h', …)` to compute the root directly. Using `pkFromSig` is
both cheaper — it folds the auth path it just produced, `h'` hashes, rather than
rebuilding the tree — and safer: it guarantees the value the next layer signs is
*exactly* what a verifier will reconstruct. If the two ever disagreed, signatures
would fail to verify; deriving one from the other makes disagreement impossible.

**`if (j < d - 1)` skips the last root.** The top layer's root *is* `PK.root`, and
nothing signs it — it is already in the public key. Computing it would be wasted
work.

**`setLayer` distinguishes the layers.** Two trees at different layers can share a
tree address, so without the layer in the address they would produce identical
nodes and become interchangeable.

## `verify` — §7.2, Algorithm 13

The mirror image, and notably simple:

```zig
var node: [n]u8 = undefined;
Xmss.pkFromSig(idx_leaf, sig[0..Xmss.signature_bytes], msg, pk_seed, &adrs, &node);

var tree = idx_tree;
var j: usize = 1;
while (j < d) : (j += 1) {
    const leaf: u32 = @intCast(tree & leaf_mask);
    tree >>= h_prime_shift;
    adrs.setLayer(@intCast(j));
    adrs.setTreeAddress(tree);

    const layer = sig[j * Xmss.signature_bytes ..][0..Xmss.signature_bytes];
    var next: [n]u8 = undefined;
    Xmss.pkFromSig(leaf, layer, &node, pk_seed, &adrs, &next);
    node = next;
}

return std.mem.eql(u8, &node, pk_root);
```

The whole verification is `d` reconstructions and **one comparison**. Each layer's
output feeds the next as its message. This is the payoff for
`pkFromSig` returning a value instead of a boolean — see
[the convention](index.md#conventions-across-every-module).

!!! note "Why `std.mem.eql` and not a constant-time compare"

    A plain comparison here is correct, and this is worth being explicit about
    because "use constant-time comparison for cryptographic values" is a good
    reflex that does not apply.

    Every input to `ht_verify` is public: the signature came off the wire, `PK.seed`
    and `PK.root` are the public key, and the reconstructed node is a deterministic
    function of public data. There is no secret whose timing could leak. An
    attacker learning *how many leading bytes of their forgery matched* gains
    nothing they could not compute themselves.

    Contrast a MAC comparison, where the expected tag is secret and an early-exit
    compare leaks it byte by byte. Different situation, different requirement.

    `verify` returns `bool` rather than an error union precisely because it is a
    pure predicate over public data; the top level converts it to
    `error.InvalidSignature`.

## Constant-time notes

`idx_tree` and `idx_leaf` come from the message digest and are recoverable from
the signature — **public**. Branching and indexing on them is fine.

`sk_seed` flows into `Xmss.sign` → `Wots.pkGen` → `PRF`, and is scrubbed by the
buffers that hold derived material. See
[constant-time discipline](../implementation/constant-time.md) for what has been
empirically verified versus what remains open.

## Tests in this module

- Round-trip: a hypertree signature reconstructs to `PK.root`.
- Negatives: tampering any layer's signature, or passing wrong indices, fails.
- Index arithmetic checked against the `h = h' · d` relation for every set.
