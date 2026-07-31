# 4. XMSS

!!! abstract "Where we are"

    **Left over from [chapter 3](merkle-trees.md):** a Merkle tree over WOTS+
    keys works, but the hashing must be position-aware, and we need a concrete
    specification rather than a sketch.
    **Goal:** name and pin down the combination.

## The combination

**XMSS** — the eXtended Merkle Signature Scheme — is exactly
[chapter 2](wots.md) plus [chapter 3](merkle-trees.md), made rigorous:

> a Merkle tree of height `h'` whose leaves are WOTS+ public keys, with every
> hash tweaked by `PK.seed` and an `ADRS` giving its position.

It exists as a standard in its own right ([RFC 8391][rfc8391]) and is deployed
where a stateful signer is acceptable. In SLH-DSA it is a **component**: the
hypertree of [chapter 7](hypertree.md) is a stack of XMSS trees.

## Three operations

FIPS 205 §6 gives XMSS three algorithms — implemented in
[`src/xmss.zig`](../components/xmss.md):

| Algorithm | Section | Purpose |
|---|---|---|
| `xmss_node` | §6.1, Alg 9 | Compute the node at height `z`, index `i` — recursively |
| `xmss_sign` | §6.2, Alg 10 | WOTS+ signature + authentication path |
| `xmss_pkFromSig` | §6.3, Alg 11 | Reconstruct the root from a signature |

### `xmss_node` — the recursive heart

Everything else is built on this. It says: to get a node, get its two children
and hash them.

```
xmss_node(i, z):
    if z == 0:                        # leaf layer
        return T_len( wots_pkGen(leaf i) )
    else:
        left  = xmss_node(2i,     z-1)
        right = xmss_node(2i + 1, z-1)
        return H(left || right)
```

The base case compresses a whole WOTS+ public key (`len` blocks of `n` bytes)
into a single `n`-byte leaf using the multi-block tweakable hash `T_len`. The
recursive case is ordinary Merkle hashing.

!!! warning "This recursion is the cost centre"

    `xmss_node(0, h')` — computing a root — expands into `2^h'` leaf
    computations, each a full `wots_pkGen` running `len` chains of up to `w-1`
    steps. For `h' = 9`, `len = 35`, `w = 16` that is on the order of 512 × 35 ×
    15 ≈ 270,000 hash invocations for **one root**, and a signature computes
    several roots. When you see SLH-DSA benchmarks in the hundreds of
    milliseconds, this recursion is where the time goes.

    This library implements it as written — genuine recursion, depth bounded by
    `h' ≤ 9` across all parameter sets, so a handful of `n`-byte locals per frame.
    The SPHINCS+ reference implementation instead uses an iterative *treehash*
    that computes leaves left to right and merges completed subtrees with an
    explicit stack. That is a control-flow difference, not a work saving: one
    root costs `2^h'` leaf computations either way. The cost centre is real — it
    is simply not *redundant* work, here or in `xmss_sign` — see
    [the component page](../components/xmss.md#performance-note).

### `xmss_pkFromSig` — verification by reconstruction

Note the name, matching `wots_pkFromSig`. XMSS verification does not compare
against a stored root; it **recomputes** one:

```
xmss_pkFromSig(idx, sig, M):
    node = T_len( wots_pkFromSig(sig.wots, M) )     # leaf from the WOTS+ sig
    for z in 0 .. h'-1:
        if bit z of idx == 0:
            node = H(node || sig.auth[z])           # we are the left child
        else:
            node = H(sig.auth[z] || node)           # we are the right child
    return node
```

The caller compares the returned root to what it expected. A wrong signature, a
wrong message or a wrong index all produce a wrong root and fail the comparison.

This "return a value, let the caller compare" shape is what makes XMSS stackable.
In the hypertree, the returned root is not compared against the public key at all
— it becomes **the message for the layer above**. [Chapter 7](hypertree.md) uses
this directly.

## Why the address matters so much here

The same `H` compresses every internal node of every tree. Without a tweak,
identical child pairs anywhere in the structure would hash identically, and an
attacker could relocate a subtree from one position to another — or amortise
precomputation across the entire structure, the multi-target attack from
[chapter 2](wots.md) applied at tree scale.

So each hash is tweaked with an `ADRS` recording:

- the **layer** in the hypertree,
- the **tree address** within that layer,
- the **type** of hash (WOTS+ chain, leaf compression, internal node, …),
- the **height and index** of this node.

Every node in the whole structure is therefore computed by a function unique to
its position. See [ADRS](../components/adrs.md) for the encoding — including a
genuine trap: the SHA-2 and SHAKE families use **different address sizes** (22
bytes compressed versus the full 32), and conflating them yields a library that
passes its own round-trip tests while failing every NIST vector.

## What XMSS does not fix

XMSS inherits both problems unchanged.

**Key generation is still exponential in `h'`.** `xmss_node(0, h')` visits every
leaf. Height 63 remains impossible.

**The signer must still track the index.** Each leaf is one WOTS+ key, usable
exactly once. XMSS-the-standard's answer is to *require the signer to keep
state* — a counter, persisted, monotonic, never rolled back.

That requirement is the subject of the next chapter, and it is the reason
SLH-DSA exists as a separate scheme rather than a parameter choice for XMSS.

!!! success "Chapter 4 outcome"

    XMSS = WOTS+ leaves + Merkle tree + position-tweaked hashing. Three
    algorithms: `xmss_node`, `xmss_sign`, `xmss_pkFromSig`. Verification
    reconstructs a root and hands it back, which makes trees stackable.

    Unfixed: exponential key generation, and a **stateful signer**.

[Chapter 5: The statefulness problem →](statefulness.md){ .md-button .md-button--primary }

[rfc8391]: https://www.rfc-editor.org/rfc/rfc8391
