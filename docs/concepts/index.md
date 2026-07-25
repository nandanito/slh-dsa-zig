# How it works

Eight chapters that build SLH-DSA from nothing. **Read them in order** — each
one opens by naming the problem the previous chapter left behind, and closes by
creating the problem the next one solves.

That structure is the point. Read in order, the scheme is a sequence of forced
moves. Read out of order, it is a pile of arbitrary constructions with strange
names.

| # | Chapter | Problem it solves | What it leaves broken |
|---|---|---|---|
| 1 | [One-time signatures](one-time-signatures.md) | Sign *anything* using only a hash function | Colossal keys; exactly one signature ever |
| 2 | [Winternitz and WOTS+](wots.md) | Shrink the one-time signature ~8× | Still exactly one signature per key |
| 3 | [Merkle trees](merkle-trees.md) | One public key certifies many one-time keys | Key generation cost doubles per extra height |
| 4 | [XMSS](xmss.md) | Make that practical and multi-target-safe | Signer must track which leaf is next |
| 5 | [The statefulness problem](statefulness.md) | Remove the state — choose the leaf from the message | Index collisions: keys get reused |
| 6 | [FORS](fors.md) | Survive key reuse — a *few*-time signature | FORS keys still need certifying, and the tree is too tall |
| 7 | [The hypertree](hypertree.md) | Make a height-63 tree computable | Nothing — this is the last piece |
| 8 | [Putting it together](assembly.md) | The complete scheme, end to end | — |

## Notation used throughout

Worth skimming now; all of it recurs. Fuller definitions in the
[glossary](../glossary.md).

| Symbol | Meaning | Typical value |
|---|---|---|
| `n` | Security parameter, in **bytes**. Every hash output is truncated to `n`. | 16, 24, 32 |
| `H`, `F`, `T_l` | Hash functions: `F` on one `n`-byte block, `T_l` on `l` of them | — |
| `PRF` | Pseudorandom function used to *derive* secret keys instead of storing them | — |
| `w`, `lg_w` | Winternitz parameter and its log. FIPS 205 fixes `lg_w = 4`, `w = 16`. | 16, 4 |
| `len` | Number of WOTS+ chains per one-time key (`len_1 + len_2`) | 35, 51, 67 |
| `h` | Total hypertree height | 63–68 |
| `d` | Number of hypertree layers | 7–22 |
| `h'` | Height of each XMSS tree; always `h / d` | 3–9 |
| `a` | FORS tree height, so `2^a` leaves per tree | 6–14 |
| `k` | Number of FORS trees | 14–35 |
| `ADRS` | Address — *where in the structure* a hash is happening | 22 or 32 B |

Two conventions that trip people up:

!!! info "`n` is in bytes, not bits"

    FIPS 205 uses `n` for a byte count. `n = 16` is the 128-bit security level.
    Papers that use `n` for a bit count read as if everything is eight times too
    small.

!!! info "Trees are indexed from the leaves"

    Height `z = 0` is the leaf layer; `z = h'` is the root. `xmss_node(i, z)`
    means "node `i` at height `z`", counting up.

## The one thing to hold onto

Almost every structure below is a **Merkle tree over pseudorandomly derived
secrets**. Nothing is stored that can be recomputed: a one-time key's secret
material is `PRF(SK.seed, ADRS)`, regenerated on demand from the address of the
place it belongs. That single decision is why a 64-byte private key can stand in
for a structure with `2^68` leaves — and also why signing is expensive, because
"regenerate on demand" means rebuilding whole trees per signature.

[Start: One-time signatures →](one-time-signatures.md){ .md-button .md-button--primary }
