# Addresses (ADRS)

**`src/address.zig`** — FIPS 205 §4.2 (types and fields), §11.2 (compressed
encoding).

## What an address is for

Every keyed hash in SLH-DSA takes an `ADRS` saying **where in the structure this
hash is happening**: which hypertree layer, which tree, which leaf, which chain,
which step. It is mixed into the hash input, so the function applied at each
position is effectively unique to that position.

Without it, two structurally identical positions anywhere in a `2^68`-node
structure would compute identical hashes, and an attacker could relocate subtrees
or amortise one precomputation across every target in the scheme — the
multi-target attack from
[chapter 2](../concepts/wots.md#what-the-adds).

!!! danger "Address bugs are the quiet kind"

    A wrong `ADRS` produces a library that is *self-consistent*: it signs, it
    verifies its own signatures, its round-trip tests pass. It just computes
    different values than every other implementation, and its multi-target
    security may be gone. Only KATs catch this. It is the strongest argument for
    not declaring any component functional before ACVP vectors pass.

## Type values

FIPS 205 §4.2 Table 1 — seven types, each giving different meanings to the
address's three variable slots:

```zig
pub const AdrsType = enum(u8) {
    wots_hash  = 0,   // a step within a WOTS+ chain
    wots_pk    = 1,   // compressing a WOTS+ public key into a leaf
    tree       = 2,   // an internal XMSS node
    fors_tree  = 3,   // a FORS tree node
    fors_roots = 4,   // compressing the k FORS roots
    wots_prf   = 5,   // deriving a WOTS+ secret
    fors_prf   = 6,   // deriving a FORS secret
};
```

The `_prf` types matter: secret *derivation* uses a different address type from
secret *use*, so `PRF` and `F` can never be induced to produce the same output
for the same position.

## The compressed encoding

FIPS 205 defines two encodings. The 22-byte compressed form (`ADRSc`) is
**mandatory for SHA-2** and is what this library stores:

```
offset  field                 bytes
──────  ────────────────────  ─────
0       layer address           1
1       tree address            8
9       type                    1
10      type-specific          12   (3 × 4-byte fields)
──────                        ─────
                                22
```

The three 4-byte slots at offset 10 are reinterpreted per type — for
`wots_hash` they are (key-pair address, chain address, hash address); for `tree`
they are (padding, tree height, tree index). The accessors name them:

```zig
pub fn setLayer(self: *Adrs, layer: u8) void
pub fn setTreeAddress(self: *Adrs, tree_address: u64) void
pub fn setType(self: *Adrs, t: AdrsType) void
pub fn setKeyPairAddress(self: *Adrs, key_pair_address: u32) void
pub fn setChainAddress(self: *Adrs, chain_address: u32) void
pub fn setHashAddress(self: *Adrs, hash_address: u32) void
pub fn setTreeHeight(self: *Adrs, tree_height: u32) void
pub fn setTreeIndex(self: *Adrs, tree_index: u32) void
```

!!! warning "`setType` clears the tail"

    FIPS 205 §4.3 requires that setting the type zeroes the remaining fields:
    *"the remaining fields of ADRS shall be set to zero"*. `setType` does this.
    Forgetting it lets stale values from a previous use leak into the address, and
    since the leak is deterministic, it produces consistently wrong output that
    round-trips fine. Another KAT-only bug.

## The 22-versus-32-byte trap

This is the most consequential subtlety in the module, and it caught this project
during development.

**The two hash families hash different address sizes.**

- **§11.2 (SHA-2)** hashes the **22-byte compressed** `ADRSc`.
- **§11.1 (SHAKE)** hashes the **full 32-byte** `ADRS`.

An implementation that stores only `ADRSc` and feeds it to both families produces
correct SHA-2 output and **wrong SHAKE output**. Both still round-trip against
themselves, so only the SHAKE KATs reveal it.

The fix is `expand()`, reconstructing the full form. FIPS 205 §11.2 defines the
compression as:

```
ADRSc = ADRS[3] ‖ ADRS[8:16] ‖ ADRS[19] ‖ ADRS[20:32]
```

so the inverse zero-pads the dropped high-order bytes:

```zig
pub fn expand(self: Adrs) [32]u8 {
    var out = std.mem.zeroes([32]u8);
    out[3] = self.bytes[0];              // layer: low byte of a BE u32
    @memcpy(out[8..16], self.bytes[1..9]); // tree: low 8 of 12 BE bytes
    out[19] = self.bytes[9];             // type: low byte of a BE u32
    @memcpy(out[20..32], self.bytes[10..22]); // type-specific: verbatim
    return out;
}
```

This is a faithful inverse **only if nothing ever wrote into the dropped
high-order bytes**. That precondition holds by construction here: the setters
take a `u8` layer, a `u64` tree address and a `u8` type, so the bytes `expand`
zero-fills could never have held anything else. The full 32-byte layout:

| offset | bytes | field |
|---|---|---|
| 0 | 4 | layer address (big-endian `u32`) |
| 4 | 12 | tree address (big-endian) |
| 16 | 4 | type (big-endian `u32`) |
| 20 | 12 | type-specific |

Storing the compressed form and expanding on demand — rather than storing 32
bytes and compressing — keeps the struct small, keeps the SHA-2 path
allocation- and conversion-free, and puts the conversion cost on the family that
needs it.

## Endianness

All multi-byte address fields are **big-endian**, matching FIPS 205's `toByte`
convention throughout ([`src/util.zig`](../reference/spec-map.md)). Getting this
backwards is another silently-self-consistent failure.

## Constant-time notes

Addresses are **public**. Layer, tree, leaf and chain indices all derive from the
message digest, which is in the signature. So:

- Branching on address contents is fine.
- Indexing memory by an address field is fine.
- `ADRS` needs no zeroization.

This matters for the [constant-time work](../implementation/constant-time.md):
the reason a full-signing ctgrind audit reports false positives is precisely that
public-but-secret-*derived* values like these legitimately steer control flow.
Distinguishing "derived from the secret key" from "actually secret" requires
declassification hooks, which is why that audit is still open.
