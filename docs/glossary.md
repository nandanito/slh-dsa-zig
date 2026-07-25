# Glossary

Hash-based signatures carry an unusually dense vocabulary, with several
near-synonyms that mean importantly different things. Alphabetical; use the search
box for anything specific.

---

## A

**`a`**
:   FORS tree height. Each of the `k` FORS trees has `2^a` leaves. Ranges 6–14. See
    [FORS](concepts/fors.md).

**ACVP**
:   NIST's *Automated Cryptographic Validation Protocol* — the source of the
    known-answer test vectors this library validates against. Provides `keyGen`,
    `sigGen` and `sigVer` groups, and certifies pre-hash separately from pure.
    See [testing](implementation/testing.md#known-answer-tests-acvp).

**ADRS**
:   *Address.* The structure passed to every keyed hash saying **where in the
    scheme this hash is happening** — layer, tree, type, and up to three
    type-specific fields. Makes each hash unique to its position, defeating
    [multi-target attacks](#m). See [ADRS](components/adrs.md).

**ADRSc**
:   The **compressed** 22-byte ADRS encoding (FIPS 205 §11.2). Mandatory for
    SHA-2. SHAKE (§11.1) uses the full **32-byte** form instead — conflating them
    is a real and subtle bug. See
    [the trap](components/adrs.md#the-22-versus-32-byte-trap).

**Authentication path**
:   The sibling nodes along a leaf-to-root path in a Merkle tree, `h'` of them for
    height `h'`. Lets a verifier holding only the root recompute it from a leaf.
    The `AUTH` field of an XMSS or FORS signature. See
    [Merkle trees](concepts/merkle-trees.md#proving-a-leaf-belongs).

## B

**`base_2b`**
:   FIPS 205 §3 Algorithm 4. Converts a byte string into base-`2^b` digits.
    Produces WOTS+ chain digits (`b = lg_w`) and FORS tree indices (`b = a`).
    `src/util.zig`.

**Birthday bound**
:   The rule of thumb that collisions among random values from a space of size `N`
    become likely after about `√N` draws. Why message-derived leaf selection
    collides after ~`2^(h/2)` signatures, and therefore why
    [FORS](concepts/fors.md) is needed.

## C

**`chain`**
:   FIPS 205 §5 Algorithm 5. Iterates `F` a given number of steps along a WOTS+
    hash chain. The innermost hot loop of the whole scheme. See
    [WOTS+](components/wots.md#chain-5-algorithm-5).

**Checksum (WOTS+)**
:   Extra base-`w` digits appended to the message digits, computed as
    `Σ (w-1-m_i)`. Because raising any message digit lowers the checksum, forging
    would require walking a chain *backwards*. Without it WOTS+ is trivially
    forgeable. See [chapter 2](concepts/wots.md#the-checksum).

**Comptime**
:   Zig's compile-time evaluation. This library uses it to monomorphise all twelve
    parameter sets, size every buffer statically, and turn FIPS 205's structural
    relations into compile errors. See
    [comptime parameterisation](implementation/comptime.md).

**Constant-time**
:   Execution timing independent of secret data: no secret-dependent branches,
    memory addresses, early returns, or table indices. Note that
    *derived from the secret key* is **not** the same as *secret* — see
    [discipline](implementation/constant-time.md#what-is-actually-secret).

**Context string (`ctx`)**
:   Up to 255 bytes of domain-separation material accepted by the FIPS 205 §10.2
    external interface. Prefixed to the message as
    `0x00 ‖ len(ctx) ‖ ctx ‖ M`. A signature under one context will not verify
    under another. Longer than 255 → `error.ContextTooLong`.

**ctgrind**
:   Adam Langley's technique for verifying constant-time behaviour by marking
    secrets **undefined** in Valgrind and treating any memcheck report as a
    secret-dependent operation. See
    [constant-time](implementation/constant-time.md#how-ctgrind-works).

## D

**`d`**
:   Number of XMSS layers in the hypertree, 7–22. Chosen with `h' = h/d`; the
    `s`/`f` trade-off knob. See [hypertree](concepts/hypertree.md).

**Declassify**
:   Explicitly marking a secret-derived value as public, so taint tracking stops
    following it. The missing piece for the whole-signing constant-time audit —
    see [what is still open](implementation/constant-time.md#what-is-still-open).

**Deterministic signing**
:   Signing with `opt_rand = null`, so the randomiser falls back to `PK.seed` and
    the same message always yields the same signature. Useful for reproducible
    builds and fixed test vectors. Contrast [hedged signing](#h).

**Domain separation**
:   Ensuring hashes computed for different purposes cannot collide, by mixing a
    distinguishing value into the input. Appears at every level of SLH-DSA:
    [ADRS](#a) types, the `0x00`/`0x01` pure/pre-hash separators, and
    [context strings](#c).

## E

**EUF-CMA**
:   *Existential unforgeability under chosen-message attack* — the standard
    security goal for a signature scheme: an attacker who may request signatures
    on messages of their choosing still cannot forge a signature on any new
    message.

## F

**`F`**
:   The one-block tweakable hash: `F(PK.seed, ADRS, one n-byte block) → n`. One
    WOTS+ chain step, or one FORS leaf. Invoked more than anything else in the
    scheme — which is why FIPS 205 keeps it on **SHA-256 even at security
    categories 3 and 5**. See [hashing](components/hashing.md).

**Few-time signature (FTS)**
:   A scheme secure for a small number of uses, degrading *gracefully* rather than
    catastrophically. [FORS](concepts/fors.md) is SLH-DSA's. Contrast
    [one-time signature](#o).

**FIPS 203 / 204 / 205**
:   NIST's first post-quantum standards, August 2024. 203 = ML-KEM
    (key encapsulation), 204 = ML-DSA (signatures, the default), **205 = SLH-DSA
    (signatures, the conservative hedge)**.

**FORS**
:   *Forest Of Random Subsets.* SLH-DSA's few-time signature: `k` Merkle trees of
    `2^a` leaves; signing reveals one leaf per tree, selected by the message
    digest. FIPS 205 §8. See [chapter 6](concepts/fors.md).

## G

**`gen_len2`**
:   FIPS 205 §3.2 **Algorithm 1**, which computes `len_2`. Inserted in the *final*
    standard and absent from the draft, shifting every later algorithm number up
    by one. The single most common source of wrong citations.

**Grover's algorithm**
:   Quantum search giving a **quadratic** speedup — `2^n` work becomes `2^(n/2)`
    queries. Survivable by doubling parameters, which is why hashes and symmetric
    ciphers persist post-quantum while RSA and ECDSA do not. Contrast
    [Shor's](#s).

## H

**`h`**
:   Total hypertree height, 63–68. Equals `h' · d`, an invariant
    [checked at compile time](components/parameters.md#the-comptime-self-check).

**`h'` (`h_prime`)**
:   Height of each individual XMSS tree, 3–9. Always `h / d`.

**`H`**
:   The two-block tweakable hash, compressing two Merkle children into a parent:
    `H(PK.seed, ADRS, left, right) → n`.

**`H_msg`**
:   The message digest function: `H_msg(R, PK.seed, PK.root, M') → m` bytes, split
    into `md`, `idx_tree` and `idx_leaf`. SHAKE squeezes `m` bytes directly; SHA-2
    stretches with [MGF1](#m).

**Hash-based signature**
:   A signature scheme whose security rests **only** on hash function properties —
    no factoring, discrete logs or lattices. The conservative post-quantum family.
    See [why hash-based](why/hash-based.md).

**HashSLH-DSA**
:   The pre-hash variants `hash_slh_sign` / `hash_slh_verify`, which sign `PH(M)`
    with separator `0x01` plus a hash OID. **Deferred** in this library by
    recorded decision. See
    [context strings](concepts/assembly.md#context-strings).

**Hedged signing**
:   Signing with fresh randomness in `opt_rand` — the recommendation. Contrast
    [deterministic signing](#d).

**Hypertree**
:   The stack of `d` XMSS trees of height `h'` that replaces one infeasible
    height-`h` tree. Each layer's leaves sign the roots below. FIPS 205 §7. See
    [chapter 7](concepts/hypertree.md).

## I

**`idx_leaf`**
:   Which leaf within the bottom-layer XMSS tree. From the digest, `ceil(h'/8)`
    bytes, masked to `h'` bits. **Public** — recoverable from the signature.

**`idx_tree`**
:   Which bottom-layer XMSS tree. From the digest, `ceil((h-h')/8)` bytes, masked
    to `h-h'` bits. Consumed `h'` bits at a time when climbing layers. **Public.**

## K

**`k`**
:   Number of FORS trees, 14–35. Forgery probability falls as the `k`-th power of
    per-tree exposure — the reason few-time security works.

**KAT**
:   *Known-answer test.* Fixed inputs with known correct outputs. The only test
    class that catches a self-consistent-but-wrong implementation. See
    [ACVP](#a).

**Keccak**
:   The permutation underlying SHA-3 and SHAKE. Has no data-dependent branches or
    memory accesses, hence constant-time by construction.

## L

**Lamport OTS**
:   The original 1979 one-time signature: two secrets per message bit, reveal the
    one matching each bit. Correct, simple, ~4 KB per signature. See
    [chapter 1](concepts/one-time-signatures.md).

**Lane A / Lane B**
:   This repository's split. Lane A (everything outside `upstream-candidate/`)
    permits AI assistance; Lane B is human-authored only, for eventual `std.crypto`
    contribution. See [the two-lane rule](implementation/lanes.md).

**`len`, `len_1`, `len_2`**
:   WOTS+ chain counts. `len_1 = ceil(8n/lg_w)` message digits, `len_2` checksum
    digits, `len = len_1 + len_2`. For `n=16`: 32 + 3 = 35.

**`lg_w`**
:   log₂ of the Winternitz parameter. FIPS 205 fixes it at **4** for all twelve
    sets, so `w = 16`.

**LMS**
:   *Leighton–Micali Signatures*, RFC 8554. A **stateful** hash-based scheme,
    sibling to XMSS. See [statefulness](concepts/statefulness.md).

## M

**`m`**
:   `H_msg` output length, 30–49 bytes. Exactly
    `ceil(k·a/8) + ceil((h-h')/8) + ceil(h'/8)`.

**`md`**
:   The FORS message digest — the first `ceil(k·a/8)` bytes of the `H_msg` output,
    split into `k` indices of `a` bits.

**Merkle tree**
:   A binary tree of hashes committing many leaves to one root, with logarithmic
    membership proofs. Merkle, 1979. See
    [chapter 3](concepts/merkle-trees.md).

**MGF1**
:   RFC 8017 §B.2.1 mask generation function — repeated
    `Hash(seed ‖ counter)` blocks, final one truncated. How FIPS 205 §11.2
    stretches SHA-2 to `m` bytes, which SHAKE does natively.

**ML-DSA**
:   FIPS 204, the lattice-based signature standard (formerly Dilithium). Faster and
    smaller than SLH-DSA and the sensible default; SLH-DSA exists as the hedge
    against lattice assumptions failing.

**Multi-target attack**
:   Attacking `2^h` instances simultaneously rather than one, amortising
    precomputation across all of them. Countered by tweaking every hash with
    `PK.seed` and [ADRS](#a) so no work is shared. See
    [what the "+" adds](concepts/wots.md#what-the-adds).

## N

**`n`**
:   Security parameter **in bytes** — 16, 24 or 32, i.e. the 128/192/256-bit
    levels. Every hash output is truncated to `n`. Papers using `n` for a bit count
    read eight times smaller.

## O

**One-time signature (OTS)**
:   A scheme secure for exactly **one** use. Signing twice with the same key
    typically reveals enough to forge. [Lamport](#l) and [WOTS+](#w) are OTS;
    XMSS leaves are OTS keys. Contrast [few-time](#f).

**`opt_rand`**
:   The optional per-signature randomiser. An `n`-byte buffer for
    [hedged signing](#h); `null` falls back to `PK.seed` for
    [deterministic signing](#d).

## P

**`PK.root`**
:   The root of the top-layer XMSS tree. Second half of the public key, and the one
    value verification ultimately compares against.

**`PK.seed`**
:   Public per-keypair value tweaking every hash in the scheme. First half of the
    public key. Also the fallback randomiser for deterministic signing.

**`pkFromSig`**
:   The naming convention for **reconstructing** a public key from a signature
    rather than comparing against a stored one. `wots_pkFromSig`,
    `xmss_pkFromSig`, `fors_pkFromSig`. Returning a value rather than a boolean is
    what makes the layers stackable. See
    [conventions](components/index.md#conventions-across-every-module).

**Post-quantum cryptography**
:   Cryptography secure against a quantum adversary — in practice, replacing
    [Shor](#s)-vulnerable primitives. See [why post-quantum](why/post-quantum.md).

**Pre-hash**
:   See [HashSLH-DSA](#h).

**Preimage resistance**
:   Given `H(x)`, infeasible to find any `x'` with `H(x') = H(x)`. The core
    property one-time signatures rest on.

**`PRF`**
:   `PRF(SK.seed, PK.seed, ADRS) → n`. Derives a WOTS+ or FORS **secret** from its
    address, so the structure's billions of secrets need not be stored. Uses the
    `_prf` ADRS types.

**`PRF_msg`**
:   `PRF_msg(SK.prf, opt_rand, M') → n`, producing the randomiser `R`. HMAC-SHA-2
    in the SHA-2 family; a SHAKE squeeze otherwise.

## R

**`R`**
:   The per-signature randomiser, first `n` bytes of the signature. Transmitted so
    the verifier can recompute the same digest — hence **public**.

## S

**`s` / `f` variants**
:   The two trade-off points at each security level. `s` = small signature, slow
    signing (few deep layers); `f` = fast signing, larger signature (many shallow
    layers). Same security. See
    [the split](concepts/hypertree.md#the-sf-split-finally-explained).

**Second-preimage resistance**
:   Given `x`, infeasible to find `x' ≠ x` with `H(x') = H(x)`. What makes a Merkle
    root a binding commitment to its leaves.

**SHA-2**
:   The hash family behind the `sha2` parameter sets, instantiated in FIPS 205
    §11.2. Needs [HMAC](#h) and [MGF1](#m) scaffolding, uses
    [ADRSc](#a), and notably keeps `F` on SHA-256 at every security level.

**SHAKE**
:   The extendable-output function behind the `shake` sets, FIPS 205 §11.1. Always
    SHAKE-256, at every level. Arbitrary output length makes all six functions a
    single absorb-and-squeeze. Uses the **full 32-byte** ADRS.

**Shor's algorithm**
:   Peter Shor's 1994 quantum algorithm solving factoring and discrete log in
    polynomial time — breaking RSA, DH, DSA and ECDSA outright. Not a
    security-margin erosion; larger keys do not help. Contrast [Grover](#g).

**`SK.prf`**
:   Secret value keying `PRF_msg`. Keeping it secret is what stops an attacker
    from searching for messages that collide on a chosen FORS key.

**`SK.seed`**
:   The master secret. Every WOTS+ and FORS secret in the structure is derived from
    it via `PRF`. The value the [ctgrind harness](implementation/constant-time.md)
    taints.

**SLH-DSA**
:   *Stateless Hash-Based Digital Signature Algorithm.* FIPS 205. The standardised
    form of SPHINCS+.

**SPHINCS+**
:   The submission SLH-DSA was standardised from. FIPS 205 standardises only its
    **simple** instantiations, not the *robust* ones.

**Statefulness**
:   The requirement that a signer remember which one-time keys are spent. XMSS and
    LMS need it; SLH-DSA eliminates it by deriving the index from the message. The
    central design decision — see [chapter 5](concepts/statefulness.md).

## T

**`T_l`**
:   The variable-arity tweakable hash: `T_l(PK.seed, ADRS, l blocks) → n`.
    Compresses a WOTS+ public key (`l = len`) or the `k` FORS roots.

**`toByte`**
:   FIPS 205 §3 Algorithm 3. Integer to big-endian byte string. `src/util.zig`.

**Treehash**
:   An iterative algorithm computing a Merkle root and authentication paths in one
    left-to-right sweep with an explicit stack, computing each leaf once. Used by
    the SPHINCS+ reference implementation; a known optimisation avenue here, where
    the recursive formulation is used instead. See
    [performance note](components/xmss.md#performance-note).

**Tweakable hash**
:   A hash taking an extra *tweak* — here `PK.seed` and `ADRS` — so the same data
    at different positions hashes differently. The mechanism defeating
    [multi-target attacks](#m).

## W

**`w`**
:   The Winternitz parameter, `2^lg_w`. Always **16** in FIPS 205. Larger `w` means
    fewer, longer chains: smaller signatures, more hashing.

**Winternitz**
:   The idea of encoding a base-`w` digit as *how many times* a secret has been
    hashed, extracting `lg_w` bits per secret instead of Lamport's half-bit. See
    [chapter 2](concepts/wots.md).

**WOTS+**
:   *Winternitz One-Time Signature Plus.* Winternitz chains plus a checksum plus
    per-position tweaking. FIPS 205 §5, Algorithms 5–8. See
    [chapter 2](concepts/wots.md).

## X

**XMSS**
:   *eXtended Merkle Signature Scheme.* A Merkle tree whose leaves are WOTS+ public
    keys. A standard in its own right (RFC 8391, stateful); in SLH-DSA a hypertree
    layer. FIPS 205 §6, Algorithms 9–11. See
    [chapter 4](concepts/xmss.md).

## Z

**Zeroization**
:   Explicitly overwriting secret material before it goes out of scope, with
    volatile semantics so the compiler cannot elide the write.
    `std.crypto.secureZero`. Applied precisely — buffers holding public values are
    deliberately *not* scrubbed. See
    [discipline](implementation/constant-time.md#zeroization).
