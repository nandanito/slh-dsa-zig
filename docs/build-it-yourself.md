# Build it yourself

The [How it works](concepts/index.md) chapters explain SLH-DSA. This page is a
study programme for *proving to yourself* that you understood them — by building
each layer from the specification, breaking it deliberately, and answering a
question you cannot answer from memory alone.

It is aimed at someone comfortable in a systems language who is new to
post-quantum cryptography. Hash-based signatures are the best possible entry
point: unlike lattice schemes, they need no advanced mathematics. Hash functions
and binary trees are the entire toolkit.

!!! abstract "How this page works"

    Each stage below points at the chapter that explains the idea, then adds two
    things the chapter does not have:

    **Build** — something you write yourself, from the standard, before looking at
    any implementation (including this project's).

    **Checkpoint** — a question. If you can answer it without notes, move on. If you
    cannot, you have not finished the stage, *regardless of whether your code
    passes its tests*.

    The checkpoints are the real curriculum. The code is how you earn them.

Doing the builds honestly is a matter of months, not evenings. Stages 1–3 are the
conceptual core; if time is short, do those properly and read the rest.

## The programme at a glance

| Stage | Chapter | Build | Proves you understand |
|---|---|---|---|
| 1 | [One-time signatures](concepts/one-time-signatures.md) | Lamport, then forge it | Why one-time means *one* |
| 2 | [Winternitz and WOTS+](concepts/wots.md) | WOTS+ from §5, then attack it | The checksum — the key idea in the scheme |
| 3 | [Merkle trees](concepts/merkle-trees.md) · [XMSS](concepts/xmss.md) | Treehash + auth paths | How one root certifies many keys |
| 4 | [The statefulness problem](concepts/statefulness.md) · [FORS](concepts/fors.md) | FORS from §8 | Why *few*-time is the whole design |
| 5 | [The hypertree](concepts/hypertree.md) | `ht_sign` / `ht_verify` | The `s` versus `f` trade-off |
| 6 | [Putting it together](concepts/assembly.md) | Wire it to the ACVP vectors | What is secret and what is merely derived |
| 7 | [Parameter sets](components/parameters.md) · [Hashing](components/hashing.md) | Both hash families | Why every hash call is tweaked |
| 8 | *(this page)* | Measure it on real hardware | What PQC costs on a device |

---

## Stage 1 — Lamport

Read [One-time signatures](concepts/one-time-signatures.md).

**Build.** Implement Lamport signatures from the description — no reference, no
specification. It is about fifty lines. Then write a test that signs *two*
different messages under one key and produces a forgery from the revealed
secrets.

Making the break happen with your own hands is worth more than any amount of
reading about it. Almost everything above this stage exists to escape what you
just demonstrated.

!!! question "Checkpoint"

    You have signed two messages with one Lamport key. Name a third message you
    can now forge, and a fourth you still cannot. What distinguishes them?

## Stage 2 — WOTS+

Read [Winternitz and WOTS+](concepts/wots.md). Then read the standard directly:
FIPS 205 §5 Algorithm 5 (`chain`), §5.1 Algorithm 6 (`wots_PKgen`), §5.2
Algorithm 7 (`wots_sign`), §5.3 Algorithm 8 (`wots_pkFromSig`). You will also
need §3 for `toByte` (Algorithm 3) and `base_2b` (Algorithm 4), plus `gen_len2`
(Algorithm 1, §3.2) for the checksum length.

**Build.** WOTS+ from §5 alone. Then attack it: take a valid signature, increment
one message digit, and try to forge. Watch the checksum stop you.

!!! tip "The shape to notice"

    `wots_pkFromSig` does not check a signature against a public key. It
    *recomputes a candidate public key* from the signature, and the caller
    compares. That pattern repeats at every layer above this one — XMSS, the
    hypertree, FORS. Internalise it here and the rest of the scheme reads much
    more easily.

!!! question "Checkpoint"

    Why must the checksum digits be signed with the **same** WOTS+ key as the
    message digits? Describe concretely what breaks if you use a separate key for
    them.

## Stage 3 — Merkle trees and XMSS

Read [Merkle trees](concepts/merkle-trees.md) and [XMSS](concepts/xmss.md). In the
standard: FIPS 205 §6.1 Algorithm 9 (`xmss_node`), §6.2 Algorithm 10
(`xmss_sign`), §6.3 Algorithm 11 (`xmss_pkFromSig`).

**Build.** Treehash and authentication-path generation. Write the naive recursive
version first, and **instrument it** — count the hash calls needed to produce one
authentication path. Write that number down. Stage 8 comes back to it.

!!! question "Checkpoint"

    For a tree of height `h`, how many hashes are in an authentication path, and
    how does the verifier know whether each sibling belongs on the left or the
    right? Answer without looking at the algorithm.

## Stage 4 — Statelessness and FORS

Read [The statefulness problem](concepts/statefulness.md), then
[FORS](concepts/fors.md). In the standard: FIPS 205 §8.1 Algorithm 14
(`fors_skGen`), §8.2 Algorithm 15 (`fors_node`), §8.3 Algorithm 16
(`fors_sign`), §8.4 Algorithm 17 (`fors_pkFromSig`).

The word to hold onto is **few**-time. WOTS+ shatters if a key is used twice;
FORS degrades — each reuse leaks a few more leaves. That difference is exactly
what makes a stateless scheme possible, because a pseudorandomly chosen index
will occasionally repeat.

**Build.** FORS from §8. Then simulate reuse: sign several messages that collide
on the same FORS key and measure how much of the key you have leaked.

!!! question "Checkpoint"

    An attacker collects many signatures and finds two that used the same FORS
    key. What exactly have they gained — and why is it not yet a forgery?

## Stage 5 — The hypertree

Read [The hypertree](concepts/hypertree.md). In the standard: FIPS 205 §7.1
Algorithm 12 (`ht_sign`), §7.2 Algorithm 13 (`ht_verify`).

**Build.** Layered signing and verification over the XMSS you already have.

!!! question "Checkpoint"

    Increasing `d` — more layers, shorter trees — makes signing faster but
    signatures larger. Trace both effects through the structure and derive the
    `s` versus `f` distinction **before** you look at
    [Table 2](reference/parameter-sets.md).

## Stage 6 — Assembly

Read [Putting it together](concepts/assembly.md). In the standard: FIPS 205 §9.1
Algorithm 18 (`slh_keygen_internal`), §9.2 Algorithm 19 (`slh_sign_internal`),
§9.3 Algorithm 20 (`slh_verify_internal`), then §10.1 (`slh_keygen`), §10.2
Algorithm 22 (`slh_sign`), §10.3 Algorithm 24 (`slh_verify`).

The *internal* functions are deterministic and take randomness explicitly — those
are what the NIST vectors exercise. The *external* ones draw randomness and
handle the context string and the pre-hashed variants. Knowing which is which
saves real confusion when wiring up test vectors.

**Build.** Wire your implementation to the ACVP vectors. This is the first moment
anything is externally validated.

!!! question "Checkpoint"

    Verification recomputes the FORS public key and every XMSS root from the
    signature — none of them are transmitted. Why does that make them **public**
    values, even though each one is derived from the secret seed?

    This is not academic. It is precisely the distinction a constant-time analysis
    tool cannot infer for itself, and getting it wrong yields either thousands of
    false positives or a blind audit. See
    [constant-time discipline](implementation/constant-time.md).

## Stage 7 — Tweakable hashing and parameters

Read [Addresses (ADRS)](components/adrs.md), [The hash
interface](components/hashing.md), and [Parameter
sets](components/parameters.md). In the standard: FIPS 205 §4.2 and §4.3 for
address structure, §11 Table 2 for the parameter sets, §11.1 and §11.2 for the
two instantiations.

**Build.** Both hash families, for at least one parameter set each. The
instantiations are *not* symmetric, and the asymmetries are easy to miss:

- SHAKE hashes the full 32-byte address; SHA-2 uses a 22-byte compressed form.
- In the SHA-2 instantiation, `H`, `T_l`, and `H_msg` widen to SHA-512 at the
  higher security categories, and `PRF_msg` becomes HMAC-SHA-512. The "SHA-2"
  sets are not one hash function but two, selected by `n`.

!!! question "Checkpoint"

    Pick any two of the six functions (`H_msg`, `PRF`, `PRF_msg`, `F`, `H`,
    `T_l`) and explain why they must be domain-separated from one another — with
    a concrete attack if they were not.

## Stage 8 — Measure it on real hardware

Nothing in the chapters prepares you for what these numbers look like on a
device. This stage is the practical payoff, and it is where hash-based
signatures stop being elegant and start being a budget.

**Signature size is usually the binding constraint.** Roughly 7.8 KB at the
smallest parameter set, rising to about 50 KB at the largest — against ECDSA's
64 bytes. On a constrained link or a device with limited flash, this dominates
every other consideration.

**Signing and verification are wildly asymmetric.** Signing costs millions of
hash invocations; verification is far cheaper. This is why SLH-DSA on embedded
targets is usually a *verification* story — secure boot, firmware signing — with
signing done off-device on a build server. Design for that asymmetry rather than
against it.

**Trust the count over the intuition.** Revisit the hash-call count you recorded
in Stage 3. Reading `xmss_sign`, the natural conclusion is that the `h'` sibling
subtrees overlap and that most of the work is redundant — the sibling at height
`h'-1` is half the tree, after all. Your instrumentation will say otherwise: the
siblings are pairwise disjoint, so one authentication path costs `2^h' - 1`
leaves with nothing computed twice. Iterative treehash is worth knowing as a
control-flow technique, but do not adopt it expecting a speed-up that is not
there. Catching that yourself, with a counter, is the habit worth taking away
from this stage.

**Stack, not heap.** Recursion depth is `h'`, so a few hundred bytes of frames —
never the binding constraint. On a device with tens of kilobytes of RAM the
number that decides whether the thing runs is the *signature*: 7,856 bytes at
128s up to 49,856 at 256f, which the caller has to hold somewhere.

**Choose the hash family for the silicon, not the benchmark.** Many
microcontrollers ship a SHA-256 accelerator; almost none accelerate Keccak. That
single fact can invert the SHA-2 versus SHAKE ranking relative to what you
measure on a laptop — the same effect this project documents in its own
[benchmark methodology](implementation/testing.md). Check what your target
actually accelerates before committing.

!!! question "Checkpoint"

    For firmware verification on a device with 64 KB of RAM, choose a parameter
    set and a hash family, and justify both. There is a defensible answer; the
    reasoning matters more than the choice.

For real numbers on a Cortex-M4, see [pqm4](https://github.com/mupq/pqm4), the
reference benchmarking suite for post-quantum cryptography on microcontrollers.
Read its measurements before forming intuitions from desktop benchmarks.

---

## Two notes on process

!!! warning "Do not read FIPS 205 front to back"

    It is a specification, not a teaching document, and it is deliberately
    unmotivated. Read §3 and §4 for notation and addresses, then §5–§8 for the
    components, then §9–§10 for the scheme, then §11 for the instantiations —
    and keep §3 and §4 open in a second window throughout.

    Most implementation bugs in hash-based signatures are not algorithmic. They
    are byte-order and address-field bugs, and they come from conventions defined
    far from where they are used.

!!! warning "The middle layers have no official test vectors"

    The NIST ACVP vectors are the only external oracle, and they only test
    key generation, signing, and verification at the top level. WOTS+, XMSS, and
    FORS have no published vectors of their own.

    A bug in a middle layer is therefore invisible until the top-level vectors
    fail — at which point you have five layers to bisect. Build property tests as
    you go: sign/verify round-trips, authentication-path recomputation, chain
    arithmetic. It is far cheaper than debugging backwards from a failed KAT. See
    [how this is tested](implementation/testing.md).

When you are ready to compare your reading against this one, the
[Components](components/index.md) section maps each FIPS 205 section onto the
code, and the [FIPS 205 map](reference/spec-map.md) gives the section-by-section
correspondence.

[Start: One-time signatures →](concepts/one-time-signatures.md){ .md-button .md-button--primary }
