# Why hash-based?

## Minimal assumptions

Every signature scheme is a bet on some problem being hard. The interesting
question is not *how hard* but **how well understood**.

| Family | Bet on | Studied since |
|---|---|---|
| RSA | Factoring | 1970s (as cryptography) |
| ECDSA / Ed25519 | Elliptic-curve discrete log | 1980s |
| ML-DSA, FALCON | Lattice problems (LWE, SIS, NTRU) | ~1996 |
| Multivariate | Solving multivariate quadratics | 1980s, **repeatedly broken** |
| Code-based | Decoding random linear codes | 1978 |
| **Hash-based** | **Hash functions being hash functions** | **Preimage/collision resistance is the most attacked property in cryptography** |

Hash-based signatures need **no new assumption at all**. They need a hash
function to be a good hash function — second-preimage resistant, and in some
constructions collision resistant. That is the same property already trusted by
every HMAC, every TLS transcript, every Git commit, every blockchain, and every
password-hashing scheme in production. It is the most heavily attacked and best
understood assumption in the field.

If SLH-DSA falls, SHA-2 or SHAKE has fallen, and the resulting problem is much
larger than your signatures.

Compare the lattice bet. There is nothing *wrong* with lattice assumptions —
they have survived serious attention, they come with worst-case-to-average-case
reductions that number theory cannot offer, and ML-DSA is a good design. But
they are younger, the security estimates have been revised as attacks improved,
and the gap between the problems the proofs cover and the problems the schemes
actually instantiate is wider. Reasonable cryptographers hold that lattices are
fine. Reasonable cryptographers also want a backup that does not depend on that
judgement being right.

## The idea is older than what it replaces

Ralph Merkle described how to build a many-message signature from a one-message
signature in 1979, in the same work that gave us Merkle trees. The construction
is contemporaneous with RSA and predates elliptic-curve cryptography by most of
a decade.

It was never deployed, for a simple reason: it was enormous, and RSA was
sitting right there being small and fast. Hash-based signatures spent forty
years as a textbook curiosity — the thing you show students to explain what a
signature *is*, before moving on to the schemes people actually use.

Shor's algorithm changed the accounting. Suddenly the family whose only
weakness was inefficiency became the family whose only weakness was
inefficiency. Everything else in the textbook had a worse problem.

!!! quote "The one-sentence version"

    Hash-based signatures were always the conservative choice; they were just
    never the affordable one, and now the alternatives have a deadline.

## What it costs

There is no free lunch here, and the bill is large.

- **Signatures are big.** 7,856 bytes for SLH-DSA-SHAKE-128s, 17,088 for the
  fast variant at the same security level. Ed25519 is 64 bytes. That is a
  factor of 120 to 270.
- **Signing is slow.** Every signature rebuilds tree structures from scratch,
  costing millions of hash compressions. On commodity hardware, the `s`
  variants take hundreds of milliseconds per signature; a good ECDSA
  implementation takes tens of microseconds.
- **Verification is cheap-ish.** Much faster than signing, but still far more
  work than an elliptic-curve verification.

Where does this hurt? Anywhere signatures travel per-connection or
per-transaction: TLS handshakes bloat, DNSSEC responses stop fitting in a UDP
packet, blockchains bloat, embedded devices with a 32 KB flash budget run out of
room.

Where does it not hurt? Precisely the long-lived-root cases from
[the previous page](post-quantum.md#signatures-are-on-a-different-clock-from-encryption).
A firmware image signed once at the factory and verified a thousand times over
thirty years does not care that the signature is 17 KB or that signing took a
second. It cares enormously that the signature is still unforgeable in 2056.

**That is SLH-DSA's niche**: rarely signed, long trusted, verified by something
that cannot be updated.

## Small public keys, though

One number in SLH-DSA is remarkable rather than embarrassing:

```
SLH-DSA-128s public key:  32 bytes
ML-DSA-44   public key:  1312 bytes
```

The public key is just `PK.seed || PK.root` — two `n`-byte hashes. It is the
smallest post-quantum public key of any standardised signature scheme, and
smaller than an RSA public key by a factor of eight.

For a trust anchor burned into ROM, or a root certificate replicated into
millions of devices, key size can matter more than signature size. SLH-DSA is
genuinely attractive there.

## Stateful versus stateless

One more distinction, and it is the one that gives SLH-DSA its name.

The earlier standardised hash-based schemes — **XMSS** and **LMS**, specified in
[RFC 8391][rfc8391] and [RFC 8554][rfc8554] — are **stateful**. Each signature
consumes a one-time key, and the signer must record which keys are spent and
never reuse one. Reusing a one-time key does not degrade security gracefully;
it hands out the material to forge.

Maintaining that state correctly is an operational problem, not a cryptographic
one, and operational problems are where systems actually fail. Restore a
database backup, roll back a VM snapshot, run two instances of a service behind
a load balancer, clone a container image with the key inside — any of these
silently replays indices and breaks the scheme. There is no cryptographic
defence; the signer simply has to be right, forever, across every failure mode
of every system it runs on.

**SLH-DSA is stateless.** The `SLH` is literally *stateless hash-based*. It
signs with no persistent state beyond the private key itself, so backups,
replicas and rollbacks are harmless. Achieving that is what forces the FORS
construction and the hypertree — the two pieces of the design that look most
arbitrary until you know what they are for.

That story starts with the simplest possible signature scheme.

[Chapter 1: One-time signatures →](../concepts/one-time-signatures.md){ .md-button .md-button--primary }

[rfc8391]: https://www.rfc-editor.org/rfc/rfc8391
[rfc8554]: https://www.rfc-editor.org/rfc/rfc8554
