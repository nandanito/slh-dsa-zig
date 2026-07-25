# Why post-quantum?

## Two hard problems, one algorithm

Essentially all deployed public-key cryptography rests on one of two
assumptions:

- **Integer factoring is hard.** Given `N = p·q` for large primes, recovering
  `p` and `q` takes superpolynomial time. This is RSA.
- **Discrete logarithms are hard.** Given `g` and `g^x` in a suitable group,
  recovering `x` takes superpolynomial time. This is Diffie–Hellman, DSA, and
  — in an elliptic-curve group — ECDH and ECDSA, which means Ed25519 and
  the signatures in TLS, SSH and code-signing today.

In 1994 Peter Shor published a quantum algorithm that solves **both** in
polynomial time. Factoring and discrete log are, from a quantum computer's
point of view, the same problem — period-finding — and it is a problem quantum
computers are unusually good at.

!!! warning "This is not a security-margin problem"

    Most cryptanalytic progress erodes a margin: an attack shaves a few bits,
    you increase the key size, you continue. Shor's algorithm is categorically
    different. It does not make RSA-2048 behave like RSA-1024. Enlarging the
    key does not help, because the cost grows polynomially in the key size for
    the attacker too. There is no parameter choice that rescues RSA or ECDSA
    from a sufficiently large quantum computer. The primitives have to be
    replaced.

## What about symmetric cryptography and hashes?

They survive, with a caveat. The best general quantum attack on an unstructured
search problem is Grover's algorithm, which gives a **quadratic** speedup: a
search that classically costs `2^n` costs about `2^(n/2)` quantum queries.

Quadratic is survivable. You double the parameter and you are back where you
started — AES-256 retains a comfortable margin, and a 256-bit hash retains
roughly 128 bits of preimage resistance against a generic quantum attacker.

This asymmetry is the entire strategic picture of post-quantum cryptography:

| Primitive class | Quantum impact | Response |
|---|---|---|
| RSA, DH, DSA, ECDSA, ECDH | **Broken** (Shor, polynomial time) | Replace the primitive |
| AES, SHA-2, SHA-3, HMAC | Weakened quadratically (Grover) | Increase sizes |

Everything hash-based inherits the second row. That is the point of
[the next page](hash-based.md).

## Signatures are on a different clock from encryption

The urgency argument for post-quantum **encryption** is *harvest now, decrypt
later*: an adversary records your encrypted traffic today and decrypts it in
fifteen years when the hardware exists. The secret's value has to outlive the
migration, and for a lot of traffic it does.

Signatures do not work that way. A signature forged in 2045 cannot retroactively
compromise a TLS handshake from 2026 — that session is long over. It is tempting
to conclude signatures are less urgent.

That conclusion is wrong, for two reasons.

**Long-lived verification roots.** Some public keys are trusted for decades and
cannot practically be rotated. A CA root shipped in a browser trust store. A
secure-boot key fused into silicon. The firmware-signing key for a medical
device, a satellite, a car, an industrial controller with a thirty-year service
life. If any of these is still trusted when the relevant quantum computer
exists, an attacker who breaks it can sign arbitrary firmware for the entire
remaining fleet. For these, the deadline is not "when quantum computers arrive"
— it is *now minus the device lifetime*.

**Migration takes longer than you think.** Replacing a signature algorithm
means changing formats, protocols, hardware, certificate profiles, HSMs, and
every implementation on both sides of every trust relationship. SHA-1 was known
broken in theory from 2005, demonstrated collided in 2017, and lingered in
production for years afterwards. Signature agility is measured in decades, and
the work has to start before it is needed rather than after.

## The standards

NIST ran an open post-quantum standardisation process from 2016, and published
the first three standards in August 2024:

| Standard | Algorithm | Purpose | Foundation |
|---|---|---|---|
| FIPS 203 | ML-KEM (Kyber) | Key encapsulation | Module lattices |
| FIPS 204 | ML-DSA (Dilithium) | Signatures — **the default choice** | Module lattices |
| **FIPS 205** | **SLH-DSA (SPHINCS+)** | Signatures — **the conservative hedge** | **Hash functions** |

A lattice-based signature scheme derived from FALCON was also selected and is
being standardised separately; check [NIST's PQC project pages][nistpqc] for
current status rather than trusting any snapshot, including this one.

The two signature standards are deliberately not redundant. ML-DSA is fast with
moderate signatures and is what most systems should use. SLH-DSA is slow with
large signatures and exists because **ML-DSA's security rests on lattice
assumptions that are roughly thirty years old**, whereas SLH-DSA's rests only
on hash functions. Standardising both means a future break in lattice
cryptography is survivable without another decade-long migration.

That hedging role is why an implementation of SLH-DSA is worth getting right
even though almost nobody should reach for it first.

!!! note "Where this leaves us"

    Classical signatures have a hard expiry date that nobody can name
    precisely. Two replacements are standardised. One is fast and rests on
    newer mathematics; the other is expensive and rests on the oldest, most
    scrutinised primitives in the field. This library implements the second
    one. [Why that trade is worth making →](hash-based.md)

[nistpqc]: https://csrc.nist.gov/projects/post-quantum-cryptography
