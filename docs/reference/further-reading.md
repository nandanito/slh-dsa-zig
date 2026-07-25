# Further reading

## Primary sources

**[FIPS 205 — Stateless Hash-Based Digital Signature Standard][fips205]** (NIST,
August 2024)
:   The oracle. Complete, precise, and deliberately unmotivated. Read §3 for
    notation, then §5–§8 for the components, then §9–§10 for the scheme, then §11
    for the instantiations. Always cite the **final** publication, never the
    initial public draft — see [the map](spec-map.md).

**[SPHINCS+ submission documents][sphincsplus]**
:   The design rationale FIPS 205 omits. This is where to look for *why* a
    parameter is what it is, and for the security proofs. Note that FIPS 205
    standardises only the **simple** instantiations, not the *robust* ones, so parts
    of the submission describe variants that were not standardised.

**[NIST Post-Quantum Cryptography project][nistpqc]**
:   Current standardisation status. Check here rather than trusting any snapshot —
    including this site's [summary](../why/post-quantum.md#the-standards).

## The other standards

**[FIPS 204 — ML-DSA][fips204]**
:   The lattice-based signature standard. Worth reading alongside FIPS 205: it is
    the default choice, it shares the §10.2 context-string design, and the contrast
    clarifies what SLH-DSA is trading away.

**[FIPS 203 — ML-KEM][fips203]**
:   Key encapsulation. Different problem, same migration.

## Ancestors

**[RFC 8391 — XMSS][rfc8391]**
:   The **stateful** hash-based scheme SLH-DSA's hypertree layers are built from.
    Reading it makes the statefulness problem concrete — the RFC has to spend real
    effort on state management that SLH-DSA simply does not have.

**[RFC 8554 — LMS][rfc8554]**
:   Leighton–Micali Signatures, the other stateful standard.

**Merkle, "A Certified Digital Signature" (1979)**
:   The origin of both Merkle trees and the idea of certifying many one-time keys
    under one root. Predates elliptic-curve cryptography.

**Lamport, "Constructing Digital Signatures from a One Way Function" (1979)**
:   The one-time signature everything else is a refinement of. See
    [chapter 1](../concepts/one-time-signatures.md).

## Reference implementations

Useful for cross-validation. **Never copy from them** — this project's rule is that
implementations must be independent readings of the standard; cite "see PQClean for
shape" if consulted.

**[PQClean][pqclean]**
:   Clean, portable C reference implementations. Its `clean` (non-vectorised)
    SLH-DSA variant is this project's
    [performance baseline](../implementation/testing.md#benchmarks).

**[SPHINCS+ reference implementation][sphincsref]**
:   From the submission team. Notably uses an iterative
    [treehash](../glossary.md#t) where this library uses the standard's recursive
    formulation.

**[ACVP-Server][acvp]**
:   NIST's validation server, and the source of the test vector format and files.
    See `tests/vectors/README.md` for which release this project pins.

## Supporting specifications

**[RFC 8017 §B.2.1 — MGF1][rfc8017]**
:   The mask generation function FIPS 205 §11.2 uses to stretch SHA-2 to `m` bytes.

**[FIPS 202 — SHA-3 and SHAKE][fips202]**
:   The extendable-output functions behind the `shake` parameter sets.

**[FIPS 180-4 — SHA-2][fips180]**
:   The hash family behind the `sha2` sets.

## Constant-time verification

**[ctgrind][ctgrind]** — Adam Langley
:   The original: verify constant-time behaviour by marking secrets undefined in
    Valgrind. This project implements the technique in pure Zig via `std.valgrind`,
    with no C shim. See [constant-time](../implementation/constant-time.md).

**[Valgrind memcheck][valgrind]**
:   The underlying tool. Its "conditional jump depends on uninitialised value"
    report is what ctgrind repurposes as a timing-leak detector.

## Zig

**[Zig `std.crypto`][zigcrypto]**
:   The style oracle for this project. When in doubt about Zig cryptographic
    conventions, match what `std.crypto` does — particularly `ml_dsa`, the FIPS 204
    sibling with the same context-string design.

**[tweetnacl-zig][tweetnacl]**
:   This project's predecessor and philosophical model.

## This project

- **[Repository][repo]** — source, issues, CI
- **`ARCHITECTURE.md`** — code layering and design rules (the authority on
  structure; this site is the authority on concepts)
- **`SECURITY.md`** — threat model and disclosure
- **`CONTRIBUTING.md`** — contributor process
- **`MILESTONES.md`** — development log
- **`bench/README.md`** — benchmark methodology and reproduction recipe
- **`tests/fuzz/README.md`** — fuzzing targets and the cumulative gate
- **`tests/vectors/README.md`** — which ACVP vectors to fetch, and where

## A note on sources

This project's citation discipline, which is also good practice generally:

> Blog posts are not citations. Wikipedia is not a citation. Stack Overflow is not
> a citation.

Cite the standard, the submission documents, or the ACVP vector format. Reference
implementations are for cross-validation only.

[fips205]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
[fips204]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
[fips203]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
[fips202]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
[fips180]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
[sphincsplus]: https://sphincs.org/
[sphincsref]: https://github.com/sphincs/sphincsplus
[nistpqc]: https://csrc.nist.gov/projects/post-quantum-cryptography
[rfc8391]: https://www.rfc-editor.org/rfc/rfc8391
[rfc8554]: https://www.rfc-editor.org/rfc/rfc8554
[rfc8017]: https://www.rfc-editor.org/rfc/rfc8017
[pqclean]: https://github.com/PQClean/PQClean
[acvp]: https://github.com/usnistgov/ACVP-Server
[ctgrind]: https://github.com/agl/ctgrind
[valgrind]: https://valgrind.org/docs/manual/mc-manual.html
[zigcrypto]: https://github.com/ziglang/zig/tree/master/lib/std/crypto
[tweetnacl]: https://github.com/nandanito/tweetnacl-zig
[repo]: https://github.com/nandanito/slh-dsa-zig
