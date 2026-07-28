# Implementation

How this particular library is built, as distinct from what SLH-DSA is.

<div class="grid cards" markdown>

-   **[Comptime parameterisation](comptime.md)**

    ---

    Twelve parameter sets as twelve monomorphised types, every buffer sized at
    compile time, and structural invariants checked by the compiler rather than
    by tests.

-   **[Constant-time discipline](constant-time.md)**

    ---

    What is secret and what only looks secret, plus the ctgrind harness that
    verifies the claim empirically — including why the whole-signing audit is
    still open.

-   **[How this is tested](testing.md)**

    ---

    Four independent regimes: ACVP known-answer vectors, property tests,
    coverage-guided fuzzing, and Valgrind-based timing verification.

-   **[The two-lane rule](lanes.md)**

    ---

    Why part of this repository is off-limits to AI assistance, and what that
    means if you contribute.

</div>

## Non-negotiables

Every rule below applies to `src/`. They are enforced by review, and several by
the compiler.

| Rule | In practice |
|---|---|
| **Constant-time** | No secret-dependent branches, memory accesses, early returns, or table indices |
| **No allocation in the library** | Stack buffers, comptime sizing. The library takes no allocator because it needs none |
| **Zeroize secrets** | Every secret buffer scrubbed before scope exit, with volatile semantics so the compiler cannot elide it |
| **KAT-validated** | No scheme operation is "functional" until NIST ACVP vectors pass |
| **Fuzzed** | Every parser and attacker-facing API gets a `std.testing.fuzz` harness |
| **Benchmarked** | Within 2× of PQClean's portable `clean` C reference — [measured](testing.md#the-measured-result), 36/36 pass, worst 1.15× |
| **Empirically CT-verified** | ctgrind/Valgrind, not just claimed in a comment |

## Deliberate non-goals

**No dependencies.** Zig standard library only. Partly discipline, partly because
[Lane B](lanes.md) targets `std.crypto`, which cannot take dependencies.

**No runtime parameter selection.** You cannot pass a `ParamSet` value at runtime
and get a scheme. It is a comptime argument, and a binary contains only the sets
it uses. If you need runtime agility, build a dispatch layer over the
specialisations you want — that is your policy decision, not the library's.

**No SIMD.** No hand-vectorised Keccak or SHA-NI paths *of our own*. This is why
the performance gate is pinned to PQClean's *portable* `clean` variant rather than
its AVX2 one: matching hand-written vector assembly with portable Zig is not a
realistic target, and pretending otherwise would make the gate theatre. AVX2
numbers are reported for honesty and never gated.

This is a statement about code in `src/`, not about what runs. `std.crypto` may
still dispatch to CPU instructions underneath — its SHA-256 takes an ARMv8
crypto-extension path on Apple silicon, and that, rather than anything in this
library, is what puts the SHA-2 parameter sets at 0.25×–0.56× of PQClean in the
[measured comparison](testing.md#the-measured-result). Worth knowing before
reading those numbers as a verdict on the code.

**No production claim.** Unaudited. The `🚧 EXPERIMENTAL` banner stays until a
third-party audit, regardless of how many gates are green.

## Current state

Implemented and ACVP-validated across all twelve parameter sets: key generation,
signing and verification, both interfaces, with context strings. Pre-hash
(HashSLH-DSA) is deferred by
[recorded decision](../concepts/assembly.md#context-strings).

Hardening is in progress — see the [README][readme] status table for what is
green today, and [MILESTONES.md][milestones] for the development log. This site
does not duplicate those; they move faster than prose.

[readme]: https://github.com/nandanito/slh-dsa-zig/blob/main/README.md
[milestones]: https://github.com/nandanito/slh-dsa-zig/blob/main/MILESTONES.md
