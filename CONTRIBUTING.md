# Contributing to `slh-dsa-zig`

Thanks for your interest. This document covers how to build, test, and contribute.
Please read [ARCHITECTURE.md](ARCHITECTURE.md) first; it explains the layering and
conventions that any patch needs to fit into.

## Before you start

This project is cryptographic infrastructure. We hold patches to a higher bar than typical
open-source contributions:

- **Correctness over cleverness.** A clear implementation that mirrors FIPS 205 is preferred
  to a clever one that diverges. Cite the section and algorithm numbers.
- **Constant-time discipline.** Every change touching code that handles secret material is
  reviewed for timing side channels.
- **Test coverage.** New code comes with tests. KAT-relevant code adds KAT coverage; other
  code adds property or unit tests.
- **Documentation.** Public functions are documented. Non-obvious choices are explained
  inline with a citation.

If you are unsure whether a change fits, open an issue or a draft PR before investing
significant time.

## Lane A vs Lane B

This repository operates two lanes of contribution. The distinction is important.

### Lane A — Standalone library (top-level repo)

This is most of what you see in the repo. AI-assisted development is permitted. Patches
authored with AI tools are welcome as long as the contributor reviewed every line and
takes responsibility for correctness.

Lane A contributions go through the standard GitHub flow: fork, branch, PR.

### Lane B — Upstream-candidate (`upstream-candidate/`)

Code intended for eventual upstream contribution to Zig's `std.crypto.sign.slh_dsa` lives
in [`upstream-candidate/`](upstream-candidate/) and follows the
[Ziglang community's no-AI policy](https://ziglang.org/news/) for upstream contributions.

Lane B contributions must:

1. Be authored by a human, line by line. AI may be used for spec study, code review, and
   test-harness generation, but **not** to author the code that lands in `upstream-candidate/`.
2. Be made under the contributor's own name in git history (no co-author tags, no pseudonyms
   masking AI assistance).
3. Carry a `Lane B compliant` line in the commit message attesting to (1) and (2).

The two lanes share a specification but not source files. KAT vectors are the bridge: code
in either lane must pass the same vectors. Code is **never** copied between lanes.

If you want to contribute to Lane B, please open an issue describing your intent first so we
can coordinate. Lane B is the slow lane on purpose.

## Setup

You need:

- Zig **0.16.0** on `PATH`.
- A POSIX-ish environment (Linux, macOS, WSL2). Native Windows is supported as a build
  target but the test runner currently assumes POSIX paths.
- `git` for fetching test vectors.

```sh
git clone https://github.com/nandanito/slh-dsa-zig.git
cd slh-dsa-zig
zig build test
```

If `zig build test` passes, you have a working environment.

## Workflow

1. **Pick an issue.** Issues tagged `good-first-issue` are scoped for one-session work.
2. **Branch.** `git checkout -b nnn-short-description` where `nnn` is the issue number.
3. **Implement.** Keep commits small and focused; each commit should leave the tree in a
   working state.
4. **Test.** `zig build test` plus any KATs that apply.
5. **Verify lane.** If you are touching `upstream-candidate/`, re-read the rules above and
   add the `Lane B compliant` line to every commit on the branch.
6. **PR.** Reference the issue, describe what changed and why, link the FIPS 205 sections
   relevant to the patch.

## What to test

Every patch needs at least one test. Bias towards:

- A **KAT** test if the patch touches signing, verification, or any byte-level output. KATs
  are the strongest correctness signal we have.
- A **property** test (round-trip, tamper detection, idempotence) if the patch adds an API
  surface.
- A **unit** test for internal helpers — toy parameter sets are fine, but make at least
  one full-parameter-set check exists somewhere upstream of the change.
- A **fuzz** harness for any new deserialiser or parser.

Run a single test file with `zig test src/foo.zig`. Filter inside a file with
`zig test src/foo.zig --test-filter "name"`.

## Commit-message conventions

```
<scope>: <imperative summary, <= 72 chars>

<body explaining what and why, wrapping at 72 chars, with FIPS 205
section references where relevant>

Lane B compliant   (only if touching upstream-candidate/)
```

`<scope>` is one of: `wots`, `xmss`, `hypertree`, `fors`, `slh-dsa`, `hash`, `params`,
`adrs`, `kat`, `bench`, `ci`, `docs`, `meta`.

Examples:

```
wots: implement chain function per FIPS 205 §5.1 algo 5

The chain function applies F repeatedly, with each step's ADRS
type set to WOTS_HASH and chain-position updated. Indices into the
chain are derived from the public message digest (not secret), so
the bounded loop is acceptable for constant-time.

Adds round-trip unit test plus KAT smoke test against ACVP.
```

```
fors: skeleton FORS signing surface

Defines fors_pkgen, fors_sign, fors_pkFromSig per FIPS 205 §8 with
TODO bodies. Compiles against the parameter-set table; tests are
expect-fail until the bodies land.
```

## Style

- Format with `zig fmt` before committing.
- Use full words in identifiers (`signature_length`, not `siglen`).
- Cite FIPS 205 section / algorithm numbers in comments above non-obvious code.
- Re-use existing helpers in `util.zig` and `address.zig` rather than re-deriving.
- Keep functions short. The FIPS 205 algorithms are short on the page; the implementations
  should not be much longer.

## Review

Every PR is reviewed by the maintainer. Reviews focus on:

1. **Spec correspondence** — does the code match the FIPS 205 algorithm?
2. **Constant-time** — any secret-dependent control flow or memory access?
3. **Allocator discipline** — anything heap-allocated in a hot path?
4. **Zeroisation** — sensitive material zeroed at scope exit?
5. **Test coverage** — does the test prove the property the patch claims?
6. **Documentation** — is the public surface documented and are non-obvious choices
   justified inline?

Expect at least one round of review feedback. Cryptographic patches are reviewed slowly on
purpose.

## Code of conduct

Be kind, be specific, be on-spec. Disagreement is welcome; rudeness is not.

## Questions?

Open a discussion or an issue. We do not have a chat room yet.
