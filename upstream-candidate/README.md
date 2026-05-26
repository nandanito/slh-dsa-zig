# `upstream-candidate/` — Lane B

This directory is **reserved for a future upstream contribution** of
SLH-DSA to the Zig standard library
(`std.crypto.sign.slh_dsa` or wherever the Ziglang team chooses to
locate it). It is currently empty by design.

It is not a copy of the standalone library. It is a deliberately
separate working tree governed by a different ruleset, which this README
documents in full.

## Why two lanes?

The Ziglang project does not accept AI-generated code into `std`. Quoting
from the Ziglang community policy:

> Contributions to the Zig standard library must be authored by humans.
> AI-assisted writing of any kind — autocomplete suggestions, generated
> snippets, refactors produced by a model — disqualifies the patch.

That policy is unambiguous and we want SLH-DSA in `std.crypto`
eventually. So this repository operates as two lanes:

- **Lane A** — the standalone `slh-dsa-zig` library at the repository
  root. AI-assisted authoring is permitted here; it lets us move fast,
  prototype, and have a working library available as a package much
  earlier than upstream could land it.

- **Lane B** — the `upstream-candidate/` tree. **Strictly human-authored**,
  intended for eventual upstreaming to `std.crypto`. Different code,
  written by a human reading FIPS 205 directly, validated against the
  same NIST KAT vectors as Lane A.

The two lanes meet only at the test corpus: both must pass the same
ACVP vectors. That equivalence is the *only* coupling.

## Hard rules for code that lands here

1. **No AI assistance.** No model-generated code, no
   model-suggested refactors, no model-rewritten comments. If you used
   an AI to *understand* the spec, that is fine; if you used one to
   *write* anything that ends up in a file under this directory, that is
   not.

2. **No copy-paste from Lane A.** Not even "I'll just borrow this WOTS+
   chain function, it's just a loop." The whole point of Lane B is an
   independent reading of FIPS 205. Cross-pollination defeats that.

3. **`Lane B compliant` trailer in every commit message.** Every commit
   that touches this directory must include the line:

   ```
   Lane B compliant: human-authored, no AI assistance.
   ```

   This is checked by CI (`.github/workflows/ci.yml`).

4. **Layout intentionally differs from Lane A.** When the time comes the
   structure here will mirror upstream `std.crypto` conventions, not the
   `src/wots.zig` / `src/fors.zig` / etc. split used at the repo root.
   That keeps the temptation to file-by-file mirror down.

5. **Tests live alongside the code, upstream-style.** No separate
   `tests/` directory under `upstream-candidate/`. Use `test {}` blocks
   in the same file, matching how `std.crypto` does it today.

6. **No external dependencies.** Lane A is allowed to depend on whatever
   helps; Lane B must build with nothing beyond the Zig standard
   library, because that is the constraint upstream code has to satisfy.

## Gating

Lane B work does **not** start until Lane A reaches v0.1.0 — that is,
until the standalone library passes the full ACVP KAT suite for all
twelve parameter sets. Until then, this directory holds only this README
and a `.gitkeep`.

The reason: writing Lane B from scratch is expensive. We do it once,
and we do it once we have a known-good reference (Lane A + NIST
vectors) to validate against.

## Authorship and attribution

Lane B commits must be authored under the contributor's real name and
email (matching the Ziglang `CONTRIBUTORS` conventions, whichever is
current at the time of the upstream PR). The eventual upstream PR will
list every Lane B contributor; the Lane A contributors are *not*
implicitly co-authors of Lane B by virtue of having written the
Lane A library.

If a Lane A contributor also wants to contribute to Lane B, they may —
but they must do so in a separate working session, without referring to
the Lane A code while writing.

## Reading list

Anyone working in this directory should have, at minimum:

- FIPS 205 (final, August 2024):
  <https://csrc.nist.gov/pubs/fips/205/final>
- The SPHINCS+ submission package (round 3 for the rationale, round 3.1
  for the chosen parameters):
  <https://sphincs.org/>
- The Zig `std.crypto` source tree, as a style reference for layout,
  naming, and documentation:
  <https://github.com/ziglang/zig/tree/master/lib/std/crypto>

And, of course, the Lane A code in `../src/` is **off-limits** while
writing Lane B.
