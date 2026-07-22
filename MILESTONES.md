# Milestone Log

A retrospective dev-log of the path taken through each milestone — the
starting plan, the pivots and decisions along the way, and the outcome. This
complements the forward-looking checklist in `README.md` (§ Roadmap): the
README says *what* is planned; this file records *how* each milestone was
actually reached, so a newcomer can follow the reasoning, not just the result.

All dates are the merge dates on `main`.

---

## Milestone 1 — Key generation (complete, 2026-07-21)

**Goal:** stand up the scaffold and reach the first external-ground-truth
gate as early as possible — NIST ACVP `keyGen` passing for all 12 parameter
sets — because that single gate also exercises both hash-adapter families
(SHA-2 §11.2 / SHAKE §11.1), the ADRS encodings (§4.2–4.3, §11), WOTS+
public-key generation (§5, §5.1) and XMSS tree hashing (§6.1).

**Outcome:** `slh_keygen_internal` + `KeyPair.generate` (§9.1, §10.1) landed
in **#14**, passing ACVP **keyGen 120/120** across all 12 sets. A Codex review
round on that PR caught two real issues (a weak-entropy fallback in keygen; the
KAT runner exiting 0 on zero vectors) that unit tests had missed — which is why
the Codex review-loop became standing practice for code PRs.

---

## Milestone 2 — Signing path (complete, 2026-07-22)

**Goal:** implement the full SLH-DSA signing chain on top of the KAT-validated
keygen, and close the formal exit gate — ACVP `sigGen` + `sigVer` passing for
all 12 parameter sets — the sign/verify analogue of keyGen 120/120.

### Starting plan: build the chain bottom-up

The signing chain was built in dependency order, each layer merged as its own
one-concern PR and validated by spec-derived property tests against the
KAT-validated keygen (the sign KATs can't run until the *whole* chain exists,
so property tests bridged the gap until the exit gate):

| PR   | Layer                                   | FIPS 205 ref        |
|------|-----------------------------------------|---------------------|
| #19  | WOTS+ / XMSS `sign` + `pkFromSig`       | §5.2–5.3, §6.2–6.3  |
| #21  | Hypertree `ht_sign` + `ht_verify`       | §7                  |
| #23  | FORS `skGen`, `node`, `sign`, `pkFromSig` | §8                |
| #26  | Top-level `slh_sign` / `slh_verify`     | §9.2–9.3, §10.2–10.3 |

The public API shape was decided in **#8** to match `std.crypto.ml_dsa`:
`sign`/`verify` (pure), `signWithContext`/`verifyWithContext` (context string,
≤ 255 bytes else `error.ContextTooLong`), and `signInternal`/`verifyInternal`
(the FIPS 205 §9 internal interface, exposed for the ACVP internal test mode).
The same decision **deferred HashSLH-DSA** (the pre-hash variant) out of scope.

### The exit gate: ACVP sigGen / sigVer (#25 → PR #27)

Pure test-infrastructure work: extend the existing keyGen KAT runner with
`sigGen` and `sigVer` modes and validate byte-for-byte against NIST's vectors.

#### What the ACVP corpus actually looks like (discovery)

Inspecting the real vectors (`usnistgov/ACVP-Server`) reshaped the plan:

- sigGen has **72 test groups**, sigVer **36**, spanning three orthogonal axes:
  `signatureInterface` (`internal` / `external`), `preHash`
  (`none` / `pure` / `preHash`), and — for sigGen — `deterministic`.
- Each folder ships an **`internalProjection.json`** that already merges the
  prompt inputs with the expected outputs into one self-contained file — the
  same single-file shape the keyGen runner already consumed.

#### Decisions and pivots

1. **Vector file: use `internalProjection.json`** rather than merging
   `prompt.json` + `expectedResults.json` by hand. It is self-contained and
   matches the runner's existing single-file model, so keyGen/sigGen/sigVer
   all load identically.

2. **Cover both interfaces, both randomness modes.** Internal →
   `signInternal`/`verifyInternal` (M direct); external →
   `signWithContext`/`verifyWithContext` (context-string domain separation).
   Deterministic vs randomized is keyed on the *presence* of the per-test
   `additionalRandomness` field: absent ⇒ `opt_rand = null` (defaults to
   PK.seed per §9.2), present ⇒ that value.

3. **Pre-hash is out of scope (#8).** `preHash: "preHash"` groups are skipped
   at the group level and counted under `skipped`, never silently dropped.

4. **Wrong-length inputs in sigVer are a rejection, not a runner error.** ACVP
   includes negatives labelled "invalid signature — too large / too small". A
   signature (or public key) whose length ≠ the parameter set's fixed size
   cannot even form the fixed-size array the API takes, so the runner scores it
   as *reject* — which matches the vector's `testPassed: false` — instead of
   erroring out.

5. **Pivot mid-work — the KAT unit tests were never actually running.**
   `zig build test` only compiled the *library* module; the `tests/` KAT
   module's own `test` blocks were dormant. Wiring a `kat_tests` step into the
   build (plus a `_ = @import("kat_runner.zig")` reference, since `zig test`
   only runs tests from explicitly-referenced files) turned them live — and
   that immediately surfaced a latent, never-compiled `std.json.ObjectMap.init`
   call broken by Zig 0.16 API drift, which was fixed in the same PR. A
   self-contained executor plumbing test was added so the glue is covered
   without needing external vectors.

6. **CI wiring was deliberately deferred, not guessed.** The issue listed
   "wire into CI once green," but the vectors are gitignored (the sigGen file
   alone is ~38 MB), so a KAT CI job needs a vector-fetch strategy (fetch-in-CI
   with a pinned ACVP-Server commit, or a cached/vendored subset). That is a
   real decision with trade-offs, so it was split out to **#28** rather than
   forced into this PR.

#### Implementation

- `tests/kat_runner.zig` — `Interface` enum; extended sigGen/sigVer vector
  structs (interface + optional context); `runSigGen` / `runSigVer` executors;
  plumbing + parsing unit tests.
- `tests/kat_main.zig` — parse the group-level `signatureInterface` / `preHash`
  axes and dispatch per test; skip pre-hash groups.
- `build.zig` — fold the `tests/` KAT unit tests into `zig build test`.
- `tests/vectors/README.md` — document the `internalProjection.json` source,
  the sparse-clone fetch recipe, per-mode field tables, and pre-hash handling.

#### Validation

Against the ACVP sample vectors, all 12 parameter sets, both interfaces:

| Mode   | Result                         | Pre-hash skipped |
|--------|--------------------------------|------------------|
| keyGen | **120/120** (regression)       | 0                |
| sigGen | **336/336** byte-identical     | 288              |
| sigVer | **336/336** accept/reject      | 168              |

`zig build test`: **65/65** (57 library + 8 KAT). The `s` parameter sets sign
slowly under `Debug`, so the full sweep was run with `-Doptimize=ReleaseFast`.

#### Review and merge

Codex review-loop reached a clean round with no findings (twice); CI was green
across the full matrix (build-test ×4, ctgrind, fuzz, fmt, lane-B). PR **#27**
was squash-merged to `main` (`2cc99bb`), closing issue **#25**.

### Outcome

Milestone 2 is complete: the full signing chain — WOTS+/XMSS → hypertree →
FORS → top-level `slh_sign`/`slh_verify` — is implemented and validated against
external NIST ground truth for all 12 parameter sets, across the internal and
external (context-string) interfaces.

### Deferred / follow-ups

- **#8** — HashSLH-DSA (pre-hash) variants; those ACVP groups are skipped.
- **#28** — run the ACVP KAT suite in CI with a vector-fetch strategy.

### Reference

Issues: #8 (API + pre-hash decision), #25 (exit gate), #28 (CI follow-up).
PRs: #19, #21, #23, #26 (chain), #27 (exit gate).
Key commit: `2cc99bb` (sigGen/sigVer KAT wiring).

---

*Milestone 3 (hardening — constant-time audit, fuzz harnesses, PQClean
benchmarks) will be appended here as it progresses.*
