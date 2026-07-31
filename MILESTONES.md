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

- **#45** — HashSLH-DSA (pre-hash) variants; those ACVP groups are skipped.
  (Originally tracked as part of #8, which bundled it with the `ctx` parameter.
  The `ctx` half landed here; #8 was closed and the pre-hash half moved to #45.)
- **#28** — run the ACVP KAT suite in CI with a vector-fetch strategy.

### Reference

Issues: #8 (API + pre-hash decision), #25 (exit gate), #28 (CI follow-up).
PRs: #19, #21, #23, #26 (chain), #27 (exit gate).
Key commit: `2cc99bb` (sigGen/sigVer KAT wiring).

---

## Milestone 3 — Hardening and release (complete, 2026-07-29)

**Goal:** move from "passes the KATs" to "defensible" — empirical constant-time
verification, fuzz coverage, a published performance comparison, and enough
documentation that a reader can check the reasoning rather than trust it.

The recurring theme of this milestone was that **each gate turned out to be
measuring something narrower than it claimed**, and most of the work went into
closing the gap between the claim and the measurement.

### Fuzzing (#9 → `c461ece`, 2026-07-24)

The original gate said "≥24h fuzzing in CI". GitHub Actions caps a job at 6h, so
that gate could never have been met as written. It was replaced with a
*cumulative* one: a nightly workflow fuzzes a bounded window, persists the
corpus, and a component graduates once accrued time crosses the threshold.

Two Zig 0.16 obstacles shaped the implementation. The stock test runner does not
compile under `--fuzz` (a `StackTrace` type split), which forced a vendored
patched runner. And `--fuzz=N` exits 0 even when it finds a crash, so failure has
to be detected out of band rather than from the exit code — a silent-success
failure mode that would have made the whole job decorative.

**#33** then made the PR-time fuzz smoke a required status check, so the nightly
job is a depth gate rather than the only thing standing between a regression and
`main`.

### Constant-time audit (#34 → `f9e93aa`, `3138c31`)

Landed in two passes: component-level taint tracking first, then the whole
keygen + sign path.

The blocker on the second pass was **classification, not correctness**.
`PK_FORS` and each XMSS root descend from `SK.seed`, so taint propagation marked
them undefined — but each is the message the next WOTS+ signs, and its base-`w`
digits set that layer's chain lengths. A tainted value gating a loop bound made
memcheck report thousands of errors on code that is constant-time. FIPS 205
§9.3/§7.2 has the verifier recompute both from the published signature; nothing
had told Valgrind that. `src/ct.zig` supplies the missing half — `declassify`,
gated on `builtin.valgrind_support`, called at exactly three sites (`R`,
`PK_FORS`, each XMSS root), each citing the algorithm that publishes the value.
Kept deliberately minimal: declassifying more would silence the same false
positives and blind the audit to a real leak.

A **negative control** was added alongside, because a taint harness that has gone
inert reports the same clean result as one that is genuinely passing. The control
fires first; the two clean runs only mean something because it does.

Review also caught a real hole behind a cosmetic-looking finding: the harness ran
only 128f, but FIPS 205 §11.2 widens `H`/`T_l`/`H_msg` to SHA-512 and `PRF_msg`
to HMAC-SHA-512 at `n > 16` — and `SK.prf` is that HMAC's key, so secret-keyed
SHA-512 was entirely unaudited. Coverage was extended to 128f + 192f across both
families rather than hedging the README wording.

### Benchmarks (#10 → `c0abd63`; #40 → `.github/workflows/bench.yml`)

The clearest instance of this milestone's theme: the first measurement was
*correct* and still didn't mean what the headline said.

**#10** pinned the gate to PQClean's portable `clean` variant and measured
36/36 inside it, worst 1.15×. But the run was on arm64, where Zig's SHA-256
takes an ARMv8 crypto-extension path while PQClean `clean` is portable C *by
definition of the pinned variant*. The SHAKE sets passed on their own merits;
the SHA-2 sets were carried by a CPU feature. **#40** recorded that and
predicted, extrapolating from an extensions-disabled rebuild, that a portable
x86-64 run would put nine of eighteen SHA-2 measurements over the gate.

The x86-64 run refuted its own issue. Actual: **one of eighteen**, mean 1.85×.
Zig's portable SHA-256 trails PQClean's portable C by ~1.85× on x86-64-v3, not
the ~2.05× seen on Apple silicon — a pessimistic extrapolation that did not
survive measurement.

Two decisions came out of it.

**The gate is now measured portable-against-portable**, with the target named
(`-Dcpu=x86_64_v3`) rather than left as "equivalent hardware". Gating an
accelerated build measures the CPU's hash unit, not the library — and it is a
gate that cannot fail for the right reason, since a regression in the
surrounding SLH-DSA code would hide behind the hash speedup. Accelerated
(36/36, worst 1.00×) and PQClean `avx2` (2.3×–4.3× over `clean`) are published
alongside, never gated.

**The single exceedance is attributed rather than excused.**
`SLH-DSA-SHA2-256s keygen` sits at 2.06×. SHAKE sits at 0.96× across all
eighteen measurements, and the two families run **the same structural code** —
`wots.zig`, `xmss.zig`, `hypertree.zig` and `fors.zig` are all generic over
`hash.zig`'s `Hash(p)`, which dispatches to one of the two adapters in a single
`switch`. Nothing above the adapter branches on family. So the SHAKE column
isolates the excess to the **hash-adapter layer** rather than to this project's
SLH-DSA machinery.

That is the accurate form of the claim, and it is weaker than "differ only in
the hash primitive" — which is what an earlier draft of this section said. The
two adapters differ on three axes, not one:

- **ADRS encoding.** §11.1 hashes the expanded 32-byte address (`Adrs.expand()`);
  §11.2 hashes the 22-byte compressed `ADRSc`.
- **MGF1.** §11.2's `H_msg` is MGF1 over SHA-256/SHA-512; §11.1 has no MGF1
  layer at all.
- **The primitive is not even constant within the SHA-2 family.** `H`, `T_l` and
  `H_msg` use SHA-256 at `n = 16` and **SHA-512** at `n = 24, 32`; `PRF_msg` is
  HMAC-SHA-256 or HMAC-SHA-512 on the same split. `F` and `PRF` are always
  SHA-256.

That last point matters for this specific number. `SLH-DSA-SHA2-256s` is
`n = 32`, so its keygen drives `F` (SHA-256) *and* `H` (SHA-512). Calling the
2.06× "`std.crypto`'s SHA-256" is wrong; it is `std.crypto`'s SHA-2 family, and
for this measurement mostly SHA-512.

The direction of the argument survives, and two of those three axes push toward
it rather than against: §11.2 feeds *less* data per hash call (22 bytes against
32) and still comes out slower, and MGF1 runs once per operation against the
millions of `F`/`H` calls that dominate a signature. What did not survive was
the precision, and the fix was to weaken the wording rather than wait for a
reviewer to break it.

Phase gate 4 is treated as satisfied with the exception named, which is a
stronger and more durable claim than 36/36 measured on a machine whose SHA-256
unit did the work.

The comparison harness lives in `bench/pqclean/` and stays deliberately outside
the Zig build graph, so `zig build` still needs no C toolchain.

### Documentation (#36 → `319b967`, #39, #43 → `f0814a0`)

A learning-oriented mkdocs site at <https://nandan.me/slh-dsa-zig/>: why
hash-based signatures exist, a chapter per component in dependency order,
per-module walkthroughs mapped to FIPS 205, and a glossary. **#39** fixed
Material icon shortcodes rendering as literal text — `mkdocs build --strict`
does not catch that, so the CI guard asserts on built output instead. **#43**
added a build-it-yourself study path with per-stage exercises and self-check
questions, plus a stage on what these schemes cost on constrained hardware.

### The upstream decision (#11, closed 2026-07-29)

#11 was to ask the Ziglang project whether `std.crypto.sign.slh_dsa` was wanted
before spending Lane B effort. It was closed without being asked, because the
question turned out to have no venue.

Zig moved from GitHub to Codeberg in November 2025, so the proposed venue no
longer exists. More decisively, the Code of Conduct now prohibits — in the
ziglang Codeberg org, `#zig` on Libera, and the development Zulip — LLM-generated
content, paraphrasing, editing, brainstorming-then-writing-it-yourself, using
LLMs to find bugs, and *talking about* LLM use. The plan in #11 was to disclose
this repository's two-lane structure openly and ask what provenance evidence
would be accepted; that post would itself violate the CoC, and discussing the CoC
is separately out of bounds.

The two-lane arrangement was designed against an earlier and much narrower
version of that policy. Rather than carry a blocked assumption through the
schedule, **upstreaming came off the roadmap** and became a separate decision to
be taken deliberately later. `upstream-candidate/` stays reserved with its rules
in force. The standalone library was promoted to the primary goal.

### Outcome

Phase gates 1 (functional), 2 (constant-time), 4 (benchmark) and 5
(documentation) satisfied; gate 3 (fuzz) accrues nightly. The `🚧 EXPERIMENTAL`
banner stays up — it comes down for a third-party audit, not for a green CI run.

### Deferred / follow-ups

- **#38** — iterative treehash for `xmss_sign`, filed on the premise that the
  auth path recomputes shared subtrees. **Investigated and refuted:** the `h'`
  sibling subtrees are pairwise disjoint, so the existing recursion already
  computes each leaf exactly once and does `h'` *fewer* node hashes than a
  treehash sweep would. No optimisation available; the docs that repeated the
  claim were corrected instead.
- **#6** — lift the ctgrind `x86-64-v3` pin once Valgrind can decode AVX-512.
  Externally blocked.
- **#45** — HashSLH-DSA pre-hash variants.

### Reference

Issues: #9, #33 (fuzz), #34 (constant-time), #10 (benchmarks), #36, #39, #43
(docs), #11 (upstream decision), #8 (closed — already complete).
PRs: #41 (benchmarks), #42 (whole-path CT audit), #44 (study path + roadmap).
Key commits: `c461ece`, `f9e93aa`, `3138c31`, `c0abd63`, `319b967`, `f0814a0`.

---

## Release note — v0.1.1 supersedes v0.1.0 (2026-07-30)

Both tags landed the same day. `v0.1.1` is documentation and comments only; the
library is behaviour-identical.

`v0.1.0` was tagged at `1966991`, and two corrections landed in the hours after
it — late enough to miss the tag, early enough that nothing depended on it yet.

1. **A stale example header.** `examples/basic_sign.zig` still carried
   "This example will `@panic` until the scheme bodies land" from the stub era.
   `examples` is in `build.zig.zon`'s `paths`, so that shipped inside the package:
   the most obvious first file told a new reader the library does not work.
2. **The benchmark attribution named the wrong primitive.** Four documents said
   the SHAKE and SHA-2 sets "differ only in the hash primitive" and pinned the one
   over-gate measurement on `std.crypto`'s SHA-256. The adapters differ on three
   axes, and `SLH-DSA-SHA2-256s` is `n = 32`, where `H` and `T_l` are **SHA-512**.
   Nine instances across four files — six of them inside the published package
   (`README.md` ×3, `bench/README.md` ×3).

The second is why this became a release rather than an erratum. An erratum is the
right instrument for a defect you cannot fix; this was one tag command. Publishing
a correction everywhere else while leaving it standing in the artifact those
corrections describe would have been the worse of the two options — and the cost
of re-pointing users only ever rises from here.

`v0.1.0` stays published and marked superseded. It is the honest record of what
was tagged.
