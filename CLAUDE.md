# CLAUDE.md

Guidance for Claude Code working in this repository. Read this on every
session start. Defer to the actual docs for depth; this file is the
**operating manual**.

---

## What this is

`slh-dsa-zig` — a pure-Zig implementation of SLH-DSA per FIPS 205.
Phase 1 of the [`pq-zig`](https://github.com/nandanito) post-quantum
effort. Direct successor in philosophy to
[`tweetnacl-zig`](https://github.com/nandanito/tweetnacl-zig).

Status: **🚧 EXPERIMENTAL — DO NOT USE IN PRODUCTION.** The scaffold
compiles; crypto bodies are stubs that `@panic` with FIPS 205 section
references. The job over the coming weeks is to fill those in.

For deep context:
- `README.md` — public-facing overview, status table, parameter sets.
- `ARCHITECTURE.md` — FIPS 205 § ↔ file mapping, layering, design rules.
- `CONTRIBUTING.md` — full contributor process for humans.
- `SECURITY.md` — threat model and disclosure.
- `upstream-candidate/README.md` — **read this before touching that directory.**

---

## ⚠️ The two-lane rule (most important thing in this file)

This repository has **two lanes** with different rules for AI assistance.
Violating the boundary breaks the project's eventual upstream contribution.

### Lane A — everything outside `upstream-candidate/`

The standalone library, tests, benchmarks, examples, build script, CI.
**AI assistance is welcome here.** Claude Code may draft code, propose
architectures, write tests, refactor, fix bugs.

### Lane B — `upstream-candidate/`

Reserved for code that will eventually be PR'd to Zig's `std.crypto`.
The Ziglang project does **not** accept AI-generated code into `std`.

**Claude Code rules for `upstream-candidate/`:**

1. **Never write code in this directory.** Not even one line. Not even
   "obvious" stubs. Not even fixes to typos. If a file under
   `upstream-candidate/` needs to change, **stop and tell Nandan.**
2. **Never copy from `src/` into `upstream-candidate/`.** The whole point
   of Lane B is an independent reading of FIPS 205. Cross-pollination
   defeats it.
3. **You may read** files in `upstream-candidate/` to answer questions or
   review human-authored code — but only when explicitly asked, and only
   as a critic, not as an author.
4. **You may help with non-code artifacts** in `upstream-candidate/` (the
   README itself, a `.gitkeep`, a doc page) — but flag the boundary
   crossing explicitly and confirm before saving.

### When you don't know which lane

If Nandan asks for code and it's not obvious from context which lane it's
for: **ask first.** Default assumption when truly ambiguous: **Lane B**
(don't write the code; explain instead).

Heuristic: if the request mentions "upstream", "for std.crypto",
"pure human", "I want to write this myself", or "study", treat it as
Lane B. If the request mentions "the library", "the test runner",
"the benchmark", "fix CI", "add an example", treat it as Lane A.

### CI enforces the trailer

Every commit touching `upstream-candidate/` must carry this trailer:

```
Lane B compliant: human-authored, no AI assistance.
```

`.github/workflows/ci.yml` rejects PRs that violate this. Claude Code
must **never** add this trailer to its own commits. If a commit is
co-authored by an AI, it does not belong in `upstream-candidate/`.

---

## Cryptographic discipline (apply to every line of crypto code)

These are non-negotiable for code in `src/`:

| Rule | What it means in practice |
|---|---|
| **Constant-time** | No secret-dependent branches. No secret-dependent memory accesses. No early returns on secret data. No table lookups indexed by secret bits. |
| **No allocations in hot paths** | Stack buffers, comptime sizing, explicit lifetimes. Heap use must be justified and documented. |
| **Zeroize secrets** | Every secret cleared before scope exit. Use volatile semantics where the compiler may DCE the zeroing. |
| **KAT-validated** | Scheme-level operations (keyGen/sigGen/sigVer) must pass NIST ACVP vectors before being declared functional. Components without NIST vectors (WOTS+, XMSS, FORS internals) are validated via the scheme-level KATs that exercise them, spec-derived property tests, and reference-derived intermediate fixtures where needed (issue #7). |
| **Fuzzed** | Every parser, deserializer, and attacker-facing API gets a `std.testing.fuzz` harness. The 6h GHA job cap means the gate is *cumulative*: a nightly workflow fuzzes a bounded window, persists the corpus, and accrues ≥24h total before a component graduates. See `tests/fuzz/` and issue #9. |
| **Benchmarked** | Within 2× of PQClean's portable `clean` C reference, **both sides built without hardware hash acceleration** — on x86-64 that means `-Dcpu=x86_64_v3` (AVX2, no SHA-NI). Accelerated and AVX2 numbers are published alongside, never gated. Gating an accelerated build measures the CPU's hash unit, not this library, and would let a regression in the surrounding SLH-DSA code hide behind it. See `bench/README.md` and issue #40. |
| **ctgrind/valgrind-verified** | Constant-time properties empirically verified, not just claimed. |

When you produce code that *might* violate any of these, **flag it
inline** in your response, even if the user didn't ask. Examples:

- `// CT-CONCERN: this branch depends on a secret bit. Needs refactor before merge.`
- `// ALLOC: heap allocation here — justify or move to stack.`
- `// TODO(zeroize): secret material needs explicit scrubbing before return.`

---

## Citation discipline

Every cryptographic decision in `src/` must cite a primary source.
Authoritative sources, in order of preference:

1. **FIPS 205** (the standard itself). Cite sections, algorithms, and
   table numbers: `// FIPS 205 §5.1 Algorithm 6 — wots_PKgen.`
2. **The SPHINCS+ submission documents** for design rationale not in the
   FIPS standard.
3. **NIST ACVP** for test vector format.
4. **PQClean and reference implementations** — for cross-validation only.
   Never copy code verbatim. Cite as "see PQClean for shape" if you
   referenced it, but the implementation must be your own.

Blog posts are not citations. Wikipedia is not a citation. Stack
Overflow is not a citation.

**Cite the final publication (FIPS 205, August 2024), never the initial
public draft (ipd).** The final standard inserted Algorithm 1 (`gen_len2`,
§3.2), which shifted every later algorithm number up by one relative to the
ipd, and renumbered the WOTS+ subsections (`chain` §5, `wots_pkGen` §5.1,
`wots_sign` §5.2, `wots_pkFromSig` §5.3). Verify each algorithm number
against the final PDF before citing it — a number recalled from memory or
copied from a draft-era source is very likely off by one. See issue #16 for
the full draft→final mapping.

Doc comments in `src/` should include the FIPS 205 reference like so:

```zig
/// FIPS 205 §5 Algorithm 5 — chain(X, i, s, PK.seed, ADRS).
///
/// Iterates the WOTS+ chaining function `s` times starting at index `i`,
/// applying the hash + tweak per step. Constant-time over `s` because the
/// caller passes a public chain length.
pub fn chain(...) ...
```

---

## Build and test commands

```sh
zig build                                   # default install (static lib)
zig build test                              # run unit tests
zig build kat -- --mode keygen --vectors tests/vectors/keygen.json
zig build bench                             # benchmarks (ReleaseFast default)
zig build bench -- --param-set SLH-DSA-SHAKE-128s --op sign
zig build examples                          # build all examples
zig build example_basic_sign                # build + run a single example
zig build ctgrind                           # build the constant-time harnesses
                                            # (the real check needs Valgrind — CI only)
zig fmt --check .                           # format check (CI runs this)
zig fmt .                                   # apply formatting
```

Optimisation override for benchmarks:

```sh
zig build bench -Dbench-optimize=ReleaseSafe
```

**Before claiming any change is done**, in this order:

1. `zig fmt .`
2. `zig build` (must succeed)
3. `zig build test` (must pass)
4. If you touched anything in `src/`, mentally re-check the
   cryptographic discipline table above and surface any concerns.
5. If you touched anything in CI or the build, also build `examples` and
   `bench` to catch wiring breakage.

If any of those fail, **fix it before reporting back.** Don't claim a
change works if you didn't actually run the build.

---

## Code conventions

- **Style:** match `tweetnacl-zig`. Concise, technical, no marketing
  language. Module-level `//!` doc comment at the top of every file.
- **Tests live next to code.** `test "..." { ... }` blocks at the end of
  the file, not in a separate test directory. `tests/` is for KAT/
  integration infrastructure only.
- **Comptime everything that can be.** Parameter sets are comptime.
  Buffer sizes are comptime. The 12 specialisations of `Slh_Dsa(...)` are
  monomorphised at the call site.
- **No `std.heap.GeneralPurposeAllocator` in the library.** The library
  takes allocators explicitly when it needs them. Test/bench/example
  binaries use `std.heap.ArenaAllocator` on `std.heap.page_allocator`.
- **No dependencies.** Zig stdlib only. This matches what upstream will
  eventually require.
- **License:** 0BSD for code (`src/`, `tests/`, `bench/`, `examples/`, build
  files). **CC BY 4.0** for documentation (`docs/`, top-level `*.md`) — see
  `LICENSE-DOCS`. Code samples inside a docs page are code, so 0BSD. When adding
  a file, match whichever it is; if it could be read as either, treat it as code.

---

## File organization (don't drift)

```
src/              ← Lane A library. Crypto primitives, top-level scheme.
  root.zig        ← public API surface; only re-exports.
  slh_dsa.zig     ← top-level Slh_Dsa(p) namespace per FIPS 205 §9/§10.
  params.zig      ← all 12 parameter sets (FIPS 205 §11 Table 2).
  address.zig     ← 22-byte compressed ADRS (FIPS 205 §11.2).
  util.zig        ← Algorithms 4 (base_2b) + 3 (toByte).
  ct.zig          ← constant-time audit hooks (declassify). Zero-cost unless
                    built with Valgrind support; see tests/ctgrind/.
  hash.zig        ← family dispatcher (sha2 vs shake).
  hash_sha2.zig   ← FIPS 205 §11.2 six-function adapter.
  hash_shake.zig  ← FIPS 205 §11.1 six-function adapter.
  wots.zig        ← FIPS 205 §5 (WOTS+).
  xmss.zig        ← FIPS 205 §6 (XMSS).
  hypertree.zig   ← FIPS 205 §7 (hypertree).
  fors.zig        ← FIPS 205 §8 (FORS).

tests/            ← Lane A test infrastructure (KAT runner + main).
  kat_runner.zig  ← ACVP JSON parser + dispatcher.
  kat_main.zig    ← CLI for `zig build kat`.
  vectors/        ← NIST ACVP vector files (gitignored except README.md).
  fuzz/           ← std.testing.fuzz harnesses + vendored test runner (#9).
  ctgrind/        ← constant-time harnesses (#34). taint_components.zig
                    (primitives), taint_sign.zig (whole keygen + sign),
                    negative_control.zig (proves the taint isn't inert).
                    Only meaningful under Valgrind — CI-only, x86_64-only.

bench/            ← Lane A benchmarks.
  bench.zig       ← the harness itself (`zig build bench`).
  pqclean/        ← PQClean `clean` comparison for the 2× gate: C harness +
                    shell drivers, deliberately OUTSIDE the Zig build graph.
                    `zig build` never invokes them and the repo still needs no
                    C toolchain — they exist only to reproduce a published
                    number. This is not an exception to "no dependencies".
examples/         ← Lane A runnable examples demonstrating the API.

docs/             ← Lane A mkdocs learning site (concepts, components, glossary).
  requirements.txt  ← PINNED docs-only Python tooling. Never imported by src/;
                      `zig build` must keep working with no Python installed.
mkdocs.yml        ← site config (repo root — standard mkdocs layout).

upstream-candidate/  ← Lane B. OFF-LIMITS for code authorship.

.github/workflows/   ← CI: ci.yml, ctgrind.yml, fuzz.yml.
```

When adding a new source file:
- Library code → `src/<name>.zig`, re-exported via `internal` in `src/root.zig`.
- Test infrastructure → `tests/<name>.zig`.
- Examples → `examples/<name>.zig` and wire into `build.zig` via `addExample(...)`.
- Benchmarks → extend `bench/bench.zig`, don't add new top-level bench files.
  Reference-comparison tooling belongs in `bench/pqclean/` and must stay out
  of `build.zig`.
- Docs pages → `docs/<section>/<name>.md` and add to `nav:` in `mkdocs.yml`.
  Verify with `mkdocs build --strict` (CI runs it; anchor validation is on, so a
  stale `#anchor` fails the build).

---

## Workflow expectations

### When given a task

1. **Identify the lane.** If unclear, ask. If still unclear, assume Lane B.
2. **For Lane A coding tasks:**
   - Read the relevant FIPS 205 section before producing code.
   - State which sections you're implementing in the response.
   - Apply the crypto discipline; flag concerns inline.
   - Run `zig fmt`, `zig build`, `zig build test` before claiming done.
3. **For Lane B tasks:**
   - Do not produce code. Produce explanation, walk-throughs, review
     comments, test inputs.
   - When reviewing Nandan's human-written code, cite FIPS 205 section
     numbers in your feedback.

### Commit messages

- Conventional-style summary line: `wots: implement chain function`.
- Body explains *why* and cites FIPS 205 sections for non-obvious choices.
- Lane B commits: include `Lane B compliant: human-authored, no AI assistance.`
  Lane A commits: **never include that trailer.** It is a lie and CI assumes
  it means human-authored.
- Claude Code may draft commit messages for Lane A. Nandan reviews before
  committing.

### Pull requests

- One concern per PR. Don't bundle "WOTS+ implementation" with "CI tweaks".
- PR description references the FIPS 205 sections implemented.
- Status checks must be green: `fmt`, `build-test` (x86_64 + ARM64, Debug
  + ReleaseSafe), `kat` (ACVP keyGen/sigGen/sigVer against the pinned NIST
  vectors), and `lane-b-trailer` (if any commit touched `upstream-candidate/`).

---

## What "done" means

A change is **not done** until it passes the relevant gates from the project's
six phase gates:

1. **Functional** — KATs pass on x86_64 and ARM64.
2. **Constant-time** — ctgrind/valgrind clean on hot paths.
3. **Fuzz** — ≥24h *cumulative* fuzzing (nightly, corpus persisted) surfaces no crashes.
4. **Benchmark** — within 2× of PQClean reference on equivalent hardware.
5. **Documentation** — README, inline docs, examples up to date.
6. **Banner** — `🚧 EXPERIMENTAL` remains prominent until specific
   gates move it forward.

Not every change has to pass all six (a CI tweak doesn't need a benchmark
result), but a crypto primitive does. When proposing "done", state which
gates apply and which you've satisfied.

---

## Things to never do

- Never write code in `upstream-candidate/`.
- Never copy code between Lane A and Lane B.
- Never claim a build passes without running it.
- Never silently drop a constant-time concern; flag it inline.
- Never depend on anything beyond the Zig standard library.
- Never add the `Lane B compliant:` trailer to a Claude-authored commit.
- Never invent FIPS 205 section numbers in citations. If you're unsure,
  say "see FIPS 205 (section TBD)" and Nandan will fix it.
- Never push to `main` directly. Branch → PR → review → merge.
- Never claim "production-ready". This library is experimental and will
  remain so until a third-party audit. State that clearly when relevant.

---

## Things to do without being asked

- Run `zig fmt` after editing `.zig` files.
- Run `zig build test` after changes that could affect tests.
- Flag constant-time concerns in `src/` even if the user didn't ask.
- Cite FIPS 205 sections in doc comments for new crypto code.
- Note when a change might require updating `ARCHITECTURE.md` or `README.md`.
- Note when a change might affect the public API surface (and therefore
  semver — see `build.zig.zon`).

---

## Pointers

- Project context: `CONTEXT_HANDOFF.md` (in the Claude Desktop project,
  not in this repo) — the planning history that led here.
- FIPS 205: <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf>
- NIST ACVP server: <https://github.com/usnistgov/ACVP-Server>
- PQClean reference: <https://github.com/PQClean/PQClean>
- SPHINCS+ team reference: <https://github.com/sphincs/sphincsplus>
- Zig `std.crypto`: <https://github.com/ziglang/zig/tree/master/lib/std/crypto>
- Predecessor library: <https://github.com/nandanito/tweetnacl-zig>

When in doubt about a cryptographic question, **the FIPS standard is the
oracle**. When in doubt about Zig style, **`std.crypto` is the oracle**.
When in doubt about Lane discipline, **ask Nandan**.
