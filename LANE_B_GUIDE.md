# Lane B Guide — writing the upstream SLH-DSA by hand

This guide is for the human (Nandan) who will write the code in
`upstream-candidate/`. It is deliberately written in plain language, and
it deliberately contains **no code** — not even pseudocode. Lane B code
must come from you reading FIPS 205, not from anything an AI wrote,
and that includes this file.

Read [`upstream-candidate/README.md`](upstream-candidate/README.md)
first; it has the hard rules. This guide is about *how to actually do
the work*, day to day.

---

## 1. When to start

Not yet. Lane B starts when both of these are true:

1. **Lane A passes the full ACVP KAT suite** (keyGen + sigGen + sigVer,
   all 12 parameter sets). That gives you a known-good oracle to test
   your own code against. (Tracked as Lane A `v0.1.0`.)
2. **The Zig core team has said SLH-DSA in `std.crypto` is welcome**
   (issue #11). Ask before you spend weeks writing it. If the answer is
   no, Lane B never starts and that is fine — Lane A is the deliverable.

## 2. What you are actually building

A second, independent implementation of SLH-DSA, written by you alone,
laid out the way `std.crypto` is laid out — not the way Lane A is laid
out. When it is done, it gets PR'd to `ziglang/zig` under your name,
with an honest description of how it was made.

The point of doing it twice: the Zig project does not take AI-written
code, and an independent second reading of the spec is also simply a
good way to catch bugs neither implementation would catch alone.

## 3. Before you write anything

Spend the reading time first. Suggested order:

1. **FIPS 205, §3 and §4** — notation, data structures, ADRS. Most
   implementation bugs in SLH-DSA are byte-layout bugs from these
   two sections.
2. **FIPS 205, §5 through §9, in order** — the algorithms build on each
   other exactly in that order (WOTS+ → XMSS → hypertree → FORS →
   top-level). Read each section until you could explain the algorithm
   to someone else with the book closed.
3. **FIPS 205, §10 and §11** — the external API (context strings,
   pre-hash variants) and the hash instantiations. §11.2 (SHA-2) has
   more sharp edges than §11.1 (SHAKE); read it twice.
4. **The SPHINCS+ papers** (sphincs.org) — only for the *why*. The
   standard tells you what to do; the papers tell you why it is safe.
5. **Zig `std.crypto` source** — for style only. Look at how ML-DSA and
   ML-KEM are structured: file layout, naming, doc comments, how tests
   are written in-file. Your Lane B code should look like it was always
   part of that tree.

## 4. Working rules (session hygiene)

These keep the "no AI, no Lane A" claim honest and defendable:

- **Separate sessions.** Never write Lane B code in the same sitting
  where you have been reading or reviewing Lane A's `src/`. Close those
  files. If you just spent an hour in `src/wots.zig`, do something else
  before opening your Lane B editor.
- **No AI anywhere in the loop.** No Claude, no Copilot, no
  autocomplete-from-a-model, no "just explain this error to me and
  suggest a fix." Turn model-backed assistants off in your editor for
  this repo, or work in an editor profile that has none. Using an AI to
  understand the *standard* is allowed; using it to produce or repair
  *anything that lands in a file* is not.
- **Work from the spec, not from memory of Lane A.** When you get
  stuck, the move is: reopen FIPS 205 at the relevant algorithm and
  re-derive. Not: remember how Lane A did it.
- **Keep a work log.** A short dated note per session (what you read,
  what you wrote, what you got stuck on) is cheap and becomes your
  provenance evidence if anyone upstream asks how this code was made.
- **Commit trailer, every commit:**
  `Lane B compliant: human-authored, no AI assistance.` CI rejects
  Lane B commits without it.

## 5. Suggested build order

Same keygen-first order that worked for Lane A (issue #7), because it
gets you external validation earliest:

1. Parameters and the two data-conversion helpers (§3, §11 Table 2).
2. ADRS, both encodings (§4, §11.2). Test the byte layout hard.
3. The six hash functions, both families (§11). Check them against
   hand-built concatenations before moving on.
4. WOTS+ chaining and public-key generation (§5.1–5.2).
5. XMSS tree hashing (§6.1).
6. Key generation (§9.1, §10.1) — **stop here and run the ACVP keyGen
   vectors.** If all 12 parameter sets pass, everything you have built
   in steps 1–5 is right. (The signing side in steps 7–8 is still
   unwritten and unvalidated at this point.)
7. The signing side: WOTS+ sign, XMSS sign, hypertree, FORS, top-level
   sign/verify with context strings (§5.3 → §10).
8. ACVP sigGen + sigVer, all 12 sets.

## 6. How to test without contaminating anything

- The **shared test corpus is the only bridge** between lanes: the NIST
  ACVP vector files under `tests/vectors/`. Both lanes must pass the
  same vectors. Using them is not contamination — they come from NIST,
  not from Lane A.
- Write your own unit tests in-file, `std.crypto` style. Do not port
  Lane A's tests across; write what the spec suggests to you.
- When a vector fails, debug against the *standard* (recompute a small
  case by hand, print intermediate values, check byte layouts against
  §4/§11 figures). Resist diffing intermediate values against Lane A —
  that is exactly the cross-pollination Lane B exists to avoid. If you
  are truly stuck for days, prefer the SPHINCS+/PQClean *C reference*
  as the comparison oracle; it is not AI-written and it is not Lane A.

## 7. When it is done

- All ACVP vectors pass, both lanes agreeing with NIST independently.
- Layout, naming, and docs match current `std.crypto` conventions.
- The upstream PR states plainly: this repository also contains an
  AI-assisted standalone library (Lane A); the submitted code was
  written separately by hand under the discipline in this repo, and
  here is the work log. Let the maintainers judge with full
  information. Disclosed-first always beats discovered-later.

---

*This guide is Lane A material (it is documentation about process, not
Lane B code). It was drafted with AI assistance and reviewed by Nandan —
which is exactly why nothing in it may be pasted into
`upstream-candidate/`.*
