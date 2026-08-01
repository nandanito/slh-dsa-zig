# Fuzzing

Coverage-guided fuzzing of slh-dsa-zig's attacker-facing surfaces, using
Zig's built-in fuzzer (`std.testing.fuzz`). Lane A test infrastructure.
Tracked by [issue #9](https://github.com/nandanito/slh-dsa-zig/issues/9).

## What is fuzzed

Effort goes where the input is adversarial by construction. Fuzzing keygen or
sign has little value — their inputs are secret/local, not attacker-supplied.

| Target | Surface | Property |
| --- | --- | --- |
| `verify` (SLH-DSA-SHAKE-128f) | FIPS 205 §9.3/§10.3 `slh_verify` | never panic; never accept a forged signature |
| `verify` (SLH-DSA-SHA2-128f) | same, other hash family (§11.1 vs §11.2) | as above |
| ACVP vector parser | `runVectors` (`tests/kat_main.zig`), the real vector walker | never panic on malformed input |
| `hexDecode` | leaf parser for every hex ACVP field | never panic on arbitrary bytes |

One `verify` target per hash family so both hash dispatchers are exercised. A
random public key + signature must yield `error.InvalidSignature`: an accept
would mean the scheme took a forgery, which is unreachable without inverting
SHAKE/SHA-2, so a fuzzer reaching it signals a real logic flaw.

## Running

```sh
zig build fuzz                 # smoke: each target once with empty input
zig build fuzz --fuzz=1000000  # coverage-guided, up to N iterations

# One harness at a time — what CI runs, and what the 24h gate counts.
zig build fuzz-verify-shake-128f --fuzz=1000000
```

Per-target steps: `fuzz-verify-shake-128f`, `fuzz-verify-sha2-128f`,
`fuzz-verify-prehash-shake-128f`, `fuzz-verify-prehash-sha2-128f`,
`fuzz-acvp-parser`, `fuzz-hex-decode`.

`--fuzz` bounds by iteration count; wrap with `timeout` to bound wall-clock.
Corpus is persisted under `.zig-cache/f/` (one directory per target, named
`hex(Wyhash(0, test_name))`), coverage maps under `.zig-cache/v/`; both
accumulate across runs when the cache is preserved.

Coverage feedback requires the **LLVM backend**: `-ffuzz` instrumentation is not
implemented by Zig 0.16's self-hosted x86_64 backend, which is the default for
Debug builds on that target. `build.zig` therefore sets `use_llvm = true` on the
fuzz artifact. Do not remove it — see the gotcha below.

## The vendored test runner

`test_runner.zig` is a copy of Zig 0.16.0's stock test runner with a one-spot
patch. **Stock Zig 0.16.0 fails to *compile* any test binary in fuzz mode**:
its crash-reporting path passes the `*std.builtin.StackTrace` from
`@errorReturnTrace()` to `std.debug.writeStackTrace`, which now takes a
`*const std.debug.StackTrace` — two types that were split in 0.16.0 without the
runner being updated. A custom test runner
(`addTest(.{ .test_runner = ... })`) is the supported escape hatch. See the
file header for provenance (source hash) and the exact patch.

When upstream fixes this, delete `test_runner.zig` and drop the `.test_runner`
wiring in `build.zig`; the harnesses use only the public `std.testing.fuzz`
API and need no other change.

## The cumulative-hours gate

GitHub Actions caps a single job at 6h, so "≥24h in CI" cannot be one run.
`.github/workflows/fuzz.yml` runs nightly for a bounded window, persists the
corpus + coverage + a fuzz-hours counter via `actions/cache`, and reports the
cumulative total in the job summary. A component graduates once it clears 24h,
and **the counting is per target** — one matrix job per harness, its own cache,
its own counter. The `fuzz gate` job collects the six rows into one table.

The per-target split is not bookkeeping taste; a single shared counter cannot
mean what the bar says (issue #65):

- **Nothing is shared between targets.** `corpus`, `seen_pcs` and `bests` are
  per-test in `Fuzzer.init`, and each target's corpus lives in its own
  directory. Time spent fuzzing `hexDecode` buys `verify` nothing, so one
  number cannot stand in for either.
- **Within one binary the window is divided, not replicated.** `fuzzer.zig`
  runs every fuzz test from a single-threaded loop, choosing the next by an
  adaptive weighting (a quarter on instrumented-PC count, three quarters on how
  recently that test found something, with a boost for tests that just did). So
  six harnesses in one binary each get a fraction of the wall clock — and a
  global counter reports the full window to all six. Adding a harness quietly
  takes time away from the ones already there.

Running one harness per job removes both problems: `fuzzer.zig` special-cases
`n_tests == 1` with no swapping, so the job's wall-clock *is* that target's
fuzz time. `zig build fuzz-<slug>` is the per-target entry point; plain
`zig build fuzz` still runs all six in one binary, which is right for a smoke
test and wrong for the gate.

Because the corpus directory is derived from the test name, a filtered binary
reads and writes exactly the directory the aggregate binary used — splitting
the jobs does not orphan an accrued corpus.

**Two gotchas for anyone editing the workflow.** Both are failures that keep the
job green, so both need an out-of-band assert rather than a comment.

1. `zig build fuzz --fuzz=N` exits `0` even when it finds a crash — it writes the
   reproducer to `.zig-cache/f/crash` and logs it, but the return code is
   success. Crash detection must be out-of-band (check for the marker), which is
   why the workflow deletes any restored marker before the run and fails the job
   if one reappears.

2. An **uninstrumented** build fuzzes blind and says nothing. `fuzzer.zig` reads
   the coverage counters through *weak* externs (`__start___sancov_cntrs`), so
   when the backend emits no SanitizerCoverage section the symbols resolve to
   zero and the counter slice is simply empty — no link error, no warning. With
   no PCs, no input is ever novel, so the corpus never grows and the run is
   uniform-random rather than coverage-guided. The nightly job did exactly this
   for its entire life before issue #68: 24h on the counter, `pcs_len = 0`,
   `unique_runs = 0`, and every corpus directory empty. The workflow now reads
   `pcs_len` out of the coverage-map header (`std.Build.abi.SeenPcsHeader`:
   three native-endian `usize`s — `n_runs`, `unique_runs`, `pcs_len`) after each
   run and fails the job if it is zero.
