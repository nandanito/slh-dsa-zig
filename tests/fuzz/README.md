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
```

`--fuzz` bounds by iteration count; wrap with `timeout` to bound wall-clock.
Corpus is persisted under `.zig-cache/f/`, coverage maps under `.zig-cache/v/`;
both accumulate across runs when the cache is preserved.

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
cumulative total in the job summary. A component graduates once it clears 24h.

**Gotcha for anyone editing the workflow:** `zig build fuzz --fuzz=N` exits `0`
even when it finds a crash — it writes the reproducer to `.zig-cache/f/crash`
and logs it, but the return code is success. Crash detection must be
out-of-band (check for the marker), which is why the workflow deletes any
restored marker before the run and fails the job if one reappears.
