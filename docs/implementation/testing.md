# How this is tested

Four independent regimes, each catching a class the others miss. That
independence is the point: a bug has to evade all four.

| Regime | Catches | Where |
|---|---|---|
| **ACVP KATs** | Wrong output — spec mismatch | `tests/kat_runner.zig` |
| **Property tests** | Broken internal invariants | `test` blocks in each `src/` module |
| **Fuzzing** | Panics and crashes on hostile input | `tests/fuzz/` |
| **ctgrind** | Secret-dependent timing | `tests/ctgrind/` |

## Known-answer tests (ACVP)

**The primary correctness gate.** Nothing in this library is called functional
until NIST's Automated Cryptographic Validation Protocol vectors pass.

Property tests only prove self-consistency: an implementation with a wrong `ADRS`
encoding or a missing checksum shift signs and verifies its own signatures
perfectly. Only vectors from an independent source catch that class, and in
hash-based signatures that class is where the dangerous bugs live — see
[the ADRS trap](../components/adrs.md#the-22-versus-32-byte-trap).

Three modes, all wired:

```sh
zig build kat -- --mode keygen --vectors tests/vectors/keygen.json
zig build kat -- --mode siggen --vectors tests/vectors/siggen.json
zig build kat -- --mode sigver --vectors tests/vectors/sigver.json
```

Current results on all twelve parameter sets:

| Mode | Passed | Failed | Skipped |
|---|---|---|---|
| keyGen | 120 / 120 | 0 | 0 |
| sigGen | 336 / 336 | 0 | 288 |
| sigVer | 336 / 336 | 0 | 168 |

The skips are the **pre-hash (`preHash`) groups**, matching the
[recorded deferral of HashSLH-DSA](../concepts/assembly.md#context-strings). They
are skipped explicitly by an `Interface` enum that refuses to parse `"preHash"`,
so a pre-hash vector can never be silently counted as a pass.

The runner dispatches **both interfaces**:

```zig
switch (v.interface) {
    .internal => S.signInternal(&sig, v.msg, sk, opt_rand),
    .external => S.signWithContext(&sig, v.msg, v.ctx orelse "", sk, opt_rand),
}
```

so external-interface vectors with non-empty context strings are covered — the
specific failure that motivated
[issue #8](https://github.com/nandanito/slh-dsa-zig/issues/8).

!!! note "Vectors are not in the repository"

    `tests/vectors/` is gitignored apart from its README: `siggen.json` is 38 MB
    and `sigver.json` 30 MB. The README documents which NIST ACVP release to fetch
    and where to put it. CI downloads the pinned files.

## Property tests

Next to the code they test, at the end of each module — never in a separate
directory. Two kinds carry most of the weight.

**Structural properties derived from the spec.** For example, WOTS+ chain
composition:

```
chain(x, 0, a) then chain(·, a, b)  ==  chain(x, 0, a+b)
```

That is the invariant making signing and verifying meet in the middle. If it
breaks, nothing verifies — and the test names *why*, so a failure is diagnostic
rather than just red.

**Hand-computed base cases.** `xmss_node` and `fors_node` are recursive, so each is
checked at `z = 1` against a directly computed value:

```
xmss_node(i, 1)  ==  H( pkGen(2i), pkGen(2i+1) )
fors_node(i, 1)  ==  H( F(sk_2i),  F(sk_2i+1)  )
```

This validates the inductive step independently of the recursion. A recursion bug
that happens to be self-consistent still fails here.

**Negative tests, always.** Every round-trip test has a matching tamper test.
Round-trips confirm the happy path; only negatives confirm that verification
*rejects*. The domain-separation tests are the clearest example — a positive test
would pass even if the context prefix were dropped entirely, so the suite asserts
that a signature under one context does **not** verify under another.

Speed shapes coverage: expensive round-trips run on `f` variants at the 128-bit
level (`h' = 3`, so 8-leaf trees), while exhaustive coverage of the `s` sets comes
from the release-mode KAT runs.

## Fuzzing

Effort goes where input is **adversarial by construction**. Fuzzing `keygen` or
`sign` has little value — their inputs are local and secret, not attacker-supplied.
Fuzzing `verify` has a great deal, because that is what processes bytes from the
network.

Four `std.testing.fuzz` targets:

| Target | Property |
|---|---|
| `verify` (SHAKE-128f) | Never panic; never accept a forged signature |
| `verify` (SHA2-128f) | Same, exercising the other hash dispatcher |
| ACVP vector parser | Never panic on malformed JSON |
| `hexDecode` | Never panic on arbitrary bytes |

The `verify` oracle is strong: a random public key and signature must yield
`error.InvalidSignature`. An *accept* would mean the scheme took a forgery, which
is unreachable without inverting SHAKE or SHA-2 — so a fuzzer reaching it signals a
real logic flaw, not luck.

```sh
zig build fuzz                  # smoke: each target once
zig build fuzz --fuzz=1000000   # coverage-guided
```

!!! warning "Two Zig 0.16 fuzzer problems worth knowing"

    **The stock test runner cannot compile fuzz tests** in Zig 0.16.0 (a
    `StackTrace` type split). This library vendors a patched runner at
    `tests/fuzz/test_runner.zig`. Without it, `--fuzz` does not build at all.

    **`--fuzz=N` exits 0 even when it finds a crash.** The exit code cannot be
    trusted, so the nightly workflow detects crashes **out of band** by inspecting
    the corpus directory rather than checking the return value. A CI job that
    naively gated on exit status would report green through every crash it found.

The 6-hour GitHub Actions job cap makes a single ≥24h run impossible, so the gate
is **cumulative**: a nightly workflow fuzzes a bounded window, persists the corpus
and coverage via `actions/cache`, and accrues fuzz-hours toward the 24h threshold.
Only crash-*free* runs count toward it — a run that finds a crash must not advance
a crash-free counter.

## Constant-time verification

Covered in detail on [its own page](constant-time.md). In summary: Valgrind-based
taint tracking of `SK.seed` and `SK.prf` through the secret-processing primitives
*and* through a whole key generation + signature, both hash families, with a
negative control proving the gate is not vacuous.

The AVX-512 caveat: the workflow pins the target to `x86-64-v3` because the
packaged Valgrind cannot decode AVX-512 and SIGILLs on it. Tracked as
[issue #6](https://github.com/nandanito/slh-dsa-zig/issues/6), to be lifted when
Valgrind catches up.

## Benchmarks

```sh
zig build bench
zig build bench -- --param-set SLH-DSA-SHAKE-128s --op sign
zig build bench -Dbench-optimize=ReleaseSafe
zig build bench -- --csv                     # machine-readable, on stdout
```

The gate is **within 2× of PQClean's portable `clean` C reference**, deliberately
not its AVX2 variant: a pure-Zig core without its own vectorised Keccak cannot
match hand-written vector assembly, and gating on that would make the target
theatre. AVX2 numbers are reported for honesty and never gated.

### The measured result

The comparison is scripted in `bench/pqclean/` and the numbers are published in
[`bench/README.md`](https://github.com/nandanito/slh-dsa-zig/blob/main/bench/README.md):

```sh
./bench/pqclean/compare.sh > results.csv
./bench/pqclean/table.sh < results.csv       # exits non-zero if the gate fails
```

All 36 measurements pass, worst ratio 1.15×. But the two hash families pass for
different reasons, and that distinction is the interesting part:

| family | ratio range | why |
|---|---|---|
| SHAKE | 0.89×–1.15× | Genuine parity — portable Keccak on both sides |
| SHA-2 | 0.25×–0.56× | Zig takes an ARMv8 hardware SHA-256 path; PQClean `clean` is portable C |

Rebuild with the extensions off (`-Dcpu=apple_m3-sha2`) and the SHA-2 result
inverts to 1.82×–2.14× — Zig's *portable* SHA-256 is about half the speed of
PQClean's portable C. The gate passes as measured, on the target it was measured
on; it is not a claim that it passes everywhere. Re-measuring on x86-64 is
[issue #40](https://github.com/nandanito/slh-dsa-zig/issues/40).

The lesson generalises: a performance gate that does not name the target's
feature set is only half-specified, and the half that is missing is the half
that decides the answer.

### Three measurement details worth copying

**Interleave the implementations being compared.** `compare.sh` runs zig, then
PQClean, then moves to the next parameter set. Running one to completion and then
the other measures the second on a machine the first had already heated — on a
laptop that is larger than several of the ratios being reported.

**Iteration budgets are speed-class aware.** `s` sets sign 20–100× slower than `f`
sets, so a uniform iteration count either takes forever or produces noise. `s` sets
default to 5 signing iterations, `f` sets to 50, verify to 500 everywhere.

**Results are folded into a live value before the clock stops.** An early version
discarded `verify`'s return, which let the optimiser elide the work being measured
— a benchmark timing nothing. The loop now accumulates into `ok` and calls
`doNotOptimizeAway(ok)` *before* stopping the timer. This class of error is easy to
introduce and produces impressively fast, entirely meaningless numbers.

## CI

`.github/workflows/`:

| Workflow | Runs |
|---|---|
| `ci.yml` | `zig fmt --check`, build + test on x86_64 and ARM64 (Debug and ReleaseSafe), the ACVP KAT suite, and the Lane B trailer check |
| `ctgrind.yml` | The Valgrind constant-time check plus its negative control |
| `fuzz.yml` | A per-PR smoke build, and the nightly cumulative fuzzing run |

`main` is branch-protected: PRs required, force-push and deletion blocked, and the
above checks required to merge.

## Before claiming anything works

The project's rule, in order:

```sh
zig fmt .
zig build            # must succeed
zig build test       # must pass
```

Then re-check the cryptographic discipline table for anything touching `src/`, and
build `examples` and `bench` too if the build wiring changed. A change is not done
because it looks right — it is done when the commands above have actually been run.
