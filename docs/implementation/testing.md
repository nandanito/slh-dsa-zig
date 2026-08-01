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
| sigGen | 624 / 624 | 0 | 0 |
| sigVer | 504 / 504 | 0 | 0 |

Nothing is skipped. The sigGen and sigVer counts grew by 288 and 168 when the
[pre-hash interface](../concepts/assembly.md#the-pre-hash-interface) landed and
the `preHash` groups stopped being skipped.

Those groups are worth their weight. FIPS 205 writes out the OIDs for only four
of the twelve approved pre-hash functions, leaving the rest to the NIST CSOR
registry — so for eight of them these vectors are the only end-to-end check that
the right OID went into `M'`. A wrong byte there produces a wrong signature and
fails loudly.

The runner dispatches **all three interfaces**:

```zig
if (v.pre_hash) |ph| {
    S.signPreHash(&sig, v.msg, v.ctx orelse "", ph, sk, opt_rand)
} else switch (v.interface) {
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

Six `std.testing.fuzz` targets:

| Target | Property |
|---|---|
| `verify` (SHAKE-128f) | Never panic; never accept a forged signature |
| `verify` (SHA2-128f) | Same, exercising the other hash dispatcher |
| `verifyPreHash` (SHAKE-128f) | Same oracle for HashSLH-DSA, with the pre-hash function drawn from fuzzer bytes so all twelve `M'` layouts are reachable |
| `verifyPreHash` (SHA2-128f) | Same, other hash family |
| ACVP vector parser | Never panic on malformed JSON |
| `hexDecode` | Never panic on arbitrary bytes |

The `verify` oracle is strong: a random public key and signature must yield
`error.InvalidSignature`. An *accept* would mean the scheme took a forgery, which
is unreachable without inverting SHAKE or SHA-2 — so a fuzzer reaching it signals a
real logic flaw, not luck.

```sh
zig build fuzz                  # smoke: each target once
zig build fuzz --fuzz=1000000   # coverage-guided, all six in one binary

# One harness at a time — what CI runs, and what the gate counts.
zig build fuzz-verify-shake-128f --fuzz=1000000
```

!!! warning "Three Zig 0.16 fuzzer problems worth knowing"

    **The stock test runner cannot compile fuzz tests** in Zig 0.16.0 (a
    `StackTrace` type split). This library vendors a patched runner at
    `tests/fuzz/test_runner.zig`. Without it, `--fuzz` does not build at all.

    **`--fuzz=N` exits 0 even when it finds a crash.** The exit code cannot be
    trusted, so the nightly workflow detects crashes **out of band** by inspecting
    the corpus directory rather than checking the return value. A CI job that
    naively gated on exit status would report green through every crash it found.

    **An uninstrumented build fuzzes blind and reports nothing.** `-ffuzz`
    coverage instrumentation is emitted only by the LLVM backend, and Zig 0.16
    defaults to the self-hosted x86_64 backend for Debug builds. The fuzzer picks
    up its counters through *weak* externs, so the missing section resolves to
    zero rather than failing to link: no PCs, no input ever novel, an empty
    corpus, and no diagnostic. This library's nightly job did exactly that for its
    entire first life — 24 hours on the clock with a completely empty corpus —
    until [issue #68](https://github.com/nandanito/slh-dsa-zig/issues/68). The
    build pins `use_llvm`, and CI now reads the instrumented-PC count out of the
    coverage map after every run and fails the job if it is zero.

The 6-hour GitHub Actions job cap makes a single ≥24h run impossible, so the gate
is **cumulative**: a nightly workflow fuzzes a bounded window, persists the corpus
and coverage via `actions/cache`, and accrues fuzz-hours toward the 24h threshold.
Only crash-*free* runs count toward it — a run that finds a crash must not advance
a crash-free counter.

The accrual is counted **per target**, one matrix job per harness, each with its
own cache and counter
([issue #65](https://github.com/nandanito/slh-dsa-zig/issues/65)). A single shared
counter cannot mean what the bar says, for two independent reasons. Nothing is
shared between targets — corpus and coverage state are per-test, so time spent on
one buys another nothing. And the fuzzer runs every test in a binary from one
single-threaded loop, choosing the next by an adaptive weighting, so a window is
*divided* among the harnesses rather than replicated: a global counter would
report the full window to all six at once, and adding a harness would quietly take
time from the ones already there. Running one harness per job removes both
problems, since the job's wall-clock is then exactly that target's fuzz time.

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

The gate is measured **portable against portable** — both sides built without
hardware hash acceleration, on x86-64 at `-Dcpu=x86_64_v3`. On that basis
**35 of 36 measurements pass**, with one exceedance:

| family | portable ratio | over 2× |
|---|---|---|
| SHAKE | 0.87×–0.98× (mean 0.96×) | 0 / 18 |
| SHA-2 | 1.73×–2.06× (mean 1.85×) | 1 / 18 — `SHA2-256s keygen` at 2.06× |

That the gate is measured this way is itself the interesting decision. Building
Zig *with* SHA-NI makes all 36 pass at 0.33×–1.00× — Zig comes out two to three
times faster than PQClean `clean`. But that number compares a hardware hash unit
against portable C, and a gate you can pass with a CPU feature is a gate that
**cannot fail for the right reason**: the SLH-DSA machinery around the hash could
regress badly and the speedup would hide it. The accelerated numbers are
published because they are what users get; they are not the gate.

!!! tip "SHAKE is the control"

    The two families run the **same structural code**: `wots.zig`, `xmss.zig`,
    `hypertree.zig` and `fors.zig` are generic over `hash.zig`'s `Hash(p)`, which
    dispatches to one of two adapters in a single `switch`. Nothing above the
    adapter branches on hash family. SHAKE landing at 0.96× is therefore direct
    evidence that this library's SLH-DSA code is at parity with PQClean's, and
    that the SHA-2 gap belongs to the **hash-adapter layer** — `std.crypto`'s
    SHA-2 implementations.

    That is a stronger claim than "36/36 passes", and it is why the one 2.06× is
    recorded as a known, attributed exceedance rather than hidden behind an
    accelerated build.

!!! warning "The adapters differ by more than the primitive"

    A tempting shorthand — "the families differ only in the hash primitive" — is
    wrong, and worth not repeating. The §11.1 and §11.2 adapters differ on three
    axes: §11.1 hashes the expanded 32-byte address while §11.2 hashes the
    22-byte compressed `ADRSc`; §11.2's `H_msg` adds an MGF1 layer that §11.1
    has no equivalent of; and within §11.2 the primitive itself changes with
    security level — `H`, `T_l` and `H_msg` are SHA-256 at `n = 16` but
    **SHA-512** at `n = 24, 32`, with `PRF_msg` splitting the same way. Only `F`
    and `PRF` are SHA-256 throughout.

    That last axis lands on the one failing measurement: `SLH-DSA-SHA2-256s` is
    `n = 32`, so its keygen drives `F` (SHA-256) *and* `H` (SHA-512). The
    exceedance is `std.crypto`'s SHA-2 family, not SHA-256 specifically.

    The conclusion survives — §11.2 feeds *less* data per hash call and is still
    slower, and MGF1 runs once per operation against millions of `F`/`H` calls —
    but the claim has to be made at adapter granularity to be true.

One further detail: Zig's SHA-2 dispatch is a **comptime** check on target
features, not a runtime probe — `std/crypto/sha2.zig` takes its x86-64 SHA-NI
path only when the target has both `sha` and `avx2`. A binary built for a
baseline target will not opportunistically use SHA-NI on a CPU that has it.

The lesson generalises: a performance gate that does not name the target's
feature set is only half-specified, and the half that is missing is the half
that decides the answer. The original wording said "equivalent hardware", which
was unfalsifiable; it now names a target.

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
| `fuzz.yml` | A per-PR smoke build, and the nightly cumulative fuzzing run — one matrix job per target, plus a `fuzz gate` job that collects the per-target hours into one table |

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
