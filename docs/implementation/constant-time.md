# Constant-time discipline

A cryptographic implementation must not let its **timing** depend on secret data.
If it does, an attacker who can measure execution — locally, over a network, or
from a neighbouring VM — recovers key material without breaking any mathematics.

The concrete prohibitions:

- No **branch** whose condition depends on a secret.
- No **memory access** at an address derived from a secret.
- No **early return** on secret data.
- No **table lookup** indexed by secret bits.

## What is actually secret

This is the question that matters most, and getting it wrong in either direction
is expensive. Over-classify and you write slow, contorted code defending public
values. Under-classify and you leak.

In SLH-DSA:

| Value | Secret? | Why |
|---|---|---|
| `SK.seed` | **Yes** | Derives every WOTS+ and FORS secret in the structure |
| `SK.prf` | **Yes** | Keys the message randomiser |
| PRF-derived leaf/chain secrets | **Yes** | Direct key material |
| `PK.seed`, `PK.root` | No | Literally the public key |
| `R` (the randomiser) | No | Transmitted in the signature |
| `md`, `idx_tree`, `idx_leaf` | **No** | Recoverable from the signature by anyone |
| `ADRS` contents | No | Public tree geometry |
| WOTS+ digit values | **No** | Derived from public values; recoverable from the signature |

The last three rows are the interesting ones. They are **derived from the secret
key** but are **not themselves secret** — a verifier recomputes them from public
data. So branching on them is legitimate, and the code does it freely: `chain`'s
loop bound is a WOTS+ digit; FORS's loops are indexed by digest fields.

!!! warning "\"Derived from the secret key\" ≠ \"secret\""

    This distinction is the single most important idea on this page. Nearly every
    intermediate in SLH-DSA descends from `SK.seed`. If that made a value secret,
    the scheme would be unimplementable in constant time — every tree index would
    be untouchable.

    What matters is whether the value is **published**. `idx_leaf` descends from
    `SK.prf` through `PRF_msg`, but it is recomputable from `R` and the message,
    both of which the attacker has. Treating it as secret buys nothing and costs a
    great deal.

    This is also, precisely, why the whole-signing audit is hard — see
    [below](#what-is-still-open).

## Verification, not assertion

A comment saying "this is constant-time" is a claim. The project's discipline is
to **verify empirically**, which is what the ctgrind harness does.

### How ctgrind works

The technique (Adam Langley's `ctgrind`) repurposes Valgrind's memcheck. Memcheck
already reports any branch or memory access that depends on **undefined** memory.
So: mark the secret as undefined, run the code, and any report is a
secret-dependent operation.

This library issues the taint markers through `std.valgrind` — inline assembly
client requests in pure Zig, with no C shim and no `<valgrind/memcheck.h>`:

```zig
var sk_seed: [n]u8 = undefined;
try io.randomSecure(&sk_seed);
std.valgrind.memcheck.makeMemUndefined(&sk_seed);   // ← now tracked

Wots.pkGen(&sk_seed, &pk_seed, &adrs, &out_pk);

std.valgrind.memcheck.makeMemDefined(&out_pk);      // public output: declassify
std.mem.doNotOptimizeAway(out_pk[0]);
```

Secrets come from the **OS RNG**, not constants, so the optimiser cannot fold the
secret away and make the test vacuous.

```sh
zig build ctgrind                        # build + run (taint inert without Valgrind)
valgrind zig-out/bin/slh-dsa-ctgrind     # the real check
```

### What is covered

`tests/ctgrind/taint_components.zig` taints `SK.seed` and drives the primitives
that consume it, for **both hash families**:

- **`wots_pkGen`** — `PRF` per chain origin, full-length WOTS+ chaining, `T_len`
  compression.
- **`fors_node`** — `PRF` plus `F` over a leaf secret, then `H` up a whole tree.

These are the right components because their loop bounds are *fixed or public*:
WOTS+ chains always run exactly `w-1` steps during `pkGen`, and FORS tree heights
and indices are public geometry. There is no secret-derived loop bound, so a clean
run means exactly one thing — **the primitives are constant-time in the secret
value.** No interpretation required.

### The non-vacuity problem

A taint-based test has a nasty failure mode: if the markers compile to no-ops, the
harness taints nothing, the run is clean, and the gate passes **vacuously**. It
looks green and checks nothing.

That is not hypothetical here. `std.valgrind` client requests only emit when the
module is built with Valgrind support, which `build.zig` gates on the target. A
release build, or the wrong target, silently disables the whole check.

So there is a **negative control**, `tests/ctgrind/negative_control.zig`, that
deliberately leaks:

```zig
var secret: [1]u8 = undefined;
try init.io.randomSecure(&secret);              // DEFINED — memcheck ignores it
std.valgrind.memcheck.makeMemUndefined(&secret); // the exact marker under test
// … then branch on it …
```

Valgrind **must** report this. CI runs it expecting failure, and treats a *clean*
run as a broken gate:

```sh
if valgrind --error-exitcode=1 "$negctl"; then
    echo "negative control did NOT leak — taint machinery is inert"
    exit 1
fi
```

!!! tip "Every taint-based gate needs this"

    A negative control converts "the check passed" into "the check ran and
    passed" — which are entirely different statements. This one caught a real
    instance of the vacuity trap during development, where a release-mode build
    silently no-oped the taint.

    It matters doubly here because Valgrind does not run on the maintainer's
    macOS/Apple-Silicon machine. CI is the *only* place this check executes, so
    there is no local run that would notice it had gone inert.

## What is still open

The **whole-signing** audit — tainting `SK.seed` and running a complete `sign` —
currently reports false positives, and understanding why is genuinely instructive.

Inside `ht_sign`, the message handed to WOTS+ is a FORS public key or an XMSS root.
Those values are **public** — they end up recoverable from the signature — but they
are computed *from* `SK.seed`, so Valgrind's taint propagation marks them
undefined. Their base-`w` digits then set WOTS+ chain lengths, which means a tainted
value gates a loop bound, which memcheck dutifully reports.

The code is correct. The tool is right that a tainted value reached a branch. The
disagreement is over classification: the value is public, but nothing has told
Valgrind so.

Fixing it needs **in-library declassify hooks** — `makeMemDefined` calls at the
points where a secret-derived value becomes public — which means either
conditional instrumentation inside `src/` or a test-only seam. That is a real
design decision affecting production code paths, so it is deliberately deferred and
documented rather than rushed. Tracked as
[issue #34](https://github.com/nandanito/slh-dsa-zig/issues/34).

Until then the honest claim is narrow and precise: **the secret-processing
primitives are verified constant-time; the composed signing path is not yet
verified end-to-end.**

## In-code conventions

Constant-time reasoning is recorded next to the code it applies to, so a reader can
check it without reconstructing the argument:

```zig
// Constant-time: yes — the loop bound `s` is derived from a message
// digest (public after signing); the secret key X is not used to
// index any table or gate any branch.
```

And unresolved concerns are flagged inline rather than left implicit:

```zig
// CT-CONCERN: this branch depends on a secret bit. Needs refactor before merge.
// ALLOC: heap allocation here — justify or move to stack.
// TODO(zeroize): secret material needs explicit scrubbing before return.
```

## Zeroization

Secrets are scrubbed at scope exit with `std.crypto.secureZero`, which has volatile
semantics so the compiler cannot eliminate it as a dead store:

```zig
var sk: [n]u8 = undefined;
defer std.crypto.secureZero(u8, &sk);
```

The discipline is to be **precise about what is secret**, not maximal:

```zig
var sk: [n]u8 = undefined;
defer std.crypto.secureZero(u8, &sk);   // PRF output — secret
var tmp: [len * n]u8 = undefined;        // chain endpoints — this IS the public key
```

Scrubbing `tmp` would be pure cost. Keeping the distinction sharp is what stops
zeroization from becoming ritual — and makes the `defer` lines meaningful signposts
for where secrets actually live.

Note also that `KeyPair.generate` scrubs its **local** seed copies but not the
returned keypair: the caller owns that, and it holds the secret key by design.

## The hash layer

Both backends are constant-time by construction, for reasons specific to each:

- **Keccak-f** (SHAKE) has no data-dependent branches or memory accesses at all.
- **SHA-256/SHA-512/HMAC** compression functions likewise — notably no S-box
  tables, which is the usual source of timing leaks in block-cipher-based
  primitives.

Since the hash layer is where all secret material ultimately flows, this is the
foundation the rest of the argument rests on.
