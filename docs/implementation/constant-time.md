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
    [declassification](#declassification-teaching-the-tool-what-is-public).

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
zig build ctgrind                            # build + run (taint inert without Valgrind)
valgrind zig-out/bin/slh-dsa-ctgrind         # components
valgrind zig-out/bin/slh-dsa-ctgrind-sign    # whole keygen + sign
```

### What is covered

Two harnesses, both run for **both hash families** on the 128f sets.

**`tests/ctgrind/taint_components.zig`** taints `SK.seed` and drives the primitives
that consume it:

- **`wots_pkGen`** — `PRF` per chain origin, full-length WOTS+ chaining, `T_len`
  compression.
- **`fors_node`** — `PRF` plus `F` over a leaf secret, then `H` up a whole tree.

These are the right components because their loop bounds are *fixed or public*:
WOTS+ chains always run exactly `w-1` steps during `pkGen`, and FORS tree heights
and indices are public geometry. There is no secret-derived loop bound, so a clean
run means exactly one thing — **the primitives are constant-time in the secret
value.** No interpretation required, and no declassification needed.

**`tests/ctgrind/taint_sign.zig`** taints `SK.seed` *and* `SK.prf` and runs a
complete key generation (§9.1) and signature (§9.2) — FORS signing, all `d = 22`
XMSS layers, the hash-family dispatch, and the index arithmetic joining them. A
clean run means no branch and no memory address anywhere in keygen or sign depends
on the secret key's value.

Both are kept. The component pass needs no declassification to be meaningful, so
when something regresses it says *which primitive* broke; the whole-path pass
covers what their composition adds.

### Declassification: teaching the tool what is public

The whole-path audit only works once Valgrind is told which SK-derived values are
public — otherwise it reports thousands of secret-dependent branches at `chain`
on code that is perfectly constant-time. The reasoning is the [warning
above](#what-is-actually-secret) made concrete:

1. `PK_FORS` and each XMSS root descend from `SK.seed`, so taint propagation marks
   them undefined.
2. Each is the *message* the next WOTS+ signs, and its base-`w` digits set that
   layer's chain lengths.
3. So a tainted value gates a loop bound, and memcheck dutifully reports it.

The code is right and the tool is right; they disagree only about
**classification**. `src/ct.zig` supplies the missing half:

```zig
pub const audit_enabled: bool = builtin.valgrind_support;

pub inline fn declassify(bytes: []const u8) void {
    if (!audit_enabled) return;
    std.valgrind.memcheck.makeMemDefined(bytes);
}
```

It is called at exactly three points, each one a place where FIPS 205 itself makes
the value public:

| Value | Site | Why it is public |
|---|---|---|
| `R` | `signCore`, after `PRF_msg` | Published verbatim as the first `n` signature bytes (§9.2) |
| `PK_FORS` | `signCore`, after `fors_pkFromSig` | Exactly what the verifier recomputes (§9.3) |
| Each XMSS root | `ht_sign`, after each `xmss_pkFromSig` | `ht_verify` reconstructs it from the signature (§7.2) |

Three properties make this safe to have in production code:

-   **Zero-cost by default.** `audit_enabled` is comptime-known and false in
    ordinary builds, so the call vanishes — no branch, no code. When it *is*
    enabled the emitted sequence is Valgrind's no-op client request, which changes
    memcheck's shadow state only, never program values or timing on real hardware.
-   **Minimal by construction.** Only these three. Declassifying, say, the whole
    FORS signature would also silence the false positives — and would silently
    blind the audit to a genuine leak through those bytes. Over-declassification
    costs nothing at runtime and everything in coverage, which makes it the
    failure mode to guard against.
-   **Justified at the call site.** Each one cites the algorithm that publishes
    the value, so the classification can be checked rather than trusted.

!!! note "Why this failure mode is the safe one"

    Inert *taint* markers would make the gate pass while checking nothing — the
    vacuity trap, which the negative control exists to catch. Inert
    *declassification* does the opposite: it makes the gate **fail**, loudly, at
    `chain`. Only the first is dangerous. A comptime assertion in the harness
    additionally pins that the library and the harness resolve Valgrind support
    identically, which in Zig 0.16 they always do — it is set per compilation, not
    per module.

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

The gate covers key generation and signing. Three limits are worth stating plainly:

-   **Verify is not audited, by construction.** It takes no secret input — the
    signature, the reconstructed root, and `PK.root` are all public — which is why
    `ht_verify` ends in a plain `std.mem.eql` rather than a constant-time compare.
    Auditing it would verify a property it does not need to have.
-   **One microarchitecture level.** The workflow pins `x86-64-v3`, because the
    packaged Valgrind cannot decode AVX-512 and SIGILLs on it. The AVX-512 code
    paths are therefore unaudited. Tracked as
    [issue #6](https://github.com/nandanito/slh-dsa-zig/issues/6).
-   **x86_64 only.** `-fvalgrind` does not compile for aarch64, so there is no ARM
    leg — and none on the maintainer's macOS/Apple-Silicon machine, which is why
    CI is the only place this check runs at all.

And the standing caveat that no tool removes: memcheck proves the absence of
secret-dependent *branches and memory addresses*. It says nothing about
data-dependent instruction timing in the underlying hardware, or about physical
side channels. See [SECURITY.md][security] for what is out of scope.

[security]: https://github.com/nandanito/slh-dsa-zig/blob/main/SECURITY.md

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
