//! Fuzz harnesses for slh-dsa-zig — Lane A test infrastructure.
//!
//! Run:
//!   zig build fuzz              — quick smoke (each target once, empty input)
//!   zig build fuzz --fuzz=N     — coverage-guided fuzzing, up to N iterations
//!
//! These targets use only the public `std.testing.fuzz` API. They compile
//! against a vendored, patched test runner (tests/fuzz/test_runner.zig)
//! because stock Zig 0.16.0 fails to *build* any fuzz test — see that file's
//! header and issue #9.
//!
//! Attacker model. Effort goes where the input is adversarial by
//! construction: `verify` (signatures are attacker-supplied) and the ACVP
//! vector parser (external JSON). Fuzzing keygen/sign has little value —
//! their inputs are secret/local, not attacker-controlled.
//!
//! Targets:
//!   - verify (SLH-DSA-SHAKE-128f, SLH-DSA-SHA2-128f): feed arbitrary bytes
//!     as (public key, signature, message) to `Slh_Dsa.verify`. Properties:
//!     never panic; never accept (FIPS 205 §9.3/§10.3 slh_verify). One target
//!     per hash family so both hash dispatchers (§11.1 SHAKE, §11.2 SHA-2)
//!     are exercised.
//!   - verifyPreHash (same two parameter sets): the same oracle for the
//!     HashSLH-DSA verifier (§10.3 Algorithm 25), with the pre-hash function
//!     and context string also drawn from fuzzer bytes so all twelve `M'`
//!     layouts are reachable.
//!   - ACVP vector parser + hexDecode: feed arbitrary bytes to the real
//!     `runVectors` walker (tests/kat_main.zig) and the `hexDecode` leaf
//!     parser. Property: never panic on malformed input — a controlled error
//!     is the correct outcome.

const std = @import("std");
const slh_dsa = @import("slh_dsa");
const kat = @import("kat"); // tests/kat_main.zig; parser primitives at kat.runner

const Smith = std.testing.Smith;

// ---------------------------------------------------------------------------
// verify — FIPS 205 §9.3 / §10.3 slh_verify.
// ---------------------------------------------------------------------------

/// Property: a public key + signature + message drawn from fuzzer bytes must
/// never verify, and `verify` must never panic while deciding that.
///
/// `error.InvalidSignature` is the only acceptable outcome:
///   - an *accept* (`verify` returns void) would mean the scheme accepted a
///     forgery — catastrophic, and unreachable without inverting SHAKE/SHA-2,
///     so if a fuzzer ever gets there it is a real logic flaw, not luck;
///   - any other error, or a safety panic inside the WOTS+/FORS/hypertree
///     reconstruction (base_2b index decode, chain bounds, address
///     arithmetic), is likewise a bug this oracle turns into a failure.
fn fuzzVerify(comptime param_set: slh_dsa.ParamSet, smith: *Smith) anyerror!void {
    const Scheme = slh_dsa.Slh_Dsa(param_set);

    var pk: Scheme.PublicKey = undefined;
    var sig: Scheme.Signature = undefined;
    var msg_buf: [256]u8 = undefined;

    smith.bytes(&pk);
    smith.bytes(&sig);
    const msg_len = smith.slice(&msg_buf);
    const msg = msg_buf[0..msg_len];

    try std.testing.expectError(error.InvalidSignature, Scheme.verify(&sig, msg, &pk));
}

fn verifyShake128f(_: void, smith: *Smith) anyerror!void {
    return fuzzVerify(.slh_dsa_shake_128f, smith);
}

fn verifySha2128f(_: void, smith: *Smith) anyerror!void {
    return fuzzVerify(.slh_dsa_sha2_128f, smith);
}

test "fuzz: verify rejects arbitrary bytes (SLH-DSA-SHAKE-128f)" {
    try std.testing.fuzz({}, verifyShake128f, .{});
}

test "fuzz: verify rejects arbitrary bytes (SLH-DSA-SHA2-128f)" {
    try std.testing.fuzz({}, verifySha2128f, .{});
}

/// Same oracle for the pre-hash verifier (FIPS 205 §10.3 Algorithm 25), which
/// is equally attacker-facing: the signature, message, and context all arrive
/// from outside.
///
/// The pre-hash function is drawn from the fuzzer's bytes too, so every one of
/// the twelve `M'` layouts — three digest lengths across two hash families plus
/// the XOFs — is reachable. `ctx` is capped at 255 bytes so that
/// `error.ContextTooLong` cannot mask a missing rejection: `InvalidSignature`
/// stays the single acceptable outcome.
fn fuzzVerifyPreHash(comptime param_set: slh_dsa.ParamSet, smith: *Smith) anyerror!void {
    const Scheme = slh_dsa.Slh_Dsa(param_set);
    const all = comptime std.enums.values(slh_dsa.PreHash);

    var pk: Scheme.PublicKey = undefined;
    var sig: Scheme.Signature = undefined;
    var selector: [1]u8 = undefined;
    var msg_buf: [256]u8 = undefined;
    var ctx_buf: [255]u8 = undefined;

    smith.bytes(&pk);
    smith.bytes(&sig);
    smith.bytes(&selector);
    const msg_len = smith.slice(&msg_buf);
    const ctx_len = smith.slice(&ctx_buf);

    const ph = all[selector[0] % all.len];

    try std.testing.expectError(error.InvalidSignature, Scheme.verifyPreHash(
        &sig,
        msg_buf[0..msg_len],
        ctx_buf[0..ctx_len],
        ph,
        &pk,
    ));
}

fn verifyPreHashShake128f(_: void, smith: *Smith) anyerror!void {
    return fuzzVerifyPreHash(.slh_dsa_shake_128f, smith);
}

fn verifyPreHashSha2128f(_: void, smith: *Smith) anyerror!void {
    return fuzzVerifyPreHash(.slh_dsa_sha2_128f, smith);
}

test "fuzz: verifyPreHash rejects arbitrary bytes (SLH-DSA-SHAKE-128f)" {
    try std.testing.fuzz({}, verifyPreHashShake128f, .{});
}

test "fuzz: verifyPreHash rejects arbitrary bytes (SLH-DSA-SHA2-128f)" {
    try std.testing.fuzz({}, verifyPreHashSha2128f, .{});
}

// ---------------------------------------------------------------------------
// ACVP vector parser — tests/kat_main.zig `runVectors`.
// ---------------------------------------------------------------------------

/// Property: parsing arbitrary bytes as an ACVP vector file must never panic.
/// A malformed file must surface as a controlled error, never a crash.
///
/// This drives the *real* walker (`kat.runVectors`, the one the KAT CLI uses)
/// for each mode, so adversarial shapes — wrong `testGroups`/`tcId`/
/// `testPassed` types, missing fields, bad hex — flow through the exact typed
/// accessors and per-mode dispatch that run on NIST vector files. The per-mode
/// runners length-check key/sig material before any crypto, and fuzzer bytes
/// cannot synthesize correctly-sized hex, so this stays parser-bound (the
/// crypto is covered by the `verify` targets and the KATs).
fn fuzzKatVectors(_: void, smith: *Smith) anyerror!void {
    var buf: [4096]u8 = undefined;
    const n = smith.slice(&buf);
    const bytes = buf[0..n];

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var parsed = std.json.parseFromSlice(std.json.Value, alloc, bytes, .{}) catch return;
    defer parsed.deinit();

    const modes = [_]kat.runner.VectorType{ .key_gen, .sig_gen, .sig_ver };
    for (modes) |mode| {
        _ = kat.runVectors(alloc, parsed.value, mode, null) catch {};
    }
}

test "fuzz: ACVP vector parser tolerates arbitrary bytes" {
    try std.testing.fuzz({}, fuzzKatVectors, .{});
}

// ---------------------------------------------------------------------------
// hexDecode — the leaf parser every hex ACVP field flows through.
// ---------------------------------------------------------------------------

/// `walkJson` only reaches `hexDecode` via JSON strings, which are UTF-8
/// validated by the parser. This target feeds it truly arbitrary bytes so odd
/// lengths and non-hex bytes are covered directly. Property: never panic.
fn fuzzHexDecode(_: void, smith: *Smith) anyerror!void {
    var buf: [512]u8 = undefined;
    const n = smith.slice(&buf);
    const s = buf[0..n];

    if (kat.runner.hexDecode(std.testing.allocator, s)) |decoded| {
        std.testing.allocator.free(decoded);
    } else |_| {}
}

test "fuzz: hexDecode tolerates arbitrary bytes" {
    try std.testing.fuzz({}, fuzzHexDecode, .{});
}
