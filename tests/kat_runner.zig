//! KAT (Known-Answer Test) runner for SLH-DSA against NIST ACVP vectors.
//!
//! NIST publishes ACVP test vectors as JSON. For SLH-DSA there are three
//! vector files we care about:
//!
//!   - keyGen     : seeds in, expected (pk, sk) out.
//!   - sigGen     : (sk, message, opt_rand) in, expected signature out.
//!   - sigVer     : (pk, message, signature) in, expected accept/reject out.
//!
//! This module:
//!
//!   - Parses the ACVP JSON structure into Zig structs.
//!   - Dispatches each vector to the correct SLH-DSA parameter set.
//!   - Compares byte-for-byte against expected outputs.
//!   - Reports per-vector pass/fail with diagnostic context.
//!
//! Lane: this file is Lane A. It is test infrastructure, not crypto core,
//! and is intentionally not in the upstream-candidate tree.
//!
//! Status: keyGen, sigGen, and sigVer are fully wired, across all three
//! signature interfaces. sigGen drives the §9.2 internal signer
//! (`signInternal`), the §10.2.1 external signer (`signWithContext`,
//! context-string domain separation), and the §10.2.2 pre-hash signer
//! (`signPreHash`, HashSLH-DSA); sigVer drives their §9.3 / §10.3
//! counterparts. No group is skipped.

const std = @import("std");
const slh_dsa = @import("slh_dsa");

/// Top-level ACVP test groups we recognise.
pub const VectorType = enum {
    key_gen,
    sig_gen,
    sig_ver,

    pub fn fromString(s: []const u8) ?VectorType {
        if (std.mem.eql(u8, s, "keyGen")) return .key_gen;
        if (std.mem.eql(u8, s, "sigGen")) return .sig_gen;
        if (std.mem.eql(u8, s, "sigVer")) return .sig_ver;
        return null;
    }
};

/// ACVP `signatureInterface` for the sigGen/sigVer modes.
///
///   - internal : sign/verify M directly (FIPS 205 §9.2 / §9.3).
///   - external : prepend the domain separator + context string
///                (FIPS 205 §10.2 / §10.3).
///
/// The HashSLH-DSA pre-hash variant (`preHash: "preHash"`) is an orthogonal
/// third axis, carried separately as `pre_hash` on the decoded vectors rather
/// than folded in here — ACVP reports the two independently, and every
/// pre-hash group is also an `external` group.
pub const Interface = enum {
    internal,
    external,

    pub fn fromString(s: []const u8) ?Interface {
        if (std.mem.eql(u8, s, "internal")) return .internal;
        if (std.mem.eql(u8, s, "external")) return .external;
        return null;
    }
};

/// Re-exported so the walker in `kat_main.zig` can name the type without
/// reaching past this module into the library.
pub const PreHash = slh_dsa.PreHash;

/// Parsed ACVP `hashAlg` name -> the pre-hash function (FIPS 205 §10.2.2).
///
/// Only meaningful inside a `preHash: "preHash"` group; pure and internal
/// groups report `hashAlg: "none"`, which has no `PreHash` and maps to null.
pub fn parsePreHash(name: []const u8) ?slh_dsa.PreHash {
    const map = .{
        .{ "SHA2-224", slh_dsa.PreHash.sha2_224 },
        .{ "SHA2-256", slh_dsa.PreHash.sha2_256 },
        .{ "SHA2-384", slh_dsa.PreHash.sha2_384 },
        .{ "SHA2-512", slh_dsa.PreHash.sha2_512 },
        .{ "SHA2-512/224", slh_dsa.PreHash.sha2_512_224 },
        .{ "SHA2-512/256", slh_dsa.PreHash.sha2_512_256 },
        .{ "SHA3-224", slh_dsa.PreHash.sha3_224 },
        .{ "SHA3-256", slh_dsa.PreHash.sha3_256 },
        .{ "SHA3-384", slh_dsa.PreHash.sha3_384 },
        .{ "SHA3-512", slh_dsa.PreHash.sha3_512 },
        .{ "SHAKE-128", slh_dsa.PreHash.shake_128 },
        .{ "SHAKE-256", slh_dsa.PreHash.shake_256 },
    };
    inline for (map) |entry| {
        if (std.mem.eql(u8, name, entry[0])) return entry[1];
    }
    return null;
}

/// Parsed ACVP parameter-set name -> our enum.
pub fn parseParamSet(name: []const u8) ?slh_dsa.ParamSet {
    const map = .{
        .{ "SLH-DSA-SHA2-128s", slh_dsa.ParamSet.slh_dsa_sha2_128s },
        .{ "SLH-DSA-SHA2-128f", slh_dsa.ParamSet.slh_dsa_sha2_128f },
        .{ "SLH-DSA-SHA2-192s", slh_dsa.ParamSet.slh_dsa_sha2_192s },
        .{ "SLH-DSA-SHA2-192f", slh_dsa.ParamSet.slh_dsa_sha2_192f },
        .{ "SLH-DSA-SHA2-256s", slh_dsa.ParamSet.slh_dsa_sha2_256s },
        .{ "SLH-DSA-SHA2-256f", slh_dsa.ParamSet.slh_dsa_sha2_256f },
        .{ "SLH-DSA-SHAKE-128s", slh_dsa.ParamSet.slh_dsa_shake_128s },
        .{ "SLH-DSA-SHAKE-128f", slh_dsa.ParamSet.slh_dsa_shake_128f },
        .{ "SLH-DSA-SHAKE-192s", slh_dsa.ParamSet.slh_dsa_shake_192s },
        .{ "SLH-DSA-SHAKE-192f", slh_dsa.ParamSet.slh_dsa_shake_192f },
        .{ "SLH-DSA-SHAKE-256s", slh_dsa.ParamSet.slh_dsa_shake_256s },
        .{ "SLH-DSA-SHAKE-256f", slh_dsa.ParamSet.slh_dsa_shake_256f },
    };
    inline for (map) |entry| {
        if (std.mem.eql(u8, name, entry[0])) return entry[1];
    }
    return null;
}

/// Decoded keyGen vector.
pub const KeyGenVector = struct {
    tc_id: u64,
    param_set: slh_dsa.ParamSet,
    sk_seed: []u8,
    sk_prf: []u8,
    pk_seed: []u8,
    expected_pk: []u8,
    expected_sk: []u8,
};

/// Decoded sigGen vector.
pub const SigGenVector = struct {
    tc_id: u64,
    param_set: slh_dsa.ParamSet,
    interface: Interface,
    sk: []u8,
    msg: []u8,
    /// Context string for the external interface (may be empty); `null` for
    /// the internal interface, which has no context.
    ctx: ?[]u8,
    /// The per-signature randomiser (`additionalRandomness`), `null` for
    /// deterministic signing (opt_rand defaults to PK.seed per FIPS 205 §9.2).
    opt_rand: ?[]u8,
    /// The pre-hash function for a HashSLH-DSA vector (FIPS 205 §10.2.2),
    /// or `null` for a pure/internal vector. When set it takes precedence
    /// over `interface`, which ACVP always reports as `external` here.
    pre_hash: ?slh_dsa.PreHash = null,
    expected_sig: []u8,
};

/// Decoded sigVer vector.
pub const SigVerVector = struct {
    tc_id: u64,
    param_set: slh_dsa.ParamSet,
    interface: Interface,
    pk: []u8,
    msg: []u8,
    /// Context string for the external interface (may be empty); `null` for
    /// the internal interface.
    ctx: ?[]u8,
    sig: []u8,
    /// The pre-hash function for a HashSLH-DSA vector (FIPS 205 §10.3), or
    /// `null` for a pure/internal vector.
    pre_hash: ?slh_dsa.PreHash = null,
    expected_accept: bool,
};

/// Per-vector result.
pub const VectorResult = struct {
    tc_id: u64,
    param_set: slh_dsa.ParamSet,
    pass: bool,
    /// Optional human-readable diagnostic. Allocated by the runner; the
    /// caller owns it.
    detail: ?[]const u8 = null,
};

/// Aggregate result over a batch of vectors.
pub const RunSummary = struct {
    total: u32 = 0,
    passed: u32 = 0,
    failed: u32 = 0,
    skipped: u32 = 0,

    pub fn record(self: *RunSummary, result: VectorResult) void {
        self.total += 1;
        if (result.pass) self.passed += 1 else self.failed += 1;
    }
};

// -----------------------------------------------------------------------------
// Vector loading.
//
// The ACVP JSON structure (paraphrased):
//
//   {
//     "vsId": ...,
//     "algorithm": "SLH-DSA",
//     "mode": "keyGen" | "sigGen" | "sigVer",
//     "testGroups": [
//       {
//         "tgId": 1,
//         "parameterSet": "SLH-DSA-SHAKE-128s",
//         "tests": [
//           { "tcId": 1, ...vector-specific fields... },
//           ...
//         ]
//       },
//       ...
//     ]
//   }
//
// We use std.json to parse generically and then post-process per-mode.
// -----------------------------------------------------------------------------

/// The vector file did not match the documented ACVP shape (missing
/// field, wrong JSON type, or out-of-range value). Raised by the typed
/// accessors below so malformed input surfaces as a controlled error
/// instead of a safety panic in the JSON walk.
pub const VectorFileError = error{MalformedVectorFile};

/// Typed accessors over `std.json.Value`. ACVP files are external input;
/// every field access in the walk goes through these rather than
/// force-unwrapping unions.
pub fn asObject(v: std.json.Value) VectorFileError!std.json.ObjectMap {
    return switch (v) {
        .object => |o| o,
        else => error.MalformedVectorFile,
    };
}

pub fn asArray(v: std.json.Value) VectorFileError!std.json.Array {
    return switch (v) {
        .array => |a| a,
        else => error.MalformedVectorFile,
    };
}

pub fn asString(v: std.json.Value) VectorFileError![]const u8 {
    return switch (v) {
        .string => |s| s,
        else => error.MalformedVectorFile,
    };
}

/// The sigVer `testPassed` field is a JSON boolean; anything else is
/// malformed.
pub fn asBool(v: std.json.Value) VectorFileError!bool {
    return switch (v) {
        .bool => |b| b,
        else => error.MalformedVectorFile,
    };
}

/// A tcId must be a non-negative JSON integer; anything else (including
/// a negative value, which `std.json` can represent) is malformed.
pub fn asTcId(v: std.json.Value) VectorFileError!u64 {
    return switch (v) {
        .integer => |i| if (i < 0) error.MalformedVectorFile else @intCast(i),
        else => error.MalformedVectorFile,
    };
}

/// Fetch a required field from an ACVP object.
pub fn getField(obj: std.json.ObjectMap, name: []const u8) VectorFileError!std.json.Value {
    return obj.get(name) orelse error.MalformedVectorFile;
}

/// Open a JSON vector file from disk and parse it into a `std.json.Value`.
/// Caller frees the returned `Parsed` value.
pub fn loadVectorsFromFile(
    io: std.Io,
    allocator: std.mem.Allocator,
    path: []const u8,
) !std.json.Parsed(std.json.Value) {
    const file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    const stat = try file.stat(io);
    const buf = try allocator.alloc(u8, stat.size);
    defer allocator.free(buf);
    _ = try file.readPositionalAll(io, buf, 0);
    return std.json.parseFromSlice(std.json.Value, allocator, buf, .{});
}

// -----------------------------------------------------------------------------
// Per-mode executors. Each takes a vector struct and produces a VectorResult.
//
// All three are implemented and drive the real scheme; none returns a
// "skipped" result of its own. `skipped` in the summary is accounted for by
// the walker in `kat_main.zig`, and only for input it cannot recognise.
// -----------------------------------------------------------------------------

pub fn runKeyGen(
    allocator: std.mem.Allocator,
    v: KeyGenVector,
) !VectorResult {
    switch (v.param_set) {
        inline else => |ps| {
            const S = slh_dsa.Slh_Dsa(ps);
            const n = S.params.n;

            if (v.sk_seed.len != n or v.sk_prf.len != n or v.pk_seed.len != n) {
                return .{
                    .tc_id = v.tc_id,
                    .param_set = v.param_set,
                    .pass = false,
                    .detail = try std.fmt.allocPrint(allocator, "seed length mismatch (expected {d} bytes)", .{n}),
                };
            }

            const kp = S.KeyPair.fromSeeds(
                v.sk_seed[0..n],
                v.sk_prf[0..n],
                v.pk_seed[0..n],
            ) catch |err| {
                return .{
                    .tc_id = v.tc_id,
                    .param_set = v.param_set,
                    .pass = false,
                    .detail = try std.fmt.allocPrint(allocator, "fromSeeds failed: {s}", .{@errorName(err)}),
                };
            };

            const pk_ok = std.mem.eql(u8, &kp.public_key, v.expected_pk);
            const sk_ok = std.mem.eql(u8, &kp.secret_key, v.expected_sk);
            if (pk_ok and sk_ok) {
                return .{ .tc_id = v.tc_id, .param_set = v.param_set, .pass = true };
            }
            return .{
                .tc_id = v.tc_id,
                .param_set = v.param_set,
                .pass = false,
                .detail = try std.fmt.allocPrint(allocator, "mismatch: pk_ok={} sk_ok={}", .{ pk_ok, sk_ok }),
            };
        },
    }
}

/// Build a failing `VectorResult` with an allocated diagnostic string.
/// The caller owns `detail`.
fn fail(
    allocator: std.mem.Allocator,
    tc_id: u64,
    param_set: slh_dsa.ParamSet,
    comptime fmt: []const u8,
    args: anytype,
) !VectorResult {
    return .{
        .tc_id = tc_id,
        .param_set = param_set,
        .pass = false,
        .detail = try std.fmt.allocPrint(allocator, fmt, args),
    };
}

/// FIPS 205 §9.2 / §10.2 — sign `v.msg` and compare against the ACVP
/// expected signature byte-for-byte. `v.interface` selects the internal
/// signer (M direct) or the external signer (context-string prefix); a
/// present `v.opt_rand` selects randomised signing, `null` deterministic.
pub fn runSigGen(
    allocator: std.mem.Allocator,
    v: SigGenVector,
) !VectorResult {
    switch (v.param_set) {
        inline else => |ps| {
            const S = slh_dsa.Slh_Dsa(ps);
            const n = S.params.n;

            if (v.sk.len != S.secret_key_length)
                return fail(allocator, v.tc_id, v.param_set, "sk length {d}, expected {d}", .{ v.sk.len, S.secret_key_length });
            if (v.expected_sig.len != S.signature_length)
                return fail(allocator, v.tc_id, v.param_set, "expected signature length {d}, expected {d}", .{ v.expected_sig.len, S.signature_length });
            if (v.opt_rand) |r| {
                if (r.len != n)
                    return fail(allocator, v.tc_id, v.param_set, "additionalRandomness length {d}, expected {d}", .{ r.len, n });
            }

            const sk: *const S.SecretKey = v.sk[0..S.secret_key_length];
            const opt_rand: ?*const [n]u8 = if (v.opt_rand) |r| r[0..n] else null;

            var sig: S.Signature = undefined;
            if (v.pre_hash) |ph| {
                S.signPreHash(&sig, v.msg, v.ctx orelse "", ph, sk, opt_rand) catch |err|
                    return fail(allocator, v.tc_id, v.param_set, "signPreHash failed: {s}", .{@errorName(err)});
            } else switch (v.interface) {
                .internal => S.signInternal(&sig, v.msg, sk, opt_rand),
                .external => S.signWithContext(&sig, v.msg, v.ctx orelse "", sk, opt_rand) catch |err|
                    return fail(allocator, v.tc_id, v.param_set, "signWithContext failed: {s}", .{@errorName(err)}),
            }

            if (std.mem.eql(u8, &sig, v.expected_sig))
                return .{ .tc_id = v.tc_id, .param_set = v.param_set, .pass = true };
            if (v.pre_hash) |ph|
                return fail(allocator, v.tc_id, v.param_set, "signature mismatch (pre-hash {s})", .{@tagName(ph)});
            return fail(allocator, v.tc_id, v.param_set, "signature mismatch ({s} interface)", .{@tagName(v.interface)});
        },
    }
}

/// FIPS 205 §9.3 / §10.3 — verify `v.sig` over `v.msg` and check the
/// accept/reject decision against the ACVP `testPassed` expectation. A
/// wrong-length public key or signature (ACVP's "too large" / "too small"
/// negatives) cannot form the fixed-size arrays the API takes, so it is a
/// rejection rather than a runner error.
pub fn runSigVer(
    allocator: std.mem.Allocator,
    v: SigVerVector,
) !VectorResult {
    switch (v.param_set) {
        inline else => |ps| {
            const S = slh_dsa.Slh_Dsa(ps);

            const accepted = blk: {
                if (v.pk.len != S.public_key_length or v.sig.len != S.signature_length)
                    break :blk false;
                const pk: *const S.PublicKey = v.pk[0..S.public_key_length];
                const sig: *const S.Signature = v.sig[0..S.signature_length];
                const res = if (v.pre_hash) |ph|
                    S.verifyPreHash(sig, v.msg, v.ctx orelse "", ph, pk)
                else switch (v.interface) {
                    .internal => S.verifyInternal(sig, v.msg, pk),
                    .external => S.verifyWithContext(sig, v.msg, v.ctx orelse "", pk),
                };
                break :blk if (res) |_| true else |_| false;
            };

            if (accepted == v.expected_accept)
                return .{ .tc_id = v.tc_id, .param_set = v.param_set, .pass = true };
            if (v.pre_hash) |ph|
                return fail(allocator, v.tc_id, v.param_set, "verify accepted={}, expected accepted={} (pre-hash {s})", .{ accepted, v.expected_accept, @tagName(ph) });
            return fail(allocator, v.tc_id, v.param_set, "verify accepted={}, expected accepted={} ({s} interface)", .{ accepted, v.expected_accept, @tagName(v.interface) });
        },
    }
}

// -----------------------------------------------------------------------------
// Hex decode helper — ACVP vectors use uppercase hex strings throughout.
// -----------------------------------------------------------------------------

pub fn hexDecode(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return error.OddHexLength;
    const out = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(out);
    var i: usize = 0;
    while (i < hex.len) : (i += 2) {
        out[i / 2] = try std.fmt.parseInt(u8, hex[i .. i + 2], 16);
    }
    return out;
}

// -----------------------------------------------------------------------------
// Tests.
// -----------------------------------------------------------------------------

test "parseParamSet maps every ACVP name" {
    try std.testing.expectEqual(@as(?slh_dsa.ParamSet, slh_dsa.ParamSet.slh_dsa_sha2_128s), parseParamSet("SLH-DSA-SHA2-128s"));
    try std.testing.expectEqual(@as(?slh_dsa.ParamSet, slh_dsa.ParamSet.slh_dsa_shake_256f), parseParamSet("SLH-DSA-SHAKE-256f"));
    try std.testing.expectEqual(@as(?slh_dsa.ParamSet, null), parseParamSet("not-a-real-set"));
}

test "VectorType.fromString" {
    try std.testing.expectEqual(@as(?VectorType, .key_gen), VectorType.fromString("keyGen"));
    try std.testing.expectEqual(@as(?VectorType, .sig_gen), VectorType.fromString("sigGen"));
    try std.testing.expectEqual(@as(?VectorType, .sig_ver), VectorType.fromString("sigVer"));
    try std.testing.expectEqual(@as(?VectorType, null), VectorType.fromString("garbage"));
}

test "Interface.fromString" {
    try std.testing.expectEqual(@as(?Interface, .internal), Interface.fromString("internal"));
    try std.testing.expectEqual(@as(?Interface, .external), Interface.fromString("external"));
    try std.testing.expectEqual(@as(?Interface, null), Interface.fromString("preHash"));
}

test "parsePreHash maps every ACVP hashAlg the vectors use" {
    // The twelve names that appear as `hashAlg` across siggen.json and
    // sigver.json. ACVP spells the XOFs "SHAKE-128"/"SHAKE-256" (hyphenated),
    // unlike FIPS 205's "SHAKE128"/"SHAKE256", so these strings are matched
    // against the vector files rather than the standard's prose.
    const cases = .{
        .{ "SHA2-224", PreHash.sha2_224 },         .{ "SHA2-256", PreHash.sha2_256 },
        .{ "SHA2-384", PreHash.sha2_384 },         .{ "SHA2-512", PreHash.sha2_512 },
        .{ "SHA2-512/224", PreHash.sha2_512_224 }, .{ "SHA2-512/256", PreHash.sha2_512_256 },
        .{ "SHA3-224", PreHash.sha3_224 },         .{ "SHA3-256", PreHash.sha3_256 },
        .{ "SHA3-384", PreHash.sha3_384 },         .{ "SHA3-512", PreHash.sha3_512 },
        .{ "SHAKE-128", PreHash.shake_128 },       .{ "SHAKE-256", PreHash.shake_256 },
    };
    inline for (cases) |c| {
        try std.testing.expectEqual(@as(?PreHash, c[1]), parsePreHash(c[0]));
    }
    // Pure and internal groups report "none": no pre-hash function.
    try std.testing.expectEqual(@as(?PreHash, null), parsePreHash("none"));
    try std.testing.expectEqual(@as(?PreHash, null), parsePreHash("SHAKE128"));
    try std.testing.expectEqual(@as(?PreHash, null), parsePreHash(""));
    try std.testing.expectEqual(@as(?Interface, null), Interface.fromString(""));
}

test "hexDecode round-trips" {
    const out = try hexDecode(std.testing.allocator, "DEADBEEF");
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF }, out);
}

test "typed accessors reject wrong JSON types instead of panicking" {
    const str_val = std.json.Value{ .string = "hello" };
    const int_val = std.json.Value{ .integer = 42 };
    const neg_val = std.json.Value{ .integer = -1 };

    try std.testing.expectError(error.MalformedVectorFile, asObject(str_val));
    try std.testing.expectError(error.MalformedVectorFile, asArray(str_val));
    try std.testing.expectError(error.MalformedVectorFile, asString(int_val));
    try std.testing.expectError(error.MalformedVectorFile, asTcId(str_val));
    try std.testing.expectError(error.MalformedVectorFile, asTcId(neg_val));
    try std.testing.expectError(error.MalformedVectorFile, asBool(int_val));

    try std.testing.expectEqualStrings("hello", try asString(str_val));
    try std.testing.expectEqual(@as(u64, 42), try asTcId(int_val));
    try std.testing.expectEqual(true, try asBool(.{ .bool = true }));
    try std.testing.expectEqual(false, try asBool(.{ .bool = false }));
}

test "getField reports missing fields as malformed" {
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, "{\"present\":1}", .{});
    defer parsed.deinit();
    const obj = try asObject(parsed.value);

    try std.testing.expectError(error.MalformedVectorFile, getField(obj, "absent"));
    const got = try getField(obj, "present");
    try std.testing.expectEqual(@as(i64, 1), got.integer);
}

test "sigGen/sigVer executors: interface dispatch + accept/reject plumbing" {
    // Self-contained smoke test of the executor plumbing — interface
    // dispatch, deterministic vs randomised, context handling, and the
    // wrong-length-signature rejection path — without needing external ACVP
    // files. The library is its own oracle here: sign, then feed the
    // produced signature back through the executors. Byte-exact validation
    // against NIST's expected outputs is the job of `zig build kat`
    // (issue #25); this only guards the runner glue on a fast parameter set.
    const S = slh_dsa.Slh_Dsa(.slh_dsa_shake_128f);
    const ps = slh_dsa.ParamSet.slh_dsa_shake_128f;
    const n = S.params.n;

    var sk_seed: [n]u8 = undefined;
    var sk_prf: [n]u8 = undefined;
    var pk_seed: [n]u8 = undefined;
    for (&sk_seed, 0..) |*b, i| b.* = @intCast(0x11 + i);
    for (&sk_prf, 0..) |*b, i| b.* = @intCast(0x55 + i);
    for (&pk_seed, 0..) |*b, i| b.* = @intCast(0x99 + i);
    const kp = try S.KeyPair.fromSeeds(&sk_seed, &sk_prf, &pk_seed);

    var sk = kp.secret_key;
    var pk = kp.public_key;
    var msg = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    var ctx = [_]u8{ 0x01, 0x02, 0x03 };

    // internal, deterministic (opt_rand = null): sigGen must reproduce the
    // signature and sigVer must accept it.
    var sig_int: S.Signature = undefined;
    S.signInternal(&sig_int, &msg, &sk, null);
    {
        const gen = try runSigGen(std.testing.allocator, .{
            .tc_id = 1,
            .param_set = ps,
            .interface = .internal,
            .sk = sk[0..],
            .msg = msg[0..],
            .ctx = null,
            .opt_rand = null,
            .expected_sig = sig_int[0..],
        });
        try std.testing.expect(gen.pass);

        const ver = try runSigVer(std.testing.allocator, .{
            .tc_id = 1,
            .param_set = ps,
            .interface = .internal,
            .pk = pk[0..],
            .msg = msg[0..],
            .ctx = null,
            .sig = sig_int[0..],
            .expected_accept = true,
        });
        try std.testing.expect(ver.pass);
    }

    // external, randomised, non-empty context.
    var rnd: [n]u8 = undefined;
    for (&rnd, 0..) |*b, i| b.* = @intCast(0xE1 ^ i);
    var sig_ext: S.Signature = undefined;
    try S.signWithContext(&sig_ext, &msg, &ctx, &sk, &rnd);
    {
        const gen = try runSigGen(std.testing.allocator, .{
            .tc_id = 2,
            .param_set = ps,
            .interface = .external,
            .sk = sk[0..],
            .msg = msg[0..],
            .ctx = ctx[0..],
            .opt_rand = rnd[0..],
            .expected_sig = sig_ext[0..],
        });
        try std.testing.expect(gen.pass);

        const ver = try runSigVer(std.testing.allocator, .{
            .tc_id = 2,
            .param_set = ps,
            .interface = .external,
            .pk = pk[0..],
            .msg = msg[0..],
            .ctx = ctx[0..],
            .sig = sig_ext[0..],
            .expected_accept = true,
        });
        try std.testing.expect(ver.pass);
    }

    // sigVer negatives: a tampered signature with an expected reject must be
    // *scored* as a pass (the executor checks accept == expected).
    var tampered = sig_int;
    tampered[0] ^= 0x01;
    {
        const ver = try runSigVer(std.testing.allocator, .{
            .tc_id = 3,
            .param_set = ps,
            .interface = .internal,
            .pk = pk[0..],
            .msg = msg[0..],
            .ctx = null,
            .sig = tampered[0..],
            .expected_accept = false,
        });
        try std.testing.expect(ver.pass);
    }

    // A truncated signature (ACVP "invalid signature - too small") is a
    // rejection, handled without forming the fixed-size array or crashing.
    {
        const ver = try runSigVer(std.testing.allocator, .{
            .tc_id = 4,
            .param_set = ps,
            .interface = .internal,
            .pk = pk[0..],
            .msg = msg[0..],
            .ctx = null,
            .sig = sig_int[0 .. sig_int.len - 1],
            .expected_accept = false,
        });
        try std.testing.expect(ver.pass);
    }

    // A genuine mismatch produces a failing result with a heap-allocated
    // diagnostic — verify the failure path and free the detail.
    {
        const gen = try runSigGen(std.testing.allocator, .{
            .tc_id = 5,
            .param_set = ps,
            .interface = .external,
            .sk = sk[0..],
            .msg = msg[0..],
            .ctx = ctx[0..],
            .opt_rand = null, // deterministic external ≠ the randomised sig_ext
            .expected_sig = sig_ext[0..],
        });
        try std.testing.expect(!gen.pass);
        if (gen.detail) |d| std.testing.allocator.free(d);
    }
}
