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
//! Status: keyGen is fully wired; sigGen/sigVer executors return
//! "not implemented" until the corresponding scheme bodies land.

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
    sk: []u8,
    msg: []u8,
    /// `null` for deterministic signing.
    opt_rand: ?[]u8,
    expected_sig: []u8,
};

/// Decoded sigVer vector.
pub const SigVerVector = struct {
    tc_id: u64,
    param_set: slh_dsa.ParamSet,
    pk: []u8,
    msg: []u8,
    sig: []u8,
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
// These are SKELETON and will be filled in alongside the corresponding
// scheme implementation. Until then they return a "skipped" result.
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

pub fn runSigGen(
    _: std.mem.Allocator,
    v: SigGenVector,
) !VectorResult {
    // TODO: instantiate Slh_Dsa, call sign, compare expected_sig.
    return .{ .tc_id = v.tc_id, .param_set = v.param_set, .pass = false, .detail = "skeleton: sign not implemented" };
}

pub fn runSigVer(
    _: std.mem.Allocator,
    v: SigVerVector,
) !VectorResult {
    // TODO: instantiate Slh_Dsa, call verify, compare against expected_accept.
    return .{ .tc_id = v.tc_id, .param_set = v.param_set, .pass = false, .detail = "skeleton: verify not implemented" };
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

    try std.testing.expectEqualStrings("hello", try asString(str_val));
    try std.testing.expectEqual(@as(u64, 42), try asTcId(int_val));
}

test "getField reports missing fields as malformed" {
    var obj = std.json.ObjectMap.init(std.testing.allocator);
    defer obj.deinit();
    try obj.put("present", .{ .integer = 1 });

    try std.testing.expectError(error.MalformedVectorFile, getField(obj, "absent"));
    const got = try getField(obj, "present");
    try std.testing.expectEqual(@as(i64, 1), got.integer);
}
