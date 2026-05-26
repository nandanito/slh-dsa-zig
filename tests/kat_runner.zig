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
//! Status: SKELETON. The dispatcher is wired up but most parameter-set
//! arms early-return until the underlying scheme implementations land.

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
    _: std.mem.Allocator,
    v: KeyGenVector,
) !VectorResult {
    // TODO: switch on v.param_set, instantiate Slh_Dsa, call
    // KeyPair.fromSeeds, compare expected_pk / expected_sk.
    return .{ .tc_id = v.tc_id, .param_set = v.param_set, .pass = false, .detail = "skeleton: KeyPair.fromSeeds not implemented" };
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
