//! FIPS 205 §10 — Hash function instantiations.
//!
//! SLH-DSA defines six keyed hash functions (PRF, PRF_msg, H_msg, F, H, T_l).
//! FIPS 205 §10.1 instantiates them with SHA-2; §10.2 instantiates them with
//! SHAKE. This module is the comptime dispatcher that picks the right
//! backend based on the parameter set.
//!
//! All adapter functions follow the same contract: a `pk_seed` (sometimes
//! abbreviated to just "seed"), an `Adrs`, the input data, and an output
//! buffer. None of the hash adapter calls allocate.

const std = @import("std");
const params_mod = @import("params.zig");
const address = @import("address.zig");

const sha2_backend = @import("hash_sha2.zig");
const shake_backend = @import("hash_shake.zig");

/// Construct a hash-adapter namespace specialised to a parameter set.
pub fn Hash(comptime p: params_mod.Params) type {
    return switch (p.family) {
        .sha2 => sha2_backend.Sha2Adapter(p),
        .shake => shake_backend.ShakeAdapter(p),
    };
}

// -----------------------------------------------------------------------------
// Adapter contract — the type returned by Hash(p) is expected to expose:
//
//   PRF      (sk_seed: *const [n]u8, pk_seed: *const [n]u8, adrs: *const Adrs,
//             out: *[n]u8) void
//
//   PRF_msg  (sk_prf: *const [n]u8, opt_rand: *const [n]u8, msg: []const u8,
//             out: *[n]u8) void
//
//   H_msg    (rand: *const [n]u8, pk_seed: *const [n]u8, pk_root: *const [n]u8,
//             msg: []const u8, out: *[m]u8) void
//
//   F        (pk_seed: *const [n]u8, adrs: *const Adrs, msg: *const [n]u8,
//             out: *[n]u8) void
//
//   H        (pk_seed: *const [n]u8, adrs: *const Adrs, left: *const [n]u8,
//             right: *const [n]u8, out: *[n]u8) void
//
//   T_l      (pk_seed: *const [n]u8, adrs: *const Adrs, msg: []const u8,
//             out: *[n]u8) void
//
// Both backends MUST match the byte-for-byte output of FIPS 205 reference
// implementations. KAT vectors are the contract; this is the unit-test
// gate that every backend has to pass before being considered functional.
// -----------------------------------------------------------------------------

const testing = std.testing;

test "Hash adapter resolves for all parameter sets" {
    inline for (std.enums.values(params_mod.ParamSet)) |ps| {
        const p = ps.params();
        _ = Hash(p);
    }
}
