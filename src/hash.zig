//! FIPS 205 §11 — Hash function instantiations.
//!
//! SLH-DSA defines six keyed hash functions (PRF, PRF_msg, H_msg, F, H, T_l).
//! FIPS 205 §11.1 instantiates them with SHAKE; §11.2 instantiates them with
//! SHA-2. This module is the comptime dispatcher that picks the right
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
//   PRF_msg  (sk_prf: *const [n]u8, opt_rand: *const [n]u8,
//             msg_parts: []const []const u8, out: *[n]u8) void
//
//   H_msg    (rand: *const [n]u8, pk_seed: *const [n]u8, pk_root: *const [n]u8,
//             msg_parts: []const []const u8, out: *[m]u8) void
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
const Adrs = address.Adrs;

test "Hash adapter resolves for all parameter sets" {
    inline for (std.enums.values(params_mod.ParamSet)) |ps| {
        const p = comptime ps.params();
        _ = Hash(p);
    }
}

test "every parameter set: PRF and F produce deterministic, non-zero output" {
    inline for (std.enums.values(params_mod.ParamSet)) |ps| {
        const p = comptime ps.params();
        const H = Hash(p);
        const n = H.n;

        const sk_seed = [_]u8{0x5A} ** n;
        const pk_seed = [_]u8{0xA5} ** n;
        const msg = [_]u8{0x3C} ** n;

        var adrs = Adrs.init();
        adrs.setType(.wots_hash);
        adrs.setKeyPairAddress(7);
        adrs.setChainAddress(3);

        // PRF — twice, assert deterministic and not all-zero.
        var prf1: [n]u8 = undefined;
        var prf2: [n]u8 = undefined;
        H.prf(&sk_seed, &pk_seed, &adrs, &prf1);
        H.prf(&sk_seed, &pk_seed, &adrs, &prf2);
        try testing.expectEqualSlices(u8, &prf1, &prf2);
        try testing.expect(!std.mem.allEqual(u8, &prf1, 0));

        // F — twice, assert deterministic and not all-zero.
        var f1: [n]u8 = undefined;
        var f2: [n]u8 = undefined;
        H.f(&pk_seed, &adrs, &msg, &f1);
        H.f(&pk_seed, &adrs, &msg, &f2);
        try testing.expectEqualSlices(u8, &f1, &f2);
        try testing.expect(!std.mem.allEqual(u8, &f1, 0));
    }
}

test "SHAKE and SHA-2 backends differ on identical inputs" {
    // Same (pk_seed, adrs, msg) under matched 128-bit param sets must produce
    // different F output — a sanity check that the dispatcher is not routing
    // both families to the same implementation.
    const Shake = Hash(comptime params_mod.ParamSet.slh_dsa_shake_128s.params());
    const Sha2 = Hash(comptime params_mod.ParamSet.slh_dsa_sha2_128s.params());
    const n = Shake.n; // == Sha2.n == 16

    const pk_seed = [_]u8{0x11} ** n;
    const msg = [_]u8{0x22} ** n;
    var adrs = Adrs.init();
    adrs.setType(.wots_hash);
    adrs.setChainAddress(1);

    var out_shake: [n]u8 = undefined;
    var out_sha2: [n]u8 = undefined;
    Shake.f(&pk_seed, &adrs, &msg, &out_shake);
    Sha2.f(&pk_seed, &adrs, &msg, &out_sha2);

    try testing.expect(!std.mem.eql(u8, &out_shake, &out_sha2));
}
