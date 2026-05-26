//! FIPS 205 §10.2 — SHAKE instantiations of SLH-DSA hash functions.
//!
//! All six functions are realised via SHAKE-256 with appropriate output
//! lengths. SHAKE-256 is convenient here because its variable output length
//! sidesteps the MGF1 layer that the SHA-2 instances require.
//!
//! Status: SKELETON. Function signatures match the FIPS 205 contract;
//! bodies @panic until the Lane B implementation lands.

const std = @import("std");
const params_mod = @import("params.zig");
const address = @import("address.zig");

const Shake256 = std.crypto.hash.sha3.Shake256;

pub fn ShakeAdapter(comptime p: params_mod.Params) type {
    return struct {
        pub const n: usize = p.n;
        pub const m: usize = p.m;
        pub const family = params_mod.HashFamily.shake;

        const Self = @This();

        /// FIPS 205 §10.2 — PRF.
        ///
        /// PRF(PK.seed, SK.seed, ADRS) = SHAKE256(PK.seed || ADRS || SK.seed, 8n).
        pub fn prf(
            sk_seed: *const [n]u8,
            pk_seed: *const [n]u8,
            adrs: *const address.Adrs,
            out: *[n]u8,
        ) void {
            _ = sk_seed;
            _ = pk_seed;
            _ = adrs;
            _ = out;
            @panic("TODO: PRF not implemented yet (FIPS 205 §10.2)");
        }

        /// FIPS 205 §10.2 — PRF_msg.
        ///
        /// PRF_msg(SK.prf, opt_rand, M) = SHAKE256(SK.prf || opt_rand || M, 8n).
        pub fn prf_msg(
            sk_prf: *const [n]u8,
            opt_rand: *const [n]u8,
            msg: []const u8,
            out: *[n]u8,
        ) void {
            _ = sk_prf;
            _ = opt_rand;
            _ = msg;
            _ = out;
            @panic("TODO: PRF_msg not implemented yet (FIPS 205 §10.2)");
        }

        /// FIPS 205 §10.2 — H_msg.
        ///
        /// H_msg(R, PK.seed, PK.root, M) = SHAKE256(R || PK.seed || PK.root || M, 8m).
        pub fn h_msg(
            rand: *const [n]u8,
            pk_seed: *const [n]u8,
            pk_root: *const [n]u8,
            msg: []const u8,
            out: *[m]u8,
        ) void {
            _ = rand;
            _ = pk_seed;
            _ = pk_root;
            _ = msg;
            _ = out;
            @panic("TODO: H_msg not implemented yet (FIPS 205 §10.2)");
        }

        /// FIPS 205 §10.2 — F.
        ///
        /// F(PK.seed, ADRS, M_1) = SHAKE256(PK.seed || ADRS || M_1, 8n).
        pub fn f(
            pk_seed: *const [n]u8,
            adrs: *const address.Adrs,
            msg: *const [n]u8,
            out: *[n]u8,
        ) void {
            _ = pk_seed;
            _ = adrs;
            _ = msg;
            _ = out;
            @panic("TODO: F not implemented yet (FIPS 205 §10.2)");
        }

        /// FIPS 205 §10.2 — H.
        ///
        /// H(PK.seed, ADRS, M_2) = SHAKE256(PK.seed || ADRS || M_2, 8n)
        /// where M_2 is the concatenation of two n-byte messages.
        pub fn h(
            pk_seed: *const [n]u8,
            adrs: *const address.Adrs,
            left: *const [n]u8,
            right: *const [n]u8,
            out: *[n]u8,
        ) void {
            _ = pk_seed;
            _ = adrs;
            _ = left;
            _ = right;
            _ = out;
            @panic("TODO: H not implemented yet (FIPS 205 §10.2)");
        }

        /// FIPS 205 §10.2 — T_l.
        ///
        /// T_l(PK.seed, ADRS, M_l) = SHAKE256(PK.seed || ADRS || M_l, 8n)
        /// where M_l is l concatenated n-byte messages.
        pub fn t_l(
            pk_seed: *const [n]u8,
            adrs: *const address.Adrs,
            msg: []const u8,
            out: *[n]u8,
        ) void {
            _ = pk_seed;
            _ = adrs;
            _ = msg;
            _ = out;
            @panic("TODO: T_l not implemented yet (FIPS 205 §10.2)");
        }
    };
}

test "ShakeAdapter compiles for all SHAKE parameter sets" {
    inline for (std.enums.values(params_mod.ParamSet)) |ps| {
        if (ps.family() == .shake) {
            const A = ShakeAdapter(ps.params());
            try std.testing.expectEqual(@as(usize, ps.params().n), A.n);
        }
    }
}
