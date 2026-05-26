//! FIPS 205 §10.1 — SHA-2 instantiations of SLH-DSA hash functions.
//!
//! Backend selection rules from §10.1:
//!
//!   - For all SLH-DSA-SHA2-* sets: F uses SHA-256 (always).
//!   - For n = 16 (128-bit security): H, T_l, H_msg use SHA-256.
//!   - For n = 24, 32 (192/256-bit security): H, T_l, H_msg use SHA-512.
//!   - PRF and PRF_msg use HMAC-SHA-X with the appropriate hash function.
//!   - Variable-length outputs (H_msg, PRF_msg) are extended via MGF1.
//!
//! Status: SKELETON. Function signatures match the FIPS 205 contract;
//! bodies return zero (with a `@compileLog`-equivalent TODO) until the
//! Lane B implementation lands.

const std = @import("std");
const params_mod = @import("params.zig");
const address = @import("address.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha512 = std.crypto.hash.sha2.Sha512;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const HmacSha512 = std.crypto.auth.hmac.sha2.HmacSha512;

pub fn Sha2Adapter(comptime p: params_mod.Params) type {
    return struct {
        pub const n: usize = p.n;
        pub const m: usize = p.m;
        pub const family = params_mod.HashFamily.sha2;

        const Self = @This();

        /// FIPS 205 §10.1 — PRF (PK.seed, SK.seed, ADRS).
        ///
        /// Constant-time: yes — inputs are public (sk_seed, pk_seed, ADRS)
        /// but sk_seed is secret and must not gate any branch or memory
        /// access. The SHA-256 compression function does neither.
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
            @panic("TODO: PRF not implemented yet (FIPS 205 §10.1)");
        }

        /// FIPS 205 §10.1 — PRF_msg (SK.prf, opt_rand, M).
        ///
        /// Output length is `n`, produced via HMAC-SHA-X depending on `n`.
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
            @panic("TODO: PRF_msg not implemented yet (FIPS 205 §10.1)");
        }

        /// FIPS 205 §10.1 — H_msg (R, PK.seed, PK.root, M).
        ///
        /// Output length is `m` bytes, produced via MGF1 over SHA-X.
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
            @panic("TODO: H_msg not implemented yet (FIPS 205 §10.1)");
        }

        /// FIPS 205 §10.1 — F (PK.seed, ADRS, M_1).
        ///
        /// F always uses SHA-256 regardless of n. The output is the first
        /// n bytes of SHA-256(toByte(PK.seed, 64) || ADRS_c || M_1).
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
            @panic("TODO: F not implemented yet (FIPS 205 §10.1)");
        }

        /// FIPS 205 §10.1 — H (PK.seed, ADRS, M_2).
        ///
        /// H hashes two n-byte messages. Uses SHA-256 when n=16, SHA-512
        /// otherwise. Output is the first n bytes of the digest.
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
            @panic("TODO: H not implemented yet (FIPS 205 §10.1)");
        }

        /// FIPS 205 §10.1 — T_l (PK.seed, ADRS, M_l).
        ///
        /// T_l hashes a variable number of n-byte messages concatenated.
        /// Uses SHA-256 when n=16, SHA-512 otherwise. Output is the first
        /// n bytes of the digest.
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
            @panic("TODO: T_l not implemented yet (FIPS 205 §10.1)");
        }
    };
}

// -----------------------------------------------------------------------------
// Tests — these will only run once the adapter is actually implemented.
// Until then they trip the @panic above; the build still imports the file
// to verify the signatures compile.
// -----------------------------------------------------------------------------

test "Sha2Adapter compiles for all SHA-2 parameter sets" {
    inline for (std.enums.values(params_mod.ParamSet)) |ps| {
        if (ps.family() == .sha2) {
            const A = Sha2Adapter(ps.params());
            try std.testing.expectEqual(@as(usize, ps.params().n), A.n);
        }
    }
}
