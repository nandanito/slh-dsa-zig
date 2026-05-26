//! FIPS 205 §5 — WOTS+ (Winternitz One-Time Signature Plus).
//!
//! WOTS+ is the leaf-level one-time signature scheme that XMSS builds on.
//! Each WOTS+ key signs *exactly one* message. The leaves of every XMSS
//! tree in the hypertree are WOTS+ public keys; the leaves of the bottom
//! XMSS layer are the WOTS+ keys that ultimately sign FORS public keys.
//!
//! Key concepts:
//!
//!   - Chain: an iterated application of F. WOTS+ defines `len` chains,
//!     each of length `w = 2^lg_w`. A secret key is the chain origin;
//!     the public key is the chain endpoint.
//!
//!   - Signature: for each chain `i`, advance from the secret element
//!     `c_i` positions along the chain, where `c_i` is the i-th base-w
//!     digit of (digest || checksum).
//!
//!   - Checksum: protects against forgery. Without the checksum, an
//!     attacker who sees a signature `s` could create a valid signature
//!     for any message whose digits are pointwise >= those of the
//!     original message. The checksum makes that impossible.
//!
//! Status: SKELETON. Public surface is set; bodies @panic with FIPS 205
//! algorithm references until the Lane B implementation lands.

const std = @import("std");
const params_mod = @import("params.zig");
const address = @import("address.zig");
const hash_mod = @import("hash.zig");
const util = @import("util.zig");

/// Construct the WOTS+ namespace for a parameter set.
pub fn Wots(comptime p: params_mod.Params) type {
    return struct {
        pub const n: usize = p.n;
        pub const w: usize = @as(usize, 1) << @as(u6, @intCast(p.lg_w));
        pub const len_1: usize = p.len_1();
        pub const len_2: usize = p.len_2();
        pub const len: usize = p.len();
        pub const lg_w: u6 = @intCast(p.lg_w);

        pub const signature_bytes: usize = len * n;

        const Hash = hash_mod.Hash(p);

        // -----------------------------------------------------------------
        // FIPS 205 §5.1 Algorithm 4 — chain(X, i, s, PK.seed, ADRS).
        //
        // Chains the n-byte input X forward by s steps starting from
        // position i.
        //
        // Constant-time: yes — the loop bound `s` is derived from a message
        // digest (public after signing); the secret key X is not used to
        // index any table or gate any branch.
        // -----------------------------------------------------------------
        pub fn chain(
            input: *const [n]u8,
            i: u32,
            s: u32,
            pk_seed: *const [n]u8,
            adrs: *address.Adrs,
            out: *[n]u8,
        ) void {
            _ = input;
            _ = i;
            _ = s;
            _ = pk_seed;
            _ = adrs;
            _ = out;
            @panic("TODO: WOTS+ chain not implemented yet (FIPS 205 §5.1 Algorithm 4)");
        }

        // -----------------------------------------------------------------
        // FIPS 205 §5.2 Algorithm 5 — wots_PKgen(SK.seed, PK.seed, ADRS).
        //
        // Computes the WOTS+ public key by chaining each secret chain
        // origin to the end and then compressing the chain endpoints
        // with T_l under ADRS type WOTS_PK.
        //
        // SK.seed is secret — must not gate branches or memory accesses.
        // -----------------------------------------------------------------
        pub fn pkGen(
            sk_seed: *const [n]u8,
            pk_seed: *const [n]u8,
            adrs: *address.Adrs,
            out_pk: *[n]u8,
        ) void {
            _ = sk_seed;
            _ = pk_seed;
            _ = adrs;
            _ = out_pk;
            @panic("TODO: WOTS+ pkGen not implemented yet (FIPS 205 §5.2 Algorithm 5)");
        }

        // -----------------------------------------------------------------
        // FIPS 205 §5.3 Algorithm 6 — wots_sign(M, SK.seed, PK.seed, ADRS).
        //
        // Signs a length-n message digest with WOTS+. Output is `len`
        // n-byte chain values.
        // -----------------------------------------------------------------
        pub fn sign(
            msg: *const [n]u8,
            sk_seed: *const [n]u8,
            pk_seed: *const [n]u8,
            adrs: *address.Adrs,
            out_sig: *[signature_bytes]u8,
        ) void {
            _ = msg;
            _ = sk_seed;
            _ = pk_seed;
            _ = adrs;
            _ = out_sig;
            @panic("TODO: WOTS+ sign not implemented yet (FIPS 205 §5.3 Algorithm 6)");
        }

        // -----------------------------------------------------------------
        // FIPS 205 §5.4 Algorithm 7 — wots_pkFromSig(sig, M, PK.seed, ADRS).
        //
        // Reconstructs the WOTS+ public key from a candidate signature
        // and a message. The verifier uses this and compares against the
        // expected public key (stored in the parent XMSS leaf).
        // -----------------------------------------------------------------
        pub fn pkFromSig(
            sig: *const [signature_bytes]u8,
            msg: *const [n]u8,
            pk_seed: *const [n]u8,
            adrs: *address.Adrs,
            out_pk: *[n]u8,
        ) void {
            _ = sig;
            _ = msg;
            _ = pk_seed;
            _ = adrs;
            _ = out_pk;
            @panic("TODO: WOTS+ pkFromSig not implemented yet (FIPS 205 §5.4 Algorithm 7)");
        }
    };
}

// -----------------------------------------------------------------------------
// Tests — sizes and surface area only until bodies land.
// -----------------------------------------------------------------------------

test "WOTS+ sizes match FIPS 205 §11 derived values" {
    const p = params_mod.ParamSet.slh_dsa_sha2_128s.params();
    const W = Wots(p);
    // For n=16, lg_w=4: len_1 = 32, len_2 = 3, len = 35.
    try std.testing.expectEqual(@as(usize, 32), W.len_1);
    try std.testing.expectEqual(@as(usize, 3), W.len_2);
    try std.testing.expectEqual(@as(usize, 35), W.len);
    try std.testing.expectEqual(@as(usize, 16), W.w);
    try std.testing.expectEqual(@as(usize, 35 * 16), W.signature_bytes);
}

test "WOTS+ instantiates for all parameter sets" {
    inline for (std.enums.values(params_mod.ParamSet)) |ps| {
        const W = Wots(ps.params());
        _ = W.signature_bytes; // exercise type construction
    }
}
