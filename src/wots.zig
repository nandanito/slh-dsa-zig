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
//! Status: chain + pkGen implemented (keygen path); sign + pkFromSig are
//! stubs that @panic with FIPS 205 algorithm references.

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
        // FIPS 205 §5 Algorithm 5 — chain(X, i, s, PK.seed, ADRS).
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
            var tmp: [n]u8 = input.*;
            var j: u32 = i;
            while (j < i + s) : (j += 1) {
                adrs.setHashAddress(j);
                // In-place F is safe: both backends fully absorb the input
                // before the output buffer is written.
                Hash.f(pk_seed, adrs, &tmp, &tmp);
            }
            out.* = tmp;
        }

        // -----------------------------------------------------------------
        // FIPS 205 §5.1 Algorithm 6 — wots_PKgen(SK.seed, PK.seed, ADRS).
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
            // skADRS: same layer/tree/keypair as ADRS, type WOTS_PRF.
            var sk_adrs = adrs.*;
            sk_adrs.setType(.wots_prf);
            sk_adrs.setKeyPairAddress(adrs.getKeyPairAddress());

            var sk: [n]u8 = undefined;
            defer std.crypto.secureZero(u8, &sk);

            // tmp holds the chain endpoints — public key material, no scrub.
            var tmp: [len * n]u8 = undefined;
            for (0..len) |i| {
                sk_adrs.setChainAddress(@intCast(i));
                Hash.prf(sk_seed, pk_seed, &sk_adrs, &sk);
                adrs.setChainAddress(@intCast(i));
                chain(&sk, 0, @intCast(w - 1), pk_seed, adrs, tmp[i * n ..][0..n]);
            }

            // wotspkADRS: same layer/tree/keypair as ADRS, type WOTS_PK.
            // (setType clears the chain/hash fields mutated by the loop.)
            var pk_adrs = adrs.*;
            pk_adrs.setType(.wots_pk);
            pk_adrs.setKeyPairAddress(adrs.getKeyPairAddress());
            Hash.t_l(pk_seed, &pk_adrs, &tmp, out_pk);
        }

        // -----------------------------------------------------------------
        // FIPS 205 §5.2 Algorithm 7 — wots_sign(M, SK.seed, PK.seed, ADRS).
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
            @panic("TODO: WOTS+ sign not implemented yet (FIPS 205 §5.2 Algorithm 7)");
        }

        // -----------------------------------------------------------------
        // FIPS 205 §5.3 Algorithm 8 — wots_pkFromSig(sig, M, PK.seed, ADRS).
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
            @panic("TODO: WOTS+ pkFromSig not implemented yet (FIPS 205 §5.3 Algorithm 8)");
        }
    };
}

// -----------------------------------------------------------------------------
// Tests — sizes and surface area only until bodies land.
// -----------------------------------------------------------------------------

test "chain: s = 0 is the identity" {
    const p = comptime params_mod.ParamSet.slh_dsa_shake_128f.params();
    const W = Wots(p);
    const x = [_]u8{0x42} ** W.n;
    const pk_seed = [_]u8{0x11} ** W.n;
    var adrs = address.Adrs.init();
    adrs.setType(.wots_hash);
    var out: [W.n]u8 = undefined;
    W.chain(&x, 0, 0, &pk_seed, &adrs, &out);
    try std.testing.expectEqualSlices(u8, &x, &out);
}

test "chain: composes — chain(x, 0, a+b) == chain(chain(x, 0, a), a, b)" {
    // FIPS 205 §5: chaining is iterated F with the hash address tracking
    // the absolute position, so splitting the walk must not change the result.
    inline for (.{ params_mod.ParamSet.slh_dsa_shake_128f, params_mod.ParamSet.slh_dsa_sha2_128f }) |ps| {
        const p = comptime ps.params();
        const W = Wots(p);
        const x = [_]u8{0xA7} ** W.n;
        const pk_seed = [_]u8{0x33} ** W.n;

        var adrs_one = address.Adrs.init();
        adrs_one.setType(.wots_hash);
        adrs_one.setChainAddress(5);
        var full: [W.n]u8 = undefined;
        W.chain(&x, 0, 15, &pk_seed, &adrs_one, &full);

        var adrs_two = address.Adrs.init();
        adrs_two.setType(.wots_hash);
        adrs_two.setChainAddress(5);
        var half: [W.n]u8 = undefined;
        W.chain(&x, 0, 7, &pk_seed, &adrs_two, &half);
        var split: [W.n]u8 = undefined;
        W.chain(&half, 7, 8, &pk_seed, &adrs_two, &split);

        try std.testing.expectEqualSlices(u8, &full, &split);
    }
}

test "pkGen: deterministic, and distinct key pairs get distinct public keys" {
    inline for (.{ params_mod.ParamSet.slh_dsa_shake_128f, params_mod.ParamSet.slh_dsa_sha2_128f }) |ps| {
        const p = comptime ps.params();
        const W = Wots(p);
        const sk_seed = [_]u8{0x55} ** W.n;
        const pk_seed = [_]u8{0xAA} ** W.n;

        var adrs_a = address.Adrs.init();
        adrs_a.setType(.wots_hash);
        adrs_a.setKeyPairAddress(0);
        var pk_a: [W.n]u8 = undefined;
        W.pkGen(&sk_seed, &pk_seed, &adrs_a, &pk_a);

        var adrs_a2 = address.Adrs.init();
        adrs_a2.setType(.wots_hash);
        adrs_a2.setKeyPairAddress(0);
        var pk_a2: [W.n]u8 = undefined;
        W.pkGen(&sk_seed, &pk_seed, &adrs_a2, &pk_a2);
        try std.testing.expectEqualSlices(u8, &pk_a, &pk_a2);

        var adrs_b = address.Adrs.init();
        adrs_b.setType(.wots_hash);
        adrs_b.setKeyPairAddress(1);
        var pk_b: [W.n]u8 = undefined;
        W.pkGen(&sk_seed, &pk_seed, &adrs_b, &pk_b);
        try std.testing.expect(!std.mem.eql(u8, &pk_a, &pk_b));
    }
}

test "WOTS+ sizes match FIPS 205 §11 derived values" {
    const p = comptime params_mod.ParamSet.slh_dsa_sha2_128s.params();
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
