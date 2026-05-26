//! FIPS 205 §6 — XMSS (eXtended Merkle Signature Scheme).
//!
//! An XMSS tree of height `h'` has 2^h' leaves, each a WOTS+ public key.
//! The XMSS root commits to all 2^h' leaves; signing one of them produces
//! a WOTS+ signature plus an authentication path of h' nodes that lets the
//! verifier walk from the leaf to the root.
//!
//! SLH-DSA stacks `d` XMSS trees into a hypertree. This module handles a
//! single XMSS layer; the hypertree composition lives in `hypertree.zig`.
//!
//! Status: SKELETON.

const std = @import("std");
const params_mod = @import("params.zig");
const address = @import("address.zig");
const hash_mod = @import("hash.zig");
const wots_mod = @import("wots.zig");

pub fn Xmss(comptime p: params_mod.Params) type {
    return struct {
        pub const n: usize = p.n;
        pub const h_prime: usize = p.h_prime;
        pub const tree_leaves: usize = @as(usize, 1) << @as(u6, @intCast(p.h_prime));

        const Wots = wots_mod.Wots(p);
        const Hash = hash_mod.Hash(p);

        /// XMSS signature: a WOTS+ signature followed by an h'-node auth path.
        pub const signature_bytes: usize = Wots.signature_bytes + h_prime * n;

        // -----------------------------------------------------------------
        // FIPS 205 §6.1 Algorithm 8 — xmss_node(SK.seed, i, z, PK.seed, ADRS).
        //
        // Recursively computes the value of node `i` at height `z` in the
        // XMSS tree rooted at PK.seed. Base case (z = 0) is a WOTS+
        // public key (i.e. wots_PKgen output). Inductive case stacks two
        // child nodes via H.
        //
        // NOTE: This is the obvious recursive formulation. Production
        // implementations should use the TreeHash construction (FIPS 205
        // §6.1 Algorithm 9) to bound stack usage to h' entries. Decide
        // which to land in upstream-candidate during Lane B.
        // -----------------------------------------------------------------
        pub fn node(
            sk_seed: *const [n]u8,
            i: u32,
            z: u32,
            pk_seed: *const [n]u8,
            adrs: *address.Adrs,
            out: *[n]u8,
        ) void {
            _ = sk_seed;
            _ = i;
            _ = z;
            _ = pk_seed;
            _ = adrs;
            _ = out;
            @panic("TODO: xmss_node not implemented yet (FIPS 205 §6.1 Algorithm 8)");
        }

        // -----------------------------------------------------------------
        // FIPS 205 §6.2 Algorithm 9 — xmss_sign(M, SK.seed, idx, PK.seed, ADRS).
        //
        // Produces an XMSS signature on the n-byte message M with leaf
        // `idx`. Output is `signature_bytes` (= WOTS+ sig + h' auth nodes).
        // -----------------------------------------------------------------
        pub fn sign(
            msg: *const [n]u8,
            sk_seed: *const [n]u8,
            idx: u32,
            pk_seed: *const [n]u8,
            adrs: *address.Adrs,
            out_sig: *[signature_bytes]u8,
        ) void {
            _ = msg;
            _ = sk_seed;
            _ = idx;
            _ = pk_seed;
            _ = adrs;
            _ = out_sig;
            @panic("TODO: xmss_sign not implemented yet (FIPS 205 §6.2 Algorithm 9)");
        }

        // -----------------------------------------------------------------
        // FIPS 205 §6.3 Algorithm 10 — xmss_pkFromSig(idx, sig, M, PK.seed, ADRS).
        //
        // Reconstructs the XMSS root from a candidate signature, by
        // verifying the WOTS+ part to get the leaf and then climbing the
        // h'-node auth path. The caller compares the returned root
        // against the expected XMSS root (stored in the parent layer or,
        // for the top layer, in PK.root).
        // -----------------------------------------------------------------
        pub fn pkFromSig(
            idx: u32,
            sig: *const [signature_bytes]u8,
            msg: *const [n]u8,
            pk_seed: *const [n]u8,
            adrs: *address.Adrs,
            out_root: *[n]u8,
        ) void {
            _ = idx;
            _ = sig;
            _ = msg;
            _ = pk_seed;
            _ = adrs;
            _ = out_root;
            @panic("TODO: xmss_pkFromSig not implemented yet (FIPS 205 §6.3 Algorithm 10)");
        }
    };
}

test "XMSS sizes for slh_dsa_sha2_128s" {
    const p = comptime params_mod.ParamSet.slh_dsa_sha2_128s.params();
    const X = Xmss(p);
    try std.testing.expectEqual(@as(usize, 9), X.h_prime);
    try std.testing.expectEqual(@as(usize, 1 << 9), X.tree_leaves);
    // WOTS+ sig (35 * 16 = 560 bytes) + auth path (9 * 16 = 144 bytes) = 704 bytes.
    try std.testing.expectEqual(@as(usize, 35 * 16 + 9 * 16), X.signature_bytes);
}

test "XMSS instantiates for all parameter sets" {
    inline for (std.enums.values(params_mod.ParamSet)) |ps| {
        const X = Xmss(ps.params());
        _ = X.signature_bytes;
    }
}
