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
//! Status: node implemented (keygen path); sign + pkFromSig are stubs.

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
        // NOTE: This is the recursive formulation as written in the
        // standard. Recursion depth is bounded by h' (≤ 9 across all
        // parameter sets), i.e. ~2n bytes of locals per frame — fine for
        // stack use. An iterative treehash (as used by the SPHINCS+
        // reference implementation) is a possible later optimisation.
        // -----------------------------------------------------------------
        pub fn node(
            sk_seed: *const [n]u8,
            i: u32,
            z: u32,
            pk_seed: *const [n]u8,
            adrs: *address.Adrs,
            out: *[n]u8,
        ) void {
            // Validity per FIPS 205 §6.1: z ≤ h' and i < 2^(h'-z). Both are
            // public values, so branching on them is CT-safe.
            std.debug.assert(z <= p.h_prime);
            std.debug.assert(i < @as(u32, 1) << @as(u5, @intCast(p.h_prime - z)));

            if (z == 0) {
                adrs.setType(.wots_hash);
                adrs.setKeyPairAddress(i);
                Wots.pkGen(sk_seed, pk_seed, adrs, out);
            } else {
                // All tree nodes hash public WOTS+ public keys — no secret
                // residue to scrub in lnode/rnode.
                var lnode: [n]u8 = undefined;
                var rnode: [n]u8 = undefined;
                node(sk_seed, 2 * i, z - 1, pk_seed, adrs, &lnode);
                node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs, &rnode);
                adrs.setType(.tree);
                adrs.setTreeHeight(z);
                adrs.setTreeIndex(i);
                Hash.h(pk_seed, adrs, &lnode, &rnode, out);
            }
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

test "node: deterministic and equals H over its two children" {
    // FIPS 205 §6.1 Algorithm 8 inductive case, checked by hand at z = 1:
    // node(i=0, z=1) must equal H(PK.seed, TREE-adrs(z=1, i=0), leaf_0, leaf_1).
    inline for (.{ params_mod.ParamSet.slh_dsa_shake_128f, params_mod.ParamSet.slh_dsa_sha2_128f }) |ps| {
        const p = comptime ps.params();
        const X = Xmss(p);
        const H = hash_mod.Hash(p);
        const sk_seed = [_]u8{0x5A} ** X.n;
        const pk_seed = [_]u8{0xA5} ** X.n;

        var adrs = address.Adrs.init();
        var parent: [X.n]u8 = undefined;
        X.node(&sk_seed, 0, 1, &pk_seed, &adrs, &parent);

        var adrs_l = address.Adrs.init();
        var leaf_0: [X.n]u8 = undefined;
        X.node(&sk_seed, 0, 0, &pk_seed, &adrs_l, &leaf_0);

        var adrs_r = address.Adrs.init();
        var leaf_1: [X.n]u8 = undefined;
        X.node(&sk_seed, 1, 0, &pk_seed, &adrs_r, &leaf_1);

        var adrs_h = address.Adrs.init();
        adrs_h.setType(.tree);
        adrs_h.setTreeHeight(1);
        adrs_h.setTreeIndex(0);
        var expected: [X.n]u8 = undefined;
        H.h(&pk_seed, &adrs_h, &leaf_0, &leaf_1, &expected);

        try std.testing.expectEqualSlices(u8, &expected, &parent);
    }
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
