//! FIPS 205 §7 — Hypertree (HT).
//!
//! A hypertree is a stack of `d` XMSS trees. The bottom-layer XMSS trees
//! sign messages (in SLH-DSA's case, FORS public keys); each non-bottom
//! XMSS tree signs the root of the XMSS tree at the layer below it. The
//! root of the topmost tree is the hypertree public key — which is what
//! SLH-DSA exposes as PK.root.
//!
//! The total tree height h = d · h' is the number of "leaf-layer" bits
//! consumed by an HT signature index. SLH-DSA derives that index from
//! the message digest (via H_msg + a few extra hash output bytes for
//! tree / leaf selection).
//!
//! Status: SKELETON.

const std = @import("std");
const params_mod = @import("params.zig");
const address = @import("address.zig");
const xmss_mod = @import("xmss.zig");

pub fn Hypertree(comptime p: params_mod.Params) type {
    return struct {
        pub const n: usize = p.n;
        pub const h: usize = p.h;
        pub const d: usize = p.d;
        pub const h_prime: usize = p.h_prime;

        const Xmss = xmss_mod.Xmss(p);

        /// Hypertree signature: d concatenated XMSS signatures.
        pub const signature_bytes: usize = d * Xmss.signature_bytes;

        // -----------------------------------------------------------------
        // FIPS 205 §7.1 Algorithm 11 — ht_sign(M, SK.seed, PK.seed, idx_tree, idx_leaf).
        //
        // Signs message M with the hypertree. The bottom-layer XMSS tree
        // is selected by `idx_tree`, and within it leaf `idx_leaf` is used.
        // Each layer above signs the root of the layer below.
        //
        // The index split is:
        //   - bottom-layer leaf: low h' bits of (idx_tree, idx_leaf)
        //   - bottom-layer tree: next (h - h') bits
        //   - layers 1..d-1: parent indices derived by shifting
        // -----------------------------------------------------------------
        pub fn sign(
            msg: *const [n]u8,
            sk_seed: *const [n]u8,
            pk_seed: *const [n]u8,
            idx_tree: u64,
            idx_leaf: u32,
            out_sig: *[signature_bytes]u8,
        ) void {
            _ = msg;
            _ = sk_seed;
            _ = pk_seed;
            _ = idx_tree;
            _ = idx_leaf;
            _ = out_sig;
            @panic("TODO: ht_sign not implemented yet (FIPS 205 §7.1 Algorithm 11)");
        }

        // -----------------------------------------------------------------
        // FIPS 205 §7.2 Algorithm 12 — ht_verify(M, sig, PK.seed, idx_tree, idx_leaf, PK.root).
        //
        // Verifies the hypertree signature by reconstructing roots layer
        // by layer using XMSS pkFromSig, and checking that the final root
        // equals PK.root.
        // -----------------------------------------------------------------
        pub fn verify(
            msg: *const [n]u8,
            sig: *const [signature_bytes]u8,
            pk_seed: *const [n]u8,
            idx_tree: u64,
            idx_leaf: u32,
            pk_root: *const [n]u8,
        ) bool {
            _ = msg;
            _ = sig;
            _ = pk_seed;
            _ = idx_tree;
            _ = idx_leaf;
            _ = pk_root;
            @panic("TODO: ht_verify not implemented yet (FIPS 205 §7.2 Algorithm 12)");
        }
    };
}

test "Hypertree sizes for slh_dsa_sha2_128s" {
    const p = comptime params_mod.ParamSet.slh_dsa_sha2_128s.params();
    const HT = Hypertree(p);
    try std.testing.expectEqual(@as(usize, 7), HT.d);
    try std.testing.expectEqual(@as(usize, 63), HT.h);
    // 7 XMSS sigs × 704 bytes = 4928 bytes.
    try std.testing.expectEqual(@as(usize, 7 * (35 * 16 + 9 * 16)), HT.signature_bytes);
}

test "Hypertree instantiates for all parameter sets" {
    inline for (std.enums.values(params_mod.ParamSet)) |ps| {
        const HT = Hypertree(ps.params());
        _ = HT.signature_bytes;
    }
}
