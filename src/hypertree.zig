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
//! Status: ht_sign and ht_verify implemented.

const std = @import("std");
const params_mod = @import("params.zig");
const address = @import("address.zig");
const xmss_mod = @import("xmss.zig");
const ct = @import("ct.zig");

pub fn Hypertree(comptime p: params_mod.Params) type {
    return struct {
        pub const n: usize = p.n;
        pub const h: usize = p.h;
        pub const d: usize = p.d;
        pub const h_prime: usize = p.h_prime;

        const Xmss = xmss_mod.Xmss(p);

        /// Hypertree signature: d concatenated XMSS signatures.
        pub const signature_bytes: usize = d * Xmss.signature_bytes;

        // Per-layer index arithmetic (FIPS 205 §7.1): each layer up consumes
        // the low h' bits of idx_tree to pick that layer's leaf, then shifts
        // them off. These are public tree-position values, not secrets.
        const h_prime_shift: u6 = @intCast(p.h_prime);
        const leaf_mask: u64 = (@as(u64, 1) << h_prime_shift) - 1;

        // -----------------------------------------------------------------
        // FIPS 205 §7.1 Algorithm 12 — ht_sign(M, SK.seed, PK.seed, idx_tree, idx_leaf).
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
            // Bottom layer (layer 0, tree = idx_tree): sign M with the given
            // leaf, then recover the XMSS root the next layer up will sign.
            var adrs = address.Adrs.init();
            adrs.setTreeAddress(idx_tree);

            const bottom = out_sig[0..Xmss.signature_bytes];
            Xmss.sign(msg, sk_seed, idx_leaf, pk_seed, &adrs, bottom);

            var root: [n]u8 = undefined;
            Xmss.pkFromSig(idx_leaf, bottom, msg, pk_seed, &adrs, &root);
            // Every XMSS root threaded up the hypertree is public: ht_verify
            // reconstructs this exact value from the published signature
            // (§7.2 Algorithm 13). It is also the message the next layer's
            // WOTS+ signs, and its base-w digits set that layer's chain
            // lengths — so a CT audit that has not been told it is public
            // reports a false secret-dependent branch. See ct.zig.
            ct.declassify(&root);

            // Layers 1..d-1: each signs the root of the layer below. The leaf
            // within a layer is the low h' bits of idx_tree; the remaining
            // high bits select the tree at that layer.
            var tree = idx_tree;
            var j: usize = 1;
            while (j < d) : (j += 1) {
                const leaf: u32 = @intCast(tree & leaf_mask);
                tree >>= h_prime_shift;
                adrs.setLayer(@intCast(j));
                adrs.setTreeAddress(tree);

                const layer = out_sig[j * Xmss.signature_bytes ..][0..Xmss.signature_bytes];
                Xmss.sign(&root, sk_seed, leaf, pk_seed, &adrs, layer);

                // Thread the root upward; the top layer has no parent to sign.
                if (j < d - 1) {
                    var next_root: [n]u8 = undefined;
                    Xmss.pkFromSig(leaf, layer, &root, pk_seed, &adrs, &next_root);
                    ct.declassify(&next_root); // public, as above
                    root = next_root;
                }
            }
        }

        // -----------------------------------------------------------------
        // FIPS 205 §7.2 Algorithm 13 — ht_verify(M, sig, PK.seed, idx_tree, idx_leaf, PK.root).
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
            // Reconstruct the bottom-layer XMSS root from its signature.
            var adrs = address.Adrs.init();
            adrs.setTreeAddress(idx_tree);

            var node: [n]u8 = undefined;
            Xmss.pkFromSig(idx_leaf, sig[0..Xmss.signature_bytes], msg, pk_seed, &adrs, &node);

            // Climb the layers, each reconstructing the root above from the
            // one below, until the top tree yields the candidate PK.root.
            var tree = idx_tree;
            var j: usize = 1;
            while (j < d) : (j += 1) {
                const leaf: u32 = @intCast(tree & leaf_mask);
                tree >>= h_prime_shift;
                adrs.setLayer(@intCast(j));
                adrs.setTreeAddress(tree);

                const layer = sig[j * Xmss.signature_bytes ..][0..Xmss.signature_bytes];
                var next: [n]u8 = undefined;
                Xmss.pkFromSig(leaf, layer, &node, pk_seed, &adrs, &next);
                node = next;
            }

            // Verification has no secret inputs — sig, the reconstructed node,
            // and PK.root are all public — so a plain comparison is fine.
            return std.mem.eql(u8, &node, pk_root);
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

test "ht_verify(ht_sign(M)) succeeds against keygen PK.root; tampering fails" {
    // FIPS 205 §7.1/§7.2: a hypertree signature reconstructs to PK.root — the
    // top-tree root produced by the ACVP-validated key generation path. The
    // top layer always lands on tree address 0, whose root is PK.root, so the
    // two must agree. Property-tested (no ACVP vectors at this layer) across
    // both hash families on f-variants, paired with negative controls.
    const slh = @import("slh_dsa.zig");
    inline for (.{
        params_mod.ParamSet.slh_dsa_shake_128f,
        params_mod.ParamSet.slh_dsa_sha2_128f,
    }) |ps| {
        const p = comptime ps.params();
        const HT = Hypertree(p);
        const S = slh.Slh_Dsa(ps);
        const n = HT.n;

        var sk_seed: [n]u8 = undefined;
        var sk_prf: [n]u8 = undefined;
        var pk_seed: [n]u8 = undefined;
        for (&sk_seed, 0..) |*b, i| b.* = @intCast(0x31 + i);
        for (&sk_prf, 0..) |*b, i| b.* = @intCast(0x62 + i);
        for (&pk_seed, 0..) |*b, i| b.* = @intCast(0x9D + i);

        // PK.root from the key generation path (PK = PK.seed || PK.root).
        const kp = try S.KeyPair.fromSeeds(&sk_seed, &sk_prf, &pk_seed);
        const pk_root = kp.public_key[n..][0..n];

        var msg: [n]u8 = undefined;
        for (&msg, 0..) |*b, i| b.* = @intCast(0x4E ^ i);

        // Valid signatures over the all-zero and all-ones index paths.
        const max_tree: u64 = (@as(u64, 1) << @intCast(p.h - p.h_prime)) - 1;
        const max_leaf: u32 = (@as(u32, 1) << @intCast(p.h_prime)) - 1;
        const cases = [_]struct { t: u64, l: u32 }{
            .{ .t = 0, .l = 0 },
            .{ .t = max_tree, .l = max_leaf },
        };
        for (cases) |c| {
            var sig: [HT.signature_bytes]u8 = undefined;
            HT.sign(&msg, &sk_seed, &pk_seed, c.t, c.l, &sig);
            try std.testing.expect(HT.verify(&msg, &sig, &pk_seed, c.t, c.l, pk_root));
        }

        // Negative controls, reusing a valid (0, 0) signature.
        var sig: [HT.signature_bytes]u8 = undefined;
        HT.sign(&msg, &sk_seed, &pk_seed, 0, 0, &sig);
        try std.testing.expect(HT.verify(&msg, &sig, &pk_seed, 0, 0, pk_root));

        var bad_sig = sig;
        bad_sig[0] ^= 0x01;
        try std.testing.expect(!HT.verify(&msg, &bad_sig, &pk_seed, 0, 0, pk_root));

        var bad_msg = msg;
        bad_msg[0] ^= 0xFF;
        try std.testing.expect(!HT.verify(&bad_msg, &sig, &pk_seed, 0, 0, pk_root));

        var bad_root = pk_root.*;
        bad_root[0] ^= 0xFF;
        try std.testing.expect(!HT.verify(&msg, &sig, &pk_seed, 0, 0, &bad_root));

        // A wrong leaf index reconstructs a different root.
        try std.testing.expect(!HT.verify(&msg, &sig, &pk_seed, 0, 1, pk_root));
    }
}
