//! FIPS 205 §8 — FORS (Forest Of Random Subsets).
//!
//! FORS is the *few-time* signature scheme used at the bottom of SLH-DSA:
//! it is what actually signs the message digest. The hypertree signs the
//! FORS public key.
//!
//! Why few-time, not one-time? Because the bottom XMSS layer is reused
//! across signatures: the same hypertree leaf signs every FORS public
//! key whose `idx_tree` || `idx_leaf` lands on it. To avoid forgeries
//! from collisions among those signers, FORS gives statistical, not
//! perfect, unforgeability — calibrated so that the chance of catastrophe
//! over the lifetime of the keypair is negligible (≤ 2^-128 for L1 sets).
//!
//! Construction:
//!
//!   - `k` independent Merkle trees, each of height `a` (so 2^a leaves).
//!   - Together, the trees encode k indices into the message digest.
//!   - To sign, reveal one leaf from each tree: that's `k` leaves plus
//!     `k * a` authentication-path nodes.
//!   - To verify, reconstruct each tree root from the leaf + auth path,
//!     then hash all k roots together (via T_l with ADRS type FORS_ROOTS)
//!     to recover the FORS public key.
//!
//! Status: skGen, node, sign, and pkFromSig implemented.

const std = @import("std");
const params_mod = @import("params.zig");
const address = @import("address.zig");
const hash_mod = @import("hash.zig");
const util = @import("util.zig");

pub fn Fors(comptime p: params_mod.Params) type {
    return struct {
        pub const n: usize = p.n;
        pub const a: usize = p.a;
        pub const k: usize = p.k;
        pub const md_bytes: usize = (k * a + 7) / 8;

        const Hash = hash_mod.Hash(p);

        // `a` as the base-2^b width for base_2b, and 2^a as the per-tree leaf
        // count (each of the k FORS trees has height a, i.e. 2^a leaves).
        const a_bits: u6 = @intCast(a);
        const two_pow_a: u32 = @as(u32, 1) << a_bits;

        /// FORS signature: k revealed leaves plus k * a auth-path nodes,
        /// laid out as k blocks of (1 + a) × n bytes.
        pub const signature_bytes: usize = k * (a + 1) * n;

        // -----------------------------------------------------------------
        // FIPS 205 §8.1 Algorithm 14 — fors_skGen(SK.seed, PK.seed, ADRS, idx).
        //
        // Computes the FORS secret-key element at index `idx` via PRF
        // with ADRS type FORS_PRF.
        // -----------------------------------------------------------------
        pub fn skGen(
            sk_seed: *const [n]u8,
            pk_seed: *const [n]u8,
            adrs: *address.Adrs,
            idx: u32,
            out: *[n]u8,
        ) void {
            // skADRS: same layer/tree/keypair as ADRS, type FORS_PRF, with the
            // tree index set to the (global) leaf index. `out` receives a FORS
            // secret-key element — the caller scrubs it for internal leaves
            // (see node) or reveals it in the signature (see sign).
            var sk_adrs = adrs.*;
            sk_adrs.setType(.fors_prf);
            sk_adrs.setKeyPairAddress(adrs.getKeyPairAddress());
            sk_adrs.setTreeIndex(idx);
            Hash.prf(sk_seed, pk_seed, &sk_adrs, out);
        }

        // -----------------------------------------------------------------
        // FIPS 205 §8.2 Algorithm 15 — fors_node(SK.seed, i, z, PK.seed, ADRS).
        //
        // Recursive node-value computation for a FORS Merkle tree. Same
        // structure as xmss_node: base case (z = 0) is F(PK.seed, ADRS,
        // fors_skGen(...)), inductive case stacks two children with H.
        // -----------------------------------------------------------------
        pub fn node(
            sk_seed: *const [n]u8,
            i: u32,
            z: u32,
            pk_seed: *const [n]u8,
            adrs: *address.Adrs,
            out: *[n]u8,
        ) void {
            // Validity per FIPS 205 §8.2: z ≤ a and i < k·2^(a−z). Public
            // values, so branching on them is constant-time-safe.
            std.debug.assert(z <= p.a);
            std.debug.assert(@as(u64, i) < @as(u64, p.k) << @as(u6, @intCast(p.a - z)));

            if (z == 0) {
                // Base case: F over the secret leaf key. The key is scrubbed
                // before return; only its public image `out` survives.
                var sk: [n]u8 = undefined;
                defer std.crypto.secureZero(u8, &sk);
                skGen(sk_seed, pk_seed, adrs, i, &sk);
                adrs.setTreeHeight(0);
                adrs.setTreeIndex(i);
                Hash.f(pk_seed, adrs, &sk, out);
            } else {
                // Inductive case: stack two child nodes with H. Child values
                // are public — no secret residue to scrub.
                var lnode: [n]u8 = undefined;
                var rnode: [n]u8 = undefined;
                node(sk_seed, 2 * i, z - 1, pk_seed, adrs, &lnode);
                node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs, &rnode);
                adrs.setTreeHeight(z);
                adrs.setTreeIndex(i);
                Hash.h(pk_seed, adrs, &lnode, &rnode, out);
            }
        }

        // -----------------------------------------------------------------
        // FIPS 205 §8.3 Algorithm 16 — fors_sign(md, SK.seed, PK.seed, ADRS).
        //
        // Signs the message digest `md` (k * a bits, packed). Output is
        // `k` blocks of (revealed_leaf, auth_path_node_0, ..., auth_path_node_{a-1}),
        // each n bytes — `signature_bytes` total.
        // -----------------------------------------------------------------
        pub fn sign(
            md: *const [md_bytes]u8,
            sk_seed: *const [n]u8,
            pk_seed: *const [n]u8,
            adrs: *address.Adrs,
            out_sig: *[signature_bytes]u8,
        ) void {
            // Split the digest into k indices of a bits — one revealed leaf per
            // tree (FIPS 205 §8.3 Algorithm 16 line 2). The indices are public
            // after signing (recoverable from md), so branching on them below
            // is constant-time-safe.
            var indices: [k]u32 = undefined;
            util.base_2b(md, a_bits, &indices);

            // Per-tree block: revealed leaf secret (n bytes) then a auth nodes.
            const block = (a + 1) * n;
            for (0..k) |i| {
                const base = i * block;
                const tree: u32 = @intCast(i);
                const leaf = tree * two_pow_a + indices[i];

                // Reveal the leaf secret — it IS part of the signature (public
                // after signing), so it goes straight to the output buffer.
                skGen(sk_seed, pk_seed, adrs, leaf, out_sig[base..][0..n]);

                // Auth path: the sibling node at each height j of tree i.
                // As in xmss.sign, these a subtrees are pairwise disjoint, so
                // tree i costs 2^a - 1 leaf computations with none repeated —
                // an iterative treehash sweep would cost 2^a, one more.
                for (0..a) |j| {
                    const s = (indices[i] >> @as(u5, @intCast(j))) ^ 1;
                    const sib = tree * (two_pow_a >> @as(u5, @intCast(j))) + s;
                    node(sk_seed, sib, @intCast(j), pk_seed, adrs, out_sig[base + (1 + j) * n ..][0..n]);
                }
            }
        }

        // -----------------------------------------------------------------
        // FIPS 205 §8.4 Algorithm 17 — fors_pkFromSig(sig, md, PK.seed, ADRS).
        //
        // Reconstructs the FORS public key from a candidate signature
        // and the message digest. The caller passes this into the
        // hypertree verifier.
        // -----------------------------------------------------------------
        pub fn pkFromSig(
            sig: *const [signature_bytes]u8,
            md: *const [md_bytes]u8,
            pk_seed: *const [n]u8,
            adrs: *address.Adrs,
            out_pk: *[n]u8,
        ) void {
            var indices: [k]u32 = undefined;
            util.base_2b(md, a_bits, &indices);

            const block = (a + 1) * n;
            // Reconstructed roots of the k trees — public material.
            var roots: [k * n]u8 = undefined;
            for (0..k) |i| {
                const base = i * block;
                const tree: u32 = @intCast(i);
                const leaf = tree * two_pow_a + indices[i];

                // Leaf node: F over the revealed leaf secret from the signature
                // (FIPS 205 §8.4 Algorithm 17 lines 3–6).
                var nodev: [n]u8 = undefined;
                adrs.setTreeHeight(0);
                adrs.setTreeIndex(leaf);
                Hash.f(pk_seed, adrs, sig[base..][0..n], &nodev);

                // Climb the a-node auth path to the tree root (lines 8–17). The
                // low bit of indices[i] (shifted) picks the left/right order.
                for (0..a) |j| {
                    const auth = sig[base + (1 + j) * n ..][0..n];
                    adrs.setTreeHeight(@intCast(j + 1));
                    var parent: [n]u8 = undefined;
                    if ((indices[i] >> @as(u5, @intCast(j))) & 1 == 0) {
                        adrs.setTreeIndex(adrs.getTreeIndex() >> 1);
                        Hash.h(pk_seed, adrs, &nodev, auth, &parent);
                    } else {
                        adrs.setTreeIndex((adrs.getTreeIndex() - 1) >> 1);
                        Hash.h(pk_seed, adrs, auth, &nodev, &parent);
                    }
                    nodev = parent;
                }
                roots[i * n ..][0..n].* = nodev;
            }

            // FORS public key = T_k over the k roots under a FORS_ROOTS address
            // (lines 19–22). All inputs here are public.
            var pk_adrs = adrs.*;
            pk_adrs.setType(.fors_roots);
            pk_adrs.setKeyPairAddress(adrs.getKeyPairAddress());
            Hash.t_l(pk_seed, &pk_adrs, &roots, out_pk);
        }
    };
}

test "FORS sizes for slh_dsa_sha2_128s" {
    const p = comptime params_mod.ParamSet.slh_dsa_sha2_128s.params();
    const F = Fors(p);
    try std.testing.expectEqual(@as(usize, 12), F.a);
    try std.testing.expectEqual(@as(usize, 14), F.k);
    // md = ceil(k * a / 8) = ceil(168 / 8) = 21 bytes.
    try std.testing.expectEqual(@as(usize, 21), F.md_bytes);
    // sig = k * (a + 1) * n = 14 * 13 * 16 = 2912 bytes.
    try std.testing.expectEqual(@as(usize, 14 * 13 * 16), F.signature_bytes);
}

test "FORS instantiates for all parameter sets" {
    inline for (std.enums.values(params_mod.ParamSet)) |ps| {
        const F = Fors(ps.params());
        _ = F.signature_bytes;
    }
}

test "fors_node: leaf = F(skGen), parent = H(children)" {
    // FIPS 205 §8.2 Algorithm 15, checked by hand at z = 1 and independent of
    // sign/pkFromSig: node(0,1) must equal H over node(0,0) and node(1,0)
    // under a FORS_TREE address at height 1, index 0. Validates the leaf-F /
    // skGen base case and the internal-H address logic on their own.
    inline for (.{ params_mod.ParamSet.slh_dsa_shake_128f, params_mod.ParamSet.slh_dsa_sha2_128f }) |ps| {
        const p = comptime ps.params();
        const F = Fors(p);
        const H = hash_mod.Hash(p);
        const sk_seed = [_]u8{0x5A} ** F.n;
        const pk_seed = [_]u8{0xA5} ** F.n;
        const kp: u32 = 3;

        var adrs = address.Adrs.init();
        adrs.setType(.fors_tree);
        adrs.setKeyPairAddress(kp);
        var parent: [F.n]u8 = undefined;
        F.node(&sk_seed, 0, 1, &pk_seed, &adrs, &parent);

        var adrs0 = address.Adrs.init();
        adrs0.setType(.fors_tree);
        adrs0.setKeyPairAddress(kp);
        var leaf0: [F.n]u8 = undefined;
        F.node(&sk_seed, 0, 0, &pk_seed, &adrs0, &leaf0);

        var adrs1 = address.Adrs.init();
        adrs1.setType(.fors_tree);
        adrs1.setKeyPairAddress(kp);
        var leaf1: [F.n]u8 = undefined;
        F.node(&sk_seed, 1, 0, &pk_seed, &adrs1, &leaf1);

        var adrs_h = address.Adrs.init();
        adrs_h.setType(.fors_tree);
        adrs_h.setKeyPairAddress(kp);
        adrs_h.setTreeHeight(1);
        adrs_h.setTreeIndex(0);
        var expected: [F.n]u8 = undefined;
        H.h(&pk_seed, &adrs_h, &leaf0, &leaf1, &expected);

        try std.testing.expectEqualSlices(u8, &expected, &parent);
    }
}

test "fors_pkFromSig(fors_sign(md), md) reproduces the FORS public key; tampering fails" {
    // FIPS 205 §8.3/§8.4: signing then reconstructing recovers the FORS public
    // key computed independently from the k tree roots — node(t, a) for each
    // tree, compressed with T_k. pkFromSig rebuilds each root from the revealed
    // leaf + auth path via F/H (a different code path than the full-tree node
    // build), so agreement cross-checks both. Property-tested (no ACVP vectors
    // at this layer) over both hash families on f-variants, with a negative.
    inline for (.{ params_mod.ParamSet.slh_dsa_shake_128f, params_mod.ParamSet.slh_dsa_sha2_128f }) |ps| {
        const p = comptime ps.params();
        const F = Fors(p);
        const H = hash_mod.Hash(p);
        const n = F.n;

        var sk_seed: [n]u8 = undefined;
        var pk_seed: [n]u8 = undefined;
        var md: [F.md_bytes]u8 = undefined;
        for (&sk_seed, 0..) |*b, i| b.* = @intCast(0x13 + i);
        for (&pk_seed, 0..) |*b, i| b.* = @intCast(0x71 + i);
        for (&md, 0..) |*b, i| b.* = @intCast(0xC5 ^ i);
        const kp: u32 = 2;

        // Independent oracle: each tree root via node(t, a), then T_k.
        var roots: [F.k * n]u8 = undefined;
        for (0..F.k) |t| {
            var adrs_t = address.Adrs.init();
            adrs_t.setType(.fors_tree);
            adrs_t.setKeyPairAddress(kp);
            F.node(&sk_seed, @intCast(t), @intCast(F.a), &pk_seed, &adrs_t, roots[t * n ..][0..n]);
        }
        var pk_adrs = address.Adrs.init();
        pk_adrs.setType(.fors_roots);
        pk_adrs.setKeyPairAddress(kp);
        var pk_expected: [n]u8 = undefined;
        H.t_l(&pk_seed, &pk_adrs, &roots, &pk_expected);

        // Sign the digest, then reconstruct the public key from the signature.
        var adrs_sign = address.Adrs.init();
        adrs_sign.setType(.fors_tree);
        adrs_sign.setKeyPairAddress(kp);
        var sig: [F.signature_bytes]u8 = undefined;
        F.sign(&md, &sk_seed, &pk_seed, &adrs_sign, &sig);

        var adrs_ver = address.Adrs.init();
        adrs_ver.setType(.fors_tree);
        adrs_ver.setKeyPairAddress(kp);
        var pk_from_sig: [n]u8 = undefined;
        F.pkFromSig(&sig, &md, &pk_seed, &adrs_ver, &pk_from_sig);
        try std.testing.expectEqualSlices(u8, &pk_expected, &pk_from_sig);

        // Negative control: a different digest reconstructs a different key.
        var md2 = md;
        md2[0] ^= 0xFF;
        var adrs_ver2 = address.Adrs.init();
        adrs_ver2.setType(.fors_tree);
        adrs_ver2.setKeyPairAddress(kp);
        var pk_from_sig2: [n]u8 = undefined;
        F.pkFromSig(&sig, &md2, &pk_seed, &adrs_ver2, &pk_from_sig2);
        try std.testing.expect(!std.mem.eql(u8, &pk_expected, &pk_from_sig2));
    }
}
