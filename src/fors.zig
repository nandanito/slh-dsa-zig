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
//! Status: SKELETON.

const std = @import("std");
const params_mod = @import("params.zig");
const address = @import("address.zig");
const hash_mod = @import("hash.zig");

pub fn Fors(comptime p: params_mod.Params) type {
    return struct {
        pub const n: usize = p.n;
        pub const a: usize = p.a;
        pub const k: usize = p.k;
        pub const md_bytes: usize = (k * a + 7) / 8;

        const Hash = hash_mod.Hash(p);

        /// FORS signature: k revealed leaves plus k * a auth-path nodes,
        /// laid out as k blocks of (1 + a) × n bytes.
        pub const signature_bytes: usize = k * (a + 1) * n;

        // -----------------------------------------------------------------
        // FIPS 205 §8.1 Algorithm 13 — fors_skGen(SK.seed, PK.seed, ADRS, idx).
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
            _ = sk_seed;
            _ = pk_seed;
            _ = adrs;
            _ = idx;
            _ = out;
            @panic("TODO: fors_skGen not implemented yet (FIPS 205 §8.1 Algorithm 13)");
        }

        // -----------------------------------------------------------------
        // FIPS 205 §8.2 Algorithm 14 — fors_node(SK.seed, i, z, PK.seed, ADRS).
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
            _ = sk_seed;
            _ = i;
            _ = z;
            _ = pk_seed;
            _ = adrs;
            _ = out;
            @panic("TODO: fors_node not implemented yet (FIPS 205 §8.2 Algorithm 14)");
        }

        // -----------------------------------------------------------------
        // FIPS 205 §8.3 Algorithm 15 — fors_sign(md, SK.seed, PK.seed, ADRS).
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
            _ = md;
            _ = sk_seed;
            _ = pk_seed;
            _ = adrs;
            _ = out_sig;
            @panic("TODO: fors_sign not implemented yet (FIPS 205 §8.3 Algorithm 15)");
        }

        // -----------------------------------------------------------------
        // FIPS 205 §8.4 Algorithm 16 — fors_pkFromSig(sig, md, PK.seed, ADRS).
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
            _ = sig;
            _ = md;
            _ = pk_seed;
            _ = adrs;
            _ = out_pk;
            @panic("TODO: fors_pkFromSig not implemented yet (FIPS 205 §8.4 Algorithm 16)");
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
