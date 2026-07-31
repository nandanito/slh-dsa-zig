//! FIPS 205 §9, §10.3 — Top-level SLH-DSA scheme.
//!
//! `Slh_Dsa(param_set)` returns a namespace exposing the public surface
//! that callers actually use: key generation, signing, and verification.
//! It drives the FORS, hypertree, and hash layers; the details of each
//! live in their own modules.
//!
//! Status: key generation, signing, and verification are implemented (pure
//! SLH-DSA with context strings, FIPS 205 §9–§10.3). The HashSLH-DSA pre-hash
//! variants are deferred by decision (issue #8 / ARCHITECTURE.md).
//!
//! API shape:
//!
//!   const Scheme = slh_dsa.Slh_Dsa(.slh_dsa_shake_128s);
//!
//!   const kp = try Scheme.KeyPair.generate(io);
//!   try Scheme.sign(&sig, message, &kp.secret_key, opt_rand);
//!   try Scheme.verify(&sig, message, &kp.public_key);
//!
//! The `io` parameter is a `std.Io` providing access to a CSPRNG; this is
//! the Zig 0.16 idiom that `std.crypto.nacl` and friends already use.

const std = @import("std");
const params_mod = @import("params.zig");
const address = @import("address.zig");
const hash_mod = @import("hash.zig");
const wots_mod = @import("wots.zig");
const xmss_mod = @import("xmss.zig");
const hypertree_mod = @import("hypertree.zig");
const fors_mod = @import("fors.zig");
const util = @import("util.zig");
const ct = @import("ct.zig");

pub const ParamSet = params_mod.ParamSet;

/// SLH-DSA error set.
pub const Error = error{
    /// The signature did not verify against the message and public key.
    InvalidSignature,
    /// Input data was the wrong length or otherwise malformed.
    InvalidInput,
    /// Caller-side I/O error (RNG exhausted, etc.). Specific causes are
    /// surfaced by the underlying `std.Io`.
    IoError,
    /// The context string exceeded 255 bytes (FIPS 205 §10.2). Uses the
    /// canonical `std.crypto` error name (`std.crypto.errors.ContextTooLongError`).
    ContextTooLong,
};

/// Build the SLH-DSA namespace for a parameter set.
pub fn Slh_Dsa(comptime param_set: ParamSet) type {
    const p = param_set.params();

    return struct {
        pub const params = p;

        pub const public_key_length: usize = p.pk_bytes;
        pub const secret_key_length: usize = p.sk_bytes;
        pub const signature_length: usize = p.sig_bytes;

        /// SLH-DSA public key: PK.seed || PK.root.
        pub const PublicKey = [public_key_length]u8;

        /// SLH-DSA secret key: SK.seed || SK.prf || PK.seed || PK.root.
        pub const SecretKey = [secret_key_length]u8;

        /// SLH-DSA signature: R || FORS_SIG || HT_SIG.
        pub const Signature = [signature_length]u8;

        const Hash = hash_mod.Hash(p);
        const Fors = fors_mod.Fors(p);
        const Hypertree = hypertree_mod.Hypertree(p);

        // Digest parsing (FIPS 205 §9.2): the `m`-byte H_msg output splits into
        // the FORS message digest, then the hypertree tree- and leaf-index
        // fields. All of these lengths and index bit-widths are public.
        const md_bytes = Fors.md_bytes; // ceil(k*a/8)
        const tree_bytes = (p.h - p.h_prime + 7) / 8; // ceil((h-h')/8)
        const leaf_bytes = (p.h_prime + 7) / 8; // ceil(h'/8)
        const tree_bits = p.h - p.h_prime;
        const leaf_bits = p.h_prime;
        const tree_mask: u64 = if (tree_bits >= 64) std.math.maxInt(u64) else (@as(u64, 1) << @intCast(tree_bits)) - 1;
        const leaf_mask: u64 = (@as(u64, 1) << @intCast(leaf_bits)) - 1;

        comptime {
            if (md_bytes + tree_bytes + leaf_bytes != p.m)
                @compileError("params: m != md_bytes + tree_bytes + leaf_bytes");
        }

        // -----------------------------------------------------------------
        // FIPS 205 §9.1 Algorithm 18 — slh_keygen_internal(SK.seed, SK.prf, PK.seed).
        // FIPS 205 §10.1 wraps this with random-bit sampling.
        //
        // For deterministic testing, callers can use `KeyPair.fromSeeds`;
        // for normal use, `KeyPair.generate` draws three n-byte values
        // from `io`'s CSPRNG.
        // -----------------------------------------------------------------
        pub const KeyPair = struct {
            public_key: PublicKey,
            secret_key: SecretKey,

            /// Generate a fresh keypair from `io`'s CSPRNG.
            ///
            /// FIPS 205 §10.1 — slh_keygen: draw SK.seed, SK.prf, PK.seed
            /// from an approved RBG, then derive via Algorithm 18.
            ///
            /// Uses `Io.randomSecure` (fresh OS entropy, no fallback), not
            /// `Io.random`: the latter silently degrades to a best-effort
            /// process-state seed when OS entropy is unavailable, which
            /// would violate the approved-RBG requirement for key material.
            /// Entropy failure surfaces as `error.IoError`.
            pub fn generate(io: std.Io) Error!KeyPair {
                var sk_seed: [p.n]u8 = undefined;
                var sk_prf: [p.n]u8 = undefined;
                var pk_seed: [p.n]u8 = undefined;
                // Local seed copies are secret; scrub before return. The
                // caller-owned KeyPair retains them by design.
                defer std.crypto.secureZero(u8, &sk_seed);
                defer std.crypto.secureZero(u8, &sk_prf);
                io.randomSecure(&sk_seed) catch return Error.IoError;
                io.randomSecure(&sk_prf) catch return Error.IoError;
                io.randomSecure(&pk_seed) catch return Error.IoError;
                return fromSeeds(&sk_seed, &sk_prf, &pk_seed);
            }

            /// Deterministically derive a keypair from explicit seed values.
            /// Used by KAT vectors and by callers who manage their own
            /// entropy.
            ///
            /// FIPS 205 §9.1 Algorithm 18 — slh_keygen_internal:
            /// PK.root is the root of the top-layer XMSS tree (layer d-1,
            /// tree address 0), computed via xmss_node(SK.seed, 0, h', ...).
            pub fn fromSeeds(
                sk_seed: *const [p.n]u8,
                sk_prf: *const [p.n]u8,
                pk_seed: *const [p.n]u8,
            ) Error!KeyPair {
                const XmssTop = xmss_mod.Xmss(p);

                var adrs = address.Adrs.init();
                adrs.setLayer(@intCast(p.d - 1));

                var pk_root: [p.n]u8 = undefined;
                XmssTop.node(sk_seed, 0, p.h_prime, pk_seed, &adrs, &pk_root);

                // SK = SK.seed || SK.prf || PK.seed || PK.root (§9.1).
                var kp: KeyPair = undefined;
                @memcpy(kp.secret_key[0..p.n], sk_seed);
                @memcpy(kp.secret_key[p.n .. 2 * p.n], sk_prf);
                @memcpy(kp.secret_key[2 * p.n .. 3 * p.n], pk_seed);
                @memcpy(kp.secret_key[3 * p.n ..], &pk_root);
                // PK = PK.seed || PK.root.
                @memcpy(kp.public_key[0..p.n], pk_seed);
                @memcpy(kp.public_key[p.n..], &pk_root);
                return kp;
            }
        };

        // -----------------------------------------------------------------
        // FIPS 205 §9.2 Algorithm 19 — slh_sign_internal(M, SK, opt_rand).
        //
        // The engine shared by the internal- and external-interface signers.
        // `msg_parts` is the message as an ordered sequence of byte slices
        // (M for the internal interface; the §10.2 domain-separation prefix,
        // ctx, then M for the external one), absorbed by PRF_msg / H_msg
        // without copying an arbitrary-length message.
        //
        // `opt_rand` supplies the per-signature randomiser; `null` falls back
        // to PK.seed (deterministic signing). SK.seed / SK.prf are secret;
        // PRF_msg scrubs its own state and no other secret buffer is used here.
        // -----------------------------------------------------------------
        fn signCore(
            out_sig: *Signature,
            msg_parts: []const []const u8,
            sk: *const SecretKey,
            opt_rand: ?*const [p.n]u8,
        ) void {
            const sk_seed = sk[0..p.n];
            const sk_prf = sk[p.n .. 2 * p.n];
            const pk_seed = sk[2 * p.n .. 3 * p.n];
            const pk_root = sk[3 * p.n .. 4 * p.n];

            // R = PRF_msg(SK.prf, opt_rand ?? PK.seed, M') — the first n sig bytes.
            const randomizer = opt_rand orelse pk_seed;
            const r = out_sig[0..p.n];
            Hash.prf_msg(sk_prf, randomizer, msg_parts, r);
            // R is keyed by the secret SK.prf but is published verbatim as the
            // first n signature bytes (§9.2 Algorithm 19), so it is public from
            // the moment it is written — and the digest below, which it seeds,
            // is public with it. Declassify for CT audits; compiles away
            // otherwise (see ct.zig).
            ct.declassify(r);

            // digest = H_msg(R, PK.seed, PK.root, M'); parse the tree/leaf indices.
            var digest: [p.m]u8 = undefined;
            Hash.h_msg(r, pk_seed, pk_root, msg_parts, &digest);
            const md = digest[0..md_bytes];
            const idx_tree = util.toInt(digest[md_bytes..][0..tree_bytes]) & tree_mask;
            const idx_leaf: u32 = @intCast(util.toInt(digest[md_bytes + tree_bytes ..][0..leaf_bytes]) & leaf_mask);

            // FORS signs the message digest; recover its public key for the HT.
            var adrs = address.Adrs.init();
            adrs.setTreeAddress(idx_tree);
            adrs.setType(.fors_tree);
            adrs.setKeyPairAddress(idx_leaf);
            const fors_sig = out_sig[p.n..][0..Fors.signature_bytes];
            Fors.sign(md, sk_seed, pk_seed, &adrs, fors_sig);

            var pk_fors: [p.n]u8 = undefined;
            var adrs_pk = address.Adrs.init();
            adrs_pk.setTreeAddress(idx_tree);
            adrs_pk.setType(.fors_tree);
            adrs_pk.setKeyPairAddress(idx_leaf);
            Fors.pkFromSig(fors_sig, md, pk_seed, &adrs_pk, &pk_fors);
            // PK_FORS descends from SK.seed, but it is exactly what the
            // verifier recomputes from the signature and the digest (§9.3
            // Algorithm 20 — see `verifyCore` below), so it is public. The
            // hypertree's WOTS+ digits are derived from it and gate `chain`'s
            // loop bound, so a CT audit must classify it correctly.
            ct.declassify(&pk_fors);

            // The hypertree signs the FORS public key.
            const ht_sig = out_sig[p.n + Fors.signature_bytes ..][0..Hypertree.signature_bytes];
            Hypertree.sign(&pk_fors, sk_seed, pk_seed, idx_tree, idx_leaf, ht_sig);
        }

        // -----------------------------------------------------------------
        // FIPS 205 §9.2 Algorithm 19 — slh_sign_internal (internal interface).
        //
        // Signs M directly, with no context-string domain separation. Exposed
        // for the ACVP internal-interface test mode; most callers want `sign`.
        // -----------------------------------------------------------------
        pub fn signInternal(
            out_sig: *Signature,
            msg: []const u8,
            sk: *const SecretKey,
            opt_rand: ?*const [p.n]u8,
        ) void {
            signCore(out_sig, &[_][]const u8{msg}, sk, opt_rand);
        }

        // -----------------------------------------------------------------
        // FIPS 205 §10.2 Algorithm 22 — slh_sign (external interface).
        //
        // Prepends the domain separator and context string
        // (M' = toByte(0,1) ‖ toByte(|ctx|,1) ‖ ctx ‖ M), then signs. `ctx`
        // may be up to 255 bytes; longer returns error.ContextTooLong.
        // -----------------------------------------------------------------
        pub fn signWithContext(
            out_sig: *Signature,
            msg: []const u8,
            ctx: []const u8,
            sk: *const SecretKey,
            opt_rand: ?*const [p.n]u8,
        ) Error!void {
            if (ctx.len > 255) return Error.ContextTooLong;
            const prefix = [2]u8{ 0x00, @intCast(ctx.len) };
            signCore(out_sig, &[_][]const u8{ &prefix, ctx, msg }, sk, opt_rand);
        }

        // -----------------------------------------------------------------
        // Convenience signer: pure SLH-DSA with an empty context.
        //
        // `opt_rand` = a `params.n`-byte buffer for randomised signing
        // (recommended), or `null` for deterministic signing (FIPS 205 §9.2).
        // -----------------------------------------------------------------
        pub fn sign(
            out_sig: *Signature,
            msg: []const u8,
            sk: *const SecretKey,
            opt_rand: ?*const [p.n]u8,
        ) Error!void {
            return signWithContext(out_sig, msg, "", sk, opt_rand);
        }

        // -----------------------------------------------------------------
        // FIPS 205 §9.3 Algorithm 20 — slh_verify_internal(M, sig, PK).
        //
        // The engine shared by the internal- and external-interface verifiers.
        // Reconstructs the FORS public key from the signature and the parsed
        // digest, then checks the hypertree signature against PK.root. Returns
        // error.InvalidSignature on any mismatch. No secret inputs.
        // -----------------------------------------------------------------
        fn verifyCore(
            sig: *const Signature,
            msg_parts: []const []const u8,
            pk: *const PublicKey,
        ) Error!void {
            const pk_seed = pk[0..p.n];
            const pk_root = pk[p.n .. 2 * p.n];

            const r = sig[0..p.n];
            const fors_sig = sig[p.n..][0..Fors.signature_bytes];
            const ht_sig = sig[p.n + Fors.signature_bytes ..][0..Hypertree.signature_bytes];

            var digest: [p.m]u8 = undefined;
            Hash.h_msg(r, pk_seed, pk_root, msg_parts, &digest);
            const md = digest[0..md_bytes];
            const idx_tree = util.toInt(digest[md_bytes..][0..tree_bytes]) & tree_mask;
            const idx_leaf: u32 = @intCast(util.toInt(digest[md_bytes + tree_bytes ..][0..leaf_bytes]) & leaf_mask);

            var adrs = address.Adrs.init();
            adrs.setTreeAddress(idx_tree);
            adrs.setType(.fors_tree);
            adrs.setKeyPairAddress(idx_leaf);
            var pk_fors: [p.n]u8 = undefined;
            Fors.pkFromSig(fors_sig, md, pk_seed, &adrs, &pk_fors);

            if (!Hypertree.verify(&pk_fors, ht_sig, pk_seed, idx_tree, idx_leaf, pk_root)) {
                return Error.InvalidSignature;
            }
        }

        // -----------------------------------------------------------------
        // FIPS 205 §9.3 Algorithm 20 — slh_verify_internal (internal interface).
        //
        // Verifies M directly, with no context-string domain separation.
        // Exposed for the ACVP internal-interface test mode.
        // -----------------------------------------------------------------
        pub fn verifyInternal(
            sig: *const Signature,
            msg: []const u8,
            pk: *const PublicKey,
        ) Error!void {
            return verifyCore(sig, &[_][]const u8{msg}, pk);
        }

        // -----------------------------------------------------------------
        // FIPS 205 §10.3 Algorithm 24 — slh_verify (external interface).
        //
        // Rebuilds M' = toByte(0,1) ‖ toByte(|ctx|,1) ‖ ctx ‖ M and verifies.
        // `ctx` > 255 bytes returns error.ContextTooLong (no signature could
        // have been produced under such a context).
        // -----------------------------------------------------------------
        pub fn verifyWithContext(
            sig: *const Signature,
            msg: []const u8,
            ctx: []const u8,
            pk: *const PublicKey,
        ) Error!void {
            if (ctx.len > 255) return Error.ContextTooLong;
            const prefix = [2]u8{ 0x00, @intCast(ctx.len) };
            return verifyCore(sig, &[_][]const u8{ &prefix, ctx, msg }, pk);
        }

        // -----------------------------------------------------------------
        // Convenience verifier: pure SLH-DSA with an empty context.
        // Returns error.InvalidSignature on failure.
        // -----------------------------------------------------------------
        pub fn verify(
            sig: *const Signature,
            msg: []const u8,
            pk: *const PublicKey,
        ) Error!void {
            return verifyWithContext(sig, msg, "", pk);
        }
    };
}

// -----------------------------------------------------------------------------
// Tests — surface shape, key-generation invariants, and sign/verify behaviour.
// The authoritative correctness check is the ACVP KAT suite (`zig build kat`);
// these cover what vectors cannot, such as entropy failure never yielding a
// weak key.
// -----------------------------------------------------------------------------

test "Slh_Dsa exposes correct sizes for all parameter sets" {
    inline for (std.enums.values(ParamSet)) |ps| {
        const S = Slh_Dsa(ps);
        const p = ps.params();
        try std.testing.expectEqual(@as(usize, p.pk_bytes), S.public_key_length);
        try std.testing.expectEqual(@as(usize, p.sk_bytes), S.secret_key_length);
        try std.testing.expectEqual(@as(usize, p.sig_bytes), S.signature_length);
    }
}

test "PublicKey/SecretKey/Signature are arrays" {
    const S = Slh_Dsa(.slh_dsa_shake_128s);
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(S.PublicKey));
    try std.testing.expectEqual(@as(usize, 64), @sizeOf(S.SecretKey));
    try std.testing.expectEqual(@as(usize, 7856), @sizeOf(S.Signature));
}

test "generate: entropy failure surfaces as IoError, never a weak key" {
    // std.Io.failing has no entropy source: randomSecure always returns
    // error.EntropyUnavailable. generate must refuse, not fall back.
    const S = Slh_Dsa(.slh_dsa_shake_128f);
    try std.testing.expectError(Error.IoError, S.KeyPair.generate(std.Io.failing));
}

test "fromSeeds: deterministic; SK/PK layout per FIPS 205 §9.1" {
    // f-variants keep the top tree small (h' = 3 -> 8 leaves), so this
    // stays fast in Debug. The s-variants are exercised by the ACVP
    // keyGen KAT run, not the unit suite.
    inline for (.{ ParamSet.slh_dsa_shake_128f, ParamSet.slh_dsa_sha2_128f }) |ps| {
        const S = Slh_Dsa(ps);
        const n = S.params.n;

        var sk_seed: [n]u8 = undefined;
        var sk_prf: [n]u8 = undefined;
        var pk_seed: [n]u8 = undefined;
        for (&sk_seed, 0..) |*b, i| b.* = @intCast(i + 1);
        for (&sk_prf, 0..) |*b, i| b.* = @intCast(0x40 + i);
        for (&pk_seed, 0..) |*b, i| b.* = @intCast(0x80 + i);

        const kp1 = try S.KeyPair.fromSeeds(&sk_seed, &sk_prf, &pk_seed);
        const kp2 = try S.KeyPair.fromSeeds(&sk_seed, &sk_prf, &pk_seed);
        try std.testing.expectEqualSlices(u8, &kp1.secret_key, &kp2.secret_key);
        try std.testing.expectEqualSlices(u8, &kp1.public_key, &kp2.public_key);

        // SK = SK.seed || SK.prf || PK.seed || PK.root; PK = PK.seed || PK.root.
        try std.testing.expectEqualSlices(u8, &sk_seed, kp1.secret_key[0..n]);
        try std.testing.expectEqualSlices(u8, &sk_prf, kp1.secret_key[n .. 2 * n]);
        try std.testing.expectEqualSlices(u8, &pk_seed, kp1.secret_key[2 * n .. 3 * n]);
        try std.testing.expectEqualSlices(u8, kp1.secret_key[2 * n ..], &kp1.public_key);

        // PK.root must not be degenerate.
        try std.testing.expect(!std.mem.allEqual(u8, kp1.public_key[n..], 0));

        // A different SK.seed must change PK.root.
        sk_seed[0] ^= 0xFF;
        const kp3 = try S.KeyPair.fromSeeds(&sk_seed, &sk_prf, &pk_seed);
        try std.testing.expect(!std.mem.eql(u8, kp1.public_key[n..], kp3.public_key[n..]));
    }
}

test "slh-dsa: sign/verify round-trips (pure + context) and rejects tampering" {
    // FIPS 205 §9–§10.3: verify(sign(M, ctx), M, ctx) succeeds, and any
    // mismatch (signature, message, context, key) is rejected. Property-tested
    // (ACVP sigGen/sigVer wired separately — issue #25) on f-variants across
    // both hash families.
    inline for (.{ ParamSet.slh_dsa_shake_128f, ParamSet.slh_dsa_sha2_128f }) |ps| {
        const S = Slh_Dsa(ps);
        const n = S.params.n;

        var sk_seed: [n]u8 = undefined;
        var sk_prf: [n]u8 = undefined;
        var pk_seed: [n]u8 = undefined;
        for (&sk_seed, 0..) |*b, i| b.* = @intCast(0x11 + i);
        for (&sk_prf, 0..) |*b, i| b.* = @intCast(0x55 + i);
        for (&pk_seed, 0..) |*b, i| b.* = @intCast(0x99 + i);
        const kp = try S.KeyPair.fromSeeds(&sk_seed, &sk_prf, &pk_seed);

        const msg = "FIPS 205 SLH-DSA end-to-end round-trip";
        const ctx = "context-string";
        var rnd: [n]u8 = undefined;
        for (&rnd, 0..) |*b, i| b.* = @intCast(0xE1 ^ i);

        // Randomised signing with a non-empty context.
        var sig: S.Signature = undefined;
        try S.signWithContext(&sig, msg, ctx, &kp.secret_key, &rnd);
        try S.verifyWithContext(&sig, msg, ctx, &kp.public_key);

        // Negatives: tampered signature (R and the last HT byte), wrong
        // message, wrong context, corrupted PK.root.
        var bad = sig;
        bad[0] ^= 0x01;
        try std.testing.expectError(Error.InvalidSignature, S.verifyWithContext(&bad, msg, ctx, &kp.public_key));
        bad = sig;
        bad[sig.len - 1] ^= 0x01;
        try std.testing.expectError(Error.InvalidSignature, S.verifyWithContext(&bad, msg, ctx, &kp.public_key));
        try std.testing.expectError(Error.InvalidSignature, S.verifyWithContext(&sig, "different message", ctx, &kp.public_key));
        try std.testing.expectError(Error.InvalidSignature, S.verifyWithContext(&sig, msg, "", &kp.public_key));
        try std.testing.expectError(Error.InvalidSignature, S.verifyWithContext(&sig, msg, "other-context", &kp.public_key));
        var bad_pk = kp.public_key;
        bad_pk[n] ^= 0x01; // corrupt PK.root
        try std.testing.expectError(Error.InvalidSignature, S.verifyWithContext(&sig, msg, ctx, &bad_pk));

        // Pure convenience API (ctx = "") round-trips and is deterministic when
        // opt_rand is null.
        var sig_det1: S.Signature = undefined;
        var sig_det2: S.Signature = undefined;
        try S.sign(&sig_det1, msg, &kp.secret_key, null);
        try S.sign(&sig_det2, msg, &kp.secret_key, null);
        try std.testing.expectEqualSlices(u8, &sig_det1, &sig_det2);
        try S.verify(&sig_det1, msg, &kp.public_key);

        // Internal interface round-trips against itself. Domain separation is
        // real: a pure (0x00‖0x00-prefixed) signature must not verify as an
        // internal one, and vice versa.
        var sig_int: S.Signature = undefined;
        S.signInternal(&sig_int, msg, &kp.secret_key, null);
        try S.verifyInternal(&sig_int, msg, &kp.public_key);
        try std.testing.expectError(Error.InvalidSignature, S.verifyInternal(&sig_det1, msg, &kp.public_key));
        try std.testing.expectError(Error.InvalidSignature, S.verify(&sig_int, msg, &kp.public_key));

        // A context longer than 255 bytes is rejected before any work.
        const long_ctx = [_]u8{0} ** 256;
        try std.testing.expectError(Error.ContextTooLong, S.signWithContext(&sig, msg, &long_ctx, &kp.secret_key, &rnd));
        try std.testing.expectError(Error.ContextTooLong, S.verifyWithContext(&sig, msg, &long_ctx, &kp.public_key));
    }
}
