//! FIPS 205 §9, §10.3 — Top-level SLH-DSA scheme.
//!
//! `Slh_Dsa(param_set)` returns a namespace exposing the public surface
//! that callers actually use: key generation, signing, and verification.
//! It drives the FORS, hypertree, and hash layers; the details of each
//! live in their own modules.
//!
//! Status: key generation is implemented; sign and verify are stubs that
//! @panic with FIPS 205 references.
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
    /// Skeleton-only: function body has not been implemented yet.
    NotImplemented,
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

        // -----------------------------------------------------------------
        // FIPS 205 §9.1 Algorithm 17 — slh_keygen_internal(SK.seed, SK.prf, PK.seed).
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
            /// from an approved RBG, then derive via Algorithm 17.
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
            /// FIPS 205 §9.1 Algorithm 17 — slh_keygen_internal:
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
        // FIPS 205 §9.2 Algorithm 18 — slh_sign_internal(M, SK, opt_rand).
        // FIPS 205 §10.3 wraps with caller-supplied randomisation policy.
        //
        // Set `opt_rand` to a buffer of `params.n` bytes for randomised
        // signing (recommended), or `null` to fall back to PK.seed
        // (deterministic — FIPS 205 §9.2). Randomised signing is the
        // default in most implementations because deterministic signing
        // can leak via side channels if the same message is signed
        // multiple times.
        // -----------------------------------------------------------------
        pub fn sign(
            out_sig: *Signature,
            msg: []const u8,
            sk: *const SecretKey,
            opt_rand: ?*const [p.n]u8,
        ) Error!void {
            _ = out_sig;
            _ = msg;
            _ = sk;
            _ = opt_rand;
            @panic("TODO: slh_sign not implemented yet (FIPS 205 §9.2 / §10.3)");
        }

        // -----------------------------------------------------------------
        // FIPS 205 §9.3 Algorithm 19 — slh_verify_internal(M, sig, PK).
        // FIPS 205 §10.3 wrapper is the public verifier.
        //
        // Returns `error.InvalidSignature` on failure. The verifier is
        // a complete function: it returns success exactly when the
        // signature reconstructs PK.root from the message.
        // -----------------------------------------------------------------
        pub fn verify(
            sig: *const Signature,
            msg: []const u8,
            pk: *const PublicKey,
        ) Error!void {
            _ = sig;
            _ = msg;
            _ = pk;
            @panic("TODO: slh_verify not implemented yet (FIPS 205 §9.3 / §10.3)");
        }
    };
}

// -----------------------------------------------------------------------------
// Tests — public surface only, until bodies land.
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
