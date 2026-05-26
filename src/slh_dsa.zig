//! FIPS 205 §9, §10.3 — Top-level SLH-DSA scheme.
//!
//! `Slh_Dsa(param_set)` returns a namespace exposing the public surface
//! that callers actually use: key generation, signing, and verification.
//! It drives the FORS, hypertree, and hash layers; the details of each
//! live in their own modules.
//!
//! API shape (planned — bodies @panic until Lane B implementation lands):
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
        // FIPS 205 §10.3 wraps this with random-bit sampling.
        //
        // For deterministic testing, callers can use `KeyPair.fromSeeds`;
        // for normal use, `KeyPair.generate` draws three n-byte values
        // from `io`'s CSPRNG.
        // -----------------------------------------------------------------
        pub const KeyPair = struct {
            public_key: PublicKey,
            secret_key: SecretKey,

            /// Generate a fresh keypair from `io`'s CSPRNG.
            pub fn generate(io: anytype) Error!KeyPair {
                _ = io;
                @panic("TODO: keygen not implemented yet (FIPS 205 §9.1 / §10.3)");
            }

            /// Deterministically derive a keypair from explicit seed values.
            /// Used by KAT vectors and by callers who manage their own
            /// entropy.
            pub fn fromSeeds(
                sk_seed: *const [p.n]u8,
                sk_prf: *const [p.n]u8,
                pk_seed: *const [p.n]u8,
            ) Error!KeyPair {
                _ = sk_seed;
                _ = sk_prf;
                _ = pk_seed;
                @panic("TODO: KeyPair.fromSeeds not implemented yet (FIPS 205 §9.1 Algorithm 17)");
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
