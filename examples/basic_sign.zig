//! examples/basic_sign.zig — End-to-end key generation, signing, and
//! verification with SLH-DSA-SHAKE-128s.
//!
//! Run with:
//!
//!   zig build example_basic_sign
//!
//! > 🚧 **This example will @panic until the scheme bodies land.** It is
//! > here to lock down the public API surface and document the intended
//! > calling convention for downstream users.
//!
//! Lane: Lane A (documentation / example).

const std = @import("std");
const slh_dsa = @import("slh_dsa");

pub fn main() !void {
    // Pick a parameter set at comptime. The 12 options live in
    // `slh_dsa.ParamSet`; "s" variants are smaller signatures + slower
    // signing, "f" variants are the inverse.
    const Scheme = slh_dsa.Slh_Dsa(.slh_dsa_shake_128s);

    std.debug.print("SLH-DSA-SHAKE-128s\n", .{});
    std.debug.print("  public key:  {d} bytes\n", .{Scheme.public_key_length});
    std.debug.print("  secret key:  {d} bytes\n", .{Scheme.secret_key_length});
    std.debug.print("  signature:   {d} bytes\n\n", .{Scheme.signature_length});

    // -----------------------------------------------------------------
    // Key generation.
    //
    // `KeyPair.generate` draws three n-byte values from a CSPRNG
    // exposed via `std.Io`. For example purposes we'd normally pass
    // the default Io implementation here; the exact shape depends on
    // Zig 0.16's std.Io migration and will be filled in alongside the
    // implementation.
    //
    // For deterministic / test workflows, use `KeyPair.fromSeeds`:
    //
    //   const sk_seed = [_]u8{...} ** Scheme.params.n;
    //   const sk_prf  = [_]u8{...} ** Scheme.params.n;
    //   const pk_seed = [_]u8{...} ** Scheme.params.n;
    //   const kp = try Scheme.KeyPair.fromSeeds(&sk_seed, &sk_prf, &pk_seed);
    // -----------------------------------------------------------------

    // TODO: switch the placeholder below for the real `std.Io` once
    // wired up in `src/slh_dsa.zig`.
    const io = {}; // placeholder until the std.Io plumbing lands
    const kp = try Scheme.KeyPair.generate(io);

    // -----------------------------------------------------------------
    // Sign.
    //
    // `opt_rand` is the randomiser. Pass `null` for deterministic
    // signing (PK.seed is used as fallback per FIPS 205 §9.2), or pass
    // a fresh n-byte random buffer for randomised signing.
    //
    // Randomised signing is recommended for general use; deterministic
    // signing exists for KAT compatibility and constrained
    // environments.
    // -----------------------------------------------------------------

    const message = "hello, post-quantum world";
    var sig: Scheme.Signature = undefined;

    try Scheme.sign(&sig, message, &kp.secret_key, null);
    std.debug.print("signed {d}-byte message -> {d}-byte signature\n", .{
        message.len,
        sig.len,
    });

    // -----------------------------------------------------------------
    // Verify.
    //
    // Returns `error.InvalidSignature` if the signature does not
    // reconstruct PK.root from the message. Any other error indicates
    // malformed inputs.
    // -----------------------------------------------------------------

    try Scheme.verify(&sig, message, &kp.public_key);
    std.debug.print("verification: OK\n", .{});

    // -----------------------------------------------------------------
    // Tamper check — flip one bit and confirm the verifier rejects.
    // -----------------------------------------------------------------

    sig[0] ^= 0x01;
    Scheme.verify(&sig, message, &kp.public_key) catch |err| {
        std.debug.print("tampered signature rejected: {s}\n", .{@errorName(err)});
        return;
    };
    std.debug.print("ERROR: tampered signature was accepted!\n", .{});
    return error.VerifierAcceptedTamper;
}
