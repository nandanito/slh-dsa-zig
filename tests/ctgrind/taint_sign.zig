//! Whole-path constant-time harness (Lane A). Run under Valgrind/ctgrind: it
//! taints SK.seed and SK.prf and drives a complete key generation and signature
//! — FIPS 205 §9.1 Algorithm 18 and §9.2 Algorithm 19 — so memcheck flags any
//! branch or memory access anywhere in those paths that depends on secret data.
//! Built + run by the ctgrind workflow. Issue #34.
//!
//! Relationship to `taint_components.zig`
//! --------------------------------------
//! That harness audits the secret-processing primitives in isolation
//! (`wots_pkGen`, `fors_node`), where every loop bound is fixed or public
//! geometry. This one audits their *composition*: FORS signing, the d XMSS
//! layers, the hash-family dispatch, and the index arithmetic that joins them.
//! Both are kept: the component harness pins down exactly which primitive broke
//! when something regresses, and it needs no declassification to be meaningful.
//!
//! The classification problem, and how it is solved
//! ------------------------------------------------
//! Nearly every intermediate in `sign` descends from SK.seed, but almost none
//! are secret — the FORS public key and each XMSS root are recomputed by any
//! verifier from the signature (§9.3 Algorithm 20). Their base-w digits set the
//! WOTS+ chain lengths, so pure taint propagation reports thousands of
//! secret-dependent branches at `chain` on code that is constant-time. `src/ct.zig`
//! supplies the missing classification: `ct.declassify` at the three points
//! where the standard makes a value public (R, PK_FORS, each XMSS root). Those
//! calls compile to nothing in ordinary builds.
//!
//! What stays tainted, and therefore what this actually proves
//! ----------------------------------------------------------
//! SK.seed and SK.prf, every PRF-derived WOTS+/FORS secret, and every value
//! that is only ever hashed. A clean run means no branch and no memory address
//! in keygen or sign depends on the secret key's *value*.
//!
//! Non-vacuity is guarded from both ends: `negative_control.zig` proves the
//! taint markers are live, and the comptime check below proves the in-library
//! declassify hooks are live in the same build. Note the asymmetry — inert
//! taint would make the gate pass while checking nothing, whereas inert
//! declassification would make it *fail* loudly at `chain`. Only the first is
//! dangerous, and it is the one the negative control covers.

const std = @import("std");
const builtin = @import("builtin");
const slh_dsa = @import("slh_dsa");

comptime {
    // The harness and the library must agree on Valgrind support, because the
    // taint markers below live here while the declassify hooks live in `src/`.
    // Zig 0.16 resolves that support per *compilation* — build.zig sets
    // `.valgrind` on this module and the imported `slh_dsa` module inherits it
    // — so today the two always match. This pins that down: were it ever to
    // become per-module, the taint would stay live while `ct.declassify` went
    // inert, burying the real result under thousands of false positives at
    // `chain`. Fail at compile time with a readable reason instead.
    if (builtin.valgrind_support != slh_dsa.internal.ct.audit_enabled) {
        @compileError(
            "ctgrind: the harness and the slh_dsa module disagree on Valgrind support. " ++
                "Valgrind support is no longer compilation-wide — give the slh_dsa module " ++
                "imported by the ctgrind executables `.valgrind` matching the harness " ++
                "(see build.zig).",
        );
    }
}

fn auditKeygenAndSign(comptime param_set: slh_dsa.ParamSet, io: std.Io) !void {
    const S = slh_dsa.Slh_Dsa(param_set);
    const n = S.params.n;

    // Seeds come from the OS RNG, not constants, so the optimiser cannot fold
    // the secret away and leave the audit vacuous.
    var sk_seed: [n]u8 = undefined;
    var sk_prf: [n]u8 = undefined;
    var pk_seed: [n]u8 = undefined;
    try io.randomSecure(&sk_seed);
    try io.randomSecure(&sk_prf);
    try io.randomSecure(&pk_seed);

    // The two secrets of FIPS 205 §9.1: SK.seed derives every WOTS+/FORS
    // per-node secret, SK.prf keys the message randomiser. PK.seed is public.
    // From here, any branch or memory address derived from either is an error.
    std.valgrind.memcheck.makeMemUndefined(&sk_seed);
    std.valgrind.memcheck.makeMemUndefined(&sk_prf);

    // -- Key generation: §9.1 Algorithm 18 --------------------------------
    // PK.root is built by a full top-layer xmss_node walk over SK.seed-derived
    // WOTS+ public keys.
    const kp = try S.KeyPair.fromSeeds(&sk_seed, &sk_prf, &pk_seed);

    // PK = PK.seed ‖ PK.root is the public key by definition, so declassify it
    // — both the copy the caller gets and the copy the secret key carries
    // (SK = SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root). The first 2n bytes of the
    // secret key stay tainted: they were copied from the tainted seeds above,
    // which is exactly the classification `sign` must respect.
    std.valgrind.memcheck.makeMemDefined(&kp.public_key);
    std.valgrind.memcheck.makeMemDefined(kp.secret_key[2 * n ..]);

    // -- Signing: §9.2 Algorithm 19 (via the §10.2 external interface) -----
    const msg = "FIPS 205 SLH-DSA constant-time audit: whole signing path";
    const ctx = "ctgrind";

    // Randomised signing. opt_rand is a public randomiser (it is not secret
    // material — §9.2 permits PK.seed in its place).
    var opt_rand: [n]u8 = undefined;
    try io.randomSecure(&opt_rand);

    var sig: S.Signature = undefined;
    try S.signWithContext(&sig, msg, ctx, &kp.secret_key, &opt_rand);

    // The signature is published, so declassify it before verifying: `verify`
    // takes no secret input and compares the reconstructed root against
    // PK.root with a plain `std.mem.eql` (hypertree.zig), which is correct
    // precisely because nothing there is secret.
    std.valgrind.memcheck.makeMemDefined(&sig);

    // A round-trip check, so a harness that silently signed garbage — or that
    // the declassification markers somehow perturbed — cannot pass as clean.
    try S.verifyWithContext(&sig, msg, ctx, &kp.public_key);

    // Deterministic signing (opt_rand = null) takes the `orelse pk_seed`
    // branch through PRF_msg; the rest of the path is shared.
    var sig_det: S.Signature = undefined;
    try S.sign(&sig_det, msg, &kp.secret_key, null);
    std.valgrind.memcheck.makeMemDefined(&sig_det);
    try S.verify(&sig_det, msg, &kp.public_key);
}

pub fn main(init: std.process.Init) !void {
    // Parameter sets are comptime-monomorphised, so "audited" is per set. These
    // four cover every distinct code path in both dispatchers:
    //
    //   * both families — §11.1 SHAKE and §11.2 SHA-2.
    //   * both SHA-2 widths — §11.2 widens H, T_l and H_msg to SHA-512, and
    //     PRF_msg to HMAC-SHA-512, for categories 3/5 (n = 24, 32). That matters
    //     here beyond mere coverage: SK.prf is the HMAC *key*, so the 192f set
    //     is the only one that audits secret-keyed SHA-512. n = 32 takes the
    //     same branch as n = 24, so it would add cost and no new path.
    //
    // What the remaining eight sets vary is public tree geometry (h, d, h', a,
    // k) and output lengths — loop bounds over values the verifier recomputes,
    // never a new branch on secret data. The f-variants also keep the run
    // inside Valgrind's slowdown budget while still exercising the full layer
    // stack (d = 22 for 128f, 17 for 192f).
    try auditKeygenAndSign(.slh_dsa_shake_128f, init.io);
    try auditKeygenAndSign(.slh_dsa_sha2_128f, init.io);
    try auditKeygenAndSign(.slh_dsa_shake_192f, init.io);
    try auditKeygenAndSign(.slh_dsa_sha2_192f, init.io);
}
