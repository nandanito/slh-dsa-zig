//! Constant-time verification harness (Lane A). Run under Valgrind/ctgrind:
//! it taints SK.seed and runs the secret-processing primitives, letting
//! memcheck flag any branch or memory access that depends on secret data.
//! Built + run by the ctgrind workflow (`zig build ctgrind`). Issue #34.
//!
//! Component-level, by design
//! --------------------------
//! SLH-DSA's per-node WOTS+/FORS secrets are all PRF-derived from SK.seed
//! (FIPS 205 §9.1). This harness taints SK.seed and drives the primitives that
//! consume it — `wots_pkGen` (PRF + full-length WOTS+ chaining + T_len) and
//! `fors_node` (PRF + F over a leaf secret, then H up a full tree). Their step
//! counts and indices are constant / public tree geometry (WOTS+ chains run
//! the fixed `w-1` steps; FORS heights/indices are public), so there is no
//! secret-derived loop bound and thus no false positive — the check is clean
//! iff the primitives are constant-time in the secret VALUE.
//!
//! What this does NOT cover (deferred, tracked on #34): the *whole* `sign`
//! path. There the WOTS+ message is a public-but-SK.seed-derived value (the
//! FORS public key / XMSS roots) whose digits set the chain lengths; auditing
//! that end-to-end needs in-library declassify hooks marking those public
//! intermediates, so memcheck doesn't false-positive on constant-time code.
//!
//! Non-vacuity: the std.valgrind client requests below only emit when the
//! module is built with valgrind support (build.zig gates `.valgrind` on the
//! target); `negative_control.zig` guarantees the on-target build is not
//! silently inert. Inputs come from the OS RNG so the optimiser can't fold the
//! secret away.

const std = @import("std");
const slh_dsa = @import("slh_dsa");
const internal = slh_dsa.internal;

fn auditComponents(comptime param_set: slh_dsa.ParamSet, io: std.Io) !void {
    const p = comptime param_set.params();
    const n = p.n;
    const Wots = internal.wots.Wots(p);
    const Fors = internal.fors.Fors(p);
    const Adrs = internal.address.Adrs;

    // PK.seed and ADRS are public; a real (defined) value is fine.
    var pk_seed: [n]u8 = undefined;
    try io.randomSecure(&pk_seed);

    // The one secret. Any branch or memory address derived from it is now a
    // memcheck error.
    var sk_seed: [n]u8 = undefined;
    try io.randomSecure(&sk_seed);
    std.valgrind.memcheck.makeMemUndefined(&sk_seed);

    // WOTS+ public-key generation (FIPS 205 §5.1): PRF(SK.seed) origin per
    // chain, each chained the fixed w-1 steps, then T_len-compressed.
    {
        var adrs = Adrs.init();
        var out_pk: [n]u8 = undefined;
        Wots.pkGen(&sk_seed, &pk_seed, &adrs, &out_pk);
        std.valgrind.memcheck.makeMemDefined(&out_pk); // public output
        std.mem.doNotOptimizeAway(out_pk[0]);
    }

    // FORS tree root (FIPS 205 §8.2): base case F over a PRF(SK.seed) leaf
    // secret, inductive case stacks children with H. Height `a` = a full tree.
    {
        var adrs = Adrs.init();
        var out_node: [n]u8 = undefined;
        Fors.node(&sk_seed, 0, p.a, &pk_seed, &adrs, &out_node);
        std.valgrind.memcheck.makeMemDefined(&out_node); // public output
        std.mem.doNotOptimizeAway(out_node[0]);
    }
}

pub fn main(init: std.process.Init) !void {
    // One target per hash family so both dispatchers (§11.1 SHAKE, §11.2
    // SHA-2) are audited, and both SHA-2 widths: §11.2 widens H and T_l to
    // SHA-512 for categories 3/5 (n = 24, 32), which `fors_node` and
    // `wots_pkGen` respectively reach. n = 32 takes the same branch as n = 24.
    // See taint_sign.zig for the full parameter-set coverage argument.
    try auditComponents(.slh_dsa_shake_128f, init.io);
    try auditComponents(.slh_dsa_sha2_128f, init.io);
    try auditComponents(.slh_dsa_shake_192f, init.io);
    try auditComponents(.slh_dsa_sha2_192f, init.io);
}
