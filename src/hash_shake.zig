//! FIPS 205 §11.1 — SHAKE instantiations of SLH-DSA hash functions.
//!
//! All six functions are realised via SHAKE-256 with appropriate output
//! lengths. SHAKE-256 is convenient here because its variable output length
//! sidesteps the MGF1 layer that the SHA-2 instances require.
//!
//! Each function is a single SHAKE256 absorb over the concatenated inputs
//! followed by a squeeze of the required length (8n or 8m bits). The four
//! ADRS-keyed functions (PRF, F, H, T_l) hash the **full 32-byte ADRS**
//! (FIPS 205 §11.1), reconstructed from the 22-byte compressed form via
//! `Adrs.expand()`.
//!
//! Constant-time: Keccak-f has no data-dependent branches or memory
//! accesses, so every function here is constant-time over its (possibly
//! secret) inputs. Secret inputs are `sk_seed` (PRF), `sk_prf` (PRF_msg),
//! and the WOTS+/FORS chain/leaf value fed to `F`; those paths scrub the
//! sponge state after squeezing. H/T_l/H_msg hash only public material.

const std = @import("std");
const params_mod = @import("params.zig");
const address = @import("address.zig");

const Shake256 = std.crypto.hash.sha3.Shake256;

pub fn ShakeAdapter(comptime p: params_mod.Params) type {
    return struct {
        pub const n: usize = p.n;
        pub const m: usize = p.m;
        pub const family = params_mod.HashFamily.shake;

        /// FIPS 205 §11.1 — PRF.
        ///
        /// PRF(PK.seed, SK.seed, ADRS) = SHAKE256(PK.seed || ADRS || SK.seed, 8n).
        ///
        /// `sk_seed` is secret; it is absorbed directly into the sponge and
        /// never gates a branch or index. Constant-time.
        pub fn prf(
            sk_seed: *const [n]u8,
            pk_seed: *const [n]u8,
            adrs: *const address.Adrs,
            out: *[n]u8,
        ) void {
            const adrs_full = adrs.expand();
            var st = Shake256.init(.{});
            st.update(pk_seed);
            st.update(&adrs_full);
            st.update(sk_seed);
            st.final(out);
            // `st` absorbed SK.seed; final() clears only the sponge rate.
            // Scrub the whole state to remove secret-derived residue.
            std.crypto.secureZero(u8, std.mem.asBytes(&st));
        }

        /// FIPS 205 §11.1 — PRF_msg.
        ///
        /// PRF_msg(SK.prf, opt_rand, M) = SHAKE256(SK.prf || opt_rand || M, 8n).
        ///
        /// `sk_prf` is secret; absorbed directly. Constant-time.
        pub fn prf_msg(
            sk_prf: *const [n]u8,
            opt_rand: *const [n]u8,
            msg: []const u8,
            out: *[n]u8,
        ) void {
            var st = Shake256.init(.{});
            st.update(sk_prf);
            st.update(opt_rand);
            st.update(msg);
            st.final(out);
            // `st` absorbed SK.prf; scrub the state for the same reason as PRF.
            std.crypto.secureZero(u8, std.mem.asBytes(&st));
        }

        /// FIPS 205 §11.1 — H_msg.
        ///
        /// H_msg(R, PK.seed, PK.root, M) = SHAKE256(R || PK.seed || PK.root || M, 8m).
        /// All inputs are public (R is the per-signature randomiser).
        pub fn h_msg(
            rand: *const [n]u8,
            pk_seed: *const [n]u8,
            pk_root: *const [n]u8,
            msg: []const u8,
            out: *[m]u8,
        ) void {
            var st = Shake256.init(.{});
            st.update(rand);
            st.update(pk_seed);
            st.update(pk_root);
            st.update(msg);
            st.final(out);
        }

        /// FIPS 205 §11.1 — F.
        ///
        /// F(PK.seed, ADRS, M_1) = SHAKE256(PK.seed || ADRS || M_1, 8n).
        /// In WOTS+ chaining and FORS leaf generation `M_1` is a secret chain /
        /// leaf value, so the sponge state is scrubbed after squeezing.
        pub fn f(
            pk_seed: *const [n]u8,
            adrs: *const address.Adrs,
            msg: *const [n]u8,
            out: *[n]u8,
        ) void {
            const adrs_full = adrs.expand();
            var st = Shake256.init(.{});
            st.update(pk_seed);
            st.update(&adrs_full);
            st.update(msg);
            st.final(out);
            // `st` absorbed the secret M_1; final() clears only the sponge
            // rate, so scrub the whole state (same rationale as PRF).
            std.crypto.secureZero(u8, std.mem.asBytes(&st));
        }

        /// FIPS 205 §11.1 — H.
        ///
        /// H(PK.seed, ADRS, M_2) = SHAKE256(PK.seed || ADRS || M_2, 8n)
        /// where M_2 = left || right is the concatenation of two n-byte
        /// messages.
        pub fn h(
            pk_seed: *const [n]u8,
            adrs: *const address.Adrs,
            left: *const [n]u8,
            right: *const [n]u8,
            out: *[n]u8,
        ) void {
            const adrs_full = adrs.expand();
            var st = Shake256.init(.{});
            st.update(pk_seed);
            st.update(&adrs_full);
            st.update(left);
            st.update(right);
            st.final(out);
        }

        /// FIPS 205 §11.1 — T_l.
        ///
        /// T_l(PK.seed, ADRS, M_l) = SHAKE256(PK.seed || ADRS || M_l, 8n)
        /// where M_l is l concatenated n-byte messages.
        pub fn t_l(
            pk_seed: *const [n]u8,
            adrs: *const address.Adrs,
            msg: []const u8,
            out: *[n]u8,
        ) void {
            const adrs_full = adrs.expand();
            var st = Shake256.init(.{});
            st.update(pk_seed);
            st.update(&adrs_full);
            st.update(msg);
            st.final(out);
        }
    };
}

// -----------------------------------------------------------------------------
// Tests.
//
// The "matches single-shot SHAKE256 of the explicit concatenation" tests are
// the byte-layout cross-checks: each rebuilds the FIPS 205 §11.1 input string
// by hand into one contiguous buffer, hashes it in a single call, and asserts
// the adapter's streamed-update assembly produces identical bytes. This
// catches mis-ordering, missing, or extra bytes independently of the adapter.
//
// Byte-for-byte cross-validation against PQClean / NIST ACVP vectors is
// tracked separately (gated on vector files landing in tests/vectors/).
// -----------------------------------------------------------------------------

const testing = std.testing;
const Shake256Test = std.crypto.hash.sha3.Shake256;

test "ShakeAdapter compiles for all SHAKE parameter sets" {
    inline for (std.enums.values(params_mod.ParamSet)) |ps| {
        if (ps.family() == .shake) {
            const A = ShakeAdapter(ps.params());
            try std.testing.expectEqual(@as(usize, ps.params().n), A.n);
        }
    }
}

test "shake F: matches single-shot SHAKE256 of PK.seed || ADRS || M_1" {
    const A = ShakeAdapter(comptime params_mod.ParamSet.slh_dsa_shake_128s.params());
    const n = A.n;

    var pk_seed: [n]u8 = undefined;
    var msg: [n]u8 = undefined;
    for (&pk_seed, 0..) |*b, i| b.* = @intCast(i + 1);
    for (&msg, 0..) |*b, i| b.* = @intCast(0xA0 + i);

    var adrs = address.Adrs.init();
    adrs.setLayer(3);
    adrs.setTreeAddress(0x0102030405060708);
    adrs.setType(.wots_hash);
    adrs.setKeyPairAddress(0x11223344);
    adrs.setChainAddress(0x55667788);
    adrs.setHashAddress(0x99AABBCC);

    var got: [n]u8 = undefined;
    A.f(&pk_seed, &adrs, &msg, &got);

    // Independent re-derivation: full 32-byte ADRS, single SHAKE256 call.
    const adrs_full = adrs.expand();
    var concat: [n + 32 + n]u8 = undefined;
    @memcpy(concat[0..n], &pk_seed);
    @memcpy(concat[n .. n + 32], &adrs_full);
    @memcpy(concat[n + 32 ..], &msg);
    var want: [n]u8 = undefined;
    Shake256Test.hash(&concat, &want, .{});

    try testing.expectEqualSlices(u8, &want, &got);
}

test "shake H: matches single-shot SHAKE256 of PK.seed || ADRS || left || right" {
    const A = ShakeAdapter(comptime params_mod.ParamSet.slh_dsa_shake_192f.params());
    const n = A.n;

    var pk_seed: [n]u8 = undefined;
    var left: [n]u8 = undefined;
    var right: [n]u8 = undefined;
    for (&pk_seed, 0..) |*b, i| b.* = @intCast(i + 1);
    for (&left, 0..) |*b, i| b.* = @intCast(0x40 + i);
    for (&right, 0..) |*b, i| b.* = @intCast(0x80 + i);

    var adrs = address.Adrs.init();
    adrs.setType(.tree);
    adrs.setTreeHeight(5);
    adrs.setTreeIndex(7);

    var got: [n]u8 = undefined;
    A.h(&pk_seed, &adrs, &left, &right, &got);

    const adrs_full = adrs.expand();
    var concat: [n + 32 + 2 * n]u8 = undefined;
    @memcpy(concat[0..n], &pk_seed);
    @memcpy(concat[n .. n + 32], &adrs_full);
    @memcpy(concat[n + 32 .. n + 32 + n], &left);
    @memcpy(concat[n + 32 + n ..], &right);
    var want: [n]u8 = undefined;
    Shake256Test.hash(&concat, &want, .{});

    try testing.expectEqualSlices(u8, &want, &got);
}

test "shake PRF: matches single-shot SHAKE256 of PK.seed || ADRS || SK.seed" {
    const A = ShakeAdapter(comptime params_mod.ParamSet.slh_dsa_shake_256s.params());
    const n = A.n;

    var sk_seed: [n]u8 = undefined;
    var pk_seed: [n]u8 = undefined;
    for (&sk_seed, 0..) |*b, i| b.* = @intCast(0xC0 + i);
    for (&pk_seed, 0..) |*b, i| b.* = @intCast(i + 1);

    var adrs = address.Adrs.init();
    adrs.setType(.wots_prf);
    adrs.setKeyPairAddress(0xDEADBEEF);

    var got: [n]u8 = undefined;
    A.prf(&sk_seed, &pk_seed, &adrs, &got);

    const adrs_full = adrs.expand();
    var concat: [n + 32 + n]u8 = undefined;
    @memcpy(concat[0..n], &pk_seed);
    @memcpy(concat[n .. n + 32], &adrs_full);
    @memcpy(concat[n + 32 ..], &sk_seed);
    var want: [n]u8 = undefined;
    Shake256Test.hash(&concat, &want, .{});

    try testing.expectEqualSlices(u8, &want, &got);
}

test "shake PRF_msg: matches single-shot SHAKE256 of SK.prf || opt_rand || M" {
    const A = ShakeAdapter(comptime params_mod.ParamSet.slh_dsa_shake_128f.params());
    const n = A.n;

    var sk_prf: [n]u8 = undefined;
    var opt_rand: [n]u8 = undefined;
    for (&sk_prf, 0..) |*b, i| b.* = @intCast(0x10 + i);
    for (&opt_rand, 0..) |*b, i| b.* = @intCast(0x70 + i);
    const msg = "the quick brown fox";

    var got: [n]u8 = undefined;
    A.prf_msg(&sk_prf, &opt_rand, msg, &got);

    var concat: [2 * n + msg.len]u8 = undefined;
    @memcpy(concat[0..n], &sk_prf);
    @memcpy(concat[n .. 2 * n], &opt_rand);
    @memcpy(concat[2 * n ..], msg);
    var want: [n]u8 = undefined;
    Shake256Test.hash(&concat, &want, .{});

    try testing.expectEqualSlices(u8, &want, &got);
}

test "shake H_msg: matches single-shot SHAKE256 of R || PK.seed || PK.root || M, length 8m" {
    const A = ShakeAdapter(comptime params_mod.ParamSet.slh_dsa_shake_192s.params());
    const n = A.n;
    const m = A.m;

    var rand: [n]u8 = undefined;
    var pk_seed: [n]u8 = undefined;
    var pk_root: [n]u8 = undefined;
    for (&rand, 0..) |*b, i| b.* = @intCast(0x20 + i);
    for (&pk_seed, 0..) |*b, i| b.* = @intCast(i + 1);
    for (&pk_root, 0..) |*b, i| b.* = @intCast(0x90 + i);
    const msg = "FIPS 205 H_msg layout check";

    var got: [m]u8 = undefined;
    A.h_msg(&rand, &pk_seed, &pk_root, msg, &got);

    var concat: [3 * n + msg.len]u8 = undefined;
    @memcpy(concat[0..n], &rand);
    @memcpy(concat[n .. 2 * n], &pk_seed);
    @memcpy(concat[2 * n .. 3 * n], &pk_root);
    @memcpy(concat[3 * n ..], msg);
    var want: [m]u8 = undefined;
    Shake256Test.hash(&concat, &want, .{});

    try testing.expectEqualSlices(u8, &want, &got);
    try testing.expectEqual(@as(usize, m), got.len);
}

test "shake: every function is deterministic" {
    const A = ShakeAdapter(comptime params_mod.ParamSet.slh_dsa_shake_128s.params());
    const n = A.n;

    const seed = [_]u8{0x5A} ** n;
    const msg = [_]u8{0x3C} ** n;
    var adrs = address.Adrs.init();
    adrs.setType(.fors_tree);
    adrs.setTreeIndex(42);

    var a1: [n]u8 = undefined;
    var a2: [n]u8 = undefined;
    A.f(&seed, &adrs, &msg, &a1);
    A.f(&seed, &adrs, &msg, &a2);
    try testing.expectEqualSlices(u8, &a1, &a2);

    var p1: [n]u8 = undefined;
    var p2: [n]u8 = undefined;
    A.prf(&msg, &seed, &adrs, &p1);
    A.prf(&msg, &seed, &adrs, &p2);
    try testing.expectEqualSlices(u8, &p1, &p2);
}

test "shake F: one ADRS byte flip changes the output" {
    const A = ShakeAdapter(comptime params_mod.ParamSet.slh_dsa_shake_128s.params());
    const n = A.n;

    const pk_seed = [_]u8{0x11} ** n;
    const msg = [_]u8{0x22} ** n;

    var adrs_a = address.Adrs.init();
    adrs_a.setType(.wots_hash);
    adrs_a.setChainAddress(1);

    var adrs_b = address.Adrs.init();
    adrs_b.setType(.wots_hash);
    adrs_b.setChainAddress(2); // single differing field

    var out_a: [n]u8 = undefined;
    var out_b: [n]u8 = undefined;
    A.f(&pk_seed, &adrs_a, &msg, &out_a);
    A.f(&pk_seed, &adrs_b, &msg, &out_b);

    try testing.expect(!std.mem.eql(u8, &out_a, &out_b));
}
