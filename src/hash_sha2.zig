//! FIPS 205 §11.2 — SHA-2 instantiations of SLH-DSA hash functions.
//!
//! Backend selection rules from §11.2 (the easy-to-miss part):
//!
//!   - `F` and `PRF` use **SHA-256 always**, regardless of `n`. The §11.2.2
//!     block for categories 3/5 otherwise looks all-SHA-512 at a glance.
//!   - `H`, `T_l`, `H_msg` use SHA-256 for n = 16 (category 1) and SHA-512
//!     for n = 24, 32 (categories 3, 5).
//!   - `PRF_msg` is HMAC-SHA-256 (n = 16) or HMAC-SHA-512 (n = 24, 32),
//!     truncated to n bytes.
//!   - `H_msg` is MGF1 over SHA-256/SHA-512 expanding to `m` bytes.
//!
//! The keyed hashes (F, H, T_l, PRF) prepend `PK.seed` padded up to one
//! hash block with `toByte(0, block_len - n)` zero bytes, then the 22-byte
//! compressed ADRSc, then the message blocks (FIPS 205 §11.2). The zero
//! padding mirrors an HMAC-ipad-style precomputed state the standard could
//! have specified statically; we just emit the literal zero bytes.
//!
//! Constant-time: SHA-256/SHA-512/HMAC compression functions have no
//! data-dependent branches or memory accesses. Secret inputs are `sk_seed`
//! (PRF), `sk_prf` (PRF_msg), and the WOTS+/FORS chain/leaf value fed to `F`;
//! the hash state and truncated digest derived from them are scrubbed before
//! returning. H/T_l/H_msg hash only public material (Merkle tree nodes, WOTS+
//! public keys, FORS roots, the message and the public randomiser).

const std = @import("std");
const params_mod = @import("params.zig");
const address = @import("address.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha512 = std.crypto.hash.sha2.Sha512;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const HmacSha512 = std.crypto.auth.hmac.sha2.HmacSha512;

/// RFC 8017 §B.2.1 — MGF1 mask generation function.
///
/// Expands `seed` to `out.len` bytes as the concatenation of
/// `Hash(seed || I2OSP(counter, 4))` blocks, counter starting at 0, with the
/// final block truncated. FIPS 205 §11.2 uses this to stretch H_msg to `m`
/// bytes.
///
/// Constant-time: the loop bound is `out.len` (public, comptime-derived from
/// `m`); the counter is a public sequence. No secret-dependent control flow.
fn mgf1(comptime Hash: type, seed: []const u8, out: []u8) void {
    var counter: u32 = 0;
    var off: usize = 0;
    while (off < out.len) : (counter += 1) {
        var c: [4]u8 = undefined;
        std.mem.writeInt(u32, &c, counter, .big);

        var h = Hash.init(.{});
        h.update(seed);
        h.update(&c);
        var block: [Hash.digest_length]u8 = undefined;
        h.final(&block);

        const take = @min(Hash.digest_length, out.len - off);
        @memcpy(out[off..][0..take], block[0..take]);
        off += take;
    }
}

pub fn Sha2Adapter(comptime p: params_mod.Params) type {
    return struct {
        pub const n: usize = p.n;
        pub const m: usize = p.m;
        pub const family = params_mod.HashFamily.sha2;

        // FIPS 205 §11.2: H, T_l, and H_msg widen to SHA-512 for categories
        // 3/5 (n = 24, 32); F and PRF stay on SHA-256 unconditionally.
        const MsgHash = if (p.n == 16) Sha256 else Sha512;
        const MsgHmac = if (p.n == 16) HmacSha256 else HmacSha512;

        /// Begin a keyed hash: absorb PK.seed, the block-filling zero pad, and
        /// the 22-byte compressed ADRSc. The caller then absorbs the message
        /// blocks and calls `finishTrunc`.
        fn keyedInit(comptime Hash: type, pk_seed: *const [n]u8, adrs: *const address.Adrs) Hash {
            var st = Hash.init(.{});
            st.update(pk_seed);
            const pad = [_]u8{0} ** (Hash.block_length - n);
            st.update(&pad);
            st.update(adrs.slice());
            return st;
        }

        /// Finalise a keyed hash and truncate the digest to the first n bytes.
        /// `scrub` zeroizes the full digest afterwards; set it when the input
        /// included secret material (PRF).
        fn finishTrunc(comptime Hash: type, comptime scrub: bool, st: *Hash, out: *[n]u8) void {
            var digest: [Hash.digest_length]u8 = undefined;
            st.final(&digest);
            @memcpy(out, digest[0..n]);
            if (scrub) {
                // The caller absorbed secret material (SK.seed for PRF, a secret
                // WOTS+ chain / FORS leaf value for F): the hash's last-block
                // buffer still holds those raw bytes, and the truncated tail of
                // `digest` is secret-derived. Scrub both (volatile via secureZero).
                std.crypto.secureZero(u8, &digest);
                std.crypto.secureZero(u8, std.mem.asBytes(st));
            }
        }

        /// FIPS 205 §11.2 — PRF (PK.seed, SK.seed, ADRS).
        ///
        /// Trunc_n(SHA-256(PK.seed || toByte(0, 64-n) || ADRSc || SK.seed)).
        /// SHA-256 always. `sk_seed` is secret; the digest is scrubbed.
        pub fn prf(
            sk_seed: *const [n]u8,
            pk_seed: *const [n]u8,
            adrs: *const address.Adrs,
            out: *[n]u8,
        ) void {
            var st = keyedInit(Sha256, pk_seed, adrs);
            st.update(sk_seed);
            finishTrunc(Sha256, true, &st, out);
        }

        /// FIPS 205 §11.2 — PRF_msg (SK.prf, opt_rand, M).
        ///
        /// Trunc_n(HMAC-SHA-X(SK.prf, opt_rand || M)). HMAC-SHA-256 for n=16,
        /// HMAC-SHA-512 otherwise. `sk_prf` is the HMAC key (secret); the tag
        /// is scrubbed after truncation.
        pub fn prf_msg(
            sk_prf: *const [n]u8,
            opt_rand: *const [n]u8,
            msg_parts: []const []const u8,
            out: *[n]u8,
        ) void {
            var mac = MsgHmac.init(sk_prf);
            mac.update(opt_rand);
            for (msg_parts) |part| mac.update(part);
            var tag: [MsgHmac.mac_length]u8 = undefined;
            mac.final(&tag);
            @memcpy(out, tag[0..n]);
            // SK.prf is the HMAC key; the HMAC state retains key-derived
            // material (recoverable from the opad block). Scrub tag + state.
            std.crypto.secureZero(u8, &tag);
            std.crypto.secureZero(u8, std.mem.asBytes(&mac));
        }

        /// FIPS 205 §11.2 — H_msg (R, PK.seed, PK.root, M).
        ///
        /// MGF1-SHA-X(R || PK.seed || SHA-X(R || PK.seed || PK.root || M), m).
        /// SHA-256 for n=16, SHA-512 otherwise. All inputs are public.
        pub fn h_msg(
            rand: *const [n]u8,
            pk_seed: *const [n]u8,
            pk_root: *const [n]u8,
            msg_parts: []const []const u8,
            out: *[m]u8,
        ) void {
            var inner = MsgHash.init(.{});
            inner.update(rand);
            inner.update(pk_seed);
            inner.update(pk_root);
            for (msg_parts) |part| inner.update(part);
            var digest: [MsgHash.digest_length]u8 = undefined;
            inner.final(&digest);

            // MGF1 seed = R || PK.seed || inner-digest, expanded to m bytes.
            var mgf_seed: [2 * n + MsgHash.digest_length]u8 = undefined;
            @memcpy(mgf_seed[0..n], rand);
            @memcpy(mgf_seed[n .. 2 * n], pk_seed);
            @memcpy(mgf_seed[2 * n ..], &digest);
            mgf1(MsgHash, &mgf_seed, out);
        }

        /// FIPS 205 §11.2 — F (PK.seed, ADRS, M_1).
        ///
        /// Trunc_n(SHA-256(PK.seed || toByte(0, 64-n) || ADRSc || M_1)).
        /// SHA-256 always. In WOTS+ chaining and FORS leaf generation `M_1`
        /// is a secret chain / leaf value, so the hash state is scrubbed.
        pub fn f(
            pk_seed: *const [n]u8,
            adrs: *const address.Adrs,
            msg: *const [n]u8,
            out: *[n]u8,
        ) void {
            var st = keyedInit(Sha256, pk_seed, adrs);
            st.update(msg);
            finishTrunc(Sha256, true, &st, out);
        }

        /// FIPS 205 §11.2 — H (PK.seed, ADRS, M_2).
        ///
        /// Trunc_n(SHA-X(PK.seed || toByte(0, blk-n) || ADRSc || left || right)).
        /// SHA-256 for n=16, SHA-512 otherwise.
        pub fn h(
            pk_seed: *const [n]u8,
            adrs: *const address.Adrs,
            left: *const [n]u8,
            right: *const [n]u8,
            out: *[n]u8,
        ) void {
            var st = keyedInit(MsgHash, pk_seed, adrs);
            st.update(left);
            st.update(right);
            finishTrunc(MsgHash, false, &st, out);
        }

        /// FIPS 205 §11.2 — T_l (PK.seed, ADRS, M_l).
        ///
        /// Trunc_n(SHA-X(PK.seed || toByte(0, blk-n) || ADRSc || M_l)).
        /// SHA-256 for n=16, SHA-512 otherwise.
        pub fn t_l(
            pk_seed: *const [n]u8,
            adrs: *const address.Adrs,
            msg: []const u8,
            out: *[n]u8,
        ) void {
            var st = keyedInit(MsgHash, pk_seed, adrs);
            st.update(msg);
            finishTrunc(MsgHash, false, &st, out);
        }
    };
}

// -----------------------------------------------------------------------------
// Tests.
//
// The "matches single-shot ..." tests rebuild the FIPS 205 §11.2 input string
// by hand and hash it in one call, cross-checking the adapter's streamed
// assembly (ordering, the toByte(0, blk-n) pad width, ADRSc, truncation).
// The "uses SHA-256 not SHA-512" test is the regression guard for the
// easy-to-miss F/PRF rule in §11.2.2.
//
// Byte-for-byte cross-validation against PQClean / NIST ACVP vectors is
// tracked separately (gated on vector files landing in tests/vectors/).
// -----------------------------------------------------------------------------

const testing = std.testing;

fn fillAscending(buf: []u8, start: u8) void {
    for (buf, 0..) |*b, i| b.* = start +% @as(u8, @intCast(i));
}

test "Sha2Adapter compiles for all SHA-2 parameter sets" {
    inline for (std.enums.values(params_mod.ParamSet)) |ps| {
        if (ps.family() == .sha2) {
            const A = Sha2Adapter(ps.params());
            try std.testing.expectEqual(@as(usize, ps.params().n), A.n);
        }
    }
}

test "sha2 F (n=16): matches single-shot SHA-256 with 48-byte pad" {
    const A = Sha2Adapter(comptime params_mod.ParamSet.slh_dsa_sha2_128s.params());
    const n = A.n; // 16

    var pk_seed: [n]u8 = undefined;
    var msg: [n]u8 = undefined;
    fillAscending(&pk_seed, 1);
    fillAscending(&msg, 0xA0);

    var adrs = address.Adrs.init();
    adrs.setLayer(2);
    adrs.setTreeAddress(0x1122334455667788);
    adrs.setType(.wots_hash);
    adrs.setChainAddress(9);
    adrs.setHashAddress(3);

    var got: [n]u8 = undefined;
    A.f(&pk_seed, &adrs, &msg, &got);

    // PK.seed || toByte(0, 64-16=48) || ADRSc(22) || M_1(16)
    var buf: [n + (64 - n) + 22 + n]u8 = undefined;
    @memcpy(buf[0..n], &pk_seed);
    @memset(buf[n .. n + (64 - n)], 0);
    @memcpy(buf[n + (64 - n) .. n + (64 - n) + 22], adrs.slice());
    @memcpy(buf[n + (64 - n) + 22 ..], &msg);

    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(&buf, &digest, .{});
    try testing.expectEqualSlices(u8, digest[0..n], &got);
}

test "sha2 H (n=24): matches single-shot SHA-512 with 104-byte pad" {
    const A = Sha2Adapter(comptime params_mod.ParamSet.slh_dsa_sha2_192s.params());
    const n = A.n; // 24

    var pk_seed: [n]u8 = undefined;
    var left: [n]u8 = undefined;
    var right: [n]u8 = undefined;
    fillAscending(&pk_seed, 1);
    fillAscending(&left, 0x40);
    fillAscending(&right, 0x80);

    var adrs = address.Adrs.init();
    adrs.setType(.tree);
    adrs.setTreeHeight(4);
    adrs.setTreeIndex(11);

    var got: [n]u8 = undefined;
    A.h(&pk_seed, &adrs, &left, &right, &got);

    // PK.seed || toByte(0, 128-24=104) || ADRSc(22) || left(24) || right(24)
    var buf: [n + (128 - n) + 22 + 2 * n]u8 = undefined;
    @memcpy(buf[0..n], &pk_seed);
    @memset(buf[n .. n + (128 - n)], 0);
    @memcpy(buf[n + (128 - n) .. n + (128 - n) + 22], adrs.slice());
    @memcpy(buf[n + (128 - n) + 22 .. n + (128 - n) + 22 + n], &left);
    @memcpy(buf[n + (128 - n) + 22 + n ..], &right);

    var digest: [Sha512.digest_length]u8 = undefined;
    Sha512.hash(&buf, &digest, .{});
    try testing.expectEqualSlices(u8, digest[0..n], &got);
}

test "sha2 (n=24): F and PRF use SHA-256, not SHA-512 (regression guard)" {
    const A = Sha2Adapter(comptime params_mod.ParamSet.slh_dsa_sha2_192s.params());
    const n = A.n; // 24

    var pk_seed: [n]u8 = undefined;
    var msg: [n]u8 = undefined;
    fillAscending(&pk_seed, 1);
    fillAscending(&msg, 0xA0);

    var adrs = address.Adrs.init();
    adrs.setType(.wots_hash);
    adrs.setChainAddress(7);

    var got_f: [n]u8 = undefined;
    A.f(&pk_seed, &adrs, &msg, &got_f);

    // Correct (SHA-256): pad is 64-n bytes.
    var buf256: [n + (64 - n) + 22 + n]u8 = undefined;
    @memcpy(buf256[0..n], &pk_seed);
    @memset(buf256[n .. n + (64 - n)], 0);
    @memcpy(buf256[n + (64 - n) .. n + (64 - n) + 22], adrs.slice());
    @memcpy(buf256[n + (64 - n) + 22 ..], &msg);
    var d256: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(&buf256, &d256, .{});
    try testing.expectEqualSlices(u8, d256[0..n], &got_f); // F == SHA-256

    // Wrong (SHA-512): pad is 128-n bytes. Must NOT match.
    var buf512: [n + (128 - n) + 22 + n]u8 = undefined;
    @memcpy(buf512[0..n], &pk_seed);
    @memset(buf512[n .. n + (128 - n)], 0);
    @memcpy(buf512[n + (128 - n) .. n + (128 - n) + 22], adrs.slice());
    @memcpy(buf512[n + (128 - n) + 22 ..], &msg);
    var d512: [Sha512.digest_length]u8 = undefined;
    Sha512.hash(&buf512, &d512, .{});
    try testing.expect(!std.mem.eql(u8, d512[0..n], &got_f)); // F != SHA-512

    // Same guard for PRF.
    var sk_seed: [n]u8 = undefined;
    fillAscending(&sk_seed, 0xC0);
    var adrs_prf = address.Adrs.init();
    adrs_prf.setType(.wots_prf);
    adrs_prf.setKeyPairAddress(5);

    var got_prf: [n]u8 = undefined;
    A.prf(&sk_seed, &pk_seed, &adrs_prf, &got_prf);

    var pbuf256: [n + (64 - n) + 22 + n]u8 = undefined;
    @memcpy(pbuf256[0..n], &pk_seed);
    @memset(pbuf256[n .. n + (64 - n)], 0);
    @memcpy(pbuf256[n + (64 - n) .. n + (64 - n) + 22], adrs_prf.slice());
    @memcpy(pbuf256[n + (64 - n) + 22 ..], &sk_seed);
    var pd256: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(&pbuf256, &pd256, .{});
    try testing.expectEqualSlices(u8, pd256[0..n], &got_prf);
}

test "sha2 PRF_msg (n=24): matches Trunc_n(HMAC-SHA-512(SK.prf, opt_rand || M))" {
    const A = Sha2Adapter(comptime params_mod.ParamSet.slh_dsa_sha2_192f.params());
    const n = A.n; // 24

    var sk_prf: [n]u8 = undefined;
    var opt_rand: [n]u8 = undefined;
    fillAscending(&sk_prf, 0x10);
    fillAscending(&opt_rand, 0x70);
    const msg = "the quick brown fox jumps";

    var got: [n]u8 = undefined;
    A.prf_msg(&sk_prf, &opt_rand, &.{msg}, &got);

    var hmac_msg: [n + msg.len]u8 = undefined;
    @memcpy(hmac_msg[0..n], &opt_rand);
    @memcpy(hmac_msg[n..], msg);
    var tag: [HmacSha512.mac_length]u8 = undefined;
    HmacSha512.create(&tag, &hmac_msg, &sk_prf);
    try testing.expectEqualSlices(u8, tag[0..n], &got);
}

test "sha2 H_msg (n=16, m=34): matches MGF1-SHA-256 over inner digest, two blocks" {
    const A = Sha2Adapter(comptime params_mod.ParamSet.slh_dsa_sha2_128f.params());
    const n = A.n; // 16
    const m = A.m; // 34 (> 32 → exercises MGF1 counter increment)

    var rand: [n]u8 = undefined;
    var pk_seed: [n]u8 = undefined;
    var pk_root: [n]u8 = undefined;
    fillAscending(&rand, 0x20);
    fillAscending(&pk_seed, 1);
    fillAscending(&pk_root, 0x90);
    const msg = "FIPS 205 H_msg over SHA-256";

    var got: [m]u8 = undefined;
    A.h_msg(&rand, &pk_seed, &pk_root, &.{msg}, &got);

    // inner = SHA-256(R || PK.seed || PK.root || M)
    var inner_buf: [3 * n + msg.len]u8 = undefined;
    @memcpy(inner_buf[0..n], &rand);
    @memcpy(inner_buf[n .. 2 * n], &pk_seed);
    @memcpy(inner_buf[2 * n .. 3 * n], &pk_root);
    @memcpy(inner_buf[3 * n ..], msg);
    var inner: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(&inner_buf, &inner, .{});

    // MGF1 seed = R || PK.seed || inner
    var seed: [2 * n + Sha256.digest_length]u8 = undefined;
    @memcpy(seed[0..n], &rand);
    @memcpy(seed[n .. 2 * n], &pk_seed);
    @memcpy(seed[2 * n ..], &inner);

    // Two MGF1 blocks (counter 0, 1), final truncated to m.
    var block0_buf: [seed.len + 4]u8 = undefined;
    @memcpy(block0_buf[0..seed.len], &seed);
    @memcpy(block0_buf[seed.len..], &[_]u8{ 0, 0, 0, 0 });
    var block0: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(&block0_buf, &block0, .{});

    var block1_buf: [seed.len + 4]u8 = undefined;
    @memcpy(block1_buf[0..seed.len], &seed);
    @memcpy(block1_buf[seed.len..], &[_]u8{ 0, 0, 0, 1 });
    var block1: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(&block1_buf, &block1, .{});

    var want: [m]u8 = undefined;
    @memcpy(want[0..Sha256.digest_length], &block0);
    @memcpy(want[Sha256.digest_length..], block1[0 .. m - Sha256.digest_length]);

    try testing.expectEqualSlices(u8, &want, &got);
}

test "sha2: every function is deterministic" {
    const A = Sha2Adapter(comptime params_mod.ParamSet.slh_dsa_sha2_128s.params());
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

    var t1: [n]u8 = undefined;
    var t2: [n]u8 = undefined;
    A.t_l(&seed, &adrs, &msg, &t1);
    A.t_l(&seed, &adrs, &msg, &t2);
    try testing.expectEqualSlices(u8, &t1, &t2);
}

test "sha2 F: one ADRS byte flip changes the output" {
    const A = Sha2Adapter(comptime params_mod.ParamSet.slh_dsa_sha2_128s.params());
    const n = A.n;

    const pk_seed = [_]u8{0x11} ** n;
    const msg = [_]u8{0x22} ** n;

    var adrs_a = address.Adrs.init();
    adrs_a.setType(.wots_hash);
    adrs_a.setChainAddress(1);

    var adrs_b = address.Adrs.init();
    adrs_b.setType(.wots_hash);
    adrs_b.setChainAddress(2);

    var out_a: [n]u8 = undefined;
    var out_b: [n]u8 = undefined;
    A.f(&pk_seed, &adrs_a, &msg, &out_a);
    A.f(&pk_seed, &adrs_b, &msg, &out_b);

    try testing.expect(!std.mem.eql(u8, &out_a, &out_b));
}
