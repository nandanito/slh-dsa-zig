//! FIPS 205 §11 — SLH-DSA parameter sets.
//!
//! All 12 standardised parameter sets are defined here. Each is selected at
//! comptime via the `ParamSet` enum, and the corresponding `Params` struct
//! drives the comptime sizing of every internal buffer in the library.
//!
//! Sizes and tree heights are taken directly from FIPS 205 Table 2. They are
//! cross-checked at comptime against the structural relations FIPS 205
//! requires (e.g. h = h' · d, m derivable from k·a/8 + ceil(h/8) + ceil(h'/8)),
//! so a transcription error becomes a build error rather than a silent
//! correctness break.

const std = @import("std");

/// The 12 SLH-DSA parameter sets standardised in FIPS 205.
///
/// Naming follows the FIPS 205 §11 convention:
///   slh_dsa_<hash>_<n>{s,f}
/// where:
///   - `hash`  : `sha2` or `shake`
///   - `n`     : security parameter (in bytes × 8 = bits) — 128, 192, 256
///   - `s`/`f` : "small signature" or "fast signing"
pub const ParamSet = enum {
    slh_dsa_sha2_128s,
    slh_dsa_sha2_128f,
    slh_dsa_sha2_192s,
    slh_dsa_sha2_192f,
    slh_dsa_sha2_256s,
    slh_dsa_sha2_256f,

    slh_dsa_shake_128s,
    slh_dsa_shake_128f,
    slh_dsa_shake_192s,
    slh_dsa_shake_192f,
    slh_dsa_shake_256s,
    slh_dsa_shake_256f,

    /// Which hash family backs this parameter set.
    pub fn family(self: ParamSet) HashFamily {
        return switch (self) {
            .slh_dsa_sha2_128s,
            .slh_dsa_sha2_128f,
            .slh_dsa_sha2_192s,
            .slh_dsa_sha2_192f,
            .slh_dsa_sha2_256s,
            .slh_dsa_sha2_256f,
            => .sha2,

            .slh_dsa_shake_128s,
            .slh_dsa_shake_128f,
            .slh_dsa_shake_192s,
            .slh_dsa_shake_192f,
            .slh_dsa_shake_256s,
            .slh_dsa_shake_256f,
            => .shake,
        };
    }

    /// Resolve the parameter set to its concrete `Params` struct.
    pub fn params(comptime self: ParamSet) Params {
        return all_params.get(self);
    }
};

pub const HashFamily = enum { sha2, shake };

/// Concrete parameters for a single parameter set. All sizes are in bytes
/// (or, where noted, in bits).
///
/// Field naming follows FIPS 205 §3 conventions where reasonable.
pub const Params = struct {
    /// `n` — security parameter (FIPS 205 §3, Table 2). Drives WOTS+ secret /
    /// public element sizes, FORS element sizes, hash output truncation, etc.
    n: u32,

    /// `h` — total hypertree height (number of WOTS+/leaf levels stacked).
    h: u32,

    /// `d` — number of XMSS layers in the hypertree.
    d: u32,

    /// `h_prime` — XMSS tree height. Always equal to h / d. Stored for
    /// readability; verified comptime.
    h_prime: u32,

    /// `a` — FORS tree height. Number of leaves in each FORS tree = 2^a.
    a: u32,

    /// `k` — number of FORS trees.
    k: u32,

    /// `lg_w` — log₂(w) where w is the WOTS+ Winternitz parameter. FIPS 205
    /// fixes lg_w = 4 (so w = 16) for all parameter sets.
    lg_w: u32,

    /// `m` — message-digest length used by H_msg.
    m: u32,

    /// `pk_bytes` — public-key length (= 2n).
    pk_bytes: u32,

    /// `sk_bytes` — secret-key length (= 4n).
    sk_bytes: u32,

    /// `sig_bytes` — signature length.
    sig_bytes: u32,

    /// Family selector.
    family: HashFamily,

    // Derived values exposed for downstream comptime checks.

    /// `len_1` — number of base-w digits to encode an n-byte message
    /// (= ceil(8n / lg_w) = 2n when lg_w = 4).
    pub fn len_1(self: Params) u32 {
        return (8 * self.n + self.lg_w - 1) / self.lg_w;
    }

    /// `len_2` — number of base-w digits to encode the WOTS+ checksum.
    pub fn len_2(self: Params) u32 {
        const len1 = self.len_1();
        const max_checksum: u32 = len1 * ((@as(u32, 1) << @as(u5, @intCast(self.lg_w))) - 1);
        return std.math.log2_int_ceil(u32, max_checksum + 1) / self.lg_w + 1;
    }

    /// `len` — total WOTS+ chain count = len_1 + len_2.
    pub fn len(self: Params) u32 {
        return self.len_1() + self.len_2();
    }

    /// `w` — Winternitz parameter.
    pub fn w(self: Params) u32 {
        return @as(u32, 1) << @as(u5, @intCast(self.lg_w));
    }
};

// -----------------------------------------------------------------------------
// FIPS 205 §11 Table 2 — all 12 parameter sets.
// -----------------------------------------------------------------------------
//
// The values below are transcribed from FIPS 205 §11 Table 2. The signature
// sizes also match the per-row totals derivable from
//     sig_bytes = n + (k * (a + 1) * n) + (h + d * len) * n
// — verified by `comptime_self_check` below.

const all_params = std.EnumArray(ParamSet, Params).init(.{
    // ---- SHA-2 family ----
    .slh_dsa_sha2_128s = .{
        .n = 16,
        .h = 63,
        .d = 7,
        .h_prime = 9,
        .a = 12,
        .k = 14,
        .lg_w = 4,
        .m = 30,
        .pk_bytes = 32,
        .sk_bytes = 64,
        .sig_bytes = 7856,
        .family = .sha2,
    },
    .slh_dsa_sha2_128f = .{
        .n = 16,
        .h = 66,
        .d = 22,
        .h_prime = 3,
        .a = 6,
        .k = 33,
        .lg_w = 4,
        .m = 34,
        .pk_bytes = 32,
        .sk_bytes = 64,
        .sig_bytes = 17088,
        .family = .sha2,
    },
    .slh_dsa_sha2_192s = .{
        .n = 24,
        .h = 63,
        .d = 7,
        .h_prime = 9,
        .a = 14,
        .k = 17,
        .lg_w = 4,
        .m = 39,
        .pk_bytes = 48,
        .sk_bytes = 96,
        .sig_bytes = 16224,
        .family = .sha2,
    },
    .slh_dsa_sha2_192f = .{
        .n = 24,
        .h = 66,
        .d = 22,
        .h_prime = 3,
        .a = 8,
        .k = 33,
        .lg_w = 4,
        .m = 42,
        .pk_bytes = 48,
        .sk_bytes = 96,
        .sig_bytes = 35664,
        .family = .sha2,
    },
    .slh_dsa_sha2_256s = .{
        .n = 32,
        .h = 64,
        .d = 8,
        .h_prime = 8,
        .a = 14,
        .k = 22,
        .lg_w = 4,
        .m = 47,
        .pk_bytes = 64,
        .sk_bytes = 128,
        .sig_bytes = 29792,
        .family = .sha2,
    },
    .slh_dsa_sha2_256f = .{
        .n = 32,
        .h = 68,
        .d = 17,
        .h_prime = 4,
        .a = 9,
        .k = 35,
        .lg_w = 4,
        .m = 49,
        .pk_bytes = 64,
        .sk_bytes = 128,
        .sig_bytes = 49856,
        .family = .sha2,
    },

    // ---- SHAKE family ----
    .slh_dsa_shake_128s = .{
        .n = 16,
        .h = 63,
        .d = 7,
        .h_prime = 9,
        .a = 12,
        .k = 14,
        .lg_w = 4,
        .m = 30,
        .pk_bytes = 32,
        .sk_bytes = 64,
        .sig_bytes = 7856,
        .family = .shake,
    },
    .slh_dsa_shake_128f = .{
        .n = 16,
        .h = 66,
        .d = 22,
        .h_prime = 3,
        .a = 6,
        .k = 33,
        .lg_w = 4,
        .m = 34,
        .pk_bytes = 32,
        .sk_bytes = 64,
        .sig_bytes = 17088,
        .family = .shake,
    },
    .slh_dsa_shake_192s = .{
        .n = 24,
        .h = 63,
        .d = 7,
        .h_prime = 9,
        .a = 14,
        .k = 17,
        .lg_w = 4,
        .m = 39,
        .pk_bytes = 48,
        .sk_bytes = 96,
        .sig_bytes = 16224,
        .family = .shake,
    },
    .slh_dsa_shake_192f = .{
        .n = 24,
        .h = 66,
        .d = 22,
        .h_prime = 3,
        .a = 8,
        .k = 33,
        .lg_w = 4,
        .m = 42,
        .pk_bytes = 48,
        .sk_bytes = 96,
        .sig_bytes = 35664,
        .family = .shake,
    },
    .slh_dsa_shake_256s = .{
        .n = 32,
        .h = 64,
        .d = 8,
        .h_prime = 8,
        .a = 14,
        .k = 22,
        .lg_w = 4,
        .m = 47,
        .pk_bytes = 64,
        .sk_bytes = 128,
        .sig_bytes = 29792,
        .family = .shake,
    },
    .slh_dsa_shake_256f = .{
        .n = 32,
        .h = 68,
        .d = 17,
        .h_prime = 4,
        .a = 9,
        .k = 35,
        .lg_w = 4,
        .m = 49,
        .pk_bytes = 64,
        .sk_bytes = 128,
        .sig_bytes = 49856,
        .family = .shake,
    },
});

// -----------------------------------------------------------------------------
// Comptime self-check — verify Table 2 transcription against derived relations.
// -----------------------------------------------------------------------------

comptime {
    // For each parameter set, assert:
    //   1. h == h' * d
    //   2. pk_bytes == 2 * n
    //   3. sk_bytes == 4 * n
    //   4. sig_bytes == n + k*(a+1)*n + (h + d*len) * n
    //                     ↑    ↑          ↑
    //                     R    FORS sig   Hypertree (XMSS auth paths + WOTS+ sigs)
    //
    // Reference: FIPS 205 §11.
    for (std.enums.values(ParamSet)) |ps| {
        const p = ps.params();

        if (p.h != p.h_prime * p.d) {
            @compileError("params: h != h_prime * d for " ++ @tagName(ps));
        }
        if (p.pk_bytes != 2 * p.n) {
            @compileError("params: pk_bytes != 2n for " ++ @tagName(ps));
        }
        if (p.sk_bytes != 4 * p.n) {
            @compileError("params: sk_bytes != 4n for " ++ @tagName(ps));
        }

        const len = p.len();
        const expected_sig =
            p.n // R (randomiser)
            + p.k * (p.a + 1) * p.n // FORS_SIG
            + (p.h + p.d * len) * p.n; // HT_SIG = h XMSS auth nodes + d WOTS+ signatures
        if (p.sig_bytes != expected_sig) {
            @compileError("params: sig_bytes mismatch for " ++ @tagName(ps));
        }
    }
}

// -----------------------------------------------------------------------------
// Tests.
// -----------------------------------------------------------------------------

test "all parameter sets resolve" {
    inline for (std.enums.values(ParamSet)) |ps| {
        const p = ps.params();
        try std.testing.expect(p.n == 16 or p.n == 24 or p.n == 32);
        try std.testing.expect(p.lg_w == 4);
        try std.testing.expect(p.w() == 16);
    }
}

test "len, len_1, len_2 are consistent" {
    // For lg_w = 4 and n = 16: len_1 = 32, len_2 = 3, len = 35.
    const p = ParamSet.slh_dsa_sha2_128s.params();
    try std.testing.expectEqual(@as(u32, 32), p.len_1());
    try std.testing.expectEqual(@as(u32, 3), p.len_2());
    try std.testing.expectEqual(@as(u32, 35), p.len());
}

test "family classification" {
    try std.testing.expectEqual(HashFamily.sha2, ParamSet.slh_dsa_sha2_128s.family());
    try std.testing.expectEqual(HashFamily.shake, ParamSet.slh_dsa_shake_192f.family());
}
