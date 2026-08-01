//! FIPS 205 §10.2.2 / §10.3 — HashSLH-DSA pre-hash function selection.
//!
//! The pre-hash variants sign a *digest* of the content rather than the content
//! itself. `PH` names the approved hash function or XOF; its identity is bound
//! into the signature through the DER encoding of its OID, which the caller
//! concatenates into `M'` alongside the digest (Algorithm 23 line 24 and
//! Algorithm 25 line 20):
//!
//!   M' = toByte(1, 1) ‖ toByte(|ctx|, 1) ‖ ctx ‖ OID ‖ PH_M
//!
//! This module supplies the two per-function values that expression needs — the
//! OID encoding and `PH_M` — and nothing else. Assembling `M'` and driving the
//! signature belongs to `slh_dsa.zig`.
//!
//! Nothing here touches secret material. The content, its digest, and the
//! choice of `PH` are all public: `PH_M` is a hash of the message the verifier
//! also has, and the OID travels in the clear as part of the signed input. So
//! this module carries no constant-time obligations, and the `switch` on
//! `PreHash` is deliberately an ordinary runtime branch.

const std = @import("std");
const sha2 = std.crypto.hash.sha2;
const sha3 = std.crypto.hash.sha3;

/// Length of the DER-encoded OID of every approved pre-hash function.
///
/// FIPS 205 §10.2.2 encodes each as `toByte(0x06 09 …, 11)` — DER tag `0x06`,
/// length `0x09`, and nine content bytes. Every OID in the NIST CSOR `hashAlgs`
/// arc shares that shape, so the length is a constant rather than per-function.
pub const oid_length = 11;

/// The longest digest any approved pre-hash function produces: 64 bytes, from
/// SHA-512, SHA3-512, and SHAKE256 (the last fixed at 512 bits by FIPS 205,
/// not by the XOF itself).
pub const max_digest_length = 64;

/// Bytes 0..10 of every approved OID: the DER tag and length, then the arc
/// 2.16.840.1.101.3.4.2 (`nistAlgorithms.hashAlgs`). Only the final byte —
/// see `PreHash.arc` — distinguishes one function from another.
///
/// FIPS 205 §10.2.2 Algorithm 23 spells out four of these literally; the
/// `preHashOidsMatchTheStandard` test below checks this prefix plus each arc
/// against those four verbatim.
const oid_prefix = [_]u8{ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02 };

/// FIPS 205 §10.2.2 Algorithm 23 / §10.3 Algorithm 25 — the pre-hash function
/// `PH`.
///
/// FIPS 205 names only SHA-256, SHA-512, SHAKE128, and SHAKE256 explicitly,
/// leaving `case …  ▷ other approved hash functions or XOFs` open. The twelve
/// here are the ones NIST's ACVP test vectors exercise, which is the practical
/// definition of "approved" for interoperability purposes.
///
/// Note that SHA-256 and SHAKE128 are only appropriate for parameter sets
/// claimed at security category 1 (FIPS 205 §10.2.2). This library does not
/// enforce that pairing — the standard states it as guidance on selection, and
/// ACVP exercises every hash against every parameter set.
pub const PreHash = enum {
    sha2_224,
    sha2_256,
    sha2_384,
    sha2_512,
    sha2_512_224,
    sha2_512_256,
    sha3_224,
    sha3_256,
    sha3_384,
    sha3_512,
    shake_128,
    shake_256,

    /// Final arc of the OID under 2.16.840.1.101.3.4.2 (NIST CSOR
    /// `nistAlgorithms.hashAlgs`).
    fn arc(self: PreHash) u8 {
        return switch (self) {
            .sha2_256 => 1, // 2.16.840.1.101.3.4.2.1  — given by FIPS 205
            .sha2_384 => 2, // 2.16.840.1.101.3.4.2.2
            .sha2_512 => 3, // 2.16.840.1.101.3.4.2.3  — given by FIPS 205
            .sha2_224 => 4, // 2.16.840.1.101.3.4.2.4
            .sha2_512_224 => 5, // 2.16.840.1.101.3.4.2.5
            .sha2_512_256 => 6, // 2.16.840.1.101.3.4.2.6
            .sha3_224 => 7, // 2.16.840.1.101.3.4.2.7
            .sha3_256 => 8, // 2.16.840.1.101.3.4.2.8
            .sha3_384 => 9, // 2.16.840.1.101.3.4.2.9
            .sha3_512 => 10, // 2.16.840.1.101.3.4.2.10
            .shake_128 => 11, // 2.16.840.1.101.3.4.2.11 — given by FIPS 205
            .shake_256 => 12, // 2.16.840.1.101.3.4.2.12 — given by FIPS 205
        };
    }

    /// The std implementation backing this function.
    ///
    /// For the ten fixed-output functions this also fixes the digest length;
    /// for the two XOFs it does not, which is why `digestLength` is declared
    /// separately from the standard rather than read off this type.
    fn Impl(comptime self: PreHash) type {
        return switch (self) {
            .sha2_224 => sha2.Sha224,
            .sha2_256 => sha2.Sha256,
            .sha2_384 => sha2.Sha384,
            .sha2_512 => sha2.Sha512,
            .sha2_512_224 => sha2.Sha512_224,
            .sha2_512_256 => sha2.Sha512_256,
            .sha3_224 => sha3.Sha3_224,
            .sha3_256 => sha3.Sha3_256,
            .sha3_384 => sha3.Sha3_384,
            .sha3_512 => sha3.Sha3_512,
            .shake_128 => sha3.Shake128,
            .shake_256 => sha3.Shake256,
        };
    }

    /// Length in bytes of `PH_M`.
    ///
    /// Taken from FIPS 205 rather than from the backing type. That matters for
    /// the XOFs: Algorithm 23 fixes them at `SHAKE128(M, 256)` and
    /// `SHAKE256(M, 512)`, so the output length is a property of *this
    /// standard's use* of the XOF, not of the XOF. The two happen to coincide
    /// with std's current defaults, and `preHashDigestLengthsAgreeWithStd`
    /// below asserts that they still do — if std ever changes a default, the
    /// build fails rather than silently signing a different digest.
    pub fn digestLength(self: PreHash) usize {
        return switch (self) {
            .sha2_224, .sha2_512_224, .sha3_224 => 28,
            .sha2_256, .sha2_512_256, .sha3_256 => 32,
            .sha2_384, .sha3_384 => 48,
            .sha2_512, .sha3_512 => 64,
            .shake_128 => 32, // SHAKE128(M, 256) — Algorithm 23 line 17
            .shake_256 => 64, // SHAKE256(M, 512) — Algorithm 23 line 20
        };
    }

    /// DER encoding of this function's OID, as `M'` requires it — tag and
    /// length included (FIPS 205 §10.2.2).
    pub fn oid(self: PreHash) [oid_length]u8 {
        var encoded: [oid_length]u8 = undefined;
        @memcpy(encoded[0..oid_prefix.len], &oid_prefix);
        encoded[oid_length - 1] = self.arc();
        return encoded;
    }

    /// `PH_M ← PH(M)`. Writes into `out` and returns the populated prefix,
    /// whose length is `digestLength()`.
    ///
    /// `out` is a caller-owned stack buffer sized for the largest approved
    /// digest, so no path here allocates.
    pub fn hash(self: PreHash, msg: []const u8, out: *[max_digest_length]u8) []const u8 {
        switch (self) {
            inline else => |ph| {
                const n = comptime ph.digestLength();
                comptime std.debug.assert(n <= max_digest_length);
                Impl(ph).hash(msg, out[0..n], .{});
                return out[0..n];
            },
        }
    }
};

test "preHashOidsMatchTheStandard" {
    // The four OIDs FIPS 205 §10.2.2 Algorithm 23 writes out verbatim, as
    // `toByte(0x…, 11)`. Checking these pins the shared prefix and the arc
    // encoding against the standard itself rather than against the CSOR
    // registry the other eight are read from.
    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 },
        &PreHash.sha2_256.oid(),
    );
    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 },
        &PreHash.sha2_512.oid(),
    );
    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B },
        &PreHash.shake_128.oid(),
    );
    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C },
        &PreHash.shake_256.oid(),
    );
}

test "preHashOidsAreDistinctAndWellFormed" {
    var seen = std.EnumSet(PreHash).initEmpty();
    var arcs: [12]u8 = undefined;
    var i: usize = 0;
    for (std.enums.values(PreHash)) |ph| {
        const encoded = ph.oid();
        // DER tag 0x06 (OBJECT IDENTIFIER), then a length covering the rest.
        try std.testing.expectEqual(@as(u8, 0x06), encoded[0]);
        try std.testing.expectEqual(@as(u8, oid_length - 2), encoded[1]);
        // No two functions may share an OID, or the domain separation that the
        // OID exists to provide would collapse.
        for (arcs[0..i]) |prior| try std.testing.expect(prior != encoded[oid_length - 1]);
        arcs[i] = encoded[oid_length - 1];
        i += 1;
        seen.insert(ph);
    }
    try std.testing.expectEqual(@as(usize, 12), seen.count());
}

test "preHashDigestLengthsAgreeWithStd" {
    // Guards the one place FIPS 205 and std could silently diverge: the XOFs,
    // whose output length the standard fixes independently of the primitive.
    inline for (comptime std.enums.values(PreHash)) |ph| {
        try std.testing.expectEqual(PreHash.Impl(ph).digest_length, ph.digestLength());
    }
}

test "preHashProducesKnownDigests" {
    // Spot-check against published values so a mis-wired `Impl` mapping cannot
    // pass unnoticed. SHA2-256 and SHAKE128 of "abc" are the standard NIST
    // examples; the SHAKE case also confirms the 256-bit output length.
    var buf: [max_digest_length]u8 = undefined;

    const sha256 = PreHash.sha2_256.hash("abc", &buf);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    }, sha256);

    const shake128 = PreHash.shake_128.hash("abc", &buf);
    try std.testing.expectEqual(@as(usize, 32), shake128.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x58, 0x81, 0x09, 0x2d, 0xd8, 0x18, 0xbf, 0x5c, 0xf8, 0xa3, 0xdd, 0xb7, 0x93, 0xfb, 0xcb, 0xa7,
        0x40, 0x97, 0xd5, 0xc5, 0x26, 0xa6, 0xd3, 0x5f, 0x97, 0xb8, 0x33, 0x51, 0x94, 0x0f, 0x2c, 0xc8,
    }, shake128);
}
