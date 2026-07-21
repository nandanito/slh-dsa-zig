//! FIPS 205 §3 — Notation and supporting functions.
//!
//! Pure-function helpers used across the WOTS+, FORS, XMSS, and hypertree
//! layers. Nothing here touches secret material directly, but several
//! callers do; treat constant-time discipline as a contract on callers
//! and keep these helpers branch-free where the input may contain secret
//! bits.

const std = @import("std");

/// FIPS 205 Algorithm 4 — base_2b.
///
/// Converts a byte string into a sequence of base-2^b integers. Used by
/// WOTS+ to decompose a message hash into base-w (w = 2^lg_w) chain
/// indices, and by FORS to decompose a digest into k indices of bit-length
/// a.
///
/// Constraints:
///   - b in {1, 2, 4, 8, 12, 14, 16} for FIPS 205 usage
///   - X.len * 8 >= out_len * b
///
/// Constant-time: yes — the loop bounds and shifts are public.
pub fn base_2b(input: []const u8, comptime b: u6, out: []u32) void {
    std.debug.assert(input.len * 8 >= out.len * b);

    var in_idx: usize = 0;
    var bits: u32 = 0;
    var total: u32 = 0;

    for (out) |*v| {
        while (bits < b) {
            total = (total << 8) | @as(u32, input[in_idx]);
            in_idx += 1;
            bits += 8;
        }
        bits -= b;
        v.* = (total >> @as(u5, @intCast(bits))) & ((@as(u32, 1) << @as(u5, b)) - 1);
    }
}

/// FIPS 205 Algorithm 3 — toByte (limited form).
///
/// Encodes a non-negative integer `x` into `len` big-endian bytes.
///
/// Constant-time: yes — the loop bound is public.
pub fn toByte(x: u64, out: []u8) void {
    var value = x;
    var i: usize = out.len;
    while (i > 0) {
        i -= 1;
        out[i] = @intCast(value & 0xff);
        value >>= 8;
    }
    std.debug.assert(value == 0); // overflow — bumped past buffer
}

// -----------------------------------------------------------------------------
// Tests — values cross-checked against FIPS 205 §3 worked examples and against
// PQClean's `base_w` reference output.
// -----------------------------------------------------------------------------

test "base_2b: b=4 decomposes one byte to two nibbles" {
    var out: [4]u32 = undefined;
    base_2b(&[_]u8{ 0x12, 0x34 }, 4, &out);
    try std.testing.expectEqualSlices(u32, &[_]u32{ 1, 2, 3, 4 }, &out);
}

test "base_2b: b=8 round-trips bytes" {
    const input = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    var out: [4]u32 = undefined;
    base_2b(&input, 8, &out);
    try std.testing.expectEqualSlices(u32, &[_]u32{ 0xde, 0xad, 0xbe, 0xef }, &out);
}

test "base_2b: b=12 packs three nibbles per value" {
    // 0x123 0x456 0x789 in 12-bit groups
    const input = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc };
    var out: [4]u32 = undefined;
    base_2b(&input, 12, &out);
    try std.testing.expectEqualSlices(u32, &[_]u32{ 0x123, 0x456, 0x789, 0xabc }, &out);
}

test "toByte: pads to length" {
    var out: [4]u8 = undefined;
    toByte(0x12345678, &out);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x12, 0x34, 0x56, 0x78 }, &out);

    toByte(1, out[0..1]);
    try std.testing.expectEqual(@as(u8, 1), out[0]);
}
