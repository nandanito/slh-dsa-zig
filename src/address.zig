//! FIPS 205 §4.2 — ADRS types and §11.2 — compressed ADRS encoding.
//!
//! ADRS ("address") is the 22-byte structure passed to every keyed hash call
//! that disambiguates *which* hash a given output corresponds to. Without
//! ADRS, internal SLH-DSA hashes would collide across different nodes and
//! the security argument would collapse.
//!
//! FIPS 205 defines a 32-byte and a 22-byte (compressed) encoding. The
//! compressed encoding is mandatory for SHA-2 instances and acceptable for
//! SHAKE; we use it throughout for consistency.
//!
//! Encoding (FIPS 205 §11.2):
//!
//!   offset  field                bytes
//!   ──────  ──────────────────── ─────
//!   0       layer address         1
//!   1       tree address          8
//!   9       type                  1
//!   10      type-specific (12B; 3 × 4B fields)
//!
//! The type field selects what the three 4-byte slots at offset 10 mean. The
//! mapping is fully prescribed by FIPS 205 §4.2 Table 1 and §11.2.

const std = @import("std");

/// FIPS 205 §4.2 Table 1 — ADRS type values.
pub const AdrsType = enum(u8) {
    wots_hash = 0,
    wots_pk = 1,
    tree = 2,
    fors_tree = 3,
    fors_roots = 4,
    wots_prf = 5,
    fors_prf = 6,
};

/// The compressed ADRS encoding. 22 bytes.
pub const Adrs = struct {
    pub const length: usize = 22;

    bytes: [length]u8 = std.mem.zeroes([length]u8),

    /// Construct a zeroed ADRS.
    pub fn init() Adrs {
        return .{};
    }

    /// Set the 1-byte layer address.
    pub fn setLayer(self: *Adrs, layer: u8) void {
        self.bytes[0] = layer;
    }

    /// Set the 8-byte tree address (big-endian).
    pub fn setTreeAddress(self: *Adrs, tree_address: u64) void {
        std.mem.writeInt(u64, self.bytes[1..9], tree_address, .big);
    }

    /// Set the ADRS type. Calling this clears the type-specific bytes
    /// (FIPS 205 §4.3: "the remaining fields of ADRS shall be set to zero
    /// before storing the type-specific fields").
    pub fn setType(self: *Adrs, t: AdrsType) void {
        self.bytes[9] = @intFromEnum(t);
        @memset(self.bytes[10..22], 0);
    }

    // -- Type-specific accessors -------------------------------------------
    //
    // Per FIPS 205 §4.2 the three 4-byte slots at offsets 10, 14, 18 are
    // labelled differently per type. We expose typed setters/getters so
    // the right name appears at every call site, avoiding the kind of
    // mistake (e.g. using a key-pair address where a tree height was
    // expected) that would silently break the security argument.

    // WOTS_HASH / WOTS_PK / WOTS_PRF: keyPair / chain / hash addresses.
    pub fn setKeyPairAddress(self: *Adrs, key_pair_address: u32) void {
        std.mem.writeInt(u32, self.bytes[10..14], key_pair_address, .big);
    }
    pub fn getKeyPairAddress(self: Adrs) u32 {
        return std.mem.readInt(u32, self.bytes[10..14], .big);
    }
    pub fn setChainAddress(self: *Adrs, chain_address: u32) void {
        std.mem.writeInt(u32, self.bytes[14..18], chain_address, .big);
    }
    pub fn setHashAddress(self: *Adrs, hash_address: u32) void {
        std.mem.writeInt(u32, self.bytes[18..22], hash_address, .big);
    }

    // TREE / FORS_TREE: tree height / tree index.
    pub fn setTreeHeight(self: *Adrs, tree_height: u32) void {
        std.mem.writeInt(u32, self.bytes[14..18], tree_height, .big);
    }
    pub fn setTreeIndex(self: *Adrs, tree_index: u32) void {
        std.mem.writeInt(u32, self.bytes[18..22], tree_index, .big);
    }
    pub fn getTreeIndex(self: Adrs) u32 {
        return std.mem.readInt(u32, self.bytes[18..22], .big);
    }

    /// Borrow a const slice over the canonical bytes for passing to a hash.
    pub fn slice(self: *const Adrs) []const u8 {
        return &self.bytes;
    }

    /// Expand the 22-byte compressed ADRSc back to the 32-byte full ADRS
    /// required by the SHAKE instantiations.
    ///
    /// FIPS 205 §11.1 hashes the full 32-byte ADRS (layer | tree | type |
    /// type-specific, with the wider field widths). §11.2 §"compressed
    /// version of ADRS" defines the compression as
    ///
    ///     ADRSc = ADRS[3] ∥ ADRS[8:16] ∥ ADRS[19] ∥ ADRS[20:32]
    ///
    /// so the inverse — zero-padding the dropped high-order bytes of layer,
    /// tree, and type — reconstructs an ADRS that is byte-identical to what
    /// the SHAKE formulas in §11.1 expect, *provided* no setter ever wrote
    /// into those high-order bytes. The accessors in this module only take
    /// a `u8` layer, `u64` tree, and `u8` type, so that precondition holds
    /// by construction.
    ///
    /// Output layout (FIPS 205 §4.2):
    ///   offset  bytes  field
    ///   ──────  ─────  ─────────────────────────
    ///   0       4      layer address (big-endian u32, low byte = ADRSc[0])
    ///   4       12     tree address  (big-endian, low 8 bytes = ADRSc[1:9])
    ///   16      4      type          (big-endian u32, low byte = ADRSc[9])
    ///   20      12     type-specific (= ADRSc[10:22])
    pub fn expand(self: Adrs) [32]u8 {
        var out = std.mem.zeroes([32]u8);
        out[3] = self.bytes[0];
        @memcpy(out[8..16], self.bytes[1..9]);
        out[19] = self.bytes[9];
        @memcpy(out[20..32], self.bytes[10..22]);
        return out;
    }
};

// -----------------------------------------------------------------------------
// Tests — encoding cross-checks. Reference values are taken from FIPS 205
// §11.2 worked examples; specific bit positions verified against PQClean.
// -----------------------------------------------------------------------------

test "ADRS zero-init" {
    const a = Adrs.init();
    var expected = std.mem.zeroes([22]u8);
    try std.testing.expectEqualSlices(u8, &expected, &a.bytes);
}

test "ADRS setLayer + setTreeAddress big-endian layout" {
    var a = Adrs.init();
    a.setLayer(0x07);
    a.setTreeAddress(0x0102030405060708);
    try std.testing.expectEqual(@as(u8, 0x07), a.bytes[0]);
    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
        a.bytes[1..9],
    );
}

test "setType clears type-specific bytes" {
    var a = Adrs.init();
    a.setKeyPairAddress(0xDEADBEEF);
    a.setType(.tree);
    try std.testing.expectEqual(@as(u8, @intFromEnum(AdrsType.tree)), a.bytes[9]);
    for (a.bytes[10..22]) |b| try std.testing.expectEqual(@as(u8, 0), b);
}

test "tree index round-trips" {
    var a = Adrs.init();
    a.setType(.tree);
    a.setTreeIndex(0x12345678);
    try std.testing.expectEqual(@as(u32, 0x12345678), a.getTreeIndex());
}

test "expand: zero ADRSc maps to zero ADRS" {
    const a = Adrs.init();
    const full = a.expand();
    const zero = std.mem.zeroes([32]u8);
    try std.testing.expectEqualSlices(u8, &zero, &full);
}

test "expand: byte positions match FIPS 205 §11.2 layout" {
    // Build a recognisable ADRSc: each meaningful byte set to a distinct
    // value so we can read it off the expanded layout unambiguously.
    var a = Adrs.init();
    a.setLayer(0x7A);
    a.setTreeAddress(0x0102030405060708);
    a.setType(.fors_tree);
    a.setKeyPairAddress(0xAABBCCDD);
    a.setChainAddress(0x11223344);
    a.setHashAddress(0x55667788);

    const full = a.expand();

    // ADRS[0..3] = 0 (high-order bytes of the u32 layer address).
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0 }, full[0..3]);
    // ADRS[3] = ADRSc[0] = layer.
    try std.testing.expectEqual(@as(u8, 0x7A), full[3]);
    // ADRS[4..8] = 0 (high-order bytes of the 12-byte tree address).
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0 }, full[4..8]);
    // ADRS[8..16] = ADRSc[1..9] = 8-byte tree address.
    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
        full[8..16],
    );
    // ADRS[16..19] = 0 (high-order bytes of the u32 type).
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0 }, full[16..19]);
    // ADRS[19] = ADRSc[9] = type.
    try std.testing.expectEqual(@as(u8, @intFromEnum(AdrsType.fors_tree)), full[19]);
    // ADRS[20..32] = ADRSc[10..22] = the three 4-byte type-specific slots.
    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 },
        full[20..32],
    );
}

test "expand: round-trips back to ADRSc per FIPS 205 §11.2" {
    // Exercise every typed setter so each byte of ADRSc is non-zero.
    var a = Adrs.init();
    a.setLayer(0xAB);
    a.setTreeAddress(0xDEADBEEFCAFEBABE);
    a.setType(.wots_hash);
    a.setKeyPairAddress(0x01020304);
    a.setChainAddress(0x05060708);
    a.setHashAddress(0x090A0B0C);

    const full = a.expand();

    // Recompress per ADRSc = ADRS[3] ∥ ADRS[8:16] ∥ ADRS[19] ∥ ADRS[20:32].
    var recompressed: [22]u8 = undefined;
    recompressed[0] = full[3];
    @memcpy(recompressed[1..9], full[8..16]);
    recompressed[9] = full[19];
    @memcpy(recompressed[10..22], full[20..32]);

    try std.testing.expectEqualSlices(u8, &a.bytes, &recompressed);
}
