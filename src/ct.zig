//! Constant-time audit support — declassification hooks.
//!
//! Taint-tracking constant-time audits (ctgrind: Valgrind memcheck with the
//! secret key marked *undefined*) need one thing the source cannot otherwise
//! express — the points at which a secret-derived value becomes **public**.
//!
//! SLH-DSA needs this more than most schemes. Nearly every intermediate in a
//! signature descends from `SK.seed`, yet almost none of them are secret: the
//! FORS public key and each XMSS root are recomputed by any verifier from the
//! signature and the public key (FIPS 205 §9.3 Algorithm 20). Their base-`w`
//! digits set WOTS+ chain lengths (`wots.zig` — `chain`'s loop bound), so a
//! taint tracker that has not been told they are public reports a
//! secret-dependent branch on code that is constant-time. Declassifying them
//! at the point they are produced is what makes a whole-`sign` audit meaningful
//! instead of a wall of false positives.
//!
//! Zero-cost by default
//! --------------------
//! `declassify` lowers to nothing unless the module was compiled with Valgrind
//! client-request support (`.valgrind = true` in `build.zig`, which the ctgrind
//! harness sets; Zig also enables it for Debug builds on targets that support
//! it). Outside that, `audit_enabled` is `false` and the call disappears at
//! compile time — no runtime branch, no code, no behavioural difference. When
//! it *is* enabled the emitted sequence is Valgrind's no-op client request:
//! it changes memcheck's shadow state only, never program values or timing on
//! real hardware.
//!
//! Deliberately narrow
//! -------------------
//! Only values that a verifier can recompute from public data may be passed
//! here. Every call site names the FIPS 205 algorithm that makes the value
//! public. Over-declassifying does not slow anything down — it silently blinds
//! the audit, which is worse. See `docs/implementation/constant-time.md` and
//! issue #34.

const std = @import("std");
const builtin = @import("builtin");

/// Whether declassification markers are actually emitted. False in ordinary
/// builds, so `declassify` compiles away entirely.
///
/// The ctgrind harness asserts this matches its own setting at comptime: if
/// the library were built without Valgrind support while the harness taints,
/// the hooks below would be inert and the audit would drown in false
/// positives at `chain`.
pub const audit_enabled: bool = builtin.valgrind_support;

/// Mark `bytes` as public for a taint-tracking constant-time audit.
///
/// Call this only where the standard makes the value public — where a verifier
/// holding just the signature and the public key can recompute it. It has no
/// effect on program behaviour; it exists so that a constant-time audit
/// classifies the value the way FIPS 205 does.
pub inline fn declassify(bytes: []const u8) void {
    if (!audit_enabled) return;
    std.valgrind.memcheck.makeMemDefined(bytes);
}

test "declassify never alters the data it marks" {
    // The whole premise of putting these calls in production code is that they
    // are semantically invisible. Under a Valgrind-enabled build this also
    // exercises the client request itself.
    var buf = [_]u8{ 1, 2, 3, 4 };
    declassify(&buf);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4 }, &buf);

    // Const data and empty slices are both legal arguments.
    const fixed = [_]u8{0xAA} ** 8;
    declassify(&fixed);
    declassify(buf[0..0]);
}
