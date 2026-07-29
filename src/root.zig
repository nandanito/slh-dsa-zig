//! slh-dsa-zig — Pure-Zig SLH-DSA (FIPS 205).
//!
//! See README.md for an overview, ARCHITECTURE.md for the layering, and
//! SECURITY.md for the threat model and current limitations.
//!
//! > 🚧 EXPERIMENTAL — DO NOT USE IN PRODUCTION.
//!
//! Public entry points:
//!   const slh_dsa = @import("slh_dsa");
//!   const Scheme = slh_dsa.Slh_Dsa(.slh_dsa_shake_128s);
//!   const kp = try Scheme.KeyPair.generate(io);
//!
//! Available parameter sets are listed by `slh_dsa.ParamSet`.

const std = @import("std");

// -- Public API -----------------------------------------------------------

const slh_dsa_mod = @import("slh_dsa.zig");

pub const ParamSet = slh_dsa_mod.ParamSet;
pub const Error = slh_dsa_mod.Error;
pub const Slh_Dsa = slh_dsa_mod.Slh_Dsa;

// -- Internal modules re-exported for in-tree testing only ---------------
//
// These are not part of the stable public API. They are exposed here so
// `zig build test` runs the tests in each module; downstream code should
// not depend on these paths.

pub const internal = struct {
    pub const ct = @import("ct.zig");
    pub const params = @import("params.zig");
    pub const util = @import("util.zig");
    pub const address = @import("address.zig");
    pub const hash = @import("hash.zig");
    pub const hash_sha2 = @import("hash_sha2.zig");
    pub const hash_shake = @import("hash_shake.zig");
    pub const wots = @import("wots.zig");
    pub const xmss = @import("xmss.zig");
    pub const hypertree = @import("hypertree.zig");
    pub const fors = @import("fors.zig");
};

// -- Test surface ---------------------------------------------------------
//
// Pull every module into the test graph so `zig build test` runs them all.

test {
    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(internal);
}
