//! Negative control for the constant-time gate (Lane A). This harness
//! DELIBERATELY leaks: it taints a byte and then branches on it, so Valgrind
//! MUST report it. The ctgrind workflow runs this expecting a failure.
//!
//! Why it exists: if the std.valgrind client requests ever compile to no-ops
//! (e.g. a release build without `.valgrind = true`), `makeMemUndefined`
//! becomes inert, the real check (`taint_components.zig`) taints nothing, and the
//! gate passes vacuously. This control catches exactly that: it can only be
//! flagged if the taint machinery is live, so the workflow treats a *clean*
//! run here as a broken gate and fails the job. That guarantee matters because
//! Valgrind cannot run on the maintainer's macOS/Apple-Silicon box — CI is the
//! only place the check runs at all. Issue #34.

const std = @import("std");

pub fn main(init: std.process.Init) !void {
    // A DEFINED byte from the OS RNG: memcheck would not flag it on its own,
    // so a report below can only come from the taint marker taking effect.
    var secret: [1]u8 = undefined;
    try init.io.randomSecure(&secret);

    // The exact client request the real harness relies on. If it is a no-op,
    // `secret` stays defined and the branch below is NOT reported.
    std.valgrind.memcheck.makeMemUndefined(&secret);

    // Secret-dependent control flow: a loop whose bound is the tainted byte.
    // A loop (not an `if`) can't be lowered to a branchless `cmov`, so the
    // conditional jump genuinely depends on secret data — the canonical
    // constant-time violation memcheck reports.
    var acc: u32 = 0;
    var i: u8 = 0;
    while (i < (secret[0] & 0x0f)) : (i += 1) acc +%= i;
    std.mem.doNotOptimizeAway(acc);
}
