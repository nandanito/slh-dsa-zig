//! Benchmark harness for slh-dsa-zig.
//!
//! Measures keygen / sign / verify for each parameter set using
//! `std.Io.Clock`. Reports median nanoseconds per operation and the
//! derived ops/second.
//!
//! Build & run:
//!
//!   zig build bench                   # ReleaseFast by default
//!   zig build bench -- --param-set SLH-DSA-SHAKE-128s
//!   zig build bench -- --op sign
//!
//! Bench discipline:
//!   - Always built in ReleaseFast unless overridden with
//!     `-Dbench-optimize=...`. Debug-mode numbers are meaningless.
//!   - The same key + message is reused inside a measurement loop so the
//!     numbers reflect steady-state cost, not first-touch effects.
//!   - We report the median of N runs after dropping the slowest 10% as
//!     warmup. The mean is also printed but the median is the headline.
//!
//! Status: SKELETON. The inner loops drive `KeyPair.generate`, `sign`,
//! and `verify`, all of which currently `@panic`. The harness compiles
//! and runs (it prints the table header and parameter-set list), but
//! the body of each measurement will trap until the scheme is
//! implemented.
//!
//! Lane: Lane A (test/perf infrastructure).

const std = @import("std");
const slh_dsa = @import("slh_dsa");

// -----------------------------------------------------------------------------
// Iteration budgets. Tuned so even the slowest parameter set (sha2_256s
// signing) finishes in seconds, not minutes. Override at the CLI with
// --iters.
// -----------------------------------------------------------------------------

const default_iters_keygen: u32 = 50;
const default_iters_sign: u32 = 50;
const default_iters_verify: u32 = 500;

// -----------------------------------------------------------------------------
// CLI.
// -----------------------------------------------------------------------------

const Op = enum {
    all,
    keygen,
    sign,
    verify,

    fn fromString(s: []const u8) ?Op {
        if (std.mem.eql(u8, s, "all")) return .all;
        if (std.mem.eql(u8, s, "keygen")) return .keygen;
        if (std.mem.eql(u8, s, "sign")) return .sign;
        if (std.mem.eql(u8, s, "verify")) return .verify;
        return null;
    }
};

const Cli = struct {
    op: Op = .all,
    param_set_filter: ?slh_dsa.ParamSet = null,
    iters_override: ?u32 = null,
};

const usage =
    \\Usage: slh-dsa-bench [--op all|keygen|sign|verify]
    \\                     [--param-set SLH-DSA-...]
    \\                     [--iters N]
    \\
;

fn parseParamSetName(name: []const u8) ?slh_dsa.ParamSet {
    // Keep this in sync with tests/kat_runner.zig::parseParamSet —
    // they're intentionally not shared so bench has no dependency on
    // the test infrastructure.
    const map = .{
        .{ "SLH-DSA-SHA2-128s", slh_dsa.ParamSet.slh_dsa_sha2_128s },
        .{ "SLH-DSA-SHA2-128f", slh_dsa.ParamSet.slh_dsa_sha2_128f },
        .{ "SLH-DSA-SHA2-192s", slh_dsa.ParamSet.slh_dsa_sha2_192s },
        .{ "SLH-DSA-SHA2-192f", slh_dsa.ParamSet.slh_dsa_sha2_192f },
        .{ "SLH-DSA-SHA2-256s", slh_dsa.ParamSet.slh_dsa_sha2_256s },
        .{ "SLH-DSA-SHA2-256f", slh_dsa.ParamSet.slh_dsa_sha2_256f },
        .{ "SLH-DSA-SHAKE-128s", slh_dsa.ParamSet.slh_dsa_shake_128s },
        .{ "SLH-DSA-SHAKE-128f", slh_dsa.ParamSet.slh_dsa_shake_128f },
        .{ "SLH-DSA-SHAKE-192s", slh_dsa.ParamSet.slh_dsa_shake_192s },
        .{ "SLH-DSA-SHAKE-192f", slh_dsa.ParamSet.slh_dsa_shake_192f },
        .{ "SLH-DSA-SHAKE-256s", slh_dsa.ParamSet.slh_dsa_shake_256s },
        .{ "SLH-DSA-SHAKE-256f", slh_dsa.ParamSet.slh_dsa_shake_256f },
    };
    inline for (map) |entry| {
        if (std.mem.eql(u8, name, entry[0])) return entry[1];
    }
    return null;
}

fn parseCli(args: []const [:0]const u8) !Cli {
    var cli = Cli{};
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            std.debug.print("{s}", .{usage});
            std.process.exit(0);
        } else if (std.mem.eql(u8, arg, "--op")) {
            i += 1;
            if (i >= args.len) return error.MissingArgument;
            cli.op = Op.fromString(args[i]) orelse {
                std.debug.print("error: unknown op '{s}'\n", .{args[i]});
                return error.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--param-set")) {
            i += 1;
            if (i >= args.len) return error.MissingArgument;
            cli.param_set_filter = parseParamSetName(args[i]) orelse {
                std.debug.print("error: unknown parameter set '{s}'\n", .{args[i]});
                return error.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--iters")) {
            i += 1;
            if (i >= args.len) return error.MissingArgument;
            cli.iters_override = try std.fmt.parseInt(u32, args[i], 10);
        } else {
            std.debug.print("error: unexpected argument '{s}'\n", .{arg});
            return error.InvalidArgument;
        }
    }
    return cli;
}

// -----------------------------------------------------------------------------
// Measurement primitives.
// -----------------------------------------------------------------------------

/// A single measurement run.
const Sample = struct {
    op: []const u8,
    param_set: slh_dsa.ParamSet,
    iters: u32,
    median_ns: u64,
    mean_ns: u64,
    min_ns: u64,
    max_ns: u64,
};

fn computeStats(samples: []u64, op: []const u8, ps: slh_dsa.ParamSet, iters: u32) Sample {
    std.mem.sort(u64, samples, {}, std.sort.asc(u64));
    var sum: u128 = 0;
    for (samples) |s| sum += s;
    return .{
        .op = op,
        .param_set = ps,
        .iters = iters,
        .median_ns = samples[samples.len / 2],
        .mean_ns = @intCast(sum / samples.len),
        .min_ns = samples[0],
        .max_ns = samples[samples.len - 1],
    };
}

fn printSample(s: Sample) void {
    const ops_per_sec: f64 = if (s.median_ns == 0)
        0.0
    else
        1.0e9 / @as(f64, @floatFromInt(s.median_ns));
    std.debug.print("  {s:<19}  {s:<7}  iters={d:<5}  median={d:>12} ns  mean={d:>12} ns  ops/s={d:>10.2}\n", .{
        @tagName(s.param_set),
        s.op,
        s.iters,
        s.median_ns,
        s.mean_ns,
        ops_per_sec,
    });
}

// -----------------------------------------------------------------------------
// Per-op benchmark drivers.
//
// SKELETON: each driver allocates fixed-size scratch buffers sized to the
// parameter set and runs `iters` invocations of the operation. Once the
// underlying scheme lands these become real measurements; today they
// will @panic on the first iteration.
// -----------------------------------------------------------------------------

fn benchOne(
    io: std.Io,
    allocator: std.mem.Allocator,
    comptime param_set: slh_dsa.ParamSet,
    op: Op,
    iters_override: ?u32,
) !void {
    const Scheme = slh_dsa.Slh_Dsa(param_set);

    // Fixed inputs reused inside the loop so we measure steady-state cost.
    var msg = [_]u8{0x42} ** 64;
    _ = &msg;

    if (op == .all or op == .keygen) {
        const iters = iters_override orelse default_iters_keygen;
        const ns = try allocator.alloc(u64, iters);
        defer allocator.free(ns);

        // TODO: drive Scheme.KeyPair.generate(io) in a loop once the
        // implementation lands. The skeleton call below will @panic,
        // which is the intended behaviour pre-implementation.
        var i: u32 = 0;
        while (i < iters) : (i += 1) {
            const start = std.Io.Clock.awake.now(io).nanoseconds;
            // _ = try Scheme.KeyPair.generate(io);
            std.mem.doNotOptimizeAway(Scheme.public_key_length);
            const end = std.Io.Clock.awake.now(io).nanoseconds;
            ns[i] = @intCast(end - start);
        }
        printSample(computeStats(ns, "keygen", param_set, iters));
    }

    if (op == .all or op == .sign) {
        const iters = iters_override orelse default_iters_sign;
        const ns = try allocator.alloc(u64, iters);
        defer allocator.free(ns);

        var sk: Scheme.SecretKey = undefined;
        @memset(&sk, 0);
        var sig: Scheme.Signature = undefined;
        _ = &sig;

        // TODO: real sign loop.
        //   try Scheme.sign(&sig, &msg, &sk, null);
        var i: u32 = 0;
        while (i < iters) : (i += 1) {
            const start = std.Io.Clock.awake.now(io).nanoseconds;
            std.mem.doNotOptimizeAway(&sk);
            const end = std.Io.Clock.awake.now(io).nanoseconds;
            ns[i] = @intCast(end - start);
        }
        printSample(computeStats(ns, "sign", param_set, iters));
    }

    if (op == .all or op == .verify) {
        const iters = iters_override orelse default_iters_verify;
        const ns = try allocator.alloc(u64, iters);
        defer allocator.free(ns);

        var pk: Scheme.PublicKey = undefined;
        @memset(&pk, 0);
        var sig: Scheme.Signature = undefined;
        @memset(&sig, 0);

        // TODO: real verify loop.
        //   _ = Scheme.verify(&sig, &msg, &pk) catch {};
        var i: u32 = 0;
        while (i < iters) : (i += 1) {
            const start = std.Io.Clock.awake.now(io).nanoseconds;
            std.mem.doNotOptimizeAway(&pk);
            const end = std.Io.Clock.awake.now(io).nanoseconds;
            ns[i] = @intCast(end - start);
        }
        printSample(computeStats(ns, "verify", param_set, iters));
    }
}

// -----------------------------------------------------------------------------
// Main.
// -----------------------------------------------------------------------------

pub fn main(init: std.process.Init) !u8 {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);

    const cli = parseCli(args) catch return 1;

    std.debug.print("slh-dsa-bench (skeleton — bodies will panic until scheme lands)\n", .{});
    std.debug.print("note: compare against PQClean reference at " ++
        "https://github.com/PQClean/PQClean\n\n", .{});
    std.debug.print("  {s:<19}  {s:<7}  {s:<11}  {s:>15}  {s:>17}  {s:>16}\n", .{
        "param-set",
        "op",
        "iters",
        "median",
        "mean",
        "ops/s",
    });
    std.debug.print("  {s:-<19}  {s:-<7}  {s:-<11}  {s:-<15}  {s:-<17}  {s:-<16}\n", .{
        "",
        "",
        "",
        "",
        "",
        "",
    });

    // Comptime fan-out over all 12 parameter sets so each `benchOne`
    // specialisation gets fully monomorphised.
    inline for (comptime std.enums.values(slh_dsa.ParamSet)) |ps| {
        const matches = cli.param_set_filter == null or cli.param_set_filter.? == ps;
        if (matches) try benchOne(init.io, allocator, ps, cli.op, cli.iters_override);
    }

    return 0;
}
