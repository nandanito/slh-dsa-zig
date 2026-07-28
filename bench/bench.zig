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
//!   - We report the median of the N per-iteration samples; the mean, min
//!     and max are also computed, but the median is the headline because it
//!     is the statistic least disturbed by scheduler jitter and page faults.
//!     No samples are discarded — the median already discounts the warmup
//!     iteration rather than us picking a trim fraction by hand.
//!
//! Comparison baseline: the 2× performance gate (CLAUDE.md discipline
//! table, README "Cryptographic discipline" item 6) is pinned to
//! PQClean's portable `clean` variant, *not* its AVX2 path. See
//! bench/README.md for the methodology and the recorded reference
//! commit; AVX2 numbers are reported for honesty but never gated on.
//!
//! Lane: Lane A (test/perf infrastructure).

const std = @import("std");
const builtin = @import("builtin");
const slh_dsa = @import("slh_dsa");

// -----------------------------------------------------------------------------
// Iteration budgets. Chosen from measured timings so that a no-arg
// `zig build bench` (all ops, all 12 sets) finishes in tens of seconds, not
// minutes. Override at the CLI with --iters.
//
// The "small-signature" (`s`) parameter sets sign ~20–100× slower than their
// "fast" (`f`) siblings — fewer hypertree layers means taller subtrees and
// far more WOTS+ work per signature — so they get smaller budgets. Verify is
// cheap for every set, so its budget is uniform. For tighter medians on a
// single set, pass a larger --iters.
// -----------------------------------------------------------------------------

const IterBudget = struct { keygen: u32, sign: u32, verify: u32 };

const fast_budget: IterBudget = .{ .keygen = 50, .sign = 50, .verify = 500 };
const small_budget: IterBudget = .{ .keygen = 20, .sign = 5, .verify = 500 };

/// The `s` variants are the "small-signature / slow-signing" sets; the tag
/// suffix (`...128s` vs `...128f`) is the canonical discriminator (FIPS 205
/// §11 naming; see src/params.zig ParamSet doc comment).
fn defaultBudget(comptime param_set: slh_dsa.ParamSet) IterBudget {
    const name = @tagName(param_set);
    return if (name[name.len - 1] == 's') small_budget else fast_budget;
}

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
    csv: bool = false,
};

const usage =
    \\Usage: slh-dsa-bench [--op all|keygen|sign|verify]
    \\                     [--param-set SLH-DSA-...]
    \\                     [--iters N]
    \\                     [--csv]
    \\
    \\--csv emits machine-readable rows for joining against an external
    \\reference run (see bench/pqclean/run.sh, which emits the same schema).
    \\
;

/// Canonical FIPS 205 §11 parameter-set names, paired with their enum tags.
///
/// Used both to parse `--param-set` and to label `--csv` rows. The CSV must
/// print this spelling rather than `@tagName` so its rows join directly
/// against the PQClean reference harness, which emits the same names.
///
/// Keep in sync with tests/kat_runner.zig::parseParamSet — they're
/// intentionally not shared so bench has no dependency on the test
/// infrastructure.
const param_set_names = [_]struct { []const u8, slh_dsa.ParamSet }{
    .{ "SLH-DSA-SHA2-128s", .slh_dsa_sha2_128s },
    .{ "SLH-DSA-SHA2-128f", .slh_dsa_sha2_128f },
    .{ "SLH-DSA-SHA2-192s", .slh_dsa_sha2_192s },
    .{ "SLH-DSA-SHA2-192f", .slh_dsa_sha2_192f },
    .{ "SLH-DSA-SHA2-256s", .slh_dsa_sha2_256s },
    .{ "SLH-DSA-SHA2-256f", .slh_dsa_sha2_256f },
    .{ "SLH-DSA-SHAKE-128s", .slh_dsa_shake_128s },
    .{ "SLH-DSA-SHAKE-128f", .slh_dsa_shake_128f },
    .{ "SLH-DSA-SHAKE-192s", .slh_dsa_shake_192s },
    .{ "SLH-DSA-SHAKE-192f", .slh_dsa_shake_192f },
    .{ "SLH-DSA-SHAKE-256s", .slh_dsa_shake_256s },
    .{ "SLH-DSA-SHAKE-256f", .slh_dsa_shake_256f },
};

fn parseParamSetName(name: []const u8) ?slh_dsa.ParamSet {
    for (param_set_names) |entry| {
        if (std.mem.eql(u8, name, entry[0])) return entry[1];
    }
    return null;
}

fn canonicalName(ps: slh_dsa.ParamSet) []const u8 {
    for (param_set_names) |entry| {
        if (entry[1] == ps) return entry[0];
    }
    unreachable; // Exhaustiveness is asserted below.
}

comptime {
    // Makes `canonicalName`'s `unreachable` sound, and catches a parameter set
    // added to src/params.zig without a name here (which would otherwise only
    // surface as a panic mid-benchmark).
    if (param_set_names.len != std.enums.values(slh_dsa.ParamSet).len) {
        @compileError("param_set_names does not cover every ParamSet tag");
    }
    for (std.enums.values(slh_dsa.ParamSet)) |ps| {
        var found = false;
        for (param_set_names) |entry| {
            if (entry[1] == ps) found = true;
        }
        if (!found) @compileError("missing canonical name for " ++ @tagName(ps));
    }
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
        } else if (std.mem.eql(u8, arg, "--csv")) {
            cli.csv = true;
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

/// Emits one measurement. `csv_out` non-null selects the machine-readable
/// form, which goes to stdout (it is data); the human table stays on stderr
/// via `std.debug.print`, so `--csv` output can be piped without the
/// progress chatter mixing in.
fn printSample(s: Sample, csv_out: ?*std.Io.Writer) !void {
    if (csv_out) |out| {
        // Schema shared with bench/pqclean/run.sh so the two runs join on
        // (param_set, op). Keep the column order identical in both.
        try out.print("slh-dsa-zig,{s},{s},{d},{d},{d},{d},{d}\n", .{
            canonicalName(s.param_set),
            s.op,
            s.iters,
            s.median_ns,
            s.mean_ns,
            s.min_ns,
            s.max_ns,
        });
        return;
    }
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
// Each driver allocates a fixed-size sample buffer sized to the iteration
// count and runs `iters` invocations of the operation, timing each with
// `std.Io.Clock.awake`. Inputs are set up once and reused across the loop so
// the numbers reflect steady-state cost, and every result is kept live with
// `std.mem.doNotOptimizeAway` so the optimiser cannot DCE the operation.
// -----------------------------------------------------------------------------

fn benchOne(
    io: std.Io,
    allocator: std.mem.Allocator,
    comptime param_set: slh_dsa.ParamSet,
    op: Op,
    iters_override: ?u32,
    csv_out: ?*std.Io.Writer,
) !void {
    const Scheme = slh_dsa.Slh_Dsa(param_set);
    const n = Scheme.params.n;
    const budget = comptime defaultBudget(param_set);

    // Fixed message reused across every measurement loop for this parameter
    // set, so we capture steady-state cost, not first-touch effects.
    const msg = [_]u8{0x42} ** 64;

    if (op == .all or op == .keygen) {
        const iters = iters_override orelse budget.keygen;
        const ns = try allocator.alloc(u64, iters);
        defer allocator.free(ns);

        // Draw fresh key material each iteration from the real CSPRNG — this
        // is the cost callers actually pay. An entropy failure aborts the
        // bench (surfaced as error.IoError) rather than reporting a bogus number.
        var i: u32 = 0;
        while (i < iters) : (i += 1) {
            const start = std.Io.Clock.awake.now(io).nanoseconds;
            const kp = try Scheme.KeyPair.generate(io);
            const end = std.Io.Clock.awake.now(io).nanoseconds;
            std.mem.doNotOptimizeAway(&kp);
            ns[i] = @intCast(end - start);
        }
        try printSample(computeStats(ns, "keygen", param_set, iters), csv_out);
    }

    // Sign and verify share a deterministic keypair. `fromSeeds` needs no
    // entropy, so the setup is reproducible run to run and independent of the
    // keygen loop above.
    if (op == .all or op == .sign or op == .verify) {
        var sk_seed: [n]u8 = undefined;
        var sk_prf: [n]u8 = undefined;
        var pk_seed: [n]u8 = undefined;
        for (&sk_seed, 0..) |*b, i| b.* = @intCast(0x11 + i);
        for (&sk_prf, 0..) |*b, i| b.* = @intCast(0x55 + i);
        for (&pk_seed, 0..) |*b, i| b.* = @intCast(0x99 + i);
        // Local seed copies are secret; fromSeeds retains them in the SK by
        // design, but scrub these stack buffers once we're done with them.
        defer std.crypto.secureZero(u8, &sk_seed);
        defer std.crypto.secureZero(u8, &sk_prf);
        const kp = try Scheme.KeyPair.fromSeeds(&sk_seed, &sk_prf, &pk_seed);

        // Fixed per-signature randomiser: measures the randomised (default)
        // signing path without paying the RNG cost inside the timed loop.
        var opt_rand: [n]u8 = undefined;
        for (&opt_rand, 0..) |*b, i| b.* = @intCast(0xE1 ^ i);

        if (op == .all or op == .sign) {
            const iters = iters_override orelse budget.sign;
            const ns = try allocator.alloc(u64, iters);
            defer allocator.free(ns);

            var sig: Scheme.Signature = undefined;
            var i: u32 = 0;
            while (i < iters) : (i += 1) {
                const start = std.Io.Clock.awake.now(io).nanoseconds;
                try Scheme.sign(&sig, &msg, &kp.secret_key, &opt_rand);
                const end = std.Io.Clock.awake.now(io).nanoseconds;
                std.mem.doNotOptimizeAway(&sig);
                ns[i] = @intCast(end - start);
            }
            try printSample(computeStats(ns, "sign", param_set, iters), csv_out);
        }

        if (op == .all or op == .verify) {
            const iters = iters_override orelse budget.verify;
            const ns = try allocator.alloc(u64, iters);
            defer allocator.free(ns);

            // A valid signature to verify, produced once outside the loop.
            var sig: Scheme.Signature = undefined;
            try Scheme.sign(&sig, &msg, &kp.secret_key, &opt_rand);

            var i: u32 = 0;
            while (i < iters) : (i += 1) {
                const start = std.Io.Clock.awake.now(io).nanoseconds;
                // Fold verify's result into a live value *before* stopping the
                // clock. verify has no output but its return, so
                // `... catch unreachable` (discarding it) would let ReleaseFast
                // elide the whole call and leave us timing clock overhead —
                // pinning only `&sig` keeps the input live, not the work
                // (Codex review, PR #31). Observing `ok` keeps the verifier
                // inside the timed region.
                const ok = if (Scheme.verify(&sig, &msg, &kp.public_key)) |_| true else |_| false;
                std.mem.doNotOptimizeAway(ok);
                const end = std.Io.Clock.awake.now(io).nanoseconds;
                ns[i] = @intCast(end - start);
            }
            try printSample(computeStats(ns, "verify", param_set, iters), csv_out);
        }
    }
}

// -----------------------------------------------------------------------------
// Main.
// -----------------------------------------------------------------------------

pub fn main(init: std.process.Init) !u8 {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);

    const cli = parseCli(args) catch return 1;

    if (cli.csv) {
        // CSV is data, so it goes to stdout and can be piped straight into
        // bench/pqclean/table.sh. Column order must match
        // bench/pqclean/run.sh exactly.
        var stdout_buf: [4096]u8 = undefined;
        var stdout_writer = std.Io.File.stdout().writer(init.io, &stdout_buf);
        const out = &stdout_writer.interface;

        try out.print("impl,param_set,op,iters,median_ns,mean_ns,min_ns,max_ns\n", .{});
        inline for (comptime std.enums.values(slh_dsa.ParamSet)) |ps| {
            const matches = cli.param_set_filter == null or cli.param_set_filter.? == ps;
            if (matches) try benchOne(init.io, allocator, ps, cli.op, cli.iters_override, out);
        }
        try stdout_writer.flush();
        return 0;
    }

    std.debug.print("slh-dsa-bench (optimize={s})\n", .{@tagName(builtin.mode)});
    std.debug.print("note: the 2x gate is measured against PQClean's `clean` " ++
        "(portable) variant, not AVX2 — see bench/README.md\n\n", .{});
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
        if (matches) try benchOne(init.io, allocator, ps, cli.op, cli.iters_override, null);
    }

    return 0;
}
