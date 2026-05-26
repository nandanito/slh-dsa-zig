//! CLI entry point for the SLH-DSA KAT (Known-Answer Test) runner.
//!
//! Usage:
//!
//!   slh-dsa-kat --mode <keygen|siggen|sigver> --vectors <path.json>
//!                [--param-set <SLH-DSA-...>]
//!
//! `--param-set` is optional: when omitted, every parameter set found in
//! the vector file is exercised. When supplied, only vectors matching that
//! parameter set are run (useful for iterating on one set while the others
//! are still skeletons).
//!
//! Exit codes:
//!   0 — all vectors passed.
//!   1 — at least one vector failed, or a CLI/parse error occurred.
//!
//! Driven by `zig build kat`. Pass arguments after `--`, e.g.:
//!
//!   zig build kat -- --mode keygen --vectors tests/vectors/keygen.json
//!
//! Lane: Lane A (test infrastructure).

const std = @import("std");
const runner = @import("kat_runner.zig");
const slh_dsa = @import("slh_dsa");

const Args = struct {
    mode: ?runner.VectorType = null,
    vectors_path: ?[]const u8 = null,
    param_set_filter: ?slh_dsa.ParamSet = null,
};

const usage =
    \\Usage: slh-dsa-kat --mode <keygen|siggen|sigver> --vectors <path.json>
    \\                   [--param-set <SLH-DSA-...>]
    \\
    \\Run NIST ACVP Known-Answer Test vectors against this library.
    \\
;

fn parseArgs(allocator: std.mem.Allocator) !Args {
    var args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var out = Args{};

    var i: usize = 1; // skip argv[0]
    while (i < args.len) : (i += 1) {
        const arg = args[i];

        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            std.debug.print("{s}", .{usage});
            std.process.exit(0);
        } else if (std.mem.eql(u8, arg, "--mode")) {
            i += 1;
            if (i >= args.len) return error.MissingArgument;
            const mode_str = args[i];
            // Accept both the short forms and the ACVP names.
            if (std.mem.eql(u8, mode_str, "keygen") or std.mem.eql(u8, mode_str, "keyGen")) {
                out.mode = .key_gen;
            } else if (std.mem.eql(u8, mode_str, "siggen") or std.mem.eql(u8, mode_str, "sigGen")) {
                out.mode = .sig_gen;
            } else if (std.mem.eql(u8, mode_str, "sigver") or std.mem.eql(u8, mode_str, "sigVer")) {
                out.mode = .sig_ver;
            } else {
                std.debug.print("error: unknown mode '{s}'\n", .{mode_str});
                return error.InvalidArgument;
            }
        } else if (std.mem.eql(u8, arg, "--vectors")) {
            i += 1;
            if (i >= args.len) return error.MissingArgument;
            out.vectors_path = args[i];
        } else if (std.mem.eql(u8, arg, "--param-set")) {
            i += 1;
            if (i >= args.len) return error.MissingArgument;
            out.param_set_filter = runner.parseParamSet(args[i]) orelse {
                std.debug.print("error: unknown parameter set '{s}'\n", .{args[i]});
                return error.InvalidArgument;
            };
        } else {
            std.debug.print("error: unexpected argument '{s}'\n", .{arg});
            return error.InvalidArgument;
        }
    }

    if (out.mode == null) {
        std.debug.print("error: --mode is required\n{s}", .{usage});
        return error.InvalidArgument;
    }
    if (out.vectors_path == null) {
        std.debug.print("error: --vectors is required\n{s}", .{usage});
        return error.InvalidArgument;
    }

    return out;
}

pub fn main() !u8 {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const cli = parseArgs(allocator) catch return 1;

    std.debug.print("slh-dsa-kat: mode={s} vectors={s}", .{
        @tagName(cli.mode.?),
        cli.vectors_path.?,
    });
    if (cli.param_set_filter) |ps| {
        std.debug.print(" param-set={s}\n", .{@tagName(ps)});
    } else {
        std.debug.print(" param-set=<all>\n", .{});
    }

    // -----------------------------------------------------------------
    // Load and dispatch.
    //
    // SKELETON: the executors in kat_runner currently return "skipped"
    // results. Once the scheme bodies land we walk testGroups -> tests,
    // decode each vector, and feed it to the right executor.
    // -----------------------------------------------------------------

    var parsed = runner.loadVectorsFromFile(allocator, cli.vectors_path.?) catch |err| {
        std.debug.print("error: failed to load vectors: {s}\n", .{@errorName(err)});
        return 1;
    };
    defer parsed.deinit();

    var summary = runner.RunSummary{};

    // The real loop will go here. For now we mark every vector as
    // skipped so the build target at least exits cleanly against a
    // well-formed JSON file.
    //
    // TODO: walk `parsed.value` as a std.json.Value, iterate
    //       testGroups, parse per-mode fields, dispatch to runKeyGen /
    //       runSigGen / runSigVer, accumulate into `summary`.
    summary.skipped = 0;

    std.debug.print("\nresults: total={d} passed={d} failed={d} skipped={d}\n", .{
        summary.total,
        summary.passed,
        summary.failed,
        summary.skipped,
    });

    if (summary.failed > 0) return 1;
    return 0;
}
