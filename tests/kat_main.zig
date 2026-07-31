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
/// Re-exported so the fuzz harness (tests/fuzz/harness.zig) can reach the ACVP
/// parser primitives and `VectorType` through the same module instance it
/// drives `runVectors` with. See issue #9.
pub const runner = @import("kat_runner.zig");
const slh_dsa = @import("slh_dsa");

test {
    // Pull the KAT runner's own unit tests into this module's test binary.
    // `zig test` only runs tests from files reachable via an explicit
    // reference, so importing `kat_runner` for its decls above is not enough
    // — this reference forces its `test` blocks (typed accessors, param-set
    // and interface parsing, executor plumbing) to run under `zig build test`.
    _ = @import("kat_runner.zig");
}

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

fn parseArgs(args: []const [:0]const u8) !Args {
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

/// Decode an optional hex field: absent → `null`, present → decoded bytes.
/// Used for ACVP fields that only appear in some groups — e.g.
/// `additionalRandomness`, which is present only for non-deterministic
/// sigGen groups.
fn optHex(
    allocator: std.mem.Allocator,
    obj: std.json.ObjectMap,
    name: []const u8,
) !?[]u8 {
    const v = obj.get(name) orelse return null;
    return try runner.hexDecode(allocator, try runner.asString(v));
}

/// The context string is present (possibly empty) for the external
/// interface and absent for the internal one. Decodes it accordingly.
fn optContext(
    allocator: std.mem.Allocator,
    obj: std.json.ObjectMap,
    interface: runner.Interface,
) !?[]u8 {
    return switch (interface) {
        .internal => null,
        .external => try runner.hexDecode(allocator, try runner.asString(try runner.getField(obj, "context"))),
    };
}

/// Walk the parsed ACVP structure (testGroups -> tests), dispatch each
/// vector, and accumulate a summary. All field accesses go through the
/// typed accessors in kat_runner so malformed files produce
/// `error.MalformedVectorFile` instead of a union-access panic.
///
/// `pub` so the fuzz harness (issue #9) can exercise this exact walker on
/// adversarial JSON — it is the real parser of untrusted ACVP vector files.
pub fn runVectors(
    allocator: std.mem.Allocator,
    root_value: std.json.Value,
    mode: runner.VectorType,
    param_set_filter: ?slh_dsa.ParamSet,
) !runner.RunSummary {
    var summary = runner.RunSummary{};

    const root = try runner.asObject(root_value);
    const groups = try runner.asArray(try runner.getField(root, "testGroups"));

    for (groups.items) |group| {
        const gobj = try runner.asObject(group);
        const ps_name = try runner.asString(try runner.getField(gobj, "parameterSet"));
        const tests = try runner.asArray(try runner.getField(gobj, "tests"));

        const ps = runner.parseParamSet(ps_name) orelse {
            std.debug.print("warning: unknown parameter set '{s}', skipping group\n", .{ps_name});
            summary.skipped += @intCast(tests.items.len);
            continue;
        };
        if (param_set_filter) |filter| {
            if (ps != filter) continue;
        }

        // Signature modes carry two extra group-level axes: the signature
        // interface (internal vs external) and the pre-hash mode. They are
        // orthogonal — every HashSLH-DSA group is also an `external` group —
        // so both are read, and the pre-hash function itself comes from a
        // per-test field below (FIPS 205 §10.2.2).
        var interface: runner.Interface = .internal;
        var group_is_pre_hash = false;
        if (mode == .sig_gen or mode == .sig_ver) {
            const pre_hash = try runner.asString(try runner.getField(gobj, "preHash"));
            group_is_pre_hash = std.mem.eql(u8, pre_hash, "preHash");
            const iface_name = try runner.asString(try runner.getField(gobj, "signatureInterface"));
            interface = runner.Interface.fromString(iface_name) orelse {
                std.debug.print("warning: unknown signatureInterface '{s}', skipping group\n", .{iface_name});
                summary.skipped += @intCast(tests.items.len);
                continue;
            };
        }

        for (tests.items) |tc| {
            const tobj = try runner.asObject(tc);
            const tc_id = try runner.asTcId(try runner.getField(tobj, "tcId"));

            // `hashAlg` is a per-test field, not a group-level one: ACVP varies
            // the pre-hash function within a single group. Pure and internal
            // groups carry `hashAlg: "none"`, so the group's `preHash` axis —
            // not the presence of the field — decides whether it is read.
            var pre_hash: ?runner.PreHash = null;
            if (group_is_pre_hash) {
                const alg_name = try runner.asString(try runner.getField(tobj, "hashAlg"));
                pre_hash = runner.parsePreHash(alg_name) orelse {
                    std.debug.print("warning: unknown hashAlg '{s}' (tcId={d}), skipping\n", .{ alg_name, tc_id });
                    summary.skipped += 1;
                    continue;
                };
            }

            const result: runner.VectorResult = switch (mode) {
                .key_gen => try runner.runKeyGen(allocator, .{
                    .tc_id = tc_id,
                    .param_set = ps,
                    .sk_seed = try runner.hexDecode(allocator, try runner.asString(try runner.getField(tobj, "skSeed"))),
                    .sk_prf = try runner.hexDecode(allocator, try runner.asString(try runner.getField(tobj, "skPrf"))),
                    .pk_seed = try runner.hexDecode(allocator, try runner.asString(try runner.getField(tobj, "pkSeed"))),
                    .expected_pk = try runner.hexDecode(allocator, try runner.asString(try runner.getField(tobj, "pk"))),
                    .expected_sk = try runner.hexDecode(allocator, try runner.asString(try runner.getField(tobj, "sk"))),
                }),
                .sig_gen => try runner.runSigGen(allocator, .{
                    .tc_id = tc_id,
                    .param_set = ps,
                    .interface = interface,
                    .sk = try runner.hexDecode(allocator, try runner.asString(try runner.getField(tobj, "sk"))),
                    .msg = try runner.hexDecode(allocator, try runner.asString(try runner.getField(tobj, "message"))),
                    .ctx = try optContext(allocator, tobj, interface),
                    .opt_rand = try optHex(allocator, tobj, "additionalRandomness"),
                    .pre_hash = pre_hash,
                    .expected_sig = try runner.hexDecode(allocator, try runner.asString(try runner.getField(tobj, "signature"))),
                }),
                .sig_ver => try runner.runSigVer(allocator, .{
                    .tc_id = tc_id,
                    .param_set = ps,
                    .interface = interface,
                    .pk = try runner.hexDecode(allocator, try runner.asString(try runner.getField(tobj, "pk"))),
                    .msg = try runner.hexDecode(allocator, try runner.asString(try runner.getField(tobj, "message"))),
                    .ctx = try optContext(allocator, tobj, interface),
                    .sig = try runner.hexDecode(allocator, try runner.asString(try runner.getField(tobj, "signature"))),
                    .pre_hash = pre_hash,
                    .expected_accept = try runner.asBool(try runner.getField(tobj, "testPassed")),
                }),
            };

            summary.record(result);
            if (!result.pass) {
                std.debug.print("FAIL {s} tcId={d}: {s}\n", .{
                    @tagName(result.param_set),
                    result.tc_id,
                    result.detail orelse "(no detail)",
                });
            }
        }
    }

    return summary;
}

pub fn main(init: std.process.Init) !u8 {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);

    const cli = parseArgs(args) catch return 1;

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
    // keyGen, sigGen, and sigVer are all wired, including the HashSLH-DSA
    // pre-hash groups (FIPS 205 §10.2.2 / §10.3). Nothing is skipped by
    // design; `skipped` now only counts genuinely unrecognised input.
    // -----------------------------------------------------------------

    var parsed = runner.loadVectorsFromFile(init.io, allocator, cli.vectors_path.?) catch |err| {
        std.debug.print("error: failed to load vectors: {s}\n", .{@errorName(err)});
        return 1;
    };
    defer parsed.deinit();

    const summary = runVectors(allocator, parsed.value, cli.mode.?, cli.param_set_filter) catch |err| {
        // ACVP files are external input: any shape mismatch (or bad hex)
        // lands here as a controlled failure rather than a safety panic.
        std.debug.print("error: failed to process vector file: {s}\n", .{@errorName(err)});
        return 1;
    };

    std.debug.print("\nresults: total={d} passed={d} failed={d} skipped={d}\n", .{
        summary.total,
        summary.passed,
        summary.failed,
        summary.skipped,
    });

    if (summary.failed > 0) return 1;
    if (summary.total == 0) {
        // A KAT invocation that executed zero vectors must not report
        // success: it would let CI pass for unimplemented modes (sigGen/
        // sigVer today), unknown parameter sets, or an empty vector file
        // while validating nothing.
        std.debug.print("error: no vectors were executed (unimplemented mode, unknown parameter sets, or empty file)\n", .{});
        return 1;
    }
    return 0;
}
