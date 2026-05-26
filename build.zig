//! Build script for slh-dsa-zig.
//!
//! Steps:
//!   zig build              — build the static library (default install step)
//!   zig build test         — run the unit-test suite
//!   zig build kat          — run NIST ACVP KAT vectors
//!   zig build bench        — run benchmarks (defaults to ReleaseFast)
//!   zig build examples     — build the runnable examples
//!   zig build example_sign — build and run a single example
//!
//! Lane discipline:
//!   The build script is Lane A. It does not pull anything from
//!   upstream-candidate/ into the standalone library, nor vice versa.

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ---------------------------------------------------------------------
    // Library module — the public API surface.
    // ---------------------------------------------------------------------

    const slh_dsa_mod = b.addModule("slh_dsa", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addLibrary(.{
        .name = "slh_dsa",
        .root_module = slh_dsa_mod,
        .linkage = .static,
    });
    b.installArtifact(lib);

    // ---------------------------------------------------------------------
    // Unit tests against the library module.
    // ---------------------------------------------------------------------

    const lib_tests = b.addTest(.{
        .root_module = slh_dsa_mod,
    });
    const run_lib_tests = b.addRunArtifact(lib_tests);

    const test_step = b.step("test", "Run the unit-test suite");
    test_step.dependOn(&run_lib_tests.step);

    // ---------------------------------------------------------------------
    // KAT runner CLI — exercises the library against NIST ACVP vectors.
    // ---------------------------------------------------------------------

    const kat_mod = b.createModule(.{
        .root_source_file = b.path("tests/kat_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    kat_mod.addImport("slh_dsa", slh_dsa_mod);

    const kat_exe = b.addExecutable(.{
        .name = "slh-dsa-kat",
        .root_module = kat_mod,
    });
    b.installArtifact(kat_exe);

    const run_kat = b.addRunArtifact(kat_exe);
    if (b.args) |args| run_kat.addArgs(args);

    const kat_step = b.step("kat", "Run NIST ACVP KAT vectors");
    kat_step.dependOn(&run_kat.step);

    // ---------------------------------------------------------------------
    // Benchmarks — pinned to ReleaseFast unless overridden.
    // ---------------------------------------------------------------------

    const bench_optimize = b.option(
        std.builtin.OptimizeMode,
        "bench-optimize",
        "Optimisation mode for the benchmark binary (default ReleaseFast)",
    ) orelse .ReleaseFast;

    const bench_mod = b.createModule(.{
        .root_source_file = b.path("bench/bench.zig"),
        .target = target,
        .optimize = bench_optimize,
    });
    bench_mod.addImport("slh_dsa", slh_dsa_mod);

    const bench_exe = b.addExecutable(.{
        .name = "slh-dsa-bench",
        .root_module = bench_mod,
    });
    b.installArtifact(bench_exe);

    const run_bench = b.addRunArtifact(bench_exe);
    if (b.args) |args| run_bench.addArgs(args);

    const bench_step = b.step("bench", "Run the benchmark suite");
    bench_step.dependOn(&run_bench.step);

    // ---------------------------------------------------------------------
    // Runnable examples.
    // ---------------------------------------------------------------------

    const examples_step = b.step("examples", "Build all runnable examples");

    addExample(b, target, optimize, slh_dsa_mod, "basic_sign", "examples/basic_sign.zig", examples_step);
}

/// Add a runnable example: registers an install artifact and a `example_<name>`
/// build step that runs it.
fn addExample(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    slh_dsa_mod: *std.Build.Module,
    comptime name: []const u8,
    comptime source_path: []const u8,
    examples_step: *std.Build.Step,
) void {
    const example_mod = b.createModule(.{
        .root_source_file = b.path(source_path),
        .target = target,
        .optimize = optimize,
    });
    example_mod.addImport("slh_dsa", slh_dsa_mod);

    const exe = b.addExecutable(.{
        .name = name,
        .root_module = example_mod,
    });
    b.installArtifact(exe);
    examples_step.dependOn(&exe.step);

    const run = b.addRunArtifact(exe);
    if (b.args) |args| run.addArgs(args);

    const step = b.step("example_" ++ name, "Build and run example: " ++ name);
    step.dependOn(&run.step);
}
