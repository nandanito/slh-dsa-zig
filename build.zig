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

    // Vendored, patched default test runner. Stock Zig 0.16.0 fails to compile
    // any test binary in fuzz mode (`--fuzz`); this copy carries a one-spot
    // fix. See tests/fuzz/test_runner.zig and issue #9. Every test artifact
    // uses it so that `zig build test --fuzz` never trips the stock compile
    // bug (it will instead report "no fuzz tests found" — the harnesses live
    // behind `zig build fuzz`).
    const fuzz_runner: std.Build.Step.Compile.TestRunner = .{
        .path = b.path("tests/fuzz/test_runner.zig"),
        .mode = .server,
    };

    // ---------------------------------------------------------------------
    // Unit tests against the library module.
    // ---------------------------------------------------------------------

    const lib_tests = b.addTest(.{
        .root_module = slh_dsa_mod,
        .test_runner = fuzz_runner,
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

    // The KAT runner/CLI carries its own unit tests (typed ACVP accessors,
    // parameter-set + interface parsing, executor plumbing) that live under
    // tests/ rather than in the library module. Fold them into `zig build
    // test` so they run in CI alongside the library suite.
    const kat_tests = b.addTest(.{
        .root_module = kat_mod,
        .test_runner = fuzz_runner,
    });
    const run_kat_tests = b.addRunArtifact(kat_tests);
    test_step.dependOn(&run_kat_tests.step);

    // ---------------------------------------------------------------------
    // Fuzz harnesses — `std.testing.fuzz` targets over the attacker-facing
    // surfaces (verify, the ACVP parser). FIPS 205 §9.3/§10.3. See issue #9.
    //
    //   zig build fuzz            — smoke: each target once with empty input.
    //   zig build fuzz --fuzz=N   — coverage-guided fuzzing, up to N runs.
    //
    // The harness imports the KAT runner, so it needs the same `slh_dsa`
    // import kat_mod carries.
    // ---------------------------------------------------------------------

    // The harness lives under tests/fuzz/, so it cannot reach tests/kat_main.zig
    // with a relative import (that escapes its module root). Expose the KAT
    // driver as a named module instead; the harness fuzzes its real
    // `runVectors` walker and reaches the parser primitives via `kat.runner`.
    // A dedicated module instance carries its own `slh_dsa` import.
    const kat_main_mod = b.createModule(.{
        .root_source_file = b.path("tests/kat_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    kat_main_mod.addImport("slh_dsa", slh_dsa_mod);

    const fuzz_mod = b.createModule(.{
        .root_source_file = b.path("tests/fuzz/harness.zig"),
        .target = target,
        .optimize = optimize,
    });
    fuzz_mod.addImport("slh_dsa", slh_dsa_mod);
    fuzz_mod.addImport("kat", kat_main_mod);

    const fuzz_tests = b.addTest(.{
        .root_module = fuzz_mod,
        .test_runner = fuzz_runner,
    });
    const run_fuzz_tests = b.addRunArtifact(fuzz_tests);

    const fuzz_step = b.step("fuzz", "Run fuzz harnesses (add --fuzz=N for coverage-guided fuzzing)");
    fuzz_step.dependOn(&run_fuzz_tests.step);

    // ---------------------------------------------------------------------
    // Benchmarks — pinned to ReleaseFast unless overridden.
    // ---------------------------------------------------------------------

    const bench_optimize = b.option(
        std.builtin.OptimizeMode,
        "bench-optimize",
        "Optimisation mode for the benchmark binary (default ReleaseFast)",
    ) orelse .ReleaseFast;

    // The benchmark links its own copy of the library compiled at
    // `bench_optimize`, so the timed scheme code is optimised identically to
    // the harness and independently of the top-level `-Doptimize`. (Zig 0.16
    // already compiles imported modules at the root artifact's optimize mode,
    // so importing the default `slh_dsa_mod` measures the same thing today;
    // pinning a dedicated module makes the bench's optimize contract explicit
    // and robust to that behaviour changing.)
    const slh_dsa_bench_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = bench_optimize,
    });

    const bench_mod = b.createModule(.{
        .root_source_file = b.path("bench/bench.zig"),
        .target = target,
        .optimize = bench_optimize,
    });
    bench_mod.addImport("slh_dsa", slh_dsa_bench_mod);

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
