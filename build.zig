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
        // `-ffuzz` instrumentation is emitted only by the LLVM backend. Zig
        // 0.16 defaults to the self-hosted x86_64 backend for Debug builds,
        // which does not implement SanitizerCoverage — and `fuzzer.zig` picks
        // the counters up through *weak* externs (`__start___sancov_cntrs`),
        // so a missing section resolves to a zero-length slice instead of a
        // link error. The fuzzer then runs blind: `pcs_len = 0`, no input is
        // ever novel, and the corpus stays empty with no diagnostic anywhere.
        //
        // That is exactly what the nightly job did on ubuntu-latest until this
        // line existed — see issue #68. Pin the backend for this artifact only;
        // the check that it stayed pinned lives in .github/workflows/fuzz.yml.
        .use_llvm = true,
    });
    const run_fuzz_tests = b.addRunArtifact(fuzz_tests);

    const fuzz_step = b.step("fuzz", "Run fuzz harnesses (add --fuzz=N for coverage-guided fuzzing)");
    fuzz_step.dependOn(&run_fuzz_tests.step);

    // Per-target fuzz steps, one harness each — `zig build fuzz-<target>`.
    //
    // The aggregate `fuzz` step above is right for a smoke test and wrong for
    // the 24h gate. `fuzzer.zig` drives every fuzz test in a binary from one
    // single-threaded loop (`while (fuzzer.select()) |i| runTest(i)`), picking
    // the next test by an adaptive weighting — a quarter on instrumented-PC
    // count, three quarters on how recently the test found something. So a
    // wall-clock window is *divided* among the tests in the binary, never
    // replicated: with six harnesses no target accrues the window, and adding
    // a harness silently cuts every existing target's share.
    //
    // A compile-time filter reduces the binary to a single test, which
    // `fuzzer.zig` special-cases — `if (n_tests == 1) runTest(0)`, no swapping
    // — so the whole window lands on one target and its seconds are exactly
    // the job's seconds. That is what makes the per-component wording of the
    // gate literally true rather than aspirational. See issue #65.
    //
    // Filtering is safe for the accrued corpus: the corpus directory is
    // `f/hex(Wyhash(0, test_name))`, a function of the test *name* only, so a
    // filtered binary reads and writes exactly the directory the aggregate
    // binary used. Corpora are per-target throughout — `corpus`, `seen_pcs`
    // and `bests` are all per-test in `Fuzzer.init` — which is also why time
    // spent on one target buys nothing for another, and why a single global
    // counter could not stand in for per-target progress.
    const FuzzTarget = struct {
        /// `zig build fuzz-<slug>`; also the per-target cache and counter key.
        slug: []const u8,
        /// Substring of the test name. Must match exactly one harness.
        filter: []const u8,
    };
    const fuzz_targets = [_]FuzzTarget{
        .{ .slug = "verify-shake-128f", .filter = "verify rejects arbitrary bytes (SLH-DSA-SHAKE-128f)" },
        .{ .slug = "verify-sha2-128f", .filter = "verify rejects arbitrary bytes (SLH-DSA-SHA2-128f)" },
        .{ .slug = "verify-prehash-shake-128f", .filter = "verifyPreHash rejects arbitrary bytes (SLH-DSA-SHAKE-128f)" },
        .{ .slug = "verify-prehash-sha2-128f", .filter = "verifyPreHash rejects arbitrary bytes (SLH-DSA-SHA2-128f)" },
        .{ .slug = "acvp-parser", .filter = "ACVP vector parser tolerates arbitrary bytes" },
        .{ .slug = "hex-decode", .filter = "hexDecode tolerates arbitrary bytes" },
    };
    for (fuzz_targets) |ft| {
        const one_mod = b.createModule(.{
            .root_source_file = b.path("tests/fuzz/harness.zig"),
            .target = target,
            .optimize = optimize,
        });
        one_mod.addImport("slh_dsa", slh_dsa_mod);
        one_mod.addImport("kat", kat_main_mod);

        const one_test = b.addTest(.{
            .root_module = one_mod,
            .test_runner = fuzz_runner,
            .filters = &.{ft.filter},
            .use_llvm = true, // see the aggregate artifact above (#68)
        });
        const run_one = b.addRunArtifact(one_test);

        const step = b.step(
            b.fmt("fuzz-{s}", .{ft.slug}),
            b.fmt("Fuzz one harness: {s} (add --fuzz=N)", .{ft.filter}),
        );
        step.dependOn(&run_one.step);
    }

    // ---------------------------------------------------------------------
    // Constant-time (ctgrind) harnesses — taint the secret key so Valgrind's
    // memcheck can flag any secret-dependent branch or memory access. Uses
    // std.valgrind client requests (pure Zig, no C shim). See issue #34 and
    // .github/workflows/ctgrind.yml, which runs the built binaries under
    // Valgrind.
    //
    //   zig build ctgrind            — build + run directly (no-op taint; sanity)
    //   valgrind zig-out/bin/slh-dsa-ctgrind        — components, the real check
    //   valgrind zig-out/bin/slh-dsa-ctgrind-sign   — whole keygen + sign
    // ---------------------------------------------------------------------

    // Force Zig to emit the std.valgrind client requests even in release
    // builds — without this they compile to no-ops outside Debug (`-fvalgrind`
    // default), so the taint markers would be inert and the check vacuous
    // (the workflow builds ReleaseSafe). But `-fvalgrind` only compiles on
    // targets Zig supports it for — not, e.g., the maintainer's aarch64 macOS
    // box — so gate it on the arch. Off-target it degrades to no-ops, which is
    // fine: Valgrind only runs in CI on x86_64, and the negative control proves
    // the on-target build is non-vacuous.
    const valgrind_ok = target.result.cpu.arch == .x86_64;

    // Setting `.valgrind` on a harness module is enough to reach the library
    // too: Zig 0.16 resolves Valgrind support per *compilation*, so the root
    // module's `-fvalgrind` also governs `builtin.valgrind_support` in imported
    // modules — verified by disassembly, and the reason the whole-sign
    // harness's in-library declassify hooks (src/ct.zig) actually emit while it
    // imports the ordinary `slh_dsa_mod`. taint_sign.zig asserts the two agree
    // at comptime, so a future Zig that makes this per-module fails the build
    // with a readable message rather than an avalanche of false positives.

    const ctgrind_step = b.step("ctgrind", "Build & run the constant-time (ctgrind) harnesses");

    // Component-level: primitives in isolation, no declassification needed.
    const ctgrind_mod = b.createModule(.{
        .root_source_file = b.path("tests/ctgrind/taint_components.zig"),
        .target = target,
        .optimize = optimize,
        .valgrind = valgrind_ok,
    });
    ctgrind_mod.addImport("slh_dsa", slh_dsa_mod);

    const ctgrind_exe = b.addExecutable(.{
        .name = "slh-dsa-ctgrind",
        .root_module = ctgrind_mod,
    });
    // Installed so the workflow can invoke it under Valgrind at a stable path.
    b.installArtifact(ctgrind_exe);
    ctgrind_step.dependOn(&b.addRunArtifact(ctgrind_exe).step);

    // Whole-path: a complete keygen + sign, resting on the in-library
    // declassify hooks for the public SK.seed-derived intermediates.
    const ctgrind_sign_mod = b.createModule(.{
        .root_source_file = b.path("tests/ctgrind/taint_sign.zig"),
        .target = target,
        .optimize = optimize,
        .valgrind = valgrind_ok,
    });
    ctgrind_sign_mod.addImport("slh_dsa", slh_dsa_mod);

    const ctgrind_sign_exe = b.addExecutable(.{
        .name = "slh-dsa-ctgrind-sign",
        .root_module = ctgrind_sign_mod,
    });
    b.installArtifact(ctgrind_sign_exe);
    ctgrind_step.dependOn(&b.addRunArtifact(ctgrind_sign_exe).step);

    // Negative control: deliberately branches on tainted data, so Valgrind MUST
    // flag it. The workflow runs it expecting failure — this proves the taint
    // machinery is live (guarding against the vacuous-gate failure mode above),
    // which matters because Valgrind can't run on the maintainer's macOS box.
    const ctgrind_negctl_mod = b.createModule(.{
        .root_source_file = b.path("tests/ctgrind/negative_control.zig"),
        .target = target,
        .optimize = optimize,
        .valgrind = valgrind_ok,
    });
    const ctgrind_negctl_exe = b.addExecutable(.{
        .name = "slh-dsa-ctgrind-negctl",
        .root_module = ctgrind_negctl_mod,
    });
    b.installArtifact(ctgrind_negctl_exe);
    // Built, not run: running it outside Valgrind would prove nothing, and it
    // is *supposed* to fail under Valgrind.
    ctgrind_step.dependOn(&ctgrind_negctl_exe.step);

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
