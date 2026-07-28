#!/usr/bin/env bash
#
# Build and run the PQClean `clean` reference side of the 2x performance gate.
#
# Emits CSV on stdout (impl,param_set,op,iters,median_ns,mean_ns,min_ns,max_ns)
# and a provenance header on stderr, so a published number can be traced back
# to an exact PQClean commit, compiler, and machine.
#
#   ./bench/pqclean/run.sh                       # clone PQClean, build, run all 12
#   PQCLEAN_DIR=/path/to/PQClean ./run.sh        # reuse an existing checkout
#   PQCLEAN_REF=<sha> ./run.sh                   # pin a specific commit
#   KEYGEN_ITERS=100 SIGN_ITERS=100 ./run.sh     # override the iteration budgets
#   PARAM_SETS="sphincs-shake-128f-simple" ./run.sh
#
# Iteration budgets default to bench/bench.zig's, including its speed-class
# split ("f" sets get a larger budget than the much slower "s" sets), so both
# sides of the comparison average over the same number of operations.
#
# Lane: Lane A (bench infrastructure). Not part of the Zig build graph, and
# `zig build` never invokes it -- the repo stays pure-Zig with no C toolchain
# requirement. This script is only for reproducing a published comparison.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Pinned by default to the commit the published table in bench/README.md was
# measured against. Override with PQCLEAN_REF to compare a different revision.
PQCLEAN_REF="${PQCLEAN_REF:-202a8f96315f9ed219387a50f7e40d04af037ea8}"
PQCLEAN_URL="${PQCLEAN_URL:-https://github.com/PQClean/PQClean.git}"

WORK="${WORK:-${TMPDIR:-/tmp}/slh-dsa-pqclean-bench}"
PQCLEAN_DIR="${PQCLEAN_DIR:-$WORK/PQClean}"
# BUILD is fingerprinted below, once CC/flags/commit are known.

CC="${CC:-cc}"
# PQClean's own Makefile uses -O3; match it for the harness translation unit.
# No -flto: the harness must not be able to inline or elide the library calls.
#
# -std=gnu99 rather than PQClean's -std=c99, for two reasons, both of which
# only bite on glibc/Linux (the x86-64 re-measure path in issue #40):
#   - strict c99 defines no feature-test macro, so glibc hides clock_gettime,
#     struct timespec and CLOCK_MONOTONIC_RAW, and harness.c will not compile;
#   - PQClean's own common/randombytes.c reaches for SYS_getrandom, which
#     likewise needs the default (non-strict) namespace.
# This governs only the harness and the common objects compiled here. Each
# PQClean implementation library is still built by PQClean's own Makefile at
# its own -std=c99 -O3, untouched.
HARNESS_CFLAGS="${HARNESS_CFLAGS:--std=gnu99 -O3 -Wall -Wextra}"

ALL_PARAM_SETS="
sphincs-sha2-128s-simple
sphincs-sha2-128f-simple
sphincs-sha2-192s-simple
sphincs-sha2-192f-simple
sphincs-sha2-256s-simple
sphincs-sha2-256f-simple
sphincs-shake-128s-simple
sphincs-shake-128f-simple
sphincs-shake-192s-simple
sphincs-shake-192f-simple
sphincs-shake-256s-simple
sphincs-shake-256f-simple
"
PARAM_SETS="${PARAM_SETS:-$ALL_PARAM_SETS}"

# ---------------------------------------------------------------------------
# Fetch PQClean at the pinned commit.
# ---------------------------------------------------------------------------

mkdir -p "$WORK"

if [ ! -d "$PQCLEAN_DIR/.git" ]; then
    echo "==> cloning PQClean into $PQCLEAN_DIR" >&2
    git clone --quiet "$PQCLEAN_URL" "$PQCLEAN_DIR"
fi

# Only move HEAD if it is not already where we want it -- lets a caller point
# PQCLEAN_DIR at a checkout they are managing themselves.
CURRENT_REF="$(git -C "$PQCLEAN_DIR" rev-parse HEAD)"
if [ "$CURRENT_REF" != "$PQCLEAN_REF" ]; then
    echo "==> checking out $PQCLEAN_REF (was $CURRENT_REF)" >&2
    git -C "$PQCLEAN_DIR" fetch --quiet origin "$PQCLEAN_REF" 2>/dev/null || git -C "$PQCLEAN_DIR" fetch --quiet origin
    git -C "$PQCLEAN_DIR" checkout --quiet "$PQCLEAN_REF"
fi

COMMON="$PQCLEAN_DIR/common"

# ---------------------------------------------------------------------------
# Build cache, keyed by everything that can change the generated code.
#
# The cached objects are SHA-2 and Keccak -- they dominate PQClean's timing.
# A cache keyed only on source mtime would happily reuse objects built by a
# different compiler or at different flags while the provenance header above
# advertises the *current* ones, i.e. report numbers that were never measured
# under the settings being published. Fingerprinting the directory makes a
# changed CC, changed flags, or a different PQClean commit land in a
# different cache rather than silently reusing the old one.
# ---------------------------------------------------------------------------

# The literal $CC string is part of the key, not just its --version line: a
# wrapper script, or `CC="clang -mcpu=native"`, changes code generation while
# reporting an identical version.
FINGERPRINT="$(printf '%s|%s|%s|%s' \
    "$CC" \
    "$($CC --version 2>&1 | head -1)" \
    "$HARNESS_CFLAGS" \
    "$(git -C "$PQCLEAN_DIR" rev-parse HEAD)" \
    | cksum | cut -d' ' -f1)"
BUILD="$WORK/build/$FINGERPRINT"
mkdir -p "$BUILD"

# ---------------------------------------------------------------------------
# Provenance header (stderr, so it never contaminates the CSV).
# ---------------------------------------------------------------------------

{
    echo "# slh-dsa-zig <-> PQClean clean comparison"
    echo "# pqclean_commit: $(git -C "$PQCLEAN_DIR" rev-parse HEAD)"
    echo "# cc:             $CC — $($CC --version 2>&1 | head -1)"
    echo "# harness_cflags: $HARNESS_CFLAGS"
    echo "# uname:          $(uname -srm)"
    if command -v sysctl >/dev/null 2>&1 && sysctl -n machdep.cpu.brand_string >/dev/null 2>&1; then
        echo "# cpu:            $(sysctl -n machdep.cpu.brand_string)"
    elif [ -r /proc/cpuinfo ]; then
        echo "# cpu:            $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//')"
    fi
} >&2

# ---------------------------------------------------------------------------
# Shared common objects (SHA-2, Keccak, cSHAKE, CSPRNG).
# ---------------------------------------------------------------------------

echo "==> building PQClean common objects" >&2
COMMON_OBJS=""
for src in sha2 fips202 sp800-185 randombytes; do
    obj="$BUILD/common_$src.o"
    if [ ! -f "$obj" ] || [ "$COMMON/$src.c" -nt "$obj" ]; then
        $CC $HARNESS_CFLAGS -I"$COMMON" -c -o "$obj" "$COMMON/$src.c"
    fi
    COMMON_OBJS="$COMMON_OBJS $obj"
done

# ---------------------------------------------------------------------------
# Per-parameter-set: build the clean library, link a harness, run it.
# ---------------------------------------------------------------------------

# CSV header on stdout.
echo "impl,param_set,op,iters,median_ns,mean_ns,min_ns,max_ns"

for ps in $PARAM_SETS; do
    src_dir="$PQCLEAN_DIR/crypto_sign/$ps/clean"
    if [ ! -d "$src_dir" ]; then
        echo "error: no such parameter set: $ps" >&2
        exit 1
    fi

    # PQClean symbol prefix: uppercase the directory name, strip dashes.
    prefix="PQCLEAN_$(echo "$ps" | tr -d '-' | tr '[:lower:]' '[:upper:]')_CLEAN_"

    # Speed class drives the iteration budget, matching bench.zig::defaultBudget.
    # The "s" (small-signature) sets sign 20-100x slower than their "f" siblings.
    case "$ps" in
        *-128s-*|*-192s-*|*-256s-*)
            def_keygen=20; def_sign=5;  def_verify=500 ;;
        *)
            def_keygen=50; def_sign=50; def_verify=500 ;;
    esac
    keygen_iters="${KEYGEN_ITERS:-$def_keygen}"
    sign_iters="${SIGN_ITERS:-$def_sign}"
    verify_iters="${VERIFY_ITERS:-$def_verify}"

    echo "==> $ps (keygen=$keygen_iters sign=$sign_iters verify=$verify_iters)" >&2

    # PQClean ships a per-implementation Makefile that already uses -O3.
    #
    # Clean *before* building, not only after. Relying on the post-run clean
    # leaves three ways to link a stale archive into a published measurement:
    # an interrupted previous run, a caller-managed PQCLEAN_DIR that already
    # had artifacts, or a previous run under a different CC -- `make` would
    # see up-to-date objects and skip the rebuild in all three. The archives
    # are small and this costs a couple of seconds per set, which is the
    # right trade for a number that gets published.
    make -s -C "$src_dir" clean >/dev/null 2>&1 || true
    make -s -C "$src_dir" CC="$CC" >/dev/null

    lib="$src_dir/lib${ps}_clean.a"
    if [ ! -f "$lib" ]; then
        echo "error: expected library not produced: $lib" >&2
        exit 1
    fi

    bin="$BUILD/harness_$ps"
    $CC $HARNESS_CFLAGS \
        -DPQC_PREFIX="$prefix" \
        -I"$src_dir" -I"$COMMON" \
        -o "$bin" "$HERE/harness.c" "$lib" $COMMON_OBJS

    # Map PQClean's name onto the FIPS 205 name bench.zig prints, so the two
    # CSVs join on a common key. sphincs-sha2-128f-simple -> SLH-DSA-SHA2-128f
    label="$(echo "$ps" \
        | sed -e 's/^sphincs-/SLH-DSA-/' -e 's/-simple$//' \
        | sed -e 's/SLH-DSA-sha2-/SLH-DSA-SHA2-/' -e 's/SLH-DSA-shake-/SLH-DSA-SHAKE-/')"

    "$bin" "$label" "$keygen_iters" "$sign_iters" "$verify_iters"

    # Leave the checkout pristine for the next run.
    make -s -C "$src_dir" clean >/dev/null
done

echo "==> done" >&2
