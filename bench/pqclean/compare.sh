#!/usr/bin/env bash
#
# Drive both sides of the 2x performance gate and emit one joined CSV.
#
#   ./bench/pqclean/compare.sh > results.csv
#   ./bench/pqclean/compare.sh | ./bench/pqclean/table.sh     # markdown table
#
# Why this exists rather than "run each side once":
#
#   The two sides are interleaved *per parameter set* -- zig, then PQClean,
#   then the next set -- so the members of each comparison are measured
#   within seconds of one another. Running one implementation to completion
#   and then the other would measure the second one on a machine that the
#   first had already heated, and on a laptop that difference is larger than
#   several of the ratios we are trying to report.
#
# Both sides get identical iteration budgets, class-split the same way
# bench.zig splits them (the "s" sets sign far slower than the "f" sets).
# The budgets here are deliberately larger than bench.zig's interactive
# defaults: those are tuned to keep `zig build bench` snappy, which is the
# wrong trade for a number that gets published.
#
# Environment:
#   PQCLEAN_DIR   reuse an existing PQClean checkout
#   PQCLEAN_REF   pin a different PQClean commit
#   PARAM_SETS    subset of FIPS 205 names, space separated
#   ZIG_BUILD_ARGS extra args for `zig build` (e.g. -Dcpu=apple_m3-sha2 to
#                  measure the portable SHA-2 path with no ARMv8 crypto
#                  extensions)
#   IMPL_LABEL    label for the zig rows (default slh-dsa-zig)
#   KEYGEN_ITERS_F / SIGN_ITERS_F / VERIFY_ITERS_F  budgets for "f" sets
#   KEYGEN_ITERS_S / SIGN_ITERS_S / VERIFY_ITERS_S  budgets for "s" sets
#
# Lane: Lane A (bench infrastructure). Not part of the Zig build graph.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

ZIG_BUILD_ARGS="${ZIG_BUILD_ARGS:-}"
IMPL_LABEL="${IMPL_LABEL:-slh-dsa-zig}"

# Published-run budgets. Larger than bench.zig's interactive defaults.
KEYGEN_ITERS_F="${KEYGEN_ITERS_F:-100}"
SIGN_ITERS_F="${SIGN_ITERS_F:-100}"
VERIFY_ITERS_F="${VERIFY_ITERS_F:-1000}"
KEYGEN_ITERS_S="${KEYGEN_ITERS_S:-30}"
SIGN_ITERS_S="${SIGN_ITERS_S:-20}"
VERIFY_ITERS_S="${VERIFY_ITERS_S:-1000}"

ALL_PARAM_SETS="
SLH-DSA-SHA2-128s
SLH-DSA-SHA2-128f
SLH-DSA-SHA2-192s
SLH-DSA-SHA2-192f
SLH-DSA-SHA2-256s
SLH-DSA-SHA2-256f
SLH-DSA-SHAKE-128s
SLH-DSA-SHAKE-128f
SLH-DSA-SHAKE-192s
SLH-DSA-SHAKE-192f
SLH-DSA-SHAKE-256s
SLH-DSA-SHAKE-256f
"
PARAM_SETS="${PARAM_SETS:-$ALL_PARAM_SETS}"

# FIPS 205 name -> PQClean directory name.
# SLH-DSA-SHA2-128f -> sphincs-sha2-128f-simple
pqclean_name() {
    echo "$1" \
        | sed -e 's/^SLH-DSA-/sphincs-/' \
        | tr '[:upper:]' '[:lower:]' \
        | sed -e 's/$/-simple/'
}

{
    echo "# interleaved comparison run"
    echo "# zig:            $(zig version) ${ZIG_BUILD_ARGS:-(default target)}"
    echo "# impl_label:     $IMPL_LABEL"
    echo "# budgets f:      keygen=$KEYGEN_ITERS_F sign=$SIGN_ITERS_F verify=$VERIFY_ITERS_F"
    echo "# budgets s:      keygen=$KEYGEN_ITERS_S sign=$SIGN_ITERS_S verify=$VERIFY_ITERS_S"
} >&2

echo "impl,param_set,op,iters,median_ns,mean_ns,min_ns,max_ns"

for ps in $PARAM_SETS; do
    case "$ps" in
        *s) kg="$KEYGEN_ITERS_S"; sg="$SIGN_ITERS_S"; vf="$VERIFY_ITERS_S" ;;
        *)  kg="$KEYGEN_ITERS_F"; sg="$SIGN_ITERS_F"; vf="$VERIFY_ITERS_F" ;;
    esac

    echo "==> $ps (keygen=$kg sign=$sg verify=$vf)" >&2

    # --- zig side ---
    # One invocation per op, because bench.zig's --iters applies to all three
    # ops at once and we want a different budget for verify.
    for pair in "keygen:$kg" "sign:$sg" "verify:$vf"; do
        op="${pair%%:*}"
        iters="${pair##*:}"
        # sed rather than `grep -v`: grep exits 1 when it selects no lines,
        # which under `set -o pipefail` would abort the run.
        # shellcheck disable=SC2086
        (cd "$REPO" && zig build bench $ZIG_BUILD_ARGS -- \
            --param-set "$ps" --op "$op" --iters "$iters" --csv) \
            | sed -e '/^impl,/d' -e "s/^slh-dsa-zig,/$IMPL_LABEL,/"
    done

    # --- PQClean side, immediately after, same machine state ---
    PARAM_SETS="$(pqclean_name "$ps")" \
    KEYGEN_ITERS="$kg" SIGN_ITERS="$sg" VERIFY_ITERS="$vf" \
        "$HERE/run.sh" | sed -e '/^impl,/d'
done

echo "==> done" >&2
