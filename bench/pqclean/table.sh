#!/usr/bin/env bash
#
# Render the joined CSV from compare.sh as the markdown table published in
# bench/README.md.
#
#   ./bench/pqclean/compare.sh > results.csv
#   ./bench/pqclean/table.sh < results.csv
#
# Ratio is zig_median / pqclean_median, so lower is better and the project's
# gate is "<= 2.00". The gate is checked against PQClean's `clean` variant
# only; see bench/README.md for why AVX2 is reported but never gated on.
#
# This doubles as the gate check rather than being only a formatter:
#
#   0  a complete result set, every measurement within the gate
#   1  at least one measurement exceeded the gate
#   2  the input could not be gated -- no comparable pairs at all, a
#      (param_set, op) with one side's row but not the other, or fewer
#      measurements than EXPECT
#
# Exit 2 exists because a silently short table is the dangerous failure: an
# interrupted run would otherwise print three green rows and exit 0.
#
# Environment:
#   GATE    ratio ceiling (default 2.0)
#   EXPECT  required measurement count (default 36 = 12 sets x 3 ops); set
#           explicitly to gate a deliberate subset
#
# Lane: Lane A (bench infrastructure).

set -euo pipefail

GATE="${GATE:-2.0}"
# 12 parameter sets x {keygen, sign, verify}. A run that stopped early is the
# failure this guards: it yields complete *pairs*, just not all of them, so
# pair-level validation alone would pass it. Set EXPECT explicitly when
# gating a deliberate subset (e.g. EXPECT=3 for one parameter set, EXPECT=18
# for the six SHA-2 sets in a portable-only pass).
EXPECT="${EXPECT:-36}"

awk -F, -v gate="$GATE" -v expect="$EXPECT" '
function fmt(ns) {
    if (ns < 1000)      return sprintf("%d ns", ns)
    else if (ns < 1e6)  return sprintf("%.2f us", ns / 1000)
    else                return sprintf("%.2f ms", ns / 1e6)
}
# Preserve first-seen order of (param_set, op) pairs for stable output.
function remember(key) {
    if (!(key in seen)) { seen[key] = 1; order[++n] = key }
}
/^#/ || /^==>/ || /^impl,/ { next }
NF < 8 { next }
{
    impl = $1; ps = $2; op = $3; iters = $4; median = $5
    if (op == "randombytes") { probe[ps] = median; next }
    key = ps SUBSEP op
    remember(key)
    it[key] = iters
    if (impl == "pqclean-clean")            ref[key]  = median
    else if (impl ~ /portable/)             port[key] = median
    else                                    zig[key]  = median
}
END {
    print "| param set | op | iters | slh-dsa-zig | PQClean `clean` | ratio | gate |"
    print "|---|---|---:|---:|---:|---:|:---:|"
    worst = 0; worst_key = ""; fails = 0; rows = 0; incomplete = 0
    for (i = 1; i <= n; i++) {
        key = order[i]
        split(key, parts, SUBSEP)
        ps = parts[1]; op = parts[2]

        # A half-populated pair is a broken run, not a row to skip quietly.
        # This script is the gate check, so an incomplete CSV must fail rather
        # than produce a short table that reads as a pass. The one legitimate
        # exception is a portable-only run, which carries port+ref and no zig.
        if (!(key in zig)) {
            if ((key in ref) && (key in port)) continue        # portable-only run
            incomplete++
            problems[incomplete] = ps " " op ": no slh-dsa-zig row"
            continue
        }
        if (!(key in ref)) {
            incomplete++
            problems[incomplete] = ps " " op ": no pqclean-clean row"
            continue
        }
        if (ref[key] == 0) {
            incomplete++
            problems[incomplete] = ps " " op ": pqclean-clean median is zero"
            continue
        }

        rows++
        r = zig[key] / ref[key]
        if (r > worst) { worst = r; worst_key = ps " " op }
        ok = (r <= gate + 1e-9) ? "pass" : "**FAIL**"
        if (r > gate + 1e-9) fails++
        printf "| %s | %s | %d | %s | %s | %.2fx | %s |\n", \
            ps, op, it[key], fmt(zig[key]), fmt(ref[key]), r, ok
    }

    # Supplementary table: only emitted when a portable-build pass is present.
    have_port = 0; port_rows = 0
    for (i = 1; i <= n; i++) if (order[i] in port) { have_port = 1; port_rows++ }
    if (have_port) {
        print ""
        print "Portable build (ARMv8 crypto extensions disabled), isolating the"
        print "algorithmic comparison from hardware SHA-2 acceleration:"
        print ""
        print "| param set | op | zig (portable) | PQClean `clean` | ratio |"
        print "|---|---|---:|---:|---:|"
        for (i = 1; i <= n; i++) {
            key = order[i]
            split(key, parts, SUBSEP)
            if (!(key in port) || !(key in ref) || ref[key] == 0) continue
            printf "| %s | %s | %s | %s | %.2fx |\n", \
                parts[1], parts[2], fmt(port[key]), fmt(ref[key]), port[key] / ref[key]
        }
    }

    if (rows > 0)
        printf "\nWorst ratio: %.2fx (%s) over %d measurement(s). Gate: <= %.2fx.\n", \
            worst, worst_key, rows, gate

    # The optrand fairness note: PQClean draws its randomiser inside the timed
    # sign call, bench.zig does not. Show the cost so the reader can size it.
    for (ps in probe) {
        printf "PQClean randombytes(n) probe, %s: %s per draw.\n", ps, fmt(probe[ps])
        break
    }

    # Report the specific diagnosis before the generic one: a run that lost
    # one side names the pairs it lost, rather than only saying "nothing to
    # compare".
    if (incomplete > 0) {
        printf "\n%d incomplete comparison(s) -- each needs both a slh-dsa-zig and a pqclean-clean row:\n", \
            incomplete > "/dev/stderr"
        for (i = 1; i <= incomplete; i++) printf "  - %s\n", problems[i] > "/dev/stderr"
        exit 2
    }

    # An empty gate table must never look like a pass. Reaching here with no
    # comparable rows means the CSV was empty or malformed.
    if (rows == 0 && !have_port) {
        print "\nerror: no comparable (param_set, op) pairs found in the input." > "/dev/stderr"
        exit 2
    }

    # Completeness. Pair-level validation above catches a run that lost one
    # *side*; it cannot catch a run that stopped cleanly at a parameter-set
    # boundary, which leaves whole sets absent while every surviving pair is
    # intact. An interrupted sweep would otherwise print three green rows and
    # exit 0 -- a short table reading as a pass is the exact failure this
    # script exists to prevent, so completeness is checked explicitly.
    #
    # Counted against whichever table this CSV actually produced: the gate
    # table normally, the portable table for a supplementary-only pass.
    actual = (rows > 0) ? rows : port_rows
    if (actual != expect) {
        printf "\nerror: expected %d measurements, found %d.\n", expect, actual > "/dev/stderr"
        print "  An interrupted run yields complete pairs but incomplete coverage." > "/dev/stderr"
        print "  Re-run the full sweep, or set EXPECT=<n> to gate a deliberate subset." > "/dev/stderr"
        exit 2
    }

    if (fails > 0) {
        printf "\n%d measurement(s) exceeded the gate.\n", fails
        exit 1
    }
}
'
