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
# Exits non-zero if any parameter set/op exceeds the gate, so this doubles as
# a check rather than only a formatter.
#
# Lane: Lane A (bench infrastructure).

set -euo pipefail

GATE="${GATE:-2.0}"

awk -F, -v gate="$GATE" '
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
    worst = 0; worst_key = ""; fails = 0
    for (i = 1; i <= n; i++) {
        key = order[i]
        split(key, parts, SUBSEP)
        ps = parts[1]; op = parts[2]
        if (!(key in zig) || !(key in ref) || ref[key] == 0) continue
        r = zig[key] / ref[key]
        if (r > worst) { worst = r; worst_key = ps " " op }
        ok = (r <= gate + 1e-9) ? "pass" : "**FAIL**"
        if (r > gate + 1e-9) fails++
        printf "| %s | %s | %d | %s | %s | %.2fx | %s |\n", \
            ps, op, it[key], fmt(zig[key]), fmt(ref[key]), r, ok
    }

    # Supplementary table: only emitted when a portable-build pass is present.
    have_port = 0
    for (i = 1; i <= n; i++) if (order[i] in port) have_port = 1
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

    printf "\nWorst ratio: %.2fx (%s). Gate: <= %.2fx.\n", worst, worst_key, gate

    # The optrand fairness note: PQClean draws its randomiser inside the timed
    # sign call, bench.zig does not. Show the cost so the reader can size it.
    for (ps in probe) {
        printf "PQClean randombytes(n) probe, %s: %s per draw.\n", ps, fmt(probe[ps])
        break
    }

    if (fails > 0) {
        printf "\n%d measurement(s) exceeded the gate.\n", fails
        exit 1
    }
}
'
