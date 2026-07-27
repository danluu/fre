#!/bin/sh
set -eu

directory=${1:?usage: verify_qualification_results.sh RESULT_DIRECTORY EXPECTED_SYNTHETIC_CELLS}
expected_cells=${2:?usage: verify_qualification_results.sh RESULT_DIRECTORY EXPECTED_SYNTHETIC_CELLS}
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
raw="$directory/raw.csv"
instructions="$directory/exact-span.instructions.txt"

"$script_dir/verify_provenance.sh" "$directory"
test -f "$raw"
test -f "$instructions"
span_identity=$(
    awk -F= '
        $1 == "identity" {
            if (found++) exit 2
            print $2
        }
        END { if (!found) exit 2 }
    ' "$instructions"
)
case "$span_identity" in
    *[!0-9a-f]*|"")
        echo "malformed exact-span artifact identity" >&2
        exit 2
        ;;
esac
if [ "${#span_identity}" != 64 ]; then
    echo "exact-span artifact identity must contain 64 lowercase hex digits" >&2
    exit 2
fi

awk -v span_identity="$span_identity" \
    -f "$script_dir/verify_evidence_rows.awk" "$raw"
"$script_dir/verify_evidence_identity.sh" "$raw"

awk -F, -v expected_cells="$expected_cells" '
NR == 1 { next }
{
    sample[$5 SUBSEP $12 SUBSEP $13]++
    cell[$5] = 1
    shape[$5] = $6
    fixture[$5] = $35
}
END {
    for (key in sample) {
        if (sample[key] != 5) {
            print "expected five process samples for " key ", got " sample[key] > "/dev/stderr"
            bad = 1
        }
    }
    synthetic = 0
    sherlock = 0
    for (key in cell) {
        if (key == "exact-count-rebar-sherlock") {
            sherlock++
            continue
        }
        synthetic++
        if (shape[key] == "exact") {
            required[key SUBSEP "fre-qualified-exact" SUBSEP "search"] = 1
            required[key SUBSEP "fre-qualified-exact" SUBSEP "build_full_workload"] = 1
            required[key SUBSEP "fre-qualified-exact-under-threshold" SUBSEP "search"] = 1
            required[key SUBSEP "fre-qualified-exact-under-threshold" SUBSEP "build_full_workload"] = 1
        }
    }
    if (synthetic != expected_cells) {
        print "expected " expected_cells " synthetic cells, got " synthetic > "/dev/stderr"
        bad = 1
    }
    for (key in required) {
        if (sample[key] != 5) {
            print "missing qualified five-sample stage " key > "/dev/stderr"
            bad = 1
        }
    }
    exit bad
}' "$raw"

echo "verified: provenance, actual-route evidence, declared workload, and measured calls agree"
