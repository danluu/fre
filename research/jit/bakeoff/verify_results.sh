#!/bin/sh
set -eu

directory=${1:?usage: verify_results.sh RESULT_DIRECTORY}
raw="$directory/raw.csv"

test -f "$raw"
awk -F, '
NR == 1 { next }
{
    sample[$5 SUBSEP $12 SUBSEP $13]++
    cell[$5] = 1
    if ($18 == "" || $19 == "") bad = 1
}
END {
    for (key in sample) {
        if (sample[key] != 5) {
            print "expected five process samples for " key ", got " sample[key] > "/dev/stderr"
            bad = 1
        }
    }
    synthetic = 0
    fixture = 0
    for (key in cell) {
        if (key == "exact-count-rebar-sherlock") fixture++
        else synthetic++
    }
    if (synthetic != 90 || fixture != 1) {
        print "expected 90 synthetic cells and one fixture cell, got " synthetic " and " fixture > "/dev/stderr"
        bad = 1
    }
    exit bad
}' "$raw"

echo "verified: five samples for every stage in 90 synthetic cells plus the Sherlock fixture"
