#!/bin/sh
set -eu

raw=${1:?usage: verify_evidence_identity.sh RAW_CSV}
awk -F, '
    NR == 1 {
        for (column = 1; column <= NF; column++) {
            if ($column in index_of) exit 2
            index_of[$column] = column
        }
        if (!("evidence_identity" in index_of) ||
            !("evidence_binding" in index_of)) exit 2
        next
    }
    $index_of["engine"] == "fre-qualified-exact" ||
        $index_of["engine"] == "fre-qualified-exact-under-threshold" {
        print $index_of["evidence_identity"] "\t" $index_of["evidence_binding"]
    }
' "$raw" |
while IFS='	' read -r expected binding; do
    actual=$(printf '%s' "$binding" | shasum -a 256 | awk '{print $1}')
    if [ "$actual" != "$expected" ]; then
        echo "qualified evidence identity does not hash its canonical binding" >&2
        exit 1
    fi
done
