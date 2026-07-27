#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$script_dir/runner_support.sh"
. "$script_dir/qualification_receipts.sh"
. "$script_dir/qualification_bundle_support.sh"
tab=$(printf '\t')

usage() {
    echo "usage: verify_qualification_bundle.sh BUNDLE_ROOT EXPECTED_BUNDLE_SHA256 REPOSITORY" >&2
    exit 2
}

if [ "$#" != 3 ]; then
    usage
fi

root_argument=$1
expected_bundle_sha256=$2
repository_argument=$3
case "$root_argument:$repository_argument" in
    /*:/*) ;;
    *)
        echo "bundle root and repository must be absolute paths" >&2
        exit 2
        ;;
esac
if ! fre_jit_nonzero_sha256 "$expected_bundle_sha256"; then
    echo "expected bundle SHA-256 must be 64 nonzero lowercase hex digits" >&2
    exit 2
fi
if [ ! -d "$root_argument" ] || [ -L "$root_argument" ]; then
    echo "bundle root must be an existing non-symlink directory" >&2
    exit 2
fi
if [ ! -d "$repository_argument" ] || [ -L "$repository_argument" ]; then
    echo "repository must be an existing non-symlink directory" >&2
    exit 2
fi
root=$(CDPATH= cd -P -- "$root_argument" && pwd -P)
repository=$(CDPATH= cd -P -- "$repository_argument" && pwd -P)
bundle="$root/qualification-bundle-v1.tsv"
if [ ! -f "$bundle" ] || [ -L "$bundle" ]; then
    echo "missing canonical qualification-bundle-v1.tsv" >&2
    exit 2
fi
if [ "$(fre_bakeoff_sha256 "$bundle")" != "$expected_bundle_sha256" ]; then
    echo "qualification bundle differs from its external SHA-256" >&2
    exit 2
fi

temporary=$(mktemp -d "${TMPDIR:-/tmp}/fre-jit-qualification-verify.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

LC_ALL=C awk -F '	' '
    NR == 1 {
        if (NF != 2 || $1 != "schema" ||
            $2 != "fre-qualified-exact-qualification-bundle-v1") bad = 1
        next
    }
    NR == 2 {
        if (NF != 2 || $1 != "subject_revision" ||
            $2 !~ /^[0-9a-f]{40}$/) bad = 1
        next
    }
    NR == 3 {
        if (NF != 2 || $1 != "subject_tree" ||
            $2 !~ /^[0-9a-f]{40}$/) bad = 1
        next
    }
    {
        if (NF != 5 || $1 != "entry" ||
            $3 !~ /^[0-9a-f]{64}$/ ||
            $4 !~ /^(0|[1-9][0-9]*)$/ ||
            $5 == "" || seen[$5]++ ||
            $5 ~ /^\// || $5 ~ /\/\// ||
            $5 ~ /(^|\/)[.][.]?(\/|$)/ ||
            $5 !~ /^[A-Za-z0-9._\/-]+$/) {
            bad = 1
            next
        }
        key = $2 SUBSEP $5
        if (previous != "" && key <= previous) bad = 1
        previous = key
        print $2 "\t" $5 > entries
    }
    END {
        if (NR < 13) bad = 1
        exit bad
    }
' entries="$temporary/inputs.tsv" "$bundle"
fre_jit_bundle_validate_entry_contract "$temporary/inputs.tsv"

subject_revision=$(awk -F '	' 'NR == 2 { print $2 }' "$bundle")
subject_tree=$(awk -F '	' 'NR == 3 { print $2 }' "$bundle")
fre_bakeoff_validate_exact_clean_commit \
    "$repository" "$subject_revision" qualification_bundle_subject
test "$(git -C "$repository" show -s --format=%T "$subject_revision")" = \
    "$subject_tree"

canonical_entry_file() {
    relative=$1
    candidate="$root/$relative"
    if [ ! -f "$candidate" ] || [ -L "$candidate" ]; then
        echo "missing or non-regular qualification input: $relative" >&2
        return 2
    fi
    parent=$(CDPATH= cd -P -- "$(dirname -- "$candidate")" && pwd -P) || return 2
    canonical="$parent/$(basename -- "$candidate")"
    if [ "$canonical" != "$candidate" ]; then
        echo "qualification input traverses a symlink or alias: $relative" >&2
        return 2
    fi
}

while IFS=$tab read -r kind relative; do
    canonical_entry_file "$relative"
done < "$temporary/inputs.tsv"
fre_jit_bundle_require_exact_inventory \
    "$root" "$temporary/inputs.tsv" "$temporary/inventory-before"
fre_jit_bundle_entry_records \
    "$root" "$temporary/inputs.tsv" "$temporary/entries-before.tsv"
tail -n +4 "$bundle" > "$temporary/declared-entries.tsv"
cmp -s "$temporary/entries-before.tsv" "$temporary/declared-entries.tsv" || {
    echo "qualification entry content differs from the bundle manifest" >&2
    exit 2
}

fre_jit_bundle_copy_snapshot \
    "$root" "$temporary/inputs.tsv" "$temporary/snapshot"
fre_jit_bundle_entry_records \
    "$temporary/snapshot" "$temporary/inputs.tsv" \
    "$temporary/entries-snapshot.tsv"
cmp -s "$temporary/entries-before.tsv" "$temporary/entries-snapshot.tsv" || {
    echo "frozen snapshot differs from the pre-copy qualification state" >&2
    exit 2
}
fre_jit_bundle_entry_records \
    "$root" "$temporary/inputs.tsv" "$temporary/entries-after-copy.tsv"
cmp -s "$temporary/entries-before.tsv" "$temporary/entries-after-copy.tsv" || {
    echo "qualification entry changed while verification snapshotted it" >&2
    exit 2
}
test "$(fre_bakeoff_sha256 "$bundle")" = "$expected_bundle_sha256"
fre_jit_bundle_require_exact_inventory \
    "$root" "$temporary/inputs.tsv" "$temporary/inventory-after-copy"
cmp -s \
    "$temporary/inventory-before.inventory" \
    "$temporary/inventory-after-copy.inventory" || {
    echo "qualification inventory changed while verification snapshotted it" >&2
    exit 2
}

promotion="$temporary/snapshot/$FRE_JIT_BUNDLE_PROMOTION_GATE"
review="$temporary/snapshot/$FRE_JIT_BUNDLE_REVIEW"
findings="$temporary/snapshot/$FRE_JIT_BUNDLE_FINDINGS"
fre_jit_validate_promotion_gate_receipt \
    "$promotion" "$repository" "$subject_revision" "$subject_tree"
fre_jit_validate_independent_review_receipt \
    "$review" "$repository" "$subject_revision" "$subject_tree"
fre_jit_bundle_validate_artifact_bindings "$temporary/snapshot"
test "$(awk -F '	' 'NR == 7 { print $2 }' "$review")" = \
    "$(fre_bakeoff_sha256 "$findings")"
fre_jit_bundle_replay_gate \
    "$temporary/snapshot" "$repository" "$subject_revision" "$temporary/replay"

awk -F '	' '$1 == "input_sha256" {
    print "entry\tresult\t" $2 "\t" $3 "\t" $4
}' "$promotion" | LC_ALL=C sort > "$temporary/replayed-results.tsv"
awk -F '	' '$1 == "entry" && $2 == "result" { print }' \
    "$temporary/entries-before.tsv" |
    LC_ALL=C sort > "$temporary/declared-results.tsv"
cmp -s "$temporary/replayed-results.tsv" "$temporary/declared-results.tsv" || {
    echo "replayed gate inputs do not exactly equal bundled result entries" >&2
    exit 2
}

fre_jit_bundle_entry_records \
    "$root" "$temporary/inputs.tsv" "$temporary/entries-after-replay.tsv"
cmp -s "$temporary/entries-before.tsv" "$temporary/entries-after-replay.tsv" || {
    echo "qualification entry changed during semantic replay" >&2
    exit 2
}
fre_jit_bundle_require_exact_inventory \
    "$root" "$temporary/inputs.tsv" "$temporary/inventory-after-replay"
cmp -s \
    "$temporary/inventory-before.inventory" \
    "$temporary/inventory-after-replay.inventory" || {
    echo "qualification inventory changed during semantic replay" >&2
    exit 2
}
test "$(fre_bakeoff_sha256 "$bundle")" = "$expected_bundle_sha256"

echo "verified: frozen complete inventory, exact Q replay, binary receipts, review, and external hash agree"
