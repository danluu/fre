#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$script_dir/runner_support.sh"
. "$script_dir/qualification_receipts.sh"
. "$script_dir/qualification_bundle_support.sh"
tab=$(printf '\t')

usage() {
    echo "usage: make_qualification_bundle.sh BUNDLE_ROOT REPOSITORY Q_REVISION INPUTS_TSV" >&2
    exit 2
}

if [ "$#" != 4 ]; then
    usage
fi

root_argument=$1
repository_argument=$2
subject_argument=$3
inputs=$4
case "$root_argument:$repository_argument" in
    /*:/*) ;;
    *)
        echo "bundle root and repository must be absolute paths" >&2
        exit 2
        ;;
esac
if [ ! -d "$root_argument" ] || [ -L "$root_argument" ]; then
    echo "bundle root must be an existing non-symlink directory" >&2
    exit 2
fi
if [ ! -d "$repository_argument" ] || [ -L "$repository_argument" ]; then
    echo "repository must be an existing non-symlink directory" >&2
    exit 2
fi
if [ ! -f "$inputs" ] || [ -L "$inputs" ]; then
    echo "bundle input list must be a regular non-symlink file" >&2
    exit 2
fi
root=$(CDPATH= cd -P -- "$root_argument" && pwd -P)
repository=$(CDPATH= cd -P -- "$repository_argument" && pwd -P)
bundle="$root/qualification-bundle-v1.tsv"
if [ -e "$bundle" ] || [ -L "$bundle" ]; then
    echo "refusing to overwrite existing qualification bundle" >&2
    exit 2
fi

fre_bakeoff_validate_exact_clean_commit \
    "$repository" "$subject_argument" Q_revision
subject_revision=$subject_argument
subject_tree=$(git -C "$repository" show -s --format=%T "$subject_revision")

temporary=$(mktemp -d "${TMPDIR:-/tmp}/fre-jit-qualification-bundle.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

LC_ALL=C awk -F '	' '
    NF != 2 || $1 == "" || $2 == "" { bad = 1; next }
    {
        if ($2 ~ /^\// || $2 ~ /\/\// ||
            $2 ~ /(^|\/)[.][.]?(\/|$)/ ||
            $2 !~ /^[A-Za-z0-9._\/-]+$/ ||
            seen[$2]++) bad = 1
        print
    }
    END { exit bad }
' "$inputs" | LC_ALL=C sort -t '	' -k1,1 -k2,2 \
    > "$temporary/inputs.tsv"
if [ ! -s "$temporary/inputs.tsv" ]; then
    echo "qualification bundle has no canonical inputs" >&2
    exit 2
fi
fre_jit_bundle_validate_entry_contract "$temporary/inputs.tsv"

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

# All semantic checks run on one immutable copy.  The original tree is hashed
# again both before and after replay so a concurrent writer cannot splice two
# source states into one manifest.
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
    echo "qualification input changed while the snapshot was copied" >&2
    exit 2
}
fre_jit_bundle_require_exact_inventory \
    "$root" "$temporary/inputs.tsv" "$temporary/inventory-after-copy"
cmp -s \
    "$temporary/inventory-before.inventory" \
    "$temporary/inventory-after-copy.inventory" || {
    echo "qualification inventory changed while the snapshot was copied" >&2
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
findings_sha256=$(awk -F '	' 'NR == 7 { print $2 }' "$review")
test "$findings_sha256" = "$(fre_bakeoff_sha256 "$findings")"

fre_jit_bundle_replay_gate \
    "$temporary/snapshot" "$repository" "$subject_revision" "$temporary/replay"

# Replayed input rows must be byte/size-identical to every result entry and to
# no other entry.
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
    echo "qualification input changed while the gate was replayed" >&2
    exit 2
}
fre_jit_bundle_require_exact_inventory \
    "$root" "$temporary/inputs.tsv" "$temporary/inventory-after-replay"
cmp -s \
    "$temporary/inventory-before.inventory" \
    "$temporary/inventory-after-replay.inventory" || {
    echo "qualification inventory changed while the gate was replayed" >&2
    exit 2
}

{
    printf 'schema\tfre-qualified-exact-qualification-bundle-v1\n'
    printf 'subject_revision\t%s\n' "$subject_revision"
    printf 'subject_tree\t%s\n' "$subject_tree"
    cat "$temporary/entries-before.tsv"
} > "$temporary/qualification-bundle-v1.tsv"

mv -- "$temporary/qualification-bundle-v1.tsv" "$bundle"
printf 'bundle=%s\n' "$bundle"
printf 'bundle_sha256=%s\n' "$(fre_bakeoff_sha256 "$bundle")"
