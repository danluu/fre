#!/bin/sh
set -eu

directory=${1:?usage: verify_provenance.sh RESULT_DIRECTORY}
source_dir="$directory/provenance/source"
source_state_file="$source_dir/source-state-id.txt"
receipt="$directory/provenance/build-receipt.tsv"
receipt_sha_file="$directory/provenance/build-receipt.sha256"
receipt_path_file="$directory/provenance/build-receipt-source-path.txt"
binary_sha_file="$directory/provenance/binary.sha256"
binary_path_file="$directory/provenance/binary-path.txt"
environment="$directory/environment.txt"
completion="$directory/completion.txt"
raw="$directory/raw.csv"

for required in \
    "$source_state_file" \
    "$source_dir/source-inputs.sha256" \
    "$source_dir/source-digest.txt" \
    "$source_dir/head.txt" \
    "$source_dir/dirty.txt" \
    "$receipt" \
    "$receipt_sha_file" \
    "$receipt_path_file" \
    "$binary_sha_file" \
    "$binary_path_file" \
    "$environment" \
    "$completion" \
    "$raw"
do
    test -f "$required"
done

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$script_dir/runner_support.sh"
fre_bakeoff_validate_build_receipt "$receipt"

source_state=$(sed -n '1p' "$source_state_file")
source_digest=$(sed -n '1p' "$source_dir/source-digest.txt")
source_head=$(sed -n '1p' "$source_dir/head.txt")
source_dirty=$(sed -n '1p' "$source_dir/dirty.txt")
expected_receipt_sha=$(sed -n '1p' "$receipt_sha_file")
expected_receipt_path=$(sed -n '1p' "$receipt_path_file")
expected_binary_sha=$(sed -n '1p' "$binary_sha_file")
expected_binary_path=$(sed -n '1p' "$binary_path_file")
actual_receipt_sha=$(fre_bakeoff_sha256 "$receipt")
receipt_source=$(fre_bakeoff_receipt_field "$receipt" source_state_id)
receipt_binary_path=$(fre_bakeoff_receipt_field "$receipt" binary_path)
receipt_binary_sha=$(fre_bakeoff_receipt_field "$receipt" binary_sha256)

(
    cd "$source_dir"
    shasum -a 256 -c source-inputs.sha256 > /dev/null
)
test "$(fre_bakeoff_sha256 "$source_dir/source-inputs.sha256")" = "$source_digest"
case "$source_dirty" in
    0) test "$source_state" = "$source_head" ;;
    1) test "$source_state" = "${source_head}+dirty.${source_digest}" ;;
    *) exit 1 ;;
esac
test "$actual_receipt_sha" = "$expected_receipt_sha"
test "$receipt_source" = "$source_state"
test "$receipt_binary_path" = "$expected_binary_path"
test "$receipt_binary_sha" = "$expected_binary_sha"
test -f "$directory/provenance/source/verified-at-finish.txt"

environment_source=$(
    awk -F= '$1 == "source_state_id" { if (found++) exit 2; print substr($0, index($0, "=") + 1) }' \
        "$environment"
)
completion_source=$(
    awk -F= '$1 == "source_state_id" { if (found++) exit 2; print substr($0, index($0, "=") + 1) }' \
        "$completion"
)
environment_binary=$(
    awk -F= '$1 == "binary" { if (found++) exit 2; print substr($0, index($0, "=") + 1) }' \
        "$environment"
)
environment_receipt=$(
    awk -F= '$1 == "build_receipt" { if (found++) exit 2; print substr($0, index($0, "=") + 1) }' \
        "$environment"
)
test "$environment_source" = "$source_state"
test "$completion_source" = "$source_state"
test "$environment_binary" = "$expected_binary_sha  $expected_binary_path"
test "$environment_receipt" = "$expected_receipt_sha  $expected_receipt_path"

awk -F, -v source_state="$source_state" '
    NR == 1 { next }
    {
        revision[$2] = 1
        if ($2 != source_state) bad = 1
    }
    END {
        revisions = 0
        for (key in revision) revisions++
        if (revisions != 1) bad = 1
        exit bad
    }
' "$raw"

echo "verified: source state, build receipt, binary hash, and raw revisions agree"
