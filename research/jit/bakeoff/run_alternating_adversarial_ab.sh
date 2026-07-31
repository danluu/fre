#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
workspace=$(CDPATH= cd -P -- "$script_dir/../../.." && pwd -P)
output=${1:?usage: run_alternating_adversarial_ab.sh ABSOLUTE_OUTPUT BASELINE_RECEIPT CANDIDATE_RECEIPT}
baseline_receipt=${2:?usage: run_alternating_adversarial_ab.sh ABSOLUTE_OUTPUT BASELINE_RECEIPT CANDIDATE_RECEIPT}
candidate_receipt=${3:?usage: run_alternating_adversarial_ab.sh ABSOLUTE_OUTPUT BASELINE_RECEIPT CANDIDATE_RECEIPT}
if [ "$#" != 3 ]; then
    echo "usage: run_alternating_adversarial_ab.sh ABSOLUTE_OUTPUT BASELINE_RECEIPT CANDIDATE_RECEIPT" >&2
    exit 2
fi

. "$script_dir/runner_support.sh"

validate_clean_source_bundle() {
    receipt=$1
    expected_source=$2
    bundle="$(dirname -- "$receipt")/source"
    for required in \
        "$bundle/source-state-id.txt" \
        "$bundle/source-inputs.sha256" \
        "$bundle/source-digest.txt" \
        "$bundle/head.txt" \
        "$bundle/dirty.txt"
    do
        test -f "$required"
    done
    (
        cd "$bundle"
        shasum -a 256 -c source-inputs.sha256 > /dev/null
    )
    test "$(sed -n '1p' "$bundle/dirty.txt")" = 0
    test "$(sed -n '1p' "$bundle/head.txt")" = "$expected_source"
    test "$(sed -n '1p' "$bundle/source-state-id.txt")" = "$expected_source"
    test "$(fre_bakeoff_sha256 "$bundle/source-inputs.sha256")" = \
        "$(sed -n '1p' "$bundle/source-digest.txt")"
}

materialize_baseline_verifiers() {
    source=$1
    destination=$2
    rows_path=research/jit/bakeoff/verify_evidence_rows.awk
    identity_path=research/jit/bakeoff/verify_evidence_identity.sh
    rows_object="$source:$rows_path"
    identity_object="$source:$identity_path"
    test "$(git -C "$workspace" cat-file -t "$rows_object")" = blob
    test "$(git -C "$workspace" cat-file -t "$identity_object")" = blob
    mkdir -- "$destination"
    git -C "$workspace" show "$rows_object" > "$destination/verify_evidence_rows.awk"
    git -C "$workspace" show "$identity_object" > "$destination/verify_evidence_identity.sh"
    rows_blob=$(git -C "$workspace" rev-parse "$rows_object")
    identity_blob=$(git -C "$workspace" rev-parse "$identity_object")
    baseline_rows_sha=$(
        fre_bakeoff_sha256 "$destination/verify_evidence_rows.awk"
    )
    baseline_identity_sha=$(
        fre_bakeoff_sha256 "$destination/verify_evidence_identity.sh"
    )
    {
        printf 'schema\tfre-jit-baseline-evidence-verifier-v1\n'
        printf 'source_revision\t%s\n' "$source"
        printf 'rows_blob\t%s\n' "$rows_blob"
        printf 'rows_sha256\t%s\n' "$baseline_rows_sha"
        printf 'identity_blob\t%s\n' "$identity_blob"
        printf 'identity_sha256\t%s\n' "$baseline_identity_sha"
    } > "$destination/verifier-receipt.tsv"
}

fre_bakeoff_require_holder timing
fre_bakeoff_canonical_new_external_directory "$workspace" "$output"
output=$FRE_BAKEOFF_CANONICAL_PATH
fre_bakeoff_canonical_regular_file "$baseline_receipt" baseline_receipt
baseline_receipt=$FRE_BAKEOFF_CANONICAL_PATH
fre_bakeoff_canonical_regular_file "$candidate_receipt" candidate_receipt
candidate_receipt=$FRE_BAKEOFF_CANONICAL_PATH
fre_bakeoff_validate_build_receipt "$baseline_receipt"
fre_bakeoff_validate_build_receipt "$candidate_receipt"

baseline_source=$(fre_bakeoff_receipt_field "$baseline_receipt" source_state_id)
candidate_source=$(fre_bakeoff_receipt_field "$candidate_receipt" source_state_id)
baseline_binary=$(fre_bakeoff_receipt_field "$baseline_receipt" binary_path)
candidate_binary=$(fre_bakeoff_receipt_field "$candidate_receipt" binary_path)
baseline_binary_sha=$(fre_bakeoff_receipt_field "$baseline_receipt" binary_sha256)
candidate_binary_sha=$(fre_bakeoff_receipt_field "$candidate_receipt" binary_sha256)
fre_bakeoff_canonical_executable "$baseline_binary" baseline_binary
baseline_binary=$FRE_BAKEOFF_CANONICAL_PATH
fre_bakeoff_canonical_executable "$candidate_binary" candidate_binary
candidate_binary=$FRE_BAKEOFF_CANONICAL_PATH

fre_bakeoff_validate_distinct_exact_commits \
    "$workspace" "$baseline_source" "$candidate_source"
validate_clean_source_bundle "$baseline_receipt" "$baseline_source"
validate_clean_source_bundle "$candidate_receipt" "$candidate_source"
if [ "$(fre_bakeoff_sha256 "$baseline_binary")" != "$baseline_binary_sha" ] ||
    [ "$(fre_bakeoff_sha256 "$candidate_binary")" != "$candidate_binary_sha" ]
then
    echo "a prebuilt binary does not match its source-bound receipt" >&2
    exit 2
fi

mkdir -- "$output"
chmod 0700 "$output"
mkdir -- "$output/provenance"
mkdir -- "$output/processes"
current_source=$(
    "$script_dir/capture_provenance.sh" capture \
        "$workspace" "$output/provenance/current-source"
)
if [ "$current_source" != "$candidate_source" ]; then
    echo "candidate receipt must match the clean current source state" >&2
    exit 2
fi
cp -- "$baseline_receipt" "$output/provenance/baseline-build-receipt.tsv"
cp -- "$candidate_receipt" "$output/provenance/candidate-build-receipt.tsv"
cp -R -- "$(dirname -- "$baseline_receipt")/source" \
    "$output/provenance/baseline-source"
cp -R -- "$(dirname -- "$candidate_receipt")/source" \
    "$output/provenance/candidate-source"
materialize_baseline_verifiers \
    "$baseline_source" "$output/provenance/baseline-verifier"

"$baseline_binary" header > "$output/baseline.header.csv"
"$candidate_binary" header > "$output/candidate.header.csv"
cp -- "$output/baseline.header.csv" "$output/baseline.raw.csv"
cp -- "$output/candidate.header.csv" "$output/candidate.raw.csv"
"$baseline_binary" list-adversarial > "$output/baseline.cells.txt"
"$candidate_binary" list-adversarial > "$output/candidate.cells.txt"
cmp -s "$output/baseline.cells.txt" "$output/candidate.cells.txt"
cp -- "$output/candidate.cells.txt" "$output/cells.txt"
if [ "$(wc -l < "$output/cells.txt" | tr -d ' ')" != 54 ]; then
    echo "alternating adversarial matrix must contain exactly 54 cells" >&2
    exit 2
fi
"$baseline_binary" inspect exact span > "$output/baseline.exact-span.instructions.txt"
"$candidate_binary" inspect exact span > "$output/candidate.exact-span.instructions.txt"

printf 'sequence\tcell\trepetition\tvariant\tsource_state\tpid\tprocess_output\n' \
    > "$output/sequence.tsv"
sequence=0
while IFS=' ' read -r shape operation size scenario; do
    repetition=0
    while [ "$repetition" -lt 5 ]; do
        cell="$shape-$operation-$size-$scenario"
        if [ $((repetition % 2)) -eq 0 ]; then
            order="baseline candidate"
        else
            order="candidate baseline"
        fi
        for variant in $order; do
            if [ "$variant" = baseline ]; then
                binary=$baseline_binary
                source=$baseline_source
                raw="$output/baseline.raw.csv"
            else
                binary=$candidate_binary
                source=$candidate_source
                raw="$output/candidate.raw.csv"
            fi
            sequence=$((sequence + 1))
            process_name=$(printf '%06d.csv' "$sequence")
            process_relative="processes/$process_name"
            process_output="$output/$process_relative"
            FRE_BAKEOFF_REVISION=$source \
                "$binary" run "$shape" "$operation" "$size" "$scenario" "$repetition" \
                > "$process_output"
            fre_bakeoff_validate_process_output \
                "$process_output" "$output/$variant.header.csv" \
                "$source" "$repetition" "$cell"
            pid=$FRE_BAKEOFF_PROCESS_PID
            if awk -F '	' -v pid="$pid" 'NR > 1 && $6 == pid { found = 1 } END { exit !found }' \
                "$output/sequence.tsv"
            then
                echo "timed process ID was reused: $pid" >&2
                exit 2
            fi
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "$sequence" "$cell" "$repetition" "$variant" "$source" \
                "$pid" "$process_relative" >> "$output/sequence.tsv"
            cat "$process_output" >> "$raw"
        done
        repetition=$((repetition + 1))
    done
done < "$output/cells.txt"

for variant in baseline candidate; do
    raw="$output/$variant.raw.csv"
    LC_ALL=C awk -f "$script_dir/summarize.awk" "$raw" | {
        IFS= read -r header
        printf '%s\n' "$header"
        LC_ALL=C sort
    } > "$output/$variant.ranges.csv"
    LC_ALL=C awk -f "$script_dir/compare.awk" "$output/$variant.ranges.csv" | {
        IFS= read -r header
        printf '%s\n' "$header"
        LC_ALL=C sort
    } > "$output/$variant.comparisons.csv"
    awk -F, 'NR == 1 || $3 == "loss"' \
        "$output/$variant.comparisons.csv" > "$output/$variant.losses.csv"
    identity=$(
        awk -F= '$1 == "identity" { if (found++) exit 2; print $2 } END { if (!found) exit 2 }' \
            "$output/$variant.exact-span.instructions.txt"
    )
    row_schema=$(fre_bakeoff_row_schema "$raw")
    abi2_identity=
    case "$row_schema" in
        fre-jit-bakeoff-v2) ;;
        fre-jit-bakeoff-v3)
            abi2_identity=$(
                fre_bakeoff_abi2_identity_from_inspect \
                    "$output/$variant.exact-span.instructions.txt"
            )
            ;;
        *)
            echo "unsupported $variant evidence schema: $row_schema" >&2
            exit 2
            ;;
    esac
    if [ "$variant" = candidate ]; then
        awk -v span_identity="$identity" \
            -v abi2_identity="$abi2_identity" \
            -f "$script_dir/verify_evidence_rows.awk" "$raw"
        "$script_dir/verify_evidence_identity.sh" "$raw"
    else
        baseline_verifier="$output/provenance/baseline-verifier"
        test "$(fre_bakeoff_sha256 "$baseline_verifier/verify_evidence_rows.awk")" = \
            "$baseline_rows_sha"
        test "$(fre_bakeoff_sha256 "$baseline_verifier/verify_evidence_identity.sh")" = \
            "$baseline_identity_sha"
        awk -v span_identity="$identity" \
            -v abi2_identity="$abi2_identity" \
            -f "$baseline_verifier/verify_evidence_rows.awk" "$raw"
        sh "$baseline_verifier/verify_evidence_identity.sh" "$raw"
    fi
done

LC_ALL=C awk -f "$script_dir/ab_compare.awk" \
    "$output/baseline.ranges.csv" "$output/candidate.ranges.csv" | {
    IFS= read -r header
    printf '%s\n' "$header"
    LC_ALL=C sort
} > "$output/direct-jit-ab.csv"

if [ "$(fre_bakeoff_sha256 "$baseline_binary")" != "$baseline_binary_sha" ] ||
    [ "$(fre_bakeoff_sha256 "$candidate_binary")" != "$candidate_binary_sha" ]
then
    echo "a prebuilt binary changed during alternating timing" >&2
    exit 2
fi
"$script_dir/capture_provenance.sh" verify \
    "$workspace" "$output/provenance/current-source"
{
    printf 'schema=fre-jit-alternating-adversarial-ab-v3\n'
    printf 'baseline_source=%s\n' "$baseline_source"
    printf 'candidate_source=%s\n' "$candidate_source"
    printf 'baseline_binary_sha256=%s\n' "$baseline_binary_sha"
    printf 'candidate_binary_sha256=%s\n' "$candidate_binary_sha"
    printf 'cells=54\n'
    printf 'processes_per_cell_per_variant=5\n'
    printf 'utc_finished='; date -u '+%Y-%m-%dT%H:%M:%SZ'
} > "$output/completion.txt"
