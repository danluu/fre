#!/bin/sh
set -eu

usage() {
    echo "usage: verify_v7_promotion_gates.sh MAIN_RESULTS ADVERSARIAL_AB TARGETED_AB OUTPUT_RECEIPT" >&2
    exit 2
}

if [ "$#" != 4 ]; then
    usage
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
replay=${FRE_JIT_PROMOTION_REPLAY:-0}
case "$replay" in
    0)
        workspace=$(CDPATH= cd -P -- "$script_dir/../../.." && pwd -P)
        ;;
    1)
        replay_repository_argument=${FRE_JIT_REPLAY_REPOSITORY:-}
        case "$replay_repository_argument" in
            /*) ;;
            *)
                echo "FRE_JIT_REPLAY_REPOSITORY must be absolute in replay mode" >&2
                exit 2
                ;;
        esac
        if [ ! -d "$replay_repository_argument" ] ||
            [ -L "$replay_repository_argument" ]
        then
            echo "replay repository must be a regular directory" >&2
            exit 2
        fi
        workspace=$(CDPATH= cd -P -- "$replay_repository_argument" && pwd -P)
        ;;
    *)
        echo "FRE_JIT_PROMOTION_REPLAY must be 0 or 1" >&2
        exit 2
        ;;
esac
. "$script_dir/runner_support.sh"
. "$script_dir/qualification_receipts.sh"

if [ "$replay" = 1 ]; then
    fre_bakeoff_canonical_executable \
        "${FRE_JIT_REPLAY_CANDIDATE_BINARY:-}" \
        FRE_JIT_REPLAY_CANDIDATE_BINARY
    replay_candidate_binary=$FRE_BAKEOFF_CANONICAL_PATH
    fre_bakeoff_canonical_executable \
        "${FRE_JIT_REPLAY_BASELINE_BINARY:-}" \
        FRE_JIT_REPLAY_BASELINE_BINARY
    replay_baseline_binary=$FRE_BAKEOFF_CANONICAL_PATH
    fre_bakeoff_canonical_regular_file \
        "${FRE_JIT_REPLAY_CANDIDATE_RECEIPT:-}" \
        FRE_JIT_REPLAY_CANDIDATE_RECEIPT
    replay_candidate_receipt=$FRE_BAKEOFF_CANONICAL_PATH
    fre_bakeoff_canonical_regular_file \
        "${FRE_JIT_REPLAY_BASELINE_RECEIPT:-}" \
        FRE_JIT_REPLAY_BASELINE_RECEIPT
    replay_baseline_receipt=$FRE_BAKEOFF_CANONICAL_PATH
fi

canonical_input_directory() {
    fre_bakeoff_canonical_external_directory "$workspace" "$1"
    printf '%s\n' "$FRE_BAKEOFF_CANONICAL_PATH"
}

main=$(canonical_input_directory "$1")
adversarial=$(canonical_input_directory "$2")
targeted=$(canonical_input_directory "$3")
output_argument=$4
case "$output_argument" in
    /*) ;;
    *)
        echo "promotion-gate receipt path must be absolute" >&2
        exit 2
        ;;
esac
output_parent_argument=$(dirname -- "$output_argument")
output_name=$(basename -- "$output_argument")
if [ ! -d "$output_parent_argument" ] || [ -L "$output_parent_argument" ]; then
    echo "promotion-gate receipt parent must be a regular directory" >&2
    exit 2
fi
output_parent=$(CDPATH= cd -P -- "$output_parent_argument" && pwd -P)
output="$output_parent/$output_name"
case "$output" in
    "$workspace"|"$workspace"/*|"$main"|"$main"/*|"$adversarial"|"$adversarial"/*|"$targeted"|"$targeted"/*)
        echo "promotion-gate receipt must be outside source and result trees" >&2
        exit 2
        ;;
esac
if [ -e "$output" ] || [ -L "$output" ]; then
    echo "refusing to overwrite promotion-gate receipt: $output" >&2
    exit 2
fi

temporary=$(mktemp -d "${TMPDIR:-/tmp}/fre-jit-v7-promotion-gates.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

completion_field() {
    file=$1
    key=$2
    awk -F= -v key="$key" '
        $1 == key {
            if (found++) exit 2
            print substr($0, index($0, "=") + 1)
            found = 1
        }
        END { if (!found) exit 2 }
    ' "$file"
}

tsv_field() {
    file=$1
    key=$2
    awk -F '	' -v key="$key" '
        $1 == key {
            if (NF != 2 || found++) exit 2
            print $2
            found = 1
        }
        END { if (!found) exit 2 }
    ' "$file"
}

validate_clean_source_bundle() {
    bundle=$1
    expected_source=$2
    for required in \
        "$bundle/source-state-id.txt" \
        "$bundle/source-inputs.sha256" \
        "$bundle/source-digest.txt" \
        "$bundle/head.txt" \
        "$bundle/dirty.txt"
    do
        test -f "$required"
        test ! -L "$required"
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

validate_actual_binary() {
    receipt=$1
    fre_bakeoff_validate_build_receipt "$receipt"
    binary=$(fre_bakeoff_receipt_field "$receipt" binary_path)
    expected=$(fre_bakeoff_receipt_field "$receipt" binary_sha256)
    fre_bakeoff_canonical_executable "$binary" "source-bound bakeoff binary"
    if [ "$(fre_bakeoff_sha256 "$FRE_BAKEOFF_CANONICAL_PATH")" != "$expected" ]; then
        echo "source-bound bakeoff binary differs from its receipt" >&2
        exit 2
    fi
}

validate_bound_binary() {
    receipt=$1
    binary=$2
    label=$3
    fre_bakeoff_validate_build_receipt "$receipt"
    fre_bakeoff_canonical_executable "$binary" "$label"
    binary=$FRE_BAKEOFF_CANONICAL_PATH
    expected=$(fre_bakeoff_receipt_field "$receipt" binary_sha256)
    if [ "$(fre_bakeoff_sha256 "$binary")" != "$expected" ]; then
        echo "$label differs from its canonical bundled receipt" >&2
        exit 2
    fi
}

verify_candidate_rows() {
    raw=$1
    instructions=$2
    expected_source=$3
    identity=$(
        awk -F= '
            $1 == "identity" {
                if (found++) exit 2
                print $2
                found = 1
            }
            END { if (!found) exit 2 }
        ' "$instructions"
    )
    awk -v span_identity="$identity" \
        -f "$script_dir/verify_evidence_rows.awk" "$raw"
    "$script_dir/verify_evidence_identity.sh" "$raw"
    awk -F, -v expected_source="$expected_source" '
        NR == 1 {
            for (column = 1; column <= NF; column++) {
                if ($column in index_of) exit 2
                index_of[$column] = column
            }
            required[1] = "revision"
            required[2] = "engine"
            required[3] = "route"
            required[4] = "backend"
            required[5] = "qualification_state"
            required[6] = "qualification_bundle_sha256"
            for (item in required) {
                if (!(required[item] in index_of)) exit 2
            }
            next
        }
        {
            if ($(index_of["revision"]) != expected_source) bad = 1
            engine = $(index_of["engine"])
            if (engine != "fre-qualified-exact" &&
                engine != "fre-qualified-exact-under-threshold") next
            qualified_rows++
            if ($(index_of["qualification_state"]) != "candidate" ||
                $(index_of["qualification_bundle_sha256"]) != "none") bad = 1
            if ($(index_of["route"]) == "native-jit" &&
                $(index_of["backend"]) != "aarch64-search-v7") bad = 1
        }
        END {
            if (!qualified_rows) bad = 1
            exit bad
        }
    ' "$raw"
}

verify_materialized_baseline_verifier() {
    baseline_verifier_directory=$1
    baseline_verifier_source=$2
    baseline_verifier_raw=$3
    baseline_verifier_instructions=$4
    baseline_verifier_receipt="$baseline_verifier_directory/verifier-receipt.tsv"
    baseline_verifier_rows="$baseline_verifier_directory/verify_evidence_rows.awk"
    baseline_verifier_identity_script="$baseline_verifier_directory/verify_evidence_identity.sh"
    fre_bakeoff_validate_exact_clean_commit \
        "$workspace" "$baseline_verifier_source" baseline_verifier_source
    for required in \
        "$baseline_verifier_receipt" \
        "$baseline_verifier_rows" \
        "$baseline_verifier_identity_script"
    do
        test -f "$required"
        test ! -L "$required"
    done
    awk -F '	' '
        NF != 2 { bad = 1 }
        {
            count[$1]++
            if ($1 != "schema" && $1 != "source_revision" &&
                $1 != "rows_blob" && $1 != "rows_sha256" &&
                $1 != "identity_blob" && $1 != "identity_sha256") bad = 1
        }
        END {
            required[1] = "schema"
            required[2] = "source_revision"
            required[3] = "rows_blob"
            required[4] = "rows_sha256"
            required[5] = "identity_blob"
            required[6] = "identity_sha256"
            for (item in required) {
                if (count[required[item]] != 1) bad = 1
            }
            exit bad
        }
    ' "$baseline_verifier_receipt"
    test "$(tsv_field "$baseline_verifier_receipt" schema)" = \
        fre-jit-baseline-evidence-verifier-v1
    test "$(tsv_field "$baseline_verifier_receipt" source_revision)" = \
        "$baseline_verifier_source"
    baseline_verifier_rows_object="$baseline_verifier_source:research/jit/bakeoff/verify_evidence_rows.awk"
    baseline_verifier_identity_object="$baseline_verifier_source:research/jit/bakeoff/verify_evidence_identity.sh"
    test "$(git -C "$workspace" cat-file -t \
        "$baseline_verifier_rows_object")" = blob
    test "$(git -C "$workspace" cat-file -t \
        "$baseline_verifier_identity_object")" = blob
    test "$(tsv_field "$baseline_verifier_receipt" rows_blob)" = \
        "$(git -C "$workspace" rev-parse "$baseline_verifier_rows_object")"
    test "$(tsv_field "$baseline_verifier_receipt" identity_blob)" = \
        "$(git -C "$workspace" rev-parse "$baseline_verifier_identity_object")"
    test "$(tsv_field "$baseline_verifier_receipt" rows_sha256)" = \
        "$(fre_bakeoff_sha256 "$baseline_verifier_rows")"
    test "$(tsv_field "$baseline_verifier_receipt" identity_sha256)" = \
        "$(fre_bakeoff_sha256 "$baseline_verifier_identity_script")"
    baseline_verifier_expected_rows=$(
        mktemp "$temporary/baseline-rows.XXXXXX"
    )
    baseline_verifier_expected_identity=$(
        mktemp "$temporary/baseline-identity.XXXXXX"
    )
    git -C "$workspace" show "$baseline_verifier_rows_object" \
        > "$baseline_verifier_expected_rows"
    git -C "$workspace" show "$baseline_verifier_identity_object" \
        > "$baseline_verifier_expected_identity"
    cmp -s "$baseline_verifier_expected_rows" "$baseline_verifier_rows"
    cmp -s \
        "$baseline_verifier_expected_identity" \
        "$baseline_verifier_identity_script"
    awk -F, -v source="$baseline_verifier_source" '
        NR == 1 {
            for (column = 1; column <= NF; column++) index_of[$column] = column
            if (!("revision" in index_of)) exit 2
            next
        }
        $(index_of["revision"]) != source { bad = 1 }
        END { exit bad }
    ' "$baseline_verifier_raw"
    baseline_verifier_identity=$(
        awk -F= '
            $1 == "identity" {
                if (found++) exit 2
                print $2
                found = 1
            }
            END { if (!found) exit 2 }
        ' "$baseline_verifier_instructions"
    )
    awk -v span_identity="$baseline_verifier_identity" \
        -f "$baseline_verifier_rows" "$baseline_verifier_raw"
    sh "$baseline_verifier_identity_script" "$baseline_verifier_raw"
}

verify_direct_sample_shape() {
    raw=$1
    expected_source=$2
    expected_cells=$3
    expected_repetitions=$4
    awk -F, \
        -v expected_source="$expected_source" \
        -v expected_cells="$expected_cells" \
        -v expected_repetitions="$expected_repetitions" '
        NR == 1 {
            for (column = 1; column <= NF; column++) {
                if ($column in index_of) exit 2
                index_of[$column] = column
            }
            required[1] = "revision"
            required[2] = "cell"
            required[3] = "engine"
            required[4] = "stage"
            for (item in required) {
                if (!(required[item] in index_of)) exit 2
            }
            next
        }
        {
            if ($(index_of["revision"]) != expected_source) bad = 1
            if ($(index_of["engine"]) == "jit" &&
                $(index_of["stage"]) == "direct_lease_call") {
                cell = $(index_of["cell"])
                samples[cell]++
            }
        }
        END {
            cells = 0
            for (cell in samples) {
                cells++
                if (samples[cell] != expected_repetitions) bad = 1
            }
            if (cells != expected_cells) bad = 1
            exit bad
        }
    ' "$raw"
}

recompute_ab_derivatives() {
    directory=$1
    for variant in baseline candidate; do
        LC_ALL=C awk -f "$script_dir/summarize.awk" \
            "$directory/$variant.raw.csv" | {
            IFS= read -r header
            printf '%s\n' "$header"
            LC_ALL=C sort
        } > "$temporary/$variant.ranges.csv"
        cmp -s "$temporary/$variant.ranges.csv" "$directory/$variant.ranges.csv"
    done
    LC_ALL=C awk -f "$script_dir/ab_compare.awk" \
        "$temporary/baseline.ranges.csv" "$temporary/candidate.ranges.csv" | {
        IFS= read -r header
        printf '%s\n' "$header"
        LC_ALL=C sort
    } > "$temporary/direct-jit-ab.csv"
    cmp -s "$temporary/direct-jit-ab.csv" "$directory/direct-jit-ab.csv"
}

verify_ab_directory() {
    directory=$1
    expected_schema=$2
    expected_cells=$3
    expected_repetitions=$4
    required_cell=${5:-}
    for required in \
        "$directory/baseline.raw.csv" \
        "$directory/candidate.raw.csv" \
        "$directory/baseline.ranges.csv" \
        "$directory/candidate.ranges.csv" \
        "$directory/direct-jit-ab.csv" \
        "$directory/baseline.exact-span.instructions.txt" \
        "$directory/candidate.exact-span.instructions.txt" \
        "$directory/cells.txt" \
        "$directory/sequence.tsv" \
        "$directory/completion.txt" \
        "$directory/provenance/baseline-build-receipt.tsv" \
        "$directory/provenance/candidate-build-receipt.tsv" \
        "$directory/provenance/baseline-verifier/verifier-receipt.tsv" \
        "$directory/provenance/baseline-verifier/verify_evidence_rows.awk" \
        "$directory/provenance/baseline-verifier/verify_evidence_identity.sh"
    do
        test -f "$required"
        test ! -L "$required"
    done
    baseline_receipt="$directory/provenance/baseline-build-receipt.tsv"
    candidate_receipt="$directory/provenance/candidate-build-receipt.tsv"
    if [ "$replay" = 1 ]; then
        cmp -s "$baseline_receipt" "$replay_baseline_receipt"
        cmp -s "$candidate_receipt" "$replay_candidate_receipt"
        validate_bound_binary \
            "$replay_baseline_receipt" "$replay_baseline_binary" \
            "canonical bundled baseline binary"
        validate_bound_binary \
            "$replay_candidate_receipt" "$replay_candidate_binary" \
            "canonical bundled candidate binary"
    else
        validate_actual_binary "$baseline_receipt"
        validate_actual_binary "$candidate_receipt"
    fi
    baseline_source=$(fre_bakeoff_receipt_field "$baseline_receipt" source_state_id)
    candidate_source=$(fre_bakeoff_receipt_field "$candidate_receipt" source_state_id)
    if [ "$replay" = 1 ]; then
        baseline_binary=$replay_baseline_binary
        candidate_binary=$replay_candidate_binary
    else
        baseline_binary=$(fre_bakeoff_receipt_field "$baseline_receipt" binary_path)
        candidate_binary=$(fre_bakeoff_receipt_field "$candidate_receipt" binary_path)
    fi
    fre_bakeoff_validate_distinct_exact_commits \
        "$workspace" "$baseline_source" "$candidate_source"
    "$baseline_binary" list-adversarial > "$temporary/baseline-catalog.cells.txt"
    "$candidate_binary" list-adversarial > "$temporary/candidate-catalog.cells.txt"
    cmp -s \
        "$temporary/baseline-catalog.cells.txt" \
        "$temporary/candidate-catalog.cells.txt"
    test "$(wc -l < "$temporary/candidate-catalog.cells.txt" | tr -d ' ')" = 54
    if [ "$expected_cells" = 54 ]; then
        for catalog in \
            "$directory/baseline.cells.txt" \
            "$directory/candidate.cells.txt"
        do
            test -f "$catalog"
            test ! -L "$catalog"
            cmp -s "$temporary/candidate-catalog.cells.txt" "$catalog"
        done
        cmp -s "$temporary/candidate-catalog.cells.txt" "$directory/cells.txt"
    else
        for catalog in \
            "$directory/baseline.catalog.cells.txt" \
            "$directory/candidate.catalog.cells.txt"
        do
            test -f "$catalog"
            test ! -L "$catalog"
            cmp -s "$temporary/candidate-catalog.cells.txt" "$catalog"
        done
        awk -v selected="$required_cell" '
            {
                cell = $1 "-" $2 "-" $3 "-" $4
                if (cell == selected) {
                    print
                    found++
                }
            }
            END { if (found != 1) exit 2 }
        ' "$temporary/candidate-catalog.cells.txt" \
            > "$temporary/selected-catalog.cells.txt"
        cmp -s "$temporary/selected-catalog.cells.txt" "$directory/cells.txt"
    fi
    test "$(completion_field "$directory/completion.txt" schema)" = "$expected_schema"
    test "$(completion_field "$directory/completion.txt" baseline_source)" = "$baseline_source"
    test "$(completion_field "$directory/completion.txt" candidate_source)" = "$candidate_source"
    test "$(completion_field "$directory/completion.txt" baseline_binary_sha256)" = \
        "$(fre_bakeoff_receipt_field "$baseline_receipt" binary_sha256)"
    test "$(completion_field "$directory/completion.txt" candidate_binary_sha256)" = \
        "$(fre_bakeoff_receipt_field "$candidate_receipt" binary_sha256)"
    test "$(completion_field "$directory/completion.txt" cells)" = "$expected_cells"
    test "$(completion_field "$directory/completion.txt" processes_per_cell_per_variant)" = \
        "$expected_repetitions"
    if [ -n "$required_cell" ]; then
        test "$(completion_field "$directory/completion.txt" cell)" = "$required_cell"
        test "$(completion_field "$directory/completion.txt" total_timed_processes)" = 30
    fi
    validate_clean_source_bundle \
        "$directory/provenance/baseline-source" "$baseline_source"
    validate_clean_source_bundle \
        "$directory/provenance/candidate-source" "$candidate_source"
    validate_clean_source_bundle \
        "$directory/provenance/current-source" "$candidate_source"
    verify_materialized_baseline_verifier \
        "$directory/provenance/baseline-verifier" \
        "$baseline_source" \
        "$directory/baseline.raw.csv" \
        "$directory/baseline.exact-span.instructions.txt"
    verify_candidate_rows \
        "$directory/candidate.raw.csv" \
        "$directory/candidate.exact-span.instructions.txt" \
        "$candidate_source"
    verify_direct_sample_shape \
        "$directory/baseline.raw.csv" "$baseline_source" \
        "$expected_cells" "$expected_repetitions"
    verify_direct_sample_shape \
        "$directory/candidate.raw.csv" "$candidate_source" \
        "$expected_cells" "$expected_repetitions"
    "$script_dir/verify_alternating_process_evidence.sh" \
        "$directory" "$expected_cells" "$expected_repetitions" \
        "$baseline_source" "$candidate_source" "$required_cell"
    test "$(wc -l < "$directory/cells.txt" | tr -d ' ')" = "$expected_cells"
    test "$(wc -l < "$directory/direct-jit-ab.csv" | tr -d ' ')" = \
        $((expected_cells + 1))
    if [ -n "$required_cell" ]; then
        test "$(sed -n '1p' "$directory/cells.txt")" = \
            "exact exists 64k primary-dense-secondary-absent"
    fi
    recompute_ab_derivatives "$directory"
}

extract_direct_stats() {
    raw=$1
    output_file=$2
    awk -F, '
        NR == 1 {
            for (column = 1; column <= NF; column++) index_of[$column] = column
            required[1] = "cell"
            required[2] = "engine"
            required[3] = "stage"
            required[4] = "ns_per_iter"
            for (item in required) {
                if (!(required[item] in index_of)) exit 2
            }
            next
        }
        $(index_of["engine"]) == "jit" &&
            $(index_of["stage"]) == "direct_lease_call" {
            cell = $(index_of["cell"])
            value = $(index_of["ns_per_iter"])
            if (value !~ /^[0-9]+$/) bad = 1
            count[cell]++
            sum[cell] += value
        }
        END {
            for (cell in count) print cell "\t" count[cell] "\t" sum[cell]
            exit bad
        }
    ' "$raw" > "$output_file.unsorted"
    LC_ALL=C sort "$output_file.unsorted" > "$output_file"
}

compare_ab_gate() {
    directory=$1
    kind=$2
    expected_count=$3
    expected_samples=$4
    required_cell=${5:-}
    extract_direct_stats "$directory/baseline.raw.csv" "$temporary/$kind-baseline.tsv"
    extract_direct_stats "$directory/candidate.raw.csv" "$temporary/$kind-candidate.tsv"
    awk -F '	' \
        -v kind="$kind" \
        -v expected_count="$expected_count" \
        -v expected_samples="$expected_samples" \
        -v required_cell="$required_cell" '
        FNR == NR {
            baseline_count[$1] = $2
            baseline_sum[$1] = $3
            next
        }
        {
            candidate_count[$1] = $2
            candidate_sum[$1] = $3
        }
        END {
            gate_count = 0
            maximum = 0
            for (cell in baseline_count) {
                required = required_cell != "" \
                    ? cell == required_cell \
                    : cell ~ /-(pair-dense-literal-absent|triple-dense-literal-absent)$/
                if (!required) continue
                gate_count++
                if (!(cell in candidate_count) ||
                    baseline_count[cell] != expected_samples ||
                    candidate_count[cell] != expected_samples ||
                    baseline_sum[cell] <= 0) {
                    bad = 1
                    continue
                }
                ratio = candidate_sum[cell] / baseline_sum[cell]
                if (ratio > maximum) maximum = ratio
                if (ratio > 1.15) bad = 1
            }
            for (cell in candidate_count) {
                required = required_cell != "" \
                    ? cell == required_cell \
                    : cell ~ /-(pair-dense-literal-absent|triple-dense-literal-absent)$/
                if (required && !(cell in baseline_count)) bad = 1
            }
            if (gate_count != expected_count) bad = 1
            if (bad) exit 1
            printf "%s_gate_cells\t%d\n", kind, gate_count
            printf "%s_max_candidate_over_baseline\t%.9f\n", kind, maximum
            printf "%s_max_ratio\t1.150000000\n", kind
        }
    ' "$temporary/$kind-baseline.tsv" "$temporary/$kind-candidate.tsv"
}

hash_tree() {
    label=$1
    directory=$2
    destination=$3
    find "$directory" -type l -print > "$temporary/$label.symlinks"
    test ! -s "$temporary/$label.symlinks"
    find "$directory" ! -type d ! -type f ! -type l -print > "$temporary/$label.special"
    test ! -s "$temporary/$label.special"
    find "$directory" -type f -print | LC_ALL=C sort |
    while IFS= read -r file; do
        relative=${file#"$directory"/}
        if [ "$relative" = "$file" ] || [ -z "$relative" ] ||
            ! printf '%s\n' "$relative" |
                LC_ALL=C grep -Eq '^[A-Za-z0-9._/-]+$'
        then
            echo "non-canonical result path: $label/$relative" >&2
            exit 2
        fi
        printf '%s\n' "$relative"
    done > "$temporary/$label.paths"
    (
        cd "$directory"
        xargs shasum -a 256 < "$temporary/$label.paths"
    ) | awk '{ print $2 "\t" $1 }' > "$temporary/$label.hashes"
    (
        cd "$directory"
        xargs wc -c < "$temporary/$label.paths"
    ) | awk '$2 != "total" { print $2 "\t" $1 }' \
        > "$temporary/$label.sizes"
    paste \
        "$temporary/$label.paths" \
        "$temporary/$label.hashes" \
        "$temporary/$label.sizes" |
    awk -F '	' -v label="$label" '
        NF != 5 || $1 != $2 || $1 != $4 { bad = 1; next }
        { print "input_sha256\t" $3 "\t" $5 "\t" label "/" $1 }
        END { exit bad }
    ' >> "$destination"
}

snapshot_inputs() {
    destination=$1
    : > "$destination"
    hash_tree main "$main" "$destination"
    hash_tree adversarial "$adversarial" "$destination"
    hash_tree targeted "$targeted" "$destination"
    LC_ALL=C sort -o "$destination" "$destination"
}

snapshot_inputs "$temporary/inputs-before.tsv"

"$script_dir/verify_qualification_results.sh" "$main" 90
main_receipt="$main/provenance/build-receipt.tsv"
if [ "$replay" = 1 ]; then
    cmp -s "$main_receipt" "$replay_candidate_receipt"
    validate_bound_binary \
        "$replay_candidate_receipt" "$replay_candidate_binary" \
        "canonical bundled candidate binary"
else
    validate_actual_binary "$main_receipt"
fi
subject_revision=$(fre_bakeoff_receipt_field "$main_receipt" source_state_id)
fre_bakeoff_validate_exact_clean_commit \
    "$workspace" "$subject_revision" promotion_subject
if [ "$replay" = 0 ]; then
    test "$(git -C "$workspace" rev-parse --verify HEAD^{commit})" = "$subject_revision"
    test -z "$(git -C "$workspace" status --porcelain=v1 --untracked-files=all)"
fi
subject_tree=$(git -C "$workspace" show -s --format=%T "$subject_revision")
main_binary_sha256=$(fre_bakeoff_receipt_field "$main_receipt" binary_sha256)
main_receipt_sha256=$(fre_bakeoff_sha256 "$main_receipt")

awk -F, '
    NR == 1 {
        for (column = 1; column <= NF; column++) index_of[$column] = column
        required[1] = "cell"
        required[2] = "shape"
        required[3] = "size"
        required[4] = "engine"
        required[5] = "stage"
        required[6] = "ns_per_iter"
        required[7] = "route"
        required[8] = "backend"
        required[9] = "qualification_state"
        required[10] = "qualification_bundle_sha256"
        for (item in required) {
            if (!(required[item] in index_of)) exit 2
        }
        next
    }
    {
        shape = $(index_of["shape"])
        size = $(index_of["size"])
        if (shape != "exact" || (size != "64k" && size != "1m")) next
        cell = $(index_of["cell"])
        engine = $(index_of["engine"])
        stage = $(index_of["stage"])
        value = $(index_of["ns_per_iter"])
        if (value !~ /^[0-9]+$/) bad = 1
        if (engine == "fre-kernels" && stage == "search") {
            kernel_count[cell]++
            kernel_sum[cell] += value
        }
        if (engine == "fre-qualified-exact" &&
            (stage == "search" || stage == "build_full_workload")) {
            if ($(index_of["route"]) != "native-jit" ||
                $(index_of["backend"]) != "aarch64-search-v7" ||
                $(index_of["qualification_state"]) != "candidate" ||
                $(index_of["qualification_bundle_sha256"]) != "none") bad = 1
            key = cell SUBSEP stage
            facade_count[key]++
            facade_sum[key] += value
        }
    }
    END {
        gates = 0
        maximum = 0
        for (key in facade_count) {
            split(key, fields, SUBSEP)
            cell = fields[1]
            gates++
            if (facade_count[key] != 5 || kernel_count[cell] != 5 ||
                facade_sum[key] * kernel_count[cell] >= kernel_sum[cell] * facade_count[key]) {
                bad = 1
                continue
            }
            ratio = (facade_sum[key] / facade_count[key]) / (kernel_sum[cell] / kernel_count[cell])
            if (ratio > maximum) maximum = ratio
        }
        if (gates != 60) bad = 1
        if (bad) exit 1
        printf "main_facade_gate_rows\t%d\n", gates
        printf "main_max_facade_over_kernels\t%.9f\n", maximum
        printf "main_required_ratio\tstrictly_less_than_1\n"
    }
' "$main/raw.csv" > "$temporary/main-gates.tsv"

verify_ab_directory \
    "$adversarial" fre-jit-alternating-adversarial-ab-v3 54 5
verify_ab_directory \
    "$targeted" fre-jit-targeted-alternating-adversarial-ab-v2 1 15 \
    exact-exists-64k-primary-dense-secondary-absent

adversarial_candidate_receipt="$adversarial/provenance/candidate-build-receipt.tsv"
targeted_candidate_receipt="$targeted/provenance/candidate-build-receipt.tsv"
adversarial_baseline_receipt="$adversarial/provenance/baseline-build-receipt.tsv"
targeted_baseline_receipt="$targeted/provenance/baseline-build-receipt.tsv"
test "$(fre_bakeoff_sha256 "$adversarial_candidate_receipt")" = "$main_receipt_sha256"
test "$(fre_bakeoff_sha256 "$targeted_candidate_receipt")" = "$main_receipt_sha256"
test "$(fre_bakeoff_receipt_field "$adversarial_candidate_receipt" source_state_id)" = \
    "$subject_revision"
test "$(fre_bakeoff_receipt_field "$targeted_candidate_receipt" source_state_id)" = \
    "$subject_revision"
test "$(fre_bakeoff_receipt_field "$adversarial_candidate_receipt" binary_sha256)" = \
    "$main_binary_sha256"
test "$(fre_bakeoff_receipt_field "$targeted_candidate_receipt" binary_sha256)" = \
    "$main_binary_sha256"
baseline_receipt_sha256=$(fre_bakeoff_sha256 "$adversarial_baseline_receipt")
test "$(fre_bakeoff_sha256 "$targeted_baseline_receipt")" = "$baseline_receipt_sha256"
baseline_revision=$(fre_bakeoff_receipt_field "$adversarial_baseline_receipt" source_state_id)
baseline_binary_sha256=$(
    fre_bakeoff_receipt_field "$adversarial_baseline_receipt" binary_sha256
)

compare_ab_gate "$adversarial" adversarial 18 5 \
    > "$temporary/adversarial-gates.tsv"
compare_ab_gate \
    "$targeted" targeted 1 15 \
    exact-exists-64k-primary-dense-secondary-absent \
    > "$temporary/targeted-gates.tsv"

snapshot_inputs "$temporary/inputs-after.tsv"
cmp -s "$temporary/inputs-before.tsv" "$temporary/inputs-after.tsv"

receipt="$temporary/promotion-gate-receipt.tsv"
{
    printf 'schema\tfre-jit-v7-promotion-gate-receipt-v1\n'
    printf 'result\tpass\n'
    printf 'qualification_state\tcandidate\n'
    printf 'backend\taarch64-search-v7\n'
    printf 'subject_revision\t%s\n' "$subject_revision"
    printf 'subject_tree\t%s\n' "$subject_tree"
    printf 'candidate_binary_sha256\t%s\n' "$main_binary_sha256"
    printf 'candidate_build_receipt_sha256\t%s\n' "$main_receipt_sha256"
    printf 'baseline_revision\t%s\n' "$baseline_revision"
    printf 'baseline_binary_sha256\t%s\n' "$baseline_binary_sha256"
    printf 'baseline_build_receipt_sha256\t%s\n' "$baseline_receipt_sha256"
    cat "$temporary/main-gates.tsv"
    cat "$temporary/adversarial-gates.tsv"
    cat "$temporary/targeted-gates.tsv"
    cat "$temporary/inputs-before.tsv"
} > "$receipt"

fre_jit_validate_promotion_gate_receipt \
    "$receipt" "$workspace" "$subject_revision" "$subject_tree"
mv -- "$receipt" "$output"
printf 'receipt=%s\n' "$output"
printf 'receipt_sha256=%s\n' "$(fre_bakeoff_sha256 "$output")"
