#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
temporary=$(mktemp -d "${TMPDIR:-/tmp}/fre-jit-process-evidence-test.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
tab=$(printf '\t')

baseline_source=$(git -C "$script_dir/../../.." rev-parse --verify HEAD^^{commit})
candidate_source=$(git -C "$script_dir/../../.." rev-parse --verify HEAD^{commit})
baseline_header="schema,revision,pid,repetition,cell,shape,operation,size,scenario,haystack_bytes,alignment_mod16,engine,stage,timing_scope,iterations,total_ns,ns_per_iter,checksum,semantic_value,code_bytes,data_bytes,payload_used_bytes,total_mapped_bytes,total_pages,instructions,vector_instructions,loads,stores,branches,identity_bytes_hashed,identity_scratch_bytes,identity_heap_allocations,cache_bookkeeping_bytes,cache_hits,fixture,output_kind,backend,route,artifact_identity,evidence_identity,evidence_manifest_identity,evidence_binding,artifact_binding,declared_min_window_bytes,declared_min_qualifying_calls,measured_calls,measured_qualifying_calls"
candidate_header="schema,revision,pid,repetition,cell,shape,operation,size,scenario,haystack_bytes,alignment_mod16,engine,stage,timing_scope,iterations,total_ns,ns_per_iter,checksum,semantic_value,code_bytes,data_bytes,payload_used_bytes,total_mapped_bytes,total_pages,instructions,vector_instructions,loads,stores,branches,identity_bytes_hashed,identity_scratch_bytes,identity_heap_allocations,cache_bookkeeping_bytes,cache_hits,fixture,output_kind,backend,route,artifact_identity,evidence_identity,qualification_state,qualification_bundle_sha256,evidence_binding,artifact_binding,declared_min_window_bytes,declared_min_qualifying_calls,measured_calls,measured_qualifying_calls"

write_row() {
    header=$1
    source=$2
    pid=$3
    repetition=$4
    cell=$5
    engine=$6
    stage=$7
    printf '%s\n' "$header" |
        awk -F, -v OFS=, \
            -v source="$source" \
            -v pid="$pid" \
            -v repetition="$repetition" \
            -v cell="$cell" \
            -v engine="$engine" \
            -v stage="$stage" '
            {
                for (column = 1; column <= NF; column++) {
                    name = $column
                    if (name == "schema") $column = "synthetic"
                    else if (name == "revision") $column = source
                    else if (name == "pid") $column = pid
                    else if (name == "repetition") $column = repetition
                    else if (name == "cell") $column = cell
                    else if (name == "engine") $column = engine
                    else if (name == "stage") $column = stage
                    else $column = "1"
                }
                print
            }
        '
}

valid="$temporary/valid"
mkdir -p "$valid/processes"
printf '%s\n' "$baseline_header" > "$valid/baseline.header.csv"
printf '%s\n' "$candidate_header" > "$valid/candidate.header.csv"
cp -- "$valid/baseline.header.csv" "$valid/baseline.raw.csv"
cp -- "$valid/candidate.header.csv" "$valid/candidate.raw.csv"
{
    printf 'exact exists 64k absent\n'
    printf 'exact exists 64k dense\n'
} > "$valid/cells.txt"
{
    printf 'sequence\tcell\trepetition\tvariant\tsource_state\tpid\tprocess_output\n'
    printf '1\texact-exists-64k-absent\t0\tbaseline\t%s\t1001\tprocesses/000001.csv\n' "$baseline_source"
    printf '2\texact-exists-64k-absent\t0\tcandidate\t%s\t1002\tprocesses/000002.csv\n' "$candidate_source"
    printf '3\texact-exists-64k-absent\t1\tcandidate\t%s\t1003\tprocesses/000003.csv\n' "$candidate_source"
    printf '4\texact-exists-64k-absent\t1\tbaseline\t%s\t1004\tprocesses/000004.csv\n' "$baseline_source"
    printf '5\texact-exists-64k-dense\t0\tbaseline\t%s\t1005\tprocesses/000005.csv\n' "$baseline_source"
    printf '6\texact-exists-64k-dense\t0\tcandidate\t%s\t1006\tprocesses/000006.csv\n' "$candidate_source"
    printf '7\texact-exists-64k-dense\t1\tcandidate\t%s\t1007\tprocesses/000007.csv\n' "$candidate_source"
    printf '8\texact-exists-64k-dense\t1\tbaseline\t%s\t1008\tprocesses/000008.csv\n' "$baseline_source"
} > "$valid/sequence.tsv"

tail -n +2 "$valid/sequence.tsv" |
while IFS=$tab read -r sequence cell repetition variant source pid relative; do
    process_output="$valid/$relative"
    if [ "$variant" = baseline ]; then
        header=$baseline_header
    else
        header=$candidate_header
    fi
    {
        write_row "$header" "$source" "$pid" "$repetition" "$cell" \
            jit direct_lease_call
        write_row "$header" "$source" "$pid" "$repetition" "$cell" \
            fre-kernels search
    } > "$process_output"
    cat "$process_output" >> "$valid/$variant.raw.csv"
done

"$script_dir/verify_alternating_process_evidence.sh" \
    "$valid" 2 2 "$baseline_source" "$candidate_source"
test "$(awk -F, 'NR == 1 { print NF }' "$valid/baseline.header.csv")" = 47
test "$(awk -F, 'NR == 1 { print NF }' "$valid/candidate.header.csv")" = 48

assert_mutation_rejected() {
    case_name=$1
    case_root="$temporary/$case_name"
    cp -R -- "$valid" "$case_root"
    "$2" "$case_root"
    if "$script_dir/verify_alternating_process_evidence.sh" \
        "$case_root" 2 2 "$baseline_source" "$candidate_source" >/dev/null 2>&1
    then
        echo "alternating evidence mutation was accepted: $case_name" >&2
        exit 1
    fi
}

duplicate_raw_sample() {
    root=$1
    cat "$root/processes/000001.csv" >> "$root/baseline.raw.csv"
}

mutate_process_field() {
    file=$1
    header=$2
    field=$3
    value=$4
    awk -F, -v OFS=, -v field="$field" -v value="$value" '
        FNR == NR {
            for (column = 1; column <= NF; column++) {
                if ($column == field) target = column
            }
            next
        }
        { $target = value; print }
    ' "$header" "$file" > "$file.tmp"
    mv -- "$file.tmp" "$file"
}

alter_repetition() {
    root=$1
    mutate_process_field \
        "$root/processes/000001.csv" "$root/baseline.header.csv" repetition 1
}

alter_source() {
    root=$1
    mutate_process_field \
        "$root/processes/000001.csv" "$root/baseline.header.csv" revision \
        "$candidate_source"
}

alter_variant() {
    root=$1
    awk -F '	' -v OFS='	' \
        'NR == 2 { $4 = "candidate"; $5 = candidate } { print }' \
        candidate="$candidate_source" "$root/sequence.tsv" > "$root/sequence.tmp"
    mv -- "$root/sequence.tmp" "$root/sequence.tsv"
}

reorder_variants() {
    root=$1
    awk 'NR == 2 { first = $0; next }
        NR == 3 { print; print first; next }
        { print }' "$root/sequence.tsv" > "$root/sequence.tmp"
    mv -- "$root/sequence.tmp" "$root/sequence.tsv"
}

missing_process() {
    root=$1
    rm -- "$root/processes/000001.csv"
}

extra_process() {
    root=$1
    cp -- "$root/processes/000001.csv" "$root/processes/999999.csv"
}

duplicate_pid() {
    root=$1
    awk -F '	' -v OFS='	' 'NR == 3 { $6 = 1001 } { print }' \
        "$root/sequence.tsv" > "$root/sequence.tmp"
    mv -- "$root/sequence.tmp" "$root/sequence.tsv"
    mutate_process_field \
        "$root/processes/000002.csv" "$root/candidate.header.csv" pid 1001
}

alter_cell_order() {
    root=$1
    {
        printf 'exact exists 64k dense\n'
        printf 'exact exists 64k absent\n'
    } > "$root/cells.txt"
}

assert_mutation_rejected duplicate-raw-sample duplicate_raw_sample
assert_mutation_rejected altered-repetition alter_repetition
assert_mutation_rejected altered-source alter_source
assert_mutation_rejected altered-variant alter_variant
assert_mutation_rejected reordered-variants reorder_variants
assert_mutation_rejected missing-process missing_process
assert_mutation_rejected extra-process extra_process
assert_mutation_rejected duplicate-pid duplicate_pid
assert_mutation_rejected altered-cell-order alter_cell_order

echo "verified: 47/48-column cross-version process evidence and order tampering fail closed"
