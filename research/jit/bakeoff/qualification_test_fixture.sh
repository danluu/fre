#!/bin/sh

fre_jit_test_candidate_identity=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
fre_jit_test_baseline_identity=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
fre_jit_test_manifest_identity=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc

fre_jit_test_candidate_header() {
    printf '%s\n' \
        'schema,revision,pid,repetition,cell,shape,operation,size,scenario,haystack_bytes,alignment_mod16,engine,stage,timing_scope,iterations,total_ns,ns_per_iter,checksum,semantic_value,code_bytes,data_bytes,payload_used_bytes,total_mapped_bytes,total_pages,instructions,vector_instructions,loads,stores,branches,identity_bytes_hashed,identity_scratch_bytes,identity_heap_allocations,cache_bookkeeping_bytes,cache_hits,fixture,output_kind,backend,route,artifact_identity,evidence_identity,qualification_state,qualification_bundle_sha256,evidence_binding,artifact_binding,declared_min_window_bytes,declared_min_qualifying_calls,measured_calls,measured_qualifying_calls'
}

fre_jit_test_baseline_header() {
    printf '%s\n' \
        'schema,revision,pid,repetition,cell,shape,operation,size,scenario,haystack_bytes,alignment_mod16,engine,stage,timing_scope,iterations,total_ns,ns_per_iter,checksum,semantic_value,code_bytes,data_bytes,payload_used_bytes,total_mapped_bytes,total_pages,instructions,vector_instructions,loads,stores,branches,identity_bytes_hashed,identity_scratch_bytes,identity_heap_allocations,cache_bookkeeping_bytes,cache_hits,fixture,output_kind,backend,route,artifact_identity,evidence_identity,evidence_manifest_identity,evidence_binding,artifact_binding,declared_min_window_bytes,declared_min_qualifying_calls,measured_calls,measured_qualifying_calls'
}

fre_jit_test_sha_text() {
    printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
}

fre_jit_test_candidate_row() {
    fre_jit_row_destination=$1
    fre_jit_row_revision=$2
    fre_jit_row_pid=$3
    fre_jit_row_repetition=$4
    fre_jit_row_cell=$5
    fre_jit_row_shape=$6
    fre_jit_row_operation=$7
    fre_jit_row_size=$8
    fre_jit_row_scenario=$9
    shift 9
    fre_jit_row_haystack=$1
    fre_jit_row_engine=$2
    fre_jit_row_stage=$3
    fre_jit_row_ns=$4

    fre_jit_row_output=span
    fre_jit_row_backend=unqualified
    fre_jit_row_route=unqualified
    fre_jit_row_artifact=none
    fre_jit_row_binding=unqualified
    fre_jit_row_artifact_binding=unqualified
    fre_jit_row_min_window=1
    fre_jit_row_min_calls=1
    fre_jit_row_qualifying=1
    fre_jit_row_code=0
    fre_jit_row_data=0
    fre_jit_row_payload=0
    fre_jit_row_mapped=0
    fre_jit_row_pages=0
    fre_jit_row_instructions=0
    fre_jit_row_vectors=0
    fre_jit_row_loads=0
    fre_jit_row_stores=0
    fre_jit_row_branches=0
    fre_jit_row_identity_bytes=0
    fre_jit_row_scratch=0
    fre_jit_row_heap=0
    case "$fre_jit_row_engine" in
        fre-qualified-exact)
            fre_jit_row_backend=aarch64-search-v7
            fre_jit_row_route=native-jit
            fre_jit_row_artifact=$fre_jit_test_candidate_identity
            fre_jit_row_artifact_binding=facade-reported-identity+deterministic-native-span-image
            fre_jit_row_code=1
            fre_jit_row_data=1
            fre_jit_row_payload=1
            fre_jit_row_mapped=1
            fre_jit_row_pages=1
            fre_jit_row_instructions=1
            fre_jit_row_vectors=1
            fre_jit_row_loads=1
            fre_jit_row_stores=1
            fre_jit_row_branches=1
            fre_jit_row_identity_bytes=1
            fre_jit_row_scratch=1
            fre_jit_row_heap=1
            fre_jit_row_binding="fre-qualified-exact-evidence-v2|output=span|backend=$fre_jit_row_backend|route=$fre_jit_row_route|artifact=$fre_jit_row_artifact|qualification_state=candidate|qualification_bundle=none|minimum_window_bytes=1|minimum_qualifying_calls=1"
            ;;
        fre-qualified-exact-under-threshold)
            fre_jit_row_backend=portable-literal
            fre_jit_row_route=portable-literal
            fre_jit_row_artifact=none
            fre_jit_row_artifact_binding=portable-semantic-owner
            fre_jit_row_binding="fre-qualified-exact-evidence-v2|output=span|backend=portable-literal|route=portable-literal|artifact=none|qualification_state=candidate|qualification_bundle=none|minimum_window_bytes=1|minimum_qualifying_calls=1"
            ;;
        jit)
            fre_jit_row_backend=jit
            fre_jit_row_route=direct-image
            fre_jit_row_artifact=$fre_jit_test_candidate_identity
            ;;
        fre-kernels)
            fre_jit_row_backend=fre-kernels
            fre_jit_row_route=kernel
            ;;
    esac
    if [ "$fre_jit_row_engine" = fre-qualified-exact ] ||
        [ "$fre_jit_row_engine" = fre-qualified-exact-under-threshold ]
    then
        fre_jit_row_evidence=$(fre_jit_test_sha_text "$fre_jit_row_binding")
    else
        fre_jit_row_evidence=none
    fi
    printf '%s\n' \
        "fre-jit-bakeoff-v2,$fre_jit_row_revision,$fre_jit_row_pid,$fre_jit_row_repetition,$fre_jit_row_cell,$fre_jit_row_shape,$fre_jit_row_operation,$fre_jit_row_size,$fre_jit_row_scenario,$fre_jit_row_haystack,0,$fre_jit_row_engine,$fre_jit_row_stage,synthetic,1,$fre_jit_row_ns,$fre_jit_row_ns,0x1,0x1,$fre_jit_row_code,$fre_jit_row_data,$fre_jit_row_payload,$fre_jit_row_mapped,$fre_jit_row_pages,$fre_jit_row_instructions,$fre_jit_row_vectors,$fre_jit_row_loads,$fre_jit_row_stores,$fre_jit_row_branches,$fre_jit_row_identity_bytes,$fre_jit_row_scratch,$fre_jit_row_heap,0,0,synthetic-v2,$fre_jit_row_output,$fre_jit_row_backend,$fre_jit_row_route,$fre_jit_row_artifact,$fre_jit_row_evidence,candidate,none,$fre_jit_row_binding,$fre_jit_row_artifact_binding,$fre_jit_row_min_window,$fre_jit_row_min_calls,1,$fre_jit_row_qualifying" \
        >> "$fre_jit_row_destination"
}

fre_jit_test_baseline_row() {
    fre_jit_row_destination=$1
    fre_jit_row_revision=$2
    fre_jit_row_pid=$3
    fre_jit_row_repetition=$4
    fre_jit_row_cell=$5
    fre_jit_row_shape=$6
    fre_jit_row_operation=$7
    fre_jit_row_size=$8
    fre_jit_row_scenario=$9
    shift 9
    fre_jit_row_haystack=$1
    fre_jit_row_engine=$2
    fre_jit_row_stage=$3
    fre_jit_row_ns=$4

    fre_jit_row_backend=unqualified
    fre_jit_row_route=unqualified
    fre_jit_row_artifact=none
    fre_jit_row_manifest=none
    fre_jit_row_binding=unqualified
    fre_jit_row_artifact_binding=unqualified
    fre_jit_row_code=0
    fre_jit_row_data=0
    fre_jit_row_payload=0
    fre_jit_row_mapped=0
    fre_jit_row_pages=0
    fre_jit_row_instructions=0
    fre_jit_row_vectors=0
    fre_jit_row_loads=0
    fre_jit_row_stores=0
    fre_jit_row_branches=0
    fre_jit_row_identity_bytes=0
    fre_jit_row_scratch=0
    fre_jit_row_heap=0
    case "$fre_jit_row_engine" in
        fre-qualified-exact)
            fre_jit_row_backend=aarch64-jit-v2
            fre_jit_row_route=native-jit
            fre_jit_row_artifact=$fre_jit_test_baseline_identity
            fre_jit_row_manifest=$fre_jit_test_manifest_identity
            fre_jit_row_artifact_binding=facade-reported-identity+deterministic-native-span-image
            fre_jit_row_code=1
            fre_jit_row_data=1
            fre_jit_row_payload=1
            fre_jit_row_mapped=1
            fre_jit_row_pages=1
            fre_jit_row_instructions=1
            fre_jit_row_vectors=1
            fre_jit_row_loads=1
            fre_jit_row_stores=1
            fre_jit_row_branches=1
            fre_jit_row_identity_bytes=1
            fre_jit_row_scratch=1
            fre_jit_row_heap=1
            fre_jit_row_binding="fre-qualified-exact-evidence-v1|output=span|backend=$fre_jit_row_backend|route=$fre_jit_row_route|artifact=$fre_jit_row_artifact|evidence_manifest=$fre_jit_row_manifest|minimum_window_bytes=1|minimum_qualifying_calls=1"
            ;;
        jit)
            fre_jit_row_backend=jit
            fre_jit_row_route=direct-image
            fre_jit_row_artifact=$fre_jit_test_baseline_identity
            ;;
    esac
    if [ "$fre_jit_row_engine" = fre-qualified-exact ]; then
        fre_jit_row_evidence=$(fre_jit_test_sha_text "$fre_jit_row_binding")
    else
        fre_jit_row_evidence=none
    fi
    printf '%s\n' \
        "fre-jit-bakeoff-v1,$fre_jit_row_revision,$fre_jit_row_pid,$fre_jit_row_repetition,$fre_jit_row_cell,$fre_jit_row_shape,$fre_jit_row_operation,$fre_jit_row_size,$fre_jit_row_scenario,$fre_jit_row_haystack,0,$fre_jit_row_engine,$fre_jit_row_stage,synthetic,1,$fre_jit_row_ns,$fre_jit_row_ns,0x1,0x1,$fre_jit_row_code,$fre_jit_row_data,$fre_jit_row_payload,$fre_jit_row_mapped,$fre_jit_row_pages,$fre_jit_row_instructions,$fre_jit_row_vectors,$fre_jit_row_loads,$fre_jit_row_stores,$fre_jit_row_branches,$fre_jit_row_identity_bytes,$fre_jit_row_scratch,$fre_jit_row_heap,0,0,synthetic-v1,span,$fre_jit_row_backend,$fre_jit_row_route,$fre_jit_row_artifact,$fre_jit_row_evidence,$fre_jit_row_manifest,$fre_jit_row_binding,$fre_jit_row_artifact_binding,1,1,1,1" \
        >> "$fre_jit_row_destination"
}

fre_jit_test_write_catalog() {
    fre_jit_catalog_destination=$1
    : > "$fre_jit_catalog_destination"
    for fre_jit_catalog_operation in exists end span; do
        for fre_jit_catalog_size in short 64k 1m; do
            for fre_jit_catalog_scenario in \
                primary-dense-secondary-absent \
                pair-dense-literal-absent \
                triple-dense-literal-absent \
                false-pair-distant-match \
                binary \
                natural-text
            do
                printf 'exact %s %s %s\n' \
                    "$fre_jit_catalog_operation" \
                    "$fre_jit_catalog_size" \
                    "$fre_jit_catalog_scenario" \
                    >> "$fre_jit_catalog_destination"
            done
        done
    done
}

fre_jit_test_write_binary() {
    fre_jit_binary_destination=$1
    fre_jit_binary_label=$2
    {
        printf '#!/bin/sh\n'
        printf '# %s\n' "$fre_jit_binary_label"
        printf 'if [ "${1:-}" != list-adversarial ]; then exit 2; fi\n'
        printf 'for operation in exists end span; do\n'
        printf '  for size in short 64k 1m; do\n'
        printf '    for scenario in primary-dense-secondary-absent pair-dense-literal-absent triple-dense-literal-absent false-pair-distant-match binary natural-text; do\n'
        printf '      printf "exact %%s %%s %%s\\n" "$operation" "$size" "$scenario"\n'
        printf '    done\n'
        printf '  done\n'
        printf 'done\n'
    } > "$fre_jit_binary_destination"
    chmod 0755 "$fre_jit_binary_destination"
}

fre_jit_test_write_build_receipt() {
    fre_jit_receipt_destination=$1
    fre_jit_receipt_source=$2
    fre_jit_receipt_binary=$3
    fre_jit_receipt_binary_sha=$4
    {
        printf 'schema\tfre-jit-bakeoff-build-receipt-v1\n'
        printf 'source_state_id\t%s\n' "$fre_jit_receipt_source"
        printf 'binary_path\t%s\n' "$fre_jit_receipt_binary"
        printf 'binary_sha256\t%s\n' "$fre_jit_receipt_binary_sha"
        printf 'build_dir\t/private/tmp/removed-build\n'
        printf 'manifest_path\tresearch/jit/bakeoff/Cargo.toml\n'
        printf 'manifest_sha256\t%s\n' "$fre_jit_test_candidate_identity"
        printf 'lockfile_path\tresearch/jit/bakeoff/Cargo.lock\n'
        printf 'lockfile_sha256\t%s\n' "$fre_jit_test_baseline_identity"
        printf 'rustc\trustc-test\n'
        printf 'cargo\tcargo-test\n'
        printf 'coordinator_holder_dir\t/private/tmp/removed-holder\n'
        printf 'built_utc\t2026-07-26T00:00:00Z\n'
    } > "$fre_jit_receipt_destination"
}

fre_jit_test_write_source_bundle() {
    fre_jit_source_destination=$1
    fre_jit_source_revision=$2
    mkdir -p "$fre_jit_source_destination"
    printf '%s\n' "$fre_jit_source_revision" > "$fre_jit_source_destination/head.txt"
    : > "$fre_jit_source_destination/status.txt"
    : > "$fre_jit_source_destination/untracked.txt"
    : > "$fre_jit_source_destination/staged.patch"
    : > "$fre_jit_source_destination/worktree.patch"
    : > "$fre_jit_source_destination/submodules.txt"
    printf 'synthetic lockfiles\n' > "$fre_jit_source_destination/lockfiles.sha256"
    printf 'synthetic manifests\n' > "$fre_jit_source_destination/manifests.sha256"
    (
        cd "$fre_jit_source_destination"
        shasum -a 256 \
            head.txt status.txt untracked.txt staged.patch worktree.patch \
            submodules.txt lockfiles.sha256 manifests.sha256
    ) > "$fre_jit_source_destination/source-inputs.sha256"
    fre_jit_source_digest=$(
        shasum -a 256 "$fre_jit_source_destination/source-inputs.sha256" |
            awk '{print $1}'
    )
    printf '0\n' > "$fre_jit_source_destination/dirty.txt"
    printf '%s\n' "$fre_jit_source_digest" \
        > "$fre_jit_source_destination/source-digest.txt"
    printf '%s\n' "$fre_jit_source_revision" \
        > "$fre_jit_source_destination/source-state-id.txt"
    printf '2026-07-26T00:00:00Z\n' \
        > "$fre_jit_source_destination/verified-at-finish.txt"
}

fre_jit_test_write_main() {
    fre_jit_main_root=$1
    fre_jit_main_revision=$2
    fre_jit_main_receipt=$3
    mkdir -p "$fre_jit_main_root/provenance"
    fre_jit_test_candidate_header > "$fre_jit_main_root/raw.csv"
    : > "$fre_jit_main_root/cells.txt"
    fre_jit_main_pid=1000
    fre_jit_main_index=1
    while [ "$fre_jit_main_index" -le 30 ]; do
        if [ $((fre_jit_main_index % 2)) -eq 0 ]; then
            fre_jit_main_size=1m
            fre_jit_main_haystack=1048576
        else
            fre_jit_main_size=64k
            fre_jit_main_haystack=65536
        fi
        fre_jit_main_suffix=$(printf '%02d' "$fre_jit_main_index")
        fre_jit_main_cell="exact-exists-$fre_jit_main_size-case$fre_jit_main_suffix"
        printf 'exact exists %s case%s\n' \
            "$fre_jit_main_size" "$fre_jit_main_suffix" \
            >> "$fre_jit_main_root/cells.txt"
        fre_jit_main_repetition=0
        while [ "$fre_jit_main_repetition" -lt 5 ]; do
            fre_jit_main_pid=$((fre_jit_main_pid + 1))
            fre_jit_test_candidate_row \
                "$fre_jit_main_root/raw.csv" "$fre_jit_main_revision" \
                "$fre_jit_main_pid" "$fre_jit_main_repetition" \
                "$fre_jit_main_cell" exact exists "$fre_jit_main_size" \
                "case$fre_jit_main_suffix" "$fre_jit_main_haystack" \
                fre-kernels search 100
            fre_jit_test_candidate_row \
                "$fre_jit_main_root/raw.csv" "$fre_jit_main_revision" \
                "$fre_jit_main_pid" "$fre_jit_main_repetition" \
                "$fre_jit_main_cell" exact exists "$fre_jit_main_size" \
                "case$fre_jit_main_suffix" "$fre_jit_main_haystack" \
                fre-qualified-exact search 40
            fre_jit_test_candidate_row \
                "$fre_jit_main_root/raw.csv" "$fre_jit_main_revision" \
                "$fre_jit_main_pid" "$fre_jit_main_repetition" \
                "$fre_jit_main_cell" exact exists "$fre_jit_main_size" \
                "case$fre_jit_main_suffix" "$fre_jit_main_haystack" \
                fre-qualified-exact build_full_workload 45
            fre_jit_test_candidate_row \
                "$fre_jit_main_root/raw.csv" "$fre_jit_main_revision" \
                "$fre_jit_main_pid" "$fre_jit_main_repetition" \
                "$fre_jit_main_cell" exact exists "$fre_jit_main_size" \
                "case$fre_jit_main_suffix" "$fre_jit_main_haystack" \
                fre-qualified-exact-under-threshold search 60
            fre_jit_test_candidate_row \
                "$fre_jit_main_root/raw.csv" "$fre_jit_main_revision" \
                "$fre_jit_main_pid" "$fre_jit_main_repetition" \
                "$fre_jit_main_cell" exact exists "$fre_jit_main_size" \
                "case$fre_jit_main_suffix" "$fre_jit_main_haystack" \
                fre-qualified-exact-under-threshold build_full_workload 65
            fre_jit_main_repetition=$((fre_jit_main_repetition + 1))
        done
        fre_jit_main_index=$((fre_jit_main_index + 1))
    done
    fre_jit_main_index=1
    while [ "$fre_jit_main_index" -le 60 ]; do
        fre_jit_main_suffix=$(printf '%02d' "$fre_jit_main_index")
        fre_jit_main_cell="class-exists-short-case$fre_jit_main_suffix"
        printf 'class exists short case%s\n' "$fre_jit_main_suffix" \
            >> "$fre_jit_main_root/cells.txt"
        fre_jit_main_repetition=0
        while [ "$fre_jit_main_repetition" -lt 5 ]; do
            fre_jit_main_pid=$((fre_jit_main_pid + 1))
            fre_jit_test_candidate_row \
                "$fre_jit_main_root/raw.csv" "$fre_jit_main_revision" \
                "$fre_jit_main_pid" "$fre_jit_main_repetition" \
                "$fre_jit_main_cell" class exists short \
                "case$fre_jit_main_suffix" 96 jit direct_lease_call 20
            fre_jit_main_repetition=$((fre_jit_main_repetition + 1))
        done
        fre_jit_main_index=$((fre_jit_main_index + 1))
    done

    printf 'identity=%s\n' "$fre_jit_test_candidate_identity" \
        > "$fre_jit_main_root/exact-span.instructions.txt"
    printf 'identity=%s\n' "$fre_jit_test_candidate_identity" \
        > "$fre_jit_main_root/class-span.instructions.txt"
    LC_ALL=C awk -f "$fre_jit_test_script_dir/summarize.awk" \
        "$fre_jit_main_root/raw.csv" > "$fre_jit_main_root/ranges.csv"
    LC_ALL=C awk -f "$fre_jit_test_script_dir/compare.awk" \
        "$fre_jit_main_root/ranges.csv" > "$fre_jit_main_root/comparisons.csv"
    awk -F, 'NR == 1 || $3 == "loss"' \
        "$fre_jit_main_root/comparisons.csv" > "$fre_jit_main_root/losses.csv"
    printf 'synthetic symbols\n' > "$fre_jit_main_root/linked-symbols.txt"
    printf 'synthetic load commands\n' > "$fre_jit_main_root/linked-load-commands.txt"
    printf 'synthetic disassembly\n' > "$fre_jit_main_root/linked-disassembly.txt"

    cp -- "$fre_jit_main_receipt" \
        "$fre_jit_main_root/provenance/build-receipt.tsv"
    fre_jit_test_write_source_bundle \
        "$fre_jit_main_root/provenance/source" "$fre_jit_main_revision"
    fre_jit_main_receipt_sha=$(
        shasum -a 256 "$fre_jit_main_receipt" | awk '{print $1}'
    )
    fre_jit_main_binary_path=$(
        awk -F '	' '$1 == "binary_path" { print $2 }' "$fre_jit_main_receipt"
    )
    fre_jit_main_binary_sha=$(
        awk -F '	' '$1 == "binary_sha256" { print $2 }' "$fre_jit_main_receipt"
    )
    printf '%s\n' "$fre_jit_main_receipt_sha" \
        > "$fre_jit_main_root/provenance/build-receipt.sha256"
    printf '/private/tmp/removed-candidate-receipt.tsv\n' \
        > "$fre_jit_main_root/provenance/build-receipt-source-path.txt"
    printf '%s\n' "$fre_jit_main_binary_sha" \
        > "$fre_jit_main_root/provenance/binary.sha256"
    printf '%s\n' "$fre_jit_main_binary_path" \
        > "$fre_jit_main_root/provenance/binary-path.txt"
    {
        printf 'source_state_id=%s\n' "$fre_jit_main_revision"
        printf 'binary=%s  %s\n' \
            "$fre_jit_main_binary_sha" "$fre_jit_main_binary_path"
        printf 'build_receipt=%s  /private/tmp/removed-candidate-receipt.tsv\n' \
            "$fre_jit_main_receipt_sha"
    } > "$fre_jit_main_root/environment.txt"
    {
        printf 'source_state_id=%s\n' "$fre_jit_main_revision"
        printf 'cells=90\n'
    } > "$fre_jit_main_root/completion.txt"
}

fre_jit_test_materialize_baseline_verifier() {
    fre_jit_verifier_destination=$1
    fre_jit_verifier_repository=$2
    fre_jit_verifier_revision=$3
    mkdir -p "$fre_jit_verifier_destination"
    fre_jit_verifier_rows=research/jit/bakeoff/verify_evidence_rows.awk
    fre_jit_verifier_identity=research/jit/bakeoff/verify_evidence_identity.sh
    git -C "$fre_jit_verifier_repository" \
        show "$fre_jit_verifier_revision:$fre_jit_verifier_rows" \
        > "$fre_jit_verifier_destination/verify_evidence_rows.awk"
    git -C "$fre_jit_verifier_repository" \
        show "$fre_jit_verifier_revision:$fre_jit_verifier_identity" \
        > "$fre_jit_verifier_destination/verify_evidence_identity.sh"
    chmod 0755 "$fre_jit_verifier_destination/verify_evidence_identity.sh"
    {
        printf 'schema\tfre-jit-baseline-evidence-verifier-v1\n'
        printf 'source_revision\t%s\n' "$fre_jit_verifier_revision"
        printf 'rows_blob\t%s\n' \
            "$(git -C "$fre_jit_verifier_repository" rev-parse \
                "$fre_jit_verifier_revision:$fre_jit_verifier_rows")"
        printf 'rows_sha256\t%s\n' \
            "$(shasum -a 256 "$fre_jit_verifier_destination/verify_evidence_rows.awk" |
                awk '{print $1}')"
        printf 'identity_blob\t%s\n' \
            "$(git -C "$fre_jit_verifier_repository" rev-parse \
                "$fre_jit_verifier_revision:$fre_jit_verifier_identity")"
        printf 'identity_sha256\t%s\n' \
            "$(shasum -a 256 "$fre_jit_verifier_destination/verify_evidence_identity.sh" |
                awk '{print $1}')"
    } > "$fre_jit_verifier_destination/verifier-receipt.tsv"
}

fre_jit_test_haystack_for_size() {
    case "$1" in
        short) printf '96\n' ;;
        64k) printf '65536\n' ;;
        1m) printf '1048576\n' ;;
        *) return 2 ;;
    esac
}

fre_jit_test_write_ab() {
    fre_jit_ab_root=$1
    fre_jit_ab_repository=$2
    fre_jit_ab_baseline_revision=$3
    fre_jit_ab_candidate_revision=$4
    fre_jit_ab_baseline_receipt=$5
    fre_jit_ab_candidate_receipt=$6
    fre_jit_ab_kind=$7
    mkdir -p "$fre_jit_ab_root/provenance" "$fre_jit_ab_root/processes"
    fre_jit_test_write_catalog "$fre_jit_ab_root/all-cells.txt"
    if [ "$fre_jit_ab_kind" = adversarial ]; then
        cp -- "$fre_jit_ab_root/all-cells.txt" "$fre_jit_ab_root/cells.txt"
        cp -- "$fre_jit_ab_root/all-cells.txt" "$fre_jit_ab_root/baseline.cells.txt"
        cp -- "$fre_jit_ab_root/all-cells.txt" "$fre_jit_ab_root/candidate.cells.txt"
        fre_jit_ab_repetitions=5
        fre_jit_ab_schema=fre-jit-alternating-adversarial-ab-v3
    else
        awk '$0 == "exact exists 64k primary-dense-secondary-absent"' \
            "$fre_jit_ab_root/all-cells.txt" > "$fre_jit_ab_root/cells.txt"
        cp -- "$fre_jit_ab_root/all-cells.txt" \
            "$fre_jit_ab_root/baseline.catalog.cells.txt"
        cp -- "$fre_jit_ab_root/all-cells.txt" \
            "$fre_jit_ab_root/candidate.catalog.cells.txt"
        fre_jit_ab_repetitions=15
        fre_jit_ab_schema=fre-jit-targeted-alternating-adversarial-ab-v2
    fi
    rm -- "$fre_jit_ab_root/all-cells.txt"

    fre_jit_test_baseline_header > "$fre_jit_ab_root/baseline.header.csv"
    fre_jit_test_candidate_header > "$fre_jit_ab_root/candidate.header.csv"
    cp -- "$fre_jit_ab_root/baseline.header.csv" "$fre_jit_ab_root/baseline.raw.csv"
    cp -- "$fre_jit_ab_root/candidate.header.csv" "$fre_jit_ab_root/candidate.raw.csv"
    printf 'identity=%s\n' "$fre_jit_test_baseline_identity" \
        > "$fre_jit_ab_root/baseline.exact-span.instructions.txt"
    printf 'identity=%s\n' "$fre_jit_test_candidate_identity" \
        > "$fre_jit_ab_root/candidate.exact-span.instructions.txt"
    printf 'sequence\tcell\trepetition\tvariant\tsource_state\tpid\tprocess_output\n' \
        > "$fre_jit_ab_root/sequence.tsv"

    fre_jit_ab_sequence=0
    while IFS=' ' read -r fre_jit_ab_shape fre_jit_ab_operation \
        fre_jit_ab_size fre_jit_ab_scenario
    do
        fre_jit_ab_cell="$fre_jit_ab_shape-$fre_jit_ab_operation-$fre_jit_ab_size-$fre_jit_ab_scenario"
        fre_jit_ab_haystack=$(fre_jit_test_haystack_for_size "$fre_jit_ab_size")
        fre_jit_ab_repetition=0
        while [ "$fre_jit_ab_repetition" -lt "$fre_jit_ab_repetitions" ]; do
            if [ $((fre_jit_ab_repetition % 2)) -eq 0 ]; then
                fre_jit_ab_order="baseline candidate"
            else
                fre_jit_ab_order="candidate baseline"
            fi
            for fre_jit_ab_variant in $fre_jit_ab_order; do
                fre_jit_ab_sequence=$((fre_jit_ab_sequence + 1))
                fre_jit_ab_pid=$((20000 + fre_jit_ab_sequence))
                fre_jit_ab_process=$(printf 'processes/%06d.csv' "$fre_jit_ab_sequence")
                fre_jit_ab_output="$fre_jit_ab_root/$fre_jit_ab_process"
                : > "$fre_jit_ab_output"
                if [ "$fre_jit_ab_variant" = baseline ]; then
                    fre_jit_ab_source=$fre_jit_ab_baseline_revision
                    fre_jit_test_baseline_row \
                        "$fre_jit_ab_output" "$fre_jit_ab_source" \
                        "$fre_jit_ab_pid" "$fre_jit_ab_repetition" \
                        "$fre_jit_ab_cell" "$fre_jit_ab_shape" \
                        "$fre_jit_ab_operation" "$fre_jit_ab_size" \
                        "$fre_jit_ab_scenario" "$fre_jit_ab_haystack" \
                        jit direct_lease_call 100
                    fre_jit_test_baseline_row \
                        "$fre_jit_ab_output" "$fre_jit_ab_source" \
                        "$fre_jit_ab_pid" "$fre_jit_ab_repetition" \
                        "$fre_jit_ab_cell" "$fre_jit_ab_shape" \
                        "$fre_jit_ab_operation" "$fre_jit_ab_size" \
                        "$fre_jit_ab_scenario" "$fre_jit_ab_haystack" \
                        fre-qualified-exact search 80
                else
                    fre_jit_ab_source=$fre_jit_ab_candidate_revision
                    fre_jit_test_candidate_row \
                        "$fre_jit_ab_output" "$fre_jit_ab_source" \
                        "$fre_jit_ab_pid" "$fre_jit_ab_repetition" \
                        "$fre_jit_ab_cell" "$fre_jit_ab_shape" \
                        "$fre_jit_ab_operation" "$fre_jit_ab_size" \
                        "$fre_jit_ab_scenario" "$fre_jit_ab_haystack" \
                        jit direct_lease_call 50
                    fre_jit_test_candidate_row \
                        "$fre_jit_ab_output" "$fre_jit_ab_source" \
                        "$fre_jit_ab_pid" "$fre_jit_ab_repetition" \
                        "$fre_jit_ab_cell" "$fre_jit_ab_shape" \
                        "$fre_jit_ab_operation" "$fre_jit_ab_size" \
                        "$fre_jit_ab_scenario" "$fre_jit_ab_haystack" \
                        fre-qualified-exact search 40
                fi
                cat "$fre_jit_ab_output" \
                    >> "$fre_jit_ab_root/$fre_jit_ab_variant.raw.csv"
                printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                    "$fre_jit_ab_sequence" "$fre_jit_ab_cell" \
                    "$fre_jit_ab_repetition" "$fre_jit_ab_variant" \
                    "$fre_jit_ab_source" "$fre_jit_ab_pid" \
                    "$fre_jit_ab_process" >> "$fre_jit_ab_root/sequence.tsv"
            done
            fre_jit_ab_repetition=$((fre_jit_ab_repetition + 1))
        done
    done < "$fre_jit_ab_root/cells.txt"

    for fre_jit_ab_variant in baseline candidate; do
        LC_ALL=C awk -f "$fre_jit_test_script_dir/summarize.awk" \
            "$fre_jit_ab_root/$fre_jit_ab_variant.raw.csv" | {
                IFS= read -r fre_jit_ab_header
                printf '%s\n' "$fre_jit_ab_header"
                LC_ALL=C sort
            } > "$fre_jit_ab_root/$fre_jit_ab_variant.ranges.csv"
        LC_ALL=C awk -f "$fre_jit_test_script_dir/compare.awk" \
            "$fre_jit_ab_root/$fre_jit_ab_variant.ranges.csv" \
            > "$fre_jit_ab_root/$fre_jit_ab_variant.comparisons.csv"
        awk -F, 'NR == 1 || $3 == "loss"' \
            "$fre_jit_ab_root/$fre_jit_ab_variant.comparisons.csv" \
            > "$fre_jit_ab_root/$fre_jit_ab_variant.losses.csv"
    done
    LC_ALL=C awk -f "$fre_jit_test_script_dir/ab_compare.awk" \
        "$fre_jit_ab_root/baseline.ranges.csv" \
        "$fre_jit_ab_root/candidate.ranges.csv" | {
            IFS= read -r fre_jit_ab_header
            printf '%s\n' "$fre_jit_ab_header"
            LC_ALL=C sort
        } > "$fre_jit_ab_root/direct-jit-ab.csv"

    cp -- "$fre_jit_ab_baseline_receipt" \
        "$fre_jit_ab_root/provenance/baseline-build-receipt.tsv"
    cp -- "$fre_jit_ab_candidate_receipt" \
        "$fre_jit_ab_root/provenance/candidate-build-receipt.tsv"
    fre_jit_test_write_source_bundle \
        "$fre_jit_ab_root/provenance/baseline-source" \
        "$fre_jit_ab_baseline_revision"
    fre_jit_test_write_source_bundle \
        "$fre_jit_ab_root/provenance/candidate-source" \
        "$fre_jit_ab_candidate_revision"
    fre_jit_test_write_source_bundle \
        "$fre_jit_ab_root/provenance/current-source" \
        "$fre_jit_ab_candidate_revision"
    fre_jit_test_materialize_baseline_verifier \
        "$fre_jit_ab_root/provenance/baseline-verifier" \
        "$fre_jit_ab_repository" "$fre_jit_ab_baseline_revision"
    fre_jit_ab_baseline_sha=$(
        awk -F '	' '$1 == "binary_sha256" { print $2 }' \
            "$fre_jit_ab_baseline_receipt"
    )
    fre_jit_ab_candidate_sha=$(
        awk -F '	' '$1 == "binary_sha256" { print $2 }' \
            "$fre_jit_ab_candidate_receipt"
    )
    {
        printf 'schema=%s\n' "$fre_jit_ab_schema"
        printf 'baseline_source=%s\n' "$fre_jit_ab_baseline_revision"
        printf 'candidate_source=%s\n' "$fre_jit_ab_candidate_revision"
        printf 'baseline_binary_sha256=%s\n' "$fre_jit_ab_baseline_sha"
        printf 'candidate_binary_sha256=%s\n' "$fre_jit_ab_candidate_sha"
        if [ "$fre_jit_ab_kind" = targeted ]; then
            printf 'cell=exact-exists-64k-primary-dense-secondary-absent\n'
        fi
        printf 'cells=%s\n' "$(wc -l < "$fre_jit_ab_root/cells.txt" | tr -d ' ')"
        printf 'processes_per_cell_per_variant=%s\n' "$fre_jit_ab_repetitions"
        printf 'total_timed_processes=%s\n' "$fre_jit_ab_sequence"
    } > "$fre_jit_ab_root/completion.txt"
}

fre_jit_test_write_review() {
    fre_jit_review_destination=$1
    fre_jit_review_revision=$2
    fre_jit_review_tree=$3
    fre_jit_review_findings=$4
    {
        printf 'schema\tfre-jit-v7-independent-review-v1\n'
        printf 'result\tpass\n'
        printf 'subject_revision\t%s\n' "$fre_jit_review_revision"
        printf 'subject_tree\t%s\n' "$fre_jit_review_tree"
        printf 'scope\texecution+evidence-schema\n'
        printf 'reviewer_task\t/root/jit_v7_fixture_review\n'
        printf 'findings_sha256\t%s\n' \
            "$(shasum -a 256 "$fre_jit_review_findings" | awk '{print $1}')"
    } > "$fre_jit_review_destination"
}

fre_jit_test_prepare_bundle_root() {
    fre_jit_fixture_root=$1
    fre_jit_fixture_repository=$2
    fre_jit_fixture_revision=$3
    fre_jit_fixture_baseline=$4
    fre_jit_fixture_ephemeral=$5
    fre_jit_test_script_dir=$6
    mkdir -p \
        "$fre_jit_fixture_root/main" \
        "$fre_jit_fixture_root/adversarial" \
        "$fre_jit_fixture_root/targeted" \
        "$fre_jit_fixture_root/binaries" \
        "$fre_jit_fixture_root/receipts" \
        "$fre_jit_fixture_root/gates" \
        "$fre_jit_fixture_root/reviews" \
        "$fre_jit_fixture_root/fixtures" \
        "$fre_jit_fixture_root/environment" \
        "$fre_jit_fixture_ephemeral"
    fre_jit_fixture_candidate_ephemeral="$fre_jit_fixture_ephemeral/candidate-fre-jit-bakeoff"
    fre_jit_fixture_baseline_ephemeral="$fre_jit_fixture_ephemeral/baseline-fre-jit-bakeoff"
    fre_jit_test_write_binary \
        "$fre_jit_fixture_candidate_ephemeral" candidate-v7
    fre_jit_test_write_binary \
        "$fre_jit_fixture_baseline_ephemeral" baseline-v4
    cp -p -- "$fre_jit_fixture_candidate_ephemeral" \
        "$fre_jit_fixture_root/binaries/candidate-fre-jit-bakeoff"
    cp -p -- "$fre_jit_fixture_baseline_ephemeral" \
        "$fre_jit_fixture_root/binaries/baseline-fre-jit-bakeoff"
    fre_jit_fixture_candidate_sha=$(
        shasum -a 256 "$fre_jit_fixture_candidate_ephemeral" | awk '{print $1}'
    )
    fre_jit_fixture_baseline_sha=$(
        shasum -a 256 "$fre_jit_fixture_baseline_ephemeral" | awk '{print $1}'
    )
    fre_jit_test_write_build_receipt \
        "$fre_jit_fixture_root/receipts/candidate-build-receipt.tsv" \
        "$fre_jit_fixture_revision" "$fre_jit_fixture_candidate_ephemeral" \
        "$fre_jit_fixture_candidate_sha"
    fre_jit_test_write_build_receipt \
        "$fre_jit_fixture_root/receipts/baseline-build-receipt.tsv" \
        "$fre_jit_fixture_baseline" "$fre_jit_fixture_baseline_ephemeral" \
        "$fre_jit_fixture_baseline_sha"
    fre_jit_test_write_main \
        "$fre_jit_fixture_root/main" "$fre_jit_fixture_revision" \
        "$fre_jit_fixture_root/receipts/candidate-build-receipt.tsv"
    fre_jit_test_write_ab \
        "$fre_jit_fixture_root/adversarial" "$fre_jit_fixture_repository" \
        "$fre_jit_fixture_baseline" "$fre_jit_fixture_revision" \
        "$fre_jit_fixture_root/receipts/baseline-build-receipt.tsv" \
        "$fre_jit_fixture_root/receipts/candidate-build-receipt.tsv" \
        adversarial
    fre_jit_test_write_ab \
        "$fre_jit_fixture_root/targeted" "$fre_jit_fixture_repository" \
        "$fre_jit_fixture_baseline" "$fre_jit_fixture_revision" \
        "$fre_jit_fixture_root/receipts/baseline-build-receipt.tsv" \
        "$fre_jit_fixture_root/receipts/candidate-build-receipt.tsv" \
        targeted
    printf 'synthetic fixture\n' > "$fre_jit_fixture_root/fixtures/en-sampled.txt"
    printf 'synthetic host\n' > "$fre_jit_fixture_root/environment/host.txt"
    "$fre_jit_test_script_dir/verify_v7_promotion_gates.sh" \
        "$fre_jit_fixture_root/main" \
        "$fre_jit_fixture_root/adversarial" \
        "$fre_jit_fixture_root/targeted" \
        "$fre_jit_fixture_root/gates/promotion.tsv" > /dev/null
    printf 'independent synthetic findings\n' \
        > "$fre_jit_fixture_root/reviews/findings.txt"
    fre_jit_test_write_review \
        "$fre_jit_fixture_root/reviews/independent.txt" \
        "$fre_jit_fixture_revision" \
        "$(git -C "$fre_jit_fixture_repository" show -s --format=%T \
            "$fre_jit_fixture_revision")" \
        "$fre_jit_fixture_root/reviews/findings.txt"
    rm -- \
        "$fre_jit_fixture_candidate_ephemeral" \
        "$fre_jit_fixture_baseline_ephemeral"
}

fre_jit_test_write_inputs() {
    fre_jit_inputs_root=$1
    fre_jit_inputs_destination=$2
    {
        printf 'binary\tbinaries/baseline-fre-jit-bakeoff\n'
        printf 'binary\tbinaries/candidate-fre-jit-bakeoff\n'
        printf 'receipt\treceipts/baseline-build-receipt.tsv\n'
        printf 'receipt\treceipts/candidate-build-receipt.tsv\n'
        printf 'gate\tgates/promotion.tsv\n'
        printf 'review\treviews/independent.txt\n'
        printf 'findings\treviews/findings.txt\n'
        printf 'fixture\tfixtures/en-sampled.txt\n'
        printf 'environment\tenvironment/host.txt\n'
        for fre_jit_inputs_tree in main adversarial targeted; do
            find "$fre_jit_inputs_root/$fre_jit_inputs_tree" -type f -print |
            while IFS= read -r fre_jit_inputs_file; do
                printf 'result\t%s\n' \
                    "${fre_jit_inputs_file#"$fre_jit_inputs_root"/}"
            done
        done
    } | LC_ALL=C sort -t '	' -k1,1 -k2,2 > "$fre_jit_inputs_destination"
}
