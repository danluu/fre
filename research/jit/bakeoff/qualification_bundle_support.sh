#!/bin/sh

# Canonical, closed qualification-bundle layout.  Result trees are intentionally
# variable-sized, but every regular file in every managed directory must be
# listed in the bundle manifest.
FRE_JIT_BUNDLE_CANDIDATE_BINARY=binaries/candidate-fre-jit-bakeoff
FRE_JIT_BUNDLE_BASELINE_BINARY=binaries/baseline-fre-jit-bakeoff
FRE_JIT_BUNDLE_CANDIDATE_RECEIPT=receipts/candidate-build-receipt.tsv
FRE_JIT_BUNDLE_BASELINE_RECEIPT=receipts/baseline-build-receipt.tsv
FRE_JIT_BUNDLE_PROMOTION_GATE=gates/promotion.tsv
FRE_JIT_BUNDLE_REVIEW=reviews/independent.txt
FRE_JIT_BUNDLE_FINDINGS=reviews/findings.txt
FRE_JIT_BUNDLE_FIXTURE=fixtures/en-sampled.txt
FRE_JIT_BUNDLE_ENVIRONMENT=environment/host.txt

fre_jit_bundle_contract_error() {
    echo "$*" >&2
    return 2
}

fre_jit_bundle_validate_entry_contract() {
    fre_jit_contract_entries=$1
    LC_ALL=C awk -F '	' \
        -v candidate_binary="$FRE_JIT_BUNDLE_CANDIDATE_BINARY" \
        -v baseline_binary="$FRE_JIT_BUNDLE_BASELINE_BINARY" \
        -v candidate_receipt="$FRE_JIT_BUNDLE_CANDIDATE_RECEIPT" \
        -v baseline_receipt="$FRE_JIT_BUNDLE_BASELINE_RECEIPT" \
        -v promotion="$FRE_JIT_BUNDLE_PROMOTION_GATE" \
        -v review="$FRE_JIT_BUNDLE_REVIEW" \
        -v findings="$FRE_JIT_BUNDLE_FINDINGS" \
        -v fixture="$FRE_JIT_BUNDLE_FIXTURE" \
        -v environment="$FRE_JIT_BUNDLE_ENVIRONMENT" '
        NF != 2 || $1 == "" || $2 == "" { bad = 1; next }
        {
            kind = $1
            path = $2
            if (seen[path]++) bad = 1
            if (kind == "result") {
                if (path !~ /^(main|adversarial|targeted)\//) bad = 1
                result++
            } else if (kind == "binary") {
                if (path != candidate_binary && path != baseline_binary) bad = 1
                binary++
            } else if (kind == "receipt") {
                if (path != candidate_receipt && path != baseline_receipt) bad = 1
                receipt++
            } else if (kind == "gate") {
                if (path != promotion) bad = 1
                gate++
            } else if (kind == "review") {
                if (path != review) bad = 1
                review_count++
            } else if (kind == "findings") {
                if (path != findings) bad = 1
                findings_count++
            } else if (kind == "fixture") {
                if (path != fixture) bad = 1
                fixture_count++
            } else if (kind == "environment") {
                if (path != environment) bad = 1
                environment_count++
            } else {
                bad = 1
            }
        }
        END {
            required[1] = candidate_binary
            required[2] = baseline_binary
            required[3] = candidate_receipt
            required[4] = baseline_receipt
            required[5] = promotion
            required[6] = review
            required[7] = findings
            required[8] = fixture
            required[9] = environment
            for (item in required) {
                if (seen[required[item]] != 1) bad = 1
            }
            if (binary != 2 || receipt != 2 || gate != 1 ||
                review_count != 1 || findings_count != 1 ||
                fixture_count != 1 || environment_count != 1 ||
                result < 3) bad = 1
            exit bad
        }
    ' "$fre_jit_contract_entries" || {
        fre_jit_bundle_contract_error \
            "qualification inputs do not match the closed canonical layout"
        return $?
    }
}

fre_jit_bundle_inventory() {
    fre_jit_inventory_root=$1
    fre_jit_inventory_destination=$2
    : > "$fre_jit_inventory_destination"
    for fre_jit_inventory_name in \
        main adversarial targeted binaries receipts gates reviews fixtures environment
    do
        fre_jit_inventory_path="$fre_jit_inventory_root/$fre_jit_inventory_name"
        if [ ! -d "$fre_jit_inventory_path" ] || [ -L "$fre_jit_inventory_path" ]; then
            fre_jit_bundle_contract_error \
                "missing canonical bundle directory: $fre_jit_inventory_name"
            return $?
        fi
    done

    find "$fre_jit_inventory_root" -type l -print \
        > "$fre_jit_inventory_destination.symlinks"
    if [ -s "$fre_jit_inventory_destination.symlinks" ]; then
        fre_jit_bundle_contract_error "qualification bundle contains a symlink"
        return $?
    fi
    find "$fre_jit_inventory_root" ! -type d ! -type f ! -type l -print \
        > "$fre_jit_inventory_destination.special"
    if [ -s "$fre_jit_inventory_destination.special" ]; then
        fre_jit_bundle_contract_error "qualification bundle contains a special file"
        return $?
    fi
    find "$fre_jit_inventory_root" -type d -print |
    while IFS= read -r fre_jit_inventory_directory; do
        fre_jit_inventory_relative=${fre_jit_inventory_directory#"$fre_jit_inventory_root"}
        fre_jit_inventory_relative=${fre_jit_inventory_relative#/}
        case "$fre_jit_inventory_relative" in
            ""|main|main/*|adversarial|adversarial/*|targeted|targeted/*|\
            binaries|receipts|gates|reviews|fixtures|environment)
                ;;
            *)
                echo "non-canonical qualification directory: $fre_jit_inventory_relative" >&2
                exit 2
                ;;
        esac
    done || return $?

    find "$fre_jit_inventory_root" -type f -print |
    while IFS= read -r fre_jit_inventory_file; do
        fre_jit_inventory_relative=${fre_jit_inventory_file#"$fre_jit_inventory_root"/}
        if [ "$fre_jit_inventory_relative" = "$fre_jit_inventory_file" ]; then
            exit 2
        fi
        case "$fre_jit_inventory_relative" in
            qualification-bundle-v1.tsv) continue ;;
        esac
        if ! printf '%s\n' "$fre_jit_inventory_relative" |
            LC_ALL=C grep -Eq '^[A-Za-z0-9._/-]+$'
        then
            echo "non-canonical qualification file: $fre_jit_inventory_relative" >&2
            exit 2
        fi
        printf '%s\n' "$fre_jit_inventory_relative"
    done > "$fre_jit_inventory_destination.unsorted" || return $?
    LC_ALL=C sort \
        "$fre_jit_inventory_destination.unsorted" \
        > "$fre_jit_inventory_destination" || return $?
}

fre_jit_bundle_declared_paths() {
    fre_jit_declared_entries=$1
    fre_jit_declared_destination=$2
    awk -F '	' '{ print $2 }' "$fre_jit_declared_entries" |
        LC_ALL=C sort > "$fre_jit_declared_destination"
}

fre_jit_bundle_require_exact_inventory() {
    fre_jit_exact_root=$1
    fre_jit_exact_entries=$2
    fre_jit_exact_temporary=$3
    fre_jit_bundle_inventory \
        "$fre_jit_exact_root" "$fre_jit_exact_temporary.inventory" || return $?
    fre_jit_bundle_declared_paths \
        "$fre_jit_exact_entries" "$fre_jit_exact_temporary.declared" || return $?
    if ! cmp -s \
        "$fre_jit_exact_temporary.inventory" \
        "$fre_jit_exact_temporary.declared"
    then
        fre_jit_bundle_contract_error \
            "declared entries do not exactly equal the managed bundle inventory"
        return $?
    fi
}

fre_jit_bundle_entry_records() {
    fre_jit_records_root=$1
    fre_jit_records_entries=$2
    fre_jit_records_destination=$3
    fre_jit_records_prefix="$fre_jit_records_destination.records"
    awk -F '	' '{ print $2 }' "$fre_jit_records_entries" \
        > "$fre_jit_records_prefix.paths"
    (
        cd "$fre_jit_records_root"
        xargs shasum -a 256 < "$fre_jit_records_prefix.paths"
    ) | awk '{ print $2 "\t" $1 }' > "$fre_jit_records_prefix.hashes"
    (
        cd "$fre_jit_records_root"
        xargs wc -c < "$fre_jit_records_prefix.paths"
    ) | awk '$2 != "total" { print $2 "\t" $1 }' \
        > "$fre_jit_records_prefix.sizes"
    paste \
        "$fre_jit_records_entries" \
        "$fre_jit_records_prefix.hashes" \
        "$fre_jit_records_prefix.sizes" |
    awk -F '	' '
        NF != 6 || $2 != $3 || $2 != $5 { bad = 1; next }
        { print "entry\t" $1 "\t" $4 "\t" $6 "\t" $2 }
        END { exit bad }
    ' > "$fre_jit_records_destination"
}

fre_jit_bundle_copy_snapshot() {
    fre_jit_copy_root=$1
    fre_jit_copy_entries=$2
    fre_jit_copy_destination=$3
    mkdir -- "$fre_jit_copy_destination" || return 2
    while IFS='	' read -r fre_jit_copy_kind fre_jit_copy_relative; do
        fre_jit_copy_source="$fre_jit_copy_root/$fre_jit_copy_relative"
        fre_jit_copy_target="$fre_jit_copy_destination/$fre_jit_copy_relative"
        mkdir -p -- "$(dirname -- "$fre_jit_copy_target")" || return 2
        cp -p -- "$fre_jit_copy_source" "$fre_jit_copy_target" || return 2
    done < "$fre_jit_copy_entries"
}

fre_jit_bundle_validate_artifact_bindings() {
    fre_jit_binding_root=$1
    fre_jit_binding_gate="$fre_jit_binding_root/$FRE_JIT_BUNDLE_PROMOTION_GATE"
    fre_jit_binding_candidate_binary="$fre_jit_binding_root/$FRE_JIT_BUNDLE_CANDIDATE_BINARY"
    fre_jit_binding_baseline_binary="$fre_jit_binding_root/$FRE_JIT_BUNDLE_BASELINE_BINARY"
    fre_jit_binding_candidate_receipt="$fre_jit_binding_root/$FRE_JIT_BUNDLE_CANDIDATE_RECEIPT"
    fre_jit_binding_baseline_receipt="$fre_jit_binding_root/$FRE_JIT_BUNDLE_BASELINE_RECEIPT"

    for fre_jit_binding_file in \
        "$fre_jit_binding_candidate_binary" \
        "$fre_jit_binding_baseline_binary" \
        "$fre_jit_binding_candidate_receipt" \
        "$fre_jit_binding_baseline_receipt"
    do
        if [ ! -f "$fre_jit_binding_file" ] || [ -L "$fre_jit_binding_file" ]; then
            fre_jit_bundle_contract_error "missing canonical bound artifact"
            return $?
        fi
    done
    for fre_jit_binding_binary in \
        "$fre_jit_binding_candidate_binary" "$fre_jit_binding_baseline_binary"
    do
        if [ ! -x "$fre_jit_binding_binary" ]; then
            fre_jit_bundle_contract_error "canonical bundled binary is not executable"
            return $?
        fi
    done
    fre_bakeoff_validate_build_receipt "$fre_jit_binding_candidate_receipt" || return $?
    fre_bakeoff_validate_build_receipt "$fre_jit_binding_baseline_receipt" || return $?

    fre_jit_binding_candidate_binary_sha=$(
        fre_bakeoff_sha256 "$fre_jit_binding_candidate_binary"
    )
    fre_jit_binding_baseline_binary_sha=$(
        fre_bakeoff_sha256 "$fre_jit_binding_baseline_binary"
    )
    fre_jit_binding_candidate_receipt_sha=$(
        fre_bakeoff_sha256 "$fre_jit_binding_candidate_receipt"
    )
    fre_jit_binding_baseline_receipt_sha=$(
        fre_bakeoff_sha256 "$fre_jit_binding_baseline_receipt"
    )
    test "$(fre_bakeoff_receipt_field \
        "$fre_jit_binding_candidate_receipt" binary_sha256)" = \
        "$fre_jit_binding_candidate_binary_sha" || return 2
    test "$(fre_bakeoff_receipt_field \
        "$fre_jit_binding_baseline_receipt" binary_sha256)" = \
        "$fre_jit_binding_baseline_binary_sha" || return 2
    test "$(awk -F '	' 'NR == 7 { print $2 }' "$fre_jit_binding_gate")" = \
        "$fre_jit_binding_candidate_binary_sha" || return 2
    test "$(awk -F '	' 'NR == 8 { print $2 }' "$fre_jit_binding_gate")" = \
        "$fre_jit_binding_candidate_receipt_sha" || return 2
    test "$(awk -F '	' 'NR == 10 { print $2 }' "$fre_jit_binding_gate")" = \
        "$fre_jit_binding_baseline_binary_sha" || return 2
    test "$(awk -F '	' 'NR == 11 { print $2 }' "$fre_jit_binding_gate")" = \
        "$fre_jit_binding_baseline_receipt_sha" || return 2
}

fre_jit_bundle_materialize_replay_scripts() {
    fre_jit_scripts_repository=$1
    fre_jit_scripts_revision=$2
    fre_jit_scripts_destination=$3
    fre_jit_scripts_relative=research/jit/bakeoff
    mkdir -p -- "$fre_jit_scripts_destination/$fre_jit_scripts_relative" || return 2
    for fre_jit_scripts_name in \
        verify_v7_promotion_gates.sh \
        verify_qualification_results.sh \
        verify_provenance.sh \
        verify_evidence_rows.awk \
        verify_evidence_identity.sh \
        verify_alternating_process_evidence.sh \
        summarize.awk \
        ab_compare.awk \
        runner_support.sh \
        qualification_receipts.sh
    do
        fre_jit_scripts_object="$fre_jit_scripts_revision:$fre_jit_scripts_relative/$fre_jit_scripts_name"
        if [ "$(git -C "$fre_jit_scripts_repository" cat-file -t \
            "$fre_jit_scripts_object" 2>/dev/null)" != blob ]
        then
            fre_jit_bundle_contract_error \
                "qualification replay script is absent from the exact Q commit"
            return $?
        fi
        git -C "$fre_jit_scripts_repository" show "$fre_jit_scripts_object" \
            > "$fre_jit_scripts_destination/$fre_jit_scripts_relative/$fre_jit_scripts_name" ||
            return 2
    done
    chmod 0755 \
        "$fre_jit_scripts_destination/$fre_jit_scripts_relative/"*.sh || return 2
}

fre_jit_bundle_replay_gate() {
    fre_jit_replay_root=$1
    fre_jit_replay_repository=$2
    fre_jit_replay_revision=$3
    fre_jit_replay_temporary=$4
    fre_jit_replay_expected="$fre_jit_replay_root/$FRE_JIT_BUNDLE_PROMOTION_GATE"
    fre_jit_replay_scripts="$fre_jit_replay_temporary/scripts"
    fre_jit_bundle_materialize_replay_scripts \
        "$fre_jit_replay_repository" "$fre_jit_replay_revision" \
        "$fre_jit_replay_scripts" || return $?
    fre_jit_replay_output="$fre_jit_replay_temporary/replayed-promotion.tsv"
    FRE_JIT_PROMOTION_REPLAY=1 \
    FRE_JIT_REPLAY_REPOSITORY="$fre_jit_replay_repository" \
    FRE_JIT_REPLAY_CANDIDATE_BINARY="$fre_jit_replay_root/$FRE_JIT_BUNDLE_CANDIDATE_BINARY" \
    FRE_JIT_REPLAY_BASELINE_BINARY="$fre_jit_replay_root/$FRE_JIT_BUNDLE_BASELINE_BINARY" \
    FRE_JIT_REPLAY_CANDIDATE_RECEIPT="$fre_jit_replay_root/$FRE_JIT_BUNDLE_CANDIDATE_RECEIPT" \
    FRE_JIT_REPLAY_BASELINE_RECEIPT="$fre_jit_replay_root/$FRE_JIT_BUNDLE_BASELINE_RECEIPT" \
        "$fre_jit_replay_scripts/research/jit/bakeoff/verify_v7_promotion_gates.sh" \
        "$fre_jit_replay_root/main" \
        "$fre_jit_replay_root/adversarial" \
        "$fre_jit_replay_root/targeted" \
        "$fre_jit_replay_output" > /dev/null || return $?
    if ! cmp -s "$fre_jit_replay_output" "$fre_jit_replay_expected"; then
        fre_jit_bundle_contract_error \
            "replayed promotion gate differs from the bundled receipt"
        return $?
    fi
}
