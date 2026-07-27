#!/bin/sh

fre_jit_nonzero_sha256() {
    fre_jit_hash=$1
    case "$fre_jit_hash" in
        *[!0-9a-f]*|"")
            return 1
            ;;
    esac
    [ "${#fre_jit_hash}" = 64 ] &&
        [ "$fre_jit_hash" != \
            0000000000000000000000000000000000000000000000000000000000000000 ]
}

fre_jit_validate_independent_review_receipt() {
    fre_jit_review=$1
    fre_jit_repository=$2
    fre_jit_expected_revision=$3
    fre_jit_expected_tree=$4
    if [ ! -f "$fre_jit_review" ] || [ -L "$fre_jit_review" ]; then
        echo "independent-review receipt must be a regular non-symlink file" >&2
        return 2
    fi
    awk -F '	' '
        NR == 1 {
            if (NF != 2 || $1 != "schema" ||
                $2 != "fre-jit-v7-independent-review-v1") bad = 1
        }
        NR == 2 {
            if (NF != 2 || $1 != "result" || $2 != "pass") bad = 1
        }
        NR == 3 { if (NF != 2 || $1 != "subject_revision") bad = 1 }
        NR == 4 { if (NF != 2 || $1 != "subject_tree") bad = 1 }
        NR == 5 {
            if (NF != 2 || $1 != "scope" ||
                $2 != "execution+evidence-schema") bad = 1
        }
        NR == 6 { if (NF != 2 || $1 != "reviewer_task") bad = 1 }
        NR == 7 { if (NF != 2 || $1 != "findings_sha256") bad = 1 }
        NR > 7 { bad = 1 }
        END { if (NR != 7) bad = 1; exit bad }
    ' "$fre_jit_review" || {
        echo "malformed independent-review receipt" >&2
        return 2
    }
    fre_jit_review_revision=$(
        awk -F '	' 'NR == 3 { print $2 }' "$fre_jit_review"
    )
    fre_jit_review_tree=$(
        awk -F '	' 'NR == 4 { print $2 }' "$fre_jit_review"
    )
    fre_jit_reviewer_task=$(
        awk -F '	' 'NR == 6 { print $2 }' "$fre_jit_review"
    )
    fre_jit_findings_sha256=$(
        awk -F '	' 'NR == 7 { print $2 }' "$fre_jit_review"
    )
    fre_bakeoff_validate_exact_clean_commit \
        "$fre_jit_repository" "$fre_jit_review_revision" \
        independent_review_subject || return $?
    if [ "$fre_jit_review_revision" != "$fre_jit_expected_revision" ] ||
        [ "$fre_jit_review_tree" != "$fre_jit_expected_tree" ] ||
        [ "$(git -C "$fre_jit_repository" show -s --format=%T \
            "$fre_jit_review_revision")" != "$fre_jit_review_tree" ]
    then
        echo "independent-review receipt names the wrong Q commit/tree" >&2
        return 2
    fi
    if ! printf '%s\n' "$fre_jit_reviewer_task" |
        LC_ALL=C grep -Eq '^/root/[a-z0-9_]+$'
    then
        echo "independent-review reviewer_task is not canonical" >&2
        return 2
    fi
    if ! fre_jit_nonzero_sha256 "$fre_jit_findings_sha256"; then
        echo "independent-review findings_sha256 is malformed or zero" >&2
        return 2
    fi
}

fre_jit_validate_promotion_gate_receipt() {
    fre_jit_gate=$1
    fre_jit_repository=$2
    fre_jit_expected_revision=$3
    fre_jit_expected_tree=$4
    if [ ! -f "$fre_jit_gate" ] || [ -L "$fre_jit_gate" ]; then
        echo "promotion-gate receipt must be a regular non-symlink file" >&2
        return 2
    fi
    LC_ALL=C awk -F '	' '
        function decimal(value) {
            return value ~ /^(0|[1-9][0-9]*)([.][0-9]+)?$/
        }
        function nonzero_hex(value, digits, compact) {
            compact = value
            gsub(/[0-9a-f]/, "", compact)
            return length(value) == digits && compact == "" &&
                value != "0000000000000000000000000000000000000000000000000000000000000000"
        }
        function canonical_path(path) {
            return path ~ /^[A-Za-z0-9._\/-]+$/ &&
                path !~ /^\// && path !~ /\/\// &&
                path !~ /(^|\/)[.][.]?(\/|$)/
        }
        NR <= 20 {
            if (NF != 2) bad = 1
            expected[1] = "schema"
            expected[2] = "result"
            expected[3] = "qualification_state"
            expected[4] = "backend"
            expected[5] = "subject_revision"
            expected[6] = "subject_tree"
            expected[7] = "candidate_binary_sha256"
            expected[8] = "candidate_build_receipt_sha256"
            expected[9] = "baseline_revision"
            expected[10] = "baseline_binary_sha256"
            expected[11] = "baseline_build_receipt_sha256"
            expected[12] = "main_facade_gate_rows"
            expected[13] = "main_max_facade_over_kernels"
            expected[14] = "main_required_ratio"
            expected[15] = "adversarial_gate_cells"
            expected[16] = "adversarial_max_candidate_over_baseline"
            expected[17] = "adversarial_max_ratio"
            expected[18] = "targeted_gate_cells"
            expected[19] = "targeted_max_candidate_over_baseline"
            expected[20] = "targeted_max_ratio"
            if ($1 != expected[NR] || seen_fixed[$1]++) bad = 1
            value[NR] = $2
            next
        }
        {
            if (NF != 4 || $1 != "input_sha256" ||
                !nonzero_hex($2, 64) ||
                $3 !~ /^(0|[1-9][0-9]*)$/ ||
                !canonical_path($4) ||
                seen_path[$4]++ ||
                (previous_input != "" && $0 <= previous_input)) {
                bad = 1
            }
            previous_input = $0
            if ($4 ~ /^main\//) main_inputs++
            else if ($4 ~ /^adversarial\//) adversarial_inputs++
            else if ($4 ~ /^targeted\//) targeted_inputs++
            else bad = 1
            input_rows++
        }
        END {
            # These are only structural lower bounds.  Authentication requires
            # replaying the gate against the frozen, exact bundle inventory.
            if (main_inputs < 20 || adversarial_inputs < 560 ||
                targeted_inputs < 60) bad = 1
            if (value[1] != "fre-jit-v7-promotion-gate-receipt-v1" ||
                value[2] != "pass" ||
                value[3] != "candidate" ||
                value[4] != "aarch64-search-v7" ||
                !nonzero_hex(value[7], 64) ||
                !nonzero_hex(value[8], 64) ||
                !nonzero_hex(value[10], 64) ||
                !nonzero_hex(value[11], 64) ||
                value[12] != "60" ||
                !decimal(value[13]) || value[13] + 0 >= 1 ||
                value[14] != "strictly_less_than_1" ||
                value[15] != "18" ||
                !decimal(value[16]) || value[16] + 0 > 1.15 ||
                value[17] != "1.150000000" ||
                value[18] != "1" ||
                !decimal(value[19]) || value[19] + 0 > 1.15 ||
                value[20] != "1.150000000") bad = 1
            exit bad
        }
    ' "$fre_jit_gate" || {
        echo "malformed or incomplete promotion-gate-v1 receipt" >&2
        return 2
    }
    fre_jit_gate_revision=$(
        awk -F '	' 'NR == 5 { print $2 }' "$fre_jit_gate"
    )
    fre_jit_gate_tree=$(
        awk -F '	' 'NR == 6 { print $2 }' "$fre_jit_gate"
    )
    fre_jit_baseline_revision=$(
        awk -F '	' 'NR == 9 { print $2 }' "$fre_jit_gate"
    )
    fre_bakeoff_validate_exact_clean_commit \
        "$fre_jit_repository" "$fre_jit_gate_revision" \
        promotion_subject || return $?
    fre_bakeoff_validate_exact_clean_commit \
        "$fre_jit_repository" "$fre_jit_baseline_revision" \
        promotion_baseline || return $?
    if [ "$fre_jit_gate_revision" != "$fre_jit_expected_revision" ] ||
        [ "$fre_jit_gate_tree" != "$fre_jit_expected_tree" ] ||
        [ "$(git -C "$fre_jit_repository" show -s --format=%T \
            "$fre_jit_gate_revision")" != "$fre_jit_gate_tree" ] ||
        [ "$fre_jit_gate_revision" = "$fre_jit_baseline_revision" ]
    then
        echo "promotion-gate receipt names inconsistent source commits" >&2
        return 2
    fi
}
