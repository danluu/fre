#!/usr/bin/env bash
# Reject Rebar candidates whose provenance or known-invalid compile surface is
# ambiguous. This is deliberately narrower than semantic qualification.

set -euo pipefail
export LC_ALL=C

readonly VERSION="2"

fail() {
    local reason=$1
    printf 'candidate_integrity_v%s\tresult=FAIL\treason=%s\n' "$VERSION" "$reason" >&2
    exit 1
}

usage() {
    printf 'usage: %s <repo-top> <required-safe-baseline-sha> <candidate-ref-or-sha> <candidate-worktree>\n' "${0##*/}" >&2
    exit 64
}

canonical_dir() {
    local directory=$1
    (CDPATH= cd -- "$directory" 2>/dev/null && pwd -P)
}

git_common_dir() {
    local worktree=$1
    local common
    common=$(git -C "$worktree" rev-parse --git-common-dir 2>/dev/null) || return 1
    case "$common" in
        /*) canonical_dir "$common" ;;
        *) canonical_dir "$worktree/$common" ;;
    esac
}

sha256_file() {
    local file=$1
    local digest_line
    if command -v shasum >/dev/null 2>&1; then
        digest_line=$(shasum -a 256 -- "$file") || return 1
    elif command -v sha256sum >/dev/null 2>&1; then
        digest_line=$(sha256sum -- "$file") || return 1
    else
        return 1
    fi
    printf '%s\n' "${digest_line%% *}"
}

sha256_text() {
    local value=$1
    local digest_line
    if command -v shasum >/dev/null 2>&1; then
        digest_line=$(printf '%s' "$value" | shasum -a 256) || return 1
    elif command -v sha256sum >/dev/null 2>&1; then
        digest_line=$(printf '%s' "$value" | sha256sum) || return 1
    else
        return 1
    fi
    printf '%s\n' "${digest_line%% *}"
}

resolve_named_or_full_ref() {
    local repo=$1
    local requested=$2
    local symbolic

    if [[ "$requested" =~ ^[0-9a-f]{40}$ ]]; then
        printf '%s\n' "$requested"
        return 0
    fi
    case "$requested" in
        ''|-*|*$'\n'*|*$'\r'*|*$'\t'*|*' '*) return 1 ;;
    esac
    symbolic=$(git -C "$repo" rev-parse --symbolic-full-name "$requested" 2>/dev/null) || return 1
    case "$symbolic" in
        refs/*) ;;
        *) return 1 ;;
    esac
    case "$symbolic" in
        *$'\n'*) return 1 ;;
    esac
    git -C "$repo" show-ref --verify --quiet "$symbolic" || return 1
    printf '%s\n' "$symbolic"
}

candidate_is_clean() {
    local worktree=$1
    local status marker marker_path

    status=$(git -C "$worktree" status --porcelain=v1 --untracked-files=all 2>/dev/null) || return 1
    [[ -z "$status" ]] || return 1

    # A worktree with an otherwise empty index can still be mid-operation.
    for marker in MERGE_HEAD AUTO_MERGE CHERRY_PICK_HEAD REVERT_HEAD REBASE_HEAD \
        BISECT_LOG sequencer rebase-apply rebase-merge; do
        marker_path=$(git -C "$worktree" rev-parse --git-path "$marker" 2>/dev/null) || return 1
        [[ ! -e "$marker_path" ]] || return 1
    done
}

[[ $# -eq 4 ]] || usage
command -v git >/dev/null 2>&1 || fail missing_git
command -v python3 >/dev/null 2>&1 || fail missing_python3

repo_input=$1
baseline_requested=$2
candidate_requested=$3
candidate_input=$4

case "$repo_input$baseline_requested$candidate_requested$candidate_input" in
    *$'\n'*|*$'\r'*|*$'\t'*) fail control_character_in_input ;;
esac

repo=$(canonical_dir "$repo_input") || fail invalid_repo_path
repo_top_raw=$(git -C "$repo" rev-parse --show-toplevel 2>/dev/null) || fail invalid_repo
repo_top=$(canonical_dir "$repo_top_raw") || fail invalid_repo_top
[[ "$repo" == "$repo_top" ]] || fail repo_path_is_not_top
repo_common=$(git_common_dir "$repo") || fail invalid_repo_common_dir

[[ "$baseline_requested" =~ ^[0-9a-f]{40}$ ]] || fail baseline_not_full_sha
baseline_sha=$(git -C "$repo" rev-parse --verify "${baseline_requested}^{commit}" 2>/dev/null) || fail invalid_baseline_commit
[[ "$baseline_sha" == "$baseline_requested" ]] || fail baseline_sha_mismatch
baseline_tree=$(git -C "$repo" rev-parse --verify "${baseline_sha}^{tree}" 2>/dev/null) || fail invalid_baseline_tree

candidate_ref=$(resolve_named_or_full_ref "$repo" "$candidate_requested") || fail invalid_candidate_ref
candidate_sha_start=$(git -C "$repo" rev-parse --verify "${candidate_ref}^{commit}" 2>/dev/null) || fail invalid_candidate_commit
candidate_tree_start=$(git -C "$repo" rev-parse --verify "${candidate_sha_start}^{tree}" 2>/dev/null) || fail invalid_candidate_tree

candidate_worktree=$(canonical_dir "$candidate_input") || fail invalid_candidate_path
candidate_top_raw=$(git -C "$candidate_worktree" rev-parse --show-toplevel 2>/dev/null) || fail candidate_path_not_worktree
candidate_top=$(canonical_dir "$candidate_top_raw") || fail invalid_candidate_top
[[ "$candidate_worktree" == "$candidate_top" ]] || fail candidate_path_is_not_top
candidate_common=$(git_common_dir "$candidate_worktree") || fail invalid_candidate_common_dir
[[ "$candidate_common" == "$repo_common" ]] || fail candidate_from_different_repo

candidate_worktree_sha_start=$(git -C "$candidate_worktree" rev-parse --verify 'HEAD^{commit}' 2>/dev/null) || fail invalid_candidate_worktree_head
candidate_worktree_tree_start=$(git -C "$candidate_worktree" rev-parse --verify 'HEAD^{tree}' 2>/dev/null) || fail invalid_candidate_worktree_tree
[[ "$candidate_worktree_sha_start" == "$candidate_sha_start" ]] || fail candidate_ref_worktree_mismatch
[[ "$candidate_worktree_tree_start" == "$candidate_tree_start" ]] || fail candidate_ref_worktree_tree_mismatch
candidate_is_clean "$candidate_worktree" || fail candidate_worktree_dirty_or_in_progress

git -C "$repo" merge-base --is-ancestor "$baseline_sha" "$candidate_sha_start" 2>/dev/null || fail required_baseline_not_ancestor

invalid_path=$(git -C "$repo" ls-tree -r --name-only "$candidate_sha_start" -- crates/fre/src/unicode_compile.rs 2>/dev/null) || fail invalid_surface_path_check_failed
[[ -z "$invalid_path" ]] || fail known_invalid_unicode_compile_path

if invalid_symbols=$(git -C "$repo" grep -n -E '(fre_unicode_compile_verify|UnicodeCompileArtifact)' "$candidate_sha_start" -- \
    ':(glob)crates/**/*.rs' ':(glob)tools/**/*.rs' 2>/dev/null); then
    fail known_invalid_unicode_compile_symbol
else
    grep_status=$?
    [[ "$grep_status" -eq 1 ]] || fail invalid_surface_symbol_check_failed
fi

guard_dir=$(canonical_dir "$(dirname -- "${BASH_SOURCE[0]}")") || fail invalid_guard_directory
source_policy="$guard_dir/candidate-source-policy.py"
[[ -f "$source_policy" ]] || fail missing_source_policy
if source_policy_receipt=$(python3 "$source_policy" "$repo" "$baseline_sha" "$candidate_sha_start" 2>&1); then
    case "$source_policy_receipt" in
        candidate_source_policy_v1$'\t'result=PASS$'\t'*) ;;
        *) fail invalid_source_policy_receipt ;;
    esac
else
    policy_status=$?
    printf '%s\n' "$source_policy_receipt" >&2
    case "$policy_status" in
        1) fail candidate_source_policy_violation ;;
        *) fail candidate_source_policy_check_failed ;;
    esac
fi

# Re-read every mutable identity after all content checks. A ref move, checkout,
# edit, or repository substitution makes the receipt fail closed.
candidate_ref_end=$(resolve_named_or_full_ref "$repo" "$candidate_requested") || fail candidate_ref_changed
[[ "$candidate_ref_end" == "$candidate_ref" ]] || fail candidate_ref_changed
candidate_sha_end=$(git -C "$repo" rev-parse --verify "${candidate_ref_end}^{commit}" 2>/dev/null) || fail candidate_ref_changed
candidate_tree_end=$(git -C "$repo" rev-parse --verify "${candidate_sha_end}^{tree}" 2>/dev/null) || fail candidate_ref_tree_changed
candidate_worktree_sha_end=$(git -C "$candidate_worktree" rev-parse --verify 'HEAD^{commit}' 2>/dev/null) || fail candidate_worktree_changed
candidate_worktree_tree_end=$(git -C "$candidate_worktree" rev-parse --verify 'HEAD^{tree}' 2>/dev/null) || fail candidate_worktree_tree_changed
candidate_common_end=$(git_common_dir "$candidate_worktree") || fail candidate_repository_changed
candidate_is_clean "$candidate_worktree" || fail candidate_worktree_changed

[[ "$candidate_sha_end" == "$candidate_sha_start" ]] || fail candidate_ref_changed
[[ "$candidate_tree_end" == "$candidate_tree_start" ]] || fail candidate_ref_tree_changed
[[ "$candidate_worktree_sha_end" == "$candidate_worktree_sha_start" ]] || fail candidate_worktree_changed
[[ "$candidate_worktree_tree_end" == "$candidate_worktree_tree_start" ]] || fail candidate_worktree_tree_changed
[[ "$candidate_common_end" == "$candidate_common" ]] || fail candidate_repository_changed

script_path="$guard_dir/$(basename -- "${BASH_SOURCE[0]}")"
guard_sha256=$(sha256_file "$script_path") || fail missing_sha256_tool
source_policy_sha256=$(sha256_file "$source_policy") || fail missing_sha256_tool

printf -v receipt 'candidate_integrity_v%s\tresult=PASS\trepo=%s\tbaseline_sha=%s\tbaseline_tree=%s\tcandidate_ref=%s\tcandidate_sha=%s\tcandidate_tree=%s\tworktree=%s\tclean=1\tancestor=1\tinvalid_path_absent=1\tinvalid_symbols_absent=1\tsource_policy=1\tstable=1\tguard_sha256=%s\tsource_policy_sha256=%s' \
    "$VERSION" "$repo" "$baseline_sha" "$baseline_tree" "$candidate_ref" \
    "$candidate_sha_start" "$candidate_tree_start" "$candidate_worktree" "$guard_sha256" \
    "$source_policy_sha256"
receipt_sha256=$(sha256_text "$receipt") || fail missing_sha256_tool
printf '%s\treceipt_sha256=%s\n' "$receipt" "$receipt_sha256"
