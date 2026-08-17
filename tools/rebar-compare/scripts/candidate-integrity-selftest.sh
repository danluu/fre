#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
guard="$script_dir/candidate-integrity.sh"
repo=${1:-$(CDPATH= cd -- "$script_dir/../../.." && pwd -P)}
fixtures="$script_dir/fixtures/candidate-source-policy"

readonly safe_baseline=a16e41e471e4d969c0dc43e00c50bb851f989033
readonly pre_contamination_baseline=d7e151eb7fe5ae646bcab1be49ee9c90e62566d9
readonly contaminated_310=31001465fa49998eede9cf860a9be4c09b4d0cd5
readonly contaminated_790=79003592e9ba2efbd2d5bf0cb150e73fc5c9fc73

tmp_root=$(mktemp -d "${TMPDIR:-/tmp}/fre-candidate-integrity.XXXXXX")
declare -a worktrees=()

cleanup() {
    local index
    for ((index=${#worktrees[@]} - 1; index >= 0; index--)); do
        git -C "$repo" worktree remove --force "${worktrees[$index]}" >/dev/null 2>&1 || true
    done
    rm -rf -- "$tmp_root"
}
trap cleanup EXIT INT TERM

safe_baseline_available=true
if ! git -C "$repo" cat-file -e "${safe_baseline}^{commit}" 2>/dev/null; then
    safe_baseline_available=false
fi

contamination_history_available=true
for object in "$pre_contamination_baseline" "$contaminated_310" "$contaminated_790"; do
    if ! git -C "$repo" cat-file -e "${object}^{commit}" 2>/dev/null; then
        contamination_history_available=false
    fi
done

new_worktree() {
    local label=$1
    local ref=$2
    current_worktree="$tmp_root/$label"
    git -C "$repo" worktree add --quiet --detach "$current_worktree" "$ref"
    worktrees+=("$current_worktree")
}

expect_accept() {
    local label=$1
    local baseline=$2
    local ref=$3
    local receipt
    new_worktree "$label" "$ref"
    receipt="$tmp_root/$label.receipt"
    "$guard" "$repo" "$baseline" "$ref" "$current_worktree" >"$receipt"
    grep -q $'^candidate_integrity_v2\tresult=PASS\t' "$receipt"
    grep -q $'\tclean=1\tancestor=1\tinvalid_path_absent=1\tinvalid_symbols_absent=1\tsource_policy=1\tstable=1\t' "$receipt"
    grep -Eq $'\tsource_policy_sha256=[0-9a-f]{64}\t' "$receipt"
    grep -Eq $'\treceipt_sha256=[0-9a-f]{64}$' "$receipt"
}

expect_reject() {
    local label=$1
    local expected_reason=$2
    local baseline=$3
    local ref=$4
    local error_log
    new_worktree "$label" "$ref"
    error_log="$tmp_root/$label.error"
    if "$guard" "$repo" "$baseline" "$ref" "$current_worktree" >"$tmp_root/$label.out" 2>"$error_log"; then
        printf 'selftest: %s unexpectedly passed\n' "$label" >&2
        exit 1
    fi
    grep -q "reason=$expected_reason" "$error_log"
}

fixture_repo="$tmp_root/source-policy-repo"
mkdir -p "$fixture_repo/crates/demo/src"
git -C "$fixture_repo" init --quiet
git -C "$fixture_repo" config user.name candidate-integrity-selftest
git -C "$fixture_repo" config user.email candidate-integrity-selftest.invalid
cp "$fixtures/safe-baseline.rs" "$fixture_repo/crates/demo/src/lib.rs"
git -C "$fixture_repo" add crates/demo/src/lib.rs
git -C "$fixture_repo" commit --quiet -m safe-baseline
fixture_baseline=$(git -C "$fixture_repo" rev-parse HEAD)

fixture_commit() {
    local label=$1
    local fixture=$2
    git -C "$fixture_repo" checkout --quiet --detach "$fixture_baseline"
    cp "$fixtures/$fixture" "$fixture_repo/crates/demo/src/lib.rs"
    if [[ "$fixture" == included-fixture.rs ]]; then
        cp "$fixtures/benchmark.payload" "$fixture_repo/crates/demo/src/benchmark.payload"
    fi
    git -C "$fixture_repo" add -A crates/demo/src
    git -C "$fixture_repo" commit --quiet -m "$label"
    fixture_sha=$(git -C "$fixture_repo" rev-parse HEAD)
}

expect_policy_accept() {
    local label=$1
    local fixture=$2
    local receipt worktree
    fixture_commit "$label" "$fixture"
    worktree="$tmp_root/$label-worktree"
    git -C "$fixture_repo" worktree add --quiet --detach "$worktree" "$fixture_sha"
    receipt="$tmp_root/$label.receipt"
    "$guard" "$fixture_repo" "$fixture_baseline" "$fixture_sha" "$worktree" >"$receipt"
    grep -q $'^candidate_integrity_v2\tresult=PASS\t' "$receipt"
    grep -q $'\tsource_policy=1\t' "$receipt"
}

expect_policy_reject() {
    local label=$1
    local fixture=$2
    local expected_rule=$3
    local error_log worktree
    fixture_commit "$label" "$fixture"
    worktree="$tmp_root/$label-worktree"
    git -C "$fixture_repo" worktree add --quiet --detach "$worktree" "$fixture_sha"
    error_log="$tmp_root/$label.error"
    if "$guard" "$fixture_repo" "$fixture_baseline" "$fixture_sha" "$worktree" \
        >"$tmp_root/$label.out" 2>"$error_log"; then
        printf 'selftest: source-policy case %s unexpectedly passed\n' "$label" >&2
        exit 1
    fi
    grep -q "rule=$expected_rule" "$error_log"
    grep -q 'reason=candidate_source_policy_violation' "$error_log"
}

# Exercise the policy against commits in a separate synthetic repository. The
# accepted case covers regex-redux model patterns, source-bound artifact
# authentication and cfg(test) exceptions. Each malicious commit changes
# exactly one production surface from the same safe baseline.
expect_policy_accept policy-allowed-model-and-binding allowed-model-and-binding.rs
expect_policy_reject policy-exact-source exact-source.rs raw_regex_source_exact_decision
expect_policy_reject policy-renamed-source renamed-source-constant.rs raw_regex_source_exact_decision
expect_policy_reject policy-job-id job-id.rs benchmark_identity_match_dispatch
expect_policy_reject policy-benchmark-name benchmark-name.rs benchmark_identity_exact_decision
expect_policy_reject policy-source-hash source-hash.rs source_fingerprint_exact_decision
expect_policy_reject policy-included-fixture included-fixture.rs raw_regex_source_exact_decision
expect_policy_reject policy-expected-answer expected-answer.rs reachable_expected_answer_constant

if [[ "$safe_baseline_available" == true ]]; then
    expect_accept safe-baseline "$safe_baseline" "$safe_baseline"

    # A clean commit is insufficient if its checked-out worktree has untracked or
    # modified content.
    new_worktree dirty-worktree "$safe_baseline"
    touch "$current_worktree/.candidate-integrity-dirty"
    if "$guard" "$repo" "$safe_baseline" "$safe_baseline" "$current_worktree" >"$tmp_root/dirty.out" 2>"$tmp_root/dirty.error"; then
        printf 'selftest: dirty worktree unexpectedly passed\n' >&2
        exit 1
    fi
    grep -q 'reason=candidate_worktree_dirty_or_in_progress' "$tmp_root/dirty.error"
else
    printf 'selftest: safe provenance baseline unavailable\n' >&2
fi

if [[ "$contamination_history_available" == true ]]; then
# The production baseline rejects these old contaminated frontier commits by
# ancestry. A known-safe earlier baseline also proves that the content gate,
# independently, rejects their Unicode compile surface.
expect_reject contaminated-310-ancestry required_baseline_not_ancestor "$safe_baseline" "$contaminated_310"
expect_reject contaminated-790-ancestry required_baseline_not_ancestor "$safe_baseline" "$contaminated_790"
expect_reject contaminated-310-surface known_invalid_unicode_compile_path "$pre_contamination_baseline" "$contaminated_310"
expect_reject contaminated-790-surface known_invalid_unicode_compile_path "$pre_contamination_baseline" "$contaminated_790"
else
    printf 'selftest: historical Unicode contamination fixtures unavailable; those cases skipped\n' >&2
fi

# Exercise the live safe Unicode and capture branches when their current tips
# really descend from the required baseline. Their absence is not a failure in
# a clone that contains only canonical refs.
if [[ "$safe_baseline_available" == true ]]; then
    for safe_ref in lane/g0-compose-unicode-word-bf53-r1 lane/g0-capture-on-unicode-bf53-r1; do
        if git -C "$repo" rev-parse --verify "${safe_ref}^{commit}" >/dev/null 2>&1 &&
            git -C "$repo" merge-base --is-ancestor "$safe_baseline" "$safe_ref"; then
            label=${safe_ref##*/}
            expect_accept "$label" "$safe_baseline" "$safe_ref"
        fi
    done
fi

printf 'candidate-integrity selftest: PASS\n'
