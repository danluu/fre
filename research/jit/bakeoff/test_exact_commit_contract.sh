#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repository=$(CDPATH= cd -P -- "$script_dir/../../.." && pwd -P)
. "$script_dir/runner_support.sh"

candidate=$(git -C "$repository" rev-parse --verify HEAD^{commit})
baseline=$(git -C "$repository" rev-parse --verify HEAD^^{commit})
fre_bakeoff_validate_exact_clean_commit \
    "$repository" "$candidate" candidate
fre_bakeoff_validate_distinct_exact_commits \
    "$repository" "$baseline" "$candidate"

assert_rejected() {
    case_name=$1
    shift
    if "$@" >/dev/null 2>&1; then
        echo "non-exact commit contract was accepted: $case_name" >&2
        exit 1
    fi
}

assert_rejected symbolic-head \
    fre_bakeoff_validate_exact_clean_commit "$repository" HEAD forged
assert_rejected abbreviated \
    fre_bakeoff_validate_exact_clean_commit \
    "$repository" "$(printf '%s' "$candidate" | cut -c1-12)" forged
assert_rejected tag-shaped \
    fre_bakeoff_validate_exact_clean_commit "$repository" v7-qualified forged
assert_rejected uppercase \
    fre_bakeoff_validate_exact_clean_commit \
    "$repository" "$(printf '%s' "$candidate" | tr 'a-f' 'A-F')" forged
assert_rejected candidate-vs-itself \
    fre_bakeoff_validate_distinct_exact_commits \
    "$repository" "$candidate" "$candidate"

echo "verified: symbolic, abbreviated, tag-shaped, and self-baseline commits fail closed"
