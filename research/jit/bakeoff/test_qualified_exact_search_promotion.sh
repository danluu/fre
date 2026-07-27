#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repository=$(CDPATH= cd -P -- "$script_dir/../../.." && pwd -P)
validator="$script_dir/verify_qualified_exact_search_promotion.sh"
subject_revision=88e9c22c4ac382531bc1026ca0e25587905f5206
qualification_path=crates/fre/src/qualified_exact_search_qualification.rs
if [ "$#" -gt 1 ]; then
    echo "usage: test_qualified_exact_search_promotion.sh [PROMOTION_REVISION]" >&2
    exit 2
fi
if [ "$#" = 1 ]; then
    promotion_revision=$1
else
    promotion_revision=$(git -C "$repository" rev-parse --verify HEAD^{commit})
fi

temporary=$(mktemp -d "${TMPDIR:-/tmp}/fre-jit-promotion-test.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

expect_rejection() {
    label=$1
    expected=$2
    shift 2
    if "$@" > "$temporary/$label.stdout" 2> "$temporary/$label.stderr"; then
        echo "promotion validator accepted $label" >&2
        exit 1
    fi
    if ! grep -F "$expected" "$temporary/$label.stderr" > /dev/null; then
        echo "promotion validator rejected $label for the wrong reason" >&2
        sed 's/^/  /' "$temporary/$label.stderr" >&2
        exit 1
    fi
}

commit_tree() {
    tree=$1
    parent=$2
    message=$3
    printf '%s\n' "$message" |
        env \
            GIT_AUTHOR_NAME='JIT promotion contract test' \
            GIT_AUTHOR_EMAIL='jit-promotion-test@example.invalid' \
            GIT_COMMITTER_NAME='JIT promotion contract test' \
            GIT_COMMITTER_EMAIL='jit-promotion-test@example.invalid' \
            git -C "$repository" commit-tree "$tree" -p "$parent"
}

"$validator" --source-only "$promotion_revision" "$repository" \
    > "$temporary/source-only.stdout"
grep -F 'no bundle authorization was performed' \
    "$temporary/source-only.stdout" > /dev/null

expect_rejection \
    q8-is-not-promotion \
    'exact Q8 qualification commit as its sole parent' \
    "$validator" --source-only "$subject_revision" "$repository"

promotion_tree=$(git -C "$repository" rev-parse "$promotion_revision^{tree}")
descendant=$(commit_tree \
    "$promotion_tree" "$promotion_revision" \
    'synthetic stale descendant')
expect_rejection \
    stale-descendant \
    'exact Q8 qualification commit as its sole parent' \
    "$validator" --source-only "$descendant" "$repository"

production_path=crates/fre/src/qualified_exact_search.rs
production_blob=$(
    {
        git -C "$repository" show "$promotion_revision:$production_path"
        printf '\n// unauthorized synthetic execution-source drift\n'
    } | git -C "$repository" hash-object -w --stdin
)
production_index="$temporary/production.index"
GIT_INDEX_FILE="$production_index" \
    git -C "$repository" read-tree "$promotion_revision^{tree}"
GIT_INDEX_FILE="$production_index" \
    git -C "$repository" update-index --add --cacheinfo \
        "100644,$production_blob,$production_path"
production_tree=$(
    GIT_INDEX_FILE="$production_index" git -C "$repository" write-tree
)
production_drift=$(commit_tree \
    "$production_tree" "$subject_revision" \
    'synthetic unauthorized execution-source drift')
expect_rejection \
    execution-source-drift \
    'unexpected delta; audited execution source may have drifted' \
    "$validator" --source-only "$production_drift" "$repository"

wrong_qualification_blob=$(
    {
        printf '%s\n' \
            'pub const QUALIFIED_EXACT_SEARCH_QUALIFICATION: super::QualifiedExactSearchQualification =' \
            '    super::QualifiedExactSearchQualification::Qualified {' \
            '        bundle_sha256: [0x5a; 32],' \
            '    };'
    } | git -C "$repository" hash-object -w --stdin
)
qualification_index="$temporary/qualification.index"
GIT_INDEX_FILE="$qualification_index" \
    git -C "$repository" read-tree "$promotion_revision^{tree}"
GIT_INDEX_FILE="$qualification_index" \
    git -C "$repository" update-index --add --cacheinfo \
        "100644,$wrong_qualification_blob,$qualification_path"
wrong_qualification_tree=$(
    GIT_INDEX_FILE="$qualification_index" git -C "$repository" write-tree
)
wrong_qualification=$(commit_tree \
    "$wrong_qualification_tree" "$subject_revision" \
    'synthetic arbitrary bundle authorization')
expect_rejection \
    arbitrary-bundle-authorization \
    'not the canonical bundle authorization' \
    "$validator" --source-only "$wrong_qualification" "$repository"

stale_bundle="$temporary/stale-bundle"
mkdir -- "$stale_bundle"
printf '%s\n' \
    'schema	fre-qualified-exact-qualification-bundle-v1' \
    "subject_revision	$subject_revision" \
    > "$stale_bundle/qualification-bundle-v1.tsv"
expect_rejection \
    stale-bundle \
    'qualification bundle differs from its external SHA-256' \
    "$validator" "$promotion_revision" "$stale_bundle" "$repository"

if [ -n "${FRE_JIT_CANONICAL_BUNDLE_ROOT:-}" ]; then
    "$validator" \
        "$promotion_revision" "$FRE_JIT_CANONICAL_BUNDLE_ROOT" "$repository"
fi

echo "verified: promotion rejects non-Q parents, source drift, arbitrary authorization, and stale bundles"
