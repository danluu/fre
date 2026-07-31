#!/bin/bash -p
set -Eeuo pipefail

export LC_ALL=C
export TZ=UTC
umask 077
export PATH=/usr/bin:/bin
hash -r
while IFS= read -r variable; do
    unset "$variable"
done < <(compgen -A variable GIT_)
unset BASH_ENV ENV CDPATH LD_PRELOAD LD_LIBRARY_PATH \
    DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH \
    PYTHONHOME PYTHONPATH PYTHONINSPECT PYTHONSTARTUP \
    TMP TEMP TMPDIR
export GIT_NO_REPLACE_OBJECTS=1
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null

die() {
    printf 'linux-search-private-row-test: %s\n' "$*" >&2
    exit 1
}

[[ $# -eq 2 ]] || {
    printf 'usage: test_promotion_delta.sh REPOSITORY CANDIDATE\n' >&2
    exit 2
}
repository=$1
candidate=$2
[[ $repository == /* && -d $repository && ! -L $repository ]] ||
    die "repository must be an absolute non-symlink directory"
repository=$(CDPATH= cd -P -- "$repository" && pwd -P)
[[ $(git -C "$repository" rev-parse --verify "$candidate^{commit}") == "$candidate" ]] ||
    die "candidate does not resolve exactly"

script_dir=$(CDPATH= cd -P -- "$(dirname -- "$0")" && pwd -P)
verifier=$script_dir/verify-promotion-delta.sh
tool=$script_dir/source_row_tool.py
atom=crates/fre-aot-static-runtime/src/search_support/private_rows.rs
production_atom=crates/fre-aot-static-runtime/src/search_support/production_rows.rs
support=crates/fre-aot-static-runtime/src/search_support.rs
routing=crates/fre-aot-static-runtime/src/search_linked/mod.rs

temporary=$(/usr/bin/mktemp -d \
    /private/tmp/fre-linux-search-private-row-test.XXXXXX) ||
    die "cannot create private test directory"
case $temporary in
    /private/tmp/fre-linux-search-private-row-test.[A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9]) ;;
    *) die "mktemp returned a path outside the test namespace" ;;
esac
cleanup() {
    local status=$?
    /bin/chmod -R u+w -- "$temporary" 2>/dev/null || :
    /bin/rm -rf -- "$temporary"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

git clone --quiet --shared --no-checkout "$repository" "$temporary/repository" ||
    die "cannot create private synthetic repository"

proposal=$temporary/source-row-proposal.tsv
{
    printf 'schema\tfre-aot-linux-search-span-source-row-proposal-v1\n'
    printf 'promotion_state\tproposal-only\n'
    printf 'table_target\tprivate-qualification-input\n'
    printf 'runtime_authority\tabsent\n'
    printf 'selector\t7\n'
    printf 'qualification_field_count\t12\n'
    printf 'live_literal_bytes\t16\n'
    identity=0101010101010101010101010101010101010101010101010101010101010101
    for field in \
        manifest_identity semantic_binding_identity literal_identity \
        kir_identity artifact_identity binding_identity compile_identity \
        object_identity receipt_identity expectation_identity payload_identity; do
        printf '%s\t%s\n' "$field" "$identity"
    done
} > "$proposal"
/bin/chmod 0600 "$proposal"
proposal_sha=$(/usr/bin/python3 -I -B "$tool" sha256 "$proposal") ||
    die "synthetic canonical proposal was refused"

/usr/bin/python3 -I -B "$tool" \
    render-private-module "$proposal" > "$temporary/promoted-private-rows.rs" ||
    die "cannot render synthetic promoted module"

commit_with_atom() {
    local parent=$1
    local message=$2
    local atom_source=$3
    local extra_path=${4:-}
    local extra_source=${5:-}
    local atom_blob extra_blob tree
    git -C "$temporary/repository" read-tree "$parent"
    atom_blob=$(git -C "$temporary/repository" hash-object -w "$atom_source")
    git -C "$temporary/repository" update-index \
        --add --cacheinfo 100644 "$atom_blob" "$atom"
    if [[ -n $extra_path ]]; then
        extra_blob=$(git -C "$temporary/repository" hash-object -w "$extra_source")
        git -C "$temporary/repository" update-index \
            --add --cacheinfo 100644 "$extra_blob" "$extra_path"
    fi
    tree=$(git -C "$temporary/repository" write-tree)
    printf '%s\n' "$message" |
        env \
            GIT_AUTHOR_NAME='FRE private-row tamper test' \
            GIT_AUTHOR_EMAIL='private-row-test@example.invalid' \
            GIT_AUTHOR_DATE='2001-01-01T00:00:00Z' \
            GIT_COMMITTER_NAME='FRE private-row tamper test' \
            GIT_COMMITTER_EMAIL='private-row-test@example.invalid' \
            GIT_COMMITTER_DATE='2001-01-01T00:00:00Z' \
            git -C "$temporary/repository" commit-tree "$tree" -p "$parent"
}

exact_promoted=$(commit_with_atom \
    "$candidate" "synthetic exact private row" \
    "$temporary/promoted-private-rows.rs")
"$verifier" \
    "$temporary/repository" "$candidate" "$exact_promoted" \
    "$proposal" "$proposal_sha" > "$temporary/exact.stdout" ||
    die "verifier refused the exact one-atom promotion"

rejections=0
expect_rejection() {
    local name=$1
    shift
    if "$@" > "$temporary/$name.stdout" 2> "$temporary/$name.stderr"; then
        die "verifier accepted adversarial case: $name"
    fi
    rejections=$((rejections + 1))
}

wrong_sha=0${proposal_sha:1}
[[ $wrong_sha != "$proposal_sha" ]] || wrong_sha=1${proposal_sha:1}
expect_rejection wrong-proposal-identity \
    "$verifier" \
    "$temporary/repository" "$candidate" "$exact_promoted" \
    "$proposal" "$wrong_sha"

cp -- "$temporary/promoted-private-rows.rs" "$temporary/noncanonical-private-rows.rs"
printf '\n// unreviewed private-table mutation\n' \
    >> "$temporary/noncanonical-private-rows.rs"
noncanonical_promoted=$(commit_with_atom \
    "$candidate" "synthetic noncanonical row" \
    "$temporary/noncanonical-private-rows.rs")
expect_rejection noncanonical-private-module \
    "$verifier" \
    "$temporary/repository" "$candidate" "$noncanonical_promoted" \
    "$proposal" "$proposal_sha"

git -C "$temporary/repository" cat-file blob "$candidate:$support" \
    > "$temporary/tampered-support.rs"
printf '\n// adversarial production-support delta\n' \
    >> "$temporary/tampered-support.rs"
support_promoted=$(commit_with_atom \
    "$candidate" "synthetic support mutation" \
    "$temporary/promoted-private-rows.rs" \
    "$support" "$temporary/tampered-support.rs")
expect_rejection production-support-path \
    "$verifier" \
    "$temporary/repository" "$candidate" "$support_promoted" \
    "$proposal" "$proposal_sha"

git -C "$temporary/repository" cat-file blob "$candidate:$production_atom" \
    > "$temporary/tampered-production-rows.rs"
printf '\n// adversarial production-authority delta\n' \
    >> "$temporary/tampered-production-rows.rs"
production_promoted=$(commit_with_atom \
    "$candidate" "synthetic production atom mutation" \
    "$temporary/promoted-private-rows.rs" \
    "$production_atom" "$temporary/tampered-production-rows.rs")
expect_rejection production-authority-path \
    "$verifier" \
    "$temporary/repository" "$candidate" "$production_promoted" \
    "$proposal" "$proposal_sha"

git -C "$temporary/repository" cat-file blob "$candidate:$routing" \
    > "$temporary/tampered-routing.rs"
printf '\n// adversarial production-routing delta\n' \
    >> "$temporary/tampered-routing.rs"
routing_promoted=$(commit_with_atom \
    "$candidate" "synthetic routing mutation" \
    "$temporary/promoted-private-rows.rs" \
    "$routing" "$temporary/tampered-routing.rs")
expect_rejection production-routing-path \
    "$verifier" \
    "$temporary/repository" "$candidate" "$routing_promoted" \
    "$proposal" "$proposal_sha"

candidate_tree=$(git -C "$temporary/repository" rev-parse "$candidate^{tree}")
intermediate=$(
    printf 'synthetic intermediate\n' |
        env \
            GIT_AUTHOR_NAME='FRE private-row tamper test' \
            GIT_AUTHOR_EMAIL='private-row-test@example.invalid' \
            GIT_AUTHOR_DATE='2001-01-02T00:00:00Z' \
            GIT_COMMITTER_NAME='FRE private-row tamper test' \
            GIT_COMMITTER_EMAIL='private-row-test@example.invalid' \
            GIT_COMMITTER_DATE='2001-01-02T00:00:00Z' \
            git -C "$temporary/repository" \
                commit-tree "$candidate_tree" -p "$candidate"
)
indirect_promoted=$(commit_with_atom \
    "$intermediate" "synthetic indirect row" \
    "$temporary/promoted-private-rows.rs")
expect_rejection indirect-promotion \
    "$verifier" \
    "$temporary/repository" "$candidate" "$indirect_promoted" \
    "$proposal" "$proposal_sha"

cp -- "$proposal" "$temporary/noncanonical-proposal.tsv"
printf 'unexpected\tfield\n' >> "$temporary/noncanonical-proposal.tsv"
/bin/chmod 0600 "$temporary/noncanonical-proposal.tsv"
expect_rejection noncanonical-proposal \
    "$verifier" \
    "$temporary/repository" "$candidate" "$exact_promoted" \
    "$temporary/noncanonical-proposal.tsv" "$proposal_sha"

[[ $rejections -eq 7 ]] ||
    die "tamper suite did not exercise exactly seven rejection classes"
printf 'linux-search-private-row-test: PASS rejections=%s\n' "$rejections"
