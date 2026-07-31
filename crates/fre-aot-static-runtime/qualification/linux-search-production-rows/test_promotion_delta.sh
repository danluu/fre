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
    printf 'linux-search-production-row-test: %s\n' "$*" >&2
    exit 1
}

[[ $# -eq 2 ]] || {
    printf 'usage: test_promotion_delta.sh REPOSITORY CANDIDATE\n' >&2
    exit 2
}
repository=$1
source_candidate=$2
[[ $repository == /* && -d $repository && ! -L $repository ]] ||
    die "repository must be an absolute non-symlink directory"
repository=$(CDPATH= cd -P -- "$repository" && pwd -P)
[[ $(git -C "$repository" rev-parse \
    --verify "$source_candidate^{commit}") == "$source_candidate" ]] ||
    die "candidate does not resolve exactly"

script_dir=$(CDPATH= cd -P -- "$(dirname -- "$0")" && pwd -P)
verifier=$script_dir/verify-promotion-delta.sh
tool=$script_dir/production_row_tool.py
private_tool=$script_dir/../linux-search-private-rows/source_row_tool.py
production_atom=crates/fre-aot-static-runtime/src/search_support/production_rows.rs
private_atom=crates/fre-aot-static-runtime/src/search_support/private_rows.rs
routing=crates/fre-aot-static-runtime/src/search_linked/mod.rs
mapped_verifier=crates/fre-aot-static-runtime/src/search_linked/linux_aarch64.rs
identity_contract=crates/fre-aot-search-contract/src/lib.rs

temporary=$(/usr/bin/mktemp -d \
    /private/tmp/fre-linux-search-production-row-test.XXXXXX) ||
    die "cannot create private test directory"
case $temporary in
    /private/tmp/fre-linux-search-production-row-test.[A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9]) ;;
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
proposal_sha=$(/usr/bin/python3 -I -B "$private_tool" sha256 "$proposal") ||
    die "synthetic private proposal was refused"
/usr/bin/python3 -I -B "$private_tool" \
    render-reviewed-private-module "$proposal" "$proposal_sha" \
    > "$temporary/private-rows.rs" ||
    die "cannot render synthetic private atom"

commit_with_atom() {
    local parent=$1
    local message=$2
    local atom_path=$3
    local atom_source=$4
    local extra_path=${5:-}
    local extra_source=${6:-}
    local atom_blob extra_blob tree
    git -C "$temporary/repository" read-tree "$parent"
    atom_blob=$(git -C "$temporary/repository" hash-object -w "$atom_source")
    git -C "$temporary/repository" update-index \
        --add --cacheinfo 100644 "$atom_blob" "$atom_path"
    if [[ -n $extra_path ]]; then
        extra_blob=$(git -C "$temporary/repository" hash-object -w "$extra_source")
        git -C "$temporary/repository" update-index \
            --add --cacheinfo 100644 "$extra_blob" "$extra_path"
    fi
    tree=$(git -C "$temporary/repository" write-tree)
    printf '%s\n' "$message" |
        env \
            GIT_AUTHOR_NAME='FRE production-row tamper test' \
            GIT_AUTHOR_EMAIL='production-row-test@example.invalid' \
            GIT_AUTHOR_DATE='2001-01-01T00:00:00Z' \
            GIT_COMMITTER_NAME='FRE production-row tamper test' \
            GIT_COMMITTER_EMAIL='production-row-test@example.invalid' \
            GIT_COMMITTER_DATE='2001-01-01T00:00:00Z' \
            git -C "$temporary/repository" commit-tree "$tree" -p "$parent"
}

private_promotion=$(commit_with_atom \
    "$source_candidate" "synthetic exact private row" \
    "$private_atom" "$temporary/private-rows.rs")
private_tree=$(git -C "$temporary/repository" \
    rev-parse "$private_promotion^{tree}")

write_authorization() {
    local output=$1
    local private_candidate_value=$2
    local private_promotion_value=$3
    local post_private_commit_value=$4
    local post_private_tree_value=$5
    {
        printf 'schema\tfre-aot-linux-search-span-production-authorization-v1\n'
        printf 'authorization_state\treviewed-production-authorization\n'
        printf 'table_target\tproduction-runtime-authority\n'
        printf 'runtime_authority\tsource-reviewed\n'
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
        printf 'private_candidate_commit\t%s\n' "$private_candidate_value"
        printf 'private_promotion_commit\t%s\n' "$private_promotion_value"
        printf 'private_source_row_proposal_sha256\t%s\n' "$proposal_sha"
        printf 'post_private_evidence_commit\t%s\n' "$post_private_commit_value"
        printf 'post_private_evidence_tree\t%s\n' "$post_private_tree_value"
        printf 'post_private_evidence_manifest_sha256\t%s\n' \
            1111111111111111111111111111111111111111111111111111111111111111
        printf 'post_private_evidence_receipt_sha256\t%s\n' \
            2222222222222222222222222222222222222222222222222222222222222222
        printf 'post_private_evidence_bundle_sha256\t%s\n' \
            3333333333333333333333333333333333333333333333333333333333333333
        printf 'post_private_evidence_final_image_sha256\t%s\n' \
            4444444444444444444444444444444444444444444444444444444444444444
    } > "$output"
    /bin/chmod 0600 "$output"
}

authorization=$temporary/production-authorization.tsv
write_authorization \
    "$authorization" "$source_candidate" "$private_promotion" \
    "$private_promotion" "$private_tree"
authorization_sha=$(/usr/bin/python3 -I -B "$tool" sha256 "$authorization") ||
    die "synthetic production authorization was refused"
/usr/bin/python3 -I -B "$tool" \
    render-reviewed-production-module \
    "$authorization" "$authorization_sha" \
    > "$temporary/production-rows.rs" ||
    die "cannot render synthetic production atom"

exact_promoted=$(commit_with_atom \
    "$private_promotion" "synthetic exact production row" \
    "$production_atom" "$temporary/production-rows.rs")
"$verifier" \
    "$temporary/repository" "$private_promotion" "$exact_promoted" \
    "$authorization" "$authorization_sha" > "$temporary/exact.stdout" ||
    die "verifier refused the exact two-stage authority chain"

rejections=0
expect_rejection() {
    local name=$1
    shift
    if "$@" > "$temporary/$name.stdout" 2> "$temporary/$name.stderr"; then
        die "verifier accepted adversarial case: $name"
    fi
    rejections=$((rejections + 1))
}

wrong_sha=0${authorization_sha:1}
[[ $wrong_sha != "$authorization_sha" ]] ||
    wrong_sha=1${authorization_sha:1}
expect_rejection wrong-authorization-identity \
    "$verifier" \
    "$temporary/repository" "$private_promotion" "$exact_promoted" \
    "$authorization" "$wrong_sha"

cp -- "$temporary/production-rows.rs" \
    "$temporary/noncanonical-production-rows.rs"
printf '\n// unreviewed production mutation\n' \
    >> "$temporary/noncanonical-production-rows.rs"
noncanonical_promoted=$(commit_with_atom \
    "$private_promotion" "synthetic noncanonical production row" \
    "$production_atom" "$temporary/noncanonical-production-rows.rs")
expect_rejection noncanonical-production-module \
    "$verifier" \
    "$temporary/repository" "$private_promotion" "$noncanonical_promoted" \
    "$authorization" "$authorization_sha"

git -C "$temporary/repository" cat-file blob "$private_promotion:$routing" \
    > "$temporary/tampered-routing.rs"
printf '\n// adversarial production-routing delta\n' \
    >> "$temporary/tampered-routing.rs"
routing_promoted=$(commit_with_atom \
    "$private_promotion" "synthetic routing mutation" \
    "$production_atom" "$temporary/production-rows.rs" \
    "$routing" "$temporary/tampered-routing.rs")
expect_rejection routing-path \
    "$verifier" \
    "$temporary/repository" "$private_promotion" "$routing_promoted" \
    "$authorization" "$authorization_sha"

cp -- "$temporary/private-rows.rs" "$temporary/tampered-private-rows.rs"
printf '\n// adversarial private-authority delta\n' \
    >> "$temporary/tampered-private-rows.rs"
private_mutation_promoted=$(commit_with_atom \
    "$private_promotion" "synthetic private mutation" \
    "$production_atom" "$temporary/production-rows.rs" \
    "$private_atom" "$temporary/tampered-private-rows.rs")
expect_rejection private-row-path \
    "$verifier" \
    "$temporary/repository" "$private_promotion" \
    "$private_mutation_promoted" "$authorization" "$authorization_sha"

git -C "$temporary/repository" \
    cat-file blob "$private_promotion:$mapped_verifier" \
    > "$temporary/tampered-mapped-verifier.rs"
printf '\n// adversarial mapped-verifier delta\n' \
    >> "$temporary/tampered-mapped-verifier.rs"
mapped_promoted=$(commit_with_atom \
    "$private_promotion" "synthetic mapped verifier mutation" \
    "$production_atom" "$temporary/production-rows.rs" \
    "$mapped_verifier" "$temporary/tampered-mapped-verifier.rs")
expect_rejection mapped-verifier-path \
    "$verifier" \
    "$temporary/repository" "$private_promotion" "$mapped_promoted" \
    "$authorization" "$authorization_sha"

git -C "$temporary/repository" \
    cat-file blob "$private_promotion:$identity_contract" \
    > "$temporary/tampered-identity-contract.rs"
printf '\n// adversarial tag21/VL16 contract delta\n' \
    >> "$temporary/tampered-identity-contract.rs"
contract_promoted=$(commit_with_atom \
    "$private_promotion" "synthetic identity contract mutation" \
    "$production_atom" "$temporary/production-rows.rs" \
    "$identity_contract" "$temporary/tampered-identity-contract.rs")
expect_rejection tag21-identity-contract-path \
    "$verifier" \
    "$temporary/repository" "$private_promotion" "$contract_promoted" \
    "$authorization" "$authorization_sha"

candidate_tree=$(git -C "$temporary/repository" \
    rev-parse "$private_promotion^{tree}")
intermediate=$(
    printf 'synthetic intermediate\n' |
        env \
            GIT_AUTHOR_NAME='FRE production-row tamper test' \
            GIT_AUTHOR_EMAIL='production-row-test@example.invalid' \
            GIT_AUTHOR_DATE='2001-01-02T00:00:00Z' \
            GIT_COMMITTER_NAME='FRE production-row tamper test' \
            GIT_COMMITTER_EMAIL='production-row-test@example.invalid' \
            GIT_COMMITTER_DATE='2001-01-02T00:00:00Z' \
            git -C "$temporary/repository" \
                commit-tree "$candidate_tree" -p "$private_promotion"
)
indirect_promoted=$(commit_with_atom \
    "$intermediate" "synthetic indirect production row" \
    "$production_atom" "$temporary/production-rows.rs")
expect_rejection indirect-production-promotion \
    "$verifier" \
    "$temporary/repository" "$private_promotion" "$indirect_promoted" \
    "$authorization" "$authorization_sha"

wrong_tree=0${private_tree:1}
[[ $wrong_tree != "$private_tree" ]] || wrong_tree=1${private_tree:1}
stale_authorization=$temporary/stale-production-authorization.tsv
write_authorization \
    "$stale_authorization" "$source_candidate" "$private_promotion" \
    "$private_promotion" "$wrong_tree"
stale_authorization_sha=$(
    /usr/bin/python3 -I -B "$tool" sha256 "$stale_authorization"
) || die "synthetic stale-tree authorization was unexpectedly malformed"
expect_rejection stale-post-private-tree \
    "$verifier" \
    "$temporary/repository" "$private_promotion" "$exact_promoted" \
    "$stale_authorization" "$stale_authorization_sha"

wrong_candidate_authorization=$temporary/wrong-candidate-authorization.tsv
wrong_candidate=0${source_candidate:1}
[[ $wrong_candidate != "$source_candidate" ]] ||
    wrong_candidate=1${source_candidate:1}
write_authorization \
    "$wrong_candidate_authorization" "$wrong_candidate" "$private_promotion" \
    "$private_promotion" "$private_tree"
wrong_candidate_authorization_sha=$(
    /usr/bin/python3 -I -B "$tool" sha256 "$wrong_candidate_authorization"
) || die "synthetic wrong-candidate authorization was unexpectedly malformed"
expect_rejection wrong-private-parent \
    "$verifier" \
    "$temporary/repository" "$private_promotion" "$exact_promoted" \
    "$wrong_candidate_authorization" "$wrong_candidate_authorization_sha"

[[ $rejections -eq 9 ]] ||
    die "tamper suite did not exercise exactly nine rejection classes"
printf 'linux-search-production-row-test: PASS rejections=%s\n' "$rejections"
