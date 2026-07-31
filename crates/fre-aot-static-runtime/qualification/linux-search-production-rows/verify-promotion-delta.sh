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
    printf 'linux-search-production-row-promotion: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat >&2 <<'EOF'
usage: verify-promotion-delta.sh REPOSITORY CANDIDATE PROMOTED PRODUCTION_AUTHORIZATION EXPECTED_AUTHORIZATION_SHA256

Verify the first production Linux Search qualification-row promotion.
CANDIDATE must itself be the exact one-file private-row promotion named by the
authorization and the exact commit on which fresh post-private evidence was
reviewed. PROMOTED must have CANDIDATE as its only direct parent and change
exactly production_rows.rs to the candidate renderer's one-row projection.
The expected authorization digest must come from the external review boundary.
EOF
    exit 2
}

[[ $# -eq 5 ]] || usage
repository_arg=$1
candidate=$2
promoted=$3
authorization=$4
expected_authorization_sha256=$5

[[ $repository_arg == /* && -d $repository_arg && ! -L $repository_arg ]] ||
    die "repository must be an absolute existing non-symlink directory"
repository=$(CDPATH= cd -P -- "$repository_arg" && pwd -P) ||
    die "cannot resolve repository"
[[ $repository == "$repository_arg" ]] ||
    die "repository path must already be physical and canonical"

[[ $authorization == /* && -f $authorization && ! -L $authorization ]] ||
    die "production authorization must be an absolute regular non-symlink path"
authorization_parent=$(
    CDPATH= cd -P -- "$(dirname -- "$authorization")" && pwd -P
) || die "cannot resolve production authorization parent"
[[ $authorization == "$authorization_parent/$(basename -- "$authorization")" ]] ||
    die "production authorization path must already be physical and canonical"

case $expected_authorization_sha256 in
    *[!0-9a-f]* | "")
        die "expected production authorization SHA-256 is not lowercase hexadecimal"
        ;;
esac
[[ ${#expected_authorization_sha256} -eq 64 &&
    $expected_authorization_sha256 != \
        0000000000000000000000000000000000000000000000000000000000000000 ]] ||
    die "expected production authorization SHA-256 must be one nonzero 32-byte identity"

for commit in "$candidate" "$promoted"; do
    case $commit in
        *[!0-9a-f]* | "") die "commit identity is not lowercase hexadecimal" ;;
    esac
    [[ ${#commit} -eq 40 ]] || die "commit identity is not exactly 20 bytes"
    resolved=$(git -C "$repository" rev-parse --verify "$commit^{commit}" 2>/dev/null) ||
        die "repository does not contain commit $commit"
    [[ $resolved == "$commit" ]] ||
        die "commit did not resolve exactly: $commit"
done
[[ $candidate != "$promoted" ]] ||
    die "candidate and promoted commits must differ"
[[ $(git -C "$repository" show -s --format=%P "$promoted") == "$candidate" ]] ||
    die "production promotion must have candidate as its only direct parent"
[[ $(git -C "$repository" rev-parse --is-shallow-repository) == false ]] ||
    die "production promotion verification requires complete history"
grafts=$(git -C "$repository" rev-parse --git-path info/grafts) ||
    die "cannot resolve graft path"
case $grafts in
    /*) ;;
    *) grafts=$repository/$grafts ;;
esac
[[ ! -e $grafts && ! -L $grafts ]] ||
    die "repository contains a graft history override"
[[ -z $(git -C "$repository" for-each-ref \
    --format='%(refname)' refs/replace | sed -n '1p') ]] ||
    die "repository contains a replace-ref history override"

script_dir=$(CDPATH= cd -P -- "$(dirname -- "$0")" && pwd -P) ||
    die "cannot resolve verifier directory"
running_verifier=$script_dir/verify-promotion-delta.sh
[[ -f $running_verifier && ! -L $running_verifier ]] ||
    die "running verifier must be a regular non-symlink file"

tool_path=crates/fre-aot-static-runtime/qualification/linux-search-production-rows/production_row_tool.py
verifier_path=crates/fre-aot-static-runtime/qualification/linux-search-production-rows/verify-promotion-delta.sh
production_atom=crates/fre-aot-static-runtime/src/search_support/production_rows.rs
private_atom=crates/fre-aot-static-runtime/src/search_support/private_rows.rs
support_source=crates/fre-aot-static-runtime/src/search_support.rs
routing_source=crates/fre-aot-static-runtime/src/search_linked/mod.rs
mapped_verifier_source=crates/fre-aot-static-runtime/src/search_linked/linux_aarch64.rs
call_contract_source=crates/fre-aot-static-runtime/src/search_call.rs
expected_contract_source=crates/fre-aot-static-runtime/src/search_expected.rs
runtime_facade_source=crates/fre-aot-static-runtime/src/lib.rs
identity_contract_source=crates/fre-aot-search-contract/src/lib.rs

temporary=$(/usr/bin/mktemp -d \
    /private/tmp/fre-linux-search-production-row-promotion.XXXXXX) ||
    die "cannot create private verification directory"
case $temporary in
    /private/tmp/fre-linux-search-production-row-promotion.[A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9]) ;;
    *) die "mktemp returned a path outside the exact private namespace" ;;
esac
cleanup() {
    local status=$?
    /bin/rm -f -- \
        "$temporary/candidate-tool.py" \
        "$temporary/candidate-verifier.sh" \
        "$temporary/authorization-bindings" \
        "$temporary/private-candidate-private-rows.rs" \
        "$temporary/candidate-private-rows.rs" \
        "$temporary/promoted-private-rows.rs" \
        "$temporary/candidate-production-rows.rs" \
        "$temporary/promoted-production-rows.rs" \
        "$temporary/candidate-search-support.rs" \
        "$temporary/promoted-search-support.rs" \
        "$temporary/expected-empty-private.rs" \
        "$temporary/expected-private.rs" \
        "$temporary/expected-empty-production.rs" \
        "$temporary/expected-production.rs" \
        "$temporary/private-changed-paths" \
        "$temporary/production-changed-paths" \
        "$temporary/expected-private-changed-paths" \
        "$temporary/expected-production-changed-paths" \
        "$temporary/candidate-routing.rs" \
        "$temporary/promoted-routing.rs" \
        "$temporary/candidate-mapped-verifier.rs" \
        "$temporary/promoted-mapped-verifier.rs" \
        "$temporary/candidate-call-contract.rs" \
        "$temporary/promoted-call-contract.rs" \
        "$temporary/candidate-expected-contract.rs" \
        "$temporary/promoted-expected-contract.rs" \
        "$temporary/candidate-runtime-facade.rs" \
        "$temporary/promoted-runtime-facade.rs" \
        "$temporary/candidate-identity-contract.rs" \
        "$temporary/promoted-identity-contract.rs"
    /bin/rmdir -- "$temporary" 2>/dev/null || status=1
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

extract_blob() {
    local commit=$1
    local path=$2
    local expected_mode=$3
    local maximum_bytes=$4
    local output=$5
    local entry size
    entry=$(git -C "$repository" ls-tree "$commit" -- "$path") ||
        die "cannot inspect $path at $commit"
    [[ $entry == "$expected_mode blob "*$'\t'"$path" ]] ||
        die "$path at $commit is not one mode-$expected_mode blob"
    size=$(git -C "$repository" cat-file -s "$commit:$path") ||
        die "cannot size $path at $commit"
    [[ $size =~ ^(0|[1-9][0-9]*)$ && $size -le $maximum_bytes ]] ||
        die "$path at $commit exceeds its closed byte bound"
    git -C "$repository" cat-file blob "$commit:$path" > "$output" ||
        die "cannot extract $path at $commit"
}

assert_unchanged_blob() {
    local path=$1
    local maximum_bytes=$2
    local label=$3
    extract_blob "$candidate" "$path" 100644 "$maximum_bytes" \
        "$temporary/candidate-$label.rs"
    extract_blob "$promoted" "$path" 100644 "$maximum_bytes" \
        "$temporary/promoted-$label.rs"
    /usr/bin/cmp -s \
        "$temporary/candidate-$label.rs" "$temporary/promoted-$label.rs" ||
        die "$path changed in the production promotion"
}

extract_blob "$candidate" "$tool_path" 100755 524288 \
    "$temporary/candidate-tool.py"
extract_blob "$candidate" "$verifier_path" 100755 524288 \
    "$temporary/candidate-verifier.sh"
/usr/bin/cmp -s "$running_verifier" "$temporary/candidate-verifier.sh" ||
    die "running verifier is not the candidate's exact trusted blob"

/usr/bin/python3 -I -B "$temporary/candidate-tool.py" \
    verification-bindings \
    "$authorization" "$expected_authorization_sha256" \
    > "$temporary/authorization-bindings" ||
    die "candidate tool refused the reviewed production authorization"
[[ $(/usr/bin/wc -l < "$temporary/authorization-bindings" | tr -d ' ') == 4 ]] ||
    die "candidate tool emitted an ambiguous authorization binding set"
private_candidate=$(sed -n '1p' "$temporary/authorization-bindings")
private_promotion=$(sed -n '2p' "$temporary/authorization-bindings")
post_private_evidence_commit=$(sed -n '3p' "$temporary/authorization-bindings")
post_private_evidence_tree=$(sed -n '4p' "$temporary/authorization-bindings")
[[ $private_promotion == "$candidate" ]] ||
    die "authorization does not name candidate as the private promotion"
[[ $post_private_evidence_commit == "$candidate" ]] ||
    die "post-private evidence is not rooted at candidate"

resolved_private_candidate=$(
    git -C "$repository" rev-parse --verify "$private_candidate^{commit}" 2>/dev/null
) || die "repository does not contain the authorized private candidate"
[[ $resolved_private_candidate == "$private_candidate" ]] ||
    die "authorized private candidate did not resolve exactly"
[[ $(git -C "$repository" show -s --format=%P "$candidate") == "$private_candidate" ]] ||
    die "candidate is not the direct single-parent private promotion"
candidate_tree=$(git -C "$repository" rev-parse "$candidate^{tree}") ||
    die "cannot resolve candidate tree"
[[ $candidate_tree == "$post_private_evidence_tree" ]] ||
    die "post-private evidence tree does not equal candidate's exact tree"

git -C "$repository" diff --no-ext-diff --name-only --no-renames -z \
    "$private_candidate" "$candidate" > "$temporary/private-changed-paths" ||
    die "cannot inspect private promotion path delta"
printf '%s\0' "$private_atom" > "$temporary/expected-private-changed-paths"
/usr/bin/cmp -s \
    "$temporary/private-changed-paths" \
    "$temporary/expected-private-changed-paths" ||
    die "authorized private promotion was not exactly one private-row path"

git -C "$repository" diff --no-ext-diff --name-only --no-renames -z \
    "$candidate" "$promoted" > "$temporary/production-changed-paths" ||
    die "cannot inspect production promotion path delta"
printf '%s\0' "$production_atom" > "$temporary/expected-production-changed-paths"
/usr/bin/cmp -s \
    "$temporary/production-changed-paths" \
    "$temporary/expected-production-changed-paths" ||
    die "production promotion changed a path other than production_rows.rs"

extract_blob "$private_candidate" "$private_atom" 100644 262144 \
    "$temporary/private-candidate-private-rows.rs"
extract_blob "$candidate" "$private_atom" 100644 262144 \
    "$temporary/candidate-private-rows.rs"
extract_blob "$promoted" "$private_atom" 100644 262144 \
    "$temporary/promoted-private-rows.rs"
extract_blob "$candidate" "$production_atom" 100644 262144 \
    "$temporary/candidate-production-rows.rs"
extract_blob "$promoted" "$production_atom" 100644 262144 \
    "$temporary/promoted-production-rows.rs"
extract_blob "$candidate" "$support_source" 100644 1048576 \
    "$temporary/candidate-search-support.rs"
extract_blob "$promoted" "$support_source" 100644 1048576 \
    "$temporary/promoted-search-support.rs"

/usr/bin/cmp -s \
    "$temporary/candidate-private-rows.rs" \
    "$temporary/promoted-private-rows.rs" ||
    die "private qualification row changed in the production promotion"
/usr/bin/cmp -s \
    "$temporary/candidate-search-support.rs" \
    "$temporary/promoted-search-support.rs" ||
    die "production/private support source changed in the production promotion"

support_sha256=$(
    /usr/bin/python3 -I -B "$temporary/candidate-tool.py" \
        audit-support-source \
        "$temporary/candidate-search-support.rs" \
        "$temporary/candidate-production-rows.rs"
) || die "candidate support or empty production atom was refused"

/usr/bin/python3 -I -B "$temporary/candidate-tool.py" \
    render-empty-private-module > "$temporary/expected-empty-private.rs" ||
    die "candidate tool could not render the pre-private empty atom"
/usr/bin/cmp -s \
    "$temporary/private-candidate-private-rows.rs" \
    "$temporary/expected-empty-private.rs" ||
    die "private candidate did not have the canonical empty private atom"

/usr/bin/python3 -I -B "$temporary/candidate-tool.py" \
    render-reviewed-private-module \
    "$authorization" "$expected_authorization_sha256" \
    > "$temporary/expected-private.rs" ||
    die "candidate tool could not derive the reviewed private atom"
/usr/bin/cmp -s \
    "$temporary/candidate-private-rows.rs" "$temporary/expected-private.rs" ||
    die "candidate private atom differs from the authorization-bound row"

/usr/bin/python3 -I -B "$temporary/candidate-tool.py" \
    render-empty-production-module > "$temporary/expected-empty-production.rs" ||
    die "candidate tool could not render the closed empty production atom"
/usr/bin/cmp -s \
    "$temporary/candidate-production-rows.rs" \
    "$temporary/expected-empty-production.rs" ||
    die "candidate production atom is not the canonical empty state"

/usr/bin/python3 -I -B "$temporary/candidate-tool.py" \
    render-reviewed-production-module \
    "$authorization" "$expected_authorization_sha256" \
    > "$temporary/expected-production.rs" ||
    die "candidate tool refused the externally reviewed production authority"
/usr/bin/cmp -s \
    "$temporary/promoted-production-rows.rs" \
    "$temporary/expected-production.rs" ||
    die "promoted production atom is not the exact canonical rendering"

assert_unchanged_blob "$routing_source" 2097152 routing
assert_unchanged_blob "$mapped_verifier_source" 2097152 mapped-verifier
assert_unchanged_blob "$call_contract_source" 1048576 call-contract
assert_unchanged_blob "$expected_contract_source" 1048576 expected-contract
assert_unchanged_blob "$runtime_facade_source" 1048576 runtime-facade
assert_unchanged_blob "$identity_contract_source" 2097152 identity-contract

printf '%s\n' \
    "linux-search-production-row-promotion: PASS" \
    "private_candidate=$private_candidate" \
    "candidate_private_promotion=$candidate" \
    "post_private_evidence_tree=$post_private_evidence_tree" \
    "promoted=$promoted" \
    "production_authorization_sha256=$expected_authorization_sha256" \
    "unchanged_support_sha256=$support_sha256" \
    "changed_path=$production_atom" \
    "protected_private_rows=$private_atom" \
    "protected_routing=$routing_source" \
    "protected_mapped_verifier=$mapped_verifier_source" \
    "protected_tag21_contract=$identity_contract_source"
