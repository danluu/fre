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
    printf 'linux-search-private-row-promotion: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat >&2 <<'EOF'
usage: verify-promotion-delta.sh REPOSITORY CANDIDATE PROMOTED SOURCE_ROW_PROPOSAL EXPECTED_PROPOSAL_SHA256

Verify a first private Linux Search qualification-row promotion. CANDIDATE
must be the direct and only parent of PROMOTED. The expected proposal digest
must come from the independent measurement/review boundary. The complete
promotion delta must be the canonical private_rows.rs rendering and no other
path; production rows, production/private routing, features, and tooling
therefore remain byte-identical to CANDIDATE.
EOF
    exit 2
}

[[ $# -eq 5 ]] || usage
repository_arg=$1
candidate=$2
promoted=$3
proposal=$4
expected_proposal_sha256=$5

[[ $repository_arg == /* && -d $repository_arg && ! -L $repository_arg ]] ||
    die "repository must be an absolute existing non-symlink directory"
repository=$(CDPATH= cd -P -- "$repository_arg" && pwd -P) ||
    die "cannot resolve repository"
[[ $repository == "$repository_arg" ]] ||
    die "repository path must already be physical and canonical"

[[ $proposal == /* && -f $proposal && ! -L $proposal ]] ||
    die "proposal must be an absolute regular non-symlink path"
proposal_parent=$(CDPATH= cd -P -- "$(dirname -- "$proposal")" && pwd -P) ||
    die "cannot resolve proposal parent"
[[ $proposal == "$proposal_parent/$(basename -- "$proposal")" ]] ||
    die "proposal path must already be physical and canonical"

case $expected_proposal_sha256 in
    *[!0-9a-f]* | "") die "expected proposal SHA-256 is not lowercase hexadecimal" ;;
esac
[[ ${#expected_proposal_sha256} -eq 64 &&
    $expected_proposal_sha256 != \
        0000000000000000000000000000000000000000000000000000000000000000 ]] ||
    die "expected proposal SHA-256 must be one nonzero 32-byte identity"

for commit in "$candidate" "$promoted"; do
    case $commit in
        *[!0-9a-f]* | "") die "commit identity is not lowercase hexadecimal" ;;
    esac
    [[ ${#commit} -eq 40 ]] || die "commit identity is not exactly 20 bytes"
    resolved=$(git -C "$repository" rev-parse --verify "$commit^{commit}" 2>/dev/null) ||
        die "repository does not contain commit $commit"
    [[ $resolved == "$commit" ]] || die "commit did not resolve exactly: $commit"
done
[[ $candidate != "$promoted" ]] ||
    die "candidate and promoted commits must differ"
[[ $(git -C "$repository" show -s --format=%P "$promoted") == "$candidate" ]] ||
    die "promoted commit must have candidate as its only direct parent"
[[ $(git -C "$repository" rev-parse --is-shallow-repository) == false ]] ||
    die "promotion verification requires complete history"
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

tool_path=crates/fre-aot-static-runtime/qualification/linux-search-private-rows/source_row_tool.py
verifier_path=crates/fre-aot-static-runtime/qualification/linux-search-private-rows/verify-promotion-delta.sh
atom=crates/fre-aot-static-runtime/src/search_support/private_rows.rs
production_atom=crates/fre-aot-static-runtime/src/search_support/production_rows.rs
support_source=crates/fre-aot-static-runtime/src/search_support.rs
routing_source=crates/fre-aot-static-runtime/src/search_linked/mod.rs

temporary=$(/usr/bin/mktemp -d \
    /private/tmp/fre-linux-search-private-row-promotion.XXXXXX) ||
    die "cannot create private verification directory"
case $temporary in
    /private/tmp/fre-linux-search-private-row-promotion.[A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9]) ;;
    *) die "mktemp returned a path outside the exact private namespace" ;;
esac
cleanup() {
    local status=$?
    /bin/rm -f -- \
        "$temporary/candidate-tool.py" \
        "$temporary/candidate-verifier.sh" \
        "$temporary/candidate-private-rows.rs" \
        "$temporary/promoted-private-rows.rs" \
        "$temporary/candidate-production-rows.rs" \
        "$temporary/promoted-production-rows.rs" \
        "$temporary/candidate-search-support.rs" \
        "$temporary/promoted-search-support.rs" \
        "$temporary/candidate-search-routing.rs" \
        "$temporary/promoted-search-routing.rs" \
        "$temporary/expected-empty.rs" \
        "$temporary/expected-promoted.rs" \
        "$temporary/changed-paths" \
        "$temporary/expected-changed-paths"
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

extract_blob "$candidate" "$tool_path" 100755 262144 \
    "$temporary/candidate-tool.py"
extract_blob "$candidate" "$verifier_path" 100755 262144 \
    "$temporary/candidate-verifier.sh"
/usr/bin/cmp -s "$running_verifier" "$temporary/candidate-verifier.sh" ||
    die "running verifier is not the candidate's exact trusted blob"

extract_blob "$candidate" "$atom" 100644 262144 \
    "$temporary/candidate-private-rows.rs"
extract_blob "$promoted" "$atom" 100644 262144 \
    "$temporary/promoted-private-rows.rs"
extract_blob "$candidate" "$production_atom" 100644 262144 \
    "$temporary/candidate-production-rows.rs"
extract_blob "$promoted" "$production_atom" 100644 262144 \
    "$temporary/promoted-production-rows.rs"
extract_blob "$candidate" "$support_source" 100644 1048576 \
    "$temporary/candidate-search-support.rs"
extract_blob "$promoted" "$support_source" 100644 1048576 \
    "$temporary/promoted-search-support.rs"
extract_blob "$candidate" "$routing_source" 100644 2097152 \
    "$temporary/candidate-search-routing.rs"
extract_blob "$promoted" "$routing_source" 100644 2097152 \
    "$temporary/promoted-search-routing.rs"
/usr/bin/cmp -s \
    "$temporary/candidate-production-rows.rs" \
    "$temporary/promoted-production-rows.rs" ||
    die "isolated production authority atom changed in the private promotion"
/usr/bin/cmp -s \
    "$temporary/candidate-search-support.rs" \
    "$temporary/promoted-search-support.rs" ||
    die "production/private support source changed in the promotion"
/usr/bin/cmp -s \
    "$temporary/candidate-search-routing.rs" \
    "$temporary/promoted-search-routing.rs" ||
    die "production/private routing source changed in the promotion"
support_sha256=$(
    /usr/bin/python3 -I -B "$temporary/candidate-tool.py" \
        audit-support-source \
        "$temporary/candidate-search-support.rs" \
        "$temporary/candidate-production-rows.rs"
) || die "candidate production-empty/private-constructor source shape was refused"

/usr/bin/python3 -I -B "$temporary/candidate-tool.py" \
    render-private-module > "$temporary/expected-empty.rs" ||
    die "candidate renderer could not produce the closed empty module"
/usr/bin/cmp -s \
    "$temporary/candidate-private-rows.rs" "$temporary/expected-empty.rs" ||
    die "candidate private table is not the canonical empty state"

/usr/bin/python3 -I -B "$temporary/candidate-tool.py" \
    render-reviewed-private-module \
    "$proposal" "$expected_proposal_sha256" \
    > "$temporary/expected-promoted.rs" ||
    die "candidate renderer refused the source-row proposal or its reviewed identity"
/usr/bin/cmp -s \
    "$temporary/promoted-private-rows.rs" "$temporary/expected-promoted.rs" ||
    die "promoted private table is not the exact canonical proposal rendering"

git -C "$repository" diff --no-ext-diff --name-only --no-renames -z \
    "$candidate" "$promoted" > "$temporary/changed-paths" ||
    die "cannot inspect promotion path delta"
printf '%s\0' "$atom" > "$temporary/expected-changed-paths"
/usr/bin/cmp -s \
    "$temporary/changed-paths" "$temporary/expected-changed-paths" ||
    die "promotion changed a path other than the private row module"

printf '%s\n' \
    "linux-search-private-row-promotion: PASS" \
    "candidate=$candidate" \
    "promoted=$promoted" \
    "proposal_sha256=$expected_proposal_sha256" \
    "unchanged_support_sha256=$support_sha256" \
    "unchanged_production_atom=$production_atom" \
    "changed_path=$atom"
