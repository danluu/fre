#!/bin/bash -p
set -Eeuo pipefail

export LC_ALL=C
export TZ=UTC
umask 077
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
hash -r
while IFS= read -r variable; do
    unset "$variable"
done < <(compgen -A variable GIT_)
export GIT_NO_REPLACE_OBJECTS=1
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null
unset BASH_ENV ENV CDPATH LD_PRELOAD LD_LIBRARY_PATH \
    DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH \
    TMP TEMP TMPDIR \
    PYTHONHOME PYTHONPATH PYTHONINSPECT PYTHONSTARTUP \
    PERL5OPT PERL5LIB PERLLIB PERL_UNICODE PERL_LOCAL_LIB_ROOT \
    PERL_MB_OPT PERL_MM_OPT

script_dir=$(CDPATH= cd -P -- "$(dirname -- "$0")" && pwd -P)
# shellcheck source=qualification-common.sh
. "$script_dir/qualification-common.sh"

usage() {
    cat >&2 <<'EOF'
usage: test-promotion-trust-root.sh REPOSITORY CANDIDATE PROMOTED EXPECTED_TREE EXPECTED_SOURCE_SHA256 EXPECTED_BINARY_SHA256 EXPECTED_MANIFEST_SHA256 EXPECTED_CARGO_SHA256 EXPECTED_RUSTC_SHA256 EXPECTED_RUSTDOC_SHA256 EXPECTED_TOOLCHAIN_CLOSURE_SHA256 EXPECTED_TOOLCHAIN_CLOSURE_ENTRIES EXPECTED_TOOLCHAIN_CLOSURE_BYTES EXPECTED_CARGO_REGISTRY_CLOSURE_SHA256 EXPECTED_CARGO_REGISTRY_CLOSURE_ENTRIES EXPECTED_CARGO_REGISTRY_CLOSURE_BYTES EXPECTED_RESOURCE_COORDINATOR_SHA256 EXPECTED_CUTOVER_RECEIPT_SHA256 BUNDLE_DIR REVIEW_RECEIPT EXPECTED_REVIEW_SHA256

Require the exact real promotion invocation to pass, then prove that
non-atom, indirect, self-approved/resealed, stale-subject, synthetic-review,
inside-bundle-review, and mismatched-identity variants fail closed.
EOF
    exit 2
}

[[ $# -eq 21 ]] || usage
repository=$1
candidate=$2
promoted=$3
expected_tree=$4
expected_source=$5
expected_binary=$6
expected_manifest=$7
expected_cargo_sha=$8
expected_rustc_sha=$9
expected_rustdoc_sha=${10}
expected_toolchain_closure_sha=${11}
expected_toolchain_closure_entries=${12}
expected_toolchain_closure_bytes=${13}
expected_cargo_registry_closure_sha=${14}
expected_cargo_registry_closure_entries=${15}
expected_cargo_registry_closure_bytes=${16}
expected_resource_coordinator_sha=${17}
expected_cutover_receipt_sha=${18}
bundle=${19}
review_receipt=${20}
expected_review_sha=${21}

verifier=$script_dir/verify-promotion-delta.sh
fre_c5_require_regular "$verifier" "promotion verifier"
[[ -x $verifier ]] || fre_c5_die "promotion verifier must be executable"
fre_c5_require_regular \
    "$bundle/dependency-tree.txt" "bundle dependency report"
expected_dependency_rederive_sha=$(fre_c5_sha256 "$bundle/dependency-tree.txt")

verify_with_pins() {
    local invocation_repository=$1
    local invocation_candidate=$2
    local invocation_promoted=$3
    local invocation_tree=$4
    local invocation_source=$5
    local invocation_binary=$6
    local invocation_manifest=$7
    shift 7
    "$verifier" \
        "$invocation_repository" \
        "$invocation_candidate" \
        "$invocation_promoted" \
        "$invocation_tree" \
        "$invocation_source" \
        "$invocation_binary" \
        "$invocation_manifest" \
        "$expected_cargo_sha" \
        "$expected_rustc_sha" \
        "$expected_rustdoc_sha" \
        "$expected_toolchain_closure_sha" \
        "$expected_toolchain_closure_entries" \
        "$expected_toolchain_closure_bytes" \
        "$expected_cargo_registry_closure_sha" \
        "$expected_cargo_registry_closure_entries" \
        "$expected_cargo_registry_closure_bytes" \
        "$expected_resource_coordinator_sha" \
        "$expected_cutover_receipt_sha" \
        "$@"
}

verify() {
    verify_with_pins \
        "$repository" \
        "$candidate" \
        "$promoted" \
        "$expected_tree" \
        "$expected_source" \
        "$expected_binary" \
        "$expected_manifest" \
        "$bundle" \
        "$review_receipt" \
        "$expected_review_sha"
}

verify_with_explicit_provenance_pins() {
    local cargo_sha=$1
    local rustc_sha=$2
    local rustdoc_sha=$3
    local closure_sha=$4
    local closure_entries=$5
    local closure_bytes=$6
    local registry_sha=$7
    local registry_entries=$8
    local registry_bytes=$9
    local coordinator_sha=${10}
    local cutover_sha=${11}
    "$verifier" \
        "$repository" \
        "$candidate" \
        "$promoted" \
        "$expected_tree" \
        "$expected_source" \
        "$expected_binary" \
        "$expected_manifest" \
        "$cargo_sha" \
        "$rustc_sha" \
        "$rustdoc_sha" \
        "$closure_sha" \
        "$closure_entries" \
        "$closure_bytes" \
        "$registry_sha" \
        "$registry_entries" \
        "$registry_bytes" \
        "$coordinator_sha" \
        "$cutover_sha" \
        "$bundle" \
        "$review_receipt" \
        "$expected_review_sha"
}

# A negative-only suite can pass vacuously. First require the exact production
# invocation, including Candidate-extracted replay of the real measured bundle.
hostile_tmpdir=/private/tmp/fre-aot-c5-hostile-tmp-does-not-exist-$$
[[ ! -e $hostile_tmpdir && ! -L $hostile_tmpdir ]] ||
    fre_c5_die "hostile TMPDIR refusal path unexpectedly exists"
(
    export TMPDIR="$hostile_tmpdir"
    verify
) > /dev/null
[[ ! -e $hostile_tmpdir && ! -L $hostile_tmpdir ]] ||
    fre_c5_die "promotion verifier honored the hostile caller TMPDIR"

temporary=$(mktemp -d "/private/tmp/fre-aot-c5-promotion-test.XXXXXX") ||
    fre_c5_die "cannot create promotion-test scratch directory"
temporary_identity=$(
    fre_c5_owned_directory_identity "$temporary" "promotion-test scratch directory"
)
cleanup() {
    local status=$?
    local cleanup_failed=false
    if [[ -n ${temporary:-} && ( -e $temporary || -L $temporary ) ]]; then
        if [[ -z ${temporary_identity:-} ]] ||
            ! fre_c5_cleanup_owned_directory \
                "$temporary" "$temporary_identity" \
                /private/tmp/fre-aot-c5-promotion-test. \
                "promotion-test scratch directory"; then
            printf '%s\n' \
                "c5-qualification: refused unsafe promotion-test cleanup" >&2
            cleanup_failed=true
        fi
    fi
    if $cleanup_failed && [[ $status == 0 ]]; then
        status=1
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

regression_source=crates/fre-aot-count-compiler/benchmarks/c5-qualified-vs-portable/test-promotion-trust-root.sh
[[ $(git -C "$repository" ls-tree "$candidate" -- "$regression_source" |
    awk '{ print $1 " " $2 }') == "100755 blob" ]] ||
    fre_c5_die "candidate trust-root regression must be one executable blob"
regression_size=$(git -C "$repository" \
    cat-file -s "$candidate:$regression_source") ||
    fre_c5_die "cannot determine candidate trust-root regression size"
[[ $regression_size =~ ^(0|[1-9][0-9]*)$ && $regression_size -le 262144 ]] ||
    fre_c5_die "candidate trust-root regression exceeds byte cap 262144"
git -C "$repository" cat-file blob "$candidate:$regression_source" \
    > "$temporary/candidate-trust-root-regression.sh"
cmp -s "$script_dir/test-promotion-trust-root.sh" \
    "$temporary/candidate-trust-root-regression.sh" ||
    fre_c5_die "running trust-root regression differs from the candidate blob"

rejections=0
expect_rejection() {
    local name=$1
    shift
    if "$@" > "$temporary/$name.stdout" 2> "$temporary/$name.stderr"; then
        fre_c5_die "promotion verifier accepted adversarial case: $name"
    fi
    rejections=$((rejections + 1))
}

different_hex() {
    local value=$1
    case ${value:0:1} in
        0) printf '1%s\n' "${value:1}" ;;
        *) printf '0%s\n' "${value:1}" ;;
    esac
}

different_decimal() {
    local value=$1
    case $value in
        1) printf '2\n' ;;
        *) printf '1\n' ;;
    esac
}

rewrite_tsv_field() {
    local file=$1
    local key=$2
    local value=$3
    awk -F '	' -v OFS='	' -v key="$key" -v value="$value" '
        $1 == key {
            if (NF != 2) exit 1
            $2 = value
            replacements++
        }
        { print }
        END { if (replacements != 1) exit 1 }
    ' "$file" > "$file.rewrite" ||
        fre_c5_die "cannot rewrite adversarial TSV field: $key"
    mv -- "$file.rewrite" "$file"
}

rewrite_manifest() {
    local target=$1
    (
        cd "$target"
        find . -type f ! -path ./manifest.sha256 -print |
            LC_ALL=C sort |
            while IFS= read -r relative; do
                printf '%s  %s\n' "$(fre_c5_sha256 "$relative")" "$relative"
            done > manifest.sha256
    )
    fre_c5_sha256 "$target/manifest.sha256"
}

commit_tree() {
    local tree=$1
    local parent=$2
    local message=$3
    local timestamp=$4
    printf '%s\n' "$message" |
        env \
            GIT_AUTHOR_NAME='FRE C5 trust-root regression' \
            GIT_AUTHOR_EMAIL='fre-c5-trust-root@example.invalid' \
            GIT_AUTHOR_DATE="$timestamp" \
            GIT_COMMITTER_NAME='FRE C5 trust-root regression' \
            GIT_COMMITTER_EMAIL='fre-c5-trust-root@example.invalid' \
            GIT_COMMITTER_DATE="$timestamp" \
            git -C "$temporary/repository" commit-tree "$tree" -p "$parent"
}

promotion_tree() {
    local parent=$1
    local manifest=$2
    local extra_path=${3:-}
    local atom=crates/fre-aot-static-runtime/src/support.rs
    git -C "$temporary/repository" cat-file blob "$parent:$atom" \
        > "$temporary/candidate-support.rs"
    fre_c5_render_promoted_support \
        "$temporary/candidate-support.rs" \
        "$manifest" \
        "$temporary/promoted-support.rs"
    local atom_blob
    atom_blob=$(git -C "$temporary/repository" hash-object -w \
        "$temporary/promoted-support.rs")
    git -C "$temporary/repository" read-tree "$parent"
    git -C "$temporary/repository" update-index \
        --add --cacheinfo 100644 "$atom_blob" "$atom"
    if [[ -n $extra_path ]]; then
        git -C "$temporary/repository" cat-file blob "$parent:$extra_path" \
            > "$temporary/extra-path"
        printf '\nadversarial extra promotion delta\n' \
            >> "$temporary/extra-path"
        local extra_blob
        extra_blob=$(git -C "$temporary/repository" hash-object -w \
            "$temporary/extra-path")
        git -C "$temporary/repository" update-index \
            --add --cacheinfo 100644 "$extra_blob" "$extra_path"
    fi
    git -C "$temporary/repository" write-tree
}

commit_promotion() {
    local parent=$1
    local manifest=$2
    local message=$3
    local timestamp=$4
    local extra_path=${5:-}
    local tree
    tree=$(promotion_tree "$parent" "$manifest" "$extra_path")
    commit_tree "$tree" "$parent" "$message" "$timestamp"
}

commit_file_replacement() {
    local parent=$1
    local path=$2
    local mode=$3
    local replacement=$4
    local message=$5
    local timestamp=$6
    local blob tree
    blob=$(git -C "$temporary/repository" hash-object -w "$replacement")
    git -C "$temporary/repository" read-tree "$parent"
    git -C "$temporary/repository" update-index \
        --add --cacheinfo "$mode" "$blob" "$path"
    tree=$(git -C "$temporary/repository" write-tree)
    commit_tree "$tree" "$parent" "$message" "$timestamp"
}

write_review_receipt() {
    local review_candidate=$1
    local review_source=$2
    local review_binary=$3
    local review_manifest=$4
    local review_dependency_rederive=$5
    local review_class=$6
    local output=$7
    local review_tree review_evidence
    review_tree=$(git -C "$temporary/repository" \
        rev-parse --verify "$review_candidate^{tree}")
    review_evidence=$(printf 'C5 independent review regression: %s %s\n' \
        "$review_candidate" "$review_manifest" |
        shasum -a 256 | awk '{ print $1 }')
    {
        printf 'schema\tfre-aot-count-c5-independent-review-v3\n'
        printf 'candidate_commit\t%s\n' "$review_candidate"
        printf 'candidate_tree\t%s\n' "$review_tree"
        printf 'benchmark_source_sha256\t%s\n' "$review_source"
        printf 'benchmark_binary_sha256\t%s\n' "$review_binary"
        printf 'cargo_binary_sha256\t%s\n' "$expected_cargo_sha"
        printf 'rustc_binary_sha256\t%s\n' "$expected_rustc_sha"
        printf 'rustdoc_binary_sha256\t%s\n' "$expected_rustdoc_sha"
        printf 'toolchain_closure_sha256\t%s\n' \
            "$expected_toolchain_closure_sha"
        printf 'toolchain_closure_entries\t%s\n' \
            "$expected_toolchain_closure_entries"
        printf 'toolchain_closure_bytes\t%s\n' \
            "$expected_toolchain_closure_bytes"
        printf 'cargo_registry_closure_sha256\t%s\n' \
            "$expected_cargo_registry_closure_sha"
        printf 'cargo_registry_closure_entries\t%s\n' \
            "$expected_cargo_registry_closure_entries"
        printf 'cargo_registry_closure_bytes\t%s\n' \
            "$expected_cargo_registry_closure_bytes"
        printf 'resource_coordinator_sha256\t%s\n' \
            "$expected_resource_coordinator_sha"
        printf 'resource_coordinator_cutover_receipt_sha256\t%s\n' \
            "$expected_cutover_receipt_sha"
        printf 'bundle_manifest_sha256\t%s\n' "$review_manifest"
        printf 'evidence_class\t%s\n' "$review_class"
        printf 'verifier_commit\t%s\n' "$review_candidate"
        printf 'dependency_rederive_sha256\t%s\n' \
            "$review_dependency_rederive"
        printf 'review_evidence_sha256\t%s\n' "$review_evidence"
        printf 'overall\tPASS\n'
    } > "$output"
    chmod 0644 "$output"
}

# This is a local shared-object clone: new adversarial commits and index writes
# are private, while the source repository and all of its refs remain untouched.
git clone --quiet --shared --no-checkout \
    "$repository" "$temporary/repository"
for commit in "$candidate" "$promoted"; do
    [[ $(git -C "$temporary/repository" rev-parse --verify \
        "$commit^{commit}") == "$commit" ]] ||
        fre_c5_die "private repository cannot resolve baseline commit"
done

# Exactly one path is allowed, even if the atom itself is otherwise canonical.
extra_promoted=$(commit_promotion \
    "$candidate" \
    "$expected_manifest" \
    "C5 adversarial extra-path promotion" \
    "2001-01-01T00:00:00Z" \
    crates/fre-aot-count-compiler/benchmarks/c5-qualified-vs-portable/README.md)
expect_rejection extra-path \
    verify_with_pins "$temporary/repository" "$candidate" "$extra_promoted" \
    "$expected_tree" "$expected_source" "$expected_binary" \
    "$expected_manifest" "$bundle" "$review_receipt" "$expected_review_sha"

# A matching atom below an intermediate commit is not a direct-child promotion.
candidate_tree=$(git -C "$temporary/repository" \
    rev-parse --verify "$candidate^{tree}")
intermediate=$(commit_tree \
    "$candidate_tree" "$candidate" \
    "C5 adversarial intermediate" "2001-01-02T00:00:00Z")
indirect_promoted=$(commit_promotion \
    "$intermediate" "$expected_manifest" \
    "C5 adversarial indirect promotion" "2001-01-03T00:00:00Z")
expect_rejection indirect-child \
    verify_with_pins "$temporary/repository" "$candidate" "$indirect_promoted" \
    "$expected_tree" "$expected_source" "$expected_binary" \
    "$expected_manifest" "$bundle" "$review_receipt" "$expected_review_sha"

# A Candidate cannot force an unbounded extraction before its trusted helper is
# sourced. Keep the promotion-verifier blob exact while making common oversized.
oversized_common=$temporary/oversized-qualification-common.sh
git -C "$temporary/repository" cat-file blob \
    "$candidate:crates/fre-aot-count-compiler/benchmarks/c5-qualified-vs-portable/qualification-common.sh" \
    > "$oversized_common"
/bin/dd if=/dev/zero bs=131073 count=1 2>/dev/null \
    >> "$oversized_common"
oversized_candidate=$(commit_file_replacement \
    "$candidate" \
    crates/fre-aot-count-compiler/benchmarks/c5-qualified-vs-portable/qualification-common.sh \
    100644 \
    "$oversized_common" \
    "C5 adversarial oversized Candidate helper" \
    "2001-01-03T01:00:00Z")
oversized_tree=$(git -C "$temporary/repository" \
    rev-parse --verify "$oversized_candidate^{tree}")
oversized_promoted=$(commit_promotion \
    "$oversized_candidate" "$expected_manifest" \
    "C5 adversarial oversized-helper promotion" "2001-01-03T02:00:00Z")
oversized_review=$temporary/oversized-candidate-review.tsv
write_review_receipt \
    "$oversized_candidate" "$expected_source" "$expected_binary" \
    "$expected_manifest" "$expected_dependency_rederive_sha" \
    measured "$oversized_review"
oversized_review_sha=$(fre_c5_sha256 "$oversized_review")
expect_rejection oversized-candidate-helper \
    verify_with_pins "$temporary/repository" \
    "$oversized_candidate" "$oversized_promoted" \
    "$oversized_tree" "$expected_source" "$expected_binary" \
    "$expected_manifest" "$bundle" "$oversized_review" "$oversized_review_sha"

# Reproduce a self-approval attack: replace the verifier inside source.tar with
# unconditional success, rewrite the source-archive receipts, and reseal the
# flat bundle. The malicious archived verifier really accepts; the verifier
# extracted from Candidate must still reject the bundle.
self_bundle=$temporary/self-approved-resealed-bundle
mkdir "$self_bundle"
cp -pR -- "$bundle/." "$self_bundle/"
mkdir "$temporary/self-approved-source"
tar -xf "$self_bundle/source.tar" -C "$temporary/self-approved-source"
malicious_verifier=$temporary/self-approved-source/crates/fre-aot-count-compiler/benchmarks/c5-qualified-vs-portable/verify-qualification-bundle.sh
printf '#!/bin/bash\nexit 0\n' > "$malicious_verifier"
chmod 0755 "$malicious_verifier"
"$malicious_verifier" >/dev/null ||
    fre_c5_die "self-approving regression verifier did not accept"
tar -cf "$self_bundle/source.tar" \
    -C "$temporary/self-approved-source" .
self_archive_sha=$(fre_c5_sha256 "$self_bundle/source.tar")
rewrite_tsv_field "$self_bundle/binding.tsv" \
    source_archive_sha256 "$self_archive_sha"
rewrite_tsv_field "$self_bundle/build-receipt.tsv" \
    source_archive_sha256 "$self_archive_sha"
self_manifest=$(rewrite_manifest "$self_bundle")
self_promoted=$(commit_promotion \
    "$candidate" "$self_manifest" \
    "C5 adversarial self-approved promotion" "2001-01-04T00:00:00Z")
self_review=$temporary/self-approved-review.tsv
write_review_receipt \
    "$candidate" "$expected_source" "$expected_binary" "$self_manifest" \
    "$expected_dependency_rederive_sha" measured "$self_review"
self_review_sha=$(fre_c5_sha256 "$self_review")
expect_rejection self-approved-resealed \
    verify_with_pins "$temporary/repository" "$candidate" "$self_promoted" \
    "$expected_tree" "$expected_source" "$expected_binary" \
    "$self_manifest" "$self_bundle" "$self_review" "$self_review_sha"

# A distinct commit with the Candidate tree is still not the measured subject.
stale_candidate=$(commit_tree \
    "$candidate_tree" "$candidate" \
    "C5 adversarial same-tree stale Candidate" "2001-01-05T00:00:00Z")
stale_promoted=$(commit_promotion \
    "$stale_candidate" "$expected_manifest" \
    "C5 adversarial stale promotion" "2001-01-06T00:00:00Z")
stale_review=$temporary/stale-review.tsv
write_review_receipt \
    "$stale_candidate" "$expected_source" "$expected_binary" \
    "$expected_manifest" "$expected_dependency_rederive_sha" \
    measured "$stale_review"
stale_review_sha=$(fre_c5_sha256 "$stale_review")
expect_rejection same-tree-stale-subject \
    verify_with_pins "$temporary/repository" "$stale_candidate" "$stale_promoted" \
    "$expected_tree" "$expected_source" "$expected_binary" \
    "$expected_manifest" "$bundle" "$stale_review" "$stale_review_sha"

synthetic_review=$temporary/synthetic-review.tsv
cp -p -- "$review_receipt" "$synthetic_review"
rewrite_tsv_field "$synthetic_review" evidence_class synthetic
synthetic_review_sha=$(fre_c5_sha256 "$synthetic_review")
expect_rejection synthetic-review \
    verify_with_pins "$repository" "$candidate" "$promoted" \
    "$expected_tree" "$expected_source" "$expected_binary" \
    "$expected_manifest" "$bundle" "$synthetic_review" "$synthetic_review_sha"

mismatched_subject_review=$temporary/mismatched-subject-review.tsv
cp -p -- "$review_receipt" "$mismatched_subject_review"
rewrite_tsv_field "$mismatched_subject_review" candidate_commit "$promoted"
mismatched_subject_review_sha=$(fre_c5_sha256 "$mismatched_subject_review")
expect_rejection mismatched-review-subject \
    verify_with_pins "$repository" "$candidate" "$promoted" \
    "$expected_tree" "$expected_source" "$expected_binary" \
    "$expected_manifest" "$bundle" "$mismatched_subject_review" \
    "$mismatched_subject_review_sha"

mismatched_dependency_review=$temporary/mismatched-dependency-review.tsv
cp -p -- "$review_receipt" "$mismatched_dependency_review"
mismatched_dependency_sha=$(different_hex "$expected_dependency_rederive_sha")
rewrite_tsv_field "$mismatched_dependency_review" \
    dependency_rederive_sha256 "$mismatched_dependency_sha"
mismatched_dependency_review_sha=$(fre_c5_sha256 \
    "$mismatched_dependency_review")
expect_rejection mismatched-dependency-rederive \
    verify_with_pins "$repository" "$candidate" "$promoted" \
    "$expected_tree" "$expected_source" "$expected_binary" \
    "$expected_manifest" "$bundle" "$mismatched_dependency_review" \
    "$mismatched_dependency_review_sha"

mismatched_review_sha=$(different_hex "$expected_review_sha")
expect_rejection mismatched-review-pin \
    verify_with_pins "$repository" "$candidate" "$promoted" \
    "$expected_tree" "$expected_source" "$expected_binary" \
    "$expected_manifest" "$bundle" "$review_receipt" "$mismatched_review_sha"

oversized_review_receipt=$temporary/oversized-review.tsv
cp -p -- "$review_receipt" "$oversized_review_receipt"
/bin/dd if=/dev/zero bs=4097 count=1 2>/dev/null \
    >> "$oversized_review_receipt"
oversized_review_receipt_sha=$(fre_c5_sha256 "$oversized_review_receipt")
expect_rejection oversized-review-receipt \
    verify_with_pins "$repository" "$candidate" "$promoted" \
    "$expected_tree" "$expected_source" "$expected_binary" \
    "$expected_manifest" "$bundle" "$oversized_review_receipt" \
    "$oversized_review_receipt_sha"

inside_bundle=$temporary/inside-review-bundle
mkdir "$inside_bundle"
cp -pR -- "$bundle/." "$inside_bundle/"
cp -p -- "$review_receipt" "$inside_bundle/independent-review.tsv"
expect_rejection review-inside-bundle \
    verify_with_pins "$repository" "$candidate" "$promoted" \
    "$expected_tree" "$expected_source" "$expected_binary" \
    "$expected_manifest" "$inside_bundle" \
    "$inside_bundle/independent-review.tsv" "$expected_review_sha"

mismatched_tree=$(different_hex "$expected_tree")
expect_rejection mismatched-tree \
    verify_with_pins "$repository" "$candidate" "$promoted" \
    "$mismatched_tree" "$expected_source" "$expected_binary" \
    "$expected_manifest" "$bundle" "$review_receipt" "$expected_review_sha"

mismatched_source=$(different_hex "$expected_source")
expect_rejection mismatched-source \
    verify_with_pins "$repository" "$candidate" "$promoted" \
    "$expected_tree" "$mismatched_source" "$expected_binary" \
    "$expected_manifest" "$bundle" "$review_receipt" "$expected_review_sha"

mismatched_binary=$(different_hex "$expected_binary")
expect_rejection mismatched-binary \
    verify_with_pins "$repository" "$candidate" "$promoted" \
    "$expected_tree" "$expected_source" "$mismatched_binary" \
    "$expected_manifest" "$bundle" "$review_receipt" "$expected_review_sha"

mismatched_manifest=$(different_hex "$expected_manifest")
expect_rejection mismatched-manifest \
    verify_with_pins "$repository" "$candidate" "$promoted" \
    "$expected_tree" "$expected_source" "$expected_binary" \
    "$mismatched_manifest" "$bundle" "$review_receipt" "$expected_review_sha"

mismatched_cargo_sha=$(different_hex "$expected_cargo_sha")
expect_rejection mismatched-cargo-pin \
    verify_with_explicit_provenance_pins \
    "$mismatched_cargo_sha" "$expected_rustc_sha" "$expected_rustdoc_sha" \
    "$expected_toolchain_closure_sha" "$expected_toolchain_closure_entries" \
    "$expected_toolchain_closure_bytes" "$expected_cargo_registry_closure_sha" \
    "$expected_cargo_registry_closure_entries" \
    "$expected_cargo_registry_closure_bytes" \
    "$expected_resource_coordinator_sha" "$expected_cutover_receipt_sha"

mismatched_rustc_sha=$(different_hex "$expected_rustc_sha")
expect_rejection mismatched-rustc-pin \
    verify_with_explicit_provenance_pins \
    "$expected_cargo_sha" "$mismatched_rustc_sha" "$expected_rustdoc_sha" \
    "$expected_toolchain_closure_sha" "$expected_toolchain_closure_entries" \
    "$expected_toolchain_closure_bytes" "$expected_cargo_registry_closure_sha" \
    "$expected_cargo_registry_closure_entries" \
    "$expected_cargo_registry_closure_bytes" \
    "$expected_resource_coordinator_sha" "$expected_cutover_receipt_sha"

mismatched_rustdoc_sha=$(different_hex "$expected_rustdoc_sha")
expect_rejection mismatched-rustdoc-pin \
    verify_with_explicit_provenance_pins \
    "$expected_cargo_sha" "$expected_rustc_sha" "$mismatched_rustdoc_sha" \
    "$expected_toolchain_closure_sha" "$expected_toolchain_closure_entries" \
    "$expected_toolchain_closure_bytes" "$expected_cargo_registry_closure_sha" \
    "$expected_cargo_registry_closure_entries" \
    "$expected_cargo_registry_closure_bytes" \
    "$expected_resource_coordinator_sha" "$expected_cutover_receipt_sha"

mismatched_closure_sha=$(different_hex "$expected_toolchain_closure_sha")
expect_rejection mismatched-toolchain-closure-pin \
    verify_with_explicit_provenance_pins \
    "$expected_cargo_sha" "$expected_rustc_sha" "$expected_rustdoc_sha" \
    "$mismatched_closure_sha" "$expected_toolchain_closure_entries" \
    "$expected_toolchain_closure_bytes" "$expected_cargo_registry_closure_sha" \
    "$expected_cargo_registry_closure_entries" \
    "$expected_cargo_registry_closure_bytes" \
    "$expected_resource_coordinator_sha" "$expected_cutover_receipt_sha"

mismatched_closure_entries=$(different_decimal \
    "$expected_toolchain_closure_entries")
expect_rejection mismatched-toolchain-closure-entries \
    verify_with_explicit_provenance_pins \
    "$expected_cargo_sha" "$expected_rustc_sha" "$expected_rustdoc_sha" \
    "$expected_toolchain_closure_sha" "$mismatched_closure_entries" \
    "$expected_toolchain_closure_bytes" "$expected_cargo_registry_closure_sha" \
    "$expected_cargo_registry_closure_entries" \
    "$expected_cargo_registry_closure_bytes" \
    "$expected_resource_coordinator_sha" "$expected_cutover_receipt_sha"

mismatched_closure_bytes=$(different_decimal "$expected_toolchain_closure_bytes")
expect_rejection mismatched-toolchain-closure-bytes \
    verify_with_explicit_provenance_pins \
    "$expected_cargo_sha" "$expected_rustc_sha" "$expected_rustdoc_sha" \
    "$expected_toolchain_closure_sha" "$expected_toolchain_closure_entries" \
    "$mismatched_closure_bytes" "$expected_cargo_registry_closure_sha" \
    "$expected_cargo_registry_closure_entries" \
    "$expected_cargo_registry_closure_bytes" \
    "$expected_resource_coordinator_sha" "$expected_cutover_receipt_sha"

mismatched_registry_sha=$(different_hex "$expected_cargo_registry_closure_sha")
expect_rejection mismatched-cargo-registry-pin \
    verify_with_explicit_provenance_pins \
    "$expected_cargo_sha" "$expected_rustc_sha" "$expected_rustdoc_sha" \
    "$expected_toolchain_closure_sha" "$expected_toolchain_closure_entries" \
    "$expected_toolchain_closure_bytes" "$mismatched_registry_sha" \
    "$expected_cargo_registry_closure_entries" \
    "$expected_cargo_registry_closure_bytes" \
    "$expected_resource_coordinator_sha" "$expected_cutover_receipt_sha"

mismatched_registry_entries=$(different_decimal \
    "$expected_cargo_registry_closure_entries")
expect_rejection mismatched-cargo-registry-entries \
    verify_with_explicit_provenance_pins \
    "$expected_cargo_sha" "$expected_rustc_sha" "$expected_rustdoc_sha" \
    "$expected_toolchain_closure_sha" "$expected_toolchain_closure_entries" \
    "$expected_toolchain_closure_bytes" "$expected_cargo_registry_closure_sha" \
    "$mismatched_registry_entries" "$expected_cargo_registry_closure_bytes" \
    "$expected_resource_coordinator_sha" "$expected_cutover_receipt_sha"

mismatched_registry_bytes=$(different_decimal \
    "$expected_cargo_registry_closure_bytes")
expect_rejection mismatched-cargo-registry-bytes \
    verify_with_explicit_provenance_pins \
    "$expected_cargo_sha" "$expected_rustc_sha" "$expected_rustdoc_sha" \
    "$expected_toolchain_closure_sha" "$expected_toolchain_closure_entries" \
    "$expected_toolchain_closure_bytes" "$expected_cargo_registry_closure_sha" \
    "$expected_cargo_registry_closure_entries" "$mismatched_registry_bytes" \
    "$expected_resource_coordinator_sha" "$expected_cutover_receipt_sha"

mismatched_coordinator_sha=$(different_hex "$expected_resource_coordinator_sha")
expect_rejection mismatched-resource-coordinator-pin \
    verify_with_explicit_provenance_pins \
    "$expected_cargo_sha" "$expected_rustc_sha" "$expected_rustdoc_sha" \
    "$expected_toolchain_closure_sha" "$expected_toolchain_closure_entries" \
    "$expected_toolchain_closure_bytes" "$expected_cargo_registry_closure_sha" \
    "$expected_cargo_registry_closure_entries" \
    "$expected_cargo_registry_closure_bytes" "$mismatched_coordinator_sha" \
    "$expected_cutover_receipt_sha"

mismatched_cutover_sha=$(different_hex "$expected_cutover_receipt_sha")
expect_rejection mismatched-cutover-receipt-pin \
    verify_with_explicit_provenance_pins \
    "$expected_cargo_sha" "$expected_rustc_sha" "$expected_rustdoc_sha" \
    "$expected_toolchain_closure_sha" "$expected_toolchain_closure_entries" \
    "$expected_toolchain_closure_bytes" "$expected_cargo_registry_closure_sha" \
    "$expected_cargo_registry_closure_entries" \
    "$expected_cargo_registry_closure_bytes" \
    "$expected_resource_coordinator_sha" "$mismatched_cutover_sha"

[[ $rejections == 26 ]] ||
    fre_c5_die "trust-root regression rejection count changed"
printf '%s\n' \
    'PROMOTION_TRUST_ROOT_VERIFIED,baseline=1,rejected=26,direct_child=true,atom_only=true,candidate_rooted_verifier=true,bounded_candidate_extraction=true,external_subject_receipts=true,independent_review_pin=true,dependency_rederive_pin=true,toolchain_registry_coordinator_pins=true,hostile_tmpdir_ignored=true'
