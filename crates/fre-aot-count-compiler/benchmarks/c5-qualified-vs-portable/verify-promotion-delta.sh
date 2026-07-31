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

die() {
    printf 'c5-promotion: %s\n' "$*" >&2
    exit 1
}

require_hex() {
    local value=$1
    local digits=$2
    local label=$3
    [[ ${#value} -eq $digits && $value != *[!0-9a-f]* ]] ||
        die "$label must be exactly $digits lowercase hexadecimal digits"
}

require_nonzero_sha256() {
    local value=$1
    local label=$2
    require_hex "$value" 64 "$label"
    [[ $value != 0000000000000000000000000000000000000000000000000000000000000000 ]] ||
        die "$label must not be zero"
}

require_bounded_positive_decimal() {
    local value=$1
    local maximum=$2
    local label=$3
    [[ $value =~ ^[1-9][0-9]*$ &&
        ${#value} -le ${#maximum} ]] ||
        die "$label must be a positive decimal at most $maximum"
    if [[ ${#value} -eq ${#maximum} && $value -gt $maximum ]]; then
        die "$label must be a positive decimal at most $maximum"
    fi
}

require_candidate_blob_size() {
    local repository=$1
    local candidate=$2
    local source_path=$3
    local maximum=$4
    local label=$5
    local size
    size=$(git -C "$repository" cat-file -s "$candidate:$source_path" 2>/dev/null) ||
        die "cannot determine candidate blob size for $label"
    [[ $size =~ ^(0|[1-9][0-9]*)$ && $size -le $maximum ]] ||
        die "candidate blob exceeds byte cap $maximum for $label"
}

canonical_directory() {
    local path=$1
    local label=$2
    [[ $path == /* && -d $path && ! -L $path ]] ||
        die "$label must be an absolute existing non-symlink directory"
    local canonical
    canonical=$(CDPATH= cd -P -- "$path" && pwd -P) ||
        die "cannot resolve $label"
    [[ $canonical == "$path" ]] ||
        die "$label must already be canonical"
    printf '%s\n' "$canonical"
}

cleanup_empty_exact_scratch() {
    /usr/bin/env -i \
        LC_ALL=C \
        TZ=UTC \
        PATH=/usr/bin:/bin \
        /usr/bin/python3 -I -B - \
        "$1" "$2" "$3" "$4" <<'PY'
import os
import stat
import sys

path = os.fsencode(sys.argv[1])
expected_identity = sys.argv[2]
namespace_prefix = os.fsencode(sys.argv[3])
label = sys.argv[4]

if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
    raise SystemExit(f"{label}: cleanup requires O_NOFOLLOW and O_DIRECTORY")
try:
    device_text, inode_text, owner_text = expected_identity.split(":")
    expected_device = int(device_text)
    expected_inode = int(inode_text)
    expected_owner = int(owner_text)
except (TypeError, ValueError) as error:
    raise SystemExit(f"{label}: malformed recorded identity") from error
if (
    not path.startswith(b"/")
    or not namespace_prefix.startswith(b"/")
    or namespace_prefix == b"/"
    or not namespace_prefix.endswith(b".")
    or not path.startswith(namespace_prefix)
):
    raise SystemExit(f"{label}: path is outside its exact namespace")
suffix = path[len(namespace_prefix) :]
if len(suffix) != 6 or any(
    byte not in b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    for byte in suffix
):
    raise SystemExit(f"{label}: malformed namespace suffix")
parent = os.path.dirname(path)
name = os.path.basename(path)
if not parent or not name or b"/" in name:
    raise SystemExit(f"{label}: malformed path")

directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
if hasattr(os, "O_CLOEXEC"):
    directory_flags |= os.O_CLOEXEC
parent_fd = os.open(parent, directory_flags)


def same_root(metadata: os.stat_result) -> bool:
    return (
        metadata.st_dev == expected_device
        and metadata.st_ino == expected_inode
        and metadata.st_uid == expected_owner
        and stat.S_ISDIR(metadata.st_mode)
    )


try:
    root_metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not same_root(root_metadata):
        raise SystemExit(f"{label}: root differs from its recorded identity")
    root_fd = os.open(name, directory_flags, dir_fd=parent_fd)
    try:
        opened_root = os.fstat(root_fd)
        if not same_root(opened_root):
            raise SystemExit(f"{label}: root changed while being opened")
        if expected_owner != os.geteuid():
            raise SystemExit(f"{label}: root is not owned by this user")
        with os.scandir(root_fd) as scanner:
            if next(scanner, None) is not None:
                raise SystemExit(
                    f"{label}: cannot use empty-only cleanup after files exist"
                )
        if not same_root(os.fstat(root_fd)):
            raise SystemExit(f"{label}: root changed during empty check")
    finally:
        os.close(root_fd)
    final_root = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not same_root(final_root):
        raise SystemExit(f"{label}: root changed before final removal")
    os.rmdir(name, dir_fd=parent_fd)
finally:
    os.close(parent_fd)
PY
}

usage() {
    cat >&2 <<'EOF'
usage: verify-promotion-delta.sh REPOSITORY CANDIDATE PROMOTED EXPECTED_TREE EXPECTED_SOURCE_SHA256 EXPECTED_BINARY_SHA256 EXPECTED_MANIFEST_SHA256 EXPECTED_CARGO_SHA256 EXPECTED_RUSTC_SHA256 EXPECTED_RUSTDOC_SHA256 EXPECTED_TOOLCHAIN_CLOSURE_SHA256 EXPECTED_TOOLCHAIN_CLOSURE_ENTRIES EXPECTED_TOOLCHAIN_CLOSURE_BYTES EXPECTED_CARGO_REGISTRY_CLOSURE_SHA256 EXPECTED_CARGO_REGISTRY_CLOSURE_ENTRIES EXPECTED_CARGO_REGISTRY_CLOSURE_BYTES EXPECTED_RESOURCE_COORDINATOR_SHA256 EXPECTED_CUTOVER_RECEIPT_SHA256 BUNDLE_DIR REVIEW_RECEIPT EXPECTED_REVIEW_SHA256 [aot-only|composed-exact-union-delegated]

Verify a direct-child, atom-only C5 production promotion. Every measured
subject identity, bundle manifest, toolchain/registry closure bounds,
coordinator/cutover identities, and independently published review-receipt
identity must be supplied from outside the bundle.
The composed mode delegates only the global changed-path union to a
Candidate-rooted combined verifier; this verifier still owns the exact AOT
support.rs atom rendering and every AOT evidence check.
EOF
    exit 2
}

[[ $# -eq 21 || $# -eq 22 ]] || usage
repository_arg=$1
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
bundle_arg=${19}
review_receipt_arg=${20}
expected_review_sha=${21}
scope=${22:-aot-only}
case $scope in
    aot-only|composed-exact-union-delegated) ;;
    *) usage ;;
esac

repository=$(canonical_directory "$repository_arg" "repository")
bundle=$(canonical_directory "$bundle_arg" "bundle")
grafts=$(git -C "$repository" rev-parse --git-path info/grafts) ||
    die "cannot resolve repository graft path"
case $grafts in
    /*) ;;
    *) grafts=$repository/$grafts ;;
esac
[[ ! -e $grafts && ! -L $grafts ]] ||
    die "repository must not contain an info/grafts history override"
replace_ref=$(git -C "$repository" for-each-ref \
    --format='%(refname)' refs/replace | sed -n '1p') ||
    die "cannot inspect repository replace refs"
[[ -z $replace_ref ]] || die "repository must not contain replace refs"
[[ $(git -C "$repository" rev-parse --is-shallow-repository) == false ]] ||
    die "promotion verification requires a complete non-shallow repository"
[[ $review_receipt_arg == /* ]] ||
    die "review receipt must be an absolute path"

require_hex "$candidate" 40 "candidate commit"
require_hex "$promoted" 40 "promoted commit"
require_hex "$expected_tree" 40 "expected candidate tree"
require_nonzero_sha256 "$expected_source" "expected benchmark source SHA-256"
require_nonzero_sha256 "$expected_binary" "expected benchmark binary SHA-256"
require_nonzero_sha256 "$expected_manifest" "expected bundle manifest SHA-256"
require_nonzero_sha256 "$expected_cargo_sha" "expected Cargo binary SHA-256"
require_nonzero_sha256 "$expected_rustc_sha" "expected rustc binary SHA-256"
require_nonzero_sha256 "$expected_rustdoc_sha" "expected rustdoc binary SHA-256"
require_nonzero_sha256 \
    "$expected_toolchain_closure_sha" "expected toolchain closure SHA-256"
require_bounded_positive_decimal \
    "$expected_toolchain_closure_entries" 16384 \
    "expected toolchain closure entry count"
require_bounded_positive_decimal \
    "$expected_toolchain_closure_bytes" 4294967296 \
    "expected toolchain closure byte count"
require_nonzero_sha256 \
    "$expected_cargo_registry_closure_sha" \
    "expected Cargo registry closure SHA-256"
require_bounded_positive_decimal \
    "$expected_cargo_registry_closure_entries" 100000 \
    "expected Cargo registry closure entry count"
require_bounded_positive_decimal \
    "$expected_cargo_registry_closure_bytes" 4294967296 \
    "expected Cargo registry closure byte count"
require_nonzero_sha256 \
    "$expected_resource_coordinator_sha" "expected resource coordinator SHA-256"
require_nonzero_sha256 \
    "$expected_cutover_receipt_sha" "expected cutover receipt SHA-256"
require_nonzero_sha256 "$expected_review_sha" "expected review receipt SHA-256"
[[ $candidate != "$promoted" ]] ||
    die "candidate and promoted commits must differ"

for commit in "$candidate" "$promoted"; do
    actual=$(git -C "$repository" rev-parse --verify "$commit^{commit}" 2>/dev/null) ||
        die "repository does not contain commit $commit"
    [[ $actual == "$commit" ]] ||
        die "commit did not resolve exactly: $commit"
done
candidate_tree=$(git -C "$repository" rev-parse --verify "$candidate^{tree}") ||
    die "cannot resolve candidate tree"
[[ $candidate_tree == "$expected_tree" ]] ||
    die "candidate tree differs from the external expected tree"
[[ $(git -C "$repository" show -s --format=%P "$promoted") == "$candidate" ]] ||
    die "promoted commit must have the candidate as its only direct parent"

temporary=
temporary_identity=
cleanup() {
    local status=$?
    local cleanup_failed=false
    if [[ -n ${temporary:-} && ( -e $temporary || -L $temporary ) ]]; then
        if [[ -z ${temporary_identity:-} ]]; then
            cleanup_failed=true
        elif declare -F fre_c5_cleanup_owned_directory >/dev/null; then
            if ! fre_c5_cleanup_owned_directory \
                "$temporary" "$temporary_identity" \
                /private/tmp/fre-aot-c5-promotion. \
                "promotion-verifier scratch directory"; then
                cleanup_failed=true
            fi
        elif ! cleanup_empty_exact_scratch \
            "$temporary" "$temporary_identity" \
            /private/tmp/fre-aot-c5-promotion. \
            "promotion-verifier scratch directory"; then
            cleanup_failed=true
        fi
        if $cleanup_failed; then
            printf '%s\n' \
                "c5-promotion: refused unsafe promotion-verifier cleanup" >&2
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

temporary=$(mktemp -d "/private/tmp/fre-aot-c5-promotion.XXXXXX") ||
    die "cannot create promotion-verifier scratch directory"
temporary_identity=$(stat -f '%d:%i:%u' -- "$temporary") ||
    die "cannot determine promotion-verifier scratch identity"
[[ $temporary =~ ^/private/tmp/fre-aot-c5-promotion\.[A-Za-z0-9]{6}$ &&
    -d $temporary && ! -L $temporary ]] ||
    die "promotion-verifier scratch directory has an unsafe namespace"
[[ $temporary_identity =~ ^[0-9]+:[0-9]+:[0-9]+$ ]] ||
    die "promotion-verifier scratch identity is malformed"
temporary_owner=${temporary_identity##*:}
[[ $temporary_owner == "$(/usr/bin/id -u)" ]] ||
    die "promotion-verifier scratch directory is not owned by this user"

script_dir=$(CDPATH= cd -P -- "$(dirname -- "$0")" && pwd -P)
self=$script_dir/verify-promotion-delta.sh
promotion_source=crates/fre-aot-count-compiler/benchmarks/c5-qualified-vs-portable/verify-promotion-delta.sh
[[ -f $self && ! -L $self ]] ||
    die "running promotion verifier must be a regular non-symlink file"
[[ $(stat -f '%Lp' -- "$self") == 755 ]] ||
    die "running promotion verifier must have mode 0755"
[[ $(git -C "$repository" ls-tree "$candidate" -- "$promotion_source" |
    awk '{ print $1 " " $2 }') == "100755 blob" ]] ||
    die "candidate promotion verifier must be one executable blob"
require_candidate_blob_size \
    "$repository" "$candidate" "$promotion_source" 131072 "promotion verifier"
git -C "$repository" cat-file blob "$candidate:$promotion_source" \
    > "$temporary/candidate-promotion-verifier.sh"
cmp -s -- "$self" "$temporary/candidate-promotion-verifier.sh" ||
    die "running promotion verifier differs from the candidate blob"

atom=crates/fre-aot-static-runtime/src/support.rs
if ! git -C "$repository" diff --name-only --no-renames \
    --no-ext-diff --no-textconv \
    "$candidate" "$promoted" |
    awk '
        length($0) > 1024 { exit 1 }
        NR > 8 { exit 1 }
        { print }
    ' > "$temporary/changed-paths.txt"; then
    die "promotion changed-path report exceeds its bounded envelope"
fi
if [[ $scope == aot-only ]]; then
    [[ $(wc -l < "$temporary/changed-paths.txt" | tr -d ' ') == 1 &&
        $(sed -n '1p' "$temporary/changed-paths.txt") == "$atom" ]] ||
        die "AOT-only promotion must change exactly the C5 support atom file"
else
    awk -v atom="$atom" '
        $0 == atom { found++ }
        END { exit found == 1 ? 0 : 1 }
    ' "$temporary/changed-paths.txt" ||
        die "composed promotion does not contain exactly one C5 support atom path"
fi
for commit in "$candidate" "$promoted"; do
    [[ $(git -C "$repository" ls-tree "$commit" -- "$atom" |
        awk '{ print $1 " " $2 }') == "100644 blob" ]] ||
        die "C5 support atom must remain one mode-100644 blob"
done
require_candidate_blob_size \
    "$repository" "$candidate" "$atom" 262144 "C5 support atom source"
require_candidate_blob_size \
    "$repository" "$promoted" "$atom" 262144 "promoted C5 support atom source"
git -C "$repository" cat-file blob "$candidate:$atom" \
    > "$temporary/candidate-support.rs"

mkdir "$temporary/trusted"
while IFS=$'\t' read -r trusted_file git_mode file_mode; do
    source_path=crates/fre-aot-count-compiler/benchmarks/c5-qualified-vs-portable/$trusted_file
    [[ $(git -C "$repository" ls-tree "$candidate" -- "$source_path" |
        awk '{ print $1 " " $2 }') == "$git_mode blob" ]] ||
        die "candidate trust closure has the wrong type or mode: $trusted_file"
    case $trusted_file in
        qualification-common.sh) maximum=131072 ;;
        verify-qualification-bundle.sh) maximum=262144 ;;
        *) die "internal candidate trust-closure error" ;;
    esac
    require_candidate_blob_size \
        "$repository" "$candidate" "$source_path" "$maximum" "$trusted_file"
    git -C "$repository" cat-file blob "$candidate:$source_path" \
        > "$temporary/trusted/$trusted_file"
    chmod "$file_mode" "$temporary/trusted/$trusted_file"
done <<'EOF'
qualification-common.sh	100644	0644
verify-qualification-bundle.sh	100755	0755
EOF
# shellcheck source=qualification-common.sh
. "$temporary/trusted/qualification-common.sh"

fre_c5_render_promoted_support \
    "$temporary/candidate-support.rs" \
    "$expected_manifest" \
    "$temporary/expected-promoted-support.rs"
git -C "$repository" cat-file blob "$promoted:$atom" \
    > "$temporary/promoted-support.rs"
cmp -s \
    "$temporary/expected-promoted-support.rs" \
    "$temporary/promoted-support.rs" ||
    die "promoted support source is not the exact canonical manifest atom replacement"

[[ -f $review_receipt_arg && ! -L $review_receipt_arg ]] ||
    die "review receipt must be a regular non-symlink file"
review_size=$(stat -f '%z' -- "$review_receipt_arg") ||
    die "cannot determine review receipt size"
[[ $review_size =~ ^(0|[1-9][0-9]*)$ && $review_size -le 4096 ]] ||
    die "review receipt exceeds byte cap 4096"
review_parent_arg=${review_receipt_arg%/*}
review_name=${review_receipt_arg##*/}
[[ -n $review_parent_arg && -n $review_name ]] ||
    die "review receipt path is malformed"
review_parent=$(canonical_directory "$review_parent_arg" "review receipt parent")
review_receipt=$review_parent/$review_name
[[ $review_receipt == "$review_receipt_arg" ]] ||
    die "review receipt path must already be canonical"
case $review_receipt in
    "$bundle"/*) die "review receipt must be outside the resealable bundle" ;;
esac
[[ $(stat -f '%l' -- "$review_receipt") == 1 ]] ||
    die "review receipt must not be multiply linked"
/bin/dd \
    if="$review_receipt" \
    of="$temporary/independent-review.tsv" \
    bs=4097 \
    count=1 \
    2>/dev/null ||
    die "cannot snapshot bounded review receipt"
snapshot_review_size=$(stat -f '%z' -- "$temporary/independent-review.tsv") ||
    die "cannot determine snapshotted review receipt size"
[[ $snapshot_review_size == "$review_size" && $snapshot_review_size -le 4096 ]] ||
    die "review receipt changed or exceeded its cap while being snapshotted"
chmod 0400 "$temporary/independent-review.tsv"
review_sha=$(fre_c5_sha256 "$temporary/independent-review.tsv")
[[ $review_sha == "$expected_review_sha" ]] ||
    die "review receipt differs from its independently supplied SHA-256"
fre_c5_require_text_bounds \
    "$temporary/independent-review.tsv" 4096 256 24 "independent review receipt"
awk -F '	' \
    -v candidate="$candidate" \
    -v tree="$expected_tree" \
    -v source="$expected_source" \
    -v binary="$expected_binary" \
    -v cargo="$expected_cargo_sha" \
    -v rustc="$expected_rustc_sha" \
    -v rustdoc="$expected_rustdoc_sha" \
    -v closure="$expected_toolchain_closure_sha" \
    -v closure_entries="$expected_toolchain_closure_entries" \
    -v closure_bytes="$expected_toolchain_closure_bytes" \
    -v registry="$expected_cargo_registry_closure_sha" \
    -v registry_entries="$expected_cargo_registry_closure_entries" \
    -v registry_bytes="$expected_cargo_registry_closure_bytes" \
    -v coordinator="$expected_resource_coordinator_sha" \
    -v cutover="$expected_cutover_receipt_sha" \
    -v manifest="$expected_manifest" '
    NR == 1 && (NF != 2 || $1 != "schema" ||
        $2 != "fre-aot-count-c5-independent-review-v3") { bad = 1 }
    NR == 2 && (NF != 2 || $1 != "candidate_commit" ||
        $2 != candidate) { bad = 1 }
    NR == 3 && (NF != 2 || $1 != "candidate_tree" ||
        $2 != tree) { bad = 1 }
    NR == 4 && (NF != 2 || $1 != "benchmark_source_sha256" ||
        $2 != source) { bad = 1 }
    NR == 5 && (NF != 2 || $1 != "benchmark_binary_sha256" ||
        $2 != binary) { bad = 1 }
    NR == 6 && (NF != 2 || $1 != "cargo_binary_sha256" ||
        $2 != cargo) { bad = 1 }
    NR == 7 && (NF != 2 || $1 != "rustc_binary_sha256" ||
        $2 != rustc) { bad = 1 }
    NR == 8 && (NF != 2 || $1 != "rustdoc_binary_sha256" ||
        $2 != rustdoc) { bad = 1 }
    NR == 9 && (NF != 2 || $1 != "toolchain_closure_sha256" ||
        $2 != closure) { bad = 1 }
    NR == 10 && (NF != 2 || $1 != "toolchain_closure_entries" ||
        $2 != closure_entries) { bad = 1 }
    NR == 11 && (NF != 2 || $1 != "toolchain_closure_bytes" ||
        $2 != closure_bytes) { bad = 1 }
    NR == 12 && (NF != 2 || $1 != "cargo_registry_closure_sha256" ||
        $2 != registry) { bad = 1 }
    NR == 13 && (NF != 2 || $1 != "cargo_registry_closure_entries" ||
        $2 != registry_entries) { bad = 1 }
    NR == 14 && (NF != 2 || $1 != "cargo_registry_closure_bytes" ||
        $2 != registry_bytes) { bad = 1 }
    NR == 15 && (NF != 2 || $1 != "resource_coordinator_sha256" ||
        $2 != coordinator) { bad = 1 }
    NR == 16 &&
        (NF != 2 || $1 != "resource_coordinator_cutover_receipt_sha256" ||
         $2 != cutover) { bad = 1 }
    NR == 17 && (NF != 2 || $1 != "bundle_manifest_sha256" ||
        $2 != manifest) { bad = 1 }
    NR == 18 && (NF != 2 || $1 != "evidence_class" ||
        $2 != "measured") { bad = 1 }
    NR == 19 && (NF != 2 || $1 != "verifier_commit" ||
        $2 != candidate) { bad = 1 }
    NR == 20 {
        if (NF != 2 || $1 != "dependency_rederive_sha256") bad = 1
        if (length($2) != 64 || $2 ~ /[^0-9a-f]/ ||
            $2 == "0000000000000000000000000000000000000000000000000000000000000000") {
            bad = 1
        }
    }
    NR == 21 {
        if (NF != 2 || $1 != "review_evidence_sha256") bad = 1
        if (length($2) != 64 || $2 ~ /[^0-9a-f]/ ||
            $2 == "0000000000000000000000000000000000000000000000000000000000000000") {
            bad = 1
        }
    }
    NR == 22 && (NF != 2 || $1 != "overall" || $2 != "PASS") {
        bad = 1
    }
    END { if (NR != 22 || bad) exit 1 }
' "$temporary/independent-review.tsv" ||
    die "independent review receipt is not the exact measured Candidate receipt"
review_dependency_rederive_sha=$(awk -F '	' \
    '$1 == "dependency_rederive_sha256" { print $2 }' \
    "$temporary/independent-review.tsv")

"$temporary/trusted/verify-qualification-bundle.sh" \
    "$candidate" \
    "$expected_tree" \
    "$expected_source" \
    "$expected_binary" \
    "$expected_manifest" \
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
    "$bundle" \
    "$repository" \
    > "$temporary/bundle-verification.txt" ||
    die "candidate-extracted qualification-bundle verifier rejected the bundle"
fre_c5_require_text_bounds \
    "$temporary/bundle-verification.txt" 4096 2048 2 \
    "candidate bundle verification result"
bundle_dependency_rederive_sha=$(awk -F, \
    -v candidate="$candidate" \
    -v tree="$expected_tree" \
    -v source="$expected_source" \
    -v binary="$expected_binary" \
    -v manifest="$expected_manifest" '
    NR == 1 {
        if (NF != 14 ||
            $1 != "VERIFIED_BUNDLE" ||
            $2 != "commit=" candidate ||
            $3 != "tree=" tree ||
            $4 != "source=" source ||
            $5 != "binary=" binary ||
            $6 != "manifest=" manifest ||
            $8 != "static_dependency_contract=true" ||
            $9 != "VERIFIED" ||
            $10 != "processes=3" ||
            $11 != "cells=174" ||
            $12 != "pairs=2784") {
            bad = 1
        }
        prefix = "dependency_rederive_sha256="
        if (index($7, prefix) != 1) {
            bad = 1
        } else {
            digest = substr($7, length(prefix) + 1)
            if (length(digest) != 64 || digest ~ /[^0-9a-f]/ ||
                digest == "0000000000000000000000000000000000000000000000000000000000000000") {
                bad = 1
            }
        }
        if (index($13, "pair_wins=") != 1 ||
            index($14, "pair_win_rate=") != 1) {
            bad = 1
        }
    }
    END {
        if (NR != 1 || bad) exit 1
        print digest
    }
    ' "$temporary/bundle-verification.txt") ||
    die "candidate bundle verifier emitted a malformed result"
[[ $bundle_dependency_rederive_sha == "$review_dependency_rederive_sha" ]] ||
    die "independent review did not reproduce the pinned dependency report"

printf 'PROMOTION_VERIFIED,candidate=%s,promoted=%s,tree=%s,source=%s,binary=%s,manifest=%s,review=%s,dependency_rederive=%s,scope=%s,aot_atom_exact=true,direct_child=true,candidate_rooted_verifier=true\n' \
    "$candidate" "$promoted" "$expected_tree" "$expected_source" \
    "$expected_binary" "$expected_manifest" "$review_sha" \
    "$bundle_dependency_rederive_sha" "$scope"
