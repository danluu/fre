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
usage: test-qualification-bundle.sh EXPECTED_COMMIT EXPECTED_TREE EXPECTED_SOURCE_SHA256 EXPECTED_BINARY_SHA256 EXPECTED_MANIFEST_SHA256 EXPECTED_CARGO_SHA256 EXPECTED_RUSTC_SHA256 EXPECTED_RUSTDOC_SHA256 EXPECTED_TOOLCHAIN_CLOSURE_SHA256 EXPECTED_TOOLCHAIN_CLOSURE_ENTRIES EXPECTED_TOOLCHAIN_CLOSURE_BYTES EXPECTED_CARGO_REGISTRY_CLOSURE_SHA256 EXPECTED_CARGO_REGISTRY_CLOSURE_ENTRIES EXPECTED_CARGO_REGISTRY_CLOSURE_BYTES EXPECTED_RESOURCE_COORDINATOR_SHA256 EXPECTED_CUTOVER_RECEIPT_SHA256 BUNDLE_DIR REPOSITORY

Require one valid bundle, then prove that stale-manifest, source, binary,
binding, symlink, hardlink, missing-file, inventory, and resource-bound
mutations fail closed.
EOF
    exit 2
}

[[ $# -eq 18 ]] || usage
expected_commit=$1
expected_tree=$2
expected_source=$3
expected_binary=$4
expected_manifest=$5
expected_cargo_sha=$6
expected_rustc_sha=$7
expected_rustdoc_sha=$8
expected_toolchain_closure_sha=$9
expected_toolchain_closure_entries=${10}
expected_toolchain_closure_bytes=${11}
expected_cargo_registry_closure_sha=${12}
expected_cargo_registry_closure_entries=${13}
expected_cargo_registry_closure_bytes=${14}
expected_resource_coordinator_sha=${15}
expected_cutover_receipt_sha=${16}
bundle=${17}
repository=${18}

verifier=$script_dir/verify-qualification-bundle.sh
fre_c5_require_regular "$verifier" "bundle verifier"

verify() {
    local manifest=$1
    local candidate=$2
    "$verifier" \
        "$expected_commit" \
        "$expected_tree" \
        "$expected_source" \
        "$expected_binary" \
        "$manifest" \
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
        "$candidate" \
        "$repository"
}

hostile_tmpdir=/private/tmp/fre-aot-c5-bundle-hostile-tmp-does-not-exist-$$
[[ ! -e $hostile_tmpdir && ! -L $hostile_tmpdir ]] ||
    fre_c5_die "hostile TMPDIR refusal path unexpectedly exists"
(
    export TMPDIR="$hostile_tmpdir"
    export TAR_OPTIONS=--fre-aot-c5-hostile-tar-option
    verify "$expected_manifest" "$bundle"
) > /dev/null
[[ ! -e $hostile_tmpdir && ! -L $hostile_tmpdir ]] ||
    fre_c5_die "bundle verifier honored the hostile caller TMPDIR"

temporary=$(mktemp -d "/private/tmp/fre-aot-c5-bundle-test.XXXXXX") ||
    fre_c5_die "cannot create bundle-test scratch directory"
temporary_identity=$(
    fre_c5_owned_directory_identity "$temporary" "bundle-test scratch directory"
)
cleanup() {
    local status=$?
    local cleanup_failed=false
    if [[ -n ${temporary:-} && ( -e $temporary || -L $temporary ) ]]; then
        if [[ -z ${temporary_identity:-} ]] ||
            ! fre_c5_cleanup_owned_directory \
                "$temporary" "$temporary_identity" \
                /private/tmp/fre-aot-c5-bundle-test. \
                "bundle-test scratch directory"; then
            printf '%s\n' \
                "c5-qualification: refused unsafe bundle-test cleanup" >&2
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

copy_case() {
    local name=$1
    local target=$temporary/$name
    mkdir "$target"
    cp -pR -- "$bundle/." "$target/"
    printf '%s\n' "$target"
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

assert_rejected() {
    local name=$1
    local manifest=$2
    local target=$3
    if verify "$manifest" "$target" \
        > "$temporary/$name.stdout" 2> "$temporary/$name.stderr"; then
        fre_c5_die "bundle verifier accepted adversarial case: $name"
    fi
}

assert_rejected_with() {
    local name=$1
    local expected_error=$2
    local manifest=$3
    local target=$4
    assert_rejected "$name" "$manifest" "$target"
    grep -F "$expected_error" "$temporary/$name.stderr" > /dev/null ||
        fre_c5_die "bundle verifier rejected $name for the wrong reason"
}

target=$(copy_case stale-manifest)
printf 'tamper\n' >> "$target/run-1.time"
assert_rejected stale-manifest "$expected_manifest" "$target"

target=$(copy_case source-tamper)
printf 'tamper\n' >> "$target/source.tar"
manifest=$(rewrite_manifest "$target")
assert_rejected source-tamper "$manifest" "$target"

target=$(copy_case binary-tamper)
chmod u+w "$target/candidate-binary"
printf 'tamper\n' >> "$target/candidate-binary"
chmod 0555 "$target/candidate-binary"
manifest=$(rewrite_manifest "$target")
assert_rejected binary-tamper "$manifest" "$target"

target=$(copy_case coordinator-tamper)
chmod u+w "$target/resource-coordinator"
printf 'tamper\n' >> "$target/resource-coordinator"
chmod 0555 "$target/resource-coordinator"
manifest=$(rewrite_manifest "$target")
assert_rejected coordinator-tamper "$manifest" "$target"

target=$(copy_case binding-tamper)
awk -F '	' -v OFS='	' '
    $1 == "benchmark_source_sha256" {
        $2 = "0000000000000000000000000000000000000000000000000000000000000001"
    }
    { print }
' "$target/binding.tsv" > "$target/binding.rewrite"
mv -- "$target/binding.rewrite" "$target/binding.tsv"
manifest=$(rewrite_manifest "$target")
assert_rejected binding-tamper "$manifest" "$target"

target=$(copy_case symlink-tamper)
mv -- "$target/run-1.time" "$target/real-run-1.time"
ln -s real-run-1.time "$target/run-1.time"
manifest=$(rewrite_manifest "$target")
assert_rejected symlink-tamper "$manifest" "$target"

target=$(copy_case hardlink-tamper)
rm -- "$target/run-1.time"
ln "$target/run-2.time" "$target/run-1.time"
manifest=$(rewrite_manifest "$target")
assert_rejected hardlink-tamper "$manifest" "$target"

target=$(copy_case missing-file)
rm -- "$target/run-3.time"
manifest=$(rewrite_manifest "$target")
assert_rejected missing-file "$manifest" "$target"

target=$(copy_case inventory-overflow)
printf 'unexpected\n' > "$target/unexpected-file"
manifest=$(rewrite_manifest "$target")
assert_rejected_with inventory-overflow "inventory exceeds 25 top-level entries" \
    "$manifest" "$target"

target=$(copy_case oversized-manifest)
dd if=/dev/zero bs=4096 count=2 >> "$target/manifest.sha256" 2>/dev/null
manifest=$(fre_c5_sha256 "$target/manifest.sha256")
assert_rejected_with oversized-manifest "bundle manifest exceeds byte cap 4096" \
    "$manifest" "$target"

target=$(copy_case overlong-manifest-line)
awk '
    NR == 1 {
        for (ordinal = 0; ordinal < 300; ordinal++) $0 = $0 "x"
    }
    { print }
' "$target/manifest.sha256" > "$target/manifest.rewrite"
mv -- "$target/manifest.rewrite" "$target/manifest.sha256"
manifest=$(fre_c5_sha256 "$target/manifest.sha256")
assert_rejected_with overlong-manifest-line \
    "bundle manifest exceeds line-length or line-count cap" "$manifest" "$target"

target=$(copy_case oversized-raw-run)
dd if=/dev/zero bs=1048576 count=1 >> "$target/run-1.csv" 2>/dev/null
manifest=$(rewrite_manifest "$target")
assert_rejected_with oversized-raw-run "raw run exceeds byte cap 1048576" \
    "$manifest" "$target"

target=$(copy_case overlong-raw-line)
awk 'BEGIN { for (ordinal = 0; ordinal < 600; ordinal++) printf "x"; print "" }' \
    >> "$target/run-1.csv"
manifest=$(rewrite_manifest "$target")
assert_rejected_with overlong-raw-line \
    "raw run exceeds line-length or line-count cap" "$manifest" "$target"

target=$(copy_case oversized-verification-result)
dd if=/dev/zero bs=2048 count=1 >> "$target/raw-verification.txt" 2>/dev/null
manifest=$(rewrite_manifest "$target")
assert_rejected_with oversized-verification-result \
    "raw verification result exceeds byte cap 1024" "$manifest" "$target"

printf 'VERIFIED_BUNDLE_ADVERSARIAL,positive=1,rejected=14,cases=stale-manifest+source+binary+coordinator+binding+symlink+hardlink+missing+inventory+resource-bounds,hostile_tmpdir_ignored=true,hostile_tar_options_ignored=true\n'
