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
usage: build-qualified-candidate.sh EXPECTED_COMMIT EXPECTED_TREE EXPECTED_SOURCE_SHA256 EXPECTED_BINARY_SHA256 TOOLCHAIN_ROOT EXPECTED_CARGO_SHA256 EXPECTED_RUSTC_SHA256 EXPECTED_RUSTDOC_SHA256 EXPECTED_TOOLCHAIN_CLOSURE_SHA256 EXPECTED_TOOLCHAIN_CLOSURE_ENTRIES EXPECTED_TOOLCHAIN_CLOSURE_BYTES CARGO_REGISTRY_ROOT EXPECTED_CARGO_REGISTRY_CLOSURE_SHA256 EXPECTED_CARGO_REGISTRY_CLOSURE_ENTRIES EXPECTED_CARGO_REGISTRY_CLOSURE_BYTES RESOURCE_COORDINATOR EXPECTED_RESOURCE_COORDINATOR_SHA256 CUTOVER_RECEIPT EXPECTED_CUTOVER_RECEIPT_SHA256 OUTPUT_DIR

Rebuild the exact C5 candidate twice in independent target directories,
regenerate its custom-emitter objects, and publish a sealed build receipt.
Every expected identity is supplied externally; the script never discovers an
identity and then treats that discovered value as authority. TOOLCHAIN_ROOT
must contain direct regular bin/cargo, bin/rustc, and bin/rustdoc executables;
rustup proxies are not accepted. CARGO_REGISTRY_ROOT is the complete externally
pinned registry subtree copied under a private, configuration-free CARGO_HOME.
EOF
    exit 2
}

[[ $# -eq 20 ]] || usage
expected_commit=$1
expected_tree=$2
expected_source=$3
expected_binary=$4
toolchain_root_arg=$5
expected_cargo_sha=$6
expected_rustc_sha=$7
expected_rustdoc_sha=$8
expected_toolchain_closure_sha=$9
expected_toolchain_closure_entries=${10}
expected_toolchain_closure_bytes=${11}
cargo_registry_root_arg=${12}
expected_cargo_registry_closure_sha=${13}
expected_cargo_registry_closure_entries=${14}
expected_cargo_registry_closure_bytes=${15}
resource_coordinator_arg=${16}
expected_resource_coordinator_sha=${17}
cutover_receipt_arg=${18}
expected_cutover_receipt_sha=${19}
output=${20}

fre_c5_require_nonzero_sha256 "$expected_binary" "expected benchmark binary SHA-256"
fre_c5_require_nonzero_sha256 "$expected_cargo_sha" "expected Cargo binary SHA-256"
fre_c5_require_nonzero_sha256 "$expected_rustc_sha" "expected rustc binary SHA-256"
fre_c5_require_nonzero_sha256 "$expected_rustdoc_sha" "expected rustdoc binary SHA-256"
fre_c5_require_nonzero_sha256 \
    "$expected_toolchain_closure_sha" "expected toolchain closure SHA-256"
fre_c5_require_bounded_positive_decimal \
    "$expected_toolchain_closure_entries" 16384 \
    "expected toolchain closure entry count"
fre_c5_require_bounded_positive_decimal \
    "$expected_toolchain_closure_bytes" 4294967296 \
    "expected toolchain closure byte count"
fre_c5_require_nonzero_sha256 \
    "$expected_cargo_registry_closure_sha" \
    "expected Cargo registry closure SHA-256"
fre_c5_require_bounded_positive_decimal \
    "$expected_cargo_registry_closure_entries" 100000 \
    "expected Cargo registry closure entry count"
fre_c5_require_bounded_positive_decimal \
    "$expected_cargo_registry_closure_bytes" 4294967296 \
    "expected Cargo registry closure byte count"
fre_c5_require_nonzero_sha256 \
    "$expected_resource_coordinator_sha" "expected resource coordinator SHA-256"
fre_c5_require_nonzero_sha256 \
    "$expected_cutover_receipt_sha" "expected cutover receipt SHA-256"
fre_c5_require_new_output_path "$output"
toolchain_root=$(fre_c5_canonical_directory "$toolchain_root_arg")
cargo_registry_root=$(fre_c5_canonical_directory "$cargo_registry_root_arg")
fre_c5_require_absolute_path_value "$toolchain_root" "toolchain root"
fre_c5_require_absolute_path_value "$cargo_registry_root" "Cargo registry root"
resource_coordinator=$(
    fre_c5_canonical_regular_file \
        "$resource_coordinator_arg" "resource coordinator"
)
[[ -x $resource_coordinator ]] ||
    fre_c5_die "resource coordinator must be directly executable"
cutover_receipt=$(
    fre_c5_canonical_regular_file "$cutover_receipt_arg" "cutover receipt"
)
cargo_tool=$toolchain_root/bin/cargo
rustc_tool=$toolchain_root/bin/rustc
rustdoc_tool=$toolchain_root/bin/rustdoc
clang_tool=/usr/bin/clang
for tool_spec in \
    "$cargo_tool:Cargo" \
    "$rustc_tool:rustc" \
    "$rustdoc_tool:rustdoc"; do
    tool=${tool_spec%%:*}
    label=${tool_spec##*:}
    fre_c5_require_regular "$tool" "$label tool"
    [[ -x $tool ]] || fre_c5_die "$label tool is not executable: $tool"
done
fre_c5_require_regular "$clang_tool" "Apple clang tool"
[[ -x $clang_tool ]] || fre_c5_die "Apple clang tool is not executable"
[[ $(fre_c5_sha256 "$cargo_tool") == "$expected_cargo_sha" ]] ||
    fre_c5_die "Cargo tool differs from externally expected SHA-256"
[[ $(fre_c5_sha256 "$rustc_tool") == "$expected_rustc_sha" ]] ||
    fre_c5_die "rustc tool differs from externally expected SHA-256"
[[ $(fre_c5_sha256 "$rustdoc_tool") == "$expected_rustdoc_sha" ]] ||
    fre_c5_die "rustdoc tool differs from externally expected SHA-256"
for child in cache index src; do
    [[ -d $cargo_registry_root/$child &&
        ! -L $cargo_registry_root/$child ]] ||
        fre_c5_die "Cargo registry root lacks a physical $child directory"
done

subject_repository=$(git -C "$script_dir" rev-parse --show-toplevel) ||
    fre_c5_die "cannot resolve repository root"
subject_repository=$(fre_c5_canonical_directory "$subject_repository")
grafts=$(git -C "$subject_repository" rev-parse --git-path info/grafts) ||
    fre_c5_die "cannot resolve repository graft path"
case $grafts in
    /*) ;;
    *) grafts=$subject_repository/$grafts ;;
esac
[[ ! -e $grafts && ! -L $grafts ]] ||
    fre_c5_die "subject repository contains an info/grafts override"
replace_ref=$(git -C "$subject_repository" for-each-ref \
    --format='%(refname)' refs/replace | sed -n '1p') ||
    fre_c5_die "cannot inspect subject replacement refs"
[[ -z $replace_ref ]] ||
    fre_c5_die "subject repository contains replacement refs"
[[ $(git -C "$subject_repository" rev-parse --is-shallow-repository) == false ]] ||
    fre_c5_die "subject repository must be complete and non-shallow"
fre_c5_require_no_archive_attribute_overrides "$subject_repository"
fre_c5_require_subject \
    "$subject_repository" "$expected_commit" "$expected_tree" "$expected_source" true

subject_benchmark=$subject_repository/crates/fre-aot-count-compiler/benchmarks/c5-qualified-vs-portable
subject_evidence=$subject_repository/crates/fre-aot-count-compiler/evidence/c5-count-v2-candidate
for path in \
    "$subject_benchmark/Cargo.toml" \
    "$subject_benchmark/Cargo.lock" \
    "$subject_benchmark/build.rs" \
    "$subject_benchmark/src/main.rs" \
    "$subject_evidence/SHA256SUMS" \
    "$subject_evidence/implementation.o" \
    "$subject_evidence/final-image-glue.o" \
    "$subject_evidence/expectation.bin"; do
    fre_c5_require_regular "$path" "candidate input"
done
special=$(find "$subject_benchmark" "$subject_evidence" \
    ! -type d ! -type f -print -quit)
[[ -z $special ]] || fre_c5_die "candidate inputs contain a symlink or special object: $special"
(
    cd "$subject_evidence"
    /usr/bin/shasum -a 256 -c SHA256SUMS
) >/dev/null || fre_c5_die "retained C5 evidence manifest failed"

temporary=$(mktemp -d "/private/tmp/fre-aot-c5-build.XXXXXX") ||
    fre_c5_die "cannot create build scratch directory"
[[ $temporary =~ ^/private/tmp/fre-aot-c5-build\.[A-Za-z0-9]{6}$ ]] ||
    fre_c5_die "build scratch directory does not have the fixed reproducible layout"
temporary_identity=$(
    fre_c5_owned_directory_identity "$temporary" "build scratch directory"
)
cleanup() {
    local status=$?
    local cleanup_failed=false
    if [[ -n ${publish:-} && ( -e $publish || -L $publish ) ]]; then
        if [[ -z ${publish_identity:-} || -z ${publish_namespace:-} ]] ||
            ! fre_c5_cleanup_owned_directory \
                "$publish" "$publish_identity" "$publish_namespace" \
                "build publication scratch directory"; then
            printf '%s\n' \
                "c5-qualification: refused unsafe build publication cleanup" >&2
            cleanup_failed=true
        fi
    fi
    if [[ -n ${temporary:-} && ( -e $temporary || -L $temporary ) ]]; then
        if [[ -z ${temporary_identity:-} ]] ||
            ! fre_c5_cleanup_owned_directory \
                "$temporary" "$temporary_identity" \
                /private/tmp/fre-aot-c5-build. \
                "build scratch directory"; then
            printf '%s\n' \
                "c5-qualification: refused unsafe build scratch cleanup" >&2
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

controlled_home=$temporary/home
tool_tmp=$temporary/tool-tmp
cargo_cwd=$temporary/cargo-cwd
cargo_home=$temporary/cargo-home
mkdir -m 0700 "$controlled_home" "$tool_tmp" "$cargo_cwd" "$cargo_home"
resource_coordinator_snapshot=$temporary/resource-coordinator
cutover_receipt_snapshot=$temporary/resource-coordinator-cutover-receipt
fre_c5_snapshot_pinned_file \
    "$resource_coordinator" "$expected_resource_coordinator_sha" \
    16777216 "resource coordinator" "$resource_coordinator_snapshot"
[[ -x $resource_coordinator_snapshot ]] ||
    fre_c5_die "snapshotted resource coordinator is not executable"
fre_c5_snapshot_pinned_file \
    "$cutover_receipt" "$expected_cutover_receipt_sha" \
    1048576 "cutover receipt" "$cutover_receipt_snapshot"
cargo_build_jobs=${FRE_CARGO_BUILD_JOBS:-${CARGO_BUILD_JOBS:-}}
if [[ -n $cargo_build_jobs &&
    ! $cargo_build_jobs =~ ^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-6])$ ]]; then
    fre_c5_die "Cargo build jobs must be an integer from 1 through 256"
fi
cargo_job_environment=()
if [[ -n $cargo_build_jobs ]]; then
    cargo_job_environment=("CARGO_BUILD_JOBS=$cargo_build_jobs")
fi

toolchain_closure_record=$(
    fre_c5_toolchain_closure_fingerprint "$toolchain_root"
) || fre_c5_die "cannot fingerprint the Rust toolchain closure"
[[ $toolchain_closure_record != *$'\n'* ]] ||
    fre_c5_die "Rust toolchain closure fingerprint emitted multiple records"
IFS=$'\t' read -r toolchain_closure_sha toolchain_closure_entries \
    toolchain_closure_bytes closure_extra \
    <<< "$toolchain_closure_record"
[[ -z ${closure_extra:-} ]] ||
    fre_c5_die "Rust toolchain closure fingerprint emitted extra fields"
fre_c5_require_nonzero_sha256 \
    "$toolchain_closure_sha" "observed toolchain closure SHA-256"
[[ $toolchain_closure_sha == "$expected_toolchain_closure_sha" ]] ||
    fre_c5_die "Rust toolchain closure differs from externally expected SHA-256"
[[ $toolchain_closure_entries == "$expected_toolchain_closure_entries" ]] ||
    fre_c5_die "Rust toolchain closure entry count differs from external pin"
[[ $toolchain_closure_bytes == "$expected_toolchain_closure_bytes" ]] ||
    fre_c5_die "Rust toolchain closure byte count differs from external pin"

require_expected_toolchain_closure() {
    local phase=$1
    local observed
    observed=$(fre_c5_toolchain_closure_fingerprint "$toolchain_root") ||
        fre_c5_die "cannot fingerprint Rust toolchain closure $phase"
    [[ $observed == "$toolchain_closure_record" ]] ||
        fre_c5_die "Rust toolchain closure changed $phase"
}

rustc_sysroot=$(
    /usr/bin/env -i \
        LC_ALL=C \
        TZ=UTC \
        PATH=/usr/bin:/bin:/usr/sbin:/sbin \
        "$rustc_tool" --print sysroot
) || fre_c5_die "cannot query the direct rustc sysroot"
[[ $rustc_sysroot == /* && -d $rustc_sysroot && ! -L $rustc_sysroot ]] ||
    fre_c5_die "direct rustc reported a non-canonical sysroot"
rustc_sysroot=$(CDPATH= cd -P -- "$rustc_sysroot" && pwd -P) ||
    fre_c5_die "cannot canonicalize the direct rustc sysroot"
[[ $rustc_sysroot == "$toolchain_root" ]] ||
    fre_c5_die "direct rustc sysroot differs from TOOLCHAIN_ROOT"
require_expected_toolchain_closure "after direct rustc sysroot query"

cargo_registry_closure_record=$(
    fre_c5_cargo_registry_closure_fingerprint "$cargo_registry_root"
) || fre_c5_die "cannot fingerprint the Cargo registry closure"
[[ $cargo_registry_closure_record != *$'\n'* ]] ||
    fre_c5_die "Cargo registry closure fingerprint emitted multiple records"
IFS=$'\t' read -r cargo_registry_closure_sha \
    cargo_registry_closure_entries cargo_registry_closure_bytes closure_extra \
    <<< "$cargo_registry_closure_record"
[[ -z ${closure_extra:-} ]] ||
    fre_c5_die "Cargo registry closure fingerprint emitted extra fields"
fre_c5_require_nonzero_sha256 \
    "$cargo_registry_closure_sha" "observed Cargo registry closure SHA-256"
[[ $cargo_registry_closure_sha == "$expected_cargo_registry_closure_sha" ]] ||
    fre_c5_die "Cargo registry closure differs from externally expected SHA-256"
[[ $cargo_registry_closure_entries == \
    "$expected_cargo_registry_closure_entries" ]] ||
    fre_c5_die "Cargo registry closure entry count differs from external pin"
[[ $cargo_registry_closure_bytes == \
    "$expected_cargo_registry_closure_bytes" ]] ||
    fre_c5_die "Cargo registry closure byte count differs from external pin"

/bin/cp -pR -- "$cargo_registry_root" "$cargo_home/registry" ||
    fre_c5_die "cannot snapshot the externally pinned Cargo registry"
[[ $(fre_c5_cargo_registry_closure_fingerprint "$cargo_home/registry") == \
    "$cargo_registry_closure_record" ]] ||
    fre_c5_die "private Cargo registry snapshot differs from external closure"
[[ $(fre_c5_cargo_registry_closure_fingerprint "$cargo_registry_root") == \
    "$cargo_registry_closure_record" ]] ||
    fre_c5_die "Cargo registry source changed while being snapshotted"
for config in "$cargo_home/config" "$cargo_home/config.toml"; do
    [[ ! -e $config && ! -L $config ]] ||
        fre_c5_die "private Cargo home unexpectedly contains configuration"
done

source_snapshot_fingerprint() {
    local source_root=$1
    /usr/bin/env -i \
        LC_ALL=C \
        TZ=UTC \
        PATH=/usr/bin:/bin \
        /usr/bin/python3 -I -B - "$source_root" <<'PY'
import hashlib
import os
import stat
import sys

root = os.fsencode(sys.argv[1])
digest = hashlib.sha256()


def add(value: bytes) -> None:
    digest.update(len(value).to_bytes(8, "big"))
    digest.update(value)


def visit(directory: bytes, relative: bytes) -> None:
    entries = sorted(os.scandir(directory), key=lambda entry: os.fsencode(entry.name))
    for entry in entries:
        name = os.fsencode(entry.name)
        child_relative = name if not relative else relative + b"/" + name
        metadata = entry.stat(follow_symlinks=False)
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISDIR(metadata.st_mode):
            if mode & 0o222:
                raise SystemExit(f"writable source directory: {os.fsdecode(child_relative)}")
            digest.update(b"D")
            add(child_relative)
            digest.update(mode.to_bytes(4, "big"))
            visit(os.path.join(directory, name), child_relative)
        elif stat.S_ISREG(metadata.st_mode):
            if mode & 0o222:
                raise SystemExit(f"writable source file: {os.fsdecode(child_relative)}")
            digest.update(b"F")
            add(child_relative)
            digest.update(mode.to_bytes(4, "big"))
            digest.update(metadata.st_size.to_bytes(8, "big"))
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(os.path.join(directory, name), flags)
            try:
                before = os.fstat(descriptor)
                while True:
                    chunk = os.read(descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                after = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            if (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_size,
                before.st_mtime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_size,
                after.st_mtime_ns,
            ):
                raise SystemExit(
                    f"source changed during fingerprint: {os.fsdecode(child_relative)}"
                )
        else:
            raise SystemExit(f"special source object: {os.fsdecode(child_relative)}")


visit(root, b"")
print(digest.hexdigest())
PY
}

require_cargo_config_boundary() {
    local invocation_root=$1
    local ancestor=$invocation_root
    while true; do
        for config in "$ancestor/.cargo/config" "$ancestor/.cargo/config.toml"; do
            [[ ! -e $config && ! -L $config ]] ||
                fre_c5_die "ambient Cargo configuration is present: $config"
        done
        [[ $ancestor != / ]] || break
        ancestor=${ancestor%/*}
        [[ -n $ancestor ]] || ancestor=/
    done
}

require_cargo_config_boundary "$cargo_cwd"

# Every compiler, linker, regeneration, and dependency-inspection input below
# comes from immutable exact-commit archives, never from the live worktree.
# Two physically distinct extractions plus one virtual source prefix make the
# byte-identical rebuild gate meaningful across source paths.
git -c tar.umask=0002 -c core.attributesFile=/dev/null \
    -C "$subject_repository" \
    archive --format=tar "$expected_commit" \
    > "$temporary/source.tar"
[[ $(git get-tar-commit-id < "$temporary/source.tar") == "$expected_commit" ]] ||
    fre_c5_die "source archive does not carry the exact Candidate commit"
source_archive=$(fre_c5_sha256 "$temporary/source.tar")
source_a=$temporary/source-a
source_b=$temporary/source-b
mkdir -m 0700 "$source_a" "$source_b"
for source_root in "$source_a" "$source_b"; do
    /usr/bin/env -i \
        LC_ALL=C \
        TZ=UTC \
        PATH=/usr/bin:/bin \
        /usr/bin/tar -xf "$temporary/source.tar" -C "$source_root" ||
        fre_c5_die "cannot extract exact Candidate source snapshot"
    special=$(find "$source_root" ! -type d ! -type f -print -quit)
    [[ -z $special ]] ||
        fre_c5_die "Candidate source snapshot contains a symlink or special object: $special"
    fre_c5_require_exact_git_snapshot \
        "$subject_repository" "$expected_commit" "$source_root"
    snapshot_source=$(fre_c5_benchmark_source_sha256 "$source_root")
    [[ $snapshot_source == "$expected_source" ]] ||
        fre_c5_die "Candidate source snapshot differs from expected source identity"
    snapshot_evidence=$source_root/crates/fre-aot-count-compiler/evidence/c5-count-v2-candidate
    (
        cd "$snapshot_evidence"
        /usr/bin/shasum -a 256 -c SHA256SUMS
    ) >/dev/null || fre_c5_die "snapshot C5 evidence manifest failed"
    chmod -R a-w "$source_root"
    fingerprint=$(source_snapshot_fingerprint "$source_root") ||
        fre_c5_die "cannot fingerprint read-only Candidate source snapshot"
    if [[ $source_root == "$source_a" ]]; then
        source_a_fingerprint=$fingerprint
    else
        source_b_fingerprint=$fingerprint
    fi
done
[[ $source_a_fingerprint == "$source_b_fingerprint" ]] ||
    fre_c5_die "independent Candidate source snapshots differ"

repository=$source_a
benchmark=$repository/crates/fre-aot-count-compiler/benchmarks/c5-qualified-vs-portable
evidence=$repository/crates/fre-aot-count-compiler/evidence/c5-count-v2-candidate
for source_root in "$source_a" "$source_b"; do
    fre_c5_require_registry_or_path_lockfile \
        "$source_root/Cargo.lock" "workspace Cargo lock"
    fre_c5_require_registry_or_path_lockfile \
        "$source_root/crates/fre-aot-count-compiler/benchmarks/c5-qualified-vs-portable/Cargo.lock" \
        "standalone benchmark Cargo lock"
done

run_build() {
    local name=$1
    local build_dir=$2
    local coordinator_status=0
    shift 2
    [[ $(fre_c5_sha256 "$resource_coordinator") == \
        "$expected_resource_coordinator_sha" &&
        $(fre_c5_sha256 "$cutover_receipt") == \
        "$expected_cutover_receipt_sha" ]] ||
        fre_c5_die "coordinator admission identity changed before build"
    "$resource_coordinator" run-build "$name" \
        --wait-seconds 0 \
        --build-dir "$build_dir" -- "$@" ||
        coordinator_status=$?
    [[ $(fre_c5_sha256 "$resource_coordinator") == \
        "$expected_resource_coordinator_sha" &&
        $(fre_c5_sha256 "$cutover_receipt") == \
        "$expected_cutover_receipt_sha" ]] ||
        fre_c5_die "coordinator admission identity changed during build"
    [[ $coordinator_status == 0 ]] ||
        fre_c5_die "resource coordinator rejected or failed build: $name"
}

run_snapshot_build() {
    local name=$1
    local build_dir=$2
    local source_root=$3
    shift 3
    (
        cd "$cargo_cwd"
        require_cargo_config_boundary "$cargo_cwd"
        run_build "$name" "$build_dir" \
            /usr/bin/env -i \
            LC_ALL=C \
            TZ=UTC \
            HOME="$controlled_home" \
            TMPDIR="$tool_tmp" \
            PATH=/usr/bin:/bin:/usr/sbin:/sbin \
            CARGO_HOME="$cargo_home" \
            CARGO_NET_OFFLINE=true \
            CARGO_INCREMENTAL=0 \
            CARGO_TERM_COLOR=never \
            CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=$source_root=/fre-source" \
            CARGO_ENCODED_RUSTDOCFLAGS= \
            RUSTC="$rustc_tool" \
            RUSTDOC="$rustdoc_tool" \
            RUSTC_WRAPPER= \
            RUSTC_WORKSPACE_WRAPPER= \
            CC=/usr/bin/clang \
            CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER=/usr/bin/clang \
            "${cargo_job_environment[@]}" \
            "$@"
    )
}

run_snapshot_command() {
    local source_root=$1
    shift
    (
        cd "$cargo_cwd"
        require_cargo_config_boundary "$cargo_cwd"
        /usr/bin/env -i \
            LC_ALL=C \
            TZ=UTC \
            HOME="$controlled_home" \
            TMPDIR="$tool_tmp" \
            PATH=/usr/bin:/bin:/usr/sbin:/sbin \
            CARGO_HOME="$cargo_home" \
            CARGO_NET_OFFLINE=true \
            CARGO_INCREMENTAL=0 \
            CARGO_TERM_COLOR=never \
            CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=$source_root=/fre-source" \
            CARGO_ENCODED_RUSTDOCFLAGS= \
            RUSTC="$rustc_tool" \
            RUSTDOC="$rustdoc_tool" \
            RUSTC_WRAPPER= \
            RUSTC_WORKSPACE_WRAPPER= \
            CC=/usr/bin/clang \
            CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER=/usr/bin/clang \
            "${cargo_job_environment[@]}" \
            "$@"
    )
}

require_expected_toolchain_closure "before production symbol-matrix phase"
symbol_gate=$temporary/production-symbol-gate.tsv
printf 'schema\tfre-aot-count-c5-production-symbol-gate-v1\n' > "$symbol_gate"
for mode in no-features linked-count hardware-matrix all-features; do
    production_features=(--no-default-features)
    case $mode in
        no-features) ;;
        linked-count) production_features+=(--features linked-count-v2) ;;
        hardware-matrix) production_features+=(--features linked-hardware-matrix-v2) ;;
        all-features) production_features=(--all-features) ;;
        *) fre_c5_die "internal production feature mode error" ;;
    esac
    production_target=$temporary/production-target-$mode
    run_snapshot_build \
        "aot-c5-production-inert-$mode-$$" "$production_target" "$repository" \
        CARGO_TARGET_DIR="$production_target" \
        CARGO_INCREMENTAL=0 \
        "$cargo_tool" test \
            --manifest-path "$repository/Cargo.toml" \
            -p fre-aot-static-runtime \
            "${production_features[@]}" \
            --locked \
            --offline
    symbol_report=$temporary/production-symbols-$mode.txt
    : > "$symbol_report"
    runtime_rlibs=$(find "$production_target/debug/deps" -maxdepth 1 -type f \
        -name 'libfre_aot_static_runtime-*.rlib' -print)
    [[ -n $runtime_rlibs ]] ||
        fre_c5_die "production feature mode emitted no static-runtime rlib: $mode"
    while IFS= read -r runtime_rlib; do
        /usr/bin/nm -g "$runtime_rlib" >> "$symbol_report" 2>/dev/null ||
            fre_c5_die "cannot inspect static-runtime symbols for mode: $mode"
    done <<< "$runtime_rlibs"
    if [[ $mode == all-features ]]; then
        grep -Fq 'fre_aot_static_count_adopt_qualification_raw_v2' "$symbol_report" ||
            fre_c5_die "all-features audit did not compile the private qualification boundary"
        printf '%s\tpresent-audit-only\n' "$mode" >> "$symbol_gate"
    elif grep -Fq 'fre_aot_static_count_adopt_qualification_raw_v2' "$symbol_report"; then
        fre_c5_die "private qualification boundary leaked into production feature mode: $mode"
    else
        printf '%s\tabsent\n' "$mode" >> "$symbol_gate"
    fi
done
fre_c5_require_production_symbol_gate "$symbol_gate"
require_expected_toolchain_closure \
    "after production symbol-matrix and before release-rebuild phase"

target_a=$temporary/target-a
target_b=$temporary/target-b
binary_name=fre-aot-count-qualified-benchmark
for lane in a b; do
    if [[ $lane == a ]]; then
        target=$target_a
        lane_repository=$source_a
    else
        target=$target_b
        lane_repository=$source_b
    fi
    lane_benchmark=$lane_repository/crates/fre-aot-count-compiler/benchmarks/c5-qualified-vs-portable
    run_snapshot_build \
        "aot-c5-build-$lane-$$" "$target" "$lane_repository" \
        CARGO_TARGET_DIR="$target" \
        CARGO_INCREMENTAL=0 \
        "$cargo_tool" build \
            --manifest-path "$lane_benchmark/Cargo.toml" \
            --release \
            --locked \
            --offline
done
require_expected_toolchain_closure \
    "after release rebuilds and before evidence-regeneration phase"

binary_a=$target_a/release/$binary_name
binary_b=$target_b/release/$binary_name
fre_c5_require_regular "$binary_a" "first release binary"
fre_c5_require_regular "$binary_b" "second release binary"
cmp -s -- "$binary_a" "$binary_b" ||
    fre_c5_die "independent release rebuilds are not byte-identical"
actual_binary=$(fre_c5_sha256 "$binary_a")
[[ $actual_binary == "$expected_binary" ]] ||
    fre_c5_die "release binary differs from externally expected SHA-256"

regen=$temporary/regenerated
run_snapshot_build \
    "aot-c5-regenerate-$$" "$temporary/regen-target" "$repository" \
    CARGO_TARGET_DIR="$temporary/regen-target" \
    CARGO_INCREMENTAL=0 \
    "$cargo_tool" run \
        --manifest-path "$repository/Cargo.toml" \
        -p fre-aot-count-compiler \
        --example emit_c3_evidence \
        --release \
        --locked \
        --offline \
        -- "$regen" --qualification-private

regenerated_files=(
    implementation.o
    final-image-glue.o
    expectation.bin
    unsigned-prelink-receipt.bin
    unsigned-final-image-receipt.bin
)
: > "$temporary/regeneration.sha256"
for name in "${regenerated_files[@]}"; do
    fre_c5_require_regular "$regen/$name" "regenerated artifact"
    cmp -s -- "$evidence/$name" "$regen/$name" ||
        fre_c5_die "regenerated artifact differs from retained C5 bytes: $name"
    printf '%s  %s\n' "$(fre_c5_sha256 "$regen/$name")" "$name" \
        >> "$temporary/regeneration.sha256"
done
LC_ALL=C sort "$temporary/regeneration.sha256" \
    > "$temporary/regeneration.sorted"
mv -- "$temporary/regeneration.sorted" "$temporary/regeneration.sha256"
(
    cd "$regen"
    /usr/bin/shasum -a 256 -c SHA256SUMS
) >/dev/null || fre_c5_die "regenerated evidence manifest failed"
cmp -s -- "$evidence/SHA256SUMS" "$regen/SHA256SUMS" ||
    fre_c5_die "regenerated complete evidence manifest differs"
while read -r _sha name; do
    [[ $name == [A-Za-z0-9]* && $name != */* ]] ||
        fre_c5_die "unsafe retained evidence manifest path: $name"
    cmp -s -- "$evidence/$name" "$regen/$name" ||
        fre_c5_die "complete regenerated evidence differs: $name"
done < "$evidence/SHA256SUMS"
require_expected_toolchain_closure \
    "after evidence regeneration and before dependency-inspection phase"

{
    printf 'TREE\tbenchmark\n'
    run_snapshot_command "$repository" \
        CARGO_TARGET_DIR="$temporary/tree-target" "$cargo_tool" tree \
        --manifest-path "$benchmark/Cargo.toml" \
        --locked \
        --offline \
        --prefix none
    printf 'TREE\tcustom-aot-compiler\n'
    run_snapshot_command "$repository" \
        CARGO_TARGET_DIR="$temporary/tree-target" "$cargo_tool" tree \
        --manifest-path "$repository/Cargo.toml" \
        -p fre-aot-count-compiler \
        --locked \
        --offline \
        --prefix none
    printf 'TREE\tworkspace-runtime-features\n'
    run_snapshot_command "$repository" \
        CARGO_TARGET_DIR="$temporary/tree-target" "$cargo_tool" tree \
        --manifest-path "$repository/Cargo.toml" \
        -p fre-aot-static-runtime \
        -e normal \
        --depth 0 \
        --format $'{p}\t{f}' \
        --locked \
        --offline \
        --prefix none
    printf 'TREE\tqualification-runtime-features\n'
    run_snapshot_command "$repository" \
        CARGO_TARGET_DIR="$temporary/tree-target" "$cargo_tool" tree \
        --manifest-path "$benchmark/Cargo.toml" \
        -p fre-aot-static-runtime \
        -e normal \
        --depth 0 \
        --format $'{p}\t{f}' \
        --locked \
        --offline \
        --prefix none
    printf 'TREE\tqualification-runtime-reverse\n'
    run_snapshot_command "$repository" \
        CARGO_TARGET_DIR="$temporary/tree-target" "$cargo_tool" tree \
        --manifest-path "$benchmark/Cargo.toml" \
        -i fre-aot-static-runtime \
        -e normal \
        --depth 1 \
        --format $'{p}\t{f}' \
        --locked \
        --offline \
        --prefix none
} | sed "s# ($repository/# (REPOSITORY/#g" \
    > "$temporary/dependency-tree.txt"
fre_c5_require_no_llvm_dependency "$temporary/dependency-tree.txt"
fre_c5_require_candidate_feature_isolation "$temporary/dependency-tree.txt"
require_expected_toolchain_closure "after dependency-inspection phase"

(
    cd "$temporary"
    /usr/bin/otool -l "$binary_a" | sed '1s#^.*:#candidate-binary:#'
) > "$temporary/otool-l.txt"
fre_c5_require_readonly_segment_report "$temporary/otool-l.txt"

implementation_sha=$(fre_c5_sha256 "$evidence/implementation.o")
glue_sha=$(fre_c5_sha256 "$evidence/final-image-glue.o")
expectation_sha=$(fre_c5_sha256 "$evidence/expectation.bin")
verifier_sha=$(fre_c5_sha256 "$benchmark/verify-results.sh")
require_expected_toolchain_closure "before Rust tool verbose-identity phase"
run_snapshot_command "$repository" "$rustc_tool" --version --verbose \
    > "$temporary/rustc-verbose.txt"
run_snapshot_command "$repository" "$cargo_tool" --version --verbose \
    > "$temporary/cargo-verbose.txt"
require_expected_toolchain_closure "after Rust tool verbose-identity phase"
/usr/bin/env -i \
    LC_ALL=C \
    TZ=UTC \
    PATH=/usr/bin:/bin \
    "$clang_tool" --version > "$temporary/clang-version.txt"
fre_c5_require_text_bounds \
    "$temporary/rustc-verbose.txt" 8192 1024 64 "rustc verbose identity"
fre_c5_require_text_bounds \
    "$temporary/cargo-verbose.txt" 8192 1024 64 "Cargo verbose identity"
fre_c5_require_text_bounds \
    "$temporary/clang-version.txt" 8192 1024 64 "Apple clang identity"
rustc_release=$(awk -F ': ' '$1 == "release" { print $2 }' \
    "$temporary/rustc-verbose.txt")
rustc_commit=$(awk -F ': ' '$1 == "commit-hash" { print $2 }' \
    "$temporary/rustc-verbose.txt")
rustc_host=$(awk -F ': ' '$1 == "host" { print $2 }' \
    "$temporary/rustc-verbose.txt")
rustc_llvm=$(awk -F ': ' '$1 == "LLVM version" { print $2 }' \
    "$temporary/rustc-verbose.txt")
[[ $rustc_release == 1.93.0 &&
    $rustc_commit =~ ^[0-9a-f]{40}$ &&
    $rustc_host == aarch64-apple-darwin &&
    -n $rustc_llvm ]] ||
    fre_c5_die "pinned rustc identity differs from the Candidate toolchain contract"
cargo_binary_sha=$(fre_c5_sha256 "$cargo_tool")
rustc_binary_sha=$(fre_c5_sha256 "$rustc_tool")
rustdoc_binary_sha=$(fre_c5_sha256 "$rustdoc_tool")
clang_binary_sha=$(fre_c5_sha256 "$clang_tool")
rustc_verbose_sha=$(fre_c5_sha256 "$temporary/rustc-verbose.txt")
cargo_verbose_sha=$(fre_c5_sha256 "$temporary/cargo-verbose.txt")
clang_version_sha=$(fre_c5_sha256 "$temporary/clang-version.txt")

[[ $(source_snapshot_fingerprint "$source_a") == "$source_a_fingerprint" &&
    $(source_snapshot_fingerprint "$source_b") == "$source_b_fingerprint" ]] ||
    fre_c5_die "Candidate source snapshot content, type, or mode changed during build"
require_cargo_config_boundary "$cargo_cwd"
[[ $(fre_c5_toolchain_closure_fingerprint "$toolchain_root") == \
    "$toolchain_closure_record" ]] ||
    fre_c5_die "Rust toolchain closure changed during build"
[[ $(fre_c5_cargo_registry_closure_fingerprint "$cargo_registry_root") == \
    "$cargo_registry_closure_record" ]] ||
    fre_c5_die "external Cargo registry closure changed during build"
[[ $(fre_c5_cargo_registry_closure_fingerprint "$cargo_home/registry") == \
    "$cargo_registry_closure_record" ]] ||
    fre_c5_die "private Cargo registry closure changed during build"
[[ $(fre_c5_sha256 "$resource_coordinator") == \
    "$expected_resource_coordinator_sha" &&
    $(fre_c5_sha256 "$resource_coordinator_snapshot") == \
    "$expected_resource_coordinator_sha" ]] ||
    fre_c5_die "resource coordinator changed during build"
[[ $(fre_c5_sha256 "$cutover_receipt") == "$expected_cutover_receipt_sha" &&
    $(fre_c5_sha256 "$cutover_receipt_snapshot") == \
    "$expected_cutover_receipt_sha" ]] ||
    fre_c5_die "resource coordinator cutover receipt changed during build"
[[ $(fre_c5_sha256 "$cargo_tool") == "$expected_cargo_sha" &&
    $(fre_c5_sha256 "$rustc_tool") == "$expected_rustc_sha" &&
    $(fre_c5_sha256 "$rustdoc_tool") == "$expected_rustdoc_sha" &&
    $(fre_c5_sha256 "$clang_tool") == "$clang_binary_sha" ]] ||
    fre_c5_die "compiler tool input changed during build"
for config in "$cargo_home/config" "$cargo_home/config.toml"; do
    [[ ! -e $config && ! -L $config ]] ||
        fre_c5_die "Cargo configuration appeared during build: $config"
done
cargo_build_jobs_receipt=${cargo_build_jobs:-cargo-default}

cat > "$temporary/build-receipt.tsv" <<EOF
schema	fre-aot-count-c5-build-receipt-v2
source_commit	$expected_commit
source_tree	$expected_tree
source_archive_sha256	$source_archive
benchmark_source_sha256	$expected_source
benchmark_binary_sha256	$expected_binary
implementation_object_sha256	$implementation_sha
final_image_glue_sha256	$glue_sha
final_image_glue_adopter	qualification-private
qualification_adopter_symbol	fre_aot_static_count_adopt_qualification_raw_v2
expectation_sha256	$expectation_sha
raw_verifier_sha256	$verifier_sha
repository_clean	true
locked_offline	true
release_rebuilds	2
release_rebuilds_byte_identical	true
custom_objects_regenerated	true
custom_objects_byte_identical	true
complete_evidence_byte_identical	true
llvm_aot_dependency	absent
macho_lc_uuid	content-hash
linker_reproducible	enabled
linker_reproducible_layout	fixed-private-tmp-v2
release_source_snapshots	2
release_source_snapshot_roots_disjoint	true
source_snapshots_read_only_before_build	true
source_snapshot_integrity_rechecked	true
source_snapshot_fingerprint	$source_a_fingerprint
rust_source_path_remap	/fre-source
cargo_invocation_cwd	isolated-config-free-cwd-v1
cargo_environment	isolated-env-i-v1
cargo_home_config	absent
cargo_registry_root	$cargo_registry_root
cargo_registry_snapshot_root	private-cargo-home-registry-v1
cargo_registry_closure_sha256	$cargo_registry_closure_sha
cargo_registry_closure_entries	$cargo_registry_closure_entries
cargo_registry_closure_bytes	$cargo_registry_closure_bytes
cargo_registry_snapshot_integrity_rechecked	true
cargo_dependency_source_classes	registry-and-path-only
resource_coordinator_path	canonical-external-direct-v1
resource_coordinator_sha256	$expected_resource_coordinator_sha
resource_coordinator_cutover_receipt_sha256	$expected_cutover_receipt_sha
resource_coordinator_direct_fallback	absent
ambient_rust_cargo_environment	cleared
cargo_build_jobs	$cargo_build_jobs_receipt
toolchain_root	$toolchain_root
cargo_binary_sha256	$cargo_binary_sha
rustc_binary_sha256	$rustc_binary_sha
rustdoc_binary_sha256	$rustdoc_binary_sha
toolchain_closure_sha256	$toolchain_closure_sha
toolchain_closure_entries	$toolchain_closure_entries
toolchain_closure_bytes	$toolchain_closure_bytes
rustc_sysroot_binding	toolchain-root
clang_binary_sha256	$clang_binary_sha
cargo_verbose_sha256	$cargo_verbose_sha
rustc_verbose_sha256	$rustc_verbose_sha
clang_version_sha256	$clang_version_sha
production_activation	absent
production_feature_matrix_gate	passed
production_adopter_feature_invariant	passed
production_private_symbol_gate	passed
qualification_feature_isolation	passed
qualification_registry	isolated
rustc_release	$rustc_release
rustc_commit	$rustc_commit
rustc_host	$rustc_host
rustc_llvm_backend	$rustc_llvm
EOF
fre_c5_validate_tsv "$temporary/build-receipt.tsv"
fre_c5_require_exact_tsv_keys \
    "$temporary/build-receipt.tsv" "build receipt" <<'EOF'
schema
source_commit
source_tree
source_archive_sha256
benchmark_source_sha256
benchmark_binary_sha256
implementation_object_sha256
final_image_glue_sha256
final_image_glue_adopter
qualification_adopter_symbol
expectation_sha256
raw_verifier_sha256
repository_clean
locked_offline
release_rebuilds
release_rebuilds_byte_identical
custom_objects_regenerated
custom_objects_byte_identical
complete_evidence_byte_identical
llvm_aot_dependency
macho_lc_uuid
linker_reproducible
linker_reproducible_layout
release_source_snapshots
release_source_snapshot_roots_disjoint
source_snapshots_read_only_before_build
source_snapshot_integrity_rechecked
source_snapshot_fingerprint
rust_source_path_remap
cargo_invocation_cwd
cargo_environment
cargo_home_config
cargo_registry_root
cargo_registry_snapshot_root
cargo_registry_closure_sha256
cargo_registry_closure_entries
cargo_registry_closure_bytes
cargo_registry_snapshot_integrity_rechecked
cargo_dependency_source_classes
resource_coordinator_path
resource_coordinator_sha256
resource_coordinator_cutover_receipt_sha256
resource_coordinator_direct_fallback
ambient_rust_cargo_environment
cargo_build_jobs
toolchain_root
cargo_binary_sha256
rustc_binary_sha256
rustdoc_binary_sha256
toolchain_closure_sha256
toolchain_closure_entries
toolchain_closure_bytes
rustc_sysroot_binding
clang_binary_sha256
cargo_verbose_sha256
rustc_verbose_sha256
clang_version_sha256
production_activation
production_feature_matrix_gate
production_adopter_feature_invariant
production_private_symbol_gate
qualification_feature_isolation
qualification_registry
rustc_release
rustc_commit
rustc_host
rustc_llvm_backend
EOF

fre_c5_require_subject \
    "$subject_repository" "$expected_commit" "$expected_tree" "$expected_source" true

fre_c5_require_new_output_path "$output"
output_parent=${output%/*}
publish_namespace=$output_parent/.fre-aot-c5-build.
publish=$(mktemp -d "$publish_namespace"XXXXXX) ||
    fre_c5_die "cannot create publication scratch directory"
publish_identity=$(
    fre_c5_owned_directory_identity \
        "$publish" "build publication scratch directory"
)
cp -p -- \
    "$temporary/build-receipt.tsv" \
    "$temporary/dependency-tree.txt" \
    "$temporary/otool-l.txt" \
    "$temporary/production-symbol-gate.tsv" \
    "$temporary/regeneration.sha256" \
    "$resource_coordinator_snapshot" \
    "$cutover_receipt_snapshot" \
    "$temporary/source.tar" \
    "$publish/"
cp -p -- "$binary_a" "$publish/candidate-binary"
chmod 0555 "$publish/candidate-binary"
mv -- "$publish" "$output"
[[ ! -e $publish && ! -L $publish ]] ||
    fre_c5_die "publication scratch path still exists after publication"
[[ $(fre_c5_owned_directory_identity "$output" "published build directory") == \
    "$publish_identity" ]] ||
    fre_c5_die "published build directory differs from owned publication scratch"

printf 'BUILT,commit=%s,tree=%s,source=%s,binary=%s,output=%s\n' \
    "$expected_commit" "$expected_tree" "$expected_source" "$expected_binary" "$output"
