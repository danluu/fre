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
usage: run-qualified-candidate.sh EXPECTED_COMMIT EXPECTED_TREE EXPECTED_SOURCE_SHA256 EXPECTED_BINARY_SHA256 EXPECTED_CARGO_SHA256 EXPECTED_RUSTC_SHA256 EXPECTED_RUSTDOC_SHA256 EXPECTED_TOOLCHAIN_CLOSURE_SHA256 EXPECTED_TOOLCHAIN_CLOSURE_ENTRIES EXPECTED_TOOLCHAIN_CLOSURE_BYTES EXPECTED_CARGO_REGISTRY_CLOSURE_SHA256 EXPECTED_CARGO_REGISTRY_CLOSURE_ENTRIES EXPECTED_CARGO_REGISTRY_CLOSURE_BYTES RESOURCE_COORDINATOR EXPECTED_RESOURCE_COORDINATOR_SHA256 CUTOVER_RECEIPT EXPECTED_CUTOVER_RECEIPT_SHA256 BUILD_DIR OUTPUT_DIR

Run exactly three fresh benchmark processes from a sealed build. The source
tree and executable are hashed before and after the timing wave, every process
is checked by the raw-derived verifier, and the output is a closed manifest
bundle. The script requires and snapshots an externally pinned physical
resource coordinator and cutover receipt, then admits the timing wave with no
direct-execution fallback and no wait for global CPU idleness.
EOF
    exit 2
}

[[ $# -eq 19 ]] || usage
expected_commit=$1
expected_tree=$2
expected_source=$3
expected_binary=$4
expected_cargo_sha=$5
expected_rustc_sha=$6
expected_rustdoc_sha=$7
expected_toolchain_closure_sha=$8
expected_toolchain_closure_entries=$9
expected_toolchain_closure_bytes=${10}
expected_cargo_registry_closure_sha=${11}
expected_cargo_registry_closure_entries=${12}
expected_cargo_registry_closure_bytes=${13}
resource_coordinator_arg=${14}
expected_resource_coordinator_sha=${15}
cutover_receipt_arg=${16}
expected_cutover_receipt_sha=${17}
build_arg=${18}
output=${19}

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
build=$(fre_c5_canonical_directory "$build_arg")
resource_coordinator=$(
    fre_c5_canonical_regular_file \
        "$resource_coordinator_arg" "resource coordinator"
)
[[ -x $resource_coordinator ]] ||
    fre_c5_die "resource coordinator must be directly executable"
cutover_receipt=$(
    fre_c5_canonical_regular_file "$cutover_receipt_arg" "cutover receipt"
)

repository=$(git -C "$script_dir" rev-parse --show-toplevel) ||
    fre_c5_die "cannot resolve repository root"
repository=$(fre_c5_canonical_directory "$repository")
grafts=$(git -C "$repository" rev-parse --git-path info/grafts) ||
    fre_c5_die "cannot resolve repository graft path"
case $grafts in
    /*) ;;
    *) grafts=$repository/$grafts ;;
esac
[[ ! -e $grafts && ! -L $grafts ]] ||
    fre_c5_die "subject repository contains an info/grafts override"
replace_ref=$(git -C "$repository" for-each-ref \
    --format='%(refname)' refs/replace | sed -n '1p') ||
    fre_c5_die "cannot inspect subject replacement refs"
[[ -z $replace_ref ]] ||
    fre_c5_die "subject repository contains replacement refs"
[[ $(git -C "$repository" rev-parse --is-shallow-repository) == false ]] ||
    fre_c5_die "subject repository must be complete and non-shallow"
fre_c5_require_no_archive_attribute_overrides "$repository"
fre_c5_require_subject \
    "$repository" "$expected_commit" "$expected_tree" "$expected_source" true

build_files=(
    build-receipt.tsv
    candidate-binary
    dependency-tree.txt
    otool-l.txt
    production-symbol-gate.tsv
    regeneration.sha256
    resource-coordinator
    resource-coordinator-cutover-receipt
    source.tar
)
for name in "${build_files[@]}"; do
    fre_c5_require_regular "$build/$name" "sealed build input"
done
actual_build_paths=$(find "$build" -mindepth 1 -maxdepth 1 -type f -print |
    sed "s#^$build/##" | sort)
expected_build_paths=$(printf '%s\n' "${build_files[@]}" | sort)
[[ $actual_build_paths == "$expected_build_paths" ]] ||
    fre_c5_die "sealed build directory has a non-canonical file inventory"
special=$(find "$build" -mindepth 1 ! -type f -print -quit)
[[ -z $special ]] || fre_c5_die "sealed build directory contains a special object"
hardlink=$(find "$build" -type f -links +1 -print -quit)
[[ -z $hardlink ]] || fre_c5_die "sealed build directory contains a multiply linked file"
fre_c5_require_file_bytes "$build/candidate-binary" 16777216 "sealed candidate binary"
fre_c5_require_file_bytes \
    "$build/resource-coordinator" 16777216 "sealed resource coordinator"
[[ -x $build/resource-coordinator ]] ||
    fre_c5_die "sealed resource coordinator is not executable"
fre_c5_require_file_bytes \
    "$build/resource-coordinator-cutover-receipt" 1048576 \
    "sealed resource coordinator cutover receipt"
fre_c5_require_file_bytes "$build/source.tar" 536870912 "sealed source archive"
fre_c5_require_text_bounds "$build/build-receipt.tsv" 8192 1024 80 \
    "sealed build receipt"
fre_c5_require_text_bounds "$build/dependency-tree.txt" 65536 2048 2048 \
    "sealed dependency report"
fre_c5_require_text_bounds "$build/otool-l.txt" 131072 2048 2048 \
    "sealed Mach-O report"
fre_c5_require_production_symbol_gate "$build/production-symbol-gate.tsv"
fre_c5_require_text_bounds "$build/regeneration.sha256" 4096 256 16 \
    "sealed regeneration manifest"

receipt=$build/build-receipt.tsv
fre_c5_validate_tsv "$receipt"
fre_c5_require_exact_tsv_keys "$receipt" "sealed build receipt" <<'EOF'
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
fre_c5_require_tsv_value "$receipt" schema fre-aot-count-c5-build-receipt-v2
fre_c5_require_tsv_value "$receipt" source_commit "$expected_commit"
fre_c5_require_tsv_value "$receipt" source_tree "$expected_tree"
fre_c5_require_tsv_value "$receipt" benchmark_source_sha256 "$expected_source"
fre_c5_require_tsv_value "$receipt" benchmark_binary_sha256 "$expected_binary"
fre_c5_require_tsv_value "$receipt" cargo_binary_sha256 "$expected_cargo_sha"
fre_c5_require_tsv_value "$receipt" rustc_binary_sha256 "$expected_rustc_sha"
fre_c5_require_tsv_value "$receipt" rustdoc_binary_sha256 "$expected_rustdoc_sha"
fre_c5_require_tsv_value \
    "$receipt" toolchain_closure_sha256 "$expected_toolchain_closure_sha"
fre_c5_require_tsv_value \
    "$receipt" toolchain_closure_entries "$expected_toolchain_closure_entries"
fre_c5_require_tsv_value \
    "$receipt" toolchain_closure_bytes "$expected_toolchain_closure_bytes"
fre_c5_require_tsv_value "$receipt" final_image_glue_adopter qualification-private
fre_c5_require_tsv_value "$receipt" qualification_adopter_symbol \
    fre_aot_static_count_adopt_qualification_raw_v2
fre_c5_require_tsv_value "$receipt" repository_clean true
fre_c5_require_tsv_value "$receipt" locked_offline true
fre_c5_require_tsv_value "$receipt" release_rebuilds 2
fre_c5_require_tsv_value "$receipt" release_rebuilds_byte_identical true
fre_c5_require_tsv_value "$receipt" custom_objects_regenerated true
fre_c5_require_tsv_value "$receipt" custom_objects_byte_identical true
fre_c5_require_tsv_value "$receipt" complete_evidence_byte_identical true
fre_c5_require_tsv_value "$receipt" llvm_aot_dependency absent
fre_c5_require_tsv_value "$receipt" macho_lc_uuid content-hash
fre_c5_require_tsv_value "$receipt" linker_reproducible enabled
fre_c5_require_tsv_value "$receipt" linker_reproducible_layout fixed-private-tmp-v2
fre_c5_require_tsv_value "$receipt" release_source_snapshots 2
fre_c5_require_tsv_value "$receipt" release_source_snapshot_roots_disjoint true
fre_c5_require_tsv_value "$receipt" source_snapshots_read_only_before_build true
fre_c5_require_tsv_value "$receipt" source_snapshot_integrity_rechecked true
fre_c5_require_tsv_value "$receipt" rust_source_path_remap /fre-source
fre_c5_require_tsv_value \
    "$receipt" cargo_invocation_cwd isolated-config-free-cwd-v1
fre_c5_require_tsv_value "$receipt" cargo_environment isolated-env-i-v1
fre_c5_require_tsv_value "$receipt" cargo_home_config absent
cargo_registry_receipt_root=$(fre_c5_tsv_value "$receipt" cargo_registry_root)
fre_c5_require_absolute_path_value \
    "$cargo_registry_receipt_root" "build receipt Cargo registry root"
fre_c5_require_tsv_value \
    "$receipt" cargo_registry_snapshot_root private-cargo-home-registry-v1
fre_c5_require_tsv_value \
    "$receipt" cargo_registry_closure_sha256 \
    "$expected_cargo_registry_closure_sha"
fre_c5_require_tsv_value \
    "$receipt" cargo_registry_closure_entries \
    "$expected_cargo_registry_closure_entries"
fre_c5_require_tsv_value \
    "$receipt" cargo_registry_closure_bytes \
    "$expected_cargo_registry_closure_bytes"
fre_c5_require_tsv_value \
    "$receipt" cargo_registry_snapshot_integrity_rechecked true
fre_c5_require_tsv_value \
    "$receipt" cargo_dependency_source_classes registry-and-path-only
fre_c5_require_tsv_value \
    "$receipt" resource_coordinator_path canonical-external-direct-v1
fre_c5_require_tsv_value \
    "$receipt" resource_coordinator_sha256 \
    "$expected_resource_coordinator_sha"
fre_c5_require_tsv_value \
    "$receipt" resource_coordinator_cutover_receipt_sha256 \
    "$expected_cutover_receipt_sha"
fre_c5_require_tsv_value \
    "$receipt" resource_coordinator_direct_fallback absent
fre_c5_require_tsv_value "$receipt" ambient_rust_cargo_environment cleared
fre_c5_require_tsv_value "$receipt" production_activation absent
fre_c5_require_tsv_value "$receipt" production_feature_matrix_gate passed
fre_c5_require_tsv_value "$receipt" production_adopter_feature_invariant passed
fre_c5_require_tsv_value "$receipt" production_private_symbol_gate passed
fre_c5_require_tsv_value "$receipt" qualification_feature_isolation passed
fre_c5_require_tsv_value "$receipt" qualification_registry isolated
for key in \
    source_snapshot_fingerprint \
    cargo_binary_sha256 \
    rustc_binary_sha256 \
    rustdoc_binary_sha256 \
    toolchain_closure_sha256 \
    cargo_registry_closure_sha256 \
    clang_binary_sha256 \
    cargo_verbose_sha256 \
    rustc_verbose_sha256 \
    clang_version_sha256; do
    fre_c5_require_nonzero_sha256 \
        "$(fre_c5_tsv_value "$receipt" "$key")" "build receipt $key"
done
toolchain_closure_entries=$(
    fre_c5_tsv_value "$receipt" toolchain_closure_entries
)
toolchain_closure_bytes=$(
    fre_c5_tsv_value "$receipt" toolchain_closure_bytes
)
[[ $toolchain_closure_entries =~ ^[1-9][0-9]*$ &&
    $toolchain_closure_entries -le 16384 &&
    $toolchain_closure_bytes =~ ^[1-9][0-9]*$ &&
    $toolchain_closure_bytes -le 4294967296 ]] ||
    fre_c5_die "build receipt has invalid toolchain closure bounds"
cargo_registry_closure_entries=$(
    fre_c5_tsv_value "$receipt" cargo_registry_closure_entries
)
cargo_registry_closure_bytes=$(
    fre_c5_tsv_value "$receipt" cargo_registry_closure_bytes
)
fre_c5_require_bounded_positive_decimal \
    "$cargo_registry_closure_entries" 100000 \
    "build receipt Cargo registry closure entry count"
fre_c5_require_bounded_positive_decimal \
    "$cargo_registry_closure_bytes" 4294967296 \
    "build receipt Cargo registry closure byte count"
fre_c5_require_tsv_value "$receipt" rustc_sysroot_binding toolchain-root
cargo_build_jobs=$(fre_c5_tsv_value "$receipt" cargo_build_jobs)
[[ $cargo_build_jobs == cargo-default ||
    $cargo_build_jobs =~ ^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-6])$ ]] ||
    fre_c5_die "build receipt has an invalid Cargo job count"
toolchain_receipt_root=$(fre_c5_tsv_value "$receipt" toolchain_root)
fre_c5_require_absolute_path_value \
    "$toolchain_receipt_root" "build receipt toolchain root"
fre_c5_require_tsv_value "$receipt" rustc_release 1.93.0
fre_c5_require_tsv_value "$receipt" rustc_host aarch64-apple-darwin
rustc_commit=$(fre_c5_tsv_value "$receipt" rustc_commit)
rustc_llvm_backend=$(fre_c5_tsv_value "$receipt" rustc_llvm_backend)
[[ $rustc_commit =~ ^[0-9a-f]{40}$ &&
    $rustc_llvm_backend =~ ^[0-9]+([.][0-9]+){1,3}$ ]] ||
    fre_c5_die "build receipt has a malformed rustc backend identity"
fre_c5_require_no_llvm_dependency "$build/dependency-tree.txt"
fre_c5_require_candidate_feature_isolation "$build/dependency-tree.txt"
fre_c5_require_readonly_segment_report "$build/otool-l.txt"
[[ $(fre_c5_sha256 "$build/source.tar") == \
    "$(fre_c5_tsv_value "$receipt" source_archive_sha256)" ]] ||
    fre_c5_die "sealed source archive differs from build receipt"
raw_verifier_sha=$(fre_c5_tsv_value "$receipt" raw_verifier_sha256)
[[ $(fre_c5_sha256 "$script_dir/verify-results.sh") == \
    "$raw_verifier_sha" ]] ||
    fre_c5_die "raw verifier differs from sealed build receipt"
[[ $(fre_c5_sha256 "$build/resource-coordinator") == \
    "$expected_resource_coordinator_sha" ]] ||
    fre_c5_die "sealed resource coordinator differs from external identity"
[[ $(fre_c5_sha256 "$build/resource-coordinator-cutover-receipt") == \
    "$expected_cutover_receipt_sha" ]] ||
    fre_c5_die "sealed cutover receipt differs from external identity"

binary=$build/candidate-binary
[[ -x $binary ]] || fre_c5_die "sealed candidate binary is not executable"
[[ $(fre_c5_sha256 "$binary") == "$expected_binary" ]] ||
    fre_c5_die "sealed candidate binary differs from external identity"

case "$(uname -s):$(uname -m)" in
    Darwin:arm64) ;;
    *) fre_c5_die "qualified C5 execution requires arm64 macOS" ;;
esac

parent=${output%/*}
temporary_namespace=$parent/.fre-aot-c5-run.
temporary=$(mktemp -d "$temporary_namespace"XXXXXX) ||
    fre_c5_die "cannot create timing scratch directory"
temporary_identity=$(
    fre_c5_owned_directory_identity "$temporary" "timing scratch directory"
)
cleanup() {
    local status=$?
    local cleanup_failed=false
    if [[ -n ${temporary:-} && ( -e $temporary || -L $temporary ) ]]; then
        if [[ -z ${temporary_identity:-} || -z ${temporary_namespace:-} ]] ||
            ! fre_c5_cleanup_owned_directory \
                "$temporary" "$temporary_identity" "$temporary_namespace" \
                "timing scratch directory"; then
            printf '%s\n' \
                "c5-qualification: refused unsafe timing scratch cleanup" >&2
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

cp -p -- "$build/build-receipt.tsv" "$temporary/"
cp -p -- "$build/dependency-tree.txt" "$temporary/"
cp -p -- "$build/otool-l.txt" "$temporary/"
cp -p -- "$build/production-symbol-gate.tsv" "$temporary/"
cp -p -- "$build/regeneration.sha256" "$temporary/"
cp -p -- "$build/source.tar" "$temporary/"
cp -p -- "$binary" "$temporary/candidate-binary"
chmod 0555 "$temporary/candidate-binary"
fre_c5_snapshot_pinned_file \
    "$resource_coordinator" "$expected_resource_coordinator_sha" \
    16777216 "resource coordinator" "$temporary/resource-coordinator"
[[ -x $temporary/resource-coordinator ]] ||
    fre_c5_die "snapshotted resource coordinator is not executable"
fre_c5_snapshot_pinned_file \
    "$cutover_receipt" "$expected_cutover_receipt_sha" \
    1048576 "cutover receipt" \
    "$temporary/resource-coordinator-cutover-receipt"
fre_c5_snapshot_pinned_file \
    "$script_dir/verify-results.sh" "$raw_verifier_sha" \
    131072 "raw results verifier" "$temporary/raw-verifier.sh"
chmod 0500 "$temporary/raw-verifier.sh"
cmp -s \
    "$build/resource-coordinator" "$temporary/resource-coordinator" ||
    fre_c5_die "build and timing coordinator snapshots differ"
cmp -s \
    "$build/resource-coordinator-cutover-receipt" \
    "$temporary/resource-coordinator-cutover-receipt" ||
    fre_c5_die "build and timing cutover receipt snapshots differ"
timing_helper_source=crates/fre-aot-count-compiler/benchmarks/c5-qualified-vs-portable/run-qualified-timing-wave.sh
[[ $(git -C "$repository" ls-tree "$expected_commit" -- "$timing_helper_source" |
    awk '{ print $1 " " $2 }') == "100755 blob" ]] ||
    fre_c5_die "Candidate timing-wave helper must be one executable blob"
timing_helper_bytes=$(
    git -C "$repository" cat-file -s "$expected_commit:$timing_helper_source"
) || fre_c5_die "cannot determine Candidate timing-wave helper size"
[[ $timing_helper_bytes =~ ^[1-9][0-9]*$ &&
    $timing_helper_bytes -le 131072 ]] ||
    fre_c5_die "Candidate timing-wave helper exceeds its byte cap"
git -C "$repository" cat-file blob \
    "$expected_commit:$timing_helper_source" \
    > "$temporary/run-qualified-timing-wave.sh" ||
    fre_c5_die "cannot extract Candidate timing-wave helper"
chmod 0500 "$temporary/run-qualified-timing-wave.sh"
cmp -s \
    "$script_dir/run-qualified-timing-wave.sh" \
    "$temporary/run-qualified-timing-wave.sh" ||
    fre_c5_die "live timing-wave helper differs from the exact Candidate blob"
timing_helper_sha=$(fre_c5_sha256 "$temporary/run-qualified-timing-wave.sh")
fre_c5_require_nonzero_sha256 \
    "$timing_helper_sha" "Candidate timing-wave helper SHA-256"
[[ $(fre_c5_sha256 "$resource_coordinator") == \
    "$expected_resource_coordinator_sha" &&
    $(fre_c5_sha256 "$cutover_receipt") == "$expected_cutover_receipt_sha" ]] ||
    fre_c5_die "coordinator admission identity changed before timing wave"
coordinator_status=0
"$resource_coordinator" run-timing-wave "aot-c5-final-$$" \
    --wait-seconds 0 -- \
    "$temporary/run-qualified-timing-wave.sh" \
    "$temporary" "$expected_binary" ||
    coordinator_status=$?
[[ $(fre_c5_sha256 "$resource_coordinator") == \
    "$expected_resource_coordinator_sha" &&
    $(fre_c5_sha256 "$cutover_receipt") == "$expected_cutover_receipt_sha" ]] ||
    fre_c5_die "coordinator admission identity changed during timing wave"
[[ $coordinator_status == 0 ]] ||
    fre_c5_die "resource coordinator rejected or failed timing wave"
[[ $(fre_c5_sha256 "$temporary/run-qualified-timing-wave.sh") == \
    "$timing_helper_sha" ]] ||
    fre_c5_die "Candidate timing-wave helper changed during execution"

[[ $(fre_c5_sha256 "$temporary/raw-verifier.sh") == "$raw_verifier_sha" ]] ||
    fre_c5_die "snapshotted raw verifier changed before replay"
/bin/bash -p "$temporary/raw-verifier.sh" \
    "$expected_binary" \
    "$expected_source" \
    "$temporary/run-1.csv" \
    "$temporary/run-2.csv" \
    "$temporary/run-3.csv" \
    > "$temporary/raw-verification.txt"
/bin/rm -- \
    "$temporary/raw-verifier.sh" \
    "$temporary/run-qualified-timing-wave.sh"

source_archive=$(fre_c5_tsv_value "$receipt" source_archive_sha256)
implementation_sha=$(fre_c5_tsv_value "$receipt" implementation_object_sha256)
glue_sha=$(fre_c5_tsv_value "$receipt" final_image_glue_sha256)
expectation_sha=$(fre_c5_tsv_value "$receipt" expectation_sha256)
verifier_sha=$(fre_c5_tsv_value "$receipt" raw_verifier_sha256)

cat > "$temporary/binding.tsv" <<EOF
schema	fre-aot-count-c5-qualification-bundle-v3
source_commit	$expected_commit
source_tree	$expected_tree
source_archive_sha256	$source_archive
benchmark_source_sha256	$expected_source
benchmark_binary_sha256	$expected_binary
cargo_binary_sha256	$expected_cargo_sha
rustc_binary_sha256	$expected_rustc_sha
rustdoc_binary_sha256	$expected_rustdoc_sha
toolchain_closure_sha256	$expected_toolchain_closure_sha
toolchain_closure_entries	$expected_toolchain_closure_entries
toolchain_closure_bytes	$expected_toolchain_closure_bytes
cargo_registry_snapshot_root	private-cargo-home-registry-v1
cargo_registry_closure_sha256	$expected_cargo_registry_closure_sha
cargo_registry_closure_entries	$expected_cargo_registry_closure_entries
cargo_registry_closure_bytes	$expected_cargo_registry_closure_bytes
resource_coordinator_sha256	$expected_resource_coordinator_sha
resource_coordinator_cutover_receipt_sha256	$expected_cutover_receipt_sha
implementation_object_sha256	$implementation_sha
final_image_glue_sha256	$glue_sha
final_image_glue_adopter	qualification-private
qualification_adopter_symbol	fre_aot_static_count_adopt_qualification_raw_v2
expectation_sha256	$expectation_sha
raw_verifier_sha256	$verifier_sha
fresh_processes	3
fixture_cases	58
fixture_sizes	2
alignment_residues	16
steady_repetitions	16
samples_per_process	1856
bytes_per_steady_sample	67108864
performance_scope	selector-11-needle-steady-state-plus-qualification-private-adoption-v1
compile_link_startup_costs	unmeasured
production_adoption_latency	unmeasured
runtime_authority	qualification-private
qualification_state	candidate
production_activation	absent
production_private_symbol_gate	passed
promotion_bundle_manifest_sha256	unbound
raw_cells	174
raw_pairs	2784
minimum_cell_speedup	1.10
minimum_pair_win_rate	0.95
immutable_mapping_gate	passed
safe_handle_gate	passed
per_call_policy_gate	passed
EOF
fre_c5_validate_tsv "$temporary/binding.tsv"
fre_c5_require_exact_tsv_keys "$temporary/binding.tsv" "bundle binding" <<'EOF'
schema
source_commit
source_tree
source_archive_sha256
benchmark_source_sha256
benchmark_binary_sha256
cargo_binary_sha256
rustc_binary_sha256
rustdoc_binary_sha256
toolchain_closure_sha256
toolchain_closure_entries
toolchain_closure_bytes
cargo_registry_snapshot_root
cargo_registry_closure_sha256
cargo_registry_closure_entries
cargo_registry_closure_bytes
resource_coordinator_sha256
resource_coordinator_cutover_receipt_sha256
implementation_object_sha256
final_image_glue_sha256
final_image_glue_adopter
qualification_adopter_symbol
expectation_sha256
raw_verifier_sha256
fresh_processes
fixture_cases
fixture_sizes
alignment_residues
steady_repetitions
samples_per_process
bytes_per_steady_sample
performance_scope
compile_link_startup_costs
production_adoption_latency
runtime_authority
qualification_state
production_activation
production_private_symbol_gate
promotion_bundle_manifest_sha256
raw_cells
raw_pairs
minimum_cell_speedup
minimum_pair_win_rate
immutable_mapping_gate
safe_handle_gate
per_call_policy_gate
EOF

{
    printf 'schema\tfre-aot-count-c5-environment-v3\n'
    printf 'uname_s\t%s\n' "$(uname -s)"
    printf 'uname_m\t%s\n' "$(uname -m)"
    printf 'os_version\t%s\n' "$(sw_vers -productVersion)"
    printf 'os_build\t%s\n' "$(sw_vers -buildVersion)"
    printf 'runtime_environment\tisolated-env-i-v1\n'
    printf 'benchmark_cwd\tprivate-bundle\n'
    printf 'build_toolchain_root\t%s\n' "$toolchain_receipt_root"
    printf 'build_cargo_binary_sha256\t%s\n' \
        "$(fre_c5_tsv_value "$receipt" cargo_binary_sha256)"
    printf 'build_rustc_binary_sha256\t%s\n' \
        "$(fre_c5_tsv_value "$receipt" rustc_binary_sha256)"
    printf 'build_rustdoc_binary_sha256\t%s\n' \
        "$(fre_c5_tsv_value "$receipt" rustdoc_binary_sha256)"
    printf 'build_toolchain_closure_sha256\t%s\n' \
        "$(fre_c5_tsv_value "$receipt" toolchain_closure_sha256)"
    printf 'build_toolchain_closure_entries\t%s\n' \
        "$toolchain_closure_entries"
    printf 'build_toolchain_closure_bytes\t%s\n' \
        "$toolchain_closure_bytes"
    printf 'build_cargo_registry_root\t%s\n' "$cargo_registry_receipt_root"
    printf 'build_cargo_registry_snapshot_root\tprivate-cargo-home-registry-v1\n'
    printf 'build_cargo_registry_closure_sha256\t%s\n' \
        "$expected_cargo_registry_closure_sha"
    printf 'build_cargo_registry_closure_entries\t%s\n' \
        "$cargo_registry_closure_entries"
    printf 'build_cargo_registry_closure_bytes\t%s\n' \
        "$cargo_registry_closure_bytes"
    printf 'resource_coordinator_sha256\t%s\n' \
        "$expected_resource_coordinator_sha"
    printf 'resource_coordinator_cutover_receipt_sha256\t%s\n' \
        "$expected_cutover_receipt_sha"
    printf 'build_clang_binary_sha256\t%s\n' \
        "$(fre_c5_tsv_value "$receipt" clang_binary_sha256)"
    printf 'build_cargo_verbose_sha256\t%s\n' \
        "$(fre_c5_tsv_value "$receipt" cargo_verbose_sha256)"
    printf 'build_rustc_verbose_sha256\t%s\n' \
        "$(fre_c5_tsv_value "$receipt" rustc_verbose_sha256)"
    printf 'build_clang_version_sha256\t%s\n' \
        "$(fre_c5_tsv_value "$receipt" clang_version_sha256)"
} > "$temporary/environment.tsv"
fre_c5_validate_tsv "$temporary/environment.tsv"
fre_c5_require_exact_tsv_keys \
    "$temporary/environment.tsv" "bundle environment" <<'EOF'
schema
uname_s
uname_m
os_version
os_build
runtime_environment
benchmark_cwd
build_toolchain_root
build_cargo_binary_sha256
build_rustc_binary_sha256
build_rustdoc_binary_sha256
build_toolchain_closure_sha256
build_toolchain_closure_entries
build_toolchain_closure_bytes
build_cargo_registry_root
build_cargo_registry_snapshot_root
build_cargo_registry_closure_sha256
build_cargo_registry_closure_entries
build_cargo_registry_closure_bytes
resource_coordinator_sha256
resource_coordinator_cutover_receipt_sha256
build_clang_binary_sha256
build_cargo_verbose_sha256
build_rustc_verbose_sha256
build_clang_version_sha256
EOF

fre_c5_require_subject \
    "$repository" "$expected_commit" "$expected_tree" "$expected_source" true
[[ $(fre_c5_sha256 "$binary") == "$expected_binary" ]] ||
    fre_c5_die "sealed build binary changed during the timing wave"
[[ $(fre_c5_sha256 "$resource_coordinator") == \
    "$expected_resource_coordinator_sha" &&
    $(fre_c5_sha256 "$temporary/resource-coordinator") == \
    "$expected_resource_coordinator_sha" ]] ||
    fre_c5_die "resource coordinator changed during the timing wave"
[[ $(fre_c5_sha256 "$cutover_receipt") == "$expected_cutover_receipt_sha" &&
    $(fre_c5_sha256 "$temporary/resource-coordinator-cutover-receipt") == \
    "$expected_cutover_receipt_sha" ]] ||
    fre_c5_die "cutover receipt changed during the timing wave"

(
    cd "$temporary"
    find . -type f ! -path ./manifest.sha256 -print |
        LC_ALL=C sort |
        while IFS= read -r relative; do
            printf '%s  %s\n' "$(fre_c5_sha256 "$relative")" "$relative"
        done > manifest.sha256
)
manifest_sha=$(fre_c5_sha256 "$temporary/manifest.sha256")

fre_c5_require_new_output_path "$output"
mv -- "$temporary" "$output"
[[ $(fre_c5_owned_directory_identity "$output" "published timing bundle") == \
    "$temporary_identity" ]] ||
    fre_c5_die "published timing bundle differs from owned timing scratch"
temporary=

printf 'SEALED,commit=%s,tree=%s,source=%s,binary=%s,manifest=%s,output=%s\n' \
    "$expected_commit" "$expected_tree" "$expected_source" "$expected_binary" \
    "$manifest_sha" "$output"
