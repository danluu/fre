#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
workspace=$(CDPATH= cd -P -- "$script_dir/../../.." && pwd -P)
build_argument=${1:?usage: build_bakeoff.sh ABSOLUTE_BUILD_DIRECTORY ABSOLUTE_RECEIPT_DIRECTORY}
receipt_argument=${2:?usage: build_bakeoff.sh ABSOLUTE_BUILD_DIRECTORY ABSOLUTE_RECEIPT_DIRECTORY}
if [ "$#" != 2 ]; then
    echo "usage: build_bakeoff.sh ABSOLUTE_BUILD_DIRECTORY ABSOLUTE_RECEIPT_DIRECTORY" >&2
    exit 2
fi

. "$script_dir/runner_support.sh"
fre_bakeoff_require_holder build
fre_bakeoff_canonical_external_directory "$workspace" "$build_argument"
build_dir=$FRE_BAKEOFF_CANONICAL_PATH
fre_bakeoff_canonical_new_external_directory "$workspace" "$receipt_argument"
receipt_dir=$FRE_BAKEOFF_CANONICAL_PATH

mkdir -- "$receipt_dir"
chmod 0700 "$receipt_dir"
source_state=$(
    "$script_dir/capture_provenance.sh" capture "$workspace" "$receipt_dir/source"
)

export CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR=$build_dir
cargo build --manifest-path "$script_dir/Cargo.toml" --release --locked

binary="$build_dir/release/fre-jit-bakeoff"
fre_bakeoff_canonical_executable "$binary" "built bakeoff binary"
binary=$FRE_BAKEOFF_CANONICAL_PATH
binary_sha=$(fre_bakeoff_sha256 "$binary")
"$script_dir/capture_provenance.sh" verify "$workspace" "$receipt_dir/source"

manifest="$script_dir/Cargo.toml"
lockfile="$script_dir/Cargo.lock"
temporary="$receipt_dir/build-receipt.tsv.tmp"
{
    printf 'schema\tfre-jit-bakeoff-build-receipt-v1\n'
    printf 'source_state_id\t%s\n' "$source_state"
    printf 'binary_path\t%s\n' "$binary"
    printf 'binary_sha256\t%s\n' "$binary_sha"
    printf 'build_dir\t%s\n' "$build_dir"
    printf 'manifest_path\t%s\n' "$manifest"
    printf 'manifest_sha256\t%s\n' "$(fre_bakeoff_sha256 "$manifest")"
    printf 'lockfile_path\t%s\n' "$lockfile"
    printf 'lockfile_sha256\t%s\n' "$(fre_bakeoff_sha256 "$lockfile")"
    printf 'rustc\t%s\n' "$(rustc --version)"
    printf 'cargo\t%s\n' "$(cargo --version)"
    printf 'coordinator_holder_dir\t%s\n' "${FRE_RESOURCE_HOLDER_DIR:-unknown}"
    printf 'built_utc\t%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
} > "$temporary"
mv -- "$temporary" "$receipt_dir/build-receipt.tsv"
fre_bakeoff_validate_build_receipt "$receipt_dir/build-receipt.tsv"
fre_bakeoff_sha256 "$receipt_dir/build-receipt.tsv" \
    > "$receipt_dir/build-receipt.sha256"

printf 'binary=%s\n' "$binary"
printf 'binary_sha256=%s\n' "$binary_sha"
printf 'source_state_id=%s\n' "$source_state"
printf 'receipt=%s\n' "$receipt_dir/build-receipt.tsv"
printf 'receipt_sha256='
sed -n '1p' "$receipt_dir/build-receipt.sha256"
