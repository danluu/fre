#!/bin/bash -p
set -Eeuo pipefail

export LC_ALL=C
export TZ=UTC
umask 077
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
hash -r
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
usage: fingerprint-cargo-registry.sh CARGO_REGISTRY_ROOT

Emit the externally reviewable bounded identity of the complete registry
subtree that will be copied under the build's private CARGO_HOME. The root
must be canonical and contain physical cache, index, and src directories.
EOF
    exit 2
}

[[ $# -eq 1 ]] || usage
cargo_registry_root=$(fre_c5_canonical_directory "$1")
fre_c5_require_absolute_path_value "$cargo_registry_root" "Cargo registry root"
for child in cache index src; do
    [[ -d $cargo_registry_root/$child &&
        ! -L $cargo_registry_root/$child ]] ||
        fre_c5_die "Cargo registry root lacks a physical $child directory"
done

closure_record=$(
    fre_c5_cargo_registry_closure_fingerprint "$cargo_registry_root"
) || fre_c5_die "cannot fingerprint the Cargo registry closure"
[[ $closure_record != *$'\n'* ]] ||
    fre_c5_die "Cargo registry fingerprint emitted multiple records"
IFS=$'\t' read -r closure_sha closure_entries closure_bytes extra \
    <<< "$closure_record"
[[ -z ${extra:-} ]] ||
    fre_c5_die "Cargo registry fingerprint emitted extra fields"
fre_c5_require_nonzero_sha256 "$closure_sha" "Cargo registry closure SHA-256"
fre_c5_require_bounded_positive_decimal \
    "$closure_entries" 100000 "Cargo registry closure entry count"
fre_c5_require_bounded_positive_decimal \
    "$closure_bytes" 4294967296 "Cargo registry closure byte count"

printf '%s\n' \
    "schema	fre-aot-count-c5-cargo-registry-fingerprint-v1" \
    "cargo_registry_root	$cargo_registry_root" \
    "cargo_registry_closure_sha256	$closure_sha" \
    "cargo_registry_closure_entries	$closure_entries" \
    "cargo_registry_closure_bytes	$closure_bytes"
