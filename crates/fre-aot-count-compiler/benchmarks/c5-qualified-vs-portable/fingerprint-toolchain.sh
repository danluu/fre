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
usage: fingerprint-toolchain.sh TOOLCHAIN_ROOT

Emit the externally reviewable Cargo, rustc, rustdoc, and bounded full physical
Rust toolchain-root identities consumed by the C5 build and bundle verifiers.
TOOLCHAIN_ROOT must be canonical and contain direct regular bin/cargo,
bin/rustc, and bin/rustdoc executables plus a regular lib directory.
EOF
    exit 2
}

[[ $# -eq 1 ]] || usage
toolchain_root=$(fre_c5_canonical_directory "$1")
fre_c5_require_absolute_path_value "$toolchain_root" "toolchain root"
cargo_tool=$toolchain_root/bin/cargo
rustc_tool=$toolchain_root/bin/rustc
rustdoc_tool=$toolchain_root/bin/rustdoc
for tool_spec in \
    "$cargo_tool:Cargo" \
    "$rustc_tool:rustc" \
    "$rustdoc_tool:rustdoc"; do
    tool=${tool_spec%%:*}
    label=${tool_spec##*:}
    fre_c5_require_regular "$tool" "$label tool"
    [[ -x $tool ]] || fre_c5_die "$label tool is not executable: $tool"
done
[[ -d $toolchain_root/lib && ! -L $toolchain_root/lib ]] ||
    fre_c5_die "toolchain lib must be a regular non-symlink directory"

cargo_sha=$(fre_c5_sha256 "$cargo_tool")
rustc_sha=$(fre_c5_sha256 "$rustc_tool")
rustdoc_sha=$(fre_c5_sha256 "$rustdoc_tool")
for pin_spec in \
    "$cargo_sha:Cargo binary SHA-256" \
    "$rustc_sha:rustc binary SHA-256" \
    "$rustdoc_sha:rustdoc binary SHA-256"; do
    fre_c5_require_nonzero_sha256 "${pin_spec%%:*}" "${pin_spec#*:}"
done

closure_record=$(
    fre_c5_toolchain_closure_fingerprint "$toolchain_root"
) || fre_c5_die "cannot fingerprint the Rust toolchain closure"
[[ $closure_record != *$'\n'* ]] ||
    fre_c5_die "toolchain closure fingerprint emitted multiple records"
IFS=$'\t' read -r closure_sha closure_entries closure_bytes extra \
    <<< "$closure_record"
[[ -z ${extra:-} ]] ||
    fre_c5_die "toolchain closure fingerprint emitted extra fields"
fre_c5_require_nonzero_sha256 "$closure_sha" "toolchain closure SHA-256"
[[ $closure_entries =~ ^[1-9][0-9]*$ && $closure_entries -le 16384 ]] ||
    fre_c5_die "toolchain closure has an invalid entry count"
[[ $closure_bytes =~ ^[1-9][0-9]*$ && $closure_bytes -le 4294967296 ]] ||
    fre_c5_die "toolchain closure has an invalid byte count"

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

[[ $(fre_c5_sha256 "$cargo_tool") == "$cargo_sha" &&
    $(fre_c5_sha256 "$rustc_tool") == "$rustc_sha" &&
    $(fre_c5_sha256 "$rustdoc_tool") == "$rustdoc_sha" ]] ||
    fre_c5_die "toolchain executable changed while being fingerprinted"
[[ $(fre_c5_toolchain_closure_fingerprint "$toolchain_root") == \
    "$closure_record" ]] ||
    fre_c5_die "toolchain closure changed while being fingerprinted"
rustc_sysroot_after=$(
    /usr/bin/env -i \
        LC_ALL=C \
        TZ=UTC \
        PATH=/usr/bin:/bin:/usr/sbin:/sbin \
        "$rustc_tool" --print sysroot
) || fre_c5_die "cannot re-query the direct rustc sysroot"
[[ $rustc_sysroot_after == "$toolchain_root" ]] ||
    fre_c5_die "direct rustc sysroot changed while being fingerprinted"
[[ $(fre_c5_toolchain_closure_fingerprint "$toolchain_root") == \
    "$closure_record" ]] ||
    fre_c5_die "toolchain closure changed after final rustc sysroot query"

printf '%s\n' \
    "schema	fre-aot-count-c5-toolchain-fingerprint-v2" \
    "toolchain_root	$toolchain_root" \
    "cargo_binary_sha256	$cargo_sha" \
    "rustc_binary_sha256	$rustc_sha" \
    "rustdoc_binary_sha256	$rustdoc_sha" \
    "toolchain_closure_sha256	$closure_sha" \
    "toolchain_closure_entries	$closure_entries" \
    "toolchain_closure_bytes	$closure_bytes" \
    "rustc_sysroot_binding	toolchain-root"
