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

[[ $# -eq 2 ]] || fre_c5_die \
    "usage: run-qualified-timing-wave.sh RUN_DIR EXPECTED_BINARY_SHA256"
run_dir=$(fre_c5_canonical_directory "$1")
expected_binary=$2
fre_c5_require_nonzero_sha256 \
    "$expected_binary" "expected benchmark binary SHA-256"
binary=$run_dir/candidate-binary
fre_c5_require_regular "$binary" "timing-wave candidate binary"
[[ -x $binary ]] || fre_c5_die "timing-wave candidate binary is not executable"
[[ $(fre_c5_sha256 "$binary") == "$expected_binary" ]] ||
    fre_c5_die "timing-wave candidate binary differs from external identity"

runtime_home=$run_dir/runtime-home
[[ ! -e $runtime_home && ! -L $runtime_home ]] ||
    fre_c5_die "timing-wave private HOME path already exists"
mkdir -m 0700 "$runtime_home"
for process_index in 1 2 3; do
    for output in \
        "$run_dir/run-$process_index.csv" \
        "$run_dir/run-$process_index.time" \
        "$run_dir/run-$process_index.binary.before" \
        "$run_dir/run-$process_index.binary.after"; do
        [[ ! -e $output && ! -L $output ]] ||
            fre_c5_die "timing-wave output already exists: $output"
    done
    before=$(fre_c5_sha256 "$binary")
    [[ $before == "$expected_binary" ]] ||
        fre_c5_die "candidate binary changed before process $process_index"
    printf '%s  candidate-binary\n' "$before" \
        > "$run_dir/run-$process_index.binary.before"
    (
        cd "$run_dir"
        /usr/bin/env -i \
            LC_ALL=C \
            TZ=UTC \
            HOME="$runtime_home" \
            PATH=/usr/bin:/bin:/usr/sbin:/sbin \
            /usr/bin/time -l ./candidate-binary
    ) > "$run_dir/run-$process_index.csv" \
        2> "$run_dir/run-$process_index.time"
    after=$(fre_c5_sha256 "$binary")
    [[ $after == "$expected_binary" ]] ||
        fre_c5_die "candidate binary changed after process $process_index"
    printf '%s  candidate-binary\n' "$after" \
        > "$run_dir/run-$process_index.binary.after"
done
[[ -z $(find "$runtime_home" -mindepth 1 -print -quit) ]] ||
    fre_c5_die "benchmark wrote unexpected state under its private HOME"
rmdir "$runtime_home"
