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
usage: test-results-verifier.sh EXPECTED_BINARY_SHA256 EXPECTED_SOURCE_SHA256 RUN1 RUN2 RUN3

Require one known-valid three-process input, prove exact lower/upper numeric
boundaries remain accepted, then prove that raw, summary, identity, source,
binary, symlink, missing-row, duplicate-PID, huge, noncanonical, non-finite,
out-of-range numeric, and resource-shape mutations all fail closed.
EOF
    exit 2
}

[[ $# -eq 5 ]] || usage
expected_binary=$1
expected_source=$2
shift 2
runs=("$1" "$2" "$3")

fre_c5_require_nonzero_sha256 "$expected_binary" "expected benchmark binary SHA-256"
fre_c5_require_nonzero_sha256 "$expected_source" "expected benchmark source SHA-256"
for run in "${runs[@]}"; do
    fre_c5_require_regular "$run" "known-valid raw run"
done

temporary=$(mktemp -d "/private/tmp/fre-aot-c5-results-test.XXXXXX") ||
    fre_c5_die "cannot create verifier-test scratch directory"
temporary_identity=$(
    fre_c5_owned_directory_identity "$temporary" "results-test scratch directory"
)
cleanup() {
    local status=$?
    local cleanup_failed=false
    if [[ -n ${temporary:-} && ( -e $temporary || -L $temporary ) ]]; then
        if [[ -z ${temporary_identity:-} ]] ||
            ! fre_c5_cleanup_owned_directory \
                "$temporary" "$temporary_identity" \
                /private/tmp/fre-aot-c5-results-test. \
                "results-test scratch directory"; then
            printf '%s\n' \
                "c5-qualification: refused unsafe results-test cleanup" >&2
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

verifier=$script_dir/verify-results.sh
fre_c5_require_regular "$verifier" "raw-results verifier"

verify() {
    /bin/bash -p "$verifier" "$expected_binary" "$expected_source" "$@"
}

verify "${runs[@]}" > "$temporary/positive.txt"

prepare() {
    local case_name=$1
    local case_dir=$temporary/$case_name
    mkdir "$case_dir"
    cp -p -- "${runs[0]}" "$case_dir/run-1.csv"
    cp -p -- "${runs[1]}" "$case_dir/run-2.csv"
    cp -p -- "${runs[2]}" "$case_dir/run-3.csv"
    printf '%s\n' "$case_dir"
}

assert_rejected() {
    local case_name=$1
    shift
    if verify "$@" > "$temporary/$case_name.stdout" 2> "$temporary/$case_name.stderr"; then
        fre_c5_die "raw verifier accepted adversarial case: $case_name"
    fi
}

assert_rejected_with() {
    local case_name=$1
    local expected_error=$2
    shift 2
    assert_rejected "$case_name" "$@"
    grep -F "$expected_error" "$temporary/$case_name.stderr" > /dev/null ||
        fre_c5_die "raw verifier rejected $case_name for the wrong reason"
}

assert_accepted() {
    local case_name=$1
    shift
    verify "$@" > "$temporary/$case_name.stdout" ||
        fre_c5_die "raw verifier rejected valid boundary case: $case_name"
}

rewrite() {
    local input=$1
    local output=$2
    local program=$3
    awk -F, -v OFS=, "$program" "$input" > "$output"
    mv -- "$output" "$input"
}

rewrite_timing_boundary() {
    local input=$1
    local output=$2
    local boundary=$3
    awk -F, -v OFS=, -v boundary="$boundary" '
        $1 == "SAMPLE" && $2 != "case" {
            if (boundary == "lower") {
                aot_elapsed = $8
                portable_elapsed = 2 * $8
            } else {
                aot_elapsed = 34359738368
                portable_elapsed = 68719476736
            }
            $9 = $7 == "qualified-aot-handle" ? aot_elapsed : portable_elapsed
            $10 = sprintf("%.3f", ($9 + 0) / ($8 + 0))
        }
        $1 == "SUMMARY" && $2 != "case" {
            iterations = ($3 + 0) == 65536 ? 1024 : 64
            if (boundary == "lower") {
                aot = 1
                portable = 2
            } else {
                aot = 34359738368 / iterations
                portable = 68719476736 / iterations
            }
            $5 = sprintf("%.3f", aot)
            $6 = sprintf("%.3f", portable)
            $7 = sprintf("%.4f", portable / aot)
            $8 = sprintf("%.4f",
                ($3 + 0) / (1024 * 1024 * 1024) / (aot / 1000000000))
            $9 = sprintf("%.4f",
                ($3 + 0) / (1024 * 1024 * 1024) / (portable / 1000000000))
        }
        { print }
    ' "$input" > "$output"
    mv -- "$output" "$input"
}

for boundary in lower upper; do
    case_dir=$(prepare "sample-$boundary-boundary")
    for run in "$case_dir"/run-{1,2,3}.csv; do
        rewrite_timing_boundary "$run" "$run.rewrite" "$boundary"
    done
    assert_accepted "sample-$boundary-boundary" \
        "$case_dir/run-1.csv" "$case_dir/run-2.csv" "$case_dir/run-3.csv"
done

for specification in \
    first-adoption-lower:first_adoption_ns:1000:none \
    first-adoption-upper:first_adoption_ns:1000000000:none \
    cached-adoption-lower:cached_adoption_total_ns:4096:1.000 \
    cached-adoption-upper:cached_adoption_total_ns:1000000000:244140.625 \
    pid-lower:pid:1:none \
    pid-upper:pid:4294967295:none; do
    case_name=${specification%%:*}
    remainder=${specification#*:}
    key=${remainder%%:*}
    remainder=${remainder#*:}
    value=${remainder%%:*}
    per_call=${remainder##*:}
    case_dir=$(prepare "$case_name")
    awk -F, -v OFS=, -v key="$key" -v value="$value" -v per_call="$per_call" '
        $1 == "META" && $2 == key { $3 = value }
        per_call != "none" &&
            $1 == "META" && $2 == "cached_adoption_ns_per_call" {
            $3 = per_call
        }
        { print }
    ' "$case_dir/run-1.csv" > "$case_dir/rewrite"
    mv -- "$case_dir/rewrite" "$case_dir/run-1.csv"
    assert_accepted "$case_name" \
        "$case_dir/run-1.csv" "$case_dir/run-2.csv" "$case_dir/run-3.csv"
done

case_dir=$(prepare raw-tamper)
rewrite "$case_dir/run-1.csv" "$case_dir/rewrite" '
    !changed && $1 == "SAMPLE" && $2 != "case" {
        $9 = $9 + 1
        changed = 1
    }
    { print }
'
assert_rejected raw-tamper \
    "$case_dir/run-1.csv" "$case_dir/run-2.csv" "$case_dir/run-3.csv"

case_dir=$(prepare summary-tamper)
rewrite "$case_dir/run-1.csv" "$case_dir/rewrite" '
    !changed && $1 == "SUMMARY" && $2 != "case" {
        $7 = "999.0000"
        changed = 1
    }
    { print }
'
assert_rejected summary-tamper \
    "$case_dir/run-1.csv" "$case_dir/run-2.csv" "$case_dir/run-3.csv"

case_dir=$(prepare identity-tamper)
rewrite "$case_dir/run-1.csv" "$case_dir/rewrite" '
    $1 == "META" && $2 == "compile_identity" {
        $3 = "0d06366efaed9de023166d65fcee6dbce761bec7aa62c96ba17d5bece445831f"
    }
    { print }
'
assert_rejected identity-tamper \
    "$case_dir/run-1.csv" "$case_dir/run-2.csv" "$case_dir/run-3.csv"

case_dir=$(prepare source-tamper)
rewrite "$case_dir/run-1.csv" "$case_dir/rewrite" '
    $1 == "META" && $2 == "benchmark_source_sha256" {
        $3 = "0000000000000000000000000000000000000000000000000000000000000001"
    }
    { print }
'
assert_rejected source-tamper \
    "$case_dir/run-1.csv" "$case_dir/run-2.csv" "$case_dir/run-3.csv"

case_dir=$(prepare binary-tamper)
rewrite "$case_dir/run-1.csv" "$case_dir/rewrite" '
    $1 == "META" && $2 == "executable_sha256" {
        $3 = "0000000000000000000000000000000000000000000000000000000000000001"
    }
    { print }
'
assert_rejected binary-tamper \
    "$case_dir/run-1.csv" "$case_dir/run-2.csv" "$case_dir/run-3.csv"

case_dir=$(prepare symlink-tamper)
mv -- "$case_dir/run-1.csv" "$case_dir/real-run-1.csv"
ln -s real-run-1.csv "$case_dir/run-1.csv"
assert_rejected symlink-tamper \
    "$case_dir/run-1.csv" "$case_dir/run-2.csv" "$case_dir/run-3.csv"

case_dir=$(prepare missing-row)
rewrite "$case_dir/run-1.csv" "$case_dir/rewrite" '
    !removed && $1 == "SAMPLE" && $2 != "case" {
        removed = 1
        next
    }
    { print }
'
assert_rejected missing-row \
    "$case_dir/run-1.csv" "$case_dir/run-2.csv" "$case_dir/run-3.csv"

case_dir=$(prepare duplicate-pid)
first_pid=$(awk -F, '$1 == "META" && $2 == "pid" { print $3 }' "$case_dir/run-1.csv")
awk -F, -v OFS=, -v first_pid="$first_pid" '
    $1 == "META" && $2 == "pid" { $3 = first_pid }
    { print }
' "$case_dir/run-2.csv" > "$case_dir/rewrite"
mv -- "$case_dir/rewrite" "$case_dir/run-2.csv"
assert_rejected duplicate-pid \
    "$case_dir/run-1.csv" "$case_dir/run-2.csv" "$case_dir/run-3.csv"

case_dir=$(prepare oversized-run)
dd if=/dev/zero bs=1048576 count=1 >> "$case_dir/run-1.csv" 2>/dev/null
assert_rejected_with oversized-run "raw run exceeds 1048576-byte cap" \
    "$case_dir/run-1.csv" "$case_dir/run-2.csv" "$case_dir/run-3.csv"

case_dir=$(prepare overlong-line)
awk '
    NR == 1 {
        for (ordinal = 0; ordinal < 600; ordinal++) $0 = $0 "x"
    }
    { print }
' "$case_dir/run-1.csv" > "$case_dir/rewrite"
mv -- "$case_dir/rewrite" "$case_dir/run-1.csv"
assert_rejected_with overlong-line "raw run exceeds 512-byte line or 4096-line cap" \
    "$case_dir/run-1.csv" "$case_dir/run-2.csv" "$case_dir/run-3.csv"

case_dir=$(prepare excessive-lines)
awk 'BEGIN { for (ordinal = 0; ordinal < 5000; ordinal++) print "" }' \
    >> "$case_dir/run-1.csv"
assert_rejected_with excessive-lines "raw run exceeds 512-byte line or 4096-line cap" \
    "$case_dir/run-1.csv" "$case_dir/run-2.csv" "$case_dir/run-3.csv"

mutate_first_sample() {
    local case_name=$1
    local field=$2
    local value=$3
    local case_dir
    case_dir=$(prepare "$case_name")
    awk -F, -v OFS=, -v field="$field" -v value="$value" '
        !changed && $1 == "SAMPLE" && $2 != "case" {
            $field = value
            changed = 1
        }
        { print }
    ' "$case_dir/run-1.csv" > "$case_dir/rewrite"
    mv -- "$case_dir/rewrite" "$case_dir/run-1.csv"
    assert_rejected "$case_name" \
        "$case_dir/run-1.csv" "$case_dir/run-2.csv" "$case_dir/run-3.csv"
}

huge=$(printf '1%0300d' 0)
mutate_first_sample huge-decimal 9 "$huge"
mutate_first_sample leading-zero 9 0001024
mutate_first_sample positive-sign 9 +1024
mutate_first_sample negative-sign 9 -1024
mutate_first_sample exponent 10 1e3
mutate_first_sample nan 10 NaN
mutate_first_sample positive-inf 10 Inf
mutate_first_sample negative-inf 10 -Inf
mutate_first_sample elapsed-overflow 9 68719476737
mutate_first_sample elapsed-underflow 9 0
mutate_first_sample fractional-overflow 10 1073741824.001
mutate_first_sample checksum-leading-zero 11 03072
mutate_first_sample coordinate-leading-zero 3 065536
mutate_first_sample repetition-overflow 5 16
mutate_first_sample iterations-overflow 8 1025

for specification in \
    pid-overflow:pid:4294967296 \
    first-adoption-underflow:first_adoption_ns:999 \
    first-adoption-overflow:first_adoption_ns:1000000001 \
    cached-adoption-underflow:cached_adoption_total_ns:4095 \
    cached-adoption-overflow:cached_adoption_total_ns:1000000001 \
    adoption-leading-zero:first_adoption_ns:0001000 \
    adoption-exponent:first_adoption_ns:1e6 \
    adoption-nan:cached_adoption_ns_per_call:NaN \
    adoption-inf:cached_adoption_ns_per_call:Inf; do
    case_name=${specification%%:*}
    remainder=${specification#*:}
    key=${remainder%%:*}
    value=${remainder##*:}
    case_dir=$(prepare "$case_name")
    awk -F, -v OFS=, -v key="$key" -v value="$value" '
        $1 == "META" && $2 == key { $3 = value }
        { print }
    ' "$case_dir/run-1.csv" > "$case_dir/rewrite"
    mv -- "$case_dir/rewrite" "$case_dir/run-1.csv"
    assert_rejected "$case_name" \
        "$case_dir/run-1.csv" "$case_dir/run-2.csv" "$case_dir/run-3.csv"
done

printf 'VERIFIED_ADVERSARIAL,positive=9,rejected=35,cases=structural+identity+numeric-syntax+numeric-bounds+overflow+resource-bounds\n'
