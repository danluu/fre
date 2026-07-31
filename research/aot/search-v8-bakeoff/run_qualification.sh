#!/bin/bash -p
set -Eeuo pipefail

export LC_ALL=C
export TZ=UTC
umask 077
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
hash -r
unset BASH_ENV ENV CDPATH LD_PRELOAD LD_LIBRARY_PATH \
    DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH \
    PYTHONHOME PYTHONPATH PYTHONINSPECT PYTHONSTARTUP 2>/dev/null || :

usage='usage: run_qualification.sh ABSOLUTE_BINARY ABSOLUTE_BUILD_RECEIPT ABSOLUTE_NEW_OUTPUT_DIRECTORY'
[[ $# -eq 3 ]] || {
    printf '%s\n' "$usage" >&2
    exit 2
}
binary=$1
build_receipt=$2
output=$3
case "$binary:$build_receipt:$output" in
    /*:/*:/*) ;;
    *) printf '%s\n' 'all arguments must be absolute paths' >&2; exit 2 ;;
esac

# This driver never invokes a coordinator and never waits for idle CPUs. The
# caller must already hold the reviewed timing admission used by the rest of
# the source-bound qualification system.
[[ ${FRE_RESOURCE_HOLDER_KIND:-} == timing ]]
[[ ${FRE_RESOURCE_HOLDER_DIR:-} == /* ]]
[[ -d $FRE_RESOURCE_HOLDER_DIR && ! -L $FRE_RESOURCE_HOLDER_DIR ]]
holder_token=${FRE_RESOURCE_HOLDER_TOKEN:-}
[[ $holder_token =~ ^[0-9a-f]{64}$ ]] || {
    printf '%s\n' \
        'timing holder token must be exactly 64 lowercase hexadecimal characters' >&2
    exit 2
}

script_dir=$(CDPATH= cd -P -- "$(dirname -- "$0")" && pwd -P)
verifier=$script_dir/verify_results.py
linked_qualifier=$script_dir/qualify_linked_image.sh
[[ -f $binary && ! -L $binary && -x $binary ]]
[[ -f $build_receipt && ! -L $build_receipt ]]
[[ -f $verifier && ! -L $verifier ]]
[[ -f $linked_qualifier && ! -L $linked_qualifier ]]
[[ ! -e $output && ! -L $output ]]
mkdir -m 0700 -- "$output"
mkdir -m 0700 -- \
    "$output/hot-processes" \
    "$output/cold-processes" \
    "$output/first-call-processes" \
    "$output/lifecycle-processes" \
    "$output/runtime-cwd"

sha256() {
    /usr/bin/shasum -a 256 "$1" | /usr/bin/awk '{ print $1 }'
}

receipt_value() {
    local key=$1
    /usr/bin/awk -F '	' -v key="$key" '
        $1 == key {
            if (seen++ || NF != 2 || $2 == "") exit 2
            value = $2
        }
        END {
            if (seen != 1) exit 2
            print value
        }
    ' "$build_receipt"
}

revision=$(receipt_value subject_revision)
[[ $revision =~ ^[0-9a-f]{40}$ ]]
object_path=$(receipt_value object_path)
link_map_path=$(receipt_value link_map_path)
[[ $object_path == /* && -f $object_path && ! -L $object_path ]]
[[ $link_map_path == /* && -f $link_map_path && ! -L $link_map_path ]]
[[ $(sha256 "$object_path") == "$(receipt_value object_identity)" ]]
source_binary_sha256=$(sha256 "$binary")
/bin/cp "$build_receipt" "$output/build-receipt.tsv"
/bin/cp "$object_path" "$output/subject.o"
/bin/cp "$binary" "$output/subject-bin"
/bin/chmod 0400 "$output/subject.o"
/bin/chmod 0500 "$output/subject-bin"
retained_binary=$output/subject-bin
retained_binary_sha256=$(sha256 "$retained_binary")
[[ $retained_binary_sha256 == "$source_binary_sha256" ]]
[[ $(sha256 "$output/subject.o") == "$(receipt_value object_identity)" ]]

/bin/bash -p "$linked_qualifier" \
    "$output/build-receipt.tsv" \
    "$output/subject.o" \
    "$retained_binary" \
    "$link_map_path" \
    "$output/linked-image"
[[ $(sha256 "$retained_binary") == "$retained_binary_sha256" ]]

run_clean() {
    [[ -d $FRE_RESOURCE_HOLDER_DIR && ! -L $FRE_RESOURCE_HOLDER_DIR ]]
    (
        cd "$output/runtime-cwd"
        /usr/bin/env -i \
            LC_ALL=C \
            TZ=UTC \
            PATH=/usr/bin:/bin:/usr/sbin:/sbin \
            FRE_RESOURCE_HOLDER_KIND="$FRE_RESOURCE_HOLDER_KIND" \
            FRE_RESOURCE_HOLDER_DIR="$FRE_RESOURCE_HOLDER_DIR" \
            FRE_RESOURCE_HOLDER_TOKEN="$holder_token" \
            "$@"
    )
}

run_clean "$retained_binary" metadata |
    /usr/bin/awk -F '	' '
        $1 == "FRE_SEARCH_V8_META" && NF == 3 {
            print $2 "\t" $3
            next
        }
        { bad = 1 }
        END { if (bad) exit 1 }
    ' > "$output/metadata.tsv"

run_clean "$retained_binary" hot-header |
    /usr/bin/awk -F '	' '
        $1 == "FRE_SEARCH_V8_HOT_ROW" && NF == 2 { print $2; rows++; next }
        { bad = 1 }
        END { if (bad || rows != 1) exit 1 }
    ' > "$output/hot.csv"
run_clean "$retained_binary" cold-header |
    /usr/bin/awk -F '	' '
        $1 == "FRE_SEARCH_V8_COLD_ROW" && NF == 2 { print $2; rows++; next }
        { bad = 1 }
        END { if (bad || rows != 1) exit 1 }
    ' > "$output/cold.csv"
run_clean "$retained_binary" first-call-header |
    /usr/bin/awk -F '	' '
        $1 == "FRE_SEARCH_V8_FIRST_CALL_ROW" && NF == 2 { print $2; rows++; next }
        { bad = 1 }
        END { if (bad || rows != 1) exit 1 }
    ' > "$output/first-call.csv"
run_clean "$retained_binary" lifecycle-header |
    /usr/bin/awk -F '	' '
        $1 == "FRE_SEARCH_V8_LIFECYCLE_ROW" && NF == 2 { print $2; rows++; next }
        { bad = 1 }
        END { if (bad || rows != 1) exit 1 }
    ' > "$output/lifecycle.csv"

printf '%s\n' 'kind	ordinal	pid	output_sha256	relative_path' \
    > "$output/sequence.tsv"
[[ $(sha256 "$retained_binary") == "$retained_binary_sha256" ]]

record_process() {
    local kind=$1
    local ordinal=$2
    local expected_rows=$3
    local marker=$4
    local process=$5
    local raw=$6
    local rows
    rows=$(
        /usr/bin/awk -F '	' -v marker="$marker" '
            $1 == marker && NF == 2 { print $2; rows++; next }
            { bad = 1 }
            END { if (bad || rows == 0) exit 1 }
        ' "$process"
    )
    [[ $(printf '%s\n' "$rows" | /usr/bin/wc -l | /usr/bin/tr -d ' ') == "$expected_rows" ]]
    local pid
    pid=$(
        printf '%s\n' "$rows" |
            /usr/bin/awk -F, '
                NR == 1 { pid = $3 }
                $3 != pid || $3 !~ /^[1-9][0-9]*$/ { bad = 1 }
                END { if (bad || NR == 0) exit 1; print pid }
            '
    )
    printf '%s\n' "$rows" >> "$raw"
    local relative
    relative=$(printf '%s-processes/%06d.txt' "$kind" "$ordinal")
    printf '%s\t%d\t%s\t%s\t%s\n' \
        "$kind" "$ordinal" "$pid" "$(sha256 "$process")" "$relative" \
        >> "$output/sequence.tsv"
}

scenarios=(
    present
    absent
    dense
    tail
    primary-dense-secondary-absent
    adaptive-secondary-dense-primary-absent
    pair-dense-literal-absent
    triple-dense-literal-absent
    false-pair-distant-match
    binary
    natural-text
)
for residue in {0..15}; do
    scenarios+=("alignment-$residue")
done
[[ ${#scenarios[@]} -eq 27 ]]

hot_ordinal=0
for size in 64k 1m; do
    for scenario in "${scenarios[@]}"; do
        for repetition in {0..11}; do
            hot_ordinal=$((hot_ordinal + 1))
            process=$(printf '%s/hot-processes/%06d.txt' "$output" "$hot_ordinal")
            run_clean "$retained_binary" hot "$size" "$scenario" "$repetition" \
                > "$process" 2>&1
            record_process \
                hot "$hot_ordinal" 3 FRE_SEARCH_V8_HOT_ROW \
                "$process" "$output/hot.csv"
        done
    done
done
[[ $hot_ordinal -eq 648 ]]
[[ $(sha256 "$retained_binary") == "$retained_binary_sha256" ]]

cold_ordinal=0
for repetition in {0..11}; do
    cold_ordinal=$((cold_ordinal + 1))
    process=$(printf '%s/cold-processes/%06d.txt' "$output" "$cold_ordinal")
    run_clean "$retained_binary" cold "$repetition" > "$process" 2>&1
    record_process \
        cold "$cold_ordinal" 7 FRE_SEARCH_V8_COLD_ROW \
        "$process" "$output/cold.csv"
done
[[ $cold_ordinal -eq 12 ]]
[[ $(sha256 "$retained_binary") == "$retained_binary_sha256" ]]

first_cases=(
    '64k absent'
    '64k adaptive-secondary-dense-primary-absent'
    '1m tail'
    '1m natural-text'
)
engines=(raw-static-aot strict-wx-jit portable)
first_ordinal=0
for case_fields in "${first_cases[@]}"; do
    read -r size scenario <<< "$case_fields"
    for engine in "${engines[@]}"; do
        for repetition in {0..19}; do
            first_ordinal=$((first_ordinal + 1))
            process=$(printf '%s/first-call-processes/%06d.txt' \
                "$output" "$first_ordinal")
            run_clean "$retained_binary" first-call \
                "$engine" "$size" "$scenario" "$repetition" \
                > "$process" 2>&1
            record_process \
                first-call "$first_ordinal" 1 \
                FRE_SEARCH_V8_FIRST_CALL_ROW \
                "$process" "$output/first-call.csv"
        done
    done
done
[[ $first_ordinal -eq 240 ]]
[[ $(sha256 "$retained_binary") == "$retained_binary_sha256" ]]

lifecycle_cases=(
    '64k absent'
    '64k adaptive-secondary-dense-primary-absent'
    '1m tail'
    '1m natural-text'
)
lifecycle_ordinal=0
for case_fields in "${lifecycle_cases[@]}"; do
    read -r size scenario <<< "$case_fields"
    if [[ $size == 64k ]]; then
        lifecycle_calls=(0 1 2 4 8 16 32 64 128 256 512 1024)
    else
        lifecycle_calls=(0 1 2 4 8 16 32 64)
    fi
    for calls in "${lifecycle_calls[@]}"; do
        for repetition in {0..23}; do
            lifecycle_ordinal=$((lifecycle_ordinal + 1))
            process=$(printf '%s/lifecycle-processes/%06d.txt' \
                "$output" "$lifecycle_ordinal")
            run_clean "$retained_binary" lifecycle \
                "$size" "$scenario" "$calls" "$repetition" \
                > "$process" 2>&1
            record_process \
                lifecycle "$lifecycle_ordinal" 2 \
                FRE_SEARCH_V8_LIFECYCLE_ROW \
                "$process" "$output/lifecycle.csv"
        done
    done
done
[[ $lifecycle_ordinal -eq 960 ]]
[[ $(sha256 "$retained_binary") == "$retained_binary_sha256" ]]

run_clean /usr/bin/python3 "$verifier" derive \
    "$output/build-receipt.tsv" "$output/hot.csv" \
    > "$output/summary.csv"
run_clean /usr/bin/python3 "$verifier" derive-lifecycle-summary \
    "$output/build-receipt.tsv" "$output/lifecycle.csv" \
    > "$output/lifecycle-summary.csv"
run_clean /usr/bin/python3 "$verifier" derive-lifecycle-break-even \
    "$output/build-receipt.tsv" "$output/lifecycle.csv" \
    > "$output/lifecycle-break-even.csv"

# Preserve the raw-derived diagnostics above for a losing candidate, but do
# not emit environment or completion evidence unless the strict sustained
# lifecycle break-even gate passes.
run_clean /usr/bin/python3 "$verifier" qualify-lifecycle \
    "$output/build-receipt.tsv" "$output/lifecycle.csv" \
    > /dev/null

{
    [[ $(sha256 "$retained_binary") == "$retained_binary_sha256" ]]
    printf 'schema\tfre-search-v8-bakeoff-environment-v3\n'
    printf 'subject_revision\t%s\n' "$revision"
    printf 'binary_relative_path\tsubject-bin\n'
    printf 'binary_sha256\t%s\n' "$retained_binary_sha256"
    printf 'build_receipt_sha256\t%s\n' \
        "$(sha256 "$output/build-receipt.tsv")"
    printf 'linked_verification_sha256\t%s\n' \
        "$(sha256 "$output/linked-image/verification.tsv")"
    printf 'timing_admission_kind\ttiming\n'
    printf 'lifecycle_process_state\tfresh-process-per-case-call-count-repetition\n'
    printf 'lifecycle_os_page_cache\tuncontrolled\n'
    printf 'lifecycle_cache_flush\tabsent\n'
    printf 'lifecycle_outlier_removal\tabsent\n'
} > "$output/environment.tsv"

{
    printf 'schema\tfre-search-v8-bakeoff-completion-v3\n'
    printf 'subject_revision\t%s\n' "$revision"
    printf 'hot_invocations\t648\n'
    printf 'hot_rows\t1944\n'
    printf 'cold_invocations\t12\n'
    printf 'cold_rows\t84\n'
    printf 'first_call_invocations\t240\n'
    printf 'first_call_rows\t240\n'
    printf 'lifecycle_invocations\t960\n'
    printf 'lifecycle_rows\t1920\n'
    printf 'hot_repetitions\t12\n'
    printf 'cold_repetitions\t12\n'
    printf 'first_call_repetitions\t20\n'
    printf 'lifecycle_repetitions\t24\n'
    printf 'lifecycle_cases\t4\n'
    printf 'lifecycle_call_cells\t40\n'
    printf 'lifecycle_engines\t2\n'
    printf 'retained_binary_files\t1\n'
    printf 'linked_image_files\t4\n'
    printf 'linked_image_receipt_rows\t24\n'
    printf 'timing_admission_kind\ttiming\n'
    printf 'evidence_class\tmeasured\n'
} > "$output/completion.tsv"

run_clean /usr/bin/python3 "$verifier" verify "$output"
[[ $(sha256 "$retained_binary") == "$retained_binary_sha256" ]]
