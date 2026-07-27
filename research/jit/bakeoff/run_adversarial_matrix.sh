#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
workspace=$(CDPATH= cd -P -- "$script_dir/../../.." && pwd -P)
output_argument=${1:?usage: run_adversarial_matrix.sh ABSOLUTE_OUTPUT_DIRECTORY}
jobs=${FRE_BAKEOFF_JOBS:-1}
. "$script_dir/runner_support.sh"

if [ "$jobs" != 1 ]; then
    echo "FRE_BAKEOFF_JOBS must remain 1: concurrent timing processes contaminate samples" >&2
    exit 2
fi

fre_bakeoff_prepare_timing_inputs \
    "$workspace" "$output_argument" "$script_dir/capture_provenance.sh"
output=$FRE_BAKEOFF_OUTPUT
source_state=$FRE_BAKEOFF_SOURCE_STATE
binary=$FRE_BAKEOFF_BINARY_PATH

{
    date -u '+utc_started=%Y-%m-%dT%H:%M:%SZ'
    printf 'workspace_revision='; sed -n '1p' "$output/provenance/source/head.txt"
    printf 'source_state_id=%s\n' "$source_state"
    printf 'source_dirty='; sed -n '1p' "$output/provenance/source/dirty.txt"
    printf 'rustc=%s\n' "$FRE_BAKEOFF_BUILD_RUSTC"
    printf 'cargo=%s\n' "$FRE_BAKEOFF_BUILD_CARGO"
    printf 'uname='; uname -a
    printf 'cpu='; sysctl -n machdep.cpu.brand_string 2>/dev/null || printf unavailable
    printf 'physical_cpus='; sysctl -n hw.physicalcpu 2>/dev/null || printf unavailable
    printf 'logical_cpus='; sysctl -n hw.logicalcpu 2>/dev/null || printf unavailable
    printf 'memory_bytes='; sysctl -n hw.memsize 2>/dev/null || printf unavailable
    printf 'binary=%s  %s\n' "$FRE_BAKEOFF_BINARY_SHA256" "$binary"
    printf 'build_receipt=%s  %s\n' \
        "$FRE_BAKEOFF_BUILD_RECEIPT_SHA256" "$FRE_BAKEOFF_BUILD_RECEIPT_PATH"
} > "$output/environment.txt"

"$binary" adversarial-info > "$output/adversarial-cases.txt"
"$binary" inspect exact span > "$output/exact-span.instructions.txt"
"$binary" header > "$output/raw.csv"
"$binary" list-adversarial > "$output/cells.txt"
if [ "$(wc -l < "$output/cells.txt" | tr -d ' ')" != 54 ]; then
    echo "adversarial matrix must contain exactly 54 cells" >&2
    exit 2
fi

while IFS=' ' read -r shape operation size scenario; do
    repetition=0
    while [ "$repetition" -lt 5 ]; do
        "$binary" run "$shape" "$operation" "$size" "$scenario" "$repetition" \
            >> "$output/raw.csv"
        repetition=$((repetition + 1))
    done
done < "$output/cells.txt"

LC_ALL=C awk -f "$script_dir/summarize.awk" "$output/raw.csv" | {
    IFS= read -r header
    printf '%s\n' "$header"
    LC_ALL=C sort
} > "$output/ranges.csv"
LC_ALL=C awk -f "$script_dir/compare.awk" "$output/ranges.csv" | {
    IFS= read -r header
    printf '%s\n' "$header"
    LC_ALL=C sort
} > "$output/comparisons.csv"
awk -F, 'NR == 1 || $3 == "loss"' "$output/comparisons.csv" > "$output/losses.csv"

fre_bakeoff_verify_timing_inputs "$workspace" "$script_dir/capture_provenance.sh"
{
    printf 'raw_rows='; awk 'END { print NR - 1 }' "$output/raw.csv"
    printf 'cells=54\n'
    printf 'processes_per_cell=5\n'
    printf 'source_state_id=%s\n' "$source_state"
    printf 'utc_finished='; date -u '+%Y-%m-%dT%H:%M:%SZ'
} > "$output/completion.txt"
