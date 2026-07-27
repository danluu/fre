#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
workspace=$(CDPATH= cd -P -- "$script_dir/../../.." && pwd -P)
output_argument=${1:?usage: run_class_focus.sh ABSOLUTE_OUTPUT_DIRECTORY [RETAINED_RESULTS]}
retained=${2:-"$script_dir/results/after-lazy-two-position"}
. "$script_dir/runner_support.sh"

if [ ! -f "$retained/ranges.csv" ]; then
    echo "missing retained ranges: $retained/ranges.csv" >&2
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
    printf 'binary=%s  %s\n' "$FRE_BAKEOFF_BINARY_SHA256" "$binary"
    printf 'build_receipt=%s  %s\n' \
        "$FRE_BAKEOFF_BUILD_RECEIPT_SHA256" "$FRE_BAKEOFF_BUILD_RECEIPT_PATH"
    printf 'retained_ranges='; shasum -a 256 "$retained/ranges.csv"
} > "$output/environment.txt"

"$binary" list | awk '$1 == "class"' > "$output/cells.txt"
if [ "$(wc -l < "$output/cells.txt" | tr -d ' ')" != 45 ]; then
    echo "class focus must contain exactly 45 cells" >&2
    exit 2
fi

"$binary" header > "$output/raw.csv"
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

awk -F, '
    BEGIN { OFS = "," }
    NR == FNR {
        if ($2 == "jit" && $3 == "direct_lease_call") retained[$1] = $6
        next
    }
    FNR == 1 {
        print "cell", "result", "new_mean_ns", "retained_mean_ns", "new_over_retained"
        next
    }
    $2 == "jit" && $3 == "direct_lease_call" {
        result = $6 < retained[$1] ? "improved" : ($6 > retained[$1] ? "regressed" : "tie")
        ratio = retained[$1] == 0 ? "inf" : sprintf("%.4f", $6 / retained[$1])
        print $1, result, $6, retained[$1], ratio
    }
' "$retained/ranges.csv" "$output/ranges.csv" > "$output/vs-retained.csv"

fre_bakeoff_verify_timing_inputs "$workspace" "$script_dir/capture_provenance.sh"
{
    printf 'raw_rows='; awk 'END { print NR - 1 }' "$output/raw.csv"
    printf 'cells='; wc -l < "$output/cells.txt" | tr -d ' '
    printf 'processes_per_cell=5\n'
    printf 'source_state_id=%s\n' "$source_state"
    printf 'utc_finished='; date -u '+%Y-%m-%dT%H:%M:%SZ'
} > "$output/completion.txt"
