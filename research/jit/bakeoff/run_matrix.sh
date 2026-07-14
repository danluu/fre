#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
workspace=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
output=${1:-"$script_dir/results/baseline"}
jobs=${FRE_BAKEOFF_JOBS:-1}
linked_artifacts=${FRE_BAKEOFF_LINKED_ARTIFACTS:-1}

if [ "$jobs" != 1 ]; then
    echo "FRE_BAKEOFF_JOBS must remain 1: concurrent timing processes contaminate samples" >&2
    exit 2
fi
if [ "$linked_artifacts" != 0 ] && [ "$linked_artifacts" != 1 ]; then
    echo "FRE_BAKEOFF_LINKED_ARTIFACTS must be 0 or 1" >&2
    exit 2
fi

mkdir -p "$output"
fixture=$($script_dir/fetch_sherlock.sh)
revision=$(git -C "$workspace" rev-parse HEAD 2>/dev/null || printf unknown)
export FRE_BAKEOFF_REVISION=$revision

cargo build --manifest-path "$script_dir/Cargo.toml" --release --locked
binary="$script_dir/target/release/fre-jit-bakeoff"

{
    date -u '+utc_started=%Y-%m-%dT%H:%M:%SZ'
    printf 'workspace_revision=%s\n' "$revision"
    printf 'rebar_revision=%s\n' 463d00f31887e84c38467805b9e3122c314b9521
    printf 'rustc='; rustc --version
    printf 'cargo='; cargo --version
    printf 'uname='; uname -a
    printf 'cpu='; sysctl -n machdep.cpu.brand_string 2>/dev/null || printf unavailable
    printf 'physical_cpus='; sysctl -n hw.physicalcpu 2>/dev/null || printf unavailable
    printf 'logical_cpus='; sysctl -n hw.logicalcpu 2>/dev/null || printf unavailable
    printf 'memory_bytes='; sysctl -n hw.memsize 2>/dev/null || printf unavailable
    printf 'fixture='; shasum -a 256 "$fixture"
    printf 'binary='; shasum -a 256 "$binary"
} > "$output/environment.txt"

"$binary" header > "$output/raw.csv"
"$binary" list > "$output/cells.txt"

while IFS=' ' read -r shape operation size scenario; do
    repetition=0
    while [ "$repetition" -lt 5 ]; do
        "$binary" run "$shape" "$operation" "$size" "$scenario" "$repetition" >> "$output/raw.csv"
        repetition=$((repetition + 1))
    done
done < "$output/cells.txt"

repetition=0
while [ "$repetition" -lt 5 ]; do
    "$binary" sherlock "$fixture" "$repetition" >> "$output/raw.csv"
    repetition=$((repetition + 1))
done

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

"$binary" inspect exact span > "$output/exact-span.instructions.txt"
"$binary" inspect class span > "$output/class-span.instructions.txt"
if [ "$linked_artifacts" = 1 ]; then
    nm -nm "$binary" > "$output/linked-symbols.txt"
    otool -l "$binary" > "$output/linked-load-commands.txt"
    otool -tvV "$binary" > "$output/linked-disassembly.txt"
else
    printf 'linked binary artifacts skipped by FRE_BAKEOFF_LINKED_ARTIFACTS=0\n' \
        > "$output/linked-artifacts-skipped.txt"
fi

{
    printf 'raw_rows='; awk 'END { print NR - 1 }' "$output/raw.csv"
    printf 'cells='; wc -l < "$output/cells.txt" | tr -d ' '
    printf 'processes_per_cell=5\n'
    printf 'linked_artifacts=%s\n' "$linked_artifacts"
    printf 'utc_finished='; date -u '+%Y-%m-%dT%H:%M:%SZ'
} > "$output/completion.txt"
