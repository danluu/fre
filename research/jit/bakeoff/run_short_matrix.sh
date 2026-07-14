#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
output=${1:?usage: run_short_matrix.sh OUTPUT_DIRECTORY}

mkdir -p "$output"
binary="$script_dir/target/release/fre-jit-bakeoff"
if [ "${FRE_BAKEOFF_SKIP_BUILD:-0}" != 1 ]; then
    cargo build --manifest-path "$script_dir/Cargo.toml" --release --locked
fi
test -x "$binary"
"$binary" header > "$output/raw.csv"

for shape in literal1 literal6 literal15; do
    for operation in exists end span; do
        for size in short 64k 1m; do
            for scenario in present absent dense tail unaligned; do
                repetition=0
                while [ "$repetition" -lt 5 ]; do
                    "$binary" run "$shape" "$operation" "$size" "$scenario" "$repetition" >> "$output/raw.csv"
                    repetition=$((repetition + 1))
                done
            done
        done
    done
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

{
    printf 'raw_rows='; awk 'END { print NR - 1 }' "$output/raw.csv"
    printf 'cells=135\n'
    printf 'processes_per_cell=5\n'
} > "$output/completion.txt"
