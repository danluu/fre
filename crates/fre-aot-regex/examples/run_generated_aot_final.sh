#!/usr/bin/env bash
# Run one host's final flat+nested, two-root, AB/BA, three-contract matrix.
#
# Deliberately no root seeds are embedded here. Set FINAL_ROOT_A and
# FINAL_ROOT_B only when the reserved final roots are released for use.
# Build and source transfer happen once before any benchmark process.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 OUTPUT_DIRECTORY FEATURES" >&2
  echo "example FEATURES: asimd or avx2" >&2
  exit 64
fi
: "${FINAL_ROOT_A:?set FINAL_ROOT_A only after final-root release}"
: "${FINAL_ROOT_B:?set FINAL_ROOT_B only after final-root release}"

output_directory=$1
features=$2
trials=${FRE_FINAL_TRIALS:-5}
warmup_rounds=${FRE_FINAL_WARMUP_ROUNDS:-8}
bytes_per_trial=${FRE_FINAL_BYTES_PER_TRIAL:-262144}
min_trial_ns=${FRE_FINAL_MIN_TRIAL_NS:-5000000}
min_searches=${FRE_FINAL_MIN_SEARCHES:-1}

for root in "$FINAL_ROOT_A" "$FINAL_ROOT_B"; do
  if [[ ! $root =~ ^0x[0-9a-fA-F]{1,16}$ ]]; then
    echo "final roots must be 0x-prefixed u64 values" >&2
    exit 64
  fi
done
if [[ $FINAL_ROOT_A == "$FINAL_ROOT_B" ]]; then
  echo "final roots must be distinct" >&2
  exit 64
fi

mkdir -p "$output_directory"
cargo build --locked --release -p fre-aot-regex \
  --example generated_aot_upstream_comparison
benchmark=${FRE_FINAL_BENCHMARK_BIN:-target/release/examples/generated_aot_upstream_comparison}
if [[ ! -x $benchmark ]]; then
  echo "benchmark executable is missing: $benchmark" >&2
  exit 66
fi

common=(
  --output-matrix
  --features "$features"
  --trials "$trials"
  --warmup-rounds "$warmup_rounds"
  --bytes-per-trial "$bytes_per_trial"
  --min-searches "$min_searches"
  --min-trial-ns "$min_trial_ns"
)
configuration=0
for root in "$FINAL_ROOT_A" "$FINAL_ROOT_B"; do
  root_label=${root#0x}
  for generator in flat nested; do
    if [[ $generator == flat ]]; then
      generator_flag=--grammar
      expected_rows=1944
    else
      generator_flag=--nested-grammar
      expected_rows=6912
    fi
    if (( configuration % 2 == 0 )); then
      orders=(upstream-native native-upstream)
    else
      orders=(native-upstream upstream-native)
    fi
    for order in "${orders[@]}"; do
      stem="${generator}__${root_label}__${order}"
      temporary="$output_directory/.${stem}.tsv.tmp"
      "$benchmark" "$generator_flag" --seed "$root" \
        --measurement-order "$order" "${common[@]}" \
        >"$temporary" 2>"$output_directory/${stem}.stderr"
      if ! awk -F '\t' -v expected="$order" \
        '$1 == "environment" && $2 == "measurement_order" && $3 == expected { found = 1 } END { exit !found }' \
        "$temporary"; then
        echo "missing measurement-order receipt in $temporary" >&2
        exit 65
      fi
      if ! awk -F '\t' \
        '$1 == "environment" && $2 == "output_matrix" && $3 == "span_exists_selected_end_v1" { found = 1 } END { exit !found }' \
        "$temporary"; then
        echo "missing output-matrix receipt in $temporary" >&2
        exit 65
      fi
      actual_rows=$(awk -F '\t' '$1 == "comparison" && $2 != "case" { count++ } END { print count + 0 }' "$temporary")
      if [[ $actual_rows -ne $expected_rows ]]; then
        echo "$temporary has $actual_rows comparison rows; expected $expected_rows" >&2
        exit 65
      fi
      mv "$temporary" "$output_directory/${stem}.tsv"
    done
    configuration=$((configuration + 1))
  done
done

echo "completed one-host final matrix in $output_directory" >&2
echo "after collecting all hosts, score with:" >&2
echo "python3 crates/fre-aot-regex/examples/score_generated_aot_comparison.py <all .tsv files>" >&2
