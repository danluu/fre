#!/usr/bin/env bash
# Run one preregistered host profile's flat+nested, two-root, AB/BA,
# three-contract matrix under one complete acceptance schema.
#
# Deliberately no root seeds are embedded here. Set FINAL_ROOT_A and
# FINAL_ROOT_B only when the reserved final roots are released for use.
# Build and source transfer happen once before any benchmark process.
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "usage: $0 OUTPUT_DIRECTORY PROFILE [MATRIX_SCHEMA]" >&2
  echo "base PROFILE values: macos-aarch64-asimd, linux-aarch64-asimd, linux-x86_64-avx2" >&2
  echo "additive PROFILE values: linux-aarch64-sve, linux-aarch64-sve2, linux-x86_64-avx512" >&2
  echo "MATRIX_SCHEMA defaults to general-v1" >&2
  exit 64
fi
: "${FINAL_ROOT_A:?set FINAL_ROOT_A only after final-root release}"
: "${FINAL_ROOT_B:?set FINAL_ROOT_B only after final-root release}"

output_directory=$1
requested_profile=$2
matrix_schema=${3:-general-v1}
trials=${FRE_FINAL_TRIALS:-5}
warmup_rounds=${FRE_FINAL_WARMUP_ROUNDS:-8}
bytes_per_trial=${FRE_FINAL_BYTES_PER_TRIAL:-262144}
min_trial_ns=${FRE_FINAL_MIN_TRIAL_NS:-5000000}
min_searches=${FRE_FINAL_MIN_SEARCHES:-1}

case "$(uname -s):$(uname -m)" in
  Darwin:arm64 | Darwin:aarch64) actual_target=macos-aarch64 ;;
  Linux:arm64 | Linux:aarch64) actual_target=linux-aarch64 ;;
  Linux:x86_64 | Linux:amd64) actual_target=linux-x86_64 ;;
  *)
    echo "unsupported qualification host: $(uname -s):$(uname -m)" >&2
    exit 64
    ;;
esac

# Keep the historical base feature spellings as host-specific aliases. All
# additive invocations use a canonical profile name so a feature experiment
# cannot silently become qualification input.
case "$actual_target:$requested_profile" in
  macos-aarch64:asimd | macos-aarch64:macos-aarch64-asimd)
    profile=macos-aarch64-asimd
    expected_target=macos-aarch64
    features=asimd
    expected_feature_bits=0x100000000
    ;;
  linux-aarch64:asimd | linux-aarch64:linux-aarch64-asimd)
    profile=linux-aarch64-asimd
    expected_target=linux-aarch64
    features=asimd
    expected_feature_bits=0x100000000
    ;;
  linux-aarch64:linux-aarch64-sve)
    profile=linux-aarch64-sve
    expected_target=linux-aarch64
    features=asimd,sve
    expected_feature_bits=0x300000000
    ;;
  linux-aarch64:linux-aarch64-sve2)
    profile=linux-aarch64-sve2
    expected_target=linux-aarch64
    features=asimd,sve,sve2
    expected_feature_bits=0x700000000
    ;;
  linux-x86_64:avx2 | linux-x86_64:linux-x86_64-avx2)
    profile=linux-x86_64-avx2
    expected_target=linux-x86_64
    features=avx2
    expected_feature_bits=0x2
    ;;
  linux-x86_64:linux-x86_64-avx512)
    profile=linux-x86_64-avx512
    expected_target=linux-x86_64
    features=avx2,avx512f,avx512bw,avx512vl
    expected_feature_bits=0x1e
    ;;
  *)
    echo "profile $requested_profile is not preregistered for $actual_target" >&2
    exit 64
    ;;
esac

schema_flag=
case "$matrix_schema" in
  general-v1)
    expected_force_resource=false
    expected_force_retained=false
    expected_force_slow_partial=false
    expected_slow_aot_policy=default
    ;;
  forced-resource-fallback-v1)
    schema_flag=--force-resource-fallback
    expected_force_resource=true
    expected_force_retained=false
    expected_force_slow_partial=false
    expected_slow_aot_policy=disabled_for_zero_rows
    ;;
  forced-retained-resource-fallback-v1)
    schema_flag=--force-retained-resource-fallback
    expected_force_resource=false
    expected_force_retained=true
    expected_force_slow_partial=false
    expected_slow_aot_policy=disabled_for_retained_rows
    ;;
  forced-slow-partial-resource-fallback-v1)
    schema_flag=--force-slow-partial-resource-fallback
    expected_force_resource=false
    expected_force_retained=false
    expected_force_slow_partial=true
    expected_slow_aot_policy=derived_incomplete_forward_prefix
    ;;
  *)
    echo "unknown complete matrix schema: $matrix_schema" >&2
    exit 64
    ;;
esac

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
if [[ -n $schema_flag ]]; then
  common+=("$schema_flag")
fi
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
      stem="${matrix_schema}__${profile}__${generator}__${root_label}__${order}"
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
      require_environment_receipt() {
        local key=$1
        local expected=$2
        if ! awk -F '\t' -v key="$key" -v expected="$expected" \
          '$1 == "environment" && $2 == key && $3 == expected { found = 1 } END { exit !found }' \
          "$temporary"; then
          echo "missing $key=$expected receipt in $temporary" >&2
          exit 65
        fi
      }
      require_environment_receipt target "$expected_target"
      require_environment_receipt requested_features "$features"
      require_environment_receipt feature_bits "$expected_feature_bits"
      require_environment_receipt host_feature_validation passed
      require_environment_receipt force_resource_fallback "$expected_force_resource"
      require_environment_receipt force_retained_resource_fallback "$expected_force_retained"
      require_environment_receipt force_slow_partial_resource_fallback "$expected_force_slow_partial"
      require_environment_receipt slow_native_data_bytes default
      require_environment_receipt slow_aot_policy "$expected_slow_aot_policy"
      actual_rows=$(awk -F '\t' '$1 == "comparison" && $2 != "case" { count++ } END { print count + 0 }' "$temporary")
      if [[ $actual_rows -ne $expected_rows ]]; then
        echo "$temporary has $actual_rows comparison rows; expected $expected_rows" >&2
        exit 65
      fi
      if [[ $matrix_schema == forced-slow-partial-resource-fallback-v1 ]]; then
        admitted=$(awk -F '\t' '$1 == "comparison" && $2 != "case" && $10 == "slow_partial_resource_fallback" { seen[$3 FS $7 FS $8] = 1 } END { for (key in seen) { count++ } print count + 0 }' "$temporary")
        if [[ $admitted -eq 0 ]]; then
          echo "$temporary admitted no slow-partial source contract" >&2
          exit 65
        fi
      fi
      mv "$temporary" "$output_directory/${stem}.tsv"
    done
    configuration=$((configuration + 1))
  done
done

echo "completed $profile / $matrix_schema matrix in $output_directory" >&2
echo "after collecting all hosts, score with:" >&2
score_profile_option=
case "$profile" in
  linux-aarch64-sve | linux-aarch64-sve2 | linux-x86_64-avx512)
    score_profile_option=" --additive-profile $profile"
    ;;
esac
echo "python3 crates/fre-aot-regex/examples/score_generated_aot_comparison.py --matrix-schema $matrix_schema${score_profile_option} <the complete schema's base + selected-profile .tsv files>" >&2
