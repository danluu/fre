#!/usr/bin/env bash
# Collect the frozen exact-ByteSet parent/candidate ABBA matrix. No comparison
# timing field is parsed until seal.py has atomically sealed all five outputs.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 OUTPUT_DIRECTORY" >&2
  exit 64
fi

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
frozen_root=$(CDPATH= cd -- "$script_directory/.." && pwd -P)
output_directory=$1

python3 "$script_directory/verify_frozen.py" \
  "$frozen_root/FROZEN_SHA256SUMS" "$frozen_root"

# shellcheck disable=SC1091
source "$frozen_root/manifests/qualification.env"

if [[ -e $output_directory ]]; then
  if [[ ! -d $output_directory || -n $(find "$output_directory" -mindepth 1 -maxdepth 1 -print -quit) ]]; then
    echo "output directory must be absent or empty: $output_directory" >&2
    exit 64
  fi
else
  mkdir -p "$output_directory"
fi
output_directory=$(CDPATH= cd -- "$output_directory" && pwd -P)

parent_binary="$frozen_root/binaries/parent/generated_aot_upstream_comparison"
candidate_binary="$frozen_root/binaries/candidate/generated_aot_upstream_comparison"
parent_archive="$frozen_root/binaries/parent/libfre_aot_regex_runtime.a"
candidate_archive="$frozen_root/binaries/candidate/libfre_aot_regex_runtime.a"

common=(
  --atomic-choice-grammar
  --features "$QUALIFICATION_FEATURES"
  --trials 5
  --warmup-rounds 8
  --bytes-per-trial 1048576
  --min-searches 32
  --min-trial-ns 5000000
)

run_opaque() {
  local subject=$1
  local order=$2
  local stem=$3
  local binary archive libraries
  case "$subject" in
    parent)
      binary=$parent_binary
      archive=$parent_archive
      libraries=$PARENT_RUNTIME_NATIVE_LIBS
      ;;
    candidate)
      binary=$candidate_binary
      archive=$candidate_archive
      libraries=$CANDIDATE_RUNTIME_NATIVE_LIBS
      ;;
    *)
      echo "unknown frozen subject: $subject" >&2
      exit 64
      ;;
  esac
  FRE_AOT_REGEX_RUNTIME_ARCHIVE="$archive" \
  FRE_AOT_REGEX_RUNTIME_NATIVE_LIBS="$libraries" \
    "$binary" "${common[@]}" --measurement-order "$order" \
    >"$output_directory/.${stem}.tsv.part" \
    2>"$output_directory/.${stem}.stderr.part"
  mv "$output_directory/.${stem}.tsv.part" "$output_directory/${stem}.tsv"
  mv "$output_directory/.${stem}.stderr.part" "$output_directory/${stem}.stderr"
}

# Candidate metadata is a semantic/receipt phase only and exits before runtime
# building, native linking, or timing.
"$candidate_binary" "${common[@]}" --metadata-only \
  >"$output_directory/.metadata-candidate.tsv.part" \
  2>"$output_directory/.metadata-candidate.stderr.part"
mv "$output_directory/.metadata-candidate.tsv.part" \
  "$output_directory/metadata-candidate.tsv"
mv "$output_directory/.metadata-candidate.stderr.part" \
  "$output_directory/metadata-candidate.stderr"

# Frozen mirrored ABBA order. Each subject is measured once under each engine
# order, and equal-order parent/candidate phases are paired by the scorer.
run_opaque parent upstream-native 01-parent-upstream-native
run_opaque candidate native-upstream 02-candidate-native-upstream
run_opaque candidate upstream-native 03-candidate-upstream-native
run_opaque parent native-upstream 04-parent-native-upstream

# seal.py hashes bytes only. score.py is the first process permitted to parse
# timing fields, and it refuses any incomplete or digest-mismatched seal.
python3 "$script_directory/seal.py" "$output_directory"
python3 "$script_directory/score.py" \
  --frozen-root "$frozen_root" \
  --output "$output_directory/score.tsv" \
  "$output_directory"
