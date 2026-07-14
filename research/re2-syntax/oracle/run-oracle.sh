#!/bin/sh
set -eu

re2_source=${RE2_SOURCE:-/tmp/regex-src-re2}
expected_revision=972a15cedd008d846f1a39b2e88ce48d7f166cbd
if [ "$#" -ne 5 ]; then
  echo "usage: $0 PATTERN_HEX HAYSTACK_HEX perl\|posix utf8\|latin1 FLAGS" >&2
  exit 2
fi
pattern_hex=$1
haystack_hex=$2
syntax=$3
encoding=$4
flags=$5
actual_revision=$(git -C "$re2_source" rev-parse HEAD)
if [ "$actual_revision" != "$expected_revision" ]; then
  echo "refusing non-pinned RE2 checkout: $actual_revision" >&2
  exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
build_dir=${RE2_ORACLE_BUILD_DIR:-"$script_dir/build"}
set -- -S "$script_dir" -B "$build_dir" -DRE2_SOURCE="$re2_source" -DRE2_INSTALL=OFF
if [ -n "${ABSL_SOURCE:-}" ]; then
  set -- "$@" -DABSL_SOURCE="$ABSL_SOURCE"
fi
cmake "$@"
cmake --build "$build_dir" --target fre-re2-oracle --parallel
exec "$build_dir/fre-re2-oracle" "$pattern_hex" "$haystack_hex" "$syntax" "$encoding" "$flags"
