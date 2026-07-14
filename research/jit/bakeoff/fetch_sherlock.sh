#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
revision=463d00f31887e84c38467805b9e3122c314b9521
expected=0d40805f6d02c8fe02bd75945b98911891f707e8ecb939e018446858065d76ea
destination=${1:-"$script_dir/.inputs/en-sampled.txt"}
url="https://raw.githubusercontent.com/BurntSushi/rebar/$revision/benchmarks/haystacks/opensubtitles/en-sampled.txt"

mkdir -p "$(dirname -- "$destination")"
if [ ! -f "$destination" ]; then
    temporary="$destination.tmp.$$"
    trap 'rm -f "$temporary"' EXIT HUP INT TERM
    curl --fail --location --silent --show-error "$url" --output "$temporary"
    mv "$temporary" "$destination"
    trap - EXIT HUP INT TERM
fi

actual=$(shasum -a 256 "$destination" | awk '{print $1}')
if [ "$actual" != "$expected" ]; then
    echo "Sherlock fixture SHA-256 mismatch: expected $expected, got $actual" >&2
    exit 1
fi
bytes=$(wc -c < "$destination" | tr -d ' ')
if [ "$bytes" != 899232 ]; then
    echo "Sherlock fixture length mismatch: expected 899232, got $bytes" >&2
    exit 1
fi
printf '%s\n' "$destination"
