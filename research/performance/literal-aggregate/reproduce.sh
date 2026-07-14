#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/../../.." && pwd)"
checkout="${REBAR_CHECKOUT:-/tmp/rebar-fre}"
cd "$root"

test "$(git -C "$checkout" rev-parse HEAD)" = 463d00f31887e84c38467805b9e3122c314b9521
printf '%s  %s\n' \
  09a7bfe5df8a4d78c21144b4d45f584167a1607f412990a60045878227553e43 \
  research/rebar/expanded/manifest.json | shasum -a 256 -c -
printf '%s  %s\n' \
  9650c4ca45df876045a9b3ae5533247f6c38d7e563f8666f1fe5bd7a8d14fdf6 \
  research/rebar/expanded/blobs/sha256-9650c4ca45df876045a9b3ae5533247f6c38d7e563f8666f1fe5bd7a8d14fdf6.pattern | shasum -a 256 -c -
printf '%s  %s\n' \
  0d40805f6d02c8fe02bd75945b98911891f707e8ecb939e018446858065d76ea \
  "$checkout/benchmarks/haystacks/opensubtitles/en-sampled.txt" | shasum -a 256 -c -

cargo build -p fre-kernels --release --example literal_aggregate_integration
bin=target/release/examples/literal_aggregate_integration

run_five() {
  local engine="$1" case="$2" operation="$3" size="$4" iterations="$5"
  for _ in 1 2 3 4 5; do
    REBAR_CHECKOUT="$checkout" "$bin" "$engine" "$case" "$operation" "$size" "$iterations"
  done
}

printf '%s\n' 'engine,case,operation,size,iterations,total_ns,ns_per_iter,checksum,expected,plan'
for operation in count span-sum; do
  for engine in aggregate rust; do
    run_five "$engine" short-positive "$operation" 8 1000000
    run_five "$engine" positive "$operation" 65536 50000
    run_five "$engine" negative "$operation" 65536 50000
    run_five "$engine" dense "$operation" 65536 500
    run_five "$engine" overlapping "$operation" 65536 2000
    run_five "$engine" empty "$operation" 65536 200
    run_five "$engine" positive "$operation" 1048576 5000
    run_five "$engine" negative "$operation" 1048576 5000
    run_five "$engine" dense "$operation" 1048576 50
    run_five "$engine" overlapping "$operation" 1048576 200
    run_five "$engine" empty "$operation" 1048576 20
    run_five "$engine" rebar-sherlock "$operation" 0 20000
  done
done

cargo run -p fre-kernels --release --example literal_aggregate_scaling
