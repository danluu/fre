#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
# Normalize the worker stack needed by FRE's deep exhaustive planner fixtures.
export RUST_MIN_STACK=16777216

cargo test \
    --locked \
    --offline \
    -p fre-target-features \
    -p fre-simd-kernels \
    -p fre-jit-x86_64 \
    -p fre-kernels \
    -p fre \
    -p fre-unsafe-lint-boundary

cargo test \
    --locked \
    --offline \
    --release \
    -p fre-simd-kernels

cargo test \
    --locked \
    --offline \
    --release \
    -p fre-kernels \
    literal_class_run_literal

cargo test \
    --locked \
    --offline \
    --release \
    -p fre \
    --test literal_class_run_literal

cargo clippy \
    --locked \
    --offline \
    --all-targets \
    -p fre-target-features \
    -p fre-simd-kernels \
    -p fre-jit-x86_64 \
    -p fre-kernels \
    -p fre \
    -p fre-unsafe-lint-boundary \
    -- \
    -D warnings

scripts/check-unsafe-lint-boundary.sh
scripts/check-simd-codegen.sh

cargo run \
    --locked \
    --offline \
    --quiet \
    -p fre-target-features \
    --example host_features

selection_output="$(
    cargo test \
        --locked \
        --offline \
        -p fre-simd-kernels \
        tests::host_auto_selection_receipt_matches_usable_features \
        -- \
        --nocapture \
        --exact 2>&1
)"
printf '%s\n' "$selection_output"
if ! grep -Eq 'SIMD_SELECTION narrow=.* wide=.* usable=' <<<"$selection_output"; then
    echo "native automatic SIMD selection did not emit an authenticated receipt" >&2
    exit 1
fi

if [[ "${FRE_SIMD_RUN_SVE2_BENCH:-0}" == 1 ]]; then
    benchmark_output="$(
        cargo test \
            --locked \
            --offline \
            --release \
            -p fre-simd-kernels \
            tests::benchmark_sve2_against_split_neon \
            -- \
            --ignored \
            --nocapture \
            --exact 2>&1
    )"
    printf '%s\n' "$benchmark_output"
    if command -v rg >/dev/null 2>&1; then
        benchmark_receipt_present="$(
            rg -c 'SIMD_BENCH .*sve2_over_neon=' <<<"$benchmark_output" || true
        )"
    else
        benchmark_receipt_present="$(
            grep -Ec 'SIMD_BENCH .*sve2_over_neon=' <<<"$benchmark_output" || true
        )"
    fi
    if [[ "${benchmark_receipt_present:-0}" -lt 1 ]]; then
        echo "SVE2 qualification benchmark did not emit an authenticated result" >&2
        exit 1
    fi
fi
