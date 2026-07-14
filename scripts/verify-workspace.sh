#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

cargo fmt --all -- --check
./scripts/check-unsafe-lint-boundary.sh
cargo check --workspace --all-targets --all-features
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings

if [[ -f research/rebar/manifest.json ]]; then
    cargo run --quiet -p rebar-manifest -- \
        generate \
        --input research/rebar/inventory.csv \
        --output /tmp/fre-rebar-manifest.verify.json \
        --summary /tmp/fre-rebar-summary.verify.md \
        --runner-revision 463d00f31887e84c38467805b9e3122c314b9521
    cmp research/rebar/manifest.json /tmp/fre-rebar-manifest.verify.json
    cmp research/rebar/README.md /tmp/fre-rebar-summary.verify.md
fi
