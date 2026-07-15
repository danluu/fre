#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
temporary="$(mktemp -d "${TMPDIR:-/tmp}/fre-unsafe-lint-boundary.XXXXXX")"
trap 'rm -rf "$temporary"' EXIT
cd "$root"

extract_lints() {
    awk '
        /^\[(workspace\.)?lints\.(rust|clippy)\]$/ {
            inside = 1
            sub(/workspace\./, "")
            print
            next
        }
        /^\[/ {
            inside = 0
        }
        inside && !/^#/ && !/^$/ {
            print
        }
    ' "$1"
}

extract_lints Cargo.toml >"$temporary/workspace-lints"
extract_lints crates/fre-kernels/Cargo.toml \
    | sed 's/^unsafe_code = "deny"$/unsafe_code = "forbid"/' \
    >"$temporary/kernel-lints-normalized"
if ! diff -u "$temporary/workspace-lints" "$temporary/kernel-lints-normalized"; then
    echo "unsafe lint boundary failure: fre-kernels lint table drifted" >&2
    exit 1
fi

cat >"$temporary/forbid-mutation.rs" <<'RS'
#![allow(unsafe_code)]

fn main() {
    let value = 7_u8;
    let pointer = &raw const value;
    let _observed = unsafe { *pointer };
}
RS

if rustc \
    --crate-name forbid_mutation \
    --edition=2024 \
    --forbid=unsafe_code \
    "$temporary/forbid-mutation.rs" \
    -o "$temporary/forbid-mutation" \
    >"$temporary/forbid-mutation.stdout" \
    2>"$temporary/forbid-mutation.stderr"
then
    echo "unsafe lint boundary failure: a target-level allow overrode forbid" >&2
    exit 1
fi
if ! grep -q 'E0453' "$temporary/forbid-mutation.stderr"; then
    echo "unsafe lint boundary failure: mutation failed for an unexpected reason" >&2
    cat "$temporary/forbid-mutation.stderr" >&2
    exit 1
fi

export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_TARGET_DIR="$temporary/target"

cargo test --locked --offline -p fre-unsafe-lint-boundary \
    >"$temporary/metadata-checker-tests.log" 2>&1
cargo metadata --locked --offline --no-deps --format-version 1 \
    >"$temporary/metadata.json"
cargo run --locked --offline --quiet -p fre-unsafe-lint-boundary \
    <"$temporary/metadata.json" \
    >"$temporary/metadata-audit.log" 2>&1

cargo check --locked --offline -p rebar-expand --lib -v \
    >"$temporary/unrelated.log" 2>&1
if ! grep -E -- '--crate-name rebar_expand .*--forbid=unsafe_code' \
    "$temporary/unrelated.log" >/dev/null
then
    echo "unsafe lint boundary failure: unrelated target did not receive forbid" >&2
    cat "$temporary/unrelated.log" >&2
    exit 1
fi

cargo check --locked --offline -p fre-kernels --lib -v \
    >"$temporary/kernels.log" 2>&1
if ! grep -E -- '--crate-name fre_kernels .*--forbid=unsafe_code' \
    "$temporary/kernels.log" >/dev/null
then
    echo "unsafe lint boundary failure: audited library did not receive forbid" >&2
    cat "$temporary/kernels.log" >&2
    exit 1
fi

cargo test --locked --offline -p fre-kernels \
    forward_anchored::tests::exact_suffix_copy_has_exact_capacity_and_typed_failure \
    --lib -- --exact >"$temporary/helper-test.log" 2>&1

printf '%s\n' \
    'PASS lint-tables=matched workspace-unrelated=forbid target-allow=E0453 audited-library=forbid metadata-targets=forbid exceptions=allowlisted mutation-fixtures=pass helper=pass'
