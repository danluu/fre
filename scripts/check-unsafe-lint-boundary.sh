#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
temporary="$(mktemp -d "${TMPDIR:-/tmp}/fre-unsafe-lint-boundary.XXXXXX")"
trap 'rm -rf "$temporary"' EXIT
cd "$root"

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

cargo check -p rebar-expand --lib -v >"$temporary/unrelated.log" 2>&1
if ! grep -E -- '--crate-name rebar_expand .*--forbid=unsafe_code' \
    "$temporary/unrelated.log" >/dev/null
then
    echo "unsafe lint boundary failure: unrelated target did not receive forbid" >&2
    cat "$temporary/unrelated.log" >&2
    exit 1
fi

cargo check -p fre-kernels --lib -v >"$temporary/kernels.log" 2>&1
if ! grep -E -- '--crate-name fre_kernels .*--deny=unsafe_code' \
    "$temporary/kernels.log" >/dev/null
then
    echo "unsafe lint boundary failure: audited library did not receive deny" >&2
    cat "$temporary/kernels.log" >&2
    exit 1
fi

for example in crates/fre-kernels/examples/*.rs; do
    if ! grep -q '^#!\[forbid(unsafe_code)\]$' "$example"; then
        echo "unsafe lint boundary failure: missing example-root forbid: $example" >&2
        exit 1
    fi
done

cargo test -p fre-kernels \
    forward_anchored::tests::exact_suffix_copy_has_exact_capacity_and_typed_failure \
    -- --exact >"$temporary/helper-test.log" 2>&1

printf '%s\n' \
    'PASS workspace-unrelated=forbid target-allow=E0453 audited-library=deny helper=pass examples=forbid'
