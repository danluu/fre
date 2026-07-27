#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
workspace=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
receipt=${1:?usage: build_release.sh ABSOLUTE_RECEIPT_PATH}
target_dir=${CARGO_TARGET_DIR:-}

case "$receipt" in
    /*) ;;
    *)
        echo "receipt path must be absolute" >&2
        exit 2
        ;;
esac
case "$target_dir" in
    /*) ;;
    *)
        echo "CARGO_TARGET_DIR must be an absolute task-private directory" >&2
        exit 2
        ;;
esac

if [ -n "$(git -C "$workspace" status --porcelain=v1 --untracked-files=all)" ]; then
    echo "source-bound release builds require a clean workspace" >&2
    exit 2
fi

revision=$(git -C "$workspace" rev-parse HEAD)
tree=$(git -C "$workspace" rev-parse 'HEAD^{tree}')
rustc_version=$(rustc --version)
cargo_version=$(cargo --version)

CARGO_INCREMENTAL=0 cargo build \
    --manifest-path "$script_dir/Cargo.toml" \
    --release \
    --locked

binary="$target_dir/release/fre-jit-bakeoff"
if [ ! -f "$binary" ] || [ ! -x "$binary" ]; then
    echo "release build did not produce the expected executable: $binary" >&2
    exit 2
fi
if [ -n "$(git -C "$workspace" status --porcelain=v1 --untracked-files=all)" ]; then
    echo "workspace changed during the source-bound release build" >&2
    exit 2
fi
if [ "$(git -C "$workspace" rev-parse HEAD)" != "$revision" ] ||
    [ "$(git -C "$workspace" rev-parse 'HEAD^{tree}')" != "$tree" ]; then
    echo "source revision changed during the release build" >&2
    exit 2
fi

mkdir -p "$(dirname -- "$receipt")"
temporary=$(mktemp "${receipt}.tmp.XXXXXX")
trap 'rm -f "$temporary"' EXIT HUP INT TERM
{
    printf 'schema=fre-jit-bakeoff-build-receipt-v1\n'
    printf 'workspace_revision=%s\n' "$revision"
    printf 'workspace_tree=%s\n' "$tree"
    printf 'workspace_dirty=false\n'
    printf 'manifest_path=%s\n' "$script_dir/Cargo.toml"
    printf 'cargo_lock_sha256='
    shasum -a 256 "$script_dir/Cargo.lock" | awk '{ print $1 }'
    printf 'profile=release\n'
    printf 'cargo_incremental=0\n'
    printf 'rustc=%s\n' "$rustc_version"
    printf 'cargo=%s\n' "$cargo_version"
    printf 'binary_path=%s\n' "$binary"
    printf 'binary_sha256='
    shasum -a 256 "$binary" | awk '{ print $1 }'
    printf 'utc_built='
    date -u '+%Y-%m-%dT%H:%M:%SZ'
} > "$temporary"
mv "$temporary" "$receipt"
trap - EXIT HUP INT TERM
printf '%s\n' "$receipt"
