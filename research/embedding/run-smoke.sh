#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
include="$root/crates/fre-capi/include"
build="$root/target/debug"

if [ "${1:-}" = "--release" ]; then
  cargo build --manifest-path "$root/Cargo.toml" -p fre-capi --release
  build="$root/target/release"
else
  cargo build --manifest-path "$root/Cargo.toml" -p fre-capi
fi

if command -v clang >/dev/null 2>&1; then
  cc=${CC:-clang}
elif command -v cc >/dev/null 2>&1; then
  cc=${CC:-cc}
else
  echo "C compiler unavailable; smoke skipped" >&2
  exit 77
fi

if command -v clang++ >/dev/null 2>&1; then
  cxx=${CXX:-clang++}
elif command -v c++ >/dev/null 2>&1; then
  cxx=${CXX:-c++}
else
  echo "C++ compiler unavailable; smoke skipped" >&2
  exit 77
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/fre-capi-smoke.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

case $(uname -s) in
  Darwin)
    library="$build/libfre_capi.dylib"
    rpath="-Wl,-rpath,$build"
    nm -gU "$library" | awk '{ name=$NF; if (name ~ /^_fre_v1_/) { sub(/^_/, "", name); print name } }' | sort > "$tmp/symbols.txt"
    ;;
  *)
    library="$build/libfre_capi.so"
    rpath="-Wl,-rpath,$build"
    nm -D --defined-only "$library" | awk '{ name=$NF; if (name ~ /^fre_v1_/) print name }' | sort > "$tmp/symbols.txt"
    ;;
esac

test -f "$library"
diff -u "$script_dir/expected-symbols.txt" "$tmp/symbols.txt"

"$cc" -std=c11 -Wall -Wextra -Werror -I"$include" \
  "$script_dir/c11-smoke.c" -L"$build" -lfre_capi "$rpath" -o "$tmp/c-smoke"
"$cxx" -std=c++17 -Wall -Wextra -Werror -Wno-missing-field-initializers \
  -I"$include" "$script_dir/cpp17-smoke.cc" -L"$build" -lfre_capi \
  "$rpath" -o "$tmp/cpp-smoke"

"$tmp/c-smoke"
"$tmp/cpp-smoke"
