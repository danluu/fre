#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
temporary="$(mktemp -d "${TMPDIR:-/tmp}/fre-simd-codegen.XXXXXX")"
trap 'rm -rf "$temporary"' EXIT

export CARGO_TARGET_DIR="$temporary/target"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"

requested_target="${FRE_SIMD_CODEGEN_TARGET:-}"
assembly_directory="$CARGO_TARGET_DIR/release/deps"
effective_host="$(rustc -vV | sed -n 's/^host: //p')"
if [[ -n "$requested_target" ]]; then
    [[ "$requested_target" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]*$ ]] || {
        echo "SIMD codegen failure: invalid explicit target ${requested_target}" >&2
        exit 1
    }
    assembly_directory="$CARGO_TARGET_DIR/$requested_target/release/deps"
    effective_host="$requested_target"
fi

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

if [[ -n "$requested_target" ]]; then
    cargo rustc \
        --manifest-path "$root/Cargo.toml" \
        --locked \
        --offline \
        -p fre-simd-kernels \
        --target "$requested_target" \
        --release \
        --lib \
        -- \
        --emit=asm
else
    cargo rustc \
        --manifest-path "$root/Cargo.toml" \
        --locked \
        --offline \
        -p fre-simd-kernels \
        --release \
        --lib \
        -- \
        --emit=asm
fi

assembly="$(
    find "$assembly_directory" \
        -type f \
        -name 'fre_simd_kernels-*.s' \
        -print \
        -quit
)"
if [[ -z "$assembly" ]]; then
    echo "SIMD codegen failure: release assembly was not produced" >&2
    exit 1
fi

extract_function() {
    local symbol="$1"
    local output="$2"
    local has_size=0
    if grep -Eq "\\.size[[:space:]]+${symbol}([[:space:],]|$)" "$assembly"; then
        has_size=1
    fi
    awk -v symbol="$symbol" -v has_size="$has_size" '
        index($0, symbol) != 0 && $0 ~ /:$/ {
            in_function = 1
        }
        in_function {
            print
        }
        in_function && has_size && $0 ~ /^[[:space:]]*\.size/ && index($0, symbol) != 0 {
            exit
        }
        in_function && !has_size && $0 ~ /^[[:space:]]*\.cfi_endproc/ {
            exit
        }
    ' "$assembly" >"$output"
    if [[ ! -s "$output" ]]; then
        echo "SIMD codegen failure: symbol containing ${symbol} is absent" >&2
        exit 1
    fi
}

require_count() {
    local pattern="$1"
    local minimum="$2"
    local source="$3"
    local description="$4"
    local observed
    if command -v rg >/dev/null 2>&1; then
        observed="$(rg -c "$pattern" "$source" || true)"
    else
        observed="$(grep -Ec "$pattern" "$source" || true)"
    fi
    observed="${observed:-0}"
    if (( observed < minimum )); then
        echo "SIMD codegen failure: ${description}: observed=${observed} required=${minimum}" >&2
        exit 1
    fi
}

require_exact_count() {
    local pattern="$1"
    local expected="$2"
    local source="$3"
    local description="$4"
    local observed
    if command -v rg >/dev/null 2>&1; then
        observed="$(rg -c "$pattern" "$source" || true)"
    else
        observed="$(grep -Ec "$pattern" "$source" || true)"
    fi
    observed="${observed:-0}"
    if (( observed != expected )); then
        echo "SIMD codegen failure: ${description}: observed=${observed} required=${expected}" >&2
        exit 1
    fi
}

reject_count() {
    local pattern="$1"
    local source="$2"
    local description="$3"
    local observed
    if command -v rg >/dev/null 2>&1; then
        observed="$(rg -c "$pattern" "$source" || true)"
    else
        observed="$(grep -Ec "$pattern" "$source" || true)"
    fi
    observed="${observed:-0}"
    if (( observed != 0 )); then
        echo "SIMD codegen failure: ${description}: observed=${observed} required=0" >&2
        exit 1
    fi
}

host="$effective_host"
authenticated_leaf=""
case "$host" in
    aarch64-*)
        extract_function "classify_16_neon" "$temporary/neon.s"
        require_count '\btbl\b' 2 "$temporary/neon.s" "NEON nibble table lookups"
        require_count '\baddv\b' 2 "$temporary/neon.s" "NEON lane-mask reductions"

        extract_function "scan_run_forward_neon" "$temporary/run-neon-forward.s"
        require_exact_count '\btbl\b' 2 "$temporary/run-neon-forward.s" "forward NEON run membership table lookups"
        require_exact_count '\bumaxv\b' 1 "$temporary/run-neon-forward.s" "forward NEON failed-block reduction"
        reject_count '\baddv\b' "$temporary/run-neon-forward.s" "forward NEON run leaf materializing a lane mask"

        extract_function "scan_run_backward_neon" "$temporary/run-neon-backward.s"
        require_exact_count '\btbl\b' 2 "$temporary/run-neon-backward.s" "backward NEON run membership table lookups"
        require_exact_count '\bumaxv\b' 1 "$temporary/run-neon-backward.s" "backward NEON failed-block reduction"
        reject_count '\baddv\b' "$temporary/run-neon-backward.s" "backward NEON run leaf materializing a lane mask"

        if [[ "$host" == aarch64-unknown-linux-* ]]; then
            extract_function "fre_ascii_mask32_sve2_asm" "$temporary/sve2.s"
            require_count '\bwhilelo\b' 2 "$temporary/sve2.s" "SVE exact-bound predicates"
            require_count '\btbl\b' 1 "$temporary/sve2.s" "SVE nibble table lookup"
            require_count '\bmatch\b' 1 "$temporary/sve2.s" "SVE2 ASCII classification"
            require_count '\bincb\b' 1 "$temporary/sve2.s" "SVE vector-length loop progress"
            require_count '\bstr[[:space:]]+p[12]\b' 2 "$temporary/sve2.s" "SVE predicate serialization"
            require_count '\.cfi_startproc\b' 1 "$temporary/sve2.s" "SVE unwind start"
            require_count '\.cfi_def_cfa_offset[[:space:]]+32\b' 1 "$temporary/sve2.s" "SVE fixed-frame unwind extent"
            require_count '\.size[[:space:]]+fre_ascii_mask32_sve2_asm\b' 1 "$temporary/sve2.s" "SVE symbol boundary"

            extract_function "fre_ascii_run_forward_sve_asm" "$temporary/run-sve-forward.s"
            require_exact_count '\bptrue[[:space:]]+p0\.b,[[:space:]]*vl16\b' 1 "$temporary/run-sve-forward.s" "forward base-SVE fixed 16-lane full-block predicate"
            require_exact_count '\bwhilelo\b' 1 "$temporary/run-sve-forward.s" "forward base-SVE exact tail predicate"
            require_exact_count '\bld1b\b' 3 "$temporary/run-sve-forward.s" "forward base-SVE exact table, full-block, and tail loads"
            require_exact_count '\btbl\b' 2 "$temporary/run-sve-forward.s" "forward base-SVE full-block and tail membership lookups"
            require_exact_count '\bptest\b' 2 "$temporary/run-sve-forward.s" "forward base-SVE full-block and tail all-member tests"
            require_exact_count '\bbrkb\b' 1 "$temporary/run-sve-forward.s" "forward base-SVE first-nonmember prefix"
            require_exact_count '\bcntp\b' 2 "$temporary/run-sve-forward.s" "forward base-SVE boundary and examined counts"
            reject_count '\bincp\b' "$temporary/run-sve-forward.s" "forward base-SVE hardware-VL progress"
            reject_count '\b(match|ld1rqb|cntb)\b' "$temporary/run-sve-forward.s" "forward base-SVE leaf using SVE2 or hardware-VL chunking"
            reject_count '\bstr[[:space:]]+p[0-9]+\b' "$temporary/run-sve-forward.s" "forward base-SVE predicate serialization"

            extract_function "fre_ascii_run_backward_sve_asm" "$temporary/run-sve-backward.s"
            require_exact_count '\bptrue[[:space:]]+p0\.b,[[:space:]]*vl16\b' 1 "$temporary/run-sve-backward.s" "backward base-SVE fixed 16-lane full-block predicate"
            require_exact_count '\bwhilelo\b' 1 "$temporary/run-sve-backward.s" "backward base-SVE exact tail predicate"
            require_exact_count '\bld1b\b' 3 "$temporary/run-sve-backward.s" "backward base-SVE exact table, full-block, and tail loads"
            require_exact_count '\btbl\b' 2 "$temporary/run-sve-backward.s" "backward base-SVE full-block and tail membership lookups"
            require_exact_count '\bptest\b' 2 "$temporary/run-sve-backward.s" "backward base-SVE full-block and tail all-member tests"
            require_exact_count '\blastb\b' 1 "$temporary/run-sve-backward.s" "backward base-SVE last-nonmember lane"
            reject_count '\b(match|ld1rqb|cntb)\b' "$temporary/run-sve-backward.s" "backward base-SVE leaf using SVE2 or hardware-VL chunking"
            reject_count '\bstr[[:space:]]+p[0-9]+\b' "$temporary/run-sve-backward.s" "backward base-SVE predicate serialization"

            extract_function "fre_ascii_run_forward_sve2_asm" "$temporary/run-sve2-forward.s"
            require_exact_count '\bld1rqb\b' 1 "$temporary/run-sve2-forward.s" "forward SVE2 repeated small-set load"
            require_exact_count '\bptrue[[:space:]]+p0\.b,[[:space:]]*vl16\b' 1 "$temporary/run-sve2-forward.s" "forward SVE2 fixed 16-lane full-block predicate"
            require_exact_count '\bwhilelo\b' 1 "$temporary/run-sve2-forward.s" "forward SVE2 exact tail predicate"
            require_exact_count '\bld1b\b' 2 "$temporary/run-sve2-forward.s" "forward SVE2 exact full-block and tail loads"
            require_exact_count '\bmatch\b' 2 "$temporary/run-sve2-forward.s" "forward SVE2 full-block and tail membership"
            require_exact_count '\bptest\b' 2 "$temporary/run-sve2-forward.s" "forward SVE2 full-block and tail all-member tests"
            require_exact_count '\bbrkb\b' 1 "$temporary/run-sve2-forward.s" "forward SVE2 first-nonmember prefix"
            require_exact_count '\bcntp\b' 2 "$temporary/run-sve2-forward.s" "forward SVE2 boundary and examined counts"
            reject_count '\bincp\b' "$temporary/run-sve2-forward.s" "forward SVE2 hardware-VL progress"
            reject_count '\b(tbl|cntb)\b' "$temporary/run-sve2-forward.s" "forward SVE2 MATCH leaf using table lookup or hardware-VL chunking"
            reject_count '\bstr[[:space:]]+p[0-9]+\b' "$temporary/run-sve2-forward.s" "forward SVE2 predicate serialization"

            extract_function "fre_ascii_run_backward_sve2_asm" "$temporary/run-sve2-backward.s"
            require_exact_count '\bld1rqb\b' 1 "$temporary/run-sve2-backward.s" "backward SVE2 repeated small-set load"
            require_exact_count '\bptrue[[:space:]]+p0\.b,[[:space:]]*vl16\b' 1 "$temporary/run-sve2-backward.s" "backward SVE2 fixed 16-lane full-block predicate"
            require_exact_count '\bwhilelo\b' 1 "$temporary/run-sve2-backward.s" "backward SVE2 exact tail predicate"
            require_exact_count '\bld1b\b' 2 "$temporary/run-sve2-backward.s" "backward SVE2 exact full-block and tail loads"
            require_exact_count '\bmatch\b' 2 "$temporary/run-sve2-backward.s" "backward SVE2 full-block and tail membership"
            require_exact_count '\bptest\b' 2 "$temporary/run-sve2-backward.s" "backward SVE2 full-block and tail all-member tests"
            require_exact_count '\blastb\b' 1 "$temporary/run-sve2-backward.s" "backward SVE2 last-nonmember lane"
            reject_count '\b(tbl|cntb)\b' "$temporary/run-sve2-backward.s" "backward SVE2 MATCH leaf using table lookup or hardware-VL chunking"
            reject_count '\bstr[[:space:]]+p[0-9]+\b' "$temporary/run-sve2-backward.s" "backward SVE2 predicate serialization"

            authenticated_leaf="$temporary/run-sve2-forward.s"
        else
            authenticated_leaf="$temporary/run-neon-forward.s"
        fi
        ;;
    x86_64-*)
        extract_function "classify_16_sse2" "$temporary/sse2.s"
        require_count '\bpmovmskb\b' 1 "$temporary/sse2.s" "SSE2 ASCII lane mask"
        reject_count '\bpshufb\b' "$temporary/sse2.s" "SSE2 leaf using unqualified SSSE3 shuffle"

        extract_function "classify_16_ssse3" "$temporary/ssse3.s"
        require_count '\bpshufb\b' 2 "$temporary/ssse3.s" "SSSE3 nibble table lookups"
        require_count '\bpmovmskb\b' 2 "$temporary/ssse3.s" "SSSE3 lane masks"

        extract_function "classify_32_avx2" "$temporary/avx2.s"
        require_count '\bvpshufb\b' 2 "$temporary/avx2.s" "AVX2 nibble table lookups"
        require_count '\bvpmovmskb\b' 2 "$temporary/avx2.s" "AVX2 lane masks"
        require_count '\bvzeroupper\b' 1 "$temporary/avx2.s" "AVX2 transition cleanup"

        extract_function "classify_32_avx512" "$temporary/avx512.s"
        require_exact_count '\bkxnord\b' 1 "$temporary/avx512.s" "AVX-512BW all-lanes opmask construction"
        require_exact_count '\bvmovdqu8\b' 1 "$temporary/avx512.s" "AVX-512BW/VL exact-width input load"
        require_exact_count '\bvbroadcasti32x4\b' 2 "$temporary/avx512.s" "AVX-512F/VL exact 16-byte table broadcasts"
        require_exact_count '\bvpbroadcastd\b' 1 "$temporary/avx512.s" "AVX-512F/VL nibble-mask broadcast"
        require_exact_count '\bvpandd\b' 2 "$temporary/avx512.s" "AVX-512F/VL nibble masks"
        require_exact_count '\bvpsrlw\b' 1 "$temporary/avx512.s" "AVX-512BW/VL high-nibble shift"
        require_exact_count '\bvpshufb\b' 2 "$temporary/avx512.s" "AVX-512BW/VL nibble table lookups"
        require_exact_count '\bvptestmb\b' 1 "$temporary/avx512.s" "AVX-512BW/VL member opmask comparison"
        require_exact_count '\bvpmovb2m\b' 1 "$temporary/avx512.s" "AVX-512BW/VL ASCII opmask extraction"
        require_exact_count '\bkmovd\b' 2 "$temporary/avx512.s" "AVX-512 opmask serialization"
        require_exact_count '\bvzeroupper\b' 1 "$temporary/avx512.s" "AVX-512 transition cleanup"
        require_exact_count '\{%k1\}' 9 "$temporary/avx512.s" "EVEX mask modifiers on every vector data operation"
        require_exact_count '%ymm[0-9]+\b' 11 "$temporary/avx512.s" "complete exact-width YMM instruction body"
        require_exact_count '\bvmovdqu8[[:space:]]+\([^)]*\),[[:space:]]+%ymm[0-9]+[[:space:]]+\{%k1\}' 1 "$temporary/avx512.s" "exact 32-byte memory-source/YMM-destination input load"
        require_exact_count '\bvbroadcasti32x4[[:space:]]+\([^)]*\),[[:space:]]+%ymm[0-9]+[[:space:]]+\{%k1\}' 2 "$temporary/avx512.s" "exact 16-byte memory-source/YMM-destination table loads"
        require_exact_count '\bvpbroadcastd\b.*\{%k1\}' 1 "$temporary/avx512.s" "EVEX nibble-mask broadcast"
        require_exact_count '\bvpandd\b.*\{%k1\}' 2 "$temporary/avx512.s" "EVEX nibble masks"
        require_exact_count '\bvpsrlw\b.*\{%k1\}' 1 "$temporary/avx512.s" "EVEX high-nibble shift"
        require_exact_count '\bvpshufb\b.*\{%k1\}' 2 "$temporary/avx512.s" "EVEX nibble table lookups"
        reject_count '\b(vbroadcasti128|vpmovmskb|vperm2i128|vinserti128|vextracti128|vmovdqu|vmovdqa|vpand)\b' "$temporary/avx512.s" "AVX-512 leaf using a VEX AVX2-only data instruction"
        reject_count '\bzmm[0-9]+\b' "$temporary/avx512.s" "AVX-512 exact-32-byte leaf using an over-width ZMM register"
        authenticated_leaf="$temporary/avx512.s"
        ;;
    *)
        echo "SIMD codegen check has no authenticated leaf for host ${host}" >&2
        exit 1
        ;;
esac

[[ -n "$authenticated_leaf" && -s "$authenticated_leaf" ]]
printf 'PASS host=%s assembly_sha256=%s authenticated_leaf_sha256=%s\n' \
    "$host" "$(sha256_file "$assembly")" "$(sha256_file "$authenticated_leaf")"
