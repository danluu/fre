#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
temporary=$(mktemp -d "${TMPDIR:-/tmp}/fre-jit-evidence-verifier.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
artifact=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
accepted_bundle=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
zero_bundle=0000000000000000000000000000000000000000000000000000000000000000
historical_bundle=89af5a04190a39c40a4819ce916fc28630330550e1cafc15e9919122af0ae9f7
header="schema,revision,pid,repetition,cell,shape,operation,size,scenario,haystack_bytes,alignment_mod16,engine,stage,timing_scope,iterations,total_ns,ns_per_iter,checksum,semantic_value,code_bytes,data_bytes,payload_used_bytes,total_mapped_bytes,total_pages,instructions,vector_instructions,loads,stores,branches,identity_bytes_hashed,identity_scratch_bytes,identity_heap_allocations,cache_bookkeeping_bytes,cache_hits,fixture,output_kind,backend,route,artifact_identity,evidence_identity,qualification_state,qualification_bundle_sha256,evidence_binding,artifact_binding,declared_min_window_bytes,declared_min_qualifying_calls,measured_calls,measured_qualifying_calls"

write_native_csv() {
    destination=$1
    state=$2
    bundle=$3
    backend=$4
    schema=$5
    binding="fre-qualified-exact-evidence-v2|output=span|backend=$backend|route=native-jit|artifact=$artifact|qualification_state=$state|qualification_bundle=$bundle|minimum_window_bytes=65536|minimum_qualifying_calls=1024"
    evidence=$(printf '%s' "$binding" | shasum -a 256 | awk '{print $1}')
    {
        printf '%s\n' "$header"
        printf '%s\n' "$schema,rev,1,0,exact-span-64k-absent,exact,span,64k,absent,65536,0,fre-qualified-exact,search,search_only_declared_workload_build_excluded,1024,1,1,0x1,0x1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,synthetic-v1,span,$backend,native-jit,$artifact,$evidence,$state,$bundle,$binding,facade-reported-identity+deterministic-native-span-image,65536,1024,1024,1024"
    } > "$destination"
}

verify() {
    awk -v span_identity="$artifact" \
        -f "$script_dir/verify_evidence_rows.awk" "$1" &&
        "$script_dir/verify_evidence_identity.sh" "$1"
}

write_native_csv \
    "$temporary/valid-candidate.csv" candidate none \
    aarch64-search-v7 fre-jit-bakeoff-v2
verify "$temporary/valid-candidate.csv"

write_native_csv \
    "$temporary/valid-qualified.csv" qualified "$accepted_bundle" \
    aarch64-search-v7 fre-jit-bakeoff-v2
verify "$temporary/valid-qualified.csv"

for field_and_value in \
    "output_kind exists" \
    "route portable-literal" \
    "artifact_identity cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" \
    "evidence_identity cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" \
    "declared_min_qualifying_calls 2048" \
    "measured_calls 500" \
    "measured_qualifying_calls 500"
do
    field=${field_and_value%% *}
    value=${field_and_value#* }
    awk -F, -v OFS=, -v field="$field" -v value="$value" '
        NR == 1 {
            for (column = 1; column <= NF; column++) {
                if ($column == field) target = column
            }
            if (!target) exit 2
        }
        NR == 2 { $target = value }
        { print }
    ' "$temporary/valid-candidate.csv" > "$temporary/tampered.csv"
    if verify "$temporary/tampered.csv" >/dev/null 2>&1; then
        echo "tampered evidence field $field was accepted" >&2
        exit 1
    fi
done

assert_rejected() {
    if verify "$1" >/dev/null 2>&1; then
        echo "invalid evidence row was accepted: $1" >&2
        exit 1
    fi
}

write_native_csv \
    "$temporary/candidate-with-bundle.csv" candidate "$accepted_bundle" \
    aarch64-search-v7 fre-jit-bakeoff-v2
assert_rejected "$temporary/candidate-with-bundle.csv"
write_native_csv \
    "$temporary/qualified-zero.csv" qualified "$zero_bundle" \
    aarch64-search-v7 fre-jit-bakeoff-v2
assert_rejected "$temporary/qualified-zero.csv"
write_native_csv \
    "$temporary/qualified-historical.csv" qualified "$historical_bundle" \
    aarch64-search-v7 fre-jit-bakeoff-v2
assert_rejected "$temporary/qualified-historical.csv"
write_native_csv \
    "$temporary/old-backend.csv" candidate none \
    aarch64-jit-v2 fre-jit-bakeoff-v2
assert_rejected "$temporary/old-backend.csv"
write_native_csv \
    "$temporary/old-schema.csv" candidate none \
    aarch64-search-v7 fre-jit-bakeoff-v1
assert_rejected "$temporary/old-schema.csv"

echo "verified: V7 backend, typed qualification, binding, and call-count tampering fail closed"
