#!/bin/bash -p
set -eu

export LC_ALL=C
export TZ=UTC
export PATH=/usr/bin:/bin
unset ENV CDPATH LD_PRELOAD LD_LIBRARY_PATH \
    DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH \
    TMP TEMP TMPDIR \
    PYTHONHOME PYTHONPATH PYTHONINSPECT PYTHONSTARTUP \
    PERL5OPT PERL5LIB PERLLIB PERL_UNICODE PERL_LOCAL_LIB_ROOT \
    PERL_MB_OPT PERL_MM_OPT

if [ "$#" -ne 5 ]; then
    echo "usage: verify-results.sh EXPECTED_BINARY_SHA256 EXPECTED_SOURCE_SHA256 RUN1 RUN2 RUN3" >&2
    exit 2
fi

expected_binary=$1
expected_source=$2
shift 2

case "$expected_binary:$expected_source" in
    *[!0-9a-f:]*)
        echo "expected identities must be lowercase hexadecimal" >&2
        exit 2
        ;;
esac
if [ "${#expected_binary}" -ne 64 ] || [ "${#expected_source}" -ne 64 ]; then
    echo "expected identities must be exactly 64 hexadecimal digits" >&2
    exit 2
fi
case "$expected_binary:$expected_source" in
    0000000000000000000000000000000000000000000000000000000000000000:*|\
    *:0000000000000000000000000000000000000000000000000000000000000000)
        echo "expected identities must not be zero" >&2
        exit 2
        ;;
esac

for run do
    if [ ! -f "$run" ] || [ -L "$run" ]; then
        echo "run must be a regular non-symlink file: $run" >&2
        exit 2
    fi
    run_bytes=$(stat -f '%z' -- "$run") || {
        echo "cannot determine raw run byte size: $run" >&2
        exit 2
    }
    case "$run_bytes" in
        ''|*[!0-9]*)
            echo "invalid raw run byte size: $run" >&2
            exit 2
            ;;
    esac
    if [ "$run_bytes" -gt 1048576 ]; then
        echo "raw run exceeds 1048576-byte cap: $run" >&2
        exit 2
    fi
    if ! awk '
        length($0) > 512 { bad = 1; exit }
        NR > 4096 { bad = 1; exit }
        END { exit bad ? 1 : 0 }
    ' "$run"; then
        echo "raw run exceeds 512-byte line or 4096-line cap: $run" >&2
        exit 2
    fi
done
if [ "$1" = "$2" ] || [ "$1" = "$3" ] || [ "$2" = "$3" ]; then
    echo "the three run paths must be distinct" >&2
    exit 2
fi

awk -F, -v expected_binary="$expected_binary" -v expected_source="$expected_source" '
BEGIN {
    # Keep every value converted by awk below 2^53. The 2^36-ns sample
    # ceiling is over 68 seconds for one 64-MiB timing batch; the adoption
    # ceilings are one second. These are refusal bounds, not performance wins.
    max_pid = 4294967295
    min_sample_ns_per_call = 1
    max_sample_elapsed_ns = 68719476736
    max_sample_ns_per_call = 1073741824
    min_first_adoption_ns = 1000
    max_first_adoption_ns = 1000000000
    min_cached_adoption_total_ns = 4096
    max_cached_adoption_total_ns = 1000000000
    max_cached_adoption_ns_per_call = 244140.625
    max_summary_speedup = 2000000000
    max_summary_gib_per_s = 1000000

    sample_header = "SAMPLE,case,bytes,expected_count,repetition,order,engine,iterations,elapsed_ns,ns_per_call,checksum"
    summary_header = "SUMMARY,case,bytes,expected_count,qualified_aot_median_ns,portable_median_ns,portable_over_aot,qualified_aot_gib_per_s,portable_gib_per_s"

    case_total = 0
    for (size_ordinal = 0; size_ordinal < 2; size_ordinal++) {
        bytes = size_ordinal == 0 ? 65536 : 1048576
        suffix = size_ordinal == 0 ? "64k" : "1m"
        add_case("sparse-present-" suffix, bytes, 3)
        add_case("absent-easy-" suffix, bytes, 0)
        add_case("dense-match-" suffix, bytes, int(bytes / 6))
        add_case("tail-" suffix, bytes, 1)
        for (base_residue = 0; base_residue < 16; base_residue++) {
            start_residue = 15 - base_residue
            alignment_name = sprintf("alignment-base-%02d-start-%02d-cross-%s",
                base_residue, start_residue, suffix)
            add_case(alignment_name, bytes, 1)
        }
        add_case("binary-absent-" suffix, bytes, 0)
        add_case("binary-present-" suffix, bytes, 3)
        add_case("natural-absent-" suffix, bytes, 0)
        add_case("natural-present-" suffix, bytes, 3)
        add_case("selected-pair-dense-absent-" suffix, bytes, 0)
        add_case("selected-triple-dense-absent-" suffix, bytes, 0)
        add_case("sparse-false-positive-late-match-" suffix, bytes, 1)
        add_case("first-last-dense-absent-" suffix, bytes, 0)
        add_case("dense-run-transition-" suffix, bytes, int(bytes / 64) * 4)
    }
    expected_case_total = 58
    expected_samples_per_process = expected_case_total * 16 * 2
    expected_cells = 3 * expected_case_total
    expected_pairs = 3 * expected_case_total * 16
    if (case_total != expected_case_total ||
        expected_samples_per_process != 1856 ||
        expected_cells != 174 ||
        expected_pairs != 2784) {
        bad("internal qualification cardinality mismatch")
    }

    required_meta["schema"] = "fre-aot-count-qualified-benchmark-v2"
    required_meta["runtime_authority"] = "qualification-private"
    required_meta["qualification_state"] = "candidate"
    required_meta["production_activation"] = "absent"
    required_meta["performance_scope"] = "selector-11-needle-steady-state-plus-qualification-private-adoption-v1"
    required_meta["compile_link_startup_costs"] = "unmeasured"
    required_meta["production_adoption_latency"] = "unmeasured"
    required_meta["benchmark_source_sha256"] = expected_source
    required_meta["row_selector"] = "11"
    required_meta["compile_identity"] = "ed06366efaed9de023166d65fcee6dbce761bec7aa62c96ba17d5bece445831f"
    required_meta["object_identity"] = "b88728fcfd040ff9e8e7094ae19e2529f9c0b08b2da6f0a0d5d471c0510fad0b"
    required_meta["expectation_identity"] = "afc00275b8be5b661f41521edc8f0477b668c365d779ecc0e51636a2aa1f57d5"
    required_meta["receipt_identity"] = "6c04357fc22f5e5d97742361d9ea2e0be23c05d4b6c23c4c494890698ecf7d7f"
    required_meta["resource_receipt_identity"] = "32829b6ce4c402c4c15fe7b144440b072808b868d9a0594d04e5281c7322e7b7"
    required_meta["implementation_object_sha256"] = "b88728fcfd040ff9e8e7094ae19e2529f9c0b08b2da6f0a0d5d471c0510fad0b"
    required_meta["final_image_glue_sha256"] = "08acd36cd90384db4527d4bb00df9d6edb0f8a855e9aa6ade2d7608cebade132"
    required_meta["expectation_sha256"] = "f6533b964a4388410d6f617100e489d4bc6f0c95ca4319b33bc19cc3972e650f"
    required_meta["executable_sha256"] = expected_binary
    required_uint_meta["row_selector"] = 11
    required_uint_meta["inspection_expectation_bytes"] = 672
    required_uint_meta["inspection_metadata_bytes"] = 232
    required_uint_meta["inspection_payload_bytes"] = 1136
    required_uint_meta["inspection_vm_regions_checked"] = 3
    required_uint_meta["inspection_payload_bytes_hashed"] = 1136
    required_uint_meta["inspection_work_upper_bound"] = 8379
    required_uint_meta["inspection_scratch_bytes_upper_bound"] = 1936
    required_uint_meta["inspection_registry_capacity_entries"] = 256
    required_uint_meta["inspection_registry_capacity_bytes"] = 387072
    required_uint_meta["inspection_allocations"] = 0
    required_uint_meta["cached_adoption_iterations"] = 4096
    required_uint_meta["fixture_cases"] = expected_case_total
    required_uint_meta["fixture_sizes"] = 2
    required_uint_meta["alignment_residues"] = 16
    required_uint_meta["steady_repetitions"] = 16
    required_uint_meta["samples_per_process"] = expected_samples_per_process
    required_uint_meta["bytes_per_steady_sample"] = 67108864
    for (key in required_uint_meta) {
        required_meta[key] = sprintf("%.0f", required_uint_meta[key])
    }
    for (key in required_meta) required_meta_count++
}

FNR == 1 {
    file_index++
    if ($0 != "META,key,value") bad("invalid META header")
    next
}

$1 == "META" {
    if (NF != 3 || $2 == "key" || $2 == "" || meta_seen[file_index, $2]++) {
        bad("malformed or duplicate META row")
    }
    meta[file_index, $2] = $3
    meta_rows[file_index]++
    next
}

$1 == "SAMPLE" && $2 == "case" {
    if ($0 != sample_header || sample_headers[file_index]++) {
        bad("invalid or duplicate SAMPLE header")
    }
    next
}

$1 == "SAMPLE" {
    if (NF != 11 || sample_headers[file_index] != 1) {
        bad("malformed SAMPLE row")
        next
    }
    name = $2
    repetition = $5
    engine = $7
    if (!(name in case_index) ||
        !canonical_uint_equal($3, case_bytes[name], 7) ||
        !canonical_uint_equal($4, case_count[name], 6) ||
        !canonical_uint(repetition, 0, 15, 2) ||
        (engine != "qualified-aot-handle" && engine != "portable-count-value")) {
        bad("invalid SAMPLE coordinates")
        next
    }
    expected_order = ((repetition + case_index[name]) % 2 == 0) ? "aot-first" : "portable-first"
    expected_iterations = 67108864 / case_bytes[name]
    expected_checksum = case_count[name] * expected_iterations
    if ($6 != expected_order ||
        !canonical_uint_equal($8, expected_iterations, 4) ||
        !canonical_uint($9, expected_iterations, max_sample_elapsed_ns, 11) ||
        !canonical_fixed_3($10, min_sample_ns_per_call, max_sample_ns_per_call, 10) ||
        !canonical_uint_equal($11, expected_checksum, 9)) {
        bad("invalid SAMPLE values")
        next
    }
    key = file_index SUBSEP name SUBSEP repetition SUBSEP engine
    if (key in sample_ns) {
        bad("duplicate SAMPLE cell")
        next
    }
    computed = ($9 + 0) / expected_iterations
    difference = computed - ($10 + 0)
    if (difference < 0) difference = -difference
    if (difference > 0.000501) {
        bad("SAMPLE ns_per_call arithmetic mismatch")
    }
    sample_ns[key] = computed
    sample_rows[file_index]++
    next
}

$1 == "SUMMARY" && $2 == "case" {
    if ($0 != summary_header || summary_headers[file_index]++) {
        bad("invalid or duplicate SUMMARY header")
    }
    next
}

$1 == "SUMMARY" {
    name = $2
    if (NF != 9 || summary_headers[file_index] != 1 || !(name in case_index) ||
        !canonical_uint_equal($3, case_bytes[name], 7) ||
        !canonical_uint_equal($4, case_count[name], 6) ||
        !canonical_fixed_3($5, min_sample_ns_per_call, max_sample_ns_per_call, 10) ||
        !canonical_fixed_3($6, min_sample_ns_per_call, max_sample_ns_per_call, 10) ||
        !canonical_fixed_4($7, 0, max_summary_speedup, 10) ||
        !canonical_fixed_4($8, 0, max_summary_gib_per_s, 7) ||
        !canonical_fixed_4($9, 0, max_summary_gib_per_s, 7)) {
        bad("malformed SUMMARY row")
        next
    }
    key = file_index SUBSEP name
    if (summary_seen[key]++) bad("duplicate SUMMARY cell")
    summary_line[key] = $0
    summary_rows[file_index]++
    next
}

{
    bad("unknown row")
}

END {
    if (file_index != 3) bad("expected exactly three files")
    for (file = 1; file <= 3; file++) {
        if (sample_headers[file] != 1 || summary_headers[file] != 1 ||
            sample_rows[file] != expected_samples_per_process ||
            summary_rows[file] != expected_case_total) {
            bad("incomplete run shape")
        }
        if (meta_rows[file] != required_meta_count + 4) {
            bad("non-canonical META row count")
        }
        for (key in required_meta) {
            if (meta[file, key] != required_meta[key]) bad("required META mismatch: " key)
        }
        for (key in required_uint_meta) {
            if (!canonical_uint_equal(meta[file, key], required_uint_meta[key], 10)) {
                bad("non-canonical numeric META field: " key)
            }
        }
        pid = meta[file, "pid"]
        if (!canonical_uint(pid, 1, max_pid, 10) || pid_seen[pid]++) {
            bad("invalid or reused process PID")
        }
        first_adoption = meta[file, "first_adoption_ns"]
        cached_total = meta[file, "cached_adoption_total_ns"]
        cached_per_call = meta[file, "cached_adoption_ns_per_call"]
        if (!canonical_uint(first_adoption, min_first_adoption_ns,
                max_first_adoption_ns, 10) ||
            !canonical_uint(cached_total, min_cached_adoption_total_ns,
                max_cached_adoption_total_ns, 10) ||
            !canonical_fixed_3(cached_per_call, 1,
                max_cached_adoption_ns_per_call, 6)) {
            bad("invalid adoption accounting")
        } else {
            computed_cached = (cached_total + 0) / 4096
            difference = computed_cached - (cached_per_call + 0)
            if (difference < 0) difference = -difference
            if (difference > 0.000501) {
                bad("cached adoption arithmetic mismatch")
            }
        }
        if (failed) continue

        for (case_ordinal = 0; case_ordinal < expected_case_total; case_ordinal++) {
            name = case_name[case_ordinal]
            aot = median(file, name, "qualified-aot-handle")
            portable = median(file, name, "portable-count-value")
            speedup = portable / aot
            aot_gib = case_bytes[name] / (1024 * 1024 * 1024) / (aot / 1000000000)
            portable_gib = case_bytes[name] / (1024 * 1024 * 1024) / (portable / 1000000000)
            expected_summary = sprintf("SUMMARY,%s,%d,%d,%.3f,%.3f,%.4f,%.4f,%.4f",
                name, case_bytes[name], case_count[name], aot, portable,
                speedup, aot_gib, portable_gib)
            if (summary_line[file SUBSEP name] != expected_summary) {
                bad("reported SUMMARY differs from raw-derived summary")
            }
            if (speedup < 1.10) bad("raw-derived process/cell speedup is below 1.10")
            for (repetition = 0; repetition < 16; repetition++) {
                pairs++
                pair_aot = sample_ns[file SUBSEP name SUBSEP repetition SUBSEP "qualified-aot-handle"]
                pair_portable = sample_ns[file SUBSEP name SUBSEP repetition SUBSEP "portable-count-value"]
                if (pair_aot < pair_portable) {
                    pair_wins++
                }
            }
        }
    }
    if (pairs != expected_pairs) {
        bad("raw paired result count differs from 2784")
    } else if (pair_wins / pairs < 0.95) {
        bad("raw paired win rate is below 95 percent")
    }
    if (failed) exit 1
    printf "VERIFIED,processes=3,cells=%d,pairs=%d,pair_wins=%d,pair_win_rate=%.6f\n",
        expected_cells, pairs, pair_wins, pair_wins / pairs
}

function median(file, name, engine, values, count, repetition, value, ordinal, cursor) {
    count = 0
    for (repetition = 0; repetition < 16; repetition++) {
        value = sample_ns[file SUBSEP name SUBSEP repetition SUBSEP engine]
        if (value == "") {
            bad("missing raw sample for median")
            return 0
        }
        values[count++] = value + 0
    }
    for (ordinal = 1; ordinal < count; ordinal++) {
        value = values[ordinal]
        cursor = ordinal - 1
        while (cursor >= 0 && values[cursor] > value) {
            values[cursor + 1] = values[cursor]
            cursor--
        }
        values[cursor + 1] = value
    }
    return (values[7] + values[8]) / 2
}

function canonical_uint(value, minimum, maximum, max_digits, numeric) {
    if (value !~ /^(0|[1-9][0-9]*)$/ || length(value) > max_digits) return 0
    numeric = value + 0
    return numeric >= minimum && numeric <= maximum
}

function canonical_uint_equal(value, expected, max_digits) {
    return canonical_uint(value, expected, expected, max_digits) &&
        value == sprintf("%.0f", expected)
}

function canonical_fixed_3(value, minimum, maximum, max_integer_digits, numeric, integer) {
    if (value !~ /^(0|[1-9][0-9]*)[.][0-9][0-9][0-9]$/) return 0
    integer = value
    sub(/[.].*$/, "", integer)
    if (length(integer) > max_integer_digits) return 0
    numeric = value + 0
    return numeric >= minimum && numeric <= maximum
}

function canonical_fixed_4(value, minimum, maximum, max_integer_digits, numeric, integer) {
    if (value !~ /^(0|[1-9][0-9]*)[.][0-9][0-9][0-9][0-9]$/) return 0
    integer = value
    sub(/[.].*$/, "", integer)
    if (length(integer) > max_integer_digits) return 0
    numeric = value + 0
    return numeric >= minimum && numeric <= maximum
}

function add_case(name, bytes, count) {
    if (name in case_index) {
        bad("internal duplicate qualification case")
        return
    }
    case_name[case_total] = name
    case_index[name] = case_total
    case_bytes[name] = bytes
    case_count[name] = count
    case_total++
}

function bad(message) {
    if (!failed) print "verify-results: " message > "/dev/stderr"
    failed = 1
}
' "$@"
