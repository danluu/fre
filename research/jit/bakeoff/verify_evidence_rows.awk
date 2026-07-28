BEGIN {
    FS = ","
}

NR == 1 {
    for (column = 1; column <= NF; column++) {
        if ($column in index_of) {
            print "duplicate CSV column " $column > "/dev/stderr"
            bad = 1
        }
        index_of[$column] = column
    }
    required[1] = "schema"
    required[2] = "iterations"
    required[3] = "haystack_bytes"
    required[4] = "engine"
    required[5] = "stage"
    required[6] = "output_kind"
    required[7] = "backend"
    required[8] = "route"
    required[9] = "artifact_identity"
    required[10] = "evidence_identity"
    required[11] = "qualification_state"
    required[12] = "qualification_bundle_sha256"
    required[13] = "evidence_binding"
    required[14] = "artifact_binding"
    required[15] = "declared_min_window_bytes"
    required[16] = "declared_min_qualifying_calls"
    required[17] = "measured_calls"
    required[18] = "measured_qualifying_calls"
    required[19] = "timing_scope"
    for (item in required) {
        if (!(required[item] in index_of)) {
            print "missing CSV column " required[item] > "/dev/stderr"
            bad = 1
        }
    }
    columns = NF
    next
}

{
    if (NF != columns) {
        print "row " NR " has " NF " columns, expected " columns > "/dev/stderr"
        bad = 1
        next
    }
    schema = $(index_of["schema"])
    if (schema != "fre-jit-bakeoff-v2" &&
        schema != "fre-jit-bakeoff-v3") {
        print "row " NR " has the wrong row schema" > "/dev/stderr"
        bad = 1
    }
    engine = $(index_of["engine"])
    if (engine != "fre-qualified-exact" &&
        engine != "fre-qualified-exact-under-threshold") {
        next
    }

    qualified_rows++
    iterations = $(index_of["iterations"]) + 0
    haystack = $(index_of["haystack_bytes"]) + 0
    stage = $(index_of["stage"])
    timing_scope = $(index_of["timing_scope"])
    output = $(index_of["output_kind"])
    backend = $(index_of["backend"])
    route = $(index_of["route"])
    artifact = $(index_of["artifact_identity"])
    evidence = $(index_of["evidence_identity"])
    qualification_state = $(index_of["qualification_state"])
    qualification_bundle = $(index_of["qualification_bundle_sha256"])
    binding = $(index_of["evidence_binding"])
    artifact_binding = $(index_of["artifact_binding"])
    min_window = $(index_of["declared_min_window_bytes"]) + 0
    min_calls = $(index_of["declared_min_qualifying_calls"]) + 0
    measured = $(index_of["measured_calls"]) + 0
    measured_qualifying = $(index_of["measured_qualifying_calls"]) + 0

    if (output != "span") {
        print "qualified row " NR " is not bound to span output" > "/dev/stderr"
        bad = 1
    }
    if (qualification_state == "candidate") {
        if (qualification_bundle != "none") {
            print "candidate row " NR " carries a qualification bundle" > "/dev/stderr"
            bad = 1
        }
    } else if (qualification_state == "qualified") {
        if (length(qualification_bundle) != 64 ||
            qualification_bundle ~ /[^0-9a-f]/ ||
            qualification_bundle == "0000000000000000000000000000000000000000000000000000000000000000" ||
            qualification_bundle == "89af5a04190a39c40a4819ce916fc28630330550e1cafc15e9919122af0ae9f7") {
            print "qualified row " NR " carries an invalid bundle identity" > "/dev/stderr"
            bad = 1
        }
    } else {
        print "unknown qualification state at row " NR ": " qualification_state > "/dev/stderr"
        bad = 1
    }
    if (route == "native-jit") {
        if (schema == "fre-jit-bakeoff-v2") {
            expected_backend = "aarch64-search-v7"
            expected_artifact_binding = \
                "facade-reported-identity+deterministic-native-span-image"
            identity_matches = artifact == span_identity
        } else {
            expected_backend = \
                "aarch64-search-v8-selected-end-register-v2"
            expected_artifact_binding = \
                "facade-reported-abi2-identity+deterministic-selected-end-register-v2-image"
            identity_matches = 1
        }
        if (backend != expected_backend ||
            !identity_matches ||
            artifact_binding != expected_artifact_binding ||
            length(artifact) != 64 || artifact ~ /[^0-9a-f]/) {
            print "qualified native artifact binding mismatch at row " NR > "/dev/stderr"
            bad = 1
        }
        if (schema == "fre-jit-bakeoff-v2") {
            for (field = 20; field <= 29; field++) {
                if ($(field) + 0 <= 0) {
                    print "qualified native row " NR " has empty native accounting" > "/dev/stderr"
                    bad = 1
                }
            }
        } else {
            required_positive[1] = "code_bytes"
            required_positive[2] = "data_bytes"
            required_positive[3] = "payload_used_bytes"
            required_positive[4] = "total_mapped_bytes"
            required_positive[5] = "total_pages"
            required_positive[6] = "instructions"
            required_positive[7] = "vector_instructions"
            required_positive[8] = "loads"
            required_positive[9] = "branches"
            for (item in required_positive) {
                field = index_of[required_positive[item]]
                if ($(field) + 0 <= 0) {
                    print "qualified ABI2 native row " NR " has empty " required_positive[item] > "/dev/stderr"
                    bad = 1
                }
            }
            if ($(index_of["stores"]) + 0 != 0 ||
                $(index_of["identity_bytes_hashed"]) + 0 != 0 ||
                $(index_of["identity_scratch_bytes"]) + 0 != 0 ||
                $(index_of["identity_heap_allocations"]) + 0 != 0) {
                print "qualified ABI2 native row " NR " violates register-return/hot-identity accounting" > "/dev/stderr"
                bad = 1
            }
        }
    } else if (route == "portable-literal") {
        if (backend != route || artifact != "none" ||
            artifact_binding != "portable-semantic-owner") {
            print "qualified portable artifact binding mismatch at row " NR > "/dev/stderr"
            bad = 1
        }
        for (field = 20; field <= 32; field++) {
            if ($(field) + 0 != 0) {
                print "qualified portable row " NR " carries native metadata" > "/dev/stderr"
                bad = 1
            }
        }
    } else {
        print "unknown qualified route at row " NR ": " route > "/dev/stderr"
        bad = 1
    }

    if (schema == "fre-jit-bakeoff-v2") {
        expected_binding = \
            "fre-qualified-exact-evidence-v2|output=" output \
            "|backend=" backend \
            "|route=" route \
            "|artifact=" artifact \
            "|qualification_state=" qualification_state \
            "|qualification_bundle=" qualification_bundle \
            "|minimum_window_bytes=" min_window \
            "|minimum_qualifying_calls=" min_calls
    } else {
        native_output = route == "native-jit" ? "selected-end" : "none"
        native_abi = route == "native-jit" ? \
            "selected-end-register-v2" : "none"
        expected_binding = \
            "fre-qualified-exact-evidence-v3|public_output=" output \
            "|native_output=" native_output \
            "|native_abi=" native_abi \
            "|backend=" backend \
            "|route=" route \
            "|artifact=" artifact \
            "|qualification_state=" qualification_state \
            "|qualification_bundle=" qualification_bundle \
            "|minimum_window_bytes=" min_window \
            "|minimum_qualifying_calls=" min_calls
    }
    if (schema == "fre-jit-bakeoff-v3") {
        if (engine == "fre-qualified-exact" && stage == "search") {
            expected_scope = \
                "session_value_search_declared_workload_build_and_session_excluded"
        } else if (engine == "fre-qualified-exact" &&
                   stage == "build_full_workload") {
            expected_scope = \
                "build_plus_session_plus_declared_workload_amortized_per_value_search"
        } else if (engine == "fre-qualified-exact-under-threshold" &&
                   stage == "search") {
            expected_scope = \
                "session_value_search_forced_portable_build_and_session_excluded"
        } else if (engine == "fre-qualified-exact-under-threshold" &&
                   stage == "build_full_workload") {
            expected_scope = \
                "portable_build_plus_session_plus_declared_workload_amortized_per_value_search"
        } else {
            expected_scope = ""
        }
        if (expected_scope == "" || timing_scope != expected_scope) {
            print "qualified V3 timing boundary mismatch at row " NR > "/dev/stderr"
            bad = 1
        }
    }
    if (binding != expected_binding) {
        print "qualified evidence binding mismatch at row " NR > "/dev/stderr"
        bad = 1
    }
    if (length(evidence) != 64 || evidence ~ /[^0-9a-f]/) {
        print "malformed qualified evidence identity at row " NR > "/dev/stderr"
        bad = 1
    }
    if (min_window <= 0 || min_calls <= 0 || measured != iterations) {
        print "dishonest declared/measured call accounting at row " NR > "/dev/stderr"
        bad = 1
    }
    expected_qualifying = haystack >= min_window ? measured : 0
    if (measured_qualifying != expected_qualifying) {
        print "qualifying-call accounting mismatch at row " NR > "/dev/stderr"
        bad = 1
    }
    if (stage == "build_full_workload" && measured != min_calls) {
        print "full-workload row does not execute its declaration at row " NR > "/dev/stderr"
        bad = 1
    }
    if (engine == "fre-qualified-exact") {
        if (stage == "search" && measured_qualifying < min_calls) {
            print "search-only row does not meet its declared reuse at row " NR > "/dev/stderr"
            bad = 1
        }
    } else {
        under_threshold = \
            min_window < 65536 || \
            (min_window >= 1048576 ? min_calls < 64 : min_calls < 1024)
        if (!under_threshold || route != "portable-literal") {
            print "under-threshold row is not an honest portable refusal at row " NR > "/dev/stderr"
            bad = 1
        }
    }
}

END {
    if (qualified_rows == 0) {
        print "no qualified evidence rows" > "/dev/stderr"
        bad = 1
    }
    exit bad
}
