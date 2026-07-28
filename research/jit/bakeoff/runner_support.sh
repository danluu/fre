#!/bin/sh

fre_bakeoff_error() {
    echo "$*" >&2
    return 2
}

fre_bakeoff_sha256() {
    shasum -a 256 "$1" | awk '{print $1}'
}

fre_bakeoff_validate_exact_clean_commit() {
    fre_bakeoff_repository=$1
    fre_bakeoff_revision=$2
    fre_bakeoff_label=$3
    case "$fre_bakeoff_revision" in
        *[!0-9a-f]*|"")
            fre_bakeoff_error \
                "$fre_bakeoff_label must be exactly 40 lowercase hexadecimal digits"
            return $?
            ;;
    esac
    if [ "${#fre_bakeoff_revision}" != 40 ]; then
        fre_bakeoff_error \
            "$fre_bakeoff_label must be exactly 40 lowercase hexadecimal digits"
        return $?
    fi
    fre_bakeoff_resolved=$(
        git -C "$fre_bakeoff_repository" \
            rev-parse --verify "$fre_bakeoff_revision^{commit}" 2>/dev/null
    ) || {
        fre_bakeoff_error "$fre_bakeoff_label is not a commit"
        return $?
    }
    if [ "$fre_bakeoff_resolved" != "$fre_bakeoff_revision" ]; then
        fre_bakeoff_error "$fre_bakeoff_label did not resolve exactly"
        return $?
    fi
}

fre_bakeoff_validate_distinct_exact_commits() {
    fre_bakeoff_repository=$1
    fre_bakeoff_baseline=$2
    fre_bakeoff_candidate=$3
    fre_bakeoff_validate_exact_clean_commit \
        "$fre_bakeoff_repository" "$fre_bakeoff_baseline" baseline_source || return $?
    fre_bakeoff_validate_exact_clean_commit \
        "$fre_bakeoff_repository" "$fre_bakeoff_candidate" candidate_source || return $?
    if [ "$fre_bakeoff_baseline" = "$fre_bakeoff_candidate" ]; then
        fre_bakeoff_error "baseline and candidate source states must differ"
        return $?
    fi
}

fre_bakeoff_validate_process_output() {
    fre_bakeoff_process_output=$1
    fre_bakeoff_header_file=$2
    fre_bakeoff_expected_source=$3
    fre_bakeoff_expected_repetition=$4
    fre_bakeoff_expected_cell=$5
    if [ ! -f "$fre_bakeoff_process_output" ] ||
        [ -L "$fre_bakeoff_process_output" ]
    then
        fre_bakeoff_error \
            "timed invocation output must be a regular non-symlink file"
        return $?
    fi
    FRE_BAKEOFF_PROCESS_PID=$(
        awk -F, \
            -v expected_source="$fre_bakeoff_expected_source" \
            -v expected_repetition="$fre_bakeoff_expected_repetition" \
            -v expected_cell="$fre_bakeoff_expected_cell" '
            FNR == NR {
                if (FNR != 1) bad = 1
                columns = NF
                for (column = 1; column <= NF; column++) {
                    if ($column in index_of) bad = 1
                    index_of[$column] = column
                }
                required[1] = "revision"
                required[2] = "pid"
                required[3] = "repetition"
                required[4] = "cell"
                required[5] = "engine"
                required[6] = "stage"
                for (item in required) {
                    if (!(required[item] in index_of)) bad = 1
                }
                next
            }
            {
                rows++
                if (NF != columns) bad = 1
                source = $(index_of["revision"])
                pid_value = $(index_of["pid"])
                repetition = $(index_of["repetition"])
                cell = $(index_of["cell"])
                if (source != expected_source ||
                    repetition != expected_repetition ||
                    cell != expected_cell ||
                    pid_value !~ /^[0-9]+$/ ||
                    sprintf("%d", pid_value + 0) != pid_value ||
                    pid_value + 0 <= 0) bad = 1
                if (!pid) pid = pid_value
                else if (pid != pid_value) bad = 1
                if ($(index_of["engine"]) == "jit" &&
                    $(index_of["stage"]) == "direct_lease_call") direct++
            }
            END {
                if (rows == 0 || direct != 1 || !pid) bad = 1
                if (bad) exit 2
                print pid
            }
        ' "$fre_bakeoff_header_file" "$fre_bakeoff_process_output"
    ) || {
        fre_bakeoff_error \
            "timed invocation rows do not match their source/process contract"
        return $?
    }
}

fre_bakeoff_require_holder() {
    fre_bakeoff_expected_holder=$1
    case "$fre_bakeoff_expected_holder" in
        build|timing|target-cpu-timing) ;;
        *)
            fre_bakeoff_error \
                "unsupported resource coordinator holder kind"
            return $?
            ;;
    esac
    fre_bakeoff_holder_command="run-$fre_bakeoff_expected_holder"
    if [ "$fre_bakeoff_expected_holder" = timing ]; then
        fre_bakeoff_holder_command=run-timing-wave
    fi
    fre_bakeoff_holder_dir=${FRE_RESOURCE_HOLDER_DIR:-}
    fre_bakeoff_holder_token=${FRE_RESOURCE_HOLDER_TOKEN:-}
    if [ "${FRE_RESOURCE_HOLDER_KIND:-}" != "$fre_bakeoff_expected_holder" ] ||
        [ "${#fre_bakeoff_holder_token}" != 64 ] ||
        [ ! -d "$fre_bakeoff_holder_dir" ] ||
        [ -L "$fre_bakeoff_holder_dir" ]
    then
        fre_bakeoff_error \
            "must run under resource-coordinator.zsh $fre_bakeoff_holder_command"
        return $?
    fi
    case "$fre_bakeoff_holder_token" in
        *[!0-9a-f]*)
            fre_bakeoff_error "malformed resource coordinator holder token"
            return $?
            ;;
    esac
    if [ "$fre_bakeoff_expected_holder" = target-cpu-timing ]; then
        fre_bakeoff_target_cpu=${FRE_RESOURCE_TARGET_CPU:-}
        fre_bakeoff_session_id=${FRE_RESOURCE_TIMING_SESSION_ID:-}
        fre_bakeoff_session_holder_id=\
${FRE_RESOURCE_TIMING_SESSION_HOLDER_ID:-}
        fre_bakeoff_owner_sha256=\
${FRE_RESOURCE_TIMING_SESSION_OWNER_SHA256:-}
        fre_bakeoff_admission=\
${FRE_RESOURCE_TIMING_ADMISSION_RECEIPT:-}
        fre_bakeoff_admission_sha256=\
${FRE_RESOURCE_TIMING_ADMISSION_RECEIPT_SHA256:-}
        fre_bakeoff_coordinator=${FRE_RESOURCE_COORDINATOR_PATH:-}
        fre_bakeoff_coordinator_sha256=\
${FRE_RESOURCE_COORDINATOR_SHA256:-}
        case "$fre_bakeoff_target_cpu" in
            0|[1-9]|[1-9][0-9]|[1-9][0-9][0-9]|\
[1-3][0-9][0-9][0-9]|4[0][0-8][0-9]|409[0-5]) ;;
            *)
                fre_bakeoff_error "malformed target CPU"
                return $?
                ;;
        esac
        if [ "$fre_bakeoff_session_holder_id" != \
            "${fre_bakeoff_holder_dir##*/}" ] ||
            [ "$fre_bakeoff_admission" != \
            "$fre_bakeoff_holder_dir/admission.tsv" ] ||
            [ ! -f "$fre_bakeoff_admission" ] ||
            [ -L "$fre_bakeoff_admission" ] ||
            [ "${fre_bakeoff_coordinator#/}" = \
            "$fre_bakeoff_coordinator" ] ||
            [ ! -f "$fre_bakeoff_coordinator" ] ||
            [ -L "$fre_bakeoff_coordinator" ]
        then
            fre_bakeoff_error \
                "target-CPU session paths do not match the inherited holder"
            return $?
        fi
        for fre_bakeoff_target_digest in \
            "$fre_bakeoff_session_id" \
            "$fre_bakeoff_owner_sha256" \
            "$fre_bakeoff_admission_sha256" \
            "$fre_bakeoff_coordinator_sha256"
        do
            if [ "${#fre_bakeoff_target_digest}" != 64 ]; then
                fre_bakeoff_error \
                    "malformed target-CPU authority digest"
                return $?
            fi
            case "$fre_bakeoff_target_digest" in
                *[!0-9a-f]*|\
0000000000000000000000000000000000000000000000000000000000000000)
                    fre_bakeoff_error \
                        "malformed target-CPU authority digest"
                    return $?
                    ;;
            esac
        done
    fi
}

fre_bakeoff_canonical_new_external_directory() {
    fre_bakeoff_workspace=$1
    fre_bakeoff_candidate=$2
    case "$fre_bakeoff_candidate" in
        /*) ;;
        *)
            fre_bakeoff_error "output directory must be absolute: $fre_bakeoff_candidate"
            return $?
            ;;
    esac
    if [ -e "$fre_bakeoff_candidate" ] || [ -L "$fre_bakeoff_candidate" ]; then
        fre_bakeoff_error "refusing to overwrite existing output: $fre_bakeoff_candidate"
        return $?
    fi
    fre_bakeoff_parent_argument=$(dirname -- "$fre_bakeoff_candidate")
    fre_bakeoff_name=$(basename -- "$fre_bakeoff_candidate")
    if [ "$fre_bakeoff_name" = . ] || [ "$fre_bakeoff_name" = .. ]; then
        fre_bakeoff_error "invalid output directory: $fre_bakeoff_candidate"
        return $?
    fi
    if [ ! -d "$fre_bakeoff_parent_argument" ]; then
        fre_bakeoff_error "output parent must already exist: $fre_bakeoff_parent_argument"
        return $?
    fi
    fre_bakeoff_parent=$(
        CDPATH= cd -P -- "$fre_bakeoff_parent_argument" && pwd -P
    ) || return 2
    FRE_BAKEOFF_CANONICAL_PATH="$fre_bakeoff_parent/$fre_bakeoff_name"
    case "$FRE_BAKEOFF_CANONICAL_PATH" in
        "$fre_bakeoff_workspace"|"$fre_bakeoff_workspace"/*)
            fre_bakeoff_error \
                "output directory must be outside the workspace: $FRE_BAKEOFF_CANONICAL_PATH"
            return $?
            ;;
    esac
}

fre_bakeoff_canonical_external_directory() {
    fre_bakeoff_workspace=$1
    fre_bakeoff_candidate=$2
    case "$fre_bakeoff_candidate" in
        /*) ;;
        *)
            fre_bakeoff_error "directory must be absolute: $fre_bakeoff_candidate"
            return $?
            ;;
    esac
    if [ ! -d "$fre_bakeoff_candidate" ] || [ -L "$fre_bakeoff_candidate" ]; then
        fre_bakeoff_error "directory must be regular and non-symlink: $fre_bakeoff_candidate"
        return $?
    fi
    FRE_BAKEOFF_CANONICAL_PATH=$(
        CDPATH= cd -P -- "$fre_bakeoff_candidate" && pwd -P
    ) || return 2
    case "$FRE_BAKEOFF_CANONICAL_PATH" in
        "$fre_bakeoff_workspace"|"$fre_bakeoff_workspace"/*)
            fre_bakeoff_error \
                "directory must be outside the workspace: $FRE_BAKEOFF_CANONICAL_PATH"
            return $?
            ;;
    esac
}

fre_bakeoff_canonical_regular_file() {
    fre_bakeoff_candidate=$1
    fre_bakeoff_label=$2
    case "$fre_bakeoff_candidate" in
        /*) ;;
        *)
            fre_bakeoff_error "$fre_bakeoff_label must be an absolute path"
            return $?
            ;;
    esac
    if [ ! -f "$fre_bakeoff_candidate" ] || [ -L "$fre_bakeoff_candidate" ]; then
        fre_bakeoff_error "$fre_bakeoff_label must name a regular non-symlink file"
        return $?
    fi
    fre_bakeoff_file_parent=$(
        CDPATH= cd -P -- "$(dirname -- "$fre_bakeoff_candidate")" && pwd -P
    ) || return 2
    FRE_BAKEOFF_CANONICAL_PATH="$fre_bakeoff_file_parent/$(basename -- "$fre_bakeoff_candidate")"
}

fre_bakeoff_canonical_executable() {
    fre_bakeoff_canonical_regular_file "$1" "$2" || return $?
    if [ ! -x "$FRE_BAKEOFF_CANONICAL_PATH" ]; then
        fre_bakeoff_error "$2 must be executable"
        return $?
    fi
}

fre_bakeoff_receipt_field() {
    fre_bakeoff_receipt=$1
    fre_bakeoff_key=$2
    awk -F '	' -v key="$fre_bakeoff_key" '
        $1 == key {
            if (NF != 2 || found) exit 2
            value = $2
            found = 1
        }
        END {
            if (!found) exit 2
            print value
        }
    ' "$fre_bakeoff_receipt"
}

fre_bakeoff_validate_build_receipt() {
    fre_bakeoff_receipt=$1
    awk -F '	' '
        NF != 2 { bad = 1 }
        {
            count[$1]++
            allowed = \
                $1 == "schema" || \
                $1 == "source_state_id" || \
                $1 == "binary_path" || \
                $1 == "binary_sha256" || \
                $1 == "build_dir" || \
                $1 == "manifest_path" || \
                $1 == "manifest_sha256" || \
                $1 == "lockfile_path" || \
                $1 == "lockfile_sha256" || \
                $1 == "rustc" || \
                $1 == "cargo" || \
                $1 == "coordinator_holder_dir" || \
                $1 == "built_utc"
            if (!allowed) bad = 1
        }
        END {
            required["schema"] = 1
            required["source_state_id"] = 1
            required["binary_path"] = 1
            required["binary_sha256"] = 1
            required["build_dir"] = 1
            required["manifest_path"] = 1
            required["manifest_sha256"] = 1
            required["lockfile_path"] = 1
            required["lockfile_sha256"] = 1
            required["rustc"] = 1
            required["cargo"] = 1
            required["coordinator_holder_dir"] = 1
            required["built_utc"] = 1
            for (key in required) {
                if (count[key] != 1) bad = 1
            }
            exit bad
        }
    ' "$fre_bakeoff_receipt"
}

fre_bakeoff_prepare_timing_inputs() {
    fre_bakeoff_workspace=$1
    fre_bakeoff_output_argument=$2
    fre_bakeoff_capture_script=$3

    fre_bakeoff_require_holder timing || return $?
    fre_bakeoff_canonical_new_external_directory \
        "$fre_bakeoff_workspace" "$fre_bakeoff_output_argument" || return $?
    FRE_BAKEOFF_OUTPUT=$FRE_BAKEOFF_CANONICAL_PATH

    fre_bakeoff_canonical_executable \
        "${FRE_BAKEOFF_BINARY:-}" FRE_BAKEOFF_BINARY || return $?
    FRE_BAKEOFF_BINARY_PATH=$FRE_BAKEOFF_CANONICAL_PATH
    fre_bakeoff_canonical_regular_file \
        "${FRE_BAKEOFF_BUILD_RECEIPT:-}" FRE_BAKEOFF_BUILD_RECEIPT || return $?
    FRE_BAKEOFF_BUILD_RECEIPT_PATH=$FRE_BAKEOFF_CANONICAL_PATH

    mkdir -- "$FRE_BAKEOFF_OUTPUT" || return 2
    chmod 0700 "$FRE_BAKEOFF_OUTPUT" || return 2
    mkdir -- "$FRE_BAKEOFF_OUTPUT/provenance" || return 2
    FRE_BAKEOFF_SOURCE_STATE=$(
        "$fre_bakeoff_capture_script" capture \
            "$fre_bakeoff_workspace" "$FRE_BAKEOFF_OUTPUT/provenance/source"
    ) || return $?

    cp -- \
        "$FRE_BAKEOFF_BUILD_RECEIPT_PATH" \
        "$FRE_BAKEOFF_OUTPUT/provenance/build-receipt.tsv" || return 2
    fre_bakeoff_validate_build_receipt \
        "$FRE_BAKEOFF_OUTPUT/provenance/build-receipt.tsv" || {
        fre_bakeoff_error "invalid build receipt"
        return $?
    }
    FRE_BAKEOFF_BUILD_RECEIPT_SHA256=$(
        fre_bakeoff_sha256 "$FRE_BAKEOFF_BUILD_RECEIPT_PATH"
    ) || return 2
    fre_bakeoff_copied_receipt_sha=$(
        fre_bakeoff_sha256 "$FRE_BAKEOFF_OUTPUT/provenance/build-receipt.tsv"
    ) || return 2
    if [ "$FRE_BAKEOFF_BUILD_RECEIPT_SHA256" != "$fre_bakeoff_copied_receipt_sha" ]; then
        fre_bakeoff_error "build receipt changed while it was copied"
        return $?
    fi

    fre_bakeoff_receipt_schema=$(
        fre_bakeoff_receipt_field \
            "$FRE_BAKEOFF_OUTPUT/provenance/build-receipt.tsv" schema
    ) || return 2
    fre_bakeoff_receipt_source=$(
        fre_bakeoff_receipt_field \
            "$FRE_BAKEOFF_OUTPUT/provenance/build-receipt.tsv" source_state_id
    ) || return 2
    fre_bakeoff_receipt_binary=$(
        fre_bakeoff_receipt_field \
            "$FRE_BAKEOFF_OUTPUT/provenance/build-receipt.tsv" binary_path
    ) || return 2
    fre_bakeoff_receipt_binary_sha=$(
        fre_bakeoff_receipt_field \
            "$FRE_BAKEOFF_OUTPUT/provenance/build-receipt.tsv" binary_sha256
    ) || return 2
    FRE_BAKEOFF_BUILD_RUSTC=$(
        fre_bakeoff_receipt_field \
            "$FRE_BAKEOFF_OUTPUT/provenance/build-receipt.tsv" rustc
    ) || return 2
    FRE_BAKEOFF_BUILD_CARGO=$(
        fre_bakeoff_receipt_field \
            "$FRE_BAKEOFF_OUTPUT/provenance/build-receipt.tsv" cargo
    ) || return 2
    if [ "$fre_bakeoff_receipt_schema" != fre-jit-bakeoff-build-receipt-v1 ]; then
        fre_bakeoff_error "unsupported build receipt schema"
        return $?
    fi
    if [ "$fre_bakeoff_receipt_source" != "$FRE_BAKEOFF_SOURCE_STATE" ]; then
        fre_bakeoff_error "build receipt source state does not match timing source state"
        return $?
    fi
    if [ "$fre_bakeoff_receipt_binary" != "$FRE_BAKEOFF_BINARY_PATH" ]; then
        fre_bakeoff_error "build receipt names a different executable"
        return $?
    fi
    FRE_BAKEOFF_BINARY_SHA256=$(fre_bakeoff_sha256 "$FRE_BAKEOFF_BINARY_PATH") || return 2
    if [ "$fre_bakeoff_receipt_binary_sha" != "$FRE_BAKEOFF_BINARY_SHA256" ]; then
        fre_bakeoff_error "prebuilt executable does not match its build receipt"
        return $?
    fi

    printf '%s\n' "$FRE_BAKEOFF_BUILD_RECEIPT_PATH" \
        > "$FRE_BAKEOFF_OUTPUT/provenance/build-receipt-source-path.txt"
    printf '%s\n' "$FRE_BAKEOFF_BUILD_RECEIPT_SHA256" \
        > "$FRE_BAKEOFF_OUTPUT/provenance/build-receipt.sha256"
    printf '%s\n' "$FRE_BAKEOFF_BINARY_PATH" \
        > "$FRE_BAKEOFF_OUTPUT/provenance/binary-path.txt"
    printf '%s\n' "$FRE_BAKEOFF_BINARY_SHA256" \
        > "$FRE_BAKEOFF_OUTPUT/provenance/binary.sha256"
    export FRE_BAKEOFF_REVISION=$FRE_BAKEOFF_SOURCE_STATE
}

fre_bakeoff_verify_timing_inputs() {
    fre_bakeoff_workspace=$1
    fre_bakeoff_capture_script=$2
    "$fre_bakeoff_capture_script" verify \
        "$fre_bakeoff_workspace" "$FRE_BAKEOFF_OUTPUT/provenance/source" || return $?
    fre_bakeoff_finish_binary_sha=$(
        fre_bakeoff_sha256 "$FRE_BAKEOFF_BINARY_PATH"
    ) || return 2
    if [ "$fre_bakeoff_finish_binary_sha" != "$FRE_BAKEOFF_BINARY_SHA256" ]; then
        fre_bakeoff_error "prebuilt executable changed during timing"
        return $?
    fi
    fre_bakeoff_finish_receipt_sha=$(
        fre_bakeoff_sha256 "$FRE_BAKEOFF_BUILD_RECEIPT_PATH"
    ) || return 2
    if [ "$fre_bakeoff_finish_receipt_sha" != "$FRE_BAKEOFF_BUILD_RECEIPT_SHA256" ]; then
        fre_bakeoff_error "build receipt changed during timing"
        return $?
    fi
}
