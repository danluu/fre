#!/usr/bin/env python3
"""Focused synthetic tests for the public-Rebar true-native census control."""

from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import pathlib
import tempfile
import unittest


MODULE_PATH = pathlib.Path(__file__).with_name("true_native_census.py")
SCHEMA_PATH = pathlib.Path(__file__).with_name("true_native_census.schema.json")
SPEC = importlib.util.spec_from_file_location("true_native_census", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
CENSUS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CENSUS)


def frozen_validation_fields() -> dict[str, str]:
    return {
        "validation_authority": "frozen-public-schedule-v1",
        "expected_value_sealed": "true",
        "expected_value": "1",
        "expected_comparator": "rust-regex-1.12.4",
        "schedule_klv_sha256": "7" * 64,
        "schedule_binding_sha256": "8" * 64,
        "stock_comparator": "rust-regex-1.12.4",
        "stock_divergence_policy": "report-only",
    }


def synthetic_plan() -> dict[str, object]:
    runtime_ids = [f"runtime-job-{index:03}" for index in range(311)]
    compile_ids = [f"compile-job-{index:03}" for index in range(33)]
    all_ids = compile_ids + runtime_ids
    jobs = []
    input_identity = {
        "pattern_sha256": ["4" * 64],
        "haystack_sha256": "9" * 64,
        "haystack_bytes": 1,
        "case_insensitive": False,
        "unicode": True,
    }
    klv_identity = {"path": "fixture.klv", "sha256": "7" * 64, "bytes": 1}
    for job_id in compile_ids:
        jobs.append({
            "job_id": job_id, "benchmark": job_id, "model": "compile",
            "input": input_identity, "candidate_klv": klv_identity,
            "is_runtime": False, "exact_adapter": False,
            "adapter_reason": "compile-job-outside-runtime-denominator", "point_ids": [],
        })
    for index, job_id in enumerate(runtime_ids):
        model = (
            "count-captures" if index == 0
            else "grep-captures" if index == 2
            else "unsupported-runtime" if index == len(runtime_ids) - 1
            else "count"
        )
        jobs.append({
            "job_id": job_id, "benchmark": job_id,
            "model": model,
            "input": input_identity, "candidate_klv": klv_identity,
            "is_runtime": True, "exact_adapter": index != len(runtime_ids) - 1,
            "adapter_reason": (
                "exact-uniform-capture-native-row-composite-adapter"
                if index in (0, 2)
                else "unsupported-runtime-model-or-cardinality"
                if index == len(runtime_ids) - 1
                else "exact-single-pattern-scalar-adapter"
            ),
            "point_ids": [],
        })
    points = []
    for ordinal, job in enumerate(jobs):
        point_id = f"point-{ordinal:03}"
        job["point_ids"] = [point_id]
        points.append({
            "point_id": point_id,
            "job_id": job["job_id"],
            "benchmark": job["benchmark"],
            "model": job["model"],
            "boundary": "synthetic",
            "comparator": "rust-regex-1.12.4",
            "expected": 1,
            "input": input_identity,
            "candidate_klv": klv_identity,
            "reference_klv": klv_identity,
            "source_schedule_sha256": "7" * 64,
            "source_ordinal": ordinal,
        })
    all_point_ids = [point["point_id"] for point in points]
    runtime_point_ids = [
        point["point_id"] for point in points if point["model"] != "compile"
    ]
    unsigned = {
        "schema": CENSUS.PLAN_SCHEMA,
        "candidate_source": {
            "commit": "1" * 40,
            "tree": "2" * 40,
            "cargo_lock_sha256": "3" * 64,
        },
        "public_corpus": {
            "label": "synthetic-public",
            "klv_root_recorded": "public/klv",
            "privacy_policy": "public-rebar-only; hashed-input-identities; no-pattern-or-haystack-bytes",
            "rebar_revisions": ["6" * 40],
            "schedules": [{
                "file_sha256": "7" * 64, "internal_sha256": "8" * 64,
                "canonical_commit": "1" * 40, "canonical_tree": "2" * 40,
                "rebar_revision": "6" * 40, "point_count": len(points),
            }],
        },
        "target": {
            "triple": "aarch64-linux",
            "features": "asimd",
            "feature_bits": "0000000100000000",
        },
        "policy": {
            "compiler_mode": "Optimizing", "timing": False,
            "public_klv_bytes_hashed": True, "reproducible_builds_required": 2,
            "native_proof": (
                "unmodified-oracle-pass + all-semantic-helper-traps-pass + "
                "claimed-entry-trap-fires"
            ),
            "compiled_artifact_is_runtime_execution": False,
            "unsupported_failure_timeout_are_nonnative": True,
            "canonical_denominator": "deduplicated-public-rust-rebar-runtime-job",
        },
        "denominators": {
            "all_public_jobs": CENSUS.id_set(all_ids),
            "compile_jobs": CENSUS.id_set(compile_ids),
            "runtime_jobs": CENSUS.id_set(runtime_ids),
            "exact_adapter_runtime_jobs": CENSUS.id_set(runtime_ids[:-1]),
            "all_raw_schedule_points": CENSUS.id_set(all_point_ids),
            "raw_runtime_schedule_points": CENSUS.id_set(runtime_point_ids),
        },
        "jobs": jobs,
        "points": points,
    }
    return CENSUS.add_digest(unsigned, "plan_sha256")


def synthetic_qualification_receipt(plan: dict[str, object]) -> dict[str, object]:
    job = plan["jobs"][34]
    object_sha256 = "a" * 64
    fields = scalar_native_reducer_provenance_fields("count", ordered=False)
    fields.update({
        "benchmark": job["benchmark"],
        "source_commit": plan["candidate_source"]["commit"],
        "source_tree": plan["candidate_source"]["tree"],
        "target": plan["target"]["triple"],
        "feature_bits": plan["target"]["feature_bits"],
        "program_sha256": "b" * 64,
        "object_sha256": object_sha256,
    })
    encoded = " ".join(f"{key}={value}" for key, value in fields.items()).encode()
    provenance = CENSUS.provenance_receipt(CENSUS.parse_provenance(encoded))
    entry = fields["reducer_symbol"]
    artifact = {
        "runner_sha256": "c" * 64,
        "objects": [{"ordinal": 0, "sha256": object_sha256, "bytes": 123}],
    }
    empty_process = {
        "outcome": "not-run",
        "returncode": None,
        "stdout_bytes": 0,
        "stdout_sha256": CENSUS.sha_bytes(b""),
        "stderr_bytes": 0,
        "stderr_sha256": CENSUS.sha_bytes(b""),
    }
    exited_process = {
        **empty_process,
        "outcome": "exit",
        "returncode": 0,
    }
    helper_marker = {
        "status": "missing", "sha256": None, "armed": [], "triggered": None,
    }
    entry_marker = {
        "status": "valid",
        "sha256": "d" * 64,
        "kind": "claimed-operation-entry",
        "architecture": "aarch64",
        "installed": 1,
        "expected": 1,
        "armed": [{
            "symbol": entry,
            "offset": "0x100",
            "before": "fd7bbfa9",
            "after": "000020d4",
        }],
        "triggered": entry,
        "completed": None,
    }
    phases = {
        "unmodified_oracle": exited_process,
        "semantic_helper_trap": {"process": empty_process, "marker": helper_marker},
        "claimed_entry_negative_traps": [{
            "ordinal": 0,
            "symbol": entry,
            "process": {**exited_process, "returncode": CENSUS.TRAP_EXIT},
            "marker": entry_marker,
        }],
    }
    route = {
        "operation_entry_symbols": [entry],
        "operation_entry_symbols_sha256": CENSUS.sha_bytes(
            CENSUS.canonical([entry]).encode()
        ),
        "adapter_route": "linked-reducer",
        "semantic_helper_symbols": [],
        "semantic_helper_symbols_sha256": CENSUS.sha_bytes(
            CENSUS.canonical([]).encode()
        ),
        "provenance_declared_runtime_symbols": [],
        "primary_nm_sha256": "e" * 64,
        "replica_nm_sha256": "e" * 64,
    }
    receipt = {
        "schema": CENSUS.RECEIPT_SCHEMA,
        "plan_sha256": plan["plan_sha256"],
        "candidate_source": plan["candidate_source"],
        "job": {
            "job_id": job["job_id"],
            "point_ids": job["point_ids"],
            "model": job["model"],
            "input": job["input"],
            "candidate_klv": job["candidate_klv"],
        },
        "artifacts": {
            "primary": artifact,
            "replica": artifact,
            "reproducible": True,
            "compiled_artifact_present": True,
            "runtime_execution_authenticated_separately": True,
            "provenance": provenance,
        },
        "route": route,
        "phases": phases,
        "classification": CENSUS.classification_from_qualification_evidence(
            True, [entry], route["adapter_route"], [], phases, "aarch64"
        ),
    }
    return CENSUS.add_digest(receipt, "receipt_sha256")


def synthetic_regex_redux_fields() -> dict[str, str]:
    identity = "a" * 64
    fields = {
        **frozen_validation_fields(),
        "schema": "fre.aot.rebar-runner.v3",
        "model": "regex-redux",
        "component_count": "15",
        "adapter": "general-aot-native-regex-redux-reducer-v1",
        "engine": "NativeRegexReduxAotV1",
        "aggregate_strategy": "native-fixed-regex-redux-whole-operation-v1",
        "boundary": "single-call-native-regex-redux-reducer",
        "target": "x86_64-unknown-linux-gnu",
        "reducer_symbol": f"fre_aot_regex_rebar_regex_redux_v1_{identity}",
        "operation_identity_sha256": identity,
        "reducer_code_sha256": "b" * 64,
        "reducer_data_sha256": "c" * 64,
        "reducer_object_sha256": "d" * 64,
        "reducer_relocation_count": "16",
        "semantic_runtime_symbols": "",
        "abi_version": "1",
        "request_bytes": "72",
        "receipt_bytes": "144",
        "report_bytes": "1024",
        "scratch_buffer_count": "2",
        "scratch_capacity_numerator": "3",
        "scratch_capacity_denominator": "2",
        "receipt_schema": "u64-input-clean-variant9-substitution5-final-report-v1",
        "report_schema": "variant9-blank-input-clean-final-lines-v1",
    }
    entries = []
    for index in range(15):
        fields[f"component_{index}_native"] = "true"
        entry = f"fre_aot_regex_search_v1_{index + 1:064x}"
        entries.append(entry)
        fields[f"component_{index}_entry_symbol"] = entry
        fields[f"component_{index}_runtime_symbols"] = ""
        fields[f"component_{index}_program_sha256"] = f"{index:064x}"
        fields[f"component_{index}_object_sha256"] = f"{index + 1:064x}"
    fields["reducer_link_symbols"] = ",".join(entries)
    return fields


def uniform_capture_provenance_fields() -> dict[str, str]:
    entry_suffix = "d" * 64
    fields = {
        **frozen_validation_fields(),
        "schema": "fre.aot.rebar-runner.v3",
        "disposition": "executed",
        "configured": "true",
        "adapter": "general-aot-uniform-capture-native-row-count-adapter-loop-v1",
        "model": "count-captures",
        "benchmark": "runtime-job-000",
        "source_commit": "1" * 40,
        "source_tree": "2" * 40,
        "target": "aarch64-linux",
        "feature_bits": "0000000100000000",
        "compiler_version": "1",
        "optimizer_version": "1",
        "engine": "IndependentNativeSpanRows(OrderedDfa)",
        "aggregate_strategy": "native-row-static-uniform-capture-multiplier-v1",
        "native_row_bridge": "true",
        "uniform_capture_bridge": "true",
        "source_pattern_count": "1",
        "row_total_object_bytes": "123",
        "source_to_artifact": "0",
        "component_count": "1",
        "prepare_max_handle_bytes": "0",
        "prepare_max_scratch_bytes": "0",
        "prepare_max_setup_work": "0",
        "component_0_native": "true",
        "component_0_source_ordinal": "0",
        "component_0_entry_symbol": f"fre_aot_regex_search_v1_{entry_suffix}",
        "component_0_runtime_symbols": "",
        "component_0_required_prepare_capabilities": "0000000000000000",
        "component_0_prepare_config_version": "0",
        "component_0_prepare_operation_flags": "0000000000000000",
        "component_0_runtime_program_symbol": "",
        "component_0_runtime_program_len": "0",
        "component_0_span_fill_symbol": "",
        "component_0_prepared_bulk_strategy": "None",
        "component_0_automaton_sha256": "a" * 64,
        "component_0_program_sha256": "b" * 64,
        "component_0_object_sha256": "c" * 64,
        "capture_resolution": "static-uniform-multiplier",
        "capture_proof_algorithm_version": "1",
        "capture_proof_accounting_version": "1",
        "source_participating_groups": "2",
        "source_minimum_match_bytes": "1",
        "source_capture_annotations": "1",
        "source_proof_work": "7",
        "source_proof_peak_stack_items": "3",
        "source_selector_automaton_sha256": "a" * 64,
        "source_selector_program_sha256": "b" * 64,
        "source_selector_object_sha256": "c" * 64,
        "boundary": "native-search-core-static-uniform-capture-resolution",
        "required_comparators": "rust-regex-1.12.4,fre-current-runtime",
    }
    return fields


def prepared_scalar_grep_provenance_fields() -> dict[str, str]:
    native_identity = "d" * 64
    aggregate_identity = "e" * 64
    return {
        **frozen_validation_fields(),
        "schema": "fre.aot.rebar-runner.v2",
        "disposition": "executed",
        "configured": "true",
        "adapter": "general-aot-linked-native-grep-count-reducer-prepared-v3-required-ordered-nfa-v15",
        "model": "grep",
        "benchmark": "synthetic/prepared-grep",
        "source_commit": "1" * 40,
        "source_tree": "2" * 40,
        "target": "aarch64-linux",
        "feature_bits": "0000000100000000",
        "compiler_version": "1",
        "optimizer_version": "1",
        "engine": "OrderedNfa",
        "aggregate_strategy": "Some(NativeOrderedNfaFused)",
        "prepared_bulk_strategy": "Some(NativeOrderedNfaLoop)",
        "span_iteration_strategy": "not-applicable",
        "grep_iteration_strategy": "linked-native-grep-count-reducer-v1",
        "shared_ordered_many": "false",
        "source_pattern_count": "1",
        "ordered_many_receipt_schema": "0",
        "ordered_many_sources_sha256": "0" * 64,
        "prepare_config_version": "3",
        "prepare_operation_flags": "0000000000000002",
        "required_prepare_capabilities": "0000000000000001",
        "prepare_scope": "runtime-handle-state",
        "object_descriptor_setup": "authenticated-v3-when-required",
        "max_start_filter_setup_work": "100000000",
        "max_grep_count_workspace_bytes": "67108864",
        "max_handle_bytes": "8388608",
        "max_ordered_nfa_scratch_bytes": "8388608",
        "max_ordered_nfa_setup_work": "2000000",
        "program_sha256": "3" * 64,
        "object_sha256": "4" * 64,
        "program_symbol": (
            f"fre_aot_regex_runtime_program_v1_{native_identity}"
        ),
        "program_len": "4096",
        "entry_symbol": f"fre_aot_regex_search_v1_{native_identity}",
        "reducer_symbol": (
            f"fre_aot_regex_grep_count_exclusive_v1_{aggregate_identity}"
        ),
        "span_fill_symbol": (
            f"fre_aot_regex_fill_spans_exclusive_v1_{native_identity}"
        ),
        "required_runtime_symbols": ",".join(
            CENSUS.PREPARED_V15_SCALAR_GREP_RUNTIME_SYMBOLS
        ),
        "boundary": "runtime-klv-warmup-schedule",
        "required_comparators": "rust-regex-1.12.4,fre-current-runtime",
    }


def direct_scalar_grep_provenance_fields() -> dict[str, str]:
    fields = prepared_scalar_grep_provenance_fields()
    aggregate_identity = "e" * 64
    fields.update({
        "adapter": "general-aot-linked-native-grep-count-reducer-prepared-v2",
        "engine": "OrderedContextDfa",
        "aggregate_strategy": "Some(NativeFused)",
        "prepared_bulk_strategy": "None",
        "grep_iteration_strategy": "linked-native-grep-count-reducer-v1",
        "prepare_config_version": "2",
        "prepare_operation_flags": "0000000000000008",
        "required_prepare_capabilities": "0000000000000000",
        "max_handle_bytes": "0",
        "max_ordered_nfa_scratch_bytes": "0",
        "max_ordered_nfa_setup_work": "0",
        "program_symbol": (
            f"fre_aot_regex_runtime_program_v1_{aggregate_identity}"
        ),
        "span_fill_symbol": "",
        "required_runtime_symbols": "",
    })
    return fields


def scalar_native_reducer_provenance_fields(
    model: str = "count", ordered: bool = False,
) -> dict[str, str]:
    fields = prepared_scalar_grep_provenance_fields()
    entry_identity = "d" * 64
    program_identity = "e" * 64
    reducer_identity = "f" * 64
    if model == "count":
        direct_adapter = "general-aot-identity-suffixed-exclusive-count-prepared-v2"
        ordered_adapter = (
            "general-aot-identity-suffixed-exclusive-count-prepared-v3-required-ordered-nfa-v15"
        )
        reducer = f"fre_aot_regex_count_exclusive_v1_{reducer_identity}"
        operation_flags = CENSUS.PREPARED_V15_SPAN_OPERATION_FLAGS
        runtime_symbols = CENSUS.PREPARED_V15_SHARED_COUNT_RUNTIME_SYMBOLS
        span_iteration = "not-applicable"
    elif model == "count-spans":
        direct_adapter = "general-aot-linked-complete-spans-prepared-v2"
        ordered_adapter = (
            "general-aot-linked-complete-spans-prepared-v3-required-ordered-nfa-v15"
        )
        reducer = f"fre_aot_regex_span_sum_exclusive_v1_{reducer_identity}"
        operation_flags = CENSUS.PREPARED_V15_SPAN_SUM_OPERATION_FLAGS
        runtime_symbols = CENSUS.PREPARED_V15_SHARED_SPAN_SUM_RUNTIME_SYMBOLS
        span_iteration = CENSUS.NATIVE_SPAN_SUM_ITERATION_STRATEGY
    else:
        raise AssertionError(f"unsupported synthetic scalar reducer model {model!r}")
    fields.update({
        "adapter": ordered_adapter if ordered else direct_adapter,
        "model": model,
        "benchmark": f"synthetic/native-{model}",
        "engine": "OrderedNfa" if ordered else "OrderedContextDfa",
        "aggregate_strategy": (
            "Some(NativeOrderedNfaFused)" if ordered else "Some(NativeFused)"
        ),
        "prepared_bulk_strategy": (
            "Some(NativeOrderedNfaLoop)" if ordered else "None"
        ),
        "span_iteration_strategy": span_iteration,
        "grep_iteration_strategy": "not-applicable",
        "prepare_config_version": (
            str(CENSUS.PREPARED_V15_CONFIG_VERSION)
            if ordered else str(CENSUS.PREPARED_V2_CONFIG_VERSION)
        ),
        "prepare_operation_flags": f"{operation_flags:016x}",
        "required_prepare_capabilities": (
            f"{CENSUS.PREPARED_V15_CAPABILITY:016x}"
            if ordered else "0000000000000000"
        ),
        "max_handle_bytes": (
            str(CENSUS.PREPARED_V15_MAX_HANDLE_BYTES) if ordered else "0"
        ),
        "max_ordered_nfa_scratch_bytes": (
            str(CENSUS.PREPARED_V15_MAX_SCRATCH_BYTES) if ordered else "0"
        ),
        "max_ordered_nfa_setup_work": (
            str(CENSUS.PREPARED_V15_MAX_SETUP_WORK) if ordered else "0"
        ),
        "program_symbol": (
            f"fre_aot_regex_runtime_program_v1_{program_identity}"
        ),
        "program_len": "512",
        "entry_symbol": f"fre_aot_regex_search_v1_{entry_identity}",
        "reducer_symbol": reducer,
        "span_fill_symbol": (
            f"fre_aot_regex_fill_spans_exclusive_v1_{entry_identity}"
            if ordered else ""
        ),
        "required_runtime_symbols": (
            ",".join(runtime_symbols) if ordered else ""
        ),
        "boundary": "runtime-klv-warmup-schedule",
    })
    return fields


def native_uniform_capture_provenance_fields(
    model: str = "grep-captures", ordered: bool = False,
) -> dict[str, str]:
    fields = prepared_scalar_grep_provenance_fields()
    entry_identity = "d" * 64
    program_identity = "e" * 64
    reducer_identity = "f" * 64
    if model == "count-captures":
        adapter = "general-aot-native-uniform-capture-count-reducer-v1"
        reducer = (
            f"fre_aot_regex_count_captures_exclusive_v1_{reducer_identity}"
        )
        grep_iteration = "not-applicable"
    elif model == "grep-captures":
        adapter = "general-aot-native-uniform-capture-grep-reducer-v1"
        reducer = (
            f"fre_aot_regex_grep_captures_exclusive_v1_{reducer_identity}"
        )
        grep_iteration = "linked-native-uniform-capture-reducer-v1"
    else:
        raise AssertionError(f"unsupported synthetic capture model {model!r}")
    fields.update({
        "adapter": adapter,
        "model": model,
        "benchmark": f"synthetic/native-uniform-{model}",
        "engine": "OrderedNfa" if ordered else "OrderedDfa",
        "aggregate_strategy": (
            "Some(NativeOrderedNfaFused)" if ordered else "Some(NativeFused)"
        ),
        "prepared_bulk_strategy": (
            "Some(NativeOrderedNfaLoop)" if ordered else "None"
        ),
        "span_iteration_strategy": "not-applicable",
        "grep_iteration_strategy": grep_iteration,
        "prepare_config_version": (
            str(CENSUS.PREPARED_V15_CONFIG_VERSION) if ordered else "2"
        ),
        "prepare_operation_flags": "0000000000000002",
        "required_prepare_capabilities": (
            f"{CENSUS.PREPARED_V15_CAPABILITY:016x}"
            if ordered else "0000000000000000"
        ),
        "max_handle_bytes": (
            str(CENSUS.PREPARED_V15_MAX_HANDLE_BYTES) if ordered else "0"
        ),
        "max_ordered_nfa_scratch_bytes": (
            str(CENSUS.PREPARED_V15_MAX_SCRATCH_BYTES) if ordered else "0"
        ),
        "max_ordered_nfa_setup_work": (
            str(CENSUS.PREPARED_V15_MAX_SETUP_WORK) if ordered else "0"
        ),
        "program_symbol": (
            f"fre_aot_regex_runtime_program_v1_{program_identity}"
        ),
        "program_len": "512",
        "entry_symbol": f"fre_aot_regex_search_v1_{entry_identity}",
        "reducer_symbol": reducer,
        "span_fill_symbol": (
            f"fre_aot_regex_fill_spans_exclusive_v1_{entry_identity}"
            if ordered else ""
        ),
        "required_runtime_symbols": (
            ",".join(CENSUS.PREPARED_V15_SHARED_COUNT_RUNTIME_SYMBOLS)
            if ordered else ""
        ),
        "boundary": (
            "single-call-native-uniform-capture-helper-backed-reducer"
            if ordered else "single-call-native-uniform-capture-reducer"
        ),
    })
    return fields


def shared_ordered_many_provenance_fields(
    model: str = "count",
    native_fused: bool = False,
) -> dict[str, str]:
    native_identity = "a" * 64
    aggregate_identity = "b" * 64
    if model == "count":
        adapter = "general-aot-shared-ordered-many-native-count-v1"
        reducer = f"fre_aot_regex_count_exclusive_v1_{aggregate_identity}"
        operation_flags = CENSUS.PREPARED_V15_SPAN_OPERATION_FLAGS
        runtime_symbols = CENSUS.PREPARED_V15_SHARED_COUNT_RUNTIME_SYMBOLS
        span_iteration = "not-applicable"
    elif model == "count-spans":
        adapter = "general-aot-shared-ordered-many-native-span-sum-v1"
        reducer = f"fre_aot_regex_span_sum_exclusive_v1_{aggregate_identity}"
        operation_flags = CENSUS.PREPARED_V15_SPAN_SUM_OPERATION_FLAGS
        runtime_symbols = CENSUS.PREPARED_V15_SHARED_SPAN_SUM_RUNTIME_SYMBOLS
        span_iteration = (
            "linked-shared-ordered-many-native-span-sum-reducer-v1"
        )
    else:
        raise AssertionError(f"unsupported synthetic shared model {model!r}")
    if native_fused:
        engine = "OrderedDfa"
        aggregate_strategy = "Some(NativeFused)"
        prepared_bulk_strategy = "None"
        prepare_config_version = CENSUS.PREPARED_V2_CONFIG_VERSION
        required_prepare_capabilities = 0
        max_handle_bytes = 0
        max_scratch_bytes = 0
        max_setup_work = 0
        span_fill_symbol = ""
        runtime_symbols = ()
        boundary = (
            "single-call-shared-ordered-many-helper-free-native-reducer"
        )
    else:
        engine = "OrderedNfa"
        aggregate_strategy = "Some(NativeOrderedNfaFused)"
        prepared_bulk_strategy = "Some(NativeOrderedNfaLoop)"
        prepare_config_version = CENSUS.PREPARED_V15_CONFIG_VERSION
        required_prepare_capabilities = CENSUS.PREPARED_V15_CAPABILITY
        max_handle_bytes = CENSUS.PREPARED_V15_MAX_HANDLE_BYTES
        max_scratch_bytes = CENSUS.PREPARED_V15_MAX_SCRATCH_BYTES
        max_setup_work = CENSUS.PREPARED_V15_MAX_SETUP_WORK
        span_fill_symbol = (
            f"fre_aot_regex_fill_spans_exclusive_v1_{native_identity}"
        )
        boundary = "single-call-shared-ordered-many-helper-backed-reducer"
    return {
        **frozen_validation_fields(),
        "schema": "fre.aot.rebar-runner.v2",
        "disposition": "executed",
        "configured": "true",
        "adapter": adapter,
        "model": model,
        "benchmark": f"synthetic/shared-{model}",
        "source_commit": "1" * 40,
        "source_tree": "2" * 40,
        "target": "aarch64-linux",
        "feature_bits": "0000000100000000",
        "compiler_version": "1",
        "optimizer_version": "1",
        "engine": engine,
        "aggregate_strategy": aggregate_strategy,
        "prepared_bulk_strategy": prepared_bulk_strategy,
        "span_iteration_strategy": span_iteration,
        "grep_iteration_strategy": "not-applicable",
        "shared_ordered_many": "true",
        "source_pattern_count": "3",
        "ordered_many_receipt_schema": str(CENSUS.ORDERED_MANY_RECEIPT_VERSION),
        "ordered_many_sources_sha256": "c" * 64,
        "prepare_config_version": str(prepare_config_version),
        "prepare_operation_flags": f"{operation_flags:016x}",
        "required_prepare_capabilities": (
            f"{required_prepare_capabilities:016x}"
        ),
        "prepare_scope": "runtime-handle-state",
        "object_descriptor_setup": "authenticated-v3-when-required",
        "max_start_filter_setup_work": "100000000",
        "max_grep_count_workspace_bytes": "67108864",
        "max_handle_bytes": str(max_handle_bytes),
        "max_ordered_nfa_scratch_bytes": str(max_scratch_bytes),
        "max_ordered_nfa_setup_work": str(max_setup_work),
        "program_sha256": "d" * 64,
        "object_sha256": "e" * 64,
        "program_symbol": (
            f"fre_aot_regex_runtime_program_v1_{native_identity}"
        ),
        "program_len": "4096",
        "entry_symbol": f"fre_aot_regex_search_v1_{native_identity}",
        "reducer_symbol": reducer,
        "span_fill_symbol": span_fill_symbol,
        "required_runtime_symbols": ",".join(runtime_symbols),
        "boundary": boundary,
        "required_comparators": "rust-regex-1.12.4,fre-current-runtime",
    }


def mixed_prepared_grep_provenance_fields() -> dict[str, str]:
    ordinary_identity = "a" * 64
    prepared_identity = "b" * 64
    fields = {
        **frozen_validation_fields(),
        "schema": "fre.aot.rebar-runner.v3",
        "disposition": "executed",
        "configured": "true",
        "adapter": "general-aot-native-row-bridge-grep-mixed-prepared-ordered-nfa-v15-v1",
        "model": "grep",
        "benchmark": "synthetic/mixed-prepared-grep",
        "source_commit": "1" * 40,
        "source_tree": "2" * 40,
        "target": "aarch64-linux",
        "feature_bits": "0000000100000000",
        "compiler_version": "1",
        "optimizer_version": "1",
        "engine": "IndependentNativeSpanRows(OrderedDfa,OrderedNfa)",
        "aggregate_strategy": (
            "per-line-native-independent-span-row-exists-mixed-prepared-v15-v1"
        ),
        "native_row_bridge": "true",
        "uniform_capture_bridge": "false",
        "source_pattern_count": "2",
        "row_total_object_bytes": "8192",
        "source_to_artifact": "0,1",
        "component_count": "2",
        "prepare_max_handle_bytes": "8388608",
        "prepare_max_scratch_bytes": "8388608",
        "prepare_max_setup_work": "2000000",
        "boundary": "complete-native-row-bridge",
        "required_comparators": "rust-regex-1.12.4,fre-current-runtime",
    }
    fields.update({
        "component_0_native": "true",
        "component_0_source_ordinal": "0",
        "component_0_entry_symbol": (
            f"fre_aot_regex_search_v1_{ordinary_identity}"
        ),
        "component_0_runtime_symbols": "",
        "component_0_required_prepare_capabilities": "0000000000000000",
        "component_0_prepare_config_version": "0",
        "component_0_prepare_operation_flags": "0000000000000000",
        "component_0_runtime_program_symbol": "",
        "component_0_runtime_program_len": "0",
        "component_0_span_fill_symbol": "",
        "component_0_prepared_bulk_strategy": "None",
        "component_0_automaton_sha256": "1" * 64,
        "component_0_program_sha256": "2" * 64,
        "component_0_object_sha256": "3" * 64,
        "component_1_native": "true",
        "component_1_source_ordinal": "1",
        "component_1_entry_symbol": (
            f"fre_aot_regex_search_exclusive_v1_{prepared_identity}"
        ),
        "component_1_runtime_symbols": ",".join(
            CENSUS.PREPARED_V15_RUNTIME_SYMBOLS
        ),
        "component_1_required_prepare_capabilities": "0000000000000001",
        "component_1_prepare_config_version": "3",
        "component_1_prepare_operation_flags": "0000000000000002",
        "component_1_runtime_program_symbol": (
            f"fre_aot_regex_runtime_program_v1_{prepared_identity}"
        ),
        "component_1_runtime_program_len": "4096",
        "component_1_span_fill_symbol": (
            f"fre_aot_regex_fill_spans_exclusive_v1_{prepared_identity}"
        ),
        "component_1_prepared_bulk_strategy": "Some(NativeOrderedNfaLoop)",
        "component_1_automaton_sha256": "4" * 64,
        "component_1_program_sha256": "5" * 64,
        "component_1_object_sha256": "6" * 64,
    })
    return fields


def synthetic_uniform_capture_qualification_receipt(
    plan: dict[str, object]
) -> dict[str, object]:
    receipt = copy.deepcopy(synthetic_qualification_receipt(plan))
    receipt.pop("receipt_sha256")
    job = plan["jobs"][33]
    fields = uniform_capture_provenance_fields()
    encoded = " ".join(f"{key}={value}" for key, value in fields.items()).encode()
    provenance = CENSUS.provenance_receipt(CENSUS.parse_provenance(encoded))
    entry = fields["component_0_entry_symbol"]
    receipt["job"] = {
        "job_id": job["job_id"],
        "point_ids": job["point_ids"],
        "model": job["model"],
        "input": job["input"],
        "candidate_klv": job["candidate_klv"],
    }
    artifact = {
        "runner_sha256": "e" * 64,
        "objects": [{"ordinal": 0, "sha256": "c" * 64, "bytes": 123}],
    }
    receipt["artifacts"] = {
        "primary": artifact,
        "replica": artifact,
        "reproducible": True,
        "compiled_artifact_present": True,
        "runtime_execution_authenticated_separately": True,
        "provenance": provenance,
    }
    receipt["route"]["operation_entry_symbols"] = [entry]
    receipt["route"]["operation_entry_symbols_sha256"] = CENSUS.sha_bytes(
        CENSUS.canonical([entry]).encode()
    )
    receipt["route"]["adapter_route"] = (
        "linked-uniform-capture-row-adapter-loop"
    )
    negative = receipt["phases"]["claimed_entry_negative_traps"][0]
    negative["symbol"] = entry
    negative["marker"]["armed"][0]["symbol"] = entry
    negative["marker"]["triggered"] = entry
    receipt["classification"] = CENSUS.classification_from_qualification_evidence(
        True,
        [entry],
        receipt["route"]["adapter_route"],
        [],
        receipt["phases"],
        "aarch64",
    )
    return CENSUS.add_digest(receipt, "receipt_sha256")


def participation_capture_provenance_fields() -> dict[str, str]:
    selector = f"fre_aot_regex_search_v1_{'a' * 64}"
    export_identity = CENSUS.participation_export_identity(
        "6" * 64,
        "aarch64-linux",
        "0000000100000000",
        "5" * 64,
        selector,
    )
    entry = f"fre_aot_regex_participation_exact_v1_{export_identity}"
    bundle = f"fre_aot_regex_participation_bundle_v1_{export_identity}"
    return {
        **frozen_validation_fields(),
        "schema": "fre.aot.rebar-runner.v4",
        "disposition": "executed",
        "configured": "true",
        "adapter": "general-aot-native-exact-span-participation-count-v1",
        "model": "count-captures",
        "benchmark": "runtime-job-000",
        "source_commit": "1" * 40,
        "source_tree": "2" * 40,
        "target": "aarch64-linux",
        "feature_bits": "0000000100000000",
        "compiler_version": "1",
        "optimizer_version": "1",
        "engine": "NativeExactSpanParticipationDfaV1",
        "aggregate_strategy": "native-exact-span-participation-dfa-v1",
        "native_row_bridge": "true",
        "uniform_capture_bridge": "false",
        "strict_capture_bridge": "false",
        "participation_capture_bridge": "true",
        "source_pattern_count": "1",
        "row_total_object_bytes": "123",
        "source_to_artifact": "0",
        "component_count": "1",
        "component_0_native": "true",
        "component_0_source_ordinal": "0",
        "component_0_entry_symbol": selector,
        "component_0_runtime_symbols": "",
        "component_0_program_sha256": "3" * 64,
        "component_0_object_sha256": "4" * 64,
        "capture_resolution": "native-exact-span-participation-dfa-v1",
        "capture_group_count": "3",
        "participation_algorithm_id": (
            "fre-aot-regex.exact-span-participation-dfa.v1"
        ),
        "participation_strategy": "2",
        "participation_semantic_runtime_calls": "0",
        "participation_assertions": "0",
        "participation_assertion_signatures": "1",
        "participation_byte_classes": "8",
        "participation_dfa_states": "17",
        "participation_transition_cells": "136",
        "participation_build_work": "999",
        "participation_scratch_bytes": "16",
        "participation_plan_bytes": "1093",
        "capture_source_sha256": "1" * 64,
        "capture_selector_sha256": "2" * 64,
        "capture_program_sha256": "3" * 64,
        "selector_object_sha256": "5" * 64,
        "participation_bundle_sha256": "6" * 64,
        "participation_export_identity_sha256": export_identity,
        "participation_object_sha256": "4" * 64,
        "capture_artifact_identity_sha256": "7" * 64,
        "participation_bundle_symbol": bundle,
        "capture_selector_symbol": selector,
        "participation_entry_symbol": entry,
        "boundary": (
            "native-span-selector-with-helper-free-exact-span-participation-replay"
        ),
        "required_comparators": "rust-regex-1.12.4,fre-current-runtime",
    }


def synthetic_participation_capture_qualification_receipt(
    plan: dict[str, object]
) -> dict[str, object]:
    receipt = copy.deepcopy(synthetic_qualification_receipt(plan))
    receipt.pop("receipt_sha256")
    job = plan["jobs"][33]
    fields = participation_capture_provenance_fields()
    encoded = " ".join(f"{key}={value}" for key, value in fields.items()).encode()
    provenance = CENSUS.provenance_receipt(CENSUS.parse_provenance(encoded))
    selector = fields["component_0_entry_symbol"]
    participation = fields["participation_entry_symbol"]
    entries = [selector, participation]
    receipt["job"] = {
        "job_id": job["job_id"],
        "point_ids": job["point_ids"],
        "model": job["model"],
        "input": job["input"],
        "candidate_klv": job["candidate_klv"],
    }
    artifact = {
        "runner_sha256": "8" * 64,
        "objects": [{"ordinal": 0, "sha256": "4" * 64, "bytes": 123}],
    }
    receipt["artifacts"] = {
        "primary": artifact,
        "replica": artifact,
        "reproducible": True,
        "compiled_artifact_present": True,
        "runtime_execution_authenticated_separately": True,
        "provenance": provenance,
    }
    receipt["route"]["operation_entry_symbols"] = entries
    receipt["route"]["operation_entry_symbols_sha256"] = CENSUS.sha_bytes(
        CENSUS.canonical(entries).encode()
    )
    receipt["route"]["adapter_route"] = (
        "linked-exact-span-participation-adapter-loop"
    )
    first = receipt["phases"]["claimed_entry_negative_traps"][0]
    first["symbol"] = selector
    first["marker"]["armed"][0]["symbol"] = selector
    first["marker"]["triggered"] = selector
    second = copy.deepcopy(first)
    second["ordinal"] = 1
    second["symbol"] = participation
    second["marker"]["armed"][0]["symbol"] = participation
    second["marker"]["triggered"] = participation
    receipt["phases"]["claimed_entry_negative_traps"].append(second)
    receipt["classification"] = CENSUS.classification_from_qualification_evidence(
        True,
        entries,
        receipt["route"]["adapter_route"],
        [],
        receipt["phases"],
        "aarch64",
    )
    return CENSUS.add_digest(receipt, "receipt_sha256")


def selector_capture_fallback_provenance_fields() -> dict[str, str]:
    selector = f"fre_aot_regex_search_v1_{'a' * 64}"
    return {
        **frozen_validation_fields(),
        "schema": "fre.aot.rebar-runner.v4",
        "disposition": "executed",
        "configured": "true",
        "adapter": (
            "general-aot-native-selector-negative-certificate-stock-positive-capture-fallback-v1"
        ),
        "model": "grep-captures",
        "benchmark": "runtime-job-002",
        "source_commit": "1" * 40,
        "source_tree": "2" * 40,
        "target": "aarch64-linux",
        "feature_bits": "0000000100000000",
        "compiler_version": "1",
        "optimizer_version": "1",
        "engine": "IndependentNativeSpanRows(OrderedContextDfa)",
        "aggregate_strategy": (
            "native-selector-negative-certificate-with-stock-positive-capture-fallback-v1"
        ),
        "native_row_bridge": "true",
        "uniform_capture_bridge": "false",
        "strict_capture_bridge": "false",
        "participation_capture_bridge": "false",
        "selector_capture_fallback_bridge": "true",
        "source_pattern_count": "1",
        "row_total_object_bytes": "123",
        "source_to_artifact": "0",
        "component_count": "1",
        "component_0_native": "true",
        "component_0_source_ordinal": "0",
        "component_0_entry_symbol": selector,
        "component_0_runtime_symbols": "",
        "component_0_program_sha256": "3" * 64,
        "component_0_object_sha256": "4" * 64,
        "capture_resolution": (
            "native-selector-negative-certificate-with-stock-positive-capture-fallback-v1"
        ),
        "positive_fallback_profile": "rust-regex-1.12.4-captures",
        "positive_fallback_symbol": (
            "fre_aot_rebar_runner_stock_capture_positive_fallback_v1"
        ),
        "direct_participation_resource": "DfaStates",
        "direct_participation_required": "131073",
        "direct_participation_limit": "131072",
        "boundary": (
            "per-line-native-span-negative-certificate-with-trap-visible-stock-positive-capture-fallback"
        ),
        "required_comparators": "rust-regex-1.12.4,fre-current-runtime",
    }


def synthetic_selector_capture_fallback_qualification_receipt(
    plan: dict[str, object]
) -> dict[str, object]:
    receipt = copy.deepcopy(synthetic_qualification_receipt(plan))
    receipt.pop("receipt_sha256")
    job = plan["jobs"][35]
    fields = selector_capture_fallback_provenance_fields()
    encoded = " ".join(f"{key}={value}" for key, value in fields.items()).encode()
    provenance = CENSUS.provenance_receipt(CENSUS.parse_provenance(encoded))
    selector = fields["component_0_entry_symbol"]
    fallback = fields["positive_fallback_symbol"]
    receipt["job"] = {
        "job_id": job["job_id"],
        "point_ids": job["point_ids"],
        "model": job["model"],
        "input": job["input"],
        "candidate_klv": job["candidate_klv"],
    }
    artifact = {
        "runner_sha256": "8" * 64,
        "objects": [{"ordinal": 0, "sha256": "4" * 64, "bytes": 123}],
    }
    receipt["artifacts"] = {
        "primary": artifact,
        "replica": artifact,
        "reproducible": True,
        "compiled_artifact_present": True,
        "runtime_execution_authenticated_separately": True,
        "provenance": provenance,
    }
    receipt["route"]["operation_entry_symbols"] = [selector]
    receipt["route"]["operation_entry_symbols_sha256"] = CENSUS.sha_bytes(
        CENSUS.canonical([selector]).encode()
    )
    receipt["route"]["adapter_route"] = (
        "linked-selector-negative-certificate-adapter-loop"
    )
    receipt["route"]["semantic_helper_symbols"] = [fallback]
    receipt["route"]["semantic_helper_symbols_sha256"] = CENSUS.sha_bytes(
        CENSUS.canonical([fallback]).encode()
    )
    negative = receipt["phases"]["claimed_entry_negative_traps"][0]
    negative["symbol"] = selector
    negative["marker"]["armed"][0]["symbol"] = selector
    negative["marker"]["triggered"] = selector
    helper = receipt["phases"]["semantic_helper_trap"]
    helper["process"]["outcome"] = "exit"
    helper["process"]["returncode"] = 0
    helper["marker"] = {
        "status": "valid",
        "sha256": "f" * 64,
        "kind": "semantic-helpers",
        "architecture": "aarch64",
        "installed": 1,
        "expected": 1,
        "armed": [{
            "symbol": fallback,
            "offset": "0x200",
            "before": "fd7bbfa9",
            "after": "000020d4",
        }],
        "triggered": None,
        "completed": "normal",
    }
    receipt["classification"] = CENSUS.classification_from_qualification_evidence(
        True,
        [selector],
        receipt["route"]["adapter_route"],
        [fallback],
        receipt["phases"],
        "aarch64",
    )
    return CENSUS.add_digest(receipt, "receipt_sha256")


def strict_capture_provenance_fields() -> dict[str, str]:
    next_symbol = f"fre_aot_regex_capture_next_v1_{'a' * 64}"
    return {
        **frozen_validation_fields(),
        "schema": "fre.aot.rebar-runner.v4",
        "disposition": "executed",
        "configured": "true",
        "adapter": "general-aot-native-single-capture-next-count-v1",
        "model": "count-captures",
        "benchmark": "runtime-job-000",
        "source_commit": "1" * 40,
        "source_tree": "2" * 40,
        "target": "aarch64-linux",
        "feature_bits": "0000000100000000",
        "compiler_version": "1",
        "optimizer_version": "1",
        "engine": "NativeOnePassCaptureV1",
        "aggregate_strategy": "native-single-capture-next-participation-v1",
        "native_row_bridge": "true",
        "uniform_capture_bridge": "false",
        "strict_capture_bridge": "true",
        "source_pattern_count": "1",
        "row_total_object_bytes": "123",
        "source_to_artifact": "0",
        "component_count": "1",
        "component_0_native": "true",
        "component_0_source_ordinal": "0",
        "component_0_entry_symbol": next_symbol,
        "component_0_runtime_symbols": "",
        "component_0_program_sha256": "3" * 64,
        "component_0_object_sha256": "4" * 64,
        "capture_resolution": "native-onepass-capture-next-v1",
        "capture_group_count": "3",
        "capture_can_match_empty": "false",
        "capture_source_sha256": "1" * 64,
        "capture_selector_sha256": "2" * 64,
        "capture_program_sha256": "3" * 64,
        "capture_plan_sha256": "5" * 64,
        "capture_bundle_sha256": "6" * 64,
        "capture_artifact_identity_sha256": "7" * 64,
        "capture_materialize_symbol": (
            f"fre_aot_regex_capture_materialize_v1_{'b' * 64}"
        ),
        "capture_selector_symbol": f"fre_aot_regex_search_v1_{'c' * 64}",
        "boundary": (
            "native-search-core-with-native-capture-materialization-adapter-loop"
        ),
        "required_comparators": "rust-regex-1.12.4,fre-current-runtime",
    }


def synthetic_strict_capture_qualification_receipt(
    plan: dict[str, object]
) -> dict[str, object]:
    receipt = copy.deepcopy(synthetic_qualification_receipt(plan))
    receipt.pop("receipt_sha256")
    job = plan["jobs"][33]
    fields = strict_capture_provenance_fields()
    encoded = " ".join(f"{key}={value}" for key, value in fields.items()).encode()
    provenance = CENSUS.provenance_receipt(CENSUS.parse_provenance(encoded))
    entry = fields["component_0_entry_symbol"]
    receipt["job"] = {
        "job_id": job["job_id"],
        "point_ids": job["point_ids"],
        "model": job["model"],
        "input": job["input"],
        "candidate_klv": job["candidate_klv"],
    }
    artifact = {
        "runner_sha256": "8" * 64,
        "objects": [{"ordinal": 0, "sha256": "4" * 64, "bytes": 123}],
    }
    receipt["artifacts"] = {
        "primary": artifact,
        "replica": artifact,
        "reproducible": True,
        "compiled_artifact_present": True,
        "runtime_execution_authenticated_separately": True,
        "provenance": provenance,
    }
    receipt["route"]["operation_entry_symbols"] = [entry]
    receipt["route"]["operation_entry_symbols_sha256"] = CENSUS.sha_bytes(
        CENSUS.canonical([entry]).encode()
    )
    receipt["route"]["adapter_route"] = "linked-strict-capture-next-adapter-loop"
    negative = receipt["phases"]["claimed_entry_negative_traps"][0]
    negative["symbol"] = entry
    negative["marker"]["armed"][0]["symbol"] = entry
    negative["marker"]["triggered"] = entry
    receipt["classification"] = CENSUS.classification_from_qualification_evidence(
        True,
        [entry],
        receipt["route"]["adapter_route"],
        [],
        receipt["phases"],
        "aarch64",
    )
    return CENSUS.add_digest(receipt, "receipt_sha256")


def single_capture_reducer_provenance_fields(
    source_route: str = "exact-span-participation-v1",
    model: str = "count-captures",
) -> dict[str, str]:
    if model == "count-captures":
        operation = "count-captures"
        domain = "whole-haystack"
        benchmark = "runtime-job-000"
        reducer = f"fre_aot_regex_count_captures_v1_{'e' * 64}"
    elif model == "grep-captures":
        operation = "grep-captures"
        domain = "byte-slice-lines-lf-crlf"
        benchmark = "runtime-job-002"
        reducer = f"fre_aot_regex_grep_captures_v1_{'e' * 64}"
    else:
        raise AssertionError(f"unsupported synthetic capture reducer model {model!r}")
    if source_route == "exact-span-participation-v1":
        adapter = {
            "count-captures": (
                "general-aot-native-exact-span-participation-count-reducer-v1"
            ),
            "grep-captures": (
                "general-aot-native-exact-span-participation-grep-reducer-v1"
            ),
        }[model]
        engine = "NativeExactSpanParticipationDfaV1"
        aggregate = (
            "native-exact-span-participation-whole-operation-reducer-v1"
        )
        private = (16, 0, 0, 0)
    elif source_route == "capture-next-v1":
        adapter = {
            "count-captures": (
                "general-aot-native-single-capture-next-count-reducer-v1"
            ),
            "grep-captures": (
                "general-aot-native-single-capture-next-grep-reducer-v1"
            ),
        }[model]
        engine = "NativeOnePassCaptureV1"
        aggregate = "native-single-capture-next-whole-operation-reducer-v1"
        private = (0, 24, 3, 48)
    else:
        raise AssertionError(f"unsupported synthetic reducer source route {source_route!r}")
    fields = {
        **frozen_validation_fields(),
        "schema": "fre.aot.rebar-runner.v5",
        "disposition": "executed",
        "configured": "true",
        "adapter": adapter,
        "model": model,
        "benchmark": benchmark,
        "source_commit": "1" * 40,
        "source_tree": "2" * 40,
        "target": "aarch64-linux",
        "feature_bits": "0000000100000000",
        "compiler_version": "1",
        "optimizer_version": "1",
        "engine": engine,
        "aggregate_strategy": aggregate,
        "native_row_bridge": "false",
        "capture_reducer_bridge": "true",
        "source_pattern_count": "1",
        "operation": operation,
        "domain": domain,
        "source_route": source_route,
        "source_cardinality": "1",
        "source_bytes": "4",
        "source_pattern_sha256": "4" * 64,
        "source_sha256": "1" * 64,
        "group_count": "3",
        "can_match_empty": "false",
        "empty_progress": "byte",
        "semantic_runtime_calls": "0",
        "private_participation_scratch_bytes": str(private[0]),
        "private_iterator_state_bytes": str(private[1]),
        "private_result_slot_count": str(private[2]),
        "private_result_slot_bytes": str(private[3]),
        "selector_sha256": "2" * 64,
        "capture_sha256": "3" * 64,
        "source_artifact_identity_sha256": "7" * 64,
        "source_object_sha256": "c" * 64,
        "reducer_symbol": reducer,
        "reducer_symbol_sha256": CENSUS.sha_bytes(reducer.encode()),
        "object_sha256": "d" * 64,
        "object_bytes": "123",
        "max_object_bytes": str(CENSUS.MAX_NATIVE_ROW_OBJECT_BYTES),
        "artifact_identity_sha256": "f" * 64,
        "required_runtime_symbols": "",
        "operation_entry_symbol": reducer,
        "boundary": (
            "single-call-helper-free-single-capture-whole-operation-reducer"
        ),
        "required_comparators": "rust-regex-1.12.4,fre-current-runtime",
    }
    if source_route == "exact-span-participation-v1":
        selector = f"fre_aot_regex_search_v1_{'a' * 64}"
        export_identity = CENSUS.participation_export_identity(
            "6" * 64,
            fields["target"],
            fields["feature_bits"],
            "5" * 64,
            selector,
        )
        fields.update({
            "participation_algorithm_id": (
                "fre-aot-regex.exact-span-participation-dfa.v1"
            ),
            "participation_strategy": "2",
            "participation_assertions": "0",
            "participation_assertion_signatures": "1",
            "participation_byte_classes": "8",
            "participation_dfa_states": "17",
            "participation_transition_cells": "136",
            "participation_build_work": "999",
            "participation_scratch_bytes": "16",
            "participation_plan_bytes": str(
                CENSUS.participation_plan_bytes(0, 1, 17, 136)
            ),
            "participation_selector_object_sha256": "5" * 64,
            "participation_bundle_sha256": "6" * 64,
            "participation_export_identity_sha256": export_identity,
            "participation_bundle_symbol": (
                f"fre_aot_regex_participation_bundle_v1_{export_identity}"
            ),
            "participation_selector_symbol": selector,
            "participation_entry_symbol": (
                f"fre_aot_regex_participation_exact_v1_{export_identity}"
            ),
        })
    else:
        fields.update({
            "capture_plan_sha256": "5" * 64,
            "capture_bundle_sha256": "6" * 64,
            "capture_next_symbol": f"fre_aot_regex_capture_next_v1_{'a' * 64}",
            "capture_materialize_symbol": (
                f"fre_aot_regex_capture_materialize_v1_{'b' * 64}"
            ),
            "capture_selector_symbol": f"fre_aot_regex_search_v1_{'c' * 64}",
        })
    return fields


def synthetic_single_capture_reducer_qualification_receipt(
    plan: dict[str, object],
    source_route: str = "exact-span-participation-v1",
    model: str = "count-captures",
) -> dict[str, object]:
    receipt = copy.deepcopy(synthetic_qualification_receipt(plan))
    receipt.pop("receipt_sha256")
    job = plan["jobs"][33 if model == "count-captures" else 35]
    fields = single_capture_reducer_provenance_fields(source_route, model)
    encoded = " ".join(f"{key}={value}" for key, value in fields.items()).encode()
    parsed = CENSUS.parse_provenance(encoded)
    provenance = CENSUS.provenance_receipt(parsed)
    reducer = fields["reducer_symbol"]
    receipt["job"] = {
        "job_id": job["job_id"],
        "point_ids": job["point_ids"],
        "model": job["model"],
        "input": job["input"],
        "candidate_klv": job["candidate_klv"],
    }
    artifact = {
        "runner_sha256": "8" * 64,
        "objects": [{"ordinal": 0, "sha256": "d" * 64, "bytes": 123}],
    }
    receipt["artifacts"] = {
        "primary": artifact,
        "replica": artifact,
        "reproducible": True,
        "compiled_artifact_present": True,
        "runtime_execution_authenticated_separately": True,
        "provenance": provenance,
    }
    receipt["route"]["operation_entry_symbols"] = [reducer]
    receipt["route"]["operation_entry_symbols_sha256"] = CENSUS.sha_bytes(
        CENSUS.canonical([reducer]).encode()
    )
    receipt["route"]["adapter_route"] = "linked-native-single-capture-reducer"
    negative = receipt["phases"]["claimed_entry_negative_traps"][0]
    negative["symbol"] = reducer
    negative["marker"]["armed"][0]["symbol"] = reducer
    negative["marker"]["triggered"] = reducer
    receipt["classification"] = CENSUS.classification_from_qualification_evidence(
        True,
        [reducer],
        receipt["route"]["adapter_route"],
        [],
        receipt["phases"],
        "aarch64",
    )
    return CENSUS.add_digest(receipt, "receipt_sha256")


class TrueNativeCensusTests(unittest.TestCase):
    def test_exact_adapter_includes_ordered_many_grep_and_uniform_capture_rows(self) -> None:
        self.assertTrue(CENSUS.has_exact_adapter("count", 1))
        self.assertTrue(CENSUS.has_exact_adapter("count", 3))
        self.assertFalse(
            CENSUS.has_exact_adapter("count", CENSUS.MAX_NATIVE_ROW_COMPONENTS + 1)
        )
        self.assertTrue(CENSUS.has_exact_adapter("count-spans", 2))
        self.assertTrue(CENSUS.has_exact_adapter("grep", 1))
        self.assertTrue(CENSUS.has_exact_adapter("grep", 2))
        self.assertTrue(
            CENSUS.has_exact_adapter("grep", CENSUS.MAX_NATIVE_ROW_COMPONENTS)
        )
        self.assertFalse(
            CENSUS.has_exact_adapter("grep", CENSUS.MAX_NATIVE_ROW_COMPONENTS + 1)
        )
        self.assertEqual(
            CENSUS.exact_adapter_reason("grep", 2),
            "exact-native-row-composite-adapter",
        )
        for model in ("count-captures", "grep-captures"):
            self.assertFalse(CENSUS.has_exact_adapter(model, 0))
            self.assertTrue(CENSUS.has_exact_adapter(model, 1))
            self.assertTrue(
                CENSUS.has_exact_adapter(model, CENSUS.MAX_NATIVE_ROW_COMPONENTS)
            )
            self.assertFalse(
                CENSUS.has_exact_adapter(
                    model, CENSUS.MAX_NATIVE_ROW_COMPONENTS + 1
                )
            )
        self.assertTrue(CENSUS.has_exact_adapter("regex-redux", 0))
        self.assertFalse(CENSUS.has_exact_adapter("regex-redux", 1))
        self.assertFalse(CENSUS.has_exact_adapter("compile", 1))

    def test_json_schema_names_uniform_capture_proof_and_automaton_surface(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        definitions = schema["$defs"]
        self.assertIn("validation", definitions["provenance"]["required"])
        self.assertEqual(
            definitions["frozenValidation"]["properties"]["authority"]["const"],
            "frozen-public-schedule-v1",
        )
        self.assertIn(
            "automaton_sha256",
            definitions["componentProvenance"]["required"],
        )
        self.assertIn(
            "uniform-capture-row-bridge-v1",
            definitions["provenance"]["properties"]["composite_kind"]["enum"],
        )
        self.assertIn("uniform_capture", definitions["provenance"]["required"])
        proof = definitions["uniformCaptureProvenance"]
        self.assertFalse(proof["additionalProperties"])
        self.assertEqual(
            proof["properties"]["capture_resolution"]["const"],
            "static-uniform-multiplier",
        )
        strict = definitions["strictCaptureProvenance"]
        self.assertFalse(strict["additionalProperties"])
        self.assertIn("capture_next_symbol", strict["required"])
        self.assertIn(
            "strict-capture-v4",
            definitions["provenance"]["properties"]["kind"]["enum"],
        )
        self.assertIn(
            "strict-capture-next-v1",
            definitions["provenance"]["properties"]["composite_kind"]["enum"],
        )
        participation = definitions["participationCaptureProvenance"]
        self.assertFalse(participation["additionalProperties"])
        self.assertIn("participation_entry_symbol", participation["required"])
        self.assertEqual(
            participation["properties"]["participation_semantic_runtime_calls"]["const"],
            0,
        )
        self.assertIn(
            "participation-capture-v4",
            definitions["provenance"]["properties"]["kind"]["enum"],
        )
        reducer = definitions["captureReducerProvenance"]
        self.assertFalse(reducer["additionalProperties"])
        self.assertIn("source_pattern_sha256", reducer["required"])
        self.assertIn("source_object_sha256", reducer["required"])
        self.assertIn("object_sha256", reducer["required"])
        self.assertIn("participation_source", reducer["required"])
        self.assertIn("capture_next_source", reducer["required"])
        self.assertIn(
            "single-capture-reducer-v5",
            definitions["provenance"]["properties"]["kind"]["enum"],
        )
        self.assertIn(
            "single-capture-whole-operation-reducer-v1",
            definitions["provenance"]["properties"]["composite_kind"]["enum"],
        )
        self.assertIn(
            "exact-span-participation-v1",
            definitions["provenance"]["properties"]["composite_kind"]["enum"],
        )
        selector_fallback = definitions["selectorCaptureFallbackProvenance"]
        self.assertFalse(selector_fallback["additionalProperties"])
        self.assertEqual(
            selector_fallback["properties"]["positive_fallback_symbol"]["const"],
            "fre_aot_rebar_runner_stock_capture_positive_fallback_v1",
        )
        self.assertIn(
            "selector-capture-fallback-v4",
            definitions["provenance"]["properties"]["kind"]["enum"],
        )
        self.assertIn(
            "runtime_program_len",
            definitions["preparedGrepV15Provenance"]["required"],
        )
        scalar_reducer = definitions["scalarNativeReducerProvenance"]
        self.assertFalse(scalar_reducer["additionalProperties"])
        self.assertEqual(
            scalar_reducer["properties"]["route_variant"]["enum"],
            ["direct-v2", "ordered-v15"],
        )
        self.assertEqual(
            definitions["provenance"]["properties"]["scalar_native_reducer"],
            {"$ref": "#/$defs/scalarNativeReducerProvenance"},
        )
        self.assertTrue(any(
            condition.get("then", {}).get("required")
            == ["scalar_native_reducer"]
            for condition in definitions["provenance"]["allOf"]
        ))
        self.assertIn(
            "prepared_v15",
            definitions["componentProvenance"]["properties"],
        )
        shared = definitions["sharedOrderedManyProvenance"]
        self.assertFalse(shared["additionalProperties"])
        self.assertIn("ordered_sources_sha256", shared["required"])
        self.assertIn("shared_ordered_many", definitions["provenance"]["required"])
        self.assertIn(
            "shared-ordered-many-v2",
            definitions["provenance"]["properties"]["kind"]["enum"],
        )

    def test_formal_provenance_requires_closed_frozen_schedule_authority(self) -> None:
        fields = prepared_scalar_grep_provenance_fields()
        encoded = " ".join(f"{key}={value}" for key, value in fields.items()).encode()
        parsed = CENSUS.parse_provenance(encoded)
        provenance = CENSUS.provenance_receipt(parsed)
        self.assertEqual(
            provenance["validation"]["authority"],
            "frozen-public-schedule-v1",
        )
        for field, value in (
            ("validation_authority", "stock-rust-unsealed-v1"),
            ("expected_value_sealed", "false"),
            ("schedule_klv_sha256", "0" * 64),
            ("schedule_binding_sha256", "0" * 64),
            ("stock_divergence_policy", "fatal"),
        ):
            with self.subTest(field=field):
                poisoned = copy.deepcopy(fields)
                poisoned[field] = value
                poisoned_encoded = " ".join(
                    f"{key}={item}" for key, item in poisoned.items()
                ).encode()
                with self.assertRaises(CENSUS.CensusError):
                    CENSUS.parse_provenance(poisoned_encoded)
        missing = copy.deepcopy(fields)
        missing.pop("expected_comparator")
        with self.assertRaises(CENSUS.CensusError):
            CENSUS.parse_provenance(
                " ".join(f"{key}={value}" for key, value in missing.items()).encode()
            )
        normalized = copy.deepcopy(provenance)
        normalized["validation"]["schedule_binding_sha256"] = "0" * 64
        with self.assertRaises(CENSUS.CensusError):
            CENSUS.validate_provenance_record(normalized, "tampered frozen binding")

    def test_frozen_job_expectation_prefers_re2_and_rejects_conflicts(self) -> None:
        plan = synthetic_plan()
        job = plan["jobs"][33]
        original = next(
            point for point in plan["points"]
            if point["point_id"] == job["point_ids"][0]
        )
        re2 = copy.deepcopy(original)
        re2["point_id"] = "point-re2-replica"
        re2["comparator"] = "re2-2025-11-05"
        plan["points"].append(re2)
        job["point_ids"].append(re2["point_id"])
        self.assertEqual(
            CENSUS.frozen_job_expectation(plan, job),
            (1, "re2-2025-11-05"),
        )
        re2["expected"] = 2
        with self.assertRaisesRegex(CENSUS.CensusError, "conflicting"):
            CENSUS.frozen_job_expectation(plan, job)

    def test_denominator_set_is_sorted_unique_and_hashed(self) -> None:
        receipt = CENSUS.id_set(["b", "a"])
        self.assertEqual(receipt["count"], 2)
        self.assertEqual(receipt["ids"], ["a", "b"])
        self.assertEqual(
            receipt["ids_sha256"],
            CENSUS.sha_bytes(CENSUS.canonical(["a", "b"]).encode()),
        )
        with self.assertRaises(CENSUS.CensusError):
            CENSUS.id_set(["same", "same"])

    def test_final_binary_inventory_traps_unknown_future_semantic_helpers(self) -> None:
        nm = """
0000000000001000 T fre_aot_regex_runtime_prepare_exclusive_v3
0000000000001010 T fre_aot_regex_runtime_destroy_exclusive_v1
0000000000001020 T fre_aot_regex_runtime_search_exclusive_v1
0000000000001030 W fre_aot_regex_runtime_future_capture_replay_v9
0000000000001038 t fre_aot_regex_runtime_hidden_local_v1
                 U fre_aot_regex_runtime_future_shared_v1
0000000000001040 D fre_aot_regex_runtime_program_v1_deadbeef
0000000000001050 T fre_aot_regex_count_exclusive_v1_deadbeef
"""
        symbols = CENSUS.nm_runtime_references(nm)
        self.assertEqual(
            CENSUS.semantic_helper_symbols(symbols),
            [
                "fre_aot_regex_runtime_future_capture_replay_v9",
                "fre_aot_regex_runtime_future_shared_v1",
                "fre_aot_regex_runtime_hidden_local_v1",
                "fre_aot_regex_runtime_search_exclusive_v1",
            ],
        )
        self.assertNotIn(
            "fre_aot_regex_runtime_future_shared_v1", CENSUS.nm_text_symbols(nm)
        )
        self.assertIn(
            "fre_aot_regex_runtime_program_v1_deadbeef",
            CENSUS.nm_defined_symbols(nm),
        )

    def test_macho_leading_underscore_is_normalized(self) -> None:
        symbols = CENSUS.nm_text_symbols(
            "0000000100001000 T _fre_aot_regex_runtime_search_v1\n"
            "0000000100002000 T "
            "_fre_aot_rebar_runner_stock_capture_positive_fallback_v1\n"
        )
        self.assertIn("fre_aot_regex_runtime_search_v1", symbols)
        self.assertIn(
            "fre_aot_rebar_runner_stock_capture_positive_fallback_v1", symbols
        )

    def test_operation_entry_is_the_actual_adapter_boundary(self) -> None:
        count = scalar_native_reducer_provenance_fields("count", ordered=False)
        common = {
            "reducer_symbol": "fre_aot_regex_count_exclusive_v1_deadbeef",
            "span_fill_symbol": "",
            "entry_symbol": "fre_aot_regex_search_v1_deadbeef",
        }
        self.assertEqual(
            CENSUS.selected_operation_entries(count),
            ([count["reducer_symbol"]], "linked-reducer"),
        )
        self.assertEqual(
            CENSUS.selected_operation_entries({**common, "model": "count-spans"}),
            ([common["entry_symbol"]], "linked-direct-entry-adapter-loop"),
        )
        fill = "fre_aot_regex_fill_spans_exclusive_v1_deadbeef"
        self.assertEqual(
            CENSUS.selected_operation_entries(
                {**common, "model": "count-spans", "span_fill_symbol": fill}
            ),
            ([fill], "linked-span-fill"),
        )

    def test_every_operation_route_has_a_closed_boundary_classification(self) -> None:
        expected = {
            "linked-reducer": (
                False, True, "whole-operation-native-authenticated"
            ),
            "linked-span-sum-reducer": (
                False, True, "whole-operation-native-authenticated"
            ),
            "linked-native-count-helper-backed-reducer": (
                False,
                False,
                "single-call-native-reducer-retains-semantic-runtime-helpers",
            ),
            "linked-native-span-sum-helper-backed-reducer": (
                False,
                False,
                "single-call-native-reducer-retains-semantic-runtime-helpers",
            ),
            "linked-native-grep-count-reducer": (
                False, True, "whole-operation-native-authenticated"
            ),
            "linked-native-uniform-capture-reducer": (
                False, True, "whole-operation-native-authenticated"
            ),
            "linked-native-single-capture-reducer": (
                False, True, "whole-operation-native-authenticated"
            ),
            "linked-native-uniform-capture-helper-backed-reducer": (
                False,
                False,
                "single-call-native-reducer-retains-semantic-runtime-helpers",
            ),
            "linked-span-fill": (
                True,
                False,
                "native-span-fill-core-with-checked-rust-reduction-adapter-loop",
            ),
            "linked-direct-entry-adapter-loop": (
                True, False, "native-search-core-with-adapter-outer-loop"
            ),
            "linked-prepared-span-fill-grep-adapter-loop": (
                True,
                False,
                "native-prepared-span-fill-core-with-per-line-adapter-loop",
            ),
            "linked-native-regex-redux-reducer": (
                False, True, "whole-operation-native-authenticated"
            ),
            "linked-native-row-adapter-loop": (
                True, False, "native-search-core-with-adapter-outer-loop"
            ),
            "linked-uniform-capture-row-adapter-loop": (
                True,
                False,
                "native-search-core-with-static-uniform-capture-adapter-loop",
            ),
            "linked-exact-span-participation-adapter-loop": (
                True,
                False,
                "native-search-capture-core-with-exact-span-replay-adapter-loop",
            ),
            "linked-strict-capture-next-adapter-loop": (
                True,
                False,
                "native-search-capture-core-with-checked-rust-adapter-loop",
            ),
            "linked-selector-negative-certificate-adapter-loop": (
                True,
                False,
                "native-negative-certificate-with-unused-stock-capture-fallback",
            ),
            "linked-shared-ordered-many-helper-backed-reducer": (
                False,
                False,
                "single-call-native-reducer-retains-semantic-runtime-helpers",
            ),
            "linked-shared-ordered-many-helper-free-reducer": (
                False,
                True,
                "whole-operation-native-authenticated",
            ),
        }
        self.assertEqual(set(CENSUS.OPERATION_ROUTE_POLICIES), set(expected))
        receipt = synthetic_qualification_receipt(synthetic_plan())
        entries = receipt["route"]["operation_entry_symbols"]
        phases = receipt["phases"]
        for route, (adapter, whole, reason) in expected.items():
            with self.subTest(route=route):
                classification = CENSUS.classification_from_qualification_evidence(
                    True, entries, route, [], phases, "aarch64"
                )
                self.assertTrue(
                    classification["native_search_core_authenticated"]
                )
                self.assertEqual(classification["adapter_outer_loop"], adapter)
                self.assertEqual(
                    classification["whole_operation_native_authenticated"], whole
                )
                self.assertEqual(classification["reason"], reason)

    def test_span_fill_is_a_checked_rust_reduction_adapter(self) -> None:
        receipt = synthetic_qualification_receipt(synthetic_plan())
        classification = CENSUS.classification_from_qualification_evidence(
            True,
            receipt["route"]["operation_entry_symbols"],
            "linked-span-fill",
            [],
            receipt["phases"],
            "aarch64",
        )
        self.assertTrue(classification["native_search_core_authenticated"])
        self.assertTrue(classification["adapter_outer_loop"])
        self.assertFalse(
            classification["whole_operation_native_authenticated"]
        )

    def test_unknown_operation_route_fails_closed_even_with_adapter_suffix(self) -> None:
        receipt = synthetic_qualification_receipt(synthetic_plan())
        with self.assertRaisesRegex(CENSUS.CensusError, "unknown operation route"):
            CENSUS.classification_from_qualification_evidence(
                True,
                receipt["route"]["operation_entry_symbols"],
                "linked-future-native-adapter-loop",
                [],
                receipt["phases"],
                "aarch64",
            )

    def test_scalar_native_reducer_selector_closes_direct_and_ordered_routes(self) -> None:
        expected_routes = {
            ("count", False): "linked-reducer",
            ("count", True): "linked-native-count-helper-backed-reducer",
            ("count-spans", False): "linked-span-sum-reducer",
            ("count-spans", True): (
                "linked-native-span-sum-helper-backed-reducer"
            ),
        }
        for (model, ordered), route in expected_routes.items():
            with self.subTest(model=model, ordered=ordered):
                fields = scalar_native_reducer_provenance_fields(model, ordered)
                encoded = " ".join(
                    f"{key}={value}" for key, value in fields.items()
                ).encode()
                parsed = CENSUS.parse_provenance(encoded)
                self.assertEqual(
                    CENSUS.selected_operation_entries(parsed),
                    ([fields["reducer_symbol"]], route),
                )
                provenance = CENSUS.provenance_receipt(parsed)
                CENSUS.validate_provenance_record(
                    provenance, f"synthetic scalar {model} reducer"
                )
                self.assertEqual(
                    CENSUS.operation_route_from_provenance_record(provenance),
                    ([fields["reducer_symbol"]], route),
                )
                proof = provenance["scalar_native_reducer"]
                self.assertEqual(
                    proof["route_variant"],
                    "ordered-v15" if ordered else "direct-v2",
                )
                self.assertEqual(
                    CENSUS.OPERATION_ROUTE_POLICIES[route].boundary,
                    CENSUS.OperationBoundary.SEMANTIC_HELPER_BACKED
                    if ordered else CENSUS.OperationBoundary.WHOLE_OPERATION,
                )
                expected_helpers = (
                    list(
                        CENSUS.PREPARED_V15_SHARED_COUNT_RUNTIME_SYMBOLS
                        if model == "count"
                        else CENSUS.PREPARED_V15_SHARED_SPAN_SUM_RUNTIME_SYMBOLS
                    )
                    if ordered else []
                )
                self.assertEqual(
                    CENSUS.declared_runtime_symbols_from_provenance(provenance),
                    expected_helpers,
                )

    def test_scalar_native_reducer_selector_rejects_poisoned_envelopes(self) -> None:
        helper = "fre_aot_regex_runtime_future_v1"
        for model in ("count", "count-spans"):
            direct = scalar_native_reducer_provenance_fields(model, ordered=False)
            direct_poisons = {
                "runtime-symbol": {"required_runtime_symbols": helper},
                "prepare-capability": {
                    "required_prepare_capabilities": "0000000000000001"
                },
                "prepared-bulk": {
                    "prepared_bulk_strategy": "Some(NativePreparedLoop)"
                },
                "mixed-aggregate": {
                    "aggregate_strategy": "Some(NativeFusedWithRuntimeHelper)"
                },
                "unknown-aggregate": {
                    "aggregate_strategy": "Some(FutureNativeFused)"
                },
            }
            for poison, updates in direct_poisons.items():
                with self.subTest(model=model, variant="raw-direct", poison=poison):
                    poisoned = {**direct, **updates}
                    with self.assertRaises(CENSUS.CensusError):
                        CENSUS.selected_operation_entries(poisoned)

            ordered = scalar_native_reducer_provenance_fields(model, ordered=True)
            ordered_helpers = ordered["required_runtime_symbols"].split(",")
            ordered_poisons = {
                "runtime-symbol": {
                    "required_runtime_symbols": ",".join(ordered_helpers[:-1])
                },
                "prepare-capability": {
                    "required_prepare_capabilities": "0000000000000000"
                },
                "prepared-bulk": {"prepared_bulk_strategy": "None"},
                "engine": {"engine": "OrderedContextDfa"},
                "mixed-aggregate": {
                    "aggregate_strategy": (
                        "Some(NativeOrderedNfaFusedWithRuntimeHelper)"
                    )
                },
                "unknown-aggregate": {
                    "aggregate_strategy": "Some(FutureNativeOrderedNfaFused)"
                },
            }
            for poison, updates in ordered_poisons.items():
                with self.subTest(model=model, variant="raw-ordered", poison=poison):
                    poisoned = {**ordered, **updates}
                    with self.assertRaises(CENSUS.CensusError):
                        CENSUS.selected_operation_entries(poisoned)

            for ordered_variant in (False, True):
                fields = scalar_native_reducer_provenance_fields(
                    model, ordered=ordered_variant
                )
                encoded = " ".join(
                    f"{key}={value}" for key, value in fields.items()
                ).encode()
                provenance = CENSUS.provenance_receipt(
                    CENSUS.parse_provenance(encoded)
                )
                normalized_poisons = []
                if ordered_variant:
                    normalized_poisons.extend([
                        ("runtime-symbol", ordered_helpers[:-1]),
                        ("prepare-capability", 0),
                        ("prepared-bulk", "None"),
                        ("engine", "OrderedContextDfa"),
                        (
                            "mixed-aggregate",
                            "Some(NativeOrderedNfaFusedWithRuntimeHelper)",
                        ),
                        (
                            "unknown-aggregate",
                            "Some(FutureNativeOrderedNfaFused)",
                        ),
                    ])
                else:
                    normalized_poisons.extend([
                        ("runtime-symbol", [helper]),
                        ("prepare-capability", 1),
                        ("prepared-bulk", "Some(NativePreparedLoop)"),
                        (
                            "mixed-aggregate",
                            "Some(NativeFusedWithRuntimeHelper)",
                        ),
                        ("unknown-aggregate", "Some(FutureNativeFused)"),
                    ])
                for poison, value in normalized_poisons:
                    with self.subTest(
                        model=model,
                        variant="normalized-ordered" if ordered_variant else "normalized-direct",
                        poison=poison,
                    ):
                        poisoned = copy.deepcopy(provenance)
                        if poison == "runtime-symbol":
                            poisoned["required_runtime_symbols"] = value
                        elif poison == "prepare-capability":
                            poisoned["scalar_native_reducer"][
                                "required_prepare_capabilities"
                            ] = value
                        elif poison == "prepared-bulk":
                            poisoned["prepared_bulk_strategy"] = value
                        elif poison == "engine":
                            poisoned["engine"] = value
                        else:
                            poisoned["aggregate_strategy"] = value
                        with self.assertRaises(CENSUS.CensusError):
                            CENSUS.operation_route_from_provenance_record(poisoned)

    def test_regex_redux_selects_only_the_whole_operation_reducer(self) -> None:
        fields = synthetic_regex_redux_fields()
        selected, route = CENSUS.selected_operation_entries(fields)
        self.assertEqual(route, "linked-native-regex-redux-reducer")
        self.assertEqual(selected, [fields["reducer_symbol"]])
        fields["semantic_runtime_symbols"] = "fre_aot_regex_runtime_search_v1"
        with self.assertRaisesRegex(CENSUS.CensusError, "semantic runtime helpers"):
            CENSUS.selected_operation_entries(fields)

    def test_regex_redux_zero_identity_and_reducer_digests_fail_closed(self) -> None:
        fields = synthetic_regex_redux_fields()
        zero = "0" * 64
        for name in (
            "operation_identity_sha256",
            "reducer_code_sha256",
            "reducer_data_sha256",
            "reducer_object_sha256",
        ):
            with self.subTest(layer="raw", field=name):
                poisoned = copy.deepcopy(fields)
                poisoned[name] = zero
                if name == "operation_identity_sha256":
                    poisoned["reducer_symbol"] = (
                        f"fre_aot_regex_rebar_regex_redux_v1_{zero}"
                    )
                with self.assertRaisesRegex(CENSUS.CensusError, "zero"):
                    CENSUS.selected_operation_entries(poisoned)

        components = CENSUS.components_from_provenance(fields)
        proof = CENSUS.regex_redux_proof_from_provenance(fields, components)
        provenance = {
            "components": components,
            "target": fields["target"],
            "reducer_symbol": fields["reducer_symbol"],
            "object_sha256": fields["reducer_object_sha256"],
        }
        CENSUS.validate_normalized_regex_redux(
            proof, provenance, "synthetic normalized regex-redux"
        )
        for name in (
            "operation_identity_sha256",
            "reducer_code_sha256",
            "reducer_data_sha256",
            "reducer_object_sha256",
        ):
            with self.subTest(layer="normalized", field=name):
                poisoned_proof = copy.deepcopy(proof)
                poisoned_provenance = copy.deepcopy(provenance)
                poisoned_proof[name] = zero
                if name == "operation_identity_sha256":
                    reducer = f"fre_aot_regex_rebar_regex_redux_v1_{zero}"
                    poisoned_proof["reducer_symbol"] = reducer
                    poisoned_provenance["reducer_symbol"] = reducer
                elif name == "reducer_object_sha256":
                    poisoned_provenance["object_sha256"] = zero
                with self.assertRaisesRegex(CENSUS.CensusError, "zero"):
                    CENSUS.validate_normalized_regex_redux(
                        poisoned_proof,
                        poisoned_provenance,
                        "synthetic normalized regex-redux",
                    )

        unsupported_proof = copy.deepcopy(proof)
        unsupported_proof["reducer_relocation_count"] = 0
        unsupported_provenance = copy.deepcopy(provenance)
        unsupported_provenance["target"] = "riscv64-unknown-linux-gnu"
        with self.assertRaisesRegex(CENSUS.CensusError, "relocation closure"):
            CENSUS.validate_normalized_regex_redux(
                unsupported_proof,
                unsupported_provenance,
                "synthetic normalized regex-redux",
            )

    def test_native_row_components_are_search_core_with_an_adapter_loop(self) -> None:
        fields = {
            "schema": "fre.aot.rebar-runner.v3",
            "model": "count-spans",
            "native_row_bridge": "true",
            "component_count": "2",
        }
        for index in range(2):
            fields[f"component_{index}_native"] = "true"
            fields[f"component_{index}_source_ordinal"] = str(index)
            fields[f"component_{index}_entry_symbol"] = (
                f"fre_aot_regex_search_v1_{index + 11:064x}"
            )
            fields[f"component_{index}_runtime_symbols"] = ""
            fields[f"component_{index}_required_prepare_capabilities"] = (
                "0000000000000000"
            )
            fields[f"component_{index}_prepare_config_version"] = "0"
            fields[f"component_{index}_prepare_operation_flags"] = (
                "0000000000000000"
            )
            fields[f"component_{index}_runtime_program_symbol"] = ""
            fields[f"component_{index}_runtime_program_len"] = "0"
            fields[f"component_{index}_span_fill_symbol"] = ""
            fields[f"component_{index}_prepared_bulk_strategy"] = "None"
            fields[f"component_{index}_automaton_sha256"] = f"{index + 9:064x}"
            fields[f"component_{index}_program_sha256"] = f"{index + 1:064x}"
            fields[f"component_{index}_object_sha256"] = f"{index + 3:064x}"
        self.assertEqual(
            CENSUS.selected_operation_entries(fields),
            (
                [
                    f"fre_aot_regex_search_v1_{index + 11:064x}"
                    for index in range(2)
                ],
                "linked-native-row-adapter-loop",
            ),
        )

    def test_native_row_v3_provenance_closes_and_seals_source_topology(self) -> None:
        fields = {
            **frozen_validation_fields(),
            "schema": "fre.aot.rebar-runner.v3",
            "disposition": "executed",
            "configured": "true",
            "adapter": "general-aot-native-row-bridge-count-v1",
            "model": "count",
            "benchmark": "synthetic/native-row",
            "source_commit": "1" * 40,
            "source_tree": "2" * 40,
            "target": "x86_64-linux",
            "feature_bits": "0000000000000000",
            "compiler_version": "1",
            "optimizer_version": "1",
            "engine": "IndependentNativeSpanRows(OrderedDfa,OrderedContextDfa)",
            "aggregate_strategy": "native-independent-span-row-selector-v1",
            "native_row_bridge": "true",
            "uniform_capture_bridge": "false",
            "source_pattern_count": "3",
            "row_total_object_bytes": "4096",
            "source_to_artifact": "0,1,0",
            "component_count": "2",
            "prepare_max_handle_bytes": "0",
            "prepare_max_scratch_bytes": "0",
            "prepare_max_setup_work": "0",
            "boundary": "complete-native-row-bridge",
            "required_comparators": "rust-regex-1.12.4,fre-current-runtime",
        }
        for index, source_ordinal in enumerate((0, 1)):
            fields[f"component_{index}_native"] = "true"
            fields[f"component_{index}_source_ordinal"] = str(source_ordinal)
            fields[f"component_{index}_entry_symbol"] = (
                f"fre_aot_regex_search_v1_{index + 11:064x}"
            )
            fields[f"component_{index}_runtime_symbols"] = ""
            fields[f"component_{index}_required_prepare_capabilities"] = (
                "0000000000000000"
            )
            fields[f"component_{index}_prepare_config_version"] = "0"
            fields[f"component_{index}_prepare_operation_flags"] = (
                "0000000000000000"
            )
            fields[f"component_{index}_runtime_program_symbol"] = ""
            fields[f"component_{index}_runtime_program_len"] = "0"
            fields[f"component_{index}_span_fill_symbol"] = ""
            fields[f"component_{index}_prepared_bulk_strategy"] = "None"
            fields[f"component_{index}_automaton_sha256"] = f"{index + 9:064x}"
            fields[f"component_{index}_program_sha256"] = f"{index + 1:064x}"
            fields[f"component_{index}_object_sha256"] = f"{index + 3:064x}"
        encoded = " ".join(f"{key}={value}" for key, value in fields.items()).encode()
        parsed = CENSUS.parse_provenance(encoded)
        self.assertEqual(parsed, fields)
        receipt = CENSUS.provenance_receipt(parsed)
        CENSUS.validate_provenance_record(receipt, "synthetic native row")
        self.assertEqual(receipt["composite_kind"], "native-row-bridge-v1")
        self.assertIsNone(receipt["uniform_capture"])
        self.assertEqual(receipt["source_pattern_count"], 3)
        self.assertEqual(receipt["source_to_artifact"], [0, 1, 0])
        self.assertIsNone(receipt["span_iteration_strategy"])
        self.assertIsNone(receipt["grep_iteration_strategy"])
        self.assertEqual(
            [component["source_ordinal"] for component in receipt["components"]],
            [0, 1],
        )
        with self.assertRaisesRegex(CENSUS.CensusError, "field closure differs"):
            CENSUS.parse_provenance(encoded + b" unsealed_field=1")

        grep_fields = dict(fields)
        grep_fields.update({
            "adapter": "general-aot-native-row-bridge-grep-v1",
            "model": "grep",
            "aggregate_strategy": "per-line-native-independent-span-row-exists-v1",
        })
        grep_encoded = " ".join(
            f"{key}={value}" for key, value in grep_fields.items()
        ).encode()
        grep_receipt = CENSUS.provenance_receipt(
            CENSUS.parse_provenance(grep_encoded)
        )
        CENSUS.validate_provenance_record(
            grep_receipt, "synthetic multi-pattern grep row"
        )
        self.assertEqual(
            grep_receipt["aggregate_strategy"],
            "per-line-native-independent-span-row-exists-v1",
        )
        self.assertIsNone(grep_receipt["span_iteration_strategy"])
        self.assertIsNone(grep_receipt["grep_iteration_strategy"])
        self.assertEqual(
            CENSUS.operation_route_from_provenance_record(grep_receipt),
            (
                [
                    f"fre_aot_regex_search_v1_{index + 11:064x}"
                    for index in range(2)
                ],
                "linked-native-row-adapter-loop",
            ),
        )

        poisoned_grep = dict(grep_fields)
        poisoned_grep["aggregate_strategy"] = "native-independent-span-row-selector-v1"
        with self.assertRaisesRegex(CENSUS.CensusError, "wrong typed route"):
            CENSUS.parse_provenance(
                " ".join(
                    f"{key}={value}" for key, value in poisoned_grep.items()
                ).encode()
            )

        missing_false = dict(fields)
        missing_false.pop("uniform_capture_bridge")
        with self.assertRaisesRegex(CENSUS.CensusError, "unknown native-row route"):
            CENSUS.parse_provenance(
                " ".join(
                    f"{key}={value}" for key, value in missing_false.items()
                ).encode()
            )

    def test_scalar_prepared_grep_v15_closes_route_caps_and_identities(self) -> None:
        fields = prepared_scalar_grep_provenance_fields()
        encoded = " ".join(f"{key}={value}" for key, value in fields.items()).encode()
        parsed = CENSUS.parse_provenance(encoded)
        receipt = CENSUS.provenance_receipt(parsed)
        CENSUS.validate_provenance_record(receipt, "synthetic prepared grep")
        self.assertEqual(receipt["kind"], "prepared-grep-v15-v2")
        self.assertEqual(receipt["prepared_grep_v15"]["runtime_program_len"], 4096)
        self.assertEqual(
            CENSUS.selected_operation_entries(parsed),
            ([fields["reducer_symbol"]], "linked-native-grep-count-reducer"),
        )
        self.assertEqual(
            CENSUS.operation_route_from_provenance_record(receipt),
            ([fields["reducer_symbol"]], "linked-native-grep-count-reducer"),
        )
        self.assertEqual(
            CENSUS.identity_defined_symbols_from_provenance(receipt),
            sorted([
                fields["entry_symbol"], fields["program_symbol"],
                fields["span_fill_symbol"],
            ]),
        )

        poisons = {
            "engine": "OrderedDfa",
            "max_handle_bytes": "8388607",
            "program_len": "0",
            "required_runtime_symbols": (
                fields["required_runtime_symbols"] + ",fre_aot_regex_runtime_future_v1"
            ),
            "program_symbol": (
                f"fre_aot_regex_runtime_program_v1_{'9' * 64}"
            ),
            "reducer_symbol": (
                f"fre_aot_regex_grep_count_exclusive_v1_{'d' * 64}"
            ),
        }
        for name, value in poisons.items():
            with self.subTest(name=name):
                poisoned = dict(fields)
                poisoned[name] = value
                with self.assertRaises(CENSUS.CensusError):
                    CENSUS.parse_provenance(
                        " ".join(
                            f"{key}={item}" for key, item in poisoned.items()
                        ).encode()
                    )

    def test_scalar_direct_grep_closes_whole_operation_reducer(self) -> None:
        fields = direct_scalar_grep_provenance_fields()
        encoded = " ".join(f"{key}={value}" for key, value in fields.items()).encode()
        parsed = CENSUS.parse_provenance(encoded)
        receipt = CENSUS.provenance_receipt(parsed)
        CENSUS.validate_provenance_record(receipt, "synthetic direct grep")
        self.assertEqual(receipt["kind"], "scalar-v2")
        self.assertEqual(
            CENSUS.selected_operation_entries(parsed),
            ([fields["reducer_symbol"]], "linked-native-grep-count-reducer"),
        )
        self.assertEqual(
            CENSUS.operation_route_from_provenance_record(receipt),
            ([fields["reducer_symbol"]], "linked-native-grep-count-reducer"),
        )
        self.assertEqual(
            CENSUS.identity_defined_symbols_from_provenance(receipt),
            sorted([fields["entry_symbol"], fields["program_symbol"]]),
        )
        for name, value in {
            "aggregate_strategy": "Some(RuntimeHelper)",
            "required_runtime_symbols": "fre_aot_regex_runtime_search_v1",
            "program_symbol": f"fre_aot_regex_runtime_program_v1_{'9' * 64}",
            "reducer_symbol": (
                f"fre_aot_regex_grep_count_exclusive_v1_{'d' * 64}"
            ),
            "malformed_reducer_symbol": "fre_aot_regex_grep_count_exclusive_v1_not-a-digest",
        }.items():
            with self.subTest(name=name):
                poisoned = dict(fields)
                poisoned[
                    "reducer_symbol" if name == "malformed_reducer_symbol" else name
                ] = value
                with self.assertRaises(CENSUS.CensusError):
                    CENSUS.parse_provenance(
                        " ".join(
                            f"{key}={item}" for key, item in poisoned.items()
                        ).encode()
                    )

    def test_native_uniform_capture_closes_single_call_route(self) -> None:
        for model in ("count-captures", "grep-captures"):
            for ordered in (False, True):
                with self.subTest(model=model, ordered=ordered):
                    fields = native_uniform_capture_provenance_fields(
                        model, ordered
                    )
                    parsed = CENSUS.parse_provenance(
                        " ".join(
                            f"{key}={value}" for key, value in fields.items()
                        ).encode()
                    )
                    receipt = CENSUS.provenance_receipt(parsed)
                    CENSUS.validate_provenance_record(
                        receipt, "synthetic native uniform capture"
                    )
                    route = (
                        "linked-native-uniform-capture-helper-backed-reducer"
                        if ordered
                        else "linked-native-uniform-capture-reducer"
                    )
                    self.assertEqual(receipt["kind"], "scalar-v2")
                    self.assertEqual(
                        receipt["uniform_capture"]["route_variant"],
                        "ordered-v15" if ordered else "direct-v1",
                    )
                    self.assertEqual(
                        CENSUS.selected_operation_entries(parsed),
                        ([fields["reducer_symbol"]], route),
                    )
                    self.assertEqual(
                        CENSUS.operation_route_from_provenance_record(receipt),
                        ([fields["reducer_symbol"]], route),
                    )
                    identity_symbols = [
                        fields["entry_symbol"], fields["program_symbol"]
                    ]
                    if ordered:
                        identity_symbols.append(fields["span_fill_symbol"])
                    self.assertEqual(
                        CENSUS.identity_defined_symbols_from_provenance(receipt),
                        sorted(identity_symbols),
                    )

        raw_poisons = {
            "adapter": "general-aot-native-uniform-capture-grep-reducer-v2",
            "boundary": "runtime-klv-warmup-schedule",
            "max_handle_bytes": "1",
            "required_runtime_symbols": "fre_aot_regex_runtime_search_v1",
            "reducer_symbol": (
                f"fre_aot_regex_grep_captures_exclusive_v1_{'0' * 63}g"
            ),
        }
        fields = native_uniform_capture_provenance_fields()
        for name, value in raw_poisons.items():
            with self.subTest(raw_poison=name):
                poisoned = dict(fields)
                poisoned[name] = value
                with self.assertRaises(CENSUS.CensusError):
                    CENSUS.parse_provenance(
                        " ".join(
                            f"{key}={item}" for key, item in poisoned.items()
                        ).encode()
                    )

        receipt = CENSUS.provenance_receipt(
            CENSUS.parse_provenance(
                " ".join(
                    f"{key}={value}" for key, value in fields.items()
                ).encode()
            )
        )
        for name, value in {
            "route_variant": "ordered-v15",
            "prepare_config_version": 3,
            "runtime_program_len": 0,
            "reducer_identity_sha256": "0" * 64,
        }.items():
            with self.subTest(receipt_poison=name):
                poisoned = dict(receipt)
                poisoned["uniform_capture"] = dict(receipt["uniform_capture"])
                poisoned["uniform_capture"][name] = value
                with self.assertRaises(CENSUS.CensusError):
                    CENSUS.validate_provenance_record(
                        poisoned, "poisoned native uniform capture"
                    )

    def test_shared_ordered_many_closes_one_reducer_route_and_receipt(self) -> None:
        for model in ("count", "count-spans"):
            for native_fused in (False, True):
                fields = shared_ordered_many_provenance_fields(
                    model, native_fused=native_fused
                )
                encoded = " ".join(
                    f"{key}={value}" for key, value in fields.items()
                ).encode()
                parsed = CENSUS.parse_provenance(encoded)
                receipt = CENSUS.provenance_receipt(parsed)
                CENSUS.validate_provenance_record(
                    receipt, f"synthetic shared {model}"
                )
                self.assertEqual(receipt["kind"], "shared-ordered-many-v2")
                self.assertEqual(
                    receipt["composite_kind"],
                    "shared-ordered-many-native-reducer-v1",
                )
                self.assertEqual(receipt["source_pattern_count"], 3)
                self.assertEqual(receipt["source_to_artifact"], [0, 0, 0])
                expected_route = (
                    "linked-shared-ordered-many-helper-free-reducer"
                    if native_fused
                    else "linked-shared-ordered-many-helper-backed-reducer"
                )
                self.assertEqual(
                    CENSUS.operation_route_from_provenance_record(receipt),
                    ([fields["reducer_symbol"]], expected_route),
                )
                identity_symbols = [
                    fields["entry_symbol"], fields["program_symbol"],
                ]
                if fields["span_fill_symbol"]:
                    identity_symbols.append(fields["span_fill_symbol"])
                self.assertEqual(
                    CENSUS.identity_defined_symbols_from_provenance(receipt),
                    sorted(identity_symbols),
                )
                helpers = CENSUS.semantic_helper_symbols(
                    set(receipt["required_runtime_symbols"])
                )
                if native_fused:
                    self.assertEqual(helpers, [])
                else:
                    # V15 remains subject to the independent semantic-helper
                    # trap even though its reducer is called only once.
                    self.assertTrue(helpers)
                    self.assertIn(
                        "fre_aot_regex_runtime_search_exclusive_v1", helpers
                    )

                synthetic = synthetic_qualification_receipt(synthetic_plan())
                classification = CENSUS.classification_from_qualification_evidence(
                    True,
                    synthetic["route"]["operation_entry_symbols"],
                    expected_route,
                    [],
                    synthetic["phases"],
                    "aarch64",
                )
                self.assertTrue(
                    classification["native_search_core_authenticated"]
                )
                self.assertFalse(classification["adapter_outer_loop"])
                self.assertEqual(
                    classification["whole_operation_native_authenticated"],
                    native_fused,
                )
                self.assertEqual(
                    classification["reason"],
                    (
                        "whole-operation-native-authenticated"
                        if native_fused
                        else "single-call-native-reducer-retains-semantic-runtime-helpers"
                    ),
                )

        fields = shared_ordered_many_provenance_fields("count")
        poisons = {
            "adapter": "general-aot-native-row-bridge-count-v1",
            "source_pattern_count": "1",
            "ordered_many_receipt_schema": "0",
            "ordered_many_sources_sha256": "0" * 64,
            "boundary": "runtime-klv-warmup-schedule",
            "required_runtime_symbols": "",
            "reducer_symbol": (
                f"fre_aot_regex_count_exclusive_v1_{'a' * 64}"
            ),
        }
        for name, value in poisons.items():
            with self.subTest(poison=name):
                poisoned = dict(fields)
                poisoned[name] = value
                with self.assertRaises(CENSUS.CensusError):
                    CENSUS.parse_provenance(
                        " ".join(
                            f"{key}={item}" for key, item in poisoned.items()
                        ).encode()
                    )

    def test_unknown_non_loop_route_cannot_claim_whole_operation_native(self) -> None:
        receipt = synthetic_qualification_receipt(synthetic_plan())
        with self.assertRaises(CENSUS.CensusError):
            CENSUS.classification_from_qualification_evidence(
                True,
                receipt["route"]["operation_entry_symbols"],
                "linked-native-grep-count-reducer-v2-unsealed",
                [],
                receipt["phases"],
                "aarch64",
            )

    def test_helper_free_shared_route_rejects_helpers_and_accepts_prepared_bulk(self) -> None:
        helper_free = shared_ordered_many_provenance_fields(
            "count", native_fused=True
        )
        helper_free["required_runtime_symbols"] = (
            "fre_aot_regex_runtime_search_v1"
        )
        with self.assertRaises(CENSUS.CensusError):
            CENSUS.parse_provenance(
                " ".join(
                    f"{key}={value}" for key, value in helper_free.items()
                ).encode()
            )

        prepared_helper_free = shared_ordered_many_provenance_fields(
            "count-spans", native_fused=True
        )
        prepared_helper_free["prepared_bulk_strategy"] = (
            "Some(NativePreparedLoop)"
        )
        prepared_helper_free["span_fill_symbol"] = (
            f"fre_aot_regex_fill_spans_exclusive_v1_{'a' * 64}"
        )
        prepared_receipt = CENSUS.provenance_receipt(
            CENSUS.parse_provenance(
                " ".join(
                    f"{key}={value}"
                    for key, value in prepared_helper_free.items()
                ).encode()
            )
        )
        CENSUS.validate_provenance_record(
            prepared_receipt, "synthetic prepared helper-free shared route"
        )

    def test_mixed_prepared_v15_rows_close_each_component_and_engine(self) -> None:
        fields = mixed_prepared_grep_provenance_fields()
        encoded = " ".join(f"{key}={value}" for key, value in fields.items()).encode()
        receipt = CENSUS.provenance_receipt(CENSUS.parse_provenance(encoded))
        CENSUS.validate_provenance_record(receipt, "synthetic mixed prepared grep")
        self.assertEqual(
            receipt["composite_kind"], "mixed-prepared-native-row-bridge-v15"
        )
        self.assertIsNone(receipt["components"][0]["prepared_v15"])
        self.assertEqual(
            receipt["components"][1]["prepared_v15"]["runtime_program_len"],
            4096,
        )
        self.assertEqual(
            CENSUS.operation_route_from_provenance_record(receipt),
            (
                [
                    fields["component_0_entry_symbol"],
                    fields["component_1_entry_symbol"],
                ],
                "linked-native-row-adapter-loop",
            ),
        )
        self.assertEqual(
            CENSUS.identity_defined_symbols_from_provenance(receipt),
            sorted([
                fields["component_1_runtime_program_symbol"],
                fields["component_1_span_fill_symbol"],
            ]),
        )

        poisons = {
            "engine": "IndependentNativeSpanRows(OrderedDfa,OrderedDfa)",
            "prepare_max_scratch_bytes": "8388607",
            "component_1_required_prepare_capabilities": "0000000000000002",
            "component_1_prepare_config_version": "2",
            "component_1_prepare_operation_flags": "0000000000000001",
            "component_1_runtime_program_len": "0",
            "component_1_runtime_symbols": (
                fields["component_1_runtime_symbols"]
                + ",fre_aot_regex_runtime_future_v1"
            ),
            "component_1_span_fill_symbol": (
                f"fre_aot_regex_fill_spans_exclusive_v1_{'8' * 64}"
            ),
        }
        for name, value in poisons.items():
            with self.subTest(name=name):
                poisoned = dict(fields)
                poisoned[name] = value
                with self.assertRaises(CENSUS.CensusError):
                    CENSUS.parse_provenance(
                        " ".join(
                            f"{key}={item}" for key, item in poisoned.items()
                        ).encode()
                    )

        normalized = copy.deepcopy(receipt)
        normalized["components"][0].pop("prepared_v15")
        with self.assertRaisesRegex(CENSUS.CensusError, "keys differ"):
            CENSUS.validate_provenance_record(normalized, "missing ordinary route marker")

    def test_uniform_capture_v3_seals_proof_lists_and_mapped_selector_digests(self) -> None:
        fields = uniform_capture_provenance_fields()
        fields.update({
            "engine": "IndependentNativeSpanRows(OrderedDfa,OrderedContextDfa)",
            "source_pattern_count": "3",
            "row_total_object_bytes": "246",
            "source_to_artifact": "0,1,0",
            "component_count": "2",
            "component_1_native": "true",
            "component_1_source_ordinal": "1",
            "component_1_entry_symbol": f"fre_aot_regex_search_v1_{'e' * 64}",
            "component_1_runtime_symbols": "",
            "component_1_required_prepare_capabilities": "0000000000000000",
            "component_1_prepare_config_version": "0",
            "component_1_prepare_operation_flags": "0000000000000000",
            "component_1_runtime_program_symbol": "",
            "component_1_runtime_program_len": "0",
            "component_1_span_fill_symbol": "",
            "component_1_prepared_bulk_strategy": "None",
            "component_1_automaton_sha256": "4" * 64,
            "component_1_program_sha256": "5" * 64,
            "component_1_object_sha256": "6" * 64,
            "source_participating_groups": "2,3,1",
            "source_minimum_match_bytes": "1,2,1",
            "source_capture_annotations": "1,2,0",
            "source_proof_work": "7,9,8",
            "source_proof_peak_stack_items": "3,4,2",
            "source_selector_automaton_sha256": (
                f"{'a' * 64},{'4' * 64},{'a' * 64}"
            ),
            "source_selector_program_sha256": (
                f"{'b' * 64},{'5' * 64},{'b' * 64}"
            ),
            "source_selector_object_sha256": (
                f"{'c' * 64},{'6' * 64},{'c' * 64}"
            ),
        })
        encoded = " ".join(f"{key}={value}" for key, value in fields.items()).encode()
        parsed = CENSUS.parse_provenance(encoded)
        receipt = CENSUS.provenance_receipt(parsed)
        CENSUS.validate_provenance_record(receipt, "synthetic uniform capture")
        self.assertEqual(
            receipt["composite_kind"], "uniform-capture-row-bridge-v1"
        )
        self.assertNotIn("strict_capture", receipt)
        self.assertEqual(
            receipt["uniform_capture"]["source_participating_groups"], [2, 3, 1]
        )
        self.assertEqual(
            CENSUS.operation_route_from_provenance_record(receipt),
            (
                [
                    fields["component_0_entry_symbol"],
                    fields["component_1_entry_symbol"],
                ],
                "linked-uniform-capture-row-adapter-loop",
            ),
        )

        wrong_digest = dict(fields)
        wrong_digest["source_selector_object_sha256"] = (
            f"{'c' * 64},{'c' * 64},{'c' * 64}"
        )
        with self.assertRaisesRegex(
            CENSUS.CensusError, "selector digests differ from its mapped component"
        ):
            CENSUS.parse_provenance(
                " ".join(
                    f"{key}={value}" for key, value in wrong_digest.items()
                ).encode()
            )

        missing_source = dict(fields)
        missing_source["source_participating_groups"] = ""
        with self.assertRaisesRegex(CENSUS.CensusError, "cardinality differs"):
            CENSUS.parse_provenance(
                " ".join(
                    f"{key}={value}" for key, value in missing_source.items()
                ).encode()
            )

        grep_fields = dict(fields)
        grep_fields["model"] = "grep-captures"
        grep_fields["adapter"] = (
            "general-aot-uniform-capture-native-row-grep-adapter-loop-v1"
        )
        grep_fields["benchmark"] = "synthetic/grep-captures"
        grep_parsed = CENSUS.parse_provenance(
            " ".join(
                f"{key}={value}" for key, value in grep_fields.items()
            ).encode()
        )
        CENSUS.validate_provenance_record(
            CENSUS.provenance_receipt(grep_parsed), "synthetic grep captures"
        )

    def test_uniform_capture_receipt_is_native_core_but_not_whole_operation(self) -> None:
        plan = synthetic_plan()
        receipt = synthetic_uniform_capture_qualification_receipt(plan)
        validated = CENSUS.validate_receipt(receipt, plan)
        self.assertTrue(
            validated["classification"]["native_search_core_authenticated"]
        )
        self.assertTrue(validated["classification"]["adapter_outer_loop"])
        self.assertFalse(
            validated["classification"]["whole_operation_native_authenticated"]
        )
        self.assertEqual(
            validated["classification"]["reason"],
            "native-search-core-with-static-uniform-capture-adapter-loop",
        )

    def test_single_capture_reducer_v5_is_whole_and_reducer_only(self) -> None:
        plan = synthetic_plan()
        for source_route in (
            "exact-span-participation-v1", "capture-next-v1"
        ):
            for model in ("count-captures", "grep-captures"):
                with self.subTest(source_route=source_route, model=model):
                    fields = single_capture_reducer_provenance_fields(
                        source_route, model
                    )
                    encoded = " ".join(
                        f"{key}={value}" for key, value in fields.items()
                    ).encode()
                    parsed = CENSUS.parse_provenance(encoded)
                    provenance = CENSUS.provenance_receipt(parsed)
                    CENSUS.validate_provenance_record(
                        provenance, "synthetic single-capture reducer"
                    )
                    reducer = fields["reducer_symbol"]
                    expected_route = (
                        [reducer], "linked-native-single-capture-reducer"
                    )
                    self.assertEqual(
                        CENSUS.selected_operation_entries(parsed), expected_route
                    )
                    self.assertEqual(
                        CENSUS.operation_route_from_provenance_record(provenance),
                        expected_route,
                    )
                    identity_symbols = (
                        CENSUS.identity_defined_symbols_from_provenance(provenance)
                    )
                    self.assertEqual(len(identity_symbols), 3)
                    self.assertNotIn(reducer, identity_symbols)
                    self.assertEqual(
                        CENSUS.authenticate_identity_defined_symbol_inventory(
                            provenance, set(identity_symbols), set(identity_symbols)
                        ),
                        identity_symbols,
                    )
                    with self.assertRaisesRegex(
                        CENSUS.CensusError, "identity symbols are absent"
                    ):
                        CENSUS.authenticate_identity_defined_symbol_inventory(
                            provenance,
                            set(identity_symbols[1:]),
                            set(identity_symbols),
                        )
                    receipt = synthetic_single_capture_reducer_qualification_receipt(
                        plan, source_route, model
                    )
                    validated = CENSUS.validate_receipt(receipt, plan)
                    self.assertEqual(
                        validated["route"]["operation_entry_symbols"], [reducer]
                    )
                    self.assertTrue(
                        validated["classification"][
                            "whole_operation_native_authenticated"
                        ]
                    )
                    self.assertFalse(
                        validated["classification"]["adapter_outer_loop"]
                    )
                    self.assertEqual(
                        validated["classification"]["reason"],
                        "whole-operation-native-authenticated",
                    )

    def test_single_capture_reducer_v5_fails_closed(self) -> None:
        base = single_capture_reducer_provenance_fields()

        def parse(fields: dict[str, str]) -> dict[str, str]:
            return CENSUS.parse_provenance(
                " ".join(f"{key}={value}" for key, value in fields.items()).encode()
            )

        mutations = []
        wrong_prefix = dict(base)
        wrong_prefix["reducer_symbol"] = (
            f"fre_aot_regex_count_captures_exclusive_v1_{'e' * 64}"
        )
        wrong_prefix["operation_entry_symbol"] = wrong_prefix["reducer_symbol"]
        wrong_prefix["reducer_symbol_sha256"] = CENSUS.sha_bytes(
            wrong_prefix["reducer_symbol"].encode()
        )
        mutations.append((wrong_prefix, "symbol is not canonical"))

        wrong_symbol_digest = dict(base)
        wrong_symbol_digest["reducer_symbol_sha256"] = "9" * 64
        mutations.append((wrong_symbol_digest, "symbol digest does not authenticate"))

        wrong_domain = dict(base)
        wrong_domain["domain"] = "byte-slice-lines-lf-crlf"
        mutations.append((wrong_domain, "operation/domain differs"))

        wrong_source_route = dict(base)
        wrong_source_route["source_route"] = "capture-next-v1"
        mutations.append((wrong_source_route, "private schema differs"))

        zero_source_receipt = dict(base)
        zero_source_receipt["source_sha256"] = "0" * 64
        mutations.append((zero_source_receipt, "zero SHA-256 digest"))

        aliased_source_digests = dict(base)
        aliased_source_digests["source_sha256"] = base["source_pattern_sha256"]
        mutations.append((aliased_source_digests, "digests are not distinct"))

        swapped_objects = dict(base)
        swapped_objects["source_object_sha256"] = base["object_sha256"]
        mutations.append((swapped_objects, "source and final objects are not distinct"))

        zero_identity = dict(base)
        zero_identity["artifact_identity_sha256"] = "0" * 64
        mutations.append((zero_identity, "zero SHA-256 digest"))

        reused_identity = dict(base)
        reused_identity["artifact_identity_sha256"] = base[
            "source_artifact_identity_sha256"
        ]
        mutations.append((reused_identity, "source and final identities are not distinct"))

        wrong_private = dict(base)
        wrong_private["private_iterator_state_bytes"] = "24"
        mutations.append((wrong_private, "private schema differs"))

        runtime_backed = dict(base)
        runtime_backed["required_runtime_symbols"] = (
            "fre_aot_regex_runtime_search_v1"
        )
        mutations.append((runtime_backed, "noncanonical route"))

        missing_child = dict(base)
        missing_child.pop("participation_entry_symbol")
        mutations.append((missing_child, "child symbols are not canonical"))

        for fields, message in mutations:
            with self.subTest(message=message):
                with self.assertRaisesRegex(CENSUS.CensusError, message):
                    parse(fields)

        plan = synthetic_plan()
        receipt = synthetic_single_capture_reducer_qualification_receipt(plan)

        source_object_substitution = copy.deepcopy(receipt)
        source_object_substitution.pop("receipt_sha256")
        for label in ("primary", "replica"):
            source_object_substitution["artifacts"][label]["objects"][0][
                "sha256"
            ] = base["source_object_sha256"]
        source_object_substitution = CENSUS.add_digest(
            source_object_substitution, "receipt_sha256"
        )
        with self.assertRaisesRegex(CENSUS.CensusError, "object files differ"):
            CENSUS.validate_receipt(source_object_substitution, plan)

        wrong_pattern_source = copy.deepcopy(receipt)
        wrong_pattern_source.pop("receipt_sha256")
        wrong_pattern_source["artifacts"]["provenance"]["capture_reducer"][
            "source_pattern_sha256"
        ] = "9" * 64
        wrong_pattern_source = CENSUS.add_digest(
            wrong_pattern_source, "receipt_sha256"
        )
        with self.assertRaisesRegex(CENSUS.CensusError, "pattern digest differs"):
            CENSUS.validate_receipt(wrong_pattern_source, plan)

        wrong_receipt_source = copy.deepcopy(receipt)
        wrong_receipt_source.pop("receipt_sha256")
        wrong_receipt_source["artifacts"]["provenance"]["capture_reducer"][
            "source_sha256"
        ] = "0" * 64
        wrong_receipt_source = CENSUS.add_digest(
            wrong_receipt_source, "receipt_sha256"
        )
        with self.assertRaisesRegex(CENSUS.CensusError, "zero SHA-256 digest"):
            CENSUS.validate_receipt(wrong_receipt_source, plan)

        missing_reducer_trap = copy.deepcopy(receipt)
        missing_reducer_trap.pop("receipt_sha256")
        missing_reducer_trap["phases"]["claimed_entry_negative_traps"] = []
        missing_reducer_trap["classification"] = (
            CENSUS.classification_from_qualification_evidence(
                True,
                missing_reducer_trap["route"]["operation_entry_symbols"],
                missing_reducer_trap["route"]["adapter_route"],
                [],
                missing_reducer_trap["phases"],
                "aarch64",
            )
        )
        missing_reducer_trap = CENSUS.add_digest(
            missing_reducer_trap, "receipt_sha256"
        )
        validated = CENSUS.validate_receipt(missing_reducer_trap, plan)
        self.assertFalse(
            validated["classification"]["whole_operation_native_authenticated"]
        )
        self.assertEqual(
            validated["classification"]["reason"],
            "claimed-entry-negative-control-failure",
        )

    def test_participation_capture_v4_closes_both_native_operation_entries(self) -> None:
        fields = participation_capture_provenance_fields()
        encoded = " ".join(f"{key}={value}" for key, value in fields.items()).encode()
        parsed = CENSUS.parse_provenance(encoded)
        provenance = CENSUS.provenance_receipt(parsed)
        CENSUS.validate_provenance_record(
            provenance, "synthetic exact-span participation"
        )
        entries = [
            fields["capture_selector_symbol"],
            fields["participation_entry_symbol"],
        ]
        self.assertEqual(provenance["kind"], "participation-capture-v4")
        self.assertEqual(
            provenance["composite_kind"], "exact-span-participation-v1"
        )
        self.assertNotIn("strict_capture", provenance)
        self.assertEqual(
            provenance["participation_capture"]["participation_strategy"], 2
        )
        self.assertEqual(
            CENSUS.selected_operation_entries(parsed),
            (entries, "linked-exact-span-participation-adapter-loop"),
        )
        self.assertEqual(
            CENSUS.operation_route_from_provenance_record(provenance),
            (entries, "linked-exact-span-participation-adapter-loop"),
        )

        grep_fields = dict(fields)
        grep_fields["model"] = "grep-captures"
        grep_fields["adapter"] = (
            "general-aot-native-exact-span-participation-grep-v1"
        )
        grep_fields["benchmark"] = "synthetic/grep-captures"
        grep_parsed = CENSUS.parse_provenance(
            " ".join(f"{key}={value}" for key, value in grep_fields.items()).encode()
        )
        CENSUS.validate_provenance_record(
            CENSUS.provenance_receipt(grep_parsed),
            "synthetic exact-span participation grep",
        )

        wrong_strategy = dict(fields)
        wrong_strategy["participation_strategy"] = "1"
        with self.assertRaisesRegex(CENSUS.CensusError, "outside 2..=2"):
            CENSUS.parse_provenance(
                " ".join(
                    f"{key}={value}" for key, value in wrong_strategy.items()
                ).encode()
            )

        helper_backed = dict(fields)
        helper_backed["participation_semantic_runtime_calls"] = "1"
        with self.assertRaisesRegex(CENSUS.CensusError, "outside 0..=0"):
            CENSUS.parse_provenance(
                " ".join(
                    f"{key}={value}" for key, value in helper_backed.items()
                ).encode()
            )

        wrong_object = dict(fields)
        wrong_object["participation_object_sha256"] = "9" * 64
        with self.assertRaisesRegex(CENSUS.CensusError, "differs from its component"):
            CENSUS.parse_provenance(
                " ".join(
                    f"{key}={value}" for key, value in wrong_object.items()
                ).encode()
            )

        wrong_bundle = dict(fields)
        wrong_bundle["participation_bundle_sha256"] = "8" * 64
        with self.assertRaisesRegex(
            CENSUS.CensusError, "export identity does not authenticate its inputs"
        ):
            CENSUS.parse_provenance(
                " ".join(
                    f"{key}={value}" for key, value in wrong_bundle.items()
                ).encode()
            )

        wrong_cells = dict(fields)
        wrong_cells["participation_transition_cells"] = "135"
        with self.assertRaisesRegex(CENSUS.CensusError, "geometry does not close"):
            CENSUS.parse_provenance(
                " ".join(
                    f"{key}={value}" for key, value in wrong_cells.items()
                ).encode()
            )

        wrong_plan = dict(fields)
        wrong_plan["participation_plan_bytes"] = "1092"
        with self.assertRaisesRegex(CENSUS.CensusError, "plan extent does not close"):
            CENSUS.parse_provenance(
                " ".join(
                    f"{key}={value}" for key, value in wrong_plan.items()
                ).encode()
            )

        over_cap = dict(fields)
        over_cap["participation_assertions"] = "65"
        with self.assertRaisesRegex(CENSUS.CensusError, "outside 0..=64"):
            CENSUS.parse_provenance(
                " ".join(
                    f"{key}={value}" for key, value in over_cap.items()
                ).encode()
            )

        with self.assertRaisesRegex(CENSUS.CensusError, "field closure differs"):
            CENSUS.parse_provenance(encoded + b" unsealed_field=1")

    def test_selector_capture_fallback_v4_closes_the_mixed_boundary(self) -> None:
        fields = selector_capture_fallback_provenance_fields()
        encoded = " ".join(f"{key}={value}" for key, value in fields.items()).encode()
        parsed = CENSUS.parse_provenance(encoded)
        provenance = CENSUS.provenance_receipt(parsed)
        CENSUS.validate_provenance_record(
            provenance, "synthetic selector capture fallback"
        )
        selector = fields["component_0_entry_symbol"]
        self.assertEqual(provenance["kind"], "selector-capture-fallback-v4")
        self.assertEqual(
            provenance["composite_kind"], "selector-negative-certificate-v1"
        )
        self.assertEqual(
            CENSUS.selected_operation_entries(parsed),
            ([selector], "linked-selector-negative-certificate-adapter-loop"),
        )
        self.assertEqual(
            CENSUS.conditional_fallback_symbols_from_provenance(provenance),
            [fields["positive_fallback_symbol"]],
        )

        wrong_engine = dict(fields)
        wrong_engine["engine"] = "IndependentNativeSpanRows(RuntimeHelper)"
        with self.assertRaisesRegex(CENSUS.CensusError, "noncanonical route"):
            CENSUS.parse_provenance(
                " ".join(
                    f"{key}={value}" for key, value in wrong_engine.items()
                ).encode()
            )

        normalized_wrong_engine = copy.deepcopy(provenance)
        normalized_wrong_engine["engine"] = "IndependentNativeSpanRows(FakeEngine)"
        with self.assertRaisesRegex(CENSUS.CensusError, "topology is not canonical"):
            CENSUS.validate_provenance_record(
                normalized_wrong_engine,
                "synthetic selector capture fallback wrong engine",
            )

        wrong_limit = dict(fields)
        wrong_limit["direct_participation_limit"] = "131071"
        with self.assertRaisesRegex(CENSUS.CensusError, "outside 131072..=131072"):
            CENSUS.parse_provenance(
                " ".join(
                    f"{key}={value}" for key, value in wrong_limit.items()
                ).encode()
            )

        build_work = dict(fields)
        build_work["direct_participation_resource"] = "BuildWork"
        build_work["direct_participation_required"] = "268435457"
        build_work["direct_participation_limit"] = "268435456"
        build_work_record = CENSUS.provenance_receipt(
            CENSUS.parse_provenance(
                " ".join(
                    f"{key}={value}" for key, value in build_work.items()
                ).encode()
            )
        )
        self.assertEqual(
            build_work_record["selector_capture_fallback"][
                "direct_participation_resource"
            ],
            "BuildWork",
        )

        wrong_required = dict(fields)
        wrong_required["direct_participation_required"] = "131074"
        with self.assertRaisesRegex(CENSUS.CensusError, "outside 131073..=131073"):
            CENSUS.parse_provenance(
                " ".join(
                    f"{key}={value}" for key, value in wrong_required.items()
                ).encode()
            )

        wrong_profile = dict(fields)
        wrong_profile["positive_fallback_profile"] = "unsealed-stock-profile"
        with self.assertRaisesRegex(CENSUS.CensusError, "stock profile differs"):
            CENSUS.parse_provenance(
                " ".join(
                    f"{key}={value}" for key, value in wrong_profile.items()
                ).encode()
            )

        with self.assertRaisesRegex(CENSUS.CensusError, "field closure differs"):
            CENSUS.parse_provenance(encoded + b" capture_group_count=1")

    def test_selector_capture_fallback_is_native_only_while_marker_is_unreached(
        self,
    ) -> None:
        plan = synthetic_plan()
        receipt = synthetic_selector_capture_fallback_qualification_receipt(plan)
        validated = CENSUS.validate_receipt(receipt, plan)
        fallback = selector_capture_fallback_provenance_fields()[
            "positive_fallback_symbol"
        ]
        self.assertTrue(
            validated["classification"]["native_search_core_authenticated"]
        )
        self.assertEqual(
            validated["classification"]["reason"],
            "native-negative-certificate-with-unused-stock-capture-fallback",
        )
        self.assertEqual(validated["route"]["semantic_helper_symbols"], [fallback])

        triggered = copy.deepcopy(receipt)
        triggered.pop("receipt_sha256")
        helper = triggered["phases"]["semantic_helper_trap"]
        helper["process"]["returncode"] = CENSUS.TRAP_EXIT
        helper["marker"]["triggered"] = fallback
        helper["marker"]["completed"] = None
        triggered["classification"] = CENSUS.classification_from_qualification_evidence(
            True,
            triggered["route"]["operation_entry_symbols"],
            triggered["route"]["adapter_route"],
            [fallback],
            triggered["phases"],
            "aarch64",
        )
        triggered = CENSUS.add_digest(triggered, "receipt_sha256")
        validated_triggered = CENSUS.validate_receipt(triggered, plan)
        self.assertFalse(
            validated_triggered["classification"]["native_search_core_authenticated"]
        )
        self.assertEqual(
            validated_triggered["classification"]["reason"],
            "semantic-runtime-helper-invoked",
        )

        omitted = copy.deepcopy(receipt)
        omitted.pop("receipt_sha256")
        omitted["route"]["semantic_helper_symbols"] = []
        omitted["route"]["semantic_helper_symbols_sha256"] = CENSUS.sha_bytes(
            CENSUS.canonical([]).encode()
        )
        omitted = CENSUS.add_digest(omitted, "receipt_sha256")
        with self.assertRaisesRegex(CENSUS.CensusError, "escaped the helper trap set"):
            CENSUS.validate_receipt(omitted, plan)

    def test_participation_receipt_is_native_capture_core_and_traps_both_entries(
        self,
    ) -> None:
        plan = synthetic_plan()
        receipt = synthetic_participation_capture_qualification_receipt(plan)
        validated = CENSUS.validate_receipt(receipt, plan)
        self.assertTrue(
            validated["classification"]["native_search_core_authenticated"]
        )
        self.assertTrue(validated["classification"]["adapter_outer_loop"])
        self.assertFalse(
            validated["classification"]["whole_operation_native_authenticated"]
        )
        self.assertEqual(
            validated["classification"]["reason"],
            "native-search-capture-core-with-exact-span-replay-adapter-loop",
        )
        self.assertEqual(
            len(validated["route"]["operation_entry_symbols"]), 2
        )

        poisoned_proof = copy.deepcopy(receipt)
        poisoned_proof.pop("receipt_sha256")
        poisoned_proof["artifacts"]["provenance"]["participation_capture"][
            "participation_bundle_sha256"
        ] = "8" * 64
        poisoned_proof = CENSUS.add_digest(poisoned_proof, "receipt_sha256")
        with self.assertRaisesRegex(
            CENSUS.CensusError, "export identity does not authenticate its inputs"
        ):
            CENSUS.validate_receipt(poisoned_proof, plan)

        missing_replay_trap = copy.deepcopy(receipt)
        missing_replay_trap.pop("receipt_sha256")
        missing_replay_trap["phases"]["claimed_entry_negative_traps"].pop()
        missing_replay_trap["classification"] = (
            CENSUS.classification_from_qualification_evidence(
                True,
                missing_replay_trap["route"]["operation_entry_symbols"],
                missing_replay_trap["route"]["adapter_route"],
                [],
                missing_replay_trap["phases"],
                "aarch64",
            )
        )
        missing_replay_trap = CENSUS.add_digest(
            missing_replay_trap, "receipt_sha256"
        )
        validated_missing = CENSUS.validate_receipt(missing_replay_trap, plan)
        self.assertFalse(
            validated_missing["classification"]["native_search_core_authenticated"]
        )
        self.assertEqual(
            validated_missing["classification"]["reason"],
            "claimed-entry-negative-control-failure",
        )

    def test_strict_capture_v4_is_closed_and_selects_capture_next(self) -> None:
        fields = strict_capture_provenance_fields()
        encoded = " ".join(f"{key}={value}" for key, value in fields.items()).encode()
        parsed = CENSUS.parse_provenance(encoded)
        provenance = CENSUS.provenance_receipt(parsed)
        CENSUS.validate_provenance_record(provenance, "synthetic strict capture")
        self.assertEqual(provenance["kind"], "strict-capture-v4")
        self.assertEqual(provenance["composite_kind"], "strict-capture-next-v1")
        self.assertEqual(provenance["required_runtime_symbols"], [])
        self.assertEqual(
            provenance["strict_capture"]["capture_next_symbol"],
            fields["component_0_entry_symbol"],
        )
        self.assertEqual(
            CENSUS.selected_operation_entries(parsed),
            (
                [fields["component_0_entry_symbol"]],
                "linked-strict-capture-next-adapter-loop",
            ),
        )
        self.assertEqual(
            CENSUS.operation_route_from_provenance_record(provenance),
            (
                [fields["component_0_entry_symbol"]],
                "linked-strict-capture-next-adapter-loop",
            ),
        )

        grep_fields = dict(fields)
        grep_fields["model"] = "grep-captures"
        grep_fields["adapter"] = "general-aot-native-single-capture-next-grep-v1"
        grep_fields["benchmark"] = "synthetic/grep-captures"
        grep_parsed = CENSUS.parse_provenance(
            " ".join(f"{key}={value}" for key, value in grep_fields.items()).encode()
        )
        CENSUS.validate_provenance_record(
            CENSUS.provenance_receipt(grep_parsed), "synthetic strict grep capture"
        )

        with self.assertRaisesRegex(CENSUS.CensusError, "field closure differs"):
            CENSUS.parse_provenance(encoded + b" unsealed_field=1")

        helper_backed = dict(fields)
        helper_backed["component_0_runtime_symbols"] = (
            "fre_aot_regex_runtime_capture_materialize_v1"
        )
        with self.assertRaisesRegex(CENSUS.CensusError, "requires semantic runtime"):
            CENSUS.parse_provenance(
                " ".join(
                    f"{key}={value}" for key, value in helper_backed.items()
                ).encode()
            )

        wrong_entry = dict(fields)
        wrong_entry["component_0_entry_symbol"] = fields["capture_selector_symbol"]
        with self.assertRaisesRegex(CENSUS.CensusError, "not native capture_next"):
            CENSUS.parse_provenance(
                " ".join(f"{key}={value}" for key, value in wrong_entry.items()).encode()
            )

        wrong_program = dict(fields)
        wrong_program["capture_program_sha256"] = "9" * 64
        with self.assertRaisesRegex(CENSUS.CensusError, "differs from its component"):
            CENSUS.parse_provenance(
                " ".join(f"{key}={value}" for key, value in wrong_program.items()).encode()
            )

    def test_strict_capture_receipt_is_native_capture_core_not_whole_operation(self) -> None:
        plan = synthetic_plan()
        receipt = synthetic_strict_capture_qualification_receipt(plan)
        validated = CENSUS.validate_receipt(receipt, plan)
        self.assertTrue(
            validated["classification"]["native_search_core_authenticated"]
        )
        self.assertTrue(validated["classification"]["adapter_outer_loop"])
        self.assertFalse(
            validated["classification"]["whole_operation_native_authenticated"]
        )
        self.assertEqual(
            validated["classification"]["reason"],
            "native-search-capture-core-with-checked-rust-adapter-loop",
        )
        self.assertEqual(
            validated["route"]["operation_entry_symbols"],
            [strict_capture_provenance_fields()["component_0_entry_symbol"]],
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            receipts = root / "receipts"
            receipts.mkdir()
            (receipts / "runtime-job-000.json").write_text(
                json.dumps(receipt), encoding="utf-8"
            )
            summary = CENSUS.summarize(argparse.Namespace(
                plan=str(plan_path), receipts=str(receipts)
            ))
        self.assertEqual(
            summary["fractions"]["native_search_core_over_all_runtime_jobs"],
            {"numerator": 1, "denominator": 311},
        )
        self.assertEqual(
            summary["fractions"]["whole_operation_native_over_all_runtime_jobs"],
            {"numerator": 0, "denominator": 311},
        )

        retained_helper = copy.deepcopy(receipt)
        retained_helper.pop("receipt_sha256")
        retained_helper["route"]["semantic_helper_symbols"] = [
            "fre_aot_regex_runtime_capture_materialize_v1"
        ]
        retained_helper["route"]["semantic_helper_symbols_sha256"] = CENSUS.sha_bytes(
            CENSUS.canonical(
                retained_helper["route"]["semantic_helper_symbols"]
            ).encode()
        )
        retained_helper = CENSUS.add_digest(retained_helper, "receipt_sha256")
        with self.assertRaisesRegex(
            CENSUS.CensusError, "retains semantic runtime symbols"
        ):
            CENSUS.validate_receipt(retained_helper, plan)

    def test_uniform_capture_build_decline_is_recorded_not_dropped(self) -> None:
        plan = synthetic_plan()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            failure = CENSUS.record_failure(argparse.Namespace(
                plan=str(plan_path),
                job_id="runtime-job-000",
                stage="build",
                outcome="failure",
                evidence_sha256=None,
                evidence_bytes=None,
                output=str(root / "unused.json"),
            ))
            CENSUS.validate_receipt(failure, plan)
            receipts = root / "receipts"
            receipts.mkdir()
            (receipts / "runtime-job-000.json").write_text(
                json.dumps(failure), encoding="utf-8"
            )
            summary = CENSUS.summarize(argparse.Namespace(
                plan=str(plan_path), receipts=str(receipts)
            ))
        self.assertEqual(summary["disposition_counts"], {
            "build-failure": 1,
            "missing-receipt": 309,
            "unsupported-no-exact-adapter": 1,
        })

    def test_scalar_v2_provenance_has_a_closed_raw_contract(self) -> None:
        fields = scalar_native_reducer_provenance_fields("count", ordered=False)
        encoded = " ".join(f"{key}={value}" for key, value in fields.items()).encode()
        parsed = CENSUS.parse_provenance(encoded)
        self.assertEqual(parsed, fields)
        receipt = CENSUS.provenance_receipt(parsed)
        self.assertEqual(receipt["required_runtime_symbols"], [])
        self.assertEqual(
            receipt["scalar_native_reducer"]["route_variant"], "direct-v2"
        )
        self.assertNotIn("strict_capture", receipt)
        with self.assertRaisesRegex(CENSUS.CensusError, "field closure differs"):
            CENSUS.parse_provenance(encoded + b" unsealed_field=1")

    def test_empty_semantic_helper_inventory_is_a_valid_proof_surface(self) -> None:
        phase = {
            "outcome": "not-run",
            "returncode": None,
            "stdout_bytes": 0,
            "stdout_sha256": CENSUS.sha_bytes(b""),
            "stderr_bytes": 0,
            "stderr_sha256": CENSUS.sha_bytes(b""),
        }
        marker = {
            "status": "missing",
            "sha256": None,
            "armed": [],
            "triggered": None,
        }
        self.assertTrue(CENSUS.semantic_helper_control_pass([], phase, marker, "aarch64"))
        self.assertFalse(
            CENSUS.semantic_helper_control_pass(
                [], phase, {**marker, "armed": [1]}, "aarch64"
            )
        )

    def test_plan_is_closed_and_requires_canonical_311_jobs(self) -> None:
        plan = synthetic_plan()
        self.assertEqual(
            CENSUS.validate_plan(plan)["denominators"]["runtime_jobs"]["count"], 311
        )
        extra = copy.deepcopy(plan)
        extra["not_in_schema"] = True
        extra = CENSUS.add_digest(
            {key: value for key, value in extra.items() if key != "plan_sha256"},
            "plan_sha256",
        )
        with self.assertRaises(CENSUS.CensusError):
            CENSUS.validate_plan(extra)
        short = copy.deepcopy(plan)
        short["denominators"]["runtime_jobs"] = CENSUS.id_set(
            short["denominators"]["runtime_jobs"]["ids"][:-1]
        )
        short = CENSUS.add_digest(
            {key: value for key, value in short.items() if key != "plan_sha256"},
            "plan_sha256",
        )
        with self.assertRaisesRegex(CENSUS.CensusError, "311"):
            CENSUS.validate_plan(short)

        altered_policy = copy.deepcopy(plan)
        altered_policy["policy"]["timing"] = True
        altered_policy = CENSUS.add_digest(
            {
                key: value
                for key, value in altered_policy.items()
                if key != "plan_sha256"
            },
            "plan_sha256",
        )
        with self.assertRaisesRegex(CENSUS.CensusError, "policy"):
            CENSUS.validate_plan(altered_policy)

        point_free = copy.deepcopy(plan)
        point_free["points"] = []
        for job in point_free["jobs"]:
            job["point_ids"] = []
        point_free["denominators"]["all_raw_schedule_points"] = CENSUS.id_set([])
        point_free["denominators"]["raw_runtime_schedule_points"] = CENSUS.id_set([])
        point_free = CENSUS.add_digest(
            {key: value for key, value in point_free.items() if key != "plan_sha256"},
            "plan_sha256",
        )
        with self.assertRaisesRegex(CENSUS.CensusError, "no source points"):
            CENSUS.validate_plan(point_free)

        malformed_input = copy.deepcopy(plan)
        job = malformed_input["jobs"][34]
        job["input"]["pattern_sha256"] = "4" * 64
        point_id = job["point_ids"][0]
        point = next(row for row in malformed_input["points"] if row["point_id"] == point_id)
        point["input"] = job["input"]
        malformed_input = CENSUS.add_digest(
            {
                key: value
                for key, value in malformed_input.items()
                if key != "plan_sha256"
            },
            "plan_sha256",
        )
        with self.assertRaisesRegex(CENSUS.CensusError, "pattern identities"):
            CENSUS.validate_plan(malformed_input)

    def test_summary_counts_missing_and_unsupported_as_nonnative(self) -> None:
        plan = synthetic_plan()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            receipts = root / "receipts"
            receipts.mkdir()
            summary = CENSUS.summarize(argparse.Namespace(
                plan=str(plan_path), receipts=str(receipts)
            ))
        self.assertEqual(
            summary["fractions"]["native_search_core_over_all_runtime_jobs"],
            {"numerator": 0, "denominator": 311},
        )
        self.assertEqual(summary["disposition_counts"], {
            "missing-receipt": 310,
            "unsupported-no-exact-adapter": 1,
        })

    def test_receipt_classification_is_recomputed_from_closed_evidence(self) -> None:
        plan = synthetic_plan()
        receipt = synthetic_qualification_receipt(plan)
        validated = CENSUS.validate_receipt(receipt, plan)
        self.assertTrue(validated["classification"]["native_search_core_authenticated"])

        forged = copy.deepcopy(receipt)
        forged["phases"]["claimed_entry_negative_traps"][0]["process"][
            "returncode"
        ] = 0
        forged = CENSUS.add_digest(
            {key: value for key, value in forged.items() if key != "receipt_sha256"},
            "receipt_sha256",
        )
        with self.assertRaisesRegex(CENSUS.CensusError, "differs from its evidence"):
            CENSUS.validate_receipt(forged, plan)

    def test_control_plane_symbol_cannot_pose_as_native_operation_entry(self) -> None:
        plan = synthetic_plan()
        forged = synthetic_qualification_receipt(plan)
        control_plane = "fre_aot_regex_runtime_prepare_exclusive_v3"
        forged["artifacts"]["provenance"]["reducer_symbol"] = control_plane
        forged["route"]["operation_entry_symbols"] = [control_plane]
        forged["route"]["operation_entry_symbols_sha256"] = CENSUS.sha_bytes(
            CENSUS.canonical([control_plane]).encode()
        )
        negative = forged["phases"]["claimed_entry_negative_traps"][0]
        negative["symbol"] = control_plane
        negative["marker"]["armed"][0]["symbol"] = control_plane
        negative["marker"]["triggered"] = control_plane
        forged["classification"] = CENSUS.classification_from_qualification_evidence(
            True,
            [control_plane],
            forged["route"]["adapter_route"],
            [],
            forged["phases"],
            "aarch64",
        )
        forged = CENSUS.add_digest(
            {key: value for key, value in forged.items() if key != "receipt_sha256"},
            "receipt_sha256",
        )
        with self.assertRaisesRegex(
            CENSUS.CensusError, "noncanonical symbol|non-native operation entry"
        ):
            CENSUS.validate_receipt(forged, plan)

    def test_cross_architecture_trap_marker_cannot_authenticate_entry(self) -> None:
        plan = synthetic_plan()
        forged = synthetic_qualification_receipt(plan)
        marker = forged["phases"]["claimed_entry_negative_traps"][0]["marker"]
        marker["architecture"] = "x86_64"
        marker["armed"][0]["before"] = "5548"
        marker["armed"][0]["after"] = "0f0b"
        forged["classification"] = CENSUS.classification_from_qualification_evidence(
            True,
            forged["route"]["operation_entry_symbols"],
            forged["route"]["adapter_route"],
            [],
            forged["phases"],
            "x86_64",
        )
        forged = CENSUS.add_digest(
            {key: value for key, value in forged.items() if key != "receipt_sha256"},
            "receipt_sha256",
        )
        with self.assertRaisesRegex(CENSUS.CensusError, "differs from its evidence"):
            CENSUS.validate_receipt(forged, plan)

    def test_public_path_cannot_enter_holdout_component(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            forbidden = root / "holdout" / "case.klv"
            forbidden.parent.mkdir()
            forbidden.write_bytes(b"public-looking-but-forbidden")
            with self.assertRaises(CENSUS.CensusError):
                CENSUS.relative_public_path(root, str(forbidden), "fixture")

    def test_trap_marker_preserves_offsets_and_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "marker"
            path.write_text(
                "schema=fre.aot-rebar.runtime-trap.v1\n"
                "kind=claimed-operation-entry\n"
                "architecture=x86_64\n"
                "armed=fre_aot_regex_search_v1_deadbeef offset=0x1234 before=5548 after=0f0b\n"
                "installed=1\nexpected=1\n"
                "triggered=fre_aot_regex_search_v1_deadbeef\n",
                encoding="ascii",
            )
            marker = CENSUS.parse_trap_marker(path)
        self.assertEqual(marker["status"], "valid")
        self.assertEqual(marker["installed"], 1)
        self.assertEqual(marker["armed"][0]["offset"], "0x1234")
        self.assertEqual(marker["triggered"], "fre_aot_regex_search_v1_deadbeef")

        helpers = [
            "fre_aot_regex_runtime_helper_alpha",
            "fre_aot_regex_runtime_helper_alias",
            "fre_aot_regex_runtime_helper_second_alias",
        ]
        helper_phase = {
            "outcome": "exit",
            "returncode": 0,
            "stdout_bytes": 0,
            "stdout_sha256": CENSUS.sha_bytes(b""),
            "stderr_bytes": 0,
            "stderr_sha256": CENSUS.sha_bytes(b""),
        }
        alias_marker = {
            "status": "valid",
            "sha256": "d" * 64,
            "kind": "semantic-helpers",
            "architecture": "aarch64",
            "installed": 3,
            "expected": 3,
            "armed": [
                {
                    "symbol": helpers[0],
                    "offset": "0x100",
                    "before": "fd7bbfa9",
                    "after": "000020d4",
                },
                {
                    "symbol": helpers[1],
                    "offset": "0x100",
                    "before": "000020d4",
                    "after": "000020d4",
                },
                {
                    "symbol": helpers[2],
                    "offset": "0x100",
                    "before": "000020d4",
                    "after": "000020d4",
                },
            ],
            "triggered": None,
            "completed": "normal",
        }
        self.assertTrue(CENSUS.marker_patch_evidence_pass(alias_marker, "aarch64"))
        self.assertTrue(CENSUS.semantic_helper_control_pass(
            helpers, helper_phase, alias_marker, "aarch64"
        ))

        for triggered in (helpers[0], helpers[1], "unowned-signal"):
            with self.subTest(triggered=triggered):
                triggered_marker = copy.deepcopy(alias_marker)
                triggered_marker["triggered"] = triggered
                triggered_marker["completed"] = None
                self.assertFalse(CENSUS.semantic_helper_control_pass(
                    helpers, helper_phase, triggered_marker, "aarch64"
                ))

        x86_alias_marker = copy.deepcopy(alias_marker)
        x86_alias_marker["architecture"] = "x86_64"
        x86_alias_marker["installed"] = 2
        x86_alias_marker["expected"] = 2
        x86_alias_marker["armed"] = x86_alias_marker["armed"][:2]
        x86_alias_marker["armed"][0]["before"] = "5548"
        x86_alias_marker["armed"][0]["after"] = "0f0b"
        x86_alias_marker["armed"][1]["before"] = "0f0b"
        x86_alias_marker["armed"][1]["after"] = "0f0b"
        self.assertTrue(CENSUS.marker_patch_evidence_pass(
            x86_alias_marker, "x86_64"
        ))
        self.assertTrue(CENSUS.semantic_helper_control_pass(
            helpers[:2], helper_phase, x86_alias_marker, "x86_64"
        ))

        first_record_is_trap = copy.deepcopy(alias_marker)
        first_record_is_trap["armed"][0]["before"] = "000020d4"
        self.assertFalse(CENSUS.marker_patch_evidence_pass(
            first_record_is_trap, "aarch64"
        ))

        second_record_is_not_trap = copy.deepcopy(alias_marker)
        second_record_is_not_trap["armed"][1]["before"] = "a57bbfa9"
        self.assertFalse(CENSUS.marker_patch_evidence_pass(
            second_record_is_not_trap, "aarch64"
        ))

        trap_at_new_offset = copy.deepcopy(alias_marker)
        trap_at_new_offset["armed"][1]["offset"] = "0x101"
        self.assertFalse(CENSUS.marker_patch_evidence_pass(
            trap_at_new_offset, "aarch64"
        ))

        reordered_alias = copy.deepcopy(alias_marker)
        reordered_alias["armed"].reverse()
        self.assertFalse(CENSUS.marker_patch_evidence_pass(
            reordered_alias, "aarch64"
        ))

        noncanonical_offset = copy.deepcopy(alias_marker)
        noncanonical_offset["armed"][1]["offset"] = "0x0100"
        self.assertFalse(CENSUS.marker_patch_evidence_pass(
            noncanonical_offset, "aarch64"
        ))

        malformed_first_record = copy.deepcopy(alias_marker)
        malformed_first_record["armed"][0]["before"] = "nothex!!"
        self.assertFalse(CENSUS.marker_patch_evidence_pass(
            malformed_first_record, "aarch64"
        ))

        wrong_first_patch = copy.deepcopy(alias_marker)
        wrong_first_patch["armed"][0]["after"] = "fd7bbfa9"
        self.assertFalse(CENSUS.marker_patch_evidence_pass(
            wrong_first_patch, "aarch64"
        ))

        wrong_patch = copy.deepcopy(alias_marker)
        wrong_patch["armed"][1]["after"] = "fd7bbfa9"
        self.assertFalse(CENSUS.marker_patch_evidence_pass(
            wrong_patch, "aarch64"
        ))

        wrong_symbol_order = copy.deepcopy(alias_marker)
        wrong_symbol_order["armed"][0]["symbol"] = helpers[1]
        wrong_symbol_order["armed"][1]["symbol"] = helpers[0]
        self.assertTrue(CENSUS.marker_patch_evidence_pass(
            wrong_symbol_order, "aarch64"
        ))
        self.assertFalse(CENSUS.semantic_helper_control_pass(
            helpers, helper_phase, wrong_symbol_order, "aarch64"
        ))

        wrong_count = copy.deepcopy(alias_marker)
        wrong_count["installed"] = 1
        self.assertTrue(CENSUS.marker_patch_evidence_pass(wrong_count, "aarch64"))
        self.assertFalse(CENSUS.semantic_helper_control_pass(
            helpers, helper_phase, wrong_count, "aarch64"
        ))


if __name__ == "__main__":
    unittest.main()
