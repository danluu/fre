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
SPEC = importlib.util.spec_from_file_location("true_native_census", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
CENSUS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CENSUS)


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
    klv_identity = {"path": "fixture.klv", "sha256": "5" * 64, "bytes": 1}
    for job_id in compile_ids:
        jobs.append({
            "job_id": job_id, "benchmark": job_id, "model": "compile",
            "input": input_identity, "candidate_klv": klv_identity,
            "is_runtime": False, "exact_adapter": False,
            "adapter_reason": "compile-job-outside-runtime-denominator", "point_ids": [],
        })
    for index, job_id in enumerate(runtime_ids):
        jobs.append({
            "job_id": job_id, "benchmark": job_id,
            "model": "count-captures" if index == 0 else "count",
            "input": input_identity, "candidate_klv": klv_identity,
            "is_runtime": True, "exact_adapter": index != 0,
            "adapter_reason": (
                "unsupported-runtime-model-or-cardinality" if index == 0
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
            "comparator": "synthetic",
            "expected": 0,
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
            "exact_adapter_runtime_jobs": CENSUS.id_set(runtime_ids[1:]),
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
    identity_suffix = "f" * 64
    entry = f"fre_aot_regex_count_exclusive_v1_{identity_suffix}"
    provenance = {
        "schema": "fre.aot.rebar-runner.v2",
        "adapter": "general-aot-linked-count-v1",
        "model": job["model"],
        "benchmark": job["benchmark"],
        "source_commit": plan["candidate_source"]["commit"],
        "source_tree": plan["candidate_source"]["tree"],
        "target": plan["target"]["triple"],
        "feature_bits": plan["target"]["feature_bits"],
        "kind": "scalar-v2",
        "composite_kind": None,
        "source_pattern_count": None,
        "source_to_artifact": [],
        "row_total_object_bytes": None,
        "boundary": "complete-native-count",
        "engine": "OrderedDfa",
        "aggregate_strategy": "single-pattern",
        "prepared_bulk_strategy": "linked-reducer",
        "span_iteration_strategy": "none",
        "grep_iteration_strategy": "none",
        "program_sha256": "b" * 64,
        "object_sha256": object_sha256,
        "program_symbol": f"fre_aot_regex_program_v1_{identity_suffix}",
        "entry_symbol": f"fre_aot_regex_search_v1_{identity_suffix}",
        "reducer_symbol": entry,
        "span_fill_symbol": "",
        "required_runtime_symbols": [],
        "components": [],
    }
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


class TrueNativeCensusTests(unittest.TestCase):
    def test_exact_adapter_includes_ordered_many_but_not_multi_grep(self) -> None:
        self.assertTrue(CENSUS.has_exact_adapter("count", 1))
        self.assertTrue(CENSUS.has_exact_adapter("count", 3))
        self.assertFalse(
            CENSUS.has_exact_adapter("count", CENSUS.MAX_NATIVE_ROW_COMPONENTS + 1)
        )
        self.assertTrue(CENSUS.has_exact_adapter("count-spans", 2))
        self.assertTrue(CENSUS.has_exact_adapter("grep", 1))
        self.assertFalse(CENSUS.has_exact_adapter("grep", 2))
        self.assertTrue(CENSUS.has_exact_adapter("regex-redux", 0))
        self.assertFalse(CENSUS.has_exact_adapter("regex-redux", 1))
        self.assertFalse(CENSUS.has_exact_adapter("compile", 1))

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

    def test_macho_leading_underscore_is_normalized(self) -> None:
        symbols = CENSUS.nm_text_symbols(
            "0000000100001000 T _fre_aot_regex_runtime_search_v1\n"
        )
        self.assertIn("fre_aot_regex_runtime_search_v1", symbols)

    def test_operation_entry_is_the_actual_adapter_boundary(self) -> None:
        common = {
            "reducer_symbol": "fre_aot_regex_count_exclusive_v1_deadbeef",
            "span_fill_symbol": "",
            "entry_symbol": "fre_aot_regex_search_v1_deadbeef",
        }
        self.assertEqual(
            CENSUS.selected_operation_entries({**common, "model": "count"}),
            ([common["reducer_symbol"]], "linked-reducer"),
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

    def test_composite_v3_requires_and_returns_every_component_entry(self) -> None:
        fields = {
            "schema": "fre.aot.rebar-runner.v3",
            "model": "regex-redux",
            "component_count": "15",
        }
        for index in range(15):
            fields[f"component_{index}_native"] = "true"
            fields[f"component_{index}_entry_symbol"] = f"fre_component_{index}_entry"
            fields[f"component_{index}_runtime_symbols"] = (
                "fre_aot_regex_runtime_search_exclusive_v1"
            )
            fields[f"component_{index}_program_sha256"] = f"{index:064x}"
            fields[f"component_{index}_object_sha256"] = f"{index + 1:064x}"
        entries, route = CENSUS.selected_operation_entries(fields)
        self.assertEqual(route, "linked-fixed-composite-adapter-loop")
        self.assertEqual(len(entries), 15)
        self.assertEqual(entries[0], "fre_component_0_entry")
        self.assertEqual(entries[-1], "fre_component_14_entry")

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
            fields[f"component_{index}_entry_symbol"] = f"fre_row_{index}_entry"
            fields[f"component_{index}_runtime_symbols"] = ""
            fields[f"component_{index}_program_sha256"] = f"{index + 1:064x}"
            fields[f"component_{index}_object_sha256"] = f"{index + 3:064x}"
        self.assertEqual(
            CENSUS.selected_operation_entries(fields),
            (["fre_row_0_entry", "fre_row_1_entry"], "linked-native-row-adapter-loop"),
        )

    def test_native_row_v3_provenance_closes_and_seals_source_topology(self) -> None:
        fields = {
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
            "engine": "IndependentNativeSpanRows(OrderedDfa,OrderedNfa)",
            "aggregate_strategy": "native-independent-span-row-selector-v1",
            "native_row_bridge": "true",
            "source_pattern_count": "3",
            "row_total_object_bytes": "4096",
            "source_to_artifact": "0,1,0",
            "component_count": "2",
            "boundary": "complete-native-row-bridge",
            "required_comparators": "rust-regex-1.12.4,fre-current-runtime",
        }
        for index, source_ordinal in enumerate((0, 1)):
            fields[f"component_{index}_native"] = "true"
            fields[f"component_{index}_source_ordinal"] = str(source_ordinal)
            fields[f"component_{index}_entry_symbol"] = f"fre_row_{index}_entry"
            fields[f"component_{index}_runtime_symbols"] = ""
            fields[f"component_{index}_program_sha256"] = f"{index + 1:064x}"
            fields[f"component_{index}_object_sha256"] = f"{index + 3:064x}"
        encoded = " ".join(f"{key}={value}" for key, value in fields.items()).encode()
        parsed = CENSUS.parse_provenance(encoded)
        receipt = CENSUS.provenance_receipt(parsed)
        self.assertEqual(receipt["composite_kind"], "native-row-bridge-v1")
        self.assertEqual(receipt["source_pattern_count"], 3)
        self.assertEqual(receipt["source_to_artifact"], [0, 1, 0])
        self.assertEqual(
            [component["source_ordinal"] for component in receipt["components"]],
            [0, 1],
        )
        with self.assertRaisesRegex(CENSUS.CensusError, "field closure differs"):
            CENSUS.parse_provenance(encoded + b" unsealed_field=1")

    def test_scalar_v2_provenance_has_a_closed_raw_contract(self) -> None:
        suffix = "f" * 64
        fields = {
            "schema": "fre.aot.rebar-runner.v2",
            "disposition": "executed",
            "configured": "true",
            "adapter": "general-aot-linked-count-v1",
            "model": "count",
            "benchmark": "synthetic/scalar",
            "source_commit": "1" * 40,
            "source_tree": "2" * 40,
            "target": "aarch64-linux",
            "feature_bits": "0000000100000000",
            "compiler_version": "1",
            "optimizer_version": "1",
            "engine": "OrderedDfa",
            "aggregate_strategy": "single-pattern",
            "prepared_bulk_strategy": "linked-reducer",
            "span_iteration_strategy": "none",
            "grep_iteration_strategy": "none",
            "prepare_config_version": "1",
            "prepare_operation_flags": "0000000000000000",
            "required_prepare_capabilities": "0000000000000000",
            "prepare_scope": "runtime-handle-state",
            "object_descriptor_setup": "authenticated-v3-when-required",
            "max_start_filter_setup_work": "1",
            "max_grep_count_workspace_bytes": "1",
            "max_handle_bytes": "0",
            "max_ordered_nfa_scratch_bytes": "0",
            "max_ordered_nfa_setup_work": "0",
            "program_sha256": "3" * 64,
            "object_sha256": "4" * 64,
            "program_symbol": f"fre_aot_regex_program_v1_{suffix}",
            "entry_symbol": f"fre_aot_regex_search_v1_{suffix}",
            "reducer_symbol": f"fre_aot_regex_count_exclusive_v1_{suffix}",
            "span_fill_symbol": "",
            "required_runtime_symbols": (
                "fre_aot_regex_runtime_search_v1,"
                "fre_aot_regex_runtime_compiler_private_count_v1"
            ),
            "boundary": "runtime-klv-warmup-schedule",
            "required_comparators": "rust-regex-1.12.4,fre-current-runtime",
        }
        encoded = " ".join(f"{key}={value}" for key, value in fields.items()).encode()
        parsed = CENSUS.parse_provenance(encoded)
        self.assertEqual(parsed, fields)
        self.assertEqual(
            CENSUS.provenance_receipt(parsed)["required_runtime_symbols"],
            [
                "fre_aot_regex_runtime_compiler_private_count_v1",
                "fre_aot_regex_runtime_search_v1",
            ],
        )
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

    def test_summary_counts_unsupported_and_missing_receipts_as_nonnative(self) -> None:
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
        with self.assertRaisesRegex(CENSUS.CensusError, "non-native operation entry"):
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


if __name__ == "__main__":
    unittest.main()
