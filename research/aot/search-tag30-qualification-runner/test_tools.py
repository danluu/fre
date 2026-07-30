#!/usr/bin/env python3
"""Tests for the frozen tag-30 shard controller and analyzer."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import sys
import tempfile
import unittest
from fractions import Fraction
from pathlib import Path
from types import ModuleType


DIRECTORY = Path(__file__).resolve().parent


def load_module(name: str, path: Path) -> ModuleType:
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


analyzer = load_module("tag30_analyzer", DIRECTORY / "analyze_fragments.py")
controller = load_module("tag30_controller", DIRECTORY / "run_shards.py")
identity_renderer = load_module(
    "tag30_identity_renderer", DIRECTORY / "render_identity.py"
)
sys.modules["render_identity"] = identity_renderer
authorization_preparer = load_module(
    "tag30_authorization_preparer",
    DIRECTORY / "prepare_discovery_authorization.py",
)
derivation = load_module(
    "tag30_long_derivation",
    DIRECTORY.parent / "search-tag30-long-input-policy-v1" / "derive_projection.py",
)


def cell(
    ratio: Fraction = Fraction(1, 2), strict_wins: int = 6
) -> object:
    return analyzer.TimingCell(
        row={
            "row_sha256": f"{1:064x}",
            "literal_bytes": 6,
            "topology": "binary-aperiodic",
            "window_bytes": 65_536,
            "outcome": "absent",
            "learned_source_kind": "primary",
            "learned_source_relations": ["equals-primary"],
        },
        record={},
        ratio=ratio,
        strict_wins=strict_wins,
    )


class ContractTests(unittest.TestCase):
    def test_discovery_authorization_inventory_is_exact_and_injective(
        self,
    ) -> None:
        def digest(value: bytes) -> str:
            return hashlib.sha256(value).hexdigest()

        candidates = []
        expected_candidates = []
        for ordinal in range(808):
            literal = ordinal.to_bytes(6, "big")
            token = str(ordinal).encode()
            expected_candidates.append(
                {
                    "literal_bytes": len(literal),
                    "literal_hex": literal.hex(),
                    "literal_sha256": digest(literal),
                    "semantic_candidate_sha256": digest(
                        authorization_preparer.CANDIDATE_DOMAIN + literal
                    ),
                }
            )
            candidates.append(
                {
                    "ordinal": ordinal,
                    "semantic_candidate_sha256": digest(
                        authorization_preparer.CANDIDATE_DOMAIN + literal
                    ),
                    "literal_sha256": digest(literal),
                    "literal_hex": literal.hex(),
                    "compile_identity": digest(b"compile-identity-" + token),
                    "compile_receipt_sha256": digest(
                        b"compile-receipt-" + token
                    ),
                    "compile_receipt_basename": (
                        f"external-search-{ordinal}-compile-receipt.bin"
                    ),
                    "implementation_object_sha256": digest(
                        b"implementation-object-" + token
                    ),
                    "glue_object_sha256": digest(b"glue-object-" + token),
                    "implementation_object_basename": (
                        f"external-search-{ordinal}-implementation.o"
                    ),
                    "glue_object_basename": (
                        f"external-search-{ordinal}-family-glue.o"
                    ),
                    "implementation_symbols": {
                        "entry": f"entry_{ordinal}",
                        "payload": f"payload_{ordinal}",
                        "metadata": f"metadata_{ordinal}",
                    },
                    "glue_symbol": f"glue_{ordinal}",
                }
            )
        refusals = []
        expected_refusals = []
        for ordinal in range(114):
            literal = b"\xff" + ordinal.to_bytes(5, "big")
            expected_refusals.append(
                {
                    "literal_bytes": len(literal),
                    "literal_hex": literal.hex(),
                    "literal_sha256": digest(literal),
                    "semantic_candidate_sha256": digest(
                        authorization_preparer.CANDIDATE_DOMAIN + literal
                    ),
                    "selector_eligible": False,
                    "expected_compiler_disposition": "structural-refusal",
                }
            )
            refusals.append(
                {
                    "ordinal": ordinal,
                    "semantic_candidate_sha256": digest(
                        authorization_preparer.CANDIDATE_DOMAIN + literal
                    ),
                    "literal_sha256": digest(literal),
                    "literal_hex": literal.hex(),
                    "disposition": "structural-refusal",
                    "compile_receipt_sha256": digest(
                        b"refusal-receipt-" + str(ordinal).encode()
                    ),
                    "compile_receipt_basename": (
                        "external-search-refusal-"
                        f"{ordinal}-compile-receipt.bin"
                    ),
                }
            )
        authorization_preparer.validate_candidate_rows(
            candidates,
            refusals,
            expected_candidates,
            expected_refusals,
        )
        candidates[1]["literal_sha256"] = candidates[0]["literal_sha256"]
        with self.assertRaises(authorization_preparer.Refusal):
            authorization_preparer.validate_candidate_rows(
                candidates,
                refusals,
                expected_candidates,
                expected_refusals,
            )

    def test_private_evidence_identity_uses_discovery_authorization(self) -> None:
        contract = json.loads(
            (DIRECTORY / "campaign-contract-v1.json").read_bytes()
        )
        analyzer_sha256 = "11" * 32
        authorization_sha256 = "22" * 32
        evidence = contract["private_family_authority"][
            "evidence_identity"
        ]
        expected = hashlib.sha256(
            bytes.fromhex(evidence["domain_hex"])
            + bytes.fromhex(identity_renderer.CONTRACT_SHA256)
            + bytes.fromhex(analyzer_sha256)
            + bytes.fromhex(authorization_sha256)
        ).hexdigest()
        self.assertEqual(
            identity_renderer.intent_identity(
                contract, analyzer_sha256, authorization_sha256
            ),
            expected,
        )
        self.assertEqual(
            evidence["raw_digest_order"],
            [
                "domain_bytes",
                "campaign_contract_sha256",
                "analyzer_source_sha256",
                "discovery_authorization_file_sha256",
            ],
        )

    def test_identity_template_is_closed_and_unsealed(self) -> None:
        contract = identity_renderer.load_contract(DIRECTORY)
        template = identity_renderer.load_template(DIRECTORY)
        self.assertEqual(
            contract["private_family_authority"][
                "discovery_authorization"
            ]["schema"],
            identity_renderer.DISCOVERY_AUTHORIZATION_SCHEMA,
        )
        self.assertIsNone(template["auto_routing"]["evidence_identity"])
        self.assertIsNone(
            template["private_family"]["discovery_authorization_sha256"]
        )
        self.assertEqual(
            set(template["platform_artifacts"]),
            set(identity_renderer.PLATFORMS),
        )

    def test_contract_hash_and_exact_ranges(self) -> None:
        contract = analyzer.authenticate_contract(
            DIRECTORY / "campaign-contract-v1.json"
        )
        sharding = contract["sharding"]
        expected = {
            "correctness_ranges": 123_424,
            "universal_timing_ranges": 3_078,
            "long_policy_timing_ranges": 1_458,
            "diagnostic_timing_ranges": 30,
        }
        for field, total in expected.items():
            ranges = sharding[field]
            self.assertEqual(len(ranges), 16)
            self.assertEqual(ranges[0][0], 0)
            self.assertEqual(ranges[-1][1], total)
            self.assertTrue(
                all(
                    ranges[index][1] == ranges[index + 1][0]
                    for index in range(15)
                )
            )
            self.assertEqual(
                ranges,
                [
                    list(analyzer.shard_bounds(total, shard))
                    for shard in range(16)
                ],
            )
        diagnostic = contract["projections"]["diagnostic"]
        self.assertEqual(diagnostic["cells"], 30)
        self.assertEqual(
            diagnostic["source_ordinals"],
            sorted(set(diagnostic["source_ordinals"])),
        )
        self.assertTrue(
            all(
                analyzer.is_hex(row_sha)
                for row_sha in diagnostic["source_row_sha256s"]
            )
        )
        self.assertTrue(all(diagnostic["coverage"].values()))

    def test_expected_fragment_set_is_exact(self) -> None:
        names = analyzer.expected_fragment_names()
        self.assertEqual(len(names), 2 * 2 * 2 * 16)
        self.assertTrue(
            all(name.endswith(".jsonl") for name in names)
        )

    def test_diagnostic_subset_matches_authenticated_source_and_coverage(
        self,
    ) -> None:
        contract = analyzer.authenticate_contract(
            DIRECTORY / "campaign-contract-v1.json"
        )
        diagnostic = contract["projections"]["diagnostic"]
        with tempfile.TemporaryDirectory() as raw_directory:
            timed_path = Path(raw_directory) / "long-timed.jsonl"
            summary = derivation.generate(
                DIRECTORY.parents[2], timed_output=timed_path
            )
            self.assertEqual(
                summary["timed_projection"]["sha256"],
                diagnostic["source_sha256"],
            )
            rows = [
                json.loads(line)
                for line in timed_path.read_text(encoding="utf-8").splitlines()
            ]
        selected = [
            rows[ordinal] for ordinal in diagnostic["source_ordinals"]
        ]
        self.assertEqual(
            [row["row_sha256"] for row in selected],
            diagnostic["source_row_sha256s"],
        )
        for field in (
            "literal_bytes",
            "topology",
            "window_bytes",
            "outcome",
            "learned_source_kind",
            "right_guarded",
        ):
            self.assertEqual(
                {row[field] for row in selected},
                {row[field] for row in rows},
            )


class ControllerTests(unittest.TestCase):
    def test_cpu_envelope(self) -> None:
        self.assertEqual(
            controller.parse_cpus(
                "0,1,2,3,4,5,6,7",
                "zstd-eval-c9g-neoverse-v3-aarch64-asimd",
            ),
            tuple(range(8)),
        )
        self.assertEqual(
            controller.parse_cpus(
                "12,13,14,15,16,17",
                "local-apple-aarch64-asimd",
            ),
            tuple(range(12, 18)),
        )
        with self.assertRaises(controller.Refusal):
            controller.parse_cpus(
                "0,1,2,3,4,5,6",
                "zstd-eval-c9g-neoverse-v3-aarch64-asimd",
            )
        with self.assertRaises(controller.Refusal):
            controller.parse_cpus(
                "0,1,2,3,4,5,6,6",
                "zstd-eval-c9g-neoverse-v3-aarch64-asimd",
            )
        with self.assertRaises(controller.Refusal):
            controller.parse_cpus(
                "12,13,14,15,16,0",
                "local-apple-aarch64-asimd",
            )


class GateTests(unittest.TestCase):
    def test_complete_universal_projection_uses_strict_cell_gate(self) -> None:
        cells = [cell(Fraction(4, 5) - Fraction(1, 1_000_000))]
        cells.extend(cell() for _ in range(3_077))
        receipt = analyzer.evaluate_universal_host("test-host", cells)
        self.assertTrue(receipt["pass"])
        self.assertFalse(receipt["aggregate_rescue_permitted"])
        self.assertIn(
            "width_topology=6:binary-aperiodic",
            receipt["strata_completeness"],
        )
        cells[0] = cell(Fraction(4, 5))
        with self.assertRaises(analyzer.Refusal):
            analyzer.evaluate_universal_host("test-host", cells)

    def test_complete_long_projection_passes(self) -> None:
        cells = [cell() for _ in range(1_458)]
        receipt = analyzer.evaluate_long_host("test-host", cells)
        self.assertTrue(receipt["pass"])
        self.assertEqual(receipt["strict_pairs"], 1_458 * 6)

    def test_individual_cell_limit_is_inclusive(self) -> None:
        cells = [cell() for _ in range(1_458)]
        cells[0] = cell(Fraction(21, 20))
        receipt = analyzer.evaluate_long_host("test-host", cells)
        self.assertTrue(receipt["pass"])
        cells[0] = cell(Fraction(21, 20) + Fraction(1, 1_000_000))
        with self.assertRaises(analyzer.Refusal):
            analyzer.evaluate_long_host("test-host", cells)

    def test_strict_pair_fraction_uses_complete_host_projection(self) -> None:
        cells = [cell(strict_wins=0) for _ in range(1_458)]
        remaining = 6_999
        for index in range(len(cells)):
            wins = min(6, remaining)
            cells[index] = cell(strict_wins=wins)
            remaining -= wins
        self.assertEqual(remaining, 0)
        receipt = analyzer.evaluate_long_host("test-host", cells)
        self.assertEqual(receipt["strict_pair_wins"], 6_999)
        cells[0] = cell(strict_wins=5)
        with self.assertRaises(analyzer.Refusal):
            analyzer.evaluate_long_host("test-host", cells)

    def test_geomean_gate_is_not_pooled_timing(self) -> None:
        cells = [cell(Fraction(9, 10)) for _ in range(1_458)]
        with self.assertRaises(analyzer.Refusal):
            analyzer.evaluate_long_host("test-host", cells)
        exact_boundary = [cell(Fraction(4, 5)) for _ in range(1_458)]
        with self.assertRaises(analyzer.Refusal):
            analyzer.evaluate_long_host("test-host", exact_boundary)


class ImmutabilityTests(unittest.TestCase):
    def test_stable_open_regular_file_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            path = Path(raw_directory) / "stable.txt"
            path.write_bytes(b"stable\n")
            source, before = analyzer.open_regular(path)
            with source:
                self.assertEqual(source.read(), b"stable\n")
                analyzer.unchanged(source, before, "stable")

    def test_timing_pairs_share_calibration_and_checksum(self) -> None:
        expected = analyzer.ProjectionExpectation(
            row_sha256="1" * 64,
            literal_sha256="2" * 64,
            selector_eligible=True,
            compiler_disposition="tag30-object",
            expected_route="tag30-static-tail",
            expected_static_invoked=True,
            expected_span=None,
            right_guarded=False,
            physical_mod16=3,
        )
        row = {
            "literal_sha256": expected.literal_sha256,
            "literal_bytes": 6,
            "topology": "binary-aperiodic",
            "mutation_class": 5,
            "learned_source_kind": "primary",
            "learned_source_relations": ["equals-primary"],
            "literal_phase_class": 0,
            "selector_primary_offset_class": 0,
            "logical_prefix_bytes": 3,
            "window_bytes": 65_536,
            "outcome": "absent",
            "right_guarded": False,
            "expected_route": "tag30-static-tail",
        }
        pairs = [
            {
                "repetition": repetition,
                "order": (
                    "portable-first"
                    if repetition % 2 == 0
                    else "candidate-first"
                ),
                "iterations": 14,
                "portable_elapsed_ns": 500_000_000,
                "candidate_elapsed_ns": 450_000_000,
                "portable_checksum": 7,
                "candidate_checksum": 7,
                "portable_cpu_before": 3,
                "portable_cpu_after": 3,
                "portable_cpu_retries": 0,
                "portable_cpu_attempts": [
                    {
                        "attempt": 0,
                        "cpu_before": 3,
                        "cpu_after": 3,
                        "accepted": True,
                    }
                ],
                "candidate_cpu_before": 3,
                "candidate_cpu_after": 3,
                "candidate_cpu_retries": 0,
                "candidate_cpu_attempts": [
                    {
                        "attempt": 0,
                        "cpu_before": 3,
                        "cpu_after": 3,
                        "accepted": True,
                    }
                ],
            }
            for repetition in range(6)
        ]

        def calibration_anchor(elapsed_ns: int) -> dict[str, object]:
            return {
                "iterations": 1,
                "elapsed_ns": elapsed_ns,
                "checksum": 1,
                "cpu_before": 3,
                "cpu_after": 3,
                "cpu_retries": 0,
                "cpu_attempts": [
                    {
                        "attempt": 0,
                        "cpu_before": 3,
                        "cpu_after": 3,
                        "accepted": True,
                    }
                ],
            }

        record = {
            "schema": analyzer.TIMING_SCHEMA,
            "ordinal": 0,
            "row_sha256": expected.row_sha256,
            **row,
            "candidate_call": "direct-v17",
            "mapping": {
                "kind": "right-padded",
                "haystack_start_offset": 32,
                "haystack_bytes": 64,
                "guard_page": False,
            },
            "actual_window_start_mod16": 3,
            "logical_cpu": 3,
            "minimum_elapsed_ns_each_variant": analyzer.MINIMUM_NS,
            "calibration": {
                "target_elapsed_ns": analyzer.CALIBRATION_TARGET_NS,
                "floor_elapsed_ns": analyzer.CALIBRATION_FLOOR_NS,
                "anchor_samples": analyzer.CALIBRATION_ANCHOR_SAMPLES,
                "maximum_iterations": analyzer.MAXIMUM_ITERATIONS,
                "selected_iterations": 14,
                "portable_pilots": [
                    calibration_anchor(50_000_000),
                    calibration_anchor(44_000_000),
                    calibration_anchor(48_000_000),
                ],
                "candidate_pilots": [
                    calibration_anchor(50_000_000),
                    calibration_anchor(44_000_000),
                    calibration_anchor(48_000_000),
                ],
            },
            "pairs": pairs,
            "pass": True,
            "rebar_accepted_as_input": False,
        }
        analyzer.parse_timing_record(
            record, expected, row, 0, "universal", 3
        )
        pairs[1]["iterations"] = 15
        with self.assertRaises(analyzer.Refusal):
            analyzer.parse_timing_record(
                record, expected, row, 0, "universal", 3
            )
        pairs[1]["iterations"] = 14
        pairs[1]["portable_checksum"] = 9
        pairs[1]["candidate_checksum"] = 9
        with self.assertRaises(analyzer.Refusal):
            analyzer.parse_timing_record(
                record, expected, row, 0, "universal", 3
            )
        pairs[1]["portable_checksum"] = 7
        pairs[1]["candidate_checksum"] = 7
        record["calibration"]["anchor_samples"] = 2
        with self.assertRaises(analyzer.Refusal):
            analyzer.parse_timing_record(
                record, expected, row, 0, "universal", 3
            )
        record["calibration"]["anchor_samples"] = (
            analyzer.CALIBRATION_ANCHOR_SAMPLES
        )
        removed_anchor = record["calibration"]["candidate_pilots"].pop()
        with self.assertRaises(analyzer.Refusal):
            analyzer.parse_timing_record(
                record, expected, row, 0, "universal", 3
            )
        record["calibration"]["candidate_pilots"].append(removed_anchor)
        candidate_anchor = record["calibration"]["candidate_pilots"][-1]
        candidate_anchor["iterations"] = 2
        with self.assertRaises(analyzer.Refusal):
            analyzer.parse_timing_record(
                record, expected, row, 0, "universal", 3
            )
        candidate_anchor["iterations"] = 1
        record["calibration"]["selected_iterations"] = 12
        for pair in pairs:
            pair["iterations"] = 12
        with self.assertRaises(analyzer.Refusal):
            analyzer.parse_timing_record(
                record, expected, row, 0, "universal", 3
            )
        record["calibration"]["selected_iterations"] = 14
        for pair in pairs:
            pair["iterations"] = 14
        candidate_anchor["checksum"] = 2
        with self.assertRaises(analyzer.Refusal):
            analyzer.parse_timing_record(
                record, expected, row, 0, "universal", 3
            )
        candidate_anchor["checksum"] = 1
        record["logical_cpu"] = 12
        for pilots in (
            record["calibration"]["portable_pilots"],
            record["calibration"]["candidate_pilots"],
        ):
            for pilot in pilots:
                pilot["cpu_before"] = 12
                pilot["cpu_after"] = 12
                pilot["cpu_retries"] = 0
                pilot["cpu_attempts"] = [
                    {
                        "attempt": 0,
                        "cpu_before": 12,
                        "cpu_after": 12,
                        "accepted": True,
                    }
                ]
        portable_pilot = record["calibration"]["portable_pilots"][0]
        portable_pilot["cpu_before"] = 12
        portable_pilot["cpu_after"] = 13
        portable_pilot["cpu_retries"] = 1
        portable_pilot["cpu_attempts"] = [
            {
                "attempt": 0,
                "cpu_before": 0,
                "cpu_after": 12,
                "accepted": False,
            },
            {
                "attempt": 1,
                "cpu_before": 12,
                "cpu_after": 13,
                "accepted": True,
            },
        ]
        for pair in pairs:
            for variant in ("portable", "candidate"):
                pair[f"{variant}_cpu_before"] = 12
                pair[f"{variant}_cpu_after"] = 12
                pair[f"{variant}_cpu_retries"] = 0
                pair[f"{variant}_cpu_attempts"] = [
                    {
                        "attempt": 0,
                        "cpu_before": 12,
                        "cpu_after": 12,
                        "accepted": True,
                    }
                ]
        pairs[0]["portable_cpu_before"] = 12
        pairs[0]["portable_cpu_after"] = 13
        pairs[0]["portable_cpu_retries"] = 1
        pairs[0]["portable_cpu_attempts"] = [
            {
                "attempt": 0,
                "cpu_before": 0,
                "cpu_after": 12,
                "accepted": False,
            },
            {
                "attempt": 1,
                "cpu_before": 12,
                "cpu_after": 13,
                "accepted": True,
            },
        ]
        analyzer.parse_timing_record(
            record,
            expected,
            row,
            0,
            "universal",
            12,
            analyzer.HOSTS[0],
        )
        pairs[0]["portable_cpu_attempts"][0]["cpu_before"] = 12
        with self.assertRaises(analyzer.Refusal):
            analyzer.parse_timing_record(
                record,
                expected,
                row,
                0,
                "universal",
                12,
                analyzer.HOSTS[0],
            )

    def test_output_is_create_new(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            output = Path(raw_directory) / "existing.json"
            output.write_text("{}\n", encoding="utf-8")
            descriptor_flags = (
                __import__("os").O_WRONLY
                | __import__("os").O_CREAT
                | __import__("os").O_EXCL
            )
            with self.assertRaises(FileExistsError):
                __import__("os").open(output, descriptor_flags, 0o444)

    def test_fragment_parser_authenticates_exact_record_and_trailer(self) -> None:
        expected = analyzer.ProjectionExpectation(
            row_sha256="1" * 64,
            literal_sha256="2" * 64,
            selector_eligible=False,
            compiler_disposition="structural-refusal",
            expected_route="portable-only",
            expected_static_invoked=False,
            expected_span=None,
            right_guarded=False,
            physical_mod16=3,
        )
        spec = {
            "schema": "test.projection.v1",
            "domain": b"test",
            "rows": 1,
            "sha256": "3" * 64,
            "static_rows": 0,
            "portable_rows": 1,
        }
        header = {
            "schema": analyzer.HEADER_SCHEMA,
            "contract_schema": analyzer.CONTRACT_SCHEMA,
            "contract_sha256": analyzer.CONTRACT_SHA256,
            "mode": "correctness",
            "projection_kind": "universal",
            "projection_schema": spec["schema"],
            "projection_rows": 1,
            "projection_sha256": spec["sha256"],
            "shard_id": 0,
            "shard_start": 0,
            "shard_end": 1,
            "host_id": analyzer.HOSTS[0],
            "logical_cpu": 12,
            "cpu_residence_method": (
                "macos-user-interactive-qos-affinity-hint-bounded-super-"
                "wait-cpu-only-retry"
            ),
            "affinity_request_status": 46,
            "qos_class": 0x21,
            "qos_request_status": 0,
            "accepted_cpu_class": "Super",
            "accepted_cpu_ids": list(analyzer.MACOS_SUPER_CPUS),
            "macos_performance_levels": (
                analyzer.MACOS_PERFORMANCE_LEVEL_RECEIPT
            ),
            "macos_super_class_wait_timeout_ns": (
                analyzer.MACOS_SUPER_CLASS_WAIT_TIMEOUT_NS
            ),
            "maximum_cpu_only_retries_per_variant": 64,
            "runner_source_sha256": "4" * 64,
            "runner_binary_sha256": "5" * 64,
            "runner_identity_sha256": "6" * 64,
            "compiler_identity": "8" * 64,
            "platform_manifest_identity": "9" * 64,
            "build_receipt_sha256": "a" * 64,
            "object_candidate_manifest_sha256": "7" * 64,
            "backend_tag": 30,
            "backend_name": "AsimdV17",
            "family_selector": 13,
            "minimum_window_bytes": 65_536,
            "portable_prefix_candidate_starts": 256,
            "timing_repetitions": None,
            "minimum_elapsed_ns_each_variant": None,
            "rebar_accepted_as_input": False,
            "result_derived_exclusions": False,
        }
        record = {
            "schema": analyzer.CORRECTNESS_SCHEMA,
            "ordinal": 0,
            "row_sha256": expected.row_sha256,
            "literal_sha256": expected.literal_sha256,
            "selector_eligible": False,
            "expected_compiler_disposition": "structural-refusal",
            "expected_route": "portable-only",
            "expected_static_invoked": False,
            "scalar_span": None,
            "portable_span": None,
            "direct_v17_span": None,
            "automatic_long_policy_span": None,
            "mapping": {
                "kind": "right-padded",
                "haystack_start_offset": 32,
                "haystack_bytes": 64,
                "guard_page": False,
            },
            "actual_window_start_mod16": 3,
            "worker_logical_cpu": 12,
            "pass": True,
        }
        record_line = analyzer.canonical_bytes(record) + b"\n"
        digest = hashlib.sha256()
        digest.update(len(record_line).to_bytes(8, "little"))
        digest.update(record_line)
        trailer = {
            "schema": analyzer.TRAILER_SCHEMA,
            "rows": 1,
            "shard_start": 0,
            "shard_end": 1,
            "records_sha256": digest.hexdigest(),
            "complete": True,
        }
        encoded = b"".join(
            (
                analyzer.canonical_bytes(header) + b"\n",
                record_line,
                analyzer.canonical_bytes(trailer) + b"\n",
            )
        )
        with tempfile.TemporaryDirectory() as raw_directory:
            path = Path(raw_directory) / "fragment.jsonl"
            path.write_bytes(encoded)
            path.chmod(0o444)
            original = analyzer.PROJECTIONS[("universal", "correctness")]
            analyzer.PROJECTIONS[("universal", "correctness")] = spec
            try:
                changed_wait = dict(header)
                changed_wait["macos_super_class_wait_timeout_ns"] -= 1
                with self.assertRaises(analyzer.Refusal):
                    analyzer.parse_header(
                        changed_wait,
                        analyzer.HOSTS[0],
                        "correctness",
                        "universal",
                        0,
                        0,
                        1,
                    )
                parsed = analyzer.parse_fragment(
                    path,
                    analyzer.HOSTS[0],
                    "correctness",
                    "universal",
                    0,
                    [expected],
                    (),
                )
                self.assertEqual(parsed.static_rows, 0)
                self.assertEqual(parsed.portable_rows, 1)
                path.chmod(0o644)
                with self.assertRaises(analyzer.Refusal):
                    analyzer.parse_fragment(
                        path,
                        analyzer.HOSTS[0],
                        "correctness",
                        "universal",
                        0,
                        [expected],
                        (),
                    )
            finally:
                analyzer.PROJECTIONS[("universal", "correctness")] = original


if __name__ == "__main__":
    unittest.main()
