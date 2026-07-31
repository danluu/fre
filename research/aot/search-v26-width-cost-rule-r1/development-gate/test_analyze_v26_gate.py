#!/usr/bin/env python3

import copy
import hashlib
import json
import math
import os
import tempfile
import unittest
from fractions import Fraction
from pathlib import Path

import analyze_v26_gate as gate


def full_ratio_map(
    default: Fraction = Fraction(7, 10),
) -> dict[tuple[int, int, int, str], Fraction]:
    return {
        (width, gate.OUTPUT_TAGS[output], ordinal, window): default
        for width in range(6, 33)
        for output in gate.EXPECTED_OUTPUTS
        for ordinal in range(16)
        for window in gate.EXPECTED_WINDOWS
    }


def acceptance() -> dict[str, float | int | bool | str]:
    return copy.deepcopy(gate.EXPECTED_ACCEPTANCE)


def sample_cell_identity() -> dict:
    literal = gate.derive_literal(6, 1, 0)
    window_start, window_end, haystack_len, expected_match = gate.expected_geometry(
        6, 0, "no_match"
    )
    return {
        "cell_id": 0,
        "shard_id": 0,
        "population_sha256": (
            "a682375f2e6e051f97322396bafc46974df47baa3518bc17f5d6b71b56407b73"
        ),
        "width": 6,
        "output": "exists",
        "output_tag": 1,
        "accepted_ordinal": 0,
        "source_ordinal": 0,
        "literal_hex": literal.hex(),
        "literal_sha256": hashlib.sha256(literal).hexdigest(),
        "window_shape": "no_match",
        "window_shape_tag": 0,
        "fixture_recipe": "fre-search-v26-long-scan-fixture-v1",
        "filler_byte": gate.lowest_unused_byte(literal),
        "window_start": window_start,
        "window_end": window_end,
        "window_bytes": window_end - window_start,
        "haystack_len": haystack_len,
        "haystack_sha256": "1" * 64,
        "fixture_sha256": "2" * 64,
        "expected_match_start": None,
        "expected_match_end": None,
        "expected_output_sha256": gate.expected_output_sha256(1, expected_match),
    }


def sample_result() -> tuple[dict, dict]:
    expected = sample_cell_identity()
    repetitions = []
    for index, order in enumerate(gate.EXPECTED_ORDERS):
        repetitions.append(
            {
                "repetition": index,
                "order": list(order),
                "engines": {
                    "portable": {"elapsed_ns": 300, "iterations": 2},
                    "v17": {"elapsed_ns": 200, "iterations": 2},
                    "v26": {"elapsed_ns": 140, "iterations": 2},
                },
            }
        )
    digest = expected["expected_output_sha256"]
    calibration = {
        "iterations": 2,
        "elapsed_ns": 4_000_000,
        "previous_iterations": 1,
        "previous_elapsed_ns": 2_000_000,
    }
    result = {
        "schema": "fre-search-v26-development-gate-cell-result-v1",
        **expected,
        "semantics": {
            "equal": True,
            "expected": digest,
            "portable": digest,
            "v17": digest,
            "v26": digest,
        },
        "calibrations": {
            "portable": copy.deepcopy(calibration),
            "v17": copy.deepcopy(calibration),
            "v26": copy.deepcopy(calibration),
        },
        "repetitions": repetitions,
    }
    return expected, result


def sample_header(shard_id: int = 0, cpu_id: int = 120) -> dict:
    return {
        "schema": "fre-search-v26-development-gate-shard-header-v1",
        "shard_id": shard_id,
        "candidate_backend": 39,
        "reference_backend": 30,
        "source_commit": "1" * 40,
        "source_tree": "2" * 40,
        "source_archive_sha256": "3" * 64,
        "runner_binary_sha256": "4" * 64,
        "runner_binary_bytes": 1234,
        "contract_sha256": "5" * 64,
        "cell_manifest_sha256": "6" * 64,
        "host_fingerprint_sha256": "7" * 64,
        "cpu_id": cpu_id,
        "shard_nonce": "b" * 64,
        "run_nonce": "8" * 64,
        "one_shot_seal_sha256": "9" * 64,
        "run_manifest_sha256": "a" * 64,
    }


class AnalyzerTests(unittest.TestCase):
    def sealed_contract(self, cells_file: gate.StableFile) -> dict:
        source = Path(__file__).with_name("gate-contract-v1.json")
        contract = json.loads(source.read_text(encoding="utf-8"))
        contract["status"] = "SEALED_READY_FOR_ONE_SHOT_TIMING"
        contract["candidate"]["source_commit"] = "1" * 40
        contract["candidate"]["source_tree"] = "2" * 40
        contract["inputs"]["cell_manifest_sha256"] = cells_file.sha256
        contract["execution"]["sealing_authority"] = "seal-v1.json"
        return contract

    def test_estimators_are_exact(self) -> None:
        values = [Fraction(value) for value in range(1, 13)]
        self.assertEqual(gate.median12(values), Fraction(13, 2))
        self.assertTrue(
            math.isclose(gate.geomean([Fraction(1, 2), Fraction(2)]), 1.0)
        )
        with self.assertRaises(gate.GateError):
            gate.median12(values[:-1])
        with self.assertRaises(gate.GateError):
            gate.geomean([Fraction(0)])

    def test_complete_uniform_population_passes(self) -> None:
        report = gate.evaluate_thresholds(full_ratio_map(), acceptance())
        self.assertTrue(report["pass"])
        self.assertEqual(report["cells_strictly_over_1_05"], 0)
        self.assertTrue(math.isclose(report["overall_geomean"], 0.7))

    def test_tail_allowance_and_exact_boundaries(self) -> None:
        ratios = full_ratio_map()
        keys = list(ratios)
        for key in keys[:77]:
            ratios[key] = Fraction(53, 50)
        self.assertTrue(gate.evaluate_thresholds(ratios, acceptance())["pass"])
        ratios[keys[77]] = Fraction(53, 50)
        report = gate.evaluate_thresholds(ratios, acceptance())
        self.assertFalse(report["checks"]["tail_count"])

        ratios = full_ratio_map()
        ratios[keys[0]] = Fraction(21, 20)
        report = gate.evaluate_thresholds(ratios, acceptance())
        self.assertEqual(report["cells_strictly_over_1_05"], 0)

        ratios[keys[0]] = Fraction(11, 10)
        self.assertTrue(
            gate.evaluate_thresholds(ratios, acceptance())["checks"]["maximum"]
        )
        ratios[keys[0]] = Fraction(11_000_001, 10_000_000)
        self.assertFalse(
            gate.evaluate_thresholds(ratios, acceptance())["checks"]["maximum"]
        )

    def test_short_wide_output_and_window_gates_are_independent(self) -> None:
        ratios = full_ratio_map()
        for key in ratios:
            if key[0] <= 8:
                ratios[key] = Fraction(103, 100)
        self.assertFalse(gate.evaluate_thresholds(ratios, acceptance())["checks"]["short"])

        ratios = full_ratio_map()
        for key in ratios:
            if key[1] == 1:
                ratios[key] = Fraction(103, 100)
        self.assertFalse(
            gate.evaluate_thresholds(ratios, acceptance())["checks"]["outputs"]
        )

        ratios = full_ratio_map()
        for key in ratios:
            if key[3] == "no_match":
                ratios[key] = Fraction(103, 100)
        self.assertFalse(
            gate.evaluate_thresholds(ratios, acceptance())["checks"]["windows"]
        )

    def test_result_recomputes_fraction_and_rejects_identity_drift(self) -> None:
        expected, result = sample_result()
        self.assertEqual(
            gate.validate_cell_result(result, expected), Fraction(7, 10)
        )

        wrong_order = copy.deepcopy(result)
        wrong_order["repetitions"][0]["order"] = ["v17", "portable", "v26"]
        with self.assertRaises(gate.GateError):
            gate.validate_cell_result(wrong_order, expected)

        output_drift = copy.deepcopy(result)
        output_drift["output"] = "span"
        with self.assertRaises(gate.GateError):
            gate.validate_cell_result(output_drift, expected)

        mismatch = copy.deepcopy(result)
        mismatch["semantics"]["v26"] = "b" * 64
        with self.assertRaises(gate.GateError):
            gate.validate_cell_result(mismatch, expected)

        extra_key = copy.deepcopy(result)
        extra_key["trusted_summary"] = True
        with self.assertRaises(gate.GateError):
            gate.validate_cell_result(extra_key, expected)

    def test_calibration_chain_and_sample_count_are_mandatory(self) -> None:
        expected, result = sample_result()
        drift = copy.deepcopy(result)
        drift["calibrations"]["v26"]["previous_elapsed_ns"] = 4_000_000
        with self.assertRaises(gate.GateError):
            gate.validate_cell_result(drift, expected)

        drift = copy.deepcopy(result)
        drift["calibrations"]["v26"]["previous_iterations"] = 2
        with self.assertRaises(gate.GateError):
            gate.validate_cell_result(drift, expected)

        drift = copy.deepcopy(result)
        drift["repetitions"][0]["engines"]["v26"]["iterations"] = 1
        with self.assertRaises(gate.GateError):
            gate.validate_cell_result(drift, expected)

    def test_strict_json_rejects_duplicate_keys_and_nonfinite_numbers(self) -> None:
        with self.assertRaises(gate.GateError):
            gate.strict_json_loads(b'{"a":1,"a":2}', "duplicate")
        for spelling in (b"NaN", b"Infinity", b"-Infinity"):
            with self.assertRaises(gate.GateError):
                gate.strict_json_loads(b'{"value":' + spelling + b"}", "nonfinite")

    def test_numeric_fields_reject_string_and_bool_coercion(self) -> None:
        base = {
            "width": 6,
            "output_tag": 1,
            "accepted_ordinal": 0,
            "window_shape": "no_match",
        }
        for field, value in (("width", "6"), ("output_tag", True)):
            mutated = dict(base)
            mutated[field] = value
            with self.assertRaises(gate.GateError):
                gate.cell_key(mutated)

    def test_header_requires_every_exact_sealed_identity(self) -> None:
        expected = sample_header()
        gate.validate_shard_header(expected, 0, expected)
        mutated = dict(expected)
        mutated["cpu_id"] = 130
        with self.assertRaises(gate.GateError):
            gate.validate_shard_header(mutated, 0, expected)
        mutated = dict(expected)
        mutated["extra"] = "unsealed"
        with self.assertRaises(gate.GateError):
            gate.validate_shard_header(mutated, 0, expected)

    def test_absolute_expected_output_coordinates_include_nonzero_window_start(self) -> None:
        absolute = gate.expected_output_sha256(3, (32, 38))
        relative = gate.expected_output_sha256(3, (0, 6))
        self.assertNotEqual(absolute, relative)

    def test_sealed_contract_cannot_relax_thresholds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cells_path = root / "cells.jsonl"
            cells_path.write_text("{}\n", encoding="utf-8")
            cells_path.chmod(0o444)
            cells_file = gate.stable_read(cells_path, gate.MAX_CELL_MANIFEST_BYTES)
            contract_path = root / "contract.json"
            contract = self.sealed_contract(cells_file)
            contract_path.write_text(json.dumps(contract) + "\n", encoding="utf-8")
            contract_path.chmod(0o444)
            contract_file = gate.stable_read(
                contract_path, gate.MAX_CONTRACT_BYTES
            )
            gate.require_exact_contract(contract, contract_file, cells_file)

            contract["acceptance"]["overall_geomean_lte"] = 0.9
            with self.assertRaises(gate.GateError):
                gate.require_exact_contract(contract, contract_file, cells_file)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_stable_read_rejects_symlink_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.write_bytes(b"{}\n")
            link = root / "link"
            link.symlink_to(target)
            with self.assertRaises(gate.GateError):
                gate.stable_read(link, 1024)


if __name__ == "__main__":
    unittest.main()
