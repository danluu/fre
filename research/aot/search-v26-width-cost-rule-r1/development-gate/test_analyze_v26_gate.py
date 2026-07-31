#!/usr/bin/env python3

import copy
import json
import math
import tempfile
import unittest
from pathlib import Path

import analyze_v26_gate as gate


def full_ratio_map(default: float = 0.7) -> dict[tuple[int, int, int, str], float]:
    return {
        (width, {"exists": 1, "span": 3, "selected_end": 2}[output], ordinal, window): default
        for width in range(6, 33)
        for output in gate.EXPECTED_OUTPUTS
        for ordinal in range(16)
        for window in gate.EXPECTED_WINDOWS
    }


def acceptance() -> dict[str, float | int | bool]:
    return {
        "exact_semantics": True,
        "overall_geomean_lte": 0.8,
        "short_width_6_through_8_geomean_lte": 1.02,
        "wide_width_9_through_32_geomean_lte": 0.8,
        "every_output_geomean_lte": 1.02,
        "every_window_shape_geomean_lte": 1.02,
        "cells_strictly_over_1_05_lte": 77,
        "cells_strictly_over_1_05_fraction_lte": 0.01,
        "maximum_cell_ratio_lte": 1.1,
        "p95_nearest_rank": 7_388,
    }


def sample_result() -> tuple[dict, dict]:
    expected = {
        "cell_id": 0,
        "width": 6,
        "output": "exists",
        "output_tag": 1,
        "accepted_ordinal": 0,
        "window_shape": "no_match",
        "literal_sha256": "1" * 64,
        "fixture_sha256": "2" * 64,
        "shard_id": 0,
    }
    repetitions = []
    for index, order in enumerate(gate.EXPECTED_ORDERS):
        repetitions.append(
            {
                "repetition": index,
                "order": list(order),
                "engines": {
                    "portable": {"elapsed_ns": 300, "iterations": 1},
                    "v17": {"elapsed_ns": 200, "iterations": 2},
                    "v26": {"elapsed_ns": 140, "iterations": 2},
                },
            }
        )
    result = {
        "schema": "fre-search-v26-development-gate-cell-result-v1",
        **expected,
        "semantics": {
            "equal": True,
            "portable": "a" * 64,
            "v17": "a" * 64,
            "v26": "a" * 64,
        },
        "repetitions": repetitions,
    }
    return expected, result


class AnalyzerTests(unittest.TestCase):
    def sealed_contract(self, cells_path: Path) -> dict:
        source = Path(__file__).with_name("gate-contract-v1.json")
        contract = json.loads(source.read_text(encoding="utf-8"))
        contract["status"] = "SEALED_READY_FOR_ONE_SHOT_TIMING"
        contract["candidate"]["source_commit"] = "1" * 40
        contract["candidate"]["source_tree"] = "2" * 40
        contract["inputs"]["cell_manifest_sha256"] = gate.sha256_file(cells_path)
        contract["execution"]["sealing_authority"] = "seal-v1.json"
        return contract

    def test_sealed_contract_cannot_relax_thresholds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cells_path = root / "cells.jsonl"
            cells_path.write_text("{}\n", encoding="utf-8")
            contract_path = root / "contract.json"
            contract = self.sealed_contract(cells_path)
            contract_path.write_text(json.dumps(contract) + "\n", encoding="utf-8")
            cells_path.chmod(0o444)
            contract_path.chmod(0o444)
            gate.require_exact_contract(contract, contract_path, cells_path)

            contract["acceptance"]["overall_geomean_lte"] = 0.9
            with self.assertRaises(gate.GateError):
                gate.require_exact_contract(contract, contract_path, cells_path)

    def test_estimators_are_exact(self) -> None:
        values = [float(value) for value in range(1, 13)]
        self.assertEqual(gate.median12(values), 6.5)
        self.assertTrue(math.isclose(gate.geomean([0.5, 2.0]), 1.0))
        with self.assertRaises(gate.GateError):
            gate.median12(values[:-1])
        with self.assertRaises(gate.GateError):
            gate.geomean([0.0])

    def test_complete_uniform_population_passes(self) -> None:
        report = gate.evaluate_thresholds(full_ratio_map(), acceptance())
        self.assertTrue(report["pass"])
        self.assertEqual(report["cells_strictly_over_1_05"], 0)
        self.assertTrue(math.isclose(report["overall_geomean"], 0.7))

    def test_tail_allowance_is_exactly_seventy_seven_cells(self) -> None:
        ratios = full_ratio_map()
        for key in list(ratios)[:77]:
            ratios[key] = 1.06
        self.assertTrue(gate.evaluate_thresholds(ratios, acceptance())["pass"])
        ratios[list(ratios)[77]] = 1.06
        report = gate.evaluate_thresholds(ratios, acceptance())
        self.assertFalse(report["pass"])
        self.assertFalse(report["checks"]["tail_count"])

    def test_short_wide_output_window_and_maximum_gates_are_independent(self) -> None:
        ratios = full_ratio_map()
        for key in ratios:
            if key[0] <= 8:
                ratios[key] = 1.03
        self.assertFalse(gate.evaluate_thresholds(ratios, acceptance())["checks"]["short"])

        ratios = full_ratio_map()
        for key in ratios:
            if key[1] == 1:
                ratios[key] = 1.03
        self.assertFalse(gate.evaluate_thresholds(ratios, acceptance())["checks"]["outputs"])

        ratios = full_ratio_map()
        for key in ratios:
            if key[3] == "no_match":
                ratios[key] = 1.03
        self.assertFalse(gate.evaluate_thresholds(ratios, acceptance())["checks"]["windows"])

        ratios = full_ratio_map()
        ratios[next(iter(ratios))] = 1.1000001
        self.assertFalse(gate.evaluate_thresholds(ratios, acceptance())["checks"]["maximum"])

    def test_raw_cell_recomputes_ratio_and_rejects_order_or_semantic_drift(self) -> None:
        expected, result = sample_result()
        self.assertTrue(math.isclose(gate.validate_cell_result(result, expected), 0.7))

        wrong_order = copy.deepcopy(result)
        wrong_order["repetitions"][0]["order"] = ["v17", "portable", "v26"]
        with self.assertRaises(gate.GateError):
            gate.validate_cell_result(wrong_order, expected)

        mismatch = copy.deepcopy(result)
        mismatch["semantics"]["v26"] = "b" * 64
        with self.assertRaises(gate.GateError):
            gate.validate_cell_result(mismatch, expected)

        nonfinite_proxy = copy.deepcopy(result)
        nonfinite_proxy["repetitions"][0]["engines"]["v26"]["elapsed_ns"] = 0
        with self.assertRaises(gate.GateError):
            gate.validate_cell_result(nonfinite_proxy, expected)


if __name__ == "__main__":
    unittest.main()
