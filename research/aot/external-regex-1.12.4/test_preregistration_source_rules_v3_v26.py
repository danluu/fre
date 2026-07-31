#!/usr/bin/env python3
"""Tests for the result-blind external Search-V26 source authority."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

import validate_preregistration_source_rules_v3_v26 as rules


ROOT = Path(__file__).resolve().parent
V3_PATH = ROOT / "preregistration-source-rules-v3-v26.json"
V2_PATH = ROOT / "preregistration-source-rules-v2.json"


class V26SourceRulesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.payload = json.loads(V3_PATH.read_bytes())["payload"]
        self.inherited = json.loads(V2_PATH.read_bytes())["payload"]

    def refusal(self, mutate: object) -> None:
        payload = copy.deepcopy(self.payload)
        mutate(payload)
        with self.assertRaises(rules.Refusal):
            rules.validate_payload(payload, self.inherited)

    def test_exact_checked_in_authority_passes(self) -> None:
        result = rules.validate(V3_PATH)
        self.assertEqual(result["candidate_literal_widths"], "9..32")
        self.assertEqual(result["production_window_floor"], 65_536)
        self.assertFalse(result["heldout_source_materialized"])

    def test_corpus_partition_or_fixture_drift_is_refused(self) -> None:
        for section in ("source", "selection", "partition", "fixtures"):
            with self.subTest(section=section):
                self.refusal(
                    lambda payload, section=section: payload[section].update(
                        {"unexpected": True}
                    )
                )
        self.refusal(lambda payload: payload["hosts"].append("result-selected-host"))

    def test_result_or_rebar_derived_membership_is_refused(self) -> None:
        self.refusal(
            lambda payload: payload["independence"].update(
                {"result_derived_selection": True}
            )
        )
        self.refusal(
            lambda payload: payload["independence"].update(
                {"rebar_inputs": ["benchmark-manifest"]}
            )
        )
        self.refusal(
            lambda payload: payload["v26_projection"].update(
                {"rebar_or_benchmark_membership_input": True}
            )
        )

    def test_development_result_or_heldout_reveal_is_refused(self) -> None:
        self.refusal(
            lambda payload: payload["v26_development_gate"].update(
                {"candidate_result_read_before_this_freeze": True}
            )
        )
        self.refusal(
            lambda payload: payload["independence"].update(
                {"heldout_source_materialized": True}
            )
        )

    def test_short_width_or_benchmark_specific_route_is_refused(self) -> None:
        self.refusal(
            lambda payload: payload["final_engine_requirements"].update(
                {"candidate_minimum_literal_bytes": 8}
            )
        )
        self.refusal(
            lambda payload: payload["v26_projection"].update(
                {"candidate_literal_widths": "selected-benchmark-widths"}
            )
        )

    def test_llvm_wrong_backend_or_timed_construction_is_refused(self) -> None:
        self.refusal(
            lambda payload: payload["final_engine_requirements"].update(
                {"llvm": True}
            )
        )
        self.refusal(
            lambda payload: payload["final_engine_requirements"].update(
                {"backend_tag": 38}
            )
        )
        self.refusal(
            lambda payload: payload["final_engine_requirements"].update(
                {"construction_link_adoption_timed": True}
            )
        )

    def test_weakened_speed_or_tail_risk_gate_is_refused(self) -> None:
        self.refusal(
            lambda payload: payload["qualification_requirements"].update(
                {
                    "per_host_candidate_over_portable_equal_cell_geomean_ppm_lte": 900_000
                }
            )
        )
        self.refusal(
            lambda payload: payload["qualification_requirements"].update(
                {"per_host_maximum_cell_ratio_ppm_lte": 1_200_000}
            )
        )
        self.refusal(
            lambda payload: payload["qualification_requirements"].update(
                {"aggregate_rescue_for_failed_host_band_or_scenario": True}
            )
        )


if __name__ == "__main__":
    unittest.main()
