#!/usr/bin/env python3
"""Mutation tests for the result-blind external-regex source-rule freeze."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


DIRECTORY = Path(__file__).resolve().parent
VALIDATOR_PATH = DIRECTORY / "validate_preregistration_source_rules_v2.py"
SPEC = importlib.util.spec_from_file_location("_source_rules_v2", VALIDATOR_PATH)
assert SPEC is not None and SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VALIDATOR
SPEC.loader.exec_module(VALIDATOR)


class SourceRuleFreezeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.authority = DIRECTORY / "preregistration-source-rules-v2.json"

    def write_mutation(self, value: dict[str, object]) -> Path:
        directory = Path(self.addCleanupContext(tempfile.TemporaryDirectory()))
        path = directory / "source-rules.json"
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        return path

    def addCleanupContext(self, context: tempfile.TemporaryDirectory[str]) -> str:
        value = context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        return value

    def test_exact_authority_passes(self) -> None:
        receipt = VALIDATOR.validate(self.authority)
        self.assertFalse(receipt["heldout_source_materialized"])
        self.assertFalse(receipt["rebar_accepted_as_input"])

    def test_rebar_input_mutation_refused(self) -> None:
        value = json.loads(self.authority.read_bytes())
        value["payload"]["independence"]["rebar_inputs"] = ["forbidden"]
        with self.assertRaisesRegex(VALIDATOR.Refusal, "file bytes changed"):
            VALIDATOR.validate(self.write_mutation(value))

    def test_result_derived_exclusion_mutation_refused(self) -> None:
        value = json.loads(self.authority.read_bytes())
        value["payload"]["independence"]["result_derived_exclusions"] = True
        with self.assertRaisesRegex(VALIDATOR.Refusal, "file bytes changed"):
            VALIDATOR.validate(self.write_mutation(value))

    def test_heldout_materialization_mutation_refused(self) -> None:
        value = json.loads(self.authority.read_bytes())
        value["payload"]["independence"]["heldout_source_materialized"] = True
        with self.assertRaisesRegex(VALIDATOR.Refusal, "file bytes changed"):
            VALIDATOR.validate(self.write_mutation(value))

    def test_gate_relaxation_mutation_refused(self) -> None:
        value = json.loads(self.authority.read_bytes())
        value["payload"]["qualification_requirements"][
            "aggregate_rescue_permitted"
        ] = True
        with self.assertRaisesRegex(VALIDATOR.Refusal, "file bytes changed"):
            VALIDATOR.validate(self.write_mutation(value))


if __name__ == "__main__":
    unittest.main()
