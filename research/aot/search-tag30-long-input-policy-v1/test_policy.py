#!/usr/bin/env python3
"""Adversarial tests for the frozen tag-30 long-input policy."""

from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path
from types import ModuleType


HERE = Path(__file__).resolve().parent


def load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


derivation = load_module("tag30_long_derivation", HERE / "derive_projection.py")
validator = load_module("tag30_long_validator", HERE / "validate_policy.py")


class LongInputPolicyTests(unittest.TestCase):
    def row(
        self,
        identity_byte: int,
        input_bytes: int,
        disposition: str = "tag30-object",
    ) -> dict[str, object]:
        return {
            "schema": "fre.aot.search-tag30-learned-continuation-projection.v1",
            "row_sha256": f"{identity_byte:02x}" * 32,
            "expected_compiler_disposition": disposition,
            "window_bytes": input_bytes,
            "expected_route": "tag30-static-tail",
            "expected_static_invoked": True,
        }

    def test_route_floor_is_exact_and_refusals_never_enter(self) -> None:
        below = derivation.policy_row(self.row(1, 65_535))
        boundary = derivation.policy_row(self.row(2, 65_536))
        refused = derivation.policy_row(
            self.row(3, 1_048_576, "structural-refusal")
        )
        self.assertEqual(below["expected_route"], "portable-only")
        self.assertFalse(below["expected_static_invoked"])
        self.assertEqual(boundary["expected_route"], "tag30-static-tail")
        self.assertTrue(boundary["expected_static_invoked"])
        self.assertEqual(refused["expected_route"], "portable-only")
        self.assertFalse(refused["expected_static_invoked"])

    def test_payload_mutation_breaks_the_frozen_digest(self) -> None:
        freeze = json.loads((HERE / "freeze-v1.json").read_bytes())
        payload = freeze["payload"]
        self.assertEqual(
            validator.sha256(validator.canonical_bytes(payload)),
            validator.PAYLOAD_SHA256,
        )
        for path, replacement in (
            (("policy", "production_input_floor_bytes"), 65_535),
            (("policy", "rebar_effect"), "selector-input"),
            (("gates", "individual_cell_inclusive_maximum"), 1.50),
            (("status", "production_authority_granted"), True),
        ):
            mutant = copy.deepcopy(payload)
            mutant[path[0]][path[1]] = replacement
            self.assertNotEqual(
                validator.sha256(validator.canonical_bytes(mutant)),
                validator.PAYLOAD_SHA256,
            )

    def test_complete_procedural_projection_revalidates(self) -> None:
        receipt = validator.validate(Path.cwd().resolve(strict=True))
        self.assertEqual(receipt["full_rows"], 123_424)
        self.assertEqual(receipt["timed_rows"], 1_458)
        self.assertEqual(receipt["unique_literals"], 808)
        self.assertFalse(receipt["production_authority_granted"])


if __name__ == "__main__":
    unittest.main()
