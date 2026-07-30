#!/usr/bin/env python3

import importlib.util
import unittest
from pathlib import Path


CONTROLLER_PATH = Path(__file__).with_name("production_confirm.py")
CONTROLLER_SPEC = importlib.util.spec_from_file_location(
    "production_confirm", CONTROLLER_PATH
)
assert CONTROLLER_SPEC is not None and CONTROLLER_SPEC.loader is not None
production_confirm = importlib.util.module_from_spec(CONTROLLER_SPEC)
CONTROLLER_SPEC.loader.exec_module(production_confirm)


def eligibility(**changes):
    row = {
        "compiler_version": 3,
        "metadata_version": 3,
        "image_schema_version": 3,
        "backend_version": 0xA003,
        "algorithm_version": 11,
        "auditor_version": 3,
        "kir_semantics_version": 1,
        "kir_abi_version": 1,
        "recipe_schema_version": 3,
        "optimizer_version": 3,
        "tuning_class_id": 3,
        "strategy_id": 2,
        "schedule_id": 2,
        "register_plan_id": 4,
        "literal_bytes": 6,
        "filter_len": 2,
        "sparse_group_count": 2,
        "match_stride": 6,
        "periodic_stride": 0,
        "call_abi_schema": 2,
        "abi_kind": 1,
        "status_bits": 64,
        "output_kind": 1,
        "architecture": 1,
        "little_endian": True,
        "pointer_width": 64,
        "target_abi": 1,
        "object_format": 2,
        "required_isa_id": 2,
        "actual_features": 3,
        "allowed_features": 3,
        "candidate_block_starts": 16,
        "vector_bytes": 16,
        "sve_vector_length_bytes": 16,
        "max_literal_bytes": 32,
    }
    row.update(changes)
    return row


class EligibilityTargetTests(unittest.TestCase):
    def test_production_confirmation_floor_is_64_kib(self) -> None:
        self.assertEqual(production_confirm.MINIMUM_INVENTORY_BYTES, 4_096)
        self.assertEqual(production_confirm.MINIMUM_AOT_BYTES, 65_536)
        self.assertEqual(
            production_confirm.LONG_SCAN_POLICY,
            "minimum-haystack-65536-bytes-v1",
        )
        with self.assertRaises(production_confirm.ConfirmationError):
            production_confirm.require_uint(
                65_535,
                production_confirm.MINIMUM_AOT_BYTES,
                1 << 40,
                "input bytes",
            )
        self.assertEqual(
            production_confirm.require_uint(
                65_536,
                production_confirm.MINIMUM_AOT_BYTES,
                1 << 40,
                "input bytes",
            ),
            65_536,
        )

    def test_only_selected_production_cells_must_reach_64_kib(self) -> None:
        cells = {
            "cell-below-floor": {
                "cell_id": "cell-below-floor",
                "input_bytes": 4_096,
            },
            "cell-production": {
                "cell_id": "cell-production",
                "input_bytes": 65_536,
            },
        }
        self.assertEqual(
            production_confirm.select_production_cells(
                cells, [{"cell_id": "cell-production"}]
            ),
            {"cell-production": cells["cell-production"]},
        )
        with self.assertRaisesRegex(
            production_confirm.ConfirmationError,
            "selected production cell cell-below-floor input bytes",
        ):
            production_confirm.select_production_cells(
                cells, [{"cell_id": "cell-below-floor"}]
            )

    def test_accepts_closed_neon_sve_and_sve2_targets(self) -> None:
        for row in [
            eligibility(
                required_isa_id=1,
                register_plan_id=1,
                actual_features=1,
                allowed_features=1,
                sve_vector_length_bytes=0,
            ),
            eligibility(),
            eligibility(
                required_isa_id=3,
                register_plan_id=5,
                actual_features=7,
                allowed_features=7,
            ),
        ]:
            self.assertEqual(
                production_confirm._validate_eligibility_tuple(row, "tuple"), row
            )

    def test_rejects_legacy_pure_sve_plans_and_missing_asimd(self) -> None:
        for row in [
            eligibility(register_plan_id=2, actual_features=2, allowed_features=2),
            eligibility(actual_features=2, allowed_features=2),
            eligibility(
                required_isa_id=3,
                register_plan_id=3,
                actual_features=6,
                allowed_features=6,
            ),
            eligibility(
                required_isa_id=3,
                register_plan_id=5,
                actual_features=6,
                allowed_features=6,
            ),
        ]:
            with self.assertRaises(production_confirm.ConfirmationError):
                production_confirm._validate_eligibility_tuple(row, "tuple")

    def test_rejects_cross_plan_macho_or_non_vl16_sve(self) -> None:
        for row in [
            eligibility(register_plan_id=5),
            eligibility(object_format=1),
            eligibility(sve_vector_length_bytes=32),
            eligibility(vector_bytes=32),
            eligibility(candidate_block_starts=32),
        ]:
            with self.assertRaises(production_confirm.ConfirmationError):
                production_confirm._validate_eligibility_tuple(row, "tuple")


if __name__ == "__main__":
    unittest.main()
