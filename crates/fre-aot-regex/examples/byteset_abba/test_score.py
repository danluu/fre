#!/usr/bin/env python3
"""Unit tests for preregistered ByteSet gate geometry."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("score.py")
SPEC = importlib.util.spec_from_file_location("byteset_score", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
score = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = score
SPEC.loader.exec_module(score)


def timing_row(family: str, speed: float) -> dict[str, str]:
    return {
        "family": family,
        "upstream_median_ns_per_search": f"{speed:.9f}",
        "native_median_ns_per_search": "1.0",
        "speedup_at_median": f"{speed:.9f}",
    }


def complete_fixture(normalized: float = 1.06):
    cells = []
    phase_rows = {name: {} for name in score.PHASES}
    ordinal = 0
    for family, sizes in (
        ("atomic_byte_set", score.CARDINALITIES),
        ("atomic_single_literal", score.CONTROL_WIDTHS),
    ):
        for size in sizes:
            for seed in range(2):
                for window in score.WINDOWS:
                    for density in score.DENSITIES:
                        for position in score.POSITIONS:
                            case = f"cell-{ordinal}"
                            ordinal += 1
                            ratio = normalized if family == "atomic_byte_set" else 1.0
                            cells.append(
                                score.CellScore(
                                    family,
                                    size,
                                    window,
                                    position,
                                    density,
                                    ratio,
                                    1.2,
                                    1.2 / ratio,
                                )
                            )
                            for rows in phase_rows.values():
                                rows[case] = timing_row(family, 1.2)
    parsed = {
        name: score.ParsedOutput(Path(name), {}, rows, {}, False)
        for name, rows in phase_rows.items()
    }
    return cells, parsed


class GateTests(unittest.TestCase):
    def test_complete_passing_geometry(self) -> None:
        rows, parsed = complete_fixture()
        report, failed = score.score_rows(rows, parsed)
        self.assertFalse(failed)
        self.assertEqual(report[-1][-1], "pass")
        self.assertEqual(
            sum(row[1] == "eligible_cross" for row in report),
            len(score.CARDINALITIES)
            * len(score.WINDOWS)
            * len(score.DENSITIES)
            * len(score.POSITIONS),
        )

    def test_one_cross_group_below_floor_fails(self) -> None:
        rows, parsed = complete_fixture()
        first = rows[0]
        replacement = score.CellScore(
            first.family,
            first.size,
            first.window,
            first.position,
            first.density,
            0.80,
            first.candidate_over_rust,
            first.parent_over_rust,
        )
        rows[0] = replacement
        report, failed = score.score_rows(rows, parsed)
        self.assertTrue(failed)
        self.assertEqual(report[-1][-1], "fail")


if __name__ == "__main__":
    unittest.main()
