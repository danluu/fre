#!/usr/bin/env python3
"""Validate paired Search V9/V8/portable CSVs and summarize median ratios."""

import csv
import json
import math
import statistics
import sys
from collections import defaultdict

SCHEMA = "fre-search-v9-broad-deploy-v2"
ENGINES = (
    "native-v8-aot-code-tag8",
    "native-v9-aot-code-tag22",
    "hybrid-portable256-v9-tag22-floor4093-width2",
    "portable-memmem",
)
REPETITIONS = {"screen": 3, "heldout": 7, "confirm": 12}
FIXTURE_FIELDS = (
    "phase",
    "seed",
    "width",
    "shape",
    "size",
    "scenario",
    "alignment",
    "window_start",
    "window_end",
)


def fail(message):
    raise SystemExit(message)


def geometric_mean(values):
    if not values or any(value <= 0.0 for value in values):
        fail("geometric mean requires nonempty positive values")
    return math.exp(math.fsum(math.log(value) for value in values) / len(values))


def percentile(values, fraction):
    ordered = sorted(values)
    index = round((len(ordered) - 1) * fraction)
    return ordered[index]


def ratio_summary(values):
    return {
        "fixtures": len(values),
        "geomean": geometric_mean(values),
        "median": statistics.median(values),
        "p10": percentile(values, 0.10),
        "p90": percentile(values, 0.90),
        "max": max(values),
        "fraction_lt_1": sum(value < 1.0 for value in values) / len(values),
        "fraction_gt_1": sum(value > 1.0 for value in values) / len(values),
        "fraction_ge_1_2": sum(value >= 1.2 for value in values) / len(values),
    }


def main():
    if len(sys.argv) < 3:
        fail("usage: analyze.py PHASE CSV...")
    expected_phase = sys.argv[1]
    expected_repetitions = REPETITIONS.get(expected_phase)
    if expected_repetitions is None:
        fail("PHASE must be screen, heldout, or confirm")

    rows = defaultdict(lambda: defaultdict(list))
    seen_phase_rows = 0
    for path in sys.argv[2:]:
        with open(path, newline="", encoding="utf-8") as source:
            for row in csv.DictReader(source):
                if row["schema"] != SCHEMA:
                    fail(f"{path}: unexpected schema {row['schema']!r}")
                if row["phase"] != expected_phase:
                    fail(f"{path}: unexpected phase {row['phase']!r}")
                engine = row["engine"]
                if engine not in ENGINES:
                    fail(f"{path}: unexpected engine {engine!r}")
                fixture = tuple(row[field] for field in FIXTURE_FIELDS)
                rows[fixture][engine].append(row)
                seen_phase_rows += 1

    if not rows:
        fail("no data rows")
    expected_rows = len(rows) * len(ENGINES) * expected_repetitions
    if seen_phase_rows != expected_rows:
        fail(f"row count {seen_phase_rows} != exact expected {expected_rows}")

    fixture_ratios = []
    for fixture, by_engine in rows.items():
        if set(by_engine) != set(ENGINES):
            fail(f"fixture lacks exact engine set: {fixture}")
        medians = {}
        for engine in ENGINES:
            engine_rows = by_engine[engine]
            if len(engine_rows) != expected_repetitions:
                fail(f"fixture/engine repetition count mismatch: {fixture} {engine}")
            repetitions = {int(row["repetition"]) for row in engine_rows}
            if repetitions != set(range(expected_repetitions)):
                fail(f"fixture/engine repetition identities mismatch: {fixture} {engine}")
            medians[engine] = statistics.median(
                float(row["ns_per_iter"]) for row in engine_rows
            )
        for repetition in range(expected_repetitions):
            paired = [
                next(row for row in by_engine[engine] if int(row["repetition"]) == repetition)
                for engine in ENGINES
            ]
            for field in ("iterations", "checksum", "semantic"):
                if len({row[field] for row in paired}) != 1:
                    fail(f"paired {field} mismatch: {fixture} repetition={repetition}")
        v8 = medians[ENGINES[0]]
        v9 = medians[ENGINES[1]]
        hybrid = medians[ENGINES[2]]
        portable = medians[ENGINES[3]]
        fixture_ratios.append(
            {
                "fixture": fixture,
                "v8_over_v9": v8 / v9,
                "portable_over_v9": portable / v9,
                "portable_over_v8": portable / v8,
                "portable_over_hybrid": portable / hybrid,
                "hybrid_over_portable": hybrid / portable,
                "v9_over_hybrid": v9 / hybrid,
            }
        )

    def grouped(field, ratio):
        index = FIXTURE_FIELDS.index(field)
        values = defaultdict(list)
        for item in fixture_ratios:
            values[item["fixture"][index]].append(item[ratio])
        return {
            key: ratio_summary(group)
            for key, group in sorted(values.items(), key=lambda pair: pair[0])
        }

    ratio_names = (
        "v8_over_v9",
        "portable_over_v9",
        "portable_over_v8",
        "portable_over_hybrid",
        "hybrid_over_portable",
        "v9_over_hybrid",
    )

    def selected(ratio, predicate):
        return [item[ratio] for item in fixture_ratios if predicate(item["fixture"])]

    width_index = FIXTURE_FIELDS.index("width")
    scenario_index = FIXTURE_FIELDS.index("scenario")
    start_index = FIXTURE_FIELDS.index("window_start")
    end_index = FIXTURE_FIELDS.index("window_end")
    hybrid_eligible = lambda fixture: (
        int(fixture[width_index]) >= 2
        and int(fixture[end_index]) - int(fixture[start_index]) >= 4_093
    )
    first_candidate = lambda fixture: fixture[scenario_index] == "first_candidate_exact"
    safety_scenario = lambda fixture: fixture[scenario_index] in {
        "early",
        "dense",
        "first_candidate_exact",
    }
    long_scan = lambda fixture: not safety_scenario(fixture)

    def geomean_gate(ratio, predicate, minimum):
        values = selected(ratio, predicate)
        summary = ratio_summary(values)
        return {
            "minimum_geomean": minimum,
            "actual": summary,
            "pass": summary["geomean"] >= minimum,
        }

    def geomean_max_gate(ratio, predicate, maximum):
        values = selected(ratio, predicate)
        summary = ratio_summary(values)
        return {
            "maximum_geomean_exclusive": maximum,
            "actual": summary,
            "pass": summary["geomean"] < maximum,
        }

    def long_scan_gate(predicate):
        values = selected(
            "hybrid_over_portable",
            lambda fixture: hybrid_eligible(fixture)
            and long_scan(fixture)
            and predicate(fixture),
        )
        summary = ratio_summary(values)
        return {
            "minimum_observations": 100,
            "maximum_geomean_exclusive": 0.80,
            "minimum_win_fraction": 0.80,
            "maximum_p90": 1.00,
            "maximum_cell": 1.25,
            "actual": summary,
            "pass": (
                summary["fixtures"] >= 100
                and summary["geomean"] < 0.80
                and summary["fraction_lt_1"] >= 0.80
                and summary["p90"] <= 1.00
                and summary["max"] <= 1.25
            ),
        }

    def parity_gate(predicate):
        values = selected("hybrid_over_portable", predicate)
        summary = ratio_summary(values)
        return {
            "minimum_observations": 100,
            "maximum_geomean": 1.02,
            "maximum_p90": 1.05,
            "maximum_cell": 1.25,
            "actual": summary,
            "pass": (
                summary["fixtures"] >= 100
                and summary["geomean"] <= 1.02
                and summary["p90"] <= 1.05
                and summary["max"] <= 1.25
            ),
        }

    output = {
        "schema": "fre-search-v9-broad-deploy-analysis-v1",
        "phase": expected_phase,
        "fixtures": len(rows),
        "rows": seen_phase_rows,
        "ratios": {
            ratio: ratio_summary([item[ratio] for item in fixture_ratios])
            for ratio in ratio_names
        },
        "by_width": {
            ratio: grouped("width", ratio)
            for ratio in ("v8_over_v9", "portable_over_v9", "portable_over_hybrid")
        },
        "by_size": {
            ratio: grouped("size", ratio)
            for ratio in ("v8_over_v9", "portable_over_v9", "portable_over_hybrid")
        },
        "by_shape": {
            ratio: grouped("shape", ratio)
            for ratio in ("v8_over_v9", "portable_over_v9", "portable_over_hybrid")
        },
        "by_scenario": {
            ratio: grouped("scenario", ratio)
            for ratio in ("v8_over_v9", "portable_over_v9", "portable_over_hybrid")
        },
        "predeclared_screen_gates": {
            "v9_first_candidate_vs_v8": geomean_gate(
                "v8_over_v9", first_candidate, 1.20
            ),
            "v9_nonfirst_no_regression_vs_v8": geomean_gate(
                "v8_over_v9", lambda fixture: not first_candidate(fixture), 0.98
            ),
            "hybrid_tail_owned_long_scan_vs_portable": long_scan_gate(
                lambda fixture: True
            ),
            "hybrid_prefix_owned_parity_vs_portable": parity_gate(
                lambda fixture: hybrid_eligible(fixture) and safety_scenario(fixture)
            ),
            "hybrid_ineligible_parity_vs_portable": parity_gate(
                lambda fixture: not hybrid_eligible(fixture)
            ),
            "hybrid_tail_owned_each_width_vs_portable": {
                str(width): long_scan_gate(
                    lambda fixture, width=width: int(fixture[width_index]) == width
                )
                for width in range(2, 33)
            },
            "hybrid_tail_owned_each_shape_vs_portable": {
                shape: long_scan_gate(
                    lambda fixture, shape=shape: fixture[
                        FIXTURE_FIELDS.index("shape")
                    ]
                    == shape
                )
                for shape in ("entropy", "repeated", "periodic", "binary")
            },
            "hybrid_tail_owned_each_scenario_vs_portable": {
                scenario: long_scan_gate(
                    lambda fixture, scenario=scenario: fixture[scenario_index] == scenario
                )
                for scenario in sorted(
                    {
                        item["fixture"][scenario_index]
                        for item in fixture_ratios
                        if long_scan(item["fixture"])
                    }
                )
            },
        },
    }
    json.dump(output, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
