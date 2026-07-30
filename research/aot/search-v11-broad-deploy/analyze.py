#!/usr/bin/env python3
"""Validate paired Search V11/V10/portable development CSVs."""

import csv
import json
import math
import statistics
import sys
from collections import defaultdict

SCHEMA = "fre-search-v11-broad-devscreen-v1"
ENGINES = (
    "native-v10-aot-code-tag23",
    "native-v11-aot-code-tag24",
    "hybrid-portable256-v11-tag24-floor4093-width2",
    "portable-memmem",
)
REPETITIONS = {"screen": 3}
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
        "p99": percentile(values, 0.99),
        "max": max(values),
        "fraction_lt_1": sum(value < 1.0 for value in values) / len(values),
        "fraction_gt_1": sum(value > 1.0 for value in values) / len(values),
        "fraction_ge_1_2": sum(value >= 1.2 for value in values) / len(values),
    }


def delta_summary(values):
    if not values:
        fail("delta summary requires nonempty values")
    return {
        "fixtures": len(values),
        "median_ns": statistics.median(values),
        "p10_ns": percentile(values, 0.10),
        "p90_ns": percentile(values, 0.90),
        "p99_ns": percentile(values, 0.99),
        "min_ns": min(values),
        "max_ns": max(values),
    }


def mutation_offset(scenario):
    prefix = "near-miss-offset-"
    if not scenario.startswith(prefix):
        return None
    suffix = scenario[len(prefix) :]
    if len(suffix) != 2 or not suffix.isdigit():
        fail(f"non-canonical mutation scenario {scenario!r}")
    return int(suffix)


def main():
    if len(sys.argv) < 3:
        fail("usage: analyze.py PHASE CSV...")
    expected_phase = sys.argv[1]
    expected_repetitions = REPETITIONS.get(expected_phase)
    if expected_repetitions is None:
        fail("this development analyzer accepts only PHASE=screen")

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

    inventory = defaultdict(set)
    for fixture in rows:
        width = int(fixture[FIXTURE_FIELDS.index("width")])
        scenario = fixture[FIXTURE_FIELDS.index("scenario")]
        offset = mutation_offset(scenario)
        inventory_key = (
            fixture[FIXTURE_FIELDS.index("phase")],
            fixture[FIXTURE_FIELDS.index("seed")],
            fixture[FIXTURE_FIELDS.index("width")],
            fixture[FIXTURE_FIELDS.index("shape")],
            fixture[FIXTURE_FIELDS.index("size")],
        )
        if offset is not None:
            if width == 1 or offset >= width:
                fail(f"out-of-range mutation offset: {fixture}")
            inventory[inventory_key].add(offset)
    expected_inventory_keys = {
        (
            fixture[FIXTURE_FIELDS.index("phase")],
            fixture[FIXTURE_FIELDS.index("seed")],
            fixture[FIXTURE_FIELDS.index("width")],
            fixture[FIXTURE_FIELDS.index("shape")],
            fixture[FIXTURE_FIELDS.index("size")],
        )
        for fixture in rows
        if int(fixture[FIXTURE_FIELDS.index("width")]) > 1
    }
    if set(inventory) != expected_inventory_keys:
        fail("mutation inventory keys are incomplete")
    for key, observed_offsets in inventory.items():
        width = int(key[2])
        if observed_offsets != set(range(width)):
            fail(
                f"mutation inventory offset set mismatch: {key} "
                f"{sorted(observed_offsets)}"
            )

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
        v10 = medians[ENGINES[0]]
        v11 = medians[ENGINES[1]]
        hybrid = medians[ENGINES[2]]
        portable = medians[ENGINES[3]]
        fixture_ratios.append(
            {
                "fixture": fixture,
                "v10_over_v11": v10 / v11,
                "v11_over_v10": v11 / v10,
                "portable_over_v11": portable / v11,
                "portable_over_v10": portable / v10,
                "portable_over_hybrid": portable / hybrid,
                "hybrid_over_portable": hybrid / portable,
                "v11_over_hybrid": v11 / hybrid,
                "hybrid_minus_portable_ns": hybrid - portable,
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
        "v10_over_v11",
        "v11_over_v10",
        "portable_over_v11",
        "portable_over_v10",
        "portable_over_hybrid",
        "hybrid_over_portable",
        "v11_over_hybrid",
    )

    def selected(ratio, predicate):
        return [item[ratio] for item in fixture_ratios if predicate(item["fixture"])]

    def selected_delta(predicate):
        return [
            item["hybrid_minus_portable_ns"]
            for item in fixture_ratios
            if predicate(item["fixture"])
        ]

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
    is_mutation = lambda fixture: mutation_offset(fixture[scenario_index]) is not None

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
            "maximum_p99": 1.15,
            "maximum_cell_diagnostic_only": summary["max"],
            "actual": summary,
            "pass": (
                summary["fixtures"] >= 100
                and summary["geomean"] < 0.80
                and summary["fraction_lt_1"] >= 0.80
                and summary["p90"] <= 1.00
                and summary["p99"] <= 1.15
            ),
        }

    def parity_gate(ratio, predicate):
        values = selected(ratio, predicate)
        summary = ratio_summary(values)
        return {
            "minimum_observations": 100,
            "maximum_geomean": 1.02,
            "maximum_p90": 1.05,
            "maximum_p99": 1.10,
            "maximum_cell_diagnostic_only": summary["max"],
            "actual": summary,
            "pass": (
                summary["fixtures"] >= 100
                and summary["geomean"] <= 1.02
                and summary["p90"] <= 1.05
                and summary["p99"] <= 1.10
            ),
        }

    def fixed_overhead_gate(predicate):
        ratio = ratio_summary(selected("hybrid_over_portable", predicate))
        delta = delta_summary(selected_delta(predicate))
        return {
            "minimum_observations": 100,
            "ratio_diagnostic": ratio,
            "maximum_median_overhead_ns": 3.0,
            "maximum_p90_overhead_ns": 4.0,
            "absolute_overhead": delta,
            "pass": (
                delta["fixtures"] >= 100
                and delta["median_ns"] <= 3.0
                and delta["p90_ns"] <= 4.0
            ),
        }

    mutation_cells = {}
    for width in range(2, 33):
        for offset in range(width):
            values = selected(
                "hybrid_over_portable",
                lambda fixture, width=width, offset=offset: (
                    hybrid_eligible(fixture)
                    and int(fixture[width_index]) == width
                    and mutation_offset(fixture[scenario_index]) == offset
                ),
            )
            summary = ratio_summary(values)
            mutation_cells[f"{width}:{offset:02}"] = {
                "minimum_observations": 80,
                "maximum_geomean_exclusive": 0.80,
                "minimum_win_fraction": 0.70,
                "maximum_p90": 1.10,
                "actual": summary,
                "pass": (
                    summary["fixtures"] >= 80
                    and summary["geomean"] < 0.80
                    and summary["fraction_lt_1"] >= 0.70
                    and summary["p90"] <= 1.10
                ),
            }
    worst_mutation_cell = max(
        mutation_cells.items(),
        key=lambda item: item[1]["actual"]["geomean"],
    )
    mutation_values = selected(
        "hybrid_over_portable",
        lambda fixture: hybrid_eligible(fixture) and is_mutation(fixture),
    )
    mutation_summary = ratio_summary(mutation_values)
    mutation_gate = {
        "inventory": {
            "candidate_independent": True,
            "widths": "2..=32",
            "offset_rule": "every literal byte offset",
            "seeds": 4,
            "shapes": 4,
            "sizes": 7,
            "eligible_observations_per_width_offset": 80,
        },
        "aggregate": {
            "maximum_geomean_exclusive": 0.80,
            "minimum_win_fraction": 0.80,
            "maximum_p90": 1.00,
            "actual": mutation_summary,
            "pass": (
                mutation_summary["geomean"] < 0.80
                and mutation_summary["fraction_lt_1"] >= 0.80
                and mutation_summary["p90"] <= 1.00
            ),
        },
        "worst_width_offset_geomean": {
            "maximum_exclusive": 0.80,
            "cell": worst_mutation_cell[0],
            "actual": worst_mutation_cell[1]["actual"]["geomean"],
            "pass": worst_mutation_cell[1]["actual"]["geomean"] < 0.80,
        },
        "all_width_offset_cells_pass": all(
            cell["pass"] for cell in mutation_cells.values()
        ),
        "by_width_offset": mutation_cells,
    }

    output = {
        "schema": "fre-search-v11-broad-devscreen-analysis-v1",
        "phase": expected_phase,
        "fixtures": len(rows),
        "rows": seen_phase_rows,
        "ratios": {
            ratio: ratio_summary([item[ratio] for item in fixture_ratios])
            for ratio in ratio_names
        },
        "by_width": {
            ratio: grouped("width", ratio)
            for ratio in ("v10_over_v11", "portable_over_v11", "portable_over_hybrid")
        },
        "by_size": {
            ratio: grouped("size", ratio)
            for ratio in ("v10_over_v11", "portable_over_v11", "portable_over_hybrid")
        },
        "by_shape": {
            ratio: grouped("shape", ratio)
            for ratio in ("v10_over_v11", "portable_over_v11", "portable_over_hybrid")
        },
        "by_scenario": {
            ratio: grouped("scenario", ratio)
            for ratio in ("v10_over_v11", "portable_over_v11", "portable_over_hybrid")
        },
        "predeclared_screen_gates": {
            "candidate_independent_every_offset_mutation_vs_portable": mutation_gate,
            "v11_first_candidate_vs_v10": geomean_gate(
                "v10_over_v11", first_candidate, 0.98
            ),
            "hybrid_tail_owned_long_scan_vs_portable": long_scan_gate(
                lambda fixture: True
            ),
            "v11_nonfirst_tail_guard_vs_v10": parity_gate(
                "v11_over_v10", lambda fixture: not first_candidate(fixture)
            ),
            "hybrid_prefix_owned_absolute_overhead_vs_portable": fixed_overhead_gate(
                lambda fixture: hybrid_eligible(fixture) and safety_scenario(fixture)
            ),
            "hybrid_ineligible_absolute_overhead_diagnostic": fixed_overhead_gate(
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
                        and not is_mutation(item["fixture"])
                    }
                )
            },
            "hybrid_tail_owned_each_window_size_vs_portable": {
                str(window_bytes): long_scan_gate(
                    lambda fixture, window_bytes=window_bytes: (
                        int(fixture[end_index]) - int(fixture[start_index])
                        == window_bytes
                    )
                )
                for window_bytes in sorted(
                    {
                        int(item["fixture"][end_index])
                        - int(item["fixture"][start_index])
                        for item in fixture_ratios
                        if hybrid_eligible(item["fixture"])
                        and long_scan(item["fixture"])
                    }
                )
            },
            "hybrid_tail_owned_each_alignment_vs_portable": {
                alignment: long_scan_gate(
                    lambda fixture, alignment=alignment: fixture[
                        FIXTURE_FIELDS.index("alignment")
                    ]
                    == alignment
                )
                for alignment in sorted(
                    {
                        item["fixture"][FIXTURE_FIELDS.index("alignment")]
                        for item in fixture_ratios
                        if hybrid_eligible(item["fixture"])
                        and long_scan(item["fixture"])
                    },
                    key=int,
                )
            },
            "hybrid_tail_owned_each_window_topology_vs_portable": {
                topology: long_scan_gate(
                    lambda fixture, topology=topology: (
                        ("nonzero" if int(fixture[start_index]) > 0 else "full")
                        == topology
                    )
                )
                for topology in ("full", "nonzero")
            },
        },
    }
    json.dump(output, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
