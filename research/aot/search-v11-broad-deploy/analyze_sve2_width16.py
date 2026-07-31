#!/usr/bin/env python3
"""Validate the frozen width-16 V12/tag25 versus SVE2/tag21 screen."""

import csv
import json
import math
import statistics
import sys
from collections import defaultdict

SCHEMA = "fre-search-v12-width16-sve2-devscreen-v1"
ENGINES = (
    "native-v12-aot-code-tag25",
    "native-sve2-fixed16-aot-code-tag21",
    "hybrid-portable256-v12-tag25-floor4093-width2",
    "hybrid-portable256-sve2-fixed16-tag21-floor4093-width2",
    "portable-memmem",
)
REPETITIONS = 3
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


def percentile(values, fraction):
    ordered = sorted(values)
    return ordered[round((len(ordered) - 1) * fraction)]


def geometric_mean(values):
    if not values or any(value <= 0.0 for value in values):
        fail("geometric mean requires nonempty positive values")
    return math.exp(math.fsum(math.log(value) for value in values) / len(values))


def summary(values):
    if not values:
        fail("summary requires observations")
    return {
        "fixtures": len(values),
        "geomean": geometric_mean(values),
        "median": statistics.median(values),
        "p10": percentile(values, 0.10),
        "p90": percentile(values, 0.90),
        "p99": percentile(values, 0.99),
        "max": max(values),
        "fraction_lt_1": sum(value < 1.0 for value in values) / len(values),
    }


def mutation_offset(scenario):
    prefix = "near-miss-offset-"
    if not scenario.startswith(prefix):
        return None
    suffix = scenario[len(prefix) :]
    if len(suffix) != 2 or not suffix.isdigit():
        fail(f"noncanonical mutation scenario {scenario!r}")
    offset = int(suffix)
    if not 0 <= offset < 16:
        fail(f"out-of-range width-16 mutation offset {offset}")
    return offset


def broad_gate(values, minimum_observations=100):
    actual = summary(values)
    return {
        "minimum_observations": minimum_observations,
        "maximum_geomean_exclusive": 0.80,
        "minimum_win_fraction": 0.80,
        "maximum_p90": 1.00,
        "maximum_p99": 1.15,
        "actual": actual,
        "pass": (
            actual["fixtures"] >= minimum_observations
            and actual["geomean"] < 0.80
            and actual["fraction_lt_1"] >= 0.80
            and actual["p90"] <= 1.00
            and actual["p99"] <= 1.15
        ),
    }


def mutation_gate(items, ratio_name):
    cells = {}
    for offset in range(16):
        values = [
            item[ratio_name]
            for item in items
            if item["eligible"] and item["mutation_offset"] == offset
        ]
        actual = summary(values)
        cells[f"{offset:02}"] = {
            "minimum_observations": 80,
            "maximum_geomean_exclusive": 0.80,
            "minimum_win_fraction": 0.70,
            "maximum_p90": 1.10,
            "actual": actual,
            "pass": (
                actual["fixtures"] >= 80
                and actual["geomean"] < 0.80
                and actual["fraction_lt_1"] >= 0.70
                and actual["p90"] <= 1.10
            ),
        }
    aggregate = broad_gate(
        [
            item[ratio_name]
            for item in items
            if item["eligible"] and item["mutation_offset"] is not None
        ]
    )
    worst = max(cells.items(), key=lambda pair: pair[1]["actual"]["geomean"])
    return {
        "candidate_independent_inventory": {
            "width": 16,
            "offsets": "0..=15",
            "seeds": 4,
            "shapes": 4,
            "eligible_sizes": 5,
            "eligible_observations_per_offset": 80,
        },
        "aggregate": aggregate,
        "worst_offset_geomean": {
            "offset": worst[0],
            "actual": worst[1]["actual"]["geomean"],
        },
        "all_offsets_pass": all(cell["pass"] for cell in cells.values()),
        "by_offset": cells,
        "pass": aggregate["pass"] and all(cell["pass"] for cell in cells.values()),
    }


def engine_gates(items, ratio_name):
    safety = {"early", "dense", "first_candidate_exact"}
    long_values = [
        item[ratio_name]
        for item in items
        if item["eligible"] and item["scenario"] not in safety
    ]
    mutations = mutation_gate(items, ratio_name)
    by_shape = {
        shape: broad_gate(
            [
                item[ratio_name]
                for item in items
                if item["eligible"]
                and item["scenario"] not in safety
                and item["shape"] == shape
            ]
        )
        for shape in ("entropy", "repeated", "periodic", "binary")
    }
    by_size = {
        str(size): broad_gate(
            [
                item[ratio_name]
                for item in items
                if item["eligible"]
                and item["scenario"] not in safety
                and item["window_bytes"] == size
            ]
        )
        for size in (4093, 16381, 65521, 262139, 1048573)
    }
    required_scenarios = (
        "absent-entropy",
        "absent-filler",
        "middle",
        "tail",
        "first-byte-dense-absent",
        "near-miss-head",
        "near-miss-tail",
        "binary-tail",
        "selected_byte_hit_then_full_miss",
        "window-absent",
        "window-tail",
    )
    by_scenario = {
        scenario: broad_gate(
            [
                item[ratio_name]
                for item in items
                if item["eligible"] and item["scenario"] == scenario
            ],
            minimum_observations=80,
        )
        for scenario in required_scenarios
    }
    long_scan = broad_gate(long_values)
    passed = (
        long_scan["pass"]
        and mutations["pass"]
        and all(gate["pass"] for gate in by_shape.values())
        and all(gate["pass"] for gate in by_size.values())
        and all(gate["pass"] for gate in by_scenario.values())
    )
    return {
        "tail_owned_long_scan": long_scan,
        "candidate_independent_every_offset_mutation": mutations,
        "tail_owned_each_shape": by_shape,
        "tail_owned_each_window_size": by_size,
        "tail_owned_each_required_scenario": by_scenario,
        "pass": passed,
    }


def main():
    if len(sys.argv) < 2:
        fail("usage: analyze_sve2_width16.py CSV...")

    rows = defaultdict(lambda: defaultdict(list))
    row_count = 0
    for path in sys.argv[1:]:
        with open(path, newline="", encoding="utf-8") as source:
            for row in csv.DictReader(source):
                if row["schema"] != SCHEMA:
                    fail(f"{path}: unexpected schema {row['schema']!r}")
                if row["phase"] != "screen" or row["width"] != "16":
                    fail(f"{path}: expected screen/width16 row")
                if row["engine"] not in ENGINES:
                    fail(f"{path}: unexpected engine {row['engine']!r}")
                fixture = tuple(row[field] for field in FIXTURE_FIELDS)
                rows[fixture][row["engine"]].append(row)
                row_count += 1

    if not rows:
        fail("no data rows")
    if len(rows) != 3808:
        fail(f"fixture count {len(rows)} != exact expected 3808")
    if row_count != len(rows) * len(ENGINES) * REPETITIONS:
        fail("row count does not match exact fixture/engine/repetition product")

    inventory = defaultdict(set)
    items = []
    for fixture, by_engine in rows.items():
        if set(by_engine) != set(ENGINES):
            fail(f"fixture lacks exact engine set: {fixture}")
        medians = {}
        for engine in ENGINES:
            engine_rows = by_engine[engine]
            if len(engine_rows) != REPETITIONS:
                fail(f"wrong repetition count: {fixture} {engine}")
            if {int(row["repetition"]) for row in engine_rows} != set(
                range(REPETITIONS)
            ):
                fail(f"wrong repetition identities: {fixture} {engine}")
            medians[engine] = statistics.median(
                float(row["ns_per_iter"]) for row in engine_rows
            )
        for repetition in range(REPETITIONS):
            paired = [
                next(
                    row
                    for row in by_engine[engine]
                    if int(row["repetition"]) == repetition
                )
                for engine in ENGINES
            ]
            for field in ("iterations", "checksum", "semantic"):
                if len({row[field] for row in paired}) != 1:
                    fail(f"paired {field} mismatch: {fixture} repetition={repetition}")

        fields = dict(zip(FIXTURE_FIELDS, fixture))
        offset = mutation_offset(fields["scenario"])
        if offset is not None:
            inventory[
                (
                    fields["seed"],
                    fields["shape"],
                    fields["size"],
                    fields["window_start"],
                    fields["window_end"],
                )
            ].add(offset)
        window_bytes = int(fields["window_end"]) - int(fields["window_start"])
        v12 = medians[ENGINES[0]]
        sve2 = medians[ENGINES[1]]
        hybrid_v12 = medians[ENGINES[2]]
        hybrid_sve2 = medians[ENGINES[3]]
        portable = medians[ENGINES[4]]
        items.append(
            {
                "shape": fields["shape"],
                "size": int(fields["size"]),
                "scenario": fields["scenario"],
                "window_bytes": window_bytes,
                "eligible": window_bytes >= 4093,
                "mutation_offset": offset,
                "sve2_over_v12": sve2 / v12,
                "v12_over_sve2": v12 / sve2,
                "hybrid_sve2_over_hybrid_v12": hybrid_sve2 / hybrid_v12,
                "hybrid_v12_over_hybrid_sve2": hybrid_v12 / hybrid_sve2,
                "hybrid_v12_over_portable": hybrid_v12 / portable,
                "hybrid_sve2_over_portable": hybrid_sve2 / portable,
            }
        )

    if len(inventory) != 4 * 4 * 7:
        fail("mutation inventory lacks exact seed/shape/size cells")
    if any(offsets != set(range(16)) for offsets in inventory.values()):
        fail("mutation inventory does not contain every width-16 offset")

    v12_gates = engine_gates(items, "hybrid_v12_over_portable")
    sve2_gates = engine_gates(items, "hybrid_sve2_over_portable")
    eligible_long = [
        item
        for item in items
        if item["eligible"]
        and item["scenario"] not in {"early", "dense", "first_candidate_exact"}
    ]
    native_comparison = summary(
        [item["sve2_over_v12"] for item in eligible_long]
    )
    hybrid_comparison = summary(
        [item["hybrid_sve2_over_hybrid_v12"] for item in eligible_long]
    )

    qualified = []
    if v12_gates["pass"]:
        qualified.append("v12-tag25")
    if sve2_gates["pass"]:
        qualified.append("sve2-fixed16-tag21")
    if qualified == ["sve2-fixed16-tag21"]:
        preferred = qualified[0]
        preference_reason = "only SVE2/tag21 cleared every broad width-16 gate"
    elif qualified == ["v12-tag25"]:
        preferred = qualified[0]
        preference_reason = "only V12/tag25 cleared every broad width-16 gate"
    elif len(qualified) == 2 and (
        hybrid_comparison["geomean"] < 0.98
        and hybrid_comparison["p90"] <= 1.05
    ):
        preferred = "sve2-fixed16-tag21"
        preference_reason = (
            "both cleared broad gates and SVE2 was at least 2% faster geometrically "
            "without a p90 regression"
        )
    elif len(qualified) == 2:
        preferred = "v12-tag25"
        preference_reason = (
            "both cleared broad gates but SVE2 lacked a stable >=2% deployable advantage"
        )
    else:
        preferred = None
        preference_reason = "neither engine cleared every broad width-16 gate"

    output = {
        "schema": "fre-search-v12-width16-sve2-devscreen-analysis-v1",
        "fixtures": len(rows),
        "rows": row_count,
        "ratios": {
            name: summary([item[name] for item in items])
            for name in (
                "sve2_over_v12",
                "v12_over_sve2",
                "hybrid_sve2_over_hybrid_v12",
                "hybrid_v12_over_hybrid_sve2",
                "hybrid_v12_over_portable",
                "hybrid_sve2_over_portable",
            )
        },
        "eligible_tail_owned_long_scan_comparison": {
            "native_sve2_over_v12": native_comparison,
            "hybrid_sve2_over_v12": hybrid_comparison,
        },
        "predeclared_screen_gates": {
            "v12_tag25": v12_gates,
            "sve2_fixed16_tag21": sve2_gates,
        },
        "width16_preference": {
            "qualified_engines": qualified,
            "preferred_engine": preferred,
            "reason": preference_reason,
            "production_authority": False,
        },
    }
    json.dump(output, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
