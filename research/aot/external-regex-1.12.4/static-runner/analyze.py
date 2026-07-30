#!/usr/bin/env python3
"""Validate external paired static-AOT CSVs and apply preregistered gates."""

from __future__ import annotations

import csv
import json
import math
import statistics
import sys
from collections import defaultdict
from pathlib import Path

SCHEMA = "fre.aot.external-regex-1.12.4-static-search-results.v1"
ENGINES = ("portable", "static-auto-aot")
REPETITIONS = 6
MINIMUM_NS = 400_000_000
FIXTURE_FIELDS = (
    "candidate_sha256",
    "literal_hex",
    "scenario",
    "fixture_sha256",
    "alignment",
    "tail_owned",
)


def fail(message: str) -> None:
    raise SystemExit(message)


def geometric_mean(values: list[float]) -> float:
    if not values or any(not math.isfinite(value) or value <= 0 for value in values):
        fail("geometric mean requires finite positive observations")
    return math.exp(math.fsum(math.log(value) for value in values) / len(values))


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[round((len(ordered) - 1) * fraction)]


def summary(values: list[float]) -> dict[str, float | int]:
    return {
        "cells": len(values),
        "geomean_candidate_over_baseline": geometric_mean(values),
        "median_candidate_over_baseline": statistics.median(values),
        "p90_candidate_over_baseline": percentile(values, 0.90),
        "maximum_candidate_over_baseline": max(values),
        "win_fraction": sum(value < 1.0 for value in values) / len(values),
        "twenty_percent_win_fraction": sum(value <= 0.80 for value in values)
        / len(values),
    }


def main() -> None:
    if len(sys.argv) < 2:
        fail("usage: analyze.py CSV...")
    rows: dict[tuple[str, ...], dict[str, list[dict[str, str]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    identities: set[tuple[str, ...]] = set()
    row_count = 0
    for raw_path in sys.argv[1:]:
        path = Path(raw_path)
        with path.open(newline="", encoding="utf-8") as source:
            reader = csv.DictReader(source)
            if reader.fieldnames is None:
                fail(f"{path}: missing header")
            for row in reader:
                if row["schema"] != SCHEMA:
                    fail(f"{path}: unexpected schema {row['schema']!r}")
                engine = row["engine"]
                if engine not in ENGINES:
                    fail(f"{path}: unexpected engine {engine!r}")
                if int(row["total_ns"]) < MINIMUM_NS:
                    fail(f"{path}: sample below minimum duration")
                if int(row["iterations"]) <= 0:
                    fail(f"{path}: nonpositive iteration count")
                fixture = tuple(row[field] for field in FIXTURE_FIELDS)
                rows[fixture][engine].append(row)
                identities.add(
                    (
                        row["identity_sha256"],
                        row["runner_source_sha256"],
                        row["backend_name"],
                        row["backend_tag"],
                        row["family_selector"],
                    )
                )
                row_count += 1
    if not rows:
        fail("no result rows")
    if len(identities) != 1:
        fail("result files mix static runner identities")
    expected_rows = len(rows) * len(ENGINES) * REPETITIONS
    if row_count != expected_rows:
        fail(f"row count {row_count} != expected {expected_rows}")

    observations: list[dict[str, object]] = []
    for fixture, by_engine in rows.items():
        if set(by_engine) != set(ENGINES):
            fail(f"fixture lacks exact engine pair: {fixture}")
        medians: dict[str, float] = {}
        for engine in ENGINES:
            engine_rows = by_engine[engine]
            if len(engine_rows) != REPETITIONS:
                fail(f"fixture repetition count differs: {fixture} {engine}")
            if {int(row["repetition"]) for row in engine_rows} != set(
                range(REPETITIONS)
            ):
                fail(f"fixture repetition identities differ: {fixture} {engine}")
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
            expected_order = (
                "portable+static-auto-aot"
                if repetition % 2 == 0
                else "static-auto-aot+portable"
            )
            if {row["order"] for row in paired} != {expected_order}:
                fail(f"paired order differs: {fixture} repetition={repetition}")
            for field in ("iterations", "checksum", "semantic"):
                if paired[0][field] != paired[1][field]:
                    fail(
                        f"paired {field} differs: {fixture} repetition={repetition}"
                    )
        ratio = medians["static-auto-aot"] / medians["portable"]
        observations.append(
            {
                "fixture": fixture,
                "ratio": ratio,
                "tail_owned": fixture[FIXTURE_FIELDS.index("tail_owned")] == "true",
                "scenario": fixture[FIXTURE_FIELDS.index("scenario")],
                "candidate": fixture[FIXTURE_FIELDS.index("candidate_sha256")],
            }
        )

    tail = [float(item["ratio"]) for item in observations if item["tail_owned"]]
    non_target = [
        float(item["ratio"]) for item in observations if not item["tail_owned"]
    ]
    by_scenario: dict[str, list[float]] = defaultdict(list)
    by_candidate: dict[str, list[float]] = defaultdict(list)
    for item in observations:
        if item["tail_owned"]:
            by_scenario[str(item["scenario"])].append(float(item["ratio"]))
            by_candidate[str(item["candidate"])].append(float(item["ratio"]))

    tail_summary = summary(tail)
    non_target_summary = summary(non_target)
    scenario_summaries = {
        key: summary(value) for key, value in sorted(by_scenario.items())
    }
    candidate_summaries = {
        key: summary(value) for key, value in sorted(by_candidate.items())
    }
    gates = {
        "independent_tail_owned_geomean_at_most_0_80": (
            tail_summary["geomean_candidate_over_baseline"] <= 0.80
        ),
        "every_tail_scenario_at_most_1_05": all(
            value["geomean_candidate_over_baseline"] <= 1.05
            for value in scenario_summaries.values()
        ),
        "every_independent_candidate_at_most_1_05": all(
            value["geomean_candidate_over_baseline"] <= 1.05
            for value in candidate_summaries.values()
        ),
        "non_target_geomean_at_most_1_05": (
            non_target_summary["geomean_candidate_over_baseline"] <= 1.05
        ),
    }
    output = {
        "schema": "fre.aot.external-regex-1.12.4-static-search-analysis.v1",
        "identity": list(next(iter(identities))),
        "fixtures": len(rows),
        "rows": row_count,
        "tail_owned": tail_summary,
        "non_target": non_target_summary,
        "by_tail_scenario": scenario_summaries,
        "by_independent_candidate": candidate_summaries,
        "gates": gates,
        "pass": all(gates.values()),
    }
    print(json.dumps(output, sort_keys=True, indent=2))
    if not output["pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
