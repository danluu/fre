#!/usr/bin/env python3
"""Exact result analyzer for the frozen Search V26 development gate.

This program never emits or executes regex code. It authenticates a sealed
contract and complete 7,776-cell manifest, validates every raw timing sample,
and recomputes all estimators and thresholds without trusting runner summaries.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence


EXPECTED_CELLS = 7_776
EXPECTED_SHARD_CELLS = 2_592
EXPECTED_OUTPUTS = ("exists", "span", "selected_end")
OUTPUT_TAGS = {"exists": 1, "selected_end": 2, "span": 3}
EXPECTED_WINDOWS = (
    "no_match",
    "first_legal_position",
    "middle_complete_vector_group",
    "last_legal_position",
    "overlapping_near_miss_before_match",
    "dense_primary_byte_false_candidates",
)
EXPECTED_ORDERS = (
    ("portable", "v17", "v26"),
    ("portable", "v26", "v17"),
    ("v17", "portable", "v26"),
    ("v17", "v26", "portable"),
    ("v26", "portable", "v17"),
    ("v26", "v17", "portable"),
) * 2
SHARD_WIDTHS = ((6, 14), (15, 23), (24, 32))
EXPECTED_ACCEPTANCE = {
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
    "p95": "report-only",
}


class GateError(ValueError):
    """Malformed, incomplete, unauthenticated, or semantically invalid evidence."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def geomean(values: Iterable[float]) -> float:
    materialized = list(values)
    if not materialized or any(not math.isfinite(v) or v <= 0.0 for v in materialized):
        raise GateError("geomean requires a nonempty set of finite positive ratios")
    return math.exp(math.fsum(math.log(v) for v in materialized) / len(materialized))


def median12(values: Iterable[float]) -> float:
    ordered = sorted(values)
    if len(ordered) != 12 or any(not math.isfinite(v) or v <= 0.0 for v in ordered):
        raise GateError("cell estimator requires exactly 12 finite positive ratios")
    return (ordered[5] + ordered[6]) / 2.0


def nearest_rank(values: Sequence[float], rank: int) -> float:
    if rank < 1 or rank > len(values):
        raise GateError("nearest rank is outside the observed population")
    return sorted(values)[rank - 1]


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GateError(f"cannot read canonical JSON {path}: {error}") from error
    if not isinstance(value, dict):
        raise GateError(f"{path} is not a JSON object")
    return value


def read_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    try:
        with path.open("r", encoding="utf-8", newline="") as source:
            for line_number, line in enumerate(source, 1):
                if not line.endswith("\n"):
                    raise GateError(f"{path}:{line_number} lacks a final newline")
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as error:
                    raise GateError(f"{path}:{line_number}: {error}") from error
                if not isinstance(value, dict):
                    raise GateError(f"{path}:{line_number} is not a JSON object")
                yield value
    except (OSError, UnicodeError) as error:
        raise GateError(f"cannot read JSONL {path}: {error}") from error


def require_exact_contract(contract: Mapping[str, Any], contract_path: Path, cells_path: Path) -> None:
    if contract.get("schema") != "fre-search-v26-development-gate-contract-v1":
        raise GateError("unexpected gate contract schema")
    if contract.get("status") != "SEALED_READY_FOR_ONE_SHOT_TIMING":
        raise GateError("contract is not sealed timing authority")
    encoded = json.dumps(contract, sort_keys=True)
    if "AWAITING_" in encoded:
        raise GateError("sealed contract contains an unresolved placeholder")
    candidate = contract.get("candidate")
    if not isinstance(candidate, dict) or candidate != {
        "backend_policy": "AsimdV26",
        "backend_version": 39,
        "source_commit": candidate.get("source_commit"),
        "source_tree": candidate.get("source_tree"),
        "llvm": False,
    }:
        raise GateError("candidate contract fields drifted")
    source_ids = (candidate["source_commit"], candidate["source_tree"])
    if any(
        not isinstance(value, str)
        or len(value) != 40
        or any(character not in "0123456789abcdef" for character in value)
        for value in source_ids
    ):
        raise GateError("candidate source identity is not a full Git object ID")
    inputs = contract.get("inputs")
    if not isinstance(inputs, dict):
        raise GateError("sealed input identity is missing")
    if (
        inputs.get("preregistration_sha256")
        != "772a23e5e6c4354fa3bdc9ad307601dbbce655a62dd5ee7ded075dbe4869a02a"
        or inputs.get("literal_records") != 1_296
        or inputs.get("cells") != EXPECTED_CELLS
        or inputs.get("synthetic_population_sha256")
        != "a682375f2e6e051f97322396bafc46974df47baa3518bc17f5d6b71b56407b73"
        or inputs.get("cell_manifest_sha256") != sha256_file(cells_path)
    ):
        raise GateError("sealed input identity mismatch")
    if inputs.get("cell_key_fields") != [
        "width",
        "output_tag",
        "accepted_ordinal",
        "window_shape",
    ] or inputs.get("cell_order") != [
        "width ascending 6..32",
        "output order exists, span, selected_end",
        "accepted ordinal ascending 0..15",
        "window order no_match, first_legal_position, middle_complete_vector_group, last_legal_position, overlapping_near_miss_before_match, dense_primary_byte_false_candidates",
    ]:
        raise GateError("cell lattice contract drifted")
    fixtures = contract.get("fixtures")
    if not isinstance(fixtures, dict) or fixtures != {
        "recipe": "fre-search-v26-long-scan-fixture-v1",
        "long_window_bytes": 2_097_152,
        "long_shapes": [
            "no_match",
            "middle_complete_vector_group",
            "last_legal_position",
            "overlapping_near_miss_before_match",
            "dense_primary_byte_false_candidates",
        ],
        "first_legal_position": {
            "window_bytes": "literal_width",
            "match_offset_from_window_start": 0,
            "purpose": "intentional call/setup stratum",
        },
        "window_start": "32 + accepted_ordinal, covering every modulo-16 start alignment once per width/output",
        "haystack_suffix_padding_bytes": 64,
        "filler_byte": "lowest u8 value absent from the literal",
        "middle_match_offset_from_window_start": 1_048_581,
        "overlap_match_offset_from_window_start": 1_048_581,
        "overlap_near_miss": "start at exact_match_start - (literal_width - 1), copy the literal, replace the near-miss first byte with filler, then install the exact match",
        "dense_false_candidates": "from window_start, advance by literal_width + 3 while the candidate ends before the last legal position; candidate i contains filler except literal[i mod literal_width] at that same column",
        "dense_exact_match": "last legal position after all false candidates",
        "identity": "SHA-256 over fre-search-v26-long-scan-fixture-v1 binary domain, literal coordinate and bytes, shape tag, geometry, expected match, and complete haystack bytes",
        "allocation": "construct and release exactly one fixture/cell at a time; retaining the 7,776 long haystacks is forbidden",
    }:
        raise GateError("fixture geometry contract drifted")
    if contract.get("engines") != {
        "portable": "safe Kernel IR execution",
        "reference": "AsimdV17/backend30 native Search-v1",
        "candidate": "AsimdV26/backend39 native Search-v1",
        "semantic_equality_before_timing": "hard failure",
    }:
        raise GateError("engine identity contract drifted")
    measurement = contract.get("measurement")
    if not isinstance(measurement, dict):
        raise GateError("measurement contract is missing")
    try:
        orders = tuple(tuple(order) for order in measurement.get("orders", ()))
    except TypeError as error:
        raise GateError("measurement orders are malformed") from error
    if orders != EXPECTED_ORDERS:
        raise GateError("measurement order contract drifted")
    if {
        key: value for key, value in measurement.items() if key != "orders"
    } != {
        "calibration_target_ns": 4_000_000,
        "calibration": "per cell and engine, begin at one search and double the batch until elapsed_ns >= target; fail on overflow or zero/nonfinite normalized time",
        "paired_repetitions": 12,
        "per_repetition_ratio": "(v26_elapsed_ns / v26_iterations) / (v17_elapsed_ns / v17_iterations)",
        "cell_estimator": "arithmetic median of the 12 paired ratios; average sorted ranks 6 and 7",
        "aggregate_estimator": "equal-cell-weight exp(fsum(log(cell_ratio)) / cell_count)",
    }:
        raise GateError("measurement estimator contract drifted")
    if contract.get("shards") != [
        {"id": 0, "widths": "6..14", "cells": EXPECTED_SHARD_CELLS},
        {"id": 1, "widths": "15..23", "cells": EXPECTED_SHARD_CELLS},
        {"id": 2, "widths": "24..32", "cells": EXPECTED_SHARD_CELLS},
    ]:
        raise GateError("shard contract drifted")
    if contract.get("acceptance") != EXPECTED_ACCEPTANCE:
        raise GateError("acceptance thresholds drifted")
    execution = contract.get("execution")
    if not isinstance(execution, dict) or execution.get("candidate_timing_executed") is not False:
        raise GateError("frozen contract must precede candidate timing")
    if {
        key: value
        for key, value in execution.items()
        if key != "sealing_authority"
    } != {
        "runs": 1,
        "launcher": "one-shot; three disjoint shards may run concurrently",
        "missing_duplicate_nonfinite_unpaired_wrong_order_or_mutated_input": "hard failure",
        "rebar_input": False,
        "candidate_timing_executed": False,
    } or not isinstance(execution.get("sealing_authority"), str):
        raise GateError("execution contract drifted")
    if contract_path.stat().st_mode & 0o222:
        raise GateError("sealed contract remains writable")
    if cells_path.stat().st_mode & 0o222:
        raise GateError("sealed cell manifest remains writable")


def cell_key(record: Mapping[str, Any]) -> tuple[int, int, int, str]:
    try:
        key = (
            int(record["width"]),
            int(record["output_tag"]),
            int(record["accepted_ordinal"]),
            str(record["window_shape"]),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise GateError(f"invalid cell key: {error}") from error
    return key


def expected_shard(width: int) -> int:
    for shard, (minimum, maximum) in enumerate(SHARD_WIDTHS):
        if minimum <= width <= maximum:
            return shard
    raise GateError(f"width {width} is outside the frozen shard envelope")


def validate_cell_manifest(records: Iterable[dict[str, Any]]) -> dict[tuple[int, int, int, str], dict[str, Any]]:
    cells: dict[tuple[int, int, int, str], dict[str, Any]] = {}
    expected_id = 0
    for record in records:
        if record.get("schema") != "fre-search-v26-development-gate-cell-v1":
            raise GateError("unexpected cell-manifest record schema")
        if record.get("cell_id") != expected_id:
            raise GateError(f"cell id closure broke at {expected_id}")
        key = cell_key(record)
        width, output_tag, accepted_ordinal, window_shape = key
        output = str(record.get("output"))
        if (
            not 6 <= width <= 32
            or output not in EXPECTED_OUTPUTS
            or output_tag != OUTPUT_TAGS[output]
            or not 0 <= accepted_ordinal < 16
            or window_shape not in EXPECTED_WINDOWS
            or record.get("shard_id") != expected_shard(width)
        ):
            raise GateError(f"cell {expected_id} is outside the frozen lattice")
        if key in cells:
            raise GateError(f"duplicate cell key {key}")
        if not isinstance(record.get("literal_sha256"), str) or len(record["literal_sha256"]) != 64:
            raise GateError(f"cell {expected_id} has no literal identity")
        if not isinstance(record.get("fixture_sha256"), str) or len(record["fixture_sha256"]) != 64:
            raise GateError(f"cell {expected_id} has no fixture identity")
        cells[key] = record
        expected_id += 1
    if expected_id != EXPECTED_CELLS or len(cells) != EXPECTED_CELLS:
        raise GateError(f"cell manifest has {expected_id} records, expected {EXPECTED_CELLS}")
    expected_keys = [
        (width, OUTPUT_TAGS[output], ordinal, window)
        for width in range(6, 33)
        for output in EXPECTED_OUTPUTS
        for ordinal in range(16)
        for window in EXPECTED_WINDOWS
    ]
    if list(cells) != expected_keys:
        raise GateError("cell-manifest canonical ordering drifted")
    return cells


def positive_integer(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise GateError(f"{name} must be a positive integer")
    return value


def validate_cell_result(
    record: Mapping[str, Any], expected: Mapping[str, Any], repetition_count: int = 12
) -> float:
    if record.get("schema") != "fre-search-v26-development-gate-cell-result-v1":
        raise GateError("unexpected cell result schema")
    if record.get("cell_id") != expected.get("cell_id") or cell_key(record) != cell_key(expected):
        raise GateError("result cell identity differs from its sealed input")
    for field in ("literal_sha256", "fixture_sha256", "shard_id"):
        if record.get(field) != expected.get(field):
            raise GateError(f"result cell mutated sealed {field}")
    semantics = record.get("semantics")
    if not isinstance(semantics, dict) or semantics.get("equal") is not True:
        raise GateError("exact semantic equality did not pass")
    digests = tuple(semantics.get(engine) for engine in ("portable", "v17", "v26"))
    if any(not isinstance(value, str) or len(value) != 64 for value in digests):
        raise GateError("semantic result digest is missing")
    if len(set(digests)) != 1:
        raise GateError("portable/V17/V26 semantics differ")
    repetitions = record.get("repetitions")
    if not isinstance(repetitions, list) or len(repetitions) != repetition_count:
        raise GateError("cell does not contain exactly 12 repetitions")
    ratios: list[float] = []
    for index, repetition in enumerate(repetitions):
        if not isinstance(repetition, dict) or repetition.get("repetition") != index:
            raise GateError("repetition ordinal closure failed")
        order = tuple(repetition.get("order", ()))
        if repetition_count == 12 and order != EXPECTED_ORDERS[index]:
            raise GateError(f"repetition {index} has the wrong engine order")
        engines = repetition.get("engines")
        if not isinstance(engines, dict) or set(engines) != {"portable", "v17", "v26"}:
            raise GateError("repetition engine closure failed")
        normalized: dict[str, float] = {}
        for engine in ("portable", "v17", "v26"):
            sample = engines[engine]
            if not isinstance(sample, dict):
                raise GateError("engine sample is not an object")
            elapsed = positive_integer(sample.get("elapsed_ns"), f"{engine} elapsed_ns")
            iterations = positive_integer(sample.get("iterations"), f"{engine} iterations")
            normalized[engine] = elapsed / iterations
            if not math.isfinite(normalized[engine]) or normalized[engine] <= 0.0:
                raise GateError("normalized engine time is not finite and positive")
        ratios.append(normalized["v26"] / normalized["v17"])
    return median12(ratios)


def evaluate_thresholds(
    ratios_by_key: Mapping[tuple[int, int, int, str], float],
    acceptance: Mapping[str, Any],
) -> dict[str, Any]:
    if len(ratios_by_key) != EXPECTED_CELLS:
        raise GateError("threshold evaluation requires the complete cell population")
    ratios = list(ratios_by_key.values())
    short = [ratio for key, ratio in ratios_by_key.items() if key[0] <= 8]
    wide = [ratio for key, ratio in ratios_by_key.items() if key[0] >= 9]
    by_output: dict[int, list[float]] = defaultdict(list)
    by_window: dict[str, list[float]] = defaultdict(list)
    for key, ratio in ratios_by_key.items():
        by_output[key[1]].append(ratio)
        by_window[key[3]].append(ratio)
    output_names = {1: "exists", 2: "selected_end", 3: "span"}
    output_gm = {output_names[tag]: geomean(by_output[tag]) for tag in sorted(by_output)}
    window_gm = {window: geomean(by_window[window]) for window in EXPECTED_WINDOWS}
    over = sum(ratio > 1.05 for ratio in ratios)
    maximum = max(ratios)
    report = {
        "overall_geomean": geomean(ratios),
        "short_width_6_through_8_geomean": geomean(short),
        "wide_width_9_through_32_geomean": geomean(wide),
        "output_geomeans": output_gm,
        "window_geomeans": window_gm,
        "cells_strictly_over_1_05": over,
        "cells_strictly_over_1_05_fraction": over / EXPECTED_CELLS,
        "maximum_cell_ratio": maximum,
        "p95_nearest_rank_7388": nearest_rank(ratios, 7_388),
    }
    checks = {
        "overall": report["overall_geomean"] <= acceptance["overall_geomean_lte"],
        "short": report["short_width_6_through_8_geomean"]
        <= acceptance["short_width_6_through_8_geomean_lte"],
        "wide": report["wide_width_9_through_32_geomean"]
        <= acceptance["wide_width_9_through_32_geomean_lte"],
        "outputs": all(
            value <= acceptance["every_output_geomean_lte"] for value in output_gm.values()
        ),
        "windows": all(
            value <= acceptance["every_window_shape_geomean_lte"]
            for value in window_gm.values()
        ),
        "tail_count": over <= acceptance["cells_strictly_over_1_05_lte"],
        "tail_fraction": over / EXPECTED_CELLS
        <= acceptance["cells_strictly_over_1_05_fraction_lte"],
        "maximum": maximum <= acceptance["maximum_cell_ratio_lte"],
    }
    report["checks"] = checks
    report["pass"] = all(checks.values())
    return report


def validate_shard_file(
    path: Path,
    shard_id: int,
    contract_sha256: str,
    cells_sha256: str,
    cells: Mapping[tuple[int, int, int, str], Mapping[str, Any]],
) -> dict[tuple[int, int, int, str], float]:
    records = list(read_jsonl(path))
    if len(records) != EXPECTED_SHARD_CELLS + 2:
        raise GateError(f"shard {shard_id} has the wrong record count")
    header, *body, footer = records
    if (
        header.get("schema") != "fre-search-v26-development-gate-shard-header-v1"
        or header.get("shard_id") != shard_id
        or header.get("contract_sha256") != contract_sha256
        or header.get("cell_manifest_sha256") != cells_sha256
        or header.get("candidate_backend") != 39
        or header.get("reference_backend") != 30
    ):
        raise GateError(f"shard {shard_id} header identity mismatch")
    observed: dict[tuple[int, int, int, str], float] = {}
    for result in body:
        key = cell_key(result)
        expected = cells.get(key)
        if expected is None or expected_shard(key[0]) != shard_id or key in observed:
            raise GateError(f"shard {shard_id} contains an unknown or duplicate cell {key}")
        observed[key] = validate_cell_result(result, expected)
    if len(observed) != EXPECTED_SHARD_CELLS:
        raise GateError(f"shard {shard_id} is incomplete")
    if (
        footer.get("schema") != "fre-search-v26-development-gate-shard-footer-v1"
        or footer.get("shard_id") != shard_id
        or footer.get("cells") != EXPECTED_SHARD_CELLS
        or footer.get("complete") is not True
    ):
        raise GateError(f"shard {shard_id} footer is not terminal")
    return observed


def analyze_paths(
    contract_path: Path, cells_path: Path, shard_paths: Sequence[Path]
) -> dict[str, Any]:
    if len(shard_paths) != 3:
        raise GateError("exactly three shard files are required")
    contract = read_json(contract_path)
    require_exact_contract(contract, contract_path, cells_path)
    cells = validate_cell_manifest(read_jsonl(cells_path))
    contract_sha256 = sha256_file(contract_path)
    cells_sha256 = sha256_file(cells_path)
    ratios: dict[tuple[int, int, int, str], float] = {}
    shard_sha256: list[str] = []
    for shard_id, shard_path in enumerate(shard_paths):
        shard_ratios = validate_shard_file(
            shard_path, shard_id, contract_sha256, cells_sha256, cells
        )
        overlap = ratios.keys() & shard_ratios.keys()
        if overlap:
            raise GateError(f"cross-shard duplicate cells: {sorted(overlap)[:1]}")
        ratios.update(shard_ratios)
        shard_sha256.append(sha256_file(shard_path))
    if set(ratios) != set(cells):
        raise GateError("three-shard result closure differs from the sealed cell manifest")
    metrics = evaluate_thresholds(ratios, contract["acceptance"])
    return {
        "schema": "fre-search-v26-development-gate-analysis-v1",
        "contract_sha256": contract_sha256,
        "cell_manifest_sha256": cells_sha256,
        "shard_sha256": shard_sha256,
        "cells": len(ratios),
        "semantics": {"comparisons": len(ratios) * 3, "mismatches": 0, "pass": True},
        "metrics": metrics,
        "pass": metrics["pass"],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("contract", type=Path)
    parser.add_argument("cells", type=Path)
    parser.add_argument("shards", nargs=3, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        report = analyze_paths(args.contract, args.cells, args.shards)
    except GateError as error:
        print(json.dumps({"schema": "fre-search-v26-development-gate-error-v1", "error": str(error)}))
        return 2
    json.dump(report, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
