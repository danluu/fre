#!/usr/bin/env python3
"""Result-only analyzer for the frozen Search V26 development gate.

The analyzer never emits or executes regex code. It validates a complete,
immutable 7,776-cell closure and recomputes every ratio and aggregate from raw
elapsed nanoseconds and iteration counts.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any, Iterable


EXPECTED_CELLS = 7_776
EXPECTED_ORDERS = (
    ("portable", "v17", "v26"),
    ("portable", "v26", "v17"),
    ("v17", "portable", "v26"),
    ("v17", "v26", "portable"),
    ("v26", "portable", "v17"),
    ("v26", "v17", "portable"),
) * 2


class GateError(ValueError):
    """Malformed, incomplete, or failing gate evidence."""


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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("contract", type=Path)
    parser.add_argument("cells", type=Path)
    parser.add_argument("shards", nargs=3, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    # Full closure and threshold implementation follows in the next
    # result-blind tooling checkpoint.
    contract: dict[str, Any] = json.loads(args.contract.read_text())
    if contract.get("schema") != "fre-search-v26-development-gate-contract-v1":
        raise GateError("unexpected gate contract schema")
    if contract["execution"]["candidate_timing_executed"] is not False:
        raise GateError("tooling contract already claims candidate timing")
    raise GateError("analyzer skeleton is not execution authority")


if __name__ == "__main__":
    raise SystemExit(main())
