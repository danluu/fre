#!/usr/bin/env python3
"""Paired public benchmark for the exact-singleton AOT Count-v3 route."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "fre-aot-direct-count-public-v1"
WIDTHS = (1, 2, 4, 8, 16, 32)
BYTE_SIZES = (64, 4096, 65536, 1048576)
SCENARIOS = ("negative", "early", "late", "dense", "overlap")
RESULT_KEYS = {
    "schema",
    "status",
    "scenario",
    "width",
    "bytes",
    "iterations",
    "elapsed_ns",
    "count",
    "checksum",
    "haystack_sha256",
    "result_sha256",
    "route",
    "non_aot",
}
ROUTE_KEYS = {
    "api",
    "mode",
    "output",
    "aggregate",
    "implementation",
    "target",
    "features",
    "engine",
    "reason",
}
NON_AOT_KEYS = {"count", "plan"}
SEMANTIC_KEYS = (
    "schema",
    "status",
    "scenario",
    "width",
    "bytes",
    "iterations",
    "count",
    "checksum",
    "haystack_sha256",
    "result_sha256",
    "non_aot",
)
IMPLEMENTATIONS = {
    "baseline": "incumbent-ordinary-entry-loop",
    "candidate": "direct-exact-singleton-count-v3",
}
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX16 = re.compile(r"[0-9a-f]{16}\Z")
MAX_ITERATIONS = 10_000_000_000


class BenchmarkFailure(RuntimeError):
    pass


class EventWriter:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.stream = path.open("x", encoding="utf-8", newline="\n")

    def write(self, event: dict[str, Any]) -> None:
        json.dump(event, self.stream, sort_keys=True, separators=(",", ":"))
        self.stream.write("\n")
        self.stream.flush()

    def close(self) -> None:
        self.stream.close()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def parse_int_csv(value: str, allowed: tuple[int, ...], name: str) -> tuple[int, ...]:
    try:
        parsed = tuple(int(item) for item in value.split(",") if item)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"{name} must be comma-separated integers") from error
    if not parsed or len(parsed) != len(set(parsed)):
        raise argparse.ArgumentTypeError(f"{name} must be a nonempty unique list")
    unexpected = [item for item in parsed if item not in allowed]
    if unexpected:
        raise argparse.ArgumentTypeError(
            f"unsupported {name} {unexpected}; allowed values are {allowed}"
        )
    return parsed


def parse_str_csv(value: str, allowed: tuple[str, ...], name: str) -> tuple[str, ...]:
    parsed = tuple(item for item in value.split(",") if item)
    if not parsed or len(parsed) != len(set(parsed)):
        raise argparse.ArgumentTypeError(f"{name} must be a nonempty unique list")
    unexpected = [item for item in parsed if item not in allowed]
    if unexpected:
        raise argparse.ArgumentTypeError(
            f"unsupported {name} {unexpected}; allowed values are {allowed}"
        )
    return parsed


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--baseline", required=True, type=Path)
    result.add_argument("--candidate", required=True, type=Path)
    result.add_argument("--samples", required=True, type=Path)
    result.add_argument("--summary", required=True, type=Path)
    result.add_argument("--baseline-label", default="bb84cb599")
    result.add_argument("--candidate-label", default="ea995db90")
    result.add_argument("--pairs", type=int, default=61)
    result.add_argument("--warmup-pairs", type=int, default=4)
    result.add_argument("--min-sample-ms", type=float, default=200.0)
    result.add_argument("--bootstrap-resamples", type=int, default=5000)
    result.add_argument("--timeout-seconds", type=float, default=600.0)
    result.add_argument("--smoke", action="store_true")
    result.add_argument(
        "--widths",
        type=lambda value: parse_int_csv(value, WIDTHS, "widths"),
        default=WIDTHS,
    )
    result.add_argument(
        "--bytes",
        dest="byte_sizes",
        type=lambda value: parse_int_csv(value, BYTE_SIZES, "bytes"),
        default=BYTE_SIZES,
    )
    result.add_argument(
        "--scenarios",
        type=lambda value: parse_str_csv(value, SCENARIOS, "scenarios"),
        default=SCENARIOS,
    )
    return result


def validate_args(args: argparse.Namespace) -> None:
    args.baseline = args.baseline.resolve(strict=True)
    args.candidate = args.candidate.resolve(strict=True)
    for role in ("baseline", "candidate"):
        path = getattr(args, role)
        if not path.is_file() or not os.access(path, os.X_OK):
            raise BenchmarkFailure(f"{role} is not an executable file: {path}")
    if args.baseline == args.candidate or os.path.samefile(args.baseline, args.candidate):
        raise BenchmarkFailure("baseline and candidate must be distinct executable files")
    baseline_sha = sha256_file(args.baseline)
    candidate_sha = sha256_file(args.candidate)
    if baseline_sha == candidate_sha:
        raise BenchmarkFailure("baseline and candidate executable SHA-256 values are identical")
    args.binary_sha256 = {"baseline": baseline_sha, "candidate": candidate_sha}
    if args.samples.exists() or args.summary.exists():
        raise BenchmarkFailure("samples and summary paths must not already exist")
    if args.samples.resolve() == args.summary.resolve():
        raise BenchmarkFailure("samples and summary paths must differ")
    if args.pairs < 2:
        raise BenchmarkFailure("pairs must be at least 2 so AB and BA strata are nonempty")
    if args.warmup_pairs < 0:
        raise BenchmarkFailure("warmup-pairs must be nonnegative")
    if not math.isfinite(args.min_sample_ms) or args.min_sample_ms <= 0:
        raise BenchmarkFailure("min-sample-ms must be finite and positive")
    if args.bootstrap_resamples < 1:
        raise BenchmarkFailure("bootstrap-resamples must be positive")
    if not math.isfinite(args.timeout_seconds) or args.timeout_seconds <= 0:
        raise BenchmarkFailure("timeout-seconds must be finite and positive")
    if not args.smoke:
        if args.pairs < 61:
            raise BenchmarkFailure("the final gate requires at least 61 pairs; use --smoke for less")
        if args.warmup_pairs < 4:
            raise BenchmarkFailure("the final gate requires at least 4 warmup pairs")
        if args.min_sample_ms < 200:
            raise BenchmarkFailure("the final gate requires samples calibrated to at least 200ms")


def validate_result(
    result: Any,
    *,
    role: str,
    scenario: str,
    width: int,
    byte_size: int,
    iterations: int,
) -> dict[str, Any]:
    if not isinstance(result, dict):
        raise BenchmarkFailure("benchmark stdout JSON must be an object")
    if set(result) != RESULT_KEYS:
        raise BenchmarkFailure(
            f"result schema drift: missing={sorted(RESULT_KEYS - set(result))}, "
            f"extra={sorted(set(result) - RESULT_KEYS)}"
        )
    if result["schema"] != SCHEMA or result["status"] != "ok":
        raise BenchmarkFailure("benchmark returned the wrong schema or status")
    expected_input = (scenario, width, byte_size, iterations)
    actual_input = (
        result["scenario"],
        result["width"],
        result["bytes"],
        result["iterations"],
    )
    if actual_input != expected_input:
        raise BenchmarkFailure(f"benchmark input echo mismatch: {actual_input} != {expected_input}")
    for key in ("width", "bytes", "iterations", "elapsed_ns", "count"):
        if type(result[key]) is not int or result[key] < 0:
            raise BenchmarkFailure(f"result {key} must be a nonnegative integer")
    if result["elapsed_ns"] <= 0:
        raise BenchmarkFailure("elapsed_ns must be positive")
    if not isinstance(result["checksum"], str) or HEX16.fullmatch(result["checksum"]) is None:
        raise BenchmarkFailure("checksum must be 16 lowercase hexadecimal characters")
    for key in ("haystack_sha256", "result_sha256"):
        if not isinstance(result[key], str) or HEX64.fullmatch(result[key]) is None:
            raise BenchmarkFailure(f"{key} must be a lowercase SHA-256")
    route = result["route"]
    if not isinstance(route, dict) or set(route) != ROUTE_KEYS:
        raise BenchmarkFailure("route schema drift")
    if not all(isinstance(value, str) and value for value in route.values()):
        raise BenchmarkFailure("every route value must be a nonempty string")
    if route["implementation"] != IMPLEMENTATIONS[role]:
        raise BenchmarkFailure(
            f"{role} selected {route['implementation']!r}, expected {IMPLEMENTATIONS[role]!r}"
        )
    expected_route = {
        "api": "count-v1",
        "mode": "optimizing",
        "output": "span",
        "aggregate": "native-fused",
        "features": "asimd",
    }
    for key, expected in expected_route.items():
        if route[key] != expected:
            raise BenchmarkFailure(f"unexpected route {key}: {route[key]!r}")
    non_aot = result["non_aot"]
    if not isinstance(non_aot, dict) or set(non_aot) != NON_AOT_KEYS:
        raise BenchmarkFailure("non_aot diagnostic schema drift")
    if type(non_aot["count"]) is not int or non_aot["count"] < 0:
        raise BenchmarkFailure("non_aot count must be a nonnegative integer")
    if non_aot["count"] != result["count"]:
        raise BenchmarkFailure("normal FRE Count diagnostic disagrees with AOT Count")
    if not isinstance(non_aot["plan"], str) or not non_aot["plan"]:
        raise BenchmarkFailure("normal FRE Count diagnostic plan is missing")
    return result


def normalized_route(route: dict[str, str]) -> dict[str, str]:
    result = dict(route)
    del result["implementation"]
    return result


def validate_pair(baseline: dict[str, Any], candidate: dict[str, Any]) -> None:
    mismatches = [key for key in SEMANTIC_KEYS if baseline[key] != candidate[key]]
    if mismatches:
        raise BenchmarkFailure(f"baseline/candidate semantic mismatch in {mismatches}")
    if normalized_route(baseline["route"]) != normalized_route(candidate["route"]):
        raise BenchmarkFailure("baseline/candidate routes differ outside implementation")


def invoke(
    *,
    writer: EventWriter,
    invocation_id: int,
    role: str,
    binary: Path,
    phase: str,
    cell_index: int,
    scenario: str,
    width: int,
    byte_size: int,
    iterations: int,
    ordinal: int,
    order: str,
    slot: int,
    timeout_seconds: float,
) -> dict[str, Any]:
    command = [str(binary), scenario, str(width), str(byte_size), str(iterations)]
    event: dict[str, Any] = {
        "event": "invocation",
        "invocation_id": invocation_id,
        "role": role,
        "phase": phase,
        "cell_index": cell_index,
        "scenario": scenario,
        "width": width,
        "bytes": byte_size,
        "iterations": iterations,
        "ordinal": ordinal,
        "order": order,
        "slot": slot,
        "stdout_sha256": EMPTY_SHA256,
        "stderr_sha256": EMPTY_SHA256,
    }
    started = time.monotonic_ns()
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout_seconds,
        )
        event["wall_ns"] = time.monotonic_ns() - started
        event["returncode"] = completed.returncode
        event["stdout_sha256"] = sha256_bytes(completed.stdout)
        event["stderr_sha256"] = sha256_bytes(completed.stderr)
        if completed.returncode != 0:
            raise BenchmarkFailure(f"{role} exited with status {completed.returncode}")
        try:
            stdout = completed.stdout.decode("utf-8", errors="strict")
            stderr = completed.stderr.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise BenchmarkFailure(f"{role} emitted non-UTF-8 output") from error
        if stderr:
            raise BenchmarkFailure(f"{role} emitted unexpected stderr")
        try:
            parsed = json.loads(stdout)
        except json.JSONDecodeError as error:
            raise BenchmarkFailure(f"{role} emitted invalid JSON") from error
        result = validate_result(
            parsed,
            role=role,
            scenario=scenario,
            width=width,
            byte_size=byte_size,
            iterations=iterations,
        )
        event["result"] = result
    except Exception as error:
        event["wall_ns"] = event.get("wall_ns", time.monotonic_ns() - started)
        event["error"] = f"{type(error).__name__}: {error}"
        if "completed" in locals():
            event["stdout_public"] = completed.stdout.decode("utf-8", errors="backslashreplace")
            event["stderr_public"] = completed.stderr.decode("utf-8", errors="backslashreplace")
        writer.write(event)
        raise
    writer.write(event)
    return result


def order_for(cell_index: int, ordinal: int) -> str:
    return "AB" if (cell_index + ordinal) % 2 == 0 else "BA"


def run_pair(
    *,
    args: argparse.Namespace,
    writer: EventWriter,
    next_invocation_id: list[int],
    phase: str,
    cell_index: int,
    scenario: str,
    width: int,
    byte_size: int,
    iterations: int,
    ordinal: int,
) -> dict[str, Any]:
    order = order_for(cell_index, ordinal)
    roles = ("baseline", "candidate") if order == "AB" else ("candidate", "baseline")
    results: dict[str, dict[str, Any]] = {}
    for slot, role in enumerate(roles):
        invocation_id = next_invocation_id[0]
        next_invocation_id[0] += 1
        results[role] = invoke(
            writer=writer,
            invocation_id=invocation_id,
            role=role,
            binary=getattr(args, role),
            phase=phase,
            cell_index=cell_index,
            scenario=scenario,
            width=width,
            byte_size=byte_size,
            iterations=iterations,
            ordinal=ordinal,
            order=order,
            slot=slot,
            timeout_seconds=args.timeout_seconds,
        )
    validate_pair(results["baseline"], results["candidate"])
    baseline_ns = results["baseline"]["elapsed_ns"]
    candidate_ns = results["candidate"]["elapsed_ns"]
    pair = {
        "event": "pair",
        "phase": phase,
        "cell_index": cell_index,
        "scenario": scenario,
        "width": width,
        "bytes": byte_size,
        "iterations": iterations,
        "ordinal": ordinal,
        "order": order,
        "baseline_elapsed_ns": baseline_ns,
        "candidate_elapsed_ns": candidate_ns,
        "speedup": baseline_ns / candidate_ns,
    }
    writer.write(pair)
    return pair


def calibrate(
    *,
    args: argparse.Namespace,
    writer: EventWriter,
    next_invocation_id: list[int],
    cell_index: int,
    scenario: str,
    width: int,
    byte_size: int,
) -> int:
    target_ns = math.ceil(args.min_sample_ms * 1_000_000)
    iterations = 1
    for attempt in range(12):
        pair = run_pair(
            args=args,
            writer=writer,
            next_invocation_id=next_invocation_id,
            phase="calibration",
            cell_index=cell_index,
            scenario=scenario,
            width=width,
            byte_size=byte_size,
            iterations=iterations,
            ordinal=attempt,
        )
        minimum = min(pair["baseline_elapsed_ns"], pair["candidate_elapsed_ns"])
        if minimum >= target_ns:
            return iterations
        factor = max(2, math.ceil(target_ns / minimum * 1.05))
        proposed = iterations * factor
        if proposed > MAX_ITERATIONS:
            raise BenchmarkFailure(
                f"calibration needs more than {MAX_ITERATIONS} iterations for cell {cell_index}"
            )
        iterations = proposed
    raise BenchmarkFailure(f"calibration did not converge for cell {cell_index}")


def geometric_mean(values: Iterable[float]) -> float:
    logs = [math.log(value) for value in values]
    if not logs:
        raise BenchmarkFailure("cannot summarize an empty sample")
    return math.exp(statistics.fmean(logs))


def percentile(sorted_values: list[float], probability: float) -> float:
    if len(sorted_values) == 1:
        return sorted_values[0]
    location = probability * (len(sorted_values) - 1)
    low = math.floor(location)
    high = math.ceil(location)
    if low == high:
        return sorted_values[low]
    weight = location - low
    return sorted_values[low] * (1.0 - weight) + sorted_values[high] * weight


def bootstrap_geomean_ci(
    ratios: list[float], *, resamples: int, seed: int
) -> tuple[float, float]:
    logs = [math.log(ratio) for ratio in ratios]
    rng = random.Random(seed)
    estimates = []
    for _ in range(resamples):
        estimates.append(
            math.exp(statistics.fmean(rng.choice(logs) for _ in range(len(logs))))
        )
    estimates.sort()
    return percentile(estimates, 0.025), percentile(estimates, 0.975)


def summarize_rows(
    rows: list[dict[str, Any]], *, byte_size: int, resamples: int, seed: int
) -> dict[str, Any]:
    ratios = [row["speedup"] for row in rows]
    baseline_ns_call = [row["baseline_elapsed_ns"] / row["iterations"] for row in rows]
    candidate_ns_call = [row["candidate_elapsed_ns"] / row["iterations"] for row in rows]
    baseline_mean = statistics.fmean(baseline_ns_call)
    candidate_mean = statistics.fmean(candidate_ns_call)
    low, high = bootstrap_geomean_ci(ratios, resamples=resamples, seed=seed)
    result: dict[str, Any] = {
        "pairs": len(rows),
        "speedup_geomean": geometric_mean(ratios),
        "speedup_median": statistics.median(ratios),
        "speedup_ci95": [low, high],
        "baseline_ns_per_call": baseline_mean,
        "candidate_ns_per_call": candidate_mean,
        "candidate_minus_baseline_ns_per_call": candidate_mean - baseline_mean,
        "baseline_ns_per_byte": baseline_mean / byte_size,
        "candidate_ns_per_byte": candidate_mean / byte_size,
        "baseline_gib_per_second": byte_size / baseline_mean * 1e9 / (1024**3),
        "candidate_gib_per_second": byte_size / candidate_mean * 1e9 / (1024**3),
        "order_strata": {},
    }
    for order in ("AB", "BA"):
        stratum = [row for row in rows if row["order"] == order]
        if not stratum:
            raise BenchmarkFailure(f"empty {order} order stratum")
        stratum_ratios = [row["speedup"] for row in stratum]
        result["order_strata"][order] = {
            "pairs": len(stratum),
            "speedup_geomean": geometric_mean(stratum_ratios),
            "baseline_ns_per_call": statistics.fmean(
                row["baseline_elapsed_ns"] / row["iterations"] for row in stratum
            ),
            "candidate_ns_per_call": statistics.fmean(
                row["candidate_elapsed_ns"] / row["iterations"] for row in stratum
            ),
        }
    return result


def write_summary(path: Path, summary: dict[str, Any]) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(summary, stream, sort_keys=True, indent=2)
        stream.write("\n")


def benchmark(args: argparse.Namespace, writer: EventWriter) -> dict[str, Any]:
    cells = [
        (scenario, width, byte_size)
        for scenario in args.scenarios
        for width in args.widths
        for byte_size in args.byte_sizes
    ]
    writer.write(
        {
            "event": "run_start",
            "schema": SCHEMA,
            "time_unix_ns": time.time_ns(),
            "configuration": {
                "pairs": args.pairs,
                "warmup_pairs": args.warmup_pairs,
                "min_sample_ms": args.min_sample_ms,
                "bootstrap_resamples": args.bootstrap_resamples,
                "smoke": args.smoke,
                "widths": args.widths,
                "bytes": args.byte_sizes,
                "scenarios": args.scenarios,
            },
            "binaries": {
                role: {
                    "path": str(getattr(args, role)),
                    "sha256": args.binary_sha256[role],
                    "label": getattr(args, f"{role}_label"),
                }
                for role in ("baseline", "candidate")
            },
        }
    )
    next_invocation_id = [0]
    all_rows: list[dict[str, Any]] = []
    cell_summaries = []
    for cell_index, (scenario, width, byte_size) in enumerate(cells):
        iterations = calibrate(
            args=args,
            writer=writer,
            next_invocation_id=next_invocation_id,
            cell_index=cell_index,
            scenario=scenario,
            width=width,
            byte_size=byte_size,
        )
        for ordinal in range(args.warmup_pairs):
            run_pair(
                args=args,
                writer=writer,
                next_invocation_id=next_invocation_id,
                phase="warmup",
                cell_index=cell_index,
                scenario=scenario,
                width=width,
                byte_size=byte_size,
                iterations=iterations,
                ordinal=ordinal,
            )
        rows = []
        for ordinal in range(args.pairs):
            row = run_pair(
                args=args,
                writer=writer,
                next_invocation_id=next_invocation_id,
                phase="measurement",
                cell_index=cell_index,
                scenario=scenario,
                width=width,
                byte_size=byte_size,
                iterations=iterations,
                ordinal=ordinal,
            )
            rows.append(row)
            all_rows.append(row)
        cell_summary = {
            "cell_index": cell_index,
            "scenario": scenario,
            "width": width,
            "bytes": byte_size,
            "iterations": iterations,
            **summarize_rows(
                rows,
                byte_size=byte_size,
                resamples=args.bootstrap_resamples,
                seed=0xC01A_7000 + cell_index,
            ),
        }
        cell_summaries.append(cell_summary)
        writer.write({"event": "cell_summary", **cell_summary})

    ratios = [row["speedup"] for row in all_rows]
    overall_low, overall_high = bootstrap_geomean_ci(
        ratios,
        resamples=args.bootstrap_resamples,
        seed=0xC01A_7A11,
    )
    summary = {
        "schema": SCHEMA,
        "status": "ok",
        "qualification_gate": (
            not args.smoke
            and args.pairs >= 61
            and args.warmup_pairs >= 4
            and args.min_sample_ms >= 200
        ),
        "baseline": {
            "path": str(args.baseline),
            "sha256": args.binary_sha256["baseline"],
            "label": args.baseline_label,
            "implementation": IMPLEMENTATIONS["baseline"],
        },
        "candidate": {
            "path": str(args.candidate),
            "sha256": args.binary_sha256["candidate"],
            "label": args.candidate_label,
            "implementation": IMPLEMENTATIONS["candidate"],
        },
        "configuration": {
            "pairs": args.pairs,
            "warmup_pairs": args.warmup_pairs,
            "min_sample_ms": args.min_sample_ms,
            "bootstrap_resamples": args.bootstrap_resamples,
            "cells": len(cells),
            "measurement_invocations": len(all_rows) * 2,
        },
        "overall": {
            "paired_speedup_geomean": geometric_mean(ratios),
            "paired_speedup_ci95": [overall_low, overall_high],
            "pairs": len(all_rows),
            "regressing_cells": sum(
                cell["speedup_geomean"] < 1.0 for cell in cell_summaries
            ),
        },
        "cells": cell_summaries,
    }
    writer.write(
        {
            "event": "run_complete",
            "status": "ok",
            "time_unix_ns": time.time_ns(),
            "overall": summary["overall"],
        }
    )
    return summary


def main() -> int:
    args = parser().parse_args()
    try:
        validate_args(args)
    except Exception as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    writer = EventWriter(args.samples)
    try:
        summary = benchmark(args, writer)
    except Exception as error:
        failure = {
            "schema": SCHEMA,
            "status": "failed",
            "error": f"{type(error).__name__}: {error}",
            "samples": str(args.samples),
        }
        writer.write(
            {
                "event": "run_complete",
                "status": "failed",
                "time_unix_ns": time.time_ns(),
                "error": failure["error"],
            }
        )
        writer.close()
        write_summary(args.summary, failure)
        print(f"error: {error}", file=sys.stderr)
        return 1
    writer.close()
    write_summary(args.summary, summary)
    print(json.dumps(summary["overall"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
