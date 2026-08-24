#!/usr/bin/env python3
"""Run the public direct-Exists batch causal comparison.

Build this exact harness commit in both source trees, using isolated target
directories and the manifest checked into each tree:

  FRE_RIPGREP_AOT_PATTERNS_FILE="$PWD/tools/ripgrep-aot-thin/testdata/public-direct-exists-batch.tsv" \
  FRE_RIPGREP_AOT_VARIANTS=optimizing-exists \
  cargo build --release -p fre-ripgrep-aot-thin \
    --example public_direct_exists_batch --target-dir TARGET

Then pass the two TARGET/release/examples/public_direct_exists_batch paths to
this runner. Each recorded sample is a fresh process. The runner writes JSONL
incrementally and never removes or filters a measurement.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import random
import statistics
import subprocess
import sys
import time
from typing import Any, TextIO


SCHEMA = "fre-public-direct-exists-batch-v1"
SCENARIOS = ("negative", "early", "late", "dense-decoy")
BATCHES = (1, 8, 64)
BYTE_SIZES = (64, 4096, 65536)
EXPECTED_ROUTE = {
    "baseline": {"route": "direct-native", "api": "per-haystack", "bulk": "none"},
    "candidate": {
        "route": "direct-native",
        "api": "direct-exists-batch-v1",
        "bulk": "native-direct-public-loop",
    },
}
DEFAULT_PAIRS = 61
DEFAULT_WARMUP_PAIRS = 4
DEFAULT_MIN_SAMPLE_NS = 200_000_000
DEFAULT_TARGET_SAMPLE_NS = 250_000_000
BOOTSTRAP_REPETITIONS = 10_000
RESULT_KEYS = frozenset(
    {
        "schema",
        "status",
        "scenario",
        "batch",
        "bytes_per_haystack",
        "total_bytes",
        "iterations",
        "elapsed_ns",
        "matches_per_batch",
        "input_digest",
        "result_digest",
        "route",
    }
)


class BenchmarkError(RuntimeError):
    """A fail-closed benchmark or validation error."""


class EventLog:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self._stream: TextIO = os.fdopen(descriptor, "w", encoding="utf-8")

    def write(self, event: dict[str, Any]) -> None:
        json.dump(event, self._stream, sort_keys=True, separators=(",", ":"))
        self._stream.write("\n")
        self._stream.flush()

    def close(self) -> None:
        self._stream.close()


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="paired fresh-process public direct Exists-batch benchmark",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--baseline-bin", required=True, type=Path)
    parser.add_argument("--candidate-bin", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--pairs", type=positive_int, default=DEFAULT_PAIRS)
    parser.add_argument("--warmup-pairs", type=nonnegative_int, default=DEFAULT_WARMUP_PAIRS)
    parser.add_argument(
        "--min-sample-ms",
        type=positive_float,
        default=DEFAULT_MIN_SAMPLE_NS / 1_000_000,
    )
    parser.add_argument(
        "--target-sample-ms",
        type=positive_float,
        default=DEFAULT_TARGET_SAMPLE_NS / 1_000_000,
    )
    parser.add_argument("--scenarios", nargs="+", choices=SCENARIOS, default=SCENARIOS)
    parser.add_argument("--batches", nargs="+", type=positive_int, default=BATCHES)
    parser.add_argument("--bytes", nargs="+", type=positive_int, default=BYTE_SIZES)
    return parser.parse_args()


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def nonnegative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be nonnegative")
    return parsed


def positive_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be finite and positive")
    return parsed


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def route_fields(description: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for item in description.split(","):
        key, separator, value = item.partition("=")
        if not separator or not key or key in fields:
            raise BenchmarkError(f"malformed route description: {description!r}")
        fields[key] = value
    return fields


def validate_result(
    result: dict[str, Any],
    *,
    side: str,
    scenario: str,
    batch: int,
    byte_size: int,
    iterations: int,
) -> None:
    if set(result) != RESULT_KEYS:
        missing = sorted(RESULT_KEYS - set(result))
        unexpected = sorted(set(result) - RESULT_KEYS)
        raise BenchmarkError(
            f"{side} result key drift: missing={missing!r} unexpected={unexpected!r}"
        )
    exact = {
        "schema": SCHEMA,
        "status": "ok",
        "scenario": scenario,
        "batch": batch,
        "bytes_per_haystack": byte_size,
        "total_bytes": batch * byte_size,
        "iterations": iterations,
        "matches_per_batch": batch if scenario in ("early", "late") else 0,
    }
    for field, expected in exact.items():
        if result.get(field) != expected:
            raise BenchmarkError(
                f"{side} returned {field}={result.get(field)!r}, expected {expected!r}"
            )
    elapsed = result.get("elapsed_ns")
    if not isinstance(elapsed, int) or isinstance(elapsed, bool) or elapsed <= 0:
        raise BenchmarkError(f"{side} returned invalid elapsed_ns={elapsed!r}")
    for field in ("input_digest", "result_digest"):
        value = result.get(field)
        if not isinstance(value, str) or len(value) != 16:
            raise BenchmarkError(f"{side} returned invalid {field}={value!r}")
        try:
            int(value, 16)
        except ValueError as error:
            raise BenchmarkError(f"{side} returned non-hex {field}={value!r}") from error
    description = result.get("route")
    if not isinstance(description, str):
        raise BenchmarkError(f"{side} returned invalid route={description!r}")
    fields = route_fields(description)
    for field, expected in EXPECTED_ROUTE[side].items():
        if fields.get(field) != expected:
            raise BenchmarkError(
                f"{side} route has {field}={fields.get(field)!r}, expected {expected!r}: {description}"
            )


def invoke(
    *,
    binary: Path,
    side: str,
    scenario: str,
    batch: int,
    byte_size: int,
    iterations: int,
    phase: str,
    ordinal: int,
    pair: int | None,
    order: str,
    event_log: EventLog,
) -> dict[str, Any]:
    command = [
        str(binary),
        scenario,
        str(batch),
        str(byte_size),
        str(iterations),
    ]
    wall_started = time.perf_counter_ns()
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    wall_ns = time.perf_counter_ns() - wall_started
    event: dict[str, Any] = {
        "type": "invocation",
        "phase": phase,
        "ordinal": ordinal,
        "pair": pair,
        "order": order,
        "side": side,
        "scenario": scenario,
        "batch": batch,
        "bytes_per_haystack": byte_size,
        "iterations": iterations,
        "returncode": completed.returncode,
        "wall_ns": wall_ns,
        "stdout_sha256": hashlib.sha256(completed.stdout.encode("utf-8")).hexdigest(),
        "stderr_sha256": hashlib.sha256(completed.stderr.encode("utf-8")).hexdigest(),
    }
    if completed.returncode != 0:
        event["stdout"] = completed.stdout
        event["stderr"] = completed.stderr
        event["validation"] = "failed"
        event_log.write(event)
        raise BenchmarkError(
            f"{side} process failed with status {completed.returncode}: {completed.stderr.strip()}"
        )
    lines = completed.stdout.splitlines()
    if len(lines) != 1:
        event["stdout"] = completed.stdout
        event["stderr"] = completed.stderr
        event["validation"] = "failed"
        event_log.write(event)
        raise BenchmarkError(f"{side} emitted {len(lines)} stdout lines, expected one")
    try:
        result = json.loads(lines[0])
    except json.JSONDecodeError as error:
        event["stdout"] = completed.stdout
        event["stderr"] = completed.stderr
        event["validation"] = "failed"
        event_log.write(event)
        raise BenchmarkError(f"{side} emitted invalid JSON: {error}") from error
    if not isinstance(result, dict):
        event["result"] = result
        event["stderr"] = completed.stderr
        event["validation"] = "failed"
        event_log.write(event)
        raise BenchmarkError(f"{side} result is not a JSON object")
    try:
        validate_result(
            result,
            side=side,
            scenario=scenario,
            batch=batch,
            byte_size=byte_size,
            iterations=iterations,
        )
    except BenchmarkError:
        event["result"] = result
        event["stderr"] = completed.stderr
        event["validation"] = "failed"
        event_log.write(event)
        raise
    event["result"] = result
    event["stderr"] = completed.stderr
    event["validation"] = "ok"
    event_log.write(event)
    return result


def validate_pair(baseline: dict[str, Any], candidate: dict[str, Any]) -> None:
    for field in ("input_digest", "result_digest", "matches_per_batch"):
        if baseline[field] != candidate[field]:
            raise BenchmarkError(
                f"baseline/candidate {field} mismatch: {baseline[field]!r} != {candidate[field]!r}"
            )
    baseline_route = route_fields(baseline["route"])
    candidate_route = route_fields(candidate["route"])
    baseline_normalized = {
        key: value for key, value in baseline_route.items() if key not in ("api", "bulk")
    }
    candidate_normalized = {
        key: value for key, value in candidate_route.items() if key not in ("api", "bulk")
    }
    if baseline_normalized != candidate_normalized:
        raise BenchmarkError(
            "route descriptions differ outside api/bulk: "
            f"{baseline_normalized!r} != {candidate_normalized!r}"
        )


def run_pair(
    *,
    binaries: dict[str, Path],
    scenario: str,
    batch: int,
    byte_size: int,
    iterations: int,
    phase: str,
    ordinal: int,
    pair: int | None,
    order: str,
    event_log: EventLog,
) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for letter in order:
        side = "baseline" if letter == "A" else "candidate"
        results[side] = invoke(
            binary=binaries[side],
            side=side,
            scenario=scenario,
            batch=batch,
            byte_size=byte_size,
            iterations=iterations,
            phase=phase,
            ordinal=ordinal,
            pair=pair,
            order=order,
            event_log=event_log,
        )
    validate_pair(results["baseline"], results["candidate"])
    return results


def calibrate(
    *,
    binaries: dict[str, Path],
    scenario: str,
    batch: int,
    byte_size: int,
    minimum_ns: int,
    target_ns: int,
    cell_index: int,
    event_log: EventLog,
) -> int:
    iterations = 1
    for ordinal in range(16):
        order = "AB" if (cell_index + ordinal) % 2 == 0 else "BA"
        results = run_pair(
            binaries=binaries,
            scenario=scenario,
            batch=batch,
            byte_size=byte_size,
            iterations=iterations,
            phase="calibration",
            ordinal=ordinal,
            pair=None,
            order=order,
            event_log=event_log,
        )
        fastest_ns = min(result["elapsed_ns"] for result in results.values())
        if fastest_ns >= minimum_ns:
            return iterations
        multiplier = max(2, math.ceil(target_ns / fastest_ns))
        iterations = iterations * min(multiplier, 1_000_000)
        if iterations > (1 << 63) - 1:
            raise BenchmarkError("calibrated iteration count exceeds signed 64-bit range")
    raise BenchmarkError("calibration did not reach the minimum sample duration in 16 attempts")


def percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    position = quantile * (len(ordered) - 1)
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def bootstrap_geomean_ci(log_ratios: list[float], seed_material: str) -> tuple[float, float]:
    seed = int.from_bytes(hashlib.sha256(seed_material.encode("ascii")).digest()[:8], "big")
    generator = random.Random(seed)
    count = len(log_ratios)
    estimates = []
    for _ in range(BOOTSTRAP_REPETITIONS):
        mean = sum(log_ratios[generator.randrange(count)] for _ in range(count)) / count
        estimates.append(math.exp(mean))
    return percentile(estimates, 0.025), percentile(estimates, 0.975)


def paired_summary(
    scenario: str,
    batch: int,
    byte_size: int,
    pairs: list[tuple[str, dict[str, dict[str, Any]]]],
) -> dict[str, Any]:
    baseline_ns = [pair["baseline"]["elapsed_ns"] for _, pair in pairs]
    candidate_ns = [pair["candidate"]["elapsed_ns"] for _, pair in pairs]
    ratios = [baseline / candidate for baseline, candidate in zip(baseline_ns, candidate_ns)]
    log_ratios = [math.log(ratio) for ratio in ratios]
    low, high = bootstrap_geomean_ci(log_ratios, f"{scenario}:{batch}:{byte_size}")
    iterations = pairs[0][1]["baseline"]["iterations"]
    baseline_mean = statistics.fmean(baseline_ns)
    candidate_mean = statistics.fmean(candidate_ns)
    bytes_per_invocation = iterations * batch * byte_size
    gib = 1024**3

    order_strata = {}
    for order in ("AB", "BA"):
        selected = [
            results
            for pair_order, results in pairs
            if pair_order == order
        ]
        selected_baseline = [results["baseline"]["elapsed_ns"] for results in selected]
        selected_candidate = [results["candidate"]["elapsed_ns"] for results in selected]
        selected_ratios = [
            baseline / candidate
            for baseline, candidate in zip(selected_baseline, selected_candidate)
        ]
        if selected:
            order_strata[order] = {
                "pair_count": len(selected),
                "paired_geomean_speedup": math.exp(
                    statistics.fmean(math.log(ratio) for ratio in selected_ratios)
                ),
                "paired_median_speedup": statistics.median(selected_ratios),
                "ratio_of_means_speedup": statistics.fmean(selected_baseline)
                / statistics.fmean(selected_candidate),
            }
        else:
            order_strata[order] = {
                "pair_count": 0,
                "paired_geomean_speedup": None,
                "paired_median_speedup": None,
                "ratio_of_means_speedup": None,
            }
    return {
        "type": "paired_summary",
        "scenario": scenario,
        "batch": batch,
        "bytes_per_haystack": byte_size,
        "iterations": iterations,
        "pair_count": len(pairs),
        "baseline_mean_ns": baseline_mean,
        "baseline_median_ns": statistics.median(baseline_ns),
        "candidate_mean_ns": candidate_mean,
        "candidate_median_ns": statistics.median(candidate_ns),
        "baseline_mean_ns_per_batch": baseline_mean / iterations,
        "candidate_mean_ns_per_batch": candidate_mean / iterations,
        "baseline_mean_ns_per_item": baseline_mean / (iterations * batch),
        "candidate_mean_ns_per_item": candidate_mean / (iterations * batch),
        "baseline_mean_gib_per_second": (bytes_per_invocation / gib)
        / (baseline_mean / 1e9),
        "candidate_mean_gib_per_second": (bytes_per_invocation / gib)
        / (candidate_mean / 1e9),
        "candidate_elapsed_delta_percent": 100 * (candidate_mean / baseline_mean - 1),
        "ratio_of_means_speedup": baseline_mean / candidate_mean,
        "paired_geomean_speedup": math.exp(statistics.fmean(log_ratios)),
        "paired_geomean_speedup_bootstrap_95_low": low,
        "paired_geomean_speedup_bootstrap_95_high": high,
        "paired_median_speedup": statistics.median(ratios),
        "paired_p05_speedup": percentile(ratios, 0.05),
        "paired_p95_speedup": percentile(ratios, 0.95),
        "candidate_wins": sum(
            candidate < baseline for baseline, candidate in zip(baseline_ns, candidate_ns)
        ),
        "candidate_ties": sum(
            candidate == baseline for baseline, candidate in zip(baseline_ns, candidate_ns)
        ),
        "order_strata": order_strata,
    }


def validate_binary(path: Path, name: str) -> Path:
    resolved = path.expanduser().resolve(strict=True)
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise BenchmarkError(f"{name} is not an executable regular file: {resolved}")
    return resolved


def main() -> int:
    arguments = parse_arguments()
    event_log: EventLog | None = None
    try:
        minimum_ns = round(arguments.min_sample_ms * 1_000_000)
        target_ns = round(arguments.target_sample_ms * 1_000_000)
        if target_ns < minimum_ns:
            raise BenchmarkError("--target-sample-ms must be at least --min-sample-ms")
        if any(batch > 64 for batch in arguments.batches):
            raise BenchmarkError("all --batches values must be at most 64")
        if any(byte_size < 64 for byte_size in arguments.bytes):
            raise BenchmarkError("all --bytes values must be at least 64")
        binaries = {
            "baseline": validate_binary(arguments.baseline_bin, "baseline binary"),
            "candidate": validate_binary(arguments.candidate_bin, "candidate binary"),
        }
        event_log = EventLog(arguments.output)
        event_log.write(
            {
                "type": "metadata",
                "schema": "fre-public-direct-exists-batch-run-v1",
                "baseline_binary": str(binaries["baseline"]),
                "baseline_sha256": file_sha256(binaries["baseline"]),
                "candidate_binary": str(binaries["candidate"]),
                "candidate_sha256": file_sha256(binaries["candidate"]),
                "scenarios": arguments.scenarios,
                "batches": arguments.batches,
                "byte_sizes": arguments.bytes,
                "pairs": arguments.pairs,
                "warmup_pairs": arguments.warmup_pairs,
                "minimum_sample_ns": minimum_ns,
                "target_sample_ns": target_ns,
                "bootstrap_repetitions": BOOTSTRAP_REPETITIONS,
                "sample_policy": "retain-all",
                "process_policy": "fresh-process-per-invocation",
                "order_policy": "alternating-AB-BA",
            }
        )
        summaries = []
        cells = [
            (scenario, batch, byte_size)
            for scenario in arguments.scenarios
            for batch in arguments.batches
            for byte_size in arguments.bytes
        ]
        for cell_index, (scenario, batch, byte_size) in enumerate(cells):
            print(
                f"calibrating {scenario} batch={batch} bytes={byte_size}",
                file=sys.stderr,
                flush=True,
            )
            iterations = calibrate(
                binaries=binaries,
                scenario=scenario,
                batch=batch,
                byte_size=byte_size,
                minimum_ns=minimum_ns,
                target_ns=target_ns,
                cell_index=cell_index,
                event_log=event_log,
            )
            event_log.write(
                {
                    "type": "calibrated",
                    "scenario": scenario,
                    "batch": batch,
                    "bytes_per_haystack": byte_size,
                    "iterations": iterations,
                }
            )
            for warmup in range(arguments.warmup_pairs):
                order = "AB" if (cell_index + warmup) % 2 == 0 else "BA"
                run_pair(
                    binaries=binaries,
                    scenario=scenario,
                    batch=batch,
                    byte_size=byte_size,
                    iterations=iterations,
                    phase="warmup",
                    ordinal=warmup,
                    pair=None,
                    order=order,
                    event_log=event_log,
                )
            measured = []
            for pair in range(arguments.pairs):
                order = "AB" if (cell_index + pair) % 2 == 0 else "BA"
                measured.append(
                    (
                        order,
                        run_pair(
                            binaries=binaries,
                            scenario=scenario,
                            batch=batch,
                            byte_size=byte_size,
                            iterations=iterations,
                            phase="measure",
                            ordinal=pair,
                            pair=pair,
                            order=order,
                            event_log=event_log,
                        ),
                    )
                )
            summary = paired_summary(scenario, batch, byte_size, measured)
            summaries.append(summary)
            event_log.write(summary)
            print(
                f"finished {scenario} batch={batch} bytes={byte_size}: "
                f"{summary['paired_geomean_speedup']:.4f}x",
                file=sys.stderr,
                flush=True,
            )
        cell_log_speedups = [
            math.log(summary["paired_geomean_speedup"]) for summary in summaries
        ]
        aggregate_low, aggregate_high = bootstrap_geomean_ci(
            cell_log_speedups, "aggregate-cells"
        )
        aggregate = {
            "type": "aggregate_summary",
            "cell_count": len(summaries),
            "pairs_per_cell": arguments.pairs,
            "measured_invocations": len(summaries) * arguments.pairs * 2,
            "equal_cell_geomean_speedup": math.exp(statistics.fmean(cell_log_speedups)),
            "equal_cell_geomean_speedup_bootstrap_95_low": aggregate_low,
            "equal_cell_geomean_speedup_bootstrap_95_high": aggregate_high,
            "status": "complete",
        }
        event_log.write(aggregate)
        print(json.dumps(aggregate, sort_keys=True, separators=(",", ":")))
        return 0
    except (BenchmarkError, OSError, ValueError) as error:
        if event_log is not None:
            event_log.write({"type": "error", "status": "failed", "message": str(error)})
        print(f"benchmark-aot-direct-exists-batch: {error}", file=sys.stderr)
        return 1
    finally:
        if event_log is not None:
            event_log.close()


if __name__ == "__main__":
    raise SystemExit(main())
