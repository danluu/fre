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

For a same-artifact causal comparison, build the direct-batch candidate once,
pass that exact executable as both --baseline-bin and --candidate-bin, and add
--same-binary-causal. The runner then sends the equal-length, versioned
timed-mode tokens scalar-loop-v1 and direct-call-v1. Both modes prepare identical generated
haystacks and descriptors before timing; only the selected timed call path
differs. Each result must authenticate the expected timed_mode route field.

After an interruption, rerun the identical command with --resume. Resume
authenticates the binaries, options, routes, and every existing event before
opening the file with O_APPEND. It reuses complete pairs and, if the final
record is the first arm of the predetermined AB/BA order, runs only its missing
counterpart. Malformed, inconsistent, or failed logs remain untouched.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import hashlib
import json
import math
import os
from pathlib import Path
import random
import stat
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
        "bulk": "native-direct-trusted-full-window-loop",
    },
}
DIRECT_BATCH_ROUTE = {
    "route": "direct-native",
    "api": "direct-exists-batch-v1",
    "bulk": "native-direct-trusted-full-window-loop",
}
SAME_BINARY_EXECUTION_MODES = {
    "baseline": "scalar-loop-v1",
    "candidate": "direct-call-v1",
}
SAME_BINARY_TIMED_ROUTE = {
    "baseline": "scalar-per-haystack-loop-v1",
    "candidate": "direct-descriptor-batch-api-v1",
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
INVOCATION_KEYS = frozenset(
    {
        "type",
        "phase",
        "ordinal",
        "pair",
        "order",
        "side",
        "scenario",
        "batch",
        "bytes_per_haystack",
        "iterations",
        "returncode",
        "wall_ns",
        "stdout_sha256",
        "stderr_sha256",
        "result",
        "stderr",
        "validation",
    }
)
CALIBRATED_KEYS = frozenset(
    {"type", "scenario", "batch", "bytes_per_haystack", "iterations"}
)


class BenchmarkError(RuntimeError):
    """A fail-closed benchmark or validation error."""


@dataclass(frozen=True)
class LogIdentity:
    device: int
    inode: int
    size: int
    mtime_ns: int
    sha256: str


@dataclass
class ResumeProgress:
    summaries: list[dict[str, Any]]
    cell_index: int
    phase: str
    iterations: int | None = None
    calibration_ordinal: int = 0
    warmup_pairs_completed: int = 0
    measured: list[tuple[str, dict[str, dict[str, Any]]]] = field(
        default_factory=list
    )
    partial_results: dict[str, dict[str, Any]] = field(default_factory=dict)
    aggregate: dict[str, Any] | None = None


class EventLog:
    def __init__(
        self,
        path: Path,
        *,
        append_identity: LogIdentity | None = None,
    ) -> None:
        if append_identity is None:
            path.parent.mkdir(parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        else:
            flags = os.O_RDWR | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o600)
        if append_identity is not None:
            try:
                opened = os.fstat(descriptor)
                identity = LogIdentity(
                    opened.st_dev,
                    opened.st_ino,
                    opened.st_size,
                    opened.st_mtime_ns,
                    _descriptor_sha256(descriptor, opened.st_size),
                )
                if not stat.S_ISREG(opened.st_mode) or identity != append_identity:
                    raise BenchmarkError(
                        "output changed between resume validation and append open"
                    )
            except Exception:
                os.close(descriptor)
                raise
        self._stream: TextIO = os.fdopen(descriptor, "w", encoding="utf-8")

    def write(self, event: dict[str, Any]) -> None:
        json.dump(event, self._stream, sort_keys=True, separators=(",", ":"))
        self._stream.write("\n")
        self._stream.flush()

    def close(self) -> None:
        self._stream.close()


def _descriptor_sha256(descriptor: int, size: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        chunk = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
        if not chunk:
            raise BenchmarkError("output became unreadable during identity validation")
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="paired fresh-process public direct Exists-batch benchmark",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--baseline-bin", required=True, type=Path)
    parser.add_argument("--candidate-bin", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--resume",
        action="store_true",
        help=(
            "validate and append to an interrupted output without repeating "
            "complete pairs"
        ),
    )
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
    parser.add_argument(
        "--baseline-route",
        choices=("per-haystack", "direct-batch"),
        default="per-haystack",
        help="authenticated API route expected from the baseline binary",
    )
    parser.add_argument(
        "--same-binary-causal",
        action="store_true",
        help=(
            "require both binary paths to resolve identically, then compare "
            "the explicit scalar-loop and direct-descriptor-batch timed modes"
        ),
    )
    return parser.parse_args(argv)


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
    expected_routes: dict[str, dict[str, str]],
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
        actual = result.get(field)
        if type(actual) is not type(expected) or actual != expected:
            raise BenchmarkError(
                f"{side} returned {field}={actual!r}, expected {expected!r}"
            )
    elapsed = result.get("elapsed_ns")
    if type(elapsed) is not int or elapsed <= 0:
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
    for field, expected in expected_routes[side].items():
        if fields.get(field) != expected:
            raise BenchmarkError(
                f"{side} route has {field}={fields.get(field)!r}, expected {expected!r}: {description}"
            )


def invocation_command(
    binary: Path,
    scenario: str,
    batch: int,
    byte_size: int,
    iterations: int,
    timed_mode: str | None,
) -> list[str]:
    if timed_mode is not None and timed_mode not in SAME_BINARY_EXECUTION_MODES.values():
        raise BenchmarkError(f"unsupported benchmark timed mode: {timed_mode!r}")
    command = [
        str(binary),
        scenario,
        str(batch),
        str(byte_size),
        str(iterations),
    ]
    if timed_mode is not None:
        command.append(timed_mode)
    return command


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
    expected_routes: dict[str, dict[str, str]],
    execution_modes: dict[str, str] | None = None,
) -> dict[str, Any]:
    timed_mode = None if execution_modes is None else execution_modes[side]
    command = invocation_command(
        binary, scenario, batch, byte_size, iterations, timed_mode
    )
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
        result = json.loads(
            lines[0],
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, BenchmarkError) as error:
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
            expected_routes=expected_routes,
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


def validate_pair(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    *,
    expected_routes: dict[str, dict[str, str]],
) -> None:
    for field in ("input_digest", "result_digest", "matches_per_batch"):
        if baseline[field] != candidate[field]:
            raise BenchmarkError(
                f"baseline/candidate {field} mismatch: {baseline[field]!r} != {candidate[field]!r}"
            )
    baseline_route = route_fields(baseline["route"])
    candidate_route = route_fields(candidate["route"])
    allowed_differences = {"api", "bulk"}
    for field in set(expected_routes["baseline"]) | set(expected_routes["candidate"]):
        if expected_routes["baseline"].get(field) != expected_routes["candidate"].get(
            field
        ):
            allowed_differences.add(field)
    baseline_normalized = {
        key: value
        for key, value in baseline_route.items()
        if key not in allowed_differences
    }
    candidate_normalized = {
        key: value
        for key, value in candidate_route.items()
        if key not in allowed_differences
    }
    if baseline_normalized != candidate_normalized:
        raise BenchmarkError(
            "route descriptions differ outside authenticated per-arm fields: "
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
    expected_routes: dict[str, dict[str, str]],
    execution_modes: dict[str, str] | None = None,
    existing_results: dict[str, dict[str, Any]] | None = None,
) -> dict[str, dict[str, Any]]:
    results = {} if existing_results is None else dict(existing_results)
    expected_sides = [
        "baseline" if letter == "A" else "candidate" for letter in order
    ]
    if set(results) != set(expected_sides[: len(results)]) or len(results) > 1:
        raise BenchmarkError(
            f"partial {phase} pair {ordinal} is not an exact one-arm order prefix"
        )
    for letter in order[len(results) :]:
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
            expected_routes=expected_routes,
            execution_modes=execution_modes,
        )
    validate_pair(
        results["baseline"], results["candidate"], expected_routes=expected_routes
    )
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
    expected_routes: dict[str, dict[str, str]],
    execution_modes: dict[str, str] | None = None,
    start_iterations: int = 1,
    start_ordinal: int = 0,
    start_partial_results: dict[str, dict[str, Any]] | None = None,
) -> int:
    iterations = start_iterations
    for ordinal in range(start_ordinal, 16):
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
            expected_routes=expected_routes,
            execution_modes=execution_modes,
            existing_results=(
                start_partial_results if ordinal == start_ordinal else None
            ),
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


def aggregate_summary(
    summaries: list[dict[str, Any]], pairs_per_cell: int
) -> dict[str, Any]:
    cell_log_speedups = [
        math.log(summary["paired_geomean_speedup"]) for summary in summaries
    ]
    aggregate_low, aggregate_high = bootstrap_geomean_ci(
        cell_log_speedups, "aggregate-cells"
    )
    return {
        "type": "aggregate_summary",
        "cell_count": len(summaries),
        "pairs_per_cell": pairs_per_cell,
        "measured_invocations": len(summaries) * pairs_per_cell * 2,
        "equal_cell_geomean_speedup": math.exp(
            statistics.fmean(cell_log_speedups)
        ),
        "equal_cell_geomean_speedup_bootstrap_95_low": aggregate_low,
        "equal_cell_geomean_speedup_bootstrap_95_high": aggregate_high,
        "status": "complete",
    }


def metadata_event(
    *,
    binaries: dict[str, Path],
    scenarios: list[str] | tuple[str, ...],
    batches: list[int] | tuple[int, ...],
    byte_sizes: list[int] | tuple[int, ...],
    pairs: int,
    warmup_pairs: int,
    minimum_ns: int,
    target_ns: int,
    expected_routes: dict[str, dict[str, str]],
    execution_modes: dict[str, str] | None = None,
) -> dict[str, Any]:
    event = {
        "type": "metadata",
        "schema": "fre-public-direct-exists-batch-run-v1",
        "baseline_binary": str(binaries["baseline"]),
        "baseline_sha256": file_sha256(binaries["baseline"]),
        "candidate_binary": str(binaries["candidate"]),
        "candidate_sha256": file_sha256(binaries["candidate"]),
        "scenarios": list(scenarios),
        "batches": list(batches),
        "byte_sizes": list(byte_sizes),
        "pairs": pairs,
        "warmup_pairs": warmup_pairs,
        "minimum_sample_ns": minimum_ns,
        "target_sample_ns": target_ns,
        "bootstrap_repetitions": BOOTSTRAP_REPETITIONS,
        "sample_policy": "retain-all",
        "process_policy": "fresh-process-per-invocation",
        "order_policy": "alternating-AB-BA",
        "expected_routes": expected_routes,
        "route_evidence": {
            "description_scope": "linked-artifact-capability-not-dynamic-call-counter",
            "singleton_dispatch": "batch=1-source-audited-scalar-entry",
            "larger_dispatch": "batch=2..64-authenticated-direct-entry",
        },
    }
    if execution_modes is not None:
        causal_routes = {
            side: {
                **DIRECT_BATCH_ROUTE,
                "timed_mode": SAME_BINARY_TIMED_ROUTE[side],
            }
            for side in ("baseline", "candidate")
        }
        if binaries["baseline"] != binaries["candidate"]:
            raise BenchmarkError(
                "same-binary metadata requires identical resolved binary paths"
            )
        if not structurally_equal(execution_modes, SAME_BINARY_EXECUTION_MODES):
            raise BenchmarkError(
                f"invalid same-binary execution modes: {execution_modes!r}"
            )
        if not structurally_equal(expected_routes, causal_routes):
            raise BenchmarkError(
                f"invalid same-binary expected routes: {expected_routes!r}"
            )
        if event["baseline_sha256"] != event["candidate_sha256"]:
            raise BenchmarkError("same-binary hashes changed during metadata capture")
        event.update(
            {
                "comparison_policy": "same-binary-explicit-timed-mode-v1",
                "binary_identity_policy": "same-resolved-executable-v1",
                "execution_modes": execution_modes,
            }
        )
    return event


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BenchmarkError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise BenchmarkError(f"non-finite JSON number {value!r}")


def structurally_equal(actual: Any, expected: Any) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(actual) == set(expected) and all(
            structurally_equal(actual[key], expected[key]) for key in expected
        )
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(
            structurally_equal(actual_item, expected_item)
            for actual_item, expected_item in zip(actual, expected)
        )
    return actual == expected


def read_event_log(path: Path) -> tuple[list[dict[str, Any]], LogIdentity]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise BenchmarkError(f"resume output is not a regular file: {path}")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            raw = stream.read()
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    before_identity = LogIdentity(
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        hashlib.sha256(raw).hexdigest(),
    )
    identity = LogIdentity(
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        hashlib.sha256(raw).hexdigest(),
    )
    if before_identity != identity or len(raw) != identity.size:
        raise BenchmarkError("resume output changed while it was being validated")
    if not raw:
        raise BenchmarkError("resume output is empty")
    if not raw.endswith(b"\n"):
        raise BenchmarkError("resume output ends with an incomplete JSONL record")
    events: list[dict[str, Any]] = []
    for record_number, encoded in enumerate(raw[:-1].split(b"\n"), 1):
        if not encoded:
            raise BenchmarkError(f"empty JSONL record {record_number}")
        try:
            line = encoded.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise BenchmarkError(
                f"JSONL record {record_number} is not UTF-8"
            ) from error
        try:
            event = json.loads(
                line,
                object_pairs_hook=_strict_json_object,
                parse_constant=_reject_json_constant,
            )
        except json.JSONDecodeError as error:
            raise BenchmarkError(
                f"JSONL record {record_number} is invalid JSON: {error}"
            ) from error
        if not isinstance(event, dict):
            raise BenchmarkError(f"JSONL record {record_number} is not an object")
        events.append(event)
    return events, identity


def _validate_sha256(value: Any, description: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or value != value.lower():
        raise BenchmarkError(f"invalid {description}: {value!r}")
    try:
        int(value, 16)
    except ValueError as error:
        raise BenchmarkError(f"invalid {description}: {value!r}") from error


def validate_invocation_event(
    event: dict[str, Any],
    *,
    side: str,
    phase: str,
    ordinal: int,
    pair: int | None,
    order: str,
    scenario: str,
    batch: int,
    byte_size: int,
    iterations: int,
    expected_routes: dict[str, dict[str, str]],
) -> dict[str, Any]:
    if set(event) != INVOCATION_KEYS:
        missing = sorted(INVOCATION_KEYS - set(event))
        unexpected = sorted(set(event) - INVOCATION_KEYS)
        raise BenchmarkError(
            f"invocation key drift: missing={missing!r} unexpected={unexpected!r}"
        )
    exact = {
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
        "returncode": 0,
        "validation": "ok",
    }
    for name, expected in exact.items():
        actual = event.get(name)
        if type(actual) is not type(expected) or actual != expected:
            raise BenchmarkError(
                f"invocation has {name}={actual!r}, expected {expected!r}"
            )
    wall_ns = event.get("wall_ns")
    if type(wall_ns) is not int or wall_ns <= 0:
        raise BenchmarkError(f"invocation has invalid wall_ns={wall_ns!r}")
    _validate_sha256(event.get("stdout_sha256"), "stdout_sha256")
    _validate_sha256(event.get("stderr_sha256"), "stderr_sha256")
    stderr = event.get("stderr")
    if not isinstance(stderr, str):
        raise BenchmarkError(f"invocation has invalid stderr={stderr!r}")
    expected_stderr_sha256 = hashlib.sha256(stderr.encode("utf-8")).hexdigest()
    if event["stderr_sha256"] != expected_stderr_sha256:
        raise BenchmarkError("invocation stderr_sha256 does not authenticate stderr")
    result = event.get("result")
    if not isinstance(result, dict):
        raise BenchmarkError("invocation result is not an object")
    validate_result(
        result,
        side=side,
        scenario=scenario,
        batch=batch,
        byte_size=byte_size,
        iterations=iterations,
        expected_routes=expected_routes,
    )
    return result


def consume_logged_pair(
    events: list[dict[str, Any]],
    cursor: int,
    *,
    phase: str,
    ordinal: int,
    pair: int | None,
    order: str,
    scenario: str,
    batch: int,
    byte_size: int,
    iterations: int,
    expected_routes: dict[str, dict[str, str]],
) -> tuple[dict[str, dict[str, Any]], int, bool]:
    if cursor >= len(events):
        raise BenchmarkError(f"missing {phase} pair {ordinal}")
    results: dict[str, dict[str, Any]] = {}
    for offset, letter in enumerate(order):
        if cursor + offset >= len(events):
            if offset == 1:
                return results, cursor + 1, False
            raise AssertionError("logged pair consumer lost its first arm")
        side = "baseline" if letter == "A" else "candidate"
        event = events[cursor + offset]
        if event.get("type") != "invocation":
            raise BenchmarkError(
                f"incomplete {phase} pair {ordinal}: expected {side} invocation"
            )
        results[side] = validate_invocation_event(
            event,
            side=side,
            phase=phase,
            ordinal=ordinal,
            pair=pair,
            order=order,
            scenario=scenario,
            batch=batch,
            byte_size=byte_size,
            iterations=iterations,
            expected_routes=expected_routes,
        )
    validate_pair(
        results["baseline"], results["candidate"], expected_routes=expected_routes
    )
    return results, cursor + 2, True


def validate_calibrated_event(
    event: dict[str, Any],
    *,
    scenario: str,
    batch: int,
    byte_size: int,
    iterations: int,
) -> None:
    if set(event) != CALIBRATED_KEYS:
        missing = sorted(CALIBRATED_KEYS - set(event))
        unexpected = sorted(set(event) - CALIBRATED_KEYS)
        raise BenchmarkError(
            f"calibrated key drift: missing={missing!r} unexpected={unexpected!r}"
        )
    expected = {
        "type": "calibrated",
        "scenario": scenario,
        "batch": batch,
        "bytes_per_haystack": byte_size,
        "iterations": iterations,
    }
    for name, expected_value in expected.items():
        actual = event.get(name)
        if type(actual) is not type(expected_value) or actual != expected_value:
            raise BenchmarkError(
                f"calibrated event has {name}={actual!r}, "
                f"expected {expected_value!r}"
            )


def validate_resume_events(
    events: list[dict[str, Any]],
    *,
    expected_metadata: dict[str, Any],
    cells: list[tuple[str, int, int]],
    pairs: int,
    warmup_pairs: int,
    minimum_ns: int,
    target_ns: int,
    expected_routes: dict[str, dict[str, str]],
) -> ResumeProgress:
    if not events:
        raise BenchmarkError("resume output has no metadata record")
    if len(set(cells)) != len(cells):
        raise BenchmarkError("benchmark cell list contains duplicates")
    metadata_compatibility = validate_resume_metadata(
        events[0], expected_metadata=expected_metadata
    )
    if metadata_compatibility not in ("current-v1", "legacy-v1-without-route-evidence"):
        raise AssertionError("unhandled metadata compatibility result")
    for record_number, event in enumerate(events[1:], 2):
        if event.get("type") == "error":
            raise BenchmarkError(
                f"resume output contains terminal error event at record {record_number}"
            )

    cursor = 1
    summaries: list[dict[str, Any]] = []
    for cell_index, (scenario, batch, byte_size) in enumerate(cells):
        iterations = 1
        calibration_ordinal = 0
        calibration_ready = False
        while True:
            if calibration_ready:
                if cursor == len(events):
                    return ResumeProgress(
                        summaries,
                        cell_index,
                        "record-calibrated",
                        iterations=iterations,
                        calibration_ordinal=calibration_ordinal,
                    )
                validate_calibrated_event(
                    events[cursor],
                    scenario=scenario,
                    batch=batch,
                    byte_size=byte_size,
                    iterations=iterations,
                )
                cursor += 1
                break
            if cursor == len(events):
                return ResumeProgress(
                    summaries,
                    cell_index,
                    "calibration",
                    iterations=iterations,
                    calibration_ordinal=calibration_ordinal,
                )
            if calibration_ordinal >= 16:
                raise BenchmarkError(
                    f"calibration exhausted 16 pairs for cell {cell_index}"
                )
            order = "AB" if (cell_index + calibration_ordinal) % 2 == 0 else "BA"
            results, cursor, pair_complete = consume_logged_pair(
                events,
                cursor,
                phase="calibration",
                ordinal=calibration_ordinal,
                pair=None,
                order=order,
                scenario=scenario,
                batch=batch,
                byte_size=byte_size,
                iterations=iterations,
                expected_routes=expected_routes,
            )
            if not pair_complete:
                return ResumeProgress(
                    summaries,
                    cell_index,
                    "calibration",
                    iterations=iterations,
                    calibration_ordinal=calibration_ordinal,
                    partial_results=results,
                )
            fastest_ns = min(result["elapsed_ns"] for result in results.values())
            if fastest_ns >= minimum_ns:
                calibration_ready = True
                continue
            multiplier = max(2, math.ceil(target_ns / fastest_ns))
            iterations *= min(multiplier, 1_000_000)
            if iterations > (1 << 63) - 1:
                raise BenchmarkError(
                    "logged calibration implies an iteration count beyond signed 64-bit"
                )
            calibration_ordinal += 1

        warmup_completed = 0
        while warmup_completed < warmup_pairs:
            if cursor == len(events):
                return ResumeProgress(
                    summaries,
                    cell_index,
                    "warmup",
                    iterations=iterations,
                    warmup_pairs_completed=warmup_completed,
                )
            order = "AB" if (cell_index + warmup_completed) % 2 == 0 else "BA"
            results, cursor, pair_complete = consume_logged_pair(
                events,
                cursor,
                phase="warmup",
                ordinal=warmup_completed,
                pair=None,
                order=order,
                scenario=scenario,
                batch=batch,
                byte_size=byte_size,
                iterations=iterations,
                expected_routes=expected_routes,
            )
            if not pair_complete:
                return ResumeProgress(
                    summaries,
                    cell_index,
                    "warmup",
                    iterations=iterations,
                    warmup_pairs_completed=warmup_completed,
                    partial_results=results,
                )
            warmup_completed += 1

        measured: list[tuple[str, dict[str, dict[str, Any]]]] = []
        while len(measured) < pairs:
            if cursor == len(events):
                return ResumeProgress(
                    summaries,
                    cell_index,
                    "measure",
                    iterations=iterations,
                    warmup_pairs_completed=warmup_pairs,
                    measured=measured,
                )
            pair = len(measured)
            order = "AB" if (cell_index + pair) % 2 == 0 else "BA"
            results, cursor, pair_complete = consume_logged_pair(
                events,
                cursor,
                phase="measure",
                ordinal=pair,
                pair=pair,
                order=order,
                scenario=scenario,
                batch=batch,
                byte_size=byte_size,
                iterations=iterations,
                expected_routes=expected_routes,
            )
            if not pair_complete:
                return ResumeProgress(
                    summaries,
                    cell_index,
                    "measure",
                    iterations=iterations,
                    warmup_pairs_completed=warmup_pairs,
                    measured=measured,
                    partial_results=results,
                )
            measured.append((order, results))

        expected_summary = paired_summary(scenario, batch, byte_size, measured)
        if cursor == len(events):
            return ResumeProgress(
                summaries,
                cell_index,
                "summary",
                iterations=iterations,
                warmup_pairs_completed=warmup_pairs,
                measured=measured,
            )
        if not structurally_equal(events[cursor], expected_summary):
            raise BenchmarkError(
                f"paired summary does not authenticate measured cell {cell_index}"
            )
        summaries.append(events[cursor])
        cursor += 1

    expected_aggregate = aggregate_summary(summaries, pairs)
    if cursor == len(events):
        return ResumeProgress(summaries, len(cells), "aggregate")
    if not structurally_equal(events[cursor], expected_aggregate):
        raise BenchmarkError("aggregate summary does not authenticate all cell summaries")
    cursor += 1
    if cursor != len(events):
        raise BenchmarkError("resume output has records after its aggregate summary")
    return ResumeProgress(
        summaries,
        len(cells),
        "complete",
        aggregate=expected_aggregate,
    )


def validate_resume_metadata(
    actual: dict[str, Any], *, expected_metadata: dict[str, Any]
) -> str:
    if structurally_equal(actual, expected_metadata):
        return "current-v1"
    if "comparison_policy" not in expected_metadata:
        legacy_expected = dict(expected_metadata)
        legacy_expected.pop("route_evidence")
        if set(actual) == set(legacy_expected) and structurally_equal(
            actual, legacy_expected
        ):
            return "legacy-v1-without-route-evidence"
    keys = sorted(set(actual) | set(expected_metadata))
    differences = [
        key
        for key in keys
        if not structurally_equal(actual.get(key), expected_metadata.get(key))
    ]
    raise BenchmarkError(
        "resume metadata does not match requested binaries/options/routes or "
        "the exact legacy-v1 compatibility shape; "
        f"different fields={differences!r}"
    )


def validate_binary(path: Path, name: str) -> Path:
    resolved = path.expanduser().resolve(strict=True)
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise BenchmarkError(f"{name} is not an executable regular file: {resolved}")
    return resolved


def main(argv: list[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    event_log: EventLog | None = None
    try:
        minimum_ns = round(arguments.min_sample_ms * 1_000_000)
        target_ns = round(arguments.target_sample_ms * 1_000_000)
        if minimum_ns <= 0 or target_ns <= 0:
            raise BenchmarkError("sample durations must round to at least one nanosecond")
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
        if arguments.same_binary_causal:
            if arguments.baseline_route != "per-haystack":
                raise BenchmarkError(
                    "--same-binary-causal cannot be combined with "
                    "--baseline-route=direct-batch"
                )
            if binaries["baseline"] != binaries["candidate"]:
                raise BenchmarkError(
                    "--same-binary-causal requires identical resolved binary paths"
                )
            execution_modes: dict[str, str] | None = dict(
                SAME_BINARY_EXECUTION_MODES
            )
            expected_routes = {
                side: {
                    **DIRECT_BATCH_ROUTE,
                    "timed_mode": SAME_BINARY_TIMED_ROUTE[side],
                }
                for side in ("baseline", "candidate")
            }
        else:
            execution_modes = None
            expected_routes = {
                "baseline": (
                    EXPECTED_ROUTE["baseline"]
                    if arguments.baseline_route == "per-haystack"
                    else DIRECT_BATCH_ROUTE
                ),
                "candidate": EXPECTED_ROUTE["candidate"],
            }
        cells = [
            (scenario, batch, byte_size)
            for scenario in arguments.scenarios
            for batch in arguments.batches
            for byte_size in arguments.bytes
        ]
        if len(set(cells)) != len(cells):
            raise BenchmarkError("duplicate benchmark cells are not allowed")
        metadata = metadata_event(
            binaries=binaries,
            scenarios=arguments.scenarios,
            batches=arguments.batches,
            byte_sizes=arguments.bytes,
            pairs=arguments.pairs,
            warmup_pairs=arguments.warmup_pairs,
            minimum_ns=minimum_ns,
            target_ns=target_ns,
            expected_routes=expected_routes,
            execution_modes=execution_modes,
        )
        if arguments.resume:
            events, log_identity = read_event_log(arguments.output)
            metadata_compatibility = validate_resume_metadata(
                events[0], expected_metadata=metadata
            )
            progress = validate_resume_events(
                events,
                expected_metadata=metadata,
                cells=cells,
                pairs=arguments.pairs,
                warmup_pairs=arguments.warmup_pairs,
                minimum_ns=minimum_ns,
                target_ns=target_ns,
                expected_routes=expected_routes,
            )
            if progress.phase == "complete":
                if progress.aggregate is None:
                    raise AssertionError("complete resume state has no aggregate")
                print(
                    json.dumps(progress.aggregate, sort_keys=True, separators=(",", ":"))
                )
                return 0
            print(
                "resuming authenticated append-only log: "
                f"metadata={metadata_compatibility} "
                f"completed_cells={len(progress.summaries)} "
                f"cell={progress.cell_index} phase={progress.phase} "
                f"completed_pairs={len(progress.measured)} "
                f"partial_sides={sorted(progress.partial_results)!r}",
                file=sys.stderr,
                flush=True,
            )
            event_log = EventLog(arguments.output, append_identity=log_identity)
        else:
            event_log = EventLog(arguments.output)
            event_log.write(metadata)
            progress = ResumeProgress([], 0, "calibration", iterations=1)

        summaries = list(progress.summaries)
        for cell_index in range(progress.cell_index, len(cells)):
            scenario, batch, byte_size = cells[cell_index]
            if cell_index == progress.cell_index:
                phase = progress.phase
                iterations = progress.iterations
                calibration_ordinal = progress.calibration_ordinal
                warmup_completed = progress.warmup_pairs_completed
                measured = list(progress.measured)
                partial_results = dict(progress.partial_results)
            else:
                phase = "calibration"
                iterations = 1
                calibration_ordinal = 0
                warmup_completed = 0
                measured = []
                partial_results = {}

            if phase == "calibration":
                if iterations is None:
                    raise AssertionError("calibration resume state has no iterations")
                print(
                    f"calibrating {scenario} batch={batch} bytes={byte_size} "
                    f"from ordinal={calibration_ordinal}",
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
                    expected_routes=expected_routes,
                    execution_modes=execution_modes,
                    start_iterations=iterations,
                    start_ordinal=calibration_ordinal,
                    start_partial_results=partial_results or None,
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
                warmup_completed = 0
                measured = []
                partial_results = {}
            elif phase == "record-calibrated":
                if iterations is None:
                    raise AssertionError("calibrated resume state has no iterations")
                event_log.write(
                    {
                        "type": "calibrated",
                        "scenario": scenario,
                        "batch": batch,
                        "bytes_per_haystack": byte_size,
                        "iterations": iterations,
                    }
                )
                warmup_completed = 0
                measured = []
                partial_results = {}
            elif phase not in ("warmup", "measure", "summary"):
                raise AssertionError(f"unexpected cell resume phase {phase!r}")

            if iterations is None:
                raise AssertionError("post-calibration resume state has no iterations")
            for warmup in range(warmup_completed, arguments.warmup_pairs):
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
                    expected_routes=expected_routes,
                    execution_modes=execution_modes,
                    existing_results=(
                        partial_results if warmup == warmup_completed else None
                    ),
                )
                partial_results = {}
            for pair in range(len(measured), arguments.pairs):
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
                            expected_routes=expected_routes,
                            execution_modes=execution_modes,
                            existing_results=partial_results or None,
                        ),
                    )
                )
                partial_results = {}
            summary = paired_summary(scenario, batch, byte_size, measured)
            summaries.append(summary)
            event_log.write(summary)
            print(
                f"finished {scenario} batch={batch} bytes={byte_size}: "
                f"{summary['paired_geomean_speedup']:.4f}x",
                file=sys.stderr,
                flush=True,
            )
        aggregate = aggregate_summary(summaries, arguments.pairs)
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
