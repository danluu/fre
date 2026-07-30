#!/usr/bin/env python3
"""Deterministic, dispatch-only controller for the steady-state gate."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import pathlib
import subprocess
import sys
import time
from typing import Any


SCHEDULE_SCHEMA = "fre.steady-state-generalization.schedule.v1"
RUN_SCHEMA = "fre.steady-state-generalization.run.v1"
RESULT_SCHEMA = "fre.steady-state-generalization.result.v1"
COMPLETION_SCHEMA = "fre.steady-state-generalization.completion.v1"
MAX_WORKERS = 96
DEFAULT_SEED = 0xA6D4_19C8_735B_E20F
MASK64 = (1 << 64) - 1


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_path(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: pathlib.Path, value: Any) -> str:
    encoded = canonical_json(value)
    path.write_bytes(encoded)
    return sha256_bytes(encoded)


class SplitMix64:
    """Small version-independent PRNG used only to freeze the schedule."""

    def __init__(self, seed: int) -> None:
        self.state = seed & MASK64

    def next(self) -> int:
        self.state = (self.state + 0x9E37_79B9_7F4A_7C15) & MASK64
        value = self.state
        value = ((value ^ (value >> 30)) * 0xBF58_476D_1CE4_E5B9) & MASK64
        value = ((value ^ (value >> 27)) * 0x94D0_49BB_1331_11EB) & MASK64
        return (value ^ (value >> 31)) & MASK64

    def shuffle(self, values: list[Any]) -> None:
        for index in range(len(values) - 1, 0, -1):
            selected = self.next() % (index + 1)
            values[index], values[selected] = values[selected], values[index]


def point_key(point: dict[str, Any]) -> tuple[str, int, str, str]:
    return (
        str(point["case"]),
        int(point["size"]),
        str(point["density"]),
        str(point["operation"]),
    )


def validate_catalog(catalog: Any) -> dict[str, Any]:
    if not isinstance(catalog, dict):
        raise ValueError("catalog must be a JSON object")
    for field in ("schema", "plan_id", "plan_checksum", "generator_id"):
        if not isinstance(catalog.get(field), str) or not catalog[field]:
            raise ValueError(f"catalog has invalid {field}")
    cases = catalog.get("cases")
    sizes = catalog.get("sizes")
    densities = catalog.get("densities")
    operations = catalog.get("operations")
    points = catalog.get("points")
    cold_coordinate = catalog.get("cold_session_coordinate")
    if not all(isinstance(value, list) and value for value in (
        cases,
        sizes,
        densities,
        operations,
        points,
    )):
        raise ValueError("catalog matrix dimensions must be nonempty arrays")

    case_ids = []
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("id"), str):
            raise ValueError("catalog case is malformed")
        case_ids.append(case["id"])
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("catalog case IDs are not unique")
    if not isinstance(cold_coordinate, dict):
        raise ValueError("catalog cold_session_coordinate is malformed")
    cold_size = cold_coordinate.get("size")
    cold_density = cold_coordinate.get("density")
    if cold_size not in sizes or cold_density not in densities:
        raise ValueError("catalog cold_session_coordinate is outside the matrix")
    expected = {
        (case_id, int(size), str(density), str(operation))
        for case_id in case_ids
        for size in sizes
        for density in densities
        for operation in operations
        if operation != "session_setup"
        or (size == cold_size and density == cold_density)
    }
    actual: set[tuple[str, int, str, str]] = set()
    for point in points:
        if not isinstance(point, dict):
            raise ValueError("catalog point is malformed")
        key = point_key(point)
        if key in actual:
            raise ValueError(f"duplicate catalog point {key!r}")
        actual.add(key)
        if not isinstance(point.get("family"), str):
            raise ValueError(f"catalog point {key!r} has no family")
        if not isinstance(point.get("pattern"), str):
            raise ValueError(f"catalog point {key!r} has no pattern")
        if point.get("lane") not in {"steady", "cold-session"}:
            raise ValueError(f"catalog point {key!r} has invalid lane")
        if not isinstance(point.get("default_iterations"), int) or point[
            "default_iterations"
        ] <= 0:
            raise ValueError(f"catalog point {key!r} has invalid iterations")
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ValueError(f"catalog is not a full cross product: missing={missing}, extra={extra}")
    return catalog


def build_schedule(
    catalog: dict[str, Any],
    repetitions: int,
    seed: int,
    catalog_sha256: str,
) -> dict[str, Any]:
    if repetitions <= 0:
        raise ValueError("repetitions must be positive")
    rng = SplitMix64(seed)
    blocks: list[dict[str, Any]] = []
    for point_index, point in enumerate(catalog["points"]):
        first_is_fre = (rng.next() & 1) == 0
        for repetition in range(repetitions):
            orientation_is_fre = first_is_fre ^ bool(repetition & 1)
            engines = ("fre", "rust") if orientation_is_fre else ("rust", "fre")
            pair_id = f"p{point_index:04d}-r{repetition:03d}"
            tasks = []
            for engine in engines:
                tasks.append(
                    {
                        "task_id": f"{pair_id}-{engine}",
                        "pair_id": pair_id,
                        "point_index": point_index,
                        "repetition": repetition,
                        "engine": engine,
                        "case": point["case"],
                        "family": point["family"],
                        "pattern": point["pattern"],
                        "size": point["size"],
                        "density": point["density"],
                        "operation": point["operation"],
                        "lane": point["lane"],
                        "iterations": point["default_iterations"],
                    }
                )
            blocks.append(
                {
                    "pair_id": pair_id,
                    "orientation": "AB" if engines[0] == "fre" else "BA",
                    "tasks": tasks,
                }
            )
    rng.shuffle(blocks)
    tasks = []
    for block_index, block in enumerate(blocks):
        for within_pair, task in enumerate(block["tasks"]):
            task["block_index"] = block_index
            task["within_pair"] = within_pair
            task["schedule_index"] = len(tasks)
            tasks.append(task)
    return {
        "schema": SCHEDULE_SCHEMA,
        "catalog_schema": catalog["schema"],
        "plan_id": catalog["plan_id"],
        "plan_checksum": catalog["plan_checksum"],
        "generator_id": catalog["generator_id"],
        "catalog_sha256": catalog_sha256,
        "seed": seed & MASK64,
        "repetitions": repetitions,
        "point_count": len(catalog["points"]),
        "pair_count": len(blocks),
        "task_count": len(tasks),
        "pair_protocol": (
            "point/repetition blocks are deterministically shuffled; each block is "
            "adjacent AB or BA, and each point alternates orientation by repetition"
        ),
        "no_affinity": True,
        "no_cgroups": True,
        "no_retries": True,
        "hard_worker_cap": MAX_WORKERS,
        "tasks": tasks,
    }


def point_command(binary: pathlib.Path, task: dict[str, Any]) -> list[str]:
    return [
        str(binary),
        "point",
        "--case",
        str(task["case"]),
        "--size",
        str(task["size"]),
        "--density",
        str(task["density"]),
        "--operation",
        str(task["operation"]),
        "--engine",
        str(task["engine"]),
        "--iterations",
        str(task["iterations"]),
    ]


def validate_point(point: Any, task: dict[str, Any], schedule: dict[str, Any]) -> None:
    if not isinstance(point, dict):
        raise ValueError("point output is not a JSON object")
    expected = {
        "schema": schedule["catalog_schema"],
        "plan_id": schedule["plan_id"],
        "plan_checksum": schedule["plan_checksum"],
        "generator_id": schedule["generator_id"],
        "case": task["case"],
        "family": task["family"],
        "pattern": task["pattern"],
        "size": task["size"],
        "density": task["density"],
        "operation": task["operation"],
        "lane": task["lane"],
        "engine": task["engine"],
        "iterations": task["iterations"],
    }
    for field, value in expected.items():
        if point.get(field) != value:
            raise ValueError(
                f"point field {field} is {point.get(field)!r}, expected {value!r}"
            )
    if not isinstance(point.get("elapsed_ns"), int) or point["elapsed_ns"] <= 0:
        raise ValueError("point elapsed_ns must be a positive integer")
    checksum = point.get("timed_checksum")
    if not isinstance(checksum, str) or len(checksum) != 16:
        raise ValueError("point timed_checksum must be a 16-digit string")


def text_from_timeout(value: str | bytes | None) -> str:
    if value is None:
        return ""
    return value.decode(errors="replace") if isinstance(value, bytes) else value


def execute_task(
    binary: pathlib.Path,
    task: dict[str, Any],
    schedule: dict[str, Any],
    timeout_seconds: float,
) -> dict[str, Any]:
    command = point_command(binary, task)
    started_ns = time.time_ns()
    try:
        completed = subprocess.run(
            command,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
        )
        status = "ok"
        error = None
        point = None
        if completed.returncode != 0:
            status = "error"
            error = f"point exited with {completed.returncode}"
        else:
            try:
                point = json.loads(completed.stdout)
                validate_point(point, task, schedule)
            except (json.JSONDecodeError, ValueError) as exception:
                status = "error"
                error = f"invalid point output: {exception}"
        return {
            "schema": RESULT_SCHEMA,
            "task_id": task["task_id"],
            "pair_id": task["pair_id"],
            "schedule_index": task["schedule_index"],
            "status": status,
            "returncode": completed.returncode,
            "error": error,
            "point": point,
            "stdout_sha256": sha256_bytes(completed.stdout.encode()),
            "stderr": completed.stderr,
            "controller_wall_ns": time.time_ns() - started_ns,
        }
    except subprocess.TimeoutExpired as exception:
        return {
            "schema": RESULT_SCHEMA,
            "task_id": task["task_id"],
            "pair_id": task["pair_id"],
            "schedule_index": task["schedule_index"],
            "status": "timeout",
            "returncode": None,
            "error": f"point exceeded {timeout_seconds} seconds",
            "point": None,
            "stdout_sha256": sha256_bytes(text_from_timeout(exception.stdout).encode()),
            "stderr": text_from_timeout(exception.stderr),
            "controller_wall_ns": time.time_ns() - started_ns,
        }
    except OSError as exception:
        return {
            "schema": RESULT_SCHEMA,
            "task_id": task["task_id"],
            "pair_id": task["pair_id"],
            "schedule_index": task["schedule_index"],
            "status": "error",
            "returncode": None,
            "error": f"could not execute point: {exception}",
            "point": None,
            "stdout_sha256": sha256_bytes(b""),
            "stderr": "",
            "controller_wall_ns": time.time_ns() - started_ns,
        }


def execute_pair(
    binary: pathlib.Path,
    tasks: list[dict[str, Any]],
    schedule: dict[str, Any],
    timeout_seconds: float,
) -> list[dict[str, Any]]:
    if len(tasks) != 2 or {task["engine"] for task in tasks} != {"fre", "rust"}:
        raise ValueError("scheduled dispatch unit is not one AB/BA pair")
    return [
        execute_task(binary, task, schedule, timeout_seconds)
        for task in tasks
    ]


def validate_workers(workers: int) -> int:
    if workers < 1 or workers > MAX_WORKERS:
        raise ValueError(f"--workers must be between 1 and {MAX_WORKERS}")
    return workers


def obtain_catalog(binary: pathlib.Path, timeout_seconds: float) -> dict[str, Any]:
    completed = subprocess.run(
        [str(binary), "catalog"],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout_seconds,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"catalog failed ({completed.returncode}): {completed.stderr}"
        )
    try:
        return validate_catalog(json.loads(completed.stdout))
    except json.JSONDecodeError as exception:
        raise RuntimeError(f"catalog emitted invalid JSON: {exception}") from exception


def run_campaign(args: argparse.Namespace) -> dict[str, Any]:
    workers = validate_workers(args.workers)
    if args.repetitions <= 0:
        raise ValueError("--repetitions must be positive")
    if args.timeout <= 0:
        raise ValueError("--timeout must be positive")
    binary = pathlib.Path(args.binary).expanduser().resolve()
    if not binary.is_file():
        raise ValueError(f"binary does not exist: {binary}")
    output = pathlib.Path(args.out).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=False)

    catalog = obtain_catalog(binary, args.timeout)
    catalog_sha256 = write_json(output / "catalog.json", catalog)
    schedule = build_schedule(
        catalog, args.repetitions, args.seed, catalog_sha256
    )
    schedule_sha256 = write_json(output / "schedule.json", schedule)
    (output / "schedule.sha256").write_text(
        f"{schedule_sha256}  schedule.json\n", encoding="utf-8"
    )
    run_record = {
        "schema": RUN_SCHEMA,
        "binary": str(binary),
        "binary_sha256": sha256_path(binary),
        "catalog_sha256": catalog_sha256,
        "schedule_sha256": schedule_sha256,
        "plan_id": catalog["plan_id"],
        "plan_checksum": catalog["plan_checksum"],
        "generator_id": catalog["generator_id"],
        "workers": workers,
        "repetitions": args.repetitions,
        "timeout_seconds": args.timeout,
        "seed": args.seed & MASK64,
        "no_affinity": True,
        "no_cgroups": True,
        "dispatch_only_limit": True,
        "dispatch_unit": "one sequential AB/BA pair per worker",
        "no_retries": True,
        "started_unix_ns": time.time_ns(),
    }
    write_json(output / "run.json", run_record)

    results_path = output / "results.jsonl"
    ok = 0
    failures = 0
    with results_path.open("x", encoding="utf-8") as results:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            pairs = [
                schedule["tasks"][index : index + 2]
                for index in range(0, schedule["task_count"], 2)
            ]
            futures = {
                executor.submit(
                    execute_pair, binary, pair, schedule, args.timeout
                ): pair
                for pair in pairs
            }
            for future in concurrent.futures.as_completed(futures):
                for record in future.result():
                    results.write(canonical_json(record).decode())
                    results.flush()
                    if record["status"] == "ok":
                        ok += 1
                    else:
                        failures += 1
                completed = ok + failures
                if completed % 100 == 0 or completed == schedule["task_count"]:
                    print(
                        f"completed {completed}/{schedule['task_count']} "
                        f"(failures={failures})",
                        file=sys.stderr,
                        flush=True,
                    )

    complete = ok + failures == schedule["task_count"] and failures == 0
    completion = {
        "schema": COMPLETION_SCHEMA,
        "schedule_sha256": schedule_sha256,
        "expected_tasks": schedule["task_count"],
        "recorded_tasks": ok + failures,
        "ok_tasks": ok,
        "failed_tasks": failures,
        "complete": complete,
        "finished_unix_ns": time.time_ns(),
        "results_sha256": sha256_path(results_path),
    }
    write_json(output / "completion.json", completion)
    print(canonical_json(completion).decode(), end="")
    if not complete:
        raise RuntimeError(
            f"campaign failed closed: {failures} failed and "
            f"{schedule['task_count'] - ok - failures} missing tasks"
        )
    return completion


def parse_seed(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as exception:
        raise argparse.ArgumentTypeError(f"invalid integer seed {value!r}") from exception


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    run = subparsers.add_parser("run", help="freeze and execute one complete campaign")
    run.add_argument("--binary", required=True)
    run.add_argument("--out", required=True)
    run.add_argument("--workers", required=True, type=int)
    run.add_argument("--repetitions", type=int, default=4)
    run.add_argument("--seed", type=parse_seed, default=DEFAULT_SEED)
    run.add_argument("--timeout", type=float, default=600.0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "run":
            run_campaign(args)
        else:
            raise AssertionError(f"unhandled command {args.command}")
    except (OSError, RuntimeError, ValueError) as exception:
        print(f"controller: {exception}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
