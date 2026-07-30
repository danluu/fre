#!/usr/bin/env python3
"""Authenticate and summarize a steady-state generalization campaign."""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
import pathlib
import statistics
import sys
from typing import Any, Iterable


SCHEDULE_SCHEMA = "fre.steady-state-generalization.schedule.v1"
RUN_SCHEMA = "fre.steady-state-generalization.run.v1"
RESULT_SCHEMA = "fre.steady-state-generalization.result.v1"
COMPLETION_SCHEMA = "fre.steady-state-generalization.completion.v1"
ANALYSIS_SCHEMA = "fre.steady-state-generalization.analysis.v1"


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode()


def sha256_path(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_json(path: pathlib.Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exception:
        raise ValueError(f"cannot read valid JSON from {path}: {exception}") from exception


def load_jsonl(path: pathlib.Path) -> list[Any]:
    records = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exception:
        raise ValueError(f"cannot read {path}: {exception}") from exception
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as exception:
            raise ValueError(
                f"{path}:{line_number} is invalid JSON: {exception}"
            ) from exception
    return records


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def geomean(values: Iterable[float]) -> float:
    materialized = list(values)
    require(bool(materialized), "geomean requires at least one value")
    require(
        all(math.isfinite(value) and value > 0 for value in materialized),
        "geomean requires positive finite values",
    )
    return math.exp(
        math.fsum(math.log(value) for value in materialized) / len(materialized)
    )


def summary(values: Iterable[float]) -> dict[str, Any]:
    materialized = list(values)
    return {
        "points": len(materialized),
        "rust_time_over_fre_time_geomean": geomean(materialized),
        "rust_time_over_fre_time_min": min(materialized),
        "rust_time_over_fre_time_max": max(materialized),
    }


def grouped_summary(
    rows: Iterable[dict[str, Any]], field: str
) -> dict[str, dict[str, Any]]:
    groups: dict[str, list[float]] = collections.defaultdict(list)
    for row in rows:
        groups[str(row[field])].append(row["rust_time_over_fre_time"])
    return {
        group: summary(values)
        for group, values in sorted(groups.items(), key=lambda item: item[0])
    }


def verify_schedule_shape(schedule: dict[str, Any]) -> None:
    tasks = schedule.get("tasks")
    require(isinstance(tasks, list), "schedule tasks must be an array")
    require(schedule.get("task_count") == len(tasks), "schedule task_count differs")
    require(len(tasks) % 2 == 0, "schedule task count is not paired")
    task_ids: set[str] = set()
    for schedule_index, task in enumerate(tasks):
        require(isinstance(task, dict), "schedule task is malformed")
        require(
            task.get("schedule_index") == schedule_index,
            f"schedule index {schedule_index} is not canonical",
        )
        task_id = task.get("task_id")
        require(isinstance(task_id, str), "schedule task ID is malformed")
        require(task_id not in task_ids, f"duplicate schedule task {task_id!r}")
        task_ids.add(task_id)
    for index in range(0, len(tasks), 2):
        first, second = tasks[index : index + 2]
        require(
            first.get("pair_id") == second.get("pair_id"),
            f"schedule pair at {index} is not adjacent",
        )
        require(
            {first.get("engine"), second.get("engine")} == {"fre", "rust"},
            f"schedule pair {first.get('pair_id')} lacks both engines",
        )
        require(
            first.get("within_pair") == 0 and second.get("within_pair") == 1,
            f"schedule pair {first.get('pair_id')} has invalid order markers",
        )


def expected_point_fields(
    task: dict[str, Any], schedule: dict[str, Any]
) -> dict[str, Any]:
    return {
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


def authenticate_result(
    record: dict[str, Any], task: dict[str, Any], schedule: dict[str, Any]
) -> dict[str, Any]:
    require(record.get("schema") == RESULT_SCHEMA, "result schema differs")
    require(record.get("task_id") == task["task_id"], "result task ID differs")
    require(record.get("pair_id") == task["pair_id"], "result pair ID differs")
    require(
        record.get("schedule_index") == task["schedule_index"],
        "result schedule index differs",
    )
    require(record.get("status") == "ok", f"task {task['task_id']} is not successful")
    require(record.get("returncode") == 0, f"task {task['task_id']} returned nonzero")
    require(record.get("error") is None, f"task {task['task_id']} reports an error")
    require(isinstance(record.get("stderr"), str), "result stderr was not captured")
    point = record.get("point")
    require(isinstance(point, dict), f"task {task['task_id']} has no point JSON")
    for field, expected in expected_point_fields(task, schedule).items():
        require(
            point.get(field) == expected,
            f"task {task['task_id']} point {field} differs",
        )
    require(
        isinstance(point.get("elapsed_ns"), int) and point["elapsed_ns"] > 0,
        f"task {task['task_id']} has invalid elapsed_ns",
    )
    checksum = point.get("timed_checksum")
    require(
        isinstance(checksum, str) and len(checksum) == 16,
        f"task {task['task_id']} has invalid timed checksum",
    )
    require(
        isinstance(point.get("runtime_plan"), str) and point["runtime_plan"],
        f"task {task['task_id']} has no runtime plan identity",
    )
    return point


def analyze_run(run_directory: pathlib.Path) -> dict[str, Any]:
    run_directory = run_directory.resolve()
    paths = {
        name: run_directory / name
        for name in (
            "catalog.json",
            "schedule.json",
            "schedule.sha256",
            "run.json",
            "results.jsonl",
            "completion.json",
        )
    }
    for name, path in paths.items():
        require(path.is_file(), f"missing {name}")

    catalog = load_json(paths["catalog.json"])
    schedule = load_json(paths["schedule.json"])
    run = load_json(paths["run.json"])
    completion = load_json(paths["completion.json"])
    require(isinstance(catalog, dict), "catalog is not an object")
    require(isinstance(schedule, dict), "schedule is not an object")
    require(isinstance(run, dict), "run is not an object")
    require(isinstance(completion, dict), "completion is not an object")
    require(schedule.get("schema") == SCHEDULE_SCHEMA, "schedule schema differs")
    require(run.get("schema") == RUN_SCHEMA, "run schema differs")
    require(completion.get("schema") == COMPLETION_SCHEMA, "completion schema differs")

    catalog_sha256 = sha256_path(paths["catalog.json"])
    schedule_sha256 = sha256_path(paths["schedule.json"])
    results_sha256 = sha256_path(paths["results.jsonl"])
    checksum_line = paths["schedule.sha256"].read_text(encoding="utf-8")
    require(
        checksum_line == f"{schedule_sha256}  schedule.json\n",
        "schedule.sha256 does not authenticate schedule.json",
    )
    require(
        run.get("catalog_sha256") == catalog_sha256
        and schedule.get("catalog_sha256") == catalog_sha256,
        "catalog checksum identity differs",
    )
    require(
        run.get("schedule_sha256") == schedule_sha256
        and completion.get("schedule_sha256") == schedule_sha256,
        "schedule checksum identity differs",
    )
    require(
        completion.get("results_sha256") == results_sha256,
        "results checksum identity differs",
    )
    for field in ("plan_id", "plan_checksum", "generator_id"):
        identity = catalog.get(field)
        require(identity == schedule.get(field), f"schedule {field} differs")
        require(identity == run.get(field), f"run {field} differs")
    require(
        catalog.get("schema") == schedule.get("catalog_schema"),
        "catalog schema identity differs",
    )
    require(run.get("no_affinity") is True, "run did not record no-affinity")
    require(run.get("no_cgroups") is True, "run did not record no-cgroups")
    require(
        run.get("dispatch_only_limit") is True,
        "run did not record dispatch-only limiting",
    )
    require(
        run.get("dispatch_unit") == "one sequential AB/BA pair per worker",
        "run did not preserve sequential AB/BA dispatch",
    )
    require(run.get("no_retries") is True, "run permits retries")
    require(schedule.get("no_affinity") is True, "schedule permits affinity")
    require(schedule.get("no_cgroups") is True, "schedule permits cgroups")
    require(schedule.get("no_retries") is True, "schedule permits retries")
    require(schedule.get("hard_worker_cap") == 96, "schedule worker cap differs")
    require(
        isinstance(run.get("workers"), int) and 1 <= run["workers"] <= 96,
        "worker count violates hard cap",
    )
    verify_schedule_shape(schedule)

    tasks = schedule["tasks"]
    catalog_points = catalog.get("points")
    require(isinstance(catalog_points, list), "catalog points are malformed")
    require(
        schedule.get("point_count") == len(catalog_points),
        "schedule point count differs from catalog",
    )
    require(
        schedule.get("repetitions") == run.get("repetitions"),
        "run repetition count differs from schedule",
    )
    require(
        len(tasks)
        == len(catalog_points) * int(schedule["repetitions"]) * 2,
        "schedule is not the full point/engine/repetition cross product",
    )
    orientations: dict[int, dict[int, str]] = collections.defaultdict(dict)
    for task in tasks:
        point_index = task.get("point_index")
        repetition = task.get("repetition")
        require(
            isinstance(point_index, int) and 0 <= point_index < len(catalog_points),
            "schedule point index is out of range",
        )
        require(
            isinstance(repetition, int)
            and 0 <= repetition < int(schedule["repetitions"]),
            "schedule repetition is out of range",
        )
        point = catalog_points[point_index]
        for field in (
            "case",
            "family",
            "pattern",
            "size",
            "density",
            "operation",
            "lane",
        ):
            require(
                task.get(field) == point.get(field),
                f"schedule task {task.get('task_id')} {field} differs from catalog",
            )
        require(
            task.get("iterations") == point.get("default_iterations"),
            f"schedule task {task.get('task_id')} iterations differ from catalog",
        )
        if task.get("within_pair") == 0:
            orientations[point_index][repetition] = task["engine"]
    require(
        set(orientations) == set(range(len(catalog_points))),
        "schedule does not cover every catalog point",
    )
    for point_index, by_repetition in orientations.items():
        require(
            len(by_repetition) == int(schedule["repetitions"]),
            f"point {point_index} lacks an orientation for every repetition",
        )
        for repetition in range(1, int(schedule["repetitions"])):
            require(
                by_repetition[repetition] != by_repetition[repetition - 1],
                f"point {point_index} does not alternate AB/BA",
            )

    records = load_jsonl(paths["results.jsonl"])
    require(completion.get("complete") is True, "completion is not successful")
    require(completion.get("failed_tasks") == 0, "completion records failed tasks")
    require(
        completion.get("expected_tasks") == len(tasks)
        and completion.get("recorded_tasks") == len(records)
        and completion.get("ok_tasks") == len(tasks),
        "completion counts differ from schedule/results",
    )
    require(len(records) == len(tasks), "result count differs from schedule")

    by_task: dict[str, dict[str, Any]] = {}
    for record in records:
        require(isinstance(record, dict), "result record is malformed")
        task_id = record.get("task_id")
        require(isinstance(task_id, str), "result task ID is malformed")
        require(task_id not in by_task, f"duplicate result task {task_id!r}")
        by_task[task_id] = record
    expected_ids = {task["task_id"] for task in tasks}
    require(set(by_task) == expected_ids, "results contain missing or extra task IDs")

    point_by_task: dict[str, dict[str, Any]] = {}
    for task in tasks:
        point_by_task[task["task_id"]] = authenticate_result(
            by_task[task["task_id"]], task, schedule
        )

    pairs: dict[tuple[int, int], dict[str, dict[str, Any]]] = (
        collections.defaultdict(dict)
    )
    task_meta: dict[tuple[int, int], dict[str, Any]] = {}
    for task in tasks:
        key = (int(task["point_index"]), int(task["repetition"]))
        pairs[key][task["engine"]] = point_by_task[task["task_id"]]
        task_meta[key] = task
    expected_pairs = int(schedule["point_count"]) * int(schedule["repetitions"])
    require(len(pairs) == expected_pairs, "point/repetition pair count differs")
    for key, engines in pairs.items():
        require(set(engines) == {"fre", "rust"}, f"pair {key} lacks an engine")
        fre = engines["fre"]
        rust = engines["rust"]
        require(fre.get("semantic") == rust.get("semantic"), f"pair {key} semantic differs")
        if task_meta[key]["lane"] == "steady":
            require(
                fre.get("timed_checksum") == rust.get("timed_checksum"),
                f"pair {key} steady checksum differs",
            )

    for point_index in range(len(catalog_points)):
        for engine in ("fre", "rust"):
            repeated = [
                pairs[(point_index, repetition)][engine]
                for repetition in range(int(schedule["repetitions"]))
            ]
            semantics = {
                canonical_json(point.get("semantic")) for point in repeated
            }
            checksums = {point.get("timed_checksum") for point in repeated}
            runtime_plans = {point.get("runtime_plan") for point in repeated}
            require(
                len(semantics) == 1,
                f"point {point_index} {engine} semantic changed across repetitions",
            )
            require(
                len(checksums) == 1,
                f"point {point_index} {engine} checksum changed across repetitions",
            )
            require(
                len(runtime_plans) == 1,
                f"point {point_index} {engine} runtime plan changed",
            )

    samples: dict[tuple[int, str], list[float]] = collections.defaultdict(list)
    for task in tasks:
        point = point_by_task[task["task_id"]]
        ns_per_iteration = point["elapsed_ns"] / point["iterations"]
        require(
            math.isfinite(ns_per_iteration) and ns_per_iteration > 0,
            f"task {task['task_id']} has invalid normalized timing",
        )
        samples[(int(task["point_index"]), task["engine"])].append(ns_per_iteration)

    pointwise = []
    for point_index, catalog_point in enumerate(catalog["points"]):
        fre_samples = samples.get((point_index, "fre"), [])
        rust_samples = samples.get((point_index, "rust"), [])
        repetitions = int(schedule["repetitions"])
        require(
            len(fre_samples) == repetitions and len(rust_samples) == repetitions,
            f"point {point_index} repetition count differs",
        )
        fre_median = statistics.median(fre_samples)
        rust_median = statistics.median(rust_samples)
        ratio = rust_median / fre_median
        paired = []
        for repetition in range(repetitions):
            pair = pairs[(point_index, repetition)]
            paired.append(
                (pair["rust"]["elapsed_ns"] / pair["rust"]["iterations"])
                / (pair["fre"]["elapsed_ns"] / pair["fre"]["iterations"])
            )
        pointwise.append(
            {
                "point_index": point_index,
                "case": catalog_point["case"],
                "family": catalog_point["family"],
                "size": catalog_point["size"],
                "density": catalog_point["density"],
                "operation": catalog_point["operation"],
                "lane": catalog_point["lane"],
                "repetitions": repetitions,
                "fre_median_ns_per_iteration": fre_median,
                "rust_median_ns_per_iteration": rust_median,
                "rust_time_over_fre_time": ratio,
                "paired_ratio_geomean": geomean(paired),
            }
        )

    steady = [row for row in pointwise if row["lane"] == "steady"]
    setup = [row for row in pointwise if row["operation"] == "session_setup"]
    require(steady, "analysis has no steady points")
    require(setup, "analysis has no session_setup points")
    geomeans = {
        "overall_steady": summary(
            row["rust_time_over_fre_time"] for row in steady
        ),
        "session_setup": summary(
            row["rust_time_over_fre_time"] for row in setup
        ),
        "steady_by_family": grouped_summary(steady, "family"),
        "steady_by_size": grouped_summary(steady, "size"),
        "steady_by_density": grouped_summary(steady, "density"),
        "steady_by_operation": grouped_summary(steady, "operation"),
        "session_setup_by_family": grouped_summary(setup, "family"),
        "session_setup_by_size": grouped_summary(setup, "size"),
        "session_setup_by_density": grouped_summary(setup, "density"),
    }
    return {
        "schema": ANALYSIS_SCHEMA,
        "verdict": "PASS",
        "authentication": {
            "plan_id": catalog["plan_id"],
            "plan_checksum": catalog["plan_checksum"],
            "generator_id": catalog["generator_id"],
            "catalog_sha256": catalog_sha256,
            "schedule_sha256": schedule_sha256,
            "results_sha256": results_sha256,
            "binary_sha256": run.get("binary_sha256"),
            "task_count": len(tasks),
            "point_count": len(pointwise),
            "repetitions": schedule["repetitions"],
            "workers": run["workers"],
            "semantic_pairs_equal": True,
            "steady_checksums_equal": True,
            "complete": True,
            "no_affinity": True,
            "no_cgroups": True,
            "dispatch_only_limit": True,
        },
        "ratio_definition": (
            "median Rust ns/iteration divided by median FRE ns/iteration; "
            "values above 1 mean FRE is faster"
        ),
        "geomeans": geomeans,
        "pointwise": pointwise,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True, help="complete controller output directory")
    parser.add_argument("--out", required=True, help="analysis JSON output")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        analysis = analyze_run(pathlib.Path(args.run))
        output = pathlib.Path(args.out).expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(canonical_json(analysis))
        print(
            json.dumps(
                {
                    "verdict": analysis["verdict"],
                    "analysis": str(output),
                    "plan_checksum": analysis["authentication"]["plan_checksum"],
                    "steady_rust_over_fre_geomean": analysis["geomeans"][
                        "overall_steady"
                    ]["rust_time_over_fre_time_geomean"],
                    "session_setup_rust_over_fre_geomean": analysis["geomeans"][
                        "session_setup"
                    ]["rust_time_over_fre_time_geomean"],
                },
                sort_keys=True,
            )
        )
    except (OSError, ValueError) as exception:
        print(f"analyze: {exception}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
