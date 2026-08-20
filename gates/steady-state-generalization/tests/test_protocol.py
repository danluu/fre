from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock


GATE = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GATE))

import analyze  # noqa: E402
import controller  # noqa: E402


def fake_catalog() -> dict:
    return {
        "schema": "fre.steady-state-generalization.v2",
        "plan_id": "test-plan",
        "plan_checksum": "0123456789abcdef",
        "generator_id": "test-generator",
        "cases": [{"id": "case", "family": "family", "pattern": "x"}],
        "sizes": [31],
        "densities": ["absent"],
        "operations": ["find", "session_setup"],
        "cold_session_coordinate": {"size": 31, "density": "absent"},
        "points": [
            {
                "case": "case",
                "family": "family",
                "pattern": "x",
                "size": 31,
                "density": "absent",
                "operation": "find",
                "lane": "steady",
                "default_iterations": 10,
            },
            {
                "case": "case",
                "family": "family",
                "pattern": "x",
                "size": 31,
                "density": "absent",
                "operation": "session_setup",
                "lane": "cold-session",
                "default_iterations": 10,
            },
        ],
    }


def write_fake_run(directory: pathlib.Path) -> None:
    catalog = controller.validate_catalog(fake_catalog())
    catalog_sha256 = controller.write_json(directory / "catalog.json", catalog)
    schedule = controller.build_schedule(catalog, 2, 17, catalog_sha256)
    schedule_sha256 = controller.write_json(directory / "schedule.json", schedule)
    (directory / "schedule.sha256").write_text(
        f"{schedule_sha256}  schedule.json\n", encoding="utf-8"
    )
    controller.write_json(
        directory / "run.json",
        {
            "schema": controller.RUN_SCHEMA,
            "binary": "/fixture/binary",
            "binary_sha256": "f" * 64,
            "catalog_sha256": catalog_sha256,
            "schedule_sha256": schedule_sha256,
            "plan_id": catalog["plan_id"],
            "plan_checksum": catalog["plan_checksum"],
            "generator_id": catalog["generator_id"],
            "workers": 2,
            "repetitions": 2,
            "seed": 17,
            "no_affinity": True,
            "no_cgroups": True,
            "dispatch_only_limit": True,
            "dispatch_unit": "one sequential AB/BA pair per worker",
            "no_retries": True,
        },
    )
    records = []
    for task in schedule["tasks"]:
        per_iteration = 100 + task["repetition"]
        if task["engine"] == "rust":
            per_iteration *= 2
        point = {
            "schema": catalog["schema"],
            "plan_id": catalog["plan_id"],
            "plan_checksum": catalog["plan_checksum"],
            "generator_id": catalog["generator_id"],
            "case": task["case"],
            "family": task["family"],
            "pattern": task["pattern"],
            "size": task["size"],
            "density": task["density"],
            "operation": task["operation"],
            "lane": task["lane"],
            "engine": task["engine"],
            "iterations": task["iterations"],
            "elapsed_ns": per_iteration * task["iterations"],
            "timed_checksum": (
                "0123456789abcdef"
                if task["lane"] == "steady"
                else ("a" if task["engine"] == "fre" else "b") * 16
            ),
            "semantic": (
                {"count": 1, "span_sum": 1, "hash": 1}
                if task["lane"] == "steady"
                else None
            ),
            "runtime_plan": "fixture-plan",
        }
        records.append(
            {
                "schema": controller.RESULT_SCHEMA,
                "task_id": task["task_id"],
                "pair_id": task["pair_id"],
                "schedule_index": task["schedule_index"],
                "status": "ok",
                "returncode": 0,
                "error": None,
                "point": point,
                "stdout_sha256": "e" * 64,
                "stderr": "",
                "controller_wall_ns": 1,
            }
        )
    results = directory / "results.jsonl"
    results.write_bytes(b"".join(controller.canonical_json(record) for record in records))
    controller.write_json(
        directory / "completion.json",
        {
            "schema": controller.COMPLETION_SCHEMA,
            "schedule_sha256": schedule_sha256,
            "expected_tasks": len(records),
            "recorded_tasks": len(records),
            "ok_tasks": len(records),
            "failed_tasks": 0,
            "complete": True,
            "results_sha256": controller.sha256_path(results),
        },
    )


class ControllerTests(unittest.TestCase):
    def test_schedule_is_deterministic_paired_and_alternating(self) -> None:
        catalog = controller.validate_catalog(fake_catalog())
        first = controller.build_schedule(catalog, 4, 1234, "a" * 64)
        second = controller.build_schedule(catalog, 4, 1234, "a" * 64)
        self.assertEqual(first, second)
        self.assertEqual(first["task_count"], len(catalog["points"]) * 4 * 2)
        orientations: dict[int, dict[int, str]] = {}
        for index in range(0, len(first["tasks"]), 2):
            pair = first["tasks"][index : index + 2]
            self.assertEqual(pair[0]["pair_id"], pair[1]["pair_id"])
            self.assertEqual({pair[0]["engine"], pair[1]["engine"]}, {"fre", "rust"})
            point = pair[0]["point_index"]
            repetition = pair[0]["repetition"]
            orientations.setdefault(point, {})[repetition] = pair[0]["engine"]
        for by_repetition in orientations.values():
            for repetition in range(1, 4):
                self.assertNotEqual(
                    by_repetition[repetition - 1], by_repetition[repetition]
                )

    def test_worker_cap_and_command_are_dispatch_only(self) -> None:
        self.assertEqual(controller.validate_workers(96), 96)
        for invalid in (0, 97):
            with self.assertRaises(ValueError):
                controller.validate_workers(invalid)
        schedule = controller.build_schedule(
            controller.validate_catalog(fake_catalog()), 1, 1, "a" * 64
        )
        command = controller.point_command(pathlib.Path("/bin/gate"), schedule["tasks"][0])
        joined = " ".join(command)
        self.assertNotIn("taskset", joined)
        self.assertNotIn("cgroup", joined)
        self.assertNotIn("numactl", joined)

    def test_pair_dispatch_is_sequential_in_frozen_order(self) -> None:
        schedule = controller.build_schedule(
            controller.validate_catalog(fake_catalog()), 1, 1, "a" * 64
        )
        pair = schedule["tasks"][:2]
        observed = []

        def fake_execute(binary, task, frozen, timeout):
            del binary, frozen, timeout
            observed.append(task["engine"])
            return {"status": "ok"}

        with mock.patch.object(controller, "execute_task", side_effect=fake_execute):
            records = controller.execute_pair(
                pathlib.Path("/bin/gate"), pair, schedule, 1.0
            )
        self.assertEqual(observed, [task["engine"] for task in pair])
        self.assertEqual(len(records), 2)


class AnalyzerTests(unittest.TestCase):
    def test_complete_authenticated_run_reports_expected_ratio(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            write_fake_run(directory)
            report = analyze.analyze_run(directory)
            self.assertEqual(report["verdict"], "PASS")
            self.assertEqual(report["authentication"]["task_count"], 8)
            self.assertAlmostEqual(
                report["geomeans"]["overall_steady"][
                    "rust_time_over_fre_time_geomean"
                ],
                2.0,
            )
            self.assertAlmostEqual(
                report["geomeans"]["session_setup"][
                    "rust_time_over_fre_time_geomean"
                ],
                2.0,
            )

    def test_missing_result_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            write_fake_run(directory)
            results = directory / "results.jsonl"
            lines = results.read_text(encoding="utf-8").splitlines()
            results.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
            completion = json.loads(
                (directory / "completion.json").read_text(encoding="utf-8")
            )
            completion["results_sha256"] = controller.sha256_path(results)
            controller.write_json(directory / "completion.json", completion)
            with self.assertRaises(ValueError):
                analyze.analyze_run(directory)


if __name__ == "__main__":
    unittest.main()
