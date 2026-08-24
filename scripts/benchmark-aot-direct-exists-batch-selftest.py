#!/usr/bin/env python3
"""Focused fail-closed resume tests for the direct Exists batch runner."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import pathlib
import runpy
import tempfile
import unittest


RUNNER = runpy.run_path(
    str(pathlib.Path(__file__).with_name("benchmark-aot-direct-exists-batch.py"))
)
BenchmarkError = RUNNER["BenchmarkError"]

EXPECTED_ROUTES = {
    "baseline": {"route": "direct-native", "api": "per-haystack", "bulk": "none"},
    "candidate": RUNNER["EXPECTED_ROUTE"]["candidate"],
}
CAUSAL_ROUTES = {
    side: {
        **RUNNER["DIRECT_BATCH_ROUTE"],
        "timed_mode": RUNNER["SAME_BINARY_TIMED_ROUTE"][side],
    }
    for side in ("baseline", "candidate")
}
CELLS = [("negative", 1, 64)]
PAIRS = 6
WARMUPS = 2
MINIMUM_NS = 80
TARGET_NS = 100


def metadata() -> dict:
    return {
        "type": "metadata",
        "schema": "fre-public-direct-exists-batch-run-v1",
        "baseline_binary": "/tmp/authenticated-baseline",
        "baseline_sha256": "01" * 32,
        "candidate_binary": "/tmp/authenticated-candidate",
        "candidate_sha256": "02" * 32,
        "scenarios": ["negative"],
        "batches": [1],
        "byte_sizes": [64],
        "pairs": PAIRS,
        "warmup_pairs": WARMUPS,
        "minimum_sample_ns": MINIMUM_NS,
        "target_sample_ns": TARGET_NS,
        "bootstrap_repetitions": RUNNER["BOOTSTRAP_REPETITIONS"],
        "sample_policy": "retain-all",
        "process_policy": "fresh-process-per-invocation",
        "order_policy": "alternating-AB-BA",
        "expected_routes": EXPECTED_ROUTES,
        "route_evidence": {
            "description_scope": "linked-artifact-capability-not-dynamic-call-counter",
            "singleton_dispatch": "batch=1-source-audited-scalar-entry",
            "larger_dispatch": "batch=2..64-authenticated-direct-entry",
        },
    }


def result(
    side: str,
    *,
    scenario: str,
    batch: int,
    byte_size: int,
    iterations: int,
    elapsed_ns: int,
) -> dict:
    route = EXPECTED_ROUTES[side]
    description = (
        "mode=optimizing,"
        f"route={route['route']},api={route['api']},bulk={route['bulk']},"
        "engine=ordered-dfa"
    )
    return {
        "schema": RUNNER["SCHEMA"],
        "status": "ok",
        "scenario": scenario,
        "batch": batch,
        "bytes_per_haystack": byte_size,
        "total_bytes": batch * byte_size,
        "iterations": iterations,
        "elapsed_ns": elapsed_ns,
        "matches_per_batch": batch if scenario in ("early", "late") else 0,
        "input_digest": "11" * 8,
        "result_digest": "22" * 8,
        "route": description,
    }


def causal_result(
    side: str,
    *,
    scenario: str = "negative",
    batch: int = 8,
    byte_size: int = 4096,
    iterations: int = 7,
    elapsed_ns: int = 100,
) -> dict:
    value = result(
        side,
        scenario=scenario,
        batch=batch,
        byte_size=byte_size,
        iterations=iterations,
        elapsed_ns=elapsed_ns,
    )
    route = CAUSAL_ROUTES[side]
    value["route"] = (
        "mode=optimizing,"
        f"route={route['route']},api={route['api']},bulk={route['bulk']},"
        f"engine=ordered-dfa,timed_mode={route['timed_mode']}"
    )
    return value


def pair_events(
    *,
    cell_index: int,
    scenario: str,
    phase: str,
    ordinal: int,
    pair: int | None,
    iterations: int,
    elapsed_ns: int,
) -> tuple[list[dict], tuple[str, dict[str, dict]]]:
    order = "AB" if (cell_index + ordinal) % 2 == 0 else "BA"
    events = []
    results = {}
    for offset, letter in enumerate(order):
        side = "baseline" if letter == "A" else "candidate"
        side_result = result(
            side,
            scenario=scenario,
            batch=1,
            byte_size=64,
            iterations=iterations,
            elapsed_ns=elapsed_ns + offset,
        )
        results[side] = side_result
        stderr = ""
        events.append(
            {
                "type": "invocation",
                "phase": phase,
                "ordinal": ordinal,
                "pair": pair,
                "order": order,
                "side": side,
                "scenario": scenario,
                "batch": 1,
                "bytes_per_haystack": 64,
                "iterations": iterations,
                "returncode": 0,
                "wall_ns": elapsed_ns + offset + 10,
                "stdout_sha256": "ab" * 32,
                "stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest(),
                "result": side_result,
                "stderr": stderr,
                "validation": "ok",
            }
        )
    return events, (order, results)


def calibrated_prefix(cell_index: int, scenario: str) -> tuple[list[dict], list[list[dict]]]:
    low, _ = pair_events(
        cell_index=cell_index,
        scenario=scenario,
        phase="calibration",
        ordinal=0,
        pair=None,
        iterations=1,
        elapsed_ns=10,
    )
    high, _ = pair_events(
        cell_index=cell_index,
        scenario=scenario,
        phase="calibration",
        ordinal=1,
        pair=None,
        iterations=10,
        elapsed_ns=100,
    )
    calibrated = {
        "type": "calibrated",
        "scenario": scenario,
        "batch": 1,
        "bytes_per_haystack": 64,
        "iterations": 10,
    }
    return low + high + [calibrated], [low, high, [calibrated]]


def cell_events(cell_index: int, scenario: str) -> tuple[list[dict], dict, list[list[dict]]]:
    events, phases = calibrated_prefix(cell_index, scenario)
    for warmup in range(WARMUPS):
        pair, _ = pair_events(
            cell_index=cell_index,
            scenario=scenario,
            phase="warmup",
            ordinal=warmup,
            pair=None,
            iterations=10,
            elapsed_ns=110 + warmup,
        )
        events.extend(pair)
        phases.append(pair)
    measured = []
    for pair_number in range(PAIRS):
        pair, measurements = pair_events(
            cell_index=cell_index,
            scenario=scenario,
            phase="measure",
            ordinal=pair_number,
            pair=pair_number,
            iterations=10,
            elapsed_ns=120 + pair_number,
        )
        events.extend(pair)
        phases.append(pair)
        measured.append(measurements)
    summary = RUNNER["paired_summary"](scenario, 1, 64, measured)
    return events + [summary], summary, phases + [[summary]]


def validate(events: list[dict], *, cells=CELLS):
    return RUNNER["validate_resume_events"](
        events,
        expected_metadata=metadata(),
        cells=cells,
        pairs=PAIRS,
        warmup_pairs=WARMUPS,
        minimum_ns=MINIMUM_NS,
        target_ns=TARGET_NS,
        expected_routes=EXPECTED_ROUTES,
    )


class DirectExistsBatchResumeTests(unittest.TestCase):
    def test_same_binary_causal_command_metadata_and_routes_are_authenticated(self):
        scalar_command = RUNNER["invocation_command"](
            pathlib.Path("one-binary"), "late", 8, 4096, 7, "scalar-loop-v1"
        )
        direct_command = RUNNER["invocation_command"](
            pathlib.Path("one-binary"),
            "late",
            8,
            4096,
            7,
            "direct-call-v1",
        )
        self.assertEqual(scalar_command[:-1], direct_command[:-1])
        self.assertEqual(len(scalar_command[-1]), len(direct_command[-1]))
        self.assertEqual(scalar_command[-1], "scalar-loop-v1")
        self.assertEqual(direct_command[-1], "direct-call-v1")
        with self.assertRaisesRegex(BenchmarkError, "unsupported benchmark timed mode"):
            RUNNER["invocation_command"](
                pathlib.Path("one-binary"), "late", 8, 4096, 7, "scalar"
            )

        baseline = causal_result("baseline")
        candidate = causal_result("candidate")
        for side, value in (("baseline", baseline), ("candidate", candidate)):
            RUNNER["validate_result"](
                value,
                side=side,
                scenario="negative",
                batch=8,
                byte_size=4096,
                iterations=7,
                expected_routes=CAUSAL_ROUTES,
            )
        RUNNER["validate_pair"](
            baseline, candidate, expected_routes=CAUSAL_ROUTES
        )

        wrong_mode = dict(baseline)
        wrong_mode["route"] = wrong_mode["route"].replace(
            "scalar-per-haystack-loop-v1", "direct-descriptor-batch-api-v1"
        )
        with self.assertRaisesRegex(BenchmarkError, "timed_mode"):
            RUNNER["validate_result"](
                wrong_mode,
                side="baseline",
                scenario="negative",
                batch=8,
                byte_size=4096,
                iterations=7,
                expected_routes=CAUSAL_ROUTES,
            )

        unexpected_route_difference = dict(candidate)
        baseline["route"] += ",causal_control=same"
        unexpected_route_difference["route"] += ",causal_control=different"
        with self.assertRaisesRegex(
            BenchmarkError, "outside authenticated per-arm fields"
        ):
            RUNNER["validate_pair"](
                baseline,
                unexpected_route_difference,
                expected_routes=CAUSAL_ROUTES,
            )

        with tempfile.TemporaryDirectory() as directory:
            binary = pathlib.Path(directory) / "one-binary"
            binary.write_bytes(b"same artifact")
            run_metadata = RUNNER["metadata_event"](
                binaries={"baseline": binary, "candidate": binary},
                scenarios=["negative"],
                batches=[8],
                byte_sizes=[4096],
                pairs=61,
                warmup_pairs=4,
                minimum_ns=200_000_000,
                target_ns=250_000_000,
                expected_routes=CAUSAL_ROUTES,
                execution_modes=RUNNER["SAME_BINARY_EXECUTION_MODES"],
            )
        self.assertEqual(
            run_metadata["comparison_policy"],
            "same-binary-explicit-timed-mode-v1",
        )
        self.assertEqual(
            run_metadata["binary_identity_policy"],
            "same-resolved-executable-v1",
        )
        self.assertEqual(
            run_metadata["execution_modes"], RUNNER["SAME_BINARY_EXECUTION_MODES"]
        )
        self.assertEqual(
            run_metadata["baseline_sha256"], run_metadata["candidate_sha256"]
        )
        missing_mode_metadata = dict(run_metadata)
        missing_mode_metadata.pop("execution_modes")
        with self.assertRaisesRegex(BenchmarkError, "execution_modes"):
            RUNNER["validate_resume_metadata"](
                missing_mode_metadata, expected_metadata=run_metadata
            )
        missing_route_evidence = dict(run_metadata)
        missing_route_evidence.pop("route_evidence")
        with self.assertRaisesRegex(BenchmarkError, "route_evidence"):
            RUNNER["validate_resume_metadata"](
                missing_route_evidence, expected_metadata=run_metadata
            )

    def test_same_binary_causal_rejects_distinct_artifacts_before_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            baseline = root / "baseline"
            candidate = root / "candidate"
            output = root / "must-not-exist.jsonl"
            for binary in (baseline, candidate):
                binary.write_text("#!/bin/sh\nexit 0\n")
                os.chmod(binary, 0o700)
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                status = RUNNER["main"](
                    [
                        "--baseline-bin",
                        str(baseline),
                        "--candidate-bin",
                        str(candidate),
                        "--output",
                        str(output),
                        "--same-binary-causal",
                    ]
                )
            self.assertEqual(status, 1)
            self.assertIn("identical resolved binary paths", stderr.getvalue())
            self.assertFalse(output.exists())

    def test_truncation_after_each_complete_phase_has_exact_resume_point(self):
        initial = [metadata()]
        progress = validate(initial)
        self.assertEqual((progress.phase, progress.iterations), ("calibration", 1))

        low, _ = pair_events(
            cell_index=0,
            scenario="negative",
            phase="calibration",
            ordinal=0,
            pair=None,
            iterations=1,
            elapsed_ns=10,
        )
        progress = validate(initial + low)
        self.assertEqual(
            (progress.phase, progress.iterations, progress.calibration_ordinal),
            ("calibration", 10, 1),
        )

        high, _ = pair_events(
            cell_index=0,
            scenario="negative",
            phase="calibration",
            ordinal=1,
            pair=None,
            iterations=10,
            elapsed_ns=100,
        )
        progress = validate(initial + low + high)
        self.assertEqual(
            (progress.phase, progress.iterations), ("record-calibrated", 10)
        )

        calibrated = {
            "type": "calibrated",
            "scenario": "negative",
            "batch": 1,
            "bytes_per_haystack": 64,
            "iterations": 10,
        }
        records = initial + low + high + [calibrated]
        progress = validate(records)
        self.assertEqual(
            (progress.phase, progress.warmup_pairs_completed), ("warmup", 0)
        )

        for warmup in range(WARMUPS):
            pair, _ = pair_events(
                cell_index=0,
                scenario="negative",
                phase="warmup",
                ordinal=warmup,
                pair=None,
                iterations=10,
                elapsed_ns=110 + warmup,
            )
            records += pair
            progress = validate(records)
            expected_phase = "measure" if warmup + 1 == WARMUPS else "warmup"
            self.assertEqual(progress.phase, expected_phase)
            self.assertEqual(progress.warmup_pairs_completed, warmup + 1)

        measured = []
        for pair_number in range(PAIRS):
            pair, measurements = pair_events(
                cell_index=0,
                scenario="negative",
                phase="measure",
                ordinal=pair_number,
                pair=pair_number,
                iterations=10,
                elapsed_ns=120 + pair_number,
            )
            records += pair
            measured.append(measurements)
            progress = validate(records)
            expected_phase = "summary" if pair_number + 1 == PAIRS else "measure"
            self.assertEqual(progress.phase, expected_phase)
            self.assertEqual(len(progress.measured), pair_number + 1)

        summary = RUNNER["paired_summary"]("negative", 1, 64, measured)
        records.append(summary)
        progress = validate(records)
        self.assertEqual(progress.phase, "aggregate")
        self.assertEqual(progress.summaries, [summary])

        aggregate = RUNNER["aggregate_summary"]([summary], PAIRS)
        records.append(aggregate)
        progress = validate(records)
        self.assertEqual(progress.phase, "complete")
        self.assertEqual(progress.aggregate, aggregate)

    def test_single_first_arm_is_recoverable_in_every_pair_phase(self):
        calibrated, pieces = calibrated_prefix(0, "negative")
        warmup_zero, _ = pair_events(
            cell_index=0,
            scenario="negative",
            phase="warmup",
            ordinal=0,
            pair=None,
            iterations=10,
            elapsed_ns=110,
        )
        warmup_one, _ = pair_events(
            cell_index=0,
            scenario="negative",
            phase="warmup",
            ordinal=1,
            pair=None,
            iterations=10,
            elapsed_ns=111,
        )
        measure_zero, _ = pair_events(
            cell_index=0,
            scenario="negative",
            phase="measure",
            ordinal=0,
            pair=0,
            iterations=10,
            elapsed_ns=120,
        )
        cases = {
            "calibration": [metadata(), pieces[0][0]],
            "warmup": [metadata()] + calibrated + [warmup_zero[0]],
            "measure": [metadata()]
            + calibrated
            + warmup_zero
            + warmup_one
            + [measure_zero[0]],
        }
        for phase, events in cases.items():
            with self.subTest(phase=phase):
                progress = validate(events)
                self.assertEqual(progress.phase, phase)
                self.assertEqual(len(progress.partial_results), 1)

    def test_misordered_duplicate_or_nonterminal_partial_arm_is_rejected(self):
        calibrated, _ = calibrated_prefix(0, "negative")
        warmup_zero, _ = pair_events(
            cell_index=0,
            scenario="negative",
            phase="warmup",
            ordinal=0,
            pair=None,
            iterations=10,
            elapsed_ns=110,
        )
        prefix = [metadata()] + calibrated
        malformed = {
            "second-arm-only": prefix + [warmup_zero[1]],
            "duplicate-first-arm": prefix + [warmup_zero[0], warmup_zero[0]],
            "nonterminal-first-arm": prefix
            + [warmup_zero[0], {"type": "paired_summary"}],
        }
        for shape, events in malformed.items():
            with self.subTest(shape=shape):
                with self.assertRaises(BenchmarkError):
                    validate(events)

    def test_completed_summary_is_preserved_before_partial_next_cell(self):
        first_events, first_summary, _ = cell_events(0, "negative")
        second_prefix, _ = calibrated_prefix(1, "early")
        for warmup in range(WARMUPS):
            pair, _ = pair_events(
                cell_index=1,
                scenario="early",
                phase="warmup",
                ordinal=warmup,
                pair=None,
                iterations=10,
                elapsed_ns=110 + warmup,
            )
            second_prefix += pair
        for pair_number in range(4):
            pair, _ = pair_events(
                cell_index=1,
                scenario="early",
                phase="measure",
                ordinal=pair_number,
                pair=pair_number,
                iterations=10,
                elapsed_ns=120 + pair_number,
            )
            second_prefix += pair
        dangling, _ = pair_events(
            cell_index=1,
            scenario="early",
            phase="measure",
            ordinal=4,
            pair=4,
            iterations=10,
            elapsed_ns=124,
        )
        second_prefix.append(dangling[0])
        run_metadata = metadata()
        run_metadata["scenarios"] = ["negative", "early"]
        events = [run_metadata] + first_events + second_prefix
        progress = RUNNER["validate_resume_events"](
            events,
            expected_metadata=run_metadata,
            cells=[("negative", 1, 64), ("early", 1, 64)],
            pairs=PAIRS,
            warmup_pairs=WARMUPS,
            minimum_ns=MINIMUM_NS,
            target_ns=TARGET_NS,
            expected_routes=EXPECTED_ROUTES,
        )
        self.assertEqual(progress.summaries, [first_summary])
        self.assertEqual((progress.cell_index, progress.phase), (1, "measure"))
        self.assertEqual(len(progress.measured), 4)
        self.assertEqual(set(progress.partial_results), {"candidate"})

    def test_ba_partial_pair_invokes_only_missing_baseline_arm(self):
        existing = result(
            "candidate",
            scenario="early",
            batch=1,
            byte_size=64,
            iterations=10,
            elapsed_ns=124,
        )
        calls = []

        def fake_invoke(**kwargs):
            calls.append(kwargs["side"])
            return result(
                kwargs["side"],
                scenario=kwargs["scenario"],
                batch=kwargs["batch"],
                byte_size=kwargs["byte_size"],
                iterations=kwargs["iterations"],
                elapsed_ns=125,
            )

        globals_dict = RUNNER["run_pair"].__globals__
        original_invoke = globals_dict["invoke"]
        globals_dict["invoke"] = fake_invoke
        try:
            results = RUNNER["run_pair"](
                binaries={
                    "baseline": pathlib.Path("baseline"),
                    "candidate": pathlib.Path("candidate"),
                },
                scenario="early",
                batch=1,
                byte_size=64,
                iterations=10,
                phase="measure",
                ordinal=4,
                pair=4,
                order="BA",
                event_log=object(),
                expected_routes=EXPECTED_ROUTES,
                existing_results={"candidate": existing},
            )
        finally:
            globals_dict["invoke"] = original_invoke
        self.assertEqual(calls, ["baseline"])
        self.assertEqual(set(results), {"baseline", "candidate"})

    def test_metadata_compatibility_is_exact_and_explicit(self):
        current = metadata()
        self.assertEqual(
            RUNNER["validate_resume_metadata"](
                current, expected_metadata=current
            ),
            "current-v1",
        )
        legacy = dict(current)
        legacy.pop("route_evidence")
        self.assertEqual(
            RUNNER["validate_resume_metadata"](
                legacy, expected_metadata=current
            ),
            "legacy-v1-without-route-evidence",
        )
        for field in ("candidate_sha256", "pairs", "expected_routes"):
            invalid = dict(legacy)
            invalid.pop(field)
            with self.subTest(field=field):
                with self.assertRaises(BenchmarkError):
                    RUNNER["validate_resume_metadata"](
                        invalid, expected_metadata=current
                    )
        type_smuggled = dict(legacy)
        type_smuggled["pairs"] = True
        with self.assertRaises(BenchmarkError):
            RUNNER["validate_resume_metadata"](
                type_smuggled, expected_metadata=current
            )

    def test_error_duplicate_cell_and_bad_summaries_are_rejected(self):
        with self.assertRaisesRegex(BenchmarkError, "terminal error"):
            validate([metadata(), {"type": "error", "status": "failed"}])
        with self.assertRaisesRegex(BenchmarkError, "duplicates"):
            validate([metadata()], cells=CELLS + CELLS)

        complete, _, _ = cell_events(0, "negative")
        bad_summary_events = [metadata()] + complete
        bad_summary_events[-1] = dict(bad_summary_events[-1])
        bad_summary_events[-1]["pair_count"] = 5
        with self.assertRaisesRegex(BenchmarkError, "does not authenticate"):
            validate(bad_summary_events)

        complete, summary, _ = cell_events(0, "negative")
        bad_aggregate = RUNNER["aggregate_summary"]([summary], PAIRS)
        bad_aggregate["cell_count"] = 2
        with self.assertRaisesRegex(BenchmarkError, "aggregate summary"):
            validate([metadata()] + complete + [bad_aggregate])

    def test_jsonl_reader_rejects_partial_and_duplicate_key_records(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "events.jsonl"
            path.write_bytes(b'{"type":"metadata"}')
            with self.assertRaisesRegex(BenchmarkError, "incomplete JSONL"):
                RUNNER["read_event_log"](path)
            path.write_bytes(b'{"type":"metadata","type":"metadata"}\n')
            with self.assertRaisesRegex(BenchmarkError, "duplicate JSON"):
                RUNNER["read_event_log"](path)

    def test_fresh_invoke_rejects_duplicate_keys_and_nonfinite_numbers(self):
        class RecordingLog:
            def __init__(self):
                self.events = []

            def write(self, event):
                self.events.append(event)

        globals_dict = RUNNER["invoke"].__globals__
        original_run = globals_dict["subprocess"].run
        for stdout in ('{"x":1,"x":2}\n', '{"x":NaN}\n'):
            with self.subTest(stdout=stdout):
                def fake_run(*_args, **_kwargs):
                    return type(
                        "Completed",
                        (),
                        {"returncode": 0, "stdout": stdout, "stderr": ""},
                    )()

                log = RecordingLog()
                globals_dict["subprocess"].run = fake_run
                try:
                    with self.assertRaisesRegex(BenchmarkError, "invalid JSON"):
                        RUNNER["invoke"](
                            binary=pathlib.Path("binary"),
                            side="baseline",
                            scenario="negative",
                            batch=1,
                            byte_size=64,
                            iterations=1,
                            phase="measure",
                            ordinal=0,
                            pair=0,
                            order="AB",
                            event_log=log,
                            expected_routes=EXPECTED_ROUTES,
                        )
                finally:
                    globals_dict["subprocess"].run = original_run
                self.assertEqual(len(log.events), 1)
                self.assertEqual(log.events[0]["validation"], "failed")

    def test_append_open_preserves_validated_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "events.jsonl"
            prefix = b'{"type":"metadata"}\n'
            path.write_bytes(prefix)
            _, identity = RUNNER["read_event_log"](path)
            log = RUNNER["EventLog"](path, append_identity=identity)
            log.write({"type": "sentinel"})
            log.close()
            self.assertTrue(path.read_bytes().startswith(prefix))
            self.assertEqual(path.read_bytes().count(prefix), 1)

    def test_append_open_rejects_same_size_content_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "events.jsonl"
            path.write_bytes(b'{"type":"metadata"}\n')
            _, identity = RUNNER["read_event_log"](path)
            path.write_bytes(b'{"type":"sentinel"}\n')
            os.utime(path, ns=(identity.mtime_ns, identity.mtime_ns))
            with self.assertRaisesRegex(BenchmarkError, "output changed"):
                RUNNER["EventLog"](path, append_identity=identity)

    def test_main_resumes_at_next_measure_pair_and_authenticates_final_log(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            baseline = root / "baseline"
            candidate = root / "candidate"
            baseline.write_text("#!/bin/sh\nexit 0\n")
            candidate.write_text("#!/bin/sh\nexit 0\n")
            os.chmod(baseline, 0o700)
            os.chmod(candidate, 0o700)
            binaries = {
                "baseline": baseline.resolve(),
                "candidate": candidate.resolve(),
            }
            run_metadata = RUNNER["metadata_event"](
                binaries=binaries,
                scenarios=["negative"],
                batches=[1],
                byte_sizes=[64],
                pairs=PAIRS,
                warmup_pairs=WARMUPS,
                minimum_ns=MINIMUM_NS,
                target_ns=TARGET_NS,
                expected_routes=EXPECTED_ROUTES,
            )
            records, _ = calibrated_prefix(0, "negative")
            for warmup in range(WARMUPS):
                events, _ = pair_events(
                    cell_index=0,
                    scenario="negative",
                    phase="warmup",
                    ordinal=warmup,
                    pair=None,
                    iterations=10,
                    elapsed_ns=110 + warmup,
                )
                records += events
            for pair_number in range(4):
                events, _ = pair_events(
                    cell_index=0,
                    scenario="negative",
                    phase="measure",
                    ordinal=pair_number,
                    pair=pair_number,
                    iterations=10,
                    elapsed_ns=120 + pair_number,
                )
                records += events
            dangling, _ = pair_events(
                cell_index=0,
                scenario="negative",
                phase="measure",
                ordinal=4,
                pair=4,
                iterations=10,
                elapsed_ns=124,
            )
            records.append(dangling[0])
            output = root / "run.jsonl"
            with output.open("w", encoding="utf-8") as stream:
                for event in [run_metadata] + records:
                    json.dump(event, stream, sort_keys=True, separators=(",", ":"))
                    stream.write("\n")
            os.chmod(output, 0o600)

            calls = []

            def fake_run_pair(**kwargs):
                existing = kwargs.get("existing_results") or {}
                calls.append(
                    (
                        kwargs["phase"],
                        kwargs["ordinal"],
                        kwargs["pair"],
                        tuple(sorted(existing)),
                    )
                )
                events, (_, results) = pair_events(
                    cell_index=0,
                    scenario=kwargs["scenario"],
                    phase=kwargs["phase"],
                    ordinal=kwargs["ordinal"],
                    pair=kwargs["pair"],
                    iterations=kwargs["iterations"],
                    elapsed_ns=125 + kwargs["ordinal"],
                )
                for event in events[len(existing) :]:
                    kwargs["event_log"].write(event)
                results.update(existing)
                RUNNER["validate_pair"](
                    results["baseline"],
                    results["candidate"],
                    expected_routes=EXPECTED_ROUTES,
                )
                return results

            globals_dict = RUNNER["main"].__globals__
            original_run_pair = globals_dict["run_pair"]
            globals_dict["run_pair"] = fake_run_pair
            try:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
                    io.StringIO()
                ):
                    status = RUNNER["main"](
                        [
                            "--baseline-bin",
                            str(baseline),
                            "--candidate-bin",
                            str(candidate),
                            "--output",
                            str(output),
                            "--resume",
                            "--pairs",
                            str(PAIRS),
                            "--warmup-pairs",
                            str(WARMUPS),
                            "--min-sample-ms",
                            "0.00008",
                            "--target-sample-ms",
                            "0.0001",
                            "--scenarios",
                            "negative",
                            "--batches",
                            "1",
                            "--bytes",
                            "64",
                        ]
                    )
            finally:
                globals_dict["run_pair"] = original_run_pair
            self.assertEqual(status, 0)
            self.assertEqual(
                calls,
                [
                    ("measure", 4, 4, ("baseline",)),
                    ("measure", 5, 5, ()),
                ],
            )
            events, _ = RUNNER["read_event_log"](output)
            final = RUNNER["validate_resume_events"](
                events,
                expected_metadata=run_metadata,
                cells=CELLS,
                pairs=PAIRS,
                warmup_pairs=WARMUPS,
                minimum_ns=MINIMUM_NS,
                target_ns=TARGET_NS,
                expected_routes=EXPECTED_ROUTES,
            )
            self.assertEqual(final.phase, "complete")


if __name__ == "__main__":
    unittest.main()
