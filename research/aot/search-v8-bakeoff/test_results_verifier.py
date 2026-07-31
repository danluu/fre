#!/usr/bin/env python3
"""Source-level tamper tests for verify_results.py."""

from __future__ import annotations

import copy
import csv
import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path

import verify_results as verifier


def receipt() -> dict[str, str]:
    identity = "1" * 64
    compile_identity = "2" * 64
    return {
        "schema": verifier.RECEIPT_SCHEMA,
        "subject_revision": "3" * 40,
        "benchmark_source_sha256": identity,
        "semantic_identity_bytes_hashed": "512",
        "semantic_identity": "4" * 64,
        "binding_identity": "a" * 64,
        "compiler_receipt_identity": "b" * 64,
        "source_identity": "5" * 64,
        "artifact_identity": "6" * 64,
        "compile_identity": compile_identity,
        "object_identity": "7" * 64,
        "payload_sha256": "8" * 64,
        "metadata_sha256": "9" * 64,
        "literal_hex": "30313233343536373839616263646566",
        "literal_bytes": "16",
        "backend_version": "8",
        "output_kind": "3",
        "object_bytes": "1024",
        "payload_bytes": "64",
        "metadata_bytes": "216",
        "code_bytes": "48",
        "rodata_offset": "48",
        "rodata_bytes": "16",
        "entry_symbol": f"fre_aot_search_entry_v1_{compile_identity}",
        "payload_symbol": f"fre_aot_payload_v1_{compile_identity}",
        "metadata_symbol": f"fre_aot_metadata_v1_{compile_identity}",
        "object_path": "/private/tmp/search.o",
        "link_map_path": "/private/tmp/search.map",
        "target": "aarch64-apple-macos",
        "aot_authority": "benchmark-local-raw-abi-no-adoption",
        "qualification_state": "candidate",
        "production_activation": "absent",
    }


def common_row(bound: dict[str, str]) -> dict[str, str]:
    return {
        "revision": bound["subject_revision"],
        "pid": "123",
        "qualification_state": "candidate",
        "production_activation": "absent",
        **{field: bound[field] for field in verifier.IDENTITY_FIELDS},
    }


def hot_rows(bound: dict[str, str]) -> list[dict[str, str]]:
    rows = []
    elapsed = {
        "raw-static-aot": 100,
        "strict-wx-jit": 120,
        "portable": 200,
    }
    for size, (byte_count, iterations) in verifier.SIZES.items():
        for scenario in verifier.SCENARIOS:
            for repetition in range(verifier.HOT_REPETITIONS):
                order = verifier.ENGINE_ORDERS[
                    repetition % len(verifier.ENGINE_ORDERS)
                ]
                for engine in order:
                    route, authority, backend = verifier.ENGINES[engine]
                    total = elapsed[engine] * iterations
                    rows.append(
                        {
                            **common_row(bound),
                            "schema": verifier.HOT_SCHEMA,
                            "repetition": str(repetition),
                            "cell": f"span-{size}-{scenario}",
                            "size": size,
                            "scenario": scenario,
                            "order": "+".join(order),
                            "engine": engine,
                            "stage": "hot",
                            "iterations": str(iterations),
                            "total_ns": str(total),
                            "ns_per_iter": str(elapsed[engine]),
                            "checksum": "0x1111111111111111",
                            "semantic_value": "0x2222222222222222",
                            "haystack_bytes": str(byte_count),
                            "window_start": "0",
                            "window_end": str(byte_count),
                            "alignment_mod16": str(
                                verifier.expected_alignment(scenario)
                            ),
                            "route": route,
                            "authority": authority,
                            "backend": backend,
                        }
                    )
    return rows


def cold_rows(bound: dict[str, str]) -> list[dict[str, str]]:
    rows = []
    phases = list(verifier.COLD_PHASES)
    for repetition in range(verifier.COLD_REPETITIONS):
        for offset in range(len(phases)):
            phase = phases[(repetition + offset) % len(phases)]
            rows.append(
                {
                    **common_row(bound),
                    "schema": verifier.COLD_SCHEMA,
                    "repetition": str(repetition),
                    "order": f"rotation-{repetition % len(phases)}",
                    "phase": phase,
                    "iterations": str(verifier.COLD_ITERATIONS),
                    "total_ns": str(verifier.COLD_ITERATIONS * 100),
                    "ns_per_iter": "100",
                    "checksum": "0x3333333333333333",
                    "scope": verifier.COLD_PHASES[phase],
                }
            )
    return rows


def first_rows(bound: dict[str, str]) -> list[dict[str, str]]:
    rows = []
    for size, scenario in verifier.FIRST_CASES:
        byte_count = verifier.SIZES[size][0]
        for engine, (route, authority, backend) in verifier.ENGINES.items():
            for repetition in range(verifier.FIRST_REPETITIONS):
                rows.append(
                    {
                        **common_row(bound),
                        "schema": verifier.FIRST_SCHEMA,
                        "repetition": str(repetition),
                        "cell": f"span-{size}-{scenario}",
                        "size": size,
                        "scenario": scenario,
                        "engine": engine,
                        "stage": "ready-first-call",
                        "iterations": "1",
                        "total_ns": "100",
                        "ns_per_iter": "100",
                        "checksum": "0x4444444444444444",
                        "semantic_value": "0x5555555555555555",
                        "haystack_bytes": str(byte_count),
                        "alignment_mod16": "0",
                        "route": route,
                        "authority": authority,
                        "backend": backend,
                    }
                )
    return rows


def lifecycle_rows(bound: dict[str, str]) -> list[dict[str, str]]:
    rows = []
    semantic = 0x5555_5555_5555_5555
    for size, scenario in verifier.LIFECYCLE_CASES:
        byte_count = verifier.SIZES[size][0]
        for calls in verifier.LIFECYCLE_CALL_GRIDS[size]:
            portable_ns = 1_000 + calls * 100
            jit_ns = 2_000 + calls * 50
            for repetition in range(verifier.LIFECYCLE_REPETITIONS):
                order = verifier.LIFECYCLE_ENGINE_ORDERS[repetition % 2]
                for engine in order:
                    route, authority, backend, stage = (
                        verifier.LIFECYCLE_ENGINES[engine]
                    )
                    total_ns = (
                        portable_ns if engine == "portable" else jit_ns
                    )
                    rows.append(
                        {
                            **common_row(bound),
                            "schema": verifier.LIFECYCLE_SCHEMA,
                            "repetition": str(repetition),
                            "cell": (
                                f"span-{size}-{scenario}-calls-{calls}"
                            ),
                            "size": size,
                            "scenario": scenario,
                            "calls": str(calls),
                            "order": "+".join(order),
                            "engine": engine,
                            "stage": stage,
                            "total_ns": str(total_ns),
                            "checksum": (
                                f"0x{verifier.lifecycle_checksum(calls, semantic):016x}"
                            ),
                            "semantic_value": f"0x{semantic:016x}",
                            "haystack_bytes": str(byte_count),
                            "alignment_mod16": "0",
                            "route": route,
                            "authority": authority,
                            "backend": backend,
                        }
                    )
    return rows


class ResultsVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.receipt = receipt()

    def assert_rejected(self, operation) -> None:
        with self.assertRaises(verifier.VerificationError):
            operation()

    def test_complete_matrices_pass(self) -> None:
        summary = verifier.validate_hot_rows(hot_rows(self.receipt), self.receipt)
        self.assertEqual(len(summary), 55)
        verifier.validate_cold_rows(cold_rows(self.receipt), self.receipt)
        verifier.validate_first_rows(first_rows(self.receipt), self.receipt)
        lifecycle_summary, lifecycle_break_even = (
            verifier.validate_lifecycle_rows(
                lifecycle_rows(self.receipt), self.receipt
            )
        )
        self.assertEqual(len(lifecycle_summary), 41)
        self.assertEqual(len(lifecycle_break_even), 5)
        self.assertEqual(
            {row[7] for row in lifecycle_break_even[1:]}, {"32"}
        )
        self.assertEqual(
            {row[9] for row in lifecycle_break_even[1:]}, {"20"}
        )

    def test_hot_tampers_fail_closed(self) -> None:
        mutations = []
        base = hot_rows(self.receipt)
        for field, value in [
            ("artifact_identity", "a" * 64),
            ("engine", "portable"),
            ("route", "qualified-aot"),
            ("checksum", "0x9999999999999999"),
            ("semantic_value", "0x9999999999999999"),
            ("alignment_mod16", "15"),
            ("iterations", "1"),
            ("order", "portable+strict-wx-jit+raw-static-aot"),
        ]:
            changed = copy.deepcopy(base)
            changed[0][field] = value
            mutations.append(changed)
        slow = copy.deepcopy(base)
        for row in slow:
            if row["engine"] == "raw-static-aot":
                row["total_ns"] = str(int(row["iterations"]) * 300)
                row["ns_per_iter"] = "300"
        mutations.append(slow)
        reordered = copy.deepcopy(base)
        reordered[0], reordered[1] = reordered[1], reordered[0]
        mutations.append(reordered)
        for changed in mutations:
            with self.subTest(changed=changed[0]):
                self.assert_rejected(
                    lambda changed=changed: verifier.validate_hot_rows(
                        changed, self.receipt
                    )
                )

    def test_cold_and_first_call_tampers_fail_closed(self) -> None:
        cold = cold_rows(self.receipt)
        cold[0]["scope"] = "link-time"
        self.assert_rejected(
            lambda: verifier.validate_cold_rows(cold, self.receipt)
        )
        first = first_rows(self.receipt)
        first[0]["authority"] = "production"
        self.assert_rejected(
            lambda: verifier.validate_first_rows(first, self.receipt)
        )

        cold = cold_rows(self.receipt)
        cold[0], cold[1] = cold[1], cold[0]
        self.assert_rejected(
            lambda: verifier.validate_cold_rows(cold, self.receipt)
        )

        first = first_rows(self.receipt)
        first[0], first[1] = first[1], first[0]
        self.assert_rejected(
            lambda: verifier.validate_first_rows(first, self.receipt)
        )

    def test_lifecycle_schema_route_and_matrix_tampers_fail_closed(self) -> None:
        base = lifecycle_rows(self.receipt)
        mutations = []
        for field, value in [
            ("schema", verifier.HOT_SCHEMA),
            ("route", "strict-wx-published-jit"),
            ("stage", "hot"),
            ("engine", "raw-static-aot"),
            ("order", "strict-wx-jit+portable"),
            ("calls", "3"),
            ("checksum", "0x9999999999999999"),
            ("semantic_value", "0x9999999999999999"),
            ("alignment_mod16", "1"),
            ("total_ns", "0"),
        ]:
            changed = copy.deepcopy(base)
            changed[0][field] = value
            mutations.append(changed)
        reordered = copy.deepcopy(base)
        reordered[0], reordered[1] = reordered[1], reordered[0]
        mutations.append(reordered)
        for changed in mutations:
            with self.subTest(changed=changed[0]):
                self.assert_rejected(
                    lambda changed=changed: verifier.validate_lifecycle_rows(
                        changed, self.receipt
                    )
                )

    def test_lifecycle_strict_ratio_and_win_gates_fail_closed(self) -> None:
        ratio_failure = lifecycle_rows(self.receipt)
        for row in ratio_failure:
            if (
                row["size"] == "64k"
                and row["scenario"] == "absent"
                and row["calls"] == "1024"
                and row["engine"] == "strict-wx-jit"
            ):
                portable_ns = 1_000 + 1024 * 100
                row["total_ns"] = str(portable_ns * 99 // 100)
        self.assert_rejected(
            lambda: verifier.validate_lifecycle_rows(
                ratio_failure, self.receipt
            )
        )

        win_failure = lifecycle_rows(self.receipt)
        for row in win_failure:
            if (
                row["size"] == "64k"
                and row["scenario"] == "absent"
                and row["calls"] == "1024"
                and row["engine"] == "strict-wx-jit"
                and int(row["repetition"]) >= 19
            ):
                row["total_ns"] = str(1_000 + 1024 * 100)
        self.assert_rejected(
            lambda: verifier.validate_lifecycle_rows(
                win_failure, self.receipt
            )
        )

        no_crossing = lifecycle_rows(self.receipt)
        for row in no_crossing:
            if row["engine"] == "strict-wx-jit":
                calls = int(row["calls"])
                row["total_ns"] = str(2_000 + calls * 150)
        diagnostic_summary, diagnostic_break_even = (
            verifier.validate_lifecycle_rows(
                no_crossing,
                self.receipt,
                require_sustained_break_even=False,
            )
        )
        self.assertEqual(len(diagnostic_summary), 41)
        self.assertEqual(
            {row[6] for row in diagnostic_break_even[1:]},
            {"not-observed-through-grid"},
        )
        self.assertEqual(
            {row[7] for row in diagnostic_break_even[1:]},
            {"not-applicable"},
        )
        self.assert_rejected(
            lambda: verifier.validate_lifecycle_rows(
                no_crossing, self.receipt
            )
        )

    def test_lifecycle_admission_is_strict_and_precedes_completion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt_path = root / "build-receipt.tsv"
            receipt_path.write_text(
                "".join(
                    f"{key}\t{self.receipt[key]}\n"
                    for key in verifier.RECEIPT_KEYS
                ),
                encoding="ascii",
            )
            lifecycle_path = root / "lifecycle.csv"

            def write_lifecycle(rows: list[dict[str, str]]) -> None:
                with lifecycle_path.open(
                    "w", encoding="ascii", newline=""
                ) as output:
                    writer = csv.DictWriter(
                        output,
                        fieldnames=verifier.LIFECYCLE_HEADER,
                        lineterminator="\n",
                    )
                    writer.writeheader()
                    writer.writerows(rows)

            passing = lifecycle_rows(self.receipt)
            write_lifecycle(passing)
            verifier.qualify_lifecycle(receipt_path, lifecycle_path)

            no_crossing = copy.deepcopy(passing)
            for row in no_crossing:
                if row["engine"] == "strict-wx-jit":
                    calls = int(row["calls"])
                    row["total_ns"] = str(2_000 + calls * 150)
            write_lifecycle(no_crossing)
            self.assert_rejected(
                lambda: verifier.qualify_lifecycle(
                    receipt_path, lifecycle_path
                )
            )

        runner = Path(__file__).with_name("run_qualification.sh").read_text(
            encoding="ascii"
        )
        derive = runner.index("derive-lifecycle-break-even")
        admission = runner.index('"$verifier" qualify-lifecycle')
        environment = runner.index(
            "fre-search-v8-bakeoff-environment-v3"
        )
        completion = runner.index(
            "fre-search-v8-bakeoff-completion-v3"
        )
        final_verify = runner.index('"$verifier" verify')
        self.assertLess(derive, admission)
        self.assertLess(admission, environment)
        self.assertLess(environment, completion)
        self.assertLess(completion, final_verify)

    def test_receipt_order_and_identity_symbols_are_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.tsv"
            path.write_text(
                "".join(
                    f"{key}\t{self.receipt[key]}\n"
                    for key in verifier.RECEIPT_KEYS
                ),
                encoding="ascii",
            )
            self.assertEqual(verifier.parse_receipt(path), self.receipt)
            changed = dict(self.receipt)
            changed["entry_symbol"] = "fre_aot_search_entry_v1_" + "f" * 64
            path.write_text(
                "".join(
                    f"{key}\t{changed[key]}\n"
                    for key in verifier.RECEIPT_KEYS
                ),
                encoding="ascii",
            )
            self.assert_rejected(lambda: verifier.parse_receipt(path))
            for identity_field in [
                "binding_identity",
                "compiler_receipt_identity",
            ]:
                changed = dict(self.receipt)
                changed[identity_field] = "0" * 64
                path.write_text(
                    "".join(
                        f"{key}\t{changed[key]}\n"
                        for key in verifier.RECEIPT_KEYS
                    ),
                    encoding="ascii",
                )
                with self.subTest(identity_field=identity_field):
                    self.assert_rejected(lambda: verifier.parse_receipt(path))
            changed = dict(self.receipt)
            changed["binding_identity"] = changed["semantic_identity"]
            path.write_text(
                "".join(
                    f"{key}\t{changed[key]}\n"
                    for key in verifier.RECEIPT_KEYS
                ),
                encoding="ascii",
            )
            self.assert_rejected(lambda: verifier.parse_receipt(path))

    def test_environment_binds_retained_and_linked_binary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt_path = root / "build-receipt.tsv"
            receipt_path.write_text(
                "".join(
                    f"{key}\t{self.receipt[key]}\n"
                    for key in verifier.RECEIPT_KEYS
                ),
                encoding="ascii",
            )
            subject = root / "subject-bin"
            subject.write_bytes(b"retained benchmark executable")
            linked_directory = root / "linked-image"
            linked_directory.mkdir()
            linked_verification = linked_directory / "verification.tsv"
            linked_verification.write_text("overall\tPASS\n", encoding="ascii")
            binary_sha256 = hashlib.sha256(subject.read_bytes()).hexdigest()
            environment = root / "environment.tsv"

            def write_environment(binary_digest: str) -> None:
                environment.write_text(
                    "".join(
                        [
                            "schema\tfre-search-v8-bakeoff-environment-v3\n",
                            f"subject_revision\t{self.receipt['subject_revision']}\n",
                            "binary_relative_path\tsubject-bin\n",
                            f"binary_sha256\t{binary_digest}\n",
                            "build_receipt_sha256\t"
                            f"{hashlib.sha256(receipt_path.read_bytes()).hexdigest()}\n",
                            "linked_verification_sha256\t"
                            f"{hashlib.sha256(linked_verification.read_bytes()).hexdigest()}\n",
                            "timing_admission_kind\ttiming\n",
                            "lifecycle_process_state\t"
                            "fresh-process-per-case-call-count-repetition\n",
                            "lifecycle_os_page_cache\tuncontrolled\n",
                            "lifecycle_cache_flush\tabsent\n",
                            "lifecycle_outlier_removal\tabsent\n",
                        ]
                    ),
                    encoding="ascii",
                )

            linked_receipt = {"executable_sha256": binary_sha256}
            write_environment(binary_sha256)
            verifier.verify_environment(root, self.receipt, linked_receipt)

            environment.write_text(
                environment.read_text(encoding="ascii").replace(
                    "lifecycle_os_page_cache\tuncontrolled",
                    "lifecycle_os_page_cache\tcontrolled",
                ),
                encoding="ascii",
            )
            self.assert_rejected(
                lambda: verifier.verify_environment(
                    root, self.receipt, linked_receipt
                )
            )

            write_environment("a" * 64)
            self.assert_rejected(
                lambda: verifier.verify_environment(
                    root, self.receipt, linked_receipt
                )
            )

            write_environment(binary_sha256)
            subject.write_bytes(b"changed retained benchmark executable")
            self.assert_rejected(
                lambda: verifier.verify_environment(
                    root, self.receipt, linked_receipt
                )
            )

    def test_runner_rejects_malformed_timing_holder_tokens(self) -> None:
        runner = Path(__file__).with_name("run_qualification.sh")
        rejection = (
            "timing holder token must be exactly 64 lowercase hexadecimal characters"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            arguments = [
                "/bin/bash",
                "-p",
                str(runner),
                str(root / "missing-subject"),
                str(root / "missing-receipt"),
                str(root / "missing-output"),
            ]
            base_environment = {
                "FRE_RESOURCE_HOLDER_KIND": "timing",
                "FRE_RESOURCE_HOLDER_DIR": str(root),
            }
            for token in ["", "a" * 63, "a" * 65, "A" * 64, "g" * 64]:
                environment = {
                    **base_environment,
                    "FRE_RESOURCE_HOLDER_TOKEN": token,
                }
                completed = subprocess.run(
                    arguments,
                    check=False,
                    capture_output=True,
                    env=environment,
                    text=True,
                )
                with self.subTest(token=token):
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertIn(rejection, completed.stderr)

            valid_environment = {
                **base_environment,
                "FRE_RESOURCE_HOLDER_TOKEN": "a" * 64,
            }
            completed = subprocess.run(
                arguments,
                check=False,
                capture_output=True,
                env=valid_environment,
                text=True,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertNotIn(rejection, completed.stderr)


if __name__ == "__main__":
    unittest.main()
