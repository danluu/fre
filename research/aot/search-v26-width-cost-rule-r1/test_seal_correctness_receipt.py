#!/usr/bin/env python3
"""Tests for Search V26 platform execution and correctness-only receipts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_correctness_lane as lane_runner
import seal_correctness_receipt as seal


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_bytes(seal.canonical_bytes(value) + b"\n")


def local_macho() -> bytes:
    value = bytearray(96)
    value[:4] = b"\xcf\xfa\xed\xfe"
    value[4:8] = (0x0100000C).to_bytes(4, "little")
    value[8:12] = (0).to_bytes(4, "little")
    value[12:16] = (2).to_bytes(4, "little")
    value[32:] = b"local-v26-runner" + bytes(48)
    return bytes(value)


def c9g_elf() -> bytes:
    value = bytearray(96)
    value[:4] = b"\x7fELF"
    value[4] = 2
    value[5] = 1
    value[6] = 1
    value[16:18] = (3).to_bytes(2, "little")
    value[18:20] = (183).to_bytes(2, "little")
    value[20:24] = (1).to_bytes(4, "little")
    value[64:] = b"c9g-v26-runner" + bytes(18)
    return bytes(value)


class ReceiptFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="fre-v26-receipt-test-")
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.execution_tool = Path(lane_runner.__file__).resolve()
        self.validation_tool = Path(seal.__file__).resolve()
        subprocess.run(["git", "init", "-q", str(self.source)], check=True)
        subprocess.run(
            ["git", "-C", str(self.source), "config", "user.name", "V26 Test"],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(self.source),
                "config",
                "user.email",
                "v26@example.invalid",
            ],
            check=True,
        )
        (self.source / "source.txt").write_text("exact source\n", encoding="utf-8")
        for repository_path, source_path in (
            (seal.EXECUTION_TOOL_REPOSITORY_PATH, self.execution_tool),
            (seal.VALIDATION_TOOL_REPOSITORY_PATH, self.validation_tool),
        ):
            destination = self.source / repository_path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source_path.read_bytes())
        subprocess.run(["git", "-C", str(self.source), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(self.source), "commit", "-q", "-m", "source"],
            check=True,
        )
        self.commit = self.git("rev-parse", "HEAD")
        self.tree = self.git("rev-parse", "HEAD^{tree}")
        self.source_set_sha256 = seal.git_source_set_sha256(
            self.source, self.commit
        )
        self.archive = self.root / "source.tar"
        with self.archive.open("wb") as output:
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(self.source),
                    "archive",
                    "--format=tar",
                    "HEAD",
                ],
                check=True,
                stdout=output,
            )

        self.local_binary = self.root / "local" / seal.RUNNER_BASENAME
        self.c9g_binary = self.root / "c9g" / seal.RUNNER_BASENAME
        self.local_binary.parent.mkdir()
        self.c9g_binary.parent.mkdir()
        self.local_binary.write_bytes(local_macho())
        self.c9g_binary.write_bytes(c9g_elf())
        self.local_binary.chmod(0o755)
        self.c9g_binary.chmod(0o755)
        self.static = self.root / "static.json"
        self.local = self.root / "local.json"
        self.c9g = self.root / "c9g.json"
        write_json(self.static, self.static_report())
        write_json(self.local, self.correctness_report("local"))
        write_json(self.c9g, self.correctness_report("c9g"))
        self.local_manifest = self.root / "local-execution.json"
        self.c9g_manifest = self.root / "c9g-execution.json"
        self.local_host = "local-macos-arm64-unit-fixture"
        self.c9g_host = "ec2-c9g-arm64-unit-fixture"
        self.write_manifests()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def git(self, *arguments: str) -> str:
        return subprocess.check_output(
            ["git", "-C", str(self.source), *arguments], text=True
        ).strip()

    @staticmethod
    def static_report() -> dict[str, object]:
        return {
            "schema": seal.STATIC_SCHEMA,
            "population_sha256": seal.POPULATION_SHA256,
            "candidate_backend": 39,
            "short_source_backend": 30,
            "wide_source_backend": 38,
            "literals": 1296,
            "exact_machine_object_parities": 1296,
            "distinct_aot_identities": 1296,
            "routing_boundary_checks": 24,
            "candidate_aot_magic_hex": "4652454136340027",
            "candidate": dict(seal.EXPECTED_TOTALS),
            "selected_source": dict(seal.EXPECTED_TOTALS),
            "timing": "not-run",
        }

    @staticmethod
    def correctness_report(lane: str) -> dict[str, object]:
        linux = lane == "c9g"
        return {
            "schema": seal.CORRECTNESS_SCHEMA,
            "lane": lane,
            "population_sha256": seal.POPULATION_SHA256,
            "backend": 39,
            "literals": 1296,
            "window_shapes": 6,
            "comparisons": 7776,
            "mismatches": 0,
            "target": {
                "architecture": "aarch64",
                "operating_system": "linux" if linux else "macos",
                "pointer_width": 64,
                "little_endian": True,
                "features": {
                    "asimd": True,
                    "sve": linux,
                    "sve2": linux,
                    "sve_vector_bytes": 16 if linux else None,
                },
            },
        }

    def build_identity_report(self, lane: str) -> dict[str, object]:
        return {
            "candidate_backend": 39,
            "debug_assertions": False,
            "performance_gate_authority": False,
            "population_sha256": seal.POPULATION_SHA256,
            "production_or_deployment_authority": False,
            "schema": seal.BUILD_IDENTITY_SCHEMA,
            "search_performance_timing_present": False,
            "source_archive_sha256": digest(self.archive),
            "source_commit": self.commit,
            "source_set_sha256": self.source_set_sha256,
            "source_tree": self.tree,
            "target_architecture": "aarch64",
            "target_little_endian": True,
            "target_operating_system": "macos" if lane == "local" else "linux",
            "target_pointer_width": 64,
        }

    def execution_payload(
        self,
        *,
        lane: str,
        created_utc: str,
    ) -> dict[str, object]:
        local = lane == "local"
        correctness_path = self.local if local else self.c9g
        correctness_raw = correctness_path.read_bytes()
        correctness_report = json.loads(correctness_raw)
        runner = self.local_binary if local else self.c9g_binary
        build_identity_report = self.build_identity_report(lane)
        build_identity_raw = seal.canonical_bytes(build_identity_report) + b"\n"
        return seal.execution_payload(
            lane=lane,
            created_utc=created_utc,
            host_identity=self.local_host if local else self.c9g_host,
            source_commit=self.commit,
            source_tree=self.tree,
            archive_sha256=digest(self.archive),
            archive_bytes=self.archive.stat().st_size,
            source_set_sha256=self.source_set_sha256,
            runner_sha256=digest(runner),
            runner_bytes=runner.stat().st_size,
            execution_tool_sha256=digest(self.execution_tool),
            execution_tool_bytes=self.execution_tool.stat().st_size,
            validation_tool_sha256=digest(self.validation_tool),
            validation_tool_bytes=self.validation_tool.stat().st_size,
            build_identity_raw=build_identity_raw,
            build_identity_report=build_identity_report,
            correctness_raw=correctness_raw,
            correctness_report=correctness_report,
            static_raw=self.static.read_bytes() if local else None,
        )

    def write_manifests(self) -> None:
        write_json(
            self.local_manifest,
            seal.execution_manifest(
                self.execution_payload(
                    lane="local", created_utc="2026-07-31T11:00:00Z"
                )
            ),
        )
        write_json(
            self.c9g_manifest,
            seal.execution_manifest(
                self.execution_payload(
                    lane="c9g", created_utc="2026-07-31T11:30:00Z"
                )
            ),
        )

    def arguments(self, output: str = "receipt.json") -> argparse.Namespace:
        return argparse.Namespace(
            source_root=str(self.source),
            source_commit=self.commit,
            source_tree=self.tree,
            source_archive=str(self.archive),
            source_archive_sha256=digest(self.archive),
            local_runner_binary=str(self.local_binary),
            local_runner_binary_sha256=digest(self.local_binary),
            c9g_runner_binary=str(self.c9g_binary),
            c9g_runner_binary_sha256=digest(self.c9g_binary),
            execution_tool=str(self.execution_tool),
            execution_tool_sha256=digest(self.execution_tool),
            static_report=str(self.static),
            static_report_sha256=digest(self.static),
            local_report=str(self.local),
            local_report_sha256=digest(self.local),
            local_host_identity=self.local_host,
            local_execution_manifest=str(self.local_manifest),
            local_execution_manifest_sha256=digest(self.local_manifest),
            c9g_report=str(self.c9g),
            c9g_report_sha256=digest(self.c9g),
            c9g_host_identity=self.c9g_host,
            c9g_execution_manifest=str(self.c9g_manifest),
            c9g_execution_manifest_sha256=digest(self.c9g_manifest),
            created_utc="2026-07-31T12:00:00Z",
            output=str(self.root / output),
        )


class SealCorrectnessReceiptTests(ReceiptFixture):
    def test_seals_create_new_read_only_receipt(self) -> None:
        arguments = self.arguments()
        receipt = seal.seal(arguments)
        output = Path(arguments.output)
        self.assertEqual(receipt["schema"], seal.RECEIPT_SCHEMA)
        self.assertTrue(output.is_file())
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o444)
        self.assertEqual(json.loads(output.read_bytes()), receipt)
        payload = receipt["payload"]
        self.assertNotEqual(
            payload["runners"]["local"]["binary_sha256"],
            payload["runners"]["c9g"]["binary_sha256"],
        )
        self.assertFalse(payload["result_policy"]["performance_gate_authority"])
        self.assertFalse(payload["result_policy"]["production_or_deployment_authority"])
        with self.assertRaises(seal.Refusal):
            seal.seal(arguments)

    def test_rejects_archive_not_equal_to_deterministic_git_archive(self) -> None:
        self.archive.write_bytes(self.archive.read_bytes() + b"attacker suffix")
        arguments = self.arguments("mutated-archive.json")
        arguments.source_archive_sha256 = digest(self.archive)
        with self.assertRaisesRegex(seal.Refusal, "byte-for-byte"):
            seal.seal(arguments)

    def test_source_and_archive_validation_ignore_git_replace_objects(self) -> None:
        source_file = self.source / "source.txt"
        source_file.write_text("replacement source\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(self.source), "add", "source.txt"], check=True
        )
        replacement_tree = self.git("write-tree")
        replacement_commit = subprocess.check_output(
            [
                "git",
                "-C",
                str(self.source),
                "commit-tree",
                replacement_tree,
                "-m",
                "replacement",
            ],
            text=True,
        ).strip()
        subprocess.run(
            ["git", "-C", str(self.source), "reset", "-q", "HEAD", "--", "."],
            check=True,
        )
        source_file.write_text("exact source\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(self.source), "replace", self.commit, replacement_commit],
            check=True,
        )
        self.assertEqual(self.git("rev-parse", "HEAD^{tree}"), replacement_tree)
        seal.validate_source(self.source, self.commit, self.tree)
        self.assertEqual(
            seal.verify_git_archive(
                self.source,
                self.commit,
                self.archive,
                digest(self.archive),
            ),
            (digest(self.archive), self.archive.stat().st_size),
        )
        self.assertEqual(
            seal.git_source_set_sha256(self.source, self.commit),
            self.source_set_sha256,
        )

    def test_rejects_same_binary_for_both_platforms(self) -> None:
        arguments = self.arguments("same-binary.json")
        arguments.c9g_runner_binary = arguments.local_runner_binary
        arguments.c9g_runner_binary_sha256 = arguments.local_runner_binary_sha256
        with self.assertRaises(seal.Refusal):
            seal.seal(arguments)

    def test_rejects_stale_runner_embedded_source_even_when_envelope_is_rehashed(self) -> None:
        manifest = json.loads(self.local_manifest.read_bytes())
        identity = manifest["payload"]["runner"]["build_identity"]
        identity["source_commit"] = "a" * 40
        identity_raw = seal.canonical_bytes(identity) + b"\n"
        binding = manifest["payload"]["reports"]["build_identity"]
        binding["report_sha256"] = hashlib.sha256(identity_raw).hexdigest()
        binding["report_bytes"] = len(identity_raw)
        manifest["payload_sha256"] = hashlib.sha256(
            seal.canonical_bytes(manifest["payload"])
        ).hexdigest()
        write_json(self.local_manifest, manifest)
        arguments = self.arguments("stale-runner-source.json")
        with self.assertRaisesRegex(seal.Refusal, "embedded source_commit mismatch"):
            seal.seal(arguments)

    def test_rejects_relabelled_compiled_source_set_with_rehashed_envelope(self) -> None:
        manifest = json.loads(self.local_manifest.read_bytes())
        identity = manifest["payload"]["runner"]["build_identity"]
        identity["source_set_sha256"] = "b" * 64
        identity_raw = seal.canonical_bytes(identity) + b"\n"
        binding = manifest["payload"]["reports"]["build_identity"]
        binding["report_sha256"] = hashlib.sha256(identity_raw).hexdigest()
        binding["report_bytes"] = len(identity_raw)
        manifest["payload_sha256"] = hashlib.sha256(
            seal.canonical_bytes(manifest["payload"])
        ).hexdigest()
        write_json(self.local_manifest, manifest)
        arguments = self.arguments("relabelled-source-set.json")
        with self.assertRaisesRegex(seal.Refusal, "embedded source_set_sha256 mismatch"):
            seal.seal(arguments)

    def test_rejects_debug_or_wrong_target_embedded_identity(self) -> None:
        for field, value in (
            ("debug_assertions", True),
            ("target_operating_system", "linux"),
        ):
            with self.subTest(field=field):
                manifest = json.loads(self.local_manifest.read_bytes())
                identity = manifest["payload"]["runner"]["build_identity"]
                identity[field] = value
                identity_raw = seal.canonical_bytes(identity) + b"\n"
                binding = manifest["payload"]["reports"]["build_identity"]
                binding["report_sha256"] = hashlib.sha256(identity_raw).hexdigest()
                binding["report_bytes"] = len(identity_raw)
                manifest["payload_sha256"] = hashlib.sha256(
                    seal.canonical_bytes(manifest["payload"])
                ).hexdigest()
                write_json(self.local_manifest, manifest)
                arguments = self.arguments(f"bad-build-{field}.json")
                with self.assertRaises(seal.Refusal):
                    seal.seal(arguments)
                self.write_manifests()

    def test_exact_correctness_numeric_types_reject_bool_zero_alias(self) -> None:
        report = self.correctness_report("local")
        report["mismatches"] = False
        with self.assertRaisesRegex(seal.Refusal, "exact integer 0"):
            seal.validate_correctness(report, "local")

    def test_rejects_wrong_platform_binary_format(self) -> None:
        self.c9g_binary.write_bytes(local_macho() + b"different")
        self.c9g_binary.chmod(0o755)
        arguments = self.arguments("wrong-format.json")
        with self.assertRaisesRegex(seal.Refusal, "AArch64 ELF"):
            seal.seal(arguments)

    def test_rejects_execution_tool_not_equal_to_bound_source_blob(self) -> None:
        stale_directory = self.root / "stale-tool"
        stale_directory.mkdir()
        stale_tool = stale_directory / seal.EXECUTION_TOOL_BASENAME
        stale_tool.write_bytes(self.execution_tool.read_bytes() + b"\n# stale copy\n")
        stale_tool.chmod(0o755)
        arguments = self.arguments("stale-tool.json")
        arguments.execution_tool = str(stale_tool)
        arguments.execution_tool_sha256 = digest(stale_tool)
        with self.assertRaisesRegex(seal.Refusal, "bound source-commit blob"):
            seal.seal(arguments)

    def test_rejects_manifest_report_hash_mismatch(self) -> None:
        self.local.write_bytes(b" " + self.local.read_bytes())
        arguments = self.arguments("manifest-report-mismatch.json")
        with self.assertRaisesRegex(seal.Refusal, "execution bindings changed"):
            seal.seal(arguments)

    def test_rejects_duplicated_or_wrong_lane_report(self) -> None:
        self.c9g.write_bytes(self.local.read_bytes())
        arguments = self.arguments("duplicate-report.json")
        with self.assertRaises(seal.Refusal):
            seal.seal(arguments)

    def test_rejects_manifest_command_mutation_with_recomputed_envelope(self) -> None:
        manifest = json.loads(self.local_manifest.read_bytes())
        manifest["payload"]["reports"]["correctness"]["argv"][-1] = "c9g"
        manifest["payload_sha256"] = hashlib.sha256(
            seal.canonical_bytes(manifest["payload"])
        ).hexdigest()
        write_json(self.local_manifest, manifest)
        arguments = self.arguments("mutated-command.json")
        with self.assertRaisesRegex(seal.Refusal, "execution bindings changed"):
            seal.seal(arguments)

    def test_rejects_duplicate_json_keys_in_report_or_manifest(self) -> None:
        original_local = self.local.read_bytes()
        original_manifest = self.local_manifest.read_bytes()
        cases = ("report", "manifest")
        for case in cases:
            with self.subTest(case=case):
                if case == "report":
                    self.local.write_bytes(b'{"schema":"one","schema":"two"}\n')
                    arguments = self.arguments(f"duplicate-{case}.json")
                    arguments.local_report_sha256 = digest(self.local)
                else:
                    self.local_manifest.write_bytes(
                        b'{"schema":"one","schema":"two"}\n'
                    )
                    arguments = self.arguments(f"duplicate-{case}.json")
                    arguments.local_execution_manifest_sha256 = digest(
                        self.local_manifest
                    )
                with self.assertRaisesRegex(seal.Refusal, "duplicate JSON key"):
                    seal.seal(arguments)
                self.local.write_bytes(original_local)
                self.local_manifest.write_bytes(original_manifest)

    def test_strict_json_rejects_float_aliases_and_exponent_overflow(self) -> None:
        for raw in (b'{"value":1.0}\n', b'{"value":1e9999}\n'):
            with self.subTest(raw=raw):
                with self.assertRaises(seal.Refusal):
                    seal.strict_json_bytes(raw, "noninteger numeric mutation")

    def test_strict_file_json_requires_one_lf_terminated_line(self) -> None:
        for index, raw in enumerate((b"{}", b"{}\r\n", b"\n{}\n")):
            with self.subTest(raw=raw):
                value = self.root / f"noncanonical-json-{index}"
                value.write_bytes(raw)
                with self.assertRaisesRegex(seal.Refusal, "one LF-terminated"):
                    seal.strict_json(
                        value, hashlib.sha256(raw).hexdigest(), "noncanonical JSON"
                    )

    def test_rejects_bool_integer_alias_inside_rehashed_execution_payload(self) -> None:
        manifest = json.loads(self.local_manifest.read_bytes())
        manifest["payload"]["result_policy"]["performance_gate_authority"] = 0
        manifest["payload_sha256"] = hashlib.sha256(
            seal.canonical_bytes(manifest["payload"])
        ).hexdigest()
        write_json(self.local_manifest, manifest)
        arguments = self.arguments("bool-integer-alias.json")
        with self.assertRaisesRegex(seal.Refusal, "execution bindings changed"):
            seal.seal(arguments)

    def test_rejects_mutated_static_coverage_even_with_matching_hash(self) -> None:
        report = self.static_report()
        report["exact_machine_object_parities"] = 1295
        write_json(self.static, report)
        arguments = self.arguments("mutated-static.json")
        with self.assertRaises(seal.Refusal):
            seal.seal(arguments)

    def test_rejects_hash_or_identity_placeholders(self) -> None:
        cases = (
            ("source_commit", "0" * 40),
            ("c9g_host_identity", "pending-c9g-host"),
            ("local_runner_binary_sha256", "0" * 64),
        )
        for field, value in cases:
            with self.subTest(field=field):
                arguments = self.arguments(f"placeholder-{field}.json")
                setattr(arguments, field, value)
                with self.assertRaises(seal.Refusal):
                    seal.seal(arguments)

    def test_rejects_same_host_identity_for_both_lanes(self) -> None:
        arguments = self.arguments("same-host.json")
        arguments.c9g_host_identity = arguments.local_host_identity
        with self.assertRaisesRegex(seal.Refusal, "must be distinct"):
            seal.seal(arguments)

    def test_rejects_dirty_or_wrong_source(self) -> None:
        (self.source / "untracked.txt").write_text("dirty\n", encoding="utf-8")
        with self.assertRaises(seal.Refusal):
            seal.seal(self.arguments("dirty.json"))
        (self.source / "untracked.txt").unlink()
        arguments = self.arguments("wrong-tree.json")
        arguments.source_tree = "1" * 40
        with self.assertRaises(seal.Refusal):
            seal.seal(arguments)

    def test_rejects_receipt_output_inside_source_worktree(self) -> None:
        arguments = self.arguments()
        arguments.output = str(self.source / "ignored-receipt.json")
        with self.assertRaisesRegex(seal.Refusal, "outside"):
            seal.seal(arguments)


class RunCorrectnessLaneTests(ReceiptFixture):
    def mock_runner(self, *, stderr: bool = False) -> Path:
        runner = self.root / "mock" / seal.RUNNER_BASENAME
        runner.parent.mkdir()
        static_json = seal.canonical_bytes(self.static_report()).decode("ascii")
        local_json = seal.canonical_bytes(
            self.correctness_report("local")
        ).decode("ascii")
        identity_json = seal.canonical_bytes(
            self.build_identity_report("local")
        ).decode("ascii")
        stderr_line = "printf '%s\\n' 'unexpected stderr' >&2\n" if stderr else ""
        runner.write_text(
            "#!/bin/sh\n"
            + stderr_line
            + "if [ \"$1\" = \"evidence-build-identity\" ]; then\n"
            + f"  printf '%s\\n' '{identity_json}'\n"
            + "elif [ \"$1\" = \"static\" ]; then\n"
            + f"  printf '%s\\n' '{static_json}'\n"
            + "elif [ \"$1\" = \"correctness\" ] && [ \"$2\" = \"local\" ]; then\n"
            + f"  printf '%s\\n' '{local_json}'\n"
            + "else\n"
            + "  exit 64\n"
            + "fi\n",
            encoding="utf-8",
        )
        runner.chmod(0o755)
        return runner

    @staticmethod
    def permit_script_artifact(
        path: Path, expected_sha256: str, lane: str
    ) -> tuple[bytes, str, int]:
        seal.require(path.name == seal.RUNNER_BASENAME, "mock basename changed")
        raw = seal.stable_bytes(path, seal.MAX_RUNNER_BYTES, f"{lane} mock runner")
        observed = hashlib.sha256(raw).hexdigest()
        seal.require(observed == expected_sha256, "mock runner hash changed")
        return raw, observed, len(raw)

    def lane_arguments(self, runner: Path, prefix: str) -> argparse.Namespace:
        return argparse.Namespace(
            source_root=str(self.source),
            source_commit=self.commit,
            source_tree=self.tree,
            source_archive=str(self.archive),
            source_archive_sha256=digest(self.archive),
            runner_binary=str(runner),
            runner_binary_sha256=digest(runner),
            host_identity="local-macos-arm64-controller-fixture",
            lane="local",
            created_utc="2026-07-31T10:00:00Z",
            static_output=str(self.root / f"{prefix}-static.json"),
            correctness_output=str(self.root / f"{prefix}-correctness.json"),
            manifest_output=str(self.root / f"{prefix}-manifest.json"),
        )

    def test_controller_executes_and_create_new_seals_exact_outputs(self) -> None:
        runner = self.mock_runner()
        arguments = self.lane_arguments(runner, "controller")
        with (
            mock.patch.object(
                lane_runner,
                "validate_host",
                return_value={
                    "architecture": "aarch64",
                    "operating_system": "macos",
                },
            ),
            mock.patch.object(
                seal,
                "validate_runner_artifact",
                side_effect=self.permit_script_artifact,
            ),
        ):
            manifest = lane_runner.run_lane(arguments)
            with self.assertRaises(seal.Refusal):
                lane_runner.run_lane(arguments)
        for field in ("static_output", "correctness_output", "manifest_output"):
            output = Path(getattr(arguments, field))
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o444)
        self.assertEqual(
            Path(arguments.static_output).read_bytes(), self.static.read_bytes()
        )
        self.assertEqual(
            Path(arguments.correctness_output).read_bytes(), self.local.read_bytes()
        )
        self.assertEqual(
            json.loads(Path(arguments.manifest_output).read_bytes()), manifest
        )
        self.assertEqual(
            manifest["payload"]["reports"]["correctness"]["argv"],
            [seal.RUNNER_BASENAME, "correctness", "local"],
        )
        self.assertEqual(
            manifest["payload"]["reports"]["build_identity"]["argv"],
            [seal.RUNNER_BASENAME, "evidence-build-identity"],
        )
        self.assertEqual(
            manifest["payload"]["runner"]["build_identity"]["source_commit"],
            self.commit,
        )
        self.assertFalse(
            manifest["payload"]["result_policy"]["performance_gate_authority"]
        )

    def test_controller_refuses_stderr_without_publishing_outputs(self) -> None:
        runner = self.mock_runner(stderr=True)
        arguments = self.lane_arguments(runner, "stderr")
        with (
            mock.patch.object(
                lane_runner,
                "validate_host",
                return_value={
                    "architecture": "aarch64",
                    "operating_system": "macos",
                },
            ),
            mock.patch.object(
                seal,
                "validate_runner_artifact",
                side_effect=self.permit_script_artifact,
            ),
            self.assertRaisesRegex(seal.Refusal, "stderr"),
        ):
            lane_runner.run_lane(arguments)
        for field in ("static_output", "correctness_output", "manifest_output"):
            self.assertFalse(os.path.lexists(getattr(arguments, field)))

    def test_staged_runner_detects_inode_or_mode_replacement(self) -> None:
        runner = self.mock_runner()
        staged = lane_runner.stage_runner(self.root, runner.read_bytes())
        try:
            if staged.executable_path is not None:
                os.chmod(staged.directory, 0o700)
                displaced = staged.directory / "displaced-runner"
                staged.executable_path.rename(displaced)
                staged.executable_path.write_bytes(b"#!/bin/sh\nexit 0\n")
                staged.executable_path.chmod(0o500)
                os.chmod(staged.directory, 0o500)
            else:
                os.fchmod(staged.descriptor, 0o700)
            with self.assertRaises(seal.Refusal):
                lane_runner.verify_staged_runner(staged)
        finally:
            lane_runner.close_staged(staged)

    def test_controller_refuses_output_inside_source_worktree(self) -> None:
        runner = self.mock_runner()
        arguments = self.lane_arguments(runner, "inside-source")
        arguments.manifest_output = str(self.source / "manifest.json")
        with self.assertRaisesRegex(seal.Refusal, "outside"):
            lane_runner.run_lane(arguments)

    def test_c9g_host_check_requires_linux_aarch64(self) -> None:
        with (
            mock.patch.object(lane_runner.platform, "system", return_value="Linux"),
            mock.patch.object(lane_runner.platform, "machine", return_value="x86_64"),
            self.assertRaisesRegex(seal.Refusal, "AArch64"),
        ):
            lane_runner.validate_host("c9g")
        with (
            mock.patch.object(lane_runner.platform, "system", return_value="Linux"),
            mock.patch.object(lane_runner.platform, "machine", return_value="aarch64"),
        ):
            self.assertEqual(
                lane_runner.validate_host("c9g"),
                {"architecture": "aarch64", "operating_system": "linux"},
            )


if __name__ == "__main__":
    unittest.main()
