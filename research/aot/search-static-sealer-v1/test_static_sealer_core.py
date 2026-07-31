#!/usr/bin/env python3
"""Adversarial tests for the post-link static evidence sealer."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import static_sealer_core as sealer


def make_policy(root: Path) -> SimpleNamespace:
    source = root / "policy.py"
    source.write_text("# test policy\n", encoding="utf-8")

    def validate_identity_row(
        _platform: str, _authority: object, _label: str
    ) -> None:
        return None

    return SimpleNamespace(
        __file__=str(source),
        AUTHORITY_FIELDS=(
            "platform",
            "runner_identity_sha256",
            "runner_binary_identity_sha256",
            "linked_artifact_identity_sha256",
            "facade_adoption_receipt_identity_sha256",
            "symbol_receipt_identity_sha256",
        ),
        validate_identity_row=validate_identity_row,
    )


def make_spec_and_authority(
    root: Path,
) -> tuple[SimpleNamespace, Path, str, Path]:
    policy = make_policy(root)
    expected_authority = {
        "platform": "test-platform",
        "runner_identity_sha256": "1" * 64,
        "runner_binary_identity_sha256": "6" * 64,
        "linked_artifact_identity_sha256": "6" * 64,
        "facade_adoption_receipt_identity_sha256": "7" * 64,
        "symbol_receipt_identity_sha256": "8" * 64,
    }
    deployment = {
        "expected_authority": expected_authority,
        "platform_key": "macos_aarch64",
        "fixture_manifest_sha256": "2" * 64,
        "identity_sha256": "1" * 64,
        "build_receipt_sha256": "3" * 64,
        "candidate_manifest_sha256": "4" * 64,
        "link_map_sha256": "5" * 64,
        "binary_sha256": "6" * 64,
        "nm_sha256": "9" * 64,
        "execution_identities": {
            "binary": {
                "mechanism": "darwin-suspended-cdhash-v1",
                "cdhash": "a" * 40,
            },
            "nm": {
                "mechanism": "darwin-suspended-cdhash-v1",
                "cdhash": "b" * 40,
            },
        },
        "shard_limits": {
            "maximum_output_bytes": 1024 * 1024,
            "timeout_seconds": 60,
        },
    }
    spec_path = root / "spec.json"
    spec_sha256 = sealer.write_envelope(
        spec_path,
        sealer.SPEC_SCHEMA,
        {
            "policy_source_sha256": sealer.file_sha(Path(policy.__file__)),
            "deployments": {
                "test-scope": {"test-platform": deployment},
            },
        },
    )
    authority_path = root / "authority.json"
    sealer.write_envelope(
        authority_path,
        sealer.AUTHORITY_RECEIPT_SCHEMA,
        {
            "deployment_spec_sha256": spec_sha256,
            "scope": "test-scope",
            "platform": "test-platform",
            "authority": expected_authority,
            "fixture_manifest_sha256": "2" * 64,
            "identity_sha256": "1" * 64,
            "build_receipt_sha256": "3" * 64,
            "candidate_manifest_sha256": "4" * 64,
            "link_map_sha256": "5" * 64,
            "binary_path": str(root / "runner"),
            "binary_sha256": "6" * 64,
            "fixture_root": str(root / "fixtures"),
            "inspect_sha256": expected_authority.get(
                "facade_adoption_receipt_identity_sha256", "7" * 64
            ),
            "symbol_receipt_sha256": expected_authority.get(
                "symbol_receipt_identity_sha256", "8" * 64
            ),
            "binary_execution_identity": deployment[
                "execution_identities"
            ]["binary"],
            "shard_limits": deployment["shard_limits"],
        },
    )
    return policy, spec_path, spec_sha256, authority_path


class StaticSealerTests(unittest.TestCase):
    def test_dependency_lock_is_the_static_runner_lock(self) -> None:
        repo = Path(__file__).resolve().parents[3]
        self.assertEqual(
            sealer.static_runner_dependency_lock(repo),
            (
                repo
                / "research/aot/external-regex-1.12.4/static-runner/Cargo.lock"
            ).resolve(strict=True),
        )

    def test_held_copy_cannot_be_modified_through_returned_descriptor(
        self,
    ) -> None:
        with tempfile.TemporaryFile() as source:
            source.write(b"immutable held input")
            source.flush()
            expected = hashlib.sha256(b"immutable held input").hexdigest()
            descriptor = sealer.sealed_copy_descriptor(
                source.fileno(), expected, executable=False
            )
            try:
                with self.assertRaises(OSError):
                    os.pwrite(descriptor, b"X", 0)
                self.assertEqual(
                    sealer.file_sha_fd(descriptor),
                    expected,
                )
            finally:
                os.close(descriptor)

    @staticmethod
    def darwin_cdhash(path: Path) -> str:
        result = subprocess.run(
            ["/usr/bin/codesign", "-d", "--verbose=4", str(path)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        match = re.search(rb"^CDHash=([0-9a-f]{40})$", result.stderr, re.M)
        if match is None:
            raise AssertionError("codesign did not report one CDHash")
        return match.group(1).decode()

    def test_linux_cpu_identity_ignores_dynamic_counters(self) -> None:
        first = b"""processor : 0
CPU implementer : 0x41
CPU architecture : 8
CPU part : 0xd84
CPU revision : 1
Features : fp asimd sve sve2
BogoMIPS : 100.00
cpu MHz : 2400.00

processor : 1
CPU implementer : 0x41
CPU architecture : 8
CPU part : 0xd84
CPU revision : 1
Features : fp asimd sve sve2
BogoMIPS : 100.00
cpu MHz : 2400.00
"""
        second = first.replace(b"100.00", b"999.00").replace(
            b"2400.00", b"1234.00"
        )
        self.assertEqual(
            sealer.canonical_sha(sealer.stable_linux_cpu_payload(first)),
            sealer.canonical_sha(sealer.stable_linux_cpu_payload(second)),
        )
        changed = second.replace(b"sve sve2", b"sve")
        self.assertNotEqual(
            sealer.canonical_sha(sealer.stable_linux_cpu_payload(first)),
            sealer.canonical_sha(sealer.stable_linux_cpu_payload(changed)),
        )

    def test_source_set_requires_exact_sorted_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "a").mkdir()
            (root / "a" / "one.rs").write_text("one\n", encoding="utf-8")
            (root / "two.rs").write_text("two\n", encoding="utf-8")
            with self.assertRaisesRegex(sealer.Refusal, "exact file"):
                sealer.source_set_sha(root, ["a"], "test")
            with self.assertRaisesRegex(sealer.Refusal, "sorted file list"):
                sealer.source_set_sha(root, ["two.rs", "a/one.rs"], "test")
            self.assertRegex(
                sealer.source_set_sha(
                    root, ["a/one.rs", "two.rs"], "test"
                ),
                r"^[0-9a-f]{64}$",
            )

    def test_regular_resolution_rejects_final_and_intermediate_symlinks(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "real").mkdir()
            (root / "real" / "artifact").write_text(
                "artifact\n", encoding="utf-8"
            )
            (root / "final-link").symlink_to(root / "real" / "artifact")
            (root / "directory-link").symlink_to(root / "real")
            with self.assertRaisesRegex(sealer.Refusal, "symlink"):
                sealer.resolve_regular(root, "final-link")
            with self.assertRaisesRegex(sealer.Refusal, "symlink"):
                sealer.resolve_regular(root, "directory-link/artifact")

    def test_regular_read_uses_held_descriptor_across_path_swap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            path = root / "receipt"
            replacement = root / "replacement"
            path.write_bytes(b"original-authority\n")
            replacement.write_bytes(b"substitute-content\n")
            pread = sealer.os.pread
            swapped = False

            def swap_then_read(
                descriptor: int, count: int, offset: int
            ) -> bytes:
                nonlocal swapped
                if not swapped:
                    swapped = True
                    replacement.replace(path)
                return pread(descriptor, count, offset)

            with mock.patch.object(
                sealer.os, "pread", side_effect=swap_then_read
            ):
                self.assertEqual(
                    sealer.regular_file(path), b"original-authority\n"
                )
            self.assertEqual(path.read_bytes(), b"substitute-content\n")

    @unittest.skipUnless(
        platform.system() == "Darwin", "Darwin CDHash attestation test"
    )
    def test_darwin_path_swap_is_killed_before_substitute_runs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            executable = root / "runner"
            replacement = root / "replacement"
            original = root / "original"
            marker = root / "substitute-ran"
            shutil.copy("/usr/bin/true", executable)
            shutil.copy("/usr/bin/true", original)
            shutil.copy("/usr/bin/touch", replacement)
            expected_sha256 = sealer.file_sha(executable)
            expected_cdhash = self.darwin_cdhash(Path("/usr/bin/true"))
            spawn = sealer.darwin_spawn_suspended

            def swap_before_spawn(**arguments: object) -> int:
                replacement.replace(executable)
                try:
                    return spawn(**arguments)
                finally:
                    original.replace(executable)

            with mock.patch.object(
                sealer,
                "darwin_spawn_suspended",
                side_effect=swap_before_spawn,
            ):
                with self.assertRaisesRegex(
                    sealer.Refusal, "CDHash changed"
                ):
                    sealer.run_sealed(
                        executable=executable,
                        expected_sha256=expected_sha256,
                        expected_execution_identity=sealer.execution_identity(
                            "darwin-suspended-cdhash-v1",
                            expected_cdhash,
                        ),
                        arguments=[str(marker)],
                    )
            self.assertFalse(
                marker.exists(), "substituted executable reached userspace"
            )

    def test_sealed_execution_enforces_output_bound_while_running(
        self,
    ) -> None:
        executable = Path("/usr/bin/yes")
        expected_sha256 = sealer.file_sha(executable)
        if platform.system() == "Darwin":
            identity = sealer.execution_identity(
                "darwin-suspended-cdhash-v1",
                self.darwin_cdhash(executable),
            )
        elif platform.system() == "Linux":
            identity = sealer.execution_identity(
                "linux-sealed-memfd-v1", expected_sha256
            )
        else:
            self.skipTest("sealed execution requires Darwin or Linux")
        with self.assertRaisesRegex(sealer.Refusal, "stdout exceeded"):
            sealer.run_sealed(
                executable=executable,
                expected_sha256=expected_sha256,
                expected_execution_identity=identity,
                arguments=[],
                maximum=1024,
                timeout_seconds=5,
            )

    def test_sealed_execution_reports_one_child_for_lineage(self) -> None:
        executable = Path("/usr/bin/true")
        expected_sha256 = sealer.file_sha(executable)
        if platform.system() == "Darwin":
            identity = sealer.execution_identity(
                "darwin-suspended-cdhash-v1",
                self.darwin_cdhash(executable),
            )
        elif platform.system() == "Linux":
            identity = sealer.execution_identity(
                "linux-sealed-memfd-v1", expected_sha256
            )
        else:
            self.skipTest("sealed execution requires Darwin or Linux")
        children: list[int] = []
        result = sealer.run_sealed(
            executable=executable,
            expected_sha256=expected_sha256,
            expected_execution_identity=identity,
            arguments=[],
            on_spawn=children.append,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(children), 1)
        self.assertGreater(children[0], 0)

    @unittest.skipUnless(
        platform.system() == "Linux", "Linux sealed-memfd execution test"
    )
    def test_linux_path_swap_executes_held_sealed_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            executable = root / "runner"
            replacement = root / "replacement"
            marker = root / "substitute-ran"
            shutil.copy("/usr/bin/true", executable)
            shutil.copy("/usr/bin/touch", replacement)
            expected_sha256 = sealer.file_sha(executable)
            sealed_copy = sealer.sealed_copy_descriptor
            swapped = False

            def swap_after_copy(
                source: int, digest: str, *, executable: bool
            ) -> int:
                nonlocal swapped
                descriptor = sealed_copy(
                    source, digest, executable=executable
                )
                if executable and not swapped:
                    swapped = True
                    replacement.replace(root / "runner")
                return descriptor

            with mock.patch.object(
                sealer,
                "sealed_copy_descriptor",
                side_effect=swap_after_copy,
            ):
                result = sealer.run_sealed(
                    executable=executable,
                    expected_sha256=expected_sha256,
                    expected_execution_identity=sealer.execution_identity(
                        "linux-sealed-memfd-v1", expected_sha256
                    ),
                    arguments=[str(marker)],
                )
            self.assertEqual(result.returncode, 0)
            self.assertTrue(swapped)
            self.assertFalse(marker.exists())

    @unittest.skipUnless(
        platform.system() == "Linux", "Linux sealed-memfd execution test"
    )
    def test_linux_in_place_mutation_cannot_change_executed_bytes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            executable = root / "runner"
            marker = root / "mutated-ran"
            shutil.copy("/usr/bin/true", executable)
            expected_sha256 = sealer.file_sha(executable)
            replacement = Path("/usr/bin/touch").read_bytes()
            sealed_copy = sealer.sealed_copy_descriptor
            mutated = False

            def mutate_after_copy(
                source: int, digest: str, *, executable: bool
            ) -> int:
                nonlocal mutated
                descriptor = sealed_copy(
                    source, digest, executable=executable
                )
                if executable and not mutated:
                    mutated = True
                    with (root / "runner").open("r+b") as output:
                        output.seek(0)
                        output.write(replacement)
                        output.truncate()
                        output.flush()
                return descriptor

            with mock.patch.object(
                sealer,
                "sealed_copy_descriptor",
                side_effect=mutate_after_copy,
            ):
                with self.assertRaisesRegex(
                    sealer.Refusal, "executable changed"
                ):
                    sealer.run_sealed(
                        executable=executable,
                        expected_sha256=expected_sha256,
                        expected_execution_identity=(
                            sealer.execution_identity(
                                "linux-sealed-memfd-v1",
                                expected_sha256,
                            )
                        ),
                        arguments=[str(marker)],
                    )
            self.assertTrue(mutated)
            self.assertFalse(marker.exists())

    @unittest.skipUnless(
        platform.system() == "Linux", "Linux process-group containment test"
    )
    def test_linux_timeout_kills_descendant_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            marker = root / "descendant-survived"
            executable = Path("/bin/sh").resolve(strict=True)
            expected_sha256 = sealer.file_sha(executable)
            command = (
                '(sleep 2; /usr/bin/touch "$1") & '
                "sleep 30"
            )
            with self.assertRaisesRegex(
                sealer.Refusal, "exceeded time bound"
            ):
                sealer.run_sealed(
                    executable=executable,
                    expected_sha256=expected_sha256,
                    expected_execution_identity=sealer.execution_identity(
                        "linux-sealed-memfd-v1", expected_sha256
                    ),
                    arguments=[
                        "-c",
                        command,
                        "fre-static-sealer-test",
                        str(marker),
                    ],
                    timeout_seconds=1,
                )
            time.sleep(1.5)
            self.assertFalse(marker.exists())

    def test_authority_receipt_must_equal_preregistered_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            policy, spec_path, spec_sha256, authority_path = (
                make_spec_and_authority(root)
            )
            sealer.load_authority_receipt(
                authority_path, spec_path, spec_sha256, policy
            )

            forged = json.loads(authority_path.read_text(encoding="utf-8"))
            forged["payload"]["authority"][
                "runner_identity_sha256"
            ] = "9" * 64
            sealer.write_envelope(
                authority_path,
                sealer.AUTHORITY_RECEIPT_SCHEMA,
                forged["payload"],
            )
            with self.assertRaisesRegex(
                sealer.Refusal, "preregistered deployment"
            ):
                sealer.load_authority_receipt(
                    authority_path, spec_path, spec_sha256, policy
                )
            forged = json.loads(authority_path.read_text(encoding="utf-8"))
            forged["payload"]["authority"][
                "runner_identity_sha256"
            ] = "1" * 64
            forged["payload"]["binary_sha256"] = "9" * 64
            sealer.write_envelope(
                authority_path,
                sealer.AUTHORITY_RECEIPT_SCHEMA,
                forged["payload"],
            )
            with self.assertRaisesRegex(
                sealer.Refusal, "preregistered deployment"
            ):
                sealer.load_authority_receipt(
                    authority_path, spec_path, spec_sha256, policy
                )

    def test_shard_launch_refuses_existing_output_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            policy, spec_path, spec_sha256, authority_path = (
                make_spec_and_authority(root)
            )
            raw = root / "raw.csv"
            raw.write_text("do-not-overwrite\n", encoding="utf-8")
            with self.assertRaisesRegex(sealer.Refusal, "already exist"):
                sealer.run_shard(
                    policy=policy,
                    spec_path=spec_path,
                    expected_spec_sha256=spec_sha256,
                    authority_receipt_path=authority_path,
                    shard="0",
                    shards="1",
                    raw_output=raw,
                    shard_receipt_output=root / "shard.json",
                )
            self.assertEqual(
                raw.read_text(encoding="utf-8"), "do-not-overwrite\n"
            )

    def test_shard_set_requires_complete_unique_authenticated_raw_files(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            policy, spec_path, spec_sha256, authority_path = (
                make_spec_and_authority(root)
            )
            _, authority_sha256 = sealer.load_authority_receipt(
                authority_path, spec_path, spec_sha256, policy
            )

            def write_shard(
                coordinate: int, raw: Path, output: Path
            ) -> None:
                sealer.write_envelope(
                    output,
                    sealer.SHARD_RECEIPT_SCHEMA,
                    {
                        "deployment_spec_sha256": spec_sha256,
                        "authority_receipt_path": str(authority_path),
                        "authority_receipt_sha256": authority_sha256,
                        "scope": "test-scope",
                        "platform": "test-platform",
                        "fixture_manifest_sha256": "2" * 64,
                        "binary_sha256_before": "6" * 64,
                        "binary_sha256_after": "6" * 64,
                        "shard": coordinate,
                        "shards": 2,
                        "raw_path": str(raw),
                        "raw_sha256": sealer.file_sha(raw),
                    },
                )

            raw_zero = root / "raw-zero.csv"
            raw_one = root / "raw-one.csv"
            raw_zero.write_text("zero\n", encoding="utf-8")
            raw_one.write_text("one\n", encoding="utf-8")
            shard_zero = root / "shard-zero.json"
            shard_one = root / "shard-one.json"
            write_shard(0, raw_zero, shard_zero)
            write_shard(1, raw_one, shard_one)
            with self.assertRaisesRegex(sealer.Refusal, "incomplete"):
                sealer.authenticate_shard_receipts(
                    [shard_zero], spec_path, spec_sha256, policy
                )
            authority, paths = sealer.authenticate_shard_receipts(
                [shard_zero, shard_one], spec_path, spec_sha256, policy
            )
            self.assertEqual(authority["scope"], "test-scope")
            self.assertEqual(
                paths, [raw_zero.resolve(), raw_one.resolve()]
            )

            raw_one.write_text("mutated\n", encoding="utf-8")
            with self.assertRaisesRegex(sealer.Refusal, "raw CSV changed"):
                sealer.authenticate_shard_receipts(
                    [shard_zero, shard_one],
                    spec_path,
                    spec_sha256,
                    policy,
                )
            raw_one.write_text("one\n", encoding="utf-8")
            write_shard(1, raw_zero, shard_one)
            with self.assertRaisesRegex(sealer.Refusal, "path is duplicated"):
                sealer.authenticate_shard_receipts(
                    [shard_zero, shard_one],
                    spec_path,
                    spec_sha256,
                    policy,
                )

    def test_envelope_payload_tampering_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / "receipt.json"
            sealer.write_envelope(path, "test.schema", {"value": 1})
            root = json.loads(path.read_text(encoding="utf-8"))
            root["payload"]["value"] = 2
            path.write_text(json.dumps(root), encoding="utf-8")
            with self.assertRaisesRegex(sealer.Refusal, "envelope changed"):
                sealer.load_envelope(path, "test.schema")


if __name__ == "__main__":
    unittest.main()
