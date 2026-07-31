#!/usr/bin/env python3

import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

import analyze_v26_gate as gate
import launch_v26_gate_once as launch
import seal_v26_gate as seal


class SealAndLaunchTests(unittest.TestCase):
    @staticmethod
    def initialize_repository(repository: Path) -> None:
        subprocess.run(["git", "init", "-q", str(repository)], check=True)
        subprocess.run(
            ["git", "-C", str(repository), "config", "user.email", "gate@test.invalid"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(repository), "config", "user.name", "Gate Test"],
            check=True,
        )

    def test_create_new_publication_is_read_only_and_never_replaces(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "sealed.json"
            seal.publish_bytes_create_new(output, b'{"value":1}\n')
            self.assertEqual(output.read_bytes(), b'{"value":1}\n')
            self.assertFalse(output.stat().st_mode & 0o222)
            with self.assertRaises(gate.GateError):
                seal.publish_bytes_create_new(output, b'{"value":2}\n')
            self.assertEqual(output.read_bytes(), b'{"value":1}\n')

    def test_contract_finalization_only_fills_seal_placeholders(self) -> None:
        draft_path = Path(__file__).with_name("gate-contract-v1.json")
        draft = json.loads(draft_path.read_text(encoding="utf-8"))
        finalized = seal.finalize_contract(
            draft,
            "1" * 40,
            "2" * 40,
            "3" * 64,
            "one-shot-seal-v1.json",
        )
        self.assertEqual(finalized["status"], "SEALED_READY_FOR_ONE_SHOT_TIMING")
        self.assertEqual(finalized["candidate"]["source_commit"], "1" * 40)
        self.assertEqual(finalized["candidate"]["source_tree"], "2" * 40)
        self.assertEqual(finalized["inputs"]["cell_manifest_sha256"], "3" * 64)
        self.assertNotIn("AWAITING_", json.dumps(finalized))
        self.assertIn("AWAITING_", json.dumps(draft))

    def test_git_archive_is_created_from_the_exact_commit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repo"
            repository.mkdir()
            self.initialize_repository(repository)
            (repository / "payload.txt").write_text("frozen\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repository), "add", "payload.txt"], check=True)
            subprocess.run(
                ["git", "-C", str(repository), "commit", "-q", "-m", "fixture"],
                check=True,
            )
            commit = seal.git_object_id(repository, "HEAD^{commit}", "commit")
            tree = seal.git_object_id(repository, f"{commit}^{{tree}}", "tree")
            self.assertEqual(len(commit), 40)
            self.assertEqual(len(tree), 40)
            archive = root / "source.tar"
            archive_file = seal.publish_git_archive(repository, commit, tree, archive)
            self.assertGreater(len(archive_file.data), 0)
            self.assertFalse(archive.stat().st_mode & 0o222)
            listing = subprocess.run(
                ["tar", "-tf", str(archive)],
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            ).stdout.splitlines()
            self.assertIn("payload.txt", listing)

    def test_archive_source_set_accepts_git_directories_and_binds_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repo"
            repository.mkdir()
            self.initialize_repository(repository)
            files = {
                "Cargo.toml": "[workspace]\n",
                "rust-toolchain.toml": "[toolchain]\nchannel = \"stable\"\n",
                ".cargo/config.toml": "[build]\nincremental = false\n",
                "crates/example/src/lib.rs": "pub fn example() {}\n",
                (
                    "research/aot/search-v26-width-cost-rule-r1/"
                    "synthetic-runner/src/lib.rs"
                ): "pub fn synthetic() {}\n",
                (
                    "research/aot/search-v26-width-cost-rule-r1/"
                    "development-gate/runner/src/lib.rs"
                ): "pub fn runner() {}\n",
            }
            for relative, contents in files.items():
                path = repository / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents, encoding="utf-8")
            preregistration = (
                Path(__file__).parent.parent / "preregistration-v1.json"
            ).read_bytes()
            preregistration_path = (
                repository
                / "research/aot/search-v26-width-cost-rule-r1/preregistration-v1.json"
            )
            preregistration_path.parent.mkdir(parents=True, exist_ok=True)
            preregistration_path.write_bytes(preregistration)
            subprocess.run(["git", "-C", str(repository), "add", "."], check=True)
            subprocess.run(
                ["git", "-C", str(repository), "commit", "-q", "-m", "sources"],
                check=True,
            )
            commit = seal.git_object_id(repository, "HEAD^{commit}", "commit")
            tree = seal.git_object_id(repository, f"{commit}^{{tree}}", "tree")
            first_path = root / "first.tar"
            first = seal.publish_git_archive(repository, commit, tree, first_path)
            first_source_set = gate.archive_runner_source_set_sha256(first)
            self.assertEqual(len(first_source_set), 64)
            with tarfile.open(first_path, "r:") as archive:
                self.assertTrue(any(member.isdir() for member in archive))

            changed = repository / "crates/example/src/lib.rs"
            changed.write_text("pub fn example() { assert!(true); }\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repository), "add", "."], check=True)
            subprocess.run(
                ["git", "-C", str(repository), "commit", "-q", "-m", "changed"],
                check=True,
            )
            second_commit = seal.git_object_id(repository, "HEAD^{commit}", "commit")
            second_tree = seal.git_object_id(
                repository, f"{second_commit}^{{tree}}", "tree"
            )
            second = seal.publish_git_archive(
                repository, second_commit, second_tree, root / "second.tar"
            )
            self.assertNotEqual(
                first_source_set, gate.archive_runner_source_set_sha256(second)
            )

    def test_launcher_requires_exactly_three_distinct_cpu_ids(self) -> None:
        self.assertEqual(launch.require_cpu_ids([120, 130, 140]), [120, 130, 140])
        for values in ([120, 130], [120, 120, 140], [120, 130, 140, 150]):
            with self.assertRaises(gate.GateError):
                launch.require_cpu_ids(list(values))
        with self.assertRaises(gate.GateError):
            launch.require_cpu_ids([True, 130, 140])

    def test_host_fingerprint_is_canonical_and_sensitive(self) -> None:
        components = {
            "schema": "fre-search-v26-development-gate-host-fingerprint-input-v1",
            "system": "Linux",
            "node": "c9g",
            "release": "one",
            "version": "two",
            "machine": "aarch64",
            "machine_id_sha256": "1" * 64,
            "cpuinfo_sha256": "2" * 64,
            "online_cpus_sha256": "3" * 64,
        }
        first = launch.host_fingerprint_sha256(components)
        second = launch.host_fingerprint_sha256(dict(reversed(components.items())))
        self.assertEqual(first, second)
        mutated = dict(components)
        mutated["machine"] = "x86_64"
        self.assertNotEqual(first, launch.host_fingerprint_sha256(mutated))

    def test_consumed_marker_enforces_create_new_one_shot_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            registry = Path(directory).resolve()
            marker = launch.consume_seal_once(
                registry,
                "1" * 64,
                "2" * 64,
                "3" * 64,
                "4" * 64,
                "5" * 64,
            )
            self.assertEqual(
                marker, registry / f"{'1' * 64}.consumed-v1.json"
            )
            self.assertTrue(marker.exists())
            self.assertFalse(marker.stat().st_mode & 0o222)
            with self.assertRaises(gate.GateError):
                launch.consume_seal_once(
                    registry,
                    "1" * 64,
                    "2" * 64,
                    "3" * 64,
                    "4" * 64,
                    "5" * 64,
                )

    def test_launcher_has_no_load_wait_or_kill_path(self) -> None:
        source = Path(launch.__file__).read_text(encoding="utf-8")
        self.assertNotIn("loadavg", source)
        self.assertNotIn(".kill(", source)
        self.assertNotIn(".terminate(", source)
        self.assertNotIn("resource-coordinator", source)


if __name__ == "__main__":
    unittest.main()
