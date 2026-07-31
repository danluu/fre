#!/usr/bin/env python3

import errno
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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
        self.assertNotIn("os.kill(", source)
        self.assertNotIn("os.killpg(", source)
        self.assertNotIn("resource-coordinator", source)
        self.assertIn("pidfd_send_signal", source)

    def test_partial_launch_failure_supervises_started_child_and_closes_slots(
        self,
    ) -> None:
        first_process = mock.Mock()
        with (
            mock.patch.object(
                launch, "reserve_pidfd_slots", return_value=[71, 72, 73]
            ),
            mock.patch.object(
                launch,
                "supervision_pipe",
                side_effect=[(81, 82), (83, 84)],
            ),
            mock.patch.object(
                launch.subprocess,
                "Popen",
                side_effect=[first_process, OSError("synthetic launch failure")],
            ),
            mock.patch.object(launch, "open_child_pidfd", return_value=91),
            mock.patch.object(
                launch, "supervise_children", return_value=[(0, 0)]
            ) as supervise,
            mock.patch.object(launch.os, "close") as close,
        ):
            with self.assertRaises(gate.GateError):
                launch.run_shard_phase(
                    "preflight",
                    taskset_descriptor=10,
                    runner_descriptor=11,
                    cpu_ids=[120, 130, 140],
                    seal_path=Path("/seal"),
                    contract_path=Path("/contract"),
                    cells_path=Path("/cells"),
                    run_manifest_path=Path("/manifest"),
                    output_paths=[
                        Path("/output-0"),
                        Path("/output-1"),
                        Path("/output-2"),
                    ],
                )
        self.assertEqual(
            supervise.call_args.args[1],
            [(0, first_process, 91)],
        )
        close.assert_any_call(71)
        close.assert_any_call(72)
        close.assert_any_call(82)
        close.assert_any_call(83)
        close.assert_any_call(84)

    def test_pidfd_open_failure_closes_barrier_and_reaps_unreleased_child(
        self,
    ) -> None:
        process = mock.Mock()
        process.wait.return_value = 2
        with (
            mock.patch.object(
                launch, "reserve_pidfd_slots", return_value=[71, 72, 73]
            ),
            mock.patch.object(launch, "supervision_pipe", return_value=(81, 82)),
            mock.patch.object(launch.subprocess, "Popen", return_value=process),
            mock.patch.object(
                launch,
                "open_child_pidfd",
                side_effect=gate.GateError("synthetic pidfd failure"),
            ),
            mock.patch.object(
                launch, "supervise_children", return_value=[]
            ) as supervise,
            mock.patch.object(launch.os, "close") as close,
        ):
            with self.assertRaises(gate.GateError):
                launch.run_shard_phase(
                    "preflight",
                    taskset_descriptor=10,
                    runner_descriptor=11,
                    cpu_ids=[120, 130, 140],
                    seal_path=Path("/seal"),
                    contract_path=Path("/contract"),
                    cells_path=Path("/cells"),
                    run_manifest_path=Path("/manifest"),
                    output_paths=[
                        Path("/output-0"),
                        Path("/output-1"),
                        Path("/output-2"),
                    ],
                )
        close.assert_any_call(81)
        close.assert_any_call(82)
        process.wait.assert_called_once_with(
            timeout=launch.OWN_CHILD_TERM_GRACE_SECONDS
        )
        self.assertEqual(supervise.call_args.args[1], [])

    def test_all_three_pidfds_bind_before_any_shard_is_released(self) -> None:
        processes = [mock.Mock(), mock.Mock(), mock.Mock()]
        events: list[str] = []

        def popen(*_args: object, **_kwargs: object) -> mock.Mock:
            ordinal = len([event for event in events if event.startswith("spawn")])
            events.append(f"spawn-{ordinal}")
            return processes[ordinal]

        def release(writer: int) -> None:
            events.append(f"release-{writer}")

        with (
            mock.patch.object(
                launch, "reserve_pidfd_slots", return_value=[71, 72, 73]
            ),
            mock.patch.object(
                launch,
                "supervision_pipe",
                side_effect=[(81, 82), (83, 84), (85, 86)],
            ),
            mock.patch.object(launch.subprocess, "Popen", side_effect=popen),
            mock.patch.object(
                launch, "open_child_pidfd", side_effect=[91, 92, 93]
            ),
            mock.patch.object(
                launch, "release_startup_barrier", side_effect=release
            ),
            mock.patch.object(
                launch,
                "supervise_children",
                return_value=[(0, 0), (1, 0), (2, 0)],
            ) as supervise,
            mock.patch.object(launch.os, "close"),
        ):
            launch.run_shard_phase(
                "preflight",
                taskset_descriptor=10,
                runner_descriptor=11,
                cpu_ids=[120, 130, 140],
                seal_path=Path("/seal"),
                contract_path=Path("/contract"),
                cells_path=Path("/cells"),
                run_manifest_path=Path("/manifest"),
                output_paths=[
                    Path("/output-0"),
                    Path("/output-1"),
                    Path("/output-2"),
                ],
            )
        self.assertEqual(
            events,
            [
                "spawn-0",
                "spawn-1",
                "spawn-2",
                "release-82",
                "release-84",
                "release-86",
            ],
        )
        self.assertEqual(
            supervise.call_args.args[1],
            [
                (0, processes[0], 91),
                (1, processes[1], 92),
                (2, processes[2], 93),
            ],
        )

    def test_deadline_escalation_uses_only_captured_pidfd(self) -> None:
        process = mock.Mock()
        process.poll.return_value = None
        with (
            mock.patch.object(
                launch,
                "wait_until",
                side_effect=[None, 0, 0],
            ),
            mock.patch.object(
                launch.signal,
                "pidfd_send_signal",
                create=True,
            ) as send_signal,
            mock.patch.object(launch.os, "close") as close,
        ):
            with self.assertRaisesRegex(
                gate.GateError,
                "one-shot authority remains consumed",
            ):
                launch.supervise_children(
                    "timing shards",
                    [(0, process, 444)],
                    1.0,
                    consumed_attempt=True,
                )
        self.assertEqual(
            send_signal.call_args_list,
            [
                mock.call(444, launch.signal.SIGTERM, None, 0),
                mock.call(444, launch.signal.SIGKILL, None, 0),
            ],
        )
        close.assert_called_once_with(444)

    def test_analyzer_uses_explicit_sealed_path_not_magic_file(self) -> None:
        source = Path(gate.__file__).read_text(encoding="utf-8")
        analyze_body = source.split("def analyze_paths(", 1)[1].split(
            "\ndef parse_args()", 1
        )[0]
        self.assertIn(
            "analyzer_file = stable_read(analyzer_path, MAX_CONTRACT_BYTES)",
            analyze_body,
        )
        self.assertNotIn("stable_read(Path(__file__)", analyze_body)

    @unittest.skipUnless(
        sys.platform.startswith("linux") and Path("/proc/self/fd").is_dir(),
        "Linux proc-fd semantics",
    )
    def test_procfd_magic_link_is_rejected_by_stable_read_flags(self) -> None:
        descriptor = os.open(gate.__file__, os.O_RDONLY)
        try:
            procfd_path = f"/proc/self/fd/{descriptor}"
            with self.assertRaises(OSError) as raised:
                os.open(
                    procfd_path,
                    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                )
            self.assertEqual(raised.exception.errno, errno.ELOOP)
        finally:
            os.close(descriptor)

    def test_analyzer_supervision_barrier_accepts_only_one_marker_byte(self) -> None:
        reader, writer = os.pipe()
        os.write(writer, b"\x01")
        os.close(writer)
        gate.await_pidfd_supervision(reader)

        reader, writer = os.pipe()
        os.close(writer)
        with self.assertRaises(gate.GateError):
            gate.await_pidfd_supervision(reader)


if __name__ == "__main__":
    unittest.main()
