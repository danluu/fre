#!/usr/bin/env python3
"""Focused orchestration tests for resumable formal census qualification."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import formal_qualification as DRIVER  # noqa: E402
import true_native_census as CENSUS  # noqa: E402
from test_true_native_census import synthetic_plan  # noqa: E402


class FormalQualificationTests(unittest.TestCase):
    def test_plan_target_must_match_the_native_host(self) -> None:
        plan = synthetic_plan()
        self.assertEqual(plan["target"]["triple"], "aarch64-linux")
        with (
            mock.patch.object(DRIVER, "native_host_target", return_value="x86_64-linux"),
            self.assertRaisesRegex(DRIVER.DriverError, "differs from native host"),
        ):
            DRIVER.require_native_target(plan)

    def test_build_contract_is_offline_locked_single_job_and_environment_is_closed(self) -> None:
        plan = synthetic_plan()
        job = plan["jobs"][33]
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "fixture.klv").write_bytes(b"x")
            job["candidate_klv"] = {
                "path": "fixture.klv",
                "sha256": CENSUS.sha_bytes(b"x"),
                "bytes": 1,
            }
            target = root / "target"
            with mock.patch.dict(os.environ, {
                "PATH": "/formal/bin",
                "HOME": "/formal/home",
                "FRE_AOT_REBAR_EXPECTED_VALUE": "999",
                "FRE_AOT_REBAR_PRIVATE_QUERY": "must-not-leak",
                "RUSTFLAGS": "hostile-flags",
                "LD_PRELOAD": "/hostile/preload.so",
                "DYLD_INSERT_LIBRARIES": "/hostile/inject.dylib",
                "AWS_SECRET_ACCESS_KEY": "must-not-leak",
            }, clear=True):
                environment = DRIVER.controlled_build_environment(
                    plan, job, root, target, "/tool/rustc",
                    "aarch64-unknown-linux-gnu",
                )
                runtime_environment = DRIVER.controlled_runtime_environment()
        self.assertEqual(DRIVER.build_command(
            "/tool/cargo", "aarch64-unknown-linux-gnu"
        ), [
            "/tool/cargo", "build", "--release", "--locked", "--offline",
            "--jobs", "1", "--target", "aarch64-unknown-linux-gnu",
            "--package", "fre-aot-rebar-runner",
        ])
        self.assertEqual(environment["CARGO_INCREMENTAL"], "0")
        self.assertEqual(environment["CARGO_NET_OFFLINE"], "true")
        self.assertEqual(environment["CARGO_PROFILE_RELEASE_DEBUG"], "0")
        self.assertEqual(environment["CARGO_BUILD_TARGET"], "aarch64-unknown-linux-gnu")
        self.assertEqual(environment["RUSTC"], "/tool/rustc")
        self.assertEqual(environment["FRE_AOT_REBAR_EXPECTED_VALUE"], "1")
        self.assertEqual(
            environment["FRE_AOT_REBAR_EXPECTED_COMPARATOR"],
            "rust-regex-1.12.4",
        )
        self.assertEqual(
            environment["RUSTFLAGS"],
            "-C debuginfo=0 -C link-arg=-Wl,--export-dynamic",
        )
        self.assertNotIn("FRE_AOT_REBAR_PRIVATE_QUERY", environment)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", environment)
        self.assertNotIn("LD_PRELOAD", environment)
        self.assertNotIn("DYLD_INSERT_LIBRARIES", environment)
        for name in (
            "FRE_AOT_REBAR_PRIVATE_QUERY", "RUSTFLAGS", "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES", "AWS_SECRET_ACCESS_KEY",
        ):
            self.assertNotIn(name, runtime_environment)

    def test_rust_target_normalization_is_closed(self) -> None:
        self.assertEqual(
            DRIVER.normalized_rust_target("x86_64-unknown-linux-gnu"),
            "x86_64-linux",
        )
        self.assertEqual(
            DRIVER.normalized_rust_target("aarch64-apple-darwin"),
            "aarch64-macos",
        )
        with self.assertRaisesRegex(DRIVER.DriverError, "not a supported"):
            DRIVER.normalized_rust_target("riscv64gc-unknown-linux-gnu")

    def test_object_preservation_is_ordered_nonempty_and_byte_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            runner = root / "runner"
            runner.write_bytes(b"runner-bytes")
            first = root / "row-10.o"
            second = root / "row-2.o"
            first.write_bytes(b"first-object")
            second.write_bytes(b"second-object")
            preserved_runner, preserved = DRIVER.preserve_build(
                runner, [first, second], root / "preserved"
            )
            self.assertEqual(preserved_runner.read_bytes(), b"runner-bytes")
            self.assertEqual(
                [path.read_bytes() for path in preserved],
                [b"first-object", b"second-object"],
            )
            self.assertTrue(preserved[0].name.startswith("object-0000-"))
            self.assertTrue(preserved[1].name.startswith("object-0001-"))

            empty = root / "empty.o"
            empty.write_bytes(b"")
            with self.assertRaisesRegex(DRIVER.DriverError, "empty"):
                DRIVER.preserve_build(runner, [empty], root / "rejected")

    def test_artifact_manifest_rehashes_preserved_files_on_resume(self) -> None:
        plan = synthetic_plan()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            job = plan["jobs"][33]
            artifacts = root / "artifacts"
            artifacts.mkdir()
            attempt = DRIVER.next_attempt_dir(artifacts, 0, job["job_id"])
            runner = root / "runner"
            first = root / "first.o"
            second = root / "second.o"
            runner.write_bytes(b"runner")
            first.write_bytes(b"first")
            second.write_bytes(b"second")
            primary_runner, primary_objects = DRIVER.preserve_build(
                runner, [first, second], attempt / "primary"
            )
            replica_runner, replica_objects = DRIVER.preserve_build(
                runner, [first, second], attempt / "replica"
            )
            def artifact_claim(
                preserved_runner: pathlib.Path, objects: list[pathlib.Path]
            ) -> dict[str, object]:
                return {
                    "runner_sha256": CENSUS.sha_file(preserved_runner),
                    "objects": [
                        {
                            "ordinal": ordinal,
                            "sha256": CENSUS.sha_file(path),
                            "bytes": path.stat().st_size,
                        }
                        for ordinal, path in enumerate(objects)
                    ],
                }

            receipt = {
                "receipt_sha256": "a" * 64,
                "job": {"job_id": job["job_id"]},
                "artifacts": {
                    "primary": artifact_claim(primary_runner, primary_objects),
                    "replica": artifact_claim(replica_runner, replica_objects),
                },
            }
            DRIVER.write_artifact_manifest(
                attempt, receipt, plan, primary_runner, primary_objects,
                replica_runner, replica_objects,
            )
            indexed = {job["job_id"]: (root / "receipt.json", receipt)}
            DRIVER.audit_preserved_artifacts(artifacts, indexed, plan)

            attempt.chmod(0o700)
            relocated_primary = attempt / "primary-real"
            (attempt / "primary").rename(relocated_primary)
            (attempt / "primary").symlink_to(attempt / "replica", target_is_directory=True)
            attempt.chmod(0o500)
            with self.assertRaisesRegex(DRIVER.DriverError, "symbolic-link"):
                DRIVER.audit_preserved_artifacts(artifacts, indexed, plan)
            attempt.chmod(0o700)
            (attempt / "primary").unlink()
            relocated_primary.rename(attempt / "primary")
            attempt.chmod(0o500)

            primary_objects[0].chmod(0o600)
            primary_objects[0].write_bytes(b"forged")
            primary_objects[0].chmod(0o400)
            with self.assertRaisesRegex(DRIVER.DriverError, "content differs"):
                DRIVER.audit_preserved_artifacts(artifacts, indexed, plan)

    def test_state_binds_trap_cargo_and_nm_file_bytes(self) -> None:
        plan = synthetic_plan()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source = root / "source"
            public = root / "public"
            primary = root / "primary"
            replica = root / "replica"
            receipts = root / "receipts"
            artifacts = root / "artifacts"
            for directory in (
                source, public, primary, replica, receipts, artifacts,
            ):
                directory.mkdir()
            trap = root / "trap.so"
            cargo = root / "cargo"
            nm = root / "nm"
            rustc = root / "rustc"
            git = root / "git"
            trap.write_bytes(b"trap-v1")
            cargo.write_bytes(b"cargo-v1")
            nm.write_bytes(b"nm-v1")
            rustc.write_bytes(b"rustc-v1")
            git.write_bytes(b"git-v1")
            cargo.chmod(0o500)
            nm.chmod(0o500)
            rustc.chmod(0o500)
            git.chmod(0o500)
            state = DRIVER.state_record(
                plan, source, public, primary, replica, receipts, artifacts,
                trap, str(cargo), str(rustc), str(nm), str(git),
                "aarch64-unknown-linux-gnu", 10, 20,
            )
            DRIVER.verify_bound_inputs(state)
            changed_timeout = DRIVER.state_record(
                plan, source, public, primary, replica, receipts, artifacts,
                trap, str(cargo), str(rustc), str(nm), str(git),
                "aarch64-unknown-linux-gnu", 11, 20,
            )
            self.assertNotEqual(state, changed_timeout)
            with mock.patch.dict(
                os.environ, {"CARGO_HOME": str(root / "other-cargo")}
            ):
                changed_environment = DRIVER.state_record(
                    plan, source, public, primary, replica, receipts, artifacts,
                    trap, str(cargo), str(rustc), str(nm), str(git),
                    "aarch64-unknown-linux-gnu", 10, 20,
                )
            self.assertNotEqual(state, changed_environment)
            trap.write_bytes(b"trap-v2")
            with self.assertRaisesRegex(DRIVER.DriverError, "trap_library content changed"):
                DRIVER.verify_bound_inputs(state)

    def test_timeout_is_sealed_as_timeout_not_generic_failure(self) -> None:
        timeout = subprocess.TimeoutExpired(["cargo"], 1)
        self.assertEqual(DRIVER.failure_outcome(timeout), "timeout")
        self.assertEqual(DRIVER.failure_outcome(OSError("failure")), "failure")
        process = mock.Mock(pid=4242, returncode=-15)
        process.communicate.side_effect = [
            subprocess.TimeoutExpired(["cargo"], 1, output=b"partial"),
            (b"partial", None),
        ]
        with (
            mock.patch.object(DRIVER.subprocess, "Popen", return_value=process) as popen,
            mock.patch.object(DRIVER.os, "getpgid", return_value=4242),
            mock.patch.object(DRIVER.os, "killpg") as killpg,
        ):
            ok, outcome, output_evidence = DRIVER.run_build(
                "/tool/cargo", "aarch64-unknown-linux-gnu",
                pathlib.Path("/source"), {}, 1
            )
        self.assertFalse(ok)
        self.assertEqual(outcome, "timeout")
        self.assertEqual(output_evidence, (CENSUS.sha_bytes(b"partial"), 7))
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        killpg.assert_called_once_with(4242, DRIVER.signal.SIGTERM)

        alien = mock.Mock(pid=5151, returncode=None)
        alien.communicate.side_effect = subprocess.TimeoutExpired(["cargo"], 1)
        with (
            mock.patch.object(DRIVER.subprocess, "Popen", return_value=alien),
            mock.patch.object(DRIVER.os, "getpgid", return_value=9999),
            mock.patch.object(DRIVER.os, "killpg") as alien_killpg,
            self.assertRaisesRegex(DRIVER.DriverError, "owned process group"),
        ):
            DRIVER.run_build(
                "/tool/cargo", "aarch64-unknown-linux-gnu",
                pathlib.Path("/source"), {}, 1
            )
        alien_killpg.assert_not_called()

    def test_new_driver_refuses_nonempty_or_shared_target_directories(self) -> None:
        plan = synthetic_plan()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source = root / "source"
            source.mkdir()
            public = root / "public"
            public.mkdir()
            trap = root / "trap.so"
            trap.write_bytes(b"trap")
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            occupied = root / "occupied-target"
            occupied.mkdir()
            (occupied / "user-owned").write_text("keep", encoding="utf-8")
            arguments = argparse.Namespace(
                plan=str(plan_path),
                source_dir=str(source),
                public_klv_root=str(public),
                work_dir=str(root / "work"),
                primary_target_dir=str(occupied),
                replica_target_dir=str(root / "replica"),
                trap_library=str(trap),
                cargo="cargo",
                rustc="rustc",
                nm="nm",
                git="git",
                build_timeout=1,
                timeout=1,
            )
            with (
                mock.patch.object(DRIVER, "source_recheck"),
                mock.patch.object(DRIVER, "require_native_target"),
                mock.patch.object(
                    DRIVER, "resolve_rust_tool", return_value=sys.executable
                ),
                mock.patch.object(
                    DRIVER, "rustc_host_target",
                    return_value="aarch64-unknown-linux-gnu",
                ),
                mock.patch.object(DRIVER, "resolve_executable", return_value="/bin/true"),
                self.assertRaisesRegex(DRIVER.DriverError, "not empty"),
            ):
                DRIVER.run(arguments)

            arguments.primary_target_dir = str(root / "shared")
            arguments.replica_target_dir = str(root / "shared")
            with (
                mock.patch.object(DRIVER, "source_recheck"),
                mock.patch.object(DRIVER, "require_native_target"),
                mock.patch.object(
                    DRIVER, "resolve_rust_tool", return_value=sys.executable
                ),
                mock.patch.object(
                    DRIVER, "rustc_host_target",
                    return_value="aarch64-unknown-linux-gnu",
                ),
                mock.patch.object(DRIVER, "resolve_executable", return_value="/bin/true"),
                self.assertRaisesRegex(DRIVER.DriverError, "distinct"),
            ):
                DRIVER.run(arguments)

    def test_resume_revalidates_receipts_without_building_and_summarizes_exact_311(self) -> None:
        plan = synthetic_plan()
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            source = root / "source"
            source.mkdir()
            public = root / "public"
            public.mkdir()
            trap = root / "trap.so"
            trap.write_bytes(b"trap")
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            work = root / "work"
            receipts = work / "receipts"
            artifacts = work / "artifacts"
            receipts.mkdir(parents=True)
            artifacts.mkdir()
            primary = root / "primary"
            replica = root / "replica"
            primary.mkdir()
            replica.mkdir()
            jobs = {job["job_id"]: job for job in plan["jobs"]}
            runtime_ids = plan["denominators"]["runtime_jobs"]["ids"]
            for ordinal, job_id in enumerate(runtime_ids):
                if not jobs[job_id]["exact_adapter"]:
                    continue
                receipt = CENSUS.record_failure(argparse.Namespace(
                    plan=str(plan_path),
                    job_id=job_id,
                    stage="build",
                    outcome="failure",
                    evidence_sha256=None,
                    evidence_bytes=None,
                ))
                receipt_name = (
                    "arbitrary-resume-name.json" if ordinal == 0
                    else DRIVER.receipt_filename(ordinal, job_id)
                )
                (receipts / receipt_name).write_text(
                    json.dumps(receipt), encoding="utf-8"
                )
            state = DRIVER.state_record(
                plan, source.resolve(), public.resolve(), primary.resolve(),
                replica.resolve(), receipts.resolve(), artifacts.resolve(),
                trap.resolve(), sys.executable, sys.executable, sys.executable,
                sys.executable, "aarch64-unknown-linux-gnu", 1, 1,
            )
            (work / "qualification-state.json").write_text(
                json.dumps(state), encoding="utf-8"
            )
            arguments = argparse.Namespace(
                plan=str(plan_path),
                source_dir=str(source),
                public_klv_root=str(public),
                work_dir=str(work),
                primary_target_dir=str(primary),
                replica_target_dir=str(replica),
                trap_library=str(trap),
                cargo="cargo",
                rustc="rustc",
                nm="nm",
                git="git",
                build_timeout=1,
                timeout=1,
            )
            with (
                mock.patch.object(DRIVER, "source_recheck"),
                mock.patch.object(DRIVER, "require_native_target"),
                mock.patch.object(
                    DRIVER, "resolve_rust_tool", return_value=sys.executable
                ),
                mock.patch.object(
                    DRIVER, "rustc_host_target",
                    return_value="aarch64-unknown-linux-gnu",
                ),
                mock.patch.object(
                    DRIVER, "resolve_executable", return_value=sys.executable
                ),
                mock.patch.object(DRIVER, "run_build") as run_build,
            ):
                summary = DRIVER.run(arguments)
                repeated = DRIVER.run(arguments)
            run_build.assert_not_called()
            self.assertEqual(summary, repeated)
            self.assertEqual(summary["canonical_runtime_denominator"]["count"], 311)
            self.assertEqual(summary["disposition_counts"], {
                "build-failure": 310,
                "unsupported-no-exact-adapter": 1,
            })
            self.assertEqual(len(list(receipts.glob("*.json"))), 310)
            self.assertEqual(
                CENSUS.load_json(work / "summary.json")["summary_sha256"],
                summary["summary_sha256"],
            )


if __name__ == "__main__":
    unittest.main()
