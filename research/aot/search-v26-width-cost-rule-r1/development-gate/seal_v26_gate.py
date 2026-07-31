#!/usr/bin/env python3
"""Finalize immutable Search V26 inputs and create one-shot timing authority.

This program performs no regex execution and no timing. It creates a Git
archive directly from the named commit, proves that commit's tree, finalizes a
copy of the result-blind contract, and seals every executable/input identity.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path
from typing import Any

import analyze_v26_gate as gate

GIT_EXECUTABLE = "/usr/bin/git"


def canonical_json_bytes(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("utf-8")


def sync_parent(path: Path) -> None:
    parent = path.parent if path.parent != Path("") else Path(".")
    descriptor = os.open(parent, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_bytes_create_new(path: Path, data: bytes, mode: int = 0o444) -> None:
    if path.exists():
        raise gate.GateError(f"refusing to replace existing output {path}")
    temporary = path.with_name(
        f".{path.name}.partial.{os.getpid()}.{secrets.token_hex(8)}"
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise gate.GateError(f"short write while creating {path}")
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
        os.close(descriptor)
        descriptor = None
        os.link(temporary, path)
        os.unlink(temporary)
        sync_parent(path)
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def git_object_id(repository: Path, expression: str, name: str) -> str:
    git_environment = controlled_git_environment()
    completed = subprocess.run(
        [
            GIT_EXECUTABLE,
            "--no-replace-objects",
            "-c",
            "core.attributesFile=/dev/null",
            "-C",
            str(repository),
            "rev-parse",
            "--verify",
            expression,
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=git_environment,
    )
    if completed.returncode != 0:
        raise gate.GateError(
            f"cannot resolve {name}: {completed.stderr.strip() or completed.stdout.strip()}"
        )
    return gate.lowercase_hex(completed.stdout.strip(), 40, name)


def git_blob_bytes(repository: Path, source_commit: str, path: str) -> bytes:
    completed = subprocess.run(
        [
            GIT_EXECUTABLE,
            "--no-replace-objects",
            "-c",
            "core.attributesFile=/dev/null",
            "-C",
            str(repository),
            "cat-file",
            "blob",
            f"{source_commit}:{path}",
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=controlled_git_environment(),
    )
    if completed.returncode != 0:
        raise gate.GateError(
            f"cannot read committed source {path}: "
            + completed.stderr.decode("utf-8", errors="replace").strip()
        )
    return completed.stdout


def require_distinct_artifacts(artifacts: dict[str, gate.StableFile]) -> None:
    paths: dict[Path, str] = {}
    inodes: dict[tuple[int, int], str] = {}
    for name, artifact in artifacts.items():
        resolved = artifact.path.resolve(strict=True)
        if resolved in paths:
            raise gate.GateError(f"{name} aliases {paths[resolved]}")
        paths[resolved] = name
        metadata = os.stat(artifact.path, follow_symlinks=False)
        identity = (metadata.st_dev, metadata.st_ino)
        if identity in inodes:
            raise gate.GateError(f"{name} hard-links {inodes[identity]}")
        inodes[identity] = name


def controlled_git_environment() -> dict[str, str]:
    return {
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def publish_git_archive(
    repository: Path,
    source_commit: str,
    source_tree: str,
    destination: Path,
) -> gate.StableFile:
    if destination.exists():
        raise gate.GateError(f"refusing to replace existing archive {destination}")
    temporary = destination.with_name(
        f".{destination.name}.partial.{os.getpid()}.{secrets.token_hex(8)}"
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            descriptor = None
            completed = subprocess.run(
                [
                    GIT_EXECUTABLE,
                    "--no-replace-objects",
                    "-c",
                    "core.attributesFile=/dev/null",
                    "-C",
                    str(repository),
                    "archive",
                    "--format=tar",
                    source_commit,
                ],
                check=False,
                stdout=output,
                stderr=subprocess.PIPE,
                env=controlled_git_environment(),
            )
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), 0o444)
        if completed.returncode != 0:
            raise gate.GateError(
                "git archive failed: "
                + completed.stderr.decode("utf-8", errors="replace").strip()
            )
        os.link(temporary, destination)
        os.unlink(temporary)
        sync_parent(destination)
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    archive_file = gate.stable_read(destination, gate.MAX_SHARD_BYTES)
    verify_git_archive(
        repository, source_commit, source_tree, archive_file
    )
    return archive_file


def verify_git_archive(
    repository: Path,
    source_commit: str,
    source_tree: str,
    archive_file: gate.StableFile,
) -> None:
    before_commit = git_object_id(
        repository, f"{source_commit}^{{commit}}", "pre-verify source commit"
    )
    before_tree = git_object_id(
        repository, f"{source_commit}^{{tree}}", "pre-verify source tree"
    )
    if before_commit != source_commit or before_tree != source_tree:
        raise gate.GateError("archive source commit/tree changed before verification")
    embedded = subprocess.run(
        [GIT_EXECUTABLE, "--no-replace-objects", "get-tar-commit-id"],
        check=False,
        input=archive_file.data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=controlled_git_environment(),
    )
    if embedded.returncode != 0 or embedded.stdout.decode("ascii", errors="replace").strip() != source_commit:
        raise gate.GateError("archive does not embed the exact source commit")
    verification_path = archive_file.path.with_name(
        f".{archive_file.path.name}.verify.{os.getpid()}.{secrets.token_hex(8)}"
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(
            verification_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            descriptor = None
            regenerated = subprocess.run(
                [
                    GIT_EXECUTABLE,
                    "--no-replace-objects",
                    "-c",
                    "core.attributesFile=/dev/null",
                    "-C",
                    str(repository),
                    "archive",
                    "--format=tar",
                    source_commit,
                ],
                check=False,
                stdout=output,
                stderr=subprocess.PIPE,
                env=controlled_git_environment(),
            )
            output.flush()
            os.fsync(output.fileno())
        if regenerated.returncode != 0:
            raise gate.GateError(
                "archive regeneration failed: "
                + regenerated.stderr.decode("utf-8", errors="replace").strip()
            )
        regenerated_file = gate.stable_read(verification_path, gate.MAX_SHARD_BYTES)
        if (
            regenerated_file.sha256 != archive_file.sha256
            or regenerated_file.data != archive_file.data
        ):
            raise gate.GateError(
                "archive bytes differ from a fresh controlled no-replace Git archive"
            )
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(verification_path)
        except FileNotFoundError:
            pass
    after_commit = git_object_id(
        repository, f"{source_commit}^{{commit}}", "post-verify source commit"
    )
    after_tree = git_object_id(
        repository, f"{source_commit}^{{tree}}", "post-verify source tree"
    )
    if (after_commit, after_tree) != (before_commit, before_tree):
        raise gate.GateError("source commit/tree changed across archive verification")


def finalize_contract(
    draft: dict[str, Any],
    source_commit: str,
    source_tree: str,
    cells_sha256: str,
    seal_name: str,
) -> dict[str, Any]:
    finalized = json.loads(json.dumps(draft))
    finalized["status"] = "SEALED_READY_FOR_ONE_SHOT_TIMING"
    finalized["candidate"]["source_commit"] = source_commit
    finalized["candidate"]["source_tree"] = source_tree
    finalized["inputs"]["cell_manifest_sha256"] = cells_sha256
    finalized["execution"]["sealing_authority"] = seal_name
    encoded = json.dumps(finalized, sort_keys=True)
    if "AWAITING_" in encoded:
        raise gate.GateError("finalized contract still contains an unresolved placeholder")
    return finalized


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--source-archive", required=True, type=Path)
    parser.add_argument("--runner", required=True, type=Path)
    parser.add_argument("--taskset", required=True, type=Path)
    parser.add_argument("--cells", required=True, type=Path)
    parser.add_argument("--contract-draft", required=True, type=Path)
    parser.add_argument("--sealed-contract-output", required=True, type=Path)
    parser.add_argument("--launcher", required=True, type=Path)
    parser.add_argument("--analyzer", required=True, type=Path)
    parser.add_argument("--authorization-nonce", required=True)
    parser.add_argument("--one-shot-registry", required=True, type=Path)
    parser.add_argument("--seal-output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        requested_commit = gate.lowercase_hex(
            args.source_commit, 40, "requested source commit"
        )
        requested_tree = gate.lowercase_hex(
            args.source_tree, 40, "requested source tree"
        )
        resolved_commit = git_object_id(
            args.repository, f"{requested_commit}^{{commit}}", "resolved source commit"
        )
        resolved_tree = git_object_id(
            args.repository, f"{requested_commit}^{{tree}}", "resolved source tree"
        )
        if resolved_commit != requested_commit or resolved_tree != requested_tree:
            raise gate.GateError("requested source commit/tree does not match Git")
        authorization_nonce = gate.nonce_hex(
            args.authorization_nonce, "authorization nonce"
        )
        if not args.one_shot_registry.is_absolute():
            raise gate.GateError("one-shot registry must be an absolute path")
        try:
            one_shot_registry = args.one_shot_registry.resolve(strict=True)
        except OSError as error:
            raise gate.GateError(f"cannot resolve one-shot registry: {error}") from error
        if one_shot_registry != args.one_shot_registry or not one_shot_registry.is_dir():
            raise gate.GateError("one-shot registry must be a canonical real directory")
        if not os.access(one_shot_registry, os.W_OK):
            raise gate.GateError("one-shot registry is not writable by the sealing operator")
        if args.taskset != Path("/usr/bin/taskset"):
            raise gate.GateError("frozen gate requires absolute /usr/bin/taskset")
        try:
            resolved_taskset = args.taskset.resolve(strict=True)
        except OSError as error:
            raise gate.GateError(f"cannot resolve taskset binary: {error}") from error
        if resolved_taskset != args.taskset:
            raise gate.GateError("taskset path is not canonical")
        cells_file = gate.stable_read(args.cells, gate.MAX_CELL_MANIFEST_BYTES)
        runner_file = gate.stable_read(args.runner, gate.MAX_SHARD_BYTES)
        taskset_file = gate.stable_read(args.taskset, gate.MAX_SHARD_BYTES)
        launcher_file = gate.stable_read(args.launcher, gate.MAX_CONTRACT_BYTES)
        analyzer_file = gate.stable_read(args.analyzer, gate.MAX_CONTRACT_BYTES)
        if cells_file.mode & 0o222:
            raise gate.GateError("cell manifest must be read-only before sealing")
        if runner_file.mode & 0o222 or not runner_file.mode & 0o111:
            raise gate.GateError("runner must be read-only and executable before sealing")
        if taskset_file.mode & 0o222 or not taskset_file.mode & 0o111:
            raise gate.GateError("taskset must be read-only and executable before sealing")
        gate.require_elf64_aarch64(taskset_file, "taskset binary")
        if launcher_file.mode & 0o222:
            raise gate.GateError("launcher must be read-only before sealing")
        if analyzer_file.mode & 0o222:
            raise gate.GateError("analyzer must be read-only before sealing")
        draft_file = gate.stable_read(args.contract_draft, gate.MAX_CONTRACT_BYTES)
        draft = gate.read_json_file(draft_file)
        archive_file = gate.stable_read(args.source_archive, gate.MAX_SHARD_BYTES)
        if archive_file.mode & 0o222:
            raise gate.GateError("source archive must be read-only before sealing")
        verify_git_archive(
            args.repository, requested_commit, requested_tree, archive_file
        )
        require_distinct_artifacts(
            {
                "cell manifest": cells_file,
                "runner": runner_file,
                "taskset": taskset_file,
                "launcher": launcher_file,
                "analyzer": analyzer_file,
                "contract draft": draft_file,
                "source archive": archive_file,
            }
        )
        gate_directory = (
            "research/aot/search-v26-width-cost-rule-r1/development-gate"
        )
        for name, source, relative_path in (
            (
                "launcher",
                launcher_file,
                f"{gate_directory}/launch_v26_gate_once.py",
            ),
            (
                "analyzer",
                analyzer_file,
                f"{gate_directory}/analyze_v26_gate.py",
            ),
            (
                "contract draft",
                draft_file,
                f"{gate_directory}/gate-contract-v1.json",
            ),
        ):
            if source.data != git_blob_bytes(
                args.repository, requested_commit, relative_path
            ):
                raise gate.GateError(
                    f"{name} bytes differ from the exact source commit"
                )
        existing_paths = {
            artifact.path.resolve(strict=True)
            for artifact in (
                cells_file,
                runner_file,
                taskset_file,
                launcher_file,
                analyzer_file,
                draft_file,
                archive_file,
            )
        }
        output_paths = {
            args.sealed_contract_output.resolve(strict=False),
            args.seal_output.resolve(strict=False),
        }
        if (
            len(output_paths) != 2
            or output_paths & existing_paths
        ):
            raise gate.GateError("seal outputs alias an immutable input or each other")
        build_identity, build_identity_sha256 = gate.runner_build_identity(
            runner_file
        )
        archive_source_set_sha256 = gate.archive_runner_source_set_sha256(
            archive_file
        )
        if (
            build_identity["source_commit"] != requested_commit
            or build_identity["source_tree"] != requested_tree
            or build_identity["source_archive_sha256"] != archive_file.sha256
            or build_identity["runner_source_set_sha256"]
            != archive_source_set_sha256
        ):
            raise gate.GateError(
                "runner build identity does not match Git-proven commit/tree/archive/source set"
            )
        contract = finalize_contract(
            draft,
            requested_commit,
            requested_tree,
            cells_file.sha256,
            args.seal_output.name,
        )
        publish_bytes_create_new(
            args.sealed_contract_output, canonical_json_bytes(contract)
        )
        contract_file = gate.stable_read(
            args.sealed_contract_output, gate.MAX_CONTRACT_BYTES
        )
        gate.require_exact_contract(contract, contract_file, cells_file)
        seal = {
            "schema": "fre-search-v26-development-gate-one-shot-seal-v1",
            "status": "SEALED_READY_FOR_ONE_SHOT_TIMING",
            "source_commit": requested_commit,
            "source_tree": requested_tree,
            "source_archive_sha256": archive_file.sha256,
            "runner_binary_sha256": runner_file.sha256,
            "runner_binary_bytes": len(runner_file.data),
            "runner_build_identity_sha256": build_identity_sha256,
            "taskset_path": str(args.taskset),
            "taskset_binary_sha256": taskset_file.sha256,
            "taskset_binary_bytes": len(taskset_file.data),
            "contract_sha256": contract_file.sha256,
            "cell_manifest_sha256": cells_file.sha256,
            "launcher_sha256": launcher_file.sha256,
            "analyzer_sha256": analyzer_file.sha256,
            "authorization_nonce": authorization_nonce,
            "one_shot_registry": str(one_shot_registry),
            "timing_runs": 1,
        }
        publish_bytes_create_new(args.seal_output, canonical_json_bytes(seal))
        seal_file = gate.stable_read(args.seal_output, gate.MAX_SEAL_BYTES)
        sys.stdout.write(
            json.dumps(
                {
                    "schema": "fre-search-v26-development-gate-seal-summary-v1",
                    "source_commit": requested_commit,
                    "source_tree": requested_tree,
                    "source_archive_sha256": archive_file.sha256,
                    "contract_sha256": contract_file.sha256,
                    "cell_manifest_sha256": cells_file.sha256,
                    "runner_binary_sha256": runner_file.sha256,
                    "runner_build_identity_sha256": build_identity_sha256,
                    "taskset_binary_sha256": taskset_file.sha256,
                    "one_shot_seal_sha256": seal_file.sha256,
                    "timing_executed": False,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )
        return 0
    except gate.GateError as error:
        sys.stderr.write(f"seal refused: {error}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
