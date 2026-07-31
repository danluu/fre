#!/usr/bin/env python3
"""Execute and seal one Search V26 static/correctness platform lane.

This controller executes only correctness evidence. It has no timing command
and cannot authorize a performance gate, promotion, or deployment.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import selectors
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import seal_correctness_receipt as receipt


MAX_STDERR_BYTES = 64 << 10
MAX_COMMAND_SECONDS = 30 * 60


def output_preflight(paths: list[Path], inputs: list[Path]) -> None:
    resolved_outputs = [path.resolve(strict=False) for path in paths]
    require = receipt.require
    require(len(set(resolved_outputs)) == len(paths), "lane output paths are duplicated")
    resolved_inputs = {path.resolve() for path in inputs}
    require(
        not set(resolved_outputs) & resolved_inputs,
        "lane output path aliases an evidence input",
    )
    for path in paths:
        require(not os.path.lexists(path), f"lane output already exists: {path}")
        require(
            path.parent.is_dir() and not path.parent.is_symlink(),
            f"lane output parent is not a regular directory: {path.parent}",
        )


def validate_host(lane: str) -> dict[str, str]:
    receipt.require(lane in {"local", "c9g"}, "lane must be local or c9g")
    observed_system = platform.system().lower()
    observed_machine = platform.machine().lower()
    expected_system = "darwin" if lane == "local" else "linux"
    receipt.require(
        observed_system == expected_system,
        f"{lane} controller is running on {observed_system}, not {expected_system}",
    )
    receipt.require(
        observed_machine in {"arm64", "aarch64"},
        f"{lane} controller is not running on AArch64",
    )
    return {
        "architecture": "aarch64",
        "operating_system": "macos" if lane == "local" else "linux",
    }


def terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.kill()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def run_bounded(
    argv: list[str],
    *,
    executable_fd: int | None = None,
    working_directory: Path | None = None,
) -> tuple[bytes, bytes]:
    receipt.require(bool(argv) and Path(argv[0]).is_absolute(), "runner argv is not absolute")
    pass_fds: tuple[int, ...] = ()
    if executable_fd is not None:
        metadata = os.fstat(executable_fd)
        receipt.require(
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_mode & 0o111 != 0,
            "runner executable FD is not a regular executable",
        )
        os.lseek(executable_fd, 0, os.SEEK_SET)
        pass_fds = (executable_fd,)
    process = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(working_directory or Path(argv[0]).parent),
        env=dict(receipt.EXECUTION_ENVIRONMENT),
        close_fds=True,
        pass_fds=pass_fds,
        start_new_session=True,
    )
    receipt.require(
        process.stdout is not None and process.stderr is not None,
        "runner pipes were not created",
    )
    streams = {
        process.stdout.fileno(): ("stdout", process.stdout, receipt.MAX_REPORT_BYTES),
        process.stderr.fileno(): ("stderr", process.stderr, MAX_STDERR_BYTES),
    }
    chunks: dict[str, list[bytes]] = {"stdout": [], "stderr": []}
    totals = {"stdout": 0, "stderr": 0}
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + MAX_COMMAND_SECONDS
    try:
        for descriptor, (name, stream, _) in streams.items():
            os.set_blocking(descriptor, False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise receipt.Refusal("runner command exceeded the bounded deadline")
            for key, _ in selector.select(timeout=min(1.0, remaining)):
                name = key.data
                descriptor = key.fileobj.fileno()
                try:
                    chunk = os.read(descriptor, 64 << 10)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                totals[name] += len(chunk)
                maximum = streams[descriptor][2]
                if totals[name] > maximum:
                    raise receipt.Refusal(f"runner {name} exceeded its byte limit")
                chunks[name].append(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise receipt.Refusal("runner command exceeded the bounded deadline")
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as error:
            raise receipt.Refusal("runner command exceeded the bounded deadline") from error
    except BaseException:
        terminate(process)
        raise
    finally:
        selector.close()
        for _, stream, _ in streams.values():
            if not stream.closed:
                stream.close()
    stdout = b"".join(chunks["stdout"])
    stderr = b"".join(chunks["stderr"])
    receipt.require(returncode == 0, f"runner exited with status {returncode}")
    receipt.require(not stderr, "runner wrote to stderr")
    return stdout, stderr


def validate_report_bytes(raw: bytes, name: str) -> dict[str, Any]:
    receipt.require(
        0 < len(raw) <= receipt.MAX_REPORT_BYTES,
        f"{name} has an invalid size",
    )
    receipt.require(
        raw.endswith(b"\n") and raw.count(b"\n") == 1 and b"\r" not in raw,
        f"{name} is not exactly one LF-terminated JSON line",
    )
    return receipt.strict_json_bytes(raw, name)


@dataclass(frozen=True)
class StagedRunner:
    temporary: tempfile.TemporaryDirectory[str]
    descriptor: int
    directory: Path
    executable_path: Path | None
    identity: tuple[int, int, int, int, int, int]
    raw: bytes
    mechanism: str


def executable_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        stat.S_IMODE(metadata.st_mode),
    )


def read_descriptor(descriptor: int, expected_bytes: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    observed = bytearray()
    while len(observed) < expected_bytes:
        chunk = os.read(descriptor, min(1 << 20, expected_bytes - len(observed)))
        receipt.require(bool(chunk), "staged runner executable ended early")
        observed.extend(chunk)
    receipt.require(
        not os.read(descriptor, 1),
        "staged runner executable grew",
    )
    os.lseek(descriptor, 0, os.SEEK_SET)
    return bytes(observed)


def verify_staged_runner(staged: StagedRunner) -> None:
    metadata = os.fstat(staged.descriptor)
    receipt.require(
        executable_identity(metadata) == staged.identity
        and stat.S_ISREG(metadata.st_mode)
        and metadata.st_mode & 0o111 != 0
        and read_descriptor(staged.descriptor, len(staged.raw)) == staged.raw,
        "staged runner executable FD identity changed",
    )
    if staged.executable_path is not None:
        path_metadata = staged.executable_path.lstat()
        receipt.require(
            not staged.executable_path.is_symlink()
            and executable_identity(path_metadata) == staged.identity,
            "closed Darwin runner pathname no longer names the validated inode",
        )
        directory_metadata = staged.directory.stat()
        receipt.require(
            stat.S_IMODE(directory_metadata.st_mode) == 0o500,
            "closed Darwin runner directory permissions changed",
        )


def stage_runner(parent: Path, raw: bytes) -> StagedRunner:
    temporary = tempfile.TemporaryDirectory(prefix=".fre-v26-runner-", dir=parent)
    staged = Path(temporary.name) / receipt.RUNNER_BASENAME
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(staged, flags, 0o500)
    try:
        written = 0
        while written < len(raw):
            amount = os.write(descriptor, raw[written:])
            receipt.require(amount > 0, "staged runner write made no progress")
            written += amount
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o500)
    finally:
        os.close(descriptor)
    read_flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        read_flags |= os.O_NOFOLLOW
    executable_fd = os.open(staged, read_flags)
    try:
        metadata = os.fstat(executable_fd)
        receipt.require(
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_size == len(raw)
            and metadata.st_mode & 0o111 != 0,
            "staged runner executable identity changed",
        )
        receipt.require(
            read_descriptor(executable_fd, len(raw)) == raw,
            "staged runner executable bytes changed",
        )
        observed_system = platform.system().lower()
        if observed_system == "linux":
            staged.unlink()
            executable_path: Path | None = None
            mechanism = "validated-open-fd"
        elif observed_system == "darwin":
            executable_path = staged
            mechanism = "closed-private-inode"
        else:
            raise receipt.Refusal("runner staging requires Linux or macOS")
        os.chmod(temporary.name, 0o500)
        directory = os.open(temporary.name, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        os.close(executable_fd)
        os.chmod(temporary.name, 0o700)
        temporary.cleanup()
        raise
    staged_runner = StagedRunner(
        temporary=temporary,
        descriptor=executable_fd,
        directory=Path(temporary.name),
        executable_path=executable_path,
        identity=executable_identity(os.fstat(executable_fd)),
        raw=raw,
        mechanism=mechanism,
    )
    verify_staged_runner(staged_runner)
    return staged_runner


def run_staged(staged: StagedRunner, arguments: list[str]) -> tuple[bytes, bytes]:
    verify_staged_runner(staged)
    if staged.mechanism == "validated-open-fd":
        executable = f"/proc/self/fd/{staged.descriptor}"
        descriptor: int | None = staged.descriptor
    else:
        receipt.require(
            staged.executable_path is not None,
            "closed Darwin runner pathname is missing",
        )
        executable = str(staged.executable_path)
        descriptor = None
    try:
        return run_bounded(
            [executable, *arguments],
            executable_fd=descriptor,
            working_directory=staged.directory,
        )
    finally:
        verify_staged_runner(staged)


def close_staged(staged: StagedRunner) -> None:
    os.close(staged.descriptor)
    os.chmod(staged.directory, 0o700)
    staged.temporary.cleanup()


def run_lane(arguments: argparse.Namespace) -> dict[str, Any]:
    lane = arguments.lane
    receipt.require(lane in {"local", "c9g"}, "lane must be local or c9g")
    source_root = Path(arguments.source_root)
    source_archive = Path(arguments.source_archive)
    runner_binary = Path(arguments.runner_binary)
    correctness_output = Path(arguments.correctness_output)
    manifest_output = Path(arguments.manifest_output)
    static_output = Path(arguments.static_output) if arguments.static_output else None
    if lane == "local":
        receipt.require(static_output is not None, "local lane requires --static-output")
    else:
        receipt.require(static_output is None, "c9g lane forbids --static-output")

    outputs = [correctness_output, manifest_output]
    if static_output is not None:
        outputs.insert(0, static_output)
    resolved_source_root = source_root.resolve()
    receipt.require(
        all(
            not path.resolve(strict=False).is_relative_to(resolved_source_root)
            for path in outputs
        ),
        "lane outputs must be outside the bound source worktree",
    )
    execution_tool_path = Path(__file__).resolve()
    validation_tool_path = Path(receipt.__file__).resolve()
    receipt.require(
        execution_tool_path.name == receipt.EXECUTION_TOOL_BASENAME
        and validation_tool_path.name == receipt.VALIDATION_TOOL_BASENAME,
        "lane controller or validation tool basename changed",
    )
    inputs = [
        source_archive,
        runner_binary,
        execution_tool_path,
        validation_tool_path,
    ]
    output_preflight(outputs, inputs)
    receipt.validate_created_utc(arguments.created_utc)
    host_identity = receipt.require_host_identity(
        arguments.host_identity, f"{lane} host identity"
    )
    observed_host_platform = validate_host(lane)
    receipt.validate_source(
        source_root, arguments.source_commit, arguments.source_tree
    )
    archive_sha, archive_bytes = receipt.verify_git_archive(
        source_root,
        arguments.source_commit,
        source_archive,
        arguments.source_archive_sha256,
    )
    source_set_sha = receipt.git_source_set_sha256(
        source_root, arguments.source_commit
    )
    runner_raw, runner_sha, runner_bytes = receipt.validate_runner_artifact(
        runner_binary, arguments.runner_binary_sha256, lane
    )
    execution_tool_raw = receipt.stable_bytes(
        execution_tool_path,
        receipt.MAX_EXECUTION_TOOL_BYTES,
        "lane execution tool",
    )
    validation_tool_raw = receipt.stable_bytes(
        validation_tool_path,
        receipt.MAX_EXECUTION_TOOL_BYTES,
        "lane validation tool",
    )
    execution_tool_sha = hashlib.sha256(execution_tool_raw).hexdigest()
    validation_tool_sha = hashlib.sha256(validation_tool_raw).hexdigest()
    receipt.validate_tracked_tool_bytes(
        source_root,
        arguments.source_commit,
        receipt.EXECUTION_TOOL_REPOSITORY_PATH,
        execution_tool_raw,
        "lane execution tool",
    )
    receipt.validate_tracked_tool_bytes(
        source_root,
        arguments.source_commit,
        receipt.VALIDATION_TOOL_REPOSITORY_PATH,
        validation_tool_raw,
        "lane validation tool",
    )

    staged_runner = stage_runner(manifest_output.parent, runner_raw)
    try:
        receipt.require(
            staged_runner.mechanism
            == ("closed-private-inode" if lane == "local" else "validated-open-fd"),
            f"{lane} runner execution mechanism changed",
        )
        build_identity_raw, _ = run_staged(
            staged_runner, ["evidence-build-identity"]
        )
        build_identity_report = validate_report_bytes(
            build_identity_raw, f"{lane} runner build identity"
        )
        receipt.require(
            build_identity_raw
            == receipt.canonical_bytes(build_identity_report) + b"\n",
            f"{lane} runner build identity is not canonical JSON",
        )
        receipt.validate_build_identity(
            build_identity_report,
            lane,
            arguments.source_commit,
            arguments.source_tree,
            archive_sha,
            source_set_sha,
        )
        static_raw: bytes | None = None
        if lane == "local":
            static_raw, _ = run_staged(staged_runner, ["static"])
            static_report = validate_report_bytes(static_raw, "static report")
            receipt.validate_static(static_report)
        correctness_raw, _ = run_staged(staged_runner, ["correctness", lane])
        correctness_report = validate_report_bytes(
            correctness_raw, f"{lane} correctness report"
        )
        receipt.validate_correctness(correctness_report, lane)
    finally:
        close_staged(staged_runner)

    receipt.validate_source(
        source_root, arguments.source_commit, arguments.source_tree
    )
    receipt.stable_sha256(
        source_archive,
        receipt.MAX_ARCHIVE_BYTES,
        archive_sha,
        "source archive after execution",
    )
    runner_raw_after, runner_sha_after, runner_bytes_after = (
        receipt.validate_runner_artifact(
            runner_binary, arguments.runner_binary_sha256, lane
        )
    )
    receipt.require(
        runner_raw_after == runner_raw
        and runner_sha_after == runner_sha
        and runner_bytes_after == runner_bytes,
        "runner artifact changed during execution",
    )
    receipt.require(
        receipt.stable_bytes(
            execution_tool_path,
            receipt.MAX_EXECUTION_TOOL_BYTES,
            "lane execution tool after execution",
        )
        == execution_tool_raw,
        "lane execution tool changed during execution",
    )
    receipt.require(
        receipt.stable_bytes(
            validation_tool_path,
            receipt.MAX_EXECUTION_TOOL_BYTES,
            "lane validation tool after execution",
        )
        == validation_tool_raw,
        "lane validation tool changed during execution",
    )

    payload = receipt.execution_payload(
        lane=lane,
        created_utc=arguments.created_utc,
        host_identity=host_identity,
        source_commit=arguments.source_commit,
        source_tree=arguments.source_tree,
        archive_sha256=archive_sha,
        archive_bytes=archive_bytes,
        source_set_sha256=source_set_sha,
        runner_sha256=runner_sha,
        runner_bytes=runner_bytes,
        execution_tool_sha256=execution_tool_sha,
        execution_tool_bytes=len(execution_tool_raw),
        validation_tool_sha256=validation_tool_sha,
        validation_tool_bytes=len(validation_tool_raw),
        build_identity_raw=build_identity_raw,
        build_identity_report=build_identity_report,
        correctness_raw=correctness_raw,
        correctness_report=correctness_report,
        static_raw=static_raw,
    )
    receipt.require(
        payload["host_platform"] == observed_host_platform,
        "controller host observation changed before sealing",
    )
    manifest = receipt.execution_manifest(payload)
    if static_output is not None:
        receipt.require(static_raw is not None, "local static output is unavailable")
        receipt.create_new_output(static_output, static_raw)
    receipt.create_new_output(correctness_output, correctness_raw)
    receipt.create_new_output(
        manifest_output, receipt.canonical_bytes(manifest) + b"\n"
    )
    return manifest


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--source-root", required=True)
    result.add_argument("--source-commit", required=True)
    result.add_argument("--source-tree", required=True)
    result.add_argument("--source-archive", required=True)
    result.add_argument("--source-archive-sha256", required=True)
    result.add_argument("--runner-binary", required=True)
    result.add_argument("--runner-binary-sha256", required=True)
    result.add_argument("--host-identity", required=True)
    result.add_argument("--lane", required=True, choices=("local", "c9g"))
    result.add_argument("--created-utc", required=True)
    result.add_argument("--static-output")
    result.add_argument("--correctness-output", required=True)
    result.add_argument("--manifest-output", required=True)
    return result


def main() -> None:
    arguments = parser().parse_args()
    try:
        manifest = run_lane(arguments)
    except (OSError, receipt.Refusal, subprocess.SubprocessError) as error:
        print(f"run-v26-correctness-lane: {error}", file=os.sys.stderr)
        raise SystemExit(1) from error
    encoded = receipt.canonical_bytes(manifest) + b"\n"
    print(f"schema={receipt.EXECUTION_SCHEMA}")
    print(f"manifest_sha256={hashlib.sha256(encoded).hexdigest()}")
    print("correctness=pass performance_authority=false production_authority=false")


if __name__ == "__main__":
    main()
