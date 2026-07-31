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
import subprocess
import tempfile
import time
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


def run_bounded(argv: list[str]) -> tuple[bytes, bytes]:
    receipt.require(bool(argv) and Path(argv[0]).is_absolute(), "runner argv is not absolute")
    process = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(Path(argv[0]).parent),
        env=dict(receipt.EXECUTION_ENVIRONMENT),
        close_fds=True,
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


def stage_runner(parent: Path, raw: bytes) -> tuple[tempfile.TemporaryDirectory[str], Path]:
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
    return temporary, staged.resolve()


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

    temporary, staged_runner = stage_runner(manifest_output.parent, runner_raw)
    try:
        static_raw: bytes | None = None
        if lane == "local":
            static_raw, _ = run_bounded([str(staged_runner), "static"])
            static_report = validate_report_bytes(static_raw, "static report")
            receipt.validate_static(static_report)
        correctness_raw, _ = run_bounded(
            [str(staged_runner), "correctness", lane]
        )
        correctness_report = validate_report_bytes(
            correctness_raw, f"{lane} correctness report"
        )
        receipt.validate_correctness(correctness_report, lane)
    finally:
        temporary.cleanup()

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
        runner_sha256=runner_sha,
        runner_bytes=runner_bytes,
        execution_tool_sha256=execution_tool_sha,
        execution_tool_bytes=len(execution_tool_raw),
        validation_tool_sha256=validation_tool_sha,
        validation_tool_bytes=len(validation_tool_raw),
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
