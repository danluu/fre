#!/usr/bin/env python3
"""Run one frozen Search tag-30 phase with platform-specific workers."""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import platform
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence


CONTRACT_SHA256 = (
    "d39dc02c741a13adc8e0c7c3cc818ffa69e96132af89caf0fef6b5dad6d14333"
)
CONTRACT_SCHEMA = "fre.aot.search-tag30-qualification-campaign-contract.v1"
HOST_TARGETS = {
    "local-apple-aarch64-asimd": ("Darwin", "arm64"),
    "zstd-eval-c9g-neoverse-v3-aarch64-asimd": ("Linux", "aarch64"),
}
SHARDS = 16
MACOS_WORKER_LABELS = (12, 13, 14, 15, 16, 17)
MAXIMUM_SMALL_FILE = 128 * 1024


class Refusal(RuntimeError):
    """A frozen controller input or one runner process failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def sha256(encoded: bytes) -> str:
    return hashlib.sha256(encoded).hexdigest()


def regular_file(path: Path, maximum: int | None = None) -> os.stat_result:
    status = path.lstat()
    require(
        path.is_file()
        and not path.is_symlink()
        and stat.S_ISREG(status.st_mode)
        and status.st_nlink == 1
        and status.st_size > 0
        and (maximum is None or status.st_size <= maximum),
        f"not one bounded unshared regular file: {path}",
    )
    return status


def authenticate_contract(path: Path) -> Mapping[str, Any]:
    status = regular_file(path, MAXIMUM_SMALL_FILE)
    encoded = path.read_bytes()
    require(len(encoded) == status.st_size, "campaign contract short read")
    require(sha256(encoded) == CONTRACT_SHA256, "campaign contract changed")
    contract = json.loads(encoded)
    require(
        isinstance(contract, dict)
        and contract.get("schema") == CONTRACT_SCHEMA
        and contract.get("result_blind") is True
        and contract.get("rebar_inputs") == []
        and contract.get("result_derived_selection") is False
        and contract.get("result_derived_exclusions") is False,
        "campaign contract authority changed",
    )
    return contract


def parse_cpus(value: str, host: str) -> tuple[int, ...]:
    try:
        cpus = tuple(int(part, 10) for part in value.split(","))
    except ValueError as error:
        raise Refusal("CPU list is not comma-separated decimal integers") from error
    require(host in HOST_TARGETS, "host ID is not frozen")
    require(
        len(set(cpus)) == len(cpus) and all(cpu >= 0 for cpu in cpus),
        "worker labels must be unique nonnegative integers",
    )
    if host == "local-apple-aarch64-asimd":
        require(
            cpus == MACOS_WORKER_LABELS,
            "macOS requires the six ordered Super worker labels 12 through 17",
        )
    else:
        require(
            8 <= len(cpus) <= 16,
            "Linux requires 8 through 16 exact CPU workers",
        )
    return cpus


def validate_host(host: str) -> None:
    require(host in HOST_TARGETS, "host ID is not frozen")
    expected_system, expected_machine = HOST_TARGETS[host]
    actual_machine = platform.machine()
    require(
        platform.system() == expected_system
        and (
            actual_machine == expected_machine
            or (expected_machine == "arm64" and actual_machine == "aarch64")
        ),
        "host ID does not match the controller platform",
    )


def fragment_name(host: str, mode: str, kind: str, shard: int) -> str:
    return f"{host}--{mode}--{kind}--shard-{shard:02}.jsonl"


def worker(
    runner: Path,
    contract: Path,
    mode: str,
    kind: str,
    projection: Path,
    host: str,
    cpu: int,
    shards: Sequence[int],
    output_directory: Path,
) -> list[Mapping[str, Any]]:
    receipts = []
    for shard in shards:
        output = output_directory / fragment_name(host, mode, kind, shard)
        require(not output.exists(), f"refusing to replace fragment: {output.name}")
        command = [
            str(runner),
            mode,
            str(contract),
            kind,
            str(projection),
            str(shard),
            host,
            str(cpu),
            str(output),
        ]
        completed = subprocess.run(
            command,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={
                key: value
                for key, value in os.environ.items()
                if "REBAR" not in key.upper()
            },
        )
        require(
            completed.returncode == 0,
            f"shard {shard} on CPU {cpu} failed: {completed.stderr.strip()}",
        )
        status = regular_file(output)
        require(
            status.st_mode & 0o222 == 0,
            f"completed fragment remained writable: {output.name}",
        )
        receipts.append(
            {
                "shard": shard,
                "cpu": cpu,
                "output": output.name,
                "bytes": status.st_size,
                "sha256": sha256(output.read_bytes()),
                "runner_stdout": completed.stdout.strip(),
            }
        )
    return receipts


def run_phase(
    mode: str,
    contract_path: Path,
    kind: str,
    projection: Path,
    host: str,
    runner: Path,
    cpus: tuple[int, ...],
    output_directory: Path,
) -> None:
    require(mode in {"correctness", "timing"}, "mode is not frozen")
    require(
        kind in {"universal", "long-policy", "diagnostic"},
        "projection kind is not frozen",
    )
    require(
        not (mode == "correctness" and kind == "diagnostic"),
        "the preregistered diagnostic has timing mode only",
    )
    authenticate_contract(contract_path)
    validate_host(host)
    require(
        parse_cpus(",".join(str(cpu) for cpu in cpus), host) == cpus,
        "worker CPU contract changed",
    )
    regular_file(projection)
    runner_status = regular_file(runner)
    controller_source_sha256 = sha256(
        read_small_source(Path(__file__).resolve())
    )
    require(
        runner_status.st_mode & 0o111 != 0,
        "runner is not executable",
    )
    directory_status = output_directory.lstat()
    require(
        output_directory.is_dir()
        and not output_directory.is_symlink()
        and stat.S_ISDIR(directory_status.st_mode),
        "output directory is not one real directory",
    )
    if mode == "timing" and kind != "diagnostic":
        for correctness_kind in ("universal", "long-policy"):
            for correctness_shard in range(SHARDS):
                prerequisite = output_directory / fragment_name(
                    host,
                    "correctness",
                    correctness_kind,
                    correctness_shard,
                )
                status = regular_file(prerequisite)
                require(
                    status.st_mode & 0o222 == 0,
                    "formal timing requires completed immutable local correctness fragments",
                )
    for shard in range(SHARDS):
        require(
            not (output_directory / fragment_name(host, mode, kind, shard)).exists(),
            "one or more target fragments already exist",
        )
    assignments = {
        cpu: tuple(
            shard
            for shard in range(SHARDS)
            if shard % len(cpus) == worker_ordinal
        )
        for worker_ordinal, cpu in enumerate(cpus)
    }
    all_receipts = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(cpus)) as executor:
        futures = [
            executor.submit(
                worker,
                runner.resolve(strict=True),
                contract_path.resolve(strict=True),
                mode,
                kind,
                projection.resolve(strict=True),
                host,
                cpu,
                shards,
                output_directory.resolve(strict=True),
            )
            for cpu, shards in assignments.items()
        ]
        for future in futures:
            all_receipts.extend(future.result())
    all_receipts.sort(key=lambda receipt: receipt["shard"])
    require(
        [receipt["shard"] for receipt in all_receipts] == list(range(SHARDS)),
        "controller shard union changed",
    )
    summary = {
        "schema": "fre.aot.search-tag30-shard-controller-summary.v1",
        "contract_sha256": CONTRACT_SHA256,
        "controller_source_sha256": controller_source_sha256,
        "mode": mode,
        "projection_kind": kind,
        "host": host,
        "worker_cpus": list(cpus),
        "shards": SHARDS,
        "fragments": all_receipts,
        "complete": True,
        "rebar_accepted_as_input": False,
    }
    print(json.dumps(summary, sort_keys=True))


def read_small_source(path: Path) -> bytes:
    status = regular_file(path, 1 << 20)
    encoded = path.read_bytes()
    require(len(encoded) == status.st_size, "controller source short read")
    return encoded


def main(argv: Sequence[str]) -> None:
    require(
        len(argv) == 8,
        "usage: run_shards.py (correctness|timing) CONTRACT "
        "(universal|long-policy|diagnostic) PROJECTION HOST RUNNER CPU0,...,CPUN "
        "EXISTING_OUTPUT_DIRECTORY",
    )
    mode, contract, kind, projection, host, runner, raw_cpus, output = argv
    run_phase(
        mode,
        Path(contract),
        kind,
        Path(projection),
        host,
        Path(runner),
        parse_cpus(raw_cpus, host),
        Path(output),
    )


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, TypeError, KeyError, Refusal) as error:
        print(f"search-tag30-shard-controller: {error}", file=sys.stderr)
        raise SystemExit(1)
