#!/usr/bin/env python3
"""Run or resume one tag-30 application phase on frozen CPU workers."""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import platform
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Sequence


CONTRACT_SHA256 = (
    "121c44149d1b758fa5ac750aa524621669c92d23c4c095bab7f36bc767faa34b"
)
CONTRACT_SCHEMA = "fre.aot.search-tag30-ripgrep-application-contract.v1"
SHARDS = 16
HOST_CPUS = {
    "local-apple-aarch64-asimd": tuple(range(12, 18)),
    "zstd-eval-c9g-neoverse-v3-aarch64-asimd": tuple(range(64, 80)),
}
HOST_PLATFORMS = {
    "local-apple-aarch64-asimd": ("Darwin", {"arm64", "aarch64"}),
    "zstd-eval-c9g-neoverse-v3-aarch64-asimd": ("Linux", {"aarch64"}),
}
HEADER_SCHEMA = (
    "fre.aot.search-tag30-ripgrep-application-fragment-header.v1"
)
TRAILER_SCHEMA = (
    "fre.aot.search-tag30-ripgrep-application-fragment-trailer.v1"
)


class Refusal(RuntimeError):
    """A frozen controller input or runner process failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def sha256(encoded: bytes) -> str:
    return hashlib.sha256(encoded).hexdigest()


def regular(path: Path, maximum: int | None = None) -> os.stat_result:
    status = path.lstat()
    require(
        stat.S_ISREG(status.st_mode)
        and not path.is_symlink()
        and status.st_nlink == 1
        and status.st_size > 0
        and (maximum is None or status.st_size <= maximum),
        f"not one bounded unshared regular file: {path}",
    )
    return status


def real_directory(path: Path) -> None:
    status = path.lstat()
    require(
        stat.S_ISDIR(status.st_mode) and not path.is_symlink(),
        f"not one real directory: {path}",
    )


def fragment_name(host: str, mode: str, shard: int) -> str:
    return f"{host}.{mode}.shard-{shard:02}.jsonl"


def shard_bounds(shard: int) -> tuple[int, int]:
    quotient, remainder = divmod(154, SHARDS)
    start = shard * quotient + min(shard, remainder)
    return start, start + quotient + int(shard < remainder)


def validate_fragment(
    path: Path,
    host: str,
    mode: str,
    shard: int,
) -> dict[str, Any]:
    status = regular(path, 64 << 20)
    encoded = path.read_bytes()
    require(len(encoded) == status.st_size, "fragment short read")
    lines = encoded.splitlines()
    require(len(lines) >= 2, "fragment is incomplete")
    header = json.loads(lines[0])
    trailer = json.loads(lines[-1])
    start, end = shard_bounds(shard)
    require(
        header.get("schema") == HEADER_SCHEMA
        and header.get("host_id") == host
        and header.get("mode") == mode
        and header.get("shard_id") == shard
        and header.get("shard_start") == start
        and header.get("shard_end") == end
        and header.get("logical_cpu") in HOST_CPUS[host]
        and trailer.get("schema") == TRAILER_SCHEMA
        and trailer.get("shard_start") == start
        and trailer.get("shard_end") == end
        and trailer.get("rows") == end - start
        and trailer.get("complete") is True,
        f"fragment identity or completion changed: {path.name}",
    )
    return {
        "shard": shard,
        "cpu": header["logical_cpu"],
        "output": path.name,
        "bytes": status.st_size,
        "sha256": sha256(encoded),
    }


def worker(
    runner: Path,
    contract: Path,
    projection: Path,
    fixtures: Path,
    receipt: Path,
    host: str,
    mode: str,
    cpu: int,
    shards: Sequence[int],
    results: Path,
    control: Path,
) -> list[dict[str, Any]]:
    completed_receipts = []
    for shard in shards:
        final = results / fragment_name(host, mode, shard)
        if final.exists():
            completed_receipts.append(
                validate_fragment(final, host, mode, shard)
            )
            continue
        attempt = (
            control
            / (
                f"{fragment_name(host, mode, shard)}."
                f"attempt-{os.getpid()}-{cpu}-{time.time_ns()}"
            )
        )
        log = attempt.with_suffix(attempt.suffix + ".log")
        require(
            not attempt.exists() and not log.exists(),
            "controller attempt path collision",
        )
        command = [
            str(runner),
            mode,
            str(contract),
            str(projection),
            str(fixtures),
            str(receipt),
            str(shard),
            host,
            str(cpu),
            str(attempt),
        ]
        completed = subprocess.run(
            command,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env={
                key: value
                for key, value in os.environ.items()
                if "REBAR" not in key.upper()
            },
        )
        log.write_bytes(completed.stdout)
        require(
            completed.returncode == 0,
            f"shard {shard} on CPU {cpu} failed; see {log}",
        )
        fragment = validate_fragment(attempt, host, mode, shard)
        require(not final.exists(), f"refusing to replace {final.name}")
        attempt.chmod(0o444)
        attempt.rename(final)
        fragment["output"] = final.name
        completed_receipts.append(fragment)
    return completed_receipts


def run(argv: Sequence[str]) -> None:
    require(
        len(argv) == 9,
        "usage: run_shards.py (correctness|timing) CONTRACT PROJECTION "
        "FIXTURE_ROOT BUILD_RECEIPT HOST RUNNER RESULT_DIRECTORY "
        "CONTROL_DIRECTORY",
    )
    (
        mode,
        raw_contract,
        raw_projection,
        raw_fixtures,
        raw_receipt,
        host,
        raw_runner,
        raw_results,
        raw_control,
    ) = argv
    require(mode in {"correctness", "timing"}, "mode is not frozen")
    require(host in HOST_CPUS, "host ID is not frozen")
    expected_system, expected_machines = HOST_PLATFORMS[host]
    require(
        platform.system() == expected_system
        and platform.machine() in expected_machines,
        "host ID does not match controller platform",
    )
    contract = Path(raw_contract).resolve(strict=True)
    projection = Path(raw_projection).resolve(strict=True)
    fixtures = Path(raw_fixtures).resolve(strict=True)
    receipt = Path(raw_receipt).resolve(strict=True)
    runner = Path(raw_runner).resolve(strict=True)
    results = Path(raw_results).resolve(strict=True)
    control = Path(raw_control).resolve(strict=True)
    real_directory(fixtures)
    real_directory(results)
    real_directory(control)
    regular(contract, 128 << 10)
    contract_bytes = contract.read_bytes()
    require(
        sha256(contract_bytes) == CONTRACT_SHA256
        and json.loads(contract_bytes).get("schema") == CONTRACT_SCHEMA,
        "application contract changed",
    )
    regular(projection, 2 << 20)
    regular(receipt, 4 << 20)
    runner_status = regular(runner, 1 << 30)
    require(runner_status.st_mode & 0o111 != 0, "runner is not executable")
    if mode == "timing":
        for shard in range(SHARDS):
            correctness = results / fragment_name(
                host,
                "correctness",
                shard,
            )
            validate_fragment(correctness, host, "correctness", shard)
    cpus = HOST_CPUS[host]
    assignments = {
        cpu: tuple(
            shard
            for shard in range(SHARDS)
            if shard % len(cpus) == worker
        )
        for worker, cpu in enumerate(cpus)
    }
    receipts = []
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=len(cpus)
    ) as executor:
        futures = [
            executor.submit(
                worker,
                runner,
                contract,
                projection,
                fixtures,
                receipt,
                host,
                mode,
                cpu,
                shards,
                results,
                control,
            )
            for cpu, shards in assignments.items()
        ]
        for future in concurrent.futures.as_completed(futures):
            receipts.extend(future.result())
            print(
                json.dumps(
                    {
                        "host": host,
                        "mode": mode,
                        "completed": len(receipts),
                        "shards": SHARDS,
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
    receipts.sort(key=lambda value: value["shard"])
    require(
        [value["shard"] for value in receipts] == list(range(SHARDS)),
        "controller shard union changed",
    )
    summary = {
        "schema": (
            "fre.aot.search-tag30-ripgrep-application-controller-summary.v1"
        ),
        "contract_sha256": CONTRACT_SHA256,
        "controller_source_sha256": sha256(
            Path(__file__).resolve(strict=True).read_bytes()
        ),
        "host": host,
        "mode": mode,
        "worker_cpus": list(cpus),
        "fragments": receipts,
        "complete": True,
        "rebar_accepted_as_input": False,
    }
    summary_path = control / f"{host}.{mode}.summary.json"
    if summary_path.exists():
        regular(summary_path, 1 << 20)
        existing = json.loads(summary_path.read_bytes())
        require(existing == summary, "existing controller summary changed")
        print(json.dumps(summary, sort_keys=True))
        return
    summary_path.write_text(
        json.dumps(summary, sort_keys=True, indent=2) + "\n",
        encoding="ascii",
    )
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    run(sys.argv[1:])
