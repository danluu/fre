#!/usr/bin/env python3
"""Sealed controller for the source-blind composition interaction gate."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import pathlib
import random
import shutil
import subprocess
import sys
from typing import Any


GATE_DIR = pathlib.Path(__file__).resolve().parent
POLICY_PATH = GATE_DIR / "policy.json"


def sha256_path(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def run_checked(
    command: list[str],
    *,
    cwd: pathlib.Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {command!r}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed


def source_identity(source: pathlib.Path) -> dict[str, Any]:
    identity: dict[str, Any] = {
        "path": str(source.resolve()),
        "fre_manifest_sha256": sha256_path(source / "crates/fre/Cargo.toml"),
    }
    try:
        identity["commit"] = run_checked(
            ["git", "rev-parse", "HEAD"], cwd=source
        ).stdout.strip()
        identity["tree"] = run_checked(
            ["git", "rev-parse", "HEAD^{tree}"], cwd=source
        ).stdout.strip()
        crate_diff = run_checked(
            ["git", "diff", "--binary", "--", "crates"], cwd=source
        ).stdout.encode()
        identity["crates_diff_sha256"] = hashlib.sha256(crate_diff).hexdigest()
        identity["crates_dirty"] = bool(crate_diff)
    except (RuntimeError, FileNotFoundError):
        identity["commit"] = None
        identity["tree"] = None
        identity["crates_diff_sha256"] = None
        identity["crates_dirty"] = None
    return identity


def render_gate(source: pathlib.Path, rendered: pathlib.Path) -> None:
    if rendered.exists():
        shutil.rmtree(rendered)
    (rendered / "src").mkdir(parents=True)
    shutil.copy2(GATE_DIR / "src/main.rs", rendered / "src/main.rs")
    manifest = (GATE_DIR / "Cargo.toml.in").read_text()
    crate_path = str((source / "crates/fre").resolve()).replace("\\", "\\\\")
    manifest = manifest.replace("__FRE_CRATE_PATH__", crate_path)
    (rendered / "Cargo.toml").write_text(manifest)
    lock = GATE_DIR / "Cargo.lock"
    if lock.exists():
        shutil.copy2(lock, rendered / "Cargo.lock")


def command_build(args: argparse.Namespace) -> None:
    source = pathlib.Path(args.source).resolve()
    output = pathlib.Path(args.out).resolve()
    rendered = output / "rendered" / args.label
    target = output / "target" / args.label
    render_gate(source, rendered)
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(target)
    env["CARGO_BUILD_JOBS"] = str(args.jobs)
    command = [
        "cargo",
        "build",
        "--release",
        "--offline",
        "--manifest-path",
        str(rendered / "Cargo.toml"),
    ]
    if (rendered / "Cargo.lock").exists():
        command.append("--locked")
    if args.feature:
        command.extend(["--features", args.feature])
    completed = run_checked(command, env=env)
    binary = target / "release/fre-composition-interaction-gate"
    if not binary.is_file():
        raise RuntimeError(f"build did not produce {binary}")
    build_record = {
        "schema": "fre.composition-interaction-gate.build.v1",
        "label": args.label,
        "source": source_identity(source),
        "feature": args.feature,
        "jobs": args.jobs,
        "binary": str(binary),
        "binary_sha256": sha256_path(binary),
        "cargo_stdout": completed.stdout,
        "cargo_stderr": completed.stderr,
    }
    output.mkdir(parents=True, exist_ok=True)
    record_path = output / f"build-{args.label}.json"
    record_path.write_bytes(canonical_json(build_record))
    print(canonical_json(build_record).decode(), end="")


def command_lock(args: argparse.Namespace) -> None:
    source = pathlib.Path(args.source).resolve()
    output = pathlib.Path(args.out).resolve()
    rendered = output / "lock-rendered"
    render_gate(source, rendered)
    lock = rendered / "Cargo.lock"
    if lock.exists():
        lock.unlink()
    run_checked(
        [
            "cargo",
            "generate-lockfile",
            "--offline",
            "--manifest-path",
            str(rendered / "Cargo.toml"),
        ]
    )
    print(lock)


def binary_json(binary: pathlib.Path, arguments: list[str]) -> Any:
    completed = run_checked([str(binary), *arguments])
    return json.loads(completed.stdout)


def command_verify(args: argparse.Namespace) -> None:
    binary = pathlib.Path(args.binary).resolve()
    receipt = binary_json(binary, ["verify"])
    output = pathlib.Path(args.out).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(canonical_json(receipt))
    print(
        canonical_json(
            {
                "receipt": str(output),
                "sha256": sha256_path(output),
                "record_count": receipt["record_count"],
            }
        ).decode(),
        end="",
    )


def execute_task(task: dict[str, Any]) -> dict[str, Any]:
    command = [
        task["binary"],
        "point",
        "--case",
        task["case_id"],
        "--tier",
        task["tier"],
        "--operation",
        task["operation"],
        "--engine",
        task["engine"],
    ]
    completed = subprocess.run(
        command,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"ordinal {task['ordinal']} failed without retry: "
            f"{completed.returncode}: {completed.stderr}"
        )
    result = json.loads(completed.stdout)
    result["source"] = task["source"]
    result["repetition"] = task["repetition"]
    result["schedule_ordinal"] = task["ordinal"]
    return result


def command_run(args: argparse.Namespace) -> None:
    if args.workers < 1 or args.workers > 96:
        raise ValueError("--workers must be between 1 and 96")
    policy = json.loads(POLICY_PATH.read_text())
    base_binary = pathlib.Path(args.base_binary).resolve()
    candidate_binary = pathlib.Path(args.candidate_binary).resolve()
    base_catalog = binary_json(base_binary, ["catalog"])
    candidate_catalog = binary_json(candidate_binary, ["catalog"])
    if base_catalog != candidate_catalog:
        raise RuntimeError("base and candidate catalogs differ")

    tasks: list[dict[str, Any]] = []
    repetitions = policy["timing"]["repetitions"]
    binaries = {"base": base_binary, "candidate": candidate_binary}
    for point in base_catalog["points"]:
        for repetition in range(repetitions):
            for source, binary in binaries.items():
                tasks.append(
                    {
                        "source": source,
                        "binary": str(binary),
                        "engine": "fre",
                        "repetition": repetition,
                        **point,
                    }
                )
                if point["comparable_to_rust"]:
                    tasks.append(
                        {
                            "source": source,
                            "binary": str(binary),
                            "engine": "rust",
                            "repetition": repetition,
                            **point,
                        }
                    )

    random.Random(policy["timing"]["schedule_seed"]).shuffle(tasks)
    for ordinal, task in enumerate(tasks):
        task["ordinal"] = ordinal
    output = pathlib.Path(args.out).resolve()
    output.mkdir(parents=True, exist_ok=False)
    schedule = {
        "schema": "fre.composition-interaction-gate.schedule.v1",
        "policy_sha256": sha256_path(POLICY_PATH),
        "catalog_sha256": hashlib.sha256(canonical_json(base_catalog)).hexdigest(),
        "workers": args.workers,
        "task_count": len(tasks),
        "no_retries": True,
        "no_exclusions": True,
        "no_affinity": True,
        "no_cgroups": True,
        "tasks": tasks,
    }
    (output / "schedule.json").write_bytes(canonical_json(schedule))
    results: list[dict[str, Any] | None] = [None] * len(tasks)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_ordinal = {
            executor.submit(execute_task, task): task["ordinal"] for task in tasks
        }
        try:
            for future in concurrent.futures.as_completed(future_to_ordinal):
                ordinal = future_to_ordinal[future]
                results[ordinal] = future.result()
        except BaseException:
            for future in future_to_ordinal:
                future.cancel()
            raise
    if any(result is None for result in results):
        raise RuntimeError("schedule ended with missing results")
    with (output / "timings.jsonl").open("w") as handle:
        for result in results:
            handle.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    completion = {
        "schema": "fre.composition-interaction-gate.completion.v1",
        "task_count": len(tasks),
        "timings_sha256": sha256_path(output / "timings.jsonl"),
        "schedule_sha256": sha256_path(output / "schedule.json"),
    }
    (output / "completion.json").write_bytes(canonical_json(completion))
    print(canonical_json(completion).decode(), end="")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    lock = subparsers.add_parser("lock")
    lock.add_argument("--source", required=True)
    lock.add_argument("--out", required=True)

    build = subparsers.add_parser("build")
    build.add_argument("--source", required=True)
    build.add_argument("--label", required=True)
    build.add_argument("--out", required=True)
    build.add_argument("--feature", default="")
    build.add_argument("--jobs", type=int, default=32, choices=range(1, 33))

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--binary", required=True)
    verify_parser.add_argument("--out", required=True)

    timing = subparsers.add_parser("run")
    timing.add_argument("--base-binary", required=True)
    timing.add_argument("--candidate-binary", required=True)
    timing.add_argument("--out", required=True)
    timing.add_argument("--workers", type=int, default=96)

    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "lock":
        command_lock(args)
    elif args.command == "build":
        command_build(args)
    elif args.command == "verify":
        command_verify(args)
    elif args.command == "run":
        command_run(args)
    else:
        raise AssertionError(args.command)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"fatal: {error}", file=sys.stderr)
        raise
