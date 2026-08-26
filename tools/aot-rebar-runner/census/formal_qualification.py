#!/usr/bin/env python3
"""Resumable, fail-closed driver for the sealed public-Rebar AOT census."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import pathlib
import platform
import shutil
import signal
import stat
import subprocess
import sys
from typing import Optional

import true_native_census as census


STATE_SCHEMA = "fre.aot-rebar.formal-qualification-state.v1"
ARTIFACT_MANIFEST_SCHEMA = "fre.aot-rebar.formal-artifact-manifest.v1"
BUILD_ENV_ALLOWLIST = (
    "PATH", "HOME", "USER", "LOGNAME", "SHELL", "TMPDIR",
    "CARGO_HOME", "RUSTUP_HOME", "DEVELOPER_DIR", "SDKROOT",
    "MACOSX_DEPLOYMENT_TARGET",
)
RUNNER_RELATIVE_PATH = pathlib.PurePosixPath("release/fre-aot-rebar-runner")


class DriverError(RuntimeError):
    """A formal qualification orchestration failure."""


def resolved_non_source_path(raw: str, source: pathlib.Path, context: str) -> pathlib.Path:
    path = pathlib.Path(raw).expanduser().resolve()
    if path == pathlib.Path(path.anchor):
        raise DriverError(f"{context} cannot be a filesystem root")
    try:
        path.relative_to(source)
    except ValueError:
        return path
    raise DriverError(f"{context} must be outside the sealed source worktree")


def paths_overlap(left: pathlib.Path, right: pathlib.Path) -> bool:
    if left == right:
        return True
    for child, parent in ((left, right), (right, left)):
        try:
            child.relative_to(parent)
        except ValueError:
            continue
        return True
    return False


def resolve_executable(raw: str, context: str) -> str:
    if "/" in raw or (os.altsep is not None and os.altsep in raw):
        path = pathlib.Path(raw).expanduser().resolve(strict=True)
        if not path.is_file() or not os.access(path, os.X_OK):
            raise DriverError(f"{context} is not executable")
        return str(path)
    found = shutil.which(raw)
    if found is None:
        raise DriverError(f"{context} executable {raw!r} is unavailable")
    return str(pathlib.Path(found).resolve(strict=True))


def source_recheck(
    source_dir: pathlib.Path, plan: dict[str, object], git: str = "git"
) -> None:
    expected = plan["candidate_source"]
    actual = census.source_identity(
        source_dir, expected["commit"], expected["tree"], git
    )
    if actual != expected:
        raise DriverError("candidate source identity changed during qualification")


def native_host_target() -> str:
    machine = platform.machine().lower()
    architecture = {
        "amd64": "x86_64",
        "x86_64": "x86_64",
        "aarch64": "aarch64",
        "arm64": "aarch64",
    }.get(machine)
    operating_system = {
        "darwin": "macos",
        "linux": "linux",
    }.get(platform.system().lower())
    if architecture is None or operating_system is None:
        raise DriverError("formal qualification host is not a supported native target")
    return f"{architecture}-{operating_system}"


def require_native_target(plan: dict[str, object]) -> None:
    host = native_host_target()
    target = plan["target"]["triple"]
    if target != host:
        raise DriverError(
            f"sealed plan target {target!r} differs from native host {host!r}"
        )


def rustflags_for_target(target: str) -> str:
    if target.endswith("-linux"):
        return "-C link-arg=-Wl,--export-dynamic"
    if target.endswith("-macos"):
        return "-C link-arg=-Wl,-export_dynamic"
    raise DriverError("formal qualification target has no export-dynamic policy")


def controlled_build_inherited_environment() -> dict[str, str]:
    return {
        name: os.environ[name] for name in BUILD_ENV_ALLOWLIST if name in os.environ
    }


def controlled_build_environment_record(
    plan: dict[str, object],
    job: dict[str, object],
    public_root: pathlib.Path,
    target_dir: pathlib.Path,
    rustc: str,
    rust_target: str,
) -> dict[str, str]:
    environment = controlled_build_inherited_environment()
    expected, comparator = census.frozen_job_expectation(plan, job)
    relative = pathlib.PurePosixPath(job["candidate_klv"]["path"])
    klv_path = (public_root / pathlib.Path(*relative.parts)).resolve()
    environment.update({
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "CARGO_INCREMENTAL": "0",
        "CARGO_NET_OFFLINE": "true",
        "CARGO_BUILD_TARGET": rust_target,
        "CARGO_PROFILE_RELEASE_DEBUG": "0",
        "CARGO_TERM_COLOR": "never",
        "CARGO_TARGET_DIR": str(target_dir),
        "RUST_BACKTRACE": "0",
        "RUSTC": rustc,
        "RUSTC_WRAPPER": "",
        "RUSTC_WORKSPACE_WRAPPER": "",
        "RUSTFLAGS": (
            "-C debuginfo=0 " + rustflags_for_target(plan["target"]["triple"])
        ),
        "FRE_AOT_REBAR_KLV": str(klv_path),
        "FRE_AOT_REBAR_FEATURES": plan["target"]["features"],
        "FRE_AOT_REBAR_SOURCE_COMMIT": plan["candidate_source"]["commit"],
        "FRE_AOT_REBAR_SOURCE_TREE": plan["candidate_source"]["tree"],
        "FRE_AOT_REBAR_EXPECTED_VALUE": str(expected),
        "FRE_AOT_REBAR_EXPECTED_COMPARATOR": comparator,
    })
    return environment


def controlled_build_environment(
    plan: dict[str, object],
    job: dict[str, object],
    public_root: pathlib.Path,
    target_dir: pathlib.Path,
    rustc: str,
    rust_target: str,
) -> dict[str, str]:
    relative = pathlib.PurePosixPath(job["candidate_klv"]["path"])
    klv_path = (public_root / pathlib.Path(*relative.parts)).resolve(strict=True)
    census.relative_public_path(public_root, str(klv_path), "formal build KLV")
    if (
        klv_path.stat().st_size != job["candidate_klv"]["bytes"]
        or census.sha_file(klv_path) != job["candidate_klv"]["sha256"]
    ):
        raise DriverError("formal build KLV differs from the sealed plan")
    return controlled_build_environment_record(
        plan, job, public_root, target_dir, rustc, rust_target
    )


def controlled_runtime_environment() -> dict[str, str]:
    environment = {
        name: os.environ[name]
        for name in (
            "PATH", "HOME", "USER", "LOGNAME", "SHELL", "TMPDIR", "SYSTEMROOT",
        )
        if name in os.environ
    }
    environment.update({"LANG": "C", "LC_ALL": "C", "TZ": "UTC"})
    return environment


def resolve_rust_tool(raw: str, tool: str) -> str:
    if "/" in raw or (os.altsep is not None and os.altsep in raw):
        unresolved = pathlib.Path(raw).expanduser().absolute()
    else:
        found = shutil.which(raw)
        if found is None:
            raise DriverError(f"{tool} executable {raw!r} is unavailable")
        unresolved = pathlib.Path(found).absolute()
    resolved = unresolved.resolve(strict=True)
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise DriverError(f"{tool} is not executable")
    if resolved.name != "rustup":
        return str(resolved)
    completed = subprocess.run(
        [str(resolved), "which", tool],
        env=controlled_runtime_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        raise DriverError(f"rustup could not resolve the active {tool} binary")
    try:
        selected = pathlib.Path(
            completed.stdout.decode("utf-8", "strict").strip()
        ).resolve(strict=True)
    except (UnicodeDecodeError, OSError) as error:
        raise DriverError(f"rustup returned an invalid {tool} path") from error
    if not selected.is_file() or not os.access(selected, os.X_OK):
        raise DriverError(f"rustup-selected {tool} is not executable")
    return str(selected)


def rustc_host_target(rustc: str) -> str:
    completed = subprocess.run(
        [rustc, "-vV"],
        env=controlled_runtime_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        raise DriverError("sealed rustc did not publish its host target")
    try:
        lines = completed.stdout.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError as error:
        raise DriverError("sealed rustc host output is not UTF-8") from error
    hosts = [line.removeprefix("host: ") for line in lines if line.startswith("host: ")]
    if len(hosts) != 1 or not hosts[0]:
        raise DriverError("sealed rustc host target is not canonical")
    return hosts[0]


def normalized_rust_target(rust_target: str) -> str:
    architecture = (
        "x86_64" if rust_target.startswith("x86_64-")
        else "aarch64" if rust_target.startswith("aarch64-") else None
    )
    operating_system = (
        "macos" if rust_target.endswith("-darwin")
        else "linux" if "-linux-" in rust_target else None
    )
    if architecture is None or operating_system is None:
        raise DriverError("sealed rustc host is not a supported formal target")
    return f"{architecture}-{operating_system}"


@contextlib.contextmanager
def installed_process_environment(environment: dict[str, str]):
    inherited = dict(os.environ)
    os.environ.clear()
    os.environ.update(environment)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(inherited)


def build_command(cargo: str, rust_target: str) -> list[str]:
    return [
        cargo, "build", "--release", "--locked", "--offline",
        "--jobs", "1", "--target", rust_target,
        "--package", "fre-aot-rebar-runner",
    ]


def evidence(data: bytes) -> tuple[str, int]:
    return hashlib.sha256(data).hexdigest(), len(data)


def run_build(
    cargo: str,
    rust_target: str,
    source_dir: pathlib.Path,
    environment: dict[str, str],
    timeout: int,
) -> tuple[bool, str, tuple[str, int]]:
    try:
        process = subprocess.Popen(
            build_command(cargo, rust_target),
            cwd=source_dir,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        stdout, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        try:
            process_group = os.getpgid(process.pid)
        except ProcessLookupError:
            process_group = None
        if process_group is not None:
            if process_group != process.pid:
                raise DriverError("Cargo did not retain its owned process group")
            try:
                os.killpg(process_group, signal.SIGTERM)
            except ProcessLookupError:
                pass
        try:
            stdout, _ = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                process_group = os.getpgid(process.pid)
            except ProcessLookupError:
                process_group = None
            if process_group is not None:
                if process_group != process.pid:
                    raise DriverError("Cargo changed its owned process group")
                try:
                    os.killpg(process_group, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                stdout, _ = process.communicate(timeout=5)
            except subprocess.TimeoutExpired as cleanup_error:
                raise DriverError(
                    "owned Cargo process group did not close after SIGKILL"
                ) from cleanup_error
        output = stdout if isinstance(stdout, bytes) else (
            error.output if isinstance(error.output, bytes) else b""
        )
        return False, "timeout", evidence(output)
    except (OSError, subprocess.SubprocessError) as error:
        return False, "failure", evidence(str(error).encode("utf-8", "replace"))
    return process.returncode == 0, "failure", evidence(stdout)


def expected_object_hashes(provenance: dict[str, object]) -> list[str]:
    if provenance["kind"] in {
        "scalar-v2", "prepared-grep-v15-v2", "shared-ordered-many-v2",
        "single-capture-reducer-v5",
    }:
        hashes = [provenance["object_sha256"]]
    else:
        hashes = [component["object_sha256"] for component in provenance["components"]]
    if provenance.get("composite_kind") == "regex-redux-fixed-v1":
        hashes.append(provenance["object_sha256"])
    if provenance.get("kind") == "weighted-capture-reducer-v6":
        hashes.append(provenance["object_sha256"])
    if provenance.get("composite_kind") in {
        "native-multi-grep-reducer-v1", "native-row-scalar-reducer-v1",
    }:
        hashes.append(provenance["object_sha256"])
    return hashes


def configured_build_outputs(
    target_dir: pathlib.Path, rust_target: str, timeout: int
) -> tuple[pathlib.Path, list[pathlib.Path]]:
    output_root = target_dir / rust_target
    runner = (
        output_root / pathlib.Path(*RUNNER_RELATIVE_PATH.parts)
    ).resolve(strict=True)
    provenance_process = subprocess.run(
        [str(runner), "--provenance"],
        env=controlled_runtime_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout,
    )
    if provenance_process.returncode != 0:
        raise DriverError("built runner did not publish provenance")
    fields = census.parse_provenance(provenance_process.stdout)
    provenance = census.provenance_receipt(fields)
    wanted = expected_object_hashes(provenance)
    if not wanted:
        raise DriverError("build provenance has no ordered AOT object identities")
    candidates = sorted(
        output_root.glob("release/build/fre-aot-rebar-runner-*/out/*.o")
    )
    if not candidates:
        raise DriverError("build produced no preserved AOT object candidates")
    by_hash: dict[str, list[pathlib.Path]] = {}
    for candidate in candidates:
        if candidate.is_file() and candidate.stat().st_size > 0:
            by_hash.setdefault(census.sha_file(candidate), []).append(candidate)
    objects = []
    for digest in wanted:
        matches = by_hash.get(digest, [])
        if not matches:
            raise DriverError("build provenance names an object absent from its target dir")
        objects.append(matches[0])
    return runner, objects


def copy_exclusive(source: pathlib.Path, destination: pathlib.Path, mode: int) -> None:
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with source.open("rb") as input_file, os.fdopen(descriptor, "wb", closefd=False) as output:
            shutil.copyfileobj(input_file, output, 1024 * 1024)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(descriptor)


def next_attempt_dir(artifacts: pathlib.Path, ordinal: int, job_id: str) -> pathlib.Path:
    artifacts = artifacts.resolve(strict=True)
    job_token = hashlib.sha256(job_id.encode("utf-8", "strict")).hexdigest()[:16]
    job_root = artifacts / f"{ordinal:03d}-{job_token}"
    job_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if job_root.is_symlink() or job_root.resolve(strict=True).parent != artifacts:
        raise DriverError("formal artifact job directory escaped its sealed root")
    for attempt in range(1_000_000):
        candidate = job_root / f"attempt-{attempt:06d}"
        try:
            candidate.mkdir(mode=0o700)
        except FileExistsError:
            continue
        return candidate
    raise DriverError("formal qualification exhausted attempt ordinals")


def preserve_build(
    runner: pathlib.Path,
    objects: list[pathlib.Path],
    destination: pathlib.Path,
) -> tuple[pathlib.Path, list[pathlib.Path]]:
    if runner.stat().st_size <= 0 or not objects:
        raise DriverError("configured build has an empty runner or object list")
    object_records = []
    for source in objects:
        if source.stat().st_size <= 0:
            raise DriverError("configured build has an empty ordered AOT object")
        object_records.append((source, census.sha_file(source)))
    destination.mkdir(mode=0o700)
    preserved_runner = destination / "fre-aot-rebar-runner"
    runner_sha256 = census.sha_file(runner)
    copy_exclusive(runner, preserved_runner, 0o500)
    if preserved_runner.stat().st_size <= 0 or census.sha_file(preserved_runner) != runner_sha256:
        raise DriverError("preserved runner differs from its configured build")
    preserved_objects = []
    for ordinal, (source, source_sha256) in enumerate(object_records):
        preserved = destination / f"object-{ordinal:04d}-{source.name}"
        copy_exclusive(source, preserved, 0o400)
        if preserved.stat().st_size <= 0 or census.sha_file(preserved) != source_sha256:
            raise DriverError("preserved AOT object differs from its configured build")
        preserved_objects.append(preserved)
    return preserved_runner, preserved_objects


def file_identity(
    raw_path: pathlib.Path | str, context: str, *, executable: bool = False
) -> dict[str, object]:
    path = pathlib.Path(raw_path).resolve(strict=True)
    if not path.is_file() or path.stat().st_size <= 0:
        raise DriverError(f"{context} is not a nonempty regular file")
    if executable and not os.access(path, os.X_OK):
        raise DriverError(f"{context} is not executable")
    return {
        "path": str(path),
        "sha256": census.sha_file(path),
        "bytes": path.stat().st_size,
    }


def verify_bound_inputs(state: dict[str, object]) -> None:
    if (
        controlled_build_inherited_environment()
        != state["build_inherited_environment"]
        or controlled_runtime_environment()
        != state["runtime_inherited_environment"]
    ):
        raise DriverError("controlled inherited environment changed during qualification")
    for name, executable in (
        ("trap_library", False), ("cargo", True), ("rustc", True),
        ("nm", True), ("git", True),
    ):
        sealed = state[name]
        if not isinstance(sealed, dict) or file_identity(
            sealed.get("path", ""), f"sealed {name}", executable=executable
        ) != sealed:
            raise DriverError(f"sealed {name} content changed during qualification")


def artifact_file_record(
    path: pathlib.Path, attempt: pathlib.Path, context: str,
    *, ordinal: Optional[int] = None,
) -> dict[str, object]:
    attempt = attempt.resolve(strict=True)
    if path.is_symlink():
        raise DriverError(f"{context} is a symbolic link")
    resolved = path.resolve(strict=True)
    try:
        relative = resolved.relative_to(attempt)
    except ValueError as error:
        raise DriverError(f"{context} escaped its attempt directory") from error
    metadata = resolved.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0:
        raise DriverError(f"{context} is not a nonempty regular file")
    record: dict[str, object] = {
        "path": relative.as_posix(),
        "sha256": census.sha_file(resolved),
        "bytes": metadata.st_size,
    }
    if ordinal is not None:
        record["ordinal"] = ordinal
    return record


def artifact_side_record(
    runner: pathlib.Path, objects: list[pathlib.Path], attempt: pathlib.Path,
    context: str,
) -> dict[str, object]:
    if not objects:
        raise DriverError(f"{context} has no ordered AOT objects")
    return {
        "runner": artifact_file_record(runner, attempt, f"{context} runner"),
        "objects": [
            artifact_file_record(
                path, attempt, f"{context} object {ordinal}", ordinal=ordinal
            )
            for ordinal, path in enumerate(objects)
        ],
    }


def validate_artifact_file_record(
    record: object, attempt: pathlib.Path, context: str,
    *, side_name: str, ordinal: Optional[int] = None,
) -> pathlib.Path:
    if not isinstance(record, dict):
        raise DriverError(f"{context} record is not an object")
    keys = {"path", "sha256", "bytes"} | ({"ordinal"} if ordinal is not None else set())
    if set(record) != keys:
        raise DriverError(f"{context} record schema keys differ")
    if ordinal is not None and record["ordinal"] != ordinal:
        raise DriverError(f"{context} ordinal differs")
    census.require_hex64(record["sha256"], f"{context} digest")
    if (
        not isinstance(record["bytes"], int)
        or isinstance(record["bytes"], bool)
        or record["bytes"] <= 0
    ):
        raise DriverError(f"{context} byte count is invalid")
    if not isinstance(record["path"], str):
        raise DriverError(f"{context} path is not a string")
    relative = pathlib.PurePosixPath(record["path"])
    if relative.is_absolute() or not relative.parts or any(
        part in {"", ".", ".."} for part in relative.parts
    ):
        raise DriverError(f"{context} path is not canonical relative form")
    if len(relative.parts) != 2 or relative.parts[0] != side_name:
        raise DriverError(f"{context} path differs from its declared artifact side")
    declared_side = attempt / side_name
    if declared_side.is_symlink():
        raise DriverError(f"{context} has a symbolic-link path component")
    try:
        side_metadata = declared_side.lstat()
    except FileNotFoundError as error:
        raise DriverError(f"{context} artifact side is absent") from error
    if (
        not stat.S_ISDIR(side_metadata.st_mode)
        or declared_side.resolve(strict=True) != declared_side
    ):
        raise DriverError(f"{context} artifact side is not canonical")
    path = attempt.joinpath(*relative.parts)
    if path.is_symlink():
        raise DriverError(f"{context} is a symbolic link")
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise DriverError(f"{context} is absent") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0:
        raise DriverError(f"{context} is not a nonempty regular file")
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(attempt)
    except ValueError as error:
        raise DriverError(f"{context} escaped its attempt directory") from error
    if metadata.st_mode & stat.S_IWUSR:
        raise DriverError(f"{context} remains owner-writable")
    if metadata.st_size != record["bytes"] or census.sha_file(resolved) != record["sha256"]:
        raise DriverError(f"{context} content differs from its sealed identity")
    return resolved


def validate_artifact_side(
    value: object, attempt: pathlib.Path, context: str, side_name: str,
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {"runner", "objects"}:
        raise DriverError(f"{context} schema keys differ")
    objects = value["objects"]
    if not isinstance(objects, list) or not objects:
        raise DriverError(f"{context} has no ordered objects")
    runner = validate_artifact_file_record(
        value["runner"], attempt, f"{context} runner", side_name=side_name
    )
    object_paths = [
        validate_artifact_file_record(
            record, attempt, f"{context} object {ordinal}",
            side_name=side_name, ordinal=ordinal,
        )
        for ordinal, record in enumerate(objects)
    ]
    side_dir = runner.parent
    if side_dir.is_symlink() or side_dir.parent != attempt:
        raise DriverError(f"{context} directory escaped its attempt")
    if side_dir.stat().st_mode & stat.S_IWUSR:
        raise DriverError(f"{context} directory remains owner-writable")
    if set(side_dir.iterdir()) != {runner, *object_paths}:
        raise DriverError(f"{context} directory has unsealed files")
    return value


def validate_artifact_manifest(
    value: object, manifest_path: pathlib.Path, plan: dict[str, object],
    receipt: Optional[dict[str, object]] = None,
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise DriverError("formal artifact manifest is not an object")
    if set(value) != {
        "schema", "plan_sha256", "job_id", "receipt_sha256", "primary",
        "replica", "artifact_manifest_sha256",
    }:
        raise DriverError("formal artifact manifest schema keys differ")
    if (
        value["schema"] != ARTIFACT_MANIFEST_SCHEMA
        or value["plan_sha256"] != plan["plan_sha256"]
    ):
        raise DriverError("formal artifact manifest plan binding differs")
    census.validate_digest(
        value, "artifact_manifest_sha256", "formal artifact manifest"
    )
    census.require_hex64(value["receipt_sha256"], "artifact manifest receipt")
    jobs = {job["job_id"]: job for job in plan["jobs"]}
    job = jobs.get(value["job_id"])
    if job is None or not job["is_runtime"] or not job["exact_adapter"]:
        raise DriverError("formal artifact manifest names an ineligible job")
    attempt = manifest_path.parent.resolve(strict=True)
    if manifest_path.is_symlink() or manifest_path.resolve(strict=True).parent != attempt:
        raise DriverError("formal artifact manifest escaped its attempt")
    manifest_metadata = manifest_path.lstat()
    if (
        not stat.S_ISREG(manifest_metadata.st_mode)
        or manifest_metadata.st_mode & stat.S_IWUSR
    ):
        raise DriverError("formal artifact manifest is not a sealed regular file")
    if attempt.is_symlink() or attempt.stat().st_mode & stat.S_IWUSR:
        raise DriverError("formal artifact attempt remains owner-writable")
    present_names = {"artifact-manifest.json"}
    for name in ("primary", "replica"):
        side = value[name]
        if side is not None:
            validate_artifact_side(
                side, attempt, f"formal {name} artifact", name
            )
            present_names.add(name)
    if {path.name for path in attempt.iterdir()} != present_names:
        raise DriverError("formal artifact attempt has unsealed files")
    if receipt is not None:
        if (
            receipt["receipt_sha256"] != value["receipt_sha256"]
            or receipt["job"]["job_id"] != value["job_id"]
        ):
            raise DriverError("formal artifact manifest receipt binding differs")
        receipt_artifacts = receipt["artifacts"]
        if receipt_artifacts["primary"] is not None:
            for name in ("primary", "replica"):
                side = value[name]
                claimed = receipt_artifacts[name]
                if side is None:
                    raise DriverError("qualification receipt has no preserved artifact side")
                if side["runner"]["sha256"] != claimed["runner_sha256"] or [
                    {
                        "ordinal": row["ordinal"],
                        "sha256": row["sha256"],
                        "bytes": row["bytes"],
                    }
                    for row in side["objects"]
                ] != claimed["objects"]:
                    raise DriverError(
                        f"preserved {name} artifacts differ from qualification receipt"
                    )
    return value


def close_attempt(attempt: pathlib.Path) -> None:
    for name in ("primary", "replica"):
        side = attempt / name
        if side.is_dir() and not side.is_symlink():
            side.chmod(0o500)
    attempt.chmod(0o500)


def write_artifact_manifest(
    attempt: pathlib.Path, receipt: dict[str, object], plan: dict[str, object],
    primary_runner: Optional[pathlib.Path], primary_objects: list[pathlib.Path],
    replica_runner: Optional[pathlib.Path], replica_objects: list[pathlib.Path],
) -> dict[str, object]:
    primary = (
        artifact_side_record(primary_runner, primary_objects, attempt, "primary artifact")
        if primary_runner is not None else None
    )
    replica = (
        artifact_side_record(replica_runner, replica_objects, attempt, "replica artifact")
        if replica_runner is not None else None
    )
    value = census.add_digest({
        "schema": ARTIFACT_MANIFEST_SCHEMA,
        "plan_sha256": plan["plan_sha256"],
        "job_id": receipt["job"]["job_id"],
        "receipt_sha256": receipt["receipt_sha256"],
        "primary": primary,
        "replica": replica,
    }, "artifact_manifest_sha256")
    manifest_path = attempt / "artifact-manifest.json"
    census.write_exclusive(manifest_path, value)
    close_attempt(attempt)
    return validate_artifact_manifest(
        census.load_json(manifest_path), manifest_path, plan, receipt
    )


def discard_partial_side(side: pathlib.Path, attempt: pathlib.Path) -> None:
    if not side.exists() and not side.is_symlink():
        return
    if side.is_symlink() or side.parent.resolve(strict=True) != attempt.resolve(strict=True):
        raise DriverError("partial artifact side escaped its attempt")
    shutil.rmtree(side)


def persist_job_receipt(
    receipt_path: pathlib.Path, receipt: dict[str, object],
    plan: dict[str, object], state: dict[str, object], attempt: pathlib.Path,
    primary_runner: Optional[pathlib.Path], primary_objects: list[pathlib.Path],
    replica_runner: Optional[pathlib.Path], replica_objects: list[pathlib.Path],
) -> dict[str, object]:
    verify_bound_inputs(state)
    validated = census.validate_receipt(receipt, plan)
    if primary_runner is not None or replica_runner is not None:
        write_artifact_manifest(
            attempt, validated, plan, primary_runner, primary_objects,
            replica_runner, replica_objects,
        )
    else:
        close_attempt(attempt)
    return write_and_revalidate_receipt(receipt_path, validated, plan)


def audit_preserved_artifacts(
    artifacts: pathlib.Path,
    receipts_by_job: dict[str, tuple[pathlib.Path, dict[str, object]]],
    plan: dict[str, object],
) -> None:
    artifacts = artifacts.resolve(strict=True)
    matching: set[tuple[str, str]] = set()
    receipts_by_identity = {
        (receipt["job"]["job_id"], receipt["receipt_sha256"]): receipt
        for _, receipt in receipts_by_job.values()
    }
    for manifest_path in sorted(artifacts.glob("*/attempt-*/artifact-manifest.json")):
        relative = manifest_path.relative_to(artifacts)
        if (
            len(relative.parts) != 3
            or not relative.parts[1].startswith("attempt-")
            or manifest_path.is_symlink()
            or manifest_path.parent.is_symlink()
            or manifest_path.parent.parent.is_symlink()
        ):
            raise DriverError("formal artifact manifest path is not canonical")
        try:
            manifest_path.resolve(strict=True).relative_to(artifacts)
        except ValueError as error:
            raise DriverError("formal artifact manifest escaped its root") from error
        value = census.load_json(manifest_path)
        if not isinstance(value, dict):
            raise DriverError("formal artifact manifest is not an object")
        identity = (value.get("job_id"), value.get("receipt_sha256"))
        receipt = receipts_by_identity.get(identity)
        validate_artifact_manifest(value, manifest_path, plan, receipt)
        if receipt is not None and receipt["artifacts"]["primary"] is not None:
            matching.add(identity)
    for identity, receipt in receipts_by_identity.items():
        if receipt["artifacts"]["primary"] is not None and identity not in matching:
            raise DriverError(
                f"qualification receipt for {identity[0]} has no revalidated artifacts"
            )


def write_and_revalidate_receipt(
    receipt_path: pathlib.Path,
    receipt: dict[str, object],
    plan: dict[str, object],
) -> dict[str, object]:
    census.write_exclusive(receipt_path, receipt)
    return census.validate_receipt(census.load_json(receipt_path), plan)


def index_valid_receipts(
    receipts: pathlib.Path, plan: dict[str, object]
) -> dict[str, tuple[pathlib.Path, dict[str, object]]]:
    """Index resumable receipts by authenticated content, never by filename."""
    indexed: dict[str, tuple[pathlib.Path, dict[str, object]]] = {}
    for path in sorted(receipts.glob("*.json")):
        receipt = census.validate_receipt(census.load_json(path), plan)
        job_id = receipt["job"]["job_id"]
        if job_id in indexed:
            raise DriverError(f"duplicate validated receipt content for job {job_id}")
        indexed[job_id] = (path, receipt)
    return indexed


def failure_outcome(error: BaseException) -> str:
    return "timeout" if isinstance(error, subprocess.TimeoutExpired) else "failure"


def failure_receipt(
    plan_path: pathlib.Path,
    job_id: str,
    stage: str,
    outcome: str,
    output_evidence: Optional[tuple[str, int]],
) -> dict[str, object]:
    arguments = argparse.Namespace(
        plan=str(plan_path),
        job_id=job_id,
        stage=stage,
        outcome=outcome,
        evidence_sha256=(output_evidence[0] if output_evidence else None),
        evidence_bytes=(output_evidence[1] if output_evidence else None),
    )
    return census.record_failure(arguments)


def state_record(
    plan: dict[str, object], source: pathlib.Path, public_root: pathlib.Path,
    primary_target: pathlib.Path, replica_target: pathlib.Path,
    receipts: pathlib.Path, artifacts: pathlib.Path, trap_library: pathlib.Path,
    cargo: str, rustc: str, nm: str, git: str, rust_target: str,
    build_timeout: int, timeout: int,
) -> dict[str, object]:
    manifest = plan["public_corpus"].get("manifest")
    expected_results = plan["public_corpus"].get("expected_results")
    environment_projection = [
        {
            "job_id": job["job_id"],
            "primary": controlled_build_environment_record(
                plan, job, public_root, primary_target, rustc, rust_target
            ),
            "replica": controlled_build_environment_record(
                plan, job, public_root, replica_target, rustc, rust_target
            ),
        }
        for job in plan["jobs"]
        if job["is_runtime"] and job["exact_adapter"]
    ]
    return census.add_digest({
        "schema": STATE_SCHEMA,
        "plan_sha256": plan["plan_sha256"],
        "public_manifest_sha256": (
            manifest["file_sha256"] if isinstance(manifest, dict) else None
        ),
        "schedule_file_sha256": [
            schedule["file_sha256"]
            for schedule in plan["public_corpus"]["schedules"]
        ],
        "expected_results_sha256": (
            expected_results["runtime_jobs_sha256"]
            if isinstance(expected_results, dict) else None
        ),
        "source_dir": str(source),
        "public_klv_root": str(public_root),
        "primary_target_dir": str(primary_target),
        "replica_target_dir": str(replica_target),
        "receipts_dir": str(receipts),
        "artifacts_dir": str(artifacts),
        "build_timeout_seconds": build_timeout,
        "qualification_timeout_seconds": timeout,
        "build_inherited_environment": controlled_build_inherited_environment(),
        "runtime_inherited_environment": controlled_runtime_environment(),
        "build_environments_sha256": census.sha_bytes(
            census.canonical(environment_projection).encode()
        ),
        "rust_target": rust_target,
        "trap_library": file_identity(trap_library, "runtime trap library"),
        "cargo": file_identity(cargo, "Cargo", executable=True),
        "rustc": file_identity(rustc, "rustc", executable=True),
        "nm": file_identity(nm, "nm", executable=True),
        "git": file_identity(git, "Git", executable=True),
    }, "state_sha256")


def ensure_state(path: pathlib.Path, expected: dict[str, object]) -> None:
    if path.exists():
        value = census.load_json(path)
        if not isinstance(value, dict):
            raise DriverError("formal qualification state is not an object")
        census.validate_digest(value, "state_sha256", "formal qualification state")
        if value != expected:
            raise DriverError("formal qualification resume state differs from this invocation")
    else:
        census.write_exclusive(path, expected)


def receipt_filename(ordinal: int, job_id: str) -> str:
    token = hashlib.sha256(job_id.encode("utf-8", "strict")).hexdigest()[:16]
    return f"{ordinal:03d}-{token}.json"


def run(args: argparse.Namespace) -> dict[str, object]:
    if args.build_timeout <= 0 or args.timeout <= 0:
        raise DriverError("formal qualification timeouts must be positive")
    plan_path = pathlib.Path(args.plan).resolve(strict=True)
    plan = census.validate_plan(census.load_json(plan_path))
    require_native_target(plan)
    source = pathlib.Path(args.source_dir).resolve(strict=True)
    public_root = pathlib.Path(args.public_klv_root).resolve(strict=True)
    trap_library = pathlib.Path(args.trap_library).resolve(strict=True)
    if not public_root.is_dir():
        raise DriverError("public KLV root is not a directory")
    if not trap_library.is_file() or trap_library.stat().st_size <= 0:
        raise DriverError("runtime trap library is not a nonempty regular file")
    cargo = resolve_rust_tool(args.cargo, "cargo")
    rustc = resolve_rust_tool(args.rustc, "rustc")
    nm = resolve_executable(args.nm, "nm")
    git = resolve_executable(args.git, "Git")
    rust_target = rustc_host_target(rustc)
    if normalized_rust_target(rust_target) != plan["target"]["triple"]:
        raise DriverError("sealed rustc host target differs from the sealed plan")
    source_recheck(source, plan, git)

    work = resolved_non_source_path(args.work_dir, source, "qualification work directory")
    primary_target = resolved_non_source_path(
        args.primary_target_dir, source, "primary target directory"
    )
    replica_target = resolved_non_source_path(
        args.replica_target_dir, source, "replica target directory"
    )
    if primary_target == replica_target:
        raise DriverError("independent builds require two distinct target directories")
    mutable_roots = (
        (work, "qualification work"),
        (primary_target, "primary target"),
        (replica_target, "replica target"),
    )
    for index, (left, left_name) in enumerate(mutable_roots):
        if paths_overlap(left, public_root):
            raise DriverError(f"{left_name} directory overlaps the public KLV root")
        for right, right_name in mutable_roots[index + 1:]:
            if paths_overlap(left, right):
                raise DriverError(
                    f"{left_name} and {right_name} directories overlap"
                )
    state_path = work / "qualification-state.json"
    if not state_path.exists():
        for path, context in (
            (work, "qualification work directory"),
            (primary_target, "primary target directory"),
            (replica_target, "replica target directory"),
        ):
            if path.exists() and (not path.is_dir() or next(path.iterdir(), None) is not None):
                raise DriverError(f"new {context} is not empty")
    work.mkdir(parents=True, exist_ok=True, mode=0o700)
    primary_target.mkdir(parents=True, exist_ok=True, mode=0o700)
    replica_target.mkdir(parents=True, exist_ok=True, mode=0o700)
    receipts_path = work / "receipts"
    artifacts_path = work / "artifacts"
    receipts_path.mkdir(exist_ok=True, mode=0o700)
    artifacts_path.mkdir(exist_ok=True, mode=0o700)
    receipts = receipts_path.resolve(strict=True)
    artifacts = artifacts_path.resolve(strict=True)
    if receipts.parent != work or artifacts.parent != work:
        raise DriverError("qualification receipt or artifact directory escaped its work root")
    state = state_record(
        plan, source, public_root, primary_target, replica_target, receipts,
        artifacts, trap_library, cargo, rustc, nm, git, rust_target,
        args.build_timeout, args.timeout,
    )
    ensure_state(state_path, state)
    verify_bound_inputs(state)

    runtime_ids = plan["denominators"]["runtime_jobs"]["ids"]
    if len(runtime_ids) != census.EXPECTED_RUNTIME_JOBS:
        raise DriverError("formal qualification plan does not retain exactly 311 runtime jobs")
    jobs = {job["job_id"]: job for job in plan["jobs"]}
    receipts_by_job = index_valid_receipts(receipts, plan)
    audit_preserved_artifacts(artifacts, receipts_by_job, plan)
    for ordinal, job_id in enumerate(runtime_ids):
        source_recheck(source, plan, git)
        verify_bound_inputs(state)
        job = jobs[job_id]
        if not job["exact_adapter"]:
            continue
        if job_id in receipts_by_job:
            continue

        receipt_path = receipts / receipt_filename(ordinal, job_id)
        if receipt_path.exists():
            raise DriverError("canonical receipt path is occupied by unrelated content")
        attempt = next_attempt_dir(artifacts, ordinal, job_id)
        primary_runner: Optional[pathlib.Path] = None
        primary_objects: list[pathlib.Path] = []
        replica_runner: Optional[pathlib.Path] = None
        replica_objects: list[pathlib.Path] = []
        primary_environment = controlled_build_environment(
            plan, job, public_root, primary_target, rustc, rust_target
        )
        ok, outcome, build_evidence = run_build(
            cargo, rust_target, source, primary_environment, args.build_timeout
        )
        source_recheck(source, plan, git)
        if not ok:
            verify_bound_inputs(state)
            validated = persist_job_receipt(
                receipt_path,
                failure_receipt(
                    plan_path, job_id, "build", outcome, build_evidence
                ),
                plan, state, attempt, primary_runner, primary_objects,
                replica_runner, replica_objects,
            )
            receipts_by_job[job_id] = (receipt_path, validated)
            continue
        try:
            configured_runner, configured_objects = configured_build_outputs(
                primary_target, rust_target, args.timeout
            )
            primary_runner, primary_objects = preserve_build(
                configured_runner, configured_objects, attempt / "primary"
            )
        except (census.CensusError, DriverError, OSError, subprocess.SubprocessError) as error:
            source_recheck(source, plan, git)
            verify_bound_inputs(state)
            discard_partial_side(attempt / "primary", attempt)
            diagnostic = str(error).encode("utf-8", "replace")
            validated = persist_job_receipt(
                receipt_path,
                failure_receipt(
                    plan_path, job_id, "provenance", failure_outcome(error),
                    evidence(diagnostic)
                ),
                plan, state, attempt, primary_runner, primary_objects,
                replica_runner, replica_objects,
            )
            receipts_by_job[job_id] = (receipt_path, validated)
            continue

        source_recheck(source, plan, git)
        verify_bound_inputs(state)
        replica_environment = controlled_build_environment(
            plan, job, public_root, replica_target, rustc, rust_target
        )
        ok, outcome, build_evidence = run_build(
            cargo, rust_target, source, replica_environment, args.build_timeout
        )
        source_recheck(source, plan, git)
        if not ok:
            verify_bound_inputs(state)
            validated = persist_job_receipt(
                receipt_path,
                failure_receipt(
                    plan_path, job_id, "build", outcome, build_evidence
                ),
                plan, state, attempt, primary_runner, primary_objects,
                replica_runner, replica_objects,
            )
            receipts_by_job[job_id] = (receipt_path, validated)
            continue
        try:
            configured_runner, configured_objects = configured_build_outputs(
                replica_target, rust_target, args.timeout
            )
            replica_runner, replica_objects = preserve_build(
                configured_runner, configured_objects, attempt / "replica"
            )
        except (census.CensusError, DriverError, OSError, subprocess.SubprocessError) as error:
            source_recheck(source, plan, git)
            verify_bound_inputs(state)
            discard_partial_side(attempt / "replica", attempt)
            diagnostic = str(error).encode("utf-8", "replace")
            validated = persist_job_receipt(
                receipt_path,
                failure_receipt(
                    plan_path, job_id, "provenance", failure_outcome(error),
                    evidence(diagnostic)
                ),
                plan, state, attempt, primary_runner, primary_objects,
                replica_runner, replica_objects,
            )
            receipts_by_job[job_id] = (receipt_path, validated)
            continue

        source_recheck(source, plan, git)
        verify_bound_inputs(state)
        qualification_arguments = argparse.Namespace(
            plan=str(plan_path),
            job_id=job_id,
            public_klv_root=str(public_root),
            primary_runner=str(primary_runner),
            replica_runner=str(replica_runner),
            primary_object=[str(path) for path in primary_objects],
            replica_object=[str(path) for path in replica_objects],
            trap_library=str(trap_library),
            nm=nm,
            timeout=args.timeout,
        )
        try:
            with installed_process_environment(controlled_runtime_environment()):
                receipt = census.qualify_job(qualification_arguments)
        except (census.CensusError, OSError, subprocess.SubprocessError, ValueError) as error:
            diagnostic = str(error).encode("utf-8", "replace")
            receipt = failure_receipt(
                plan_path, job_id, "qualification", failure_outcome(error),
                evidence(diagnostic)
            )
        source_recheck(source, plan, git)
        verify_bound_inputs(state)
        validated = persist_job_receipt(
            receipt_path, receipt, plan, state, attempt, primary_runner, primary_objects,
            replica_runner, replica_objects,
        )
        receipts_by_job[job_id] = (receipt_path, validated)

    source_recheck(source, plan, git)
    verify_bound_inputs(state)
    receipts_by_job = index_valid_receipts(receipts, plan)
    audit_preserved_artifacts(artifacts, receipts_by_job, plan)
    exact_runtime_ids = {
        job_id for job_id in runtime_ids if jobs[job_id]["exact_adapter"]
    }
    if set(receipts_by_job) != exact_runtime_ids:
        missing = sorted(exact_runtime_ids - set(receipts_by_job))
        extra = sorted(set(receipts_by_job) - exact_runtime_ids)
        raise DriverError(
            "validated receipt population is incomplete before summary: "
            f"missing={len(missing)} extra={len(extra)}"
        )
    if len(receipts_by_job) + len(set(runtime_ids) - exact_runtime_ids) != 311:
        raise DriverError("formal receipt/disposition audit does not close exactly 311 jobs")
    summary = census.summarize(argparse.Namespace(
        plan=str(plan_path), receipts=str(receipts)
    ))
    if summary["canonical_runtime_denominator"]["count"] != census.EXPECTED_RUNTIME_JOBS:
        raise DriverError("formal summary does not retain exactly 311 runtime jobs")
    summary_path = work / "summary.json"
    if summary_path.exists():
        if census.load_json(summary_path) != summary:
            raise DriverError("existing formal summary differs from revalidated receipts")
    else:
        census.write_exclusive(summary_path, summary)
    source_recheck(source, plan, git)
    verify_bound_inputs(state)
    audit_preserved_artifacts(artifacts, receipts_by_job, plan)
    return summary


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--plan", required=True)
    result.add_argument("--source-dir", required=True)
    result.add_argument("--public-klv-root", required=True)
    result.add_argument("--work-dir", required=True)
    result.add_argument("--primary-target-dir", required=True)
    result.add_argument("--replica-target-dir", required=True)
    result.add_argument("--trap-library", required=True)
    result.add_argument("--cargo", default="cargo")
    result.add_argument("--rustc", default="rustc")
    result.add_argument("--nm", default="nm")
    result.add_argument("--git", default="git")
    result.add_argument("--build-timeout", type=int, default=3600)
    result.add_argument("--timeout", type=int, default=300)
    return result


def main() -> int:
    args = parser().parse_args()
    if args.build_timeout <= 0 or args.timeout <= 0:
        print("formal-qualification: timeouts must be positive", file=sys.stderr)
        return 2
    try:
        summary = run(args)
    except (
        census.CensusError, DriverError, OSError, ValueError,
        subprocess.SubprocessError,
    ) as error:
        print(f"formal-qualification: {error}", file=sys.stderr)
        return 2
    print(json.dumps({
        "schema": summary["schema"],
        "summary_sha256": summary["summary_sha256"],
        "runtime_jobs": summary["canonical_runtime_denominator"]["count"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
