#!/usr/bin/env python3
"""Run the sealed Search V26 gate exactly once on three explicit Linux CPUs.

There is deliberately no load/headroom coordinator or wait-for-GO path. The
launcher first completes and validates all three untimed semantic preflights,
consumes one-shot authority only after that global barrier, pins the three
timing shards concurrently with sealed `/usr/bin/taskset`, and analyzes the
outputs. Sealed multi-hour phase deadlines use Linux pidfds to escalate only
the exact launcher-created children; unrelated processes are never targeted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import secrets
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import analyze_v26_gate as gate

SEALED_RUNNER_ENVIRONMENT = {"LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
PREFLIGHT_DEADLINE_SECONDS = 2 * 60 * 60
TIMING_DEADLINE_SECONDS = 8 * 60 * 60
ANALYZER_DEADLINE_SECONDS = 2 * 60 * 60
OWN_CHILD_TERM_GRACE_SECONDS = 30
OWN_CHILD_KILL_GRACE_SECONDS = 30


def require_pidfd_supervision() -> None:
    """Fail before launch unless this Linux Python/kernel can bind exact children."""
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise gate.GateError("Linux pidfd child supervision is unavailable")
    try:
        descriptor = os.pidfd_open(os.getpid(), 0)
    except OSError as error:
        raise gate.GateError(f"Linux pidfd child supervision is unusable: {error}") from error
    os.close(descriptor)


def reserve_pidfd_slots(count: int) -> list[int]:
    """Reserve descriptor capacity before any child is created."""
    descriptors: list[int] = []
    try:
        for _ in range(count):
            descriptors.append(
                os.open(
                    "/dev/null",
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
                )
            )
        return descriptors
    except OSError as error:
        for descriptor in descriptors:
            os.close(descriptor)
        raise gate.GateError(f"cannot reserve pidfd supervision slots: {error}") from error


def open_child_pidfd(
    process: subprocess.Popen[bytes],
    reserved_descriptor: int,
) -> int:
    """Replace one reserved descriptor with a pidfd for an unreaped child."""
    os.close(reserved_descriptor)
    try:
        return os.pidfd_open(process.pid, 0)
    except OSError as error:
        # The caller still holds every per-child startup-barrier writer. It
        # closes those writers on this path, causing every unreleased child to
        # exit before any authority/input/timer access. No raw-PID fallback
        # exists.
        raise gate.GateError(
            f"cannot bind launcher-created child to a pidfd: {error}"
        ) from error


def release_startup_barrier(readiness_writer: int) -> None:
    marker = memoryview(b"\x01")
    try:
        while marker:
            written = os.write(readiness_writer, marker)
            if written <= 0:
                raise gate.GateError("short write to supervision startup barrier")
            marker = marker[written:]
    except OSError as error:
        raise gate.GateError(
            f"cannot release pidfd-supervised children: {error}"
        ) from error
    finally:
        os.close(readiness_writer)


def reap_unbound_barrier_child(
    process: subprocess.Popen[bytes] | None,
    label: str,
) -> None:
    if process is None:
        return
    try:
        process.wait(timeout=OWN_CHILD_TERM_GRACE_SECONDS)
    except subprocess.TimeoutExpired as error:
        raise gate.GateError(
            f"{label} remained unreaped behind its closed startup barrier"
        ) from error


def supervision_pipe() -> tuple[int, int]:
    try:
        # Python creates non-inheritable descriptors; Popen pass_fds exposes
        # only the read end to the intended direct child.
        return os.pipe()
    except OSError as error:
        raise gate.GateError(f"cannot create supervision readiness pipe: {error}") from error


def wait_until(
    process: subprocess.Popen[bytes],
    deadline: float,
) -> int | None:
    return_code = process.poll()
    if return_code is not None:
        return return_code
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    try:
        return process.wait(timeout=remaining)
    except subprocess.TimeoutExpired:
        return None


def signal_live_pidfd(pidfd: int, process: subprocess.Popen[bytes], signum: int) -> None:
    """Signal only the still-live child identity captured by this pidfd."""
    if process.poll() is not None:
        return
    try:
        signal.pidfd_send_signal(pidfd, signum, None, 0)
    except ProcessLookupError:
        return
    except OSError as error:
        raise gate.GateError(f"cannot signal launcher-created child pidfd: {error}") from error


def supervise_children(
    label: str,
    children: list[tuple[int, subprocess.Popen[bytes], int]],
    deadline: float,
    *,
    consumed_attempt: bool,
) -> list[tuple[int, int]]:
    """Wait naturally, then escalate only exact pidfd-bound children at expiry."""
    try:
        return_codes: list[tuple[int, int]] = []
        timed_out = False
        for child_id, process, _pidfd in children:
            return_code = wait_until(process, deadline)
            if return_code is None:
                timed_out = True
                break
            return_codes.append((child_id, return_code))
        if not timed_out:
            return return_codes

        signal_errors: list[str] = []
        for child_id, process, pidfd in children:
            try:
                signal_live_pidfd(pidfd, process, signal.SIGTERM)
            except gate.GateError as error:
                signal_errors.append(f"child {child_id} SIGTERM: {error}")
        term_deadline = time.monotonic() + OWN_CHILD_TERM_GRACE_SECONDS
        for _child_id, process, _pidfd in children:
            wait_until(process, term_deadline)

        for child_id, process, pidfd in children:
            try:
                signal_live_pidfd(pidfd, process, signal.SIGKILL)
            except gate.GateError as error:
                signal_errors.append(f"child {child_id} SIGKILL: {error}")
        kill_deadline = time.monotonic() + OWN_CHILD_KILL_GRACE_SECONDS
        unreaped: list[int] = []
        for child_id, process, _pidfd in children:
            if wait_until(process, kill_deadline) is None:
                unreaped.append(child_id)

        terminal = (
            "; one-shot authority remains consumed and this attempt is terminal"
            if consumed_attempt
            else ""
        )
        suffix = f"; unreaped child IDs after SIGKILL: {unreaped}" if unreaped else ""
        if signal_errors:
            suffix += f"; pidfd signaling errors: {signal_errors}"
        raise gate.GateError(
            f"{label} exceeded its sealed phase deadline{terminal}{suffix}"
        )
    finally:
        for _child_id, _process, pidfd in children:
            os.close(pidfd)


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


def hash_optional_file(path: Path, maximum_bytes: int) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return "unavailable"
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            return "unavailable"
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, min(1 << 20, maximum_bytes + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum_bytes:
                return "unavailable"
            digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return "unavailable"
    finally:
        os.close(descriptor)


def host_fingerprint_components() -> dict[str, Any]:
    uname = os.uname()
    return {
        "schema": "fre-search-v26-development-gate-host-fingerprint-input-v1",
        "system": uname.sysname,
        "node": uname.nodename,
        "release": uname.release,
        "version": uname.version,
        "machine": uname.machine,
        "machine_id_sha256": hash_optional_file(Path("/etc/machine-id"), 4096),
        "cpuinfo_sha256": hash_optional_file(Path("/proc/cpuinfo"), 16 * 1024 * 1024),
        "online_cpus_sha256": hash_optional_file(
            Path("/sys/devices/system/cpu/online"), 4096
        ),
    }


def host_fingerprint_sha256(components: dict[str, Any]) -> str:
    hasher = hashlib.sha256()
    hasher.update(b"FRE-SEARCH-V26-DEVELOPMENT-GATE-HOST-V1\0\x01")
    hasher.update(canonical_json_bytes(components))
    return hasher.hexdigest()


def require_cpu_ids(values: list[int]) -> list[int]:
    if len(values) != 3:
        raise gate.GateError("exactly three --cpu arguments are required")
    cpu_ids = [
        gate.strict_integer(value, f"CPU ID {index}", minimum=0)
        for index, value in enumerate(values)
    ]
    if len(set(cpu_ids)) != 3:
        raise gate.GateError("the three explicit CPU IDs must be distinct")
    return cpu_ids


def consume_seal_once(
    registry: Path,
    seal_sha256: str,
    authorization_nonce: str,
    run_manifest_sha256: str,
    run_nonce: str,
    preflight_manifest_sha256: str,
) -> Path:
    try:
        resolved_registry = registry.resolve(strict=True)
    except OSError as error:
        raise gate.GateError(f"cannot resolve one-shot registry: {error}") from error
    if resolved_registry != registry or not registry.is_dir():
        raise gate.GateError("one-shot registry is not a canonical real directory")
    marker_path = registry / f"{seal_sha256}.consumed-v1.json"
    marker = {
        "schema": "fre-search-v26-development-gate-consumed-seal-v1",
        "one_shot_seal_sha256": seal_sha256,
        "authorization_nonce": authorization_nonce,
        "run_manifest_sha256": run_manifest_sha256,
        "run_nonce": run_nonce,
        "preflight_manifest_sha256": preflight_manifest_sha256,
    }
    publish_bytes_create_new(marker_path, canonical_json_bytes(marker))
    return marker_path


def publish_analyzer_output(
    command: list[str],
    output_path: Path,
    *,
    pass_fds: tuple[int, ...],
    environment: dict[str, str],
) -> int:
    if output_path.exists():
        raise gate.GateError(f"analysis output already exists: {output_path}")
    temporary = output_path.with_name(
        f".{output_path.name}.partial.{os.getpid()}.{secrets.token_hex(8)}"
    )
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        reservations = reserve_pidfd_slots(1)
    except Exception:
        os.close(descriptor)
        os.unlink(temporary)
        raise
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            deadline = time.monotonic() + ANALYZER_DEADLINE_SECONDS
            readiness_reader, readiness_writer = supervision_pipe()
            supervised_command = [
                *command[:4],
                "--supervision-ready-fd",
                str(readiness_reader),
                *command[4:],
            ]
            try:
                process = subprocess.Popen(
                    supervised_command,
                    stdout=output,
                    stdin=subprocess.DEVNULL,
                    close_fds=True,
                    pass_fds=(*pass_fds, readiness_reader),
                    env=environment,
                )
            except (OSError, ValueError) as error:
                os.close(readiness_reader)
                os.close(readiness_writer)
                raise gate.GateError(f"cannot start sealed analyzer: {error}") from error
            os.close(readiness_reader)
            try:
                pidfd = open_child_pidfd(process, reservations.pop())
            except gate.GateError:
                os.close(readiness_writer)
                reap_unbound_barrier_child(process, "analyzer")
                raise
            try:
                release_startup_barrier(readiness_writer)
            except gate.GateError:
                supervise_children(
                    "analyzer startup abort",
                    [(0, process, pidfd)],
                    time.monotonic() + OWN_CHILD_TERM_GRACE_SECONDS,
                    consumed_attempt=True,
                )
                raise
            completed = supervise_children(
                "analyzer",
                [(0, process, pidfd)],
                deadline,
                consumed_attempt=True,
            )
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), 0o444)
        return_code = completed[0][1]
        if return_code not in (0, 1):
            raise gate.GateError(
                f"analyzer rejected evidence with exit {return_code}"
            )
        os.link(temporary, output_path)
        os.unlink(temporary)
        sync_parent(output_path)
        return return_code
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    finally:
        for reserved_descriptor in reservations:
            os.close(reserved_descriptor)


def run_shard_phase(
    phase: str,
    *,
    taskset_descriptor: int,
    runner_descriptor: int,
    cpu_ids: list[int],
    seal_path: Path,
    contract_path: Path,
    cells_path: Path,
    run_manifest_path: Path,
    output_paths: list[Path],
    timing_arguments: list[str] | None = None,
) -> None:
    if (
        phase not in {"preflight", "timing"}
        or len(cpu_ids) != 3
        or len(output_paths) != 3
    ):
        raise gate.GateError("invalid three-shard phase request")
    taskset_executable = f"/proc/self/fd/{taskset_descriptor}"
    runner_executable = f"/proc/self/fd/{runner_descriptor}"
    deadline_seconds = (
        PREFLIGHT_DEADLINE_SECONDS
        if phase == "preflight"
        else TIMING_DEADLINE_SECONDS
    )
    deadline = time.monotonic() + deadline_seconds
    pending_children: list[tuple[int, subprocess.Popen[bytes], int, int]] = []
    reservations = reserve_pidfd_slots(3)
    launch_error: OSError | ValueError | gate.GateError | None = None
    unbound_process: subprocess.Popen[bytes] | None = None
    try:
        for shard_id, cpu_id in enumerate(cpu_ids):
            try:
                readiness_reader, readiness_writer = supervision_pipe()
            except gate.GateError as error:
                launch_error = error
                break
            spawned_process: subprocess.Popen[bytes] | None = None
            command = [
                taskset_executable,
                "--cpu-list",
                str(cpu_id),
                runner_executable,
                "--supervision-ready-fd",
                str(readiness_reader),
                "--phase",
                phase,
                "--shard-id",
                str(shard_id),
                "--seal",
                str(seal_path),
                "--contract",
                str(contract_path),
                "--cells",
                str(cells_path),
                "--run-manifest",
                str(run_manifest_path),
                *(timing_arguments or []),
                "--output",
                str(output_paths[shard_id]),
            ]
            try:
                spawned_process = subprocess.Popen(
                    command,
                    executable=taskset_executable,
                    stdin=subprocess.DEVNULL,
                    close_fds=True,
                    pass_fds=(
                        taskset_descriptor,
                        runner_descriptor,
                        readiness_reader,
                    ),
                    env=SEALED_RUNNER_ENVIRONMENT,
                )
                os.close(readiness_reader)
                readiness_reader = -1
                pidfd = open_child_pidfd(spawned_process, reservations.pop())
                pending_children.append(
                    (shard_id, spawned_process, pidfd, readiness_writer)
                )
                readiness_writer = -1
            except (OSError, ValueError, gate.GateError) as error:
                if readiness_reader >= 0:
                    os.close(readiness_reader)
                if readiness_writer >= 0:
                    os.close(readiness_writer)
                if spawned_process is not None and all(
                    spawned_process is not pending[1] for pending in pending_children
                ):
                    unbound_process = spawned_process
                launch_error = error
                break
        children = [
            (shard_id, process, pidfd)
            for shard_id, process, pidfd, _writer in pending_children
        ]
        if launch_error is not None:
            for _shard_id, _process, _pidfd, readiness_writer in pending_children:
                os.close(readiness_writer)
            abort_errors: list[str] = []
            try:
                reap_unbound_barrier_child(unbound_process, f"{phase} shard")
            except gate.GateError as error:
                abort_errors.append(str(error))
            try:
                supervise_children(
                    f"{phase} startup abort",
                    children,
                    time.monotonic() + OWN_CHILD_TERM_GRACE_SECONDS,
                    consumed_attempt=phase == "timing",
                )
            except gate.GateError as error:
                abort_errors.append(str(error))
            suffix = (
                f"; startup-abort errors: {abort_errors}" if abort_errors else ""
            )
            raise gate.GateError(
                f"could not bind all three {phase} shards before global release: "
                f"{launch_error}{suffix}"
            )

        release_error: gate.GateError | None = None
        for _shard_id, _process, _pidfd, readiness_writer in pending_children:
            if release_error is None:
                try:
                    release_startup_barrier(readiness_writer)
                except gate.GateError as error:
                    release_error = error
            else:
                os.close(readiness_writer)
        if release_error is not None:
            try:
                supervise_children(
                    f"{phase} startup release failure",
                    children,
                    time.monotonic() + OWN_CHILD_TERM_GRACE_SECONDS,
                    consumed_attempt=phase == "timing",
                )
            except gate.GateError as error:
                raise gate.GateError(
                    f"{release_error}; startup cleanup failed: {error}"
                ) from error
            raise release_error

        return_codes = supervise_children(
            f"{phase} shards",
            children,
            deadline,
            consumed_attempt=phase == "timing",
        )
    finally:
        for reserved_descriptor in reservations:
            os.close(reserved_descriptor)
    failures = [
        (shard_id, return_code)
        for shard_id, return_code in return_codes
        if return_code != 0
    ]
    if failures:
        raise gate.GateError(
            f"{phase} shards failed after natural completion: {failures}"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-seal-sha256", required=True)
    parser.add_argument("--seal", required=True, type=Path)
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--cells", required=True, type=Path)
    parser.add_argument("--source-archive", required=True, type=Path)
    parser.add_argument("--runner", required=True, type=Path)
    parser.add_argument("--taskset", required=True, type=Path)
    parser.add_argument("--analyzer", required=True, type=Path)
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--cpu", required=True, action="append", type=int)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if platform.system() != "Linux":
            raise gate.GateError("one-shot timing launcher requires Linux taskset")
        if args.taskset != Path("/usr/bin/taskset"):
            raise gate.GateError("frozen launcher requires absolute /usr/bin/taskset")
        require_pidfd_supervision()
        cpu_ids = require_cpu_ids(args.cpu)
        if not hasattr(os, "sched_getaffinity"):
            raise gate.GateError("Linux CPU affinity introspection is unavailable")
        allowed_cpus = os.sched_getaffinity(0)
        unavailable = [cpu_id for cpu_id in cpu_ids if cpu_id not in allowed_cpus]
        if unavailable:
            raise gate.GateError(
                f"explicit CPU IDs are outside launcher affinity: {unavailable}"
            )
        try:
            analyzer_path = args.analyzer.resolve(strict=True)
        except OSError as error:
            raise gate.GateError(f"cannot resolve sealed analyzer path: {error}") from error
        if Path(gate.__file__).resolve(strict=True) != analyzer_path:
            raise gate.GateError(
                "loaded analyzer module differs from the sealed analyzer path"
            )

        seal_file = gate.stable_read(args.seal, gate.MAX_SEAL_BYTES)
        contract_file = gate.stable_read(args.contract, gate.MAX_CONTRACT_BYTES)
        cells_file = gate.stable_read(args.cells, gate.MAX_CELL_MANIFEST_BYTES)
        archive_file = gate.stable_read(args.source_archive, gate.MAX_SHARD_BYTES)
        runner_file = gate.stable_read(args.runner, gate.MAX_SHARD_BYTES)
        taskset_file = gate.stable_read(args.taskset, gate.MAX_SHARD_BYTES)
        launcher_file = gate.stable_read(Path(__file__), gate.MAX_CONTRACT_BYTES)
        analyzer_file = gate.stable_read(analyzer_path, gate.MAX_CONTRACT_BYTES)
        seal = gate.read_json_file(seal_file)
        contract = gate.read_json_file(contract_file)
        gate.require_exact_contract(contract, contract_file, cells_file)
        gate.validate_one_shot_seal(
            seal,
            seal_file,
            args.expected_seal_sha256,
            contract,
            contract_file,
            cells_file,
            archive_file,
            runner_file,
            taskset_file,
            launcher_file,
            analyzer_file,
        )

        try:
            args.run_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
        except OSError as error:
            raise gate.GateError(f"cannot create fresh run directory: {error}") from error
        components = host_fingerprint_components()
        host_fingerprint = host_fingerprint_sha256(components)
        authorization_nonce = gate.nonce_hex(
            seal["authorization_nonce"], "authorization nonce"
        )
        while True:
            run_nonce = gate.nonce_hex(secrets.token_hex(32), "run nonce")
            shard_nonces = [
                gate.nonce_hex(
                    secrets.token_hex(32), f"shard {shard_id} nonce"
                )
                for shard_id in range(3)
            ]
            if len(set((authorization_nonce, run_nonce, *shard_nonces))) == 5:
                break
        run_manifest = {
            "schema": "fre-search-v26-development-gate-run-manifest-v1",
            "status": "SEALED_BEFORE_TIMING",
            "one_shot_seal_sha256": seal_file.sha256,
            "authorization_nonce": seal["authorization_nonce"],
            "run_nonce": run_nonce,
            "source_commit": seal["source_commit"],
            "source_tree": seal["source_tree"],
            "source_archive_sha256": archive_file.sha256,
            "runner_binary_sha256": runner_file.sha256,
            "runner_binary_bytes": len(runner_file.data),
            "runner_build_identity_sha256": seal[
                "runner_build_identity_sha256"
            ],
            "taskset_binary_sha256": taskset_file.sha256,
            "taskset_binary_bytes": len(taskset_file.data),
            "contract_sha256": contract_file.sha256,
            "cell_manifest_sha256": cells_file.sha256,
            "host_fingerprint_sha256": host_fingerprint,
            "cpu_ids": cpu_ids,
            "shard_cpu_map": [
                {
                    "shard_id": shard_id,
                    "cpu_id": cpu_ids[shard_id],
                    "shard_nonce": shard_nonces[shard_id],
                }
                for shard_id in range(3)
            ],
        }
        run_manifest_path = args.run_dir / "run-manifest-v1.json"
        publish_bytes_create_new(
            run_manifest_path, canonical_json_bytes(run_manifest)
        )
        run_manifest_file = gate.stable_read(
            run_manifest_path, gate.MAX_RUN_MANIFEST_BYTES
        )
        gate.validate_run_manifest(
            run_manifest,
            run_manifest_file,
            seal,
            seal_file,
            contract,
            contract_file,
            cells_file,
        )
        cells = gate.validate_cell_manifest(gate.read_jsonl_file(cells_file))
        runner_descriptor = gate.open_verified_fd(runner_file)
        taskset_descriptor = gate.open_verified_fd(taskset_file)
        try:
            preflight_paths = [
                args.run_dir / f"preflight-shard-{shard_id}.jsonl"
                for shard_id in range(3)
            ]
            run_shard_phase(
                "preflight",
                taskset_descriptor=taskset_descriptor,
                runner_descriptor=runner_descriptor,
                cpu_ids=cpu_ids,
                seal_path=args.seal,
                contract_path=args.contract,
                cells_path=args.cells,
                run_manifest_path=run_manifest_path,
                output_paths=preflight_paths,
            )
            preflight_files = [
                gate.stable_read(path, gate.MAX_SHARD_BYTES)
                for path in preflight_paths
            ]
            for shard_id, proof_file in enumerate(preflight_files):
                expected_header = gate.preflight_expected_header(
                    shard_id,
                    seal,
                    seal_file,
                    run_manifest_file,
                    contract_file,
                    cells_file,
                    cpu_ids[shard_id],
                    shard_nonces[shard_id],
                    host_fingerprint,
                    run_nonce,
                )
                gate.validate_preflight_file(
                    proof_file,
                    shard_id,
                    expected_header,
                    shard_nonces[shard_id],
                    run_nonce,
                    cells,
                )
            preflight_manifest = {
                "schema": "fre-search-v26-development-gate-preflight-manifest-v1",
                "status": "COMPLETE_BEFORE_TIMING",
                "one_shot_seal_sha256": seal_file.sha256,
                "run_manifest_sha256": run_manifest_file.sha256,
                "source_commit": seal["source_commit"],
                "source_tree": seal["source_tree"],
                "source_archive_sha256": seal["source_archive_sha256"],
                "runner_binary_sha256": seal["runner_binary_sha256"],
                "runner_binary_bytes": seal["runner_binary_bytes"],
                "runner_build_identity_sha256": seal[
                    "runner_build_identity_sha256"
                ],
                "taskset_binary_sha256": seal["taskset_binary_sha256"],
                "taskset_binary_bytes": seal["taskset_binary_bytes"],
                "contract_sha256": contract_file.sha256,
                "cell_manifest_sha256": cells_file.sha256,
                "host_fingerprint_sha256": host_fingerprint,
                "run_nonce": run_nonce,
                "proofs": [
                    {
                        "shard_id": shard_id,
                        "cpu_id": cpu_ids[shard_id],
                        "shard_nonce": shard_nonces[shard_id],
                        "sha256": preflight_files[shard_id].sha256,
                        "bytes": len(preflight_files[shard_id].data),
                        "cells": gate.EXPECTED_SHARD_CELLS,
                    }
                    for shard_id in range(3)
                ],
                "cells": gate.EXPECTED_CELLS,
                "semantic_comparisons": gate.EXPECTED_CELLS * 3,
                "complete": True,
            }
            preflight_manifest_path = args.run_dir / "preflight-manifest-v1.json"
            publish_bytes_create_new(
                preflight_manifest_path,
                canonical_json_bytes(preflight_manifest),
            )
            preflight_manifest_file = gate.stable_read(
                preflight_manifest_path, gate.MAX_RUN_MANIFEST_BYTES
            )
            gate.validate_preflight_manifest(
                preflight_manifest,
                preflight_manifest_file,
                preflight_files,
                seal,
                seal_file,
                run_manifest_file,
                contract_file,
                cells_file,
                cpu_ids,
                shard_nonces,
                host_fingerprint,
                run_nonce,
                cells,
            )
            consumed_marker_path = consume_seal_once(
                Path(seal["one_shot_registry"]),
                seal_file.sha256,
                seal["authorization_nonce"],
                run_manifest_file.sha256,
                run_nonce,
                preflight_manifest_file.sha256,
            )
            timing_arguments = [
                "--consumed-marker",
                str(consumed_marker_path),
                "--preflight-manifest",
                str(preflight_manifest_path),
            ]
            for proof_path in preflight_paths:
                timing_arguments.extend(("--preflight-proof", str(proof_path)))
            shard_paths = [
                args.run_dir / f"shard-{shard_id}.jsonl"
                for shard_id in range(3)
            ]
            run_shard_phase(
                "timing",
                taskset_descriptor=taskset_descriptor,
                runner_descriptor=runner_descriptor,
                cpu_ids=cpu_ids,
                seal_path=args.seal,
                contract_path=args.contract,
                cells_path=args.cells,
                run_manifest_path=run_manifest_path,
                output_paths=shard_paths,
                timing_arguments=timing_arguments,
            )
        finally:
            os.close(taskset_descriptor)
            os.close(runner_descriptor)

        analysis_output = args.run_dir / "analysis-v1.json"
        analyzer_descriptor = gate.open_verified_fd(analyzer_file)
        try:
            analyzer_command = [
                sys.executable,
                "-I",
                "-B",
                f"/proc/self/fd/{analyzer_descriptor}",
                "--expected-seal-sha256",
                seal_file.sha256,
                str(args.seal),
                str(args.contract),
                str(args.cells),
                str(run_manifest_path),
                str(preflight_manifest_path),
                *(str(path) for path in preflight_paths),
                str(consumed_marker_path),
                str(args.source_archive),
                str(args.runner),
                str(args.taskset),
                str(Path(__file__)),
                str(analyzer_path),
                *(str(path) for path in shard_paths),
            ]
            return publish_analyzer_output(
                analyzer_command,
                analysis_output,
                pass_fds=(analyzer_descriptor,),
                environment=SEALED_RUNNER_ENVIRONMENT,
            )
        finally:
            os.close(analyzer_descriptor)
    except gate.GateError as error:
        sys.stderr.write(f"launch refused: {error}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
