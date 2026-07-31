#!/usr/bin/env python3
"""Provisional sealed Cargo controller for static AOT construction.

The controller starts Cargo through the kernel-attested sealer, gives Cargo
only held wrapper/launcher/sealer descriptors, and services the native
launcher's stop/attest/resume protocol for every rustc, linker, and generated
build-script launch.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import platform
import re
import signal
import stat
import threading
from pathlib import Path
from typing import Any, Mapping, Sequence

import static_build_closure as closure
import static_sealer_core as sealer
import static_tool_wrapper as wrapper


CARGO_RECEIPT_SCHEMA = "fre.aot.search-static-cargo-build.v1"
LINK_RECEIPT_SCHEMA = "fre.aot.search-tag29-link-invocation-receipt.v1"
BUILD_RECEIPT_SCHEMA = (
    "fre.aot.external-regex-1.12.4-static-runner-build-receipt.v2"
)
OBJECT_COUNT = 808
REFUSAL_COUNT = 114
OBJECT_BASENAME = re.compile(
    r"external-search-(0|[1-9][0-9]{0,3})-"
    r"(implementation|family-glue)[.]o\Z"
)
MAXIMUM_BUILD_RECEIPT_BYTES = 4 * 1024 * 1024
MAXIMUM_LINK_MAP_BYTES = 128 * 1024 * 1024
MAXIMUM_LINKED_IMAGE_BYTES = 512 * 1024 * 1024
MAXIMUM_OBJECT_BYTES = 16 * 1024 * 1024
MAXIMUM_COMPILE_RECEIPT_BYTES = 64 * 1024
DESCRIPTOR_NUMBERS = {
    "wrapper_script": 112,
    "sealer_source": 113,
    "monitor": 114,
}
ALLOWED_BASE_ENVIRONMENT = {
    "HOME",
    "PATH",
    "LANG",
    "LC_ALL",
    "CARGO_HOME",
    "RUSTUP_HOME",
    "SDKROOT",
    "CPATH",
    "LIBRARY_PATH",
    "DEVELOPER_DIR",
    "MACOSX_DEPLOYMENT_TARGET",
    "SOURCE_DATE_EPOCH",
    "ZERO_AR_DATE",
}
CONTROLLER_ENVIRONMENT = {
    "TMPDIR",
    "CARGO_TARGET_DIR",
    "CARGO_BUILD_JOBS",
    "CARGO_INCREMENTAL",
    "CARGO_NET_OFFLINE",
    "CARGO_TERM_COLOR",
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTFLAGS",
}


class Refusal(RuntimeError):
    """The build differs from the provisional exact controller contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def descriptor_prefix() -> str:
    if platform.system() == "Darwin":
        return "/dev/fd"
    if platform.system() == "Linux":
        return "/proc/self/fd"
    raise Refusal("static build controller requires Darwin or Linux")


def descriptor_path(descriptor: int) -> str:
    return f"{descriptor_prefix()}/{descriptor}"


def reject_ambient_environment(environment: Mapping[str, str]) -> None:
    require(
        set(environment) <= ALLOWED_BASE_ENVIRONMENT
        and {
            "HOME",
            "PATH",
            "LANG",
            "LC_ALL",
            "CARGO_HOME",
            "RUSTUP_HOME",
        }
        <= set(environment)
        and environment["PATH"] == "/usr/bin:/bin"
        and environment["LANG"] == "C"
        and environment["LC_ALL"] == "C"
        and all(
            key
            and "=" not in key
            and "\0" not in key
            and isinstance(value, str)
            and "\0" not in value
            for key, value in environment.items()
        )
        and not any(
            key.startswith(("PYTHON", "LD_", "DYLD_"))
            or key in CONTROLLER_ENVIRONMENT
            or key.startswith(wrapper.CONTROL_PREFIX)
            for key in environment
        ),
        "pre-Cargo environment is not the exact injection-free allowlist",
    )


def validate_tool(tool: Mapping[str, Any], label: str) -> Path:
    require(
        set(tool) == {"path", "sha256", "execution_identity"}
        and isinstance(tool["path"], str)
        and Path(tool["path"]).is_absolute()
        and wrapper.is_sha256(tool["sha256"])
        and isinstance(tool["execution_identity"], dict),
        f"{label} tool fields changed",
    )
    path = Path(tool["path"])
    status = path.lstat()
    require(
        stat.S_ISREG(status.st_mode)
        and not path.is_symlink()
        and status.st_mode & 0o111 != 0
        and sealer.file_sha(path) == tool["sha256"],
        f"{label} tool bytes changed",
    )
    mechanism = (
        "darwin-suspended-cdhash-v1"
        if platform.system() == "Darwin"
        else "linux-sealed-memfd-v1"
    )
    require(
        tool["execution_identity"].get("mechanism") == mechanism,
        f"{label} execution mechanism changed",
    )
    return path


def validate_launcher_tool(
    tool: Mapping[str, Any], label: str
) -> Path:
    require(
        set(tool) == {"path", "sha256", "execution_identity"}
        and isinstance(tool["path"], str)
        and Path(tool["path"]).is_absolute()
        and wrapper.is_sha256(tool["sha256"])
        and isinstance(tool["execution_identity"], dict),
        f"{label} tool fields changed",
    )
    path = Path(tool["path"])
    status = path.lstat()
    require(
        stat.S_ISREG(status.st_mode)
        and not path.is_symlink()
        and status.st_mode & 0o111 != 0
        and sealer.file_sha(path) == tool["sha256"],
        f"{label} tool bytes changed",
    )
    identity = tool["execution_identity"]
    expected = (
        {
            "mechanism": "darwin-suspended-cdhash-v1",
            "cdhash": wrapper.darwin_cdhash_from_macho(path),
        }
        if platform.system() == "Darwin"
        else {
            "mechanism": "linux-stopped-proc-exe-sha256-v1",
            "sha256": tool["sha256"],
        }
    )
    require(identity == expected, f"{label} execution identity changed")
    return path


def require_unused_descriptor(descriptor: int) -> None:
    try:
        os.fstat(descriptor)
    except OSError as error:
        require(
            error.errno == errno.EBADF,
            "deterministic descriptor probe failed",
        )
        return
    raise Refusal(f"deterministic descriptor is already open: {descriptor}")


def install_held_descriptor(
    path: Path,
    expected_sha256: str,
    target: int,
    *,
    executable: bool,
) -> None:
    source = sealer.open_regular_fd(path)
    held = -1
    try:
        held = sealer.sealed_copy_descriptor(
            source, expected_sha256, executable=executable
        )
        os.dup2(held, target, inheritable=True)
        require(
            sealer.file_sha_fd(target) == expected_sha256
            and os.get_inheritable(target),
            "installed held descriptor identity changed",
        )
    finally:
        if held >= 0:
            os.close(held)
        os.close(source)


def publish_launcher(
    launcher: Path,
    expected_sha256: str,
    destination: Path,
) -> str:
    encoded = sealer.regular_file(launcher, 16 * 1024 * 1024)
    require(
        hashlib.sha256(encoded).hexdigest() == expected_sha256,
        "native launcher source identity changed",
    )
    wrapper.write_exclusive(destination, encoded, 0o500)
    require(
        not destination.is_symlink()
        and stat.S_ISREG(destination.lstat().st_mode)
        and destination.lstat().st_mode & 0o777 == 0o500
        and sealer.file_sha(destination) == expected_sha256,
        "published native launcher identity changed",
    )
    return str(destination)


def linux_process_executable_sha256(pid: int) -> str:
    descriptor = os.open(
        f"/proc/{pid}/exe", os.O_RDONLY | os.O_CLOEXEC
    )
    try:
        return sealer.file_sha_fd(descriptor)
    finally:
        os.close(descriptor)


class LaunchMonitor:
    def __init__(
        self,
        descriptor: int,
        *,
        target_root: Path,
        rustc_launcher_path: str,
        linker_launcher_path: str,
        launcher_sha256: str,
        launcher_execution_identity: Mapping[str, str],
    ) -> None:
        self._descriptor = descriptor
        self._target_root = target_root.resolve(strict=True)
        self._rustc = rustc_launcher_path
        self._linker = linker_launcher_path
        self._sha256 = launcher_sha256
        self._identity = dict(launcher_execution_identity)
        self._cargo_pid = 0
        self._events: list[dict[str, Any]] = []
        self._error: BaseException | None = None
        self._thread = threading.Thread(
            target=self._run,
            name="fre-static-launch-monitor",
            daemon=True,
        )

    def set_cargo_pid(self, pid: int) -> None:
        require(self._cargo_pid == 0 and pid > 0, "Cargo PID changed")
        self._cargo_pid = pid

    def start(self) -> None:
        self._thread.start()

    def _kill_build(self) -> None:
        if self._cargo_pid:
            try:
                os.killpg(self._cargo_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def _validate_path(self, encoded: str) -> str:
        candidate = Path(encoded)
        build_script = (
            candidate.is_absolute()
            and candidate.name == "build-script-build"
            and not candidate.is_symlink()
            and stat.S_ISREG(candidate.lstat().st_mode)
            and candidate.resolve(strict=True).is_relative_to(
                self._target_root
            )
        )
        require(
            encoded in {self._rustc, self._linker}
            or build_script,
            "native launcher path is outside its exact role",
        )
        return (
            "rustc"
            if encoded == self._rustc
            else "linker"
            if encoded == self._linker
            else "build-script"
        )

    def _attest(
        self, pid: int, parent_pid: int, path: str
    ) -> dict[str, Any]:
        role = self._validate_path(path)
        if platform.system() == "Darwin":
            observed_identity = {
                "mechanism": "darwin-suspended-cdhash-v1",
                "cdhash": sealer.darwin_process_cdhash(pid),
            }
            observed_sha256 = sealer.file_sha(Path(path))
        else:
            observed_sha256 = linux_process_executable_sha256(pid)
            observed_identity = {
                "mechanism": "linux-stopped-proc-exe-sha256-v1",
                "sha256": observed_sha256,
            }
        require(
            observed_sha256 == self._sha256
            and observed_identity == self._identity,
            "stopped native launcher differs from preregistration",
        )
        event = {
            "pid": pid,
            "parent_pid": parent_pid,
            "path": path,
            "role": role,
            "sha256": observed_sha256,
            "execution_identity": observed_identity,
        }
        os.kill(pid, signal.SIGCONT)
        return event

    def _run(self) -> None:
        try:
            with os.fdopen(
                self._descriptor, "r", encoding="utf-8"
            ) as stream:
                for line in stream:
                    fields = line.rstrip("\n").split(" ", 3)
                    require(
                        len(fields) == 4
                        and fields[0] == "FRELAUNCH1"
                        and fields[1].isascii()
                        and fields[1].isdecimal()
                        and fields[2].isascii()
                        and fields[2].isdecimal(),
                        "native launcher monitor message changed",
                    )
                    event = self._attest(
                        int(fields[1]), int(fields[2]), fields[3]
                    )
                    require(
                        all(
                            row["pid"] != event["pid"]
                            for row in self._events
                        ),
                        "native launcher PID was represented twice",
                    )
                    self._events.append(event)
        except BaseException as error:
            self._error = error
            self._kill_build()

    def finish(self) -> list[dict[str, Any]]:
        self._thread.join(timeout=30)
        require(
            not self._thread.is_alive(),
            "native launcher monitor did not reach EOF",
        )
        if self._error is not None:
            raise Refusal("native launcher attestation failed") from self._error
        return self._events


def parse_cargo_messages(encoded: bytes) -> list[dict[str, Any]]:
    messages = []
    for line in encoded.splitlines():
        value = json.loads(line)
        require(
            isinstance(value, dict)
            and value.get("reason")
            in {
                "compiler-artifact",
                "compiler-message",
                "build-script-executed",
                "build-finished",
            },
            "Cargo JSON message changed",
        )
        messages.append(value)
    require(
        bool(messages)
        and messages[-1]
        == {"reason": "build-finished", "success": True},
        "Cargo did not publish one successful final JSON message",
    )
    return messages


def published_runner_binary(
    messages: Sequence[Mapping[str, Any]], target_root: Path
) -> Path:
    candidates: list[Path] = []
    for message in messages:
        target = message.get("target")
        executable = message.get("executable")
        if (
            message.get("reason") == "compiler-artifact"
            and isinstance(target, dict)
            and target.get("name") == "fre-external-regex-static-runner"
            and target.get("kind") == ["bin"]
            and target.get("crate_types") == ["bin"]
            and isinstance(executable, str)
            and Path(executable).is_absolute()
        ):
            candidates.append(Path(executable))
    expected = target_root / "release" / "fre-external-regex-static-runner"
    require(
        candidates == [expected]
        and expected.is_file()
        and not expected.is_symlink(),
        "Cargo did not publish one exact final static runner",
    )
    return expected


def target_link_identity() -> dict[str, Any]:
    machine = platform.machine().lower()
    require(
        machine in {"arm64", "aarch64"},
        "tag-29 static artifact construction requires AArch64",
    )
    if platform.system() == "Darwin":
        return {
            "frozen_host": "local-apple-aarch64-asimd",
            "canonical_host": "apple-aarch64-asimd",
            "target_os": "macos",
            "target_arch": "aarch64",
            "target_triple": "aarch64-apple-darwin",
            "features": {
                "architecture": "aarch64",
                "asimd": True,
                "sve": False,
                "sve2": False,
                "sve_vector_bytes": None,
            },
        }
    require(
        platform.system() == "Linux",
        "tag-29 static artifact construction requires Darwin or Linux",
    )
    getauxval = ctypes.CDLL(None, use_errno=True).getauxval
    getauxval.argtypes = [ctypes.c_ulong]
    getauxval.restype = ctypes.c_ulong
    ctypes.set_errno(0)
    hwcap = int(getauxval(16))
    hwcap_errno = ctypes.get_errno()
    ctypes.set_errno(0)
    hwcap2 = int(getauxval(26))
    hwcap2_errno = ctypes.get_errno()
    require(
        hwcap_errno == 0
        and hwcap2_errno == 0
        and hwcap & (1 << 1) != 0
        and hwcap & (1 << 22) != 0
        and hwcap2 & (1 << 1) != 0,
        "Linux qualification host lacks ASIMD/SVE/SVE2",
    )
    return {
        "frozen_host": "zstd-eval-ec2-aarch64-asimd-sve2-vl16",
        "canonical_host": "c9g-aarch64-asimd-sve2",
        "target_os": "linux",
        "target_arch": "aarch64",
        "target_triple": "aarch64-unknown-linux-gnu",
        "features": {
            "architecture": "aarch64",
            "asimd": True,
            "sve": True,
            "sve2": True,
            "sve_vector_bytes": 16,
        },
    }


def candidate_link_rows(
    raw_payloads: Sequence[Mapping[str, Any]],
    held_link_root: Path,
) -> tuple[
    Mapping[str, Any],
    dict[tuple[int, str], Mapping[str, Any]],
    Path,
]:
    possible: list[
        tuple[
            Mapping[str, Any],
            dict[tuple[int, str], Mapping[str, Any]],
            Path,
        ]
    ] = []
    held_root = held_link_root.resolve(strict=True)
    for payload in raw_payloads:
        if payload.get("role") != "linker" or payload.get("returncode") != 0:
            continue
        rows = payload.get("input_rows")
        if not isinstance(rows, list):
            continue
        indexed: dict[tuple[int, str], Mapping[str, Any]] = {}
        source_directories: set[Path] = set()
        rejected = False
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("path"), str):
                continue
            original = Path(row["path"])
            match = OBJECT_BASENAME.fullmatch(original.name)
            if match is None:
                continue
            ordinal = int(match.group(1))
            kind = "implementation" if match.group(2) == "implementation" else "glue"
            held_argument = row.get("held_argument")
            if (
                ordinal >= OBJECT_COUNT
                or not original.is_absolute()
                or not isinstance(held_argument, str)
            ):
                rejected = True
                break
            held_path = Path(held_argument)
            try:
                resolved = held_path.resolve(strict=True)
            except OSError:
                rejected = True
                break
            if (
                not held_path.is_absolute()
                or held_path.name != original.name
                or not resolved.is_relative_to(held_root)
                or held_path.is_symlink()
                or not stat.S_ISREG(held_path.lstat().st_mode)
                or held_path.lstat().st_mode & 0o777 != 0o400
                or set(row)
                != {
                    "ordinal",
                    "argument_index",
                    "path",
                    "sha256",
                    "bytes",
                    "kind",
                    "held_argument",
                }
                or row["kind"] != "object"
                or not wrapper.is_sha256(row["sha256"])
                or not isinstance(row["bytes"], int)
                or isinstance(row["bytes"], bool)
                or row["bytes"] <= 0
                or sealer.file_sha(held_path) != row["sha256"]
                or held_path.stat().st_size != row["bytes"]
                or (ordinal, kind) in indexed
            ):
                rejected = True
                break
            indexed[(ordinal, kind)] = row
            source_directories.add(original.parent)
        if (
            not rejected
            and len(indexed) == OBJECT_COUNT * 2
            and len(source_directories) == 1
        ):
            possible.append((payload, indexed, next(iter(source_directories))))
    require(
        len(possible) == 1,
        "Cargo transcript does not contain one exact 1616-object final link",
    )
    payload, indexed, source_directory = possible[0]
    expected = {
        (ordinal, kind)
        for ordinal in range(OBJECT_COUNT)
        for kind in ("implementation", "glue")
    }
    require(
        set(indexed) == expected
        and source_directory.is_absolute()
        and source_directory.is_dir()
        and not source_directory.is_symlink(),
        "final candidate-link input inventory changed",
    )
    arguments = payload.get("executed_arguments")
    output = payload.get("output")
    require(
        isinstance(arguments, list)
        and all(
            isinstance(argument, str) and argument and "\0" not in argument
            for argument in arguments
        )
        and isinstance(output, dict)
        and set(output) == {"path", "sha256", "bytes"}
        and isinstance(output["path"], str)
        and Path(output["path"]).is_absolute()
        and wrapper.is_sha256(output["sha256"])
        and isinstance(output["bytes"], int)
        and not isinstance(output["bytes"], bool)
        and output["bytes"] > 0,
        "final candidate-link output or expanded argv changed",
    )
    for row in indexed.values():
        require(
            arguments.count(row["held_argument"]) == 1,
            "candidate object is not one exact expanded linker argument",
        )
    return payload, indexed, source_directory


def stage_regular(
    source: Path, destination: Path, maximum: int, mode: int
) -> tuple[str, int]:
    encoded = sealer.regular_file(source, maximum)
    digest = hashlib.sha256(encoded).hexdigest()
    wrapper.write_exclusive(destination, encoded, mode)
    require(
        not destination.is_symlink()
        and stat.S_ISREG(destination.lstat().st_mode)
        and destination.lstat().st_mode & 0o777 == mode
        and sealer.file_sha(destination) == digest,
        f"staged artifact changed: {destination.name}",
    )
    return digest, len(encoded)


def stage_link_artifacts(
    *,
    work_root: Path,
    held_link_root: Path,
    raw_payloads: Sequence[Mapping[str, Any]],
    published_image: Path,
) -> dict[str, Any]:
    link_payload, indexed, source = candidate_link_rows(
        raw_payloads, held_link_root
    )
    target = target_link_identity()
    expanded_argv = link_payload["executed_arguments"]
    map_source = source / "linked-image.map"
    map_argument = (
        f"-Wl,-map,{map_source}"
        if target["target_os"] == "macos"
        else f"-Wl,-Map,{map_source}"
    )
    require(
        expanded_argv.count(map_argument) == 1,
        "final link does not name one exact build-output link map",
    )
    output = link_payload["output"]
    linker_output = Path(output["path"])
    require(
        linker_output.is_file()
        and not linker_output.is_symlink()
        and linker_output.parent == work_root / "target" / "release" / "deps"
        and published_image
        == work_root / "target" / "release" / "fre-external-regex-static-runner"
        and published_image.is_file()
        and not published_image.is_symlink()
        and sealer.file_sha(linker_output) == sealer.file_sha(published_image)
        and linker_output.stat().st_size == published_image.stat().st_size,
        "rustc/Cargo final linked-image publication changed",
    )
    image_source = published_image
    build_source = source / "build-receipt.json"
    build_raw = sealer.regular_file(
        build_source, MAXIMUM_BUILD_RECEIPT_BYTES
    )
    try:
        build = json.loads(build_raw)
    except json.JSONDecodeError as error:
        raise Refusal("external build receipt is not JSON") from error
    require(
        isinstance(build, dict)
        and build.get("schema") == BUILD_RECEIPT_SCHEMA
        and isinstance(build.get("candidates"), list)
        and len(build["candidates"]) == OBJECT_COUNT
        and isinstance(build.get("refusals"), list)
        and len(build["refusals"]) == REFUSAL_COUNT,
        "external build receipt does not cover the exact disposition envelope",
    )

    artifacts = work_root / "artifacts"
    require(not artifacts.exists(), "artifact staging directory already exists")
    artifacts.mkdir(mode=0o700)
    require(
        not artifacts.is_symlink()
        and artifacts.lstat().st_mode & 0o777 == 0o700,
        "artifact staging directory changed",
    )
    expected_inventory = {
        "build-receipt.json",
        "link-invocation-receipt.json",
        "linked-image",
        "linked-image.map",
    }
    build_sha, _ = stage_regular(
        build_source,
        artifacts / "build-receipt.json",
        MAXIMUM_BUILD_RECEIPT_BYTES,
        0o400,
    )
    input_receipts: list[dict[str, Any]] = []
    for ordinal, candidate in enumerate(build["candidates"]):
        require(
            isinstance(candidate, dict),
            f"build candidate {ordinal} is not an object",
        )
        implementation_name = f"external-search-{ordinal}-implementation.o"
        glue_name = f"external-search-{ordinal}-family-glue.o"
        compile_name = f"external-search-{ordinal}-compile-receipt.bin"
        require(
            candidate.get("ordinal") == ordinal
            and candidate.get("implementation_object_basename")
            == implementation_name
            and candidate.get("glue_object_basename") == glue_name
            and candidate.get("compile_receipt_basename") == compile_name
            and wrapper.is_sha256(
                candidate.get("implementation_object_sha256")
            )
            and wrapper.is_sha256(candidate.get("glue_object_sha256"))
            and wrapper.is_sha256(candidate.get("compile_receipt_sha256")),
            f"build candidate {ordinal} artifact binding changed",
        )
        for kind, basename, expected_sha in (
            (
                "implementation",
                implementation_name,
                candidate["implementation_object_sha256"],
            ),
            ("glue", glue_name, candidate["glue_object_sha256"]),
        ):
            row = indexed[(ordinal, kind)]
            require(
                Path(row["path"]) == source / basename
                and Path(row["held_argument"]).name == basename
                and row["sha256"] == expected_sha,
                f"linked object {ordinal}/{kind} differs from build receipt",
            )
            staged_sha, staged_bytes = stage_regular(
                Path(row["held_argument"]),
                artifacts / basename,
                MAXIMUM_OBJECT_BYTES,
                0o400,
            )
            require(
                staged_sha == expected_sha and staged_bytes == row["bytes"],
                f"staged object {ordinal}/{kind} differs from linker input",
            )
            input_receipts.append(
                {
                    "ordinal": ordinal,
                    "kind": kind,
                    "artifact_basename": basename,
                    "linker_path": row["held_argument"],
                    "sha256": staged_sha,
                    "bytes": staged_bytes,
                    "expanded_argv_multiplicity": 1,
                }
            )
            expected_inventory.add(basename)
        compile_sha, _ = stage_regular(
            source / compile_name,
            artifacts / compile_name,
            MAXIMUM_COMPILE_RECEIPT_BYTES,
            0o400,
        )
        require(
            compile_sha == candidate["compile_receipt_sha256"],
            f"candidate compile receipt {ordinal} changed",
        )
        expected_inventory.add(compile_name)
    for ordinal, refusal in enumerate(build["refusals"]):
        require(
            isinstance(refusal, dict),
            f"build refusal {ordinal} is not an object",
        )
        basename = (
            f"external-search-refusal-{ordinal}-compile-receipt.bin"
        )
        require(
            refusal.get("ordinal") == ordinal
            and refusal.get("compile_receipt_basename") == basename
            and wrapper.is_sha256(refusal.get("compile_receipt_sha256")),
            f"build refusal {ordinal} artifact binding changed",
        )
        refusal_sha, _ = stage_regular(
            source / basename,
            artifacts / basename,
            MAXIMUM_COMPILE_RECEIPT_BYTES,
            0o400,
        )
        require(
            refusal_sha == refusal["compile_receipt_sha256"],
            f"structural-refusal compile receipt {ordinal} changed",
        )
        expected_inventory.add(basename)

    link_map_sha, _ = stage_regular(
        map_source,
        artifacts / "linked-image.map",
        MAXIMUM_LINK_MAP_BYTES,
        0o400,
    )
    linked_image_sha, _ = stage_regular(
        image_source,
        artifacts / "linked-image",
        MAXIMUM_LINKED_IMAGE_BYTES,
        0o500,
    )
    receipt_payload = {
        **target,
        "build_receipt_basename": "build-receipt.json",
        "build_receipt_sha256": build_sha,
        "linked_image_basename": "linked-image",
        "linked_image_sha256": linked_image_sha,
        "link_map_basename": "linked-image.map",
        "link_map_sha256": link_map_sha,
        "expanded_argv": expanded_argv,
        "expanded_argv_sha256": wrapper.canonical_sha(expanded_argv),
        "inputs": input_receipts,
    }
    envelope = {
        "schema": LINK_RECEIPT_SCHEMA,
        "payload_sha256": wrapper.canonical_sha(receipt_payload),
        "payload": receipt_payload,
    }
    link_receipt = artifacts / "link-invocation-receipt.json"
    wrapper.write_exclusive(
        link_receipt, wrapper.canonical_bytes(envelope) + b"\n", 0o400
    )
    require(
        set(path.name for path in artifacts.iterdir()) == expected_inventory
        and len(expected_inventory) == 2542,
        "staged artifact inventory is incomplete or contains extra files",
    )
    return {
        "artifact_directory": str(artifacts),
        "build_receipt_sha256": build_sha,
        "link_receipt_sha256": sealer.file_sha(link_receipt),
        "linked_image_sha256": linked_image_sha,
        "link_map_sha256": link_map_sha,
        "candidate_input_count": len(input_receipts),
        "refusal_count": len(build["refusals"]),
    }


def run_attested_cargo_build(
    *,
    repo: Path,
    work_root: Path,
    manifest: Path,
    jobs: int,
    base_environment: Mapping[str, str],
    external_environment: Mapping[str, str],
    cargo_tool: Mapping[str, Any],
    rustc_tool: Mapping[str, Any],
    linker_tool: Mapping[str, Any],
    launcher_tool: Mapping[str, Any],
    python_runtime: Mapping[str, Any],
    timeout_seconds: int = 2 * 60 * 60,
) -> dict[str, Any]:
    reject_ambient_environment(base_environment)
    require(
        repo.is_absolute()
        and repo.is_dir()
        and manifest.is_absolute()
        and manifest.is_file()
        and work_root.is_absolute()
        and not work_root.exists()
        and 1 <= jobs <= 256
        and set(external_environment)
        <= {
            "FRE_EXTERNAL_SEARCH_STATIC_IDENTITY",
            "FRE_EXTERNAL_SEARCH_OBJECT_CANDIDATE_MANIFEST",
            "FRE_EXTERNAL_SEARCH_LITERAL_DISPOSITIONS",
            "FRE_EXTERNAL_SEARCH_RUNNER_REVISION",
            "FRE_EXTERNAL_SEARCH_ALLOW_UNSEALED_ARTIFACT_BUILD",
        }
        and all(
            isinstance(value, str) and value and "\0" not in value
            for value in external_environment.values()
        ),
        "Cargo construction inputs changed",
    )
    cargo = validate_tool(cargo_tool, "Cargo")
    rustc = validate_tool(rustc_tool, "rustc")
    linker = validate_tool(linker_tool, "linker")
    launcher = validate_launcher_tool(
        launcher_tool, "native launcher"
    )
    require(
        set(python_runtime)
        == {"path", "sha256", "execution_identity", "flags"}
        and python_runtime["flags"] == ["-I", "-S", "-E"]
        and Path(python_runtime["path"]).is_absolute()
        and sealer.file_sha(Path(python_runtime["path"]))
        == python_runtime["sha256"],
        "embedded Python runtime identity changed",
    )
    wrapper_source = Path(wrapper.__file__).resolve(strict=True)
    sealer_source = Path(sealer.__file__).resolve(strict=True)
    wrapper_sha256 = sealer.file_sha(wrapper_source)
    sealer_sha256 = sealer.file_sha(sealer_source)
    work_root.mkdir(mode=0o700)
    target = work_root / "target"
    receipts = work_root / "receipts"
    temporary = work_root / "tmp"
    controls = work_root / "controls"
    held_link_root = work_root / "held-link-inputs"
    for directory in (
        target,
        receipts,
        temporary,
        controls,
        held_link_root,
    ):
        directory.mkdir(mode=0o700)
    for descriptor in DESCRIPTOR_NUMBERS.values():
        require_unused_descriptor(descriptor)
    install_held_descriptor(
        wrapper_source,
        wrapper_sha256,
        DESCRIPTOR_NUMBERS["wrapper_script"],
        executable=False,
    )
    install_held_descriptor(
        sealer_source,
        sealer_sha256,
        DESCRIPTOR_NUMBERS["sealer_source"],
        executable=False,
    )
    monitor_read, monitor_write = os.pipe()
    os.dup2(
        monitor_write,
        DESCRIPTOR_NUMBERS["monitor"],
        inheritable=True,
    )
    os.close(monitor_write)
    rustc_launcher = publish_launcher(
        launcher,
        launcher_tool["sha256"],
        controls / "rustc-launcher",
    )
    linker_launcher = publish_launcher(
        launcher,
        launcher_tool["sha256"],
        controls / "linker-launcher",
    )
    wrapper_script = descriptor_path(
        DESCRIPTOR_NUMBERS["wrapper_script"]
    )
    sealer_path = descriptor_path(
        DESCRIPTOR_NUMBERS["sealer_source"]
    )
    monitor = LaunchMonitor(
        monitor_read,
        target_root=target,
        rustc_launcher_path=rustc_launcher,
        linker_launcher_path=linker_launcher,
        launcher_sha256=launcher_tool["sha256"],
        launcher_execution_identity=launcher_tool[
            "execution_identity"
        ],
    )
    environment = {
        **base_environment,
        **external_environment,
        "TMPDIR": f"{temporary}/",
        "CARGO_TARGET_DIR": str(target),
        "CARGO_BUILD_JOBS": str(jobs),
        "CARGO_INCREMENTAL": "0",
        "CARGO_NET_OFFLINE": "true",
        "CARGO_TERM_COLOR": "never",
        "RUSTC": str(rustc),
        "RUSTC_WRAPPER": rustc_launcher,
        "RUSTFLAGS": f"-C linker={linker_launcher}",
        f"{wrapper.CONTROL_PREFIX}MONITOR_FD": str(
            DESCRIPTOR_NUMBERS["monitor"]
        ),
        f"{wrapper.CONTROL_PREFIX}LAUNCHER_SHA256": launcher_tool[
            "sha256"
        ],
        f"{wrapper.CONTROL_PREFIX}LAUNCHER_EXECUTION_IDENTITY": (
            wrapper.canonical_bytes(
                launcher_tool["execution_identity"]
            ).decode()
        ),
        f"{wrapper.CONTROL_PREFIX}WRAPPER_SCRIPT_PATH": wrapper_script,
        f"{wrapper.CONTROL_PREFIX}WRAPPER_SOURCE_SHA256": wrapper_sha256,
        f"{wrapper.CONTROL_PREFIX}PYTHON_RUNTIME_PATH": python_runtime[
            "path"
        ],
        f"{wrapper.CONTROL_PREFIX}PYTHON_RUNTIME_SHA256": python_runtime[
            "sha256"
        ],
        f"{wrapper.CONTROL_PREFIX}PYTHON_RUNTIME_EXECUTION_IDENTITY": (
            wrapper.canonical_bytes(
                python_runtime["execution_identity"]
            ).decode()
        ),
        f"{wrapper.CONTROL_PREFIX}SEALER_SOURCE": sealer_path,
        f"{wrapper.CONTROL_PREFIX}SEALER_SOURCE_SHA256": sealer_sha256,
        f"{wrapper.CONTROL_PREFIX}RECEIPT_DIR": str(receipts),
        f"{wrapper.CONTROL_PREFIX}HELD_LINK_ROOT": str(held_link_root),
        f"{wrapper.CONTROL_PREFIX}RUSTC_PATH": str(rustc),
        f"{wrapper.CONTROL_PREFIX}RUSTC_SHA256": rustc_tool["sha256"],
        f"{wrapper.CONTROL_PREFIX}RUSTC_EXECUTION_IDENTITY": (
            wrapper.canonical_bytes(
                rustc_tool["execution_identity"]
            ).decode()
        ),
        f"{wrapper.CONTROL_PREFIX}RUSTC_WRAPPER_PATH": rustc_launcher,
        f"{wrapper.CONTROL_PREFIX}RUSTC_CHILD_FDS": "112,113,114",
        f"{wrapper.CONTROL_PREFIX}LINKER_PATH": str(linker),
        f"{wrapper.CONTROL_PREFIX}LINKER_SHA256": linker_tool["sha256"],
        f"{wrapper.CONTROL_PREFIX}LINKER_EXECUTION_IDENTITY": (
            wrapper.canonical_bytes(
                linker_tool["execution_identity"]
            ).decode()
        ),
        f"{wrapper.CONTROL_PREFIX}LINKER_WRAPPER_PATH": linker_launcher,
        f"{wrapper.CONTROL_PREFIX}BUILD_SCRIPT_CHILD_FDS": (
            "112,113,114"
        ),
    }
    require(
        not any(
            key.startswith(("PYTHON", "LD_", "DYLD_"))
            for key in environment
        ),
        "controller introduced an ambient startup injection",
    )
    arguments = [
        "build",
        "--release",
        "--locked",
        "--offline",
        "--manifest-path",
        str(manifest),
        "--target-dir",
        str(target),
        "--jobs",
        str(jobs),
        "--message-format",
        "json-render-diagnostics",
    ]
    inherited = tuple(DESCRIPTOR_NUMBERS.values())
    monitor.start()
    result = None
    events: list[dict[str, Any]] = []
    try:
        result = sealer.run_sealed(
            executable=cargo,
            expected_sha256=cargo_tool["sha256"],
            expected_execution_identity=cargo_tool[
                "execution_identity"
            ],
            arguments=arguments,
            inherited_descriptors=inherited,
            maximum=256 * 1024 * 1024,
            timeout_seconds=timeout_seconds,
            environment=environment,
            on_spawn=monitor.set_cargo_pid,
        )
    finally:
        for descriptor in DESCRIPTOR_NUMBERS.values():
            try:
                os.close(descriptor)
            except OSError:
                pass
        events = monitor.finish()
    require(
        result is not None
        and result.returncode == 0
        and bool(events),
        "attested Cargo build failed before one authenticated launch: "
        + (
            result.stderr[-4096:].decode(errors="replace")
            if result is not None
            else "sealed Cargo execution did not return"
        ),
    )
    messages = parse_cargo_messages(result.stdout)
    expected_launcher = {
        "sha256": launcher_tool["sha256"],
        "execution_identity": launcher_tool["execution_identity"],
    }
    projection, projection_sha256 = closure.load_receipt_set(
        receipts,
        cargo_pid=monitor._cargo_pid,
        expected_wrapper_sha256=wrapper_sha256,
        expected_sealer_sha256=sealer_sha256,
        expected_launcher=expected_launcher,
        expected_python_runtime=python_runtime,
        expected_tools={"rustc": rustc_tool, "linker": linker_tool},
    )
    raw_payloads = [
        closure.read_receipt(path)[0]
        for path in sorted(receipts.iterdir())
    ]
    event_by_pid = {event["pid"]: event for event in events}
    require(
        len(event_by_pid) == len(events) == len(raw_payloads)
        and all(
            payload["lineage"]["wrapper_pid"] in event_by_pid
            and payload["lineage"]["parent_pid"]
            == event_by_pid[payload["lineage"]["wrapper_pid"]][
                "parent_pid"
            ]
            and payload["launcher"]["path"]
            == event_by_pid[payload["lineage"]["wrapper_pid"]]["path"]
            for payload in raw_payloads
        ),
        "kernel launch events and wrapper receipts are not bijective",
    )
    plan = closure.build_plan(projection)
    payload = {
        "cargo": dict(cargo_tool),
        "cargo_pid": monitor._cargo_pid,
        "arguments": arguments,
        "arguments_sha256": closure.canonical_sha(arguments),
        "environment": dict(sorted(environment.items())),
        "environment_sha256": closure.canonical_sha(
            dict(sorted(environment.items()))
        ),
        "returncode": result.returncode,
        "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        "stdout_bytes": len(result.stdout),
        "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
        "stderr_bytes": len(result.stderr),
        "cargo_message_count": len(messages),
        "launch_events": events,
        "launch_events_sha256": closure.canonical_sha(events),
        "construction_plan": plan,
        "construction_plan_sha256": closure.canonical_sha(plan),
        "projection_sha256": projection_sha256,
    }
    envelope = {
        "schema": CARGO_RECEIPT_SCHEMA,
        "payload_sha256": closure.canonical_sha(payload),
        "payload": payload,
    }
    receipt_path = work_root / "cargo-build-receipt.json"
    wrapper.write_exclusive(
        receipt_path, wrapper.canonical_bytes(envelope) + b"\n", 0o400
    )
    link_artifacts = stage_link_artifacts(
        work_root=work_root,
        held_link_root=held_link_root,
        raw_payloads=raw_payloads,
        published_image=published_runner_binary(messages, target),
    )
    return {
        "receipt_path": str(receipt_path),
        "receipt_sha256": sealer.file_sha(receipt_path),
        "projection_sha256": projection_sha256,
        "invocation_count": len(projection),
        "binary_path": str(
            target / "release" / "fre-external-regex-static-runner"
        ),
        **link_artifacts,
    }
