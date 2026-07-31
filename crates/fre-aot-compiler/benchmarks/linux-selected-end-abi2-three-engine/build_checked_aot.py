#!/usr/bin/env python3
"""Build and post-link-verify the exact ABI2 AOT subject after explicit GO.

This wrapper does not obtain or mint resource-coordinator authority.  Its
deliberately awkward confirmation argument is only an operator assertion that
the external controller has already published the applicable GO.  Before that
GO this file is source-only material and must not be executed.
"""

from __future__ import annotations

import sys

if (
    sys.flags.isolated != 1
    or not sys.dont_write_bytecode
    or sys.flags.optimize != 0
):
    print("REFUSED: use python3 -I -B without optimization", file=sys.stderr)
    raise SystemExit(1)

import argparse
import ctypes
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


RECEIPT_SCHEMA = "fre-aot-selected-end-abi2-checked-build-v1"
POST_LINK_SCHEMA = "fre-aot-selected-end-abi2-post-link-observation-v3"
PROFILE = "linux-target-cpu-local-v1"
TARGET = "aarch64-unknown-linux-gnu"
BIN = "fre-aot-linux-selected-end-abi2-three-engine"
NATIVE_TARGET_FEATURES_ENV = "FRE_ABI2_THREE_ENGINE_NATIVE_TARGET_FEATURES"
POST_GO_CONFIRMATION = "I_HAVE_EXPLICIT_LIVE_CUTOVER_GO"
BENCHMARK_RELATIVE = Path(
    "crates/fre-aot-compiler/benchmarks/"
    "linux-selected-end-abi2-three-engine"
)
BUILDER_NAME = "build_checked_aot.py"
MANIFEST_NAME = "Cargo.toml"
LOCK_NAME = "Cargo.lock"
BUILD_SCRIPT_NAME = "build.rs"
VERIFIER_NAME = "verify_post_link.py"
OBSERVATION_NAME = "post-link-observation.txt"
RECEIPT_NAME = "build-receipt-v1.json"
CARGO_STDOUT_NAME = "cargo-messages.jsonl"
CARGO_STDERR_NAME = "cargo.stderr"
VERIFIER_STDERR_NAME = "verify-post-link.stderr"
RUSTFLAGS = ("-Ctarget-cpu=native", "-Cstrip=none")
ENCODED_RUSTFLAGS = "\x1f".join(RUSTFLAGS)
EXPECTED_SOURCE_CARGO_CONFIG = (
    b'[alias]\n'
    b'check-all = "check --workspace --all-targets --all-features"\n'
    b'test-all = "test --workspace --all-targets --all-features"\n'
    b'lint-all = "clippy --workspace --all-targets --all-features -- -D warnings"\n'
)
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
MAX_SOURCE_BYTES = 16 << 20
MAX_TOOL_BYTES = 1 << 30
MAX_HELPER_BYTES = 64 << 20
MAX_CARGO_OUTPUT_BYTES = 256 << 20
MAX_VERIFIER_OUTPUT_BYTES = 4 << 20
MAX_BINARY_BYTES = 512 << 20
MAX_ARTIFACT_BYTES = 64 << 20
MAX_VERSION_BYTES = 1 << 20
MAX_JSON_MESSAGES = 250_000
MAX_TRACKED_ENTRIES = 250_000
MAX_TRACKED_FILE_BYTES = 1 << 30
MAX_TRACKED_TOTAL_BYTES = 64 << 30
CPU_INFO = Path("/proc/cpuinfo")
READ_ELF = Path("/usr/bin/readelf")
OBJECT_DUMP = Path("/usr/bin/objdump")
PR_SVE_GET_VL = 51
PR_SVE_VL_LEN_MASK = 0xFFFF
ARTIFACT_NAMES = {
    "implementation_object": "selected-end-implementation-v2.o",
    "direct_glue_object": "selected-end-direct-glue-v2.o",
    "direct_header": "selected-end-direct-v2.h",
    "expectation": "selected-end-expectation-v2.bin",
    "compiler_receipt": "selected-end-compiler-receipt-v2.bin",
    "bundle_receipt": "selected-end-bundle-receipt-v2.bin",
    "deployment_receipt": "selected-end-deployment-receipt-v2.bin",
    "deployment_binding": "linked_selected_end_deployment_v2.rs",
    "post_link_contract": "selected-end-post-link-contract-v2.tsv",
    "benchmark_metadata": "linked_selected_end_metadata_v2.rs",
    "consumer_hot_callsite": "linked_selected_end_hot_callsite_v2.rs",
}
POST_LINK_FIELDS = {
    "source_commit",
    "source_tree",
    "artifact_identity",
    "compile_identity",
    "implementation_object_identity",
    "glue_object_identity",
    "bundle_identity",
    "deployment_binding_identity",
    "deployment_receipt_identity",
    "final_binary_sha256",
    "helper_sha256",
    "profile",
    "wrapper_call",
    "generated_proof_callsite",
    "primary_aot_call",
    "consumer_hot_callsite_final_observed",
    "generated_binding_authenticated",
    "deployment_receipt_authenticated",
    "entry_bytes_equal",
    "payload_bytes_equal",
    "metadata_bytes_equal",
    "compile_identity_derived",
    "reject_plt",
    "reject_blr",
    "reject_x4_argument",
    "consumer_loop_x4_scratch",
    "result_slot_bytes",
    "runtime_authority",
    "promotion_authority",
}


class Refusal(RuntimeError):
    """A fail-closed checked-build refusal."""


@dataclass(frozen=True)
class Snapshot:
    """A stable regular-file observation used for later mutation checks."""

    label: str
    path: Path
    signature: tuple[int, int, int, int, int, int]
    record: dict[str, Any]


@dataclass(frozen=True)
class ExecutableAlias:
    """One fixed executable symlink and its directly named canonical target."""

    label: str
    path: Path
    signature: tuple[int, int, int, int, int, int]
    link_text: str
    target: Path
    record: dict[str, Any]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def signature(status: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


def canonical_directory(raw_path: str | Path, label: str) -> Path:
    path = Path(raw_path)
    require(path.is_absolute(), f"{label} must be absolute")
    resolved = Path(os.path.realpath(path))
    require(path == resolved, f"{label} must not contain symlinks")
    status = os.stat(path, follow_symlinks=False)
    require(stat.S_ISDIR(status.st_mode), f"{label} must be a directory")
    return path


def path_is_within(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory)
    except ValueError:
        return False
    return True


def hash_fd(
    fd: int,
    size: int,
    maximum: int,
    label: str,
    *,
    capture: bool,
) -> tuple[str, bytes]:
    require(0 <= size <= maximum, f"{label} has an invalid size")
    digest = hashlib.sha256()
    chunks: list[bytes] = []
    offset = 0
    while offset < size:
        chunk = os.pread(fd, min(1 << 20, size - offset), offset)
        require(bool(chunk), f"{label} changed while being read")
        digest.update(chunk)
        if capture:
            chunks.append(chunk)
        offset += len(chunk)
    require(os.fstat(fd).st_size == size, f"{label} size changed while being read")
    return digest.hexdigest(), b"".join(chunks)


def inspect_regular(
    raw_path: str | Path,
    label: str,
    maximum: int,
    *,
    allow_empty: bool = False,
    capture: bool = False,
    executable: bool = False,
) -> tuple[Snapshot, bytes]:
    path = Path(raw_path)
    require(path.is_absolute(), f"{label} must be absolute")
    resolved = Path(os.path.realpath(path))
    require(path == resolved, f"{label} must not contain symlinks")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise Refusal(f"cannot open {label}: {error}") from error
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode), f"{label} must be a regular file")
        require(
            (allow_empty or before.st_size > 0) and before.st_size <= maximum,
            f"{label} has an invalid size",
        )
        if executable:
            require(before.st_mode & 0o111 != 0, f"{label} is not executable")
        digest, value = hash_fd(
            fd,
            before.st_size,
            maximum,
            label,
            capture=capture,
        )
        after = os.fstat(fd)
        current = os.stat(path, follow_symlinks=False)
        expected = signature(before)
        require(
            signature(after) == expected and signature(current) == expected,
            f"{label} changed while being inspected",
        )
        record = {
            "bytes": before.st_size,
            "mode": f"{stat.S_IMODE(before.st_mode):04o}",
            "path": os.fspath(path),
            "sha256": digest,
        }
        return Snapshot(label, path, expected, record), value
    finally:
        os.close(fd)


def require_unchanged(snapshot: Snapshot, maximum: int) -> None:
    current, _ = inspect_regular(
        snapshot.path,
        snapshot.label,
        maximum,
        allow_empty=snapshot.record["bytes"] == 0,
        capture=False,
        executable=bool(int(snapshot.record["mode"], 8) & 0o111),
    )
    require(
        current.signature == snapshot.signature
        and current.record == snapshot.record,
        f"{snapshot.label} changed during the checked build",
    )


def inspect_fixed_executable(
    path: Path,
    label: str,
) -> tuple[Snapshot, ExecutableAlias | None]:
    require(path.is_absolute(), f"{label} path must be absolute")
    try:
        alias_status = os.lstat(path)
    except OSError as error:
        raise Refusal(f"cannot inspect fixed {label} path: {error}") from error
    if stat.S_ISREG(alias_status.st_mode):
        snapshot, _ = inspect_regular(
            path,
            label,
            MAX_TOOL_BYTES,
            executable=True,
        )
        return snapshot, None
    require(
        stat.S_ISLNK(alias_status.st_mode),
        f"fixed {label} path is neither a regular file nor a symlink",
    )
    try:
        link_text = os.readlink(path)
    except OSError as error:
        raise Refusal(f"cannot read fixed {label} symlink: {error}") from error
    link_bytes = os.fsencode(link_text)
    require(
        0 < len(link_bytes) <= 4096,
        f"fixed {label} symlink target is empty or unbounded",
    )
    direct_target = Path(link_text)
    if not direct_target.is_absolute():
        direct_target = path.parent / direct_target
    direct_target = Path(os.path.normpath(direct_target))
    resolved_target = Path(os.path.realpath(path))
    require(
        direct_target == resolved_target and resolved_target != path,
        f"fixed {label} must be a single-hop symlink to a canonical target",
    )
    target_snapshot, _ = inspect_regular(
        resolved_target,
        f"{label} canonical target",
        MAX_TOOL_BYTES,
        executable=True,
    )
    current_status = os.lstat(path)
    current_link_text = os.readlink(path)
    expected_signature = signature(alias_status)
    require(
        signature(current_status) == expected_signature
        and current_link_text == link_text
        and Path(os.path.realpath(path)) == resolved_target,
        f"fixed {label} symlink changed while being inspected",
    )
    alias = ExecutableAlias(
        label=label,
        path=path,
        signature=expected_signature,
        link_text=link_text,
        target=resolved_target,
        record={
            "kind": "single-hop-symlink",
            "link_sha256": sha256_bytes(link_bytes),
            "link_text": link_text,
            "mode": f"{stat.S_IMODE(alias_status.st_mode):04o}",
            "path": os.fspath(path),
            "target": os.fspath(resolved_target),
        },
    )
    return target_snapshot, alias


def require_executable_alias_unchanged(alias: ExecutableAlias) -> None:
    try:
        current_status = os.lstat(alias.path)
        current_link_text = os.readlink(alias.path)
    except OSError as error:
        raise Refusal(f"fixed {alias.label} symlink changed: {error}") from error
    require(
        signature(current_status) == alias.signature
        and stat.S_ISLNK(current_status.st_mode)
        and current_link_text == alias.link_text
        and Path(os.path.realpath(alias.path)) == alias.target,
        f"fixed {alias.label} symlink changed during the checked build",
    )


def inspect_virtual_file(
    path: Path,
    label: str,
    maximum: int,
) -> tuple[dict[str, Any], bytes]:
    require(path.is_absolute(), f"{label} must be absolute")
    require(path == Path(os.path.realpath(path)), f"{label} must not be a symlink")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode), f"{label} must be a regular virtual file")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(1 << 20, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            require(total <= maximum, f"{label} exceeds its size bound")
        value = b"".join(chunks)
        require(bool(value), f"{label} is empty")
        after = os.fstat(fd)
        current = os.stat(path, follow_symlinks=False)
        require(
            (before.st_dev, before.st_ino, before.st_mode)
            == (after.st_dev, after.st_ino, after.st_mode)
            == (current.st_dev, current.st_ino, current.st_mode),
            f"{label} changed identity while being read",
        )
        return {
            "bytes": len(value),
            "mode": f"{stat.S_IMODE(before.st_mode):04o}",
            "path": os.fspath(path),
            "sha256": sha256_bytes(value),
        }, value
    finally:
        os.close(fd)


def current_sve_vector_bytes() -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    prctl.restype = ctypes.c_int
    ctypes.set_errno(0)
    raw = prctl(PR_SVE_GET_VL, 0, 0, 0, 0)
    if raw < 0:
        error_number = ctypes.get_errno()
        raise Refusal(
            f"PR_SVE_GET_VL failed: {os.strerror(error_number)}"
        )
    vector_bytes = raw & PR_SVE_VL_LEN_MASK
    require(vector_bytes == 16, f"current-thread SVE VL is {vector_bytes}, not 16")
    return vector_bytes


def parse_homogeneous_cpuinfo(raw: bytes) -> dict[str, Any]:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise Refusal("/proc/cpuinfo is not ASCII") from error
    processors: list[dict[str, str]] = []
    for section in text.split("\n\n"):
        if not section.strip():
            continue
        fields: dict[str, str] = {}
        for line in section.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip()
            require(key not in fields, f"/proc/cpuinfo repeats field {key!r}")
            fields[key] = value.strip()
        if "processor" in fields:
            processors.append(fields)
    require(bool(processors), "/proc/cpuinfo has no processor sections")
    required_features = {"asimd", "sve", "sve2"}
    feature_sets: list[set[str]] = []
    signatures: list[tuple[str, str, str, str, str]] = []
    for fields in processors:
        require(
            all(
                fields.get(name, "") != ""
                for name in (
                    "CPU implementer",
                    "CPU architecture",
                    "CPU variant",
                    "CPU part",
                    "CPU revision",
                    "Features",
                )
            ),
            "/proc/cpuinfo CPU identity is incomplete",
        )
        require(
            fields.get("CPU implementer", "").lower() == "0x41"
            and fields.get("CPU part", "").lower() == "0xd84",
            "build host is not homogeneous Arm 0x41/0xd84",
        )
        features = set(fields.get("Features", "").split())
        require(
            required_features <= features,
            "build host lacks ASIMD, SVE, or SVE2",
        )
        feature_sets.append(features)
        signatures.append(
            (
                fields.get("CPU implementer", "").lower(),
                fields.get("CPU architecture", "").lower(),
                fields.get("CPU variant", "").lower(),
                fields.get("CPU part", "").lower(),
                fields.get("CPU revision", "").lower(),
            )
        )
    require(
        all(features == feature_sets[0] for features in feature_sets)
        and all(cpu == signatures[0] for cpu in signatures),
        "build host CPU sections are not homogeneous",
    )
    return {
        "cpu_architecture": signatures[0][1],
        "cpu_implementer": signatures[0][0],
        "cpu_part": signatures[0][3],
        "cpu_revision": signatures[0][4],
        "cpu_variant": signatures[0][2],
        "feature_words": sorted(feature_sets[0]),
        "processor_count": len(processors),
        "required_features": sorted(required_features),
    }


def require_cpuinfo_unchanged(
    expected_record: dict[str, Any],
    expected_raw: bytes,
) -> None:
    record, raw = inspect_virtual_file(CPU_INFO, "host CPU information", MAX_SOURCE_BYTES)
    require(
        record == expected_record and raw == expected_raw,
        "host CPU information changed during the checked build",
    )
    current_sve_vector_bytes()


def rustc_native_cfg(
    rustc: Snapshot,
    source_root: Path,
) -> dict[str, Any]:
    command = [
        os.fspath(rustc.path),
        "--print",
        "cfg",
        "--target",
        TARGET,
        "-Ctarget-cpu=native",
    ]
    environment = base_environment()
    output = run_bounded(
        command,
        cwd=source_root,
        environment=environment,
        label="rustc native cfg",
    )
    try:
        text = output.decode("ascii")
    except UnicodeDecodeError as error:
        raise Refusal("rustc native cfg is not ASCII") from error
    require(text.endswith("\n"), "rustc native cfg is not newline-terminated")
    ordered_lines = text.splitlines()
    lines = set(ordered_lines)
    require(
        len(lines) == len(ordered_lines),
        "rustc native cfg repeats a configuration line",
    )
    required = {
        'target_arch="aarch64"',
        'target_endian="little"',
        'target_env="gnu"',
        'target_feature="neon"',
        'target_feature="sve"',
        'target_feature="sve2"',
    }
    require(required <= lines, "rustc native cfg lacks AArch64 NEON/SVE/SVE2")
    target_feature_prefix = 'target_feature="'
    target_features = sorted(
        line[len(target_feature_prefix) : -1]
        for line in lines
        if line.startswith(target_feature_prefix) and line.endswith('"')
    )
    require(
        bool(target_features)
        and len(target_features) == len(set(target_features))
        and all(
            re.fullmatch(r"[a-z0-9][a-z0-9._+-]*", feature) is not None
            for feature in target_features
        ),
        "rustc native cfg target-feature set is malformed",
    )
    return {
        "bytes": len(output),
        "command": command,
        "environment": environment,
        "required_cfg": sorted(required),
        "sha256": sha256_bytes(output),
        "stdout": text,
        "target_features": target_features,
    }


def base_environment() -> dict[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TERM": "dumb",
        "TZ": "UTC",
    }


def run_bounded(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    label: str,
    maximum: int = MAX_VERSION_BYTES,
    allow_empty: bool = False,
) -> bytes:
    try:
        result = subprocess.run(
            command,
            check=False,
            close_fds=True,
            cwd=cwd,
            env=environment,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise Refusal(f"{label} failed to execute: {error}") from error
    require(result.returncode == 0, f"{label} exited {result.returncode}")
    require(not result.stderr, f"{label} wrote stderr")
    require(
        (allow_empty or len(result.stdout) > 0) and len(result.stdout) <= maximum,
        f"{label} output is invalid",
    )
    return result.stdout


def one_ascii_line(value: bytes, label: str) -> str:
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError as error:
        raise Refusal(f"{label} is not ASCII") from error
    require(text.endswith("\n") and text.count("\n") == 1, f"{label} is not one line")
    return text[:-1]


def git_output(git: Path, source_root: Path, *arguments: str) -> bytes:
    return run_bounded(
        [
            os.fspath(git),
            "--no-replace-objects",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.untrackedCache=false",
            "-C",
            os.fspath(source_root),
            *arguments,
        ],
        cwd=source_root,
        environment=base_environment(),
        label=f"git {' '.join(arguments)}",
        maximum=MAX_SOURCE_BYTES,
        allow_empty=True,
    )


def git_blob_hasher(size: int) -> Any:
    digest = hashlib.sha1(usedforsecurity=False)
    digest.update(f"blob {size}\0".encode("ascii"))
    return digest


def inspect_tracked_regular(
    path: Path,
    expected_mode: str,
    expected_blob: str,
) -> tuple[int, int, str]:
    require(
        path == Path(os.path.realpath(path)),
        f"tracked path contains a symlink: {path}",
    )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise Refusal(f"cannot open tracked path {path}: {error}") from error
    try:
        before = os.fstat(fd)
        require(
            stat.S_ISREG(before.st_mode)
            and before.st_size <= MAX_TRACKED_FILE_BYTES,
            f"tracked path is not a bounded regular file: {path}",
        )
        expected_executable = expected_mode == "100755"
        require(
            bool(before.st_mode & 0o111) == expected_executable,
            f"tracked executable mode differs from HEAD: {path}",
        )
        git_digest = git_blob_hasher(before.st_size)
        strong_digest = hashlib.sha256()
        offset = 0
        while offset < before.st_size:
            chunk = os.pread(fd, min(1 << 20, before.st_size - offset), offset)
            require(bool(chunk), f"tracked path changed while being read: {path}")
            git_digest.update(chunk)
            strong_digest.update(chunk)
            offset += len(chunk)
        after = os.fstat(fd)
        current = os.stat(path, follow_symlinks=False)
        require(
            signature(after) == signature(before)
            and signature(current) == signature(before),
            f"tracked path changed while being read: {path}",
        )
        require(
            git_digest.hexdigest() == expected_blob,
            f"tracked path bytes differ from HEAD: {path}",
        )
        return before.st_size, stat.S_IMODE(before.st_mode), strong_digest.hexdigest()
    finally:
        os.close(fd)


def inspect_tracked_symlink(
    path: Path,
    expected_blob: str,
) -> tuple[int, int, str]:
    require(
        path.parent == Path(os.path.realpath(path.parent)),
        f"tracked symlink has a symlinked ancestor: {path}",
    )
    try:
        before = os.lstat(path)
        link_text = os.readlink(path)
    except OSError as error:
        raise Refusal(f"cannot inspect tracked symlink {path}: {error}") from error
    require(stat.S_ISLNK(before.st_mode), f"tracked path is not a symlink: {path}")
    link_bytes = os.fsencode(link_text)
    require(
        len(link_bytes) <= MAX_TRACKED_FILE_BYTES,
        f"tracked symlink is unbounded: {path}",
    )
    git_digest = git_blob_hasher(len(link_bytes))
    git_digest.update(link_bytes)
    require(
        git_digest.hexdigest() == expected_blob,
        f"tracked symlink differs from HEAD: {path}",
    )
    try:
        after = os.lstat(path)
        current_link_text = os.readlink(path)
    except OSError as error:
        raise Refusal(f"tracked symlink changed while being read: {path}") from error
    require(
        signature(after) == signature(before) and current_link_text == link_text,
        f"tracked symlink changed while being read: {path}",
    )
    return len(link_bytes), stat.S_IMODE(before.st_mode), sha256_bytes(link_bytes)


def verify_tracked_worktree(
    source_root: Path,
    tree_inventory: bytes,
) -> dict[str, Any]:
    split_rows = tree_inventory.split(b"\x00")
    require(
        split_rows[-1] == b"" and 1 < len(split_rows) <= MAX_TRACKED_ENTRIES + 1,
        "Git tree inventory is empty, unterminated, or unbounded",
    )
    closure = hashlib.sha256()
    total_bytes = 0
    paths: set[bytes] = set()
    for row in split_rows[:-1]:
        require(b"\t" in row, "Git tree inventory row is malformed")
        metadata, raw_path = row.split(b"\t", 1)
        fields = metadata.split(b" ")
        require(
            len(fields) == 3
            and fields[1] == b"blob"
            and HEX40.fullmatch(os.fsdecode(fields[2])) is not None,
            "Git tree inventory contains a non-blob or malformed row",
        )
        mode = fields[0].decode("ascii")
        require(
            mode in {"100644", "100755", "120000"},
            "Git tree inventory contains an unsupported mode",
        )
        require(
            raw_path not in paths and b"\x00" not in raw_path and raw_path != b"",
            "Git tree inventory repeats or omits a path",
        )
        paths.add(raw_path)
        decoded_path = os.fsdecode(raw_path)
        relative = Path(decoded_path)
        require(
            not relative.is_absolute()
            and relative.parts
            and all(part not in {"", ".", ".."} for part in relative.parts),
            "Git tree inventory contains an unsafe path",
        )
        absolute = source_root / relative
        expected_blob = fields[2].decode("ascii")
        if mode == "120000":
            size, observed_mode, strong_digest = inspect_tracked_symlink(
                absolute,
                expected_blob,
            )
        else:
            size, observed_mode, strong_digest = inspect_tracked_regular(
                absolute,
                mode,
                expected_blob,
            )
        total_bytes += size
        require(
            total_bytes <= MAX_TRACKED_TOTAL_BYTES,
            "tracked worktree byte count exceeds its bound",
        )
        closure.update(len(raw_path).to_bytes(8, "big"))
        closure.update(raw_path)
        closure.update(mode.encode("ascii"))
        closure.update(observed_mode.to_bytes(4, "big"))
        closure.update(size.to_bytes(8, "big"))
        closure.update(bytes.fromhex(strong_digest))
    return {
        "entry_count": len(paths),
        "inventory_sha256": sha256_bytes(tree_inventory),
        "raw_byte_count": total_bytes,
        "worktree_closure_sha256": closure.hexdigest(),
    }


def verify_clean_source(
    git: Path,
    source_root: Path,
    source_commit: str,
    source_tree: str,
) -> dict[str, Any]:
    top = one_ascii_line(
        git_output(git, source_root, "rev-parse", "--show-toplevel"),
        "git top-level",
    )
    require(Path(top) == source_root, "source root differs from Git top-level")
    head = one_ascii_line(
        git_output(git, source_root, "rev-parse", "--verify", "HEAD^{commit}"),
        "Git HEAD",
    )
    tree = one_ascii_line(
        git_output(git, source_root, "rev-parse", "--verify", "HEAD^{tree}"),
        "Git HEAD tree",
    )
    commit_tree = one_ascii_line(
        git_output(
            git,
            source_root,
            "rev-parse",
            "--verify",
            f"{source_commit}^{{tree}}",
        ),
        "caller commit tree",
    )
    require(head == source_commit, "caller source commit differs from clean checkout HEAD")
    require(tree == source_tree, "caller source tree differs from checkout HEAD tree")
    require(
        commit_tree == source_tree,
        "caller source tree is not the tree of the caller source commit",
    )
    index_rows = git_output(
        git,
        source_root,
        "ls-files",
        "-v",
        "-z",
    )
    split_index_rows = index_rows.split(b"\x00")
    require(
        split_index_rows[-1] == b"" and len(split_index_rows) > 1,
        "Git index inventory is empty or unterminated",
    )
    index_entries = split_index_rows[:-1]
    require(
        all(
            len(row) >= 3 and row[:2] == b"H "
            for row in index_entries
        ),
        "Git index contains skip-worktree, assume-unchanged, or nonordinary entries",
    )
    tree_inventory = git_output(
        git,
        source_root,
        "ls-tree",
        "-r",
        "-z",
        "--abbrev=40",
        "--full-tree",
        source_tree,
    )
    tracked_worktree = verify_tracked_worktree(source_root, tree_inventory)
    require(
        tracked_worktree["entry_count"] == len(index_entries),
        "Git index and HEAD tree entry counts differ",
    )
    config_inventory = git_output(
        git,
        source_root,
        "config",
        "--null",
        "--show-origin",
        "--show-scope",
        "--list",
    )
    status = git_output(
        git,
        source_root,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignored=matching",
        "--ignore-submodules=none",
    )
    require(status == b"", "source checkout contains tracked, untracked, or ignored dirt")
    commit_unix_seconds = one_ascii_line(
        git_output(
            git,
            source_root,
            "show",
            "-s",
            "--format=%ct",
            "--no-show-signature",
            source_commit,
        ),
        "source commit timestamp",
    )
    require(
        commit_unix_seconds.isascii()
        and commit_unix_seconds.isdigit()
        and 0 < int(commit_unix_seconds) < (1 << 63),
        "source commit timestamp is invalid",
    )
    return {
        "clean_status_sha256": sha256_bytes(status),
        "commit": head,
        "commit_unix_seconds": commit_unix_seconds,
        "config_inventory_bytes": len(config_inventory),
        "config_inventory_sha256": sha256_bytes(config_inventory),
        "index_entry_count": len(index_entries),
        "index_inventory_sha256": sha256_bytes(index_rows),
        "tracked_worktree": tracked_worktree,
        "tree": tree,
    }


def require_tracked(
    git: Path,
    source_root: Path,
    source_path: Path,
    label: str,
) -> None:
    try:
        relative = source_path.relative_to(source_root)
    except ValueError as error:
        raise Refusal(f"{label} is outside source root") from error
    output = git_output(
        git,
        source_root,
        "ls-files",
        "--error-unmatch",
        "--",
        relative.as_posix(),
    )
    require(
        one_ascii_line(output, f"tracked {label}") == relative.as_posix(),
        f"{label} is not exactly tracked",
    )


def reject_cargo_configuration(
    cwd: Path,
    cargo_home: Path,
    allowed_source_config: Path,
) -> None:
    directories = [cwd, *cwd.parents]
    candidates: list[Path] = []
    for directory in directories:
        candidates.extend(
            (
                directory / ".cargo" / "config",
                directory / ".cargo" / "config.toml",
            )
        )
    candidates.extend((cargo_home / "config", cargo_home / "config.toml"))
    for candidate in candidates:
        if candidate == allowed_source_config:
            continue
        require(
            not os.path.lexists(candidate),
            f"ambient Cargo configuration is forbidden: {candidate}",
        )


def fsync_directory(path: Path) -> None:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def create_output_directory(
    raw_path: str,
    source_root: Path,
    cargo_home: Path,
) -> tuple[Path, int]:
    path = Path(raw_path)
    require(path.is_absolute(), "output directory must be absolute")
    require(not os.path.lexists(path), "output directory already exists")
    parent = canonical_directory(path.parent, "output parent")
    require(
        not path_is_within(path, source_root)
        and not path_is_within(source_root, path),
        "output directory must be disjoint from source checkout",
    )
    require(
        not path_is_within(path, cargo_home)
        and not path_is_within(cargo_home, path),
        "output directory must be disjoint from Cargo home",
    )
    try:
        os.mkdir(path, 0o700)
        fsync_directory(parent)
    except OSError as error:
        raise Refusal(f"cannot create output directory: {error}") from error
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    root_fd = os.open(path, flags)
    try:
        for name in ("home", "tmp"):
            os.mkdir(name, 0o700, dir_fd=root_fd)
        os.fsync(root_fd)
    except BaseException:
        os.close(root_fd)
        raise
    return path, root_fd


def open_exclusive(root_fd: int, name: str, label: str) -> int:
    require(
        name not in ("", ".", "..") and "/" not in name,
        f"{label} has an unsafe name",
    )
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        fd = os.open(name, flags, 0o600, dir_fd=root_fd)
        os.fsync(root_fd)
        return fd
    except OSError as error:
        raise Refusal(f"cannot create {label}: {error}") from error


def seal_fd(fd: int, mode: int, label: str) -> os.stat_result:
    try:
        os.fsync(fd)
        os.fchmod(fd, mode)
        os.fsync(fd)
        status = os.fstat(fd)
        require(
            stat.S_ISREG(status.st_mode) and status.st_nlink == 1,
            f"{label} is not one privately owned regular file",
        )
        require(
            stat.S_IMODE(status.st_mode) == mode,
            f"{label} did not seal to mode {mode:04o}",
        )
        return status
    finally:
        os.close(fd)


def write_all(fd: int, value: bytes, label: str) -> None:
    offset = 0
    while offset < len(value):
        try:
            written = os.write(fd, value[offset:])
        except OSError as error:
            raise Refusal(f"{label} write failed: {error}") from error
        require(written > 0, f"{label} write made no progress")
        offset += written


def write_exclusive_read_only(
    root_fd: int,
    output_root: Path,
    name: str,
    value: bytes,
    label: str,
) -> Snapshot:
    fd = open_exclusive(root_fd, name, label)
    try:
        write_all(fd, value, label)
    except BaseException:
        os.close(fd)
        raise
    seal_fd(fd, 0o444, label)
    os.fsync(root_fd)
    snapshot, actual = inspect_regular(
        output_root / name,
        label,
        max(len(value), 1),
        capture=True,
    )
    require(actual == value, f"{label} changed after publication")
    return snapshot


def version_record(
    snapshot: Snapshot,
    arguments: list[str],
    cwd: Path,
    *,
    invocation_path: Path | None = None,
    alias: ExecutableAlias | None = None,
) -> dict[str, Any]:
    command_path = snapshot.path if invocation_path is None else invocation_path
    output = run_bounded(
        [os.fspath(command_path), *arguments],
        cwd=cwd,
        environment=base_environment(),
        label=f"{snapshot.label} version",
    )
    try:
        text = output.decode("utf-8")
    except UnicodeDecodeError as error:
        raise Refusal(f"{snapshot.label} version is not UTF-8") from error
    require("\x00" not in text, f"{snapshot.label} version contains NUL")
    result = dict(snapshot.record)
    result["invocation_path"] = os.fspath(command_path)
    result["invocation_alias"] = None if alias is None else alias.record
    result["version_command"] = [os.fspath(command_path), *arguments]
    result["version_environment"] = base_environment()
    result["version_sha256"] = sha256_bytes(output)
    result["version_stdout"] = text
    return result


def execute_to_logs(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    stdout_fd: int,
    stderr_fd: int,
    label: str,
) -> int:
    try:
        result = subprocess.run(
            command,
            check=False,
            close_fds=True,
            cwd=cwd,
            env=environment,
            stderr=stderr_fd,
            stdout=stdout_fd,
        )
    except OSError as error:
        raise Refusal(f"{label} failed to execute: {error}") from error
    return result.returncode


def parse_cargo_messages(
    raw: bytes,
    benchmark: Path,
    target_root: Path,
) -> tuple[str, Path, Path]:
    require(
        raw.endswith(b"\n") and 0 < raw.count(b"\n") <= MAX_JSON_MESSAGES,
        "Cargo JSON stream is empty, unterminated, or unbounded",
    )
    messages: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(raw.splitlines(), 1):
        try:
            message = json.loads(raw_line)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise Refusal(f"Cargo JSON line {line_number} is invalid") from error
        require(isinstance(message, dict), f"Cargo JSON line {line_number} is not an object")
        require(isinstance(message.get("reason"), str), "Cargo message lacks a reason")
        messages.append(message)

    finished = [
        message
        for message in messages
        if message.get("reason") == "build-finished"
    ]
    require(
        len(finished) == 1 and finished[0].get("success") is True,
        "Cargo JSON does not contain one successful build-finished event",
    )
    expected_source = benchmark / "src" / "main.rs"
    candidates: list[dict[str, Any]] = []
    for message in messages:
        if message.get("reason") != "compiler-artifact":
            continue
        target = message.get("target")
        if not isinstance(target, dict):
            continue
        if (
            target.get("name") == BIN
            and target.get("kind") == ["bin"]
            and target.get("crate_types") == ["bin"]
            and target.get("src_path") == os.fspath(expected_source)
            and isinstance(message.get("executable"), str)
        ):
            candidates.append(message)
    require(
        len(candidates) == 1,
        "Cargo JSON does not identify one exact benchmark executable",
    )
    artifact = candidates[0]
    require(artifact.get("fresh") is False, "benchmark executable was unexpectedly fresh")
    profile = artifact.get("profile")
    require(isinstance(profile, dict), "benchmark artifact profile is absent")
    require(
        profile.get("opt_level") == "3"
        and profile.get("debug_assertions") is False
        and profile.get("overflow_checks") is False
        and profile.get("test") is False,
        "benchmark artifact does not have the exact release profile",
    )
    package_id = artifact.get("package_id")
    require(isinstance(package_id, str) and package_id != "", "benchmark package ID is absent")

    build_scripts = [
        message
        for message in messages
        if message.get("reason") == "build-script-executed"
        and message.get("package_id") == package_id
        and isinstance(message.get("out_dir"), str)
    ]
    require(
        len(build_scripts) == 1,
        "Cargo JSON does not identify one exact benchmark build-script OUT_DIR",
    )
    executable = Path(artifact["executable"])
    out_dir = Path(build_scripts[0]["out_dir"])
    require(
        executable.is_absolute() and out_dir.is_absolute(),
        "Cargo returned a relative executable or OUT_DIR",
    )
    resolved_executable = Path(os.path.realpath(executable))
    resolved_out_dir = Path(os.path.realpath(out_dir))
    require(
        executable == resolved_executable and out_dir == resolved_out_dir,
        "Cargo executable or OUT_DIR contains a symlink",
    )
    executable = resolved_executable
    out_dir = resolved_out_dir
    require(
        path_is_within(executable, target_root)
        and path_is_within(out_dir, target_root),
        "Cargo executable or OUT_DIR escaped the fresh target directory",
    )
    require(out_dir.is_dir(), "Cargo build-script OUT_DIR is absent")
    return package_id, executable, out_dir


def parse_observation(
    raw: bytes,
    source_commit: str,
    source_tree: str,
    helper_sha256: str,
    binary_sha256: str,
) -> dict[str, str]:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise Refusal("post-link observation is not ASCII") from error
    require(
        text.endswith("\n") and text.count("\n") == 1,
        "post-link observation must be exactly one newline-terminated line",
    )
    columns = text[:-1].split("\t")
    require(
        columns[:3] == ["OBSERVATION", POST_LINK_SCHEMA, "PASS"],
        "post-link verifier did not emit its canonical PASS prefix",
    )
    fields: dict[str, str] = {}
    for column in columns[3:]:
        require("=" in column, "post-link observation field is malformed")
        key, value = column.split("=", 1)
        require(key != "" and key not in fields, "post-link observation repeats a field")
        fields[key] = value
    require(set(fields) == POST_LINK_FIELDS, "post-link observation field set changed")
    require(
        fields["source_commit"] == source_commit
        and fields["source_tree"] == source_tree
        and fields["helper_sha256"] == helper_sha256
        and fields["profile"] == PROFILE
        and fields["final_binary_sha256"] == binary_sha256,
        "post-link observation identity differs from checked build inputs",
    )
    for key in (
        "artifact_identity",
        "compile_identity",
        "implementation_object_identity",
        "glue_object_identity",
        "bundle_identity",
        "deployment_binding_identity",
        "deployment_receipt_identity",
        "final_binary_sha256",
        "helper_sha256",
    ):
        require(HEX64.fullmatch(fields[key]) is not None, f"{key} is not canonical SHA-256")
    fixed = {
        "wrapper_call": "R_AARCH64_CALL26-to-direct-bl",
        "generated_proof_callsite": "hidden-direct-bl-exact-entry",
        "primary_aot_call": "hidden-consumer-loop-direct-bl-exact-entry",
        "consumer_hot_callsite_final_observed": "true",
        "generated_binding_authenticated": "true",
        "deployment_receipt_authenticated": "true",
        "entry_bytes_equal": "true",
        "payload_bytes_equal": "true",
        "metadata_bytes_equal": "true",
        "compile_identity_derived": "true",
        "reject_plt": "true",
        "reject_blr": "true",
        "reject_x4_argument": "true",
        "consumer_loop_x4_scratch": "unconstrained-nonabi",
        "result_slot_bytes": "0",
        "runtime_authority": "absent",
        "promotion_authority": "absent",
    }
    require(
        all(fields[key] == value for key, value in fixed.items()),
        "post-link observation proof claims changed",
    )
    return fields


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description=(
            "Build and post-link-verify the source-bound ABI2 AOT subject. "
            "Do not execute before the external controller publishes GO."
        )
    )
    result.add_argument("--source-root", required=True)
    result.add_argument("--source-commit", required=True)
    result.add_argument("--source-tree", required=True)
    result.add_argument("--helper", required=True)
    result.add_argument("--cargo", required=True)
    result.add_argument("--rustc", required=True)
    result.add_argument("--linker", required=True)
    result.add_argument("--git", required=True)
    result.add_argument("--cargo-home", required=True)
    result.add_argument("--output-directory", required=True)
    result.add_argument("--explicit-post-fence-go", required=True)
    return result


def main() -> int:
    arguments = parser().parse_args()
    require(
        arguments.explicit_post_fence_go == POST_GO_CONFIRMATION,
        "explicit post-fence GO confirmation is absent",
    )
    require(
        HEX40.fullmatch(arguments.source_commit) is not None
        and HEX40.fullmatch(arguments.source_tree) is not None,
        "source commit/tree are not canonical lowercase Git object IDs",
    )
    require(
        platform.system() == "Linux"
        and platform.machine().lower() in {"aarch64", "arm64"}
        and sys.byteorder == "little",
        "checked build requires a native little-endian Linux/AArch64 host",
    )
    os.umask(0o077)

    source_root = canonical_directory(arguments.source_root, "source root")
    benchmark = source_root / BENCHMARK_RELATIVE
    require(
        canonical_directory(benchmark, "benchmark directory") == benchmark,
        "benchmark directory is not canonical",
    )
    script_path = Path(os.path.realpath(__file__))
    require(
        script_path == benchmark / BUILDER_NAME,
        "builder is not executing from the exact source checkout",
    )
    cargo_home = canonical_directory(arguments.cargo_home, "Cargo home")
    require(
        not path_is_within(cargo_home, source_root)
        and not path_is_within(source_root, cargo_home),
        "Cargo home must be disjoint from source checkout",
    )
    source_cargo_config = source_root / ".cargo" / "config.toml"
    reject_cargo_configuration(benchmark, cargo_home, source_cargo_config)

    tool_inputs = {
        "cargo": (arguments.cargo, ["--version", "--verbose"]),
        "git": (arguments.git, ["--version"]),
        "linker": (arguments.linker, ["--version"]),
        "objdump": (OBJECT_DUMP, ["--version"]),
        "readelf": (READ_ELF, ["--version"]),
        "rustc": (arguments.rustc, ["--version", "--verbose"]),
    }
    tool_snapshots: dict[str, Snapshot] = {}
    tool_invocation_paths: dict[str, Path] = {}
    tool_aliases: dict[str, ExecutableAlias] = {}
    for name, (path, _) in tool_inputs.items():
        invocation_path = Path(path)
        if name in {"objdump", "readelf"}:
            snapshot, alias = inspect_fixed_executable(invocation_path, name)
            if alias is not None:
                tool_aliases[name] = alias
        else:
            snapshot, _ = inspect_regular(
                invocation_path,
                name,
                MAX_TOOL_BYTES,
                executable=True,
            )
        tool_snapshots[name] = snapshot
        tool_invocation_paths[name] = invocation_path
    python_path = Path(sys.executable).resolve(strict=True)
    python_snapshot, _ = inspect_regular(
        python_path,
        "python",
        MAX_TOOL_BYTES,
        executable=True,
    )
    tool_snapshots["python"] = python_snapshot
    helper_snapshot, _ = inspect_regular(
        Path(arguments.helper),
        "reviewed helper",
        MAX_HELPER_BYTES,
        executable=True,
    )

    git_path = tool_snapshots["git"].path
    source_before = verify_clean_source(
        git_path,
        source_root,
        arguments.source_commit,
        arguments.source_tree,
    )
    source_paths = {
        "builder": benchmark / BUILDER_NAME,
        "cargo_config": source_cargo_config,
        "manifest": benchmark / MANIFEST_NAME,
        "lock": benchmark / LOCK_NAME,
        "build_script": benchmark / BUILD_SCRIPT_NAME,
        "readme": benchmark / "README.md",
        "post_link_verifier": benchmark / VERIFIER_NAME,
        "benchmark_main": benchmark / "src" / "main.rs",
    }
    source_snapshots: dict[str, Snapshot] = {}
    for name, path in source_paths.items():
        try:
            require_tracked(git_path, source_root, path, name)
            snapshot, source_bytes = inspect_regular(
                path,
                name,
                MAX_SOURCE_BYTES,
                capture=name == "cargo_config",
            )
        except Refusal as error:
            if name == "lock":
                raise Refusal(
                    "nested Cargo.lock is missing or invalid; generate, review, "
                    "and commit it only after explicit GO"
                ) from error
            raise
        if name == "cargo_config":
            require(
                source_bytes == EXPECTED_SOURCE_CARGO_CONFIG,
                "tracked root Cargo config is not the exact aliases-only policy",
            )
        source_snapshots[name] = snapshot

    output_root, output_fd = create_output_directory(
        arguments.output_directory,
        source_root,
        cargo_home,
    )
    target_root = output_root / "target"
    require(not os.path.lexists(target_root), "fresh target directory already exists")

    tool_records: dict[str, Any] = {}
    for name, (_, version_arguments) in tool_inputs.items():
        tool_records[name] = version_record(
            tool_snapshots[name],
            version_arguments,
            source_root,
            invocation_path=tool_invocation_paths[name],
            alias=tool_aliases.get(name),
        )
    for alias in tool_aliases.values():
        require_executable_alias_unchanged(alias)
    linker_version = tool_records["linker"]["version_stdout"].lower()
    require(
        "gcc" in linker_version or "clang" in linker_version,
        "linker must be a native GCC or Clang compiler driver, not direct ld",
    )
    cpuinfo_record, cpuinfo_raw = inspect_virtual_file(
        CPU_INFO,
        "host CPU information",
        MAX_SOURCE_BYTES,
    )
    host_cpu = parse_homogeneous_cpuinfo(cpuinfo_raw)
    host_cpu["cpuinfo"] = cpuinfo_record
    host_cpu["rustc_native_cfg"] = rustc_native_cfg(
        tool_snapshots["rustc"],
        source_root,
    )
    native_target_features = ",".join(
        host_cpu["rustc_native_cfg"]["target_features"]
    )
    host_cpu["sve_vector_bytes"] = current_sve_vector_bytes()
    uname = platform.uname()
    host_cpu["uname"] = {
        "machine": uname.machine,
        "node": uname.node,
        "release": uname.release,
        "system": uname.system,
        "version": uname.version,
    }
    python_version = (
        f"{platform.python_implementation()} {platform.python_version()}\n"
        f"{sys.version}\n"
    ).encode("utf-8")
    python_record = dict(python_snapshot.record)
    python_record["version_sha256"] = sha256_bytes(python_version)
    python_record["version_stdout"] = python_version.decode("utf-8")
    tool_records["python"] = python_record

    cargo_environment = {
        "CARGO_ENCODED_RUSTFLAGS": ENCODED_RUSTFLAGS,
        "CARGO_HOME": os.fspath(cargo_home),
        "CARGO_INCREMENTAL": "0",
        "CARGO_NET_OFFLINE": "true",
        "CARGO_PROFILE_RELEASE_CODEGEN_UNITS": "1",
        "CARGO_PROFILE_RELEASE_INCREMENTAL": "false",
        "CARGO_PROFILE_RELEASE_LTO": "thin",
        "CARGO_PROFILE_RELEASE_OPT_LEVEL": "3",
        "CARGO_PROFILE_RELEASE_PANIC": "abort",
        "CARGO_PROFILE_RELEASE_STRIP": "none",
        "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER": os.fspath(
            tool_snapshots["linker"].path
        ),
        "CARGO_TARGET_DIR": os.fspath(target_root),
        "CARGO_TERM_COLOR": "never",
        "FRE_ABI2_THREE_ENGINE_HELPER_SHA256": helper_snapshot.record["sha256"],
        NATIVE_TARGET_FEATURES_ENV: native_target_features,
        "FRE_ABI2_THREE_ENGINE_PROFILE": PROFILE,
        "FRE_ABI2_THREE_ENGINE_SOURCE_COMMIT": arguments.source_commit,
        "FRE_ABI2_THREE_ENGINE_SOURCE_TREE": arguments.source_tree,
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "HOME": os.fspath(output_root / "home"),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "RUSTC": os.fspath(tool_snapshots["rustc"].path),
        "RUST_BACKTRACE": "0",
        "SOURCE_DATE_EPOCH": source_before["commit_unix_seconds"],
        "TERM": "dumb",
        "TMPDIR": os.fspath(output_root / "tmp"),
        "TZ": "UTC",
    }
    cargo_command = [
        os.fspath(tool_snapshots["cargo"].path),
        "build",
        "--manifest-path",
        os.fspath(benchmark / MANIFEST_NAME),
        "--locked",
        "--offline",
        "--release",
        "--target",
        TARGET,
        "--bin",
        BIN,
        "--message-format=json-render-diagnostics",
    ]

    cargo_stdout_fd = open_exclusive(output_fd, CARGO_STDOUT_NAME, "Cargo JSON log")
    cargo_stderr_fd = open_exclusive(output_fd, CARGO_STDERR_NAME, "Cargo stderr")
    build_started_unix_ns = time.time_ns()
    build_started_monotonic_ns = time.monotonic_ns()
    try:
        cargo_returncode = execute_to_logs(
            cargo_command,
            cwd=benchmark,
            environment=cargo_environment,
            stdout_fd=cargo_stdout_fd,
            stderr_fd=cargo_stderr_fd,
            label="Cargo build",
        )
    finally:
        seal_fd(cargo_stdout_fd, 0o444, "Cargo JSON log")
        seal_fd(cargo_stderr_fd, 0o444, "Cargo stderr")
        os.fsync(output_fd)
    build_finished_monotonic_ns = time.monotonic_ns()
    require(cargo_returncode == 0, f"Cargo build exited {cargo_returncode}")

    cargo_stdout_snapshot, cargo_stdout = inspect_regular(
        output_root / CARGO_STDOUT_NAME,
        "Cargo JSON log",
        MAX_CARGO_OUTPUT_BYTES,
        capture=True,
    )
    cargo_stderr_snapshot, _ = inspect_regular(
        output_root / CARGO_STDERR_NAME,
        "Cargo stderr",
        MAX_CARGO_OUTPUT_BYTES,
        allow_empty=True,
    )
    package_id, executable_path, out_dir = parse_cargo_messages(
        cargo_stdout,
        benchmark,
        target_root,
    )
    binary_snapshot, _ = inspect_regular(
        executable_path,
        "final benchmark executable",
        MAX_BINARY_BYTES,
        executable=True,
    )
    artifact_snapshots: dict[str, Snapshot] = {}
    for name, filename in ARTIFACT_NAMES.items():
        snapshot, _ = inspect_regular(
            out_dir / filename,
            name.replace("_", " "),
            MAX_ARTIFACT_BYTES,
        )
        artifact_snapshots[name] = snapshot

    source_after_build = verify_clean_source(
        git_path,
        source_root,
        arguments.source_commit,
        arguments.source_tree,
    )
    require(source_after_build == source_before, "source identity changed during Cargo build")
    for snapshot in source_snapshots.values():
        require_unchanged(snapshot, MAX_SOURCE_BYTES)
    for snapshot in tool_snapshots.values():
        require_unchanged(snapshot, MAX_TOOL_BYTES)
    for alias in tool_aliases.values():
        require_executable_alias_unchanged(alias)
    require_unchanged(helper_snapshot, MAX_HELPER_BYTES)
    require_cpuinfo_unchanged(cpuinfo_record, cpuinfo_raw)

    verifier_environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "HOME": os.fspath(output_root / "home"),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TERM": "dumb",
        "TMPDIR": os.fspath(output_root / "tmp"),
        "TZ": "UTC",
    }
    verifier_command = [
        os.fspath(python_snapshot.path),
        "-I",
        "-B",
        os.fspath(source_snapshots["post_link_verifier"].path),
        "--binary",
        os.fspath(binary_snapshot.path),
        "--implementation",
        os.fspath(artifact_snapshots["implementation_object"].path),
        "--glue",
        os.fspath(artifact_snapshots["direct_glue_object"].path),
        "--contract",
        os.fspath(artifact_snapshots["post_link_contract"].path),
        "--binding",
        os.fspath(artifact_snapshots["deployment_binding"].path),
        "--deployment-receipt",
        os.fspath(artifact_snapshots["deployment_receipt"].path),
        "--source-commit",
        arguments.source_commit,
        "--source-tree",
        arguments.source_tree,
    ]
    observation_fd = open_exclusive(
        output_fd,
        OBSERVATION_NAME,
        "post-link observation",
    )
    verifier_stderr_fd = open_exclusive(
        output_fd,
        VERIFIER_STDERR_NAME,
        "post-link verifier stderr",
    )
    verifier_started_monotonic_ns = time.monotonic_ns()
    try:
        verifier_returncode = execute_to_logs(
            verifier_command,
            cwd=benchmark,
            environment=verifier_environment,
            stdout_fd=observation_fd,
            stderr_fd=verifier_stderr_fd,
            label="post-link verifier",
        )
    finally:
        seal_fd(observation_fd, 0o444, "post-link observation")
        seal_fd(verifier_stderr_fd, 0o444, "post-link verifier stderr")
        os.fsync(output_fd)
    verifier_finished_monotonic_ns = time.monotonic_ns()
    require(
        verifier_returncode == 0,
        f"post-link verifier exited {verifier_returncode}",
    )
    observation_snapshot, observation = inspect_regular(
        output_root / OBSERVATION_NAME,
        "post-link observation",
        MAX_VERIFIER_OUTPUT_BYTES,
        capture=True,
    )
    verifier_stderr_snapshot, verifier_stderr = inspect_regular(
        output_root / VERIFIER_STDERR_NAME,
        "post-link verifier stderr",
        MAX_VERIFIER_OUTPUT_BYTES,
        allow_empty=True,
        capture=True,
    )
    require(not verifier_stderr, "successful post-link verifier wrote stderr")
    observation_fields = parse_observation(
        observation,
        arguments.source_commit,
        arguments.source_tree,
        helper_snapshot.record["sha256"],
        binary_snapshot.record["sha256"],
    )

    source_after_verify = verify_clean_source(
        git_path,
        source_root,
        arguments.source_commit,
        arguments.source_tree,
    )
    require(
        source_after_verify == source_before,
        "source identity changed during post-link verification",
    )
    for snapshot in source_snapshots.values():
        require_unchanged(snapshot, MAX_SOURCE_BYTES)
    for snapshot in tool_snapshots.values():
        require_unchanged(snapshot, MAX_TOOL_BYTES)
    for alias in tool_aliases.values():
        require_executable_alias_unchanged(alias)
    require_unchanged(helper_snapshot, MAX_HELPER_BYTES)
    require_unchanged(binary_snapshot, MAX_BINARY_BYTES)
    for snapshot in artifact_snapshots.values():
        require_unchanged(snapshot, MAX_ARTIFACT_BYTES)
    require_unchanged(cargo_stdout_snapshot, MAX_CARGO_OUTPUT_BYTES)
    require_unchanged(cargo_stderr_snapshot, MAX_CARGO_OUTPUT_BYTES)
    require_unchanged(observation_snapshot, MAX_VERIFIER_OUTPUT_BYTES)
    require_unchanged(verifier_stderr_snapshot, MAX_VERIFIER_OUTPUT_BYTES)
    require_cpuinfo_unchanged(cpuinfo_record, cpuinfo_raw)

    receipt = {
        "authority": {
            "promotion_authority": "absent",
            "runtime_authority": "absent",
        },
        "build": {
            "command": cargo_command,
            "cwd": os.fspath(benchmark),
            "duration_monotonic_ns": (
                build_finished_monotonic_ns - build_started_monotonic_ns
            ),
            "environment": cargo_environment,
            "package_id": package_id,
            "returncode": cargo_returncode,
            "stderr": cargo_stderr_snapshot.record,
            "stdout_json": cargo_stdout_snapshot.record,
            "target": TARGET,
            "target_directory": os.fspath(target_root),
        },
        "created_unix_ns": time.time_ns(),
        "evidence_class": "source-bound-checked-build-nonpromotion",
        "host_cpu": host_cpu,
        "inputs": {
            "cargo_lock": source_snapshots["lock"].record,
            "helper": helper_snapshot.record,
        },
        "outputs": {
            "artifacts": {
                name: snapshot.record
                for name, snapshot in sorted(artifact_snapshots.items())
            },
            "binary": binary_snapshot.record,
            "build_script_out_dir": os.fspath(out_dir),
            "root": os.fspath(output_root),
        },
        "post_go": {
            "confirmation": arguments.explicit_post_fence_go,
            "external_authority_validated_by_wrapper": False,
            "meaning": (
                "operator asserts that the external controller already "
                "published the applicable live-cutover GO"
            ),
        },
        "post_link": {
            "command": verifier_command,
            "cwd": os.fspath(benchmark),
            "duration_monotonic_ns": (
                verifier_finished_monotonic_ns - verifier_started_monotonic_ns
            ),
            "environment": verifier_environment,
            "fields": observation_fields,
            "observation": observation_snapshot.record,
            "returncode": verifier_returncode,
            "stderr": verifier_stderr_snapshot.record,
        },
        "profile": PROFILE,
        "schema": RECEIPT_SCHEMA,
        "source": {
            **source_before,
            "files": {
                name: snapshot.record
                for name, snapshot in sorted(source_snapshots.items())
            },
            "git_environment": base_environment(),
            "git_policy": {
                "config_overrides": [
                    "core.fsmonitor=false",
                    "core.hooksPath=/dev/null",
                    "core.untrackedCache=false",
                ],
                "dirty_scope": "tracked-untracked-and-ignored",
                "index_policy": "every-ls-files-v-entry-is-H",
                "local_config": "hashed-and-rechecked",
                "replacement_objects": "disabled",
                "tracked_content": (
                    "raw-worktree-bytes-and-executable-modes-equal-HEAD-blobs"
                ),
            },
            "root": os.fspath(source_root),
        },
        "started_unix_ns": build_started_unix_ns,
        "status": "PASS",
        "toolchain": tool_records,
    }
    receipt_bytes = canonical_json(receipt)
    receipt_snapshot = write_exclusive_read_only(
        output_fd,
        output_root,
        RECEIPT_NAME,
        receipt_bytes,
        "canonical build receipt",
    )
    os.fsync(output_fd)
    os.close(output_fd)
    print(
        "BUILD_RECEIPT"
        f"\t{RECEIPT_SCHEMA}"
        "\tPASS"
        f"\tpath={receipt_snapshot.path}"
        f"\tsha256={receipt_snapshot.record['sha256']}"
        f"\tbinary_sha256={binary_snapshot.record['sha256']}"
        f"\tobservation_sha256={observation_snapshot.record['sha256']}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Refusal as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        raise SystemExit(2)
    except OSError as error:
        print(f"REFUSED: operating-system error: {error}", file=sys.stderr)
        raise SystemExit(2)
