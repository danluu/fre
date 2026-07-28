#!/usr/bin/env python3
"""Run a source-bound, fresh-process ABI2 three-engine campaign.

This runner deliberately consumes a retained admission receipt instead of
guessing a resource-coordinator command-line API.  It never searches PATH,
never kills unrelated work, and never retries a measurement process.
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
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import time
from pathlib import Path
from typing import Any


CAMPAIGN_SCHEMA = "fre-aot-selected-end-abi2-three-engine-campaign-v1"
BENCHMARK_SCHEMA = "fre-aot-selected-end-abi2-three-engine-v2"
ADMISSION_SCHEMA = "fre-aot-selected-end-abi2-retained-admission-v1"
HEARTBEAT_SCHEMA = "fre-aot-selected-end-abi2-admission-heartbeat-v1"
POST_LINK_SCHEMA = "fre-aot-selected-end-abi2-post-link-observation-v2"
EVIDENCE_CLASS = "diagnostic-nonpromotion"
AUTHORITY = "absent"
PROFILE = "linux-target-cpu-local-v1"
SIZES = ("96", "4k", "64k", "1m")
SCENARIOS = (
    "present",
    "absent",
    "five-filter-dense-literal-absent",
    "tail",
    "window-present",
    "window-excluded",
)
ENGINES = (
    "aot-tag21-entry-direct-abi2",
    "jit-tag21-strict-wx-abi2",
    "portable-exact-literal",
)
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
SAFE_RUN = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
SAFE_INSTANCE_ID = re.compile(r"[A-Za-z0-9_.:-]{1,160}\Z")
SAFE_INSTANCE_TYPE = re.compile(r"(?:c9g|m9g)\.[A-Za-z0-9.-]{1,80}\Z")
SAFE_PROTOCOL = re.compile(r"[A-Za-z0-9_.:/+-]{1,160}\Z")
MAX_EVIDENCE_BYTES = 16 << 20
MAX_BINARY_BYTES = 512 << 20
MAX_CHILD_OUTPUT_BYTES = 4 << 20
RAW_DIRECTORY = "raw"
EVIDENCE_DIRECTORY = "evidence"
MANIFEST_NAME = "manifest.v1.json"
MANIFEST_SHA_NAME = "manifest.v1.json.sha256"
POST_LINK_FIELDS = {
    "source_commit",
    "source_tree",
    "artifact_identity",
    "compile_identity",
    "implementation_object_identity",
    "glue_object_identity",
    "bundle_identity",
    "final_binary_sha256",
    "helper_sha256",
    "profile",
    "wrapper_call",
    "primary_aot_call",
    "entry_bytes_equal",
    "payload_bytes_equal",
    "metadata_bytes_equal",
    "compile_identity_derived",
    "reject_plt",
    "reject_blr",
    "reject_x4_argument",
    "result_slot_bytes",
    "runtime_authority",
    "promotion_authority",
}


class Refusal(RuntimeError):
    """Fail-closed campaign refusal."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


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


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_all_fd(fd: int, maximum: int, label: str) -> bytes:
    size = os.fstat(fd).st_size
    require(0 <= size <= maximum, f"{label} exceeds its {maximum}-byte limit")
    chunks: list[bytes] = []
    offset = 0
    while offset < size:
        chunk = os.pread(fd, min(1 << 20, size - offset), offset)
        require(bool(chunk), f"{label} changed while being read")
        chunks.append(chunk)
        offset += len(chunk)
    require(os.fstat(fd).st_size == size, f"{label} size changed while being read")
    return b"".join(chunks)


def open_exact_regular(
    raw_path: str, label: str, maximum: int, *, executable: bool = False
) -> tuple[int, Path, os.stat_result]:
    path = Path(raw_path)
    require(path.is_absolute(), f"{label} path must be absolute")
    resolved = Path(os.path.realpath(path))
    require(path == resolved, f"{label} path must not contain symlinks")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        status = os.fstat(fd)
        require(stat.S_ISREG(status.st_mode), f"{label} must be a regular file")
        require(0 < status.st_size <= maximum, f"{label} has an invalid size")
        if executable:
            require(status.st_mode & 0o111 != 0, f"{label} is not executable")
        current = os.stat(path, follow_symlinks=False)
        require(
            (status.st_dev, status.st_ino, status.st_size, status.st_mtime_ns)
            == (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns),
            f"{label} path changed while being opened",
        )
        return fd, path, status
    except BaseException:
        os.close(fd)
        raise


def mkdir_output(raw_path: str) -> tuple[Path, int, int, int]:
    path = Path(raw_path)
    require(path.is_absolute(), "output path must be absolute")
    require(not path.exists(), "output path already exists")
    parent = path.parent
    require(parent == Path(os.path.realpath(parent)), "output parent contains a symlink")
    os.mkdir(path, 0o700)
    root_fd = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.mkdir(RAW_DIRECTORY, 0o700, dir_fd=root_fd)
        os.mkdir(EVIDENCE_DIRECTORY, 0o700, dir_fd=root_fd)
        raw_fd = os.open(
            RAW_DIRECTORY,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=root_fd,
        )
        evidence_fd = os.open(
            EVIDENCE_DIRECTORY,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=root_fd,
        )
        return path, root_fd, raw_fd, evidence_fd
    except BaseException:
        os.close(root_fd)
        raise


def write_exclusive(
    directory_fd: int, name: str, value: bytes, mode: int, label: str
) -> dict[str, Any]:
    require("/" not in name and name not in ("", ".", ".."), f"unsafe {label} name")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    fd = os.open(name, flags, 0o600, dir_fd=directory_fd)
    try:
        offset = 0
        while offset < len(value):
            written = os.write(fd, value[offset:])
            require(written > 0, f"short write for {label}")
            offset += written
        os.fsync(fd)
        os.fchmod(fd, mode)
        status = os.fstat(fd)
    finally:
        os.close(fd)
    return {
        "path": name,
        "bytes": len(value),
        "sha256": sha256_bytes(value),
        "mode": f"{stat.S_IMODE(status.st_mode):04o}",
    }


def copy_fd_exclusive(
    source_fd: int,
    directory_fd: int,
    name: str,
    mode: int,
    maximum: int,
    label: str,
) -> tuple[dict[str, Any], int]:
    source = os.fstat(source_fd)
    require(0 < source.st_size <= maximum, f"{label} has an invalid size")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    destination_fd = os.open(name, flags, 0o600, dir_fd=directory_fd)
    digest = hashlib.sha256()
    offset = 0
    snapshot_fd = -1
    try:
        while offset < source.st_size:
            chunk = os.pread(source_fd, min(1 << 20, source.st_size - offset), offset)
            require(bool(chunk), f"{label} changed during snapshot")
            digest.update(chunk)
            written_offset = 0
            while written_offset < len(chunk):
                written = os.write(destination_fd, chunk[written_offset:])
                require(written > 0, f"short snapshot write for {label}")
                written_offset += written
            offset += len(chunk)
        require(
            os.fstat(source_fd).st_size == source.st_size,
            f"{label} size changed during snapshot",
        )
        os.fsync(destination_fd)
        os.fchmod(destination_fd, mode)
        destination = os.fstat(destination_fd)
        snapshot_fd = os.open(
            f"/proc/self/fd/{destination_fd}",
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
        )
        snapshot = os.fstat(snapshot_fd)
        require(
            stat.S_ISREG(snapshot.st_mode)
            and (
                snapshot.st_dev,
                snapshot.st_ino,
                snapshot.st_size,
                snapshot.st_mtime_ns,
            )
            == (
                destination.st_dev,
                destination.st_ino,
                destination.st_size,
                destination.st_mtime_ns,
            ),
            f"{label} snapshot changed while reopening its exact descriptor",
        )
    except BaseException:
        if snapshot_fd >= 0:
            os.close(snapshot_fd)
        raise
    finally:
        os.close(destination_fd)
    return (
        {
            "path": f"{EVIDENCE_DIRECTORY}/{name}",
            "bytes": source.st_size,
            "sha256": digest.hexdigest(),
            "mode": f"{mode:04o}",
        },
        snapshot_fd,
    )


def require_hex(value: str, width: int, label: str) -> str:
    pattern = HEX40 if width == 40 else HEX64
    require(pattern.fullmatch(value) is not None, f"{label} is not lowercase hex{width}")
    require(set(value) != {"0"}, f"{label} must not be all zero")
    return value


def require_integer(value: Any, minimum: int, maximum: int, label: str) -> int:
    require(type(value) is int, f"{label} must be an integer")
    require(minimum <= value <= maximum, f"{label} is outside {minimum}..{maximum}")
    return value


def load_canonical_json_file(
    raw_path: str, label: str, maximum: int
) -> tuple[dict[str, Any], bytes, str]:
    fd, _, _ = open_exact_regular(raw_path, label, maximum)
    try:
        raw = read_all_fd(fd, maximum, label)
    finally:
        os.close(fd)
    try:
        decoded = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Refusal(f"{label} is not valid JSON: {error}") from error
    require(type(decoded) is dict, f"{label} root must be an object")
    require(raw == canonical_json(decoded), f"{label} is not canonical JSON")
    return decoded, raw, sha256_bytes(raw)


def validate_admission(
    receipt: dict[str, Any],
    evidence_sha256: str,
    identity: dict[str, Any],
    target_cpu: int,
    now_unix_ns: int,
    required_valid_until_ns: int,
) -> dict[str, Any]:
    exact_top = {
        "schema",
        "receipt_id",
        "decision",
        "evidence_class",
        "promotion_authority",
        "runtime_authority",
        "source_commit",
        "source_tree",
        "run_id",
        "instance_id",
        "instance_type",
        "target_cpu",
        "helper_sha256",
        "helper_protocol",
        "profile",
        "pins",
        "headroom",
        "acquisition",
        "continuity",
        "valid_from_unix_ns",
        "valid_until_unix_ns",
    }
    require(set(receipt) == exact_top, "admission receipt field set changed")
    for key, expected in (
        ("schema", ADMISSION_SCHEMA),
        ("decision", "admit"),
        ("evidence_class", EVIDENCE_CLASS),
        ("promotion_authority", AUTHORITY),
        ("runtime_authority", AUTHORITY),
        ("source_commit", identity["source_commit"]),
        ("source_tree", identity["source_tree"]),
        ("run_id", identity["run_id"]),
        ("instance_id", identity["instance_id"]),
        ("instance_type", identity["instance_type"]),
        ("target_cpu", target_cpu),
        ("helper_sha256", identity["helper_sha256"]),
        ("profile", identity["profile"]),
    ):
        require(receipt[key] == expected, f"admission {key} differs from campaign")
    require(
        type(receipt["receipt_id"]) is str
        and SAFE_RUN.fullmatch(receipt["receipt_id"]) is not None,
        "admission receipt_id has unsafe syntax",
    )
    require(
        type(receipt["helper_protocol"]) is str
        and SAFE_PROTOCOL.fullmatch(receipt["helper_protocol"]) is not None,
        "admission helper_protocol has unsafe syntax",
    )

    pins = receipt["pins"]
    require(type(pins) is dict and bool(pins), "admission pins must be a nonempty object")
    required_pins = {
        "source_commit": identity["source_commit"],
        "source_tree": identity["source_tree"],
        "helper_sha256": identity["helper_sha256"],
        "profile": identity["profile"],
    }
    for key, expected in required_pins.items():
        require(pins.get(key) == expected, f"admission pin {key} differs")
    for key, value in pins.items():
        require(
            type(key) is str
            and 1 <= len(key) <= 80
            and type(value) is str
            and 1 <= len(value) <= 256
            and "\x00" not in value,
            "admission pin syntax is unsafe",
        )

    headroom = receipt["headroom"]
    require(
        type(headroom) is dict
        and set(headroom)
        == {
            "basis",
            "evidence_sha256",
            "other_work_kill_policy",
            "target_cpu_admitted",
            "unrelated_cpu_work",
        },
        "admission headroom field set changed",
    )
    require(headroom["target_cpu_admitted"] is True, "target CPU was not admitted")
    require(
        headroom["unrelated_cpu_work"] == "coexist-if-target-cpu-admitted",
        "admission does not permit bounded coexistence",
    )
    require(
        headroom["other_work_kill_policy"] == "never",
        "admission does not prohibit killing other work",
    )
    require(
        type(headroom["basis"]) is str
        and 1 <= len(headroom["basis"]) <= 512
        and "\x00" not in headroom["basis"],
        "admission headroom basis is malformed",
    )
    require(
        headroom["evidence_sha256"] == evidence_sha256,
        "admission evidence digest differs from supplied evidence",
    )

    acquisition = receipt["acquisition"]
    require(
        type(acquisition) is dict
        and set(acquisition)
        == {
            "attempts_used",
            "completed_unix_ns",
            "deadline_unix_ns",
            "max_attempts",
            "started_unix_ns",
        },
        "admission acquisition field set changed",
    )
    attempts_used = require_integer(
        acquisition["attempts_used"], 1, 120, "admission attempts_used"
    )
    max_attempts = require_integer(
        acquisition["max_attempts"], 1, 120, "admission max_attempts"
    )
    require(attempts_used <= max_attempts, "admission exceeded its retry bound")
    started = require_integer(
        acquisition["started_unix_ns"], 1, (1 << 63) - 1, "admission start"
    )
    completed = require_integer(
        acquisition["completed_unix_ns"], 1, (1 << 63) - 1, "admission completion"
    )
    deadline = require_integer(
        acquisition["deadline_unix_ns"], 1, (1 << 63) - 1, "admission deadline"
    )
    require(started <= completed <= deadline, "admission exceeded its acquisition deadline")
    require(completed <= now_unix_ns, "admission acquisition completed in the future")

    continuity = receipt["continuity"]
    require(
        type(continuity) is dict
        and set(continuity)
        == {
            "continuous_since_unix_ns",
            "heartbeat_schema",
            "holder_id",
            "lease_epoch",
            "maximum_heartbeat_age_ns",
            "mode",
            "session_id",
        },
        "admission continuity field set changed",
    )
    require(
        continuity["mode"] == "continuous-live-holder",
        "admission is not backed by a continuous live holder",
    )
    require(
        continuity["heartbeat_schema"] == HEARTBEAT_SCHEMA,
        "admission heartbeat schema changed",
    )
    for key in ("holder_id", "session_id", "lease_epoch"):
        require(
            type(continuity[key]) is str
            and SAFE_RUN.fullmatch(continuity[key]) is not None,
            f"admission continuity {key} has unsafe syntax",
        )
    continuous_since = require_integer(
        continuity["continuous_since_unix_ns"],
        1,
        (1 << 63) - 1,
        "admission continuous_since",
    )
    require(
        continuous_since <= completed,
        "admission continuity starts after receipt acquisition",
    )
    maximum_heartbeat_age_ns = require_integer(
        continuity["maximum_heartbeat_age_ns"],
        1_000_000,
        300_000_000_000,
        "maximum heartbeat age",
    )

    valid_from = require_integer(
        receipt["valid_from_unix_ns"], 1, (1 << 63) - 1, "admission valid_from"
    )
    valid_until = require_integer(
        receipt["valid_until_unix_ns"], 1, (1 << 63) - 1, "admission valid_until"
    )
    require(valid_from <= now_unix_ns, "admission is not valid yet")
    require(now_unix_ns < valid_until, "admission has expired")
    require(
        valid_until >= required_valid_until_ns,
        "admission does not cover the bounded campaign deadline",
    )
    return {
        "receipt_id": receipt["receipt_id"],
        "helper_protocol": receipt["helper_protocol"],
        "pin_set_sha256": sha256_bytes(canonical_json(pins)),
        "headroom_basis": headroom["basis"],
        "acquisition_attempts_used": attempts_used,
        "acquisition_max_attempts": max_attempts,
        "acquisition_deadline_unix_ns": deadline,
        "valid_from_unix_ns": valid_from,
        "valid_until_unix_ns": valid_until,
        "coexistence_policy": headroom["unrelated_cpu_work"],
        "other_work_kill_policy": headroom["other_work_kill_policy"],
        "continuity_mode": continuity["mode"],
        "continuous_since_unix_ns": continuous_since,
        "holder_id": continuity["holder_id"],
        "session_id": continuity["session_id"],
        "lease_epoch": continuity["lease_epoch"],
        "maximum_heartbeat_age_ns": maximum_heartbeat_age_ns,
    }


def load_and_validate_heartbeat(
    raw_path: str,
    admission: dict[str, Any],
    evidence_sha256: str,
    identity: dict[str, Any],
    now_unix_ns: int,
) -> tuple[dict[str, Any], bytes, str]:
    heartbeat, raw, digest = load_canonical_json_file(
        raw_path, "admission heartbeat", MAX_EVIDENCE_BYTES
    )
    verification_unix_ns = max(now_unix_ns, time.time_ns())
    require(
        set(heartbeat)
        == {
            "schema",
            "status",
            "evidence_class",
            "promotion_authority",
            "runtime_authority",
            "receipt_id",
            "holder_id",
            "session_id",
            "lease_epoch",
            "sequence",
            "source_commit",
            "source_tree",
            "run_id",
            "instance_id",
            "instance_type",
            "target_cpu",
            "helper_sha256",
            "profile",
            "continuous_since_unix_ns",
            "observed_unix_ns",
            "valid_until_unix_ns",
            "headroom",
        },
        "admission heartbeat field set changed",
    )
    for key, expected in (
        ("schema", HEARTBEAT_SCHEMA),
        ("status", "active"),
        ("evidence_class", EVIDENCE_CLASS),
        ("promotion_authority", AUTHORITY),
        ("runtime_authority", AUTHORITY),
        ("receipt_id", admission["receipt_id"]),
        ("holder_id", admission["holder_id"]),
        ("session_id", admission["session_id"]),
        ("lease_epoch", admission["lease_epoch"]),
        ("source_commit", identity["source_commit"]),
        ("source_tree", identity["source_tree"]),
        ("run_id", identity["run_id"]),
        ("instance_id", identity["instance_id"]),
        ("instance_type", identity["instance_type"]),
        ("target_cpu", identity["target_cpu"]),
        ("helper_sha256", identity["helper_sha256"]),
        ("profile", identity["profile"]),
        ("continuous_since_unix_ns", admission["continuous_since_unix_ns"]),
    ):
        require(heartbeat[key] == expected, f"admission heartbeat {key} drifted")
    sequence = require_integer(
        heartbeat["sequence"], 0, (1 << 63) - 1, "admission heartbeat sequence"
    )
    observed = require_integer(
        heartbeat["observed_unix_ns"],
        1,
        (1 << 63) - 1,
        "admission heartbeat observation",
    )
    valid_until = require_integer(
        heartbeat["valid_until_unix_ns"],
        1,
        (1 << 63) - 1,
        "admission heartbeat valid_until",
    )
    require(
        observed <= verification_unix_ns,
        "admission heartbeat observation is in the future",
    )
    require(
        verification_unix_ns - observed <= admission["maximum_heartbeat_age_ns"],
        "admission heartbeat is stale",
    )
    require(verification_unix_ns < valid_until, "admission heartbeat lease has expired")
    require(
        valid_until <= admission["valid_until_unix_ns"],
        "heartbeat outlives its retained admission receipt",
    )
    headroom = heartbeat["headroom"]
    require(
        type(headroom) is dict
        and set(headroom)
        == {
            "evidence_sha256",
            "other_work_kill_policy",
            "target_cpu_admitted",
            "unrelated_cpu_work",
        },
        "admission heartbeat headroom field set changed",
    )
    require(headroom["target_cpu_admitted"] is True, "heartbeat withdrew target CPU admission")
    require(
        headroom["unrelated_cpu_work"] == "coexist-if-target-cpu-admitted",
        "heartbeat coexistence policy changed",
    )
    require(
        headroom["other_work_kill_policy"] == "never",
        "heartbeat permits killing other work",
    )
    require(
        headroom["evidence_sha256"] == evidence_sha256,
        "heartbeat admission evidence digest drifted",
    )
    return (
        {
            "sequence": sequence,
            "observed_unix_ns": observed,
            "valid_until_unix_ns": valid_until,
            "sha256": digest,
        },
        raw,
        digest,
    )


def parse_record(line: str) -> tuple[str, str | None, dict[str, str]]:
    columns = line.split("\t")
    require(bool(columns) and columns[0] != "", "empty output record kind")
    if columns[0] == "META":
        require(len(columns) == 3 and columns[1] != "", "malformed META record")
        return "META", None, {columns[1]: columns[2]}
    require(len(columns) >= 3, f"malformed {columns[0]} record")
    schema = columns[1]
    fields: dict[str, str] = {}
    positional = columns[2:]
    if columns[0] == "QUALIFICATION":
        require(positional[0] == "PASS", "qualification did not pass")
        positional = positional[1:]
    for column in positional:
        require("=" in column, f"malformed field in {columns[0]} record")
        key, value = column.split("=", 1)
        require(key != "" and key not in fields, f"duplicate {columns[0]} field {key!r}")
        fields[key] = value
    return columns[0], schema, fields


def parse_stdout(raw: bytes, label: str) -> tuple[dict[str, str], list[tuple[str, dict[str, str]]]]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise Refusal(f"{label} stdout is not UTF-8") from error
    require("\r" not in text and "\x00" not in text, f"{label} stdout has unsafe bytes")
    require(text.endswith("\n"), f"{label} stdout is truncated")
    lines = text.splitlines()
    require(bool(lines) and all(line != "" for line in lines), f"{label} has blank output lines")
    metadata: dict[str, str] = {}
    records: list[tuple[str, dict[str, str]]] = []
    for line in lines:
        kind, schema, fields = parse_record(line)
        if kind == "META":
            key, value = next(iter(fields.items()))
            require(key not in metadata, f"{label} duplicates META {key!r}")
            metadata[key] = value
        else:
            require(schema == BENCHMARK_SCHEMA, f"{label} benchmark schema changed")
            records.append((kind, fields))
    return metadata, records


def validate_process_output(
    command: str,
    stdout: bytes,
    stderr: bytes,
    identity: dict[str, Any],
    coordinate: dict[str, Any],
    baseline: dict[str, str] | None,
) -> dict[str, str]:
    require(stderr == b"", f"{command} wrote stderr")
    metadata, records = parse_stdout(stdout, command)
    expected_meta = {
        "schema": BENCHMARK_SCHEMA,
        "evidence_class": EVIDENCE_CLASS,
        "promotion_authority": AUTHORITY,
        "runtime_authority": AUTHORITY,
        "source_commit": identity["source_commit"],
        "source_tree": identity["source_tree"],
        "helper_sha256": identity["helper_sha256"],
        "profile": identity["profile"],
        "run_id": identity["run_id"],
        "instance_type": identity["instance_type"],
        "affinity_cpu": str(identity["target_cpu"]),
        "arm_cpu_implementer": "0x0041",
        "arm_cpu_part": "0x0d84",
        "asimd": "true",
        "sve": "true",
        "sve2": "true",
        "sve_vector_bytes": "16",
        "engine_order_rotation": "all-six-permutations-by-repetition",
    }
    for key, expected in expected_meta.items():
        require(metadata.get(key) == expected, f"{command} META {key} drifted")
    for key in ("artifact_identity", "compile_identity", "bundle_identity"):
        require(HEX64.fullmatch(metadata.get(key, "")) is not None, f"{command} {key} malformed")
    if baseline is not None:
        for key in (
            "artifact_identity",
            "compile_identity",
            "implementation_object_identity",
            "glue_object_identity",
            "bundle_identity",
            "aot_entry_symbol",
            "aot_wrapper_symbol",
        ):
            require(metadata.get(key) == baseline.get(key), f"{command} META {key} drifted")

    kinds = [kind for kind, _ in records]
    if command == "qualification":
        require(kinds == ["QUALIFICATION"], "qualification output shape changed")
    elif command == "cell":
        require(kinds == ["CELL", "SAMPLE", "SAMPLE", "SAMPLE"], "hot output shape changed")
    elif command == "lifecycle":
        require(
            kinds == ["LIFECYCLE", "SAMPLE", "SAMPLE", "SAMPLE", "SAMPLE"],
            "lifecycle output shape changed",
        )
    else:
        raise Refusal(f"unknown command {command!r}")

    samples: set[tuple[str, str]] = set()
    for kind, fields in records:
        required_identity = {
            "source_commit": identity["source_commit"],
            "source_tree": identity["source_tree"],
            "run_id": identity["run_id"],
            "instance_type": identity["instance_type"],
            "helper_sha256": identity["helper_sha256"],
            "profile": identity["profile"],
            "artifact_identity": metadata["artifact_identity"],
            "bundle_identity": metadata["bundle_identity"],
            "evidence_class": EVIDENCE_CLASS,
            "runtime_authority": AUTHORITY,
            "promotion_authority": AUTHORITY,
        }
        for key, expected in required_identity.items():
            require(
                fields.get(key) == expected,
                f"{command} {kind} row {key} is absent or drifted",
            )
        if kind in ("QUALIFICATION", "CELL", "LIFECYCLE"):
            require(
                fields.get("affinity_cpu") == str(identity["target_cpu"]),
                f"{command} {kind} header affinity_cpu is absent or drifted",
            )
        if kind in ("CELL", "LIFECYCLE"):
            for key in ("size", "scenario", "repetition"):
                require(
                    fields.get(key) == str(coordinate[key]),
                    f"{command} header {key} drifted",
                )
        if kind == "SAMPLE":
            require(
                fields.get("repetition") == str(coordinate["repetition"]),
                f"{command} sample repetition is absent or drifted",
            )
            key = (fields.get("stage", ""), fields.get("engine", ""))
            require(key not in samples, f"{command} duplicates sample {key!r}")
            samples.add(key)
    if command == "cell":
        require(
            samples == {("hot", engine) for engine in ENGINES},
            "hot sample engine set changed",
        )
    if command == "lifecycle":
        require(
            samples
            == {("lifecycle", engine) for engine in ENGINES}
            | {("aot-activation", ENGINES[0])},
            "lifecycle sample engine/stage set changed",
        )
    return metadata


def safe_child_environment() -> dict[str, str]:
    return {
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "RUST_BACKTRACE": "0",
        "OMP_NUM_THREADS": "1",
        "OPENBLAS_NUM_THREADS": "1",
        "MKL_NUM_THREADS": "1",
        "VECLIB_MAXIMUM_THREADS": "1",
        "NUMEXPR_NUM_THREADS": "1",
        "RAYON_NUM_THREADS": "1",
    }


def run_child(
    binary_fd: int,
    raw_fd: int,
    sequence: int,
    command: str,
    arguments: list[str],
    coordinate: dict[str, Any],
    identity: dict[str, Any],
    target_cpu: int,
    child_timeout_seconds: int,
    campaign_deadline_monotonic_ns: int,
    admission: dict[str, Any],
    admission_evidence_sha256: str,
    admission_heartbeat_path: str,
    previous_heartbeat: dict[str, Any],
    baseline: dict[str, str] | None,
) -> tuple[dict[str, Any], dict[str, str], dict[str, Any]]:
    now_unix_ns = time.time_ns()
    require(
        now_unix_ns < admission["valid_until_unix_ns"],
        "admission receipt expired before child launch",
    )
    remaining_ns = campaign_deadline_monotonic_ns - time.monotonic_ns()
    require(remaining_ns > 0, "campaign deadline expired before child launch")
    timeout = min(float(child_timeout_seconds), remaining_ns / 1_000_000_000)
    require(timeout > 0.0, "no campaign time remains for child launch")
    stem = f"{sequence:06d}-{command}"
    heartbeat_before, heartbeat_before_raw, _ = load_and_validate_heartbeat(
        admission_heartbeat_path,
        admission,
        admission_evidence_sha256,
        identity,
        now_unix_ns,
    )
    require(
        heartbeat_before["sequence"] >= previous_heartbeat["sequence"]
        and heartbeat_before["observed_unix_ns"]
        >= previous_heartbeat["observed_unix_ns"],
        "admission heartbeat moved backward between child executions",
    )
    heartbeat_before_record = write_exclusive(
        raw_fd,
        f"{stem}.admission-before.json",
        heartbeat_before_raw,
        0o444,
        "pre-child admission heartbeat",
    )
    heartbeat_before_record["path"] = (
        f"{RAW_DIRECTORY}/{stem}.admission-before.json"
    )
    stdout_name = f"{stem}.stdout"
    stderr_name = f"{stem}.stderr"
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    stdout_fd = os.open(stdout_name, flags, 0o600, dir_fd=raw_fd)
    stderr_fd = os.open(stderr_name, flags, 0o600, dir_fd=raw_fd)
    started_unix_ns = time.time_ns()
    started_monotonic_ns = time.monotonic_ns()
    child_argv = [f"/proc/self/fd/{binary_fd}", command, *arguments]

    def pin_child() -> None:
        os.sched_setaffinity(0, {target_cpu})

    timed_out = False
    with os.fdopen(stdout_fd, "wb", closefd=True) as stdout_file, os.fdopen(
        stderr_fd, "wb", closefd=True
    ) as stderr_file:
        process = subprocess.Popen(
            child_argv,
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
            cwd="/",
            env=safe_child_environment(),
            close_fds=True,
            pass_fds=(binary_fd,),
            preexec_fn=pin_child,
        )
        try:
            exit_code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            exit_code = process.wait()
        stdout_file.flush()
        stderr_file.flush()
        os.fsync(stdout_file.fileno())
        os.fsync(stderr_file.fileno())
        stdout = read_all_fd(
            stdout_file.fileno(), MAX_CHILD_OUTPUT_BYTES, f"{command} stdout"
        )
        stderr = read_all_fd(
            stderr_file.fileno(), MAX_CHILD_OUTPUT_BYTES, f"{command} stderr"
        )
        os.fchmod(stdout_file.fileno(), 0o444)
        os.fchmod(stderr_file.fileno(), 0o444)
    completed_monotonic_ns = time.monotonic_ns()
    completed_unix_ns = time.time_ns()
    require(
        completed_monotonic_ns <= campaign_deadline_monotonic_ns,
        "child completed after the bounded campaign deadline",
    )
    require(
        completed_unix_ns < admission["valid_until_unix_ns"],
        "admission receipt expired before child completion",
    )
    heartbeat_after, heartbeat_after_raw, _ = load_and_validate_heartbeat(
        admission_heartbeat_path,
        admission,
        admission_evidence_sha256,
        identity,
        completed_unix_ns,
    )
    require(
        heartbeat_after["sequence"] >= heartbeat_before["sequence"]
        and heartbeat_after["observed_unix_ns"]
        >= heartbeat_before["observed_unix_ns"],
        "admission heartbeat moved backward across child execution",
    )
    heartbeat_after_record = write_exclusive(
        raw_fd,
        f"{stem}.admission-after.json",
        heartbeat_after_raw,
        0o444,
        "post-child admission heartbeat",
    )
    heartbeat_after_record["path"] = f"{RAW_DIRECTORY}/{stem}.admission-after.json"
    require(not timed_out, f"{command} exceeded its {timeout}-second child deadline")
    require(exit_code == 0, f"{command} exited with status {exit_code}")
    metadata = validate_process_output(
        command, stdout, stderr, identity, coordinate, baseline
    )
    record = {
        "sequence": sequence,
        "command": command,
        "arguments": arguments,
        "coordinate": coordinate,
        "fresh_process": True,
        "single_thread_environment": True,
        "target_cpu": target_cpu,
        "exit_code": exit_code,
        "started_unix_ns": started_unix_ns,
        "completed_unix_ns": completed_unix_ns,
        "runner_elapsed_ns": completed_monotonic_ns - started_monotonic_ns,
        "admission_before": heartbeat_before_record,
        "admission_after": heartbeat_after_record,
        "stdout": {
            "path": f"{RAW_DIRECTORY}/{stdout_name}",
            "bytes": len(stdout),
            "sha256": sha256_bytes(stdout),
            "mode": "0444",
        },
        "stderr": {
            "path": f"{RAW_DIRECTORY}/{stderr_name}",
            "bytes": len(stderr),
            "sha256": sha256_bytes(stderr),
            "mode": "0444",
        },
    }
    return record, metadata, heartbeat_after


def parse_post_link_observation(
    raw: bytes, identity: dict[str, Any]
) -> dict[str, str]:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise Refusal("post-link observation is not ASCII") from error
    require(text.endswith("\n") and text.count("\n") == 1, "post-link observation must be one line")
    columns = text[:-1].split("\t")
    require(
        len(columns) >= 4
        and columns[:3] == ["OBSERVATION", POST_LINK_SCHEMA, "PASS"],
        "post-link observation did not pass",
    )
    fields: dict[str, str] = {}
    for column in columns[3:]:
        require("=" in column, "malformed post-link observation field")
        key, value = column.split("=", 1)
        require(key != "" and key not in fields, "duplicate post-link observation field")
        fields[key] = value
    require(set(fields) == POST_LINK_FIELDS, "post-link observation field set changed")
    for key, expected in (
        ("source_commit", identity["source_commit"]),
        ("source_tree", identity["source_tree"]),
        ("helper_sha256", identity["helper_sha256"]),
        ("profile", identity["profile"]),
        ("runtime_authority", AUTHORITY),
        ("promotion_authority", AUTHORITY),
        ("wrapper_call", "R_AARCH64_CALL26-to-direct-bl"),
        ("primary_aot_call", "direct-bl-exact-entry"),
        ("reject_plt", "true"),
        ("reject_blr", "true"),
        ("reject_x4_argument", "true"),
        ("result_slot_bytes", "0"),
        ("entry_bytes_equal", "true"),
        ("payload_bytes_equal", "true"),
        ("metadata_bytes_equal", "true"),
        ("compile_identity_derived", "true"),
    ):
        require(fields.get(key) == expected, f"post-link {key} drifted")
    for key in (
        "artifact_identity",
        "compile_identity",
        "implementation_object_identity",
        "glue_object_identity",
        "bundle_identity",
        "final_binary_sha256",
    ):
        require(HEX64.fullmatch(fields.get(key, "")) is not None, f"post-link {key} malformed")
    return fields


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Run a diagnostic-only fresh-process ABI2 campaign"
    )
    result.add_argument("--binary", required=True)
    result.add_argument("--output", required=True)
    result.add_argument("--source-commit", required=True)
    result.add_argument("--source-tree", required=True)
    result.add_argument("--run-id", required=True)
    result.add_argument("--instance-id", required=True)
    result.add_argument("--instance-type", required=True)
    result.add_argument("--helper-sha256", required=True)
    result.add_argument("--profile", required=True)
    result.add_argument("--target-cpu", required=True, type=int)
    result.add_argument("--repetitions", required=True, type=int)
    result.add_argument("--admission-receipt", required=True)
    result.add_argument("--admission-evidence", required=True)
    result.add_argument("--admission-heartbeat", required=True)
    result.add_argument("--post-link-observation", required=True)
    result.add_argument("--campaign-deadline-seconds", type=int, default=21600)
    result.add_argument("--child-timeout-seconds", type=int, default=900)
    return result


def main() -> int:
    arguments = parser().parse_args()
    require(sys.platform == "linux", "campaign runner requires Linux")
    require(
        platform.machine().lower() in ("aarch64", "arm64"),
        "campaign runner requires AArch64",
    )
    source_commit = require_hex(arguments.source_commit, 40, "source commit")
    source_tree = require_hex(arguments.source_tree, 40, "source tree")
    helper_sha256 = require_hex(arguments.helper_sha256, 64, "helper SHA-256")
    require(SAFE_RUN.fullmatch(arguments.run_id) is not None, "run ID has unsafe syntax")
    require(
        SAFE_INSTANCE_ID.fullmatch(arguments.instance_id) is not None,
        "instance ID has unsafe syntax",
    )
    require(
        SAFE_INSTANCE_TYPE.fullmatch(arguments.instance_type) is not None,
        "instance type must be c9g.* or m9g.*",
    )
    require(arguments.profile == PROFILE, "unsupported campaign profile")
    require(
        6 <= arguments.repetitions <= 96 and arguments.repetitions % 6 == 0,
        "repetitions must be 6..96 and a multiple of six",
    )
    require(0 <= arguments.target_cpu < (1 << 20), "target CPU is outside the safe range")
    require(
        600 <= arguments.campaign_deadline_seconds <= 86400,
        "campaign deadline must be 600..86400 seconds",
    )
    require(
        10 <= arguments.child_timeout_seconds <= 3600,
        "child timeout must be 10..3600 seconds",
    )
    allowed_cpus = sorted(os.sched_getaffinity(0))
    require(arguments.target_cpu in allowed_cpus, "target CPU is outside runner affinity")

    identity: dict[str, Any] = {
        "source_commit": source_commit,
        "source_tree": source_tree,
        "run_id": arguments.run_id,
        "instance_id": arguments.instance_id,
        "instance_type": arguments.instance_type,
        "helper_sha256": helper_sha256,
        "profile": arguments.profile,
        "target_cpu": arguments.target_cpu,
    }

    admission_evidence_fd, _, _ = open_exact_regular(
        arguments.admission_evidence, "admission evidence", MAX_EVIDENCE_BYTES
    )
    try:
        admission_evidence_raw = read_all_fd(
            admission_evidence_fd, MAX_EVIDENCE_BYTES, "admission evidence"
        )
    finally:
        os.close(admission_evidence_fd)
    admission_evidence_sha256 = sha256_bytes(admission_evidence_raw)
    receipt, receipt_raw, receipt_sha256 = load_canonical_json_file(
        arguments.admission_receipt, "admission receipt", MAX_EVIDENCE_BYTES
    )
    now_unix_ns = time.time_ns()
    required_valid_until_ns = now_unix_ns + arguments.campaign_deadline_seconds * 1_000_000_000
    admission_summary = validate_admission(
        receipt,
        admission_evidence_sha256,
        identity,
        arguments.target_cpu,
        now_unix_ns,
        required_valid_until_ns,
    )
    initial_heartbeat, initial_heartbeat_raw, _ = load_and_validate_heartbeat(
        arguments.admission_heartbeat,
        admission_summary,
        admission_evidence_sha256,
        identity,
        time.time_ns(),
    )
    started_unix_ns = time.time_ns()
    started_monotonic_ns = time.monotonic_ns()
    require(
        admission_summary["valid_until_unix_ns"]
        >= started_unix_ns
        + arguments.campaign_deadline_seconds * 1_000_000_000,
        "admission receipt does not cover the campaign deadline from actual start",
    )
    campaign_deadline_monotonic_ns = (
        started_monotonic_ns + arguments.campaign_deadline_seconds * 1_000_000_000
    )

    post_link_fd, _, _ = open_exact_regular(
        arguments.post_link_observation, "post-link observation", MAX_EVIDENCE_BYTES
    )
    try:
        post_link_raw = read_all_fd(
            post_link_fd, MAX_EVIDENCE_BYTES, "post-link observation"
        )
    finally:
        os.close(post_link_fd)
    post_link_fields = parse_post_link_observation(post_link_raw, identity)

    source_binary_fd, source_binary_path, source_binary_status = open_exact_regular(
        arguments.binary, "benchmark binary", MAX_BINARY_BYTES, executable=True
    )
    output_path: Path | None = None
    root_fd = raw_fd = evidence_fd = snapshot_binary_fd = -1
    try:
        output_path, root_fd, raw_fd, evidence_fd = mkdir_output(arguments.output)
        binary_record, snapshot_binary_fd = copy_fd_exclusive(
            source_binary_fd,
            evidence_fd,
            "benchmark.bin",
            0o555,
            MAX_BINARY_BYTES,
            "benchmark binary",
        )
        require(
            binary_record["sha256"] == post_link_fields["final_binary_sha256"],
            "snapshotted binary digest differs from post-link observation",
        )
        receipt_record = write_exclusive(
            evidence_fd, "admission-receipt.json", receipt_raw, 0o444, "admission receipt"
        )
        receipt_record["path"] = f"{EVIDENCE_DIRECTORY}/admission-receipt.json"
        evidence_record = write_exclusive(
            evidence_fd,
            "admission-evidence.raw",
            admission_evidence_raw,
            0o444,
            "admission evidence",
        )
        evidence_record["path"] = f"{EVIDENCE_DIRECTORY}/admission-evidence.raw"
        initial_heartbeat_record = write_exclusive(
            evidence_fd,
            "admission-initial-heartbeat.json",
            initial_heartbeat_raw,
            0o444,
            "initial admission heartbeat",
        )
        initial_heartbeat_record["path"] = (
            f"{EVIDENCE_DIRECTORY}/admission-initial-heartbeat.json"
        )
        post_link_record = write_exclusive(
            evidence_fd,
            "post-link-observation.txt",
            post_link_raw,
            0o444,
            "post-link observation",
        )
        post_link_record["path"] = f"{EVIDENCE_DIRECTORY}/post-link-observation.txt"
        cpuinfo = Path("/proc/cpuinfo").read_bytes()
        require(0 < len(cpuinfo) <= MAX_EVIDENCE_BYTES, "/proc/cpuinfo has an invalid size")
        cpuinfo_record = write_exclusive(
            evidence_fd, "proc-cpuinfo.raw", cpuinfo, 0o444, "CPU evidence"
        )
        cpuinfo_record["path"] = f"{EVIDENCE_DIRECTORY}/proc-cpuinfo.raw"

        processes: list[dict[str, Any]] = []
        qualification_arguments = [
            source_commit,
            source_tree,
            arguments.run_id,
            arguments.instance_type,
            helper_sha256,
            arguments.profile,
        ]
        qualification_record, baseline, last_heartbeat = run_child(
            snapshot_binary_fd,
            raw_fd,
            0,
            "qualification",
            qualification_arguments,
            {"kind": "qualification"},
            identity,
            arguments.target_cpu,
            arguments.child_timeout_seconds,
            campaign_deadline_monotonic_ns,
            admission_summary,
            admission_evidence_sha256,
            arguments.admission_heartbeat,
            initial_heartbeat,
            None,
        )
        processes.append(qualification_record)
        require(
            baseline["artifact_identity"] == post_link_fields["artifact_identity"]
            and baseline["compile_identity"] == post_link_fields["compile_identity"]
            and baseline["implementation_object_identity"]
            == post_link_fields["implementation_object_identity"]
            and baseline["glue_object_identity"]
            == post_link_fields["glue_object_identity"]
            and baseline["bundle_identity"] == post_link_fields["bundle_identity"],
            "qualification identity differs from post-link observation",
        )

        sequence = 1
        for repetition in range(arguments.repetitions):
            for size in SIZES:
                for scenario in SCENARIOS:
                    coordinate = {
                        "size": size,
                        "scenario": scenario,
                        "repetition": repetition,
                    }
                    cell_arguments = [
                        size,
                        scenario,
                        str(repetition),
                        *qualification_arguments,
                    ]
                    for command in ("cell", "lifecycle"):
                        record, _, last_heartbeat = run_child(
                            snapshot_binary_fd,
                            raw_fd,
                            sequence,
                            command,
                            cell_arguments,
                            coordinate,
                            identity,
                            arguments.target_cpu,
                            arguments.child_timeout_seconds,
                            campaign_deadline_monotonic_ns,
                            admission_summary,
                            admission_evidence_sha256,
                            arguments.admission_heartbeat,
                            last_heartbeat,
                            baseline,
                        )
                        processes.append(record)
                        sequence += 1

        expected_processes = 1 + arguments.repetitions * len(SIZES) * len(SCENARIOS) * 2
        require(len(processes) == expected_processes, "campaign process count is incomplete")
        final_heartbeat_boundary_ns = time.time_ns()
        final_heartbeat, final_heartbeat_raw, _ = load_and_validate_heartbeat(
            arguments.admission_heartbeat,
            admission_summary,
            admission_evidence_sha256,
            identity,
            final_heartbeat_boundary_ns,
        )
        completed_monotonic_ns = time.monotonic_ns()
        completed_unix_ns = time.time_ns()
        require(
            completed_monotonic_ns <= campaign_deadline_monotonic_ns,
            "campaign completed after its monotonic deadline",
        )
        require(
            completed_unix_ns < admission_summary["valid_until_unix_ns"],
            "admission receipt expired before campaign completion",
        )
        require(
            completed_unix_ns < final_heartbeat["valid_until_unix_ns"]
            and completed_unix_ns - final_heartbeat["observed_unix_ns"]
            <= admission_summary["maximum_heartbeat_age_ns"],
            "final admission heartbeat is not valid at campaign completion",
        )
        require(
            final_heartbeat["sequence"] >= last_heartbeat["sequence"]
            and final_heartbeat["observed_unix_ns"]
            >= last_heartbeat["observed_unix_ns"],
            "admission heartbeat moved backward across the campaign",
        )
        final_heartbeat_record = write_exclusive(
            evidence_fd,
            "admission-final-heartbeat.json",
            final_heartbeat_raw,
            0o444,
            "final admission heartbeat",
        )
        final_heartbeat_record["path"] = (
            f"{EVIDENCE_DIRECTORY}/admission-final-heartbeat.json"
        )
        manifest = {
            "schema": CAMPAIGN_SCHEMA,
            "evidence_class": EVIDENCE_CLASS,
            "promotion_authority": AUTHORITY,
            "runtime_authority": AUTHORITY,
            "decision": "diagnostic-raw-evidence-only",
            "identity": identity,
            "benchmark": {
                "schema": BENCHMARK_SCHEMA,
                "sizes": list(SIZES),
                "scenarios": list(SCENARIOS),
                "engines": list(ENGINES),
                "repetitions": arguments.repetitions,
                "engine_order_rotation": "all-six-permutations-by-repetition",
                "qualification_processes": 1,
                "fresh_process_per_hot_cell": True,
                "fresh_process_per_lifecycle_cell": True,
                "expected_processes": expected_processes,
            },
            "bounds": {
                "campaign_deadline_seconds": arguments.campaign_deadline_seconds,
                "child_timeout_seconds": arguments.child_timeout_seconds,
                "measurement_retries": 0,
                "maximum_repetitions": 96,
                "maximum_child_output_bytes": MAX_CHILD_OUTPUT_BYTES,
            },
            "binary": {
                **binary_record,
                "source_path": str(source_binary_path),
                "source_device": source_binary_status.st_dev,
                "source_inode": source_binary_status.st_ino,
                "source_mtime_ns": source_binary_status.st_mtime_ns,
                "post_link_observed_sha256": post_link_fields["final_binary_sha256"],
            },
            "admission": {
                **admission_summary,
                "receipt": receipt_record,
                "receipt_sha256": receipt_sha256,
                "raw_evidence": evidence_record,
                "initial_heartbeat": initial_heartbeat_record,
                "final_heartbeat": final_heartbeat_record,
                "initial_heartbeat_sequence": initial_heartbeat["sequence"],
                "final_heartbeat_sequence": final_heartbeat["sequence"],
                "target_cpu": arguments.target_cpu,
                "runner_allowed_cpus": allowed_cpus,
                "admitted_unrelated_cpu_work_may_continue": True,
                "runner_never_kills_other_work": True,
            },
            "post_link": {
                "observation": post_link_record,
                "observed_binary_sha256": post_link_fields["final_binary_sha256"],
                "artifact_identity": post_link_fields["artifact_identity"],
                "compile_identity": post_link_fields["compile_identity"],
                "implementation_object_identity": post_link_fields[
                    "implementation_object_identity"
                ],
                "glue_object_identity": post_link_fields["glue_object_identity"],
                "bundle_identity": post_link_fields["bundle_identity"],
                "runtime_authority": AUTHORITY,
                "promotion_authority": AUTHORITY,
            },
            "host": {
                "system": platform.system(),
                "machine": platform.machine(),
                "release": platform.release(),
                "target_cpu": arguments.target_cpu,
                "runner_allowed_cpus": allowed_cpus,
                "proc_cpuinfo": cpuinfo_record,
            },
            "started_unix_ns": started_unix_ns,
            "completed_unix_ns": completed_unix_ns,
            "processes": processes,
        }
        manifest_raw = canonical_json(manifest)
        manifest_record = write_exclusive(
            root_fd, MANIFEST_NAME, manifest_raw, 0o444, "campaign manifest"
        )
        manifest_sha_raw = (
            f"{manifest_record['sha256']}  {MANIFEST_NAME}\n".encode("ascii")
        )
        write_exclusive(
            root_fd,
            MANIFEST_SHA_NAME,
            manifest_sha_raw,
            0o444,
            "campaign manifest digest",
        )
        os.fsync(raw_fd)
        os.fsync(evidence_fd)
        os.fsync(root_fd)
        if time.monotonic_ns() > campaign_deadline_monotonic_ns:
            os.unlink(MANIFEST_SHA_NAME, dir_fd=root_fd)
            os.unlink(MANIFEST_NAME, dir_fd=root_fd)
            os.fsync(root_fd)
            raise Refusal(
                "manifest finalization exceeded the monotonic campaign deadline"
            )
        print(
            "CAMPAIGN"
            f"\t{CAMPAIGN_SCHEMA}"
            "\tCOMPLETE"
            f"\tmanifest={output_path / MANIFEST_NAME}"
            f"\tmanifest_sha256={manifest_record['sha256']}"
            f"\tprocesses={expected_processes}"
            f"\trepetitions={arguments.repetitions}"
            f"\ttarget_cpu={arguments.target_cpu}"
            "\tevidence_class=diagnostic-nonpromotion"
            "\truntime_authority=absent"
            "\tpromotion_authority=absent"
        )
        return 0
    finally:
        for fd in (snapshot_binary_fd, evidence_fd, raw_fd, root_fd, source_binary_fd):
            if fd >= 0:
                os.close(fd)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Refusal as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        raise SystemExit(1) from error
