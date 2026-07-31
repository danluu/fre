#!/usr/bin/env python3
"""Independently verify and summarize an ABI2 three-engine campaign."""

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
import math
import os
import re
import stat
from fractions import Fraction
from pathlib import Path
from typing import Any


CAMPAIGN_SCHEMA = "fre-aot-selected-end-abi2-three-engine-campaign-v2"
BENCHMARK_SCHEMA = "fre-aot-selected-end-abi2-three-engine-v2"
ADMISSION_SCHEMA = "fre-aot-selected-end-abi2-retained-admission-v1"
HEARTBEAT_SCHEMA = "fre-aot-selected-end-abi2-admission-heartbeat-v1"
POST_LINK_SCHEMA = "fre-aot-selected-end-abi2-post-link-observation-v3"
PROGRESS_SCHEMA = "fre-aot-selected-end-abi2-campaign-progress-v1"
SUMMARY_SCHEMA = "fre-aot-selected-end-abi2-three-engine-summary-v1"
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
AOT = "aot-tag21-entry-direct-abi2"
JIT = "jit-tag21-strict-wx-abi2"
PORTABLE = "portable-exact-literal"
ENGINES = (AOT, JIT, PORTABLE)
ENGINE_ORIGINS = {
    AOT: "offline-compiled-static-link",
    JIT: "runtime-emitted-strict-wx",
    PORTABLE: "portable-preprocessed",
}
ENGINE_ORDERS = (
    (AOT, JIT, PORTABLE),
    (AOT, PORTABLE, JIT),
    (JIT, AOT, PORTABLE),
    (JIT, PORTABLE, AOT),
    (PORTABLE, AOT, JIT),
    (PORTABLE, JIT, AOT),
)
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
UINT = re.compile(r"(?:0|[1-9][0-9]*)\Z")
SAFE_RUN = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
SAFE_INSTANCE_ID = re.compile(r"[A-Za-z0-9_.:-]{1,160}\Z")
SAFE_INSTANCE_TYPE = re.compile(r"(?:c9g|m9g)\.[A-Za-z0-9.-]{1,80}\Z")
SAFE_PROTOCOL = re.compile(r"[A-Za-z0-9_.:/+-]{1,160}\Z")
MANIFEST_NAME = "manifest.v1.json"
MANIFEST_SHA_NAME = "manifest.v1.json.sha256"
MAX_MANIFEST_BYTES = 256 << 20
MAX_EVIDENCE_BYTES = 16 << 20
MAX_BINARY_BYTES = 512 << 20
MAX_CHILD_OUTPUT_BYTES = 4 << 20
MAX_CAMPAIGN_PROCESSES = 1 + 96 * len(SIZES) * len(SCENARIOS) * 2
MAX_PROGRESS_EVENTS = 2 * MAX_CAMPAIGN_PROCESSES + 4
MAX_PROGRESS_EVENT_BYTES = 4096
MAX_PROGRESS_JOURNAL_BYTES = 8 << 20
OWNED_CHILD_REAP_SECONDS = 5
RUNNER_SIGNAL_POLL_MILLISECONDS = 250
PROGRESS_NAME = "progress.v1.ndjson"
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
    """Fail-closed verification refusal."""


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


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def require_hex(value: str, width: int, label: str) -> str:
    pattern = HEX40 if width == 40 else HEX64
    require(pattern.fullmatch(value) is not None, f"{label} is not lowercase hex{width}")
    require(set(value) != {"0"}, f"{label} must not be all zero")
    return value


def integer(value: Any, minimum: int, maximum: int, label: str) -> int:
    require(type(value) is int, f"{label} must be an integer")
    require(minimum <= value <= maximum, f"{label} is outside {minimum}..{maximum}")
    return value


def uint_field(fields: dict[str, str], key: str, maximum: int = (1 << 128) - 1) -> int:
    value = fields.get(key)
    require(value is not None and UINT.fullmatch(value) is not None, f"{key} is not canonical uint")
    parsed = int(value)
    require(parsed <= maximum, f"{key} exceeds its numeric bound")
    return parsed


def read_fd(fd: int, maximum: int, label: str) -> bytes:
    status = os.fstat(fd)
    require(stat.S_ISREG(status.st_mode), f"{label} is not a regular file")
    require(0 <= status.st_size <= maximum, f"{label} exceeds its size bound")
    chunks: list[bytes] = []
    offset = 0
    while offset < status.st_size:
        chunk = os.pread(fd, min(1 << 20, status.st_size - offset), offset)
        require(bool(chunk), f"{label} changed during read")
        chunks.append(chunk)
        offset += len(chunk)
    require(os.fstat(fd).st_size == status.st_size, f"{label} size changed during read")
    return b"".join(chunks)


def open_directory(raw_path: str) -> tuple[Path, int, int, int]:
    path = Path(raw_path)
    require(path.is_absolute(), "campaign directory must be absolute")
    require(path == Path(os.path.realpath(path)), "campaign path contains a symlink")
    root_fd = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        root_names = set(os.listdir(root_fd))
        require(
            root_names
            == {
                MANIFEST_NAME,
                MANIFEST_SHA_NAME,
                PROGRESS_NAME,
                "raw",
                "evidence",
            },
            "campaign root is partial or contains unbound files",
        )
        raw_fd = os.open(
            "raw",
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=root_fd,
        )
        evidence_fd = os.open(
            "evidence",
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=root_fd,
        )
        return path, root_fd, raw_fd, evidence_fd
    except BaseException:
        os.close(root_fd)
        raise


def read_named(
    directory_fd: int,
    name: str,
    maximum: int,
    expected_mode: int,
    label: str,
) -> bytes:
    require("/" not in name and name not in ("", ".", ".."), f"unsafe {label} path")
    fd = os.open(
        name,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=directory_fd,
    )
    try:
        status = os.fstat(fd)
        require(stat.S_ISREG(status.st_mode), f"{label} is not regular")
        require(
            stat.S_IMODE(status.st_mode) == expected_mode,
            f"{label} mode is not {expected_mode:04o}",
        )
        require(status.st_nlink == 1, f"{label} has unexpected hard links")
        return read_fd(fd, maximum, label)
    finally:
        os.close(fd)


def read_relative(
    raw_fd: int,
    evidence_fd: int,
    path: str,
    maximum: int,
    expected_mode: int,
    label: str,
) -> bytes:
    pieces = path.split("/")
    require(len(pieces) == 2, f"{label} path is not a bound two-component path")
    directory, name = pieces
    if directory == "raw":
        directory_fd = raw_fd
    elif directory == "evidence":
        directory_fd = evidence_fd
    else:
        raise Refusal(f"{label} path escapes campaign directories")
    return read_named(directory_fd, name, maximum, expected_mode, label)


def verify_file_record(
    record: Any,
    expected_path: str,
    raw_fd: int,
    evidence_fd: int,
    maximum: int,
    expected_mode: int,
    label: str,
) -> bytes:
    require(
        type(record) is dict and set(record) == {"path", "bytes", "sha256", "mode"},
        f"{label} file record changed",
    )
    require(record["path"] == expected_path, f"{label} path drifted")
    require(record["mode"] == f"{expected_mode:04o}", f"{label} recorded mode drifted")
    require_hex(record["sha256"], 64, f"{label} digest")
    raw = read_relative(raw_fd, evidence_fd, expected_path, maximum, expected_mode, label)
    recorded_bytes = integer(record["bytes"], 0, maximum, f"{label} byte length")
    require(recorded_bytes == len(raw), f"{label} byte length drifted")
    require(record["sha256"] == sha256(raw), f"{label} digest drifted")
    return raw


def load_canonical(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Refusal(f"{label} is invalid JSON: {error}") from error
    require(type(value) is dict, f"{label} root is not an object")
    require(raw == canonical_json(value), f"{label} is not canonical JSON")
    return value


def parse_record(line: str) -> tuple[str, str | None, dict[str, str]]:
    columns = line.split("\t")
    require(bool(columns) and columns[0] != "", "empty output record")
    if columns[0] == "META":
        require(len(columns) == 3 and columns[1] != "", "malformed META record")
        return "META", None, {columns[1]: columns[2]}
    require(len(columns) >= 3, f"malformed {columns[0]} record")
    schema = columns[1]
    remaining = columns[2:]
    if columns[0] == "QUALIFICATION":
        require(remaining[0] == "PASS", "qualification did not pass")
        remaining = remaining[1:]
    fields: dict[str, str] = {}
    for column in remaining:
        require("=" in column, f"malformed {columns[0]} field")
        key, value = column.split("=", 1)
        require(key != "" and key not in fields, f"duplicate {columns[0]} field {key!r}")
        fields[key] = value
    return columns[0], schema, fields


def parse_stdout(raw: bytes, label: str) -> tuple[dict[str, str], list[tuple[str, dict[str, str]]]]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise Refusal(f"{label} stdout is not UTF-8") from error
    require(text.endswith("\n"), f"{label} stdout is truncated")
    require("\r" not in text and "\x00" not in text, f"{label} stdout has unsafe bytes")
    lines = text.splitlines()
    require(bool(lines) and all(line != "" for line in lines), f"{label} stdout has blank lines")
    metadata: dict[str, str] = {}
    records: list[tuple[str, dict[str, str]]] = []
    for line in lines:
        kind, schema, fields = parse_record(line)
        if kind == "META":
            key, value = next(iter(fields.items()))
            require(key not in metadata, f"{label} duplicates META {key!r}")
            metadata[key] = value
        else:
            require(schema == BENCHMARK_SCHEMA, f"{label} benchmark schema drifted")
            records.append((kind, fields))
    return metadata, records


def require_row_identity(
    kind: str,
    fields: dict[str, str],
    identity: dict[str, Any],
    baseline: dict[str, str],
    *,
    header: bool,
) -> None:
    required = {
        "source_commit": identity["source_commit"],
        "source_tree": identity["source_tree"],
        "run_id": identity["run_id"],
        "instance_type": identity["instance_type"],
        "helper_sha256": identity["helper_sha256"],
        "profile": identity["profile"],
        "artifact_identity": baseline["artifact_identity"],
        "bundle_identity": baseline["bundle_identity"],
        "evidence_class": EVIDENCE_CLASS,
        "runtime_authority": AUTHORITY,
        "promotion_authority": AUTHORITY,
    }
    if header:
        required["affinity_cpu"] = str(identity["target_cpu"])
    for key, expected in required.items():
        require(fields.get(key) == expected, f"{kind} row {key} is absent or drifted")


def validate_metadata(
    metadata: dict[str, str],
    command: str,
    identity: dict[str, Any],
    baseline: dict[str, str] | None,
) -> dict[str, str]:
    required = {
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
        "aot_primary_hot_route": "generated-owned-plan-consumer-loop-direct",
        "aot_compiler_cost_scope": "offline-excluded",
        "aot_linker_cost_scope": "offline-excluded",
    }
    for key, expected in required.items():
        require(metadata.get(key) == expected, f"{command} META {key} drifted")
    for key in (
        "artifact_identity",
        "compile_identity",
        "implementation_object_identity",
        "glue_object_identity",
        "bundle_identity",
        "deployment_binding_identity",
        "deployment_receipt_identity",
    ):
        require(HEX64.fullmatch(metadata.get(key, "")) is not None, f"{command} {key} malformed")
    compile_identity = metadata["compile_identity"]
    for key, expected in (
        (
            "aot_wrapper_symbol",
            "fre_aot_search_selected_end_qualification_direct_v2_" + compile_identity,
        ),
        (
            "aot_entry_symbol",
            "fre_aot_search_selected_end_entry_v2_" + compile_identity,
        ),
        (
            "aot_payload_symbol",
            "fre_aot_search_selected_end_payload_v2_" + compile_identity,
        ),
        (
            "aot_metadata_symbol",
            "fre_aot_search_selected_end_metadata_v2_" + compile_identity,
        ),
        (
            "aot_generated_proof_callsite_symbol",
            "fre_aot_search_selected_end_qualification_primary_callsite_v2_"
            + compile_identity,
        ),
        (
            "aot_consumer_hot_callsite_symbol",
            "fre_aot_search_selected_end_three_engine_hot_callsite_v2_"
            + compile_identity,
        ),
    ):
        require(metadata.get(key) == expected, f"{command} META {key} changed namespace")
    require(
        metadata["implementation_object_identity"] != metadata["glue_object_identity"],
        f"{command} object identities unexpectedly alias",
    )
    if baseline is not None:
        for key in (
            "artifact_identity",
            "compile_identity",
            "implementation_object_identity",
            "glue_object_identity",
            "bundle_identity",
            "deployment_binding_identity",
            "deployment_receipt_identity",
            "aot_wrapper_symbol",
            "aot_entry_symbol",
            "aot_payload_symbol",
            "aot_metadata_symbol",
            "aot_generated_proof_callsite_symbol",
            "aot_consumer_hot_callsite_symbol",
        ):
            require(metadata.get(key) == baseline.get(key), f"{command} META {key} drifted")
    if command in ("qualification", "cell"):
        for key, expected in (
            ("jit_aot_artifact_equal", "true"),
            ("jit_publication", "strict-wx"),
            ("selected_end_return_encoding", "zero-or-absolute-end"),
            ("selected_end_result_slot_bytes", "0"),
        ):
            require(metadata.get(key) == expected, f"{command} META {key} drifted")
        uint_field(metadata, "jit_code_bytes", (1 << 32) - 1)
        uint_field(metadata, "jit_vector_instructions", (1 << 32) - 1)
    return metadata


def expected_order(repetition: int) -> tuple[str, str, str]:
    return ENGINE_ORDERS[repetition % len(ENGINE_ORDERS)]


def validate_qualification(
    records: list[tuple[str, dict[str, str]]],
    identity: dict[str, Any],
    baseline: dict[str, str],
) -> None:
    require([kind for kind, _ in records] == ["QUALIFICATION"], "qualification shape changed")
    fields = records[0][1]
    require_row_identity("QUALIFICATION", fields, identity, baseline, header=True)
    require(uint_field(fields, "cases", 10_000) == 72, "qualification case count changed")
    require(
        uint_field(fields, "comparisons", 100_000) == 288,
        "qualification comparison count changed",
    )
    for key, expected in (
        ("aot_primary", "generated-owned-plan-consumer-loop-direct"),
        ("qualification_wrapper", "linked-and-exercised"),
        ("jit_publication", "strict-wx"),
        ("jit_aot_artifact_equal", "true"),
        ("vl16_sessions", "aot-and-jit"),
    ):
        require(fields.get(key) == expected, f"qualification {key} drifted")


def validate_hot(
    records: list[tuple[str, dict[str, str]]],
    identity: dict[str, Any],
    baseline: dict[str, str],
    coordinate: dict[str, Any],
) -> dict[str, dict[str, int]]:
    require(
        [kind for kind, _ in records] == ["CELL", "SAMPLE", "SAMPLE", "SAMPLE"],
        "hot process shape changed",
    )
    header = records[0][1]
    require_row_identity("CELL", header, identity, baseline, header=True)
    repetition = coordinate["repetition"]
    order = expected_order(repetition)
    for key, expected in (
        ("stage", "hot"),
        ("size", coordinate["size"]),
        ("scenario", coordinate["scenario"]),
        ("repetition", str(repetition)),
        ("order", ",".join(order)),
    ):
        require(header.get(key) == expected, f"hot header {key} drifted")
    require(
        uint_field(header, "alignment", 15) == (repetition // 6) % 16,
        "hot alignment rotation drifted",
    )
    require(uint_field(header, "searched_bytes") > 0, "hot searched_bytes is zero")

    values: dict[str, dict[str, int]] = {}
    for kind, fields in records[1:]:
        require_row_identity(kind, fields, identity, baseline, header=False)
        require(fields.get("stage") == "hot", "hot sample stage drifted")
        engine = fields.get("engine", "")
        require(engine in ENGINES and engine not in values, "hot engine set duplicates or drifted")
        require(fields.get("code_origin") == ENGINE_ORIGINS[engine], "hot code origin drifted")
        require(fields.get("repetition") == str(repetition), "hot repetition drifted")
        position = uint_field(fields, "position", 2)
        require(order[position] == engine, "hot sample position differs from order")
        iterations = uint_field(fields, "iterations", 1 << 62)
        elapsed_ns = uint_field(fields, "elapsed_ns")
        require(iterations > 0 and elapsed_ns > 0, "hot sample is empty")
        uint_field(fields, "checksum", (1 << 64) - 1)
        for key in ("cpu_before", "cpu_after"):
            require(
                uint_field(fields, key, 1 << 20) == identity["target_cpu"],
                f"hot {key} drifted",
            )
        values[engine] = {"iterations": iterations, "elapsed_ns": elapsed_ns}
    require(set(values) == set(ENGINES), "hot sample engine set is incomplete")
    return values


def validate_lifecycle(
    records: list[tuple[str, dict[str, str]]],
    identity: dict[str, Any],
    baseline: dict[str, str],
    coordinate: dict[str, Any],
) -> tuple[dict[str, dict[str, int]], dict[str, int]]:
    require(
        [kind for kind, _ in records]
        == ["LIFECYCLE", "SAMPLE", "SAMPLE", "SAMPLE", "SAMPLE"],
        "lifecycle process shape changed",
    )
    header = records[0][1]
    require_row_identity("LIFECYCLE", header, identity, baseline, header=True)
    repetition = coordinate["repetition"]
    order = expected_order(repetition)
    for key, expected in (
        ("size", coordinate["size"]),
        ("scenario", coordinate["scenario"]),
        ("repetition", str(repetition)),
        ("order", ",".join(order)),
        ("iterations", "8"),
        ("aot_compile", "offline-excluded"),
        ("aot_link", "offline-excluded"),
    ):
        require(header.get(key) == expected, f"lifecycle header {key} drifted")

    values: dict[str, dict[str, int]] = {}
    activation: dict[str, int] | None = None
    timing_keys = (
        "plan_ns",
        "emit_ns",
        "publish_ns",
        "preflight_ns",
        "session_ns",
        "first_call_ns",
        "total_ns",
    )
    for kind, fields in records[1:]:
        require_row_identity(kind, fields, identity, baseline, header=False)
        require(fields.get("repetition") == str(repetition), "lifecycle repetition drifted")
        engine = fields.get("engine", "")
        require(engine in ENGINES, "lifecycle engine drifted")
        require(fields.get("code_origin") == ENGINE_ORIGINS[engine], "lifecycle origin drifted")
        iterations = uint_field(fields, "iterations", 8)
        require(iterations == 8, "lifecycle iterations drifted")
        timings = {
            "iterations": iterations,
            **{key: uint_field(fields, key) for key in timing_keys},
        }
        require(timings["total_ns"] > 0, "lifecycle total is empty")
        require(
            sum(timings[key] for key in timing_keys[:-1]) <= timings["total_ns"],
            "lifecycle stage sum exceeds total",
        )
        uint_field(fields, "checksum", (1 << 64) - 1)
        for key in ("cpu_before", "cpu_after"):
            require(
                uint_field(fields, key, 1 << 20) == identity["target_cpu"],
                f"lifecycle {key} drifted",
            )
        stage = fields.get("stage")
        if stage == "lifecycle":
            require(engine not in values, "duplicate lifecycle engine")
            position = uint_field(fields, "position", 2)
            require(order[position] == engine, "lifecycle position differs from order")
            values[engine] = timings
        elif stage == "aot-activation":
            require(engine == AOT and activation is None, "AOT activation duplicates or drifted")
            require(fields.get("prepared_preflight") == "outside", "activation scope drifted")
            for key in ("plan_ns", "emit_ns", "publish_ns", "preflight_ns"):
                require(timings[key] == 0, f"activation {key} is not excluded")
            activation = timings
        else:
            raise Refusal("unknown lifecycle sample stage")
    require(set(values) == set(ENGINES), "lifecycle engine set is incomplete")
    require(activation is not None, "AOT activation sample is absent")
    return values, activation


def validate_receipt(
    receipt: dict[str, Any],
    identity: dict[str, Any],
    evidence_sha256: str,
    started_unix_ns: int,
    completed_unix_ns: int,
) -> dict[str, Any]:
    require(
        set(receipt)
        == {
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
        },
        "admission receipt field set changed",
    )
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
        ("target_cpu", identity["target_cpu"]),
        ("helper_sha256", identity["helper_sha256"]),
        ("profile", identity["profile"]),
    ):
        require(receipt[key] == expected, f"admission receipt {key} drifted")
    integer(
        receipt["target_cpu"],
        identity["target_cpu"],
        identity["target_cpu"],
        "admission receipt target CPU",
    )
    require(
        type(receipt["receipt_id"]) is str
        and SAFE_RUN.fullmatch(receipt["receipt_id"]) is not None,
        "admission receipt ID is malformed",
    )
    require(
        type(receipt["helper_protocol"]) is str
        and SAFE_PROTOCOL.fullmatch(receipt["helper_protocol"]) is not None,
        "admission helper protocol is malformed",
    )

    pins = receipt["pins"]
    require(type(pins) is dict and bool(pins), "admission pins are absent")
    for key, expected in (
        ("source_commit", identity["source_commit"]),
        ("source_tree", identity["source_tree"]),
        ("helper_sha256", identity["helper_sha256"]),
        ("profile", identity["profile"]),
    ):
        require(pins.get(key) == expected, f"admission pin {key} drifted")
    for key, value in pins.items():
        require(
            type(key) is str
            and 1 <= len(key) <= 80
            and type(value) is str
            and 1 <= len(value) <= 256
            and "\x00" not in value,
            "admission pin syntax is malformed",
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
    require(headroom["target_cpu_admitted"] is True, "receipt did not admit target CPU")
    require(
        type(headroom["basis"]) is str
        and 1 <= len(headroom["basis"]) <= 512
        and "\x00" not in headroom["basis"],
        "receipt headroom basis is malformed",
    )
    require(
        headroom["unrelated_cpu_work"] == "coexist-if-target-cpu-admitted",
        "receipt coexistence policy drifted",
    )
    require(
        headroom["other_work_kill_policy"] == "never",
        "receipt permits killing other work",
    )
    require(
        headroom["evidence_sha256"] == evidence_sha256,
        "receipt evidence digest drifted",
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
        "admission acquisition fields changed",
    )
    used = integer(acquisition["attempts_used"], 1, 120, "admission attempts used")
    maximum = integer(acquisition["max_attempts"], 1, 120, "admission max attempts")
    acquired_start = integer(
        acquisition["started_unix_ns"], 1, (1 << 63) - 1, "admission acquisition start"
    )
    acquired_complete = integer(
        acquisition["completed_unix_ns"],
        1,
        (1 << 63) - 1,
        "admission acquisition completion",
    )
    acquired_deadline = integer(
        acquisition["deadline_unix_ns"],
        1,
        (1 << 63) - 1,
        "admission acquisition deadline",
    )
    require(used <= maximum, "admission exceeded bounded attempts")
    require(
        acquired_start <= acquired_complete <= acquired_deadline,
        "admission exceeded bounded acquisition deadline",
    )
    require(
        acquired_complete <= started_unix_ns,
        "admission acquisition completed after the campaign started",
    )

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
        "admission continuity fields changed",
    )
    require(continuity["mode"] == "continuous-live-holder", "admission holder is not continuous")
    require(continuity["heartbeat_schema"] == HEARTBEAT_SCHEMA, "heartbeat schema drifted")
    for key in ("holder_id", "session_id", "lease_epoch"):
        require(
            type(continuity[key]) is str
            and SAFE_RUN.fullmatch(continuity[key]) is not None,
            f"continuity {key} is malformed",
        )
    continuous_since = integer(
        continuity["continuous_since_unix_ns"],
        1,
        (1 << 63) - 1,
        "continuous holder start",
    )
    max_heartbeat_age = integer(
        continuity["maximum_heartbeat_age_ns"],
        1_000_000,
        300_000_000_000,
        "maximum heartbeat age",
    )
    valid_from = integer(
        receipt["valid_from_unix_ns"], 1, (1 << 63) - 1, "receipt valid_from"
    )
    valid_until = integer(
        receipt["valid_until_unix_ns"], 1, (1 << 63) - 1, "receipt valid_until"
    )
    require(
        continuous_since <= acquired_complete,
        "continuous holder starts after receipt acquisition",
    )
    require(valid_from <= started_unix_ns, "receipt was not valid at campaign start")
    require(completed_unix_ns < valid_until, "receipt expired before campaign completion")
    return {
        "receipt_id": receipt["receipt_id"],
        "helper_protocol": receipt["helper_protocol"],
        "pin_set_sha256": sha256(canonical_json(pins)),
        "headroom_basis": headroom["basis"],
        "acquisition_attempts_used": used,
        "acquisition_max_attempts": maximum,
        "acquisition_deadline_unix_ns": acquired_deadline,
        "holder_id": continuity["holder_id"],
        "session_id": continuity["session_id"],
        "lease_epoch": continuity["lease_epoch"],
        "continuity_mode": continuity["mode"],
        "continuous_since_unix_ns": continuous_since,
        "maximum_heartbeat_age_ns": max_heartbeat_age,
        "valid_from_unix_ns": valid_from,
        "valid_until_unix_ns": valid_until,
        "coexistence_policy": headroom["unrelated_cpu_work"],
        "other_work_kill_policy": headroom["other_work_kill_policy"],
    }


def validate_heartbeat(
    heartbeat: dict[str, Any],
    admission: dict[str, Any],
    identity: dict[str, Any],
    evidence_sha256: str,
    boundary_unix_ns: int,
    label: str,
) -> dict[str, int]:
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
        f"{label} heartbeat field set changed",
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
        require(heartbeat[key] == expected, f"{label} heartbeat {key} drifted")
    integer(
        heartbeat["target_cpu"],
        identity["target_cpu"],
        identity["target_cpu"],
        f"{label} heartbeat target CPU",
    )
    integer(
        heartbeat["continuous_since_unix_ns"],
        admission["continuous_since_unix_ns"],
        admission["continuous_since_unix_ns"],
        f"{label} heartbeat continuous start",
    )
    sequence = integer(heartbeat["sequence"], 0, (1 << 63) - 1, f"{label} heartbeat sequence")
    observed = integer(
        heartbeat["observed_unix_ns"],
        1,
        (1 << 63) - 1,
        f"{label} heartbeat observation",
    )
    valid_until = integer(
        heartbeat["valid_until_unix_ns"],
        1,
        (1 << 63) - 1,
        f"{label} heartbeat validity",
    )
    require(
        observed <= boundary_unix_ns + admission["maximum_heartbeat_age_ns"],
        f"{label} heartbeat observation is implausibly after its boundary",
    )
    require(
        boundary_unix_ns - observed <= admission["maximum_heartbeat_age_ns"],
        f"{label} heartbeat is stale at its boundary",
    )
    require(boundary_unix_ns < valid_until, f"{label} heartbeat expired at its boundary")
    require(
        valid_until <= admission["valid_until_unix_ns"],
        f"{label} heartbeat outlives receipt",
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
        f"{label} heartbeat headroom fields changed",
    )
    require(headroom["target_cpu_admitted"] is True, f"{label} target CPU was not admitted")
    require(
        headroom["unrelated_cpu_work"] == "coexist-if-target-cpu-admitted",
        f"{label} coexistence policy drifted",
    )
    require(
        headroom["other_work_kill_policy"] == "never",
        f"{label} permits killing other work",
    )
    require(
        headroom["evidence_sha256"] == evidence_sha256,
        f"{label} evidence digest drifted",
    )
    return {
        "sequence": sequence,
        "observed_unix_ns": observed,
        "valid_until_unix_ns": valid_until,
    }


def parse_post_link(
    raw: bytes, identity: dict[str, Any], binary_sha256: str
) -> dict[str, str]:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise Refusal("post-link observation is not ASCII") from error
    require(text.endswith("\n") and text.count("\n") == 1, "post-link observation is not one line")
    columns = text[:-1].split("\t")
    require(
        len(columns) >= 4
        and columns[:3] == ["OBSERVATION", POST_LINK_SCHEMA, "PASS"],
        "post-link observation did not pass",
    )
    fields: dict[str, str] = {}
    for column in columns[3:]:
        require("=" in column, "malformed post-link field")
        key, value = column.split("=", 1)
        require(key != "" and key not in fields, f"duplicate post-link field {key!r}")
        fields[key] = value
    require(set(fields) == POST_LINK_FIELDS, "post-link observation field set changed")
    for key, expected in (
        ("source_commit", identity["source_commit"]),
        ("source_tree", identity["source_tree"]),
        ("helper_sha256", identity["helper_sha256"]),
        ("profile", identity["profile"]),
        ("final_binary_sha256", binary_sha256),
        ("wrapper_call", "R_AARCH64_CALL26-to-direct-bl"),
        ("generated_proof_callsite", "hidden-direct-bl-exact-entry"),
        (
            "primary_aot_call",
            "hidden-consumer-loop-direct-bl-exact-entry",
        ),
        ("consumer_hot_callsite_final_observed", "true"),
        ("generated_binding_authenticated", "true"),
        ("deployment_receipt_authenticated", "true"),
        ("reject_plt", "true"),
        ("reject_blr", "true"),
        ("reject_x4_argument", "true"),
        ("consumer_loop_x4_scratch", "unconstrained-nonabi"),
        ("result_slot_bytes", "0"),
        ("entry_bytes_equal", "true"),
        ("payload_bytes_equal", "true"),
        ("metadata_bytes_equal", "true"),
        ("compile_identity_derived", "true"),
        ("runtime_authority", AUTHORITY),
        ("promotion_authority", AUTHORITY),
    ):
        require(fields.get(key) == expected, f"post-link {key} is absent or drifted")
    for key in (
        "artifact_identity",
        "compile_identity",
        "implementation_object_identity",
        "glue_object_identity",
        "bundle_identity",
        "deployment_binding_identity",
        "deployment_receipt_identity",
        "final_binary_sha256",
    ):
        require(HEX64.fullmatch(fields.get(key, "")) is not None, f"post-link {key} malformed")
    return fields


def median_fraction(values: list[Fraction]) -> Fraction:
    require(bool(values), "cannot summarize an empty vector")
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2


def percentile_fraction(values: list[Fraction], numerator: int, denominator: int) -> Fraction:
    require(bool(values), "cannot summarize an empty vector")
    ordered = sorted(values)
    rank = max(1, (len(ordered) * numerator + denominator - 1) // denominator)
    return ordered[min(rank - 1, len(ordered) - 1)]


def as_number(value: Fraction) -> float:
    result = float(value)
    require(math.isfinite(result), "summary produced a non-finite number")
    return result


def numeric_stats(values: list[Fraction], *, geometric: bool) -> dict[str, Any]:
    require(bool(values), "numeric summary is empty")
    result: dict[str, Any] = {
        "count": len(values),
        "minimum": as_number(min(values)),
        "p05": as_number(percentile_fraction(values, 5, 100)),
        "median": as_number(median_fraction(values)),
        "p95": as_number(percentile_fraction(values, 95, 100)),
        "maximum": as_number(max(values)),
        "arithmetic_mean": math.fsum(float(value) for value in values) / len(values),
    }
    if geometric:
        require(all(value > 0 for value in values), "geometric mean requires positive values")
        result["geometric_mean"] = math.exp(
            math.fsum(math.log(float(value)) for value in values) / len(values)
        )
    return result


def sign_test_two_sided(wins: int, losses: int) -> float | None:
    trials = wins + losses
    if trials == 0:
        return None
    tail = min(wins, losses)
    probability = 2.0 * sum(math.comb(trials, index) for index in range(tail + 1)) / (2**trials)
    return min(1.0, probability)


def paired_stats(left: list[Fraction], right: list[Fraction]) -> dict[str, Any]:
    require(len(left) == len(right) and bool(left), "paired vectors are incomplete")
    ratios = [left_value / right_value for left_value, right_value in zip(left, right)]
    deltas = [left_value - right_value for left_value, right_value in zip(left, right)]
    wins = sum(value < 1 for value in ratios)
    ties = sum(value == 1 for value in ratios)
    losses = len(ratios) - wins - ties
    return {
        "direction": "left_over_right; less_than_one_favors_left",
        "ratio": numeric_stats(ratios, geometric=True),
        "delta_ns_per_operation": numeric_stats(deltas, geometric=False),
        "left_wins": wins,
        "ties": ties,
        "left_losses": losses,
        "two_sided_exact_sign_test_p": sign_test_two_sided(wins, losses),
    }


def engine_ns(
    samples: list[dict[str, dict[str, int]]], engine: str, elapsed_key: str
) -> list[Fraction]:
    return [
        Fraction(sample[engine][elapsed_key], sample[engine]["iterations"])
        for sample in samples
    ]


def summarize_engine_samples(
    samples: list[dict[str, dict[str, int]]], elapsed_key: str
) -> dict[str, Any]:
    values = {engine: engine_ns(samples, engine, elapsed_key) for engine in ENGINES}
    return {
        "engine_ns_per_operation": {
            engine: numeric_stats(engine_values, geometric=True)
            for engine, engine_values in values.items()
        },
        "paired_ratios": {
            "jit_over_portable": paired_stats(values[JIT], values[PORTABLE]),
            "aot_over_portable": paired_stats(values[AOT], values[PORTABLE]),
            "jit_over_aot": paired_stats(values[JIT], values[AOT]),
        },
    }


def summarize_cells(
    samples_by_key: dict[tuple[str, str, int], dict[str, dict[str, int]]],
    elapsed_key: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    per_cell: dict[str, Any] = {}
    aggregate: list[dict[str, dict[str, int]]] = []
    for size in SIZES:
        for scenario in SCENARIOS:
            samples = [
                samples_by_key[(size, scenario, repetition)]
                for repetition in sorted(
                    key[2]
                    for key in samples_by_key
                    if key[0] == size and key[1] == scenario
                )
            ]
            require(bool(samples), f"cell {size}/{scenario} has no samples")
            per_cell[f"{size}/{scenario}"] = summarize_engine_samples(samples, elapsed_key)
            aggregate.extend(samples)
    return per_cell, summarize_engine_samples(aggregate, elapsed_key)


def summarize_lifecycle_stages(
    lifecycle: dict[tuple[str, str, int], dict[str, dict[str, int]]],
) -> dict[str, Any]:
    stage_keys = (
        "plan_ns",
        "emit_ns",
        "publish_ns",
        "preflight_ns",
        "session_ns",
        "first_call_ns",
        "total_ns",
    )
    summary: dict[str, Any] = {}
    for engine in ENGINES:
        summary[engine] = {}
        for stage in stage_keys:
            values = [
                Fraction(samples[engine][stage], samples[engine]["iterations"])
                for samples in lifecycle.values()
            ]
            summary[engine][f"{stage}_per_iteration"] = numeric_stats(
                values, geometric=all(value > 0 for value in values)
            )
    return summary


def summarize_activation(
    activation: dict[tuple[str, str, int], dict[str, int]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for stage in ("session_ns", "first_call_ns", "total_ns"):
        values = [
            Fraction(sample[stage], sample["iterations"]) for sample in activation.values()
        ]
        result[f"{stage}_per_iteration"] = numeric_stats(
            values, geometric=all(value > 0 for value in values)
        )
    return result


def break_even_summary(
    hot: dict[tuple[str, str, int], dict[str, dict[str, int]]],
    lifecycle: dict[tuple[str, str, int], dict[str, dict[str, int]]],
    candidate: str,
    baseline: str,
) -> dict[str, Any]:
    setup_deltas: list[Fraction] = []
    hot_savings: list[Fraction] = []
    additional_hot_calls: list[Fraction] = []
    total_calls: list[Fraction] = []
    unavailable = 0
    for key in sorted(hot):
        hot_candidate = Fraction(
            hot[key][candidate]["elapsed_ns"], hot[key][candidate]["iterations"]
        )
        hot_baseline = Fraction(
            hot[key][baseline]["elapsed_ns"], hot[key][baseline]["iterations"]
        )
        setup_candidate = Fraction(
            lifecycle[key][candidate]["total_ns"], lifecycle[key][candidate]["iterations"]
        )
        setup_baseline = Fraction(
            lifecycle[key][baseline]["total_ns"], lifecycle[key][baseline]["iterations"]
        )
        setup_delta = setup_candidate - setup_baseline
        saving = hot_baseline - hot_candidate
        setup_deltas.append(setup_delta)
        hot_savings.append(saving)
        if saving > 0:
            exact_additional = max(setup_delta, Fraction(0)) / saving
            rounded_additional = (
                exact_additional.numerator + exact_additional.denominator - 1
            ) // exact_additional.denominator
            additional_hot_calls.append(Fraction(rounded_additional))
            total_calls.append(Fraction(rounded_additional + 1))
        else:
            unavailable += 1
    return {
        "formula": (
            "additional_hot_calls=ceil(max(candidate_lifecycle_minus_"
            "baseline_lifecycle,0)/(baseline_hot_minus_candidate_hot));"
            " total_calls=1+additional_hot_calls because each measured lifecycle"
            " already includes its first call"
        ),
        "rounding": "exact-rational-ceiling-per-paired-input-before-summary",
        "paired_inputs": len(setup_deltas),
        "candidate_lifecycle_minus_baseline_lifecycle_ns": numeric_stats(
            setup_deltas, geometric=False
        ),
        "baseline_hot_minus_candidate_hot_ns_per_call": numeric_stats(
            hot_savings, geometric=False
        ),
        "additional_hot_calls_after_lifecycle_when_candidate_hot_is_faster": (
            numeric_stats(
                additional_hot_calls,
                geometric=all(value > 0 for value in additional_hot_calls),
            )
            if additional_hot_calls
            else None
        ),
        "total_calls_including_lifecycle_first_call_when_candidate_hot_is_faster": (
            numeric_stats(total_calls, geometric=True)
            if total_calls
            else None
        ),
        "unavailable_when_candidate_not_hotter": unavailable,
    }


def build_summary(
    identity: dict[str, Any],
    manifest_sha256: str,
    binary_sha256: str,
    admission_receipt_sha256: str,
    admission_evidence_sha256: str,
    hot: dict[tuple[str, str, int], dict[str, dict[str, int]]],
    lifecycle: dict[tuple[str, str, int], dict[str, dict[str, int]]],
    activation: dict[tuple[str, str, int], dict[str, int]],
) -> dict[str, Any]:
    hot_cells, hot_aggregate = summarize_cells(hot, "elapsed_ns")
    lifecycle_cells, lifecycle_aggregate = summarize_cells(lifecycle, "total_ns")
    return {
        "schema": SUMMARY_SCHEMA,
        "evidence_class": EVIDENCE_CLASS,
        "promotion_authority": AUTHORITY,
        "runtime_authority": AUTHORITY,
        "decision": "diagnostic-statistics-only-no-hard-coded-success",
        "identity": identity,
        "bindings": {
            "manifest_sha256": manifest_sha256,
            "binary_sha256": binary_sha256,
            "admission_receipt_sha256": admission_receipt_sha256,
            "admission_evidence_sha256": admission_evidence_sha256,
        },
        "hot": {
            "unit": "nanoseconds-per-search-call",
            "per_cell": hot_cells,
            "aggregate_equal_weight_per_cell_repetition": hot_aggregate,
        },
        "lifecycle": {
            "unit": "nanoseconds-per-lifecycle-iteration",
            "per_cell": lifecycle_cells,
            "aggregate_equal_weight_per_cell_repetition": lifecycle_aggregate,
            "aggregate_stage_components": summarize_lifecycle_stages(lifecycle),
        },
        "aot_activation": {
            "scope": "prepared-preflight-outside; VL16-session-plus-first-direct-call",
            **summarize_activation(activation),
        },
        "break_even_inputs": {
            "jit_vs_portable": break_even_summary(hot, lifecycle, JIT, PORTABLE),
            "aot_vs_portable_runtime_lifecycle": break_even_summary(
                hot, lifecycle, AOT, PORTABLE
            ),
            "jit_vs_aot_runtime_lifecycle": break_even_summary(hot, lifecycle, JIT, AOT),
            "aot_offline_compiler_and_linker_cost": "unmeasured-and-excluded",
        },
        "interpretation": {
            "ratios": "left_over_right; less_than_one_favors_left",
            "pairing": "same-size-scenario-repetition fresh-process rows",
            "weighting": "each size/scenario/repetition pair receives equal weight",
            "authority": "results do not promote or activate any runtime route",
        },
    }


def require_cpuinfo_d84(raw: bytes) -> None:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise Refusal("CPU evidence is not ASCII") from error
    processors = 0
    for section in text.split("\n\n"):
        fields = {
            key.strip(): value.strip()
            for line in section.splitlines()
            if ":" in line
            for key, value in [line.split(":", 1)]
        }
        if "processor" not in fields:
            continue
        processors += 1
        require(fields.get("CPU implementer") == "0x41", "CPU evidence implementer drifted")
        require(fields.get("CPU part") == "0xd84", "CPU evidence part drifted")
        features = set(fields.get("Features", "").split())
        require({"asimd", "sve", "sve2"} <= features, "CPU evidence lacks ASIMD/SVE/SVE2")
    require(processors > 0, "CPU evidence contains no processor sections")


def expected_schedule(
    repetitions: int, identity: dict[str, Any]
) -> list[tuple[str, dict[str, Any], list[str]]]:
    qualification_arguments = [
        identity["source_commit"],
        identity["source_tree"],
        identity["run_id"],
        identity["instance_type"],
        identity["helper_sha256"],
        identity["profile"],
    ]
    result = [
        ("qualification", {"kind": "qualification"}, qualification_arguments)
    ]
    for repetition in range(repetitions):
        for size in SIZES:
            for scenario in SCENARIOS:
                coordinate = {
                    "size": size,
                    "scenario": scenario,
                    "repetition": repetition,
                }
                arguments = [
                    size,
                    scenario,
                    str(repetition),
                    *qualification_arguments,
                ]
                result.append(("cell", coordinate, arguments))
                result.append(("lifecycle", coordinate, arguments))
    return result


def validate_progress_journal(
    raw: bytes,
    schedule: list[tuple[str, dict[str, Any], list[str]]],
    processes: list[dict[str, Any]],
    started_unix_ns: int,
    completed_unix_ns: int,
) -> int:
    require(
        0 < len(raw) <= MAX_PROGRESS_JOURNAL_BYTES,
        "progress journal exceeds its byte bound",
    )
    require(raw.endswith(b"\n"), "progress journal is truncated")
    lines = raw.splitlines(keepends=True)
    expected_events = 2 * len(schedule) + 2
    require(
        expected_events <= MAX_PROGRESS_EVENTS and len(lines) == expected_events,
        "progress journal event schedule is incomplete",
    )
    records: list[dict[str, Any]] = []
    runner_pid: int | None = None
    previous_emitted = started_unix_ns
    exact_fields = {
        "schema",
        "event_sequence",
        "event",
        "emitted_unix_ns",
        "runner_pid",
        "expected_processes",
        "completed_processes",
        "child_sequence",
        "child_command",
        "child_pid",
        "coordinate",
        "resumable",
        "selective_retry",
    }
    for event_sequence, line in enumerate(lines):
        require(
            len(line) <= MAX_PROGRESS_EVENT_BYTES,
            f"progress event {event_sequence} exceeds its byte bound",
        )
        record = load_canonical(line, f"progress event {event_sequence}")
        require(
            set(record) == exact_fields,
            f"progress event {event_sequence} field set changed",
        )
        require(record["schema"] == PROGRESS_SCHEMA, "progress schema drifted")
        observed_event_sequence = integer(
            record["event_sequence"],
            0,
            MAX_PROGRESS_EVENTS - 1,
            f"progress event {event_sequence} sequence",
        )
        require(
            observed_event_sequence == event_sequence,
            f"progress event {event_sequence} sequence drifted",
        )
        observed_expected_processes = integer(
            record["expected_processes"],
            1,
            MAX_CAMPAIGN_PROCESSES,
            f"progress event {event_sequence} expected processes",
        )
        require(
            observed_expected_processes == len(schedule),
            f"progress event {event_sequence} process bound drifted",
        )
        record["completed_processes"] = integer(
            record["completed_processes"],
            0,
            len(schedule),
            f"progress event {event_sequence} completed processes",
        )
        require(
            record["resumable"] is False and record["selective_retry"] is False,
            f"progress event {event_sequence} claims replay authority",
        )
        emitted = integer(
            record["emitted_unix_ns"],
            1,
            (1 << 63) - 1,
            f"progress event {event_sequence} timestamp",
        )
        require(
            previous_emitted <= emitted <= completed_unix_ns,
            f"progress event {event_sequence} timestamp moved backward or escaped campaign",
        )
        previous_emitted = emitted
        record["emitted_unix_ns"] = emitted
        observed_runner_pid = integer(
            record["runner_pid"],
            1,
            (1 << 31) - 1,
            f"progress event {event_sequence} runner PID",
        )
        if runner_pid is None:
            runner_pid = observed_runner_pid
        require(
            observed_runner_pid == runner_pid,
            f"progress event {event_sequence} runner PID drifted",
        )
        record["runner_pid"] = observed_runner_pid
        records.append(record)

    for index in (0, len(records) - 1):
        record = records[index]
        require(
            record["child_sequence"] is None
            and record["child_command"] is None
            and record["child_pid"] is None
            and record["coordinate"] is None,
            f"campaign progress event {index} unexpectedly names a child",
        )
    require(
        records[0]["event"] == "campaign-started"
        and records[0]["completed_processes"] == 0,
        "progress journal does not begin at campaign start",
    )
    require(
        records[-1]["event"] == "campaign-finalizing"
        and records[-1]["completed_processes"] == len(schedule),
        "progress journal does not end at manifest finalization",
    )

    for sequence, ((command, coordinate, _), process) in enumerate(
        zip(schedule, processes)
    ):
        started = records[1 + sequence * 2]
        completed = records[2 + sequence * 2]
        for event_name, record in (("start", started), ("completion", completed)):
            require(
                integer(
                    record["child_sequence"],
                    0,
                    len(schedule) - 1,
                    f"progress child {sequence} {event_name} sequence",
                )
                == sequence,
                f"progress child {sequence} {event_name} sequence drifted",
            )
            require(
                type(record["child_command"]) is str
                and record["child_command"] == command,
                f"progress child {sequence} {event_name} command drifted",
            )
            observed_coordinate = record["coordinate"]
            require(
                type(observed_coordinate) is dict
                and set(observed_coordinate) == set(coordinate),
                f"progress child {sequence} {event_name} coordinate shape drifted",
            )
            for key, expected_value in coordinate.items():
                observed_value = observed_coordinate[key]
                if type(expected_value) is int:
                    require(
                        integer(
                            observed_value,
                            0,
                            95,
                            f"progress child {sequence} {event_name} coordinate {key}",
                        )
                        == expected_value,
                        f"progress child {sequence} {event_name} coordinate {key} drifted",
                    )
                else:
                    require(
                        type(observed_value) is str
                        and observed_value == expected_value,
                        f"progress child {sequence} {event_name} coordinate {key} drifted",
                    )
        child_pid = integer(
            started["child_pid"],
            1,
            (1 << 31) - 1,
            f"progress child {sequence} PID",
        )
        require(
            integer(
                completed["child_pid"],
                1,
                (1 << 31) - 1,
                f"progress child {sequence} completion PID",
            )
            == child_pid,
            f"progress child {sequence} PID drifted",
        )
        require(
            started["event"] == "child-started"
            and started["completed_processes"] == sequence
            and completed["event"] == "child-completed"
            and completed["completed_processes"] == sequence + 1,
            f"progress child {sequence} terminal state drifted",
        )
        require(
            process["started_unix_ns"]
            <= started["emitted_unix_ns"]
            <= process["completed_unix_ns"]
            <= completed["emitted_unix_ns"],
            f"progress child {sequence} timestamps do not enclose execution",
        )
    return expected_events


def subset_file_record(record: dict[str, Any]) -> dict[str, Any]:
    return {key: record[key] for key in ("path", "bytes", "sha256", "mode")}


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Independently verify and summarize a fresh-process ABI2 campaign"
    )
    result.add_argument("--campaign-dir", required=True)
    result.add_argument("--source-commit", required=True)
    result.add_argument("--source-tree", required=True)
    result.add_argument("--run-id", required=True)
    result.add_argument("--instance-id", required=True)
    result.add_argument("--instance-type", required=True)
    result.add_argument("--helper-sha256", required=True)
    result.add_argument("--profile", required=True)
    result.add_argument("--target-cpu", required=True, type=int)
    result.add_argument("--expected-manifest-sha256", required=True)
    result.add_argument("--expected-binary-sha256", required=True)
    result.add_argument("--expected-admission-receipt-sha256", required=True)
    result.add_argument("--expected-admission-evidence-sha256", required=True)
    result.add_argument("--summary-out")
    return result


def write_summary(raw_path: str, value: bytes, campaign_path: Path) -> None:
    path = Path(raw_path)
    require(path.is_absolute(), "summary output path must be absolute")
    require(not path.exists(), "summary output already exists")
    require(path.parent == Path(os.path.realpath(path.parent)), "summary parent contains symlink")
    resolved_candidate = path.parent / path.name
    require(
        campaign_path not in resolved_candidate.parents and resolved_candidate != campaign_path,
        "summary output must be outside the immutable campaign directory",
    )
    fd = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(value):
            written = os.write(fd, value[offset:])
            require(written > 0, "short summary write")
            offset += written
        os.fsync(fd)
        os.fchmod(fd, 0o444)
    finally:
        os.close(fd)


def main() -> int:
    arguments = parser().parse_args()
    identity = {
        "source_commit": require_hex(arguments.source_commit, 40, "source commit"),
        "source_tree": require_hex(arguments.source_tree, 40, "source tree"),
        "run_id": arguments.run_id,
        "instance_id": arguments.instance_id,
        "instance_type": arguments.instance_type,
        "helper_sha256": require_hex(arguments.helper_sha256, 64, "helper SHA-256"),
        "profile": arguments.profile,
        "target_cpu": arguments.target_cpu,
    }
    require(SAFE_RUN.fullmatch(identity["run_id"]) is not None, "run ID syntax is unsafe")
    require(
        SAFE_INSTANCE_ID.fullmatch(identity["instance_id"]) is not None,
        "instance ID syntax is unsafe",
    )
    require(
        SAFE_INSTANCE_TYPE.fullmatch(identity["instance_type"]) is not None,
        "instance type must be c9g.* or m9g.*",
    )
    require(identity["profile"] == PROFILE, "profile is unsupported")
    require(0 <= identity["target_cpu"] < (1 << 20), "target CPU is outside safe range")
    expected_manifest_sha256 = require_hex(
        arguments.expected_manifest_sha256, 64, "expected manifest SHA-256"
    )
    expected_binary_sha256 = require_hex(
        arguments.expected_binary_sha256, 64, "expected binary SHA-256"
    )
    expected_receipt_sha256 = require_hex(
        arguments.expected_admission_receipt_sha256,
        64,
        "expected admission receipt SHA-256",
    )
    expected_evidence_sha256 = require_hex(
        arguments.expected_admission_evidence_sha256,
        64,
        "expected admission evidence SHA-256",
    )

    campaign_path, root_fd, raw_fd, evidence_fd = open_directory(arguments.campaign_dir)
    try:
        manifest_raw = read_named(root_fd, MANIFEST_NAME, MAX_MANIFEST_BYTES, 0o444, "manifest")
        manifest_sha256 = sha256(manifest_raw)
        require(
            manifest_sha256 == expected_manifest_sha256,
            "manifest differs from the independently supplied digest",
        )
        digest_sidecar = read_named(
            root_fd, MANIFEST_SHA_NAME, 256, 0o444, "manifest digest sidecar"
        )
        require(
            digest_sidecar
            == f"{manifest_sha256}  {MANIFEST_NAME}\n".encode("ascii"),
            "manifest digest sidecar drifted",
        )
        manifest = load_canonical(manifest_raw, "manifest")
        require(
            set(manifest)
            == {
                "schema",
                "evidence_class",
                "promotion_authority",
                "runtime_authority",
                "decision",
                "identity",
                "benchmark",
                "bounds",
                "progress",
                "binary",
                "admission",
                "post_link",
                "host",
                "started_unix_ns",
                "completed_unix_ns",
                "processes",
            },
            "manifest field set changed",
        )
        for key, expected in (
            ("schema", CAMPAIGN_SCHEMA),
            ("evidence_class", EVIDENCE_CLASS),
            ("promotion_authority", AUTHORITY),
            ("runtime_authority", AUTHORITY),
            ("decision", "diagnostic-raw-evidence-only"),
        ):
            require(manifest[key] == expected, f"manifest {key} drifted")
        manifest_identity = manifest["identity"]
        require(
            type(manifest_identity) is dict
            and set(manifest_identity) == set(identity),
            "manifest identity field set changed",
        )
        for key, expected in identity.items():
            if type(expected) is int:
                integer(
                    manifest_identity[key],
                    expected,
                    expected,
                    f"manifest identity {key}",
                )
            else:
                require(
                    type(manifest_identity[key]) is str
                    and manifest_identity[key] == expected,
                    f"manifest identity {key} differs from verifier input",
                )
        started_unix_ns = integer(
            manifest["started_unix_ns"], 1, (1 << 63) - 1, "campaign start"
        )
        completed_unix_ns = integer(
            manifest["completed_unix_ns"], 1, (1 << 63) - 1, "campaign completion"
        )
        require(started_unix_ns <= completed_unix_ns, "campaign timestamps are reversed")

        benchmark = manifest["benchmark"]
        require(
            type(benchmark) is dict
            and set(benchmark)
            == {
                "schema",
                "sizes",
                "scenarios",
                "engines",
                "repetitions",
                "engine_order_rotation",
                "qualification_processes",
                "fresh_process_per_hot_cell",
                "fresh_process_per_lifecycle_cell",
                "expected_processes",
            },
            "benchmark manifest field set changed",
        )
        repetitions = integer(benchmark.get("repetitions"), 6, 96, "campaign repetitions")
        require(repetitions % 6 == 0, "repetitions are not a multiple of six")
        expected_process_count = 1 + repetitions * len(SIZES) * len(SCENARIOS) * 2
        integer(
            benchmark.get("qualification_processes"),
            1,
            1,
            "qualification process count",
        )
        integer(
            benchmark.get("expected_processes"),
            expected_process_count,
            expected_process_count,
            "expected process count",
        )
        require(
            benchmark.get("fresh_process_per_hot_cell") is True
            and benchmark.get("fresh_process_per_lifecycle_cell") is True,
            "benchmark fresh-process contract drifted",
        )
        for key, expected in (
            ("schema", BENCHMARK_SCHEMA),
            ("sizes", list(SIZES)),
            ("scenarios", list(SCENARIOS)),
            ("engines", list(ENGINES)),
            ("engine_order_rotation", "all-six-permutations-by-repetition"),
        ):
            require(benchmark.get(key) == expected, f"benchmark manifest {key} drifted")
        bounds = manifest["bounds"]
        require(
            type(bounds) is dict
            and set(bounds)
            == {
                "campaign_deadline_seconds",
                "child_timeout_seconds",
                "measurement_retries",
                "resume_supported",
                "selective_retry_supported",
                "maximum_repetitions",
                "maximum_child_output_bytes",
                "maximum_campaign_processes",
                "maximum_progress_events",
                "maximum_progress_event_bytes",
                "maximum_progress_journal_bytes",
                "owned_child_reap_seconds",
                "runner_signal_poll_milliseconds",
                "owned_child_cleanup_scope",
                "parent_death_signal",
                "handled_runner_signals",
            }
            and bounds.get("measurement_retries") == 0
            and bounds.get("resume_supported") is False
            and bounds.get("selective_retry_supported") is False
            and bounds.get("maximum_repetitions") == 96
            and bounds.get("maximum_child_output_bytes") == MAX_CHILD_OUTPUT_BYTES,
            "campaign bounds drifted",
        )
        campaign_deadline_seconds = integer(
            bounds.get("campaign_deadline_seconds"), 600, 86400, "campaign deadline"
        )
        integer(bounds.get("child_timeout_seconds"), 10, 3600, "child timeout")
        integer(
            bounds.get("owned_child_reap_seconds"),
            OWNED_CHILD_REAP_SECONDS,
            OWNED_CHILD_REAP_SECONDS,
            "owned child reap bound",
        )
        integer(
            bounds.get("runner_signal_poll_milliseconds"),
            RUNNER_SIGNAL_POLL_MILLISECONDS,
            RUNNER_SIGNAL_POLL_MILLISECONDS,
            "runner signal poll bound",
        )
        for key, expected in (
            ("measurement_retries", 0),
            ("maximum_repetitions", 96),
            ("maximum_child_output_bytes", MAX_CHILD_OUTPUT_BYTES),
            ("maximum_campaign_processes", MAX_CAMPAIGN_PROCESSES),
            ("maximum_progress_events", MAX_PROGRESS_EVENTS),
            ("maximum_progress_event_bytes", MAX_PROGRESS_EVENT_BYTES),
            ("maximum_progress_journal_bytes", MAX_PROGRESS_JOURNAL_BYTES),
        ):
            integer(bounds.get(key), expected, expected, f"campaign bound {key}")
        require(
            bounds.get("maximum_campaign_processes") == MAX_CAMPAIGN_PROCESSES
            and bounds.get("maximum_progress_events") == MAX_PROGRESS_EVENTS
            and bounds.get("maximum_progress_event_bytes")
            == MAX_PROGRESS_EVENT_BYTES
            and bounds.get("maximum_progress_journal_bytes")
            == MAX_PROGRESS_JOURNAL_BYTES
            and bounds.get("owned_child_reap_seconds")
            == OWNED_CHILD_REAP_SECONDS
            and bounds.get("runner_signal_poll_milliseconds")
            == RUNNER_SIGNAL_POLL_MILLISECONDS
            and bounds.get("owned_child_cleanup_scope")
            == "active-runner-owned-process-group-only"
            and bounds.get("parent_death_signal") == "SIGKILL"
            and bounds.get("handled_runner_signals")
            == ["SIGHUP", "SIGINT", "SIGQUIT", "SIGTERM"],
            "campaign progress or cleanup bounds drifted",
        )

        progress = manifest["progress"]
        require(
            type(progress) is dict
            and set(progress)
            == {
                "path",
                "bytes",
                "sha256",
                "mode",
                "schema",
                "events",
                "resumable",
                "selective_retry",
            },
            "progress manifest record changed",
        )
        require(
            progress["path"] == PROGRESS_NAME
            and progress["mode"] == "0444"
            and progress["schema"] == PROGRESS_SCHEMA
            and progress["resumable"] is False
            and progress["selective_retry"] is False,
            "progress manifest contract drifted",
        )
        require_hex(progress["sha256"], 64, "progress journal digest")
        progress_bytes = integer(
            progress["bytes"],
            1,
            MAX_PROGRESS_JOURNAL_BYTES,
            "progress journal byte count",
        )
        progress_event_count = integer(
            progress["events"],
            1,
            MAX_PROGRESS_EVENTS,
            "progress journal event count",
        )
        progress_raw = read_named(
            root_fd,
            PROGRESS_NAME,
            MAX_PROGRESS_JOURNAL_BYTES,
            0o444,
            "progress journal",
        )
        require(
            progress_bytes == len(progress_raw)
            and progress["sha256"] == sha256(progress_raw),
            "progress journal record drifted",
        )

        binary = manifest["binary"]
        require(
            type(binary) is dict
            and set(binary)
            == {
                "path",
                "bytes",
                "sha256",
                "mode",
                "source_path",
                "source_device",
                "source_inode",
                "source_mtime_ns",
                "post_link_observed_sha256",
            },
            "binary manifest field set changed",
        )
        binary_raw = verify_file_record(
            subset_file_record(binary),
            "evidence/benchmark.bin",
            raw_fd,
            evidence_fd,
            MAX_BINARY_BYTES,
            0o555,
            "benchmark binary",
        )
        require(bool(binary_raw), "benchmark binary is empty")
        binary_sha256 = sha256(binary_raw)
        require(binary_sha256 == expected_binary_sha256, "binary differs from verifier expectation")
        source_path = binary["source_path"]
        require(
            type(source_path) is str
            and 1 <= len(source_path) <= 4096
            and "\x00" not in source_path
            and Path(source_path).is_absolute(),
            "binary source path is malformed",
        )
        integer(
            binary["source_device"],
            0,
            (1 << 64) - 1,
            "binary source device",
        )
        integer(
            binary["source_inode"],
            0,
            (1 << 64) - 1,
            "binary source inode",
        )
        integer(
            binary["source_mtime_ns"],
            -(1 << 63),
            (1 << 63) - 1,
            "binary source modification time",
        )
        require(
            binary["post_link_observed_sha256"] == binary_sha256,
            "binary differs from recorded post-link digest",
        )

        admission_manifest = manifest["admission"]
        require(
            type(admission_manifest) is dict
            and set(admission_manifest)
            == {
                "receipt_id",
                "helper_protocol",
                "pin_set_sha256",
                "headroom_basis",
                "acquisition_attempts_used",
                "acquisition_max_attempts",
                "acquisition_deadline_unix_ns",
                "valid_from_unix_ns",
                "valid_until_unix_ns",
                "coexistence_policy",
                "other_work_kill_policy",
                "continuity_mode",
                "continuous_since_unix_ns",
                "holder_id",
                "session_id",
                "lease_epoch",
                "maximum_heartbeat_age_ns",
                "receipt",
                "receipt_sha256",
                "raw_evidence",
                "initial_heartbeat",
                "final_heartbeat",
                "initial_heartbeat_sequence",
                "final_heartbeat_sequence",
                "target_cpu",
                "runner_allowed_cpus",
                "admitted_unrelated_cpu_work_may_continue",
                "runner_never_kills_other_work",
            },
            "admission manifest field set changed",
        )
        receipt_raw = verify_file_record(
            admission_manifest["receipt"],
            "evidence/admission-receipt.json",
            raw_fd,
            evidence_fd,
            MAX_EVIDENCE_BYTES,
            0o444,
            "admission receipt",
        )
        evidence_raw = verify_file_record(
            admission_manifest["raw_evidence"],
            "evidence/admission-evidence.raw",
            raw_fd,
            evidence_fd,
            MAX_EVIDENCE_BYTES,
            0o444,
            "admission evidence",
        )
        require(bool(evidence_raw), "admission evidence is empty")
        require(sha256(receipt_raw) == expected_receipt_sha256, "receipt digest differs")
        require(sha256(evidence_raw) == expected_evidence_sha256, "evidence digest differs")
        require(
            admission_manifest.get("receipt_sha256") == expected_receipt_sha256,
            "manifest receipt digest differs",
        )
        receipt = load_canonical(receipt_raw, "admission receipt")
        admission = validate_receipt(
            receipt,
            identity,
            expected_evidence_sha256,
            started_unix_ns,
            completed_unix_ns,
        )
        require(
            admission["valid_until_unix_ns"]
            >= started_unix_ns + campaign_deadline_seconds * 1_000_000_000,
            "receipt does not cover the declared deadline from campaign start",
        )
        for key in (
            "receipt_id",
            "helper_protocol",
            "pin_set_sha256",
            "headroom_basis",
            "acquisition_attempts_used",
            "acquisition_max_attempts",
            "acquisition_deadline_unix_ns",
            "valid_from_unix_ns",
            "valid_until_unix_ns",
            "coexistence_policy",
            "other_work_kill_policy",
            "continuity_mode",
            "continuous_since_unix_ns",
            "holder_id",
            "session_id",
            "lease_epoch",
            "maximum_heartbeat_age_ns",
        ):
            actual = admission_manifest.get(key)
            expected = admission[key]
            if type(expected) is int:
                integer(
                    actual,
                    expected,
                    expected,
                    f"manifest admission {key}",
                )
            else:
                require(
                    type(actual) is str and actual == expected,
                    f"manifest admission {key} differs from receipt",
                )

        initial_heartbeat_raw = verify_file_record(
            admission_manifest["initial_heartbeat"],
            "evidence/admission-initial-heartbeat.json",
            raw_fd,
            evidence_fd,
            MAX_EVIDENCE_BYTES,
            0o444,
            "initial heartbeat",
        )
        final_heartbeat_raw = verify_file_record(
            admission_manifest["final_heartbeat"],
            "evidence/admission-final-heartbeat.json",
            raw_fd,
            evidence_fd,
            MAX_EVIDENCE_BYTES,
            0o444,
            "final heartbeat",
        )
        initial_heartbeat = validate_heartbeat(
            load_canonical(initial_heartbeat_raw, "initial heartbeat"),
            admission,
            identity,
            expected_evidence_sha256,
            started_unix_ns,
            "initial",
        )
        final_heartbeat = validate_heartbeat(
            load_canonical(final_heartbeat_raw, "final heartbeat"),
            admission,
            identity,
            expected_evidence_sha256,
            completed_unix_ns,
            "final",
        )
        initial_heartbeat_sequence = integer(
            admission_manifest["initial_heartbeat_sequence"],
            0,
            (1 << 63) - 1,
            "manifest initial heartbeat sequence",
        )
        final_heartbeat_sequence = integer(
            admission_manifest["final_heartbeat_sequence"],
            0,
            (1 << 63) - 1,
            "manifest final heartbeat sequence",
        )
        require(
            initial_heartbeat["sequence"] == initial_heartbeat_sequence
            and final_heartbeat["sequence"] == final_heartbeat_sequence,
            "manifest heartbeat sequence drifted",
        )
        require(
            final_heartbeat["sequence"] >= initial_heartbeat["sequence"]
            and final_heartbeat["observed_unix_ns"]
            >= initial_heartbeat["observed_unix_ns"],
            "campaign heartbeat chain moved backward",
        )
        integer(
            admission_manifest["target_cpu"],
            identity["target_cpu"],
            identity["target_cpu"],
            "manifest admission target CPU",
        )
        require(
            admission_manifest["admitted_unrelated_cpu_work_may_continue"] is True
            and admission_manifest["runner_never_kills_other_work"] is True,
            "manifest admission policy claims drifted",
        )
        runner_allowed_cpus = admission_manifest["runner_allowed_cpus"]
        require(
            type(runner_allowed_cpus) is list
            and runner_allowed_cpus == sorted(set(runner_allowed_cpus))
            and all(type(cpu) is int and 0 <= cpu < (1 << 20) for cpu in runner_allowed_cpus)
            and identity["target_cpu"] in runner_allowed_cpus,
            "manifest runner CPU affinity set is malformed",
        )

        post_link_manifest = manifest["post_link"]
        require(
            type(post_link_manifest) is dict
            and set(post_link_manifest)
            == {
                "observation",
                "observed_binary_sha256",
                "artifact_identity",
                "compile_identity",
                "implementation_object_identity",
                "glue_object_identity",
                "bundle_identity",
                "deployment_binding_identity",
                "deployment_receipt_identity",
                "runtime_authority",
                "promotion_authority",
            },
            "post-link manifest field set changed",
        )
        post_link_raw = verify_file_record(
            post_link_manifest["observation"],
            "evidence/post-link-observation.txt",
            raw_fd,
            evidence_fd,
            MAX_EVIDENCE_BYTES,
            0o444,
            "post-link observation",
        )
        post_link = parse_post_link(post_link_raw, identity, binary_sha256)
        for key in (
            "artifact_identity",
            "compile_identity",
            "implementation_object_identity",
            "glue_object_identity",
            "bundle_identity",
            "deployment_binding_identity",
            "deployment_receipt_identity",
        ):
            require(post_link_manifest.get(key) == post_link[key], f"post-link manifest {key} drifted")
        require(
            post_link_manifest.get("observed_binary_sha256") == binary_sha256,
            "post-link manifest binary digest drifted",
        )
        require(
            post_link_manifest.get("runtime_authority") == AUTHORITY
            and post_link_manifest.get("promotion_authority") == AUTHORITY,
            "post-link manifest acquired authority",
        )

        host = manifest["host"]
        require(
            type(host) is dict
            and set(host)
            == {
                "system",
                "machine",
                "release",
                "target_cpu",
                "runner_allowed_cpus",
                "proc_cpuinfo",
            },
            "host manifest field set changed",
        )
        require(
            type(host["system"]) is str
            and host["system"] == "Linux"
            and type(host["machine"]) is str
            and host["machine"].lower() in ("aarch64", "arm64")
            and type(host["release"]) is str
            and 1 <= len(host["release"]) <= 256
            and "\x00" not in host["release"],
            "host manifest identity drifted",
        )
        integer(
            host["target_cpu"],
            identity["target_cpu"],
            identity["target_cpu"],
            "host target CPU",
        )
        host_allowed_cpus = host["runner_allowed_cpus"]
        require(
            type(host_allowed_cpus) is list
            and all(
                type(cpu) is int and 0 <= cpu < (1 << 20)
                for cpu in host_allowed_cpus
            )
            and host_allowed_cpus == runner_allowed_cpus,
            "host runner CPU affinity set drifted",
        )
        cpuinfo_raw = verify_file_record(
            host["proc_cpuinfo"],
            "evidence/proc-cpuinfo.raw",
            raw_fd,
            evidence_fd,
            MAX_EVIDENCE_BYTES,
            0o444,
            "CPU evidence",
        )
        require_cpuinfo_d84(cpuinfo_raw)

        schedule = expected_schedule(repetitions, identity)
        processes = manifest["processes"]
        require(
            type(processes) is list and len(processes) == len(schedule),
            "manifest process list is partial",
        )
        hot: dict[tuple[str, str, int], dict[str, dict[str, int]]] = {}
        lifecycle: dict[tuple[str, str, int], dict[str, dict[str, int]]] = {}
        activation: dict[tuple[str, str, int], dict[str, int]] = {}
        raw_paths: set[str] = set()
        baseline: dict[str, str] | None = None
        previous_completed = started_unix_ns
        previous_heartbeat = initial_heartbeat
        total_runner_elapsed_ns = 0

        for sequence, (process, expected) in enumerate(zip(processes, schedule)):
            command, coordinate, command_arguments = expected
            require(
                type(process) is dict
                and set(process)
                == {
                    "sequence",
                    "command",
                    "arguments",
                    "coordinate",
                    "fresh_process",
                    "single_thread_environment",
                    "target_cpu",
                    "exit_code",
                    "started_unix_ns",
                    "completed_unix_ns",
                    "runner_elapsed_ns",
                    "admission_before",
                    "admission_after",
                    "stdout",
                    "stderr",
                },
                f"process {sequence} field set changed",
            )
            require(
                integer(
                    process["sequence"],
                    sequence,
                    sequence,
                    f"process {sequence} sequence",
                )
                == sequence,
                f"process {sequence} sequence drifted",
            )
            require(
                type(process["command"]) is str and process["command"] == command,
                f"process {sequence} command drifted",
            )
            require(
                type(process["arguments"]) is list
                and all(type(value) is str for value in process["arguments"])
                and process["arguments"] == command_arguments,
                f"process {sequence} arguments drifted",
            )
            process_coordinate = process["coordinate"]
            require(
                type(process_coordinate) is dict
                and set(process_coordinate) == set(coordinate),
                f"process {sequence} coordinate shape drifted",
            )
            for key, expected_value in coordinate.items():
                observed_value = process_coordinate[key]
                if type(expected_value) is int:
                    require(
                        integer(
                            observed_value,
                            0,
                            95,
                            f"process {sequence} coordinate {key}",
                        )
                        == expected_value,
                        f"process {sequence} coordinate {key} drifted",
                    )
                else:
                    require(
                        type(observed_value) is str
                        and observed_value == expected_value,
                        f"process {sequence} coordinate {key} drifted",
                    )
            require(
                process["fresh_process"] is True
                and process["single_thread_environment"] is True,
                f"process {sequence} execution mode drifted",
            )
            integer(
                process["target_cpu"],
                identity["target_cpu"],
                identity["target_cpu"],
                f"process {sequence} target CPU",
            )
            integer(process["exit_code"], 0, 0, f"process {sequence} exit status")
            process_started = integer(
                process["started_unix_ns"], 1, (1 << 63) - 1, f"process {sequence} start"
            )
            process_completed = integer(
                process["completed_unix_ns"],
                1,
                (1 << 63) - 1,
                f"process {sequence} completion",
            )
            runner_elapsed_ns = integer(
                process["runner_elapsed_ns"],
                1,
                (1 << 63) - 1,
                f"process {sequence} elapsed",
            )
            total_runner_elapsed_ns += runner_elapsed_ns
            require(
                total_runner_elapsed_ns
                <= campaign_deadline_seconds * 1_000_000_000,
                f"process {sequence} cumulative elapsed exceeds the campaign bound",
            )
            require(
                previous_completed <= process_started <= process_completed <= completed_unix_ns,
                f"process {sequence} timestamps overlap or escape campaign",
            )
            previous_completed = process_completed
            stem = f"{sequence:06d}-{command}"
            before_path = f"raw/{stem}.admission-before.json"
            after_path = f"raw/{stem}.admission-after.json"
            stdout_path = f"raw/{stem}.stdout"
            stderr_path = f"raw/{stem}.stderr"
            before_raw = verify_file_record(
                process["admission_before"],
                before_path,
                raw_fd,
                evidence_fd,
                MAX_EVIDENCE_BYTES,
                0o444,
                f"process {sequence} pre-heartbeat",
            )
            after_raw = verify_file_record(
                process["admission_after"],
                after_path,
                raw_fd,
                evidence_fd,
                MAX_EVIDENCE_BYTES,
                0o444,
                f"process {sequence} post-heartbeat",
            )
            before = validate_heartbeat(
                load_canonical(before_raw, f"process {sequence} pre-heartbeat"),
                admission,
                identity,
                expected_evidence_sha256,
                process_started,
                f"process {sequence} pre",
            )
            after = validate_heartbeat(
                load_canonical(after_raw, f"process {sequence} post-heartbeat"),
                admission,
                identity,
                expected_evidence_sha256,
                process_completed,
                f"process {sequence} post",
            )
            require(
                before["sequence"] >= previous_heartbeat["sequence"]
                and before["observed_unix_ns"] >= previous_heartbeat["observed_unix_ns"]
                and after["sequence"] >= before["sequence"]
                and after["observed_unix_ns"] >= before["observed_unix_ns"],
                f"process {sequence} heartbeat chain moved backward",
            )
            previous_heartbeat = after
            stdout_raw = verify_file_record(
                process["stdout"],
                stdout_path,
                raw_fd,
                evidence_fd,
                MAX_CHILD_OUTPUT_BYTES,
                0o444,
                f"process {sequence} stdout",
            )
            stderr_raw = verify_file_record(
                process["stderr"],
                stderr_path,
                raw_fd,
                evidence_fd,
                MAX_CHILD_OUTPUT_BYTES,
                0o444,
                f"process {sequence} stderr",
            )
            require(stderr_raw == b"", f"process {sequence} stderr is not empty")
            for path in (before_path, after_path, stdout_path, stderr_path):
                require(path not in raw_paths, f"duplicate raw path {path}")
                raw_paths.add(path)
            metadata, records = parse_stdout(stdout_raw, f"process {sequence}")
            metadata = validate_metadata(metadata, command, identity, baseline)
            if baseline is None:
                require(command == "qualification", "first process is not qualification")
                baseline = metadata
                validate_qualification(records, identity, baseline)
            elif command == "cell":
                key = (
                    coordinate["size"],
                    coordinate["scenario"],
                    coordinate["repetition"],
                )
                require(key not in hot, f"duplicate hot cell {key}")
                hot[key] = validate_hot(records, identity, baseline, coordinate)
            elif command == "lifecycle":
                key = (
                    coordinate["size"],
                    coordinate["scenario"],
                    coordinate["repetition"],
                )
                require(key not in lifecycle, f"duplicate lifecycle cell {key}")
                lifecycle[key], activation[key] = validate_lifecycle(
                    records, identity, baseline, coordinate
                )
            else:
                raise Refusal(f"unexpected process command {command!r}")

        progress_events = validate_progress_journal(
            progress_raw,
            schedule,
            processes,
            started_unix_ns,
            completed_unix_ns,
        )
        require(
            progress_event_count == progress_events,
            "progress manifest event count drifted",
        )
        require(baseline is not None, "qualification metadata is absent")
        require(
            final_heartbeat["sequence"] >= previous_heartbeat["sequence"]
            and final_heartbeat["observed_unix_ns"]
            >= previous_heartbeat["observed_unix_ns"],
            "final heartbeat precedes last child heartbeat",
        )
        for key in (
            "artifact_identity",
            "compile_identity",
            "implementation_object_identity",
            "glue_object_identity",
            "bundle_identity",
            "deployment_binding_identity",
            "deployment_receipt_identity",
        ):
            require(baseline[key] == post_link[key], f"qualification/post-link {key} drifted")
        expected_keys = {
            (size, scenario, repetition)
            for repetition in range(repetitions)
            for size in SIZES
            for scenario in SCENARIOS
        }
        require(set(hot) == expected_keys, "hot matrix is partial")
        require(set(lifecycle) == expected_keys, "lifecycle matrix is partial")
        require(set(activation) == expected_keys, "activation matrix is partial")
        require(
            set(os.listdir(raw_fd)) == {path.split("/", 1)[1] for path in raw_paths},
            "raw directory is partial or contains duplicate/unbound files",
        )
        expected_evidence_names = {
            "benchmark.bin",
            "admission-receipt.json",
            "admission-evidence.raw",
            "admission-initial-heartbeat.json",
            "admission-final-heartbeat.json",
            "post-link-observation.txt",
            "proc-cpuinfo.raw",
        }
        require(
            set(os.listdir(evidence_fd)) == expected_evidence_names,
            "evidence directory is partial or contains unbound files",
        )

        summary = build_summary(
            identity,
            manifest_sha256,
            binary_sha256,
            expected_receipt_sha256,
            expected_evidence_sha256,
            hot,
            lifecycle,
            activation,
        )
        summary_raw = canonical_json(summary)
        if arguments.summary_out:
            write_summary(arguments.summary_out, summary_raw, campaign_path)
        else:
            sys.stdout.buffer.write(summary_raw)
        return 0
    finally:
        os.close(evidence_fd)
        os.close(raw_fd)
        os.close(root_fd)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Refusal as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        raise SystemExit(1) from error
