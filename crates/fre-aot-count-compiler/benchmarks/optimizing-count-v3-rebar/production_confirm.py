#!/usr/bin/env python3
"""Bounded post-promotion confirmation for the production Count-v3 runner.

The timing wrapper is an argv prefix, not an admission probe.  Every
correctness or measurement runner is a child of that wrapper for its complete
lifetime.  A wrapper denial (exit 75) is journaled and returned immediately;
the controller never waits for an idle host or signals unrelated work.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


PLAN_SCHEMA = "fre.optimizing-count-v3.production-confirmation-plan.v1"
PROMOTION_PROPOSAL_SCHEMA = "fre.optimizing-count-v3.promotion-proposal.v3"
PROMOTION_MANIFEST_SCHEMA = "fre.optimizing-count-v3.promotion-manifest.v1"
QUALIFIED_TUPLE_SET_SCHEMA = (
    "fre.optimizing-count-v3.qualified-eligibility-tuples.v1"
)
REGISTRY_SCHEMA = (
    "fre.optimizing-count-v3.production-confirmation-artifact-registry.v1"
)
REQUEST_SCHEMA = (
    "fre.optimizing-count-v3.production-confirmation-runner-request.v1"
)
AUTHORIZATION_SCHEMA = "fre.optimizing-count-v3.production-authorization.v1"
OBSERVATION_SCHEMA = (
    "fre.optimizing-count-v3.production-confirmation-observation.v1"
)
SUMMARY_PAYLOAD_SCHEMA = (
    "fre.optimizing-count-v3.production-confirmation-summary-payload.v1"
)
SEALED_SUMMARY_SCHEMA = (
    "fre.optimizing-count-v3.production-confirmation-sealed-summary.v1"
)
JOURNAL_LAUNCH_SCHEMA = (
    "fre.optimizing-count-v3.production-confirmation-launch.v1"
)
JOURNAL_RESULT_SCHEMA = (
    "fre.optimizing-count-v3.production-confirmation-result.v1"
)

ENGINES = ("portable-current", "count-v2-current", "count-v3-aot")
ORDERS = (
    ENGINES,
    ("portable-current", "count-v3-aot", "count-v2-current"),
    ("count-v2-current", "portable-current", "count-v3-aot"),
    ("count-v2-current", "count-v3-aot", "portable-current"),
    ("count-v3-aot", "portable-current", "count-v2-current"),
    ("count-v3-aot", "count-v2-current", "portable-current"),
)
TEMPORARY_UNAVAILABLE = 75
MINIMUM_AOT_BYTES = 4_096
MINIMUM_REPETITIONS = 30
MAXIMUM_REPETITIONS = 60
MINIMUM_SAMPLE_NS = 1_000_000_000
MAXIMUM_SAMPLE_NS = 120_000_000_000
MAXIMUM_CELLS = 1_024
MAXIMUM_PROCESS_OUTPUT_BYTES = 1_048_576
MAXIMUM_PLAN_BYTES = 4 * 1_048_576
MAXIMUM_PROMOTION_BYTES = 64 * 1_048_576
MAXIMUM_JOURNAL_BYTES = 512 * 1_048_576
MAXIMUM_RUNNER_BYTES = 512 * 1_048_576
MAXIMUM_WRAPPER_BYTES = 32 * 1_048_576
MAXIMUM_DENIALS_PER_ITEM = 256
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,95}$")
RESULT_DOMAIN = b"fre.optimizing-count-v3.production-confirmation.result.v1\0"
WORK_DOMAIN = b"fre.optimizing-count-v3.production-confirmation.work.v1\0"
LONG_SCAN_POLICY = "minimum-haystack-4096-bytes-v1"
TIMING_WRAPPER_CONTRACT = "full-lifetime-holder-no-child-on-exit-75-v1"
GENERAL_ELIGIBILITY_FIELDS = (
    "compiler_version",
    "metadata_version",
    "image_schema_version",
    "backend_version",
    "algorithm_version",
    "auditor_version",
    "kir_semantics_version",
    "kir_abi_version",
    "recipe_schema_version",
    "optimizer_version",
    "tuning_class_id",
    "strategy_id",
    "schedule_id",
    "register_plan_id",
    "literal_bytes",
    "filter_len",
    "sparse_group_count",
    "match_stride",
    "periodic_stride",
    "call_abi_schema",
    "abi_kind",
    "status_bits",
    "output_kind",
    "architecture",
    "little_endian",
    "pointer_width",
    "target_abi",
    "object_format",
    "required_isa_id",
    "actual_features",
    "allowed_features",
    "candidate_block_starts",
    "vector_bytes",
    "sve_vector_length_bytes",
    "max_literal_bytes",
)
COUNT_V3_ASIMD_FEATURE = 1
COUNT_V3_SVE_FEATURE = 1 << 1
COUNT_V3_SVE2_FEATURE = 1 << 2
COUNT_V3_CLOSED_TARGETS = {
    # required_isa_id: (register_plan_id, exact features, exact SVE VL,
    #                   admitted object-format wire IDs)
    1: (1, COUNT_V3_ASIMD_FEATURE, 0, frozenset((1, 2))),
    2: (
        4,
        COUNT_V3_ASIMD_FEATURE | COUNT_V3_SVE_FEATURE,
        16,
        frozenset((2,)),
    ),
    3: (
        5,
        COUNT_V3_ASIMD_FEATURE | COUNT_V3_SVE_FEATURE | COUNT_V3_SVE2_FEATURE,
        16,
        frozenset((2,)),
    ),
}


class ConfirmationError(RuntimeError):
    """One fail-closed controller refusal."""


def fail(message: str) -> None:
    raise ConfirmationError(message)


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def decode_json(bytes_value: bytes, label: str) -> Any:
    try:
        return json.loads(
            bytes_value,
            object_pairs_hook=reject_duplicate_pairs,
            parse_constant=lambda token: fail(f"{label} has nonfinite {token}"),
        )
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        fail(f"{label} is not strict UTF-8 JSON: {error}")


def exact_keys(value: Mapping[str, Any], expected: Iterable[str], label: str) -> None:
    expected_set = set(expected)
    if set(value) != expected_set:
        fail(f"{label} fields differ from the closed schema")


def require_object(value: Any, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        fail(f"{label} is not an object")
    return value


def require_list(value: Any, label: str, maximum: int) -> list[Any]:
    if type(value) is not list or not value or len(value) > maximum:
        fail(f"{label} is empty, not a list, or exceeds {maximum}")
    return value


def require_string(value: Any, label: str, pattern: re.Pattern[str] | None = None) -> str:
    if type(value) is not str or not value or "\x00" in value:
        fail(f"{label} is not a nonempty NUL-free string")
    if pattern is not None and pattern.fullmatch(value) is None:
        fail(f"{label} is not canonical")
    return value


def require_uint(value: Any, minimum: int, maximum: int, label: str) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        fail(f"{label} is outside [{minimum}, {maximum}]")
    return value


def _load_canonical_json(path: Path, maximum: int, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        before = path.lstat()
    except OSError as error:
        fail(f"stat {label}: {error}")
    if (
        path.is_symlink()
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size < 2
        or before.st_size > maximum
    ):
        fail(f"{label} is not one bounded regular file")
    try:
        bytes_value = path.read_bytes()
        after = path.stat()
    except OSError as error:
        fail(f"read {label}: {error}")
    if (
        len(bytes_value) != before.st_size
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    ):
        fail(f"{label} changed while reading")
    value = require_object(decode_json(bytes_value, label), label)
    if canonical_json_bytes(value) != bytes_value:
        fail(f"{label} is not exact compact sorted canonical JSON")
    return value, bytes_value


def _load_canonical_json_file(
    path: Path, maximum: int, label: str
) -> tuple[dict[str, Any], bytes]:
    try:
        before = path.lstat()
    except OSError as error:
        fail(f"stat {label}: {error}")
    if (
        path.is_symlink()
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size < 3
        or before.st_size > maximum
    ):
        fail(f"{label} is not one bounded regular file")
    try:
        bytes_value = path.read_bytes()
        after = path.stat()
    except OSError as error:
        fail(f"read {label}: {error}")
    if (
        len(bytes_value) != before.st_size
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    ):
        fail(f"{label} changed while reading")
    if not bytes_value.endswith(b"\n") or bytes_value[:-1].find(b"\n") >= 0:
        fail(f"{label} is not one LF-terminated canonical JSON object")
    value = require_object(decode_json(bytes_value[:-1], label), label)
    if canonical_json_bytes(value) + b"\n" != bytes_value:
        fail(f"{label} is not exact compact sorted canonical JSON plus LF")
    return value, bytes_value


def _canonical_absolute_path(raw_path: Any, label: str) -> Path:
    path = Path(require_string(raw_path, label))
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        fail(f"resolve {label}: {error}")
    if not path.is_absolute() or resolved != path:
        fail(f"{label} is not absolute and canonical")
    return path


def _seal_executable(
    raw_path: Any,
    expected_sha256: Any,
    maximum: int,
    label: str,
) -> dict[str, Any]:
    path_text = require_string(raw_path, f"{label} path")
    expected = require_string(expected_sha256, f"{label} SHA-256", HEX64)
    path = Path(path_text)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        fail(f"{label} path is not absolute and canonical")
    before = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size < 1
        or before.st_size > maximum
        or before.st_mode & 0o222
        or not before.st_mode & 0o111
    ):
        fail(f"{label} is not a sealed executable regular file")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        opened = os.fstat(source.fileno())
        while chunk := source.read(1 << 20):
            digest.update(chunk)
        final = os.fstat(source.fileno())
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    if identity != (
        opened.st_dev,
        opened.st_ino,
        opened.st_size,
        opened.st_mtime_ns,
    ) or identity != (
        final.st_dev,
        final.st_ino,
        final.st_size,
        final.st_mtime_ns,
    ):
        fail(f"{label} changed while hashing")
    if digest.hexdigest() != expected:
        fail(f"{label} digest differs from the plan")
    return {"path": path, "identity": identity, "sha256": expected}


def _recheck_executable(seal: Mapping[str, Any], label: str) -> None:
    path = seal["path"]
    try:
        current = path.lstat()
    except OSError as error:
        fail(f"restat {label}: {error}")
    if (
        path.is_symlink()
        or not stat.S_ISREG(current.st_mode)
        or current.st_nlink != 1
        or current.st_mode & 0o222
        or not current.st_mode & 0o111
        or (
            current.st_dev,
            current.st_ino,
            current.st_size,
            current.st_mtime_ns,
        )
        != seal["identity"]
    ):
        fail(f"{label} seal changed before launch")


def validate_plan(value: dict[str, Any]) -> dict[str, Any]:
    exact_keys(
        value,
        {
            "cells",
            "haystack_dir",
            "minimum_elapsed_ns",
            "promotion",
            "repetitions",
            "runner",
            "schema",
            "target_contract_sha256",
            "target_id",
            "timing_wrapper",
        },
        "plan",
    )
    if value["schema"] != PLAN_SCHEMA:
        fail("plan schema differs")
    target_id = require_string(value["target_id"], "target ID", SAFE_ID)
    target_contract = require_string(
        value["target_contract_sha256"], "target contract SHA-256", HEX64
    )
    repetitions = require_uint(
        value["repetitions"],
        MINIMUM_REPETITIONS,
        MAXIMUM_REPETITIONS,
        "repetitions",
    )
    if repetitions % len(ORDERS) != 0:
        fail("repetitions must contain complete six-order rotations")
    minimum_elapsed_ns = require_uint(
        value["minimum_elapsed_ns"],
        MINIMUM_SAMPLE_NS,
        MAXIMUM_SAMPLE_NS,
        "minimum elapsed nanoseconds",
    )

    runner = require_object(value["runner"], "runner")
    exact_keys(
        runner,
        {"path", "registry_sha256", "sha256", "timeout_seconds"},
        "runner",
    )
    runner_path = require_string(runner["path"], "runner path")
    runner_sha256 = require_string(runner["sha256"], "runner SHA-256", HEX64)
    registry_sha256 = require_string(
        runner["registry_sha256"], "runner registry SHA-256", HEX64
    )
    timeout_seconds = require_uint(
        runner["timeout_seconds"], 2, 3_600, "runner timeout seconds"
    )
    if timeout_seconds * 1_000_000_000 <= minimum_elapsed_ns:
        fail("runner timeout must exceed the retained minimum elapsed time")

    promotion = require_object(value["promotion"], "promotion")
    exact_keys(
        promotion,
        {
            "manifest_path",
            "manifest_sha256",
            "proposal_path",
            "proposal_sha256",
        },
        "promotion",
    )
    proposal_path = _canonical_absolute_path(
        promotion["proposal_path"], "promotion proposal path"
    )
    manifest_path = _canonical_absolute_path(
        promotion["manifest_path"], "promotion manifest path"
    )
    proposal_sha256 = require_string(
        promotion["proposal_sha256"], "promotion proposal SHA-256", HEX64
    )
    manifest_sha256 = require_string(
        promotion["manifest_sha256"], "promotion manifest SHA-256", HEX64
    )
    if proposal_path == manifest_path:
        fail("promotion proposal and manifest paths are not distinct")

    wrapper = require_object(value["timing_wrapper"], "timing wrapper")
    exact_keys(
        wrapper,
        {"argv", "contract", "executable_sha256"},
        "timing wrapper",
    )
    if wrapper["contract"] != TIMING_WRAPPER_CONTRACT:
        fail("timing-wrapper contract differs from the no-child-on-75 protocol")
    argv = require_list(wrapper["argv"], "timing-wrapper argv", 64)
    normalized_argv = []
    for ordinal, argument in enumerate(argv):
        argument = require_string(argument, f"timing-wrapper argv[{ordinal}]")
        if len(argument.encode("utf-8")) > 4_096:
            fail("timing-wrapper argument exceeds 4096 UTF-8 bytes")
        normalized_argv.append(argument)
    wrapper_sha256 = require_string(
        wrapper["executable_sha256"], "timing-wrapper executable SHA-256", HEX64
    )

    haystack_text = require_string(value["haystack_dir"], "haystack directory")
    haystack_dir = Path(haystack_text)
    if (
        not haystack_dir.is_absolute()
        or haystack_dir.resolve(strict=True) != haystack_dir
        or haystack_dir.is_symlink()
        or not haystack_dir.is_dir()
    ):
        fail("haystack directory is not one absolute canonical real directory")

    cells = require_list(value["cells"], "plan cells", MAXIMUM_CELLS)
    normalized_cells = []
    previous = ""
    for ordinal, raw in enumerate(cells):
        row = require_object(raw, f"plan cells[{ordinal}]")
        exact_keys(row, {"cell_id", "iterations"}, f"plan cells[{ordinal}]")
        cell_id = require_string(row["cell_id"], f"plan cells[{ordinal}].cell_id", SAFE_ID)
        if cell_id <= previous:
            fail("plan cells are not in canonical unique cell-ID order")
        previous = cell_id
        normalized_cells.append(
            {
                "cell_id": cell_id,
                "iterations": require_uint(
                    row["iterations"],
                    1,
                    (1 << 32) - 1,
                    f"plan cells[{ordinal}].iterations",
                ),
            }
        )
    return {
        "target_id": target_id,
        "target_contract_sha256": target_contract,
        "repetitions": repetitions,
        "minimum_elapsed_ns": minimum_elapsed_ns,
        "runner": {
            "path": runner_path,
            "sha256": runner_sha256,
            "registry_sha256": registry_sha256,
            "timeout_seconds": timeout_seconds,
        },
        "timing_wrapper": {
            "argv": normalized_argv,
            "contract": TIMING_WRAPPER_CONTRACT,
            "executable_sha256": wrapper_sha256,
        },
        "promotion": {
            "manifest_path": manifest_path,
            "manifest_sha256": manifest_sha256,
            "proposal_path": proposal_path,
            "proposal_sha256": proposal_sha256,
        },
        "haystack_dir": haystack_dir,
        "cells": normalized_cells,
    }


def _run_bounded(
    argv: Sequence[str],
    input_bytes: bytes,
    timeout_seconds: int,
    environment: Mapping[str, str],
) -> tuple[int, bytes, bytes]:
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(
            list(argv),
            stdin=subprocess.PIPE,
            stdout=stdout,
            stderr=stderr,
            env=dict(environment),
            shell=False,
            close_fds=True,
            start_new_session=True,
        )
        try:
            process.communicate(input=input_bytes, timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            # This process group contains only the wrapper and descendants
            # launched by this controller. Unrelated host work is never touched.
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise
        stdout.flush()
        stderr.flush()
        if (
            stdout.tell() > MAXIMUM_PROCESS_OUTPUT_BYTES
            or stderr.tell() > MAXIMUM_PROCESS_OUTPUT_BYTES
        ):
            fail("child output exceeds the bounded protocol")
        stdout.seek(0)
        stderr.seek(0)
        return process.returncode, stdout.read(), stderr.read()


def _one_json_line(bytes_value: bytes, label: str) -> dict[str, Any]:
    if not bytes_value.endswith(b"\n") or bytes_value[:-1].find(b"\n") >= 0:
        fail(f"{label} is not exactly one LF-terminated JSON object")
    return require_object(decode_json(bytes_value[:-1], label), label)


def _validate_eligibility_tuple(value: Any, label: str) -> dict[str, Any]:
    row = require_object(value, label)
    exact_keys(row, GENERAL_ELIGIBILITY_FIELDS, label)
    for field in GENERAL_ELIGIBILITY_FIELDS:
        if field == "little_endian":
            if row[field] is not True:
                fail(f"{label}.little_endian is not true")
        elif type(row[field]) is not int or not 0 <= row[field] <= (1 << 64) - 1:
            fail(f"{label}.{field} is not a canonical unsigned integer")
    if not 1 <= row["literal_bytes"] <= 32:
        fail(f"{label}.literal_bytes is outside the Count-v3 bound")
    if not 1 <= row["max_literal_bytes"] <= (1 << 16) - 1:
        fail(f"{label}.max_literal_bytes is outside the Count-v3 bound")
    if row["literal_bytes"] > row["max_literal_bytes"]:
        fail(f"{label} literal width exceeds max_literal_bytes")
    if row["actual_features"] & ~row["allowed_features"]:
        fail(f"{label}.actual_features escapes allowed_features")
    target = COUNT_V3_CLOSED_TARGETS.get(row["required_isa_id"])
    if target is None:
        fail(f"{label}.required_isa_id is not a closed Count-v3 target")
    register_plan_id, features, sve_vector_bytes, object_formats = target
    if (
        row["register_plan_id"] != register_plan_id
        or row["actual_features"] != features
        or row["allowed_features"] != features
        or row["object_format"] not in object_formats
        or row["architecture"] != 1
        or row["pointer_width"] != 64
        or row["target_abi"] != 1
        or row["candidate_block_starts"] != 16
        or row["vector_bytes"] != 16
        or row["sve_vector_length_bytes"] != sve_vector_bytes
        or row["max_literal_bytes"] != 32
    ):
        fail(f"{label} differs from its exact mixed register/feature target")
    return dict(row)


def _validated_qualified_target(
    raw: Any, label: str
) -> tuple[dict[str, Any], dict[bytes, dict[str, Any]]]:
    target = require_object(raw, label)
    exact_keys(
        target,
        {
            "evaluated_class_manifest_sha256",
            "evaluated_classes",
            "evaluated_families",
            "qualified_classes",
            "qualified_families",
            "rejected_classes",
            "rejected_families",
            "target_id",
            "target_receipt_sha256",
        },
        label,
    )
    require_string(target["target_id"], f"{label}.target_id", SAFE_ID)
    require_string(
        target["target_receipt_sha256"],
        f"{label}.target_receipt_sha256",
        HEX64,
    )
    require_string(
        target["evaluated_class_manifest_sha256"],
        f"{label}.evaluated_class_manifest_sha256",
        HEX64,
    )
    classes = require_list(
        target["qualified_classes"], f"{label}.qualified_classes", 65_536
    )
    qualified: dict[bytes, dict[str, Any]] = {}
    for ordinal, raw_class in enumerate(classes):
        class_label = f"{label}.qualified_classes[{ordinal}]"
        result = require_object(raw_class, class_label)
        exact_keys(
            result,
            {
                "exact_tuple_gate_result",
                "family_gate_result",
                "general_eligibility_tuple",
                "scan_generalization_family",
                "state",
            },
            class_label,
        )
        exact_gate = require_object(
            result["exact_tuple_gate_result"],
            f"{class_label}.exact_tuple_gate_result",
        )
        family_gate = require_object(
            result["family_gate_result"],
            f"{class_label}.family_gate_result",
        )
        require_object(
            result["scan_generalization_family"],
            f"{class_label}.scan_generalization_family",
        )
        if (
            result["state"] != "pass"
            or exact_gate.get("state") != "pass"
            or family_gate.get("state") != "pass"
        ):
            fail(f"{class_label} is not an explicit exact-and-family pass")
        eligibility = _validate_eligibility_tuple(
            result["general_eligibility_tuple"],
            f"{class_label}.general_eligibility_tuple",
        )
        encoded = canonical_json_bytes(eligibility)
        if encoded in qualified:
            fail(f"{label} repeats a qualified eligibility tuple")
        qualified[encoded] = eligibility
    evaluated_classes = require_uint(
        target["evaluated_classes"], 1, 65_536, f"{label}.evaluated_classes"
    )
    rejected_classes = require_uint(
        target["rejected_classes"], 0, 65_536, f"{label}.rejected_classes"
    )
    qualified_families = require_uint(
        target["qualified_families"], 1, 65_536, f"{label}.qualified_families"
    )
    rejected_families = require_uint(
        target["rejected_families"], 0, 65_536, f"{label}.rejected_families"
    )
    evaluated_families = require_uint(
        target["evaluated_families"], 1, 65_536, f"{label}.evaluated_families"
    )
    if evaluated_classes != len(classes) + rejected_classes:
        fail(f"{label} class counts do not close")
    if evaluated_families != qualified_families + rejected_families:
        fail(f"{label} family counts do not close")
    return dict(target), qualified


def load_promotion(
    plan: Mapping[str, Any], registry: Mapping[str, Any]
) -> dict[str, Any]:
    proposal, proposal_bytes = _load_canonical_json_file(
        plan["promotion"]["proposal_path"],
        MAXIMUM_PROMOTION_BYTES,
        "promotion proposal",
    )
    manifest, manifest_bytes = _load_canonical_json_file(
        plan["promotion"]["manifest_path"],
        MAXIMUM_PROMOTION_BYTES,
        "promotion manifest",
    )
    if sha256_bytes(proposal_bytes) != plan["promotion"]["proposal_sha256"]:
        fail("promotion proposal digest differs from the plan")
    if sha256_bytes(manifest_bytes) != plan["promotion"]["manifest_sha256"]:
        fail("promotion manifest digest differs from the plan")

    exact_keys(
        proposal,
        {
            "class_gate_policy",
            "long_scan_policy",
            "production_authority",
            "qualification_id",
            "qualification_state",
            "scan_generalization_family_policy",
            "schema",
            "spec_sha256",
            "targets",
        },
        "promotion proposal",
    )
    qualification_id = require_string(
        proposal["qualification_id"], "promotion qualification ID", SAFE_ID
    )
    spec_sha256 = require_string(
        proposal["spec_sha256"], "promotion spec SHA-256", HEX64
    )
    if (
        proposal["schema"] != PROMOTION_PROPOSAL_SCHEMA
        or proposal["qualification_state"] != "candidate"
        or proposal["production_authority"] != "absent"
        or proposal["long_scan_policy"] != LONG_SCAN_POLICY
    ):
        fail("promotion proposal is not the closed review-only long-scan candidate")
    require_object(proposal["class_gate_policy"], "proposal class-gate policy")
    require_object(
        proposal["scan_generalization_family_policy"],
        "proposal scan-generalization-family policy",
    )
    proposal_targets: dict[str, dict[str, Any]] = {}
    target_tuples: dict[str, dict[bytes, dict[str, Any]]] = {}
    all_proposal_tuples: dict[bytes, dict[str, Any]] = {}
    previous_target = ""
    for ordinal, raw_target in enumerate(
        require_list(proposal["targets"], "proposal targets", 256)
    ):
        target, qualified = _validated_qualified_target(
            raw_target, f"proposal targets[{ordinal}]"
        )
        target_id = target["target_id"]
        if target_id <= previous_target or target_id in proposal_targets:
            fail("proposal targets are not in canonical unique target-ID order")
        previous_target = target_id
        proposal_targets[target_id] = target
        target_tuples[target_id] = qualified
        all_proposal_tuples.update(qualified)
    target_id = plan["target_id"]
    if target_id not in proposal_targets:
        fail("plan target has no qualified promotion-proposal target")

    exact_keys(
        manifest,
        {
            "bundle",
            "long_scan_policy",
            "production_authority",
            "qualification_id",
            "qualified_tuple_set",
            "schema",
            "source_freeze",
            "toolchain",
            "trusted_spec",
            "verifier_projection",
        },
        "promotion manifest",
    )
    if (
        manifest["schema"] != PROMOTION_MANIFEST_SCHEMA
        or manifest["qualification_id"] != qualification_id
        or manifest["production_authority"] != "absent"
        or manifest["long_scan_policy"] != LONG_SCAN_POLICY
    ):
        fail("promotion manifest identity or review-only authority differs")
    trusted_spec = require_object(manifest["trusted_spec"], "manifest trusted spec")
    exact_keys(trusted_spec, {"bytes", "sha256"}, "manifest trusted spec")
    require_uint(
        trusted_spec["bytes"], 1, MAXIMUM_PROMOTION_BYTES, "trusted spec bytes"
    )
    if require_string(
        trusted_spec["sha256"], "manifest trusted-spec SHA-256", HEX64
    ) != spec_sha256:
        fail("proposal spec digest differs from the manifest trust anchor")

    projection = require_object(
        manifest["verifier_projection"], "manifest verifier projection"
    )
    exact_keys(
        projection,
        {
            "bytes",
            "class_gate_policy",
            "file",
            "scan_generalization_family_policy",
            "schema",
            "sha256",
            "targets",
        },
        "manifest verifier projection",
    )
    if (
        projection["schema"] != PROMOTION_PROPOSAL_SCHEMA
        or projection["file"] != "promotion-proposal.json"
        or projection["bytes"] != len(proposal_bytes)
        or projection["sha256"] != plan["promotion"]["proposal_sha256"]
        or projection["class_gate_policy"] != proposal["class_gate_policy"]
        or projection["scan_generalization_family_policy"]
        != proposal["scan_generalization_family_policy"]
    ):
        fail("manifest verifier projection differs from the authenticated proposal")
    projected_targets = require_list(
        projection["targets"], "manifest projected targets", 256
    )
    if len(projected_targets) != len(proposal_targets):
        fail("manifest and proposal target counts differ")
    target_artifact_registry_sha256 = ""
    projected_ids: list[str] = []
    for ordinal, raw_target in enumerate(projected_targets):
        projected = require_object(
            raw_target, f"manifest projected targets[{ordinal}]"
        )
        expected_fields = set(proposal_targets[next(iter(proposal_targets))])
        exact_keys(
            projected,
            expected_fields | {"artifact_registry_sha256"},
            f"manifest projected targets[{ordinal}]",
        )
        projected_id = require_string(
            projected["target_id"], "manifest projected target ID", SAFE_ID
        )
        if projected_id not in proposal_targets:
            fail("manifest projection contains an unknown target")
        projected_ids.append(projected_id)
        projected_copy = dict(projected)
        artifact_registry_sha256 = require_string(
            projected_copy.pop("artifact_registry_sha256"),
            "qualification artifact-registry SHA-256",
            HEX64,
        )
        if projected_copy != proposal_targets[projected_id]:
            fail("manifest target projection differs from the proposal target")
        if projected_id == target_id:
            target_artifact_registry_sha256 = artifact_registry_sha256
    if projected_ids != list(proposal_targets):
        fail("manifest projected targets are not the proposal target sequence")
    if not target_artifact_registry_sha256:
        fail("manifest lacks the selected target projection")

    tuple_set = require_object(
        manifest["qualified_tuple_set"], "manifest qualified tuple set"
    )
    exact_keys(
        tuple_set,
        {"count", "schema", "sha256", "sort", "tuples"},
        "manifest qualified tuple set",
    )
    raw_tuples = require_list(
        tuple_set["tuples"], "manifest qualified tuples", 65_536
    )
    manifest_tuples: dict[bytes, dict[str, Any]] = {}
    encoded_order: list[bytes] = []
    for ordinal, raw_tuple in enumerate(raw_tuples):
        eligibility = _validate_eligibility_tuple(
            raw_tuple, f"manifest qualified tuples[{ordinal}]"
        )
        encoded = canonical_json_bytes(eligibility)
        if encoded in manifest_tuples:
            fail("manifest repeats a qualified tuple")
        encoded_order.append(encoded)
        manifest_tuples[encoded] = eligibility
    tuple_payload = {
        "schema": QUALIFIED_TUPLE_SET_SCHEMA,
        "sort": "canonical-json-bytes-v1",
        "tuples": raw_tuples,
    }
    if (
        tuple_set["schema"] != QUALIFIED_TUPLE_SET_SCHEMA
        or tuple_set["sort"] != "canonical-json-bytes-v1"
        or require_uint(
            tuple_set["count"], 1, 65_536, "manifest qualified tuple count"
        )
        != len(raw_tuples)
        or require_string(
            tuple_set["sha256"], "manifest qualified tuple-set SHA-256", HEX64
        )
        != sha256_bytes(canonical_json_bytes(tuple_payload))
        or encoded_order != sorted(encoded_order)
        or set(manifest_tuples) != set(all_proposal_tuples)
    ):
        fail("manifest qualified tuple-set closure differs from the proposal")

    for field, expected in [
        ("promotion_manifest_sha256", plan["promotion"]["manifest_sha256"]),
        ("promotion_proposal_sha256", plan["promotion"]["proposal_sha256"]),
    ]:
        if require_string(registry.get(field), f"registry {field}", HEX64) != expected:
            fail(f"production registry {field} differs from the plan")
    authority_source_sha256 = require_string(
        registry.get("promotion_authority_source_sha256"),
        "registry promotion authority source SHA-256",
        HEX64,
    )
    return {
        "authority_source_sha256": authority_source_sha256,
        "manifest_sha256": plan["promotion"]["manifest_sha256"],
        "proposal_sha256": plan["promotion"]["proposal_sha256"],
        "qualification_artifact_registry_sha256": (
            target_artifact_registry_sha256
        ),
        "qualification_id": qualification_id,
        "qualified_target_tuples": target_tuples[target_id],
        "spec_sha256": spec_sha256,
    }


def load_registry(
    plan: Mapping[str, Any],
    runner_seal: Mapping[str, Any],
    environment: Mapping[str, str],
) -> dict[str, Any]:
    _recheck_executable(runner_seal, "runner")
    try:
        returncode, stdout, stderr = _run_bounded(
            [str(runner_seal["path"]), "inventory"],
            b"",
            plan["runner"]["timeout_seconds"],
            environment,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        fail(f"inventory runner failed: {error}")
    if returncode != 0 or stderr:
        fail(f"inventory runner exited {returncode} or wrote stderr")
    registry = _one_json_line(stdout, "production registry")
    registry_bytes = stdout[:-1]
    if sha256_bytes(registry_bytes) != plan["runner"]["registry_sha256"]:
        fail("production registry digest differs from the plan")
    if canonical_json_bytes(registry) != registry_bytes:
        fail("production registry is not compact sorted canonical JSON")
    exact_keys(
        registry,
        {
            "artifact_root",
            "artifacts",
            "build_authority",
            "cells",
            "compiled_patterns",
            "distinct_artifacts",
            "input_policy",
            "inventory_identity",
            "inventory_sha256",
            "object_format",
            "production_authority",
            "promotion_authority_source_sha256",
            "promotion_manifest_sha256",
            "promotion_proposal_sha256",
            "qualification_authority",
            "required_isa",
            "schema",
            "source",
            "target_contract_sha256",
            "target_id",
            "target_triple",
            "tuning_class",
        },
        "production registry",
    )
    if (
        registry["schema"] != REGISTRY_SCHEMA
        or registry["build_authority"] != "production"
        or registry["production_authority"] != "source-reviewed-tuples-required"
        or registry["qualification_authority"] != "absent"
        or registry["target_id"] != plan["target_id"]
        or registry["target_contract_sha256"] != plan["target_contract_sha256"]
    ):
        fail("production registry authority or target binding differs")
    return registry


def index_registry(
    registry: Mapping[str, Any],
    selected: Sequence[Mapping[str, Any]],
    qualified_target_tuples: Mapping[bytes, Mapping[str, Any]],
) -> tuple[dict[str, dict[str, Any]], dict[tuple[str, str], dict[str, Any]]]:
    raw_cells = require_list(registry["cells"], "registry cells", 16_384)
    cells: dict[str, dict[str, Any]] = {}
    previous = ""
    for ordinal, raw in enumerate(raw_cells):
        row = require_object(raw, f"registry cells[{ordinal}]")
        exact_keys(
            row,
            {
                "cell_id",
                "expected_count",
                "input_bytes",
                "input_sha256",
                "oracle_receipt_sha256",
                "pattern_input_id",
                "pattern_sha256",
            },
            f"registry cells[{ordinal}]",
        )
        cell_id = require_string(row["cell_id"], "registry cell ID", SAFE_ID)
        if cell_id <= previous or cell_id in cells:
            fail("registry cells are not canonically ordered and unique")
        previous = cell_id
        normalized = {
            "cell_id": cell_id,
            "expected_count": require_uint(
                row["expected_count"], 0, (1 << 64) - 1, "expected count"
            ),
            "input_bytes": require_uint(
                row["input_bytes"], MINIMUM_AOT_BYTES, 1 << 40, "input bytes"
            ),
            "input_sha256": require_string(
                row["input_sha256"], "input SHA-256", HEX64
            ),
            "oracle_receipt_sha256": require_string(
                row["oracle_receipt_sha256"], "oracle receipt SHA-256", HEX64
            ),
            "pattern_input_id": require_string(
                row["pattern_input_id"], "pattern input ID", SAFE_ID
            ),
            "pattern_sha256": require_string(
                row["pattern_sha256"], "pattern SHA-256", HEX64
            ),
        }
        cells[cell_id] = normalized

    selected_ids = {row["cell_id"] for row in selected}
    if len(selected_ids) != len(selected) or not selected_ids.issubset(cells):
        fail("plan cell selection is duplicated or escapes the production registry")
    cells = {cell_id: cells[cell_id] for cell_id in sorted(selected_ids)}

    artifacts: dict[tuple[str, str], dict[str, Any]] = {}
    for ordinal, raw in enumerate(
        require_list(registry["artifacts"], "registry artifacts", 49_152)
    ):
        row = require_object(raw, f"registry artifacts[{ordinal}]")
        exact_keys(
            row,
            {
                "artifact_file_path",
                "artifact_file_sha256",
                "artifact_id",
                "engine",
                "metadata_sha256",
                "pattern_sha256",
                "payload_sha256",
            },
            f"registry artifacts[{ordinal}]",
        )
        engine = require_string(row["engine"], "artifact engine")
        pattern = require_string(row["pattern_sha256"], "artifact pattern", HEX64)
        if engine not in ENGINES:
            fail("registry artifact has an unknown engine")
        key = (pattern, engine)
        if key in artifacts:
            fail("registry artifact matrix has a duplicate")
        artifacts[key] = {
            "artifact_id": require_string(row["artifact_id"], "artifact ID", HEX64),
            "artifact_file_sha256": require_string(
                row["artifact_file_sha256"], "artifact file SHA-256", HEX64
            ),
        }

    pattern_tuples: dict[str, dict[str, Any]] = {}
    compiled_patterns = require_list(
        registry["compiled_patterns"], "compiled patterns", 16_384
    )
    for ordinal, raw in enumerate(compiled_patterns):
        pattern = require_object(raw, f"compiled patterns[{ordinal}]")
        exact_keys(
            pattern,
            {
                "claim_derivations",
                "engines",
                "input_policy",
                "optimizer_input_sha256",
                "pattern_input_id",
                "pattern_sha256",
                "planning_receipt_identity",
                "semantic_binding_identity",
            },
            f"compiled patterns[{ordinal}]",
        )
        pattern_sha256 = require_string(
            pattern.get("pattern_sha256"), "compiled pattern SHA-256", HEX64
        )
        if pattern_sha256 in pattern_tuples:
            fail("compiled pattern registry repeats a pattern SHA-256")
        engines = require_list(pattern.get("engines"), "compiled engines", 3)
        if len(engines) != len(ENGINES):
            fail("compiled pattern does not have exactly three engine rows")
        rows = [
            require_object(row, f"compiled patterns[{ordinal}] engine row")
            for row in engines
        ]
        labels = [row.get("engine") for row in rows]
        if labels != list(ENGINES):
            fail("compiled engine rows differ from the canonical control/v3 matrix")
        for row in rows[:2]:
            if (
                row.get("runtime_authority") != "control"
                or row.get("general_eligibility_tuple") is not None
            ):
                fail("compiled current-control row gained production authority")
        v3 = rows[2]
        if (
            v3.get("runtime_authority") != "production"
            or v3.get("engine") != "count-v3-aot"
        ):
            fail("compiled Count-v3 row is not production-authority typed")
        eligibility = _validate_eligibility_tuple(
            v3.get("general_eligibility_tuple"), "general eligibility tuple"
        )
        pattern_tuples[pattern_sha256] = eligibility

    distinct_artifacts = require_uint(
        registry["distinct_artifacts"], 1, 16_384, "distinct artifacts"
    )
    if (
        distinct_artifacts != len(pattern_tuples)
        or len(artifacts) != len(pattern_tuples) * len(ENGINES)
        or set(artifacts)
        != {
            (pattern_sha256, engine)
            for pattern_sha256 in pattern_tuples
            for engine in ENGINES
        }
    ):
        fail("production registry does not close over one three-engine artifact matrix")

    for cell in cells.values():
        pattern = cell["pattern_sha256"]
        if pattern not in pattern_tuples:
            fail("selected cell lacks a compiled eligibility tuple")
        eligibility = pattern_tuples[pattern]
        encoded = canonical_json_bytes(eligibility)
        if encoded not in qualified_target_tuples:
            fail(
                "selected cell tuple is not an exact qualified tuple for the "
                "proposal target"
            )
        cell["eligibility_tuple"] = eligibility
        cell["eligibility_tuple_sha256"] = sha256_bytes(encoded)
        for engine in ENGINES:
            if (pattern, engine) not in artifacts:
                fail("selected cell lacks the complete three-engine artifact matrix")
    for selected_row in selected:
        cell = cells[selected_row["cell_id"]]
        if cell["input_bytes"] * selected_row["iterations"] > (1 << 64) - 1:
            fail("selected cell searched-byte count exceeds u64")
    return cells, artifacts


def schedule(
    selected: Sequence[Mapping[str, Any]],
    repetitions: int,
    cells: Mapping[str, Mapping[str, Any]],
    artifacts: Mapping[tuple[str, str], Mapping[str, Any]],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    sequence = 1
    for selected_row in selected:
        cell_id = selected_row["cell_id"]
        cell = cells[cell_id]
        result.append(
            {
                "sequence": sequence,
                "kind": "authorization",
                "cell_id": cell_id,
                "engine": "count-v3-aot",
                "iterations": 0,
                "repetition": 0,
                "order": "authorization",
                "artifact_id": artifacts[
                    (cell["pattern_sha256"], "count-v3-aot")
                ]["artifact_id"],
            }
        )
        sequence += 1
    for selected_row in selected:
        cell_id = selected_row["cell_id"]
        cell = cells[cell_id]
        for engine in ENGINES:
            result.append(
                {
                    "sequence": sequence,
                    "kind": "correctness",
                    "cell_id": cell_id,
                    "engine": engine,
                    "iterations": 1,
                    "repetition": 0,
                    "order": ">".join(ENGINES),
                    "artifact_id": artifacts[
                        (cell["pattern_sha256"], engine)
                    ]["artifact_id"],
                }
            )
            sequence += 1
    for selected_row in selected:
        cell_id = selected_row["cell_id"]
        cell = cells[cell_id]
        iterations = selected_row["iterations"]
        for repetition in range(1, repetitions + 1):
            order = ORDERS[(repetition - 1) % len(ORDERS)]
            for engine in order:
                result.append(
                    {
                        "sequence": sequence,
                        "kind": "measurement",
                        "cell_id": cell_id,
                        "engine": engine,
                        "iterations": iterations,
                        "repetition": repetition,
                        "order": ">".join(order),
                        "artifact_id": artifacts[
                            (cell["pattern_sha256"], engine)
                        ]["artifact_id"],
                    }
                )
                sequence += 1
    return result


def _runner_request(target_id: str, nonce: str) -> dict[str, Any]:
    return {
        "process_nonce": nonce,
        "schema": REQUEST_SCHEMA,
        "target_id": target_id,
    }


def _result_checksum(cell: Mapping[str, Any]) -> str:
    digest = hashlib.sha256()
    digest.update(RESULT_DOMAIN)
    digest.update(cell["cell_id"].encode("utf-8"))
    digest.update(b"\0")
    digest.update(str(cell["expected_count"]).encode("ascii"))
    digest.update(b"\0")
    digest.update(cell["oracle_receipt_sha256"].encode("ascii"))
    return digest.hexdigest()


def _work_checksum(result: str, iterations: int, searched_bytes: int) -> str:
    digest = hashlib.sha256()
    digest.update(WORK_DOMAIN)
    digest.update(result.encode("ascii"))
    digest.update(b"\0")
    digest.update(str(iterations).encode("ascii"))
    digest.update(b"\0")
    digest.update(str(searched_bytes).encode("ascii"))
    return digest.hexdigest()


def _validate_authorization(
    value: Any,
    item: Mapping[str, Any],
    nonce: str,
    target_id: str,
) -> dict[str, Any]:
    row = require_object(value, "authorization response")
    exact_keys(
        row,
        {
            "artifact_id",
            "build_authority",
            "cell_id",
            "process_nonce",
            "schema",
            "target_id",
        },
        "authorization response",
    )
    if row != {
        "artifact_id": item["artifact_id"],
        "build_authority": "production",
        "cell_id": item["cell_id"],
        "process_nonce": nonce,
        "schema": AUTHORIZATION_SCHEMA,
        "target_id": target_id,
    }:
        fail("authorization response differs from the scheduled source-authority proof")
    return row


def _validate_observation(
    value: Any,
    item: Mapping[str, Any],
    nonce: str,
    request_bytes: bytes,
    runner_sha256: str,
    cell: Mapping[str, Any],
    target_id: str,
    minimum_elapsed_ns: int,
) -> dict[str, Any]:
    row = require_object(value, "runner observation")
    exact_keys(
        row,
        {
            "artifact_id",
            "cell_id",
            "elapsed_ns",
            "engine",
            "engine_binary_sha256",
            "iterations",
            "process_nonce",
            "request_sha256",
            "result_checksum",
            "result_count",
            "schema",
            "searched_bytes",
            "status",
            "target_id",
            "work_checksum",
        },
        "runner observation",
    )
    iterations = item["iterations"]
    searched_bytes = cell["input_bytes"] * iterations
    elapsed = require_uint(row["elapsed_ns"], 0, (1 << 64) - 1, "elapsed nanoseconds")
    if item["kind"] == "correctness":
        if elapsed != 0:
            fail("correctness observation has nonzero elapsed time")
    elif elapsed < minimum_elapsed_ns:
        fail(
            f"{item['cell_id']}/{item['engine']} retained sample is shorter "
            f"than {minimum_elapsed_ns} ns"
        )
    expected_result = _result_checksum(cell)
    expected = {
        "artifact_id": item["artifact_id"],
        "cell_id": item["cell_id"],
        "engine": item["engine"],
        "engine_binary_sha256": runner_sha256,
        "iterations": iterations,
        "process_nonce": nonce,
        "request_sha256": sha256_bytes(request_bytes),
        "result_checksum": expected_result,
        "result_count": cell["expected_count"],
        "schema": OBSERVATION_SCHEMA,
        "searched_bytes": searched_bytes,
        "status": "pass",
        "target_id": target_id,
        "work_checksum": _work_checksum(expected_result, iterations, searched_bytes),
    }
    for field, expected_value in expected.items():
        if row.get(field) != expected_value:
            fail(f"runner observation field {field} differs")
    return row


def _journal_read(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    before = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_mode & 0o077
        or before.st_size > MAXIMUM_JOURNAL_BYTES
    ):
        fail("journal is not one bounded private regular file")
    bytes_value = path.read_bytes()
    after = path.stat()
    if (
        len(bytes_value) != before.st_size
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or bytes_value and not bytes_value.endswith(b"\n")
    ):
        fail("journal changed while reading or lacks its final LF")
    events = []
    for ordinal, line in enumerate(bytes_value.splitlines()):
        event = require_object(decode_json(line, f"journal line {ordinal + 1}"), "journal event")
        if canonical_json_bytes(event) != line:
            fail("journal event is not compact sorted canonical JSON")
        events.append(event)
    return events


def _journal_append(path: Path, event: Mapping[str, Any]) -> None:
    parent = path.parent.resolve(strict=True)
    if not path.is_absolute() or path.parent != parent:
        fail("journal path parent is not absolute and canonical")
    if path.is_symlink():
        fail("journal path is a symbolic link")
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    descriptor = os.open(path, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o077
            or metadata.st_size > MAXIMUM_JOURNAL_BYTES
        ):
            fail("journal descriptor is not one bounded private regular file")
        payload = canonical_json_bytes(dict(event)) + b"\n"
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                fail("journal append was short")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _replay(
    events: Sequence[Mapping[str, Any]],
    scheduled: Sequence[Mapping[str, Any]],
    plan_sha256: str,
    target_id: str,
    runner_sha256: str,
    cells: Mapping[str, Mapping[str, Any]],
    minimum_elapsed_ns: int,
) -> tuple[int, list[tuple[dict[str, Any], dict[str, Any]]]]:
    event_index = 0
    completed = 0
    successful: list[tuple[dict[str, Any], dict[str, Any]]] = []
    denials_for_item = 0
    nonces: set[str] = set()
    while event_index < len(events):
        if completed >= len(scheduled):
            fail("journal has events beyond the closed schedule")
        item = scheduled[completed]
        launch = events[event_index]
        event_index += 1
        exact_keys(
            launch,
            {
                "item_sha256",
                "nonce",
                "plan_sha256",
                "request_sha256",
                "schema",
                "sequence",
            },
            "journal launch",
        )
        nonce = require_string(launch["nonce"], "journal nonce", HEX64)
        if nonce in nonces:
            fail("journal reuses a process nonce")
        nonces.add(nonce)
        request = _runner_request(target_id, nonce)
        request_bytes = canonical_json_bytes(request)
        if (
            launch["schema"] != JOURNAL_LAUNCH_SCHEMA
            or launch["plan_sha256"] != plan_sha256
            or launch["sequence"] != item["sequence"]
            or launch["item_sha256"] != sha256_bytes(canonical_json_bytes(item))
            or launch["request_sha256"] != sha256_bytes(request_bytes)
        ):
            fail("journal launch differs from the scheduled request")
        if event_index >= len(events):
            fail("journal ends with an unmatched launch; sample replacement is forbidden")
        result = events[event_index]
        event_index += 1
        exact_keys(
            result,
            {
                "kind",
                "nonce",
                "plan_sha256",
                "response",
                "runner_stderr_sha256",
                "schema",
                "sequence",
            },
            "journal result",
        )
        if (
            result["schema"] != JOURNAL_RESULT_SCHEMA
            or result["plan_sha256"] != plan_sha256
            or result["sequence"] != item["sequence"]
            or result["nonce"] != nonce
            or require_string(
                result["runner_stderr_sha256"], "runner stderr SHA-256", HEX64
            )
            != result["runner_stderr_sha256"]
        ):
            fail("journal result differs from its launch")
        kind = result["kind"]
        if kind == "denied":
            if result["response"] is not None:
                fail("temporary denial unexpectedly carries a response")
            denials_for_item += 1
            if denials_for_item > MAXIMUM_DENIALS_PER_ITEM:
                fail("journal exceeds the bounded temporary-denial count for one item")
            continue
        if kind == "failure":
            fail("journal contains a terminal runner failure")
        response = require_object(result["response"], "journal response")
        if item["kind"] == "authorization" and kind == "authorization":
            validated = _validate_authorization(response, item, nonce, target_id)
        elif item["kind"] != "authorization" and kind == "observation":
            validated = _validate_observation(
                response,
                item,
                nonce,
                request_bytes,
                runner_sha256,
                cells[item["cell_id"]],
                target_id,
                minimum_elapsed_ns,
            )
        else:
            fail("journal response kind differs from the scheduled item")
        successful.append((dict(item), validated))
        completed += 1
        denials_for_item = 0
    return completed, successful


def _run_item(
    item: Mapping[str, Any],
    plan: Mapping[str, Any],
    plan_sha256: str,
    journal: Path,
    runner_seal: Mapping[str, Any],
    wrapper_seal: Mapping[str, Any],
    environment: Mapping[str, str],
    cell: Mapping[str, Any],
    used_nonces: set[str],
) -> int:
    nonce = secrets.token_hex(32)
    while nonce in used_nonces:
        nonce = secrets.token_hex(32)
    used_nonces.add(nonce)
    request = _runner_request(plan["target_id"], nonce)
    request_bytes = canonical_json_bytes(request)
    launch = {
        "item_sha256": sha256_bytes(canonical_json_bytes(item)),
        "nonce": nonce,
        "plan_sha256": plan_sha256,
        "request_sha256": sha256_bytes(request_bytes),
        "schema": JOURNAL_LAUNCH_SCHEMA,
        "sequence": item["sequence"],
    }
    _journal_append(journal, launch)
    _recheck_executable(runner_seal, "runner")
    if item["kind"] == "authorization":
        argv = [str(runner_seal["path"]), "authorize", item["cell_id"]]
    else:
        _recheck_executable(wrapper_seal, "timing wrapper")
        command = "correctness" if item["kind"] == "correctness" else "measure"
        argv = list(plan["timing_wrapper"]["argv"]) + [
            str(runner_seal["path"]),
            command,
            item["cell_id"],
            item["engine"],
            str(item["iterations"]),
        ]
    try:
        returncode, stdout, stderr = _run_bounded(
            argv,
            request_bytes,
            plan["runner"]["timeout_seconds"],
            environment,
        )
    except (OSError, subprocess.TimeoutExpired, ConfirmationError) as error:
        _journal_append(
            journal,
            {
                "kind": "failure",
                "nonce": nonce,
                "plan_sha256": plan_sha256,
                "response": None,
                "runner_stderr_sha256": sha256_bytes(str(error).encode("utf-8")),
                "schema": JOURNAL_RESULT_SCHEMA,
                "sequence": item["sequence"],
            },
        )
        fail(f"runner launch failed and was sealed: {error}")
    stderr_sha256 = sha256_bytes(stderr)
    if returncode == TEMPORARY_UNAVAILABLE and item["kind"] != "authorization":
        if stdout:
            _journal_append(
                journal,
                {
                    "kind": "failure",
                    "nonce": nonce,
                    "plan_sha256": plan_sha256,
                    "response": None,
                    "runner_stderr_sha256": stderr_sha256,
                    "schema": JOURNAL_RESULT_SCHEMA,
                    "sequence": item["sequence"],
                },
            )
            fail(
                "timing wrapper returned 75 after producing child output; "
                "sample replacement is forbidden"
            )
        _journal_append(
            journal,
            {
                "kind": "denied",
                "nonce": nonce,
                "plan_sha256": plan_sha256,
                "response": None,
                "runner_stderr_sha256": stderr_sha256,
                "schema": JOURNAL_RESULT_SCHEMA,
                "sequence": item["sequence"],
            },
        )
        return TEMPORARY_UNAVAILABLE
    if returncode != 0 or (item["kind"] == "authorization" and stderr):
        _journal_append(
            journal,
            {
                "kind": "failure",
                "nonce": nonce,
                "plan_sha256": plan_sha256,
                "response": None,
                "runner_stderr_sha256": stderr_sha256,
                "schema": JOURNAL_RESULT_SCHEMA,
                "sequence": item["sequence"],
            },
        )
        fail(
            f"runner exited {returncode}, or the direct authorization wrote "
            "stderr; failure was sealed"
        )
    try:
        response = _one_json_line(stdout, "runner response")
        if item["kind"] == "authorization":
            response = _validate_authorization(
                response, item, nonce, plan["target_id"]
            )
            result_kind = "authorization"
        else:
            response = _validate_observation(
                response,
                item,
                nonce,
                request_bytes,
                plan["runner"]["sha256"],
                cell,
                plan["target_id"],
                plan["minimum_elapsed_ns"],
            )
            result_kind = "observation"
    except ConfirmationError as error:
        _journal_append(
            journal,
            {
                "kind": "failure",
                "nonce": nonce,
                "plan_sha256": plan_sha256,
                "response": None,
                "runner_stderr_sha256": sha256_bytes(str(error).encode("utf-8")),
                "schema": JOURNAL_RESULT_SCHEMA,
                "sequence": item["sequence"],
            },
        )
        fail(f"runner response was malformed and the failure was sealed: {error}")
    _journal_append(
        journal,
        {
            "kind": result_kind,
            "nonce": nonce,
            "plan_sha256": plan_sha256,
            "response": response,
            "runner_stderr_sha256": stderr_sha256,
            "schema": JOURNAL_RESULT_SCHEMA,
            "sequence": item["sequence"],
        },
    )
    return 0


def _geomean_ratio(numerators: Sequence[int], denominators: Sequence[int]) -> float:
    if (
        not numerators
        or len(numerators) != len(denominators)
        or any(value <= 0 for value in numerators)
        or any(value <= 0 for value in denominators)
    ):
        fail("cannot form a positive paired geometric mean")
    log_ratio = math.fsum(
        math.log(numerator) - math.log(denominator)
        for numerator, denominator in zip(numerators, denominators, strict=True)
    )
    return math.exp(log_ratio / len(numerators))


def _strict_four_fifths(numerators: Sequence[int], denominators: Sequence[int]) -> bool:
    if not numerators or len(numerators) != len(denominators):
        fail("exact ratio test lacks paired values")
    numerator_product = math.prod(numerators)
    denominator_product = math.prod(denominators)
    count = len(numerators)
    return numerator_product * (5**count) < denominator_product * (4**count)


def derive_summary(
    plan: Mapping[str, Any],
    plan_sha256: str,
    registry: Mapping[str, Any],
    promotion: Mapping[str, Any],
    journal: Path,
    successful: Sequence[tuple[Mapping[str, Any], Mapping[str, Any]]],
    cells: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    measurements: dict[tuple[str, int, str], int] = {}
    for item, response in successful:
        if item["kind"] == "measurement":
            key = (item["cell_id"], item["repetition"], item["engine"])
            if key in measurements:
                fail("successful journal repeats a retained measurement")
            measurements[key] = response["elapsed_ns"]
    expected_measurements = (
        len(plan["cells"]) * plan["repetitions"] * len(ENGINES)
    )
    if len(measurements) != expected_measurements:
        fail("completed journal lacks the exact retained measurement matrix")

    required_wins = (4 * plan["repetitions"] + 4) // 5
    cell_summaries = []
    aggregate_v3: list[int] = []
    aggregate_faster: list[int] = []
    aggregate_portable: list[int] = []
    aggregate_wins = 0
    order_counts = {">".join(order): 0 for order in ORDERS}
    tuple_accumulator: dict[str, dict[str, Any]] = {}
    for selected in plan["cells"]:
        cell = cells[selected["cell_id"]]
        v3_values = []
        faster_values = []
        portable_values = []
        samples = []
        cell_order_counts = {">".join(order): 0 for order in ORDERS}
        wins = 0
        for repetition in range(1, plan["repetitions"] + 1):
            portable = measurements[(cell["cell_id"], repetition, "portable-current")]
            v2 = measurements[(cell["cell_id"], repetition, "count-v2-current")]
            v3 = measurements[(cell["cell_id"], repetition, "count-v3-aot")]
            faster = min(portable, v2)
            portable_values.append(portable)
            faster_values.append(faster)
            v3_values.append(v3)
            if v3 < faster:
                wins += 1
            order = ">".join(ORDERS[(repetition - 1) % len(ORDERS)])
            cell_order_counts[order] += 1
            order_counts[order] += 1
            samples.append(
                {
                    "count_v2_elapsed_ns": v2,
                    "count_v3_elapsed_ns": v3,
                    "faster_control": (
                        "portable-current"
                        if portable <= v2
                        else "count-v2-current"
                    ),
                    "order": order,
                    "portable_elapsed_ns": portable,
                    "repetition": repetition,
                }
            )
        strict = _strict_four_fifths(v3_values, faster_values)
        passed = strict and wins >= required_wins
        summary = {
            "cell_id": cell["cell_id"],
            "eligibility_tuple_sha256": cell["eligibility_tuple_sha256"],
            "faster_control_ratio": f"{_geomean_ratio(v3_values, faster_values):.9f}",
            "input_bytes": cell["input_bytes"],
            "iterations": selected["iterations"],
            "order_counts": cell_order_counts,
            "paired_samples": samples,
            "pattern_sha256": cell["pattern_sha256"],
            "portable_ratio": f"{_geomean_ratio(v3_values, portable_values):.9f}",
            "required_strict_paired_wins": required_wins,
            "status": "pass" if passed else "fail",
            "strict_faster_control_ratio_below_four_fifths": strict,
            "strict_paired_wins": wins,
        }
        cell_summaries.append(summary)
        aggregate_v3.extend(v3_values)
        aggregate_faster.extend(faster_values)
        aggregate_portable.extend(portable_values)
        aggregate_wins += wins
        accumulator = tuple_accumulator.setdefault(
            cell["eligibility_tuple_sha256"],
            {
                "cells": [],
                "eligibility_tuple": cell["eligibility_tuple"],
                "faster": [],
                "portable": [],
                "v3": [],
                "wins": 0,
            },
        )
        accumulator["cells"].append(cell["cell_id"])
        accumulator["faster"].extend(faster_values)
        accumulator["portable"].extend(portable_values)
        accumulator["v3"].extend(v3_values)
        accumulator["wins"] += wins

    tuple_summaries = []
    for tuple_sha256 in sorted(tuple_accumulator):
        values = tuple_accumulator[tuple_sha256]
        sample_count = len(values["v3"])
        tuple_required_wins = (4 * sample_count + 4) // 5
        strict = _strict_four_fifths(values["v3"], values["faster"])
        passed = strict and values["wins"] >= tuple_required_wins
        tuple_summaries.append(
            {
                "cell_ids": values["cells"],
                "eligibility_tuple": values["eligibility_tuple"],
                "eligibility_tuple_sha256": tuple_sha256,
                "faster_control_ratio": (
                    f"{_geomean_ratio(values['v3'], values['faster']):.9f}"
                ),
                "portable_ratio": (
                    f"{_geomean_ratio(values['v3'], values['portable']):.9f}"
                ),
                "required_strict_paired_wins": tuple_required_wins,
                "status": "pass" if passed else "fail",
                "strict_faster_control_ratio_below_four_fifths": strict,
                "strict_paired_wins": values["wins"],
            }
        )

    aggregate_strict = _strict_four_fifths(aggregate_v3, aggregate_faster)
    aggregate_required_wins = (4 * len(aggregate_v3) + 4) // 5
    aggregate_wins_pass = aggregate_wins >= aggregate_required_wins
    expected_order_count = (
        len(plan["cells"]) * plan["repetitions"] // len(ORDERS)
    )
    all_orders_balanced = all(
        count == expected_order_count for count in order_counts.values()
    )
    all_cells_pass = all(row["status"] == "pass" for row in cell_summaries)
    all_tuples_pass = all(row["status"] == "pass" for row in tuple_summaries)
    target_pass = aggregate_strict and aggregate_wins_pass
    status = (
        "pass"
        if target_pass
        and all_cells_pass
        and all_tuples_pass
        and all_orders_balanced
        else "fail"
    )
    journal_bytes = journal.read_bytes()
    return {
        "target_aggregate": {
            "faster_control_ratio": (
                f"{_geomean_ratio(aggregate_v3, aggregate_faster):.9f}"
            ),
            "order_counts": order_counts,
            "paired_samples": len(aggregate_v3),
            "portable_ratio": (
                f"{_geomean_ratio(aggregate_v3, aggregate_portable):.9f}"
            ),
            "required_strict_paired_wins": aggregate_required_wins,
            "status": "pass" if target_pass and all_orders_balanced else "fail",
            "strict_faster_control_ratio_below_four_fifths": aggregate_strict,
            "strict_paired_wins": aggregate_wins,
            "six_order_rotation_balanced": all_orders_balanced,
            "target_id": plan["target_id"],
        },
        "build_authority": "production",
        "cells": cell_summaries,
        "coverage": {
            "authorized_cells": len(cell_summaries),
            "distinct_eligibility_tuples": len(tuple_summaries),
            "distinct_patterns": len(
                {cells[row["cell_id"]]["pattern_sha256"] for row in plan["cells"]}
            ),
            "retained_measurements": expected_measurements,
            "selected_cell_ids": [row["cell_id"] for row in plan["cells"]],
        },
        "journal_sha256": sha256_bytes(journal_bytes),
        "measurement_policy": (
            "fresh-process-full-lifetime-wrapper-rotating-six-order-paired-v1"
        ),
        "minimum_elapsed_ns": plan["minimum_elapsed_ns"],
        "plan_sha256": plan_sha256,
        "promotion_authority_source_sha256": promotion[
            "authority_source_sha256"
        ],
        "promotion_manifest_sha256": promotion["manifest_sha256"],
        "promotion_proposal_sha256": promotion["proposal_sha256"],
        "qualification_artifact_registry_sha256": promotion[
            "qualification_artifact_registry_sha256"
        ],
        "qualification_id": promotion["qualification_id"],
        "qualification_spec_sha256": promotion["spec_sha256"],
        "registry_sha256": plan["runner"]["registry_sha256"],
        "repetitions": plan["repetitions"],
        "runner_sha256": plan["runner"]["sha256"],
        "schema": SUMMARY_PAYLOAD_SCHEMA,
        "source_set_sha256": require_string(
            require_object(registry["source"], "registry source").get(
                "source_set_sha256"
            ),
            "source-set SHA-256",
            HEX64,
        ),
        "status": status,
        "target_contract_sha256": plan["target_contract_sha256"],
        "target_id": plan["target_id"],
        "timing_wrapper_argv_sha256": sha256_bytes(
            canonical_json_bytes(plan["timing_wrapper"]["argv"])
        ),
        "timing_wrapper_contract": plan["timing_wrapper"]["contract"],
        "timing_wrapper_executable_sha256": plan["timing_wrapper"][
            "executable_sha256"
        ],
        "tuple_summaries": tuple_summaries,
    }


def _write_summary(path: Path, payload: Mapping[str, Any]) -> None:
    parent = path.parent.resolve(strict=True)
    if not path.is_absolute() or path.parent != parent or path.exists():
        fail("summary path must be a new file under an absolute canonical parent")
    payload_bytes = canonical_json_bytes(payload)
    envelope = {
        "payload": dict(payload),
        "payload_sha256": sha256_bytes(payload_bytes),
        "schema": SEALED_SUMMARY_SCHEMA,
    }
    output = canonical_json_bytes(envelope) + b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        offset = 0
        while offset < len(output):
            written = os.write(descriptor, output[offset:])
            if written <= 0:
                fail("sealed summary write was short")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def run(plan_path: Path, journal: Path, summary_path: Path) -> int:
    raw_plan, plan_bytes = _load_canonical_json(
        plan_path, MAXIMUM_PLAN_BYTES, "production confirmation plan"
    )
    plan = validate_plan(raw_plan)
    plan_sha256 = sha256_bytes(plan_bytes)
    runner_seal = _seal_executable(
        plan["runner"]["path"],
        plan["runner"]["sha256"],
        MAXIMUM_RUNNER_BYTES,
        "runner",
    )
    wrapper_seal = _seal_executable(
        plan["timing_wrapper"]["argv"][0],
        plan["timing_wrapper"]["executable_sha256"],
        MAXIMUM_WRAPPER_BYTES,
        "timing wrapper",
    )
    environment = dict(os.environ)
    environment["FRE_COUNT_V3_HAYSTACK_DIR"] = str(plan["haystack_dir"])
    registry = load_registry(plan, runner_seal, environment)
    promotion = load_promotion(plan, registry)
    cells, artifacts = index_registry(
        registry,
        plan["cells"],
        promotion["qualified_target_tuples"],
    )
    scheduled = schedule(
        plan["cells"], plan["repetitions"], cells, artifacts
    )
    events = _journal_read(journal)
    completed, successful = _replay(
        events,
        scheduled,
        plan_sha256,
        plan["target_id"],
        plan["runner"]["sha256"],
        cells,
        plan["minimum_elapsed_ns"],
    )
    used_nonces = {
        event["nonce"]
        for event in events
        if event.get("schema") == JOURNAL_LAUNCH_SCHEMA
    }
    for item in scheduled[completed:]:
        status = _run_item(
            item,
            plan,
            plan_sha256,
            journal,
            runner_seal,
            wrapper_seal,
            environment,
            cells[item["cell_id"]],
            used_nonces,
        )
        if status == TEMPORARY_UNAVAILABLE:
            return TEMPORARY_UNAVAILABLE
    final_events = _journal_read(journal)
    final_completed, successful = _replay(
        final_events,
        scheduled,
        plan_sha256,
        plan["target_id"],
        plan["runner"]["sha256"],
        cells,
        plan["minimum_elapsed_ns"],
    )
    if final_completed != len(scheduled):
        fail("confirmation schedule is incomplete")
    payload = derive_summary(
        plan,
        plan_sha256,
        registry,
        promotion,
        journal,
        successful,
        cells,
    )
    _write_summary(summary_path, payload)
    return 0 if payload["status"] == "pass" else 1


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="run and seal post-promotion Count-v3 confirmation"
    )
    parser.add_argument("plan", type=Path)
    parser.add_argument("journal", type=Path)
    parser.add_argument("summary", type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        return run(arguments.plan, arguments.journal, arguments.summary)
    except ConfirmationError as error:
        print(f"production_confirm: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
