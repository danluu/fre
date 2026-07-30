#!/usr/bin/env python3
"""Fail-closed analyzer for attested Cargo/rustc/linker construction receipts."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Mapping, Sequence

import static_tool_wrapper as wrapper


PLAN_SCHEMA = "fre.aot.search-static-construction-plan.v1"
TOOL_PAYLOAD_FIELDS = {
    "role",
    "launcher",
    "python_runtime",
    "wrapper_source_sha256",
    "sealer_source_sha256",
    "tool",
    "lineage",
    "arguments",
    "arguments_sha256",
    "executed_arguments",
    "executed_arguments_sha256",
    "environment",
    "environment_sha256",
    "input_rows",
    "input_rows_sha256",
    "symbolic_inputs",
    "symbolic_inputs_sha256",
    "build_script_publication",
    "output",
    "returncode",
    "stdout_sha256",
    "stdout_bytes",
    "stderr_sha256",
    "stderr_bytes",
}
TOOL_FIELDS = {"path", "sha256", "execution_identity"}
PYTHON_RUNTIME_FIELDS = TOOL_FIELDS | {"flags"}
LINEAGE_FIELDS = {"parent_pid", "wrapper_pid", "tool_pid"}
INPUT_FIELDS = {
    "ordinal",
    "argument_index",
    "path",
    "sha256",
    "bytes",
    "kind",
    "held_argument",
}
SYMBOLIC_FIELDS = {"argument_index", "kind", "value"}
OUTPUT_FIELDS = {"path", "sha256", "bytes"}
BUILD_SCRIPT_PUBLICATION_FIELDS = {
    "sidecar_path",
    "sidecar_sha256",
    "launcher_sha256",
    "wrapper_source_sha256",
    "tool_path",
    "tool_sha256",
    "execution_identity",
    "rustc_arguments_sha256",
}
JOBSERVER = re.compile(
    r"(?<!\S)--jobserver-(?:fds|auth)=[0-9]+,[0-9]+(?!\S)"
)


class Refusal(RuntimeError):
    """Construction receipts differ from a complete preregistered plan."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode()


def canonical_sha(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def file_sha(path: Path, maximum: int = 1 << 31) -> str:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        status = os.fstat(descriptor)
        require(
            stat.S_ISREG(status.st_mode)
            and 0 < status.st_size <= maximum,
            f"not one bounded regular artifact: {path}",
        )
        digest = hashlib.sha256()
        offset = 0
        while offset < status.st_size:
            encoded = os.pread(
                descriptor,
                min(1024 * 1024, status.st_size - offset),
                offset,
            )
            require(bool(encoded), f"artifact ended early: {path}")
            digest.update(encoded)
            offset += len(encoded)
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def read_receipt(path: Path) -> tuple[dict[str, Any], str]:
    encoded = path.read_bytes()
    require(
        0 < len(encoded) <= 16 * 1024 * 1024 and encoded.endswith(b"\n"),
        "tool receipt is empty, oversized, or not newline terminated",
    )
    root = json.loads(encoded)
    require(
        isinstance(root, dict)
        and set(root) == {"schema", "payload_sha256", "payload"}
        and root["schema"] == wrapper.SCHEMA
        and isinstance(root["payload"], dict)
        and canonical_sha(root["payload"]) == root["payload_sha256"],
        "tool receipt envelope changed",
    )
    return root["payload"], hashlib.sha256(encoded).hexdigest()


def normalize_jobserver(environment: Mapping[str, str]) -> dict[str, str]:
    normalized = dict(environment)
    for key in ("CARGO_MAKEFLAGS", "MAKEFLAGS", "MFLAGS"):
        if key not in normalized:
            continue
        value = normalized[key]
        if "jobserver" in value:
            require(
                JOBSERVER.search(value) is not None,
                f"unrecognized nondeterministic jobserver value: {key}",
            )
            normalized[key] = JOBSERVER.sub(
                "--jobserver-auth=<inherited-fd-pair>", value
            ).strip()
    return normalized


def validate_input_rows(
    payload: Mapping[str, Any],
) -> None:
    arguments = payload["arguments"]
    executed = payload["executed_arguments"]
    rows = payload["input_rows"]
    symbolic = payload["symbolic_inputs"]
    explicit, output_index, derived_symbolic = wrapper.link_operand_kinds(
        arguments
    )
    require(
        isinstance(rows, list)
        and canonical_sha(rows) == payload["input_rows_sha256"]
        and isinstance(symbolic, list)
        and canonical_sha(symbolic) == payload["symbolic_inputs_sha256"]
        and symbolic == derived_symbolic,
        "link input projections changed",
    )
    require(
        len(rows) == len(explicit)
        and [row.get("ordinal") for row in rows] == list(range(len(rows)))
        and [row.get("argument_index") for row in rows]
        == sorted(explicit),
        "explicit link input receipt is not one exact ordered multiset",
    )
    rewritten_indices: set[int] = set()
    for row in rows:
        require(
            isinstance(row, dict)
            and set(row) == INPUT_FIELDS
            and isinstance(row["argument_index"], int)
            and row["argument_index"] in explicit
            and explicit[row["argument_index"]][0] == Path(row["path"])
            and wrapper.is_sha256(row["sha256"])
            and isinstance(row["bytes"], int)
            and row["bytes"] > 0
            and row["kind"]
            in {
                "object",
                "archive",
                "dynamic-library",
                "text-stub",
                "symbol-list",
            }
            and isinstance(row["held_argument"], str)
            and executed[row["argument_index"]]
            == row["held_argument"],
            "explicit link input row changed",
        )
        rewritten_indices.add(row["argument_index"])
    require(
        all(
            original == actual or index in rewritten_indices
            for index, (original, actual) in enumerate(
                zip(arguments, executed, strict=True)
            )
        ),
        "link wrapper changed a non-input argument",
    )
    output = payload["output"]
    require(
        isinstance(output, dict)
        and set(output) == OUTPUT_FIELDS
        and output["path"] == arguments[output_index]
        and wrapper.is_sha256(output["sha256"])
        and isinstance(output["bytes"], int)
        and output["bytes"] > 0,
        "link output receipt changed",
    )


def validate_tool_payload(
    payload: Mapping[str, Any],
    *,
    expected_wrapper_sha256: str,
    expected_sealer_sha256: str,
    expected_launcher: Mapping[str, Any],
    expected_python_runtime: Mapping[str, Any],
    expected_tools: Mapping[str, Mapping[str, Any]],
) -> None:
    require(
        set(payload) == TOOL_PAYLOAD_FIELDS
        and payload["role"] in {"rustc", "linker", "build-script"}
        and payload["wrapper_source_sha256"] == expected_wrapper_sha256
        and payload["sealer_source_sha256"] == expected_sealer_sha256
        and isinstance(payload["returncode"], int)
        and 0 <= payload["returncode"] <= 255,
        "tool receipt header changed",
    )
    role = payload["role"]
    launcher = payload["launcher"]
    python_runtime = payload["python_runtime"]
    require(
        isinstance(launcher, dict)
        and set(launcher) == TOOL_FIELDS
        and Path(launcher["path"]).is_absolute()
        and launcher["sha256"] == expected_launcher["sha256"]
        and launcher["execution_identity"]
        == expected_launcher["execution_identity"]
        and isinstance(python_runtime, dict)
        and set(python_runtime) == PYTHON_RUNTIME_FIELDS
        and python_runtime == expected_python_runtime,
        "launcher or isolated Python runtime identity changed",
    )
    tool = payload["tool"]
    require(
        isinstance(tool, dict) and set(tool) == TOOL_FIELDS,
        "executed tool identity changed",
    )
    publication = payload["build_script_publication"]
    if role == "build-script":
        require(
            isinstance(publication, dict)
            and set(publication) == BUILD_SCRIPT_PUBLICATION_FIELDS
            and tool["path"] == publication["tool_path"]
            and tool["sha256"] == publication["tool_sha256"]
            and tool["execution_identity"]
            == publication["execution_identity"],
            "executed build-script publication changed",
        )
    else:
        require(
            tool == expected_tools[role],
            "executed tool identity changed",
        )
    lineage = payload["lineage"]
    require(
        isinstance(lineage, dict)
        and set(lineage) == LINEAGE_FIELDS
        and all(
            isinstance(lineage[field], int) and lineage[field] > 0
            for field in LINEAGE_FIELDS
        )
        and len(set(lineage.values())) == len(lineage),
        "tool parent/wrapper/child lineage changed",
    )
    arguments = payload["arguments"]
    executed = payload["executed_arguments"]
    environment = payload["environment"]
    require(
        isinstance(arguments, list)
        and all(isinstance(value, str) and value for value in arguments)
        and canonical_sha(arguments) == payload["arguments_sha256"]
        and isinstance(executed, list)
        and len(executed) == len(arguments)
        and canonical_sha(executed)
        == payload["executed_arguments_sha256"]
        and isinstance(environment, dict)
        and bool(environment)
        and all(
            isinstance(key, str)
            and key
            and "=" not in key
            and isinstance(value, str)
            and "\0" not in value
            for key, value in environment.items()
        )
        and canonical_sha(environment) == payload["environment_sha256"]
        and not any(
            key in environment
            for key in (
                "LD_PRELOAD",
                "DYLD_INSERT_LIBRARIES",
                "DYLD_LIBRARY_PATH",
            )
        ),
        "tool argv/environment changed",
    )
    for prefix in ("stdout", "stderr"):
        require(
            wrapper.is_sha256(payload[f"{prefix}_sha256"])
            and isinstance(payload[f"{prefix}_bytes"], int)
            and 0 <= payload[f"{prefix}_bytes"]
            <= wrapper.MAXIMUM_TOOL_OUTPUT_BYTES,
            f"tool {prefix} receipt changed",
        )
    if role == "rustc":
        require(
            arguments == executed
            and payload["input_rows"] == []
            and payload["symbolic_inputs"] == []
            and payload["output"] is None,
            "rustc wrapper performed a linker-only transformation",
        )
        if publication is not None:
            require(
                isinstance(publication, dict)
                and set(publication)
                == BUILD_SCRIPT_PUBLICATION_FIELDS
                and publication["launcher_sha256"]
                == launcher["sha256"]
                and publication["wrapper_source_sha256"]
                == expected_wrapper_sha256
                and publication["rustc_arguments_sha256"]
                == payload["arguments_sha256"]
                and wrapper.is_sha256(publication["sidecar_sha256"])
                and wrapper.is_sha256(publication["tool_sha256"])
                and publication["tool_path"].endswith(
                    ".fre-attested-real"
                ),
                "published build-script identity changed",
            )
    elif role == "linker":
        require(
            payload["returncode"] == 0 and publication is None,
            "linker unexpectedly published a build script",
        )
        validate_input_rows(payload)
    else:
        require(
            payload["returncode"] == 0
            and arguments == executed
            and payload["input_rows"] == []
            and payload["symbolic_inputs"] == []
            and payload["output"] is None,
            "build-script wrapper performed a linker-only transformation",
        )


def normalized_projection(payload: Mapping[str, Any]) -> dict[str, Any]:
    projected = copy.deepcopy(payload)
    projected["lineage"] = {
        "parent_pid": "<attested-parent>",
        "wrapper_pid": "<attested-wrapper>",
        "tool_pid": "<attested-tool>",
    }
    projected["environment"] = normalize_jobserver(projected["environment"])
    projected["environment_sha256"] = canonical_sha(
        projected["environment"]
    )
    return projected


def validate_build_script_coverage(
    payloads: Sequence[Mapping[str, Any]],
) -> None:
    published = {
        payload["build_script_publication"]["tool_path"]: payload[
            "build_script_publication"
        ]
        for payload in payloads
        if payload["role"] == "rustc"
        and payload["build_script_publication"] is not None
    }
    publication_count = sum(
        payload["role"] == "rustc"
        and payload["build_script_publication"] is not None
        for payload in payloads
    )
    executed: dict[str, list[Mapping[str, Any]]] = {}
    for payload in payloads:
        if payload["role"] == "build-script":
            executed.setdefault(payload["tool"]["path"], []).append(
                payload["build_script_publication"]
            )
    require(
        len(published) == publication_count
        and set(published) == set(executed)
        and all(
            all(execution == published[tool] for execution in executions)
            for tool, executions in executed.items()
        ),
        "published/executed build-script coverage changed",
    )


def load_receipt_set(
    directory: Path,
    *,
    cargo_pid: int,
    expected_wrapper_sha256: str,
    expected_sealer_sha256: str,
    expected_launcher: Mapping[str, Any],
    expected_python_runtime: Mapping[str, Any],
    expected_tools: Mapping[str, Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], str]:
    require(
        directory.is_absolute()
        and directory.is_dir()
        and not directory.is_symlink(),
        "tool receipt root changed",
    )
    paths = sorted(directory.iterdir(), key=lambda path: path.name)
    require(
        bool(paths)
        and all(
            path.name.endswith(".json")
            and path.is_file()
            and not path.is_symlink()
            for path in paths
        ),
        "tool receipt set has an extra or nonregular entry",
    )
    payloads: list[dict[str, Any]] = []
    receipt_hashes: set[str] = set()
    wrapper_pids: set[int] = set()
    tool_pids: set[int] = set()
    rustc_tool_pids: set[int] = set()
    build_script_tool_pids: set[int] = set()
    for path in paths:
        payload, receipt_sha256 = read_receipt(path)
        require(
            receipt_sha256 not in receipt_hashes,
            "tool receipt bytes are duplicated",
        )
        receipt_hashes.add(receipt_sha256)
        validate_tool_payload(
            payload,
            expected_wrapper_sha256=expected_wrapper_sha256,
            expected_sealer_sha256=expected_sealer_sha256,
            expected_launcher=expected_launcher,
            expected_python_runtime=expected_python_runtime,
            expected_tools=expected_tools,
        )
        lineage = payload["lineage"]
        require(
            lineage["wrapper_pid"] not in wrapper_pids
            and lineage["tool_pid"] not in tool_pids,
            "tool lineage child is represented more than once",
        )
        wrapper_pids.add(lineage["wrapper_pid"])
        tool_pids.add(lineage["tool_pid"])
        if payload["role"] == "rustc":
            rustc_tool_pids.add(lineage["tool_pid"])
        elif payload["role"] == "build-script":
            require(
                lineage["parent_pid"] == cargo_pid,
                "build-script wrapper is not one direct child of attested Cargo",
            )
            build_script_tool_pids.add(lineage["tool_pid"])
        payloads.append(payload)
    require(
        all(
            payload["role"] != "rustc"
            or payload["lineage"]["parent_pid"]
            in {cargo_pid, *build_script_tool_pids}
            for payload in payloads
        ),
        "rustc wrapper parent is not Cargo or one represented build script",
    )
    require(
        all(
            payload["role"] != "rustc"
            or payload["returncode"] == 0
            or payload["lineage"]["parent_pid"] in build_script_tool_pids
            for payload in payloads
        ),
        "failed rustc probe is not one represented build-script child",
    )
    require(
        all(
            payload["role"] != "linker"
            or payload["lineage"]["parent_pid"] in rustc_tool_pids
            for payload in payloads
        ),
        "linker wrapper is not one child of a represented rustc",
    )
    validate_build_script_coverage(payloads)
    projection = sorted(
        (normalized_projection(payload) for payload in payloads),
        key=canonical_bytes,
    )
    return projection, canonical_sha(projection)


def validate_final_link_candidates(
    projection: Sequence[Mapping[str, Any]],
    *,
    final_output: Path,
    required_candidates: Sequence[Mapping[str, str]],
) -> Mapping[str, Any]:
    final_rows = [
        row
        for row in projection
        if row["role"] == "linker"
        and row["output"]["path"] == str(final_output)
    ]
    require(len(final_rows) == 1, "final image link is missing or duplicated")
    final = final_rows[0]
    observed = [
        {
            "path": row["path"],
            "sha256": row["sha256"],
            "kind": row["kind"],
        }
        for row in final["input_rows"]
        if Path(row["path"]).name.startswith("external-search-")
    ]
    require(
        observed == list(required_candidates),
        "final image candidate input multiset differs from exact required objects",
    )
    return final


def compare_plan(
    observed_projection: Sequence[Mapping[str, Any]],
    expected_plan: Mapping[str, Any],
) -> None:
    require(
        set(expected_plan)
        == {
            "schema",
            "projection_sha256",
            "invocation_count",
            "rustc_invocation_count",
            "build_script_invocation_count",
            "linker_invocation_count",
            "projection",
        }
        and expected_plan["schema"] == PLAN_SCHEMA
        and expected_plan["projection_sha256"]
        == canonical_sha(expected_plan["projection"])
        and expected_plan["invocation_count"]
        == len(expected_plan["projection"])
        and expected_plan["rustc_invocation_count"]
        == sum(
            row["role"] == "rustc"
            for row in expected_plan["projection"]
        )
        and expected_plan["build_script_invocation_count"]
        == sum(
            row["role"] == "build-script"
            for row in expected_plan["projection"]
        )
        and expected_plan["linker_invocation_count"]
        == sum(
            row["role"] == "linker"
            for row in expected_plan["projection"]
        ),
        "preregistered construction plan changed",
    )
    require(
        list(observed_projection) == expected_plan["projection"],
        "construction invocation set differs from preregistration",
    )


def build_plan(projection: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    rows = list(projection)
    return {
        "schema": PLAN_SCHEMA,
        "projection_sha256": canonical_sha(rows),
        "invocation_count": len(rows),
        "rustc_invocation_count": sum(
            row["role"] == "rustc" for row in rows
        ),
        "build_script_invocation_count": sum(
            row["role"] == "build-script" for row in rows
        ),
        "linker_invocation_count": sum(
            row["role"] == "linker" for row in rows
        ),
        "projection": rows,
    }
