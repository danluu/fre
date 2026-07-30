#!/usr/bin/env python3
"""Verify that a production Count-v3 rebuild is the frozen qualified code.

This tool compares the authenticated, canonical build registries rather than
trusting paths or compiler self-report. It allows only the authority, source,
and content-addressed path fields to differ. Every Count-v3 machine-code,
object, metadata, expectation, optimizer, recipe, and facade-binding identity
must remain byte-for-byte identical.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence


QUALIFICATION_REGISTRY_SCHEMA = (
    "fre.optimizing-count-v3.compiled-artifact-registry.v2"
)
PRODUCTION_REGISTRY_SCHEMA = (
    "fre.optimizing-count-v3.production-confirmation-artifact-registry.v1"
)
IDENTITY_RECEIPT_SCHEMA = (
    "fre.optimizing-count-v3.production-code-identity-receipt.v1"
)
ENGINES = ("portable-current", "count-v2-current", "count-v3-aot")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_REGISTRY_BYTES = 64 * 1024 * 1024
MAX_ARTIFACTS = 16_384

GENERAL_ELIGIBILITY_FIELDS = {
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
}
COMMON_REGISTRY_FIELDS = (
    "distinct_artifacts",
    "input_policy",
    "inventory_identity",
    "inventory_sha256",
    "object_format",
    "required_isa",
    "target_contract_sha256",
    "target_id",
    "target_triple",
    "tuning_class",
)
QUALIFICATION_REGISTRY_FIELDS = {
    "artifact_root",
    "artifacts",
    "compiled_patterns",
    "distinct_artifacts",
    "input_policy",
    "inventory_identity",
    "inventory_sha256",
    "object_format",
    "production_authority",
    "qualification_authority",
    "required_isa",
    "schema",
    "source",
    "target_contract_sha256",
    "target_id",
    "target_triple",
    "tuning_class",
}
PRODUCTION_REGISTRY_FIELDS = QUALIFICATION_REGISTRY_FIELDS | {
    "build_authority",
    "cells",
    "promotion_authority_source_sha256",
    "promotion_manifest_sha256",
    "promotion_proposal_sha256",
}
PATTERN_FIELDS = {
    "claim_derivations",
    "engines",
    "input_policy",
    "optimizer_input_sha256",
    "pattern_input_id",
    "pattern_sha256",
    "planning_receipt_identity",
    "semantic_binding_identity",
}
ENGINE_FIELDS = {
    "artifact_file_path",
    "artifact_file_sha256",
    "artifact_id",
    "code_bytes",
    "compile_identity",
    "engine",
    "expectation_bytes_sha256",
    "expectation_file_path",
    "expectation_file_sha256",
    "expectation_identity",
    "expectation_symbol",
    "general_eligibility_tuple",
    "metadata_sha256",
    "object_bytes",
    "object_identity",
    "object_sha256",
    "optimizer_receipt_identity",
    "payload_bytes",
    "payload_sha256",
    "receipt_identity",
    "recipe_identity",
    "runtime_authority",
}
CAMPAIGN_ARTIFACT_FIELDS = {
    "artifact_file_path",
    "artifact_file_sha256",
    "artifact_id",
    "engine",
    "metadata_sha256",
    "pattern_sha256",
    "payload_sha256",
}
PATH_AND_AUTHORITY_ENGINE_FIELDS = {
    "artifact_file_path",
    "expectation_file_path",
    "runtime_authority",
}
CODE_IDENTITY_ENGINE_FIELDS = tuple(
    sorted(ENGINE_FIELDS - PATH_AND_AUTHORITY_ENGINE_FIELDS)
)
CODE_IDENTITY_PATTERN_FIELDS = tuple(sorted(PATTERN_FIELDS - {"engines"}))


class IdentityVerificationError(ValueError):
    """The production rebuild is not the frozen qualified Count-v3 code."""


def fail(message: str) -> None:
    raise IdentityVerificationError(message)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def reject_duplicate_pairs(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            fail(f"JSON object repeats key {key!r}")
        value[key] = item
    return value


def parse_registry_bytes(
    data: bytes, expected_sha256: str, label: str
) -> dict[str, Any]:
    require_hex(expected_sha256, f"{label} expected SHA-256")
    if not data or len(data) > MAX_REGISTRY_BYTES:
        fail(f"{label} has an invalid byte length")
    if sha256_bytes(data) != expected_sha256:
        fail(f"{label} SHA-256 differs from the frozen input")
    try:
        value = json.loads(
            data,
            object_pairs_hook=reject_duplicate_pairs,
            parse_constant=lambda token: fail(
                f"{label} contains non-finite number {token!r}"
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not strict JSON: {error}")
    registry = require_object(value, label)
    if canonical_json_bytes(registry) != data:
        fail(f"{label} is not compact sorted canonical JSON")
    return registry


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{label} is not an object")
    return value


def require_list(value: Any, label: str, maximum: int) -> list[Any]:
    if not isinstance(value, list) or len(value) > maximum:
        fail(f"{label} is not a bounded list")
    return value


def require_string(
    value: Any, label: str, pattern: re.Pattern[str] | None = None
) -> str:
    if not isinstance(value, str) or not value:
        fail(f"{label} is not a nonempty string")
    if pattern is not None and pattern.fullmatch(value) is None:
        fail(f"{label} has an invalid encoding")
    return value


def require_hex(value: Any, label: str) -> str:
    return require_string(value, label, HEX64)


def require_uint(value: Any, minimum: int, maximum: int, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value > maximum
    ):
        fail(f"{label} is outside its closed integer range")
    return value


def exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        fail(f"{label} fields differ from the closed schema")


def validate_eligibility(
    raw: Any, registry: Mapping[str, Any], label: str
) -> dict[str, Any]:
    value = require_object(raw, label)
    exact_keys(value, GENERAL_ELIGIBILITY_FIELDS, label)
    if value["little_endian"] is not True:
        fail(f"{label}.little_endian must be true")
    for field in GENERAL_ELIGIBILITY_FIELDS - {"little_endian"}:
        require_uint(value[field], 0, (1 << 64) - 1, f"{label}.{field}")
    fixed = {
        "compiler_version": 3,
        "metadata_version": 3,
        "image_schema_version": 3,
        "backend_version": 0xA003,
        "algorithm_version": 11,
        "auditor_version": 2,
        "kir_semantics_version": 1,
        "kir_abi_version": 1,
        "recipe_schema_version": 3,
        "optimizer_version": 7,
        "call_abi_schema": 2,
        "abi_kind": 2,
        "status_bits": 64,
        "output_kind": 1,
        "architecture": 1,
        "pointer_width": 64,
        "target_abi": 1,
        "candidate_block_starts": 16,
        "vector_bytes": 16,
        "max_literal_bytes": 32,
    }
    for field, expected in fixed.items():
        if value[field] != expected:
            fail(f"{label}.{field} is outside the closed Count-v3 support row")
    expected_tuning = {
        "generic-aarch64": 1,
        "apple-m-series": 2,
        "neoverse-v2-v3": 3,
    }.get(registry["tuning_class"])
    if expected_tuning is None or value["tuning_class_id"] != expected_tuning:
        fail(f"{label} does not match the registry tuning class")
    expected_triple = {
        "macho-arm64": "aarch64-apple-darwin",
        "elf64-aarch64": "aarch64-unknown-linux-gnu",
    }.get(registry["object_format"])
    if expected_triple is None or registry["target_triple"] != expected_triple:
        fail(f"{label} registry object format and target triple disagree")
    required_isa = registry["required_isa"]
    expected_target = {
        "neon": (1, 1, 1, 0, {"macho-arm64": 1, "elf64-aarch64": 2}),
        "sve-vl16": (2, 4, 3, 16, {"elf64-aarch64": 2}),
        "sve2-vl16": (3, 5, 7, 16, {"elf64-aarch64": 2}),
    }.get(required_isa)
    if expected_target is None:
        fail(f"{label} registry ISA is outside the closed target set")
    (
        expected_isa,
        expected_plan,
        expected_features,
        expected_vl,
        expected_formats,
    ) = expected_target
    expected_format_id = expected_formats.get(registry["object_format"])
    if (
        expected_format_id is None
        or value["object_format"] != expected_format_id
        or value["required_isa_id"] != expected_isa
        or value["register_plan_id"] != expected_plan
        or value["actual_features"] != expected_features
        or value["allowed_features"] != expected_features
        or value["sve_vector_length_bytes"] != expected_vl
    ):
        fail(f"{label} does not match the exact hybrid Count-v3 target row")
    return dict(value)


def validate_engine(
    raw: Any,
    expected_engine: str,
    expected_authority: str,
    registry: Mapping[str, Any],
    label: str,
) -> dict[str, Any]:
    value = require_object(raw, label)
    exact_keys(value, ENGINE_FIELDS, label)
    if value["engine"] != expected_engine:
        fail(f"{label} is outside canonical engine order")
    expected_runtime = (
        expected_authority if expected_engine == "count-v3-aot" else "control"
    )
    if value["runtime_authority"] != expected_runtime:
        fail(f"{label} has the wrong runtime authority")
    for field in (
        "artifact_file_sha256",
        "artifact_id",
        "metadata_sha256",
        "payload_sha256",
    ):
        require_hex(value[field], f"{label}.{field}")
    require_string(value["artifact_file_path"], f"{label}.artifact_file_path")
    if expected_engine == "count-v3-aot":
        for field in (
            "compile_identity",
            "expectation_bytes_sha256",
            "expectation_file_sha256",
            "expectation_identity",
            "object_identity",
            "object_sha256",
            "optimizer_receipt_identity",
            "recipe_identity",
        ):
            require_hex(value[field], f"{label}.{field}")
        require_string(
            value["expectation_file_path"], f"{label}.expectation_file_path"
        )
        expectation_symbol = require_string(
            value["expectation_symbol"], f"{label}.expectation_symbol"
        )
        if expectation_symbol != (
            f"fre_aot_count_expectation_v3_{value['compile_identity']}"
        ):
            fail(f"{label}.expectation_symbol is not compile_identity suffixed")
        for field in ("code_bytes", "object_bytes", "payload_bytes"):
            require_uint(value[field], 1, 1 << 32, f"{label}.{field}")
        if value["artifact_file_sha256"] != value["object_sha256"]:
            fail(
                f"{label}.artifact_file_sha256 and object_sha256 differ"
            )
        if value["receipt_identity"] is not None:
            fail(f"{label}.receipt_identity must be null")
        validate_eligibility(
            value["general_eligibility_tuple"], registry, f"{label}.tuple"
        )
    elif value["general_eligibility_tuple"] is not None:
        fail(f"{label} control engine gained a Count-v3 tuple")
    return value


def project_registry(
    registry: Mapping[str, Any], production: bool, label: str
) -> dict[str, dict[str, Any]]:
    expected_fields = (
        PRODUCTION_REGISTRY_FIELDS
        if production
        else QUALIFICATION_REGISTRY_FIELDS
    )
    exact_keys(registry, expected_fields, label)
    if production:
        if (
            registry["schema"] != PRODUCTION_REGISTRY_SCHEMA
            or registry["build_authority"] != "production"
            or registry["production_authority"]
            != "source-reviewed-tuples-required"
            or registry["qualification_authority"] != "absent"
        ):
            fail(f"{label} production authority binding differs")
        expected_authority = "production"
        for field in (
            "promotion_authority_source_sha256",
            "promotion_manifest_sha256",
            "promotion_proposal_sha256",
        ):
            require_hex(registry[field], f"{label}.{field}")
        require_list(registry["cells"], f"{label}.cells", 16_384)
    else:
        if (
            registry["schema"] != QUALIFICATION_REGISTRY_SCHEMA
            or registry["production_authority"] != "absent"
            or registry["qualification_authority"] != "private-only"
        ):
            fail(f"{label} qualification authority binding differs")
        expected_authority = "qualification-private"
    for field in (
        "inventory_identity",
        "inventory_sha256",
        "target_contract_sha256",
    ):
        require_hex(registry[field], f"{label}.{field}")
    for field in (
        "input_policy",
        "object_format",
        "required_isa",
        "target_id",
        "target_triple",
        "tuning_class",
    ):
        require_string(registry[field], f"{label}.{field}")
    require_object(registry["source"], f"{label}.source")
    require_string(registry["artifact_root"], f"{label}.artifact_root")

    patterns = require_list(
        registry["compiled_patterns"], f"{label}.compiled_patterns", MAX_ARTIFACTS
    )
    if not patterns:
        fail(f"{label} has no compiled patterns")
    if require_uint(
        registry["distinct_artifacts"],
        1,
        MAX_ARTIFACTS,
        f"{label}.distinct_artifacts",
    ) != len(patterns):
        fail(f"{label} distinct artifact count differs")

    projected: dict[str, dict[str, Any]] = {}
    engines_by_pattern: dict[str, dict[str, Any]] = {}
    for ordinal, raw_pattern in enumerate(patterns):
        pattern_label = f"{label}.compiled_patterns[{ordinal}]"
        pattern = require_object(raw_pattern, pattern_label)
        exact_keys(pattern, PATTERN_FIELDS, pattern_label)
        pattern_sha256 = require_hex(
            pattern["pattern_sha256"], f"{pattern_label}.pattern_sha256"
        )
        if pattern_sha256 in projected:
            fail(f"{label} repeats pattern {pattern_sha256}")
        for field in (
            "optimizer_input_sha256",
            "planning_receipt_identity",
            "semantic_binding_identity",
        ):
            require_hex(pattern[field], f"{pattern_label}.{field}")
        require_string(pattern["pattern_input_id"], f"{pattern_label}.pattern_input_id")
        if pattern["input_policy"] != registry["input_policy"]:
            fail(f"{pattern_label}.input_policy differs from the registry")
        require_object(pattern["claim_derivations"], f"{pattern_label}.claim_derivations")
        engines = require_list(pattern["engines"], f"{pattern_label}.engines", 3)
        if len(engines) != 3:
            fail(f"{pattern_label} lacks the exact three-engine matrix")
        normalized_engines = [
            validate_engine(
                row,
                engine,
                expected_authority,
                registry,
                f"{pattern_label}.{engine}",
            )
            for row, engine in zip(engines, ENGINES, strict=True)
        ]
        v3 = normalized_engines[2]
        projection = {
            field: pattern[field] for field in CODE_IDENTITY_PATTERN_FIELDS
        }
        projection["count_v3_code"] = {
            field: v3[field] for field in CODE_IDENTITY_ENGINE_FIELDS
        }
        projected[pattern_sha256] = projection
        engines_by_pattern[pattern_sha256] = v3

    artifacts = require_list(
        registry["artifacts"],
        f"{label}.artifacts",
        MAX_ARTIFACTS * len(ENGINES),
    )
    if len(artifacts) != len(patterns) * len(ENGINES):
        fail(f"{label} campaign artifact matrix is incomplete")
    seen: set[tuple[str, str]] = set()
    for ordinal, raw_artifact in enumerate(artifacts):
        artifact_label = f"{label}.artifacts[{ordinal}]"
        artifact = require_object(raw_artifact, artifact_label)
        exact_keys(artifact, CAMPAIGN_ARTIFACT_FIELDS, artifact_label)
        pattern_sha256 = require_hex(
            artifact["pattern_sha256"], f"{artifact_label}.pattern_sha256"
        )
        engine = require_string(artifact["engine"], f"{artifact_label}.engine")
        require_string(
            artifact["artifact_file_path"],
            f"{artifact_label}.artifact_file_path",
        )
        for field in (
            "artifact_file_sha256",
            "artifact_id",
            "metadata_sha256",
            "payload_sha256",
        ):
            require_hex(artifact[field], f"{artifact_label}.{field}")
        key = (pattern_sha256, engine)
        if (
            pattern_sha256 not in projected
            or engine not in ENGINES
            or key in seen
        ):
            fail(f"{artifact_label} escapes the unique artifact matrix")
        seen.add(key)
        if engine == "count-v3-aot":
            v3 = engines_by_pattern[pattern_sha256]
            for field in (
                "artifact_file_sha256",
                "artifact_id",
                "metadata_sha256",
                "payload_sha256",
            ):
                if artifact[field] != v3[field]:
                    fail(f"{artifact_label}.{field} differs from compiled pattern")
    return projected


def verify_identity_bytes(
    qualification_bytes: bytes,
    qualification_sha256: str,
    production_bytes: bytes,
    production_sha256: str,
    verifier_source_sha256: str,
) -> dict[str, Any]:
    require_hex(verifier_source_sha256, "verifier source SHA-256")
    qualification = parse_registry_bytes(
        qualification_bytes, qualification_sha256, "qualification registry"
    )
    production = parse_registry_bytes(
        production_bytes, production_sha256, "production registry"
    )
    qualified_projection = project_registry(
        qualification, False, "qualification registry"
    )
    production_projection = project_registry(
        production, True, "production registry"
    )
    for field in COMMON_REGISTRY_FIELDS:
        if qualification[field] != production[field]:
            fail(f"production registry changed frozen field {field}")
    if set(qualified_projection) != set(production_projection):
        fail("production registry changed the frozen compiled pattern set")
    for pattern_sha256 in sorted(qualified_projection):
        if qualified_projection[pattern_sha256] != production_projection[pattern_sha256]:
            qualified = qualified_projection[pattern_sha256]
            rebuilt = production_projection[pattern_sha256]
            for field in CODE_IDENTITY_PATTERN_FIELDS:
                if qualified[field] != rebuilt[field]:
                    fail(
                        f"production pattern {pattern_sha256} changed frozen field {field}"
                    )
            qualified_code = qualified["count_v3_code"]
            rebuilt_code = rebuilt["count_v3_code"]
            for field in CODE_IDENTITY_ENGINE_FIELDS:
                if qualified_code[field] != rebuilt_code[field]:
                    fail(
                        f"production pattern {pattern_sha256} changed frozen "
                        f"Count-v3 field {field}"
                    )
            fail(f"production pattern {pattern_sha256} changed frozen code identity")
    identity_rows = [
        qualified_projection[pattern_sha256]
        for pattern_sha256 in sorted(qualified_projection)
    ]
    identity_set_sha256 = sha256_bytes(canonical_json_bytes(identity_rows))
    return {
        "compared_artifacts": len(identity_rows),
        "compared_count_v3_fields": list(CODE_IDENTITY_ENGINE_FIELDS),
        "identity_projection_sha256": identity_set_sha256,
        "production_registry_sha256": production_sha256,
        "qualification_registry_sha256": qualification_sha256,
        "schema": IDENTITY_RECEIPT_SCHEMA,
        "status": "pass",
        "target_contract_sha256": production["target_contract_sha256"],
        "target_id": production["target_id"],
        "verifier_source_sha256": verifier_source_sha256,
    }


def read_frozen_file(path: Path, maximum: int, label: str) -> bytes:
    if not path.is_absolute():
        fail(f"{label} path is not absolute")
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        fail(f"{label} is not a regular non-symlink file")
    if before.st_size <= 0 or before.st_size > maximum:
        fail(f"{label} has an invalid byte length")
    with path.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        data = handle.read(maximum + 1)
        after = os.fstat(handle.fileno())
    final = path.lstat()
    identity = lambda info: (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )
    if (
        len(data) > maximum
        or identity(before) != identity(opened)
        or identity(opened) != identity(after)
        or identity(after) != identity(final)
    ):
        fail(f"{label} changed while reading")
    return data


def write_create_only(path: Path, value: Mapping[str, Any]) -> None:
    if not path.is_absolute():
        fail("output receipt path is not absolute")
    parent = path.parent
    parent_info = parent.lstat()
    if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
        fail("output receipt parent is not a real directory")
    data = canonical_json_bytes(value) + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o444)
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                fail("short write while sealing identity receipt")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, 0o444)


def main(argv: Sequence[str]) -> int:
    if len(argv) != 6:
        print(
            "usage: verify_production_identity.py "
            "QUALIFICATION_REGISTRY QUALIFICATION_SHA256 "
            "PRODUCTION_REGISTRY PRODUCTION_SHA256 OUTPUT_RECEIPT",
            file=sys.stderr,
        )
        return 2
    try:
        qualification_path = Path(argv[1])
        production_path = Path(argv[3])
        source_path = Path(__file__).resolve(strict=True)
        source_bytes = read_frozen_file(
            source_path, 4 * 1024 * 1024, "verifier source"
        )
        receipt = verify_identity_bytes(
            read_frozen_file(
                qualification_path,
                MAX_REGISTRY_BYTES,
                "qualification registry",
            ),
            argv[2],
            read_frozen_file(
                production_path,
                MAX_REGISTRY_BYTES,
                "production registry",
            ),
            argv[4],
            sha256_bytes(source_bytes),
        )
        write_create_only(Path(argv[5]), receipt)
    except (IdentityVerificationError, OSError) as error:
        print(f"production code identity verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
