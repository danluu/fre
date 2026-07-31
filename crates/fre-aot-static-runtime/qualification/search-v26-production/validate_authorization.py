#!/usr/bin/env python3
"""Strict, read-only V26 production authorization and inventory validator.

The validator never edits source or renders an authority atom. Reviewed inputs
must be externally supplied, SHA-pinned, owned mode-0600 regular files with one
link. The V26 runtime remains inert even after this command returns PASS.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

AUTH_SCHEMA = "fre.aot.search-v26-production-authorization.v1"
INVENTORY_SCHEMA = "fre.aot.search-v26-production-source-inventory.v1"
BACKEND_TAG = 39
IMAGE_MAGIC = 0x27
CANDIDATE_MIN = 6
PORTABLE_MAX = 8
PRODUCTION_MIN = 9
MAX_LITERAL = 32
MAX_AUTH_BYTES = 64 * 1024
MAX_INVENTORY_BYTES = 8 * 1024 * 1024
MAX_SOURCES = 4096
GLUE_PREFIX = "fre_aot_search_span_glue_v1_"
ZERO20 = "0" * 40
ZERO32 = "0" * 64

AUTH_TOP_KEYS = (
    "schema",
    "state",
    "production_authority",
    "predecessor",
    "source",
    "compiler_architecture",
    "qualification",
    "review",
    "routing",
    "family",
    "targets",
)
PREDECESSOR_KEYS = (
    "v25_terminal_decision",
    "v25_terminal_analysis_sha256",
)
SOURCE_KEYS = ("commit", "tree")
ARCHITECTURE_KEYS = (
    "backend_tag",
    "image_magic",
    "regex_codegen",
    "regex_codegen_uses_llvm",
    "architecture_review_sha256",
)
QUALIFICATION_KEYS = (
    "campaign_is_fresh_and_disjoint_from_v25",
    "campaign_contract_sha256",
    "development_decision",
    "development_pass_sha256",
    "correctness_decision",
    "two_host_correctness_gate_sha256",
    "heldout_decision",
    "heldout_pass_sha256",
    "heldout_analysis_sha256",
)
REVIEW_KEYS = (
    "production_review_sha256",
    "authorization_sha256",
    "source_inventory_review_sha256",
)
ROUTING_KEYS = (
    "candidate_minimum_literal_bytes",
    "portable_max_literal_bytes",
    "production_minimum_literal_bytes",
    "maximum_literal_bytes",
    "short_width_route",
    "short_width_production_authority",
)
FAMILY_KEYS = (
    "selector",
    "minimum_window_bytes",
    "portable_prefix_candidate_starts",
    "plan_identity",
    "analyzer_identity",
    "evidence_identity",
)
TARGET_KEYS = ("macos_aarch64", "linux_aarch64")
TARGET_AUTH_KEYS = (
    "manifest_identity",
    "build_receipt_sha256",
    "final_image_review_sha256",
)
INVENTORY_TOP_KEYS = (
    "schema",
    "state",
    "production_authority",
    "authorization_decision_sha256",
    "backend_tag",
    "minimum_literal_bytes",
    "maximum_literal_bytes",
    "family_selector",
    "canonical_order",
    "sources",
    "each_source_common_requires",
    "each_source_target_requires",
    "cross_target_equalities_require_explicit_derivation_receipt",
)
SOURCE_COMMON_FIELDS = (
    "source_sha256",
    "semantic_binding_identity",
    "literal_bytes",
    "literal_sha256",
    "tag39_shape_admission_receipt_sha256",
)
SOURCE_RECORD_KEYS = SOURCE_COMMON_FIELDS + ("targets", "cross_target_equalities")
TARGET_SOURCE_FIELDS = (
    "manifest_identity",
    "literal_identity",
    "kir_identity",
    "artifact_identity",
    "binding_identity",
    "compile_identity",
    "object_identity",
    "receipt_identity",
    "expectation_identity",
    "payload_identity",
    "compile_receipt_sha256",
    "implementation_object_sha256",
    "expectation_sha256",
    "production_glue_object_sha256",
    "production_glue_receipt_sha256",
    "identity_suffixed_glue_symbol",
    "final_image_inspection_receipt_sha256",
    "independent_derivation_receipt_sha256",
)
EQUALITY_KEYS = ("field", "independent_derivation_receipt_sha256")


class Refusal(ValueError):
    """Input is not the exact closed V26 authorization grammar."""


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise Refusal(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_float(value: str) -> Any:
    raise Refusal(f"floating-point JSON value is forbidden: {value}")


def _reject_constant(value: str) -> Any:
    raise Refusal(f"non-finite JSON value is forbidden: {value}")


def _load_json(raw: bytes, label: str, maximum: int) -> dict[str, Any]:
    if not raw or len(raw) > maximum:
        raise Refusal(f"{label} size is outside 1..={maximum}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise Refusal(f"{label} is not UTF-8") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_pairs,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, Refusal) as error:
        if isinstance(error, Refusal):
            raise
        raise Refusal(f"{label} is not strict JSON: {error}") from error
    if type(value) is not dict:
        raise Refusal(f"{label} root must be an object")
    return value


def _exact_object(value: Any, label: str, keys: tuple[str, ...]) -> dict[str, Any]:
    if type(value) is not dict:
        raise Refusal(f"{label} must be an object")
    actual = set(value)
    expected = set(keys)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise Refusal(f"{label} keys differ; missing={missing}, extra={extra}")
    return value


def _exact(value: Any, expected: Any, label: str) -> None:
    if type(value) is not type(expected) or value != expected:
        raise Refusal(f"{label} must equal {expected!r}")


def _integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise Refusal(f"{label} must be an integer in {minimum}..={maximum}")
    return value


def _hex(value: Any, label: str, digits: int) -> str:
    if (
        type(value) is not str
        or len(value) != digits
        or value.lower() != value
        or any(character not in "0123456789abcdef" for character in value)
        or value == "0" * digits
    ):
        raise Refusal(f"{label} must be one nonzero lowercase {digits}-digit identity")
    return value


def _sha256(value: Any, label: str) -> str:
    return _hex(value, label, 64)


def _git_identity(value: Any, label: str) -> str:
    return _hex(value, label, 40)


def _targets(value: Any, label: str) -> dict[str, Any]:
    return _exact_object(value, label, TARGET_KEYS)


def parse_reviewed_authorization_bytes(
    raw: bytes, label: str = "authorization.json"
) -> dict[str, Any]:
    authorization = _exact_object(
        _load_json(raw, label, MAX_AUTH_BYTES), label, AUTH_TOP_KEYS
    )
    _exact(authorization["schema"], AUTH_SCHEMA, f"{label}.schema")
    _exact(
        authorization["state"],
        "reviewed-production-authorization",
        f"{label}.state",
    )
    _exact(authorization["production_authority"], True, f"{label}.production_authority")

    predecessor = _exact_object(
        authorization["predecessor"], f"{label}.predecessor", PREDECESSOR_KEYS
    )
    _exact(
        predecessor["v25_terminal_decision"],
        "FAIL",
        f"{label}.predecessor.v25_terminal_decision",
    )
    _sha256(
        predecessor["v25_terminal_analysis_sha256"],
        f"{label}.predecessor.v25_terminal_analysis_sha256",
    )

    source = _exact_object(authorization["source"], f"{label}.source", SOURCE_KEYS)
    source_commit = _git_identity(source["commit"], f"{label}.source.commit")
    source_tree = _git_identity(source["tree"], f"{label}.source.tree")
    if source_commit == source_tree:
        raise Refusal(f"{label} source commit and tree must be distinct typed Git objects")

    architecture = _exact_object(
        authorization["compiler_architecture"],
        f"{label}.compiler_architecture",
        ARCHITECTURE_KEYS,
    )
    _exact(architecture["backend_tag"], BACKEND_TAG, f"{label}.backend_tag")
    _exact(architecture["image_magic"], IMAGE_MAGIC, f"{label}.image_magic")
    _exact(
        architecture["regex_codegen"],
        "self-contained-fre-aarch64-search-v26",
        f"{label}.compiler_architecture.regex_codegen",
    )
    _exact(
        architecture["regex_codegen_uses_llvm"],
        False,
        f"{label}.compiler_architecture.regex_codegen_uses_llvm",
    )
    _sha256(
        architecture["architecture_review_sha256"],
        f"{label}.compiler_architecture.architecture_review_sha256",
    )

    qualification = _exact_object(
        authorization["qualification"],
        f"{label}.qualification",
        QUALIFICATION_KEYS,
    )
    _exact(
        qualification["campaign_is_fresh_and_disjoint_from_v25"],
        True,
        f"{label}.qualification.campaign_is_fresh_and_disjoint_from_v25",
    )
    for decision in (
        "development_decision",
        "correctness_decision",
        "heldout_decision",
    ):
        _exact(qualification[decision], "PASS", f"{label}.qualification.{decision}")
    for field in (
        "campaign_contract_sha256",
        "development_pass_sha256",
        "two_host_correctness_gate_sha256",
        "heldout_pass_sha256",
        "heldout_analysis_sha256",
    ):
        _sha256(qualification[field], f"{label}.qualification.{field}")

    review = _exact_object(authorization["review"], f"{label}.review", REVIEW_KEYS)
    review_hashes = [_sha256(review[field], f"{label}.review.{field}") for field in REVIEW_KEYS]
    if len(set(review_hashes)) != len(review_hashes):
        raise Refusal(f"{label} review domains must have distinct receipts")

    routing = _exact_object(
        authorization["routing"], f"{label}.routing", ROUTING_KEYS
    )
    _exact(
        routing["candidate_minimum_literal_bytes"],
        CANDIDATE_MIN,
        f"{label}.routing.candidate_minimum_literal_bytes",
    )
    _exact(
        routing["portable_max_literal_bytes"],
        PORTABLE_MAX,
        f"{label}.routing.portable_max_literal_bytes",
    )
    _exact(
        routing["production_minimum_literal_bytes"],
        PRODUCTION_MIN,
        f"{label}.routing.production_minimum_literal_bytes",
    )
    _exact(
        routing["maximum_literal_bytes"],
        MAX_LITERAL,
        f"{label}.routing.maximum_literal_bytes",
    )
    _exact(
        routing["short_width_route"],
        "existing-non-v26",
        f"{label}.routing.short_width_route",
    )
    _exact(
        routing["short_width_production_authority"],
        False,
        f"{label}.routing.short_width_production_authority",
    )
    if PORTABLE_MAX + 1 != PRODUCTION_MIN:
        raise Refusal("internal V26 routing contract lost the frozen 8+1=9 boundary")

    family = _exact_object(
        authorization["family"], f"{label}.family", FAMILY_KEYS
    )
    _integer(family["selector"], f"{label}.family.selector", 1, 65535)
    minimum_window = _integer(
        family["minimum_window_bytes"],
        f"{label}.family.minimum_window_bytes",
        1,
        2**32 - 1,
    )
    prefix = _integer(
        family["portable_prefix_candidate_starts"],
        f"{label}.family.portable_prefix_candidate_starts",
        1,
        2**32 - 1,
    )
    if minimum_window < prefix + MAX_LITERAL - 1:
        raise Refusal(f"{label} family floor cannot contain its complete portable prefix")
    for field in ("plan_identity", "analyzer_identity", "evidence_identity"):
        _sha256(family[field], f"{label}.family.{field}")

    targets = _targets(authorization["targets"], f"{label}.targets")
    target_records: list[dict[str, Any]] = []
    for target in TARGET_KEYS:
        record = _exact_object(
            targets[target], f"{label}.targets.{target}", TARGET_AUTH_KEYS
        )
        for field in TARGET_AUTH_KEYS:
            _sha256(record[field], f"{label}.targets.{target}.{field}")
        target_records.append(record)
    for field in TARGET_AUTH_KEYS:
        if target_records[0][field] == target_records[1][field]:
            raise Refusal(f"{label} target-specific {field} must be independently derived")

    return authorization


def parse_template_bytes(raw: bytes, label: str = "authorization template") -> None:
    template = _exact_object(
        _load_json(raw, label, MAX_AUTH_BYTES), label, AUTH_TOP_KEYS
    )
    _exact(template["schema"], AUTH_SCHEMA, f"{label}.schema")
    _exact(template["state"], "unactivated-template", f"{label}.state")
    _exact(template["production_authority"], False, f"{label}.production_authority")
    predecessor = _exact_object(
        template["predecessor"], f"{label}.predecessor", PREDECESSOR_KEYS
    )
    _exact(predecessor["v25_terminal_decision"], "FAIL", f"{label}.v25 decision")
    _exact(predecessor["v25_terminal_analysis_sha256"], None, f"{label}.v25 receipt")
    architecture = _exact_object(
        template["compiler_architecture"],
        f"{label}.compiler_architecture",
        ARCHITECTURE_KEYS,
    )
    _exact(architecture["backend_tag"], BACKEND_TAG, f"{label}.backend_tag")
    _exact(architecture["image_magic"], IMAGE_MAGIC, f"{label}.image_magic")
    _exact(
        architecture["regex_codegen"],
        "self-contained-fre-aarch64-search-v26",
        f"{label}.regex_codegen",
    )
    _exact(architecture["regex_codegen_uses_llvm"], False, f"{label}.LLVM")
    _exact(
        architecture["architecture_review_sha256"],
        None,
        f"{label}.architecture_review_sha256",
    )
    source = _exact_object(template["source"], f"{label}.source", SOURCE_KEYS)
    for field in SOURCE_KEYS:
        _exact(source[field], None, f"{label}.source.{field}")
    qualification = _exact_object(
        template["qualification"], f"{label}.qualification", QUALIFICATION_KEYS
    )
    _exact(
        qualification["campaign_is_fresh_and_disjoint_from_v25"],
        True,
        f"{label}.qualification.campaign_is_fresh_and_disjoint_from_v25",
    )
    for field in (
        "development_decision",
        "correctness_decision",
        "heldout_decision",
    ):
        _exact(qualification[field], "PASS", f"{label}.qualification.{field}")
    for field in (
        "campaign_contract_sha256",
        "development_pass_sha256",
        "two_host_correctness_gate_sha256",
        "heldout_pass_sha256",
        "heldout_analysis_sha256",
    ):
        _exact(qualification[field], None, f"{label}.qualification.{field}")
    review = _exact_object(template["review"], f"{label}.review", REVIEW_KEYS)
    for field in REVIEW_KEYS:
        _exact(review[field], None, f"{label}.review.{field}")
    routing = _exact_object(template["routing"], f"{label}.routing", ROUTING_KEYS)
    fixed = {
        "candidate_minimum_literal_bytes": CANDIDATE_MIN,
        "portable_max_literal_bytes": PORTABLE_MAX,
        "production_minimum_literal_bytes": PRODUCTION_MIN,
        "maximum_literal_bytes": MAX_LITERAL,
        "short_width_route": "existing-non-v26",
        "short_width_production_authority": False,
    }
    for field, expected in fixed.items():
        _exact(routing[field], expected, f"{label}.routing.{field}")
    family = _exact_object(template["family"], f"{label}.family", FAMILY_KEYS)
    for field in FAMILY_KEYS:
        _exact(family[field], None, f"{label}.family.{field}")
    targets = _targets(template["targets"], f"{label}.targets")
    for target in TARGET_KEYS:
        record = _exact_object(
            targets[target], f"{label}.targets.{target}", TARGET_AUTH_KEYS
        )
        for field in TARGET_AUTH_KEYS:
            _exact(record[field], None, f"{label}.targets.{target}.{field}")


def parse_reviewed_inventory_bytes(
    raw: bytes,
    authorization: dict[str, Any],
    label: str = "source-inventory.json",
) -> dict[str, Any]:
    inventory = _exact_object(
        _load_json(raw, label, MAX_INVENTORY_BYTES), label, INVENTORY_TOP_KEYS
    )
    _exact(inventory["schema"], INVENTORY_SCHEMA, f"{label}.schema")
    _exact(
        inventory["state"],
        "reviewed-production-source-inventory",
        f"{label}.state",
    )
    _exact(inventory["production_authority"], True, f"{label}.production_authority")
    _exact(
        inventory["authorization_decision_sha256"],
        authorization["review"]["authorization_sha256"],
        f"{label}.authorization_decision_sha256",
    )
    _exact(inventory["backend_tag"], BACKEND_TAG, f"{label}.backend_tag")
    _exact(
        inventory["minimum_literal_bytes"],
        PRODUCTION_MIN,
        f"{label}.minimum_literal_bytes",
    )
    _exact(
        inventory["maximum_literal_bytes"],
        MAX_LITERAL,
        f"{label}.maximum_literal_bytes",
    )
    _exact(
        inventory["family_selector"],
        authorization["family"]["selector"],
        f"{label}.family_selector",
    )
    _exact(
        inventory["canonical_order"],
        "semantic_binding_identity_then_source_sha256",
        f"{label}.canonical_order",
    )
    _exact(
        inventory["each_source_common_requires"],
        list(SOURCE_COMMON_FIELDS),
        f"{label}.each_source_common_requires",
    )
    target_requirements = _exact_object(
        inventory["each_source_target_requires"],
        f"{label}.each_source_target_requires",
        TARGET_KEYS,
    )
    for target in TARGET_KEYS:
        _exact(
            target_requirements[target],
            list(TARGET_SOURCE_FIELDS),
            f"{label}.each_source_target_requires.{target}",
        )
    _exact(
        inventory["cross_target_equalities_require_explicit_derivation_receipt"],
        True,
        f"{label}.cross_target_equalities_require_explicit_derivation_receipt",
    )

    sources = inventory["sources"]
    if type(sources) is not list or not 1 <= len(sources) <= MAX_SOURCES:
        raise Refusal(f"{label}.sources must contain 1..={MAX_SOURCES} records")
    previous_order: tuple[str, str] | None = None
    seen_sources: set[str] = set()
    seen_semantics: set[str] = set()
    for index, value in enumerate(sources):
        source_label = f"{label}.sources[{index}]"
        source = _exact_object(value, source_label, SOURCE_RECORD_KEYS)
        source_sha = _sha256(source["source_sha256"], f"{source_label}.source_sha256")
        semantic = _sha256(
            source["semantic_binding_identity"],
            f"{source_label}.semantic_binding_identity",
        )
        literal_bytes = _integer(
            source["literal_bytes"],
            f"{source_label}.literal_bytes",
            PRODUCTION_MIN,
            MAX_LITERAL,
        )
        _sha256(source["literal_sha256"], f"{source_label}.literal_sha256")
        _sha256(
            source["tag39_shape_admission_receipt_sha256"],
            f"{source_label}.tag39_shape_admission_receipt_sha256",
        )
        order = (semantic, source_sha)
        if previous_order is not None and previous_order >= order:
            raise Refusal(f"{label}.sources are not in strict canonical order")
        previous_order = order
        if source_sha in seen_sources:
            raise Refusal(f"{label} repeats source_sha256 {source_sha}")
        seen_sources.add(source_sha)
        if semantic in seen_semantics:
            raise Refusal(f"{label} repeats semantic_binding_identity {semantic}")
        seen_semantics.add(semantic)

        targets = _targets(source["targets"], f"{source_label}.targets")
        parsed_targets: dict[str, dict[str, str]] = {}
        for target in TARGET_KEYS:
            record = _exact_object(
                targets[target], f"{source_label}.targets.{target}", TARGET_SOURCE_FIELDS
            )
            parsed: dict[str, str] = {}
            for field in TARGET_SOURCE_FIELDS:
                if field == "identity_suffixed_glue_symbol":
                    compile_identity = _sha256(
                        record["compile_identity"],
                        f"{source_label}.targets.{target}.compile_identity",
                    )
                    expected_symbol = GLUE_PREFIX + compile_identity
                    _exact(
                        record[field],
                        expected_symbol,
                        f"{source_label}.targets.{target}.{field}",
                    )
                    parsed[field] = expected_symbol
                else:
                    parsed[field] = _sha256(
                        record[field], f"{source_label}.targets.{target}.{field}"
                    )
            _exact(
                parsed["manifest_identity"],
                authorization["targets"][target]["manifest_identity"],
                f"{source_label}.targets.{target}.manifest_identity",
            )
            parsed_targets[target] = parsed

        if (
            parsed_targets["macos_aarch64"]["independent_derivation_receipt_sha256"]
            == parsed_targets["linux_aarch64"][
                "independent_derivation_receipt_sha256"
            ]
        ):
            raise Refusal(f"{source_label} target derivation receipts must differ")

        equality_records = source["cross_target_equalities"]
        if type(equality_records) is not list:
            raise Refusal(f"{source_label}.cross_target_equalities must be an array")
        equality_fields: list[str] = []
        equality_receipts: set[str] = set()
        for equality_index, equality_value in enumerate(equality_records):
            equality_label = (
                f"{source_label}.cross_target_equalities[{equality_index}]"
            )
            equality = _exact_object(equality_value, equality_label, EQUALITY_KEYS)
            field = equality["field"]
            if type(field) is not str or field not in TARGET_SOURCE_FIELDS:
                raise Refusal(f"{equality_label}.field is not a target field")
            receipt = _sha256(
                equality["independent_derivation_receipt_sha256"],
                f"{equality_label}.independent_derivation_receipt_sha256",
            )
            if receipt in equality_receipts:
                raise Refusal(f"{source_label} repeats an equality derivation receipt")
            equality_receipts.add(receipt)
            equality_fields.append(field)
        if equality_fields != sorted(set(equality_fields)):
            raise Refusal(f"{source_label}.cross_target_equalities are not canonical")
        actual_equalities = sorted(
            field
            for field in TARGET_SOURCE_FIELDS
            if field != "independent_derivation_receipt_sha256"
            and parsed_targets["macos_aarch64"][field]
            == parsed_targets["linux_aarch64"][field]
        )
        if equality_fields != actual_equalities:
            raise Refusal(
                f"{source_label} cross-target equality declarations differ from values"
            )
        target_derivation_receipts = {
            parsed_targets[target]["independent_derivation_receipt_sha256"]
            for target in TARGET_KEYS
        }
        if equality_receipts & target_derivation_receipts:
            raise Refusal(
                f"{source_label} equality and target derivation receipts must be disjoint"
            )
        if not PRODUCTION_MIN <= literal_bytes <= MAX_LITERAL:
            raise Refusal(f"{source_label} escaped the frozen V26 production envelope")

    return inventory


def _sealed_read(path_text: str, maximum: int, label: str) -> bytes:
    path = Path(path_text)
    if not path.is_absolute():
        raise Refusal(f"{label} path must be absolute")
    if os.path.realpath(path) != str(path):
        raise Refusal(f"{label} path must already be physical and canonical")
    try:
        before = os.lstat(path)
    except OSError as error:
        raise Refusal(f"cannot inspect {label}: {error}") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.getuid()
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o600
        or not 1 <= before.st_size <= maximum
    ):
        raise Refusal(
            f"{label} must be owned, mode-0600, singly linked, regular, and bounded"
        )
    flags = os.O_RDONLY
    for flag_name in ("O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK"):
        flags |= getattr(os, flag_name, 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise Refusal(f"cannot open {label} without following links: {error}") from error
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or opened.st_mode != before.st_mode
            or opened.st_uid != before.st_uid
            or opened.st_nlink != before.st_nlink
            or opened.st_size != before.st_size
        ):
            raise Refusal(f"{label} changed while being opened")
        first = _read_bounded_descriptor(descriptor, maximum)
        os.lseek(descriptor, 0, os.SEEK_SET)
        second = _read_bounded_descriptor(descriptor, maximum)
        after = os.fstat(descriptor)
        if first != second or len(first) != before.st_size:
            raise Refusal(f"{label} changed across two bounded reads")
        if (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_nlink,
            after.st_size,
        ) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_uid,
            opened.st_nlink,
            opened.st_size,
        ):
            raise Refusal(f"{label} metadata changed during its bounded reads")
        return first
    finally:
        os.close(descriptor)


def _read_bounded_descriptor(descriptor: int, maximum: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total <= maximum:
        chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def _expected_sha256(value: str, label: str) -> str:
    return _sha256(value, label)


def _usage() -> str:
    return (
        "usage:\n"
        "  validate_authorization.py template AUTHORIZATION_TEMPLATE\n"
        "  validate_authorization.py reviewed AUTH EXPECTED_AUTH_SHA256 "
        "INVENTORY EXPECTED_INVENTORY_SHA256"
    )


def main(arguments: list[str]) -> int:
    try:
        if len(arguments) == 3 and arguments[1] == "template":
            raw = Path(arguments[2]).read_bytes()
            parse_template_bytes(raw, arguments[2])
            print("v26-production-authorization-template: PASS")
            return 0
        if len(arguments) == 6 and arguments[1] == "reviewed":
            expected_authorization = _expected_sha256(
                arguments[3], "expected authorization SHA-256"
            )
            expected_inventory = _expected_sha256(
                arguments[5], "expected inventory SHA-256"
            )
            authorization_raw = _sealed_read(
                arguments[2], MAX_AUTH_BYTES, "authorization"
            )
            inventory_raw = _sealed_read(
                arguments[4], MAX_INVENTORY_BYTES, "source inventory"
            )
            actual_authorization = hashlib.sha256(authorization_raw).hexdigest()
            actual_inventory = hashlib.sha256(inventory_raw).hexdigest()
            if actual_authorization != expected_authorization:
                raise Refusal("authorization differs from its independent SHA-256")
            if actual_inventory != expected_inventory:
                raise Refusal("source inventory differs from its independent SHA-256")
            authorization = parse_reviewed_authorization_bytes(authorization_raw)
            inventory = parse_reviewed_inventory_bytes(inventory_raw, authorization)
            print("v26-production-authorization: PASS")
            print(f"authorization_sha256={actual_authorization}")
            print(f"source_inventory_sha256={actual_inventory}")
            print(f"sources={len(inventory['sources'])}")
            return 0
        raise Refusal(_usage())
    except (OSError, Refusal) as error:
        print(f"v26-production-authorization: REFUSED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
