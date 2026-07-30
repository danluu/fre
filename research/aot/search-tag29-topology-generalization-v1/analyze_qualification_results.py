#!/usr/bin/env python3
"""Fail-closed analyzer for paired tag-29 topology result bundles.

The campaign authority is deliberately a pre-result input.  It is supplied as
its own file together with an expected whole-file SHA-256 on the command line;
the result manifest can only refer to that authority.  Result files are opened
relative to held directory descriptors with ``O_NOFOLLOW`` and the bytes used
for hashing are the same bytes used for parsing.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
from collections import defaultdict
from fractions import Fraction
from pathlib import Path
from contextlib import contextmanager
from typing import Any, BinaryIO, Iterator, Iterable


AUTHORITY_SCHEMA = "fre.aot.search-tag29-campaign-authority.v2"
MANIFEST_SCHEMA = "fre.aot.search-tag29-paired-result-manifest.v2"
CORRECTNESS_HEADER_SCHEMA = (
    "fre.aot.search-tag29-host-correctness-header.v2"
)
CORRECTNESS_CASE_SCHEMA = "fre.aot.search-tag29-host-correctness-case.v2"
CORRECTNESS_TRAILER_SCHEMA = (
    "fre.aot.search-tag29-host-correctness-trailer.v2"
)
HEADER_SCHEMA = "fre.aot.search-tag29-host-timing-header.v2"
CASE_SCHEMA = "fre.aot.search-tag29-host-timing-case.v2"
TRAILER_SCHEMA = "fre.aot.search-tag29-host-timing-trailer.v2"
OBJECT_EVIDENCE_SCHEMA = (
    "fre.aot.search-tag29-compiler-object-link-evidence.v1"
)
CAMPAIGN_DOMAIN = b"FRE-SEARCH-TAG29-PAIRED-RESULT-CAMPAIGN\0\x01"
PROJECTION_DOMAIN = b"FRE-SEARCH-TAG29-TOPOLOGY-PROJECTION\0\x01"
GLUE_SYMBOL_DOMAIN = b"FRE-SEARCH-TAG29-GLUE-SYMBOL\0\x01"
FREEZE_SHA256 = (
    "9f6ba2af9ff7e2296f65dc20b4386d68ddd5ea41837814a1b6b4c3ee2faf4856"
)
GENERATOR_SHA256 = (
    "35aacbca100dde74a2ead493ceab1197c813d37c17d5f4a9d3e62938c3a2b610"
)
SELECTOR_SHA256 = (
    "38ca5ebc1b239b541afcf9eeb679bf8b156c8690e7422a96f69a9457a155daf0"
)
LINK_PROOF_VERIFIER_SHA256 = (
    "8b3d13c5233e68b6ef4f398a713792515f8fb1b1001ca699e39b81746d2ac9bb"
)
LINK_PROOF_CONTRACT_SHA256 = (
    "42921564050b795b4a097c8b74dde2e947b914931e71dd5faafe274a4975e60e"
)
TIMED_PROJECTION_DIGEST = (
    "72d85a032a90e4347be2d537c2ff11bac15016787c055332843f143da72e487f"
)
FULL_PROJECTION_DIGEST = (
    "5d548159e8c93d6ddb8d57847e01cc97ea2b661f736b2e8a126df6cd35cf612f"
)
FULL_ROWS = 123_424
TIMED_ROWS = 3_078
REPETITIONS = 6
PAIRS_PER_HOST = TIMED_ROWS * REPETITIONS
MEASUREMENTS_PER_HOST = PAIRS_PER_HOST * 2
MINIMUM_NS = 400_000_000
STRICT_GATE = Fraction(4, 5)
HOSTS = (
    {
        "frozen_name": "local-apple-aarch64-asimd",
        "canonical_name": "apple-aarch64-asimd",
        "target_triple": "aarch64-apple-darwin",
        "features": {
            "architecture": "aarch64",
            "asimd": True,
            "sve": False,
            "sve2": False,
            "sve_vector_bytes": None,
        },
    },
    {
        "frozen_name": "zstd-eval-ec2-aarch64-asimd-sve2-vl16",
        "canonical_name": "c9g-aarch64-asimd-sve2",
        "target_triple": "aarch64-unknown-linux-gnu",
        "features": {
            "architecture": "aarch64",
            "asimd": True,
            "sve": True,
            "sve2": True,
            "sve_vector_bytes": 16,
        },
    },
)
AUTHORITY_ENVELOPE_FIELDS = {"schema", "payload_sha256", "payload"}
AUTHORITY_FIELDS = {
    "campaign_name",
    "freeze_sha256",
    "generator_sha256",
    "selector_contract_sha256",
    "qualification_plan_sha256",
    "qualification_plan_payload_sha256",
    "timed_projection_digest",
    "timed_projection_rows",
    "full_projection_digest",
    "full_projection_rows",
    "runner",
    "host_aliases",
    "hosts",
    "performance_authority",
    "rebar_inputs",
    "benchmark_result_inputs",
    "result_derived_exclusions",
}
RUNNER_FIELDS = {
    "source_commit",
    "source_set_sha256",
    "controller_source_sha256",
    "sealer_source_sha256",
    "analyzer_source_sha256",
    "qualification_validator_source_sha256",
    "object_manifest_sha256",
    "object_manifest_payload_sha256",
    "backend_tag",
    "backend_version",
    "candidate_policy",
    "llvm",
    "ordinary_candidate_entry",
    "baseline_entry",
    "timed_function_identity_sha256",
}
AUTHORITY_HOST_FIELDS = {
    "frozen_name",
    "canonical_name",
    "target_triple",
    "features",
    "allowed_logical_cpus",
    "host_attestation_sha256",
    "runner_binary_sha256",
    "linked_image_sha256",
    "linked_image_platform_identity_sha256",
    "build_closure_sha256",
    "toolchain_closure_sha256",
    "object_evidence",
}
OBJECT_EVIDENCE_RECEIPT_FIELDS = {
    "path",
    "bytes",
    "sha256",
    "payload_sha256",
}
OBJECT_EVIDENCE_ENVELOPE_FIELDS = {"schema", "payload_sha256", "payload"}
OBJECT_EVIDENCE_PAYLOAD_FIELDS = {
    "frozen_host",
    "canonical_host",
    "target_triple",
    "features",
    "object_manifest_sha256",
    "object_manifest_payload_sha256",
    "literal_dispositions_sha256",
    "literal_dispositions_payload_sha256",
    "verifier_source_sha256",
    "verifier_contract_sha256",
    "external_build_receipt_sha256",
    "external_link_receipt_sha256",
    "link_map_sha256",
    "linked_image_sha256",
    "objects",
    "refusals",
}
OBJECT_MAPPING_FIELDS = {
    "ordinal",
    "literal_sha256",
    "semantic_candidate_sha256",
    "compile_identity",
    "compile_receipt_sha256",
    "implementation_object_sha256",
    "glue_object_sha256",
    "implementation_symbols",
    "glue_symbol",
    "glue_symbol_identity_sha256",
    "glue_relocation_targets",
    "implementation_linker_input_multiplicity",
    "glue_linker_input_multiplicity",
    "link_map_origins",
    "final_image_retentions",
}
IMPLEMENTATION_SYMBOL_FIELDS = {"entry", "payload", "metadata"}
SYMBOL_PROOF_FIELDS = {"symbol", "object_sha256", "receipt_sha256"}
REFUSAL_MAPPING_FIELDS = {
    "ordinal",
    "literal_sha256",
    "semantic_candidate_sha256",
    "disposition",
    "compile_receipt_sha256",
}
HOST_MANIFEST_FIELDS = {
    "frozen_name",
    "canonical_name",
    "correctness_bundle",
    "timing_bundle",
}
CORRECTNESS_BUNDLE_FIELDS = {
    "path",
    "bytes",
    "sha256",
    "case_records",
}
TIMING_BUNDLE_FIELDS = {
    "path",
    "bytes",
    "sha256",
    "case_records",
    "pairs",
    "measurements",
}
HEADER_FIELDS = {
    "schema",
    "campaign_id",
    "frozen_host",
    "canonical_host",
    "target_triple",
    "features",
    "host_attestation_sha256",
    "runner_binary_sha256",
    "linked_image_sha256",
    "linked_image_platform_identity_sha256",
    "build_closure_sha256",
    "toolchain_closure_sha256",
    "runner_source_commit",
    "runner_source_set_sha256",
    "object_manifest_sha256",
    "object_evidence_sha256",
    "qualification_plan_sha256",
    "case_records",
    "pairs",
    "measurements",
}
CORRECTNESS_HEADER_FIELDS = {
    "schema",
    "campaign_id",
    "frozen_host",
    "canonical_host",
    "target_triple",
    "features",
    "host_attestation_sha256",
    "runner_binary_sha256",
    "linked_image_sha256",
    "linked_image_platform_identity_sha256",
    "build_closure_sha256",
    "toolchain_closure_sha256",
    "runner_source_commit",
    "runner_source_set_sha256",
    "object_manifest_sha256",
    "object_evidence_sha256",
    "qualification_plan_sha256",
    "case_records",
}
CASE_FIELDS = {
    "schema",
    "campaign_id",
    "ordinal",
    "row_sha256",
    "literal_sha256",
    "literal_hex",
    "dimensions",
    "compiler",
    "precheck",
    "mapping",
    "timing_setup",
    "pairs",
}
CORRECTNESS_CASE_FIELDS = {
    "schema",
    "campaign_id",
    "ordinal",
    "row_sha256",
    "literal_sha256",
    "literal_hex",
    "compiler",
    "precheck",
    "mapping",
}
DIMENSION_FIELDS = {
    "width",
    "topology",
    "mutation_class",
    "learned_source_kind",
    "learned_source_relations",
    "literal_phase_class",
    "selector_primary_offset_class",
    "logical_prefix_bytes",
    "physical_window_start_mod16",
    "mapping",
    "window_bytes",
    "outcome",
}
COMPILER_FIELDS = {
    "backend_tag",
    "backend_version",
    "candidate_policy",
    "disposition",
    "compile_identity",
    "compile_receipt_sha256",
    "implementation_object_sha256",
    "glue_object_sha256",
    "semantic_candidate_sha256",
    "glue_symbol_identity_sha256",
    "link_map_origins_sha256",
    "final_image_retentions_sha256",
}
PRECHECK_FIELDS = {
    "scalar_span",
    "portable_span",
    "candidate_span",
    "expected_nonoverlapping_count",
    "portable_nonoverlapping_count",
    "candidate_nonoverlapping_count",
    "portable_route",
    "candidate_route",
    "portable_static_invocations",
    "candidate_static_invocations",
}
MAPPING_FIELDS = {
    "allocation_start_address",
    "allocation_bytes",
    "fixture_pointer_address",
    "checked_pointer_address",
    "checked_bytes",
    "actual_window_start_mod16",
    "mapping",
    "readable_left_bytes",
    "readable_right_bytes",
    "padding_sentinel",
    "padding_verified",
    "page_size",
    "guard_page_start_address",
    "guard_protection",
    "guard_protection_receipt_sha256",
    "allocation_receipt_sha256",
}
TIMING_SETUP_FIELDS = {
    "fixture_materialization_outside_timing",
    "compile_link_adoption_outside_timing",
    "pilot_outside_timing",
    "route_instrumentation_outside_timing",
    "timed_function_identity_sha256",
}
PAIR_FIELDS = {
    "pair_index",
    "first_variant",
    "iteration_count",
    "fixture_pointer_address",
    "checked_pointer_address",
    "logical_cpu",
    "cpu_before",
    "cpu_after",
    "affinity_receipt_sha256",
    "admission_receipt_sha256",
    "portable",
    "candidate",
}
MEASUREMENT_FIELDS = {
    "elapsed_ns",
    "output_accumulator",
    "last_span",
    "route",
}
TRAILER_FIELDS = {
    "schema",
    "campaign_id",
    "case_records",
    "pairs",
    "measurements",
    "prefix_sha256",
}


class Refusal(RuntimeError):
    """A result bundle is incomplete, unauthenticated, or fails a cell."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def sha256(encoded: bytes) -> str:
    return hashlib.sha256(encoded).hexdigest()


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def canonical_sha(value: Any) -> str:
    return sha256(canonical_bytes(value))


def regular_file(path: Path, maximum: int = 1024 * 1024 * 1024) -> bytes:
    """Read a trusted program input through one no-follow descriptor."""
    parent = path.parent.resolve(strict=True)
    with held_directory(parent) as directory_fd:
        return read_regular_at(directory_fd, path.name, maximum)[0]


def flat_name(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value not in {"", ".", ".."}
        and "/" not in value
        and "\\" not in value
        and "\x00" not in value
    )


@contextmanager
def held_directory(path: Path) -> Iterator[int]:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        status = os.fstat(descriptor)
        require(stat.S_ISDIR(status.st_mode), f"not one held directory: {path}")
        yield descriptor
    finally:
        os.close(descriptor)


def open_regular_at(
    directory_fd: int,
    name: str,
    maximum: int,
) -> tuple[BinaryIO, os.stat_result]:
    require(flat_name(name), f"not one exact flat file name: {name!r}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, dir_fd=directory_fd)
    try:
        status = os.fstat(descriptor)
        require(
            stat.S_ISREG(status.st_mode)
            and 0 < status.st_size <= maximum
            and status.st_nlink == 1,
            f"not one bounded unshared regular file: {name}",
        )
        return os.fdopen(descriptor, "rb", closefd=True), status
    except BaseException:
        os.close(descriptor)
        raise


def require_unchanged_descriptor(
    source: BinaryIO,
    before: os.stat_result,
    name: str,
) -> None:
    after = os.fstat(source.fileno())
    require(
        (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        == (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ),
        f"file changed while held: {name}",
    )


def read_regular_at(
    directory_fd: int,
    name: str,
    maximum: int = 1024 * 1024 * 1024,
) -> tuple[bytes, str]:
    source, before = open_regular_at(directory_fd, name, maximum)
    with source:
        encoded = source.read(maximum + 1)
        require(
            0 < len(encoded) <= maximum and len(encoded) == before.st_size,
            f"short, empty, or oversized read: {name}",
        )
        require_unchanged_descriptor(source, before, name)
    return encoded, sha256(encoded)


def is_hex(value: Any, length: int = 64) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(byte in "0123456789abcdef" for byte in value)
    )


def is_uint(value: Any, maximum: int = (1 << 64) - 1) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= maximum
    )


def is_u64(value: Any) -> bool:
    return is_uint(value)


def exact_uint(value: Any, expected: int) -> bool:
    return is_uint(value) and value == expected


def exact_json(value: Any, expected: Any) -> bool:
    """Equality which cannot confuse bools and integers."""
    return canonical_bytes(value) == canonical_bytes(expected)


def validate_span(value: Any, expected: Any, message: str) -> None:
    require(
        value == expected
        and (
            value is None
            or (
                isinstance(value, list)
                and len(value) == 2
                and all(is_u64(item) for item in value)
                and value[0] <= value[1]
            )
        ),
        message,
    )


def validate_plan(
    qualification_root: Path, directory_fd: int | None = None
) -> dict[str, Any]:
    if directory_fd is None:
        with held_directory(qualification_root) as held_fd:
            return validate_plan(qualification_root, held_fd)
    validator = (
        Path(__file__).resolve().with_name("validate_qualification_plan.py")
    )
    result = subprocess.run(
        [sys.executable, str(validator), str(qualification_root)],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    require(
        result.returncode == 0 and not result.stderr,
        "qualification plan validation failed",
    )
    plan_path = qualification_root / "qualification-plan.json"
    plan_bytes, plan_sha = read_regular_at(
        directory_fd, "qualification-plan.json", 16 * 1024 * 1024
    )
    plan = json.loads(plan_bytes)
    return {
        "path": plan_path,
        "sha256": plan_sha,
        "payload_sha256": plan["payload_sha256"],
        "payload": plan["payload"],
    }


def load_timed_rows(
    qualification_root: Path,
    plan: dict[str, Any],
    directory_fd: int | None = None,
) -> list[dict[str, Any]]:
    if directory_fd is None:
        with held_directory(qualification_root) as held_fd:
            return load_timed_rows(qualification_root, plan, held_fd)
    receipt = plan["payload"]["timed_projection"]
    require(flat_name(receipt["path"]), "timed projection name changed")
    encoded, raw_sha = read_regular_at(
        directory_fd, receipt["path"], 64 * 1024 * 1024
    )
    require(
        raw_sha == receipt["file_sha256"]
        and receipt["rows"] == TIMED_ROWS
        and receipt["projection_digest"] == TIMED_PROJECTION_DIGEST,
        "timed projection receipt changed",
    )
    digest = hashlib.sha256(PROJECTION_DOMAIN)
    rows = []
    for line_number, line in enumerate(encoded.splitlines(keepends=True), 1):
        require(
            line.endswith(b"\n") and 1 < len(line) <= 16 * 1024,
            f"timed projection line {line_number} changed",
        )
        row = json.loads(line)
        require(
            canonical_bytes(row) + b"\n" == line,
            f"timed projection row {line_number} is not canonical",
        )
        digest.update(len(line).to_bytes(8, "little"))
        digest.update(line)
        rows.append(row)
    require(
        len(rows) == TIMED_ROWS
        and len({row["row_sha256"] for row in rows}) == TIMED_ROWS
        and digest.hexdigest() == TIMED_PROJECTION_DIGEST
        and all(
            row["expected_route"] == "tag29-static-tail"
            and row["expected_compiler_disposition"] == "tag29-object"
            and row["expected_static_invoked"] is True
            for row in rows
        ),
        "timed projection membership or route changed",
    )
    return rows


def campaign_id(authority_file_sha256: str) -> str:
    require(is_hex(authority_file_sha256), "authority file SHA-256 changed")
    return sha256(CAMPAIGN_DOMAIN + bytes.fromhex(authority_file_sha256))


def validate_authority(
    authority: dict[str, Any],
    plan: dict[str, Any],
    analyzer_sha256: str,
    qualification_validator_sha256: str,
) -> None:
    expected_performance = {
        "cell_ratio": (
            "sort six exact candidate_elapsed_ns/portable_elapsed_ns "
            "rationals; median=(ratio[2]+ratio[3])/2"
        ),
        "cell_gate": "strictly less than 4/5 on every host and row",
        "aggregate_strata": (
            "completeness groups whose pass is conjunction of member cell "
            "gates; no pooled or aggregate rescue"
        ),
        "diagnostic_aggregates_authorize": False,
        "minimum_elapsed_ns_each_variant": MINIMUM_NS,
        "repetitions": REPETITIONS,
    }
    require(
        isinstance(authority, dict)
        and set(authority) == AUTHORITY_FIELDS
        and authority["campaign_name"] == "search-tag29-topology-v1"
        and authority["freeze_sha256"] == FREEZE_SHA256
        and authority["generator_sha256"] == GENERATOR_SHA256
        and authority["selector_contract_sha256"] == SELECTOR_SHA256
        and authority["qualification_plan_sha256"] == plan["sha256"]
        and authority["qualification_plan_payload_sha256"]
        == plan["payload_sha256"]
        and authority["timed_projection_digest"]
        == TIMED_PROJECTION_DIGEST
        and exact_uint(authority["timed_projection_rows"], TIMED_ROWS)
        and authority["full_projection_digest"] == FULL_PROJECTION_DIGEST
        and exact_uint(authority["full_projection_rows"], FULL_ROWS)
        and exact_json(
            authority["host_aliases"],
            {
                host["frozen_name"]: host["canonical_name"]
                for host in HOSTS
            },
        )
        and exact_json(
            authority["performance_authority"], expected_performance
        )
        and authority["rebar_inputs"] == []
        and authority["benchmark_result_inputs"] == []
        and authority["result_derived_exclusions"] is False,
        "campaign authority changed",
    )
    runner = authority["runner"]
    object_receipt = plan["payload"]["object_candidates"]
    require(
        set(runner) == RUNNER_FIELDS
        and is_hex(runner["source_commit"], 40)
        and all(
            is_hex(runner[field])
            for field in (
                "source_set_sha256",
                "controller_source_sha256",
                "sealer_source_sha256",
                "analyzer_source_sha256",
                "qualification_validator_source_sha256",
                "object_manifest_sha256",
                "object_manifest_payload_sha256",
            )
        )
        and runner["analyzer_source_sha256"] == analyzer_sha256
        and runner["qualification_validator_source_sha256"]
        == qualification_validator_sha256
        and runner["object_manifest_sha256"]
        == object_receipt["file_sha256"]
        and runner["object_manifest_payload_sha256"]
        == object_receipt["payload_sha256"]
        and exact_uint(runner["backend_tag"], 29)
        and runner["backend_version"] == "SEARCH_V16"
        and exact_uint(runner["candidate_policy"], 15)
        and runner["llvm"] is False
        and runner["ordinary_candidate_entry"]
        == "production-auto-route-portable-prefix-static-tail"
        and runner["baseline_entry"] == "forced-full-portable"
        and is_hex(runner["timed_function_identity_sha256"])
        and runner["timed_function_identity_sha256"] != "0" * 64,
        "runner authority changed",
    )
    hosts = authority["hosts"]
    require(
        isinstance(hosts, list) and len(hosts) == len(HOSTS),
        "authority host count changed",
    )
    attestations: set[str] = set()
    evidence_names: set[str] = set()
    for index, (host, expected) in enumerate(zip(hosts, HOSTS, strict=True)):
        expected_evidence_name = (
            f"{expected['canonical_name']}.compiler-object-link-evidence.json"
        )
        require(
            isinstance(host, dict)
            and set(host) == AUTHORITY_HOST_FIELDS
            and host["frozen_name"] == expected["frozen_name"]
            and host["canonical_name"] == expected["canonical_name"]
            and host["target_triple"] == expected["target_triple"]
            and exact_json(host["features"], expected["features"])
            and isinstance(host["allowed_logical_cpus"], list)
            and 0 < len(host["allowed_logical_cpus"]) <= 4096
            and all(
                is_uint(cpu, (1 << 31) - 1)
                for cpu in host["allowed_logical_cpus"]
            )
            and host["allowed_logical_cpus"]
            == sorted(set(host["allowed_logical_cpus"]))
            and all(
                is_hex(host[field]) and host[field] != "0" * 64
                for field in (
                    "host_attestation_sha256",
                    "runner_binary_sha256",
                    "linked_image_sha256",
                    "linked_image_platform_identity_sha256",
                    "build_closure_sha256",
                    "toolchain_closure_sha256",
                )
            )
            and isinstance(host["object_evidence"], dict)
            and set(host["object_evidence"])
            == OBJECT_EVIDENCE_RECEIPT_FIELDS
            and host["object_evidence"]["path"] == expected_evidence_name
            and is_uint(host["object_evidence"]["bytes"])
            and host["object_evidence"]["bytes"] > 0
            and is_hex(host["object_evidence"]["sha256"])
            and is_hex(host["object_evidence"]["payload_sha256"]),
            f"authority host {index} changed",
        )
        require(
            host["host_attestation_sha256"] not in attestations
            and expected_evidence_name not in evidence_names,
            "authority hosts share an attestation or evidence path",
        )
        attestations.add(host["host_attestation_sha256"])
        evidence_names.add(expected_evidence_name)


def load_plan_json_receipt(
    qualification_fd: int,
    receipt: dict[str, Any],
    maximum: int = 32 * 1024 * 1024,
) -> dict[str, Any]:
    require(
        isinstance(receipt, dict)
        and flat_name(receipt["path"])
        and is_hex(receipt["file_sha256"])
        and is_hex(receipt["payload_sha256"]),
        "qualification artifact receipt changed",
    )
    encoded, digest = read_regular_at(
        qualification_fd, receipt["path"], maximum
    )
    envelope = json.loads(encoded)
    require(
        digest == receipt["file_sha256"]
        and isinstance(envelope, dict)
        and set(envelope) == {"schema", "payload_sha256", "payload"}
        and envelope["schema"] == receipt["schema"]
        and envelope["payload_sha256"] == receipt["payload_sha256"]
        and canonical_sha(envelope["payload"]) == envelope["payload_sha256"],
        f"qualification artifact changed: {receipt['path']}",
    )
    return envelope


def ascii_symbol(value: Any) -> bool:
    allowed = (
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789_.$"
    )
    return (
        isinstance(value, str)
        and 0 < len(value) <= 256
        and all(character in allowed for character in value)
    )


def validate_symbol_proofs(
    value: Any,
    expected: list[tuple[str, str]],
    message: str,
    receipt_identities: set[str],
) -> None:
    require(
        isinstance(value, list) and len(value) == len(expected),
        message,
    )
    for index, (record, (symbol, object_sha)) in enumerate(
        zip(value, expected, strict=True)
    ):
        require(
            isinstance(record, dict)
            and set(record) == SYMBOL_PROOF_FIELDS
            and record["symbol"] == symbol
            and record["object_sha256"] == object_sha
            and is_hex(record["receipt_sha256"])
            and record["receipt_sha256"] != "0" * 64
            and record["receipt_sha256"] not in receipt_identities,
            f"{message} record {index}",
        )
        receipt_identities.add(record["receipt_sha256"])


def compiler_case_record(
    mapping: dict[str, Any],
    disposition: str,
) -> dict[str, Any]:
    if disposition == "structural-refusal":
        return {
            "backend_tag": 29,
            "backend_version": "SEARCH_V16",
            "candidate_policy": 15,
            "disposition": disposition,
            "compile_identity": None,
            "compile_receipt_sha256": mapping["compile_receipt_sha256"],
            "implementation_object_sha256": None,
            "glue_object_sha256": None,
            "semantic_candidate_sha256": mapping[
                "semantic_candidate_sha256"
            ],
            "glue_symbol_identity_sha256": None,
            "link_map_origins_sha256": None,
            "final_image_retentions_sha256": None,
        }
    return {
        "backend_tag": 29,
        "backend_version": "SEARCH_V16",
        "candidate_policy": 15,
        "disposition": "tag29-object",
        "compile_identity": mapping["compile_identity"],
        "compile_receipt_sha256": mapping["compile_receipt_sha256"],
        "implementation_object_sha256": mapping[
            "implementation_object_sha256"
        ],
        "glue_object_sha256": mapping["glue_object_sha256"],
        "semantic_candidate_sha256": mapping[
            "semantic_candidate_sha256"
        ],
        "glue_symbol_identity_sha256": mapping[
            "glue_symbol_identity_sha256"
        ],
        "link_map_origins_sha256": canonical_sha(
            mapping["link_map_origins"]
        ),
        "final_image_retentions_sha256": canonical_sha(
            mapping["final_image_retentions"]
        ),
    }


def load_object_evidence(
    authority_fd: int,
    host: dict[str, Any],
    expected_host: dict[str, Any],
    plan: dict[str, Any],
    qualification_fd: int,
) -> dict[str, dict[str, Any]]:
    object_receipt = plan["payload"]["object_candidates"]
    disposition_receipt = plan["payload"]["literal_dispositions"]
    object_envelope = load_plan_json_receipt(
        qualification_fd, object_receipt
    )
    disposition_envelope = load_plan_json_receipt(
        qualification_fd, disposition_receipt
    )
    candidates = object_envelope["payload"]["candidates"]
    dispositions = disposition_envelope["payload"]["dispositions"]
    expected_refusals = [
        item
        for item in dispositions
        if item["expected_compiler_disposition"] == "structural-refusal"
    ]
    receipt = host["object_evidence"]
    encoded, digest = read_regular_at(
        authority_fd, receipt["path"], 64 * 1024 * 1024
    )
    evidence = json.loads(encoded)
    require(
        digest == receipt["sha256"]
        and exact_uint(receipt["bytes"], len(encoded))
        and isinstance(evidence, dict)
        and set(evidence) == OBJECT_EVIDENCE_ENVELOPE_FIELDS
        and evidence["schema"] == OBJECT_EVIDENCE_SCHEMA
        and evidence["payload_sha256"] == receipt["payload_sha256"]
        and canonical_sha(evidence["payload"])
        == evidence["payload_sha256"],
        f"{expected_host['canonical_name']}: object evidence changed",
    )
    payload = evidence["payload"]
    require(
        isinstance(payload, dict)
        and set(payload) == OBJECT_EVIDENCE_PAYLOAD_FIELDS
        and payload["frozen_host"] == expected_host["frozen_name"]
        and payload["canonical_host"] == expected_host["canonical_name"]
        and payload["target_triple"] == expected_host["target_triple"]
        and exact_json(payload["features"], expected_host["features"])
        and payload["object_manifest_sha256"]
        == object_receipt["file_sha256"]
        and payload["object_manifest_payload_sha256"]
        == object_receipt["payload_sha256"]
        and payload["literal_dispositions_sha256"]
        == disposition_receipt["file_sha256"]
        and payload["literal_dispositions_payload_sha256"]
        == disposition_receipt["payload_sha256"]
        and payload["linked_image_sha256"] == host["linked_image_sha256"]
        and payload["verifier_source_sha256"]
        == LINK_PROOF_VERIFIER_SHA256
        and payload["verifier_contract_sha256"]
        == LINK_PROOF_CONTRACT_SHA256
        and all(
            is_hex(payload[field]) and payload[field] != "0" * 64
            for field in (
                "external_build_receipt_sha256",
                "external_link_receipt_sha256",
                "link_map_sha256",
            )
        )
        and isinstance(payload["objects"], list)
        and len(payload["objects"]) == len(candidates) == 808
        and isinstance(payload["refusals"], list)
        and len(payload["refusals"]) == len(expected_refusals) == 114,
        f"{expected_host['canonical_name']}: object evidence envelope changed",
    )
    injective: dict[str, set[str]] = {
        "compile_identity": set(),
        "compile_receipt_sha256": set(),
        "implementation_object_sha256": set(),
        "glue_object_sha256": set(),
        "symbols": set(),
        "proof_receipts": set(),
    }
    compiler_by_literal: dict[str, dict[str, Any]] = {}
    for ordinal, (mapping, candidate) in enumerate(
        zip(payload["objects"], candidates, strict=True)
    ):
        require(
            isinstance(mapping, dict)
            and set(mapping) == OBJECT_MAPPING_FIELDS
            and exact_uint(mapping["ordinal"], ordinal)
            and mapping["literal_sha256"] == candidate["literal_sha256"]
            and mapping["semantic_candidate_sha256"]
            == candidate["semantic_candidate_sha256"]
            and all(
                is_hex(mapping[field]) and mapping[field] != "0" * 64
                for field in (
                    "compile_identity",
                    "compile_receipt_sha256",
                    "implementation_object_sha256",
                    "glue_object_sha256",
                )
            )
            and isinstance(mapping["implementation_symbols"], dict)
            and set(mapping["implementation_symbols"])
            == IMPLEMENTATION_SYMBOL_FIELDS
            and all(
                ascii_symbol(symbol)
                for symbol in mapping["implementation_symbols"].values()
            )
            and ascii_symbol(mapping["glue_symbol"])
            and all(
                symbol.endswith(mapping["compile_identity"])
                for symbol in (
                    *mapping["implementation_symbols"].values(),
                    mapping["glue_symbol"],
                )
            )
            and mapping["glue_symbol_identity_sha256"]
            == sha256(
                GLUE_SYMBOL_DOMAIN
                + mapping["glue_symbol"].encode("ascii")
            )
            and exact_json(
                mapping["glue_relocation_targets"],
                [
                    mapping["implementation_symbols"]["entry"],
                    mapping["implementation_symbols"]["payload"],
                    mapping["implementation_symbols"]["metadata"],
                ],
            )
            and exact_uint(
                mapping["implementation_linker_input_multiplicity"], 1
            )
            and exact_uint(mapping["glue_linker_input_multiplicity"], 1),
            f"{expected_host['canonical_name']}: object mapping {ordinal}",
        )
        for field in (
            "compile_identity",
            "compile_receipt_sha256",
            "implementation_object_sha256",
            "glue_object_sha256",
        ):
            require(
                mapping[field] not in injective[field],
                f"{expected_host['canonical_name']}: {field} is not injective",
            )
            injective[field].add(mapping[field])
        symbols = [
            mapping["implementation_symbols"]["entry"],
            mapping["implementation_symbols"]["payload"],
            mapping["implementation_symbols"]["metadata"],
            mapping["glue_symbol"],
        ]
        require(
            len(set(symbols)) == 4
            and injective["symbols"].isdisjoint(symbols),
            f"{expected_host['canonical_name']}: symbols are not injective",
        )
        injective["symbols"].update(symbols)
        expected_proofs = [
            (symbol, mapping["implementation_object_sha256"])
            for symbol in symbols[:3]
        ] + [(symbols[3], mapping["glue_object_sha256"])]
        validate_symbol_proofs(
            mapping["link_map_origins"],
            expected_proofs,
            f"{expected_host['canonical_name']}: link origins {ordinal}",
            injective["proof_receipts"],
        )
        validate_symbol_proofs(
            mapping["final_image_retentions"],
            expected_proofs,
            f"{expected_host['canonical_name']}: retentions {ordinal}",
            injective["proof_receipts"],
        )
        compiler_by_literal[candidate["literal_sha256"]] = (
            compiler_case_record(mapping, "tag29-object")
        )
    for refusal_index, (mapping, disposition) in enumerate(
        zip(payload["refusals"], expected_refusals, strict=True)
    ):
        require(
            isinstance(mapping, dict)
            and set(mapping) == REFUSAL_MAPPING_FIELDS
            and exact_uint(mapping["ordinal"], refusal_index)
            and mapping["literal_sha256"] == disposition["literal_sha256"]
            and mapping["semantic_candidate_sha256"]
            == disposition["semantic_candidate_sha256"]
            and mapping["disposition"] == "structural-refusal"
            and is_hex(mapping["compile_receipt_sha256"])
            and mapping["compile_receipt_sha256"] != "0" * 64
            and mapping["compile_receipt_sha256"]
            not in injective["compile_receipt_sha256"],
            f"{expected_host['canonical_name']}: refusal {refusal_index}",
        )
        injective["compile_receipt_sha256"].add(
            mapping["compile_receipt_sha256"]
        )
        compiler_by_literal[disposition["literal_sha256"]] = (
            compiler_case_record(mapping, "structural-refusal")
        )
    require(
        len(compiler_by_literal) == len(dispositions) == 922,
        f"{expected_host['canonical_name']}: compiler evidence not bijective",
    )
    return compiler_by_literal


def expected_dimensions(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "width": row["literal_bytes"],
        "topology": row["topology"],
        "mutation_class": row["mutation_class"],
        "learned_source_kind": row["learned_source_kind"],
        "learned_source_relations": row["learned_source_relations"],
        "literal_phase_class": row["literal_phase_class"],
        "selector_primary_offset_class": row[
            "selector_primary_offset_class"
        ],
        "logical_prefix_bytes": row["logical_prefix_bytes"],
        "physical_window_start_mod16": row[
            "expected_physical_window_start_mod16"
        ],
        "mapping": (
            "right-guarded" if row["right_guarded"] else "right-padded"
        ),
        "window_bytes": row["window_bytes"],
        "outcome": row["outcome"],
    }


def expected_nonoverlapping_count(row: dict[str, Any]) -> int:
    return 0 if row["expected_match_start"] is None else 1


def bind_receipt(
    registry: dict[str, str],
    receipt: Any,
    binding: tuple[str, ...],
    message: str,
) -> None:
    require(
        is_hex(receipt) and receipt != "0" * 64,
        f"{message}: absent receipt",
    )
    binding_identity = sha256("\0".join(binding).encode("utf-8"))
    previous = registry.setdefault(receipt, binding_identity)
    require(
        previous == binding_identity,
        f"{message}: receipt is not case-bound",
    )


def validate_mapping(
    mapping: dict[str, Any],
    row: dict[str, Any],
    receipt_registry: dict[str, str],
    binding: tuple[str, ...],
) -> None:
    require(
        isinstance(mapping, dict)
        and set(mapping) == MAPPING_FIELDS
        and all(
            is_u64(mapping[field])
            for field in (
                "allocation_start_address",
                "allocation_bytes",
                "fixture_pointer_address",
                "checked_pointer_address",
                "checked_bytes",
                "actual_window_start_mod16",
                "readable_left_bytes",
                "readable_right_bytes",
                "padding_sentinel",
                "page_size",
            )
        )
        and mapping["allocation_start_address"] > 0
        and 0 < mapping["allocation_bytes"] <= (1 << 40)
        and mapping["fixture_pointer_address"] > 0
        and mapping["checked_pointer_address"] > 0
        and mapping["checked_bytes"] > 0
        and mapping["actual_window_start_mod16"] <= 15
        and mapping["padding_sentinel"] <= 255
        and mapping["checked_pointer_address"]
        == mapping["fixture_pointer_address"] + row["logical_prefix_bytes"]
        and exact_uint(mapping["checked_bytes"], row["window_bytes"])
        and mapping["actual_window_start_mod16"]
        == row["expected_physical_window_start_mod16"]
        and mapping["checked_pointer_address"] % 16
        == row["expected_physical_window_start_mod16"]
        and mapping["mapping"]
        == ("right-guarded" if row["right_guarded"] else "right-padded")
        and mapping["padding_sentinel"]
        == row["fixture_recipe"]["background_byte"]
        and mapping["padding_verified"] is True
        and 4096 <= mapping["page_size"] <= (1 << 30)
        and mapping["page_size"] & (mapping["page_size"] - 1) == 0
        and mapping["allocation_start_address"]
        <= mapping["fixture_pointer_address"]
        < mapping["allocation_start_address"] + mapping["allocation_bytes"]
        and mapping["allocation_start_address"] + mapping["allocation_bytes"]
        <= (1 << 64) - 1
        and mapping["checked_pointer_address"]
        >= mapping["readable_left_bytes"]
        and mapping["allocation_start_address"]
        <= mapping["checked_pointer_address"]
        - mapping["readable_left_bytes"]
        and mapping["checked_pointer_address"] + mapping["checked_bytes"]
        <= mapping["allocation_start_address"] + mapping["allocation_bytes"],
        "physical mapping receipt changed",
    )
    bind_receipt(
        receipt_registry,
        mapping["allocation_receipt_sha256"],
        (*binding, "allocation"),
        "physical allocation",
    )
    if row["right_guarded"]:
        require(
            exact_uint(mapping["readable_left_bytes"], 32)
            and exact_uint(mapping["readable_right_bytes"], 0)
            and is_u64(mapping["guard_page_start_address"])
            and mapping["guard_page_start_address"] > 0
            and mapping["guard_page_start_address"]
            == mapping["checked_pointer_address"] + row["window_bytes"]
            and mapping["guard_page_start_address"] % mapping["page_size"] == 0
            and mapping["guard_page_start_address"] + mapping["page_size"]
            <= mapping["allocation_start_address"] + mapping["allocation_bytes"]
            and mapping["guard_protection"] == "PROT_NONE"
            and is_hex(mapping["guard_protection_receipt_sha256"]),
            "guard-page mapping is not exact",
        )
        bind_receipt(
            receipt_registry,
            mapping["guard_protection_receipt_sha256"],
            (*binding, "guard"),
            "guard protection",
        )
    else:
        require(
            exact_uint(mapping["readable_left_bytes"], 32)
            and exact_uint(mapping["readable_right_bytes"], 32)
            and mapping["guard_page_start_address"] is None
            and mapping["guard_protection"] == "none"
            and mapping["guard_protection_receipt_sha256"] is None
            and mapping["checked_pointer_address"]
            + mapping["checked_bytes"]
            + mapping["readable_right_bytes"]
            <= mapping["allocation_start_address"] + mapping["allocation_bytes"],
            "right-padded mapping is not exact",
        )


def validate_measurement(
    measurement: dict[str, Any],
    expected_span: Any,
    expected_route: str,
) -> None:
    require(
        isinstance(measurement, dict)
        and set(measurement) == MEASUREMENT_FIELDS
        and is_u64(measurement["elapsed_ns"])
        and measurement["elapsed_ns"] >= MINIMUM_NS
        and is_u64(measurement["output_accumulator"])
        and measurement["route"] == expected_route,
        "timed measurement changed",
    )
    validate_span(
        measurement["last_span"], expected_span, "timed semantic span changed"
    )


def group_keys(dimensions: dict[str, Any]) -> Iterable[tuple[str, str]]:
    yield ("width", str(dimensions["width"]))
    yield ("topology", dimensions["topology"])
    yield ("mutation_class", str(dimensions["mutation_class"]))
    yield ("learned_source_kind", dimensions["learned_source_kind"])
    for relation in dimensions["learned_source_relations"]:
        yield ("learned_source_relation", relation)
    yield ("literal_phase_class", str(dimensions["literal_phase_class"]))
    yield (
        "selector_primary_offset_class",
        str(dimensions["selector_primary_offset_class"]),
    )
    yield ("logical_prefix_bytes", str(dimensions["logical_prefix_bytes"]))
    yield (
        "physical_window_start_mod16",
        str(dimensions["physical_window_start_mod16"]),
    )
    yield ("mapping", dimensions["mapping"])
    yield ("window_bytes", str(dimensions["window_bytes"]))
    yield ("outcome", dimensions["outcome"])


def validate_case(
    case: dict[str, Any],
    row: dict[str, Any],
    ordinal: int,
    expected_campaign_id: str,
    compiler_by_literal: dict[str, dict[str, Any]],
    receipt_registry: dict[str, str],
    canonical_host: str,
    allowed_logical_cpus: set[int],
    timed_function_identity_sha256: str,
) -> Fraction:
    expected_span = (
        None
        if row["expected_match_start"] is None
        else [row["expected_match_start"], row["expected_match_end"]]
    )
    require(
        isinstance(case, dict)
        and set(case) == CASE_FIELDS
        and case["schema"] == CASE_SCHEMA
        and case["campaign_id"] == expected_campaign_id
        and exact_uint(case["ordinal"], ordinal)
        and case["row_sha256"] == row["row_sha256"]
        and case["literal_sha256"] == row["literal_sha256"]
        and case["literal_hex"] == row["literal_hex"]
        and isinstance(case["dimensions"], dict)
        and set(case["dimensions"]) == DIMENSION_FIELDS
        and exact_json(case["dimensions"], expected_dimensions(row)),
        f"case {ordinal}: identity or dimensions changed",
    )
    compiler = case["compiler"]
    expected_compiler = compiler_by_literal[row["literal_sha256"]]
    require(
        isinstance(compiler, dict)
        and set(compiler) == COMPILER_FIELDS
        and exact_json(compiler, expected_compiler)
        and compiler["disposition"] == "tag29-object"
        and exact_uint(compiler["backend_tag"], 29)
        and exact_uint(compiler["candidate_policy"], 15),
        f"case {ordinal}: compiler disposition changed",
    )
    precheck = case["precheck"]
    count = expected_nonoverlapping_count(row)
    require(
        isinstance(precheck, dict)
        and set(precheck) == PRECHECK_FIELDS
        and exact_uint(precheck["expected_nonoverlapping_count"], count)
        and exact_uint(precheck["portable_nonoverlapping_count"], count)
        and exact_uint(precheck["candidate_nonoverlapping_count"], count)
        and precheck["portable_route"] == "full-portable"
        and precheck["candidate_route"] == "portable-prefix-static-tail"
        and exact_uint(precheck["portable_static_invocations"], 0)
        and exact_uint(precheck["candidate_static_invocations"], 1),
        f"case {ordinal}: correctness or route precheck changed",
    )
    validate_span(
        precheck["scalar_span"], expected_span, f"case {ordinal}: scalar span"
    )
    validate_span(
        precheck["portable_span"],
        expected_span,
        f"case {ordinal}: portable span",
    )
    validate_span(
        precheck["candidate_span"],
        expected_span,
        f"case {ordinal}: candidate span",
    )
    case_binding = (
        canonical_host,
        "timing",
        str(ordinal),
        row["row_sha256"],
    )
    validate_mapping(
        case["mapping"], row, receipt_registry, case_binding
    )
    setup = case["timing_setup"]
    require(
        isinstance(setup, dict)
        and set(setup) == TIMING_SETUP_FIELDS
        and setup["fixture_materialization_outside_timing"] is True
        and setup["compile_link_adoption_outside_timing"] is True
        and setup["pilot_outside_timing"] is True
        and setup["route_instrumentation_outside_timing"] is True
        and setup["timed_function_identity_sha256"]
        == timed_function_identity_sha256,
        f"case {ordinal}: timed boundary changed",
    )
    pairs = case["pairs"]
    require(
        isinstance(pairs, list) and len(pairs) == REPETITIONS,
        f"case {ordinal}: pair count changed",
    )
    iteration_count = None
    logical_cpu = None
    affinity_receipt = None
    admission_receipt = None
    output_accumulator = None
    ratios = []
    for pair_index, pair in enumerate(pairs):
        require(
            isinstance(pair, dict)
            and set(pair) == PAIR_FIELDS
            and exact_uint(pair["pair_index"], pair_index)
            and pair["first_variant"]
            == ("portable" if pair_index % 2 == 0 else "candidate")
            and is_u64(pair["iteration_count"])
            and pair["iteration_count"] > 0
            and is_u64(pair["fixture_pointer_address"])
            and pair["fixture_pointer_address"]
            == case["mapping"]["fixture_pointer_address"]
            and is_u64(pair["checked_pointer_address"])
            and pair["checked_pointer_address"]
            == case["mapping"]["checked_pointer_address"]
            and is_uint(pair["logical_cpu"], (1 << 31) - 1)
            and pair["logical_cpu"] in allowed_logical_cpus
            and is_uint(pair["cpu_before"], (1 << 31) - 1)
            and is_uint(pair["cpu_after"], (1 << 31) - 1)
            and pair["cpu_before"] == pair["logical_cpu"]
            and pair["cpu_after"] == pair["logical_cpu"]
            and is_hex(pair["affinity_receipt_sha256"])
            and is_hex(pair["admission_receipt_sha256"]),
            f"case {ordinal} pair {pair_index}: pairing or CPU receipt changed",
        )
        iteration_count = (
            pair["iteration_count"]
            if iteration_count is None
            else iteration_count
        )
        logical_cpu = (
            pair["logical_cpu"] if logical_cpu is None else logical_cpu
        )
        affinity_receipt = (
            pair["affinity_receipt_sha256"]
            if affinity_receipt is None
            else affinity_receipt
        )
        admission_receipt = (
            pair["admission_receipt_sha256"]
            if admission_receipt is None
            else admission_receipt
        )
        require(
            pair["iteration_count"] == iteration_count
            and pair["logical_cpu"] == logical_cpu
            and pair["affinity_receipt_sha256"] == affinity_receipt
            and pair["admission_receipt_sha256"] == admission_receipt,
            f"case {ordinal}: calibration, CPU, or admission varies",
        )
        bind_receipt(
            receipt_registry,
            pair["affinity_receipt_sha256"],
            (*case_binding, "affinity"),
            f"case {ordinal}: affinity",
        )
        bind_receipt(
            receipt_registry,
            pair["admission_receipt_sha256"],
            (*case_binding, "admission"),
            f"case {ordinal}: admission",
        )
        validate_measurement(pair["portable"], expected_span, "full-portable")
        validate_measurement(
            pair["candidate"],
            expected_span,
            "portable-prefix-static-tail",
        )
        require(
            pair["portable"]["output_accumulator"]
            == pair["candidate"]["output_accumulator"],
            f"case {ordinal} pair {pair_index}: output accumulator differs",
        )
        output_accumulator = (
            pair["portable"]["output_accumulator"]
            if output_accumulator is None
            else output_accumulator
        )
        require(
            pair["portable"]["output_accumulator"] == output_accumulator,
            f"case {ordinal}: output accumulator varies across six pairs",
        )
        ratios.append(
            Fraction(
                pair["candidate"]["elapsed_ns"],
                pair["portable"]["elapsed_ns"],
            )
        )
    ratios.sort()
    median = (ratios[2] + ratios[3]) / 2
    return median


def validate_correctness_case(
    case: dict[str, Any],
    row: dict[str, Any],
    ordinal: int,
    expected_campaign_id: str,
    compiler_by_literal: dict[str, dict[str, Any]],
    receipt_registry: dict[str, str],
    canonical_host: str,
) -> None:
    expected_span = (
        None
        if row["expected_match_start"] is None
        else [row["expected_match_start"], row["expected_match_end"]]
    )
    require(
        isinstance(case, dict)
        and set(case) == CORRECTNESS_CASE_FIELDS
        and case["schema"] == CORRECTNESS_CASE_SCHEMA
        and case["campaign_id"] == expected_campaign_id
        and exact_uint(case["ordinal"], ordinal)
        and case["row_sha256"] == row["row_sha256"]
        and case["literal_sha256"] == row["literal_sha256"]
        and case["literal_hex"] == row["literal_hex"],
        f"correctness case {ordinal}: identity changed",
    )
    expected_compiler = compiler_by_literal[row["literal_sha256"]]
    require(
        isinstance(case["compiler"], dict)
        and set(case["compiler"]) == COMPILER_FIELDS
        and exact_json(case["compiler"], expected_compiler)
        and case["compiler"]["disposition"]
        == row["expected_compiler_disposition"],
        f"correctness case {ordinal}: compiler evidence changed",
    )
    count = expected_nonoverlapping_count(row)
    static_invocations = 1 if row["expected_static_invoked"] else 0
    precheck = case["precheck"]
    require(
        isinstance(precheck, dict)
        and set(precheck) == PRECHECK_FIELDS
        and exact_uint(precheck["expected_nonoverlapping_count"], count)
        and exact_uint(precheck["portable_nonoverlapping_count"], count)
        and exact_uint(precheck["candidate_nonoverlapping_count"], count)
        and precheck["portable_route"] == "full-portable"
        and precheck["candidate_route"] == row["expected_route"]
        and exact_uint(precheck["portable_static_invocations"], 0)
        and exact_uint(
            precheck["candidate_static_invocations"], static_invocations
        ),
        f"correctness case {ordinal}: count or route changed",
    )
    validate_span(
        precheck["scalar_span"],
        expected_span,
        f"correctness case {ordinal}: scalar span",
    )
    validate_span(
        precheck["portable_span"],
        expected_span,
        f"correctness case {ordinal}: portable span",
    )
    validate_span(
        precheck["candidate_span"],
        expected_span,
        f"correctness case {ordinal}: candidate span",
    )
    validate_mapping(
        case["mapping"],
        row,
        receipt_registry,
        (
            canonical_host,
            "correctness",
            str(ordinal),
            row["row_sha256"],
        ),
    )


def canonical_line(
    source: BinaryIO,
    maximum: int,
    message: str,
) -> tuple[bytes, dict[str, Any]]:
    encoded = source.readline(maximum + 1)
    require(
        1 < len(encoded) <= maximum
        and encoded.endswith(b"\n")
        and b"\x00" not in encoded,
        message,
    )
    parsed = json.loads(encoded)
    require(
        isinstance(parsed, dict) and canonical_bytes(parsed) + b"\n" == encoded,
        message,
    )
    return encoded, parsed


def validate_common_header(
    header: dict[str, Any],
    fields: set[str],
    schema: str,
    case_records: int,
    authority_host: dict[str, Any],
    expected_host: dict[str, Any],
    authority: dict[str, Any],
    expected_campaign_id: str,
) -> None:
    require(
        isinstance(header, dict)
        and set(header) == fields
        and header["schema"] == schema
        and header["campaign_id"] == expected_campaign_id
        and header["frozen_host"] == expected_host["frozen_name"]
        and header["canonical_host"] == expected_host["canonical_name"]
        and header["target_triple"] == expected_host["target_triple"]
        and exact_json(header["features"], expected_host["features"])
        and header["host_attestation_sha256"]
        == authority_host["host_attestation_sha256"]
        and header["runner_binary_sha256"]
        == authority_host["runner_binary_sha256"]
        and header["linked_image_sha256"]
        == authority_host["linked_image_sha256"]
        and header["linked_image_platform_identity_sha256"]
        == authority_host["linked_image_platform_identity_sha256"]
        and header["build_closure_sha256"]
        == authority_host["build_closure_sha256"]
        and header["toolchain_closure_sha256"]
        == authority_host["toolchain_closure_sha256"]
        and header["runner_source_commit"]
        == authority["runner"]["source_commit"]
        and header["runner_source_set_sha256"]
        == authority["runner"]["source_set_sha256"]
        and header["object_manifest_sha256"]
        == authority["runner"]["object_manifest_sha256"]
        and header["object_evidence_sha256"]
        == authority_host["object_evidence"]["sha256"]
        and header["qualification_plan_sha256"]
        == authority["qualification_plan_sha256"]
        and exact_uint(header["case_records"], case_records),
        f"{expected_host['canonical_name']}: bundle header changed",
    )


def parse_correctness_bundle(
    result_fd: int,
    qualification_fd: int,
    bundle: dict[str, Any],
    authority_host: dict[str, Any],
    expected_host: dict[str, Any],
    authority: dict[str, Any],
    expected_campaign_id: str,
    plan: dict[str, Any],
    compiler_by_literal: dict[str, dict[str, Any]],
    receipt_registry: dict[str, str],
) -> dict[str, int]:
    expected_name = f"{expected_host['canonical_name']}.correctness.jsonl"
    require(
        isinstance(bundle, dict)
        and set(bundle) == CORRECTNESS_BUNDLE_FIELDS
        and bundle["path"] == expected_name
        and is_uint(bundle["bytes"])
        and bundle["bytes"] > 0
        and is_hex(bundle["sha256"])
        and exact_uint(bundle["case_records"], FULL_ROWS),
        f"{expected_host['canonical_name']}: correctness receipt changed",
    )
    result, result_before = open_regular_at(
        result_fd, expected_name, 2 * 1024 * 1024 * 1024
    )
    projection_receipt = plan["payload"]["full_projection"]
    require(
        flat_name(projection_receipt["path"])
        and exact_uint(projection_receipt["rows"], FULL_ROWS)
        and projection_receipt["projection_digest"]
        == FULL_PROJECTION_DIGEST,
        "full projection receipt changed",
    )
    projection, projection_before = open_regular_at(
        qualification_fd,
        projection_receipt["path"],
        512 * 1024 * 1024,
    )
    result_digest = hashlib.sha256()
    prefix_digest = hashlib.sha256()
    projection_file_digest = hashlib.sha256()
    projection_digest = hashlib.sha256(PROJECTION_DOMAIN)
    result_bytes = 0
    projection_bytes = 0
    routes: dict[str, int] = defaultdict(int)
    literals: set[str] = set()
    try:
        encoded, header = canonical_line(
            result, 64 * 1024, "correctness header changed"
        )
        result_digest.update(encoded)
        prefix_digest.update(encoded)
        result_bytes += len(encoded)
        validate_common_header(
            header,
            CORRECTNESS_HEADER_FIELDS,
            CORRECTNESS_HEADER_SCHEMA,
            FULL_ROWS,
            authority_host,
            expected_host,
            authority,
            expected_campaign_id,
        )
        for ordinal in range(FULL_ROWS):
            projection_line, row = canonical_line(
                projection,
                16 * 1024,
                f"full projection row {ordinal} changed",
            )
            projection_file_digest.update(projection_line)
            projection_digest.update(
                len(projection_line).to_bytes(8, "little")
            )
            projection_digest.update(projection_line)
            projection_bytes += len(projection_line)
            case_line, case = canonical_line(
                result,
                32 * 1024,
                f"correctness case line {ordinal} changed",
            )
            result_digest.update(case_line)
            prefix_digest.update(case_line)
            result_bytes += len(case_line)
            validate_correctness_case(
                case,
                row,
                ordinal,
                expected_campaign_id,
                compiler_by_literal,
                receipt_registry,
                expected_host["canonical_name"],
            )
            routes[row["expected_route"]] += 1
            literals.add(row["literal_sha256"])
        require(
            projection.read(1) == b"",
            "full projection has trailing rows",
        )
        trailer_line, trailer = canonical_line(
            result, 64 * 1024, "correctness trailer changed"
        )
        result_digest.update(trailer_line)
        result_bytes += len(trailer_line)
        require(result.read(1) == b"", "correctness bundle has trailing bytes")
        require(
            isinstance(trailer, dict)
            and set(trailer) == TRAILER_FIELDS
            and trailer["schema"] == CORRECTNESS_TRAILER_SCHEMA
            and trailer["campaign_id"] == expected_campaign_id
            and exact_uint(trailer["case_records"], FULL_ROWS)
            and exact_uint(trailer["pairs"], 0)
            and exact_uint(trailer["measurements"], 0)
            and trailer["prefix_sha256"] == prefix_digest.hexdigest(),
            f"{expected_host['canonical_name']}: correctness trailer changed",
        )
        require_unchanged_descriptor(
            result, result_before, expected_name
        )
        require_unchanged_descriptor(
            projection, projection_before, projection_receipt["path"]
        )
    finally:
        result.close()
        projection.close()
    require(
        result_bytes == result_before.st_size
        and exact_uint(bundle["bytes"], result_bytes)
        and result_digest.hexdigest() == bundle["sha256"]
        and projection_bytes == projection_before.st_size
        and projection_file_digest.hexdigest()
        == projection_receipt["file_sha256"]
        and projection_digest.hexdigest() == FULL_PROJECTION_DIGEST
        and len(literals) == len(compiler_by_literal) == 922,
        f"{expected_host['canonical_name']}: correctness completeness changed",
    )
    return dict(routes)


def parse_host_bundle(
    result_fd: int,
    bundle: dict[str, Any],
    authority_host: dict[str, Any],
    expected_host: dict[str, Any],
    authority: dict[str, Any],
    expected_campaign_id: str,
    timed_rows: list[dict[str, Any]],
    compiler_by_literal: dict[str, dict[str, Any]],
    receipt_registry: dict[str, str],
) -> tuple[list[Fraction], dict[tuple[str, str], list[Fraction]]]:
    expected_name = f"{expected_host['canonical_name']}.timing.jsonl"
    require(
        isinstance(bundle, dict)
        and set(bundle) == TIMING_BUNDLE_FIELDS
        and bundle["path"] == expected_name
        and is_uint(bundle["bytes"])
        and bundle["bytes"] > 0
        and is_hex(bundle["sha256"])
        and exact_uint(bundle["case_records"], TIMED_ROWS)
        and exact_uint(bundle["pairs"], PAIRS_PER_HOST)
        and exact_uint(bundle["measurements"], MEASUREMENTS_PER_HOST),
        f"{expected_host['canonical_name']}: bundle receipt changed",
    )
    source, before = open_regular_at(
        result_fd, expected_name, 1024 * 1024 * 1024
    )
    file_digest = hashlib.sha256()
    prefix_digest = hashlib.sha256()
    total_bytes = 0
    ratios: list[Fraction] = []
    groups: dict[tuple[str, str], list[Fraction]] = defaultdict(list)
    try:
        header_line, header = canonical_line(
            source, 64 * 1024, "timing header changed"
        )
        file_digest.update(header_line)
        prefix_digest.update(header_line)
        total_bytes += len(header_line)
        validate_common_header(
            header,
            HEADER_FIELDS,
            HEADER_SCHEMA,
            TIMED_ROWS,
            authority_host,
            expected_host,
            authority,
            expected_campaign_id,
        )
        require(
            exact_uint(header["pairs"], PAIRS_PER_HOST)
            and exact_uint(
                header["measurements"], MEASUREMENTS_PER_HOST
            ),
            f"{expected_host['canonical_name']}: timing totals changed",
        )
        for ordinal, row in enumerate(timed_rows):
            case_line, case = canonical_line(
                source,
                256 * 1024,
                f"timing case line {ordinal} changed",
            )
            file_digest.update(case_line)
            prefix_digest.update(case_line)
            total_bytes += len(case_line)
            ratio = validate_case(
                case,
                row,
                ordinal,
                expected_campaign_id,
                compiler_by_literal,
                receipt_registry,
                expected_host["canonical_name"],
                set(authority_host["allowed_logical_cpus"]),
                authority["runner"]["timed_function_identity_sha256"],
            )
            ratios.append(ratio)
            for key in group_keys(case["dimensions"]):
                groups[key].append(ratio)
        trailer_line, trailer = canonical_line(
            source, 64 * 1024, "timing trailer changed"
        )
        file_digest.update(trailer_line)
        total_bytes += len(trailer_line)
        require(
            source.read(1) == b""
            and isinstance(trailer, dict)
            and set(trailer) == TRAILER_FIELDS
            and trailer["schema"] == TRAILER_SCHEMA
            and trailer["campaign_id"] == expected_campaign_id
            and exact_uint(trailer["case_records"], TIMED_ROWS)
            and exact_uint(trailer["pairs"], PAIRS_PER_HOST)
            and exact_uint(
                trailer["measurements"], MEASUREMENTS_PER_HOST
            )
            and trailer["prefix_sha256"] == prefix_digest.hexdigest(),
            f"{expected_host['canonical_name']}: timing trailer changed",
        )
        require_unchanged_descriptor(source, before, expected_name)
    finally:
        source.close()
    require(
        len(ratios) == TIMED_ROWS
        and total_bytes == before.st_size
        and exact_uint(bundle["bytes"], total_bytes)
        and file_digest.hexdigest() == bundle["sha256"],
        f"{expected_host['canonical_name']}: case bijection changed",
    )
    return ratios, groups


def rational_receipt(value: Fraction) -> dict[str, Any]:
    return {
        "numerator": value.numerator,
        "denominator": value.denominator,
        "decimal_diagnostic": float(value),
    }


def main() -> None:
    require(
        len(sys.argv) == 5,
        (
            "usage: analyze_qualification_results.py QUALIFICATION_DIR "
            "CAMPAIGN_AUTHORITY EXPECTED_AUTHORITY_FILE_SHA256 "
            "RESULT_MANIFEST"
        ),
    )
    qualification_root = Path(sys.argv[1]).resolve(strict=True)
    authority_path = Path(sys.argv[2])
    expected_authority_sha256 = sys.argv[3]
    manifest_path = Path(sys.argv[4])
    require(
        authority_path.name == "campaign-authority.json"
        and manifest_path.name == "result-manifest.json"
        and is_hex(expected_authority_sha256),
        "authority or result manifest path changed",
    )
    authority_root = authority_path.parent.resolve(strict=True)
    result_root = manifest_path.parent.resolve(strict=True)
    with (
        held_directory(qualification_root) as qualification_fd,
        held_directory(authority_root) as authority_fd,
        held_directory(result_root) as result_fd,
    ):
        plan = validate_plan(qualification_root, qualification_fd)
        timed_rows = load_timed_rows(
            qualification_root, plan, qualification_fd
        )
        authority_bytes, authority_file_sha256 = read_regular_at(
            authority_fd, "campaign-authority.json", 16 * 1024 * 1024
        )
        require(
            authority_file_sha256 == expected_authority_sha256,
            "campaign authority does not match the pre-result expected SHA-256",
        )
        authority_envelope = json.loads(authority_bytes)
        require(
            isinstance(authority_envelope, dict)
            and set(authority_envelope) == AUTHORITY_ENVELOPE_FIELDS
            and authority_envelope["schema"] == AUTHORITY_SCHEMA
            and is_hex(authority_envelope["payload_sha256"])
            and canonical_sha(authority_envelope["payload"])
            == authority_envelope["payload_sha256"],
            "campaign authority envelope changed",
        )
        authority = authority_envelope["payload"]
        analyzer_sha256 = sha256(regular_file(Path(__file__).resolve()))
        validator_path = Path(__file__).resolve().with_name(
            "validate_qualification_plan.py"
        )
        qualification_validator_sha256 = sha256(regular_file(validator_path))
        validate_authority(
            authority,
            plan,
            analyzer_sha256,
            qualification_validator_sha256,
        )
        expected_campaign_id = campaign_id(authority_file_sha256)
        manifest_bytes, _ = read_regular_at(
            result_fd, "result-manifest.json", 16 * 1024 * 1024
        )
        manifest = json.loads(manifest_bytes)
        require(
            isinstance(manifest, dict)
            and set(manifest)
            == {
                "schema",
                "campaign_id",
                "campaign_authority_sha256",
                "hosts",
            }
            and manifest["schema"] == MANIFEST_SCHEMA
            and manifest["campaign_id"] == expected_campaign_id
            and manifest["campaign_authority_sha256"]
            == authority_file_sha256,
            "result manifest envelope changed",
        )
        hosts = manifest["hosts"]
        require(
            isinstance(hosts, list)
            and len(hosts) == len(HOSTS)
            and all(
                isinstance(host, dict) and set(host) == HOST_MANIFEST_FIELDS
                for host in hosts
            ),
            "host manifest set changed",
        )
        output_hosts: dict[str, Any] = {}
        all_pass = True
        receipt_registry: dict[str, str] = {}
        expected_group_counts: dict[tuple[str, str], int] = defaultdict(int)
        for row in timed_rows:
            for key in group_keys(expected_dimensions(row)):
                expected_group_counts[key] += 1
        prepared_hosts = []
        for (
            manifest_host,
            authority_host,
            expected_host,
        ) in zip(hosts, authority["hosts"], HOSTS, strict=True):
            require(
                manifest_host["frozen_name"] == expected_host["frozen_name"]
                and manifest_host["canonical_name"]
                == expected_host["canonical_name"],
                "result host membership changed",
            )
            compiler_by_literal = load_object_evidence(
                authority_fd,
                authority_host,
                expected_host,
                plan,
                qualification_fd,
            )
            correctness_routes = parse_correctness_bundle(
                result_fd,
                qualification_fd,
                manifest_host["correctness_bundle"],
                authority_host,
                expected_host,
                authority,
                expected_campaign_id,
                plan,
                compiler_by_literal,
                receipt_registry,
            )
            prepared_hosts.append(
                (
                    manifest_host,
                    authority_host,
                    expected_host,
                    compiler_by_literal,
                    correctness_routes,
                )
            )
        # No performance record is consumed until both hosts have completed
        # their exact 123,424-row correctness and route projections.
        for (
            manifest_host,
            authority_host,
            expected_host,
            compiler_by_literal,
            correctness_routes,
        ) in prepared_hosts:
            ratios, groups = parse_host_bundle(
                result_fd,
                manifest_host["timing_bundle"],
                authority_host,
                expected_host,
                authority,
                expected_campaign_id,
                timed_rows,
                compiler_by_literal,
                receipt_registry,
            )
            failing = [
                timed_rows[index]["row_sha256"]
                for index, ratio in enumerate(ratios)
                if ratio >= STRICT_GATE
            ]
            host_pass = not failing
            all_pass = all_pass and host_pass
            group_output = {}
            for (dimension, value), group_ratios in sorted(groups.items()):
                group_pass = all(
                    ratio < STRICT_GATE for ratio in group_ratios
                )
                require(
                    len(group_ratios)
                    == expected_group_counts[(dimension, value)],
                    "group completeness reconstruction changed",
                )
                group_output[f"{dimension}={value}"] = {
                    "cells": len(group_ratios),
                    "maximum_cell_ratio": rational_receipt(
                        max(group_ratios)
                    ),
                    "pass_as_conjunction_of_cells": group_pass,
                    "authorizes_independently": False,
                }
            require(
                set(groups) == set(expected_group_counts),
                "result strata set differs from frozen projection",
            )
            output_hosts[expected_host["canonical_name"]] = {
                "full_correctness_rows": FULL_ROWS,
                "full_correctness_routes": correctness_routes,
                "cells": len(ratios),
                "maximum_cell_ratio": rational_receipt(max(ratios)),
                "failing_cells": failing,
                "cell_gate": "strictly-less-than-4/5",
                "pass": host_pass,
                "strata_completeness": group_output,
            }
    output = {
        "schema": "fre.aot.search-tag29-paired-result-analysis.v2",
        "campaign_id": expected_campaign_id,
        "campaign_authority_sha256": authority_file_sha256,
        "qualification_plan_sha256": plan["sha256"],
        "full_projection_digest": FULL_PROJECTION_DIGEST,
        "timed_projection_digest": TIMED_PROJECTION_DIGEST,
        "hosts": output_hosts,
        "total_correctness_rows": FULL_ROWS * len(HOSTS),
        "total_cells": TIMED_ROWS * len(HOSTS),
        "total_pairs": PAIRS_PER_HOST * len(HOSTS),
        "total_measurements": MEASUREMENTS_PER_HOST * len(HOSTS),
        "rebar_inputs": [],
        "result_derived_exclusions": False,
        "aggregate_rescue_permitted": False,
        "pass": all_pass,
    }
    print(json.dumps(output, sort_keys=True, indent=2))
    if not all_pass:
        raise SystemExit(1)


if __name__ == "__main__":
    try:
        main()
    except (
        OSError,
        UnicodeError,
        ValueError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
        Refusal,
    ) as error:
        print(f"search-tag29-paired-results: {error}", file=sys.stderr)
        raise SystemExit(1)
