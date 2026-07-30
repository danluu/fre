#!/usr/bin/env python3
"""Fail-closed analyzer for the tag-30 ripgrep application campaign."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
from fractions import Fraction
from pathlib import Path
from types import ModuleType
from typing import Any


CONTRACT_RELATIVE = (
    "research/aot/search-ripgrep-application-tag30-v1/"
    "campaign-contract-v1.json"
)
CONTRACT_SHA256 = (
    "db2faa1308d3a103a2b5fc5ebb2c26c0461fadddffc3f214cfcd23e25a8dbfc7"
)
PROJECTION_RELATIVE = (
    "research/aot/search-ripgrep-application-tag30-v1/"
    "projection-v1.jsonl"
)
PROJECTION_SHA256 = (
    "1ea6896b7d89bb812130d6f6c4b743d9eed79169c0154f0b6bb37686576b9332"
)
PROJECTION_FILE_SHA256 = (
    "d53ab752f7fc7b16e14e9989a08e4780a2a6865ace451efb9d1a14019040aa77"
)
PROJECTION_PREPARER_RELATIVE = (
    "research/aot/search-ripgrep-application-tag30-v1/"
    "prepare_projection.py"
)
PROJECTION_PREPARER_SHA256 = (
    "4aeaa5b5cae0f167dd538b8dbed07286f0da0350871a6f7bc05e5cd68fe4ec91"
)
FREEZE_VALIDATOR_RELATIVE = (
    "research/aot/search-ripgrep-application-independent-v2/"
    "validate_freeze.py"
)
FREEZE_VALIDATOR_SHA256 = (
    "8e844fe88c6c5c3456f60258f8b0b754c687775f38c4b647314f4195a9133ea5"
)
FREEZE_RELATIVE = (
    "research/aot/search-ripgrep-application-independent-v2/freeze-v2.json"
)
FIXTURE_MANIFEST_SHA256 = (
    "b20181470c604d01d2ec236259293cfcb6e5eff145bcd3e4daa91554c8cebcca"
)
OBJECT_MANIFEST_SHA256 = (
    "ec4e1cf7bbd70f99dc0675b6e3fd47b2da9034753d4f5a1a836206c5756ed0b6"
)
DISPOSITIONS_SHA256 = (
    "433029525cfb74122f275f4282901fc6e7711b34aa7115b4bd53ef537dd5e1a1"
)
BINDING_SCHEMA = (
    "fre.aot.search-tag30-ripgrep-application-campaign-binding.v1"
)
FRAGMENT_HEADER_SCHEMA = (
    "fre.aot.search-tag30-ripgrep-application-fragment-header.v1"
)
CORRECTNESS_ROW_SCHEMA = (
    "fre.aot.search-tag30-ripgrep-application-correctness-row.v1"
)
TIMING_ROW_SCHEMA = (
    "fre.aot.search-tag30-ripgrep-application-timing-row.v1"
)
FRAGMENT_TRAILER_SCHEMA = (
    "fre.aot.search-tag30-ripgrep-application-fragment-trailer.v1"
)
ANALYSIS_SCHEMA = (
    "fre.aot.search-tag30-ripgrep-application-analysis.v1"
)
EVIDENCE_DOMAIN = (
    b"FRE-SEARCH-TAG30-RIPGREP-APPLICATION-EVIDENCE\0\x01"
)
CASES = 154
SHARDS = 16
REPETITIONS = 6
MINIMUM_NS = 400_000_000
CALIBRATION_TARGET_NS = 500_000_000
CALIBRATION_FLOOR_NS = 50_000_000
CALIBRATION_ANCHOR_SAMPLES = 3
MAXIMUM_ITERATIONS = 1 << 30
STATIC_GATE = Fraction(4, 5)
NONTARGET_GATE = Fraction(21, 20)
MAXIMUM_CPU_ONLY_RETRIES = 64
MACOS_SUPER_CLASS_WAIT_TIMEOUT_NS = 5_000_000_000
MACOS_SUPER_CPUS = tuple(range(12, 18))
MACOS_PERFORMANCE_CPUS = tuple(range(12))
MACOS_PERFORMANCE_LEVEL_RECEIPT = {
    "machine_model": "Mac17,7",
    "chip": "Apple M5 Max",
    "mapping_authority": "ioreg-cluster-type-logical-cluster-plus-sysctl",
    "levels": [
        {
            "index": 0,
            "name": "Super",
            "physical_cpus": 6,
            "logical_cpus": 6,
            "cpus_per_l2": 6,
            "l1_data_cache_bytes": 131_072,
            "l2_cache_bytes": 16_777_216,
            "logical_cpu_ids": list(MACOS_SUPER_CPUS),
        },
        {
            "index": 1,
            "name": "Performance",
            "physical_cpus": 12,
            "logical_cpus": 12,
            "cpus_per_l2": 6,
            "l1_data_cache_bytes": 65_536,
            "l2_cache_bytes": 8_388_608,
            "logical_cpu_ids": list(MACOS_PERFORMANCE_CPUS),
        },
    ],
}
EXPECTED_HOSTS = {
    "local-apple-aarch64-asimd": {
        "canonical_host": "apple-aarch64-asimd",
        "target_triple": "aarch64-apple-darwin",
        "features": {
            "asimd": True,
            "sve": False,
            "sve2": False,
        },
    },
    "zstd-eval-c9g-neoverse-v3-aarch64-asimd": {
        "canonical_host": "c9g-aarch64-asimd-sve2",
        "target_triple": "aarch64-unknown-linux-gnu",
        "features": {
            "asimd": True,
            "sve": True,
            "sve2": True,
            "sve_vector_bytes": 16,
        },
    },
}
HEADER_FIELDS = {
    "schema",
    "mode",
    "contract_schema",
    "contract_sha256",
    "projection_schema",
    "projection_rows",
    "projection_sha256",
    "projection_file_sha256",
    "shard_id",
    "shard_start",
    "shard_end",
    "host_id",
    "logical_cpu",
    "cpu_residence_method",
    "affinity_request_status",
    "qos_class",
    "qos_request_status",
    "accepted_cpu_class",
    "accepted_cpu_ids",
    "macos_performance_levels",
    "macos_super_class_wait_timeout_ns",
    "maximum_cpu_only_retries_per_variant",
    "runner_binary_sha256",
    "runner_source_sha256",
    "runner_identity_sha256",
    "source_archive_sha256",
    "private_family_source_sha256",
    "compiler_identity",
    "platform_manifest_identity",
    "build_receipt_sha256",
    "object_manifest_sha256",
    "literal_dispositions_sha256",
    "fixture_manifest_sha256",
    "backend_tag",
    "backend_name",
    "family_selector",
    "minimum_window_bytes",
    "portable_prefix_candidate_starts",
    "plan_identity",
    "analyzer_identity",
    "evidence_identity",
    "private_family_authorization_identity",
    "application_contract_identity",
    "timing_repetitions",
    "minimum_elapsed_ns_each_variant",
    "production_authority",
    "rebar_accepted_as_input",
    "heldout_materialized",
    "result_derived_exclusions",
}
MAPPING_FIELDS = {
    "allocation_start_address",
    "allocation_bytes",
    "checked_pointer_address",
    "checked_bytes",
    "start_offset",
    "actual_window_start_mod16",
    "readable_left_bytes",
    "readable_right_bytes",
    "padding_sentinel",
    "padding_verified",
    "allocation_receipt_sha256",
}
CORRECTNESS_FIELDS = {
    "schema",
    "ordinal",
    "row_sha256",
    "case_id",
    "candidate_sha256",
    "literal_sha256",
    "fixture_sha256",
    "scenario",
    "compiler_disposition",
    "route_class",
    "expected_static_invoked",
    "portable_span",
    "candidate_span",
    "direct_tail_span",
    "scalar_span",
    "scalar_nonoverlapping_count",
    "mapping",
    "worker_logical_cpu",
    "pass",
}
TIMING_FIELDS = {
    "schema",
    "ordinal",
    "row_sha256",
    "case_id",
    "candidate_sha256",
    "literal_sha256",
    "fixture_sha256",
    "scenario",
    "compiler_disposition",
    "route_class",
    "expected_static_invoked",
    "mapping",
    "logical_cpu",
    "minimum_elapsed_ns_each_variant",
    "calibration",
    "pairs",
    "pass",
    "production_authority",
    "rebar_accepted_as_input",
}
PAIR_FIELDS = {
    "repetition",
    "order",
    "iterations",
    "portable_elapsed_ns",
    "candidate_elapsed_ns",
    "portable_checksum",
    "candidate_checksum",
    "portable_cpu_before",
    "portable_cpu_after",
    "portable_cpu_retries",
    "portable_cpu_attempts",
    "candidate_cpu_before",
    "candidate_cpu_after",
    "candidate_cpu_retries",
    "candidate_cpu_attempts",
}
CPU_ATTEMPT_FIELDS = {
    "attempt",
    "cpu_before",
    "cpu_after",
    "accepted",
}
CALIBRATION_FIELDS = {
    "target_elapsed_ns",
    "floor_elapsed_ns",
    "anchor_samples",
    "maximum_iterations",
    "selected_iterations",
    "portable_pilots",
    "candidate_pilots",
}
CALIBRATION_PILOT_FIELDS = {
    "iterations",
    "elapsed_ns",
    "checksum",
    "cpu_before",
    "cpu_after",
    "cpu_retries",
    "cpu_attempts",
}
TRAILER_FIELDS = {
    "schema",
    "rows",
    "shard_start",
    "shard_end",
    "records_sha256",
    "complete",
}


class Refusal(RuntimeError):
    """An authority, evidence, completeness, or gate check failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def sha256(encoded: bytes) -> str:
    return hashlib.sha256(encoded).hexdigest()


def is_hex(value: Any, length: int = 64) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(byte in "0123456789abcdef" for byte in value)
    )


def uint(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def canonical_sha(value: Any) -> str:
    return sha256(canonical_bytes(value))


def regular_file(path: Path, maximum: int) -> bytes:
    before = path.lstat()
    require(
        stat.S_ISREG(before.st_mode)
        and not path.is_symlink()
        and before.st_nlink == 1
        and 0 < before.st_size <= maximum,
        f"not one bounded unshared regular file: {path}",
    )
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        require(
            (
                opened.st_dev,
                opened.st_ino,
                opened.st_mode,
                opened.st_nlink,
                opened.st_size,
            )
            == (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_nlink,
                before.st_size,
            ),
            f"file changed before open: {path}",
        )
        encoded = bytearray()
        while len(encoded) <= maximum:
            block = os.read(
                descriptor, min(1 << 20, maximum + 1 - len(encoded))
            )
            if not block:
                break
            encoded.extend(block)
        after = os.fstat(descriptor)
        require(
            len(encoded) == opened.st_size
            and (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            == (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
                opened.st_ctime_ns,
            ),
            f"file changed while held: {path}",
        )
        return bytes(encoded)
    finally:
        os.close(descriptor)


def load_projection_module(repo: Path) -> ModuleType:
    source_path = repo / PROJECTION_PREPARER_RELATIVE
    source = regular_file(source_path, 2 * 1024 * 1024)
    require(
        sha256(source) == PROJECTION_PREPARER_SHA256,
        "projection preparer changed",
    )
    specification = importlib.util.spec_from_file_location(
        "_fre_tag30_application_projection", source_path
    )
    require(specification is not None, "cannot load projection preparer")
    module = importlib.util.module_from_spec(specification)
    assert specification.loader is not None
    specification.loader.exec_module(module)
    return module


def validate_frozen_inputs(
    repo: Path, ripgrep_root: Path, fixture_root: Path
) -> list[dict[str, Any]]:
    validator = repo / FREEZE_VALIDATOR_RELATIVE
    require(
        sha256(regular_file(validator, 2 * 1024 * 1024))
        == FREEZE_VALIDATOR_SHA256,
        "freeze validator changed",
    )
    subprocess.run(
        [
            sys.executable,
            str(validator),
            str(repo / FREEZE_RELATIVE),
            str(repo),
            str(ripgrep_root),
            str(fixture_root),
        ],
        check=True,
        stdin=subprocess.DEVNULL,
    )
    module = load_projection_module(repo)
    derived, digest = module.derive(repo, fixture_root)
    projection_bytes = regular_file(
        repo / PROJECTION_RELATIVE, 2 * 1024 * 1024
    )
    committed = [
        json.loads(line)
        for line in projection_bytes.splitlines(keepends=True)
    ]
    require(
        digest == PROJECTION_SHA256
        and sha256(projection_bytes) == PROJECTION_FILE_SHA256
        and committed == derived
        and len(committed) == CASES,
        "committed application projection changed",
    )
    return committed


def analyzer_source_sha256() -> str:
    return sha256(regular_file(Path(__file__).resolve(strict=True), 2 << 20))


def load_binding(
    path: Path, expected_sha256: str, source_sha256: str
) -> dict[str, Any]:
    encoded = regular_file(path, 4 * 1024 * 1024)
    require(
        is_hex(expected_sha256)
        and sha256(encoded) == expected_sha256,
        "campaign binding file identity changed",
    )
    root = json.loads(encoded)
    require(
        isinstance(root, dict)
        and set(root) == {"schema", "payload_sha256", "payload"}
        and root["schema"] == BINDING_SCHEMA
        and is_hex(root["payload_sha256"])
        and canonical_sha(root["payload"]) == root["payload_sha256"],
        "campaign binding envelope changed",
    )
    payload = root["payload"]
    fields = {
        "contract_sha256",
        "projection_sha256",
        "projection_file_sha256",
        "fixture_manifest_sha256",
        "object_manifest_sha256",
        "literal_dispositions_sha256",
        "application_analyzer_source_sha256",
        "campaign_plan_identity",
        "campaign_analyzer_identity",
        "campaign_evidence_identity",
        "private_family_authorization_identity",
        "runner_source_commit",
        "runner_source_sha256",
        "source_archive_sha256",
        "private_family_source_sha256",
        "hosts",
        "timing_sealed",
        "bindings_complete",
        "application_qualification_authority",
        "production_authority",
        "rebar_inputs",
        "benchmark_results",
        "external_regex_heldout_inputs",
        "heldout_materialized",
        "result_derived_exclusions",
    }
    require(
        isinstance(payload, dict)
        and set(payload) == fields
        and payload["contract_sha256"] == CONTRACT_SHA256
        and payload["projection_sha256"] == PROJECTION_SHA256
        and payload["projection_file_sha256"]
        == PROJECTION_FILE_SHA256
        and payload["fixture_manifest_sha256"]
        == FIXTURE_MANIFEST_SHA256
        and payload["object_manifest_sha256"]
        == OBJECT_MANIFEST_SHA256
        and payload["literal_dispositions_sha256"]
        == DISPOSITIONS_SHA256
        and payload["application_analyzer_source_sha256"]
        == source_sha256
        and all(
            is_hex(payload[field])
            for field in (
                "campaign_plan_identity",
                "campaign_analyzer_identity",
                "campaign_evidence_identity",
                "private_family_authorization_identity",
                "runner_source_sha256",
                "source_archive_sha256",
                "private_family_source_sha256",
            )
        )
        and is_hex(payload["runner_source_commit"], 40)
        and payload["timing_sealed"] is True
        and payload["bindings_complete"] is True
        and payload["application_qualification_authority"] is True
        and payload["production_authority"] is False
        and payload["rebar_inputs"] == []
        and payload["benchmark_results"] == []
        and payload["external_regex_heldout_inputs"] == []
        and payload["heldout_materialized"] is False
        and payload["result_derived_exclusions"] is False,
        "campaign binding payload changed or remains unresolved",
    )
    hosts = payload["hosts"]
    require(
        isinstance(hosts, list)
        and len(hosts) == 2
        and {host.get("host_id") for host in hosts}
        == set(EXPECTED_HOSTS),
        "campaign binding hosts changed",
    )
    host_fields = {
        "host_id",
        "canonical_host",
        "target_triple",
        "features",
        "allowed_logical_cpus",
        "runner_binary_sha256",
        "runner_identity_sha256",
        "build_receipt_sha256",
        "manifest_identity",
        "compiler_identity",
    }
    for host in hosts:
        expected = EXPECTED_HOSTS[host["host_id"]]
        cpus = host.get("allowed_logical_cpus")
        expected_cpus = (
            list(MACOS_SUPER_CPUS)
            if host["host_id"] == "local-apple-aarch64-asimd"
            else list(range(64, 80))
        )
        require(
            isinstance(host, dict)
            and set(host) == host_fields
            and host["canonical_host"] == expected["canonical_host"]
            and host["target_triple"] == expected["target_triple"]
            and host["features"] == expected["features"]
            and cpus == expected_cpus
            and all(
                is_hex(host[field])
                for field in (
                    "runner_binary_sha256",
                    "runner_identity_sha256",
                    "build_receipt_sha256",
                    "manifest_identity",
                    "compiler_identity",
                )
            ),
            f"campaign binding host changed: {host.get('host_id')}",
        )
    return payload


def shard_bounds(shard: int) -> tuple[int, int]:
    quotient, remainder = divmod(CASES, SHARDS)
    start = shard * quotient + min(shard, remainder)
    return start, start + quotient + int(shard < remainder)


def canonical_line(source: Any, maximum: int, label: str) -> tuple[bytes, Any]:
    encoded = source.readline(maximum + 1)
    require(
        1 < len(encoded) <= maximum
        and encoded.endswith(b"\n"),
        f"{label}: invalid framing",
    )
    value = json.loads(encoded)
    require(
        canonical_bytes(value) + b"\n" == encoded,
        f"{label}: noncanonical JSON",
    )
    return encoded, value


def validate_header(
    header: Any,
    mode: str,
    shard: int,
    host: dict[str, Any],
    binding: dict[str, Any],
) -> None:
    start, end = shard_bounds(shard)
    host_id = host["host_id"]
    cpu_residence_valid = (
        (
            host_id == "local-apple-aarch64-asimd"
            and header.get("cpu_residence_method")
            == (
                "macos-user-interactive-qos-affinity-hint-bounded-super-"
                "wait-cpu-only-retry"
            )
            and header.get("affinity_request_status") in {0, 46}
            and header.get("qos_class") == 0x21
            and header.get("qos_request_status") == 0
            and header.get("accepted_cpu_class") == "Super"
            and header.get("accepted_cpu_ids") == list(MACOS_SUPER_CPUS)
            and header.get("macos_performance_levels")
            == MACOS_PERFORMANCE_LEVEL_RECEIPT
            and header.get("macos_super_class_wait_timeout_ns")
            == MACOS_SUPER_CLASS_WAIT_TIMEOUT_NS
            and header.get("logical_cpu") in MACOS_SUPER_CPUS
            and header.get("maximum_cpu_only_retries_per_variant")
            == MAXIMUM_CPU_ONLY_RETRIES
        )
        or (
            host_id == "zstd-eval-c9g-neoverse-v3-aarch64-asimd"
            and header.get("cpu_residence_method")
            == "linux-sched-setaffinity-plus-samples"
            and header.get("affinity_request_status") == 0
            and header.get("qos_class") is None
            and header.get("qos_request_status") is None
            and header.get("accepted_cpu_class") == "exact-requested"
            and header.get("accepted_cpu_ids")
            == [header.get("logical_cpu")]
            and header.get("macos_performance_levels") is None
            and header.get("macos_super_class_wait_timeout_ns") is None
            and header.get("maximum_cpu_only_retries_per_variant") == 0
        )
    )
    require(
        isinstance(header, dict)
        and set(header) == HEADER_FIELDS
        and header["schema"] == FRAGMENT_HEADER_SCHEMA
        and header["mode"] == mode
        and header["contract_schema"]
        == "fre.aot.search-tag30-ripgrep-application-contract.v1"
        and header["contract_sha256"] == CONTRACT_SHA256
        and header["projection_schema"]
        == "fre.aot.search-tag30-ripgrep-application-projection-row.v1"
        and header["projection_rows"] == CASES
        and header["projection_sha256"] == PROJECTION_SHA256
        and header["projection_file_sha256"]
        == PROJECTION_FILE_SHA256
        and header["shard_id"] == shard
        and header["shard_start"] == start
        and header["shard_end"] == end
        and header["host_id"] == host["host_id"]
        and header["logical_cpu"] in host["allowed_logical_cpus"]
        and cpu_residence_valid
        and header["runner_binary_sha256"]
        == host["runner_binary_sha256"]
        and header["runner_source_sha256"]
        == binding["runner_source_sha256"]
        and header["runner_identity_sha256"]
        == host["runner_identity_sha256"]
        and header["source_archive_sha256"]
        == binding["source_archive_sha256"]
        and header["private_family_source_sha256"]
        == binding["private_family_source_sha256"]
        and header["compiler_identity"] == host["compiler_identity"]
        and header["platform_manifest_identity"]
        == host["manifest_identity"]
        and header["build_receipt_sha256"]
        == host["build_receipt_sha256"]
        and header["object_manifest_sha256"]
        == OBJECT_MANIFEST_SHA256
        and header["literal_dispositions_sha256"]
        == DISPOSITIONS_SHA256
        and header["fixture_manifest_sha256"]
        == FIXTURE_MANIFEST_SHA256
        and header["backend_tag"] == 30
        and header["backend_name"] == "AsimdV17"
        and header["family_selector"] == 13
        and header["minimum_window_bytes"] == 65_536
        and header["portable_prefix_candidate_starts"] == 256
        and header["plan_identity"]
        == binding["campaign_plan_identity"]
        and header["analyzer_identity"]
        == binding["campaign_analyzer_identity"]
        and header["evidence_identity"]
        == binding["campaign_evidence_identity"]
        and header["private_family_authorization_identity"]
        == binding["private_family_authorization_identity"]
        and header["application_contract_identity"] == CONTRACT_SHA256
        and header["timing_repetitions"]
        == (REPETITIONS if mode == "timing" else None)
        and header["minimum_elapsed_ns_each_variant"]
        == (MINIMUM_NS if mode == "timing" else None)
        and header["production_authority"] is False
        and header["rebar_accepted_as_input"] is False
        and header["heldout_materialized"] is False
        and header["result_derived_exclusions"] is False,
        f"{host['host_id']} {mode} shard {shard}: header changed",
    )


def validate_mapping(mapping: Any, row: dict[str, Any]) -> None:
    require(
        isinstance(mapping, dict)
        and set(mapping) == MAPPING_FIELDS
        and all(
            uint(mapping[field])
            for field in MAPPING_FIELDS
            - {"padding_verified", "allocation_receipt_sha256"}
        )
        and is_hex(mapping["allocation_receipt_sha256"])
        and mapping["padding_verified"] is True
        and mapping["allocation_start_address"] > 0
        and mapping["allocation_bytes"] == row["fixture_bytes"] + 63
        and 16 <= mapping["start_offset"] <= 31
        and mapping["checked_pointer_address"]
        == mapping["allocation_start_address"] + mapping["start_offset"]
        and mapping["checked_bytes"] == row["fixture_bytes"]
        and mapping["actual_window_start_mod16"]
        == row["alignment_offset"]
        and mapping["checked_pointer_address"] % 16
        == row["alignment_offset"]
        and mapping["readable_left_bytes"] == mapping["start_offset"]
        and mapping["readable_right_bytes"]
        == 63 - mapping["start_offset"]
        and mapping["padding_sentinel"] == row["padding_sentinel"],
        f"case {row['ordinal']}: mapping changed",
    )


def common_row(result: Any, row: dict[str, Any], fields: set[str]) -> None:
    require(
        isinstance(result, dict)
        and set(result) == fields
        and all(
            result[field] == row[field]
            for field in (
                "ordinal",
                "row_sha256",
                "case_id",
                "candidate_sha256",
                "literal_sha256",
                "fixture_sha256",
                "scenario",
                "route_class",
                "expected_static_invoked",
            )
        )
        and result["compiler_disposition"]
        == row["expected_compiler_disposition"]
        and result["pass"] is True,
        f"case {row['ordinal']}: result identity changed",
    )
    validate_mapping(result["mapping"], row)


def validate_correctness(
    result: Any, row: dict[str, Any], logical_cpu: int
) -> None:
    common_row(result, row, CORRECTNESS_FIELDS)
    expected = row["expected_span"]
    require(
        result["schema"] == CORRECTNESS_ROW_SCHEMA
        and result["portable_span"] == expected
        and result["candidate_span"] == expected
        and result["scalar_span"] == expected
        and result["scalar_nonoverlapping_count"]
        == row["expected_nonoverlapping_count"]
        and result["direct_tail_span"]
        == (expected if row["route_class"] == "tag30-static-tail" else None)
        and result["worker_logical_cpu"] == logical_cpu,
        f"case {row['ordinal']}: correctness or route proof changed",
    )


def validate_cpu_attempts(
    value: Any,
    retries: Any,
    host_id: str,
    requested_cpu: int,
    accepted_before: Any,
    accepted_after: Any,
    context: str,
) -> None:
    maximum_retries = (
        MAXIMUM_CPU_ONLY_RETRIES
        if host_id == "local-apple-aarch64-asimd"
        else 0
    )
    require(
        isinstance(value, list)
        and 1 <= len(value) <= maximum_retries + 1
        and retries == len(value) - 1,
        f"{context}: CPU retry extent changed",
    )
    for ordinal, raw_attempt in enumerate(value):
        require(
            isinstance(raw_attempt, dict)
            and set(raw_attempt) == CPU_ATTEMPT_FIELDS,
            f"{context}: CPU attempt fields changed",
        )
        before = raw_attempt["cpu_before"]
        after = raw_attempt["cpu_after"]
        require(
            raw_attempt["attempt"] == ordinal
            and uint(before)
            and uint(after),
            f"{context}: CPU attempt framing changed",
        )
        if host_id == "local-apple-aarch64-asimd":
            require(
                before in (*MACOS_PERFORMANCE_CPUS, *MACOS_SUPER_CPUS)
                and after in (*MACOS_PERFORMANCE_CPUS, *MACOS_SUPER_CPUS),
                f"{context}: CPU endpoint is outside the authenticated machine",
            )
            accepted = (
                before in MACOS_SUPER_CPUS and after in MACOS_SUPER_CPUS
            )
        else:
            accepted = before == requested_cpu and after == requested_cpu
        require(
            raw_attempt["accepted"] is accepted
            and accepted is (ordinal == len(value) - 1),
            f"{context}: retry was not decided solely by CPU class",
        )
    last = value[-1]
    require(
        last["cpu_before"] == accepted_before
        and last["cpu_after"] == accepted_after,
        f"{context}: accepted endpoints differ from the attempt receipt",
    )


def scaled_iterations(pilot: dict[str, Any]) -> int:
    numerator = (
        CALIBRATION_TARGET_NS * pilot["iterations"]
        + pilot["elapsed_ns"]
        - 1
    )
    return min(
        MAXIMUM_ITERATIONS,
        max(1, numerator // pilot["elapsed_ns"]),
    )


def validate_calibration_pilots(
    value: Any,
    host_id: str,
    requested_cpu: int,
    context: str,
) -> list[dict[str, Any]]:
    require(
        isinstance(value, list) and len(value) >= CALIBRATION_ANCHOR_SAMPLES,
        f"{context}: calibration pilot set lacks frozen anchors",
    )
    pilots: list[dict[str, Any]] = []
    expected_iterations = 1
    anchor_start = len(value) - CALIBRATION_ANCHOR_SAMPLES
    for ordinal, raw_pilot in enumerate(value):
        require(
            isinstance(raw_pilot, dict)
            and set(raw_pilot) == CALIBRATION_PILOT_FIELDS,
            f"{context} pilot {ordinal}: fields changed",
        )
        require(
            raw_pilot["iterations"] == expected_iterations
            and uint(raw_pilot["elapsed_ns"])
            and raw_pilot["elapsed_ns"] > 0
            and uint(raw_pilot["checksum"])
            and uint(raw_pilot["cpu_before"])
            and uint(raw_pilot["cpu_after"]),
            f"{context} pilot {ordinal}: calibration receipt changed",
        )
        validate_cpu_attempts(
            raw_pilot["cpu_attempts"],
            raw_pilot["cpu_retries"],
            host_id,
            requested_cpu,
            raw_pilot["cpu_before"],
            raw_pilot["cpu_after"],
            f"{context} pilot {ordinal}",
        )
        pilots.append(raw_pilot)
        if ordinal < anchor_start:
            require(
                raw_pilot["elapsed_ns"] < CALIBRATION_FLOOR_NS
                and raw_pilot["iterations"] < MAXIMUM_ITERATIONS,
                f"{context} pilot {ordinal}: unnecessary pilot followed",
            )
            expected_iterations = min(
                MAXIMUM_ITERATIONS,
                raw_pilot["iterations"] * 4,
            )
        elif ordinal + 1 < len(value):
            expected_iterations = raw_pilot["iterations"]
    require(
        pilots[anchor_start]["elapsed_ns"] >= CALIBRATION_FLOOR_NS
        or pilots[anchor_start]["iterations"] == MAXIMUM_ITERATIONS,
        f"{context}: calibration stopped before the frozen floor",
    )
    anchor_iterations = pilots[anchor_start]["iterations"]
    require(
        all(
            pilot["iterations"] == anchor_iterations
            for pilot in pilots[anchor_start:]
        ),
        f"{context}: calibration anchor iterations changed",
    )
    return pilots[anchor_start:]


def validate_calibration(
    value: Any,
    host_id: str,
    requested_cpu: int,
    context: str,
) -> int:
    require(
        isinstance(value, dict) and set(value) == CALIBRATION_FIELDS,
        f"{context}: calibration fields changed",
    )
    require(
        value["target_elapsed_ns"] == CALIBRATION_TARGET_NS
        and value["floor_elapsed_ns"] == CALIBRATION_FLOOR_NS
        and value["anchor_samples"] == CALIBRATION_ANCHOR_SAMPLES
        and value["maximum_iterations"] == MAXIMUM_ITERATIONS,
        f"{context}: calibration constants changed",
    )
    portable = validate_calibration_pilots(
        value["portable_pilots"],
        host_id,
        requested_cpu,
        f"{context} portable",
    )
    candidate = validate_calibration_pilots(
        value["candidate_pilots"],
        host_id,
        requested_cpu,
        f"{context} candidate",
    )
    selected = max(
        *(scaled_iterations(pilot) for pilot in portable),
        *(scaled_iterations(pilot) for pilot in candidate),
    )
    require(
        value["selected_iterations"] == selected,
        f"{context}: selected iterations changed",
    )
    return selected


def validate_timing(
    result: Any,
    row: dict[str, Any],
    logical_cpu: int,
    host_id: str = "local-apple-aarch64-asimd",
) -> Fraction:
    common_row(result, row, TIMING_FIELDS)
    require(
        result["schema"] == TIMING_ROW_SCHEMA
        and result["logical_cpu"] == logical_cpu
        and result["minimum_elapsed_ns_each_variant"] == MINIMUM_NS
        and result["production_authority"] is False
        and result["rebar_accepted_as_input"] is False
        and isinstance(result["pairs"], list)
        and len(result["pairs"]) == REPETITIONS,
        f"case {row['ordinal']}: timing contract changed",
    )
    selected_iterations = validate_calibration(
        result["calibration"],
        host_id,
        logical_cpu,
        f"case {row['ordinal']} calibration",
    )
    ratios = []
    iterations = None
    checksum = None
    for repetition, pair in enumerate(result["pairs"]):
        require(
            isinstance(pair, dict)
            and set(pair) == PAIR_FIELDS
            and pair["repetition"] == repetition
            and pair["order"]
            == ("portable-first" if repetition % 2 == 0 else "candidate-first")
            and uint(pair["iterations"])
            and pair["iterations"] > 0
            and uint(pair["portable_elapsed_ns"])
            and uint(pair["candidate_elapsed_ns"])
            and pair["portable_elapsed_ns"] >= MINIMUM_NS
            and pair["candidate_elapsed_ns"] >= MINIMUM_NS
            and uint(pair["portable_checksum"])
            and pair["portable_checksum"] == pair["candidate_checksum"]
            and all(
                uint(pair[field])
                for field in (
                    "portable_cpu_before",
                    "portable_cpu_after",
                    "candidate_cpu_before",
                    "candidate_cpu_after",
                )
            ),
            f"case {row['ordinal']} pair {repetition}: measurement changed",
        )
        validate_cpu_attempts(
            pair["portable_cpu_attempts"],
            pair["portable_cpu_retries"],
            host_id,
            logical_cpu,
            pair["portable_cpu_before"],
            pair["portable_cpu_after"],
            f"case {row['ordinal']} pair {repetition} portable",
        )
        validate_cpu_attempts(
            pair["candidate_cpu_attempts"],
            pair["candidate_cpu_retries"],
            host_id,
            logical_cpu,
            pair["candidate_cpu_before"],
            pair["candidate_cpu_after"],
            f"case {row['ordinal']} pair {repetition} candidate",
        )
        if iterations is None:
            iterations = pair["iterations"]
            checksum = pair["portable_checksum"]
        require(
            pair["iterations"] == iterations
            and pair["portable_checksum"] == checksum,
            f"case {row['ordinal']}: paired work changed",
        )
        ratios.append(
            Fraction(
                pair["candidate_elapsed_ns"],
                pair["portable_elapsed_ns"],
            )
        )
    ratios.sort()
    require(
        iterations == selected_iterations,
        f"case {row['ordinal']}: calibrated iterations changed",
    )
    return (ratios[2] + ratios[3]) / 2


def parse_fragment(
    path: Path,
    mode: str,
    shard: int,
    host: dict[str, Any],
    binding: dict[str, Any],
    rows: list[dict[str, Any]],
) -> list[Fraction]:
    encoded = regular_file(
        path, 64 * 1024 * 1024 if mode == "timing" else 16 * 1024 * 1024
    )
    source = memoryview(encoded)
    # BytesIO retains the exact immutable fragment for canonical line reads.
    import io

    stream = io.BytesIO(source)
    _, header = canonical_line(stream, 64 * 1024, "fragment header")
    validate_header(header, mode, shard, host, binding)
    start, end = shard_bounds(shard)
    digest = hashlib.sha256()
    ratios: list[Fraction] = []
    for ordinal in range(start, end):
        line, result = canonical_line(
            stream,
            512 * 1024 if mode == "timing" else 128 * 1024,
            f"fragment row {ordinal}",
        )
        digest.update(len(line).to_bytes(8, "little"))
        digest.update(line)
        row = rows[ordinal]
        if mode == "correctness":
            validate_correctness(result, row, header["logical_cpu"])
        else:
            ratios.append(
                validate_timing(
                    result,
                    row,
                    header["logical_cpu"],
                    header["host_id"],
                )
            )
    _, trailer = canonical_line(stream, 64 * 1024, "fragment trailer")
    require(
        stream.read(1) == b""
        and isinstance(trailer, dict)
        and set(trailer) == TRAILER_FIELDS
        and trailer["schema"] == FRAGMENT_TRAILER_SCHEMA
        and trailer["rows"] == end - start
        and trailer["shard_start"] == start
        and trailer["shard_end"] == end
        and trailer["records_sha256"] == digest.hexdigest()
        and trailer["complete"] is True,
        f"{host['host_id']} {mode} shard {shard}: trailer changed",
    )
    return ratios


def rational(value: Fraction) -> dict[str, int]:
    return {"numerator": value.numerator, "denominator": value.denominator}


def analyze(
    repo: Path,
    ripgrep_root: Path,
    fixture_root: Path,
    binding_path: Path,
    expected_binding_sha256: str,
    result_root: Path,
) -> dict[str, Any]:
    require(
        sha256(regular_file(repo / CONTRACT_RELATIVE, 128 * 1024))
        == CONTRACT_SHA256,
        "application contract changed",
    )
    rows = validate_frozen_inputs(repo, ripgrep_root, fixture_root)
    source_sha256 = analyzer_source_sha256()
    binding = load_binding(
        binding_path, expected_binding_sha256, source_sha256
    )
    expected_names = {
        f"{host_id}.{mode}.shard-{shard:02}.jsonl"
        for host_id in EXPECTED_HOSTS
        for mode in ("correctness", "timing")
        for shard in range(SHARDS)
    }
    actual_names = {entry.name for entry in os.scandir(result_root)}
    require(
        actual_names == expected_names,
        "result directory is not the exact 64-fragment campaign",
    )
    hosts = {host["host_id"]: host for host in binding["hosts"]}

    # All correctness, compile dispositions, and route proofs are consumed
    # before any timing fragment is opened.
    for host_id in EXPECTED_HOSTS:
        for shard in range(SHARDS):
            parse_fragment(
                result_root
                / f"{host_id}.correctness.shard-{shard:02}.jsonl",
                "correctness",
                shard,
                hosts[host_id],
                binding,
                rows,
            )

    output_hosts = []
    for host_id in EXPECTED_HOSTS:
        ratios: list[Fraction] = []
        for shard in range(SHARDS):
            ratios.extend(
                parse_fragment(
                    result_root
                    / f"{host_id}.timing.shard-{shard:02}.jsonl",
                    "timing",
                    shard,
                    hosts[host_id],
                    binding,
                    rows,
                )
            )
        require(len(ratios) == CASES, f"{host_id}: timing incomplete")
        by_route: dict[str, list[Fraction]] = {
            "tag30-static-tail": [],
            "portable-prefix-return": [],
            "full-portable-fallback": [],
        }
        for row, ratio in zip(rows, ratios, strict=True):
            by_route[row["route_class"]].append(ratio)
            gate = (
                STATIC_GATE
                if row["route_class"] == "tag30-static-tail"
                else NONTARGET_GATE
            )
            relation = ratio < gate if gate == STATIC_GATE else ratio <= gate
            require(
                relation,
                f"{host_id} case {row['ordinal']} failed "
                f"{row['route_class']} gate: {ratio}",
            )
        require(
            {route: len(values) for route, values in by_route.items()}
            == {
                "tag30-static-tail": 75,
                "portable-prefix-return": 10,
                "full-portable-fallback": 69,
            },
            f"{host_id}: route cardinality changed",
        )
        output_hosts.append(
            {
                "host_id": host_id,
                "case_count": CASES,
                "route_counts": {
                    route: len(values)
                    for route, values in by_route.items()
                },
                "worst_fixture_ratio": {
                    route: rational(max(values))
                    for route, values in by_route.items()
                },
                "all_per_fixture_gates_pass": True,
            }
        )
    payload = {
        "contract_sha256": CONTRACT_SHA256,
        "projection_sha256": PROJECTION_SHA256,
        "application_analyzer_source_sha256": source_sha256,
        "campaign_binding_sha256": expected_binding_sha256,
        "hosts": output_hosts,
        "candidate_count": 11,
        "fixture_count": CASES,
        "eligible_candidate_count": 5,
        "ineligible_candidate_count": 6,
        "static_tail_fixture_count_per_host": 75,
        "portable_prefix_fixture_count_per_host": 10,
        "portable_fallback_fixture_count_per_host": 69,
        "all_correctness_routes_and_dispositions_pass": True,
        "all_per_fixture_per_host_performance_gates_pass": True,
        "aggregate_rescue_used": False,
        "result_derived_exclusions": False,
        "rebar_accepted_as_input": False,
        "heldout_materialized": False,
        "application_qualification_pass": True,
        "production_authority": False,
    }
    payload_sha256 = canonical_sha(payload)
    evidence_identity = sha256(
        EVIDENCE_DOMAIN
        + bytes.fromhex(CONTRACT_SHA256)
        + bytes.fromhex(source_sha256)
        + bytes.fromhex(expected_binding_sha256)
        + bytes.fromhex(payload_sha256)
    )
    return {
        "schema": ANALYSIS_SCHEMA,
        "payload_sha256": payload_sha256,
        "application_evidence_identity": evidence_identity,
        "payload": payload,
    }


def main() -> None:
    require(
        len(sys.argv) == 7,
        "usage: analyze_qualification_results.py REPO RIPGREP_ROOT "
        "FIXTURE_ROOT BINDING EXPECTED_BINDING_SHA256 RESULT_ROOT",
    )
    result = analyze(
        Path(sys.argv[1]).resolve(strict=True),
        Path(sys.argv[2]).resolve(strict=True),
        Path(sys.argv[3]).resolve(strict=True),
        Path(sys.argv[4]).resolve(strict=True),
        sys.argv[5],
        Path(sys.argv[6]).resolve(strict=True),
    )
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (
        OSError,
        UnicodeError,
        ValueError,
        KeyError,
        TypeError,
        subprocess.CalledProcessError,
        json.JSONDecodeError,
        Refusal,
    ) as error:
        print(f"search-tag30-application-analysis: {error}", file=sys.stderr)
        raise SystemExit(1)
