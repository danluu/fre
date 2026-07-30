#!/usr/bin/env python3
"""Authenticate and evaluate the complete sharded Search tag-30 campaign."""

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
import sys
from collections import defaultdict
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from typing import Any, BinaryIO, Iterable, Iterator, Mapping, Sequence


CONTRACT_SCHEMA = "fre.aot.search-tag30-qualification-campaign-contract.v1"
CONTRACT_SHA256 = (
    "0ea6b3aefac2d31e67aae3acdef3b9f65d0b0fa91421a9ec5c3afe5517c9b2fd"
)
HEADER_SCHEMA = "fre.aot.search-tag30-qualification-fragment-header.v1"
CORRECTNESS_SCHEMA = "fre.aot.search-tag30-qualification-correctness-row.v1"
TIMING_SCHEMA = "fre.aot.search-tag30-qualification-timing-row.v1"
TRAILER_SCHEMA = "fre.aot.search-tag30-qualification-fragment-trailer.v1"
UNIVERSAL_DOMAIN = b"FRE-SEARCH-TAG29-TOPOLOGY-PROJECTION\0\x01"
LONG_DOMAIN = b"FRE-SEARCH-TAG30-LONG-INPUT-POLICY-PROJECTION\0\x01"
HOSTS = (
    "local-apple-aarch64-asimd",
    "zstd-eval-c9g-neoverse-v3-aarch64-asimd",
)
KINDS = ("universal", "long-policy")
MODES = ("correctness", "timing")
SHARDS = 16
REPETITIONS = 6
MINIMUM_NS = 400_000_000
CALIBRATION_TARGET_NS = 440_000_000
CALIBRATION_FLOOR_NS = 100_000
MAXIMUM_ITERATIONS = 1 << 30
MAXIMUM_CPU_ONLY_RETRIES = 64
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
EXPECTED_CANDIDATES = 808
EXPECTED_FULL_UNIQUE_LITERALS = 922
MAXIMUM_JSON_LINE = 32 * 1024
MAXIMUM_INPUT_BYTES = 1 << 30

PROJECTIONS = {
    ("universal", "correctness"): {
        "schema": "fre.aot.search-tag30-learned-continuation-projection.v1",
        "domain": UNIVERSAL_DOMAIN,
        "rows": 123_424,
        "sha256": "0326944c2c95dfd10740d2ea0a72c910dd1a03df8c16e3a2180391d069841480",
        "static_rows": 49_248,
        "portable_rows": 74_176,
    },
    ("universal", "timing"): {
        "schema": "fre.aot.search-tag30-learned-continuation-projection.v1",
        "domain": UNIVERSAL_DOMAIN,
        "rows": 3_078,
        "sha256": "a92a59554188a82b6e7c49833dda599aa7d87014ae6815ba9fbe0f5502b31a4c",
    },
    ("long-policy", "correctness"): {
        "schema": "fre.aot.search-tag30-long-input-policy-projection.v1",
        "domain": LONG_DOMAIN,
        "rows": 123_424,
        "sha256": "c912b402244ff9814fe6160f9f5a117d7b253af5ff35ee69a78a6250aae94561",
        "static_rows": 23_328,
        "portable_rows": 100_096,
    },
    ("long-policy", "timing"): {
        "schema": "fre.aot.search-tag30-long-input-policy-projection.v1",
        "domain": LONG_DOMAIN,
        "rows": 1_458,
        "sha256": "b3093f9fed70fd500852742d18994fce80d4a144cb9b9cbaac4ad0e7f84ccffd",
    },
}

HEADER_FIELDS = {
    "schema",
    "contract_schema",
    "contract_sha256",
    "mode",
    "projection_kind",
    "projection_schema",
    "projection_rows",
    "projection_sha256",
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
    "maximum_cpu_only_retries_per_variant",
    "runner_source_sha256",
    "runner_binary_sha256",
    "runner_identity_sha256",
    "compiler_identity",
    "platform_manifest_identity",
    "build_receipt_sha256",
    "object_candidate_manifest_sha256",
    "backend_tag",
    "backend_name",
    "family_selector",
    "minimum_window_bytes",
    "portable_prefix_candidate_starts",
    "timing_repetitions",
    "minimum_elapsed_ns_each_variant",
    "rebar_accepted_as_input",
    "result_derived_exclusions",
}
TRAILER_FIELDS = {
    "schema",
    "rows",
    "shard_start",
    "shard_end",
    "records_sha256",
    "complete",
}
CORRECTNESS_FIELDS = {
    "schema",
    "ordinal",
    "row_sha256",
    "literal_sha256",
    "selector_eligible",
    "expected_compiler_disposition",
    "expected_route",
    "expected_static_invoked",
    "scalar_span",
    "portable_span",
    "direct_v17_span",
    "automatic_long_policy_span",
    "mapping",
    "actual_window_start_mod16",
    "worker_logical_cpu",
    "pass",
}
TIMING_FIELDS = {
    "schema",
    "ordinal",
    "row_sha256",
    "literal_sha256",
    "literal_bytes",
    "topology",
    "mutation_class",
    "learned_source_kind",
    "learned_source_relations",
    "literal_phase_class",
    "selector_primary_offset_class",
    "logical_prefix_bytes",
    "window_bytes",
    "outcome",
    "right_guarded",
    "expected_route",
    "candidate_call",
    "mapping",
    "actual_window_start_mod16",
    "logical_cpu",
    "minimum_elapsed_ns_each_variant",
    "calibration",
    "pairs",
    "pass",
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
    "candidate_cpu_before",
    "candidate_cpu_after",
    "portable_cpu_retries",
    "portable_cpu_attempts",
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


class Refusal(RuntimeError):
    """An input changed, a shard is incomplete, or a frozen gate failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def sha256(encoded: bytes) -> str:
    return hashlib.sha256(encoded).hexdigest()


def is_hex(value: Any, length: int = 64) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(byte in "0123456789abcdef" for byte in value)
    )


def is_uint(value: Any) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value < 1 << 64
    )


def exact_keys(value: Any, fields: set[str], context: str) -> Mapping[str, Any]:
    require(
        isinstance(value, dict) and set(value) == fields,
        f"{context}: fields changed",
    )
    return value


def flat_name(value: str) -> bool:
    return (
        value not in {"", ".", ".."}
        and "/" not in value
        and "\\" not in value
        and "\x00" not in value
    )


def open_regular(path: Path, maximum: int = MAXIMUM_INPUT_BYTES) -> tuple[BinaryIO, os.stat_result]:
    require(flat_name(path.name), f"not one flat input name: {path.name!r}")
    parent = path.parent.resolve(strict=True)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_CLOEXEC", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    directory = os.open(parent, directory_flags)
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path.name, flags, dir_fd=directory)
    finally:
        os.close(directory)
    try:
        status = os.fstat(descriptor)
        require(
            stat.S_ISREG(status.st_mode)
            and status.st_nlink == 1
            and 0 < status.st_size <= maximum,
            f"not one bounded unshared regular file: {path}",
        )
        return os.fdopen(descriptor, "rb", closefd=True), status
    except BaseException:
        os.close(descriptor)
        raise


def unchanged(source: BinaryIO, before: os.stat_result, context: str) -> None:
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
        f"{context}: file changed while held",
    )


def read_small_regular(path: Path, maximum: int) -> bytes:
    source, before = open_regular(path, maximum)
    with source:
        encoded = source.read(maximum + 1)
        require(
            len(encoded) == before.st_size,
            f"{path}: short or oversized read",
        )
        unchanged(source, before, str(path))
    return encoded


def authenticate_contract(path: Path) -> Mapping[str, Any]:
    encoded = read_small_regular(path, 128 * 1024)
    require(sha256(encoded) == CONTRACT_SHA256, "campaign contract changed")
    contract = json.loads(encoded)
    require(
        isinstance(contract, dict)
        and contract.get("schema") == CONTRACT_SCHEMA
        and contract.get("result_blind") is True
        and contract.get("rebar_inputs") == []
        and contract.get("result_derived_selection") is False
        and contract.get("result_derived_exclusions") is False,
        "campaign contract authority changed",
    )
    return contract


def shard_bounds(total: int, shard: int) -> tuple[int, int]:
    quotient, remainder = divmod(total, SHARDS)
    start = shard * quotient + min(shard, remainder)
    return start, start + quotient + int(shard < remainder)


@dataclass(frozen=True)
class ProjectionExpectation:
    row_sha256: str
    literal_sha256: str
    selector_eligible: bool
    compiler_disposition: str
    expected_route: str
    expected_static_invoked: bool
    expected_span: list[int] | None
    right_guarded: bool
    physical_mod16: int


def projection_expectation(row: Mapping[str, Any]) -> ProjectionExpectation:
    start = row.get("expected_match_start")
    end = row.get("expected_match_end")
    expected_span = None if start is None else [start, end]
    require(
        (start is None and end is None)
        or (is_uint(start) and is_uint(end) and start <= end),
        "projection expected span changed",
    )
    return ProjectionExpectation(
        row_sha256=row["row_sha256"],
        literal_sha256=row["literal_sha256"],
        selector_eligible=row["selector_eligible"],
        compiler_disposition=row["expected_compiler_disposition"],
        expected_route=row["expected_route"],
        expected_static_invoked=row["expected_static_invoked"],
        expected_span=expected_span,
        right_guarded=row["right_guarded"],
        physical_mod16=row["expected_physical_window_start_mod16"],
    )


def load_projection(
    path: Path, kind: str, mode: str
) -> tuple[list[ProjectionExpectation], list[Mapping[str, Any]]]:
    spec = PROJECTIONS[(kind, mode)]
    source, before = open_regular(path)
    digest = hashlib.sha256(spec["domain"])
    expectations: list[ProjectionExpectation] = []
    timing_rows: list[Mapping[str, Any]] = []
    with source:
        for ordinal, line in enumerate(source):
            require(
                1 < len(line) <= MAXIMUM_JSON_LINE + 1
                and line.endswith(b"\n"),
                f"{kind} {mode} projection row {ordinal}: framing changed",
            )
            digest.update(len(line).to_bytes(8, "little"))
            digest.update(line)
            row = json.loads(line)
            require(
                canonical_bytes(row) + b"\n" == line
                and row.get("schema") == spec["schema"]
                and is_hex(row.get("row_sha256"))
                and is_hex(row.get("literal_sha256")),
                f"{kind} {mode} projection row {ordinal}: identity changed",
            )
            expectations.append(projection_expectation(row))
            if mode == "timing":
                timing_rows.append(row)
        unchanged(source, before, f"{kind} {mode} projection")
    require(
        len(expectations) == spec["rows"]
        and digest.hexdigest() == spec["sha256"],
        f"{kind} {mode} projection digest changed",
    )
    require(
        len({row.row_sha256 for row in expectations}) == len(expectations),
        f"{kind} {mode} projection row identities are not injective",
    )
    return expectations, timing_rows


def fragment_name(host: str, mode: str, kind: str, shard: int) -> str:
    return f"{host}--{mode}--{kind}--shard-{shard:02}.jsonl"


def expected_fragment_names() -> set[str]:
    return {
        fragment_name(host, mode, kind, shard)
        for host in HOSTS
        for mode in MODES
        for kind in KINDS
        for shard in range(SHARDS)
    }


@dataclass
class TimingCell:
    row: Mapping[str, Any]
    record: Mapping[str, Any]
    ratio: Fraction
    strict_wins: int


@dataclass
class FragmentResult:
    header: Mapping[str, Any]
    file_sha256: str
    static_rows: int = 0
    portable_rows: int = 0
    timing_cells: list[TimingCell] | None = None


def host_binding(header: Mapping[str, Any]) -> Mapping[str, Any]:
    return {
        "runner_source_sha256": header["runner_source_sha256"],
        "runner_binary_sha256": header["runner_binary_sha256"],
        "runner_identity_sha256": header["runner_identity_sha256"],
        "object_candidate_manifest_sha256": header[
            "object_candidate_manifest_sha256"
        ],
        "compiler_identity": header["compiler_identity"],
        "platform_manifest_identity": header["platform_manifest_identity"],
        "build_receipt_sha256": header["build_receipt_sha256"],
        "backend_tag": header["backend_tag"],
        "backend_name": header["backend_name"],
        "family_selector": header["family_selector"],
        "minimum_window_bytes": header["minimum_window_bytes"],
        "portable_prefix_candidate_starts": header[
            "portable_prefix_candidate_starts"
        ],
    }


def parse_header(
    value: Any,
    host: str,
    mode: str,
    kind: str,
    shard: int,
    start: int,
    end: int,
) -> Mapping[str, Any]:
    header = exact_keys(value, HEADER_FIELDS, "fragment header")
    spec = PROJECTIONS[(kind, mode)]
    cpu_residence_valid = (
        (
            host == HOSTS[0]
            and header["cpu_residence_method"]
            == (
                "macos-user-interactive-qos-affinity-hint-super-class-"
                "cpu-only-retry"
            )
            and header["affinity_request_status"] in {0, 46}
            and header["qos_class"] == 0x21
            and header["qos_request_status"] == 0
            and header["accepted_cpu_class"] == "Super"
            and header["accepted_cpu_ids"] == list(MACOS_SUPER_CPUS)
            and header["macos_performance_levels"]
            == MACOS_PERFORMANCE_LEVEL_RECEIPT
            and header["logical_cpu"] in MACOS_SUPER_CPUS
        )
        or (
            host == HOSTS[1]
            and header["cpu_residence_method"]
            == "linux-sched-setaffinity-plus-samples"
            and header["affinity_request_status"] == 0
            and header["qos_class"] is None
            and header["qos_request_status"] is None
            and header["accepted_cpu_class"] == "exact-requested"
            and header["accepted_cpu_ids"] == [header["logical_cpu"]]
            and header["macos_performance_levels"] is None
        )
    )
    require(
        header["schema"] == HEADER_SCHEMA
        and header["contract_schema"] == CONTRACT_SCHEMA
        and header["contract_sha256"] == CONTRACT_SHA256
        and header["mode"] == mode
        and header["projection_kind"] == kind
        and header["projection_schema"] == spec["schema"]
        and header["projection_rows"] == spec["rows"]
        and header["projection_sha256"] == spec["sha256"]
        and header["shard_id"] == shard
        and header["shard_start"] == start
        and header["shard_end"] == end
        and header["host_id"] == host
        and is_uint(header["logical_cpu"])
        and cpu_residence_valid
        and header["maximum_cpu_only_retries_per_variant"]
        == (MAXIMUM_CPU_ONLY_RETRIES if host == HOSTS[0] else 0)
        and is_hex(header["runner_source_sha256"])
        and is_hex(header["runner_binary_sha256"])
        and is_hex(header["runner_identity_sha256"])
        and is_hex(header["compiler_identity"])
        and is_hex(header["platform_manifest_identity"])
        and is_hex(header["build_receipt_sha256"])
        and is_hex(header["object_candidate_manifest_sha256"])
        and header["backend_tag"] == 30
        and header["backend_name"] == "AsimdV17"
        and header["family_selector"] == 13
        and header["minimum_window_bytes"] == 65_536
        and header["portable_prefix_candidate_starts"] == 256
        and (
            (
                mode == "correctness"
                and header["timing_repetitions"] is None
                and header["minimum_elapsed_ns_each_variant"] is None
            )
            or (
                mode == "timing"
                and header["timing_repetitions"] == REPETITIONS
                and header["minimum_elapsed_ns_each_variant"] == MINIMUM_NS
            )
        )
        and header["rebar_accepted_as_input"] is False
        and header["result_derived_exclusions"] is False,
        f"{host} {mode} {kind} shard {shard}: header changed",
    )
    return header


def validate_mapping(
    mapping: Any, expected: ProjectionExpectation, context: str
) -> None:
    require(isinstance(mapping, dict), f"{context}: mapping is not an object")
    expected_kind = "right-guarded" if expected.right_guarded else "right-padded"
    require(
        mapping.get("kind") == expected_kind
        and mapping.get("guard_page") is expected.right_guarded
        and (
            not expected.right_guarded
            or (
                mapping.get("guard_protection") == "none"
                and is_uint(mapping.get("page_bytes"))
                and mapping["page_bytes"] >= 4_096
            )
        ),
        f"{context}: guarded/padded mapping proof changed",
    )


def parse_correctness_record(
    value: Any,
    expected: ProjectionExpectation,
    ordinal: int,
    kind: str,
    cpu: int,
) -> tuple[int, int]:
    record = exact_keys(value, CORRECTNESS_FIELDS, f"correctness row {ordinal}")
    eligible_span = expected.expected_span if expected.selector_eligible else None
    automatic_span = (
        eligible_span
        if kind == "long-policy" and expected.selector_eligible
        else None
    )
    require(
        record["schema"] == CORRECTNESS_SCHEMA
        and record["ordinal"] == ordinal
        and record["row_sha256"] == expected.row_sha256
        and record["literal_sha256"] == expected.literal_sha256
        and record["selector_eligible"] is expected.selector_eligible
        and record["expected_compiler_disposition"]
        == expected.compiler_disposition
        and record["expected_route"] == expected.expected_route
        and record["expected_static_invoked"] is expected.expected_static_invoked
        and record["scalar_span"] == expected.expected_span
        and record["portable_span"] == expected.expected_span
        and record["direct_v17_span"] == eligible_span
        and record["automatic_long_policy_span"] == automatic_span
        and record["actual_window_start_mod16"] == expected.physical_mod16
        and record["worker_logical_cpu"] == cpu
        and record["pass"] is True,
        f"correctness row {ordinal}: semantic receipt changed",
    )
    validate_mapping(record["mapping"], expected, f"correctness row {ordinal}")
    return (
        (1, 0) if expected.expected_static_invoked else (0, 1)
    )


def median_ratio(pairs: Sequence[Mapping[str, Any]]) -> Fraction:
    ratios = sorted(
        Fraction(pair["candidate_elapsed_ns"], pair["portable_elapsed_ns"])
        for pair in pairs
    )
    return (ratios[2] + ratios[3]) / 2


def validate_cpu_attempts(
    value: Any,
    retries: Any,
    host: str,
    requested_cpu: int,
    accepted_before: Any,
    accepted_after: Any,
    context: str,
) -> None:
    maximum_retries = MAXIMUM_CPU_ONLY_RETRIES if host == HOSTS[0] else 0
    require(
        isinstance(value, list)
        and 1 <= len(value) <= maximum_retries + 1
        and retries == len(value) - 1,
        f"{context}: CPU retry extent changed",
    )
    for ordinal, raw_attempt in enumerate(value):
        attempt = exact_keys(raw_attempt, CPU_ATTEMPT_FIELDS, context)
        before = attempt["cpu_before"]
        after = attempt["cpu_after"]
        require(
            attempt["attempt"] == ordinal
            and is_uint(before)
            and is_uint(after),
            f"{context}: CPU attempt framing changed",
        )
        if host == HOSTS[0]:
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
            attempt["accepted"] is accepted
            and accepted is (ordinal == len(value) - 1),
            f"{context}: retry was not decided solely by CPU class",
        )
    last = value[-1]
    require(
        last["cpu_before"] == accepted_before
        and last["cpu_after"] == accepted_after,
        f"{context}: accepted endpoints differ from the attempt receipt",
    )


def scaled_iterations(pilot: Mapping[str, Any]) -> int:
    numerator = (
        CALIBRATION_TARGET_NS * pilot["iterations"]
        + pilot["elapsed_ns"]
        - 1
    )
    return min(MAXIMUM_ITERATIONS, max(1, numerator // pilot["elapsed_ns"]))


def validate_calibration_pilots(
    value: Any,
    host: str,
    requested_cpu: int,
    context: str,
) -> Sequence[Mapping[str, Any]]:
    require(
        isinstance(value, list) and value,
        f"{context}: calibration pilot set is empty",
    )
    pilots: list[Mapping[str, Any]] = []
    expected_iterations = 1
    for ordinal, raw_pilot in enumerate(value):
        pilot = exact_keys(
            raw_pilot, CALIBRATION_PILOT_FIELDS, f"{context} pilot"
        )
        require(
            pilot["iterations"] == expected_iterations
            and is_uint(pilot["elapsed_ns"])
            and pilot["elapsed_ns"] > 0
            and is_uint(pilot["checksum"])
            and is_uint(pilot["cpu_before"])
            and is_uint(pilot["cpu_after"]),
            f"{context} pilot {ordinal}: calibration receipt changed",
        )
        validate_cpu_attempts(
            pilot["cpu_attempts"],
            pilot["cpu_retries"],
            host,
            requested_cpu,
            pilot["cpu_before"],
            pilot["cpu_after"],
            f"{context} pilot {ordinal}",
        )
        pilots.append(pilot)
        if ordinal + 1 < len(value):
            require(
                pilot["elapsed_ns"] < CALIBRATION_FLOOR_NS
                and pilot["iterations"] < MAXIMUM_ITERATIONS,
                f"{context} pilot {ordinal}: unnecessary pilot followed",
            )
            expected_iterations = min(
                MAXIMUM_ITERATIONS, pilot["iterations"] * 4
            )
    require(
        pilots[-1]["elapsed_ns"] >= CALIBRATION_FLOOR_NS
        or pilots[-1]["iterations"] == MAXIMUM_ITERATIONS,
        f"{context}: calibration stopped before the frozen floor",
    )
    return pilots


def validate_calibration(
    value: Any, host: str, requested_cpu: int, context: str
) -> int:
    calibration = exact_keys(value, CALIBRATION_FIELDS, context)
    require(
        calibration["target_elapsed_ns"] == CALIBRATION_TARGET_NS
        and calibration["floor_elapsed_ns"] == CALIBRATION_FLOOR_NS
        and calibration["maximum_iterations"] == MAXIMUM_ITERATIONS,
        f"{context}: calibration constants changed",
    )
    portable = validate_calibration_pilots(
        calibration["portable_pilots"],
        host,
        requested_cpu,
        f"{context} portable",
    )
    candidate = validate_calibration_pilots(
        calibration["candidate_pilots"],
        host,
        requested_cpu,
        f"{context} candidate",
    )
    selected = max(
        scaled_iterations(portable[-1]), scaled_iterations(candidate[-1])
    )
    require(
        calibration["selected_iterations"] == selected,
        f"{context}: selected iteration count changed",
    )
    return selected


def parse_timing_record(
    value: Any,
    expected: ProjectionExpectation,
    row: Mapping[str, Any],
    ordinal: int,
    kind: str,
    cpu: int,
    host: str = HOSTS[1],
) -> TimingCell:
    record = exact_keys(value, TIMING_FIELDS, f"timing row {ordinal}")
    dimension_fields = (
        "literal_sha256",
        "literal_bytes",
        "topology",
        "mutation_class",
        "learned_source_kind",
        "learned_source_relations",
        "literal_phase_class",
        "selector_primary_offset_class",
        "logical_prefix_bytes",
        "window_bytes",
        "outcome",
        "right_guarded",
        "expected_route",
    )
    require(
        record["schema"] == TIMING_SCHEMA
        and record["ordinal"] == ordinal
        and record["row_sha256"] == expected.row_sha256
        and all(record[field] == row[field] for field in dimension_fields)
        and record["candidate_call"]
        == (
            "direct-v17"
            if kind == "universal"
            else "automatic-portable-prefix-static-tail"
        )
        and record["actual_window_start_mod16"] == expected.physical_mod16
        and record["logical_cpu"] == cpu
        and record["minimum_elapsed_ns_each_variant"] == MINIMUM_NS
        and record["pass"] is True
        and record["rebar_accepted_as_input"] is False,
        f"timing row {ordinal}: identity or dimensions changed",
    )
    validate_mapping(record["mapping"], expected, f"timing row {ordinal}")
    selected_iterations = validate_calibration(
        record["calibration"],
        host,
        cpu,
        f"timing row {ordinal} calibration",
    )
    pairs = record["pairs"]
    require(
        isinstance(pairs, list) and len(pairs) == REPETITIONS,
        f"timing row {ordinal}: pair count changed",
    )
    strict_wins = 0
    calibrated_iterations: set[int] = set()
    repeated_checksums: set[int] = set()
    for repetition, raw_pair in enumerate(pairs):
        pair = exact_keys(raw_pair, PAIR_FIELDS, f"timing row {ordinal} pair")
        expected_order = (
            "portable-first" if repetition % 2 == 0 else "candidate-first"
        )
        require(
            pair["repetition"] == repetition
            and pair["order"] == expected_order
            and is_uint(pair["iterations"])
            and pair["iterations"] > 0
            and is_uint(pair["portable_elapsed_ns"])
            and is_uint(pair["candidate_elapsed_ns"])
            and pair["portable_elapsed_ns"] >= MINIMUM_NS
            and pair["candidate_elapsed_ns"] >= MINIMUM_NS
            and is_uint(pair["portable_checksum"])
            and pair["portable_checksum"] == pair["candidate_checksum"]
            and all(
                is_uint(pair[field])
                for field in (
                    "portable_cpu_before",
                    "portable_cpu_after",
                    "candidate_cpu_before",
                    "candidate_cpu_after",
                )
            ),
            f"timing row {ordinal} pair {repetition}: receipt changed",
        )
        validate_cpu_attempts(
            pair["portable_cpu_attempts"],
            pair["portable_cpu_retries"],
            host,
            cpu,
            pair["portable_cpu_before"],
            pair["portable_cpu_after"],
            f"timing row {ordinal} pair {repetition} portable",
        )
        validate_cpu_attempts(
            pair["candidate_cpu_attempts"],
            pair["candidate_cpu_retries"],
            host,
            cpu,
            pair["candidate_cpu_before"],
            pair["candidate_cpu_after"],
            f"timing row {ordinal} pair {repetition} candidate",
        )
        calibrated_iterations.add(pair["iterations"])
        repeated_checksums.add(pair["portable_checksum"])
        strict_wins += int(
            pair["candidate_elapsed_ns"] < pair["portable_elapsed_ns"]
        )
    require(
        calibrated_iterations == {selected_iterations}
        and len(repeated_checksums) == 1,
        f"timing row {ordinal}: calibrated iterations or checksum varied across pairs",
    )
    return TimingCell(
        row=row,
        record=record,
        ratio=median_ratio(pairs),
        strict_wins=strict_wins,
    )


def parse_fragment(
    path: Path,
    host: str,
    mode: str,
    kind: str,
    shard: int,
    expectations: Sequence[ProjectionExpectation],
    timing_rows: Sequence[Mapping[str, Any]],
) -> FragmentResult:
    spec = PROJECTIONS[(kind, mode)]
    start, end = shard_bounds(spec["rows"], shard)
    source, before = open_regular(path)
    if before.st_mode & 0o222 != 0:
        source.close()
        raise Refusal(f"{path.name}: completed fragment is still writable")
    whole_digest = hashlib.sha256()
    record_digest = hashlib.sha256()
    static_rows = 0
    portable_rows = 0
    cells: list[TimingCell] = []
    with source:
        header_line = source.readline(MAXIMUM_JSON_LINE + 2)
        whole_digest.update(header_line)
        require(
            header_line.endswith(b"\n")
            and len(header_line) <= MAXIMUM_JSON_LINE + 1,
            f"{path.name}: header framing changed",
        )
        header_value = json.loads(header_line)
        require(
            canonical_bytes(header_value) + b"\n" == header_line,
            f"{path.name}: header is not canonical",
        )
        header = parse_header(
            header_value, host, mode, kind, shard, start, end
        )
        cpu = header["logical_cpu"]
        for ordinal in range(start, end):
            line = source.readline(MAXIMUM_JSON_LINE + 2)
            whole_digest.update(line)
            require(
                line.endswith(b"\n")
                and 1 < len(line) <= MAXIMUM_JSON_LINE + 1,
                f"{path.name} row {ordinal}: framing changed",
            )
            record_digest.update(len(line).to_bytes(8, "little"))
            record_digest.update(line)
            value = json.loads(line)
            require(
                canonical_bytes(value) + b"\n" == line,
                f"{path.name} row {ordinal}: record is not canonical",
            )
            if mode == "correctness":
                static, portable = parse_correctness_record(
                    value, expectations[ordinal], ordinal, kind, cpu
                )
                static_rows += static
                portable_rows += portable
            else:
                cells.append(
                    parse_timing_record(
                        value,
                        expectations[ordinal],
                        timing_rows[ordinal],
                        ordinal,
                        kind,
                        cpu,
                        host,
                    )
                )
        trailer_line = source.readline(MAXIMUM_JSON_LINE + 2)
        whole_digest.update(trailer_line)
        require(
            trailer_line.endswith(b"\n")
            and len(trailer_line) <= MAXIMUM_JSON_LINE + 1,
            f"{path.name}: trailer framing changed",
        )
        trailer_value = json.loads(trailer_line)
        require(
            canonical_bytes(trailer_value) + b"\n" == trailer_line,
            f"{path.name}: trailer is not canonical",
        )
        trailer = exact_keys(trailer_value, TRAILER_FIELDS, "fragment trailer")
        require(
            trailer["schema"] == TRAILER_SCHEMA
            and trailer["rows"] == end - start
            and trailer["shard_start"] == start
            and trailer["shard_end"] == end
            and trailer["records_sha256"] == record_digest.hexdigest()
            and trailer["complete"] is True
            and source.read(1) == b"",
            f"{path.name}: trailer or EOF changed",
        )
        unchanged(source, before, path.name)
    return FragmentResult(
        header=header,
        file_sha256=whole_digest.hexdigest(),
        static_rows=static_rows,
        portable_rows=portable_rows,
        timing_cells=cells if mode == "timing" else None,
    )


def geomean(ratios: Iterable[Fraction]) -> float:
    values = list(ratios)
    require(values, "geometric mean group is empty")
    logarithm = math.fsum(
        math.log(value.numerator) - math.log(value.denominator)
        for value in values
    ) / len(values)
    return math.exp(logarithm)


def geomean_strictly_below(
    ratios: Iterable[Fraction], limit: Fraction
) -> bool:
    values = list(ratios)
    require(values, "geometric mean group is empty")
    numerators = math.prod(value.numerator for value in values)
    denominators = math.prod(value.denominator for value in values)
    return (
        numerators * pow(limit.denominator, len(values))
        < denominators * pow(limit.numerator, len(values))
    )


def ratio_receipt(value: Fraction) -> Mapping[str, Any]:
    return {
        "numerator": value.numerator,
        "denominator": value.denominator,
        "decimal": float(value),
    }


def evaluate_long_host(
    host: str, cells: Sequence[TimingCell]
) -> Mapping[str, Any]:
    require(len(cells) == 1_458, f"{host}: long cell union changed")
    cell_limit = Fraction(21, 20)
    strict_minimum = Fraction(4, 5)
    bad_cells = [
        cell.row["row_sha256"] for cell in cells if cell.ratio > cell_limit
    ]
    strict_wins = sum(cell.strict_wins for cell in cells)
    strict_pairs = len(cells) * REPETITIONS
    strict_fraction = Fraction(strict_wins, strict_pairs)
    groups: dict[tuple[str, Any], list[Fraction]] = defaultdict(list)
    dimensions = (
        ("literal_bytes", "width"),
        ("topology", "topology"),
        ("window_bytes", "window"),
        ("outcome", "outcome"),
        ("learned_source_kind", "learned_source_kind"),
    )
    for cell in cells:
        for field, label in dimensions:
            groups[(label, cell.row[field])].append(cell.ratio)
    aggregate = geomean(cell.ratio for cell in cells)
    aggregate_pass = geomean_strictly_below(
        (cell.ratio for cell in cells), Fraction(4, 5)
    )
    group_receipts = {}
    failing_groups = []
    for (dimension, value), ratios in sorted(
        groups.items(), key=lambda item: (item[0][0], str(item[0][1]))
    ):
        mean = geomean(ratios)
        group_pass = geomean_strictly_below(ratios, Fraction(4, 5))
        key = f"{dimension}={value}"
        group_receipts[key] = {"cells": len(ratios), "geomean": mean}
        if not group_pass:
            failing_groups.append(key)
    require(not bad_cells, f"{host}: individual long-policy cell exceeded 1.05")
    require(
        strict_fraction >= strict_minimum,
        f"{host}: complete-projection strict paired-win fraction is below 0.80",
    )
    require(
        aggregate_pass,
        f"{host}: long-policy aggregate geomean is not below 0.80",
    )
    require(
        not failing_groups,
        f"{host}: long-policy stratum geomean is not below 0.80",
    )
    return {
        "cells": len(cells),
        "aggregate_cell_geomean": aggregate,
        "maximum_cell_ratio": ratio_receipt(max(cell.ratio for cell in cells)),
        "strict_pair_wins": strict_wins,
        "strict_pairs": strict_pairs,
        "strict_pair_win_fraction": ratio_receipt(strict_fraction),
        "strata": group_receipts,
        "pass": True,
    }


def universal_group_keys(
    row: Mapping[str, Any],
) -> Iterator[tuple[str, str]]:
    yield (
        "width_topology",
        f"{row['literal_bytes']}:{row['topology']}",
    )
    yield ("width", str(row["literal_bytes"]))
    yield ("topology", row["topology"])
    yield ("learned_source_kind", row["learned_source_kind"])
    for relation in row["learned_source_relations"]:
        yield ("learned_source_relation", relation)


def evaluate_universal_host(
    host: str, cells: Sequence[TimingCell]
) -> Mapping[str, Any]:
    require(len(cells) == 3_078, f"{host}: universal cell union changed")
    strict_limit = Fraction(4, 5)
    failing = [
        cell.row["row_sha256"]
        for cell in cells
        if cell.ratio >= strict_limit
    ]
    groups: dict[tuple[str, str], list[TimingCell]] = defaultdict(list)
    for cell in cells:
        for key in universal_group_keys(cell.row):
            groups[key].append(cell)
    strata = {}
    for (dimension, value), group in sorted(groups.items()):
        group_failing = [
            cell.row["row_sha256"]
            for cell in group
            if cell.ratio >= strict_limit
        ]
        require(
            not group_failing,
            f"{host}: universal {dimension}={value} contains a failing cell",
        )
        strata[f"{dimension}={value}"] = {
            "cells": len(group),
            "maximum_cell_ratio": ratio_receipt(
                max(cell.ratio for cell in group)
            ),
            "pass_as_conjunction_of_cells": True,
            "authorizes_independently": False,
        }
    require(
        not failing,
        f"{host}: universal cell median is not strictly below 0.80",
    )
    return {
        "cells": len(cells),
        "maximum_cell_ratio": ratio_receipt(max(cell.ratio for cell in cells)),
        "failing_cells": [],
        "cell_gate": "strictly-less-than-4/5",
        "strata_completeness": strata,
        "aggregate_rescue_permitted": False,
        "pass": True,
        "production_policy_authority": False,
    }


def evaluate_universal_combined(
    cells_by_host: Mapping[str, Sequence[TimingCell]],
) -> Mapping[str, Any]:
    require(
        set(cells_by_host) == set(HOSTS)
        and all(len(cells_by_host[host]) == 3_078 for host in HOSTS),
        "universal combined-host union changed",
    )
    cells = [
        cell for host in HOSTS for cell in cells_by_host[host]
    ]
    require(
        all(cell.ratio < Fraction(4, 5) for cell in cells),
        "universal combined-host conjunction failed",
    )
    return {
        "hosts": list(HOSTS),
        "cells": len(cells),
        "maximum_cell_ratio": ratio_receipt(max(cell.ratio for cell in cells)),
        "pass_as_conjunction_of_host_cells": True,
        "aggregate_rescue_permitted": False,
        "production_policy_authority": False,
    }


def analyze(
    contract_path: Path,
    universal_full_path: Path,
    long_full_path: Path,
    universal_timed_path: Path,
    long_timed_path: Path,
    fragment_directory: Path,
    output_path: Path,
) -> None:
    authenticate_contract(contract_path)
    analyzer_source_sha256 = sha256(
        read_small_regular(Path(__file__).resolve(), 1 << 20)
    )
    projection_paths = {
        ("universal", "correctness"): universal_full_path,
        ("long-policy", "correctness"): long_full_path,
        ("universal", "timing"): universal_timed_path,
        ("long-policy", "timing"): long_timed_path,
    }
    loaded = {
        key: load_projection(path, *key)
        for key, path in projection_paths.items()
    }
    directory = fragment_directory.resolve(strict=True)
    require(directory.is_dir(), "fragment directory is not a directory")
    entries = list(os.scandir(directory))
    actual_names = {entry.name for entry in entries}
    require(
        actual_names == expected_fragment_names()
        and all(entry.is_file(follow_symlinks=False) for entry in entries),
        "fragment directory is not the exact frozen shard set",
    )
    fragment_receipts: dict[str, str] = {}
    header_bindings: dict[str, Mapping[str, Any]] = {}
    cpu_sets: dict[tuple[str, str, str], set[int]] = defaultdict(set)
    correctness_output: dict[str, Any] = {}

    # Performance bytes are deliberately not opened until every correctness
    # fragment on both hosts and both projections has authenticated.
    for host in HOSTS:
        correctness_output[host] = {}
        for kind in KINDS:
            expectations, _ = loaded[(kind, "correctness")]
            static_rows = 0
            portable_rows = 0
            literal_set = {row.literal_sha256 for row in expectations}
            for shard in range(SHARDS):
                name = fragment_name(host, "correctness", kind, shard)
                result = parse_fragment(
                    directory / name,
                    host,
                    "correctness",
                    kind,
                    shard,
                    expectations,
                    (),
                )
                fragment_receipts[name] = result.file_sha256
                static_rows += result.static_rows
                portable_rows += result.portable_rows
                cpu_sets[(host, "correctness", kind)].add(
                    result.header["logical_cpu"]
                )
                binding = host_binding(result.header)
                prior = header_bindings.setdefault(host, binding)
                require(prior == binding, f"{host}: runner binding varied")
            spec = PROJECTIONS[(kind, "correctness")]
            require(
                static_rows == spec["static_rows"]
                and portable_rows == spec["portable_rows"]
                and len(literal_set) == EXPECTED_FULL_UNIQUE_LITERALS,
                f"{host} {kind}: correctness union changed",
            )
            correctness_output[host][kind] = {
                "rows": len(expectations),
                "static_rows": static_rows,
                "portable_rows": portable_rows,
                "unique_literals": len(literal_set),
                "pass": True,
            }

    timing_output: dict[str, Any] = {}
    universal_cells_by_host: dict[str, Sequence[TimingCell]] = {}
    common_binding_fields = (
        "runner_source_sha256",
        "runner_identity_sha256",
        "object_candidate_manifest_sha256",
        "compiler_identity",
        "backend_tag",
        "backend_name",
        "family_selector",
        "minimum_window_bytes",
        "portable_prefix_candidate_starts",
    )
    for field in common_binding_fields:
        require(
            len({binding[field] for binding in header_bindings.values()}) == 1,
            f"common cross-host runner binding differs: {field}",
        )
    for host in HOSTS:
        timing_output[host] = {}
    # Both hosts' universal prerequisite is consumed before either host's
    # long-policy authority input is opened.
    for kind in KINDS:
        for host in HOSTS:
            expectations, timing_rows = loaded[(kind, "timing")]
            cells: list[TimingCell] = []
            for shard in range(SHARDS):
                name = fragment_name(host, "timing", kind, shard)
                result = parse_fragment(
                    directory / name,
                    host,
                    "timing",
                    kind,
                    shard,
                    expectations,
                    timing_rows,
                )
                fragment_receipts[name] = result.file_sha256
                require(
                    result.timing_cells is not None,
                    f"{name}: timing cells absent",
                )
                cells.extend(result.timing_cells)
                cpu_sets[(host, "timing", kind)].add(
                    result.header["logical_cpu"]
                )
                binding = host_binding(result.header)
                require(
                    header_bindings[host] == binding,
                    f"{host}: timing runner binding differs from correctness",
                )
            require(
                len(cells) == len(expectations)
                and [cell.record["ordinal"] for cell in cells]
                == list(range(len(expectations)))
                and len({cell.row["literal_sha256"] for cell in cells})
                == EXPECTED_CANDIDATES,
                f"{host} {kind}: exact timing union changed",
            )
            timing_output[host][kind] = (
                evaluate_universal_host(host, cells)
                if kind == "universal"
                else evaluate_long_host(host, cells)
            )
            if kind == "universal":
                universal_cells_by_host[host] = cells

    for key, cpus in cpu_sets.items():
        host, _, _ = key
        if host == HOSTS[0]:
            require(
                cpus == set(MACOS_SUPER_CPUS),
                f"{key}: macOS did not use the six exact Super worker labels",
            )
        else:
            require(
                8 <= len(cpus) <= 16,
                f"{key}: Linux did not use 8 through 16 exact CPUs",
            )

    output = {
        "schema": "fre.aot.search-tag30-qualification-analysis.v1",
        "contract_sha256": CONTRACT_SHA256,
        "analyzer_source_sha256": analyzer_source_sha256,
        "runner_source_sha256": header_bindings[HOSTS[0]][
            "runner_source_sha256"
        ],
        "host_bindings": header_bindings,
        "correctness": correctness_output,
        "timing": timing_output,
        "universal_combined_host_gate": evaluate_universal_combined(
            universal_cells_by_host
        ),
        "fragment_count": len(fragment_receipts),
        "fragment_sha256s": dict(sorted(fragment_receipts.items())),
        "exact_shard_union": True,
        "overlaps": 0,
        "omissions": 0,
        "long_policy_gate_scope": (
            "each exact complete 1458-cell host projection independently"
        ),
        "qualification_pass": True,
        "production_authority_granted": False,
        "rebar_accepted_as_input": False,
        "result_derived_exclusions": False,
    }
    encoded = json.dumps(output, sort_keys=True, indent=2).encode() + b"\n"
    descriptor = os.open(
        output_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o444,
    )
    with os.fdopen(descriptor, "wb", closefd=True) as destination:
        destination.write(encoded)
        destination.flush()
        os.fsync(destination.fileno())
    print(json.dumps(output, sort_keys=True))


def main(argv: Sequence[str]) -> None:
    require(
        len(argv) == 7,
        "usage: analyze_fragments.py CONTRACT UNIVERSAL_FULL LONG_FULL "
        "UNIVERSAL_TIMED LONG_TIMED FRAGMENT_DIRECTORY NEW_OUTPUT",
    )
    analyze(*(Path(argument) for argument in argv))


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, TypeError, KeyError, IndexError, Refusal) as error:
        print(f"search-tag30-qualification-analyzer: {error}", file=sys.stderr)
        raise SystemExit(1)
