#!/usr/bin/env python3
"""Fail-closed analyzer for paired tag-29 topology result bundles."""

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
from typing import Any, BinaryIO, Iterable


MANIFEST_SCHEMA = "fre.aot.search-tag29-paired-result-manifest.v1"
HEADER_SCHEMA = "fre.aot.search-tag29-host-result-header.v1"
CASE_SCHEMA = "fre.aot.search-tag29-host-case-result.v1"
TRAILER_SCHEMA = "fre.aot.search-tag29-host-result-trailer.v1"
CAMPAIGN_DOMAIN = b"FRE-SEARCH-TAG29-PAIRED-RESULT-CAMPAIGN\0\x01"
PROJECTION_DOMAIN = b"FRE-SEARCH-TAG29-TOPOLOGY-PROJECTION\0\x01"
FREEZE_SHA256 = (
    "9f6ba2af9ff7e2296f65dc20b4386d68ddd5ea41837814a1b6b4c3ee2faf4856"
)
GENERATOR_SHA256 = (
    "35aacbca100dde74a2ead493ceab1197c813d37c17d5f4a9d3e62938c3a2b610"
)
SELECTOR_SHA256 = (
    "38ca5ebc1b239b541afcf9eeb679bf8b156c8690e7422a96f69a9457a155daf0"
)
TIMED_PROJECTION_DIGEST = (
    "72d85a032a90e4347be2d537c2ff11bac15016787c055332843f143da72e487f"
)
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
AUTHORITY_FIELDS = {
    "campaign_name",
    "freeze_sha256",
    "generator_sha256",
    "selector_contract_sha256",
    "qualification_plan_sha256",
    "qualification_plan_payload_sha256",
    "timed_projection_digest",
    "timed_projection_rows",
    "runner",
    "host_aliases",
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
    "object_manifest_sha256",
    "object_manifest_payload_sha256",
    "backend_tag",
    "backend_version",
    "candidate_policy",
    "llvm",
    "ordinary_candidate_entry",
    "baseline_entry",
}
HOST_MANIFEST_FIELDS = {
    "frozen_name",
    "canonical_name",
    "target_triple",
    "features",
    "host_attestation_sha256",
    "runner_binary_sha256",
    "linked_image_sha256",
    "linked_image_platform_identity_sha256",
    "build_closure_sha256",
    "toolchain_closure_sha256",
    "bundle",
}
BUNDLE_FIELDS = {
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
    "qualification_plan_sha256",
    "case_records",
    "pairs",
    "measurements",
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
    "compile_receipt_sha256",
    "object_sha256",
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
    status = path.lstat()
    require(
        stat.S_ISREG(status.st_mode)
        and not path.is_symlink()
        and 0 < status.st_size <= maximum,
        f"not one bounded regular file: {path}",
    )
    return path.read_bytes()


def file_sha_and_bytes(path: Path) -> tuple[str, int]:
    status = path.lstat()
    require(
        stat.S_ISREG(status.st_mode)
        and not path.is_symlink()
        and 0 < status.st_size <= 1024 * 1024 * 1024,
        f"not one bounded result file: {path}",
    )
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest(), status.st_size


def is_hex(value: Any, length: int = 64) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(byte in "0123456789abcdef" for byte in value)
    )


def is_u64(value: Any) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= (1 << 64) - 1
    )


def canonical_relative(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and not value.startswith("/")
        and "\\" not in value
        and all(part not in {"", ".", ".."} for part in value.split("/"))
    )


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


def validate_plan(qualification_root: Path) -> dict[str, Any]:
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
    plan_bytes = regular_file(plan_path)
    plan = json.loads(plan_bytes)
    return {
        "path": plan_path,
        "sha256": sha256(plan_bytes),
        "payload_sha256": plan["payload_sha256"],
        "payload": plan["payload"],
    }


def load_timed_rows(
    qualification_root: Path, plan: dict[str, Any]
) -> list[dict[str, Any]]:
    receipt = plan["payload"]["timed_projection"]
    path = qualification_root / receipt["path"]
    raw_sha, _ = file_sha_and_bytes(path)
    require(
        raw_sha == receipt["file_sha256"]
        and receipt["rows"] == TIMED_ROWS
        and receipt["projection_digest"] == TIMED_PROJECTION_DIGEST,
        "timed projection receipt changed",
    )
    digest = hashlib.sha256(PROJECTION_DOMAIN)
    rows = []
    with path.open("rb") as source:
        for line_number, line in enumerate(source, 1):
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


def campaign_id(authority: dict[str, Any]) -> str:
    return sha256(CAMPAIGN_DOMAIN + canonical_bytes(authority))


def validate_authority(
    authority: dict[str, Any],
    plan: dict[str, Any],
    analyzer_sha256: str,
) -> None:
    require(
        set(authority) == AUTHORITY_FIELDS
        and authority["campaign_name"] == "search-tag29-topology-v1"
        and authority["freeze_sha256"] == FREEZE_SHA256
        and authority["generator_sha256"] == GENERATOR_SHA256
        and authority["selector_contract_sha256"] == SELECTOR_SHA256
        and authority["qualification_plan_sha256"] == plan["sha256"]
        and authority["qualification_plan_payload_sha256"]
        == plan["payload_sha256"]
        and authority["timed_projection_digest"]
        == TIMED_PROJECTION_DIGEST
        and authority["timed_projection_rows"] == TIMED_ROWS
        and authority["host_aliases"]
        == {
            host["frozen_name"]: host["canonical_name"] for host in HOSTS
        }
        and authority["performance_authority"]
        == {
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
                "object_manifest_sha256",
                "object_manifest_payload_sha256",
            )
        )
        and runner["analyzer_source_sha256"] == analyzer_sha256
        and runner["object_manifest_sha256"]
        == object_receipt["file_sha256"]
        and runner["object_manifest_payload_sha256"]
        == object_receipt["payload_sha256"]
        and runner["backend_tag"] == 29
        and runner["backend_version"] == "SEARCH_V16"
        and runner["candidate_policy"] == 15
        and runner["llvm"] is False
        and runner["ordinary_candidate_entry"]
        == "production-auto-route-portable-prefix-static-tail"
        and runner["baseline_entry"] == "forced-full-portable",
        "runner authority changed",
    )


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


def validate_mapping(
    mapping: dict[str, Any], row: dict[str, Any]
) -> None:
    require(
        isinstance(mapping, dict)
        and set(mapping) == MAPPING_FIELDS
        and all(
            is_u64(mapping[field])
            for field in (
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
        and mapping["checked_pointer_address"]
        == mapping["fixture_pointer_address"] + row["logical_prefix_bytes"]
        and mapping["checked_bytes"] == row["window_bytes"]
        and mapping["actual_window_start_mod16"]
        == row["expected_physical_window_start_mod16"]
        and mapping["checked_pointer_address"] % 16
        == row["expected_physical_window_start_mod16"]
        and mapping["mapping"]
        == ("right-guarded" if row["right_guarded"] else "right-padded")
        and mapping["padding_sentinel"]
        == row["fixture_recipe"]["background_byte"]
        and mapping["padding_verified"] is True
        and mapping["page_size"] >= 4096
        and mapping["page_size"] & (mapping["page_size"] - 1) == 0
        and is_hex(mapping["allocation_receipt_sha256"]),
        "physical mapping receipt changed",
    )
    if row["right_guarded"]:
        require(
            mapping["readable_left_bytes"] == 32
            and mapping["readable_right_bytes"] == 0
            and is_u64(mapping["guard_page_start_address"])
            and mapping["guard_page_start_address"]
            == mapping["checked_pointer_address"] + row["window_bytes"]
            and mapping["guard_page_start_address"] % mapping["page_size"] == 0
            and mapping["guard_protection"] == "PROT_NONE"
            and is_hex(mapping["guard_protection_receipt_sha256"]),
            "guard-page mapping is not exact",
        )
    else:
        require(
            mapping["readable_left_bytes"] == 32
            and mapping["readable_right_bytes"] == 32
            and mapping["guard_page_start_address"] is None
            and mapping["guard_protection"] == "none"
            and mapping["guard_protection_receipt_sha256"] is None,
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
    literal_objects: dict[str, tuple[str, str]],
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
        and case["ordinal"] == ordinal
        and case["row_sha256"] == row["row_sha256"]
        and case["literal_sha256"] == row["literal_sha256"]
        and case["literal_hex"] == row["literal_hex"]
        and set(case["dimensions"]) == DIMENSION_FIELDS
        and case["dimensions"] == expected_dimensions(row),
        f"case {ordinal}: identity or dimensions changed",
    )
    compiler = case["compiler"]
    require(
        isinstance(compiler, dict)
        and set(compiler) == COMPILER_FIELDS
        and compiler["backend_tag"] == 29
        and compiler["backend_version"] == "SEARCH_V16"
        and compiler["candidate_policy"] == 15
        and compiler["disposition"] == "tag29-object"
        and is_hex(compiler["compile_receipt_sha256"])
        and is_hex(compiler["object_sha256"]),
        f"case {ordinal}: compiler disposition changed",
    )
    literal_receipt = (
        compiler["compile_receipt_sha256"],
        compiler["object_sha256"],
    )
    previous = literal_objects.setdefault(row["literal_sha256"], literal_receipt)
    require(
        previous == literal_receipt,
        f"case {ordinal}: one literal maps to multiple objects",
    )
    precheck = case["precheck"]
    count = expected_nonoverlapping_count(row)
    require(
        isinstance(precheck, dict)
        and set(precheck) == PRECHECK_FIELDS
        and precheck["expected_nonoverlapping_count"] == count
        and precheck["portable_nonoverlapping_count"] == count
        and precheck["candidate_nonoverlapping_count"] == count
        and precheck["portable_route"] == "full-portable"
        and precheck["candidate_route"] == "portable-prefix-static-tail"
        and precheck["portable_static_invocations"] == 0
        and precheck["candidate_static_invocations"] == 1,
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
    validate_mapping(case["mapping"], row)
    setup = case["timing_setup"]
    require(
        isinstance(setup, dict)
        and set(setup) == TIMING_SETUP_FIELDS
        and setup["fixture_materialization_outside_timing"] is True
        and setup["compile_link_adoption_outside_timing"] is True
        and setup["pilot_outside_timing"] is True
        and setup["route_instrumentation_outside_timing"] is True
        and is_hex(setup["timed_function_identity_sha256"]),
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
    ratios = []
    for pair_index, pair in enumerate(pairs):
        require(
            isinstance(pair, dict)
            and set(pair) == PAIR_FIELDS
            and pair["pair_index"] == pair_index
            and pair["first_variant"]
            == ("portable" if pair_index % 2 == 0 else "candidate")
            and is_u64(pair["iteration_count"])
            and pair["iteration_count"] > 0
            and pair["fixture_pointer_address"]
            == case["mapping"]["fixture_pointer_address"]
            and pair["checked_pointer_address"]
            == case["mapping"]["checked_pointer_address"]
            and is_u64(pair["logical_cpu"])
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
        ratios.append(
            Fraction(
                pair["candidate"]["elapsed_ns"],
                pair["portable"]["elapsed_ns"],
            )
        )
    ratios.sort()
    median = (ratios[2] + ratios[3]) / 2
    return median


def parse_host_bundle(
    path: Path,
    manifest_host: dict[str, Any],
    expected_host: dict[str, Any],
    authority: dict[str, Any],
    expected_campaign_id: str,
    timed_rows: list[dict[str, Any]],
) -> tuple[list[Fraction], dict[tuple[str, str], list[Fraction]]]:
    actual_sha, actual_bytes = file_sha_and_bytes(path)
    bundle = manifest_host["bundle"]
    require(
        actual_sha == bundle["sha256"]
        and actual_bytes == bundle["bytes"]
        and bundle["case_records"] == TIMED_ROWS
        and bundle["pairs"] == PAIRS_PER_HOST
        and bundle["measurements"] == MEASUREMENTS_PER_HOST,
        f"{expected_host['canonical_name']}: bundle receipt changed",
    )
    with path.open("rb") as source:
        raw_lines = source.readlines()
    require(
        len(raw_lines) == TIMED_ROWS + 2,
        f"{expected_host['canonical_name']}: line count changed",
    )
    parsed = []
    for line_number, line in enumerate(raw_lines, 1):
        require(
            line.endswith(b"\n")
            and canonical_bytes(json.loads(line)) + b"\n" == line,
            f"{expected_host['canonical_name']}: noncanonical line {line_number}",
        )
        parsed.append(json.loads(line))
    header = parsed[0]
    require(
        isinstance(header, dict)
        and set(header) == HEADER_FIELDS
        and header["schema"] == HEADER_SCHEMA
        and header["campaign_id"] == expected_campaign_id
        and header["frozen_host"] == expected_host["frozen_name"]
        and header["canonical_host"] == expected_host["canonical_name"]
        and header["target_triple"] == expected_host["target_triple"]
        and header["features"] == expected_host["features"]
        and header["host_attestation_sha256"]
        == manifest_host["host_attestation_sha256"]
        and header["runner_binary_sha256"]
        == manifest_host["runner_binary_sha256"]
        and header["linked_image_sha256"]
        == manifest_host["linked_image_sha256"]
        and header["linked_image_platform_identity_sha256"]
        == manifest_host["linked_image_platform_identity_sha256"]
        and header["build_closure_sha256"]
        == manifest_host["build_closure_sha256"]
        and header["toolchain_closure_sha256"]
        == manifest_host["toolchain_closure_sha256"]
        and header["runner_source_commit"]
        == authority["runner"]["source_commit"]
        and header["runner_source_set_sha256"]
        == authority["runner"]["source_set_sha256"]
        and header["object_manifest_sha256"]
        == authority["runner"]["object_manifest_sha256"]
        and header["qualification_plan_sha256"]
        == authority["qualification_plan_sha256"]
        and header["case_records"] == TIMED_ROWS
        and header["pairs"] == PAIRS_PER_HOST
        and header["measurements"] == MEASUREMENTS_PER_HOST,
        f"{expected_host['canonical_name']}: header changed",
    )
    prefix_digest = hashlib.sha256()
    for line in raw_lines[:-1]:
        prefix_digest.update(line)
    trailer = parsed[-1]
    require(
        isinstance(trailer, dict)
        and set(trailer) == TRAILER_FIELDS
        and trailer
        == {
            "schema": TRAILER_SCHEMA,
            "campaign_id": expected_campaign_id,
            "case_records": TIMED_ROWS,
            "pairs": PAIRS_PER_HOST,
            "measurements": MEASUREMENTS_PER_HOST,
            "prefix_sha256": prefix_digest.hexdigest(),
        },
        f"{expected_host['canonical_name']}: trailer changed",
    )
    ratios = []
    groups: dict[tuple[str, str], list[Fraction]] = defaultdict(list)
    literal_objects: dict[str, tuple[str, str]] = {}
    for ordinal, (case, row) in enumerate(
        zip(parsed[1:-1], timed_rows, strict=True)
    ):
        ratio = validate_case(
            case, row, ordinal, expected_campaign_id, literal_objects
        )
        ratios.append(ratio)
        for key in group_keys(case["dimensions"]):
            groups[key].append(ratio)
    require(
        len(ratios) == TIMED_ROWS,
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
        len(sys.argv) == 3,
        "usage: analyze_qualification_results.py QUALIFICATION_DIR RESULT_MANIFEST",
    )
    qualification_root = Path(sys.argv[1]).resolve(strict=True)
    manifest_path = Path(sys.argv[2]).resolve(strict=True)
    result_root = manifest_path.parent
    plan = validate_plan(qualification_root)
    timed_rows = load_timed_rows(qualification_root, plan)
    manifest = json.loads(regular_file(manifest_path, 16 * 1024 * 1024))
    require(
        isinstance(manifest, dict)
        and set(manifest)
        == {"schema", "campaign_id", "authority_sha256", "authority", "hosts"}
        and manifest["schema"] == MANIFEST_SCHEMA
        and canonical_sha(manifest["authority"])
        == manifest["authority_sha256"],
        "result manifest envelope changed",
    )
    analyzer_sha256 = sha256(regular_file(Path(__file__).resolve()))
    authority = manifest["authority"]
    validate_authority(authority, plan, analyzer_sha256)
    expected_campaign_id = campaign_id(authority)
    require(
        manifest["campaign_id"] == expected_campaign_id,
        "campaign identity changed",
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
    attestation_identities = set()
    output_hosts = {}
    all_pass = True
    expected_group_counts: dict[tuple[str, str], int] = defaultdict(int)
    for row in timed_rows:
        for key in group_keys(expected_dimensions(row)):
            expected_group_counts[key] += 1
    for manifest_host, expected_host in zip(hosts, HOSTS, strict=True):
        require(
            manifest_host["frozen_name"] == expected_host["frozen_name"]
            and manifest_host["canonical_name"]
            == expected_host["canonical_name"]
            and manifest_host["target_triple"]
            == expected_host["target_triple"]
            and manifest_host["features"] == expected_host["features"]
            and all(
                is_hex(manifest_host[field])
                for field in (
                    "host_attestation_sha256",
                    "runner_binary_sha256",
                    "linked_image_sha256",
                    "linked_image_platform_identity_sha256",
                    "build_closure_sha256",
                    "toolchain_closure_sha256",
                )
            )
            and isinstance(manifest_host["bundle"], dict)
            and set(manifest_host["bundle"]) == BUNDLE_FIELDS
            and canonical_relative(manifest_host["bundle"]["path"])
            and is_u64(manifest_host["bundle"]["bytes"])
            and is_hex(manifest_host["bundle"]["sha256"]),
            "host identity or bundle authority changed",
        )
        require(
            manifest_host["host_attestation_sha256"]
            not in attestation_identities,
            "hosts share one attestation identity",
        )
        attestation_identities.add(manifest_host["host_attestation_sha256"])
        ratios, groups = parse_host_bundle(
            result_root / manifest_host["bundle"]["path"],
            manifest_host,
            expected_host,
            authority,
            expected_campaign_id,
            timed_rows,
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
            group_pass = all(ratio < STRICT_GATE for ratio in group_ratios)
            require(
                len(group_ratios)
                == expected_group_counts[(dimension, value)],
                "group completeness reconstruction changed",
            )
            group_output[f"{dimension}={value}"] = {
                "cells": len(group_ratios),
                "maximum_cell_ratio": rational_receipt(max(group_ratios)),
                "pass_as_conjunction_of_cells": group_pass,
                "authorizes_independently": False,
            }
        require(
            set(groups) == set(expected_group_counts),
            "result strata set differs from frozen projection",
        )
        output_hosts[expected_host["canonical_name"]] = {
            "cells": len(ratios),
            "maximum_cell_ratio": rational_receipt(max(ratios)),
            "failing_cells": failing,
            "cell_gate": "strictly-less-than-4/5",
            "pass": host_pass,
            "strata_completeness": group_output,
        }
    output = {
        "schema": "fre.aot.search-tag29-paired-result-analysis.v1",
        "campaign_id": expected_campaign_id,
        "qualification_plan_sha256": plan["sha256"],
        "timed_projection_digest": TIMED_PROJECTION_DIGEST,
        "hosts": output_hosts,
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
