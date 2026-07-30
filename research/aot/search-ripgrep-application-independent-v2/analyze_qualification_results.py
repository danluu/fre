#!/usr/bin/env python3
"""Fail-closed paired analyzer for the Rebar-blind ripgrep application gate."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import stat
import subprocess
import sys
from collections import defaultdict
from fractions import Fraction
from pathlib import Path
from types import ModuleType
from typing import Any, BinaryIO, Iterable


MANIFEST_SCHEMA = "fre.aot.search-tag29-application-result-manifest.v2"
HEADER_SCHEMA = "fre.aot.search-tag29-application-host-header.v2"
CASE_SCHEMA = "fre.aot.search-tag29-application-case-result.v2"
TRAILER_SCHEMA = "fre.aot.search-tag29-application-host-trailer.v2"
CAMPAIGN_DOMAIN = b"FRE-SEARCH-TAG29-APPLICATION-RESULT-CAMPAIGN\0\x02"
CASE_DOMAIN = b"FRE-SEARCH-TAG29-APPLICATION-CASE\0\x02"
FREEZE_RELATIVE = (
    "research/aot/search-ripgrep-application-independent-v2/freeze-v2.json"
)
FREEZE_SHA256 = (
    "a491f2fd1e19d01cca9a237770c8cdefa04a90e3623dadfcc4c79012eb2abd52"
)
FREEZE_PAYLOAD_SHA256 = (
    "3359ab7c620482d67d67d09903981c8b322c5268cfe0640e273de0f778192822"
)
INVENTORY_RELATIVE = (
    "research/aot/search-ripgrep-application-independent-v2/inventory-v2.json"
)
INVENTORY_SHA256 = (
    "2aec7b83cfcafbd0f8a9cab2e08941882b34d39786d26f26837c671378f1275b"
)
INVENTORY_PAYLOAD_SHA256 = (
    "68af2c6dd547935d3c4dd095f18958035104d153b355ff416c46c78a922b0979"
)
FIXTURE_MANIFEST_SHA256 = (
    "b20181470c604d01d2ec236259293cfcb6e5eff145bcd3e4daa91554c8cebcca"
)
FIXTURE_MANIFEST_PAYLOAD_SHA256 = (
    "1cbda700087f5506daa91b0657070cbf39fac68222ff84e273d1d83c09f6ebfd"
)
UPSTREAM_COMMIT = "f9c05a949d1a0dc8e16dee28ca9605d38611faeb"
UPSTREAM_TREE = "ce81df4f8cad2dbfd1afb6b3ba53fd19846a5794"
CASES = 154
REPETITIONS = 6
PAIRS_PER_HOST = CASES * REPETITIONS
MEASUREMENTS_PER_HOST = PAIRS_PER_HOST * 2
MINIMUM_NS = 400_000_000
STATIC_GATE = Fraction(4, 5)
NONTARGET_GATE = Fraction(21, 20)
HOSTS = (
    {
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
    "freeze_payload_sha256",
    "inventory_sha256",
    "inventory_payload_sha256",
    "fixture_manifest_sha256",
    "fixture_manifest_payload_sha256",
    "upstream_commit",
    "upstream_tree",
    "case_count",
    "runner",
    "hosts",
    "performance_authority",
    "rebar_inputs",
    "benchmark_result_inputs",
    "network",
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
    "fixture_manifest_sha256",
    "case_records",
    "pairs",
    "measurements",
}
CASE_FIELDS = {
    "schema",
    "campaign_id",
    "ordinal",
    "case_id",
    "candidate_sha256",
    "literal_hex",
    "literal_sha256",
    "literal_bytes",
    "scenario",
    "scenario_family",
    "fixture_sha256",
    "fixture_bytes",
    "alignment_offset",
    "structural_class",
    "route_class",
    "compiler",
    "precheck",
    "mapping",
    "timing_setup",
    "pairs",
}
COMPILER_FIELDS = {
    "backend_tag",
    "backend_version",
    "candidate_policy",
    "disposition",
    "compile_receipt_sha256",
    "object_sha256",
    "refusal_receipt_sha256",
}
PRECHECK_FIELDS = {
    "scalar_span",
    "portable_span",
    "candidate_span",
    "scalar_nonoverlapping_count",
    "portable_nonoverlapping_count",
    "candidate_nonoverlapping_count",
    "portable_route",
    "candidate_route",
    "portable_static_invocations",
    "candidate_static_invocations",
}
MAPPING_FIELDS = {
    "storage_pointer_address",
    "checked_pointer_address",
    "storage_bytes",
    "checked_bytes",
    "start_offset",
    "actual_window_start_mod16",
    "readable_left_bytes",
    "readable_right_bytes",
    "padding_sentinel",
    "padding_verified",
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
    "storage_pointer_address",
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
    "nonoverlapping_count",
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
    """The application result bundle is incomplete, changed, or fails."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def load_core() -> ModuleType:
    path = (
        Path(__file__).resolve().parents[1]
        / "search-tag29-topology-generalization-v1"
        / "analyze_qualification_results.py"
    )
    specification = importlib.util.spec_from_file_location(
        "_fre_search_tag29_result_core", path
    )
    require(
        specification is not None and specification.loader is not None,
        "cannot load paired-result core",
    )
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


CORE = load_core()


def sha256(encoded: bytes) -> str:
    return hashlib.sha256(encoded).hexdigest()


def canonical_bytes(value: Any) -> bytes:
    return CORE.canonical_bytes(value)


def canonical_sha(value: Any) -> str:
    return CORE.canonical_sha(value)


def is_hex(value: Any, length: int = 64) -> bool:
    return CORE.is_hex(value, length)


def is_u64(value: Any) -> bool:
    return CORE.is_u64(value)


def canonical_relative(value: Any) -> bool:
    return CORE.canonical_relative(value)


def regular_file(path: Path, maximum: int = 1024 * 1024 * 1024) -> bytes:
    return CORE.regular_file(path, maximum)


def file_sha_and_bytes(path: Path) -> tuple[str, int]:
    return CORE.file_sha_and_bytes(path)


def campaign_id(authority: dict[str, Any]) -> str:
    return sha256(CAMPAIGN_DOMAIN + canonical_bytes(authority))


def validate_span(value: Any, expected: Any, message: str) -> None:
    CORE.validate_span(value, expected, message)


def run_freeze_validator(
    repo: Path, ripgrep_root: Path, fixture_root: Path
) -> None:
    validator = (
        repo
        / "research/aot/search-ripgrep-application-independent-v2/"
        "validate_freeze.py"
    )
    result = subprocess.run(
        [
            sys.executable,
            str(validator),
            str(repo / FREEZE_RELATIVE),
            str(repo),
            str(ripgrep_root),
            str(fixture_root),
        ],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    require(
        result.returncode == 0 and not result.stderr,
        "application freeze validation failed",
    )


def case_id(
    candidate_sha256: str, scenario: str, fixture_sha256: str
) -> str:
    return sha256(
        CASE_DOMAIN
        + bytes.fromhex(candidate_sha256)
        + b"\0"
        + scenario.encode("ascii")
        + b"\0"
        + bytes.fromhex(fixture_sha256)
    )


def scenario_family(scenario: str) -> str:
    return "mutation" if scenario.startswith("near-miss-offset-") else "common"


def load_cases(
    repo: Path, fixture_root: Path
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    freeze = json.loads(regular_file(repo / FREEZE_RELATIVE))
    inventory = json.loads(regular_file(repo / INVENTORY_RELATIVE))
    manifest_bytes = regular_file(fixture_root / "manifest.json")
    require(
        sha256(regular_file(repo / FREEZE_RELATIVE)) == FREEZE_SHA256
        and freeze["payload_sha256"] == FREEZE_PAYLOAD_SHA256
        and sha256(regular_file(repo / INVENTORY_RELATIVE))
        == INVENTORY_SHA256
        and inventory["payload_sha256"] == INVENTORY_PAYLOAD_SHA256
        and sha256(manifest_bytes) == FIXTURE_MANIFEST_SHA256,
        "application source or fixture identity changed",
    )
    manifest = json.loads(manifest_bytes)
    require(
        manifest["payload_sha256"] == FIXTURE_MANIFEST_PAYLOAD_SHA256,
        "fixture manifest payload changed",
    )
    eligible = {
        row["semantic_candidate_sha256"]
        for row in freeze["payload"]["selector"]["eligible"]
    }
    ineligible = {
        row["semantic_candidate_sha256"]
        for row in freeze["payload"]["selector"]["ineligible"]
    }
    cases = []
    route_counts: dict[str, int] = defaultdict(int)
    for candidate in manifest["payload"]["candidates"]:
        candidate_identity = candidate["semantic_candidate_sha256"]
        structural_class = (
            "tag29-object"
            if candidate_identity in eligible
            else "structural-refusal"
        )
        require(
            candidate_identity in eligible | ineligible,
            "fixture candidate lacks frozen selector class",
        )
        for row in candidate["fixtures"]:
            if structural_class == "structural-refusal":
                route_class = "full-portable-fallback"
            elif row["scenario"] in {"early", "dense"}:
                route_class = "portable-prefix-return"
            else:
                route_class = "tag29-static-tail"
            route_counts[route_class] += 1
            cases.append(
                {
                    "case_id": case_id(
                        candidate_identity,
                        row["scenario"],
                        row["sha256"],
                    ),
                    "candidate_sha256": candidate_identity,
                    "literal_hex": candidate["literal_hex"],
                    "literal_sha256": candidate["literal_sha256"],
                    "literal_bytes": candidate["literal_bytes"],
                    "scenario": row["scenario"],
                    "scenario_family": scenario_family(row["scenario"]),
                    "fixture_sha256": row["sha256"],
                    "fixture_bytes": row["bytes"],
                    "alignment_offset": row["alignment_offset"],
                    "wrong_byte": row["wrong_byte"],
                    "expected_span": row["expected_leftmost_span"],
                    "expected_count": row["expected_nonoverlapping_count"],
                    "structural_class": structural_class,
                    "route_class": route_class,
                }
            )
    require(
        len(cases) == CASES
        and len({case["case_id"] for case in cases}) == CASES
        and route_counts
        == {
            "tag29-static-tail": 75,
            "portable-prefix-return": 10,
            "full-portable-fallback": 69,
        },
        "application case or route cardinality changed",
    )
    return cases, freeze


def validate_authority(
    authority: dict[str, Any], analyzer_sha256: str
) -> None:
    require(
        set(authority) == AUTHORITY_FIELDS
        and authority["campaign_name"] == "search-tag29-ripgrep-application-v2"
        and authority["freeze_sha256"] == FREEZE_SHA256
        and authority["freeze_payload_sha256"] == FREEZE_PAYLOAD_SHA256
        and authority["inventory_sha256"] == INVENTORY_SHA256
        and authority["inventory_payload_sha256"]
        == INVENTORY_PAYLOAD_SHA256
        and authority["fixture_manifest_sha256"]
        == FIXTURE_MANIFEST_SHA256
        and authority["fixture_manifest_payload_sha256"]
        == FIXTURE_MANIFEST_PAYLOAD_SHA256
        and authority["upstream_commit"] == UPSTREAM_COMMIT
        and authority["upstream_tree"] == UPSTREAM_TREE
        and authority["case_count"] == CASES
        and authority["hosts"]
        == [host["canonical_name"] for host in HOSTS]
        and authority["performance_authority"]
        == {
            "cell_ratio": (
                "sort six exact candidate_elapsed_ns/portable_elapsed_ns "
                "rationals; median=(ratio[2]+ratio[3])/2"
            ),
            "tag29_static_tail_gate": (
                "strictly less than 4/5 for each of 75 cases on each host"
            ),
            "portable_prefix_return_gate": (
                "at most 21/20 for each of 10 cases on each host"
            ),
            "full_portable_fallback_gate": (
                "at most 21/20 for each of 69 cases on each host"
            ),
            "minimum_elapsed_ns_each_variant": MINIMUM_NS,
            "repetitions": REPETITIONS,
            "aggregate_rescue_permitted": False,
        }
        and authority["rebar_inputs"] == []
        and authority["benchmark_result_inputs"] == []
        and authority["network"] is False
        and authority["result_derived_exclusions"] is False,
        "application campaign authority changed",
    )
    runner = authority["runner"]
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
        and runner["object_manifest_sha256"] == FIXTURE_MANIFEST_SHA256
        and runner["object_manifest_payload_sha256"]
        == FIXTURE_MANIFEST_PAYLOAD_SHA256
        and runner["backend_tag"] == 29
        and runner["backend_version"] == "SEARCH_V16"
        and runner["candidate_policy"] == 15
        and runner["llvm"] is False
        and runner["ordinary_candidate_entry"]
        == "production-auto-route-portable-prefix-static-tail-or-fallback"
        and runner["baseline_entry"] == "forced-full-portable",
        "application runner authority changed",
    )


def candidate_route(route_class: str) -> str:
    return {
        "tag29-static-tail": "portable-prefix-static-tail",
        "portable-prefix-return": "portable-prefix-return",
        "full-portable-fallback": "full-portable",
    }[route_class]


def candidate_static_invocations(route_class: str) -> int:
    return 1 if route_class == "tag29-static-tail" else 0


def validate_mapping(mapping: dict[str, Any], expected: dict[str, Any]) -> None:
    require(
        isinstance(mapping, dict)
        and set(mapping) == MAPPING_FIELDS
        and all(
            is_u64(mapping[field])
            for field in (
                "storage_pointer_address",
                "checked_pointer_address",
                "storage_bytes",
                "checked_bytes",
                "start_offset",
                "actual_window_start_mod16",
                "readable_left_bytes",
                "readable_right_bytes",
                "padding_sentinel",
            )
        )
        and mapping["storage_bytes"] == expected["fixture_bytes"] + 63
        and mapping["checked_bytes"] == expected["fixture_bytes"]
        and mapping["checked_pointer_address"]
        == mapping["storage_pointer_address"] + mapping["start_offset"]
        and mapping["start_offset"]
        == 16
        + (
            expected["alignment_offset"]
            - ((mapping["storage_pointer_address"] + 16) % 16)
        )
        % 16
        and 16 <= mapping["start_offset"] <= 31
        and mapping["actual_window_start_mod16"]
        == expected["alignment_offset"]
        and mapping["checked_pointer_address"] % 16
        == expected["alignment_offset"]
        and mapping["readable_left_bytes"] == mapping["start_offset"]
        and mapping["readable_right_bytes"]
        == 63 - mapping["start_offset"]
        and 32 <= mapping["readable_right_bytes"] <= 47
        and mapping["padding_sentinel"] == expected["wrong_byte"]
        and mapping["padding_verified"] is True
        and is_hex(mapping["allocation_receipt_sha256"]),
        "application physical alignment receipt changed",
    )


def validate_measurement(
    measurement: dict[str, Any],
    expected: dict[str, Any],
    route: str,
) -> None:
    require(
        isinstance(measurement, dict)
        and set(measurement) == MEASUREMENT_FIELDS
        and is_u64(measurement["elapsed_ns"])
        and measurement["elapsed_ns"] >= MINIMUM_NS
        and is_u64(measurement["output_accumulator"])
        and measurement["nonoverlapping_count"]
        == expected["expected_count"]
        and measurement["route"] == route,
        "application timed measurement changed",
    )
    validate_span(
        measurement["last_span"],
        expected["expected_span"],
        "application timed span changed",
    )


def validate_case(
    result: dict[str, Any],
    expected: dict[str, Any],
    ordinal: int,
    expected_campaign_id: str,
    candidate_compilers: dict[str, tuple[Any, ...]],
) -> Fraction:
    require(
        isinstance(result, dict)
        and set(result) == CASE_FIELDS
        and result["schema"] == CASE_SCHEMA
        and result["campaign_id"] == expected_campaign_id
        and result["ordinal"] == ordinal
        and all(
            result[field] == expected[field]
            for field in (
                "case_id",
                "candidate_sha256",
                "literal_hex",
                "literal_sha256",
                "literal_bytes",
                "scenario",
                "scenario_family",
                "fixture_sha256",
                "fixture_bytes",
                "alignment_offset",
                "structural_class",
                "route_class",
            )
        ),
        f"application case {ordinal}: identity or classification changed",
    )
    compiler = result["compiler"]
    eligible = expected["structural_class"] == "tag29-object"
    require(
        isinstance(compiler, dict)
        and set(compiler) == COMPILER_FIELDS
        and compiler["backend_tag"] == 29
        and compiler["backend_version"] == "SEARCH_V16"
        and compiler["candidate_policy"] == 15
        and compiler["disposition"] == expected["structural_class"]
        and is_hex(compiler["compile_receipt_sha256"])
        and (
            is_hex(compiler["object_sha256"])
            if eligible
            else compiler["object_sha256"] is None
        )
        and (
            compiler["refusal_receipt_sha256"] is None
            if eligible
            else is_hex(compiler["refusal_receipt_sha256"])
        ),
        f"application case {ordinal}: compiler disposition changed",
    )
    compiler_identity = tuple(compiler[field] for field in COMPILER_FIELDS)
    previous = candidate_compilers.setdefault(
        expected["candidate_sha256"], compiler_identity
    )
    require(
        previous == compiler_identity,
        f"application case {ordinal}: candidate compiler receipt varies",
    )
    route = candidate_route(expected["route_class"])
    static_invocations = candidate_static_invocations(
        expected["route_class"]
    )
    precheck = result["precheck"]
    require(
        isinstance(precheck, dict)
        and set(precheck) == PRECHECK_FIELDS
        and precheck["scalar_nonoverlapping_count"]
        == expected["expected_count"]
        and precheck["portable_nonoverlapping_count"]
        == expected["expected_count"]
        and precheck["candidate_nonoverlapping_count"]
        == expected["expected_count"]
        and precheck["portable_route"] == "full-portable"
        and precheck["candidate_route"] == route
        and precheck["portable_static_invocations"] == 0
        and precheck["candidate_static_invocations"] == static_invocations,
        f"application case {ordinal}: route or count precheck changed",
    )
    for field in ("scalar_span", "portable_span", "candidate_span"):
        validate_span(
            precheck[field],
            expected["expected_span"],
            f"application case {ordinal}: {field}",
        )
    validate_mapping(result["mapping"], expected)
    setup = result["timing_setup"]
    require(
        isinstance(setup, dict)
        and set(setup) == TIMING_SETUP_FIELDS
        and setup["fixture_materialization_outside_timing"] is True
        and setup["compile_link_adoption_outside_timing"] is True
        and setup["pilot_outside_timing"] is True
        and setup["route_instrumentation_outside_timing"] is True
        and is_hex(setup["timed_function_identity_sha256"]),
        f"application case {ordinal}: timing boundary changed",
    )
    pairs = result["pairs"]
    require(
        isinstance(pairs, list) and len(pairs) == REPETITIONS,
        f"application case {ordinal}: pair count changed",
    )
    iteration_count = None
    logical_cpu = None
    affinity = None
    admission = None
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
            and pair["storage_pointer_address"]
            == result["mapping"]["storage_pointer_address"]
            and pair["checked_pointer_address"]
            == result["mapping"]["checked_pointer_address"]
            and is_u64(pair["logical_cpu"])
            and pair["cpu_before"] == pair["logical_cpu"]
            and pair["cpu_after"] == pair["logical_cpu"]
            and is_hex(pair["affinity_receipt_sha256"])
            and is_hex(pair["admission_receipt_sha256"]),
            f"application case {ordinal} pair {pair_index}: pairing changed",
        )
        if iteration_count is None:
            iteration_count = pair["iteration_count"]
            logical_cpu = pair["logical_cpu"]
            affinity = pair["affinity_receipt_sha256"]
            admission = pair["admission_receipt_sha256"]
        require(
            pair["iteration_count"] == iteration_count
            and pair["logical_cpu"] == logical_cpu
            and pair["affinity_receipt_sha256"] == affinity
            and pair["admission_receipt_sha256"] == admission,
            f"application case {ordinal}: pair environment varies",
        )
        validate_measurement(
            pair["portable"], expected, "full-portable"
        )
        validate_measurement(pair["candidate"], expected, route)
        require(
            pair["portable"]["output_accumulator"]
            == pair["candidate"]["output_accumulator"],
            f"application case {ordinal}: accumulator differs",
        )
        ratios.append(
            Fraction(
                pair["candidate"]["elapsed_ns"],
                pair["portable"]["elapsed_ns"],
            )
        )
    ratios.sort()
    return (ratios[2] + ratios[3]) / 2


def parse_bundle(
    path: Path,
    manifest_host: dict[str, Any],
    expected_host: dict[str, Any],
    authority: dict[str, Any],
    expected_campaign_id: str,
    expected_cases: list[dict[str, Any]],
) -> tuple[list[Fraction], dict[str, list[Fraction]]]:
    actual_sha, actual_bytes = file_sha_and_bytes(path)
    bundle = manifest_host["bundle"]
    require(
        actual_sha == bundle["sha256"]
        and actual_bytes == bundle["bytes"]
        and bundle["case_records"] == CASES
        and bundle["pairs"] == PAIRS_PER_HOST
        and bundle["measurements"] == MEASUREMENTS_PER_HOST,
        f"{expected_host['canonical_name']}: application bundle changed",
    )
    with path.open("rb") as source:
        raw_lines = source.readlines()
    require(
        len(raw_lines) == CASES + 2,
        f"{expected_host['canonical_name']}: application line count changed",
    )
    parsed = []
    for line_number, line in enumerate(raw_lines, 1):
        value = json.loads(line)
        require(
            line.endswith(b"\n") and canonical_bytes(value) + b"\n" == line,
            f"{expected_host['canonical_name']}: noncanonical line {line_number}",
        )
        parsed.append(value)
    header = parsed[0]
    require(
        isinstance(header, dict)
        and set(header) == HEADER_FIELDS
        and header["schema"] == HEADER_SCHEMA
        and header["campaign_id"] == expected_campaign_id
        and header["canonical_host"] == expected_host["canonical_name"]
        and header["target_triple"] == expected_host["target_triple"]
        and header["features"] == expected_host["features"]
        and all(
            header[field] == manifest_host[field]
            for field in (
                "host_attestation_sha256",
                "runner_binary_sha256",
                "linked_image_sha256",
                "linked_image_platform_identity_sha256",
                "build_closure_sha256",
                "toolchain_closure_sha256",
            )
        )
        and header["runner_source_commit"]
        == authority["runner"]["source_commit"]
        and header["runner_source_set_sha256"]
        == authority["runner"]["source_set_sha256"]
        and header["object_manifest_sha256"]
        == FIXTURE_MANIFEST_SHA256
        and header["fixture_manifest_sha256"]
        == FIXTURE_MANIFEST_SHA256
        and header["case_records"] == CASES
        and header["pairs"] == PAIRS_PER_HOST
        and header["measurements"] == MEASUREMENTS_PER_HOST,
        f"{expected_host['canonical_name']}: application header changed",
    )
    prefix = hashlib.sha256()
    for line in raw_lines[:-1]:
        prefix.update(line)
    require(
        parsed[-1]
        == {
            "schema": TRAILER_SCHEMA,
            "campaign_id": expected_campaign_id,
            "case_records": CASES,
            "pairs": PAIRS_PER_HOST,
            "measurements": MEASUREMENTS_PER_HOST,
            "prefix_sha256": prefix.hexdigest(),
        },
        f"{expected_host['canonical_name']}: application trailer changed",
    )
    ratios = []
    groups: dict[str, list[Fraction]] = defaultdict(list)
    candidate_compilers: dict[str, tuple[Any, ...]] = {}
    for ordinal, (result, expected) in enumerate(
        zip(parsed[1:-1], expected_cases, strict=True)
    ):
        ratio = validate_case(
            result,
            expected,
            ordinal,
            expected_campaign_id,
            candidate_compilers,
        )
        ratios.append(ratio)
        for key in (
            f"route={expected['route_class']}",
            f"candidate={expected['candidate_sha256']}",
            f"width={expected['literal_bytes']}",
            f"scenario={expected['scenario']}",
            f"scenario_family={expected['scenario_family']}",
            f"alignment={expected['alignment_offset']}",
        ):
            groups[key].append(ratio)
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
        "usage: analyze_qualification_results.py REPO RIPGREP_ROOT FIXTURE_ROOT RESULT_MANIFEST",
    )
    repo = Path(sys.argv[1]).resolve(strict=True)
    ripgrep_root = Path(sys.argv[2]).resolve(strict=True)
    fixture_root = Path(sys.argv[3]).resolve(strict=True)
    manifest_path = Path(sys.argv[4]).resolve(strict=True)
    run_freeze_validator(repo, ripgrep_root, fixture_root)
    expected_cases, _ = load_cases(repo, fixture_root)
    manifest = json.loads(regular_file(manifest_path, 16 * 1024 * 1024))
    require(
        isinstance(manifest, dict)
        and set(manifest)
        == {"schema", "campaign_id", "authority_sha256", "authority", "hosts"}
        and manifest["schema"] == MANIFEST_SCHEMA
        and canonical_sha(manifest["authority"])
        == manifest["authority_sha256"],
        "application result manifest changed",
    )
    analyzer_sha256 = sha256(regular_file(Path(__file__).resolve()))
    authority = manifest["authority"]
    validate_authority(authority, analyzer_sha256)
    expected_campaign_id = campaign_id(authority)
    require(
        manifest["campaign_id"] == expected_campaign_id,
        "application campaign identity changed",
    )
    hosts = manifest["hosts"]
    require(
        isinstance(hosts, list)
        and len(hosts) == len(HOSTS)
        and all(
            isinstance(host, dict) and set(host) == HOST_MANIFEST_FIELDS
            for host in hosts
        ),
        "application host set changed",
    )
    attestations = set()
    output_hosts = {}
    all_pass = True
    expected_group_counts: dict[str, int] = defaultdict(int)
    for case in expected_cases:
        for key in (
            f"route={case['route_class']}",
            f"candidate={case['candidate_sha256']}",
            f"width={case['literal_bytes']}",
            f"scenario={case['scenario']}",
            f"scenario_family={case['scenario_family']}",
            f"alignment={case['alignment_offset']}",
        ):
            expected_group_counts[key] += 1
    for manifest_host, expected_host in zip(hosts, HOSTS, strict=True):
        require(
            manifest_host["canonical_name"]
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
            and set(manifest_host["bundle"]) == BUNDLE_FIELDS
            and canonical_relative(manifest_host["bundle"]["path"])
            and is_u64(manifest_host["bundle"]["bytes"])
            and is_hex(manifest_host["bundle"]["sha256"]),
            "application host identity changed",
        )
        require(
            manifest_host["host_attestation_sha256"] not in attestations,
            "application hosts share one attestation",
        )
        attestations.add(manifest_host["host_attestation_sha256"])
        ratios, groups = parse_bundle(
            manifest_path.parent / manifest_host["bundle"]["path"],
            manifest_host,
            expected_host,
            authority,
            expected_campaign_id,
            expected_cases,
        )
        failures = []
        for expected, ratio in zip(expected_cases, ratios, strict=True):
            threshold = (
                STATIC_GATE
                if expected["route_class"] == "tag29-static-tail"
                else NONTARGET_GATE
            )
            passes = (
                ratio < threshold
                if expected["route_class"] == "tag29-static-tail"
                else ratio <= threshold
            )
            if not passes:
                failures.append(expected["case_id"])
        host_pass = not failures
        all_pass = all_pass and host_pass
        group_output = {}
        for key, values in sorted(groups.items()):
            require(
                len(values) == expected_group_counts[key],
                "application diagnostic group is incomplete",
            )
            group_output[key] = {
                "cells": len(values),
                "maximum_cell_ratio": rational_receipt(max(values)),
                "authorizes_independently": False,
            }
        require(
            set(groups) == set(expected_group_counts),
            "application diagnostic group set changed",
        )
        output_hosts[expected_host["canonical_name"]] = {
            "cases": len(ratios),
            "maximum_cell_ratio": rational_receipt(max(ratios)),
            "failing_cases": failures,
            "route_counts": {
                route: sum(
                    case["route_class"] == route for case in expected_cases
                )
                for route in (
                    "tag29-static-tail",
                    "portable-prefix-return",
                    "full-portable-fallback",
                )
            },
            "pass": host_pass,
            "diagnostic_groups": group_output,
        }
    output = {
        "schema": "fre.aot.search-tag29-application-result-analysis.v2",
        "campaign_id": expected_campaign_id,
        "freeze_sha256": FREEZE_SHA256,
        "freeze_payload_sha256": FREEZE_PAYLOAD_SHA256,
        "hosts": output_hosts,
        "total_cases": CASES * len(HOSTS),
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
        print(f"search-tag29-application-results: {error}", file=sys.stderr)
        raise SystemExit(1)
