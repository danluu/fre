#!/usr/bin/env python3
"""Fail-closed analyzer for the Rebar-blind ripgrep application gate.

Campaign authority and compiler/object/link evidence are pre-result inputs.
The result manifest may only refer to their exact whole-file identities.
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
from types import ModuleType
from typing import Any


AUTHORITY_SCHEMA = (
    "fre.aot.search-tag29-application-campaign-authority.v3"
)
MANIFEST_SCHEMA = "fre.aot.search-tag29-application-result-manifest.v3"
CORRECTNESS_HEADER_SCHEMA = (
    "fre.aot.search-tag29-application-correctness-header.v3"
)
CORRECTNESS_CASE_SCHEMA = (
    "fre.aot.search-tag29-application-correctness-case.v3"
)
CORRECTNESS_TRAILER_SCHEMA = (
    "fre.aot.search-tag29-application-correctness-trailer.v3"
)
HEADER_SCHEMA = "fre.aot.search-tag29-application-timing-header.v3"
CASE_SCHEMA = "fre.aot.search-tag29-application-timing-case.v3"
TRAILER_SCHEMA = "fre.aot.search-tag29-application-timing-trailer.v3"
OBJECT_EVIDENCE_SCHEMA = (
    "fre.aot.search-tag29-compiler-object-link-evidence.v1"
)
CAMPAIGN_DOMAIN = b"FRE-SEARCH-TAG29-APPLICATION-RESULT-CAMPAIGN\0\x03"
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
OBJECT_MANIFEST_SHA256 = (
    "2e6612dc25e1186e0dd78597f045a4ece6ecc8dafcc2270cacc445be8753aff4"
)
OBJECT_MANIFEST_PAYLOAD_SHA256 = (
    "5ffcb2ba1816a0bca3f5e4d74773e1cfff90288eb3c40d599256b380b3342dab"
)
DISPOSITIONS_SHA256 = (
    "69246c2df3cf3f408af2a88d0243e7a55fd3c0f8b55cdebc6ef396e12b61b2f4"
)
DISPOSITIONS_PAYLOAD_SHA256 = (
    "a25ed0def38578ea854be59e65c49b2b322b6a96c6d93d1749c48fb88b460227"
)
LINK_PROOF_CONTRACT_SHA256 = (
    "8119ee1d6449b7c4d29cc917d0611e2f05234bf34f4e1be8ec90a564995e72a9"
)
LINK_PROOF_VERIFIER_SHA256 = (
    "5e7e347f8796941fb7dfa654ad011400c20461d53784837d53a793e7756db38d"
)
CORE_SOURCE_SHA256 = (
    "0d2c8d9ee3a7e8bf470a25d3bc7a4d076f24bd51759fdcbb27920ee693c2c34d"
)
LINK_MANIFEST_VALIDATOR_SHA256 = (
    "8f1ac7057f666b06b053d2644f19ebe8969d9502092c27fb6ecf3cfa446e24fd"
)
FREEZE_VALIDATOR_SHA256 = (
    "8e844fe88c6c5c3456f60258f8b0b754c687775f38c4b647314f4195a9133ea5"
)
GLUE_SYMBOL_DOMAIN = b"FRE-SEARCH-TAG29-GLUE-SYMBOL\0\x01"
CASES = 154
REPETITIONS = 6
PAIRS_PER_HOST = CASES * REPETITIONS
MEASUREMENTS_PER_HOST = PAIRS_PER_HOST * 2
MINIMUM_NS = 400_000_000
STATIC_GATE = Fraction(4, 5)
NONTARGET_GATE = Fraction(21, 20)
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
    "fixture_backend_requirement",
    "fixture_backend_authority",
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
    "result_core_source_sha256",
    "freeze_validator_source_sha256",
    "link_manifest_validator_source_sha256",
    "object_manifest_sha256",
    "object_manifest_payload_sha256",
    "literal_dispositions_sha256",
    "literal_dispositions_payload_sha256",
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
COMMON_HEADER_FIELDS = {
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
    "literal_dispositions_sha256",
    "object_evidence_sha256",
    "fixture_manifest_sha256",
    "case_records",
}
HEADER_FIELDS = COMMON_HEADER_FIELDS | {
    "pairs",
    "measurements",
}
CORRECTNESS_HEADER_FIELDS = COMMON_HEADER_FIELDS
IDENTITY_FIELDS = {
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
}
CASE_FIELDS = IDENTITY_FIELDS | {
    "compiler",
    "precheck",
    "mapping",
    "timing_setup",
    "pairs",
}
CORRECTNESS_CASE_FIELDS = IDENTITY_FIELDS | {
    "compiler",
    "precheck",
    "mapping",
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
    "scalar_nonoverlapping_count",
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
    status = path.lstat()
    require(
        stat.S_ISREG(status.st_mode)
        and not path.is_symlink()
        and status.st_nlink == 1
        and 0 < status.st_size <= 2 * 1024 * 1024,
        "paired-result core is not one bounded regular file",
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
                status.st_dev,
                status.st_ino,
                status.st_mode,
                status.st_nlink,
                status.st_size,
            ),
            "paired-result core changed before open",
        )
        encoded = b""
        while len(encoded) < opened.st_size:
            block = os.read(descriptor, opened.st_size - len(encoded))
            require(bool(block), "paired-result core read was short")
            encoded += block
        after = os.fstat(descriptor)
        require(
            (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_nlink,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            == (
                opened.st_dev,
                opened.st_ino,
                opened.st_mode,
                opened.st_nlink,
                opened.st_size,
                opened.st_mtime_ns,
                opened.st_ctime_ns,
            ),
            "paired-result core changed while read",
        )
    finally:
        os.close(descriptor)
    digest = hashlib.sha256(encoded).hexdigest()
    require(
        digest == CORE_SOURCE_SHA256,
        "paired-result core source changed",
    )
    module = ModuleType("_fre_search_tag29_result_core")
    module.__file__ = str(path)
    exec(
        compile(encoded, str(path), "exec", dont_inherit=True),
        module.__dict__,
    )
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


def regular_file(path: Path, maximum: int = 1024 * 1024 * 1024) -> bytes:
    return CORE.regular_file(path, maximum)


def campaign_id(authority_file_sha256: str) -> str:
    require(is_hex(authority_file_sha256), "authority file SHA-256 changed")
    return sha256(
        CAMPAIGN_DOMAIN + bytes.fromhex(authority_file_sha256)
    )


def exact_uint(value: Any, expected: int) -> bool:
    return CORE.exact_uint(value, expected)


def exact_json(value: Any, expected: Any) -> bool:
    return CORE.exact_json(value, expected)


def flat_name(value: Any) -> bool:
    return CORE.flat_name(value)


held_directory = CORE.held_directory
open_regular_at = CORE.open_regular_at
read_regular_at = CORE.read_regular_at
require_unchanged_descriptor = CORE.require_unchanged_descriptor
canonical_line = CORE.canonical_line
bind_receipt = CORE.bind_receipt


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
    require(
        sha256(regular_file(validator, 2 * 1024 * 1024))
        == FREEZE_VALIDATOR_SHA256,
        "application freeze validator source changed",
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


def run_link_manifest_validator(repo: Path) -> None:
    validator = (
        repo
        / "research/aot/search-ripgrep-application-independent-v2/"
        "validate_link_manifests.py"
    )
    require(
        sha256(regular_file(validator, 2 * 1024 * 1024))
        == LINK_MANIFEST_VALIDATOR_SHA256,
        "application link-manifest validator source changed",
    )
    result = subprocess.run(
        [sys.executable, str(validator), str(repo)],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    require(
        result.returncode == 0 and not result.stderr,
        "application link-manifest validation failed",
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
    repo: Path,
    fixture_root: Path,
    fixture_fd: int | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if fixture_fd is None:
        with held_directory(fixture_root) as held_fd:
            return load_cases(repo, fixture_root, held_fd)
    freeze = json.loads(regular_file(repo / FREEZE_RELATIVE))
    inventory = json.loads(regular_file(repo / INVENTORY_RELATIVE))
    manifest_bytes, manifest_sha256 = read_regular_at(
        fixture_fd, "manifest.json", 16 * 1024 * 1024
    )
    require(
        sha256(regular_file(repo / FREEZE_RELATIVE)) == FREEZE_SHA256
        and freeze["payload_sha256"] == FREEZE_PAYLOAD_SHA256
        and sha256(regular_file(repo / INVENTORY_RELATIVE))
        == INVENTORY_SHA256
        and inventory["payload_sha256"] == INVENTORY_PAYLOAD_SHA256
        and manifest_sha256 == FIXTURE_MANIFEST_SHA256,
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
    authority: dict[str, Any],
    analyzer_sha256: str,
    core_sha256: str,
    freeze_validator_sha256: str,
    link_manifest_validator_sha256: str,
) -> None:
    expected_performance = {
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
    require(
        isinstance(authority, dict)
        and set(authority) == AUTHORITY_FIELDS
        and authority["campaign_name"] == "search-tag29-ripgrep-application-v3"
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
        and exact_uint(authority["case_count"], CASES)
        and authority["fixture_backend_requirement"]
        == "required-tag29-frozen-input"
        and authority["fixture_backend_authority"] is False
        and exact_json(
            authority["performance_authority"], expected_performance
        )
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
                "result_core_source_sha256",
                "freeze_validator_source_sha256",
                "link_manifest_validator_source_sha256",
                "object_manifest_sha256",
                "object_manifest_payload_sha256",
                "literal_dispositions_sha256",
                "literal_dispositions_payload_sha256",
            )
        )
        and runner["analyzer_source_sha256"] == analyzer_sha256
        and runner["result_core_source_sha256"] == core_sha256
        and runner["freeze_validator_source_sha256"]
        == freeze_validator_sha256
        and runner["link_manifest_validator_source_sha256"]
        == link_manifest_validator_sha256
        and runner["object_manifest_sha256"] == OBJECT_MANIFEST_SHA256
        and runner["object_manifest_payload_sha256"]
        == OBJECT_MANIFEST_PAYLOAD_SHA256
        and runner["literal_dispositions_sha256"] == DISPOSITIONS_SHA256
        and runner["literal_dispositions_payload_sha256"]
        == DISPOSITIONS_PAYLOAD_SHA256
        and exact_uint(runner["backend_tag"], 29)
        and runner["backend_version"] == "SEARCH_V16"
        and exact_uint(runner["candidate_policy"], 15)
        and runner["llvm"] is False
        and runner["ordinary_candidate_entry"]
        == "production-auto-route-portable-prefix-static-tail-or-fallback"
        and runner["baseline_entry"] == "forced-full-portable"
        and is_hex(runner["timed_function_identity_sha256"])
        and runner["timed_function_identity_sha256"] != "0" * 64,
        "application runner authority changed",
    )
    hosts = authority["hosts"]
    require(
        isinstance(hosts, list) and len(hosts) == len(HOSTS),
        "application authority host count changed",
    )
    attestations: set[str] = set()
    evidence_names: set[str] = set()
    for index, (host, expected) in enumerate(
        zip(hosts, HOSTS, strict=True)
    ):
        expected_evidence_name = (
            f"{expected['canonical_name']}."
            "application-compiler-object-link-evidence.json"
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
                CORE.is_uint(cpu, (1 << 31) - 1)
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
            and is_u64(host["object_evidence"]["bytes"])
            and host["object_evidence"]["bytes"] > 0
            and is_hex(host["object_evidence"]["sha256"])
            and is_hex(host["object_evidence"]["payload_sha256"]),
            f"application authority host {index} changed",
        )
        require(
            host["host_attestation_sha256"] not in attestations
            and expected_evidence_name not in evidence_names,
            "application hosts share an attestation or evidence path",
        )
        attestations.add(host["host_attestation_sha256"])
        evidence_names.add(expected_evidence_name)


def load_link_manifest(
    repo: Path,
    name: str,
    schema: str,
    expected_sha256: str,
    expected_payload_sha256: str,
) -> dict[str, Any]:
    path = (
        repo
        / "research/aot/search-ripgrep-application-independent-v2"
        / name
    )
    encoded = regular_file(path, 16 * 1024 * 1024)
    envelope = json.loads(encoded)
    require(
        sha256(encoded) == expected_sha256
        and isinstance(envelope, dict)
        and set(envelope) == {"schema", "payload_sha256", "payload"}
        and envelope["schema"] == schema
        and envelope["payload_sha256"] == expected_payload_sha256
        and canonical_sha(envelope["payload"])
        == expected_payload_sha256,
        f"application link manifest changed: {name}",
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
    repo: Path,
) -> dict[str, dict[str, Any]]:
    object_envelope = load_link_manifest(
        repo,
        "object-candidates-v1.json",
        "fre.aot.search-tag29-application-object-candidates.v1",
        OBJECT_MANIFEST_SHA256,
        OBJECT_MANIFEST_PAYLOAD_SHA256,
    )
    disposition_envelope = load_link_manifest(
        repo,
        "literal-dispositions-v1.json",
        "fre.aot.search-tag29-application-literal-dispositions.v1",
        DISPOSITIONS_SHA256,
        DISPOSITIONS_PAYLOAD_SHA256,
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
        authority_fd, receipt["path"], 16 * 1024 * 1024
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
        f"{expected_host['canonical_name']}: application object evidence changed",
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
        == OBJECT_MANIFEST_SHA256
        and payload["object_manifest_payload_sha256"]
        == OBJECT_MANIFEST_PAYLOAD_SHA256
        and payload["literal_dispositions_sha256"]
        == DISPOSITIONS_SHA256
        and payload["literal_dispositions_payload_sha256"]
        == DISPOSITIONS_PAYLOAD_SHA256
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
        and len(payload["objects"]) == len(candidates) == 5
        and isinstance(payload["refusals"], list)
        and len(payload["refusals"]) == len(expected_refusals) == 6,
        f"{expected_host['canonical_name']}: application evidence envelope changed",
    )
    injective: dict[str, set[str]] = {
        "compile_identity": set(),
        "compile_receipt_sha256": set(),
        "implementation_object_sha256": set(),
        "glue_object_sha256": set(),
        "symbols": set(),
        "proof_receipts": set(),
    }
    compiler_by_candidate: dict[str, dict[str, Any]] = {}
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
            f"{expected_host['canonical_name']}: application object {ordinal}",
        )
        for field in (
            "compile_identity",
            "compile_receipt_sha256",
            "implementation_object_sha256",
            "glue_object_sha256",
        ):
            require(
                mapping[field] not in injective[field],
                f"{expected_host['canonical_name']}: {field} not injective",
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
            f"{expected_host['canonical_name']}: symbols not injective",
        )
        injective["symbols"].update(symbols)
        expected_proofs = [
            (symbol, mapping["implementation_object_sha256"])
            for symbol in symbols[:3]
        ] + [(symbols[3], mapping["glue_object_sha256"])]
        validate_symbol_proofs(
            mapping["link_map_origins"],
            expected_proofs,
            f"{expected_host['canonical_name']}: origins {ordinal}",
            injective["proof_receipts"],
        )
        validate_symbol_proofs(
            mapping["final_image_retentions"],
            expected_proofs,
            f"{expected_host['canonical_name']}: retentions {ordinal}",
            injective["proof_receipts"],
        )
        compiler_by_candidate[candidate["semantic_candidate_sha256"]] = (
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
        compiler_by_candidate[
            disposition["semantic_candidate_sha256"]
        ] = compiler_case_record(mapping, "structural-refusal")
    require(
        len(compiler_by_candidate) == len(dispositions) == 11,
        f"{expected_host['canonical_name']}: evidence not bijective",
    )
    return compiler_by_candidate


def candidate_route(route_class: str) -> str:
    return {
        "tag29-static-tail": "portable-prefix-static-tail",
        "portable-prefix-return": "portable-prefix-return",
        "full-portable-fallback": "full-portable",
    }[route_class]


def candidate_static_invocations(route_class: str) -> int:
    return 1 if route_class == "tag29-static-tail" else 0


def validate_mapping(
    mapping: dict[str, Any],
    expected: dict[str, Any],
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
        and mapping["allocation_start_address"] > 0
        and exact_uint(
            mapping["allocation_bytes"], expected["fixture_bytes"] + 63
        )
        and mapping["allocation_bytes"] <= (1 << 40)
        and mapping["storage_pointer_address"]
        == mapping["allocation_start_address"]
        and exact_uint(
            mapping["storage_bytes"], expected["fixture_bytes"] + 63
        )
        and exact_uint(mapping["checked_bytes"], expected["fixture_bytes"])
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
        and exact_uint(
            mapping["actual_window_start_mod16"],
            expected["alignment_offset"],
        )
        and mapping["checked_pointer_address"] % 16
        == expected["alignment_offset"]
        and mapping["readable_left_bytes"] == mapping["start_offset"]
        and mapping["readable_right_bytes"]
        == 63 - mapping["start_offset"]
        and 32 <= mapping["readable_right_bytes"] <= 47
        and exact_uint(mapping["padding_sentinel"], expected["wrong_byte"])
        and mapping["padding_sentinel"] <= 255
        and mapping["padding_verified"] is True
        and mapping["checked_pointer_address"] + mapping["checked_bytes"]
        + mapping["readable_right_bytes"]
        == mapping["allocation_start_address"] + mapping["allocation_bytes"],
        "application physical alignment receipt changed",
    )
    bind_receipt(
        receipt_registry,
        mapping["allocation_receipt_sha256"],
        (*binding, "allocation"),
        "application physical allocation",
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
        and exact_uint(
            measurement["nonoverlapping_count"],
            expected["expected_count"],
        )
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
    compiler_by_candidate: dict[str, dict[str, Any]],
    receipt_registry: dict[str, str],
    canonical_host: str,
    allowed_logical_cpus: set[int],
    timed_function_identity_sha256: str,
) -> Fraction:
    require(
        isinstance(result, dict)
        and set(result) == CASE_FIELDS
        and result["schema"] == CASE_SCHEMA
        and result["campaign_id"] == expected_campaign_id
        and exact_uint(result["ordinal"], ordinal)
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
    expected_compiler = compiler_by_candidate[
        expected["candidate_sha256"]
    ]
    require(
        isinstance(compiler, dict)
        and set(compiler) == COMPILER_FIELDS
        and exact_json(compiler, expected_compiler)
        and compiler["disposition"] == expected["structural_class"]
        and exact_uint(compiler["backend_tag"], 29)
        and exact_uint(compiler["candidate_policy"], 15),
        f"application case {ordinal}: compiler disposition changed",
    )
    route = candidate_route(expected["route_class"])
    static_invocations = candidate_static_invocations(
        expected["route_class"]
    )
    precheck = result["precheck"]
    require(
        isinstance(precheck, dict)
        and set(precheck) == PRECHECK_FIELDS
        and exact_uint(
            precheck["scalar_nonoverlapping_count"],
            expected["expected_count"],
        )
        and exact_uint(
            precheck["portable_nonoverlapping_count"],
            expected["expected_count"],
        )
        and exact_uint(
            precheck["candidate_nonoverlapping_count"],
            expected["expected_count"],
        )
        and precheck["portable_route"] == "full-portable"
        and precheck["candidate_route"] == route
        and exact_uint(precheck["portable_static_invocations"], 0)
        and exact_uint(
            precheck["candidate_static_invocations"],
            static_invocations,
        ),
        f"application case {ordinal}: route or count precheck changed",
    )
    for field in ("scalar_span", "portable_span", "candidate_span"):
        validate_span(
            precheck[field],
            expected["expected_span"],
            f"application case {ordinal}: {field}",
        )
    case_binding = (
        canonical_host,
        "timing",
        str(ordinal),
        expected["case_id"],
    )
    validate_mapping(
        result["mapping"], expected, receipt_registry, case_binding
    )
    setup = result["timing_setup"]
    require(
        isinstance(setup, dict)
        and set(setup) == TIMING_SETUP_FIELDS
        and setup["fixture_materialization_outside_timing"] is True
        and setup["compile_link_adoption_outside_timing"] is True
        and setup["pilot_outside_timing"] is True
        and setup["route_instrumentation_outside_timing"] is True
        and setup["timed_function_identity_sha256"]
        == timed_function_identity_sha256,
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
            and pair["storage_pointer_address"]
            == result["mapping"]["storage_pointer_address"]
            and pair["checked_pointer_address"]
            == result["mapping"]["checked_pointer_address"]
            and CORE.is_uint(pair["logical_cpu"], (1 << 31) - 1)
            and pair["logical_cpu"] in allowed_logical_cpus
            and CORE.is_uint(pair["cpu_before"], (1 << 31) - 1)
            and CORE.is_uint(pair["cpu_after"], (1 << 31) - 1)
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
        bind_receipt(
            receipt_registry,
            pair["affinity_receipt_sha256"],
            (*case_binding, "affinity"),
            f"application case {ordinal}: affinity",
        )
        bind_receipt(
            receipt_registry,
            pair["admission_receipt_sha256"],
            (*case_binding, "admission"),
            f"application case {ordinal}: admission",
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
        if pair_index == 0:
            output_accumulator = pair["portable"]["output_accumulator"]
        require(
            pair["portable"]["output_accumulator"] == output_accumulator,
            f"application case {ordinal}: accumulator varies",
        )
        ratios.append(
            Fraction(
                pair["candidate"]["elapsed_ns"],
                pair["portable"]["elapsed_ns"],
            )
        )
    ratios.sort()
    return (ratios[2] + ratios[3]) / 2


def validate_correctness_case(
    result: dict[str, Any],
    expected: dict[str, Any],
    ordinal: int,
    expected_campaign_id: str,
    compiler_by_candidate: dict[str, dict[str, Any]],
    receipt_registry: dict[str, str],
    canonical_host: str,
) -> None:
    require(
        isinstance(result, dict)
        and set(result) == CORRECTNESS_CASE_FIELDS
        and result["schema"] == CORRECTNESS_CASE_SCHEMA
        and result["campaign_id"] == expected_campaign_id
        and exact_uint(result["ordinal"], ordinal)
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
        f"application correctness case {ordinal}: identity changed",
    )
    compiler = result["compiler"]
    require(
        isinstance(compiler, dict)
        and set(compiler) == COMPILER_FIELDS
        and exact_json(
            compiler,
            compiler_by_candidate[expected["candidate_sha256"]],
        )
        and compiler["disposition"] == expected["structural_class"],
        f"application correctness case {ordinal}: compiler changed",
    )
    route = candidate_route(expected["route_class"])
    static_invocations = candidate_static_invocations(
        expected["route_class"]
    )
    precheck = result["precheck"]
    require(
        isinstance(precheck, dict)
        and set(precheck) == PRECHECK_FIELDS
        and exact_uint(
            precheck["scalar_nonoverlapping_count"],
            expected["expected_count"],
        )
        and exact_uint(
            precheck["portable_nonoverlapping_count"],
            expected["expected_count"],
        )
        and exact_uint(
            precheck["candidate_nonoverlapping_count"],
            expected["expected_count"],
        )
        and precheck["portable_route"] == "full-portable"
        and precheck["candidate_route"] == route
        and exact_uint(precheck["portable_static_invocations"], 0)
        and exact_uint(
            precheck["candidate_static_invocations"],
            static_invocations,
        ),
        f"application correctness case {ordinal}: precheck changed",
    )
    for field in ("scalar_span", "portable_span", "candidate_span"):
        validate_span(
            precheck[field],
            expected["expected_span"],
            f"application correctness case {ordinal}: {field}",
        )
    validate_mapping(
        result["mapping"],
        expected,
        receipt_registry,
        (
            canonical_host,
            "correctness",
            str(ordinal),
            expected["case_id"],
        ),
    )


def validate_common_header(
    header: dict[str, Any],
    fields: set[str],
    schema: str,
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
        and header["object_manifest_sha256"] == OBJECT_MANIFEST_SHA256
        and header["literal_dispositions_sha256"]
        == DISPOSITIONS_SHA256
        and header["object_evidence_sha256"]
        == authority_host["object_evidence"]["sha256"]
        and header["fixture_manifest_sha256"]
        == FIXTURE_MANIFEST_SHA256
        and exact_uint(header["case_records"], CASES),
        f"{expected_host['canonical_name']}: application header changed",
    )


def parse_correctness_bundle(
    result_fd: int,
    bundle: dict[str, Any],
    authority_host: dict[str, Any],
    expected_host: dict[str, Any],
    authority: dict[str, Any],
    expected_campaign_id: str,
    expected_cases: list[dict[str, Any]],
    compiler_by_candidate: dict[str, dict[str, Any]],
    receipt_registry: dict[str, str],
) -> dict[str, int]:
    expected_name = (
        f"{expected_host['canonical_name']}.application-correctness.jsonl"
    )
    require(
        isinstance(bundle, dict)
        and set(bundle) == CORRECTNESS_BUNDLE_FIELDS
        and bundle["path"] == expected_name
        and is_u64(bundle["bytes"])
        and bundle["bytes"] > 0
        and is_hex(bundle["sha256"])
        and exact_uint(bundle["case_records"], CASES),
        f"{expected_host['canonical_name']}: correctness receipt changed",
    )
    source, before = open_regular_at(
        result_fd, expected_name, 128 * 1024 * 1024
    )
    file_digest = hashlib.sha256()
    prefix_digest = hashlib.sha256()
    total_bytes = 0
    routes: dict[str, int] = defaultdict(int)
    candidates: set[str] = set()
    try:
        header_line, header = canonical_line(
            source, 64 * 1024, "application correctness header changed"
        )
        file_digest.update(header_line)
        prefix_digest.update(header_line)
        total_bytes += len(header_line)
        validate_common_header(
            header,
            CORRECTNESS_HEADER_FIELDS,
            CORRECTNESS_HEADER_SCHEMA,
            authority_host,
            expected_host,
            authority,
            expected_campaign_id,
        )
        for ordinal, expected in enumerate(expected_cases):
            case_line, case = canonical_line(
                source,
                64 * 1024,
                f"application correctness line {ordinal} changed",
            )
            file_digest.update(case_line)
            prefix_digest.update(case_line)
            total_bytes += len(case_line)
            validate_correctness_case(
                case,
                expected,
                ordinal,
                expected_campaign_id,
                compiler_by_candidate,
                receipt_registry,
                expected_host["canonical_name"],
            )
            routes[expected["route_class"]] += 1
            candidates.add(expected["candidate_sha256"])
        trailer_line, trailer = canonical_line(
            source, 64 * 1024, "application correctness trailer changed"
        )
        file_digest.update(trailer_line)
        total_bytes += len(trailer_line)
        require(
            source.read(1) == b""
            and isinstance(trailer, dict)
            and set(trailer) == TRAILER_FIELDS
            and trailer["schema"] == CORRECTNESS_TRAILER_SCHEMA
            and trailer["campaign_id"] == expected_campaign_id
            and exact_uint(trailer["case_records"], CASES)
            and exact_uint(trailer["pairs"], 0)
            and exact_uint(trailer["measurements"], 0)
            and trailer["prefix_sha256"] == prefix_digest.hexdigest(),
            f"{expected_host['canonical_name']}: correctness trailer changed",
        )
        require_unchanged_descriptor(source, before, expected_name)
    finally:
        source.close()
    require(
        total_bytes == before.st_size
        and exact_uint(bundle["bytes"], total_bytes)
        and file_digest.hexdigest() == bundle["sha256"]
        and len(candidates) == 11,
        f"{expected_host['canonical_name']}: correctness completeness changed",
    )
    return dict(routes)


def parse_timing_bundle(
    result_fd: int,
    bundle: dict[str, Any],
    authority_host: dict[str, Any],
    expected_host: dict[str, Any],
    authority: dict[str, Any],
    expected_campaign_id: str,
    expected_cases: list[dict[str, Any]],
    compiler_by_candidate: dict[str, dict[str, Any]],
    receipt_registry: dict[str, str],
) -> tuple[list[Fraction], dict[str, list[Fraction]]]:
    expected_name = (
        f"{expected_host['canonical_name']}.application-timing.jsonl"
    )
    require(
        isinstance(bundle, dict)
        and set(bundle) == TIMING_BUNDLE_FIELDS
        and bundle["path"] == expected_name
        and is_u64(bundle["bytes"])
        and bundle["bytes"] > 0
        and is_hex(bundle["sha256"])
        and exact_uint(bundle["case_records"], CASES)
        and exact_uint(bundle["pairs"], PAIRS_PER_HOST)
        and exact_uint(bundle["measurements"], MEASUREMENTS_PER_HOST),
        f"{expected_host['canonical_name']}: timing receipt changed",
    )
    source, before = open_regular_at(
        result_fd, expected_name, 256 * 1024 * 1024
    )
    file_digest = hashlib.sha256()
    prefix_digest = hashlib.sha256()
    total_bytes = 0
    ratios: list[Fraction] = []
    groups: dict[str, list[Fraction]] = defaultdict(list)
    try:
        header_line, header = canonical_line(
            source, 64 * 1024, "application timing header changed"
        )
        file_digest.update(header_line)
        prefix_digest.update(header_line)
        total_bytes += len(header_line)
        validate_common_header(
            header,
            HEADER_FIELDS,
            HEADER_SCHEMA,
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
        for ordinal, expected in enumerate(expected_cases):
            case_line, result = canonical_line(
                source,
                256 * 1024,
                f"application timing line {ordinal} changed",
            )
            file_digest.update(case_line)
            prefix_digest.update(case_line)
            total_bytes += len(case_line)
            ratio = validate_case(
                result,
                expected,
                ordinal,
                expected_campaign_id,
                compiler_by_candidate,
                receipt_registry,
                expected_host["canonical_name"],
                set(authority_host["allowed_logical_cpus"]),
                authority["runner"]["timed_function_identity_sha256"],
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
        trailer_line, trailer = canonical_line(
            source, 64 * 1024, "application timing trailer changed"
        )
        file_digest.update(trailer_line)
        total_bytes += len(trailer_line)
        require(
            source.read(1) == b""
            and isinstance(trailer, dict)
            and set(trailer) == TRAILER_FIELDS
            and trailer["schema"] == TRAILER_SCHEMA
            and trailer["campaign_id"] == expected_campaign_id
            and exact_uint(trailer["case_records"], CASES)
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
        len(ratios) == CASES
        and total_bytes == before.st_size
        and exact_uint(bundle["bytes"], total_bytes)
        and file_digest.hexdigest() == bundle["sha256"],
        f"{expected_host['canonical_name']}: timing completeness changed",
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
        len(sys.argv) == 7,
        (
            "usage: analyze_qualification_results.py REPO RIPGREP_ROOT "
            "FIXTURE_ROOT CAMPAIGN_AUTHORITY "
            "EXPECTED_AUTHORITY_FILE_SHA256 RESULT_MANIFEST"
        ),
    )
    repo = Path(sys.argv[1]).resolve(strict=True)
    ripgrep_root = Path(sys.argv[2]).resolve(strict=True)
    fixture_root = Path(sys.argv[3]).resolve(strict=True)
    authority_path = Path(sys.argv[4])
    expected_authority_sha256 = sys.argv[5]
    manifest_path = Path(sys.argv[6])
    require(
        authority_path.name == "campaign-authority.json"
        and manifest_path.name == "result-manifest.json"
        and is_hex(expected_authority_sha256),
        "application authority or result manifest path changed",
    )
    authority_root = authority_path.parent.resolve(strict=True)
    result_root = manifest_path.parent.resolve(strict=True)
    run_freeze_validator(repo, ripgrep_root, fixture_root)
    run_link_manifest_validator(repo)
    with (
        held_directory(fixture_root) as fixture_fd,
        held_directory(authority_root) as authority_fd,
        held_directory(result_root) as result_fd,
    ):
        expected_cases, _ = load_cases(repo, fixture_root, fixture_fd)
        authority_bytes, authority_file_sha256 = read_regular_at(
            authority_fd, "campaign-authority.json", 16 * 1024 * 1024
        )
        require(
            authority_file_sha256 == expected_authority_sha256,
            (
                "application campaign authority does not match the "
                "pre-result expected SHA-256"
            ),
        )
        authority_envelope = json.loads(authority_bytes)
        require(
            isinstance(authority_envelope, dict)
            and set(authority_envelope) == AUTHORITY_ENVELOPE_FIELDS
            and authority_envelope["schema"] == AUTHORITY_SCHEMA
            and is_hex(authority_envelope["payload_sha256"])
            and canonical_sha(authority_envelope["payload"])
            == authority_envelope["payload_sha256"],
            "application campaign authority envelope changed",
        )
        authority = authority_envelope["payload"]
        analyzer_sha256 = sha256(regular_file(Path(__file__).resolve()))
        core_path = (
            Path(__file__).resolve().parents[1]
            / "search-tag29-topology-generalization-v1"
            / "analyze_qualification_results.py"
        )
        freeze_validator_path = Path(__file__).resolve().with_name(
            "validate_freeze.py"
        )
        link_manifest_validator_path = Path(__file__).resolve().with_name(
            "validate_link_manifests.py"
        )
        validate_authority(
            authority,
            analyzer_sha256,
            sha256(regular_file(core_path, 2 * 1024 * 1024)),
            sha256(
                regular_file(freeze_validator_path, 2 * 1024 * 1024)
            ),
            sha256(
                regular_file(
                    link_manifest_validator_path, 2 * 1024 * 1024
                )
            ),
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
            "application result manifest envelope changed",
        )
        hosts = manifest["hosts"]
        require(
            isinstance(hosts, list)
            and len(hosts) == len(HOSTS)
            and all(
                isinstance(host, dict)
                and set(host) == HOST_MANIFEST_FIELDS
                for host in hosts
            ),
            "application host manifest set changed",
        )
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
        receipt_registry: dict[str, str] = {}
        prepared_hosts = []
        for (
            manifest_host,
            authority_host,
            expected_host,
        ) in zip(hosts, authority["hosts"], HOSTS, strict=True):
            require(
                manifest_host["frozen_name"]
                == expected_host["frozen_name"]
                and manifest_host["canonical_name"]
                == expected_host["canonical_name"],
                "application result host membership changed",
            )
            compiler_by_candidate = load_object_evidence(
                authority_fd,
                authority_host,
                expected_host,
                repo,
            )
            correctness_routes = parse_correctness_bundle(
                result_fd,
                manifest_host["correctness_bundle"],
                authority_host,
                expected_host,
                authority,
                expected_campaign_id,
                expected_cases,
                compiler_by_candidate,
                receipt_registry,
            )
            require(
                correctness_routes
                == {
                    "tag29-static-tail": 75,
                    "portable-prefix-return": 10,
                    "full-portable-fallback": 69,
                },
                "application correctness route projection changed",
            )
            prepared_hosts.append(
                (
                    manifest_host,
                    authority_host,
                    expected_host,
                    compiler_by_candidate,
                    correctness_routes,
                )
            )
        # Performance data remains unread until both complete correctness
        # projections and both compiler/object/link evidence files pass.
        output_hosts: dict[str, Any] = {}
        all_pass = True
        for (
            manifest_host,
            authority_host,
            expected_host,
            compiler_by_candidate,
            correctness_routes,
        ) in prepared_hosts:
            ratios, groups = parse_timing_bundle(
                result_fd,
                manifest_host["timing_bundle"],
                authority_host,
                expected_host,
                authority,
                expected_campaign_id,
                expected_cases,
                compiler_by_candidate,
                receipt_registry,
            )
            failures = []
            for expected, ratio in zip(
                expected_cases, ratios, strict=True
            ):
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
                "full_correctness_rows": CASES,
                "full_correctness_routes": correctness_routes,
                "cells": len(ratios),
                "maximum_cell_ratio": rational_receipt(max(ratios)),
                "failing_cells": failures,
                "cell_gates": {
                    "tag29-static-tail": "strictly-less-than-4/5",
                    "portable-prefix-return": "at-most-21/20",
                    "full-portable-fallback": "at-most-21/20",
                },
                "pass": host_pass,
                "diagnostic_groups": group_output,
            }
    output = {
        "schema": "fre.aot.search-tag29-application-result-analysis.v3",
        "campaign_id": expected_campaign_id,
        "campaign_authority_sha256": authority_file_sha256,
        "freeze_sha256": FREEZE_SHA256,
        "freeze_payload_sha256": FREEZE_PAYLOAD_SHA256,
        "object_manifest_sha256": OBJECT_MANIFEST_SHA256,
        "literal_dispositions_sha256": DISPOSITIONS_SHA256,
        "hosts": output_hosts,
        "total_correctness_rows": CASES * len(HOSTS),
        "total_cells": CASES * len(HOSTS),
        "total_pairs": PAIRS_PER_HOST * len(HOSTS),
        "total_measurements": MEASUREMENTS_PER_HOST * len(HOSTS),
        "fixture_backend_requirement": "required-tag29-frozen-input",
        "fixture_backend_authority": False,
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
