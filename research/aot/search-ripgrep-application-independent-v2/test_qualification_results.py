#!/usr/bin/env python3
"""End-to-end and adversarial tests for the v3 application result gate."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def sha256(encoded: bytes) -> str:
    return hashlib.sha256(encoded).hexdigest()


def identity(label: str) -> str:
    return sha256(label.encode("ascii"))


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def canonical_line(value: Any) -> bytes:
    return canonical_bytes(value) + b"\n"


def pretty_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode("ascii")


def write_new(path: Path, encoded: bytes) -> None:
    with path.open("xb") as output:
        output.write(encoded)
        output.flush()


def envelope(schema: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": schema,
        "payload_sha256": sha256(canonical_bytes(payload)),
        "payload": payload,
    }


def load_analyzer() -> ModuleType:
    path = Path(__file__).resolve().with_name(
        "analyze_qualification_results.py"
    )
    specification = importlib.util.spec_from_file_location(
        "_fre_test_tag29_application_analyzer", path
    )
    require(
        specification is not None and specification.loader is not None,
        "cannot load application analyzer",
    )
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def load_link_inputs(
    analyzer: ModuleType, repo: Path
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    directory = (
        repo / "research/aot/search-ripgrep-application-independent-v2"
    )
    objects_raw = (directory / "object-candidates-v1.json").read_bytes()
    dispositions_raw = (
        directory / "literal-dispositions-v1.json"
    ).read_bytes()
    objects = json.loads(objects_raw)
    dispositions = json.loads(dispositions_raw)
    require(
        sha256(objects_raw) == analyzer.OBJECT_MANIFEST_SHA256
        and sha256(dispositions_raw) == analyzer.DISPOSITIONS_SHA256,
        "test link inputs changed",
    )
    return (
        objects["payload"]["candidates"],
        dispositions["payload"]["dispositions"],
    )


def host_authority(
    analyzer: ModuleType,
    expected_host: dict[str, Any],
    host_index: int,
) -> dict[str, Any]:
    return {
        "frozen_name": expected_host["frozen_name"],
        "canonical_name": expected_host["canonical_name"],
        "target_triple": expected_host["target_triple"],
        "features": expected_host["features"],
        "allowed_logical_cpus": [4 + host_index],
        "host_attestation_sha256": identity(f"host:{host_index}"),
        "runner_binary_sha256": identity(f"runner:{host_index}"),
        "linked_image_sha256": identity(f"image:{host_index}"),
        "linked_image_platform_identity_sha256": identity(
            f"platform-image:{host_index}"
        ),
        "build_closure_sha256": identity(f"build:{host_index}"),
        "toolchain_closure_sha256": identity(f"toolchain:{host_index}"),
    }


def build_object_evidence(
    analyzer: ModuleType,
    directory: Path,
    host: dict[str, Any],
    expected_host: dict[str, Any],
    host_index: int,
    candidates: list[dict[str, Any]],
    dispositions: list[dict[str, Any]],
    mutation: str,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    objects = []
    compiler_by_candidate: dict[str, dict[str, Any]] = {}
    for ordinal, candidate in enumerate(candidates):
        semantic = candidate["semantic_candidate_sha256"]
        compile_identity = identity(
            f"compile-identity:{host_index}:{semantic}"
        )
        implementation_sha = identity(
            f"implementation:{host_index}:{semantic}"
        )
        glue_sha = identity(f"glue:{host_index}:{semantic}")
        symbols = {
            "entry": f"fre_aot_search_entry_v1_{compile_identity}",
            "payload": f"fre_aot_payload_v1_{compile_identity}",
            "metadata": f"fre_aot_metadata_v1_{compile_identity}",
        }
        glue_identity = (
            identity("wrong-evidence-glue")
            if mutation == "wrong-evidence-symbol" and ordinal == 0
            else compile_identity
        )
        glue_symbol = f"fre_aot_search_span_glue_v1_{glue_identity}"
        proof_symbols = [
            (symbols["entry"], implementation_sha),
            (symbols["payload"], implementation_sha),
            (symbols["metadata"], implementation_sha),
            (glue_symbol, glue_sha),
        ]
        mapping = {
            "ordinal": ordinal,
            "literal_sha256": candidate["literal_sha256"],
            "semantic_candidate_sha256": semantic,
            "compile_identity": compile_identity,
            "compile_receipt_sha256": identity(
                f"compile-receipt:{host_index}:{semantic}"
            ),
            "implementation_object_sha256": implementation_sha,
            "glue_object_sha256": glue_sha,
            "implementation_symbols": symbols,
            "glue_symbol": glue_symbol,
            "glue_symbol_identity_sha256": sha256(
                analyzer.GLUE_SYMBOL_DOMAIN + glue_symbol.encode("ascii")
            ),
            "glue_relocation_targets": [
                symbols["entry"],
                symbols["payload"],
                symbols["metadata"],
            ],
            "implementation_linker_input_multiplicity": 1,
            "glue_linker_input_multiplicity": 1,
            "link_map_origins": [
                {
                    "symbol": symbol,
                    "object_sha256": object_sha,
                    "receipt_sha256": identity(
                        f"origin:{host_index}:{ordinal}:{role}"
                    ),
                }
                for role, (symbol, object_sha) in enumerate(proof_symbols)
            ],
            "final_image_retentions": [
                {
                    "symbol": symbol,
                    "object_sha256": object_sha,
                    "receipt_sha256": identity(
                        f"retention:{host_index}:{ordinal}:{role}"
                    ),
                }
                for role, (symbol, object_sha) in enumerate(proof_symbols)
            ],
        }
        objects.append(mapping)
        compiler_by_candidate[semantic] = analyzer.compiler_case_record(
            mapping, "tag29-object"
        )
    refusals = []
    expected_refusals = [
        row
        for row in dispositions
        if row["expected_compiler_disposition"] == "structural-refusal"
    ]
    for ordinal, disposition in enumerate(expected_refusals):
        semantic = disposition["semantic_candidate_sha256"]
        mapping = {
            "ordinal": ordinal,
            "literal_sha256": disposition["literal_sha256"],
            "semantic_candidate_sha256": semantic,
            "disposition": "structural-refusal",
            "compile_receipt_sha256": identity(
                f"refusal:{host_index}:{semantic}"
            ),
        }
        refusals.append(mapping)
        compiler_by_candidate[semantic] = analyzer.compiler_case_record(
            mapping, "structural-refusal"
        )
    payload = {
        "frozen_host": expected_host["frozen_name"],
        "canonical_host": expected_host["canonical_name"],
        "target_triple": expected_host["target_triple"],
        "features": expected_host["features"],
        "object_manifest_sha256": analyzer.OBJECT_MANIFEST_SHA256,
        "object_manifest_payload_sha256": (
            analyzer.OBJECT_MANIFEST_PAYLOAD_SHA256
        ),
        "literal_dispositions_sha256": analyzer.DISPOSITIONS_SHA256,
        "literal_dispositions_payload_sha256": (
            analyzer.DISPOSITIONS_PAYLOAD_SHA256
        ),
        "verifier_source_sha256": analyzer.LINK_PROOF_VERIFIER_SHA256,
        "verifier_contract_sha256": analyzer.LINK_PROOF_CONTRACT_SHA256,
        "external_build_receipt_sha256": identity(
            f"external-build:{host_index}"
        ),
        "external_link_receipt_sha256": identity(
            f"external-link:{host_index}"
        ),
        "link_map_sha256": identity(f"link-map:{host_index}"),
        "linked_image_sha256": host["linked_image_sha256"],
        "objects": objects,
        "refusals": refusals,
    }
    evidence = envelope(analyzer.OBJECT_EVIDENCE_SCHEMA, payload)
    encoded = pretty_bytes(evidence)
    name = (
        f"{expected_host['canonical_name']}."
        "application-compiler-object-link-evidence.json"
    )
    write_new(directory / name, encoded)
    return (
        {
            "path": name,
            "bytes": len(encoded),
            "sha256": sha256(encoded),
            "payload_sha256": evidence["payload_sha256"],
        },
        compiler_by_candidate,
    )


def identity_fields(
    analyzer: ModuleType,
    schema: str,
    campaign_id: str,
    expected: dict[str, Any],
    ordinal: int,
) -> dict[str, Any]:
    return {
        "schema": schema,
        "campaign_id": campaign_id,
        "ordinal": ordinal,
        **{
            field: expected[field]
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
        },
    }


def precheck(
    analyzer: ModuleType, expected: dict[str, Any]
) -> dict[str, Any]:
    route = analyzer.candidate_route(expected["route_class"])
    return {
        "scalar_span": expected["expected_span"],
        "portable_span": expected["expected_span"],
        "candidate_span": expected["expected_span"],
        "scalar_nonoverlapping_count": expected["expected_count"],
        "portable_nonoverlapping_count": expected["expected_count"],
        "candidate_nonoverlapping_count": expected["expected_count"],
        "portable_route": "full-portable",
        "candidate_route": route,
        "portable_static_invocations": 0,
        "candidate_static_invocations": (
            analyzer.candidate_static_invocations(expected["route_class"])
        ),
    }


def mapping(
    expected: dict[str, Any],
    host_index: int,
    ordinal: int,
    phase: str,
) -> dict[str, Any]:
    phase_offset = 0 if phase == "correctness" else 0x1000_0000
    allocation_start = (
        0x10_0000_0000
        + host_index * 0x10_0000_0000
        + phase_offset
        + ordinal * 0x10_0000
    )
    start = 16 + (
        expected["alignment_offset"] - ((allocation_start + 16) % 16)
    ) % 16
    checked = allocation_start + start
    return {
        "allocation_start_address": allocation_start,
        "allocation_bytes": expected["fixture_bytes"] + 63,
        "storage_pointer_address": allocation_start,
        "checked_pointer_address": checked,
        "storage_bytes": expected["fixture_bytes"] + 63,
        "checked_bytes": expected["fixture_bytes"],
        "start_offset": start,
        "actual_window_start_mod16": checked % 16,
        "readable_left_bytes": start,
        "readable_right_bytes": 63 - start,
        "padding_sentinel": expected["wrong_byte"],
        "padding_verified": True,
        "allocation_receipt_sha256": identity(
            f"allocation:{host_index}:{phase}:{ordinal}"
        ),
    }


def correctness_case(
    analyzer: ModuleType,
    campaign_id: str,
    expected: dict[str, Any],
    ordinal: int,
    host_index: int,
    compiler_by_candidate: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    return {
        **identity_fields(
            analyzer,
            analyzer.CORRECTNESS_CASE_SCHEMA,
            campaign_id,
            expected,
            ordinal,
        ),
        "compiler": compiler_by_candidate[expected["candidate_sha256"]],
        "precheck": precheck(analyzer, expected),
        "mapping": mapping(expected, host_index, ordinal, "correctness"),
    }


def elapsed(
    route_class: str,
    mode: str,
    first_of_class: bool,
) -> tuple[int, int]:
    portable = 600_000_000
    if route_class == "tag29-static-tail":
        candidate = 450_000_000
        if mode == "static-boundary" and first_of_class:
            candidate = 480_000_000
    else:
        candidate = 630_000_000
        if (
            mode == "fallback-over"
            and route_class == "full-portable-fallback"
            and first_of_class
        ):
            candidate += 1
    return portable, candidate


def timing_case(
    analyzer: ModuleType,
    campaign_id: str,
    expected: dict[str, Any],
    ordinal: int,
    host_index: int,
    authority: dict[str, Any],
    compiler_by_candidate: dict[str, dict[str, Any]],
    mode: str,
    first_of_class: bool,
) -> dict[str, Any]:
    physical = mapping(expected, host_index, ordinal, "timing")
    cpu = authority["hosts"][host_index]["allowed_logical_cpus"][0]
    iteration_count = 2000 + ordinal % 11
    accumulator = (
        int(expected["case_id"][:16], 16) ^ iteration_count
    ) & ((1 << 64) - 1)
    portable_ns, candidate_ns = elapsed(
        expected["route_class"], mode, first_of_class
    )
    route = analyzer.candidate_route(expected["route_class"])
    affinity = identity(f"affinity:{host_index}:{ordinal}")
    admission = identity(f"admission:{host_index}:{ordinal}")
    pairs = []
    for pair_index in range(analyzer.REPETITIONS):
        pairs.append(
            {
                "pair_index": pair_index,
                "first_variant": (
                    "portable" if pair_index % 2 == 0 else "candidate"
                ),
                "iteration_count": iteration_count,
                "storage_pointer_address": physical[
                    "storage_pointer_address"
                ],
                "checked_pointer_address": physical[
                    "checked_pointer_address"
                ],
                "logical_cpu": cpu,
                "cpu_before": cpu,
                "cpu_after": cpu,
                "affinity_receipt_sha256": affinity,
                "admission_receipt_sha256": admission,
                "portable": {
                    "elapsed_ns": portable_ns,
                    "output_accumulator": accumulator,
                    "last_span": expected["expected_span"],
                    "nonoverlapping_count": expected["expected_count"],
                    "route": "full-portable",
                },
                "candidate": {
                    "elapsed_ns": candidate_ns,
                    "output_accumulator": accumulator,
                    "last_span": expected["expected_span"],
                    "nonoverlapping_count": expected["expected_count"],
                    "route": route,
                },
            }
        )
    return {
        **identity_fields(
            analyzer,
            analyzer.CASE_SCHEMA,
            campaign_id,
            expected,
            ordinal,
        ),
        "compiler": compiler_by_candidate[expected["candidate_sha256"]],
        "precheck": precheck(analyzer, expected),
        "mapping": physical,
        "timing_setup": {
            "fixture_materialization_outside_timing": True,
            "compile_link_adoption_outside_timing": True,
            "pilot_outside_timing": True,
            "route_instrumentation_outside_timing": True,
            "timed_function_identity_sha256": authority["runner"][
                "timed_function_identity_sha256"
            ],
        },
        "pairs": pairs,
    }


def common_header(
    analyzer: ModuleType,
    schema: str,
    campaign_id: str,
    authority: dict[str, Any],
    authority_host: dict[str, Any],
    expected_host: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema": schema,
        "campaign_id": campaign_id,
        "frozen_host": expected_host["frozen_name"],
        "canonical_host": expected_host["canonical_name"],
        "target_triple": expected_host["target_triple"],
        "features": expected_host["features"],
        **{
            field: authority_host[field]
            for field in (
                "host_attestation_sha256",
                "runner_binary_sha256",
                "linked_image_sha256",
                "linked_image_platform_identity_sha256",
                "build_closure_sha256",
                "toolchain_closure_sha256",
            )
        },
        "runner_source_commit": authority["runner"]["source_commit"],
        "runner_source_set_sha256": authority["runner"][
            "source_set_sha256"
        ],
        "object_manifest_sha256": analyzer.OBJECT_MANIFEST_SHA256,
        "literal_dispositions_sha256": analyzer.DISPOSITIONS_SHA256,
        "object_evidence_sha256": authority_host["object_evidence"][
            "sha256"
        ],
        "fixture_manifest_sha256": analyzer.FIXTURE_MANIFEST_SHA256,
        "case_records": analyzer.CASES,
    }


def build_correctness_bundle(
    analyzer: ModuleType,
    directory: Path,
    authority: dict[str, Any],
    campaign_id: str,
    cases: list[dict[str, Any]],
    expected_host: dict[str, Any],
    host_index: int,
    compiler_by_candidate: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    authority_host = authority["hosts"][host_index]
    prefix = bytearray(
        canonical_line(
            common_header(
                analyzer,
                analyzer.CORRECTNESS_HEADER_SCHEMA,
                campaign_id,
                authority,
                authority_host,
                expected_host,
            )
        )
    )
    for ordinal, expected in enumerate(cases):
        prefix.extend(
            canonical_line(
                correctness_case(
                    analyzer,
                    campaign_id,
                    expected,
                    ordinal,
                    host_index,
                    compiler_by_candidate,
                )
            )
        )
    trailer = {
        "schema": analyzer.CORRECTNESS_TRAILER_SCHEMA,
        "campaign_id": campaign_id,
        "case_records": analyzer.CASES,
        "pairs": 0,
        "measurements": 0,
        "prefix_sha256": sha256(prefix),
    }
    encoded = bytes(prefix) + canonical_line(trailer)
    name = (
        f"{expected_host['canonical_name']}.application-correctness.jsonl"
    )
    write_new(directory / name, encoded)
    return {
        "path": name,
        "bytes": len(encoded),
        "sha256": sha256(encoded),
        "case_records": analyzer.CASES,
    }


def build_timing_bundle(
    analyzer: ModuleType,
    directory: Path,
    authority: dict[str, Any],
    campaign_id: str,
    cases: list[dict[str, Any]],
    expected_host: dict[str, Any],
    host_index: int,
    compiler_by_candidate: dict[str, dict[str, Any]],
    mode: str,
) -> dict[str, Any]:
    authority_host = authority["hosts"][host_index]
    header = common_header(
        analyzer,
        analyzer.HEADER_SCHEMA,
        campaign_id,
        authority,
        authority_host,
        expected_host,
    )
    header["pairs"] = analyzer.PAIRS_PER_HOST
    header["measurements"] = analyzer.MEASUREMENTS_PER_HOST
    prefix = bytearray(canonical_line(header))
    seen_classes: set[str] = set()
    for ordinal, expected in enumerate(cases):
        first = expected["route_class"] not in seen_classes
        seen_classes.add(expected["route_class"])
        prefix.extend(
            canonical_line(
                timing_case(
                    analyzer,
                    campaign_id,
                    expected,
                    ordinal,
                    host_index,
                    authority,
                    compiler_by_candidate,
                    mode,
                    first,
                )
            )
        )
    trailer = {
        "schema": analyzer.TRAILER_SCHEMA,
        "campaign_id": campaign_id,
        "case_records": analyzer.CASES,
        "pairs": analyzer.PAIRS_PER_HOST,
        "measurements": analyzer.MEASUREMENTS_PER_HOST,
        "prefix_sha256": sha256(prefix),
    }
    encoded = bytes(prefix) + canonical_line(trailer)
    name = f"{expected_host['canonical_name']}.application-timing.jsonl"
    write_new(directory / name, encoded)
    return {
        "path": name,
        "bytes": len(encoded),
        "sha256": sha256(encoded),
        "case_records": analyzer.CASES,
        "pairs": analyzer.PAIRS_PER_HOST,
        "measurements": analyzer.MEASUREMENTS_PER_HOST,
    }


def performance_authority(analyzer: ModuleType) -> dict[str, Any]:
    return {
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
        "minimum_elapsed_ns_each_variant": analyzer.MINIMUM_NS,
        "repetitions": analyzer.REPETITIONS,
        "aggregate_rescue_permitted": False,
    }


def build_campaign(
    analyzer: ModuleType,
    repo: Path,
    fixture_root: Path,
    directory: Path,
    mode: str,
    mutation: str = "none",
) -> tuple[Path, str, Path, dict[str, Any]]:
    cases, _ = analyzer.load_cases(repo, fixture_root)
    candidates, dispositions = load_link_inputs(analyzer, repo)
    hosts = [
        host_authority(analyzer, expected_host, host_index)
        for host_index, expected_host in enumerate(analyzer.HOSTS)
    ]
    compiler_maps = []
    for host_index, (host, expected_host) in enumerate(
        zip(hosts, analyzer.HOSTS, strict=True)
    ):
        evidence_receipt, compiler_map = build_object_evidence(
            analyzer,
            directory,
            host,
            expected_host,
            host_index,
            candidates,
            dispositions,
            mutation,
        )
        host["object_evidence"] = evidence_receipt
        compiler_maps.append(compiler_map)
    analyzer_sha = sha256(Path(analyzer.__file__).resolve().read_bytes())
    authority = {
        "campaign_name": "search-tag29-ripgrep-application-v3",
        "freeze_sha256": analyzer.FREEZE_SHA256,
        "freeze_payload_sha256": analyzer.FREEZE_PAYLOAD_SHA256,
        "inventory_sha256": analyzer.INVENTORY_SHA256,
        "inventory_payload_sha256": analyzer.INVENTORY_PAYLOAD_SHA256,
        "fixture_manifest_sha256": analyzer.FIXTURE_MANIFEST_SHA256,
        "fixture_manifest_payload_sha256": (
            analyzer.FIXTURE_MANIFEST_PAYLOAD_SHA256
        ),
        "upstream_commit": analyzer.UPSTREAM_COMMIT,
        "upstream_tree": analyzer.UPSTREAM_TREE,
        "case_count": analyzer.CASES,
        "runner": {
            "source_commit": identity("commit")[:40],
            "source_set_sha256": identity("source-set"),
            "controller_source_sha256": identity("controller"),
            "sealer_source_sha256": identity("sealer"),
            "analyzer_source_sha256": analyzer_sha,
            "result_core_source_sha256": analyzer.CORE_SOURCE_SHA256,
            "freeze_validator_source_sha256": (
                analyzer.FREEZE_VALIDATOR_SHA256
            ),
            "link_manifest_validator_source_sha256": (
                analyzer.LINK_MANIFEST_VALIDATOR_SHA256
            ),
            "object_manifest_sha256": analyzer.OBJECT_MANIFEST_SHA256,
            "object_manifest_payload_sha256": (
                analyzer.OBJECT_MANIFEST_PAYLOAD_SHA256
            ),
            "literal_dispositions_sha256": analyzer.DISPOSITIONS_SHA256,
            "literal_dispositions_payload_sha256": (
                analyzer.DISPOSITIONS_PAYLOAD_SHA256
            ),
            "backend_tag": 29,
            "backend_version": "SEARCH_V16",
            "candidate_policy": 15,
            "llvm": False,
            "ordinary_candidate_entry": (
                "production-auto-route-portable-prefix-static-tail-or-fallback"
            ),
            "baseline_entry": "forced-full-portable",
            "timed_function_identity_sha256": identity(
                "ordinary-production-application-auto-route-v3"
            ),
        },
        "hosts": hosts,
        "fixture_backend_requirement": "required-tag29-frozen-input",
        "fixture_backend_authority": False,
        "performance_authority": performance_authority(analyzer),
        "rebar_inputs": [],
        "benchmark_result_inputs": [],
        "network": False,
        "result_derived_exclusions": False,
    }
    if mutation == "wrong-backend":
        authority["runner"]["backend_tag"] = 28
    elif mutation == "missing-backend":
        del authority["runner"]["backend_tag"]
    elif mutation == "fixture-label-authority":
        authority["fixture_backend_authority"] = True
    authority_envelope = envelope(analyzer.AUTHORITY_SCHEMA, authority)
    authority_bytes = pretty_bytes(authority_envelope)
    authority_path = directory / "campaign-authority.json"
    write_new(authority_path, authority_bytes)
    authority_sha = sha256(authority_bytes)
    campaign_id = analyzer.campaign_id(authority_sha)
    manifest_hosts = []
    for host_index, expected_host in enumerate(analyzer.HOSTS):
        manifest_hosts.append(
            {
                "frozen_name": expected_host["frozen_name"],
                "canonical_name": expected_host["canonical_name"],
                "correctness_bundle": build_correctness_bundle(
                    analyzer,
                    directory,
                    authority,
                    campaign_id,
                    cases,
                    expected_host,
                    host_index,
                    compiler_maps[host_index],
                ),
                "timing_bundle": build_timing_bundle(
                    analyzer,
                    directory,
                    authority,
                    campaign_id,
                    cases,
                    expected_host,
                    host_index,
                    compiler_maps[host_index],
                    mode,
                ),
            }
        )
    manifest = {
        "schema": analyzer.MANIFEST_SCHEMA,
        "campaign_id": campaign_id,
        "campaign_authority_sha256": authority_sha,
        "hosts": manifest_hosts,
    }
    manifest_path = directory / "result-manifest.json"
    write_new(manifest_path, pretty_bytes(manifest))
    return authority_path, authority_sha, manifest_path, authority


def run_analyzer(
    analyzer: ModuleType,
    repo: Path,
    ripgrep_root: Path,
    fixture_root: Path,
    authority_path: Path,
    authority_sha: str,
    manifest_path: Path,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            sys.executable,
            str(Path(analyzer.__file__).resolve()),
            str(repo),
            str(ripgrep_root),
            str(fixture_root),
            str(authority_path),
            authority_sha,
            str(manifest_path),
        ],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def main() -> None:
    require(
        len(sys.argv) == 4,
        "usage: test_qualification_results.py REPO RIPGREP_ROOT FIXTURE_ROOT",
    )
    analyzer = load_analyzer()
    repo = Path(sys.argv[1]).resolve(strict=True)
    ripgrep_root = Path(sys.argv[2]).resolve(strict=True)
    fixture_root = Path(sys.argv[3]).resolve(strict=True)
    for mode, expected_code in (
        ("pass", 0),
        ("static-boundary", 1),
        ("fallback-over", 1),
    ):
        with tempfile.TemporaryDirectory(
            prefix=f"fre-tag29-app-v3-{mode}-"
        ) as name:
            authority_path, authority_sha, manifest_path, _ = (
                build_campaign(
                    analyzer,
                    repo,
                    fixture_root,
                    Path(name),
                    mode,
                )
            )
            result = run_analyzer(
                analyzer,
                repo,
                ripgrep_root,
                fixture_root,
                authority_path,
                authority_sha,
                manifest_path,
            )
            require(
                result.returncode == expected_code
                and not result.stderr
                and json.loads(result.stdout)["pass"]
                is (expected_code == 0),
                f"application analyzer gate mode failed: {mode}",
            )
            manifest = json.loads(manifest_path.read_bytes())
            require(
                set(manifest)
                == {
                    "schema",
                    "campaign_id",
                    "campaign_authority_sha256",
                    "hosts",
                },
                "result manifest can carry campaign authority",
            )
    for mutation in (
        "wrong-backend",
        "missing-backend",
        "fixture-label-authority",
        "wrong-evidence-symbol",
    ):
        with tempfile.TemporaryDirectory(
            prefix=f"fre-tag29-app-v3-refusal-{mutation}-"
        ) as name:
            authority_path, authority_sha, manifest_path, authority = (
                build_campaign(
                    analyzer,
                    repo,
                    fixture_root,
                    Path(name),
                    "pass",
                    mutation,
                )
            )
            require(
                authority["fixture_backend_requirement"]
                == "required-tag29-frozen-input",
                "adversarial fixture label changed",
            )
            result = run_analyzer(
                analyzer,
                repo,
                ripgrep_root,
                fixture_root,
                authority_path,
                authority_sha,
                manifest_path,
            )
            require(
                result.returncode == 1
                and bool(result.stderr)
                and not result.stdout,
                f"application analyzer accepted structural mutation: {mutation}",
            )
    with tempfile.TemporaryDirectory(
        prefix="fre-tag29-app-v3-correctness-first-"
    ) as name:
        directory = Path(name)
        authority_path, authority_sha, manifest_path, _ = build_campaign(
            analyzer, repo, fixture_root, directory, "pass"
        )
        manifest = json.loads(manifest_path.read_bytes())
        correctness_path = (
            directory
            / manifest["hosts"][0]["correctness_bundle"]["path"]
        )
        with correctness_path.open("ab") as output:
            output.write(b"{}\n")
        for host in manifest["hosts"]:
            (
                directory / host["timing_bundle"]["path"]
            ).unlink()
        result = run_analyzer(
            analyzer,
            repo,
            ripgrep_root,
            fixture_root,
            authority_path,
            authority_sha,
            manifest_path,
        )
        require(
            result.returncode == 1
            and b"correctness" in result.stderr
            and b"timing" not in result.stderr,
            "application analyzer consumed timing before both correctness bundles",
        )
    with tempfile.TemporaryDirectory(
        prefix="fre-tag29-app-v3-result-authority-"
    ) as name:
        directory = Path(name)
        authority_path, authority_sha, manifest_path, authority = (
            build_campaign(
                analyzer, repo, fixture_root, directory, "pass"
            )
        )
        wrong_expected = run_analyzer(
            analyzer,
            repo,
            ripgrep_root,
            fixture_root,
            authority_path,
            identity("wrong-authority-file"),
            manifest_path,
        )
        require(
            wrong_expected.returncode == 1
            and b"pre-result expected SHA-256" in wrong_expected.stderr,
            "application analyzer accepted an unpinned authority file",
        )
        manifest = json.loads(manifest_path.read_bytes())
        manifest["authority"] = authority
        manifest_path.write_bytes(pretty_bytes(manifest))
        embedded = run_analyzer(
            analyzer,
            repo,
            ripgrep_root,
            fixture_root,
            authority_path,
            authority_sha,
            manifest_path,
        )
        require(
            embedded.returncode == 1
            and b"result manifest envelope changed" in embedded.stderr,
            "application result manifest carried authority",
        )
    print(
        "application-qualification-tools-v3=pass "
        "correctness_rows=308 cells=308 pairs=1848 measurements=3696 "
        "static-boundary-4/5=rejected nontarget-boundary-21/20=accepted "
        "nontarget-over-21/20=rejected "
        "b201-label-wrong-or-unpinned-backend=rejected "
        "fixture-label-authority=rejected malformed-object-evidence=rejected "
        "correctness-before-timing=proved result-authority-injection=rejected"
    )


if __name__ == "__main__":
    try:
        main()
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        RuntimeError,
        json.JSONDecodeError,
    ) as error:
        print(
            f"search-tag29-application-tools-test: {error}",
            file=sys.stderr,
        )
        raise SystemExit(1)
