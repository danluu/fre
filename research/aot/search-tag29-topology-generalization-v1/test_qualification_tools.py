#!/usr/bin/env python3
"""End-to-end and adversarial tests for the v2 qualification contract."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any, BinaryIO


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def sha256(encoded: bytes) -> str:
    return hashlib.sha256(encoded).hexdigest()


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def line(value: Any) -> bytes:
    return canonical_bytes(value) + b"\n"


def identity(label: str) -> str:
    return sha256(label.encode())


def load_analyzer() -> ModuleType:
    path = Path(__file__).resolve().with_name(
        "analyze_qualification_results.py"
    )
    specification = importlib.util.spec_from_file_location(
        "_fre_test_tag29_analyzer", path
    )
    require(
        specification is not None and specification.loader is not None,
        "cannot load analyzer",
    )
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def write_new(path: Path, encoded: bytes) -> None:
    with path.open("xb") as output:
        output.write(encoded)
        output.flush()


def json_envelope(schema: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": schema,
        "payload_sha256": sha256(canonical_bytes(payload)),
        "payload": payload,
    }


def common_header(
    analyzer: ModuleType,
    schema: str,
    campaign_id: str,
    authority: dict[str, Any],
    authority_host: dict[str, Any],
    expected_host: dict[str, Any],
    case_records: int,
) -> dict[str, Any]:
    return {
        "schema": schema,
        "campaign_id": campaign_id,
        "frozen_host": expected_host["frozen_name"],
        "canonical_host": expected_host["canonical_name"],
        "target_triple": expected_host["target_triple"],
        "features": expected_host["features"],
        "host_attestation_sha256": authority_host[
            "host_attestation_sha256"
        ],
        "runner_binary_sha256": authority_host["runner_binary_sha256"],
        "linked_image_sha256": authority_host["linked_image_sha256"],
        "linked_image_platform_identity_sha256": authority_host[
            "linked_image_platform_identity_sha256"
        ],
        "build_closure_sha256": authority_host["build_closure_sha256"],
        "toolchain_closure_sha256": authority_host[
            "toolchain_closure_sha256"
        ],
        "runner_source_commit": authority["runner"]["source_commit"],
        "runner_source_set_sha256": authority["runner"][
            "source_set_sha256"
        ],
        "object_manifest_sha256": authority["runner"][
            "object_manifest_sha256"
        ],
        "object_evidence_sha256": authority_host["object_evidence"][
            "sha256"
        ],
        "qualification_plan_sha256": authority[
            "qualification_plan_sha256"
        ],
        "case_records": case_records,
    }


def mapping_record(
    analyzer: ModuleType,
    row: dict[str, Any],
    ordinal: int,
    host_index: int,
    phase: str,
) -> dict[str, Any]:
    page_size = 4096
    if row["right_guarded"]:
        guard = 0x4_0000_0000 + ordinal * 0x20_0000
        checked = guard - row["window_bytes"]
        fixture = checked - row["logical_prefix_bytes"]
        allocation_start = checked - 32
        allocation_end = guard + page_size
        return {
            "allocation_start_address": allocation_start,
            "allocation_bytes": allocation_end - allocation_start,
            "fixture_pointer_address": fixture,
            "checked_pointer_address": checked,
            "checked_bytes": row["window_bytes"],
            "actual_window_start_mod16": checked % 16,
            "mapping": "right-guarded",
            "readable_left_bytes": 32,
            "readable_right_bytes": 0,
            "padding_sentinel": row["fixture_recipe"]["background_byte"],
            "padding_verified": True,
            "page_size": page_size,
            "guard_page_start_address": guard,
            "guard_protection": "PROT_NONE",
            "guard_protection_receipt_sha256": identity(
                f"{phase}:guard:{host_index}:{ordinal}"
            ),
            "allocation_receipt_sha256": identity(
                f"{phase}:allocation:{host_index}:{ordinal}"
            ),
        }
    base = 0x8_0000_0000 + ordinal * 0x20_0000
    checked = base + row["expected_physical_window_start_mod16"]
    fixture = checked - row["logical_prefix_bytes"]
    allocation_start = checked - 32
    allocation_end = checked + row["window_bytes"] + 32
    return {
        "allocation_start_address": allocation_start,
        "allocation_bytes": allocation_end - allocation_start,
        "fixture_pointer_address": fixture,
        "checked_pointer_address": checked,
        "checked_bytes": row["window_bytes"],
        "actual_window_start_mod16": checked % 16,
        "mapping": "right-padded",
        "readable_left_bytes": 32,
        "readable_right_bytes": 32,
        "padding_sentinel": row["fixture_recipe"]["background_byte"],
        "padding_verified": True,
        "page_size": page_size,
        "guard_page_start_address": None,
        "guard_protection": "none",
        "guard_protection_receipt_sha256": None,
        "allocation_receipt_sha256": identity(
            f"{phase}:allocation:{host_index}:{ordinal}"
        ),
    }


def precheck_record(
    row: dict[str, Any], candidate_route: str
) -> dict[str, Any]:
    span = (
        None
        if row["expected_match_start"] is None
        else [row["expected_match_start"], row["expected_match_end"]]
    )
    count = 0 if span is None else 1
    static = 1 if row["expected_static_invoked"] else 0
    return {
        "scalar_span": span,
        "portable_span": span,
        "candidate_span": span,
        "expected_nonoverlapping_count": count,
        "portable_nonoverlapping_count": count,
        "candidate_nonoverlapping_count": count,
        "portable_route": "full-portable",
        "candidate_route": candidate_route,
        "portable_static_invocations": 0,
        "candidate_static_invocations": static,
    }


def correctness_case(
    analyzer: ModuleType,
    campaign_id: str,
    row: dict[str, Any],
    ordinal: int,
    host_index: int,
    compiler_by_literal: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema": analyzer.CORRECTNESS_CASE_SCHEMA,
        "campaign_id": campaign_id,
        "ordinal": ordinal,
        "row_sha256": row["row_sha256"],
        "literal_sha256": row["literal_sha256"],
        "literal_hex": row["literal_hex"],
        "compiler": compiler_by_literal[row["literal_sha256"]],
        "precheck": precheck_record(row, row["expected_route"]),
        "mapping": mapping_record(
            analyzer, row, ordinal, host_index, "correctness"
        ),
    }


def timing_case(
    analyzer: ModuleType,
    campaign_id: str,
    row: dict[str, Any],
    ordinal: int,
    host_index: int,
    compiler_by_literal: dict[str, dict[str, Any]],
    timed_function: str,
) -> dict[str, Any]:
    mapping = mapping_record(analyzer, row, ordinal, host_index, "timing")
    precheck = precheck_record(row, "portable-prefix-static-tail")
    iteration_count = 1000 + ordinal % 7
    accumulator = int(row["row_sha256"][:16], 16)
    logical_cpu = 2 + host_index
    affinity = identity(f"timing:affinity:{host_index}:{ordinal}")
    admission = identity(f"timing:admission:{host_index}:{ordinal}")
    pairs = []
    for pair_index in range(analyzer.REPETITIONS):
        portable_ns = 600_000_000 + pair_index * 1_000_000
        candidate_ns = 450_000_000 + pair_index * 750_000
        span = precheck["scalar_span"]
        pairs.append(
            {
                "pair_index": pair_index,
                "first_variant": (
                    "portable" if pair_index % 2 == 0 else "candidate"
                ),
                "iteration_count": iteration_count,
                "fixture_pointer_address": mapping[
                    "fixture_pointer_address"
                ],
                "checked_pointer_address": mapping[
                    "checked_pointer_address"
                ],
                "logical_cpu": logical_cpu,
                "cpu_before": logical_cpu,
                "cpu_after": logical_cpu,
                "affinity_receipt_sha256": affinity,
                "admission_receipt_sha256": admission,
                "portable": {
                    "elapsed_ns": portable_ns,
                    "output_accumulator": accumulator,
                    "last_span": span,
                    "route": "full-portable",
                },
                "candidate": {
                    "elapsed_ns": candidate_ns,
                    "output_accumulator": accumulator,
                    "last_span": span,
                    "route": "portable-prefix-static-tail",
                },
            }
        )
    return {
        "schema": analyzer.CASE_SCHEMA,
        "campaign_id": campaign_id,
        "ordinal": ordinal,
        "row_sha256": row["row_sha256"],
        "literal_sha256": row["literal_sha256"],
        "literal_hex": row["literal_hex"],
        "dimensions": analyzer.expected_dimensions(row),
        "compiler": compiler_by_literal[row["literal_sha256"]],
        "precheck": precheck,
        "mapping": mapping,
        "timing_setup": {
            "fixture_materialization_outside_timing": True,
            "compile_link_adoption_outside_timing": True,
            "pilot_outside_timing": True,
            "route_instrumentation_outside_timing": True,
            "timed_function_identity_sha256": timed_function,
        },
        "pairs": pairs,
    }


def proof_records(
    symbols: list[str],
    implementation_object: str,
    glue_object: str,
    label: str,
) -> list[dict[str, Any]]:
    return [
        {
            "symbol": symbol,
            "object_sha256": (
                implementation_object if index < 3 else glue_object
            ),
            "receipt_sha256": identity(f"{label}:{index}:{symbol}"),
        }
        for index, symbol in enumerate(symbols)
    ]


def build_object_evidence(
    analyzer: ModuleType,
    directory: Path,
    plan: dict[str, Any],
    qualification_root: Path,
    expected_host: dict[str, Any],
    host_index: int,
    linked_image: str,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], dict[str, Any]]:
    object_envelope = json.loads(
        (
            qualification_root
            / plan["payload"]["object_candidates"]["path"]
        ).read_bytes()
    )
    disposition_envelope = json.loads(
        (
            qualification_root
            / plan["payload"]["literal_dispositions"]["path"]
        ).read_bytes()
    )
    candidates = object_envelope["payload"]["candidates"]
    dispositions = disposition_envelope["payload"]["dispositions"]
    objects = []
    compiler_by_literal: dict[str, dict[str, Any]] = {}
    for ordinal, candidate in enumerate(candidates):
        compile_identity = identity(
            f"compile-identity:{host_index}:{candidate['literal_sha256']}"
        )
        implementation_object = identity(
            f"implementation-object:{host_index}:{candidate['literal_sha256']}"
        )
        glue_object = identity(
            f"glue-object:{host_index}:{candidate['literal_sha256']}"
        )
        implementation_symbols = {
            "entry": f"fre_entry_{compile_identity}",
            "payload": f"fre_payload_{compile_identity}",
            "metadata": f"fre_metadata_{compile_identity}",
        }
        glue_symbol = f"fre_glue_{compile_identity}"
        symbols = [*implementation_symbols.values(), glue_symbol]
        mapping = {
            "ordinal": ordinal,
            "literal_sha256": candidate["literal_sha256"],
            "semantic_candidate_sha256": candidate[
                "semantic_candidate_sha256"
            ],
            "compile_identity": compile_identity,
            "compile_receipt_sha256": identity(
                f"compile-receipt:{host_index}:{candidate['literal_sha256']}"
            ),
            "implementation_object_sha256": implementation_object,
            "glue_object_sha256": glue_object,
            "implementation_symbols": implementation_symbols,
            "glue_symbol": glue_symbol,
            "glue_symbol_identity_sha256": sha256(
                analyzer.GLUE_SYMBOL_DOMAIN + glue_symbol.encode()
            ),
            "glue_relocation_targets": list(
                implementation_symbols.values()
            ),
            "implementation_linker_input_multiplicity": 1,
            "glue_linker_input_multiplicity": 1,
            "link_map_origins": proof_records(
                symbols,
                implementation_object,
                glue_object,
                f"origin:{host_index}:{ordinal}",
            ),
            "final_image_retentions": proof_records(
                symbols,
                implementation_object,
                glue_object,
                f"retention:{host_index}:{ordinal}",
            ),
        }
        objects.append(mapping)
        compiler_by_literal[candidate["literal_sha256"]] = (
            analyzer.compiler_case_record(mapping, "tag29-object")
        )
    refusals = []
    for disposition in dispositions:
        if disposition["expected_compiler_disposition"] != "structural-refusal":
            continue
        refusal_ordinal = len(refusals)
        mapping = {
            "ordinal": refusal_ordinal,
            "literal_sha256": disposition["literal_sha256"],
            "semantic_candidate_sha256": disposition[
                "semantic_candidate_sha256"
            ],
            "disposition": "structural-refusal",
            "compile_receipt_sha256": identity(
                f"refusal:{host_index}:{disposition['literal_sha256']}"
            ),
        }
        refusals.append(mapping)
        compiler_by_literal[disposition["literal_sha256"]] = (
            analyzer.compiler_case_record(mapping, "structural-refusal")
        )
    payload = {
        "frozen_host": expected_host["frozen_name"],
        "canonical_host": expected_host["canonical_name"],
        "target_triple": expected_host["target_triple"],
        "features": expected_host["features"],
        "object_manifest_sha256": plan["payload"]["object_candidates"][
            "file_sha256"
        ],
        "object_manifest_payload_sha256": plan["payload"][
            "object_candidates"
        ]["payload_sha256"],
        "literal_dispositions_sha256": plan["payload"][
            "literal_dispositions"
        ]["file_sha256"],
        "literal_dispositions_payload_sha256": plan["payload"][
            "literal_dispositions"
        ]["payload_sha256"],
        "verifier_source_sha256": analyzer.LINK_PROOF_VERIFIER_SHA256,
        "verifier_contract_sha256": analyzer.LINK_PROOF_CONTRACT_SHA256,
        "external_build_receipt_sha256": identity(
            f"external-build:{host_index}"
        ),
        "external_link_receipt_sha256": identity(
            f"external-link:{host_index}"
        ),
        "link_map_sha256": identity(f"link-map:{host_index}"),
        "linked_image_sha256": linked_image,
        "objects": objects,
        "refusals": refusals,
    }
    envelope = json_envelope(analyzer.OBJECT_EVIDENCE_SCHEMA, payload)
    encoded = line(envelope)
    name = (
        f"{expected_host['canonical_name']}"
        ".compiler-object-link-evidence.json"
    )
    write_new(directory / name, encoded)
    receipt = {
        "path": name,
        "bytes": len(encoded),
        "sha256": sha256(encoded),
        "payload_sha256": envelope["payload_sha256"],
    }
    return receipt, compiler_by_literal, envelope


def write_stream_record(
    output: BinaryIO,
    value: dict[str, Any],
    file_digest: Any,
    prefix_digest: Any | None,
) -> int:
    encoded = line(value)
    output.write(encoded)
    file_digest.update(encoded)
    if prefix_digest is not None:
        prefix_digest.update(encoded)
    return len(encoded)


def build_correctness_bundle(
    analyzer: ModuleType,
    directory: Path,
    qualification_root: Path,
    authority: dict[str, Any],
    authority_host: dict[str, Any],
    expected_host: dict[str, Any],
    campaign_id: str,
    host_index: int,
    compiler_by_literal: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    name = f"{expected_host['canonical_name']}.correctness.jsonl"
    file_digest = hashlib.sha256()
    prefix_digest = hashlib.sha256()
    total = 0
    with (directory / name).open("xb") as output, (
        qualification_root / "full-projection.ndjson"
    ).open("rb") as projection:
        header = common_header(
            analyzer,
            analyzer.CORRECTNESS_HEADER_SCHEMA,
            campaign_id,
            authority,
            authority_host,
            expected_host,
            analyzer.FULL_ROWS,
        )
        total += write_stream_record(
            output, header, file_digest, prefix_digest
        )
        for ordinal, encoded in enumerate(projection):
            row = json.loads(encoded)
            total += write_stream_record(
                output,
                correctness_case(
                    analyzer,
                    campaign_id,
                    row,
                    ordinal,
                    host_index,
                    compiler_by_literal,
                ),
                file_digest,
                prefix_digest,
            )
        require(
            ordinal + 1 == analyzer.FULL_ROWS,
            "test projection row count changed",
        )
        trailer = {
            "schema": analyzer.CORRECTNESS_TRAILER_SCHEMA,
            "campaign_id": campaign_id,
            "case_records": analyzer.FULL_ROWS,
            "pairs": 0,
            "measurements": 0,
            "prefix_sha256": prefix_digest.hexdigest(),
        }
        total += write_stream_record(output, trailer, file_digest, None)
        output.flush()
    return {
        "path": name,
        "bytes": total,
        "sha256": file_digest.hexdigest(),
        "case_records": analyzer.FULL_ROWS,
    }


def build_timing_bundle(
    analyzer: ModuleType,
    directory: Path,
    authority: dict[str, Any],
    authority_host: dict[str, Any],
    expected_host: dict[str, Any],
    campaign_id: str,
    host_index: int,
    compiler_by_literal: dict[str, dict[str, Any]],
    rows: list[dict[str, Any]],
) -> dict[str, Any]:
    name = f"{expected_host['canonical_name']}.timing.jsonl"
    file_digest = hashlib.sha256()
    prefix_digest = hashlib.sha256()
    total = 0
    with (directory / name).open("xb") as output:
        header = common_header(
            analyzer,
            analyzer.HEADER_SCHEMA,
            campaign_id,
            authority,
            authority_host,
            expected_host,
            analyzer.TIMED_ROWS,
        )
        header["pairs"] = analyzer.PAIRS_PER_HOST
        header["measurements"] = analyzer.MEASUREMENTS_PER_HOST
        total += write_stream_record(
            output, header, file_digest, prefix_digest
        )
        for ordinal, row in enumerate(rows):
            total += write_stream_record(
                output,
                timing_case(
                    analyzer,
                    campaign_id,
                    row,
                    ordinal,
                    host_index,
                    compiler_by_literal,
                    authority["runner"][
                        "timed_function_identity_sha256"
                    ],
                ),
                file_digest,
                prefix_digest,
            )
        trailer = {
            "schema": analyzer.TRAILER_SCHEMA,
            "campaign_id": campaign_id,
            "case_records": analyzer.TIMED_ROWS,
            "pairs": analyzer.PAIRS_PER_HOST,
            "measurements": analyzer.MEASUREMENTS_PER_HOST,
            "prefix_sha256": prefix_digest.hexdigest(),
        }
        total += write_stream_record(output, trailer, file_digest, None)
        output.flush()
    return {
        "path": name,
        "bytes": total,
        "sha256": file_digest.hexdigest(),
        "case_records": analyzer.TIMED_ROWS,
        "pairs": analyzer.PAIRS_PER_HOST,
        "measurements": analyzer.MEASUREMENTS_PER_HOST,
    }


def build_campaign(
    analyzer: ModuleType,
    qualification_root: Path,
    directory: Path,
) -> tuple[Path, Path, str, dict[str, Any], list[dict[str, Any]], list[dict[str, dict[str, Any]]], list[dict[str, Any]]]:
    plan = analyzer.validate_plan(qualification_root)
    rows = analyzer.load_timed_rows(qualification_root, plan)
    analyzer_sha = sha256(Path(analyzer.__file__).resolve().read_bytes())
    validator_sha = sha256(
        Path(analyzer.__file__)
        .resolve()
        .with_name("validate_qualification_plan.py")
        .read_bytes()
    )
    timed_function = identity("ordinary-production-auto-route-v2")
    authority_hosts = []
    compiler_maps = []
    evidence_envelopes = []
    for host_index, expected_host in enumerate(analyzer.HOSTS):
        linked_image = identity(f"linked-image:{host_index}")
        receipt, compiler_map, evidence = build_object_evidence(
            analyzer,
            directory,
            plan,
            qualification_root,
            expected_host,
            host_index,
            linked_image,
        )
        authority_hosts.append(
            {
                "frozen_name": expected_host["frozen_name"],
                "canonical_name": expected_host["canonical_name"],
                "target_triple": expected_host["target_triple"],
                "features": expected_host["features"],
                "allowed_logical_cpus": [2 + host_index],
                "host_attestation_sha256": identity(f"host:{host_index}"),
                "runner_binary_sha256": identity(f"binary:{host_index}"),
                "linked_image_sha256": linked_image,
                "linked_image_platform_identity_sha256": identity(
                    f"platform-image:{host_index}"
                ),
                "build_closure_sha256": identity(f"build:{host_index}"),
                "toolchain_closure_sha256": identity(
                    f"toolchain:{host_index}"
                ),
                "object_evidence": receipt,
            }
        )
        compiler_maps.append(compiler_map)
        evidence_envelopes.append(evidence)
    object_receipt = plan["payload"]["object_candidates"]
    authority = {
        "campaign_name": "search-tag29-topology-v1",
        "freeze_sha256": analyzer.FREEZE_SHA256,
        "generator_sha256": analyzer.GENERATOR_SHA256,
        "selector_contract_sha256": analyzer.SELECTOR_SHA256,
        "qualification_plan_sha256": plan["sha256"],
        "qualification_plan_payload_sha256": plan["payload_sha256"],
        "timed_projection_digest": analyzer.TIMED_PROJECTION_DIGEST,
        "timed_projection_rows": analyzer.TIMED_ROWS,
        "full_projection_digest": analyzer.FULL_PROJECTION_DIGEST,
        "full_projection_rows": analyzer.FULL_ROWS,
        "runner": {
            "source_commit": identity("commit")[:40],
            "source_set_sha256": identity("source-set"),
            "controller_source_sha256": identity("controller"),
            "sealer_source_sha256": identity("sealer"),
            "analyzer_source_sha256": analyzer_sha,
            "qualification_validator_source_sha256": validator_sha,
            "object_manifest_sha256": object_receipt["file_sha256"],
            "object_manifest_payload_sha256": object_receipt[
                "payload_sha256"
            ],
            "backend_tag": 29,
            "backend_version": "SEARCH_V16",
            "candidate_policy": 15,
            "llvm": False,
            "ordinary_candidate_entry": (
                "production-auto-route-portable-prefix-static-tail"
            ),
            "baseline_entry": "forced-full-portable",
            "timed_function_identity_sha256": timed_function,
        },
        "host_aliases": {
            host["frozen_name"]: host["canonical_name"]
            for host in analyzer.HOSTS
        },
        "hosts": authority_hosts,
        "performance_authority": {
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
            "minimum_elapsed_ns_each_variant": analyzer.MINIMUM_NS,
            "repetitions": analyzer.REPETITIONS,
        },
        "rebar_inputs": [],
        "benchmark_result_inputs": [],
        "result_derived_exclusions": False,
    }
    authority_envelope = json_envelope(analyzer.AUTHORITY_SCHEMA, authority)
    authority_path = directory / "campaign-authority.json"
    authority_encoded = line(authority_envelope)
    write_new(authority_path, authority_encoded)
    authority_sha = sha256(authority_encoded)
    campaign_id = analyzer.campaign_id(authority_sha)
    manifest_hosts = []
    for host_index, (authority_host, expected_host, compiler_map) in enumerate(
        zip(authority_hosts, analyzer.HOSTS, compiler_maps, strict=True)
    ):
        correctness = build_correctness_bundle(
            analyzer,
            directory,
            qualification_root,
            authority,
            authority_host,
            expected_host,
            campaign_id,
            host_index,
            compiler_map,
        )
        timing = build_timing_bundle(
            analyzer,
            directory,
            authority,
            authority_host,
            expected_host,
            campaign_id,
            host_index,
            compiler_map,
            rows,
        )
        manifest_hosts.append(
            {
                "frozen_name": expected_host["frozen_name"],
                "canonical_name": expected_host["canonical_name"],
                "correctness_bundle": correctness,
                "timing_bundle": timing,
            }
        )
    manifest = {
        "schema": analyzer.MANIFEST_SCHEMA,
        "campaign_id": campaign_id,
        "campaign_authority_sha256": authority_sha,
        "hosts": manifest_hosts,
    }
    manifest_path = directory / "result-manifest.json"
    write_new(manifest_path, line(manifest))
    return (
        authority_path,
        manifest_path,
        authority_sha,
        authority,
        rows,
        compiler_maps,
        evidence_envelopes,
    )


def run_analyzer(
    analyzer: ModuleType,
    qualification_root: Path,
    authority: Path,
    authority_sha: str,
    manifest: Path,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            sys.executable,
            str(Path(analyzer.__file__).resolve()),
            str(qualification_root),
            str(authority),
            authority_sha,
            str(manifest),
        ],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def expect_refusal(function: Any, message: str) -> None:
    try:
        function()
    except Exception as error:
        require(
            error.__class__.__name__ == "Refusal"
            or isinstance(error, OSError),
            f"{message}: wrong exception {error!r}",
        )
    else:
        raise RuntimeError(f"{message}: mutation passed")


def adversarial_unit_tests(
    analyzer: ModuleType,
    campaign_id: str,
    authority: dict[str, Any],
    rows: list[dict[str, Any]],
    compiler_maps: list[dict[str, dict[str, Any]]],
) -> None:
    row = rows[0]
    valid = timing_case(
        analyzer,
        campaign_id,
        row,
        0,
        0,
        compiler_maps[0],
        authority["runner"]["timed_function_identity_sha256"],
    )

    def validate(case: dict[str, Any], registry: dict[str, str] | None = None) -> Any:
        return analyzer.validate_case(
            case,
            row,
            0,
            campaign_id,
            compiler_maps[0],
            {} if registry is None else registry,
            analyzer.HOSTS[0]["canonical_name"],
            {2},
            authority["runner"]["timed_function_identity_sha256"],
        )

    require(validate(copy.deepcopy(valid)) < analyzer.STRICT_GATE, "valid case")
    mutation = copy.deepcopy(valid)
    mutation["ordinal"] = True
    expect_refusal(lambda: validate(mutation), "bool ordinal")
    mutation = copy.deepcopy(valid)
    mutation["mapping"]["allocation_start_address"] = 0
    expect_refusal(lambda: validate(mutation), "zero allocation bound")
    mutation = copy.deepcopy(valid)
    mutation["pairs"][0]["logical_cpu"] = 99
    mutation["pairs"][0]["cpu_before"] = 99
    mutation["pairs"][0]["cpu_after"] = 99
    expect_refusal(lambda: validate(mutation), "CPU outside authority")
    mutation = copy.deepcopy(valid)
    mutation["pairs"][1]["portable"]["output_accumulator"] += 1
    mutation["pairs"][1]["candidate"]["output_accumulator"] += 1
    expect_refusal(lambda: validate(mutation), "varying accumulator")
    mutation = copy.deepcopy(valid)
    mutation["timing_setup"]["timed_function_identity_sha256"] = identity(
        "other-function"
    )
    expect_refusal(lambda: validate(mutation), "second timed function")
    boundary = copy.deepcopy(valid)
    for pair in boundary["pairs"]:
        pair["candidate"]["elapsed_ns"] = (
            pair["portable"]["elapsed_ns"] * 4 // 5
        )
    require(
        validate(boundary) == analyzer.STRICT_GATE,
        "exact strict boundary changed",
    )
    second = timing_case(
        analyzer,
        campaign_id,
        rows[1],
        1,
        0,
        compiler_maps[0],
        authority["runner"]["timed_function_identity_sha256"],
    )
    second["mapping"]["allocation_receipt_sha256"] = valid["mapping"][
        "allocation_receipt_sha256"
    ]
    registry: dict[str, str] = {}
    validate(copy.deepcopy(valid), registry)
    expect_refusal(
        lambda: analyzer.validate_case(
            second,
            rows[1],
            1,
            campaign_id,
            compiler_maps[0],
            registry,
            analyzer.HOSTS[0]["canonical_name"],
            {2},
            authority["runner"]["timed_function_identity_sha256"],
        ),
        "cross-case receipt reuse",
    )
    full = correctness_case(
        analyzer,
        campaign_id,
        row,
        0,
        0,
        compiler_maps[0],
    )
    full["precheck"]["candidate_route"] = "portable-only"
    expect_refusal(
        lambda: analyzer.validate_correctness_case(
            full,
            row,
            0,
            campaign_id,
            compiler_maps[0],
            {},
            analyzer.HOSTS[0]["canonical_name"],
        ),
        "full-correctness route mutation",
    )


def object_evidence_mutation_test(
    analyzer: ModuleType,
    qualification_root: Path,
    authority: dict[str, Any],
    evidence: dict[str, Any],
) -> None:
    plan = analyzer.validate_plan(qualification_root)
    mutated = copy.deepcopy(evidence)
    mutated["payload"]["objects"][0]["implementation_symbols"][
        "entry"
    ] = "fre_entry_without_compile_identity"
    mutated["payload_sha256"] = sha256(
        canonical_bytes(mutated["payload"])
    )
    encoded = line(mutated)
    with tempfile.TemporaryDirectory(
        prefix="fre-tag29-bad-object-evidence-"
    ) as name:
        directory = Path(name)
        evidence_name = authority["hosts"][0]["object_evidence"]["path"]
        write_new(directory / evidence_name, encoded)
        bad_host = copy.deepcopy(authority["hosts"][0])
        bad_host["object_evidence"] = {
            "path": evidence_name,
            "bytes": len(encoded),
            "sha256": sha256(encoded),
            "payload_sha256": mutated["payload_sha256"],
        }
        with (
            analyzer.held_directory(directory) as authority_fd,
            analyzer.held_directory(qualification_root) as qualification_fd,
        ):
            expect_refusal(
                lambda: analyzer.load_object_evidence(
                    authority_fd,
                    bad_host,
                    analyzer.HOSTS[0],
                    plan,
                    qualification_fd,
                ),
                "object symbol without compile identity",
            )


def main() -> None:
    require(
        len(sys.argv) == 2,
        "usage: test_qualification_tools.py QUALIFICATION_DIRECTORY",
    )
    analyzer = load_analyzer()
    qualification_root = Path(sys.argv[1]).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="fre-tag29-result-v2-") as name:
        directory = Path(name)
        (
            authority_path,
            manifest_path,
            authority_sha,
            authority,
            rows,
            compiler_maps,
            evidence,
        ) = build_campaign(analyzer, qualification_root, directory)
        result = run_analyzer(
            analyzer,
            qualification_root,
            authority_path,
            authority_sha,
            manifest_path,
        )
        require(
            result.returncode == 0
            and not result.stderr
            and json.loads(result.stdout)["pass"] is True
            and json.loads(result.stdout)["total_correctness_rows"]
            == analyzer.FULL_ROWS * 2,
            f"complete v2 campaign failed: {result.stderr.decode()}",
        )
        wrong_authority = run_analyzer(
            analyzer,
            qualification_root,
            authority_path,
            identity("not-the-pre-registered-authority"),
            manifest_path,
        )
        require(
            wrong_authority.returncode == 1
            and b"pre-result expected SHA-256" in wrong_authority.stderr,
            "self-authorized result was not rejected",
        )
        correctness_path = (
            directory
            / f"{analyzer.HOSTS[0]['canonical_name']}.correctness.jsonl"
        )
        held_path = directory / "temporarily-held-correctness.jsonl"
        correctness_path.rename(held_path)
        try:
            missing_correctness = run_analyzer(
                analyzer,
                qualification_root,
                authority_path,
                authority_sha,
                manifest_path,
            )
        finally:
            held_path.rename(correctness_path)
        require(
            missing_correctness.returncode == 1
            and b".correctness.jsonl" in missing_correctness.stderr,
            "full correctness bundle was optional",
        )
        adversarial_unit_tests(
            analyzer, result_id := analyzer.campaign_id(authority_sha),
            authority, rows, compiler_maps
        )
        object_evidence_mutation_test(
            analyzer, qualification_root, authority, evidence[0]
        )
        require(
            result_id == json.loads(result.stdout)["campaign_id"],
            "campaign identity test changed",
        )
        symlink_root = directory / "symlink-test"
        symlink_root.mkdir()
        write_new(symlink_root / "real", b"x")
        os.symlink("real", symlink_root / "alias")
        with analyzer.held_directory(symlink_root) as directory_fd:
            expect_refusal(
                lambda: analyzer.read_regular_at(directory_fd, "alias"),
                "symlink bundle",
            )
    print(
        "qualification-tools=v2-pass full-correctness=246848 "
        "timed-cells=6156 authority=self-reference-rejected "
        "strict-boundary-4/5=rejected adversarial-mutations=rejected"
    )


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, RuntimeError) as error:
        print(f"search-tag29-qualification-tools-test: {error}", file=sys.stderr)
        raise SystemExit(1)
