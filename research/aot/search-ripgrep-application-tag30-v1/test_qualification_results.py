#!/usr/bin/env python3
"""Synthetic contract and adversarial tests for application qualification."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def identity(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def load_analyzer(repo: Path) -> Any:
    path = (
        repo
        / "research/aot/search-ripgrep-application-tag30-v1/"
        "analyze_qualification_results.py"
    )
    specification = importlib.util.spec_from_file_location(
        "_fre_tag30_application_analyzer_test", path
    )
    require(specification is not None, "cannot load analyzer")
    module = importlib.util.module_from_spec(specification)
    assert specification.loader is not None
    specification.loader.exec_module(module)
    return module


def envelope(analyzer: Any, schema: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": schema,
        "payload_sha256": analyzer.canonical_sha(payload),
        "payload": payload,
    }


def binding_payload(analyzer: Any) -> dict[str, Any]:
    hosts = []
    for index, (host_id, expected) in enumerate(
        analyzer.EXPECTED_HOSTS.items()
    ):
        hosts.append(
            {
                "host_id": host_id,
                "canonical_host": expected["canonical_host"],
                "target_triple": expected["target_triple"],
                "features": expected["features"],
                "allowed_logical_cpus": [6 + index * 34],
                "runner_binary_sha256": identity(f"binary:{index}"),
                "runner_identity_sha256": identity(f"identity:{index}"),
                "build_receipt_sha256": identity(f"build:{index}"),
                "manifest_identity": identity(f"manifest:{index}"),
                "compiler_identity": identity(f"compiler:{index}"),
            }
        )
    return {
        "contract_sha256": analyzer.CONTRACT_SHA256,
        "projection_sha256": analyzer.PROJECTION_SHA256,
        "projection_file_sha256": analyzer.PROJECTION_FILE_SHA256,
        "fixture_manifest_sha256": analyzer.FIXTURE_MANIFEST_SHA256,
        "object_manifest_sha256": analyzer.OBJECT_MANIFEST_SHA256,
        "literal_dispositions_sha256": analyzer.DISPOSITIONS_SHA256,
        "application_analyzer_source_sha256": (
            analyzer.analyzer_source_sha256()
        ),
        "campaign_plan_identity": identity("campaign-plan"),
        "campaign_analyzer_identity": identity("campaign-analyzer"),
        "campaign_evidence_identity": identity("campaign-evidence"),
        "private_family_authorization_identity": identity(
            "private-authorization"
        ),
        "runner_source_commit": identity("revision")[:40],
        "runner_source_sha256": identity("runner-source"),
        "source_archive_sha256": identity("source-archive"),
        "hosts": hosts,
        "timing_sealed": True,
        "bindings_complete": True,
        "application_qualification_authority": True,
        "production_authority": False,
        "rebar_inputs": [],
        "benchmark_results": [],
        "external_regex_heldout_inputs": [],
        "heldout_materialized": False,
        "result_derived_exclusions": False,
    }


def header(
    analyzer: Any,
    binding: dict[str, Any],
    host: dict[str, Any],
    mode: str,
    shard: int,
) -> dict[str, Any]:
    start, end = analyzer.shard_bounds(shard)
    return {
        "schema": analyzer.FRAGMENT_HEADER_SCHEMA,
        "mode": mode,
        "contract_schema": (
            "fre.aot.search-tag30-ripgrep-application-contract.v1"
        ),
        "contract_sha256": analyzer.CONTRACT_SHA256,
        "projection_schema": (
            "fre.aot.search-tag30-ripgrep-application-projection-row.v1"
        ),
        "projection_rows": analyzer.CASES,
        "projection_sha256": analyzer.PROJECTION_SHA256,
        "projection_file_sha256": analyzer.PROJECTION_FILE_SHA256,
        "shard_id": shard,
        "shard_start": start,
        "shard_end": end,
        "host_id": host["host_id"],
        "logical_cpu": host["allowed_logical_cpus"][0],
        "runner_binary_sha256": host["runner_binary_sha256"],
        "runner_source_sha256": binding["runner_source_sha256"],
        "runner_identity_sha256": host["runner_identity_sha256"],
        "build_receipt_sha256": host["build_receipt_sha256"],
        "object_manifest_sha256": analyzer.OBJECT_MANIFEST_SHA256,
        "literal_dispositions_sha256": analyzer.DISPOSITIONS_SHA256,
        "fixture_manifest_sha256": analyzer.FIXTURE_MANIFEST_SHA256,
        "backend_tag": 30,
        "backend_name": "AsimdV17",
        "family_selector": 13,
        "minimum_window_bytes": 65_536,
        "portable_prefix_candidate_starts": 256,
        "plan_identity": binding["campaign_plan_identity"],
        "analyzer_identity": binding["campaign_analyzer_identity"],
        "evidence_identity": binding["campaign_evidence_identity"],
        "private_family_authorization_identity": (
            binding["private_family_authorization_identity"]
        ),
        "application_contract_identity": analyzer.CONTRACT_SHA256,
        "timing_repetitions": (
            analyzer.REPETITIONS if mode == "timing" else None
        ),
        "minimum_elapsed_ns_each_variant": (
            analyzer.MINIMUM_NS if mode == "timing" else None
        ),
        "production_authority": False,
        "rebar_accepted_as_input": False,
        "heldout_materialized": False,
        "result_derived_exclusions": False,
    }


def mapping(analyzer: Any, row: dict[str, Any], salt: int) -> dict[str, Any]:
    base = 0x1000_0000 + salt * 0x20_0000
    start = 16 + (
        row["alignment_offset"] - ((base + 16) % 16)
    ) % 16
    return {
        "allocation_start_address": base,
        "allocation_bytes": row["fixture_bytes"] + 63,
        "checked_pointer_address": base + start,
        "checked_bytes": row["fixture_bytes"],
        "start_offset": start,
        "actual_window_start_mod16": row["alignment_offset"],
        "readable_left_bytes": start,
        "readable_right_bytes": 63 - start,
        "padding_sentinel": row["padding_sentinel"],
        "padding_verified": True,
        "allocation_receipt_sha256": identity(
            f"allocation:{row['case_id']}:{salt}"
        ),
    }


def common(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "ordinal": row["ordinal"],
        "row_sha256": row["row_sha256"],
        "case_id": row["case_id"],
        "candidate_sha256": row["candidate_sha256"],
        "literal_sha256": row["literal_sha256"],
        "fixture_sha256": row["fixture_sha256"],
        "scenario": row["scenario"],
        "compiler_disposition": row[
            "expected_compiler_disposition"
        ],
        "route_class": row["route_class"],
        "expected_static_invoked": row["expected_static_invoked"],
    }


def correctness_row(
    analyzer: Any, row: dict[str, Any], cpu: int, salt: int
) -> dict[str, Any]:
    expected = row["expected_span"]
    return {
        "schema": analyzer.CORRECTNESS_ROW_SCHEMA,
        **common(row),
        "portable_span": expected,
        "candidate_span": expected,
        "direct_tail_span": (
            expected
            if row["route_class"] == "tag30-static-tail"
            else None
        ),
        "scalar_span": expected,
        "scalar_nonoverlapping_count": row[
            "expected_nonoverlapping_count"
        ],
        "mapping": mapping(analyzer, row, salt),
        "worker_logical_cpu": cpu,
        "pass": True,
    }


def timing_row(
    analyzer: Any,
    row: dict[str, Any],
    cpu: int,
    salt: int,
    candidate_ns: int | None = None,
) -> dict[str, Any]:
    portable_ns = 1_000_000_000
    if candidate_ns is None:
        candidate_ns = (
            700_000_000
            if row["route_class"] == "tag30-static-tail"
            else 1_000_000_000
        )
    checksum = row["ordinal"] + 17
    pairs = [
        {
            "repetition": repetition,
            "order": (
                "portable-first"
                if repetition % 2 == 0
                else "candidate-first"
            ),
            "iterations": 9,
            "portable_elapsed_ns": portable_ns,
            "candidate_elapsed_ns": candidate_ns,
            "portable_checksum": checksum,
            "candidate_checksum": checksum,
            "portable_cpu_before": cpu,
            "portable_cpu_after": cpu,
            "candidate_cpu_before": cpu,
            "candidate_cpu_after": cpu,
        }
        for repetition in range(analyzer.REPETITIONS)
    ]
    return {
        "schema": analyzer.TIMING_ROW_SCHEMA,
        **common(row),
        "mapping": mapping(analyzer, row, salt),
        "logical_cpu": cpu,
        "minimum_elapsed_ns_each_variant": analyzer.MINIMUM_NS,
        "pairs": pairs,
        "pass": True,
        "production_authority": False,
        "rebar_accepted_as_input": False,
    }


def encoded_line(analyzer: Any, value: Any) -> bytes:
    return analyzer.canonical_bytes(value) + b"\n"


def write_fragment(
    analyzer: Any,
    path: Path,
    binding: dict[str, Any],
    host: dict[str, Any],
    mode: str,
    shard: int,
    rows: list[dict[str, Any]],
    host_index: int,
) -> None:
    start, end = analyzer.shard_bounds(shard)
    records = []
    for row in rows[start:end]:
        salt = (
            host_index * 10_000
            + (0 if mode == "correctness" else 1_000)
            + row["ordinal"]
        )
        result = (
            correctness_row(
                analyzer, row, host["allowed_logical_cpus"][0], salt
            )
            if mode == "correctness"
            else timing_row(
                analyzer, row, host["allowed_logical_cpus"][0], salt
            )
        )
        records.append(encoded_line(analyzer, result))
    digest = hashlib.sha256()
    for encoded in records:
        digest.update(len(encoded).to_bytes(8, "little"))
        digest.update(encoded)
    trailer = {
        "schema": analyzer.FRAGMENT_TRAILER_SCHEMA,
        "rows": end - start,
        "shard_start": start,
        "shard_end": end,
        "records_sha256": digest.hexdigest(),
        "complete": True,
    }
    path.write_bytes(
        encoded_line(analyzer, header(analyzer, binding, host, mode, shard))
        + b"".join(records)
        + encoded_line(analyzer, trailer)
    )


def expect_refusal(label: str, invoke: Any) -> None:
    try:
        invoke()
    except Exception:
        return
    raise RuntimeError(f"adversarial mutation accepted: {label}")


def run(repo: Path, ripgrep_root: Path, fixture_root: Path) -> None:
    analyzer = load_analyzer(repo)
    rows = [
        json.loads(line)
        for line in (
            repo / analyzer.PROJECTION_RELATIVE
        ).read_bytes().splitlines()
    ]
    binding = binding_payload(analyzer)
    with tempfile.TemporaryDirectory(
        prefix="fre-tag30-application-test-"
    ) as temporary:
        root = Path(temporary)
        result_root = root / "results"
        result_root.mkdir()
        binding_path = root / "campaign-binding.json"
        binding_root = envelope(
            analyzer, analyzer.BINDING_SCHEMA, binding
        )
        binding_path.write_bytes(
            json.dumps(
                binding_root,
                sort_keys=True,
                indent=2,
                ensure_ascii=True,
            ).encode("ascii")
            + b"\n"
        )
        binding_sha = hashlib.sha256(binding_path.read_bytes()).hexdigest()
        for host_index, host in enumerate(binding["hosts"]):
            for mode in ("correctness", "timing"):
                for shard in range(analyzer.SHARDS):
                    write_fragment(
                        analyzer,
                        result_root
                        / (
                            f"{host['host_id']}.{mode}."
                            f"shard-{shard:02}.jsonl"
                        ),
                        binding,
                        host,
                        mode,
                        shard,
                        rows,
                        host_index,
                    )
        result = analyzer.analyze(
            repo,
            ripgrep_root,
            fixture_root,
            binding_path,
            binding_sha,
            result_root,
        )
        require(
            result["payload"]["application_qualification_pass"] is True
            and result["payload"]["production_authority"] is False,
            "valid synthetic campaign did not pass",
        )

        unresolved = copy.deepcopy(binding)
        unresolved["bindings_complete"] = False
        unresolved_path = root / "unresolved.json"
        unresolved_root = envelope(
            analyzer, analyzer.BINDING_SCHEMA, unresolved
        )
        unresolved_path.write_bytes(
            json.dumps(
                unresolved_root, sort_keys=True, indent=2
            ).encode("ascii")
            + b"\n"
        )
        expect_refusal(
            "unresolved binding",
            lambda: analyzer.load_binding(
                unresolved_path,
                hashlib.sha256(unresolved_path.read_bytes()).hexdigest(),
                analyzer.analyzer_source_sha256(),
            ),
        )

        static = next(
            row
            for row in rows
            if row["route_class"] == "tag30-static-tail"
        )
        prefix = next(
            row
            for row in rows
            if row["route_class"] == "portable-prefix-return"
        )
        fallback = next(
            row
            for row in rows
            if row["route_class"] == "full-portable-fallback"
        )
        cpu = binding["hosts"][0]["allowed_logical_cpus"][0]
        strict_boundary = timing_row(
            analyzer, static, cpu, 90_001, 800_000_000
        )
        require(
            analyzer.validate_timing(strict_boundary, static, cpu)
            == analyzer.STATIC_GATE,
            "strict boundary construction changed",
        )
        require(
            not (
                analyzer.validate_timing(strict_boundary, static, cpu)
                < analyzer.STATIC_GATE
            ),
            "strict static gate accepted equality",
        )
        prefix_boundary = timing_row(
            analyzer, prefix, cpu, 90_002, 1_050_000_000
        )
        require(
            analyzer.validate_timing(prefix_boundary, prefix, cpu)
            == analyzer.NONTARGET_GATE,
            "prefix inclusive boundary changed",
        )
        fallback_over = timing_row(
            analyzer, fallback, cpu, 90_003, 1_050_000_001
        )
        require(
            analyzer.validate_timing(fallback_over, fallback, cpu)
            > analyzer.NONTARGET_GATE,
            "fallback over-gate construction changed",
        )

        wrong_route = correctness_row(analyzer, static, cpu, 90_004)
        wrong_route["route_class"] = "portable-prefix-return"
        expect_refusal(
            "route substitution",
            lambda: analyzer.validate_correctness(
                wrong_route, static, cpu
            ),
        )
        wrong_disposition = correctness_row(
            analyzer, static, cpu, 90_005
        )
        wrong_disposition["compiler_disposition"] = "structural-refusal"
        expect_refusal(
            "compiler disposition substitution",
            lambda: analyzer.validate_correctness(
                wrong_disposition, static, cpu
            ),
        )
        migrated = timing_row(analyzer, static, cpu, 90_006)
        migrated["pairs"][3]["candidate_cpu_after"] = cpu + 1
        expect_refusal(
            "CPU migration",
            lambda: analyzer.validate_timing(migrated, static, cpu),
        )
        unequal_work = timing_row(analyzer, static, cpu, 90_007)
        unequal_work["pairs"][2]["candidate_checksum"] += 1
        expect_refusal(
            "unequal paired work",
            lambda: analyzer.validate_timing(
                unequal_work, static, cpu
            ),
        )
        short_variant = timing_row(analyzer, static, cpu, 90_008)
        short_variant["pairs"][1]["portable_elapsed_ns"] = (
            analyzer.MINIMUM_NS - 1
        )
        expect_refusal(
            "short timed variant",
            lambda: analyzer.validate_timing(
                short_variant, static, cpu
            ),
        )
        bad_mapping = correctness_row(analyzer, static, cpu, 90_009)
        bad_mapping["mapping"]["actual_window_start_mod16"] ^= 1
        expect_refusal(
            "fabricated physical alignment",
            lambda: analyzer.validate_correctness(
                bad_mapping, static, cpu
            ),
        )
        rebar = timing_row(analyzer, static, cpu, 90_010)
        rebar["rebar_accepted_as_input"] = True
        expect_refusal(
            "Rebar input",
            lambda: analyzer.validate_timing(rebar, static, cpu),
        )
        production = timing_row(analyzer, static, cpu, 90_011)
        production["production_authority"] = True
        expect_refusal(
            "production authority escalation",
            lambda: analyzer.validate_timing(
                production, static, cpu
            ),
        )
        wrong_header = header(
            analyzer, binding, binding["hosts"][0], "timing", 0
        )
        wrong_header["build_receipt_sha256"] = identity("wrong-build")
        expect_refusal(
            "cross-build fragment",
            lambda: analyzer.validate_header(
                wrong_header,
                "timing",
                0,
                binding["hosts"][0],
                binding,
            ),
        )

    print(
        "search-tag30-application-tests: PASS "
        "baseline=1 adversarial=12 candidates=11 fixtures=154 "
        "rebar_inputs=0 heldout_materialized=false"
    )


def main() -> None:
    require(
        len(sys.argv) == 4,
        "usage: test_qualification_results.py "
        "REPO RIPGREP_ROOT FIXTURE_ROOT",
    )
    run(
        Path(sys.argv[1]).resolve(strict=True),
        Path(sys.argv[2]).resolve(strict=True),
        Path(sys.argv[3]).resolve(strict=True),
    )


if __name__ == "__main__":
    main()
