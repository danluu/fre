#!/usr/bin/env python3
"""End-to-end deterministic and threshold tests for tag-29 qualification tools."""

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


def case_record(
    analyzer: ModuleType,
    campaign_id: str,
    row: dict[str, Any],
    ordinal: int,
    host_index: int,
    boundary_first: bool,
) -> dict[str, Any]:
    expected_span = (
        None
        if row["expected_match_start"] is None
        else [row["expected_match_start"], row["expected_match_end"]]
    )
    dimensions = analyzer.expected_dimensions(row)
    page_size = 4096
    if row["right_guarded"]:
        guard = 0x4_0000_0000 + ordinal * 0x20_0000
        checked = guard - row["window_bytes"]
        fixture = checked - row["logical_prefix_bytes"]
        mapping = {
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
                f"guard:{host_index}:{ordinal}"
            ),
            "allocation_receipt_sha256": identity(
                f"allocation:{host_index}:{ordinal}"
            ),
        }
    else:
        fixture = 0x8_0000_0000 + ordinal * 0x20_0000
        checked = fixture + row["logical_prefix_bytes"]
        mapping = {
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
                f"allocation:{host_index}:{ordinal}"
            ),
        }
    count = 0 if expected_span is None else 1
    iteration_count = 1000 + ordinal % 7
    output_accumulator = (
        int(row["row_sha256"][:16], 16) ^ iteration_count
    ) & ((1 << 64) - 1)
    logical_cpu = 2 + host_index
    affinity = identity(f"affinity:{host_index}:{ordinal}")
    admission = identity(f"admission:{host_index}:{ordinal}")
    pairs = []
    for pair_index in range(analyzer.REPETITIONS):
        portable_ns = 600_000_000 + pair_index * 1_000_000
        candidate_ns = 450_000_000 + pair_index * 750_000
        if boundary_first and ordinal == 0:
            candidate_ns = portable_ns * 4 // 5
        pairs.append(
            {
                "pair_index": pair_index,
                "first_variant": (
                    "portable" if pair_index % 2 == 0 else "candidate"
                ),
                "iteration_count": iteration_count,
                "fixture_pointer_address": fixture,
                "checked_pointer_address": checked,
                "logical_cpu": logical_cpu,
                "cpu_before": logical_cpu,
                "cpu_after": logical_cpu,
                "affinity_receipt_sha256": affinity,
                "admission_receipt_sha256": admission,
                "portable": {
                    "elapsed_ns": portable_ns,
                    "output_accumulator": output_accumulator,
                    "last_span": expected_span,
                    "route": "full-portable",
                },
                "candidate": {
                    "elapsed_ns": candidate_ns,
                    "output_accumulator": output_accumulator,
                    "last_span": expected_span,
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
        "dimensions": dimensions,
        "compiler": {
            "backend_tag": 29,
            "backend_version": "SEARCH_V16",
            "candidate_policy": 15,
            "disposition": "tag29-object",
            "compile_receipt_sha256": identity(
                f"compile:{host_index}:{row['literal_sha256']}"
            ),
            "object_sha256": identity(
                f"object:{host_index}:{row['literal_sha256']}"
            ),
        },
        "precheck": {
            "scalar_span": expected_span,
            "portable_span": expected_span,
            "candidate_span": expected_span,
            "expected_nonoverlapping_count": count,
            "portable_nonoverlapping_count": count,
            "candidate_nonoverlapping_count": count,
            "portable_route": "full-portable",
            "candidate_route": "portable-prefix-static-tail",
            "portable_static_invocations": 0,
            "candidate_static_invocations": 1,
        },
        "mapping": mapping,
        "timing_setup": {
            "fixture_materialization_outside_timing": True,
            "compile_link_adoption_outside_timing": True,
            "pilot_outside_timing": True,
            "route_instrumentation_outside_timing": True,
            "timed_function_identity_sha256": identity(
                "ordinary-production-auto-route-v1"
            ),
        },
        "pairs": pairs,
    }


def build_bundle(
    analyzer: ModuleType,
    directory: Path,
    authority: dict[str, Any],
    campaign_id: str,
    rows: list[dict[str, Any]],
    expected_host: dict[str, Any],
    host_index: int,
    boundary_first: bool,
) -> dict[str, Any]:
    host_hashes = {
        "host_attestation_sha256": identity(f"host:{host_index}"),
        "runner_binary_sha256": identity(f"binary:{host_index}"),
        "linked_image_sha256": identity(f"image:{host_index}"),
        "linked_image_platform_identity_sha256": identity(
            f"platform-image:{host_index}"
        ),
        "build_closure_sha256": identity(f"build:{host_index}"),
        "toolchain_closure_sha256": identity(f"toolchain:{host_index}"),
    }
    header = {
        "schema": analyzer.HEADER_SCHEMA,
        "campaign_id": campaign_id,
        "frozen_host": expected_host["frozen_name"],
        "canonical_host": expected_host["canonical_name"],
        "target_triple": expected_host["target_triple"],
        "features": expected_host["features"],
        **host_hashes,
        "runner_source_commit": authority["runner"]["source_commit"],
        "runner_source_set_sha256": authority["runner"][
            "source_set_sha256"
        ],
        "object_manifest_sha256": authority["runner"][
            "object_manifest_sha256"
        ],
        "qualification_plan_sha256": authority[
            "qualification_plan_sha256"
        ],
        "case_records": analyzer.TIMED_ROWS,
        "pairs": analyzer.PAIRS_PER_HOST,
        "measurements": analyzer.MEASUREMENTS_PER_HOST,
    }
    prefix = bytearray(line(header))
    for ordinal, row in enumerate(rows):
        prefix.extend(
            line(
                case_record(
                    analyzer,
                    campaign_id,
                    row,
                    ordinal,
                    host_index,
                    boundary_first,
                )
            )
        )
    trailer = {
        "schema": analyzer.TRAILER_SCHEMA,
        "campaign_id": campaign_id,
        "case_records": analyzer.TIMED_ROWS,
        "pairs": analyzer.PAIRS_PER_HOST,
        "measurements": analyzer.MEASUREMENTS_PER_HOST,
        "prefix_sha256": sha256(prefix),
    }
    encoded = bytes(prefix) + line(trailer)
    relative = f"{expected_host['canonical_name']}.jsonl"
    write_new(directory / relative, encoded)
    return {
        "frozen_name": expected_host["frozen_name"],
        "canonical_name": expected_host["canonical_name"],
        "target_triple": expected_host["target_triple"],
        "features": expected_host["features"],
        **host_hashes,
        "bundle": {
            "path": relative,
            "bytes": len(encoded),
            "sha256": sha256(encoded),
            "case_records": analyzer.TIMED_ROWS,
            "pairs": analyzer.PAIRS_PER_HOST,
            "measurements": analyzer.MEASUREMENTS_PER_HOST,
        },
    }


def build_campaign(
    analyzer: ModuleType,
    qualification_root: Path,
    directory: Path,
    boundary_first: bool,
) -> Path:
    plan = analyzer.validate_plan(qualification_root)
    rows = analyzer.load_timed_rows(qualification_root, plan)
    analyzer_sha = sha256(Path(analyzer.__file__).resolve().read_bytes())
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
        "runner": {
            "source_commit": identity("commit")[:40],
            "source_set_sha256": identity("source-set"),
            "controller_source_sha256": identity("controller"),
            "sealer_source_sha256": identity("sealer"),
            "analyzer_source_sha256": analyzer_sha,
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
        },
        "host_aliases": {
            host["frozen_name"]: host["canonical_name"]
            for host in analyzer.HOSTS
        },
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
    campaign_id = analyzer.campaign_id(authority)
    hosts = [
        build_bundle(
            analyzer,
            directory,
            authority,
            campaign_id,
            rows,
            expected_host,
            host_index,
            boundary_first,
        )
        for host_index, expected_host in enumerate(analyzer.HOSTS)
    ]
    manifest = {
        "schema": analyzer.MANIFEST_SCHEMA,
        "campaign_id": campaign_id,
        "authority_sha256": analyzer.canonical_sha(authority),
        "authority": authority,
        "hosts": hosts,
    }
    path = directory / "result-manifest.json"
    write_new(
        path,
        (
            json.dumps(
                manifest, sort_keys=True, indent=2, ensure_ascii=True
            )
            + "\n"
        ).encode(),
    )
    return path


def run_analyzer(
    analyzer: ModuleType, qualification_root: Path, manifest: Path
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            sys.executable,
            str(Path(analyzer.__file__).resolve()),
            str(qualification_root),
            str(manifest),
        ],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def main() -> None:
    require(
        len(sys.argv) == 2,
        "usage: test_qualification_tools.py QUALIFICATION_DIRECTORY",
    )
    analyzer = load_analyzer()
    qualification_root = Path(sys.argv[1]).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="fre-tag29-result-pass-") as name:
        directory = Path(name)
        manifest = build_campaign(
            analyzer, qualification_root, directory, False
        )
        result = run_analyzer(analyzer, qualification_root, manifest)
        require(
            result.returncode == 0
            and not result.stderr
            and json.loads(result.stdout)["pass"] is True,
            "complete strict-win bundle did not pass",
        )
    with tempfile.TemporaryDirectory(
        prefix="fre-tag29-result-boundary-"
    ) as name:
        directory = Path(name)
        manifest = build_campaign(
            analyzer, qualification_root, directory, True
        )
        result = run_analyzer(analyzer, qualification_root, manifest)
        require(
            result.returncode == 1
            and not result.stderr
            and json.loads(result.stdout)["pass"] is False,
            "exact 4/5 boundary did not fail",
        )
    print(
        "qualification-tools=pass complete-cells=6156 complete-pairs=36936 "
        "strict-boundary-4/5=rejected"
    )


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, RuntimeError) as error:
        print(f"search-tag29-qualification-tools-test: {error}", file=sys.stderr)
        raise SystemExit(1)
