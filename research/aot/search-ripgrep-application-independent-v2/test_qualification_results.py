#!/usr/bin/env python3
"""Synthetic completeness and exact-threshold tests for the application gate."""

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
    return sha256(label.encode())


def canonical_line(value: Any) -> bytes:
    return (
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        + "\n"
    ).encode()


def write_new(path: Path, encoded: bytes) -> None:
    with path.open("xb") as output:
        output.write(encoded)
        output.flush()


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


def elapsed(
    route_class: str, mode: str, first_of_class: bool, pair_index: int
) -> tuple[int, int]:
    portable = 600_000_000 + pair_index * 1_000_000
    if route_class == "tag29-static-tail":
        candidate = 450_000_000 + pair_index * 750_000
        if mode == "static-boundary" and first_of_class:
            candidate = portable * 4 // 5
    else:
        candidate = portable * 21 // 20
        if mode == "fallback-over" and first_of_class:
            candidate += 1
    return portable, candidate


def case_record(
    analyzer: ModuleType,
    campaign_id: str,
    expected: dict[str, Any],
    ordinal: int,
    host_index: int,
    mode: str,
    first_of_class: bool,
) -> dict[str, Any]:
    eligible = expected["structural_class"] == "tag29-object"
    base = 0x10_0000_0000 + ordinal * 0x20_0000
    start = 16 + expected["alignment_offset"]
    checked = base + start
    route = analyzer.candidate_route(expected["route_class"])
    static_invocations = analyzer.candidate_static_invocations(
        expected["route_class"]
    )
    iteration_count = 2000 + ordinal % 11
    output = (
        int(expected["case_id"][:16], 16) ^ iteration_count
    ) & ((1 << 64) - 1)
    cpu = 4 + host_index
    affinity = identity(f"affinity:{host_index}:{ordinal}")
    admission = identity(f"admission:{host_index}:{ordinal}")
    pairs = []
    for pair_index in range(analyzer.REPETITIONS):
        portable_ns, candidate_ns = elapsed(
            expected["route_class"], mode, first_of_class, pair_index
        )
        pairs.append(
            {
                "pair_index": pair_index,
                "first_variant": (
                    "portable" if pair_index % 2 == 0 else "candidate"
                ),
                "iteration_count": iteration_count,
                "storage_pointer_address": base,
                "checked_pointer_address": checked,
                "logical_cpu": cpu,
                "cpu_before": cpu,
                "cpu_after": cpu,
                "affinity_receipt_sha256": affinity,
                "admission_receipt_sha256": admission,
                "portable": {
                    "elapsed_ns": portable_ns,
                    "output_accumulator": output,
                    "last_span": expected["expected_span"],
                    "nonoverlapping_count": expected["expected_count"],
                    "route": "full-portable",
                },
                "candidate": {
                    "elapsed_ns": candidate_ns,
                    "output_accumulator": output,
                    "last_span": expected["expected_span"],
                    "nonoverlapping_count": expected["expected_count"],
                    "route": route,
                },
            }
        )
    return {
        "schema": analyzer.CASE_SCHEMA,
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
        "compiler": {
            "backend_tag": 29,
            "backend_version": "SEARCH_V16",
            "candidate_policy": 15,
            "disposition": expected["structural_class"],
            "compile_receipt_sha256": identity(
                f"compile:{host_index}:{expected['candidate_sha256']}"
            ),
            "object_sha256": (
                identity(
                    f"object:{host_index}:{expected['candidate_sha256']}"
                )
                if eligible
                else None
            ),
            "refusal_receipt_sha256": (
                None
                if eligible
                else identity(
                    f"refusal:{host_index}:{expected['candidate_sha256']}"
                )
            ),
        },
        "precheck": {
            "scalar_span": expected["expected_span"],
            "portable_span": expected["expected_span"],
            "candidate_span": expected["expected_span"],
            "scalar_nonoverlapping_count": expected["expected_count"],
            "portable_nonoverlapping_count": expected["expected_count"],
            "candidate_nonoverlapping_count": expected["expected_count"],
            "portable_route": "full-portable",
            "candidate_route": route,
            "portable_static_invocations": 0,
            "candidate_static_invocations": static_invocations,
        },
        "mapping": {
            "storage_pointer_address": base,
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
                f"allocation:{host_index}:{ordinal}"
            ),
        },
        "timing_setup": {
            "fixture_materialization_outside_timing": True,
            "compile_link_adoption_outside_timing": True,
            "pilot_outside_timing": True,
            "route_instrumentation_outside_timing": True,
            "timed_function_identity_sha256": identity(
                "ordinary-production-application-auto-route-v2"
            ),
        },
        "pairs": pairs,
    }


def build_bundle(
    analyzer: ModuleType,
    directory: Path,
    authority: dict[str, Any],
    campaign_id: str,
    cases: list[dict[str, Any]],
    expected_host: dict[str, Any],
    host_index: int,
    mode: str,
) -> dict[str, Any]:
    receipts = {
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
        "canonical_host": expected_host["canonical_name"],
        "target_triple": expected_host["target_triple"],
        "features": expected_host["features"],
        **receipts,
        "runner_source_commit": authority["runner"]["source_commit"],
        "runner_source_set_sha256": authority["runner"][
            "source_set_sha256"
        ],
        "object_manifest_sha256": analyzer.FIXTURE_MANIFEST_SHA256,
        "fixture_manifest_sha256": analyzer.FIXTURE_MANIFEST_SHA256,
        "case_records": analyzer.CASES,
        "pairs": analyzer.PAIRS_PER_HOST,
        "measurements": analyzer.MEASUREMENTS_PER_HOST,
    }
    prefix = bytearray(canonical_line(header))
    seen_classes = set()
    for ordinal, expected in enumerate(cases):
        first_of_class = expected["route_class"] not in seen_classes
        seen_classes.add(expected["route_class"])
        prefix.extend(
            canonical_line(
                case_record(
                    analyzer,
                    campaign_id,
                    expected,
                    ordinal,
                    host_index,
                    mode,
                    first_of_class,
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
    relative = f"{expected_host['canonical_name']}.jsonl"
    write_new(directory / relative, encoded)
    return {
        "canonical_name": expected_host["canonical_name"],
        "target_triple": expected_host["target_triple"],
        "features": expected_host["features"],
        **receipts,
        "bundle": {
            "path": relative,
            "bytes": len(encoded),
            "sha256": sha256(encoded),
            "case_records": analyzer.CASES,
            "pairs": analyzer.PAIRS_PER_HOST,
            "measurements": analyzer.MEASUREMENTS_PER_HOST,
        },
    }


def build_campaign(
    analyzer: ModuleType,
    repo: Path,
    fixture_root: Path,
    directory: Path,
    mode: str,
) -> Path:
    cases, _ = analyzer.load_cases(repo, fixture_root)
    analyzer_sha = sha256(Path(analyzer.__file__).resolve().read_bytes())
    authority = {
        "campaign_name": "search-tag29-ripgrep-application-v2",
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
            "object_manifest_sha256": analyzer.FIXTURE_MANIFEST_SHA256,
            "object_manifest_payload_sha256": (
                analyzer.FIXTURE_MANIFEST_PAYLOAD_SHA256
            ),
            "backend_tag": 29,
            "backend_version": "SEARCH_V16",
            "candidate_policy": 15,
            "llvm": False,
            "ordinary_candidate_entry": (
                "production-auto-route-portable-prefix-static-tail-or-fallback"
            ),
            "baseline_entry": "forced-full-portable",
        },
        "hosts": [host["canonical_name"] for host in analyzer.HOSTS],
        "performance_authority": {
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
        },
        "rebar_inputs": [],
        "benchmark_result_inputs": [],
        "network": False,
        "result_derived_exclusions": False,
    }
    campaign_id = analyzer.campaign_id(authority)
    hosts = [
        build_bundle(
            analyzer,
            directory,
            authority,
            campaign_id,
            cases,
            expected_host,
            host_index,
            mode,
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


def run(
    analyzer: ModuleType,
    repo: Path,
    ripgrep_root: Path,
    fixture_root: Path,
    manifest: Path,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            sys.executable,
            str(Path(analyzer.__file__).resolve()),
            str(repo),
            str(ripgrep_root),
            str(fixture_root),
            str(manifest),
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
    expectations = {
        "pass": 0,
        "static-boundary": 1,
        "fallback-over": 1,
    }
    for mode, expected_code in expectations.items():
        with tempfile.TemporaryDirectory(
            prefix=f"fre-tag29-app-{mode}-"
        ) as name:
            manifest = build_campaign(
                analyzer, repo, fixture_root, Path(name), mode
            )
            result = run(
                analyzer, repo, ripgrep_root, fixture_root, manifest
            )
            require(
                result.returncode == expected_code
                and not result.stderr
                and json.loads(result.stdout)["pass"]
                is (expected_code == 0),
                f"application analyzer mode failed: {mode}",
            )
    print(
        "application-qualification-tools=pass cases=308 pairs=1848 "
        "static-boundary-4/5=rejected nontarget-boundary-21/20=accepted "
        "nontarget-over-21/20=rejected"
    )


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, RuntimeError) as error:
        print(f"search-tag29-application-tools-test: {error}", file=sys.stderr)
        raise SystemExit(1)
