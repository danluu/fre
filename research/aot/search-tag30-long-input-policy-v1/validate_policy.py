#!/usr/bin/env python3
"""Validate the immutable tag-30 broad long-input policy."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
from typing import Any, Mapping


DIRECTORY = "research/aot/search-tag30-long-input-policy-v1"
FREEZE_SHA256 = (
    "70123d2c2068d9260d3a8d3face867bc01f42dbd91e82a686bf06af11b0babbb"
)
DERIVATION_SHA256 = (
    "b8690387a15655da415466943ff93726b828146e7c849266aa35907203b03671"
)
PAYLOAD_SHA256 = (
    "d6779be1b1e6694709339e48ee589c11cb4b436f831662011f3d9f9556bba0d9"
)
SUMMARY_SHA256 = (
    "985fa9ddebe98a0470ea8e7fa71e4cae9c671654069274a6d6876a5e22671b4e"
)


class Refusal(RuntimeError):
    """The checked-in freeze or its procedural derivation changed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def sha256(encoded: bytes) -> str:
    return hashlib.sha256(encoded).hexdigest()


def regular_file(path: Path, maximum: int = 2 * 1024 * 1024) -> bytes:
    status = path.lstat()
    require(
        path.is_file()
        and not path.is_symlink()
        and 0 < status.st_size <= maximum,
        f"not one bounded regular file: {path}",
    )
    return path.read_bytes()


def mapping(value: Any, label: str) -> Mapping[str, Any]:
    require(isinstance(value, dict), f"{label} is not an object")
    return value


def validate(repo: Path) -> dict[str, Any]:
    directory = repo / DIRECTORY
    freeze_bytes = regular_file(directory / "freeze-v1.json")
    derivation_bytes = regular_file(directory / "derive_projection.py")
    require(sha256(freeze_bytes) == FREEZE_SHA256, "freeze bytes changed")
    require(
        sha256(derivation_bytes) == DERIVATION_SHA256,
        "derivation bytes changed",
    )
    freeze = mapping(json.loads(freeze_bytes), "freeze")
    require(
        freeze.get("schema")
        == "fre.aot.search-tag30-long-input-policy-freeze.v1",
        "freeze schema changed",
    )
    payload = mapping(freeze.get("payload"), "payload")
    require(
        freeze.get("payload_sha256") == PAYLOAD_SHA256
        and sha256(canonical_bytes(payload)) == PAYLOAD_SHA256,
        "freeze payload changed",
    )

    status = mapping(payload.get("status"), "status")
    inputs = mapping(payload.get("inputs"), "inputs")
    policy = mapping(payload.get("policy"), "policy")
    require(
        status
        == {
            "frozen_before_tag30_results": True,
            "tag30_timing_results_observed": False,
            "production_authority_granted": False,
            "result_derived_exclusions": False,
        },
        "freeze status changed",
    )
    require(
        inputs
        == {
            "corpus_files": [],
            "benchmark_results": [],
            "rebar_files": [],
            "network": False,
            "result_derived_selection": False,
            "result_derived_exclusions": False,
        },
        "policy acquired a workload or result input",
    )
    require(
        policy.get("backend_tag") == 30
        and policy.get("backend_name") == "AsimdV17"
        and policy.get("production_input_floor_bytes") == 65_536
        and policy.get("pattern_class")
        == (
            "every phase-unique-selector-eligible exact byte literal "
            "of width 6 through 32"
        )
        and policy.get("below_floor_route") == "portable-only"
        and policy.get("admitted_route") == "tag30-static-tail"
        and policy.get("rebar_effect") == "none"
        and policy.get("llvm_codegen") is False,
        "production policy changed",
    )

    spec = importlib.util.spec_from_file_location(
        "fre_search_tag30_long_policy",
        directory / "derive_projection.py",
    )
    require(spec is not None and spec.loader is not None, "cannot load derivation")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    summary = module.generate(repo)
    require(
        sha256(canonical_bytes(summary)) == SUMMARY_SHA256,
        "derived summary changed",
    )

    derivation = mapping(payload.get("derivation"), "derivation")
    full = mapping(payload.get("full_projection"), "full projection")
    timed = mapping(payload.get("timed_projection"), "timed projection")
    gates = mapping(payload.get("gates"), "gates")
    require(
        derivation.get("sha256") == DERIVATION_SHA256
        and derivation.get("expected_summary_sha256") == SUMMARY_SHA256
        and derivation.get("parent_freeze_sha256")
        == summary["parent_freeze_sha256"]
        and derivation.get("parent_generator_sha256")
        == summary["parent_generator_sha256"],
        "derivation identity changed",
    )
    require(
        full.get("rows") == summary["full_projection"]["rows"] == 123_424
        and full.get("sha256") == summary["full_projection"]["sha256"]
        and full.get("portable_only_rows") == 100_096
        and full.get("tag30_static_tail_rows") == 23_328,
        "full projection identity changed",
    )
    derived_timed = summary["timed_projection"]
    require(
        timed.get("rows") == derived_timed["rows"] == 1_458
        and timed.get("sha256") == derived_timed["sha256"]
        and timed.get("unique_literals")
        == derived_timed["unique_literal_sha256s"]
        == 808
        and timed.get("unique_literal_set_sha256")
        == derived_timed["unique_literal_set_sha256"]
        and timed.get("mutation_classes")
        == [int(value) for value in derived_timed["mutation_class_counts"]]
        and timed.get("window_bytes")
        == [int(value) for value in derived_timed["window_counts"]],
        "timed projection identity changed",
    )
    require(
        gates.get("hosts")
        == [
            "local-apple-aarch64-asimd",
            "zstd-eval-c9g-neoverse-v3-aarch64-asimd",
        ]
        and gates.get("correctness") == summary["gates"]["correctness"]
        and gates.get("aggregate_candidate_over_portable_exclusive_maximum")
        == 0.8
        and gates.get("each_width_geomean_exclusive_maximum") == 0.8
        and gates.get("each_topology_geomean_exclusive_maximum") == 0.8
        and gates.get("each_window_geomean_exclusive_maximum") == 0.8
        and gates.get("each_outcome_geomean_exclusive_maximum") == 0.8
        and gates.get(
            "each_learned_source_kind_geomean_exclusive_maximum"
        )
        == 0.8
        and gates.get("individual_cell_inclusive_maximum") == 1.05
        and gates.get("strict_pair_win_fraction_minimum") == 0.8
        and gates.get("timing_repetitions") == 6
        and gates.get("timing_minimum_elapsed_ns_each_variant")
        == 400_000_000
        and gates.get("result_derived_exclusions") is False
        and gates.get("one_failure_rejects_whole_class") is True,
        "qualification gates changed",
    )
    return {
        "freeze_sha256": FREEZE_SHA256,
        "payload_sha256": PAYLOAD_SHA256,
        "full_rows": full["rows"],
        "full_projection_sha256": full["sha256"],
        "timed_rows": timed["rows"],
        "timed_projection_sha256": timed["sha256"],
        "unique_literals": timed["unique_literals"],
        "production_input_floor_bytes": policy["production_input_floor_bytes"],
        "rebar_accepted_as_input": False,
        "production_authority_granted": False,
    }


def main() -> None:
    repo = Path.cwd().resolve(strict=True)
    print(json.dumps(validate(repo), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, Refusal) as error:
        print(f"search-tag30-long-input-policy: {error}", file=os.sys.stderr)
        raise SystemExit(1)
