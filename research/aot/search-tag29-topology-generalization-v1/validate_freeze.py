#!/usr/bin/env python3
"""Recompute and validate the pre-result tag-29 topology freeze."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


class Refusal(RuntimeError):
    """The checked-in freeze differs from the deterministic projection."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def regular_file(path: Path, maximum: int = 2 * 1024 * 1024) -> bytes:
    status = path.lstat()
    require(
        status.st_size > 0
        and status.st_size <= maximum
        and path.is_file()
        and not path.is_symlink(),
        f"not one bounded regular file: {path}",
    )
    return path.read_bytes()


def load_generator(path: Path):
    specification = importlib.util.spec_from_file_location(
        "_fre_search_tag29_topology_generator", path
    )
    require(
        specification is not None and specification.loader is not None,
        "cannot load projection generator",
    )
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def main() -> None:
    directory = Path(__file__).resolve().parent
    repo = directory.parents[2]
    freeze_path = directory / "freeze-v1.json"
    freeze_bytes = regular_file(freeze_path)
    freeze: dict[str, Any] = json.loads(freeze_bytes)
    require(
        set(freeze)
        == {
            "schema",
            "status",
            "generator",
            "selector",
            "inputs",
            "full_projection",
            "timed_projection",
            "dimensions",
            "rebar",
        }
        and freeze["schema"] == "fre.aot.search-tag29-topology-freeze.v1",
        "freeze schema or fields changed",
    )
    generator_path = repo / freeze["generator"]["path"]
    generator_bytes = regular_file(generator_path)
    require(
        hashlib.sha256(generator_bytes).hexdigest()
        == freeze["generator"]["sha256"],
        "projection generator source changed",
    )
    generator = load_generator(generator_path)
    summary = generator.generate(repo)
    require(
        summary["selector_contract_sha256"]
        == freeze["selector"]["contract_sha256"]
        and summary["selector_payload_sha256"]
        == freeze["selector"]["payload_sha256"],
        "selector authority changed",
    )
    expected_full = freeze["full_projection"]
    actual_full = summary["full_projection"]
    require(
        actual_full["rows"] == expected_full["rows"]
        and actual_full["sha256"] == expected_full["sha256"]
        and actual_full["literal_inventory_rows"]
        == expected_full["literal_inventory_rows"]
        and actual_full["literal_inventory_sha256"]
        == expected_full["literal_inventory_sha256"]
        and actual_full["expected_routes"]
        == {
            "portable-only": expected_full["portable_only_rows"],
            "tag29-static-tail": expected_full["tag29_static_tail_rows"],
        },
        "full correctness projection changed",
    )
    expected_timed = freeze["timed_projection"]
    actual_timed = summary["timed_projection"]
    frozen_count_fields = {
        "width_counts",
        "topology_counts",
        "learned_source_kind_counts",
        "learned_source_relation_counts",
        "topology_relation_counts",
        "literal_phase_class_counts",
        "selector_primary_offset_class_counts",
        "logical_prefix_counts",
        "mapping_counts",
        "physical_window_start_mod16_counts",
        "physical_window_start_mod16_counts_by_mapping",
        "window_counts",
    }
    exact_counts = expected_timed["exact_stratification_counts"]
    require(
        actual_timed["rows"] == expected_timed["rows"]
        and actual_timed["sha256"] == expected_timed["sha256"]
        and set(exact_counts) == frozen_count_fields
        and all(
            json.loads(
                json.dumps(
                    actual_timed[field],
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            == exact_counts[field]
            for field in frozen_count_fields
        ),
        "timed stratified projection changed",
    )
    require(
        freeze["inputs"]
        == {
            "corpus_files": [],
            "benchmark_results": [],
            "rebar_files": [],
            "network": False,
            "result_derived_selection": False,
            "result_derived_exclusions": False,
        }
        and freeze["rebar"]
        == {
            "read_during_generation": False,
            "affects_membership": False,
            "affects_gates": False,
            "affects_promotion": False,
            "permitted_use": (
                "post-freeze, post-promotion corroboration only"
            ),
        },
        "result/Rebar feedback boundary changed",
    )
    print(
        json.dumps(
            {
                "freeze_sha256": hashlib.sha256(freeze_bytes).hexdigest(),
                "full_rows": actual_full["rows"],
                "full_projection_sha256": actual_full["sha256"],
                "timed_rows": actual_timed["rows"],
                "timed_projection_sha256": actual_timed["sha256"],
                "rebar_accepted_as_input": False,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, Refusal) as error:
        print(f"search-tag29-topology-freeze: {error}", file=sys.stderr)
        raise SystemExit(1)
