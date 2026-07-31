#!/usr/bin/env python3
"""Derive the result-blind broad long-input policy for Search tag 30."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
from collections import Counter
from pathlib import Path
from types import ModuleType
from typing import Any, Iterator, Mapping, Sequence


SCHEMA = "fre.aot.search-tag30-long-input-policy-projection.v1"
SUMMARY_SCHEMA = "fre.aot.search-tag30-long-input-policy-summary.v1"
PARENT_DIRECTORY = "research/aot/search-tag30-learned-continuation-v1"
PARENT_FREEZE_SHA256 = (
    "367ad3655ec2f70d4a8173f68df76013fdf32dd95e07d1ebeeedb14c580b817f"
)
PARENT_GENERATOR_SHA256 = (
    "63a32488f9ac108bcc6cc5b245c4bbaea59056703787c3f40244e7b62e0b203e"
)
PROJECTION_DOMAIN = b"FRE-SEARCH-TAG30-LONG-INPUT-POLICY-PROJECTION\0\x01"
ROW_DOMAIN = b"FRE-SEARCH-TAG30-LONG-INPUT-POLICY-ROW\0\x01"
PRODUCTION_INPUT_FLOOR = 65_536
EXPECTED_FULL_ROWS = 123_424
EXPECTED_TIMED_ROWS = 1_458
EXPECTED_STATIC_ROWS = 23_328
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class Refusal(RuntimeError):
    """The immutable parent projection or derived policy changed."""


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


def load_parent(repo: Path) -> ModuleType:
    parent = repo / PARENT_DIRECTORY
    freeze_bytes = regular_file(parent / "freeze-v1.json")
    generator_bytes = regular_file(parent / "generate_projection.py")
    require(sha256(freeze_bytes) == PARENT_FREEZE_SHA256, "parent freeze changed")
    require(
        sha256(generator_bytes) == PARENT_GENERATOR_SHA256,
        "parent generator changed",
    )
    freeze = json.loads(freeze_bytes)
    require(
        freeze.get("schema")
        == "fre.aot.search-tag30-learned-continuation-freeze.v1",
        "parent freeze schema changed",
    )
    status = freeze.get("status")
    inputs = freeze.get("inputs")
    require(
        isinstance(status, dict)
        and status.get("tag30_frozen_before_results") is True
        and status.get("tag30_timing_results_observed") is False
        and status.get("production_authority_granted") is False,
        "parent is not a pre-result non-authority freeze",
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
        "parent acquired a workload or result input",
    )
    spec = importlib.util.spec_from_file_location(
        "fre_search_tag30_parent_projection",
        parent / "generate_projection.py",
    )
    require(spec is not None and spec.loader is not None, "cannot load parent")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def policy_row(base_row: Mapping[str, Any]) -> dict[str, Any]:
    base_row_sha256 = base_row.get("row_sha256")
    require(
        isinstance(base_row_sha256, str) and HEX64.fullmatch(base_row_sha256),
        "parent row identity changed",
    )
    compiler_admitted = base_row.get("expected_compiler_disposition") == "tag30-object"
    input_bytes = base_row.get("window_bytes")
    require(
        isinstance(input_bytes, int) and not isinstance(input_bytes, bool),
        "parent window changed",
    )
    production_eligible = compiler_admitted and input_bytes >= PRODUCTION_INPUT_FLOOR
    row = dict(base_row)
    row["schema"] = SCHEMA
    row["parent_schema"] = base_row.get("schema")
    row["parent_row_sha256"] = base_row_sha256
    row["parent_expected_route"] = base_row.get("expected_route")
    row["row_sha256"] = sha256(
        ROW_DOMAIN + bytes.fromhex(base_row_sha256)
    )
    row["production_input_floor_bytes"] = PRODUCTION_INPUT_FLOOR
    row["production_eligible"] = production_eligible
    row["expected_route"] = (
        "tag30-static-tail" if production_eligible else "portable-only"
    )
    row["expected_static_invoked"] = production_eligible
    return row


class ProjectionDigest:
    def __init__(self, output: Path | None) -> None:
        self.digest = hashlib.sha256(PROJECTION_DOMAIN)
        self.count = 0
        self.stream = None
        if output is not None:
            output.parent.mkdir(parents=True, exist_ok=True)
            self.stream = output.open("xb")

    def add(self, row: Mapping[str, Any]) -> None:
        encoded = canonical_bytes(row) + b"\n"
        self.digest.update(len(encoded).to_bytes(8, "little"))
        self.digest.update(encoded)
        if self.stream is not None:
            self.stream.write(encoded)
        self.count += 1

    def finish(self) -> tuple[int, str]:
        if self.stream is not None:
            self.stream.flush()
            os.fsync(self.stream.fileno())
            self.stream.close()
        return self.count, self.digest.hexdigest()


def generate(
    repo: Path,
    full_output: Path | None = None,
    timed_output: Path | None = None,
) -> dict[str, Any]:
    parent = load_parent(repo)
    parent.authenticate_selector(repo)
    full = ProjectionDigest(full_output)
    timed = ProjectionDigest(timed_output)
    routes: Counter[str] = Counter()
    widths: Counter[int] = Counter()
    topologies: Counter[str] = Counter()
    mutations: Counter[int] = Counter()
    windows: Counter[int] = Counter()
    outcomes: Counter[str] = Counter()
    source_kinds: Counter[str] = Counter()
    phases: Counter[int] = Counter()
    primary_classes: Counter[int] = Counter()
    prefixes: Counter[int] = Counter()
    physical_alignments: Counter[int] = Counter()
    mappings: Counter[str] = Counter()
    literal_keys: set[tuple[int, str, int, str]] = set()
    literal_digest = hashlib.sha256(PROJECTION_DOMAIN + b"LITERALS\0")
    unique_literal_sha256s: set[str] = set()
    unique_literal_digest = hashlib.sha256(
        PROJECTION_DOMAIN + b"UNIQUE-LITERAL-SHA256S\0"
    )

    for base_row in parent.full_rows():
        row = policy_row(base_row)
        full.add(row)
        routes[row["expected_route"]] += 1
        if parent.is_timed_row(base_row) and row["production_eligible"]:
            timed.add(row)
            widths[row["literal_bytes"]] += 1
            topologies[row["topology"]] += 1
            mutations[row["mutation_class"]] += 1
            windows[row["window_bytes"]] += 1
            outcomes[row["outcome"]] += 1
            source_kinds[row["learned_source_kind"]] += 1
            phases[row["literal_phase_class"]] += 1
            primary_classes[row["selector_primary_offset_class"]] += 1
            prefixes[row["logical_prefix_bytes"]] += 1
            physical_alignments[
                row["expected_physical_window_start_mod16"]
            ] += 1
            mappings[
                "right-guarded" if row["right_guarded"] else "right-padded"
            ] += 1
            literal_key = (
                row["literal_bytes"],
                row["topology"],
                row["literal_phase_class"],
                row["literal_sha256"],
            )
            if literal_key not in literal_keys:
                literal_keys.add(literal_key)
                encoded = canonical_bytes(literal_key)
                literal_digest.update(len(encoded).to_bytes(8, "little"))
                literal_digest.update(encoded)
            literal_sha256 = row["literal_sha256"]
            if literal_sha256 not in unique_literal_sha256s:
                unique_literal_sha256s.add(literal_sha256)
                encoded = bytes.fromhex(literal_sha256)
                unique_literal_digest.update(len(encoded).to_bytes(8, "little"))
                unique_literal_digest.update(encoded)

    full_count, full_sha256 = full.finish()
    timed_count, timed_sha256 = timed.finish()
    require(full_count == EXPECTED_FULL_ROWS, "full row count changed")
    require(timed_count == EXPECTED_TIMED_ROWS, "timed row count changed")
    require(
        routes
        == Counter(
            {
                "portable-only": EXPECTED_FULL_ROWS - EXPECTED_STATIC_ROWS,
                "tag30-static-tail": EXPECTED_STATIC_ROWS,
            }
        ),
        "production routes changed",
    )
    require(
        set(widths) == set(parent.ELIGIBLE_WIDTHS)
        and set(topologies) == set(parent.ELIGIBLE_TOPOLOGIES)
        and set(phases) == set(parent.LITERAL_PHASE_CLASSES)
        and set(primary_classes) == set(range(5))
        and set(prefixes) == set(parent.ALIGNMENTS)
        and set(physical_alignments) == set(parent.ALIGNMENTS)
        and set(outcomes) == {"absent", "tail-hit"}
        and set(source_kinds).issuperset(parent.SOURCE_KINDS)
        and all(
            source in parent.SOURCE_KINDS
            or source.endswith("-absent-fallback")
            for source in source_kinds
        ),
        "broad timing coverage changed",
    )
    require(
        all(count == len(parent.ELIGIBLE_TOPOLOGIES) * len(mutations)
            for count in widths.values())
        and all(count == len(parent.ELIGIBLE_WIDTHS) * len(mutations)
                for count in topologies.values()),
        "width/topology balance changed",
    )
    return {
        "schema": SUMMARY_SCHEMA,
        "parent_freeze_sha256": PARENT_FREEZE_SHA256,
        "parent_generator_sha256": PARENT_GENERATOR_SHA256,
        "production_input_floor_bytes": PRODUCTION_INPUT_FLOOR,
        "inputs": {
            "corpus_files": [],
            "benchmark_results": [],
            "rebar_files": [],
            "network": False,
            "result_derived_selection": False,
            "result_derived_exclusions": False,
        },
        "full_projection": {
            "rows": full_count,
            "sha256": full_sha256,
            "route_counts": dict(sorted(routes.items())),
        },
        "timed_projection": {
            "rows": timed_count,
            "sha256": timed_sha256,
            "structural_literal_inventory_rows": len(literal_keys),
            "structural_literal_inventory_sha256": literal_digest.hexdigest(),
            "unique_literal_sha256s": len(unique_literal_sha256s),
            "unique_literal_set_sha256": unique_literal_digest.hexdigest(),
            "width_counts": dict(sorted(widths.items())),
            "topology_counts": dict(sorted(topologies.items())),
            "mutation_class_counts": dict(sorted(mutations.items())),
            "window_counts": dict(sorted(windows.items())),
            "outcome_counts": dict(sorted(outcomes.items())),
            "learned_source_kind_counts": dict(sorted(source_kinds.items())),
            "literal_phase_class_counts": dict(sorted(phases.items())),
            "selector_primary_offset_class_counts": dict(
                sorted(primary_classes.items())
            ),
            "logical_prefix_counts": dict(sorted(prefixes.items())),
            "physical_window_start_mod16_counts": dict(
                sorted(physical_alignments.items())
            ),
            "mapping_counts": dict(sorted(mappings.items())),
        },
        "gates": {
            "correctness": "every full-projection row on both hosts",
            "aggregate_candidate_over_portable_exclusive_maximum": 0.80,
            "each_width_geomean_exclusive_maximum": 0.80,
            "each_topology_geomean_exclusive_maximum": 0.80,
            "each_window_geomean_exclusive_maximum": 0.80,
            "each_outcome_geomean_exclusive_maximum": 0.80,
            "each_learned_source_kind_geomean_exclusive_maximum": 0.80,
            "individual_cell_inclusive_maximum": 1.05,
            "strict_pair_win_fraction_minimum": 0.80,
            "timing_repetitions": 6,
            "timing_minimum_elapsed_ns_each_variant": 400_000_000,
            "every_platform": True,
            "result_derived_exclusions": False,
        },
    }


def parse_arguments(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--full-output", type=Path)
    parser.add_argument("--timed-output", type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str]) -> None:
    arguments = parse_arguments(argv)
    summary = generate(
        arguments.repo.resolve(strict=True),
        arguments.full_output,
        arguments.timed_output,
    )
    print(json.dumps(summary, sort_keys=True, indent=2))


if __name__ == "__main__":
    try:
        main(os.sys.argv[1:])
    except (OSError, ValueError, TypeError, KeyError, Refusal) as error:
        print(f"search-tag30-long-input-policy: {error}", file=os.sys.stderr)
        raise SystemExit(1)
