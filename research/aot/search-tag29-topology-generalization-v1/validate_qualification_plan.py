#!/usr/bin/env python3
"""Independently reconstruct and scalar-check every tag-29 topology row."""

from __future__ import annotations

import hashlib
import json
import math
import stat
import sys
from collections import Counter
from pathlib import Path
from typing import Any, BinaryIO, Iterator


PLAN_SCHEMA = "fre.aot.search-tag29-topology-qualification-plan.v1"
OBJECT_SCHEMA = "fre.aot.search-tag29-topology-object-candidates.v1"
DISPOSITION_SCHEMA = "fre.aot.search-tag29-topology-literal-dispositions.v1"
ROW_SCHEMA = "fre.aot.search-tag29-topology-projection.v1"
FREEZE_SHA256 = (
    "9f6ba2af9ff7e2296f65dc20b4386d68ddd5ea41837814a1b6b4c3ee2faf4856"
)
GENERATOR_SHA256 = (
    "35aacbca100dde74a2ead493ceab1197c813d37c17d5f4a9d3e62938c3a2b610"
)
SELECTOR_SHA256 = (
    "38ca5ebc1b239b541afcf9eeb679bf8b156c8690e7422a96f69a9457a155daf0"
)
FULL_PROJECTION_DIGEST = (
    "5d548159e8c93d6ddb8d57847e01cc97ea2b661f736b2e8a126df6cd35cf612f"
)
TIMED_PROJECTION_DIGEST = (
    "72d85a032a90e4347be2d537c2ff11bac15016787c055332843f143da72e487f"
)
FULL_ROWS = 123_424
TIMED_ROWS = 3_078
UNIQUE_LITERALS = 922
ELIGIBLE_LITERALS = 808
INELIGIBLE_LITERALS = 114
PLAN_SHA256 = (
    "84230b412df4572a8d010ee93dc219e9d9db707f7782909d5efee70d9a1d929f"
)
PLAN_PAYLOAD_SHA256 = (
    "e569e9079c81511c3c9707a83fe9bbe9b9ce2d4362ae436e2587d3c32ec7e2d7"
)
FULL_FILE_SHA256 = (
    "cf20fffc3cf3edea3994a627e6c254dba5b14aea8be2ab2017306c4d4c40ffa7"
)
TIMED_FILE_SHA256 = (
    "0844b3c566959142fc32a8232bee0660b3c675a04622d3b79ee39e395756994f"
)
SUMMARY_FILE_SHA256 = (
    "5fa4bb549489b69ce8de989f3919b8e73d47b295e804d9449d1e9f54e6da347e"
)
OBJECT_FILE_SHA256 = (
    "90b9eb70dff30e36901b86ecff34ba91938f27afa155ebb17f6daa33d3baca2c"
)
OBJECT_PAYLOAD_SHA256 = (
    "772d7e03b9c2f1d2ef7ccf40ef248e10f46c66153d08ba686351bf580c49c6cd"
)
DISPOSITION_FILE_SHA256 = (
    "a6204205fcfd87faf8bf8d6c2a5c53859ad68e81979ba8e47626afbabdd4ee4d"
)
DISPOSITION_PAYLOAD_SHA256 = (
    "b4855d3d4cfa53cc60164c8f9adc5e70511c986831a84d401043ee121b3bef88"
)
PROJECTION_DOMAIN = b"FRE-SEARCH-TAG29-TOPOLOGY-PROJECTION\0\x01"
ROW_DOMAIN = b"FRE-SEARCH-TAG29-TOPOLOGY-ROW\0\x01"
CANDIDATE_DOMAIN = b"FRE-SEARCH-TAG29-TOPOLOGY-CANDIDATE\0\x01"
ELIGIBLE_TOPOLOGIES = (
    "high-entropy-distinct",
    "binary-aperiodic",
    "ternary-aperiodic",
    "rare-markers-common-fill",
    "common-markers-rare-fill",
    "terminal-repeated-high-entropy",
)
ALL_TOPOLOGIES = (*ELIGIBLE_TOPOLOGIES, "periodic-or-uniform-refusal")
SOURCE_KINDS = ("absent", "primary", "secondary", "terminal", "mode")
ROW_FIELDS = {
    "schema",
    "row_sha256",
    "literal_sha256",
    "literal_hex",
    "literal_bytes",
    "topology",
    "literal_phase_class",
    "selector_primary_offset_class",
    "selected_offsets",
    "selector_eligible",
    "mutation_class",
    "mutation_offset",
    "mutation_column",
    "learned_source_kind",
    "learned_source_byte",
    "learned_source_relations",
    "near_miss_hex",
    "logical_prefix_bytes",
    "size_class",
    "window_bytes",
    "candidate_starts",
    "outcome",
    "expected_match_start",
    "expected_match_end",
    "expected_route",
    "expected_compiler_disposition",
    "expected_static_invoked",
    "right_guarded",
    "expected_physical_window_start_mod16",
    "fixture_recipe",
}


class Refusal(RuntimeError):
    """An execution plan, projection row, or scalar fixture changed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def sha256(encoded: bytes) -> str:
    return hashlib.sha256(encoded).hexdigest()


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def canonical_sha(value: Any) -> str:
    return sha256(canonical_bytes(value))


def regular_file(path: Path, maximum: int = 512 * 1024 * 1024) -> bytes:
    status = path.lstat()
    require(
        stat.S_ISREG(status.st_mode)
        and not path.is_symlink()
        and 0 < status.st_size <= maximum,
        f"not one bounded regular file: {path}",
    )
    return path.read_bytes()


def file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def canonical_relative(value: str) -> bool:
    return (
        bool(value)
        and not value.startswith("/")
        and "\\" not in value
        and all(part not in {"", ".", ".."} for part in value.split("/"))
    )


def parse_envelope(
    path: Path, schema: str, expected_sha256: str
) -> dict[str, Any]:
    encoded = regular_file(path)
    require(sha256(encoded) == expected_sha256, f"changed file: {path.name}")
    root = json.loads(encoded)
    require(
        isinstance(root, dict)
        and set(root) == {"schema", "payload_sha256", "payload"}
        and root["schema"] == schema
        and canonical_sha(root["payload"]) == root["payload_sha256"],
        f"invalid envelope: {path.name}",
    )
    return root


class ProjectionReader:
    def __init__(self, path: Path) -> None:
        status = path.lstat()
        require(
            stat.S_ISREG(status.st_mode)
            and not path.is_symlink()
            and 0 < status.st_size <= 512 * 1024 * 1024,
            f"projection is not one bounded file: {path}",
        )
        self.path = path
        self.source: BinaryIO = path.open("rb")
        self.digest = hashlib.sha256(PROJECTION_DOMAIN)
        self.rows = 0

    def __iter__(self) -> Iterator[dict[str, Any]]:
        for line in self.source:
            self.rows += 1
            require(
                line.endswith(b"\n") and 1 < len(line) <= 16 * 1024,
                f"{self.path.name}: invalid line {self.rows}",
            )
            row = json.loads(line)
            require(
                canonical_bytes(row) + b"\n" == line,
                f"{self.path.name}: noncanonical row {self.rows}",
            )
            self.digest.update(len(line).to_bytes(8, "little"))
            self.digest.update(line)
            yield row

    def finish(self, expected_rows: int, expected_digest: str) -> None:
        self.source.close()
        require(
            self.rows == expected_rows
            and self.digest.hexdigest() == expected_digest,
            f"{self.path.name}: row count or projection digest changed",
        )


def expected_timed(row: dict[str, Any]) -> bool:
    if (
        row["literal_bytes"] < 6
        or row["literal_bytes"] > 32
        or row["topology"] not in ELIGIBLE_TOPOLOGIES
        or row["size_class"] != "long"
    ):
        return False
    topology_index = ELIGIBLE_TOPOLOGIES.index(row["topology"])
    expected_prefix = (
        row["literal_bytes"] * 11
        + topology_index * 5
        + row["mutation_class"] * 7
    ) % 16
    return row["logical_prefix_bytes"] == expected_prefix


def literal_identity(literal: bytes) -> str:
    return sha256(CANDIDATE_DOMAIN + literal)


def overlapping_starts(
    haystack: bytes | bytearray, literal: bytes, start: int, end: int
) -> list[int]:
    matches = []
    cursor = start
    while cursor + len(literal) <= end:
        found = haystack.find(literal, cursor, end)
        if found < 0:
            break
        matches.append(found)
        cursor = found + 1
    return matches


def validate_and_materialize(row: dict[str, Any]) -> str:
    require(
        isinstance(row, dict)
        and set(row) == ROW_FIELDS
        and row["schema"] == ROW_SCHEMA,
        "projection row schema changed",
    )
    width = row["literal_bytes"]
    literal = bytes.fromhex(row["literal_hex"])
    near_miss = bytes.fromhex(row["near_miss_hex"])
    offsets = row["selected_offsets"]
    mutation_class = row["mutation_class"]
    prefix = row["logical_prefix_bytes"]
    window_bytes = row["window_bytes"]
    window_start = prefix
    window_end = prefix + window_bytes
    sentinel = row["fixture_recipe"]["background_byte"]
    require(
        isinstance(width, int)
        and 4 <= width <= 32
        and len(literal) == width
        and sha256(literal) == row["literal_sha256"]
        and len(near_miss) == width
        and sum(
            left != right
            for left, right in zip(literal, near_miss, strict=True)
        )
        == 1
        and near_miss[row["mutation_offset"]] == row["learned_source_byte"]
        and sentinel not in literal
        and row["topology"] in ALL_TOPOLOGIES
        and row["literal_phase_class"] in range(5)
        and row["selector_primary_offset_class"] == offsets[0] % 5
        and len(offsets) in {4, 5}
        and len(set(offsets)) == len(offsets)
        and all(offset in range(width) for offset in offsets)
        and mutation_class in range(19)
        and row["learned_source_kind"].split("-absent-fallback")[0]
        == SOURCE_KINDS[mutation_class % len(SOURCE_KINDS)]
        and prefix in range(16)
        and row["size_class"] in {"short", "long"}
        and window_bytes >= width
        and row["candidate_starts"] == window_bytes - width + 1,
        "literal, mutation, selector, or geometry invariant changed",
    )
    row_key = {
        "width": width,
        "topology": row["topology"],
        "mutation_class": mutation_class,
        "geometry_index": (
            (0 if row["size_class"] == "short" else 16) + prefix
        ),
    }
    require(
        sha256(ROW_DOMAIN + canonical_bytes(row_key)) == row["row_sha256"],
        "row identity changed",
    )
    expected_eligible = (
        6 <= width <= 32
        and row["topology"] != "periodic-or-uniform-refusal"
    )
    require(
        row["selector_eligible"] == expected_eligible
        and row["expected_compiler_disposition"]
        == ("tag29-object" if expected_eligible else "structural-refusal")
        and row["expected_route"]
        == (
            "tag29-static-tail"
            if expected_eligible and window_bytes >= 4_093
            else "portable-only"
        )
        and row["expected_static_invoked"]
        == (row["expected_route"] == "tag29-static-tail"),
        "compiler or route disposition changed",
    )
    if row["expected_route"] == "tag29-static-tail":
        require(
            row["mutation_column"] == "unselected-learned"
            and row["mutation_offset"] not in offsets
            and all(near_miss[offset] == literal[offset] for offset in offsets),
            "timed learned-column adversary changed",
        )
    else:
        require(
            row["mutation_column"] == "general-correctness",
            "portable correctness mutation changed",
        )
    expected_outcome = "absent" if mutation_class % 3 == 0 else "tail-hit"
    expected_start = (
        None if expected_outcome == "absent" else window_end - width
    )
    require(
        row["outcome"] == expected_outcome
        and row["expected_match_start"] == expected_start
        and row["expected_match_end"]
        == (None if expected_start is None else expected_start + width),
        "frozen scalar result changed",
    )
    right_guarded = row["right_guarded"]
    expected_mod16 = (-window_bytes) % 16 if right_guarded else prefix
    require(
        row["expected_physical_window_start_mod16"] == expected_mod16,
        "physical window mapping changed",
    )
    recipe = row["fixture_recipe"]
    require(
        set(recipe)
        == {
            "construction_version",
            "background_byte",
            "near_miss_tile_hex",
            "window_start",
            "window_end",
            "physical_mapping",
            "true_literal_guard_bytes",
            "steps",
            "scalar_oracle_required",
        }
        and recipe["construction_version"]
        == "near-miss-sentinel-tile-tail-v1"
        and recipe["near_miss_tile_hex"]
        == near_miss.hex() + f"{sentinel:02x}"
        and recipe["window_start"] == window_start
        and recipe["window_end"] == window_end
        and recipe["physical_mapping"]
        == (
            "place checked-window end at a page-aligned right guard"
            if right_guarded
            else "place checked-window start at the recorded mod-16 address"
        )
        and recipe["true_literal_guard_bytes"] == width - 1
        and recipe["steps"]
        == [
            "fill the checked window with the near-miss tile, truncating at window end",
            "for tail-hit, overwrite the width-1 bytes before the final candidate with the sentinel",
            "for tail-hit, install the exact literal at the final candidate start",
            "keep every byte outside the checked window equal to the sentinel",
        ]
        and recipe["scalar_oracle_required"] is True,
        "fixture recipe changed",
    )
    tile = near_miss + bytes([sentinel])
    repeats = math.ceil(window_bytes / len(tile))
    checked = bytearray((tile * repeats)[:window_bytes])
    if expected_start is not None:
        relative_start = expected_start - window_start
        guard_start = max(0, relative_start - width + 1)
        checked[guard_start:relative_start] = bytes([sentinel]) * (
            relative_start - guard_start
        )
        checked[relative_start : relative_start + width] = literal
    haystack = bytes([sentinel]) * prefix + checked
    starts = overlapping_starts(haystack, literal, window_start, window_end)
    require(
        starts == ([] if expected_start is None else [expected_start]),
        "materialized fixture differs from scalar oracle",
    )
    return literal_identity(literal)


def main() -> None:
    require(
        len(sys.argv) == 2,
        "usage: validate_qualification_plan.py QUALIFICATION_DIRECTORY",
    )
    supplied_root = Path(sys.argv[1])
    supplied_status = supplied_root.lstat()
    require(
        stat.S_ISDIR(supplied_status.st_mode) and not supplied_root.is_symlink(),
        "qualification root must be one real directory",
    )
    root = supplied_root.resolve(strict=True)
    plan_path = root / "qualification-plan.json"
    plan_bytes = regular_file(plan_path)
    plan = json.loads(plan_bytes)
    require(
        isinstance(plan, dict)
        and set(plan) == {"schema", "payload_sha256", "payload"}
        and plan["schema"] == PLAN_SCHEMA
        and sha256(plan_bytes) == PLAN_SHA256
        and plan["payload_sha256"] == PLAN_PAYLOAD_SHA256
        and canonical_sha(plan["payload"]) == plan["payload_sha256"],
        "qualification plan envelope changed",
    )
    payload = plan["payload"]
    require(
        set(payload)
        == {
            "freeze_sha256",
            "generator_sha256",
            "selector_contract_sha256",
            "inputs",
            "backend",
            "hosts",
            "full_projection",
            "timed_projection",
            "projection_summary",
            "object_candidates",
            "literal_dispositions",
            "execution",
        }
        and payload["freeze_sha256"] == FREEZE_SHA256
        and payload["generator_sha256"] == GENERATOR_SHA256
        and payload["selector_contract_sha256"] == SELECTOR_SHA256
        and payload["inputs"]
        == {
            "corpus_files": [],
            "benchmark_results": [],
            "rebar_files": [],
            "network": False,
            "result_derived_selection": False,
            "result_derived_exclusions": False,
        }
        and payload["backend"]
        == {
            "architecture": "aarch64",
            "required_isa": "OS-usable ASIMD",
            "backend_tag": 29,
            "backend_version": "SEARCH_V16",
            "candidate_policy": 15,
            "backend_name": "AsimdV16",
            "aot_magic_hex": "465245413634001d",
            "llvm": False,
        }
        and payload["hosts"]
        == {
            "local-apple-aarch64-asimd": "apple-aarch64-asimd",
            "zstd-eval-ec2-aarch64-asimd-sve2-vl16": (
                "c9g-aarch64-asimd-sve2"
            ),
        },
        "qualification authority changed",
    )
    execution = payload["execution"]
    require(
        execution
        == {
            "full_correctness_rows_per_host": FULL_ROWS,
            "timed_rows_per_host": TIMED_ROWS,
            "timing_repetitions": 6,
            "minimum_elapsed_ns_each_variant": 400_000_000,
            "pairing": (
                "same row and logical CPU, identical iterations, alternating "
                "portable/static order"
            ),
            "cell_ratio": (
                "sort six paired static/portable elapsed ratios; "
                "median=(ratio[2]+ratio[3])/2 without pre-rounding"
            ),
            "cell_gate": (
                "every timed row strictly less than 0.80 on each host"
            ),
            "result_derived_exclusions": False,
        },
        "execution completeness or gate changed",
    )
    full_receipt = payload["full_projection"]
    timed_receipt = payload["timed_projection"]
    require(
        full_receipt
        == {
            "path": "full-projection.ndjson",
            "rows": FULL_ROWS,
            "projection_digest": FULL_PROJECTION_DIGEST,
            "file_sha256": FULL_FILE_SHA256,
        }
        and timed_receipt
        == {
            "path": "timed-projection.ndjson",
            "rows": TIMED_ROWS,
            "projection_digest": TIMED_PROJECTION_DIGEST,
            "file_sha256": TIMED_FILE_SHA256,
        },
        "projection file receipt changed",
    )
    full_path = root / "full-projection.ndjson"
    timed_path = root / "timed-projection.ndjson"
    require(
        file_sha(full_path) == FULL_FILE_SHA256
        and file_sha(timed_path) == TIMED_FILE_SHA256,
        "projection file bytes changed",
    )
    object_receipt = payload["object_candidates"]
    disposition_receipt = payload["literal_dispositions"]
    require(
        object_receipt
        == {
            "path": "object-candidates.json",
            "schema": OBJECT_SCHEMA,
            "file_sha256": OBJECT_FILE_SHA256,
            "payload_sha256": OBJECT_PAYLOAD_SHA256,
            "candidate_count": ELIGIBLE_LITERALS,
        }
        and disposition_receipt
        == {
            "path": "literal-dispositions.json",
            "schema": DISPOSITION_SCHEMA,
            "file_sha256": DISPOSITION_FILE_SHA256,
            "payload_sha256": DISPOSITION_PAYLOAD_SHA256,
            "literal_count": UNIQUE_LITERALS,
            "eligible_literal_count": ELIGIBLE_LITERALS,
            "ineligible_literal_count": INELIGIBLE_LITERALS,
        },
        "object or disposition receipt fields changed",
    )
    object_manifest = parse_envelope(
        root / "object-candidates.json",
        OBJECT_SCHEMA,
        OBJECT_FILE_SHA256,
    )
    dispositions = parse_envelope(
        root / "literal-dispositions.json",
        DISPOSITION_SCHEMA,
        DISPOSITION_FILE_SHA256,
    )
    require(
        object_manifest["payload_sha256"]
        == object_receipt["payload_sha256"]
        and object_receipt["candidate_count"] == ELIGIBLE_LITERALS
        and dispositions["payload_sha256"]
        == disposition_receipt["payload_sha256"]
        and disposition_receipt["literal_count"] == UNIQUE_LITERALS
        and disposition_receipt["eligible_literal_count"]
        == ELIGIBLE_LITERALS
        and disposition_receipt["ineligible_literal_count"]
        == INELIGIBLE_LITERALS,
        "object or disposition receipt changed",
    )
    object_candidates = object_manifest["payload"]["candidates"]
    disposition_rows = dispositions["payload"]["dispositions"]
    require(
        object_manifest["payload"]
        == {
            "freeze_sha256": FREEZE_SHA256,
            "selector_contract_sha256": SELECTOR_SHA256,
            "full_projection_digest": FULL_PROJECTION_DIGEST,
            "timing_permitted": False,
            "timing_feedback_permitted": False,
            "external_inputs": [],
            "benchmark_results": [],
            "rebar_inputs": [],
            "network": False,
            "backend_tag": 29,
            "backend_version": "SEARCH_V16",
            "candidate_policy": 15,
            "backend_name": "AsimdV16",
            "llvm": False,
            "source_construction": "canonical-byte-escaped-exact",
            "candidate_count": ELIGIBLE_LITERALS,
            "candidates": object_candidates,
        }
        and dispositions["payload"]
        == {
            "freeze_sha256": FREEZE_SHA256,
            "selector_contract_sha256": SELECTOR_SHA256,
            "full_projection_digest": FULL_PROJECTION_DIGEST,
            "timing_permitted": False,
            "timing_feedback_permitted": False,
            "external_inputs": [],
            "benchmark_results": [],
            "rebar_inputs": [],
            "network": False,
            "literal_count": UNIQUE_LITERALS,
            "eligible_literal_count": ELIGIBLE_LITERALS,
            "ineligible_literal_count": INELIGIBLE_LITERALS,
            "dispositions": disposition_rows,
        },
        "object or disposition authority changed",
    )
    require(
        object_manifest["payload"]["candidate_count"] == ELIGIBLE_LITERALS
        and len(object_candidates) == ELIGIBLE_LITERALS
        and dispositions["payload"]["literal_count"] == UNIQUE_LITERALS
        and len(disposition_rows) == UNIQUE_LITERALS,
        "object or disposition cardinality changed",
    )
    expected_objects = {
        candidate["semantic_candidate_sha256"]: candidate
        for candidate in object_candidates
    }
    expected_dispositions = {
        candidate["semantic_candidate_sha256"]: candidate
        for candidate in disposition_rows
    }
    require(
        len(expected_objects) == ELIGIBLE_LITERALS
        and len(expected_dispositions) == UNIQUE_LITERALS,
        "object or disposition identity duplicated",
    )
    full_reader = ProjectionReader(full_path)
    timed_reader = ProjectionReader(timed_path)
    timed_iterator = iter(timed_reader)
    timed_count = 0
    seen_literals: dict[str, dict[str, Any]] = {}
    route_counts: Counter[str] = Counter()
    mapping_counts: Counter[str] = Counter()
    alignment_counts: Counter[int] = Counter()
    for row in full_reader:
        identity = validate_and_materialize(row)
        route_counts[row["expected_route"]] += 1
        mapping_counts[
            "right-guarded" if row["right_guarded"] else "right-padded"
        ] += 1
        alignment_counts[row["expected_physical_window_start_mod16"]] += 1
        disposition = {
            "semantic_candidate_sha256": identity,
            "literal_hex": row["literal_hex"],
            "literal_sha256": row["literal_sha256"],
            "literal_bytes": row["literal_bytes"],
            "selected_offsets": row["selected_offsets"],
            "selector_eligible": row["selector_eligible"],
            "expected_compiler_disposition": row[
                "expected_compiler_disposition"
            ],
        }
        if identity in seen_literals:
            require(
                seen_literals[identity] == disposition,
                "literal disposition varies between rows",
            )
        else:
            seen_literals[identity] = disposition
        if expected_timed(row):
            timed_row = next(timed_iterator, None)
            require(timed_row == row, "timed projection is not exact full subset")
            timed_count += 1
    require(
        next(timed_iterator, None) is None,
        "timed projection has trailing rows",
    )
    full_reader.finish(FULL_ROWS, FULL_PROJECTION_DIGEST)
    timed_reader.finish(TIMED_ROWS, TIMED_PROJECTION_DIGEST)
    require(
        timed_count == TIMED_ROWS
        and len(seen_literals) == UNIQUE_LITERALS
        and seen_literals == expected_dispositions
        and route_counts
        == Counter({"portable-only": 74_176, "tag29-static-tail": 49_248})
        and mapping_counts
        == Counter({"right-guarded": 61_712, "right-padded": 61_712})
        and set(alignment_counts) == set(range(16)),
        "full projection completeness or stratification changed",
    )
    derived_objects = {
        identity: {
            "semantic_candidate_sha256": identity,
            "literal_hex": row["literal_hex"],
            "literal_sha256": row["literal_sha256"],
            "literal_bytes": row["literal_bytes"],
        }
        for identity, row in seen_literals.items()
        if row["selector_eligible"]
    }
    require(
        derived_objects == expected_objects
        and list(seen_literals.values()) == disposition_rows
        and [
            {
                "semantic_candidate_sha256": identity,
                "literal_hex": row["literal_hex"],
                "literal_sha256": row["literal_sha256"],
                "literal_bytes": row["literal_bytes"],
            }
            for identity, row in seen_literals.items()
            if row["selector_eligible"]
        ]
        == object_candidates,
        "object candidate set differs from eligible literal set",
    )
    summary_receipt = payload["projection_summary"]
    require(
        summary_receipt
        == {
            "path": "projection-summary.json",
            "file_sha256": SUMMARY_FILE_SHA256,
        }
        and file_sha(root / "projection-summary.json")
        == SUMMARY_FILE_SHA256,
        "projection summary file receipt changed",
    )
    summary = json.loads(regular_file(root / "projection-summary.json"))
    require(
        summary["schema"]
        == "fre.aot.search-tag29-topology-freeze-summary.v1"
        and summary["selector_contract_sha256"] == SELECTOR_SHA256
        and summary["inputs"]
        == {
            "corpus_files": [],
            "benchmark_results": [],
            "rebar_files": [],
            "network": False,
        }
        and summary["full_projection"]["rows"] == FULL_ROWS
        and summary["full_projection"]["sha256"]
        == FULL_PROJECTION_DIGEST
        and summary["timed_projection"]["rows"] == TIMED_ROWS
        and summary["timed_projection"]["sha256"]
        == TIMED_PROJECTION_DIGEST,
        "projection summary changed",
    )
    print(
        f"plan_payload_sha256={plan['payload_sha256']} "
        f"full_rows={FULL_ROWS} timed_rows={TIMED_ROWS} "
        f"scalar_fixtures={FULL_ROWS} unique_literals={UNIQUE_LITERALS} "
        f"eligible_objects={ELIGIBLE_LITERALS} refusals={INELIGIBLE_LITERALS} "
        "physical_alignments=16 rebar_inputs=0 benchmark_results=0"
    )


if __name__ == "__main__":
    try:
        main()
    except (
        OSError,
        UnicodeError,
        ValueError,
        KeyError,
        TypeError,
        StopIteration,
        json.JSONDecodeError,
        Refusal,
    ) as error:
        print(f"search-tag29-qualification-plan: {error}", file=sys.stderr)
        raise SystemExit(1)
