#!/usr/bin/env python3
"""Authenticate every source-only ripgrep fixture and scalar oracle."""

from __future__ import annotations

import hashlib
import json
import stat
import sys
from pathlib import Path
from typing import Any

import materialize_fixtures as fixture


MANIFEST_SHA256 = (
    "b20181470c604d01d2ec236259293cfcb6e5eff145bcd3e4daa91554c8cebcca"
)
MANIFEST_PAYLOAD_SHA256 = (
    "1cbda700087f5506daa91b0657070cbf39fac68222ff84e273d1d83c09f6ebfd"
)


class Refusal(RuntimeError):
    """A manifest, fixture byte, or scalar oracle changed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_relative(value: str) -> bool:
    return (
        bool(value)
        and not value.startswith("/")
        and "\\" not in value
        and all(part not in {"", ".", ".."} for part in value.split("/"))
    )


def scenario_names(width: int) -> list[str]:
    return [
        *fixture.COMMON_SCENARIOS,
        *(f"near-miss-offset-{offset:02}" for offset in range(width)),
    ]


def validate_candidate(
    root: Path,
    candidate: dict[str, Any],
    expected: dict[str, Any],
    expected_files: set[str],
) -> int:
    require(
        set(candidate)
        == {
            "semantic_candidate_sha256",
            "literal_hex",
            "literal_sha256",
            "literal_bytes",
            "gate_membership",
            "fixtures",
        }
        and candidate["semantic_candidate_sha256"]
        == expected["semantic_candidate_sha256"]
        and candidate["literal_hex"] == expected["literal_hex"]
        and candidate["literal_sha256"] == expected["literal_sha256"]
        and candidate["literal_bytes"] == expected["literal_bytes"]
        and candidate["gate_membership"] == "source-derived",
        "candidate receipt changed",
    )
    literal = bytes.fromhex(candidate["literal_hex"])
    wrong_byte = fixture.absent_sentinel(literal)
    rows = candidate["fixtures"]
    names = scenario_names(len(literal))
    require(
        isinstance(rows, list)
        and len(rows) == len(names)
        and [row.get("scenario") for row in rows] == names,
        "candidate scenario set or order changed",
    )
    for row in rows:
        require(
            isinstance(row, dict)
            and set(row)
            == {
                "scenario",
                "path",
                "bytes",
                "sha256",
                "alignment_offset",
                "wrong_byte",
                "expected_leftmost_span",
                "expected_nonoverlapping_count",
            },
            "fixture receipt fields changed",
        )
        scenario = row["scenario"]
        relative = row["path"]
        require(
            canonical_relative(relative)
            and relative
            == f"{candidate['semantic_candidate_sha256']}-{scenario}.bin"
            and relative not in expected_files,
            "fixture path changed or is duplicated",
        )
        expected_files.add(relative)
        encoded = fixture.regular_file(root / relative, fixture.FIXTURE_BYTES)
        require(
            len(encoded) == row["bytes"] == fixture.FIXTURE_BYTES
            and sha256(encoded) == row["sha256"]
            and row["wrong_byte"] == wrong_byte
            and row["alignment_offset"]
            == fixture.alignment(
                candidate["semantic_candidate_sha256"], scenario
            ),
            "fixture byte or construction receipt changed",
        )
        start = encoded.find(literal)
        actual_span = (
            None if start < 0 else [start, start + len(literal)]
        )
        require(
            actual_span == row["expected_leftmost_span"]
            and fixture.nonoverlapping_count(encoded, literal)
            == row["expected_nonoverlapping_count"],
            "fixture scalar oracle changed",
        )
    return len(rows)


def main() -> None:
    require(
        len(sys.argv) == 5,
        "usage: validate_fixtures.py INVENTORY ALGORITHM RIPGREP_ROOT FIXTURE_ROOT",
    )
    inventory_path = Path(sys.argv[1])
    algorithm_path = Path(sys.argv[2])
    ripgrep_root = Path(sys.argv[3])
    root = Path(sys.argv[4])
    status = root.lstat()
    require(
        stat.S_ISDIR(status.st_mode) and not root.is_symlink(),
        "fixture root is not one real directory",
    )
    inventory = fixture.validate_inputs(
        inventory_path, algorithm_path, ripgrep_root
    )
    manifest_path = root / "manifest.json"
    manifest_bytes = fixture.regular_file(manifest_path, 8 * 1024 * 1024)
    require(
        sha256(manifest_bytes) == MANIFEST_SHA256,
        "fixture manifest bytes changed",
    )
    manifest = json.loads(manifest_bytes)
    require(
        isinstance(manifest, dict)
        and set(manifest) == {"schema", "payload_sha256", "payload"}
        and manifest["schema"] == fixture.OUTPUT_SCHEMA
        and manifest["payload_sha256"] == MANIFEST_PAYLOAD_SHA256
        and fixture.canonical_sha(manifest["payload"])
        == MANIFEST_PAYLOAD_SHA256,
        "fixture manifest envelope changed",
    )
    payload = manifest["payload"]
    require(
        set(payload)
        == {
            "source_inventory_sha256",
            "source_inventory_payload_sha256",
            "fixture_algorithm_sha256",
            "backend_identity",
            "timing_permitted",
            "external_classification_inputs",
            "candidate_count",
            "gating_candidate_count",
            "fixture_count",
            "gating_fixture_count",
            "fixture_bytes_each",
            "candidates",
        }
        and payload["source_inventory_sha256"] == fixture.INVENTORY_SHA256
        and payload["source_inventory_payload_sha256"]
        == fixture.INVENTORY_PAYLOAD_SHA256
        and payload["fixture_algorithm_sha256"]
        == fixture.ALGORITHM_SHA256
        and payload["backend_identity"]
        == "required-tag29-frozen-input"
        and payload["timing_permitted"] is False
        and payload["external_classification_inputs"] == []
        and payload["candidate_count"]
        == payload["gating_candidate_count"]
        == fixture.CANDIDATE_COUNT
        and payload["fixture_count"]
        == payload["gating_fixture_count"]
        == fixture.FIXTURE_COUNT
        and payload["fixture_bytes_each"] == fixture.FIXTURE_BYTES,
        "fixture manifest authority changed",
    )
    expected_candidates = inventory["payload"]["candidates"]
    candidates = payload["candidates"]
    require(
        isinstance(candidates, list)
        and len(candidates) == len(expected_candidates),
        "fixture candidate set changed",
    )
    expected_files = {"manifest.json"}
    fixture_count = sum(
        validate_candidate(root, candidate, expected, expected_files)
        for candidate, expected in zip(
            candidates, expected_candidates, strict=True
        )
    )
    actual_files = set()
    for entry in root.iterdir():
        entry_status = entry.lstat()
        require(
            stat.S_ISREG(entry_status.st_mode) and not entry.is_symlink(),
            "fixture root contains a non-file or symlink",
        )
        actual_files.add(entry.name)
    require(
        fixture_count == fixture.FIXTURE_COUNT
        and actual_files == expected_files,
        "fixture file set is incomplete or contains extras",
    )
    print(
        f"manifest_sha256={MANIFEST_SHA256} "
        f"payload_sha256={MANIFEST_PAYLOAD_SHA256} "
        "candidates=11 gating-candidates=11 fixtures=154 "
        "gating-fixtures=154 scalar-oracles=pass"
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
        json.JSONDecodeError,
        fixture.Refusal,
        Refusal,
    ) as error:
        print(f"ripgrep-source-only-fixtures: {error}", file=sys.stderr)
        raise SystemExit(1)
