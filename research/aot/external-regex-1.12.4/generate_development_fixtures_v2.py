#!/usr/bin/env python3
"""Extend the frozen v1 fixture set with backend-independent endpoint misses."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

EXPECTED_DEVELOPMENT_SHA256 = (
    "3b409957d42482b170df43ac58bfb08c019c4236b9bee95304a8419931f3d52f"
)
EXPECTED_CONTAMINATION_SHA256 = (
    "0d5b663c5da923f1284b1577e0866d78b54ecb7890942604d6d09b0a4737d08b"
)
EXPECTED_ALGORITHM_SHA256 = (
    "e99dfb5dce720484968fb074b0807f2636724e297cc682fd87575b8d5ceadd48"
)
EXPECTED_PREDECESSOR_MANIFEST_SHA256 = (
    "80dcf139225b506e294de158251bae5dbd7a2ffd0af87630420c695df7678c2b"
)
ALGORITHM_SCHEMA = (
    "fre.aot.external-regex-1.12.4-fixture-algorithm-development.v2"
)
PREDECESSOR_SCHEMA = "fre.aot.external-regex-1.12.4-development-fixtures.v1"
OUTPUT_SCHEMA = "fre.aot.external-regex-1.12.4-development-fixtures.v2"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
SUCCESSOR_SCENARIOS = ("wrong-final-dense", "wrong-first-dense")


class Refusal(RuntimeError):
    pass


def refuse(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def regular_file(
    path: Path,
    expected_sha256: str | None = None,
    maximum_bytes: int = 32 * 1024 * 1024,
) -> bytes:
    status = path.lstat()
    refuse(not path.is_symlink() and path.is_file(), f"not a regular file: {path}")
    refuse(0 < status.st_size <= maximum_bytes, f"invalid file size: {path}")
    data = path.read_bytes()
    if expected_sha256 is not None:
        refuse(sha256(data) == expected_sha256, f"SHA-256 changed: {path}")
    return data


def load_json(data: bytes, label: str) -> dict[str, Any]:
    value = json.loads(data)
    refuse(isinstance(value, dict), f"{label}: root is not an object")
    return value


def require_sha(value: Any, label: str) -> str:
    refuse(isinstance(value, str) and HEX64.fullmatch(value) is not None, label)
    return value


def occurrences(haystack: bytes, literal: bytes) -> list[int]:
    starts = []
    cursor = 0
    while cursor + len(literal) <= len(haystack):
        start = haystack.find(literal, cursor)
        if start < 0:
            break
        starts.append(start)
        cursor = start + 1
    return starts


def wrong_byte(literal: bytes) -> int:
    values = set(literal)
    for byte in range(0x20, 0x7F):
        if byte not in values:
            return byte
    raise Refusal("no printable wrong byte is absent from literal")


def successor_fixture(
    size: int,
    literal: bytes,
    scenario: str,
) -> tuple[bytes, int]:
    replacement = wrong_byte(literal)
    if scenario == "wrong-final-dense":
        block = literal[:-1] + bytes([replacement])
        endpoint = len(literal) - 1
    elif scenario == "wrong-first-dense":
        block = bytes([replacement]) + literal[1:]
        endpoint = 0
    else:
        raise Refusal(f"unknown successor scenario: {scenario}")
    refuse(
        len(block) == len(literal)
        and sum(left != right for left, right in zip(block, literal, strict=True)) == 1
        and block[endpoint] == replacement,
        "adversarial block does not differ at exactly the requested endpoint",
    )
    repetitions = (size + len(block) - 1) // len(block)
    fixture = (block * repetitions)[:size]
    refuse(len(fixture) == size, "successor fixture has the wrong length")
    refuse(not occurrences(fixture, literal), "successor fixture contains the literal")
    return fixture, replacement


def write_new(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def main() -> None:
    refuse(
        len(sys.argv) == 6,
        "usage: DEVELOPMENT CONTAMINATION ALGORITHM PREDECESSOR_DIR OUTPUT_DIR",
    )
    development_path = Path(sys.argv[1])
    contamination_path = Path(sys.argv[2])
    algorithm_path = Path(sys.argv[3])
    predecessor_directory = Path(sys.argv[4])
    output_directory = Path(sys.argv[5])
    refuse(not output_directory.exists(), f"refusing existing output: {output_directory}")

    development_bytes = regular_file(
        development_path, EXPECTED_DEVELOPMENT_SHA256
    )
    contamination_bytes = regular_file(
        contamination_path, EXPECTED_CONTAMINATION_SHA256
    )
    algorithm_bytes = regular_file(algorithm_path, EXPECTED_ALGORITHM_SHA256)
    predecessor_manifest_bytes = regular_file(
        predecessor_directory / "manifest.json",
        EXPECTED_PREDECESSOR_MANIFEST_SHA256,
    )
    development = load_json(development_bytes, "development inventory")
    contamination = load_json(contamination_bytes, "contamination index")
    algorithm = load_json(algorithm_bytes, "fixture algorithm")
    predecessor = load_json(predecessor_manifest_bytes, "predecessor manifest")
    refuse(algorithm.get("schema") == ALGORITHM_SCHEMA, "fixture algorithm schema changed")
    refuse(
        predecessor.get("schema") == PREDECESSOR_SCHEMA,
        "predecessor fixture schema changed",
    )
    size = algorithm.get("fixture_bytes")
    domain_hex = algorithm.get("fixture_domain_hex")
    refuse(
        size == 1_048_576
        and isinstance(domain_hex, str)
        and re.fullmatch(r"[0-9a-f]+", domain_hex) is not None,
        "fixture constants changed",
    )
    domain = bytes.fromhex(domain_hex)

    independent = {
        row["semantic_candidate_sha256"]
        for row in contamination["payload"]["candidates"]
        if row["disposition"] == "independent"
        and row["search_applicable"] is True
        and 2 <= row["literal_bytes"] <= 32
    }
    dev_candidates = {
        row["semantic_candidate_sha256"]: row
        for row in development["payload"]["semantic_candidates"]
    }
    predecessor_candidates = predecessor["payload"]["candidates"]
    refuse(
        len(independent) == len(predecessor_candidates) == 4,
        "candidate cardinality changed",
    )
    refuse(
        {row["semantic_candidate_sha256"] for row in predecessor_candidates}
        == independent,
        "predecessor candidate set differs from independent inventory",
    )

    output_directory.mkdir(mode=0o755)
    output_candidates = []
    for predecessor_candidate in predecessor_candidates:
        candidate_sha = require_sha(
            predecessor_candidate["semantic_candidate_sha256"],
            "candidate identity is invalid",
        )
        dev_candidate = dev_candidates.get(candidate_sha)
        refuse(dev_candidate is not None, "predecessor candidate lacks dev identity")
        literal = bytes.fromhex(dev_candidate["literal_hex"])
        refuse(
            2 <= len(literal) <= 32
            and sha256(literal) == dev_candidate["literal_sha256"],
            "candidate literal receipt differs",
        )

        fixture_rows = []
        predecessor_fixtures = predecessor_candidate["fixtures"]
        refuse(len(predecessor_fixtures) == 5, "predecessor scenario count changed")
        for fixture_row in predecessor_fixtures:
            relative = fixture_row["path"]
            expected = require_sha(
                fixture_row["sha256"], "predecessor fixture SHA-256 is invalid"
            )
            data = regular_file(
                predecessor_directory / relative, expected, maximum_bytes=size
            )
            refuse(len(data) == size, "predecessor fixture size changed")
            write_new(output_directory / relative, data)
            fixture_rows.append(fixture_row)

        for scenario in SUCCESSOR_SCENARIOS:
            fixture, replacement = successor_fixture(size, literal, scenario)
            relative = f"{candidate_sha}-{scenario}.bin"
            write_new(output_directory / relative, fixture)
            alignment = hashlib.sha256(
                domain + bytes.fromhex(candidate_sha) + scenario.encode("utf-8")
            ).digest()[0] & 15
            fixture_rows.append(
                {
                    "scenario": scenario,
                    "path": relative,
                    "bytes": len(fixture),
                    "sha256": sha256(fixture),
                    "alignment_offset": alignment,
                    "wrong_byte": replacement,
                    "expected_leftmost_span": None,
                    "expected_nonoverlapping_count": 0,
                }
            )
        candidate_row = dict(predecessor_candidate)
        candidate_row["fixtures"] = fixture_rows
        output_candidates.append(candidate_row)

    payload = {
        "development_inventory_sha256": EXPECTED_DEVELOPMENT_SHA256,
        "contamination_index_sha256": EXPECTED_CONTAMINATION_SHA256,
        "fixture_algorithm_sha256": EXPECTED_ALGORITHM_SHA256,
        "predecessor_manifest_sha256": EXPECTED_PREDECESSOR_MANIFEST_SHA256,
        "backend_identity": "required-unresolved-input",
        "known_emitter_checkpoint": "16329491",
        "timing_permitted": False,
        "candidate_count": len(output_candidates),
        "fixture_count": sum(len(row["fixtures"]) for row in output_candidates),
        "fixture_bytes_each": size,
        "candidates": output_candidates,
    }
    refuse(payload["fixture_count"] == 28, "successor fixture count changed")
    payload_bytes = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    wrapper = {
        "schema": OUTPUT_SCHEMA,
        "payload_sha256": sha256(payload_bytes),
        "payload": payload,
    }
    manifest_bytes = (
        json.dumps(wrapper, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode()
    write_new(output_directory / "manifest.json", manifest_bytes)
    print(f"output={output_directory}")
    print(f"manifest_sha256={sha256(manifest_bytes)}")
    print(f"candidates={len(output_candidates)} fixtures={payload['fixture_count']}")
    print("timing_permitted=false backend_identity=required-unresolved-input")


if __name__ == "__main__":
    try:
        main()
    except (OSError, Refusal, ValueError, json.JSONDecodeError) as error:
        print(f"fixture-generator-v2: {error}", file=sys.stderr)
        raise SystemExit(1)
