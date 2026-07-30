#!/usr/bin/env python3
"""Generate every frozen independent external-development fixture."""

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
    "2459a245c6842d98a923de13c97caf5938f92c180b76069215017fb462147242"
)
ALGORITHM_SCHEMA = (
    "fre.aot.external-regex-1.12.4-fixture-algorithm-development.v1"
)
OUTPUT_SCHEMA = "fre.aot.external-regex-1.12.4-development-fixtures.v1"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
SCENARIOS = ("absent", "early", "middle", "tail", "dense")


class Refusal(RuntimeError):
    pass


def refuse(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def regular_file(path: Path, expected_sha256: str) -> bytes:
    status = path.lstat()
    refuse(not path.is_symlink() and path.is_file(), f"not a regular file: {path}")
    refuse(0 < status.st_size <= 32 * 1024 * 1024, f"invalid file size: {path}")
    data = path.read_bytes()
    refuse(sha256(data) == expected_sha256, f"SHA-256 changed: {path}")
    return data


def load_json(data: bytes, label: str) -> dict[str, Any]:
    value = json.loads(data)
    refuse(isinstance(value, dict), f"{label}: root is not an object")
    return value


def require_sha(value: Any, label: str) -> str:
    refuse(isinstance(value, str) and HEX64.fullmatch(value) is not None, label)
    return value


def occurrences(haystack: bytes | bytearray, literal: bytes) -> list[int]:
    starts = []
    cursor = 0
    while cursor + len(literal) <= len(haystack):
        start = haystack.find(literal, cursor)
        if start < 0:
            break
        starts.append(start)
        cursor = start + 1
    return starts


def nonoverlapping_count(haystack: bytes | bytearray, literal: bytes) -> int:
    count = 0
    cursor = 0
    while cursor + len(literal) <= len(haystack):
        start = haystack.find(literal, cursor)
        if start < 0:
            break
        count += 1
        cursor = start + len(literal)
    return count


def sentinel(literal: bytes) -> int:
    values = set(literal)
    for byte in range(0x20, 0x7F):
        if byte not in values:
            return byte
    raise Refusal("no printable sentinel is absent from literal")


def background(
    size: int,
    domain: bytes,
    candidate_sha256: bytes,
    scenario: str,
) -> bytearray:
    output = bytearray()
    counter = 0
    scenario_bytes = scenario.encode("utf-8")
    while len(output) < size:
        digest = hashlib.sha256(
            domain
            + candidate_sha256
            + scenario_bytes
            + counter.to_bytes(8, "little")
        ).digest()
        output.extend(0x20 + (byte % 95) for byte in digest)
        counter += 1
    del output[size:]
    return output


def repair(haystack: bytearray, literal: bytes, replacement: int) -> None:
    cursor = 0
    while cursor + len(literal) <= len(haystack):
        start = haystack.find(literal, cursor)
        if start < 0:
            break
        haystack[start] = replacement
        cursor = start + 1
    refuse(not occurrences(haystack, literal), "absence repair did not converge")


def sole_match(
    haystack: bytearray,
    literal: bytes,
    replacement: int,
    start: int,
) -> None:
    width = len(literal)
    left = max(0, start - (width - 1))
    right = min(len(haystack), start + width + (width - 1))
    haystack[left:right] = bytes([replacement]) * (right - left)
    haystack[start : start + width] = literal
    refuse(occurrences(haystack, literal) == [start], "sole-match oracle failed")


def make_fixture(
    size: int,
    domain: bytes,
    candidate_digest: bytes,
    literal: bytes,
    scenario: str,
) -> tuple[bytes, int, int | None, int, int]:
    replacement = sentinel(literal)
    width = len(literal)
    alignment = hashlib.sha256(
        domain + candidate_digest + scenario.encode("utf-8")
    ).digest()[0] & 15
    if scenario == "dense":
        repetitions = (size - 1) // width
        used = repetitions * width
        data = bytearray(literal * repetitions)
        data.extend(bytes([replacement]) * (size - used))
        refuse(len(data) == size and size - used > 0, "dense suffix is empty")
        refuse(
            nonoverlapping_count(data, literal) == repetitions,
            "dense nonoverlapping oracle failed",
        )
        refuse(
            data.find(literal, used) < 0,
            "dense sentinel suffix contains a literal",
        )
        return bytes(data), alignment, 0, repetitions, replacement

    data = background(size, domain, candidate_digest, scenario)
    repair(data, literal, replacement)
    if scenario == "absent":
        return bytes(data), alignment, None, 0, replacement
    if scenario == "early":
        start = 64
    elif scenario == "middle":
        start = (size - width) // 2
    elif scenario == "tail":
        start = size - width
    else:
        raise Refusal(f"unknown scenario: {scenario}")
    sole_match(data, literal, replacement, start)
    return bytes(data), alignment, start, 1, replacement


def write_new(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def main() -> None:
    refuse(
        len(sys.argv) == 5,
        "usage: DEVELOPMENT_INVENTORY CONTAMINATION_INDEX ALGORITHM OUTPUT_DIRECTORY",
    )
    development_path = Path(sys.argv[1])
    contamination_path = Path(sys.argv[2])
    algorithm_path = Path(sys.argv[3])
    output_directory = Path(sys.argv[4])
    refuse(not output_directory.exists(), f"refusing existing output: {output_directory}")

    development_bytes = regular_file(
        development_path, EXPECTED_DEVELOPMENT_SHA256
    )
    contamination_bytes = regular_file(
        contamination_path, EXPECTED_CONTAMINATION_SHA256
    )
    algorithm_bytes = regular_file(algorithm_path, EXPECTED_ALGORITHM_SHA256)
    development = load_json(development_bytes, "development inventory")
    contamination = load_json(contamination_bytes, "contamination index")
    algorithm = load_json(algorithm_bytes, "fixture algorithm")
    refuse(algorithm.get("schema") == ALGORITHM_SCHEMA, "fixture algorithm schema changed")
    size = algorithm.get("fixture_bytes")
    domain_hex = algorithm.get("fixture_domain_hex")
    refuse(
        size == 1_048_576
        and isinstance(domain_hex, str)
        and re.fullmatch(r"[0-9a-f]+", domain_hex) is not None,
        "fixture algorithm constants changed",
    )
    domain = bytes.fromhex(domain_hex)

    dev_candidates = {
        row["semantic_candidate_sha256"]: row
        for row in development["payload"]["semantic_candidates"]
    }
    admitted = []
    for row in contamination["payload"]["candidates"]:
        if (
            row["disposition"] == "independent"
            and row["search_applicable"] is True
            and 2 <= row["literal_bytes"] <= 32
        ):
            candidate = dev_candidates.get(row["semantic_candidate_sha256"])
            refuse(candidate is not None, "contamination candidate lacks dev identity")
            refuse(
                candidate["literal_sha256"] == row["literal_sha256"]
                and candidate["literal_bytes"] == row["literal_bytes"],
                "contamination/dev literal identity differs",
            )
            admitted.append(candidate)
    admitted.sort(key=lambda row: row["semantic_candidate_sha256"])
    refuse(len(admitted) == 4, "independent development candidate count changed")

    output_directory.mkdir(mode=0o755)
    rows = []
    for candidate in admitted:
        candidate_sha = require_sha(
            candidate["semantic_candidate_sha256"], "candidate identity is invalid"
        )
        literal = bytes.fromhex(candidate["literal_hex"])
        refuse(
            sha256(literal) == candidate["literal_sha256"]
            and len(literal) == candidate["literal_bytes"],
            "candidate literal receipt differs",
        )
        scenario_rows = []
        for scenario in SCENARIOS:
            fixture, alignment, leftmost, count, replacement = make_fixture(
                size, domain, bytes.fromhex(candidate_sha), literal, scenario
            )
            relative = f"{candidate_sha}-{scenario}.bin"
            write_new(output_directory / relative, fixture)
            scenario_rows.append(
                {
                    "scenario": scenario,
                    "path": relative,
                    "bytes": len(fixture),
                    "sha256": sha256(fixture),
                    "alignment_offset": alignment,
                    "sentinel": replacement,
                    "expected_leftmost_span": (
                        None
                        if leftmost is None
                        else [leftmost, leftmost + len(literal)]
                    ),
                    "expected_nonoverlapping_count": count,
                }
            )
        rows.append(
            {
                "semantic_candidate_sha256": candidate_sha,
                "representative_case_id": candidate["representative_case_id"],
                "representative_case_sha256": candidate[
                    "representative_case_sha256"
                ],
                "source_files": candidate["source_files"],
                "literal_hex": candidate["literal_hex"],
                "literal_sha256": candidate["literal_sha256"],
                "literal_bytes": candidate["literal_bytes"],
                "shape": candidate["shape"],
                "fixtures": scenario_rows,
            }
        )
    payload = {
        "development_inventory_sha256": EXPECTED_DEVELOPMENT_SHA256,
        "contamination_index_sha256": EXPECTED_CONTAMINATION_SHA256,
        "fixture_algorithm_sha256": EXPECTED_ALGORITHM_SHA256,
        "backend_identity": "required-unresolved-input",
        "timing_permitted": False,
        "candidate_count": len(rows),
        "fixture_count": sum(len(row["fixtures"]) for row in rows),
        "fixture_bytes_each": size,
        "candidates": rows,
    }
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
    print(f"candidates={len(rows)} fixtures={payload['fixture_count']}")
    print("timing_permitted=false backend_identity=required-unresolved-input")


if __name__ == "__main__":
    try:
        main()
    except (OSError, Refusal, ValueError, json.JSONDecodeError) as error:
        print(f"fixture-generator: {error}", file=sys.stderr)
        raise SystemExit(1)
