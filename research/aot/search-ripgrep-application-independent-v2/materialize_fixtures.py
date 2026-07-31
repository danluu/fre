#!/usr/bin/env python3
"""Materialize all 154 source-only ripgrep application fixtures."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


INVENTORY_SHA256 = (
    "2aec7b83cfcafbd0f8a9cab2e08941882b34d39786d26f26837c671378f1275b"
)
INVENTORY_PAYLOAD_SHA256 = (
    "68af2c6dd547935d3c4dd095f18958035104d153b355ff416c46c78a922b0979"
)
ALGORITHM_SHA256 = (
    "613e75b929421091353879ffeff21dc1783d70056ce0d3c37edff7d7018d8ab3"
)
INVENTORY_SCHEMA = "fre.aot.search-ripgrep-application-literals.v2"
ALGORITHM_SCHEMA = "fre.aot.search-ripgrep-application-fixture-algorithm.v2"
OUTPUT_SCHEMA = "fre.aot.search-ripgrep-application-fixtures.v2"
FIXTURE_BYTES = 1_048_576
FIXTURE_DOMAIN = b"fre.aot.search-ripgrep-application-fixture.v2\0"
CANDIDATE_COUNT = 11
FIXTURE_COUNT = 154
COMMON_SCENARIOS = (
    "absent",
    "early",
    "middle",
    "tail",
    "dense",
    "wrong-first-dense",
    "wrong-final-dense",
)


class Refusal(RuntimeError):
    """An authenticated input or scalar fixture invariant changed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_sha(value: Any) -> str:
    return sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
    )


def regular_file(path: Path, maximum_bytes: int = 32 * 1024 * 1024) -> bytes:
    status = path.lstat()
    require(
        not path.is_symlink()
        and path.is_file()
        and 0 < status.st_size <= maximum_bytes,
        f"not one bounded regular file: {path}",
    )
    return path.read_bytes()


def write_new(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def absent_sentinel(literal: bytes) -> int:
    return next(byte for byte in range(0x20, 0x7F) if byte not in literal)


def overlapping_starts(
    haystack: bytes | bytearray, literal: bytes
) -> list[int]:
    starts = []
    cursor = 0
    while cursor + len(literal) <= len(haystack):
        start = haystack.find(literal, cursor)
        if start < 0:
            break
        starts.append(start)
        cursor = start + 1
    return starts


def nonoverlapping_count(haystack: bytes, literal: bytes) -> int:
    count = 0
    cursor = 0
    while cursor + len(literal) <= len(haystack):
        start = haystack.find(literal, cursor)
        if start < 0:
            break
        count += 1
        cursor = start + len(literal)
    return count


def repair_absent(data: bytearray, literal: bytes, sentinel: int) -> None:
    cursor = 0
    width = len(literal)
    while cursor + width <= len(data):
        start = data.find(literal, cursor)
        if start < 0:
            break
        data[start + width - 1] = sentinel
        cursor = max(0, start - width + 1)
    require(data.find(literal) < 0, "background repair retained literal")


def background(candidate_sha256: str, literal: bytes, sentinel: int) -> bytes:
    candidate = bytes.fromhex(candidate_sha256)
    output = bytearray()
    counter = 0
    while len(output) < FIXTURE_BYTES:
        digest = hashlib.sha256(
            FIXTURE_DOMAIN + candidate + counter.to_bytes(8, "little")
        ).digest()
        output.extend(0x20 + byte % 95 for byte in digest)
        counter += 1
    del output[FIXTURE_BYTES:]
    repair_absent(output, literal, sentinel)
    return bytes(output)


def sole_match(
    absent: bytes, literal: bytes, sentinel: int, start: int
) -> bytes:
    width = len(literal)
    require(0 <= start <= len(absent) - width, "match start out of range")
    fixture = bytearray(absent)
    left = max(0, start - width + 1)
    fixture[left:start] = bytes([sentinel]) * (start - left)
    right_start = start + width
    right_end = min(len(fixture), right_start + width - 1)
    fixture[right_start:right_end] = bytes([sentinel]) * (
        right_end - right_start
    )
    fixture[start:right_start] = literal
    require(
        overlapping_starts(fixture, literal) == [start],
        "sole match is not unique",
    )
    return bytes(fixture)


def repeated(block: bytes) -> bytes:
    repetitions = (FIXTURE_BYTES + len(block) - 1) // len(block)
    fixture = (block * repetitions)[:FIXTURE_BYTES]
    require(len(fixture) == FIXTURE_BYTES, "repeated fixture size changed")
    return fixture


def dense_fixture(literal: bytes, sentinel: int) -> bytes:
    repetitions = (FIXTURE_BYTES - 1) // len(literal)
    prefix = literal * repetitions
    fixture = prefix + bytes([sentinel]) * (FIXTURE_BYTES - len(prefix))
    require(
        len(fixture) == FIXTURE_BYTES and fixture.startswith(literal),
        "dense fixture changed",
    )
    return fixture


def miss_block(literal: bytes, sentinel: int, offset: int) -> bytes:
    block = bytearray(literal)
    block[offset] = sentinel
    require(
        sum(
            left != right
            for left, right in zip(block, literal, strict=True)
        )
        == 1,
        "miss block does not differ once",
    )
    return bytes(block)


def mutation_fixture(literal: bytes, sentinel: int, offset: int) -> bytes:
    fixture = bytearray(repeated(miss_block(literal, sentinel, offset)))
    width = len(literal)
    tail = FIXTURE_BYTES - width
    guard_start = max(0, tail - width + 1)
    fixture[guard_start:tail] = bytes([sentinel]) * (tail - guard_start)
    fixture[tail:] = literal
    require(
        overlapping_starts(fixture, literal) == [tail],
        "mutation stream does not have one tail match",
    )
    return bytes(fixture)


def alignment(candidate_sha256: str, scenario: str) -> int:
    digest = hashlib.sha256(
        FIXTURE_DOMAIN
        + bytes.fromhex(candidate_sha256)
        + scenario.encode()
    ).digest()
    return digest[0] & 15


def fixture_row(
    output_directory: Path,
    candidate_sha256: str,
    scenario: str,
    fixture: bytes,
    literal: bytes,
    expected_start: int | None,
    sentinel: int,
) -> dict[str, Any]:
    require(len(fixture) == FIXTURE_BYTES, "fixture size changed")
    actual_start = fixture.find(literal)
    require(
        actual_start == (-1 if expected_start is None else expected_start),
        f"{scenario}: scalar leftmost start changed",
    )
    expected_span = (
        None
        if expected_start is None
        else [expected_start, expected_start + len(literal)]
    )
    relative = f"{candidate_sha256}-{scenario}.bin"
    write_new(output_directory / relative, fixture)
    return {
        "scenario": scenario,
        "path": relative,
        "bytes": len(fixture),
        "sha256": sha256(fixture),
        "alignment_offset": alignment(candidate_sha256, scenario),
        "wrong_byte": sentinel,
        "expected_leftmost_span": expected_span,
        "expected_nonoverlapping_count": nonoverlapping_count(
            fixture, literal
        ),
    }


def materialize_candidate(
    output_directory: Path, candidate: dict[str, Any]
) -> dict[str, Any]:
    candidate_sha256 = candidate["semantic_candidate_sha256"]
    literal = bytes.fromhex(candidate["literal_hex"])
    require(
        len(literal) == candidate["literal_bytes"]
        and sha256(literal) == candidate["literal_sha256"]
        and 1 <= len(literal) <= 32,
        "candidate literal receipt changed",
    )
    sentinel = absent_sentinel(literal)
    absent = background(candidate_sha256, literal, sentinel)
    middle = (FIXTURE_BYTES - len(literal)) // 2
    tail = FIXTURE_BYTES - len(literal)
    fixtures = [
        fixture_row(
            output_directory,
            candidate_sha256,
            "absent",
            absent,
            literal,
            None,
            sentinel,
        ),
        fixture_row(
            output_directory,
            candidate_sha256,
            "early",
            sole_match(absent, literal, sentinel, 64),
            literal,
            64,
            sentinel,
        ),
        fixture_row(
            output_directory,
            candidate_sha256,
            "middle",
            sole_match(absent, literal, sentinel, middle),
            literal,
            middle,
            sentinel,
        ),
        fixture_row(
            output_directory,
            candidate_sha256,
            "tail",
            sole_match(absent, literal, sentinel, tail),
            literal,
            tail,
            sentinel,
        ),
        fixture_row(
            output_directory,
            candidate_sha256,
            "dense",
            dense_fixture(literal, sentinel),
            literal,
            0,
            sentinel,
        ),
        fixture_row(
            output_directory,
            candidate_sha256,
            "wrong-first-dense",
            repeated(miss_block(literal, sentinel, 0)),
            literal,
            None,
            sentinel,
        ),
        fixture_row(
            output_directory,
            candidate_sha256,
            "wrong-final-dense",
            repeated(miss_block(literal, sentinel, len(literal) - 1)),
            literal,
            None,
            sentinel,
        ),
    ]
    for offset in range(len(literal)):
        fixtures.append(
            fixture_row(
                output_directory,
                candidate_sha256,
                f"near-miss-offset-{offset:02}",
                mutation_fixture(literal, sentinel, offset),
                literal,
                tail,
                sentinel,
            )
        )
    require(
        len(fixtures) == len(COMMON_SCENARIOS) + len(literal),
        "candidate fixture cardinality changed",
    )
    return {
        "semantic_candidate_sha256": candidate_sha256,
        "literal_hex": candidate["literal_hex"],
        "literal_sha256": candidate["literal_sha256"],
        "literal_bytes": candidate["literal_bytes"],
        "gate_membership": "source-derived",
        "fixtures": fixtures,
    }


def validate_inputs(
    inventory_path: Path, algorithm_path: Path, ripgrep_root: Path
) -> dict[str, Any]:
    inventory_bytes = regular_file(inventory_path)
    algorithm_bytes = regular_file(algorithm_path)
    require(
        sha256(inventory_bytes) == INVENTORY_SHA256
        and sha256(algorithm_bytes) == ALGORITHM_SHA256,
        "inventory or algorithm bytes changed",
    )
    inventory = json.loads(inventory_bytes)
    algorithm = json.loads(algorithm_bytes)
    require(
        inventory.get("schema") == INVENTORY_SCHEMA
        and inventory.get("payload_sha256") == INVENTORY_PAYLOAD_SHA256
        and canonical_sha(inventory.get("payload"))
        == INVENTORY_PAYLOAD_SHA256
        and inventory["payload"]["timing_feedback_permitted"] is False
        and inventory["payload"]["independence"]
        == {
            "external_classification_inputs": [],
            "corpus_overlap_inputs": [],
            "membership": "all source-derived candidates",
            "result_derived_exclusions": False,
        },
        "source-only inventory boundary changed",
    )
    require(
        algorithm.get("schema") == ALGORITHM_SCHEMA
        and algorithm.get("fixture_bytes") == FIXTURE_BYTES
        and bytes.fromhex(algorithm.get("fixture_domain_hex", ""))
        == FIXTURE_DOMAIN
        and algorithm.get("common_scenarios") == list(COMMON_SCENARIOS)
        and algorithm.get("candidate_count") == CANDIDATE_COUNT
        and algorithm.get("fixture_count") == FIXTURE_COUNT
        and algorithm.get("every_candidate_gates") is True
        and algorithm.get("external_classification_inputs") == []
        and algorithm.get("timing_feedback_permitted") is False,
        "fixture algorithm changed",
    )
    validator = Path(__file__).resolve().with_name("validate_inventory.py")
    result = subprocess.run(
        [
            sys.executable,
            str(validator),
            str(inventory_path),
            str(ripgrep_root),
        ],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    require(
        result.returncode == 0 and not result.stderr,
        "source inventory validation failed",
    )
    return inventory


def main() -> None:
    require(
        len(sys.argv) == 5,
        "usage: materialize_fixtures.py INVENTORY ALGORITHM RIPGREP_ROOT OUTPUT_DIR",
    )
    inventory_path = Path(sys.argv[1])
    algorithm_path = Path(sys.argv[2])
    ripgrep_root = Path(sys.argv[3])
    output_directory = Path(sys.argv[4])
    require(
        not output_directory.exists(),
        f"refusing existing output: {output_directory}",
    )
    inventory = validate_inputs(
        inventory_path, algorithm_path, ripgrep_root
    )
    candidates = inventory["payload"]["candidates"]
    require(len(candidates) == CANDIDATE_COUNT, "candidate count changed")
    output_directory.mkdir(mode=0o755)
    output_candidates = [
        materialize_candidate(output_directory, candidate)
        for candidate in candidates
    ]
    fixture_count = sum(
        len(candidate["fixtures"]) for candidate in output_candidates
    )
    require(fixture_count == FIXTURE_COUNT, "fixture count changed")
    payload = {
        "source_inventory_sha256": INVENTORY_SHA256,
        "source_inventory_payload_sha256": INVENTORY_PAYLOAD_SHA256,
        "fixture_algorithm_sha256": ALGORITHM_SHA256,
        "backend_identity": "required-tag29-frozen-input",
        "timing_permitted": False,
        "external_classification_inputs": [],
        "candidate_count": len(output_candidates),
        "gating_candidate_count": len(output_candidates),
        "fixture_count": fixture_count,
        "gating_fixture_count": fixture_count,
        "fixture_bytes_each": FIXTURE_BYTES,
        "candidates": output_candidates,
    }
    wrapper = {
        "schema": OUTPUT_SCHEMA,
        "payload_sha256": canonical_sha(payload),
        "payload": payload,
    }
    manifest_bytes = (
        json.dumps(
            wrapper, sort_keys=True, indent=2, ensure_ascii=True
        )
        + "\n"
    ).encode()
    write_new(output_directory / "manifest.json", manifest_bytes)
    print(
        f"output={output_directory} "
        f"manifest_sha256={sha256(manifest_bytes)} "
        "candidates=11 gating-candidates=11 fixtures=154 "
        "gating-fixtures=154 bytes-each=1048576"
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
        Refusal,
    ) as error:
        print(f"ripgrep-source-only-materializer: {error}", file=sys.stderr)
        raise SystemExit(1)
