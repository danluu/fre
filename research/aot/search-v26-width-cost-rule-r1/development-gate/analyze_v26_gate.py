#!/usr/bin/env python3
"""Exact result analyzer for the frozen Search V26 development gate.

This program never emits or executes regex code. It authenticates a sealed
contract and complete 7,776-cell manifest, validates every raw timing sample,
and recomputes all estimators and thresholds without trusting runner summaries.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import stat
import sys
from collections import defaultdict
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence


EXPECTED_CELLS = 7_776
EXPECTED_SHARD_CELLS = 2_592
EXPECTED_OUTPUTS = ("exists", "span", "selected_end")
OUTPUT_TAGS = {"exists": 1, "selected_end": 2, "span": 3}
EXPECTED_WINDOWS = (
    "no_match",
    "first_legal_position",
    "middle_complete_vector_group",
    "last_legal_position",
    "overlapping_near_miss_before_match",
    "dense_primary_byte_false_candidates",
)
EXPECTED_ORDERS = (
    ("portable", "v17", "v26"),
    ("portable", "v26", "v17"),
    ("v17", "portable", "v26"),
    ("v17", "v26", "portable"),
    ("v26", "portable", "v17"),
    ("v26", "v17", "portable"),
) * 2
SHARD_WIDTHS = ((6, 14), (15, 23), (24, 32))
MAX_CONTRACT_BYTES = 256 * 1024
MAX_SEAL_BYTES = 256 * 1024
MAX_RUN_MANIFEST_BYTES = 256 * 1024
MAX_CELL_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_SHARD_BYTES = 512 * 1024 * 1024
HEX_DIGITS = frozenset("0123456789abcdef")
EXPECTED_ACCEPTANCE = {
    "exact_semantics": True,
    "overall_geomean_lte": 0.8,
    "short_width_6_through_8_geomean_lte": 1.02,
    "wide_width_9_through_32_geomean_lte": 0.8,
    "every_output_geomean_lte": 1.02,
    "every_window_shape_geomean_lte": 1.02,
    "cells_strictly_over_1_05_lte": 77,
    "cells_strictly_over_1_05_fraction_lte": 0.01,
    "maximum_cell_ratio_lte": 1.1,
    "p95_nearest_rank": 7_388,
    "p95": "report-only",
}
CELL_IDENTITY_FIELDS = (
    "cell_id",
    "shard_id",
    "population_sha256",
    "width",
    "output",
    "output_tag",
    "accepted_ordinal",
    "source_ordinal",
    "literal_hex",
    "literal_sha256",
    "window_shape",
    "window_shape_tag",
    "fixture_recipe",
    "filler_byte",
    "window_start",
    "window_end",
    "window_bytes",
    "haystack_len",
    "haystack_sha256",
    "fixture_sha256",
    "expected_match_start",
    "expected_match_end",
    "expected_output_sha256",
)
CELL_MANIFEST_KEYS = frozenset(("schema", *CELL_IDENTITY_FIELDS))
CELL_RESULT_KEYS = frozenset(
    ("schema", *CELL_IDENTITY_FIELDS, "semantics", "calibrations", "repetitions")
)
ENGINE_SAMPLE_KEYS = frozenset(("elapsed_ns", "iterations"))
CALIBRATION_KEYS = frozenset(
    ("iterations", "elapsed_ns", "previous_iterations", "previous_elapsed_ns")
)
SEMANTICS_KEYS = frozenset(("equal", "expected", "portable", "v17", "v26"))
REPETITION_KEYS = frozenset(("repetition", "order", "engines"))
SHARD_HEADER_KEYS = frozenset(
    (
        "schema",
        "shard_id",
        "candidate_backend",
        "reference_backend",
        "source_commit",
        "source_tree",
        "source_archive_sha256",
        "runner_binary_sha256",
        "runner_binary_bytes",
        "contract_sha256",
        "cell_manifest_sha256",
        "host_fingerprint_sha256",
        "cpu_id",
        "shard_nonce",
        "run_nonce",
        "one_shot_seal_sha256",
        "run_manifest_sha256",
    )
)
SHARD_FOOTER_KEYS = frozenset(
    ("schema", "shard_id", "cells", "complete", "shard_nonce", "run_nonce")
)
SEAL_KEYS = frozenset(
    (
        "schema",
        "status",
        "source_commit",
        "source_tree",
        "source_archive_sha256",
        "runner_binary_sha256",
        "runner_binary_bytes",
        "contract_sha256",
        "cell_manifest_sha256",
        "launcher_sha256",
        "analyzer_sha256",
        "authorization_nonce",
        "timing_runs",
    )
)
RUN_MANIFEST_KEYS = frozenset(
    (
        "schema",
        "status",
        "one_shot_seal_sha256",
        "authorization_nonce",
        "run_nonce",
        "source_commit",
        "source_tree",
        "source_archive_sha256",
        "runner_binary_sha256",
        "runner_binary_bytes",
        "contract_sha256",
        "cell_manifest_sha256",
        "host_fingerprint_sha256",
        "cpu_ids",
        "shard_cpu_map",
    )
)
CONTRACT_KEYS = frozenset(
    (
        "schema",
        "status",
        "candidate",
        "inputs",
        "fixtures",
        "engines",
        "measurement",
        "shards",
        "acceptance",
        "execution",
    )
)


class GateError(ValueError):
    """Malformed, incomplete, unauthenticated, or semantically invalid evidence."""


@dataclass(frozen=True)
class StableFile:
    path: Path
    data: bytes
    sha256: str
    mode: int


def lowercase_hex(value: Any, length: int, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != length
        or any(character not in HEX_DIGITS for character in value)
    ):
        raise GateError(f"{name} must be exactly {length} lowercase hexadecimal characters")
    return value


def exact_keys(value: Mapping[str, Any], expected: frozenset[str], name: str) -> None:
    observed = frozenset(value)
    if observed != expected:
        missing = sorted(expected - observed)
        extra = sorted(observed - expected)
        raise GateError(f"{name} keys drifted: missing={missing}, extra={extra}")


def strict_integer(
    value: Any, name: str, *, minimum: int | None = None, maximum: int | None = None
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise GateError(f"{name} must be a strict integer")
    if minimum is not None and value < minimum:
        raise GateError(f"{name} is below {minimum}")
    if maximum is not None and value > maximum:
        raise GateError(f"{name} is above {maximum}")
    return value


def stable_read(path: Path, maximum_bytes: int) -> StableFile:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise GateError(f"cannot open stable regular file {path}: {error}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise GateError(f"{path} is not a regular file")
        if before.st_size < 0 or before.st_size > maximum_bytes:
            raise GateError(f"{path} exceeds its {maximum_bytes}-byte bound")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1 << 20, remaining))
            if not chunk:
                raise GateError(f"{path} changed or truncated during its stable read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise GateError(f"{path} grew during its stable read")
        after = os.fstat(descriptor)
        stable_fields_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        stable_fields_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if stable_fields_before != stable_fields_after:
            raise GateError(f"{path} changed during its stable read")
        data = b"".join(chunks)
        return StableFile(
            path=path,
            data=data,
            sha256=hashlib.sha256(data).hexdigest(),
            mode=after.st_mode,
        )
    finally:
        os.close(descriptor)


def sha256_file(path: Path) -> str:
    return stable_read(path, MAX_SHARD_BYTES).sha256


def geomean(values: Iterable[Fraction]) -> float:
    materialized = list(values)
    if not materialized or any(value <= 0 for value in materialized):
        raise GateError("geomean requires a nonempty set of positive exact ratios")
    return math.exp(
        math.fsum(math.log(float(value)) for value in materialized)
        / len(materialized)
    )


def median12(values: Iterable[Fraction]) -> Fraction:
    ordered = sorted(values)
    if len(ordered) != 12 or any(value <= 0 for value in ordered):
        raise GateError("cell estimator requires exactly 12 positive exact ratios")
    return (ordered[5] + ordered[6]) / 2


def nearest_rank(values: Sequence[Fraction], rank: int) -> Fraction:
    if rank < 1 or rank > len(values):
        raise GateError("nearest rank is outside the observed population")
    return sorted(values)[rank - 1]


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise GateError(f"duplicate JSON object key {key!r}")
        value[key] = item
    return value


def reject_nonfinite_constant(value: str) -> None:
    raise GateError(f"nonfinite JSON number {value!r} is forbidden")


def strict_json_loads(data: bytes, context: str) -> Any:
    try:
        text = data.decode("utf-8")
        return json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite_constant,
        )
    except GateError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise GateError(f"cannot decode strict JSON {context}: {error}") from error


def read_json_file(source: StableFile) -> dict[str, Any]:
    if not source.data.endswith(b"\n"):
        raise GateError(f"{source.path} lacks a final newline")
    value = strict_json_loads(source.data, str(source.path))
    if not isinstance(value, dict):
        raise GateError(f"{source.path} is not a JSON object")
    return value


def read_jsonl_file(source: StableFile) -> Iterator[dict[str, Any]]:
    if not source.data.endswith(b"\n"):
        raise GateError(f"{source.path} lacks a final newline")
    for line_number, line in enumerate(source.data.splitlines(keepends=True), 1):
        if line == b"\n":
            raise GateError(f"{source.path}:{line_number} is blank")
        if not line.endswith(b"\n"):
            raise GateError(f"{source.path}:{line_number} lacks a final newline")
        value = strict_json_loads(
            line.removesuffix(b"\n"), f"{source.path}:{line_number}"
        )
        if not isinstance(value, dict):
            raise GateError(f"{source.path}:{line_number} is not a JSON object")
        yield value


def read_json(path: Path) -> dict[str, Any]:
    return read_json_file(stable_read(path, MAX_CONTRACT_BYTES))


def read_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    return read_jsonl_file(stable_read(path, MAX_SHARD_BYTES))


def require_exact_contract(
    contract: Mapping[str, Any], contract_file: StableFile, cells_file: StableFile
) -> None:
    exact_keys(contract, CONTRACT_KEYS, "gate contract")
    if contract.get("schema") != "fre-search-v26-development-gate-contract-v1":
        raise GateError("unexpected gate contract schema")
    if contract.get("status") != "SEALED_READY_FOR_ONE_SHOT_TIMING":
        raise GateError("contract is not sealed timing authority")
    encoded = json.dumps(contract, sort_keys=True)
    if "AWAITING_" in encoded:
        raise GateError("sealed contract contains an unresolved placeholder")
    candidate = contract.get("candidate")
    if not isinstance(candidate, dict) or candidate != {
        "backend_policy": "AsimdV26",
        "backend_version": 39,
        "source_commit": candidate.get("source_commit"),
        "source_tree": candidate.get("source_tree"),
        "llvm": False,
    }:
        raise GateError("candidate contract fields drifted")
    lowercase_hex(candidate["source_commit"], 40, "candidate source commit")
    lowercase_hex(candidate["source_tree"], 40, "candidate source tree")
    inputs = contract.get("inputs")
    if not isinstance(inputs, dict):
        raise GateError("sealed input identity is missing")
    exact_keys(
        inputs,
        frozenset(
            (
                "preregistration_sha256",
                "synthetic_population_sha256",
                "literal_records",
                "cells",
                "cell_manifest_sha256",
                "cell_key_fields",
                "cell_order",
            )
        ),
        "gate inputs",
    )
    if (
        inputs.get("preregistration_sha256")
        != "772a23e5e6c4354fa3bdc9ad307601dbbce655a62dd5ee7ded075dbe4869a02a"
        or inputs.get("literal_records") != 1_296
        or inputs.get("cells") != EXPECTED_CELLS
        or inputs.get("synthetic_population_sha256")
        != "a682375f2e6e051f97322396bafc46974df47baa3518bc17f5d6b71b56407b73"
        or inputs.get("cell_manifest_sha256") != cells_file.sha256
    ):
        raise GateError("sealed input identity mismatch")
    if inputs.get("cell_key_fields") != [
        "width",
        "output_tag",
        "accepted_ordinal",
        "window_shape",
    ] or inputs.get("cell_order") != [
        "width ascending 6..32",
        "output order exists, span, selected_end",
        "accepted ordinal ascending 0..15",
        "window order no_match, first_legal_position, middle_complete_vector_group, last_legal_position, overlapping_near_miss_before_match, dense_primary_byte_false_candidates",
    ]:
        raise GateError("cell lattice contract drifted")
    fixtures = contract.get("fixtures")
    if not isinstance(fixtures, dict) or fixtures != {
        "recipe": "fre-search-v26-long-scan-fixture-v1",
        "long_window_bytes": 2_097_152,
        "long_shapes": [
            "no_match",
            "middle_complete_vector_group",
            "last_legal_position",
            "overlapping_near_miss_before_match",
            "dense_primary_byte_false_candidates",
        ],
        "first_legal_position": {
            "window_bytes": "literal_width",
            "match_offset_from_window_start": 0,
            "purpose": "intentional call/setup stratum",
        },
        "window_start": "32 + accepted_ordinal, covering every modulo-16 start alignment once per width/output",
        "haystack_suffix_padding_bytes": 64,
        "filler_byte": "lowest u8 value absent from the literal",
        "middle_match_offset_from_window_start": 1_048_581,
        "overlap_match_offset_from_window_start": 1_048_581,
        "overlap_near_miss": "start at exact_match_start - (literal_width - 1), copy the literal, replace the near-miss first byte with filler, then install the exact match",
        "dense_false_candidates": "from window_start, advance by literal_width + 3 while the candidate ends before the last legal position; candidate i contains filler except literal[i mod literal_width] at that same column",
        "dense_exact_match": "last legal position after all false candidates",
        "expected_coordinates": "absolute haystack byte coordinates; an engine invoked on a sliced window must add window_start before hashing or comparing its result",
        "identity": "SHA-256 over fre-search-v26-long-scan-fixture-v1 binary domain, literal coordinate and bytes, shape tag, geometry, expected match, and complete haystack bytes",
        "allocation": "construct and release exactly one fixture/cell at a time; retaining the 7,776 long haystacks is forbidden",
    }:
        raise GateError("fixture geometry contract drifted")
    if contract.get("engines") != {
        "portable": "safe Kernel IR execution",
        "reference": "AsimdV17/backend30 native Search-v1",
        "candidate": "AsimdV26/backend39 native Search-v1",
        "semantic_equality_before_timing": "hard failure",
    }:
        raise GateError("engine identity contract drifted")
    measurement = contract.get("measurement")
    if not isinstance(measurement, dict):
        raise GateError("measurement contract is missing")
    try:
        orders = tuple(tuple(order) for order in measurement.get("orders", ()))
    except TypeError as error:
        raise GateError("measurement orders are malformed") from error
    if orders != EXPECTED_ORDERS:
        raise GateError("measurement order contract drifted")
    if {
        key: value for key, value in measurement.items() if key != "orders"
    } != {
        "calibration_target_ns": 4_000_000,
        "calibration": "per cell and engine, begin at one search and double the batch until elapsed_ns >= target; fail on overflow or zero/nonfinite normalized time",
        "calibration_evidence": "record chosen iterations and terminal elapsed_ns; for iterations > 1 also record exactly half the iterations and its elapsed_ns, which must be below target; every timed sample must use the chosen iterations",
        "paired_repetitions": 12,
        "per_repetition_ratio": "(v26_elapsed_ns / v26_iterations) / (v17_elapsed_ns / v17_iterations)",
        "cell_estimator": "arithmetic median of the 12 paired ratios; average sorted ranks 6 and 7",
        "aggregate_estimator": "equal-cell-weight exp(fsum(log(cell_ratio)) / cell_count)",
    }:
        raise GateError("measurement estimator contract drifted")
    if contract.get("shards") != [
        {"id": 0, "widths": "6..14", "cells": EXPECTED_SHARD_CELLS},
        {"id": 1, "widths": "15..23", "cells": EXPECTED_SHARD_CELLS},
        {"id": 2, "widths": "24..32", "cells": EXPECTED_SHARD_CELLS},
    ]:
        raise GateError("shard contract drifted")
    if contract.get("acceptance") != EXPECTED_ACCEPTANCE:
        raise GateError("acceptance thresholds drifted")
    execution = contract.get("execution")
    if not isinstance(execution, dict) or execution.get("candidate_timing_executed") is not False:
        raise GateError("frozen contract must precede candidate timing")
    if {
        key: value
        for key, value in execution.items()
        if key != "sealing_authority"
    } != {
        "runs": 1,
        "launcher": "one-shot; require three explicit distinct CPU IDs and run the three disjoint shards concurrently; on Linux pin shard i to CPU i with taskset",
        "admission": "do not wait on load, headroom, another GO, or other CPU work; do not kill other CPU work",
        "run_manifest": "create-new and read-only before timing; seal host fingerprint, ordered CPU IDs, shard-to-CPU map, source/binary/archive/contract/cell identities, authorization nonce, three distinct shard nonces, and a distinct run nonce",
        "missing_duplicate_nonfinite_unpaired_wrong_order_or_mutated_input": "hard failure",
        "rebar_input": False,
        "candidate_timing_executed": False,
    } or not isinstance(execution.get("sealing_authority"), str):
        raise GateError("execution contract drifted")
    if contract_file.mode & 0o222:
        raise GateError("sealed contract remains writable")
    if cells_file.mode & 0o222:
        raise GateError("sealed cell manifest remains writable")


def cell_key(record: Mapping[str, Any]) -> tuple[int, int, int, str]:
    width = strict_integer(record.get("width"), "cell width", minimum=6, maximum=32)
    output_tag = strict_integer(
        record.get("output_tag"), "cell output tag", minimum=1, maximum=3
    )
    accepted_ordinal = strict_integer(
        record.get("accepted_ordinal"),
        "cell accepted ordinal",
        minimum=0,
        maximum=15,
    )
    window_shape = record.get("window_shape")
    if not isinstance(window_shape, str):
        raise GateError("cell window shape must be a string")
    return (width, output_tag, accepted_ordinal, window_shape)


def expected_shard(width: int) -> int:
    for shard, (minimum, maximum) in enumerate(SHARD_WIDTHS):
        if minimum <= width <= maximum:
            return shard
    raise GateError(f"width {width} is outside the frozen shard envelope")


def derive_literal(width: int, output_tag: int, source_ordinal: int) -> bytes:
    literal = bytearray()
    block_counter = 0
    while len(literal) < width:
        hasher = hashlib.sha256()
        hasher.update(b"FRE-V26-WIDTH-COST-SYNTHETIC-R1")
        hasher.update(width.to_bytes(2, "little"))
        hasher.update(bytes((output_tag,)))
        hasher.update(source_ordinal.to_bytes(2, "little"))
        hasher.update(block_counter.to_bytes(4, "little"))
        literal.extend(hasher.digest())
        block_counter += 1
    return bytes(literal[:width])


def expected_output_sha256(
    output_tag: int, expected_match: tuple[int, int] | None
) -> str:
    hasher = hashlib.sha256()
    hasher.update(b"FRE-SEARCH-V26-EXPECTED-OUTPUT-V1\0\x01")
    hasher.update(bytes((output_tag,)))
    if output_tag == 1:
        hasher.update(bytes((int(expected_match is not None),)))
    elif output_tag == 2:
        if expected_match is None:
            hasher.update(b"\0")
        else:
            hasher.update(b"\x01")
            hasher.update(expected_match[1].to_bytes(8, "little"))
    elif output_tag == 3:
        if expected_match is None:
            hasher.update(b"\0")
        else:
            hasher.update(b"\x01")
            hasher.update(expected_match[0].to_bytes(8, "little"))
            hasher.update(expected_match[1].to_bytes(8, "little"))
    else:
        raise GateError("unknown output tag")
    return hasher.hexdigest()


def lowest_unused_byte(literal: bytes) -> int:
    for candidate in range(256):
        if candidate not in literal:
            return candidate
    raise GateError("bounded literal contains every byte")


def expected_geometry(
    width: int, accepted_ordinal: int, window_shape: str
) -> tuple[int, int, int, tuple[int, int] | None]:
    window_start = 32 + accepted_ordinal
    window_bytes = width if window_shape == "first_legal_position" else 2_097_152
    window_end = window_start + window_bytes
    haystack_len = window_end + 64
    if window_shape == "no_match":
        expected_match = None
    elif window_shape == "first_legal_position":
        expected_match = (window_start, window_start + width)
    elif window_shape in (
        "middle_complete_vector_group",
        "overlapping_near_miss_before_match",
    ):
        start = window_start + 1_048_581
        expected_match = (start, start + width)
    elif window_shape in (
        "last_legal_position",
        "dense_primary_byte_false_candidates",
    ):
        expected_match = (window_end - width, window_end)
    else:
        raise GateError(f"unknown window shape {window_shape!r}")
    return window_start, window_end, haystack_len, expected_match


def reconstruct_fixture(
    record: Mapping[str, Any], literal: bytes
) -> tuple[str, str, tuple[int, int] | None]:
    width, _, accepted_ordinal, window_shape = cell_key(record)
    window_start, window_end, haystack_len, expected_match = expected_geometry(
        width, accepted_ordinal, window_shape
    )
    filler = lowest_unused_byte(literal)
    haystack = bytearray((filler,)) * haystack_len
    if window_shape == "overlapping_near_miss_before_match":
        if expected_match is None:
            raise GateError("overlap fixture unexpectedly has no match")
        near_start = expected_match[0] - (width - 1)
        haystack[near_start : near_start + width] = literal
        haystack[near_start] = filler
    elif window_shape == "dense_primary_byte_false_candidates":
        if expected_match is None:
            raise GateError("dense fixture unexpectedly has no match")
        exact_start = expected_match[0]
        candidate_start = window_start
        candidate_index = 0
        while candidate_start + width <= exact_start:
            column = candidate_index % width
            haystack[candidate_start + column] = literal[column]
            candidate_start += width + 3
            candidate_index += 1
    if expected_match is not None:
        haystack[expected_match[0] : expected_match[1]] = literal
    observed_start = haystack.find(literal, window_start, window_end)
    observed_match = (
        None
        if observed_start < 0
        else (observed_start, observed_start + width)
    )
    if observed_match != expected_match:
        raise GateError(f"{window_shape} reconstructed the wrong first match")
    haystack_sha256 = hashlib.sha256(haystack).hexdigest()
    fixture_hasher = hashlib.sha256()
    fixture_hasher.update(b"FRE-SEARCH-V26-LONG-SCAN-FIXTURE-V1\0\x01")
    fixture_hasher.update(width.to_bytes(2, "little"))
    fixture_hasher.update(bytes((strict_integer(record.get("output_tag"), "output tag"),)))
    fixture_hasher.update(accepted_ordinal.to_bytes(2, "little"))
    fixture_hasher.update(
        strict_integer(
            record.get("source_ordinal"),
            "source ordinal",
            minimum=0,
            maximum=65_535,
        ).to_bytes(2, "little")
    )
    fixture_hasher.update(
        bytes(
            (
                EXPECTED_WINDOWS.index(window_shape),
                filler,
            )
        )
    )
    fixture_hasher.update(window_start.to_bytes(8, "little"))
    fixture_hasher.update(window_end.to_bytes(8, "little"))
    fixture_hasher.update(haystack_len.to_bytes(8, "little"))
    if expected_match is None:
        fixture_hasher.update(b"\0")
    else:
        fixture_hasher.update(b"\x01")
        fixture_hasher.update(expected_match[0].to_bytes(8, "little"))
        fixture_hasher.update(expected_match[1].to_bytes(8, "little"))
    fixture_hasher.update(width.to_bytes(2, "little"))
    fixture_hasher.update(literal)
    fixture_hasher.update(haystack)
    return haystack_sha256, fixture_hasher.hexdigest(), expected_match


def validate_cell_manifest(
    records: Iterable[dict[str, Any]],
) -> dict[tuple[int, int, int, str], dict[str, Any]]:
    cells: dict[tuple[int, int, int, str], dict[str, Any]] = {}
    population_hasher = hashlib.sha256(
        b"FRE-V26-WIDTH-COST-SYNTHETIC-R1-POPULATION\0\x01"
    )
    expected_id = 0
    for record in records:
        exact_keys(record, CELL_MANIFEST_KEYS, f"cell {expected_id}")
        if record.get("schema") != "fre-search-v26-development-gate-cell-v1":
            raise GateError("unexpected cell-manifest record schema")
        if strict_integer(record.get("cell_id"), "cell id", minimum=0) != expected_id:
            raise GateError(f"cell id closure broke at {expected_id}")
        key = cell_key(record)
        width, output_tag, accepted_ordinal, window_shape = key
        output = record.get("output")
        if (
            not isinstance(output, str)
            or output not in EXPECTED_OUTPUTS
            or output_tag != OUTPUT_TAGS[output]
            or window_shape not in EXPECTED_WINDOWS
            or strict_integer(
                record.get("shard_id"), "shard id", minimum=0, maximum=2
            )
            != expected_shard(width)
        ):
            raise GateError(f"cell {expected_id} is outside the frozen lattice")
        if key in cells:
            raise GateError(f"duplicate cell key {key}")
        if record.get("population_sha256") != (
            "a682375f2e6e051f97322396bafc46974df47baa3518bc17f5d6b71b56407b73"
        ):
            raise GateError(f"cell {expected_id} has the wrong population identity")
        source_ordinal = strict_integer(
            record.get("source_ordinal"),
            "source ordinal",
            minimum=0,
            maximum=65_535,
        )
        literal_hex = record.get("literal_hex")
        if not isinstance(literal_hex, str) or len(literal_hex) != width * 2:
            raise GateError(f"cell {expected_id} has malformed literal hex")
        if any(character not in HEX_DIGITS for character in literal_hex):
            raise GateError(f"cell {expected_id} literal hex is not canonical lowercase")
        literal = bytes.fromhex(literal_hex)
        if literal != derive_literal(width, output_tag, source_ordinal):
            raise GateError(f"cell {expected_id} literal derivation drifted")
        literal_sha256 = lowercase_hex(
            record.get("literal_sha256"), 64, "literal SHA-256"
        )
        if hashlib.sha256(literal).hexdigest() != literal_sha256:
            raise GateError(f"cell {expected_id} literal hash drifted")
        expected_shape_tag = EXPECTED_WINDOWS.index(window_shape)
        if strict_integer(
            record.get("window_shape_tag"),
            "window shape tag",
            minimum=0,
            maximum=5,
        ) != expected_shape_tag:
            raise GateError(f"cell {expected_id} shape tag drifted")
        if record.get("fixture_recipe") != "fre-search-v26-long-scan-fixture-v1":
            raise GateError(f"cell {expected_id} fixture recipe drifted")
        filler = strict_integer(
            record.get("filler_byte"), "filler byte", minimum=0, maximum=255
        )
        if filler != lowest_unused_byte(literal):
            raise GateError(f"cell {expected_id} filler byte drifted")
        geometry = expected_geometry(width, accepted_ordinal, window_shape)
        window_start, window_end, haystack_len, expected_match = geometry
        for field, expected_value in (
            ("window_start", window_start),
            ("window_end", window_end),
            ("window_bytes", window_end - window_start),
            ("haystack_len", haystack_len),
        ):
            if strict_integer(record.get(field), field, minimum=0) != expected_value:
                raise GateError(f"cell {expected_id} {field} drifted")
        recorded_match = (record.get("expected_match_start"), record.get("expected_match_end"))
        if expected_match is None:
            if recorded_match != (None, None):
                raise GateError(f"cell {expected_id} no-match expectation drifted")
        else:
            for field, observed, expected_value in (
                ("expected_match_start", recorded_match[0], expected_match[0]),
                ("expected_match_end", recorded_match[1], expected_match[1]),
            ):
                if strict_integer(observed, field, minimum=0) != expected_value:
                    raise GateError(f"cell {expected_id} {field} drifted")
        lowercase_hex(record.get("haystack_sha256"), 64, "haystack SHA-256")
        lowercase_hex(record.get("fixture_sha256"), 64, "fixture SHA-256")
        output_sha256 = lowercase_hex(
            record.get("expected_output_sha256"), 64, "expected output SHA-256"
        )
        if output_sha256 != expected_output_sha256(output_tag, expected_match):
            raise GateError(f"cell {expected_id} expected-output hash drifted")
        haystack_sha256, fixture_sha256, reconstructed_match = reconstruct_fixture(
            record, literal
        )
        if (
            record["haystack_sha256"] != haystack_sha256
            or record["fixture_sha256"] != fixture_sha256
            or reconstructed_match != expected_match
        ):
            raise GateError(f"cell {expected_id} reconstructed fixture identity drifted")
        if expected_shape_tag == 0:
            population_hasher.update(width.to_bytes(2, "little"))
            population_hasher.update(bytes((output_tag,)))
            population_hasher.update(accepted_ordinal.to_bytes(2, "little"))
            population_hasher.update(source_ordinal.to_bytes(2, "little"))
            population_hasher.update(width.to_bytes(2, "little"))
            population_hasher.update(literal)
        cells[key] = record
        expected_id += 1
    if expected_id != EXPECTED_CELLS or len(cells) != EXPECTED_CELLS:
        raise GateError(f"cell manifest has {expected_id} records, expected {EXPECTED_CELLS}")
    expected_keys = [
        (width, OUTPUT_TAGS[output], ordinal, window)
        for width in range(6, 33)
        for output in EXPECTED_OUTPUTS
        for ordinal in range(16)
        for window in EXPECTED_WINDOWS
    ]
    if list(cells) != expected_keys:
        raise GateError("cell-manifest canonical ordering drifted")
    if population_hasher.hexdigest() != (
        "a682375f2e6e051f97322396bafc46974df47baa3518bc17f5d6b71b56407b73"
    ):
        raise GateError("reconstructed population identity drifted")
    return cells


def positive_integer(value: Any, name: str) -> int:
    return strict_integer(value, name, minimum=1)


def validate_calibrations(value: Any) -> dict[str, int]:
    if not isinstance(value, dict) or frozenset(value) != {
        "portable",
        "v17",
        "v26",
    }:
        raise GateError("calibration engine closure failed")
    chosen: dict[str, int] = {}
    for engine in ("portable", "v17", "v26"):
        calibration = value[engine]
        if not isinstance(calibration, dict):
            raise GateError(f"{engine} calibration is not an object")
        exact_keys(calibration, CALIBRATION_KEYS, f"{engine} calibration")
        iterations = positive_integer(
            calibration.get("iterations"), f"{engine} calibration iterations"
        )
        if iterations & (iterations - 1):
            raise GateError(f"{engine} calibrated iterations are not a power of two")
        elapsed_ns = positive_integer(
            calibration.get("elapsed_ns"), f"{engine} calibration elapsed_ns"
        )
        if elapsed_ns < 4_000_000:
            raise GateError(f"{engine} terminal calibration did not reach 4ms")
        previous_iterations = calibration.get("previous_iterations")
        previous_elapsed_ns = calibration.get("previous_elapsed_ns")
        if iterations == 1:
            if previous_iterations is not None or previous_elapsed_ns is not None:
                raise GateError(f"{engine} one-iteration calibration has a predecessor")
        else:
            previous = positive_integer(
                previous_iterations, f"{engine} previous calibration iterations"
            )
            previous_elapsed = positive_integer(
                previous_elapsed_ns, f"{engine} previous calibration elapsed_ns"
            )
            if previous * 2 != iterations:
                raise GateError(f"{engine} calibration did not exactly double")
            if previous_elapsed >= 4_000_000:
                raise GateError(f"{engine} previous calibration already reached 4ms")
        chosen[engine] = iterations
    return chosen


def validate_cell_result(
    record: Mapping[str, Any], expected: Mapping[str, Any], repetition_count: int = 12
) -> Fraction:
    exact_keys(record, CELL_RESULT_KEYS, "cell result")
    if record.get("schema") != "fre-search-v26-development-gate-cell-result-v1":
        raise GateError("unexpected cell result schema")
    if cell_key(record) != cell_key(expected):
        raise GateError("result cell identity differs from its sealed input")
    for field in CELL_IDENTITY_FIELDS:
        if record.get(field) != expected.get(field):
            raise GateError(f"result cell mutated sealed {field}")
    semantics = record.get("semantics")
    if not isinstance(semantics, dict):
        raise GateError("exact semantic evidence is not an object")
    exact_keys(semantics, SEMANTICS_KEYS, "semantic evidence")
    if semantics.get("equal") is not True:
        raise GateError("exact semantic equality did not pass")
    expected_digest = lowercase_hex(
        expected.get("expected_output_sha256"), 64, "sealed expected-output SHA-256"
    )
    semantic_digests = tuple(
        lowercase_hex(semantics.get(engine), 64, f"{engine} semantic SHA-256")
        for engine in ("expected", "portable", "v17", "v26")
    )
    if set(semantic_digests) != {expected_digest}:
        raise GateError("expected/portable/V17/V26 semantics differ")
    calibrated_iterations = validate_calibrations(record.get("calibrations"))
    repetitions = record.get("repetitions")
    if not isinstance(repetitions, list) or len(repetitions) != repetition_count:
        raise GateError("cell does not contain exactly 12 repetitions")
    if repetition_count != 12:
        raise GateError("the frozen gate requires exactly 12 repetitions")
    ratios: list[Fraction] = []
    for index, repetition in enumerate(repetitions):
        if not isinstance(repetition, dict):
            raise GateError("repetition is not an object")
        exact_keys(repetition, REPETITION_KEYS, f"repetition {index}")
        if strict_integer(
            repetition.get("repetition"), "repetition ordinal", minimum=0
        ) != index:
            raise GateError("repetition ordinal closure failed")
        order_value = repetition.get("order")
        if not isinstance(order_value, list) or any(
            not isinstance(engine, str) for engine in order_value
        ):
            raise GateError(f"repetition {index} order is malformed")
        order = tuple(order_value)
        if order != EXPECTED_ORDERS[index]:
            raise GateError(f"repetition {index} has the wrong engine order")
        engines = repetition.get("engines")
        if not isinstance(engines, dict) or set(engines) != {"portable", "v17", "v26"}:
            raise GateError("repetition engine closure failed")
        elapsed_by_engine: dict[str, int] = {}
        for engine in ("portable", "v17", "v26"):
            sample = engines[engine]
            if not isinstance(sample, dict):
                raise GateError("engine sample is not an object")
            exact_keys(sample, ENGINE_SAMPLE_KEYS, f"{engine} timing sample")
            elapsed = positive_integer(sample.get("elapsed_ns"), f"{engine} elapsed_ns")
            iterations = positive_integer(sample.get("iterations"), f"{engine} iterations")
            if iterations != calibrated_iterations[engine]:
                raise GateError(
                    f"{engine} timing iterations differ from sealed calibration"
                )
            elapsed_by_engine[engine] = elapsed
        ratios.append(
            Fraction(
                elapsed_by_engine["v26"] * calibrated_iterations["v17"],
                calibrated_iterations["v26"] * elapsed_by_engine["v17"],
            )
        )
    return median12(ratios)


def evaluate_thresholds(
    ratios_by_key: Mapping[tuple[int, int, int, str], Fraction],
    acceptance: Mapping[str, Any],
) -> dict[str, Any]:
    if len(ratios_by_key) != EXPECTED_CELLS:
        raise GateError("threshold evaluation requires the complete cell population")
    ratios = list(ratios_by_key.values())
    if any(not isinstance(ratio, Fraction) or ratio <= 0 for ratio in ratios):
        raise GateError("threshold evaluation requires positive exact Fraction ratios")
    short = [ratio for key, ratio in ratios_by_key.items() if key[0] <= 8]
    wide = [ratio for key, ratio in ratios_by_key.items() if key[0] >= 9]
    by_output: dict[int, list[Fraction]] = defaultdict(list)
    by_window: dict[str, list[Fraction]] = defaultdict(list)
    for key, ratio in ratios_by_key.items():
        by_output[key[1]].append(ratio)
        by_window[key[3]].append(ratio)
    output_names = {1: "exists", 2: "selected_end", 3: "span"}
    output_gm = {output_names[tag]: geomean(by_output[tag]) for tag in sorted(by_output)}
    window_gm = {window: geomean(by_window[window]) for window in EXPECTED_WINDOWS}
    over = sum(ratio > Fraction(21, 20) for ratio in ratios)
    maximum = max(ratios)
    overall_geomean = geomean(ratios)
    short_geomean = geomean(short)
    wide_geomean = geomean(wide)
    p95 = nearest_rank(ratios, 7_388)
    report = {
        "overall_geomean": overall_geomean,
        "short_width_6_through_8_geomean": short_geomean,
        "wide_width_9_through_32_geomean": wide_geomean,
        "output_geomeans": output_gm,
        "window_geomeans": window_gm,
        "cells_strictly_over_1_05": over,
        "cells_strictly_over_1_05_fraction": over / EXPECTED_CELLS,
        "maximum_cell_ratio": float(maximum),
        "maximum_cell_ratio_exact": f"{maximum.numerator}/{maximum.denominator}",
        "p95_nearest_rank_7388": float(p95),
        "p95_nearest_rank_7388_exact": f"{p95.numerator}/{p95.denominator}",
    }
    threshold = lambda key: Fraction(str(acceptance[key]))
    checks = {
        "overall": overall_geomean <= float(threshold("overall_geomean_lte")),
        "short": short_geomean
        <= float(threshold("short_width_6_through_8_geomean_lte")),
        "wide": wide_geomean
        <= float(threshold("wide_width_9_through_32_geomean_lte")),
        "outputs": all(
            value <= float(threshold("every_output_geomean_lte"))
            for value in output_gm.values()
        ),
        "windows": all(
            value <= float(threshold("every_window_shape_geomean_lte"))
            for value in window_gm.values()
        ),
        "tail_count": over
        <= strict_integer(
            acceptance["cells_strictly_over_1_05_lte"],
            "tail-count acceptance",
            minimum=0,
        ),
        "tail_fraction": Fraction(over, EXPECTED_CELLS)
        <= threshold("cells_strictly_over_1_05_fraction_lte"),
        "maximum": maximum <= threshold("maximum_cell_ratio_lte"),
    }
    report["checks"] = checks
    report["pass"] = all(checks.values())
    return report


def validate_one_shot_seal(
    seal: Mapping[str, Any],
    seal_file: StableFile,
    expected_seal_sha256: str,
    contract: Mapping[str, Any],
    contract_file: StableFile,
    cells_file: StableFile,
    archive_file: StableFile,
    runner_file: StableFile,
    launcher_file: StableFile,
    analyzer_file: StableFile,
) -> None:
    exact_keys(seal, SEAL_KEYS, "one-shot seal")
    if seal.get("schema") != "fre-search-v26-development-gate-one-shot-seal-v1":
        raise GateError("unexpected one-shot seal schema")
    if seal.get("status") != "SEALED_READY_FOR_ONE_SHOT_TIMING":
        raise GateError("one-shot seal is not timing authority")
    expected_seal_sha256 = lowercase_hex(
        expected_seal_sha256, 64, "externally reviewed one-shot seal SHA-256"
    )
    if seal_file.sha256 != expected_seal_sha256:
        raise GateError("one-shot seal differs from the externally reviewed hash")
    if seal_file.mode & 0o222:
        raise GateError("one-shot seal remains writable")
    for artifact_name, artifact in (
        ("source archive", archive_file),
        ("runner binary", runner_file),
        ("launcher", launcher_file),
    ):
        if artifact.mode & 0o222:
            raise GateError(f"sealed {artifact_name} remains writable")
    if not runner_file.mode & 0o111:
        raise GateError("sealed runner binary is not executable")
    candidate = contract["candidate"]
    expected_values = {
        "source_commit": candidate["source_commit"],
        "source_tree": candidate["source_tree"],
        "source_archive_sha256": archive_file.sha256,
        "runner_binary_sha256": runner_file.sha256,
        "runner_binary_bytes": len(runner_file.data),
        "contract_sha256": contract_file.sha256,
        "cell_manifest_sha256": cells_file.sha256,
        "launcher_sha256": launcher_file.sha256,
        "analyzer_sha256": analyzer_file.sha256,
        "timing_runs": 1,
    }
    for field, expected in expected_values.items():
        observed = seal.get(field)
        if isinstance(expected, int):
            strict_integer(observed, f"seal {field}", minimum=1)
        if observed != expected:
            raise GateError(f"one-shot seal {field} identity mismatch")
    for field in (
        "source_archive_sha256",
        "runner_binary_sha256",
        "contract_sha256",
        "cell_manifest_sha256",
        "launcher_sha256",
        "analyzer_sha256",
        "authorization_nonce",
    ):
        lowercase_hex(seal.get(field), 64, f"seal {field}")
    lowercase_hex(seal.get("source_commit"), 40, "seal source commit")
    lowercase_hex(seal.get("source_tree"), 40, "seal source tree")


def validate_run_manifest(
    run_manifest: Mapping[str, Any],
    run_manifest_file: StableFile,
    seal: Mapping[str, Any],
    seal_file: StableFile,
    contract: Mapping[str, Any],
    contract_file: StableFile,
    cells_file: StableFile,
) -> tuple[list[int], list[str], str, str]:
    exact_keys(run_manifest, RUN_MANIFEST_KEYS, "run manifest")
    if run_manifest.get("schema") != "fre-search-v26-development-gate-run-manifest-v1":
        raise GateError("unexpected run-manifest schema")
    if run_manifest.get("status") != "SEALED_BEFORE_TIMING":
        raise GateError("run manifest was not sealed before timing")
    if run_manifest_file.mode & 0o222:
        raise GateError("run manifest remains writable")
    expected = {
        "one_shot_seal_sha256": seal_file.sha256,
        "authorization_nonce": seal["authorization_nonce"],
        "source_commit": seal["source_commit"],
        "source_tree": seal["source_tree"],
        "source_archive_sha256": seal["source_archive_sha256"],
        "runner_binary_sha256": seal["runner_binary_sha256"],
        "runner_binary_bytes": seal["runner_binary_bytes"],
        "contract_sha256": contract_file.sha256,
        "cell_manifest_sha256": cells_file.sha256,
    }
    for field, expected_value in expected.items():
        if run_manifest.get(field) != expected_value:
            raise GateError(f"run manifest {field} identity mismatch")
    if (
        run_manifest["source_commit"] != contract["candidate"]["source_commit"]
        or run_manifest["source_tree"] != contract["candidate"]["source_tree"]
    ):
        raise GateError("run-manifest source differs from the sealed contract")
    run_nonce = lowercase_hex(run_manifest.get("run_nonce"), 64, "run nonce")
    host_fingerprint = lowercase_hex(
        run_manifest.get("host_fingerprint_sha256"), 64, "host fingerprint"
    )
    cpu_value = run_manifest.get("cpu_ids")
    if not isinstance(cpu_value, list) or len(cpu_value) != 3:
        raise GateError("run manifest requires exactly three CPU IDs")
    cpu_ids = [
        strict_integer(cpu_id, f"CPU ID {index}", minimum=0)
        for index, cpu_id in enumerate(cpu_value)
    ]
    if len(set(cpu_ids)) != 3:
        raise GateError("run manifest CPU IDs are not distinct")
    shard_map = run_manifest.get("shard_cpu_map")
    if not isinstance(shard_map, list) or len(shard_map) != 3:
        raise GateError("run manifest shard/CPU map is incomplete")
    shard_nonces: list[str] = []
    for shard_id, mapping in enumerate(shard_map):
        if not isinstance(mapping, dict):
            raise GateError("run manifest shard/CPU mapping is not an object")
        exact_keys(
            mapping,
            frozenset(("shard_id", "cpu_id", "shard_nonce")),
            "shard/CPU mapping",
        )
        if (
            strict_integer(mapping.get("shard_id"), "mapped shard ID", minimum=0, maximum=2)
            != shard_id
            or strict_integer(mapping.get("cpu_id"), "mapped CPU ID", minimum=0)
            != cpu_ids[shard_id]
        ):
            raise GateError("run manifest shard/CPU mapping drifted")
        shard_nonces.append(
            lowercase_hex(
                mapping.get("shard_nonce"), 64, f"shard {shard_id} nonce"
            )
        )
    if len(set(shard_nonces)) != 3 or run_nonce in shard_nonces:
        raise GateError("run and shard nonces are not distinct")
    return cpu_ids, shard_nonces, host_fingerprint, run_nonce


def validate_shard_file(
    source: StableFile,
    shard_id: int,
    expected_header: Mapping[str, Any],
    expected_shard_nonce: str,
    expected_run_nonce: str,
    cells: Mapping[tuple[int, int, int, str], Mapping[str, Any]],
) -> dict[tuple[int, int, int, str], Fraction]:
    if source.mode & 0o222:
        raise GateError(f"shard {shard_id} result remains writable")
    records = list(read_jsonl_file(source))
    if len(records) != EXPECTED_SHARD_CELLS + 2:
        raise GateError(f"shard {shard_id} has the wrong record count")
    header, *body, footer = records
    validate_shard_header(header, shard_id, expected_header)
    observed: dict[tuple[int, int, int, str], Fraction] = {}
    observed_keys: list[tuple[int, int, int, str]] = []
    for result in body:
        key = cell_key(result)
        expected = cells.get(key)
        if expected is None or expected_shard(key[0]) != shard_id or key in observed:
            raise GateError(f"shard {shard_id} contains an unknown or duplicate cell {key}")
        observed[key] = validate_cell_result(result, expected)
        observed_keys.append(key)
    if len(observed) != EXPECTED_SHARD_CELLS:
        raise GateError(f"shard {shard_id} is incomplete")
    expected_keys_for_shard = [
        key for key in cells if expected_shard(key[0]) == shard_id
    ]
    if observed_keys != expected_keys_for_shard:
        raise GateError(f"shard {shard_id} cell ordering drifted")
    exact_keys(footer, SHARD_FOOTER_KEYS, f"shard {shard_id} footer")
    if (
        footer.get("schema") != "fre-search-v26-development-gate-shard-footer-v1"
        or strict_integer(
            footer.get("shard_id"), "footer shard ID", minimum=0, maximum=2
        )
        != shard_id
        or strict_integer(footer.get("cells"), "footer cell count", minimum=1)
        != EXPECTED_SHARD_CELLS
        or footer.get("complete") is not True
        or footer.get("shard_nonce") != expected_shard_nonce
        or footer.get("run_nonce") != expected_run_nonce
    ):
        raise GateError(f"shard {shard_id} footer is not terminal")
    return observed


def validate_shard_header(
    header: Mapping[str, Any],
    shard_id: int,
    expected_header: Mapping[str, Any],
) -> None:
    exact_keys(header, SHARD_HEADER_KEYS, f"shard {shard_id} header")
    strict_integer(header.get("shard_id"), "header shard ID", minimum=0, maximum=2)
    strict_integer(header.get("candidate_backend"), "candidate backend", minimum=1)
    strict_integer(header.get("reference_backend"), "reference backend", minimum=1)
    strict_integer(header.get("runner_binary_bytes"), "runner binary bytes", minimum=1)
    strict_integer(header.get("cpu_id"), "header CPU ID", minimum=0)
    if header != expected_header:
        raise GateError(f"shard {shard_id} header identity mismatch")


def analyze_paths(
    expected_seal_sha256: str,
    seal_path: Path,
    contract_path: Path,
    cells_path: Path,
    run_manifest_path: Path,
    archive_path: Path,
    runner_path: Path,
    launcher_path: Path,
    shard_paths: Sequence[Path],
) -> dict[str, Any]:
    if len(shard_paths) != 3:
        raise GateError("exactly three shard files are required")
    seal_file = stable_read(seal_path, MAX_SEAL_BYTES)
    contract_file = stable_read(contract_path, MAX_CONTRACT_BYTES)
    cells_file = stable_read(cells_path, MAX_CELL_MANIFEST_BYTES)
    run_manifest_file = stable_read(run_manifest_path, MAX_RUN_MANIFEST_BYTES)
    archive_file = stable_read(archive_path, MAX_SHARD_BYTES)
    runner_file = stable_read(runner_path, MAX_SHARD_BYTES)
    launcher_file = stable_read(launcher_path, MAX_CONTRACT_BYTES)
    analyzer_file = stable_read(Path(__file__), MAX_CONTRACT_BYTES)
    seal = read_json_file(seal_file)
    contract = read_json_file(contract_file)
    require_exact_contract(contract, contract_file, cells_file)
    validate_one_shot_seal(
        seal,
        seal_file,
        expected_seal_sha256,
        contract,
        contract_file,
        cells_file,
        archive_file,
        runner_file,
        launcher_file,
        analyzer_file,
    )
    run_manifest = read_json_file(run_manifest_file)
    cpu_ids, shard_nonces, host_fingerprint, run_nonce = validate_run_manifest(
        run_manifest,
        run_manifest_file,
        seal,
        seal_file,
        contract,
        contract_file,
        cells_file,
    )
    cells = validate_cell_manifest(read_jsonl_file(cells_file))
    ratios: dict[tuple[int, int, int, str], Fraction] = {}
    shard_sha256: list[str] = []
    for shard_id, shard_path in enumerate(shard_paths):
        shard_file = stable_read(shard_path, MAX_SHARD_BYTES)
        expected_header = {
            "schema": "fre-search-v26-development-gate-shard-header-v1",
            "shard_id": shard_id,
            "candidate_backend": 39,
            "reference_backend": 30,
            "source_commit": seal["source_commit"],
            "source_tree": seal["source_tree"],
            "source_archive_sha256": seal["source_archive_sha256"],
            "runner_binary_sha256": seal["runner_binary_sha256"],
            "runner_binary_bytes": seal["runner_binary_bytes"],
            "contract_sha256": contract_file.sha256,
            "cell_manifest_sha256": cells_file.sha256,
            "host_fingerprint_sha256": host_fingerprint,
            "cpu_id": cpu_ids[shard_id],
            "shard_nonce": shard_nonces[shard_id],
            "run_nonce": run_nonce,
            "one_shot_seal_sha256": seal_file.sha256,
            "run_manifest_sha256": run_manifest_file.sha256,
        }
        shard_ratios = validate_shard_file(
            shard_file,
            shard_id,
            expected_header,
            shard_nonces[shard_id],
            run_nonce,
            cells,
        )
        overlap = ratios.keys() & shard_ratios.keys()
        if overlap:
            raise GateError(f"cross-shard duplicate cells: {sorted(overlap)[:1]}")
        ratios.update(shard_ratios)
        shard_sha256.append(shard_file.sha256)
    if set(ratios) != set(cells):
        raise GateError("three-shard result closure differs from the sealed cell manifest")
    metrics = evaluate_thresholds(ratios, contract["acceptance"])
    return {
        "schema": "fre-search-v26-development-gate-analysis-v1",
        "one_shot_seal_sha256": seal_file.sha256,
        "run_manifest_sha256": run_manifest_file.sha256,
        "contract_sha256": contract_file.sha256,
        "cell_manifest_sha256": cells_file.sha256,
        "source_archive_sha256": archive_file.sha256,
        "runner_binary_sha256": runner_file.sha256,
        "host_fingerprint_sha256": host_fingerprint,
        "cpu_ids": cpu_ids,
        "shard_nonces": shard_nonces,
        "run_nonce": run_nonce,
        "shard_sha256": shard_sha256,
        "cells": len(ratios),
        "semantics": {"comparisons": len(ratios) * 3, "mismatches": 0, "pass": True},
        "metrics": metrics,
        "pass": metrics["pass"],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-seal-sha256", required=True)
    parser.add_argument("seal", type=Path)
    parser.add_argument("contract", type=Path)
    parser.add_argument("cells", type=Path)
    parser.add_argument("run_manifest", type=Path)
    parser.add_argument("source_archive", type=Path)
    parser.add_argument("runner", type=Path)
    parser.add_argument("launcher", type=Path)
    parser.add_argument("shards", nargs=3, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        report = analyze_paths(
            args.expected_seal_sha256,
            args.seal,
            args.contract,
            args.cells,
            args.run_manifest,
            args.source_archive,
            args.runner,
            args.launcher,
            args.shards,
        )
    except GateError as error:
        print(json.dumps({"schema": "fre-search-v26-development-gate-error-v1", "error": str(error)}))
        return 2
    json.dump(report, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
