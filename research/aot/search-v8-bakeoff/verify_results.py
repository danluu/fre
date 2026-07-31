#!/usr/bin/env python3
"""Strict raw-evidence verifier for the Search V8 three-engine bakeoff."""

from __future__ import annotations

import csv
import math
import os
import re
import stat
import sys
from collections import defaultdict
from pathlib import Path
from typing import Mapping, Sequence

import verify_linked_image as linked_verifier
from verify_common import (
    HEX64,
    MAX_OBJECT_BYTES,
    MAX_TEXT_BYTES,
    RECEIPT_KEYS,
    RECEIPT_SCHEMA,
    VerificationError,
    canonical_uint,
    fail,
    parse_receipt,
    parse_tsv,
    regular_file,
    sha256_file,
    strict_text,
)

HOT_SCHEMA = "fre-search-v8-bakeoff-hot-v1"
COLD_SCHEMA = "fre-search-v8-bakeoff-cold-v1"
FIRST_SCHEMA = "fre-search-v8-bakeoff-ready-first-call-v1"
LIFECYCLE_SCHEMA = "fre-search-v8-bakeoff-lifecycle-v1"
COMPLETION_SCHEMA = "fre-search-v8-bakeoff-completion-v3"
HOT_HEADER = (
    "schema,revision,pid,repetition,cell,size,scenario,order,engine,stage,"
    "iterations,total_ns,ns_per_iter,checksum,semantic_value,haystack_bytes,"
    "window_start,window_end,alignment_mod16,route,authority,backend,"
    "qualification_state,production_activation,benchmark_source_sha256,"
    "semantic_identity,source_identity,artifact_identity,compile_identity,"
    "object_identity,payload_sha256"
).split(",")
COLD_HEADER = (
    "schema,revision,pid,repetition,order,phase,iterations,total_ns,ns_per_iter,"
    "checksum,scope,qualification_state,production_activation,"
    "benchmark_source_sha256,semantic_identity,source_identity,"
    "artifact_identity,compile_identity,object_identity,payload_sha256"
).split(",")
FIRST_HEADER = (
    "schema,revision,pid,repetition,cell,size,scenario,engine,stage,iterations,"
    "total_ns,ns_per_iter,checksum,semantic_value,haystack_bytes,"
    "alignment_mod16,route,authority,backend,qualification_state,"
    "production_activation,benchmark_source_sha256,semantic_identity,"
    "source_identity,artifact_identity,compile_identity,object_identity,"
    "payload_sha256"
).split(",")
LIFECYCLE_HEADER = (
    "schema,revision,pid,repetition,cell,size,scenario,calls,order,engine,stage,"
    "total_ns,checksum,semantic_value,haystack_bytes,alignment_mod16,route,"
    "authority,backend,qualification_state,production_activation,"
    "benchmark_source_sha256,semantic_identity,source_identity,"
    "artifact_identity,compile_identity,object_identity,payload_sha256"
).split(",")
SUMMARY_HEADER = [
    "cell",
    "size",
    "scenario",
    "samples",
    "portable_geomean_ns",
    "raw_static_aot_geomean_ns",
    "strict_wx_jit_geomean_ns",
    "portable_over_aot",
    "portable_over_jit",
    "aot_over_jit",
    "aot_pair_wins",
    "jit_pair_wins",
]
LIFECYCLE_SUMMARY_HEADER = [
    "cell",
    "size",
    "scenario",
    "calls",
    "samples",
    "portable_geomean_total_ns",
    "strict_wx_jit_geomean_total_ns",
    "strict_wx_jit_over_portable_paired_geomean",
    "strict_wx_jit_pair_wins",
    "strict_gate",
]
LIFECYCLE_BREAK_EVEN_HEADER = [
    "case",
    "size",
    "scenario",
    "samples_per_call_count",
    "strict_ratio_limit",
    "strict_win_minimum",
    "empirical_status",
    "empirical_sustained_calls",
    "modeled_status",
    "modeled_calls",
    "model_portable_setup_ns",
    "model_strict_wx_jit_setup_ns",
    "model_portable_per_call_ns",
    "model_strict_wx_jit_per_call_ns",
]
IDENTITY_FIELDS = [
    "benchmark_source_sha256",
    "semantic_identity",
    "source_identity",
    "artifact_identity",
    "compile_identity",
    "object_identity",
    "payload_sha256",
]
NAMED_SCENARIOS = [
    "present",
    "absent",
    "dense",
    "tail",
    "primary-dense-secondary-absent",
    "adaptive-secondary-dense-primary-absent",
    "pair-dense-literal-absent",
    "triple-dense-literal-absent",
    "false-pair-distant-match",
    "binary",
    "natural-text",
]
SCENARIOS = NAMED_SCENARIOS + [f"alignment-{index}" for index in range(16)]
SIZES = {"64k": (65536, 1024), "1m": (1048576, 64)}
ENGINES = {
    "raw-static-aot": (
        "raw-statically-linked-aot",
        "benchmark-local-raw-abi-no-adoption",
        "aarch64-search-v8-static",
    ),
    "strict-wx-jit": (
        "strict-wx-published-jit",
        "runtime-audited-candidate",
        "aarch64-search-v8",
    ),
    "portable": ("portable-exact-literal", "portable", "portable"),
}
ENGINE_ORDERS = [
    ["raw-static-aot", "strict-wx-jit", "portable"],
    ["raw-static-aot", "portable", "strict-wx-jit"],
    ["strict-wx-jit", "raw-static-aot", "portable"],
    ["strict-wx-jit", "portable", "raw-static-aot"],
    ["portable", "raw-static-aot", "strict-wx-jit"],
    ["portable", "strict-wx-jit", "raw-static-aot"],
]
COLD_PHASES = {
    "portable-source-build": "portable-runtime-construction",
    "span-kir-build": "shared-native-kir-construction",
    "v8-emit-retained-kir": "shared-native-machine-code-emission",
    "jit-publish-retained-image": "strict-wx-publication-only",
    "aot-object-retained-image": "macho-object-wrap-only-no-link",
    "jit-source-to-ready": "source-kir-emit-strict-wx-no-first-call",
    "aot-source-to-object": "source-first-compiler-to-receipted-macho-no-link-no-adoption",
}
FIRST_CASES = [
    ("64k", "absent"),
    ("64k", "adaptive-secondary-dense-primary-absent"),
    ("1m", "tail"),
    ("1m", "natural-text"),
]
LIFECYCLE_CASES = FIRST_CASES
LIFECYCLE_CALL_GRIDS = {
    "64k": [0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024],
    "1m": [0, 1, 2, 4, 8, 16, 32, 64],
}
LIFECYCLE_ENGINES = {
    "portable": (
        "portable-lifecycle",
        "portable",
        "portable",
        "portable-builder-plus-public-calls",
    ),
    "strict-wx-jit": (
        "strict-wx-jit-lifecycle",
        "runtime-audited-candidate",
        "aarch64-search-v8",
        "plan-kir-emit-strict-wx-plus-public-calls",
    ),
}
LIFECYCLE_ENGINE_ORDERS = [
    ["portable", "strict-wx-jit"],
    ["strict-wx-jit", "portable"],
]
HEX16 = re.compile(r"^0x[0-9a-f]{16}$")
HOT_REPETITIONS = 12
COLD_REPETITIONS = 12
COLD_ITERATIONS = 20
FIRST_REPETITIONS = 20
LIFECYCLE_REPETITIONS = 24
LIFECYCLE_RATIO_LIMIT = 0.98
LIFECYCLE_WIN_MINIMUM = 20
LIFECYCLE_MAX_BYTES_PER_CELL = 64 * 1024 * 1024
HOT_ROWS = 2 * 27 * HOT_REPETITIONS * 3
COLD_ROWS = COLD_REPETITIONS * len(COLD_PHASES)
FIRST_ROWS = len(FIRST_CASES) * len(ENGINES) * FIRST_REPETITIONS
LIFECYCLE_CALL_CELLS = sum(
    len(LIFECYCLE_CALL_GRIDS[size]) for size, _ in LIFECYCLE_CASES
)
LIFECYCLE_INVOCATIONS = LIFECYCLE_CALL_CELLS * LIFECYCLE_REPETITIONS
LIFECYCLE_ROWS = LIFECYCLE_INVOCATIONS * len(LIFECYCLE_ENGINES)


def parse_csv(path: Path, header: Sequence[str], expected_rows: int) -> list[dict[str, str]]:
    text = strict_text(path)
    try:
        records = list(csv.reader(text.splitlines(), strict=True))
    except csv.Error as error:
        fail(f"{path} is not strict CSV: {error}")
    if not records or records[0] != list(header):
        fail(f"{path} has an unexpected header")
    if len(records) - 1 != expected_rows:
        fail(f"{path} has {len(records) - 1} rows, expected {expected_rows}")
    rows: list[dict[str, str]] = []
    for ordinal, fields in enumerate(records[1:], 2):
        if len(fields) != len(header):
            fail(f"{path}:{ordinal} has {len(fields)} fields")
        if any(not field or "," in field or "\n" in field for field in fields):
            fail(f"{path}:{ordinal} has an empty or noncanonical field")
        rows.append(dict(zip(header, fields, strict=True)))
    return rows


def validate_bound_fields(row: Mapping[str, str], receipt: Mapping[str, str]) -> None:
    if row["revision"] != receipt["subject_revision"]:
        fail("row revision differs from receipt")
    for field in IDENTITY_FIELDS:
        if row[field] != receipt[field] or not HEX64.fullmatch(row[field]):
            fail(f"row {field} differs from receipt")
    if row["qualification_state"] != "candidate":
        fail("row qualification state is not candidate")
    if row["production_activation"] != "absent":
        fail("row claims production activation")


def validate_engine(row: Mapping[str, str]) -> None:
    engine = row["engine"]
    if engine not in ENGINES:
        fail(f"unexpected engine {engine!r}")
    route, authority, backend = ENGINES[engine]
    if (row["route"], row["authority"], row["backend"]) != (
        route,
        authority,
        backend,
    ):
        fail(f"engine {engine} route/authority/backend mismatch")


def validate_time(row: Mapping[str, str], expected_iterations: int) -> float:
    iterations = canonical_uint(row["iterations"], 1, 4096, "iterations")
    if iterations != expected_iterations:
        fail(f"iterations={iterations}, expected {expected_iterations}")
    total = canonical_uint(row["total_ns"], 1, 3_600_000_000_000, "total_ns")
    per = canonical_uint(row["ns_per_iter"], 0, total, "ns_per_iter")
    if per != total // iterations:
        fail("ns_per_iter is not floor(total_ns / iterations)")
    if not HEX16.fullmatch(row["checksum"]):
        fail("invalid checksum")
    return total / iterations


def expected_alignment(scenario: str) -> int:
    if scenario in NAMED_SCENARIOS:
        return 0
    if scenario.startswith("alignment-"):
        return int(scenario.removeprefix("alignment-"))
    fail(f"unexpected scenario {scenario!r}")
    raise AssertionError


def validate_hot_rows(
    rows: Sequence[Mapping[str, str]], receipt: Mapping[str, str]
) -> list[list[str]]:
    expected_sequence = [
        (size, scenario, repetition, engine)
        for size in SIZES
        for scenario in SCENARIOS
        for repetition in range(HOT_REPETITIONS)
        for engine in ENGINE_ORDERS[repetition % len(ENGINE_ORDERS)]
    ]
    expected_groups = {
        (size, scenario, repetition)
        for size in SIZES
        for scenario in SCENARIOS
        for repetition in range(HOT_REPETITIONS)
    }
    grouped: dict[tuple[str, str, int], dict[str, tuple[Mapping[str, str], float]]] = (
        defaultdict(dict)
    )
    semantic_by_cell: dict[tuple[str, str], str] = {}
    checksum_by_cell: dict[tuple[str, str], str] = {}
    for row, expected_item in zip(rows, expected_sequence, strict=True):
        if row["schema"] != HOT_SCHEMA or row["stage"] != "hot":
            fail("hot row schema/stage mismatch")
        validate_bound_fields(row, receipt)
        validate_engine(row)
        canonical_uint(row["pid"], 1, 4_294_967_295, "pid")
        repetition = canonical_uint(
            row["repetition"], 0, HOT_REPETITIONS - 1, "hot repetition"
        )
        size = row["size"]
        scenario = row["scenario"]
        if size not in SIZES or scenario not in SCENARIOS:
            fail("hot row size/scenario is outside the closed matrix")
        if (size, scenario, repetition, row["engine"]) != expected_item:
            fail("hot rows are not in canonical invocation/engine order")
        bytes_count, iterations = SIZES[size]
        if row["cell"] != f"span-{size}-{scenario}":
            fail("hot cell name mismatch")
        expected_order = "+".join(ENGINE_ORDERS[repetition % len(ENGINE_ORDERS)])
        if row["order"] != expected_order:
            fail("hot row order mismatch")
        if canonical_uint(row["haystack_bytes"], 1, 1 << 20, "haystack bytes") != bytes_count:
            fail("hot haystack byte count mismatch")
        if row["window_start"] != "0" or canonical_uint(
            row["window_end"], 1, 1 << 20, "window end"
        ) != bytes_count:
            fail("hot window is not the complete haystack")
        alignment = canonical_uint(row["alignment_mod16"], 0, 15, "alignment")
        if alignment != expected_alignment(scenario):
            fail("hot fixture alignment mismatch")
        if not HEX16.fullmatch(row["semantic_value"]):
            fail("invalid hot semantic value")
        per_call = validate_time(row, iterations)
        key = (size, scenario, repetition)
        engine = row["engine"]
        if engine in grouped[key]:
            fail("duplicate hot engine row")
        grouped[key][engine] = (row, per_call)
        cell = (size, scenario)
        previous_semantic = semantic_by_cell.setdefault(cell, row["semantic_value"])
        previous_checksum = checksum_by_cell.setdefault(cell, row["checksum"])
        if row["semantic_value"] != previous_semantic or row["checksum"] != previous_checksum:
            fail("hot semantic/checksum drifted across engine or repetition")
    if set(grouped) != expected_groups:
        fail("hot matrix is incomplete or has extra groups")

    samples: dict[tuple[str, str], dict[str, list[float]]] = defaultdict(
        lambda: defaultdict(list)
    )
    wins = {"raw-static-aot": 0, "strict-wx-jit": 0}
    pairs = {"raw-static-aot": 0, "strict-wx-jit": 0}
    for (size, scenario, _), engines in grouped.items():
        if set(engines) != set(ENGINES):
            fail("hot group does not contain exactly three engines")
        portable = engines["portable"][1]
        for engine, (_, per_call) in engines.items():
            samples[(size, scenario)][engine].append(per_call)
        for native in wins:
            pairs[native] += 1
            if engines[native][1] < portable:
                wins[native] += 1

    summary: list[list[str]] = [SUMMARY_HEADER]
    for size in SIZES:
        for scenario in SCENARIOS:
            cell_samples = samples[(size, scenario)]
            if any(len(cell_samples[engine]) != HOT_REPETITIONS for engine in ENGINES):
                fail("hot cell sample cardinality mismatch")
            geomean = {
                engine: math.exp(
                    sum(math.log(value) for value in cell_samples[engine])
                    / HOT_REPETITIONS
                )
                for engine in ENGINES
            }
            if not all(math.isfinite(value) and value > 0 for value in geomean.values()):
                fail("non-finite hot geomean")
            portable_over_aot = geomean["portable"] / geomean["raw-static-aot"]
            portable_over_jit = geomean["portable"] / geomean["strict-wx-jit"]
            if portable_over_aot <= 1.0 or portable_over_jit <= 1.0:
                fail(f"native engine is not faster in span-{size}-{scenario}")
            aot_cell_wins = sum(
                aot < portable
                for aot, portable in zip(
                    cell_samples["raw-static-aot"],
                    cell_samples["portable"],
                    strict=True,
                )
            )
            jit_cell_wins = sum(
                jit < portable
                for jit, portable in zip(
                    cell_samples["strict-wx-jit"],
                    cell_samples["portable"],
                    strict=True,
                )
            )
            summary.append(
                [
                    f"span-{size}-{scenario}",
                    size,
                    scenario,
                    str(HOT_REPETITIONS),
                    f"{geomean['portable']:.9f}",
                    f"{geomean['raw-static-aot']:.9f}",
                    f"{geomean['strict-wx-jit']:.9f}",
                    f"{portable_over_aot:.9f}",
                    f"{portable_over_jit:.9f}",
                    f"{geomean['raw-static-aot'] / geomean['strict-wx-jit']:.9f}",
                    str(aot_cell_wins),
                    str(jit_cell_wins),
                ]
            )
    for native in wins:
        if pairs[native] != 648 or wins[native] / pairs[native] < 0.95:
            fail(f"{native} strict same-process win rate is below 95%")
    return summary


def validate_cold_rows(
    rows: Sequence[Mapping[str, str]], receipt: Mapping[str, str]
) -> None:
    grouped: dict[int, dict[str, Mapping[str, str]]] = defaultdict(dict)
    checksum_by_phase: dict[str, str] = {}
    phases = list(COLD_PHASES)
    expected_sequence = [
        (repetition, phases[(repetition + offset) % len(phases)])
        for repetition in range(COLD_REPETITIONS)
        for offset in range(len(phases))
    ]
    for row, expected_item in zip(rows, expected_sequence, strict=True):
        if row["schema"] != COLD_SCHEMA:
            fail("cold row schema mismatch")
        validate_bound_fields(row, receipt)
        canonical_uint(row["pid"], 1, 4_294_967_295, "pid")
        repetition = canonical_uint(
            row["repetition"], 0, COLD_REPETITIONS - 1, "cold repetition"
        )
        phase = row["phase"]
        if phase not in COLD_PHASES or row["scope"] != COLD_PHASES[phase]:
            fail("cold phase/scope mismatch")
        if (repetition, phase) != expected_item:
            fail("cold rows are not in canonical invocation/phase order")
        if row["order"] != f"rotation-{repetition % len(phases)}":
            fail("cold order mismatch")
        validate_time(row, COLD_ITERATIONS)
        if phase in grouped[repetition]:
            fail("duplicate cold phase")
        grouped[repetition][phase] = row
        checksum = checksum_by_phase.setdefault(phase, row["checksum"])
        if checksum != row["checksum"]:
            fail("cold phase checksum drifted")
    if set(grouped) != set(range(COLD_REPETITIONS)):
        fail("cold repetition matrix mismatch")
    if any(set(grouped[repetition]) != set(COLD_PHASES) for repetition in grouped):
        fail("cold phase matrix mismatch")


def validate_first_rows(
    rows: Sequence[Mapping[str, str]], receipt: Mapping[str, str]
) -> None:
    expected_sequence = [
        (size, scenario, engine, repetition)
        for size, scenario in FIRST_CASES
        for engine in ENGINES
        for repetition in range(FIRST_REPETITIONS)
    ]
    expected = {
        (size, scenario, engine, repetition)
        for size, scenario in FIRST_CASES
        for engine in ENGINES
        for repetition in range(FIRST_REPETITIONS)
    }
    seen: set[tuple[str, str, str, int]] = set()
    semantic_by_cell: dict[tuple[str, str], str] = {}
    checksum_by_cell: dict[tuple[str, str], str] = {}
    for row, expected_item in zip(rows, expected_sequence, strict=True):
        if row["schema"] != FIRST_SCHEMA or row["stage"] != "ready-first-call":
            fail("first-call row schema/stage mismatch")
        validate_bound_fields(row, receipt)
        validate_engine(row)
        canonical_uint(row["pid"], 1, 4_294_967_295, "pid")
        repetition = canonical_uint(
            row["repetition"], 0, FIRST_REPETITIONS - 1, "first repetition"
        )
        size, scenario, engine = row["size"], row["scenario"], row["engine"]
        key = (size, scenario, engine, repetition)
        if key not in expected or key in seen:
            fail("first-call matrix contains an extra or duplicate row")
        if key != expected_item:
            fail("first-call rows are not in canonical invocation order")
        seen.add(key)
        if row["cell"] != f"span-{size}-{scenario}":
            fail("first-call cell mismatch")
        bytes_count = SIZES[size][0]
        if canonical_uint(row["haystack_bytes"], 1, 1 << 20, "haystack bytes") != bytes_count:
            fail("first-call haystack bytes mismatch")
        if canonical_uint(row["alignment_mod16"], 0, 15, "alignment") != 0:
            fail("first-call representative fixture must be aligned")
        if not HEX16.fullmatch(row["semantic_value"]):
            fail("invalid first-call semantic value")
        validate_time(row, 1)
        cell = (size, scenario)
        semantic = semantic_by_cell.setdefault(cell, row["semantic_value"])
        checksum = checksum_by_cell.setdefault(cell, row["checksum"])
        if semantic != row["semantic_value"] or checksum != row["checksum"]:
            fail("first-call semantic/checksum differs across engines")
    if seen != expected:
        fail("first-call matrix is incomplete")


def lifecycle_checksum(calls: int, semantic_value: int) -> int:
    mask = (1 << 64) - 1
    checksum = 0xBB67_AE85_84CA_A73B
    for call in range(calls):
        checksum = ((checksum << 11) | (checksum >> (64 - 11))) & mask
        folded = (
            semantic_value + call * 0x9E37_79B9_7F4A_7C15
        ) & mask
        checksum ^= folded
    return checksum


def geomean(values: Sequence[float], label: str) -> float:
    if not values or any(not math.isfinite(value) or value <= 0 for value in values):
        fail(f"{label} contains a non-positive or non-finite sample")
    value = math.exp(sum(math.log(sample) for sample in values) / len(values))
    if not math.isfinite(value) or value <= 0:
        fail(f"{label} geomean is not finite and positive")
    return value


def median(values: Sequence[int], label: str) -> float:
    if not values:
        fail(f"{label} has no samples")
    ordered = sorted(values)
    midpoint = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[midpoint])
    return (ordered[midpoint - 1] + ordered[midpoint]) / 2.0


def validate_lifecycle_rows(
    rows: Sequence[Mapping[str, str]],
    receipt: Mapping[str, str],
    *,
    require_sustained_break_even: bool = True,
) -> tuple[list[list[str]], list[list[str]]]:
    expected_sequence = [
        (size, scenario, calls, repetition, engine)
        for size, scenario in LIFECYCLE_CASES
        for calls in LIFECYCLE_CALL_GRIDS[size]
        for repetition in range(LIFECYCLE_REPETITIONS)
        for engine in LIFECYCLE_ENGINE_ORDERS[repetition % 2]
    ]
    expected_groups = {
        (size, scenario, calls, repetition)
        for size, scenario in LIFECYCLE_CASES
        for calls in LIFECYCLE_CALL_GRIDS[size]
        for repetition in range(LIFECYCLE_REPETITIONS)
    }
    grouped: dict[
        tuple[str, str, int, int],
        dict[str, tuple[Mapping[str, str], int]],
    ] = defaultdict(dict)
    semantic_by_case: dict[tuple[str, str], str] = {}
    checksum_by_cell: dict[tuple[str, str, int], str] = {}

    for row, expected_item in zip(rows, expected_sequence, strict=True):
        if row["schema"] != LIFECYCLE_SCHEMA:
            fail("lifecycle row schema mismatch")
        validate_bound_fields(row, receipt)
        pid = canonical_uint(row["pid"], 1, 4_294_967_295, "lifecycle pid")
        repetition = canonical_uint(
            row["repetition"],
            0,
            LIFECYCLE_REPETITIONS - 1,
            "lifecycle repetition",
        )
        size, scenario, engine = row["size"], row["scenario"], row["engine"]
        case = (size, scenario)
        if case not in LIFECYCLE_CASES:
            fail("lifecycle row case is outside the closed matrix")
        calls = canonical_uint(row["calls"], 0, 1024, "lifecycle calls")
        if calls not in LIFECYCLE_CALL_GRIDS[size]:
            fail("lifecycle call count is outside the closed size grid")
        if (size, scenario, calls, repetition, engine) != expected_item:
            fail("lifecycle rows are not in canonical invocation/engine order")
        if engine not in LIFECYCLE_ENGINES:
            fail("lifecycle row names an excluded engine")
        route, authority, backend, stage = LIFECYCLE_ENGINES[engine]
        if (
            row["route"],
            row["authority"],
            row["backend"],
            row["stage"],
        ) != (route, authority, backend, stage):
            fail(f"lifecycle engine {engine} route/authority/backend/stage mismatch")
        if row["cell"] != f"span-{size}-{scenario}-calls-{calls}":
            fail("lifecycle cell name mismatch")
        expected_order = "+".join(LIFECYCLE_ENGINE_ORDERS[repetition % 2])
        if row["order"] != expected_order:
            fail("lifecycle AB/BA order mismatch")
        byte_count = SIZES[size][0]
        if canonical_uint(
            row["haystack_bytes"], 1, 1 << 20, "lifecycle haystack bytes"
        ) != byte_count:
            fail("lifecycle haystack byte count mismatch")
        if calls * byte_count > LIFECYCLE_MAX_BYTES_PER_CELL:
            fail("lifecycle cell exceeds the 64 MiB call-volume ceiling")
        if canonical_uint(
            row["alignment_mod16"], 0, 15, "lifecycle alignment"
        ) != 0:
            fail("lifecycle representative fixture must be aligned")
        total_ns = canonical_uint(
            row["total_ns"],
            1,
            3_600_000_000_000,
            "lifecycle total_ns",
        )
        if not HEX16.fullmatch(row["semantic_value"]):
            fail("invalid lifecycle semantic value")
        if not HEX16.fullmatch(row["checksum"]):
            fail("invalid lifecycle checksum")
        semantic_value = int(row["semantic_value"][2:], 16)
        expected_checksum = f"0x{lifecycle_checksum(calls, semantic_value):016x}"
        if row["checksum"] != expected_checksum:
            fail("lifecycle checksum does not match calls and semantic value")

        key = (size, scenario, calls, repetition)
        if engine in grouped[key]:
            fail("duplicate lifecycle engine row")
        grouped[key][engine] = (row, total_ns)
        prior_semantic = semantic_by_case.setdefault(case, row["semantic_value"])
        if prior_semantic != row["semantic_value"]:
            fail("lifecycle semantic value drifted across call counts or repetitions")
        cell = (size, scenario, calls)
        prior_checksum = checksum_by_cell.setdefault(cell, row["checksum"])
        if prior_checksum != row["checksum"]:
            fail("lifecycle checksum drifted across engines or repetitions")
        if any(
            int(existing_row["pid"]) != pid
            for existing_row, _ in grouped[key].values()
        ):
            fail("lifecycle engine pair did not come from one process")

    if set(grouped) != expected_groups:
        fail("lifecycle matrix is incomplete or has extra groups")
    for engines in grouped.values():
        if set(engines) != set(LIFECYCLE_ENGINES):
            fail("lifecycle invocation does not contain exactly two engines")

    samples: dict[
        tuple[str, str, int], dict[str, list[int]]
    ] = defaultdict(lambda: defaultdict(list))
    ratios: dict[tuple[str, str, int], list[float]] = defaultdict(list)
    wins: dict[tuple[str, str, int], int] = defaultdict(int)
    for size, scenario in LIFECYCLE_CASES:
        for calls in LIFECYCLE_CALL_GRIDS[size]:
            cell = (size, scenario, calls)
            for repetition in range(LIFECYCLE_REPETITIONS):
                engines = grouped[(size, scenario, calls, repetition)]
                portable_ns = engines["portable"][1]
                jit_ns = engines["strict-wx-jit"][1]
                samples[cell]["portable"].append(portable_ns)
                samples[cell]["strict-wx-jit"].append(jit_ns)
                ratios[cell].append(jit_ns / portable_ns)
                if jit_ns < portable_ns:
                    wins[cell] += 1

    summary: list[list[str]] = [LIFECYCLE_SUMMARY_HEADER]
    strict_by_case: dict[tuple[str, str], list[bool]] = defaultdict(list)
    for size, scenario in LIFECYCLE_CASES:
        for calls in LIFECYCLE_CALL_GRIDS[size]:
            cell = (size, scenario, calls)
            if any(
                len(samples[cell][engine]) != LIFECYCLE_REPETITIONS
                for engine in LIFECYCLE_ENGINES
            ):
                fail("lifecycle sample cardinality mismatch")
            portable_geomean = geomean(
                samples[cell]["portable"], "lifecycle portable"
            )
            jit_geomean = geomean(
                samples[cell]["strict-wx-jit"], "lifecycle strict-WX JIT"
            )
            paired_ratio = geomean(
                ratios[cell], "lifecycle strict-WX JIT/portable ratio"
            )
            strict = (
                paired_ratio <= LIFECYCLE_RATIO_LIMIT
                and wins[cell] >= LIFECYCLE_WIN_MINIMUM
            )
            strict_by_case[(size, scenario)].append(strict)
            summary.append(
                [
                    f"span-{size}-{scenario}-calls-{calls}",
                    size,
                    scenario,
                    str(calls),
                    str(LIFECYCLE_REPETITIONS),
                    f"{portable_geomean:.9f}",
                    f"{jit_geomean:.9f}",
                    f"{paired_ratio:.9f}",
                    str(wins[cell]),
                    "PASS" if strict else "FAIL",
                ]
            )

    break_even: list[list[str]] = [LIFECYCLE_BREAK_EVEN_HEADER]
    missing_empirical: list[str] = []
    for size, scenario in LIFECYCLE_CASES:
        case = (size, scenario)
        grid = LIFECYCLE_CALL_GRIDS[size]
        strict_cells = strict_by_case[case]
        empirical_index = next(
            (
                index
                for index in range(len(grid))
                if all(strict_cells[index:])
            ),
            None,
        )
        if empirical_index is None:
            empirical_status = "not-observed-through-grid"
            empirical_calls = "not-applicable"
            missing_empirical.append(f"span-{size}-{scenario}")
        else:
            empirical_status = "observed-sustained"
            empirical_calls = str(grid[empirical_index])

        maximum_calls = grid[-1]
        portable_setup = median(
            samples[(size, scenario, 0)]["portable"],
            "lifecycle portable zero-call setup",
        )
        jit_setup = median(
            samples[(size, scenario, 0)]["strict-wx-jit"],
            "lifecycle strict-WX JIT zero-call setup",
        )
        portable_per_call = (
            median(
                samples[(size, scenario, maximum_calls)]["portable"],
                "lifecycle portable endpoint",
            )
            - portable_setup
        ) / maximum_calls
        jit_per_call = (
            median(
                samples[(size, scenario, maximum_calls)]["strict-wx-jit"],
                "lifecycle strict-WX JIT endpoint",
            )
            - jit_setup
        ) / maximum_calls
        if portable_per_call < 0 or jit_per_call < 0:
            modeled_status = "advisory-invalid-slope"
            modeled_calls = "not-applicable"
        elif jit_setup <= portable_setup:
            modeled_status = "advisory-finite"
            modeled_calls = "0"
        elif jit_per_call >= portable_per_call:
            modeled_status = "advisory-no-crossing"
            modeled_calls = "not-applicable"
        else:
            modeled_status = "advisory-finite"
            modeled_calls = str(
                math.ceil(
                    (jit_setup - portable_setup)
                    / (portable_per_call - jit_per_call)
                )
            )
        break_even.append(
            [
                f"span-{size}-{scenario}",
                size,
                scenario,
                str(LIFECYCLE_REPETITIONS),
                f"{LIFECYCLE_RATIO_LIMIT:.9f}",
                str(LIFECYCLE_WIN_MINIMUM),
                empirical_status,
                empirical_calls,
                modeled_status,
                modeled_calls,
                f"{portable_setup:.9f}",
                f"{jit_setup:.9f}",
                f"{portable_per_call:.9f}",
                f"{jit_per_call:.9f}",
            ]
        )
    if require_sustained_break_even and missing_empirical:
        fail(
            "lifecycle strict empirical sustained break-even is absent for "
            + "+".join(missing_empirical)
        )
    return summary, break_even


def csv_bytes(rows: Sequence[Sequence[str]]) -> bytes:
    output = []
    for row in rows:
        if any(
            not field or any(character in field for character in ',\r\n"')
            for field in row
        ):
            fail("derived summary contains a noncanonical field")
        output.append(",".join(row))
    return ("\n".join(output) + "\n").encode("ascii")


def verify_bundle(root: Path) -> None:
    try:
        info = root.lstat()
    except OSError as error:
        fail(f"cannot stat bundle {root}: {error}")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        fail("bundle root is not one real directory")
    expected_root_files = {
        "build-receipt.tsv",
        "cold.csv",
        "completion.tsv",
        "environment.tsv",
        "first-call.csv",
        "hot.csv",
        "lifecycle-break-even.csv",
        "lifecycle-summary.csv",
        "lifecycle.csv",
        "metadata.tsv",
        "sequence.tsv",
        "subject-bin",
        "subject.o",
        "summary.csv",
    }
    actual = {entry.name for entry in root.iterdir()}
    process_dirs = {
        "hot-processes",
        "cold-processes",
        "first-call-processes",
        "lifecycle-processes",
        "linked-image",
        "runtime-cwd",
    }
    if actual != expected_root_files | process_dirs:
        fail(f"bundle inventory mismatch: {sorted(actual)}")
    runtime_cwd = root / "runtime-cwd"
    if runtime_cwd.is_symlink() or not runtime_cwd.is_dir() or any(runtime_cwd.iterdir()):
        fail("runtime-cwd is not one empty real directory")
    receipt = parse_receipt(root / "build-receipt.tsv")
    if sha256_file(root / "subject.o", MAX_OBJECT_BYTES) != receipt["object_identity"]:
        fail("retained subject object digest differs from receipt")
    try:
        object_info = (root / "subject.o").lstat()
    except OSError as error:
        fail(f"cannot restat retained subject object: {error}")
    if stat.S_IMODE(object_info.st_mode) != 0o400:
        fail("retained subject object mode is not 0400")
    linked_receipt = verify_linked_subbundle(root, receipt)
    hot_rows = parse_csv(root / "hot.csv", HOT_HEADER, HOT_ROWS)
    cold_rows = parse_csv(root / "cold.csv", COLD_HEADER, COLD_ROWS)
    first_rows = parse_csv(root / "first-call.csv", FIRST_HEADER, FIRST_ROWS)
    lifecycle_rows = parse_csv(
        root / "lifecycle.csv", LIFECYCLE_HEADER, LIFECYCLE_ROWS
    )
    summary = validate_hot_rows(hot_rows, receipt)
    validate_cold_rows(cold_rows, receipt)
    validate_first_rows(first_rows, receipt)
    lifecycle_summary, lifecycle_break_even = validate_lifecycle_rows(
        lifecycle_rows, receipt
    )
    if regular_file(root / "summary.csv", MAX_TEXT_BYTES) != csv_bytes(summary):
        fail("summary.csv is not the exact raw-derived summary")
    if regular_file(
        root / "lifecycle-summary.csv", MAX_TEXT_BYTES
    ) != csv_bytes(lifecycle_summary):
        fail("lifecycle-summary.csv is not the exact raw-derived summary")
    if regular_file(
        root / "lifecycle-break-even.csv", MAX_TEXT_BYTES
    ) != csv_bytes(lifecycle_break_even):
        fail("lifecycle-break-even.csv is not the exact raw-derived result")
    verify_process_sequence(root)
    verify_metadata(root / "metadata.tsv", receipt)
    verify_environment(root, receipt, linked_receipt)
    verify_completion(root / "completion.tsv", receipt)


def verify_linked_subbundle(
    root: Path, receipt: Mapping[str, str]
) -> dict[str, str]:
    directory = root / "linked-image"
    if directory.is_symlink() or not directory.is_dir():
        fail("linked-image is not one real directory")
    expected_names = {
        "link-map.txt",
        "nm.txt",
        "otool.txt",
        "verification.tsv",
    }
    names = {entry.name for entry in directory.iterdir()}
    if names != expected_names:
        fail(f"linked-image inventory mismatch: {sorted(names)}")
    subject_binary = root / "subject-bin"
    regular_file(subject_binary, linked_verifier.MAX_EXECUTABLE_BYTES)
    try:
        binary_info = subject_binary.lstat()
    except OSError as error:
        fail(f"cannot restat retained subject binary: {error}")
    if stat.S_IMODE(binary_info.st_mode) != 0o500:
        fail("retained subject binary mode is not 0500")
    rows = linked_verifier.verify(
        root / "build-receipt.tsv",
        root / "subject.o",
        subject_binary,
        directory / "link-map.txt",
        directory / "nm.txt",
        directory / "otool.txt",
    )
    expected = linked_verifier.linked_receipt_bytes(rows)
    if regular_file(directory / "verification.tsv", MAX_TEXT_BYTES) != expected:
        fail("linked-image verification.tsv is not the exact byte-derived receipt")
    linked = dict(rows)
    expected_bindings = {
        "subject_revision": receipt["subject_revision"],
        "build_receipt_sha256": sha256_file(
            root / "build-receipt.tsv", MAX_TEXT_BYTES
        ),
        "compile_identity": receipt["compile_identity"],
        "object_identity": receipt["object_identity"],
        "payload_sha256": receipt["payload_sha256"],
        "metadata_sha256": receipt["metadata_sha256"],
        "provider": "exact-receipt-derived-final-bytes",
        "link_map_role": "corroborating",
        "overall": "PASS",
    }
    for key, expected_value in expected_bindings.items():
        if linked[key] != expected_value:
            fail(f"linked-image receipt {key} mismatch")
    return linked


def verify_process_sequence(root: Path) -> None:
    header = ["kind", "ordinal", "pid", "output_sha256", "relative_path"]
    text = strict_text(root / "sequence.tsv")
    rows = list(csv.reader(text.splitlines(), delimiter="\t", strict=True))
    if (
        not rows
        or rows[0] != header
        or len(rows) != 1 + 648 + 12 + 240 + LIFECYCLE_INVOCATIONS
    ):
        fail("sequence.tsv header/cardinality mismatch")
    counts = {
        "hot": 648,
        "cold": 12,
        "first-call": 240,
        "lifecycle": LIFECYCLE_INVOCATIONS,
    }
    expected_sequence = [
        (kind, ordinal)
        for kind, count in counts.items()
        for ordinal in range(1, count + 1)
    ]
    seen: dict[str, set[int]] = defaultdict(set)
    marked_rows: dict[str, list[str]] = defaultdict(list)
    for fields, expected_item in zip(rows[1:], expected_sequence, strict=True):
        if len(fields) != len(header):
            fail("sequence row width mismatch")
        row = dict(zip(header, fields, strict=True))
        kind = row["kind"]
        if kind not in counts:
            fail("unexpected sequence kind")
        ordinal = canonical_uint(row["ordinal"], 1, counts[kind], "sequence ordinal")
        if (kind, ordinal) != expected_item:
            fail("sequence rows are not in canonical kind/ordinal order")
        sequence_pid = canonical_uint(
            row["pid"], 1, 4_294_967_295, "sequence pid"
        )
        if not HEX64.fullmatch(row["output_sha256"]):
            fail("invalid process output digest")
        expected_relative = f"{kind}-processes/{ordinal:06d}.txt"
        if row["relative_path"] != expected_relative:
            fail("sequence process path mismatch")
        if ordinal in seen[kind]:
            fail("duplicate sequence ordinal")
        seen[kind].add(ordinal)
        process_path = root / expected_relative
        if sha256_file(process_path, 256 * 1024) != row["output_sha256"]:
            fail("process output digest mismatch")
        process_text = strict_text(process_path, 256 * 1024)
        prefix = {
            "hot": "FRE_SEARCH_V8_HOT_ROW\t",
            "cold": "FRE_SEARCH_V8_COLD_ROW\t",
            "first-call": "FRE_SEARCH_V8_FIRST_CALL_ROW\t",
            "lifecycle": "FRE_SEARCH_V8_LIFECYCLE_ROW\t",
        }[kind]
        expected_marked = {
            "hot": 3,
            "cold": 7,
            "first-call": 1,
            "lifecycle": 2,
        }[kind]
        process_lines = process_text.splitlines()
        if len(process_lines) != expected_marked or any(
            not line.startswith(prefix) for line in process_lines
        ):
            fail("process output contains an extra, missing, or unmarked line")
        marked = process_lines
        for line in marked:
            try:
                fields = next(csv.reader([line.removeprefix(prefix)], strict=True))
            except csv.Error as error:
                fail(f"process output row is not strict CSV: {error}")
            if len(fields) < 3 or fields[2] != str(sequence_pid):
                fail("sequence PID differs from its retained process rows")
        marked_rows[kind].extend(line.removeprefix(prefix) for line in marked)
    for kind, count in counts.items():
        if seen[kind] != set(range(1, count + 1)):
            fail(f"{kind} sequence ordinals are incomplete")
        directory = root / f"{kind}-processes"
        if directory.is_symlink() or not directory.is_dir():
            fail(f"{kind} process directory is invalid")
        names = {entry.name for entry in directory.iterdir()}
        expected_names = {f"{ordinal:06d}.txt" for ordinal in range(1, count + 1)}
        if names != expected_names:
            fail(f"{kind} process directory inventory mismatch")
    raw_names = {
        "hot": "hot.csv",
        "cold": "cold.csv",
        "first-call": "first-call.csv",
        "lifecycle": "lifecycle.csv",
    }
    for kind, raw_name in raw_names.items():
        raw_lines = strict_text(root / raw_name).splitlines()[1:]
        if marked_rows[kind] != raw_lines:
            fail(f"{raw_name} does not exactly concatenate retained process rows")


def verify_metadata(path: Path, receipt: Mapping[str, str]) -> None:
    expected_keys = [
        "schema",
        "subject_revision",
        "benchmark_source_sha256",
        "semantic_identity",
        "binding_identity",
        "compiler_receipt_identity",
        "source_identity",
        "artifact_identity",
        "compile_identity",
        "object_identity",
        "payload_sha256",
        "metadata_sha256",
        "literal_hex",
        "backend",
        "operation",
        "hot_sizes",
        "hot_named_scenarios",
        "hot_alignment_scenarios",
        "hot_cells",
        "hot_repetitions",
        "bytes_per_hot_sample",
        "cold_phases",
        "cold_repetitions",
        "cold_iterations",
        "first_call_repetitions",
        "lifecycle_repetitions",
        "lifecycle_64k_call_grid",
        "lifecycle_1m_call_grid",
        "lifecycle_aot_route",
        "aot_route",
        "aot_adoption",
        "production_activation",
        "object_path",
        "receipt_path",
        "link_map_path",
        "entry_symbol",
        "payload_symbol",
        "metadata_symbol",
    ]
    metadata = parse_tsv(path, expected_keys)
    expected = {
        "schema": "fre-search-v8-bakeoff-metadata-v3",
        "subject_revision": receipt["subject_revision"],
        "benchmark_source_sha256": receipt["benchmark_source_sha256"],
        "semantic_identity": receipt["semantic_identity"],
        "binding_identity": receipt["binding_identity"],
        "compiler_receipt_identity": receipt["compiler_receipt_identity"],
        "source_identity": receipt["source_identity"],
        "artifact_identity": receipt["artifact_identity"],
        "compile_identity": receipt["compile_identity"],
        "object_identity": receipt["object_identity"],
        "payload_sha256": receipt["payload_sha256"],
        "metadata_sha256": receipt["metadata_sha256"],
        "literal_hex": receipt["literal_hex"],
        "backend": "aarch64-search-v8",
        "operation": "span",
        "hot_sizes": "2",
        "hot_named_scenarios": "11",
        "hot_alignment_scenarios": "16",
        "hot_cells": "54",
        "hot_repetitions": "12",
        "bytes_per_hot_sample": "67108864",
        "cold_phases": "7",
        "cold_repetitions": "12",
        "cold_iterations": "20",
        "first_call_repetitions": "20",
        "lifecycle_repetitions": "24",
        "lifecycle_64k_call_grid": "0+1+2+4+8+16+32+64+128+256+512+1024",
        "lifecycle_1m_call_grid": "0+1+2+4+8+16+32+64",
        "lifecycle_aot_route": "excluded-until-safe-static-adopter",
        "aot_route": "raw-statically-linked-aot-with-benchmark-local-decode",
        "aot_adoption": "absent",
        "production_activation": "absent",
        "object_path": receipt["object_path"],
        "link_map_path": receipt["link_map_path"],
        "entry_symbol": receipt["entry_symbol"],
        "payload_symbol": receipt["payload_symbol"],
        "metadata_symbol": receipt["metadata_symbol"],
    }
    for key, value in expected.items():
        if metadata[key] != value:
            fail(f"metadata {key} mismatch")
    if not os.path.isabs(metadata["receipt_path"]):
        fail("metadata receipt path is not absolute")


def verify_environment(
    root: Path,
    receipt: Mapping[str, str],
    linked_receipt: Mapping[str, str],
) -> None:
    keys = [
        "schema",
        "subject_revision",
        "binary_relative_path",
        "binary_sha256",
        "build_receipt_sha256",
        "linked_verification_sha256",
        "timing_admission_kind",
        "lifecycle_process_state",
        "lifecycle_os_page_cache",
        "lifecycle_cache_flush",
        "lifecycle_outlier_removal",
    ]
    path = root / "environment.tsv"
    environment = parse_tsv(path, keys)
    if environment["schema"] != "fre-search-v8-bakeoff-environment-v3":
        fail("environment schema mismatch")
    if environment["subject_revision"] != receipt["subject_revision"]:
        fail("environment revision mismatch")
    if environment["binary_relative_path"] != "subject-bin":
        fail("environment does not name the retained subject binary")
    for field in [
        "binary_sha256",
        "build_receipt_sha256",
        "linked_verification_sha256",
    ]:
        if not HEX64.fullmatch(environment[field]):
            fail(f"environment {field} is invalid")
    retained_binary_sha256 = sha256_file(
        root / "subject-bin", linked_verifier.MAX_EXECUTABLE_BYTES
    )
    if (
        environment["binary_sha256"] != retained_binary_sha256
        or linked_receipt["executable_sha256"] != retained_binary_sha256
    ):
        fail("environment, retained binary, and linked executable digests differ")
    if (
        sha256_file(root / "build-receipt.tsv", MAX_TEXT_BYTES)
        != environment["build_receipt_sha256"]
    ):
        fail("environment build receipt digest mismatch")
    if (
        sha256_file(root / "linked-image" / "verification.tsv", MAX_TEXT_BYTES)
        != environment["linked_verification_sha256"]
    ):
        fail("environment linked verification digest mismatch")
    if environment["timing_admission_kind"] != "timing":
        fail("environment did not record timing admission")
    expected_lifecycle = {
        "lifecycle_process_state": (
            "fresh-process-per-case-call-count-repetition"
        ),
        "lifecycle_os_page_cache": "uncontrolled",
        "lifecycle_cache_flush": "absent",
        "lifecycle_outlier_removal": "absent",
    }
    for field, expected_value in expected_lifecycle.items():
        if environment[field] != expected_value:
            fail(f"environment {field} mismatch")


def verify_completion(path: Path, receipt: Mapping[str, str]) -> None:
    keys = [
        "schema",
        "subject_revision",
        "hot_invocations",
        "hot_rows",
        "cold_invocations",
        "cold_rows",
        "first_call_invocations",
        "first_call_rows",
        "lifecycle_invocations",
        "lifecycle_rows",
        "hot_repetitions",
        "cold_repetitions",
        "first_call_repetitions",
        "lifecycle_repetitions",
        "lifecycle_cases",
        "lifecycle_call_cells",
        "lifecycle_engines",
        "retained_binary_files",
        "linked_image_files",
        "linked_image_receipt_rows",
        "timing_admission_kind",
        "evidence_class",
    ]
    completion = parse_tsv(path, keys)
    expected = {
        "schema": COMPLETION_SCHEMA,
        "subject_revision": receipt["subject_revision"],
        "hot_invocations": "648",
        "hot_rows": str(HOT_ROWS),
        "cold_invocations": "12",
        "cold_rows": str(COLD_ROWS),
        "first_call_invocations": "240",
        "first_call_rows": str(FIRST_ROWS),
        "lifecycle_invocations": str(LIFECYCLE_INVOCATIONS),
        "lifecycle_rows": str(LIFECYCLE_ROWS),
        "hot_repetitions": "12",
        "cold_repetitions": "12",
        "first_call_repetitions": "20",
        "lifecycle_repetitions": str(LIFECYCLE_REPETITIONS),
        "lifecycle_cases": str(len(LIFECYCLE_CASES)),
        "lifecycle_call_cells": str(LIFECYCLE_CALL_CELLS),
        "lifecycle_engines": str(len(LIFECYCLE_ENGINES)),
        "retained_binary_files": "1",
        "linked_image_files": "4",
        "linked_image_receipt_rows": str(len(linked_verifier.LINKED_KEYS)),
        "timing_admission_kind": "timing",
        "evidence_class": "measured",
    }
    if completion != expected:
        fail("completion receipt mismatch")


def derive(receipt_path: Path, hot_path: Path) -> None:
    receipt = parse_receipt(receipt_path)
    rows = parse_csv(hot_path, HOT_HEADER, HOT_ROWS)
    sys.stdout.buffer.write(csv_bytes(validate_hot_rows(rows, receipt)))


def derive_lifecycle(
    receipt_path: Path, lifecycle_path: Path, output: str
) -> None:
    receipt = parse_receipt(receipt_path)
    rows = parse_csv(lifecycle_path, LIFECYCLE_HEADER, LIFECYCLE_ROWS)
    # Derivation deliberately preserves diagnostics from a structurally valid
    # losing run. Final bundle verification calls the same validator with its
    # strict default and still rejects any missing sustained break-even.
    summary, break_even = validate_lifecycle_rows(
        rows,
        receipt,
        require_sustained_break_even=False,
    )
    selected = summary if output == "summary" else break_even
    sys.stdout.buffer.write(csv_bytes(selected))


def qualify_lifecycle(receipt_path: Path, lifecycle_path: Path) -> None:
    receipt = parse_receipt(receipt_path)
    rows = parse_csv(lifecycle_path, LIFECYCLE_HEADER, LIFECYCLE_ROWS)
    validate_lifecycle_rows(rows, receipt)


def usage() -> None:
    print(
        "usage: verify_results.py derive BUILD_RECEIPT HOT_CSV | "
        "verify_results.py derive-lifecycle-summary BUILD_RECEIPT "
        "LIFECYCLE_CSV | "
        "verify_results.py derive-lifecycle-break-even BUILD_RECEIPT "
        "LIFECYCLE_CSV | "
        "verify_results.py qualify-lifecycle BUILD_RECEIPT LIFECYCLE_CSV | "
        "verify_results.py verify BUNDLE",
        file=sys.stderr,
    )


def main(arguments: Sequence[str]) -> int:
    try:
        if len(arguments) == 3 and arguments[0] == "derive":
            derive(Path(arguments[1]), Path(arguments[2]))
        elif len(arguments) == 3 and arguments[0] in {
            "derive-lifecycle-summary",
            "derive-lifecycle-break-even",
        }:
            output = (
                "summary"
                if arguments[0] == "derive-lifecycle-summary"
                else "break-even"
            )
            derive_lifecycle(Path(arguments[1]), Path(arguments[2]), output)
        elif len(arguments) == 3 and arguments[0] == "qualify-lifecycle":
            qualify_lifecycle(Path(arguments[1]), Path(arguments[2]))
            print("PASS Search V8 lifecycle qualification")
        elif len(arguments) == 2 and arguments[0] == "verify":
            verify_bundle(Path(arguments[1]))
            print("PASS Search V8 bakeoff bundle")
        else:
            usage()
            return 2
    except VerificationError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
