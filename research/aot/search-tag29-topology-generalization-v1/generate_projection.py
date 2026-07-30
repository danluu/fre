#!/usr/bin/env python3
"""Freeze a result-blind Search tag-29 topology projection.

The full projection is a Cartesian structural/correctness matrix.  It is
described as procedural fixtures so that checking all rows does not require
checking 100+ GiB of redundant haystack bytes into the repository.  A runner
must reconstruct each fixture from the authenticated recipe and verify its
scalar oracle before either portable or static code can execute.

The timing projection is a pre-result stratified subset of the full matrix.
No corpus, benchmark, Rebar input, or timing result is read by this program.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence


SCHEMA = "fre.aot.search-tag29-topology-projection.v1"
SUMMARY_SCHEMA = "fre.aot.search-tag29-topology-freeze-summary.v1"
SELECTOR_CONTRACT_RELATIVE = (
    "research/aot/search-phase-unique-selector-v1/selector-contract-v1.json"
)
SELECTOR_CONTRACT_SHA256 = (
    "38ca5ebc1b239b541afcf9eeb679bf8b156c8690e7422a96f69a9457a155daf0"
)
SELECTOR_PAYLOAD_SHA256 = (
    "b0241b15760f441e7f4eb410611ce1a83b1a17f4858da91ce7eacba4f5a75353"
)
PROJECTION_DOMAIN = b"FRE-SEARCH-TAG29-TOPOLOGY-PROJECTION\0\x01"
LITERAL_DOMAIN = b"FRE-SEARCH-TAG29-TOPOLOGY-LITERAL\0\x01"
ROW_DOMAIN = b"FRE-SEARCH-TAG29-TOPOLOGY-ROW\0\x01"

WIDTHS = tuple(range(4, 33))
ELIGIBLE_WIDTHS = tuple(range(6, 33))
PHASE_PLACEMENTS = tuple(range(5))
MUTATION_CLASSES = tuple(range(19))
ALIGNMENTS = tuple(range(16))
GEOMETRIES = tuple(
    (size_class, alignment)
    for size_class in ("short", "long")
    for alignment in ALIGNMENTS
)
TOPOLOGIES = (
    "high-entropy-distinct",
    "binary-aperiodic",
    "ternary-aperiodic",
    "rare-markers-common-fill",
    "common-markers-rare-fill",
    "terminal-repeated-high-entropy",
    "periodic-or-uniform-refusal",
)
ELIGIBLE_TOPOLOGIES = TOPOLOGIES[:-1]
SOURCE_KINDS = ("absent", "primary", "secondary", "terminal", "mode")
SHORT_WINDOW_BYTES = (
    4,
    5,
    6,
    7,
    15,
    16,
    17,
    31,
    32,
    33,
    63,
    64,
    65,
    127,
    128,
    129,
    255,
    256,
    257,
)
LONG_WINDOW_BYTES = (
    4_093,
    4_096,
    8_192,
    16_384,
    32_768,
    65_536,
    131_072,
    262_144,
    524_288,
    1_048_576,
    4_093,
    8_192,
    32_768,
    131_072,
    1_048_576,
    4_096,
    16_384,
    65_536,
    262_144,
)
EXPECTED_FULL_ROWS = 123_424
EXPECTED_TIMED_ROWS = 3_078
HEX64 = re.compile(r"[0-9a-f]{64}\Z")

# Frozen copy of memchr 2.8.3's packed-pair byte-frequency rank.  This is
# independent of the emitter and auditor and matches the selector authority.
BYTE_FREQUENCY_RANK = (
    55, 52, 51, 50, 49, 48, 47, 46, 45, 103, 242, 66, 67, 229, 44, 43,
    42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 56, 32, 31, 30, 29, 28,
    255, 148, 164, 149, 136, 160, 155, 173, 221, 222, 134, 122, 232,
    202, 215, 224, 208, 220, 204, 187, 183, 179, 177, 168, 178, 200,
    226, 195, 154, 184, 174, 126, 120, 191, 157, 194, 170, 189, 162,
    161, 150, 193, 142, 137, 171, 176, 185, 167, 186, 112, 175, 192,
    188, 156, 140, 143, 123, 133, 128, 147, 138, 146, 114, 223, 151,
    249, 216, 238, 236, 253, 227, 218, 230, 247, 135, 180, 241, 233,
    246, 244, 231, 139, 245, 243, 251, 235, 201, 196, 240, 214, 152,
    182, 205, 181, 127, 27, 212, 211, 210, 213, 228, 197, 169, 159,
    131, 172, 105, 80, 98, 96, 97, 81, 207, 145, 116, 115, 144, 130,
    153, 121, 107, 132, 109, 110, 124, 111, 82, 108, 118, 141, 113,
    129, 119, 125, 165, 117, 92, 106, 83, 72, 99, 93, 65, 79, 166,
    237, 163, 199, 190, 225, 209, 203, 198, 217, 219, 206, 234, 248,
    158, 239, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255,
)
assert len(BYTE_FREQUENCY_RANK) == 256


class Refusal(RuntimeError):
    """A supposedly frozen projection or selector property changed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def sha256(encoded: bytes) -> str:
    return hashlib.sha256(encoded).hexdigest()


def file_bytes(path: Path, maximum: int = 2 * 1024 * 1024) -> bytes:
    status = path.lstat()
    require(
        status.st_size > 0
        and status.st_size <= maximum
        and path.is_file()
        and not path.is_symlink(),
        f"not one bounded regular file: {path}",
    )
    return path.read_bytes()


def authenticate_selector(repo: Path) -> None:
    path = repo / SELECTOR_CONTRACT_RELATIVE
    encoded = file_bytes(path)
    require(sha256(encoded) == SELECTOR_CONTRACT_SHA256, "selector bytes changed")
    root = json.loads(encoded)
    require(
        root.get("schema") == "fre.aot.search-phase-unique-selector.v1"
        and root.get("payload_sha256") == SELECTOR_PAYLOAD_SHA256
        and sha256(canonical_bytes(root.get("payload")))
        == SELECTOR_PAYLOAD_SHA256,
        "selector payload changed",
    )


def candidate_byte_pair(literal: bytes) -> tuple[int, int]:
    require(len(literal) >= 2, "topology literal is too short")
    primary, secondary = 0, 1
    if BYTE_FREQUENCY_RANK[literal[secondary]] < BYTE_FREQUENCY_RANK[literal[primary]]:
        primary, secondary = secondary, primary
    for offset in range(2, min(len(literal), 255)):
        byte = literal[offset]
        if BYTE_FREQUENCY_RANK[byte] < BYTE_FREQUENCY_RANK[literal[primary]]:
            secondary, primary = primary, offset
        elif (
            byte != literal[primary]
            and BYTE_FREQUENCY_RANK[byte]
            < BYTE_FREQUENCY_RANK[literal[secondary]]
        ):
            secondary = offset
    return primary, secondary


def ranked_offsets(literal: bytes) -> tuple[int, ...]:
    primary, secondary = candidate_byte_pair(literal)
    head = 0
    terminal = len(literal) - 1
    reserve_head = head not in {primary, secondary}
    reserve_terminal = terminal != head and terminal not in {primary, secondary}
    ranked_limit = 3 - int(reserve_head) - int(reserve_terminal)
    excluded = {primary, secondary}
    if reserve_head:
        excluded.add(head)
    if reserve_terminal:
        excluded.add(terminal)
    candidates = sorted(
        (BYTE_FREQUENCY_RANK[byte], offset)
        for offset, byte in enumerate(literal)
        if offset not in excluded
    )[:3]
    selected = [offset for _, offset in candidates[:ranked_limit]]
    if reserve_head:
        selected.append(head)
    if reserve_terminal:
        selected.append(terminal)
    return (primary, secondary, *selected)


def selector_eligible(literal: bytes) -> tuple[bool, tuple[int, ...]]:
    offsets = ranked_offsets(literal)
    eligible = (
        6 <= len(literal) <= 32
        and len(offsets) == 5
        and len(set(offsets)) == 5
        and any(offset not in offsets for offset in range(len(literal)))
        and all(
            any(
                literal[offset] != literal[(offset + shift) % len(literal)]
                for offset in offsets
            )
            for shift in range(1, len(literal))
        )
    )
    return eligible, offsets


def counter_stream(seed: bytes) -> Iterator[int]:
    counter = 0
    while True:
        digest = hashlib.sha256(
            LITERAL_DOMAIN + len(seed).to_bytes(4, "little") + seed
            + counter.to_bytes(8, "little")
        ).digest()
        yield from digest
        counter += 1


def rotate(values: bytes, phase: int) -> bytes:
    if not values:
        return values
    offset = phase % len(values)
    return values[offset:] + values[:offset]


def has_exact_period(literal: bytes) -> bool:
    for period in range(1, len(literal)):
        if len(literal) % period == 0 and literal == literal[:period] * (
            len(literal) // period
        ):
            return True
    return False


def topology_candidate(
    width: int, topology: str, phase: int, nonce: int
) -> bytes:
    seed = f"{SCHEMA}:{width}:{topology}:{phase}:{nonce}".encode()
    stream = counter_stream(seed)
    if topology == "high-entropy-distinct":
        values: list[int] = []
        for value in stream:
            if value not in values:
                values.append(value)
            if len(values) == width:
                break
        return rotate(bytes(values), phase)
    if topology == "binary-aperiodic":
        alphabet = (0x1d, 0x61)
        return rotate(bytes(alphabet[next(stream) & 1] for _ in range(width)), phase)
    if topology == "ternary-aperiodic":
        alphabet = (0x1c, 0x5a, 0xe3)
        return rotate(bytes(alphabet[next(stream) % 3] for _ in range(width)), phase)
    if topology == "rare-markers-common-fill":
        literal = bytearray([0x20] * width)
        positions = list(range(width))
        positions.sort(key=lambda _: next(stream))
        markers = (0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00)
        for index, position in enumerate(positions[: min(width - 1, 6)]):
            literal[position] = markers[index]
        return rotate(bytes(literal), phase)
    if topology == "common-markers-rare-fill":
        literal = bytearray([0x1b] * width)
        positions = list(range(width))
        positions.sort(key=lambda _: next(stream))
        markers = (0x20, 0x65, 0x74, 0x61, 0x6f, 0xff)
        for index, position in enumerate(positions[: min(width - 1, 6)]):
            literal[position] = markers[index]
        return rotate(bytes(literal), phase)
    if topology == "terminal-repeated-high-entropy":
        values = []
        for value in stream:
            if value not in values:
                values.append(value)
            if len(values) == width:
                break
        rotated = bytearray(rotate(bytes(values), phase))
        rotated[-1] = rotated[(phase + 1) % (width - 1)]
        return bytes(rotated)
    if topology == "periodic-or-uniform-refusal":
        divisors = [
            period
            for period in (2, 3, 4, 5)
            if width % period == 0 and period < width
        ]
        if not divisors:
            return bytes([0x61] * width)
        period = divisors[nonce % len(divisors)]
        unit = bytes((0x61 + index * 17) & 0xff for index in range(period))
        return rotate(unit * (width // period), phase)
    raise Refusal(f"unknown topology: {topology}")


def build_literal(width: int, topology: str, phase: int) -> tuple[bytes, tuple[int, ...]]:
    expected_eligible = width in ELIGIBLE_WIDTHS and topology in ELIGIBLE_TOPOLOGIES
    for nonce in range(65_536):
        literal = topology_candidate(width, topology, phase, nonce)
        eligible, offsets = selector_eligible(literal)
        if topology == "periodic-or-uniform-refusal":
            if not eligible and has_exact_period(literal):
                return literal, offsets
        elif eligible == expected_eligible:
            if topology == "high-entropy-distinct" and len(set(literal)) != width:
                continue
            if topology == "binary-aperiodic" and len(set(literal)) != 2:
                continue
            if topology == "ternary-aperiodic" and len(set(literal)) != 3:
                continue
            if (
                topology == "terminal-repeated-high-entropy"
                and literal.count(literal[-1]) < 2
            ):
                continue
            return literal, offsets
    raise Refusal(
        f"cannot construct topology width={width} topology={topology} phase={phase}"
    )


def absent_byte(literal: bytes) -> int:
    return next(value for value in range(256) if value not in literal)


def validate_near_miss_tile(
    literal: bytes, near_miss: bytes, sentinel: int
) -> None:
    require(sentinel not in literal, "fixture sentinel occurs in literal")
    require(
        len(near_miss) == len(literal)
        and near_miss != literal
        and sum(
            left != right
            for left, right in zip(near_miss, literal, strict=True)
        )
        == 1,
        "fixture near miss is not exactly one byte",
    )
    tile = near_miss + bytes([sentinel])
    # Any width-byte substring in the infinite periodic tile begins in the
    # first tile and is fully present in two concatenated tiles.
    doubled = tile + tile
    require(
        all(
            doubled[start : start + len(literal)] != literal
            for start in range(len(tile))
        ),
        "near-miss tile creates an accidental literal",
    )


def mutation(
    literal: bytes,
    offsets: Sequence[int],
    mutation_class: int,
    require_unselected: bool,
) -> tuple[int, int, str, bytes]:
    requested = SOURCE_KINDS[mutation_class % len(SOURCE_KINDS)]
    counts = Counter(literal)
    mode = min(counts, key=lambda byte: (-counts[byte], byte))
    source_by_kind = {
        "absent": absent_byte(literal),
        "primary": literal[offsets[0]],
        "secondary": literal[offsets[1]],
        "terminal": literal[-1],
        "mode": mode,
    }
    source = source_by_kind[requested]
    target_domain = (
        [offset for offset in range(len(literal)) if offset not in offsets]
        if require_unselected
        else list(range(len(literal)))
    )
    require(bool(target_domain), "mutation target domain is empty")
    target_index = min(
        len(target_domain) - 1,
        (mutation_class * len(target_domain)) // len(MUTATION_CLASSES),
    )
    target = target_domain[target_index]
    for delta in range(len(target_domain)):
        candidate = target_domain[(target_index + delta) % len(target_domain)]
        if literal[candidate] != source:
            target = candidate
            break
    else:
        source = absent_byte(literal)
        requested = f"{requested}-absent-fallback"
    near_miss = bytearray(literal)
    near_miss[target] = source
    require(
        near_miss != literal
        and sum(left != right for left, right in zip(near_miss, literal, strict=True))
        == 1,
        "near-miss construction changed",
    )
    return target, source, requested, bytes(near_miss)


def projection_row(
    width: int,
    topology_index: int,
    mutation_class: int,
    geometry_index: int,
) -> dict[str, Any]:
    topology = TOPOLOGIES[topology_index]
    size_class, alignment = GEOMETRIES[geometry_index]
    phase = geometry_index % len(PHASE_PLACEMENTS)
    literal, offsets = build_literal(width, topology, phase)
    eligible, checked_offsets = selector_eligible(literal)
    require(offsets == checked_offsets, "selector reconstruction changed")
    require_unselected = eligible and size_class == "long"
    mutation_offset, source, source_kind, near_miss = mutation(
        literal, offsets, mutation_class, require_unselected
    )
    source_count = literal.count(source)
    source_relations = []
    if source_count == 0:
        source_relations.append("absent-from-literal")
    elif source_count == 1:
        source_relations.append("singleton-in-literal")
    else:
        source_relations.append("repeated-in-literal")
    for label, offset in zip(
        (
            "equals-primary",
            "equals-secondary",
            "equals-verification",
            "equals-quaternary",
            "equals-quinary",
        ),
        offsets,
        strict=False,
    ):
        if source == literal[offset]:
            source_relations.append(label)
    if source == literal[-1]:
        source_relations.append("equals-terminal")
    windows = SHORT_WINDOW_BYTES if size_class == "short" else LONG_WINDOW_BYTES
    window_bytes = max(width, windows[mutation_class])
    candidate_starts = window_bytes - width + 1
    expected_route = (
        "tag29-static-tail"
        if eligible and window_bytes >= 4_093
        else "portable-only"
    )
    if expected_route == "tag29-static-tail":
        require(
            mutation_offset not in offsets
            and all(near_miss[offset] == literal[offset] for offset in offsets),
            "learned-recovery row does not survive the five-column screen",
        )
    outcome = "absent" if mutation_class % 3 == 0 else "tail-hit"
    match_start = (
        None
        if outcome == "absent"
        else alignment + window_bytes - width
    )
    sentinel = absent_byte(literal)
    validate_near_miss_tile(literal, near_miss, sentinel)
    literal_sha256 = sha256(literal)
    row_key = {
        "width": width,
        "topology": topology,
        "mutation_class": mutation_class,
        "geometry_index": geometry_index,
    }
    row_sha256 = sha256(ROW_DOMAIN + canonical_bytes(row_key))
    return {
        "schema": SCHEMA,
        "row_sha256": row_sha256,
        "literal_sha256": literal_sha256,
        "literal_hex": literal.hex(),
        "literal_bytes": width,
        "topology": topology,
        "selector_phase_placement": phase,
        "selected_offsets": list(offsets),
        "selector_eligible": eligible,
        "mutation_class": mutation_class,
        "mutation_offset": mutation_offset,
        "mutation_column": (
            "unselected-learned"
            if require_unselected
            else "general-correctness"
        ),
        "learned_source_kind": source_kind,
        "learned_source_byte": source,
        "learned_source_relations": sorted(source_relations),
        "near_miss_hex": near_miss.hex(),
        "alignment": alignment,
        "size_class": size_class,
        "window_bytes": window_bytes,
        "candidate_starts": candidate_starts,
        "outcome": outcome,
        "expected_match_start": match_start,
        "expected_match_end": (
            None if match_start is None else match_start + width
        ),
        "expected_route": expected_route,
        "expected_compiler_disposition": (
            "tag29-object" if eligible else "structural-refusal"
        ),
        "expected_static_invoked": expected_route == "tag29-static-tail",
        "right_guarded": (geometry_index + mutation_class) % 2 == 0,
        "fixture_recipe": {
            "construction_version": "near-miss-sentinel-tile-tail-v1",
            "background_byte": sentinel,
            "near_miss_tile_hex": near_miss.hex() + f"{sentinel:02x}",
            "window_start": alignment,
            "window_end": alignment + window_bytes,
            "true_literal_guard_bytes": width - 1,
            "steps": [
                "fill the checked window with the near-miss tile, truncating at window end",
                "for tail-hit, overwrite the width-1 bytes before the final candidate with the sentinel",
                "for tail-hit, install the exact literal at the final candidate start",
                "keep every byte outside the checked window equal to the sentinel",
            ],
            "scalar_oracle_required": True,
        },
    }


def full_rows() -> Iterator[dict[str, Any]]:
    for width in WIDTHS:
        for topology_index in range(len(TOPOLOGIES)):
            for mutation_class in MUTATION_CLASSES:
                for geometry_index in range(len(GEOMETRIES)):
                    yield projection_row(
                        width, topology_index, mutation_class, geometry_index
                    )


def is_timed_row(row: Mapping[str, Any]) -> bool:
    if (
        row["literal_bytes"] not in ELIGIBLE_WIDTHS
        or row["topology"] not in ELIGIBLE_TOPOLOGIES
        or row["size_class"] != "long"
    ):
        return False
    topology_index = ELIGIBLE_TOPOLOGIES.index(row["topology"])
    expected_alignment = (
        row["literal_bytes"] * 11
        + topology_index * 5
        + row["mutation_class"] * 7
    ) % len(ALIGNMENTS)
    return row["alignment"] == expected_alignment


class ProjectionDigest:
    def __init__(self, output: Path | None) -> None:
        self._digest = hashlib.sha256(PROJECTION_DOMAIN)
        self._count = 0
        self._stream = None
        if output is not None:
            output.parent.mkdir(parents=True, exist_ok=True)
            self._stream = output.open("xb")

    def add(self, row: Mapping[str, Any]) -> None:
        encoded = canonical_bytes(row) + b"\n"
        self._digest.update(len(encoded).to_bytes(8, "little"))
        self._digest.update(encoded)
        if self._stream is not None:
            self._stream.write(encoded)
        self._count += 1

    def finish(self) -> tuple[int, str]:
        if self._stream is not None:
            self._stream.flush()
            os.fsync(self._stream.fileno())
            self._stream.close()
        return self._count, self._digest.hexdigest()


def generate(
    repo: Path,
    full_output: Path | None = None,
    timed_output: Path | None = None,
) -> dict[str, Any]:
    authenticate_selector(repo)
    full = ProjectionDigest(full_output)
    timed = ProjectionDigest(timed_output)
    literal_digest = hashlib.sha256(LITERAL_DOMAIN)
    literal_keys: set[tuple[int, str, int, str]] = set()
    full_routes: Counter[str] = Counter()
    timed_widths: Counter[int] = Counter()
    timed_topologies: Counter[str] = Counter()
    timed_sources: Counter[str] = Counter()
    timed_source_relations: Counter[str] = Counter()
    timed_phases: Counter[int] = Counter()
    timed_alignments: Counter[int] = Counter()
    timed_windows: Counter[int] = Counter()
    for row in full_rows():
        full.add(row)
        full_routes[row["expected_route"]] += 1
        literal_key = (
            row["literal_bytes"],
            row["topology"],
            row["selector_phase_placement"],
            row["literal_sha256"],
        )
        if literal_key not in literal_keys:
            literal_keys.add(literal_key)
            encoded = canonical_bytes(literal_key)
            literal_digest.update(len(encoded).to_bytes(8, "little"))
            literal_digest.update(encoded)
        if is_timed_row(row):
            require(
                row["selector_eligible"]
                and row["expected_route"] == "tag29-static-tail",
                "timed projection admitted a non-native row",
            )
            timed.add(row)
            timed_widths[row["literal_bytes"]] += 1
            timed_topologies[row["topology"]] += 1
            timed_sources[row["learned_source_kind"]] += 1
            for relation in row["learned_source_relations"]:
                timed_source_relations[relation] += 1
            timed_phases[row["selector_phase_placement"]] += 1
            timed_alignments[row["alignment"]] += 1
            timed_windows[row["window_bytes"]] += 1
    full_count, full_sha256 = full.finish()
    timed_count, timed_sha256 = timed.finish()
    require(full_count == EXPECTED_FULL_ROWS, "full projection count changed")
    require(timed_count == EXPECTED_TIMED_ROWS, "timed projection count changed")
    require(
        set(timed_widths) == set(ELIGIBLE_WIDTHS)
        and set(timed_topologies) == set(ELIGIBLE_TOPOLOGIES)
        and set(timed_phases) == set(PHASE_PLACEMENTS)
        and set(timed_alignments) == set(ALIGNMENTS)
        and set(timed_windows) == set(LONG_WINDOW_BYTES),
        "timed stratification coverage changed",
    )
    require(
        all(count == len(ELIGIBLE_TOPOLOGIES) * len(MUTATION_CLASSES)
            for count in timed_widths.values())
        and all(count == len(ELIGIBLE_WIDTHS) * len(MUTATION_CLASSES)
                for count in timed_topologies.values()),
        "timed width/topology balance changed",
    )
    return {
        "schema": SUMMARY_SCHEMA,
        "selector_contract_sha256": SELECTOR_CONTRACT_SHA256,
        "selector_payload_sha256": SELECTOR_PAYLOAD_SHA256,
        "inputs": {
            "corpus_files": [],
            "benchmark_results": [],
            "rebar_files": [],
            "network": False,
        },
        "dimensions": {
            "widths": list(WIDTHS),
            "eligible_widths": list(ELIGIBLE_WIDTHS),
            "topologies": list(TOPOLOGIES),
            "eligible_topologies": list(ELIGIBLE_TOPOLOGIES),
            "mutation_classes": list(MUTATION_CLASSES),
            "phase_placements": list(PHASE_PLACEMENTS),
            "alignments": list(ALIGNMENTS),
            "geometries": [
                {"size_class": size_class, "alignment": alignment}
                for size_class, alignment in GEOMETRIES
            ],
            "short_window_bytes": list(SHORT_WINDOW_BYTES),
            "long_window_bytes": list(LONG_WINDOW_BYTES),
        },
        "full_projection": {
            "rows": full_count,
            "sha256": full_sha256,
            "literal_inventory_rows": len(literal_keys),
            "literal_inventory_sha256": literal_digest.hexdigest(),
            "expected_routes": dict(sorted(full_routes.items())),
            "use": "exhaustive-correctness-and-route-verification",
        },
        "timed_projection": {
            "rows": timed_count,
            "sha256": timed_sha256,
            "selection": (
                "one frozen long geometry for every eligible "
                "width/topology/mutation-class cell"
            ),
            "width_counts": dict(sorted(timed_widths.items())),
            "topology_counts": dict(sorted(timed_topologies.items())),
            "learned_source_kind_counts": dict(sorted(timed_sources.items())),
            "learned_source_relation_counts": dict(
                sorted(timed_source_relations.items())
            ),
            "phase_counts": dict(sorted(timed_phases.items())),
            "alignment_counts": dict(sorted(timed_alignments.items())),
            "window_counts": dict(sorted(timed_windows.items())),
        },
        "gates": {
            "correctness": (
                "every full-projection row must match the scalar span, route, "
                "guard-page, and compiler admission/refusal oracle on both hosts"
            ),
            "timing_cell_candidate_over_portable_exclusive_maximum": 0.80,
            "timing_repetitions": 6,
            "timing_minimum_elapsed_ns_each_variant": 400_000_000,
            "timing_pairing": (
                "same fixture and logical CPU with alternating engine order"
            ),
            "every_platform": True,
            "every_width_topology_cell": True,
            "every_topology": True,
            "every_width": True,
            "every_learned_source_kind": True,
            "every_learned_source_relation": True,
            "result_derived_exclusions": False,
        },
        "rebar_disposition": {
            "accepted_as_input": False,
            "gate_effect": "none",
            "permitted_use": "post-freeze-corroboration-only",
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
        print(f"search-tag29-topology-projection: {error}", file=os.sys.stderr)
        raise SystemExit(1)
