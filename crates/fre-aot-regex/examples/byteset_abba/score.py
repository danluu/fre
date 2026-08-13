#!/usr/bin/env python3
"""Strict sealed scorer for the exact-ByteSet parent/candidate ABBA matrix."""

from __future__ import annotations

import argparse
import hashlib
import math
import os
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


PHASES = {
    "parent_upstream_native": "01-parent-upstream-native.tsv",
    "candidate_native_upstream": "02-candidate-native-upstream.tsv",
    "candidate_upstream_native": "03-candidate-upstream-native.tsv",
    "parent_native_upstream": "04-parent-native-upstream.tsv",
}
SEALED_FILES = ("metadata-candidate.tsv", *PHASES.values())
FAMILIES = {"atomic_byte_set", "atomic_single_literal"}
CARDINALITIES = {2, 3, 4, 8, 16, 32, 64, 128}
CONTROL_WIDTHS = {2, 3, 4, 7, 8, 16, 31, 63}
WINDOWS = {64, 4096, 65536}
POSITIONS = {"none", "start", "middle", "end"}
DENSITIES = {"zero", "1_per_32", "near_miss_1_per_32", "dense"}
EXPECTED_ROWS = 32 * len(WINDOWS) * len(POSITIONS) * len(DENSITIES)


class ValidationError(Exception):
    """An input is incomplete, unsealed, inconsistent, or malformed."""


def geometric_mean(values: Iterable[float]) -> float:
    samples = list(values)
    if not samples or any(not math.isfinite(value) or value <= 0.0 for value in samples):
        raise ValidationError("geometric mean requires finite positive values")
    return math.exp(math.fsum(math.log(value) for value in samples) / len(samples))


def parse_key_values(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if separator != "=" or not key or key in values:
            raise ValidationError(f"{path}:{line_number}: malformed key/value")
        values[key] = value
    return values


def verify_hash_manifest(manifest: Path, root: Path) -> None:
    seen: set[str] = set()
    for line_number, line in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        if not line:
            continue
        digest, separator, relative = line.partition("  ")
        if separator != "  " or len(digest) != 64 or relative in seen:
            raise ValidationError(f"{manifest}:{line_number}: malformed hash row")
        seen.add(relative)
        path = (root / relative).resolve()
        try:
            path.relative_to(root.resolve())
        except ValueError as error:
            raise ValidationError(f"{manifest}:{line_number}: path escaped root") from error
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValidationError(f"{manifest}:{line_number}: digest mismatch for {relative}")
    if not seen:
        raise ValidationError(f"{manifest}: empty hash manifest")


def verify_seal(directory: Path) -> None:
    complete = directory / "COLLECTION_COMPLETE"
    if complete.read_text(encoding="utf-8") != (
        "all_metadata_and_abba_phases_sealed_before_timing_parse=true\n"
    ):
        raise ValidationError("collection-complete marker is absent or malformed")
    manifest = directory / "SEALED_PHASES.sha256"
    observed: dict[str, str] = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        digest, separator, relative = line.partition("  ")
        if separator != "  " or relative in observed:
            raise ValidationError("sealed-phase manifest is malformed")
        observed[relative] = digest
    if set(observed) != set(SEALED_FILES):
        raise ValidationError("sealed-phase manifest is incomplete or has extra inputs")
    for relative, digest in observed.items():
        path = directory / relative
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValidationError(f"sealed phase changed after collection: {relative}")


@dataclass(frozen=True)
class ParsedOutput:
    path: Path
    environment: dict[str, str]
    comparisons: dict[str, dict[str, str]]
    receipts: dict[str, dict[str, str]]
    metadata_complete: bool


def parse_output(path: Path) -> ParsedOutput:
    environment: dict[str, str] = {}
    comparison_header: list[str] | None = None
    receipt_header: list[str] | None = None
    comparisons: dict[str, dict[str, str]] = {}
    receipts: dict[str, dict[str, str]] = {}
    metadata_complete = False
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw_line:
            continue
        fields = raw_line.split("\t")
        kind = fields[0]
        if kind == "environment":
            if len(fields) != 3 or fields[1] in environment:
                raise ValidationError(f"{path}:{line_number}: malformed environment row")
            environment[fields[1]] = fields[2]
        elif kind == "comparison" and len(fields) > 1 and fields[1] == "case":
            if comparison_header is not None:
                raise ValidationError(f"{path}:{line_number}: duplicate comparison header")
            comparison_header = fields
        elif kind == "comparison":
            if comparison_header is None or len(fields) != len(comparison_header):
                raise ValidationError(f"{path}:{line_number}: malformed comparison row")
            row = dict(zip(comparison_header, fields))
            case = row.get("case", "")
            if not case or case in comparisons:
                raise ValidationError(f"{path}:{line_number}: duplicate/missing case")
            comparisons[case] = row
        elif kind == "#exact_byte_set_receipt":
            if receipt_header is not None:
                raise ValidationError(f"{path}:{line_number}: duplicate receipt header")
            receipt_header = [field.removeprefix("#") for field in fields]
        elif kind == "exact_byte_set_receipt":
            if receipt_header is None or len(fields) != len(receipt_header):
                raise ValidationError(f"{path}:{line_number}: malformed receipt row")
            row = dict(zip(receipt_header, fields))
            pattern = row.get("pattern", "")
            if not pattern or pattern in receipts:
                raise ValidationError(f"{path}:{line_number}: duplicate/missing receipt source")
            receipts[pattern] = row
        elif kind == "metadata_complete":
            if len(fields) != 10 or fields[-1] != "ok" or metadata_complete:
                raise ValidationError(f"{path}:{line_number}: malformed metadata seal")
            metadata_complete = True
    return ParsedOutput(path, environment, comparisons, receipts, metadata_complete)


def integer(value: str, context: str) -> int:
    try:
        return int(value)
    except ValueError as error:
        raise ValidationError(f"{context}: expected integer, got {value!r}") from error


def positive_float(value: str, context: str) -> float:
    try:
        parsed = float(value)
    except ValueError as error:
        raise ValidationError(f"{context}: expected float, got {value!r}") from error
    if not math.isfinite(parsed) or parsed <= 0.0:
        raise ValidationError(f"{context}: timing value is not finite and positive")
    return parsed


def validate_environment(
    parsed: ParsedOutput,
    frozen: dict[str, str],
    order: str,
    metadata_only: bool,
) -> None:
    expected = {
        "benchmark_mode": "atomic_choice_generated_out_of_sample",
        "generator": "exact_atomic_choice_v1",
        "target": frozen["QUALIFICATION_TARGET"],
        "requested_features": frozen["QUALIFICATION_FEATURES"],
        "feature_bits": frozen["QUALIFICATION_FEATURE_BITS"],
        "host_feature_validation": "passed",
        "regex_version": "1.13.1",
        "regex_features": "default,perf-dfa-full (logging disabled)",
        "measurement_order": order,
        "trials": "5",
        "warmup_rounds": "8",
        "bytes_per_trial": "1048576",
        "min_searches": "32",
        "min_trial_ns": "5000000",
        "compiled_patterns": "32",
        "scenarios": str(EXPECTED_ROWS),
        "output_matrix": "assigned_v1",
        "force_resource_fallback": "false",
        "force_retained_resource_fallback": "false",
        "force_slow_partial_resource_fallback": "false",
        "metadata_only": str(metadata_only).lower(),
    }
    for key, value in expected.items():
        if parsed.environment.get(key) != value:
            raise ValidationError(
                f"{parsed.path}: expected environment {key}={value!r}, "
                f"got {parsed.environment.get(key)!r}"
            )


def validate_receipts(
    parsed: ParsedOutput,
    candidate: bool,
) -> dict[str, tuple[str, int, str]]:
    if len(parsed.receipts) != 32:
        raise ValidationError(f"{parsed.path}: expected 32 exact-receipt rows")
    inventory: dict[str, tuple[str, int, str]] = {}
    seen_sizes: dict[str, set[int]] = defaultdict(set)
    seen_generations: set[int] = set()
    for pattern, row in parsed.receipts.items():
        context = f"{parsed.path}:{pattern}"
        if row.get("status") != "ok" or row.get("output") != "exists":
            raise ValidationError(f"{context}: receipt status/output is invalid")
        family = row.get("family", "")
        role = row.get("qualification_role", "")
        if family not in FAMILIES:
            raise ValidationError(f"{context}: unknown family")
        expected_role = "eligible" if family == "atomic_byte_set" else "control"
        if role != expected_role:
            raise ValidationError(f"{context}: family/qualification role disagree")
        size = integer(row.get("semantic_size", ""), context)
        generation = integer(row.get("generation_id", ""), context)
        if generation in seen_generations:
            raise ValidationError(f"{context}: duplicate generation identity")
        seen_generations.add(generation)
        seen_sizes[family].add(size)
        inventory[pattern] = (family, size, row.get("seed", ""))
        available = row.get("observation_available") == "true"
        present = row.get("present") == "true"
        if candidate:
            if not available or present != (family == "atomic_byte_set"):
                raise ValidationError(f"{context}: candidate receipt eligibility is invalid")
            if family == "atomic_byte_set":
                required = {
                    "candidate_bytes": str(size),
                    "exact_pass_count": "1",
                    "runtime_helper_required": "false",
                    "runtime_symbol": "none",
                    "runtime_program": "false",
                    "prepared_entry": "false",
                    "undefined_symbols": "0",
                    "entry_defined": "true",
                }
                for key, value in required.items():
                    if row.get(key) != value:
                        raise ValidationError(
                            f"{context}: exact receipt requires {key}={value!r}"
                        )
                scanner = row.get("scanner", "")
                if scanner != row.get("receipt_start_accelerator"):
                    raise ValidationError(f"{context}: scanner receipt mismatch")
                vectorized = row.get("vectorized") == "true"
                if integer(row.get("scan_pass_count", ""), context) != int(vectorized):
                    raise ValidationError(f"{context}: scan pass/vector receipt mismatch")
                if row.get("passes", "").split(",").count(
                    "ExactFiniteExistsByteSetLowering"
                ) != 1:
                    raise ValidationError(f"{context}: exact lowering pass is absent")
                if row.get("report_native_data_bytes") != row.get("receipt_data_bytes"):
                    raise ValidationError(f"{context}: native-data receipt mismatch")
            elif row.get("exact_pass_count") != "0":
                raise ValidationError(f"{context}: control claimed exact ByteSet lowering")
        elif available or present or row.get("exact_pass_count") != "0":
            raise ValidationError(f"{context}: parent unexpectedly claimed candidate provenance")
        for digest_name in ("object_sha256", "program_sha256", "automaton_sha256"):
            digest = row.get(digest_name, "")
            if len(digest) != 64:
                raise ValidationError(f"{context}: malformed {digest_name}")
            try:
                int(digest, 16)
            except ValueError as error:
                raise ValidationError(f"{context}: malformed {digest_name}") from error
    if seen_sizes["atomic_byte_set"] != CARDINALITIES:
        raise ValidationError(f"{parsed.path}: ByteSet cardinality census is incomplete")
    if seen_sizes["atomic_single_literal"] != CONTROL_WIDTHS:
        raise ValidationError(f"{parsed.path}: control width census is incomplete")
    family_counts = defaultdict(int)
    for family, _, _ in inventory.values():
        family_counts[family] += 1
    if family_counts != {"atomic_byte_set": 16, "atomic_single_literal": 16}:
        raise ValidationError(f"{parsed.path}: source-family census is incomplete")
    return inventory


def rust_speed(row: dict[str, str], context: str) -> float:
    rust = positive_float(row.get("upstream_median_ns_per_search", ""), context)
    native = positive_float(row.get("native_median_ns_per_search", ""), context)
    printed = positive_float(row.get("speedup_at_median", ""), context)
    ratio = rust / native
    if not math.isclose(ratio, printed, rel_tol=2.0e-6, abs_tol=2.0e-6):
        raise ValidationError(f"{context}: printed Rust/AOT ratio is inconsistent")
    return ratio


def validate_comparisons(
    parsed: ParsedOutput,
    inventory: dict[str, tuple[str, int, str]],
) -> None:
    if len(parsed.comparisons) != EXPECTED_ROWS:
        raise ValidationError(
            f"{parsed.path}: got {len(parsed.comparisons)} rows; expected {EXPECTED_ROWS}"
        )
    pattern_counts: dict[str, int] = defaultdict(int)
    observed_windows: set[int] = set()
    observed_positions: set[str] = set()
    observed_densities: set[str] = set()
    for case, row in parsed.comparisons.items():
        context = f"{parsed.path}:{case}"
        pattern = row.get("pattern_name", "")
        if pattern not in inventory or row.get("status") != "ok":
            raise ValidationError(f"{context}: source identity/status is invalid")
        family, _, seed = inventory[pattern]
        if row.get("family") != family or row.get("seed") != seed:
            raise ValidationError(f"{context}: comparison/receipt identity mismatch")
        if row.get("source_kind") != "atomic_choice_generated":
            raise ValidationError(f"{context}: source kind changed")
        if row.get("output") != "exists" or row.get("upstream_operation") != "is_match":
            raise ValidationError(f"{context}: output/oracle operation changed")
        if row.get("rotations") != "4" or row.get("trials") != "5" or row.get(
            "warmup_rounds"
        ) != "8":
            raise ValidationError(f"{context}: trial geometry changed")
        window = integer(row.get("window_bytes", ""), context)
        expected_searches = max((1_048_576 + window - 1) // window, 32)
        if integer(row.get("initial_searches", ""), context) != expected_searches:
            raise ValidationError(f"{context}: initial byte/search budget changed")
        position = row.get("match_position", "")
        density = row.get("candidate_density", "")
        observed_windows.add(window)
        observed_positions.add(position)
        observed_densities.add(density)
        pattern_counts[pattern] += 1
        rust_speed(row, context)
        for checksum_name in ("upstream_checksum", "native_checksum"):
            checksum = row.get(checksum_name, "")
            if not checksum.isdigit():
                raise ValidationError(f"{context}: malformed semantic checksum")
    if set(pattern_counts) != set(inventory) or set(pattern_counts.values()) != {48}:
        raise ValidationError(f"{parsed.path}: per-source scenario census is incomplete")
    if (
        observed_windows != WINDOWS
        or observed_positions != POSITIONS
        or observed_densities != DENSITIES
    ):
        raise ValidationError(f"{parsed.path}: scenario dimensions changed")


STATIC_COMPARISON_FIELDS = (
    "case",
    "pattern_name",
    "family",
    "seed",
    "source_kind",
    "pattern",
    "output",
    "upstream_operation",
    "target",
    "feature_bits",
    "window_bytes",
    "match_position",
    "candidate_density",
    "rotations",
    "initial_searches",
    "min_trial_ns",
    "trials",
    "warmup_rounds",
)


@dataclass(frozen=True)
class CellScore:
    family: str
    size: int
    window: int
    position: str
    density: str
    normalized_candidate_over_parent: float
    candidate_over_rust: float
    parent_over_rust: float


def build_cell_scores(
    parsed: dict[str, ParsedOutput],
    inventory: dict[str, tuple[str, int, str]],
) -> list[CellScore]:
    row_maps = {name: output.comparisons for name, output in parsed.items()}
    cases = set(next(iter(row_maps.values())))
    if any(set(rows) != cases for rows in row_maps.values()):
        raise ValidationError("ABBA phases do not contain identical case identities")
    scores: list[CellScore] = []
    for case in sorted(cases):
        rows = {name: values[case] for name, values in row_maps.items()}
        reference = rows["parent_upstream_native"]
        for name, row in rows.items():
            for field in STATIC_COMPARISON_FIELDS:
                if row.get(field) != reference.get(field):
                    raise ValidationError(f"{case}: {name} changed static field {field}")
        parent_un = rust_speed(rows["parent_upstream_native"], case)
        parent_nu = rust_speed(rows["parent_native_upstream"], case)
        candidate_un = rust_speed(rows["candidate_upstream_native"], case)
        candidate_nu = rust_speed(rows["candidate_native_upstream"], case)
        pattern = reference["pattern_name"]
        family, size, _ = inventory[pattern]
        scores.append(
            CellScore(
                family=family,
                size=size,
                window=integer(reference["window_bytes"], case),
                position=reference["match_position"],
                density=reference["candidate_density"],
                normalized_candidate_over_parent=geometric_mean(
                    (candidate_un / parent_un, candidate_nu / parent_nu)
                ),
                candidate_over_rust=geometric_mean((candidate_un, candidate_nu)),
                parent_over_rust=geometric_mean((parent_un, parent_nu)),
            )
        )
    return scores


def score_rows(
    scores: list[CellScore],
    parsed: dict[str, ParsedOutput],
) -> tuple[list[list[str]], bool]:
    output: list[list[str]] = []
    failed = False

    def add_group(
        scope: str,
        selected: list[CellScore],
        lower: float | None,
        upper: float | None,
        *dimensions: object,
    ) -> None:
        nonlocal failed
        normalized = geometric_mean(
            cell.normalized_candidate_over_parent for cell in selected
        )
        candidate_rust = geometric_mean(cell.candidate_over_rust for cell in selected)
        parent_rust = geometric_mean(cell.parent_over_rust for cell in selected)
        passed = (lower is None or normalized >= lower) and (
            upper is None or normalized <= upper
        )
        failed |= not passed
        output.append(
            [
                "group",
                scope,
                *(str(value) for value in dimensions),
                str(len(selected)),
                f"{normalized:.9f}",
                f"{candidate_rust:.9f}",
                f"{parent_rust:.9f}",
                "na" if lower is None else f"{lower:.2f}",
                "na" if upper is None else f"{upper:.2f}",
                "pass" if passed else "fail",
            ]
        )

    eligible = [cell for cell in scores if cell.family == "atomic_byte_set"]
    controls = [cell for cell in scores if cell.family == "atomic_single_literal"]
    add_group("eligible_overall", eligible, 1.05, None, "all", "all", "all", "all")
    add_group("control_overall", controls, 0.90, 1.10, "all", "all", "all", "all")

    # Preregistered hard floor at every complete cardinality/window/density/
    # position intersection. Two independent generator seeds populate each row.
    for size in sorted(CARDINALITIES):
        for window in sorted(WINDOWS):
            for density in sorted(DENSITIES):
                for position in sorted(POSITIONS):
                    selected = [
                        cell
                        for cell in eligible
                        if (cell.size, cell.window, cell.density, cell.position)
                        == (size, window, density, position)
                    ]
                    if len(selected) != 2:
                        raise ValidationError("eligible cross-group lost one generator seed")
                    add_group(
                        "eligible_cross",
                        selected,
                        0.95,
                        None,
                        size,
                        window,
                        density,
                        position,
                    )

    # Additive one-dimensional absolute Rust reports use the same sealed cells.
    dimensions = (
        ("eligible_cardinality", sorted(CARDINALITIES), lambda c: c.size),
        ("eligible_window", sorted(WINDOWS), lambda c: c.window),
        ("eligible_density", sorted(DENSITIES), lambda c: c.density),
        ("eligible_position", sorted(POSITIONS), lambda c: c.position),
    )
    for scope, values, key in dimensions:
        for value in values:
            selected = [cell for cell in eligible if key(cell) == value]
            add_group(scope, selected, None, None, value, "all", "all", "all")

    for width in sorted(CONTROL_WIDTHS):
        for window in sorted(WINDOWS):
            selected = [
                cell for cell in controls if cell.size == width and cell.window == window
            ]
            if len(selected) != 32:
                raise ValidationError("control width/window group is incomplete")
            add_group(
                "control_width_window",
                selected,
                0.85,
                None,
                width,
                window,
                "all",
                "all",
            )

    phase_pairs = {
        "parent": ("parent_upstream_native", "parent_native_upstream"),
        "candidate": ("candidate_upstream_native", "candidate_native_upstream"),
    }
    for subject, (first, second) in phase_pairs.items():
        for family in sorted(FAMILIES):
            cases = [
                case
                for case, row in parsed[first].comparisons.items()
                if row["family"] == family
            ]
            first_speed = geometric_mean(
                rust_speed(parsed[first].comparisons[case], case) for case in cases
            )
            second_speed = geometric_mean(
                rust_speed(parsed[second].comparisons[case], case) for case in cases
            )
            repeatability = first_speed / second_speed
            passed = 0.90 <= repeatability <= 1.10
            failed |= not passed
            output.append(
                [
                    "repeatability",
                    f"{subject}_{family}",
                    "all",
                    "all",
                    "all",
                    "all",
                    str(len(cases)),
                    f"{repeatability:.9f}",
                    "na",
                    "na",
                    "0.90",
                    "1.10",
                    "pass" if passed else "fail",
                ]
            )
    output.append(
        [
            "summary",
            "all_gates",
            "all",
            "all",
            "all",
            "all",
            str(len(scores)),
            "na",
            "na",
            "na",
            "na",
            "na",
            "fail" if failed else "pass",
        ]
    )
    return output, failed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--frozen-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    directory = args.directory.resolve()
    frozen_root = args.frozen_root.resolve()
    verify_hash_manifest(frozen_root / "FROZEN_SHA256SUMS", frozen_root)
    verify_seal(directory)
    frozen = parse_key_values(frozen_root / "manifests/qualification.env")

    metadata = parse_output(directory / "metadata-candidate.tsv")
    validate_environment(metadata, frozen, "upstream-native", True)
    if metadata.comparisons or not metadata.metadata_complete:
        raise ValidationError("metadata phase contains timing rows or lacks its completion seal")
    metadata_inventory = validate_receipts(metadata, True)

    phase_orders = {
        "parent_upstream_native": "upstream-native",
        "candidate_native_upstream": "native-upstream",
        "candidate_upstream_native": "upstream-native",
        "parent_native_upstream": "native-upstream",
    }
    parsed = {
        name: parse_output(directory / relative) for name, relative in PHASES.items()
    }
    inventories: dict[str, dict[str, tuple[str, int, str]]] = {}
    for name, output in parsed.items():
        candidate = name.startswith("candidate_")
        validate_environment(output, frozen, phase_orders[name], False)
        if output.metadata_complete:
            raise ValidationError(f"{output.path}: timing phase claimed metadata-only completion")
        inventories[name] = validate_receipts(output, candidate)
        validate_comparisons(output, inventories[name])
    if any(inventory != metadata_inventory for inventory in inventories.values()):
        raise ValidationError("parent/candidate source inventories are not identical")

    # Receipt rows must be byte-for-byte stable within each exact binary, and
    # candidate timing phases must reproduce the metadata-only provenance.
    if (
        parsed["parent_upstream_native"].receipts
        != parsed["parent_native_upstream"].receipts
        or parsed["candidate_upstream_native"].receipts
        != parsed["candidate_native_upstream"].receipts
        or parsed["candidate_upstream_native"].receipts != metadata.receipts
    ):
        raise ValidationError("receipt/object identities changed across frozen phases")

    scores = build_cell_scores(parsed, metadata_inventory)
    rows, failed = score_rows(scores, parsed)
    header = [
        "record",
        "scope",
        "semantic_size",
        "window_bytes",
        "candidate_density",
        "match_position",
        "cells",
        "candidate_over_parent_rust_normalized",
        "candidate_over_rust_absolute",
        "parent_over_rust_absolute",
        "lower_gate",
        "upper_gate",
        "status",
    ]
    temporary = args.output.with_name(f".{args.output.name}.tmp")
    temporary.write_text(
        "\t".join(header)
        + "\n"
        + "".join("\t".join(row) + "\n" for row in rows),
        encoding="utf-8",
    )
    os.replace(temporary, args.output)
    if failed:
        raise SystemExit("sealed ByteSet qualification failed one or more preregistered gates")
    print(f"sealed ByteSet qualification passed; report: {args.output}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValidationError) as error:
        raise SystemExit(f"sealed ByteSet qualification invalid: {error}") from error
