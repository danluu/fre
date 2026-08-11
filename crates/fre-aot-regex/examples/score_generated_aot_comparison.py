#!/usr/bin/env python3
"""Strict scorer for AB/BA generated AOT-vs-Rust comparison results.

The scorer consumes stdout TSV files from generated_aot_upstream_comparison.
It never generates patterns or invokes a benchmark. Final acceptance uses only
self-contained direct_dfa and direct_context_dfa rows by default. Preregistered
additive ISA profiles may augment, but never replace, the required ASIMD/AVX2
base profiles. The forced slow-partial schema scores its complete generated
matrix, including structural exclusions, without a post-result route filter.
Final acceptance requires every selected root, generator, output contract, and
observed route to meet the speed gate.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import math
import sys
import tempfile
from collections import defaultdict
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterable, Sequence


ORDERS = {"upstream-native", "native-upstream"}
DEFAULT_TARGETS = {"macos-aarch64", "linux-aarch64", "linux-x86_64"}


@dataclass(frozen=True)
class FeatureProfile:
    target: str
    requested_features: str
    feature_bits: str
    code_profile: str


FEATURE_PROFILES = {
    "macos-aarch64-asimd": FeatureProfile(
        "macos-aarch64", "asimd", "0x100000000", "aarch64-no-sve"
    ),
    "linux-aarch64-asimd": FeatureProfile(
        "linux-aarch64", "asimd", "0x100000000", "aarch64-no-sve"
    ),
    "linux-x86_64-avx2": FeatureProfile(
        "linux-x86_64", "avx2", "0x2", "not-aarch64"
    ),
    "linux-aarch64-sve": FeatureProfile(
        "linux-aarch64", "asimd,sve", "0x300000000", "aarch64-sve"
    ),
    "linux-aarch64-sve2": FeatureProfile(
        "linux-aarch64", "asimd,sve,sve2", "0x700000000", "aarch64-sve2"
    ),
    "linux-x86_64-avx512": FeatureProfile(
        "linux-x86_64",
        "avx2,avx512f,avx512bw,avx512vl",
        "0x1e",
        "not-aarch64",
    ),
}
BASE_PROFILE_NAMES = frozenset(
    {
        "macos-aarch64-asimd",
        "linux-aarch64-asimd",
        "linux-x86_64-avx2",
    }
)
ADDITIVE_PROFILE_NAMES = frozenset(FEATURE_PROFILES).difference(BASE_PROFILE_NAMES)
PROFILE_ALLOWED_ACCELERATORS = {
    "macos-aarch64-asimd": frozenset({"none", "scalar", "aarch64_asimd"}),
    "linux-aarch64-asimd": frozenset({"none", "scalar", "aarch64_asimd"}),
    "linux-aarch64-sve": frozenset(
        {"none", "scalar", "aarch64_asimd", "aarch64_sve"}
    ),
    "linux-aarch64-sve2": frozenset(
        {"none", "scalar", "aarch64_asimd", "aarch64_sve", "aarch64_sve2"}
    ),
    "linux-x86_64-avx2": frozenset(
        {"none", "scalar", "x86_sse2", "x86_avx2"}
    ),
    "linux-x86_64-avx512": frozenset(
        {"none", "scalar", "x86_sse2", "x86_avx2", "x86_avx512bw"}
    ),
}
DIRECT_ROUTES = frozenset({"direct_dfa", "direct_context_dfa"})
RESOURCE_FALLBACK_ROUTES = frozenset(
    {
        "direct_resource_fallback",
        "ordinary_runtime_resource_fallback",
        "prepared_runtime_resource_fallback",
        "slow_partial_resource_fallback",
    }
)
OUTPUT_MATRIX_MODES = {
    "assigned_v1": ({"span", "exists"}, 1),
    "span_exists_selected_end_v1": ({"span", "exists", "selected_end"}, 3),
}
ROUTE_METADATA = {
    "direct_dfa": ("ordered_dfa", "complete_dfa"),
    "direct_context_dfa": ("ordered_context_dfa", "complete_context_dfa"),
    "direct_context_fallback": ("ordered_nfa", "context_assertions"),
    "direct_resource_fallback": (
        "ordered_nfa",
        "determinization_resource_limit",
    ),
    "prepared_runtime_assertion": ("ordered_nfa", "context_assertions"),
    "ordinary_runtime_assertion": ("ordered_nfa", "context_assertions"),
    "ordinary_runtime_resource_fallback": (
        "ordered_nfa",
        "determinization_resource_limit",
    ),
    "prepared_runtime_resource_fallback": (
        "ordered_nfa",
        "determinization_resource_limit",
    ),
    "slow_partial_resource_fallback": (
        "ordered_nfa",
        "determinization_resource_limit",
    ),
}
ALL_COMPILED_ROUTES = frozenset(ROUTE_METADATA)
RESOURCE_FALLBACK_COMPLETE_SCOPE = "resource-fallback-complete"
RETAINED_FALLBACK_COMPLETE_SCOPE = "retained-resource-fallback-complete"
SLOW_PARTIAL_COMPLETE_SCOPE = "slow-partial-complete"
SCORE_SCOPES = {
    "direct": DIRECT_ROUTES,
    "all-compiled": ALL_COMPILED_ROUTES,
    "resource-fallback": RESOURCE_FALLBACK_ROUTES,
    RESOURCE_FALLBACK_COMPLETE_SCOPE: ALL_COMPILED_ROUTES,
    RETAINED_FALLBACK_COMPLETE_SCOPE: ALL_COMPILED_ROUTES,
    SLOW_PARTIAL_COMPLETE_SCOPE: ALL_COMPILED_ROUTES,
}
GENERAL_SCHEMA = "general-v1"
RESOURCE_FALLBACK_SCHEMA = "forced-resource-fallback-v1"
RETAINED_FALLBACK_SCHEMA = "forced-retained-resource-fallback-v1"
SLOW_PARTIAL_SCHEMA = "forced-slow-partial-resource-fallback-v1"
MATRIX_SCHEMAS = {
    GENERAL_SCHEMA: {
        "environment": {
            "force_resource_fallback": "false",
            "force_retained_resource_fallback": "false",
            "force_slow_partial_resource_fallback": "false",
            "slow_native_data_bytes": "default",
            "slow_aot_policy": "default",
        },
        "score_scope": None,
    },
    RESOURCE_FALLBACK_SCHEMA: {
        "environment": {
            "force_resource_fallback": "true",
            "force_retained_resource_fallback": "false",
            "force_slow_partial_resource_fallback": "false",
            "slow_native_data_bytes": "default",
            "slow_aot_policy": "disabled_for_zero_rows",
        },
        "score_scope": RESOURCE_FALLBACK_COMPLETE_SCOPE,
    },
    RETAINED_FALLBACK_SCHEMA: {
        "environment": {
            "force_resource_fallback": "false",
            "force_retained_resource_fallback": "true",
            "force_slow_partial_resource_fallback": "false",
            "slow_native_data_bytes": "default",
            "slow_aot_policy": "disabled_for_retained_rows",
        },
        "score_scope": RETAINED_FALLBACK_COMPLETE_SCOPE,
    },
    SLOW_PARTIAL_SCHEMA: {
        "environment": {
            "force_resource_fallback": "false",
            "force_retained_resource_fallback": "false",
            "force_slow_partial_resource_fallback": "true",
            "slow_native_data_bytes": "default",
            "slow_aot_policy": "derived_incomplete_forward_prefix",
        },
        "score_scope": SLOW_PARTIAL_COMPLETE_SCOPE,
    },
}
RETAINED_FALLBACK_DERIVATIONS = frozenset(
    {
        "excluded_contextual",
        "natural_decline_slow_disabled",
        "excluded_unusable_natural_retained_rows",
        "excluded_non_dfa_probe",
        "forward_state_limit",
        "excluded_zero_build_work",
        "final_work_limit",
        "excluded_no_usable_retained_rows",
    }
)
SLOW_PARTIAL_DERIVATIONS = frozenset(
    {
        "excluded_contextual",
        "excluded_non_resource_fallback",
        "excluded_exact_product",
        "excluded_no_complete_slow_probe",
        "excluded_no_interior_slow_state_limit",
        "excluded_no_genuine_slow_partial",
        "slow_natural_resource_limit",
        "slow_forward_state_limit",
        "slow_forward_state_search",
    }
)
SLOW_PARTIAL_ADMITTED_DERIVATIONS = frozenset(
    {
        "slow_natural_resource_limit",
        "slow_forward_state_limit",
        "slow_forward_state_search",
    }
)
FALLBACK_ARTIFACT_KINDS = frozenset(
    {
        "slow_aot_partial",
        "bit_parallel_exists",
        "retained_partial",
        "exact_product",
        "contextual",
        "dynamic_rows",
        "plain_nfa",
        "direct",
    }
)
MODE_SPECS = {
    "grammar_generated_out_of_sample": {
        "generator": "flat",
        "source_kind": "grammar_generated",
        "rows": 648,
        "patterns": 36,
        "families": 9,
        "windows": {64, 65_536},
        "positions": {"none", "start", "end"},
        "densities": {"zero", "1_per_8", "near_miss_1_per_32"},
    },
    "nested_grammar_generated_out_of_sample": {
        "generator": "nested",
        "source_kind": "nested_grammar_generated",
        "rows": 2_304,
        "patterns": 48,
        "families": 12,
        "windows": {64, 4_096, 65_536},
        "positions": {"none", "start", "middle", "end"},
        "densities": {"zero", "1_per_32", "near_miss_1_per_32", "dense"},
    },
}
STATIC_COLUMNS = (
    "case",
    "pattern_name",
    "family",
    "seed",
    "source_kind",
    "pattern",
    "output",
    "upstream_operation",
    "native_route",
    "engine",
    "selection_reason",
    "target",
    "feature_bits",
    "start_accelerator",
    "aarch64_sve_code_profile",
    "prefix_graph_bytes",
    "prefix_selective_positions",
    "prefix_filter_bytes",
    "window_bytes",
    "match_position",
    "candidate_density",
    "rotations",
    "initial_searches",
    "min_trial_ns",
    "trials",
    "warmup_rounds",
)


class ValidationError(Exception):
    """The result set is incomplete, inconsistent, or malformed."""


@dataclass(frozen=True)
class ResultFile:
    path: Path
    target: str
    feature_bits: str
    requested_features: str
    host: str
    generator: str
    seed: str
    order: str
    trials: int
    warmup_rounds: int
    min_trial_ns: int
    output_matrix: str
    matrix_schema: str
    rows: tuple[dict[str, str], ...]


@dataclass(frozen=True)
class Cell:
    host: str
    target: str
    feature_bits: str
    generator: str
    seed: str
    case: str
    pattern_name: str
    family: str
    output: str
    route: str
    window_bytes: int
    rust_over_aot: float

def geometric_mean(values: Iterable[float]) -> float:
    samples = list(values)
    if not samples or any(not math.isfinite(value) or value <= 0.0 for value in samples):
        raise ValidationError("geometric mean requires finite positive samples")
    return math.exp(math.fsum(math.log(value) for value in samples) / len(samples))


def p10(values: Iterable[float]) -> float:
    samples = sorted(values)
    if not samples:
        raise ValidationError("p10 requires at least one sample")
    return samples[(len(samples) - 1) * 10 // 100]


def rust_relative_speed(row: dict[str, str], context: str) -> float:
    try:
        rust_ns = float(row["upstream_median_ns_per_search"])
        aot_ns = float(row["native_median_ns_per_search"])
        printed = float(row["speedup_at_median"])
    except (KeyError, ValueError) as error:
        raise ValidationError(f"{context}: malformed median timing column: {error}") from error
    if not all(math.isfinite(value) and value > 0.0 for value in (rust_ns, aot_ns, printed)):
        raise ValidationError(f"{context}: median timing values must be finite and positive")
    ratio = rust_ns / aot_ns
    if not math.isclose(ratio, printed, rel_tol=1.0e-4, abs_tol=1.0e-4):
        raise ValidationError(
            f"{context}: speedup_at_median={printed} is not Rust/AOT={ratio}"
        )
    return ratio


def parse_count_receipt(value: str, context: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    if not value:
        raise ValidationError(f"{context}: empty count receipt")
    for field in value.split(","):
        name, separator, raw_count = field.partition("=")
        if not separator or not name or name in counts:
            raise ValidationError(f"{context}: malformed count receipt {value!r}")
        try:
            count = int(raw_count)
        except ValueError as error:
            raise ValidationError(
                f"{context}: malformed count receipt {value!r}"
            ) from error
        if count <= 0:
            raise ValidationError(f"{context}: counts must be positive")
        counts[name] = count
    return counts


def parse_result(path: Path, matrix_schema: str = GENERAL_SCHEMA) -> ResultFile:
    if matrix_schema not in MATRIX_SCHEMAS:
        raise ValidationError(f"unsupported matrix schema {matrix_schema!r}")
    metadata: dict[str, str] = {}
    header: list[str] | None = None
    rows: list[dict[str, str]] = []
    with path.open("r", encoding="utf-8", newline="") as source:
        for line_number, raw_line in enumerate(source, 1):
            line = raw_line.rstrip("\r\n")
            if not line:
                continue
            columns = line.split("\t")
            if columns[0] == "environment":
                if len(columns) != 3:
                    raise ValidationError(f"{path}:{line_number}: malformed environment row")
                key, value = columns[1], columns[2]
                if key in metadata and metadata[key] != value:
                    raise ValidationError(f"{path}:{line_number}: conflicting metadata {key}")
                metadata[key] = value
                continue
            if columns[0] == "comparison" and len(columns) > 1 and columns[1] == "case":
                if header is not None:
                    raise ValidationError(f"{path}:{line_number}: duplicate comparison header")
                header = columns
                continue
            if columns[0] == "comparison":
                if header is None or len(columns) != len(header):
                    raise ValidationError(f"{path}:{line_number}: malformed comparison row")
                rows.append(dict(zip(header, columns)))

    required_columns = set(STATIC_COLUMNS) | {
        "comparison",
        "upstream_median_ns_per_search",
        "native_median_ns_per_search",
        "speedup_at_median",
        "status",
    }
    if header is None or not required_columns.issubset(header):
        missing = sorted(required_columns.difference(header or ()))
        raise ValidationError(f"{path}: missing comparison columns {missing}")

    for key in (
        "benchmark_mode",
        "measurement_order",
        "target",
        "feature_bits",
        "requested_features",
        "seeds",
        "regex_version",
        "regex_features",
        "compiled_patterns",
        "scenarios",
        "host_feature_validation",
        "force_resource_fallback",
        "force_retained_resource_fallback",
        "force_slow_partial_resource_fallback",
        "slow_native_data_bytes",
        "slow_aot_policy",
        "fallback_artifact_counts",
        "fallback_limit_derivation_counts",
    ):
        if key not in metadata:
            raise ValidationError(f"{path}: missing environment metadata {key}")
    if metadata["regex_version"] != "1.13.1":
        raise ValidationError(f"{path}: Rust regex version is not the pinned 1.13.1")
    if metadata["regex_features"] != "default,perf-dfa-full (logging disabled)":
        raise ValidationError(f"{path}: Rust regex feature receipt is unexpected")
    if metadata["host_feature_validation"] != "passed":
        raise ValidationError(f"{path}: host feature validation did not pass")
    for key, expected in MATRIX_SCHEMAS[matrix_schema]["environment"].items():
        if metadata[key] != expected:
            raise ValidationError(
                f"{path}: schema {matrix_schema} requires {key}={expected!r}; "
                f"got {metadata[key]!r}"
            )
    mode = metadata["benchmark_mode"]
    if mode not in MODE_SPECS:
        raise ValidationError(f"{path}: unsupported benchmark mode {mode!r}")
    spec = MODE_SPECS[mode]
    output_matrix = metadata.get("output_matrix", "assigned_v1")
    if output_matrix not in OUTPUT_MATRIX_MODES:
        raise ValidationError(f"{path}: unsupported output matrix {output_matrix!r}")
    expected_outputs, row_multiplier = OUTPUT_MATRIX_MODES[output_matrix]
    order = metadata["measurement_order"]
    if order not in ORDERS:
        raise ValidationError(f"{path}: unsupported measurement order {order!r}")
    expected_rows = int(spec["rows"]) * row_multiplier
    if len(rows) != expected_rows:
        raise ValidationError(f"{path}: got {len(rows)} rows; expected {expected_rows}")
    seeds = {row.get("seed", "") for row in rows}
    if len(seeds) != 1:
        raise ValidationError(f"{path}: each result must contain exactly one root seed")
    seed = next(iter(seeds))
    if metadata["seeds"] != seed:
        raise ValidationError(f"{path}: environment seed and comparison rows disagree")
    target = metadata["target"]
    feature_bits = metadata["feature_bits"]
    requested_features = metadata["requested_features"]
    host = f"{target}@{feature_bits}"

    seen_cases: set[str] = set()
    for row in rows:
        case = row.get("case", "")
        context = f"{path}:{case or '<missing-case>'}"
        if not case or case in seen_cases:
            raise ValidationError(f"{context}: missing or duplicate case")
        seen_cases.add(case)
        if row.get("status") != "ok":
            raise ValidationError(f"{context}: status is not ok")
        if row.get("target") != target or row.get("feature_bits") != feature_bits:
            raise ValidationError(f"{context}: target metadata changed within a file")
        if row.get("source_kind") != spec["source_kind"]:
            raise ValidationError(f"{context}: source_kind does not match generator")
        route = row.get("native_route", "")
        if route not in ROUTE_METADATA:
            raise ValidationError(f"{context}: unknown native route {route!r}")
        expected_engine, expected_reason = ROUTE_METADATA[route]
        if (row.get("engine"), row.get("selection_reason")) != (
            expected_engine,
            expected_reason,
        ):
            raise ValidationError(f"{context}: route/engine/selection_reason disagree")
        if row.get("output") == "span" and row.get("upstream_operation") != "find":
            raise ValidationError(f"{context}: Span must compare with Regex::find")
        if row.get("output") == "exists" and row.get("upstream_operation") != "is_match":
            raise ValidationError(f"{context}: Exists must compare with Regex::is_match")
        if (
            row.get("output") == "selected_end"
            and row.get("upstream_operation") != "find_end"
        ):
            raise ValidationError(
                f"{context}: SelectedEnd must compare with Regex::find end"
            )
        if row.get("output") not in expected_outputs:
            raise ValidationError(f"{context}: unknown output contract")
        if row.get("rotations") != "4":
            raise ValidationError(f"{context}: expected four deterministic rotations")
        rust_relative_speed(row, context)

    patterns = {row["pattern_name"] for row in rows}
    families = {row["family"] for row in rows}
    outputs = {row["output"] for row in rows}
    try:
        windows = {int(row["window_bytes"]) for row in rows}
        settings = {
            (int(row["trials"]), int(row["warmup_rounds"]), int(row["min_trial_ns"]))
            for row in rows
        }
    except ValueError as error:
        raise ValidationError(f"{path}: malformed integer metadata: {error}") from error
    positions = {row["match_position"] for row in rows}
    densities = {row["candidate_density"] for row in rows}
    dimensions = (
        (len(patterns), spec["patterns"], "patterns"),
        (len(families), spec["families"], "families"),
        (outputs, expected_outputs, "output contracts"),
        (windows, spec["windows"], "window sizes"),
        (positions, spec["positions"], "match positions"),
        (densities, spec["densities"], "candidate densities"),
    )
    for actual, expected, name in dimensions:
        if actual != expected:
            raise ValidationError(f"{path}: {name} {actual!r}; expected {expected!r}")
    source_contracts: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    source_contract_rows: dict[tuple[str, str, str, str], int] = defaultdict(int)
    for row in rows:
        source = (row["pattern_name"], row["family"], row["pattern"])
        source_contracts[source].add(row["output"])
        source_contract_rows[(*source, row["output"])] += 1
    if len(source_contracts) != spec["patterns"]:
        raise ValidationError(
            f"{path}: got {len(source_contracts)} unique sources; "
            f"expected {spec['patterns']}"
        )
    if output_matrix != "assigned_v1":
        rows_per_source_contract = int(spec["rows"]) // int(spec["patterns"])
        for source, contracts in source_contracts.items():
            if contracts != expected_outputs:
                raise ValidationError(
                    f"{path}:{source[0]}: contracts {contracts}; expected {expected_outputs}"
                )
            for output in expected_outputs:
                count = source_contract_rows[(*source, output)]
                if count != rows_per_source_contract:
                    raise ValidationError(
                        f"{path}:{source[0]}/{output}: got {count} scenario rows; "
                        f"expected {rows_per_source_contract}"
                    )
    try:
        compiled_patterns = int(metadata["compiled_patterns"])
        scenarios = int(metadata["scenarios"])
    except ValueError as error:
        raise ValidationError(f"{path}: malformed compiled-pattern metadata") from error
    expected_compiled_patterns = int(spec["patterns"]) * row_multiplier
    if compiled_patterns != expected_compiled_patterns or scenarios != expected_rows:
        raise ValidationError(
            f"{path}: environment cardinality compiled_patterns={compiled_patterns}, "
            f"scenarios={scenarios}; expected {expected_compiled_patterns}, {expected_rows}"
        )
    artifact_counts = parse_count_receipt(
        metadata["fallback_artifact_counts"],
        f"{path}:fallback_artifact_counts",
    )
    derivation_counts = parse_count_receipt(
        metadata["fallback_limit_derivation_counts"],
        f"{path}:fallback_limit_derivation_counts",
    )
    if sum(artifact_counts.values()) != compiled_patterns:
        raise ValidationError(
            f"{path}: fallback artifact counts do not total compiled_patterns"
        )
    if sum(derivation_counts.values()) != compiled_patterns:
        raise ValidationError(
            f"{path}: fallback derivation counts do not total compiled_patterns"
        )
    if not set(artifact_counts).issubset(FALLBACK_ARTIFACT_KINDS):
        raise ValidationError(
            f"{path}: unknown fallback artifact kinds "
            f"{sorted(set(artifact_counts).difference(FALLBACK_ARTIFACT_KINDS))}"
        )
    if matrix_schema == RESOURCE_FALLBACK_SCHEMA:
        if derivation_counts != {"zero_state_slow_disabled": compiled_patterns}:
            raise ValidationError(
                f"{path}: zero-row fallback derivation receipt is incomplete"
            )
    elif matrix_schema == RETAINED_FALLBACK_SCHEMA:
        unknown_derivations = set(derivation_counts).difference(
            RETAINED_FALLBACK_DERIVATIONS
        )
        if unknown_derivations:
            raise ValidationError(
                f"{path}: unknown retained-row derivations {sorted(unknown_derivations)}"
            )
    elif matrix_schema == SLOW_PARTIAL_SCHEMA:
        unknown_derivations = set(derivation_counts).difference(SLOW_PARTIAL_DERIVATIONS)
        if unknown_derivations:
            raise ValidationError(
                f"{path}: unknown slow-partial derivations {sorted(unknown_derivations)}"
            )
        admitted_derivations = sum(
            derivation_counts.get(name, 0)
            for name in SLOW_PARTIAL_ADMITTED_DERIVATIONS
        )
        admitted_sources = {
            (row["pattern_name"], row["pattern"], row["output"])
            for row in rows
            if row["native_route"] == "slow_partial_resource_fallback"
        }
        if not admitted_sources:
            raise ValidationError(f"{path}: forced slow-partial schema admitted no source")
        if artifact_counts.get("slow_aot_partial", 0) != len(admitted_sources):
            raise ValidationError(
                f"{path}: slow-partial artifact count disagrees with comparison rows"
            )
        if admitted_derivations != len(admitted_sources):
            raise ValidationError(
                f"{path}: slow-partial derivation count disagrees with comparison rows"
            )
    if len(settings) != 1:
        raise ValidationError(f"{path}: timing settings changed between comparison rows")
    trials, warmup_rounds, min_trial_ns = next(iter(settings))
    if trials < 3 or warmup_rounds <= 0 or min_trial_ns <= 0:
        raise ValidationError(f"{path}: invalid timing settings")
    return ResultFile(
        path=path,
        target=target,
        feature_bits=feature_bits,
        requested_features=requested_features,
        host=host,
        generator=str(spec["generator"]),
        seed=seed,
        order=order,
        trials=trials,
        warmup_rounds=warmup_rounds,
        min_trial_ns=min_trial_ns,
        output_matrix=output_matrix,
        matrix_schema=matrix_schema,
        rows=tuple(rows),
    )


def feature_profile_name(result: ResultFile) -> str:
    receipt = (result.target, result.requested_features, result.feature_bits)
    matches = [
        name
        for name, profile in FEATURE_PROFILES.items()
        if receipt
        == (profile.target, profile.requested_features, profile.feature_bits)
    ]
    if len(matches) != 1:
        raise ValidationError(
            f"{result.path}: unregistered target/features/bits receipt {receipt!r}"
        )
    return matches[0]


def validate_profile_collection(
    files: Sequence[ResultFile], expected_profile_names: set[str]
) -> None:
    unknown_expected = expected_profile_names.difference(FEATURE_PROFILES)
    if unknown_expected:
        raise ValidationError(f"unknown expected profiles {sorted(unknown_expected)}")
    if not BASE_PROFILE_NAMES.issubset(expected_profile_names):
        raise ValidationError(
            "ASIMD/AVX2 base profiles are mandatory and cannot be replaced by additive profiles"
        )
    expected_additive = expected_profile_names.difference(BASE_PROFILE_NAMES)
    if len(expected_additive) > 1:
        raise ValidationError(
            "validate additive ISA profiles in separate scorer invocations"
        )
    files_by_profile: dict[str, list[ResultFile]] = defaultdict(list)
    for result in files:
        files_by_profile[feature_profile_name(result)].append(result)
    actual_profiles = set(files_by_profile)
    if actual_profiles != expected_profile_names:
        raise ValidationError(
            f"got profiles {sorted(actual_profiles)}; expected "
            f"{sorted(expected_profile_names)}"
        )

    valid_aarch64_profiles = {
        "none",
        "base_sve_exact_only",
        "base_sve_range_only",
        "sve2_exact_only",
        "mixed_sve2_exact_base_sve_range",
        "mixed_sve2_exact_base_sve_exact",
        "mixed_base_sve_exact_range",
        "mixed_sve2_exact_base_sve_exact_range",
    }
    for name, profile_files in files_by_profile.items():
        profile = FEATURE_PROFILES[name]
        accelerators = {
            row["start_accelerator"]
            for result in profile_files
            for row in result.rows
        }
        unexpected_accelerators = accelerators.difference(
            PROFILE_ALLOWED_ACCELERATORS[name]
        )
        if unexpected_accelerators:
            raise ValidationError(
                f"{name}: accelerator receipts exceed requested features: "
                f"{sorted(unexpected_accelerators)}"
            )
        code_profiles = {
            row["aarch64_sve_code_profile"]
            for result in profile_files
            for row in result.rows
        }
        if profile.code_profile == "not-aarch64":
            if code_profiles != {"not_aarch64"}:
                raise ValidationError(
                    f"{name}: x86 results contain AArch64 code-profile receipts "
                    f"{sorted(code_profiles)}"
                )
        elif not code_profiles.issubset(valid_aarch64_profiles):
            raise ValidationError(
                f"{name}: invalid AArch64 code-profile receipts {sorted(code_profiles)}"
            )
        elif profile.code_profile == "aarch64-no-sve" and code_profiles != {"none"}:
            raise ValidationError(
                f"{name}: base ASIMD profile unexpectedly contains SVE instructions"
            )
        elif profile.code_profile == "aarch64-sve":
            if any("sve2" in receipt for receipt in code_profiles):
                raise ValidationError(f"{name}: base-SVE profile contains SVE2 instructions")
            if code_profiles == {"none"}:
                raise ValidationError(f"{name}: additive SVE profile emitted no SVE code")
        elif profile.code_profile == "aarch64-sve2" and not any(
            "sve2" in receipt for receipt in code_profiles
        ):
            raise ValidationError(f"{name}: additive SVE2 profile emitted no SVE2 code")
        if profile.target.endswith("aarch64"):
            for result in profile_files:
                for row in result.rows:
                    code_profile = row["aarch64_sve_code_profile"]
                    accelerator = row["start_accelerator"]
                    if code_profile == "none" and accelerator in {
                        "aarch64_sve",
                        "aarch64_sve2",
                    }:
                        raise ValidationError(
                            f"{name}: scalable accelerator lacks a matching code receipt"
                        )
                    if "sve2" in code_profile and accelerator != "aarch64_sve2":
                        raise ValidationError(
                            f"{name}: SVE2 code and accelerator receipts disagree"
                        )
                    if (
                        code_profile != "none"
                        and "sve2" not in code_profile
                        and accelerator != "aarch64_sve"
                    ):
                        raise ValidationError(
                            f"{name}: base-SVE code and accelerator receipts disagree"
                        )


def validate_and_pair(
    files: Sequence[ResultFile],
    expected_targets: set[str],
    require_output_matrix: bool = True,
    expected_profile_names: set[str] | None = None,
) -> list[Cell]:
    indexed: dict[tuple[str, str, str, str], ResultFile] = {}
    for result in files:
        key = (result.host, result.generator, result.seed, result.order)
        if key in indexed:
            raise ValidationError(f"duplicate result tuple {key}")
        indexed[key] = result

    hosts = sorted({result.host for result in files})
    targets = {result.target for result in files}
    if targets != expected_targets:
        raise ValidationError(f"got targets {targets}; expected {expected_targets}")
    if expected_profile_names is None:
        if len(hosts) != len(targets):
            raise ValidationError("each target must use exactly one feature set")
    else:
        validate_profile_collection(files, expected_profile_names)
    roots = sorted({result.seed for result in files})
    if len(roots) != 2:
        raise ValidationError(f"got {len(roots)} roots; final acceptance requires exactly two")
    timing_settings = {
        (result.trials, result.warmup_rounds, result.min_trial_ns) for result in files
    }
    if len(timing_settings) != 1:
        raise ValidationError(f"timing settings differ across result files: {timing_settings}")
    output_matrices = {result.output_matrix for result in files}
    if len(output_matrices) != 1:
        raise ValidationError(f"output-matrix modes differ across files: {output_matrices}")
    output_matrix = next(iter(output_matrices))
    if require_output_matrix and output_matrix != "span_exists_selected_end_v1":
        raise ValidationError(
            "final acceptance requires --output-matrix results; "
            "use --allow-assigned-output only for legacy diagnostics"
        )
    matrix_schemas = {result.matrix_schema for result in files}
    if len(matrix_schemas) != 1:
        raise ValidationError(f"matrix schemas differ across files: {matrix_schemas}")
    for host in hosts:
        for generator in ("flat", "nested"):
            for seed in roots:
                orders = {
                    result.order
                    for result in files
                    if (result.host, result.generator, result.seed) == (host, generator, seed)
                }
                if orders != ORDERS:
                    raise ValidationError(
                        f"{host}/{generator}/{seed}: orders {orders}; expected {ORDERS}"
                    )

    paired: list[Cell] = []
    for host in hosts:
        for generator in ("flat", "nested"):
            for seed in roots:
                upstream_first = indexed[(host, generator, seed, "upstream-native")]
                native_first = indexed[(host, generator, seed, "native-upstream")]
                left = {row["case"]: row for row in upstream_first.rows}
                right = {row["case"]: row for row in native_first.rows}
                if left.keys() != right.keys():
                    raise ValidationError(f"{host}/{generator}/{seed}: AB/BA case sets differ")
                for case in sorted(left):
                    ab, ba = left[case], right[case]
                    for column in STATIC_COLUMNS:
                        if ab[column] != ba[column]:
                            raise ValidationError(
                                f"{host}/{generator}/{seed}/{case}: AB/BA {column} differs"
                            )
                    speed = geometric_mean(
                        (
                            rust_relative_speed(ab, f"{upstream_first.path}:{case}"),
                            rust_relative_speed(ba, f"{native_first.path}:{case}"),
                        )
                    )
                    paired.append(
                        Cell(
                            host=host,
                            target=upstream_first.target,
                            feature_bits=upstream_first.feature_bits,
                            generator=generator,
                            seed=seed,
                            case=case,
                            pattern_name=ab["pattern_name"],
                            family=ab["family"],
                            output=ab["output"],
                            route=ab["native_route"],
                            window_bytes=int(ab["window_bytes"]),
                            rust_over_aot=speed,
                        )
                    )

    semantic_by_host: dict[str, set[tuple[str, ...]]] = defaultdict(set)
    for cell in paired:
        semantic_by_host[cell.host].add(
            (
                cell.generator,
                cell.seed,
                cell.case,
                cell.family,
                cell.output,
                cell.route,
            )
        )
    reference_host = hosts[0]
    for host in hosts[1:]:
        if semantic_by_host[host] != semantic_by_host[reference_host]:
            raise ValidationError(f"{host}: semantic/route coverage differs from {reference_host}")
    return paired


def hierarchical_components(
    cells: Iterable[Cell],
) -> tuple[
    dict[tuple[str, str, str], float],
    dict[tuple[str, str], float],
    dict[str, float],
    float,
]:
    selected = list(cells)
    family_cells: dict[tuple[str, str, str], list[float]] = defaultdict(list)
    for cell in selected:
        family_cells[(cell.generator, cell.seed, cell.family)].append(cell.rust_over_aot)
    if not family_cells:
        raise ValidationError("hierarchical score has no cells")
    family_scores = {key: geometric_mean(values) for key, values in family_cells.items()}
    root_families: dict[tuple[str, str], list[float]] = defaultdict(list)
    for (generator, seed, _family), score in family_scores.items():
        root_families[(generator, seed)].append(score)
    root_scores = {key: geometric_mean(values) for key, values in root_families.items()}
    generator_roots: dict[str, list[float]] = defaultdict(list)
    for (generator, _seed), score in root_scores.items():
        generator_roots[generator].append(score)
    generator_scores = {
        generator: geometric_mean(values) for generator, values in generator_roots.items()
    }
    return (
        family_scores,
        root_scores,
        generator_scores,
        geometric_mean(generator_scores.values()),
    )


def hierarchical_score(cells: Iterable[Cell]) -> float:
    return hierarchical_components(cells)[3]


def report(
    cells: Sequence[Cell],
    minimum_speedup: float,
    minimum_direct_coverage: float = 1.0,
    score_routes: frozenset[str] = DIRECT_ROUTES,
) -> bool:
    hosts = sorted({cell.host for cell in cells})
    roots = sorted({cell.seed for cell in cells})
    print(
        "#coverage\thost\tgenerator\tseed\tcells\tscoreable_cells\tdirect_dfa_cells"
        "\tdirect_context_dfa_cells\tunscored_cells\tunique_patterns"
        "\tfully_direct_patterns\tdirect_pattern_coverage\tminimum_required"
        "\tfamilies\tscoreable_families\tstatus"
    )
    print(
        "#contract_coverage\thost\tgenerator\tseed\toutput\tunique_patterns"
        "\tdirect_patterns\tdirect_pattern_coverage\tminimum_required\tstatus"
    )
    coverage_accepted = {host: True for host in hosts}
    for host in hosts:
        for generator in ("flat", "nested"):
            expected_families = 9 if generator == "flat" else 12
            for seed in roots:
                group = [
                    cell
                    for cell in cells
                    if (cell.host, cell.generator, cell.seed) == (host, generator, seed)
                ]
                scoreable = [cell for cell in group if cell.route in score_routes]
                direct = sum(cell.route == "direct_dfa" for cell in group)
                context = sum(cell.route == "direct_context_dfa" for cell in group)
                families = {cell.family for cell in group}
                scoreable_families = {cell.family for cell in scoreable}
                routes_by_contract: dict[tuple[str, str], set[str]] = defaultdict(set)
                outputs_by_pattern: dict[str, set[str]] = defaultdict(set)
                for cell in group:
                    routes_by_contract[(cell.pattern_name, cell.output)].add(cell.route)
                    outputs_by_pattern[cell.pattern_name].add(cell.output)
                for unit, routes in routes_by_contract.items():
                    if len(routes) != 1:
                        raise ValidationError(
                            f"{host}/{generator}/{seed}/{unit}: route changed across scenarios"
                        )
                expected_outputs = {cell.output for cell in group}
                if any(outputs != expected_outputs for outputs in outputs_by_pattern.values()):
                    raise ValidationError(
                        f"{host}/{generator}/{seed}: output matrix is incomplete by source"
                    )
                fully_direct_patterns = {
                    pattern
                    for pattern, outputs in outputs_by_pattern.items()
                    if all(
                        next(iter(routes_by_contract[(pattern, output)])) in DIRECT_ROUTES
                        for output in outputs
                    )
                }
                pattern_coverage = len(fully_direct_patterns) / len(outputs_by_pattern)
                coverage_status = (
                    "pass"
                    if pattern_coverage >= minimum_direct_coverage
                    else "fail"
                )
                coverage_accepted[host] &= coverage_status == "pass"
                if not scoreable or len(scoreable_families) != expected_families:
                    raise ValidationError(
                        f"{host}/{generator}/{seed}: incomplete selected-route family coverage"
                    )
                if score_routes == DIRECT_ROUTES and (direct == 0 or context == 0):
                    raise ValidationError(
                        f"{host}/{generator}/{seed}: incomplete direct/context compiled coverage"
                    )
                print(
                    "coverage",
                    host,
                    generator,
                    seed,
                    len(group),
                    len(scoreable),
                    direct,
                    context,
                    len(group) - len(scoreable),
                    len(outputs_by_pattern),
                    len(fully_direct_patterns),
                    f"{pattern_coverage:.6f}",
                    f"{minimum_direct_coverage:.6f}",
                    len(families),
                    len(scoreable_families),
                    coverage_status,
                    sep="\t",
                )
                for output in sorted(expected_outputs):
                    contract_patterns = {
                        pattern
                        for pattern, outputs in outputs_by_pattern.items()
                        if output in outputs
                    }
                    direct_patterns = {
                        pattern
                        for pattern in contract_patterns
                        if next(iter(routes_by_contract[(pattern, output)])) in DIRECT_ROUTES
                    }
                    contract_coverage = len(direct_patterns) / len(contract_patterns)
                    contract_status = (
                        "pass"
                        if contract_coverage >= minimum_direct_coverage
                        else "fail"
                    )
                    coverage_accepted[host] &= contract_status == "pass"
                    print(
                        "contract_coverage",
                        host,
                        generator,
                        seed,
                        output,
                        len(contract_patterns),
                        len(direct_patterns),
                        f"{contract_coverage:.6f}",
                        f"{minimum_direct_coverage:.6f}",
                        contract_status,
                        sep="\t",
                    )

    print("#p10\thost\tscope\tvalue\tcells\tp10_rust_over_aot\tstatus")
    print(
        "#size\thost\twindow_bytes\tgenerators\troots\tfamilies\tcells"
        "\thierarchical_rust_over_aot\tp10_rust_over_aot\tstatus"
    )
    print(
        "#host_summary\thost\tgenerators\troots\tfamilies\tcells"
        "\thierarchical_rust_over_aot\tminimum_required\tstatus"
    )
    print(
        "#root_score\thost\tgenerator\tseed\tequal_weighted_families"
        "\trust_over_aot\tminimum_required\tstatus"
    )
    print(
        "#generator_score\thost\tgenerator\tequal_weighted_roots\trust_over_aot"
        "\tminimum_required\tstatus"
    )
    print(
        "#route_generator_score\thost\tgenerator\troute\tequal_weighted_roots"
        "\troot_family_blocks\tcells\trust_over_aot\tminimum_required\tstatus"
    )
    print(
        "#route_score\thost\troute\tequal_weighted_generators\tgenerator_root_blocks"
        "\tgenerator_root_family_blocks\tcells\trust_over_aot\tminimum_required\tstatus"
    )
    print(
        "#contract_generator_score\thost\tgenerator\toutput\tequal_weighted_roots"
        "\troot_family_blocks\tcells\trust_over_aot\tminimum_required\tstatus"
    )
    print(
        "#contract_root_score\thost\tgenerator\tseed\toutput\tequal_weighted_families"
        "\tcells\trust_over_aot\tminimum_required\tstatus"
    )
    print(
        "#contract_score\thost\toutput\tequal_weighted_generators"
        "\tgenerator_root_blocks\tgenerator_root_family_blocks\tcells\trust_over_aot"
        "\tminimum_required\tstatus"
    )
    accepted = True
    for host in hosts:
        host_accepted = coverage_accepted[host]
        host_cells = [
            cell
            for cell in cells
            if cell.host == host and cell.route in score_routes
        ]
        if not host_cells:
            raise ValidationError(f"{host}: selected score scope has no cells")
        for scope, value, scoped in [
            ("compiled_primary", "all", host_cells),
            *[
                (
                    "route",
                    route,
                    [cell for cell in host_cells if cell.route == route],
                )
                for route in sorted(score_routes)
                if any(cell.route == route for cell in host_cells)
            ],
        ]:
            print(
                "p10",
                host,
                scope,
                value,
                len(scoped),
                f"{p10(cell.rust_over_aot for cell in scoped):.6f}",
                "ok",
                sep="\t",
            )
        for output in sorted({cell.output for cell in host_cells}):
            output_cells = [cell for cell in host_cells if cell.output == output]
            print(
                "p10",
                host,
                "output",
                output,
                len(output_cells),
                f"{p10(cell.rust_over_aot for cell in output_cells):.6f}",
                "ok",
                sep="\t",
            )
        for window in sorted({cell.window_bytes for cell in host_cells}):
            size_cells = [cell for cell in host_cells if cell.window_bytes == window]
            print(
                "size",
                host,
                window,
                len({cell.generator for cell in size_cells}),
                len({cell.seed for cell in size_cells}),
                len({(cell.generator, cell.seed, cell.family) for cell in size_cells}),
                len(size_cells),
                f"{hierarchical_score(size_cells):.6f}",
                f"{p10(cell.rust_over_aot for cell in size_cells):.6f}",
                "ok",
                sep="\t",
            )
        family_scores, root_scores, generator_scores, score = hierarchical_components(host_cells)
        for (generator, seed), root_score in sorted(root_scores.items()):
            family_count = sum(
                key_generator == generator and key_seed == seed
                for key_generator, key_seed, _family in family_scores
            )
            root_status = "pass" if root_score >= minimum_speedup else "fail"
            host_accepted &= root_status == "pass"
            print(
                "root_score",
                host,
                generator,
                seed,
                family_count,
                f"{root_score:.6f}",
                f"{minimum_speedup:.6f}",
                root_status,
                sep="\t",
            )
        for generator, generator_score in sorted(generator_scores.items()):
            root_count = sum(key_generator == generator for key_generator, _seed in root_scores)
            generator_status = (
                "pass" if generator_score >= minimum_speedup else "fail"
            )
            host_accepted &= generator_status == "pass"
            print(
                "generator_score",
                host,
                generator,
                root_count,
                f"{generator_score:.6f}",
                f"{minimum_speedup:.6f}",
                generator_status,
                sep="\t",
            )

        contract_totals: dict[str, list[float]] = defaultdict(list)
        for generator in sorted(generator_scores):
            for output in sorted({cell.output for cell in host_cells}):
                contract_generator_cells = [
                    cell
                    for cell in host_cells
                    if cell.generator == generator and cell.output == output
                ]
                if not contract_generator_cells:
                    raise ValidationError(
                        f"{host}/{generator}/{output}: no selected compiled cells"
                    )
                (
                    contract_family_scores,
                    contract_root_scores,
                    _contract_generator_scores,
                    contract_generator_score,
                ) = hierarchical_components(contract_generator_cells)
                for (root_generator, root_seed), contract_root_score in sorted(
                    contract_root_scores.items()
                ):
                    contract_root_cells = [
                        cell
                        for cell in contract_generator_cells
                        if cell.seed == root_seed
                    ]
                    contract_root_status = (
                        "pass"
                        if contract_root_score >= minimum_speedup
                        else "fail"
                    )
                    host_accepted &= contract_root_status == "pass"
                    print(
                        "contract_root_score",
                        host,
                        root_generator,
                        root_seed,
                        output,
                        len(
                            {
                                cell.family
                                for cell in contract_root_cells
                            }
                        ),
                        len(contract_root_cells),
                        f"{contract_root_score:.6f}",
                        f"{minimum_speedup:.6f}",
                        contract_root_status,
                        sep="\t",
                    )
                contract_totals[output].append(contract_generator_score)
                contract_generator_status = (
                    "pass"
                    if contract_generator_score >= minimum_speedup
                    else "fail"
                )
                host_accepted &= contract_generator_status == "pass"
                print(
                    "contract_generator_score",
                    host,
                    generator,
                    output,
                    len(contract_root_scores),
                    len(contract_family_scores),
                    len(contract_generator_cells),
                    f"{contract_generator_score:.6f}",
                    f"{minimum_speedup:.6f}",
                    contract_generator_status,
                    sep="\t",
                )
        for output in sorted(contract_totals):
            contract_cells = [cell for cell in host_cells if cell.output == output]
            contract_score = geometric_mean(contract_totals[output])
            contract_status = "pass" if contract_score >= minimum_speedup else "fail"
            host_accepted &= contract_status == "pass"
            print(
                "contract_score",
                host,
                output,
                len(contract_totals[output]),
                len({(cell.generator, cell.seed) for cell in contract_cells}),
                len(
                    {
                        (cell.generator, cell.seed, cell.family)
                        for cell in contract_cells
                    }
                ),
                len(contract_cells),
                f"{contract_score:.6f}",
                f"{minimum_speedup:.6f}",
                contract_status,
                sep="\t",
            )

        route_totals: dict[str, list[float]] = defaultdict(list)
        for generator in sorted(generator_scores):
            for route in sorted(score_routes):
                route_generator_cells = [
                    cell
                    for cell in host_cells
                    if cell.generator == generator and cell.route == route
                ]
                if not route_generator_cells:
                    continue
                (
                    route_family_scores,
                    route_root_scores,
                    _route_generator_scores,
                    route_generator_score,
                ) = hierarchical_components(route_generator_cells)
                route_totals[route].append(route_generator_score)
                route_generator_status = (
                    "pass" if route_generator_score >= minimum_speedup else "fail"
                )
                host_accepted &= route_generator_status == "pass"
                print(
                    "route_generator_score",
                    host,
                    generator,
                    route,
                    len(route_root_scores),
                    len(route_family_scores),
                    len(route_generator_cells),
                    f"{route_generator_score:.6f}",
                    f"{minimum_speedup:.6f}",
                    route_generator_status,
                    sep="\t",
                )
        for route in sorted(route_totals):
            route_cells = [cell for cell in host_cells if cell.route == route]
            route_score = geometric_mean(route_totals[route])
            route_status = "pass" if route_score >= minimum_speedup else "fail"
            host_accepted &= route_status == "pass"
            print(
                "route_score",
                host,
                route,
                len(route_totals[route]),
                len({(cell.generator, cell.seed) for cell in route_cells}),
                len(
                    {
                        (cell.generator, cell.seed, cell.family)
                        for cell in route_cells
                    }
                ),
                len(route_cells),
                f"{route_score:.6f}",
                f"{minimum_speedup:.6f}",
                route_status,
                sep="\t",
            )
        status = "pass" if score >= minimum_speedup and host_accepted else "fail"
        accepted &= status == "pass"
        print(
            "host_summary",
            host,
            len({cell.generator for cell in host_cells}),
            len({cell.seed for cell in host_cells}),
            len({(cell.generator, cell.seed, cell.family) for cell in host_cells}),
            len(host_cells),
            f"{score:.6f}",
            f"{minimum_speedup:.6f}",
            status,
            sep="\t",
        )
    return accepted


def self_test() -> None:
    assert math.isclose(geometric_mean([1.0, 4.0]), 2.0)
    assert p10(range(1, 11)) == 1
    row = {
        "upstream_median_ns_per_search": "30.000000",
        "native_median_ns_per_search": "20.000000",
        "speedup_at_median": "1.500000",
    }
    assert math.isclose(rust_relative_speed(row, "self-test"), 1.5)

    def profile_result(name: str, code_profiles: tuple[str, ...]) -> ResultFile:
        profile = FEATURE_PROFILES[name]

        def accelerator_for(receipt: str) -> str:
            if name in {"macos-aarch64-asimd", "linux-aarch64-asimd"}:
                return "aarch64_asimd"
            if name == "linux-aarch64-sve":
                return "aarch64_asimd" if receipt == "none" else "aarch64_sve"
            if name == "linux-aarch64-sve2":
                if receipt == "none":
                    return "aarch64_asimd"
                return "aarch64_sve2" if "sve2" in receipt else "aarch64_sve"
            if name == "linux-x86_64-avx2":
                return "x86_avx2"
            return "x86_avx512bw"
        return ResultFile(
            path=Path(f"synthetic-{name}.tsv"),
            target=profile.target,
            feature_bits=profile.feature_bits,
            requested_features=profile.requested_features,
            host=f"{profile.target}@{profile.feature_bits}",
            generator="flat",
            seed="r1",
            order="upstream-native",
            trials=3,
            warmup_rounds=1,
            min_trial_ns=1,
            output_matrix="span_exists_selected_end_v1",
            matrix_schema=GENERAL_SCHEMA,
            rows=tuple(
                {
                    "aarch64_sve_code_profile": receipt,
                    "start_accelerator": accelerator_for(receipt),
                }
                for receipt in code_profiles
            ),
        )

    base_profile_files = [
        profile_result("macos-aarch64-asimd", ("none",)),
        profile_result("linux-aarch64-asimd", ("none",)),
        profile_result("linux-x86_64-avx2", ("not_aarch64",)),
    ]
    validate_profile_collection(base_profile_files, set(BASE_PROFILE_NAMES))
    sve_profile = profile_result(
        "linux-aarch64-sve", ("none", "base_sve_range_only")
    )
    sve2_profile = profile_result(
        "linux-aarch64-sve2", ("none", "sve2_exact_only")
    )
    validate_profile_collection(
        [*base_profile_files, sve_profile],
        set(BASE_PROFILE_NAMES | {"linux-aarch64-sve"}),
    )
    validate_profile_collection(
        [*base_profile_files, sve2_profile],
        set(BASE_PROFILE_NAMES | {"linux-aarch64-sve2"}),
    )
    avx512_profile = profile_result("linux-x86_64-avx512", ("not_aarch64",))
    validate_profile_collection(
        [*base_profile_files, avx512_profile],
        set(BASE_PROFILE_NAMES | {"linux-x86_64-avx512"}),
    )
    try:
        validate_profile_collection(
            [base_profile_files[0], base_profile_files[2], sve_profile],
            set(BASE_PROFILE_NAMES | {"linux-aarch64-sve"}),
        )
    except ValidationError as error:
        assert "got profiles" in str(error)
    else:
        raise AssertionError("an additive SVE profile substituted for base Linux ASIMD")
    mixed_receipt = replace(
        sve_profile,
        path=Path("synthetic-mixed-sve-receipt.tsv"),
        feature_bits="0x700000000",
        host="linux-aarch64@0x700000000",
    )
    try:
        validate_profile_collection(
            [*base_profile_files, mixed_receipt],
            set(BASE_PROFILE_NAMES | {"linux-aarch64-sve"}),
        )
    except ValidationError as error:
        assert "unregistered" in str(error)
    else:
        raise AssertionError("mixed SVE requested-feature/feature-bit receipts passed")
    mixed_code_receipt = replace(
        sve_profile,
        path=Path("synthetic-mixed-sve-code-receipt.tsv"),
        rows=(
            {
                "aarch64_sve_code_profile": "sve2_exact_only",
                "start_accelerator": "aarch64_sve",
            },
        ),
    )
    try:
        validate_profile_collection(
            [*base_profile_files, mixed_code_receipt],
            set(BASE_PROFILE_NAMES | {"linux-aarch64-sve"}),
        )
    except ValidationError as error:
        assert "contains SVE2" in str(error)
    else:
        raise AssertionError("SVE-only feature profile accepted an SVE2 code receipt")

    cells = [
        Cell(
            "h",
            "t",
            "f",
            generator,
            seed,
            f"{generator}-{seed}-{family}",
            family,
            family,
            "span",
            "direct_dfa",
            64,
            speed,
        )
        for generator, roots in {
            "flat": {"r1": {"a": 1.0, "b": 4.0}, "r2": {"a": 1.0, "b": 9.0}},
            "nested": {"r1": {"c": 16.0}, "r2": {"c": 16.0}},
        }.items()
        for seed, families in roots.items()
        for family, speed in families.items()
    ]
    # flat = sqrt(sqrt(1*4) * sqrt(1*9)) = sqrt(6); nested = 16;
    # equal-generator result is sqrt(sqrt(6) * 16).
    expected = math.sqrt(math.sqrt(6.0) * 16.0)
    assert math.isclose(hierarchical_score(cells), expected)

    def adversarial_cells(
        generator_speed: dict[str, float] | None = None,
        route_speed: dict[str, float] | None = None,
    ) -> list[Cell]:
        generated = []
        for generator, family_count in (("flat", 9), ("nested", 12)):
            for seed in ("r1", "r2"):
                for family_index in range(family_count):
                    route = (
                        "direct_context_dfa"
                        if family_index == 0
                        else "direct_dfa"
                    )
                    speed = 2.0
                    if generator_speed is not None:
                        speed = generator_speed[generator]
                    if route_speed is not None:
                        speed = route_speed[route]
                    family = f"{generator}_family_{family_index}"
                    generated.append(
                        Cell(
                            "h",
                            "t",
                            "f",
                            generator,
                            seed,
                            f"{generator}-{seed}-{family}",
                            family,
                            family,
                            "span",
                            route,
                            64,
                            speed,
                        )
                    )
        return generated

    failing_generator = adversarial_cells(
        generator_speed={"flat": 1.0, "nested": 4.0}
    )
    assert hierarchical_score(failing_generator) > 1.5
    generator_output = io.StringIO()
    with contextlib.redirect_stdout(generator_output):
        assert not report(failing_generator, minimum_speedup=1.5)
    assert any(
        line.startswith("generator_score\th\tflat\t") and line.endswith("\tfail")
        for line in generator_output.getvalue().splitlines()
    )

    failing_route = adversarial_cells(
        route_speed={"direct_dfa": 4.0, "direct_context_dfa": 1.0}
    )
    assert hierarchical_score(failing_route) > 1.5
    route_output = io.StringIO()
    with contextlib.redirect_stdout(route_output):
        assert not report(failing_route, minimum_speedup=1.5)
    assert any(
        line.startswith("route_score\th\tdirect_context_dfa\t")
        and line.endswith("\tfail")
        for line in route_output.getvalue().splitlines()
    )

    contract_matrix = [
        Cell(
            cell.host,
            cell.target,
            cell.feature_bits,
            cell.generator,
            cell.seed,
            f"{cell.case}-{output}",
            cell.pattern_name,
            cell.family,
            output,
            cell.route,
            cell.window_bytes,
            1.0 if output == "selected_end" else 4.0,
        )
        for cell in adversarial_cells()
        for output in ("span", "exists", "selected_end")
    ]
    contract_output = io.StringIO()
    with contextlib.redirect_stdout(contract_output):
        assert not report(contract_matrix, minimum_speedup=1.5)
    assert any(
        line.startswith("contract_score\th\tselected_end\t")
        and line.endswith("\tfail")
        for line in contract_output.getvalue().splitlines()
    )

    fallback_routes = sorted(RESOURCE_FALLBACK_ROUTES)
    fallback_cells = [
        Cell(
            cell.host,
            cell.target,
            cell.feature_bits,
            cell.generator,
            cell.seed,
            cell.case,
            cell.pattern_name,
            cell.family,
            cell.output,
            fallback_routes[index % len(fallback_routes)],
            cell.window_bytes,
            cell.rust_over_aot,
        )
        for index, cell in enumerate(adversarial_cells())
    ]
    fallback_output = io.StringIO()
    with contextlib.redirect_stdout(fallback_output):
        assert report(
            fallback_cells,
            minimum_speedup=1.5,
            minimum_direct_coverage=0.0,
            score_routes=RESOURCE_FALLBACK_ROUTES,
        )
    assert all(
        any(
            line.startswith(f"route_score\th\t{route}\t")
            and line.endswith("\tpass")
            for line in fallback_output.getvalue().splitlines()
        )
        for route in RESOURCE_FALLBACK_ROUTES
    )

    incomplete_coverage = adversarial_cells()
    exemplar = incomplete_coverage[1]
    incomplete_coverage.append(
        Cell(
            exemplar.host,
            exemplar.target,
            exemplar.feature_bits,
            exemplar.generator,
            exemplar.seed,
            f"{exemplar.case}-fallback",
            f"{exemplar.pattern_name}-fallback",
            exemplar.family,
            exemplar.output,
            "prepared_runtime_resource_fallback",
            exemplar.window_bytes,
            100.0,
        )
    )
    coverage_output = io.StringIO()
    with contextlib.redirect_stdout(coverage_output):
        assert not report(
            incomplete_coverage,
            minimum_speedup=1.5,
            minimum_direct_coverage=1.0,
        )
    assert any(
        line.startswith("coverage\th\tflat\tr1\t") and line.endswith("\tfail")
        for line in coverage_output.getvalue().splitlines()
    )

    header = [
        "comparison",
        "case",
        "pattern_name",
        "family",
        "seed",
        "source_kind",
        "pattern",
        "output",
        "upstream_operation",
        "native_route",
        "engine",
        "selection_reason",
        "target",
        "feature_bits",
        "start_accelerator",
        "aarch64_sve_code_profile",
        "prefix_graph_bytes",
        "prefix_selective_positions",
        "prefix_filter_bytes",
        "window_bytes",
        "match_position",
        "candidate_density",
        "rotations",
        "initial_searches",
        "min_trial_ns",
        "trials",
        "warmup_rounds",
        "upstream_searches_per_trial",
        "upstream_min_elapsed_ns",
        "upstream_median_elapsed_ns",
        "upstream_min_ns_per_search",
        "upstream_median_ns_per_search",
        "native_searches_per_trial",
        "native_min_elapsed_ns",
        "native_median_elapsed_ns",
        "native_min_ns_per_search",
        "native_median_ns_per_search",
        "speedup_at_min",
        "speedup_at_median",
        "upstream_checksum",
        "native_checksum",
        "status",
    ]

    def synthetic_file(
        directory: Path,
        generator: str,
        seed: str,
        order: str,
        output_matrix: bool = True,
        matrix_schema: str = GENERAL_SCHEMA,
        omit_final_row: bool = False,
        admit_slow_partial: bool = True,
    ) -> Path:
        if generator == "flat":
            mode = "grammar_generated_out_of_sample"
            source_kind = "grammar_generated"
            family_count = 9
            windows = (64, 65_536)
            positions = ("none", "start", "end")
            densities = ("zero", "1_per_8", "near_miss_1_per_32")
        else:
            mode = "nested_grammar_generated_out_of_sample"
            source_kind = "nested_grammar_generated"
            family_count = 12
            windows = (64, 4_096, 65_536)
            positions = ("none", "start", "middle", "end")
            densities = ("zero", "1_per_32", "near_miss_1_per_32", "dense")
        matrix_name = "matrix" if output_matrix else "assigned"
        path = directory / (
            f"{matrix_schema}-{generator}-{seed}-{order}-{matrix_name}-"
            f"omit-{omit_final_row}-admit-{admit_slow_partial}.tsv"
        )
        with path.open("w", encoding="utf-8", newline="") as output:
            output.write(f"environment\tbenchmark_mode\t{mode}\n")
            output.write(f"environment\tmeasurement_order\t{order}\n")
            output.write(
                "environment\toutput_matrix\t"
                + (
                    "span_exists_selected_end_v1\n"
                    if output_matrix
                    else "assigned_v1\n"
                )
            )
            output.write("environment\ttarget\tsynthetic-host\n")
            output.write("environment\tfeature_bits\t0x1\n")
            output.write("environment\trequested_features\tsynthetic\n")
            output.write(f"environment\tseeds\t{seed}\n")
            output.write("environment\tregex_version\t1.13.1\n")
            output.write(
                "environment\tregex_features\tdefault,perf-dfa-full (logging disabled)\n"
            )
            contract_count = 3 if output_matrix else 1
            compiled_patterns = family_count * 4 * contract_count
            schema_environment = MATRIX_SCHEMAS[matrix_schema]["environment"]
            output.write("environment\thost_feature_validation\tpassed\n")
            for key, value in schema_environment.items():
                output.write(f"environment\t{key}\t{value}\n")
            if matrix_schema == SLOW_PARTIAL_SCHEMA:
                admitted = 4 * contract_count
                output.write(
                    "environment\tfallback_artifact_counts\t"
                    f"direct={compiled_patterns - admitted},slow_aot_partial={admitted}\n"
                )
                output.write(
                    "environment\tfallback_limit_derivation_counts\t"
                    f"excluded_exact_product={compiled_patterns - admitted},"
                    f"slow_forward_state_limit={admitted}\n"
                )
            elif matrix_schema == RESOURCE_FALLBACK_SCHEMA:
                output.write(
                    f"environment\tfallback_artifact_counts\tplain_nfa={compiled_patterns}\n"
                )
                output.write(
                    "environment\tfallback_limit_derivation_counts\t"
                    f"zero_state_slow_disabled={compiled_patterns}\n"
                )
            elif matrix_schema == RETAINED_FALLBACK_SCHEMA:
                output.write(
                    f"environment\tfallback_artifact_counts\tretained_partial={compiled_patterns}\n"
                )
                output.write(
                    "environment\tfallback_limit_derivation_counts\t"
                    f"forward_state_limit={compiled_patterns}\n"
                )
            else:
                output.write(
                    f"environment\tfallback_artifact_counts\tdirect={compiled_patterns}\n"
                )
                output.write(
                    "environment\tfallback_limit_derivation_counts\t"
                    f"not_requested={compiled_patterns}\n"
                )
            output.write(
                f"environment\tcompiled_patterns\t{compiled_patterns}\n"
            )
            output.write(
                "environment\tscenarios\t"
                f"{family_count * 4 * len(windows) * len(positions) * len(densities) * contract_count}\n"
            )
            output.write("\t".join(header) + "\n")
            for family_index in range(family_count):
                family = f"{generator}_family_{family_index}"
                for pattern_index in range(4):
                    pattern_name = f"{family}_pattern_{pattern_index}"
                    if (
                        matrix_schema == SLOW_PARTIAL_SCHEMA
                        and admit_slow_partial
                        and family_index == 1
                    ):
                        route = "slow_partial_resource_fallback"
                    elif matrix_schema != GENERAL_SCHEMA and family_index == 0:
                        route = "prepared_runtime_assertion"
                    elif matrix_schema != GENERAL_SCHEMA:
                        route = "direct_resource_fallback"
                    elif family_index == 0:
                        route = "direct_context_dfa"
                    else:
                        route = "direct_dfa"
                    engine, reason = ROUTE_METADATA[route]
                    contracts = (
                        (
                            ("span", "find"),
                            ("exists", "is_match"),
                            ("selected_end", "find_end"),
                        )
                        if output_matrix
                        else (
                            ("span", "find"),
                        )
                        if pattern_index % 2 == 0
                        else (("exists", "is_match"),)
                    )
                    for output_kind, operation in contracts:
                        for window in windows:
                            for position in positions:
                                for density in densities:
                                    case = (
                                        f"{pattern_name}_{seed}_{output_kind}_"
                                        f"{window}_{position}_{density}"
                                    )
                                    values = {
                                        "comparison": "comparison",
                                        "case": case,
                                        "pattern_name": pattern_name,
                                        "family": family,
                                        "seed": seed,
                                        "source_kind": source_kind,
                                        "pattern": "synthetic",
                                        "output": output_kind,
                                        "upstream_operation": operation,
                                        "native_route": route,
                                        "engine": engine,
                                        "selection_reason": reason,
                                        "target": "synthetic-host",
                                        "feature_bits": "0x1",
                                        "start_accelerator": "scalar",
                                        "aarch64_sve_code_profile": "not_aarch64",
                                        "prefix_graph_bytes": "1",
                                        "prefix_selective_positions": "1",
                                        "prefix_filter_bytes": "1",
                                        "window_bytes": str(window),
                                        "match_position": position,
                                        "candidate_density": density,
                                        "rotations": "4",
                                        "initial_searches": "1",
                                        "min_trial_ns": "1",
                                        "trials": "3",
                                        "warmup_rounds": "1",
                                        "upstream_searches_per_trial": "1",
                                        "upstream_min_elapsed_ns": "3.0",
                                        "upstream_median_elapsed_ns": "3.0",
                                        "upstream_min_ns_per_search": "3.0",
                                        "upstream_median_ns_per_search": "3.0",
                                        "native_searches_per_trial": "1",
                                        "native_min_elapsed_ns": "2.0",
                                        "native_median_elapsed_ns": "2.0",
                                        "native_min_ns_per_search": "2.0",
                                        "native_median_ns_per_search": "2.0",
                                        "speedup_at_min": "1.5",
                                        "speedup_at_median": "1.5",
                                        "upstream_checksum": "1",
                                        "native_checksum": "1",
                                        "status": "ok",
                                    }
                                    is_final_row = (
                                        family_index == family_count - 1
                                        and pattern_index == 3
                                        and (output_kind, operation) == contracts[-1]
                                        and window == windows[-1]
                                        and position == positions[-1]
                                        and density == densities[-1]
                                    )
                                    if not (omit_final_row and is_final_row):
                                        output.write(
                                            "\t".join(values[column] for column in header) + "\n"
                                        )
        return path

    with tempfile.TemporaryDirectory(prefix="fre-generated-score-self-test-") as temporary:
        directory = Path(temporary)
        paths = [
            synthetic_file(directory, generator, seed, order)
            for generator in ("flat", "nested")
            for seed in ("0x0000000000000001", "0x0000000000000002")
            for order in sorted(ORDERS)
        ]
        parsed = [parse_result(path) for path in paths]
        paired = validate_and_pair(parsed, expected_targets={"synthetic-host"})
        assert len(paired) == 3 * 2 * (648 + 2_304)
        with contextlib.redirect_stdout(io.StringIO()):
            assert report(paired, minimum_speedup=1.49)

        try:
            validate_and_pair(parsed[:-1], expected_targets={"synthetic-host"})
        except ValidationError as error:
            assert "orders" in str(error)
        else:
            raise AssertionError("a matrix missing one measurement order passed")

        incomplete_path = synthetic_file(
            directory,
            "flat",
            "0x0000000000000003",
            "upstream-native",
            omit_final_row=True,
        )
        try:
            parse_result(incomplete_path)
        except ValidationError as error:
            assert "rows; expected" in str(error)
        else:
            raise AssertionError("a matrix missing one comparison row passed")

        missing_slow_admission = synthetic_file(
            directory,
            "flat",
            "0x0000000000000004",
            "upstream-native",
            matrix_schema=SLOW_PARTIAL_SCHEMA,
            admit_slow_partial=False,
        )
        try:
            parse_result(missing_slow_admission, matrix_schema=SLOW_PARTIAL_SCHEMA)
        except ValidationError as error:
            assert "admitted no source" in str(error)
        else:
            raise AssertionError("slow-partial schema without an admitted source passed")

        for forced_schema in (
            RESOURCE_FALLBACK_SCHEMA,
            RETAINED_FALLBACK_SCHEMA,
            SLOW_PARTIAL_SCHEMA,
        ):
            schema_paths = [
                synthetic_file(
                    directory,
                    generator,
                    seed,
                    order,
                    matrix_schema=forced_schema,
                )
                for generator in ("flat", "nested")
                for seed in ("0x0000000000000001", "0x0000000000000002")
                for order in sorted(ORDERS)
            ]
            try:
                parse_result(schema_paths[0], matrix_schema=GENERAL_SCHEMA)
            except ValidationError as error:
                assert "requires force_" in str(error)
            else:
                raise AssertionError(f"{forced_schema} passed the general schema")
            schema_parsed = [
                parse_result(path, matrix_schema=forced_schema)
                for path in schema_paths
            ]
            schema_paired = validate_and_pair(
                schema_parsed,
                expected_targets={"synthetic-host"},
            )
            with contextlib.redirect_stdout(io.StringIO()):
                assert report(
                    schema_paired,
                    minimum_speedup=1.5,
                    minimum_direct_coverage=0.0,
                    score_routes=ALL_COMPILED_ROUTES,
                )

        legacy_paths = [
            synthetic_file(
                directory,
                generator,
                seed,
                order,
                output_matrix=False,
            )
            for generator in ("flat", "nested")
            for seed in ("0x0000000000000001", "0x0000000000000002")
            for order in sorted(ORDERS)
        ]
        legacy = [parse_result(path) for path in legacy_paths]
        try:
            validate_and_pair(legacy, expected_targets={"synthetic-host"})
        except ValidationError as error:
            assert "requires --output-matrix" in str(error)
        else:
            raise AssertionError("legacy assigned-output files passed strict final validation")
        legacy_paired = validate_and_pair(
            legacy,
            expected_targets={"synthetic-host"},
            require_output_matrix=False,
        )
        assert len(legacy_paired) == 2 * (648 + 2_304)
    print("self-test: ok")


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", nargs="*", type=Path, help="benchmark stdout TSV files")
    parser.add_argument("--minimum-speedup", type=float, default=1.5)
    parser.add_argument(
        "--minimum-direct-coverage",
        type=float,
        default=None,
        help=(
            "minimum all-contract direct pattern coverage; defaults to 1 for "
            "--score-scope=direct and 0 for broader scopes"
        ),
    )
    parser.add_argument(
        "--score-scope",
        choices=tuple(SCORE_SCOPES),
        default=None,
        help=(
            "routes included in performance acceptance; general-v1 defaults to "
            "direct, while forced schemas require their complete unfiltered scope"
        ),
    )
    parser.add_argument(
        "--matrix-schema",
        choices=tuple(MATRIX_SCHEMAS),
        default=GENERAL_SCHEMA,
        help="preregistered complete-matrix environment schema",
    )
    parser.add_argument(
        "--additive-profile",
        choices=tuple(sorted(ADDITIVE_PROFILE_NAMES)),
        default=None,
        help=(
            "one preregistered additive profile required in addition to all "
            "ASIMD/AVX2 base profiles; validate distinct additive profiles in "
            "separate scorer invocations"
        ),
    )
    parser.add_argument(
        "--expected-targets",
        default=",".join(sorted(DEFAULT_TARGETS)),
        help="comma-separated target receipts required for acceptance",
    )
    parser.add_argument(
        "--allow-assigned-output",
        action="store_true",
        help="accept legacy single-assigned-contract files for diagnostics only",
    )
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args(argv)
    if arguments.self_test:
        self_test()
        return 0
    if not arguments.results:
        parser.error("at least one result TSV is required")
    expected_targets = {target for target in arguments.expected_targets.split(",") if target}
    if expected_targets != DEFAULT_TARGETS:
        parser.error(
            "qualification always requires the macOS/Linux ASIMD and Linux AVX2 base targets"
        )
    expected_profile_names = set(BASE_PROFILE_NAMES)
    if arguments.additive_profile is not None:
        expected_profile_names.add(arguments.additive_profile)
    schema = MATRIX_SCHEMAS[arguments.matrix_schema]
    required_scope = schema["score_scope"]
    if required_scope is None:
        score_scope = arguments.score_scope or "direct"
        if score_scope in {
            RESOURCE_FALLBACK_COMPLETE_SCOPE,
            RETAINED_FALLBACK_COMPLETE_SCOPE,
            SLOW_PARTIAL_COMPLETE_SCOPE,
        }:
            parser.error("a forced complete score scope requires its matching matrix schema")
    else:
        score_scope = arguments.score_scope or required_scope
        if score_scope != required_scope:
            parser.error(
                f"{arguments.matrix_schema} requires --score-scope={required_scope}; "
                "post-result route scopes are not permitted"
            )
        if arguments.allow_assigned_output:
            parser.error("forced complete schemas require the full three-contract output matrix")
    minimum_direct_coverage = arguments.minimum_direct_coverage
    if minimum_direct_coverage is None:
        minimum_direct_coverage = 1.0 if score_scope == "direct" else 0.0
    if (
        arguments.minimum_speedup < 1.5
        or not 0.0 <= minimum_direct_coverage <= 1.0
        or not expected_targets
    ):
        parser.error(
            "minimum speedup must be at least 1.5, direct coverage must be in [0,1], "
            "and expected targets must be non-empty"
        )
    try:
        files = [
            parse_result(path, matrix_schema=arguments.matrix_schema)
            for path in arguments.results
        ]
        cells = validate_and_pair(
            files,
            expected_targets,
            require_output_matrix=not arguments.allow_assigned_output,
            expected_profile_names=expected_profile_names,
        )
        return (
            0
            if report(
                cells,
                arguments.minimum_speedup,
                minimum_direct_coverage,
                SCORE_SCOPES[score_scope],
            )
            else 1
        )
    except (OSError, ValidationError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
