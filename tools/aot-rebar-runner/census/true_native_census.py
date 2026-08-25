#!/usr/bin/env python3
"""Plan, qualify, and summarize a public-Rebar true-native AOT census.

This controller deliberately does no timing.  Its unit of accountability is a
canonical public Rust/Rebar job (`fre_job_id`), while it also seals every raw
schedule point ID so comparator/boundary replication cannot change the
denominator silently.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from enum import Enum
from typing import NamedTuple, Optional


PLAN_SCHEMA = "fre.aot-rebar.true-native-plan.v2"
RECEIPT_SCHEMA = "fre.aot-rebar.true-native-job-receipt.v2"
SUMMARY_SCHEMA = "fre.aot-rebar.true-native-summary.v2"
TRAP_MARKER_SCHEMA = "fre.aot-rebar.runtime-trap.v1"
SCHEDULE_SCHEMA = "fre.full-rebar.campaign.v1"
EXPECTED_PUBLIC_JOBS = 344
EXPECTED_RUNTIME_JOBS = 311
EXPECTED_COMPILE_JOBS = 33
FROZEN_COMPARATOR_PREFERENCE = (
    "re2-2025-11-05",
    "rust-regex-1.12.4",
)
PUBLIC_MANIFEST_SCHEMA = "fre.public-rebar-klv-inventory.v1"
PUBLIC_KLV_KEYS = {
    "name",
    "model",
    "pattern",
    "case-insensitive",
    "unicode",
    "haystack",
    "max-iters",
    "max-warmup-iters",
    "max-time",
    "max-warmup-time",
}
PUBLIC_REBAR_MODELS = {
    "compile", "count", "count-spans", "count-captures", "grep",
    "grep-captures", "regex-redux",
}
MAX_NATIVE_ROW_COMPONENTS = 4_096
MAX_PUBLIC_KLV_BYTES = 64 * 1024 * 1024
MAX_NATIVE_ROW_OBJECT_BYTES = 256 * 1024 * 1024
MAX_WEIGHTED_CAPTURE_REDUCER_OBJECT_BYTES = 16 * 1024 * 1024
MAX_SERIALIZED_PROGRAM_BYTES = 256 * 1024 * 1024
PREPARED_V15_MAX_HANDLE_BYTES = 8 * 1024 * 1024
PREPARED_V15_MAX_SCRATCH_BYTES = 8 * 1024 * 1024
PREPARED_V15_MAX_SETUP_WORK = 2_000_000
PREPARED_V15_CAPABILITY = 1
PREPARED_V2_CONFIG_VERSION = 2
PREPARED_V15_CONFIG_VERSION = 3
SPAN_SEARCH_ENTRY_ABI = "SpanSearchV1"
PREPARED_SPAN_SEARCH_ENTRY_ABI = "PreparedSpanSearchV1"
EXISTS_SEARCH_ENTRY_ABI = "ExistsSearchV1"
PREPARED_SCALAR_REDUCE_ENTRY_ABI = "PreparedScalarReduceV1"
NO_PREPARED_SURFACE = "None"
PREPARED_V15_COMPATIBILITY_SURFACE = "Compatibility"
PREPARED_V15_ROW_SEARCH_SURFACE = "RowSearchOnly"
PREPARED_V15_SPAN_OPERATION_FLAGS = 1 << 1
PREPARED_V15_SPAN_SUM_OPERATION_FLAGS = 1 << 2
ORDERED_MANY_RECEIPT_VERSION = 1
PREPARED_V15_RUNTIME_SYMBOLS = (
    "fre_aot_regex_runtime_fill_spans_exclusive_v1",
    "fre_aot_regex_runtime_search_exclusive_v1",
    "fre_aot_regex_runtime_search_v1",
)
PREPARED_V15_SCALAR_GREP_RUNTIME_SYMBOLS = PREPARED_V15_RUNTIME_SYMBOLS
PREPARED_V15_SHARED_COUNT_RUNTIME_SYMBOLS = tuple(sorted((
    *PREPARED_V15_RUNTIME_SYMBOLS,
    "fre_aot_regex_runtime_compiler_private_count_exclusive_v1",
)))
PREPARED_V15_SHARED_SPAN_SUM_RUNTIME_SYMBOLS = tuple(sorted((
    *PREPARED_V15_RUNTIME_SYMBOLS,
    "fre_aot_regex_runtime_compiler_private_span_sum_exclusive_v1",
)))
FEATURE_BITS = {
    "sse2": 1 << 0,
    "avx2": 1 << 1,
    "avx512f": 1 << 2,
    "avx512bw": 1 << 3,
    "avx512vl": 1 << 4,
    "asimd": 1 << 32,
    "sve": 1 << 33,
    "sve2": 1 << 34,
}
TRAP_EXIT = 197
SCALAR_ADAPTER_MODELS = {"count", "count-spans", "grep"}
UNIFORM_CAPTURE_ADAPTER_MODELS = {"count-captures", "grep-captures"}
COMPOSITE_ADAPTER_MODELS = {"regex-redux"}
NATIVE_ROW_COMPOSITE_KINDS = {
    "native-row-bridge-v1", "native-row-scalar-reducer-v1",
    "native-multi-grep-reducer-v1",
    "uniform-capture-row-bridge-v1",
    "mixed-prepared-native-row-bridge-v15",
    "strict-capture-next-v1", "exact-span-participation-v1",
    "selector-negative-certificate-v1",
}
FORBIDDEN_PUBLIC_COMPONENTS = {
    "holdout",
    "private-query",
    "private-queries",
    "query-history",
    "codex-history",
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
SYMBOL = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
NATIVE_SEARCH_ENTRY_SYMBOL = re.compile(r"^fre_aot_regex_search_v1_[0-9a-f]{64}$")
NATIVE_SEARCH_EXCLUSIVE_ENTRY_SYMBOL = re.compile(
    r"^fre_aot_regex_search_exclusive_v1_[0-9a-f]{64}$"
)
NATIVE_COUNT_ENTRY_SYMBOL = re.compile(
    r"^fre_aot_regex_count_exclusive_v1_[0-9a-f]{64}$"
)
NATIVE_SPAN_SUM_ENTRY_SYMBOL = re.compile(
    r"^fre_aot_regex_span_sum_exclusive_v1_[0-9a-f]{64}$"
)
NATIVE_SPAN_FILL_ENTRY_SYMBOL = re.compile(
    r"^fre_aot_regex_fill_spans_exclusive_v1_[0-9a-f]{64}$"
)
NATIVE_RUNTIME_PROGRAM_SYMBOL = re.compile(
    r"^fre_aot_regex_runtime_program_v1_[0-9a-f]{64}$"
)
NATIVE_GREP_COUNT_ENTRY_SYMBOL = re.compile(
    r"^fre_aot_regex_grep_count_exclusive_v1_[0-9a-f]{64}$"
)
NATIVE_MULTI_GREP_REDUCER_SYMBOL = re.compile(
    r"^fre_aot_regex_rebar_multi_grep_v1_[0-9a-f]{64}$"
)
NATIVE_MIXED_MULTI_GREP_REDUCER_SYMBOL = re.compile(
    r"^fre_aot_regex_rebar_mixed_multi_grep_v1_[0-9a-f]{64}$"
)
NATIVE_ROW_SCALAR_REDUCER_SYMBOL = re.compile(
    r"^fre_aot_regex_rebar_row_scalar_v1_[0-9a-f]{64}$"
)
NATIVE_MIXED_ROW_SCALAR_REDUCER_SYMBOL = re.compile(
    r"^fre_aot_regex_rebar_mixed_row_scalar_v1_[0-9a-f]{64}$"
)
NATIVE_COUNT_CAPTURES_ENTRY_SYMBOL = re.compile(
    r"^fre_aot_regex_count_captures_exclusive_v1_[0-9a-f]{64}$"
)
NATIVE_GREP_CAPTURES_ENTRY_SYMBOL = re.compile(
    r"^fre_aot_regex_grep_captures_exclusive_v1_[0-9a-f]{64}$"
)
NATIVE_SINGLE_CAPTURE_COUNT_REDUCER_SYMBOL = re.compile(
    r"^fre_aot_regex_count_captures_v1_[0-9a-f]{64}$"
)
NATIVE_SINGLE_CAPTURE_GREP_REDUCER_SYMBOL = re.compile(
    r"^fre_aot_regex_grep_captures_v1_[0-9a-f]{64}$"
)
NATIVE_SINGLE_CAPTURE_COUNT_SCRATCH_REDUCER_SYMBOL = re.compile(
    r"^fre_aot_regex_count_captures_scratch_v1_[0-9a-f]{64}$"
)
NATIVE_SINGLE_CAPTURE_GREP_SCRATCH_REDUCER_SYMBOL = re.compile(
    r"^fre_aot_regex_grep_captures_scratch_v1_[0-9a-f]{64}$"
)
NATIVE_WEIGHTED_CAPTURE_COUNT_REDUCER_SYMBOL = re.compile(
    r"^fre_aot_regex_weighted_count_captures_v1_[0-9a-f]{64}$"
)
NATIVE_WEIGHTED_CAPTURE_GREP_REDUCER_SYMBOL = re.compile(
    r"^fre_aot_regex_weighted_grep_captures_v1_[0-9a-f]{64}$"
)
NATIVE_CAPTURE_NEXT_ENTRY_SYMBOL = re.compile(
    r"^fre_aot_regex_capture_next_v1_[0-9a-f]{64}$"
)
NATIVE_CAPTURE_MATERIALIZE_SYMBOL = re.compile(
    r"^fre_aot_regex_capture_materialize_v1_[0-9a-f]{64}$"
)
NATIVE_PARTICIPATION_ENTRY_SYMBOL = re.compile(
    r"^fre_aot_regex_participation_exact_v1_[0-9a-f]{64}$"
)
NATIVE_REGEX_REDUX_ENTRY_SYMBOL = re.compile(
    r"^fre_aot_regex_rebar_regex_redux_v1_[0-9a-f]{64}$"
)
NATIVE_PARTICIPATION_BUNDLE_SYMBOL = re.compile(
    r"^fre_aot_regex_participation_bundle_v1_[0-9a-f]{64}$"
)
NATIVE_PARTICIPATION_ALGORITHM_ID = (
    "fre-aot-regex.exact-span-participation-dfa.v1"
)
NATIVE_PARTICIPATION_ORDERED_NFA_ALGORITHM_ID = (
    "fre-aot-regex.exact-span-participation-ordered-nfa.v1"
)
NATIVE_PARTICIPATION_SCRATCH_BYTES = 16
NATIVE_PARTICIPATION_HEADER_BYTES = 256
NATIVE_PARTICIPATION_ORDERED_NFA_METADATA_BYTES = 112
NATIVE_PARTICIPATION_ORDERED_NFA_STATE_BYTES = 16
NATIVE_PARTICIPATION_ORDERED_NFA_RANGE_BYTES = 2
NATIVE_PARTICIPATION_ORDERED_NFA_THREAD_BYTES = 24
NATIVE_PARTICIPATION_ORDERED_NFA_SEEN_BYTES = 4
NATIVE_PARTICIPATION_MAX_ORDERED_NFA_SCRATCH_BYTES = 8 * 1_048_576
NATIVE_CAPTURE_ITERATOR_STATE_BYTES = 24
NATIVE_CAPTURE_RESULT_SLOT_BYTES = 16
NATIVE_CAPTURE_MAX_GROUPS = 16
NATIVE_PARTICIPATION_MAX_ASSERTIONS = 64
NATIVE_PARTICIPATION_MAX_ASSERTION_SIGNATURES = 256
NATIVE_PARTICIPATION_MAX_BYTE_CLASSES = 256
NATIVE_PARTICIPATION_MAX_DFA_STATES = 131_072
NATIVE_PARTICIPATION_MAX_TRANSITION_CELLS = 16 * 1_024 * 1_024
NATIVE_PARTICIPATION_MAX_BUILD_WORK = 256 * 1_048_576
NATIVE_PARTICIPATION_MAX_PLAN_BYTES = 256 * 1_048_576
SELECTOR_CAPTURE_POSITIVE_FALLBACK_SYMBOL = (
    "fre_aot_rebar_runner_stock_capture_positive_fallback_v1"
)
SELECTOR_CAPTURE_POSITIVE_FALLBACK_PROFILE = "rust-regex-1.12.4-captures"
SELECTOR_CAPTURE_ENGINE = "IndependentNativeSpanRows(OrderedContextDfa)"
SELECTOR_CAPTURE_DFA_STATES_LIMIT = 131_072
SELECTOR_CAPTURE_BUILD_WORK_LIMIT = 256 * 1_048_576
CONTROL_PLANE_PREFIXES = (
    "fre_aot_regex_runtime_prepare_",
    "fre_aot_regex_runtime_destroy_",
)
RUNTIME_PREFIX = "fre_aot_regex_runtime_"
DEFINED_TEXT_SYMBOL_TYPES = {"T", "t", "W"}
DEFINED_DATA_SYMBOL_TYPES = {"B", "b", "D", "d", "R", "r", "S", "s"}
RUNTIME_REFERENCE_SYMBOL_TYPES = DEFINED_TEXT_SYMBOL_TYPES | {"U", "u", "w"}
TRAP_PATCHES = {"x86_64": "0f0b", "aarch64": "000020d4"}


class CensusError(RuntimeError):
    """A fail-closed census validation error."""


class OperationBoundary(Enum):
    """Closed distinction between strict native work and integration glue."""

    WHOLE_OPERATION = "whole-operation"
    RUST_ADAPTER_LOOP = "rust-adapter-loop"
    SEMANTIC_HELPER_BACKED = "semantic-helper-backed"


class OperationRoutePolicy(NamedTuple):
    boundary: OperationBoundary
    success_reason: str


OPERATION_ROUTE_POLICIES = {
    "linked-reducer": OperationRoutePolicy(
        OperationBoundary.WHOLE_OPERATION,
        "whole-operation-native-authenticated",
    ),
    "linked-span-sum-reducer": OperationRoutePolicy(
        OperationBoundary.WHOLE_OPERATION,
        "whole-operation-native-authenticated",
    ),
    "linked-native-weighted-capture-reducer": OperationRoutePolicy(
        OperationBoundary.WHOLE_OPERATION,
        "whole-operation-native-authenticated",
    ),
    "linked-native-count-helper-backed-reducer": OperationRoutePolicy(
        OperationBoundary.SEMANTIC_HELPER_BACKED,
        "single-call-native-reducer-retains-semantic-runtime-helpers",
    ),
    "linked-native-span-sum-helper-backed-reducer": OperationRoutePolicy(
        OperationBoundary.SEMANTIC_HELPER_BACKED,
        "single-call-native-reducer-retains-semantic-runtime-helpers",
    ),
    "linked-native-grep-count-reducer": OperationRoutePolicy(
        OperationBoundary.WHOLE_OPERATION,
        "whole-operation-native-authenticated",
    ),
    "linked-native-uniform-capture-reducer": OperationRoutePolicy(
        OperationBoundary.WHOLE_OPERATION,
        "whole-operation-native-authenticated",
    ),
    "linked-native-single-capture-reducer": OperationRoutePolicy(
        OperationBoundary.WHOLE_OPERATION,
        "whole-operation-native-authenticated",
    ),
    "linked-native-uniform-capture-helper-backed-reducer": OperationRoutePolicy(
        OperationBoundary.SEMANTIC_HELPER_BACKED,
        "single-call-native-reducer-retains-semantic-runtime-helpers",
    ),
    "linked-span-fill": OperationRoutePolicy(
        OperationBoundary.RUST_ADAPTER_LOOP,
        "native-span-fill-core-with-checked-rust-reduction-adapter-loop",
    ),
    "linked-direct-entry-adapter-loop": OperationRoutePolicy(
        OperationBoundary.RUST_ADAPTER_LOOP,
        "native-search-core-with-adapter-outer-loop",
    ),
    "linked-prepared-span-fill-grep-adapter-loop": OperationRoutePolicy(
        OperationBoundary.RUST_ADAPTER_LOOP,
        "native-prepared-span-fill-core-with-per-line-adapter-loop",
    ),
    "linked-native-regex-redux-reducer": OperationRoutePolicy(
        OperationBoundary.WHOLE_OPERATION,
        "whole-operation-native-authenticated",
    ),
    "linked-native-row-adapter-loop": OperationRoutePolicy(
        OperationBoundary.RUST_ADAPTER_LOOP,
        "native-search-core-with-adapter-outer-loop",
    ),
    "linked-native-multi-grep-reducer": OperationRoutePolicy(
        OperationBoundary.WHOLE_OPERATION,
        "whole-operation-native-authenticated",
    ),
    "linked-native-mixed-multi-grep-reducer": OperationRoutePolicy(
        OperationBoundary.SEMANTIC_HELPER_BACKED,
        "single-call-native-reducer-retains-semantic-runtime-helpers",
    ),
    "linked-native-strict-mixed-multi-grep-reducer": OperationRoutePolicy(
        OperationBoundary.WHOLE_OPERATION,
        "whole-operation-native-authenticated",
    ),
    "linked-native-row-scalar-reducer": OperationRoutePolicy(
        OperationBoundary.WHOLE_OPERATION,
        "whole-operation-native-authenticated",
    ),
    "linked-native-row-scalar-helper-backed-reducer": OperationRoutePolicy(
        OperationBoundary.SEMANTIC_HELPER_BACKED,
        "single-call-native-reducer-retains-semantic-runtime-helpers",
    ),
    "linked-native-strict-mixed-row-scalar-reducer": OperationRoutePolicy(
        OperationBoundary.WHOLE_OPERATION,
        "whole-operation-native-authenticated",
    ),
    "linked-uniform-capture-row-adapter-loop": OperationRoutePolicy(
        OperationBoundary.RUST_ADAPTER_LOOP,
        "native-search-core-with-static-uniform-capture-adapter-loop",
    ),
    "linked-exact-span-participation-adapter-loop": OperationRoutePolicy(
        OperationBoundary.RUST_ADAPTER_LOOP,
        "native-search-capture-core-with-exact-span-replay-adapter-loop",
    ),
    "linked-strict-capture-next-adapter-loop": OperationRoutePolicy(
        OperationBoundary.RUST_ADAPTER_LOOP,
        "native-search-capture-core-with-checked-rust-adapter-loop",
    ),
    "linked-selector-negative-certificate-adapter-loop": OperationRoutePolicy(
        OperationBoundary.RUST_ADAPTER_LOOP,
        "native-negative-certificate-with-unused-stock-capture-fallback",
    ),
    "linked-shared-ordered-many-helper-backed-reducer": OperationRoutePolicy(
        OperationBoundary.SEMANTIC_HELPER_BACKED,
        "single-call-native-reducer-retains-semantic-runtime-helpers",
    ),
    "linked-shared-ordered-many-helper-free-reducer": OperationRoutePolicy(
        OperationBoundary.WHOLE_OPERATION,
        "whole-operation-native-authenticated",
    ),
}
NATIVE_SPAN_SUM_ITERATION_STRATEGY = "linked-native-span-sum-reducer"


def has_exact_adapter(model: str, pattern_count: int) -> bool:
    """Return whether the integrated runner has a typed adapter for this shape."""
    return (
        model in {"count", "count-spans", "grep"}
        and 1 <= pattern_count <= MAX_NATIVE_ROW_COMPONENTS
    ) or (
        model in UNIFORM_CAPTURE_ADAPTER_MODELS
        and 1 <= pattern_count <= MAX_NATIVE_ROW_COMPONENTS
    ) or (
        model in COMPOSITE_ADAPTER_MODELS and pattern_count == 0
    )


def exact_adapter_reason(model: str, pattern_count: int) -> str:
    exact_adapter = has_exact_adapter(model, pattern_count)
    if exact_adapter and model in {"count", "count-spans", "grep"} and pattern_count > 1:
        return "exact-native-row-composite-adapter"
    if exact_adapter and model in UNIFORM_CAPTURE_ADAPTER_MODELS:
        return "exact-uniform-capture-native-row-composite-adapter"
    if exact_adapter and model in SCALAR_ADAPTER_MODELS:
        return "exact-single-pattern-scalar-adapter"
    if exact_adapter:
        return "exact-fixed-composite-adapter"
    if model == "compile":
        return "compile-job-outside-runtime-denominator"
    return "unsupported-runtime-model-or-cardinality"


def canonical_feature_bits(target: str, features: str) -> str:
    if features in {"", "none"}:
        names: list[str] = []
    else:
        names = features.split(",")
        if any(not name for name in names) or len(names) != len(set(names)):
            raise CensusError("target feature list is empty or duplicated")
        canonical_names = [name for name in FEATURE_BITS if name in names]
        if names != canonical_names:
            raise CensusError("target feature list is unknown or not in canonical order")
    if target.startswith("x86_64-") and any(name.startswith(("asimd", "sve")) for name in names):
        raise CensusError("AArch64 feature is bound to an x86-64 target")
    if target.startswith("aarch64-") and any(name.startswith(("sse", "avx")) for name in names):
        raise CensusError("x86 feature is bound to an AArch64 target")
    if not target.startswith(("x86_64-", "aarch64-")):
        raise CensusError("census target has an unsupported architecture")
    bits = 0
    for name in names:
        bits |= FEATURE_BITS[name]
    return f"{bits:016x}"


def target_architecture(target: str) -> str:
    if target.startswith("x86_64-"):
        return "x86_64"
    if target.startswith("aarch64-"):
        return "aarch64"
    raise CensusError("census target has an unsupported architecture")


def participation_export_identity(
    bundle_sha256: str,
    target: str,
    feature_bits: str,
    selector_object_sha256: str,
    selector_symbol: str,
) -> str:
    """Recompute the compiler's frozen native-participation export identity."""
    architecture = target_architecture(target)
    architecture_byte = {"x86_64": 1, "aarch64": 2}[architecture]
    if target.endswith("-linux"):
        os_byte = 1
    elif target.endswith("-macos"):
        os_byte = 2
    else:
        raise CensusError("participation target has an unsupported operating system")
    abi_byte = {"x86_64": 1, "aarch64": 2}[architecture]
    if re.fullmatch(r"[0-9a-f]{16}", feature_bits) is None:
        raise CensusError("participation feature bits are not canonical")
    require_hex64(bundle_sha256, "participation bundle digest")
    require_hex64(selector_object_sha256, "participation selector object digest")
    if SYMBOL.fullmatch(selector_symbol) is None:
        raise CensusError("participation selector symbol is not canonical")
    digest = hashlib.sha256()
    digest.update(b"fre-aot-regex/native-participation-aot-v1\0")
    digest.update(bytes.fromhex(bundle_sha256))
    digest.update(bytes((architecture_byte, os_byte, abi_byte)))
    digest.update(int(feature_bits, 16).to_bytes(8, "little"))
    digest.update(bytes.fromhex(selector_object_sha256))
    selector_bytes = selector_symbol.encode("ascii", "strict")
    digest.update(len(selector_bytes).to_bytes(8, "little"))
    digest.update(selector_bytes)
    return digest.hexdigest()


def participation_plan_bytes(
    assertions: int,
    signatures: int,
    states: int,
    transition_cells: int,
) -> int:
    """Recompute the selected v1 bundle extent from its closed geometry."""
    signatures_offset = (NATIVE_PARTICIPATION_HEADER_BYTES + assertions * 2 + 7) & ~7
    byte_classes_offset = signatures_offset + signatures * 8
    boundary_map_offset = byte_classes_offset + 256
    start_states_offset = (boundary_map_offset + 4 + 7) & ~7
    transitions_offset = start_states_offset + signatures * 4
    accept_counts_offset = transitions_offset + transition_cells * 4
    return accept_counts_offset + states


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: pathlib.Path) -> object:
    with path.open("rb") as source:
        return json.load(source)


def add_digest(record: dict[str, object], field: str) -> dict[str, object]:
    if field in record:
        raise CensusError(f"digest field {field!r} is already present")
    result = dict(record)
    result[field] = sha_bytes(canonical(record).encode())
    return result


def validate_digest(record: dict[str, object], field: str, context: str) -> None:
    unsigned = dict(record)
    claimed = unsigned.pop(field, None)
    actual = sha_bytes(canonical(unsigned).encode())
    if claimed != actual:
        raise CensusError(f"{context} digest mismatch: {claimed!r} != {actual}")


def require_exact_keys(record: dict[str, object], expected: set[str], context: str) -> None:
    actual = set(record)
    if actual != expected:
        raise CensusError(
            f"{context} schema keys differ: missing={sorted(expected - actual)!r}, "
            f"extra={sorted(actual - expected)!r}"
        )


def write_exclusive(path: pathlib.Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    try:
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def require_hex64(value: object, context: str) -> str:
    if not isinstance(value, str) or HEX64.fullmatch(value) is None:
        raise CensusError(f"{context} is not a lowercase SHA-256 digest")
    return value


def require_nonzero_hex64(value: object, context: str) -> str:
    digest = require_hex64(value, context)
    if digest == "0" * 64:
        raise CensusError(f"{context} is the zero SHA-256 digest")
    return digest


def require_git_hash(value: object, context: str) -> str:
    if not isinstance(value, str) or HEX40.fullmatch(value) is None:
        raise CensusError(f"{context} is not a lowercase Git object ID")
    return value


def id_set(values: list[str]) -> dict[str, object]:
    ordered = sorted(set(values))
    if len(ordered) != len(values):
        raise CensusError("ID set contains duplicates")
    return {
        "count": len(ordered),
        "ids": ordered,
        "ids_sha256": sha_bytes(canonical(ordered).encode()),
    }


def forbidden_path_components(parts: tuple[str, ...]) -> list[str]:
    return sorted({
        part for part in parts
        if any(token in part.casefold() for token in FORBIDDEN_PUBLIC_COMPONENTS)
    })


def relative_public_path(
    root: pathlib.Path,
    raw: object,
    context: str,
    recorded_root: Optional[str] = None,
) -> tuple[str, pathlib.Path]:
    if not isinstance(raw, str):
        raise CensusError(f"{context} path is not text")
    root = root.resolve(strict=True)
    root_forbidden = forbidden_path_components(root.parts)
    if root_forbidden:
        raise CensusError(f"declared public root has forbidden components {root_forbidden!r}")
    path = pathlib.Path(raw)
    if path.is_absolute() and recorded_root is not None:
        try:
            recorded_relative = pathlib.PurePosixPath(raw).relative_to(
                pathlib.PurePosixPath(recorded_root)
            )
        except ValueError:
            pass
        else:
            path = root.joinpath(*recorded_relative.parts)
    path = path.resolve(strict=True) if path.is_absolute() else (root / path).resolve(strict=True)
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise CensusError(f"{context} escapes declared public root") from error
    forbidden = forbidden_path_components(relative.parts)
    if forbidden:
        raise CensusError(f"{context} enters forbidden corpus component {sorted(forbidden)!r}")
    if not path.is_file():
        raise CensusError(f"{context} is not a regular file")
    return relative.as_posix(), path


def git_output(
    source: pathlib.Path, *arguments: str, git_executable: str = "git"
) -> str:
    environment = {
        name: os.environ[name]
        for name in ("PATH", "HOME", "TMPDIR", "SYSTEMROOT")
        if name in os.environ
    }
    environment.update({
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    })
    if "/" in git_executable or (
        os.altsep is not None and os.altsep in git_executable
    ):
        git_path = pathlib.Path(git_executable).resolve(strict=True)
    else:
        found = shutil.which(git_executable, path=environment.get("PATH"))
        if found is None:
            raise CensusError("git executable is unavailable")
        git_path = pathlib.Path(found).resolve(strict=True)
    if not git_path.is_file() or not os.access(git_path, os.X_OK):
        raise CensusError("git executable is not a regular executable file")
    completed = subprocess.run(
        [
            str(git_path), "-c", "core.fsmonitor=false",
            "-c", "core.untrackedCache=false", "-C", str(source), *arguments,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        raise CensusError(f"git {' '.join(arguments)} failed")
    return completed.stdout.decode("utf-8", "strict").strip()


def source_identity(
    source: pathlib.Path, commit: str, tree: str, git_executable: str = "git"
) -> dict[str, object]:
    source = source.resolve(strict=True)
    actual_commit = git_output(
        source, "rev-parse", "HEAD", git_executable=git_executable
    )
    actual_tree = git_output(
        source, "rev-parse", "HEAD^{tree}", git_executable=git_executable
    )
    if actual_commit != commit or actual_tree != tree:
        raise CensusError("candidate source is not the declared commit/tree")
    if git_output(
        source, "status", "--porcelain", "--untracked-files=all",
        git_executable=git_executable,
    ):
        raise CensusError("candidate source worktree is not clean")
    lock = source / "Cargo.lock"
    if not lock.is_file():
        raise CensusError("candidate source has no Cargo.lock")
    return {
        "commit": commit,
        "tree": tree,
        "cargo_lock_sha256": sha_file(lock),
    }


def external_schedule(path: pathlib.Path, expected_sha256: str) -> dict[str, object]:
    forbidden = forbidden_path_components(path.resolve(strict=True).parts)
    if forbidden:
        raise CensusError(f"public schedule path has forbidden components {forbidden!r}")
    expected_sha256 = require_hex64(expected_sha256, "expected schedule SHA-256")
    actual_sha256 = sha_file(path)
    if actual_sha256 != expected_sha256:
        raise CensusError(f"public schedule file digest mismatch for {path}")
    value = load_json(path)
    if not isinstance(value, dict) or value.get("schema") != SCHEDULE_SCHEMA:
        raise CensusError(f"unexpected public schedule schema in {path}")
    if "schedule_sha256" in value:
        validate_digest(value, "schedule_sha256", f"public schedule {path}")
    if not isinstance(value.get("points"), list):
        raise CensusError(f"public schedule {path} has no point list")
    return value


def parse_public_klv_semantic_identity(
    path: pathlib.Path, context: str
) -> dict[str, object]:
    """Parse a public Rebar KLV without retaining any pattern or haystack bytes."""
    size = path.stat().st_size
    if size > MAX_PUBLIC_KLV_BYTES:
        raise CensusError(f"{context} exceeds the public KLV byte limit")
    payload = path.read_bytes()
    fields: list[tuple[str, bytes]] = []
    cursor = 0
    while cursor < len(payload):
        key_end = payload.find(b":", cursor)
        if key_end < 0:
            raise CensusError(f"{context} KLV key delimiter is missing")
        try:
            key = payload[cursor:key_end].decode("ascii", "strict")
        except UnicodeDecodeError as error:
            raise CensusError(f"{context} KLV key is not ASCII") from error
        if key not in PUBLIC_KLV_KEYS:
            raise CensusError(f"{context} KLV has unknown key {key!r}")
        length_start = key_end + 1
        length_end = payload.find(b":", length_start)
        if length_end < 0:
            raise CensusError(f"{context} KLV length delimiter is missing")
        length_bytes = payload[length_start:length_end]
        if (
            not length_bytes
            or not length_bytes.isdigit()
            or len(length_bytes) > 20
            or (len(length_bytes) > 1 and length_bytes.startswith(b"0"))
        ):
            raise CensusError(f"{context} KLV length is not canonical decimal")
        length = int(length_bytes)
        value_start = length_end + 1
        value_end = value_start + length
        if value_end >= len(payload) or payload[value_end] != 0x0A:
            raise CensusError(f"{context} KLV value is truncated or lacks its newline")
        fields.append((key, payload[value_start:value_end]))
        cursor = value_end + 1

    keys = [key for key, _ in fields]
    patterns = [value for key, value in fields if key == "pattern"]
    legacy_keys = [
        "name", "model", *("pattern" for _ in patterns),
        "case-insensitive", "unicode", "haystack", "max-iters",
        "max-warmup-iters", "max-time", "max-warmup-time",
    ]
    production_keys = [
        "name", "model", "case-insensitive", "unicode", "max-iters",
        "max-warmup-iters", "max-time", "max-warmup-time",
        *("pattern" for _ in patterns), "haystack",
    ]
    if keys not in (legacy_keys, production_keys):
        raise CensusError(f"{context} KLV field order or closure is noncanonical")
    by_key = {key: value for key, value in fields if key != "pattern"}
    try:
        benchmark = by_key["name"].decode("utf-8", "strict")
        model = by_key["model"].decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise CensusError(f"{context} KLV textual identity is not UTF-8") from error
    if not benchmark or not model:
        raise CensusError(f"{context} KLV has an empty textual identity")
    if model not in PUBLIC_REBAR_MODELS:
        raise CensusError(f"{context} KLV has an unsupported public Rebar model")
    try:
        for pattern in patterns:
            pattern.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise CensusError(f"{context} KLV pattern is not UTF-8") from error
    if (model == "regex-redux") != (not patterns):
        raise CensusError(f"{context} KLV pattern cardinality differs from its model")

    boolean_values: dict[str, bool] = {}
    for key in ("case-insensitive", "unicode"):
        raw = by_key[key]
        if raw not in {b"true", b"false"}:
            raise CensusError(f"{context} KLV {key} is not a canonical boolean")
        boolean_values[key] = raw == b"true"
    for key in ("max-iters", "max-warmup-iters", "max-time", "max-warmup-time"):
        raw = by_key[key]
        if (
            not raw
            or not raw.isdigit()
            or len(raw) > 20
            or (len(raw) > 1 and raw.startswith(b"0"))
            or int(raw) > (1 << 64) - 1
        ):
            raise CensusError(f"{context} KLV {key} is not canonical unsigned decimal")
    if int(by_key["max-iters"]) == 0:
        raise CensusError(f"{context} KLV max-iters must be nonzero")

    identity = {
        "benchmark": benchmark,
        "model": model,
        "input": {
            "pattern_sha256": [sha_bytes(pattern) for pattern in patterns],
            "haystack_sha256": sha_bytes(by_key["haystack"]),
            "haystack_bytes": len(by_key["haystack"]),
            "case_insensitive": boolean_values["case-insensitive"],
            "unicode": boolean_values["unicode"],
        },
    }
    return {
        "identity": identity,
        "semantic_identity_sha256": sha_bytes(canonical(identity).encode()),
    }


def external_public_manifest(
    path: pathlib.Path,
    expected_sha256: str,
    public_root: pathlib.Path,
    recorded_root: str,
    expected_jobs: int,
) -> tuple[
    dict[str, object], dict[str, dict[str, object]], Optional[dict[str, str]]
]:
    """Authenticate and index the canonical public Rust KLV inventory."""
    forbidden = forbidden_path_components(path.resolve(strict=True).parts)
    if forbidden:
        raise CensusError(f"public manifest path has forbidden components {forbidden!r}")
    expected_sha256 = require_hex64(expected_sha256, "expected public manifest SHA-256")
    if sha_file(path) != expected_sha256:
        raise CensusError(f"public manifest file digest mismatch for {path}")
    value = load_json(path)
    if not isinstance(value, dict):
        raise CensusError("public KLV manifest is not an object")
    minimal_keys = {"schema", "entries"}
    inventory_keys = {
        "schema", "entries", "compile_job_count", "job_count", "model_counts",
        "rebar_binary_sha256", "rebar_revision", "runtime_job_count",
    }
    inventory = "job_count" in value
    require_exact_keys(
        value, inventory_keys if inventory else minimal_keys, "public KLV manifest"
    )
    if value["schema"] != PUBLIC_MANIFEST_SCHEMA:
        raise CensusError("unexpected public KLV manifest schema")
    entries = value["entries"]
    if not isinstance(entries, list) or len(entries) != expected_jobs:
        raise CensusError(
            f"public KLV manifest has {len(entries) if isinstance(entries, list) else 'invalid'} "
            f"entries, expected {expected_jobs}"
        )
    metadata: Optional[dict[str, str]] = None
    if inventory:
        for name in ("compile_job_count", "job_count", "runtime_job_count"):
            count = value[name]
            if not isinstance(count, int) or isinstance(count, bool) or count < 0:
                raise CensusError(f"public KLV manifest {name} is invalid")
        if value["job_count"] != len(entries):
            raise CensusError("public KLV manifest job count differs from its entries")
        require_hex64(
            value["rebar_binary_sha256"], "public KLV manifest Rebar binary"
        )
        revision = value["rebar_revision"]
        if not isinstance(revision, str) or HEX40.fullmatch(revision) is None:
            raise CensusError("public KLV manifest Rebar revision is invalid")
        metadata = {"rebar_revision": revision}
        model_counts = value["model_counts"]
        if (
            not isinstance(model_counts, dict)
            or not all(isinstance(name, str) and name for name in model_counts)
            or not all(
                isinstance(count, int) and not isinstance(count, bool) and count >= 0
                for count in model_counts.values()
            )
        ):
            raise CensusError("public KLV manifest model counts are invalid")
    indexed: dict[str, dict[str, object]] = {}
    normalized_rows = []
    seen_klvs: set[tuple[str, str]] = set()
    seen_job_ids: set[str] = set()
    ordered_compile_job_ids: list[str] = []
    ordered_runtime_job_ids: list[str] = []
    observed_models: Counter[str] = Counter()
    for ordinal, raw_entry in enumerate(entries):
        if not isinstance(raw_entry, dict):
            raise CensusError(f"public manifest entry {ordinal} is not an object")
        manifest_job_id: Optional[str] = None
        declared_benchmark: Optional[str] = None
        declared_model: Optional[str] = None
        if inventory:
            require_exact_keys(
                raw_entry,
                {
                    "benchmark", "engine", "job_id", "klv_bytes", "klv_file",
                    "klv_sha256", "model",
                },
                f"public manifest entry {ordinal}",
            )
            declared_benchmark = raw_entry["benchmark"]
            declared_model = raw_entry["model"]
            manifest_job_id = raw_entry["job_id"]
            if not all(
                isinstance(item, str) and item
                for item in (declared_benchmark, declared_model, manifest_job_id)
            ):
                raise CensusError(
                    f"public manifest entry {ordinal} has invalid textual metadata"
                )
            if raw_entry["engine"] != "rust/regex":
                raise CensusError(
                    f"public manifest entry {ordinal} is not a Rust regex job"
                )
            if declared_model not in PUBLIC_REBAR_MODELS:
                raise CensusError(
                    f"public manifest entry {ordinal} has an unsupported model"
                )
            job_prefix = "compile-job-" if declared_model == "compile" else "runtime-job-"
            if re.fullmatch(re.escape(job_prefix) + r"[0-9]{3}", manifest_job_id) is None:
                raise CensusError(
                    f"public manifest entry {ordinal} has a noncanonical job ID"
                )
            if manifest_job_id in seen_job_ids:
                raise CensusError("public KLV manifest repeats a job ID")
            seen_job_ids.add(manifest_job_id)
            if declared_model == "compile":
                ordered_compile_job_ids.append(manifest_job_id)
            else:
                ordered_runtime_job_ids.append(manifest_job_id)
            observed_models[declared_model] += 1
            normalized_entry = {
                "path": raw_entry["klv_file"],
                "sha256": raw_entry["klv_sha256"],
                "bytes": raw_entry["klv_bytes"],
            }
        else:
            require_exact_keys(
                raw_entry, {"path", "sha256", "bytes"},
                f"public manifest entry {ordinal}",
            )
            normalized_entry = raw_entry
        if (
            not isinstance(normalized_entry["bytes"], int)
            or isinstance(normalized_entry["bytes"], bool)
            or normalized_entry["bytes"] < 0
        ):
            raise CensusError(f"public manifest entry {ordinal} byte count is invalid")
        klv = klv_identity(
            normalized_entry, public_root, recorded_root,
            f"public manifest entry {ordinal}", True,
        )
        if normalized_entry["bytes"] != klv["bytes"]:
            raise CensusError(f"public manifest entry {ordinal} byte count differs")
        klv_key = (str(klv["path"]), str(klv["sha256"]))
        if klv_key in seen_klvs:
            raise CensusError("public KLV manifest repeats an exact KLV identity")
        seen_klvs.add(klv_key)
        absolute = (public_root / pathlib.Path(*pathlib.PurePosixPath(
            str(klv["path"])
        ).parts)).resolve(strict=True)
        semantic = parse_public_klv_semantic_identity(
            absolute, f"public manifest entry {ordinal}"
        )
        if inventory and (
            semantic["identity"]["benchmark"] != declared_benchmark
            or semantic["identity"]["model"] != declared_model
        ):
            raise CensusError(
                f"public manifest entry {ordinal} metadata differs from its KLV"
            )
        semantic_sha = str(semantic["semantic_identity_sha256"])
        if semantic_sha in indexed:
            raise CensusError(
                "public KLV manifest repeats a semantic benchmark/model/input identity"
            )
        record = {
            "ordinal": ordinal,
            "klv": klv,
            "semantic_identity_sha256": semantic_sha,
            "identity": semantic["identity"],
            "job_id": manifest_job_id,
            "engine": "rust/regex" if inventory else None,
        }
        indexed[semantic_sha] = record
        normalized_rows.append({
            "ordinal": ordinal,
            "klv": klv,
            "semantic_identity_sha256": semantic_sha,
        })
    if inventory:
        expected_model_counts = dict(sorted(observed_models.items()))
        if value["model_counts"] != expected_model_counts:
            raise CensusError("public KLV manifest model counts differ from its entries")
        compile_count = observed_models.get("compile", 0)
        if (
            value["compile_job_count"] != compile_count
            or value["runtime_job_count"] != len(entries) - compile_count
            or value["compile_job_count"] + value["runtime_job_count"]
            != value["job_count"]
        ):
            raise CensusError("public KLV manifest runtime/compile counts differ")
        expected_compile_job_ids = [
            f"compile-job-{index:03}" for index in range(compile_count)
        ]
        expected_runtime_job_ids = [
            f"runtime-job-{index:03}"
            for index in range(len(entries) - compile_count)
        ]
        if (
            ordered_compile_job_ids != expected_compile_job_ids
            or ordered_runtime_job_ids != expected_runtime_job_ids
        ):
            raise CensusError("public KLV manifest job ID topology differs")
    manifest_record = {
        "schema": PUBLIC_MANIFEST_SCHEMA,
        "file_sha256": expected_sha256,
        "entry_count": len(entries),
        "entries_sha256": sha_bytes(canonical(normalized_rows).encode()),
        "mappings": None,
        "mapping_sha256": None,
    }
    return manifest_record, indexed, metadata


def external_schedule_klv_claim(entry: object, context: str) -> None:
    """Validate a sealed schedule KLV claim without requiring its old host path."""
    if not isinstance(entry, dict):
        raise CensusError(f"{context} KLV identity is not an object")
    require_exact_keys(entry, {"path", "sha256"}, f"{context} KLV identity")
    path = entry["path"]
    if not isinstance(path, str) or not path or "\x00" in path:
        raise CensusError(f"{context} KLV path is invalid")
    require_hex64(entry["sha256"], f"{context} KLV SHA-256")


def klv_identity(
    entry: object,
    public_root: pathlib.Path,
    recorded_root: str,
    context: str,
    validate_bytes: bool,
) -> dict[str, object]:
    if not isinstance(entry, dict):
        raise CensusError(f"{context} KLV identity is not an object")
    relative, absolute = relative_public_path(
        public_root, entry.get("path"), context, recorded_root
    )
    claimed = require_hex64(entry.get("sha256"), f"{context} KLV SHA-256")
    if validate_bytes and sha_file(absolute) != claimed:
        raise CensusError(f"{context} KLV bytes differ from schedule identity")
    return {"path": relative, "sha256": claimed, "bytes": absolute.stat().st_size}


def point_input(point: dict[str, object]) -> dict[str, object]:
    value = point.get("input")
    if not isinstance(value, dict):
        raise CensusError("schedule point has no hashed input identity")
    patterns = value.get("pattern_sha256")
    if not isinstance(patterns, list) or not all(
        isinstance(item, str) and HEX64.fullmatch(item) for item in patterns
    ):
        raise CensusError("schedule point has invalid pattern SHA-256 identities")
    case_insensitive = value.get("case_insensitive")
    unicode = value.get("unicode")
    haystack_sha256 = require_hex64(value.get("haystack_sha256"), "haystack SHA-256")
    haystack_bytes = value.get("haystack_bytes")
    if not isinstance(case_insensitive, bool) or not isinstance(unicode, bool):
        raise CensusError("schedule point has invalid regex option identity")
    if not isinstance(haystack_bytes, int) or isinstance(haystack_bytes, bool) or haystack_bytes < 0:
        raise CensusError("schedule point has invalid haystack byte count")
    return {
        "pattern_sha256": patterns,
        "haystack_sha256": haystack_sha256,
        "haystack_bytes": haystack_bytes,
        "case_insensitive": case_insensitive,
        "unicode": unicode,
    }


def validate_input_identity(value: object, context: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise CensusError(f"{context} is not an object")
    require_exact_keys(value, {
        "pattern_sha256", "haystack_sha256", "haystack_bytes",
        "case_insensitive", "unicode",
    }, context)
    patterns = value["pattern_sha256"]
    if not isinstance(patterns, list) or not all(
        isinstance(pattern, str) and HEX64.fullmatch(pattern) for pattern in patterns
    ):
        raise CensusError(f"{context} has invalid pattern identities")
    require_hex64(value["haystack_sha256"], f"{context} haystack")
    if (
        not isinstance(value["haystack_bytes"], int)
        or isinstance(value["haystack_bytes"], bool)
        or value["haystack_bytes"] < 0
    ):
        raise CensusError(f"{context} has an invalid haystack size")
    if not isinstance(value["case_insensitive"], bool) or not isinstance(
        value["unicode"], bool
    ):
        raise CensusError(f"{context} has invalid regex option identities")
    return value


def validate_recorded_klv(value: object, context: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise CensusError(f"{context} is not an object")
    require_exact_keys(value, {"path", "sha256", "bytes"}, context)
    path = value["path"]
    if not isinstance(path, str) or not path:
        raise CensusError(f"{context} has an invalid path")
    pure = pathlib.PurePosixPath(path)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise CensusError(f"{context} path is not a canonical relative path")
    if forbidden_path_components(pure.parts):
        raise CensusError(f"{context} path enters a forbidden component")
    require_hex64(value["sha256"], f"{context} digest")
    if (
        not isinstance(value["bytes"], int)
        or isinstance(value["bytes"], bool)
        or value["bytes"] < 0
    ):
        raise CensusError(f"{context} has an invalid byte count")
    return value


def make_plan(args: argparse.Namespace) -> dict[str, object]:
    if len(args.schedule) != len(args.schedule_sha256):
        raise CensusError("each --schedule requires one ordered --schedule-sha256")
    if args.skip_klv_hashing and not args.dry_run:
        raise CensusError("--skip-klv-hashing is allowed only for non-sealing --dry-run")
    if forbidden_path_components(tuple(pathlib.PurePosixPath(
        args.recorded_public_klv_root
    ).parts)):
        raise CensusError("recorded public KLV root has a forbidden path component")
    if any(token in args.public_corpus_label.casefold() for token in FORBIDDEN_PUBLIC_COMPONENTS):
        raise CensusError("public corpus label contains a forbidden privacy token")
    public_root = pathlib.Path(args.public_klv_root).resolve(strict=True)
    source = source_identity(
        pathlib.Path(args.source_dir), args.source_commit, args.source_tree
    )
    raw_public_manifest = getattr(args, "public_manifest", None)
    raw_public_manifest_sha256 = getattr(args, "public_manifest_sha256", None)
    if (raw_public_manifest is None) != (raw_public_manifest_sha256 is None):
        raise CensusError(
            "--public-manifest and --public-manifest-sha256 must be supplied together"
        )
    manifest_record: Optional[dict[str, object]] = None
    manifest_entries: Optional[dict[str, dict[str, object]]] = None
    manifest_metadata: Optional[dict[str, str]] = None
    if raw_public_manifest is not None:
        if args.skip_klv_hashing:
            raise CensusError("public manifest mode cannot skip KLV hashing")
        manifest_record, manifest_entries, manifest_metadata = external_public_manifest(
            pathlib.Path(raw_public_manifest).resolve(strict=True),
            raw_public_manifest_sha256,
            public_root,
            args.recorded_public_klv_root,
            args.expected_public_jobs,
        )
    schedules = []
    raw_points: dict[str, dict[str, object]] = {}
    jobs: dict[str, dict[str, object]] = {}
    semantic_cache: dict[tuple[str, str], dict[str, object]] = {}
    manifest_mapping: dict[str, dict[str, object]] = {}
    for raw_path, expected_sha in zip(args.schedule, args.schedule_sha256):
        path = pathlib.Path(raw_path).resolve(strict=True)
        schedule = external_schedule(path, expected_sha)
        schedule_record = {
            "file_sha256": expected_sha,
            "internal_sha256": schedule.get("schedule_sha256"),
            "canonical_commit": schedule.get("canonical_sha"),
            "canonical_tree": schedule.get("canonical_tree"),
            "rebar_revision": schedule.get("rebar_revision"),
            "point_count": len(schedule["points"]),
        }
        if (
            manifest_metadata is not None
            and schedule_record["rebar_revision"]
            != manifest_metadata["rebar_revision"]
        ):
            raise CensusError(
                "public KLV manifest Rebar revision differs from the schedule"
            )
        schedules.append(schedule_record)
        for ordinal, raw_point in enumerate(schedule["points"]):
            if not isinstance(raw_point, dict):
                raise CensusError("public schedule point is not an object")
            point_id = raw_point.get("point_id")
            job_id = raw_point.get("fre_job_id")
            benchmark = raw_point.get("benchmark")
            model = raw_point.get("model")
            boundary = raw_point.get("boundary")
            comparator = raw_point.get("comparator")
            if not all(isinstance(item, str) and item for item in (
                point_id, job_id, benchmark, model, boundary, comparator
            )):
                raise CensusError("public schedule point omits a textual identity field")
            identity = point_input(raw_point)
            structured_identity = {
                "benchmark": benchmark,
                "model": model,
                "input": identity,
            }
            if manifest_entries is not None:
                if manifest_metadata is not None:
                    external_schedule_klv_claim(
                        raw_point.get("candidate_klv"), f"point {point_id} candidate"
                    )
                    external_schedule_klv_claim(
                        raw_point.get("reference_klv"), f"point {point_id} reference"
                    )
                    semantic_sha = sha_bytes(canonical(structured_identity).encode())
                else:
                    schedule_candidate = klv_identity(
                        raw_point.get("candidate_klv"), public_root,
                        args.recorded_public_klv_root, f"point {point_id} candidate",
                        not args.skip_klv_hashing,
                    )
                    schedule_key = (
                        str(schedule_candidate["path"]),
                        str(schedule_candidate["sha256"]),
                    )
                    semantic = semantic_cache.get(schedule_key)
                    if semantic is None:
                        schedule_path = (
                            public_root
                            / pathlib.Path(*pathlib.PurePosixPath(
                                str(schedule_candidate["path"])
                            ).parts)
                        ).resolve(strict=True)
                        semantic = parse_public_klv_semantic_identity(
                            schedule_path, f"point {point_id} candidate"
                        )
                        semantic_cache[schedule_key] = semantic
                    if semantic["identity"] != structured_identity:
                        raise CensusError(
                            f"point {point_id} structured identity differs from its "
                            "candidate KLV"
                        )
                    semantic_sha = str(semantic["semantic_identity_sha256"])
                manifest_entry = manifest_entries.get(semantic_sha)
                if manifest_entry is None:
                    raise CensusError(
                        f"point {point_id} has no semantic match in the public KLV manifest"
                    )
                if (
                    manifest_metadata is not None
                    and job_id != f"{benchmark}@{manifest_entry['engine']}"
                ):
                    raise CensusError(
                        f"point {point_id} job ID is not canonical for its public engine"
                    )
                candidate = manifest_entry["klv"]
                if manifest_metadata is not None:
                    reference = candidate
                else:
                    reference = klv_identity(
                        raw_point.get("reference_klv"), public_root,
                        args.recorded_public_klv_root, f"point {point_id} reference",
                        not args.skip_klv_hashing,
                    )
                mapping = manifest_mapping.setdefault(semantic_sha, {
                    "manifest_ordinal": manifest_entry["ordinal"],
                    "manifest_klv": candidate,
                    "semantic_identity_sha256": semantic_sha,
                    "job_ids": set(),
                    "point_ids": set(),
                })
                mapping["job_ids"].add(job_id)
                mapping["point_ids"].add(point_id)
            else:
                candidate = klv_identity(
                    raw_point.get("candidate_klv"), public_root,
                    args.recorded_public_klv_root, f"point {point_id} candidate",
                    not args.skip_klv_hashing,
                )
                reference = klv_identity(
                    raw_point.get("reference_klv"), public_root,
                    args.recorded_public_klv_root, f"point {point_id} reference",
                    not args.skip_klv_hashing,
                )
            point_record = {
                "point_id": point_id,
                "job_id": job_id,
                "benchmark": benchmark,
                "model": model,
                "boundary": boundary,
                "comparator": comparator,
                "expected": canonical_expected_value(
                    raw_point.get("expected"), f"point {point_id}"
                ),
                "input": identity,
                "candidate_klv": candidate,
                "reference_klv": reference,
                "source_schedule_sha256": expected_sha,
                "source_ordinal": ordinal,
            }
            prior_point = raw_points.setdefault(point_id, point_record)
            if prior_point != point_record:
                raise CensusError(f"conflicting duplicate public point {point_id}")
            pattern_count = len(identity["pattern_sha256"])
            exact_adapter = has_exact_adapter(model, pattern_count)
            job_basis = {
                "job_id": job_id,
                "benchmark": benchmark,
                "model": model,
                "input": identity,
                "candidate_klv": candidate,
                "is_runtime": model != "compile",
                "exact_adapter": exact_adapter,
                "adapter_reason": exact_adapter_reason(model, pattern_count),
            }
            prior_job = jobs.setdefault(job_id, {**job_basis, "point_ids": []})
            for key, expected in job_basis.items():
                if prior_job[key] != expected:
                    raise CensusError(f"public job identity changes across points: {job_id}")
            prior_job["point_ids"].append(point_id)

    for job in jobs.values():
        job["point_ids"] = sorted(set(job["point_ids"]))
    job_rows = sorted(jobs.values(), key=lambda value: value["job_id"])
    point_rows = sorted(raw_points.values(), key=lambda value: value["point_id"])
    for job in job_rows:
        expected_value_for_job_points(point_rows, job)
    all_jobs = [row["job_id"] for row in job_rows]
    compile_jobs = [row["job_id"] for row in job_rows if not row["is_runtime"]]
    runtime_jobs = [row["job_id"] for row in job_rows if row["is_runtime"]]
    exact_jobs = [row["job_id"] for row in job_rows if row["is_runtime"] and row["exact_adapter"]]
    raw_runtime_points = [row["point_id"] for row in point_rows if row["model"] != "compile"]
    if len(all_jobs) != args.expected_public_jobs:
        raise CensusError(
            f"canonical public job denominator is {len(all_jobs)}, expected {args.expected_public_jobs}"
        )
    if len(runtime_jobs) != args.expected_runtime_jobs:
        raise CensusError(
            f"canonical runtime job denominator is {len(runtime_jobs)}, expected {args.expected_runtime_jobs}"
        )
    if len(compile_jobs) != args.expected_compile_jobs:
        raise CensusError(
            f"compile job count is {len(compile_jobs)}, expected {args.expected_compile_jobs}"
        )
    if manifest_entries is not None:
        missing_semantics = sorted(set(manifest_entries) - set(manifest_mapping))
        extra_semantics = sorted(set(manifest_mapping) - set(manifest_entries))
        if missing_semantics or extra_semantics:
            raise CensusError(
                "public manifest/schedule semantic mapping is incomplete: "
                f"missing={len(missing_semantics)} extra={len(extra_semantics)}"
            )
        normalized_mapping = []
        for semantic_sha in sorted(manifest_mapping):
            mapping = manifest_mapping[semantic_sha]
            job_ids_for_semantic = sorted(mapping["job_ids"])
            if len(job_ids_for_semantic) != 1:
                raise CensusError(
                    "one public manifest semantic identity maps to multiple schedule jobs"
                )
            normalized_mapping.append({
                "manifest_ordinal": mapping["manifest_ordinal"],
                "manifest_klv": mapping["manifest_klv"],
                "semantic_identity_sha256": semantic_sha,
                "job_id": job_ids_for_semantic[0],
                "point_ids": sorted(mapping["point_ids"]),
            })
        if manifest_record is None:
            raise CensusError("public manifest mapping lost its authenticated manifest")
        manifest_record["mappings"] = normalized_mapping
        manifest_record["mapping_sha256"] = sha_bytes(
            canonical(normalized_mapping).encode()
        )
    schedule_revisions = sorted({str(row["rebar_revision"]) for row in schedules})
    expectation_rows = [
        frozen_job_expectation_record(job, point_rows)
        for job in job_rows if job["is_runtime"]
    ]
    divergent_jobs = [row["job_id"] for row in expectation_rows if row["divergent"]]
    expected_results = {
        "authority": "frozen-comparator-first-v1",
        "preference": list(FROZEN_COMPARATOR_PREFERENCE),
        "runtime_jobs": expectation_rows,
        "runtime_jobs_sha256": sha_bytes(canonical(expectation_rows).encode()),
        "divergent_jobs": id_set(divergent_jobs),
    }
    public_corpus = {
        "label": args.public_corpus_label,
        "klv_root_recorded": args.recorded_public_klv_root,
        "privacy_policy": "public-rebar-only; hashed-input-identities; no-pattern-or-haystack-bytes",
        "rebar_revisions": schedule_revisions,
        "schedules": sorted(schedules, key=lambda row: row["file_sha256"]),
        "expected_results": expected_results,
    }
    if manifest_record is not None:
        public_corpus["manifest"] = manifest_record
    plan = {
        "schema": PLAN_SCHEMA,
        "candidate_source": source,
        "public_corpus": public_corpus,
        "target": {
            "triple": args.target,
            "features": "none" if args.features == "" else args.features,
            "feature_bits": canonical_feature_bits(args.target, args.features),
        },
        "policy": {
            "compiler_mode": "Optimizing",
            "timing": False,
            "public_klv_bytes_hashed": not args.skip_klv_hashing,
            "reproducible_builds_required": 2,
            "native_proof": "unmodified-oracle-pass + all-semantic-helper-traps-pass + claimed-entry-trap-fires",
            "compiled_artifact_is_runtime_execution": False,
            "unsupported_failure_timeout_are_nonnative": True,
            "canonical_denominator": "deduplicated-public-rust-rebar-runtime-job",
        },
        "denominators": {
            "all_public_jobs": id_set(all_jobs),
            "compile_jobs": id_set(compile_jobs),
            "runtime_jobs": id_set(runtime_jobs),
            "exact_adapter_runtime_jobs": id_set(exact_jobs),
            "all_raw_schedule_points": id_set([row["point_id"] for row in point_rows]),
            "raw_runtime_schedule_points": id_set(raw_runtime_points),
        },
        "jobs": job_rows,
        "points": point_rows,
    }
    return add_digest(plan, "plan_sha256")


def validate_plan(plan: object) -> dict[str, object]:
    if not isinstance(plan, dict):
        raise CensusError("plan is not an object")
    require_exact_keys(plan, {
        "schema", "candidate_source", "public_corpus", "target", "policy",
        "denominators", "jobs", "points", "plan_sha256",
    }, "plan")
    if plan["schema"] != PLAN_SCHEMA:
        raise CensusError("unexpected plan schema")
    validate_digest(plan, "plan_sha256", "plan")
    if not isinstance(plan["candidate_source"], dict):
        raise CensusError("plan candidate source is not an object")
    require_exact_keys(plan["candidate_source"], {
        "commit", "tree", "cargo_lock_sha256",
    }, "plan candidate source")
    require_git_hash(plan["candidate_source"]["commit"], "plan source commit")
    require_git_hash(plan["candidate_source"]["tree"], "plan source tree")
    require_hex64(plan["candidate_source"]["cargo_lock_sha256"], "plan Cargo.lock")
    if not isinstance(plan["public_corpus"], dict):
        raise CensusError("plan public corpus is not an object")
    public_corpus_base_keys = {
        "label", "klv_root_recorded", "privacy_policy", "rebar_revisions", "schedules",
    }
    public_corpus = plan["public_corpus"]
    public_corpus_keys = set(public_corpus)
    if (
        not public_corpus_base_keys.issubset(public_corpus_keys)
        or public_corpus_keys - public_corpus_base_keys
        not in (set(), {"expected_results"}, {"expected_results", "manifest"})
    ):
        raise CensusError("plan public corpus schema keys differ")
    if public_corpus["privacy_policy"] != (
        "public-rebar-only; hashed-input-identities; no-pattern-or-haystack-bytes"
    ):
        raise CensusError("plan has a noncanonical public-corpus privacy policy")
    if not all(
        isinstance(public_corpus[name], str) and public_corpus[name]
        for name in ("label", "klv_root_recorded")
    ):
        raise CensusError("plan public corpus has an invalid textual identity")
    manifest = public_corpus.get("manifest")
    if manifest is not None:
        if not isinstance(manifest, dict):
            raise CensusError("plan public manifest record is not an object")
        require_exact_keys(manifest, {
            "schema", "file_sha256", "entry_count", "entries_sha256",
            "mappings", "mapping_sha256",
        }, "plan public manifest record")
        if manifest["schema"] != PUBLIC_MANIFEST_SCHEMA:
            raise CensusError("plan public manifest schema differs")
        require_hex64(manifest["file_sha256"], "plan public manifest file")
        require_hex64(manifest["entries_sha256"], "plan public manifest entries")
        require_hex64(manifest["mapping_sha256"], "plan public manifest mapping")
        if (
            not isinstance(manifest["entry_count"], int)
            or isinstance(manifest["entry_count"], bool)
            or manifest["entry_count"] != EXPECTED_PUBLIC_JOBS
        ):
            raise CensusError("plan public manifest does not contain exactly 344 entries")
        mappings = manifest["mappings"]
        if not isinstance(mappings, list) or len(mappings) != manifest["entry_count"]:
            raise CensusError("plan public manifest mapping cardinality differs")
        if manifest["mapping_sha256"] != sha_bytes(canonical(mappings).encode()):
            raise CensusError("plan public manifest mapping digest differs")
    if not isinstance(plan["target"], dict):
        raise CensusError("plan target is not an object")
    require_exact_keys(plan["target"], {"triple", "features", "feature_bits"}, "plan target")
    if not all(
        isinstance(plan["target"][name], str) for name in ("triple", "features", "feature_bits")
    ):
        raise CensusError("plan target fields are not strings")
    if plan["target"]["feature_bits"] != canonical_feature_bits(
        plan["target"]["triple"], plan["target"]["features"]
    ):
        raise CensusError("plan target feature bits differ from its feature names")
    if not isinstance(plan["policy"], dict):
        raise CensusError("plan policy is not an object")
    require_exact_keys(plan["policy"], {
        "compiler_mode", "timing", "public_klv_bytes_hashed",
        "reproducible_builds_required", "native_proof",
        "compiled_artifact_is_runtime_execution",
        "unsupported_failure_timeout_are_nonnative", "canonical_denominator",
    }, "plan policy")
    expected_policy = {
        "compiler_mode": "Optimizing",
        "timing": False,
        "public_klv_bytes_hashed": True,
        "reproducible_builds_required": 2,
        "native_proof": (
            "unmodified-oracle-pass + all-semantic-helper-traps-pass + "
            "claimed-entry-trap-fires"
        ),
        "compiled_artifact_is_runtime_execution": False,
        "unsupported_failure_timeout_are_nonnative": True,
        "canonical_denominator": "deduplicated-public-rust-rebar-runtime-job",
    }
    if plan["policy"] != expected_policy:
        raise CensusError("plan policy is not the canonical sealed-census policy")
    schedules = public_corpus["schedules"]
    if not isinstance(schedules, list) or not schedules:
        raise CensusError("plan has no source schedules")
    schedule_ids = []
    for index, schedule in enumerate(schedules):
        if not isinstance(schedule, dict):
            raise CensusError(f"plan schedule {index} is not an object")
        require_exact_keys(schedule, {
            "file_sha256", "internal_sha256", "canonical_commit", "canonical_tree",
            "rebar_revision", "point_count",
        }, f"plan schedule {index}")
        require_hex64(schedule["file_sha256"], f"plan schedule {index} file")
        if schedule["internal_sha256"] is not None:
            require_hex64(schedule["internal_sha256"], f"plan schedule {index} internal")
        for name in ("canonical_commit", "canonical_tree", "rebar_revision"):
            if schedule[name] is not None:
                require_git_hash(schedule[name], f"plan schedule {index} {name}")
        if (
            not isinstance(schedule["point_count"], int)
            or isinstance(schedule["point_count"], bool)
            or schedule["point_count"] <= 0
        ):
            raise CensusError(f"plan schedule {index} has an invalid point count")
        schedule_ids.append(schedule["file_sha256"])
    if schedule_ids != sorted(set(schedule_ids)):
        raise CensusError("plan schedules are duplicated or not in canonical order")
    expected_revisions = sorted({str(schedule["rebar_revision"]) for schedule in schedules})
    if public_corpus["rebar_revisions"] != expected_revisions:
        raise CensusError("plan Rebar revision set differs from its schedules")
    denominators = plan["denominators"]
    if not isinstance(denominators, dict):
        raise CensusError("plan denominators are not an object")
    require_exact_keys(denominators, {
        "all_public_jobs", "compile_jobs", "runtime_jobs", "exact_adapter_runtime_jobs",
        "all_raw_schedule_points", "raw_runtime_schedule_points",
    }, "plan denominators")
    for name, value in denominators.items():
        if not isinstance(value, dict):
            raise CensusError(f"denominator {name} is not an object")
        require_exact_keys(value, {"count", "ids", "ids_sha256"}, f"denominator {name}")
        if not isinstance(value["ids"], list) or not all(
            isinstance(identifier, str) and identifier for identifier in value["ids"]
        ):
            raise CensusError(f"denominator {name} has invalid IDs")
        if value != id_set(list(value["ids"])):
            raise CensusError(f"denominator {name} is not canonical")
    expected_denominator_counts = {
        "all_public_jobs": EXPECTED_PUBLIC_JOBS,
        "compile_jobs": EXPECTED_COMPILE_JOBS,
        "runtime_jobs": EXPECTED_RUNTIME_JOBS,
    }
    for name, expected_count in expected_denominator_counts.items():
        if denominators[name]["count"] != expected_count:
            raise CensusError(
                f"plan does not seal the canonical {expected_count}-job {name} denominator"
            )
    job_ids = []
    compile_ids = []
    runtime_ids = []
    exact_ids = []
    if not isinstance(plan["jobs"], list) or not isinstance(plan["points"], list):
        raise CensusError("plan jobs or points are not lists")
    for index, job in enumerate(plan["jobs"]):
        if not isinstance(job, dict):
            raise CensusError(f"plan job {index} is not an object")
        require_exact_keys(job, {
            "job_id", "benchmark", "model", "input", "candidate_klv", "is_runtime",
            "exact_adapter", "adapter_reason", "point_ids",
        }, f"plan job {index}")
        if not all(
            isinstance(job[name], str) and job[name]
            for name in ("job_id", "benchmark", "model", "adapter_reason")
        ):
            raise CensusError(f"plan job {index} has an invalid textual identity")
        validate_input_identity(job["input"], f"plan job {index} input")
        validate_recorded_klv(job["candidate_klv"], f"plan job {index} KLV")
        pattern_count = len(job["input"]["pattern_sha256"])
        expected_runtime = job["model"] != "compile"
        expected_adapter = has_exact_adapter(job["model"], pattern_count)
        if not isinstance(job["is_runtime"], bool) or job["is_runtime"] != expected_runtime:
            raise CensusError(f"plan job {index} has a noncanonical runtime classification")
        if not isinstance(job["exact_adapter"], bool) or job["exact_adapter"] != expected_adapter:
            raise CensusError(f"plan job {index} has a noncanonical adapter classification")
        if job["adapter_reason"] != exact_adapter_reason(job["model"], pattern_count):
            raise CensusError(f"plan job {index} has a noncanonical adapter reason")
        if not isinstance(job["point_ids"], list) or not job["point_ids"]:
            raise CensusError(f"plan job {index} has no source points")
        job_ids.append(job["job_id"])
        if job["is_runtime"]:
            runtime_ids.append(job["job_id"])
            if job["exact_adapter"]:
                exact_ids.append(job["job_id"])
        else:
            compile_ids.append(job["job_id"])
    if job_ids != sorted(job_ids):
        raise CensusError("plan jobs are not in canonical ID order")
    jobs_by_id = {job["job_id"]: job for job in plan["jobs"]}
    point_ids = []
    runtime_point_ids = []
    points_by_job: dict[str, list[str]] = {job_id: [] for job_id in job_ids}
    points_by_schedule: dict[str, list[int]] = {schedule_id: [] for schedule_id in schedule_ids}
    for index, point in enumerate(plan["points"]):
        if not isinstance(point, dict):
            raise CensusError(f"plan point {index} is not an object")
        require_exact_keys(point, {
            "point_id", "job_id", "benchmark", "model", "boundary", "comparator",
            "expected", "input", "candidate_klv", "reference_klv",
            "source_schedule_sha256", "source_ordinal",
        }, f"plan point {index}")
        if not all(
            isinstance(point[name], str) and point[name]
            for name in (
                "point_id", "job_id", "benchmark", "model", "boundary", "comparator"
            )
        ):
            raise CensusError(f"plan point {index} has an invalid textual identity")
        canonical_expected_value(point["expected"], f"plan point {index}")
        validate_input_identity(point["input"], f"plan point {index} input")
        for name in ("candidate_klv", "reference_klv"):
            validate_recorded_klv(point[name], f"plan point {index} {name}")
        require_hex64(
            point["source_schedule_sha256"], f"plan point {index} source schedule"
        )
        point_ids.append(point["point_id"])
        schedule_ordinals = points_by_schedule.get(point["source_schedule_sha256"])
        if schedule_ordinals is None:
            raise CensusError(f"plan point {index} references an unknown source schedule")
        source_ordinal = point["source_ordinal"]
        if (
            not isinstance(source_ordinal, int)
            or isinstance(source_ordinal, bool)
            or source_ordinal < 0
        ):
            raise CensusError(f"plan point {index} has an invalid source ordinal")
        schedule_ordinals.append(source_ordinal)
        job = jobs_by_id.get(point["job_id"])
        if job is None:
            raise CensusError(f"plan point {index} references an unknown job")
        for name in ("benchmark", "model", "input", "candidate_klv"):
            if point[name] != job[name]:
                raise CensusError(f"plan point {index} differs from its job {name}")
        points_by_job[point["job_id"]].append(point["point_id"])
        if point["model"] != "compile":
            runtime_point_ids.append(point["point_id"])
    if point_ids != sorted(point_ids):
        raise CensusError("plan points are not in canonical ID order")
    for job_id, point_ids_for_job in points_by_job.items():
        if jobs_by_id[job_id]["point_ids"] != sorted(point_ids_for_job):
            raise CensusError(f"plan job {job_id} point set differs from its points")
        expected_value_for_job(plan, jobs_by_id[job_id])
    schedules_by_id = {schedule["file_sha256"]: schedule for schedule in schedules}
    for schedule_id, ordinals in points_by_schedule.items():
        expected_ordinals = list(range(schedules_by_id[schedule_id]["point_count"]))
        if sorted(ordinals) != expected_ordinals:
            raise CensusError("plan source-schedule point topology is incomplete or duplicated")
    expected_sets = {
        "all_public_jobs": job_ids,
        "compile_jobs": compile_ids,
        "runtime_jobs": runtime_ids,
        "exact_adapter_runtime_jobs": exact_ids,
        "all_raw_schedule_points": point_ids,
        "raw_runtime_schedule_points": runtime_point_ids,
    }
    for name, values in expected_sets.items():
        if denominators[name] != id_set(values):
            raise CensusError(f"plan denominator {name} differs from its rows")
    expectation_rows = [
        frozen_job_expectation_record(job, plan["points"])
        for job in plan["jobs"] if job["is_runtime"]
    ]
    expected_results = public_corpus.get("expected_results")
    if expected_results is not None:
        divergent_jobs = [
            row["job_id"] for row in expectation_rows if row["divergent"]
        ]
        canonical_expected_results = {
            "authority": "frozen-comparator-first-v1",
            "preference": list(FROZEN_COMPARATOR_PREFERENCE),
            "runtime_jobs": expectation_rows,
            "runtime_jobs_sha256": sha_bytes(canonical(expectation_rows).encode()),
            "divergent_jobs": id_set(divergent_jobs),
        }
        if expected_results != canonical_expected_results:
            raise CensusError(
                "plan comparator-first authority or divergence diagnostics differ"
            )
    if manifest is not None:
        mappings = manifest["mappings"]
        semantic_ids = []
        mapped_jobs = []
        manifest_klvs = []
        ordinals = []
        entries_projection = []
        for index, mapping in enumerate(mappings):
            if not isinstance(mapping, dict):
                raise CensusError(f"plan public manifest mapping {index} is not an object")
            require_exact_keys(mapping, {
                "manifest_ordinal", "manifest_klv", "semantic_identity_sha256",
                "job_id", "point_ids",
            }, f"plan public manifest mapping {index}")
            ordinal = mapping["manifest_ordinal"]
            if (
                not isinstance(ordinal, int)
                or isinstance(ordinal, bool)
                or ordinal < 0
            ):
                raise CensusError("plan public manifest mapping has an invalid ordinal")
            validate_recorded_klv(
                mapping["manifest_klv"], f"plan public manifest mapping {index} KLV"
            )
            semantic_sha = require_hex64(
                mapping["semantic_identity_sha256"],
                f"plan public manifest mapping {index} semantic identity",
            )
            job_id = mapping["job_id"]
            point_ids_for_mapping = mapping["point_ids"]
            if not isinstance(job_id, str) or not job_id:
                raise CensusError("plan public manifest mapping has an invalid job ID")
            if (
                not isinstance(point_ids_for_mapping, list)
                or point_ids_for_mapping != sorted(set(point_ids_for_mapping))
                or not all(isinstance(value, str) and value for value in point_ids_for_mapping)
            ):
                raise CensusError("plan public manifest mapping has invalid point IDs")
            mapped_job = jobs_by_id.get(job_id)
            expected_semantic_sha = None if mapped_job is None else sha_bytes(canonical({
                "benchmark": mapped_job["benchmark"],
                "model": mapped_job["model"],
                "input": mapped_job["input"],
            }).encode())
            if semantic_sha != expected_semantic_sha:
                raise CensusError(
                    "plan public manifest mapping semantic identity differs from its job"
                )
            if (
                mapped_job is None
                or mapped_job["candidate_klv"] != mapping["manifest_klv"]
                or mapped_job["point_ids"] != point_ids_for_mapping
            ):
                raise CensusError(
                    "plan public manifest mapping differs from its sealed job topology"
                )
            semantic_ids.append(semantic_sha)
            mapped_jobs.append(job_id)
            manifest_klvs.append((
                mapping["manifest_klv"]["path"], mapping["manifest_klv"]["sha256"]
            ))
            ordinals.append(ordinal)
            entries_projection.append({
                "ordinal": ordinal,
                "klv": mapping["manifest_klv"],
                "semantic_identity_sha256": semantic_sha,
            })
        if semantic_ids != sorted(set(semantic_ids)):
            raise CensusError("plan public manifest semantic mappings are not canonical")
        if sorted(ordinals) != list(range(manifest["entry_count"])):
            raise CensusError("plan public manifest ordinal topology differs")
        if len(set(manifest_klvs)) != len(manifest_klvs):
            raise CensusError("plan public manifest repeats an exact KLV identity")
        if sorted(mapped_jobs) != job_ids or len(set(mapped_jobs)) != len(mapped_jobs):
            raise CensusError("plan public manifest does not map every canonical public job")
        entries_projection.sort(key=lambda row: row["ordinal"])
        if manifest["entries_sha256"] != sha_bytes(
            canonical(entries_projection).encode()
        ):
            raise CensusError("plan public manifest entries digest differs")
    return plan


def frozen_job_expectation_record(
    job: dict[str, object], all_points: list[dict[str, object]]
) -> dict[str, object]:
    """Select comparator authority first and retain cross-comparator diagnostics."""
    point_ids = set(job["point_ids"])
    points = [point for point in all_points if point["point_id"] in point_ids]
    if len(points) != len(point_ids):
        raise CensusError("runtime job frozen point set is incomplete")
    by_comparator: dict[str, dict[str, object]] = {}
    for point in points:
        expected = point["expected"]
        if (
            not isinstance(expected, int)
            or isinstance(expected, bool)
            or not 0 <= expected <= (1 << 64) - 1
        ):
            raise CensusError("runtime job expected value is not a frozen u64")
        comparator = point["comparator"]
        if comparator not in FROZEN_COMPARATOR_PREFERENCE:
            raise CensusError("runtime job names an unsupported frozen comparator")
        observation = by_comparator.setdefault(comparator, {
            "comparator": comparator,
            "expected_values": set(),
        })
        observation["expected_values"].add(expected)
    comparator = next(
        (name for name in FROZEN_COMPARATOR_PREFERENCE if name in by_comparator),
        None,
    )
    if comparator is None:
        raise CensusError("runtime job has no frozen comparator")
    selected_values = by_comparator[comparator]["expected_values"]
    if len(selected_values) != 1:
        raise CensusError(
            f"runtime job has conflicting frozen values within selected comparator {comparator}"
        )
    selected_expected = next(iter(selected_values))
    normalized_observations = []
    for name in FROZEN_COMPARATOR_PREFERENCE:
        if name not in by_comparator:
            continue
        raw = by_comparator[name]
        values = sorted(raw["expected_values"])
        normalized_observations.append({
            "comparator": name,
            "expected_values": values,
            "points": sorted(
                [
                    {"point_id": point["point_id"], "expected": point["expected"]}
                    for point in points if point["comparator"] == name
                ],
                key=lambda point: point["point_id"],
            ),
        })
    divergent = any(
        value != selected_expected
        for row in normalized_observations
        for value in row["expected_values"]
    )
    return {
        "job_id": job["job_id"],
        "selected_expected": selected_expected,
        "selected_comparator": comparator,
        "divergent": divergent,
        "observations": normalized_observations,
    }


def frozen_job_expectation(
    plan: dict[str, object], job: dict[str, object]
) -> tuple[int, str]:
    """Return the scalar selected by the first available frozen comparator."""
    record = frozen_job_expectation_record(job, plan["points"])
    return record["selected_expected"], record["selected_comparator"]


FROZEN_VALIDATION_FIELDS = {
    "validation_authority", "expected_value_sealed", "expected_value",
    "expected_comparator", "schedule_klv_sha256", "schedule_binding_sha256",
    "stock_comparator", "stock_divergence_policy",
}


def frozen_schedule_validation(fields: dict[str, str]) -> dict[str, object]:
    """Require the closed build/runtime binding used by formal qualification."""
    missing = FROZEN_VALIDATION_FIELDS - set(fields)
    if missing:
        raise CensusError(
            f"runner provenance omits frozen validation fields {sorted(missing)!r}"
        )
    if fields["validation_authority"] != "frozen-public-schedule-v1":
        raise CensusError("runner provenance is not frozen-schedule authoritative")
    if fields["expected_value_sealed"] != "true":
        raise CensusError("runner frozen expected value is not sealed")
    expected_text = fields["expected_value"]
    if re.fullmatch(r"0|[1-9][0-9]*", expected_text) is None:
        raise CensusError("runner frozen expected value is not canonical u64 decimal")
    expected_value = int(expected_text, 10)
    if expected_value > (1 << 64) - 1:
        raise CensusError("runner frozen expected value exceeds u64")
    expected_comparator = fields["expected_comparator"]
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/+:\-]{0,127}", expected_comparator) is None:
        raise CensusError("runner frozen expected comparator is not canonical")
    klv_sha256 = require_hex64(
        fields["schedule_klv_sha256"], "runner frozen schedule KLV digest"
    )
    binding_sha256 = require_hex64(
        fields["schedule_binding_sha256"], "runner frozen schedule binding digest"
    )
    if klv_sha256 == "0" * 64 or binding_sha256 == "0" * 64:
        raise CensusError("runner frozen schedule binding contains a zero digest")
    if fields["stock_comparator"] != "rust-regex-1.12.4":
        raise CensusError("runner stock diagnostic comparator differs")
    if fields["stock_divergence_policy"] != "report-only":
        raise CensusError("runner frozen stock divergence policy is not report-only")
    if fields.get("required_comparators") != f"{expected_comparator},fre-current-runtime":
        raise CensusError("runner frozen comparator set differs")
    return {
        "authority": fields["validation_authority"],
        "expected_value": expected_value,
        "expected_comparator": expected_comparator,
        "schedule_klv_sha256": klv_sha256,
        "schedule_binding_sha256": binding_sha256,
        "stock_comparator": fields["stock_comparator"],
        "stock_divergence_policy": fields["stock_divergence_policy"],
    }


def parse_provenance(output: bytes) -> dict[str, str]:
    try:
        text = output.decode("utf-8", "strict").strip()
    except UnicodeDecodeError as error:
        raise CensusError("runner provenance is not UTF-8") from error
    if "\n" in text:
        raise CensusError("runner provenance is not exactly one line")
    fields: dict[str, str] = {}
    for token in shlex.split(text):
        if "=" not in token:
            raise CensusError("runner provenance token has no equals sign")
        key, value = token.split("=", 1)
        if key in fields:
            raise CensusError(f"duplicate provenance field {key}")
        fields[key] = value
    common = {
        "schema", "configured", "adapter", "model", "benchmark", "source_commit",
        "source_tree", "target", "feature_bits",
    } | FROZEN_VALIDATION_FIELDS
    if fields.get("schema") == "fre.aot.rebar-runner.v2":
        required = common | {
            "engine", "aggregate_strategy", "prepared_bulk_strategy",
            "span_iteration_strategy", "grep_iteration_strategy", "program_sha256",
            "object_sha256", "program_symbol", "program_len", "entry_symbol", "reducer_symbol",
            "span_fill_symbol", "required_runtime_symbols", "entry_abi",
        }
    elif fields.get("schema") == "fre.aot.rebar-runner.v3":
        required = common | {
            "disposition", "compiler_version", "optimizer_version", "engine",
            "aggregate_strategy", "component_count", "boundary",
            "required_comparators",
        }
    elif fields.get("schema") == "fre.aot.rebar-runner.v4":
        required = common | {
            "disposition", "compiler_version", "optimizer_version", "engine",
            "aggregate_strategy", "native_row_bridge", "uniform_capture_bridge",
            "strict_capture_bridge", "source_pattern_count",
            "row_total_object_bytes", "source_to_artifact", "component_count",
            "capture_resolution", "boundary", "required_comparators",
        }
    elif fields.get("schema") == "fre.aot.rebar-runner.v5":
        required = common | {
            "disposition", "compiler_version", "optimizer_version", "engine",
            "aggregate_strategy", "native_row_bridge", "capture_reducer_bridge",
            "source_pattern_count", "operation", "domain", "source_route",
            "source_cardinality", "source_bytes", "source_pattern_sha256",
            "source_sha256", "group_count",
            "can_match_empty", "empty_progress", "semantic_runtime_calls",
            "caller_scratch_bytes", "private_participation_scratch_bytes",
            "private_iterator_state_bytes",
            "private_result_slot_count", "private_result_slot_bytes",
            "selector_sha256", "capture_sha256",
            "source_artifact_identity_sha256", "source_object_sha256",
            "reducer_symbol", "reducer_symbol_sha256", "object_sha256",
            "object_bytes", "max_object_bytes", "artifact_identity_sha256",
            "required_runtime_symbols", "operation_entry_symbol", "boundary",
            "required_comparators",
        }
    elif fields.get("schema") == "fre.aot.rebar-runner.v6":
        required = common | {
            "disposition", "compiler_version", "optimizer_version", "engine",
            "aggregate_strategy", "native_row_bridge", "uniform_capture_bridge",
            "weighted_capture_reducer_bridge", "weighted_receipt_schema",
            "source_pattern_count", "pattern_bytes", "row_total_object_bytes",
            "component_count", "source_to_component",
            "component_first_source_ordinals", "component_weights",
            "component_entry_symbols", "component_automaton_sha256",
            "component_program_sha256", "component_object_sha256",
            "capture_resolution", "capture_proof_algorithm_version",
            "capture_proof_accounting_version", "source_participating_groups",
            "source_minimum_match_bytes", "source_participating_user_captures",
            "source_capture_annotations", "source_proof_work",
            "source_proof_peak_stack_items", "source_selector_automaton_sha256",
            "source_selector_program_sha256", "source_selector_object_sha256",
            "line_terminator", "operation", "domain", "ordered_sources_sha256",
            "operation_identity_sha256", "reducer_symbol", "reducer_symbol_sha256",
            "reducer_code_sha256", "reducer_object_sha256", "reducer_object_bytes",
            "reducer_object_cap", "reducer_artifact_identity_sha256",
            "external_relocation_count", "external_relocation_components",
            "external_relocation_offsets", "external_relocation_kinds",
            "external_relocation_addends", "semantic_runtime_symbols", "boundary",
            "required_comparators",
        }
    else:
        raise CensusError(
            "runner provenance is neither scalar v2, composite v3, "
            "native-capture v4, single-capture reducer v5, nor weighted reducer v6"
        )
    missing = required - set(fields)
    if missing:
        raise CensusError(f"runner provenance omits {sorted(missing)!r}")
    if fields["configured"] != "true":
        raise CensusError("runner is not a configured public Rebar adapter")
    if fields["schema"] == "fre.aot.rebar-runner.v2":
        validate_v2_provenance(fields)
    elif fields["schema"] == "fre.aot.rebar-runner.v3":
        components = components_from_provenance(fields)
        validate_v3_provenance(fields, components)
    elif fields["schema"] == "fre.aot.rebar-runner.v4":
        components = components_from_provenance(fields)
        validate_v4_provenance(fields, components)
    elif fields["schema"] == "fre.aot.rebar-runner.v5":
        validate_v5_provenance(fields)
    else:
        validate_v6_provenance(fields)
    return fields


def validate_v2_provenance(fields: dict[str, str]) -> None:
    """Validate the complete scalar runner contract before normalizing it."""
    expected = {
        "schema", "disposition", "configured", "adapter", "model", "benchmark",
        "source_commit", "source_tree", "target", "feature_bits",
        "compiler_version", "optimizer_version", "engine", "aggregate_strategy",
        "prepared_bulk_strategy", "span_iteration_strategy", "grep_iteration_strategy",
        "shared_ordered_many", "source_pattern_count",
        "ordered_many_receipt_schema", "ordered_many_sources_sha256",
        "prepare_config_version", "prepare_operation_flags",
        "required_prepare_capabilities", "prepare_scope", "object_descriptor_setup",
        "max_start_filter_setup_work", "max_grep_count_workspace_bytes",
        "max_handle_bytes", "max_ordered_nfa_scratch_bytes",
        "max_ordered_nfa_setup_work", "program_sha256", "object_sha256",
        "program_symbol", "program_len", "entry_symbol", "reducer_symbol", "span_fill_symbol",
        "required_runtime_symbols", "entry_abi", "boundary", "required_comparators",
    } | FROZEN_VALIDATION_FIELDS
    if set(fields) != expected:
        raise CensusError(
            "runner v2 provenance field closure differs: "
            f"missing={sorted(expected - set(fields))!r} "
            f"extra={sorted(set(fields) - expected)!r}"
        )
    if fields["disposition"] != "executed":
        raise CensusError("scalar provenance disposition is not executed")
    if fields["shared_ordered_many"] not in {"true", "false"}:
        raise CensusError("scalar provenance has an invalid shared ordered-many flag")
    if fields["entry_abi"] not in {
        EXISTS_SEARCH_ENTRY_ABI, SPAN_SEARCH_ENTRY_ABI,
        PREPARED_SCALAR_REDUCE_ENTRY_ABI,
    }:
        raise CensusError("scalar provenance has an unknown entry ABI")
    if fields["entry_abi"] == EXISTS_SEARCH_ENTRY_ABI and not (
        fields.get("model") == "grep"
        and fields.get("aggregate_strategy") == "Some(NativeFused)"
    ):
        raise CensusError("Exists search ABI is attached to another scalar route")
    if fields["entry_abi"] == PREPARED_SCALAR_REDUCE_ENTRY_ABI and not (
        fields.get("aggregate_strategy") == "Some(NativeOrderedNfaFused)"
        and fields.get("model") in {
            "count", "count-spans", "count-captures", "grep", "grep-captures",
        }
        and (
            fields.get("shared_ordered_many") == "true"
            or fields.get("model") == "count"
            or fields.get("model") in UNIFORM_CAPTURE_ADAPTER_MODELS
            or fields.get("span_iteration_strategy")
            == NATIVE_SPAN_SUM_ITERATION_STRATEGY
            or (
                fields.get("model") == "grep"
                and fields.get("shared_ordered_many") == "false"
                and fields.get("required_prepare_capabilities")
                == f"{PREPARED_V15_CAPABILITY:016x}"
            )
        )
    ):
        raise CensusError("prepared scalar reducer ABI is attached to another route")
    frozen_schedule_validation(fields)
    if fields["prepare_scope"] != "runtime-handle-state" or fields[
        "object_descriptor_setup"
    ] != "authenticated-v3-when-required":
        raise CensusError("scalar provenance has a noncanonical prepare boundary")
    for name in ("compiler_version", "optimizer_version", "prepare_config_version"):
        try:
            value = int(fields[name], 10)
        except ValueError as error:
            raise CensusError(f"scalar provenance has invalid {name}") from error
        if value <= 0:
            raise CensusError(f"scalar provenance has nonpositive {name}")
    for name in ("feature_bits", "prepare_operation_flags", "required_prepare_capabilities"):
        if re.fullmatch(r"[0-9a-f]{16}", fields[name]) is None:
            raise CensusError(f"scalar provenance has invalid {name}")
    for name in (
        "max_start_filter_setup_work", "max_grep_count_workspace_bytes",
        "max_handle_bytes", "max_ordered_nfa_scratch_bytes", "max_ordered_nfa_setup_work",
    ):
        try:
            value = int(fields[name], 10)
        except ValueError as error:
            raise CensusError(f"scalar provenance has invalid {name}") from error
        if value < 0:
            raise CensusError(f"scalar provenance has negative {name}")
    require_hex64(fields["program_sha256"], "provenance program digest")
    require_hex64(fields["object_sha256"], "provenance object digest")
    require_hex64(
        fields["ordered_many_sources_sha256"],
        "provenance ordered-many source digest",
    )
    parse_canonical_decimal(
        fields["program_len"], "scalar runtime program length", 1,
        MAX_SERIALIZED_PROGRAM_BYTES,
    )
    for name in ("program_symbol", "entry_symbol"):
        if SYMBOL.fullmatch(fields[name]) is None:
            raise CensusError(f"scalar provenance has invalid {name}")
    for name in ("reducer_symbol", "span_fill_symbol"):
        if fields[name] and SYMBOL.fullmatch(fields[name]) is None:
            raise CensusError(f"scalar provenance has invalid {name}")
    runtime_symbols = list(filter(None, fields["required_runtime_symbols"].split(",")))
    if len(runtime_symbols) != len(set(runtime_symbols)) or not all(
        SYMBOL.fullmatch(symbol) for symbol in runtime_symbols
    ):
        raise CensusError("scalar provenance runtime symbol list is malformed")
    if fields["shared_ordered_many"] == "true":
        shared_ordered_many_proof(fields)
    else:
        source_count = parse_canonical_decimal(
            fields["source_pattern_count"], "scalar source_pattern_count", 1, 1
        )
        allowed_boundary = (
            {
                "single-call-native-uniform-capture-reducer",
                "single-call-native-uniform-capture-helper-backed-reducer",
            }
            if fields["model"] in UNIFORM_CAPTURE_ADAPTER_MODELS
            else {"runtime-klv-warmup-schedule"}
        )
        if (
            source_count != 1
            or fields["ordered_many_receipt_schema"] != "0"
            or fields["ordered_many_sources_sha256"] != "0" * 64
            or fields["boundary"] not in allowed_boundary
        ):
            raise CensusError("non-shared scalar provenance retains an ordered-many receipt")
    if fields["model"] == "grep":
        capabilities = int(fields["required_prepare_capabilities"], 16)
        if capabilities == PREPARED_V15_CAPABILITY:
            scalar_prepared_grep_v15_proof(fields)
        elif capabilities == 0:
            scalar_direct_native_grep_proof(fields)
        else:
            raise CensusError("scalar grep provenance requires unknown capabilities")
    elif (
        fields["model"] in UNIFORM_CAPTURE_ADAPTER_MODELS
        and fields["shared_ordered_many"] == "false"
    ):
        scalar_native_uniform_capture_proof(fields)
    elif fields["shared_ordered_many"] == "false" and (
        fields["model"] == "count" or (
            fields["model"] == "count-spans"
            and fields["span_iteration_strategy"]
            == NATIVE_SPAN_SUM_ITERATION_STRATEGY
        )
    ):
        scalar_native_reducer_proof_from_provenance(fields)


def symbol_identity_suffix(symbol: str, pattern: re.Pattern[str], context: str) -> str:
    if pattern.fullmatch(symbol) is None:
        raise CensusError(f"{context} has a noncanonical symbol")
    return symbol.rsplit("_", 1)[1]


def scalar_native_reducer_surface(
    model: object,
) -> tuple[str, str, re.Pattern[str], int, tuple[str, ...], str, str]:
    """Return the closed Count/SpanSum reducer surface for one scalar model."""
    route = {
        "count": (
            "general-aot-identity-suffixed-exclusive-count-prepared-v2",
            "general-aot-identity-suffixed-exclusive-count-prepared-v3-required-ordered-nfa-v15",
            NATIVE_COUNT_ENTRY_SYMBOL,
            PREPARED_V15_SPAN_OPERATION_FLAGS,
            PREPARED_V15_SHARED_COUNT_RUNTIME_SYMBOLS,
            "not-applicable",
            "linked-native-count-helper-backed-reducer",
        ),
        "count-spans": (
            "general-aot-linked-complete-spans-prepared-v2",
            "general-aot-linked-complete-spans-prepared-v3-required-ordered-nfa-v15",
            NATIVE_SPAN_SUM_ENTRY_SYMBOL,
            PREPARED_V15_SPAN_SUM_OPERATION_FLAGS,
            PREPARED_V15_SHARED_SPAN_SUM_RUNTIME_SYMBOLS,
            NATIVE_SPAN_SUM_ITERATION_STRATEGY,
            "linked-native-span-sum-helper-backed-reducer",
        ),
    }.get(model)
    if route is None:
        raise CensusError("scalar native reducer has an unsupported model")
    return route


def scalar_native_reducer_route(model: object, proof: object) -> str:
    """Select one exact scalar reducer policy from its authenticated topology."""
    if not isinstance(proof, dict):
        raise CensusError("scalar native reducer proof is not an object")
    variant = proof.get("route_variant")
    if model == "count" and variant in {"direct-v2", "ordered-v15-operation-only"}:
        return "linked-reducer"
    if model == "count-spans" and variant in {
        "direct-v2", "ordered-v15-operation-only",
    }:
        return "linked-span-sum-reducer"
    if model in {"count", "count-spans"} and variant == "ordered-v15":
        return scalar_native_reducer_surface(model)[6]
    raise CensusError("scalar native reducer has an unknown model or route variant")


def scalar_native_reducer_proof_from_provenance(
    fields: dict[str, str],
) -> dict[str, object]:
    """Authenticate a direct, compatibility V15, or operation-only V15 reducer."""
    model = fields.get("model")
    (
        direct_adapter,
        ordered_adapter,
        reducer_pattern,
        operation_flags,
        ordered_runtime_symbols,
        span_iteration,
        _,
    ) = scalar_native_reducer_surface(model)
    strategy = fields.get("aggregate_strategy")
    direct = strategy == "Some(NativeFused)"
    ordered = strategy == "Some(NativeOrderedNfaFused)"
    if not (direct or ordered):
        raise CensusError("scalar native reducer has a mixed or unknown aggregate strategy")
    if (
        fields.get("schema") != "fre.aot.rebar-runner.v2"
        or fields.get("adapter") != (direct_adapter if direct else ordered_adapter)
        or fields.get("shared_ordered_many") != "false"
        or fields.get("source_pattern_count") != "1"
        or fields.get("ordered_many_receipt_schema") != "0"
        or fields.get("ordered_many_sources_sha256") != "0" * 64
        or fields.get("prepare_scope") != "runtime-handle-state"
        or fields.get("object_descriptor_setup") != "authenticated-v3-when-required"
        or fields.get("max_start_filter_setup_work") != "100000000"
        or fields.get("max_grep_count_workspace_bytes") != "67108864"
        or fields.get("prepare_operation_flags") != f"{operation_flags:016x}"
        or fields.get("span_iteration_strategy") != span_iteration
        or fields.get("grep_iteration_strategy") != "not-applicable"
        or fields.get("boundary") != "runtime-klv-warmup-schedule"
    ):
        raise CensusError("scalar native reducer operation surface differs")
    require_hex64(fields.get("program_sha256"), "scalar native reducer program digest")
    require_hex64(fields.get("object_sha256"), "scalar native reducer object digest")
    runtime_symbols_text = fields.get("required_runtime_symbols")
    if not isinstance(runtime_symbols_text, str):
        raise CensusError("scalar native reducer runtime symbol list is malformed")
    runtime_symbols = tuple(sorted(filter(None, runtime_symbols_text.split(","))))
    entry_abi = fields.get("entry_abi")
    operation_only = ordered and entry_abi == PREPARED_SCALAR_REDUCE_ENTRY_ABI
    if direct:
        if (
            entry_abi != SPAN_SEARCH_ENTRY_ABI
            or fields.get("prepared_bulk_strategy") != "None"
            or fields.get("prepare_config_version") != str(PREPARED_V2_CONFIG_VERSION)
            or fields.get("required_prepare_capabilities") != f"{0:016x}"
            or fields.get("max_handle_bytes") != "0"
            or fields.get("max_ordered_nfa_scratch_bytes") != "0"
            or fields.get("max_ordered_nfa_setup_work") != "0"
            or fields.get("span_fill_symbol") != ""
            or runtime_symbols
        ):
            raise CensusError("helper-free scalar NativeFused reducer envelope differs")
        route_variant = "direct-v2"
        span_fill_identity = None
    elif operation_only:
        if (
            fields.get("engine") != "OrderedNfa"
            or fields.get("prepared_bulk_strategy") != "None"
            or fields.get("prepare_config_version") != str(PREPARED_V15_CONFIG_VERSION)
            or fields.get("required_prepare_capabilities")
            != f"{PREPARED_V15_CAPABILITY:016x}"
            or fields.get("max_handle_bytes") != str(PREPARED_V15_MAX_HANDLE_BYTES)
            or fields.get("max_ordered_nfa_scratch_bytes")
            != str(PREPARED_V15_MAX_SCRATCH_BYTES)
            or fields.get("max_ordered_nfa_setup_work")
            != str(PREPARED_V15_MAX_SETUP_WORK)
            or fields.get("span_fill_symbol") != ""
            or runtime_symbols
        ):
            raise CensusError("operation-only scalar Ordered-NFA V15 envelope differs")
        route_variant = "ordered-v15-operation-only"
        span_fill_identity = None
    else:
        span_fill = fields.get("span_fill_symbol")
        if not isinstance(span_fill, str):
            raise CensusError("helper-backed scalar reducer SpanFill symbol is malformed")
        span_fill_identity = symbol_identity_suffix(
            span_fill,
            NATIVE_SPAN_FILL_ENTRY_SYMBOL,
            "helper-backed scalar reducer SpanFill entry",
        )
        if (
            entry_abi != SPAN_SEARCH_ENTRY_ABI
            or fields.get("engine") != "OrderedNfa"
            or fields.get("prepared_bulk_strategy") != "Some(NativeOrderedNfaLoop)"
            or fields.get("prepare_config_version") != str(PREPARED_V15_CONFIG_VERSION)
            or fields.get("required_prepare_capabilities")
            != f"{PREPARED_V15_CAPABILITY:016x}"
            or fields.get("max_handle_bytes") != str(PREPARED_V15_MAX_HANDLE_BYTES)
            or fields.get("max_ordered_nfa_scratch_bytes")
            != str(PREPARED_V15_MAX_SCRATCH_BYTES)
            or fields.get("max_ordered_nfa_setup_work")
            != str(PREPARED_V15_MAX_SETUP_WORK)
            or runtime_symbols != ordered_runtime_symbols
        ):
            raise CensusError("helper-backed scalar Ordered-NFA V15 reducer envelope differs")
        route_variant = "ordered-v15"
    entry = fields.get("entry_symbol")
    program = fields.get("program_symbol")
    reducer = fields.get("reducer_symbol")
    if not all(isinstance(symbol, str) for symbol in (entry, program, reducer)):
        raise CensusError("scalar native reducer symbols are malformed")
    entry_identity = symbol_identity_suffix(
        entry,
        reducer_pattern if operation_only else NATIVE_SEARCH_ENTRY_SYMBOL,
        (
            "operation-only scalar native reducer entry"
            if operation_only else "scalar native reducer ordinary entry"
        ),
    )
    program_identity = symbol_identity_suffix(
        program, NATIVE_RUNTIME_PROGRAM_SYMBOL, "scalar native reducer runtime program"
    )
    reducer_identity = symbol_identity_suffix(
        reducer, reducer_pattern, "scalar native reducer operation entry"
    )
    if operation_only:
        if entry != reducer or program_identity != reducer_identity:
            raise CensusError(
                "operation-only scalar reducer entry/program identities disagree"
            )
    elif len({entry, program, reducer}) != 3:
        raise CensusError("scalar native reducer symbols are not distinct")
    return {
        "route_variant": route_variant,
        "required_prepare_capabilities": parse_fixed_hex_u64(
            fields.get("required_prepare_capabilities"),
            "scalar native reducer prepare capabilities",
        ),
        "prepare_config_version": parse_canonical_decimal(
            fields.get("prepare_config_version"),
            "scalar native reducer prepare config version",
        ),
        "prepare_operation_flags": parse_fixed_hex_u64(
            fields.get("prepare_operation_flags"),
            "scalar native reducer operation flags",
        ),
        "max_handle_bytes": parse_canonical_decimal(
            fields.get("max_handle_bytes"), "scalar native reducer handle cap"
        ),
        "max_scratch_bytes": parse_canonical_decimal(
            fields.get("max_ordered_nfa_scratch_bytes"),
            "scalar native reducer scratch cap",
        ),
        "max_setup_work": parse_canonical_decimal(
            fields.get("max_ordered_nfa_setup_work"),
            "scalar native reducer setup-work cap",
        ),
        "runtime_program_len": parse_canonical_decimal(
            fields.get("program_len"),
            "scalar native reducer runtime program length",
            1,
            MAX_SERIALIZED_PROGRAM_BYTES,
        ),
        "entry_identity_sha256": entry_identity,
        "program_identity_sha256": program_identity,
        "reducer_identity_sha256": reducer_identity,
        "span_fill_identity_sha256": span_fill_identity,
    }


def scalar_direct_native_grep_proof(fields: dict[str, str]) -> None:
    """Authenticate the helper-free whole-operation direct GrepCount route."""
    if (
        fields.get("model") != "grep"
        or fields.get("entry_abi") != EXISTS_SEARCH_ENTRY_ABI
        or fields.get("adapter")
        != "general-aot-linked-native-grep-count-reducer-prepared-v2"
        or fields.get("aggregate_strategy") != "Some(NativeFused)"
        or fields.get("prepared_bulk_strategy") != "None"
        or fields.get("span_iteration_strategy") != "not-applicable"
        or fields.get("grep_iteration_strategy")
        != "linked-native-grep-count-reducer-v1"
        or fields.get("prepare_config_version") != "2"
        or fields.get("prepare_operation_flags") != f"{1 << 3:016x}"
        or fields.get("required_prepare_capabilities") != f"{0:016x}"
        or fields.get("max_handle_bytes") != "0"
        or fields.get("max_ordered_nfa_scratch_bytes") != "0"
        or fields.get("max_ordered_nfa_setup_work") != "0"
        or fields.get("span_fill_symbol") != ""
        or fields.get("required_runtime_symbols") != ""
    ):
        raise CensusError("scalar direct native grep has a noncanonical route")
    entry_suffix = symbol_identity_suffix(
        fields["entry_symbol"], NATIVE_SEARCH_ENTRY_SYMBOL,
        "scalar direct native grep entry",
    )
    reducer_suffix = symbol_identity_suffix(
        fields["reducer_symbol"], NATIVE_GREP_COUNT_ENTRY_SYMBOL,
        "scalar direct native grep reducer",
    )
    program_suffix = symbol_identity_suffix(
        fields["program_symbol"], NATIVE_RUNTIME_PROGRAM_SYMBOL,
        "scalar direct native grep runtime program",
    )
    if reducer_suffix != program_suffix or reducer_suffix == entry_suffix:
        raise CensusError("scalar direct native grep symbol identities disagree")


def scalar_native_uniform_capture_proof(
    fields: dict[str, str],
) -> dict[str, object]:
    """Authenticate the single-call uniform-capture reducer surface."""
    model = fields.get("model")
    if model == "count-captures":
        adapter = "general-aot-native-uniform-capture-count-reducer-v1"
        reducer_pattern = NATIVE_COUNT_CAPTURES_ENTRY_SYMBOL
        grep_iteration = "not-applicable"
    elif model == "grep-captures":
        adapter = "general-aot-native-uniform-capture-grep-reducer-v1"
        reducer_pattern = NATIVE_GREP_CAPTURES_ENTRY_SYMBOL
        grep_iteration = "linked-native-uniform-capture-reducer-v1"
    else:
        raise CensusError("uniform-capture reducer has a non-capture model")
    entry_abi = fields.get("entry_abi")
    operation_only = entry_abi == PREPARED_SCALAR_REDUCE_ENTRY_ABI
    if (
        fields.get("adapter") != adapter
        or fields.get("span_iteration_strategy") != "not-applicable"
        or fields.get("grep_iteration_strategy") != grep_iteration
        or fields.get("prepare_operation_flags")
        != f"{PREPARED_V15_SPAN_OPERATION_FLAGS:016x}"
    ):
        raise CensusError("uniform-capture reducer operation surface differs")
    entry = fields["entry_symbol"]
    program = fields["program_symbol"]
    reducer = fields["reducer_symbol"]
    entry_identity = symbol_identity_suffix(
        entry,
        NATIVE_COUNT_ENTRY_SYMBOL if operation_only else NATIVE_SEARCH_ENTRY_SYMBOL,
        (
            "operation-only uniform capture Count child"
            if operation_only else "uniform capture search child"
        ),
    )
    program_identity = symbol_identity_suffix(
        program, NATIVE_RUNTIME_PROGRAM_SYMBOL, "uniform capture program"
    )
    reducer_identity = symbol_identity_suffix(
        reducer, reducer_pattern, "uniform capture reducer"
    )
    if len({entry, program, reducer}) != 3:
        raise CensusError("uniform-capture reducer symbols are not distinct")
    direct = fields.get("aggregate_strategy") == "Some(NativeFused)"
    ordered = fields.get("aggregate_strategy") == "Some(NativeOrderedNfaFused)"
    runtime_symbols = sorted(filter(None, fields["required_runtime_symbols"].split(",")))
    if direct:
        if (
            entry_abi != SPAN_SEARCH_ENTRY_ABI
            or fields.get("boundary") != "single-call-native-uniform-capture-reducer"
            or fields.get("prepare_config_version") != "2"
            or fields.get("required_prepare_capabilities") != f"{0:016x}"
            or fields.get("prepared_bulk_strategy") != "None"
            or fields.get("span_fill_symbol") != ""
            or runtime_symbols != []
            or fields.get("max_handle_bytes") != "0"
            or fields.get("max_ordered_nfa_scratch_bytes") != "0"
            or fields.get("max_ordered_nfa_setup_work") != "0"
            or fields.get("max_start_filter_setup_work") != "100000000"
            or fields.get("max_grep_count_workspace_bytes") != "67108864"
        ):
            raise CensusError("helper-free uniform-capture reducer route differs")
        route_variant = "direct-v1"
        span_fill_identity = None
    elif ordered and operation_only:
        if (
            fields.get("boundary") != "single-call-native-uniform-capture-reducer"
            or fields.get("engine") != "OrderedNfa"
            or fields.get("prepare_config_version")
            != str(PREPARED_V15_CONFIG_VERSION)
            or fields.get("required_prepare_capabilities")
            != f"{PREPARED_V15_CAPABILITY:016x}"
            or fields.get("prepared_bulk_strategy") != "None"
            or fields.get("span_fill_symbol") != ""
            or runtime_symbols
            or fields.get("max_handle_bytes") != str(PREPARED_V15_MAX_HANDLE_BYTES)
            or fields.get("max_ordered_nfa_scratch_bytes")
            != str(PREPARED_V15_MAX_SCRATCH_BYTES)
            or fields.get("max_ordered_nfa_setup_work")
            != str(PREPARED_V15_MAX_SETUP_WORK)
            or fields.get("max_start_filter_setup_work") != "100000000"
            or fields.get("max_grep_count_workspace_bytes") != "67108864"
            or entry_identity != program_identity
            or reducer_identity == entry_identity
        ):
            raise CensusError("operation-only uniform-capture V15 route differs")
        route_variant = "ordered-v15-operation-only"
        span_fill_identity = None
    elif ordered:
        span_fill_identity = symbol_identity_suffix(
            fields["span_fill_symbol"],
            NATIVE_SPAN_FILL_ENTRY_SYMBOL,
            "uniform capture SpanFill entry",
        )
        if (
            entry_abi != SPAN_SEARCH_ENTRY_ABI
            or fields.get("boundary")
            != "single-call-native-uniform-capture-helper-backed-reducer"
            or fields.get("engine") != "OrderedNfa"
            or fields.get("prepare_config_version")
            != str(PREPARED_V15_CONFIG_VERSION)
            or fields.get("required_prepare_capabilities")
            != f"{PREPARED_V15_CAPABILITY:016x}"
            or fields.get("prepared_bulk_strategy") != "Some(NativeOrderedNfaLoop)"
            or NATIVE_SPAN_FILL_ENTRY_SYMBOL.fullmatch(fields["span_fill_symbol"])
            is None
            or runtime_symbols != list(PREPARED_V15_SHARED_COUNT_RUNTIME_SYMBOLS)
            or fields.get("max_handle_bytes") != str(PREPARED_V15_MAX_HANDLE_BYTES)
            or fields.get("max_ordered_nfa_scratch_bytes")
            != str(PREPARED_V15_MAX_SCRATCH_BYTES)
            or fields.get("max_ordered_nfa_setup_work")
            != str(PREPARED_V15_MAX_SETUP_WORK)
            or fields.get("max_start_filter_setup_work") != "100000000"
            or fields.get("max_grep_count_workspace_bytes") != "67108864"
        ):
            raise CensusError("helper-backed uniform-capture reducer route differs")
        route_variant = "ordered-v15"
    else:
        raise CensusError("uniform-capture reducer has a non-native aggregate")
    return {
        "route_variant": route_variant,
        "required_prepare_capabilities": int(
            fields["required_prepare_capabilities"], 16
        ),
        "prepare_config_version": int(fields["prepare_config_version"], 10),
        "prepare_operation_flags": int(fields["prepare_operation_flags"], 16),
        "max_handle_bytes": int(fields["max_handle_bytes"], 10),
        "max_scratch_bytes": int(fields["max_ordered_nfa_scratch_bytes"], 10),
        "max_setup_work": int(fields["max_ordered_nfa_setup_work"], 10),
        "runtime_program_len": parse_canonical_decimal(
            fields.get("program_len"),
            "uniform capture runtime program length",
            1,
            MAX_SERIALIZED_PROGRAM_BYTES,
        ),
        "entry_identity_sha256": entry_identity,
        "program_identity_sha256": program_identity,
        "reducer_identity_sha256": reducer_identity,
        "span_fill_identity_sha256": span_fill_identity,
    }


def scalar_prepared_grep_v15_proof(fields: dict[str, str]) -> dict[str, object]:
    """Authenticate the exact scalar native V15 GrepCount route."""
    if (
        fields.get("model") != "grep"
        or fields.get("adapter")
        != "general-aot-linked-native-grep-count-reducer-prepared-v3-required-ordered-nfa-v15"
        or fields.get("engine") != "OrderedNfa"
        or fields.get("aggregate_strategy")
        != "Some(NativeOrderedNfaFused)"
        or fields.get("span_iteration_strategy") != "not-applicable"
        or fields.get("grep_iteration_strategy")
        != "linked-native-grep-count-reducer-v1"
        or fields.get("prepare_config_version") != str(PREPARED_V15_CONFIG_VERSION)
        or fields.get("prepare_operation_flags")
        != f"{PREPARED_V15_SPAN_OPERATION_FLAGS:016x}"
        or fields.get("required_prepare_capabilities")
        != f"{PREPARED_V15_CAPABILITY:016x}"
        or fields.get("max_start_filter_setup_work") != "100000000"
        or fields.get("max_grep_count_workspace_bytes") != "67108864"
        or fields.get("max_handle_bytes") != str(PREPARED_V15_MAX_HANDLE_BYTES)
        or fields.get("max_ordered_nfa_scratch_bytes")
        != str(PREPARED_V15_MAX_SCRATCH_BYTES)
        or fields.get("max_ordered_nfa_setup_work")
        != str(PREPARED_V15_MAX_SETUP_WORK)
    ):
        raise CensusError("scalar prepared V15 grep has a noncanonical route or cap")
    program_suffix = symbol_identity_suffix(
        fields["program_symbol"], NATIVE_RUNTIME_PROGRAM_SYMBOL,
        "scalar prepared V15 runtime program",
    )
    reducer_suffix = symbol_identity_suffix(
        fields["reducer_symbol"], NATIVE_GREP_COUNT_ENTRY_SYMBOL,
        "scalar prepared V15 native reducer",
    )
    runtime_symbols = tuple(sorted(filter(
        None, fields["required_runtime_symbols"].split(",")
    )))
    if fields.get("entry_abi") == SPAN_SEARCH_ENTRY_ABI:
        entry_suffix = symbol_identity_suffix(
            fields["entry_symbol"], NATIVE_SEARCH_ENTRY_SYMBOL,
            "scalar prepared V15 ordinary entry",
        )
        span_fill_suffix = symbol_identity_suffix(
            fields["span_fill_symbol"], NATIVE_SPAN_FILL_ENTRY_SYMBOL,
            "scalar prepared V15 SpanFill entry",
        )
        if (
            fields.get("prepared_bulk_strategy")
            != "Some(NativeOrderedNfaLoop)"
            or runtime_symbols != PREPARED_V15_SCALAR_GREP_RUNTIME_SYMBOLS
            or len({entry_suffix, span_fill_suffix, program_suffix}) != 1
            or reducer_suffix == entry_suffix
        ):
            raise CensusError("scalar prepared V15 compatibility topology differs")
        artifact_identity = entry_suffix
    elif fields.get("entry_abi") == PREPARED_SCALAR_REDUCE_ENTRY_ABI:
        entry_suffix = symbol_identity_suffix(
            fields["entry_symbol"], NATIVE_GREP_COUNT_ENTRY_SYMBOL,
            "scalar prepared V15 operation entry",
        )
        if (
            fields.get("prepared_bulk_strategy") != "None"
            or fields.get("span_fill_symbol") != ""
            or runtime_symbols
            or fields["entry_symbol"] != fields["reducer_symbol"]
            or len({entry_suffix, program_suffix, reducer_suffix}) != 1
        ):
            raise CensusError("scalar prepared V15 operation-only topology differs")
        artifact_identity = entry_suffix
    else:
        raise CensusError("scalar prepared V15 entry ABI differs")
    return {
        "required_prepare_capabilities": PREPARED_V15_CAPABILITY,
        "prepare_config_version": PREPARED_V15_CONFIG_VERSION,
        "prepare_operation_flags": PREPARED_V15_SPAN_OPERATION_FLAGS,
        "max_handle_bytes": PREPARED_V15_MAX_HANDLE_BYTES,
        "max_scratch_bytes": PREPARED_V15_MAX_SCRATCH_BYTES,
        "max_setup_work": PREPARED_V15_MAX_SETUP_WORK,
        "runtime_program_len": parse_canonical_decimal(
            fields.get("program_len"), "scalar prepared V15 runtime program length",
            1, MAX_SERIALIZED_PROGRAM_BYTES,
        ),
        "artifact_identity_sha256": artifact_identity,
        "reducer_identity_sha256": reducer_suffix,
    }


def shared_ordered_many_native_fused_proof(
    fields: dict[str, str],
) -> dict[str, object]:
    """Authenticate one helper-free ordinary shared Count/SpanSum reducer."""
    route = {
        "count": (
            "general-aot-shared-ordered-many-native-count-v1",
            NATIVE_COUNT_ENTRY_SYMBOL,
            PREPARED_V15_SPAN_OPERATION_FLAGS,
            "not-applicable",
        ),
        "count-spans": (
            "general-aot-shared-ordered-many-native-span-sum-v1",
            NATIVE_SPAN_SUM_ENTRY_SYMBOL,
            PREPARED_V15_SPAN_SUM_OPERATION_FLAGS,
            "linked-shared-ordered-many-native-span-sum-reducer-v1",
            "not-applicable",
            "single-call-shared-ordered-many-helper-free-native-reducer",
            False,
        ),
        "count-captures": (
            "general-aot-shared-uniform-capture-count-reducer-v1",
            NATIVE_COUNT_CAPTURES_ENTRY_SYMBOL,
            PREPARED_V15_SPAN_OPERATION_FLAGS,
            "not-applicable",
            "not-applicable",
            "single-call-shared-uniform-capture-helper-free-native-reducer",
            True,
        ),
        "grep-captures": (
            "general-aot-shared-uniform-capture-grep-reducer-v1",
            NATIVE_GREP_CAPTURES_ENTRY_SYMBOL,
            PREPARED_V15_SPAN_OPERATION_FLAGS,
            "not-applicable",
            "linked-native-uniform-capture-reducer-v1",
            "single-call-shared-uniform-capture-helper-free-native-reducer",
            True,
        ),
    }.get(fields.get("model"))
    if route is None:
        raise CensusError("shared NativeFused provenance has an unsupported model")
    if len(route) == 4:
        adapter, reducer_pattern, operation_flags, span_iteration = route
        grep_iteration = "not-applicable"
        boundary = "single-call-shared-ordered-many-helper-free-native-reducer"
        capture = False
    else:
        (
            adapter, reducer_pattern, operation_flags, span_iteration,
            grep_iteration, boundary, capture,
        ) = route
    source_count = parse_canonical_decimal(
        fields.get("source_pattern_count"),
        "shared NativeFused source_pattern_count",
        2,
        MAX_NATIVE_ROW_COMPONENTS,
    )
    receipt_schema = parse_canonical_decimal(
        fields.get("ordered_many_receipt_schema"),
        "shared NativeFused receipt schema",
        ORDERED_MANY_RECEIPT_VERSION,
        ORDERED_MANY_RECEIPT_VERSION,
    )
    ordered_sources = fields.get("ordered_many_sources_sha256", "")
    require_hex64(ordered_sources, "shared NativeFused source digest")
    if ordered_sources == "0" * 64:
        raise CensusError("shared NativeFused source digest is zero")
    if (
        fields.get("shared_ordered_many") != "true"
        or fields.get("entry_abi") != SPAN_SEARCH_ENTRY_ABI
        or fields.get("adapter") != adapter
        or fields.get("aggregate_strategy") != "Some(NativeFused)"
        or fields.get("span_iteration_strategy") != span_iteration
        or fields.get("grep_iteration_strategy") != grep_iteration
        or fields.get("prepare_config_version") != str(PREPARED_V2_CONFIG_VERSION)
        or fields.get("prepare_operation_flags") != f"{operation_flags:016x}"
        or fields.get("required_prepare_capabilities") != f"{0:016x}"
        or fields.get("max_start_filter_setup_work") != "100000000"
        or fields.get("max_grep_count_workspace_bytes") != "67108864"
        or fields.get("max_handle_bytes") != "0"
        or fields.get("max_ordered_nfa_scratch_bytes") != "0"
        or fields.get("max_ordered_nfa_setup_work") != "0"
        or fields.get("required_runtime_symbols") != ""
        or fields.get("boundary") != boundary
    ):
        raise CensusError("shared NativeFused provenance has a noncanonical route or cap")
    entry_suffix = symbol_identity_suffix(
        fields["entry_symbol"], NATIVE_SEARCH_ENTRY_SYMBOL,
        "shared NativeFused ordinary entry",
    )
    program_suffix = symbol_identity_suffix(
        fields["program_symbol"], NATIVE_RUNTIME_PROGRAM_SYMBOL,
        "shared NativeFused runtime program",
    )
    reducer_suffix = symbol_identity_suffix(
        fields["reducer_symbol"], reducer_pattern,
        "shared NativeFused reducer",
    )
    bulk = fields.get("prepared_bulk_strategy")
    span_fill = fields.get("span_fill_symbol", "")
    if capture and bulk != "None":
        raise CensusError("shared capture NativeFused route retains a bulk loop")
    if bulk == "None":
        if span_fill:
            raise CensusError("direct shared NativeFused route retains SpanFill")
    elif bulk in {"Some(NativePreparedLoop)", "Some(NativeFrozenLoop)"}:
        span_fill_suffix = symbol_identity_suffix(
            span_fill, NATIVE_SPAN_FILL_ENTRY_SYMBOL,
            "shared NativeFused SpanFill entry",
        )
        if len({entry_suffix, span_fill_suffix, program_suffix}) != 1:
            raise CensusError("prepared shared NativeFused identities disagree")
    else:
        raise CensusError("shared NativeFused route has a non-native bulk strategy")
    return {
        "route_variant": "native-fused-v2",
        "receipt_schema_version": receipt_schema,
        "source_pattern_count": source_count,
        "ordered_sources_sha256": ordered_sources,
        "required_prepare_capabilities": 0,
        "prepare_config_version": PREPARED_V2_CONFIG_VERSION,
        "prepare_operation_flags": operation_flags,
        "max_handle_bytes": 0,
        "max_scratch_bytes": 0,
        "max_setup_work": 0,
        "runtime_program_len": int(fields["program_len"], 10),
        "artifact_identity_sha256": entry_suffix,
        "reducer_identity_sha256": reducer_suffix,
    }


def shared_ordered_many_v15_proof(fields: dict[str, str]) -> dict[str, object]:
    """Authenticate one compatibility or operation-only combined V15 reducer."""
    route = {
        "count": (
            "general-aot-shared-ordered-many-native-count-v1",
            NATIVE_COUNT_ENTRY_SYMBOL,
            PREPARED_V15_SPAN_OPERATION_FLAGS,
            PREPARED_V15_SHARED_COUNT_RUNTIME_SYMBOLS,
            "not-applicable",
        ),
        "count-spans": (
            "general-aot-shared-ordered-many-native-span-sum-v1",
            NATIVE_SPAN_SUM_ENTRY_SYMBOL,
            PREPARED_V15_SPAN_SUM_OPERATION_FLAGS,
            PREPARED_V15_SHARED_SPAN_SUM_RUNTIME_SYMBOLS,
            "linked-shared-ordered-many-native-span-sum-reducer-v1",
            NATIVE_SPAN_SUM_ENTRY_SYMBOL,
            "not-applicable",
            "single-call-shared-ordered-many-helper-free-native-reducer",
            False,
        ),
        "count-captures": (
            "general-aot-shared-uniform-capture-count-reducer-v1",
            NATIVE_COUNT_CAPTURES_ENTRY_SYMBOL,
            PREPARED_V15_SPAN_OPERATION_FLAGS,
            (),
            "not-applicable",
            NATIVE_COUNT_ENTRY_SYMBOL,
            "not-applicable",
            "single-call-shared-uniform-capture-helper-free-native-reducer",
            True,
        ),
        "grep-captures": (
            "general-aot-shared-uniform-capture-grep-reducer-v1",
            NATIVE_GREP_CAPTURES_ENTRY_SYMBOL,
            PREPARED_V15_SPAN_OPERATION_FLAGS,
            (),
            "not-applicable",
            NATIVE_COUNT_ENTRY_SYMBOL,
            "linked-native-uniform-capture-reducer-v1",
            "single-call-shared-uniform-capture-helper-free-native-reducer",
            True,
        ),
    }.get(fields.get("model"))
    if route is None:
        raise CensusError("shared ordered-many provenance has an unsupported model")
    if len(route) == 5:
        adapter, reducer_pattern, operation_flags, runtime_symbols, span_iteration = route
        operation_entry_pattern = reducer_pattern
        grep_iteration = "not-applicable"
        helper_free_boundary = "single-call-shared-ordered-many-helper-free-native-reducer"
        capture = False
    else:
        (
            adapter, reducer_pattern, operation_flags, runtime_symbols,
            span_iteration, operation_entry_pattern, grep_iteration,
            helper_free_boundary, capture,
        ) = route
    source_count = parse_canonical_decimal(
        fields.get("source_pattern_count"),
        "shared ordered-many source_pattern_count",
        2,
        MAX_NATIVE_ROW_COMPONENTS,
    )
    receipt_schema = parse_canonical_decimal(
        fields.get("ordered_many_receipt_schema"),
        "shared ordered-many receipt schema",
        ORDERED_MANY_RECEIPT_VERSION,
        ORDERED_MANY_RECEIPT_VERSION,
    )
    ordered_sources = fields.get("ordered_many_sources_sha256", "")
    require_hex64(ordered_sources, "shared ordered-many source digest")
    if ordered_sources == "0" * 64:
        raise CensusError("shared ordered-many source digest is zero")
    operation_only = fields.get("entry_abi") == PREPARED_SCALAR_REDUCE_ENTRY_ABI
    if capture and not operation_only:
        raise CensusError("shared capture V15 route is not operation-only")
    if (
        fields.get("shared_ordered_many") != "true"
        or fields.get("adapter") != adapter
        or fields.get("engine") != "OrderedNfa"
        or fields.get("aggregate_strategy") != "Some(NativeOrderedNfaFused)"
        or fields.get("span_iteration_strategy") != span_iteration
        or fields.get("grep_iteration_strategy") != grep_iteration
        or fields.get("prepare_config_version") != str(PREPARED_V15_CONFIG_VERSION)
        or fields.get("prepare_operation_flags") != f"{operation_flags:016x}"
        or fields.get("required_prepare_capabilities")
        != f"{PREPARED_V15_CAPABILITY:016x}"
        or fields.get("max_start_filter_setup_work") != "100000000"
        or fields.get("max_grep_count_workspace_bytes") != "67108864"
        or fields.get("max_handle_bytes") != str(PREPARED_V15_MAX_HANDLE_BYTES)
        or fields.get("max_ordered_nfa_scratch_bytes")
        != str(PREPARED_V15_MAX_SCRATCH_BYTES)
        or fields.get("max_ordered_nfa_setup_work")
        != str(PREPARED_V15_MAX_SETUP_WORK)
    ):
        raise CensusError("shared ordered-many provenance has a noncanonical route or cap")
    actual_runtime_symbols = tuple(sorted(filter(
        None, fields.get("required_runtime_symbols", "").split(",")
    )))
    if operation_only:
        if (
            fields.get("prepared_bulk_strategy") != "None"
            or fields.get("span_fill_symbol") != ""
            or actual_runtime_symbols
            or fields.get("boundary")
            != helper_free_boundary
        ):
            raise CensusError("operation-only shared V15 topology differs")
    elif (
        fields.get("entry_abi") != SPAN_SEARCH_ENTRY_ABI
        or fields.get("prepared_bulk_strategy") != "Some(NativeOrderedNfaLoop)"
        or actual_runtime_symbols != runtime_symbols
        or fields.get("boundary")
        != "single-call-shared-ordered-many-helper-backed-reducer"
    ):
        raise CensusError("compatibility shared V15 topology differs")
    entry_suffix = symbol_identity_suffix(
        fields["entry_symbol"],
        operation_entry_pattern if operation_only else NATIVE_SEARCH_ENTRY_SYMBOL,
        (
            "operation-only shared ordered-many entry"
            if operation_only else "shared ordered-many ordinary entry"
        ),
    )
    program_suffix = symbol_identity_suffix(
        fields["program_symbol"], NATIVE_RUNTIME_PROGRAM_SYMBOL,
        "shared ordered-many runtime program",
    )
    reducer_suffix = symbol_identity_suffix(
        fields["reducer_symbol"], reducer_pattern,
        "shared ordered-many reducer",
    )
    if operation_only:
        identities_close = (
            entry_suffix == program_suffix
            and (
                (capture and reducer_suffix != entry_suffix)
                or (not capture and reducer_suffix == entry_suffix)
            )
            and ((fields["entry_symbol"] != fields["reducer_symbol"]) == capture)
        )
        if not identities_close:
            raise CensusError("operation-only shared V15 identities disagree")
        route_variant = "ordered-v15-operation-only"
    else:
        span_fill_suffix = symbol_identity_suffix(
            fields["span_fill_symbol"], NATIVE_SPAN_FILL_ENTRY_SYMBOL,
            "shared ordered-many SpanFill entry",
        )
        if (
            len({entry_suffix, span_fill_suffix, program_suffix}) != 1
            or reducer_suffix == entry_suffix
        ):
            raise CensusError("shared ordered-many symbol identities disagree")
        route_variant = "ordered-v15"
    return {
        "route_variant": route_variant,
        "receipt_schema_version": receipt_schema,
        "source_pattern_count": source_count,
        "ordered_sources_sha256": ordered_sources,
        "required_prepare_capabilities": PREPARED_V15_CAPABILITY,
        "prepare_config_version": PREPARED_V15_CONFIG_VERSION,
        "prepare_operation_flags": operation_flags,
        "max_handle_bytes": PREPARED_V15_MAX_HANDLE_BYTES,
        "max_scratch_bytes": PREPARED_V15_MAX_SCRATCH_BYTES,
        "max_setup_work": PREPARED_V15_MAX_SETUP_WORK,
        "runtime_program_len": int(fields["program_len"], 10),
        "artifact_identity_sha256": entry_suffix,
        "reducer_identity_sha256": reducer_suffix,
    }


def shared_ordered_many_proof(fields: dict[str, str]) -> dict[str, object]:
    """Authenticate the exact ordinary or V15 shared reducer variant."""
    strategy = fields.get("aggregate_strategy")
    if strategy == "Some(NativeFused)":
        return shared_ordered_many_native_fused_proof(fields)
    if strategy == "Some(NativeOrderedNfaFused)":
        return shared_ordered_many_v15_proof(fields)
    raise CensusError("shared ordered-many provenance has an unknown aggregate strategy")


def component_field(fields: dict[str, str], index: int, suffixes: tuple[str, ...]) -> str:
    # Decimal and zero-padded ordinals coincide at ten and above. Preserve
    # compatibility with every accepted spelling without counting an
    # identical field name twice when checking the closed provenance surface.
    prefixes = tuple(dict.fromkeys(
        (f"component_{index}_", f"component_{index:02d}_", f"component{index}_")
    ))
    candidates = [
        f"{prefix}{suffix}" for prefix in prefixes for suffix in suffixes
        if f"{prefix}{suffix}" in fields
    ]
    if len(candidates) != 1:
        raise CensusError(
            f"composite provenance component {index} requires exactly one {suffixes!r} field"
        )
    return fields[candidates[0]]


def optional_component_field(
    fields: dict[str, str], index: int, suffixes: tuple[str, ...]
) -> Optional[str]:
    """Read one additive component field without weakening alias closure."""
    prefixes = tuple(dict.fromkeys(
        (f"component_{index}_", f"component_{index:02d}_", f"component{index}_")
    ))
    candidates = [
        f"{prefix}{suffix}" for prefix in prefixes for suffix in suffixes
        if f"{prefix}{suffix}" in fields
    ]
    if len(candidates) > 1:
        raise CensusError(
            f"composite provenance component {index} has multiple {suffixes!r} fields"
        )
    return fields[candidates[0]] if candidates else None


def components_from_provenance(fields: dict[str, str]) -> list[dict[str, object]]:
    schema = fields.get("schema")
    if schema not in {"fre.aot.rebar-runner.v3", "fre.aot.rebar-runner.v4"}:
        return []
    count = parse_canonical_decimal(
        fields.get("component_count"),
        "composite component_count",
        1,
        MAX_NATIVE_ROW_COMPONENTS,
    )
    if fields.get("model") == "regex-redux" and count != 15:
        raise CensusError(f"regex-redux must publish exactly 15 components, got {count}")
    if schema == "fre.aot.rebar-runner.v4" and count != 1:
        raise CensusError(f"native-capture v4 must publish exactly one component, got {count}")
    native_row = fields.get("native_row_bridge") == "true"
    has_automaton = schema == "fre.aot.rebar-runner.v3" and native_row
    components = []
    component_surface_presence = []
    for index in range(count):
        native = component_field(fields, index, ("native",))
        entry = component_field(fields, index, ("entry_symbol",))
        runtime_text = component_field(
            fields, index, ("required_runtime_symbols", "runtime_symbols")
        )
        program_sha256 = component_field(fields, index, ("program_sha256",))
        object_sha256 = component_field(fields, index, ("object_sha256",))
        automaton_sha256 = (
            component_field(fields, index, ("automaton_sha256",))
            if has_automaton else None
        )
        if native != "true":
            raise CensusError(f"composite component {index} is not claimed native")
        if SYMBOL.fullmatch(entry) is None:
            raise CensusError(f"composite component {index} has invalid entry symbol")
        require_hex64(program_sha256, f"component {index} program digest")
        require_hex64(object_sha256, f"component {index} object digest")
        if automaton_sha256 is not None:
            require_hex64(automaton_sha256, f"component {index} automaton digest")
        runtime_symbols = sorted(filter(None, runtime_text.split(",")))
        if len(runtime_symbols) != len(set(runtime_symbols)) or not all(
            SYMBOL.fullmatch(symbol) for symbol in runtime_symbols
        ):
            raise CensusError(f"component {index} runtime symbol list is malformed")
        source_ordinal = None
        prepared_v15 = None
        entry_abi = None
        prepared_surface = None
        if native_row:
            source_ordinal_text = component_field(fields, index, ("source_ordinal",))
            source_ordinal = parse_canonical_decimal(
                source_ordinal_text,
                f"composite component {index} source ordinal",
                0,
                MAX_NATIVE_ROW_COMPONENTS - 1,
            )
            if schema == "fre.aot.rebar-runner.v3":
                entry_abi = optional_component_field(fields, index, ("entry_abi",))
                prepared_surface = optional_component_field(
                    fields, index, ("prepared_surface",)
                )
                if (entry_abi is None) != (prepared_surface is None):
                    raise CensusError(
                        f"native-row component {index} has a partial ABI/surface receipt"
                    )
                component_surface_presence.append(entry_abi is not None)
                prepared_v15 = prepared_v15_component_from_provenance(
                    fields, index, entry, runtime_symbols, entry_abi, prepared_surface
                )
        components.append({
            "ordinal": index,
            "native": True,
            "source_ordinal": source_ordinal,
            "entry_symbol": entry,
            "required_runtime_symbols": runtime_symbols,
            "automaton_sha256": automaton_sha256,
            "program_sha256": program_sha256,
            "object_sha256": object_sha256,
            **({
                "entry_abi": entry_abi,
                "prepared_surface": prepared_surface,
            } if entry_abi is not None else {}),
            **({"prepared_v15": prepared_v15} if schema == "fre.aot.rebar-runner.v3"
               and native_row else {}),
        })
    if component_surface_presence and any(component_surface_presence) and not all(
        component_surface_presence
    ):
        raise CensusError("native-row ABI/surface receipt is only partially populated")
    return components


def parse_canonical_decimal(
    text: object, context: str, minimum: int = 0, maximum: int = (1 << 64) - 1
) -> int:
    """Parse the runner's canonical unsigned decimal spelling."""
    if not isinstance(text, str) or re.fullmatch(r"0|[1-9][0-9]*", text) is None:
        raise CensusError(f"{context} is not canonical unsigned decimal")
    value = int(text, 10)
    if value < minimum or value > maximum:
        raise CensusError(f"{context} is outside {minimum}..={maximum}")
    return value


def parse_fixed_hex_u64(text: object, context: str) -> int:
    if not isinstance(text, str) or re.fullmatch(r"[0-9a-f]{16}", text) is None:
        raise CensusError(f"{context} is not fixed-width lowercase hexadecimal")
    return int(text, 16)


def prepared_v15_component_from_provenance(
    fields: dict[str, str],
    index: int,
    entry_symbol: str,
    runtime_symbols: list[str],
    entry_abi: Optional[str] = None,
    prepared_surface: Optional[str] = None,
) -> Optional[dict[str, object]]:
    """Close one native-row component's ordinary or prepared V15 state."""
    capabilities = parse_fixed_hex_u64(
        component_field(fields, index, ("required_prepare_capabilities",)),
        f"component {index} required prepare capabilities",
    )
    config_version = parse_canonical_decimal(
        component_field(fields, index, ("prepare_config_version",)),
        f"component {index} prepare config version", 0, (1 << 32) - 1,
    )
    operation_flags = parse_fixed_hex_u64(
        component_field(fields, index, ("prepare_operation_flags",)),
        f"component {index} prepare operation flags",
    )
    runtime_program_symbol = component_field(
        fields, index, ("runtime_program_symbol",)
    )
    runtime_program_len = parse_canonical_decimal(
        component_field(fields, index, ("runtime_program_len",)),
        f"component {index} runtime program length", 0, MAX_SERIALIZED_PROGRAM_BYTES,
    )
    span_fill_symbol = component_field(fields, index, ("span_fill_symbol",))
    bulk_strategy = component_field(fields, index, ("prepared_bulk_strategy",))
    if capabilities == 0:
        if (
            (entry_abi is not None and entry_abi != SPAN_SEARCH_ENTRY_ABI)
            or (prepared_surface is not None and prepared_surface != NO_PREPARED_SURFACE)
            or
            config_version != 0
            or operation_flags != 0
            or runtime_program_symbol
            or runtime_program_len != 0
            or span_fill_symbol
            or bulk_strategy != "None"
            or runtime_symbols
            or NATIVE_SEARCH_ENTRY_SYMBOL.fullmatch(entry_symbol) is None
        ):
            raise CensusError(
                f"ordinary native-row component {index} advertises prepared/helper state"
            )
        return None
    if capabilities != PREPARED_V15_CAPABILITY:
        raise CensusError(f"native-row component {index} requires unknown capabilities")
    if entry_abi is None:
        legacy_compatibility = True
        strict_row_search = False
    else:
        legacy_compatibility = (
            entry_abi == SPAN_SEARCH_ENTRY_ABI
            and prepared_surface == PREPARED_V15_COMPATIBILITY_SURFACE
        )
        strict_row_search = (
            entry_abi == PREPARED_SPAN_SEARCH_ENTRY_ABI
            and prepared_surface == PREPARED_V15_ROW_SEARCH_SURFACE
        )
        if not legacy_compatibility and not strict_row_search:
            raise CensusError(
                f"prepared V15 component {index} has an unknown ABI/surface pair"
            )
    if (
        config_version != PREPARED_V15_CONFIG_VERSION
        or operation_flags != PREPARED_V15_SPAN_OPERATION_FLAGS
        or runtime_program_len == 0
    ):
        raise CensusError(f"prepared V15 component {index} has a noncanonical ABI closure")
    entry_suffix = symbol_identity_suffix(
        entry_symbol, NATIVE_SEARCH_EXCLUSIVE_ENTRY_SYMBOL,
        f"prepared V15 component {index} entry",
    )
    program_suffix = symbol_identity_suffix(
        runtime_program_symbol, NATIVE_RUNTIME_PROGRAM_SYMBOL,
        f"prepared V15 component {index} runtime program",
    )
    if legacy_compatibility:
        span_fill_suffix = symbol_identity_suffix(
            span_fill_symbol, NATIVE_SPAN_FILL_ENTRY_SYMBOL,
            f"prepared V15 component {index} SpanFill",
        )
        if (
            bulk_strategy != "Some(NativeOrderedNfaLoop)"
            or tuple(runtime_symbols) != PREPARED_V15_RUNTIME_SYMBOLS
            or len({entry_suffix, program_suffix, span_fill_suffix}) != 1
        ):
            raise CensusError(
                f"prepared V15 component {index} compatibility closure differs"
            )
    elif (
        bulk_strategy != "None"
        or runtime_symbols
        or span_fill_symbol
        or entry_suffix != program_suffix
    ):
        raise CensusError(
            f"prepared V15 component {index} strict RowSearch closure differs"
        )
    result = {
        "required_prepare_capabilities": capabilities,
        "prepare_config_version": config_version,
        "prepare_operation_flags": operation_flags,
        "runtime_program_symbol": runtime_program_symbol,
        "runtime_program_len": runtime_program_len,
        "span_fill_symbol": span_fill_symbol,
        "prepared_bulk_strategy": bulk_strategy,
        "artifact_identity_sha256": entry_suffix,
    }
    if entry_abi is not None:
        result["entry_abi"] = entry_abi
        result["prepared_surface"] = prepared_surface
    return result


def prepared_v15_component_route(component: dict[str, object]) -> int:
    """Return the reducer route tag authenticated by one normalized component."""
    prepared = component.get("prepared_v15")
    if prepared is None:
        return 0
    if (
        isinstance(prepared, dict)
        and prepared.get("entry_abi") == PREPARED_SPAN_SEARCH_ENTRY_ABI
        and prepared.get("prepared_surface") == PREPARED_V15_ROW_SEARCH_SURFACE
    ):
        return 2
    return 1


def every_prepared_component_is_strict(components: list[dict[str, object]]) -> bool:
    """True only for a mixed table whose every prepared child is RowSearch-only."""
    prepared = [
        component.get("prepared_v15") for component in components
        if component.get("prepared_v15") is not None
    ]
    return bool(prepared) and all(
        isinstance(proof, dict)
        and proof.get("entry_abi") == PREPARED_SPAN_SEARCH_ENTRY_ABI
        and proof.get("prepared_surface") == PREPARED_V15_ROW_SEARCH_SURFACE
        for proof in prepared
    )


def parse_canonical_decimal_list(
    text: object,
    context: str,
    count: int,
    minimum: int = 0,
    maximum: int = (1 << 64) - 1,
) -> list[int]:
    if not isinstance(text, str):
        raise CensusError(f"{context} is not a decimal list")
    values = text.split(",") if text else []
    if len(values) != count:
        raise CensusError(f"{context} cardinality differs from source_pattern_count")
    return [
        parse_canonical_decimal(value, f"{context}[{index}]", minimum, maximum)
        for index, value in enumerate(values)
    ]


def parse_digest_list(text: object, context: str, count: int) -> list[str]:
    if not isinstance(text, str):
        raise CensusError(f"{context} is not a digest list")
    values = text.split(",") if text else []
    if len(values) != count:
        raise CensusError(f"{context} cardinality differs from source_pattern_count")
    return [require_hex64(value, f"{context}[{index}]") for index, value in enumerate(values)]


def native_row_topology(
    fields: dict[str, str], components: list[dict[str, object]], minimum_sources: int
) -> tuple[int, int, list[int]]:
    source_count = parse_canonical_decimal(
        fields.get("source_pattern_count"),
        "native-row source_pattern_count",
        minimum_sources,
        MAX_NATIVE_ROW_COMPONENTS,
    )
    object_bytes = parse_canonical_decimal(
        fields.get("row_total_object_bytes"),
        "native-row row_total_object_bytes",
        1,
        MAX_NATIVE_ROW_OBJECT_BYTES,
    )
    source_to_artifact = parse_canonical_decimal_list(
        fields.get("source_to_artifact"),
        "native-row source_to_artifact",
        source_count,
        0,
        max(0, len(components) - 1),
    )
    if set(source_to_artifact) != set(range(len(components))):
        raise CensusError("native-row source-to-artifact map is not surjective")
    first_sources = [source_to_artifact.index(index) for index in range(len(components))]
    if first_sources != sorted(first_sources):
        raise CensusError("native-row component priority is not source ordered")
    if [component["source_ordinal"] for component in components] != first_sources:
        raise CensusError("native-row component source ordinals differ from its map")
    return source_count, object_bytes, source_to_artifact


def row_scalar_reducer_proof_from_provenance(
    fields: dict[str, str],
    components: list[dict[str, object]],
    source_count: int,
    row_object_bytes: int,
    source_to_artifact: list[int],
) -> dict[str, object]:
    """Authenticate the single-call Count/SpanSum row wrapper."""
    model = fields.get("model")
    operation = {"count": "count", "count-spans": "span-sum"}.get(model)
    mixed_text = fields.get("row_scalar_reducer_mixed_handle_table")
    if mixed_text not in {"true", "false"}:
        raise CensusError("row-scalar mixed-handle receipt is not canonical")
    mixed_handle_table = mixed_text == "true"
    has_prepared = any(component.get("prepared_v15") is not None
                       for component in components)
    adapter = ({
        "count": "general-aot-native-row-count-mixed-prepared-whole-operation-reducer-v1",
        "count-spans": (
            "general-aot-native-row-span-sum-mixed-prepared-whole-operation-reducer-v1"
        ),
    } if mixed_handle_table else {
        "count": "general-aot-native-row-count-whole-operation-reducer-v1",
        "count-spans": (
            "general-aot-native-row-span-sum-whole-operation-reducer-v1"
        ),
    }).get(model)
    aggregate_strategy = (
        "native-independent-mixed-span-row-whole-scalar-reducer-v1"
        if mixed_handle_table else
        "native-independent-span-row-whole-scalar-reducer-v1"
    )
    boundary = (
        "single-call-native-mixed-row-scalar-reducer"
        if mixed_handle_table else
        "single-call-helper-free-native-row-scalar-reducer"
    )
    if (
        operation is None
        or mixed_handle_table != has_prepared
        or fields.get("native_row_scalar_reducer") != "true"
        or fields.get("adapter") != adapter
        or fields.get("aggregate_strategy") != aggregate_strategy
        or fields.get("boundary") != boundary
        or fields.get("row_scalar_reducer_operation") != operation
    ):
        raise CensusError("row-scalar reducer has a noncanonical typed route")
    abi_version = parse_canonical_decimal(
        fields.get("row_scalar_reducer_abi_version"),
        "row-scalar reducer ABI version", 1, 1,
    )
    source_cardinality = parse_canonical_decimal(
        fields.get("row_scalar_reducer_source_cardinality"),
        "row-scalar reducer source cardinality", source_count, source_count,
    )
    required_handle_count = parse_canonical_decimal(
        fields.get("row_scalar_reducer_required_handle_count"),
        "row-scalar reducer required handle count",
        len(components) if mixed_handle_table else 0,
        len(components) if mixed_handle_table else 0,
    )
    row_routes = parse_canonical_decimal_list(
        fields.get("row_scalar_reducer_row_routes"),
        "row-scalar reducer row routes", len(components), 0, 2,
    )
    expected_routes = [
        prepared_v15_component_route(component)
        for component in components
    ]
    if row_routes != expected_routes:
        raise CensusError("row-scalar reducer route vector differs from its components")
    source_bytes = parse_canonical_decimal(
        fields.get("row_scalar_reducer_source_bytes"),
        "row-scalar reducer source bytes", 0, MAX_PUBLIC_KLV_BYTES,
    )
    semantic_runtime_calls = parse_canonical_decimal(
        fields.get("row_scalar_reducer_semantic_runtime_calls"),
        "row-scalar reducer semantic runtime calls", 0, 0,
    )
    object_bytes = parse_canonical_decimal(
        fields.get("row_scalar_reducer_object_bytes"),
        "row-scalar reducer object bytes", 1, MAX_NATIVE_ROW_OBJECT_BYTES,
    )
    max_object_bytes = parse_canonical_decimal(
        fields.get("row_scalar_reducer_max_object_bytes"),
        "row-scalar reducer maximum object bytes", 1, MAX_NATIVE_ROW_OBJECT_BYTES,
    )
    if (
        max_object_bytes != MAX_NATIVE_ROW_OBJECT_BYTES - row_object_bytes
        or object_bytes > max_object_bytes
        or row_object_bytes + object_bytes > MAX_NATIVE_ROW_OBJECT_BYTES
    ):
        raise CensusError("row-scalar reducer object envelope differs")
    ordered_sources_sha256 = require_nonzero_hex64(
        fields.get("row_scalar_reducer_ordered_sources_sha256"),
        "row-scalar ordered source digest",
    )
    operation_identity_sha256 = require_nonzero_hex64(
        fields.get("row_scalar_reducer_operation_identity_sha256"),
        "row-scalar operation identity",
    )
    code_sha256 = require_nonzero_hex64(
        fields.get("row_scalar_reducer_code_sha256"),
        "row-scalar reducer code digest",
    )
    object_sha256 = require_nonzero_hex64(
        fields.get("row_scalar_reducer_object_sha256"),
        "row-scalar reducer object digest",
    )
    artifact_identity_sha256 = require_nonzero_hex64(
        fields.get("row_scalar_reducer_artifact_identity_sha256"),
        "row-scalar artifact identity",
    )
    reducer_symbol = fields.get("row_scalar_reducer_symbol")
    if not isinstance(reducer_symbol, str):
        raise CensusError("row-scalar reducer symbol is absent")
    symbol_identity = symbol_identity_suffix(
        reducer_symbol,
        (NATIVE_MIXED_ROW_SCALAR_REDUCER_SYMBOL if mixed_handle_table
         else NATIVE_ROW_SCALAR_REDUCER_SYMBOL),
        "row-scalar reducer symbol",
    )

    relocation_count = parse_canonical_decimal(
        fields.get("row_scalar_reducer_relocation_count"),
        "row-scalar reducer relocation count", len(components), len(components),
    )
    relocation_sections = parse_canonical_decimal_list(
        fields.get("row_scalar_reducer_relocation_sections"),
        "row-scalar relocation sections", relocation_count, 0, 0,
    )
    relocation_offsets = parse_canonical_decimal_list(
        fields.get("row_scalar_reducer_relocation_offsets"),
        "row-scalar relocation offsets", relocation_count,
    )
    relocation_symbols = parse_canonical_decimal_list(
        fields.get("row_scalar_reducer_relocation_symbols"),
        "row-scalar relocation symbols", relocation_count, 1, relocation_count,
    )
    relocation_kinds = parse_canonical_decimal_list(
        fields.get("row_scalar_reducer_relocation_kinds"),
        "row-scalar relocation kinds", relocation_count, 0, 255,
    )
    relocation_addends = parse_canonical_signed_decimal_list(
        fields.get("row_scalar_reducer_relocation_addends"),
        "row-scalar relocation addends", relocation_count,
    )
    target = fields.get("target", "")
    architecture = target_architecture(target)
    if target.endswith("-linux"):
        operating_system = "linux"
    elif target.endswith("-macos"):
        operating_system = "macos"
    else:
        raise CensusError("row-scalar reducer target operating system differs")
    expected_kind = {"x86_64": 1, "aarch64": 4}[architecture]
    expected_addend = {"x86_64": -4, "aarch64": 0}[architecture]
    if (
        relocation_offsets != sorted(set(relocation_offsets))
        or relocation_symbols != list(range(1, relocation_count + 1))
        or relocation_kinds != [expected_kind] * relocation_count
        or relocation_addends != [expected_addend] * relocation_count
    ):
        raise CensusError("row-scalar reducer relocation closure differs")

    feature_bits = fields.get("feature_bits", "")
    if re.fullmatch(r"[0-9a-f]{16}", feature_bits) is None:
        raise CensusError("row-scalar reducer feature bits are not canonical")
    target_bytes = bytes((
        {"x86_64": 0, "aarch64": 1}[architecture],
        {"linux": 0, "macos": 1}[operating_system],
        {"x86_64": 0, "aarch64": 1}[architecture],
    ))
    operation_digest = hashlib.sha256()
    operation_digest.update(
        b"fre-aot-regex/rebar-mixed-native-row-scalar-reducer/v1\0"
        if mixed_handle_table else
        b"fre-aot-regex/rebar-native-row-scalar-reducer/v1\0"
    )
    operation_digest.update(abi_version.to_bytes(4, "little"))
    operation_digest.update(bytes((1 if operation == "count" else 2,)))
    operation_digest.update(target_bytes)
    operation_digest.update(int(feature_bits, 16).to_bytes(8, "little"))
    operation_digest.update(source_cardinality.to_bytes(8, "little"))
    operation_digest.update(source_bytes.to_bytes(8, "little"))
    operation_digest.update(bytes.fromhex(ordered_sources_sha256))
    operation_digest.update(len(source_to_artifact).to_bytes(8, "little"))
    for row in source_to_artifact:
        operation_digest.update(row.to_bytes(8, "little"))
    operation_digest.update(len(components).to_bytes(8, "little"))
    for row, component in enumerate(components):
        first_source = component.get("source_ordinal")
        entry_symbol = component.get("entry_symbol")
        if not isinstance(first_source, int) or not isinstance(entry_symbol, str):
            raise CensusError("row-scalar reducer row identity is malformed")
        operation_digest.update(first_source.to_bytes(8, "little"))
        if mixed_handle_table:
            operation_digest.update(bytes((row_routes[row],)))
        entry_bytes = entry_symbol.encode("ascii", "strict")
        operation_digest.update(len(entry_bytes).to_bytes(8, "little"))
        operation_digest.update(entry_bytes)
        for digest_name in (
            "automaton_sha256", "program_sha256", "object_sha256",
        ):
            operation_digest.update(bytes.fromhex(require_nonzero_hex64(
                component.get(digest_name), f"row-scalar row {digest_name}",
            )))
    if operation_identity_sha256 != operation_digest.hexdigest():
        raise CensusError("row-scalar operation identity does not authenticate its closure")
    if symbol_identity != operation_identity_sha256:
        raise CensusError("row-scalar reducer symbol does not bind operation identity")

    artifact = hashlib.sha256()
    artifact.update(
        b"fre-aot-regex/rebar-mixed-native-row-scalar-reducer-artifact/v1\0"
        if mixed_handle_table else
        b"fre-aot-regex/rebar-native-row-scalar-reducer-artifact/v1\0"
    )
    artifact.update(bytes.fromhex(operation_identity_sha256))
    symbol_bytes = reducer_symbol.encode("ascii", "strict")
    artifact.update(len(symbol_bytes).to_bytes(8, "little"))
    artifact.update(symbol_bytes)
    artifact.update(bytes.fromhex(code_sha256))
    artifact.update(bytes.fromhex(object_sha256))
    artifact.update(relocation_count.to_bytes(8, "little"))
    for section, offset, kind, symbol, addend in zip(
        relocation_sections, relocation_offsets, relocation_kinds,
        relocation_symbols, relocation_addends,
    ):
        artifact.update(section.to_bytes(8, "little"))
        artifact.update(offset.to_bytes(8, "little"))
        artifact.update(bytes((kind,)))
        artifact.update(symbol.to_bytes(8, "little"))
        artifact.update(addend.to_bytes(8, "little", signed=True))
    artifact.update(object_bytes.to_bytes(8, "little"))
    artifact.update(max_object_bytes.to_bytes(8, "little"))
    if mixed_handle_table:
        artifact.update(len(row_routes).to_bytes(8, "little"))
        artifact.update(bytes(row_routes))
    if artifact_identity_sha256 != artifact.hexdigest():
        raise CensusError("row-scalar artifact identity does not authenticate its receipt")
    return {
        "abi_version": abi_version,
        "operation": operation,
        "mixed_handle_table": mixed_handle_table,
        "required_handle_count": required_handle_count,
        "row_routes": row_routes,
        "source_cardinality": source_cardinality,
        "source_bytes": source_bytes,
        "ordered_sources_sha256": ordered_sources_sha256,
        "operation_identity_sha256": operation_identity_sha256,
        "reducer_symbol": reducer_symbol,
        "code_sha256": code_sha256,
        "object_sha256": object_sha256,
        "relocation_count": relocation_count,
        "relocation_sections": relocation_sections,
        "relocation_offsets": relocation_offsets,
        "relocation_kinds": relocation_kinds,
        "relocation_symbols": relocation_symbols,
        "relocation_addends": relocation_addends,
        "semantic_runtime_calls": semantic_runtime_calls,
        "object_bytes": object_bytes,
        "max_object_bytes": max_object_bytes,
        "artifact_identity_sha256": artifact_identity_sha256,
    }


def validate_normalized_row_scalar_reducer(
    proof: object, provenance: dict[str, object], context: str
) -> dict[str, object]:
    """Re-authenticate a normalized row-scalar reducer receipt."""
    if not isinstance(proof, dict):
        raise CensusError(f"{context} proof is not an object")
    require_exact_keys(proof, {
        "abi_version", "operation", "mixed_handle_table",
        "required_handle_count", "row_routes", "source_cardinality", "source_bytes",
        "ordered_sources_sha256", "operation_identity_sha256",
        "reducer_symbol", "code_sha256", "object_sha256", "relocation_count",
        "relocation_sections", "relocation_offsets", "relocation_kinds",
        "relocation_symbols", "relocation_addends", "semantic_runtime_calls",
        "object_bytes", "max_object_bytes", "artifact_identity_sha256",
    }, f"{context} proof")
    if not isinstance(proof["mixed_handle_table"], bool):
        raise CensusError(f"{context} mixed-handle flag is not boolean")
    components = provenance.get("components")
    source_count = provenance.get("source_pattern_count")
    source_map = provenance.get("source_to_artifact")
    row_object_bytes = provenance.get("row_total_object_bytes")
    if (
        not isinstance(components, list) or not components
        or not isinstance(source_count, int) or isinstance(source_count, bool)
        or source_count < 2
        or not isinstance(source_map, list) or len(source_map) != source_count
        or not isinstance(row_object_bytes, int) or isinstance(row_object_bytes, bool)
        or not 0 < row_object_bytes <= MAX_NATIVE_ROW_OBJECT_BYTES
        or any(
            not isinstance(row, int) or isinstance(row, bool)
            or row < 0 or row >= len(components) for row in source_map
        )
        or set(source_map) != set(range(len(components)))
    ):
        raise CensusError(f"{context} source/row topology differs")
    fake_fields = {
        "native_row_scalar_reducer": "true",
        "model": str(provenance.get("model", "")),
        "adapter": str(provenance.get("adapter", "")),
        "aggregate_strategy": str(provenance.get("aggregate_strategy", "")),
        "boundary": str(provenance.get("boundary", "")),
        "target": str(provenance.get("target", "")),
        "feature_bits": str(provenance.get("feature_bits", "")),
        "row_scalar_reducer_abi_version": str(proof["abi_version"]),
        "row_scalar_reducer_operation": str(proof["operation"]),
        "row_scalar_reducer_mixed_handle_table": (
            "true" if proof["mixed_handle_table"] else "false"
        ),
        "row_scalar_reducer_required_handle_count": str(
            proof["required_handle_count"]
        ),
        "row_scalar_reducer_row_routes": ",".join(
            str(value) for value in proof["row_routes"]
        ),
        "row_scalar_reducer_source_cardinality": str(proof["source_cardinality"]),
        "row_scalar_reducer_source_bytes": str(proof["source_bytes"]),
        "row_scalar_reducer_ordered_sources_sha256": str(
            proof["ordered_sources_sha256"]
        ),
        "row_scalar_reducer_symbol": str(proof["reducer_symbol"]),
        "row_scalar_reducer_operation_identity_sha256": str(
            proof["operation_identity_sha256"]
        ),
        "row_scalar_reducer_code_sha256": str(proof["code_sha256"]),
        "row_scalar_reducer_object_sha256": str(proof["object_sha256"]),
        "row_scalar_reducer_relocation_count": str(proof["relocation_count"]),
        "row_scalar_reducer_relocation_sections": ",".join(
            str(value) for value in proof["relocation_sections"]
        ),
        "row_scalar_reducer_relocation_offsets": ",".join(
            str(value) for value in proof["relocation_offsets"]
        ),
        "row_scalar_reducer_relocation_kinds": ",".join(
            str(value) for value in proof["relocation_kinds"]
        ),
        "row_scalar_reducer_relocation_symbols": ",".join(
            str(value) for value in proof["relocation_symbols"]
        ),
        "row_scalar_reducer_relocation_addends": ",".join(
            str(value) for value in proof["relocation_addends"]
        ),
        "row_scalar_reducer_semantic_runtime_calls": str(
            proof["semantic_runtime_calls"]
        ),
        "row_scalar_reducer_object_bytes": str(proof["object_bytes"]),
        "row_scalar_reducer_max_object_bytes": str(proof["max_object_bytes"]),
        "row_scalar_reducer_artifact_identity_sha256": str(
            proof["artifact_identity_sha256"]
        ),
    }
    expected = row_scalar_reducer_proof_from_provenance(
        fake_fields, components, source_count, row_object_bytes, source_map
    )
    if proof != expected:
        raise CensusError(f"{context} proof normalization differs")
    return expected


def multi_grep_reducer_proof_from_provenance(
    fields: dict[str, str],
    components: list[dict[str, object]],
    source_count: int,
    row_object_bytes: int,
    source_to_artifact: list[int],
) -> dict[str, object]:
    """Authenticate the ordinary or mixed whole-operation multi-Grep receipt."""
    mixed_text = fields.get("multi_grep_reducer_mixed_handle_table")
    if mixed_text not in {"true", "false"}:
        raise CensusError("multi-grep mixed-handle receipt is not canonical")
    mixed_handle_table = mixed_text == "true"
    has_prepared = any(component.get("prepared_v15") is not None
                       for component in components)
    adapter = (
        "general-aot-native-mixed-prepared-ordered-nfa-v15-"
        "multi-grep-whole-operation-reducer-v1"
        if mixed_handle_table else
        "general-aot-native-multi-grep-whole-operation-reducer-v1"
    )
    aggregate_strategy = (
        "native-independent-mixed-prepared-span-row-whole-grep-reducer-v1"
        if mixed_handle_table else
        "native-independent-span-row-whole-grep-reducer-v1"
    )
    boundary = (
        "single-call-native-mixed-multi-grep-reducer"
        if mixed_handle_table else
        "single-call-helper-free-native-multi-grep-reducer"
    )
    if (
        fields.get("native_multi_grep_reducer") != "true"
        or fields.get("model") != "grep"
        or mixed_handle_table != has_prepared
        or fields.get("adapter") != adapter
        or fields.get("aggregate_strategy") != aggregate_strategy
        or fields.get("boundary") != boundary
    ):
        raise CensusError("multi-grep reducer has a noncanonical typed route")
    abi_version = parse_canonical_decimal(
        fields.get("multi_grep_reducer_abi_version"),
        "multi-grep reducer ABI version", 1, 1,
    )
    source_cardinality = parse_canonical_decimal(
        fields.get("multi_grep_reducer_source_cardinality"),
        "multi-grep reducer source cardinality", source_count, source_count,
    )
    required_handle_count = parse_canonical_decimal(
        fields.get("multi_grep_reducer_required_handle_count"),
        "multi-grep reducer required handle count",
        len(components) if mixed_handle_table else 0,
        len(components) if mixed_handle_table else 0,
    )
    row_routes = parse_canonical_decimal_list(
        fields.get("multi_grep_reducer_row_routes"),
        "multi-grep reducer row routes", len(components), 0, 2,
    )
    expected_routes = [
        prepared_v15_component_route(component)
        for component in components
    ]
    if row_routes != expected_routes:
        raise CensusError("multi-grep reducer route vector differs from its components")
    source_bytes = parse_canonical_decimal(
        fields.get("multi_grep_reducer_source_bytes"),
        "multi-grep reducer source bytes", 0, MAX_PUBLIC_KLV_BYTES,
    )
    relocation_count = parse_canonical_decimal(
        fields.get("multi_grep_reducer_relocation_count"),
        "multi-grep reducer relocation count", len(components), len(components),
    )
    semantic_runtime_calls = parse_canonical_decimal(
        fields.get("multi_grep_reducer_semantic_runtime_calls"),
        "multi-grep reducer semantic runtime calls", 0, 0,
    )
    object_bytes = parse_canonical_decimal(
        fields.get("multi_grep_reducer_object_bytes"),
        "multi-grep reducer object bytes", 1, MAX_NATIVE_ROW_OBJECT_BYTES,
    )
    max_object_bytes = parse_canonical_decimal(
        fields.get("multi_grep_reducer_max_object_bytes"),
        "multi-grep reducer maximum object bytes", 1, MAX_NATIVE_ROW_OBJECT_BYTES,
    )
    if (
        max_object_bytes != MAX_NATIVE_ROW_OBJECT_BYTES - row_object_bytes
        or object_bytes > max_object_bytes
        or row_object_bytes + object_bytes > MAX_NATIVE_ROW_OBJECT_BYTES
    ):
        raise CensusError("multi-grep reducer object envelope differs")
    ordered_sources_sha256 = require_nonzero_hex64(
        fields.get("multi_grep_reducer_ordered_sources_sha256"),
        "multi-grep ordered source digest",
    )
    operation_identity_sha256 = require_nonzero_hex64(
        fields.get("multi_grep_reducer_operation_identity_sha256"),
        "multi-grep operation identity",
    )
    code_sha256 = require_nonzero_hex64(
        fields.get("multi_grep_reducer_code_sha256"),
        "multi-grep reducer code digest",
    )
    object_sha256 = require_nonzero_hex64(
        fields.get("multi_grep_reducer_object_sha256"),
        "multi-grep reducer object digest",
    )
    artifact_identity_sha256 = require_nonzero_hex64(
        fields.get("multi_grep_reducer_artifact_identity_sha256"),
        "multi-grep artifact identity",
    )
    reducer_symbol = fields.get("multi_grep_reducer_symbol")
    if not isinstance(reducer_symbol, str):
        raise CensusError("multi-grep reducer symbol is absent")
    symbol_identity = symbol_identity_suffix(
        reducer_symbol,
        (NATIVE_MIXED_MULTI_GREP_REDUCER_SYMBOL if mixed_handle_table
         else NATIVE_MULTI_GREP_REDUCER_SYMBOL),
        "multi-grep reducer symbol",
    )

    target = fields.get("target", "")
    architecture = target_architecture(target)
    if target.endswith("-linux"):
        operating_system = "linux"
    elif target.endswith("-macos"):
        operating_system = "macos"
    else:
        raise CensusError("multi-grep reducer target operating system differs")
    target_bytes = bytes((
        {"x86_64": 0, "aarch64": 1}[architecture],
        {"linux": 0, "macos": 1}[operating_system],
        {"x86_64": 0, "aarch64": 1}[architecture],
    ))
    feature_bits = fields.get("feature_bits", "")
    if re.fullmatch(r"[0-9a-f]{16}", feature_bits) is None:
        raise CensusError("multi-grep reducer feature bits are not canonical")
    operation = hashlib.sha256()
    operation.update(
        b"fre-aot-regex/rebar-mixed-multi-grep-reducer/v1\0"
        if mixed_handle_table else
        b"fre-aot-regex/rebar-multi-grep-reducer/v1\0"
    )
    operation.update(abi_version.to_bytes(4, "little"))
    operation.update(target_bytes)
    operation.update(int(feature_bits, 16).to_bytes(8, "little"))
    operation.update(source_cardinality.to_bytes(8, "little"))
    operation.update(source_bytes.to_bytes(8, "little"))
    operation.update(bytes.fromhex(ordered_sources_sha256))
    operation.update(len(source_to_artifact).to_bytes(8, "little"))
    for row in source_to_artifact:
        operation.update(row.to_bytes(8, "little"))
    operation.update(len(components).to_bytes(8, "little"))
    for row, component in enumerate(components):
        first_source = component.get("source_ordinal")
        entry_symbol = component.get("entry_symbol")
        if not isinstance(first_source, int) or not isinstance(entry_symbol, str):
            raise CensusError("multi-grep reducer row identity is malformed")
        operation.update(first_source.to_bytes(8, "little"))
        if mixed_handle_table:
            operation.update(bytes((row_routes[row],)))
        entry_bytes = entry_symbol.encode("ascii", "strict")
        operation.update(len(entry_bytes).to_bytes(8, "little"))
        operation.update(entry_bytes)
        for digest_name in (
            "automaton_sha256", "program_sha256", "object_sha256",
        ):
            operation.update(bytes.fromhex(require_nonzero_hex64(
                component.get(digest_name),
                f"multi-grep row {digest_name}",
            )))
    expected_operation_identity = operation.hexdigest()
    if operation_identity_sha256 != expected_operation_identity:
        raise CensusError("multi-grep operation identity does not authenticate its closure")
    if symbol_identity != operation_identity_sha256:
        raise CensusError("multi-grep reducer symbol does not bind operation identity")

    artifact = hashlib.sha256()
    artifact.update(
        b"fre-aot-regex/rebar-mixed-multi-grep-reducer-artifact/v1\0"
        if mixed_handle_table else
        b"fre-aot-regex/rebar-multi-grep-reducer-artifact/v1\0"
    )
    artifact.update(bytes.fromhex(operation_identity_sha256))
    symbol_bytes = reducer_symbol.encode("ascii", "strict")
    artifact.update(len(symbol_bytes).to_bytes(8, "little"))
    artifact.update(symbol_bytes)
    artifact.update(bytes.fromhex(code_sha256))
    artifact.update(bytes.fromhex(object_sha256))
    artifact.update(relocation_count.to_bytes(8, "little"))
    artifact.update(object_bytes.to_bytes(8, "little"))
    artifact.update(max_object_bytes.to_bytes(8, "little"))
    if mixed_handle_table:
        artifact.update(len(row_routes).to_bytes(8, "little"))
        artifact.update(bytes(row_routes))
    if artifact_identity_sha256 != artifact.hexdigest():
        raise CensusError("multi-grep artifact identity does not authenticate its receipt")
    return {
        "abi_version": abi_version,
        "mixed_handle_table": mixed_handle_table,
        "required_handle_count": required_handle_count,
        "row_routes": row_routes,
        "source_cardinality": source_cardinality,
        "source_bytes": source_bytes,
        "ordered_sources_sha256": ordered_sources_sha256,
        "operation_identity_sha256": operation_identity_sha256,
        "reducer_symbol": reducer_symbol,
        "code_sha256": code_sha256,
        "object_sha256": object_sha256,
        "relocation_count": relocation_count,
        "semantic_runtime_calls": semantic_runtime_calls,
        "object_bytes": object_bytes,
        "max_object_bytes": max_object_bytes,
        "artifact_identity_sha256": artifact_identity_sha256,
    }


def validate_normalized_multi_grep_reducer(
    proof: object, provenance: dict[str, object], context: str
) -> dict[str, object]:
    """Re-authenticate a normalized multi-Grep reducer without trusting raw text."""
    if not isinstance(proof, dict):
        raise CensusError(f"{context} proof is not an object")
    require_exact_keys(proof, {
        "abi_version", "mixed_handle_table", "required_handle_count",
        "row_routes", "source_cardinality", "source_bytes",
        "ordered_sources_sha256", "operation_identity_sha256",
        "reducer_symbol", "code_sha256", "object_sha256",
        "relocation_count", "semantic_runtime_calls", "object_bytes",
        "max_object_bytes", "artifact_identity_sha256",
    }, f"{context} proof")
    if not isinstance(proof["mixed_handle_table"], bool):
        raise CensusError(f"{context} mixed-handle flag is not boolean")
    components = provenance.get("components")
    source_count = provenance.get("source_pattern_count")
    source_map = provenance.get("source_to_artifact")
    row_object_bytes = provenance.get("row_total_object_bytes")
    if (
        not isinstance(components, list)
        or not components
        or not isinstance(source_count, int)
        or isinstance(source_count, bool)
        or source_count < 2
        or not isinstance(source_map, list)
        or len(source_map) != source_count
        or not isinstance(row_object_bytes, int)
        or isinstance(row_object_bytes, bool)
        or not 0 < row_object_bytes <= MAX_NATIVE_ROW_OBJECT_BYTES
        or any(
            not isinstance(row, int)
            or isinstance(row, bool)
            or row < 0
            or row >= len(components)
            for row in source_map
        )
        or set(source_map) != set(range(len(components)))
    ):
        raise CensusError(f"{context} source/row topology differs")
    first_sources = [source_map.index(index) for index in range(len(components))]
    if first_sources != sorted(first_sources) or [
        component.get("source_ordinal") for component in components
    ] != first_sources:
        raise CensusError(f"{context} source priority differs")
    fake_fields = {
        "native_multi_grep_reducer": "true",
        "model": str(provenance.get("model", "")),
        "adapter": str(provenance.get("adapter", "")),
        "aggregate_strategy": str(provenance.get("aggregate_strategy", "")),
        "boundary": str(provenance.get("boundary", "")),
        "target": str(provenance.get("target", "")),
        "feature_bits": str(provenance.get("feature_bits", "")),
        "multi_grep_reducer_abi_version": str(proof["abi_version"]),
        "multi_grep_reducer_mixed_handle_table": (
            "true" if proof["mixed_handle_table"] else "false"
        ),
        "multi_grep_reducer_required_handle_count": str(
            proof["required_handle_count"]
        ),
        "multi_grep_reducer_row_routes": ",".join(
            str(value) for value in proof["row_routes"]
        ),
        "multi_grep_reducer_source_cardinality": str(proof["source_cardinality"]),
        "multi_grep_reducer_source_bytes": str(proof["source_bytes"]),
        "multi_grep_reducer_ordered_sources_sha256": str(
            proof["ordered_sources_sha256"]
        ),
        "multi_grep_reducer_symbol": str(proof["reducer_symbol"]),
        "multi_grep_reducer_operation_identity_sha256": str(
            proof["operation_identity_sha256"]
        ),
        "multi_grep_reducer_code_sha256": str(proof["code_sha256"]),
        "multi_grep_reducer_object_sha256": str(proof["object_sha256"]),
        "multi_grep_reducer_relocation_count": str(proof["relocation_count"]),
        "multi_grep_reducer_semantic_runtime_calls": str(
            proof["semantic_runtime_calls"]
        ),
        "multi_grep_reducer_object_bytes": str(proof["object_bytes"]),
        "multi_grep_reducer_max_object_bytes": str(proof["max_object_bytes"]),
        "multi_grep_reducer_artifact_identity_sha256": str(
            proof["artifact_identity_sha256"]
        ),
    }
    expected = multi_grep_reducer_proof_from_provenance(
        fake_fields, components, source_count, row_object_bytes, source_map
    )
    if proof != expected:
        raise CensusError(f"{context} proof normalization differs")
    return expected


def uniform_capture_proof_from_provenance(
    fields: dict[str, str],
    components: list[dict[str, object]],
    source_count: int,
    source_to_artifact: list[int],
) -> dict[str, object]:
    """Normalize and authenticate the complete same-HIR capture proof surface."""
    algorithm_version = parse_canonical_decimal(
        fields.get("capture_proof_algorithm_version"),
        "capture proof algorithm version",
        1,
        (1 << 32) - 1,
    )
    accounting_version = parse_canonical_decimal(
        fields.get("capture_proof_accounting_version"),
        "capture proof accounting version",
        1,
        (1 << 32) - 1,
    )
    groups = parse_canonical_decimal_list(
        fields.get("source_participating_groups"),
        "source_participating_groups",
        source_count,
        1,
    )
    minimums = parse_canonical_decimal_list(
        fields.get("source_minimum_match_bytes"),
        "source_minimum_match_bytes",
        source_count,
        1,
    )
    annotations = parse_canonical_decimal_list(
        fields.get("source_capture_annotations"),
        "source_capture_annotations",
        source_count,
    )
    proof_work = parse_canonical_decimal_list(
        fields.get("source_proof_work"), "source_proof_work", source_count, 1
    )
    peak_stack = parse_canonical_decimal_list(
        fields.get("source_proof_peak_stack_items"),
        "source_proof_peak_stack_items",
        source_count,
        1,
    )
    selector_automata = parse_digest_list(
        fields.get("source_selector_automaton_sha256"),
        "source_selector_automaton_sha256",
        source_count,
    )
    selector_programs = parse_digest_list(
        fields.get("source_selector_program_sha256"),
        "source_selector_program_sha256",
        source_count,
    )
    selector_objects = parse_digest_list(
        fields.get("source_selector_object_sha256"),
        "source_selector_object_sha256",
        source_count,
    )
    for source, artifact in enumerate(source_to_artifact):
        component = components[artifact]
        if groups[source] - 1 > annotations[source]:
            raise CensusError(
                f"source {source} participating capture count exceeds its annotations"
            )
        if (
            selector_automata[source] != component["automaton_sha256"]
            or selector_programs[source] != component["program_sha256"]
            or selector_objects[source] != component["object_sha256"]
        ):
            raise CensusError(
                f"source {source} selector digests differ from its mapped component"
            )
    return {
        "capture_resolution": fields.get("capture_resolution"),
        "capture_proof_algorithm_version": algorithm_version,
        "capture_proof_accounting_version": accounting_version,
        "source_participating_groups": groups,
        "source_minimum_match_bytes": minimums,
        "source_capture_annotations": annotations,
        "source_proof_work": proof_work,
        "source_proof_peak_stack_items": peak_stack,
        "source_selector_automaton_sha256": selector_automata,
        "source_selector_program_sha256": selector_programs,
        "source_selector_object_sha256": selector_objects,
    }


def parse_canonical_signed_decimal(
    text: object, context: str, minimum: int = -(1 << 63), maximum: int = (1 << 63) - 1
) -> int:
    """Parse the runner's canonical signed decimal spelling."""
    if not isinstance(text, str) or re.fullmatch(r"0|-?[1-9][0-9]*", text) is None:
        raise CensusError(f"{context} is not canonical signed decimal")
    value = int(text, 10)
    if value < minimum or value > maximum:
        raise CensusError(f"{context} is outside {minimum}..={maximum}")
    return value


def parse_canonical_signed_decimal_list(
    text: object, context: str, count: int,
    minimum: int = -(1 << 63), maximum: int = (1 << 63) - 1,
) -> list[int]:
    if not isinstance(text, str):
        raise CensusError(f"{context} is not a signed decimal list")
    values = text.split(",") if text else []
    if len(values) != count:
        raise CensusError(f"{context} cardinality differs from component_count")
    return [
        parse_canonical_signed_decimal(
            value, f"{context}[{index}]", minimum, maximum
        )
        for index, value in enumerate(values)
    ]


def weighted_capture_target_tags(target: str) -> tuple[int, int, int]:
    """Return the Rust enum discriminants bound by the weighted receipt."""
    if target == "x86_64-linux":
        return 0, 0, 0
    if target == "x86_64-macos":
        return 0, 1, 0
    if target == "aarch64-linux":
        return 1, 0, 1
    if target == "aarch64-macos":
        return 1, 1, 1
    raise CensusError("weighted capture reducer target is unsupported")


def weighted_capture_operation_identity(
    fields: dict[str, str], components: list[dict[str, object]],
    source_to_component: list[int], first_ordinals: list[int],
    weights: list[int], proof: dict[str, object], user_captures: list[int],
) -> str:
    """Recompute the exact Rust weighted-operation identity byte stream."""
    operation = parse_canonical_decimal(
        fields.get("operation"), "weighted reducer operation", 1, 2
    )
    domain = parse_canonical_decimal(
        fields.get("domain"), "weighted reducer domain", 1, 2
    )
    architecture, operating_system, abi = weighted_capture_target_tags(fields["target"])
    feature_bits = parse_fixed_hex_u64(
        fields.get("feature_bits"), "weighted reducer feature bits"
    )
    architecture_name = target_architecture(fields["target"])
    known_bits = sum(FEATURE_BITS.values())
    architecture_bits = (
        sum(value for name, value in FEATURE_BITS.items() if name.startswith(("sse", "avx")))
        if architecture_name == "x86_64"
        else sum(value for name, value in FEATURE_BITS.items() if name.startswith(("asimd", "sve")))
    )
    if feature_bits & ~known_bits or feature_bits & ~architecture_bits:
        raise CensusError("weighted reducer feature bits are not canonical for its target")
    pattern_bytes = parse_canonical_decimal(
        fields.get("pattern_bytes"), "weighted reducer pattern bytes", 1,
        MAX_PUBLIC_KLV_BYTES,
    )
    ordered_sources = bytes.fromhex(require_nonzero_hex64(
        fields.get("ordered_sources_sha256"), "weighted reducer ordered sources digest"
    ))
    source_count = len(source_to_component)

    algorithm = proof["capture_proof_algorithm_version"]
    accounting = proof["capture_proof_accounting_version"]
    groups = proof["source_participating_groups"]
    minimums = proof["source_minimum_match_bytes"]
    annotations = proof["source_capture_annotations"]
    work = proof["source_proof_work"]
    stacks = proof["source_proof_peak_stack_items"]
    automata = proof["source_selector_automaton_sha256"]
    programs = proof["source_selector_program_sha256"]
    objects = proof["source_selector_object_sha256"]
    line_terminator = parse_canonical_decimal(
        fields.get("line_terminator"), "weighted reducer line terminator", 10, 10
    )

    digest = hashlib.sha256()
    digest.update(b"fre-aot-regex/rebar-weighted-capture-reducer-aot-v1\0")
    digest.update((1).to_bytes(4, "little"))
    digest.update(bytes((operation, domain)))
    digest.update(bytes((architecture, operating_system, abi)))
    digest.update(feature_bits.to_bytes(8, "little"))
    digest.update(pattern_bytes.to_bytes(8, "little"))
    digest.update(ordered_sources)
    digest.update(source_count.to_bytes(8, "little"))
    digest.update(len(components).to_bytes(8, "little"))
    for source, component in enumerate(source_to_component):
        digest.update(source.to_bytes(8, "little"))
        digest.update(component.to_bytes(8, "little"))
        digest.update(int(algorithm).to_bytes(4, "little"))
        digest.update(int(accounting).to_bytes(4, "little"))
        digest.update(int(minimums[source]).to_bytes(8, "little"))
        digest.update(user_captures[source].to_bytes(8, "little"))
        digest.update(int(groups[source]).to_bytes(8, "little"))
        digest.update(int(annotations[source]).to_bytes(8, "little"))
        digest.update(int(work[source]).to_bytes(8, "little"))
        digest.update(int(stacks[source]).to_bytes(8, "little"))
        digest.update(bytes.fromhex(str(automata[source])))
        digest.update(bytes.fromhex(str(programs[source])))
        digest.update(bytes.fromhex(str(objects[source])))
        digest.update(bytes((line_terminator,)))
    for ordinal, component in enumerate(components):
        digest.update(ordinal.to_bytes(8, "little"))
        digest.update(first_ordinals[ordinal].to_bytes(8, "little"))
        digest.update(weights[ordinal].to_bytes(8, "little"))
        entry = str(component["entry_symbol"]).encode("ascii", "strict")
        digest.update(len(entry).to_bytes(8, "little"))
        digest.update(entry)
        digest.update(bytes.fromhex(str(component["program_sha256"])))
        digest.update(bytes.fromhex(str(component["object_sha256"])))
    return digest.hexdigest()


def weighted_capture_artifact_identity(
    operation_identity: str, reducer_symbol: str, reducer_code: str,
    reducer_object: str, reducer_object_bytes: int, reducer_object_cap: int,
    relocations: list[dict[str, int]],
) -> str:
    """Recompute the exact separately linked wrapper artifact identity."""
    digest = hashlib.sha256()
    digest.update(b"fre-aot-regex/rebar-weighted-capture-reducer-artifact-v1\0")
    digest.update(bytes.fromhex(operation_identity))
    symbol = reducer_symbol.encode("ascii", "strict")
    digest.update(len(symbol).to_bytes(8, "little"))
    digest.update(symbol)
    digest.update(bytes.fromhex(reducer_code))
    digest.update(bytes.fromhex(reducer_object))
    digest.update(reducer_object_bytes.to_bytes(8, "little"))
    digest.update(reducer_object_cap.to_bytes(8, "little"))
    digest.update(len(relocations).to_bytes(8, "little"))
    for relocation in relocations:
        digest.update(relocation["component"].to_bytes(8, "little"))
        digest.update(relocation["offset"].to_bytes(8, "little"))
        digest.update(bytes((relocation["kind"],)))
        digest.update(relocation["addend"].to_bytes(8, "little", signed=True))
    return digest.hexdigest()


def weighted_capture_reducer_proof_from_provenance(
    fields: dict[str, str],
) -> tuple[list[dict[str, object]], list[int], dict[str, object]]:
    """Authenticate and normalize the complete helper-free v6 receipt."""
    source_count = parse_canonical_decimal(
        fields.get("source_pattern_count"), "weighted reducer source count", 2,
        MAX_NATIVE_ROW_COMPONENTS,
    )
    component_count = parse_canonical_decimal(
        fields.get("component_count"), "weighted reducer component count", 1,
        MAX_NATIVE_ROW_COMPONENTS,
    )
    source_to_component = parse_canonical_decimal_list(
        fields.get("source_to_component"), "weighted reducer source map",
        source_count, 0, component_count - 1,
    )
    if set(source_to_component) != set(range(component_count)):
        raise CensusError("weighted reducer source map is not surjective")
    expected_first = [source_to_component.index(index) for index in range(component_count)]
    first_ordinals = parse_canonical_decimal_list(
        fields.get("component_first_source_ordinals"),
        "weighted reducer component first ordinals", component_count, 0,
        source_count - 1,
    )
    if first_ordinals != expected_first or first_ordinals != sorted(first_ordinals):
        raise CensusError("weighted reducer component priority differs from its source map")
    weights = parse_canonical_decimal_list(
        fields.get("component_weights"), "weighted reducer component weights",
        component_count, 1,
    )

    entries_text = fields.get("component_entry_symbols")
    if not isinstance(entries_text, str):
        raise CensusError("weighted reducer component entries are not a list")
    entries = entries_text.split(",") if entries_text else []
    if (
        len(entries) != component_count
        or len(entries) != len(set(entries))
        or any(NATIVE_SEARCH_ENTRY_SYMBOL.fullmatch(entry) is None for entry in entries)
    ):
        raise CensusError("weighted reducer component entries are not distinct native Span rows")
    automata = parse_digest_list(
        fields.get("component_automaton_sha256"),
        "weighted reducer component automata", component_count,
    )
    programs = parse_digest_list(
        fields.get("component_program_sha256"),
        "weighted reducer component programs", component_count,
    )
    objects = parse_digest_list(
        fields.get("component_object_sha256"),
        "weighted reducer component objects", component_count,
    )
    if any(value == "0" * 64 for value in (*automata, *programs, *objects)):
        raise CensusError("weighted reducer component identity contains a zero digest")
    components = [
        {
            "ordinal": index,
            "native": True,
            "source_ordinal": first_ordinals[index],
            "entry_symbol": entries[index],
            "required_runtime_symbols": [],
            "automaton_sha256": automata[index],
            "program_sha256": programs[index],
            "object_sha256": objects[index],
        }
        for index in range(component_count)
    ]
    validate_native_row_engine_routes(fields, components)

    if fields.get("capture_resolution") != "static-uniform-multiplier":
        raise CensusError("weighted reducer capture proof route is not static uniform")
    proof = uniform_capture_proof_from_provenance(
        fields, components, source_count, source_to_component
    )
    if (
        proof["capture_proof_algorithm_version"] != 1
        or proof["capture_proof_accounting_version"] != 1
    ):
        raise CensusError("weighted reducer capture proof version is not current")
    user_captures = parse_canonical_decimal_list(
        fields.get("source_participating_user_captures"),
        "source_participating_user_captures", source_count,
    )
    groups = proof["source_participating_groups"]
    annotations = proof["source_capture_annotations"]
    if any(
        groups[source] != user_captures[source] + 1
        or user_captures[source] > annotations[source]
        for source in range(source_count)
    ):
        raise CensusError("weighted reducer participation cardinality is inconsistent")
    if len(set(groups)) == 1:
        raise CensusError("weighted reducer route does not have unequal multipliers")
    if any(value > 8_000_000 for value in proof["source_proof_work"]):
        raise CensusError("weighted reducer capture proof work exceeds its compiler cap")
    if any(value > 1_000_000 for value in proof["source_proof_peak_stack_items"]):
        raise CensusError("weighted reducer capture proof stack exceeds its compiler cap")
    if weights != [groups[source] for source in first_ordinals]:
        raise CensusError("weighted reducer component weights differ from first-source proofs")

    row_total_object_bytes = parse_canonical_decimal(
        fields.get("row_total_object_bytes"), "weighted reducer row object bytes", 1,
        MAX_NATIVE_ROW_OBJECT_BYTES,
    )
    operation = parse_canonical_decimal(
        fields.get("operation"), "weighted reducer operation", 1, 2
    )
    domain = parse_canonical_decimal(
        fields.get("domain"), "weighted reducer domain", 1, 2
    )
    expected_operation, expected_domain, expected_adapter = {
        "count-captures": (
            1, 1, "general-aot-native-weighted-capture-count-reducer-v1"
        ),
        "grep-captures": (
            2, 2, "general-aot-native-weighted-capture-grep-reducer-v1"
        ),
    }.get(fields.get("model"), (0, 0, ""))
    if (
        operation != expected_operation
        or domain != expected_domain
        or fields.get("adapter") != expected_adapter
        or fields.get("aggregate_strategy") != "native-weighted-capture-row-reducer-v1"
        or fields.get("native_row_bridge") != "true"
        or fields.get("uniform_capture_bridge") != "true"
        or fields.get("weighted_capture_reducer_bridge") != "true"
        or fields.get("semantic_runtime_symbols") != ""
        or fields.get("boundary")
        != "single-call-helper-free-native-multi-component-weighted-row-reducer"
    ):
        raise CensusError("weighted reducer provenance has a noncanonical route")
    if parse_canonical_decimal(
        fields.get("weighted_receipt_schema"), "weighted reducer receipt schema", 1, 1
    ) != 1:
        raise CensusError("weighted reducer receipt schema differs")
    if parse_canonical_decimal(
        fields.get("line_terminator"), "weighted reducer line terminator", 10, 10
    ) != 10:
        raise CensusError("weighted reducer line terminator differs")

    operation_identity = require_nonzero_hex64(
        fields.get("operation_identity_sha256"), "weighted reducer operation identity"
    )
    computed_operation_identity = weighted_capture_operation_identity(
        fields, components, source_to_component, first_ordinals, weights, proof,
        user_captures,
    )
    if operation_identity != computed_operation_identity:
        raise CensusError("weighted reducer operation identity does not recompute")
    reducer_symbol = fields.get("reducer_symbol", "")
    reducer_pattern = (
        NATIVE_WEIGHTED_CAPTURE_COUNT_REDUCER_SYMBOL
        if operation == 1 else NATIVE_WEIGHTED_CAPTURE_GREP_REDUCER_SYMBOL
    )
    reducer_suffix = symbol_identity_suffix(
        reducer_symbol, reducer_pattern, "weighted capture reducer"
    )
    if reducer_suffix != operation_identity:
        raise CensusError("weighted reducer symbol does not bind its operation identity")
    reducer_symbol_sha256 = require_nonzero_hex64(
        fields.get("reducer_symbol_sha256"), "weighted reducer symbol digest"
    )
    if reducer_symbol_sha256 != sha_bytes(reducer_symbol.encode("ascii", "strict")):
        raise CensusError("weighted reducer symbol digest differs")
    reducer_code = require_nonzero_hex64(
        fields.get("reducer_code_sha256"), "weighted reducer code digest"
    )
    reducer_object = require_nonzero_hex64(
        fields.get("reducer_object_sha256"), "weighted reducer object digest"
    )
    reducer_object_bytes = parse_canonical_decimal(
        fields.get("reducer_object_bytes"), "weighted reducer object bytes", 1,
        MAX_WEIGHTED_CAPTURE_REDUCER_OBJECT_BYTES,
    )
    reducer_object_cap = parse_canonical_decimal(
        fields.get("reducer_object_cap"), "weighted reducer object cap",
        MAX_WEIGHTED_CAPTURE_REDUCER_OBJECT_BYTES,
        MAX_WEIGHTED_CAPTURE_REDUCER_OBJECT_BYTES,
    )

    relocation_count = parse_canonical_decimal(
        fields.get("external_relocation_count"), "weighted reducer relocation count",
        component_count, component_count,
    )
    relocation_components = parse_canonical_decimal_list(
        fields.get("external_relocation_components"),
        "weighted reducer relocation components", relocation_count, 0,
        component_count - 1,
    )
    relocation_offsets = parse_canonical_decimal_list(
        fields.get("external_relocation_offsets"),
        "weighted reducer relocation offsets", relocation_count, 0,
        reducer_object_bytes - 1,
    )
    relocation_kinds = parse_canonical_decimal_list(
        fields.get("external_relocation_kinds"),
        "weighted reducer relocation kinds", relocation_count, 1, 5,
    )
    relocation_addends = parse_canonical_signed_decimal_list(
        fields.get("external_relocation_addends"),
        "weighted reducer relocation addends", relocation_count,
    )
    architecture = target_architecture(fields["target"])
    expected_kind, expected_addend = (2, -4) if architecture == "x86_64" else (5, 0)
    if (
        relocation_components != list(range(component_count))
        or relocation_offsets != sorted(set(relocation_offsets))
        or relocation_kinds != [expected_kind] * component_count
        or relocation_addends != [expected_addend] * component_count
    ):
        raise CensusError("weighted reducer external relocation closure differs")
    relocations = [
        {
            "component": relocation_components[index],
            "offset": relocation_offsets[index],
            "kind": relocation_kinds[index],
            "addend": relocation_addends[index],
        }
        for index in range(relocation_count)
    ]
    artifact_identity = require_nonzero_hex64(
        fields.get("reducer_artifact_identity_sha256"),
        "weighted reducer artifact identity",
    )
    computed_artifact_identity = weighted_capture_artifact_identity(
        operation_identity, reducer_symbol, reducer_code, reducer_object,
        reducer_object_bytes, reducer_object_cap, relocations,
    )
    if artifact_identity != computed_artifact_identity:
        raise CensusError("weighted reducer artifact identity does not recompute")
    return components, source_to_component, {
        "receipt_schema": 1,
        "pattern_bytes": parse_canonical_decimal(
            fields.get("pattern_bytes"), "weighted reducer pattern bytes", 1,
            MAX_PUBLIC_KLV_BYTES,
        ),
        "row_total_object_bytes": row_total_object_bytes,
        "component_first_source_ordinals": first_ordinals,
        "component_weights": weights,
        "source_participating_user_captures": user_captures,
        "line_terminator": 10,
        "operation": operation,
        "domain": domain,
        "ordered_sources_sha256": fields["ordered_sources_sha256"],
        "operation_identity_sha256": operation_identity,
        "reducer_symbol": reducer_symbol,
        "reducer_symbol_sha256": reducer_symbol_sha256,
        "reducer_code_sha256": reducer_code,
        "reducer_object_sha256": reducer_object,
        "reducer_object_bytes": reducer_object_bytes,
        "reducer_object_cap": reducer_object_cap,
        "artifact_identity_sha256": artifact_identity,
        "external_relocations": relocations,
        "uniform_capture": proof,
    }


def strict_capture_proof_from_provenance(
    fields: dict[str, str], components: list[dict[str, object]]
) -> dict[str, object]:
    """Normalize the complete helper-free one-pattern capture artifact surface."""
    if len(components) != 1:
        raise CensusError("strict-capture provenance does not have exactly one component")
    component = components[0]
    entry_symbol = component["entry_symbol"]
    materialize_symbol = fields.get("capture_materialize_symbol")
    selector_symbol = fields.get("capture_selector_symbol")
    if not isinstance(entry_symbol, str) or NATIVE_CAPTURE_NEXT_ENTRY_SYMBOL.fullmatch(
        entry_symbol
    ) is None:
        raise CensusError("strict-capture component entry is not native capture_next")
    if (
        not isinstance(materialize_symbol, str)
        or NATIVE_CAPTURE_MATERIALIZE_SYMBOL.fullmatch(materialize_symbol) is None
    ):
        raise CensusError("strict-capture materialize symbol is not native")
    if (
        not isinstance(selector_symbol, str)
        or NATIVE_SEARCH_ENTRY_SYMBOL.fullmatch(selector_symbol) is None
    ):
        raise CensusError("strict-capture selector symbol is not an ordinary native entry")
    if len({entry_symbol, materialize_symbol, selector_symbol}) != 3:
        raise CensusError("strict-capture operation symbols are not distinct")
    if component["required_runtime_symbols"]:
        raise CensusError("strict-capture component requires semantic runtime symbols")
    capture_program = require_hex64(
        fields.get("capture_program_sha256"), "strict-capture program digest"
    )
    if capture_program != component["program_sha256"]:
        raise CensusError("strict-capture program digest differs from its component")
    can_match_empty_text = fields.get("capture_can_match_empty")
    if can_match_empty_text not in {"true", "false"}:
        raise CensusError("strict-capture nullable flag is not canonical boolean")
    return {
        "capture_resolution": fields.get("capture_resolution"),
        "capture_group_count": parse_canonical_decimal(
            fields.get("capture_group_count"),
            "strict-capture group count",
            1,
            MAX_NATIVE_ROW_COMPONENTS,
        ),
        "capture_can_match_empty": can_match_empty_text == "true",
        "capture_source_sha256": require_hex64(
            fields.get("capture_source_sha256"), "strict-capture source digest"
        ),
        "capture_selector_sha256": require_hex64(
            fields.get("capture_selector_sha256"), "strict-capture selector digest"
        ),
        "capture_program_sha256": capture_program,
        "capture_plan_sha256": require_hex64(
            fields.get("capture_plan_sha256"), "strict-capture plan digest"
        ),
        "capture_bundle_sha256": require_hex64(
            fields.get("capture_bundle_sha256"), "strict-capture bundle digest"
        ),
        "capture_artifact_identity_sha256": require_hex64(
            fields.get("capture_artifact_identity_sha256"),
            "strict-capture artifact identity digest",
        ),
        "capture_next_symbol": entry_symbol,
        "capture_materialize_symbol": materialize_symbol,
        "capture_selector_symbol": selector_symbol,
    }


def participation_capture_proof_from_provenance(
    fields: dict[str, str], components: list[dict[str, object]]
) -> dict[str, object]:
    """Normalize the helper-free exact-span capture replay proof surface."""
    if len(components) != 1:
        raise CensusError(
            "exact-span participation provenance does not have exactly one component"
        )
    component = components[0]
    selector_symbol = fields.get("capture_selector_symbol")
    entry_symbol = fields.get("participation_entry_symbol")
    bundle_symbol = fields.get("participation_bundle_symbol")
    if (
        not isinstance(selector_symbol, str)
        or NATIVE_SEARCH_ENTRY_SYMBOL.fullmatch(selector_symbol) is None
        or not isinstance(entry_symbol, str)
        or NATIVE_PARTICIPATION_ENTRY_SYMBOL.fullmatch(entry_symbol) is None
        or not isinstance(bundle_symbol, str)
        or NATIVE_PARTICIPATION_BUNDLE_SYMBOL.fullmatch(bundle_symbol) is None
        or len({selector_symbol, entry_symbol, bundle_symbol}) != 3
    ):
        raise CensusError("exact-span participation symbols are not canonical")
    export_identity = require_hex64(
        fields.get("participation_export_identity_sha256"),
        "exact-span participation export identity digest",
    )
    selector_object = require_hex64(
        fields.get("selector_object_sha256"),
        "exact-span participation selector object digest",
    )
    bundle_digest = require_hex64(
        fields.get("participation_bundle_sha256"),
        "exact-span participation bundle digest",
    )
    if not entry_symbol.endswith(export_identity) or not bundle_symbol.endswith(
        export_identity
    ):
        raise CensusError(
            "exact-span participation symbols differ from their export identity"
        )
    expected_export_identity = participation_export_identity(
        bundle_digest,
        fields.get("target", ""),
        fields.get("feature_bits", ""),
        selector_object,
        selector_symbol,
    )
    if export_identity != expected_export_identity:
        raise CensusError(
            "exact-span participation export identity does not authenticate its inputs"
        )
    if component["entry_symbol"] != selector_symbol:
        raise CensusError(
            "exact-span participation selector differs from its component entry"
        )
    if component["required_runtime_symbols"]:
        raise CensusError(
            "exact-span participation component requires semantic runtime symbols"
        )
    capture_program = require_hex64(
        fields.get("capture_program_sha256"),
        "exact-span participation capture program digest",
    )
    participation_object = require_hex64(
        fields.get("participation_object_sha256"),
        "exact-span participation object digest",
    )
    if component["program_sha256"] != capture_program:
        raise CensusError(
            "exact-span participation capture program differs from its component"
        )
    if component["object_sha256"] != participation_object:
        raise CensusError(
            "exact-span participation object differs from its component"
        )
    ordered_nfa = fields.get("participation_strategy") in {"4", "5"}
    algorithm_id = fields.get("participation_algorithm_id")
    expected_algorithm = (
        NATIVE_PARTICIPATION_ORDERED_NFA_ALGORITHM_ID
        if ordered_nfa else NATIVE_PARTICIPATION_ALGORITHM_ID
    )
    if algorithm_id != expected_algorithm:
        raise CensusError("exact-span participation algorithm identity differs")
    architecture = target_architecture(fields.get("target", ""))
    expected_strategy = (
        {"x86_64": 4, "aarch64": 5}[architecture]
        if ordered_nfa else {"x86_64": 1, "aarch64": 2}[architecture]
    )
    strategy = parse_canonical_decimal(
        fields.get("participation_strategy"),
        "exact-span participation strategy",
        expected_strategy,
        expected_strategy,
    )
    semantic_runtime_calls = parse_canonical_decimal(
        fields.get("participation_semantic_runtime_calls"),
        "exact-span participation semantic runtime calls",
        0,
        0,
    )
    assertions = parse_canonical_decimal(
        fields.get("participation_assertions"),
        "exact-span participation assertions",
        0,
        NATIVE_PARTICIPATION_MAX_ASSERTIONS,
    )
    lower = 0 if ordered_nfa else 1
    assertion_signatures = parse_canonical_decimal(
        fields.get("participation_assertion_signatures"),
        "exact-span participation assertion signatures",
        lower, 0 if ordered_nfa else NATIVE_PARTICIPATION_MAX_ASSERTION_SIGNATURES,
    )
    byte_classes = parse_canonical_decimal(
        fields.get("participation_byte_classes"),
        "exact-span participation byte classes",
        lower, 0 if ordered_nfa else NATIVE_PARTICIPATION_MAX_BYTE_CLASSES,
    )
    dfa_states = parse_canonical_decimal(
        fields.get("participation_dfa_states"),
        "exact-span participation DFA states",
        lower, 0 if ordered_nfa else NATIVE_PARTICIPATION_MAX_DFA_STATES,
    )
    transition_cells = parse_canonical_decimal(
        fields.get("participation_transition_cells"),
        "exact-span participation transition cells",
        lower, 0 if ordered_nfa else NATIVE_PARTICIPATION_MAX_TRANSITION_CELLS,
    )
    ordered_nfa_states = parse_canonical_decimal(
        fields.get("participation_ordered_nfa_states"),
        "exact-span participation ordered-NFA states", 1 if ordered_nfa else 0,
        NATIVE_PARTICIPATION_MAX_PLAN_BYTES if ordered_nfa else 0,
    )
    ordered_nfa_byte_ranges = parse_canonical_decimal(
        fields.get("participation_ordered_nfa_byte_ranges"),
        "exact-span participation ordered-NFA byte ranges", 0,
        NATIVE_PARTICIPATION_MAX_PLAN_BYTES if ordered_nfa else 0,
    )
    fallback_resource = parse_canonical_decimal(
        fields.get("participation_dfa_fallback_resource"),
        "exact-span participation fallback resource", 1 if ordered_nfa else 0,
        2 if ordered_nfa else 0,
    )
    fallback_required = parse_canonical_decimal(
        fields.get("participation_dfa_fallback_required"),
        "exact-span participation fallback required", 1 if ordered_nfa else 0,
        (1 << 32) - 1 if ordered_nfa else 0,
    )
    fallback_limit = parse_canonical_decimal(
        fields.get("participation_dfa_fallback_limit"),
        "exact-span participation fallback limit", 0,
        (1 << 32) - 1 if ordered_nfa else 0,
    )
    expected_transition_cells = dfa_states * byte_classes * assertion_signatures
    if not ordered_nfa and transition_cells != expected_transition_cells:
        raise CensusError(
            "exact-span participation transition geometry does not close"
        )
    if ordered_nfa and fallback_required != fallback_limit + 1:
        raise CensusError("exact-span participation fallback envelope does not close")
    plan_bytes = parse_canonical_decimal(
        fields.get("participation_plan_bytes"),
        "exact-span participation plan bytes",
        NATIVE_PARTICIPATION_HEADER_BYTES,
        NATIVE_PARTICIPATION_MAX_PLAN_BYTES,
    )
    if ordered_nfa:
        states_offset = (
            NATIVE_PARTICIPATION_HEADER_BYTES
            + NATIVE_PARTICIPATION_ORDERED_NFA_METADATA_BYTES + 7
        ) & ~7
        ranges_offset = (
            states_offset
            + ordered_nfa_states * NATIVE_PARTICIPATION_ORDERED_NFA_STATE_BYTES
            + 7
        ) & ~7
        expected_plan_bytes = (
            ranges_offset
            + ordered_nfa_byte_ranges * NATIVE_PARTICIPATION_ORDERED_NFA_RANGE_BYTES
        )
        expected_scratch_bytes = (
            ordered_nfa_states
            * (3 * NATIVE_PARTICIPATION_ORDERED_NFA_THREAD_BYTES
               + NATIVE_PARTICIPATION_ORDERED_NFA_SEEN_BYTES)
            + 7
        ) & ~7
    else:
        expected_plan_bytes = participation_plan_bytes(
            assertions, assertion_signatures, dfa_states, transition_cells
        )
        expected_scratch_bytes = NATIVE_PARTICIPATION_SCRATCH_BYTES
    if plan_bytes != expected_plan_bytes:
        raise CensusError("exact-span participation plan extent does not close")
    scratch_bytes = parse_canonical_decimal(
        fields.get("participation_scratch_bytes"),
        "exact-span participation scratch bytes",
        expected_scratch_bytes, expected_scratch_bytes,
    )
    return {
        "capture_resolution": fields.get("capture_resolution"),
        "capture_group_count": parse_canonical_decimal(
            fields.get("capture_group_count"),
            "exact-span participation group count",
            1,
            MAX_NATIVE_ROW_COMPONENTS,
        ),
        "participation_algorithm_id": algorithm_id,
        "participation_strategy": strategy,
        "participation_semantic_runtime_calls": semantic_runtime_calls,
        "participation_assertions": assertions,
        "participation_assertion_signatures": assertion_signatures,
        "participation_byte_classes": byte_classes,
        "participation_dfa_states": dfa_states,
        "participation_transition_cells": transition_cells,
        "participation_ordered_nfa_states": ordered_nfa_states,
        "participation_ordered_nfa_byte_ranges": ordered_nfa_byte_ranges,
        "participation_dfa_fallback_resource": fallback_resource,
        "participation_dfa_fallback_required": fallback_required,
        "participation_dfa_fallback_limit": fallback_limit,
        "participation_build_work": parse_canonical_decimal(
            fields.get("participation_build_work"),
            "exact-span participation build work",
            1,
            NATIVE_PARTICIPATION_MAX_BUILD_WORK,
        ),
        "participation_scratch_bytes": scratch_bytes,
        "participation_plan_bytes": plan_bytes,
        "capture_source_sha256": require_hex64(
            fields.get("capture_source_sha256"),
            "exact-span participation source digest",
        ),
        "capture_selector_sha256": require_hex64(
            fields.get("capture_selector_sha256"),
            "exact-span participation selector digest",
        ),
        "capture_program_sha256": capture_program,
        "selector_object_sha256": selector_object,
        "participation_bundle_sha256": bundle_digest,
        "participation_export_identity_sha256": export_identity,
        "participation_object_sha256": participation_object,
        "capture_artifact_identity_sha256": require_hex64(
            fields.get("capture_artifact_identity_sha256"),
            "exact-span participation artifact identity digest",
        ),
        "participation_bundle_symbol": bundle_symbol,
        "capture_selector_symbol": selector_symbol,
        "participation_entry_symbol": entry_symbol,
    }


def selector_capture_fallback_proof_from_provenance(
    fields: dict[str, str], components: list[dict[str, object]]
) -> dict[str, object]:
    """Normalize the native-negative/stock-positive mixed capture boundary."""
    if len(components) != 1:
        raise CensusError(
            "selector capture fallback provenance does not have exactly one component"
        )
    component = components[0]
    selector = component["entry_symbol"]
    if (
        not isinstance(selector, str)
        or NATIVE_SEARCH_ENTRY_SYMBOL.fullmatch(selector) is None
        or component["required_runtime_symbols"]
    ):
        raise CensusError(
            "selector capture fallback component is not a helper-free native selector"
        )
    profile = fields.get("positive_fallback_profile")
    fallback_symbol = fields.get("positive_fallback_symbol")
    if profile != SELECTOR_CAPTURE_POSITIVE_FALLBACK_PROFILE:
        raise CensusError("selector capture fallback stock profile differs")
    if fallback_symbol != SELECTOR_CAPTURE_POSITIVE_FALLBACK_SYMBOL:
        raise CensusError("selector capture fallback marker symbol differs")
    resource = fields.get("direct_participation_resource")
    expected_limit = {
        "DfaStates": SELECTOR_CAPTURE_DFA_STATES_LIMIT,
        "BuildWork": SELECTOR_CAPTURE_BUILD_WORK_LIMIT,
    }.get(resource)
    if expected_limit is None:
        raise CensusError("selector capture fallback has an unknown direct resource")
    limit = parse_canonical_decimal(
        fields.get("direct_participation_limit"),
        "selector capture direct participation limit",
        expected_limit,
        expected_limit,
    )
    required = parse_canonical_decimal(
        fields.get("direct_participation_required"),
        "selector capture direct participation requirement",
        expected_limit + 1,
        expected_limit + 1,
    )
    if required != limit + 1:
        raise CensusError(
            "selector capture direct participation exhaustion is not exact"
        )
    return {
        "capture_resolution": fields.get("capture_resolution"),
        "positive_fallback_profile": profile,
        "positive_fallback_symbol": fallback_symbol,
        "direct_participation_resource": resource,
        "direct_participation_required": required,
        "direct_participation_limit": limit,
        "selector_entry_symbol": selector,
    }


def native_row_prepared_v15_limits(
    fields: dict[str, str], components: list[dict[str, object]]
) -> Optional[dict[str, int]]:
    has_prepared = any(component.get("prepared_v15") is not None for component in components)
    actual = {
        "max_handle_bytes": parse_canonical_decimal(
            fields.get("prepare_max_handle_bytes"),
            "native-row prepare max handle bytes",
        ),
        "max_scratch_bytes": parse_canonical_decimal(
            fields.get("prepare_max_scratch_bytes"),
            "native-row prepare max scratch bytes",
        ),
        "max_setup_work": parse_canonical_decimal(
            fields.get("prepare_max_setup_work"),
            "native-row prepare max setup work",
        ),
    }
    expected = {
        "max_handle_bytes": PREPARED_V15_MAX_HANDLE_BYTES if has_prepared else 0,
        "max_scratch_bytes": PREPARED_V15_MAX_SCRATCH_BYTES if has_prepared else 0,
        "max_setup_work": PREPARED_V15_MAX_SETUP_WORK if has_prepared else 0,
    }
    if actual != expected:
        raise CensusError("native-row prepared V15 effective cap receipt differs")
    return actual if has_prepared else None


def validate_native_row_engine_routes(
    fields: dict[str, str], components: list[dict[str, object]]
) -> None:
    engine = fields.get("engine", "")
    prefix = "IndependentNativeSpanRows("
    if not engine.startswith(prefix) or not engine.endswith(")"):
        raise CensusError("native-row engine list is malformed")
    engines = engine[len(prefix):-1].split(",")
    if len(engines) != len(components) or any(not value for value in engines):
        raise CensusError("native-row engine cardinality differs from its components")
    for index, (engine_name, component) in enumerate(zip(engines, components)):
        expected = (
            {"OrderedNfa"}
            if component.get("prepared_v15") is not None
            else {"OrderedDfa", "OrderedContextDfa"}
        )
        if engine_name not in expected:
            raise CensusError(
                f"native-row component {index} engine disagrees with its prepared route"
            )


def regex_redux_proof_from_provenance(
    fields: dict[str, str], components: list[dict[str, object]]
) -> dict[str, object]:
    """Authenticate the sealed helper-free one-call fixed operation."""
    if (
        fields.get("model") != "regex-redux"
        or fields.get("adapter") != "general-aot-native-regex-redux-reducer-v1"
        or fields.get("engine") != "NativeRegexReduxAotV1"
        or fields.get("aggregate_strategy")
        != "native-fixed-regex-redux-whole-operation-v1"
        or fields.get("boundary") != "single-call-native-regex-redux-reducer"
        or len(components) != 15
    ):
        raise CensusError("regex-redux provenance has a noncanonical native route")
    entries = [str(component["entry_symbol"]) for component in components]
    if (
        len(entries) != len(set(entries))
        or not all(NATIVE_SEARCH_ENTRY_SYMBOL.fullmatch(entry) for entry in entries)
        or any(component["required_runtime_symbols"] for component in components)
    ):
        raise CensusError("regex-redux components are not closed direct Span entries")
    operation_identity = fields.get("operation_identity_sha256", "")
    require_hex64(operation_identity, "regex-redux operation identity")
    if operation_identity == "0" * 64:
        raise CensusError("regex-redux operation identity is zero")
    reducer_symbol = fields.get("reducer_symbol", "")
    reducer_identity = symbol_identity_suffix(
        reducer_symbol,
        NATIVE_REGEX_REDUX_ENTRY_SYMBOL,
        "regex-redux reducer",
    )
    if reducer_identity != operation_identity:
        raise CensusError("regex-redux reducer symbol and operation identity disagree")
    digest_fields = (
        "reducer_code_sha256", "reducer_data_sha256", "reducer_object_sha256",
    )
    for name in digest_fields:
        digest = require_hex64(fields.get(name, ""), f"regex-redux {name}")
        if digest == "0" * 64:
            raise CensusError(f"regex-redux {name} is zero")
    link_symbols = fields.get("reducer_link_symbols", "").split(",")
    if link_symbols != entries:
        raise CensusError("regex-redux reducer link closure differs from its components")
    semantic_symbols = sorted(filter(
        None, fields.get("semantic_runtime_symbols", "").split(",")
    ))
    if semantic_symbols:
        raise CensusError("regex-redux reducer retains semantic runtime helpers")
    exact_decimal = {
        "abi_version": 1,
        "request_bytes": 72,
        "receipt_bytes": 144,
        "report_bytes": 1024,
        "scratch_buffer_count": 2,
        "scratch_capacity_numerator": 3,
        "scratch_capacity_denominator": 2,
    }
    for name, expected in exact_decimal.items():
        if parse_canonical_decimal(
            fields.get(name), f"regex-redux {name}", expected, expected
        ) != expected:
            raise CensusError(f"regex-redux {name} differs")
    expected_relocations = 16 if fields.get("target", "").startswith("x86_64-") else (
        17 if fields.get("target", "").startswith("aarch64-") else 0
    )
    if expected_relocations == 0 or parse_canonical_decimal(
        fields.get("reducer_relocation_count"),
        "regex-redux reducer relocation count",
        expected_relocations,
        expected_relocations,
    ) != expected_relocations:
        raise CensusError("regex-redux reducer relocation closure differs")
    if (
        fields.get("receipt_schema")
        != "u64-input-clean-variant9-substitution5-final-report-v1"
        or fields.get("report_schema")
        != "variant9-blank-input-clean-final-lines-v1"
    ):
        raise CensusError("regex-redux execution schema differs")
    return {
        "abi_version": 1,
        "operation_identity_sha256": operation_identity,
        "reducer_symbol": reducer_symbol,
        "reducer_code_sha256": fields["reducer_code_sha256"],
        "reducer_data_sha256": fields["reducer_data_sha256"],
        "reducer_object_sha256": fields["reducer_object_sha256"],
        "reducer_relocation_count": expected_relocations,
        "reducer_link_symbols": entries,
        "semantic_runtime_symbols": [],
        "request_bytes": 72,
        "receipt_bytes": 144,
        "report_bytes": 1024,
        "scratch_buffer_count": 2,
        "scratch_capacity_numerator": 3,
        "scratch_capacity_denominator": 2,
        "receipt_schema": fields["receipt_schema"],
        "report_schema": fields["report_schema"],
    }


def validate_v3_provenance(
    fields: dict[str, str], components: list[dict[str, object]]
) -> None:
    """Validate the exact raw v3 field set and composite topology."""
    if fields.get("disposition") != "executed":
        raise CensusError("composite provenance disposition is not executed")
    frozen_schedule_validation(fields)
    for name in ("compiler_version", "optimizer_version"):
        try:
            value = int(fields[name], 10)
        except ValueError as error:
            raise CensusError(f"composite provenance has invalid {name}") from error
        if value <= 0:
            raise CensusError(f"composite provenance has nonpositive {name}")
    base = {
        "schema", "disposition", "configured", "adapter", "model", "benchmark",
        "source_commit", "source_tree", "target", "feature_bits",
        "compiler_version", "optimizer_version", "engine", "aggregate_strategy",
        "component_count", "boundary", "required_comparators",
    } | FROZEN_VALIDATION_FIELDS
    component_fields = {
        f"component_{index}_{suffix}"
        for index in range(len(components))
        for suffix in (
            "native", "entry_symbol", "runtime_symbols", "program_sha256",
            "object_sha256",
        )
    }
    if fields["model"] == "regex-redux":
        regex_redux_proof_from_provenance(fields, components)
        expected = base | component_fields | {
            "reducer_symbol", "operation_identity_sha256", "reducer_code_sha256",
            "reducer_data_sha256", "reducer_object_sha256",
            "reducer_relocation_count", "reducer_link_symbols",
            "semantic_runtime_symbols", "abi_version", "request_bytes",
            "receipt_bytes", "report_bytes", "scratch_buffer_count",
            "scratch_capacity_numerator", "scratch_capacity_denominator",
            "receipt_schema", "report_schema",
        }
    elif fields.get("native_row_bridge") == "true":
        component_fields |= {
            f"component_{index}_{suffix}"
            for index in range(len(components))
            for suffix in (
                "source_ordinal", "required_prepare_capabilities",
                "prepare_config_version", "prepare_operation_flags",
                "runtime_program_symbol", "runtime_program_len", "span_fill_symbol",
                "prepared_bulk_strategy", "automaton_sha256",
            )
        }
        additive_surface_fields = {
            f"component_{index}_{suffix}"
            for index in range(len(components))
            for suffix in ("entry_abi", "prepared_surface")
        }
        present_surface_fields = additive_surface_fields & set(fields)
        if present_surface_fields:
            if present_surface_fields != additive_surface_fields:
                raise CensusError(
                    "runner v3 native-row ABI/surface fields are only partially present"
                )
            component_fields |= additive_surface_fields
        expected = base | component_fields | {
            "native_row_bridge", "uniform_capture_bridge", "source_pattern_count",
            "row_total_object_bytes", "source_to_artifact",
            "prepare_max_handle_bytes", "prepare_max_scratch_bytes",
            "prepare_max_setup_work",
        }
        prepared_limits = native_row_prepared_v15_limits(fields, components)
        validate_native_row_engine_routes(fields, components)
        has_prepared = prepared_limits is not None
        uniform_capture = fields.get("uniform_capture_bridge")
        native_row_scalar = fields.get("native_row_scalar_reducer") == "true"
        native_multi_grep = fields.get("native_multi_grep_reducer") == "true"
        if native_row_scalar:
            reducer_fields = {
                "native_row_scalar_reducer", "row_scalar_reducer_abi_version",
                "row_scalar_reducer_operation",
                "row_scalar_reducer_mixed_handle_table",
                "row_scalar_reducer_required_handle_count",
                "row_scalar_reducer_row_routes",
                "row_scalar_reducer_source_cardinality",
                "row_scalar_reducer_source_bytes",
                "row_scalar_reducer_ordered_sources_sha256",
                "row_scalar_reducer_symbol",
                "row_scalar_reducer_operation_identity_sha256",
                "row_scalar_reducer_code_sha256",
                "row_scalar_reducer_object_sha256",
                "row_scalar_reducer_relocation_count",
                "row_scalar_reducer_relocation_sections",
                "row_scalar_reducer_relocation_offsets",
                "row_scalar_reducer_relocation_kinds",
                "row_scalar_reducer_relocation_symbols",
                "row_scalar_reducer_relocation_addends",
                "row_scalar_reducer_semantic_runtime_calls",
                "row_scalar_reducer_object_bytes",
                "row_scalar_reducer_max_object_bytes",
                "row_scalar_reducer_artifact_identity_sha256",
            }
            expected |= reducer_fields
            if uniform_capture != "false" or native_multi_grep:
                raise CensusError("row-scalar reducer overlaps another row route")
            source_count, row_bytes, source_map = native_row_topology(
                fields, components, 2
            )
            row_scalar_reducer_proof_from_provenance(
                fields, components, source_count, row_bytes, source_map
            )
        elif native_multi_grep:
            reducer_fields = {
                "native_multi_grep_reducer", "multi_grep_reducer_abi_version",
                "multi_grep_reducer_mixed_handle_table",
                "multi_grep_reducer_required_handle_count",
                "multi_grep_reducer_row_routes",
                "multi_grep_reducer_source_cardinality",
                "multi_grep_reducer_source_bytes",
                "multi_grep_reducer_ordered_sources_sha256",
                "multi_grep_reducer_symbol",
                "multi_grep_reducer_operation_identity_sha256",
                "multi_grep_reducer_code_sha256",
                "multi_grep_reducer_object_sha256",
                "multi_grep_reducer_relocation_count",
                "multi_grep_reducer_semantic_runtime_calls",
                "multi_grep_reducer_object_bytes",
                "multi_grep_reducer_max_object_bytes",
                "multi_grep_reducer_artifact_identity_sha256",
            }
            expected |= reducer_fields
            if uniform_capture != "false":
                raise CensusError("multi-grep reducer overlaps another row route")
            source_count, row_bytes, source_map = native_row_topology(
                fields, components, 2
            )
            multi_grep_reducer_proof_from_provenance(
                fields, components, source_count, row_bytes, source_map
            )
        elif uniform_capture == "false" and not has_prepared and fields["model"] in {
            "count", "count-spans", "grep",
        }:
            if fields.get("boundary") != "complete-native-row-bridge":
                raise CensusError("native-row provenance has the wrong operation boundary")
            expected_adapter = {
                "count": "general-aot-native-row-bridge-count-v1",
                "count-spans": "general-aot-native-row-bridge-count-spans-v1",
                "grep": "general-aot-native-row-bridge-grep-v1",
            }[fields["model"]]
            expected_strategy = (
                "per-line-native-independent-span-row-exists-v1"
                if fields["model"] == "grep"
                else "native-independent-span-row-selector-v1"
            )
            if (
                fields.get("adapter") != expected_adapter
                or fields.get("aggregate_strategy") != expected_strategy
            ):
                raise CensusError("native-row provenance has the wrong typed route")
            native_row_topology(fields, components, 2)
        elif uniform_capture == "false" and has_prepared and fields[
            "model"
        ] in {"count", "count-spans", "grep"}:
            expected_adapter = {
                "count": (
                    "general-aot-native-row-bridge-count-mixed-prepared-ordered-nfa-v15-v1"
                ),
                "count-spans": (
                    "general-aot-native-row-bridge-count-spans-mixed-prepared-ordered-nfa-v15-v1"
                ),
                "grep": (
                    "general-aot-native-row-bridge-grep-mixed-prepared-ordered-nfa-v15-v1"
                ),
            }[fields["model"]]
            expected_strategy = (
                "per-line-native-independent-span-row-exists-mixed-prepared-v15-v1"
                if fields["model"] == "grep"
                else "native-independent-span-row-selector-mixed-prepared-v15-v1"
            )
            if (
                fields.get("boundary") != "complete-native-row-bridge"
                or fields.get("adapter") != expected_adapter
                or fields.get("aggregate_strategy") != expected_strategy
            ):
                raise CensusError("mixed prepared V15 provenance has the wrong typed route")
            native_row_topology(fields, components, 2)
        elif uniform_capture == "true" and not has_prepared and fields[
            "model"
        ] in UNIFORM_CAPTURE_ADAPTER_MODELS:
            if fields.get("boundary") != "native-search-core-static-uniform-capture-resolution":
                raise CensusError(
                    "uniform-capture provenance has the wrong operation boundary"
                )
            if fields.get("capture_resolution") != "static-uniform-multiplier":
                raise CensusError("uniform-capture resolution is not the proved static route")
            expected_adapter = {
                "count-captures": (
                    "general-aot-uniform-capture-native-row-count-adapter-loop-v1"
                ),
                "grep-captures": (
                    "general-aot-uniform-capture-native-row-grep-adapter-loop-v1"
                ),
            }[fields["model"]]
            if fields.get("adapter") != expected_adapter:
                raise CensusError("uniform-capture provenance has the wrong adapter")
            if fields.get("aggregate_strategy") != (
                "native-row-static-uniform-capture-multiplier-v1"
            ):
                raise CensusError("uniform-capture provenance has the wrong strategy")
            proof_fields = {
                "capture_resolution", "capture_proof_algorithm_version",
                "capture_proof_accounting_version", "source_participating_groups",
                "source_minimum_match_bytes", "source_capture_annotations",
                "source_proof_work", "source_proof_peak_stack_items",
                "source_selector_automaton_sha256",
                "source_selector_program_sha256", "source_selector_object_sha256",
            }
            expected |= proof_fields
            source_count, _, source_to_artifact = native_row_topology(
                fields, components, 1
            )
            uniform_capture_proof_from_provenance(
                fields, components, source_count, source_to_artifact
            )
        else:
            raise CensusError("runner v3 provenance has an unknown native-row route")
    else:
        raise CensusError("runner v3 provenance has an unknown composite route")
    if set(fields) != expected:
        raise CensusError(
            "runner v3 provenance field closure differs: "
            f"missing={sorted(expected - set(fields))!r} "
            f"extra={sorted(set(fields) - expected)!r}"
        )


def validate_v4_provenance(
    fields: dict[str, str], components: list[dict[str, object]]
) -> None:
    """Validate the closed one-pattern native-capture v4 contracts."""
    if fields.get("disposition") != "executed":
        raise CensusError("native-capture provenance disposition is not executed")
    frozen_schedule_validation(fields)
    for name in ("compiler_version", "optimizer_version"):
        parse_canonical_decimal(
            fields.get(name), f"native-capture provenance {name}", 1, (1 << 32) - 1
        )
    if re.fullmatch(r"[0-9a-f]{16}", fields.get("feature_bits", "")) is None:
        raise CensusError("native-capture provenance has invalid feature_bits")
    source_count, _, source_to_artifact = native_row_topology(fields, components, 1)
    if source_count != 1 or source_to_artifact != [0]:
        raise CensusError(
            "native-capture provenance is not exactly one source and artifact"
        )
    base = {
        "schema", "disposition", "configured", "adapter", "model", "benchmark",
        "source_commit", "source_tree", "target", "feature_bits",
        "compiler_version", "optimizer_version", "engine", "aggregate_strategy",
        "native_row_bridge", "uniform_capture_bridge", "strict_capture_bridge",
        "source_pattern_count", "row_total_object_bytes", "source_to_artifact",
        "component_count", "capture_resolution", "boundary", "required_comparators",
    } | FROZEN_VALIDATION_FIELDS
    component_fields = {
        f"component_0_{suffix}"
        for suffix in (
            "native", "source_ordinal", "entry_symbol", "runtime_symbols",
            "program_sha256", "object_sha256",
        )
    }
    selector_fallback = fields.get("selector_capture_fallback_bridge") == "true"
    if selector_fallback:
        if (
            fields.get("adapter")
            != "general-aot-native-selector-negative-certificate-stock-positive-capture-fallback-v1"
            or fields.get("model") != "grep-captures"
            or fields.get("engine") != SELECTOR_CAPTURE_ENGINE
            or fields.get("aggregate_strategy")
            != "native-selector-negative-certificate-with-stock-positive-capture-fallback-v1"
            or fields.get("native_row_bridge") != "true"
            or fields.get("uniform_capture_bridge") != "false"
            or fields.get("strict_capture_bridge") != "false"
            or fields.get("participation_capture_bridge") != "false"
            or fields.get("capture_resolution")
            != "native-selector-negative-certificate-with-stock-positive-capture-fallback-v1"
            or fields.get("boundary")
            != "per-line-native-span-negative-certificate-with-trap-visible-stock-positive-capture-fallback"
        ):
            raise CensusError(
                "selector capture fallback provenance has a noncanonical route"
            )
        selector_capture_fallback_proof_from_provenance(fields, components)
        fallback_fields = {
            "participation_capture_bridge", "selector_capture_fallback_bridge",
            "positive_fallback_profile", "positive_fallback_symbol",
            "direct_participation_resource", "direct_participation_required",
            "direct_participation_limit",
        }
        expected = base | component_fields | fallback_fields
        if set(fields) != expected:
            raise CensusError(
                "runner selector capture fallback v4 field closure differs: "
                f"missing={sorted(expected - set(fields))!r} "
                f"extra={sorted(set(fields) - expected)!r}"
            )
        return

    participation = fields.get("participation_capture_bridge") == "true"
    if participation:
        expected_adapter = {
            "count-captures": "general-aot-native-exact-span-participation-count-v1",
            "grep-captures": "general-aot-native-exact-span-participation-grep-v1",
        }.get(fields.get("model"))
        if expected_adapter is None or fields.get("adapter") != expected_adapter:
            raise CensusError(
                "exact-span participation provenance has the wrong adapter"
            )
        if (
            fields.get("engine") != "NativeExactSpanParticipationDfaV1"
            or fields.get("aggregate_strategy")
            != "native-exact-span-participation-dfa-v1"
            or fields.get("native_row_bridge") != "true"
            or fields.get("uniform_capture_bridge") != "false"
            or fields.get("strict_capture_bridge") != "false"
            or fields.get("capture_resolution")
            != "native-exact-span-participation-dfa-v1"
            or fields.get("boundary")
            != "native-span-selector-with-helper-free-exact-span-participation-replay"
        ):
            raise CensusError(
                "exact-span participation provenance has a noncanonical route"
            )
        participation_capture_proof_from_provenance(fields, components)
        participation_fields = {
            "participation_capture_bridge", "participation_algorithm_id",
            "participation_strategy", "participation_semantic_runtime_calls",
            "participation_assertions", "participation_assertion_signatures",
            "participation_byte_classes", "participation_dfa_states",
            "participation_transition_cells", "participation_ordered_nfa_states",
            "participation_ordered_nfa_byte_ranges",
            "participation_dfa_fallback_resource",
            "participation_dfa_fallback_required",
            "participation_dfa_fallback_limit", "participation_build_work",
            "participation_scratch_bytes", "participation_plan_bytes",
            "selector_object_sha256", "participation_bundle_sha256",
            "participation_export_identity_sha256", "participation_object_sha256",
            "participation_bundle_symbol", "participation_entry_symbol",
            "capture_group_count", "capture_source_sha256",
            "capture_selector_sha256", "capture_program_sha256",
            "capture_artifact_identity_sha256", "capture_selector_symbol",
        }
        expected = base | component_fields | participation_fields
        if set(fields) != expected:
            raise CensusError(
                "runner participation v4 provenance field closure differs: "
                f"missing={sorted(expected - set(fields))!r} "
                f"extra={sorted(set(fields) - expected)!r}"
            )
        return

    expected_adapter = {
        "count-captures": "general-aot-native-single-capture-next-count-v1",
        "grep-captures": "general-aot-native-single-capture-next-grep-v1",
    }.get(fields.get("model"))
    if expected_adapter is None or fields.get("adapter") != expected_adapter:
        raise CensusError("strict-capture provenance has the wrong adapter")
    if (
        fields.get("engine") != "NativeOnePassCaptureV1"
        or fields.get("aggregate_strategy")
        != "native-single-capture-next-participation-v1"
        or fields.get("native_row_bridge") != "true"
        or fields.get("uniform_capture_bridge") != "false"
        or fields.get("strict_capture_bridge") != "true"
        or fields.get("capture_resolution") != "native-onepass-capture-next-v1"
        or fields.get("boundary")
        != "native-search-core-with-native-capture-materialization-adapter-loop"
    ):
        raise CensusError("strict-capture provenance has a noncanonical route")
    strict_capture_proof_from_provenance(fields, components)
    strict_fields = {
        "capture_can_match_empty", "capture_plan_sha256", "capture_bundle_sha256",
        "capture_materialize_symbol", "capture_group_count", "capture_source_sha256",
        "capture_selector_sha256", "capture_program_sha256",
        "capture_artifact_identity_sha256", "capture_selector_symbol",
    }
    expected = base | component_fields | strict_fields
    if set(fields) != expected:
        raise CensusError(
            "runner v4 provenance field closure differs: "
            f"missing={sorted(expected - set(fields))!r} "
            f"extra={sorted(set(fields) - expected)!r}"
        )


def single_capture_reducer_proof_from_provenance(
    fields: dict[str, str],
) -> dict[str, object]:
    """Authenticate and normalize the closed helper-free v5 reducer receipt."""
    model = fields.get("model")
    operation_contract = {
        "count-captures": (
            "count-captures", "whole-haystack",
            NATIVE_SINGLE_CAPTURE_COUNT_REDUCER_SYMBOL,
            NATIVE_SINGLE_CAPTURE_COUNT_SCRATCH_REDUCER_SYMBOL,
        ),
        "grep-captures": (
            "grep-captures", "byte-slice-lines-lf-crlf",
            NATIVE_SINGLE_CAPTURE_GREP_REDUCER_SYMBOL,
            NATIVE_SINGLE_CAPTURE_GREP_SCRATCH_REDUCER_SYMBOL,
        ),
    }.get(model)
    if operation_contract is None:
        raise CensusError("single-capture reducer has an unsupported model")
    operation, domain, legacy_reducer_pattern, scratch_reducer_pattern = operation_contract
    if fields.get("operation") != operation or fields.get("domain") != domain:
        raise CensusError("single-capture reducer operation/domain differs from its model")
    source_route = fields.get("source_route")
    if source_route not in {
        "exact-span-participation-v1", "capture-next-v1",
    }:
        raise CensusError("single-capture reducer source route is not canonical")
    target_architecture(fields.get("target", ""))
    if re.fullmatch(r"[0-9a-f]{16}", fields.get("feature_bits", "")) is None:
        raise CensusError("single-capture reducer feature bits are not canonical")
    source_pattern_count = parse_canonical_decimal(
        fields.get("source_pattern_count"),
        "single-capture reducer source pattern count", 1, 1,
    )
    source_cardinality = parse_canonical_decimal(
        fields.get("source_cardinality"),
        "single-capture reducer source cardinality", 1, 1,
    )
    source_bytes = parse_canonical_decimal(
        fields.get("source_bytes"), "single-capture reducer source bytes",
        0, (1 << 64) - 1,
    )
    group_maximum = (
        NATIVE_PARTICIPATION_MAX_ASSERTIONS
        if source_route == "exact-span-participation-v1"
        else NATIVE_CAPTURE_MAX_GROUPS
    )
    group_count = parse_canonical_decimal(
        fields.get("group_count"), "single-capture reducer group count",
        1, group_maximum,
    )
    can_match_empty_text = fields.get("can_match_empty")
    if can_match_empty_text not in {"true", "false"}:
        raise CensusError("single-capture reducer nullable flag is not canonical")
    if fields.get("empty_progress") != "byte":
        raise CensusError("single-capture reducer empty progress is not byte")
    semantic_runtime_calls = parse_canonical_decimal(
        fields.get("semantic_runtime_calls"),
        "single-capture reducer semantic runtime calls", 0, 0,
    )
    caller_scratch_bytes = parse_canonical_decimal(
        fields.get("caller_scratch_bytes"),
        "single-capture reducer caller scratch bytes", 0,
        NATIVE_PARTICIPATION_MAX_ORDERED_NFA_SCRATCH_BYTES,
    )
    private_participation_scratch_bytes = parse_canonical_decimal(
        fields.get("private_participation_scratch_bytes"),
        "single-capture reducer private participation scratch bytes", 0,
        NATIVE_PARTICIPATION_SCRATCH_BYTES,
    )
    private_iterator_state_bytes = parse_canonical_decimal(
        fields.get("private_iterator_state_bytes"),
        "single-capture reducer private iterator state bytes", 0,
        NATIVE_CAPTURE_ITERATOR_STATE_BYTES,
    )
    private_result_slot_count = parse_canonical_decimal(
        fields.get("private_result_slot_count"),
        "single-capture reducer private result slot count", 0,
        NATIVE_CAPTURE_MAX_GROUPS,
    )
    private_result_slot_bytes = parse_canonical_decimal(
        fields.get("private_result_slot_bytes"),
        "single-capture reducer private result slot bytes", 0,
        NATIVE_CAPTURE_MAX_GROUPS * NATIVE_CAPTURE_RESULT_SLOT_BYTES,
    )
    ordered_participation = fields.get("participation_strategy") in {"4", "5"}
    reducer_pattern = (
        scratch_reducer_pattern if ordered_participation else legacy_reducer_pattern
    )
    if source_route == "exact-span-participation-v1" and ordered_participation:
        expected_private = (0, 0, 0, 0)
    elif source_route == "exact-span-participation-v1":
        expected_private = (NATIVE_PARTICIPATION_SCRATCH_BYTES, 0, 0, 0)
    else:
        expected_private = (
            0, NATIVE_CAPTURE_ITERATOR_STATE_BYTES, group_count,
            group_count * NATIVE_CAPTURE_RESULT_SLOT_BYTES,
        )
    if (
        private_participation_scratch_bytes, private_iterator_state_bytes,
        private_result_slot_count, private_result_slot_bytes,
    ) != expected_private:
        raise CensusError(
            "single-capture reducer private schema differs from its source route"
        )
    if not ordered_participation and caller_scratch_bytes != 0:
        raise CensusError(
            "legacy single-capture reducer unexpectedly requires caller scratch"
        )
    digest_fields = {
        name: require_nonzero_hex64(
            fields.get(name), f"single-capture reducer {name}"
        )
        for name in (
            "source_pattern_sha256", "source_sha256", "selector_sha256",
            "capture_sha256",
            "source_artifact_identity_sha256", "source_object_sha256",
            "reducer_symbol_sha256", "object_sha256", "artifact_identity_sha256",
        )
    }
    reducer_symbol = fields.get("reducer_symbol")
    if (
        not isinstance(reducer_symbol, str)
        or reducer_pattern.fullmatch(reducer_symbol) is None
    ):
        raise CensusError("single-capture reducer symbol is not canonical for its model")
    if digest_fields["reducer_symbol_sha256"] != sha_bytes(
        reducer_symbol.encode("ascii", "strict")
    ):
        raise CensusError("single-capture reducer symbol digest does not authenticate symbol")
    if digest_fields["source_pattern_sha256"] == digest_fields["source_sha256"]:
        raise CensusError(
            "single-capture reducer raw-pattern and source-receipt digests are not distinct"
        )
    if fields.get("operation_entry_symbol") != reducer_symbol:
        raise CensusError("single-capture reducer operation entry is not the reducer")
    if digest_fields["source_object_sha256"] == digest_fields["object_sha256"]:
        raise CensusError("single-capture reducer source and final objects are not distinct")
    if (
        digest_fields["source_artifact_identity_sha256"]
        == digest_fields["artifact_identity_sha256"]
    ):
        raise CensusError("single-capture reducer source and final identities are not distinct")
    object_bytes = parse_canonical_decimal(
        fields.get("object_bytes"), "single-capture reducer object bytes",
        1, MAX_NATIVE_ROW_OBJECT_BYTES,
    )
    max_object_bytes = parse_canonical_decimal(
        fields.get("max_object_bytes"), "single-capture reducer maximum object bytes",
        MAX_NATIVE_ROW_OBJECT_BYTES, MAX_NATIVE_ROW_OBJECT_BYTES,
    )
    if object_bytes > max_object_bytes:
        raise CensusError("single-capture reducer object exceeds its receipt cap")

    participation_source: Optional[dict[str, object]] = None
    capture_next_source: Optional[dict[str, object]] = None
    if source_route == "exact-span-participation-v1":
        selector_symbol = fields.get("participation_selector_symbol")
        entry_symbol = fields.get("participation_entry_symbol")
        bundle_symbol = fields.get("participation_bundle_symbol")
        export_identity = require_nonzero_hex64(
            fields.get("participation_export_identity_sha256"),
            "single-capture participation export identity",
        )
        selector_object = require_nonzero_hex64(
            fields.get("participation_selector_object_sha256"),
            "single-capture participation selector object",
        )
        bundle_sha256 = require_nonzero_hex64(
            fields.get("participation_bundle_sha256"),
            "single-capture participation bundle",
        )
        if (
            not isinstance(selector_symbol, str)
            or NATIVE_SEARCH_ENTRY_SYMBOL.fullmatch(selector_symbol) is None
            or not isinstance(entry_symbol, str)
            or NATIVE_PARTICIPATION_ENTRY_SYMBOL.fullmatch(entry_symbol) is None
            or not isinstance(bundle_symbol, str)
            or NATIVE_PARTICIPATION_BUNDLE_SYMBOL.fullmatch(bundle_symbol) is None
            or len({reducer_symbol, selector_symbol, entry_symbol, bundle_symbol}) != 4
            or not entry_symbol.endswith(export_identity)
            or not bundle_symbol.endswith(export_identity)
        ):
            raise CensusError("single-capture participation child symbols are not canonical")
        if export_identity != participation_export_identity(
            bundle_sha256, fields.get("target", ""),
            fields.get("feature_bits", ""), selector_object, selector_symbol,
        ):
            raise CensusError(
                "single-capture participation export identity does not authenticate its inputs"
            )
        architecture = target_architecture(fields.get("target", ""))
        expected_strategy = (
            {"x86_64": 4, "aarch64": 5}[architecture]
            if ordered_participation
            else {"x86_64": 1, "aarch64": 2}[architecture]
        )
        strategy = parse_canonical_decimal(
            fields.get("participation_strategy"),
            "single-capture participation strategy",
            expected_strategy, expected_strategy,
        )
        assertions = parse_canonical_decimal(
            fields.get("participation_assertions"),
            "single-capture participation assertions",
            0, NATIVE_PARTICIPATION_MAX_ASSERTIONS,
        )
        lower = 0 if ordered_participation else 1
        assertion_signatures = parse_canonical_decimal(
            fields.get("participation_assertion_signatures"),
            "single-capture participation assertion signatures", lower,
            0 if ordered_participation else NATIVE_PARTICIPATION_MAX_ASSERTION_SIGNATURES,
        )
        byte_classes = parse_canonical_decimal(
            fields.get("participation_byte_classes"),
            "single-capture participation byte classes", lower,
            0 if ordered_participation else NATIVE_PARTICIPATION_MAX_BYTE_CLASSES,
        )
        dfa_states = parse_canonical_decimal(
            fields.get("participation_dfa_states"),
            "single-capture participation DFA states", lower,
            0 if ordered_participation else NATIVE_PARTICIPATION_MAX_DFA_STATES,
        )
        transition_cells = parse_canonical_decimal(
            fields.get("participation_transition_cells"),
            "single-capture participation transition cells", lower,
            0 if ordered_participation else NATIVE_PARTICIPATION_MAX_TRANSITION_CELLS,
        )
        ordered_nfa_states = parse_canonical_decimal(
            fields.get("participation_ordered_nfa_states"),
            "single-capture participation ordered-NFA states",
            1 if ordered_participation else 0,
            NATIVE_PARTICIPATION_MAX_PLAN_BYTES if ordered_participation else 0,
        )
        ordered_nfa_byte_ranges = parse_canonical_decimal(
            fields.get("participation_ordered_nfa_byte_ranges"),
            "single-capture participation ordered-NFA byte ranges", 0,
            NATIVE_PARTICIPATION_MAX_PLAN_BYTES if ordered_participation else 0,
        )
        fallback_resource = parse_canonical_decimal(
            fields.get("participation_dfa_fallback_resource"),
            "single-capture participation DFA fallback resource",
            1 if ordered_participation else 0,
            2 if ordered_participation else 0,
        )
        fallback_required = parse_canonical_decimal(
            fields.get("participation_dfa_fallback_required"),
            "single-capture participation DFA fallback required",
            1 if ordered_participation else 0,
            (1 << 32) - 1 if ordered_participation else 0,
        )
        fallback_limit = parse_canonical_decimal(
            fields.get("participation_dfa_fallback_limit"),
            "single-capture participation DFA fallback limit",
            0, (1 << 32) - 1 if ordered_participation else 0,
        )
        if ordered_participation:
            if fallback_required != fallback_limit + 1:
                raise CensusError(
                    "single-capture ordered-NFA fallback envelope does not close"
                )
        elif transition_cells != dfa_states * byte_classes * assertion_signatures:
            raise CensusError("single-capture participation transition geometry does not close")
        plan_bytes = parse_canonical_decimal(
            fields.get("participation_plan_bytes"),
            "single-capture participation plan bytes",
            NATIVE_PARTICIPATION_HEADER_BYTES, NATIVE_PARTICIPATION_MAX_PLAN_BYTES,
        )
        if ordered_participation:
            states_offset = (
                NATIVE_PARTICIPATION_HEADER_BYTES
                + NATIVE_PARTICIPATION_ORDERED_NFA_METADATA_BYTES + 7
            ) & ~7
            ranges_offset = (
                states_offset
                + ordered_nfa_states * NATIVE_PARTICIPATION_ORDERED_NFA_STATE_BYTES
                + 7
            ) & ~7
            expected_plan_bytes = (
                ranges_offset
                + ordered_nfa_byte_ranges
                * NATIVE_PARTICIPATION_ORDERED_NFA_RANGE_BYTES
            )
            expected_scratch_bytes = (
                ordered_nfa_states
                * (
                    3 * NATIVE_PARTICIPATION_ORDERED_NFA_THREAD_BYTES
                    + NATIVE_PARTICIPATION_ORDERED_NFA_SEEN_BYTES
                )
                + 7
            ) & ~7
        else:
            expected_plan_bytes = participation_plan_bytes(
                assertions, assertion_signatures, dfa_states, transition_cells
            )
            expected_scratch_bytes = NATIVE_PARTICIPATION_SCRATCH_BYTES
        if plan_bytes != expected_plan_bytes:
            raise CensusError("single-capture participation plan extent does not close")
        scratch_bytes = parse_canonical_decimal(
            fields.get("participation_scratch_bytes"),
            "single-capture participation scratch bytes",
            expected_scratch_bytes, expected_scratch_bytes,
        )
        if ordered_participation and caller_scratch_bytes != scratch_bytes:
            raise CensusError(
                "single-capture ordered-NFA caller scratch differs from its receipt"
            )
        participation_source = {
            "algorithm_id": fields.get("participation_algorithm_id"),
            "strategy": strategy,
            "assertions": assertions,
            "assertion_signatures": assertion_signatures,
            "byte_classes": byte_classes,
            "dfa_states": dfa_states,
            "transition_cells": transition_cells,
            "ordered_nfa_states": ordered_nfa_states,
            "ordered_nfa_byte_ranges": ordered_nfa_byte_ranges,
            "dfa_fallback_resource": fallback_resource,
            "dfa_fallback_required": fallback_required,
            "dfa_fallback_limit": fallback_limit,
            "build_work": parse_canonical_decimal(
                fields.get("participation_build_work"),
                "single-capture participation build work",
                1, NATIVE_PARTICIPATION_MAX_BUILD_WORK,
            ),
            "scratch_bytes": scratch_bytes,
            "plan_bytes": plan_bytes,
            "selector_object_sha256": selector_object,
            "bundle_sha256": bundle_sha256,
            "export_identity_sha256": export_identity,
            "bundle_symbol": bundle_symbol,
            "selector_symbol": selector_symbol,
            "entry_symbol": entry_symbol,
        }
        expected_algorithm = (
            NATIVE_PARTICIPATION_ORDERED_NFA_ALGORITHM_ID
            if ordered_participation else NATIVE_PARTICIPATION_ALGORITHM_ID
        )
        if participation_source["algorithm_id"] != expected_algorithm:
            raise CensusError("single-capture participation algorithm identity differs")
    else:
        plan_sha256 = require_nonzero_hex64(
            fields.get("capture_plan_sha256"),
            "single-capture CaptureNext plan digest",
        )
        bundle_sha256 = require_nonzero_hex64(
            fields.get("capture_bundle_sha256"),
            "single-capture CaptureNext bundle digest",
        )
        next_symbol = fields.get("capture_next_symbol")
        materialize_symbol = fields.get("capture_materialize_symbol")
        selector_symbol = fields.get("capture_selector_symbol")
        if (
            not isinstance(next_symbol, str)
            or NATIVE_CAPTURE_NEXT_ENTRY_SYMBOL.fullmatch(next_symbol) is None
            or not isinstance(materialize_symbol, str)
            or NATIVE_CAPTURE_MATERIALIZE_SYMBOL.fullmatch(materialize_symbol) is None
            or not isinstance(selector_symbol, str)
            or NATIVE_SEARCH_ENTRY_SYMBOL.fullmatch(selector_symbol) is None
            or len({reducer_symbol, next_symbol, materialize_symbol, selector_symbol}) != 4
        ):
            raise CensusError("single-capture CaptureNext child symbols are not canonical")
        capture_next_source = {
            "plan_sha256": plan_sha256,
            "bundle_sha256": bundle_sha256,
            "next_symbol": next_symbol,
            "materialize_symbol": materialize_symbol,
            "selector_symbol": selector_symbol,
        }
    return {
        "operation": operation,
        "domain": domain,
        "source_route": source_route,
        "source_cardinality": source_cardinality,
        "source_bytes": source_bytes,
        "source_pattern_sha256": digest_fields["source_pattern_sha256"],
        "source_sha256": digest_fields["source_sha256"],
        "group_count": group_count,
        "can_match_empty": can_match_empty_text == "true",
        "empty_progress": "byte",
        "semantic_runtime_calls": semantic_runtime_calls,
        "caller_scratch_bytes": caller_scratch_bytes,
        "private_participation_scratch_bytes": private_participation_scratch_bytes,
        "private_iterator_state_bytes": private_iterator_state_bytes,
        "private_result_slot_count": private_result_slot_count,
        "private_result_slot_bytes": private_result_slot_bytes,
        "selector_sha256": digest_fields["selector_sha256"],
        "capture_sha256": digest_fields["capture_sha256"],
        "source_artifact_identity_sha256": (
            digest_fields["source_artifact_identity_sha256"]
        ),
        "source_object_sha256": digest_fields["source_object_sha256"],
        "reducer_symbol": reducer_symbol,
        "reducer_symbol_sha256": digest_fields["reducer_symbol_sha256"],
        "object_sha256": digest_fields["object_sha256"],
        "object_bytes": object_bytes,
        "max_object_bytes": max_object_bytes,
        "artifact_identity_sha256": digest_fields["artifact_identity_sha256"],
        "participation_source": participation_source,
        "capture_next_source": capture_next_source,
    }


def validate_v5_provenance(fields: dict[str, str]) -> None:
    """Validate the exact one-call, one-source reducer provenance closure."""
    if fields.get("disposition") != "executed":
        raise CensusError("single-capture reducer provenance disposition is not executed")
    frozen_schedule_validation(fields)
    for name in ("compiler_version", "optimizer_version"):
        parse_canonical_decimal(
            fields.get(name), f"single-capture reducer provenance {name}",
            1, (1 << 32) - 1,
        )
    proof = single_capture_reducer_proof_from_provenance(fields)
    ordered_participation = (
        proof["source_route"] == "exact-span-participation-v1"
        and proof["participation_source"] is not None
        and proof["participation_source"]["strategy"] in {4, 5}
    )
    expected_adapter = {
        ("count-captures", "exact-span-participation-v1"):
            "general-aot-native-exact-span-participation-count-reducer-v1",
        ("grep-captures", "exact-span-participation-v1"):
            "general-aot-native-exact-span-participation-grep-reducer-v1",
        ("count-captures", "capture-next-v1"):
            "general-aot-native-single-capture-next-count-reducer-v1",
        ("grep-captures", "capture-next-v1"):
            "general-aot-native-single-capture-next-grep-reducer-v1",
    }[(fields["model"], proof["source_route"])]
    if ordered_participation:
        expected_adapter = {
            "count-captures": (
                "general-aot-native-exact-span-ordered-nfa-participation-count-reducer-v1"
            ),
            "grep-captures": (
                "general-aot-native-exact-span-ordered-nfa-participation-grep-reducer-v1"
            ),
        }[fields["model"]]
    expected_engine, expected_strategy = {
        "exact-span-participation-v1": (
            "NativeExactSpanParticipationDfaV1",
            "native-exact-span-participation-whole-operation-reducer-v1",
        ),
        "capture-next-v1": (
            "NativeOnePassCaptureV1",
            "native-single-capture-next-whole-operation-reducer-v1",
        ),
    }[proof["source_route"]]
    if ordered_participation:
        expected_engine = "NativeExactSpanParticipationOrderedNfaV1"
        expected_strategy = (
            "native-exact-span-participation-ordered-nfa-whole-operation-reducer-v1"
        )
    if (
        fields.get("adapter") != expected_adapter
        or fields.get("engine") != expected_engine
        or fields.get("aggregate_strategy") != expected_strategy
        or fields.get("native_row_bridge") != "false"
        or fields.get("capture_reducer_bridge") != "true"
        or fields.get("required_runtime_symbols") != ""
        or fields.get("boundary")
        != "single-call-helper-free-single-capture-whole-operation-reducer"
    ):
        raise CensusError("single-capture reducer provenance has a noncanonical route")
    base = {
        "schema", "disposition", "configured", "adapter", "model", "benchmark",
        "source_commit", "source_tree", "target", "feature_bits",
        "compiler_version", "optimizer_version", "engine", "aggregate_strategy",
        "native_row_bridge", "capture_reducer_bridge", "source_pattern_count",
        "operation", "domain", "source_route", "source_cardinality", "source_bytes",
        "source_pattern_sha256", "source_sha256", "group_count", "can_match_empty",
        "empty_progress",
        "semantic_runtime_calls", "caller_scratch_bytes",
        "private_participation_scratch_bytes",
        "private_iterator_state_bytes", "private_result_slot_count",
        "private_result_slot_bytes", "selector_sha256", "capture_sha256",
        "source_artifact_identity_sha256", "source_object_sha256", "reducer_symbol",
        "reducer_symbol_sha256", "object_sha256", "object_bytes",
        "max_object_bytes", "artifact_identity_sha256", "required_runtime_symbols",
        "operation_entry_symbol", "boundary", "required_comparators",
    } | FROZEN_VALIDATION_FIELDS
    route_fields = {
        "exact-span-participation-v1": {
            "participation_algorithm_id", "participation_strategy",
            "participation_assertions", "participation_assertion_signatures",
            "participation_byte_classes", "participation_dfa_states",
            "participation_transition_cells", "participation_ordered_nfa_states",
            "participation_ordered_nfa_byte_ranges",
            "participation_dfa_fallback_resource",
            "participation_dfa_fallback_required",
            "participation_dfa_fallback_limit", "participation_build_work",
            "participation_scratch_bytes", "participation_plan_bytes",
            "participation_selector_object_sha256", "participation_bundle_sha256",
            "participation_export_identity_sha256", "participation_bundle_symbol",
            "participation_selector_symbol", "participation_entry_symbol",
        },
        "capture-next-v1": {
            "capture_plan_sha256", "capture_bundle_sha256", "capture_next_symbol",
            "capture_materialize_symbol", "capture_selector_symbol",
        },
    }[proof["source_route"]]
    expected = base | route_fields
    if set(fields) != expected:
        raise CensusError(
            "runner v5 provenance field closure differs: "
            f"missing={sorted(expected - set(fields))!r} "
            f"extra={sorted(set(fields) - expected)!r}"
        )


def validate_v6_provenance(fields: dict[str, str]) -> None:
    """Validate the exact multi-row weighted reducer provenance closure."""
    if fields.get("disposition") != "executed":
        raise CensusError("weighted reducer provenance disposition is not executed")
    frozen_schedule_validation(fields)
    for name in ("compiler_version", "optimizer_version"):
        parse_canonical_decimal(
            fields.get(name), f"weighted reducer provenance {name}",
            1, (1 << 32) - 1,
        )
    weighted_capture_reducer_proof_from_provenance(fields)
    expected = {
        "schema", "disposition", "configured", "adapter", "model", "benchmark",
        "source_commit", "source_tree", "target", "feature_bits",
        "compiler_version", "optimizer_version", "engine", "aggregate_strategy",
        "native_row_bridge", "uniform_capture_bridge",
        "weighted_capture_reducer_bridge", "weighted_receipt_schema",
        "source_pattern_count", "pattern_bytes", "row_total_object_bytes",
        "component_count", "source_to_component",
        "component_first_source_ordinals", "component_weights",
        "component_entry_symbols", "component_automaton_sha256",
        "component_program_sha256", "component_object_sha256",
        "capture_resolution", "capture_proof_algorithm_version",
        "capture_proof_accounting_version", "source_participating_groups",
        "source_minimum_match_bytes", "source_participating_user_captures",
        "source_capture_annotations", "source_proof_work",
        "source_proof_peak_stack_items", "source_selector_automaton_sha256",
        "source_selector_program_sha256", "source_selector_object_sha256",
        "line_terminator", "operation", "domain", "ordered_sources_sha256",
        "operation_identity_sha256", "reducer_symbol", "reducer_symbol_sha256",
        "reducer_code_sha256", "reducer_object_sha256", "reducer_object_bytes",
        "reducer_object_cap", "reducer_artifact_identity_sha256",
        "external_relocation_count", "external_relocation_components",
        "external_relocation_offsets", "external_relocation_kinds",
        "external_relocation_addends", "semantic_runtime_symbols", "boundary",
        "required_comparators",
    } | FROZEN_VALIDATION_FIELDS
    if set(fields) != expected:
        raise CensusError(
            "runner v6 provenance field closure differs: "
            f"missing={sorted(expected - set(fields))!r} "
            f"extra={sorted(set(fields) - expected)!r}"
        )


def nm_symbols_with_types(nm_output: str, symbol_types: set[str]) -> set[str]:
    result: set[str] = set()
    for line in nm_output.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        name = fields[-1]
        kind = fields[-2] if len(fields[-2]) == 1 else ""
        if kind not in symbol_types:
            continue
        if name.startswith("_") and name[1:].startswith(
            ("fre_aot_regex_", "fre_aot_rebar_runner_")
        ):
            name = name[1:]
        if SYMBOL.fullmatch(name):
            result.add(name)
    return result


def nm_text_symbols(nm_output: str) -> set[str]:
    """Return only entries that the final binary actually defines as text."""
    return nm_symbols_with_types(nm_output, DEFINED_TEXT_SYMBOL_TYPES)


def nm_defined_symbols(nm_output: str) -> set[str]:
    """Return defined text and data symbols used to close linked identities."""
    return nm_symbols_with_types(
        nm_output, DEFINED_TEXT_SYMBOL_TYPES | DEFINED_DATA_SYMBOL_TYPES
    )


def nm_runtime_references(nm_output: str) -> set[str]:
    """Return defined or imported symbols that may name semantic helper code."""
    return nm_symbols_with_types(nm_output, RUNTIME_REFERENCE_SYMBOL_TYPES)


def semantic_helper_symbols(symbols: set[str]) -> list[str]:
    return sorted(
        name for name in symbols
        if name.startswith(RUNTIME_PREFIX)
        and not name.startswith(CONTROL_PLANE_PREFIXES)
    )


def run_nm(nm: str, binary: pathlib.Path) -> tuple[set[str], set[str], set[str], str]:
    # Global-only or defined-only inventory would silently omit local/hidden
    # helpers or imported helpers. Preserve the complete table; the two parsers
    # separately authenticate defined operation entries and all executable
    # runtime references.
    arguments = [nm, str(binary)]
    completed = subprocess.run(
        arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False, timeout=60,
    )
    if completed.returncode != 0:
        raise CensusError("nm failed while independently inventorying final binary")
    output = completed.stdout.decode("utf-8", "replace")
    return (
        nm_text_symbols(output),
        nm_defined_symbols(output),
        nm_runtime_references(output),
        sha_bytes(completed.stdout),
    )


def selected_operation_entries(provenance: dict[str, str]) -> tuple[list[str], str]:
    model = provenance["model"]
    if provenance.get("schema") == "fre.aot.rebar-runner.v6":
        _, _, proof = weighted_capture_reducer_proof_from_provenance(provenance)
        reducer = proof["reducer_symbol"]
        if not isinstance(reducer, str):
            raise CensusError("weighted capture reducer operation entry is absent")
        return [reducer], "linked-native-weighted-capture-reducer"
    if provenance.get("schema") == "fre.aot.rebar-runner.v5":
        proof = single_capture_reducer_proof_from_provenance(provenance)
        reducer = proof["reducer_symbol"]
        if not isinstance(reducer, str):
            raise CensusError("single-capture reducer operation entry is absent")
        return [reducer], "linked-native-single-capture-reducer"
    if provenance.get("shared_ordered_many") == "true":
        proof = shared_ordered_many_proof(provenance)
        route = (
            "linked-shared-ordered-many-helper-backed-reducer"
            if proof.get("route_variant") == "ordered-v15"
            else "linked-shared-ordered-many-helper-free-reducer"
        )
        return [provenance["reducer_symbol"]], route
    components = components_from_provenance(provenance)
    if components:
        entries = [str(component["entry_symbol"]) for component in components]
        if len(entries) != len(set(entries)):
            raise CensusError("composite provenance repeats an entry symbol")
        if provenance.get("selector_capture_fallback_bridge") == "true":
            if (
                model != "grep-captures"
                or len(entries) != 1
                or NATIVE_SEARCH_ENTRY_SYMBOL.fullmatch(entries[0]) is None
            ):
                raise CensusError(
                    "selector capture fallback route has an invalid selector entry"
                )
            return entries, "linked-selector-negative-certificate-adapter-loop"
        if provenance.get("strict_capture_bridge") == "true" and model in (
            UNIFORM_CAPTURE_ADAPTER_MODELS
        ):
            if len(entries) != 1 or NATIVE_CAPTURE_NEXT_ENTRY_SYMBOL.fullmatch(
                entries[0]
            ) is None:
                raise CensusError("strict-capture route does not select capture_next")
            return entries, "linked-strict-capture-next-adapter-loop"
        if provenance.get("participation_capture_bridge") == "true" and model in (
            UNIFORM_CAPTURE_ADAPTER_MODELS
        ):
            participation = provenance.get("participation_entry_symbol")
            if (
                len(entries) != 1
                or NATIVE_SEARCH_ENTRY_SYMBOL.fullmatch(entries[0]) is None
                or not isinstance(participation, str)
                or NATIVE_PARTICIPATION_ENTRY_SYMBOL.fullmatch(participation) is None
                or participation == entries[0]
            ):
                raise CensusError(
                    "exact-span participation route has invalid operation entries"
                )
            return [entries[0], participation], "linked-exact-span-participation-adapter-loop"
        if model == "regex-redux":
            proof = regex_redux_proof_from_provenance(provenance, components)
            return [str(proof["reducer_symbol"])], "linked-native-regex-redux-reducer"
        if provenance.get("native_row_scalar_reducer") == "true":
            source_count, row_bytes, source_map = native_row_topology(
                provenance, components, 2
            )
            proof = row_scalar_reducer_proof_from_provenance(
                provenance, components, source_count, row_bytes, source_map
            )
            route = (
                "linked-native-strict-mixed-row-scalar-reducer"
                if proof["mixed_handle_table"]
                and every_prepared_component_is_strict(components)
                else "linked-native-row-scalar-helper-backed-reducer"
                if proof["mixed_handle_table"]
                else "linked-native-row-scalar-reducer"
            )
            return [str(proof["reducer_symbol"])], route
        if provenance.get("native_multi_grep_reducer") == "true":
            source_count, row_bytes, source_map = native_row_topology(
                provenance, components, 2
            )
            proof = multi_grep_reducer_proof_from_provenance(
                provenance, components, source_count, row_bytes, source_map
            )
            route = (
                "linked-native-strict-mixed-multi-grep-reducer"
                if proof["mixed_handle_table"]
                and every_prepared_component_is_strict(components)
                else "linked-native-mixed-multi-grep-reducer"
                if proof["mixed_handle_table"]
                else "linked-native-multi-grep-reducer"
            )
            return [str(proof["reducer_symbol"])], route
        if provenance.get("native_row_bridge") == "true" and model in {
            "count", "count-spans", "grep",
        }:
            for component, entry in zip(components, entries):
                pattern = (
                    NATIVE_SEARCH_EXCLUSIVE_ENTRY_SYMBOL
                    if component.get("prepared_v15") is not None
                    else NATIVE_SEARCH_ENTRY_SYMBOL
                )
                if pattern.fullmatch(entry) is None:
                    raise CensusError(
                        "native-row route has a noncanonical operation entry"
                    )
            return entries, "linked-native-row-adapter-loop"
        if (
            provenance.get("native_row_bridge") == "true"
            and provenance.get("uniform_capture_bridge") == "true"
            and model in UNIFORM_CAPTURE_ADAPTER_MODELS
        ):
            return entries, "linked-uniform-capture-row-adapter-loop"
        raise CensusError(f"unknown composite operation route for model {model!r}")
    if model in UNIFORM_CAPTURE_ADAPTER_MODELS:
        scalar_native_uniform_capture_proof(provenance)
        route = (
            "linked-native-uniform-capture-reducer"
            if provenance["boundary"] == "single-call-native-uniform-capture-reducer"
            else "linked-native-uniform-capture-helper-backed-reducer"
        )
        return [provenance["reducer_symbol"]], route
    if model == "count" or (
        model == "count-spans"
        and provenance.get("span_iteration_strategy")
        == NATIVE_SPAN_SUM_ITERATION_STRATEGY
    ):
        proof = scalar_native_reducer_proof_from_provenance(provenance)
        return [provenance["reducer_symbol"]], scalar_native_reducer_route(
            model, proof
        )
    if model == "count-spans" and provenance["span_fill_symbol"]:
        return [provenance["span_fill_symbol"]], "linked-span-fill"
    if model == "grep":
        return [provenance["reducer_symbol"]], "linked-native-grep-count-reducer"
    if model == "count-spans":
        return [provenance["entry_symbol"]], "linked-direct-entry-adapter-loop"
    raise CensusError(f"no exact operation entry for model {model!r}")


def run_checked_process(
    argv: list[str], input_bytes: bytes, timeout: int,
    environment: Optional[dict[str, str]] = None,
) -> dict[str, object]:
    try:
        completed = subprocess.run(
            argv, input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=timeout, env=environment,
        )
        return {
            "outcome": "exit" if completed.returncode >= 0 else "signal",
            "returncode": completed.returncode,
            "stdout_bytes": len(completed.stdout),
            "stdout_sha256": sha_bytes(completed.stdout),
            "stderr_bytes": len(completed.stderr),
            "stderr_sha256": sha_bytes(completed.stderr),
        }
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout or b""
        stderr = error.stderr or b""
        return {
            "outcome": "timeout", "returncode": None,
            "stdout_bytes": len(stdout), "stdout_sha256": sha_bytes(stdout),
            "stderr_bytes": len(stderr), "stderr_sha256": sha_bytes(stderr),
        }


def trap_environment(library: pathlib.Path, marker: pathlib.Path, symbols: list[str], kind: str) -> dict[str, str]:
    if not symbols or len(set(symbols)) != len(symbols) or not all(SYMBOL.fullmatch(x) for x in symbols):
        raise CensusError("trap symbol set is empty, duplicated, or malformed")
    environment = dict(os.environ)
    injection = "DYLD_INSERT_LIBRARIES" if sys.platform == "darwin" else "LD_PRELOAD"
    if injection in environment:
        raise CensusError(f"refusing inherited {injection}")
    environment[injection] = str(library.resolve(strict=True))
    environment["FRE_AOT_CENSUS_TRAP_MARKER"] = str(marker)
    environment["FRE_AOT_CENSUS_TRAP_SYMBOLS"] = ",".join(symbols)
    environment["FRE_AOT_CENSUS_TRAP_KIND"] = kind
    return environment


def marker_patch_evidence_pass(
    marker: dict[str, object], expected_architecture: str
) -> bool:
    expected_after = TRAP_PATCHES.get(expected_architecture)
    armed = marker.get("armed")
    if (
        expected_after is None
        or marker.get("architecture") != expected_architecture
        or not isinstance(armed, list)
    ):
        return False
    seen_offsets: set[str] = set()
    for record in armed:
        if not isinstance(record, dict):
            return False
        before = record.get("before")
        offset = record.get("offset")
        if (
            record.get("after") != expected_after
            or not isinstance(before, str)
            or len(before) != len(expected_after)
            or re.fullmatch(r"[0-9a-f]+", before) is None
            or not isinstance(offset, str)
            or re.fullmatch(r"0x(?:0|[1-9a-f][0-9a-f]*)", offset) is None
        ):
            return False
        if offset in seen_offsets:
            if before != expected_after:
                return False
        else:
            if before == expected_after:
                return False
            seen_offsets.add(offset)
    return True


def semantic_helper_control_pass(
    helpers: list[str],
    phase: dict[str, object],
    marker: dict[str, object],
    expected_architecture: str,
) -> bool:
    """Authenticate either a complete helper trap or a proven-empty helper surface."""
    if not helpers:
        return phase == {
            "outcome": "not-run",
            "returncode": None,
            "stdout_bytes": 0,
            "stdout_sha256": sha_bytes(b""),
            "stderr_bytes": 0,
            "stderr_sha256": sha_bytes(b""),
        } and marker == {
            "status": "missing",
            "sha256": None,
            "armed": [],
            "triggered": None,
        }
    armed = [row.get("symbol") for row in marker.get("armed", [])]
    return (
        phase["outcome"] == "exit"
        and phase["returncode"] == 0
        and marker.get("status") == "valid"
        and marker.get("kind") == "semantic-helpers"
        and marker_patch_evidence_pass(marker, expected_architecture)
        and marker.get("installed") == len(helpers)
        and marker.get("expected") == len(helpers)
        and armed == helpers
        and marker.get("triggered") is None
        and marker.get("completed") == "normal"
    )


def parse_trap_marker(path: pathlib.Path) -> dict[str, object]:
    if not path.is_file():
        return {"status": "missing", "sha256": None, "armed": [], "triggered": None}
    lines = path.read_text("ascii", errors="strict").splitlines()
    headers: dict[str, str] = {}
    armed = []
    triggered = None
    for line in lines:
        if line.startswith("armed="):
            fields = dict(token.split("=", 1) for token in line.split() if "=" in token)
            if set(fields) != {"armed", "offset", "before", "after"}:
                raise CensusError("trap marker has a non-closed armed record")
            armed.append({
                "symbol": fields.get("armed"), "offset": fields.get("offset"),
                "before": fields.get("before"), "after": fields.get("after"),
            })
        elif line.startswith("triggered="):
            if triggered is not None or line.count("=") != 1:
                raise CensusError("trap marker has duplicate or malformed trigger")
            triggered = line.split("=", 1)[1]
        elif "=" in line:
            key, value = line.split("=", 1)
            if key not in {"schema", "kind", "architecture", "installed", "expected", "completed"}:
                raise CensusError(f"trap marker has unknown field {key!r}")
            if key in headers:
                raise CensusError(f"trap marker repeats field {key!r}")
            headers[key] = value
        else:
            raise CensusError("trap marker has a malformed line")
    status = "valid"
    if headers.get("schema") != TRAP_MARKER_SCHEMA:
        status = "invalid"
    return {
        "status": status,
        "sha256": sha_file(path),
        "kind": headers.get("kind"),
        "architecture": headers.get("architecture"),
        "installed": int(headers["installed"]) if headers.get("installed", "").isdigit() else None,
        "expected": int(headers["expected"]) if headers.get("expected", "").isdigit() else None,
        "armed": armed,
        "triggered": triggered,
        "completed": headers.get("completed"),
    }


def provenance_receipt(fields: dict[str, str]) -> dict[str, object]:
    common = {
        key: fields[key] for key in (
            "schema", "adapter", "model", "benchmark", "source_commit", "source_tree",
            "target", "feature_bits",
        )
    }
    common["entry_abi"] = fields.get("entry_abi")
    common["validation"] = frozen_schedule_validation(fields)
    if fields["schema"] == "fre.aot.rebar-runner.v2":
        shared_ordered_many = fields["shared_ordered_many"] == "true"
        prepared_grep_v15 = (
            fields["model"] == "grep"
            and fields["required_prepare_capabilities"]
            == f"{PREPARED_V15_CAPABILITY:016x}"
        )
        uniform_capture = (
            scalar_native_uniform_capture_proof(fields)
            if (
                fields["model"] in UNIFORM_CAPTURE_ADAPTER_MODELS
                and not shared_ordered_many
            )
            else None
        )
        scalar_native_reducer = (
            scalar_native_reducer_proof_from_provenance(fields)
            if not shared_ordered_many and (
                fields["model"] == "count" or (
                    fields["model"] == "count-spans"
                    and fields["span_iteration_strategy"]
                    == NATIVE_SPAN_SUM_ITERATION_STRATEGY
                )
            )
            else None
        )
        shared_proof = (
            shared_ordered_many_proof(fields) if shared_ordered_many else None
        )
        source_pattern_count = (
            int(fields["source_pattern_count"], 10) if shared_ordered_many else None
        )
        result = {
            **common,
            "kind": (
                "shared-ordered-many-v2" if shared_ordered_many else
                "prepared-grep-v15-v2" if prepared_grep_v15 else "scalar-v2"
            ),
            "composite_kind": (
                "shared-ordered-many-native-reducer-v1"
                if shared_ordered_many else None
            ),
            "source_pattern_count": source_pattern_count,
            "source_to_artifact": (
                [0] * source_pattern_count if shared_ordered_many else []
            ),
            "row_total_object_bytes": None,
            "uniform_capture": uniform_capture,
            "shared_ordered_many": shared_proof,
            "boundary": fields.get("boundary"),
            "engine": fields["engine"],
            "aggregate_strategy": fields["aggregate_strategy"],
            "prepared_bulk_strategy": fields["prepared_bulk_strategy"],
            "span_iteration_strategy": fields["span_iteration_strategy"],
            "grep_iteration_strategy": fields["grep_iteration_strategy"],
            "program_sha256": fields["program_sha256"],
            "object_sha256": fields["object_sha256"],
            "program_symbol": fields["program_symbol"],
            "entry_symbol": fields["entry_symbol"],
            "reducer_symbol": fields["reducer_symbol"],
            "span_fill_symbol": fields["span_fill_symbol"],
            "required_runtime_symbols": sorted(filter(
                None, fields["required_runtime_symbols"].split(",")
            )),
            "components": [],
        }
        if prepared_grep_v15:
            result["prepared_grep_v15"] = scalar_prepared_grep_v15_proof(fields)
        if scalar_native_reducer is not None:
            result["scalar_native_reducer"] = scalar_native_reducer
        return result
    if fields["schema"] == "fre.aot.rebar-runner.v6":
        components, source_to_component, proof = (
            weighted_capture_reducer_proof_from_provenance(fields)
        )
        return {
            **common,
            "kind": "weighted-capture-reducer-v6",
            "composite_kind": "weighted-capture-whole-operation-reducer-v1",
            "source_pattern_count": len(source_to_component),
            "source_to_artifact": source_to_component,
            "row_total_object_bytes": proof["row_total_object_bytes"],
            "uniform_capture": proof["uniform_capture"],
            "shared_ordered_many": None,
            "weighted_capture_reducer": {
                key: value for key, value in proof.items()
                if key not in {"row_total_object_bytes", "uniform_capture"}
            },
            "boundary": fields["boundary"],
            "engine": fields["engine"],
            "aggregate_strategy": fields["aggregate_strategy"],
            "prepared_bulk_strategy": None,
            "span_iteration_strategy": None,
            "grep_iteration_strategy": None,
            "program_sha256": None,
            "object_sha256": proof["reducer_object_sha256"],
            "program_symbol": None,
            "entry_symbol": None,
            "reducer_symbol": proof["reducer_symbol"],
            "span_fill_symbol": None,
            "required_runtime_symbols": [],
            "components": components,
        }
    if fields["schema"] == "fre.aot.rebar-runner.v5":
        proof = single_capture_reducer_proof_from_provenance(fields)
        return {
            **common,
            "kind": "single-capture-reducer-v5",
            "composite_kind": "single-capture-whole-operation-reducer-v1",
            "source_pattern_count": 1,
            "source_to_artifact": [],
            "row_total_object_bytes": None,
            "uniform_capture": None,
            "shared_ordered_many": None,
            "capture_reducer": proof,
            "boundary": fields["boundary"],
            "engine": fields["engine"],
            "aggregate_strategy": fields["aggregate_strategy"],
            "prepared_bulk_strategy": None,
            "span_iteration_strategy": None,
            "grep_iteration_strategy": None,
            "program_sha256": None,
            "object_sha256": proof["object_sha256"],
            "program_symbol": None,
            "entry_symbol": None,
            "reducer_symbol": proof["reducer_symbol"],
            "span_fill_symbol": None,
            "required_runtime_symbols": [],
            "components": [],
        }
    if fields["schema"] == "fre.aot.rebar-runner.v4":
        components = components_from_provenance(fields)
        source_pattern_count = int(fields["source_pattern_count"], 10)
        source_to_artifact = [
            int(value, 10) for value in fields["source_to_artifact"].split(",")
        ]
        participation = fields.get("participation_capture_bridge") == "true"
        selector_fallback = fields.get("selector_capture_fallback_bridge") == "true"
        result = {
            **common,
            "kind": (
                "selector-capture-fallback-v4" if selector_fallback else
                "participation-capture-v4" if participation else
                "strict-capture-v4"
            ),
            "composite_kind": (
                "selector-negative-certificate-v1" if selector_fallback else
                "exact-span-participation-v1" if participation else
                "strict-capture-next-v1"
            ),
            "source_pattern_count": source_pattern_count,
            "source_to_artifact": source_to_artifact,
            "row_total_object_bytes": int(fields["row_total_object_bytes"], 10),
            "uniform_capture": None,
            "shared_ordered_many": None,
            "boundary": fields["boundary"],
            "engine": fields["engine"],
            "aggregate_strategy": fields["aggregate_strategy"],
            "prepared_bulk_strategy": None,
            "span_iteration_strategy": None,
            "grep_iteration_strategy": None,
            "program_sha256": None,
            "object_sha256": None,
            "program_symbol": None,
            "entry_symbol": None,
            "reducer_symbol": None,
            "span_fill_symbol": None,
            "required_runtime_symbols": [],
            "components": components,
        }
        if selector_fallback:
            result["selector_capture_fallback"] = (
                selector_capture_fallback_proof_from_provenance(fields, components)
            )
        elif participation:
            result["participation_capture"] = (
                participation_capture_proof_from_provenance(fields, components)
            )
        else:
            result["strict_capture"] = strict_capture_proof_from_provenance(
                fields, components
            )
        return result
    components = components_from_provenance(fields)
    native_row = fields.get("native_row_bridge") == "true"
    native_row_scalar = native_row and fields.get("native_row_scalar_reducer") == "true"
    native_multi_grep = native_row and fields.get("native_multi_grep_reducer") == "true"
    uniform_capture = native_row and fields.get("uniform_capture_bridge") == "true"
    mixed_prepared_v15 = native_row and any(
        component.get("prepared_v15") is not None for component in components
    )
    if native_row and not mixed_prepared_v15:
        components = [
            {key: value for key, value in component.items() if key != "prepared_v15"}
            for component in components
        ]
    source_pattern_count = (
        int(fields["source_pattern_count"], 10) if native_row else 0
    )
    source_to_artifact = (
        [int(value, 10) for value in fields["source_to_artifact"].split(",")]
        if native_row else []
    )
    regex_redux = (
        None if native_row else regex_redux_proof_from_provenance(fields, components)
    )
    multi_grep_reducer = None
    row_scalar_reducer = None
    if native_row_scalar:
        row_scalar_reducer = row_scalar_reducer_proof_from_provenance(
            fields,
            components,
            source_pattern_count,
            int(fields["row_total_object_bytes"], 10),
            source_to_artifact,
        )
    if native_multi_grep:
        multi_grep_reducer = multi_grep_reducer_proof_from_provenance(
            fields,
            components,
            source_pattern_count,
            int(fields["row_total_object_bytes"], 10),
            source_to_artifact,
        )
    result = {
        **common,
        "kind": "composite-v3",
        "composite_kind": (
            "uniform-capture-row-bridge-v1" if uniform_capture else
            "native-row-scalar-reducer-v1" if native_row_scalar else
            "native-multi-grep-reducer-v1" if native_multi_grep else
            "mixed-prepared-native-row-bridge-v15" if mixed_prepared_v15 else
            "native-row-bridge-v1" if native_row else
            "regex-redux-fixed-v1"
        ),
        "source_pattern_count": source_pattern_count,
        "source_to_artifact": source_to_artifact,
        "row_total_object_bytes": (
            int(fields["row_total_object_bytes"], 10) if native_row else None
        ),
        "uniform_capture": (
            uniform_capture_proof_from_provenance(
                fields, components, source_pattern_count, source_to_artifact
            ) if uniform_capture else None
        ),
        "shared_ordered_many": None,
        "boundary": fields["boundary"],
        "engine": fields["engine"],
        "aggregate_strategy": fields["aggregate_strategy"],
        "prepared_bulk_strategy": None,
        "span_iteration_strategy": None,
        "grep_iteration_strategy": None,
        "program_sha256": None,
        "object_sha256": (
            regex_redux["reducer_object_sha256"] if regex_redux else
            row_scalar_reducer["object_sha256"] if row_scalar_reducer else
            multi_grep_reducer["object_sha256"] if multi_grep_reducer else None
        ),
        "program_symbol": None,
        "entry_symbol": None,
        "reducer_symbol": (
            regex_redux["reducer_symbol"] if regex_redux else
            row_scalar_reducer["reducer_symbol"] if row_scalar_reducer else
            multi_grep_reducer["reducer_symbol"] if multi_grep_reducer else None
        ),
        "span_fill_symbol": None,
        "required_runtime_symbols": sorted(filter(
            None, fields.get("required_runtime_symbols", "").split(",")
        )),
        "components": components,
    }
    if mixed_prepared_v15:
        result["prepared_v15_limits"] = native_row_prepared_v15_limits(
            fields, components
        )
    if regex_redux is not None:
        result["regex_redux"] = regex_redux
    if multi_grep_reducer is not None:
        result["multi_grep_reducer"] = multi_grep_reducer
    if row_scalar_reducer is not None:
        result["row_scalar_reducer"] = row_scalar_reducer
    return result


def operation_route_from_provenance_record(
    provenance: dict[str, object],
) -> tuple[list[str], str]:
    """Reconstruct the exact operation entries from normalized provenance."""
    if provenance.get("kind") == "weighted-capture-reducer-v6":
        validate_normalized_weighted_capture_reducer(
            provenance.get("weighted_capture_reducer"), provenance,
            "normalized weighted-capture reducer provenance",
        )
        reducer = provenance.get("reducer_symbol")
        if not isinstance(reducer, str):
            raise CensusError("normalized weighted capture reducer is absent")
        return [reducer], "linked-native-weighted-capture-reducer"
    if provenance.get("kind") == "single-capture-reducer-v5":
        validate_normalized_single_capture_reducer(
            provenance.get("capture_reducer"), provenance,
            "normalized single-capture reducer provenance",
        )
        reducer = provenance.get("reducer_symbol")
        if not isinstance(reducer, str):
            raise CensusError("normalized single-capture reducer is absent")
        return [reducer], "linked-native-single-capture-reducer"
    if provenance.get("kind") == "shared-ordered-many-v2":
        variant = validate_normalized_shared_ordered_many(
            provenance.get("shared_ordered_many"), provenance,
            "normalized shared ordered-many provenance",
        )
        reducer = provenance.get("reducer_symbol")
        if not isinstance(reducer, str):
            raise CensusError("normalized shared ordered-many reducer is absent")
        route = (
            "linked-shared-ordered-many-helper-backed-reducer"
            if variant == "ordered-v15"
            else "linked-shared-ordered-many-helper-free-reducer"
        )
        return [reducer], route
    components = provenance["components"]
    if components:
        entries = [component["entry_symbol"] for component in components]
        if provenance["composite_kind"] == "regex-redux-fixed-v1":
            validate_normalized_regex_redux(
                provenance.get("regex_redux"), provenance, "normalized regex-redux provenance"
            )
            return [provenance["reducer_symbol"]], "linked-native-regex-redux-reducer"
        if provenance["composite_kind"] == "native-multi-grep-reducer-v1":
            proof = validate_normalized_multi_grep_reducer(
                provenance.get("multi_grep_reducer"), provenance,
                "normalized multi-Grep reducer provenance",
            )
            route = (
                "linked-native-strict-mixed-multi-grep-reducer"
                if proof["mixed_handle_table"]
                and every_prepared_component_is_strict(components)
                else "linked-native-mixed-multi-grep-reducer"
                if proof["mixed_handle_table"]
                else "linked-native-multi-grep-reducer"
            )
            return [proof["reducer_symbol"]], route
        if provenance["composite_kind"] == "native-row-scalar-reducer-v1":
            proof = validate_normalized_row_scalar_reducer(
                provenance.get("row_scalar_reducer"), provenance,
                "normalized row-scalar reducer provenance",
            )
            route = (
                "linked-native-strict-mixed-row-scalar-reducer"
                if proof["mixed_handle_table"]
                and every_prepared_component_is_strict(components)
                else "linked-native-row-scalar-helper-backed-reducer"
                if proof["mixed_handle_table"]
                else "linked-native-row-scalar-reducer"
            )
            return [proof["reducer_symbol"]], route
        if provenance["composite_kind"] == "strict-capture-next-v1":
            strict_capture = provenance.get("strict_capture")
            if (
                len(entries) != 1
                or not isinstance(entries[0], str)
                or NATIVE_CAPTURE_NEXT_ENTRY_SYMBOL.fullmatch(entries[0]) is None
                or not isinstance(strict_capture, dict)
                or strict_capture.get("capture_next_symbol") != entries[0]
            ):
                raise CensusError(
                    "normalized strict-capture provenance has a non-native operation entry"
                )
            return entries, "linked-strict-capture-next-adapter-loop"
        if provenance["composite_kind"] == "exact-span-participation-v1":
            proof = provenance.get("participation_capture")
            participation = (
                proof.get("participation_entry_symbol")
                if isinstance(proof, dict) else None
            )
            selector = entries[0] if len(entries) == 1 else None
            if (
                not isinstance(selector, str)
                or NATIVE_SEARCH_ENTRY_SYMBOL.fullmatch(selector) is None
                or not isinstance(participation, str)
                or NATIVE_PARTICIPATION_ENTRY_SYMBOL.fullmatch(participation) is None
                or selector == participation
            ):
                raise CensusError(
                    "normalized exact-span participation provenance has invalid entries"
                )
            return [selector, participation], (
                "linked-exact-span-participation-adapter-loop"
            )
        if provenance["composite_kind"] == "selector-negative-certificate-v1":
            proof = provenance.get("selector_capture_fallback")
            selector = entries[0] if len(entries) == 1 else None
            if (
                not isinstance(selector, str)
                or NATIVE_SEARCH_ENTRY_SYMBOL.fullmatch(selector) is None
                or not isinstance(proof, dict)
                or proof.get("selector_entry_symbol") != selector
            ):
                raise CensusError(
                    "normalized selector capture fallback has an invalid native entry"
                )
            return entries, "linked-selector-negative-certificate-adapter-loop"
        if provenance["composite_kind"] == "mixed-prepared-native-row-bridge-v15":
            if len(entries) != len(set(entries)):
                raise CensusError("normalized mixed prepared route repeats an entry")
            for component, entry in zip(components, entries):
                pattern = (
                    NATIVE_SEARCH_EXCLUSIVE_ENTRY_SYMBOL
                    if component.get("prepared_v15") is not None
                    else NATIVE_SEARCH_ENTRY_SYMBOL
                )
                if not isinstance(entry, str) or pattern.fullmatch(entry) is None:
                    raise CensusError(
                        "normalized mixed prepared route has a non-native entry"
                    )
            return entries, "linked-native-row-adapter-loop"
        if len(entries) != len(set(entries)) or not all(
            isinstance(entry, str) and NATIVE_SEARCH_ENTRY_SYMBOL.fullmatch(entry)
            for entry in entries
        ):
            raise CensusError(
                "normalized composite provenance has non-native operation entries"
            )
        if provenance["composite_kind"] == "native-row-bridge-v1":
            return entries, "linked-native-row-adapter-loop"
        if provenance["composite_kind"] == "uniform-capture-row-bridge-v1":
            return entries, "linked-uniform-capture-row-adapter-loop"
        raise CensusError("normalized provenance has an unknown composite kind")
    model = provenance["model"]
    if provenance["kind"] == "prepared-grep-v15-v2":
        entries = [provenance["reducer_symbol"]]
        route = "linked-native-grep-count-reducer"
        expected_symbol = NATIVE_GREP_COUNT_ENTRY_SYMBOL
    elif model in UNIFORM_CAPTURE_ADAPTER_MODELS:
        validate_normalized_uniform_capture_reducer(
            provenance.get("uniform_capture"),
            provenance,
            "normalized uniform-capture provenance",
        )
        reducer = provenance["reducer_symbol"]
        expected_symbol = (
            NATIVE_COUNT_CAPTURES_ENTRY_SYMBOL
            if model == "count-captures"
            else NATIVE_GREP_CAPTURES_ENTRY_SYMBOL
        )
        entries = [reducer]
        route = (
            "linked-native-uniform-capture-reducer"
            if provenance["boundary"] == "single-call-native-uniform-capture-reducer"
            else "linked-native-uniform-capture-helper-backed-reducer"
        )
    elif model == "count" or (
        model == "count-spans"
        and provenance.get("span_iteration_strategy")
        == NATIVE_SPAN_SUM_ITERATION_STRATEGY
    ):
        entries = [provenance["reducer_symbol"]]
        route = validate_normalized_scalar_native_reducer(
            provenance.get("scalar_native_reducer"),
            provenance,
            "normalized scalar native reducer provenance",
        )
        expected_symbol = (
            NATIVE_COUNT_ENTRY_SYMBOL
            if model == "count"
            else NATIVE_SPAN_SUM_ENTRY_SYMBOL
        )
    elif model == "count-spans" and provenance["span_fill_symbol"]:
        entries = [provenance["span_fill_symbol"]]
        route = "linked-span-fill"
        expected_symbol = NATIVE_SPAN_FILL_ENTRY_SYMBOL
    elif model == "grep":
        entries = [provenance["reducer_symbol"]]
        route = "linked-native-grep-count-reducer"
        expected_symbol = NATIVE_GREP_COUNT_ENTRY_SYMBOL
    elif model == "count-spans":
        entries = [provenance["entry_symbol"]]
        route = "linked-direct-entry-adapter-loop"
        expected_symbol = NATIVE_SEARCH_ENTRY_SYMBOL
    else:
        raise CensusError(f"normalized provenance has no operation route for {model!r}")
    if not all(
        isinstance(entry, str) and expected_symbol.fullmatch(entry) for entry in entries
    ):
        raise CensusError("normalized scalar provenance has a non-native operation entry")
    return entries, route


def declared_runtime_symbols_from_provenance(
    provenance: dict[str, object],
) -> list[str]:
    symbols = set(provenance["required_runtime_symbols"])
    for component in provenance["components"]:
        symbols.update(component["required_runtime_symbols"])
    if not all(isinstance(symbol, str) and SYMBOL.fullmatch(symbol) for symbol in symbols):
        raise CensusError("normalized provenance has malformed runtime symbols")
    return sorted(symbols)


def identity_defined_symbols_from_provenance(
    provenance: dict[str, object],
) -> list[str]:
    """Return route-bound defined symbols authenticated but not invoked."""
    if provenance.get("kind") == "weighted-capture-reducer-v6":
        validate_normalized_weighted_capture_reducer(
            provenance.get("weighted_capture_reducer"), provenance,
            "normalized weighted-capture reducer provenance",
        )
        symbols = [component["entry_symbol"] for component in provenance["components"]]
        if len(symbols) != len(set(symbols)):
            raise CensusError("weighted capture reducer repeats a child identity symbol")
        return sorted(symbols)
    if provenance.get("composite_kind") == "regex-redux-fixed-v1":
        proof = provenance.get("regex_redux")
        symbols = proof.get("reducer_link_symbols") if isinstance(proof, dict) else None
        if (
            not isinstance(symbols, list)
            or len(symbols) != 15
            or len(symbols) != len(set(symbols))
            or not all(
                isinstance(symbol, str) and NATIVE_SEARCH_ENTRY_SYMBOL.fullmatch(symbol)
                for symbol in symbols
            )
        ):
            raise CensusError("regex-redux linked component symbol set is malformed")
        return sorted(symbols)
    if provenance.get("composite_kind") == "native-multi-grep-reducer-v1":
        components = provenance.get("components")
        if (
            not isinstance(components, list)
            or not all(isinstance(component, dict) for component in components)
        ):
            raise CensusError("multi-Grep reducer row identities are malformed")
        proof = validate_normalized_multi_grep_reducer(
            provenance.get("multi_grep_reducer"), provenance,
            "normalized multi-Grep reducer provenance",
        )
        symbols: list[object] = []
        for component, route in zip(components, proof["row_routes"]):
            symbols.append(component.get("entry_symbol"))
            prepared = component.get("prepared_v15")
            if route in {1, 2} and isinstance(prepared, dict):
                symbols.append(prepared.get("runtime_program_symbol"))
                if route == 1:
                    symbols.append(prepared.get("span_fill_symbol"))
        if not all(isinstance(symbol, str) for symbol in symbols):
            raise CensusError("multi-Grep reducer linked identity symbols are malformed")
        if len(symbols) != len(set(symbols)):
            raise CensusError("multi-Grep reducer repeats a linked identity symbol")
        for index, (component, route) in enumerate(
            zip(components, proof["row_routes"])
        ):
            entry = component["entry_symbol"]
            prepared = component.get("prepared_v15")
            if route == 0:
                if (
                    prepared is not None
                    or NATIVE_SEARCH_ENTRY_SYMBOL.fullmatch(entry) is None
                ):
                    raise CensusError(
                        "multi-Grep reducer ordinary row identity route is malformed"
                    )
            elif route in {1, 2}:
                if (
                    not isinstance(prepared, dict)
                    or prepared_v15_component_route(component) != route
                    or NATIVE_SEARCH_EXCLUSIVE_ENTRY_SYMBOL.fullmatch(entry) is None
                ):
                    raise CensusError(
                        "multi-Grep reducer prepared row identity route is malformed"
                    )
                validate_normalized_prepared_v15_component(
                    prepared, component,
                    f"normalized multi-Grep reducer component {index}",
                )
            else:
                raise CensusError("multi-Grep reducer row identity route is malformed")
        return sorted(symbols)
    if provenance.get("composite_kind") == "native-row-scalar-reducer-v1":
        components = provenance.get("components")
        if (
            not isinstance(components, list)
            or not all(isinstance(component, dict) for component in components)
        ):
            raise CensusError("row-scalar reducer row identities are malformed")
        proof = validate_normalized_row_scalar_reducer(
            provenance.get("row_scalar_reducer"), provenance,
            "normalized row-scalar reducer provenance",
        )
        symbols: list[object] = []
        for component, route in zip(components, proof["row_routes"]):
            symbols.append(component.get("entry_symbol"))
            prepared = component.get("prepared_v15")
            if route in {1, 2} and isinstance(prepared, dict):
                symbols.append(prepared.get("runtime_program_symbol"))
                if route == 1:
                    symbols.append(prepared.get("span_fill_symbol"))
        if not all(isinstance(symbol, str) for symbol in symbols):
            raise CensusError("row-scalar reducer linked identity symbols are malformed")
        if len(symbols) != len(set(symbols)):
            raise CensusError("row-scalar reducer repeats a linked identity symbol")
        for index, (component, route) in enumerate(
            zip(components, proof["row_routes"])
        ):
            entry = component["entry_symbol"]
            prepared = component.get("prepared_v15")
            if route == 0:
                if (
                    prepared is not None
                    or NATIVE_SEARCH_ENTRY_SYMBOL.fullmatch(entry) is None
                ):
                    raise CensusError(
                        "row-scalar reducer ordinary row identity route is malformed"
                    )
            elif route in {1, 2}:
                if (
                    not isinstance(prepared, dict)
                    or prepared_v15_component_route(component) != route
                    or NATIVE_SEARCH_EXCLUSIVE_ENTRY_SYMBOL.fullmatch(entry) is None
                ):
                    raise CensusError(
                        "row-scalar reducer prepared row identity route is malformed"
                    )
                validate_normalized_prepared_v15_component(
                    prepared, component,
                    f"normalized row-scalar reducer component {index}",
                )
            else:
                raise CensusError("row-scalar reducer row identity route is malformed")
        return sorted(symbols)
    if provenance.get("kind") == "single-capture-reducer-v5":
        validate_normalized_single_capture_reducer(
            provenance.get("capture_reducer"), provenance,
            "normalized single-capture reducer provenance",
        )
        proof = provenance["capture_reducer"]
        if proof["source_route"] == "exact-span-participation-v1":
            child = proof["participation_source"]
            symbols = [
                child["bundle_symbol"], child["selector_symbol"],
                child["entry_symbol"],
            ]
        else:
            child = proof["capture_next_source"]
            symbols = [
                child["next_symbol"], child["materialize_symbol"],
                child["selector_symbol"],
            ]
        if len(symbols) != len(set(symbols)):
            raise CensusError("single-capture reducer repeats a child identity symbol")
        return sorted(symbols)
    if provenance.get("kind") == "shared-ordered-many-v2":
        symbols = [
            provenance.get("entry_symbol"), provenance.get("span_fill_symbol"),
            provenance.get("program_symbol"),
        ]
        symbols = [symbol for symbol in symbols if symbol]
        if not all(isinstance(symbol, str) and SYMBOL.fullmatch(symbol) for symbol in symbols):
            raise CensusError("shared ordered-many identity symbol set is malformed")
        return sorted(symbols)
    if provenance.get("kind") == "prepared-grep-v15-v2":
        validate_normalized_prepared_grep_v15(
            provenance.get("prepared_grep_v15"), provenance,
            "normalized prepared V15 grep provenance",
        )
        if provenance.get("entry_abi") == PREPARED_SCALAR_REDUCE_ENTRY_ABI:
            return [provenance["program_symbol"]]
        return sorted([
            provenance["entry_symbol"], provenance["span_fill_symbol"],
            provenance["program_symbol"],
        ])
    if provenance.get("kind") == "scalar-v2" and provenance.get("model") == "grep":
        return sorted([provenance["entry_symbol"], provenance["program_symbol"]])
    if (
        provenance.get("kind") == "scalar-v2"
        and provenance.get("model") in {"count", "count-spans"}
        and isinstance(provenance.get("scalar_native_reducer"), dict)
        and provenance["scalar_native_reducer"].get("route_variant")
        == "ordered-v15-operation-only"
    ):
        program = provenance.get("program_symbol")
        if not isinstance(program, str) or NATIVE_RUNTIME_PROGRAM_SYMBOL.fullmatch(
            program
        ) is None:
            raise CensusError("operation-only scalar runtime program is malformed")
        return [program]
    if (
        provenance.get("kind") == "scalar-v2"
        and provenance.get("model") in UNIFORM_CAPTURE_ADAPTER_MODELS
    ):
        symbols = [provenance["entry_symbol"], provenance["program_symbol"]]
        if provenance.get("span_fill_symbol"):
            symbols.append(provenance["span_fill_symbol"])
        return sorted(symbols)
    if provenance.get("composite_kind") == "mixed-prepared-native-row-bridge-v15":
        symbols = []
        for index, component in enumerate(provenance["components"]):
            prepared = component["prepared_v15"]
            if prepared is None:
                continue
            validate_normalized_prepared_v15_component(
                prepared, component,
                f"normalized mixed prepared component {index}",
            )
            symbols.append(prepared["runtime_program_symbol"])
            if prepared_v15_component_route(component) == 1:
                symbols.append(prepared["span_fill_symbol"])
        if len(symbols) != len(set(symbols)):
            raise CensusError("mixed prepared V15 route repeats a linked identity symbol")
        return sorted(symbols)
    return []


def authenticate_identity_defined_symbol_inventory(
    provenance: dict[str, object],
    primary_defined_symbols: set[str],
    replica_defined_symbols: set[str],
) -> list[str]:
    """Require both final binaries to retain every route-bound identity symbol."""
    symbols = identity_defined_symbols_from_provenance(provenance)
    if (
        not set(symbols).issubset(primary_defined_symbols)
        or not set(symbols).issubset(replica_defined_symbols)
    ):
        raise CensusError(
            "one or more provenance identity symbols are absent from a final binary"
        )
    return symbols


def conditional_fallback_symbols_from_provenance(
    provenance: dict[str, object],
) -> list[str]:
    if provenance.get("composite_kind") != "selector-negative-certificate-v1":
        return []
    proof = provenance.get("selector_capture_fallback")
    symbol = proof.get("positive_fallback_symbol") if isinstance(proof, dict) else None
    if symbol != SELECTOR_CAPTURE_POSITIVE_FALLBACK_SYMBOL:
        raise CensusError("normalized selector capture fallback marker differs")
    return [symbol]


def claimed_entry_controls_pass(
    entries: list[str],
    controls: list[dict[str, object]],
    expected_architecture: str,
) -> bool:
    if len(controls) != len(entries):
        return False
    for ordinal, (entry, control) in enumerate(zip(entries, controls)):
        process = control.get("process")
        marker = control.get("marker")
        if not isinstance(process, dict) or not isinstance(marker, dict):
            return False
        armed = marker.get("armed")
        if (
            control.get("ordinal") != ordinal
            or control.get("symbol") != entry
            or process.get("outcome") != "exit"
            or process.get("returncode") != TRAP_EXIT
            or marker.get("status") != "valid"
            or marker.get("kind") != "claimed-operation-entry"
            or not marker_patch_evidence_pass(marker, expected_architecture)
            or marker.get("installed") != 1
            or marker.get("expected") != 1
            or not isinstance(armed, list)
            or len(armed) != 1
            or armed[0].get("symbol") != entry
            or marker.get("triggered") != entry
            or marker.get("completed") is not None
        ):
            return False
    return True


def classification_from_qualification_evidence(
    reproducible: bool,
    entries: list[str],
    adapter_route: str,
    helpers: list[str],
    phases: dict[str, object],
    expected_architecture: str,
) -> dict[str, object]:
    try:
        route_policy = OPERATION_ROUTE_POLICIES[adapter_route]
    except KeyError as error:
        raise CensusError(
            f"qualification names unknown operation route {adapter_route!r}"
        ) from error
    unmodified = phases["unmodified_oracle"]
    helper = phases["semantic_helper_trap"]
    helper_phase = helper["process"]
    helper_marker = helper["marker"]
    controls = phases["claimed_entry_negative_traps"]
    executed = unmodified["outcome"] == "exit" and unmodified["returncode"] == 0
    helper_pass = semantic_helper_control_pass(
        helpers, helper_phase, helper_marker, expected_architecture
    )
    negative_pass = claimed_entry_controls_pass(
        entries, controls, expected_architecture
    )
    core_native = reproducible and executed and helper_pass and negative_pass
    adapter_outer_loop = (
        route_policy.boundary is OperationBoundary.RUST_ADAPTER_LOOP
    )
    whole_native = (
        core_native and route_policy.boundary is OperationBoundary.WHOLE_OPERATION
    )
    if not reproducible:
        reason = "non-reproducible-build"
    elif unmodified["outcome"] == "timeout":
        reason = "runtime-timeout"
    elif not executed:
        reason = "runtime-failure"
    elif helper_phase["outcome"] == "timeout":
        reason = "helper-trap-timeout"
    elif helper_phase["returncode"] == TRAP_EXIT:
        reason = "semantic-runtime-helper-invoked"
    elif not helper_pass:
        reason = "helper-trap-control-failure"
    elif not negative_pass:
        reason = "claimed-entry-negative-control-failure"
    else:
        reason = route_policy.success_reason
    return {
        "built_reproducibly": reproducible,
        "executed_oracle_correct": executed,
        "native_search_core_authenticated": core_native,
        "adapter_outer_loop": adapter_outer_loop,
        "whole_operation_native_authenticated": whole_native,
        "reason": reason,
    }


def canonical_expected_value(value: object, context: str) -> int:
    """Require one schedule-selected scalar in the runner's `u64` domain."""
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > (1 << 64) - 1
    ):
        raise CensusError(f"{context} has a non-u64 selected-comparator expectation")
    return value


def expected_value_for_job_points(
    point_rows: list[dict[str, object]], job: dict[str, object]
) -> int:
    """Return the scalar selected by the plan's comparator-first authority."""
    record = frozen_job_expectation_record(job, point_rows)
    return canonical_expected_value(
        record["selected_expected"], f"job {job['job_id']!r}"
    )


def expected_value_for_job(
    plan: dict[str, object], job: dict[str, object]
) -> int:
    return expected_value_for_job_points(plan["points"], job)


def runner_execution_command(runner: pathlib.Path, expected_value: int) -> list[str]:
    expected_value = canonical_expected_value(expected_value, "runner execution")
    return [str(runner), "--quiet", f"--expected-value={expected_value}"]


def qualify_job(args: argparse.Namespace) -> dict[str, object]:
    plan = validate_plan(load_json(pathlib.Path(args.plan)))
    jobs = {row["job_id"]: row for row in plan["jobs"]}
    if args.job_id not in jobs:
        raise CensusError(f"job {args.job_id!r} is absent from the sealed plan")
    job = jobs[args.job_id]
    if not job["is_runtime"] or not job["exact_adapter"]:
        raise CensusError("only exact-adapter runtime jobs can be dynamically qualified")
    expected_value = expected_value_for_job(plan, job)
    public_root = pathlib.Path(args.public_klv_root).resolve(strict=True)
    klv_relative = pathlib.PurePosixPath(job["candidate_klv"]["path"])
    klv_path = (public_root / pathlib.Path(*klv_relative.parts)).resolve(strict=True)
    relative_public_path(public_root, str(klv_path), "qualified job KLV")
    if sha_file(klv_path) != job["candidate_klv"]["sha256"]:
        raise CensusError("qualified job KLV differs from sealed plan")
    klv = klv_path.read_bytes()
    primary_runner = pathlib.Path(args.primary_runner).resolve(strict=True)
    replica_runner = pathlib.Path(args.replica_runner).resolve(strict=True)
    primary_objects = [pathlib.Path(path).resolve(strict=True) for path in args.primary_object]
    replica_objects = [pathlib.Path(path).resolve(strict=True) for path in args.replica_object]
    if not primary_objects or len(primary_objects) != len(replica_objects):
        raise CensusError("independent builds must supply the same nonzero object count")
    trap_library = pathlib.Path(args.trap_library).resolve(strict=True)
    execution_command = runner_execution_command(primary_runner, expected_value)
    primary_provenance_process = subprocess.run(
        [str(primary_runner), "--provenance"], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False, timeout=args.timeout,
    )
    replica_provenance_process = subprocess.run(
        [str(replica_runner), "--provenance"], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False, timeout=args.timeout,
    )
    if primary_provenance_process.returncode != 0 or replica_provenance_process.returncode != 0:
        raise CensusError("one reproducible build does not publish provenance")
    primary_fields = parse_provenance(primary_provenance_process.stdout)
    replica_fields = parse_provenance(replica_provenance_process.stdout)
    if provenance_receipt(primary_fields) != provenance_receipt(replica_fields):
        raise CensusError("independent builds publish different provenance")
    source = plan["candidate_source"]
    target = plan["target"]
    if (
        primary_fields["source_commit"] != source["commit"]
        or primary_fields["source_tree"] != source["tree"]
        or primary_fields["target"] != target["triple"]
        or primary_fields["feature_bits"] != target["feature_bits"]
        or primary_fields["model"] != job["model"]
        or primary_fields["benchmark"] != job["benchmark"]
    ):
        raise CensusError("runner provenance differs from sealed job/source/target")
    primary_hashes = {
        "runner_sha256": sha_file(primary_runner),
        "objects": [
            {"ordinal": index, "sha256": sha_file(path), "bytes": path.stat().st_size}
            for index, path in enumerate(primary_objects)
        ],
    }
    replica_hashes = {
        "runner_sha256": sha_file(replica_runner),
        "objects": [
            {"ordinal": index, "sha256": sha_file(path), "bytes": path.stat().st_size}
            for index, path in enumerate(replica_objects)
        ],
    }
    normalized_provenance = provenance_receipt(primary_fields)
    frozen_expected, frozen_comparator = frozen_job_expectation(plan, job)
    validation = normalized_provenance["validation"]
    if (
        validation["expected_value"] != frozen_expected
        or validation["expected_comparator"] != frozen_comparator
        or validation["schedule_klv_sha256"] != job["candidate_klv"]["sha256"]
    ):
        raise CensusError(
            "runner frozen value/comparator/KLV binding differs from the sealed plan"
        )
    if normalized_provenance["kind"] in {
        "composite-v3", "strict-capture-v4", "participation-capture-v4",
        "selector-capture-fallback-v4", "shared-ordered-many-v2",
        "single-capture-reducer-v5", "weighted-capture-reducer-v6",
    } and (
        normalized_provenance["source_pattern_count"]
        != len(job["input"]["pattern_sha256"])
    ):
        raise CensusError("composite provenance source count differs from sealed job")
    validate_provenance_job_binding(normalized_provenance, job["input"])
    expected_object_hashes = (
        [normalized_provenance["object_sha256"]]
        if normalized_provenance["kind"] in {
            "scalar-v2", "prepared-grep-v15-v2", "shared-ordered-many-v2",
            "single-capture-reducer-v5",
        }
        else [component["object_sha256"] for component in normalized_provenance["components"]]
    )
    if normalized_provenance.get("composite_kind") == "regex-redux-fixed-v1":
        expected_object_hashes.append(normalized_provenance["object_sha256"])
    if normalized_provenance["kind"] == "weighted-capture-reducer-v6":
        expected_object_hashes.append(normalized_provenance["object_sha256"])
    if normalized_provenance.get("composite_kind") in {
        "native-multi-grep-reducer-v1", "native-row-scalar-reducer-v1",
    }:
        expected_object_hashes.append(normalized_provenance["object_sha256"])
    if [row["sha256"] for row in primary_hashes["objects"]] != expected_object_hashes:
        raise CensusError("primary object files differ from provenance object identities")
    if [row["sha256"] for row in replica_hashes["objects"]] != expected_object_hashes:
        raise CensusError("replica object files differ from provenance object identities")
    if normalized_provenance["composite_kind"] in NATIVE_ROW_COMPOSITE_KINDS:
        expected_total_bytes = normalized_provenance["row_total_object_bytes"]
        if normalized_provenance["composite_kind"] in {
            "native-multi-grep-reducer-v1", "native-row-scalar-reducer-v1",
        }:
            proof = normalized_provenance[
                "multi_grep_reducer"
                if normalized_provenance["composite_kind"]
                == "native-multi-grep-reducer-v1"
                else "row_scalar_reducer"
            ]
            component_count = len(normalized_provenance["components"])
            if any(
                sum(row["bytes"] for row in artifact["objects"][:component_count])
                != expected_total_bytes
                or artifact["objects"][component_count]["bytes"]
                != proof["object_bytes"]
                or expected_total_bytes + proof["object_bytes"]
                > MAX_NATIVE_ROW_OBJECT_BYTES
                for artifact in (primary_hashes, replica_hashes)
            ):
                raise CensusError(
                    "native-row wrapper object files differ from their byte receipts"
                )
        elif any(
            sum(row["bytes"] for row in artifact["objects"]) != expected_total_bytes
            for artifact in (primary_hashes, replica_hashes)
        ):
            raise CensusError("native-row object files differ from its total-byte receipt")
    if normalized_provenance["kind"] == "single-capture-reducer-v5":
        expected_bytes = normalized_provenance["capture_reducer"]["object_bytes"]
        if any(
            artifact["objects"][0]["bytes"] != expected_bytes
            for artifact in (primary_hashes, replica_hashes)
        ):
            raise CensusError(
                "single-capture reducer object file differs from its byte receipt"
            )
    if normalized_provenance["kind"] == "weighted-capture-reducer-v6":
        component_count = len(normalized_provenance["components"])
        expected_row_bytes = normalized_provenance["row_total_object_bytes"]
        expected_reducer_bytes = normalized_provenance[
            "weighted_capture_reducer"
        ]["reducer_object_bytes"]
        if any(
            sum(row["bytes"] for row in artifact["objects"][:component_count])
            != expected_row_bytes
            or artifact["objects"][-1]["bytes"] != expected_reducer_bytes
            for artifact in (primary_hashes, replica_hashes)
        ):
            raise CensusError(
                "weighted capture reducer object files differ from byte receipts"
            )
    if normalized_provenance["kind"] in {
        "prepared-grep-v15-v2", "shared-ordered-many-v2",
    } and any(
        not 0 < row["bytes"] <= MAX_NATIVE_ROW_OBJECT_BYTES
        for artifact in (primary_hashes, replica_hashes)
        for row in artifact["objects"]
    ):
        raise CensusError("scalar prepared V15 object exceeds its census byte cap")
    reproducible = primary_hashes == replica_hashes
    primary_symbols, primary_defined_symbols, primary_runtime_references, primary_nm_sha = run_nm(
        args.nm, primary_runner
    )
    replica_symbols, replica_defined_symbols, replica_runtime_references, replica_nm_sha = run_nm(
        args.nm, replica_runner
    )
    runtime_helpers = semantic_helper_symbols(primary_runtime_references)
    if runtime_helpers != semantic_helper_symbols(replica_runtime_references):
        raise CensusError("independent binaries have different semantic helper inventories")
    conditional_fallbacks = conditional_fallback_symbols_from_provenance(
        normalized_provenance
    )
    if (
        not set(conditional_fallbacks).issubset(primary_symbols)
        or not set(conditional_fallbacks).issubset(replica_symbols)
    ):
        raise CensusError(
            "conditional capture fallback marker is absent from a final binary"
        )
    helpers = sorted(set(runtime_helpers) | set(conditional_fallbacks))
    declared_set = set(normalized_provenance["required_runtime_symbols"])
    for component in normalized_provenance["components"]:
        declared_set.update(component["required_runtime_symbols"])
    declared = sorted(declared_set)
    if normalized_provenance["kind"] in {
        "strict-capture-v4", "participation-capture-v4",
        "single-capture-reducer-v5", "weighted-capture-reducer-v6",
    } and declared:
        raise CensusError("native-capture provenance requires runtime symbols")
    declared_semantic = [name for name in declared if not name.startswith(CONTROL_PLANE_PREFIXES)]
    if not set(declared_semantic).issubset(runtime_helpers):
        raise CensusError("provenance-declared semantic helpers escape independent inventory")
    entries, adapter_route = selected_operation_entries(primary_fields)
    if not set(entries).issubset(primary_symbols) or not set(entries).issubset(replica_symbols):
        raise CensusError("one or more claimed operation entries are absent from a final binary")
    authenticate_identity_defined_symbol_inventory(
        normalized_provenance, primary_defined_symbols, replica_defined_symbols
    )
    unmodified = run_checked_process(execution_command, klv, args.timeout)
    helper_marker: dict[str, object]
    negative_controls: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="fre-aot-native-census-") as temporary:
        temporary_path = pathlib.Path(temporary)
        helper_path = temporary_path / "helpers.marker"
        helper_phase = run_checked_process(
            execution_command, klv, args.timeout,
            trap_environment(trap_library, helper_path, helpers, "semantic-helpers"),
        ) if helpers else {
            "outcome": "not-run", "returncode": None, "stdout_bytes": 0,
            "stdout_sha256": sha_bytes(b""), "stderr_bytes": 0,
            "stderr_sha256": sha_bytes(b""),
        }
        helper_marker = parse_trap_marker(helper_path)
        for ordinal, entry in enumerate(entries):
            negative_path = temporary_path / f"entry-{ordinal:03}.marker"
            negative_phase = run_checked_process(
                execution_command, klv, args.timeout,
                trap_environment(
                    trap_library, negative_path, [entry], "claimed-operation-entry"
                ),
            )
            negative_controls.append({
                "ordinal": ordinal,
                "symbol": entry,
                "process": negative_phase,
                "marker": parse_trap_marker(negative_path),
            })
    phases = {
        "unmodified_oracle": unmodified,
        "semantic_helper_trap": {"process": helper_phase, "marker": helper_marker},
        "claimed_entry_negative_traps": negative_controls,
    }
    classification = classification_from_qualification_evidence(
        reproducible,
        entries,
        adapter_route,
        helpers,
        phases,
        target_architecture(target["triple"]),
    )
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "plan_sha256": plan["plan_sha256"],
        "candidate_source": source,
        "job": {
            "job_id": job["job_id"], "point_ids": job["point_ids"],
            "model": job["model"], "input": job["input"],
            "candidate_klv": job["candidate_klv"],
        },
        "artifacts": {
            "primary": primary_hashes, "replica": replica_hashes,
            "reproducible": reproducible,
            "compiled_artifact_present": True,
            "runtime_execution_authenticated_separately": True,
            "provenance": normalized_provenance,
        },
        "route": {
            "operation_entry_symbols": entries,
            "operation_entry_symbols_sha256": sha_bytes(canonical(entries).encode()),
            "adapter_route": adapter_route,
            "semantic_helper_symbols": helpers,
            "semantic_helper_symbols_sha256": sha_bytes(canonical(helpers).encode()),
            "provenance_declared_runtime_symbols": declared,
            "primary_nm_sha256": primary_nm_sha,
            "replica_nm_sha256": replica_nm_sha,
        },
        "phases": phases,
        "classification": classification,
    }
    return add_digest(receipt, "receipt_sha256")


def record_failure(args: argparse.Namespace) -> dict[str, object]:
    """Record a pre-execution failure without retaining potentially sensitive logs."""
    plan = validate_plan(load_json(pathlib.Path(args.plan)))
    jobs = {row["job_id"]: row for row in plan["jobs"]}
    job = jobs.get(args.job_id)
    if job is None or not job["is_runtime"] or not job["exact_adapter"]:
        raise CensusError("failure receipt must name an exact-adapter runtime job")
    evidence = None
    if (args.evidence_sha256 is None) != (args.evidence_bytes is None):
        raise CensusError("failure evidence requires both --evidence-sha256 and --evidence-bytes")
    if args.evidence_sha256 is not None:
        if args.evidence_bytes < 0:
            raise CensusError("failure evidence byte count is negative")
        evidence = {
            "sha256": require_hex64(args.evidence_sha256, "failure evidence digest"),
            "bytes": args.evidence_bytes,
        }
    reason = f"{args.stage}-{args.outcome}"
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "plan_sha256": plan["plan_sha256"],
        "candidate_source": plan["candidate_source"],
        "job": {
            "job_id": job["job_id"], "point_ids": job["point_ids"],
            "model": job["model"], "input": job["input"],
            "candidate_klv": job["candidate_klv"],
        },
        "artifacts": {
            "primary": None, "replica": None, "reproducible": False,
            "compiled_artifact_present": False,
            "runtime_execution_authenticated_separately": True,
            "provenance": None,
        },
        "route": {
            "operation_entry_symbols": [],
            "operation_entry_symbols_sha256": sha_bytes(canonical([]).encode()),
            "adapter_route": None,
            "semantic_helper_symbols": [],
            "semantic_helper_symbols_sha256": sha_bytes(canonical([]).encode()),
            "provenance_declared_runtime_symbols": [],
            "primary_nm_sha256": None, "replica_nm_sha256": None,
        },
        "phases": {
            "pre_execution_failure": {
                "stage": args.stage, "outcome": args.outcome, "evidence": evidence,
            }
        },
        "classification": {
            "built_reproducibly": False,
            "executed_oracle_correct": False,
            "native_search_core_authenticated": False,
            "adapter_outer_loop": False,
            "whole_operation_native_authenticated": False,
            "reason": reason,
        },
    }
    return add_digest(receipt, "receipt_sha256")


def validate_process_record(process: object, context: str) -> None:
    if not isinstance(process, dict):
        raise CensusError(f"{context} is not an object")
    require_exact_keys(process, {
        "outcome", "returncode", "stdout_bytes", "stdout_sha256",
        "stderr_bytes", "stderr_sha256",
    }, context)
    if process["outcome"] not in {"exit", "signal", "timeout", "not-run"}:
        raise CensusError(f"{context} has an invalid outcome")
    if process["outcome"] in {"timeout", "not-run"}:
        if process["returncode"] is not None:
            raise CensusError(f"{context} has a return code without process exit")
    elif not isinstance(process["returncode"], int) or isinstance(process["returncode"], bool):
        raise CensusError(f"{context} has an invalid return code")
    for prefix in ("stdout", "stderr"):
        byte_count = process[f"{prefix}_bytes"]
        if not isinstance(byte_count, int) or isinstance(byte_count, bool) or byte_count < 0:
            raise CensusError(f"{context} has an invalid {prefix} byte count")
        require_hex64(process[f"{prefix}_sha256"], f"{context} {prefix} digest")


def validate_marker_record(marker: object, context: str) -> None:
    if not isinstance(marker, dict):
        raise CensusError(f"{context} is not an object")
    required = {"status", "sha256", "armed", "triggered"}
    allowed = required | {"kind", "architecture", "installed", "expected", "completed"}
    if not required.issubset(marker) or not set(marker).issubset(allowed):
        raise CensusError(f"{context} marker schema is not closed")
    if marker["status"] not in {"missing", "valid", "invalid"}:
        raise CensusError(f"{context} marker has an invalid status")
    if marker["status"] == "missing":
        if marker["sha256"] is not None or marker["armed"] != [] or marker["triggered"] is not None:
            raise CensusError(f"{context} missing marker retains evidence")
    else:
        require_hex64(marker["sha256"], f"{context} marker digest")
    if not isinstance(marker["armed"], list):
        raise CensusError(f"{context} marker armed records are not a list")
    for index, armed in enumerate(marker["armed"]):
        if not isinstance(armed, dict):
            raise CensusError(f"{context} armed record {index} is not an object")
        require_exact_keys(armed, {"symbol", "offset", "before", "after"},
                           f"{context} armed record {index}")
        if not isinstance(armed["symbol"], str) or SYMBOL.fullmatch(armed["symbol"]) is None:
            raise CensusError(f"{context} armed record {index} has an invalid symbol")
    if marker["status"] == "valid":
        architecture = marker.get("architecture")
        if not isinstance(architecture, str) or not marker_patch_evidence_pass(
            marker, architecture
        ):
            raise CensusError(f"{context} has invalid architecture or patch evidence")


def validate_normalized_uniform_capture(
    proof: object,
    components: list[dict[str, object]],
    source_count: int,
    source_map: list[int],
    context: str,
) -> None:
    if not isinstance(proof, dict):
        raise CensusError(f"{context} uniform capture proof is not an object")
    require_exact_keys(proof, {
        "capture_resolution", "capture_proof_algorithm_version",
        "capture_proof_accounting_version", "source_participating_groups",
        "source_minimum_match_bytes", "source_capture_annotations",
        "source_proof_work", "source_proof_peak_stack_items",
        "source_selector_automaton_sha256", "source_selector_program_sha256",
        "source_selector_object_sha256",
    }, f"{context} uniform capture proof")
    if proof["capture_resolution"] != "static-uniform-multiplier":
        raise CensusError(f"{context} uniform capture resolution differs")
    for field in (
        "capture_proof_algorithm_version", "capture_proof_accounting_version",
    ):
        value = proof[field]
        if (
            not isinstance(value, int) or isinstance(value, bool)
            or not 1 <= value <= (1 << 32) - 1
        ):
            raise CensusError(f"{context} {field} is not a positive u32")
    numeric_lists = {
        "source_participating_groups": 1,
        "source_minimum_match_bytes": 1,
        "source_capture_annotations": 0,
        "source_proof_work": 1,
        "source_proof_peak_stack_items": 1,
    }
    for field, minimum in numeric_lists.items():
        values = proof[field]
        if (
            not isinstance(values, list)
            or len(values) != source_count
            or any(
                not isinstance(value, int) or isinstance(value, bool)
                or not minimum <= value <= (1 << 64) - 1
                for value in values
            )
        ):
            raise CensusError(f"{context} {field} is not a canonical source list")
    digest_fields = (
        "source_selector_automaton_sha256", "source_selector_program_sha256",
        "source_selector_object_sha256",
    )
    for field in digest_fields:
        values = proof[field]
        if not isinstance(values, list) or len(values) != source_count:
            raise CensusError(f"{context} {field} has the wrong cardinality")
        for source, value in enumerate(values):
            require_hex64(value, f"{context} {field}[{source}]")
    for source, artifact in enumerate(source_map):
        component = components[artifact]
        if proof["source_participating_groups"][source] - 1 > (
            proof["source_capture_annotations"][source]
        ):
            raise CensusError(
                f"{context} source {source} participation exceeds annotations"
            )
        if (
            proof["source_selector_automaton_sha256"][source]
            != component["automaton_sha256"]
            or proof["source_selector_program_sha256"][source]
            != component["program_sha256"]
            or proof["source_selector_object_sha256"][source]
            != component["object_sha256"]
        ):
            raise CensusError(
                f"{context} source {source} selector digests differ from mapped component"
            )


def validate_normalized_strict_capture(
    proof: object, component: dict[str, object], context: str
) -> None:
    if not isinstance(proof, dict):
        raise CensusError(f"{context} strict capture proof is not an object")
    require_exact_keys(proof, {
        "capture_resolution", "capture_group_count", "capture_can_match_empty",
        "capture_source_sha256", "capture_selector_sha256", "capture_program_sha256",
        "capture_plan_sha256", "capture_bundle_sha256",
        "capture_artifact_identity_sha256", "capture_next_symbol",
        "capture_materialize_symbol", "capture_selector_symbol",
    }, f"{context} strict capture proof")
    if proof["capture_resolution"] != "native-onepass-capture-next-v1":
        raise CensusError(f"{context} strict capture resolution differs")
    group_count = proof["capture_group_count"]
    if (
        not isinstance(group_count, int)
        or isinstance(group_count, bool)
        or not 1 <= group_count <= MAX_NATIVE_ROW_COMPONENTS
        or not isinstance(proof["capture_can_match_empty"], bool)
    ):
        raise CensusError(f"{context} strict capture schema is not canonical")
    for field in (
        "capture_source_sha256", "capture_selector_sha256", "capture_program_sha256",
        "capture_plan_sha256", "capture_bundle_sha256",
        "capture_artifact_identity_sha256",
    ):
        require_hex64(proof[field], f"{context} {field}")
    next_symbol = proof["capture_next_symbol"]
    materialize_symbol = proof["capture_materialize_symbol"]
    selector_symbol = proof["capture_selector_symbol"]
    if (
        not isinstance(next_symbol, str)
        or NATIVE_CAPTURE_NEXT_ENTRY_SYMBOL.fullmatch(next_symbol) is None
        or not isinstance(materialize_symbol, str)
        or NATIVE_CAPTURE_MATERIALIZE_SYMBOL.fullmatch(materialize_symbol) is None
        or not isinstance(selector_symbol, str)
        or NATIVE_SEARCH_ENTRY_SYMBOL.fullmatch(selector_symbol) is None
        or len({next_symbol, materialize_symbol, selector_symbol}) != 3
    ):
        raise CensusError(f"{context} strict capture symbols are not canonical")
    if (
        component["entry_symbol"] != next_symbol
        or component["program_sha256"] != proof["capture_program_sha256"]
        or component["required_runtime_symbols"] != []
    ):
        raise CensusError(f"{context} strict capture component binding differs")


def validate_normalized_participation_capture(
    proof: object,
    component: dict[str, object],
    target: object,
    feature_bits: object,
    context: str,
) -> None:
    if not isinstance(proof, dict):
        raise CensusError(f"{context} participation capture proof is not an object")
    numeric_fields = {
        "capture_group_count": (1, MAX_NATIVE_ROW_COMPONENTS),
        "participation_strategy": (1, 2),
        "participation_semantic_runtime_calls": (0, 0),
        "participation_assertions": (0, NATIVE_PARTICIPATION_MAX_ASSERTIONS),
        "participation_assertion_signatures": (
            1, NATIVE_PARTICIPATION_MAX_ASSERTION_SIGNATURES
        ),
        "participation_byte_classes": (1, NATIVE_PARTICIPATION_MAX_BYTE_CLASSES),
        "participation_dfa_states": (1, NATIVE_PARTICIPATION_MAX_DFA_STATES),
        "participation_transition_cells": (
            1, NATIVE_PARTICIPATION_MAX_TRANSITION_CELLS
        ),
        "participation_ordered_nfa_states": (0, 0),
        "participation_ordered_nfa_byte_ranges": (0, 0),
        "participation_dfa_fallback_resource": (0, 0),
        "participation_dfa_fallback_required": (0, 0),
        "participation_dfa_fallback_limit": (0, 0),
        "participation_build_work": (1, NATIVE_PARTICIPATION_MAX_BUILD_WORK),
        "participation_scratch_bytes": (
            NATIVE_PARTICIPATION_SCRATCH_BYTES,
            NATIVE_PARTICIPATION_SCRATCH_BYTES,
        ),
        "participation_plan_bytes": (
            NATIVE_PARTICIPATION_HEADER_BYTES,
            NATIVE_PARTICIPATION_MAX_PLAN_BYTES,
        ),
    }
    digest_fields = {
        "capture_source_sha256", "capture_selector_sha256",
        "capture_program_sha256", "selector_object_sha256",
        "participation_bundle_sha256", "participation_export_identity_sha256",
        "participation_object_sha256", "capture_artifact_identity_sha256",
    }
    symbol_fields = {
        "participation_bundle_symbol", "capture_selector_symbol",
        "participation_entry_symbol",
    }
    require_exact_keys(
        proof,
        {
            "capture_resolution", "participation_algorithm_id",
            *numeric_fields, *digest_fields, *symbol_fields,
        },
        f"{context} participation capture proof",
    )
    if (
        proof["capture_resolution"] != "native-exact-span-participation-dfa-v1"
        or proof["participation_algorithm_id"] != NATIVE_PARTICIPATION_ALGORITHM_ID
    ):
        raise CensusError(f"{context} participation capture identity differs")
    for field, (minimum, maximum) in numeric_fields.items():
        value = proof[field]
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or not minimum <= value <= maximum
        ):
            raise CensusError(f"{context} {field} is not canonical")
    if not isinstance(target, str):
        raise CensusError(f"{context} target is not a string")
    expected_strategy = {"x86_64": 1, "aarch64": 2}[
        target_architecture(target)
    ]
    if proof["participation_strategy"] != expected_strategy:
        raise CensusError(
            f"{context} participation strategy differs from target architecture"
        )
    expected_cells = (
        proof["participation_dfa_states"]
        * proof["participation_byte_classes"]
        * proof["participation_assertion_signatures"]
    )
    if proof["participation_transition_cells"] != expected_cells:
        raise CensusError(f"{context} participation transition geometry does not close")
    if proof["participation_plan_bytes"] != participation_plan_bytes(
        proof["participation_assertions"],
        proof["participation_assertion_signatures"],
        proof["participation_dfa_states"],
        proof["participation_transition_cells"],
    ):
        raise CensusError(f"{context} participation plan extent does not close")
    for field in digest_fields:
        require_hex64(proof[field], f"{context} {field}")
    bundle = proof["participation_bundle_symbol"]
    selector = proof["capture_selector_symbol"]
    entry = proof["participation_entry_symbol"]
    export_identity = proof["participation_export_identity_sha256"]
    if (
        not isinstance(bundle, str)
        or NATIVE_PARTICIPATION_BUNDLE_SYMBOL.fullmatch(bundle) is None
        or not isinstance(selector, str)
        or NATIVE_SEARCH_ENTRY_SYMBOL.fullmatch(selector) is None
        or not isinstance(entry, str)
        or NATIVE_PARTICIPATION_ENTRY_SYMBOL.fullmatch(entry) is None
        or len({bundle, selector, entry}) != 3
        or not bundle.endswith(export_identity)
        or not entry.endswith(export_identity)
    ):
        raise CensusError(f"{context} participation symbols are not canonical")
    if not isinstance(feature_bits, str):
        raise CensusError(f"{context} feature bits are not a string")
    expected_export_identity = participation_export_identity(
        proof["participation_bundle_sha256"],
        target,
        feature_bits,
        proof["selector_object_sha256"],
        selector,
    )
    if export_identity != expected_export_identity:
        raise CensusError(
            f"{context} participation export identity does not authenticate its inputs"
        )
    if (
        component["entry_symbol"] != selector
        or component["program_sha256"] != proof["capture_program_sha256"]
        or component["object_sha256"] != proof["participation_object_sha256"]
        or component["required_runtime_symbols"] != []
    ):
        raise CensusError(f"{context} participation component binding differs")


def validate_normalized_selector_capture_fallback(
    proof: object, component: dict[str, object], context: str
) -> None:
    if not isinstance(proof, dict):
        raise CensusError(f"{context} selector capture fallback proof is not an object")
    require_exact_keys(
        proof,
        {
            "capture_resolution", "positive_fallback_profile",
            "positive_fallback_symbol", "direct_participation_resource",
            "direct_participation_required", "direct_participation_limit",
            "selector_entry_symbol",
        },
        f"{context} selector capture fallback proof",
    )
    resource = proof["direct_participation_resource"]
    expected_limit = {
        "DfaStates": SELECTOR_CAPTURE_DFA_STATES_LIMIT,
        "BuildWork": SELECTOR_CAPTURE_BUILD_WORK_LIMIT,
    }.get(resource)
    required = proof["direct_participation_required"]
    limit = proof["direct_participation_limit"]
    if (
        proof["capture_resolution"]
        != "native-selector-negative-certificate-with-stock-positive-capture-fallback-v1"
        or proof["positive_fallback_profile"]
        != SELECTOR_CAPTURE_POSITIVE_FALLBACK_PROFILE
        or proof["positive_fallback_symbol"]
        != SELECTOR_CAPTURE_POSITIVE_FALLBACK_SYMBOL
        or expected_limit is None
        or not isinstance(required, int)
        or isinstance(required, bool)
        or not isinstance(limit, int)
        or isinstance(limit, bool)
        or limit != expected_limit
        or required != expected_limit + 1
        or proof["selector_entry_symbol"] != component["entry_symbol"]
        or not isinstance(component["entry_symbol"], str)
        or NATIVE_SEARCH_ENTRY_SYMBOL.fullmatch(component["entry_symbol"]) is None
        or component["required_runtime_symbols"] != []
    ):
        raise CensusError(f"{context} selector capture fallback proof differs")


def validate_normalized_prepared_v15_limits(proof: object, context: str) -> None:
    if not isinstance(proof, dict):
        raise CensusError(f"{context} prepared V15 limits are not an object")
    require_exact_keys(
        proof, {"max_handle_bytes", "max_scratch_bytes", "max_setup_work"},
        f"{context} prepared V15 limits",
    )
    if proof != {
        "max_handle_bytes": PREPARED_V15_MAX_HANDLE_BYTES,
        "max_scratch_bytes": PREPARED_V15_MAX_SCRATCH_BYTES,
        "max_setup_work": PREPARED_V15_MAX_SETUP_WORK,
    }:
        raise CensusError(f"{context} prepared V15 limits differ")


def validate_normalized_prepared_v15_component(
    proof: object, component: dict[str, object], context: str
) -> None:
    if not isinstance(proof, dict):
        raise CensusError(f"{context} prepared V15 component proof is not an object")
    legacy_keys = {
        "required_prepare_capabilities", "prepare_config_version",
        "prepare_operation_flags", "runtime_program_symbol",
        "runtime_program_len", "span_fill_symbol", "prepared_bulk_strategy",
        "artifact_identity_sha256",
    }
    enhanced_keys = legacy_keys | {"entry_abi", "prepared_surface"}
    if frozenset(proof) not in {frozenset(legacy_keys), frozenset(enhanced_keys)}:
        raise CensusError(f"{context} prepared V15 component proof fields differ")
    entry = component["entry_symbol"]
    entry_suffix = (
        symbol_identity_suffix(entry, NATIVE_SEARCH_EXCLUSIVE_ENTRY_SYMBOL, context)
        if isinstance(entry, str) else None
    )
    program = proof["runtime_program_symbol"]
    span_fill = proof["span_fill_symbol"]
    entry_abi = proof.get("entry_abi")
    prepared_surface = proof.get("prepared_surface")
    legacy_compatibility = entry_abi is None or (
        entry_abi == SPAN_SEARCH_ENTRY_ABI
        and prepared_surface == PREPARED_V15_COMPATIBILITY_SURFACE
    )
    strict_row_search = (
        entry_abi == PREPARED_SPAN_SEARCH_ENTRY_ABI
        and prepared_surface == PREPARED_V15_ROW_SEARCH_SURFACE
    )
    if (
        proof["required_prepare_capabilities"] != PREPARED_V15_CAPABILITY
        or proof["prepare_config_version"] != PREPARED_V15_CONFIG_VERSION
        or proof["prepare_operation_flags"] != PREPARED_V15_SPAN_OPERATION_FLAGS
        or not isinstance(proof["runtime_program_len"], int)
        or isinstance(proof["runtime_program_len"], bool)
        or not 1 <= proof["runtime_program_len"] <= MAX_SERIALIZED_PROGRAM_BYTES
        or not isinstance(program, str)
        or not isinstance(span_fill, str)
        or not (legacy_compatibility or strict_row_search)
        or (
            "entry_abi" in component
            and (
                component.get("entry_abi") != entry_abi
                or component.get("prepared_surface") != prepared_surface
            )
        )
    ):
        raise CensusError(f"{context} prepared V15 component proof differs")
    program_suffix = symbol_identity_suffix(program, NATIVE_RUNTIME_PROGRAM_SYMBOL, context)
    if legacy_compatibility:
        span_fill_suffix = symbol_identity_suffix(
            span_fill, NATIVE_SPAN_FILL_ENTRY_SYMBOL, context
        )
        surface_closed = (
            proof["prepared_bulk_strategy"] == "Some(NativeOrderedNfaLoop)"
            and component["required_runtime_symbols"]
                == list(PREPARED_V15_RUNTIME_SYMBOLS)
            and len({entry_suffix, program_suffix, span_fill_suffix}) == 1
        )
    else:
        surface_closed = (
            proof["prepared_bulk_strategy"] == "None"
            and component["required_runtime_symbols"] == []
            and span_fill == ""
            and entry_suffix == program_suffix
        )
    if entry_suffix is None or not surface_closed or (
        proof["artifact_identity_sha256"] != entry_suffix
    ):
        raise CensusError(f"{context} prepared V15 component identity differs")


def validate_normalized_scalar_native_reducer(
    proof: object, provenance: dict[str, object], context: str
) -> str:
    """Close one direct, compatibility V15, or operation-only V15 scalar route."""
    if not isinstance(proof, dict):
        raise CensusError(f"{context} scalar native reducer proof is not an object")
    require_exact_keys(
        proof,
        {
            "route_variant", "required_prepare_capabilities",
            "prepare_config_version", "prepare_operation_flags",
            "max_handle_bytes", "max_scratch_bytes", "max_setup_work",
            "runtime_program_len", "entry_identity_sha256",
            "program_identity_sha256", "reducer_identity_sha256",
            "span_fill_identity_sha256",
        },
        f"{context} scalar native reducer proof",
    )
    model = provenance.get("model")
    (
        direct_adapter,
        ordered_adapter,
        reducer_pattern,
        operation_flags,
        ordered_runtime_symbols,
        span_iteration,
        _,
    ) = scalar_native_reducer_surface(model)
    entry = provenance.get("entry_symbol")
    program = provenance.get("program_symbol")
    reducer = provenance.get("reducer_symbol")
    if not all(isinstance(symbol, str) for symbol in (entry, program, reducer)):
        raise CensusError(f"{context} scalar native reducer symbols are malformed")
    require_hex64(provenance.get("program_sha256"), f"{context} program digest")
    require_hex64(provenance.get("object_sha256"), f"{context} object digest")
    direct = proof.get("route_variant") == "direct-v2"
    ordered = proof.get("route_variant") == "ordered-v15"
    operation_only = proof.get("route_variant") == "ordered-v15-operation-only"
    entry_identity = symbol_identity_suffix(
        entry,
        reducer_pattern if operation_only else NATIVE_SEARCH_ENTRY_SYMBOL,
        f"{context} {'operation-only' if operation_only else 'ordinary'} entry",
    )
    program_identity = symbol_identity_suffix(
        program, NATIVE_RUNTIME_PROGRAM_SYMBOL, f"{context} runtime program"
    )
    reducer_identity = symbol_identity_suffix(
        reducer, reducer_pattern, f"{context} operation entry"
    )
    if direct:
        expected = {
            "entry_abi": SPAN_SEARCH_ENTRY_ABI,
            "adapter": direct_adapter,
            "aggregate_strategy": "Some(NativeFused)",
            "prepared_bulk_strategy": "None",
            "required_runtime_symbols": [],
            "span_fill_symbol": "",
            "span_fill_identity_sha256": None,
            "required_prepare_capabilities": 0,
            "prepare_config_version": PREPARED_V2_CONFIG_VERSION,
            "max_handle_bytes": 0,
            "max_scratch_bytes": 0,
            "max_setup_work": 0,
        }
    elif operation_only:
        expected = {
            "entry_abi": PREPARED_SCALAR_REDUCE_ENTRY_ABI,
            "adapter": ordered_adapter,
            "aggregate_strategy": "Some(NativeOrderedNfaFused)",
            "prepared_bulk_strategy": "None",
            "required_runtime_symbols": [],
            "span_fill_symbol": "",
            "span_fill_identity_sha256": None,
            "required_prepare_capabilities": PREPARED_V15_CAPABILITY,
            "prepare_config_version": PREPARED_V15_CONFIG_VERSION,
            "max_handle_bytes": PREPARED_V15_MAX_HANDLE_BYTES,
            "max_scratch_bytes": PREPARED_V15_MAX_SCRATCH_BYTES,
            "max_setup_work": PREPARED_V15_MAX_SETUP_WORK,
        }
        if provenance.get("engine") != "OrderedNfa":
            raise CensusError(f"{context} operation-only scalar engine differs")
    elif ordered:
        span_fill = provenance.get("span_fill_symbol")
        if not isinstance(span_fill, str):
            raise CensusError(f"{context} scalar native reducer SpanFill is malformed")
        span_fill_identity = symbol_identity_suffix(
            span_fill, NATIVE_SPAN_FILL_ENTRY_SYMBOL, f"{context} SpanFill entry"
        )
        expected = {
            "entry_abi": SPAN_SEARCH_ENTRY_ABI,
            "adapter": ordered_adapter,
            "aggregate_strategy": "Some(NativeOrderedNfaFused)",
            "prepared_bulk_strategy": "Some(NativeOrderedNfaLoop)",
            "required_runtime_symbols": list(ordered_runtime_symbols),
            "span_fill_symbol": span_fill,
            "span_fill_identity_sha256": span_fill_identity,
            "required_prepare_capabilities": PREPARED_V15_CAPABILITY,
            "prepare_config_version": PREPARED_V15_CONFIG_VERSION,
            "max_handle_bytes": PREPARED_V15_MAX_HANDLE_BYTES,
            "max_scratch_bytes": PREPARED_V15_MAX_SCRATCH_BYTES,
            "max_setup_work": PREPARED_V15_MAX_SETUP_WORK,
        }
        if provenance.get("engine") != "OrderedNfa":
            raise CensusError(f"{context} scalar ordered reducer engine differs")
    else:
        raise CensusError(f"{context} scalar native reducer route variant differs")
    runtime_program_len = proof.get("runtime_program_len")
    if (
        provenance.get("schema") != "fre.aot.rebar-runner.v2"
        or provenance.get("kind") != "scalar-v2"
        or provenance.get("composite_kind") is not None
        or provenance.get("source_pattern_count") is not None
        or provenance.get("source_to_artifact") != []
        or provenance.get("row_total_object_bytes") is not None
        or provenance.get("uniform_capture") is not None
        or provenance.get("shared_ordered_many") is not None
        or provenance.get("components") != []
        or provenance.get("adapter") != expected["adapter"]
        or provenance.get("entry_abi") != expected["entry_abi"]
        or provenance.get("boundary") != "runtime-klv-warmup-schedule"
        or provenance.get("aggregate_strategy") != expected["aggregate_strategy"]
        or provenance.get("prepared_bulk_strategy")
        != expected["prepared_bulk_strategy"]
        or provenance.get("span_iteration_strategy") != span_iteration
        or provenance.get("grep_iteration_strategy") != "not-applicable"
        or provenance.get("required_runtime_symbols")
        != expected["required_runtime_symbols"]
        or provenance.get("span_fill_symbol") != expected["span_fill_symbol"]
        or proof.get("required_prepare_capabilities")
        != expected["required_prepare_capabilities"]
        or proof.get("prepare_config_version") != expected["prepare_config_version"]
        or proof.get("prepare_operation_flags") != operation_flags
        or proof.get("max_handle_bytes") != expected["max_handle_bytes"]
        or proof.get("max_scratch_bytes") != expected["max_scratch_bytes"]
        or proof.get("max_setup_work") != expected["max_setup_work"]
        or proof.get("span_fill_identity_sha256")
        != expected["span_fill_identity_sha256"]
        or proof.get("entry_identity_sha256") != entry_identity
        or proof.get("program_identity_sha256") != program_identity
        or proof.get("reducer_identity_sha256") != reducer_identity
        or not isinstance(runtime_program_len, int)
        or isinstance(runtime_program_len, bool)
        or not 1 <= runtime_program_len <= MAX_SERIALIZED_PROGRAM_BYTES
        or (
            operation_only
            and (entry != reducer or program_identity != reducer_identity)
        )
        or (not operation_only and len({entry, program, reducer}) != 3)
    ):
        raise CensusError(f"{context} scalar native reducer route differs")
    return scalar_native_reducer_route(model, proof)


def validate_normalized_prepared_grep_v15(
    proof: object, provenance: dict[str, object], context: str
) -> None:
    if not isinstance(proof, dict):
        raise CensusError(f"{context} scalar prepared V15 proof is not an object")
    require_exact_keys(
        proof,
        {
            "required_prepare_capabilities", "prepare_config_version",
            "prepare_operation_flags", "max_handle_bytes", "max_scratch_bytes",
            "max_setup_work", "artifact_identity_sha256", "reducer_identity_sha256",
            "runtime_program_len",
        },
        f"{context} scalar prepared V15 proof",
    )
    entry = provenance["entry_symbol"]
    span_fill = provenance["span_fill_symbol"]
    program = provenance["program_symbol"]
    reducer = provenance["reducer_symbol"]
    if not all(isinstance(value, str) for value in (entry, span_fill, program, reducer)):
        raise CensusError(f"{context} scalar prepared V15 symbols are malformed")
    program_suffix = symbol_identity_suffix(program, NATIVE_RUNTIME_PROGRAM_SYMBOL, context)
    reducer_suffix = symbol_identity_suffix(reducer, NATIVE_GREP_COUNT_ENTRY_SYMBOL, context)
    if (
        proof["required_prepare_capabilities"] != PREPARED_V15_CAPABILITY
        or proof["prepare_config_version"] != PREPARED_V15_CONFIG_VERSION
        or proof["prepare_operation_flags"] != PREPARED_V15_SPAN_OPERATION_FLAGS
        or proof["max_handle_bytes"] != PREPARED_V15_MAX_HANDLE_BYTES
        or proof["max_scratch_bytes"] != PREPARED_V15_MAX_SCRATCH_BYTES
        or proof["max_setup_work"] != PREPARED_V15_MAX_SETUP_WORK
        or not isinstance(proof["runtime_program_len"], int)
        or isinstance(proof["runtime_program_len"], bool)
        or not 1 <= proof["runtime_program_len"] <= MAX_SERIALIZED_PROGRAM_BYTES
        or proof["reducer_identity_sha256"] != reducer_suffix
    ):
        raise CensusError(f"{context} scalar prepared V15 proof differs")
    if provenance.get("entry_abi") == SPAN_SEARCH_ENTRY_ABI:
        entry_suffix = symbol_identity_suffix(
            entry, NATIVE_SEARCH_ENTRY_SYMBOL, context
        )
        span_fill_suffix = symbol_identity_suffix(
            span_fill, NATIVE_SPAN_FILL_ENTRY_SYMBOL, context
        )
        route_is_exact = (
            provenance.get("prepared_bulk_strategy")
            == "Some(NativeOrderedNfaLoop)"
            and provenance.get("required_runtime_symbols")
            == list(PREPARED_V15_SCALAR_GREP_RUNTIME_SYMBOLS)
            and proof["artifact_identity_sha256"] == entry_suffix
            and len({entry_suffix, span_fill_suffix, program_suffix}) == 1
            and reducer_suffix != entry_suffix
        )
    elif provenance.get("entry_abi") == PREPARED_SCALAR_REDUCE_ENTRY_ABI:
        entry_suffix = symbol_identity_suffix(
            entry, NATIVE_GREP_COUNT_ENTRY_SYMBOL, context
        )
        route_is_exact = (
            provenance.get("prepared_bulk_strategy") == "None"
            and provenance.get("required_runtime_symbols") == []
            and span_fill == ""
            and entry == reducer
            and proof["artifact_identity_sha256"] == entry_suffix
            and len({entry_suffix, program_suffix, reducer_suffix}) == 1
        )
    else:
        raise CensusError(f"{context} scalar prepared V15 entry ABI differs")
    if not route_is_exact:
        raise CensusError(f"{context} scalar prepared V15 topology differs")


def validate_normalized_uniform_capture_reducer(
    proof: object, provenance: dict[str, object], context: str
) -> None:
    """Close the normalized single-call uniform-capture reducer receipt."""
    if not isinstance(proof, dict):
        raise CensusError(f"{context} uniform-capture proof is not an object")
    require_exact_keys(
        proof,
        {
            "route_variant", "required_prepare_capabilities",
            "prepare_config_version", "prepare_operation_flags",
            "max_handle_bytes", "max_scratch_bytes", "max_setup_work",
            "runtime_program_len", "entry_identity_sha256",
            "program_identity_sha256", "reducer_identity_sha256",
            "span_fill_identity_sha256",
        },
        f"{context} uniform-capture proof",
    )
    model = provenance.get("model")
    if model == "count-captures":
        adapter = "general-aot-native-uniform-capture-count-reducer-v1"
        reducer_pattern = NATIVE_COUNT_CAPTURES_ENTRY_SYMBOL
        grep_iteration = "not-applicable"
    elif model == "grep-captures":
        adapter = "general-aot-native-uniform-capture-grep-reducer-v1"
        reducer_pattern = NATIVE_GREP_CAPTURES_ENTRY_SYMBOL
        grep_iteration = "linked-native-uniform-capture-reducer-v1"
    else:
        raise CensusError(f"{context} uniform-capture model differs")
    entry = provenance.get("entry_symbol")
    program = provenance.get("program_symbol")
    reducer = provenance.get("reducer_symbol")
    if not all(isinstance(value, str) for value in (entry, program, reducer)):
        raise CensusError(f"{context} uniform-capture symbols are malformed")
    operation_only = proof.get("route_variant") == "ordered-v15-operation-only"
    entry_identity = symbol_identity_suffix(
        entry,
        NATIVE_COUNT_ENTRY_SYMBOL if operation_only else NATIVE_SEARCH_ENTRY_SYMBOL,
        context,
    )
    program_identity = symbol_identity_suffix(
        program, NATIVE_RUNTIME_PROGRAM_SYMBOL, context
    )
    reducer_identity = symbol_identity_suffix(reducer, reducer_pattern, context)
    direct = proof.get("route_variant") == "direct-v1"
    ordered = proof.get("route_variant") == "ordered-v15"
    operation_only = proof.get("route_variant") == "ordered-v15-operation-only"
    if direct:
        expected = {
            "boundary": "single-call-native-uniform-capture-reducer",
            "aggregate_strategy": "Some(NativeFused)",
            "prepared_bulk_strategy": "None",
            "required_runtime_symbols": [],
            "span_fill_symbol": "",
            "required_prepare_capabilities": 0,
            "prepare_config_version": 2,
            "max_handle_bytes": 0,
            "max_scratch_bytes": 0,
            "max_setup_work": 0,
            "span_fill_identity_sha256": None,
        }
    elif operation_only:
        expected = {
            "entry_abi": PREPARED_SCALAR_REDUCE_ENTRY_ABI,
            "boundary": "single-call-native-uniform-capture-reducer",
            "aggregate_strategy": "Some(NativeOrderedNfaFused)",
            "prepared_bulk_strategy": "None",
            "required_runtime_symbols": [],
            "span_fill_symbol": "",
            "required_prepare_capabilities": PREPARED_V15_CAPABILITY,
            "prepare_config_version": PREPARED_V15_CONFIG_VERSION,
            "max_handle_bytes": PREPARED_V15_MAX_HANDLE_BYTES,
            "max_scratch_bytes": PREPARED_V15_MAX_SCRATCH_BYTES,
            "max_setup_work": PREPARED_V15_MAX_SETUP_WORK,
            "span_fill_identity_sha256": None,
        }
        if provenance.get("engine") != "OrderedNfa":
            raise CensusError(f"{context} uniform-capture operation-only engine differs")
    elif ordered:
        span_fill = provenance.get("span_fill_symbol")
        if not isinstance(span_fill, str):
            raise CensusError(f"{context} uniform-capture SpanFill is malformed")
        span_fill_identity = symbol_identity_suffix(
            span_fill, NATIVE_SPAN_FILL_ENTRY_SYMBOL, context
        )
        expected = {
            "boundary": "single-call-native-uniform-capture-helper-backed-reducer",
            "aggregate_strategy": "Some(NativeOrderedNfaFused)",
            "prepared_bulk_strategy": "Some(NativeOrderedNfaLoop)",
            "required_runtime_symbols": list(
                PREPARED_V15_SHARED_COUNT_RUNTIME_SYMBOLS
            ),
            "span_fill_symbol": span_fill,
            "required_prepare_capabilities": PREPARED_V15_CAPABILITY,
            "prepare_config_version": PREPARED_V15_CONFIG_VERSION,
            "max_handle_bytes": PREPARED_V15_MAX_HANDLE_BYTES,
            "max_scratch_bytes": PREPARED_V15_MAX_SCRATCH_BYTES,
            "max_setup_work": PREPARED_V15_MAX_SETUP_WORK,
            "span_fill_identity_sha256": span_fill_identity,
        }
        if provenance.get("engine") != "OrderedNfa":
            raise CensusError(f"{context} uniform-capture ordered engine differs")
    else:
        raise CensusError(f"{context} uniform-capture route variant differs")
    if (
        provenance.get("adapter") != adapter
        or provenance.get("entry_abi")
        != expected.get("entry_abi", SPAN_SEARCH_ENTRY_ABI)
        or provenance.get("boundary") != expected["boundary"]
        or provenance.get("aggregate_strategy") != expected["aggregate_strategy"]
        or provenance.get("prepared_bulk_strategy")
        != expected["prepared_bulk_strategy"]
        or provenance.get("span_iteration_strategy") != "not-applicable"
        or provenance.get("grep_iteration_strategy") != grep_iteration
        or provenance.get("required_runtime_symbols")
        != expected["required_runtime_symbols"]
        or provenance.get("span_fill_symbol") != expected["span_fill_symbol"]
        or proof.get("required_prepare_capabilities")
        != expected["required_prepare_capabilities"]
        or proof.get("prepare_config_version")
        != expected["prepare_config_version"]
        or proof.get("prepare_operation_flags")
        != PREPARED_V15_SPAN_OPERATION_FLAGS
        or proof.get("max_handle_bytes") != expected["max_handle_bytes"]
        or proof.get("max_scratch_bytes") != expected["max_scratch_bytes"]
        or proof.get("max_setup_work") != expected["max_setup_work"]
        or proof.get("span_fill_identity_sha256")
        != expected["span_fill_identity_sha256"]
        or proof.get("entry_identity_sha256") != entry_identity
        or proof.get("program_identity_sha256") != program_identity
        or proof.get("reducer_identity_sha256") != reducer_identity
        or not isinstance(proof.get("runtime_program_len"), int)
        or isinstance(proof.get("runtime_program_len"), bool)
        or not 1 <= proof["runtime_program_len"] <= MAX_SERIALIZED_PROGRAM_BYTES
        or len({entry, program, reducer}) != 3
        or (operation_only and entry_identity != program_identity)
        or (operation_only and reducer_identity == entry_identity)
    ):
        raise CensusError(f"{context} uniform-capture route differs")


def validate_normalized_shared_ordered_many(
    proof: object, provenance: dict[str, object], context: str
) -> str:
    """Close one normalized multi-source Count/SpanSum reducer receipt."""
    if not isinstance(proof, dict):
        raise CensusError(f"{context} shared ordered-many proof is not an object")
    require_exact_keys(
        proof,
        {
            "route_variant", "receipt_schema_version", "source_pattern_count",
            "ordered_sources_sha256", "required_prepare_capabilities",
            "prepare_config_version", "prepare_operation_flags",
            "max_handle_bytes", "max_scratch_bytes", "max_setup_work",
            "runtime_program_len", "artifact_identity_sha256",
            "reducer_identity_sha256",
        },
        f"{context} shared ordered-many proof",
    )
    route = {
        "count": (
            "general-aot-shared-ordered-many-native-count-v1",
            "not-applicable",
            PREPARED_V15_SPAN_OPERATION_FLAGS,
            PREPARED_V15_SHARED_COUNT_RUNTIME_SYMBOLS,
            NATIVE_COUNT_ENTRY_SYMBOL,
            "not-applicable",
            "single-call-shared-ordered-many-helper-free-native-reducer",
            NATIVE_COUNT_ENTRY_SYMBOL,
            False,
        ),
        "count-spans": (
            "general-aot-shared-ordered-many-native-span-sum-v1",
            "linked-shared-ordered-many-native-span-sum-reducer-v1",
            PREPARED_V15_SPAN_SUM_OPERATION_FLAGS,
            PREPARED_V15_SHARED_SPAN_SUM_RUNTIME_SYMBOLS,
            NATIVE_SPAN_SUM_ENTRY_SYMBOL,
            "not-applicable",
            "single-call-shared-ordered-many-helper-free-native-reducer",
            NATIVE_SPAN_SUM_ENTRY_SYMBOL,
            False,
        ),
        "count-captures": (
            "general-aot-shared-uniform-capture-count-reducer-v1",
            "not-applicable",
            PREPARED_V15_SPAN_OPERATION_FLAGS,
            (),
            NATIVE_COUNT_CAPTURES_ENTRY_SYMBOL,
            "not-applicable",
            "single-call-shared-uniform-capture-helper-free-native-reducer",
            NATIVE_COUNT_ENTRY_SYMBOL,
            True,
        ),
        "grep-captures": (
            "general-aot-shared-uniform-capture-grep-reducer-v1",
            "not-applicable",
            PREPARED_V15_SPAN_OPERATION_FLAGS,
            (),
            NATIVE_GREP_CAPTURES_ENTRY_SYMBOL,
            "linked-native-uniform-capture-reducer-v1",
            "single-call-shared-uniform-capture-helper-free-native-reducer",
            NATIVE_COUNT_ENTRY_SYMBOL,
            True,
        ),
    }.get(provenance.get("model"))
    if route is None:
        raise CensusError(f"{context} has an unsupported shared model")
    (
        adapter, span_iteration, operation_flags, runtime_symbols,
        reducer_pattern, grep_iteration, helper_free_boundary,
        operation_entry_pattern, capture,
    ) = route
    variant = proof.get("route_variant")
    native_fused = variant == "native-fused-v2"
    compatibility = variant == "ordered-v15"
    operation_only = variant == "ordered-v15-operation-only"
    if native_fused:
        bulk = provenance.get("prepared_bulk_strategy")
        variant_topology = (
            provenance.get("boundary")
            == helper_free_boundary
            and provenance.get("entry_abi") == SPAN_SEARCH_ENTRY_ABI
            and provenance.get("aggregate_strategy") == "Some(NativeFused)"
            and provenance.get("required_runtime_symbols") == []
            and bulk in {
                "None", "Some(NativePreparedLoop)", "Some(NativeFrozenLoop)",
            }
            and (not capture or bulk == "None")
        )
    elif compatibility:
        variant_topology = (
            not capture
            and
            provenance.get("boundary")
            == "single-call-shared-ordered-many-helper-backed-reducer"
            and provenance.get("engine") == "OrderedNfa"
            and provenance.get("aggregate_strategy")
            == "Some(NativeOrderedNfaFused)"
            and provenance.get("prepared_bulk_strategy")
            == "Some(NativeOrderedNfaLoop)"
            and provenance.get("required_runtime_symbols") == list(runtime_symbols)
            and provenance.get("entry_abi") == SPAN_SEARCH_ENTRY_ABI
        )
    elif operation_only:
        variant_topology = (
            provenance.get("boundary")
            == helper_free_boundary
            and provenance.get("engine") == "OrderedNfa"
            and provenance.get("entry_abi") == PREPARED_SCALAR_REDUCE_ENTRY_ABI
            and provenance.get("aggregate_strategy")
            == "Some(NativeOrderedNfaFused)"
            and provenance.get("prepared_bulk_strategy") == "None"
            and provenance.get("required_runtime_symbols") == []
            and provenance.get("span_fill_symbol") == ""
        )
    else:
        raise CensusError(f"{context} shared ordered-many route variant differs")
    source_count = proof.get("source_pattern_count")
    source_map = provenance.get("source_to_artifact")
    if (
        provenance.get("schema") != "fre.aot.rebar-runner.v2"
        or provenance.get("kind") != "shared-ordered-many-v2"
        or provenance.get("composite_kind")
        != "shared-ordered-many-native-reducer-v1"
        or provenance.get("adapter") != adapter
        or not variant_topology
        or provenance.get("span_iteration_strategy") != span_iteration
        or provenance.get("grep_iteration_strategy") != grep_iteration
        or not isinstance(source_count, int)
        or isinstance(source_count, bool)
        or not 2 <= source_count <= MAX_NATIVE_ROW_COMPONENTS
        or provenance.get("source_pattern_count") != source_count
        or source_map != [0] * source_count
        or provenance.get("row_total_object_bytes") is not None
        or provenance.get("uniform_capture") is not None
        or provenance.get("components") != []
    ):
        raise CensusError(f"{context} shared ordered-many topology differs")
    entry = provenance.get("entry_symbol")
    span_fill = provenance.get("span_fill_symbol")
    program = provenance.get("program_symbol")
    reducer = provenance.get("reducer_symbol")
    if not all(isinstance(value, str) for value in (entry, span_fill, program, reducer)):
        raise CensusError(f"{context} shared ordered-many symbols are malformed")
    entry_suffix = symbol_identity_suffix(
        entry,
        operation_entry_pattern if operation_only else NATIVE_SEARCH_ENTRY_SYMBOL,
        context,
    )
    program_suffix = symbol_identity_suffix(
        program, NATIVE_RUNTIME_PROGRAM_SYMBOL, context
    )
    reducer_suffix = symbol_identity_suffix(reducer, reducer_pattern, context)
    if operation_only:
        symbol_shape_is_exact = (
            span_fill == ""
            and entry_suffix == program_suffix
            and ((entry != reducer) == capture)
            and (
                (capture and reducer_suffix != entry_suffix)
                or (not capture and reducer_suffix == entry_suffix)
            )
        )
    elif native_fused and provenance.get("prepared_bulk_strategy") == "None":
        symbol_shape_is_exact = span_fill == ""
    else:
        span_fill_suffix = symbol_identity_suffix(
            span_fill, NATIVE_SPAN_FILL_ENTRY_SYMBOL, context
        )
        symbol_shape_is_exact = (
            len({entry_suffix, span_fill_suffix, program_suffix}) == 1
            and (native_fused or reducer_suffix != entry_suffix)
        )
    for field in ("ordered_sources_sha256", "artifact_identity_sha256", "reducer_identity_sha256"):
        value = proof.get(field)
        if not isinstance(value, str):
            raise CensusError(f"{context} {field} is malformed")
        require_hex64(value, f"{context} {field}")
    runtime_program_len = proof.get("runtime_program_len")
    expected_capabilities = 0 if native_fused else PREPARED_V15_CAPABILITY
    expected_config = (
        PREPARED_V2_CONFIG_VERSION if native_fused else PREPARED_V15_CONFIG_VERSION
    )
    expected_handle = 0 if native_fused else PREPARED_V15_MAX_HANDLE_BYTES
    expected_scratch = 0 if native_fused else PREPARED_V15_MAX_SCRATCH_BYTES
    expected_setup = 0 if native_fused else PREPARED_V15_MAX_SETUP_WORK
    if (
        proof.get("receipt_schema_version") != ORDERED_MANY_RECEIPT_VERSION
        or proof.get("required_prepare_capabilities") != expected_capabilities
        or proof.get("prepare_config_version") != expected_config
        or proof.get("prepare_operation_flags") != operation_flags
        or proof.get("max_handle_bytes") != expected_handle
        or proof.get("max_scratch_bytes") != expected_scratch
        or proof.get("max_setup_work") != expected_setup
        or proof.get("ordered_sources_sha256") == "0" * 64
        or not isinstance(runtime_program_len, int)
        or isinstance(runtime_program_len, bool)
        or not 1 <= runtime_program_len <= MAX_SERIALIZED_PROGRAM_BYTES
        or proof.get("artifact_identity_sha256") != entry_suffix
        or proof.get("reducer_identity_sha256") != reducer_suffix
        or not symbol_shape_is_exact
    ):
        raise CensusError(f"{context} shared ordered-many proof differs")
    return variant


def validate_normalized_regex_redux(
    proof: object, provenance: dict[str, object], context: str
) -> None:
    if not isinstance(proof, dict):
        raise CensusError(f"{context} proof is not an object")
    require_exact_keys(proof, {
        "abi_version", "operation_identity_sha256", "reducer_symbol",
        "reducer_code_sha256", "reducer_data_sha256", "reducer_object_sha256",
        "reducer_relocation_count", "reducer_link_symbols",
        "semantic_runtime_symbols", "request_bytes", "receipt_bytes", "report_bytes",
        "scratch_buffer_count", "scratch_capacity_numerator",
        "scratch_capacity_denominator", "receipt_schema", "report_schema",
    }, f"{context} proof")
    components = provenance.get("components")
    if not isinstance(components, list) or len(components) != 15:
        raise CensusError(f"{context} component cardinality differs")
    entries = [component.get("entry_symbol") for component in components]
    if (
        not all(
            isinstance(entry, str) and NATIVE_SEARCH_ENTRY_SYMBOL.fullmatch(entry)
            for entry in entries
        )
        or len(entries) != len(set(entries))
        or proof["reducer_link_symbols"] != entries
        or proof["semantic_runtime_symbols"] != []
    ):
        raise CensusError(f"{context} component link closure differs")
    for name in (
        "operation_identity_sha256", "reducer_code_sha256",
        "reducer_data_sha256", "reducer_object_sha256",
    ):
        require_hex64(proof[name], f"{context} {name}")
        if proof[name] == "0" * 64:
            raise CensusError(f"{context} {name} is zero")
    reducer = proof["reducer_symbol"]
    if (
        not isinstance(reducer, str)
        or NATIVE_REGEX_REDUX_ENTRY_SYMBOL.fullmatch(reducer) is None
        or reducer.rsplit("_", 1)[-1] != proof["operation_identity_sha256"]
        or provenance.get("reducer_symbol") != reducer
        or provenance.get("object_sha256") != proof["reducer_object_sha256"]
    ):
        raise CensusError(f"{context} reducer identity differs")
    exact = {
        "abi_version": 1, "request_bytes": 72, "receipt_bytes": 144,
        "report_bytes": 1024, "scratch_buffer_count": 2,
        "scratch_capacity_numerator": 3, "scratch_capacity_denominator": 2,
    }
    if any(proof.get(name) != expected for name, expected in exact.items()):
        raise CensusError(f"{context} ABI or workspace schema differs")
    expected_relocations = 16 if str(provenance.get("target", "")).startswith(
        "x86_64-"
    ) else 17 if str(provenance.get("target", "")).startswith("aarch64-") else 0
    if (
        expected_relocations == 0
        or proof["reducer_relocation_count"] != expected_relocations
    ):
        raise CensusError(f"{context} relocation closure differs")
    if (
        proof["receipt_schema"]
        != "u64-input-clean-variant9-substitution5-final-report-v1"
        or proof["report_schema"]
        != "variant9-blank-input-clean-final-lines-v1"
    ):
        raise CensusError(f"{context} execution schema differs")


def validate_normalized_weighted_capture_reducer(
    proof: object, provenance: dict[str, object], context: str
) -> None:
    """Reauthenticate a normalized v6 weighted reducer and every child edge."""
    if not isinstance(proof, dict):
        raise CensusError(f"{context} weighted reducer proof is not an object")
    require_exact_keys(proof, {
        "receipt_schema", "pattern_bytes", "component_first_source_ordinals",
        "component_weights", "source_participating_user_captures",
        "line_terminator", "operation", "domain", "ordered_sources_sha256",
        "operation_identity_sha256", "reducer_symbol", "reducer_symbol_sha256",
        "reducer_code_sha256", "reducer_object_sha256", "reducer_object_bytes",
        "reducer_object_cap", "artifact_identity_sha256", "external_relocations",
    }, f"{context} weighted reducer proof")
    components = provenance.get("components")
    source_map = provenance.get("source_to_artifact")
    source_count = provenance.get("source_pattern_count")
    row_object_bytes = provenance.get("row_total_object_bytes")
    if (
        not isinstance(components, list) or not components
        or not isinstance(source_count, int) or isinstance(source_count, bool)
        or not 2 <= source_count <= MAX_NATIVE_ROW_COMPONENTS
        or not isinstance(source_map, list) or len(source_map) != source_count
        or any(
            not isinstance(component, int) or isinstance(component, bool)
            or not 0 <= component < len(components)
            for component in source_map
        )
        or set(source_map) != set(range(len(components)))
        or not isinstance(row_object_bytes, int) or isinstance(row_object_bytes, bool)
        or not 0 < row_object_bytes <= MAX_NATIVE_ROW_OBJECT_BYTES
    ):
        raise CensusError(f"{context} weighted reducer topology differs")
    first_ordinals = [source_map.index(index) for index in range(len(components))]
    if (
        proof["receipt_schema"] != 1
        or proof["line_terminator"] != 10
        or proof["component_first_source_ordinals"] != first_ordinals
        or first_ordinals != sorted(first_ordinals)
    ):
        raise CensusError(f"{context} weighted reducer priority closure differs")
    validate_normalized_uniform_capture(
        provenance.get("uniform_capture"), components, source_count, source_map,
        context,
    )
    uniform = provenance["uniform_capture"]
    user_captures = proof["source_participating_user_captures"]
    weights = proof["component_weights"]
    if (
        not isinstance(user_captures, list) or len(user_captures) != source_count
        or any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in user_captures
        )
        or not isinstance(weights, list) or len(weights) != len(components)
        or any(
            not isinstance(value, int) or isinstance(value, bool) or value <= 0
            for value in weights
        )
        or any(
            uniform["source_participating_groups"][source]
            != user_captures[source] + 1
            or user_captures[source] > uniform["source_capture_annotations"][source]
            for source in range(source_count)
        )
        or len(set(uniform["source_participating_groups"])) == 1
        or weights != [
            uniform["source_participating_groups"][source]
            for source in first_ordinals
        ]
        or uniform["capture_proof_algorithm_version"] != 1
        or uniform["capture_proof_accounting_version"] != 1
        or any(value > 8_000_000 for value in uniform["source_proof_work"])
        or any(value > 1_000_000 for value in uniform["source_proof_peak_stack_items"])
    ):
        raise CensusError(f"{context} weighted reducer proof cardinality differs")
    entries = [component.get("entry_symbol") for component in components]
    if (
        len(entries) != len(set(entries))
        or any(
            not isinstance(entry, str)
            or NATIVE_SEARCH_ENTRY_SYMBOL.fullmatch(entry) is None
            for entry in entries
        )
        or any(component.get("required_runtime_symbols") for component in components)
    ):
        raise CensusError(f"{context} weighted reducer child symbol closure differs")
    engine = provenance.get("engine")
    engine_names = (
        engine[len("IndependentNativeSpanRows("):-1].split(",")
        if isinstance(engine, str)
        and engine.startswith("IndependentNativeSpanRows(") and engine.endswith(")")
        else []
    )
    if (
        len(engine_names) != len(components)
        or any(name not in {"OrderedDfa", "OrderedContextDfa"} for name in engine_names)
    ):
        raise CensusError(f"{context} weighted reducer child engines differ")

    operation_contract = {
        "count-captures": (
            1, 1, "general-aot-native-weighted-capture-count-reducer-v1",
            NATIVE_WEIGHTED_CAPTURE_COUNT_REDUCER_SYMBOL,
        ),
        "grep-captures": (
            2, 2, "general-aot-native-weighted-capture-grep-reducer-v1",
            NATIVE_WEIGHTED_CAPTURE_GREP_REDUCER_SYMBOL,
        ),
    }.get(provenance.get("model"))
    if operation_contract is None:
        raise CensusError(f"{context} weighted reducer model differs")
    operation, domain, adapter, reducer_pattern = operation_contract
    scalar_fields = (
        "prepared_bulk_strategy", "span_iteration_strategy", "grep_iteration_strategy",
        "program_sha256", "program_symbol", "entry_symbol", "span_fill_symbol",
    )
    if (
        provenance.get("schema") != "fre.aot.rebar-runner.v6"
        or provenance.get("kind") != "weighted-capture-reducer-v6"
        or provenance.get("composite_kind")
        != "weighted-capture-whole-operation-reducer-v1"
        or provenance.get("adapter") != adapter
        or provenance.get("aggregate_strategy")
        != "native-weighted-capture-row-reducer-v1"
        or provenance.get("boundary")
        != "single-call-helper-free-native-multi-component-weighted-row-reducer"
        or provenance.get("shared_ordered_many") is not None
        or provenance.get("required_runtime_symbols") != []
        or any(provenance.get(field) is not None for field in scalar_fields)
        or proof["operation"] != operation or proof["domain"] != domain
    ):
        raise CensusError(f"{context} weighted reducer route differs")
    pattern_bytes = proof["pattern_bytes"]
    reducer_object_bytes = proof["reducer_object_bytes"]
    reducer_object_cap = proof["reducer_object_cap"]
    if (
        not isinstance(pattern_bytes, int) or isinstance(pattern_bytes, bool)
        or not 0 < pattern_bytes <= MAX_PUBLIC_KLV_BYTES
        or not isinstance(reducer_object_bytes, int)
        or isinstance(reducer_object_bytes, bool)
        or not 0 < reducer_object_bytes <= MAX_WEIGHTED_CAPTURE_REDUCER_OBJECT_BYTES
        or reducer_object_cap != MAX_WEIGHTED_CAPTURE_REDUCER_OBJECT_BYTES
    ):
        raise CensusError(f"{context} weighted reducer resource receipt differs")
    digest_fields = (
        "ordered_sources_sha256", "operation_identity_sha256",
        "reducer_symbol_sha256", "reducer_code_sha256", "reducer_object_sha256",
        "artifact_identity_sha256",
    )
    for field in digest_fields:
        require_nonzero_hex64(proof[field], f"{context} weighted reducer {field}")
    reducer = proof["reducer_symbol"]
    if (
        not isinstance(reducer, str) or reducer_pattern.fullmatch(reducer) is None
        or reducer.rsplit("_", 1)[-1] != proof["operation_identity_sha256"]
        or proof["reducer_symbol_sha256"] != sha_bytes(reducer.encode("ascii", "strict"))
        or provenance.get("reducer_symbol") != reducer
        or provenance.get("object_sha256") != proof["reducer_object_sha256"]
    ):
        raise CensusError(f"{context} weighted reducer identity closure differs")
    relocations = proof["external_relocations"]
    architecture = target_architecture(str(provenance.get("target")))
    expected_kind, expected_addend = (2, -4) if architecture == "x86_64" else (5, 0)
    if not isinstance(relocations, list) or len(relocations) != len(components):
        raise CensusError(f"{context} weighted reducer relocation count differs")
    for index, relocation in enumerate(relocations):
        if not isinstance(relocation, dict):
            raise CensusError(f"{context} weighted reducer relocation {index} is not an object")
        require_exact_keys(
            relocation, {"component", "offset", "kind", "addend"},
            f"{context} weighted reducer relocation {index}",
        )
        if (
            relocation["component"] != index
            or not isinstance(relocation["offset"], int)
            or isinstance(relocation["offset"], bool)
            or not 0 <= relocation["offset"] < reducer_object_bytes
            or relocation["kind"] != expected_kind
            or relocation["addend"] != expected_addend
            or (index and relocation["offset"] <= relocations[index - 1]["offset"])
        ):
            raise CensusError(f"{context} weighted reducer relocation {index} differs")
    identity_fields = {
        "target": str(provenance["target"]),
        "feature_bits": str(provenance["feature_bits"]),
        "operation": str(operation), "domain": str(domain),
        "pattern_bytes": str(pattern_bytes),
        "ordered_sources_sha256": str(proof["ordered_sources_sha256"]),
        "line_terminator": "10",
    }
    operation_identity = weighted_capture_operation_identity(
        identity_fields, components, source_map, first_ordinals, weights, uniform,
        user_captures,
    )
    artifact_identity = weighted_capture_artifact_identity(
        operation_identity, reducer, proof["reducer_code_sha256"],
        proof["reducer_object_sha256"], reducer_object_bytes, reducer_object_cap,
        relocations,
    )
    if (
        operation_identity != proof["operation_identity_sha256"]
        or artifact_identity != proof["artifact_identity_sha256"]
    ):
        raise CensusError(f"{context} weighted reducer digest does not recompute")


def validate_normalized_single_capture_reducer(
    proof: object, provenance: dict[str, object], context: str
) -> None:
    """Reauthenticate a normalized v5 reducer without trusting raw parsing."""
    if not isinstance(proof, dict):
        raise CensusError(f"{context} single-capture reducer proof is not an object")
    common_keys = {
        "operation", "domain", "source_route", "source_cardinality", "source_bytes",
        "source_pattern_sha256", "source_sha256", "group_count",
        "can_match_empty", "empty_progress",
        "semantic_runtime_calls", "caller_scratch_bytes",
        "private_participation_scratch_bytes",
        "private_iterator_state_bytes", "private_result_slot_count",
        "private_result_slot_bytes", "selector_sha256", "capture_sha256",
        "source_artifact_identity_sha256", "source_object_sha256", "reducer_symbol",
        "reducer_symbol_sha256", "object_sha256", "object_bytes",
        "max_object_bytes", "artifact_identity_sha256", "participation_source",
        "capture_next_source",
    }
    require_exact_keys(proof, common_keys, f"{context} single-capture reducer proof")
    operation_contract = {
        "count-captures": (
            "count-captures", "whole-haystack",
            NATIVE_SINGLE_CAPTURE_COUNT_REDUCER_SYMBOL,
            NATIVE_SINGLE_CAPTURE_COUNT_SCRATCH_REDUCER_SYMBOL,
        ),
        "grep-captures": (
            "grep-captures", "byte-slice-lines-lf-crlf",
            NATIVE_SINGLE_CAPTURE_GREP_REDUCER_SYMBOL,
            NATIVE_SINGLE_CAPTURE_GREP_SCRATCH_REDUCER_SYMBOL,
        ),
    }.get(provenance.get("model"))
    if operation_contract is None:
        raise CensusError(f"{context} single-capture reducer model differs")
    operation, domain, legacy_reducer_pattern, scratch_reducer_pattern = (
        operation_contract
    )
    route = proof["source_route"]
    if route not in {"exact-span-participation-v1", "capture-next-v1"}:
        raise CensusError(f"{context} single-capture reducer source route differs")
    participation_child = (
        proof["participation_source"]
        if route == "exact-span-participation-v1" else None
    )
    ordered_participation = (
        isinstance(participation_child, dict)
        and participation_child.get("strategy") in {4, 5}
    )
    reducer_pattern = (
        scratch_reducer_pattern
        if ordered_participation else legacy_reducer_pattern
    )
    group_maximum = (
        NATIVE_PARTICIPATION_MAX_ASSERTIONS
        if route == "exact-span-participation-v1"
        else NATIVE_CAPTURE_MAX_GROUPS
    )
    integer_ranges = {
        "source_cardinality": (1, 1),
        "source_bytes": (0, (1 << 64) - 1),
        "group_count": (1, group_maximum),
        "semantic_runtime_calls": (0, 0),
        "caller_scratch_bytes": (
            0, NATIVE_PARTICIPATION_MAX_ORDERED_NFA_SCRATCH_BYTES
        ),
        "private_participation_scratch_bytes": (0, NATIVE_PARTICIPATION_SCRATCH_BYTES),
        "private_iterator_state_bytes": (0, NATIVE_CAPTURE_ITERATOR_STATE_BYTES),
        "private_result_slot_count": (0, NATIVE_CAPTURE_MAX_GROUPS),
        "private_result_slot_bytes": (
            0, NATIVE_CAPTURE_MAX_GROUPS * NATIVE_CAPTURE_RESULT_SLOT_BYTES
        ),
        "object_bytes": (1, MAX_NATIVE_ROW_OBJECT_BYTES),
        "max_object_bytes": (MAX_NATIVE_ROW_OBJECT_BYTES, MAX_NATIVE_ROW_OBJECT_BYTES),
    }
    for field, (minimum, maximum) in integer_ranges.items():
        value = proof[field]
        if (
            not isinstance(value, int) or isinstance(value, bool)
            or not minimum <= value <= maximum
        ):
            raise CensusError(f"{context} single-capture reducer {field} differs")
    expected_private = (
        (0, 0, 0, 0)
        if route == "exact-span-participation-v1" and ordered_participation
        else (NATIVE_PARTICIPATION_SCRATCH_BYTES, 0, 0, 0)
        if route == "exact-span-participation-v1" else (
            0, NATIVE_CAPTURE_ITERATOR_STATE_BYTES, proof["group_count"],
            proof["group_count"] * NATIVE_CAPTURE_RESULT_SLOT_BYTES,
        )
    )
    if (
        proof["private_participation_scratch_bytes"],
        proof["private_iterator_state_bytes"],
        proof["private_result_slot_count"],
        proof["private_result_slot_bytes"],
    ) != expected_private:
        raise CensusError(
            f"{context} single-capture reducer private schema differs from source route"
        )
    if not ordered_participation and proof["caller_scratch_bytes"] != 0:
        raise CensusError(
            f"{context} legacy single-capture reducer unexpectedly requires "
            "caller scratch"
        )
    if (
        proof["operation"] != operation
        or proof["domain"] != domain
        or proof["empty_progress"] != "byte"
        or not isinstance(proof["can_match_empty"], bool)
        or proof["object_bytes"] > proof["max_object_bytes"]
    ):
        raise CensusError(f"{context} single-capture reducer operation receipt differs")
    digest_fields = (
        "source_pattern_sha256", "source_sha256", "selector_sha256",
        "capture_sha256",
        "source_artifact_identity_sha256", "source_object_sha256",
        "reducer_symbol_sha256", "object_sha256", "artifact_identity_sha256",
    )
    for field in digest_fields:
        require_nonzero_hex64(proof[field], f"{context} single-capture reducer {field}")
    reducer = proof["reducer_symbol"]
    if (
        not isinstance(reducer, str)
        or reducer_pattern.fullmatch(reducer) is None
        or proof["reducer_symbol_sha256"]
        != sha_bytes(reducer.encode("ascii", "strict"))
        or proof["source_pattern_sha256"] == proof["source_sha256"]
        or proof["source_object_sha256"] == proof["object_sha256"]
        or proof["source_artifact_identity_sha256"]
        == proof["artifact_identity_sha256"]
    ):
        raise CensusError(f"{context} single-capture reducer identity closure differs")

    expected_adapter = {
        ("count-captures", "exact-span-participation-v1"):
            "general-aot-native-exact-span-participation-count-reducer-v1",
        ("grep-captures", "exact-span-participation-v1"):
            "general-aot-native-exact-span-participation-grep-reducer-v1",
        ("count-captures", "capture-next-v1"):
            "general-aot-native-single-capture-next-count-reducer-v1",
        ("grep-captures", "capture-next-v1"):
            "general-aot-native-single-capture-next-grep-reducer-v1",
    }[(provenance["model"], route)]
    if ordered_participation:
        expected_adapter = {
            "count-captures": (
                "general-aot-native-exact-span-ordered-nfa-participation-"
                "count-reducer-v1"
            ),
            "grep-captures": (
                "general-aot-native-exact-span-ordered-nfa-participation-"
                "grep-reducer-v1"
            ),
        }[provenance["model"]]
    expected_engine, expected_strategy = {
        "exact-span-participation-v1": (
            "NativeExactSpanParticipationDfaV1",
            "native-exact-span-participation-whole-operation-reducer-v1",
        ),
        "capture-next-v1": (
            "NativeOnePassCaptureV1",
            "native-single-capture-next-whole-operation-reducer-v1",
        ),
    }[route]
    if ordered_participation:
        expected_engine = "NativeExactSpanParticipationOrderedNfaV1"
        expected_strategy = (
            "native-exact-span-participation-ordered-nfa-whole-operation-"
            "reducer-v1"
        )
    if (
        provenance.get("schema") != "fre.aot.rebar-runner.v5"
        or provenance.get("kind") != "single-capture-reducer-v5"
        or provenance.get("composite_kind")
        != "single-capture-whole-operation-reducer-v1"
        or provenance.get("adapter") != expected_adapter
        or provenance.get("boundary")
        != "single-call-helper-free-single-capture-whole-operation-reducer"
        or provenance.get("engine") != expected_engine
        or provenance.get("aggregate_strategy") != expected_strategy
        or provenance.get("source_pattern_count") != 1
        or provenance.get("source_to_artifact") != []
        or provenance.get("row_total_object_bytes") is not None
        or provenance.get("uniform_capture") is not None
        or provenance.get("shared_ordered_many") is not None
        or provenance.get("components") != []
        or provenance.get("required_runtime_symbols") != []
        or provenance.get("program_sha256") is not None
        or provenance.get("program_symbol") is not None
        or provenance.get("entry_symbol") is not None
        or provenance.get("span_fill_symbol") is not None
        or provenance.get("object_sha256") != proof["object_sha256"]
        or provenance.get("reducer_symbol") != reducer
    ):
        raise CensusError(f"{context} single-capture reducer topology differs")
    if any(
        provenance.get(field) is not None
        for field in (
            "prepared_bulk_strategy", "span_iteration_strategy",
            "grep_iteration_strategy",
        )
    ):
        raise CensusError(f"{context} single-capture reducer retains scalar state")

    if route == "exact-span-participation-v1":
        child = participation_child
        if not isinstance(child, dict) or proof["capture_next_source"] is not None:
            raise CensusError(f"{context} participation source proof topology differs")
        numeric_ranges = {
            "strategy": (4, 5) if ordered_participation else (1, 2),
            "assertions": (0, NATIVE_PARTICIPATION_MAX_ASSERTIONS),
            "assertion_signatures": (
                (0, 0) if ordered_participation else
                (1, NATIVE_PARTICIPATION_MAX_ASSERTION_SIGNATURES)
            ),
            "byte_classes": (
                (0, 0) if ordered_participation else
                (1, NATIVE_PARTICIPATION_MAX_BYTE_CLASSES)
            ),
            "dfa_states": (
                (0, 0) if ordered_participation else
                (1, NATIVE_PARTICIPATION_MAX_DFA_STATES)
            ),
            "transition_cells": (
                (0, 0) if ordered_participation else
                (1, NATIVE_PARTICIPATION_MAX_TRANSITION_CELLS)
            ),
            "ordered_nfa_states": (
                (1, NATIVE_PARTICIPATION_MAX_PLAN_BYTES)
                if ordered_participation else (0, 0)
            ),
            "ordered_nfa_byte_ranges": (
                (0, NATIVE_PARTICIPATION_MAX_PLAN_BYTES)
                if ordered_participation else (0, 0)
            ),
            "dfa_fallback_resource": (
                (1, 2) if ordered_participation else (0, 0)
            ),
            "dfa_fallback_required": (
                (1, (1 << 32) - 1) if ordered_participation else (0, 0)
            ),
            "dfa_fallback_limit": (
                (0, (1 << 32) - 1) if ordered_participation else (0, 0)
            ),
            "build_work": (1, NATIVE_PARTICIPATION_MAX_BUILD_WORK),
            "scratch_bytes": (
                (1, NATIVE_PARTICIPATION_MAX_ORDERED_NFA_SCRATCH_BYTES)
                if ordered_participation else
                (NATIVE_PARTICIPATION_SCRATCH_BYTES,
                 NATIVE_PARTICIPATION_SCRATCH_BYTES)
            ),
            "plan_bytes": (
                NATIVE_PARTICIPATION_HEADER_BYTES, NATIVE_PARTICIPATION_MAX_PLAN_BYTES
            ),
        }
        child_keys = {
            "algorithm_id", *numeric_ranges, "selector_object_sha256", "bundle_sha256",
            "export_identity_sha256", "bundle_symbol", "selector_symbol", "entry_symbol",
        }
        require_exact_keys(child, child_keys, f"{context} participation source proof")
        for field, (minimum, maximum) in numeric_ranges.items():
            value = child[field]
            if (
                not isinstance(value, int) or isinstance(value, bool)
                or not minimum <= value <= maximum
            ):
                raise CensusError(f"{context} participation source {field} differs")
        expected_strategy_number = {"x86_64": 1, "aarch64": 2}[
            target_architecture(str(provenance.get("target", "")))
        ]
        if ordered_participation:
            expected_strategy_number = {"x86_64": 4, "aarch64": 5}[
                target_architecture(str(provenance.get("target", "")))
            ]
        expected_algorithm = (
            NATIVE_PARTICIPATION_ORDERED_NFA_ALGORITHM_ID
            if ordered_participation else NATIVE_PARTICIPATION_ALGORITHM_ID
        )
        if ordered_participation:
            states_offset = (
                NATIVE_PARTICIPATION_HEADER_BYTES
                + NATIVE_PARTICIPATION_ORDERED_NFA_METADATA_BYTES + 7
            ) & ~7
            ranges_offset = (
                states_offset
                + child["ordered_nfa_states"]
                * NATIVE_PARTICIPATION_ORDERED_NFA_STATE_BYTES
                + 7
            ) & ~7
            expected_plan_bytes = (
                ranges_offset
                + child["ordered_nfa_byte_ranges"]
                * NATIVE_PARTICIPATION_ORDERED_NFA_RANGE_BYTES
            )
            expected_scratch_bytes = (
                child["ordered_nfa_states"]
                * (
                    3 * NATIVE_PARTICIPATION_ORDERED_NFA_THREAD_BYTES
                    + NATIVE_PARTICIPATION_ORDERED_NFA_SEEN_BYTES
                )
                + 7
            ) & ~7
        else:
            expected_plan_bytes = participation_plan_bytes(
                child["assertions"], child["assertion_signatures"],
                child["dfa_states"], child["transition_cells"],
            )
            expected_scratch_bytes = NATIVE_PARTICIPATION_SCRATCH_BYTES
        if (
            child["algorithm_id"] != expected_algorithm
            or child["strategy"] != expected_strategy_number
            or (
                not ordered_participation
                and child["transition_cells"]
                != child["dfa_states"] * child["byte_classes"]
                * child["assertion_signatures"]
            )
            or (
                ordered_participation
                and child["dfa_fallback_required"]
                != child["dfa_fallback_limit"] + 1
            )
            or child["plan_bytes"] != expected_plan_bytes
            or child["scratch_bytes"] != expected_scratch_bytes
            or (
                ordered_participation
                and proof["caller_scratch_bytes"] != child["scratch_bytes"]
            )
        ):
            raise CensusError(f"{context} participation source geometry differs")
        for field in (
            "selector_object_sha256", "bundle_sha256", "export_identity_sha256"
        ):
            require_nonzero_hex64(child[field], f"{context} participation source {field}")
        bundle = child["bundle_symbol"]
        selector = child["selector_symbol"]
        entry = child["entry_symbol"]
        export_identity = child["export_identity_sha256"]
        feature_bits = provenance.get("feature_bits")
        if (
            not isinstance(bundle, str)
            or NATIVE_PARTICIPATION_BUNDLE_SYMBOL.fullmatch(bundle) is None
            or not isinstance(selector, str)
            or NATIVE_SEARCH_ENTRY_SYMBOL.fullmatch(selector) is None
            or not isinstance(entry, str)
            or NATIVE_PARTICIPATION_ENTRY_SYMBOL.fullmatch(entry) is None
            or len({reducer, bundle, selector, entry}) != 4
            or not bundle.endswith(export_identity)
            or not entry.endswith(export_identity)
            or not isinstance(feature_bits, str)
            or export_identity != participation_export_identity(
                child["bundle_sha256"], str(provenance.get("target", "")),
                feature_bits, child["selector_object_sha256"], selector,
            )
        ):
            raise CensusError(f"{context} participation source identity closure differs")
    else:
        child = proof["capture_next_source"]
        if not isinstance(child, dict) or proof["participation_source"] is not None:
            raise CensusError(f"{context} CaptureNext source proof topology differs")
        require_exact_keys(child, {
            "plan_sha256", "bundle_sha256", "next_symbol", "materialize_symbol",
            "selector_symbol",
        }, f"{context} CaptureNext source proof")
        require_nonzero_hex64(child["plan_sha256"], f"{context} CaptureNext plan")
        require_nonzero_hex64(child["bundle_sha256"], f"{context} CaptureNext bundle")
        next_symbol = child["next_symbol"]
        materialize = child["materialize_symbol"]
        selector = child["selector_symbol"]
        if (
            not isinstance(next_symbol, str)
            or NATIVE_CAPTURE_NEXT_ENTRY_SYMBOL.fullmatch(next_symbol) is None
            or not isinstance(materialize, str)
            or NATIVE_CAPTURE_MATERIALIZE_SYMBOL.fullmatch(materialize) is None
            or not isinstance(selector, str)
            or NATIVE_SEARCH_ENTRY_SYMBOL.fullmatch(selector) is None
            or len({reducer, next_symbol, materialize, selector}) != 4
        ):
            raise CensusError(f"{context} CaptureNext source identity closure differs")


def validate_normalized_frozen_validation(validation: object, context: str) -> None:
    if not isinstance(validation, dict):
        raise CensusError(f"{context} is not an object")
    require_exact_keys(validation, {
        "authority", "expected_value", "expected_comparator",
        "schedule_klv_sha256", "schedule_binding_sha256", "stock_comparator",
        "stock_divergence_policy",
    }, context)
    expected_value = validation["expected_value"]
    expected_comparator = validation["expected_comparator"]
    if validation["authority"] != "frozen-public-schedule-v1":
        raise CensusError(f"{context} authority differs")
    if (
        not isinstance(expected_value, int)
        or isinstance(expected_value, bool)
        or not 0 <= expected_value <= (1 << 64) - 1
    ):
        raise CensusError(f"{context} expected value is not u64")
    if (
        not isinstance(expected_comparator, str)
        or re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._/+:\-]{0,127}", expected_comparator
        ) is None
    ):
        raise CensusError(f"{context} expected comparator differs")
    for field in ("schedule_klv_sha256", "schedule_binding_sha256"):
        require_hex64(validation[field], f"{context} {field}")
        if validation[field] == "0" * 64:
            raise CensusError(f"{context} {field} is zero")
    if (
        validation["stock_comparator"] != "rust-regex-1.12.4"
        or validation["stock_divergence_policy"] != "report-only"
    ):
        raise CensusError(f"{context} stock diagnostic policy differs")


def validate_provenance_record(provenance: object, context: str) -> None:
    if not isinstance(provenance, dict):
        raise CensusError(f"{context} is not an object")
    expected_keys = {
        "schema", "adapter", "model", "benchmark", "source_commit", "source_tree",
        "target", "feature_bits", "kind", "composite_kind", "source_pattern_count",
        "source_to_artifact", "row_total_object_bytes", "boundary", "engine",
        "aggregate_strategy", "uniform_capture", "shared_ordered_many",
        "prepared_bulk_strategy", "span_iteration_strategy", "grep_iteration_strategy",
        "program_sha256", "object_sha256", "program_symbol", "entry_symbol",
        "reducer_symbol", "span_fill_symbol", "required_runtime_symbols", "components",
        "entry_abi", "validation",
    }
    if provenance.get("kind") == "strict-capture-v4":
        expected_keys.add("strict_capture")
    elif provenance.get("kind") == "participation-capture-v4":
        expected_keys.add("participation_capture")
    elif provenance.get("kind") == "single-capture-reducer-v5":
        expected_keys.add("capture_reducer")
    elif provenance.get("kind") == "weighted-capture-reducer-v6":
        expected_keys.add("weighted_capture_reducer")
    elif provenance.get("kind") == "selector-capture-fallback-v4":
        expected_keys.add("selector_capture_fallback")
    elif provenance.get("kind") == "prepared-grep-v15-v2":
        expected_keys.add("prepared_grep_v15")
    if provenance.get("kind") == "scalar-v2" and (
        provenance.get("model") == "count" or (
            provenance.get("model") == "count-spans"
            and provenance.get("span_iteration_strategy")
            == NATIVE_SPAN_SUM_ITERATION_STRATEGY
        )
    ):
        expected_keys.add("scalar_native_reducer")
    if provenance.get("composite_kind") == "regex-redux-fixed-v1":
        expected_keys.add("regex_redux")
    if provenance.get("composite_kind") == "native-multi-grep-reducer-v1":
        expected_keys.add("multi_grep_reducer")
        proof = provenance.get("multi_grep_reducer")
        if isinstance(proof, dict) and proof.get("mixed_handle_table") is True:
            expected_keys.add("prepared_v15_limits")
    if provenance.get("composite_kind") == "native-row-scalar-reducer-v1":
        expected_keys.add("row_scalar_reducer")
        proof = provenance.get("row_scalar_reducer")
        if isinstance(proof, dict) and proof.get("mixed_handle_table") is True:
            expected_keys.add("prepared_v15_limits")
    if provenance.get("composite_kind") == "mixed-prepared-native-row-bridge-v15":
        expected_keys.add("prepared_v15_limits")
    require_exact_keys(provenance, expected_keys, context)
    if provenance.get("schema") == "fre.aot.rebar-runner.v2":
        if provenance.get("entry_abi") not in {
            EXISTS_SEARCH_ENTRY_ABI, SPAN_SEARCH_ENTRY_ABI,
            PREPARED_SCALAR_REDUCE_ENTRY_ABI,
        }:
            raise CensusError(f"{context} scalar entry ABI differs")
        if provenance.get("entry_abi") == EXISTS_SEARCH_ENTRY_ABI and not (
            provenance.get("model") == "grep"
            and provenance.get("aggregate_strategy") == "Some(NativeFused)"
        ):
            raise CensusError(f"{context} Exists search ABI is attached to another route")
        if provenance.get("entry_abi") == PREPARED_SCALAR_REDUCE_ENTRY_ABI and not (
            provenance.get("aggregate_strategy") == "Some(NativeOrderedNfaFused)"
            and provenance.get("model") in {
                "count", "count-spans", "count-captures", "grep", "grep-captures",
            }
            and (
                provenance.get("kind") == "shared-ordered-many-v2"
                or provenance.get("model") == "count"
                or provenance.get("model") in UNIFORM_CAPTURE_ADAPTER_MODELS
                or provenance.get("span_iteration_strategy")
                == NATIVE_SPAN_SUM_ITERATION_STRATEGY
                or (
                    provenance.get("model") == "grep"
                    and provenance.get("kind") == "prepared-grep-v15-v2"
                )
            )
        ):
            raise CensusError(f"{context} reducer entry ABI is attached to another route")
    elif provenance.get("entry_abi") is not None:
        raise CensusError(f"{context} non-scalar provenance retains an entry ABI")
    validate_normalized_frozen_validation(
        provenance["validation"], f"{context} validation"
    )
    if not isinstance(provenance["components"], list):
        raise CensusError(f"{context} components are not a list")
    component_surface_presence = [
        "entry_abi" in component or "prepared_surface" in component
        for component in provenance["components"] if isinstance(component, dict)
    ]
    if component_surface_presence and any(component_surface_presence) and not all(
        component_surface_presence
    ):
        raise CensusError(f"{context} component ABI/surface receipts are partial")
    for index, component in enumerate(provenance["components"]):
        if not isinstance(component, dict):
            raise CensusError(f"{context} component {index} is not an object")
        component_keys = {
            "ordinal", "native", "source_ordinal", "entry_symbol",
            "required_runtime_symbols", "automaton_sha256",
            "program_sha256", "object_sha256",
        }
        if "entry_abi" in component or "prepared_surface" in component:
            component_keys.update({"entry_abi", "prepared_surface"})
        scalar_proof = provenance.get("row_scalar_reducer")
        multi_grep_proof = provenance.get("multi_grep_reducer")
        if (
            provenance.get("composite_kind") == "mixed-prepared-native-row-bridge-v15"
            or (
                provenance.get("composite_kind") == "native-row-scalar-reducer-v1"
                and isinstance(scalar_proof, dict)
                and scalar_proof.get("mixed_handle_table") is True
            )
            or (
                provenance.get("composite_kind") == "native-multi-grep-reducer-v1"
                and isinstance(multi_grep_proof, dict)
                and multi_grep_proof.get("mixed_handle_table") is True
            )
        ):
            component_keys.add("prepared_v15")
        require_exact_keys(component, component_keys, f"{context} component {index}")
        if component["ordinal"] != index or component["native"] is not True:
            raise CensusError(f"{context} component {index} identity is not canonical")
        source_ordinal = component["source_ordinal"]
        if source_ordinal is not None and (
            not isinstance(source_ordinal, int)
            or isinstance(source_ordinal, bool)
            or source_ordinal < 0
        ):
            raise CensusError(
                f"{context} component {index} source ordinal is not canonical"
            )
        require_hex64(component["program_sha256"], f"{context} component {index} program")
        require_hex64(component["object_sha256"], f"{context} component {index} object")
        if component["automaton_sha256"] is not None:
            require_hex64(
                component["automaton_sha256"],
                f"{context} component {index} automaton",
            )
        runtime_symbols = component["required_runtime_symbols"]
        if runtime_symbols != sorted(set(runtime_symbols)) or not all(
            isinstance(symbol, str) and SYMBOL.fullmatch(symbol) for symbol in runtime_symbols
        ):
            raise CensusError(f"{context} component {index} runtime symbols differ")
        if "entry_abi" in component:
            proof = component.get("prepared_v15")
            if proof is None:
                expected_pair = (SPAN_SEARCH_ENTRY_ABI, NO_PREPARED_SURFACE)
            elif isinstance(proof, dict):
                expected_pair = (
                    proof.get("entry_abi"), proof.get("prepared_surface")
                )
            else:
                raise CensusError(f"{context} component {index} prepared proof differs")
            if (
                component.get("entry_abi"), component.get("prepared_surface")
            ) != expected_pair:
                raise CensusError(f"{context} component {index} ABI/surface differs")
    required_runtime = provenance["required_runtime_symbols"]
    if required_runtime != sorted(set(required_runtime)) or not all(
        isinstance(symbol, str) and SYMBOL.fullmatch(symbol) for symbol in required_runtime
    ):
        raise CensusError(f"{context} runtime symbols are not canonical")
    if (
        provenance["kind"] != "shared-ordered-many-v2"
        and provenance["shared_ordered_many"] is not None
    ):
        raise CensusError(f"{context} non-shared route retains a shared proof")
    if provenance["kind"] in {"scalar-v2", "prepared-grep-v15-v2"}:
        if (
            provenance["schema"] != "fre.aot.rebar-runner.v2"
            or provenance["composite_kind"] is not None
            or provenance["source_pattern_count"] is not None
            or provenance["source_to_artifact"] != []
            or provenance["row_total_object_bytes"] is not None
            or (
                provenance["uniform_capture"] is not None
                and provenance["model"] not in UNIFORM_CAPTURE_ADAPTER_MODELS
            )
            or (
                provenance["uniform_capture"] is None
                and provenance["model"] in UNIFORM_CAPTURE_ADAPTER_MODELS
            )
            or provenance["components"] != []
        ):
            raise CensusError(f"{context} scalar/composite fields disagree")
        require_hex64(provenance["program_sha256"], f"{context} scalar program")
        require_hex64(provenance["object_sha256"], f"{context} scalar object")
        if provenance["kind"] == "prepared-grep-v15-v2":
            if (
                provenance["model"] != "grep"
                or provenance["adapter"]
                != "general-aot-linked-native-grep-count-reducer-prepared-v3-required-ordered-nfa-v15"
                or provenance["boundary"] != "runtime-klv-warmup-schedule"
                or provenance["engine"] != "OrderedNfa"
                or provenance["aggregate_strategy"]
                != "Some(NativeOrderedNfaFused)"
                or provenance["span_iteration_strategy"] != "not-applicable"
                or provenance["grep_iteration_strategy"]
                != "linked-native-grep-count-reducer-v1"
            ):
                raise CensusError(f"{context} scalar prepared V15 route differs")
            validate_normalized_prepared_grep_v15(
                provenance["prepared_grep_v15"], provenance, context
            )
        elif provenance["model"] == "count" or (
            provenance["model"] == "count-spans"
            and provenance["span_iteration_strategy"]
            == NATIVE_SPAN_SUM_ITERATION_STRATEGY
        ):
            validate_normalized_scalar_native_reducer(
                provenance["scalar_native_reducer"], provenance, context
            )
        elif provenance["model"] == "grep":
            entry_suffix = symbol_identity_suffix(
                provenance["entry_symbol"], NATIVE_SEARCH_ENTRY_SYMBOL, context
            )
            reducer_suffix = symbol_identity_suffix(
                provenance["reducer_symbol"], NATIVE_GREP_COUNT_ENTRY_SYMBOL, context
            )
            program_suffix = symbol_identity_suffix(
                provenance["program_symbol"], NATIVE_RUNTIME_PROGRAM_SYMBOL, context
            )
            if (
                provenance["adapter"]
                != "general-aot-linked-native-grep-count-reducer-prepared-v2"
                or provenance["entry_abi"] != EXISTS_SEARCH_ENTRY_ABI
                or provenance["boundary"] != "runtime-klv-warmup-schedule"
                or provenance["aggregate_strategy"] != "Some(NativeFused)"
                or provenance["prepared_bulk_strategy"] != "None"
                or provenance["span_iteration_strategy"] != "not-applicable"
                or provenance["grep_iteration_strategy"]
                != "linked-native-grep-count-reducer-v1"
                or provenance["span_fill_symbol"] != ""
                or provenance["required_runtime_symbols"] != []
                or reducer_suffix != program_suffix
                or reducer_suffix == entry_suffix
            ):
                raise CensusError(f"{context} scalar direct native grep route differs")
        elif provenance["model"] in UNIFORM_CAPTURE_ADAPTER_MODELS:
            validate_normalized_uniform_capture_reducer(
                provenance["uniform_capture"], provenance, context
            )
    elif provenance["kind"] == "shared-ordered-many-v2":
        require_hex64(provenance["program_sha256"], f"{context} shared program")
        require_hex64(provenance["object_sha256"], f"{context} shared object")
        validate_normalized_shared_ordered_many(
            provenance["shared_ordered_many"], provenance, context
        )
    elif provenance["kind"] == "composite-v3":
        if provenance["schema"] != "fre.aot.rebar-runner.v3" or not provenance["components"]:
            raise CensusError(f"{context} composite fields disagree")
        if provenance["composite_kind"] == "regex-redux-fixed-v1":
            if (
                provenance["model"] != "regex-redux"
                or provenance["adapter"] != "general-aot-native-regex-redux-reducer-v1"
                or provenance["boundary"] != "single-call-native-regex-redux-reducer"
                or provenance["engine"] != "NativeRegexReduxAotV1"
                or provenance["aggregate_strategy"]
                != "native-fixed-regex-redux-whole-operation-v1"
                or len(provenance["components"]) != 15
                or provenance["source_pattern_count"] != 0
                or provenance["source_to_artifact"] != []
                or provenance["row_total_object_bytes"] is not None
                or provenance["uniform_capture"] is not None
                or any(component["source_ordinal"] is not None for component in provenance["components"])
                or any(component["automaton_sha256"] is not None for component in provenance["components"])
                or provenance["program_sha256"] is not None
                or provenance["program_symbol"] is not None
                or provenance["entry_symbol"] is not None
                or provenance["span_fill_symbol"] is not None
                or provenance["prepared_bulk_strategy"] is not None
                or provenance["span_iteration_strategy"] is not None
                or provenance["grep_iteration_strategy"] is not None
                or provenance["required_runtime_symbols"] != []
            ):
                raise CensusError(f"{context} regex-redux topology is not canonical")
            validate_normalized_regex_redux(
                provenance["regex_redux"], provenance, context
            )
        elif provenance["composite_kind"] == "native-row-scalar-reducer-v1":
            components = provenance["components"]
            proof = validate_normalized_row_scalar_reducer(
                provenance["row_scalar_reducer"], provenance, context
            )
            mixed_handle_table = proof["mixed_handle_table"]
            expected_adapter = ({
                "count": (
                    "general-aot-native-row-count-mixed-prepared-"
                    "whole-operation-reducer-v1"
                ),
                "count-spans": (
                    "general-aot-native-row-span-sum-mixed-prepared-"
                    "whole-operation-reducer-v1"
                ),
            } if mixed_handle_table else {
                "count": "general-aot-native-row-count-whole-operation-reducer-v1",
                "count-spans": (
                    "general-aot-native-row-span-sum-whole-operation-reducer-v1"
                ),
            }).get(provenance["model"])
            expected_boundary = (
                "single-call-native-mixed-row-scalar-reducer"
                if mixed_handle_table else
                "single-call-helper-free-native-row-scalar-reducer"
            )
            expected_strategy = (
                "native-independent-mixed-span-row-whole-scalar-reducer-v1"
                if mixed_handle_table else
                "native-independent-span-row-whole-scalar-reducer-v1"
            )
            if (
                expected_adapter is None
                or provenance["adapter"] != expected_adapter
                or provenance["boundary"] != expected_boundary
                or provenance["aggregate_strategy"] != expected_strategy
                or provenance["uniform_capture"] is not None
                or provenance["required_runtime_symbols"] != []
                or provenance["program_sha256"] is not None
                or provenance["program_symbol"] is not None
                or provenance["entry_symbol"] is not None
                or provenance["span_fill_symbol"] is not None
                or provenance["prepared_bulk_strategy"] is not None
                or provenance["span_iteration_strategy"] is not None
                or provenance["grep_iteration_strategy"] is not None
                or any(
                    component["automaton_sha256"] is None
                    or not isinstance(component["entry_symbol"], str)
                    or (
                        component.get("prepared_v15") is None
                        and (
                            component["required_runtime_symbols"] != []
                            or NATIVE_SEARCH_ENTRY_SYMBOL.fullmatch(
                                component["entry_symbol"]
                            ) is None
                        )
                    )
                    or (
                        component.get("prepared_v15") is not None
                        and (
                            NATIVE_SEARCH_EXCLUSIVE_ENTRY_SYMBOL.fullmatch(
                                component["entry_symbol"]
                            ) is None
                        )
                    )
                    for component in components
                )
            ):
                raise CensusError(
                    f"{context} row-scalar reducer topology is not canonical"
                )
            validate_native_row_engine_routes(provenance, components)
            if mixed_handle_table:
                validate_normalized_prepared_v15_limits(
                    provenance["prepared_v15_limits"], context
                )
                for index, (component, route) in enumerate(
                    zip(components, proof["row_routes"])
                ):
                    if route in {1, 2}:
                        validate_normalized_prepared_v15_component(
                            component["prepared_v15"], component,
                            f"{context} component {index}",
                        )
            if (
                provenance["object_sha256"] != proof["object_sha256"]
                or provenance["reducer_symbol"] != proof["reducer_symbol"]
            ):
                raise CensusError(
                    f"{context} row-scalar reducer top-level identity differs"
                )
        elif provenance["composite_kind"] == "native-multi-grep-reducer-v1":
            components = provenance["components"]
            proof = validate_normalized_multi_grep_reducer(
                provenance["multi_grep_reducer"], provenance, context
            )
            mixed_handle_table = proof["mixed_handle_table"]
            expected_adapter = (
                "general-aot-native-mixed-prepared-ordered-nfa-v15-"
                "multi-grep-whole-operation-reducer-v1"
                if mixed_handle_table else
                "general-aot-native-multi-grep-whole-operation-reducer-v1"
            )
            expected_boundary = (
                "single-call-native-mixed-multi-grep-reducer"
                if mixed_handle_table else
                "single-call-helper-free-native-multi-grep-reducer"
            )
            expected_strategy = (
                "native-independent-mixed-prepared-span-row-whole-grep-reducer-v1"
                if mixed_handle_table else
                "native-independent-span-row-whole-grep-reducer-v1"
            )
            if (
                provenance["model"] != "grep"
                or provenance["adapter"] != expected_adapter
                or provenance["boundary"] != expected_boundary
                or provenance["aggregate_strategy"] != expected_strategy
                or provenance["uniform_capture"] is not None
                or provenance["required_runtime_symbols"] != []
                or provenance["program_sha256"] is not None
                or provenance["program_symbol"] is not None
                or provenance["entry_symbol"] is not None
                or provenance["span_fill_symbol"] is not None
                or provenance["prepared_bulk_strategy"] is not None
                or provenance["span_iteration_strategy"] is not None
                or provenance["grep_iteration_strategy"] is not None
                or any(
                    component["automaton_sha256"] is None
                    or not isinstance(component["entry_symbol"], str)
                    or (
                        route == 0
                        and (
                            component.get("prepared_v15") is not None
                            or component["required_runtime_symbols"] != []
                            or NATIVE_SEARCH_ENTRY_SYMBOL.fullmatch(
                                component["entry_symbol"]
                            ) is None
                        )
                    )
                    or (
                        route in {1, 2}
                        and (
                            component.get("prepared_v15") is None
                            or prepared_v15_component_route(component) != route
                            or NATIVE_SEARCH_EXCLUSIVE_ENTRY_SYMBOL.fullmatch(
                                component["entry_symbol"]
                            ) is None
                        )
                    )
                    for component, route in zip(components, proof["row_routes"])
                )
            ):
                raise CensusError(
                    f"{context} multi-Grep reducer topology is not canonical"
                )
            validate_native_row_engine_routes(provenance, components)
            if mixed_handle_table:
                validate_normalized_prepared_v15_limits(
                    provenance["prepared_v15_limits"], context
                )
                for index, (component, route) in enumerate(
                    zip(components, proof["row_routes"])
                ):
                    if route in {1, 2}:
                        validate_normalized_prepared_v15_component(
                            component["prepared_v15"], component,
                            f"{context} mixed multi-Grep component {index}",
                        )
            if (
                provenance["object_sha256"] != proof["object_sha256"]
                or provenance["reducer_symbol"] != proof["reducer_symbol"]
            ):
                raise CensusError(
                    f"{context} multi-Grep reducer top-level identity differs"
                )
        elif provenance["composite_kind"] == "native-row-bridge-v1":
            source_count = provenance["source_pattern_count"]
            source_map = provenance["source_to_artifact"]
            object_bytes = provenance["row_total_object_bytes"]
            expected_adapter = {
                "count": "general-aot-native-row-bridge-count-v1",
                "count-spans": "general-aot-native-row-bridge-count-spans-v1",
                "grep": "general-aot-native-row-bridge-grep-v1",
            }.get(provenance["model"])
            expected_strategy = (
                "per-line-native-independent-span-row-exists-v1"
                if provenance["model"] == "grep"
                else "native-independent-span-row-selector-v1"
            )
            if (
                expected_adapter is None
                or provenance["adapter"] != expected_adapter
                or provenance["boundary"] != "complete-native-row-bridge"
                or provenance["aggregate_strategy"] != expected_strategy
                or provenance["uniform_capture"] is not None
                or not isinstance(source_count, int)
                or isinstance(source_count, bool)
                or not 2 <= source_count <= MAX_NATIVE_ROW_COMPONENTS
                or not isinstance(source_map, list)
                or len(source_map) != source_count
                or not isinstance(object_bytes, int)
                or isinstance(object_bytes, bool)
                or not 0 < object_bytes <= MAX_NATIVE_ROW_OBJECT_BYTES
                or any(
                    not isinstance(artifact, int)
                    or isinstance(artifact, bool)
                    or artifact < 0
                    or artifact >= len(provenance["components"])
                    for artifact in source_map
                )
                or set(source_map) != set(range(len(provenance["components"])))
                or any(
                    component["automaton_sha256"] is None
                    for component in provenance["components"]
                )
            ):
                raise CensusError(f"{context} native-row topology is not canonical")
            first_sources = [
                source_map.index(index) for index in range(len(provenance["components"]))
            ]
            if first_sources != sorted(first_sources) or [
                component["source_ordinal"] for component in provenance["components"]
            ] != first_sources:
                raise CensusError(f"{context} native-row source priority is not canonical")
        elif provenance["composite_kind"] == "mixed-prepared-native-row-bridge-v15":
            source_count = provenance["source_pattern_count"]
            source_map = provenance["source_to_artifact"]
            object_bytes = provenance["row_total_object_bytes"]
            components = provenance["components"]
            expected_adapter = {
                "count": (
                    "general-aot-native-row-bridge-count-mixed-prepared-ordered-nfa-v15-v1"
                ),
                "count-spans": (
                    "general-aot-native-row-bridge-count-spans-mixed-prepared-ordered-nfa-v15-v1"
                ),
                "grep": (
                    "general-aot-native-row-bridge-grep-mixed-prepared-ordered-nfa-v15-v1"
                ),
            }.get(provenance["model"])
            expected_strategy = (
                "per-line-native-independent-span-row-exists-mixed-prepared-v15-v1"
                if provenance["model"] == "grep"
                else "native-independent-span-row-selector-mixed-prepared-v15-v1"
            )
            prepared_count = sum(
                component["prepared_v15"] is not None for component in components
            )
            if (
                expected_adapter is None
                or provenance["adapter"] != expected_adapter
                or provenance["boundary"] != "complete-native-row-bridge"
                or provenance["aggregate_strategy"] != expected_strategy
                or provenance["uniform_capture"] is not None
                or provenance["required_runtime_symbols"] != []
                or not isinstance(source_count, int)
                or isinstance(source_count, bool)
                or not 2 <= source_count <= MAX_NATIVE_ROW_COMPONENTS
                or not isinstance(source_map, list)
                or len(source_map) != source_count
                or not isinstance(object_bytes, int)
                or isinstance(object_bytes, bool)
                or not 0 < object_bytes <= MAX_NATIVE_ROW_OBJECT_BYTES
                or any(
                    not isinstance(artifact, int)
                    or isinstance(artifact, bool)
                    or artifact < 0
                    or artifact >= len(components)
                    for artifact in source_map
                )
                or set(source_map) != set(range(len(components)))
                or any(component["automaton_sha256"] is None for component in components)
                or not 0 < prepared_count <= len(components)
            ):
                raise CensusError(f"{context} mixed prepared V15 topology is not canonical")
            first_sources = [source_map.index(index) for index in range(len(components))]
            if first_sources != sorted(first_sources) or [
                component["source_ordinal"] for component in components
            ] != first_sources:
                raise CensusError(
                    f"{context} mixed prepared V15 source priority is not canonical"
                )
            validate_normalized_prepared_v15_limits(
                provenance["prepared_v15_limits"], context
            )
            validate_native_row_engine_routes(provenance, components)
            for index, component in enumerate(components):
                proof = component["prepared_v15"]
                if proof is None:
                    if (
                        component["required_runtime_symbols"] != []
                        or not isinstance(component["entry_symbol"], str)
                        or NATIVE_SEARCH_ENTRY_SYMBOL.fullmatch(
                            component["entry_symbol"]
                        ) is None
                    ):
                        raise CensusError(
                            f"{context} ordinary component {index} is not helper-free"
                        )
                else:
                    validate_normalized_prepared_v15_component(
                        proof, component, f"{context} component {index}"
                    )
        elif provenance["composite_kind"] == "uniform-capture-row-bridge-v1":
            source_count = provenance["source_pattern_count"]
            source_map = provenance["source_to_artifact"]
            object_bytes = provenance["row_total_object_bytes"]
            expected_adapter = {
                "count-captures": (
                    "general-aot-uniform-capture-native-row-count-adapter-loop-v1"
                ),
                "grep-captures": (
                    "general-aot-uniform-capture-native-row-grep-adapter-loop-v1"
                ),
            }.get(provenance["model"])
            if (
                expected_adapter is None
                or provenance["adapter"] != expected_adapter
                or provenance["boundary"]
                != "native-search-core-static-uniform-capture-resolution"
                or provenance["aggregate_strategy"]
                != "native-row-static-uniform-capture-multiplier-v1"
                or not isinstance(source_count, int)
                or isinstance(source_count, bool)
                or not 1 <= source_count <= MAX_NATIVE_ROW_COMPONENTS
                or not isinstance(source_map, list)
                or len(source_map) != source_count
                or not isinstance(object_bytes, int)
                or isinstance(object_bytes, bool)
                or not 0 < object_bytes <= MAX_NATIVE_ROW_OBJECT_BYTES
                or any(
                    not isinstance(artifact, int)
                    or isinstance(artifact, bool)
                    or artifact < 0
                    or artifact >= len(provenance["components"])
                    for artifact in source_map
                )
                or set(source_map) != set(range(len(provenance["components"])))
                or any(
                    component["automaton_sha256"] is None
                    for component in provenance["components"]
                )
            ):
                raise CensusError(f"{context} uniform-capture topology is not canonical")
            first_sources = [
                source_map.index(index) for index in range(len(provenance["components"]))
            ]
            if first_sources != sorted(first_sources) or [
                component["source_ordinal"] for component in provenance["components"]
            ] != first_sources:
                raise CensusError(
                    f"{context} uniform-capture source priority is not canonical"
                )
            validate_normalized_uniform_capture(
                provenance["uniform_capture"], provenance["components"],
                source_count, source_map, context,
            )
        else:
            raise CensusError(f"{context} has an unknown composite kind")
    elif provenance["kind"] == "weighted-capture-reducer-v6":
        validate_normalized_weighted_capture_reducer(
            provenance["weighted_capture_reducer"], provenance, context
        )
    elif provenance["kind"] == "single-capture-reducer-v5":
        validate_normalized_single_capture_reducer(
            provenance["capture_reducer"], provenance, context
        )
    elif provenance["kind"] == "strict-capture-v4":
        components = provenance["components"]
        component = components[0] if len(components) == 1 else None
        expected_adapter = {
            "count-captures": "general-aot-native-single-capture-next-count-v1",
            "grep-captures": "general-aot-native-single-capture-next-grep-v1",
        }.get(provenance["model"])
        scalar_fields = (
            "prepared_bulk_strategy", "span_iteration_strategy", "grep_iteration_strategy",
            "program_sha256", "object_sha256", "program_symbol", "entry_symbol",
            "reducer_symbol", "span_fill_symbol",
        )
        if (
            provenance["schema"] != "fre.aot.rebar-runner.v4"
            or provenance["composite_kind"] != "strict-capture-next-v1"
            or expected_adapter is None
            or provenance["adapter"] != expected_adapter
            or provenance["boundary"]
            != "native-search-core-with-native-capture-materialization-adapter-loop"
            or provenance["engine"] != "NativeOnePassCaptureV1"
            or provenance["aggregate_strategy"]
            != "native-single-capture-next-participation-v1"
            or provenance["source_pattern_count"] != 1
            or provenance["source_to_artifact"] != [0]
            or not isinstance(provenance["row_total_object_bytes"], int)
            or isinstance(provenance["row_total_object_bytes"], bool)
            or not 0 < provenance["row_total_object_bytes"] <= MAX_NATIVE_ROW_OBJECT_BYTES
            or provenance["uniform_capture"] is not None
            or provenance["required_runtime_symbols"] != []
            or any(provenance[field] is not None for field in scalar_fields)
            or component is None
            or component["source_ordinal"] != 0
            or component["automaton_sha256"] is not None
        ):
            raise CensusError(f"{context} strict-capture topology is not canonical")
        validate_normalized_strict_capture(
            provenance["strict_capture"], component, context
        )
    elif provenance["kind"] == "participation-capture-v4":
        components = provenance["components"]
        component = components[0] if len(components) == 1 else None
        expected_adapter = {
            "count-captures": (
                "general-aot-native-exact-span-participation-count-v1"
            ),
            "grep-captures": (
                "general-aot-native-exact-span-participation-grep-v1"
            ),
        }.get(provenance["model"])
        scalar_fields = (
            "prepared_bulk_strategy", "span_iteration_strategy", "grep_iteration_strategy",
            "program_sha256", "object_sha256", "program_symbol", "entry_symbol",
            "reducer_symbol", "span_fill_symbol",
        )
        if (
            provenance["schema"] != "fre.aot.rebar-runner.v4"
            or provenance["composite_kind"] != "exact-span-participation-v1"
            or expected_adapter is None
            or provenance["adapter"] != expected_adapter
            or provenance["boundary"]
            != "native-span-selector-with-helper-free-exact-span-participation-replay"
            or provenance["engine"] != "NativeExactSpanParticipationDfaV1"
            or provenance["aggregate_strategy"]
            != "native-exact-span-participation-dfa-v1"
            or provenance["source_pattern_count"] != 1
            or provenance["source_to_artifact"] != [0]
            or not isinstance(provenance["row_total_object_bytes"], int)
            or isinstance(provenance["row_total_object_bytes"], bool)
            or not 0 < provenance["row_total_object_bytes"] <= MAX_NATIVE_ROW_OBJECT_BYTES
            or provenance["uniform_capture"] is not None
            or provenance["required_runtime_symbols"] != []
            or any(provenance[field] is not None for field in scalar_fields)
            or component is None
            or component["source_ordinal"] != 0
            or component["automaton_sha256"] is not None
        ):
            raise CensusError(
                f"{context} exact-span participation topology is not canonical"
            )
        validate_normalized_participation_capture(
            provenance["participation_capture"],
            component,
            provenance["target"],
            provenance["feature_bits"],
            context,
        )
    elif provenance["kind"] == "selector-capture-fallback-v4":
        components = provenance["components"]
        component = components[0] if len(components) == 1 else None
        scalar_fields = (
            "prepared_bulk_strategy", "span_iteration_strategy", "grep_iteration_strategy",
            "program_sha256", "object_sha256", "program_symbol", "entry_symbol",
            "reducer_symbol", "span_fill_symbol",
        )
        if (
            provenance["schema"] != "fre.aot.rebar-runner.v4"
            or provenance["composite_kind"] != "selector-negative-certificate-v1"
            or provenance["model"] != "grep-captures"
            or provenance["adapter"]
            != "general-aot-native-selector-negative-certificate-stock-positive-capture-fallback-v1"
            or provenance["boundary"]
            != "per-line-native-span-negative-certificate-with-trap-visible-stock-positive-capture-fallback"
            or provenance["engine"] != SELECTOR_CAPTURE_ENGINE
            or provenance["aggregate_strategy"]
            != "native-selector-negative-certificate-with-stock-positive-capture-fallback-v1"
            or provenance["source_pattern_count"] != 1
            or provenance["source_to_artifact"] != [0]
            or not isinstance(provenance["row_total_object_bytes"], int)
            or isinstance(provenance["row_total_object_bytes"], bool)
            or not 0 < provenance["row_total_object_bytes"] <= MAX_NATIVE_ROW_OBJECT_BYTES
            or provenance["uniform_capture"] is not None
            or provenance["required_runtime_symbols"] != []
            or any(provenance[field] is not None for field in scalar_fields)
            or component is None
            or component["source_ordinal"] != 0
            or component["automaton_sha256"] is not None
        ):
            raise CensusError(
                f"{context} selector capture fallback topology is not canonical"
            )
        validate_normalized_selector_capture_fallback(
            provenance["selector_capture_fallback"], component, context
        )
    else:
        raise CensusError(f"{context} has an unknown provenance kind")
    operation_route_from_provenance_record(provenance)


def validate_artifact_record(artifact: object, context: str) -> dict[str, object]:
    if not isinstance(artifact, dict):
        raise CensusError(f"{context} is not an object")
    require_exact_keys(artifact, {"runner_sha256", "objects"}, context)
    require_hex64(artifact["runner_sha256"], f"{context} runner digest")
    if not isinstance(artifact["objects"], list) or not artifact["objects"]:
        raise CensusError(f"{context} has no object records")
    for index, obj in enumerate(artifact["objects"]):
        if not isinstance(obj, dict):
            raise CensusError(f"{context} object {index} is not an object")
        require_exact_keys(obj, {"ordinal", "sha256", "bytes"}, f"{context} object {index}")
        if obj["ordinal"] != index:
            raise CensusError(f"{context} object ordinals are not canonical")
        require_hex64(obj["sha256"], f"{context} object {index} digest")
        if not isinstance(obj["bytes"], int) or isinstance(obj["bytes"], bool) or obj["bytes"] <= 0:
            raise CensusError(f"{context} object {index} has invalid size")
    return artifact


def validate_provenance_job_binding(
    provenance: dict[str, object], input_identity: dict[str, object]
) -> None:
    if provenance["kind"] not in {
        "composite-v3", "strict-capture-v4", "participation-capture-v4",
        "selector-capture-fallback-v4", "shared-ordered-many-v2",
        "single-capture-reducer-v5", "weighted-capture-reducer-v6",
    }:
        return
    pattern_hashes = input_identity["pattern_sha256"]
    if provenance["source_pattern_count"] != len(pattern_hashes):
        raise CensusError("multi-source provenance count differs from sealed job")
    if provenance["kind"] == "single-capture-reducer-v5":
        if (
            len(pattern_hashes) != 1
            or provenance["capture_reducer"]["source_pattern_sha256"]
            != pattern_hashes[0]
        ):
            raise CensusError(
                "single-capture reducer raw pattern digest differs from sealed job"
            )
        return
    if (
        provenance["composite_kind"] in NATIVE_ROW_COMPOSITE_KINDS
        or provenance["kind"] == "weighted-capture-reducer-v6"
    ):
        source_map = provenance["source_to_artifact"]
        proof = provenance["uniform_capture"]
        for source, pattern_hash in enumerate(pattern_hashes):
            for prior in range(source):
                if pattern_hash != pattern_hashes[prior]:
                    continue
                if source_map[source] != source_map[prior]:
                    raise CensusError("duplicate source patterns map to different artifacts")
                if proof is not None and any(
                    proof[field][source] != proof[field][prior]
                    for field in (
                        "source_participating_groups", "source_minimum_match_bytes",
                        "source_capture_annotations", "source_proof_work",
                        "source_proof_peak_stack_items",
                        "source_selector_automaton_sha256",
                        "source_selector_program_sha256",
                        "source_selector_object_sha256",
                    )
                ):
                    raise CensusError(
                        "duplicate source patterns publish different capture proofs"
                    )
                if (
                    provenance["kind"] == "weighted-capture-reducer-v6"
                    and provenance["weighted_capture_reducer"][
                        "source_participating_user_captures"
                    ][source]
                    != provenance["weighted_capture_reducer"][
                        "source_participating_user_captures"
                    ][prior]
                ):
                    raise CensusError(
                        "duplicate source patterns publish different capture cardinalities"
                    )


def validate_receipt(
    receipt: object, plan: dict[str, object]
) -> dict[str, object]:
    if not isinstance(receipt, dict):
        raise CensusError("job receipt is not an object")
    require_exact_keys(receipt, {
        "schema", "plan_sha256", "candidate_source", "job", "artifacts", "route",
        "phases", "classification", "receipt_sha256",
    }, "job receipt")
    if (
        receipt["schema"] != RECEIPT_SCHEMA
        or receipt["plan_sha256"] != plan["plan_sha256"]
    ):
        raise CensusError("job receipt schema or plan binding differs")
    validate_digest(receipt, "receipt_sha256", "job receipt")
    require_exact_keys(receipt["candidate_source"], {
        "commit", "tree", "cargo_lock_sha256",
    }, "job receipt candidate source")
    if receipt["candidate_source"] != plan["candidate_source"]:
        raise CensusError("job receipt candidate source differs from its plan")
    require_exact_keys(receipt["job"], {
        "job_id", "point_ids", "model", "input", "candidate_klv",
    }, "job receipt job")
    require_exact_keys(receipt["job"]["input"], {
        "pattern_sha256", "haystack_sha256", "haystack_bytes",
        "case_insensitive", "unicode",
    }, "job receipt input")
    require_exact_keys(receipt["job"]["candidate_klv"], {
        "path", "sha256", "bytes",
    }, "job receipt KLV")
    planned_jobs = {job["job_id"]: job for job in plan["jobs"]}
    planned = planned_jobs.get(receipt["job"]["job_id"])
    if planned is None or not planned["is_runtime"] or not planned["exact_adapter"]:
        raise CensusError("job receipt is not for an exact-adapter runtime job")
    expected_job = {
        "job_id": planned["job_id"],
        "point_ids": planned["point_ids"],
        "model": planned["model"],
        "input": planned["input"],
        "candidate_klv": planned["candidate_klv"],
    }
    if receipt["job"] != expected_job:
        raise CensusError("job receipt identity differs from its sealed job")
    artifacts = receipt["artifacts"]
    require_exact_keys(artifacts, {
        "primary", "replica", "reproducible", "compiled_artifact_present",
        "runtime_execution_authenticated_separately", "provenance",
    }, "job receipt artifacts")
    if artifacts["runtime_execution_authenticated_separately"] is not True:
        raise CensusError("job receipt substitutes compilation for runtime execution")
    route = receipt["route"]
    require_exact_keys(route, {
        "operation_entry_symbols", "operation_entry_symbols_sha256", "adapter_route",
        "semantic_helper_symbols", "semantic_helper_symbols_sha256",
        "provenance_declared_runtime_symbols", "primary_nm_sha256", "replica_nm_sha256",
    }, "job receipt route")
    if route["operation_entry_symbols_sha256"] != sha_bytes(
        canonical(route["operation_entry_symbols"]).encode()
    ):
        raise CensusError("job receipt operation-entry set digest mismatch")
    if route["semantic_helper_symbols_sha256"] != sha_bytes(
        canonical(route["semantic_helper_symbols"]).encode()
    ):
        raise CensusError("job receipt semantic-helper set digest mismatch")
    entries = route["operation_entry_symbols"]
    helpers = route["semantic_helper_symbols"]
    declared = route["provenance_declared_runtime_symbols"]
    if (
        not isinstance(entries, list)
        or len(entries) != len(set(entries))
        or not all(isinstance(symbol, str) and SYMBOL.fullmatch(symbol) for symbol in entries)
    ):
        raise CensusError("job receipt operation-entry symbols are not canonical")
    for name, symbols in (("semantic helper", helpers), ("declared runtime", declared)):
        if (
            not isinstance(symbols, list)
            or symbols != sorted(set(symbols))
            or not all(
                isinstance(symbol, str) and SYMBOL.fullmatch(symbol) for symbol in symbols
            )
        ):
            raise CensusError(f"job receipt {name} symbols are not canonical")
    for name in ("primary_nm_sha256", "replica_nm_sha256"):
        if route[name] is not None:
            require_hex64(route[name], f"job receipt {name}")
    classification = receipt["classification"]
    require_exact_keys(classification, {
        "built_reproducibly", "executed_oracle_correct",
        "native_search_core_authenticated", "adapter_outer_loop",
        "whole_operation_native_authenticated", "reason",
    }, "job receipt classification")
    phases = receipt["phases"]
    if set(phases) == {"pre_execution_failure"}:
        failure = phases["pre_execution_failure"]
        if not isinstance(failure, dict):
            raise CensusError("job receipt pre-execution failure is not an object")
        require_exact_keys(failure, {"stage", "outcome", "evidence"},
                           "job receipt pre-execution failure")
        if failure["stage"] not in {"build", "link", "provenance", "qualification"}:
            raise CensusError("job receipt has an invalid failure stage")
        if failure["outcome"] not in {"failure", "timeout"}:
            raise CensusError("job receipt has an invalid failure outcome")
        if failure["evidence"] is not None:
            require_exact_keys(failure["evidence"], {"sha256", "bytes"},
                               "job receipt failure evidence")
            require_hex64(
                failure["evidence"]["sha256"], "job receipt failure evidence digest"
            )
            evidence_bytes = failure["evidence"]["bytes"]
            if (
                not isinstance(evidence_bytes, int)
                or isinstance(evidence_bytes, bool)
                or evidence_bytes < 0
            ):
                raise CensusError("job receipt has an invalid failure evidence size")
        expected_route = {
            "operation_entry_symbols": [],
            "operation_entry_symbols_sha256": sha_bytes(canonical([]).encode()),
            "adapter_route": None,
            "semantic_helper_symbols": [],
            "semantic_helper_symbols_sha256": sha_bytes(canonical([]).encode()),
            "provenance_declared_runtime_symbols": [],
            "primary_nm_sha256": None,
            "replica_nm_sha256": None,
        }
        expected_classification = {
            "built_reproducibly": False,
            "executed_oracle_correct": False,
            "native_search_core_authenticated": False,
            "adapter_outer_loop": False,
            "whole_operation_native_authenticated": False,
            "reason": f'{failure["stage"]}-{failure["outcome"]}',
        }
        if artifacts != {
            "primary": None,
            "replica": None,
            "reproducible": False,
            "compiled_artifact_present": False,
            "runtime_execution_authenticated_separately": True,
            "provenance": None,
        }:
            raise CensusError("pre-execution failure retains artifact claims")
        if route != expected_route or classification != expected_classification:
            raise CensusError("pre-execution failure retains a native execution claim")
    elif set(phases) == {
        "unmodified_oracle", "semantic_helper_trap", "claimed_entry_negative_traps",
    }:
        primary = validate_artifact_record(artifacts["primary"], "primary artifact")
        replica = validate_artifact_record(artifacts["replica"], "replica artifact")
        provenance = artifacts["provenance"]
        if provenance is None:
            raise CensusError("qualification receipt has no normalized provenance")
        validate_provenance_record(provenance, "job receipt provenance")
        if (
            artifacts["compiled_artifact_present"] is not True
            or not isinstance(artifacts["reproducible"], bool)
            or artifacts["reproducible"] != (primary == replica)
        ):
            raise CensusError("qualification artifact classification is not canonical")
        source = plan["candidate_source"]
        target = plan["target"]
        if (
            provenance["source_commit"] != source["commit"]
            or provenance["source_tree"] != source["tree"]
            or provenance["target"] != target["triple"]
            or provenance["feature_bits"] != target["feature_bits"]
            or provenance["model"] != planned["model"]
            or provenance["benchmark"] != planned["benchmark"]
        ):
            raise CensusError("qualification provenance differs from its sealed job")
        frozen_expected, frozen_comparator = frozen_job_expectation(plan, planned)
        validation = provenance["validation"]
        if (
            validation["expected_value"] != frozen_expected
            or validation["expected_comparator"] != frozen_comparator
            or validation["schedule_klv_sha256"]
            != planned["candidate_klv"]["sha256"]
        ):
            raise CensusError(
                "qualification frozen value/comparator/KLV binding differs from its plan"
            )
        validate_provenance_job_binding(provenance, planned["input"])
        expected_object_hashes = (
            [provenance["object_sha256"]]
            if provenance["kind"] in {
                "scalar-v2", "prepared-grep-v15-v2", "shared-ordered-many-v2",
                "single-capture-reducer-v5",
            }
            else [component["object_sha256"] for component in provenance["components"]]
        )
        if provenance.get("composite_kind") == "regex-redux-fixed-v1":
            expected_object_hashes.append(provenance["object_sha256"])
        if provenance["kind"] == "weighted-capture-reducer-v6":
            expected_object_hashes.append(provenance["object_sha256"])
        if provenance.get("composite_kind") in {
            "native-multi-grep-reducer-v1", "native-row-scalar-reducer-v1",
        }:
            expected_object_hashes.append(provenance["object_sha256"])
        for label, artifact in (("primary", primary), ("replica", replica)):
            if [row["sha256"] for row in artifact["objects"]] != expected_object_hashes:
                raise CensusError(f"{label} object files differ from provenance")
            if provenance["composite_kind"] in {
                "native-multi-grep-reducer-v1", "native-row-scalar-reducer-v1",
            }:
                proof = provenance[
                    "multi_grep_reducer"
                    if provenance["composite_kind"] == "native-multi-grep-reducer-v1"
                    else "row_scalar_reducer"
                ]
                component_count = len(provenance["components"])
                if (
                    sum(row["bytes"] for row in artifact["objects"][:component_count])
                    != provenance["row_total_object_bytes"]
                    or artifact["objects"][component_count]["bytes"]
                    != proof["object_bytes"]
                    or provenance["row_total_object_bytes"] + proof["object_bytes"]
                    > MAX_NATIVE_ROW_OBJECT_BYTES
                ):
                    raise CensusError(
                        f"{label} native-row wrapper object byte totals differ"
                    )
            elif (
                provenance["composite_kind"] in NATIVE_ROW_COMPOSITE_KINDS
                and sum(row["bytes"] for row in artifact["objects"])
                != provenance["row_total_object_bytes"]
            ):
                raise CensusError(f"{label} native-row object byte total differs")
            if (
                provenance["kind"] == "single-capture-reducer-v5"
                and artifact["objects"][0]["bytes"]
                != provenance["capture_reducer"]["object_bytes"]
            ):
                raise CensusError(
                    f"{label} single-capture reducer object byte total differs"
                )
            if provenance["kind"] == "weighted-capture-reducer-v6":
                component_count = len(provenance["components"])
                if (
                    sum(row["bytes"] for row in artifact["objects"][:component_count])
                    != provenance["row_total_object_bytes"]
                    or artifact["objects"][-1]["bytes"]
                    != provenance["weighted_capture_reducer"]["reducer_object_bytes"]
                ):
                    raise CensusError(
                        f"{label} weighted capture reducer object byte totals differ"
                    )
            if provenance["kind"] in {
                "prepared-grep-v15-v2", "shared-ordered-many-v2",
            } and any(
                not 0 < row["bytes"] <= MAX_NATIVE_ROW_OBJECT_BYTES
                for row in artifact["objects"]
            ):
                raise CensusError(
                    f"{label} scalar prepared V15 object exceeds its census byte cap"
                )
        expected_entries, expected_adapter_route = operation_route_from_provenance_record(
            provenance
        )
        expected_declared = declared_runtime_symbols_from_provenance(provenance)
        if (
            entries != expected_entries
            or route["adapter_route"] != expected_adapter_route
            or declared != expected_declared
        ):
            raise CensusError("qualification route differs from normalized provenance")
        conditional_fallbacks = conditional_fallback_symbols_from_provenance(
            provenance
        )
        if not set(conditional_fallbacks).issubset(helpers):
            raise CensusError(
                "selector capture fallback marker escaped the helper trap set"
            )
        declared_semantic = [
            symbol for symbol in declared if not symbol.startswith(CONTROL_PLANE_PREFIXES)
        ]
        if not set(declared_semantic).issubset(helpers):
            raise CensusError("declared semantic helpers escape independent inventory")
        if route["primary_nm_sha256"] is None or route["replica_nm_sha256"] is None:
            raise CensusError("qualification receipt has no final-binary symbol inventory")
        validate_process_record(phases["unmodified_oracle"], "unmodified oracle phase")
        helper = phases["semantic_helper_trap"]
        require_exact_keys(helper, {"process", "marker"}, "semantic helper phase")
        validate_process_record(helper["process"], "semantic helper process")
        validate_marker_record(helper["marker"], "semantic helper marker")
        controls = phases["claimed_entry_negative_traps"]
        if not isinstance(controls, list):
            raise CensusError("claimed entry controls are not a list")
        for index, control in enumerate(controls):
            if not isinstance(control, dict):
                raise CensusError(f"claimed entry control {index} is not an object")
            require_exact_keys(control, {"ordinal", "symbol", "process", "marker"},
                               f"claimed entry control {index}")
            validate_process_record(control["process"], f"claimed entry process {index}")
            validate_marker_record(control["marker"], f"claimed entry marker {index}")
        expected_classification = classification_from_qualification_evidence(
            artifacts["reproducible"],
            entries,
            route["adapter_route"],
            helpers,
            phases,
            target_architecture(plan["target"]["triple"]),
        )
        if classification != expected_classification:
            raise CensusError("qualification classification differs from its evidence")
    else:
        raise CensusError("job receipt phase schema is not closed")
    return receipt


def summarize(args: argparse.Namespace) -> dict[str, object]:
    plan = validate_plan(load_json(pathlib.Path(args.plan)))
    runtime_ids = list(plan["denominators"]["runtime_jobs"]["ids"])
    jobs = {row["job_id"]: row for row in plan["jobs"]}
    receipts: dict[str, dict[str, object]] = {}
    receipt_files = sorted(pathlib.Path(args.receipts).glob("*.json"))
    for path in receipt_files:
        receipt = validate_receipt(load_json(path), plan)
        job_id = receipt["job"]["job_id"]
        if job_id in receipts:
            raise CensusError(f"duplicate receipt for job {job_id}")
        if job_id not in jobs or not jobs[job_id]["is_runtime"]:
            raise CensusError(f"receipt is not for a runtime job: {job_id}")
        planned = jobs[job_id]
        if receipt["candidate_source"] != plan["candidate_source"]:
            raise CensusError(f"receipt candidate source differs for {job_id}")
        expected_job = {
            "job_id": planned["job_id"], "point_ids": planned["point_ids"],
            "model": planned["model"], "input": planned["input"],
            "candidate_klv": planned["candidate_klv"],
        }
        if receipt["job"] != expected_job:
            raise CensusError(f"receipt job identity differs for {job_id}")
        receipts[job_id] = receipt
    built, executed, core_native, whole_native = [], [], [], []
    dispositions: dict[str, str] = {}
    for job_id in runtime_ids:
        job = jobs[job_id]
        receipt = receipts.get(job_id)
        if not job["exact_adapter"]:
            dispositions[job_id] = "unsupported-no-exact-adapter"
            continue
        if receipt is None:
            dispositions[job_id] = "missing-receipt"
            continue
        classification = receipt["classification"]
        if classification["built_reproducibly"]:
            built.append(job_id)
        if classification["executed_oracle_correct"]:
            executed.append(job_id)
        if classification["native_search_core_authenticated"]:
            core_native.append(job_id)
        if classification["whole_operation_native_authenticated"]:
            whole_native.append(job_id)
        dispositions[job_id] = classification["reason"]
    summary = {
        "schema": SUMMARY_SCHEMA,
        "plan_sha256": plan["plan_sha256"],
        "candidate_source": plan["candidate_source"],
        "canonical_runtime_denominator": plan["denominators"]["runtime_jobs"],
        "raw_runtime_schedule_denominator": plan["denominators"]["raw_runtime_schedule_points"],
        "numerators": {
            "built_reproducibly": id_set(built),
            "executed_oracle_correct": id_set(executed),
            "native_search_core_authenticated": id_set(core_native),
            "whole_operation_native_authenticated": id_set(whole_native),
        },
        "fractions": {
            "native_search_core_over_all_runtime_jobs": {
                "numerator": len(core_native), "denominator": len(runtime_ids),
            },
            "whole_operation_native_over_all_runtime_jobs": {
                "numerator": len(whole_native), "denominator": len(runtime_ids),
            },
            "native_search_core_over_executed_jobs": {
                "numerator": len(core_native), "denominator": len(executed),
            },
        },
        "disposition_counts": dict(sorted(Counter(dispositions.values()).items())),
        "job_dispositions": dict(sorted(dispositions.items())),
        "receipt_manifest": {
            "count": len(receipt_files),
            "files_sha256": sha_bytes(canonical([
                {"name": path.name, "sha256": sha_file(path)} for path in receipt_files
            ]).encode()),
        },
    }
    return add_digest(summary, "summary_sha256")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subparsers = result.add_subparsers(dest="command", required=True)
    plan = subparsers.add_parser("plan", help="validate public manifests and seal census plan")
    plan.add_argument("--schedule", action="append", required=True)
    plan.add_argument("--schedule-sha256", action="append", required=True)
    plan.add_argument("--public-manifest")
    plan.add_argument("--public-manifest-sha256")
    plan.add_argument("--public-klv-root", required=True)
    plan.add_argument("--recorded-public-klv-root", required=True)
    plan.add_argument("--public-corpus-label", required=True)
    plan.add_argument("--source-dir", required=True)
    plan.add_argument("--source-commit", required=True)
    plan.add_argument("--source-tree", required=True)
    plan.add_argument("--target", required=True)
    plan.add_argument("--features", default="none")
    plan.add_argument("--expected-public-jobs", type=int, default=EXPECTED_PUBLIC_JOBS)
    plan.add_argument("--expected-runtime-jobs", type=int, default=EXPECTED_RUNTIME_JOBS)
    plan.add_argument("--expected-compile-jobs", type=int, default=EXPECTED_COMPILE_JOBS)
    plan.add_argument("--skip-klv-hashing", action="store_true")
    plan.add_argument("--dry-run", action="store_true")
    plan.add_argument("--output")
    qualify = subparsers.add_parser("qualify-job", help="run correctness and trap controls")
    qualify.add_argument("--plan", required=True)
    qualify.add_argument("--job-id", required=True)
    qualify.add_argument("--public-klv-root", required=True)
    qualify.add_argument("--primary-runner", required=True)
    qualify.add_argument("--replica-runner", required=True)
    qualify.add_argument("--primary-object", action="append", required=True)
    qualify.add_argument("--replica-object", action="append", required=True)
    qualify.add_argument("--trap-library", required=True)
    qualify.add_argument("--nm", default="nm")
    qualify.add_argument("--timeout", type=int, default=300)
    qualify.add_argument("--output", required=True)
    failure = subparsers.add_parser(
        "record-failure", help="seal build/link/provenance failures and timeouts as nonnative"
    )
    failure.add_argument("--plan", required=True)
    failure.add_argument("--job-id", required=True)
    failure.add_argument(
        "--stage", choices=("build", "link", "provenance", "qualification"), required=True
    )
    failure.add_argument("--outcome", choices=("failure", "timeout"), required=True)
    failure.add_argument("--evidence-sha256")
    failure.add_argument("--evidence-bytes", type=int)
    failure.add_argument("--output", required=True)
    aggregate = subparsers.add_parser("summarize", help="seal full denominator and receipts")
    aggregate.add_argument("--plan", required=True)
    aggregate.add_argument("--receipts", required=True)
    aggregate.add_argument("--output", required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "plan":
            payload = make_plan(args)
            if args.dry_run:
                print(json.dumps({
                    "schema": payload["schema"],
                    "plan_sha256": payload["plan_sha256"],
                    "denominators": payload["denominators"],
                    "comparator_divergences": payload["public_corpus"]
                    ["expected_results"]["divergent_jobs"],
                    "wrote_output": False,
                }, sort_keys=True))
            else:
                if not args.output:
                    raise CensusError("non-dry plan requires --output")
                write_exclusive(pathlib.Path(args.output), validate_plan(payload))
        elif args.command == "qualify-job":
            write_exclusive(pathlib.Path(args.output), qualify_job(args))
        elif args.command == "record-failure":
            write_exclusive(pathlib.Path(args.output), record_failure(args))
        elif args.command == "summarize":
            write_exclusive(pathlib.Path(args.output), summarize(args))
        else:
            raise CensusError(f"unknown command {args.command!r}")
    except (CensusError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"true-native-census: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
