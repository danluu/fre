#!/usr/bin/env python3
"""Exact result analyzer for the frozen Search V26 development gate.

This program never emits or executes regex code. It authenticates a sealed
contract and complete 7,776-cell manifest, validates every raw timing sample,
and recomputes all estimators and thresholds without trusting runner summaries.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import math
import os
import stat
import struct
import subprocess
import sys
import tarfile
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
MAX_U64 = (1 << 64) - 1
HEX_DIGITS = frozenset("0123456789abcdef")
EXPECTED_PREREGISTRATION_SHA256 = (
    "772a23e5e6c4354fa3bdc9ad307601dbbce655a62dd5ee7ded075dbe4869a02a"
)
PREREGISTRATION_ARCHIVE_PATH = (
    "research/aot/search-v26-width-cost-rule-r1/preregistration-v1.json"
)
RUNNER_SOURCE_PREFIXES = (
    "crates/",
    "research/aot/search-v26-width-cost-rule-r1/synthetic-runner/",
    "research/aot/search-v26-width-cost-rule-r1/development-gate/runner/",
)
RUNNER_SOURCE_ROOT_FILES = (
    ".cargo/config.toml",
    "Cargo.toml",
    "rust-toolchain.toml",
)
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
        "runner_build_identity_sha256",
        "taskset_binary_sha256",
        "taskset_binary_bytes",
        "contract_sha256",
        "cell_manifest_sha256",
        "host_fingerprint_sha256",
        "cpu_id",
        "shard_nonce",
        "run_nonce",
        "one_shot_seal_sha256",
        "one_shot_consumption_sha256",
        "preflight_manifest_sha256",
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
        "runner_build_identity_sha256",
        "taskset_path",
        "taskset_binary_sha256",
        "taskset_binary_bytes",
        "contract_sha256",
        "cell_manifest_sha256",
        "launcher_sha256",
        "analyzer_sha256",
        "authorization_nonce",
        "one_shot_registry",
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
        "runner_build_identity_sha256",
        "taskset_binary_sha256",
        "taskset_binary_bytes",
        "contract_sha256",
        "cell_manifest_sha256",
        "host_fingerprint_sha256",
        "cpu_ids",
        "shard_cpu_map",
    )
)
RUNNER_BUILD_IDENTITY_KEYS = frozenset(
    (
        "schema",
        "source_commit",
        "source_tree",
        "source_archive_sha256",
        "target_triple",
        "host_triple",
        "profile",
        "opt_level",
        "debug",
        "rustc_identity_sha256",
        "cargo_identity_sha256",
        "runner_source_set_sha256",
        "build_configuration_sha256",
        "crate_version",
        "candidate_backend",
        "reference_backend",
    )
)
CONSUMED_MARKER_KEYS = frozenset(
    (
        "schema",
        "one_shot_seal_sha256",
        "authorization_nonce",
        "run_manifest_sha256",
        "run_nonce",
        "preflight_manifest_sha256",
    )
)
PREFLIGHT_HEADER_KEYS = frozenset(
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
        "runner_build_identity_sha256",
        "taskset_binary_sha256",
        "taskset_binary_bytes",
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
PREFLIGHT_CELL_KEYS = frozenset(
    ("schema", *CELL_IDENTITY_FIELDS, "semantics")
)
PREFLIGHT_FOOTER_KEYS = frozenset(
    (
        "schema",
        "shard_id",
        "cells",
        "semantic_comparisons",
        "complete",
        "shard_nonce",
        "run_nonce",
    )
)
PREFLIGHT_PROOF_KEYS = frozenset(
    ("shard_id", "cpu_id", "shard_nonce", "sha256", "bytes", "cells")
)
PREFLIGHT_MANIFEST_KEYS = frozenset(
    (
        "schema",
        "status",
        "one_shot_seal_sha256",
        "run_manifest_sha256",
        "source_commit",
        "source_tree",
        "source_archive_sha256",
        "runner_binary_sha256",
        "runner_binary_bytes",
        "runner_build_identity_sha256",
        "taskset_binary_sha256",
        "taskset_binary_bytes",
        "contract_sha256",
        "cell_manifest_sha256",
        "host_fingerprint_sha256",
        "run_nonce",
        "proofs",
        "cells",
        "semantic_comparisons",
        "complete",
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


def nonplaceholder_hex(value: Any, length: int, name: str) -> str:
    value = lowercase_hex(value, length, name)
    if value in {"0" * length, "f" * length}:
        raise GateError(f"{name} is a forbidden sentinel identity")
    return value


def require_distinct_nonce_roles(
    authorization_nonce: str, run_nonce: str, shard_nonces: Sequence[str]
) -> None:
    if len(shard_nonces) != 3 or len(
        {authorization_nonce, run_nonce, *shard_nonces}
    ) != 5:
        raise GateError(
            "authorization, run, and shard nonces are not pairwise distinct"
        )


def nonce_hex(value: Any, name: str) -> str:
    return nonplaceholder_hex(value, 64, name)


def exact_keys(value: Mapping[str, Any], expected: frozenset[str], name: str) -> None:
    observed = frozenset(value)
    if observed != expected:
        missing = sorted(expected - observed)
        extra = sorted(observed - expected)
        raise GateError(f"{name} keys drifted: missing={missing}, extra={extra}")


def exact_json_value(observed: Any, expected: Any, name: str) -> None:
    """Require exact JSON shape, scalar type, and value recursively."""
    if type(observed) is not type(expected):
        raise GateError(
            f"{name} type drifted: observed={type(observed).__name__}, "
            f"expected={type(expected).__name__}"
        )
    if isinstance(expected, dict):
        exact_keys(observed, frozenset(expected), name)
        for key, expected_item in expected.items():
            exact_json_value(observed[key], expected_item, f"{name}.{key}")
    elif isinstance(expected, list):
        if len(observed) != len(expected):
            raise GateError(f"{name} length drifted")
        for index, (observed_item, expected_item) in enumerate(
            zip(observed, expected, strict=True)
        ):
            exact_json_value(observed_item, expected_item, f"{name}[{index}]")
    elif observed != expected:
        raise GateError(f"{name} value drifted")


def type_exact_equal(left: Any, right: Any) -> bool:
    """Compare parsed JSON without Python's bool/int/float equality aliases."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            type_exact_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            type_exact_equal(left_item, right_item)
            for left_item, right_item in zip(left, right, strict=True)
        )
    return left == right


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


def open_verified_fd(source: StableFile) -> int:
    """Open exactly the bytes previously authenticated by ``stable_read``."""
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(source.path, flags)
    except OSError as error:
        raise GateError(f"cannot reopen authenticated file {source.path}: {error}") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size != len(source.data)
            or metadata.st_mode != source.mode
        ):
            raise GateError(f"authenticated file metadata changed: {source.path}")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(1 << 20, remaining))
            if not chunk:
                raise GateError(f"authenticated file truncated: {source.path}")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise GateError(f"authenticated file grew: {source.path}")
        if b"".join(chunks) != source.data:
            raise GateError(f"authenticated file bytes changed: {source.path}")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def require_elf64_aarch64(source: StableFile, name: str) -> None:
    """Reject scripts and non-AArch64 binaries before executable handshakes."""
    data = source.data
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise GateError(f"{name} is not an ELF executable")
    if data[4] != 2 or data[5] != 1 or data[6] != 1:
        raise GateError(f"{name} is not little-endian ELF64 version 1")
    elf_type, machine, version = struct.unpack_from("<HHI", data, 16)
    if elf_type not in (2, 3) or machine != 183 or version != 1:
        raise GateError(f"{name} is not an AArch64 ET_EXEC/ET_DYN image")
    program_offset = struct.unpack_from("<Q", data, 32)[0]
    elf_header_bytes = struct.unpack_from("<H", data, 52)[0]
    program_entry_bytes, program_entries = struct.unpack_from("<HH", data, 54)
    if (
        elf_header_bytes != 64
        or program_entry_bytes < 56
        or program_entries == 0
        or program_offset < elf_header_bytes
        or program_offset + program_entry_bytes * program_entries > len(data)
    ):
        raise GateError(f"{name} has an invalid ELF64 program-header table")


def archive_runner_source_set_sha256(archive_file: StableFile) -> str:
    """Derive the exact in-repository source set embedded by runner build.rs."""
    selected: dict[str, tuple[int, bytes]] = {}
    observed_names: set[str] = set()
    preregistration: bytes | None = None
    prefix_counts = {prefix: 0 for prefix in RUNNER_SOURCE_PREFIXES}
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_file.data), mode="r:") as archive:
            for member in archive:
                name = member.name.removeprefix("./")
                path = Path(name)
                if (
                    not name
                    or name.startswith("/")
                    or ".." in path.parts
                    or name in observed_names
                ):
                    raise GateError(f"source archive has unsafe/duplicate member {name!r}")
                observed_names.add(name)
                selected_prefix = next(
                    (
                        prefix
                        for prefix in RUNNER_SOURCE_PREFIXES
                        if name.startswith(prefix)
                    ),
                    None,
                )
                is_preregistration = name == PREREGISTRATION_ARCHIVE_PATH
                is_root_source = name in RUNNER_SOURCE_ROOT_FILES
                if (
                    selected_prefix is None
                    and not is_preregistration
                    and not is_root_source
                ):
                    continue
                if member.isdir():
                    continue
                if not member.isfile():
                    raise GateError(f"required archive source {name!r} is not regular")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise GateError(f"cannot read required archive source {name!r}")
                data = extracted.read()
                if len(data) != member.size:
                    raise GateError(f"required archive source {name!r} is truncated")
                if is_preregistration:
                    preregistration = data
                if (
                    (selected_prefix is not None or is_root_source)
                    and "target" not in path.parts
                ):
                    selected[name] = (int(bool(member.mode & 0o111)), data)
                if selected_prefix is not None and "target" not in path.parts:
                    prefix_counts[selected_prefix] += 1
    except (tarfile.TarError, OSError) as error:
        raise GateError(f"cannot inspect source archive: {error}") from error
    if preregistration is None:
        raise GateError("source archive omits the frozen preregistration")
    if hashlib.sha256(preregistration).hexdigest() != EXPECTED_PREREGISTRATION_SHA256:
        raise GateError("source archive mutates the frozen preregistration")
    missing_prefixes = [
        prefix for prefix, count in prefix_counts.items() if count == 0
    ]
    if missing_prefixes:
        raise GateError(f"source archive omits runner source prefixes {missing_prefixes}")
    missing_root_sources = [
        path for path in RUNNER_SOURCE_ROOT_FILES if path not in selected
    ]
    if missing_root_sources:
        raise GateError(f"source archive omits root build inputs {missing_root_sources}")
    digest = hashlib.sha256()
    digest.update(b"FRE-V26-RUNNER-SOURCE-SET-V2\0\x01")
    for name in sorted(selected):
        name_bytes = name.encode("utf-8")
        mode, data = selected[name]
        digest.update(len(name_bytes).to_bytes(8, "little"))
        digest.update(name_bytes)
        digest.update(b"F")
        digest.update(mode.to_bytes(1, "little"))
        digest.update(len(data).to_bytes(8, "little"))
        digest.update(data)
    return digest.hexdigest()


def sha256_file(path: Path) -> str:
    return stable_read(path, MAX_SHARD_BYTES).sha256


def geomean(values: Iterable[Fraction]) -> float:
    materialized = list(values)
    if not materialized or any(value <= 0 for value in materialized):
        raise GateError("geomean requires a nonempty set of positive exact ratios")
    try:
        return math.exp(
            math.fsum(math.log(float(value)) for value in materialized)
            / len(materialized)
        )
    except (OverflowError, ValueError) as error:
        raise GateError(f"report-only floating geomean is unrepresentable: {error}") from error


def exact_geomean_lte(values: Iterable[Fraction], threshold: Fraction) -> bool:
    materialized = list(values)
    if (
        not materialized
        or threshold <= 0
        or any(not isinstance(value, Fraction) or value <= 0 for value in materialized)
    ):
        raise GateError("exact geomean comparison requires positive Fractions")
    numerator_product = math.prod(value.numerator for value in materialized)
    denominator_product = math.prod(value.denominator for value in materialized)
    count = len(materialized)
    return (
        numerator_product * pow(threshold.denominator, count)
        <= denominator_product * pow(threshold.numerator, count)
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


def strict_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise GateError(f"nonfinite parsed JSON number {value!r} is forbidden")
    return parsed


def strict_json_loads(data: bytes, context: str) -> Any:
    try:
        text = data.decode("utf-8")
        return json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite_constant,
            parse_float=strict_float,
        )
    except GateError:
        raise
    except (UnicodeError, ValueError) as error:
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


def runner_build_identity(
    runner_file: StableFile,
) -> tuple[dict[str, Any], str]:
    require_elf64_aarch64(runner_file, "runner binary")
    descriptor = open_verified_fd(runner_file)
    try:
        completed = subprocess.run(
            [f"/proc/self/fd/{descriptor}", "--build-identity"],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            pass_fds=(descriptor,),
            env={"LANG": "C", "LC_ALL": "C", "TZ": "UTC"},
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise GateError(f"runner build-identity handshake failed: {error}") from error
    finally:
        os.close(descriptor)
    if completed.returncode != 0:
        stderr = completed.stderr[:4096].decode("utf-8", errors="replace")
        raise GateError(
            f"runner build-identity handshake exited {completed.returncode}: {stderr}"
        )
    if len(completed.stdout) > MAX_CONTRACT_BYTES or not completed.stdout.endswith(b"\n"):
        raise GateError("runner build-identity output is unbounded or unterminated")
    value = strict_json_loads(completed.stdout, "runner --build-identity")
    if not isinstance(value, dict):
        raise GateError("runner build identity is not an object")
    exact_keys(value, RUNNER_BUILD_IDENTITY_KEYS, "runner build identity")
    if (
        value.get("schema")
        != "fre-search-v26-development-gate-runner-build-identity-v1"
        or strict_integer(
            value.get("candidate_backend"), "build candidate backend", minimum=1
        )
        != 39
        or strict_integer(
            value.get("reference_backend"), "build reference backend", minimum=1
        )
        != 30
    ):
        raise GateError("runner build-identity schema/backend drifted")
    source_commit = lowercase_hex(
        value.get("source_commit"), 40, "runner build source commit"
    )
    source_tree = lowercase_hex(
        value.get("source_tree"), 40, "runner build source tree"
    )
    source_archive = lowercase_hex(
        value.get("source_archive_sha256"), 64, "runner build source archive"
    )
    if (
        value.get("target_triple") != "aarch64-unknown-linux-gnu"
        or not isinstance(value.get("host_triple"), str)
        or not value["host_triple"]
        or value.get("profile") != "release"
        or value.get("opt_level") != "3"
        or value.get("debug") != "false"
        or value.get("crate_version") != "0.1.0"
    ):
        raise GateError(
            "runner must be an aarch64-unknown-linux-gnu release opt-level=3 non-debug build"
        )
    for field in (
        "rustc_identity_sha256",
        "cargo_identity_sha256",
        "runner_source_set_sha256",
        "build_configuration_sha256",
    ):
        lowercase_hex(value.get(field), 64, f"runner build {field}")
    marker = (
        "FRE-V26-RUNNER-BUILD-IDENTITY-V1|"
        f"{source_commit}|{source_tree}|{source_archive}|"
        f"{value['target_triple']}|{value['profile']}|"
        f"{value['runner_source_set_sha256']}|"
        f"{value['build_configuration_sha256']}|"
        f"{value['rustc_identity_sha256']}|{value['cargo_identity_sha256']}"
    ).encode("ascii")
    if runner_file.data.count(marker) != 1:
        raise GateError("runner binary does not contain exactly one matching build marker")
    return value, hashlib.sha256(completed.stdout).hexdigest()


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
    if not isinstance(candidate, dict):
        raise GateError("candidate contract fields drifted")
    exact_keys(
        candidate,
        frozenset(
            (
                "backend_policy",
                "backend_version",
                "source_commit",
                "source_tree",
                "llvm",
            )
        ),
        "candidate contract",
    )
    if (
        candidate.get("backend_policy") != "AsimdV26"
        or strict_integer(
            candidate.get("backend_version"),
            "candidate backend version",
            minimum=1,
        )
        != 39
        or candidate.get("llvm") is not False
    ):
        raise GateError("candidate contract fields drifted")
    nonplaceholder_hex(candidate["source_commit"], 40, "candidate source commit")
    nonplaceholder_hex(candidate["source_tree"], 40, "candidate source tree")
    exact_json_value(
        candidate,
        {
            "backend_policy": "AsimdV26",
            "backend_version": 39,
            "source_commit": candidate["source_commit"],
            "source_tree": candidate["source_tree"],
            "llvm": False,
        },
        "candidate contract",
    )
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
    strict_integer(inputs.get("literal_records"), "literal record count", minimum=1)
    strict_integer(inputs.get("cells"), "cell count", minimum=1)
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
    exact_json_value(
        inputs,
        {
            "preregistration_sha256": "772a23e5e6c4354fa3bdc9ad307601dbbce655a62dd5ee7ded075dbe4869a02a",
            "synthetic_population_sha256": "a682375f2e6e051f97322396bafc46974df47baa3518bc17f5d6b71b56407b73",
            "literal_records": 1_296,
            "cells": EXPECTED_CELLS,
            "cell_manifest_sha256": cells_file.sha256,
            "cell_key_fields": [
                "width",
                "output_tag",
                "accepted_ordinal",
                "window_shape",
            ],
            "cell_order": [
                "width ascending 6..32",
                "output order exists, span, selected_end",
                "accepted ordinal ascending 0..15",
                "window order no_match, first_legal_position, middle_complete_vector_group, last_legal_position, overlapping_near_miss_before_match, dense_primary_byte_false_candidates",
            ],
        },
        "gate inputs",
    )
    fixtures = contract.get("fixtures")
    expected_fixtures = {
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
    }
    if not isinstance(fixtures, dict) or fixtures != expected_fixtures:
        raise GateError("fixture geometry contract drifted")
    exact_json_value(fixtures, expected_fixtures, "fixture contract")
    expected_engines = {
        "portable": "safe Kernel IR execution",
        "reference": "AsimdV17/backend30 native Search-v1",
        "candidate": "AsimdV26/backend39 native Search-v1",
        "semantic_equality_before_timing": "hard failure",
    }
    if contract.get("engines") != expected_engines:
        raise GateError("engine identity contract drifted")
    exact_json_value(contract["engines"], expected_engines, "engine contract")
    measurement = contract.get("measurement")
    if not isinstance(measurement, dict):
        raise GateError("measurement contract is missing")
    if (
        strict_integer(
            measurement.get("calibration_target_ns"),
            "calibration target",
            minimum=1,
        )
        != 4_000_000
        or strict_integer(
            measurement.get("paired_repetitions"),
            "paired repetitions",
            minimum=1,
        )
        != 12
    ):
        raise GateError("measurement numeric types drifted")
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
    exact_json_value(
        measurement,
        {
            "calibration_target_ns": 4_000_000,
            "calibration": "per cell and engine, begin at one search and double the batch until elapsed_ns >= target; fail on overflow or zero/nonfinite normalized time",
            "calibration_evidence": "record chosen iterations and terminal elapsed_ns; for iterations > 1 also record exactly half the iterations and its elapsed_ns, which must be below target; every timed sample must use the chosen iterations",
            "paired_repetitions": 12,
            "orders": [list(order) for order in EXPECTED_ORDERS],
            "per_repetition_ratio": "(v26_elapsed_ns / v26_iterations) / (v17_elapsed_ns / v17_iterations)",
            "cell_estimator": "arithmetic median of the 12 paired ratios; average sorted ranks 6 and 7",
            "aggregate_estimator": "equal-cell-weight exp(fsum(log(cell_ratio)) / cell_count)",
        },
        "measurement contract",
    )
    expected_shards = [
        {"id": 0, "widths": "6..14", "cells": EXPECTED_SHARD_CELLS},
        {"id": 1, "widths": "15..23", "cells": EXPECTED_SHARD_CELLS},
        {"id": 2, "widths": "24..32", "cells": EXPECTED_SHARD_CELLS},
    ]
    if contract.get("shards") != expected_shards:
        raise GateError("shard contract drifted")
    exact_json_value(contract["shards"], expected_shards, "shard contract")
    acceptance = contract.get("acceptance")
    if (
        not isinstance(acceptance, dict)
        or acceptance != EXPECTED_ACCEPTANCE
        or acceptance.get("exact_semantics") is not True
    ):
        raise GateError("acceptance thresholds drifted")
    exact_json_value(acceptance, EXPECTED_ACCEPTANCE, "acceptance contract")
    execution = contract.get("execution")
    if not isinstance(execution, dict) or execution.get("candidate_timing_executed") is not False:
        raise GateError("frozen contract must precede candidate timing")
    if (
        strict_integer(execution.get("runs"), "execution runs", minimum=1) != 1
        or execution.get("rebar_input") is not False
    ):
        raise GateError("execution Boolean/integer types drifted")
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
    } or execution.get("rebar_input") is not False or not isinstance(
        execution.get("sealing_authority"), str
    ):
        raise GateError("execution contract drifted")
    exact_json_value(
        execution,
        {
            "runs": 1,
            "launcher": "one-shot; require three explicit distinct CPU IDs and run the three disjoint shards concurrently; on Linux pin shard i to CPU i with taskset",
            "admission": "do not wait on load, headroom, another GO, or other CPU work; do not kill other CPU work",
            "run_manifest": "create-new and read-only before timing; seal host fingerprint, ordered CPU IDs, shard-to-CPU map, source/binary/archive/contract/cell identities, authorization nonce, three distinct shard nonces, and a distinct run nonce",
            "missing_duplicate_nonfinite_unpaired_wrong_order_or_mutated_input": "hard failure",
            "rebar_input": False,
            "sealing_authority": execution["sealing_authority"],
            "candidate_timing_executed": False,
        },
        "execution contract",
    )
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


def enforce_literal_reuse(
    identities: dict[tuple[int, int, int], tuple[int, str, str]],
    coordinate: tuple[int, int, int],
    identity: tuple[int, str, str],
    cell_id: int,
) -> None:
    prior = identities.setdefault(coordinate, identity)
    if prior != identity:
        raise GateError(
            f"cell {cell_id} changes literal/source identity across window shapes"
        )


def validate_cell_manifest(
    records: Iterable[dict[str, Any]],
) -> dict[tuple[int, int, int, str], dict[str, Any]]:
    cells: dict[tuple[int, int, int, str], dict[str, Any]] = {}
    population_hasher = hashlib.sha256(
        b"FRE-V26-WIDTH-COST-SYNTHETIC-R1-POPULATION\0\x01"
    )
    literal_by_coordinate: dict[tuple[int, int, int], tuple[int, str, str]] = {}
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
        coordinate = (width, output_tag, accepted_ordinal)
        literal_identity = (source_ordinal, literal_hex, literal_sha256)
        enforce_literal_reuse(
            literal_by_coordinate, coordinate, literal_identity, expected_id
        )
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
    return strict_integer(value, name, minimum=1, maximum=MAX_U64)


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


def validate_semantic_evidence(value: Any, expected_digest: str) -> None:
    if not isinstance(value, dict):
        raise GateError("exact semantic evidence is not an object")
    exact_keys(value, SEMANTICS_KEYS, "semantic evidence")
    if value.get("equal") is not True:
        raise GateError("exact semantic equality did not pass")
    semantic_digests = tuple(
        lowercase_hex(value.get(engine), 64, f"{engine} semantic SHA-256")
        for engine in ("expected", "portable", "v17", "v26")
    )
    if set(semantic_digests) != {expected_digest}:
        raise GateError("expected/portable/V17/V26 semantics differ")


def validate_cell_result(
    record: Mapping[str, Any], expected: Mapping[str, Any], repetition_count: int = 12
) -> Fraction:
    exact_keys(record, CELL_RESULT_KEYS, "cell result")
    if record.get("schema") != "fre-search-v26-development-gate-cell-result-v1":
        raise GateError("unexpected cell result schema")
    if cell_key(record) != cell_key(expected):
        raise GateError("result cell identity differs from its sealed input")
    for field in CELL_IDENTITY_FIELDS:
        if not type_exact_equal(record.get(field), expected.get(field)):
            raise GateError(f"result cell mutated sealed {field}")
    expected_digest = lowercase_hex(
        expected.get("expected_output_sha256"), 64, "sealed expected-output SHA-256"
    )
    validate_semantic_evidence(record.get("semantics"), expected_digest)
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
        "overall": exact_geomean_lte(
            ratios, threshold("overall_geomean_lte")
        ),
        "short": exact_geomean_lte(
            short, threshold("short_width_6_through_8_geomean_lte")
        ),
        "wide": exact_geomean_lte(
            wide, threshold("wide_width_9_through_32_geomean_lte")
        ),
        "outputs": all(
            exact_geomean_lte(
                by_output[tag], threshold("every_output_geomean_lte")
            )
            for tag in by_output
        ),
        "windows": all(
            exact_geomean_lte(
                by_window[window], threshold("every_window_shape_geomean_lte")
            )
            for window in EXPECTED_WINDOWS
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
    taskset_file: StableFile,
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
        ("taskset binary", taskset_file),
        ("launcher", launcher_file),
        ("analyzer", analyzer_file),
    ):
        if artifact.mode & 0o222:
            raise GateError(f"sealed {artifact_name} remains writable")
    if not runner_file.mode & 0o111:
        raise GateError("sealed runner binary is not executable")
    if not taskset_file.mode & 0o111:
        raise GateError("sealed taskset binary is not executable")
    require_elf64_aarch64(taskset_file, "taskset binary")
    candidate = contract["candidate"]
    build_identity, build_identity_sha256 = runner_build_identity(runner_file)
    archive_source_set_sha256 = archive_runner_source_set_sha256(archive_file)
    if (
        build_identity["source_commit"] != candidate["source_commit"]
        or build_identity["source_tree"] != candidate["source_tree"]
        or build_identity["source_archive_sha256"] != archive_file.sha256
        or build_identity["runner_source_set_sha256"]
        != archive_source_set_sha256
    ):
        raise GateError(
            "runner build identity differs from source commit/tree/archive/source set"
        )
    expected_values = {
        "source_commit": candidate["source_commit"],
        "source_tree": candidate["source_tree"],
        "source_archive_sha256": archive_file.sha256,
        "runner_binary_sha256": runner_file.sha256,
        "runner_binary_bytes": len(runner_file.data),
        "runner_build_identity_sha256": build_identity_sha256,
        "taskset_path": str(taskset_file.path),
        "taskset_binary_sha256": taskset_file.sha256,
        "taskset_binary_bytes": len(taskset_file.data),
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
        "runner_build_identity_sha256",
        "taskset_binary_sha256",
        "contract_sha256",
        "cell_manifest_sha256",
        "launcher_sha256",
        "analyzer_sha256",
    ):
        lowercase_hex(seal.get(field), 64, f"seal {field}")
    nonplaceholder_hex(
        seal.get("authorization_nonce"), 64, "seal authorization nonce"
    )
    nonplaceholder_hex(seal.get("source_commit"), 40, "seal source commit")
    nonplaceholder_hex(seal.get("source_tree"), 40, "seal source tree")
    registry_value = seal.get("one_shot_registry")
    if (
        not isinstance(registry_value, str)
        or not Path(registry_value).is_absolute()
        or os.path.normpath(registry_value) != registry_value
    ):
        raise GateError("one-shot registry must be a normalized absolute path")
    taskset_path = seal.get("taskset_path")
    if (
        not isinstance(taskset_path, str)
        or not Path(taskset_path).is_absolute()
        or os.path.normpath(taskset_path) != taskset_path
        or Path(taskset_path).resolve(strict=True) != taskset_file.path.resolve(strict=True)
    ):
        raise GateError("sealed taskset path differs from the authenticated binary")


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
        "runner_build_identity_sha256": seal["runner_build_identity_sha256"],
        "taskset_binary_sha256": seal["taskset_binary_sha256"],
        "taskset_binary_bytes": seal["taskset_binary_bytes"],
        "contract_sha256": contract_file.sha256,
        "cell_manifest_sha256": cells_file.sha256,
    }
    for field, expected_value in expected.items():
        if not type_exact_equal(run_manifest.get(field), expected_value):
            raise GateError(f"run manifest {field} identity mismatch")
    if (
        run_manifest["source_commit"] != contract["candidate"]["source_commit"]
        or run_manifest["source_tree"] != contract["candidate"]["source_tree"]
    ):
        raise GateError("run-manifest source differs from the sealed contract")
    authorization_nonce = nonplaceholder_hex(
        seal.get("authorization_nonce"), 64, "authorization nonce"
    )
    run_nonce = nonplaceholder_hex(run_manifest.get("run_nonce"), 64, "run nonce")
    host_fingerprint = nonplaceholder_hex(
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
            nonplaceholder_hex(
                mapping.get("shard_nonce"), 64, f"shard {shard_id} nonce"
            )
        )
    require_distinct_nonce_roles(authorization_nonce, run_nonce, shard_nonces)
    return cpu_ids, shard_nonces, host_fingerprint, run_nonce


def validate_consumed_marker(
    marker: Mapping[str, Any],
    marker_file: StableFile,
    seal: Mapping[str, Any],
    seal_file: StableFile,
    run_manifest_file: StableFile,
    run_nonce: str,
    preflight_manifest_file: StableFile,
) -> None:
    exact_keys(marker, CONSUMED_MARKER_KEYS, "one-shot consumption marker")
    if marker.get("schema") != "fre-search-v26-development-gate-consumed-seal-v1":
        raise GateError("unexpected one-shot consumption-marker schema")
    registry = Path(seal["one_shot_registry"])
    try:
        resolved_registry = registry.resolve(strict=True)
    except OSError as error:
        raise GateError(f"cannot resolve sealed one-shot registry: {error}") from error
    if resolved_registry != registry or not registry.is_dir():
        raise GateError("sealed one-shot registry is not a canonical real directory")
    expected_path = registry / f"{seal_file.sha256}.consumed-v1.json"
    if marker_file.path.resolve(strict=True) != expected_path:
        raise GateError("consumption marker is not keyed by seal identity in its registry")
    if marker_file.mode & 0o222:
        raise GateError("one-shot consumption marker remains writable")
    expected = {
        "schema": "fre-search-v26-development-gate-consumed-seal-v1",
        "one_shot_seal_sha256": seal_file.sha256,
        "authorization_nonce": seal["authorization_nonce"],
        "run_manifest_sha256": run_manifest_file.sha256,
        "run_nonce": run_nonce,
        "preflight_manifest_sha256": preflight_manifest_file.sha256,
    }
    if not type_exact_equal(marker, expected):
        raise GateError("one-shot consumption marker identity mismatch")


def preflight_expected_header(
    shard_id: int,
    seal: Mapping[str, Any],
    seal_file: StableFile,
    run_manifest_file: StableFile,
    contract_file: StableFile,
    cells_file: StableFile,
    cpu_id: int,
    shard_nonce: str,
    host_fingerprint: str,
    run_nonce: str,
) -> dict[str, Any]:
    return {
        "schema": "fre-search-v26-development-gate-preflight-header-v1",
        "shard_id": shard_id,
        "candidate_backend": 39,
        "reference_backend": 30,
        "source_commit": seal["source_commit"],
        "source_tree": seal["source_tree"],
        "source_archive_sha256": seal["source_archive_sha256"],
        "runner_binary_sha256": seal["runner_binary_sha256"],
        "runner_binary_bytes": seal["runner_binary_bytes"],
        "runner_build_identity_sha256": seal["runner_build_identity_sha256"],
        "taskset_binary_sha256": seal["taskset_binary_sha256"],
        "taskset_binary_bytes": seal["taskset_binary_bytes"],
        "contract_sha256": contract_file.sha256,
        "cell_manifest_sha256": cells_file.sha256,
        "host_fingerprint_sha256": host_fingerprint,
        "cpu_id": cpu_id,
        "shard_nonce": shard_nonce,
        "run_nonce": run_nonce,
        "one_shot_seal_sha256": seal_file.sha256,
        "run_manifest_sha256": run_manifest_file.sha256,
    }


def validate_preflight_header(
    header: Mapping[str, Any],
    shard_id: int,
    expected_header: Mapping[str, Any],
) -> None:
    exact_keys(header, PREFLIGHT_HEADER_KEYS, f"preflight shard {shard_id} header")
    strict_integer(
        header.get("shard_id"), "preflight header shard ID", minimum=0, maximum=2
    )
    strict_integer(
        header.get("candidate_backend"), "preflight candidate backend", minimum=1
    )
    strict_integer(
        header.get("reference_backend"), "preflight reference backend", minimum=1
    )
    strict_integer(
        header.get("runner_binary_bytes"), "preflight runner bytes", minimum=1
    )
    strict_integer(
        header.get("taskset_binary_bytes"), "preflight taskset bytes", minimum=1
    )
    strict_integer(header.get("cpu_id"), "preflight CPU ID", minimum=0)
    if not type_exact_equal(header, expected_header):
        raise GateError(f"preflight shard {shard_id} header identity mismatch")


def validate_preflight_file(
    source: StableFile,
    shard_id: int,
    expected_header: Mapping[str, Any],
    expected_shard_nonce: str,
    expected_run_nonce: str,
    cells: Mapping[tuple[int, int, int, str], Mapping[str, Any]],
) -> None:
    if source.mode & 0o222:
        raise GateError(f"preflight shard {shard_id} remains writable")
    records = list(read_jsonl_file(source))
    if len(records) != EXPECTED_SHARD_CELLS + 2:
        raise GateError(f"preflight shard {shard_id} has the wrong record count")
    header, *body, footer = records
    validate_preflight_header(header, shard_id, expected_header)
    observed_keys: list[tuple[int, int, int, str]] = []
    for record in body:
        exact_keys(record, PREFLIGHT_CELL_KEYS, "preflight cell")
        if record.get("schema") != "fre-search-v26-development-gate-preflight-cell-v1":
            raise GateError("unexpected preflight-cell schema")
        key = cell_key(record)
        expected = cells.get(key)
        if (
            expected is None
            or expected_shard(key[0]) != shard_id
            or key in observed_keys
        ):
            raise GateError(f"preflight shard {shard_id} has unknown/duplicate cell {key}")
        for field in CELL_IDENTITY_FIELDS:
            if not type_exact_equal(record.get(field), expected.get(field)):
                raise GateError(f"preflight cell mutated sealed {field}")
        expected_digest = lowercase_hex(
            expected.get("expected_output_sha256"),
            64,
            "preflight expected-output SHA-256",
        )
        validate_semantic_evidence(record.get("semantics"), expected_digest)
        observed_keys.append(key)
    expected_keys = [key for key in cells if expected_shard(key[0]) == shard_id]
    if observed_keys != expected_keys:
        raise GateError(f"preflight shard {shard_id} cell ordering/closure drifted")
    exact_keys(footer, PREFLIGHT_FOOTER_KEYS, f"preflight shard {shard_id} footer")
    if (
        footer.get("schema")
        != "fre-search-v26-development-gate-preflight-footer-v1"
        or strict_integer(
            footer.get("shard_id"),
            "preflight footer shard ID",
            minimum=0,
            maximum=2,
        )
        != shard_id
        or strict_integer(
            footer.get("cells"), "preflight footer cells", minimum=1
        )
        != EXPECTED_SHARD_CELLS
        or strict_integer(
            footer.get("semantic_comparisons"),
            "preflight semantic comparisons",
            minimum=1,
        )
        != EXPECTED_SHARD_CELLS * 3
        or footer.get("complete") is not True
        or footer.get("shard_nonce") != expected_shard_nonce
        or footer.get("run_nonce") != expected_run_nonce
    ):
        raise GateError(f"preflight shard {shard_id} footer is not terminal")


def validate_preflight_manifest(
    manifest: Mapping[str, Any],
    manifest_file: StableFile,
    proof_files: Sequence[StableFile],
    seal: Mapping[str, Any],
    seal_file: StableFile,
    run_manifest_file: StableFile,
    contract_file: StableFile,
    cells_file: StableFile,
    cpu_ids: Sequence[int],
    shard_nonces: Sequence[str],
    host_fingerprint: str,
    run_nonce: str,
    cells: Mapping[tuple[int, int, int, str], Mapping[str, Any]],
) -> list[str]:
    if len(proof_files) != 3:
        raise GateError("preflight manifest requires exactly three proof files")
    if manifest_file.mode & 0o222:
        raise GateError("preflight manifest remains writable")
    exact_keys(manifest, PREFLIGHT_MANIFEST_KEYS, "preflight manifest")
    expected_common = {
        "schema": "fre-search-v26-development-gate-preflight-manifest-v1",
        "status": "COMPLETE_BEFORE_TIMING",
        "one_shot_seal_sha256": seal_file.sha256,
        "run_manifest_sha256": run_manifest_file.sha256,
        "source_commit": seal["source_commit"],
        "source_tree": seal["source_tree"],
        "source_archive_sha256": seal["source_archive_sha256"],
        "runner_binary_sha256": seal["runner_binary_sha256"],
        "runner_binary_bytes": seal["runner_binary_bytes"],
        "runner_build_identity_sha256": seal["runner_build_identity_sha256"],
        "taskset_binary_sha256": seal["taskset_binary_sha256"],
        "taskset_binary_bytes": seal["taskset_binary_bytes"],
        "contract_sha256": contract_file.sha256,
        "cell_manifest_sha256": cells_file.sha256,
        "host_fingerprint_sha256": host_fingerprint,
        "run_nonce": run_nonce,
        "cells": EXPECTED_CELLS,
        "semantic_comparisons": EXPECTED_CELLS * 3,
        "complete": True,
    }
    for field, expected_value in expected_common.items():
        if not type_exact_equal(manifest.get(field), expected_value):
            raise GateError(f"preflight manifest {field} identity mismatch")
    proofs = manifest.get("proofs")
    if not isinstance(proofs, list) or len(proofs) != 3:
        raise GateError("preflight manifest proof closure failed")
    proof_sha256: list[str] = []
    for shard_id, (entry, proof_file) in enumerate(
        zip(proofs, proof_files, strict=True)
    ):
        if not isinstance(entry, dict):
            raise GateError("preflight proof entry is not an object")
        exact_keys(entry, PREFLIGHT_PROOF_KEYS, f"preflight proof {shard_id}")
        expected_entry = {
            "shard_id": shard_id,
            "cpu_id": cpu_ids[shard_id],
            "shard_nonce": shard_nonces[shard_id],
            "sha256": proof_file.sha256,
            "bytes": len(proof_file.data),
            "cells": EXPECTED_SHARD_CELLS,
        }
        if not type_exact_equal(entry, expected_entry):
            raise GateError(f"preflight proof {shard_id} identity mismatch")
        expected_header = preflight_expected_header(
            shard_id,
            seal,
            seal_file,
            run_manifest_file,
            contract_file,
            cells_file,
            cpu_ids[shard_id],
            shard_nonces[shard_id],
            host_fingerprint,
            run_nonce,
        )
        validate_preflight_file(
            proof_file,
            shard_id,
            expected_header,
            shard_nonces[shard_id],
            run_nonce,
            cells,
        )
        proof_sha256.append(proof_file.sha256)
    return proof_sha256


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
    strict_integer(header.get("taskset_binary_bytes"), "taskset binary bytes", minimum=1)
    strict_integer(header.get("cpu_id"), "header CPU ID", minimum=0)
    if not type_exact_equal(header, expected_header):
        raise GateError(f"shard {shard_id} header identity mismatch")


def analyze_paths(
    expected_seal_sha256: str,
    seal_path: Path,
    contract_path: Path,
    cells_path: Path,
    run_manifest_path: Path,
    preflight_manifest_path: Path,
    preflight_paths: Sequence[Path],
    consumed_marker_path: Path,
    archive_path: Path,
    runner_path: Path,
    taskset_path: Path,
    launcher_path: Path,
    shard_paths: Sequence[Path],
) -> dict[str, Any]:
    if len(shard_paths) != 3:
        raise GateError("exactly three shard files are required")
    if len(preflight_paths) != 3:
        raise GateError("exactly three preflight proof files are required")
    seal_file = stable_read(seal_path, MAX_SEAL_BYTES)
    contract_file = stable_read(contract_path, MAX_CONTRACT_BYTES)
    cells_file = stable_read(cells_path, MAX_CELL_MANIFEST_BYTES)
    run_manifest_file = stable_read(run_manifest_path, MAX_RUN_MANIFEST_BYTES)
    preflight_manifest_file = stable_read(
        preflight_manifest_path, MAX_RUN_MANIFEST_BYTES
    )
    preflight_files = [
        stable_read(path, MAX_SHARD_BYTES) for path in preflight_paths
    ]
    consumed_marker_file = stable_read(consumed_marker_path, MAX_RUN_MANIFEST_BYTES)
    archive_file = stable_read(archive_path, MAX_SHARD_BYTES)
    runner_file = stable_read(runner_path, MAX_SHARD_BYTES)
    taskset_file = stable_read(taskset_path, MAX_SHARD_BYTES)
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
        taskset_file,
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
    preflight_manifest = read_json_file(preflight_manifest_file)
    preflight_sha256 = validate_preflight_manifest(
        preflight_manifest,
        preflight_manifest_file,
        preflight_files,
        seal,
        seal_file,
        run_manifest_file,
        contract_file,
        cells_file,
        cpu_ids,
        shard_nonces,
        host_fingerprint,
        run_nonce,
        cells,
    )
    consumed_marker = read_json_file(consumed_marker_file)
    validate_consumed_marker(
        consumed_marker,
        consumed_marker_file,
        seal,
        seal_file,
        run_manifest_file,
        run_nonce,
        preflight_manifest_file,
    )
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
            "runner_build_identity_sha256": seal[
                "runner_build_identity_sha256"
            ],
            "taskset_binary_sha256": seal["taskset_binary_sha256"],
            "taskset_binary_bytes": seal["taskset_binary_bytes"],
            "contract_sha256": contract_file.sha256,
            "cell_manifest_sha256": cells_file.sha256,
            "host_fingerprint_sha256": host_fingerprint,
            "cpu_id": cpu_ids[shard_id],
            "shard_nonce": shard_nonces[shard_id],
            "run_nonce": run_nonce,
            "one_shot_seal_sha256": seal_file.sha256,
            "one_shot_consumption_sha256": consumed_marker_file.sha256,
            "preflight_manifest_sha256": preflight_manifest_file.sha256,
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
        "one_shot_consumption_sha256": consumed_marker_file.sha256,
        "preflight_manifest_sha256": preflight_manifest_file.sha256,
        "preflight_sha256": preflight_sha256,
        "run_manifest_sha256": run_manifest_file.sha256,
        "contract_sha256": contract_file.sha256,
        "cell_manifest_sha256": cells_file.sha256,
        "source_archive_sha256": archive_file.sha256,
        "runner_binary_sha256": runner_file.sha256,
        "runner_build_identity_sha256": seal["runner_build_identity_sha256"],
        "taskset_binary_sha256": taskset_file.sha256,
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
    parser.add_argument("preflight_manifest", type=Path)
    parser.add_argument("preflights", nargs=3, type=Path)
    parser.add_argument("consumed_marker", type=Path)
    parser.add_argument("source_archive", type=Path)
    parser.add_argument("runner", type=Path)
    parser.add_argument("taskset", type=Path)
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
            args.preflight_manifest,
            args.preflights,
            args.consumed_marker,
            args.source_archive,
            args.runner,
            args.taskset,
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
