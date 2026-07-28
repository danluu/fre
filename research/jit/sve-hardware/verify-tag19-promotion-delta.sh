#!/usr/bin/python3 -I
"""Verify one source-bound ABI2 SVE tag-19 promotion delegate.

The native-promotion coordinator invokes this Candidate-extracted executable
with:

    REPOSITORY CANDIDATE PROMOTED EXPECTED_TREE EXPECTED_ARCHIVE_SHA256
    EXPECTED_BUILD_RECEIPT_SHA256 EXPECTED_MANIFEST_SHA256 EVIDENCE_DIR
    REVIEW_RECEIPT EXPECTED_REVIEW_SHA256 V8_BUNDLE_SHA256
    composed-exact-union-delegated

There is no standalone tag19 promotion mode: tag19 may become Qualified only
beside an independently verified V8 fallback. This verifier emits only the
bounded TAG19 delegate receipt. It never emits composed native authority.
"""

from __future__ import annotations

import sys

# The fixed shebang selects an absolute interpreter in isolated mode. Complete
# the equivalent of -B before importing any non-builtin module.
sys.dont_write_bytecode = True

import csv
import hashlib
import io
import math
import os
import pathlib
import re
import selectors
import stat
import subprocess
import time
from fractions import Fraction
from typing import NoReturn, Optional, Union


if not sys.flags.isolated or not sys.dont_write_bytecode or sys.flags.optimize:
    raise SystemExit(
        "verify-tag19-promotion: use /usr/bin/python3 -I without optimization"
    )

os.umask(0o077)

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX_U64 = re.compile(r"^0x[0-9a-f]{16}$")
UINT = re.compile(r"^(0|[1-9][0-9]*)$")
SAFE_PATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/+@-]{0,1023}$")
SAFE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$")
ZERO_SHA256 = "0" * 64
INVALIDATED_BUNDLES = frozenset(
    {
        "89af5a04190a39c40a4819ce916fc286"
        "30330550e1cafc15e9919122af0ae9f7",
        "de084ff0564acdb89889f28b9dcfddce"
        "9b6f0955a1b2aead30d75770039e0453",
    }
)

ATOM_PATH = "crates/fre/src/qualified_exact_search_qualification.rs"
COMPOSED_AOT_ATOM_PATH = "crates/fre-aot-static-runtime/src/support.rs"
VERIFIER_PATH = (
    "research/jit/sve-hardware/verify-tag19-promotion-delta.sh"
)
BUNDLE_MANIFEST = "qualification-bundle-tag19-abi2-v1.tsv"
BUNDLE_DIGEST = "BUNDLE.sha256"
FACADE_RECEIPT_PATH = "evidence/facade-v5.tsv"
FACADE_RECEIPT_SCHEMA = "fre-jit-auto-facade-v5"
PRODUCER_RECEIPT_PATH = "evidence/abi2-producer-v1.tsv"
PRODUCER_RECEIPT_SCHEMA = (
    "fre-jit-tag19-selected-end-register-v2-qualification-v1"
)
FACADE_PERFORMANCE_PATH = "evidence/facade-performance-v5.csv"
FACADE_PERFORMANCE_SCHEMA = "fre-jit-tag19-facade-performance-v5"
DERIVED_PERFORMANCE_SCHEMA = "fre-jit-tag19-abi2-performance-v1"
ABI2_PRODUCER_BINARY_PATH = "artifacts/tag19-abi2-producer"
FACADE_PRODUCER_BINARY_PATH = "artifacts/tag19-facade-qualification"
TOOLCHAIN_CLOSURE_PATH = "provenance/toolchain-closure.tsv"
REGISTRY_CLOSURE_PATH = "provenance/cargo-registry-closure.tsv"
TOOLCHAIN_CLOSURE_SCHEMA = "fre-jit-tag19-toolchain-closure-v1"
REGISTRY_CLOSURE_SCHEMA = "fre-jit-tag19-cargo-registry-closure-v1"
QUALIFICATION_PROFILE = "linux-aarch64-arm-41-d84-vl16-release-v1"
TARGET_TRIPLE = "aarch64-unknown-linux-gnu"
ABI2_PRODUCER_FEATURES = "sve-hardware-qualification"
FACADE_PRODUCER_FEATURES = "qualified-exact-search-jit"
QUALIFICATION_RUSTFLAGS = "-Ctarget-cpu=native"
RELEASE_PROFILE = "opt-level=3,codegen-units=1,lto=thin,panic=abort"
ABI2_PRODUCER_BUILD_COMMAND = (
    "cargo build --locked --release --target aarch64-unknown-linux-gnu "
    "-p fre-jit-runtime --no-default-features "
    "--features sve-hardware-qualification "
    "--example tag19_selected_end_register_v2_qualification"
)
FACADE_PRODUCER_BUILD_COMMAND = (
    "cargo test --locked --release --target aarch64-unknown-linux-gnu "
    "-p fre --no-default-features --features qualified-exact-search-jit "
    "--lib --no-run"
)
PER_STAGE_FAMILYWISE_CELLS = 48
# A one-sided per-cell alpha of 0.05/48 and the df=2 Student-t CDF give
# t=sqrt(458882/959). The next representable float rounds the gate outward.
BONFERRONI_DF2_CRITICAL = math.nextafter(
    math.sqrt(458_882 / 959), math.inf
)
CONFIDENCE_METHOD = (
    "paired-process-log-mean-one-sided-bonferroni-familywise95-"
    "per-stage-48cells-t-df2-conservative"
)
FACADE_RECEIPT_KEYS = (
    "case",
    "policy",
    "backend",
    "abi",
    "qualification",
    "publication_vl",
    "session_vl",
    "route",
    "artifact_sha256",
    "status",
)
PRODUCER_RECEIPT_KEYS = (
    "candidate",
    "tree",
    "source_archive_sha256",
    "build_receipt_sha256",
    "resource_coordinator_sha256",
    "resource_cutover_sha256",
    "profile",
    "run_id",
    "instance_id",
    "instance_type",
    "process_id",
    "cpu",
    "backend",
    "abi",
    "artifact_sha256",
    "target_feature_bits",
    "publication_vl",
    "session_vl",
    "independent_audit",
    "store_count",
    "forbidden_x4",
    "portable_oracle",
    "kernel_ir_oracle",
    "guard_pages",
    "abi2_vector_callee_saved_canary",
    "comparisons",
    "status",
)
FACADE_PERFORMANCE_FIELDS = (
    "schema",
    "revision",
    "pid",
    "repetition",
    "literal_class",
    "literal_hex",
    "size",
    "scenario",
    "order",
    "engine",
    "stage",
    "iterations",
    "total_ns",
    "ns_per_iter",
    "checksum",
    "semantic_value",
    "haystack_bytes",
    "route",
    "backend",
    "qualification_state",
    "artifact_sha256",
    "declared_min_window_bytes",
    "declared_min_calls",
    "measured_calls",
    "tree",
    "run_id",
    "instance_id",
    "instance_type",
    "resource_coordinator_sha256",
    "resource_cutover_sha256",
    "profile",
    "affinity_cpu",
)
FACADE_LITERAL_HEX = {
    "unique": "30313233343536373839616263646566",
    "repeated": "61616161616161616161616161616161",
    "alternating": "61626162616261626162616261626162",
    "natural": "7365617263682d7461726765742d7631",
    "binary": "00ff01fe02fd03fc04fb05fa06f907f8",
    "rank-adversarial": "61616161626161616163616161616461",
}
FACADE_SIZES = {
    "64k": (64 * 1024, 1024),
    "1m": (1024 * 1024, 64),
}
FACADE_SCENARIOS = ("absent", "late", "homogeneous", "near-miss")
FACADE_STAGES = ("build", "search", "cold", "full")
CANDIDATE_ATOM_BLOB = "44609addd5e2ada9bd003614352bda0bdc5c2316"
ABI2_SOURCE_CLOSURE_SHA256 = (
    "9097e3ffc23d7d4dd6d55f7bc19f275b436d3d04ae0d0a021f8041f98d1db805"
)
MAX_GIT_OUTPUT = 4 * 1024 * 1024
MAX_ENTRIES = 16_384
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
SMALL_RECEIPT_BYTES = 4 * 1024 * 1024
CLOSURE_RECEIPT_BYTES = 32 * 1024 * 1024
MAX_TOOLCHAIN_ENTRIES = 16_384
MAX_REGISTRY_ENTRIES = 100_000
MAX_CLOSURE_FILE_BYTES = 4 * 1024 * 1024 * 1024
GIT_QUERY_DEADLINE_SECONDS = 30.0
OWNED_CHILD_REAP_SECONDS = 5.0
MAX_CANONICAL_UINT = (1 << 63) - 1

ABI2_SOURCE_PATHS = (
    "Cargo.lock",
    "Cargo.toml",
    "rust-toolchain.toml",
    "crates/fre-jit-aarch64/Cargo.toml",
    "crates/fre-jit-aarch64/src/abi.rs",
    "crates/fre-jit-aarch64/src/audit.rs",
    "crates/fre-jit-aarch64/src/decode.rs",
    "crates/fre-jit-aarch64/src/emit.rs",
    "crates/fre-jit-aarch64/src/error.rs",
    "crates/fre-jit-aarch64/src/image.rs",
    "crates/fre-jit-aarch64/src/lib.rs",
    "crates/fre-jit-aarch64/src/search_template.rs",
    "crates/fre-jit-aarch64/src/selected_end_v2.rs",
    "crates/fre-jit-aarch64/src/tests_selected_end_v2.rs",
    "crates/fre-jit-cache/Cargo.toml",
    "crates/fre-jit-cache/src/cache.rs",
    "crates/fre-jit-cache/src/error.rs",
    "crates/fre-jit-cache/src/lib.rs",
    "crates/fre-jit-cache/src/policy.rs",
    "crates/fre-jit-cache/src/stats.rs",
    "crates/fre-jit-cache/src/tests.rs",
    "crates/fre-jit-runtime/Cargo.toml",
    "crates/fre-jit-runtime/examples/tag19_selected_end_register_v2_qualification.rs",
    "crates/fre-jit-runtime/src/error.rs",
    "crates/fre-jit-runtime/src/identity.rs",
    "crates/fre-jit-runtime/src/lib.rs",
    "crates/fre-jit-runtime/src/limits.rs",
    "crates/fre-jit-runtime/src/operation.rs",
    "crates/fre-jit-runtime/src/platform/aarch64.rs",
    "crates/fre-jit-runtime/src/platform/linux_aarch64.rs",
    "crates/fre-jit-runtime/src/platform/mod.rs",
    "crates/fre-jit-runtime/src/selected_end_register_v2.rs",
    "crates/fre-jit-runtime/src/tests.rs",
    "crates/fre-kernel-ir/Cargo.toml",
    "crates/fre-kernel-ir/src/aggregate.rs",
    "crates/fre-kernel-ir/src/contract.rs",
    "crates/fre-kernel-ir/src/error.rs",
    "crates/fre-kernel-ir/src/interpret.rs",
    "crates/fre-kernel-ir/src/ir.rs",
    "crates/fre-kernel-ir/src/lib.rs",
    "crates/fre-kernel-ir/src/lower.rs",
    "crates/fre-kernel-ir/src/serialize.rs",
    "crates/fre-kernel-ir/src/validate.rs",
    "crates/fre-kernels/Cargo.toml",
    "crates/fre-kernels/src/lib.rs",
    "crates/fre-target-features/Cargo.toml",
    "crates/fre-target-features/src/lib.rs",
    "crates/fre-exact-alloc/Cargo.toml",
    "crates/fre-exact-alloc/src/lib.rs",
    "crates/fre-syntax/Cargo.toml",
    "crates/fre-syntax/src/admission.rs",
    "crates/fre-syntax/src/error.rs",
    "crates/fre-syntax/src/lib.rs",
    "crates/fre-syntax/src/parsed.rs",
    "crates/fre-syntax/src/profile.rs",
    "crates/fre-syntax/src/re2.rs",
    "crates/fre-syntax/src/rust.rs",
    "crates/fre-syntax/src/unicode_bool_aliases.in",
    "crates/fre-syntax/src/unicode_gencat_aliases.in",
    "crates/fre-syntax/src/unicode_script_aliases.in",
    "crates/fre-syntax/src/unicode_segment_aliases.in",
    "crates/fre/Cargo.toml",
    "crates/fre/src/finite.rs",
    "crates/fre/src/finite_root.rs",
    "crates/fre/src/forward_anchored.rs",
    "crates/fre/src/guarded_ascii_word.rs",
    "crates/fre/src/lib.rs",
    "crates/fre/src/qualified_exact_search.rs",
    "crates/fre/src/qualified_exact_search_tag21_facade_qualification.rs",
    "crates/fre/src/required_literal.rs",
    "crates/fre/src/unicode_word_run.rs",
    ATOM_PATH,
)

CANDIDATE_ATOM = b"""use super::QualifiedExactSearchQualification;

/// Qualification atom scoped only to `SearchBackendPolicy::AsimdV8` / tag 8.
pub const QUALIFIED_EXACT_SEARCH_ASIMD_V8_QUALIFICATION: QualifiedExactSearchQualification =
    QualifiedExactSearchQualification::Candidate;

/// Qualification atom scoped only to `SearchBackendPolicy::Sve16V6` / tag 19.
pub const QUALIFIED_EXACT_SEARCH_SVE16_V6_QUALIFICATION: QualifiedExactSearchQualification =
    QualifiedExactSearchQualification::Candidate;

/// Qualification atom scoped only to `SearchBackendPolicy::Sve2Fixed16` / tag 10.
pub const QUALIFIED_EXACT_SEARCH_SVE2_FIXED16_QUALIFICATION: QualifiedExactSearchQualification =
    QualifiedExactSearchQualification::Candidate;

/// Qualification atom scoped only to `SearchBackendPolicy::Sve2Fixed16V2` /
/// tag 21.
pub const QUALIFIED_EXACT_SEARCH_SVE2_FIXED16_V2_QUALIFICATION: QualifiedExactSearchQualification =
    QualifiedExactSearchQualification::Candidate;
"""

SUBJECT_FIELDS = (
    "schema",
    "candidate_revision",
    "candidate_tree",
    "backend_policy",
    "backend_version",
    "qualification_atom_symbol",
    "qualification_state",
    "literal_bytes",
    "public_output",
    "native_output",
    "native_abi",
    "native_arguments",
    "native_return",
    "x4_result_slot",
    "row_schema",
    "facade_receipt_schema",
    "facade_receipt_sha256",
    "facade_performance_raw_schema",
    "facade_performance_raw_sha256",
    "abi2_producer_schema",
    "abi2_producer_sha256",
    "abi2_producer_binary_sha256",
    "facade_producer_binary_sha256",
    "evidence_binding_schema",
    "target",
    "target_feature_bits",
    "operating_system_contract",
    "sve_vector_bytes_at_publication",
    "required_thread_sve_vector_bytes",
    "host_contract",
    "artifact_sha256",
    "artifact_witness_schema",
    "artifact_witness_sha256",
    "source_archive_sha256",
    "build_receipt_sha256",
    "source_snapshot_sha256",
    "correctness_verification_sha256",
    "performance_verification_sha256",
    "evidence_class",
    "overall",
)
WITNESS_FIELDS = (
    "schema",
    "external_artifact_witness_schema",
    "candidate_revision",
    "candidate_tree",
    "abi2_source_closure_sha256",
    "backend_policy",
    "backend_version",
    "literal_bytes",
    "public_output",
    "native_output",
    "native_abi",
    "native_arguments",
    "native_return",
    "x4_result_slot",
    "target",
    "target_feature_bits",
    "operating_system_contract",
    "sve_vector_bytes_at_publication",
    "required_thread_sve_vector_bytes",
    "host_contract",
    "facade_artifact_sha256",
    "deterministic_emitter_artifact_sha256",
    "facade_identity_matches_external_witness",
    "independent_image_audit",
    "native_store_count",
    "forbidden_x4_audit",
    "qualification_state",
    "overall",
)
CORRECTNESS_FIELDS = (
    "schema",
    "candidate_revision",
    "candidate_tree",
    "backend_policy",
    "backend_version",
    "artifact_sha256",
    "row_schema",
    "facade_receipt_schema",
    "facade_receipt_sha256",
    "facade_performance_raw_schema",
    "facade_performance_raw_sha256",
    "abi2_producer_schema",
    "abi2_producer_sha256",
    "candidate_guard_scope",
    "production_candidate_execution",
    "artifact_witness_matches",
    "host_contract_checked",
    "portable_oracle",
    "kernel_ir_oracle",
    "public_facade",
    "thread_vl_contract_checked",
    "runtime_thread_sve_vector_bytes",
    "publication_sve_vector_bytes",
    "abi2_vector_callee_saved_canary",
    "guard_pages",
    "x4_and_store_audit",
    "native_comparisons",
    "evidence_class",
    "overall",
)
PERFORMANCE_FIELDS = (
    "schema",
    "candidate_revision",
    "candidate_tree",
    "backend_policy",
    "backend_version",
    "artifact_sha256",
    "row_schema",
    "facade_receipt_schema",
    "facade_receipt_sha256",
    "facade_performance_raw_schema",
    "facade_performance_raw_sha256",
    "portable_comparator",
    "hot_gate",
    "full_workload_gate",
    "comparison_direction",
    "confidence_method",
    "hot_upper95_ratio_ppm",
    "full_workload_upper95_ratio_ppm",
    "build_cost_retained",
    "cold_cost_retained",
    "break_even_gate",
    "break_even_max_calls",
    "processes",
    "timed_rows",
    "evidence_class",
    "overall",
)
BUILD_FIELDS = (
    "schema",
    "candidate_revision",
    "candidate_tree",
    "artifact_sha256",
    "abi2_producer_binary_sha256",
    "facade_producer_binary_sha256",
    "source_archive_sha256",
    "source_snapshot_receipt_sha256",
    "target_triple",
    "abi2_producer_features",
    "facade_producer_features",
    "rustflags",
    "release_profile",
    "cargo_incremental",
    "abi2_producer_build_command",
    "facade_producer_build_command",
    "cargo_binary_sha256",
    "rustc_binary_sha256",
    "rustdoc_binary_sha256",
    "toolchain_closure_sha256",
    "toolchain_closure_entries",
    "toolchain_closure_bytes",
    "cargo_registry_closure_sha256",
    "cargo_registry_closure_entries",
    "cargo_registry_closure_bytes",
    "resource_coordinator_sha256",
    "resource_coordinator_cutover_receipt_sha256",
    "profile",
    "evidence_class",
    "overall",
)
SOURCE_FIELDS = (
    "schema",
    "candidate_revision",
    "candidate_tree",
    "candidate_atom_blob",
    "abi2_source_closure_sha256",
    "source_archive_sha256",
    "source_closure_sha256",
    "source_entries",
    "source_file_bytes",
    "source_materialization",
    "source_clean",
    "evidence_class",
    "overall",
)
REVIEW_FIELDS = (
    "schema",
    "candidate_revision",
    "candidate_tree",
    "backend_policy",
    "backend_version",
    "qualification_atom_symbol",
    "bundle_manifest_sha256",
    "subject_sha256",
    "artifact_sha256",
    "artifact_witness_sha256",
    "source_archive_sha256",
    "build_receipt_sha256",
    "source_snapshot_sha256",
    "correctness_verification_sha256",
    "performance_verification_sha256",
    "abi2_source_closure_sha256",
    "public_output",
    "native_output",
    "native_abi",
    "native_arguments",
    "native_return",
    "x4_result_slot",
    "target",
    "target_feature_bits",
    "operating_system_contract",
    "sve_vector_bytes_at_publication",
    "required_thread_sve_vector_bytes",
    "host_contract",
    "row_schema",
    "facade_receipt_schema",
    "facade_receipt_sha256",
    "facade_performance_raw_schema",
    "facade_performance_raw_sha256",
    "abi2_producer_schema",
    "abi2_producer_sha256",
    "abi2_producer_binary_sha256",
    "facade_producer_binary_sha256",
    "evidence_binding_schema",
    "artifact_witness_schema",
    "qualification_state",
    "evidence_class",
    "review_evidence_sha256",
    "overall",
)


class PromotionError(Exception):
    """The proposed source or evidence does not satisfy the closed contract."""


def fail(message: str) -> NoReturn:
    raise PromotionError(message)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def require_hex(value: str, digits: int, label: str) -> None:
    pattern = HEX40 if digits == 40 else HEX64
    if pattern.fullmatch(value) is None:
        fail(f"{label} must be exactly {digits} lowercase hexadecimal digits")


def require_nonzero_sha256(value: str, label: str) -> None:
    require_hex(value, 64, label)
    if value == ZERO_SHA256:
        fail(f"{label} must not be zero")


def require_bundle(value: str, label: str) -> None:
    require_nonzero_sha256(value, label)
    if value in INVALIDATED_BUNDLES:
        fail(f"{label} is explicitly invalidated")


def require_positive_uint(
    value: str, label: str, maximum: Optional[int] = None
) -> int:
    if maximum is None:
        maximum = MAX_CANONICAL_UINT
    maximum_text = str(maximum)
    if (
        UINT.fullmatch(value) is None
        or value == "0"
        or len(value) > len(maximum_text)
        or (len(value) == len(maximum_text) and value > maximum_text)
    ):
        fail(f"{label} must be a positive canonical decimal")
    parsed = int(value)
    return parsed


def require_nonnegative_uint(value: str, label: str, maximum: int) -> int:
    maximum_text = str(maximum)
    if (
        UINT.fullmatch(value) is None
        or len(value) > len(maximum_text)
        or (len(value) == len(maximum_text) and value > maximum_text)
    ):
        fail(f"{label} must be a bounded canonical nonnegative decimal")
    return int(value)


def clean_environment() -> dict[str, str]:
    return {
        "LC_ALL": "C",
        "TZ": "UTC",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
    }


def bounded_process_output(
    process: subprocess.Popen[bytes],
    maximum_stdout: int,
    maximum_stderr: int,
    label: str,
) -> tuple[bytes, bytes, int]:
    assert process.stdout is not None and process.stderr is not None
    streams = {
        process.stdout: ("stdout", maximum_stdout),
        process.stderr: ("stderr", maximum_stderr),
    }
    chunks: dict[str, list[bytes]] = {"stdout": [], "stderr": []}
    totals = {"stdout": 0, "stderr": 0}
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + GIT_QUERY_DEADLINE_SECONDS
    try:
        for stream in streams:
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                fail(f"{label} exceeded its monotonic deadline")
            events = selector.select(remaining)
            if not events:
                fail(f"{label} exceeded its monotonic deadline")
            for key, _events in events:
                stream = key.fileobj
                name, maximum = streams[stream]
                raw = os.read(stream.fileno(), 64 * 1024)
                if not raw:
                    selector.unregister(stream)
                    continue
                totals[name] += len(raw)
                if totals[name] > maximum:
                    fail(f"{label} exceeded its {name} bound")
                chunks[name].append(raw)
        remaining = deadline - time.monotonic()
        if remaining <= 0 and process.poll() is None:
            fail(f"{label} exceeded its monotonic deadline")
        try:
            returncode = process.wait(timeout=max(remaining, 0.001))
        except subprocess.TimeoutExpired:
            fail(f"{label} exceeded its monotonic deadline")
    except BaseException:
        if process.poll() is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=OWNED_CHILD_REAP_SECONDS)
        except subprocess.TimeoutExpired as error:
            raise PromotionError(
                f"{label} did not terminate after its owned child was killed"
            ) from error
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    return (
        b"".join(chunks["stdout"]),
        b"".join(chunks["stderr"]),
        returncode,
    )


def run_git(
    repository: pathlib.Path, *arguments: str, binary: bool = False
) -> Union[bytes, str]:
    command = [
        "/usr/bin/env",
        "-i",
        *[f"{key}={value}" for key, value in clean_environment().items()],
        "/usr/bin/git",
        "-C",
        str(repository),
        *arguments,
    ]
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        output, error_output, returncode = bounded_process_output(
            process, MAX_GIT_OUTPUT, 64 * 1024, "Git query"
        )
    except OSError as error:
        fail(f"cannot execute Git query: {error}")
    if returncode != 0 or error_output:
        detail = error_output[:4096].decode("ascii", "replace").strip()
        fail(f"Git query failed: {detail or arguments[0]}")
    if binary:
        return output
    try:
        return output.decode("ascii").rstrip("\n")
    except UnicodeError as error:
        fail(f"Git output is not ASCII: {error}")


def canonical_directory(argument: str, label: str) -> pathlib.Path:
    path = pathlib.Path(argument)
    if not path.is_absolute():
        fail(f"{label} must be absolute")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve {label}: {error}")
    if (
        resolved != path
        or path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
    ):
        fail(f"{label} must be one physical non-symlink directory")
    return path


def file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def read_regular(
    path: pathlib.Path,
    maximum: int,
    label: str,
    expected_permissions: Optional[int] = None,
) -> bytes:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_CLOEXEC"):
        fail(f"{label} requires O_NOFOLLOW and O_CLOEXEC")
    descriptor = -1
    try:
        named = os.stat(path, follow_symlinks=False)
        descriptor = os.open(
            path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        before = os.fstat(descriptor)
        if (
            file_identity(named) != file_identity(before)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > maximum
            or (
                expected_permissions is not None
                and stat.S_IMODE(before.st_mode) != expected_permissions
            )
        ):
            fail(f"{label} is not one bounded regular single-link file")
        chunks: list[bytes] = []
        offset = 0
        while offset < before.st_size:
            chunk = os.pread(
                descriptor, min(1024 * 1024, before.st_size - offset), offset
            )
            if not chunk:
                fail(f"{label} had a short read")
            chunks.append(chunk)
            offset += len(chunk)
        after = os.fstat(descriptor)
    except OSError as error:
        fail(f"cannot read {label}: {error}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if file_identity(before) != file_identity(after):
        fail(f"{label} changed while being read")
    raw = b"".join(chunks)
    if len(raw) != before.st_size:
        fail(f"{label} changed size while being read")
    return raw


def hash_regular(
    path: pathlib.Path,
    expected_size: int,
    label: str,
    retain: bool = False,
    expected_permissions: Optional[int] = None,
) -> tuple[str, Optional[bytes]]:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_CLOEXEC"):
        fail(f"{label} requires O_NOFOLLOW and O_CLOEXEC")
    descriptor = -1
    try:
        named = os.stat(path, follow_symlinks=False)
        descriptor = os.open(
            path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        before = os.fstat(descriptor)
        if (
            file_identity(named) != file_identity(before)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size != expected_size
            or (
                expected_permissions is not None
                and stat.S_IMODE(before.st_mode) != expected_permissions
            )
        ):
            fail(f"{label} does not have its exact manifest-bound size")
        digest = hashlib.sha256()
        retained: Optional[list[bytes]] = [] if retain else None
        offset = 0
        while offset < expected_size:
            chunk = os.pread(
                descriptor, min(1024 * 1024, expected_size - offset), offset
            )
            if not chunk:
                fail(f"{label} had a short read")
            digest.update(chunk)
            if retained is not None:
                retained.append(chunk)
            offset += len(chunk)
        after = os.fstat(descriptor)
    except OSError as error:
        fail(f"cannot hash {label}: {error}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if file_identity(before) != file_identity(after):
        fail(f"{label} changed while being hashed")
    raw = b"".join(retained) if retained is not None else None
    return digest.hexdigest(), raw


def parse_tsv(
    raw: bytes, fields: tuple[str, ...], schema: str, label: str
) -> dict[str, str]:
    if not raw.endswith(b"\n") or b"\0" in raw or b"\r" in raw:
        fail(f"{label} is not canonical newline-terminated TSV")
    try:
        rows = [line.split("\t") for line in raw.decode("ascii").splitlines()]
    except UnicodeError as error:
        fail(f"{label} is not ASCII: {error}")
    if (
        len(rows) != len(fields)
        or tuple(row[0] if row else "" for row in rows) != fields
        or any(len(row) != 2 or not row[1] for row in rows)
    ):
        fail(f"{label} does not have its exact ordered schema")
    values = dict(rows)
    if values["schema"] != schema:
        fail(f"{label} has the wrong schema")
    return values


def parse_closure_manifest(
    raw: bytes,
    schema: str,
    label: str,
    maximum_entries: int,
) -> tuple[str, int, int, dict[str, tuple[str, int]]]:
    if not raw.endswith(b"\n") or b"\0" in raw or b"\r" in raw:
        fail(f"{label} is not canonical newline-terminated TSV")
    try:
        rows = [line.split("\t") for line in raw.decode("ascii").splitlines()]
    except UnicodeError as error:
        fail(f"{label} is not ASCII: {error}")
    if not rows or rows[0] != ["schema", schema]:
        fail(f"{label} has the wrong schema")
    if len(rows) <= 1 or len(rows) - 1 > maximum_entries:
        fail(f"{label} has the wrong entry count")
    entries: dict[str, tuple[str, int]] = {}
    previous = ""
    total = 0
    for row in rows[1:]:
        if len(row) != 4 or row[0] != "entry":
            fail(f"{label} contains a malformed entry")
        digest, size_text, path = row[1:]
        require_nonzero_sha256(digest, f"{label} entry SHA-256")
        pure_path = pathlib.PurePosixPath(path)
        if (
            SAFE_PATH.fullmatch(path) is None
            or pure_path.as_posix() != path
            or ".." in pure_path.parts
            or path <= previous
        ):
            fail(f"{label} entry violates its closed grammar")
        size = require_nonnegative_uint(
            size_text, f"{label} entry size", MAX_CLOSURE_FILE_BYTES
        )
        total += size
        if total > MAX_CLOSURE_FILE_BYTES:
            fail(f"{label} exceeds its declared byte bound")
        entries[path] = (digest, size)
        previous = path
    return sha256(raw), len(entries), total, entries


def parse_facade_receipt(raw: bytes, artifact_sha256: str) -> None:
    if (
        not raw.endswith(b"\n")
        or raw.count(b"\n") != 1
        or b"\0" in raw
        or b"\r" in raw
    ):
        fail("tag19 facade receipt is not one canonical TSV row")
    try:
        columns = raw[:-1].decode("ascii").split("\t")
    except UnicodeError as error:
        fail(f"tag19 facade receipt is not ASCII: {error}")
    if len(columns) != 1 + len(FACADE_RECEIPT_KEYS):
        fail("tag19 facade receipt does not have its exact V5 field count")
    if columns[0] != FACADE_RECEIPT_SCHEMA:
        fail("tag19 facade receipt is not the tag19-only ABI2 V5 schema")
    parsed: dict[str, str] = {}
    for expected_key, column in zip(FACADE_RECEIPT_KEYS, columns[1:]):
        key, separator, value = column.partition("=")
        if key != expected_key or separator != "=" or not value:
            fail("tag19 facade receipt does not have its exact V5 field set")
        parsed[key] = value
    expected = {
        "case": "tag19_fallback",
        "policy": "Sve16V6",
        "backend": "19",
        "abi": "SelectedEndRegisterV2",
        "qualification": "TestQualified",
        "publication_vl": "none",
        "session_vl": "16",
        "route": "NativeJit",
        "artifact_sha256": artifact_sha256,
        "status": "PASS",
    }
    if parsed != expected:
        fail("tag19 facade receipt is not the exact ABI2 V5 evidence row")


def parse_producer_receipt(
    raw: bytes,
    candidate: str,
    tree: str,
    expected_archive: str,
    expected_build_receipt: str,
    artifact_sha256: str,
) -> dict[str, str]:
    if (
        not raw.endswith(b"\n")
        or raw.count(b"\n") != 1
        or b"\0" in raw
        or b"\r" in raw
    ):
        fail("tag19 ABI2 producer receipt is not one canonical TSV row")
    try:
        columns = raw[:-1].decode("ascii").split("\t")
    except UnicodeError as error:
        fail(f"tag19 ABI2 producer receipt is not ASCII: {error}")
    if len(columns) != 1 + len(PRODUCER_RECEIPT_KEYS):
        fail("tag19 ABI2 producer receipt has the wrong field count")
    if columns[0] != PRODUCER_RECEIPT_SCHEMA:
        fail("tag19 ABI2 producer receipt has the wrong schema")
    parsed: dict[str, str] = {}
    for expected_key, column in zip(PRODUCER_RECEIPT_KEYS, columns[1:]):
        key, separator, value = column.partition("=")
        if key != expected_key or separator != "=" or not value:
            fail("tag19 ABI2 producer receipt has the wrong field set")
        parsed[key] = value
    expected = {
        "candidate": candidate,
        "tree": tree,
        "source_archive_sha256": expected_archive,
        "build_receipt_sha256": expected_build_receipt,
        "profile": QUALIFICATION_PROFILE,
        "backend": "19",
        "abi": "SelectedEndRegisterV2",
        "artifact_sha256": artifact_sha256,
        "target_feature_bits": "3",
        "publication_vl": "none",
        "session_vl": "16",
        "independent_audit": "PASS",
        "store_count": "0",
        "forbidden_x4": "PASS",
        "portable_oracle": "PASS",
        "kernel_ir_oracle": "PASS",
        "guard_pages": "PASS",
        "abi2_vector_callee_saved_canary": "PASS",
        "status": "PASS",
    }
    for field, value in expected.items():
        if parsed[field] != value:
            fail(f"tag19 ABI2 producer receipt has the wrong {field}")
    for field in (
        "resource_coordinator_sha256",
        "resource_cutover_sha256",
    ):
        require_nonzero_sha256(parsed[field], f"producer {field}")
    for field in ("run_id", "instance_id", "instance_type"):
        if SAFE_TOKEN.fullmatch(parsed[field]) is None:
            fail(f"tag19 ABI2 producer has an invalid {field}")
    require_positive_uint(parsed["process_id"], "producer process id", 1 << 31)
    require_nonnegative_uint(parsed["cpu"], "producer CPU", 1_000_000)
    if require_positive_uint(
        parsed["comparisons"], "producer comparison count", 1_000_000_000
    ) != 4102:
        fail("tag19 ABI2 producer did not retain the complete comparison corpus")
    return parsed


def conservative_log_familywise_upper95_ppm(
    ratios: list[Fraction], label: str
) -> int:
    if len(ratios) < 3:
        fail(f"{label} requires at least three paired processes")
    logs = [math.log(float(ratio)) for ratio in ratios]
    mean = sum(logs) / len(logs)
    variance = sum((value - mean) ** 2 for value in logs) / (
        len(logs) - 1
    )
    upper = math.exp(
        mean + BONFERRONI_DF2_CRITICAL * math.sqrt(variance / len(logs))
    )
    if not math.isfinite(upper) or upper <= 0:
        fail(f"{label} produced a non-finite confidence bound")
    return math.ceil(upper * 1_000_000)


def ceil_fraction(value: Fraction) -> int:
    return (value.numerator + value.denominator - 1) // value.denominator


def rotate_left_u64(value: int, count: int) -> int:
    mask = (1 << 64) - 1
    return ((value << count) | (value >> (64 - count))) & mask


def expected_facade_semantic(
    literal_class: str, size: str, scenario: str
) -> int:
    haystack_bytes, _calls = FACADE_SIZES[size]
    if scenario == "late":
        start = haystack_bytes - 16 - 31
        end = start + 16
    elif scenario == "homogeneous" and literal_class == "repeated":
        start = 0
        end = 16
    else:
        return 0
    return (
        rotate_left_u64(start, 17)
        ^ rotate_left_u64(end, 41)
        ^ 0x9E37_79B9_7F4A_7C15
    )


def expected_facade_checksum(semantic: int, iterations: int) -> int:
    mask = (1 << 64) - 1
    checksum = 0x6A09_E667_F3BC_C909
    for iteration in range(iterations):
        term = (iteration * 0x9E37_79B9_7F4A_7C15) & mask
        checksum = rotate_left_u64(checksum, 9) ^ (
            (semantic + term) & mask
        )
    return checksum


def parse_facade_performance(
    raw: bytes,
    candidate: str,
    tree: str,
    canonical_artifact: str,
    producer: dict[str, str],
) -> dict[str, int]:
    if (
        not raw.endswith(b"\n")
        or b"\0" in raw
        or b"\r" in raw
        or b'"' in raw
    ):
        fail("tag19 facade performance CSV is not canonical unquoted ASCII")
    try:
        text = raw.decode("ascii")
        rows = list(csv.reader(io.StringIO(text), strict=True))
    except (UnicodeError, csv.Error) as error:
        fail(f"tag19 facade performance CSV cannot be parsed: {error}")
    if not rows or tuple(rows[0]) != FACADE_PERFORMANCE_FIELDS:
        fail("tag19 facade performance CSV has the wrong exact header")
    if len(rows) > 100_001:
        fail("tag19 facade performance CSV exceeds its row bound")

    cell_rows: dict[
        tuple[int, str, str, str],
        dict[str, dict[str, dict[str, str]]],
    ] = {}
    pid_to_cell: dict[int, tuple[int, str, str, str]] = {}
    cell_to_pid: dict[tuple[int, str, str, str], int] = {}
    pid_to_affinity: dict[int, int] = {}
    observed_row_keys: list[
        tuple[tuple[int, str, str, str], str, str]
    ] = []
    literal_artifacts: dict[str, str] = {}
    provenance: Optional[tuple[str, ...]] = None
    for row in rows[1:]:
        if len(row) != len(FACADE_PERFORMANCE_FIELDS) or any(
            not value for value in row
        ):
            fail("tag19 facade performance CSV has a malformed row")
        record = dict(zip(FACADE_PERFORMANCE_FIELDS, row))
        if (
            record["schema"] != FACADE_PERFORMANCE_SCHEMA
            or record["revision"] != candidate
            or record["tree"] != tree
        ):
            fail("tag19 facade performance row has the wrong source identity")
        literal_class = record["literal_class"]
        if (
            literal_class not in FACADE_LITERAL_HEX
            or record["literal_hex"] != FACADE_LITERAL_HEX[literal_class]
        ):
            fail("tag19 facade performance row has an invalid literal class")
        if record["size"] not in FACADE_SIZES:
            fail("tag19 facade performance row has an invalid size")
        haystack_bytes, calls = FACADE_SIZES[record["size"]]
        if record["scenario"] not in FACADE_SCENARIOS:
            fail("tag19 facade performance row has an invalid scenario")
        repetition = require_nonnegative_uint(
            record["repetition"], "facade repetition", 9_999
        )
        pid = require_positive_uint(record["pid"], "facade process id", 1 << 31)
        affinity_cpu = require_nonnegative_uint(
            record["affinity_cpu"], "facade affinity CPU", 1_000_000
        )
        order = "portable-first" if repetition % 2 == 0 else "facade-first"
        if record["order"] != order:
            fail("tag19 facade performance row has the wrong paired order")
        if record["engine"] not in {"portable", "facade"}:
            fail("tag19 facade performance row has an invalid engine")
        if record["stage"] not in FACADE_STAGES:
            fail("tag19 facade performance row has an invalid stage")
        expected_iterations = {
            "build": 8,
            "search": calls,
            "cold": 1,
            "full": calls,
        }[record["stage"]]
        expected_measured_calls = {
            "build": 0,
            "search": calls,
            "cold": 1,
            "full": calls,
        }[record["stage"]]
        iterations = require_positive_uint(
            record["iterations"], "facade iterations", 1_000_000_000
        )
        total_ns = require_positive_uint(
            record["total_ns"], "facade total nanoseconds", 10**18
        )
        ns_per_iter = require_positive_uint(
            record["ns_per_iter"], "facade ns per iteration", 10**18
        )
        if (
            iterations != expected_iterations
            or ns_per_iter != total_ns // iterations
            or record["haystack_bytes"] != str(haystack_bytes)
            or record["declared_min_window_bytes"] != str(haystack_bytes)
            or record["declared_min_calls"] != str(calls)
            or record["measured_calls"] != str(expected_measured_calls)
            or HEX_U64.fullmatch(record["checksum"]) is None
            or HEX_U64.fullmatch(record["semantic_value"]) is None
        ):
            fail("tag19 facade performance row violates its measured contract")
        if record["qualification_state"] != "candidate":
            fail("tag19 facade raw evidence did not use the Candidate guard")
        if record["engine"] == "portable":
            if (
                record["route"] != "portable-literal"
                or record["backend"] != "portable"
                or record["artifact_sha256"] != "none"
            ):
                fail("portable facade row has a native identity")
        else:
            if (
                record["route"] != "native-jit"
                or record["backend"] != "aarch64-search-v19"
            ):
                fail("tag19 facade row did not execute NativeJit backend 19")
            require_nonzero_sha256(
                record["artifact_sha256"], "facade artifact SHA-256"
            )
            prior = literal_artifacts.setdefault(
                literal_class, record["artifact_sha256"]
            )
            if prior != record["artifact_sha256"]:
                fail("tag19 facade artifact changed within one literal class")
        for field in (
            "run_id",
            "instance_id",
            "instance_type",
        ):
            if SAFE_TOKEN.fullmatch(record[field]) is None:
                fail(f"tag19 facade row has an invalid {field}")
        for field in (
            "resource_coordinator_sha256",
            "resource_cutover_sha256",
        ):
            require_nonzero_sha256(record[field], f"facade {field}")
        current_provenance = (
            record["run_id"],
            record["instance_id"],
            record["instance_type"],
            record["resource_coordinator_sha256"],
            record["resource_cutover_sha256"],
            record["profile"],
        )
        if provenance is None:
            provenance = current_provenance
        elif provenance != current_provenance:
            fail("tag19 facade rows do not share one run/provenance identity")
        if (
            record["profile"] != QUALIFICATION_PROFILE
            or record["run_id"] != producer["run_id"]
            or record["instance_id"] != producer["instance_id"]
            or record["instance_type"] != producer["instance_type"]
            or record["resource_coordinator_sha256"]
            != producer["resource_coordinator_sha256"]
            or record["resource_cutover_sha256"]
            != producer["resource_cutover_sha256"]
        ):
            fail("tag19 facade and ABI2 producer provenance differ")

        cell = (repetition, literal_class, record["size"], record["scenario"])
        previous_cell = pid_to_cell.setdefault(pid, cell)
        if previous_cell != cell:
            fail("one facade process produced more than one timed cell")
        previous_pid = cell_to_pid.setdefault(cell, pid)
        if previous_pid != pid:
            fail("one facade timed cell was assembled from multiple processes")
        previous_affinity = pid_to_affinity.setdefault(pid, affinity_cpu)
        if previous_affinity != affinity_cpu:
            fail("one facade process reported multiple timing CPUs")
        engines = cell_rows.setdefault(cell, {})
        stages = engines.setdefault(record["stage"], {})
        if record["engine"] in stages:
            fail("tag19 facade performance CSV contains a duplicate pair row")
        stages[record["engine"]] = record
        observed_row_keys.append((cell, record["engine"], record["stage"]))

    if not cell_rows:
        fail("tag19 facade performance CSV contains no measurements")
    repetitions = sorted({cell[0] for cell in cell_rows})
    if repetitions != list(range(len(repetitions))) or len(repetitions) < 3:
        fail("tag19 facade repetitions are not contiguous from zero")
    expected_cells = {
        (repetition, literal, size, scenario)
        for repetition in repetitions
        for literal in FACADE_LITERAL_HEX
        for size in FACADE_SIZES
        for scenario in FACADE_SCENARIOS
    }
    if set(cell_rows) != expected_cells:
        fail("tag19 facade performance CSV omits or adds a matrix cell")
    expected_row_keys = [
        (
            (repetition, literal, size, scenario),
            engine,
            stage,
        )
        for repetition in repetitions
        for literal in FACADE_LITERAL_HEX
        for size in FACADE_SIZES
        for scenario in FACADE_SCENARIOS
        for engine, stage in (
            ("portable", "build"),
            ("facade", "build"),
            ("portable", "search"),
            ("facade", "search"),
            ("portable", "cold"),
            ("facade", "cold"),
            ("portable", "full"),
            ("facade", "full"),
        )
    ]
    if observed_row_keys != expected_row_keys:
        fail("tag19 facade rows are not in their exact canonical matrix order")
    if (
        len(pid_to_cell) != len(cell_rows)
        or len(cell_to_pid) != len(cell_rows)
        or set(pid_to_cell) != set(pid_to_affinity)
    ):
        fail("tag19 facade timed cells and processes are not bijective")
    if literal_artifacts.get("unique") != canonical_artifact:
        fail("canonical tag19 facade artifact differs from the ABI2 subject")
    if set(literal_artifacts) != set(FACADE_LITERAL_HEX):
        fail("tag19 facade rows omit a literal-specific artifact")
    if len(set(literal_artifacts.values())) != len(FACADE_LITERAL_HEX):
        fail("tag19 facade literal-specific artifacts are not distinct")

    ratios: dict[
        tuple[str, str, str, str], list[Fraction]
    ] = {}
    break_even = 0
    for cell, stages in cell_rows.items():
        if set(stages) != set(FACADE_STAGES) or any(
            set(pair) != {"portable", "facade"} for pair in stages.values()
        ):
            fail("tag19 facade cell does not contain all exact engine/stage pairs")
        _, literal, size, scenario = cell
        semantic = expected_facade_semantic(literal, size, scenario)
        expected_semantic = f"0x{semantic:016x}"
        for stage, pair in stages.items():
            portable = pair["portable"]
            facade = pair["facade"]
            if (
                portable["semantic_value"] != expected_semantic
                or facade["semantic_value"] != expected_semantic
            ):
                fail("tag19 facade row has the wrong deterministic semantic value")
            if stage in {"search", "cold", "full"}:
                iterations = int(portable["iterations"])
                expected_checksum = (
                    f"0x{expected_facade_checksum(semantic, iterations):016x}"
                )
                if (
                    portable["checksum"] != expected_checksum
                    or facade["checksum"] != expected_checksum
                ):
                    fail("tag19 facade row has the wrong deterministic checksum")
        for stage in ("search", "full"):
            pair = stages[stage]
            ratio = Fraction(
                int(pair["facade"]["total_ns"]),
                int(pair["portable"]["total_ns"]),
            )
            ratios.setdefault((stage, literal, size, scenario), []).append(
                ratio
            )
        cold = stages["cold"]
        search = stages["search"]
        cold_delta = int(cold["facade"]["total_ns"]) - int(
            cold["portable"]["total_ns"]
        )
        saving = Fraction(
            int(search["portable"]["total_ns"])
            - int(search["facade"]["total_ns"]),
            int(search["portable"]["iterations"]),
        )
        if saving <= 0:
            fail("a tag19 facade cell has no positive measured hot saving")
        cell_break_even = (
            1
            if cold_delta <= 0
            else 1 + ceil_fraction(Fraction(cold_delta, 1) / saving)
        )
        _haystack_bytes, declared_calls = FACADE_SIZES[size]
        if cell_break_even > declared_calls:
            fail("a tag19 facade cell does not break even within its workload")
        break_even = max(break_even, cell_break_even)

    upper_by_stage: dict[str, int] = {}
    for stage in ("search", "full"):
        bounds = [
            conservative_log_familywise_upper95_ppm(
                values, f"{stage} {key[1:]}"
            )
            for key, values in ratios.items()
            if key[0] == stage
        ]
        if len(bounds) != PER_STAGE_FAMILYWISE_CELLS:
            fail(f"tag19 facade {stage} does not contain exactly 48 cells")
        upper_by_stage[stage] = max(bounds)
        if upper_by_stage[stage] >= 1_000_000:
            fail(f"tag19 facade {stage} upper95 is not below portable")
    return {
        "hot_upper95_ratio_ppm": upper_by_stage["search"],
        "full_workload_upper95_ratio_ppm": upper_by_stage["full"],
        "break_even_max_calls": break_even,
        "processes": len(cell_to_pid),
        "timed_rows": len(rows) - 1,
    }


def git_entry(
    repository: pathlib.Path,
    revision: str,
    path: str,
    expected_mode: str,
    label: str,
) -> str:
    entry = run_git(repository, "ls-tree", revision, "--", path)
    assert isinstance(entry, str)
    try:
        metadata, observed = entry.split("\t")
        mode, kind, object_id = metadata.split(" ")
    except ValueError as error:
        fail(f"{label} is not one Git blob: {error}")
    if (
        observed != path
        or mode != expected_mode
        or kind != "blob"
        or HEX40.fullmatch(object_id) is None
    ):
        fail(f"{label} has the wrong Git identity or mode")
    return object_id


def git_blob(
    repository: pathlib.Path,
    revision: str,
    path: str,
    expected_mode: str,
    maximum: int,
    label: str,
) -> tuple[str, bytes]:
    object_id = git_entry(
        repository, revision, path, expected_mode, label
    )
    size = run_git(repository, "cat-file", "-s", object_id)
    assert isinstance(size, str)
    parsed_size = require_positive_uint(size, f"{label} size", maximum)
    raw = run_git(repository, "cat-file", "blob", object_id, binary=True)
    assert isinstance(raw, bytes)
    if len(raw) != parsed_size:
        fail(f"{label} changed during Git extraction")
    return object_id, raw


def validate_repository(
    repository: pathlib.Path,
    candidate: str,
    promoted: str,
    expected_tree: str,
) -> str:
    for value, label in ((candidate, "Candidate"), (promoted, "promoted")):
        require_hex(value, 40, f"{label} commit")
        resolved = run_git(
            repository, "rev-parse", "--verify", f"{value}^{{commit}}"
        )
        if resolved != value:
            fail(f"{label} commit did not resolve exactly")
    require_hex(expected_tree, 40, "expected Candidate tree")
    if candidate == promoted:
        fail("Candidate and promoted commits must differ")
    if run_git(repository, "rev-parse", "--is-shallow-repository") != "false":
        fail("promotion requires complete non-shallow history")
    graft = run_git(repository, "rev-parse", "--git-path", "info/grafts")
    assert isinstance(graft, str)
    graft_path = pathlib.Path(graft)
    if not graft_path.is_absolute():
        graft_path = repository / graft_path
    if graft_path.exists() or graft_path.is_symlink():
        fail("repository contains an info/grafts override")
    if run_git(
        repository, "for-each-ref", "--format=%(refname)", "refs/replace"
    ):
        fail("repository contains replacement refs")
    if run_git(repository, "show", "-s", "--format=%P", promoted) != candidate:
        fail("promotion must be the Candidate's sole direct child")
    tree = run_git(repository, "show", "-s", "--format=%T", candidate)
    assert isinstance(tree, str)
    if tree != expected_tree:
        fail("Candidate tree differs from its external pin")
    return tree


def source_closure(
    repository: pathlib.Path, candidate: str
) -> tuple[str, dict[str, bytes]]:
    lines: list[bytes] = []
    raw_by_path: dict[str, bytes] = {}
    for path in ABI2_SOURCE_PATHS:
        object_id, raw = git_blob(
            repository,
            candidate,
            path,
            "100644",
            4 * 1024 * 1024,
            f"Candidate ABI2 source {path}",
        )
        lines.append(f"100644 blob {object_id}\t{path}\n".encode("ascii"))
        raw_by_path[path] = raw
    digest = sha256(b"".join(sorted(lines, key=lambda row: row.split(b"\t", 1)[1])))
    if digest != ABI2_SOURCE_CLOSURE_SHA256:
        fail("Candidate tag19 ABI2 source closure is not the reviewed closure")
    return digest, raw_by_path


def require_source_marker(
    raw_by_path: dict[str, bytes], path: str, marker: bytes
) -> None:
    if marker not in raw_by_path[path]:
        fail(f"Candidate ABI2 source contract is missing a marker in {path}")


def reject_source_marker(
    raw_by_path: dict[str, bytes], path: str, marker: bytes
) -> None:
    if marker in raw_by_path[path]:
        fail(f"Candidate ABI2 source contract retains a forbidden marker in {path}")


def bounded_source_region(
    raw_by_path: dict[str, bytes],
    path: str,
    start_marker: bytes,
    end_marker: bytes,
    label: str,
) -> bytes:
    raw = raw_by_path[path]
    start = raw.find(start_marker)
    if start < 0:
        fail(f"Candidate ABI2 source contract omits {label} start in {path}")
    end = raw.find(end_marker, start + len(start_marker))
    if end < 0:
        fail(f"Candidate ABI2 source contract omits {label} end in {path}")
    return raw[start:end]


def validate_source_contract(raw_by_path: dict[str, bytes]) -> None:
    abi = "crates/fre-jit-aarch64/src/abi.rs"
    selected = "crates/fre-jit-aarch64/src/selected_end_v2.rs"
    selected_tests = "crates/fre-jit-aarch64/src/tests_selected_end_v2.rs"
    audit = "crates/fre-jit-aarch64/src/audit.rs"
    runtime_manifest = "crates/fre-jit-runtime/Cargo.toml"
    producer = (
        "crates/fre-jit-runtime/examples/"
        "tag19_selected_end_register_v2_qualification.rs"
    )
    platform = "crates/fre-jit-runtime/src/platform/aarch64.rs"
    linux_platform = "crates/fre-jit-runtime/src/platform/linux_aarch64.rs"
    runtime = "crates/fre-jit-runtime/src/selected_end_register_v2.rs"
    cache_manifest = "crates/fre-jit-cache/Cargo.toml"
    cache = "crates/fre-jit-cache/src/cache.rs"
    cache_tests = "crates/fre-jit-cache/src/tests.rs"
    target_features = "crates/fre-target-features/src/lib.rs"
    kernels = "crates/fre-kernels/src/lib.rs"
    facade = "crates/fre/src/qualified_exact_search.rs"
    facade_producer = (
        "crates/fre/src/"
        "qualified_exact_search_tag21_facade_qualification.rs"
    )
    for marker in (
        b"pub const HAYSTACK_BASE: Register = Register::new(0);",
        b"pub const HAYSTACK_LEN: Register = Register::new(1);",
        b"pub const WINDOW_START: Register = Register::new(2);",
        b"pub const WINDOW_END: Register = Register::new(3);",
        b"pub const END_OR_ZERO: Register = Register::new(0);",
    ):
        require_source_marker(raw_by_path, abi, marker)
    require_source_marker(
        raw_by_path,
        selected,
        b"Sve16V6Tag19Vl16 => BackendVersion::SEARCH_SVE16_V6",
    )
    for marker in (
        b"pub const fn selected_end_register_target_v2(",
        b"if (anchors.start || anchors.end) && literal_bytes < 16",
        b"features: CpuFeatures::NONE",
        b"TargetSpec::AARCH64_AAPCS64_SVE16",
        b"TargetSpec::AARCH64_AAPCS64_SVE2_16",
    ):
        require_source_marker(raw_by_path, selected, marker)
    for marker in (
        b"selected_end_register_v2_v8_authenticates_every_exact_anchor_shape",
        b"assert_eq!(image.anchors(), anchors);",
        b"selected_end_register_target_v2(SelectedEndRegisterBackendV2::AsimdV8, anchors, 6)",
        b"CpuFeatures::NONE",
        b"CpuFeatures::ASIMD",
    ):
        require_source_marker(raw_by_path, selected_tests, marker)
    require_source_marker(
        raw_by_path,
        audit,
        b"StoreContract::SelectedEndRegisterV2 && instruction.uses_gpr(4)",
    )
    require_source_marker(
        raw_by_path,
        platform,
        b'unsafe extern "C" fn(*const u8, usize, usize, usize) -> usize;',
    )
    for marker in (
        b"define_selected_end_register_v2_vector_callee_saved_canary!",
        b"mov x19, x5",
        b"mov x3, x4",
        b"mov x4, xzr",
        b"mov x5, xzr",
        b"mov x6, xzr",
        b"mov x7, xzr",
        b"fre_jit_test_selected_end_register_v2_vector_callee_saved_canary(",
    ):
        require_source_marker(raw_by_path, platform, marker)
    for marker in (
        b"const PR_SVE_GET_VL: libc::c_int = 51;",
        b"libc::prctl(PR_SVE_GET_VL, 0, 0, 0, 0)",
        b"query only while opening its current-thread session",
    ):
        require_source_marker(raw_by_path, linux_platform, marker)
    for marker in (
        b"SelectedEndRegisterBackendV2::Sve16V6Tag19Vl16",
        b"CpuFeatures::ASIMD_SVE",
        b"LiteralIdentityMismatch",
        b"preflight.was_issued_by(literal_plan)",
        b"qualification_validated_thread_sve_vector_bytes",
        b"qualification_preserves_abi2_vector_callee_saved_lanes",
    ):
        require_source_marker(raw_by_path, runtime, marker)
    for marker in (
        b"sve-hardware-qualification = []",
        b"used only by source-bound hardware qualification",
        b"It remains default-off.",
    ):
        require_source_marker(raw_by_path, runtime_manifest, marker)
    require_source_marker(raw_by_path, kernels, b"pub fn was_issued_by(")
    for marker in (
        b"fre-jit-aarch64 = { path = \"../fre-jit-aarch64\" }",
        b"fre-jit-runtime = { path = \"../fre-jit-runtime\" }",
        b"fre-kernel-ir = { path = \"../fre-kernel-ir\" }",
    ):
        require_source_marker(raw_by_path, cache_manifest, marker)
    for marker in (
        b"pub struct SelectedEndRegisterCacheV2",
        b"pub struct SelectedEndRegisterLeaseV2",
        b"pub fn kernel(&self) -> &PublishedSelectedEndRegisterV2",
        b"pub fn get_or_compile_exact_literal(",
        b"SelectedEndRegisterCompileRequestV2::new(",
        b"compile_selected_end_register_request_v2(request, publication_limits)",
        b"build_exact_literal::<SelectedEnd>(",
        b"emit_selected_end_register_v2(&program, request.backend",
        b"publish_selected_end_register_v2(&image, publication_limits)",
        b"drop(publication);",
        b"state.remove_live(identity, self.token, accounting);",
    ):
        require_source_marker(raw_by_path, cache, marker)
    for marker in (
        b"tracked_drop_unmaps_before_releasing_accounting_or_waiters",
        b"aggregate_refusal_unmaps_before_releasing_flight_or_waiters",
        b"assert!(unmap < release);",
        b"assert!(release < wake);",
    ):
        require_source_marker(raw_by_path, cache_tests, marker)
    for marker in (
        b"implementer: 0x41,",
        b"part: 0x0d84,",
    ):
        require_source_marker(raw_by_path, target_features, marker)
    require_source_marker(
        raw_by_path,
        facade,
        b"Some(SelectedEndRegisterBackendV2::Sve16V6Tag19Vl16)",
    )
    require_source_marker(
        raw_by_path,
        facade,
        b"fre-jit-auto-facade-v5\\tcase=tag19_fallback"
        b"\\tpolicy=Sve16V6\\tbackend=19\\tabi=SelectedEndRegisterV2",
    )
    require_source_marker(
        raw_by_path,
        facade,
        b"QualifiedExactSearchBackendPolicy::Sve2Fixed16\n    )",
    )
    for marker in (
        b"static DEFAULT_SELECTED_END_REGISTER_CACHE_V2: OnceLock<",
        b"if publication_limits == PublicationLimits::default()",
        b"cache.get_or_compile_exact_literal(",
        b"QualifiedExactSearchRegisterV2Owner::Cached(lease)",
        b"Self::Cached(lease) => lease.kernel()",
        b"QualifiedExactSearchNativeStatus::CacheUnavailable(",
        b"fn with_portable_plan_backend_qualification_and_cache(",
        b"selected_end_register_cache: Option<&SelectedEndRegisterCacheV2>",
        b"Some(cache) => Ok(cache)",
        b"fn from_builder_with_fresh_cache_for_qualification(",
        b"assert!(host_gate < cache_lookup);",
        b"assert!(cache_lookup < direct_kernel_ir);",
    ):
        require_source_marker(raw_by_path, facade, marker)
    for marker in (
        b"#[cfg(test)]\n#[derive(Debug)]\n"
        b"struct QualificationCandidateExecutionPermit {",
        b"struct QualificationCandidateExecutionPermit {",
        b"_thread_bound: core::marker::PhantomData<std::rc::Rc<()>>",
        b"impl Drop for QualificationCandidateExecutionPermit",
        b"#[cfg(test)]\n#[derive(Debug)]\n"
        b"enum QualificationSessionAuthority<'session> {",
        b"#[cfg(test)]\n#[derive(Debug)]\n"
        b"struct QualifiedExactSearchFacadeQualificationThreadSession<'session>",
        b"struct QualifiedExactSearchFacadeQualificationThreadSession<'session>",
        b"authority: QualificationSessionAuthority<'session>",
        b"_permit: &'session QualificationCandidateExecutionPermit",
        b"fn begin_current_thread_session_authorized_by(",
        b"authorize_native: impl FnOnce() -> bool",
        b"&& authorize_native()",
        b"|| self.search.retained_native_execution_authorized(),",
        b"preflight.searched_bytes() >= self.report.workload.minimum_window_bytes()",
        b"native.search_preflighted(preflight)?",
    ):
        require_source_marker(raw_by_path, facade, marker)
    qualification_begin = bounded_source_region(
        raw_by_path,
        facade,
        b"fn begin_current_thread_session_for_qualification<'session>(",
        b"\n    /// Find the first match in the complete haystack.",
        "qualification session constructor",
    )
    for marker in (
        b"candidate_permit.expect(",
        b"permit.assert_active();",
        b"QualificationSessionAuthority::Candidate { _permit: permit }",
        b"candidate_permit.is_none()",
        b"let session = self.begin_current_thread_session_authorized_by(|_| true)?;",
    ):
        if marker not in qualification_begin:
            fail("Candidate qualification session constructor lost its sealed authority")
    if qualification_begin.find(b"permit.assert_active();") >= qualification_begin.find(
        b"let session = self.begin_current_thread_session_authorized_by(|_| true)?;"
    ):
        fail("Candidate qualification permit is not checked before session creation")
    if (
        b"TEST_CANDIDATE_EXECUTION" in qualification_begin
        or b"self.begin_current_thread_session()?" in qualification_begin
    ):
        fail("Candidate qualification session repeats dynamic authorization")
    facade_session = bounded_source_region(
        raw_by_path,
        facade,
        b"impl QualifiedExactSearchFacadeThreadSession<'_> {",
        (
            b"\n#[cfg(test)]\n"
            b"impl QualifiedExactSearchFacadeQualificationThreadSession<'_> {"
        ),
        "facade session projection",
    )
    for marker in (
        b"fn find_window_projected_authorized_by<R>(",
        b"|search| search.search.retained_native_execution_authorized(),",
        b"QualifiedExactSearchFacadeThreadSessionPlan::ExactLiteral(search)",
        b"search\n                .find_window_projected_authorized_by(",
        b"QualifiedExactSearchFacadeThreadSessionPlan::Portable(portable)",
    ):
        if marker not in facade_session:
            fail("production facade session projection lost its sealed shared body")
    if facade_session.count(b"fn find_window_projected_authorized_by<R>(") != 1:
        fail("production facade session projection is ambiguous")
    qualification_call = bounded_source_region(
        raw_by_path,
        facade,
        b"impl QualifiedExactSearchFacadeQualificationThreadSession<'_> {",
        b"\n#[cfg(test)]\nmod tests {",
        "qualification value projection",
    )
    for marker in (
        b"self.session.find(haystack, limits)",
        b"let _authority = &self.authority;",
        b"self.session.find_window_projected_authorized_by(",
        b"\n            |_| true,",
    ):
        if marker not in qualification_call:
            fail("qualification value projection lost its shared production path")
    if (
        b"retained_native_execution_authorized" in qualification_call
        or b"TEST_CANDIDATE_EXECUTION" in qualification_call
    ):
        fail("qualification timed projection repeats dynamic authorization")
    core_search = bounded_source_region(
        raw_by_path,
        facade,
        b"    fn find_window_with_native<R>(",
        b"\n    /// Whether a selected match exists in the complete haystack.",
        "exact-search projected body",
    )
    for marker in (
        b"authorize_native: impl FnOnce() -> bool",
        b"&& authorize_native()",
        b"NativeCheckedSearchWindow::new(",
        b".preflight_checked_window(checked_window, literal_limits)?",
        b"preflight.searched_bytes() >= self.report.workload.minimum_window_bytes()",
        b"native.search_preflighted(preflight)?",
        b"let matched = preflight.find()?;",
        b"self.portable\n                .find_window(",
    ):
        if marker not in core_search:
            fail("exact-search projected body lost a safety or fallback boundary")
    if b"retained_native_execution_authorized" in core_search:
        fail("exact-search projected body reacquired dynamic authorization")
    for marker in (
        PRODUCER_RECEIPT_SCHEMA.encode("ascii"),
        b"const RANDOM_CASES: usize = 4096;",
        b"emit_selected_end_register_v2(",
        b"audit_selected_end_register_v2(&image)?",
        b"qualification_validated_thread_sve_vector_bytes()",
        b"guard_page_checks(&portable, &session)?",
        b"let canary_cases = [",
        b"qualification_preserves_abi2_vector_callee_saved_lanes(",
        b'fs::read_to_string("/proc/thread-self/status")?',
        b"comparisons={comparisons}",
    ):
        require_source_marker(raw_by_path, producer, marker)
    for marker in (
        FACADE_PERFORMANCE_SCHEMA.encode("ascii"),
        ",".join(FACADE_PERFORMANCE_FIELDS).encode("ascii"),
        b"struct CandidateExecutionGuard {",
        b"permit: QualificationCandidateExecutionPermit",
        b"QualificationCandidateExecutionPermit::acquire()",
        b"fn permit(&self) -> &QualificationCandidateExecutionPermit",
        b"CandidateExecutionGuard::acquire_for(qualification)",
        b"let candidate_permit = guard.as_ref().map(CandidateExecutionGuard::permit);",
        b".begin_current_thread_session_for_qualification(candidate_permit)",
        b"QualifiedExactSearchFacadeQualificationThreadSession<'_>",
        b".find_value(black_box(haystack), SearchLimits::unlimited())",
        b"QualifiedExactSearchRoute::NativeJit",
        b'fs::read_to_string("/proc/thread-self/status")',
        b"sole_thread_affinity_cpu()",
        b"tag19 facade timing-thread affinity changed during measurement",
        b"fn build_fresh_cache_facade(",
        b"SelectedEndRegisterCacheV2::new(CacheLimits::default(), PublicationLimits::default())",
        b"QualifiedExactSearchFacade::from_builder_with_fresh_cache_for_qualification(",
        b"let (cache, facade) = build_fresh_cache_facade(subject, case, size);",
        b"let (cache, cold) = build_fresh_cache_facade(subject, case, size);",
        b"assert!(full_elapsed < full_session_scope_end);",
        b"assert!(full_session_scope_end < full_facade_drop);",
        b"assert!(full_facade_drop < full_cache_drop);",
        b'assert!(build.contains("drop(cold);"));',
        b'assert!(build.contains("drop(cache);"));',
        b'assert!(!hot.contains("candidate_permit"));',
        b"assert!(active < hoisted_begin);",
    ):
        require_source_marker(raw_by_path, facade_producer, marker)
    for forbidden in (
        b"fre-jit-tag19-facade-performance-v4",
        b"fre-jit-tag19-facade-performance-v3",
        b"fre-jit-tag19-facade-performance-v2",
        b"struct CandidateExecutionGuard;",
        b"impl Drop for CandidateExecutionGuard",
        b"enabled.replace(true)",
    ):
        reject_source_marker(raw_by_path, facade_producer, forbidden)
    reject_source_marker(
        raw_by_path,
        producer,
        b"fre-jit-sve-hardware-qualification-v",
    )


def validate_running_candidate(
    repository: pathlib.Path, candidate: str
) -> tuple[str, str, str]:
    verifier_blob, verifier_raw = git_blob(
        repository,
        candidate,
        VERIFIER_PATH,
        "100755",
        512 * 1024,
        "Candidate tag19 promotion verifier",
    )
    running = read_regular(
        pathlib.Path(sys.argv[0]),
        512 * 1024,
        "running tag19 promotion verifier",
        expected_permissions=0o755,
    )
    if running != verifier_raw:
        fail("running verifier differs from the exact Candidate blob")
    atom_blob, atom_raw = git_blob(
        repository,
        candidate,
        ATOM_PATH,
        "100644",
        64 * 1024,
        "Candidate qualification atom",
    )
    if atom_blob != CANDIDATE_ATOM_BLOB or atom_raw != CANDIDATE_ATOM:
        fail("Candidate atom is not the exact four-Candidate root")
    closure, raw_by_path = source_closure(repository, candidate)
    validate_source_contract(raw_by_path)
    return verifier_blob, atom_blob, closure


def inventory(root: pathlib.Path) -> tuple[tuple[str, ...], tuple[str, ...]]:
    paths: list[str] = []
    directory_paths: list[str] = []
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = pathlib.Path(current)
        for name in directories:
            child = current_path / name
            relative = child.relative_to(root).as_posix()
            metadata = child.lstat()
            if (
                child.is_symlink()
                or not stat.S_ISDIR(metadata.st_mode)
                or SAFE_PATH.fullmatch(relative) is None
                or ".." in pathlib.PurePosixPath(relative).parts
            ):
                fail("qualification bundle contains a noncanonical directory")
            directory_paths.append(relative)
            if len(paths) + len(directory_paths) > MAX_ENTRIES:
                fail("qualification bundle exceeds its entry bound")
        for name in files:
            child = current_path / name
            relative = child.relative_to(root).as_posix()
            metadata = child.lstat()
            if (
                SAFE_PATH.fullmatch(relative) is None
                or ".." in pathlib.PurePosixPath(relative).parts
                or child.is_symlink()
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
            ):
                fail("qualification bundle contains a noncanonical file")
            paths.append(relative)
            if len(paths) + len(directory_paths) > MAX_ENTRIES:
                fail("qualification bundle exceeds its entry bound")
    return tuple(sorted(paths)), tuple(sorted(directory_paths))


def parse_manifest(
    raw: bytes, candidate: str, tree: str
) -> list[tuple[str, str, int, str]]:
    if not raw.endswith(b"\n") or b"\0" in raw or b"\r" in raw:
        fail("bundle manifest is not canonical")
    try:
        rows = [
            line.split("\t") for line in raw.decode("ascii").splitlines()
        ]
    except UnicodeError as error:
        fail(f"bundle manifest is not ASCII: {error}")
    expected_prefix = (
        ("schema", "fre-jit-tag19-abi2-qualification-bundle-v1"),
        ("candidate_revision", candidate),
        ("candidate_tree", tree),
        ("backend_policy", "Sve16V6"),
        ("backend_version", "19"),
        ("evidence_class", "measured"),
    )
    if tuple(tuple(row) for row in rows[:6]) != expected_prefix:
        fail("bundle manifest has the wrong source/backend prefix")
    entries: list[tuple[str, str, int, str]] = []
    previous = ""
    allowed_kinds = {
        "subject",
        "witness",
        "correctness",
        "performance",
        "build",
        "closure",
        "source",
        "source-archive",
        "producer-binary",
        "evidence",
    }
    for row in rows[6:]:
        if len(row) != 5 or row[0] != "entry":
            fail("bundle manifest contains a malformed entry")
        kind, digest, size_text, path = row[1:]
        require_nonzero_sha256(digest, "bundle entry SHA-256")
        if (
            kind not in allowed_kinds
            or SAFE_PATH.fullmatch(path) is None
            or path <= previous
            or path in {BUNDLE_MANIFEST, BUNDLE_DIGEST}
            or ".." in pathlib.PurePosixPath(path).parts
        ):
            fail("bundle manifest entry violates its closed grammar")
        size = require_positive_uint(
            size_text, "bundle entry size", MAX_FILE_BYTES
        )
        previous = path
        entries.append((kind, digest, size, path))
    required = {
        ("subject", "subject.tsv"),
        ("witness", "artifacts/abi2-witness.tsv"),
        ("correctness", "verification/correctness.tsv"),
        ("performance", "verification/performance.tsv"),
        ("build", "provenance/build-receipt.tsv"),
        ("closure", TOOLCHAIN_CLOSURE_PATH),
        ("closure", REGISTRY_CLOSURE_PATH),
        ("source", "provenance/source-snapshot.tsv"),
        ("source-archive", "provenance/source.tar.gz"),
        ("producer-binary", ABI2_PRODUCER_BINARY_PATH),
        ("producer-binary", FACADE_PRODUCER_BINARY_PATH),
        ("evidence", PRODUCER_RECEIPT_PATH),
        ("evidence", FACADE_RECEIPT_PATH),
        ("evidence", FACADE_PERFORMANCE_PATH),
        ("evidence", "evidence/review-findings.txt"),
    }
    observed = {(kind, path) for kind, _digest, _size, path in entries}
    if not required.issubset(observed):
        fail("bundle manifest omits a required tag19 ABI2 component")
    required_small = {
        "subject.tsv",
        "artifacts/abi2-witness.tsv",
        "verification/correctness.tsv",
        "verification/performance.tsv",
        "provenance/build-receipt.tsv",
        "provenance/source-snapshot.tsv",
        PRODUCER_RECEIPT_PATH,
        FACADE_RECEIPT_PATH,
        FACADE_PERFORMANCE_PATH,
    }
    for _kind, _digest, size, path in entries:
        if path in required_small and size > SMALL_RECEIPT_BYTES:
            fail(f"required receipt exceeds its parse bound: {path}")
        if (
            path in {TOOLCHAIN_CLOSURE_PATH, REGISTRY_CLOSURE_PATH}
            and size > CLOSURE_RECEIPT_BYTES
        ):
            fail(f"closure manifest exceeds its parse bound: {path}")
    return entries


def validate_bundle(
    root: pathlib.Path,
    candidate: str,
    tree: str,
    expected_archive: str,
    expected_receipt: str,
    expected_manifest: str,
) -> tuple[str, dict[str, str], dict[str, str]]:
    require_nonzero_sha256(expected_archive, "expected source archive SHA-256")
    require_nonzero_sha256(
        expected_receipt, "expected build receipt SHA-256"
    )
    require_bundle(expected_manifest, "expected evidence manifest SHA-256")
    manifest_raw = read_regular(
        root / BUNDLE_MANIFEST,
        4 * 1024 * 1024,
        "bundle manifest",
        expected_permissions=0o644,
    )
    manifest_sha = sha256(manifest_raw)
    if manifest_sha != expected_manifest:
        fail("bundle manifest differs from its external identity")
    digest_raw = read_regular(
        root / BUNDLE_DIGEST,
        128,
        "BUNDLE.sha256",
        expected_permissions=0o644,
    )
    if digest_raw != f"{expected_manifest}\n".encode("ascii"):
        fail("BUNDLE.sha256 does not name the externally pinned manifest")
    entries = parse_manifest(manifest_raw, candidate, tree)
    declared_total = sum(entry[2] for entry in entries)
    if declared_total > MAX_TOTAL_BYTES:
        fail("qualification bundle exceeds its total byte bound")
    expected_inventory = tuple(
        sorted([BUNDLE_DIGEST, BUNDLE_MANIFEST, *[entry[3] for entry in entries]])
    )
    expected_directories = {
        parent.as_posix()
        for relative in expected_inventory
        for parent in pathlib.PurePosixPath(relative).parents
        if parent.as_posix() != "."
    }
    expected_inventory_pair = (
        expected_inventory,
        tuple(sorted(expected_directories)),
    )
    if inventory(root) != expected_inventory_pair:
        fail("bundle manifest does not equal the exact bundle inventory")
    total = 0
    raw_by_path: dict[str, bytes] = {}
    hash_by_path: dict[str, str] = {}
    required_raw = {
        "subject.tsv",
        "artifacts/abi2-witness.tsv",
        "verification/correctness.tsv",
        "verification/performance.tsv",
        "provenance/build-receipt.tsv",
        "provenance/source-snapshot.tsv",
        TOOLCHAIN_CLOSURE_PATH,
        REGISTRY_CLOSURE_PATH,
        PRODUCER_RECEIPT_PATH,
        FACADE_RECEIPT_PATH,
        FACADE_PERFORMANCE_PATH,
    }
    for _kind, expected_hash, expected_size, relative in entries:
        retained = relative in required_raw
        actual_hash, raw = hash_regular(
            root / relative,
            expected_size,
            f"bundle entry {relative}",
            retain=retained,
            expected_permissions=(
                0o755
                if relative
                in {
                    ABI2_PRODUCER_BINARY_PATH,
                    FACADE_PRODUCER_BINARY_PATH,
                }
                else 0o644
            ),
        )
        if actual_hash != expected_hash:
            fail(f"bundle entry differs from its manifest: {relative}")
        if retained:
            assert raw is not None
            raw_by_path[relative] = raw
        hash_by_path[relative] = actual_hash
        total += expected_size
    if total != declared_total:
        fail("qualification bundle byte accounting changed")
    if inventory(root) != expected_inventory_pair:
        fail("qualification bundle inventory changed during verification")
    if (
        read_regular(
            root / BUNDLE_MANIFEST,
            4 * 1024 * 1024,
            "bundle manifest recheck",
            expected_permissions=0o644,
        )
        != manifest_raw
        or read_regular(
            root / BUNDLE_DIGEST,
            128,
            "BUNDLE.sha256 recheck",
            expected_permissions=0o644,
        )
        != digest_raw
    ):
        fail("qualification bundle authority changed during verification")
    if (
        hash_by_path["provenance/source.tar.gz"] != expected_archive
        or hash_by_path["provenance/build-receipt.tsv"] != expected_receipt
    ):
        fail("source archive or build receipt differs from its external pin")

    (
        toolchain_closure_sha256,
        toolchain_closure_entries,
        toolchain_closure_bytes,
        toolchain_closure,
    ) = parse_closure_manifest(
        raw_by_path[TOOLCHAIN_CLOSURE_PATH],
        TOOLCHAIN_CLOSURE_SCHEMA,
        "toolchain closure manifest",
        MAX_TOOLCHAIN_ENTRIES,
    )
    (
        registry_closure_sha256,
        registry_closure_entries,
        registry_closure_bytes,
        _registry_closure,
    ) = parse_closure_manifest(
        raw_by_path[REGISTRY_CLOSURE_PATH],
        REGISTRY_CLOSURE_SCHEMA,
        "Cargo-registry closure manifest",
        MAX_REGISTRY_ENTRIES,
    )
    required_toolchain_paths = {"bin/cargo", "bin/rustc", "bin/rustdoc"}
    if not required_toolchain_paths.issubset(toolchain_closure):
        fail("toolchain closure omits cargo, rustc, or rustdoc")
    if any(
        toolchain_closure[path][1] == 0 for path in required_toolchain_paths
    ):
        fail("toolchain closure names an empty cargo, rustc, or rustdoc")

    subject = parse_tsv(
        raw_by_path["subject.tsv"],
        SUBJECT_FIELDS,
        "fre-jit-tag19-abi2-qualification-subject-v1",
        "subject receipt",
    )
    expected_subject = {
        "candidate_revision": candidate,
        "candidate_tree": tree,
        "backend_policy": "Sve16V6",
        "backend_version": "19",
        "qualification_atom_symbol": (
            "QUALIFIED_EXACT_SEARCH_SVE16_V6_QUALIFICATION"
        ),
        "qualification_state": "candidate",
        "literal_bytes": "16",
        "public_output": "span",
        "native_output": "selected-end",
        "native_abi": "selected-end-register-v2",
        "native_arguments": "x0-haystack,x1-length,x2-start,x3-end",
        "native_return": "x0-zero-or-absolute-exclusive-end",
        "x4_result_slot": "absent-forbidden",
        "row_schema": DERIVED_PERFORMANCE_SCHEMA,
        "facade_receipt_schema": FACADE_RECEIPT_SCHEMA,
        "facade_receipt_sha256": hash_by_path[FACADE_RECEIPT_PATH],
        "facade_performance_raw_schema": FACADE_PERFORMANCE_SCHEMA,
        "facade_performance_raw_sha256": hash_by_path[
            FACADE_PERFORMANCE_PATH
        ],
        "abi2_producer_schema": PRODUCER_RECEIPT_SCHEMA,
        "abi2_producer_sha256": hash_by_path[PRODUCER_RECEIPT_PATH],
        "abi2_producer_binary_sha256": hash_by_path[
            ABI2_PRODUCER_BINARY_PATH
        ],
        "facade_producer_binary_sha256": hash_by_path[
            FACADE_PRODUCER_BINARY_PATH
        ],
        "evidence_binding_schema": (
            "fre-qualified-exact-tag19-abi2-evidence-v1"
        ),
        "target": "aarch64-aapcs64-asimd-sve",
        "target_feature_bits": "3",
        "operating_system_contract": "linux-aarch64",
        "sve_vector_bytes_at_publication": "none",
        "required_thread_sve_vector_bytes": "16",
        "host_contract": (
            "linux-arm-41-d84-hwcap-asimd-sve-pr-sve-get-vl16"
        ),
        "artifact_witness_schema": (
            "fre-jit-tag19-selected-end-register-v2-vl16-witness-v1"
        ),
        "artifact_witness_sha256": hash_by_path[
            "artifacts/abi2-witness.tsv"
        ],
        "source_archive_sha256": expected_archive,
        "build_receipt_sha256": expected_receipt,
        "source_snapshot_sha256": hash_by_path[
            "provenance/source-snapshot.tsv"
        ],
        "correctness_verification_sha256": hash_by_path[
            "verification/correctness.tsv"
        ],
        "performance_verification_sha256": hash_by_path[
            "verification/performance.tsv"
        ],
        "evidence_class": "measured",
        "overall": "PASS",
    }
    for field, expected in expected_subject.items():
        if subject[field] != expected:
            fail(f"subject receipt has the wrong {field}")
    require_nonzero_sha256(
        subject["artifact_sha256"], "ABI2 artifact SHA-256"
    )
    parse_facade_receipt(
        raw_by_path[FACADE_RECEIPT_PATH], subject["artifact_sha256"]
    )
    producer = parse_producer_receipt(
        raw_by_path[PRODUCER_RECEIPT_PATH],
        candidate,
        tree,
        expected_archive,
        expected_receipt,
        subject["artifact_sha256"],
    )
    derived_performance = parse_facade_performance(
        raw_by_path[FACADE_PERFORMANCE_PATH],
        candidate,
        tree,
        subject["artifact_sha256"],
        producer,
    )

    witness = parse_tsv(
        raw_by_path["artifacts/abi2-witness.tsv"],
        WITNESS_FIELDS,
        "fre-jit-tag19-abi2-artifact-witness-v1",
        "ABI2 witness",
    )
    witness_expected = {
        "external_artifact_witness_schema": (
            "fre-jit-tag19-selected-end-register-v2-vl16-witness-v1"
        ),
        "candidate_revision": candidate,
        "candidate_tree": tree,
        "abi2_source_closure_sha256": ABI2_SOURCE_CLOSURE_SHA256,
        "backend_policy": "Sve16V6",
        "backend_version": "19",
        "literal_bytes": "16",
        "public_output": "span",
        "native_output": "selected-end",
        "native_abi": "selected-end-register-v2",
        "native_arguments": "x0-haystack,x1-length,x2-start,x3-end",
        "native_return": "x0-zero-or-absolute-exclusive-end",
        "x4_result_slot": "absent-forbidden",
        "target": "aarch64-aapcs64-asimd-sve",
        "target_feature_bits": "3",
        "operating_system_contract": "linux-aarch64",
        "sve_vector_bytes_at_publication": "none",
        "required_thread_sve_vector_bytes": "16",
        "host_contract": (
            "linux-arm-41-d84-hwcap-asimd-sve-pr-sve-get-vl16"
        ),
        "facade_artifact_sha256": subject["artifact_sha256"],
        "deterministic_emitter_artifact_sha256": subject["artifact_sha256"],
        "facade_identity_matches_external_witness": "true",
        "independent_image_audit": "PASS",
        "native_store_count": "0",
        "forbidden_x4_audit": "PASS",
        "qualification_state": "candidate",
        "overall": "PASS",
    }
    for field, expected in witness_expected.items():
        if witness[field] != expected:
            fail(f"ABI2 witness has the wrong {field}")

    correctness = parse_tsv(
        raw_by_path["verification/correctness.tsv"],
        CORRECTNESS_FIELDS,
        "fre-jit-tag19-abi2-correctness-verification-v1",
        "correctness verification",
    )
    correctness_expected = {
        "candidate_revision": candidate,
        "candidate_tree": tree,
        "backend_policy": "Sve16V6",
        "backend_version": "19",
        "artifact_sha256": subject["artifact_sha256"],
        "row_schema": DERIVED_PERFORMANCE_SCHEMA,
        "facade_receipt_schema": FACADE_RECEIPT_SCHEMA,
        "facade_receipt_sha256": hash_by_path[FACADE_RECEIPT_PATH],
        "facade_performance_raw_schema": FACADE_PERFORMANCE_SCHEMA,
        "facade_performance_raw_sha256": hash_by_path[
            FACADE_PERFORMANCE_PATH
        ],
        "abi2_producer_schema": PRODUCER_RECEIPT_SCHEMA,
        "abi2_producer_sha256": hash_by_path[PRODUCER_RECEIPT_PATH],
        "candidate_guard_scope": "test-thread-local-only",
        "production_candidate_execution": "false",
        "artifact_witness_matches": "PASS",
        "host_contract_checked": "PASS",
        "portable_oracle": "PASS",
        "kernel_ir_oracle": "PASS",
        "public_facade": "PASS",
        "thread_vl_contract_checked": "PASS",
        "runtime_thread_sve_vector_bytes": "16",
        "publication_sve_vector_bytes": "none",
        "abi2_vector_callee_saved_canary": "PASS",
        "guard_pages": "PASS",
        "x4_and_store_audit": "PASS",
        "evidence_class": "measured",
        "overall": "PASS",
    }
    for field, expected in correctness_expected.items():
        if correctness[field] != expected:
            fail(f"correctness verification has the wrong {field}")
    if correctness["native_comparisons"] != producer["comparisons"]:
        fail("correctness summary differs from the raw producer corpus")

    performance = parse_tsv(
        raw_by_path["verification/performance.tsv"],
        PERFORMANCE_FIELDS,
        "fre-jit-tag19-abi2-performance-verification-v1",
        "performance verification",
    )
    performance_expected = {
        "candidate_revision": candidate,
        "candidate_tree": tree,
        "backend_policy": "Sve16V6",
        "backend_version": "19",
        "artifact_sha256": subject["artifact_sha256"],
        "row_schema": DERIVED_PERFORMANCE_SCHEMA,
        "facade_receipt_schema": FACADE_RECEIPT_SCHEMA,
        "facade_receipt_sha256": hash_by_path[FACADE_RECEIPT_PATH],
        "facade_performance_raw_schema": FACADE_PERFORMANCE_SCHEMA,
        "facade_performance_raw_sha256": hash_by_path[
            FACADE_PERFORMANCE_PATH
        ],
        "portable_comparator": "same-source-public-portable",
        "hot_gate": "PASS",
        "full_workload_gate": "PASS",
        "comparison_direction": "candidate_over_portable",
        "confidence_method": CONFIDENCE_METHOD,
        "build_cost_retained": "true",
        "cold_cost_retained": "true",
        "break_even_gate": "PASS",
        "evidence_class": "measured",
        "overall": "PASS",
    }
    for field, expected in performance_expected.items():
        if performance[field] != expected:
            fail(f"performance verification has the wrong {field}")
    for field, value in derived_performance.items():
        if performance[field] != str(value):
            fail(f"performance summary differs from raw evidence for {field}")

    build = parse_tsv(
        raw_by_path["provenance/build-receipt.tsv"],
        BUILD_FIELDS,
        "fre-jit-tag19-abi2-build-receipt-v1",
        "build receipt",
    )
    build_expected = {
        "candidate_revision": candidate,
        "candidate_tree": tree,
        "artifact_sha256": subject["artifact_sha256"],
        "abi2_producer_binary_sha256": hash_by_path[
            ABI2_PRODUCER_BINARY_PATH
        ],
        "facade_producer_binary_sha256": hash_by_path[
            FACADE_PRODUCER_BINARY_PATH
        ],
        "source_archive_sha256": expected_archive,
        "source_snapshot_receipt_sha256": hash_by_path[
            "provenance/source-snapshot.tsv"
        ],
        "target_triple": TARGET_TRIPLE,
        "abi2_producer_features": ABI2_PRODUCER_FEATURES,
        "facade_producer_features": FACADE_PRODUCER_FEATURES,
        "rustflags": QUALIFICATION_RUSTFLAGS,
        "release_profile": RELEASE_PROFILE,
        "cargo_incremental": "0",
        "abi2_producer_build_command": ABI2_PRODUCER_BUILD_COMMAND,
        "facade_producer_build_command": FACADE_PRODUCER_BUILD_COMMAND,
        "cargo_binary_sha256": toolchain_closure["bin/cargo"][0],
        "rustc_binary_sha256": toolchain_closure["bin/rustc"][0],
        "rustdoc_binary_sha256": toolchain_closure["bin/rustdoc"][0],
        "toolchain_closure_sha256": toolchain_closure_sha256,
        "toolchain_closure_entries": str(toolchain_closure_entries),
        "toolchain_closure_bytes": str(toolchain_closure_bytes),
        "cargo_registry_closure_sha256": registry_closure_sha256,
        "cargo_registry_closure_entries": str(registry_closure_entries),
        "cargo_registry_closure_bytes": str(registry_closure_bytes),
        "profile": "release",
        "evidence_class": "measured",
        "overall": "PASS",
    }
    for field, expected in build_expected.items():
        if build[field] != expected:
            fail(f"build receipt has the wrong {field}")
    for field in (
        "resource_coordinator_sha256",
        "resource_coordinator_cutover_receipt_sha256",
    ):
        require_nonzero_sha256(build[field], f"build receipt {field}")
    if (
        producer["resource_coordinator_sha256"]
        != build["resource_coordinator_sha256"]
        or producer["resource_cutover_sha256"]
        != build["resource_coordinator_cutover_receipt_sha256"]
    ):
        fail("ABI2 producer provenance differs from the build receipt")

    source = parse_tsv(
        raw_by_path["provenance/source-snapshot.tsv"],
        SOURCE_FIELDS,
        "fre-jit-tag19-abi2-source-snapshot-v1",
        "source snapshot",
    )
    source_expected = {
        "candidate_revision": candidate,
        "candidate_tree": tree,
        "candidate_atom_blob": CANDIDATE_ATOM_BLOB,
        "abi2_source_closure_sha256": ABI2_SOURCE_CLOSURE_SHA256,
        "source_archive_sha256": expected_archive,
        "source_materialization": "exact-git-objects-read-only-v1",
        "source_clean": "true",
        "evidence_class": "measured",
        "overall": "PASS",
    }
    for field, expected in source_expected.items():
        if source[field] != expected:
            fail(f"source snapshot has the wrong {field}")
    require_nonzero_sha256(
        source["source_closure_sha256"], "source closure SHA-256"
    )
    require_positive_uint(
        source["source_entries"], "source closure entry count", MAX_ENTRIES
    )
    require_positive_uint(
        source["source_file_bytes"],
        "source closure file bytes",
        MAX_TOTAL_BYTES,
    )
    return manifest_sha, subject, hash_by_path


def validate_review(
    path: pathlib.Path,
    expected_sha: str,
    bundle_root: pathlib.Path,
    candidate: str,
    tree: str,
    bundle_sha: str,
    expected_archive: str,
    expected_receipt: str,
    subject: dict[str, str],
    hashes: dict[str, str],
) -> str:
    require_nonzero_sha256(
        expected_sha, "expected independent review SHA-256"
    )
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        fail(f"cannot resolve independent review: {error}")
    if not path.is_absolute() or resolved != path:
        fail("independent review path must be canonical and absolute")
    try:
        path.relative_to(bundle_root)
    except ValueError:
        pass
    else:
        fail("independent review must be outside the resealable bundle")
    raw = read_regular(path, 4096, "independent review")
    actual_sha = sha256(raw)
    if actual_sha != expected_sha:
        fail("independent review differs from its external pin")
    review = parse_tsv(
        raw,
        REVIEW_FIELDS,
        "fre-jit-tag19-abi2-independent-review-v1",
        "independent review",
    )
    expected = {
        "candidate_revision": candidate,
        "candidate_tree": tree,
        "backend_policy": "Sve16V6",
        "backend_version": "19",
        "qualification_atom_symbol": (
            "QUALIFIED_EXACT_SEARCH_SVE16_V6_QUALIFICATION"
        ),
        "bundle_manifest_sha256": bundle_sha,
        "subject_sha256": hashes["subject.tsv"],
        "artifact_sha256": subject["artifact_sha256"],
        "artifact_witness_sha256": hashes["artifacts/abi2-witness.tsv"],
        "source_archive_sha256": expected_archive,
        "build_receipt_sha256": expected_receipt,
        "source_snapshot_sha256": hashes["provenance/source-snapshot.tsv"],
        "correctness_verification_sha256": hashes[
            "verification/correctness.tsv"
        ],
        "performance_verification_sha256": hashes[
            "verification/performance.tsv"
        ],
        "abi2_source_closure_sha256": ABI2_SOURCE_CLOSURE_SHA256,
        "public_output": "span",
        "native_output": "selected-end",
        "native_abi": "selected-end-register-v2",
        "native_arguments": "x0-haystack,x1-length,x2-start,x3-end",
        "native_return": "x0-zero-or-absolute-exclusive-end",
        "x4_result_slot": "absent-forbidden",
        "target": "aarch64-aapcs64-asimd-sve",
        "target_feature_bits": "3",
        "operating_system_contract": "linux-aarch64",
        "sve_vector_bytes_at_publication": "none",
        "required_thread_sve_vector_bytes": "16",
        "host_contract": (
            "linux-arm-41-d84-hwcap-asimd-sve-pr-sve-get-vl16"
        ),
        "row_schema": DERIVED_PERFORMANCE_SCHEMA,
        "facade_receipt_schema": FACADE_RECEIPT_SCHEMA,
        "facade_receipt_sha256": hashes[FACADE_RECEIPT_PATH],
        "facade_performance_raw_schema": FACADE_PERFORMANCE_SCHEMA,
        "facade_performance_raw_sha256": hashes[FACADE_PERFORMANCE_PATH],
        "abi2_producer_schema": PRODUCER_RECEIPT_SCHEMA,
        "abi2_producer_sha256": hashes[PRODUCER_RECEIPT_PATH],
        "abi2_producer_binary_sha256": hashes[ABI2_PRODUCER_BINARY_PATH],
        "facade_producer_binary_sha256": hashes[
            FACADE_PRODUCER_BINARY_PATH
        ],
        "evidence_binding_schema": (
            "fre-qualified-exact-tag19-abi2-evidence-v1"
        ),
        "artifact_witness_schema": (
            "fre-jit-tag19-selected-end-register-v2-vl16-witness-v1"
        ),
        "qualification_state": "candidate",
        "evidence_class": "measured",
        "review_evidence_sha256": hashes["evidence/review-findings.txt"],
        "overall": "PASS",
    }
    for field, value in expected.items():
        if review[field] != value:
            fail(f"independent review has the wrong {field}")
    require_nonzero_sha256(
        review["review_evidence_sha256"], "review evidence SHA-256"
    )
    return actual_sha


def render_qualification(digest: Optional[str]) -> str:
    if digest is None:
        return "    QualifiedExactSearchQualification::Candidate;\n"
    require_bundle(digest, "qualification bundle")
    values = [f"0x{digest[index:index + 2]}," for index in range(0, 64, 2)]
    rows = (
        "            " + " ".join(values[:14]),
        "            " + " ".join(values[14:28]),
        "            " + " ".join(values[28:]),
    )
    return (
        "    QualifiedExactSearchQualification::Qualified {\n"
        "        bundle_sha256: [\n"
        + "\n".join(rows)
        + "\n        ],\n"
        "    };\n"
    )


def render_atom(v8_digest: Optional[str], tag19_digest: str) -> bytes:
    return (
        "use super::QualifiedExactSearchQualification;\n\n"
        "/// Qualification atom scoped only to `SearchBackendPolicy::AsimdV8` / tag 8.\n"
        "pub const QUALIFIED_EXACT_SEARCH_ASIMD_V8_QUALIFICATION: QualifiedExactSearchQualification =\n"
        + render_qualification(v8_digest)
        + "\n"
        "/// Qualification atom scoped only to `SearchBackendPolicy::Sve16V6` / tag 19.\n"
        "pub const QUALIFIED_EXACT_SEARCH_SVE16_V6_QUALIFICATION: QualifiedExactSearchQualification =\n"
        + render_qualification(tag19_digest)
        + "\n"
        "/// Qualification atom scoped only to `SearchBackendPolicy::Sve2Fixed16` / tag 10.\n"
        "pub const QUALIFIED_EXACT_SEARCH_SVE2_FIXED16_QUALIFICATION: QualifiedExactSearchQualification =\n"
        + render_qualification(None)
        + "\n"
        "/// Qualification atom scoped only to `SearchBackendPolicy::Sve2Fixed16V2` /\n"
        "/// tag 21.\n"
        "pub const QUALIFIED_EXACT_SEARCH_SVE2_FIXED16_V2_QUALIFICATION: QualifiedExactSearchQualification =\n"
        + render_qualification(None)
    ).encode("ascii")


def verify_delta(
    repository: pathlib.Path,
    candidate: str,
    promoted: str,
    expected_atom: bytes,
    scope: str,
) -> None:
    changed_raw = run_git(
        repository,
        "diff",
        "--name-status",
        "--no-renames",
        "--no-ext-diff",
        "--no-textconv",
        candidate,
        promoted,
    )
    assert isinstance(changed_raw, str)
    changed = tuple(
        tuple(line.split("\t")) for line in changed_raw.splitlines()
    )
    if any(len(row) != 2 or row[0] != "M" for row in changed):
        fail("promotion contains a non-modification delta")
    changed_paths = tuple(sorted(row[1] for row in changed))
    permitted = (
        (ATOM_PATH,),
        tuple(sorted((ATOM_PATH, COMPOSED_AOT_ATOM_PATH))),
    )
    if changed_paths not in permitted:
        fail("promotion is not the exact scope-bounded atom union")
    _blob, promoted_atom = git_blob(
        repository,
        promoted,
        ATOM_PATH,
        "100644",
        64 * 1024,
        "promoted qualification atom",
    )
    if promoted_atom != expected_atom:
        fail("promoted atom is not the canonical four-atom rendering")


def verify(arguments: list[str]) -> str:
    if len(arguments) != 12:
        usage()
    (
        repository_arg,
        candidate,
        promoted,
        expected_tree,
        expected_archive,
        expected_receipt,
        expected_manifest,
        evidence_arg,
        review_arg,
        expected_review,
        v8_bundle,
        scope,
    ) = arguments
    if scope != "composed-exact-union-delegated":
        usage()
    require_bundle(v8_bundle, "coordinator-validated V8 bundle")
    repository = canonical_directory(repository_arg, "repository")
    evidence = canonical_directory(evidence_arg, "tag19 evidence bundle")
    tree = validate_repository(
        repository, candidate, promoted, expected_tree
    )
    source_identity = validate_running_candidate(repository, candidate)
    bundle_sha, subject, hashes = validate_bundle(
        evidence,
        candidate,
        tree,
        expected_archive,
        expected_receipt,
        expected_manifest,
    )
    review_sha = validate_review(
        pathlib.Path(review_arg),
        expected_review,
        evidence,
        candidate,
        tree,
        bundle_sha,
        expected_archive,
        expected_receipt,
        subject,
        hashes,
    )
    verify_delta(
        repository,
        candidate,
        promoted,
        render_atom(v8_bundle, bundle_sha),
        scope,
    )
    if validate_running_candidate(repository, candidate) != source_identity:
        fail("Candidate verifier/source identity changed during verification")
    if run_git(repository, "show", "-s", "--format=%T", candidate) != tree:
        fail("Candidate tree changed during verification")
    return (
        f"TAG19_PROMOTION_VERIFIED\tcandidate={candidate}"
        f"\tpromoted={promoted}\ttree={tree}\tmanifest={bundle_sha}"
        f"\treview={review_sha}\tv8_bundle={v8_bundle}\tscope={scope}"
        "\ttuning=arm-41-d84\tcomplete_atom_exact=true"
        "\tdirect_child=true\tcandidate_rooted_verifier=true"
    )


def usage() -> NoReturn:
    fail(
        "usage: verify-tag19-promotion-delta.sh REPOSITORY CANDIDATE "
        "PROMOTED EXPECTED_TREE EXPECTED_ARCHIVE_SHA256 "
        "EXPECTED_BUILD_RECEIPT_SHA256 EXPECTED_MANIFEST_SHA256 "
        "EVIDENCE_DIR REVIEW_RECEIPT EXPECTED_REVIEW_SHA256 "
        "V8_BUNDLE_SHA256 composed-exact-union-delegated"
    )


def main() -> int:
    print(verify(sys.argv[1:]))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PromotionError as error:
        print(f"verify-tag19-promotion: {error}", file=sys.stderr)
        raise SystemExit(2) from None
