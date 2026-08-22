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
import subprocess
import sys
import tempfile
from collections import Counter


PLAN_SCHEMA = "fre.aot-rebar.true-native-plan.v2"
RECEIPT_SCHEMA = "fre.aot-rebar.true-native-job-receipt.v2"
SUMMARY_SCHEMA = "fre.aot-rebar.true-native-summary.v2"
TRAP_MARKER_SCHEMA = "fre.aot-rebar.runtime-trap.v1"
SCHEDULE_SCHEMA = "fre.full-rebar.campaign.v1"
EXPECTED_PUBLIC_JOBS = 344
EXPECTED_RUNTIME_JOBS = 311
EXPECTED_COMPILE_JOBS = 33
MAX_NATIVE_ROW_COMPONENTS = 4_096
MAX_NATIVE_ROW_OBJECT_BYTES = 256 * 1024 * 1024
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
COMPOSITE_ADAPTER_MODELS = {"regex-redux"}
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
NATIVE_COUNT_ENTRY_SYMBOL = re.compile(
    r"^fre_aot_regex_count_exclusive_v1_[0-9a-f]{64}$"
)
NATIVE_SPAN_FILL_ENTRY_SYMBOL = re.compile(
    r"^fre_aot_regex_fill_spans_exclusive_v1_[0-9a-f]{64}$"
)
CONTROL_PLANE_PREFIXES = (
    "fre_aot_regex_runtime_prepare_",
    "fre_aot_regex_runtime_destroy_",
)
RUNTIME_PREFIX = "fre_aot_regex_runtime_"
DEFINED_TEXT_SYMBOL_TYPES = {"T", "t", "W"}
RUNTIME_REFERENCE_SYMBOL_TYPES = DEFINED_TEXT_SYMBOL_TYPES | {"U", "u", "w"}
TRAP_PATCHES = {"x86_64": "0f0b", "aarch64": "000020d4"}


class CensusError(RuntimeError):
    """A fail-closed census validation error."""


def has_exact_adapter(model: str, pattern_count: int) -> bool:
    """Return whether the integrated runner has a typed adapter for this shape."""
    return (
        model in {"count", "count-spans"}
        and 1 <= pattern_count <= MAX_NATIVE_ROW_COMPONENTS
    ) or (
        model == "grep" and pattern_count == 1
    ) or (
        model in COMPOSITE_ADAPTER_MODELS and pattern_count == 0
    )


def exact_adapter_reason(model: str, pattern_count: int) -> str:
    exact_adapter = has_exact_adapter(model, pattern_count)
    if exact_adapter and model in {"count", "count-spans"} and pattern_count > 1:
        return "exact-native-row-composite-adapter"
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
    recorded_root: str | None = None,
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


def git_output(source: pathlib.Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(source), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        raise CensusError(f"git {' '.join(arguments)} failed")
    return completed.stdout.decode("utf-8", "strict").strip()


def source_identity(source: pathlib.Path, commit: str, tree: str) -> dict[str, object]:
    source = source.resolve(strict=True)
    actual_commit = git_output(source, "rev-parse", "HEAD")
    actual_tree = git_output(source, "rev-parse", "HEAD^{tree}")
    if actual_commit != commit or actual_tree != tree:
        raise CensusError("candidate source is not the declared commit/tree")
    if git_output(source, "status", "--porcelain", "--untracked-files=all"):
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
    schedules = []
    raw_points: dict[str, dict[str, object]] = {}
    jobs: dict[str, dict[str, object]] = {}
    for raw_path, expected_sha in zip(args.schedule, args.schedule_sha256, strict=True):
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
            candidate = klv_identity(
                raw_point.get("candidate_klv"), public_root, args.recorded_public_klv_root,
                f"point {point_id} candidate", not args.skip_klv_hashing,
            )
            reference = klv_identity(
                raw_point.get("reference_klv"), public_root, args.recorded_public_klv_root,
                f"point {point_id} reference", not args.skip_klv_hashing,
            )
            point_record = {
                "point_id": point_id,
                "job_id": job_id,
                "benchmark": benchmark,
                "model": model,
                "boundary": boundary,
                "comparator": comparator,
                "expected": raw_point.get("expected"),
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
    schedule_revisions = sorted({str(row["rebar_revision"]) for row in schedules})
    plan = {
        "schema": PLAN_SCHEMA,
        "candidate_source": source,
        "public_corpus": {
            "label": args.public_corpus_label,
            "klv_root_recorded": args.recorded_public_klv_root,
            "privacy_policy": "public-rebar-only; hashed-input-identities; no-pattern-or-haystack-bytes",
            "rebar_revisions": schedule_revisions,
            "schedules": sorted(schedules, key=lambda row: row["file_sha256"]),
        },
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
    require_exact_keys(plan["public_corpus"], {
        "label", "klv_root_recorded", "privacy_policy", "rebar_revisions", "schedules",
    }, "plan public corpus")
    public_corpus = plan["public_corpus"]
    if public_corpus["privacy_policy"] != (
        "public-rebar-only; hashed-input-identities; no-pattern-or-haystack-bytes"
    ):
        raise CensusError("plan has a noncanonical public-corpus privacy policy")
    if not all(
        isinstance(public_corpus[name], str) and public_corpus[name]
        for name in ("label", "klv_root_recorded")
    ):
        raise CensusError("plan public corpus has an invalid textual identity")
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
    return plan


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
    }
    if fields.get("schema") == "fre.aot.rebar-runner.v2":
        required = common | {
            "engine", "aggregate_strategy", "prepared_bulk_strategy",
            "span_iteration_strategy", "grep_iteration_strategy", "program_sha256",
            "object_sha256", "program_symbol", "entry_symbol", "reducer_symbol",
            "span_fill_symbol", "required_runtime_symbols",
        }
    elif fields.get("schema") == "fre.aot.rebar-runner.v3":
        required = common | {
            "disposition", "compiler_version", "optimizer_version", "engine",
            "aggregate_strategy", "component_count", "boundary",
            "required_comparators",
        }
    else:
        raise CensusError("runner provenance is neither scalar v2 nor composite v3")
    missing = required - set(fields)
    if missing:
        raise CensusError(f"runner provenance omits {sorted(missing)!r}")
    if fields["configured"] != "true":
        raise CensusError("runner is not a configured public Rebar adapter")
    if fields["schema"] == "fre.aot.rebar-runner.v2":
        validate_v2_provenance(fields)
    else:
        components = components_from_provenance(fields)
        validate_v3_provenance(fields, components)
    return fields


def validate_v2_provenance(fields: dict[str, str]) -> None:
    """Validate the complete scalar runner contract before normalizing it."""
    expected = {
        "schema", "disposition", "configured", "adapter", "model", "benchmark",
        "source_commit", "source_tree", "target", "feature_bits",
        "compiler_version", "optimizer_version", "engine", "aggregate_strategy",
        "prepared_bulk_strategy", "span_iteration_strategy", "grep_iteration_strategy",
        "prepare_config_version", "prepare_operation_flags",
        "required_prepare_capabilities", "prepare_scope", "object_descriptor_setup",
        "max_start_filter_setup_work", "max_grep_count_workspace_bytes",
        "max_handle_bytes", "max_ordered_nfa_scratch_bytes",
        "max_ordered_nfa_setup_work", "program_sha256", "object_sha256",
        "program_symbol", "entry_symbol", "reducer_symbol", "span_fill_symbol",
        "required_runtime_symbols", "boundary", "required_comparators",
    }
    if set(fields) != expected:
        raise CensusError(
            "runner v2 provenance field closure differs: "
            f"missing={sorted(expected - set(fields))!r} "
            f"extra={sorted(set(fields) - expected)!r}"
        )
    if fields["disposition"] != "executed":
        raise CensusError("scalar provenance disposition is not executed")
    if fields["boundary"] != "runtime-klv-warmup-schedule":
        raise CensusError("scalar provenance has the wrong operation boundary")
    if fields["required_comparators"] != "rust-regex-1.12.4,fre-current-runtime":
        raise CensusError("scalar provenance comparator set differs")
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


def components_from_provenance(fields: dict[str, str]) -> list[dict[str, object]]:
    if fields.get("schema") != "fre.aot.rebar-runner.v3":
        return []
    try:
        count = int(fields["component_count"], 10)
    except (KeyError, ValueError) as error:
        raise CensusError("composite provenance has invalid component_count") from error
    if fields.get("model") == "regex-redux" and count != 15:
        raise CensusError(f"regex-redux must publish exactly 15 components, got {count}")
    if count <= 0 or count > MAX_NATIVE_ROW_COMPONENTS:
        raise CensusError(f"composite component count is out of range: {count}")
    native_row = fields.get("native_row_bridge") == "true"
    components = []
    for index in range(count):
        native = component_field(fields, index, ("native",))
        entry = component_field(fields, index, ("entry_symbol",))
        runtime_text = component_field(
            fields, index, ("required_runtime_symbols", "runtime_symbols")
        )
        program_sha256 = component_field(fields, index, ("program_sha256",))
        object_sha256 = component_field(fields, index, ("object_sha256",))
        if native != "true":
            raise CensusError(f"composite component {index} is not claimed native")
        if SYMBOL.fullmatch(entry) is None:
            raise CensusError(f"composite component {index} has invalid entry symbol")
        require_hex64(program_sha256, f"component {index} program digest")
        require_hex64(object_sha256, f"component {index} object digest")
        runtime_symbols = sorted(filter(None, runtime_text.split(",")))
        if len(runtime_symbols) != len(set(runtime_symbols)) or not all(
            SYMBOL.fullmatch(symbol) for symbol in runtime_symbols
        ):
            raise CensusError(f"component {index} runtime symbol list is malformed")
        source_ordinal = None
        if native_row:
            source_ordinal_text = component_field(fields, index, ("source_ordinal",))
            try:
                source_ordinal = int(source_ordinal_text, 10)
            except ValueError as error:
                raise CensusError(
                    f"composite component {index} has invalid source ordinal"
                ) from error
            if source_ordinal < 0:
                raise CensusError(
                    f"composite component {index} has negative source ordinal"
                )
        components.append({
            "ordinal": index,
            "native": True,
            "source_ordinal": source_ordinal,
            "entry_symbol": entry,
            "required_runtime_symbols": runtime_symbols,
            "program_sha256": program_sha256,
            "object_sha256": object_sha256,
        })
    return components


def validate_v3_provenance(
    fields: dict[str, str], components: list[dict[str, object]]
) -> None:
    """Validate the exact raw v3 field set and composite topology."""
    if fields.get("disposition") != "executed":
        raise CensusError("composite provenance disposition is not executed")
    if fields.get("required_comparators") != "rust-regex-1.12.4,fre-current-runtime":
        raise CensusError("composite provenance comparator set differs")
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
    }
    component_fields = {
        f"component_{index}_{suffix}"
        for index in range(len(components))
        for suffix in (
            "native", "entry_symbol", "runtime_symbols", "program_sha256",
            "object_sha256",
        )
    }
    if fields["model"] == "regex-redux":
        if fields.get("boundary") != "complete-regex-redux-aot-precompiled":
            raise CensusError("regex-redux provenance has the wrong operation boundary")
        expected = base | component_fields
    elif (
        fields.get("native_row_bridge") == "true"
        and fields["model"] in {"count", "count-spans"}
    ):
        if fields.get("boundary") != "complete-native-row-bridge":
            raise CensusError("native-row provenance has the wrong operation boundary")
        component_fields |= {
            f"component_{index}_source_ordinal" for index in range(len(components))
        }
        expected = base | component_fields | {
            "native_row_bridge", "source_pattern_count", "row_total_object_bytes",
            "source_to_artifact",
        }
        try:
            source_count = int(fields["source_pattern_count"], 10)
            object_bytes = int(fields["row_total_object_bytes"], 10)
            source_to_artifact = [
                int(value, 10) for value in fields["source_to_artifact"].split(",")
            ]
        except (KeyError, ValueError) as error:
            raise CensusError("native-row provenance topology is malformed") from error
        if not 2 <= source_count <= MAX_NATIVE_ROW_COMPONENTS:
            raise CensusError("native-row source pattern count is out of range")
        if not 0 < object_bytes <= MAX_NATIVE_ROW_OBJECT_BYTES:
            raise CensusError("native-row object-byte total is out of range")
        if len(source_to_artifact) != source_count or any(
            artifact < 0 or artifact >= len(components)
            for artifact in source_to_artifact
        ):
            raise CensusError("native-row source-to-artifact map is out of range")
        if set(source_to_artifact) != set(range(len(components))):
            raise CensusError("native-row source-to-artifact map is not surjective")
        first_sources = [source_to_artifact.index(index) for index in range(len(components))]
        if first_sources != sorted(first_sources):
            raise CensusError("native-row component priority is not source ordered")
        if [component["source_ordinal"] for component in components] != first_sources:
            raise CensusError("native-row component source ordinals differ from its map")
    else:
        raise CensusError("runner v3 provenance has an unknown composite route")
    if set(fields) != expected:
        raise CensusError(
            "runner v3 provenance field closure differs: "
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
        if name.startswith("_") and name[1:].startswith("fre_aot_regex_"):
            name = name[1:]
        if SYMBOL.fullmatch(name):
            result.add(name)
    return result


def nm_text_symbols(nm_output: str) -> set[str]:
    """Return only entries that the final binary actually defines as text."""
    return nm_symbols_with_types(nm_output, DEFINED_TEXT_SYMBOL_TYPES)


def nm_runtime_references(nm_output: str) -> set[str]:
    """Return defined or imported symbols that may name semantic helper code."""
    return nm_symbols_with_types(nm_output, RUNTIME_REFERENCE_SYMBOL_TYPES)


def semantic_helper_symbols(symbols: set[str]) -> list[str]:
    return sorted(
        name for name in symbols
        if name.startswith(RUNTIME_PREFIX)
        and not name.startswith(CONTROL_PLANE_PREFIXES)
    )


def run_nm(nm: str, binary: pathlib.Path) -> tuple[set[str], set[str], str]:
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
        nm_runtime_references(output),
        sha_bytes(completed.stdout),
    )


def selected_operation_entries(provenance: dict[str, str]) -> tuple[list[str], str]:
    model = provenance["model"]
    components = components_from_provenance(provenance)
    if components:
        entries = [str(component["entry_symbol"]) for component in components]
        if len(entries) != len(set(entries)):
            raise CensusError("composite provenance repeats an entry symbol")
        if model == "regex-redux":
            return entries, "linked-fixed-composite-adapter-loop"
        if provenance.get("native_row_bridge") == "true" and model in {
            "count", "count-spans",
        }:
            return entries, "linked-native-row-adapter-loop"
        raise CensusError(f"unknown composite operation route for model {model!r}")
    if model == "count":
        return [provenance["reducer_symbol"]], "linked-reducer"
    if model == "count-spans" and provenance["span_fill_symbol"]:
        return [provenance["span_fill_symbol"]], "linked-span-fill"
    if model in {"count-spans", "grep"}:
        return [provenance["entry_symbol"]], "linked-direct-entry-adapter-loop"
    raise CensusError(f"no exact operation entry for model {model!r}")


def run_checked_process(
    argv: list[str], input_bytes: bytes, timeout: int, environment: dict[str, str] | None = None
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
    return (
        expected_after is not None
        and marker.get("architecture") == expected_architecture
        and isinstance(armed, list)
        and all(
            isinstance(record, dict)
            and record.get("after") == expected_after
            and isinstance(record.get("before"), str)
            and len(record["before"]) == len(expected_after)
            and re.fullmatch(r"[0-9a-f]+", record["before"]) is not None
            and record["before"] != expected_after
            and isinstance(record.get("offset"), str)
            and re.fullmatch(r"0x[0-9a-f]+", record["offset"]) is not None
            for record in armed
        )
    )


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
    if fields["schema"] == "fre.aot.rebar-runner.v2":
        return {
            **common,
            "kind": "scalar-v2",
            "composite_kind": None,
            "source_pattern_count": None,
            "source_to_artifact": [],
            "row_total_object_bytes": None,
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
    components = components_from_provenance(fields)
    native_row = fields.get("native_row_bridge") == "true"
    return {
        **common,
        "kind": "composite-v3",
        "composite_kind": (
            "native-row-bridge-v1" if native_row else "regex-redux-fixed-v1"
        ),
        "source_pattern_count": (
            int(fields["source_pattern_count"], 10) if native_row else 0
        ),
        "source_to_artifact": (
            [int(value, 10) for value in fields["source_to_artifact"].split(",")]
            if native_row else []
        ),
        "row_total_object_bytes": (
            int(fields["row_total_object_bytes"], 10) if native_row else None
        ),
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
        "required_runtime_symbols": sorted(filter(
            None, fields.get("required_runtime_symbols", "").split(",")
        )),
        "components": components,
    }


def operation_route_from_provenance_record(
    provenance: dict[str, object],
) -> tuple[list[str], str]:
    """Reconstruct the exact operation entries from normalized provenance."""
    components = provenance["components"]
    if components:
        entries = [component["entry_symbol"] for component in components]
        if len(entries) != len(set(entries)) or not all(
            isinstance(entry, str) and NATIVE_SEARCH_ENTRY_SYMBOL.fullmatch(entry)
            for entry in entries
        ):
            raise CensusError(
                "normalized composite provenance has non-native operation entries"
            )
        if provenance["composite_kind"] == "regex-redux-fixed-v1":
            return entries, "linked-fixed-composite-adapter-loop"
        if provenance["composite_kind"] == "native-row-bridge-v1":
            return entries, "linked-native-row-adapter-loop"
        raise CensusError("normalized provenance has an unknown composite kind")
    model = provenance["model"]
    if model == "count":
        entries = [provenance["reducer_symbol"]]
        route = "linked-reducer"
        expected_symbol = NATIVE_COUNT_ENTRY_SYMBOL
    elif model == "count-spans" and provenance["span_fill_symbol"]:
        entries = [provenance["span_fill_symbol"]]
        route = "linked-span-fill"
        expected_symbol = NATIVE_SPAN_FILL_ENTRY_SYMBOL
    elif model in {"count-spans", "grep"}:
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


def claimed_entry_controls_pass(
    entries: list[str],
    controls: list[dict[str, object]],
    expected_architecture: str,
) -> bool:
    if len(controls) != len(entries):
        return False
    for ordinal, (entry, control) in enumerate(zip(entries, controls, strict=True)):
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
    adapter_outer_loop = adapter_route.endswith("-adapter-loop")
    whole_native = core_native and not adapter_outer_loop
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
    elif adapter_outer_loop:
        reason = "native-search-core-with-adapter-outer-loop"
    else:
        reason = "whole-operation-native-authenticated"
    return {
        "built_reproducibly": reproducible,
        "executed_oracle_correct": executed,
        "native_search_core_authenticated": core_native,
        "adapter_outer_loop": adapter_outer_loop,
        "whole_operation_native_authenticated": whole_native,
        "reason": reason,
    }


def qualify_job(args: argparse.Namespace) -> dict[str, object]:
    plan = validate_plan(load_json(pathlib.Path(args.plan)))
    jobs = {row["job_id"]: row for row in plan["jobs"]}
    if args.job_id not in jobs:
        raise CensusError(f"job {args.job_id!r} is absent from the sealed plan")
    job = jobs[args.job_id]
    if not job["is_runtime"] or not job["exact_adapter"]:
        raise CensusError("only exact-adapter runtime jobs can be dynamically qualified")
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
    if normalized_provenance["kind"] == "composite-v3" and (
        normalized_provenance["source_pattern_count"]
        != len(job["input"]["pattern_sha256"])
    ):
        raise CensusError("composite provenance source count differs from sealed job")
    if normalized_provenance["composite_kind"] == "native-row-bridge-v1":
        source_map = normalized_provenance["source_to_artifact"]
        pattern_hashes = job["input"]["pattern_sha256"]
        for source, pattern_hash in enumerate(pattern_hashes):
            for prior in range(source):
                if pattern_hash == pattern_hashes[prior] and source_map[source] != source_map[prior]:
                    raise CensusError("duplicate source patterns map to different artifacts")
    expected_object_hashes = (
        [normalized_provenance["object_sha256"]]
        if normalized_provenance["kind"] == "scalar-v2"
        else [component["object_sha256"] for component in normalized_provenance["components"]]
    )
    if [row["sha256"] for row in primary_hashes["objects"]] != expected_object_hashes:
        raise CensusError("primary object files differ from provenance object identities")
    if [row["sha256"] for row in replica_hashes["objects"]] != expected_object_hashes:
        raise CensusError("replica object files differ from provenance object identities")
    if normalized_provenance["composite_kind"] == "native-row-bridge-v1":
        expected_total_bytes = normalized_provenance["row_total_object_bytes"]
        if any(
            sum(row["bytes"] for row in artifact["objects"]) != expected_total_bytes
            for artifact in (primary_hashes, replica_hashes)
        ):
            raise CensusError("native-row object files differ from its total-byte receipt")
    reproducible = primary_hashes == replica_hashes
    primary_symbols, primary_runtime_references, primary_nm_sha = run_nm(
        args.nm, primary_runner
    )
    replica_symbols, replica_runtime_references, replica_nm_sha = run_nm(
        args.nm, replica_runner
    )
    helpers = semantic_helper_symbols(primary_runtime_references)
    if helpers != semantic_helper_symbols(replica_runtime_references):
        raise CensusError("independent binaries have different semantic helper inventories")
    declared_set = set(normalized_provenance["required_runtime_symbols"])
    for component in normalized_provenance["components"]:
        declared_set.update(component["required_runtime_symbols"])
    declared = sorted(declared_set)
    declared_semantic = [name for name in declared if not name.startswith(CONTROL_PLANE_PREFIXES)]
    if not set(declared_semantic).issubset(helpers):
        raise CensusError("provenance-declared semantic helpers escape independent inventory")
    entries, adapter_route = selected_operation_entries(primary_fields)
    if not set(entries).issubset(primary_symbols) or not set(entries).issubset(replica_symbols):
        raise CensusError("one or more claimed operation entries are absent from a final binary")
    unmodified = run_checked_process([str(primary_runner), "--quiet"], klv, args.timeout)
    helper_marker: dict[str, object]
    negative_controls: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="fre-aot-native-census-") as temporary:
        temporary_path = pathlib.Path(temporary)
        helper_path = temporary_path / "helpers.marker"
        helper_phase = run_checked_process(
            [str(primary_runner), "--quiet"], klv, args.timeout,
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
                [str(primary_runner), "--quiet"], klv, args.timeout,
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


def validate_provenance_record(provenance: object, context: str) -> None:
    if not isinstance(provenance, dict):
        raise CensusError(f"{context} is not an object")
    require_exact_keys(provenance, {
        "schema", "adapter", "model", "benchmark", "source_commit", "source_tree",
        "target", "feature_bits", "kind", "composite_kind", "source_pattern_count",
        "source_to_artifact", "row_total_object_bytes", "boundary", "engine",
        "aggregate_strategy",
        "prepared_bulk_strategy", "span_iteration_strategy", "grep_iteration_strategy",
        "program_sha256", "object_sha256", "program_symbol", "entry_symbol",
        "reducer_symbol", "span_fill_symbol", "required_runtime_symbols", "components",
    }, context)
    if not isinstance(provenance["components"], list):
        raise CensusError(f"{context} components are not a list")
    for index, component in enumerate(provenance["components"]):
        if not isinstance(component, dict):
            raise CensusError(f"{context} component {index} is not an object")
        require_exact_keys(component, {
            "ordinal", "native", "source_ordinal", "entry_symbol",
            "required_runtime_symbols",
            "program_sha256", "object_sha256",
        }, f"{context} component {index}")
        if component["ordinal"] != index or component["native"] is not True:
            raise CensusError(f"{context} component {index} identity is not canonical")
        require_hex64(component["program_sha256"], f"{context} component {index} program")
        require_hex64(component["object_sha256"], f"{context} component {index} object")
        runtime_symbols = component["required_runtime_symbols"]
        if runtime_symbols != sorted(set(runtime_symbols)) or not all(
            isinstance(symbol, str) and SYMBOL.fullmatch(symbol) for symbol in runtime_symbols
        ):
            raise CensusError(f"{context} component {index} runtime symbols are not canonical")
    required_runtime = provenance["required_runtime_symbols"]
    if required_runtime != sorted(set(required_runtime)) or not all(
        isinstance(symbol, str) and SYMBOL.fullmatch(symbol) for symbol in required_runtime
    ):
        raise CensusError(f"{context} runtime symbols are not canonical")
    if provenance["kind"] == "scalar-v2":
        if (
            provenance["schema"] != "fre.aot.rebar-runner.v2"
            or provenance["composite_kind"] is not None
            or provenance["source_pattern_count"] is not None
            or provenance["source_to_artifact"] != []
            or provenance["row_total_object_bytes"] is not None
            or provenance["components"] != []
        ):
            raise CensusError(f"{context} scalar/composite fields disagree")
        require_hex64(provenance["program_sha256"], f"{context} scalar program")
        require_hex64(provenance["object_sha256"], f"{context} scalar object")
    elif provenance["kind"] == "composite-v3":
        if provenance["schema"] != "fre.aot.rebar-runner.v3" or not provenance["components"]:
            raise CensusError(f"{context} composite fields disagree")
        if provenance["composite_kind"] == "regex-redux-fixed-v1":
            if (
                provenance["model"] != "regex-redux"
                or len(provenance["components"]) != 15
                or provenance["source_pattern_count"] != 0
                or provenance["source_to_artifact"] != []
                or provenance["row_total_object_bytes"] is not None
                or any(component["source_ordinal"] is not None for component in provenance["components"])
            ):
                raise CensusError(f"{context} regex-redux topology is not canonical")
        elif provenance["composite_kind"] == "native-row-bridge-v1":
            source_count = provenance["source_pattern_count"]
            source_map = provenance["source_to_artifact"]
            object_bytes = provenance["row_total_object_bytes"]
            if (
                provenance["model"] not in {"count", "count-spans"}
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
            ):
                raise CensusError(f"{context} native-row topology is not canonical")
            first_sources = [
                source_map.index(index) for index in range(len(provenance["components"]))
            ]
            if first_sources != sorted(first_sources) or [
                component["source_ordinal"] for component in provenance["components"]
            ] != first_sources:
                raise CensusError(f"{context} native-row source priority is not canonical")
        else:
            raise CensusError(f"{context} has an unknown composite kind")
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
    if provenance["kind"] != "composite-v3":
        return
    pattern_hashes = input_identity["pattern_sha256"]
    if provenance["source_pattern_count"] != len(pattern_hashes):
        raise CensusError("composite provenance source count differs from sealed job")
    if provenance["composite_kind"] == "native-row-bridge-v1":
        source_map = provenance["source_to_artifact"]
        for source, pattern_hash in enumerate(pattern_hashes):
            for prior in range(source):
                if pattern_hash == pattern_hashes[prior] and source_map[source] != source_map[prior]:
                    raise CensusError("duplicate source patterns map to different artifacts")


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
        validate_provenance_job_binding(provenance, planned["input"])
        expected_object_hashes = (
            [provenance["object_sha256"]]
            if provenance["kind"] == "scalar-v2"
            else [component["object_sha256"] for component in provenance["components"]]
        )
        for label, artifact in (("primary", primary), ("replica", replica)):
            if [row["sha256"] for row in artifact["objects"]] != expected_object_hashes:
                raise CensusError(f"{label} object files differ from provenance")
            if (
                provenance["composite_kind"] == "native-row-bridge-v1"
                and sum(row["bytes"] for row in artifact["objects"])
                != provenance["row_total_object_bytes"]
            ):
                raise CensusError(f"{label} native-row object byte total differs")
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
