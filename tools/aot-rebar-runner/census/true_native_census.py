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


PLAN_SCHEMA = "fre.aot-rebar.true-native-plan.v1"
RECEIPT_SCHEMA = "fre.aot-rebar.true-native-job-receipt.v1"
SUMMARY_SCHEMA = "fre.aot-rebar.true-native-summary.v1"
TRAP_MARKER_SCHEMA = "fre.aot-rebar.runtime-trap.v1"
SCHEDULE_SCHEMA = "fre.full-rebar.campaign.v1"
EXPECTED_PUBLIC_JOBS = 344
EXPECTED_RUNTIME_JOBS = 311
EXPECTED_COMPILE_JOBS = 33
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
SYMBOL = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
CONTROL_PLANE_PREFIXES = (
    "fre_aot_regex_runtime_prepare_",
    "fre_aot_regex_runtime_destroy_",
)
RUNTIME_PREFIX = "fre_aot_regex_runtime_"
TEXT_SYMBOL_TYPES = {"T", "t", "W", "w"}


class CensusError(RuntimeError):
    """A fail-closed census validation error."""


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
            exact_adapter = (
                model in SCALAR_ADAPTER_MODELS and len(identity["pattern_sha256"]) == 1
            ) or model in COMPOSITE_ADAPTER_MODELS
            job_basis = {
                "job_id": job_id,
                "benchmark": benchmark,
                "model": model,
                "input": identity,
                "candidate_klv": candidate,
                "is_runtime": model != "compile",
                "exact_adapter": exact_adapter,
                "adapter_reason": (
                    "exact-single-pattern-scalar-adapter"
                    if exact_adapter
                    else "compile-job-outside-runtime-denominator"
                    if model == "compile"
                    else "no-exact-current-aot-adapter"
                ),
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
        "target": {"triple": args.target, "features": args.features},
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
    require_exact_keys(plan["candidate_source"], {
        "commit", "tree", "cargo_lock_sha256",
    }, "plan candidate source")
    require_exact_keys(plan["public_corpus"], {
        "label", "klv_root_recorded", "privacy_policy", "rebar_revisions", "schedules",
    }, "plan public corpus")
    require_exact_keys(plan["target"], {"triple", "features"}, "plan target")
    require_exact_keys(plan["policy"], {
        "compiler_mode", "timing", "public_klv_bytes_hashed",
        "reproducible_builds_required", "native_proof",
        "compiled_artifact_is_runtime_execution",
        "unsupported_failure_timeout_are_nonnative", "canonical_denominator",
    }, "plan policy")
    for index, schedule in enumerate(plan["public_corpus"]["schedules"]):
        require_exact_keys(schedule, {
            "file_sha256", "internal_sha256", "canonical_commit", "canonical_tree",
            "rebar_revision", "point_count",
        }, f"plan schedule {index}")
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
        if value != id_set(list(value["ids"])):
            raise CensusError(f"denominator {name} is not canonical")
    if denominators["runtime_jobs"]["count"] != EXPECTED_RUNTIME_JOBS:
        raise CensusError("plan does not seal the canonical 311-job runtime denominator")
    job_ids = []
    compile_ids = []
    runtime_ids = []
    exact_ids = []
    for index, job in enumerate(plan["jobs"]):
        require_exact_keys(job, {
            "job_id", "benchmark", "model", "input", "candidate_klv", "is_runtime",
            "exact_adapter", "adapter_reason", "point_ids",
        }, f"plan job {index}")
        require_exact_keys(job["input"], {
            "pattern_sha256", "haystack_sha256", "haystack_bytes",
            "case_insensitive", "unicode",
        }, f"plan job {index} input")
        require_exact_keys(job["candidate_klv"], {
            "path", "sha256", "bytes",
        }, f"plan job {index} KLV")
        job_ids.append(job["job_id"])
        if job["is_runtime"]:
            runtime_ids.append(job["job_id"])
            if job["exact_adapter"]:
                exact_ids.append(job["job_id"])
        else:
            compile_ids.append(job["job_id"])
    point_ids = []
    runtime_point_ids = []
    for index, point in enumerate(plan["points"]):
        require_exact_keys(point, {
            "point_id", "job_id", "benchmark", "model", "boundary", "comparator",
            "expected", "input", "candidate_klv", "reference_klv",
            "source_schedule_sha256", "source_ordinal",
        }, f"plan point {index}")
        require_exact_keys(point["input"], {
            "pattern_sha256", "haystack_sha256", "haystack_bytes",
            "case_insensitive", "unicode",
        }, f"plan point {index} input")
        for name in ("candidate_klv", "reference_klv"):
            require_exact_keys(point[name], {"path", "sha256", "bytes"},
                               f"plan point {index} {name}")
        point_ids.append(point["point_id"])
        if point["model"] != "compile":
            runtime_point_ids.append(point["point_id"])
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
        required = common | {"component_count"}
    else:
        raise CensusError("runner provenance is neither scalar v2 nor composite v3")
    missing = required - set(fields)
    if missing:
        raise CensusError(f"runner provenance omits {sorted(missing)!r}")
    if fields["configured"] != "true":
        raise CensusError("runner is not a configured public Rebar adapter")
    if fields["schema"] == "fre.aot.rebar-runner.v2":
        require_hex64(fields["program_sha256"], "provenance program digest")
        require_hex64(fields["object_sha256"], "provenance object digest")
    else:
        components_from_provenance(fields)
    return fields


def component_field(fields: dict[str, str], index: int, suffixes: tuple[str, ...]) -> str:
    prefixes = (f"component_{index}_", f"component_{index:02d}_", f"component{index}_")
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
    if count <= 0 or count > 256:
        raise CensusError(f"composite component count is out of range: {count}")
    components = []
    for index in range(count):
        entry = component_field(fields, index, ("entry_symbol",))
        runtime_text = component_field(
            fields, index, ("required_runtime_symbols", "runtime_symbols")
        )
        program_sha256 = component_field(fields, index, ("program_sha256",))
        object_sha256 = component_field(fields, index, ("object_sha256",))
        if SYMBOL.fullmatch(entry) is None:
            raise CensusError(f"composite component {index} has invalid entry symbol")
        require_hex64(program_sha256, f"component {index} program digest")
        require_hex64(object_sha256, f"component {index} object digest")
        runtime_symbols = sorted(filter(None, runtime_text.split(",")))
        if len(runtime_symbols) != len(set(runtime_symbols)) or not all(
            SYMBOL.fullmatch(symbol) for symbol in runtime_symbols
        ):
            raise CensusError(f"component {index} runtime symbol list is malformed")
        components.append({
            "ordinal": index,
            "entry_symbol": entry,
            "required_runtime_symbols": runtime_symbols,
            "program_sha256": program_sha256,
            "object_sha256": object_sha256,
        })
    return components


def nm_text_symbols(nm_output: str) -> set[str]:
    result: set[str] = set()
    for line in nm_output.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        name = fields[-1]
        kind = fields[-2] if len(fields[-2]) == 1 else ""
        if kind not in TEXT_SYMBOL_TYPES:
            continue
        if name.startswith("_") and name[1:].startswith("fre_aot_regex_"):
            name = name[1:]
        if SYMBOL.fullmatch(name):
            result.add(name)
    return result


def semantic_helper_symbols(symbols: set[str]) -> list[str]:
    return sorted(
        name for name in symbols
        if name.startswith(RUNTIME_PREFIX)
        and not name.startswith(CONTROL_PLANE_PREFIXES)
    )


def run_nm(nm: str, binary: pathlib.Path) -> tuple[set[str], str]:
    arguments = [nm, "-gU", str(binary)] if sys.platform == "darwin" else [
        nm, "-g", "--defined-only", str(binary)
    ]
    completed = subprocess.run(
        arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False, timeout=60,
    )
    if completed.returncode != 0:
        raise CensusError("nm failed while independently inventorying final binary")
    output = completed.stdout.decode("utf-8", "replace")
    return nm_text_symbols(output), sha_bytes(completed.stdout)


def selected_operation_entries(provenance: dict[str, str]) -> tuple[list[str], str]:
    model = provenance["model"]
    components = components_from_provenance(provenance)
    if components:
        entries = [str(component["entry_symbol"]) for component in components]
        if len(entries) != len(set(entries)):
            raise CensusError("composite provenance repeats an entry symbol")
        return entries, "linked-composite-fixed-stages"
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
    return {
        **common,
        "kind": "composite-v3",
        "engine": None,
        "aggregate_strategy": None,
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
    expected_object_hashes = (
        [normalized_provenance["object_sha256"]]
        if normalized_provenance["kind"] == "scalar-v2"
        else [component["object_sha256"] for component in normalized_provenance["components"]]
    )
    if [row["sha256"] for row in primary_hashes["objects"]] != expected_object_hashes:
        raise CensusError("primary object files differ from provenance object identities")
    if [row["sha256"] for row in replica_hashes["objects"]] != expected_object_hashes:
        raise CensusError("replica object files differ from provenance object identities")
    reproducible = primary_hashes == replica_hashes
    primary_symbols, primary_nm_sha = run_nm(args.nm, primary_runner)
    replica_symbols, replica_nm_sha = run_nm(args.nm, replica_runner)
    helpers = semantic_helper_symbols(primary_symbols)
    if helpers != semantic_helper_symbols(replica_symbols):
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
    helper_armed = [row.get("symbol") for row in helper_marker.get("armed", [])]
    helper_pass = (
        bool(helpers)
        and helper_phase["returncode"] == 0
        and helper_marker.get("status") == "valid"
        and helper_marker.get("installed") == len(helpers)
        and helper_marker.get("expected") == len(helpers)
        and helper_armed == helpers
        and helper_marker.get("triggered") is None
        and helper_marker.get("completed") == "normal"
    )
    negative_pass = len(negative_controls) == len(entries) and all(
        control["process"]["returncode"] == TRAP_EXIT
        and control["marker"].get("status") == "valid"
        and control["marker"].get("installed") == 1
        and control["marker"].get("expected") == 1
        and control["marker"].get("triggered") == control["symbol"]
        for control in negative_controls
    )
    executed = unmodified["returncode"] == 0
    core_native = reproducible and executed and helper_pass and negative_pass
    adapter_outer_loop = adapter_route == "linked-direct-entry-adapter-loop"
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
        "phases": {
            "unmodified_oracle": unmodified,
            "semantic_helper_trap": {"process": helper_phase, "marker": helper_marker},
            "claimed_entry_negative_traps": negative_controls,
        },
        "classification": {
            "built_reproducibly": reproducible,
            "executed_oracle_correct": executed,
            "native_search_core_authenticated": core_native,
            "adapter_outer_loop": adapter_outer_loop,
            "whole_operation_native_authenticated": whole_native,
            "reason": reason,
        },
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


def validate_marker_record(marker: object, context: str) -> None:
    if not isinstance(marker, dict):
        raise CensusError(f"{context} is not an object")
    required = {"status", "sha256", "armed", "triggered"}
    allowed = required | {"kind", "architecture", "installed", "expected", "completed"}
    if not required.issubset(marker) or not set(marker).issubset(allowed):
        raise CensusError(f"{context} marker schema is not closed")
    for index, armed in enumerate(marker["armed"]):
        require_exact_keys(armed, {"symbol", "offset", "before", "after"},
                           f"{context} armed record {index}")


def validate_provenance_record(provenance: object, context: str) -> None:
    if not isinstance(provenance, dict):
        raise CensusError(f"{context} is not an object")
    require_exact_keys(provenance, {
        "schema", "adapter", "model", "benchmark", "source_commit", "source_tree",
        "target", "feature_bits", "kind", "engine", "aggregate_strategy",
        "prepared_bulk_strategy", "span_iteration_strategy", "grep_iteration_strategy",
        "program_sha256", "object_sha256", "program_symbol", "entry_symbol",
        "reducer_symbol", "span_fill_symbol", "required_runtime_symbols", "components",
    }, context)
    for index, component in enumerate(provenance["components"]):
        require_exact_keys(component, {
            "ordinal", "entry_symbol", "required_runtime_symbols",
            "program_sha256", "object_sha256",
        }, f"{context} component {index}")


def validate_receipt(receipt: object, plan_sha256: str) -> dict[str, object]:
    if not isinstance(receipt, dict):
        raise CensusError("job receipt is not an object")
    require_exact_keys(receipt, {
        "schema", "plan_sha256", "candidate_source", "job", "artifacts", "route",
        "phases", "classification", "receipt_sha256",
    }, "job receipt")
    if receipt["schema"] != RECEIPT_SCHEMA or receipt["plan_sha256"] != plan_sha256:
        raise CensusError("job receipt schema or plan binding differs")
    validate_digest(receipt, "receipt_sha256", "job receipt")
    require_exact_keys(receipt["candidate_source"], {
        "commit", "tree", "cargo_lock_sha256",
    }, "job receipt candidate source")
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
    artifacts = receipt["artifacts"]
    require_exact_keys(artifacts, {
        "primary", "replica", "reproducible", "compiled_artifact_present",
        "runtime_execution_authenticated_separately", "provenance",
    }, "job receipt artifacts")
    for label in ("primary", "replica"):
        artifact = artifacts[label]
        if artifact is not None:
            require_exact_keys(artifact, {"runner_sha256", "objects"},
                               f"job receipt {label} artifact")
            for index, obj in enumerate(artifact["objects"]):
                require_exact_keys(obj, {"ordinal", "sha256", "bytes"},
                                   f"job receipt {label} object {index}")
    if artifacts["provenance"] is not None:
        validate_provenance_record(artifacts["provenance"], "job receipt provenance")
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
    phases = receipt["phases"]
    if set(phases) == {"pre_execution_failure"}:
        failure = phases["pre_execution_failure"]
        require_exact_keys(failure, {"stage", "outcome", "evidence"},
                           "job receipt pre-execution failure")
        if failure["evidence"] is not None:
            require_exact_keys(failure["evidence"], {"sha256", "bytes"},
                               "job receipt failure evidence")
    elif set(phases) == {
        "unmodified_oracle", "semantic_helper_trap", "claimed_entry_negative_traps",
    }:
        validate_process_record(phases["unmodified_oracle"], "unmodified oracle phase")
        helper = phases["semantic_helper_trap"]
        require_exact_keys(helper, {"process", "marker"}, "semantic helper phase")
        validate_process_record(helper["process"], "semantic helper process")
        validate_marker_record(helper["marker"], "semantic helper marker")
        for index, control in enumerate(phases["claimed_entry_negative_traps"]):
            require_exact_keys(control, {"ordinal", "symbol", "process", "marker"},
                               f"claimed entry control {index}")
            validate_process_record(control["process"], f"claimed entry process {index}")
            validate_marker_record(control["marker"], f"claimed entry marker {index}")
    else:
        raise CensusError("job receipt phase schema is not closed")
    require_exact_keys(receipt["classification"], {
        "built_reproducibly", "executed_oracle_correct",
        "native_search_core_authenticated", "adapter_outer_loop",
        "whole_operation_native_authenticated", "reason",
    }, "job receipt classification")
    return receipt


def summarize(args: argparse.Namespace) -> dict[str, object]:
    plan = validate_plan(load_json(pathlib.Path(args.plan)))
    runtime_ids = list(plan["denominators"]["runtime_jobs"]["ids"])
    jobs = {row["job_id"]: row for row in plan["jobs"]}
    receipts: dict[str, dict[str, object]] = {}
    receipt_files = sorted(pathlib.Path(args.receipts).glob("*.json"))
    for path in receipt_files:
        receipt = validate_receipt(load_json(path), plan["plan_sha256"])
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
                write_exclusive(pathlib.Path(args.output), payload)
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
