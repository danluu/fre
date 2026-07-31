#!/usr/bin/env python3
"""Seal result-blind Search V26 static/correctness evidence.

This tool grants correctness evidence only. It does not read performance
results and cannot authorize a performance gate, promotion, or deployment.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Any, Iterable


RECEIPT_SCHEMA = "fre.aot.search-v26-correctness-receipt.v2"
EXECUTION_SCHEMA = "fre.aot.search-v26-platform-execution-manifest.v1"
STATIC_SCHEMA = "fre.aot.search-v26-local-static-parity.v1"
CORRECTNESS_SCHEMA = "fre.aot.search-v26-native-correctness.v2"
BUILD_IDENTITY_SCHEMA = "fre.aot.search-v26-evidence-build-identity.v1"
RUNNER_BASENAME = "fre-search-v26-synthetic-runner"
EXECUTION_TOOL_BASENAME = "run_correctness_lane.py"
VALIDATION_TOOL_BASENAME = "seal_correctness_receipt.py"
EXECUTION_TOOL_REPOSITORY_PATH = (
    "research/aot/search-v26-width-cost-rule-r1/run_correctness_lane.py"
)
VALIDATION_TOOL_REPOSITORY_PATH = (
    "research/aot/search-v26-width-cost-rule-r1/seal_correctness_receipt.py"
)
EXECUTION_ENVIRONMENT = {
    "LANG": "C",
    "LC_ALL": "C",
    "RUST_BACKTRACE": "0",
    "TZ": "UTC",
}
POPULATION_SHA256 = "a682375f2e6e051f97322396bafc46974df47baa3518bc17f5d6b71b56407b73"
SOURCE_SET_DOMAIN = b"FRE-V26-EVIDENCE-FULL-REPOSITORY-SOURCE-SET\0\x01"
EXPECTED_TOTALS = {
    "objects": 1296,
    "code_bytes": 3112416,
    "data_bytes": 24624,
    "labels": 56784,
    "relocations": 130944,
    "emission_work": 7589496,
    "scratch_bytes": 3649536,
    "vector_instructions": 377136,
    "audited_instructions": 778104,
}
MAX_REPORT_BYTES = 1 << 20
MAX_ARCHIVE_BYTES = 2 << 30
MAX_RUNNER_BYTES = 256 << 20
MAX_EXECUTION_TOOL_BYTES = 1 << 20
GIT_EXECUTABLE = "/usr/bin/git"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HOST_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+=@-]{7,255}\Z")
FORBIDDEN_EXACT_IDENTITIES = {
    "0" * 40,
    "f" * 40,
    "0" * 64,
    "f" * 64,
}


class Refusal(RuntimeError):
    """A fail-closed evidence refusal."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def require_exact_keys(value: dict[str, Any], expected: Iterable[str], name: str) -> None:
    expected_set = set(expected)
    require(set(value) == expected_set, f"{name} keys changed")


def require_exact_integer(value: Any, expected: int, name: str) -> None:
    require(
        type(value) is int and value == expected,
        f"{name} is not exact integer {expected}",
    )


def require_hex(value: str, width: int, name: str) -> str:
    pattern = HEX40 if width == 40 else HEX64
    require(isinstance(value, str) and pattern.fullmatch(value) is not None, f"{name} is not lowercase hex{width}")
    require(value not in FORBIDDEN_EXACT_IDENTITIES, f"{name} is a forbidden placeholder")
    lowered = value.lower()
    require(
        all(token not in lowered for token in ("pending", "placeholder", "unknown", "todo")),
        f"{name} contains a placeholder",
    )
    return value


def require_host_identity(value: str, name: str) -> str:
    require(
        isinstance(value, str) and HOST_IDENTITY.fullmatch(value) is not None,
        f"{name} is not a bounded operator-supplied fingerprint",
    )
    lowered = value.lower()
    require(
        all(token not in lowered for token in ("pending", "placeholder", "unknown", "todo")),
        f"{name} contains a placeholder",
    )
    return value


def stable_bytes(path: Path, maximum: int, name: str) -> bytes:
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and not path.is_symlink(), f"{name} is not a regular file")
    require(0 < before.st_size <= maximum, f"{name} has an invalid size")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        require(
            (opened.st_dev, opened.st_ino, opened.st_size)
            == (before.st_dev, before.st_ino, before.st_size),
            f"{name} changed before open",
        )
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1 << 20, remaining))
            require(bool(chunk), f"{name} ended early")
            chunks.append(chunk)
            remaining -= len(chunk)
        require(not os.read(descriptor, 1), f"{name} grew while read")
        after_open = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after_path = path.lstat()
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_open = (
        after_open.st_dev,
        after_open.st_ino,
        after_open.st_size,
        after_open.st_mtime_ns,
        after_open.st_ctime_ns,
    )
    identity_after = (
        after_path.st_dev,
        after_path.st_ino,
        after_path.st_size,
        after_path.st_mtime_ns,
        after_path.st_ctime_ns,
    )
    require(identity_before == identity_open == identity_after, f"{name} mutated while read")
    return b"".join(chunks)


def stable_sha256(path: Path, maximum: int, expected: str, name: str) -> tuple[str, int]:
    expected = require_hex(expected, 64, f"{name} expected sha256")
    content = stable_bytes(path, maximum, name)
    observed = hashlib.sha256(content).hexdigest()
    require(observed == expected, f"{name} sha256 mismatch")
    return observed, len(content)


def validate_runner_artifact(
    path: Path,
    expected_sha256: str,
    lane: str,
) -> tuple[bytes, str, int]:
    require(lane in {"local", "c9g"}, "runner lane is invalid")
    require(path.name == RUNNER_BASENAME, f"{lane} runner basename changed")
    metadata = path.lstat()
    require(
        stat.S_ISREG(metadata.st_mode)
        and not path.is_symlink()
        and metadata.st_mode & 0o111 != 0,
        f"{lane} runner is not a regular executable file",
    )
    raw = stable_bytes(path, MAX_RUNNER_BYTES, f"{lane} runner binary")
    observed_sha256 = hashlib.sha256(raw).hexdigest()
    require(
        observed_sha256
        == require_hex(
            expected_sha256, 64, f"{lane} runner binary expected sha256"
        ),
        f"{lane} runner binary sha256 mismatch",
    )
    if lane == "local":
        require(
            len(raw) >= 32
            and raw[:4] == b"\xcf\xfa\xed\xfe"
            and int.from_bytes(raw[4:8], "little") == 0x0100000C,
            "local runner is not a thin little-endian AArch64 Mach-O",
        )
    else:
        require(
            len(raw) >= 64
            and raw[:4] == b"\x7fELF"
            and raw[4] == 2
            and raw[5] == 1
            and int.from_bytes(raw[16:18], "little") in {2, 3}
            and int.from_bytes(raw[18:20], "little") == 183,
            "c9g runner is not a little-endian AArch64 ELF executable",
        )
    return raw, observed_sha256, len(raw)


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        require(key not in value, f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def reject_json_float(token: str) -> None:
    raise Refusal(f"floating JSON number {token!r} is forbidden")


def strict_json(path: Path, expected_sha256: str, name: str) -> tuple[bytes, dict[str, Any]]:
    expected_sha256 = require_hex(expected_sha256, 64, f"{name} expected sha256")
    raw = stable_bytes(path, MAX_REPORT_BYTES, name)
    observed = hashlib.sha256(raw).hexdigest()
    require(observed == expected_sha256, f"{name} sha256 mismatch")
    require(
        raw.endswith(b"\n") and raw.count(b"\n") == 1 and b"\r" not in raw,
        f"{name} is not exactly one LF-terminated JSON line",
    )
    return raw, strict_json_bytes(raw, name)


def strict_json_bytes(raw: bytes, name: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicate_pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                Refusal(f"non-finite JSON token {token}")
            ),
            parse_float=reject_json_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Refusal(f"{name} is not strict UTF-8 JSON: {error}") from error
    require(isinstance(value, dict), f"{name} root is not an object")
    return value


def validate_static(report: dict[str, Any]) -> None:
    require_exact_keys(
        report,
        {
            "schema",
            "population_sha256",
            "candidate_backend",
            "short_source_backend",
            "wide_source_backend",
            "literals",
            "exact_machine_object_parities",
            "distinct_aot_identities",
            "routing_boundary_checks",
            "candidate_aot_magic_hex",
            "candidate",
            "selected_source",
            "timing",
        },
        "static report",
    )
    require(report["schema"] == STATIC_SCHEMA, "static schema changed")
    require(report["population_sha256"] == POPULATION_SHA256, "static population changed")
    require(
        report["candidate_backend"] == 39
        and report["short_source_backend"] == 30
        and report["wide_source_backend"] == 38,
        "static backend identities changed",
    )
    for field, expected in (
        ("candidate_backend", 39),
        ("short_source_backend", 30),
        ("wide_source_backend", 38),
        ("literals", 1296),
        ("exact_machine_object_parities", 1296),
        ("distinct_aot_identities", 1296),
        ("routing_boundary_checks", 24),
    ):
        require_exact_integer(report[field], expected, f"static {field}")
    require(report["candidate_aot_magic_hex"] == "4652454136340027", "V26 AOT magic changed")
    require(report["timing"] == "not-run", "static report contains timing")
    require(
        canonical_bytes(report["candidate"]) == canonical_bytes(EXPECTED_TOTALS),
        "candidate static totals changed",
    )
    require(
        canonical_bytes(report["selected_source"]) == canonical_bytes(EXPECTED_TOTALS),
        "source static totals changed",
    )


def validate_build_identity(
    report: dict[str, Any],
    lane: str,
    source_commit: str,
    source_tree: str,
    source_archive_sha256: str,
    source_set_sha256: str,
) -> None:
    require(lane in {"local", "c9g"}, "runner build-identity lane is invalid")
    require_exact_keys(
        report,
        {
            "candidate_backend",
            "debug_assertions",
            "performance_gate_authority",
            "population_sha256",
            "production_or_deployment_authority",
            "schema",
            "search_performance_timing_present",
            "source_archive_sha256",
            "source_commit",
            "source_set_sha256",
            "source_tree",
            "target_architecture",
            "target_little_endian",
            "target_operating_system",
            "target_pointer_width",
        },
        "runner build identity",
    )
    require(
        report["schema"] == BUILD_IDENTITY_SCHEMA,
        "runner build-identity schema changed",
    )
    require_exact_integer(
        report["candidate_backend"], 39, "runner build candidate backend"
    )
    require(
        report["population_sha256"] == POPULATION_SHA256,
        "runner build identity has the wrong population",
    )
    require(
        report["debug_assertions"] is False
        and report["performance_gate_authority"] is False
        and report["production_or_deployment_authority"] is False
        and report["search_performance_timing_present"] is False,
        "runner build identity is debug or acquired forbidden authority",
    )
    require_exact_integer(
        report["target_pointer_width"], 64, f"{lane} runner target pointer width"
    )
    require(
        report["target_architecture"] == "aarch64"
        and report["target_little_endian"] is True
        and report["target_operating_system"]
        == ("macos" if lane == "local" else "linux"),
        f"{lane} runner embedded target identity changed",
    )
    expected = {
        "source_commit": require_hex(source_commit, 40, "expected source commit"),
        "source_tree": require_hex(source_tree, 40, "expected source tree"),
        "source_archive_sha256": require_hex(
            source_archive_sha256, 64, "expected source archive sha256"
        ),
        "source_set_sha256": require_hex(
            source_set_sha256, 64, "expected source-set sha256"
        ),
    }
    for field, value in expected.items():
        require(report[field] == value, f"runner embedded {field} mismatch")
        require_hex(report[field], len(value), f"runner embedded {field}")


def validate_target(target: dict[str, Any], lane: str) -> None:
    require_exact_keys(
        target,
        {"architecture", "operating_system", "pointer_width", "little_endian", "features"},
        f"{lane} target",
    )
    require_exact_integer(target["pointer_width"], 64, f"{lane} target pointer width")
    require(
        target["architecture"] == "aarch64" and target["little_endian"] is True,
        f"{lane} target is not little-endian AArch64",
    )
    expected_os = "macos" if lane == "local" else "linux"
    require(target["operating_system"] == expected_os, f"{lane} operating system changed")
    features = target["features"]
    require(isinstance(features, dict), f"{lane} features are not an object")
    require_exact_keys(features, {"asimd", "sve", "sve2", "sve_vector_bytes"}, f"{lane} features")
    require(features["asimd"] is True, f"{lane} lacks ASIMD")
    require(type(features["sve"]) is bool and type(features["sve2"]) is bool, f"{lane} SVE facts are not bools")
    require(not features["sve2"] or features["sve"], f"{lane} reports SVE2 without SVE")
    vector_bytes = features["sve_vector_bytes"]
    if features["sve"]:
        require(
            isinstance(vector_bytes, int)
            and not isinstance(vector_bytes, bool)
            and vector_bytes >= 16
            and vector_bytes % 16 == 0,
            f"{lane} SVE vector length is invalid",
        )
    else:
        require(vector_bytes is None, f"{lane} has an SVE vector length without SVE")


def validate_correctness(report: dict[str, Any], lane: str) -> None:
    require_exact_keys(
        report,
        {
            "schema",
            "lane",
            "population_sha256",
            "backend",
            "literals",
            "window_shapes",
            "comparisons",
            "mismatches",
            "target",
        },
        f"{lane} correctness report",
    )
    require(report["schema"] == CORRECTNESS_SCHEMA, f"{lane} correctness schema changed")
    require(report["lane"] == lane, f"{lane} lane binding changed")
    require(report["population_sha256"] == POPULATION_SHA256, f"{lane} population changed")
    require(report["backend"] == 39, f"{lane} backend changed")
    require_exact_integer(report["backend"], 39, f"{lane} correctness backend")
    for field, expected in (
        ("literals", 1296),
        ("window_shapes", 6),
        ("comparisons", 7776),
        ("mismatches", 0),
    ):
        require_exact_integer(
            report[field], expected, f"{lane} correctness {field}"
        )
    require(isinstance(report["target"], dict), f"{lane} target is not an object")
    validate_target(report["target"], lane)


def git_environment() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "LANG": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }


def git_output(source_root: Path, arguments: list[str]) -> str:
    completed = subprocess.run(
        [GIT_EXECUTABLE, "-C", str(source_root), *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=git_environment(),
    )
    require(
        completed.returncode == 0,
        f"git {' '.join(arguments)} failed: {completed.stderr.decode('utf-8', 'replace').strip()}",
    )
    return completed.stdout.decode("utf-8").strip()


def validate_source(source_root: Path, expected_commit: str, expected_tree: str) -> None:
    require(source_root.is_dir() and not source_root.is_symlink(), "source root is not a directory")
    expected_commit = require_hex(expected_commit, 40, "source commit")
    expected_tree = require_hex(expected_tree, 40, "source tree")
    observed_commit = git_output(source_root, ["rev-parse", "--verify", "HEAD^{commit}"])
    observed_tree = git_output(source_root, ["rev-parse", "--verify", "HEAD^{tree}"])
    require(observed_commit == expected_commit, "source commit does not match checked-out HEAD")
    require(observed_tree == expected_tree, "source tree does not match checked-out HEAD")
    require(
        git_output(source_root, ["status", "--porcelain=v1", "--untracked-files=all"]) == "",
        "source worktree is dirty",
    )


def validate_tracked_tool_bytes(
    source_root: Path,
    expected_commit: str,
    repository_path: str,
    observed: bytes,
    name: str,
) -> None:
    require(
        repository_path
        in {EXECUTION_TOOL_REPOSITORY_PATH, VALIDATION_TOOL_REPOSITORY_PATH},
        f"{name} repository path is not frozen",
    )
    completed = subprocess.run(
        [
            GIT_EXECUTABLE,
            "-C",
            str(source_root),
            "show",
            f"{expected_commit}:{repository_path}",
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=git_environment(),
    )
    require(
        completed.returncode == 0,
        f"cannot read bound {name} blob: "
        f"{completed.stderr.decode('utf-8', 'replace').strip()}",
    )
    require(
        0 < len(completed.stdout) <= MAX_EXECUTION_TOOL_BYTES,
        f"bound {name} blob has an invalid size",
    )
    require(
        completed.stdout == observed,
        f"{name} differs from the exact bound source-commit blob",
    )


def git_source_set_sha256(source_root: Path, expected_commit: str) -> str:
    expected_commit = require_hex(expected_commit, 40, "source-set commit")
    listing = subprocess.run(
        [
            GIT_EXECUTABLE,
            "-C",
            str(source_root),
            "ls-tree",
            "-r",
            "-z",
            "--full-tree",
            expected_commit,
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=git_environment(),
    )
    require(
        listing.returncode == 0,
        "cannot enumerate bound source tree: "
        f"{listing.stderr.decode('utf-8', 'replace').strip()}",
    )
    entries: list[tuple[bytes, bytes, bytes]] = []
    for record in listing.stdout.split(b"\0"):
        if not record:
            continue
        try:
            metadata, repository_path = record.split(b"\t", 1)
            mode, object_type, object_id = metadata.split(b" ", 2)
        except ValueError as error:
            raise Refusal("bound source-tree listing is malformed") from error
        require(
            object_type == b"blob" and mode in {b"100644", b"100755", b"120000"},
            "bound source tree contains an unsupported entry",
        )
        require(
            repository_path
            and not repository_path.startswith(b"/")
            and b"\0" not in repository_path,
            "bound source-tree path is not canonical",
        )
        entries.append((repository_path, mode, object_id))
    entries.sort(key=lambda item: item[0])
    require(bool(entries), "bound source set is empty")
    batch = subprocess.run(
        [GIT_EXECUTABLE, "-C", str(source_root), "cat-file", "--batch"],
        input=b"".join(object_id + b"\n" for _, _, object_id in entries),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=git_environment(),
    )
    require(
        batch.returncode == 0,
        "cannot read bound source blobs: "
        f"{batch.stderr.decode('utf-8', 'replace').strip()}",
    )
    cursor = 0
    hasher = hashlib.sha256(SOURCE_SET_DOMAIN)
    for repository_path, mode, expected_object_id in entries:
        header_end = batch.stdout.find(b"\n", cursor)
        require(header_end >= 0, "source blob batch header is truncated")
        header = batch.stdout[cursor:header_end]
        cursor = header_end + 1
        try:
            object_id, object_type, encoded_size = header.split(b" ", 2)
            blob_size = int(encoded_size)
        except ValueError as error:
            raise Refusal("source blob batch header is malformed") from error
        require(
            object_id == expected_object_id
            and object_type == b"blob"
            and 0 <= blob_size <= MAX_ARCHIVE_BYTES,
            "source blob batch identity changed",
        )
        blob_end = cursor + blob_size
        require(
            blob_end < len(batch.stdout)
            and batch.stdout[blob_end : blob_end + 1] == b"\n",
            "source blob batch body is truncated",
        )
        content = batch.stdout[cursor:blob_end]
        cursor = blob_end + 1
        require(
            len(repository_path) <= (1 << 32) - 1,
            "source-set path exceeds u32",
        )
        hasher.update(mode)
        hasher.update(len(repository_path).to_bytes(4, "little"))
        hasher.update(repository_path)
        hasher.update(len(content).to_bytes(8, "little"))
        hasher.update(content)
    require(cursor == len(batch.stdout), "source blob batch has trailing data")
    return hasher.hexdigest()


def verify_git_archive(
    source_root: Path,
    expected_commit: str,
    archive_path: Path,
    expected_sha256: str,
) -> tuple[str, int]:
    supplied = stable_bytes(archive_path, MAX_ARCHIVE_BYTES, "source archive")
    supplied_sha256 = hashlib.sha256(supplied).hexdigest()
    require(
        supplied_sha256 == require_hex(expected_sha256, 64, "source archive expected sha256"),
        "source archive sha256 mismatch",
    )
    completed = subprocess.run(
        [
            GIT_EXECUTABLE,
            "-C",
            str(source_root),
            "archive",
            "--format=tar",
            expected_commit,
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=git_environment(),
    )
    require(
        completed.returncode == 0,
        f"deterministic git archive failed: {completed.stderr.decode('utf-8', 'replace').strip()}",
    )
    require(0 < len(completed.stdout) <= MAX_ARCHIVE_BYTES, "generated git archive size is invalid")
    require(
        completed.stdout == supplied,
        "source archive is not byte-for-byte deterministic git archive --format=tar of bound commit",
    )
    return supplied_sha256, len(supplied)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def validate_created_utc(value: str) -> str:
    require(isinstance(value, str) and value.endswith("Z"), "created UTC must end in Z")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError as error:
        raise Refusal("created UTC must use YYYY-MM-DDTHH:MM:SSZ") from error
    require(parsed.strftime("%Y-%m-%dT%H:%M:%SZ") == value, "created UTC is not canonical")
    return value


def expected_report_binding(
    raw: bytes,
    schema: str,
    argv: list[str],
) -> dict[str, Any]:
    return {
        "argv": argv,
        "report_sha256": hashlib.sha256(raw).hexdigest(),
        "report_bytes": len(raw),
        "schema": schema,
    }


def execution_payload(
    *,
    lane: str,
    created_utc: str,
    host_identity: str,
    source_commit: str,
    source_tree: str,
    archive_sha256: str,
    archive_bytes: int,
    source_set_sha256: str,
    runner_sha256: str,
    runner_bytes: int,
    execution_tool_sha256: str,
    execution_tool_bytes: int,
    validation_tool_sha256: str,
    validation_tool_bytes: int,
    build_identity_raw: bytes,
    build_identity_report: dict[str, Any],
    correctness_raw: bytes,
    correctness_report: dict[str, Any],
    static_raw: bytes | None,
) -> dict[str, Any]:
    require(lane in {"local", "c9g"}, "execution lane is invalid")
    reports: dict[str, Any] = {
        "build_identity": expected_report_binding(
            build_identity_raw,
            BUILD_IDENTITY_SCHEMA,
            [RUNNER_BASENAME, "evidence-build-identity"],
        )
    }
    if static_raw is not None:
        reports["static"] = expected_report_binding(
            static_raw, STATIC_SCHEMA, [RUNNER_BASENAME, "static"]
        )
    reports["correctness"] = expected_report_binding(
        correctness_raw,
        CORRECTNESS_SCHEMA,
        [RUNNER_BASENAME, "correctness", lane],
    )
    return {
        "created_utc": validate_created_utc(created_utc),
        "lane": lane,
        "operator_host_identity": require_host_identity(
            host_identity, f"{lane} host identity"
        ),
        "host_platform": {
            "architecture": "aarch64",
            "operating_system": "macos" if lane == "local" else "linux",
        },
        "source": {
            "commit": require_hex(source_commit, 40, "execution source commit"),
            "tree": require_hex(source_tree, 40, "execution source tree"),
            "archive_sha256": require_hex(
                archive_sha256, 64, "execution source archive sha256"
            ),
            "archive_bytes": archive_bytes,
            "archive_format": "git-archive-tar",
            "deterministic_byte_match": True,
            "source_set_sha256": require_hex(
                source_set_sha256, 64, "execution source-set sha256"
            ),
        },
        "runner": {
            "binary_sha256": require_hex(
                runner_sha256, 64, f"{lane} runner binary sha256"
            ),
            "binary_bytes": runner_bytes,
            "basename": RUNNER_BASENAME,
            "build_identity": build_identity_report,
            "execution_mechanism": (
                "closed-private-inode"
                if lane == "local"
                else "validated-open-fd"
            ),
            "format": "macho64-aarch64" if lane == "local" else "elf64-aarch64",
        },
        "execution_tool": {
            "sha256": require_hex(
                execution_tool_sha256, 64, "execution tool sha256"
            ),
            "bytes": execution_tool_bytes,
            "basename": EXECUTION_TOOL_BASENAME,
        },
        "validation_tool": {
            "sha256": require_hex(
                validation_tool_sha256, 64, "validation tool sha256"
            ),
            "bytes": validation_tool_bytes,
            "basename": VALIDATION_TOOL_BASENAME,
        },
        "environment": dict(EXECUTION_ENVIRONMENT),
        "working_directory": "private-staged-runner-directory",
        "reports": reports,
        "target": correctness_report["target"],
        "result_policy": {
            "correctness_machine_code_executed": True,
            "search_performance_timing_present": False,
            "performance_gate_authority": False,
            "production_or_deployment_authority": False,
        },
    }


def execution_manifest(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": EXECUTION_SCHEMA,
        "payload_sha256": hashlib.sha256(canonical_bytes(payload)).hexdigest(),
        "payload": payload,
    }


def validate_execution_envelope(
    manifest: dict[str, Any],
    lane: str,
) -> dict[str, Any]:
    require_exact_keys(
        manifest, {"schema", "payload_sha256", "payload"}, f"{lane} execution manifest"
    )
    require(manifest["schema"] == EXECUTION_SCHEMA, f"{lane} execution schema changed")
    require(isinstance(manifest["payload"], dict), f"{lane} execution payload is not an object")
    observed_payload_sha = hashlib.sha256(canonical_bytes(manifest["payload"])).hexdigest()
    supplied_payload_sha = require_hex(
        manifest["payload_sha256"], 64, f"{lane} execution payload sha256"
    )
    require(
        supplied_payload_sha == observed_payload_sha,
        f"{lane} execution payload hash mismatch",
    )
    return manifest["payload"]


def validate_execution_manifest(
    *,
    raw: bytes,
    manifest: dict[str, Any],
    expected_payload: dict[str, Any],
    lane: str,
) -> None:
    require(
        raw == canonical_bytes(manifest) + b"\n",
        f"{lane} execution manifest is not canonical JSON",
    )
    validate_execution_envelope(manifest, lane)
    require(
        canonical_bytes(manifest["payload"]) == canonical_bytes(expected_payload),
        f"{lane} execution bindings changed",
    )


def create_new_output(path: Path, content: bytes) -> None:
    require(path.parent.is_dir() and not path.parent.is_symlink(), "output parent is not a directory")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o444)
    try:
        written = 0
        while written < len(content):
            amount = os.write(descriptor, content[written:])
            require(amount > 0, "receipt write made no progress")
            written += amount
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o444)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def seal(arguments: argparse.Namespace) -> dict[str, Any]:
    source_root = Path(arguments.source_root)
    source_archive = Path(arguments.source_archive)
    local_runner_binary = Path(arguments.local_runner_binary)
    c9g_runner_binary = Path(arguments.c9g_runner_binary)
    execution_tool = Path(arguments.execution_tool)
    static_path = Path(arguments.static_report)
    local_path = Path(arguments.local_report)
    c9g_path = Path(arguments.c9g_report)
    local_manifest_path = Path(arguments.local_execution_manifest)
    c9g_manifest_path = Path(arguments.c9g_execution_manifest)
    output_path = Path(arguments.output)

    require(not os.path.lexists(output_path), "receipt output already exists")
    require(
        not output_path.resolve(strict=False).is_relative_to(source_root.resolve()),
        "receipt output must be outside the bound source worktree",
    )
    require(
        execution_tool.name == EXECUTION_TOOL_BASENAME,
        "platform execution tool basename changed",
    )
    require(
        Path(__file__).resolve().name == VALIDATION_TOOL_BASENAME,
        "receipt validation tool basename changed",
    )
    execution_tool_metadata = execution_tool.lstat()
    require(
        stat.S_ISREG(execution_tool_metadata.st_mode)
        and not execution_tool.is_symlink()
        and execution_tool_metadata.st_mode & 0o111 != 0,
        "platform execution tool is not a regular executable file",
    )
    validate_source(source_root, arguments.source_commit, arguments.source_tree)
    archive_sha, archive_bytes = verify_git_archive(
        source_root,
        arguments.source_commit,
        source_archive,
        arguments.source_archive_sha256,
    )
    source_set_sha = git_source_set_sha256(
        source_root, arguments.source_commit
    )
    require(
        local_runner_binary.resolve() != c9g_runner_binary.resolve(),
        "local and c9g runners must use distinct platform artifact paths",
    )
    _, local_runner_sha, local_runner_bytes = validate_runner_artifact(
        local_runner_binary,
        arguments.local_runner_binary_sha256,
        "local",
    )
    _, c9g_runner_sha, c9g_runner_bytes = validate_runner_artifact(
        c9g_runner_binary,
        arguments.c9g_runner_binary_sha256,
        "c9g",
    )
    require(
        local_runner_sha != c9g_runner_sha,
        "local and c9g runners must have distinct platform artifact hashes",
    )
    execution_tool_sha, execution_tool_bytes = stable_sha256(
        execution_tool,
        MAX_EXECUTION_TOOL_BYTES,
        arguments.execution_tool_sha256,
        "platform execution tool",
    )
    validation_tool_raw = stable_bytes(
        Path(__file__).resolve(), MAX_EXECUTION_TOOL_BYTES, "validation tool"
    )
    validation_tool_sha = hashlib.sha256(validation_tool_raw).hexdigest()
    validation_tool_bytes = len(validation_tool_raw)
    validate_tracked_tool_bytes(
        source_root,
        arguments.source_commit,
        EXECUTION_TOOL_REPOSITORY_PATH,
        stable_bytes(
            execution_tool, MAX_EXECUTION_TOOL_BYTES, "platform execution tool"
        ),
        "platform execution tool",
    )
    validate_tracked_tool_bytes(
        source_root,
        arguments.source_commit,
        VALIDATION_TOOL_REPOSITORY_PATH,
        validation_tool_raw,
        "receipt validation tool",
    )
    require(
        execution_tool.resolve() != Path(__file__).resolve()
        and execution_tool_sha != validation_tool_sha,
        "platform execution and receipt validation tools are not distinct",
    )
    static_raw, static_report = strict_json(
        static_path, arguments.static_report_sha256, "static report"
    )
    local_raw, local_report = strict_json(
        local_path, arguments.local_report_sha256, "local correctness report"
    )
    c9g_raw, c9g_report = strict_json(
        c9g_path, arguments.c9g_report_sha256, "c9g correctness report"
    )
    local_manifest_raw, local_manifest = strict_json(
        local_manifest_path,
        arguments.local_execution_manifest_sha256,
        "local execution manifest",
    )
    c9g_manifest_raw, c9g_manifest = strict_json(
        c9g_manifest_path,
        arguments.c9g_execution_manifest_sha256,
        "c9g execution manifest",
    )
    validate_static(static_report)
    validate_correctness(local_report, "local")
    validate_correctness(c9g_report, "c9g")
    local_manifest_payload = validate_execution_envelope(local_manifest, "local")
    c9g_manifest_payload = validate_execution_envelope(c9g_manifest, "c9g")
    local_manifest_runner = local_manifest_payload.get("runner")
    c9g_manifest_runner = c9g_manifest_payload.get("runner")
    require(
        isinstance(local_manifest_runner, dict)
        and isinstance(c9g_manifest_runner, dict),
        "platform execution runner bindings are missing",
    )
    local_build_identity = local_manifest_runner.get("build_identity")
    c9g_build_identity = c9g_manifest_runner.get("build_identity")
    require(
        isinstance(local_build_identity, dict)
        and isinstance(c9g_build_identity, dict),
        "platform runner build identities are missing",
    )
    validate_build_identity(
        local_build_identity,
        "local",
        arguments.source_commit,
        arguments.source_tree,
        archive_sha,
        source_set_sha,
    )
    validate_build_identity(
        c9g_build_identity,
        "c9g",
        arguments.source_commit,
        arguments.source_tree,
        archive_sha,
        source_set_sha,
    )
    require(
        all(
            local_build_identity[field] == c9g_build_identity[field]
            for field in (
                "source_commit",
                "source_tree",
                "source_archive_sha256",
                "source_set_sha256",
            )
        ),
        "local and c9g runner embedded source identities differ",
    )
    local_build_identity_raw = canonical_bytes(local_build_identity) + b"\n"
    c9g_build_identity_raw = canonical_bytes(c9g_build_identity) + b"\n"
    local_host_identity = require_host_identity(
        arguments.local_host_identity, "local host identity"
    )
    c9g_host_identity = require_host_identity(arguments.c9g_host_identity, "c9g host identity")
    require(
        local_host_identity != c9g_host_identity,
        "local and c9g host identities must be distinct",
    )
    local_expected_payload = execution_payload(
        lane="local",
        created_utc=local_manifest_payload.get("created_utc", ""),
        host_identity=local_host_identity,
        source_commit=arguments.source_commit,
        source_tree=arguments.source_tree,
        archive_sha256=archive_sha,
        archive_bytes=archive_bytes,
        source_set_sha256=source_set_sha,
        runner_sha256=local_runner_sha,
        runner_bytes=local_runner_bytes,
        execution_tool_sha256=execution_tool_sha,
        execution_tool_bytes=execution_tool_bytes,
        validation_tool_sha256=validation_tool_sha,
        validation_tool_bytes=validation_tool_bytes,
        build_identity_raw=local_build_identity_raw,
        build_identity_report=local_build_identity,
        correctness_raw=local_raw,
        correctness_report=local_report,
        static_raw=static_raw,
    )
    c9g_expected_payload = execution_payload(
        lane="c9g",
        created_utc=c9g_manifest_payload.get("created_utc", ""),
        host_identity=c9g_host_identity,
        source_commit=arguments.source_commit,
        source_tree=arguments.source_tree,
        archive_sha256=archive_sha,
        archive_bytes=archive_bytes,
        source_set_sha256=source_set_sha,
        runner_sha256=c9g_runner_sha,
        runner_bytes=c9g_runner_bytes,
        execution_tool_sha256=execution_tool_sha,
        execution_tool_bytes=execution_tool_bytes,
        validation_tool_sha256=validation_tool_sha,
        validation_tool_bytes=validation_tool_bytes,
        build_identity_raw=c9g_build_identity_raw,
        build_identity_report=c9g_build_identity,
        correctness_raw=c9g_raw,
        correctness_report=c9g_report,
        static_raw=None,
    )
    validate_execution_manifest(
        raw=local_manifest_raw,
        manifest=local_manifest,
        expected_payload=local_expected_payload,
        lane="local",
    )
    validate_execution_manifest(
        raw=c9g_manifest_raw,
        manifest=c9g_manifest,
        expected_payload=c9g_expected_payload,
        lane="c9g",
    )

    resolved_inputs = {
        source_archive.resolve(),
        local_runner_binary.resolve(),
        c9g_runner_binary.resolve(),
        execution_tool.resolve(),
        static_path.resolve(),
        local_path.resolve(),
        c9g_path.resolve(),
        local_manifest_path.resolve(),
        c9g_manifest_path.resolve(),
    }
    require(len(resolved_inputs) == 9, "evidence input paths are duplicated")
    evidence_hashes = {
        hashlib.sha256(static_raw).hexdigest(),
        hashlib.sha256(local_raw).hexdigest(),
        hashlib.sha256(c9g_raw).hexdigest(),
        hashlib.sha256(local_manifest_raw).hexdigest(),
        hashlib.sha256(c9g_manifest_raw).hexdigest(),
    }
    require(len(evidence_hashes) == 5, "evidence reports or manifests are duplicated")

    payload = {
        "created_utc": validate_created_utc(arguments.created_utc),
        "source": {
            "commit": require_hex(arguments.source_commit, 40, "source commit"),
            "tree": require_hex(arguments.source_tree, 40, "source tree"),
            "archive_sha256": archive_sha,
            "archive_bytes": archive_bytes,
            "archive_format": "git-archive-tar",
            "deterministic_byte_match": True,
            "source_set_sha256": source_set_sha,
            "worktree_clean": True,
        },
        "runners": {
            "local": {
                "binary_sha256": local_runner_sha,
                "binary_bytes": local_runner_bytes,
                "embedded_source_identity_match": True,
                "execution_mechanism": "closed-private-inode",
                "format": "macho64-aarch64",
            },
            "c9g": {
                "binary_sha256": c9g_runner_sha,
                "binary_bytes": c9g_runner_bytes,
                "embedded_source_identity_match": True,
                "execution_mechanism": "validated-open-fd",
                "format": "elf64-aarch64",
            },
        },
        "execution_tool": {
            "sha256": execution_tool_sha,
            "bytes": execution_tool_bytes,
            "basename": EXECUTION_TOOL_BASENAME,
        },
        "validation_tool": {
            "sha256": validation_tool_sha,
            "bytes": validation_tool_bytes,
            "basename": VALIDATION_TOOL_BASENAME,
        },
        "population_sha256": POPULATION_SHA256,
        "static": {
            "report_sha256": hashlib.sha256(static_raw).hexdigest(),
            "report_bytes": len(static_raw),
            "exact_machine_object_parities": 1296,
            "distinct_aot_identities": 1296,
            "routing_boundary_checks": 24,
        },
        "correctness": {
            "local": {
                "operator_host_identity": local_host_identity,
                "execution_manifest_sha256": hashlib.sha256(local_manifest_raw).hexdigest(),
                "execution_manifest_bytes": len(local_manifest_raw),
                "report_sha256": hashlib.sha256(local_raw).hexdigest(),
                "report_bytes": len(local_raw),
                "comparisons": 7776,
                "mismatches": 0,
                "target": local_report["target"],
            },
            "c9g": {
                "operator_host_identity": c9g_host_identity,
                "execution_manifest_sha256": hashlib.sha256(c9g_manifest_raw).hexdigest(),
                "execution_manifest_bytes": len(c9g_manifest_raw),
                "report_sha256": hashlib.sha256(c9g_raw).hexdigest(),
                "report_bytes": len(c9g_raw),
                "comparisons": 7776,
                "mismatches": 0,
                "target": c9g_report["target"],
            },
        },
        "result_policy": {
            "correctness_complete": True,
            "performance_timing_present": False,
            "performance_gate_authority": False,
            "production_or_deployment_authority": False,
            "placeholders_authorize_nothing": True,
        },
    }
    payload_encoded = canonical_bytes(payload)
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "payload_sha256": hashlib.sha256(payload_encoded).hexdigest(),
        "payload": payload,
    }
    validate_source(source_root, arguments.source_commit, arguments.source_tree)
    create_new_output(output_path, canonical_bytes(receipt) + b"\n")
    return receipt


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--source-root", required=True)
    result.add_argument("--source-commit", required=True)
    result.add_argument("--source-tree", required=True)
    result.add_argument("--source-archive", required=True)
    result.add_argument("--source-archive-sha256", required=True)
    result.add_argument("--local-runner-binary", required=True)
    result.add_argument("--local-runner-binary-sha256", required=True)
    result.add_argument("--c9g-runner-binary", required=True)
    result.add_argument("--c9g-runner-binary-sha256", required=True)
    result.add_argument("--execution-tool", required=True)
    result.add_argument("--execution-tool-sha256", required=True)
    result.add_argument("--static-report", required=True)
    result.add_argument("--static-report-sha256", required=True)
    result.add_argument("--local-report", required=True)
    result.add_argument("--local-report-sha256", required=True)
    result.add_argument("--local-host-identity", required=True)
    result.add_argument("--local-execution-manifest", required=True)
    result.add_argument("--local-execution-manifest-sha256", required=True)
    result.add_argument("--c9g-report", required=True)
    result.add_argument("--c9g-report-sha256", required=True)
    result.add_argument("--c9g-host-identity", required=True)
    result.add_argument("--c9g-execution-manifest", required=True)
    result.add_argument("--c9g-execution-manifest-sha256", required=True)
    result.add_argument("--created-utc", required=True)
    result.add_argument("--output", required=True)
    return result


def main() -> None:
    arguments = parser().parse_args()
    try:
        receipt = seal(arguments)
    except (OSError, Refusal) as error:
        print(f"seal-v26-correctness: {error}", file=os.sys.stderr)
        raise SystemExit(1) from error
    encoded = canonical_bytes(receipt)
    print(f"schema={RECEIPT_SCHEMA}")
    receipt_sha256 = hashlib.sha256(encoded + bytes([10])).hexdigest()
    print(f"receipt_sha256={receipt_sha256}")
    print(f"payload_sha256={receipt['payload_sha256']}")
    print("correctness=pass performance_authority=false production_authority=false")


if __name__ == "__main__":
    main()
