#!/usr/bin/env python3
"""Build a fail-closed Rebar contamination index for the external dev corpus."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

DESCRIPTOR_SCHEMA = (
    "fre.aot.external-regex-1.12.4-contamination-sources-development.v1"
)
OUTPUT_SCHEMA = "fre.aot.external-regex-1.12.4-contamination-index-development.v1"
EXPANDED_SCHEMA = "fre.optimizing-count-v3.rebar-expanded-manifest.v1"
COUNT_SCHEMA = "fre.optimizing-count-v3.inventory.v1"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
PLAIN_PATTERN = re.compile(
    rb"(?:transformed_pattern|source_pattern|pattern)\s*[:=]\s*\"([^\"\\\\]*)\""
)
PLAIN_LITERAL_HEX = re.compile(rb"literal_hex\s*[:=]\s*\"([0-9a-f]+)\"")


class Refusal(RuntimeError):
    pass


def refuse(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def regular_file(path: Path) -> bytes:
    status = path.lstat()
    refuse(not path.is_symlink() and path.is_file(), f"not a regular file: {path}")
    refuse(status.st_size <= 256 * 1024 * 1024, f"file exceeds 256 MiB: {path}")
    return path.read_bytes()


def require_sha(value: Any, label: str) -> str:
    refuse(isinstance(value, str) and HEX64.fullmatch(value) is not None, label)
    return value


def exact_keys(value: dict[str, Any], keys: set[str], label: str) -> None:
    refuse(set(value) == keys, f"{label}: keys changed")


def load_json_bytes(data: bytes, label: str) -> dict[str, Any]:
    value = json.loads(data)
    refuse(isinstance(value, dict), f"{label}: root is not an object")
    return value


def verify_file(source: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    exact_keys(source, {"kind", "path", "sha256"}, "file source")
    path = Path(source["path"])
    expected = require_sha(source["sha256"], f"{path}: invalid expected SHA-256")
    data = regular_file(path)
    actual = sha256(data)
    refuse(actual == expected, f"{path}: SHA-256 changed")
    return data, {"kind": source["kind"], "path": str(path), "sha256": actual}


def add_sha(target: set[str], value: Any, label: str) -> None:
    target.add(require_sha(value, label))


def expanded_manifest(
    source: dict[str, Any],
    raw_patterns: set[str],
) -> dict[str, Any]:
    data, receipt = verify_file(source)
    value = load_json_bytes(data, receipt["path"])
    refuse(value.get("schema") == EXPANDED_SCHEMA, "expanded manifest schema changed")
    jobs = value.get("jobs")
    refuse(isinstance(jobs, list) and jobs, "expanded manifest jobs are empty")
    before = len(raw_patterns)
    for ordinal, job in enumerate(jobs):
        refuse(isinstance(job, dict), f"expanded job {ordinal} is not an object")
        hashes = job.get("pattern_source_sha256")
        count = job.get("pattern_count")
        refuse(
            isinstance(hashes, list)
            and isinstance(count, int)
            and count >= 0
            and len(hashes) == count,
            f"expanded job {ordinal} pattern receipts do not close",
        )
        for index, digest in enumerate(hashes):
            add_sha(raw_patterns, digest, f"expanded job {ordinal} pattern {index}")
    receipt["schema"] = EXPANDED_SCHEMA
    receipt["jobs"] = len(jobs)
    receipt["raw_pattern_receipts"] = len(raw_patterns) - before
    return receipt


def count_inventory(
    source: dict[str, Any],
    raw_patterns: set[str],
    authenticated_literals: set[str],
    declared_literals: set[str],
) -> dict[str, Any]:
    data, receipt = verify_file(source)
    value = load_json_bytes(data, receipt["path"])
    refuse(value.get("schema") == COUNT_SCHEMA, "Count inventory schema changed")
    artifacts = value.get("artifacts")
    distinct = value.get("distinct_artifacts")
    refuse(
        isinstance(artifacts, list)
        and isinstance(distinct, int)
        and artifacts
        and len(artifacts) == distinct,
        "Count inventory artifacts do not close",
    )
    seen = set()
    for ordinal, artifact in enumerate(artifacts):
        refuse(isinstance(artifact, dict), f"artifact {ordinal} is not an object")
        pattern_id = artifact.get("pattern_input_id")
        refuse(isinstance(pattern_id, str) and pattern_id not in seen, "duplicate artifact")
        seen.add(pattern_id)
        add_sha(
            raw_patterns,
            artifact.get("source_pattern_sha256"),
            f"artifact {ordinal} source pattern SHA-256",
        )
        transformed = artifact.get("transformed_pattern")
        refuse(isinstance(transformed, str) and transformed, "empty transformed pattern")
        # A transformation can change spelling while preserving the source receipt.
        # Indexing both spellings is conservative and prevents spelling-based leakage.
        raw_patterns.add(sha256(transformed.encode("utf-8")))
        literal_hex = artifact.get("literal_hex")
        refuse(
            isinstance(literal_hex, str)
            and len(literal_hex) % 2 == 0
            and re.fullmatch(r"[0-9a-f]+", literal_hex) is not None,
            f"artifact {ordinal} literal hex is invalid",
        )
        literal = bytes.fromhex(literal_hex)
        refuse(
            artifact.get("literal_bytes") == len(literal) and literal,
            f"artifact {ordinal} literal width differs",
        )
        literal_sha = require_sha(
            artifact.get("literal_sha256"), f"artifact {ordinal} literal SHA-256"
        )
        refuse(sha256(literal) == literal_sha, f"artifact {ordinal} literal hash differs")
        # The optimizing Count inventory is source-bound and its consumer replays
        # ForceExactLiteral plus the Count eligibility receipt before compilation.
        declared_literals.add(literal_sha)
        authenticated_literals.add(literal_sha)
    receipt["schema"] = COUNT_SCHEMA
    receipt["artifacts"] = len(artifacts)
    return receipt


def scan_declarations(
    data: bytes,
    raw_patterns: set[str],
    declared_literals: set[str],
) -> dict[str, int]:
    patterns = 0
    literals = 0
    for match in PLAIN_PATTERN.finditer(data):
        value = match.group(1)
        if value:
            raw_patterns.add(sha256(value))
            patterns += 1
    for match in PLAIN_LITERAL_HEX.finditer(data):
        encoded = match.group(1)
        if len(encoded) % 2 == 0:
            literal = bytes.fromhex(encoded.decode("ascii"))
            if literal:
                declared_literals.add(sha256(literal))
                literals += 1
    return {"conservative_pattern_declarations": patterns, "literal_declarations": literals}


def source_file(
    source: dict[str, Any],
    raw_patterns: set[str],
    declared_literals: set[str],
) -> dict[str, Any]:
    data, receipt = verify_file(source)
    receipt.update(scan_declarations(data, raw_patterns, declared_literals))
    return receipt


def source_tree(
    source: dict[str, Any],
    raw_patterns: set[str],
    declared_literals: set[str],
) -> dict[str, Any]:
    exact_keys(source, {"kind", "path", "files"}, "source tree")
    root = Path(source["path"])
    refuse(not root.is_symlink() and root.is_dir(), f"not a directory: {root}")
    expected = source["files"]
    refuse(
        isinstance(expected, dict) and expected,
        f"{root}: expected file inventory is empty",
    )
    actual: dict[str, str] = {}
    pattern_declarations = 0
    literal_declarations = 0
    for directory, directories, files in os.walk(root, followlinks=False):
        directories.sort()
        files.sort()
        base = Path(directory)
        for name in files:
            path = base / name
            relative = path.relative_to(root).as_posix()
            data = regular_file(path)
            actual[relative] = sha256(data)
            counts = scan_declarations(data, raw_patterns, declared_literals)
            pattern_declarations += counts["conservative_pattern_declarations"]
            literal_declarations += counts["literal_declarations"]
    normalized_expected = {
        str(path): require_sha(digest, f"{root}/{path}: invalid expected SHA-256")
        for path, digest in expected.items()
    }
    refuse(actual == normalized_expected, f"{root}: source tree file set or digest changed")
    tree_payload = json.dumps(actual, sort_keys=True, separators=(",", ":")).encode()
    return {
        "kind": "source-tree",
        "path": str(root),
        "files": len(actual),
        "file_receipts_sha256": sha256(tree_payload),
        "conservative_pattern_declarations": pattern_declarations,
        "literal_declarations": literal_declarations,
    }


def classify_candidates(
    development: dict[str, Any],
    raw_patterns: set[str],
    authenticated_literals: set[str],
    declared_literals: set[str],
) -> list[dict[str, Any]]:
    candidates = development.get("payload", {}).get("semantic_candidates")
    refuse(isinstance(candidates, list) and candidates, "development candidates are empty")
    output = []
    for candidate in candidates:
        raw = require_sha(candidate.get("raw_pattern_sha256"), "candidate raw pattern")
        literal = require_sha(candidate.get("literal_sha256"), "candidate literal")
        reasons = []
        if raw in raw_patterns:
            reasons.append("raw-pattern-sha256")
        if literal in authenticated_literals:
            reasons.append("fre-authenticated-exact-literal-sha256")
        if literal in declared_literals:
            reasons.append("declared-literal-sha256")
        output.append(
            {
                "semantic_candidate_sha256": candidate["semantic_candidate_sha256"],
                "representative_case_id": candidate["representative_case_id"],
                "representative_case_sha256": candidate["representative_case_sha256"],
                "literal_sha256": literal,
                "literal_bytes": candidate["literal_bytes"],
                "shape": candidate["shape"],
                "search_applicable": candidate["search_applicable"],
                "count_development_applicable": candidate[
                    "count_development_applicable"
                ],
                "disposition": "corroboration" if reasons else "independent",
                "overlap_reasons": reasons,
            }
        )
    return output


def main() -> None:
    refuse(len(sys.argv) == 3, "usage: DESCRIPTOR OUTPUT")
    descriptor_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])
    refuse(not output_path.exists(), f"refusing existing output: {output_path}")
    descriptor_bytes = regular_file(descriptor_path)
    descriptor = load_json_bytes(descriptor_bytes, str(descriptor_path))
    exact_keys(
        descriptor,
        {"schema", "development_inventory", "sources"},
        "descriptor",
    )
    refuse(descriptor["schema"] == DESCRIPTOR_SCHEMA, "descriptor schema changed")
    development_source = descriptor["development_inventory"]
    exact_keys(development_source, {"path", "sha256"}, "development inventory")
    development_bytes = regular_file(Path(development_source["path"]))
    refuse(
        sha256(development_bytes)
        == require_sha(development_source["sha256"], "development inventory SHA-256"),
        "development inventory SHA-256 changed",
    )
    development = load_json_bytes(development_bytes, "development inventory")

    raw_patterns: set[str] = set()
    authenticated_literals: set[str] = set()
    declared_literals: set[str] = set()
    receipts = []
    unresolved = []
    for source in descriptor["sources"]:
        refuse(isinstance(source, dict), "source is not an object")
        kind = source.get("kind")
        if kind == "blind-fenced":
            exact_keys(source, {"kind", "path", "reason"}, "blind-fenced source")
            # Deliberately do not construct a Path, stat, list, hash, or read it.
            unresolved.append(dict(source))
        elif kind == "expanded-rebar-manifest":
            receipts.append(expanded_manifest(source, raw_patterns))
        elif kind == "optimizing-count-inventory":
            receipts.append(
                count_inventory(
                    source,
                    raw_patterns,
                    authenticated_literals,
                    declared_literals,
                )
            )
        elif kind == "source-tree":
            receipts.append(
                source_tree(source, raw_patterns, declared_literals)
            )
        elif kind == "source-file":
            receipts.append(
                source_file(source, raw_patterns, declared_literals)
            )
        else:
            raise Refusal(f"unknown source kind: {kind!r}")

    candidates = classify_candidates(
        development,
        raw_patterns,
        authenticated_literals,
        declared_literals,
    )
    independent = [row for row in candidates if row["disposition"] == "independent"]
    corroboration = [row for row in candidates if row["disposition"] == "corroboration"]
    payload = {
        "descriptor_path": str(descriptor_path),
        "descriptor_sha256": sha256(descriptor_bytes),
        "development_inventory_path": development_source["path"],
        "development_inventory_sha256": sha256(development_bytes),
        "source_receipts": receipts,
        "unresolved_sources": unresolved,
        "promotion_eligible": not unresolved,
        "promotion_blockers": [
            "blind-fenced contamination source remains unresolved"
        ]
        if unresolved
        else [],
        "sets": {
            "raw_pattern_sha256": sorted(raw_patterns),
            "fre_authenticated_exact_literal_sha256": sorted(authenticated_literals),
            "declared_literal_sha256": sorted(declared_literals),
        },
        "counts": {
            "raw_pattern_sha256": len(raw_patterns),
            "fre_authenticated_exact_literal_sha256": len(authenticated_literals),
            "declared_literal_sha256": len(declared_literals),
            "development_candidates": len(candidates),
            "independent_candidates": len(independent),
            "corroboration_candidates": len(corroboration),
        },
        "candidates": candidates,
    }
    payload_bytes = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    wrapper = {
        "schema": OUTPUT_SCHEMA,
        "payload_sha256": sha256(payload_bytes),
        "payload": payload,
    }
    output = (
        json.dumps(wrapper, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644
    )
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(output)
        handle.flush()
        os.fsync(handle.fileno())
    print(f"output={output_path}")
    print(f"sha256={sha256(output)}")
    print(f"independent={len(independent)} corroboration={len(corroboration)}")
    print(f"promotion_eligible={not unresolved}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, Refusal, ValueError, json.JSONDecodeError) as error:
        print(f"contamination-index: {error}", file=sys.stderr)
        raise SystemExit(1)
