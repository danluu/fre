#!/usr/bin/env python3
"""Reproduce the source-only ripgrep exact-literal application inventory."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


SCHEMA = "fre.aot.search-ripgrep-application-literals.v2"
UPSTREAM_COMMIT = "f9c05a949d1a0dc8e16dee28ca9605d38611faeb"
UPSTREAM_TREE = "ce81df4f8cad2dbfd1afb6b3ba53fd19846a5794"
CANDIDATE_DOMAIN = b"fre.aot.search-ripgrep-application-literal.v2\0"
CALL = re.compile(
    rb"RegexMatcher::new\(\s*(r\"[^\"\r\n]*\"|\"(?:[^\"\\\r\n]|\\.)*\")\s*\)"
)
METACHARACTERS = frozenset(b".^$*+?{}[]\\|()")
COMMON_SCENARIOS = [
    "absent",
    "early",
    "middle",
    "tail",
    "dense",
    "wrong-first-dense",
    "wrong-final-dense",
]


class Refusal(RuntimeError):
    """Authenticated application source or the frozen projection changed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_sha(value: Any) -> str:
    return sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
    )


def regular_file(path: Path, maximum_bytes: int = 2 * 1024 * 1024) -> bytes:
    status = path.lstat()
    require(
        not path.is_symlink()
        and path.is_file()
        and 0 < status.st_size <= maximum_bytes,
        f"not one bounded regular file: {path}",
    )
    return path.read_bytes()


def git(root: Path, *arguments: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    require(result.returncode == 0 and not result.stderr, "git query failed")
    return result.stdout


def decode_token(token: bytes) -> bytes | None:
    if token.startswith(b'r"') and token.endswith(b'"'):
        return token[2:-1]
    try:
        decoded = json.loads(token.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(decoded, str):
        return None
    try:
        return decoded.encode("ascii")
    except UnicodeEncodeError:
        return None


def derive_candidates(ripgrep_root: Path) -> tuple[list[dict[str, Any]], int]:
    require(
        git(ripgrep_root, "rev-parse", "HEAD").decode().strip()
        == UPSTREAM_COMMIT,
        "ripgrep revision changed",
    )
    require(
        git(ripgrep_root, "rev-parse", "HEAD^{tree}").decode().strip()
        == UPSTREAM_TREE,
        "ripgrep source tree changed",
    )
    require(
        git(ripgrep_root, "status", "--porcelain=v1", "--untracked-files=no")
        == b"",
        "ripgrep tracked worktree is dirty",
    )
    tracked = [
        item.decode("utf-8")
        for item in git(
            ripgrep_root, "ls-files", "-z", "--", "*.rs"
        ).split(b"\0")
        if item
    ]
    require(
        tracked == sorted(tracked) and len(tracked) == 110,
        "tracked Rust source set changed",
    )

    occurrences: dict[bytes, list[tuple[str, int, bytes, str, int]]] = {}
    for relative in tracked:
        source = regular_file(ripgrep_root / relative)
        source_sha256 = sha256(source)
        for match in CALL.finditer(source):
            token = match.group(1)
            literal = decode_token(token)
            if literal is None:
                continue
            if not (
                1 <= len(literal) <= 32
                and all(0x20 <= byte <= 0x7E for byte in literal)
                and not any(byte in METACHARACTERS for byte in literal)
            ):
                continue
            occurrences.setdefault(literal, []).append(
                (
                    relative,
                    match.start(1),
                    token,
                    source_sha256,
                    len(source),
                )
            )

    rows: list[dict[str, Any]] = []
    for literal in sorted(occurrences, key=lambda item: (len(item), item)):
        relative, offset, token, source_sha256, source_bytes = min(
            occurrences[literal]
        )
        identity = sha256(
            CANDIDATE_DOMAIN
            + bytes.fromhex(UPSTREAM_COMMIT)
            + relative.encode()
            + b"\0"
            + offset.to_bytes(8, "little")
            + literal
        )
        rows.append(
            {
                "semantic_candidate_sha256": identity,
                "literal_hex": literal.hex(),
                "literal_sha256": sha256(literal),
                "literal_bytes": len(literal),
                "source_path": relative,
                "source_file_sha256": source_sha256,
                "source_file_bytes": source_bytes,
                "source_token_offset": offset,
                "source_token_ascii": token.decode("ascii"),
            }
        )
    require(len(rows) == 11, "eligible unique literal count changed")
    return rows, len(tracked)


def expected_payload(ripgrep_root: Path) -> dict[str, Any]:
    candidates, tracked_count = derive_candidates(ripgrep_root)
    return {
        "freeze_date": "2026-07-30",
        "freeze_boundary": (
            "source selection frozen before tag29 broad qualification timing"
        ),
        "timing_feedback_permitted": False,
        "backend_identity": "required-tag29-frozen-input",
        "source": {
            "repository": "https://github.com/BurntSushi/ripgrep",
            "upstream_commit": UPSTREAM_COMMIT,
            "tracked_rust_files": tracked_count,
        },
        "selection": {
            "call_surface": (
                "direct default RegexMatcher::new with one static string"
            ),
            "literal_width_min": 1,
            "literal_width_max": 32,
            "bytes": "printable ASCII",
            "exactness": "reject .^$*+?{}[]\\|() bytes",
            "normal_string_decoder": (
                "JSON-compatible ASCII Rust string subset"
            ),
            "raw_string_decoder": (
                "simple r-quoted ASCII Rust string without hashes"
            ),
            "deduplicate": (
                "literal bytes; lexicographically minimum (path, token offset)"
            ),
            "candidate_identity_domain_hex": CANDIDATE_DOMAIN.hex(),
        },
        "independence": {
            "external_classification_inputs": [],
            "corpus_overlap_inputs": [],
            "membership": "all source-derived candidates",
            "result_derived_exclusions": False,
        },
        "candidate_count": len(candidates),
        "candidate_widths": [
            candidate["literal_bytes"] for candidate in candidates
        ],
        "planned_fixture_scenarios": {
            "common": COMMON_SCENARIOS,
            "candidate_independent_mutation": (
                "one dense exact near-miss per literal offset"
            ),
            "planned_fixture_count": sum(
                7 + candidate["literal_bytes"]
                for candidate in candidates
            ),
            "every_candidate_gates": True,
        },
        "candidates": candidates,
    }


def envelope(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "payload_sha256": canonical_sha(payload),
        "payload": payload,
    }


def main() -> None:
    if len(sys.argv) == 3 and sys.argv[1] == "--emit":
        print(
            json.dumps(
                envelope(expected_payload(Path(sys.argv[2]))),
                sort_keys=True,
                indent=2,
            )
        )
        return
    require(
        len(sys.argv) == 3,
        "usage: validate_inventory.py INVENTORY RIPGREP_ROOT",
    )
    parsed = json.loads(regular_file(Path(sys.argv[1])))
    require(
        isinstance(parsed, dict)
        and set(parsed) == {"schema", "payload_sha256", "payload"}
        and parsed == envelope(expected_payload(Path(sys.argv[2]))),
        "inventory differs from authenticated source-only selection",
    )
    payload = parsed["payload"]
    require(
        payload["candidate_count"] == 11
        and payload["planned_fixture_scenarios"]["planned_fixture_count"]
        == 154
        and payload["independence"]["external_classification_inputs"] == []
        and payload["independence"]["corpus_overlap_inputs"] == []
        and payload["planned_fixture_scenarios"]["every_candidate_gates"]
        is True,
        "source-only gate membership changed",
    )
    print(
        f"schema={SCHEMA} payload_sha256={parsed['payload_sha256']} "
        "candidates=11 gating-candidates=11 fixtures=154 "
        "external-classification-inputs=0"
    )


if __name__ == "__main__":
    try:
        main()
    except (
        OSError,
        UnicodeError,
        ValueError,
        KeyError,
        TypeError,
        Refusal,
    ) as error:
        print(f"ripgrep-source-only-inventory: {error}", file=sys.stderr)
        raise SystemExit(1)
