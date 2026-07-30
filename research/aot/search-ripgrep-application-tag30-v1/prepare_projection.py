#!/usr/bin/env python3
"""Prepare the immutable tag-30 ripgrep application projection.

The projection is a pure derivation of the already-frozen v2 source,
selector, disposition, and fixture manifests. It reads no benchmark result,
Rebar input, or external-regex heldout material.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any


FREEZE_RELATIVE = (
    "research/aot/search-ripgrep-application-independent-v2/freeze-v2.json"
)
FREEZE_SHA256 = (
    "a491f2fd1e19d01cca9a237770c8cdefa04a90e3623dadfcc4c79012eb2abd52"
)
FREEZE_PAYLOAD_SHA256 = (
    "3359ab7c620482d67d67d09903981c8b322c5268cfe0640e273de0f778192822"
)
FIXTURE_SCHEMA = "fre.aot.search-ripgrep-application-fixtures.v2"
FIXTURE_SHA256 = (
    "b20181470c604d01d2ec236259293cfcb6e5eff145bcd3e4daa91554c8cebcca"
)
FIXTURE_PAYLOAD_SHA256 = (
    "1cbda700087f5506daa91b0657070cbf39fac68222ff84e273d1d83c09f6ebfd"
)
DISPOSITIONS_RELATIVE = (
    "research/aot/search-ripgrep-application-tag30-v1/"
    "literal-dispositions-v1.json"
)
DISPOSITIONS_SCHEMA = (
    "fre.aot.search-tag30-application-literal-dispositions.v1"
)
DISPOSITIONS_SHA256 = (
    "433029525cfb74122f275f4282901fc6e7711b34aa7115b4bd53ef537dd5e1a1"
)
DISPOSITIONS_PAYLOAD_SHA256 = (
    "134a731f76e91218a4d0946bb9394f48db7731b164452a888dcc83cca1431fb2"
)
ROW_SCHEMA = "fre.aot.search-tag30-ripgrep-application-projection-row.v1"
PROJECTION_DOMAIN = b"FRE-SEARCH-TAG30-RIPGREP-APPLICATION-PROJECTION\0\x01"
CASE_DOMAIN = b"FRE-SEARCH-TAG30-RIPGREP-APPLICATION-CASE\0\x01"
CASES = 154
ELIGIBLE = 5
INELIGIBLE = 6
STATIC_TAIL = 75
PREFIX_RETURN = 10
PORTABLE_FALLBACK = 69


class Refusal(RuntimeError):
    """An immutable source input or derivation invariant changed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def sha256(encoded: bytes) -> str:
    return hashlib.sha256(encoded).hexdigest()


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def canonical_sha(value: Any) -> str:
    return sha256(canonical_bytes(value))


def regular_file(path: Path, maximum: int) -> bytes:
    before = path.lstat()
    require(
        stat.S_ISREG(before.st_mode)
        and not path.is_symlink()
        and before.st_nlink == 1
        and 0 < before.st_size <= maximum,
        f"not one bounded unshared regular file: {path}",
    )
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        require(
            (
                opened.st_dev,
                opened.st_ino,
                opened.st_mode,
                opened.st_nlink,
                opened.st_size,
            )
            == (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_nlink,
                before.st_size,
            ),
            f"file changed before open: {path}",
        )
        encoded = bytearray()
        while len(encoded) <= maximum:
            block = os.read(
                descriptor, min(1 << 20, maximum + 1 - len(encoded))
            )
            if not block:
                break
            encoded.extend(block)
        after = os.fstat(descriptor)
        require(
            len(encoded) == opened.st_size
            and (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            == (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
                opened.st_ctime_ns,
            ),
            f"file changed while held: {path}",
        )
        return bytes(encoded)
    finally:
        os.close(descriptor)


def load_envelope(
    encoded: bytes,
    schema: str,
    file_sha256: str,
    payload_sha256: str,
    label: str,
) -> dict[str, Any]:
    root = json.loads(encoded)
    require(
        sha256(encoded) == file_sha256
        and isinstance(root, dict)
        and set(root) == {"schema", "payload_sha256", "payload"}
        and root["schema"] == schema
        and root["payload_sha256"] == payload_sha256
        and canonical_sha(root["payload"]) == payload_sha256,
        f"{label} envelope changed",
    )
    return root


def case_id(
    candidate_sha256: str, scenario: str, fixture_sha256: str
) -> str:
    return sha256(
        CASE_DOMAIN
        + bytes.fromhex(candidate_sha256)
        + len(scenario).to_bytes(8, "little")
        + scenario.encode("ascii")
        + bytes.fromhex(fixture_sha256)
    )


def projection_digest(lines: list[bytes]) -> str:
    digest = hashlib.sha256(PROJECTION_DOMAIN)
    for encoded in lines:
        digest.update(len(encoded).to_bytes(8, "little"))
        digest.update(encoded)
    return digest.hexdigest()


def derive(repo: Path, fixture_root: Path) -> tuple[list[dict[str, Any]], str]:
    freeze = load_envelope(
        regular_file(repo / FREEZE_RELATIVE, 4 * 1024 * 1024),
        "fre.aot.search-ripgrep-application-freeze.v2",
        FREEZE_SHA256,
        FREEZE_PAYLOAD_SHA256,
        "freeze",
    )
    dispositions = load_envelope(
        regular_file(repo / DISPOSITIONS_RELATIVE, 4 * 1024 * 1024),
        DISPOSITIONS_SCHEMA,
        DISPOSITIONS_SHA256,
        DISPOSITIONS_PAYLOAD_SHA256,
        "tag30 dispositions",
    )
    fixture_bytes = regular_file(
        fixture_root / "manifest.json", 16 * 1024 * 1024
    )
    fixtures = load_envelope(
        fixture_bytes,
        FIXTURE_SCHEMA,
        FIXTURE_SHA256,
        FIXTURE_PAYLOAD_SHA256,
        "fixture",
    )
    partition = {
        row["semantic_candidate_sha256"]: row
        for row in dispositions["payload"]["dispositions"]
    }
    require(
        len(partition) == 11
        and sum(row["selector_eligible"] for row in partition.values())
        == ELIGIBLE
        and sum(not row["selector_eligible"] for row in partition.values())
        == INELIGIBLE,
        "selector disposition cardinality changed",
    )
    frozen = freeze["payload"]
    require(
        frozen["independence"]["rebar_inputs"] == []
        and frozen["independence"]["benchmark_result_inputs"] == []
        and frozen["independence"]["result_derived_exclusions"] is False
        and frozen["fixtures"]["fixture_count"] == CASES,
        "frozen independence contract changed",
    )

    rows: list[dict[str, Any]] = []
    route_counts = {
        "tag30-static-tail": 0,
        "portable-prefix-return": 0,
        "full-portable-fallback": 0,
    }
    seen_paths: set[str] = set()
    seen_cases: set[str] = set()
    for candidate in fixtures["payload"]["candidates"]:
        semantic = candidate["semantic_candidate_sha256"]
        disposition = partition.get(semantic)
        require(disposition is not None, "fixture candidate lacks disposition")
        require(
            candidate["literal_hex"] == disposition["literal_hex"]
            and candidate["literal_sha256"]
            == disposition["literal_sha256"]
            and candidate["literal_bytes"]
            == disposition["literal_bytes"],
            "fixture and disposition literal identities differ",
        )
        for fixture in candidate["fixtures"]:
            path = fixture["path"]
            require(
                "/" not in path
                and path not in {"", ".", ".."}
                and path not in seen_paths,
                "fixture path is non-flat or duplicated",
            )
            seen_paths.add(path)
            raw = regular_file(fixture_root / path, 2 * 1024 * 1024)
            require(
                len(raw) == fixture["bytes"] == 1_048_576
                and sha256(raw) == fixture["sha256"],
                f"fixture bytes changed: {path}",
            )
            eligible = disposition["selector_eligible"]
            if not eligible:
                route = "full-portable-fallback"
            elif fixture["scenario"] in {"early", "dense"}:
                route = "portable-prefix-return"
            else:
                route = "tag30-static-tail"
            route_counts[route] += 1
            identity = case_id(
                semantic, fixture["scenario"], fixture["sha256"]
            )
            require(identity not in seen_cases, "case identity duplicated")
            seen_cases.add(identity)
            row = {
                "schema": ROW_SCHEMA,
                "ordinal": len(rows),
                "case_id": identity,
                "candidate_sha256": semantic,
                "literal_hex": candidate["literal_hex"],
                "literal_sha256": candidate["literal_sha256"],
                "literal_bytes": candidate["literal_bytes"],
                "scenario": fixture["scenario"],
                "fixture_path": path,
                "fixture_sha256": fixture["sha256"],
                "fixture_bytes": fixture["bytes"],
                "alignment_offset": fixture["alignment_offset"],
                "padding_sentinel": fixture["wrong_byte"],
                "expected_span": fixture["expected_leftmost_span"],
                "expected_nonoverlapping_count": (
                    fixture["expected_nonoverlapping_count"]
                ),
                "selector_eligible": eligible,
                "selected_offsets": disposition["selected_offsets"],
                "expected_compiler_disposition": (
                    disposition["expected_compiler_disposition"]
                ),
                "route_class": route,
                "expected_static_invoked": route
                == "tag30-static-tail",
                "rebar_accepted_as_input": False,
                "result_derived_exclusion": False,
            }
            row["row_sha256"] = canonical_sha(row)
            rows.append(row)
    require(
        len(rows) == CASES
        and len(seen_paths) == CASES
        and route_counts
        == {
            "tag30-static-tail": STATIC_TAIL,
            "portable-prefix-return": PREFIX_RETURN,
            "full-portable-fallback": PORTABLE_FALLBACK,
        },
        "application projection route cardinality changed",
    )
    lines = [canonical_bytes(row) + b"\n" for row in rows]
    return rows, projection_digest(lines)


def write_new(path: Path, encoded: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o644,
    )
    try:
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            require(written > 0, "short projection write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main() -> None:
    require(
        len(sys.argv) == 4,
        "usage: prepare_projection.py REPO FIXTURE_ROOT NEW_OUTPUT",
    )
    repo = Path(sys.argv[1]).resolve(strict=True)
    fixture_root = Path(sys.argv[2]).resolve(strict=True)
    output = Path(sys.argv[3])
    require(not output.exists(), "refusing existing projection output")
    rows, digest = derive(repo, fixture_root)
    encoded = b"".join(canonical_bytes(row) + b"\n" for row in rows)
    write_new(output, encoded)
    print(
        f"projection_rows={len(rows)} projection_sha256={digest} "
        f"file_sha256={sha256(encoded)} eligible={ELIGIBLE} "
        f"ineligible={INELIGIBLE} static_tail={STATIC_TAIL} "
        f"prefix_return={PREFIX_RETURN} fallback={PORTABLE_FALLBACK} "
        "rebar_inputs=0 benchmark_results=0 heldout_materialized=false"
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
        json.JSONDecodeError,
        Refusal,
    ) as error:
        print(f"search-tag30-application-projection: {error}", file=sys.stderr)
        raise SystemExit(1)
