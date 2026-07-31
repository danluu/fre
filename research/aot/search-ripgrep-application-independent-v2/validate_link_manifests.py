#!/usr/bin/env python3
"""Prove the frozen application link manifests are exact mechanical outputs."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from types import ModuleType
from typing import Any


PREPARER_NAME = "prepare_link_manifests.py"
PREPARER_SHA256 = (
    "b85e6c55d4f0641ffee858246a479412eb859f93d3a43b4fd51b9d5abbf3bee3"
)
OBJECT_NAME = "object-candidates-v1.json"
OBJECT_SHA256 = (
    "2e6612dc25e1186e0dd78597f045a4ece6ecc8dafcc2270cacc445be8753aff4"
)
OBJECT_PAYLOAD_SHA256 = (
    "5ffcb2ba1816a0bca3f5e4d74773e1cfff90288eb3c40d599256b380b3342dab"
)
DISPOSITION_NAME = "literal-dispositions-v1.json"
DISPOSITION_SHA256 = (
    "69246c2df3cf3f408af2a88d0243e7a55fd3c0f8b55cdebc6ef396e12b61b2f4"
)
DISPOSITION_PAYLOAD_SHA256 = (
    "a25ed0def38578ea854be59e65c49b2b322b6a96c6d93d1749c48fb88b460227"
)
CONTRACT_NAME = "link-proof-contract-v1.json"
CONTRACT_SHA256 = (
    "8119ee1d6449b7c4d29cc917d0611e2f05234bf34f4e1be8ec90a564995e72a9"
)


class Refusal(RuntimeError):
    """The derivation program or one frozen output changed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def sha256(encoded: bytes) -> str:
    return hashlib.sha256(encoded).hexdigest()


def regular_file(path: Path, maximum: int = 16 * 1024 * 1024) -> bytes:
    status = path.lstat()
    require(
        stat.S_ISREG(status.st_mode)
        and not path.is_symlink()
        and status.st_nlink == 1
        and 0 < status.st_size <= maximum,
        f"not one bounded unshared regular file: {path}",
    )
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
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
                status.st_dev,
                status.st_ino,
                status.st_mode,
                status.st_nlink,
                status.st_size,
            ),
            f"file changed before open: {path}",
        )
        encoded = b""
        while len(encoded) <= maximum:
            block = os.read(descriptor, min(1 << 20, maximum + 1 - len(encoded)))
            if not block:
                break
            encoded += block
        after = os.fstat(descriptor)
        require(
            len(encoded) == opened.st_size
            and (
                opened.st_dev,
                opened.st_ino,
                opened.st_mode,
                opened.st_nlink,
                opened.st_size,
                opened.st_mtime_ns,
                opened.st_ctime_ns,
            )
            == (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_nlink,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ),
            f"file changed while read: {path}",
        )
        return encoded
    finally:
        os.close(descriptor)


def load_preparer(directory: Path) -> ModuleType:
    path = directory / PREPARER_NAME
    encoded = regular_file(path, 2 * 1024 * 1024)
    require(
        sha256(encoded) == PREPARER_SHA256,
        "application link-manifest preparer changed",
    )
    module = ModuleType("_fre_application_link_manifest_preparer")
    module.__file__ = str(path)
    exec(
        compile(encoded, str(path), "exec", dont_inherit=True),
        module.__dict__,
    )
    return module


def validate(repo: Path) -> dict[str, Any]:
    directory = Path(__file__).resolve().parent
    preparer = load_preparer(directory)
    expected_objects, expected_dispositions = preparer.derive(repo)
    expected_object_bytes = preparer.json_bytes(expected_objects)
    expected_disposition_bytes = preparer.json_bytes(expected_dispositions)
    object_bytes = regular_file(directory / OBJECT_NAME)
    disposition_bytes = regular_file(directory / DISPOSITION_NAME)
    contract_bytes = regular_file(directory / CONTRACT_NAME)
    objects = json.loads(object_bytes)
    dispositions = json.loads(disposition_bytes)
    contract = json.loads(contract_bytes)
    require(
        object_bytes == expected_object_bytes
        and sha256(object_bytes) == OBJECT_SHA256
        and objects == expected_objects
        and objects["payload_sha256"] == OBJECT_PAYLOAD_SHA256
        and preparer.canonical_sha(objects["payload"])
        == OBJECT_PAYLOAD_SHA256,
        "application object-candidate manifest is not the exact derivation",
    )
    require(
        disposition_bytes == expected_disposition_bytes
        and sha256(disposition_bytes) == DISPOSITION_SHA256
        and dispositions == expected_dispositions
        and dispositions["payload_sha256"] == DISPOSITION_PAYLOAD_SHA256
        and preparer.canonical_sha(dispositions["payload"])
        == DISPOSITION_PAYLOAD_SHA256,
        "application literal-disposition manifest is not the exact derivation",
    )
    eligible = [
        row
        for row in dispositions["payload"]["dispositions"]
        if row["expected_compiler_disposition"] == "tag29-object"
    ]
    refusals = [
        row
        for row in dispositions["payload"]["dispositions"]
        if row["expected_compiler_disposition"] == "structural-refusal"
    ]
    require(
        len(eligible) == preparer.OBJECT_COUNT
        and len(refusals) == preparer.REFUSAL_COUNT
        and [
            (
                row["semantic_candidate_sha256"],
                row["literal_sha256"],
                row["literal_hex"],
                row["literal_bytes"],
            )
            for row in eligible
        ]
        == [
            (
                row["semantic_candidate_sha256"],
                row["literal_sha256"],
                row["literal_hex"],
                row["literal_bytes"],
            )
            for row in objects["payload"]["candidates"]
        ],
        "application object and disposition manifests are not bijective",
    )
    require(
        sha256(contract_bytes) == CONTRACT_SHA256
        and contract["schema"]
        == "fre.aot.search-tag29-static-link-proof-contract.v2"
        and contract["profile"] == "ripgrep-application-v2"
        and contract["status"] == "result-blind-prequalification"
        and contract["object_candidates"]
        == {
            "schema": preparer.OBJECT_SCHEMA,
            "file_sha256": OBJECT_SHA256,
            "payload_sha256": OBJECT_PAYLOAD_SHA256,
            "count": preparer.OBJECT_COUNT,
        }
        and contract["literal_dispositions"]
        == {
            "schema": preparer.DISPOSITION_SCHEMA,
            "file_sha256": DISPOSITION_SHA256,
            "payload_sha256": DISPOSITION_PAYLOAD_SHA256,
            "count": preparer.DISPOSITION_COUNT,
            "object_count": preparer.OBJECT_COUNT,
            "refusal_count": preparer.REFUSAL_COUNT,
        }
        and contract["source_authority"]
        == {
            "freeze_sha256": preparer.FREEZE_SHA256,
            "freeze_payload_sha256": preparer.FREEZE_PAYLOAD_SHA256,
            "inventory_sha256": preparer.INVENTORY_SHA256,
            "inventory_payload_sha256": (
                preparer.INVENTORY_PAYLOAD_SHA256
            ),
            "selector_contract_sha256": preparer.SELECTOR_SHA256,
            "selector_implementation_sha256": (
                preparer.SELECTOR_IMPLEMENTATION_SHA256
            ),
            "manifest_preparer_source_sha256": PREPARER_SHA256,
            "fixture_manifest_sha256": preparer.FIXTURE_MANIFEST_SHA256,
            "fixture_manifest_payload_sha256": (
                preparer.FIXTURE_MANIFEST_PAYLOAD_SHA256
            ),
            "upstream_commit": preparer.UPSTREAM_COMMIT,
            "upstream_tree": preparer.UPSTREAM_TREE,
        }
        and contract["authority"]
        == {
            "timing_results_read": False,
            "benchmark_result_inputs": [],
            "rebar_inputs": [],
            "network": False,
            "promotion_authority": False,
            "required_output_schema": (
                "fre.aot.search-tag29-compiler-object-link-evidence.v1"
            ),
        },
        "application link-proof contract is not the exact derived authority",
    )
    return {
        "contract_sha256": CONTRACT_SHA256,
        "object_file_sha256": OBJECT_SHA256,
        "object_payload_sha256": OBJECT_PAYLOAD_SHA256,
        "disposition_file_sha256": DISPOSITION_SHA256,
        "disposition_payload_sha256": DISPOSITION_PAYLOAD_SHA256,
        "objects": len(eligible),
        "refusals": len(refusals),
        "dispositions": len(eligible) + len(refusals),
    }


def main() -> None:
    require(
        len(sys.argv) == 2,
        "usage: validate_link_manifests.py REPO",
    )
    repo = Path(sys.argv[1]).resolve(strict=True)
    print(json.dumps(validate(repo), sort_keys=True))


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
        print(f"search-tag29-application-link-validate: {error}", file=sys.stderr)
        raise SystemExit(1)
