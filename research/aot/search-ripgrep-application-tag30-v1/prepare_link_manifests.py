#!/usr/bin/env python3
"""Derive result-blind tag-30 link inputs from the frozen application set."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from types import ModuleType
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
INVENTORY_RELATIVE = (
    "research/aot/search-ripgrep-application-independent-v2/inventory-v2.json"
)
INVENTORY_SHA256 = (
    "2aec7b83cfcafbd0f8a9cab2e08941882b34d39786d26f26837c671378f1275b"
)
INVENTORY_PAYLOAD_SHA256 = (
    "68af2c6dd547935d3c4dd095f18958035104d153b355ff416c46c78a922b0979"
)
SELECTOR_RELATIVE = (
    "research/aot/search-phase-unique-selector-v1/selector-contract-v1.json"
)
SELECTOR_SHA256 = (
    "38ca5ebc1b239b541afcf9eeb679bf8b156c8690e7422a96f69a9457a155daf0"
)
SELECTOR_IMPLEMENTATION_RELATIVE = (
    "research/aot/search-tag29-topology-generalization-v1/"
    "generate_projection.py"
)
SELECTOR_IMPLEMENTATION_SHA256 = (
    "35aacbca100dde74a2ead493ceab1197c813d37c17d5f4a9d3e62938c3a2b610"
)
FIXTURE_MANIFEST_SHA256 = (
    "b20181470c604d01d2ec236259293cfcb6e5eff145bcd3e4daa91554c8cebcca"
)
FIXTURE_MANIFEST_PAYLOAD_SHA256 = (
    "1cbda700087f5506daa91b0657070cbf39fac68222ff84e273d1d83c09f6ebfd"
)
UPSTREAM_COMMIT = "f9c05a949d1a0dc8e16dee28ca9605d38611faeb"
UPSTREAM_TREE = "ce81df4f8cad2dbfd1afb6b3ba53fd19846a5794"
SEMANTIC_DOMAIN = b"fre.aot.search-ripgrep-application-literal.v2\0"
OBJECT_SCHEMA = "fre.aot.search-tag30-application-object-candidates.v1"
DISPOSITION_SCHEMA = (
    "fre.aot.search-tag30-application-literal-dispositions.v1"
)
OBJECT_COUNT = 5
REFUSAL_COUNT = 6
DISPOSITION_COUNT = 11
BACKEND_TAG = 30
BACKEND_VERSION = "SEARCH_V17"
BACKEND_NAME = "AsimdV17"
CANDIDATE_POLICY = 15
FAMILY_SELECTOR = 13
MINIMUM_LITERAL_BYTES = 6
MAXIMUM_LITERAL_BYTES = 32
MINIMUM_WINDOW_BYTES = 65_536
PORTABLE_PREFIX_CANDIDATE_STARTS = 256


class Refusal(RuntimeError):
    """A frozen application or selector input changed."""


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


def json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode("ascii")


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
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_nlink,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            == (
                opened.st_dev,
                opened.st_ino,
                opened.st_mode,
                opened.st_nlink,
                opened.st_size,
                opened.st_mtime_ns,
                opened.st_ctime_ns,
            ),
            f"file changed while read: {path}",
        )
        return encoded
    finally:
        os.close(descriptor)


def load_envelope(
    path: Path,
    expected_schema: str,
    expected_file_sha256: str,
    expected_payload_sha256: str,
) -> dict[str, Any]:
    encoded = regular_file(path)
    root = json.loads(encoded)
    require(
        sha256(encoded) == expected_file_sha256
        and isinstance(root, dict)
        and set(root) == {"schema", "payload_sha256", "payload"}
        and root["schema"] == expected_schema
        and root["payload_sha256"] == expected_payload_sha256
        and canonical_sha(root["payload"]) == expected_payload_sha256,
        f"frozen envelope changed: {path}",
    )
    return root


def load_selector(repo: Path) -> ModuleType:
    selector_contract = regular_file(repo / SELECTOR_RELATIVE)
    require(
        sha256(selector_contract) == SELECTOR_SHA256,
        "selector contract changed",
    )
    implementation_path = repo / SELECTOR_IMPLEMENTATION_RELATIVE
    implementation = regular_file(implementation_path, 2 * 1024 * 1024)
    require(
        sha256(implementation) == SELECTOR_IMPLEMENTATION_SHA256,
        "selector implementation changed",
    )
    module = ModuleType("_fre_tag30_application_frozen_selector")
    module.__file__ = str(implementation_path)
    exec(
        compile(
            implementation,
            str(implementation_path),
            "exec",
            dont_inherit=True,
        ),
        module.__dict__,
    )
    return module


def envelope(schema: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": schema,
        "payload_sha256": canonical_sha(payload),
        "payload": payload,
    }


def classify(
    selector: ModuleType, literal: bytes
) -> tuple[bool, list[int]]:
    if len(literal) == 1:
        return False, [0]
    eligible, offsets = selector.selector_eligible(literal)
    return eligible, list(offsets)


def derive(repo: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    freeze = load_envelope(
        repo / FREEZE_RELATIVE,
        "fre.aot.search-ripgrep-application-freeze.v2",
        FREEZE_SHA256,
        FREEZE_PAYLOAD_SHA256,
    )
    inventory = load_envelope(
        repo / INVENTORY_RELATIVE,
        "fre.aot.search-ripgrep-application-literals.v2",
        INVENTORY_SHA256,
        INVENTORY_PAYLOAD_SHA256,
    )
    selector = load_selector(repo)
    frozen_selector = freeze["payload"]["selector"]
    frozen_eligible = {
        row["semantic_candidate_sha256"]: row
        for row in frozen_selector["eligible"]
    }
    frozen_ineligible = {
        row["semantic_candidate_sha256"]: row
        for row in frozen_selector["ineligible"]
    }
    require(
        len(frozen_eligible) == OBJECT_COUNT
        and len(frozen_ineligible) == REFUSAL_COUNT
        and not (set(frozen_eligible) & set(frozen_ineligible)),
        "frozen selector partition changed",
    )
    dispositions = []
    candidates = []
    for ordinal, source in enumerate(inventory["payload"]["candidates"]):
        require(
            isinstance(source, dict)
            and set(source)
            == {
                "semantic_candidate_sha256",
                "literal_hex",
                "literal_sha256",
                "literal_bytes",
                "source_path",
                "source_file_sha256",
                "source_file_bytes",
                "source_token_offset",
                "source_token_ascii",
            },
            f"inventory candidate {ordinal} fields changed",
        )
        literal = bytes.fromhex(source["literal_hex"])
        semantic = source["semantic_candidate_sha256"]
        derived_semantic = sha256(
            SEMANTIC_DOMAIN
            + bytes.fromhex(UPSTREAM_COMMIT)
            + source["source_path"].encode("ascii")
            + b"\0"
            + source["source_token_offset"].to_bytes(8, "little")
            + literal
        )
        require(
            len(literal) == source["literal_bytes"]
            and sha256(literal) == source["literal_sha256"]
            and derived_semantic == semantic,
            f"inventory candidate {ordinal} identity changed",
        )
        eligible, offsets = classify(selector, literal)
        expected_reason = (
            "width-below-six"
            if len(literal) < 6
            else "cyclic-phase-signature-not-unique"
        )
        if eligible:
            require(
                semantic in frozen_eligible
                and frozen_eligible[semantic]
                == {
                    "semantic_candidate_sha256": semantic,
                    "literal_bytes": len(literal),
                    "selected_offsets": offsets,
                },
                f"eligible candidate {ordinal} differs from the freeze",
            )
        else:
            require(
                semantic in frozen_ineligible
                and frozen_ineligible[semantic]
                == {
                    "semantic_candidate_sha256": semantic,
                    "reason": expected_reason,
                },
                f"ineligible candidate {ordinal} differs from the freeze",
            )
        disposition = {
            "semantic_candidate_sha256": semantic,
            "literal_hex": source["literal_hex"],
            "literal_sha256": source["literal_sha256"],
            "literal_bytes": source["literal_bytes"],
            "selected_offsets": offsets,
            "selector_eligible": eligible,
            "expected_compiler_disposition": (
                "tag30-object" if eligible else "structural-refusal"
            ),
        }
        dispositions.append(disposition)
        if eligible:
            candidates.append(
                {
                    field: disposition[field]
                    for field in (
                        "semantic_candidate_sha256",
                        "literal_hex",
                        "literal_sha256",
                        "literal_bytes",
                    )
                }
            )
    require(
        len(dispositions) == DISPOSITION_COUNT
        and len(candidates) == OBJECT_COUNT
        and sum(not row["selector_eligible"] for row in dispositions)
        == REFUSAL_COUNT,
        "derived application disposition cardinality changed",
    )
    common = {
        "freeze_sha256": FREEZE_SHA256,
        "freeze_payload_sha256": FREEZE_PAYLOAD_SHA256,
        "inventory_sha256": INVENTORY_SHA256,
        "inventory_payload_sha256": INVENTORY_PAYLOAD_SHA256,
        "selector_contract_sha256": SELECTOR_SHA256,
        "selector_implementation_sha256": SELECTOR_IMPLEMENTATION_SHA256,
        "fixture_manifest_sha256": FIXTURE_MANIFEST_SHA256,
        "fixture_manifest_payload_sha256": (
            FIXTURE_MANIFEST_PAYLOAD_SHA256
        ),
        "upstream_commit": UPSTREAM_COMMIT,
        "upstream_tree": UPSTREAM_TREE,
        "timing_permitted": False,
        "timing_feedback_permitted": False,
        "external_inputs": [],
        "benchmark_results": [],
        "rebar_inputs": [],
        "network": False,
        "production_authority": False,
        "application_qualification_authority": False,
        "campaign_plan_identity": None,
        "private_family_authorization_identity": None,
    }
    object_payload = {
        **common,
        "backend_tag": BACKEND_TAG,
        "backend_version": BACKEND_VERSION,
        "candidate_policy": CANDIDATE_POLICY,
        "backend_name": BACKEND_NAME,
        "family_selector": FAMILY_SELECTOR,
        "minimum_literal_bytes": MINIMUM_LITERAL_BYTES,
        "maximum_literal_bytes": MAXIMUM_LITERAL_BYTES,
        "minimum_window_bytes": MINIMUM_WINDOW_BYTES,
        "portable_prefix_candidate_starts": (
            PORTABLE_PREFIX_CANDIDATE_STARTS
        ),
        "llvm": False,
        "source_construction": "canonical-byte-escaped-exact",
        "candidate_count": OBJECT_COUNT,
        "candidates": candidates,
    }
    disposition_payload = {
        **common,
        "literal_count": DISPOSITION_COUNT,
        "eligible_literal_count": OBJECT_COUNT,
        "ineligible_literal_count": REFUSAL_COUNT,
        "dispositions": dispositions,
    }
    return (
        envelope(OBJECT_SCHEMA, object_payload),
        envelope(DISPOSITION_SCHEMA, disposition_payload),
    )


def write_new(path: Path, encoded: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o644,
    )
    try:
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            require(written > 0, f"short write: {path}")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main() -> None:
    require(
        len(sys.argv) == 3,
        "usage: prepare_link_manifests.py REPO NEW_OUTPUT_DIRECTORY",
    )
    repo = Path(sys.argv[1]).resolve(strict=True)
    output = Path(sys.argv[2])
    require(not output.exists(), f"refusing existing output: {output}")
    objects, dispositions = derive(repo)
    output.mkdir(mode=0o755)
    object_bytes = json_bytes(objects)
    disposition_bytes = json_bytes(dispositions)
    write_new(output / "object-candidates.json", object_bytes)
    write_new(output / "literal-dispositions.json", disposition_bytes)
    print(
        f"object_file_sha256={sha256(object_bytes)} "
        f"object_payload_sha256={objects['payload_sha256']} "
        f"disposition_file_sha256={sha256(disposition_bytes)} "
        f"disposition_payload_sha256={dispositions['payload_sha256']} "
        f"objects={OBJECT_COUNT} refusals={REFUSAL_COUNT} "
        "rebar_inputs=0 benchmark_results=0"
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
        print(f"search-tag30-application-link-prepare: {error}", file=sys.stderr)
        raise SystemExit(1)
