#!/usr/bin/env python3
"""Create the reviewed, pre-result private-family discovery authorization."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping, Sequence

import render_identity as identity


PRIVATE_SOURCE_RELATIVE = (
    "crates/fre-aot-static-runtime/src/search_support/private_rows.rs"
)
IMPLEMENTATION_SYMBOL_FIELDS = {"entry", "payload", "metadata"}
CANDIDATE_DOMAIN = b"FRE-SEARCH-TAG30-QUALIFICATION-CANDIDATE\0\x01"


class Refusal(RuntimeError):
    """A discovery identity or target receipt is mixed or incomplete."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def sha256(encoded: bytes) -> str:
    return hashlib.sha256(encoded).hexdigest()


def flat_name(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value not in {"", ".", ".."}
        and "/" not in value
        and "\\" not in value
        and "\x00" not in value
    )


def expected_discovery_identity(
    repo: Path,
    directory: Path,
    prepared: Mapping[str, Any],
    prepared_sha256: str,
    revision: str,
) -> tuple[dict[str, Any], Mapping[str, str]]:
    template = identity.load_template(directory)
    archive = identity.archive_sha256(repo)
    source_set = identity.source_set_sha256(directory)
    analyzer_sha256 = sha256(
        identity.read_regular(directory / "analyze_fragments.py", 1 << 20)
    )
    controller_sha256 = sha256(
        identity.read_regular(directory / "run_shards.py", 1 << 20)
    )
    prepare_sha256 = sha256(
        identity.read_regular(directory / "prepare_inputs.py", 1 << 20)
    )
    renderer_sha256 = sha256(
        identity.read_regular(directory / "render_identity.py", 1 << 20)
    )
    private_source = identity.read_regular(
        repo / PRIVATE_SOURCE_RELATIVE, 1 << 18
    )
    require(
        private_source.decode("utf-8").count(identity.PRIVATE_CONSTRUCTOR) == 0,
        "discovery checkout already contains private family rows",
    )
    expected = deepcopy(template)
    expected["campaign_inputs"].update(
        {
            "contract_sha256": identity.CONTRACT_SHA256,
            "prepared_inputs_sha256": prepared_sha256,
            "prepare_source_sha256": prepare_sha256,
        }
    )
    for name, projection in prepared["projections"].items():
        expected["campaign_inputs"]["projections"][name][
            "file_sha256"
        ] = projection["file_sha256"]
    for component in (
        "emitter",
        "static_pipeline",
        "auto_routing",
        "static_facade",
        "runner",
    ):
        expected[component]["source_commit"] = revision
    expected["static_pipeline"]["compiler_identity"] = (
        identity.compiler_identity(revision, archive)
    )
    expected["auto_routing"].update(
        {
            "plan_identity": identity.CONTRACT_SHA256,
            "analyzer_identity": analyzer_sha256,
            "evidence_identity": None,
        }
    )
    expected["static_facade"]["source_set_sha256"] = source_set
    expected["private_family"].update(
        {
            "source_sha256": sha256(private_source),
            "promotion_state": "empty-object-only-discovery",
            "discovery_authorization_sha256": None,
        }
    )
    expected["runner"].update(
        {
            "source_set_sha256": source_set,
            "source_archive_sha256": archive,
            "analyzer_source_sha256": analyzer_sha256,
            "controller_source_sha256": controller_sha256,
            "prepare_source_sha256": prepare_sha256,
            "identity_renderer_source_sha256": renderer_sha256,
        }
    )
    expected["state"] = {
        "heldout_materialized": False,
        "development_timing_permitted": False,
        "blocker": (
            "target-conditional selector-13 private family source promotion "
            "is unresolved"
        ),
    }
    facts = {
        "archive": archive,
        "source_set": source_set,
        "analyzer": analyzer_sha256,
        "prepare": prepare_sha256,
        "private_source": sha256(private_source),
        "compiler": expected["static_pipeline"]["compiler_identity"],
    }
    return expected, facts


def load_discovery_identity(
    path: Path,
    expected_sha256: str,
    expected: Mapping[str, Any],
) -> str:
    require(path.is_absolute(), "discovery identity path must be absolute")
    require(
        identity.is_hex(expected_sha256),
        "reviewed discovery identity SHA-256 is malformed",
    )
    encoded = identity.read_regular(path, 1 << 20, readonly=True)
    require(
        sha256(encoded) == expected_sha256,
        "discovery identity differs from its reviewed SHA-256",
    )
    require(
        json.loads(encoded) == expected,
        "discovery identity is not the exact deterministic rendering",
    )
    return expected_sha256


def validate_candidate_rows(
    candidates: Any,
    refusals: Any,
    expected_candidates: Sequence[Mapping[str, Any]],
    expected_refusals: Sequence[Mapping[str, Any]],
) -> None:
    require(
        isinstance(candidates, list)
        and len(candidates) == 808
        and isinstance(refusals, list)
        and len(refusals) == 114,
        "discovery object/refusal inventory count changed",
    )
    require(
        len(expected_candidates) == 808 and len(expected_refusals) == 114,
        "prepared object/refusal inventory count changed",
    )
    literal_hashes: set[str] = set()
    semantic_hashes: set[str] = set()
    compile_receipts: set[str] = set()
    compile_identities: set[str] = set()
    implementation_objects: set[str] = set()
    glue_objects: set[str] = set()
    glue_symbols: set[str] = set()
    for ordinal, row in enumerate(candidates):
        expected = expected_candidates[ordinal]
        identity.exact_keys(
            row,
            identity.CANDIDATE_RECEIPT_FIELDS,
            f"candidate receipt {ordinal}",
        )
        symbols = identity.exact_keys(
            row["implementation_symbols"],
            IMPLEMENTATION_SYMBOL_FIELDS,
            f"candidate symbols {ordinal}",
        )
        literal = bytes.fromhex(row["literal_hex"])
        require(
            row["ordinal"] == ordinal
            and 6 <= len(literal) <= 32
            and row["literal_hex"] == literal.hex()
            and {
                "literal_hex": row["literal_hex"],
                "literal_sha256": row["literal_sha256"],
                "semantic_candidate_sha256": row[
                    "semantic_candidate_sha256"
                ],
            }
            == {
                "literal_hex": expected["literal_hex"],
                "literal_sha256": expected["literal_sha256"],
                "semantic_candidate_sha256": expected[
                    "semantic_candidate_sha256"
                ],
            }
            and len(literal) == expected["literal_bytes"]
            and sha256(literal) == row["literal_sha256"]
            and row["semantic_candidate_sha256"]
            == sha256(CANDIDATE_DOMAIN + literal)
            and identity.is_hex(row["compile_identity"])
            and identity.is_hex(row["compile_receipt_sha256"])
            and identity.is_hex(row["implementation_object_sha256"])
            and identity.is_hex(row["glue_object_sha256"])
            and flat_name(row["compile_receipt_basename"])
            and flat_name(row["implementation_object_basename"])
            and flat_name(row["glue_object_basename"])
            and row["compile_receipt_basename"]
            == f"external-search-{ordinal}-compile-receipt.bin"
            and row["implementation_object_basename"]
            == f"external-search-{ordinal}-implementation.o"
            and row["glue_object_basename"]
            == f"external-search-{ordinal}-family-glue.o"
            and all(
                isinstance(value, str) and value
                for value in (*symbols.values(), row["glue_symbol"])
            )
            and literal_hashes.add(row["literal_sha256"]) is None
            and semantic_hashes.add(row["semantic_candidate_sha256"]) is None
            and compile_receipts.add(row["compile_receipt_sha256"]) is None
            and compile_identities.add(row["compile_identity"]) is None
            and implementation_objects.add(
                row["implementation_object_sha256"]
            )
            is None
            and glue_objects.add(row["glue_object_sha256"]) is None
            and glue_symbols.add(row["glue_symbol"]) is None,
            f"candidate receipt {ordinal} changed",
        )
    require(
        len(literal_hashes)
        == len(semantic_hashes)
        == len(compile_receipts)
        == len(compile_identities)
        == len(implementation_objects)
        == len(glue_objects)
        == len(glue_symbols)
        == 808,
        "candidate receipt identity is not injective",
    )
    for ordinal, row in enumerate(refusals):
        expected = expected_refusals[ordinal]
        identity.exact_keys(
            row,
            identity.REFUSAL_RECEIPT_FIELDS,
            f"refusal receipt {ordinal}",
        )
        literal = bytes.fromhex(row["literal_hex"])
        require(
            row["ordinal"] == ordinal
            and row["disposition"] == "structural-refusal"
            and 0 < len(literal) <= 32
            and row["literal_hex"] == literal.hex()
            and {
                "literal_hex": row["literal_hex"],
                "literal_sha256": row["literal_sha256"],
                "semantic_candidate_sha256": row[
                    "semantic_candidate_sha256"
                ],
            }
            == {
                "literal_hex": expected["literal_hex"],
                "literal_sha256": expected["literal_sha256"],
                "semantic_candidate_sha256": expected[
                    "semantic_candidate_sha256"
                ],
            }
            and len(literal) == expected["literal_bytes"]
            and expected["selector_eligible"] is False
            and expected["expected_compiler_disposition"]
            == "structural-refusal"
            and sha256(literal) == row["literal_sha256"]
            and row["semantic_candidate_sha256"]
            == sha256(CANDIDATE_DOMAIN + literal)
            and identity.is_hex(row["compile_receipt_sha256"])
            and flat_name(row["compile_receipt_basename"])
            and row["compile_receipt_basename"]
            == f"external-search-refusal-{ordinal}-compile-receipt.bin"
            and row["literal_sha256"] not in literal_hashes
            and row["semantic_candidate_sha256"] not in semantic_hashes
            and row["compile_receipt_sha256"] not in compile_receipts,
            f"refusal receipt {ordinal} changed",
        )
        literal_hashes.add(row["literal_sha256"])
        semantic_hashes.add(row["semantic_candidate_sha256"])
        compile_receipts.add(row["compile_receipt_sha256"])
    require(
        len(literal_hashes)
        == len(semantic_hashes)
        == len(compile_receipts)
        == 922,
        "literal/refusal inventory is not injective",
    )


def load_expected_inventory(
    prepared_directory: Path,
) -> tuple[Sequence[Mapping[str, Any]], Sequence[Mapping[str, Any]]]:
    objects = json.loads(
        identity.read_regular(
            prepared_directory / "object-candidates.json",
            4 << 20,
            readonly=True,
        )
    )
    dispositions = json.loads(
        identity.read_regular(
            prepared_directory / "literal-dispositions.json",
            4 << 20,
            readonly=True,
        )
    )
    object_payload = objects["payload"]
    disposition_payload = dispositions["payload"]
    require(
        objects["schema"] == identity.OBJECT_SCHEMA
        and objects["payload_sha256"] == identity.OBJECT_PAYLOAD_SHA256
        and objects["payload_sha256"]
        == sha256(identity.canonical_bytes(object_payload))
        and dispositions["schema"] == identity.DISPOSITION_SCHEMA
        and dispositions["payload_sha256"]
        == identity.DISPOSITION_PAYLOAD_SHA256
        and dispositions["payload_sha256"]
        == sha256(identity.canonical_bytes(disposition_payload)),
        "prepared object/refusal envelope changed",
    )
    candidates = object_payload["candidates"]
    refusals = [
        row
        for row in disposition_payload["dispositions"]
        if row["selector_eligible"] is False
    ]
    require(
        isinstance(candidates, list)
        and len(candidates) == 808
        and len(refusals) == 114,
        "prepared object/refusal inventory changed",
    )
    return candidates, refusals


def load_build_receipt(
    path: Path,
    expected_sha256: str,
    platform: Mapping[str, str],
    discovery_identity_sha256: str,
    revision: str,
    prepared_sha256: str,
    facts: Mapping[str, str],
    expected_candidates: Sequence[Mapping[str, Any]],
    expected_refusals: Sequence[Mapping[str, Any]],
) -> Mapping[str, Any]:
    require(path.is_absolute(), "discovery receipt path must be absolute")
    require(
        identity.is_hex(expected_sha256),
        "reviewed discovery receipt SHA-256 is malformed",
    )
    encoded = identity.read_regular(path, 64 << 20, readonly=True)
    require(
        sha256(encoded) == expected_sha256,
        "discovery receipt differs from its reviewed SHA-256",
    )
    receipt = identity.exact_keys(
        json.loads(encoded),
        identity.BUILD_RECEIPT_FIELDS,
        "discovery build receipt",
    )
    require(
        receipt["schema"] == identity.BUILD_RECEIPT_SCHEMA
        and receipt["identity_sha256"] == discovery_identity_sha256
        and receipt["runner_revision"] == revision
        and receipt["runner_source_sha256"] == facts["source_set"]
        and receipt["source_archive_sha256"] == facts["archive"]
        and receipt["private_family_source_sha256"]
        == facts["private_source"]
        and receipt["target_os"] == platform["target_os"]
        and receipt["target_arch"] == platform["target_arch"]
        and receipt["host_id"] == platform["host_id"]
        and receipt["backend_name"] == "AsimdV17"
        and receipt["backend_tag"] == 30
        and receipt["backend_version"] == "SEARCH_V17"
        and receipt["candidate_policy"] == 15
        and receipt["llvm"] is False
        and receipt["compiler_identity"] == facts["compiler"]
        and identity.is_hex(receipt["manifest_identity"])
        and receipt["discovery_authorization_sha256"] is None
        and receipt["discovery_build_receipt_sha256"] is None
        and receipt["family_selector"] == 13
        and receipt["minimum_literal_bytes"] == 6
        and receipt["maximum_literal_bytes"] == 32
        and receipt["minimum_window_bytes"] == 65_536
        and receipt["portable_prefix_candidate_starts"] == 256
        and receipt["plan_identity"] == identity.CONTRACT_SHA256
        and receipt["analyzer_identity"] == facts["analyzer"]
        and receipt["evidence_identity"] is None
        and receipt["timing_permitted"] is False
        and receipt["object_candidate_manifest_schema"]
        == identity.OBJECT_SCHEMA
        and receipt["object_candidate_manifest_sha256"]
        == identity.OBJECT_SHA256
        and receipt["object_candidate_manifest_payload_sha256"]
        == identity.OBJECT_PAYLOAD_SHA256
        and receipt["object_candidate_count"] == 808
        and receipt["literal_dispositions_sha256"]
        == identity.DISPOSITION_SHA256
        and receipt["literal_dispositions_payload_sha256"]
        == identity.DISPOSITION_PAYLOAD_SHA256
        and receipt["literal_disposition_count"] == 922
        and receipt["prepared_inputs_sha256"] == prepared_sha256
        and receipt["prepare_source_sha256"] == facts["prepare"]
        and receipt["canonical_byte_escaped_sources"] is True,
        "discovery receipt source/input identity changed",
    )
    identity.validate_family_tuple(
        receipt["family_tuple"],
        receipt["manifest_identity"],
        "discovery family tuple",
    )
    validate_candidate_rows(
        receipt["candidates"],
        receipt["refusals"],
        expected_candidates,
        expected_refusals,
    )
    return receipt


def prepare(
    repo: Path,
    prepared_directory: Path,
    discovery_identity_path: Path,
    discovery_identity_sha256: str,
    receipt_arguments: Sequence[str],
    output: Path,
) -> Mapping[str, Any]:
    require(
        len(receipt_arguments) == 4,
        "two receipt paths and two reviewed receipt SHAs are required",
    )
    revision = identity.authenticate_clean_repo(repo)
    directory = repo / identity.DIRECTORY_RELATIVE
    contract = identity.load_contract(directory)
    template = identity.load_template(directory)
    prepared, prepared_sha256 = identity.load_prepared_inputs(
        prepared_directory, template
    )
    expected, facts = expected_discovery_identity(
        repo, directory, prepared, prepared_sha256, revision
    )
    reviewed_identity = load_discovery_identity(
        discovery_identity_path,
        discovery_identity_sha256,
        expected,
    )
    expected_candidates, expected_refusals = load_expected_inventory(
        prepared_directory
    )
    receipts: dict[str, Mapping[str, Any]] = {}
    receipt_hashes: dict[str, str] = {}
    for (key, platform), (raw_path, reviewed_sha) in zip(
        identity.PLATFORMS.items(),
        (
            (receipt_arguments[0], receipt_arguments[1]),
            (receipt_arguments[2], receipt_arguments[3]),
        ),
        strict=True,
    ):
        receipts[key] = load_build_receipt(
            Path(raw_path),
            reviewed_sha,
            platform,
            reviewed_identity,
            revision,
            prepared_sha256,
            facts,
            expected_candidates,
            expected_refusals,
        )
        receipt_hashes[key] = reviewed_sha
    common_fields = (
        "identity_sha256",
        "runner_revision",
        "runner_source_sha256",
        "source_archive_sha256",
        "private_family_source_sha256",
        "compiler_identity",
        "plan_identity",
        "analyzer_identity",
        "evidence_identity",
        "prepared_inputs_sha256",
        "prepare_source_sha256",
        "object_candidate_manifest_sha256",
        "object_candidate_manifest_payload_sha256",
        "literal_dispositions_sha256",
        "literal_dispositions_payload_sha256",
    )
    require(
        all(
            receipts["macos_aarch64"][field]
            == receipts["linux_aarch64"][field]
            for field in common_fields
        )
        and receipt_hashes["macos_aarch64"]
        != receipt_hashes["linux_aarch64"],
        "discovery receipts do not form one source/input class",
    )
    authority = contract["private_family_authority"][
        "discovery_authorization"
    ]
    payload = {
        "contract_schema": identity.CONTRACT_SCHEMA,
        "campaign_contract_sha256": identity.CONTRACT_SHA256,
        "analyzer_source_sha256": facts["analyzer"],
        "prepared_inputs_sha256": prepared_sha256,
        "object_candidate_manifest_schema": identity.OBJECT_SCHEMA,
        "object_candidate_manifest_sha256": identity.OBJECT_SHA256,
        "object_candidate_manifest_payload_sha256": (
            identity.OBJECT_PAYLOAD_SHA256
        ),
        "literal_dispositions_schema": identity.DISPOSITION_SCHEMA,
        "literal_dispositions_sha256": identity.DISPOSITION_SHA256,
        "literal_dispositions_payload_sha256": (
            identity.DISPOSITION_PAYLOAD_SHA256
        ),
        "prepare_source_sha256": facts["prepare"],
        "discovery_runner_revision": revision,
        "discovery_runner_source_sha256": facts["source_set"],
        "discovery_source_archive_sha256": facts["archive"],
        "discovery_identity_sha256": reviewed_identity,
        "discovery_private_family_source_sha256": facts["private_source"],
        "family_common": {
            "backend": {
                "name": "AsimdV17",
                "tag": 30,
                "version": "SEARCH_V17",
                "candidate_policy": 15,
                "llvm": False,
            },
            "compiler": {"identity": facts["compiler"]},
            "wire": {
                "aot_magic_hex": "465245413634001e",
                "static_abi": "fre-aot-static-search-span-v1",
                "output": "Span",
                "link_interface_schema": (
                    "fre.aot.search-span-family-qualification-final-image-"
                    "glue.v1"
                ),
            },
            "envelope": {
                "family_selector": 13,
                "minimum_literal_bytes": 6,
                "maximum_literal_bytes": 32,
                "minimum_window_bytes": 65_536,
                "portable_prefix_candidate_starts": 256,
            },
        },
        "decision": authority["decision"],
        "qualification": authority["qualification"],
        "targets": {
            key: {
                "host_id": identity.PLATFORMS[key]["host_id"],
                "target_os": identity.PLATFORMS[key]["target_os"],
                "target_arch": identity.PLATFORMS[key]["target_arch"],
                "manifest_identity": receipts[key]["manifest_identity"],
                "discovery_build_receipt_schema": (
                    identity.BUILD_RECEIPT_SCHEMA
                ),
                "discovery_build_receipt_sha256": receipt_hashes[key],
                "family_tuple": receipts[key]["family_tuple"],
            }
            for key in identity.PLATFORMS
        },
    }
    envelope = {
        "schema": identity.DISCOVERY_AUTHORIZATION_SCHEMA,
        "payload_sha256": sha256(identity.canonical_bytes(payload)),
        "payload": payload,
    }
    encoded = identity.pretty_bytes(envelope)
    descriptor = os.open(
        output,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0),
        0o444,
    )
    with os.fdopen(descriptor, "wb", closefd=True) as destination:
        destination.write(encoded)
        destination.flush()
        os.fsync(destination.fileno())
    return {
        "schema": identity.DISCOVERY_AUTHORIZATION_SCHEMA,
        "discovery_authorization_sha256": sha256(encoded),
        "payload_sha256": envelope["payload_sha256"],
        "runner_revision": revision,
        "runner_source_sha256": facts["source_set"],
        "prepared_inputs_sha256": prepared_sha256,
        "private_projection": True,
        "production_projection": False,
        "output": str(output),
    }


def main(argv: Sequence[str]) -> None:
    require(
        len(argv) == 9,
        "usage: prepare_discovery_authorization.py REPO PREPARED_DIRECTORY "
        "DISCOVERY_IDENTITY IDENTITY_SHA MAC_RECEIPT MAC_RECEIPT_SHA "
        "LINUX_RECEIPT LINUX_RECEIPT_SHA NEW_OUTPUT",
    )
    repo = Path(argv[0]).resolve(strict=True)
    prepared = Path(argv[1]).resolve(strict=True)
    discovery_identity = Path(argv[2]).resolve(strict=True)
    output = Path(argv[8]).resolve()
    summary = prepare(
        repo,
        prepared,
        discovery_identity,
        argv[3],
        argv[4:8],
        output,
    )
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (
        OSError,
        UnicodeError,
        ValueError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
        identity.Refusal,
        Refusal,
    ) as error:
        print(
            f"search-tag30-prepare-discovery-authorization: {error}",
            file=sys.stderr,
        )
        raise SystemExit(1)
