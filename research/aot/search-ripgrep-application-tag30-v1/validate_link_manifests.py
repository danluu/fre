#!/usr/bin/env python3
"""Reconstruct and validate the tag-30 application link inputs."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import stat
import sys
from pathlib import Path
from typing import Any


DIRECTORY = "research/aot/search-ripgrep-application-tag30-v1"
PREPARER = f"{DIRECTORY}/prepare_link_manifests.py"
PREPARER_SHA256 = (
    "6b79046ba2ba69719f5ed66924b064ed82969073da76630abe4ada106e1576a1"
)
OBJECT = f"{DIRECTORY}/object-candidates-v1.json"
OBJECT_SHA256 = (
    "ec4e1cf7bbd70f99dc0675b6e3fd47b2da9034753d4f5a1a836206c5756ed0b6"
)
OBJECT_PAYLOAD_SHA256 = (
    "43ac3f352f2b4730d20e791964d13cf9e9fe1473f38eadb9e15ad7ee7318d144"
)
DISPOSITIONS = f"{DIRECTORY}/literal-dispositions-v1.json"
DISPOSITIONS_SHA256 = (
    "433029525cfb74122f275f4282901fc6e7711b34aa7115b4bd53ef537dd5e1a1"
)
DISPOSITIONS_PAYLOAD_SHA256 = (
    "134a731f76e91218a4d0946bb9394f48db7731b164452a888dcc83cca1431fb2"
)
IDENTITY_TEMPLATE = f"{DIRECTORY}/qualification-identity-template-v1.json"
BINDING_TEMPLATE = f"{DIRECTORY}/campaign-binding-template-v1.json"
CONTRACT = f"{DIRECTORY}/campaign-contract-v1.json"
CONTRACT_SHA256 = (
    "db2faa1308d3a103a2b5fc5ebb2c26c0461fadddffc3f214cfcd23e25a8dbfc7"
)
CAMPAIGN_PLAN_IDENTITY = (
    "d39dc02c741a13adc8e0c7c3cc818ffa69e96132af89caf0fef6b5dad6d14333"
)
CAMPAIGN_ANALYZER_IDENTITY = (
    "01839636097d4727263d24cc9194954b883997fe0535452b230595885562c8db"
)
CAMPAIGN_EVIDENCE_IDENTITY = (
    "90996b64e980df84292318bb0129adf1cc6eae1b18bc962f8a707af0aee9e2fa"
)
PRIVATE_FAMILY_AUTHORIZATION_IDENTITY = (
    "e4c2a5e115e26dfbd903522171b8c350bfba11b17e98f2b82c4bc486c1fa975b"
)
PRIVATE_FAMILY_SOURCE_SHA256 = (
    "c96ade0dc836ee11bdfed8f1ded90fbb90fbf23f7f7e04cc525d2c27fe752bab"
)


class Refusal(RuntimeError):
    """A checked-in link or authority input changed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def sha256(encoded: bytes) -> str:
    return hashlib.sha256(encoded).hexdigest()


def regular(path: Path, maximum: int = 4 << 20) -> bytes:
    status = path.lstat()
    require(
        stat.S_ISREG(status.st_mode)
        and not path.is_symlink()
        and status.st_nlink == 1
        and 0 < status.st_size <= maximum,
        f"not one bounded unshared regular file: {path}",
    )
    return path.read_bytes()


def load_preparer(repo: Path) -> Any:
    path = repo / PREPARER
    source = regular(path, 2 << 20)
    require(sha256(source) == PREPARER_SHA256, "manifest preparer changed")
    specification = importlib.util.spec_from_file_location(
        "_fre_tag30_application_link_preparer", path
    )
    require(specification is not None, "cannot load manifest preparer")
    module = importlib.util.module_from_spec(specification)
    assert specification.loader is not None
    specification.loader.exec_module(module)
    return module


def main() -> None:
    require(
        len(sys.argv) == 2,
        "usage: validate_link_manifests.py REPO",
    )
    repo = Path(sys.argv[1]).resolve(strict=True)
    preparer = load_preparer(repo)
    expected_object, expected_dispositions = preparer.derive(repo)
    object_bytes = regular(repo / OBJECT)
    disposition_bytes = regular(repo / DISPOSITIONS)
    objects = json.loads(object_bytes)
    dispositions = json.loads(disposition_bytes)
    require(
        object_bytes == preparer.json_bytes(expected_object)
        and sha256(object_bytes) == OBJECT_SHA256
        and objects["payload_sha256"] == OBJECT_PAYLOAD_SHA256
        and disposition_bytes
        == preparer.json_bytes(expected_dispositions)
        and sha256(disposition_bytes) == DISPOSITIONS_SHA256
        and dispositions["payload_sha256"]
        == DISPOSITIONS_PAYLOAD_SHA256,
        "checked-in tag30 application manifests are not the exact derivation",
    )
    object_payload = objects["payload"]
    disposition_payload = dispositions["payload"]
    require(
        object_payload["backend_tag"] == 30
        and object_payload["backend_version"] == "SEARCH_V17"
        and object_payload["backend_name"] == "AsimdV17"
        and object_payload["candidate_policy"] == 15
        and object_payload["family_selector"] == 13
        and object_payload["minimum_literal_bytes"] == 6
        and object_payload["maximum_literal_bytes"] == 32
        and object_payload["minimum_window_bytes"] == 65_536
        and object_payload["portable_prefix_candidate_starts"] == 256
        and object_payload["candidate_count"] == 5
        and disposition_payload["literal_count"] == 11
        and disposition_payload["eligible_literal_count"] == 5
        and disposition_payload["ineligible_literal_count"] == 6
        and all(
            payload["production_authority"] is False
            and payload["application_qualification_authority"] is False
            and payload["campaign_plan_identity"] is None
            and payload["private_family_authorization_identity"] is None
            and payload["rebar_inputs"] == []
            and payload["benchmark_results"] == []
            for payload in (object_payload, disposition_payload)
        ),
        "result-blind manifest authority changed",
    )
    contract = json.loads(regular(repo / CONTRACT, 128 << 10))
    require(
        sha256(regular(repo / CONTRACT, 128 << 10)) == CONTRACT_SHA256
        and contract["result_blind"] is True
        and contract["production_authority"] is False
        and contract["rebar_inputs"] == []
        and contract["heldout_materialized"] is False,
        "application contract changed",
    )
    identity = json.loads(regular(repo / IDENTITY_TEMPLATE))
    require(
        identity["state"]["bindings_complete"] is False
        and identity["state"]["development_timing_permitted"] is False
        and identity["state"]["application_qualification_authority"] is False
        and identity["state"]["production_authority"] is False
        and identity["auto_routing"]["family_selector"] == 13
        and identity["auto_routing"]["plan_identity"]
        == CAMPAIGN_PLAN_IDENTITY
        and identity["auto_routing"]["analyzer_identity"]
        == CAMPAIGN_ANALYZER_IDENTITY
        and identity["auto_routing"]["evidence_identity"]
        == CAMPAIGN_EVIDENCE_IDENTITY
        and identity["auto_routing"][
            "private_family_authorization_identity"
        ]
        == PRIVATE_FAMILY_AUTHORIZATION_IDENTITY
        and identity["private_family"]["source_path"]
        == "crates/fre-aot-static-runtime/src/search_support/private_rows.rs"
        and identity["private_family"]["source_sha256"]
        == PRIVATE_FAMILY_SOURCE_SHA256
        and sha256(
            regular(
                repo
                / "crates/fre-aot-static-runtime/src/search_support/private_rows.rs",
                1 << 18,
            )
        )
        == PRIVATE_FAMILY_SOURCE_SHA256
        and identity["runner"]["source_commit"] is None
        and identity["runner"]["source_archive_sha256"] is None
        and identity["static_pipeline"]["compiler_identity"] is None
        and all(
            platform["manifest_identity"] is None
            and platform["sealed_build_receipt_sha256"] is None
            for platform in identity["platform_artifacts"].values()
        ),
        "unresolved identity template no longer fails closed",
    )
    binding = json.loads(regular(repo / BINDING_TEMPLATE))
    binding_payload = binding["payload"]
    require(
        binding["schema"]
        == "fre.aot.search-tag30-ripgrep-application-campaign-binding.v1"
        and binding["payload_sha256"]
        == hashlib.sha256(
            json.dumps(
                binding_payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
        ).hexdigest()
        and binding_payload["application_analyzer_source_sha256"]
        == sha256(
            regular(
                repo
                / f"{DIRECTORY}/analyze_qualification_results.py",
                2 << 20,
            )
        )
        and binding_payload["campaign_plan_identity"]
        == identity["auto_routing"]["plan_identity"]
        and binding_payload["campaign_analyzer_identity"]
        == identity["auto_routing"]["analyzer_identity"]
        and binding_payload["campaign_evidence_identity"]
        == CAMPAIGN_EVIDENCE_IDENTITY
        and binding_payload["private_family_authorization_identity"]
        == PRIVATE_FAMILY_AUTHORIZATION_IDENTITY
        and binding_payload["private_family_source_sha256"]
        == PRIVATE_FAMILY_SOURCE_SHA256
        and binding_payload["runner_source_commit"] is None
        and binding_payload["runner_source_sha256"]
        == identity["runner"]["source_set_sha256"]
        and binding_payload["source_archive_sha256"] is None
        and binding_payload["hosts"][1]["allowed_logical_cpus"]
        == list(range(64, 80))
        and binding_payload["timing_sealed"] is False
        and binding_payload["bindings_complete"] is False
        and binding_payload["application_qualification_authority"] is False
        and binding_payload["production_authority"] is False
        and all(
            host[field] is None
            for host in binding_payload["hosts"]
            for field in (
                "runner_binary_sha256",
                "runner_identity_sha256",
                "build_receipt_sha256",
                "manifest_identity",
                "compiler_identity",
            )
        ),
        "unresolved campaign binding template changed or no longer fails closed",
    )
    print(
        "search-tag30-application-link-manifests: PASS "
        "objects=5 refusals=6 literals=11 fixtures=154 "
        "family_selector=13 production_authority=false rebar_inputs=0"
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
        print(
            f"search-tag30-application-link-validation: {error}",
            file=sys.stderr,
        )
        raise SystemExit(1)
