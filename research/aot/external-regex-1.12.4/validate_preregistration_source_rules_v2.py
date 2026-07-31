#!/usr/bin/env python3
"""Validate the result-blind external-regex source-rule authority.

This validator deliberately reads one file only: the v2 source-rule freeze
passed on the command line (or its sibling default).  It does not inspect the
superseded preregistration, any corpus bytes, or any benchmark result.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA = "fre.aot.external-regex-1.12.4-source-rules.v2"
FILE_SHA256 = "8dc78c62f3c684bff31169393bfb60818625399192ae9e124d90632d8d36891f"
PAYLOAD_SHA256 = "d0b919436165d44d9426a8fb91055a2ec70e8a2f0eb0f2041604ef91af51bc06"
SECTION_SHA256 = {
    "source": "4eb7a693d22f31069020cc87ce087e9e2fe6a2eca9be9a49b819d4000768cf02",
    "selection": "2b1a8bd9b7c076661fe2538afccab5d75e3a1c75e1a92aa1adf22579fa88c154",
    "partition": "f2879f4c3bf7bec685364ad1bee2d90f2d3997f837d45173a8c7c82e4262e5fd",
    "fixtures": "64616ba4a8d33b1280d713d3204afe2ce9b6b6c4a003888bfac7688979483f8f",
    "timing": "fba2e06d860a9726ff5b9da399f5f6676537a4dc16b2250a936f66cd6eaa2f2d",
    "hosts": "34339e86353da5e7508a6702b6a94730727a3dfdfc67900b5f7abedcfb911c4c",
}


class Refusal(RuntimeError):
    """The source-rule authority is no longer the frozen byte sequence."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def bounded_regular_file(path: Path) -> bytes:
    status = path.lstat()
    require(
        path.is_file()
        and not path.is_symlink()
        and 0 < status.st_size <= 128 * 1024,
        "source-rule authority is not one bounded regular file",
    )
    return path.read_bytes()


def validate(path: Path) -> dict[str, Any]:
    raw = bounded_regular_file(path)
    require(sha256(raw) == FILE_SHA256, "source-rule file bytes changed")
    root = json.loads(raw)
    require(
        isinstance(root, dict)
        and set(root) == {"schema", "payload_sha256", "payload"}
        and root["schema"] == SCHEMA,
        "source-rule envelope changed",
    )
    payload = root["payload"]
    require(
        isinstance(payload, dict)
        and set(payload)
        == {
            "freeze_date",
            "freeze_boundary",
            "source",
            "selection",
            "partition",
            "fixtures",
            "timing",
            "hosts",
            "preserved_section_sha256",
            "independence",
            "final_engine_requirements",
            "qualification_requirements",
        },
        "source-rule payload fields changed",
    )
    require(
        root["payload_sha256"] == PAYLOAD_SHA256
        and sha256(canonical_bytes(payload)) == PAYLOAD_SHA256,
        "source-rule payload identity changed",
    )
    require(
        payload["preserved_section_sha256"] == SECTION_SHA256,
        "preserved source-rule identities changed",
    )
    for section, expected in SECTION_SHA256.items():
        require(
            sha256(canonical_bytes(payload[section])) == expected,
            f"preserved {section} rules changed",
        )

    independence = payload["independence"]
    require(
        independence
        == {
            "only_corpus_source": (
                "authenticated published regex 1.12.4 rust-regex-suite"
            ),
            "external_classification_inputs": [],
            "corpus_overlap_inputs": [],
            "rebar_inputs": [],
            "benchmark_result_inputs": [],
            "network": False,
            "timing_feedback_permitted": False,
            "result_derived_selection": False,
            "result_derived_exclusions": False,
            "rebar_affects_membership": False,
            "rebar_affects_gates": False,
            "rebar_affects_promotion": False,
            "gate_membership": (
                "every admitted deduplicated representative in both partitions"
            ),
            "heldout_source_materialized": False,
        },
        "source/result/Rebar independence boundary changed",
    )
    engine = payload["final_engine_requirements"]
    require(
        engine
        == {
            "architecture": "aarch64",
            "required_isa": "OS-usable ASIMD",
            "backend_tag": 29,
            "backend_version": "SEARCH_V16",
            "candidate_policy": 15,
            "backend_name": "AsimdV16",
            "aot_magic_hex": "465245413634001d",
            "llvm": False,
            "abi": "AAPCS64-SelectedEndRegisterV2",
            "minimum_checked_window_bytes": 4093,
            "portable_prefix_candidate_starts": 256,
            "eligible_route": (
                "authoritative portable prefix then disjoint tag29 static tail"
            ),
            "ineligible_route": "full portable search",
            "construction_link_adoption_timed": False,
        },
        "final engine boundary changed",
    )
    qualification = payload["qualification_requirements"]
    require(
        qualification["development_and_application_must_pass_before_heldout_materialization"]
        is True
        and qualification["aggregate_rescue_permitted"] is False
        and qualification["heldout_each_static_tail_case_gate"]
        == (
            "six-pair median candidate/portable ratio strictly less than 4/5 "
            "on each host"
        )
        and qualification["heldout_each_prefix_or_fallback_case_gate"]
        == (
            "six-pair median candidate/portable ratio at most 21/20 on each host"
        ),
        "qualification gate changed",
    )
    return {
        "schema": SCHEMA,
        "file_sha256": FILE_SHA256,
        "payload_sha256": PAYLOAD_SHA256,
        "heldout_source_materialized": False,
        "rebar_accepted_as_input": False,
        "benchmark_results_accepted_as_input": False,
    }


def main() -> None:
    require(len(sys.argv) <= 2, "usage: validator [source-rules-v2.json]")
    path = (
        Path(sys.argv[1])
        if len(sys.argv) == 2
        else Path(__file__).resolve().with_name(
            "preregistration-source-rules-v2.json"
        )
    )
    print(json.dumps(validate(path), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, Refusal) as error:
        print(f"external-regex-source-rules-v2: {error}", file=sys.stderr)
        raise SystemExit(1)
