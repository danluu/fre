#!/usr/bin/env python3
"""Authenticate the frozen phase-unique successor selector contract."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA = "fre.aot.search-phase-unique-selector.v1"
PAYLOAD_SHA256 = "b0241b15760f441e7f4eb410611ce1a83b1a17f4858da91ce7eacba4f5a75353"


class Refusal(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def canonical_sha(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def main() -> None:
    require(len(sys.argv) == 2, "usage: validate_contract.py CONTRACT")
    path = Path(sys.argv[1])
    status = path.lstat()
    require(
        not path.is_symlink() and path.is_file() and 0 < status.st_size <= 64 * 1024,
        "contract is not a bounded regular file",
    )
    contract = json.loads(path.read_bytes())
    require(
        isinstance(contract, dict)
        and set(contract) == {"schema", "payload_sha256", "payload"},
        "contract envelope changed",
    )
    require(contract["schema"] == SCHEMA, "schema changed")
    require(contract["payload_sha256"] == PAYLOAD_SHA256, "pinned payload changed")
    payload = contract["payload"]
    require(canonical_sha(payload) == PAYLOAD_SHA256, "canonical payload hash changed")
    require(
        set(payload)
        == {
            "freeze_date",
            "feedback_boundary",
            "candidate_identity",
            "admission",
            "runtime_graph",
            "production_route",
            "qualification",
        },
        "payload fields changed",
    )
    feedback = payload["feedback_boundary"]
    require(
        feedback["rebar_feedback_permitted"] is False
        and feedback["observed_before_freeze"]
        == ["targeted repeated/periodic/binary/entropy smokes at widths 16 and 32"]
        and "Rebar corroboration timing" in feedback["not_observed_before_freeze"],
        "feedback boundary changed",
    )
    identity = payload["candidate_identity"]
    require(
        identity
        == {
            "backend_tag": "new-successor-required",
            "candidate_policy": "new-successor-required",
            "selector_version": 1,
            "llvm_codegen": False,
        },
        "candidate identity boundary changed",
    )
    admission = payload["admission"]
    require(
        admission["literal_width_min"] == 6
        and admission["literal_width_max"] == 32
        and admission["unselected_column_required"] is True
        and admission["timing_or_corpus_inputs"] is False
        and admission["predicate"]
        == "for every s, at least one selected offset o has literal[o] != literal[(o+s) mod literal_width]",
        "phase-unique admission changed",
    )
    graph = payload["runtime_graph"]
    require(
        graph["relearn"] is False
        and graph["disable"]
        == "first six-column survivor permanently enters frozen V13 adaptive recovery for the invocation",
        "one-way runtime graph changed",
    )
    route = payload["production_route"]
    require(
        route["ineligible"] == "full portable search; no V13 production route"
        and route["minimum_checked_window_bytes"] == 4093
        and route["construction_and_publication_timed"] is False,
        "production route changed",
    )
    qualification = payload["qualification"]
    require(
        qualification["rebar"] == "post-freeze corroboration only"
        and qualification["result_derived_exclusions"] is False
        and qualification["required_eligible_width_bands"]
        == ["6..=7", "8..=15", "16..=23", "24..=32"],
        "qualification boundary changed",
    )
    print(f"schema={SCHEMA}")
    print(f"payload_sha256={PAYLOAD_SHA256}")
    print("selector=cyclic-five-column-phase-unique width=6..32")
    print("rebar_feedback=false successor_timing=false authentication=pass")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, Refusal) as error:
        print(f"phase-unique-selector-contract: {error}", file=sys.stderr)
        raise SystemExit(1)
