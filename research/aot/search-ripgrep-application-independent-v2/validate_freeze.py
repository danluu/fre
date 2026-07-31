#!/usr/bin/env python3
"""Authenticate the Rebar-blind ripgrep application qualification freeze."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import stat
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any


SCHEMA = "fre.aot.search-ripgrep-application-freeze.v2"
PAYLOAD_SHA256 = (
    "3359ab7c620482d67d67d09903981c8b322c5268cfe0640e273de0f778192822"
)
HEX64 = frozenset("0123456789abcdef")

EXPECTED_INDEPENDENCE = {
    "source": "authenticated ripgrep application source only",
    "external_classification_inputs": [],
    "corpus_overlap_inputs": [],
    "rebar_inputs": [],
    "benchmark_result_inputs": [],
    "network_access": False,
    "timing_feedback_permitted": False,
    "result_derived_exclusions": False,
    "rebar_authority": False,
    "rebar_affects_membership": False,
    "rebar_affects_gates": False,
    "rebar_affects_promotion": False,
    "membership": "all 11 source-derived candidates and all 154 fixtures gate",
}
EXPECTED_BACKEND = {
    "architecture": "aarch64",
    "required_isa": "OS-usable ASIMD",
    "backend_tag": 29,
    "backend_version": "SEARCH_V16",
    "candidate_policy": 15,
    "policy_name": "AsimdV16",
    "aot_magic_hex": "465245413634001d",
    "llvm": False,
    "abi": "AAPCS64-SelectedEndRegisterV2",
    "output": "Span",
    "minimum_checked_window_bytes": 4093,
    "portable_prefix_candidate_starts": 256,
    "eligible_route": (
        "authoritative portable prefix then disjoint tag29 static tail"
    ),
    "ineligible_route": "full portable search",
    "construction_and_link_adoption_timed": False,
}
EXPECTED_QUALIFICATION = {
    "hosts": [
        "apple-aarch64-asimd",
        "c9g-aarch64-asimd-sve2",
    ],
    "baseline": "same compiled exact literal through full portable search",
    "candidate": (
        "ordinary production auto-route with a prelinked tag29 object when "
        "structurally eligible"
    ),
    "paired_order": "alternating",
    "repetitions": 6,
    "target_elapsed_ns_each_variant": 500000000,
    "minimum_elapsed_ns_each_variant": 400000000,
    "calibration": (
        "both variants; iteration count derived from the faster pilot"
    ),
    "completeness": (
        "154 fixtures times 2 hosts times 6 paired repetitions; no omissions, "
        "exclusions, substitutions, or reruns after inspection"
    ),
    "pair_validity": (
        "both variants in every pair must use an identical iteration count "
        "and independently reach minimum_elapsed_ns_each_variant"
    ),
    "fixture_ratio": (
        "for one fixture and host, sort the six order-paired "
        "static_auto_aot_elapsed_ns_i / portable_elapsed_ns_i ratios and "
        "compute (ratio[2]+ratio[3])/2 without pre-rounding"
    ),
    "correctness_gate": (
        "every scalar oracle must match both variants on both hosts before "
        "timing is accepted"
    ),
    "compile_disposition_gate": (
        "all 11 candidates must reproduce the frozen five tag29 object "
        "admissions and six exact structural refusals"
    ),
    "eligible_route_gate": (
        "eligible early and dense fixtures must return from the authoritative "
        "portable prefix with zero static invocation; each other eligible "
        "fixture must miss the prefix and invoke the tag29 static tail exactly "
        "once"
    ),
    "ineligible_route_gate": (
        "every ineligible fixture must use full portable search with zero "
        "static invocation"
    ),
    "eligible_route_counts": (
        "10 portable-prefix returns and 75 exact tag29 static-tail invocations "
        "per host"
    ),
    "eligible_static_tail_fixture_gate": (
        "every one of the 75 eligible fixtures that invokes the tag29 static "
        "tail must have a ratio strictly less than 0.80 on each host"
    ),
    "eligible_prefix_return_fixture_gate": (
        "every one of the 10 eligible fixtures that returns from the portable "
        "prefix without static invocation must have a ratio at most 1.05 on "
        "each host"
    ),
    "ineligible_fixture_gate": (
        "every one of the 69 ineligible fixture ratios must be at most 1.05 on "
        "each host and must report the exact full-portable fallback route"
    ),
    "candidate_and_aggregate_results": (
        "diagnostic only; no aggregate can rescue a failing fixture"
    ),
    "failed_cell_disposition": (
        "the broad tag29 family is not authorized; no candidate or fixture may "
        "be removed after results"
    ),
}


class Refusal(RuntimeError):
    """A source, fixture, selector, backend, or gate identity changed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def sha256(encoded: bytes) -> str:
    return hashlib.sha256(encoded).hexdigest()


def canonical_sha(value: Any) -> str:
    return sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
    )


def regular_file(path: Path, maximum: int = 16 * 1024 * 1024) -> bytes:
    status = path.lstat()
    require(
        stat.S_ISREG(status.st_mode)
        and not path.is_symlink()
        and 0 < status.st_size <= maximum,
        f"not one bounded regular file: {path}",
    )
    return path.read_bytes()


def exact_sha(root: Path, relative: str, expected: str) -> Path:
    require(
        len(expected) == 64 and set(expected) <= HEX64,
        f"invalid frozen digest for {relative}",
    )
    path = root / relative
    require(sha256(regular_file(path)) == expected, f"changed file: {relative}")
    return path


def run_validator(path: Path, arguments: list[Path]) -> str:
    result = subprocess.run(
        [sys.executable, str(path), *(str(argument) for argument in arguments)],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    require(
        result.returncode == 0 and not result.stderr,
        f"validator failed: {path.name}",
    )
    return result.stdout.decode("ascii").strip()


def load_selector(path: Path) -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        "_fre_tag29_application_selector", path
    )
    require(
        specification is not None and specification.loader is not None,
        "cannot load independent selector",
    )
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def main() -> None:
    require(
        len(sys.argv) == 5,
        "usage: validate_freeze.py FREEZE REPO RIPGREP_ROOT FIXTURE_ROOT",
    )
    freeze_path = Path(sys.argv[1])
    repo = Path(sys.argv[2])
    ripgrep_root = Path(sys.argv[3])
    fixture_root = Path(sys.argv[4])
    freeze = json.loads(regular_file(freeze_path))
    require(
        isinstance(freeze, dict)
        and set(freeze) == {"schema", "payload_sha256", "payload"}
        and freeze["schema"] == SCHEMA
        and freeze["payload_sha256"] == PAYLOAD_SHA256
        and canonical_sha(freeze["payload"]) == PAYLOAD_SHA256,
        "freeze envelope or payload changed",
    )
    payload = freeze["payload"]
    require(
        set(payload)
        == {
            "freeze_date",
            "freeze_boundary",
            "independence",
            "source",
            "fixtures",
            "selector",
            "backend",
            "qualification",
        }
        and payload["freeze_date"] == "2026-07-30"
        and payload["freeze_boundary"]
        == (
            "source, fixture, selector, route, and gates frozen before any "
            "result from this application campaign"
        )
        and payload["independence"] == EXPECTED_INDEPENDENCE
        and payload["backend"] == EXPECTED_BACKEND
        and payload["qualification"] == EXPECTED_QUALIFICATION,
        "independence, backend, or qualification gate changed",
    )

    source = payload["source"]
    require(
        source
        == {
            "repository": "https://github.com/BurntSushi/ripgrep",
            "commit": "f9c05a949d1a0dc8e16dee28ca9605d38611faeb",
            "tree": "ce81df4f8cad2dbfd1afb6b3ba53fd19846a5794",
            "projection_scope": (
                "lexical direct-call examples across tracked Rust source, "
                "including test and documentation contexts; not an "
                "execution-frequency distribution"
            ),
            "inventory_path": (
                "research/aot/search-ripgrep-application-independent-v2/"
                "inventory-v2.json"
            ),
            "inventory_sha256": (
                "2aec7b83cfcafbd0f8a9cab2e08941882b34d39786d26f26837c671378f1275b"
            ),
            "inventory_payload_sha256": (
                "68af2c6dd547935d3c4dd095f18958035104d153b355ff416c46c78a922b0979"
            ),
            "inventory_validator_path": (
                "research/aot/search-ripgrep-application-independent-v2/"
                "validate_inventory.py"
            ),
            "inventory_validator_sha256": (
                "ad9c2f4bd52417fde282057a6b5e25c4020e4468723587c350a63247ee59378d"
            ),
            "candidate_count": 11,
            "candidate_widths": [1, 1, 3, 5, 6, 8, 8, 8, 9, 14, 14],
        },
        "source freeze changed",
    )
    inventory_path = exact_sha(
        repo, source["inventory_path"], source["inventory_sha256"]
    )
    inventory_validator = exact_sha(
        repo,
        source["inventory_validator_path"],
        source["inventory_validator_sha256"],
    )
    inventory = json.loads(regular_file(inventory_path))
    require(
        inventory.get("payload_sha256")
        == source["inventory_payload_sha256"],
        "inventory payload receipt changed",
    )
    inventory_output = run_validator(
        inventory_validator, [inventory_path, ripgrep_root]
    )
    require(
        inventory_output
        == (
            "schema=fre.aot.search-ripgrep-application-literals.v2 "
            "payload_sha256="
            "68af2c6dd547935d3c4dd095f18958035104d153b355ff416c46c78a922b0979 "
            "candidates=11 gating-candidates=11 fixtures=154 "
            "external-classification-inputs=0"
        ),
        "inventory validator receipt changed",
    )

    fixtures = payload["fixtures"]
    require(
        set(fixtures)
        == {
            "algorithm_path",
            "algorithm_sha256",
            "materializer_path",
            "materializer_sha256",
            "validator_path",
            "validator_sha256",
            "manifest_sha256",
            "manifest_payload_sha256",
            "fixture_count",
            "fixture_bytes_each",
            "scalar_oracle",
            "alignment_realization",
            "every_fixture_gates",
        }
        and fixtures["fixture_count"] == 154
        and fixtures["fixture_bytes_each"] == 1_048_576
        and fixtures["scalar_oracle"]
        == "overlapping leftmost span and nonoverlapping count"
        and fixtures["alignment_realization"]
        == (
            "allocate fixture_bytes+63 readable bytes, fill padding with the "
            "candidate absent sentinel, choose "
            "checked_start=16+((alignment_offset-((base_address+16) mod 16)) "
            "mod 16), copy the exact logical fixture there, require "
            "checked_start pointer mod16 equals alignment_offset, and time "
            "only the exact fixture_bytes checked range"
        )
        and fixtures["every_fixture_gates"] is True,
        "fixture policy changed",
    )
    algorithm_path = exact_sha(
        repo, fixtures["algorithm_path"], fixtures["algorithm_sha256"]
    )
    exact_sha(
        repo, fixtures["materializer_path"], fixtures["materializer_sha256"]
    )
    fixture_validator = exact_sha(
        repo, fixtures["validator_path"], fixtures["validator_sha256"]
    )
    manifest_path = fixture_root / "manifest.json"
    manifest_bytes = regular_file(manifest_path)
    require(
        sha256(manifest_bytes) == fixtures["manifest_sha256"],
        "fixture manifest bytes changed",
    )
    manifest = json.loads(manifest_bytes)
    require(
        manifest.get("payload_sha256")
        == fixtures["manifest_payload_sha256"],
        "fixture manifest payload changed",
    )
    fixture_output = run_validator(
        fixture_validator,
        [inventory_path, algorithm_path, ripgrep_root, fixture_root],
    )
    require(
        fixture_output
        == (
            "manifest_sha256="
            "b20181470c604d01d2ec236259293cfcb6e5eff145bcd3e4daa91554c8cebcca "
            "payload_sha256="
            "1cbda700087f5506daa91b0657070cbf39fac68222ff84e273d1d83c09f6ebfd "
            "candidates=11 gating-candidates=11 fixtures=154 gating-fixtures=154 "
            "scalar-oracles=pass"
        ),
        "fixture validator receipt changed",
    )

    selector = payload["selector"]
    require(
        set(selector)
        == {
            "contract_path",
            "contract_sha256",
            "payload_sha256",
            "independent_implementation_path",
            "independent_implementation_sha256",
            "eligible_candidate_count",
            "eligible_fixture_count",
            "ineligible_candidate_count",
            "ineligible_fixture_count",
            "eligible",
            "ineligible",
        }
        and selector["eligible_candidate_count"] == 5
        and selector["eligible_fixture_count"] == 85
        and selector["ineligible_candidate_count"] == 6
        and selector["ineligible_fixture_count"] == 69,
        "selector classification counts changed",
    )
    contract_path = exact_sha(
        repo, selector["contract_path"], selector["contract_sha256"]
    )
    contract = json.loads(regular_file(contract_path))
    require(
        contract.get("schema") == "fre.aot.search-phase-unique-selector.v1"
        and contract.get("payload_sha256") == selector["payload_sha256"]
        and canonical_sha(contract.get("payload")) == selector["payload_sha256"],
        "selector contract changed",
    )
    selector_path = exact_sha(
        repo,
        selector["independent_implementation_path"],
        selector["independent_implementation_sha256"],
    )
    independent = load_selector(selector_path)
    candidates = inventory["payload"]["candidates"]
    manifest_by_identity = {
        candidate["semantic_candidate_sha256"]: candidate
        for candidate in manifest["payload"]["candidates"]
    }
    derived_eligible = []
    derived_ineligible = []
    eligible_fixtures = 0
    ineligible_fixtures = 0
    for candidate in candidates:
        identity = candidate["semantic_candidate_sha256"]
        literal = bytes.fromhex(candidate["literal_hex"])
        if len(literal) < 2:
            eligible, offsets = False, ()
        else:
            eligible, offsets = independent.selector_eligible(literal)
        fixture_count = len(manifest_by_identity[identity]["fixtures"])
        require(
            fixture_count == 7 + len(literal),
            "per-candidate fixture count changed",
        )
        if eligible:
            derived_eligible.append(
                {
                    "semantic_candidate_sha256": identity,
                    "literal_bytes": len(literal),
                    "selected_offsets": list(offsets),
                }
            )
            eligible_fixtures += fixture_count
        else:
            derived_ineligible.append(
                {
                    "semantic_candidate_sha256": identity,
                    "reason": (
                        "width-below-six"
                        if len(literal) < 6
                        else "cyclic-phase-signature-not-unique"
                    ),
                }
            )
            ineligible_fixtures += fixture_count
    require(
        selector["eligible"] == derived_eligible
        and selector["ineligible"] == derived_ineligible
        and eligible_fixtures == selector["eligible_fixture_count"] == 85
        and ineligible_fixtures == selector["ineligible_fixture_count"] == 69
        and eligible_fixtures + ineligible_fixtures == 154,
        "independent selector classification changed",
    )
    print(
        f"freeze_payload_sha256={PAYLOAD_SHA256} candidates=11 fixtures=154 "
        "eligible-candidates=5 eligible-fixtures=85 "
        "ineligible-candidates=6 ineligible-fixtures=69 "
        "backend=tag29 policy=15 llvm=false gates=rebar-blind"
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
        print(f"ripgrep-application-freeze: {error}", file=sys.stderr)
        raise SystemExit(1)
