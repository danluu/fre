#!/usr/bin/env python3
"""Validate the result-blind external Search-V26 heldout authority.

The validator reads only the frozen V26 rules and their exact V2 source-rule
predecessor. It never reads corpus material, a generated candidate inventory,
Rebar, a benchmark result, or the running V26 development gate.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA = "fre.aot.external-regex-1.12.4-source-rules.v3-v26"
FILE_SHA256 = "c3a8b89a251e4b6ca030f96c4393dc397d124f58e8d63c960c3d6d5078e845ea"
PAYLOAD_SHA256 = "385c9d06954007dd2dce3b32d81483fe13995f519cb66b4e444ba6ddb75d8bb7"
V2_FILE_SHA256 = "8dc78c62f3c684bff31169393bfb60818625399192ae9e124d90632d8d36891f"
SECTION_SHA256 = {
    "source": "4eb7a693d22f31069020cc87ce087e9e2fe6a2eca9be9a49b819d4000768cf02",
    "selection": "2b1a8bd9b7c076661fe2538afccab5d75e3a1c75e1a92aa1adf22579fa88c154",
    "partition": "f2879f4c3bf7bec685364ad1bee2d90f2d3997f837d45173a8c7c82e4262e5fd",
    "fixtures": "64616ba4a8d33b1280d713d3204afe2ce9b6b6c4a003888bfac7688979483f8f",
    "timing": "af8fbdbda276c05a6bba44f043d5f5f467bdc02eb81694ac9fab9d2ff3072ca3",
    "hosts": "34339e86353da5e7508a6702b6a94730727a3dfdfc67900b5f7abedcfb911c4c",
}
INHERITED_SECTIONS = ("source", "selection", "partition", "fixtures", "hosts")
PAYLOAD_KEYS = {
    "freeze_date",
    "freeze_boundary",
    "inherited_source_rules_v2_file_sha256",
    "source",
    "selection",
    "partition",
    "fixtures",
    "timing",
    "hosts",
    "section_sha256",
    "v26_development_gate",
    "v26_projection",
    "independence",
    "final_engine_requirements",
    "qualification_requirements",
}


class Refusal(RuntimeError):
    """The V26 heldout source authority is not its frozen closed form."""


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


def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def reject_float(value: str) -> Any:
    raise Refusal(f"floating-point JSON is forbidden: {value}")


def strict_json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw,
            object_pairs_hook=object_pairs,
            parse_float=reject_float,
            parse_constant=reject_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Refusal(f"{label} is not strict JSON: {error}") from error
    require(type(value) is dict, f"{label} root is not an object")
    return value


def bounded_regular_file(path: Path, label: str) -> bytes:
    status = path.lstat()
    require(
        path.is_file()
        and not path.is_symlink()
        and 0 < status.st_size <= 128 * 1024,
        f"{label} is not one bounded regular file",
    )
    return path.read_bytes()


def exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    require(type(value) is dict, f"{label} is not an object")
    require(set(value) == expected, f"{label} fields changed")
    return value


def validate_payload(payload: dict[str, Any], inherited: dict[str, Any]) -> None:
    exact_keys(payload, PAYLOAD_KEYS, "V26 payload")
    require(
        payload["freeze_date"] == "2026-07-30"
        and "before reading the V26 development result" in payload["freeze_boundary"],
        "freeze boundary changed",
    )
    require(
        payload["inherited_source_rules_v2_file_sha256"] == V2_FILE_SHA256,
        "V2 source-rule identity changed",
    )
    require(payload["section_sha256"] == SECTION_SHA256, "section identities changed")
    for section, expected_sha256 in SECTION_SHA256.items():
        require(
            sha256(canonical_bytes(payload[section])) == expected_sha256,
            f"{section} rules changed",
        )
    for section in INHERITED_SECTIONS:
        require(
            payload[section] == inherited[section],
            f"inherited {section} rules differ from V2",
        )

    timing = exact_keys(
        payload["timing"],
        {
            "repetitions",
            "target_elapsed_ns_each_variant",
            "minimum_elapsed_ns_each_variant",
            "calibration",
            "pairing",
            "workers",
            "unrelated_cpu_work",
        },
        "timing",
    )
    require(
        timing["repetitions"] == 6
        and timing["target_elapsed_ns_each_variant"] == 500_000_000
        and timing["minimum_elapsed_ns_each_variant"] == 400_000_000
        and timing["workers"] == "distinct explicit CPUs; concurrent unrelated work is allowed"
        and timing["unrelated_cpu_work"] == "never stopped or killed",
        "timing/admission contract changed",
    )

    development = exact_keys(
        payload["v26_development_gate"],
        {
            "source_commit",
            "source_tree",
            "contract_sha256",
            "cell_manifest_sha256",
            "one_shot_seal_sha256",
            "candidate_result_read_before_this_freeze",
            "required_terminal_decision_before_heldout_materialization",
        },
        "V26 development gate",
    )
    require(
        development
        == {
            "source_commit": "321089535ad6e65752cadbd36b077b0c7ebf8355",
            "source_tree": "1122b0124e6b42473001cad579ceb21773f64b35",
            "contract_sha256": "24a147e5bcda1370d5235ce3b0d6eb9276c17f4ff839abd0cde05de4d52a695d",
            "cell_manifest_sha256": "17484f6971dd1078e30e5e63bdf4cea5d56769a1db254c59cfa80e6c9d8bcddf",
            "one_shot_seal_sha256": "6f84f479a7d193c4a9585a6ab79fb928bcd848f05a3ef60281ed1a8e4960bc3c",
            "candidate_result_read_before_this_freeze": False,
            "required_terminal_decision_before_heldout_materialization": "PASS",
        },
        "V26 development authority changed",
    )

    projection = exact_keys(
        payload["v26_projection"],
        {
            "operation",
            "candidate_literal_widths",
            "portable_control_literal_widths",
            "candidate_output",
            "candidate_scenarios",
            "membership",
            "empty_candidate_class",
            "minimum_independent_candidate_patterns",
            "minimum_independent_widths",
            "minimum_width_bands",
            "width_bands",
            "rebar_or_benchmark_membership_input",
        },
        "V26 projection",
    )
    require(
        projection["operation"] == "leftmost-span-search"
        and projection["candidate_literal_widths"] == "9..32"
        and projection["portable_control_literal_widths"] == "1..8"
        and projection["candidate_output"] == "Span"
        and projection["membership"]
        == "every heldout representative and every scenario; no result-derived exclusions"
        and projection["empty_candidate_class"] == "terminal failure"
        and projection["minimum_independent_candidate_patterns"] == 3
        and projection["minimum_independent_widths"] == 3
        and projection["minimum_width_bands"] == 2
        and projection["width_bands"] == ["9..16", "17..24", "25..32"]
        and projection["rebar_or_benchmark_membership_input"] is False,
        "V26 source-only projection changed",
    )
    require(
        projection["candidate_scenarios"]
        == [
            "absent",
            "early",
            "middle",
            "tail",
            "dense",
            "wrong-final-dense",
            "wrong-first-dense",
        ],
        "V26 scenario lattice changed",
    )

    independence = payload["independence"]
    require(
        independence["heldout_source_materialized"] is False
        and independence["network"] is False
        and independence["timing_feedback_permitted"] is False
        and independence["result_derived_selection"] is False
        and independence["result_derived_exclusions"] is False
        and independence["rebar_inputs"] == []
        and independence["benchmark_result_inputs"] == []
        and independence["rebar_affects_membership"] is False
        and independence["rebar_affects_gates"] is False
        and independence["rebar_affects_promotion"] is False,
        "independence boundary changed",
    )

    engine = payload["final_engine_requirements"]
    require(
        engine["backend_tag"] == 39
        and engine["backend_version"] == "SEARCH_V26"
        and engine["candidate_policy"] == 16
        and engine["backend_name"] == "AsimdV26"
        and engine["aot_magic_hex"] == "4652454136340027"
        and engine["llvm"] is False
        and engine["output"] == "Span"
        and engine["candidate_minimum_literal_bytes"] == 9
        and engine["candidate_maximum_literal_bytes"] == 32
        and engine["minimum_checked_window_bytes"] == 65_536
        and engine["portable_prefix_candidate_starts"] == 256
        and engine["construction_link_adoption_timed"] is False
        and engine["final_source_and_static_runner_frozen_before_heldout_materialization"]
        is True,
        "final V26 engine boundary changed",
    )

    qualification = payload["qualification_requirements"]
    require(
        qualification["development_gate_must_pass_before_heldout_materialization"]
        is True
        and qualification["heldout_materialization_runs"] == 1
        and qualification["per_host_candidate_over_portable_equal_cell_geomean_ppm_lte"]
        == 800_000
        and qualification["per_host_each_width_band_geomean_ppm_lte"] == 850_000
        and qualification["per_host_each_scenario_geomean_ppm_lte"] == 1_030_000
        and qualification["per_host_p95_cell_ratio_ppm_lte"] == 1_050_000
        and qualification["per_host_maximum_cell_ratio_ppm_lte"] == 1_100_000
        and qualification["per_host_cells_strictly_over_1_05_fraction_ppm_lte"]
        == 10_000
        and qualification["portable_control_class_geomean_ppm_lte"] == 1_050_000
        and qualification["aggregate_rescue_for_failed_host_band_or_scenario"] is False,
        "heldout acceptance gates changed",
    )


def validate(path: Path) -> dict[str, Any]:
    raw = bounded_regular_file(path, "V26 source rules")
    require(sha256(raw) == FILE_SHA256, "V26 source-rule file bytes changed")
    root = exact_keys(
        strict_json(raw, "V26 source rules"),
        {"schema", "payload_sha256", "payload"},
        "V26 source-rule envelope",
    )
    require(root["schema"] == SCHEMA, "V26 source-rule schema changed")
    require(
        root["payload_sha256"] == PAYLOAD_SHA256
        and sha256(canonical_bytes(root["payload"])) == PAYLOAD_SHA256,
        "V26 payload identity changed",
    )

    v2_path = path.with_name("preregistration-source-rules-v2.json")
    v2_raw = bounded_regular_file(v2_path, "V2 source rules")
    require(sha256(v2_raw) == V2_FILE_SHA256, "V2 source-rule bytes changed")
    v2 = strict_json(v2_raw, "V2 source rules")
    require(type(v2.get("payload")) is dict, "V2 payload is absent")
    validate_payload(root["payload"], v2["payload"])
    return {
        "schema": SCHEMA,
        "file_sha256": FILE_SHA256,
        "payload_sha256": PAYLOAD_SHA256,
        "development_result_read_before_freeze": False,
        "heldout_source_materialized": False,
        "rebar_accepted_as_input": False,
        "benchmark_results_accepted_as_input": False,
        "candidate_literal_widths": "9..32",
        "production_window_floor": 65_536,
    }


def main() -> None:
    require(len(sys.argv) <= 2, "usage: validator [source-rules-v3-v26.json]")
    path = (
        Path(sys.argv[1])
        if len(sys.argv) == 2
        else Path(__file__).resolve().with_name(
            "preregistration-source-rules-v3-v26.json"
        )
    )
    print(json.dumps(validate(path), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, Refusal) as error:
        print(f"external-regex-source-rules-v3-v26: {error}", file=sys.stderr)
        raise SystemExit(1)
