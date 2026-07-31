#!/usr/bin/env python3
"""Validate the frozen external static-runner identity and timing seal."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA_V1 = "fre.aot.external-regex-1.12.4-static-runner-identity.v1"
SCHEMA_V2 = "fre.aot.external-regex-1.12.4-static-runner-identity.v2"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
EXTERNAL_COMMIT = "93c24d3b2618597c3336457ee570cbe00cc33bd3"
EMITTER_COMMIT = "1632949174b6a1f95981e0f68133217a267a4f8e"
FIXTURE_MANIFEST = "b979ed327db7e9623bccba1ef775d1957b7323c8b30edb44f40593176f52b44a"


class Refusal(RuntimeError):
    pass


def refuse(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    refuse(set(value) == expected, f"{label}: fields changed")


def require_object(value: Any, label: str) -> dict[str, Any]:
    refuse(isinstance(value, dict), f"{label}: not an object")
    return value


def require_sha(value: Any, label: str) -> None:
    refuse(isinstance(value, str) and HEX64.fullmatch(value) is not None, label)


def require_optional_sha(value: Any, label: str) -> None:
    if value is not None:
        require_sha(value, label)


def require_optional_commit(value: Any, label: str) -> None:
    if value is not None:
        refuse(isinstance(value, str) and HEX40.fullmatch(value) is not None, label)


def require_optional_text(value: Any, label: str) -> None:
    if value is not None:
        refuse(
            isinstance(value, str)
            and 0 < len(value) <= 256
            and all(0x20 <= ord(character) <= 0x7E for character in value),
            label,
        )


def pending_paths(value: Any, prefix: str = "") -> list[str]:
    if value is None:
        if prefix == "state.blocker":
            return []
        return [prefix]
    if isinstance(value, dict):
        paths = []
        for key in sorted(value):
            path = f"{prefix}.{key}" if prefix else key
            paths.extend(pending_paths(value[key], path))
        return paths
    if isinstance(value, list):
        paths = []
        for index, item in enumerate(value):
            paths.extend(pending_paths(item, f"{prefix}[{index}]"))
        return paths
    return []


def validate(value: dict[str, Any]) -> list[str]:
    schema = value.get("schema")
    refuse(schema in {SCHEMA_V1, SCHEMA_V2}, "identity schema changed")
    expected_keys = {
        "schema",
        "external_evidence",
        "emitter",
        "static_pipeline",
        "auto_routing",
        "static_facade",
        "platform_artifacts",
        "runner",
        "state",
    }
    if schema == SCHEMA_V2:
        expected_keys.add("object_candidates")
    exact_keys(
        value,
        expected_keys,
        "identity",
    )
    external = require_object(value["external_evidence"], "external evidence")
    exact_keys(
        external,
        {
            "source_commit",
            "development_inventory_sha256",
            "contamination_index_sha256",
            "fixture_algorithm_sha256",
            "fixture_manifest_sha256",
            "candidate_count",
            "fixture_count",
            "rebar_overlap_disposition",
        },
        "external evidence",
    )
    refuse(external.get("source_commit") == EXTERNAL_COMMIT, "external boundary changed")
    refuse(
        external.get("fixture_manifest_sha256") == FIXTURE_MANIFEST,
        "fixture manifest changed",
    )
    refuse(
        external.get("candidate_count") == 4
        and external.get("fixture_count") == 28
        and external.get("rebar_overlap_disposition") == "corroboration-only",
        "external evidence scope changed",
    )
    for field in (
        "development_inventory_sha256",
        "contamination_index_sha256",
        "fixture_algorithm_sha256",
        "fixture_manifest_sha256",
    ):
        require_sha(external.get(field), f"external evidence {field} is invalid")
    if schema == SCHEMA_V2:
        object_candidates = require_object(
            value["object_candidates"], "object candidates"
        )
        exact_keys(
            object_candidates,
            {
                "manifest_schema",
                "manifest_sha256",
                "candidate_count",
                "source_construction",
            },
            "object candidates",
        )
        refuse(
            object_candidates["source_construction"]
            == "canonical-byte-escaped-exact",
            "object candidate source construction changed",
        )
        require_optional_text(
            object_candidates["manifest_schema"],
            "object candidate manifest schema is invalid",
        )
        require_optional_sha(
            object_candidates["manifest_sha256"],
            "object candidate manifest SHA-256 is invalid",
        )
        if object_candidates["candidate_count"] is not None:
            refuse(
                isinstance(object_candidates["candidate_count"], int)
                and not isinstance(object_candidates["candidate_count"], bool)
                and 0 < object_candidates["candidate_count"] <= 1024,
                "object candidate count is invalid",
            )

    emitter = require_object(value["emitter"], "emitter")
    if schema == SCHEMA_V1:
        refuse(
            emitter
            == {
                "source_commit": EMITTER_COMMIT,
                "backend": "AsimdV10",
                "backend_tag": 23,
                "aot_magic_hex": "4652454136340017",
                "candidate_policy": 10,
                "authorization": False,
                "llvm": False,
            },
            "emitter identity changed",
        )
    else:
        exact_keys(
            emitter,
            {
                "source_commit",
                "backend",
                "backend_tag",
                "aot_magic_hex",
                "candidate_policy",
                "authorization",
                "llvm",
            },
            "emitter",
        )
        refuse(
            emitter["authorization"] is False and emitter["llvm"] is False,
            "emitter granted authority or LLVM",
        )
        require_optional_commit(emitter["source_commit"], "emitter commit is invalid")
        require_optional_text(emitter["backend"], "emitter backend is invalid")
        if emitter["backend_tag"] is not None:
            refuse(
                isinstance(emitter["backend_tag"], int)
                and not isinstance(emitter["backend_tag"], bool)
                and 0 < emitter["backend_tag"] <= 0xFFFF,
                "emitter backend tag is invalid",
            )
        if emitter["aot_magic_hex"] is not None:
            refuse(
                isinstance(emitter["aot_magic_hex"], str)
                and re.fullmatch(r"[0-9a-f]{16}", emitter["aot_magic_hex"])
                is not None,
                "emitter magic is invalid",
            )
        if emitter["candidate_policy"] is not None:
            refuse(
                isinstance(emitter["candidate_policy"], int)
                and not isinstance(emitter["candidate_policy"], bool)
                and 0 < emitter["candidate_policy"] <= 0xFFFF,
                "emitter candidate policy is invalid",
            )
    static = require_object(value["static_pipeline"], "static pipeline")
    exact_keys(
        static,
        {
            "source_commit",
            "backend_name",
            "backend_tag",
            "object_contract_schema",
            "compiler_identity",
            "object_formats",
            "link_interface_schema",
        },
        "static pipeline",
    )
    refuse(
        static.get("object_formats") == ["macho-aarch64", "elf-aarch64"],
        "static object-format matrix changed",
    )
    require_optional_text(static["backend_name"], "static backend name is invalid")
    if static["backend_tag"] is not None:
        refuse(
            isinstance(static["backend_tag"], int)
            and not isinstance(static["backend_tag"], bool)
            and 0 < static["backend_tag"] <= 0xFFFF,
            "static backend tag is invalid",
        )
    require_optional_commit(static["source_commit"], "static pipeline commit is invalid")
    require_optional_text(
        static["object_contract_schema"], "object contract schema is invalid"
    )
    require_optional_sha(static["compiler_identity"], "compiler identity is invalid")
    require_optional_text(
        static["link_interface_schema"], "link interface schema is invalid"
    )
    if schema == SCHEMA_V2 and emitter["backend_tag"] is not None:
        refuse(
            emitter["backend"] == static["backend_name"]
            and emitter["backend_tag"] == static["backend_tag"],
            "emitter and static backend identities differ",
        )
    routing = require_object(value["auto_routing"], "auto routing")
    exact_keys(
        routing,
        {
            "source_commit",
            "policy_identity",
            "plan_identity",
            "analyzer_identity",
            "evidence_identity",
            "family_selector",
            "minimum_literal_bytes",
            "maximum_literal_bytes",
            "minimum_window_bytes",
            "portable_prefix_candidate_starts",
            "full_window_preflight_authoritative",
        },
        "auto routing",
    )
    require_optional_commit(routing["source_commit"], "routing commit is invalid")
    for field in (
        "policy_identity",
        "plan_identity",
        "analyzer_identity",
        "evidence_identity",
    ):
        require_optional_sha(routing[field], f"routing {field} is invalid")
    if routing["family_selector"] is not None:
        refuse(
            isinstance(routing["family_selector"], int)
            and not isinstance(routing["family_selector"], bool)
            and 0 <= routing["family_selector"] <= 0xFFFF,
            "routing family selector is invalid",
        )
    for field in (
        "minimum_literal_bytes",
        "maximum_literal_bytes",
        "minimum_window_bytes",
        "portable_prefix_candidate_starts",
    ):
        if routing[field] is not None:
            refuse(
                isinstance(routing[field], int) and routing[field] > 0,
                f"routing {field} is invalid",
            )
    if routing["full_window_preflight_authoritative"] is not None:
        refuse(
            routing["full_window_preflight_authoritative"] is True,
            "full-window preflight is not authoritative",
        )
    facade = require_object(value["static_facade"], "static facade")
    exact_keys(
        facade,
        {
            "source_commit",
            "source_set_sha256",
            "abi",
            "output",
            "jit_publication",
            "construction_in_steady_timing",
            "link_adoption_in_steady_timing",
        },
        "static facade",
    )
    refuse(
        facade.get("output") == "Span"
        and facade.get("jit_publication") is False
        and facade.get("construction_in_steady_timing") is False
        and facade.get("link_adoption_in_steady_timing") is False,
        "static facade timing boundary changed",
    )
    require_optional_commit(facade["source_commit"], "facade commit is invalid")
    require_optional_sha(facade["source_set_sha256"], "facade source-set SHA-256 is invalid")
    require_optional_text(facade["abi"], "facade ABI is invalid")
    platforms = require_object(value["platform_artifacts"], "platform artifacts")
    exact_keys(platforms, {"macos_aarch64", "linux_aarch64"}, "platform artifacts")
    for platform, raw in platforms.items():
        exact_keys(
            require_object(raw, platform),
            {
                "manifest_identity",
                "object_sha256",
                "linked_image_sha256",
                "symbol_receipt_sha256",
                "facade_receipt_sha256",
            },
            platform,
        )
        for field, identity in raw.items():
            require_optional_sha(
                identity, f"{platform} artifact {field} SHA-256 is invalid"
            )
    runner = require_object(value["runner"], "runner")
    exact_keys(
        runner,
        {
            "source_commit",
            "source_set_sha256",
            "compiler_family",
            "fixture_oracle",
            "paired_order",
            "repetitions",
            "target_elapsed_ns",
            "minimum_elapsed_ns",
            "calibrate_both_variants",
        },
        "runner",
    )
    refuse(
        runner.get("repetitions") == 6
        and runner.get("target_elapsed_ns") == 500_000_000
        and runner.get("minimum_elapsed_ns") == 400_000_000
        and runner.get("calibrate_both_variants") is True
        and runner.get("paired_order") == "alternating",
        "runner timing contract changed",
    )
    require_optional_commit(runner["source_commit"], "runner commit is invalid")
    require_optional_sha(runner["source_set_sha256"], "runner source-set SHA-256 is invalid")
    require_optional_text(runner["compiler_family"], "runner compiler family is invalid")
    state = require_object(value["state"], "state")
    exact_keys(
        state,
        {
            "heldout_materialized",
            "development_timing_permitted",
            "blocker",
        },
        "state",
    )
    refuse(state.get("heldout_materialized") is False, "heldout was materialized")
    refuse(
        isinstance(state.get("development_timing_permitted"), bool),
        "development timing state is invalid",
    )
    if state.get("blocker") is not None:
        require_optional_text(state["blocker"], "state blocker is invalid")
    return pending_paths(value)


def main() -> None:
    refuse(len(sys.argv) == 3, "usage: status|require-development-timing IDENTITY")
    mode = sys.argv[1]
    refuse(mode in {"status", "require-development-timing"}, "unknown validation mode")
    path = Path(sys.argv[2])
    refuse(not path.is_symlink() and path.is_file(), "identity is not a regular file")
    value = json.loads(path.read_bytes())
    refuse(isinstance(value, dict), "identity root is not an object")
    pending = validate(value)
    state = value["state"]
    if mode == "require-development-timing":
        refuse(not pending, "identity contains unresolved fields: " + ", ".join(pending))
        refuse(
            state.get("development_timing_permitted") is True
            and state.get("blocker") is None,
            "development timing is not sealed",
        )
        print("development_timing_permitted=true")
    else:
        print(f"development_timing_permitted={state['development_timing_permitted']}")
        print(f"heldout_materialized={state['heldout_materialized']}")
        print(f"unresolved_fields={len(pending)}")
        for item in pending:
            print(f"pending={item}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, Refusal, ValueError, json.JSONDecodeError) as error:
        print(f"static-runner-identity: {error}", file=sys.stderr)
        raise SystemExit(1)
