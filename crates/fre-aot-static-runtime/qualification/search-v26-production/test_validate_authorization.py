#!/usr/bin/env python3
"""Adversarial tests for the inert V26 production input validator."""

from __future__ import annotations

import copy
import json
import os
import tempfile
import unittest
from pathlib import Path

import validate_authorization as validator


def identity(value: int, digits: int = 64) -> str:
    return f"{value:0{digits}x}"


def reviewed_authorization() -> dict[str, object]:
    return {
        "schema": validator.AUTH_SCHEMA,
        "state": "reviewed-production-authorization",
        "production_authority": True,
        "predecessor": {
            "v25_terminal_decision": "FAIL",
            "v25_terminal_analysis_sha256": identity(1),
        },
        "source": {
            "commit": identity(2, 40),
            "tree": identity(3, 40),
        },
        "compiler_architecture": {
            "backend_tag": 39,
            "image_magic": 0x27,
            "regex_codegen": "self-contained-fre-aarch64-search-v26",
            "regex_codegen_uses_llvm": False,
            "architecture_review_sha256": identity(4),
        },
        "qualification": {
            "campaign_is_fresh_and_disjoint_from_v25": True,
            "campaign_contract_sha256": identity(5),
            "development_decision": "PASS",
            "development_pass_sha256": identity(6),
            "correctness_decision": "PASS",
            "two_host_correctness_gate_sha256": identity(7),
            "heldout_decision": "PASS",
            "heldout_pass_sha256": identity(8),
            "heldout_analysis_sha256": identity(9),
        },
        "review": {
            "production_review_sha256": identity(10),
            "authorization_sha256": identity(11),
            "source_inventory_review_sha256": identity(12),
        },
        "routing": {
            "candidate_minimum_literal_bytes": 6,
            "portable_max_literal_bytes": 8,
            "production_minimum_literal_bytes": 9,
            "maximum_literal_bytes": 32,
            "short_width_route": "existing-non-v26",
            "short_width_production_authority": False,
        },
        "family": {
            "selector": 23,
            "minimum_window_bytes": 4093,
            "portable_prefix_candidate_starts": 256,
            "plan_identity": identity(13),
            "analyzer_identity": identity(14),
            "evidence_identity": identity(15),
        },
        "targets": {
            "macos_aarch64": {
                "manifest_identity": identity(16),
                "build_receipt_sha256": identity(17),
                "final_image_review_sha256": identity(18),
            },
            "linux_aarch64": {
                "manifest_identity": identity(19),
                "build_receipt_sha256": identity(20),
                "final_image_review_sha256": identity(21),
            },
        },
    }


def target_record(
    base: int, manifest_identity: str
) -> dict[str, str]:
    values: dict[str, str] = {}
    cursor = base
    for field in validator.TARGET_SOURCE_FIELDS:
        if field == "manifest_identity":
            values[field] = manifest_identity
        elif field == "identity_suffixed_glue_symbol":
            values[field] = (
                validator.GLUE_PREFIX + values["compile_identity"]
            )
        else:
            values[field] = identity(cursor)
            cursor += 1
    return values


def reviewed_inventory(
    authorization: dict[str, object],
) -> dict[str, object]:
    targets = authorization["targets"]
    assert isinstance(targets, dict)
    macos = targets["macos_aarch64"]
    linux = targets["linux_aarch64"]
    assert isinstance(macos, dict)
    assert isinstance(linux, dict)
    return {
        "schema": validator.INVENTORY_SCHEMA,
        "state": "reviewed-production-source-inventory",
        "production_authority": True,
        "authorization_decision_sha256": authorization["review"][
            "authorization_sha256"
        ],
        "backend_tag": 39,
        "minimum_literal_bytes": 9,
        "maximum_literal_bytes": 32,
        "family_selector": authorization["family"]["selector"],
        "canonical_order": "semantic_binding_identity_then_source_sha256",
        "sources": [
            {
                "source_sha256": identity(100),
                "semantic_binding_identity": identity(99),
                "literal_bytes": 9,
                "literal_sha256": identity(101),
                "tag39_shape_admission_receipt_sha256": identity(102),
                "targets": {
                    "macos_aarch64": target_record(
                        200, macos["manifest_identity"]
                    ),
                    "linux_aarch64": target_record(
                        400, linux["manifest_identity"]
                    ),
                },
                "cross_target_equalities": [],
            }
        ],
        "each_source_common_requires": list(validator.SOURCE_COMMON_FIELDS),
        "each_source_target_requires": {
            target: list(validator.TARGET_SOURCE_FIELDS)
            for target in validator.TARGET_KEYS
        },
        "cross_target_equalities_require_explicit_derivation_receipt": True,
    }


def encoded(value: object) -> bytes:
    return (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode()


class AuthorizationTests(unittest.TestCase):
    def test_checked_in_template_is_inert_and_exact(self) -> None:
        path = Path(__file__).with_name("authorization-v1.json.template")
        validator.parse_template_bytes(path.read_bytes(), str(path))

    def test_complete_reviewed_authorization_and_inventory_are_accepted(self) -> None:
        authorization = reviewed_authorization()
        parsed = validator.parse_reviewed_authorization_bytes(encoded(authorization))
        inventory = reviewed_inventory(authorization)
        validator.parse_reviewed_inventory_bytes(encoded(inventory), parsed)

    def test_every_frozen_policy_boundary_fails_closed(self) -> None:
        mutations = [
            ("production_authority", False),
            ("predecessor.v25_terminal_decision", "PASS"),
            ("compiler_architecture.backend_tag", 38),
            ("compiler_architecture.image_magic", 0x26),
            ("compiler_architecture.regex_codegen_uses_llvm", True),
            (
                "qualification.campaign_is_fresh_and_disjoint_from_v25",
                False,
            ),
            ("qualification.development_decision", "FAIL"),
            ("qualification.correctness_decision", "FAIL"),
            ("qualification.heldout_decision", "FAIL"),
            ("routing.candidate_minimum_literal_bytes", 7),
            ("routing.portable_max_literal_bytes", 9),
            ("routing.production_minimum_literal_bytes", 8),
            ("routing.maximum_literal_bytes", 31),
            ("routing.short_width_route", "tag30"),
            ("routing.short_width_production_authority", True),
        ]
        for dotted, replacement in mutations:
            with self.subTest(field=dotted):
                authorization = reviewed_authorization()
                target: dict[str, object] = authorization
                parts = dotted.split(".")
                for part in parts[:-1]:
                    child = target[part]
                    assert isinstance(child, dict)
                    target = child
                target[parts[-1]] = replacement
                with self.assertRaises(validator.Refusal):
                    validator.parse_reviewed_authorization_bytes(encoded(authorization))

    def test_malformed_zero_duplicate_and_cross_target_claims_are_refused(self) -> None:
        authorization = reviewed_authorization()
        authorization["review"]["authorization_sha256"] = validator.ZERO32
        with self.assertRaises(validator.Refusal):
            validator.parse_reviewed_authorization_bytes(encoded(authorization))

        with self.assertRaises(validator.Refusal):
            validator._load_json(b'{"field":1,"field":2}', "duplicate", 1024)

        authorization = reviewed_authorization()
        authorization["targets"]["linux_aarch64"]["manifest_identity"] = (
            authorization["targets"]["macos_aarch64"]["manifest_identity"]
        )
        with self.assertRaises(validator.Refusal):
            validator.parse_reviewed_authorization_bytes(encoded(authorization))

    def test_inventory_short_width_wrong_symbol_and_order_are_refused(self) -> None:
        authorization = reviewed_authorization()
        parsed = validator.parse_reviewed_authorization_bytes(encoded(authorization))

        inventory = reviewed_inventory(authorization)
        inventory["sources"][0]["literal_bytes"] = 8
        with self.assertRaises(validator.Refusal):
            validator.parse_reviewed_inventory_bytes(encoded(inventory), parsed)

        inventory = reviewed_inventory(authorization)
        inventory["sources"][0]["targets"]["linux_aarch64"][
            "identity_suffixed_glue_symbol"
        ] = validator.GLUE_PREFIX + identity(999)
        with self.assertRaises(validator.Refusal):
            validator.parse_reviewed_inventory_bytes(encoded(inventory), parsed)

        inventory = reviewed_inventory(authorization)
        second = copy.deepcopy(inventory["sources"][0])
        second["source_sha256"] = identity(1)
        second["semantic_binding_identity"] = identity(1)
        inventory["sources"].append(second)
        with self.assertRaises(validator.Refusal):
            validator.parse_reviewed_inventory_bytes(encoded(inventory), parsed)

    def test_equal_target_fields_require_a_separate_canonical_receipt(self) -> None:
        authorization = reviewed_authorization()
        parsed = validator.parse_reviewed_authorization_bytes(encoded(authorization))
        inventory = reviewed_inventory(authorization)
        source = inventory["sources"][0]
        source["targets"]["linux_aarch64"]["literal_identity"] = source["targets"][
            "macos_aarch64"
        ]["literal_identity"]
        with self.assertRaises(validator.Refusal):
            validator.parse_reviewed_inventory_bytes(encoded(inventory), parsed)

        source["cross_target_equalities"] = [
            {
                "field": "literal_identity",
                "independent_derivation_receipt_sha256": identity(900),
            }
        ]
        validator.parse_reviewed_inventory_bytes(encoded(inventory), parsed)

    def test_hardened_reader_rejects_mode_and_link_count_drift(self) -> None:
        temporary = Path(tempfile.mkdtemp()).resolve()
        try:
            path = temporary / "authorization.json"
            raw = encoded(reviewed_authorization())
            path.write_bytes(raw)
            path.chmod(0o600)
            self.assertEqual(
                validator._sealed_read(str(path), validator.MAX_AUTH_BYTES, "test"),
                raw,
            )

            path.chmod(0o644)
            with self.assertRaises(validator.Refusal):
                validator._sealed_read(str(path), validator.MAX_AUTH_BYTES, "test")
            path.chmod(0o600)

            hardlink = temporary / "authorization-hardlink.json"
            os.link(path, hardlink)
            with self.assertRaises(validator.Refusal):
                validator._sealed_read(str(path), validator.MAX_AUTH_BYTES, "test")
            hardlink.unlink()

        finally:
            for child in temporary.iterdir():
                child.unlink()
            temporary.rmdir()


if __name__ == "__main__":
    unittest.main()
