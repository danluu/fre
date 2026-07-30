#!/usr/bin/env python3
"""Tests for the frozen qualification-to-production code identity gate."""

from __future__ import annotations

import copy
import contextlib
import hashlib
import importlib.util
import io
import json
import stat
import tempfile
import unittest
from pathlib import Path
from typing import Any

VERIFIER_SPEC = importlib.util.spec_from_file_location(
    "verify_production_identity",
    Path(__file__).with_name("verify_production_identity.py"),
)
if VERIFIER_SPEC is None or VERIFIER_SPEC.loader is None:
    raise RuntimeError("cannot load production identity verifier")
verifier = importlib.util.module_from_spec(VERIFIER_SPEC)
VERIFIER_SPEC.loader.exec_module(verifier)


def h(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def eligibility() -> dict[str, Any]:
    return {
        "compiler_version": 3,
        "metadata_version": 3,
        "image_schema_version": 3,
        "backend_version": 0xA003,
        "algorithm_version": 11,
        "auditor_version": 2,
        "kir_semantics_version": 1,
        "kir_abi_version": 1,
        "recipe_schema_version": 3,
        "optimizer_version": 7,
        "tuning_class_id": 3,
        "strategy_id": 2,
        "schedule_id": 2,
        "register_plan_id": 5,
        "literal_bytes": 8,
        "filter_len": 2,
        "sparse_group_count": 1,
        "match_stride": 8,
        "periodic_stride": 0,
        "call_abi_schema": 2,
        "abi_kind": 2,
        "status_bits": 64,
        "output_kind": 1,
        "architecture": 1,
        "little_endian": True,
        "pointer_width": 64,
        "target_abi": 1,
        "object_format": 2,
        "required_isa_id": 3,
        "actual_features": 7,
        "allowed_features": 7,
        "candidate_block_starts": 16,
        "vector_bytes": 16,
        "sve_vector_length_bytes": 16,
        "max_literal_bytes": 32,
    }


def engine(name: str, authority: str) -> dict[str, Any]:
    is_v3 = name == "count-v3-aot"
    is_object = name != "portable-current"
    artifact_file_sha256 = h(
        name + ("-object" if is_object else "-file")
    )
    return {
        "artifact_file_path": (
            f"/sealed/{authority}/{name}/{artifact_file_sha256}"
        ),
        "artifact_file_sha256": artifact_file_sha256,
        "artifact_id": h(name + "-artifact"),
        "code_bytes": 384 if is_object else None,
        "compile_identity": h(name + "-compile") if is_object else None,
        "engine": name,
        "expectation_bytes_sha256": h("expectation-bytes") if is_v3 else None,
        "expectation_file_path": (
            f"/sealed/{authority}/expectation/{h('expectation-file')}"
            if is_v3
            else None
        ),
        "expectation_file_sha256": h("expectation-file") if is_v3 else None,
        "expectation_identity": h("expectation-identity") if is_v3 else None,
        "expectation_symbol": (
            f"fre_aot_count_expectation_v3_{h('count-v3-aot-compile')}"
            if is_v3
            else None
        ),
        "general_eligibility_tuple": eligibility() if is_v3 else None,
        "metadata_sha256": h(name + "-metadata"),
        "object_bytes": 768 if is_object else None,
        "object_identity": h(name + "-object-identity") if is_object else None,
        "object_sha256": h(name + "-object") if is_object else None,
        "optimizer_receipt_identity": h("optimizer-receipt") if is_v3 else None,
        "payload_bytes": 384,
        "payload_sha256": h(name + "-payload"),
        "receipt_identity": h(name + "-receipt") if not is_object else None,
        "recipe_identity": h("recipe") if is_v3 else None,
        "runtime_authority": authority if is_v3 else "control",
    }


def registry(production: bool) -> dict[str, Any]:
    authority = "production" if production else "qualification-private"
    pattern_sha256 = h("pattern")
    engines = [engine(name, authority) for name in verifier.ENGINES]
    value: dict[str, Any] = {
        "artifact_root": f"/sealed/{authority}",
        "artifacts": [
            {
                "artifact_file_path": row["artifact_file_path"],
                "artifact_file_sha256": row["artifact_file_sha256"],
                "artifact_id": row["artifact_id"],
                "engine": row["engine"],
                "metadata_sha256": row["metadata_sha256"],
                "pattern_sha256": pattern_sha256,
                "payload_sha256": row["payload_sha256"],
            }
            for row in engines
        ],
        "compiled_patterns": [
            {
                "claim_derivations": {"schema": "synthetic-claim.v1"},
                "engines": engines,
                "input_policy": "pattern-only-build-v1",
                "optimizer_input_sha256": h("optimizer-input"),
                "pattern_input_id": "pattern-1",
                "pattern_sha256": pattern_sha256,
                "planning_receipt_identity": h("planning"),
                "semantic_binding_identity": h("semantic"),
            }
        ],
        "distinct_artifacts": 1,
        "input_policy": "pattern-only-build-v1",
        "inventory_identity": h("inventory-identity"),
        "inventory_sha256": h("inventory"),
        "object_format": "elf64-aarch64",
        "production_authority": (
            "source-reviewed-tuples-required" if production else "absent"
        ),
        "qualification_authority": "absent" if production else "private-only",
        "required_isa": "sve2-vl16",
        "schema": (
            verifier.PRODUCTION_REGISTRY_SCHEMA
            if production
            else verifier.QUALIFICATION_REGISTRY_SCHEMA
        ),
        "source": {"files": {authority: h(authority)}},
        "target_contract_sha256": h("target-contract"),
        "target_id": "ec2-sve2",
        "target_triple": "aarch64-unknown-linux-gnu",
        "tuning_class": "neoverse-v2-v3",
    }
    if production:
        value.update(
            build_authority="production",
            cells=[],
            promotion_authority_source_sha256=h("authority-source"),
            promotion_manifest_sha256=h("manifest"),
            promotion_proposal_sha256=h("proposal"),
        )
    return value


def encoded(value: object) -> bytes:
    return verifier.canonical_json_bytes(value)


def retarget(
    value: dict[str, Any],
    *,
    target_id: str,
    required_isa: str,
    object_format: str,
    target_triple: str,
    tuning_class: str,
    tuning_class_id: int,
    object_format_id: int,
    required_isa_id: int,
    register_plan_id: int,
    features: int,
    sve_vl: int,
) -> None:
    value.update(
        target_id=target_id,
        required_isa=required_isa,
        object_format=object_format,
        target_triple=target_triple,
        tuning_class=tuning_class,
    )
    row = value["compiled_patterns"][0]["engines"][2][
        "general_eligibility_tuple"
    ]
    row.update(
        tuning_class_id=tuning_class_id,
        object_format=object_format_id,
        required_isa_id=required_isa_id,
        register_plan_id=register_plan_id,
        actual_features=features,
        allowed_features=features,
        sve_vector_length_bytes=sve_vl,
    )


def verify_pair(
    qualification: dict[str, Any], production: dict[str, Any]
) -> dict[str, Any]:
    qualification_bytes = encoded(qualification)
    production_bytes = encoded(production)
    return verifier.verify_identity_bytes(
        qualification_bytes,
        verifier.sha256_bytes(qualification_bytes),
        production_bytes,
        verifier.sha256_bytes(production_bytes),
        h("verifier-source"),
    )


class ProductionIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.qualification = registry(False)
        self.production = registry(True)

    def test_accepts_only_path_source_and_authority_differences(self) -> None:
        receipt = verify_pair(self.qualification, self.production)
        self.assertEqual(receipt["status"], "pass")
        self.assertEqual(receipt["compared_artifacts"], 1)
        self.assertIn("payload_sha256", receipt["compared_count_v3_fields"])
        self.assertIn("compile_identity", receipt["compared_count_v3_fields"])

    def test_accepts_all_closed_hybrid_target_rows(self) -> None:
        cases = (
            (
                "apple-neon",
                "neon",
                "macho-arm64",
                "aarch64-apple-darwin",
                "apple-m-series",
                2,
                1,
                1,
                1,
                1,
                0,
            ),
            (
                "neoverse-neon",
                "neon",
                "elf64-aarch64",
                "aarch64-unknown-linux-gnu",
                "neoverse-v2-v3",
                3,
                2,
                1,
                1,
                1,
                0,
            ),
            (
                "neoverse-sve",
                "sve-vl16",
                "elf64-aarch64",
                "aarch64-unknown-linux-gnu",
                "neoverse-v2-v3",
                3,
                2,
                2,
                4,
                3,
                16,
            ),
            (
                "neoverse-sve2",
                "sve2-vl16",
                "elf64-aarch64",
                "aarch64-unknown-linux-gnu",
                "neoverse-v2-v3",
                3,
                2,
                3,
                5,
                7,
                16,
            ),
        )
        for case in cases:
            with self.subTest(target_id=case[0]):
                qualification = registry(False)
                production = registry(True)
                for value in (qualification, production):
                    retarget(
                        value,
                        target_id=case[0],
                        required_isa=case[1],
                        object_format=case[2],
                        target_triple=case[3],
                        tuning_class=case[4],
                        tuning_class_id=case[5],
                        object_format_id=case[6],
                        required_isa_id=case[7],
                        register_plan_id=case[8],
                        features=case[9],
                        sve_vl=case[10],
                    )
                self.assertEqual(
                    verify_pair(qualification, production)["status"], "pass"
                )

    def test_rejects_payload_or_machine_code_shape_change(self) -> None:
        for field, value in (
            ("payload_sha256", h("different-payload")),
            ("code_bytes", 512),
            ("compile_identity", h("different-compile")),
            ("object_sha256", h("different-object")),
            ("expectation_bytes_sha256", h("different-expectation")),
        ):
            with self.subTest(field=field):
                production = copy.deepcopy(self.production)
                production["compiled_patterns"][0]["engines"][2][field] = value
                if field == "payload_sha256":
                    production["artifacts"][2][field] = value
                with self.assertRaisesRegex(
                    verifier.IdentityVerificationError, field
                ):
                    verify_pair(self.qualification, production)

    def test_rejects_campaign_to_compiled_payload_disagreement(self) -> None:
        production = copy.deepcopy(self.production)
        production["artifacts"][2]["payload_sha256"] = h("forged-campaign")
        with self.assertRaisesRegex(
            verifier.IdentityVerificationError, "compiled pattern"
        ):
            verify_pair(self.qualification, production)

    def test_rejects_legacy_pure_sve2_tuple(self) -> None:
        production = copy.deepcopy(self.production)
        row = production["compiled_patterns"][0]["engines"][2][
            "general_eligibility_tuple"
        ]
        row.update(
            register_plan_id=3,
            actual_features=6,
            allowed_features=6,
        )
        with self.assertRaisesRegex(
            verifier.IdentityVerificationError, "hybrid"
        ):
            verify_pair(self.qualification, production)

    def test_rejects_target_or_inventory_change(self) -> None:
        for field in ("target_contract_sha256", "inventory_sha256"):
            with self.subTest(field=field):
                production = copy.deepcopy(self.production)
                production[field] = h("changed-" + field)
                with self.assertRaisesRegex(
                    verifier.IdentityVerificationError, field
                ):
                    verify_pair(self.qualification, production)

    def test_rejects_digest_mismatch_and_noncanonical_json(self) -> None:
        qualification_bytes = encoded(self.qualification)
        production_bytes = encoded(self.production)
        with self.assertRaisesRegex(
            verifier.IdentityVerificationError, "SHA-256"
        ):
            verifier.verify_identity_bytes(
                qualification_bytes,
                h("wrong"),
                production_bytes,
                verifier.sha256_bytes(production_bytes),
                h("source"),
            )

    def test_cli_seals_a_create_only_read_only_receipt(self) -> None:
        qualification_bytes = encoded(self.qualification)
        production_bytes = encoded(self.production)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            qualification_path = root / "qualification.json"
            production_path = root / "production.json"
            output_path = root / "identity-receipt.json"
            qualification_path.write_bytes(qualification_bytes)
            production_path.write_bytes(production_bytes)
            argv = [
                "verify_production_identity.py",
                str(qualification_path),
                verifier.sha256_bytes(qualification_bytes),
                str(production_path),
                verifier.sha256_bytes(production_bytes),
                str(output_path),
            ]
            self.assertEqual(verifier.main(argv), 0)
            receipt_bytes = output_path.read_bytes()
            self.assertTrue(receipt_bytes.endswith(b"\n"))
            self.assertEqual(json.loads(receipt_bytes)["status"], "pass")
            self.assertEqual(
                stat.S_IMODE(output_path.stat().st_mode) & 0o222, 0
            )
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(verifier.main(argv), 1)
        pretty = (
            verifier.canonical_json_bytes(self.qualification)
            .decode("ascii")
            .replace(',"artifacts"', ', "artifacts"', 1)
            .encode("ascii")
        )
        with self.assertRaisesRegex(
            verifier.IdentityVerificationError, "canonical"
        ):
            verifier.verify_identity_bytes(
                pretty,
                verifier.sha256_bytes(pretty),
                production_bytes,
                verifier.sha256_bytes(production_bytes),
                h("source"),
            )


if __name__ == "__main__":
    unittest.main()
