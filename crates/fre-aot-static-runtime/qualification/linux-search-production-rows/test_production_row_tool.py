#!/usr/bin/env python3
"""Source-only and tamper tests for production Search-row authorization."""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


TOOL_DIRECTORY = Path(__file__).resolve().parent
TOOL_PATH = TOOL_DIRECTORY / "production_row_tool.py"
SPEC = importlib.util.spec_from_file_location("production_row_tool", TOOL_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load production_row_tool.py")
production_row_tool = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = production_row_tool
SPEC.loader.exec_module(production_row_tool)

CRATE_DIRECTORY = TOOL_DIRECTORY.parents[1]
SUPPORT_SOURCE = CRATE_DIRECTORY / "src" / "search_support.rs"
PRODUCTION_SOURCE = (
    CRATE_DIRECTORY / "src" / "search_support" / "production_rows.rs"
)
AUTHORIZATION_TEMPLATE = (
    TOOL_DIRECTORY / "templates" / "production-authorization-v1.tsv.template"
)

EXACT_FIELDS = (
    "schema",
    "authorization_state",
    "table_target",
    "runtime_authority",
    "selector",
    "qualification_field_count",
    "live_literal_bytes",
    "manifest_identity",
    "semantic_binding_identity",
    "literal_identity",
    "kir_identity",
    "artifact_identity",
    "binding_identity",
    "compile_identity",
    "object_identity",
    "receipt_identity",
    "expectation_identity",
    "payload_identity",
    "private_candidate_commit",
    "private_promotion_commit",
    "private_source_row_proposal_sha256",
    "post_private_evidence_commit",
    "post_private_evidence_tree",
    "post_private_evidence_manifest_sha256",
    "post_private_evidence_receipt_sha256",
    "post_private_evidence_bundle_sha256",
    "post_private_evidence_final_image_sha256",
)


def authorization_bytes(**changes: str) -> bytes:
    values = {
        "schema": "fre-aot-linux-search-span-production-authorization-v1",
        "authorization_state": "reviewed-production-authorization",
        "table_target": "production-runtime-authority",
        "runtime_authority": "source-reviewed",
        "selector": "7",
        "qualification_field_count": "12",
        "live_literal_bytes": "16",
        "private_candidate_commit": "a1" * 20,
        "private_promotion_commit": "b2" * 20,
        "private_source_row_proposal_sha256": "c3" * 32,
        "post_private_evidence_commit": "b2" * 20,
        "post_private_evidence_tree": "d4" * 20,
        "post_private_evidence_manifest_sha256": "e5" * 32,
        "post_private_evidence_receipt_sha256": "f6" * 32,
        "post_private_evidence_bundle_sha256": "17" * 32,
        "post_private_evidence_final_image_sha256": "28" * 32,
    }
    for index, name in enumerate(EXACT_FIELDS[7:18], start=1):
        values[name] = f"{index:02x}" * 32
    values.update(changes)
    return "".join(
        f"{name}\t{values[name]}\n" for name in EXACT_FIELDS
    ).encode("ascii")


class ProductionAuthorizationGrammarTests(unittest.TestCase):
    def test_exact_field_order_is_independently_fixed(self) -> None:
        self.assertEqual(production_row_tool.FIELDS, EXACT_FIELDS)

    def test_canonical_authorization_round_trips_and_renders_every_pin(
        self,
    ) -> None:
        raw = authorization_bytes()
        authorization = production_row_tool.parse_authorization_bytes(raw)
        self.assertEqual(
            production_row_tool.render_authorization_tsv(authorization),
            raw,
        )
        production = production_row_tool.render_production_module(
            authorization
        ).decode("ascii")
        private = (
            production_row_tool.render_private_module_from_authorization(
                authorization
            ).decode("ascii")
        )
        self.assertIn(
            f"production-authorization.tsv SHA-256: {authorization.sha256}",
            production,
        )
        self.assertIn(
            "source-row-proposal.tsv SHA-256: "
            f"{authorization.private_source_row_proposal_sha256}",
            private,
        )
        self.assertEqual(production.count("::production("), 1)
        self.assertEqual(private.count("::private_qualification("), 1)
        for index in range(1, 12):
            self.assertIn(f"0x{index:02x}", production)
            self.assertIn(f"0x{index:02x}", private)
        self.assertIn(".len() == 1", production)
        self.assertNotIn(".is_empty()", production)
        self.assertEqual(
            production_row_tool._reviewed(
                authorization,
                authorization.sha256,
            ),
            authorization,
        )
        with self.assertRaises(production_row_tool.Refusal):
            production_row_tool._reviewed(
                authorization,
                (
                    "0" if authorization.sha256[0] != "0" else "1"
                ) + authorization.sha256[1:],
            )

    def test_empty_atoms_are_literal_compile_time_fail_closed_states(self) -> None:
        private = production_row_tool.render_empty_private_module().decode(
            "ascii"
        )
        production = production_row_tool.EMPTY_PRODUCTION_MODULE.decode("ascii")
        self.assertIn(
            "&[SourceQualifiedStaticSearchSpanRowV1] = &[];",
            private,
        )
        self.assertIn(
            "&[SourceQualifiedStaticSearchSpanRowV1] = &[];",
            production,
        )
        self.assertNotIn("private_qualification(", private)
        self.assertNotIn("::production(", production)
        self.assertIn(
            "PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_ROWS_V1.is_empty()",
            production,
        )

    def test_closed_headers_refuse_non_authority_inputs(self) -> None:
        for field, value in (
            (
                "schema",
                "fre-aot-linux-search-span-production-authorization-v2",
            ),
            ("authorization_state", "proposal-only"),
            ("table_target", "private-qualification-input"),
            ("runtime_authority", "absent"),
            ("qualification_field_count", "11"),
        ):
            with self.subTest(field=field):
                with self.assertRaises(production_row_tool.Refusal):
                    production_row_tool.parse_authorization_bytes(
                        authorization_bytes(**{field: value})
                    )

    def test_decimals_refuse_noncanonical_or_out_of_range_values(self) -> None:
        for field, values in (
            ("selector", ("00", "+1", "-1", "65536")),
            ("live_literal_bytes", ("0", "01", "+1", "4294967296")),
        ):
            for value in values:
                with self.subTest(field=field, value=value):
                    with self.assertRaises(production_row_tool.Refusal):
                        production_row_tool.parse_authorization_bytes(
                            authorization_bytes(**{field: value})
                        )

    def test_identity_commit_and_evidence_mutations_are_refused(self) -> None:
        canonical = authorization_bytes()
        lines = canonical.splitlines(keepends=True)
        mutations = [
            authorization_bytes(manifest_identity="AA" * 32),
            authorization_bytes(manifest_identity="ab" * 31),
            authorization_bytes(private_candidate_commit="ab" * 19),
            authorization_bytes(private_candidate_commit="0" * 40),
            authorization_bytes(
                private_candidate_commit="b2" * 20,
                private_promotion_commit="b2" * 20,
            ),
            authorization_bytes(post_private_evidence_commit="e5" * 20),
            authorization_bytes(post_private_evidence_tree="0" * 40),
            authorization_bytes(
                post_private_evidence_bundle_sha256="0" * 64
            ),
            canonical[:-1],
            canonical.replace(b"\n", b"\r\n"),
            canonical + b"extra\tfield\n",
            canonical.replace(b"\t", b"\tignored\t", 1),
            canonical.replace(b"schema\t", b"table_target\t", 1),
            canonical + b"\0",
            canonical[:-1] + b"\xff\n",
            b"".join(lines[1:]),
            b"".join((lines[1], lines[0], *lines[2:])),
        ]
        for index, mutation in enumerate(mutations):
            with self.subTest(mutation=index):
                with self.assertRaises(production_row_tool.Refusal):
                    production_row_tool.parse_authorization_bytes(mutation)

    def test_file_boundary_requires_absolute_owned_mode_0600_single_link(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory_text:
            directory = Path(directory_text).resolve()
            authorization = directory / "production-authorization.tsv"
            authorization.write_bytes(authorization_bytes())
            authorization.chmod(0o600)
            self.assertEqual(
                production_row_tool.read_authorization(
                    str(authorization)
                ).selector,
                7,
            )

            authorization.chmod(0o644)
            with self.assertRaises(production_row_tool.Refusal):
                production_row_tool.read_authorization(str(authorization))
            authorization.chmod(0o600)

            hardlink = directory / "hardlink.tsv"
            os.link(authorization, hardlink)
            with self.assertRaises(production_row_tool.Refusal):
                production_row_tool.read_authorization(str(authorization))
            hardlink.unlink()

            symlink = directory / "symlink.tsv"
            symlink.symlink_to(authorization)
            with self.assertRaises(production_row_tool.Refusal):
                production_row_tool.read_authorization(str(symlink))
            with self.assertRaises(production_row_tool.Refusal):
                production_row_tool.read_authorization(
                    "production-authorization.tsv"
                )

    def test_fifo_substitution_is_bounded_and_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory_text:
            directory = Path(directory_text).resolve()
            regular = directory / "reviewed-authorization.tsv"
            regular.write_bytes(authorization_bytes())
            regular.chmod(0o600)
            regular_metadata = regular.lstat()
            fifo = directory / "substituted-authorization.tsv"
            os.mkfifo(fifo, 0o600)

            started = time.monotonic()
            with mock.patch.object(
                Path,
                "lstat",
                return_value=regular_metadata,
            ):
                with self.assertRaises(production_row_tool.Refusal):
                    production_row_tool.read_authorization(str(fifo))
            self.assertLess(time.monotonic() - started, 1.0)

    def test_checked_in_template_is_inert_and_has_no_current_authority(
        self,
    ) -> None:
        template = AUTHORIZATION_TEMPLATE.read_bytes()
        self.assertIn(b"<REQUIRED_", template)
        with self.assertRaises(production_row_tool.Refusal):
            production_row_tool.parse_authorization_bytes(
                template,
                str(AUTHORIZATION_TEMPLATE),
            )


class ProductionSupportLayoutTests(unittest.TestCase):
    def test_candidate_audit_stays_empty_while_live_atom_shape_is_exact(self) -> None:
        support = SUPPORT_SOURCE.read_bytes()
        candidate_production = production_row_tool.EMPTY_PRODUCTION_MODULE
        digest = production_row_tool.audit_support_source(
            support,
            candidate_production,
        )
        self.assertEqual(len(digest), 64)
        self.assertNotIn(b"const fn production(", support)
        self.assertEqual(
            candidate_production.count(b"    const fn production("),
            1,
        )
        self.assertNotIn(b"private_qualification", candidate_production)
        self.assertIn(
            production_row_tool.classify_live_production_atom_shape_non_authoritative(
                PRODUCTION_SOURCE.read_bytes()
            ),
            ("canonical-empty", "canonical-one-row"),
        )

    def test_live_atom_classifier_is_structural_and_never_authority(self) -> None:
        support = SUPPORT_SOURCE.read_bytes()
        authorization = production_row_tool.parse_authorization_bytes(
            authorization_bytes()
        )
        promoted = production_row_tool.render_production_module(authorization)
        self.assertEqual(
            production_row_tool.classify_live_production_atom_shape_non_authoritative(
                production_row_tool.EMPTY_PRODUCTION_MODULE
            ),
            "canonical-empty",
        )
        self.assertEqual(
            production_row_tool.classify_live_production_atom_shape_non_authoritative(
                promoted
            ),
            "canonical-one-row",
        )
        with self.assertRaises(production_row_tool.Refusal):
            production_row_tool.audit_support_source(support, promoted)

        digest = authorization.sha256.encode("ascii")
        mutations = (
            promoted + b"\n",
            promoted.replace(digest, digest.upper(), 1),
            promoted.replace(digest, b"0" * 64, 1),
            promoted.replace(
                b"    const fn production(",
                b"    pub(crate) const fn production(",
                1,
            ),
            promoted.replace(
                b"SourceQualifiedStaticSearchSpanRowV1::production(",
                b"SourceQualifiedStaticSearchSpanRowV1::private_qualification(",
                1,
            ),
            promoted.replace(
                b"        7,\n        16,",
                b"        07,\n        16,",
                1,
            ),
            promoted.replace(b"0x01", b"0xAA", 1),
            promoted.replace(b".len() == 1", b".len() == 2", 1),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assertNotEqual(mutation, promoted)
                with self.assertRaises(production_row_tool.Refusal):
                    production_row_tool.classify_live_production_atom_shape_non_authoritative(
                        mutation
                    )

    def test_support_or_production_atom_tampering_is_refused(self) -> None:
        source = SUPPORT_SOURCE.read_bytes()
        production = production_row_tool.EMPTY_PRODUCTION_MODULE
        mutations = (
            (
                source,
                production.replace(
                    b"    const fn production(",
                    b"    pub(crate) const fn production(",
                    1,
                ),
            ),
            (
                source.replace(b"mod production_rows;\n", b"", 1),
                production,
            ),
            (
                source,
                production.replace(b" = &[];", b" = AUTHORIZED_ROWS;", 1),
            ),
            (
                source,
                production.replace(b".is_empty());", b".len() == 1);", 1),
            ),
            (
                source + b"\nconst fn production() {}\n",
                production,
            ),
        )
        for index, (support_mutation, production_mutation) in enumerate(
            mutations
        ):
            with self.subTest(mutation=index):
                self.assertTrue(
                    support_mutation != source or production_mutation != production
                )
                with self.assertRaises(production_row_tool.Refusal):
                    production_row_tool.audit_support_source(
                        support_mutation,
                        production_mutation,
                    )


if __name__ == "__main__":
    unittest.main()
