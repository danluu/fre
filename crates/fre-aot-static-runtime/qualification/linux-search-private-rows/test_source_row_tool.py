#!/usr/bin/env python3
"""Source-only and tamper tests for private Linux Search row rendering."""

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
TOOL_PATH = TOOL_DIRECTORY / "source_row_tool.py"
SPEC = importlib.util.spec_from_file_location("source_row_tool", TOOL_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load source_row_tool.py")
source_row_tool = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = source_row_tool
SPEC.loader.exec_module(source_row_tool)

PRODUCTION_TOOL_PATH = (
    TOOL_DIRECTORY.parent
    / "linux-search-production-rows"
    / "production_row_tool.py"
)
PRODUCTION_SPEC = importlib.util.spec_from_file_location(
    "production_row_tool_for_private_layout_test",
    PRODUCTION_TOOL_PATH,
)
if PRODUCTION_SPEC is None or PRODUCTION_SPEC.loader is None:
    raise RuntimeError("cannot load production_row_tool.py")
production_row_tool = importlib.util.module_from_spec(PRODUCTION_SPEC)
sys.modules[PRODUCTION_SPEC.name] = production_row_tool
PRODUCTION_SPEC.loader.exec_module(production_row_tool)

CRATE_DIRECTORY = TOOL_DIRECTORY.parents[1]
SUPPORT_SOURCE = CRATE_DIRECTORY / "src" / "search_support.rs"
PRODUCTION_SOURCE = (
    CRATE_DIRECTORY / "src" / "search_support" / "production_rows.rs"
)

EXACT_FIELDS = (
    "schema",
    "promotion_state",
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
)


def proposal_bytes(**changes: str) -> bytes:
    values = {
        "schema": "fre-aot-linux-search-span-source-row-proposal-v1",
        "promotion_state": "proposal-only",
        "table_target": "private-qualification-input",
        "runtime_authority": "absent",
        "selector": "7",
        "qualification_field_count": "12",
        "live_literal_bytes": "16",
    }
    for index, name in enumerate(EXACT_FIELDS[7:], start=1):
        values[name] = f"{index:02x}" * 32
    values.update(changes)
    return "".join(f"{name}\t{values[name]}\n" for name in EXACT_FIELDS).encode("ascii")


class SourceRowGrammarTests(unittest.TestCase):
    def test_exact_field_order_is_independently_fixed(self) -> None:
        self.assertEqual(source_row_tool.FIELDS, EXACT_FIELDS)

    def test_canonical_proposal_round_trips_and_renders_every_pin(self) -> None:
        raw = proposal_bytes()
        proposal = source_row_tool.parse_proposal_bytes(raw)
        self.assertEqual(source_row_tool.render_proposal_tsv(proposal), raw)
        rendered = source_row_tool.render_private_module(proposal).decode("ascii")
        self.assertIn(
            f"source-row-proposal.tsv SHA-256: {proposal.sha256}",
            rendered,
        )
        self.assertEqual(rendered.count("private_qualification("), 1)
        for index in range(1, 12):
            self.assertIn(f"0x{index:02x}", rendered)
        self.assertEqual(
            source_row_tool.render_reviewed_private_module(proposal, proposal.sha256),
            rendered.encode("ascii"),
        )
        with self.assertRaises(source_row_tool.Refusal):
            source_row_tool.render_reviewed_private_module(
                proposal,
                ("0" if proposal.sha256[0] != "0" else "1") + proposal.sha256[1:],
            )

    def test_empty_render_is_a_literal_fail_closed_table(self) -> None:
        rendered = source_row_tool.render_private_module(None).decode("ascii")
        self.assertIn(
            "&[SourceQualifiedStaticSearchSpanRowV1] = &[];",
            rendered,
        )
        self.assertNotIn("private_qualification(", rendered)

    def test_closed_headers_refuse_authority_or_target_changes(self) -> None:
        for field, value in (
            ("schema", "fre-aot-linux-search-span-source-row-proposal-v2"),
            ("promotion_state", "promoted"),
            ("table_target", "production-input"),
            ("runtime_authority", "present"),
            ("qualification_field_count", "11"),
        ):
            with self.subTest(field=field):
                with self.assertRaises(source_row_tool.Refusal):
                    source_row_tool.parse_proposal_bytes(
                        proposal_bytes(**{field: value})
                    )

    def test_decimals_refuse_noncanonical_or_out_of_range_values(self) -> None:
        for field, values in (
            ("selector", ("00", "+1", "-1", "65536")),
            ("live_literal_bytes", ("0", "01", "+1", "4294967296")),
        ):
            for value in values:
                with self.subTest(field=field, value=value):
                    with self.assertRaises(source_row_tool.Refusal):
                        source_row_tool.parse_proposal_bytes(
                            proposal_bytes(**{field: value})
                        )

    def test_identity_and_text_mutations_are_refused(self) -> None:
        canonical = proposal_bytes()
        lines = canonical.splitlines(keepends=True)
        mutations = [
            proposal_bytes(manifest_identity="AA" * 32),
            proposal_bytes(manifest_identity="ab" * 31),
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
        for name in EXACT_FIELDS[7:]:
            mutations.append(proposal_bytes(**{name: "0" * 64}))
        for index, mutation in enumerate(mutations):
            with self.subTest(mutation=index):
                with self.assertRaises(source_row_tool.Refusal):
                    source_row_tool.parse_proposal_bytes(mutation)

    def test_file_boundary_requires_absolute_owned_mode_0600_single_link(self) -> None:
        with tempfile.TemporaryDirectory() as directory_text:
            directory = Path(directory_text).resolve()
            proposal = directory / "source-row-proposal.tsv"
            proposal.write_bytes(proposal_bytes())
            proposal.chmod(0o600)
            self.assertEqual(source_row_tool.read_proposal(str(proposal)).selector, 7)

            proposal.chmod(0o644)
            with self.assertRaises(source_row_tool.Refusal):
                source_row_tool.read_proposal(str(proposal))
            proposal.chmod(0o600)

            hardlink = directory / "hardlink.tsv"
            os.link(proposal, hardlink)
            with self.assertRaises(source_row_tool.Refusal):
                source_row_tool.read_proposal(str(proposal))
            hardlink.unlink()

            symlink = directory / "symlink.tsv"
            symlink.symlink_to(proposal)
            with self.assertRaises(source_row_tool.Refusal):
                source_row_tool.read_proposal(str(symlink))
            with self.assertRaises(source_row_tool.Refusal):
                source_row_tool.read_proposal("source-row-proposal.tsv")

    def test_fifo_substitution_is_bounded_and_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory_text:
            directory = Path(directory_text).resolve()
            regular = directory / "reviewed-proposal.tsv"
            regular.write_bytes(proposal_bytes())
            regular.chmod(0o600)
            regular_metadata = regular.lstat()
            fifo = directory / "substituted-proposal.tsv"
            os.mkfifo(fifo, 0o600)

            started = time.monotonic()
            with mock.patch.object(
                Path,
                "lstat",
                return_value=regular_metadata,
            ):
                with self.assertRaises(source_row_tool.Refusal):
                    source_row_tool.read_proposal(str(fifo))
            self.assertLess(time.monotonic() - started, 1.0)


class SupportLayoutTests(unittest.TestCase):
    def test_candidate_audit_stays_empty_while_live_atom_shape_is_exact(self) -> None:
        support = SUPPORT_SOURCE.read_bytes()
        candidate_production = source_row_tool.EMPTY_PRODUCTION_MODULE
        self.assertEqual(
            candidate_production,
            production_row_tool.EMPTY_PRODUCTION_MODULE,
        )
        digest = source_row_tool.audit_support_source(
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

    def test_production_and_constructor_source_tampering_is_refused(self) -> None:
        source = SUPPORT_SOURCE.read_bytes()
        production = source_row_tool.EMPTY_PRODUCTION_MODULE
        mutations = (
            (
                source.replace(
                    b"    const fn private_qualification(",
                    b"    pub(crate) const fn private_qualification(",
                    1,
                ),
                production,
            ),
            (
                source.replace(
                    b'#[cfg(feature = "search-span-qualification-private-v1")]\n'
                    b"mod private_rows;",
                    b"mod private_rows;",
                    1,
                ),
                production,
            ),
            (
                source,
                production.replace(
                    b"    const fn production(",
                    b"    pub(crate) const fn production(",
                    1,
                ),
            ),
            (
                source.replace(
                    b"mod production_rows;\n",
                    b"",
                    1,
                ),
                production,
            ),
            (
                source,
                production.replace(
                    b"&[SourceQualifiedStaticSearchSpanRowV1] = &[];",
                    b"&[SourceQualifiedStaticSearchSpanRowV1] = PRIVATE_ROWS;",
                    1,
                ),
            ),
            (
                source,
                production.replace(
                    b"const _: () = "
                    b"assert!(PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_ROWS_V1.is_empty());",
                    b"",
                    1,
                ),
            ),
            (
                source + b"\nconst fn production() {}\n",
                production,
            ),
        )
        for index, (support_mutation, production_mutation) in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assertTrue(
                    support_mutation != source or production_mutation != production
                )
                with self.assertRaises(source_row_tool.Refusal):
                    source_row_tool.audit_support_source(
                        support_mutation,
                        production_mutation,
                    )


if __name__ == "__main__":
    unittest.main()
