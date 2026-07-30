#!/usr/bin/env python3
"""Structural and adversarial tests for the tag-29 static-link proof."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


DIRECTORY = Path(__file__).resolve().parent
REPO = DIRECTORY.parents[2]
APPLICATION_DIRECTORY = (
    REPO / "research/aot/search-ripgrep-application-independent-v2"
)
VERIFIER_PATH = DIRECTORY / "verify_linked_candidates.py"
SPEC = importlib.util.spec_from_file_location("_search_link_proof", VERIFIER_PATH)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VERIFIER
SPEC.loader.exec_module(VERIFIER)


class LinkProofTests(unittest.TestCase):
    def test_exact_contract_passes(self) -> None:
        contract = VERIFIER.validate_contract(
            (DIRECTORY / "contract-v1.json").read_bytes()
        )
        self.assertEqual(contract["object_candidates"]["count"], 808)
        self.assertEqual(contract["authority"]["rebar_inputs"], [])
        self.assertFalse(contract["authority"]["promotion_authority"])

    def test_exact_application_contract_and_manifests_pass(self) -> None:
        raw = (
            APPLICATION_DIRECTORY / "link-proof-contract-v1.json"
        ).read_bytes()
        profile = VERIFIER.contract_profile(raw)
        contract = VERIFIER.validate_contract(raw)
        self.assertEqual(contract["profile"], "ripgrep-application-v2")
        self.assertEqual(profile["object_count"], 5)
        self.assertEqual(profile["refusal_count"], 6)
        object_root = VERIFIER.load_envelope(
            (
                APPLICATION_DIRECTORY / "object-candidates-v1.json"
            ).read_bytes(),
            profile["object_schema"],
            profile["object_sha256"],
            profile["object_payload_sha256"],
            "application objects",
        )
        candidates = VERIFIER.validate_candidate_manifest(
            object_root, profile
        )
        dispositions = VERIFIER.load_envelope(
            (
                APPLICATION_DIRECTORY / "literal-dispositions-v1.json"
            ).read_bytes(),
            profile["dispositions_schema"],
            profile["dispositions_sha256"],
            profile["dispositions_payload_sha256"],
            "application dispositions",
        )
        refusals = VERIFIER.validate_dispositions(
            dispositions, candidates, profile
        )
        self.assertEqual(len(candidates), 5)
        self.assertEqual(len(refusals), 6)

    def test_contract_parameter_bytes_are_authority_pinned(self) -> None:
        raw = (
            APPLICATION_DIRECTORY / "link-proof-contract-v1.json"
        ).read_bytes()
        with self.assertRaisesRegex(
            VERIFIER.Refusal, "contract bytes changed"
        ):
            VERIFIER.validate_contract(raw + b"\n")

    def test_apple_map_binds_exact_provider_and_address(self) -> None:
        text = """\
# Path: /proof/linked-image
# Arch: arm64
# Object files:
[  0] linker synthesized
[  7] /proof/external-search-0-implementation.o
[  8] /proof/external-search-0-family-glue.o
# Sections:
# Address\tSize    \tSegment\tSection
0x100000400\t0x00000040\t__TEXT\t__text
# Symbols:
# Address\tSize    \tFile  Name
0x100000400\t0x00000020\t[  7] _fre_aot_search_entry_v1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
0x100000420\t0x00000020\t[  8] _fre_aot_search_span_glue_v1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
"""
        entry = (
            "fre_aot_search_entry_v1_"
            + "a" * 64
        )
        glue = "fre_aot_search_span_glue_v1_" + "a" * 64
        parsed = VERIFIER.parse_apple_link_map(text, {entry, glue})
        result = VERIFIER.exact_map_definition(
            parsed,
            entry,
            "/proof/external-search-0-implementation.o",
            0x100000400,
        )
        self.assertEqual(result.symbol, entry)

    def test_apple_duplicate_definition_refused(self) -> None:
        symbol = "fre_aot_search_entry_v1_" + "a" * 64
        definition = VERIFIER.MapDefinition(symbol, "/proof/object.o", 0x1000)
        with self.assertRaisesRegex(VERIFIER.Refusal, "2 times"):
            VERIFIER.exact_map_definition(
                {symbol: (definition, definition)},
                symbol,
                "/proof/object.o",
                0x1000,
            )

    def test_gnu_map_binds_nearest_candidate_provider(self) -> None:
        entry = "fre_aot_search_entry_v1_" + "b" * 64
        glue = "fre_aot_search_span_glue_v1_" + "b" * 64
        implementation = "/proof/external-search-0-implementation.o"
        glue_object = "/proof/external-search-0-family-glue.o"
        text = f"""\
.text.impl      0x0000000000401000 0x40 {implementation}
                0x0000000000401000 {entry}
.text.glue      0x0000000000401040 0x28 {glue_object}
                0x0000000000401040 {glue}
"""
        parsed = VERIFIER.parse_gnu_link_map(
            text, {implementation, glue_object}, {entry, glue}
        )
        VERIFIER.exact_map_definition(
            parsed, entry, implementation, 0x401000
        )
        VERIFIER.exact_map_definition(
            parsed, glue, glue_object, 0x401040
        )

    def test_gnu_stale_provider_refused(self) -> None:
        entry = "fre_aot_search_entry_v1_" + "c" * 64
        implementation = "/proof/external-search-0-implementation.o"
        text = (
            f".text 0x1000 0x20 {implementation}\n"
            "one\n"
            "two\n"
            "three\n"
            "four\n"
            f"0x1000 {entry}\n"
        )
        with self.assertRaisesRegex(VERIFIER.Refusal, "under one candidate"):
            VERIFIER.parse_gnu_link_map(text, {implementation}, {entry})

    def test_checked_in_macho_object_parses_and_arch_mutation_refuses(self) -> None:
        path = (
            REPO
            / "crates/fre-aot-count-compiler/evidence/"
            "c5-count-v2-candidate/implementation.o"
        )
        raw = path.read_bytes()
        parsed = VERIFIER.parse_macho(raw, 100_000, 100_000)
        self.assertEqual(parsed.kind, "macho-object")
        self.assertGreaterEqual(len(parsed.symbols), 3)
        changed = bytearray(raw)
        changed[4:8] = (0).to_bytes(4, "little")
        with self.assertRaisesRegex(VERIFIER.Refusal, "supported arm64"):
            VERIFIER.parse_macho(bytes(changed), 100_000, 100_000)

    def test_boolean_is_not_an_integer_receipt(self) -> None:
        self.assertFalse(VERIFIER.is_strict_int(True))
        self.assertTrue(VERIFIER.is_strict_int(1, 1))

    def test_zero_identity_is_refused(self) -> None:
        with self.assertRaises(VERIFIER.Refusal):
            VERIFIER.require_sha("0" * 64, "zero identity")


if __name__ == "__main__":
    unittest.main()
