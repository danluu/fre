#!/usr/bin/env python3
"""Focused synthetic tests for the Count-v3 linked-expectation auditor."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import struct
import tempfile
import unittest
from pathlib import Path


AUDIT_PATH = Path(__file__).with_name("verify_linux_expectations.py")
AUDIT_SPEC = importlib.util.spec_from_file_location(
    "verify_linux_expectations", AUDIT_PATH
)
assert AUDIT_SPEC is not None and AUDIT_SPEC.loader is not None
audit = importlib.util.module_from_spec(AUDIT_SPEC)
AUDIT_SPEC.loader.exec_module(audit)


SYMBOL = (
    "fre_aot_count_expectation_v3_"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)
EXPECTATION = bytes([0x5A]) * audit.EXPECTATION_BYTES
ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
SECTION_HEADER = struct.Struct("<IIQQQQIIQQ")
SYMBOL_ROW = struct.Struct("<IBBHQQ")


def fixture_elf(
    *,
    expectation_load_flags: int = audit.PF_R,
    executable_page_overlap: bool = False,
) -> bytes:
    program_offset = ELF_HEADER.size
    rodata_offset = 0x1000
    rodata_address = 0x401000
    text_offset = 0x1800 if executable_page_overlap else 0x2000
    text_address = 0x401800 if executable_page_overlap else 0x402000
    symbol_offset = 0x2010
    string_table = b"\0" + SYMBOL.encode("ascii") + b"\0"
    string_offset = symbol_offset + SYMBOL_ROW.size * 2
    section_names = b"\0.rodata\0.text\0.symtab\0.strtab\0.shstrtab\0"
    section_names_offset = string_offset + len(string_table)
    section_offset = (section_names_offset + len(section_names) + 7) & -8
    file_bytes = section_offset + SECTION_HEADER.size * 6
    result = bytearray(file_bytes)

    result[: ELF_HEADER.size] = ELF_HEADER.pack(
        b"\x7fELF\x02\x01\x01" + bytes(9),
        audit.ET_EXEC,
        audit.EM_AARCH64,
        1,
        text_address,
        program_offset,
        section_offset,
        0,
        ELF_HEADER.size,
        PROGRAM_HEADER.size,
        3,
        SECTION_HEADER.size,
        6,
        5,
    )
    programs = (
        (
            audit.PT_LOAD,
            expectation_load_flags,
            0,
            0x400000,
            0x400000,
            rodata_offset + len(EXPECTATION),
            rodata_offset + len(EXPECTATION),
            0x1000,
        ),
        (
            audit.PT_LOAD,
            audit.PF_R | audit.PF_X,
            text_offset,
            text_address,
            text_address,
            4,
            4,
            0x1000,
        ),
        (
            audit.PT_GNU_STACK,
            audit.PF_R | audit.PF_W,
            0,
            0,
            0,
            0,
            0,
            0,
        ),
    )
    for ordinal, program in enumerate(programs):
        start = program_offset + ordinal * PROGRAM_HEADER.size
        result[start : start + PROGRAM_HEADER.size] = PROGRAM_HEADER.pack(*program)
    result[rodata_offset : rodata_offset + len(EXPECTATION)] = EXPECTATION
    result[text_offset : text_offset + 4] = b"\xc0\x03\x5f\xd6"
    definition = SYMBOL_ROW.pack(
        1,
        audit.STT_OBJECT,
        audit.STV_HIDDEN,
        1,
        rodata_address,
        len(EXPECTATION),
    )
    result[
        symbol_offset + SYMBOL_ROW.size : symbol_offset + SYMBOL_ROW.size * 2
    ] = definition
    result[string_offset : string_offset + len(string_table)] = string_table
    result[
        section_names_offset : section_names_offset + len(section_names)
    ] = section_names

    sections = (
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (
            1,
            1,
            audit.SHF_ALLOC,
            rodata_address,
            rodata_offset,
            len(EXPECTATION),
            0,
            0,
            8,
            0,
        ),
        (
            9,
            1,
            audit.SHF_ALLOC | audit.SHF_EXECINSTR,
            text_address,
            text_offset,
            4,
            0,
            0,
            4,
            0,
        ),
        (
            15,
            audit.SHT_SYMTAB,
            0,
            0,
            symbol_offset,
            SYMBOL_ROW.size * 2,
            4,
            1,
            8,
            SYMBOL_ROW.size,
        ),
        (23, audit.SHT_STRTAB, 0, 0, string_offset, len(string_table), 0, 0, 1, 0),
        (
            31,
            audit.SHT_STRTAB,
            0,
            0,
            section_names_offset,
            len(section_names),
            0,
            0,
            1,
            0,
        ),
    )
    for ordinal, section in enumerate(sections):
        start = section_offset + ordinal * SECTION_HEADER.size
        result[start : start + SECTION_HEADER.size] = SECTION_HEADER.pack(*section)
    return bytes(result)


def fixture_registry(digest: str | None = None) -> bytes:
    value = {
        "schema": "fre.optimizing-count-v3.compiled-artifact-registry.v2",
        "target_triple": audit.TARGET_TRIPLE,
        "object_format": audit.OBJECT_FORMAT,
        "distinct_artifacts": 1,
        "compiled_patterns": [
            {
                "engines": [
                    {
                        "engine": "count-v3-aot",
                        "expectation_symbol": SYMBOL,
                        "expectation_bytes_sha256": (
                            digest or hashlib.sha256(EXPECTATION).hexdigest()
                        ),
                    }
                ]
            }
        ],
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


class LinkedExpectationAuditTests(unittest.TestCase):
    def run_fixture(
        self, runner: bytes, registry: bytes | None = None
    ) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner_path = root / "runner"
            registry_path = root / "compiled-artifacts.json"
            runner_path.write_bytes(runner)
            registry_path.write_bytes(registry or fixture_registry())
            return audit.verify(runner_path, registry_path)

    def test_accepts_authenticated_expectation_in_r_only_load(self) -> None:
        observation = self.run_fixture(fixture_elf())
        self.assertEqual(observation["status"], "pass")
        self.assertEqual(observation["expectation_count"], 1)
        layout = observation["expectations"][0]
        self.assertEqual(layout["section"], ".rodata")
        self.assertEqual(layout["load_flags"], audit.PF_R)

    def test_rejects_expectation_in_executable_load(self) -> None:
        with self.assertRaisesRegex(audit.Refusal, "PT_LOAD is not exactly R-only"):
            self.run_fixture(
                fixture_elf(expectation_load_flags=audit.PF_R | audit.PF_X)
            )

    def test_rejects_executable_mapping_of_same_page(self) -> None:
        with self.assertRaisesRegex(audit.Refusal, "overlaps an expectation page"):
            self.run_fixture(fixture_elf(executable_page_overlap=True))

    def test_rejects_linked_bytes_that_differ_from_registry(self) -> None:
        with self.assertRaisesRegex(audit.Refusal, "linked bytes differ"):
            self.run_fixture(fixture_elf(), fixture_registry("0" * 64))

    def test_rejects_noncanonical_expectation_symbol(self) -> None:
        registry = json.loads(fixture_registry())
        registry["compiled_patterns"][0]["engines"][0][
            "expectation_symbol"
        ] = "fre_aot_count_expectation_v3_not_canonical"
        with self.assertRaisesRegex(audit.Refusal, "invalid expectation symbol"):
            self.run_fixture(
                fixture_elf(),
                json.dumps(registry, separators=(",", ":")).encode("ascii"),
            )


if __name__ == "__main__":
    unittest.main()
