#!/usr/bin/env python3
"""Structurally valid synthetic final-image tests for verify_linked_image.py."""

from __future__ import annotations

import hashlib
import struct
import tempfile
import unittest
from pathlib import Path

import verify_linked_image as linked
import verify_results as results


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.payload = bytes(range(32))
        metadata = bytearray((index * 7) & 0xFF for index in range(216))
        self.object = bytes((index * 11) & 0xFF for index in range(512))
        self.compile_identity = "2" * 64
        self.binding_identity = "a" * 64
        for value, offset in [
            ("5" * 64, 56),
            ("6" * 64, 88),
            (self.binding_identity, 120),
            (hashlib.sha256(self.payload).hexdigest(), 152),
            (self.compile_identity, 184),
        ]:
            metadata[offset : offset + linked.METADATA_IDENTITY_BYTES] = bytes.fromhex(
                value
            )
        self.metadata = bytes(metadata)
        self.text_command_offset = linked.MACH_HEADER_64_BYTES
        self.payload_section_offset = (
            self.text_command_offset + linked.SEGMENT_COMMAND_64_BYTES
        )
        self.neighbor_section_offset = (
            self.payload_section_offset + linked.SECTION_64_BYTES
        )
        self.zero_fill_section_offset = (
            self.neighbor_section_offset + linked.SECTION_64_BYTES
        )
        self.payload_offset = 0x280
        self.payload_address = 0x1280
        self.neighbor_offset = 0x2D0
        self.neighbor_address = 0x12D0
        self.zero_fill_address = 0x1300
        self.metadata_offset = 0x400
        self.metadata_address = 0x2400
        self.symbol_offset = 0x600
        self.receipt = self._receipt()
        self.executable = self._executable()
        self.paths = {
            name: root / name
            for name in [
                "receipt.tsv",
                "subject.o",
                "subject-bin",
                "subject.map",
                "nm.txt",
                "otool.txt",
            ]
        }
        self.receipt["object_path"] = str(self.paths["subject.o"])
        self._write()

    def _receipt(self) -> dict[str, str]:
        return {
            "schema": results.RECEIPT_SCHEMA,
            "subject_revision": "3" * 40,
            "benchmark_source_sha256": "1" * 64,
            "semantic_identity_bytes_hashed": "512",
            "semantic_identity": "4" * 64,
            "binding_identity": self.binding_identity,
            "compiler_receipt_identity": "b" * 64,
            "source_identity": "5" * 64,
            "artifact_identity": "6" * 64,
            "compile_identity": self.compile_identity,
            "object_identity": hashlib.sha256(self.object).hexdigest(),
            "payload_sha256": hashlib.sha256(self.payload).hexdigest(),
            "metadata_sha256": hashlib.sha256(self.metadata).hexdigest(),
            "literal_hex": "30313233343536373839616263646566",
            "literal_bytes": "16",
            "backend_version": "8",
            "output_kind": "3",
            "object_bytes": str(len(self.object)),
            "payload_bytes": str(len(self.payload)),
            "metadata_bytes": str(len(self.metadata)),
            "code_bytes": "16",
            "rodata_offset": "16",
            "rodata_bytes": "16",
            "entry_symbol": f"fre_aot_search_entry_v1_{self.compile_identity}",
            "payload_symbol": f"fre_aot_payload_v1_{self.compile_identity}",
            "metadata_symbol": f"fre_aot_metadata_v1_{self.compile_identity}",
            "object_path": "/placeholder",
            "link_map_path": "/private/tmp/subject.map",
            "target": "aarch64-apple-macos",
            "aot_authority": "benchmark-local-raw-abi-no-adoption",
            "qualification_state": "candidate",
            "production_activation": "absent",
        }

    @staticmethod
    def _fixed_name(value: str) -> bytes:
        encoded = value.encode("ascii")
        return encoded + bytes(16 - len(encoded))

    def _segment(
        self,
        name: str,
        vmaddr: int,
        vmsize: int,
        fileoff: int,
        filesize: int,
        protection: int,
        sections: tuple[tuple[str, int, int, int, int, int], ...],
    ) -> bytes:
        section_count = len(sections)
        command_size = (
            linked.SEGMENT_COMMAND_64_BYTES
            + section_count * linked.SECTION_64_BYTES
        )
        command = struct.pack(
            "<II16sQQQQiiII",
            linked.LC_SEGMENT_64,
            command_size,
            self._fixed_name(name),
            vmaddr,
            vmsize,
            fileoff,
            filesize,
            protection,
            protection,
            section_count,
            0,
        )
        for section_name, address, size, offset, alignment, flags in sections:
            command += struct.pack(
                "<16s16sQQIIIIIIII",
                self._fixed_name(section_name),
                self._fixed_name(name),
                address,
                size,
                offset,
                alignment,
                0,
                0,
                flags,
                0,
                0,
                0,
            )
        return command

    def _executable(self) -> bytearray:
        names = [
            "_" + self.receipt[field]
            for field in ["entry_symbol", "payload_symbol", "metadata_symbol"]
        ]
        strings = bytearray(b"\x00")
        string_indexes = []
        for name in names:
            string_indexes.append(len(strings))
            strings.extend(name.encode("ascii") + b"\x00")
        string_offset = self.symbol_offset + 3 * linked.NLIST_64_BYTES
        commands = [
            self._segment(
                "__TEXT",
                0x1000,
                0x340,
                0,
                0x300,
                linked.VM_PROT_READ | linked.VM_PROT_EXECUTE,
                (
                    (
                        "__fre_image",
                        self.payload_address,
                        len(self.payload),
                        self.payload_offset,
                        4,
                        0x10000400,
                    ),
                    (
                        "__text_neighbor",
                        self.neighbor_address,
                        16,
                        self.neighbor_offset,
                        4,
                        0,
                    ),
                    (
                        "__zero_probe",
                        self.zero_fill_address,
                        32,
                        0,
                        4,
                        1,
                    ),
                ),
            ),
            self._segment(
                "__FRE_CONST",
                self.metadata_address,
                len(self.metadata),
                self.metadata_offset,
                len(self.metadata),
                linked.VM_PROT_READ,
                (
                    (
                        "__fre_meta",
                        self.metadata_address,
                        len(self.metadata),
                        self.metadata_offset,
                        3,
                        0x10000000,
                    ),
                ),
            ),
            self._segment(
                "__LINKEDIT",
                0x3000,
                0x400,
                0x600,
                0x400,
                linked.VM_PROT_READ,
                (),
            ),
            struct.pack(
                "<IIIIII",
                linked.LC_SYMTAB,
                linked.SYMTAB_COMMAND_BYTES,
                self.symbol_offset,
                3,
                string_offset,
                len(strings),
            ),
        ]
        command_bytes = sum(map(len, commands))
        executable = bytearray(0xA00)
        struct.pack_into(
            "<IiiIIIII",
            executable,
            0,
            linked.MH_MAGIC_64,
            linked.CPU_TYPE_ARM64,
            0,
            linked.MH_EXECUTE,
            len(commands),
            command_bytes,
            0,
            0,
        )
        cursor = linked.MACH_HEADER_64_BYTES
        for command in commands:
            executable[cursor : cursor + len(command)] = command
            cursor += len(command)
        executable[
            self.payload_offset : self.payload_offset + len(self.payload)
        ] = self.payload
        executable[
            self.metadata_offset : self.metadata_offset + len(self.metadata)
        ] = self.metadata
        for index, (string_index, value, section) in enumerate(
            zip(
                string_indexes,
                [self.payload_address, self.payload_address, self.metadata_address],
                [1, 1, 4],
                strict=True,
            )
        ):
            struct.pack_into(
                "<IBBHQ",
                executable,
                self.symbol_offset + index * linked.NLIST_64_BYTES,
                string_index,
                linked.N_SECT | linked.N_EXT,
                section,
                0,
                value,
            )
        executable[string_offset : string_offset + len(strings)] = strings
        return executable

    def _write(self) -> None:
        self.paths["receipt.tsv"].write_text(
            "".join(
                f"{key}\t{self.receipt[key]}\n" for key in results.RECEIPT_KEYS
            ),
            encoding="ascii",
        )
        self.paths["subject.o"].write_bytes(self.object)
        self.paths["subject-bin"].write_bytes(self.executable)
        label = "[  7]"
        self.paths["subject.map"].write_text(
            f"{label} {self.receipt['object_path']}\n"
            + f"0x{self.payload_address:x} 0x20 {label} _{self.receipt['entry_symbol']}\n"
            + f"0x{self.payload_address:x} 0x20 {label} _{self.receipt['payload_symbol']}\n"
            + f"0x{self.metadata_address:x} 0xd8 {label} _{self.receipt['metadata_symbol']}\n",
            encoding="ascii",
        )
        self.paths["nm.txt"].write_text(
            f"{self.payload_address:016x} T _{self.receipt['entry_symbol']}\n"
            f"{self.payload_address:016x} S _{self.receipt['payload_symbol']}\n"
            f"{self.metadata_address:016x} S _{self.receipt['metadata_symbol']}\n",
            encoding="ascii",
        )
        self.paths["otool.txt"].write_text(
            f"""subject-bin:
Load command 0
      cmd LC_SEGMENT_64
  cmdsize 312
  segname __TEXT
   vmaddr 0x0000000000001000
   vmsize 0x0000000000000340
  fileoff 0
 filesize 768
  maxprot r-x
 initprot r-x
   nsects 3
Section
  sectname __fre_image
   segname __TEXT
      addr 0x{self.payload_address:016x}
      size 0x0000000000000020
    offset {self.payload_offset}
     align 4
Section
  sectname __text_neighbor
   segname __TEXT
      addr 0x{self.neighbor_address:016x}
      size 0x0000000000000010
    offset {self.neighbor_offset}
     align 4
Section
  sectname __zero_probe
   segname __TEXT
      addr 0x{self.zero_fill_address:016x}
      size 0x0000000000000020
    offset 0
     align 4
Load command 1
      cmd LC_SEGMENT_64
  cmdsize 152
  segname __FRE_CONST
   vmaddr 0x{self.metadata_address:016x}
   vmsize 0x00000000000000d8
  fileoff {self.metadata_offset}
 filesize 216
  maxprot r--
 initprot r--
   nsects 1
Section
  sectname __fre_meta
   segname __FRE_CONST
      addr 0x{self.metadata_address:016x}
      size 0x00000000000000d8
    offset {self.metadata_offset}
     align 3
""",
            encoding="ascii",
        )

    def verify(self):
        return linked.verify(
            self.paths["receipt.tsv"],
            self.paths["subject.o"],
            self.paths["subject-bin"],
            self.paths["subject.map"],
            self.paths["nm.txt"],
            self.paths["otool.txt"],
        )


class LinkedImageVerifierTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return Fixture(Path(temporary.name))

    def assert_rejected(self, operation) -> None:
        with self.assertRaises(results.VerificationError):
            operation()

    def test_exact_fixture_passes(self) -> None:
        fixture = self.fixture()
        receipt = dict(fixture.verify())
        self.assertEqual(receipt["overall"], "PASS")
        self.assertEqual(receipt["entry_address"], receipt["payload_address"])

    def test_nm_unprefixed_addresses_are_hexadecimal(self) -> None:
        fixture = self.fixture()
        symbols = [
            fixture.receipt["entry_symbol"],
            fixture.receipt["payload_symbol"],
            fixture.receipt["metadata_symbol"],
        ]
        addresses = linked.parse_nm(
            fixture.paths["nm.txt"].read_text(encoding="ascii"), symbols
        )
        self.assertEqual(addresses[symbols[0]], fixture.payload_address)
        self.assertEqual(addresses[symbols[2]], fixture.metadata_address)

    def test_final_byte_and_protection_tampers_fail(self) -> None:
        for kind in [
            "payload",
            "metadata",
            "direct-magic",
            "direct-cpu",
            "direct-file-type",
            "direct-command-size",
            "direct-protection",
            "direct-section-type",
            "direct-entry",
            "direct-symbol-type",
            "direct-symbol-section",
            "captured-protection",
            "provider",
            "captured-link-address",
            "captured-entry",
        ]:
            fixture = self.fixture()
            if kind == "payload":
                changed = bytearray(fixture.executable)
                changed[fixture.payload_offset] ^= 1
                fixture.paths["subject-bin"].write_bytes(changed)
            elif kind == "metadata":
                changed = bytearray(fixture.executable)
                changed[fixture.metadata_offset] ^= 1
                fixture.paths["subject-bin"].write_bytes(changed)
            elif kind == "direct-magic":
                changed = bytearray(fixture.executable)
                struct.pack_into("<I", changed, 0, 0)
                fixture.paths["subject-bin"].write_bytes(changed)
            elif kind == "direct-cpu":
                changed = bytearray(fixture.executable)
                struct.pack_into("<i", changed, 4, 7)
                fixture.paths["subject-bin"].write_bytes(changed)
            elif kind == "direct-file-type":
                changed = bytearray(fixture.executable)
                struct.pack_into("<I", changed, 12, 1)
                fixture.paths["subject-bin"].write_bytes(changed)
            elif kind == "direct-command-size":
                changed = bytearray(fixture.executable)
                struct.pack_into("<I", changed, 32 + 4, 7)
                fixture.paths["subject-bin"].write_bytes(changed)
            elif kind == "direct-protection":
                changed = bytearray(fixture.executable)
                struct.pack_into("<i", changed, 32 + 56, 7)
                fixture.paths["subject-bin"].write_bytes(changed)
            elif kind == "direct-section-type":
                changed = bytearray(fixture.executable)
                struct.pack_into("<I", changed, 32 + 72 + 64, 1)
                fixture.paths["subject-bin"].write_bytes(changed)
            elif kind == "direct-entry":
                changed = bytearray(fixture.executable)
                struct.pack_into(
                    "<Q",
                    changed,
                    fixture.symbol_offset + 8,
                    fixture.payload_address + 4,
                )
                fixture.paths["subject-bin"].write_bytes(changed)
            elif kind == "direct-symbol-type":
                changed = bytearray(fixture.executable)
                struct.pack_into(
                    "<B", changed, fixture.symbol_offset + 4, linked.N_EXT
                )
                fixture.paths["subject-bin"].write_bytes(changed)
            elif kind == "direct-symbol-section":
                changed = bytearray(fixture.executable)
                struct.pack_into("<B", changed, fixture.symbol_offset + 5, 2)
                fixture.paths["subject-bin"].write_bytes(changed)
            elif kind == "captured-protection":
                text = fixture.paths["otool.txt"].read_text(encoding="ascii")
                fixture.paths["otool.txt"].write_text(
                    text.replace("maxprot r-x", "maxprot rwx", 1),
                    encoding="ascii",
                )
            elif kind == "provider":
                text = fixture.paths["subject.map"].read_text(encoding="ascii")
                fixture.paths["subject.map"].write_text(
                    text.replace(str(fixture.paths["subject.o"]), "/tmp/wrong.o"),
                    encoding="ascii",
                )
            elif kind == "captured-link-address":
                text = fixture.paths["subject.map"].read_text(encoding="ascii")
                fixture.paths["subject.map"].write_text(
                    text.replace(
                        f"0x{fixture.payload_address:x}",
                        f"0x{fixture.payload_address + 4:x}",
                        1,
                    ),
                    encoding="ascii",
                )
            elif kind == "captured-entry":
                text = fixture.paths["nm.txt"].read_text(encoding="ascii")
                fixture.paths["nm.txt"].write_text(
                    text.replace(
                        f"{fixture.payload_address:016x} T",
                        f"{fixture.payload_address + 4:016x} T",
                    ),
                    encoding="ascii",
                )
            with self.subTest(kind=kind):
                self.assert_rejected(fixture.verify)

    def test_object_and_section_tampers_fail(self) -> None:
        fixture = self.fixture()
        fixture.receipt["binding_identity"] = "f" * 64
        fixture.paths["receipt.tsv"].write_text(
            "".join(
                f"{key}\t{fixture.receipt[key]}\n"
                for key in results.RECEIPT_KEYS
            ),
            encoding="ascii",
        )
        self.assert_rejected(fixture.verify)

        fixture = self.fixture()
        changed = bytearray(fixture.object)
        changed[0] ^= 1
        fixture.paths["subject.o"].write_bytes(changed)
        self.assert_rejected(fixture.verify)

        fixture = self.fixture()
        text = fixture.paths["otool.txt"].read_text(encoding="ascii")
        fixture.paths["otool.txt"].write_text(
            text.replace(
                "size 0x0000000000000020", "size 0x000000000000001f", 1
            ),
            encoding="ascii",
        )
        self.assert_rejected(fixture.verify)

        fixture = self.fixture()
        changed = bytearray(fixture.executable)
        struct.pack_into("<Q", changed, fixture.payload_section_offset + 40, 31)
        fixture.paths["subject-bin"].write_bytes(changed)
        self.assert_rejected(fixture.verify)

    def test_every_section_structure_and_exact_symbol_type(self) -> None:
        cases = [
            "vm-overlap",
            "file-overlap-alias",
            "displacement",
            "vm-alignment",
            "file-alignment",
            "private-external-symbol",
        ]
        for kind in cases:
            fixture = self.fixture()
            changed = bytearray(fixture.executable)
            expected_error = ""
            if kind == "vm-overlap":
                struct.pack_into(
                    "<Q",
                    changed,
                    fixture.zero_fill_section_offset + 32,
                    fixture.payload_address + 16,
                )
                expected_error = "overlap in VM"
            elif kind == "file-overlap-alias":
                struct.pack_into(
                    "<Q",
                    changed,
                    fixture.neighbor_section_offset + 32,
                    fixture.payload_address,
                )
                struct.pack_into(
                    "<I",
                    changed,
                    fixture.neighbor_section_offset + 48,
                    fixture.payload_offset,
                )
                expected_error = "overlap in file"
            elif kind == "displacement":
                struct.pack_into(
                    "<I",
                    changed,
                    fixture.neighbor_section_offset + 48,
                    fixture.neighbor_offset + 16,
                )
                expected_error = "VM/file displacement mismatch"
            elif kind == "vm-alignment":
                struct.pack_into(
                    "<I", changed, fixture.neighbor_section_offset + 52, 5
                )
                expected_error = "misaligned VM address"
            elif kind == "file-alignment":
                struct.pack_into(
                    "<Q",
                    changed,
                    fixture.neighbor_section_offset + 32,
                    fixture.neighbor_address - 16,
                )
                struct.pack_into(
                    "<I", changed, fixture.neighbor_section_offset + 52, 5
                )
                expected_error = "misaligned file offset"
            elif kind == "private-external-symbol":
                struct.pack_into(
                    "<B",
                    changed,
                    fixture.symbol_offset + 4,
                    linked.N_SECT | linked.N_EXT | linked.N_PEXT,
                )
                expected_error = "not one exact external N_SECT definition"
            else:
                raise AssertionError(f"unhandled structural tamper {kind}")
            fixture.paths["subject-bin"].write_bytes(changed)
            with self.subTest(kind=kind):
                with self.assertRaisesRegex(results.VerificationError, expected_error):
                    fixture.verify()


if __name__ == "__main__":
    unittest.main()
