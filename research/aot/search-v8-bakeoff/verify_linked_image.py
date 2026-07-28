#!/usr/bin/env python3
"""Verify one final arm64 Mach-O retained Search V8 provider without executing it."""

from __future__ import annotations

import hashlib
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from verify_common import (
    MAX_OBJECT_BYTES,
    MAX_TEXT_BYTES,
    VerificationError,
    fail,
    parse_receipt,
    parse_tsv,
    regular_file,
    strict_text,
)

MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024
MAX_CAPTURE_BYTES = 8 * 1024 * 1024
MAX_LOAD_COMMAND_BYTES = 16 * 1024 * 1024
MAX_LOAD_COMMANDS = 4096
MAX_SECTIONS = 255
MAX_SYMBOLS = 2_000_000
MAX_STRING_TABLE_BYTES = 16 * 1024 * 1024
LINKED_SCHEMA = "fre-search-v8-bakeoff-linked-image-v2"
LINKED_KEYS = [
    "schema",
    "subject_revision",
    "build_receipt_sha256",
    "compile_identity",
    "object_identity",
    "executable_sha256",
    "link_map_sha256",
    "nm_sha256",
    "otool_sha256",
    "payload_sha256",
    "metadata_sha256",
    "architecture",
    "file_type",
    "entry_address",
    "payload_address",
    "metadata_address",
    "text_protection",
    "metadata_protection",
    "symbol_source",
    "link_map_role",
    "provider",
    "aot_authority",
    "production_activation",
    "overall",
]

MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
MH_EXECUTE = 2
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
VM_PROT_READ = 0x1
VM_PROT_EXECUTE = 0x4
N_EXT = 0x01
N_PEXT = 0x10
N_SECT = 0x0E
SECTION_TYPE = 0x000000FF
ZERO_FILL_SECTION_TYPES = {0x1, 0xC, 0x12}
MACH_HEADER_64_BYTES = 32
SEGMENT_COMMAND_64_BYTES = 72
SECTION_64_BYTES = 80
SYMTAB_COMMAND_BYTES = 24
NLIST_64_BYTES = 16
U64_MAX = (1 << 64) - 1
METADATA_IDENTITY_BYTES = 32
METADATA_IDENTITY_FIELDS = [
    ("source_identity", 56),
    ("artifact_identity", 88),
    ("binding_identity", 120),
    ("payload_sha256", 152),
    ("compile_identity", 184),
]


@dataclass(frozen=True)
class MachSection:
    segment: str
    section: str
    ordinal: int
    address: int
    size: int
    offset: int
    alignment: int
    flags: int


@dataclass(frozen=True)
class MachSegment:
    name: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int
    maxprot: int
    initprot: int
    sections: tuple[MachSection, ...]


@dataclass(frozen=True)
class MachSymbol:
    name: str
    value: int
    section_ordinal: int


@dataclass(frozen=True)
class MachImage:
    segments: Mapping[str, MachSegment]
    payload_section: MachSection
    metadata_section: MachSection
    symbols: Mapping[str, MachSymbol]


def section_is_file_backed(section: MachSection) -> bool:
    return (section.flags & SECTION_TYPE) not in ZERO_FILL_SECTION_TYPES


def positive_ranges_overlap(
    left_start: int, left_length: int, right_start: int, right_length: int
) -> bool:
    return (
        left_length > 0
        and right_length > 0
        and left_start < right_start + right_length
        and right_start < left_start + left_length
    )


@dataclass(frozen=True)
class CapturedSection:
    segment: str
    section: str
    address: int
    size: int
    offset: int


@dataclass(frozen=True)
class CapturedSegment:
    name: str
    maxprot: str
    initprot: str
    sections: tuple[CapturedSection, ...]


def checked_end(start: int, length: int, limit: int, name: str) -> int:
    if start < 0 or length < 0 or start > limit or length > limit - start:
        fail(f"{name} exceeds its bounded container")
    return start + length


def checked_u64_end(start: int, length: int, name: str) -> int:
    if start < 0 or length < 0 or start > U64_MAX or length > U64_MAX - start:
        fail(f"{name} overflows u64")
    return start + length


def fixed_name(raw: bytes, name: str) -> str:
    terminator = raw.find(b"\x00")
    if terminator < 0:
        terminator = len(raw)
    elif any(raw[terminator:]):
        fail(f"{name} has nonzero bytes after its terminator")
    value = raw[:terminator]
    if not value:
        fail(f"{name} is empty")
    try:
        return value.decode("ascii")
    except UnicodeDecodeError as error:
        fail(f"{name} is not ASCII: {error}")


def parse_macho(executable: bytes, symbols: Sequence[str]) -> MachImage:
    if len(symbols) != 3 or len(set(symbols)) != 3:
        fail("linked-image verifier requires three distinct receipt symbols")
    if len(executable) < MACH_HEADER_64_BYTES:
        fail("final file is shorter than one mach_header_64")
    (
        magic,
        cpu_type,
        _cpu_subtype,
        file_type,
        command_count,
        command_bytes,
        _flags,
        _reserved,
    ) = struct.unpack_from("<IiiIIIII", executable)
    if magic != MH_MAGIC_64:
        fail("final file is not one little-endian Mach-O 64 image")
    if cpu_type != CPU_TYPE_ARM64:
        fail("final Mach-O CPU type is not ARM64")
    if file_type != MH_EXECUTE:
        fail("final Mach-O file type is not MH_EXECUTE")
    if not 1 <= command_count <= MAX_LOAD_COMMANDS:
        fail("final Mach-O load-command count is outside the verifier bound")
    if (
        command_bytes < command_count * 8
        or command_bytes > MAX_LOAD_COMMAND_BYTES
    ):
        fail("final Mach-O load-command bytes are outside the verifier bound")
    commands_end = checked_end(
        MACH_HEADER_64_BYTES,
        command_bytes,
        len(executable),
        "Mach-O load-command region",
    )

    cursor = MACH_HEADER_64_BYTES
    segments: dict[str, MachSegment] = {}
    ordered_sections: list[MachSection] = []
    symtab: tuple[int, int, int, int] | None = None
    for _ in range(command_count):
        checked_end(cursor, 8, commands_end, "Mach-O load-command header")
        command, command_size = struct.unpack_from("<II", executable, cursor)
        if command_size < 8 or command_size % 8:
            fail("Mach-O load command has invalid cmdsize")
        next_cursor = checked_end(
            cursor, command_size, commands_end, "Mach-O load command"
        )
        if command == LC_SEGMENT_64:
            if command_size < SEGMENT_COMMAND_64_BYTES:
                fail("LC_SEGMENT_64 is truncated")
            (
                parsed_command,
                parsed_size,
                raw_name,
                vmaddr,
                vmsize,
                fileoff,
                filesize,
                maxprot,
                initprot,
                section_count,
                _segment_flags,
            ) = struct.unpack_from("<II16sQQQQiiII", executable, cursor)
            if parsed_command != command or parsed_size != command_size:
                fail("LC_SEGMENT_64 header changed during parsing")
            expected_size = SEGMENT_COMMAND_64_BYTES + section_count * SECTION_64_BYTES
            if expected_size != command_size:
                fail("LC_SEGMENT_64 cmdsize does not match nsects")
            segment_name = fixed_name(raw_name, "segment name")
            if segment_name in segments:
                fail(f"duplicate LC_SEGMENT_64 {segment_name}")
            segment_vm_end = checked_u64_end(
                vmaddr, vmsize, f"{segment_name} VM range"
            )
            segment_file_end = checked_end(
                fileoff, filesize, len(executable), f"{segment_name} file range"
            )
            sections = []
            section_cursor = cursor + SEGMENT_COMMAND_64_BYTES
            for _section_index in range(section_count):
                (
                    raw_section_name,
                    raw_segment_name,
                    address,
                    size,
                    offset,
                    alignment,
                    relocation_offset,
                    relocation_count,
                    section_flags,
                    _reserved1,
                    _reserved2,
                    _reserved3,
                ) = struct.unpack_from(
                    "<16s16sQQIIIIIIII", executable, section_cursor
                )
                section_cursor += SECTION_64_BYTES
                section_name = fixed_name(raw_section_name, "section name")
                declared_segment = fixed_name(
                    raw_segment_name, f"{segment_name},{section_name} segment name"
                )
                if declared_segment != segment_name:
                    fail("section segname differs from containing segment")
                section_end = checked_u64_end(
                    address, size, f"{segment_name},{section_name} VM range"
                )
                if address < vmaddr or section_end > segment_vm_end:
                    fail(f"{segment_name},{section_name} exceeds its segment VM range")
                if alignment > 63:
                    fail(f"{segment_name},{section_name} has invalid alignment")
                alignment_bytes = 1 << alignment
                if address % alignment_bytes:
                    fail(f"{segment_name},{section_name} has a misaligned VM address")
                if relocation_count:
                    checked_end(
                        relocation_offset,
                        relocation_count * 8,
                        len(executable),
                        f"{segment_name},{section_name} relocations",
                    )
                section_type = section_flags & SECTION_TYPE
                file_backed = section_type not in ZERO_FILL_SECTION_TYPES
                if file_backed:
                    if offset % alignment_bytes:
                        fail(f"{segment_name},{section_name} has a misaligned file offset")
                    section_file_end = checked_end(
                        offset,
                        size,
                        len(executable),
                        f"{segment_name},{section_name} file range",
                    )
                    if offset < fileoff or section_file_end > segment_file_end:
                        fail(
                            f"{segment_name},{section_name} exceeds its segment file range"
                        )
                    if address - vmaddr != offset - fileoff:
                        fail(
                            f"{segment_name},{section_name} VM/file displacement mismatch"
                        )
                section = MachSection(
                    segment=segment_name,
                    section=section_name,
                    ordinal=len(ordered_sections) + 1,
                    address=address,
                    size=size,
                    offset=offset,
                    alignment=alignment,
                    flags=section_flags,
                )
                ordered_sections.append(section)
                if len(ordered_sections) > MAX_SECTIONS:
                    fail("final Mach-O section count exceeds the verifier bound")
                sections.append(section)
            for index, left in enumerate(sections):
                for right in sections[index + 1 :]:
                    if (
                        section_is_file_backed(left)
                        and section_is_file_backed(right)
                        and positive_ranges_overlap(
                            left.offset, left.size, right.offset, right.size
                        )
                    ):
                        fail(
                            f"{segment_name} sections {left.section} and "
                            f"{right.section} overlap in file"
                        )
                    if positive_ranges_overlap(
                        left.address, left.size, right.address, right.size
                    ):
                        fail(
                            f"{segment_name} sections {left.section} and "
                            f"{right.section} overlap in VM"
                        )
            segments[segment_name] = MachSegment(
                name=segment_name,
                vmaddr=vmaddr,
                vmsize=vmsize,
                fileoff=fileoff,
                filesize=filesize,
                maxprot=maxprot,
                initprot=initprot,
                sections=tuple(sections),
            )
        elif command == LC_SYMTAB:
            if command_size != SYMTAB_COMMAND_BYTES or symtab is not None:
                fail("final Mach-O must contain exactly one canonical LC_SYMTAB")
            (
                _parsed_command,
                _parsed_size,
                symbol_offset,
                symbol_count,
                string_offset,
                string_size,
            ) = struct.unpack_from("<IIIIII", executable, cursor)
            symtab = (symbol_offset, symbol_count, string_offset, string_size)
        cursor = next_cursor
    if cursor != commands_end:
        fail("Mach-O load-command traversal did not consume sizeofcmds")
    if "__TEXT" not in segments or "__FRE_CONST" not in segments:
        fail("final Mach-O omits required segments")
    segment_values = list(segments.values())
    for index, left in enumerate(segment_values):
        for right in segment_values[index + 1 :]:
            if left.filesize and right.filesize:
                left_end = left.fileoff + left.filesize
                right_end = right.fileoff + right.filesize
                if not (left_end <= right.fileoff or right_end <= left.fileoff):
                    fail(f"Mach-O segments {left.name} and {right.name} overlap in file")
            if left.vmsize and right.vmsize:
                left_end = left.vmaddr + left.vmsize
                right_end = right.vmaddr + right.vmsize
                if not (left_end <= right.vmaddr or right_end <= left.vmaddr):
                    fail(f"Mach-O segments {left.name} and {right.name} overlap in VM")
    text_segment = segments["__TEXT"]
    const_segment = segments["__FRE_CONST"]
    if (
        text_segment.maxprot != (VM_PROT_READ | VM_PROT_EXECUTE)
        or text_segment.initprot != (VM_PROT_READ | VM_PROT_EXECUTE)
    ):
        fail("__TEXT is not max/current RX")
    if (
        const_segment.maxprot != VM_PROT_READ
        or const_segment.initprot != VM_PROT_READ
    ):
        fail("__FRE_CONST is not max/current R--")

    def exact_section(segment: str, section: str) -> MachSection:
        matches = [
            item
            for item in ordered_sections
            if item.segment == segment and item.section == section
        ]
        if len(matches) != 1:
            fail(f"expected exactly one {segment},{section}, found {len(matches)}")
        if (matches[0].flags & SECTION_TYPE) in ZERO_FILL_SECTION_TYPES:
            fail(f"{segment},{section} is not backed by final-file bytes")
        return matches[0]

    payload_section = exact_section("__TEXT", "__fre_image")
    metadata_section = exact_section("__FRE_CONST", "__fre_meta")
    for target in [payload_section, metadata_section]:
        if target.size == 0 or (target.flags & SECTION_TYPE) != 0:
            fail(f"{target.segment},{target.section} is not nonempty S_REGULAR")
        if target.offset < commands_end:
            fail(f"{target.segment},{target.section} overlaps Mach-O headers")
    payload_end = checked_end(
        payload_section.offset,
        payload_section.size,
        len(executable),
        "linked payload section",
    )
    metadata_end = checked_end(
        metadata_section.offset,
        metadata_section.size,
        len(executable),
        "linked metadata section",
    )
    if not (
        payload_end <= metadata_section.offset
        or metadata_end <= payload_section.offset
    ):
        fail("linked payload and metadata sections overlap")
    if symtab is None:
        fail("final Mach-O omits LC_SYMTAB")
    symbol_offset, symbol_count, string_offset, string_size = symtab
    if symbol_count > MAX_SYMBOLS or not 1 <= string_size <= MAX_STRING_TABLE_BYTES:
        fail("final Mach-O symbol or string table exceeds the verifier bound")
    if symbol_offset % 8:
        fail("Mach-O symbol table is not naturally aligned")
    checked_end(
        symbol_offset,
        symbol_count * NLIST_64_BYTES,
        len(executable),
        "Mach-O symbol table",
    )
    string_end = checked_end(
        string_offset, string_size, len(executable), "Mach-O string table"
    )
    symbol_end = symbol_offset + symbol_count * NLIST_64_BYTES
    if not (symbol_end <= string_offset or string_end <= symbol_offset):
        fail("Mach-O symbol and string tables overlap")
    linkedit = segments.get("__LINKEDIT")
    if linkedit is None:
        fail("final Mach-O omits __LINKEDIT")
    linkedit_end = linkedit.fileoff + linkedit.filesize
    if (
        symbol_offset < linkedit.fileoff
        or symbol_end > linkedit_end
        or string_offset < linkedit.fileoff
        or string_end > linkedit_end
    ):
        fail("Mach-O symbol or string table is outside __LINKEDIT")
    strings = executable[string_offset:string_end]
    if strings[0] != 0:
        fail("Mach-O string table does not begin with the empty string")
    expected_names = {f"_{symbol}": symbol for symbol in symbols}
    found: dict[str, list[MachSymbol]] = {symbol: [] for symbol in symbols}
    for index in range(symbol_count):
        entry_offset = symbol_offset + index * NLIST_64_BYTES
        string_index, symbol_type, section_ordinal, _description, value = (
            struct.unpack_from("<IBBHQ", executable, entry_offset)
        )
        if string_index >= len(strings):
            fail("Mach-O symbol has an out-of-range string-table index")
        terminator = strings.find(b"\x00", string_index)
        if terminator < 0:
            fail("Mach-O symbol name is not NUL terminated")
        try:
            name = strings[string_index:terminator].decode("ascii")
        except UnicodeDecodeError as error:
            fail(f"Mach-O symbol name is not ASCII: {error}")
        expected = expected_names.get(name)
        if expected is None:
            continue
        if (
            symbol_type != (N_SECT | N_EXT)
            or section_ordinal == 0
            or section_ordinal > len(ordered_sections)
        ):
            fail(
                f"final Mach-O symbol {name} is not one exact external "
                "N_SECT definition"
            )
        found[expected].append(
            MachSymbol(
                name=expected,
                value=value,
                section_ordinal=section_ordinal,
            )
        )
    resolved: dict[str, MachSymbol] = {}
    for symbol, matches in found.items():
        if len(matches) != 1:
            fail(f"final Mach-O defines {symbol} {len(matches)} times")
        resolved[symbol] = matches[0]
    expected_sections = {
        symbols[0]: payload_section,
        symbols[1]: payload_section,
        symbols[2]: metadata_section,
    }
    for symbol, section in expected_sections.items():
        resolved_symbol = resolved[symbol]
        if (
            resolved_symbol.section_ordinal != section.ordinal
            or resolved_symbol.value != section.address
        ):
            fail(f"final Mach-O symbol {symbol} does not begin its exact section")
    if resolved[symbols[0]].value != resolved[symbols[1]].value:
        fail("entry and payload symbols do not share the authenticated entry offset")
    return MachImage(
        segments=segments,
        payload_section=payload_section,
        metadata_section=metadata_section,
        symbols=resolved,
    )


def otool_hex(value: str, name: str) -> int:
    if not re.fullmatch(r"0x[0-9a-fA-F]{1,16}", value):
        fail(f"{name} is not one canonical otool hexadecimal field: {value!r}")
    return int(value, 16)


def otool_decimal(value: str, name: str) -> int:
    if not re.fullmatch(r"(?:0|[1-9][0-9]{0,19})", value):
        fail(f"{name} is not one canonical otool decimal field: {value!r}")
    result = int(value, 10)
    if result > U64_MAX:
        fail(f"{name} is outside u64")
    return result


def protection(value: str, name: str) -> int:
    named = {"r-x": VM_PROT_READ | VM_PROT_EXECUTE, "r--": VM_PROT_READ}
    if value in named:
        return named[value]
    if not re.fullmatch(r"0x[0-9a-fA-F]{8}", value):
        fail(f"{name} is not one canonical protection")
    return int(value, 16)


def unique_field(record: str, name: str) -> str:
    values = []
    for line in record.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0] == name:
            values.append(fields[1])
    if len(values) != 1:
        fail(f"otool record has {len(values)} {name!r} fields")
    return values[0]


def parse_otool(text: str) -> dict[str, CapturedSegment]:
    if "\x00" in text or "\r" in text:
        fail("otool capture is not canonical text")
    commands = text.split("Load command ")
    segments: dict[str, CapturedSegment] = {}
    for command in commands[1:]:
        before_sections = command.split("Section", 1)[0]
        if not any(
            line.split() == ["cmd", "LC_SEGMENT_64"]
            for line in before_sections.splitlines()
        ):
            continue
        name = unique_field(before_sections, "segname")
        if name in segments:
            fail(f"duplicate captured LC_SEGMENT_64 {name}")
        maxprot = unique_field(before_sections, "maxprot")
        initprot = unique_field(before_sections, "initprot")
        sections = []
        for section_record in command.split("Section")[1:]:
            section = unique_field(section_record, "sectname")
            segment = unique_field(section_record, "segname")
            if segment != name:
                fail("captured section segname differs from containing segment")
            sections.append(
                CapturedSection(
                    segment=segment,
                    section=section,
                    address=otool_hex(
                        unique_field(section_record, "addr"), "section addr"
                    ),
                    size=otool_hex(
                        unique_field(section_record, "size"), "section size"
                    ),
                    offset=otool_decimal(
                        unique_field(section_record, "offset"), "section offset"
                    ),
                )
            )
        segments[name] = CapturedSegment(name, maxprot, initprot, tuple(sections))
    if "__TEXT" not in segments or "__FRE_CONST" not in segments:
        fail("otool capture omits required segments")
    return segments


def exact_captured_section(
    segments: Mapping[str, CapturedSegment], segment: str, section: str
) -> CapturedSection:
    matches = [
        item
        for candidate in segments.values()
        for item in candidate.sections
        if item.segment == segment and item.section == section
    ]
    if len(matches) != 1:
        fail(f"expected exactly one captured {segment},{section}, found {len(matches)}")
    return matches[0]


def corroborate_otool(
    captured: Mapping[str, CapturedSegment], direct: MachImage
) -> None:
    for segment_name in ["__TEXT", "__FRE_CONST"]:
        captured_segment = captured[segment_name]
        direct_segment = direct.segments[segment_name]
        if (
            protection(captured_segment.maxprot, "captured maxprot")
            != direct_segment.maxprot
            or protection(captured_segment.initprot, "captured initprot")
            != direct_segment.initprot
        ):
            fail(f"otool protection differs from final bytes for {segment_name}")
    for direct_section in [direct.payload_section, direct.metadata_section]:
        captured_section = exact_captured_section(
            captured, direct_section.segment, direct_section.section
        )
        if (
            captured_section.address,
            captured_section.size,
            captured_section.offset,
        ) != (
            direct_section.address,
            direct_section.size,
            direct_section.offset,
        ):
            fail(
                f"otool section fields differ from final bytes for "
                f"{direct_section.segment},{direct_section.section}"
            )


def parse_nm(text: str, symbols: Sequence[str]) -> dict[str, int]:
    expected = {f"_{symbol}": symbol for symbol in symbols}
    found: dict[str, list[int]] = {symbol: [] for symbol in symbols}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 3 or fields[-1] not in expected:
            continue
        address_text = fields[0]
        if not re.fullmatch(r"[0-9a-fA-F]{1,16}", address_text):
            fail(f"nm address is invalid for {fields[-1]}")
        found[expected[fields[-1]]].append(int(address_text, 16))
    output = {}
    for symbol, addresses in found.items():
        if len(addresses) != 1:
            fail(f"nm defines {symbol} {len(addresses)} times")
        output[symbol] = addresses[0]
    return output


def provider_label(link_map: str, expected_path: str) -> str:
    labels = []
    for line in link_map.splitlines():
        match = re.match(r"^(\[[^]\r\n]{1,32}\])\s+(.+)$", line)
        if match and match.group(2) == expected_path:
            labels.append(match.group(1))
    if len(labels) != 1:
        fail(f"link map names expected object provider {len(labels)} times")
    return labels[0]


def corroborate_link_map(
    link_map: str,
    object_path: str,
    symbols: Sequence[str],
    direct_addresses: Mapping[str, int],
) -> None:
    label = provider_label(link_map, object_path)
    for symbol in symbols:
        mach_symbol = f"_{symbol}"
        definitions = [
            line
            for line in link_map.splitlines()
            if line.split() and line.split()[-1] == mach_symbol
        ]
        if len(definitions) != 1:
            fail(f"link map defines {symbol} {len(definitions)} times")
        fields = definitions[0].split()
        if not re.fullmatch(r"0x[0-9a-fA-F]{1,16}", fields[0]):
            fail(f"link-map address for {symbol} is not canonical hexadecimal")
        if int(fields[0], 16) != direct_addresses[symbol]:
            fail(f"link-map address differs from final bytes for {symbol}")
        if label not in definitions[0].split() and label not in definitions[0]:
            fail(f"{symbol} came from an unexpected corroborating link-map provider")


def checked_slice(
    executable: bytes, section: MachSection, expected_length: int, name: str
) -> bytes:
    if section.size != expected_length:
        fail(f"{name} section contains extra or missing bytes")
    end = checked_end(section.offset, section.size, len(executable), name)
    return executable[section.offset:end]


def digest(bytes_value: bytes) -> str:
    return hashlib.sha256(bytes_value).hexdigest()


def verify_metadata_identities(metadata: bytes, receipt: Mapping[str, str]) -> None:
    for field, offset in METADATA_IDENTITY_FIELDS:
        end = offset + METADATA_IDENTITY_BYTES
        if metadata[offset:end].hex() != receipt[field]:
            fail(f"linked metadata {field} differs from the compiler build receipt")


def linked_receipt_bytes(rows: Sequence[tuple[str, str]]) -> bytes:
    if [key for key, _value in rows] != LINKED_KEYS:
        fail("linked-image receipt keys are not canonical")
    output = []
    for key, value in rows:
        if not key or not value or "\t" in key + value or "\n" in key + value:
            fail("linked-image receipt contains a noncanonical value")
        output.append(f"{key}\t{value}\n")
    return "".join(output).encode("ascii")


def parse_linked_receipt(path: Path) -> dict[str, str]:
    return parse_tsv(path, LINKED_KEYS)


def verify(
    receipt_path: Path,
    object_path: Path,
    executable_path: Path,
    link_map_path: Path,
    nm_path: Path,
    otool_path: Path,
) -> list[tuple[str, str]]:
    receipt = parse_receipt(receipt_path)
    receipt_bytes = regular_file(receipt_path, MAX_TEXT_BYTES)
    object_bytes = regular_file(object_path, MAX_OBJECT_BYTES)
    if len(object_bytes) != int(receipt["object_bytes"]):
        fail("retained object length differs from receipt")
    if digest(object_bytes) != receipt["object_identity"]:
        fail("retained object digest differs from receipt")
    executable = regular_file(executable_path, MAX_EXECUTABLE_BYTES)
    symbols = [
        receipt["entry_symbol"],
        receipt["payload_symbol"],
        receipt["metadata_symbol"],
    ]
    direct = parse_macho(executable, symbols)
    link_map = strict_text(link_map_path, MAX_CAPTURE_BYTES)
    nm_text = strict_text(nm_path, MAX_CAPTURE_BYTES)
    otool_text = strict_text(otool_path, MAX_CAPTURE_BYTES)
    direct_addresses = {
        symbol: direct.symbols[symbol].value for symbol in symbols
    }
    corroborate_link_map(
        link_map, receipt["object_path"], symbols, direct_addresses
    )
    captured_addresses = parse_nm(nm_text, symbols)
    for symbol in symbols:
        if captured_addresses[symbol] != direct.symbols[symbol].value:
            fail(f"nm address differs from final Mach-O symbol table for {symbol}")
    corroborate_otool(parse_otool(otool_text), direct)

    payload_bytes = int(receipt["payload_bytes"])
    metadata_bytes = int(receipt["metadata_bytes"])
    linked_payload = checked_slice(
        executable, direct.payload_section, payload_bytes, "linked payload"
    )
    linked_metadata = checked_slice(
        executable, direct.metadata_section, metadata_bytes, "linked metadata"
    )
    if digest(linked_payload) != receipt["payload_sha256"]:
        fail("linked payload bytes differ from the audited object receipt")
    if digest(linked_metadata) != receipt["metadata_sha256"]:
        fail("linked metadata bytes differ from the audited object receipt")
    verify_metadata_identities(linked_metadata, receipt)

    addresses = direct_addresses
    return [
        ("schema", LINKED_SCHEMA),
        ("subject_revision", receipt["subject_revision"]),
        ("build_receipt_sha256", digest(receipt_bytes)),
        ("compile_identity", receipt["compile_identity"]),
        ("object_identity", receipt["object_identity"]),
        ("executable_sha256", digest(executable)),
        ("link_map_sha256", digest(link_map.encode("ascii"))),
        ("nm_sha256", digest(nm_text.encode("ascii"))),
        ("otool_sha256", digest(otool_text.encode("ascii"))),
        ("payload_sha256", receipt["payload_sha256"]),
        ("metadata_sha256", receipt["metadata_sha256"]),
        ("architecture", "arm64"),
        ("file_type", "MH_EXECUTE"),
        ("entry_address", f"0x{addresses[receipt['entry_symbol']]:016x}"),
        ("payload_address", f"0x{addresses[receipt['payload_symbol']]:016x}"),
        ("metadata_address", f"0x{addresses[receipt['metadata_symbol']]:016x}"),
        ("text_protection", "rx"),
        ("metadata_protection", "r"),
        ("symbol_source", "direct-macho-symtab"),
        ("link_map_role", "corroborating"),
        ("provider", "exact-receipt-derived-final-bytes"),
        ("aot_authority", "benchmark-local-raw-abi-no-adoption"),
        ("production_activation", "absent"),
        ("overall", "PASS"),
    ]


def usage() -> None:
    print(
        "usage: verify_linked_image.py BUILD_RECEIPT OBJECT EXECUTABLE "
        "LINK_MAP NM_CAPTURE OTOOL_CAPTURE",
        file=sys.stderr,
    )


def main(arguments: Sequence[str]) -> int:
    if len(arguments) != 6:
        usage()
        return 2
    try:
        rows = verify(*(Path(argument) for argument in arguments))
        sys.stdout.buffer.write(linked_receipt_bytes(rows))
    except VerificationError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
