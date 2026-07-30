#!/usr/bin/env python3
"""Prove the exact tag-29 candidate-object chain into one linked image.

The proof is construction-only.  It authenticates no performance result and
grants no promotion authority.  All build artifacts are opened by basename
through one held, non-symlink directory descriptor.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import struct
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


CONTRACT_SHA256 = "42921564050b795b4a097c8b74dde2e947b914931e71dd5faafe274a4975e60e"
OBJECT_MANIFEST_SHA256 = (
    "90b9eb70dff30e36901b86ecff34ba91938f27afa155ebb17f6daa33d3baca2c"
)
OBJECT_MANIFEST_PAYLOAD_SHA256 = (
    "772d7e03b9c2f1d2ef7ccf40ef248e10f46c66153d08ba686351bf580c49c6cd"
)
DISPOSITIONS_SHA256 = (
    "a6204205fcfd87faf8bf8d6c2a5c53859ad68e81979ba8e47626afbabdd4ee4d"
)
DISPOSITIONS_PAYLOAD_SHA256 = (
    "b4855d3d4cfa53cc60164c8f9adc5e70511c986831a84d401043ee121b3bef88"
)
CONTRACT_SCHEMA = "fre.aot.search-tag29-static-link-proof-contract.v1"
OBJECT_SCHEMA = "fre.aot.search-tag29-topology-object-candidates.v1"
DISPOSITIONS_SCHEMA = "fre.aot.search-tag29-topology-literal-dispositions.v1"
BUILD_SCHEMA = "fre.aot.external-regex-1.12.4-static-runner-build-receipt.v2"
LINK_SCHEMA = "fre.aot.search-tag29-link-invocation-receipt.v1"
OUTPUT_SCHEMA = "fre.aot.search-tag29-compiler-object-link-evidence.v1"
OBJECT_COUNT = 808
REFUSAL_COUNT = 114
DISPOSITION_COUNT = 922
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
SAFE_BASENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}\Z")
IMPLEMENTATION_BASENAME = re.compile(
    r"external-search-(0|[1-9][0-9]{0,3})-implementation[.]o\Z"
)
GLUE_BASENAME = re.compile(
    r"external-search-(0|[1-9][0-9]{0,3})-family-glue[.]o\Z"
)
ENTRY_PREFIX = "fre_aot_search_entry_v1_"
PAYLOAD_PREFIX = "fre_aot_payload_v1_"
METADATA_PREFIX = "fre_aot_metadata_v1_"
GLUE_PREFIX = "fre_aot_search_span_glue_v1_"
GLUE_SYMBOL_DOMAIN = b"FRE-SEARCH-TAG29-GLUE-SYMBOL\0\x01"
LINK_MAP_ORIGIN_DOMAIN = b"FRE-SEARCH-TAG29-LINK-MAP-ORIGIN\0\x01"
FINAL_RETENTION_DOMAIN = b"FRE-SEARCH-TAG29-FINAL-IMAGE-RETENTION\0\x01"

MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
MH_OBJECT = 1
MH_EXECUTE = 2
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
N_STAB = 0xE0
N_TYPE = 0x0E
N_UNDF = 0x00
N_SECT = 0x0E
N_EXT = 0x01
MACH_HEADER_64 = struct.Struct("<IiiIIIII")
MACH_SEGMENT_64 = struct.Struct("<II16sQQQQiiII")
MACH_SECTION_64 = struct.Struct("<16s16sQQIIIIIIII")
MACH_SYMTAB = struct.Struct("<IIIIII")
MACH_NLIST_64 = struct.Struct("<IBBHQ")

ELF_HEADER_64 = struct.Struct("<16sHHIQQQIHHHHHH")
ELF_SECTION_64 = struct.Struct("<IIQQQQIIQQ")
ELF_SYMBOL_64 = struct.Struct("<IBBHQQ")
ELF_REL_64 = struct.Struct("<QQ")
ELF_RELA_64 = struct.Struct("<QQq")
ET_REL = 1
ET_EXEC = 2
ET_DYN = 3
EM_AARCH64 = 183
SHT_SYMTAB = 2
SHT_RELA = 4
SHT_REL = 9
SHT_DYNSYM = 11
SHN_UNDEF = 0


class Refusal(RuntimeError):
    """A build artifact does not prove the frozen construction."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def is_strict_int(value: Any, minimum: int = 0) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def require_sha(value: Any, label: str) -> str:
    require(
        isinstance(value, str)
        and HEX64.fullmatch(value) is not None
        and value != "0" * 64,
        label,
    )
    return value


def exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict) and set(value) == expected, f"{label} fields changed")
    return value


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_sha(value: Any) -> str:
    return sha256(canonical_bytes(value))


def checked_end(start: int, size: int, limit: int, label: str) -> int:
    require(
        is_strict_int(start)
        and is_strict_int(size)
        and start <= limit
        and size <= limit - start,
        f"{label} exceeds its bounded container",
    )
    return start + size


def read_path_regular(path: Path, maximum: int, label: str) -> bytes:
    before = path.lstat()
    require(
        stat.S_ISREG(before.st_mode)
        and not path.is_symlink()
        and 0 < before.st_size <= maximum,
        f"{label} is not one bounded regular file",
    )
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        require(
            (opened.st_dev, opened.st_ino, opened.st_size)
            == (before.st_dev, before.st_ino, before.st_size),
            f"{label} changed before open",
        )
        return read_descriptor(descriptor, maximum, label, opened)
    finally:
        os.close(descriptor)


def read_descriptor(
    descriptor: int, maximum: int, label: str, opened: os.stat_result | None = None
) -> bytes:
    if opened is None:
        opened = os.fstat(descriptor)
    require(
        stat.S_ISREG(opened.st_mode) and 0 < opened.st_size <= maximum,
        f"{label} is not one bounded regular file",
    )
    chunks: list[bytes] = []
    total = 0
    while True:
        block = os.read(descriptor, min(1 << 20, maximum + 1 - total))
        if not block:
            break
        chunks.append(block)
        total += len(block)
        require(total <= maximum, f"{label} exceeds its byte bound")
    after = os.fstat(descriptor)
    require(
        (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        == (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ),
        f"{label} changed while read",
    )
    return b"".join(chunks)


class HeldDirectory:
    def __init__(self, path: Path) -> None:
        require(path.is_absolute(), "artifact directory path must be absolute")
        components = path.parts
        require(
            components and components[0] == "/" and len(components) > 1,
            "artifact directory path is not canonical absolute",
        )
        descriptor = os.open(
            "/", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY
        )
        try:
            for component in components[1:]:
                require(
                    component not in {"", ".", ".."}
                    and SAFE_BASENAME.fullmatch(component) is not None,
                    "artifact directory has a noncanonical component",
                )
                child = os.open(
                    component,
                    os.O_RDONLY
                    | os.O_CLOEXEC
                    | os.O_NOFOLLOW
                    | os.O_DIRECTORY,
                    dir_fd=descriptor,
                )
                os.close(descriptor)
                descriptor = child
        except BaseException:
            os.close(descriptor)
            raise
        self.descriptor = descriptor

    def close(self) -> None:
        os.close(self.descriptor)

    def read(self, basename: str, maximum: int, label: str) -> bytes:
        require(
            isinstance(basename, str)
            and SAFE_BASENAME.fullmatch(basename) is not None,
            f"{label} basename is not canonical",
        )
        descriptor = os.open(
            basename,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=self.descriptor,
        )
        try:
            return read_descriptor(descriptor, maximum, label)
        finally:
            os.close(descriptor)


def load_envelope(
    raw: bytes, schema: str, expected_sha: str, expected_payload_sha: str, label: str
) -> dict[str, Any]:
    require(sha256(raw) == expected_sha, f"{label} file identity changed")
    root = json.loads(raw)
    exact_keys(root, {"schema", "payload_sha256", "payload"}, label)
    require(root["schema"] == schema, f"{label} schema changed")
    require(
        root["payload_sha256"] == expected_payload_sha
        and canonical_sha(root["payload"]) == expected_payload_sha,
        f"{label} payload identity changed",
    )
    require(isinstance(root["payload"], dict), f"{label} payload is not an object")
    return root


@dataclass(frozen=True)
class BinarySymbol:
    name: str
    defined: bool
    value: int


@dataclass(frozen=True)
class BinaryEvidence:
    kind: str
    symbols: dict[str, tuple[BinarySymbol, ...]]
    relocations: Counter[str]

    def exact_definition(self, symbol: str, label: str) -> BinarySymbol:
        candidates = [
            candidate
            for candidate in self.symbols.get(symbol, ())
            if candidate.defined
        ]
        matches = list(
            {
                (candidate.name, candidate.defined, candidate.value): candidate
                for candidate in candidates
            }.values()
        )
        require(len(matches) == 1, f"{label} defines {symbol!r} {len(matches)} times")
        return matches[0]


def ascii_c_string(table: bytes, offset: int, label: str) -> str:
    require(0 <= offset < len(table), f"{label} string offset is out of range")
    end = table.find(b"\0", offset)
    require(end >= 0, f"{label} string is not NUL terminated")
    try:
        value = table[offset:end].decode("ascii")
    except UnicodeDecodeError as error:
        raise Refusal(f"{label} string is not ASCII") from error
    require(0 < len(value) <= 1 << 20, f"{label} string length is invalid")
    return value


def normalize_mach_symbol(name: str) -> str:
    return name[1:] if name.startswith("_") else name


def parse_macho(
    raw: bytes,
    maximum_symbols: int,
    maximum_relocations: int,
    wanted_symbols: set[str] | None = None,
) -> BinaryEvidence:
    require(len(raw) >= MACH_HEADER_64.size, "Mach-O header is truncated")
    (
        magic,
        cpu_type,
        _cpu_subtype,
        file_type,
        command_count,
        command_bytes,
        _flags,
        _reserved,
    ) = MACH_HEADER_64.unpack_from(raw)
    require(
        magic == MH_MAGIC_64
        and cpu_type == CPU_TYPE_ARM64
        and file_type in {MH_OBJECT, MH_EXECUTE},
        "file is not one supported arm64 Mach-O object/image",
    )
    require(
        0 < command_count <= 4096 and command_bytes >= command_count * 8,
        "Mach-O load-command bounds changed",
    )
    commands_end = checked_end(
        MACH_HEADER_64.size, command_bytes, len(raw), "Mach-O load commands"
    )
    cursor = MACH_HEADER_64.size
    symtab: tuple[int, int, int, int] | None = None
    relocation_tables: list[tuple[int, int]] = []
    for _ in range(command_count):
        checked_end(cursor, 8, commands_end, "Mach-O load-command header")
        command, command_size = struct.unpack_from("<II", raw, cursor)
        require(
            command_size >= 8 and command_size % 8 == 0,
            "Mach-O load-command size is invalid",
        )
        next_cursor = checked_end(cursor, command_size, commands_end, "Mach-O load command")
        if command == LC_SEGMENT_64:
            require(
                command_size >= MACH_SEGMENT_64.size,
                "Mach-O segment command is truncated",
            )
            fields = MACH_SEGMENT_64.unpack_from(raw, cursor)
            section_count = fields[9]
            require(
                command_size
                == MACH_SEGMENT_64.size + section_count * MACH_SECTION_64.size,
                "Mach-O section-command extent changed",
            )
            section_cursor = cursor + MACH_SEGMENT_64.size
            for _section in range(section_count):
                section = MACH_SECTION_64.unpack_from(raw, section_cursor)
                relocation_offset = section[6]
                relocation_count = section[7]
                if relocation_count:
                    checked_end(
                        relocation_offset,
                        relocation_count * 8,
                        len(raw),
                        "Mach-O relocation table",
                    )
                    relocation_tables.append((relocation_offset, relocation_count))
                section_cursor += MACH_SECTION_64.size
        elif command == LC_SYMTAB:
            require(
                command_size == MACH_SYMTAB.size and symtab is None,
                "Mach-O symbol-table command changed",
            )
            _command, _size, symbol_offset, symbol_count, string_offset, string_size = (
                MACH_SYMTAB.unpack_from(raw, cursor)
            )
            require(
                0 < symbol_count <= maximum_symbols and 0 < string_size <= 64 << 20,
                "Mach-O symbol table exceeds proof bounds",
            )
            checked_end(
                symbol_offset,
                symbol_count * MACH_NLIST_64.size,
                len(raw),
                "Mach-O symbols",
            )
            checked_end(string_offset, string_size, len(raw), "Mach-O strings")
            symtab = (symbol_offset, symbol_count, string_offset, string_size)
        cursor = next_cursor
    require(cursor == commands_end and symtab is not None, "Mach-O command traversal changed")
    symbol_offset, symbol_count, string_offset, string_size = symtab
    strings = raw[string_offset : string_offset + string_size]
    indexed_names: list[str | None] = []
    symbols: dict[str, list[BinarySymbol]] = {}
    for index in range(symbol_count):
        entry = MACH_NLIST_64.unpack_from(raw, symbol_offset + index * MACH_NLIST_64.size)
        string_index, symbol_type, section_ordinal, _description, value = entry
        if string_index == 0 or symbol_type & N_STAB:
            indexed_names.append(None)
            continue
        name = normalize_mach_symbol(
            ascii_c_string(strings, string_index, "Mach-O symbol")
        )
        indexed_names.append(
            name
            if relocation_tables or wanted_symbols is None or name in wanted_symbols
            else None
        )
        kind = symbol_type & N_TYPE
        defined = kind == N_SECT and section_ordinal != 0
        if not defined and kind != N_UNDF:
            continue
        if wanted_symbols is None or name in wanted_symbols:
            symbols.setdefault(name, []).append(BinarySymbol(name, defined, value))
    relocation_count_total = sum(count for _offset, count in relocation_tables)
    require(
        relocation_count_total <= maximum_relocations,
        "Mach-O relocations exceed proof bounds",
    )
    relocations: Counter[str] = Counter()
    for offset, count in relocation_tables:
        for index in range(count):
            _address, attributes = struct.unpack_from("<II", raw, offset + index * 8)
            symbol_index = attributes & 0x00FFFFFF
            external = (attributes >> 27) & 1
            if external:
                require(
                    symbol_index < len(indexed_names),
                    "Mach-O relocation symbol index is out of range",
                )
                name = indexed_names[symbol_index]
                require(name is not None, "Mach-O relocation names the empty symbol")
                relocations[name] += 1
    return BinaryEvidence(
        kind="macho-object" if file_type == MH_OBJECT else "macho-image",
        symbols={name: tuple(values) for name, values in symbols.items()},
        relocations=relocations,
    )


@dataclass(frozen=True)
class ElfSection:
    section_type: int
    offset: int
    size: int
    link: int
    entry_size: int


def parse_elf(
    raw: bytes,
    maximum_symbols: int,
    maximum_relocations: int,
    wanted_symbols: set[str] | None = None,
) -> BinaryEvidence:
    require(len(raw) >= ELF_HEADER_64.size, "ELF header is truncated")
    fields = ELF_HEADER_64.unpack_from(raw)
    identification = fields[0]
    file_type = fields[1]
    machine = fields[2]
    section_offset = fields[6]
    header_size = fields[8]
    section_entry_size = fields[11]
    section_count = fields[12]
    require(
        identification[:7] == b"\x7fELF\x02\x01\x01"
        and machine == EM_AARCH64
        and file_type in {ET_REL, ET_EXEC, ET_DYN}
        and header_size == ELF_HEADER_64.size
        and section_entry_size == ELF_SECTION_64.size
        and 0 < section_count <= 65535,
        "file is not one supported little-endian AArch64 ELF object/image",
    )
    checked_end(
        section_offset,
        section_count * section_entry_size,
        len(raw),
        "ELF section table",
    )
    sections: list[ElfSection] = []
    for index in range(section_count):
        section = ELF_SECTION_64.unpack_from(
            raw, section_offset + index * section_entry_size
        )
        section_type = section[1]
        offset = section[4]
        size = section[5]
        link = section[6]
        entry_size = section[9]
        if section_type != 8:
            checked_end(offset, size, len(raw), "ELF section")
        sections.append(ElfSection(section_type, offset, size, link, entry_size))
    symbol_tables: dict[int, tuple[list[str | None], list[BinarySymbol]]] = {}
    symbols: dict[str, list[BinarySymbol]] = {}
    total_symbols = 0
    for section_index, section in enumerate(sections):
        if section.section_type not in {SHT_SYMTAB, SHT_DYNSYM}:
            continue
        require(
            section.entry_size == ELF_SYMBOL_64.size
            and section.size % section.entry_size == 0
            and section.link < len(sections),
            "ELF symbol table layout changed",
        )
        string_section = sections[section.link]
        require(string_section.section_type == 3, "ELF symbol table lacks its string table")
        strings = raw[
            string_section.offset : string_section.offset + string_section.size
        ]
        count = section.size // section.entry_size
        total_symbols += count
        require(total_symbols <= maximum_symbols, "ELF symbols exceed proof bounds")
        names: list[str | None] = []
        entries: list[BinarySymbol] = []
        for index in range(count):
            entry = ELF_SYMBOL_64.unpack_from(
                raw, section.offset + index * section.entry_size
            )
            name_offset, _info, _other, section_ordinal, value, _size = entry
            if name_offset == 0:
                names.append(None)
                entries.append(BinarySymbol("", False, value))
                continue
            name = ascii_c_string(strings, name_offset, "ELF symbol")
            names.append(
                name
                if file_type == ET_REL
                or wanted_symbols is None
                or name in wanted_symbols
                else None
            )
            candidate = BinarySymbol(name, section_ordinal != SHN_UNDEF, value)
            entries.append(candidate)
            if wanted_symbols is None or name in wanted_symbols:
                symbols.setdefault(name, []).append(candidate)
        symbol_tables[section_index] = (names, entries)
    relocations: Counter[str] = Counter()
    total_relocations = 0
    for section in sections:
        if section.section_type not in {SHT_REL, SHT_RELA}:
            continue
        if file_type != ET_REL:
            continue
        expected_entry = (
            ELF_REL_64.size if section.section_type == SHT_REL else ELF_RELA_64.size
        )
        require(
            section.entry_size == expected_entry
            and section.size % expected_entry == 0
            and section.link in symbol_tables,
            "ELF relocation table layout changed",
        )
        names, _entries = symbol_tables[section.link]
        count = section.size // expected_entry
        total_relocations += count
        require(
            total_relocations <= maximum_relocations,
            "ELF relocations exceed proof bounds",
        )
        for index in range(count):
            if section.section_type == SHT_REL:
                _offset, info = ELF_REL_64.unpack_from(
                    raw, section.offset + index * expected_entry
                )
            else:
                _offset, info, _addend = ELF_RELA_64.unpack_from(
                    raw, section.offset + index * expected_entry
                )
            symbol_index = info >> 32
            require(symbol_index < len(names), "ELF relocation symbol index is out of range")
            name = names[symbol_index]
            require(name is not None, "ELF relocation names the empty symbol")
            relocations[name] += 1
    return BinaryEvidence(
        kind="elf-object" if file_type == ET_REL else "elf-image",
        symbols={name: tuple(values) for name, values in symbols.items()},
        relocations=relocations,
    )


def parse_binary(
    raw: bytes,
    target_os: str,
    maximum_symbols: int,
    maximum_relocations: int,
    wanted_symbols: set[str] | None = None,
) -> BinaryEvidence:
    if target_os == "macos":
        return parse_macho(
            raw, maximum_symbols, maximum_relocations, wanted_symbols
        )
    require(target_os == "linux", "link receipt target OS is unsupported")
    return parse_elf(raw, maximum_symbols, maximum_relocations, wanted_symbols)


@dataclass(frozen=True)
class MapDefinition:
    symbol: str
    provider: str
    address: int


def link_map_text(raw: bytes) -> str:
    require(
        raw.endswith(b"\n") and b"\0" not in raw and b"\r" not in raw,
        "link map is not one LF-terminated byte stream",
    )
    # Apple ld includes raw non-UTF-8 literal payloads in map diagnostics.
    # Latin-1 preserves each byte one-to-one; every accepted candidate path,
    # address, provider label, and symbol line is independently ASCII-shaped.
    return raw.decode("latin-1")


def map_symbol_name(value: str, target_os: str) -> str:
    if target_os == "macos" and value.startswith("_"):
        return value[1:]
    return value


def parse_apple_link_map(
    text: str, expected_symbols: set[str]
) -> dict[str, tuple[MapDefinition, ...]]:
    providers: dict[str, str] = {}
    in_object_files = False
    in_symbols = False
    definitions: dict[str, list[MapDefinition]] = {}
    for line in text.splitlines():
        if line == "# Object files:":
            in_object_files = True
            in_symbols = False
            continue
        if line == "# Symbols:":
            in_symbols = True
            in_object_files = False
            continue
        if line.startswith("# "):
            if line not in {"# Address\tSize    \tFile  Name"}:
                in_object_files = False
            continue
        if in_object_files:
            match = re.fullmatch(r"(\[[ ]*[0-9]{1,7}\]) (.+)", line)
            if match:
                require(match.group(1) not in providers, "Apple link map repeats an object label")
                providers[match.group(1)] = match.group(2)
            continue
        if not in_symbols:
            continue
        match = re.fullmatch(
            r"(0x[0-9A-Fa-f]{1,16})\s+0x[0-9A-Fa-f]{1,16}\s+"
            r"(\[[ ]*[0-9]{1,7}\])\s+(\S+)",
            line,
        )
        if match is None:
            continue
        label = match.group(2)
        require(label in providers, "Apple link-map symbol has an unknown provider")
        symbol = map_symbol_name(match.group(3), "macos")
        if symbol not in expected_symbols:
            continue
        definitions.setdefault(symbol, []).append(
            MapDefinition(symbol, providers[label], int(match.group(1), 16))
        )
    require(providers and definitions, "Apple link map omits providers or symbols")
    return {name: tuple(values) for name, values in definitions.items()}


def exact_path_match(line: str, path: str) -> bool:
    start = 0
    while True:
        index = line.find(path, start)
        if index < 0:
            return False
        left_ok = index == 0 or line[index - 1].isspace()
        end = index + len(path)
        right_ok = end == len(line) or line[end].isspace() or line[end] in ":("
        if left_ok and right_ok:
            return True
        start = index + 1


def parse_gnu_link_map(
    text: str, expected_paths: set[str], expected_symbols: set[str]
) -> dict[str, tuple[MapDefinition, ...]]:
    """Parse the common GNU ld and LLD map layouts fail-closed.

    Both layouts place an input-section provider before its definitions.  A
    definition is accepted only when the closest preceding recognized
    candidate provider is no more than four nonblank lines away.
    """

    definitions: dict[str, list[MapDefinition]] = {}
    current_provider: str | None = None
    provider_line = -100
    paths_by_basename = {
        path.rsplit("/", 1)[-1]: path for path in expected_paths
    }
    require(
        len(paths_by_basename) == len(expected_paths),
        "candidate linker paths do not have unique basenames",
    )
    candidate_basename = re.compile(
        r"external-search-(?:0|[1-9][0-9]{0,3})-"
        r"(?:implementation|family-glue)[.]o"
    )
    for line_number, line in enumerate(text.splitlines()):
        matching_basenames = set(candidate_basename.findall(line))
        require(
            len(matching_basenames) <= 1,
            "GNU/LLD map line names multiple candidate inputs",
        )
        if matching_basenames:
            basename = next(iter(matching_basenames))
            require(
                basename in paths_by_basename
                and exact_path_match(line, paths_by_basename[basename]),
                "GNU/LLD map names an unexpected candidate input path",
            )
            current_provider = paths_by_basename[basename]
            provider_line = line_number
        fields = line.split()
        if not fields:
            continue
        raw_symbol = fields[-1]
        symbol = raw_symbol[1:] if raw_symbol.startswith("_") else raw_symbol
        if symbol not in expected_symbols:
            continue
        address_fields = [
            field
            for field in fields[:-1]
            if re.fullmatch(r"(?:0x)?[0-9A-Fa-f]{1,16}", field)
        ]
        require(address_fields, f"GNU/LLD map lacks an address for {symbol}")
        require(
            current_provider is not None and line_number - provider_line <= 4,
            f"GNU/LLD map does not place {symbol} under one candidate provider",
        )
        definitions.setdefault(symbol, []).append(
            MapDefinition(
                symbol,
                current_provider,
                int(address_fields[0], 16),
            )
        )
    return {name: tuple(values) for name, values in definitions.items()}


def exact_map_definition(
    definitions: dict[str, tuple[MapDefinition, ...]],
    symbol: str,
    provider: str,
    address: int,
) -> MapDefinition:
    matches = definitions.get(symbol, ())
    require(len(matches) == 1, f"link map defines {symbol!r} {len(matches)} times")
    result = matches[0]
    require(
        result.provider == provider and result.address == address,
        f"link-map origin/address differs for {symbol!r}",
    )
    return result


def load_json(raw: bytes, label: str) -> dict[str, Any]:
    value = json.loads(raw)
    require(isinstance(value, dict), f"{label} is not a JSON object")
    return value


def validate_contract(raw: bytes) -> dict[str, Any]:
    require(sha256(raw) == CONTRACT_SHA256, "link-proof contract bytes changed")
    contract = load_json(raw, "link-proof contract")
    require(
        contract
        == {
            "schema": CONTRACT_SCHEMA,
            "status": "result-blind-prequalification",
            "object_candidates": {
                "schema": OBJECT_SCHEMA,
                "file_sha256": OBJECT_MANIFEST_SHA256,
                "payload_sha256": OBJECT_MANIFEST_PAYLOAD_SHA256,
                "count": OBJECT_COUNT,
            },
            "literal_dispositions": {
                "schema": DISPOSITIONS_SCHEMA,
                "file_sha256": DISPOSITIONS_SHA256,
                "payload_sha256": DISPOSITIONS_PAYLOAD_SHA256,
                "count": DISPOSITION_COUNT,
                "object_count": OBJECT_COUNT,
                "refusal_count": REFUSAL_COUNT,
            },
            "engine": {
                "architecture": "aarch64",
                "backend_tag": 29,
                "backend_version": "SEARCH_V16",
                "candidate_policy": 15,
                "backend_name": "AsimdV16",
                "llvm": False,
            },
            "targets": {
                "macos": {
                    "triple": "aarch64-apple-darwin",
                    "object_format": "macho64-arm64",
                    "link_map_format": "apple-ld",
                    "frozen_host": "local-apple-aarch64-asimd",
                    "canonical_host": "apple-aarch64-asimd",
                    "features": {
                        "architecture": "aarch64",
                        "asimd": True,
                        "sve": False,
                        "sve2": False,
                        "sve_vector_bytes": None,
                    },
                },
                "linux": {
                    "triple": "aarch64-unknown-linux-gnu",
                    "object_format": "elf64-little-aarch64",
                    "link_map_format": "gnu-or-lld",
                    "frozen_host": "zstd-eval-ec2-aarch64-asimd-sve2-vl16",
                    "canonical_host": "c9g-aarch64-asimd-sve2",
                    "features": {
                        "architecture": "aarch64",
                        "asimd": True,
                        "sve": True,
                        "sve2": True,
                        "sve_vector_bytes": 16,
                    },
                },
            },
            "artifacts": {
                "implementation_basename": "external-search-{ordinal}-implementation.o",
                "glue_basename": "external-search-{ordinal}-family-glue.o",
                "compile_receipt_basename": "external-search-{ordinal}-compile-receipt.bin",
                "implementation_linker_input_multiplicity": 1,
                "glue_linker_input_multiplicity": 1,
            },
            "symbols": {
                "entry_prefix": ENTRY_PREFIX,
                "payload_prefix": PAYLOAD_PREFIX,
                "metadata_prefix": METADATA_PREFIX,
                "glue_prefix": GLUE_PREFIX,
                "identity_hex_bytes": 32,
                "glue_required_implementation_relocation_targets": [
                    "entry",
                    "payload",
                    "metadata",
                ],
            },
            "receipt_domains": {
                "glue_symbol": "FRE-SEARCH-TAG29-GLUE-SYMBOL\\0\\x01",
                "link_map_origin": "FRE-SEARCH-TAG29-LINK-MAP-ORIGIN\\0\\x01",
                "final_image_retention": "FRE-SEARCH-TAG29-FINAL-IMAGE-RETENTION\\0\\x01",
            },
            "limits": {
                "maximum_manifest_bytes": 4194304,
                "maximum_build_receipt_bytes": 4194304,
                "maximum_link_receipt_bytes": 8388608,
                "maximum_object_bytes": 16777216,
                "maximum_compile_receipt_bytes": 65536,
                "maximum_link_map_bytes": 134217728,
                "maximum_linked_image_bytes": 536870912,
                "maximum_linker_arguments": 65536,
                "maximum_linker_argument_bytes": 1048576,
                "maximum_symbols": 4000000,
                "maximum_sections": 65535,
                "maximum_relocations": 4000000,
            },
            "authority": {
                "timing_results_read": False,
                "benchmark_result_inputs": [],
                "rebar_inputs": [],
                "network": False,
                "promotion_authority": False,
                "required_output_schema": OUTPUT_SCHEMA,
            },
        },
        "link-proof contract fields changed",
    )
    return contract


def candidate_key(candidate: dict[str, Any]) -> tuple[str, str]:
    return candidate["semantic_candidate_sha256"], candidate["literal_sha256"]


def validate_candidate_manifest(root: dict[str, Any]) -> list[dict[str, Any]]:
    payload = root["payload"]
    candidates = payload.get("candidates")
    require(
        is_strict_int(payload.get("candidate_count"), 1)
        and payload["candidate_count"] == OBJECT_COUNT
        and isinstance(candidates, list)
        and len(candidates) == OBJECT_COUNT,
        "object-candidate cardinality changed",
    )
    semantic: set[str] = set()
    literals: set[str] = set()
    for ordinal, candidate in enumerate(candidates):
        require(isinstance(candidate, dict), f"object candidate {ordinal} is not an object")
        semantic_id = require_sha(
            candidate.get("semantic_candidate_sha256"),
            f"object candidate {ordinal} semantic identity changed",
        )
        literal_id = require_sha(
            candidate.get("literal_sha256"),
            f"object candidate {ordinal} literal identity changed",
        )
        literal_hex = candidate.get("literal_hex")
        require(
            isinstance(literal_hex, str)
            and re.fullmatch(r"(?:[0-9a-f]{2}){6,32}", literal_hex) is not None
            and sha256(bytes.fromhex(literal_hex)) == literal_id,
            f"object candidate {ordinal} literal changed",
        )
        require(
            semantic_id not in semantic and literal_id not in literals,
            f"object candidate {ordinal} is duplicated",
        )
        semantic.add(semantic_id)
        literals.add(literal_id)
    return candidates


def validate_dispositions(
    root: dict[str, Any], candidates: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    payload = root["payload"]
    rows = payload.get("dispositions")
    require(
        isinstance(rows, list)
        and len(rows) == DISPOSITION_COUNT,
        "literal-disposition cardinality changed",
    )
    eligible = [
        row
        for row in rows
        if row.get("expected_compiler_disposition") == "tag29-object"
    ]
    refusals = [
        row
        for row in rows
        if row.get("expected_compiler_disposition") == "structural-refusal"
    ]
    require(
        len(eligible) == OBJECT_COUNT
        and len(refusals) == REFUSAL_COUNT
        and [candidate_key(row) for row in eligible]
        == [candidate_key(candidate) for candidate in candidates],
        "literal dispositions do not biject to object candidates",
    )
    require(
        all(
            require_sha(
                row.get("semantic_candidate_sha256"),
                f"refusal {ordinal} semantic identity changed",
            )
            and require_sha(
                row.get("literal_sha256"),
                f"refusal {ordinal} literal identity changed",
            )
            for ordinal, row in enumerate(refusals)
        ),
        "literal refusal identity changed",
    )
    return refusals


BUILD_CANDIDATE_FIELDS = {
    "ordinal",
    "semantic_candidate_sha256",
    "literal_sha256",
    "literal_hex",
    "compile_identity",
    "compile_receipt_sha256",
    "compile_receipt_basename",
    "implementation_object_sha256",
    "glue_object_sha256",
    "implementation_object_basename",
    "glue_object_basename",
    "implementation_symbols",
    "glue_symbol",
}
BUILD_REFUSAL_FIELDS = {
    "ordinal",
    "semantic_candidate_sha256",
    "literal_sha256",
    "literal_hex",
    "disposition",
    "compile_receipt_sha256",
    "compile_receipt_basename",
}
LINK_INPUT_FIELDS = {
    "ordinal",
    "kind",
    "artifact_basename",
    "linker_path",
    "sha256",
    "bytes",
    "expanded_argv_multiplicity",
}
LINK_PAYLOAD_FIELDS = {
    "frozen_host",
    "canonical_host",
    "target_os",
    "target_arch",
    "target_triple",
    "features",
    "build_receipt_basename",
    "build_receipt_sha256",
    "linked_image_basename",
    "linked_image_sha256",
    "link_map_basename",
    "link_map_sha256",
    "expanded_argv",
    "expanded_argv_sha256",
    "inputs",
}


def exact_symbol(prefix: str, compile_identity: str) -> str:
    return prefix + compile_identity


def validate_build_receipt(
    raw: bytes,
    candidates: list[dict[str, Any]],
    expected_refusals: list[dict[str, Any]],
    target_os: str,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    receipt = load_json(raw, "build receipt")
    required = {
        "schema",
        "target_os",
        "target_arch",
        "backend_name",
        "backend_tag",
        "backend_version",
        "candidate_policy",
        "llvm",
        "object_candidate_manifest_schema",
        "object_candidate_manifest_sha256",
        "object_candidate_manifest_payload_sha256",
        "object_candidate_count",
        "literal_dispositions_sha256",
        "literal_dispositions_payload_sha256",
        "literal_disposition_count",
        "candidates",
        "refusals",
    }
    require(required <= set(receipt), "build receipt omits required fields")
    require(
        receipt["schema"] == BUILD_SCHEMA
        and receipt["target_os"] == target_os
        and receipt["target_arch"] == "aarch64"
        and receipt["backend_name"] == "AsimdV16"
        and receipt["backend_tag"] == 29
        and receipt["backend_version"] == "SEARCH_V16"
        and receipt["candidate_policy"] == 15
        and receipt["llvm"] is False
        and receipt["object_candidate_manifest_schema"] == OBJECT_SCHEMA
        and receipt["object_candidate_manifest_sha256"] == OBJECT_MANIFEST_SHA256
        and receipt["object_candidate_manifest_payload_sha256"]
        == OBJECT_MANIFEST_PAYLOAD_SHA256
        and receipt["object_candidate_count"] == OBJECT_COUNT
        and receipt["literal_dispositions_sha256"] == DISPOSITIONS_SHA256
        and receipt["literal_dispositions_payload_sha256"]
        == DISPOSITIONS_PAYLOAD_SHA256
        and receipt["literal_disposition_count"] == DISPOSITION_COUNT,
        "build receipt engine/input identity changed",
    )
    built = receipt["candidates"]
    refusals = receipt["refusals"]
    require(
        isinstance(built, list)
        and len(built) == OBJECT_COUNT
        and isinstance(refusals, list)
        and len(refusals) == REFUSAL_COUNT,
        "build receipt disposition cardinality changed",
    )
    compile_identities: set[str] = set()
    compile_receipts: set[str] = set()
    implementation_hashes: set[str] = set()
    glue_hashes: set[str] = set()
    glue_symbols: set[str] = set()
    for ordinal, (expected, actual) in enumerate(zip(candidates, built, strict=True)):
        exact_keys(actual, BUILD_CANDIDATE_FIELDS, f"build candidate {ordinal}")
        compile_identity = require_sha(
            actual["compile_identity"], f"build candidate {ordinal} compile identity"
        )
        compile_receipt = require_sha(
            actual["compile_receipt_sha256"],
            f"build candidate {ordinal} compile receipt",
        )
        implementation_sha = require_sha(
            actual["implementation_object_sha256"],
            f"build candidate {ordinal} implementation object",
        )
        glue_sha = require_sha(
            actual["glue_object_sha256"],
            f"build candidate {ordinal} glue object",
        )
        expected_implementation_basename = (
            f"external-search-{ordinal}-implementation.o"
        )
        expected_glue_basename = f"external-search-{ordinal}-family-glue.o"
        expected_compile_basename = f"external-search-{ordinal}-compile-receipt.bin"
        symbols = exact_keys(
            actual["implementation_symbols"],
            {"entry", "payload", "metadata"},
            f"build candidate {ordinal} implementation symbols",
        )
        expected_symbols = {
            "entry": exact_symbol(ENTRY_PREFIX, compile_identity),
            "payload": exact_symbol(PAYLOAD_PREFIX, compile_identity),
            "metadata": exact_symbol(METADATA_PREFIX, compile_identity),
        }
        expected_glue_symbol = exact_symbol(GLUE_PREFIX, compile_identity)
        require(
            actual["ordinal"] == ordinal
            and candidate_key(actual) == candidate_key(expected)
            and actual["literal_hex"] == expected["literal_hex"]
            and actual["implementation_object_basename"]
            == expected_implementation_basename
            and actual["glue_object_basename"] == expected_glue_basename
            and actual["compile_receipt_basename"] == expected_compile_basename
            and symbols == expected_symbols
            and actual["glue_symbol"] == expected_glue_symbol,
            f"build candidate {ordinal} semantic/artifact binding changed",
        )
        require(
            compile_identity not in compile_identities
            and compile_receipt not in compile_receipts
            and implementation_sha not in implementation_hashes
            and glue_sha not in glue_hashes
            and expected_glue_symbol not in glue_symbols,
            f"build candidate {ordinal} identity is not injective",
        )
        compile_identities.add(compile_identity)
        compile_receipts.add(compile_receipt)
        implementation_hashes.add(implementation_sha)
        glue_hashes.add(glue_sha)
        glue_symbols.add(expected_glue_symbol)
    refusal_receipts: set[str] = set()
    for ordinal, (expected, actual) in enumerate(
        zip(expected_refusals, refusals, strict=True)
    ):
        exact_keys(actual, BUILD_REFUSAL_FIELDS, f"build refusal {ordinal}")
        receipt_sha = require_sha(
            actual["compile_receipt_sha256"],
            f"build refusal {ordinal} compile receipt",
        )
        require(
            actual["ordinal"] == ordinal
            and candidate_key(actual) == candidate_key(expected)
            and actual["literal_hex"] == expected["literal_hex"]
            and actual["disposition"] == "structural-refusal"
            and actual["compile_receipt_basename"]
            == f"external-search-refusal-{ordinal}-compile-receipt.bin"
            and receipt_sha not in refusal_receipts
            and receipt_sha not in compile_receipts,
            f"build refusal {ordinal} binding or identity changed",
        )
        refusal_receipts.add(receipt_sha)
    return receipt, built, refusals


def validate_link_receipt(
    raw: bytes, build_sha: str, target_os: str
) -> tuple[dict[str, Any], dict[tuple[int, str], dict[str, Any]]]:
    root = load_json(raw, "link invocation receipt")
    exact_keys(root, {"schema", "payload_sha256", "payload"}, "link receipt")
    require(root["schema"] == LINK_SCHEMA, "link receipt schema changed")
    payload = exact_keys(root["payload"], LINK_PAYLOAD_FIELDS, "link receipt payload")
    require(
        require_sha(root["payload_sha256"], "link receipt payload identity")
        == canonical_sha(payload),
        "link receipt payload is not authentic",
    )
    target_triple = (
        "aarch64-apple-darwin"
        if target_os == "macos"
        else "aarch64-unknown-linux-gnu"
    )
    expected_host = (
        {
            "frozen_host": "local-apple-aarch64-asimd",
            "canonical_host": "apple-aarch64-asimd",
            "features": {
                "architecture": "aarch64",
                "asimd": True,
                "sve": False,
                "sve2": False,
                "sve_vector_bytes": None,
            },
        }
        if target_os == "macos"
        else {
            "frozen_host": "zstd-eval-ec2-aarch64-asimd-sve2-vl16",
            "canonical_host": "c9g-aarch64-asimd-sve2",
            "features": {
                "architecture": "aarch64",
                "asimd": True,
                "sve": True,
                "sve2": True,
                "sve_vector_bytes": 16,
            },
        }
    )
    require(
        payload["target_os"] == target_os
        and payload["target_arch"] == "aarch64"
        and payload["target_triple"] == target_triple
        and payload["frozen_host"] == expected_host["frozen_host"]
        and payload["canonical_host"] == expected_host["canonical_host"]
        and payload["features"] == expected_host["features"]
        and payload["build_receipt_basename"] == "build-receipt.json"
        and payload["build_receipt_sha256"] == build_sha
        and payload["linked_image_basename"] == "linked-image"
        and payload["link_map_basename"] == "linked-image.map",
        "link receipt host/target/artifact binding changed",
    )
    require_sha(payload["linked_image_sha256"], "linked image receipt identity")
    require_sha(payload["link_map_sha256"], "link map receipt identity")
    argv = payload["expanded_argv"]
    require(
        isinstance(argv, list)
        and 0 < len(argv) <= 65536
        and all(
            isinstance(argument, str)
            and 0 < len(argument.encode("utf-8")) <= 1 << 20
            and "\0" not in argument
            for argument in argv
        )
        and require_sha(
            payload["expanded_argv_sha256"], "expanded linker argv identity"
        )
        == canonical_sha(argv),
        "expanded linker argv changed",
    )
    inputs = payload["inputs"]
    require(
        isinstance(inputs, list) and len(inputs) == OBJECT_COUNT * 2,
        "link input cardinality changed",
    )
    expected_order = [
        (ordinal, kind)
        for ordinal in range(OBJECT_COUNT)
        for kind in ("implementation", "glue")
    ]
    indexed: dict[tuple[int, str], dict[str, Any]] = {}
    candidate_paths: set[str] = set()
    for expected, item in zip(expected_order, inputs, strict=True):
        ordinal, kind = expected
        exact_keys(item, LINK_INPUT_FIELDS, f"link input {ordinal}/{kind}")
        expected_basename = (
            f"external-search-{ordinal}-implementation.o"
            if kind == "implementation"
            else f"external-search-{ordinal}-family-glue.o"
        )
        require(
            item["ordinal"] == ordinal
            and item["kind"] == kind
            and item["artifact_basename"] == expected_basename
            and isinstance(item["linker_path"], str)
            and item["linker_path"].endswith("/" + expected_basename)
            and item["linker_path"] not in candidate_paths
            and require_sha(item["sha256"], f"link input {ordinal}/{kind} hash")
            and is_strict_int(item["bytes"], 1)
            and item["expanded_argv_multiplicity"] == 1
            and not isinstance(item["expanded_argv_multiplicity"], bool)
            and argv.count(item["linker_path"]) == 1,
            f"link input {ordinal}/{kind} binding or multiplicity changed",
        )
        candidate_paths.add(item["linker_path"])
        indexed[expected] = item
    external_object_arguments = [
        argument
        for argument in argv
        if IMPLEMENTATION_BASENAME.search(argument.rsplit("/", 1)[-1])
        or GLUE_BASENAME.search(argument.rsplit("/", 1)[-1])
    ]
    require(
        len(external_object_arguments) == OBJECT_COUNT * 2
        and set(external_object_arguments) == candidate_paths,
        "expanded linker argv contains missing or extra candidate objects",
    )
    return payload, indexed


def derived_receipt(domain: bytes, body: dict[str, Any]) -> str:
    return sha256(domain + canonical_bytes(body))


def check_object_pair(
    ordinal: int,
    built: dict[str, Any],
    link_inputs: dict[tuple[int, str], dict[str, Any]],
    directory: HeldDirectory,
    target_os: str,
    final_image: BinaryEvidence,
    link_definitions: dict[str, tuple[MapDefinition, ...]],
    linked_image_sha: str,
    link_map_sha: str,
    maximum_object_bytes: int,
    maximum_compile_receipt_bytes: int,
    maximum_symbols: int,
    maximum_relocations: int,
) -> dict[str, Any]:
    implementation_input = link_inputs[(ordinal, "implementation")]
    glue_input = link_inputs[(ordinal, "glue")]
    implementation_raw = directory.read(
        built["implementation_object_basename"],
        maximum_object_bytes,
        f"candidate {ordinal} implementation object",
    )
    glue_raw = directory.read(
        built["glue_object_basename"],
        maximum_object_bytes,
        f"candidate {ordinal} glue object",
    )
    compile_receipt = directory.read(
        built["compile_receipt_basename"],
        maximum_compile_receipt_bytes,
        f"candidate {ordinal} compile receipt",
    )
    implementation_sha = sha256(implementation_raw)
    glue_sha = sha256(glue_raw)
    require(
        implementation_sha == built["implementation_object_sha256"]
        == implementation_input["sha256"]
        and len(implementation_raw) == implementation_input["bytes"]
        and glue_sha == built["glue_object_sha256"] == glue_input["sha256"]
        and len(glue_raw) == glue_input["bytes"]
        and sha256(compile_receipt) == built["compile_receipt_sha256"],
        f"candidate {ordinal} staged artifact bytes differ from receipts",
    )
    implementation = parse_binary(
        implementation_raw, target_os, maximum_symbols, maximum_relocations
    )
    glue = parse_binary(glue_raw, target_os, maximum_symbols, maximum_relocations)
    require(
        implementation.kind.endswith("-object") and glue.kind.endswith("-object"),
        f"candidate {ordinal} inputs are not relocatable objects",
    )
    symbols = built["implementation_symbols"]
    for role in ("entry", "payload", "metadata"):
        implementation.exact_definition(
            symbols[role], f"candidate {ordinal} implementation"
        )
        require(
            not any(
                candidate.defined
                for candidate in glue.symbols.get(symbols[role], ())
            )
            and glue.relocations[symbols[role]] > 0,
            f"candidate {ordinal} glue does not relocate to paired {role}",
        )
    glue_symbol = built["glue_symbol"]
    glue.exact_definition(glue_symbol, f"candidate {ordinal} glue")
    require(
        not any(
            candidate.defined
            for candidate in implementation.symbols.get(glue_symbol, ())
        ),
        f"candidate {ordinal} implementation unexpectedly defines its glue",
    )

    ordered_symbols = [
        (symbols["entry"], implementation_sha, implementation_input["linker_path"]),
        (
            symbols["payload"],
            implementation_sha,
            implementation_input["linker_path"],
        ),
        (
            symbols["metadata"],
            implementation_sha,
            implementation_input["linker_path"],
        ),
        (glue_symbol, glue_sha, glue_input["linker_path"]),
    ]
    link_map_origins = []
    final_retentions = []
    for symbol, object_sha, provider_path in ordered_symbols:
        final_symbol = final_image.exact_definition(symbol, "final linked image")
        exact_map_definition(
            link_definitions, symbol, provider_path, final_symbol.value
        )
        origin_body = {
            "symbol": symbol,
            "object_sha256": object_sha,
            "provider_path": provider_path,
            "address": final_symbol.value,
            "link_map_sha256": link_map_sha,
        }
        retention_body = {
            "symbol": symbol,
            "object_sha256": object_sha,
            "address": final_symbol.value,
            "linked_image_sha256": linked_image_sha,
        }
        link_map_origins.append(
            {
                "symbol": symbol,
                "object_sha256": object_sha,
                "receipt_sha256": derived_receipt(
                    LINK_MAP_ORIGIN_DOMAIN, origin_body
                ),
            }
        )
        final_retentions.append(
            {
                "symbol": symbol,
                "object_sha256": object_sha,
                "receipt_sha256": derived_receipt(
                    FINAL_RETENTION_DOMAIN, retention_body
                ),
            }
        )
    return {
        "ordinal": ordinal,
        "literal_sha256": built["literal_sha256"],
        "semantic_candidate_sha256": built["semantic_candidate_sha256"],
        "compile_identity": built["compile_identity"],
        "compile_receipt_sha256": built["compile_receipt_sha256"],
        "implementation_object_sha256": implementation_sha,
        "glue_object_sha256": glue_sha,
        "implementation_symbols": symbols,
        "glue_symbol": glue_symbol,
        "glue_symbol_identity_sha256": sha256(
            GLUE_SYMBOL_DOMAIN + glue_symbol.encode("ascii")
        ),
        "glue_relocation_targets": [
            symbols["entry"],
            symbols["payload"],
            symbols["metadata"],
        ],
        "implementation_linker_input_multiplicity": 1,
        "glue_linker_input_multiplicity": 1,
        "link_map_origins": link_map_origins,
        "final_image_retentions": final_retentions,
    }


def check_refusal(
    ordinal: int,
    built: dict[str, Any],
    directory: HeldDirectory,
    maximum_compile_receipt_bytes: int,
) -> dict[str, Any]:
    raw = directory.read(
        built["compile_receipt_basename"],
        maximum_compile_receipt_bytes,
        f"refusal {ordinal} compile receipt",
    )
    require(
        sha256(raw) == built["compile_receipt_sha256"],
        f"refusal {ordinal} compile receipt bytes changed",
    )
    return {
        "ordinal": ordinal,
        "literal_sha256": built["literal_sha256"],
        "semantic_candidate_sha256": built["semantic_candidate_sha256"],
        "disposition": "structural-refusal",
        "compile_receipt_sha256": built["compile_receipt_sha256"],
    }


def verify(
    contract_path: Path,
    object_manifest_path: Path,
    dispositions_path: Path,
    artifact_directory: Path,
) -> dict[str, Any]:
    contract_raw = read_path_regular(
        contract_path, 128 * 1024, "link-proof contract"
    )
    contract = validate_contract(contract_raw)
    limits = contract["limits"]
    object_raw = read_path_regular(
        object_manifest_path,
        limits["maximum_manifest_bytes"],
        "object-candidate manifest",
    )
    object_root = load_envelope(
        object_raw,
        OBJECT_SCHEMA,
        OBJECT_MANIFEST_SHA256,
        OBJECT_MANIFEST_PAYLOAD_SHA256,
        "object-candidate manifest",
    )
    candidates = validate_candidate_manifest(object_root)
    dispositions_raw = read_path_regular(
        dispositions_path,
        limits["maximum_manifest_bytes"],
        "literal dispositions",
    )
    dispositions_root = load_envelope(
        dispositions_raw,
        DISPOSITIONS_SCHEMA,
        DISPOSITIONS_SHA256,
        DISPOSITIONS_PAYLOAD_SHA256,
        "literal dispositions",
    )
    expected_refusals = validate_dispositions(dispositions_root, candidates)

    directory = HeldDirectory(artifact_directory)
    try:
        build_raw = directory.read(
            "build-receipt.json",
            limits["maximum_build_receipt_bytes"],
            "build receipt",
        )
        link_raw = directory.read(
            "link-invocation-receipt.json",
            limits["maximum_link_receipt_bytes"],
            "link invocation receipt",
        )
        link_peek = load_json(link_raw, "link invocation receipt")
        target_os = (
            link_peek.get("payload", {}).get("target_os")
            if isinstance(link_peek.get("payload"), dict)
            else None
        )
        require(target_os in {"macos", "linux"}, "link receipt target OS changed")
        build_receipt, built_candidates, built_refusals = validate_build_receipt(
            build_raw, candidates, expected_refusals, target_os
        )
        link_payload, link_inputs = validate_link_receipt(
            link_raw, sha256(build_raw), target_os
        )
        link_map_raw = directory.read(
            link_payload["link_map_basename"],
            limits["maximum_link_map_bytes"],
            "linked-image map",
        )
        linked_image_raw = directory.read(
            link_payload["linked_image_basename"],
            limits["maximum_linked_image_bytes"],
            "linked image",
        )
        link_map_sha = sha256(link_map_raw)
        linked_image_sha = sha256(linked_image_raw)
        require(
            link_map_sha == link_payload["link_map_sha256"]
            and linked_image_sha == link_payload["linked_image_sha256"],
            "linked image or map differs from link receipt",
        )
        expected_symbols = {
            symbol
            for built in built_candidates
            for symbol in (
                built["implementation_symbols"]["entry"],
                built["implementation_symbols"]["payload"],
                built["implementation_symbols"]["metadata"],
                built["glue_symbol"],
            )
        }
        final_image = parse_binary(
            linked_image_raw,
            target_os,
            limits["maximum_symbols"],
            limits["maximum_relocations"],
            expected_symbols,
        )
        require(
            final_image.kind.endswith("-image"),
            "linked-image artifact is not a final image",
        )
        map_text = link_map_text(link_map_raw)
        expected_paths = {
            item["linker_path"] for item in link_payload["inputs"]
        }
        link_definitions = (
            parse_apple_link_map(map_text, expected_symbols)
            if target_os == "macos"
            else parse_gnu_link_map(map_text, expected_paths, expected_symbols)
        )
        output_objects = [
            check_object_pair(
                ordinal,
                built,
                link_inputs,
                directory,
                target_os,
                final_image,
                link_definitions,
                linked_image_sha,
                link_map_sha,
                limits["maximum_object_bytes"],
                limits["maximum_compile_receipt_bytes"],
                limits["maximum_symbols"],
                limits["maximum_relocations"],
            )
            for ordinal, built in enumerate(built_candidates)
        ]
        output_refusals = [
            check_refusal(
                ordinal,
                built,
                directory,
                limits["maximum_compile_receipt_bytes"],
            )
            for ordinal, built in enumerate(built_refusals)
        ]
    finally:
        directory.close()

    self_raw = read_path_regular(
        Path(__file__).resolve(), 2 * 1024 * 1024, "link verifier source"
    )
    payload = {
        "frozen_host": link_payload["frozen_host"],
        "canonical_host": link_payload["canonical_host"],
        "target_triple": link_payload["target_triple"],
        "features": link_payload["features"],
        "object_manifest_sha256": OBJECT_MANIFEST_SHA256,
        "object_manifest_payload_sha256": OBJECT_MANIFEST_PAYLOAD_SHA256,
        "literal_dispositions_sha256": DISPOSITIONS_SHA256,
        "literal_dispositions_payload_sha256": DISPOSITIONS_PAYLOAD_SHA256,
        "verifier_source_sha256": sha256(self_raw),
        "verifier_contract_sha256": sha256(contract_raw),
        "external_build_receipt_sha256": sha256(build_raw),
        "external_link_receipt_sha256": sha256(link_raw),
        "link_map_sha256": link_map_sha,
        "linked_image_sha256": linked_image_sha,
        "objects": output_objects,
        "refusals": output_refusals,
    }
    return {
        "schema": OUTPUT_SCHEMA,
        "payload_sha256": canonical_sha(payload),
        "payload": payload,
    }


def write_new(path: Path, value: dict[str, Any]) -> None:
    encoded = (
        json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("ascii")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o644,
    )
    try:
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            require(written > 0, "short write while publishing link evidence")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main() -> None:
    require(
        len(sys.argv) == 6,
        "usage: verify_linked_candidates.py CONTRACT OBJECT_MANIFEST "
        "LITERAL_DISPOSITIONS ARTIFACT_DIRECTORY NEW_OUTPUT",
    )
    output = verify(
        Path(sys.argv[1]),
        Path(sys.argv[2]),
        Path(sys.argv[3]),
        Path(sys.argv[4]),
    )
    output_path = Path(sys.argv[5])
    write_new(output_path, output)
    print(
        json.dumps(
            {
                "output": str(output_path),
                "payload_sha256": output["payload_sha256"],
                "objects": len(output["payload"]["objects"]),
                "refusals": len(output["payload"]["refusals"]),
                "promotion_authority": False,
                "rebar_accepted_as_input": False,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    try:
        main()
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        UnicodeError,
        struct.error,
        Refusal,
    ) as error:
        print(f"search-tag29-static-link-proof: {error}", file=sys.stderr)
        raise SystemExit(1)
