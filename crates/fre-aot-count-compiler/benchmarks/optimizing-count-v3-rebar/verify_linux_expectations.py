#!/usr/bin/env python3
"""Verify that linked Count-v3 expectations occupy only R-only ELF mappings."""

from __future__ import annotations

import sys

if (
    sys.flags.isolated != 1
    or not sys.dont_write_bytecode
    or sys.flags.optimize != 0
):
    print(
        "REFUSED: use python3 -I -B without optimization",
        file=sys.stderr,
    )
    raise SystemExit(1)

import argparse
import hashlib
import json
import os
import re
import stat
import struct
from pathlib import Path
from typing import Any


AUDIT_SCHEMA = "fre.optimizing-count-v3.linux-expectation-layout-audit.v1"
REGISTRY_SCHEMAS = {
    "fre.optimizing-count-v3.compiled-artifact-registry.v2",
    "fre.optimizing-count-v3.production-confirmation-artifact-registry.v1",
}
TARGET_TRIPLE = "aarch64-unknown-linux-gnu"
OBJECT_FORMAT = "elf64-aarch64"
EXPECTATION_BYTES = 1_144
MAX_RUNNER_BYTES = 512 << 20
MAX_REGISTRY_BYTES = 64 << 20
MAX_PATTERNS = 4_096
HEX64 = re.compile(r"^[0-9a-f]{64}$")
EXPECTATION_SYMBOL = re.compile(
    r"^fre_aot_count_expectation_v3_[0-9a-f]{64}$"
)

ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
SECTION_HEADER = struct.Struct("<IIQQQQIIQQ")
SYMBOL = struct.Struct("<IBBHQQ")

ET_EXEC = 2
ET_DYN = 3
EM_AARCH64 = 183
PT_LOAD = 1
PT_GNU_STACK = 0x6474E551
PF_X = 1
PF_W = 2
PF_R = 4
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_NOBITS = 8
SHN_UNDEF = 0
SHN_LORESERVE = 0xFF00
SHF_WRITE = 1
SHF_ALLOC = 2
SHF_EXECINSTR = 4
STB_LOCAL = 0
STB_GLOBAL = 1
STT_OBJECT = 1
STV_HIDDEN = 2
MIN_PAGE_BYTES = 4_096
MAX_PAGE_BYTES = 2 << 20


class Refusal(ValueError):
    """A malformed or insufficiently protected final image."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def checked_region(data: bytes, offset: int, size: int, label: str) -> bytes:
    require(offset >= 0 and size >= 0, f"{label}: negative extent")
    end = offset + size
    require(end >= offset and end <= len(data), f"{label}: outside file")
    return data[offset:end]


def read_regular(path: Path, maximum: int, label: str) -> bytes:
    before = os.stat(path, follow_symlinks=False)
    require(stat.S_ISREG(before.st_mode), f"{label}: not a regular file")
    require(0 < before.st_size <= maximum, f"{label}: invalid byte length")
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
    )
    try:
        opened = os.fstat(descriptor)
        require(
            (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            == (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns),
            f"{label}: changed before open",
        )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1 << 20, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            require(total <= maximum, f"{label}: exceeds byte bound")
        after = os.fstat(descriptor)
        require(
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            == (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns),
            f"{label}: changed while read",
        )
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def parse_json(data: bytes, label: str) -> Any:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, f"{label}: duplicate key {key}")
            result[key] = value
        return result

    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                Refusal(f"{label}: non-finite number {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Refusal(f"{label}: invalid JSON: {error}") from error


def expectation_contracts(registry: Any) -> dict[str, str]:
    require(isinstance(registry, dict), "registry: root is not an object")
    require(registry.get("schema") in REGISTRY_SCHEMAS, "registry: unknown schema")
    require(
        registry.get("target_triple") == TARGET_TRIPLE,
        "registry: target triple is not Linux/AArch64",
    )
    require(
        registry.get("object_format") == OBJECT_FORMAT,
        "registry: object format is not ELF64/AArch64",
    )
    patterns = registry.get("compiled_patterns")
    require(
        isinstance(patterns, list) and 0 < len(patterns) <= MAX_PATTERNS,
        "registry: invalid compiled pattern count",
    )
    require(
        registry.get("distinct_artifacts") == len(patterns),
        "registry: distinct artifact count differs",
    )
    contracts: dict[str, str] = {}
    for ordinal, pattern in enumerate(patterns):
        require(isinstance(pattern, dict), f"pattern {ordinal}: not an object")
        engines = pattern.get("engines")
        require(isinstance(engines, list), f"pattern {ordinal}: engines is not a list")
        rows = [
            engine
            for engine in engines
            if isinstance(engine, dict) and engine.get("engine") == "count-v3-aot"
        ]
        require(len(rows) == 1, f"pattern {ordinal}: expected one Count-v3 engine")
        row = rows[0]
        symbol = row.get("expectation_symbol")
        digest = row.get("expectation_bytes_sha256")
        require(
            isinstance(symbol, str) and EXPECTATION_SYMBOL.fullmatch(symbol),
            f"pattern {ordinal}: invalid expectation symbol",
        )
        require(
            isinstance(digest, str) and HEX64.fullmatch(digest),
            f"pattern {ordinal}: invalid expectation digest",
        )
        require(
            symbol not in contracts,
            f"pattern {ordinal}: duplicate expectation symbol",
        )
        contracts[symbol] = digest
    return contracts


def c_string(table: bytes, offset: int, label: str) -> str:
    require(0 <= offset < len(table), f"{label}: string offset outside table")
    end = table.find(b"\0", offset)
    require(end >= 0, f"{label}: unterminated string")
    try:
        return table[offset:end].decode("ascii")
    except UnicodeDecodeError as error:
        raise Refusal(f"{label}: non-ASCII string") from error


class ElfImage:
    """Bounded ELF64LE/AArch64 final-image parser."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        require(len(data) >= ELF_HEADER.size, "runner: truncated ELF header")
        (
            identity,
            elf_type,
            machine,
            version,
            _entry,
            program_offset,
            section_offset,
            _flags,
            header_size,
            program_entry_size,
            program_count,
            section_entry_size,
            section_count,
            section_name_index,
        ) = ELF_HEADER.unpack_from(data)
        require(
            identity[:7] == b"\x7fELF\x02\x01\x01"
            and elf_type in (ET_EXEC, ET_DYN)
            and machine == EM_AARCH64
            and version == 1
            and header_size == ELF_HEADER.size,
            "runner: not a supported ELF64LE/AArch64 executable",
        )
        require(
            program_entry_size == PROGRAM_HEADER.size and 0 < program_count <= 256,
            "runner: unsupported program-header encoding",
        )
        require(
            section_entry_size == SECTION_HEADER.size
            and 0 < section_count < SHN_LORESERVE
            and section_name_index < section_count,
            "runner: unsupported section-header encoding",
        )
        program_table = checked_region(
            data,
            program_offset,
            program_count * PROGRAM_HEADER.size,
            "runner program table",
        )
        self.programs = [
            self._program(
                PROGRAM_HEADER.unpack_from(
                    program_table, index * PROGRAM_HEADER.size
                )
            )
            for index in range(program_count)
        ]
        section_table = checked_region(
            data,
            section_offset,
            section_count * SECTION_HEADER.size,
            "runner section table",
        )
        raw_sections = [
            SECTION_HEADER.unpack_from(section_table, index * SECTION_HEADER.size)
            for index in range(section_count)
        ]
        names_row = raw_sections[section_name_index]
        require(names_row[1] == SHT_STRTAB, "runner: section-name table is not STRTAB")
        names = checked_region(
            data, names_row[4], names_row[5], "runner section-name table"
        )
        self.sections = [
            self._section(row, c_string(names, row[0], f"section {index} name"))
            for index, row in enumerate(raw_sections)
        ]
        self.symbols = self._symbols()
        self._verify_program_shape()

    @staticmethod
    def _program(row: tuple[int, ...]) -> dict[str, int]:
        kind, flags, offset, vaddr, _paddr, filesz, memsz, alignment = row
        require(filesz <= memsz, "runner: PT_LOAD file size exceeds memory size")
        return {
            "type": kind,
            "flags": flags,
            "offset": offset,
            "vaddr": vaddr,
            "filesz": filesz,
            "memsz": memsz,
            "alignment": alignment,
        }

    @staticmethod
    def _section(row: tuple[int, ...], name: str) -> dict[str, int | str]:
        (
            _name,
            kind,
            flags,
            address,
            offset,
            size,
            link,
            info,
            alignment,
            entry_size,
        ) = row
        return {
            "name": name,
            "type": kind,
            "flags": flags,
            "address": address,
            "offset": offset,
            "size": size,
            "link": link,
            "info": info,
            "alignment": alignment,
            "entry_size": entry_size,
        }

    def _symbols(self) -> list[dict[str, int | str]]:
        result: list[dict[str, int | str]] = []
        for section_ordinal, section in enumerate(self.sections):
            if section["type"] != SHT_SYMTAB:
                continue
            require(
                section["entry_size"] == SYMBOL.size
                and section["size"] % SYMBOL.size == 0,
                f"section {section_ordinal}: malformed symbol table",
            )
            link = int(section["link"])
            require(
                0 <= link < len(self.sections)
                and self.sections[link]["type"] == SHT_STRTAB,
                f"section {section_ordinal}: symbol strings are not STRTAB",
            )
            strings_row = self.sections[link]
            strings = checked_region(
                self.data,
                int(strings_row["offset"]),
                int(strings_row["size"]),
                f"section {section_ordinal} symbol strings",
            )
            symbols = checked_region(
                self.data,
                int(section["offset"]),
                int(section["size"]),
                f"section {section_ordinal} symbols",
            )
            for offset in range(0, len(symbols), SYMBOL.size):
                name, info, other, section_index, value, size = SYMBOL.unpack_from(
                    symbols, offset
                )
                result.append(
                    {
                        "name": c_string(strings, name, "symbol name"),
                        "bind": info >> 4,
                        "type": info & 0xF,
                        "other": other,
                        "visibility": other & 0x3,
                        "section_index": section_index,
                        "value": value,
                        "size": size,
                    }
                )
        require(result, "runner: no static symbol table")
        return result

    def _verify_program_shape(self) -> None:
        loads = [program for program in self.programs if program["type"] == PT_LOAD]
        require(loads, "runner: no PT_LOAD")
        for ordinal, load in enumerate(loads):
            require(
                load["flags"] & ~(PF_R | PF_W | PF_X) == 0
                and load["flags"] & PF_R
                and load["flags"] != PF_R | PF_W | PF_X,
                f"runner: invalid PT_LOAD {ordinal} flags",
            )
            alignment = load["alignment"]
            require(
                MIN_PAGE_BYTES <= alignment <= MAX_PAGE_BYTES
                and alignment & (alignment - 1) == 0
                and load["offset"] % alignment == load["vaddr"] % alignment,
                f"runner: invalid PT_LOAD {ordinal} alignment",
            )
        stacks = [
            program
            for program in self.programs
            if program["type"] == PT_GNU_STACK
        ]
        require(
            len(stacks) == 1 and not stacks[0]["flags"] & PF_X,
            "runner: exactly one non-executable GNU stack is required",
        )

    def definition(self, name: str) -> dict[str, int | str]:
        found = [
            symbol
            for symbol in self.symbols
            if symbol["name"] == name and symbol["section_index"] != SHN_UNDEF
        ]
        require(len(found) == 1, f"{name}: expected one final definition")
        symbol = found[0]
        require(
            symbol["bind"] in (STB_LOCAL, STB_GLOBAL)
            and symbol["type"] == STT_OBJECT
            and symbol["other"] == STV_HIDDEN
            and symbol["visibility"] == STV_HIDDEN,
            f"{name}: final symbol type/visibility differs",
        )
        section_index = int(symbol["section_index"])
        require(
            0 < section_index < len(self.sections),
            f"{name}: special section index refused",
        )
        return symbol

    def verify_expectation(
        self, name: str, expected_sha256: str
    ) -> dict[str, int | str]:
        symbol = self.definition(name)
        require(symbol["size"] == EXPECTATION_BYTES, f"{name}: symbol width differs")
        section = self.sections[int(symbol["section_index"])]
        section_flags = int(section["flags"])
        require(
            section_flags & SHF_ALLOC
            and not section_flags & (SHF_WRITE | SHF_EXECINSTR),
            f"{name}: section is not allocated non-W/non-X data",
        )
        require(section["type"] != SHT_NOBITS, f"{name}: NOBITS definition refused")
        relative = int(symbol["value"]) - int(section["address"])
        require(
            relative >= 0 and relative + EXPECTATION_BYTES <= int(section["size"]),
            f"{name}: symbol lies outside section",
        )
        file_offset = int(section["offset"]) + relative
        payload = checked_region(self.data, file_offset, EXPECTATION_BYTES, name)
        require(
            hashlib.sha256(payload).hexdigest() == expected_sha256,
            f"{name}: linked bytes differ from registry",
        )
        mappings = []
        for program in self.programs:
            if program["type"] != PT_LOAD:
                continue
            delta = int(symbol["value"]) - program["vaddr"]
            if (
                delta >= 0
                and delta + EXPECTATION_BYTES <= program["memsz"]
                and delta + EXPECTATION_BYTES <= program["filesz"]
                and program["offset"] + delta == file_offset
            ):
                mappings.append(program)
        require(len(mappings) == 1, f"{name}: not in exactly one file-backed PT_LOAD")
        mapping = mappings[0]
        require(mapping["flags"] == PF_R, f"{name}: PT_LOAD is not exactly R-only")

        page_bytes = max(
            MIN_PAGE_BYTES,
            *(
                program["alignment"]
                for program in self.programs
                if program["type"] == PT_LOAD
            ),
        )
        expectation_start = int(symbol["value"]) & -page_bytes
        expectation_end = (
            int(symbol["value"]) + EXPECTATION_BYTES + page_bytes - 1
        ) & -page_bytes
        for program in self.programs:
            if program["type"] != PT_LOAD or not program["flags"] & PF_X:
                continue
            executable_start = program["vaddr"] & -page_bytes
            executable_end = (
                program["vaddr"] + program["memsz"] + page_bytes - 1
            ) & -page_bytes
            require(
                expectation_end <= executable_start
                or executable_end <= expectation_start,
                f"{name}: executable PT_LOAD overlaps an expectation page",
            )
        return {
            "section": str(section["name"]),
            "vaddr": int(symbol["value"]),
            "bytes": EXPECTATION_BYTES,
            "load_flags": mapping["flags"],
            "page_bytes": page_bytes,
        }


def verify(runner_path: Path, registry_path: Path) -> dict[str, Any]:
    runner = read_regular(runner_path, MAX_RUNNER_BYTES, "runner")
    registry_bytes = read_regular(registry_path, MAX_REGISTRY_BYTES, "registry")
    registry = parse_json(registry_bytes, "registry")
    contracts = expectation_contracts(registry)
    image = ElfImage(runner)
    layouts = [
        {"symbol": symbol, **image.verify_expectation(symbol, digest)}
        for symbol, digest in sorted(contracts.items())
    ]
    page_bytes = {layout["page_bytes"] for layout in layouts}
    require(len(page_bytes) == 1, "runner: expectation page sizes differ")
    return {
        "schema": AUDIT_SCHEMA,
        "runner_sha256": hashlib.sha256(runner).hexdigest(),
        "registry_sha256": hashlib.sha256(registry_bytes).hexdigest(),
        "expectation_count": len(layouts),
        "expectation_page_bytes": page_bytes.pop(),
        "expectations": layouts,
        "status": "pass",
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="verify Count-v3 expectation permissions in one Linux final image"
    )
    result.add_argument("--runner", required=True, type=Path)
    result.add_argument("--registry", required=True, type=Path)
    return result


def main() -> int:
    try:
        arguments = parser().parse_args()
        observation = verify(arguments.runner, arguments.registry)
        print(json.dumps(observation, sort_keys=True, separators=(",", ":")))
    except (OSError, Refusal) as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
