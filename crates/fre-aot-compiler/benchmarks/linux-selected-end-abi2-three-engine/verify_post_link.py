#!/usr/bin/env python3
"""Static post-link checks for the SelectedEnd ABI2 three-engine diagnostic.

This verifier consumes only ELF files plus the deterministic build contract.
It does not execute the benchmark or generated code and never grants runtime,
promotion, or deployment authority.
"""

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
import fcntl
import hashlib
import os
import re
import stat
import struct
import subprocess
from pathlib import Path


SCHEMA = "fre-aot-selected-end-abi2-post-link-contract-v1"
OBSERVATION_SCHEMA = "fre-aot-selected-end-abi2-post-link-observation-v2"
MAX_BINARY_BYTES = 256 << 20
MAX_OBJECT_BYTES = 16 << 20
MAX_CONTRACT_BYTES = 64 << 10
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SYMBOL = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
INSTRUCTION = re.compile(
    r"^\s*([0-9a-f]+):\s+([0-9a-f]{8}(?:\s+[0-9a-f]{8})*)\s+"
    r"([a-z0-9.]+)\s*(.*?)\s*$"
)
RELOCATION = re.compile(
    r"^\s*[0-9a-f]+\s+[0-9a-f]+\s+(R_AARCH64_[A-Z0-9_]+)\s+"
    r"[0-9a-f]+\s+(\S+)(?:\s+[+-]\s+[0-9a-f]+)?\s*$"
)
ELF64_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
ELF64_SECTION = struct.Struct("<IIQQQQIIQQ")
ELF64_SYMBOL = struct.Struct("<IBBHQQ")
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHN_UNDEF = 0
SHN_LORESERVE = 0xFF00

CONTRACT_KEYS = (
    "schema",
    "evidence_class",
    "promotion_authority",
    "runtime_authority",
    "source_commit",
    "source_tree",
    "helper_sha256",
    "profile",
    "target",
    "backend",
    "abi",
    "literal_hex",
    "source_identity",
    "artifact_identity",
    "compile_identity",
    "implementation_object_identity",
    "glue_object_identity",
    "compiler_receipt_identity",
    "expectation_identity",
    "bundle_identity",
    "wrapper_symbol",
    "entry_symbol",
    "payload_symbol",
    "metadata_symbol",
    "required_relocation",
    "required_final_call",
    "primary_aot_hot_route",
    "qualification_wrapper_route",
    "reject_indirect_branch",
    "reject_plt",
    "reject_x4_argument",
    "result_slot_bytes",
    "required_sve_vector_bytes",
    "aot_compiler_cost_scope",
    "aot_linker_cost_scope",
    "post_link_observation",
)


class Refusal(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def read_regular(path: Path, maximum: int, label: str) -> bytes:
    before = os.stat(path, follow_symlinks=False)
    require(stat.S_ISREG(before.st_mode), f"{label} is not a regular file")
    require(0 < before.st_size <= maximum, f"{label} violates its byte bound")
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
    )
    try:
        opened = os.fstat(descriptor)
        require(
            (opened.st_dev, opened.st_ino, opened.st_size)
            == (before.st_dev, before.st_ino, before.st_size),
            f"{label} changed before open",
        )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1 << 20, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            require(total <= maximum, f"{label} exceeds its byte bound")
        after = os.fstat(descriptor)
        require(
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            == (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns),
            f"{label} changed while read",
        )
        return b"".join(chunks)
    finally:
        os.close(descriptor)


class SealedSnapshot:
    def __init__(self, raw: bytes, label: str) -> None:
        try:
            descriptor = os.memfd_create(
                f"fre-abi2-{label}",
                os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
            )
        except (AttributeError, OSError) as error:
            raise Refusal(f"cannot create sealed {label} snapshot: {error}") from error
        try:
            written = 0
            while written < len(raw):
                count = os.write(descriptor, raw[written:])
                require(count > 0, f"short write while snapshotting {label}")
                written += count
            seals = (
                fcntl.F_SEAL_SEAL
                | fcntl.F_SEAL_SHRINK
                | fcntl.F_SEAL_GROW
                | fcntl.F_SEAL_WRITE
            )
            fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seals)
            os.lseek(descriptor, 0, os.SEEK_SET)
        except BaseException:
            os.close(descriptor)
            raise
        self.descriptor = descriptor
        self.path = Path(f"/proc/self/fd/{descriptor}")

    def close(self) -> None:
        os.close(self.descriptor)


def region(raw: bytes, offset: int, size: int, label: str) -> bytes:
    require(offset >= 0 and size >= 0, f"{label} has a negative extent")
    end = offset + size
    require(
        end >= offset and end <= len(raw),
        f"{label} lies outside its ELF file",
    )
    return raw[offset:end]


def elf_sections(raw: bytes, label: str) -> list[tuple[int, ...]]:
    require(len(raw) >= ELF64_HEADER.size, f"{label} has a truncated ELF header")
    (
        identity,
        elf_type,
        machine,
        version,
        _entry,
        _program_offset,
        section_offset,
        _flags,
        header_bytes,
        _program_entry_bytes,
        _program_count,
        section_entry_bytes,
        section_count,
        section_names,
    ) = ELF64_HEADER.unpack_from(raw)
    require(
        identity[:7] == b"\x7fELF\x02\x01\x01"
        and elf_type in (1, 2, 3)
        and machine == 183
        and version == 1
        and header_bytes == ELF64_HEADER.size,
        f"{label} is not a canonical ELF64LE AArch64 file",
    )
    require(
        section_entry_bytes == ELF64_SECTION.size
        and 0 < section_count < SHN_LORESERVE
        and section_names < section_count,
        f"{label} uses an unsupported section-table encoding",
    )
    table_bytes = section_entry_bytes * section_count
    table = region(raw, section_offset, table_bytes, f"{label} section table")
    return [
        ELF64_SECTION.unpack_from(table, index * ELF64_SECTION.size)
        for index in range(section_count)
    ]


def elf_symbol(raw: bytes, symbol: str, label: str) -> dict[str, int | bytes]:
    sections = elf_sections(raw, label)
    symtabs = [section for section in sections if section[1] == SHT_SYMTAB]
    require(len(symtabs) == 1, f"{label} does not have one SHT_SYMTAB")
    symtab = symtabs[0]
    symtab_offset = symtab[4]
    symtab_bytes = symtab[5]
    string_index = symtab[6]
    symbol_bytes = symtab[9]
    require(
        symbol_bytes == ELF64_SYMBOL.size
        and symtab_bytes % symbol_bytes == 0
        and string_index < len(sections)
        and sections[string_index][1] == SHT_STRTAB,
        f"{label} has an unsupported symbol-table encoding",
    )
    strings_section = sections[string_index]
    strings = region(
        raw,
        strings_section[4],
        strings_section[5],
        f"{label} symbol strings",
    )
    symbols = region(raw, symtab_offset, symtab_bytes, f"{label} symbol table")
    matches: list[dict[str, int | bytes]] = []
    for offset in range(0, len(symbols), ELF64_SYMBOL.size):
        name_offset, info, visibility, section_index, value, size = (
            ELF64_SYMBOL.unpack_from(symbols, offset)
        )
        require(name_offset < len(strings), f"{label} symbol name is out of range")
        name_end = strings.find(b"\0", name_offset)
        require(name_end >= 0, f"{label} symbol name is unterminated")
        try:
            name = strings[name_offset:name_end].decode("ascii")
        except UnicodeError as error:
            raise Refusal(f"{label} symbol name is not ASCII") from error
        if name != symbol:
            continue
        require(
            section_index != SHN_UNDEF
            and section_index < SHN_LORESERVE
            and section_index < len(sections),
            f"{label} symbol {symbol} is not defined in a regular section",
        )
        section = sections[section_index]
        require(
            section[1] == SHT_PROGBITS,
            f"{label} symbol {symbol} is not backed by SHT_PROGBITS",
        )
        section_address = section[3]
        section_file_offset = section[4]
        section_size = section[5]
        require(
            value >= section_address,
            f"{label} symbol {symbol} precedes its section",
        )
        relative = value - section_address
        require(
            size > 0 and relative + size <= section_size,
            f"{label} symbol {symbol} exceeds its section",
        )
        matches.append(
            {
                "value": value,
                "size": size,
                "info": info,
                "visibility": visibility & 0x3,
                "bytes": region(
                    raw,
                    section_file_offset + relative,
                    size,
                    f"{label} symbol {symbol}",
                ),
            }
        )
    require(
        len(matches) == 1,
        f"{label} does not have one defined {symbol} symbol",
    )
    return matches[0]


def parse_contract(raw: bytes) -> dict[str, str]:
    require(
        raw.endswith(b"\n") and b"\r" not in raw and b"\0" not in raw,
        "contract is not canonical LF-terminated text",
    )
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError as error:
        raise Refusal("contract is not ASCII") from error
    fields: dict[str, str] = {}
    for line in lines:
        parts = line.split("\t")
        require(len(parts) == 2 and all(parts), "contract row is malformed")
        key, value = parts
        require(key not in fields, f"duplicate contract field {key!r}")
        fields[key] = value
    require(tuple(fields) == CONTRACT_KEYS, "contract field order/set changed")
    require(fields["schema"] == SCHEMA, "contract schema changed")
    require(
        fields["evidence_class"] == "diagnostic-nonpromotion"
        and fields["promotion_authority"] == "absent"
        and fields["runtime_authority"] == "absent",
        "contract attempts to grant authority",
    )
    require(
        fields["target"] == "aarch64-unknown-linux-little-endian-lp64"
        and fields["backend"] == "tag21-sve2-fixed16"
        and fields["abi"] == "selected-end-register-v2"
        and fields["literal_hex"] == "30313233343536373839616263646566",
        "target, backend, ABI, or literal contract changed",
    )
    require(
        HEX40.fullmatch(fields["source_commit"]) is not None
        and HEX40.fullmatch(fields["source_tree"]) is not None,
        "source commit/tree is not canonical hexadecimal",
    )
    for key in (
        "helper_sha256",
        "source_identity",
        "artifact_identity",
        "compile_identity",
        "implementation_object_identity",
        "glue_object_identity",
        "compiler_receipt_identity",
        "expectation_identity",
        "bundle_identity",
    ):
        require(
            HEX64.fullmatch(fields[key]) is not None and fields[key] != "0" * 64,
            f"{key} is not canonical nonzero SHA-256-width hexadecimal",
        )
    compile_identity = fields["compile_identity"]
    expected_symbols = {
        "wrapper_symbol": (
            "fre_aot_search_selected_end_qualification_direct_v2_"
            + compile_identity
        ),
        "entry_symbol": "fre_aot_search_selected_end_entry_v2_" + compile_identity,
        "payload_symbol": (
            "fre_aot_search_selected_end_payload_v2_" + compile_identity
        ),
        "metadata_symbol": (
            "fre_aot_search_selected_end_metadata_v2_" + compile_identity
        ),
    }
    for key, expected in expected_symbols.items():
        require(
            SYMBOL.fullmatch(fields[key]) is not None and fields[key] == expected,
            f"{key} differs from its exact identity-derived namespace",
        )
    require(
        fields["required_relocation"] == "R_AARCH64_CALL26"
        and fields["required_final_call"] == "direct-bl-exact-entry"
        and fields["primary_aot_hot_route"] == "exact-entry-direct"
        and fields["qualification_wrapper_route"]
        == "linked-validated-diagnostic-only"
        and fields["reject_indirect_branch"] == "blr"
        and fields["reject_plt"] == "true"
        and fields["reject_x4_argument"] == "true"
        and fields["result_slot_bytes"] == "0"
        and fields["required_sve_vector_bytes"] == "16"
        and fields["aot_compiler_cost_scope"] == "offline-excluded"
        and fields["aot_linker_cost_scope"] == "offline-excluded"
        and fields["post_link_observation"] == "pending",
        "post-link or timing-scope obligations changed",
    )
    return fields


def run_tool(tool: str, *arguments: str, pass_fds: tuple[int, ...] = ()) -> str:
    command = [tool, *arguments]
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            pass_fds=pass_fds,
            env={
                "LC_ALL": "C",
                "LANG": "C",
                "TZ": "UTC",
                "PATH": "/usr/bin:/bin",
            },
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise Refusal(f"{Path(tool).name} failed: {error}") from error
    require(not result.stderr, f"{Path(tool).name} wrote stderr")
    require(len(result.stdout) <= 64 << 20, f"{Path(tool).name} output too large")
    try:
        return result.stdout.decode("ascii")
    except UnicodeError as error:
        raise Refusal(f"{Path(tool).name} output is not ASCII") from error


def require_aarch64_elf(
    snapshot: SealedSnapshot,
    label: str,
    relocatable: bool,
) -> None:
    header = run_tool(
        "/usr/bin/readelf",
        "-Wh",
        os.fspath(snapshot.path),
        pass_fds=(snapshot.descriptor,),
    )
    require(
        "Class:                             ELF64" in header
        and "Data:                              2's complement, little endian" in header
        and "Machine:                           AArch64" in header,
        f"{label} is not ELF64LE AArch64",
    )
    expected_type = (
        "Type:                              REL (Relocatable file)"
        if relocatable
        else None
    )
    require(
        expected_type is None or expected_type in header,
        f"{label} is not relocatable",
    )


def symbol_rows(snapshot: SealedSnapshot) -> list[list[str]]:
    output = run_tool(
        "/usr/bin/readelf",
        "-Ws",
        os.fspath(snapshot.path),
        pass_fds=(snapshot.descriptor,),
    )
    rows: list[list[str]] = []
    for line in output.splitlines():
        if re.match(r"^\s*[0-9]+:", line):
            rows.append(line.split())
    return rows


def require_symbol(
    rows: list[list[str]],
    symbol: str,
    *,
    defined: bool,
    hidden: bool,
    kind: str,
) -> None:
    matches = [row for row in rows if row[-1] == symbol]
    require(len(matches) == 1, f"{symbol} does not have one symbol-table row")
    row = matches[0]
    require(len(row) >= 8, f"{symbol} has a malformed symbol-table row")
    require(row[3] == kind, f"{symbol} has unexpected symbol kind {row[3]!r}")
    require(
        (row[6] != "UND") == defined,
        f"{symbol} defined/undefined state changed",
    )
    require(
        (row[5] == "HIDDEN") == hidden,
        f"{symbol} hidden visibility changed",
    )


def require_glue_relocation(glue: SealedSnapshot, entry: str) -> None:
    output = run_tool(
        "/usr/bin/readelf",
        "-Wr",
        os.fspath(glue.path),
        pass_fds=(glue.descriptor,),
    )
    relocations: list[tuple[str, str]] = []
    for line in output.splitlines():
        if "R_AARCH64_" not in line:
            continue
        match = RELOCATION.fullmatch(line)
        require(match is not None, f"unparsed direct-glue relocation row: {line!r}")
        relocations.append((match.group(1), match.group(2)))
    require(
        relocations == [("R_AARCH64_CALL26", entry)],
        f"direct-glue relocation set changed: {relocations!r}",
    )


def instructions(output: str) -> list[tuple[int, str, str, str]]:
    decoded: list[tuple[int, str, str, str]] = []
    for line in output.splitlines():
        match = INSTRUCTION.fullmatch(line)
        if match is not None:
            decoded.append(
                (
                    int(match.group(1), 16),
                    match.group(2).replace(" ", ""),
                    match.group(3),
                    match.group(4),
                )
            )
    return decoded


def require_wrapper(binary: SealedSnapshot, wrapper: str, entry: str) -> None:
    output = run_tool(
        "/usr/bin/objdump",
        "-d",
        f"--disassemble={wrapper}",
        os.fspath(binary.path),
        pass_fds=(binary.descriptor,),
    )
    decoded = instructions(output)
    require(
        [mnemonic for _, _, mnemonic, _ in decoded]
        == ["stp", "bl", "ldp", "ret"],
        f"linked qualification wrapper is not exact stp/bl/ldp/ret: {decoded!r}",
    )
    call_operands = decoded[1][3]
    require(
        f"<{entry}>" in call_operands
        and "@plt" not in call_operands.lower()
        and ".plt" not in call_operands.lower(),
        "qualification wrapper does not directly bl the exact entry",
    )
    wrapper_text = "\n".join(
        f"{mnemonic} {operands}" for _, _, mnemonic, operands in decoded
    )
    require(
        re.search(r"\bblr\b", wrapper_text) is None
        and re.search(r"\bx4\b", wrapper_text) is None,
        "qualification wrapper contains blr or x4",
    )


def require_primary_direct_entry_call(
    binary: SealedSnapshot,
    wrapper: str,
    entry: str,
) -> None:
    output = run_tool(
        "/usr/bin/objdump",
        "-d",
        os.fspath(binary.path),
        pass_fds=(binary.descriptor,),
    )
    require(
        f"<{entry}@plt>" not in output
        and f"<{entry}.plt>" not in output
        and re.search(rf"\bblr\b[^\n]*<{re.escape(entry)}>", output) is None,
        "exact entry is reachable through PLT or blr",
    )
    direct_calls = [
        (address, operands)
        for address, _, mnemonic, operands in instructions(output)
        if mnemonic == "bl"
        and f"<{entry}>" in operands
        and "@plt" not in operands.lower()
        and ".plt" not in operands.lower()
    ]
    require(
        len(direct_calls) >= 2,
        "final image lacks separate direct bl calls for the P2b wrapper and primary AOT route",
    )
    wrapper_output = run_tool(
        "/usr/bin/objdump",
        "-d",
        f"--disassemble={wrapper}",
        os.fspath(binary.path),
        pass_fds=(binary.descriptor,),
    )
    wrapper_calls = {
        address
        for address, _, mnemonic, operands in instructions(wrapper_output)
        if mnemonic == "bl" and f"<{entry}>" in operands
    }
    require(
        len(wrapper_calls) == 1
        and any(address not in wrapper_calls for address, _ in direct_calls),
        "all exact-entry calls came from the qualification wrapper",
    )


def require_linked_implementation_bytes(
    binary: bytes,
    implementation: bytes,
    entry: str,
    payload: str,
    metadata: str,
) -> None:
    for symbol, description in (
        (entry, "exact entry instruction"),
        (payload, "complete code/padding/literal payload"),
        (metadata, "complete AOT metadata"),
    ):
        linked = elf_symbol(binary, symbol, "final executable")
        relocatable = elf_symbol(implementation, symbol, "implementation object")
        require(
            linked["bytes"] == relocatable["bytes"]
            and linked["size"] == relocatable["size"],
            f"linked {description} bytes differ from the input implementation object",
        )


def require_metadata_contract(
    implementation: bytes,
    payload: str,
    metadata: str,
    contract: dict[str, str],
) -> None:
    payload_bytes = elf_symbol(
        implementation,
        payload,
        "implementation object",
    )["bytes"]
    metadata_bytes = elf_symbol(
        implementation,
        metadata,
        "implementation object",
    )["bytes"]
    require(
        isinstance(payload_bytes, bytes)
        and isinstance(metadata_bytes, bytes)
        and len(metadata_bytes) == 224,
        "implementation metadata does not have its exact extent",
    )
    require(
        metadata_bytes[:8] == b"FRESE64\x02"
        and struct.unpack_from("<H", metadata_bytes, 8)[0] == 2
        and struct.unpack_from("<H", metadata_bytes, 10)[0] == 224
        and struct.unpack_from("<H", metadata_bytes, 12)[0] == 21
        and metadata_bytes[14:22] == bytes([2, 2, 1, 1, 64, 1, 2, 64])
        and struct.unpack_from("<H", metadata_bytes, 22)[0] == 2
        and metadata_bytes[24:26] == bytes([1, 1])
        and struct.unpack_from("<H", metadata_bytes, 26)[0] == 16
        and struct.unpack_from("<I", metadata_bytes, 28)[0] == 0
        and struct.unpack_from("<Q", metadata_bytes, 32)[0] == 7,
        "implementation metadata target/backend/ABI header changed",
    )
    claimed_payload_bytes = struct.unpack_from("<I", metadata_bytes, 40)[0]
    entry_offset = struct.unpack_from("<I", metadata_bytes, 44)[0]
    code_bytes = struct.unpack_from("<I", metadata_bytes, 48)[0]
    rodata_offset = struct.unpack_from("<I", metadata_bytes, 52)[0]
    rodata_bytes = struct.unpack_from("<I", metadata_bytes, 56)[0]
    literal_bytes = struct.unpack_from("<I", metadata_bytes, 60)[0]
    require(
        claimed_payload_bytes == len(payload_bytes)
        and entry_offset == 0
        and 0 < code_bytes <= rodata_offset
        and rodata_offset + rodata_bytes == len(payload_bytes)
        and rodata_bytes == literal_bytes == 16,
        "implementation metadata payload layout changed",
    )
    require(
        payload_bytes[rodata_offset:] == bytes.fromhex(contract["literal_hex"]),
        "implementation payload literal differs from the contract",
    )
    require(
        metadata_bytes[96:128].hex() == contract["artifact_identity"]
        and metadata_bytes[192:224].hex() == contract["compile_identity"],
        "implementation metadata identity differs from the contract",
    )
    metadata_body = bytearray(metadata_bytes)
    metadata_body[192:224] = bytes(32)
    compile_hasher = hashlib.sha256()
    compile_hasher.update(b"FRE-AOT-ELF-SEARCH-SELECTED-END-COMPILE\0\x02")
    compile_hasher.update(struct.pack("<HHH", 2, 2, 64))
    for prefix, symbol_info in (
        (b"fre_aot_search_selected_end_entry_v2_", 0x12),
        (b"fre_aot_search_selected_end_payload_v2_", 0x11),
        (b"fre_aot_search_selected_end_metadata_v2_", 0x11),
    ):
        compile_hasher.update(struct.pack("<H", len(prefix)))
        compile_hasher.update(prefix)
        compile_hasher.update(bytes([symbol_info, 2]))
    compile_hasher.update(bytes([2, 1, 1, 0]))
    compile_hasher.update(struct.pack("<HH", 1, 183))
    compile_hasher.update(metadata_body)
    require(
        compile_hasher.hexdigest() == contract["compile_identity"],
        "implementation metadata compile identity is not authentic",
    )
    require(
        hashlib.sha256(payload_bytes).digest() == metadata_bytes[160:192],
        "implementation metadata payload digest is invalid",
    )


def require_exact_linked_wrapper_bytes(
    binary: bytes,
    glue: bytes,
    wrapper: str,
    entry: str,
) -> None:
    linked_wrapper = elf_symbol(binary, wrapper, "final executable")
    relocatable_wrapper = elf_symbol(glue, wrapper, "direct-glue object")
    linked_entry = elf_symbol(binary, entry, "final executable")
    linked_bytes = linked_wrapper["bytes"]
    relocatable_bytes = relocatable_wrapper["bytes"]
    require(
        isinstance(linked_bytes, bytes)
        and isinstance(relocatable_bytes, bytes)
        and len(linked_bytes) == 16
        and len(relocatable_bytes) == 16,
        "qualification wrapper does not have the exact four-instruction extent",
    )
    require(
        linked_bytes[:4] == relocatable_bytes[:4]
        and linked_bytes[8:] == relocatable_bytes[8:],
        "linker changed a qualification-wrapper instruction outside the call relocation",
    )
    relocatable_call = int.from_bytes(relocatable_bytes[4:8], "little")
    linked_call = int.from_bytes(linked_bytes[4:8], "little")
    require(
        relocatable_call == 0x94000000
        and linked_call & 0xFC000000 == 0x94000000,
        "qualification-wrapper relocation is not an exact AArch64 bl",
    )
    immediate = linked_call & 0x03FFFFFF
    if immediate & (1 << 25):
        immediate -= 1 << 26
    call_address = int(linked_wrapper["value"]) + 4
    call_target = call_address + (immediate << 2)
    require(
        call_target == linked_entry["value"],
        "qualification-wrapper bl does not resolve to the exact entry address",
    )


def require_wx(binary: SealedSnapshot) -> None:
    output = run_tool(
        "/usr/bin/readelf",
        "-Wl",
        os.fspath(binary.path),
        pass_fds=(binary.descriptor,),
    )
    load_rows = [
        line.split()
        for line in output.splitlines()
        if line.lstrip().startswith("LOAD")
    ]
    require(load_rows, "final image has no PT_LOAD rows")
    for row in load_rows:
        flags = "".join(row[6:-1])
        require(not ("W" in flags and "E" in flags), "final image has an RWX PT_LOAD")
    stack_rows = [
        line.split()
        for line in output.splitlines()
        if line.lstrip().startswith("GNU_STACK")
    ]
    require(
        len(stack_rows) == 1 and "E" not in "".join(stack_rows[0][6:-1]),
        "final image has an executable or ambiguous GNU_STACK",
    )


def verify(arguments: argparse.Namespace) -> None:
    binary_path = arguments.binary.resolve(strict=True)
    implementation_path = arguments.implementation.resolve(strict=True)
    glue_path = arguments.glue.resolve(strict=True)
    contract_path = arguments.contract.resolve(strict=True)
    binary_bytes = read_regular(binary_path, MAX_BINARY_BYTES, "final executable")
    implementation_bytes = read_regular(
        implementation_path,
        MAX_OBJECT_BYTES,
        "implementation object",
    )
    glue_bytes = read_regular(glue_path, MAX_OBJECT_BYTES, "direct-glue object")
    contract = parse_contract(
        read_regular(contract_path, MAX_CONTRACT_BYTES, "post-link contract")
    )
    require(
        arguments.source_commit == contract["source_commit"]
        and arguments.source_tree == contract["source_tree"],
        "requested source commit/tree differs from build contract",
    )
    require(
        hashlib.sha256(implementation_bytes).hexdigest()
        == contract["implementation_object_identity"],
        "implementation object bytes differ from the contract identity",
    )
    glue_hasher = hashlib.sha256()
    glue_hasher.update(
        b"FRE-AOT-LINUX-SEARCH-SELECTED-END-DIRECT-GLUE-OBJECT\0\x02"
    )
    glue_hasher.update(glue_bytes)
    require(
        glue_hasher.hexdigest() == contract["glue_object_identity"],
        "direct-glue object bytes differ from the domain-separated contract identity",
    )
    require(binary_bytes[:4] == b"\x7fELF", "final executable lacks ELF magic")
    snapshots: list[SealedSnapshot] = []
    try:
        snapshots.append(SealedSnapshot(binary_bytes, "final-executable"))
        snapshots.append(SealedSnapshot(implementation_bytes, "implementation-object"))
        snapshots.append(SealedSnapshot(glue_bytes, "direct-glue-object"))
        binary, implementation, glue = snapshots
        require_aarch64_elf(binary, "final executable", False)
        require_aarch64_elf(implementation, "implementation object", True)
        require_aarch64_elf(glue, "direct-glue object", True)

        wrapper = contract["wrapper_symbol"]
        entry = contract["entry_symbol"]
        payload = contract["payload_symbol"]
        metadata = contract["metadata_symbol"]
        glue_symbols = symbol_rows(glue)
        implementation_symbols = symbol_rows(implementation)
        binary_symbols = symbol_rows(binary)
        require_symbol(
            glue_symbols,
            wrapper,
            defined=True,
            hidden=True,
            kind="FUNC",
        )
        require_symbol(
            glue_symbols,
            entry,
            defined=False,
            hidden=True,
            kind="NOTYPE",
        )
        require_symbol(
            implementation_symbols,
            entry,
            defined=True,
            hidden=True,
            kind="FUNC",
        )
        require_symbol(
            implementation_symbols,
            payload,
            defined=True,
            hidden=True,
            kind="OBJECT",
        )
        require_symbol(
            implementation_symbols,
            metadata,
            defined=True,
            hidden=True,
            kind="OBJECT",
        )
        require_symbol(
            binary_symbols,
            wrapper,
            defined=True,
            hidden=True,
            kind="FUNC",
        )
        require_symbol(
            binary_symbols,
            entry,
            defined=True,
            hidden=True,
            kind="FUNC",
        )
        require_symbol(
            binary_symbols,
            payload,
            defined=True,
            hidden=True,
            kind="OBJECT",
        )
        require_symbol(
            binary_symbols,
            metadata,
            defined=True,
            hidden=True,
            kind="OBJECT",
        )
        require_glue_relocation(glue, entry)
        require_wrapper(binary, wrapper, entry)
        require_primary_direct_entry_call(binary, wrapper, entry)
        require_exact_linked_wrapper_bytes(
            binary_bytes,
            glue_bytes,
            wrapper,
            entry,
        )
        require_linked_implementation_bytes(
            binary_bytes,
            implementation_bytes,
            entry,
            payload,
            metadata,
        )
        require_metadata_contract(
            implementation_bytes,
            payload,
            metadata,
            contract,
        )
        require_wx(binary)
    finally:
        for snapshot in reversed(snapshots):
            snapshot.close()
    print(
        "OBSERVATION"
        f"\t{OBSERVATION_SCHEMA}"
        "\tPASS"
        f"\tsource_commit={contract['source_commit']}"
        f"\tsource_tree={contract['source_tree']}"
        f"\tartifact_identity={contract['artifact_identity']}"
        f"\tcompile_identity={contract['compile_identity']}"
        f"\timplementation_object_identity={contract['implementation_object_identity']}"
        f"\tglue_object_identity={contract['glue_object_identity']}"
        f"\tbundle_identity={contract['bundle_identity']}"
        f"\tfinal_binary_sha256={hashlib.sha256(binary_bytes).hexdigest()}"
        f"\thelper_sha256={contract['helper_sha256']}"
        f"\tprofile={contract['profile']}"
        "\twrapper_call=R_AARCH64_CALL26-to-direct-bl"
        "\tprimary_aot_call=direct-bl-exact-entry"
        "\tentry_bytes_equal=true"
        "\tpayload_bytes_equal=true"
        "\tmetadata_bytes_equal=true"
        "\tcompile_identity_derived=true"
        "\treject_plt=true"
        "\treject_blr=true"
        "\treject_x4_argument=true"
        "\tresult_slot_bytes=0"
        "\truntime_authority=absent"
        "\tpromotion_authority=absent"
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--binary", required=True, type=Path)
    result.add_argument("--implementation", required=True, type=Path)
    result.add_argument("--glue", required=True, type=Path)
    result.add_argument("--contract", required=True, type=Path)
    result.add_argument("--source-commit", required=True)
    result.add_argument("--source-tree", required=True)
    return result


def main() -> int:
    arguments = parser().parse_args()
    require(
        HEX40.fullmatch(arguments.source_commit) is not None
        and HEX40.fullmatch(arguments.source_tree) is not None,
        "source commit/tree arguments are not canonical lowercase hexadecimal",
    )
    verify(arguments)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Refusal as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        raise SystemExit(1) from error
