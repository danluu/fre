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
import hashlib
import os
import re
import stat
import subprocess
from pathlib import Path


SCHEMA = "fre-aot-selected-end-abi2-post-link-contract-v1"
OBSERVATION_SCHEMA = "fre-aot-selected-end-abi2-post-link-observation-v1"
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
    r"[0-9a-f]+\s+(\S+)(?:\s+\+\s+[0-9a-f]+)?\s*$"
)

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


def run_tool(tool: str, *arguments: str) -> str:
    command = [tool, *arguments]
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
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


def require_aarch64_elf(path: Path, label: str, relocatable: bool) -> None:
    header = run_tool("/usr/bin/readelf", "-Wh", os.fspath(path))
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


def symbol_rows(path: Path) -> list[list[str]]:
    output = run_tool("/usr/bin/readelf", "-Ws", os.fspath(path))
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


def require_glue_relocation(glue: Path, entry: str) -> None:
    output = run_tool("/usr/bin/readelf", "-Wr", os.fspath(glue))
    relocations: list[tuple[str, str]] = []
    for line in output.splitlines():
        match = RELOCATION.fullmatch(line)
        if match is not None:
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


def require_wrapper(binary: Path, wrapper: str, entry: str) -> None:
    output = run_tool(
        "/usr/bin/objdump",
        "-d",
        f"--disassemble={wrapper}",
        os.fspath(binary),
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


def require_primary_direct_entry_call(binary: Path, wrapper: str, entry: str) -> None:
    output = run_tool("/usr/bin/objdump", "-d", os.fspath(binary))
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
        os.fspath(binary),
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


def require_entry_bytes(binary: Path, implementation: Path, entry: str) -> None:
    linked = instructions(
        run_tool(
            "/usr/bin/objdump",
            "-d",
            f"--disassemble={entry}",
            os.fspath(binary),
        )
    )
    relocatable = instructions(
        run_tool(
            "/usr/bin/objdump",
            "-d",
            f"--disassemble={entry}",
            os.fspath(implementation),
        )
    )
    require(linked and relocatable, "exact entry has no decoded instruction range")
    linked_bytes = [encoding for _, encoding, _, _ in linked]
    relocatable_bytes = [encoding for _, encoding, _, _ in relocatable]
    require(
        linked_bytes == relocatable_bytes,
        "linked exact-entry instruction bytes differ from the input implementation object",
    )


def require_wx(binary: Path) -> None:
    output = run_tool("/usr/bin/readelf", "-Wl", os.fspath(binary))
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
    binary = arguments.binary.resolve(strict=True)
    implementation = arguments.implementation.resolve(strict=True)
    glue = arguments.glue.resolve(strict=True)
    contract_path = arguments.contract.resolve(strict=True)
    binary_bytes = read_regular(binary, MAX_BINARY_BYTES, "final executable")
    implementation_bytes = read_regular(
        implementation,
        MAX_OBJECT_BYTES,
        "implementation object",
    )
    glue_bytes = read_regular(glue, MAX_OBJECT_BYTES, "direct-glue object")
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
    require_glue_relocation(glue, entry)
    require_wrapper(binary, wrapper, entry)
    require_primary_direct_entry_call(binary, wrapper, entry)
    require_entry_bytes(binary, implementation, entry)
    require_wx(binary)
    print(
        "OBSERVATION"
        f"\t{OBSERVATION_SCHEMA}"
        "\tPASS"
        f"\tsource_commit={contract['source_commit']}"
        f"\tsource_tree={contract['source_tree']}"
        f"\tartifact_identity={contract['artifact_identity']}"
        f"\tcompile_identity={contract['compile_identity']}"
        f"\tbundle_identity={contract['bundle_identity']}"
        "\twrapper_call=R_AARCH64_CALL26-to-direct-bl"
        "\tprimary_aot_call=direct-bl-exact-entry"
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
