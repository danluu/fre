#!/usr/bin/env python3
"""Fail-closed static checker for one exact private SelectedEnd ABI2 link.

This consumes externally pinned artifacts and a canonical contract. It does
not execute generated code, authorize production use, or complete deployment
qualification.
"""

from __future__ import annotations

import sys

if sys.flags.isolated != 1 or not sys.dont_write_bytecode or sys.flags.optimize != 0:
    print("REFUSED: use python3 -I -B without optimization", file=sys.stderr)
    raise SystemExit(1)

import argparse
import fcntl
import hashlib
import os
import re
import selectors
import stat
import struct
import subprocess
import time
from pathlib import Path


SCHEMA = "fre-aot-selected-end-abi2-private-link-contract-v2"
OUTPUT_SCHEMA = "fre-aot-selected-end-abi2-private-static-check-v2"
MAX_BINARY_BYTES = 256 << 20
MAX_OBJECT_BYTES = 16 << 20
MAX_BINDING_BYTES = 256 << 10
MAX_RECEIPT_BYTES = 4 << 10
MAX_EXPECTATION_BYTES = 4 << 10
MAX_CONTRACT_BYTES = 64 << 10
MAX_TOOL_STDOUT_BYTES = 64 << 20
MAX_TOOL_STDERR_BYTES = 1 << 20
TOOL_TIMEOUT_SECONDS = 30.0
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

COMPILER_RECEIPT_BYTES = 672
COMPILER_RECEIPT_BODY_BYTES = 640
BUNDLE_RECEIPT_BYTES = 512
BUNDLE_RECEIPT_BODY_BYTES = 480
DEPLOYMENT_RECEIPT_BYTES = 672
DEPLOYMENT_RECEIPT_BODY_BYTES = 640
EXPECTATION_BYTES = 608
EXPECTATION_BODY_BYTES = 576

COMPILER_RECEIPT_DOMAIN = (
    b"FRE-AOT-LINUX-SEARCH-SELECTED-END-COMPILE-RECEIPT\0\x02"
)
BUNDLE_RECEIPT_DOMAIN = (
    b"FRE-AOT-LINUX-SEARCH-SELECTED-END-QUALIFICATION-RECEIPT\0\x02"
)
DEPLOYMENT_RECEIPT_DOMAIN = (
    b"FRE-AOT-LINUX-SEARCH-SELECTED-END-QUALIFICATION-DEPLOYMENT-RECEIPT\0\x02"
)
EXPECTATION_DOMAIN = (
    b"FRE-AOT-STATIC-SEARCH-SELECTED-END-EXPECTATION-IDENTITY\0\x02"
)
GLUE_OBJECT_DOMAIN = (
    b"FRE-AOT-LINUX-SEARCH-SELECTED-END-DIRECT-GLUE-OBJECT\0\x02"
)
BINDING_DOMAIN = (
    b"FRE-AOT-LINUX-SEARCH-SELECTED-END-QUALIFICATION-RUST-BINDING\0\x02"
)
LITERAL_DOMAIN = b"FRE-AOT-LINUX-SEARCH-SELECTED-END-LITERAL\0\x02"
GLUE_CODE_DOMAIN = b"FRE-AOT-LINUX-SEARCH-SELECTED-END-DIRECT-GLUE-CODE\0\x02"

CONTRACT_KEYS = (
    "schema",
    "evidence_class",
    "production_authority",
    "runtime_authority",
    "observation_complete",
    "target",
    "backend",
    "abi",
    "argument_count",
    "return_register",
    "result_slot_bytes",
    "required_vector_bytes",
    "literal_hex",
    "manifest_identity",
    "source_identity",
    "semantic_binding_identity",
    "literal_identity",
    "kir_identity",
    "artifact_identity",
    "object_binding_identity",
    "compile_identity",
    "implementation_object_identity",
    "compiler_receipt_identity",
    "expectation_identity",
    "full_payload_sha256",
    "glue_source_identity",
    "direct_header_identity",
    "glue_code_identity",
    "glue_object_identity",
    "bundle_identity",
    "binding_identity",
    "deployment_receipt_identity",
    "final_binary_sha256",
    "wrapper_symbol",
    "primary_callsite_symbol",
    "entry_symbol",
    "payload_symbol",
    "metadata_symbol",
    "required_relocation",
    "required_final_call",
    "reject_plt",
    "reject_blr",
    "reject_x4_argument",
)


class Refusal(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def read_regular(path: Path, maximum: int, label: str) -> bytes:
    try:
        before = os.stat(path, follow_symlinks=False)
    except OSError as error:
        raise Refusal(f"cannot inspect {label}: {error}") from error
    require(stat.S_ISREG(before.st_mode), f"{label} is not a regular file")
    require(0 < before.st_size <= maximum, f"{label} violates its byte bound")
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        )
    except OSError as error:
        raise Refusal(f"cannot open {label} without following a symlink: {error}") from error
    try:
        opened = os.fstat(descriptor)
        require(
            (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
                opened.st_ctime_ns,
            )
            == (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            ),
            f"{label} changed before open",
        )
        chunks: list[bytes] = []
        total = 0
        while True:
            remaining = maximum + 1 - total
            require(remaining > 0, f"{label} exceeds its byte bound")
            chunk = os.read(descriptor, min(1 << 20, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
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
    except OSError as error:
        raise Refusal(f"cannot read stable {label}: {error}") from error
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


def digest(domain: bytes, body: bytes) -> bytes:
    hasher = hashlib.sha256()
    hasher.update(domain)
    hasher.update(body)
    return hasher.digest()


def length_prefixed_digest(domain: bytes, body: bytes) -> bytes:
    hasher = hashlib.sha256()
    hasher.update(domain)
    hasher.update(struct.pack("<Q", len(body)))
    hasher.update(body)
    return hasher.digest()


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
        and fields["production_authority"] == "absent"
        and fields["runtime_authority"] == "absent"
        and fields["observation_complete"] == "false",
        "contract attempts to grant or complete authority",
    )
    require(
        fields["target"] == "aarch64-unknown-linux-little-endian-lp64"
        and fields["backend"] == "tag21-sve2-fixed16"
        and fields["abi"] == "selected-end-register-v2"
        and fields["argument_count"] == "4"
        and fields["return_register"] == "x0"
        and fields["result_slot_bytes"] == "0"
        and fields["required_vector_bytes"] == "16",
        "target/backend/ABI contract changed",
    )
    require(
        len(fields["literal_hex"]) == 32
        and re.fullmatch(r"[0-9a-f]{32}", fields["literal_hex"]) is not None,
        "literal is not exact canonical 16-byte hex",
    )
    for key in (
        "manifest_identity",
        "source_identity",
        "semantic_binding_identity",
        "literal_identity",
        "kir_identity",
        "artifact_identity",
        "object_binding_identity",
        "compile_identity",
        "implementation_object_identity",
        "compiler_receipt_identity",
        "expectation_identity",
        "full_payload_sha256",
        "glue_source_identity",
        "direct_header_identity",
        "glue_code_identity",
        "glue_object_identity",
        "bundle_identity",
        "binding_identity",
        "deployment_receipt_identity",
        "final_binary_sha256",
    ):
        require(
            HEX64.fullmatch(fields[key]) is not None and fields[key] != "0" * 64,
            f"{key} is not canonical nonzero SHA-256-width hex",
        )
    compile_identity = fields["compile_identity"]
    exact_symbols = {
        "wrapper_symbol": (
            "fre_aot_search_selected_end_qualification_direct_v2_"
            + compile_identity
        ),
        "primary_callsite_symbol": (
            "fre_aot_search_selected_end_qualification_primary_callsite_v2_"
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
    for key, expected in exact_symbols.items():
        require(
            SYMBOL.fullmatch(fields[key]) is not None and fields[key] == expected,
            f"{key} differs from the exact identity-derived namespace",
        )
    require(
        fields["required_relocation"] == "R_AARCH64_CALL26"
        and fields["required_final_call"] == "direct-bl-exact-entry"
        and fields["reject_plt"] == "true"
        and fields["reject_blr"] == "true"
        and fields["reject_x4_argument"] == "true",
        "direct-call requirements changed",
    )
    return fields


def canonical_receipt(
    raw: bytes,
    expected_bytes: int,
    magic: bytes,
    body_bytes: int,
    domain: bytes,
    label: str,
) -> bytes:
    require(len(raw) == expected_bytes, f"{label} extent changed")
    require(raw[:8] == magic, f"{label} magic changed")
    require(
        raw[8:12] == struct.pack("<HH", 2, 2)
        and struct.unpack_from("<I", raw, 12)[0] == expected_bytes,
        f"{label} schema/version/encoded extent changed",
    )
    identity = raw[body_bytes : body_bytes + 32]
    require(identity != bytes(32), f"{label} identity is zero")
    require(digest(domain, raw[:body_bytes]) == identity, f"{label} is not authentic")
    return identity


def identity_at(raw: bytes, base: int, index: int) -> bytes:
    start = base + index * 32
    return raw[start : start + 32]


def nonzero_identity_tuple(
    raw: bytes,
    base: int,
    count: int,
    label: str,
) -> tuple[bytes, ...]:
    identities = tuple(identity_at(raw, base, index) for index in range(count))
    require(
        all(len(identity) == 32 and identity != bytes(32) for identity in identities),
        f"{label} contains an omitted identity",
    )
    return identities


def validate_receipts(
    compiler: bytes,
    bundle: bytes,
    deployment: bytes,
    expectation: bytes,
    binding: bytes,
    contract: dict[str, str],
) -> bytes:
    compiler_identity = canonical_receipt(
        compiler,
        COMPILER_RECEIPT_BYTES,
        b"FRESEC\0\x02",
        COMPILER_RECEIPT_BODY_BYTES,
        COMPILER_RECEIPT_DOMAIN,
        "compiler receipt",
    )
    bundle_identity = canonical_receipt(
        bundle,
        BUNDLE_RECEIPT_BYTES,
        b"FRESDG\0\x02",
        BUNDLE_RECEIPT_BODY_BYTES,
        BUNDLE_RECEIPT_DOMAIN,
        "bundle receipt",
    )
    deployment_identity = canonical_receipt(
        deployment,
        DEPLOYMENT_RECEIPT_BYTES,
        b"FRESDP\0\x02",
        DEPLOYMENT_RECEIPT_BODY_BYTES,
        DEPLOYMENT_RECEIPT_DOMAIN,
        "deployment receipt",
    )
    expectation_identity = canonical_receipt(
        expectation,
        EXPECTATION_BYTES,
        b"FRESEX\0\x02",
        EXPECTATION_BODY_BYTES,
        EXPECTATION_DOMAIN,
        "expectation",
    )
    binding_identity = length_prefixed_digest(BINDING_DOMAIN, binding)
    compiler_tuple = nonzero_identity_tuple(
        compiler,
        64,
        9,
        "compiler receipt",
    )
    bundle_tuple = nonzero_identity_tuple(bundle, 64, 12, "bundle receipt")
    deployment_tuple = nonzero_identity_tuple(
        deployment,
        64,
        18,
        "deployment receipt",
    )
    expectation_tuple = nonzero_identity_tuple(
        expectation,
        64,
        9,
        "expectation",
    )

    source_bytes = struct.unpack_from("<Q", compiler, 56)[0]
    require(
        struct.unpack_from("<HH", compiler, 16) == (21, 2)
        and compiler[20:24] == bytes([2, 1, 1, 4])
        and struct.unpack_from("<HH", compiler, 24) == (16, 0)
        and compiler[28:34] == bytes([0, 1, 1, 64, 1, 2])
        and compiler[34:36] == bytes(2)
        and struct.unpack_from("<I", compiler, 36)[0] == 16
        and struct.unpack_from("<Q", compiler, 40)[0] == 7
        and struct.unpack_from("<Q", compiler, 48)[0] == 0
        and 0 < source_bytes <= 1 << 20,
        "compiler receipt ABI/header contract changed",
    )
    compiler_metadata = compiler[352:576]
    (
        object_bytes,
        payload_bytes,
        object_work,
        _emission_work,
        _scratch_bytes,
    ) = struct.unpack_from("<QQQQQ", compiler, 576)
    (
        code_bytes,
        data_bytes,
        _relocations,
        _labels,
        _vector_instructions,
        reserved_stats,
    ) = struct.unpack_from("<IIIIII", compiler, 616)
    require(
        0 < object_bytes <= 5 << 20
        and 0 < payload_bytes <= 4 << 20
        and object_work > 0
        and code_bytes > 0
        and data_bytes == 16
        and reserved_stats == 0
        and struct.unpack_from("<I", compiler_metadata, 40)[0] == payload_bytes
        and struct.unpack_from("<I", compiler_metadata, 48)[0] == code_bytes
        and struct.unpack_from("<I", compiler_metadata, 56)[0] == data_bytes
        and compiler_metadata[64:96] == compiler_tuple[4]
        and compiler_metadata[96:128] == compiler_tuple[5]
        and compiler_metadata[128:160] == compiler_tuple[6]
        and compiler_metadata[192:224] == compiler_tuple[7],
        "compiler receipt stats/metadata contract changed",
    )
    require(
        struct.unpack_from("<HHI", bundle, 16) == (16, 1, 283)
        and bundle[24:28] == bytes([4, 0, 0, 0])
        and struct.unpack_from("<HHHH", bundle, 28) == (4, 4, 21, 2)
        and bundle[36:40] == bytes([0, 2, 0, 0])
        and struct.unpack_from("<I", bundle, 40)[0] == 0x7F
        and 0 < struct.unpack_from("<Q", bundle, 44)[0] <= 64 << 10
        and 0 < struct.unpack_from("<I", bundle, 52)[0] <= 256 << 10
        and 0 < struct.unpack_from("<I", bundle, 56)[0] <= 64 << 10
        and bundle[60:64] == bytes(4)
        and bundle[448:464]
        == bytes.fromhex(
            "fd7bbfa900000094fd7bc1a8c0035fd6"
        )
        and bundle[464:480] == bytes(16),
        "bundle receipt direct-glue/header contract changed",
    )
    require(
        struct.unpack_from("<HHHHH", expectation, 16)
        == (224, 2, 21, 2, 2)
        and expectation[26:38]
        == bytes([2, 0, 0, 1, 1, 64, 1, 2, 64, 0x12, 1, 1])
        and struct.unpack_from("<H", expectation, 38)[0] == 16
        and struct.unpack_from("<Q", expectation, 40)[0] == 7
        and struct.unpack_from("<I", expectation, 48)[0] == 16
        and expectation[52:56] == bytes([4, 0, 0, 0])
        and struct.unpack_from("<Q", expectation, 56)[0] == 0,
        "expectation ABI/header contract changed",
    )

    require(
        compiler_identity.hex() == contract["compiler_receipt_identity"],
        "compiler receipt pin mismatch",
    )
    require(bundle_identity.hex() == contract["bundle_identity"], "bundle pin mismatch")
    require(
        deployment_identity.hex() == contract["deployment_receipt_identity"],
        "deployment receipt pin mismatch",
    )
    require(
        expectation_identity.hex() == contract["expectation_identity"],
        "expectation pin mismatch",
    )
    require(binding_identity.hex() == contract["binding_identity"], "binding pin mismatch")

    compiler_ids = {
        "manifest_identity": compiler_tuple[0],
        "semantic_binding_identity": compiler_tuple[1],
        "source_identity": compiler_tuple[2],
        "literal_identity": compiler_tuple[3],
        "kir_identity": compiler_tuple[4],
        "artifact_identity": compiler_tuple[5],
        "object_binding_identity": compiler_tuple[6],
        "compile_identity": compiler_tuple[7],
        "implementation_object_identity": compiler_tuple[8],
    }
    for key, value in compiler_ids.items():
        require(value.hex() == contract[key], f"compiler receipt {key} mismatch")
    literal = bytes.fromhex(contract["literal_hex"])
    require(
        length_prefixed_digest(LITERAL_DOMAIN, literal) == compiler_tuple[3],
        "compiler literal identity is not authentic for the exact literal",
    )
    require(
        compiler_metadata[160:192].hex() == contract["full_payload_sha256"],
        "compiler receipt full payload digest mismatch",
    )
    require(
        compiler_metadata[192:224].hex() == contract["compile_identity"],
        "compiler receipt metadata compile identity mismatch",
    )

    require(
        expectation_tuple
        == (
            compiler_tuple[0],
            compiler_tuple[1],
            compiler_tuple[3],
            compiler_tuple[4],
            compiler_tuple[5],
            compiler_tuple[6],
            compiler_tuple[7],
            compiler_tuple[8],
            compiler_identity,
        ),
        "expectation/compiler complete identity tuple mismatch",
    )
    require(
        expectation[352:576] == compiler_metadata,
        "expectation metadata differs from compiler receipt",
    )

    bundle_ids = {
        "manifest_identity": bundle_tuple[0],
        "semantic_binding_identity": bundle_tuple[1],
        "artifact_identity": bundle_tuple[2],
        "object_binding_identity": bundle_tuple[3],
        "compile_identity": bundle_tuple[4],
        "implementation_object_identity": bundle_tuple[5],
        "compiler_receipt_identity": bundle_tuple[6],
        "expectation_identity": bundle_tuple[7],
        "glue_source_identity": bundle_tuple[8],
        "direct_header_identity": bundle_tuple[9],
        "glue_code_identity": bundle_tuple[10],
        "glue_object_identity": bundle_tuple[11],
    }
    for key, value in bundle_ids.items():
        require(value.hex() == contract[key], f"bundle receipt {key} mismatch")
    require(
        bundle_tuple[:8]
        == (
            compiler_tuple[0],
            compiler_tuple[1],
            compiler_tuple[5],
            compiler_tuple[6],
            compiler_tuple[7],
            compiler_tuple[8],
            compiler_identity,
            expectation_identity,
        ),
        "bundle/compiler/expectation complete identity tuple mismatch",
    )
    require(
        digest(GLUE_CODE_DOMAIN, bundle[448:464]) == bundle_tuple[10],
        "bundle glue-code identity is not authentic",
    )

    require(
        struct.unpack_from("<I", deployment, 16)[0] == len(binding)
        and deployment[20] == 4
        and deployment[21] == 0
        and struct.unpack_from("<H", deployment, 22)[0] == 0
        and struct.unpack_from("<H", deployment, 24)[0] == 21
        and struct.unpack_from("<H", deployment, 26)[0] == 2
        and struct.unpack_from("<H", deployment, 28)[0] == 16
        and deployment[30] == 0
        and deployment[31] == 2
        and struct.unpack_from("<I", deployment, 32)[0] == 0x7F
        and struct.unpack_from("<I", deployment, 36)[0] == 16
        and struct.unpack_from("<I", deployment, 40)[0]
        == struct.unpack_from("<I", compiler_metadata, 40)[0]
        and struct.unpack_from("<H", deployment, 44)[0] == 18
        and deployment[46:64] == bytes(18),
        "deployment ABI/header contract changed",
    )
    deployment_ids = {
        "manifest_identity": deployment_tuple[0],
        "source_identity": deployment_tuple[1],
        "semantic_binding_identity": deployment_tuple[2],
        "literal_identity": deployment_tuple[3],
        "kir_identity": deployment_tuple[4],
        "artifact_identity": deployment_tuple[5],
        "object_binding_identity": deployment_tuple[6],
        "compile_identity": deployment_tuple[7],
        "implementation_object_identity": deployment_tuple[8],
        "compiler_receipt_identity": deployment_tuple[9],
        "expectation_identity": deployment_tuple[10],
        "full_payload_sha256": deployment_tuple[11],
        "glue_source_identity": deployment_tuple[12],
        "direct_header_identity": deployment_tuple[13],
        "glue_code_identity": deployment_tuple[14],
        "glue_object_identity": deployment_tuple[15],
        "bundle_identity": deployment_tuple[16],
        "binding_identity": deployment_tuple[17],
    }
    for key, value in deployment_ids.items():
        require(value.hex() == contract[key], f"deployment receipt {key} mismatch")
    require(
        deployment_tuple[:12]
        == (
            compiler_tuple[0],
            compiler_tuple[2],
            compiler_tuple[1],
            compiler_tuple[3],
            compiler_tuple[4],
            compiler_tuple[5],
            compiler_tuple[6],
            compiler_tuple[7],
            compiler_tuple[8],
            compiler_identity,
            expectation_identity,
            compiler_metadata[160:192],
        ),
        "deployment/compiler/expectation/payload complete identity tuple mismatch",
    )
    require(
        deployment_tuple[12:17]
        == (
            bundle_tuple[8],
            bundle_tuple[9],
            bundle_tuple[10],
            bundle_tuple[11],
            bundle_identity,
        ),
        "deployment/direct-glue/bundle identity tuple mismatch",
    )
    return compiler_metadata


def validate_binding(binding: bytes, contract: dict[str, str]) -> None:
    require(binding.endswith(b"\n") and b"\r" not in binding and b"\0" not in binding, "binding is not canonical text")
    try:
        source = binding.decode("ascii")
    except UnicodeError as error:
        raise Refusal("binding is not ASCII") from error
    entry = contract["entry_symbol"]
    wrapper = contract["wrapper_symbol"]
    callsite = contract["primary_callsite_symbol"]
    compile_identity = contract["compile_identity"]
    require(f'#[link_name = "{entry}"]' in source, "binding lacks exact entry link_name")
    require(f'#[link_name = "{wrapper}"]' in source, "binding lacks exact wrapper link_name")
    require(
        f'#[unsafe(export_name = "{callsite}")]' in source
        and f'core::arch::global_asm!(".hidden {callsite}");' in source,
        "binding lacks its exact hidden primary proof callsite",
    )
    for local in (
        f"exact_linked_aot_selected_end_entry_v2_{compile_identity}",
        f"exact_linked_aot_selected_end_qualification_wrapper_v2_{compile_identity}",
    ):
        declaration = (
            f"fn {local}(haystack: *const u8, haystack_len: usize, "
            "window_start: usize, window_end: usize) -> usize;"
        )
        require(declaration in source, f"binding declaration changed for {local}")
    entry_local = f"exact_linked_aot_selected_end_entry_v2_{compile_identity}"
    callsite_local = (
        f"exact_linked_aot_selected_end_primary_callsite_v2_{compile_identity}"
    )
    key_start = source.find(
        "static EXACT_PLAN_BINDING_KEY: "
        "fre_aot_static_runtime::StaticSearchSelectedEndBindingKeyV2"
    )
    nominal_start = source.find(
        "pub(super) struct ExactLinkedAotSelectedEndPlanSessionV2"
    )
    bind_start = source.find(
        "pub(super) fn bind_exact_linked_aot_selected_end_plan_v2"
    )
    primary_start = source.find(
        "pub(super) fn search_exact_linked_aot_selected_end_v2"
    )
    diagnostic_start = source.find(
        "pub(super) fn search_exact_linked_aot_selected_end_qualification_wrapper_v2"
    )
    require(
        0 <= key_start < nominal_start < bind_start < primary_start < diagnostic_start,
        "binding key/nominal session/plan/primary/diagnostic functions are missing or reordered",
    )
    key_source = source[key_start:nominal_start]
    nominal_source = source[nominal_start:bind_start]
    bind_source = source[bind_start:primary_start]
    primary_source = source[primary_start:diagnostic_start]
    require(
        (
            "StaticSearchSelectedEndBindingKeyV2::"
            "qualification_private(COMPILE_IDENTITY)"
        )
        in key_source,
        "binding key is not tied to the exact compile identity",
    )
    require(
        (
            "pub(super) struct "
            "ExactLinkedAotSelectedEndPlanSessionV2<'session, 'owner, 'plan>"
        )
        in nominal_source
        and (
            "inner: fre_aot_static_runtime::"
            "StaticSearchSelectedEndPlanSessionV2<'session, 'owner, 'plan>"
        )
        in nominal_source
        and "pub(super) inner:" not in nominal_source
        and "pub(crate) inner:" not in nominal_source
        and "pub inner:" not in nominal_source,
        "binding does not keep the artifact session inside a private nominal wrapper",
    )
    require(
        "StaticSearchSelectedEndThreadSessionV2<'owner>" in bind_source
        and (
            "ExactLinkedAotSelectedEndPlanSessionV2<'session, 'owner, 'plan>"
        )
        in bind_source
        and (
            "inner: session.bind_literal_plan("
            "plan, &EXACT_LITERAL, &EXACT_PLAN_BINDING_KEY)?"
        )
        in bind_source,
        "binding omits one-time exact-literal/artifact plan binding",
    )
    require(
        f"{entry_local}(" in primary_source
        and f"{callsite_local}(" not in primary_source,
        "hot primary source does not bypass the retained proof wrapper",
    )
    literal = ", ".join(str(byte) for byte in bytes.fromhex(contract["literal_hex"]))
    require(
        f"pub(super) const EXACT_LITERAL: [u8; 16] = [{literal}];" in source,
        "binding exact literal differs from contract",
    )
    require(
        source.count(
            "let prepared = plan_session.inner.prepare_plan_bound(preflight)?;"
        )
        == 2
        and source.count(
            "plan_session: &ExactLinkedAotSelectedEndPlanSessionV2<'_, '_, '_>"
        )
        == 2
        and source.count("&EXACT_PLAN_BINDING_KEY") == 1
        and "session.prepare(preflight, &EXACT_LITERAL)?" not in source
        and "plan_session.prepare(preflight)?" not in source
        and (
            "plan_session.prepare(preflight, &EXACT_PLAN_BINDING_KEY)?;"
            not in source
        ),
        "binding omits nominal-session plan preflight or retains a per-call artifact/literal check",
    )
    for forbidden in ("transmute", "extern \"C\" fn(", "*mut", "result_slot", " x4", "blr"):
        require(forbidden not in source, f"binding contains forbidden form {forbidden!r}")


def region(raw: bytes, offset: int, size: int, label: str) -> bytes:
    require(offset >= 0 and size >= 0, f"{label} has a negative extent")
    end = offset + size
    require(end >= offset and end <= len(raw), f"{label} lies outside its ELF")
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
        f"{label} is not canonical ELF64LE AArch64",
    )
    require(
        section_entry_bytes == ELF64_SECTION.size
        and 0 < section_count < SHN_LORESERVE
        and section_names < section_count,
        f"{label} has an unsupported section table",
    )
    table = region(
        raw,
        section_offset,
        section_entry_bytes * section_count,
        f"{label} section table",
    )
    return [
        ELF64_SECTION.unpack_from(table, index * ELF64_SECTION.size)
        for index in range(section_count)
    ]


def elf_symbol(raw: bytes, symbol: str, label: str) -> dict[str, int | bytes]:
    sections = elf_sections(raw, label)
    symtabs = [section for section in sections if section[1] == SHT_SYMTAB]
    require(len(symtabs) == 1, f"{label} does not have one SHT_SYMTAB")
    symtab = symtabs[0]
    require(
        symtab[9] == ELF64_SYMBOL.size
        and symtab[5] % ELF64_SYMBOL.size == 0
        and symtab[6] < len(sections)
        and sections[symtab[6]][1] == SHT_STRTAB,
        f"{label} has an unsupported symbol table",
    )
    strings_section = sections[symtab[6]]
    strings = region(raw, strings_section[4], strings_section[5], f"{label} strings")
    symbols = region(raw, symtab[4], symtab[5], f"{label} symbols")
    matches: list[dict[str, int | bytes]] = []
    for offset in range(0, len(symbols), ELF64_SYMBOL.size):
        name_offset, info, visibility, section_index, value, size = ELF64_SYMBOL.unpack_from(
            symbols, offset
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
            f"{label} symbol {symbol} is undefined",
        )
        section = sections[section_index]
        require(section[1] == SHT_PROGBITS, f"{label} symbol {symbol} is not PROGBITS")
        require(value >= section[3], f"{label} symbol {symbol} precedes its section")
        relative = value - section[3]
        require(size > 0 and relative + size <= section[5], f"{label} symbol {symbol} extent is invalid")
        matches.append(
            {
                "value": value,
                "size": size,
                "info": info,
                "visibility": visibility & 0x3,
                "bytes": region(
                    raw,
                    section[4] + relative,
                    size,
                    f"{label} symbol {symbol}",
                ),
            }
        )
    require(len(matches) == 1, f"{label} does not define exactly one {symbol}")
    return matches[0]


def run_tool(tool: str, *arguments: str, pass_fds: tuple[int, ...] = ()) -> str:
    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    stdout = bytearray()
    stderr = bytearray()
    try:
        process = subprocess.Popen(
            [tool, *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=pass_fds,
            env={
                "LC_ALL": "C",
                "LANG": "C",
                "TZ": "UTC",
                "PATH": "/usr/bin:/bin",
            },
        )
        require(
            process.stdout is not None and process.stderr is not None,
            f"{Path(tool).name} pipes are unavailable",
        )
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, ("stdout", stdout))
        selector.register(process.stderr, selectors.EVENT_READ, ("stderr", stderr))
        deadline = time.monotonic() + TOOL_TIMEOUT_SECONDS
        limits = {
            "stdout": MAX_TOOL_STDOUT_BYTES,
            "stderr": MAX_TOOL_STDERR_BYTES,
        }
        while selector.get_map():
            remaining = deadline - time.monotonic()
            require(remaining > 0, f"{Path(tool).name} timed out")
            for key, _ in selector.select(min(remaining, 0.25)):
                chunk = os.read(key.fd, 64 << 10)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                stream, buffer = key.data
                require(
                    len(chunk) <= limits[stream] - len(buffer),
                    f"{Path(tool).name} {stream} output too large",
                )
                buffer.extend(chunk)
        remaining = deadline - time.monotonic()
        if process.poll() is None:
            require(remaining > 0, f"{Path(tool).name} timed out")
            process.wait(timeout=remaining)
        require(
            process.returncode == 0,
            f"{Path(tool).name} exited with status {process.returncode}",
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise Refusal(f"{Path(tool).name} failed: {error}") from error
    finally:
        if selector is not None:
            selector.close()
        if process is not None:
            if process.poll() is None:
                process.kill()
                try:
                    process.wait(timeout=1.0)
                except subprocess.TimeoutExpired as error:
                    raise Refusal(
                        f"{Path(tool).name} did not terminate after kill"
                    ) from error
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
    require(not stderr, f"{Path(tool).name} wrote stderr")
    try:
        return stdout.decode("ascii")
    except UnicodeError as error:
        raise Refusal(f"{Path(tool).name} output is not ASCII") from error


def require_aarch64_elf(snapshot: SealedSnapshot, label: str, relocatable: bool) -> None:
    output = run_tool(
        "/usr/bin/readelf",
        "-Wh",
        os.fspath(snapshot.path),
        pass_fds=(snapshot.descriptor,),
    )
    require(
        "Class:                             ELF64" in output
        and "Data:                              2's complement, little endian" in output
        and "Machine:                           AArch64" in output,
        f"{label} is not ELF64LE AArch64",
    )
    if relocatable:
        require("Type:                              REL (Relocatable file)" in output, f"{label} is not relocatable")


def symbol_rows(snapshot: SealedSnapshot) -> list[list[str]]:
    output = run_tool(
        "/usr/bin/readelf",
        "-Ws",
        os.fspath(snapshot.path),
        pass_fds=(snapshot.descriptor,),
    )
    return [line.split() for line in output.splitlines() if re.match(r"^\s*[0-9]+:", line)]


def require_symbol(
    rows: list[list[str]],
    symbol: str,
    *,
    defined: bool,
    hidden: bool,
    kind: str,
    binding: str,
) -> None:
    matches = [row for row in rows if row[-1] == symbol]
    require(len(matches) == 1, f"{symbol} does not have one symbol row")
    row = matches[0]
    require(len(row) >= 8 and row[3] == kind, f"{symbol} kind changed")
    require(row[4] == binding, f"{symbol} binding changed")
    require((row[6] != "UND") == defined, f"{symbol} definition state changed")
    require((row[5] == "HIDDEN") == hidden, f"{symbol} visibility changed")


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
        require(match is not None, f"unparsed glue relocation: {line!r}")
        relocations.append((match.group(1), match.group(2)))
    require(relocations == [("R_AARCH64_CALL26", entry)], "glue relocation set changed")


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


def require_direct_calls(
    binary: SealedSnapshot,
    wrapper: str,
    callsite: str,
    entry: str,
) -> None:
    wrapper_output = run_tool(
        "/usr/bin/objdump",
        "-d",
        f"--disassemble={wrapper}",
        os.fspath(binary.path),
        pass_fds=(binary.descriptor,),
    )
    wrapper_decoded = instructions(wrapper_output)
    require(
        [mnemonic for _, _, mnemonic, _ in wrapper_decoded]
        == ["stp", "bl", "ldp", "ret"],
        "linked wrapper is not exact stp/bl/ldp/ret",
    )
    require(
        f"<{entry}>" in wrapper_decoded[1][3]
        and "@plt" not in wrapper_decoded[1][3].lower()
        and ".plt" not in wrapper_decoded[1][3].lower(),
        "wrapper does not directly bl the exact entry",
    )
    wrapper_text = "\n".join(
        f"{mnemonic} {operands}"
        for _, _, mnemonic, operands in wrapper_decoded
    )
    require(
        re.search(r"\b(?:blr|x4)\b", wrapper_text) is None,
        "wrapper contains blr or x4",
    )

    callsite_output = run_tool(
        "/usr/bin/objdump",
        "-d",
        f"--disassemble={callsite}",
        os.fspath(binary.path),
        pass_fds=(binary.descriptor,),
    )
    callsite_decoded = instructions(callsite_output)
    callsite_all_calls = [
        (address, operands)
        for address, _, mnemonic, operands in callsite_decoded
        if mnemonic == "bl"
    ]
    callsite_calls = {
        address
        for address, operands in callsite_all_calls
        if f"<{entry}>" in operands
        and "@plt" not in operands.lower()
        and ".plt" not in operands.lower()
    }
    callsite_text = "\n".join(
        f"{mnemonic} {operands}"
        for _, _, mnemonic, operands in callsite_decoded
    )
    require(
        len(callsite_all_calls) == 1
        and len(callsite_calls) == 1
        and re.search(r"\b(?:b|br|blr|x4)\b", callsite_text) is None,
        "generated primary proof callsite is not exactly one direct bl without other branches/x4",
    )

    all_output = run_tool(
        "/usr/bin/objdump",
        "-d",
        os.fspath(binary.path),
        pass_fds=(binary.descriptor,),
    )
    require(
        f"<{entry}@plt>" not in all_output
        and f"<{entry}.plt>" not in all_output
        and re.search(rf"\bblr\b[^\n]*<{re.escape(entry)}>", all_output) is None,
        "entry is reachable through PLT or annotated blr",
    )


def require_exact_wrapper_bytes(
    binary: bytes,
    glue: bytes,
    wrapper: str,
    entry: str,
) -> None:
    linked_wrapper = elf_symbol(binary, wrapper, "final executable")
    object_wrapper = elf_symbol(glue, wrapper, "glue object")
    linked_entry = elf_symbol(binary, entry, "final executable")
    linked_bytes = linked_wrapper["bytes"]
    object_bytes = object_wrapper["bytes"]
    require(
        isinstance(linked_bytes, bytes)
        and isinstance(object_bytes, bytes)
        and len(linked_bytes) == len(object_bytes) == 16,
        "wrapper extent changed",
    )
    require(
        linked_bytes[:4] == object_bytes[:4]
        and linked_bytes[8:] == object_bytes[8:],
        "linker changed a non-relocated wrapper instruction",
    )
    object_call = int.from_bytes(object_bytes[4:8], "little")
    linked_call = int.from_bytes(linked_bytes[4:8], "little")
    require(
        object_call == 0x94000000 and linked_call & 0xFC000000 == 0x94000000,
        "wrapper call is not AArch64 bl",
    )
    immediate = linked_call & 0x03FFFFFF
    if immediate & (1 << 25):
        immediate -= 1 << 26
    target = int(linked_wrapper["value"]) + 4 + (immediate << 2)
    require(target == linked_entry["value"], "wrapper bl target differs from exact entry")


def require_implementation_bytes(
    binary: bytes,
    implementation: bytes,
    contract: dict[str, str],
) -> tuple[bytes, bytes]:
    for key, description in (
        ("entry_symbol", "entry"),
        ("payload_symbol", "complete payload"),
        ("metadata_symbol", "metadata"),
    ):
        symbol = contract[key]
        linked = elf_symbol(binary, symbol, "final executable")
        object_symbol = elf_symbol(implementation, symbol, "implementation object")
        require(
            linked["bytes"] == object_symbol["bytes"]
            and linked["size"] == object_symbol["size"],
            f"linked {description} differs from implementation object",
        )
    payload = elf_symbol(
        implementation,
        contract["payload_symbol"],
        "implementation object",
    )["bytes"]
    metadata = elf_symbol(
        implementation,
        contract["metadata_symbol"],
        "implementation object",
    )["bytes"]
    require(isinstance(payload, bytes) and isinstance(metadata, bytes), "symbol bytes missing")
    return payload, metadata


def require_metadata(
    payload: bytes,
    metadata: bytes,
    receipt_metadata: bytes,
    contract: dict[str, str],
) -> None:
    require(len(metadata) == 224 and metadata == receipt_metadata, "metadata extent/receipt binding changed")
    require(
        metadata[:8] == b"FRESE64\x02"
        and struct.unpack_from("<H", metadata, 8)[0] == 2
        and struct.unpack_from("<H", metadata, 10)[0] == 224
        and struct.unpack_from("<H", metadata, 12)[0] == 21
        and metadata[14:22] == bytes([2, 2, 1, 1, 64, 1, 2, 64])
        and struct.unpack_from("<H", metadata, 22)[0] == 2
        and metadata[24:26] == bytes([1, 1])
        and struct.unpack_from("<H", metadata, 26)[0] == 16
        and struct.unpack_from("<I", metadata, 28)[0] == 0
        and struct.unpack_from("<Q", metadata, 32)[0] == 7,
        "metadata target/backend/ABI header changed",
    )
    payload_bytes, entry_offset, code_bytes, rodata_offset, rodata_bytes, literal_bytes = (
        struct.unpack_from("<IIIIII", metadata, 40)
    )
    require(
        payload_bytes == len(payload)
        and entry_offset == 0
        and 0 < code_bytes <= rodata_offset
        and rodata_offset + rodata_bytes == len(payload)
        and rodata_bytes == literal_bytes == 16,
        "metadata payload layout changed",
    )
    require(payload[rodata_offset:] == bytes.fromhex(contract["literal_hex"]), "payload literal mismatch")
    require(metadata[64:96].hex() == contract["kir_identity"], "metadata KIR/source mismatch")
    require(metadata[96:128].hex() == contract["artifact_identity"], "metadata artifact mismatch")
    require(
        metadata[128:160].hex() == contract["object_binding_identity"],
        "metadata object binding mismatch",
    )
    require(metadata[160:192].hex() == contract["full_payload_sha256"], "metadata payload digest pin mismatch")
    require(metadata[192:224].hex() == contract["compile_identity"], "metadata compile pin mismatch")
    require(hashlib.sha256(payload).digest() == metadata[160:192], "complete payload digest is invalid")

    metadata_body = bytearray(metadata)
    metadata_body[192:224] = bytes(32)
    hasher = hashlib.sha256()
    hasher.update(b"FRE-AOT-ELF-SEARCH-SELECTED-END-COMPILE\0\x02")
    hasher.update(struct.pack("<HHH", 2, 2, 64))
    for prefix, info in (
        (b"fre_aot_search_selected_end_entry_v2_", 0x12),
        (b"fre_aot_search_selected_end_payload_v2_", 0x11),
        (b"fre_aot_search_selected_end_metadata_v2_", 0x11),
    ):
        hasher.update(struct.pack("<H", len(prefix)))
        hasher.update(prefix)
        hasher.update(bytes([info, 2]))
    hasher.update(bytes([2, 1, 1, 0]))
    hasher.update(struct.pack("<HH", 1, 183))
    hasher.update(metadata_body)
    require(hasher.hexdigest() == contract["compile_identity"], "metadata compile identity is not authentic")


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
    stacks = [
        line.split()
        for line in output.splitlines()
        if line.lstrip().startswith("GNU_STACK")
    ]
    require(
        len(stacks) == 1 and "E" not in "".join(stacks[0][6:-1]),
        "final image has an executable or ambiguous GNU_STACK",
    )


def verify(arguments: argparse.Namespace) -> None:
    expected_contract_sha256 = arguments.expected_contract_sha256
    require(
        HEX64.fullmatch(expected_contract_sha256) is not None
        and expected_contract_sha256 != "0" * 64,
        "expected contract digest is not canonical nonzero lowercase SHA-256 hex",
    )
    paths = {
        name: getattr(arguments, name)
        for name in (
            "binary",
            "implementation",
            "glue",
            "binding",
            "compiler_receipt",
            "bundle_receipt",
            "deployment_receipt",
            "expectation",
            "contract",
        )
    }
    contract_raw = read_regular(paths["contract"], MAX_CONTRACT_BYTES, "contract")
    require(
        hashlib.sha256(contract_raw).hexdigest() == expected_contract_sha256,
        "contract does not match its independently supplied digest",
    )
    contract = parse_contract(contract_raw)
    binary = read_regular(paths["binary"], MAX_BINARY_BYTES, "final executable")
    implementation = read_regular(paths["implementation"], MAX_OBJECT_BYTES, "implementation object")
    glue = read_regular(paths["glue"], MAX_OBJECT_BYTES, "glue object")
    binding = read_regular(paths["binding"], MAX_BINDING_BYTES, "generated binding")
    compiler_receipt = read_regular(paths["compiler_receipt"], MAX_RECEIPT_BYTES, "compiler receipt")
    bundle_receipt = read_regular(paths["bundle_receipt"], MAX_RECEIPT_BYTES, "bundle receipt")
    deployment_receipt = read_regular(paths["deployment_receipt"], MAX_RECEIPT_BYTES, "deployment receipt")
    expectation = read_regular(paths["expectation"], MAX_EXPECTATION_BYTES, "expectation")

    require(hashlib.sha256(binary).hexdigest() == contract["final_binary_sha256"], "final binary pin mismatch")
    require(
        hashlib.sha256(implementation).hexdigest()
        == contract["implementation_object_identity"],
        "implementation object pin mismatch",
    )
    require(
        digest(GLUE_OBJECT_DOMAIN, glue).hex() == contract["glue_object_identity"],
        "glue object pin mismatch",
    )
    require(
        struct.unpack_from("<Q", compiler_receipt, 576)[0] == len(implementation)
        and struct.unpack_from("<Q", bundle_receipt, 44)[0] == len(glue)
        and struct.unpack_from("<I", deployment_receipt, 16)[0] == len(binding),
        "persisted artifact extent differs from its receipt",
    )
    receipt_metadata = validate_receipts(
        compiler_receipt,
        bundle_receipt,
        deployment_receipt,
        expectation,
        binding,
        contract,
    )
    validate_binding(binding, contract)

    snapshots: list[SealedSnapshot] = []
    try:
        snapshots = [
            SealedSnapshot(binary, "final-executable"),
            SealedSnapshot(implementation, "implementation-object"),
            SealedSnapshot(glue, "glue-object"),
        ]
        final_snapshot, implementation_snapshot, glue_snapshot = snapshots
        require_aarch64_elf(final_snapshot, "final executable", False)
        require_aarch64_elf(implementation_snapshot, "implementation object", True)
        require_aarch64_elf(glue_snapshot, "glue object", True)

        wrapper = contract["wrapper_symbol"]
        primary_callsite = contract["primary_callsite_symbol"]
        entry = contract["entry_symbol"]
        payload_symbol = contract["payload_symbol"]
        metadata_symbol = contract["metadata_symbol"]
        glue_rows = symbol_rows(glue_snapshot)
        implementation_rows = symbol_rows(implementation_snapshot)
        final_rows = symbol_rows(final_snapshot)
        require_symbol(
            glue_rows,
            wrapper,
            defined=True,
            hidden=True,
            kind="FUNC",
            binding="GLOBAL",
        )
        require_symbol(
            glue_rows,
            entry,
            defined=False,
            hidden=True,
            kind="NOTYPE",
            binding="GLOBAL",
        )
        for symbol, kind in (
            (entry, "FUNC"),
            (payload_symbol, "OBJECT"),
            (metadata_symbol, "OBJECT"),
        ):
            require_symbol(
                implementation_rows,
                symbol,
                defined=True,
                hidden=True,
                kind=kind,
                binding="GLOBAL",
            )
            require_symbol(
                final_rows,
                symbol,
                defined=True,
                hidden=True,
                kind=kind,
                binding="GLOBAL",
            )
        require_symbol(
            final_rows,
            wrapper,
            defined=True,
            hidden=True,
            kind="FUNC",
            binding="GLOBAL",
        )
        require_symbol(
            final_rows,
            primary_callsite,
            defined=True,
            hidden=True,
            kind="FUNC",
            binding="GLOBAL",
        )
        require_glue_relocation(glue_snapshot, entry)
        require_direct_calls(final_snapshot, wrapper, primary_callsite, entry)
        require_exact_wrapper_bytes(binary, glue, wrapper, entry)
        payload, metadata = require_implementation_bytes(binary, implementation, contract)
        require(
            struct.unpack_from("<Q", compiler_receipt, 584)[0] == len(payload)
            and struct.unpack_from("<I", deployment_receipt, 40)[0] == len(payload),
            "complete payload extent differs from its receipts",
        )
        require_metadata(payload, metadata, receipt_metadata, contract)
        require_wx(final_snapshot)
    finally:
        for snapshot in reversed(snapshots):
            snapshot.close()

    print(
        "STATIC_CHECK"
        f"\t{OUTPUT_SCHEMA}"
        "\tPASS"
        f"\tfinal_binary_sha256={contract['final_binary_sha256']}"
        f"\tcontract_sha256={expected_contract_sha256}"
        f"\tcompile_identity={contract['compile_identity']}"
        f"\tbinding_identity={contract['binding_identity']}"
        f"\tdeployment_receipt_identity={contract['deployment_receipt_identity']}"
        "\tprimary_proof_callsite=hidden-direct-bl-exact-entry"
        "\tprimary_hot_route_source_checked=direct-exact-entry"
        "\tprimary_hot_route_final_observed=false"
        "\tconsumer_specific_hot_callsite_proof=required"
        "\twrapper_call=R_AARCH64_CALL26-to-direct-bl"
        "\tentry_bytes_equal=true"
        "\tfull_payload_bytes_equal=true"
        "\tmetadata_bytes_equal=true"
        "\texact_entry_plt_absent=true"
        "\tannotated_entry_blr_absent=true"
        "\tproof_callsites_reject_blr=true"
        "\tproof_callsites_reject_x4_argument=true"
        "\tresult_slot_bytes=0"
        "\tproduction_authority=absent"
        "\truntime_authority=absent"
        "\tobservation_complete=false"
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--binary", required=True, type=Path)
    result.add_argument("--implementation", required=True, type=Path)
    result.add_argument("--glue", required=True, type=Path)
    result.add_argument("--binding", required=True, type=Path)
    result.add_argument("--compiler-receipt", required=True, type=Path)
    result.add_argument("--bundle-receipt", required=True, type=Path)
    result.add_argument("--deployment-receipt", required=True, type=Path)
    result.add_argument("--expectation", required=True, type=Path)
    result.add_argument("--contract", required=True, type=Path)
    result.add_argument("--expected-contract-sha256", required=True)
    return result


def main() -> int:
    verify(parser().parse_args())
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Refusal as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        raise SystemExit(1) from error
