#!/usr/bin/env python3
"""Shared fail-closed parsing primitives for Search V8 bakeoff evidence."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path
from typing import Sequence

RECEIPT_SCHEMA = "fre-search-v8-bakeoff-build-receipt-v2"
RECEIPT_KEYS = [
    "schema",
    "subject_revision",
    "benchmark_source_sha256",
    "semantic_identity_bytes_hashed",
    "semantic_identity",
    "binding_identity",
    "compiler_receipt_identity",
    "source_identity",
    "artifact_identity",
    "compile_identity",
    "object_identity",
    "payload_sha256",
    "metadata_sha256",
    "literal_hex",
    "literal_bytes",
    "backend_version",
    "output_kind",
    "object_bytes",
    "payload_bytes",
    "metadata_bytes",
    "code_bytes",
    "rodata_offset",
    "rodata_bytes",
    "entry_symbol",
    "payload_symbol",
    "metadata_symbol",
    "object_path",
    "link_map_path",
    "target",
    "aot_authority",
    "qualification_state",
    "production_activation",
]
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SYMBOL = re.compile(r"^[a-z0-9_]{1,127}$")
UINT = re.compile(r"^(0|[1-9][0-9]*)$")
MAX_TEXT_BYTES = 4 * 1024 * 1024
MAX_OBJECT_BYTES = 5 * 1024 * 1024


class VerificationError(Exception):
    """One fail-closed evidence rejection."""


def fail(message: str) -> None:
    raise VerificationError(message)


def regular_file(path: Path, maximum: int) -> bytes:
    try:
        info = path.lstat()
    except OSError as error:
        fail(f"cannot stat {path}: {error}")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        fail(f"{path} is not one regular non-symlink file")
    if info.st_nlink != 1:
        fail(f"{path} must have exactly one hard link")
    if info.st_size <= 0 or info.st_size > maximum:
        fail(f"{path} size {info.st_size} is outside 1..{maximum}")
    try:
        return path.read_bytes()
    except OSError as error:
        fail(f"cannot read {path}: {error}")


def strict_text(path: Path, maximum: int = MAX_TEXT_BYTES) -> str:
    data = regular_file(path, maximum)
    if b"\x00" in data or b"\r" in data or not data.endswith(b"\n"):
        fail(f"{path} is not canonical newline-terminated text")
    try:
        return data.decode("ascii")
    except UnicodeDecodeError as error:
        fail(f"{path} is not ASCII: {error}")


def parse_tsv(path: Path, keys: Sequence[str]) -> dict[str, str]:
    lines = strict_text(path).splitlines()
    if len(lines) != len(keys):
        fail(f"{path} has {len(lines)} rows, expected {len(keys)}")
    output: dict[str, str] = {}
    for ordinal, (line, key) in enumerate(zip(lines, keys, strict=True), 1):
        fields = line.split("\t")
        if len(fields) != 2 or fields[0] != key or not fields[1]:
            fail(f"{path}:{ordinal} expected key {key!r}")
        output[key] = fields[1]
    return output


def canonical_uint(value: str, minimum: int, maximum: int, name: str) -> int:
    if not UINT.fullmatch(value) or len(value) > len(str(maximum)):
        fail(f"{name} is not a canonical bounded integer: {value!r}")
    number = int(value)
    if not minimum <= number <= maximum:
        fail(f"{name}={number} is outside {minimum}..{maximum}")
    return number


def parse_receipt(path: Path) -> dict[str, str]:
    receipt = parse_tsv(path, RECEIPT_KEYS)
    if receipt["schema"] != RECEIPT_SCHEMA:
        fail("unexpected build receipt schema")
    if not HEX40.fullmatch(receipt["subject_revision"]):
        fail("invalid subject revision")
    for field in [
        "benchmark_source_sha256",
        "semantic_identity",
        "binding_identity",
        "compiler_receipt_identity",
        "source_identity",
        "artifact_identity",
        "compile_identity",
        "object_identity",
        "payload_sha256",
        "metadata_sha256",
    ]:
        if not HEX64.fullmatch(receipt[field]) or receipt[field] == "0" * 64:
            fail(f"invalid {field}")
    if receipt["binding_identity"] == receipt["semantic_identity"]:
        fail("compiler object binding collapsed to the facade semantic identity")
    canonical_uint(
        receipt["semantic_identity_bytes_hashed"], 1, 1 << 20, "semantic bytes hashed"
    )
    if receipt["literal_hex"] != "30313233343536373839616263646566":
        fail("unexpected literal")
    expected_scalars = {
        "literal_bytes": "16",
        "backend_version": "8",
        "output_kind": "3",
        "metadata_bytes": "216",
        "target": "aarch64-apple-macos",
        "aot_authority": "benchmark-local-raw-abi-no-adoption",
        "qualification_state": "candidate",
        "production_activation": "absent",
    }
    for key, expected in expected_scalars.items():
        if receipt[key] != expected:
            fail(f"receipt {key}={receipt[key]!r}, expected {expected!r}")
    object_bytes = canonical_uint(
        receipt["object_bytes"], 1, MAX_OBJECT_BYTES, "object bytes"
    )
    payload_bytes = canonical_uint(
        receipt["payload_bytes"], 1, 4 * 1024 * 1024, "payload bytes"
    )
    code_bytes = canonical_uint(
        receipt["code_bytes"], 4, payload_bytes, "code bytes"
    )
    rodata_offset = canonical_uint(
        receipt["rodata_offset"], code_bytes, payload_bytes, "rodata offset"
    )
    rodata_bytes = canonical_uint(
        receipt["rodata_bytes"], 1, payload_bytes, "rodata bytes"
    )
    if code_bytes % 4 or rodata_offset % 16 or rodata_offset + rodata_bytes != payload_bytes:
        fail("receipt image layout is inconsistent")
    if object_bytes <= payload_bytes + 216:
        fail("object is too short for payload plus metadata")
    identity = receipt["compile_identity"]
    symbols = {
        "entry_symbol": f"fre_aot_search_entry_v1_{identity}",
        "payload_symbol": f"fre_aot_payload_v1_{identity}",
        "metadata_symbol": f"fre_aot_metadata_v1_{identity}",
    }
    for key, expected in symbols.items():
        if receipt[key] != expected or not SYMBOL.fullmatch(receipt[key]):
            fail(f"receipt {key} is not the identity-derived name")
    for key in ["object_path", "link_map_path"]:
        if not os.path.isabs(receipt[key]) or "\t" in receipt[key]:
            fail(f"receipt {key} is not one absolute path")
    return receipt


def sha256_file(path: Path, maximum: int) -> str:
    return hashlib.sha256(regular_file(path, maximum)).hexdigest()
