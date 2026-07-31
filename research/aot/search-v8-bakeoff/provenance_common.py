#!/usr/bin/env python3
"""Closed sidecar formats for Search V8 source/dependency provenance."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import tomllib
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Sequence

SOURCE_SNAPSHOT_SCHEMA = "fre-search-v8-source-snapshot-v2"
DEPENDENCY_MANIFEST_SCHEMA = "fre-search-v8-dependency-manifest-v2"
REGISTRY_ARCHIVES_SCHEMA = "fre-search-v8-registry-archives-v2"
PROVENANCE_SCHEMA = "fre-search-v8-source-provenance-v2"
CARGO_LOCK_POLICY = "cargo-lock-v4-bare-unique-name-edges-v1"
BUNDLE_POLICY = (
    "openat-nofollow-fstat-fsync-private-parent-absolute-rewalk-v3"
)

SOURCE_SNAPSHOT_NAME = "source-snapshot.tsv"
DEPENDENCY_MANIFEST_NAME = "dependency-manifest.tsv"
REGISTRY_ARCHIVES_NAME = "registry-archives.tsv"
CARGO_LOCK_NAME = "Cargo.lock"
PROVENANCE_NAME = "source-provenance.tsv"
BUNDLE_ORDER = (
    SOURCE_SNAPSHOT_NAME,
    CARGO_LOCK_NAME,
    DEPENDENCY_MANIFEST_NAME,
    REGISTRY_ARCHIVES_NAME,
    PROVENANCE_NAME,
)
BUNDLE_NAMES = set(BUNDLE_ORDER)

SOURCE_HEADER = ["ordinal", "mode", "git_object", "bytes", "sha256", "path"]
DEPENDENCY_HEADER = [
    "ordinal",
    "package_key",
    "name",
    "version",
    "source_kind",
    "source_locator",
    "manifest_role",
    "package_tree",
    "lock_checksum",
    "target_kinds",
    "features",
    "dependencies",
]
ARCHIVE_HEADER = [
    "ordinal",
    "package_key",
    "name",
    "version",
    "source_locator",
    "lock_checksum",
    "archive_bytes",
    "archive_sha256",
    "archive_role",
]
PROVENANCE_KEYS = [
    "schema",
    "git_object_format",
    "subject_commit",
    "subject_tree",
    "subject_dirty_state",
    "external_git_derivation_boundary",
    "source_materialization",
    "snapshot_git_tool_sha256",
    "source_snapshot_role",
    "source_snapshot_schema",
    "source_snapshot_file_sha256",
    "source_snapshot_identity_sha256",
    "source_snapshot_entries",
    "source_snapshot_content_bytes",
    "cargo_lock_source_role",
    "cargo_lock_bundle_role",
    "cargo_lock_sha256",
    "cargo_lock_schema",
    "cargo_lock_parser_policy",
    "cargo_lock_package_count",
    "dependency_manifest_role",
    "dependency_manifest_schema",
    "dependency_manifest_sha256",
    "dependency_package_count",
    "path_dependency_package_count",
    "registry_dependency_package_count",
    "root_package_key",
    "root_package_name",
    "root_package_version",
    "root_package_source",
    "root_package_manifest_role",
    "registry_archives_role",
    "registry_archives_schema",
    "registry_archives_sha256",
    "dependency_archive_count",
    "dependency_archive_content_bytes",
    "registry_archive_input_policy",
    "dependency_closure_sha256",
    "cargo_target",
    "cargo_profile",
    "cargo_dependency_kinds",
    "bundle_file_policy",
    "logical_path_policy",
    "source_provenance_sha256",
]

SOURCE_DOMAIN = b"FRE-SEARCH-V8-SOURCE-SNAPSHOT\0\x02"
DEPENDENCY_DOMAIN = b"FRE-SEARCH-V8-DEPENDENCY-CLOSURE\0\x02"
PROVENANCE_DOMAIN = b"FRE-SEARCH-V8-SOURCE-PROVENANCE\0\x02"
PACKAGE_DOMAIN = b"FRE-SEARCH-V8-PACKAGE-KEY\0\x02"

SEARCH_LOCK_PATH = "research/aot/search-v8-bakeoff/Cargo.lock"
SEARCH_ROOT_NAME = "fre-search-v8-bakeoff"
SEARCH_ROOT_VERSION = "0.1.0"
SEARCH_ROOT_DIRECTORY = "research/aot/search-v8-bakeoff"
PATH_SOURCE_PREFIX = "path:repo:"
SEARCH_ROOT_SOURCE = f"{PATH_SOURCE_PREFIX}{SEARCH_ROOT_DIRECTORY}"
SEARCH_ROOT_MANIFEST_ROLE = f"repo:{SEARCH_ROOT_DIRECTORY}/Cargo.toml"
CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
REGISTRY_MANIFEST_PREFIX = "cargo-registry-manifest:"
REGISTRY_ARCHIVE_PREFIX = "cargo-registry-archive:"

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
UINT = re.compile(r"^(0|[1-9][0-9]*)$")
ATOM = re.compile(r"^[A-Za-z0-9._+%:/=@-]{1,1024}$")
ENCODED_PATH = re.compile(r"^[A-Za-z0-9._/%-]{1,4096}$")
SAFE_PATH_BYTES = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._/-"
)
MAX_TEXT = 64 * 1024 * 1024
MAX_SOURCE_ROWS = 100_000
MAX_PACKAGES = 4096
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
READ_CHUNK = 1024 * 1024


class ProvenanceError(Exception):
    """One fail-closed provenance rejection."""


@dataclass(frozen=True)
class LockPackage:
    name: str
    version: str
    source_kind: str
    source_locator: str
    lock_checksum: str
    dependency_names: tuple[str, ...]

    def identity(self) -> tuple[str, str, str, str, str]:
        return (
            self.name,
            self.version,
            self.source_kind,
            self.source_locator,
            self.lock_checksum,
        )


def fail(message: str) -> None:
    raise ProvenanceError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_hex(value: str, width: int, name: str) -> str:
    expression = HEX40 if width == 40 else HEX64
    if not expression.fullmatch(value) or value == "0" * width:
        fail(f"{name} is not one nonzero lowercase hexadecimal identity")
    return value


def require_atom(value: str, name: str) -> str:
    if not ATOM.fullmatch(value):
        fail(f"{name} is not one canonical atom: {value!r}")
    return value


def uint(value: str, minimum: int, maximum: int, name: str) -> int:
    if not UINT.fullmatch(value) or len(value) > len(str(maximum)):
        fail(f"{name} is not a canonical integer")
    number = int(value)
    if not minimum <= number <= maximum:
        fail(f"{name}={number} is outside {minimum}..{maximum}")
    return number


def _required_flag(name: str) -> int:
    value = getattr(os, name, None)
    if value is None:
        fail(f"platform lacks required descriptor flag {name}")
    return int(value)


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | _required_flag("O_DIRECTORY")
        | _required_flag("O_NOFOLLOW")
        | _required_flag("O_CLOEXEC")
    )


def _regular_flags() -> int:
    return os.O_RDONLY | _required_flag("O_NOFOLLOW") | _required_flag("O_CLOEXEC")


def _stable_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _check_directory(
    info: os.stat_result, label: str, expected_mode: int | None = None
) -> None:
    if not stat.S_ISDIR(info.st_mode):
        fail(f"{label} is not one physical directory")
    if expected_mode is not None and stat.S_IMODE(info.st_mode) != expected_mode:
        fail(f"{label} does not have mode {expected_mode:04o}")


def _check_regular(
    info: os.stat_result,
    label: str,
    maximum: int,
    *,
    minimum: int = 1,
    single_link: bool = True,
    expected_mode: int | None = None,
) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or (single_link and info.st_nlink != 1)
        or not minimum <= info.st_size <= maximum
        or (
            expected_mode is not None
            and stat.S_IMODE(info.st_mode) != expected_mode
        )
    ):
        fail(f"{label} is not one bounded canonical regular file")


def open_physical_directory(path: Path, label: str) -> int:
    """Open every absolute path component without following a symlink."""
    if not path.is_absolute():
        fail(f"{label} path must be absolute")
    parts = path.parts
    if (
        not parts
        or parts[0] != os.sep
        or any(part in ("", ".", "..") for part in parts[1:])
    ):
        fail(f"{label} is not one canonical absolute path")
    descriptor = -1
    try:
        descriptor = os.open(os.sep, _directory_flags())
        for part in parts[1:]:
            next_descriptor = os.open(part, _directory_flags(), dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        _check_directory(os.fstat(descriptor), label)
        return descriptor
    except ProvenanceError:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        fail(f"cannot open physical {label}: {error}")
    raise AssertionError("unreachable")


def _one_name(name: str, label: str) -> str:
    if not name or name in (".", "..") or "/" in name or "\x00" in name:
        fail(f"{label} is not one physical basename")
    return name


def _open_regular_at(directory: int, name: str, label: str) -> int:
    _one_name(name, label)
    try:
        return os.open(name, _regular_flags(), dir_fd=directory)
    except OSError as error:
        fail(f"cannot open {label}: {error}")
    raise AssertionError("unreachable")


def _read_open_regular(
    descriptor: int,
    label: str,
    maximum: int,
    *,
    minimum: int = 1,
    single_link: bool = True,
    expected_mode: int | None = None,
) -> bytes:
    try:
        before = os.fstat(descriptor)
        _check_regular(
            before,
            label,
            maximum,
            minimum=minimum,
            single_link=single_link,
            expected_mode=expected_mode,
        )
        output = bytearray()
        while True:
            chunk = os.read(descriptor, min(READ_CHUNK, maximum - len(output) + 1))
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > maximum:
                fail(f"{label} grew beyond its byte bound while being read")
        after = os.fstat(descriptor)
        _check_regular(
            after,
            label,
            maximum,
            minimum=minimum,
            single_link=single_link,
            expected_mode=expected_mode,
        )
    except OSError as error:
        fail(f"cannot read {label}: {error}")
    if _stable_identity(before) != _stable_identity(after) or len(output) != after.st_size:
        fail(f"{label} changed while being read")
    return bytes(output)


def read_regular_at_bound(
    directory: int,
    name: str,
    label: str,
    maximum: int = MAX_TEXT,
    *,
    minimum: int = 1,
    single_link: bool = True,
    expected_mode: int | None = None,
) -> tuple[bytes, tuple[int, int]]:
    descriptor = _open_regular_at(directory, name, label)
    try:
        data = _read_open_regular(
            descriptor,
            label,
            maximum,
            minimum=minimum,
            single_link=single_link,
            expected_mode=expected_mode,
        )
        info = os.fstat(descriptor)
        return data, (info.st_dev, info.st_ino)
    finally:
        os.close(descriptor)


def read_regular_at(
    directory: int,
    name: str,
    label: str,
    maximum: int = MAX_TEXT,
    *,
    minimum: int = 1,
    single_link: bool = True,
    expected_mode: int | None = None,
) -> bytes:
    data, _ = read_regular_at_bound(
        directory,
        name,
        label,
        maximum,
        minimum=minimum,
        single_link=single_link,
        expected_mode=expected_mode,
    )
    return data


def read_regular_path_bound(
    path: Path,
    maximum: int = MAX_TEXT,
    *,
    label: str | None = None,
    minimum: int = 1,
    single_link: bool = True,
) -> tuple[bytes, tuple[int, int]]:
    name = _one_name(path.name, label or str(path))
    parent = open_physical_directory(path.parent, f"{label or path} parent")
    try:
        return read_regular_at_bound(
            parent,
            name,
            label or str(path),
            maximum,
            minimum=minimum,
            single_link=single_link,
        )
    finally:
        os.close(parent)


def read_regular_path(
    path: Path,
    maximum: int = MAX_TEXT,
    *,
    label: str | None = None,
    minimum: int = 1,
    single_link: bool = True,
) -> bytes:
    data, _ = read_regular_path_bound(
        path,
        maximum,
        label=label,
        minimum=minimum,
        single_link=single_link,
    )
    return data


def hash_regular_path(
    path: Path,
    maximum: int = MAX_FILE_BYTES,
    *,
    label: str | None = None,
    single_link: bool = True,
) -> tuple[int, str, tuple[int, int]]:
    name = _one_name(path.name, label or str(path))
    parent = open_physical_directory(path.parent, f"{label or path} parent")
    try:
        descriptor = _open_regular_at(parent, name, label or str(path))
    finally:
        os.close(parent)
    try:
        before = os.fstat(descriptor)
        _check_regular(
            before,
            label or str(path),
            maximum,
            single_link=single_link,
        )
        digest = hashlib.sha256()
        length = 0
        while True:
            chunk = os.read(descriptor, min(READ_CHUNK, maximum - length + 1))
            if not chunk:
                break
            length += len(chunk)
            if length > maximum:
                fail(f"{label or path} grew beyond its byte bound while being hashed")
            digest.update(chunk)
        after = os.fstat(descriptor)
        _check_regular(
            after,
            label or str(path),
            maximum,
            single_link=single_link,
        )
    except OSError as error:
        fail(f"cannot hash {label or path}: {error}")
    finally:
        os.close(descriptor)
    if _stable_identity(before) != _stable_identity(after) or length != after.st_size:
        fail(f"{label or path} changed while being hashed")
    return length, digest.hexdigest(), (after.st_dev, after.st_ino)


def _bundle_file_maximum(name: str) -> int:
    return 64 * 1024 if name == PROVENANCE_NAME else MAX_TEXT


def read_bundle_fd_bound(
    descriptor: int, label: str, *, expected_mode: int
) -> tuple[dict[str, bytes], dict[str, tuple[int, int]]]:
    before = os.fstat(descriptor)
    _check_directory(before, label, expected_mode)
    try:
        names = set(os.listdir(descriptor))
    except OSError as error:
        fail(f"cannot list {label}: {error}")
    if names != BUNDLE_NAMES:
        fail(f"bundle inventory mismatch: {sorted(names)}")
    bound = {
        name: read_regular_at_bound(
            descriptor,
            name,
            f"{label}/{name}",
            _bundle_file_maximum(name),
            expected_mode=0o400,
        )
        for name in BUNDLE_ORDER
    }
    output = {name: value[0] for name, value in bound.items()}
    identities = {name: value[1] for name, value in bound.items()}
    if len(set(identities.values())) != len(identities):
        fail("bundle roles alias one physical inode")
    after = os.fstat(descriptor)
    _check_directory(after, label, expected_mode)
    if _stable_identity(before) != _stable_identity(after):
        fail(f"{label} changed while being read")
    return output, identities


def read_bundle_fd(
    descriptor: int, label: str, *, expected_mode: int
) -> dict[str, bytes]:
    output, _ = read_bundle_fd_bound(
        descriptor, label, expected_mode=expected_mode
    )
    return output


def read_bundle_bound(
    path: Path,
) -> tuple[dict[str, bytes], dict[str, tuple[int, int]]]:
    descriptor = open_physical_directory(path, "provenance bundle")
    try:
        return read_bundle_fd_bound(
            descriptor, "provenance bundle", expected_mode=0o500
        )
    finally:
        os.close(descriptor)


def read_bundle(path: Path) -> dict[str, bytes]:
    output, _ = read_bundle_bound(path)
    return output


def _write_all(descriptor: int, data: bytes, label: str) -> None:
    offset = 0
    try:
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                fail(f"short write while creating {label}")
            offset += written
    except OSError as error:
        fail(f"cannot write {label}: {error}")


def write_new_at(directory: int, name: str, data: bytes) -> None:
    _one_name(name, "bundle role")
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | _required_flag("O_NOFOLLOW")
        | _required_flag("O_CLOEXEC")
    )
    descriptor = -1
    try:
        descriptor = os.open(name, flags, 0o400, dir_fd=directory)
        os.fchmod(descriptor, 0o400)
        _write_all(descriptor, data, name)
        os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        observed = _read_open_regular(
            descriptor,
            name,
            max(1, len(data)),
            single_link=True,
            expected_mode=0o400,
        )
        if observed != data:
            fail(f"bundle role {name!r} differs after its durable write")
    except OSError as error:
        fail(f"cannot create bundle role {name!r}: {error}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def create_bundle(path: Path, files: Mapping[str, bytes]) -> None:
    if set(files) != BUNDLE_NAMES:
        fail("generator bundle roles drifted from the exact inventory")
    if not path.is_absolute():
        fail("output must be one new absolute directory")
    name = _one_name(path.name, "output directory")
    parent = open_physical_directory(path.parent, "output parent")
    directory = -1
    created_identity: tuple[int, int] | None = None
    try:
        parent_info = os.fstat(parent)
        _check_directory(parent_info, "output parent")
        parent_identity = (parent_info.st_dev, parent_info.st_ino)
        if (
            parent_info.st_uid != os.geteuid()
            or stat.S_IMODE(parent_info.st_mode) & 0o022
        ):
            fail(
                "output parent must be effective-UID-owned and not "
                "group/other writable"
            )
        os.mkdir(name, 0o700, dir_fd=parent)
        entry = os.stat(name, dir_fd=parent, follow_symlinks=False)
        _check_directory(entry, "created provenance bundle entry")
        entry_identity = (entry.st_dev, entry.st_ino)
        directory = os.open(name, _directory_flags(), dir_fd=parent)
        os.fchmod(directory, 0o700)
        created = os.fstat(directory)
        _check_directory(created, "new provenance bundle", 0o700)
        created_identity = (created.st_dev, created.st_ino)
        if created_identity != entry_identity:
            fail("created output directory changed before descriptor binding")
        for role in BUNDLE_ORDER:
            write_new_at(directory, role, files[role])
        os.fsync(directory)
        if read_bundle_fd(directory, "new provenance bundle", expected_mode=0o700) != dict(
            files
        ):
            fail("new provenance bundle differs before sealing")
        os.fchmod(directory, 0o500)
        os.fsync(directory)
        if read_bundle_fd(directory, "new provenance bundle", expected_mode=0o500) != dict(
            files
        ):
            fail("new provenance bundle differs after sealing")
        reopened = os.open(name, _directory_flags(), dir_fd=parent)
        try:
            reopened_info = os.fstat(reopened)
            _check_directory(reopened_info, "reopened provenance bundle", 0o500)
            if (reopened_info.st_dev, reopened_info.st_ino) != created_identity:
                fail("output directory entry changed before publication")
        finally:
            os.close(reopened)
        os.fsync(parent)
        parent_after = os.fstat(parent)
        _check_directory(parent_after, "output parent")
        if (
            parent_after.st_uid != os.geteuid()
            or stat.S_IMODE(parent_after.st_mode) & 0o022
        ):
            fail("output parent policy changed before publication")

        published_parent = -1
        published_directory = -1
        try:
            published_parent = open_physical_directory(
                path.parent, "published output parent"
            )
            published_parent_info = os.fstat(published_parent)
            _check_directory(published_parent_info, "published output parent")
            if (
                (published_parent_info.st_dev, published_parent_info.st_ino)
                != parent_identity
                or published_parent_info.st_uid != os.geteuid()
                or stat.S_IMODE(published_parent_info.st_mode) & 0o022
            ):
                fail(
                    "absolute output parent changed before publication"
                )
            published_directory = os.open(
                name, _directory_flags(), dir_fd=published_parent
            )
            published_info = os.fstat(published_directory)
            _check_directory(
                published_info, "published provenance bundle", 0o500
            )
            if (
                (published_info.st_dev, published_info.st_ino)
                != created_identity
            ):
                fail("absolute output bundle changed before publication")
            if read_bundle_fd(
                published_directory,
                "published provenance bundle",
                expected_mode=0o500,
            ) != dict(files):
                fail("absolute output bundle bytes changed before publication")
        finally:
            if published_directory >= 0:
                os.close(published_directory)
            if published_parent >= 0:
                os.close(published_parent)
    except OSError as error:
        fail(f"cannot create provenance output directory: {error}")
    finally:
        if directory >= 0:
            os.close(directory)
        os.close(parent)


def parse_table(
    data: bytes, label: str, header: Sequence[str], maximum_rows: int
) -> tuple[bytes, list[dict[str, str]]]:
    if (
        not 0 < len(data) <= MAX_TEXT
        or b"\x00" in data
        or b"\r" in data
        or not data.endswith(b"\n")
    ):
        fail(f"{label} is not canonical bounded newline-terminated text")
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        fail(f"{label} is not ASCII: {error}")
    if not lines or lines[0].split("\t") != list(header):
        fail(f"{label} has an unexpected header")
    if not 0 < len(lines) - 1 <= maximum_rows:
        fail(f"{label} row count is outside the closed bound")
    rows: list[dict[str, str]] = []
    for ordinal, line in enumerate(lines[1:], 2):
        fields = line.split("\t")
        if len(fields) != len(header) or any(not field for field in fields):
            fail(f"{label}:{ordinal} has a noncanonical row")
        rows.append(dict(zip(header, fields, strict=True)))
    return data, rows


def valid_encoded_path(value: str, name: str) -> str:
    if not ENCODED_PATH.fullmatch(value):
        fail(f"{name} is not one canonical repository-relative path")
    decoded = bytearray()
    index = 0
    while index < len(value):
        if value[index] == "%":
            digits = value[index + 1 : index + 3]
            if len(digits) != 2 or not re.fullmatch(r"[0-9A-F]{2}", digits):
                fail(f"{name} contains a noncanonical percent escape")
            decoded.append(int(digits, 16))
            index += 3
        else:
            byte = ord(value[index])
            if byte not in SAFE_PATH_BYTES:
                fail(f"{name} contains an unescaped path byte")
            decoded.append(byte)
            index += 1
    raw = bytes(decoded)
    if (
        not raw
        or b"\x00" in raw
        or raw.startswith(b"/")
        or raw.endswith(b"/")
        or b"\\" in raw
        or any(part in (b"", b".", b"..") for part in raw.split(b"/"))
    ):
        fail(f"{name} is not one canonical repository-relative path")
    canonical = "".join(
        chr(byte) if byte in SAFE_PATH_BYTES else f"%{byte:02X}" for byte in raw
    )
    if canonical != value:
        fail(f"{name} has a noncanonical encoding")
    return value


def _decoded_path(value: str) -> bytes:
    """Decode a path already accepted by valid_encoded_path."""
    output = bytearray()
    index = 0
    while index < len(value):
        if value[index] == "%":
            output.append(int(value[index + 1 : index + 3], 16))
            index += 3
        else:
            output.append(ord(value[index]))
            index += 1
    return bytes(output)


def parse_source(
    data: bytes, label: str = SOURCE_SNAPSHOT_NAME
) -> tuple[bytes, list[dict[str, str]], int]:
    data, rows = parse_table(data, label, SOURCE_HEADER, MAX_SOURCE_ROWS)
    previous = b""
    folded: set[bytes] = set()
    total = 0
    for ordinal, row in enumerate(rows, 1):
        uint(row["ordinal"], ordinal, ordinal, "source ordinal")
        if row["mode"] not in ("100644", "100755"):
            fail("source snapshot contains a symlink/submodule/special mode")
        require_hex(row["git_object"], 40, "source Git object")
        size = uint(row["bytes"], 0, MAX_FILE_BYTES, "source file bytes")
        require_hex(row["sha256"], 64, "source file SHA-256")
        logical = valid_encoded_path(row["path"], "source path")
        raw = _decoded_path(logical)
        if raw <= previous or raw.lower() in folded:
            fail("source paths are not strictly sorted or case-disjoint")
        previous = raw
        folded.add(raw.lower())
        total += size
        if total > MAX_TOTAL_BYTES:
            fail("source snapshot exceeds its aggregate byte bound")
    return data, rows, total


def list_field(value: str, name: str) -> list[str]:
    if value == "none":
        return []
    fields = value.split(",")
    if fields != sorted(set(fields)):
        fail(f"{name} is not sorted and unique")
    for field in fields:
        require_atom(field, name)
        if any(separator in field for separator in ",;|"):
            fail(f"{name} contains a reserved separator")
    return fields


def domain_preimage(domain: bytes, fields: Iterable[tuple[str, bytes]]) -> bytes:
    output = bytearray(domain)
    for role, data in fields:
        role_bytes = role.encode("ascii")
        output.extend(len(role_bytes).to_bytes(8, "little"))
        output.extend(role_bytes)
        output.extend(len(data).to_bytes(8, "little"))
        output.extend(data)
    return bytes(output)


def domain_hash(domain: bytes, fields: Iterable[tuple[str, bytes]]) -> str:
    return sha256(domain_preimage(domain, fields))


def package_key(name: str, version: str, source: str) -> str:
    return domain_hash(
        PACKAGE_DOMAIN,
        [
            ("name", require_atom(name, "package name").encode("ascii")),
            ("version", require_atom(version, "package version").encode("ascii")),
            ("source", require_atom(source, "package source").encode("ascii")),
        ],
    )


def search_root_key() -> str:
    return package_key(SEARCH_ROOT_NAME, SEARCH_ROOT_VERSION, SEARCH_ROOT_SOURCE)


def registry_manifest_role(key: str) -> str:
    return f"{REGISTRY_MANIFEST_PREFIX}{require_hex(key, 64, 'package key')}/Cargo.toml"


def registry_archive_role(key: str) -> str:
    return f"{REGISTRY_ARCHIVE_PREFIX}{require_hex(key, 64, 'package key')}.crate"


def _path_manifest_role(locator: str) -> str:
    if not locator.startswith(PATH_SOURCE_PREFIX):
        fail("path package has a non-repository locator")
    directory = valid_encoded_path(
        locator.removeprefix(PATH_SOURCE_PREFIX), "path package locator"
    )
    return f"repo:{directory}/Cargo.toml"


def dependency_targets(value: str) -> tuple[str, ...]:
    if value == "none":
        return ()
    edges = value.split(";")
    if edges != sorted(set(edges)):
        fail("dependency edges are not sorted and unique")
    targets: list[str] = []
    for edge in edges:
        fields = edge.split("|")
        if len(fields) != 4 or fields[1] not in ("normal", "build"):
            fail("dependency edge is not alias|normal-or-build|target|package")
        require_atom(fields[0], "dependency alias")
        if fields[2] != "all":
            if not fields[2].startswith("cfg-sha256:"):
                fail("dependency target is not all or cfg-sha256")
            require_hex(fields[2].removeprefix("cfg-sha256:"), 64, "cfg hash")
        targets.append(require_hex(fields[3], 64, "dependency package key"))
    return tuple(targets)


def parse_dependencies(
    data: bytes, label: str = DEPENDENCY_MANIFEST_NAME
) -> tuple[bytes, list[dict[str, str]], dict[str, tuple[str, ...]], int, int]:
    data, rows = parse_table(data, label, DEPENDENCY_HEADER, MAX_PACKAGES)
    keys: set[str] = set()
    roles: set[str] = set()
    path_locators: set[str] = set()
    graph: dict[str, tuple[str, ...]] = {}
    previous = ""
    path_count = registry_count = 0
    for ordinal, row in enumerate(rows, 1):
        uint(row["ordinal"], ordinal, ordinal, "package ordinal")
        key = require_hex(row["package_key"], 64, "package key")
        if key <= previous or key in keys:
            fail("package keys are not strictly sorted and unique")
        previous = key
        keys.add(key)
        if package_key(row["name"], row["version"], row["source_locator"]) != key:
            fail("package key does not bind name/version/source")
        list_field(row["target_kinds"], "target kinds")
        list_field(row["features"], "features")
        graph[key] = dependency_targets(row["dependencies"])
        role = row["manifest_role"]
        if role in roles:
            fail("dependency manifest roles are not unique")
        roles.add(role)
        if row["source_kind"] == "path":
            path_count += 1
            expected_role = _path_manifest_role(row["source_locator"])
            if role != expected_role:
                fail("path manifest role is not derived from its repository locator")
            if row["source_locator"] in path_locators:
                fail("path package locators are not unique")
            path_locators.add(row["source_locator"])
            require_hex(row["package_tree"], 40, "path package tree")
            if row["lock_checksum"] != "none":
                fail("path package unexpectedly has a registry checksum")
        elif row["source_kind"] == "registry":
            registry_count += 1
            if row["source_locator"] != CRATES_IO_SOURCE:
                fail("registry package has a noncanonical source locator")
            if role != registry_manifest_role(key):
                fail("registry manifest role is not derived from its package key")
            if row["package_tree"] != "none":
                fail("registry package unexpectedly has a Git tree")
            require_hex(row["lock_checksum"], 64, "registry checksum")
        else:
            fail("package source kind is neither path nor registry")
    if any(target not in keys for targets in graph.values() for target in targets):
        fail("dependency edge escapes the closed package manifest")
    return data, rows, graph, path_count, registry_count


def require_connected(graph: Mapping[str, tuple[str, ...]], root: str) -> None:
    require_hex(root, 64, "root package key")
    if root not in graph:
        fail("root package is absent from dependency manifest")
    reached: set[str] = set()
    queue: deque[str] = deque([root])
    while queue:
        key = queue.popleft()
        if key not in reached:
            reached.add(key)
            queue.extend(graph[key])
    if reached != set(graph):
        fail("dependency manifest contains an unreachable package")


def require_search_root(
    rows: Sequence[Mapping[str, str]], graph: Mapping[str, tuple[str, ...]]
) -> str:
    root = search_root_key()
    matches = [row for row in rows if row["package_key"] == root]
    if len(matches) != 1:
        fail("exact Search V8 root package is absent")
    row = matches[0]
    expected = {
        "name": SEARCH_ROOT_NAME,
        "version": SEARCH_ROOT_VERSION,
        "source_kind": "path",
        "source_locator": SEARCH_ROOT_SOURCE,
        "manifest_role": SEARCH_ROOT_MANIFEST_ROLE,
        "lock_checksum": "none",
    }
    if any(row[key] != value for key, value in expected.items()):
        fail("Search V8 root package identity is not exact")
    require_connected(graph, root)
    return root


def parse_cargo_lock(
    data: bytes, label: str = CARGO_LOCK_NAME
) -> tuple[list[LockPackage], int]:
    prefix = (
        b"# This file is automatically @generated by Cargo.\n"
        b"# It is not intended for manual editing.\n"
        b"version = 4\n"
    )
    if (
        not 0 < len(data) <= MAX_TEXT
        or b"\x00" in data
        or b"\r" in data
        or not data.endswith(b"\n")
        or not data.startswith(prefix)
    ):
        fail(f"{label} is not canonical Cargo.lock v4 text")
    try:
        document = tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        fail(f"{label} is not valid Cargo.lock v4 TOML: {error}")
    if set(document) != {"version", "package"} or document["version"] != 4:
        fail(f"{label} does not have the exact Cargo.lock v4 root")
    packages = document["package"]
    if not isinstance(packages, list) or not 0 < len(packages) <= MAX_PACKAGES:
        fail(f"{label} package count is outside the closed bound")
    pending: list[tuple[str, str, str, str, str, tuple[str, ...]]] = []
    observed: set[tuple[str, str, str]] = set()
    observed_names: set[str] = set()
    previous_order: tuple[str, str, str] | None = None
    allowed_keys = {"name", "version", "source", "checksum", "dependencies"}
    for index, package in enumerate(packages, 1):
        if not isinstance(package, dict) or not set(package) <= allowed_keys:
            fail(f"{label} package {index} has unsupported fields")
        name = package.get("name")
        version = package.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            fail(f"{label} package {index} lacks a canonical name/version")
        require_atom(name, "Cargo.lock package name")
        require_atom(version, "Cargo.lock package version")
        source = package.get("source")
        checksum = package.get("checksum")
        if source is None:
            if checksum is not None:
                fail("Cargo.lock path package unexpectedly has a checksum")
            source_kind = "path"
            locator = "none"
            locked_checksum = "none"
        elif isinstance(source, str) and source == CRATES_IO_SOURCE:
            if not isinstance(checksum, str):
                fail("Cargo.lock registry package lacks a checksum")
            source_kind = "registry"
            locator = source
            locked_checksum = require_hex(checksum, 64, "Cargo.lock checksum")
        else:
            fail("Cargo.lock contains a non-path/noncanonical-registry source")
        dependencies = package.get("dependencies", [])
        if (
            not isinstance(dependencies, list)
            or any(
                not isinstance(item, str)
                or not ATOM.fullmatch(item)
                for item in dependencies
            )
            or dependencies != sorted(set(dependencies))
        ):
            fail(
                "Cargo.lock dependencies are not sorted unique bare "
                "package names"
            )
        order_key = (name, version, locator)
        if (
            order_key in observed
            or name in observed_names
            or (previous_order is not None and order_key <= previous_order)
        ):
            fail(
                "Cargo.lock packages are not ordered with globally unique "
                "names and identities"
            )
        previous_order = order_key
        observed.add(order_key)
        observed_names.add(name)
        pending.append(
            (
                name,
                version,
                source_kind,
                locator,
                locked_checksum,
                tuple(dependencies),
            )
        )
    if any(
        dependency not in observed_names
        for *_, dependencies in pending
        for dependency in dependencies
    ):
        fail("Cargo.lock dependency names do not resolve inside the lock")
    rows = [LockPackage(*fields) for fields in pending]
    return rows, len(rows)


def bind_lock_packages(
    lock_rows: Sequence[LockPackage],
    dependency_rows: Sequence[Mapping[str, str]],
) -> None:
    path_index = {
        (row.name, row.version): row
        for row in lock_rows
        if row.source_kind == "path"
    }
    registry_index = {
        (row.name, row.version, row.source_locator): row
        for row in lock_rows
        if row.source_kind == "registry"
    }
    selected_path_tuples = [
        (row["name"], row["version"])
        for row in dependency_rows
        if row["source_kind"] == "path"
    ]
    if len(selected_path_tuples) != len(set(selected_path_tuples)):
        fail("selected path packages are ambiguous in Cargo.lock")
    selected_by_key = {row["package_key"]: row for row in dependency_rows}
    mapped: dict[str, LockPackage] = {}
    for row in dependency_rows:
        if row["source_kind"] == "path":
            locked = path_index.get((row["name"], row["version"]))
            if locked is None or locked.lock_checksum != "none":
                fail("selected path package is absent from Cargo.lock")
        else:
            locked = registry_index.get(
                (row["name"], row["version"], row["source_locator"])
            )
            if locked is None or locked.lock_checksum != row["lock_checksum"]:
                fail("selected registry package/checksum differs from Cargo.lock")
        mapped[row["package_key"]] = locked

    by_name = {row.name: row for row in lock_rows}
    adjacency = {
        row.identity(): frozenset(
            by_name[name].identity() for name in row.dependency_names
        )
        for row in lock_rows
    }
    for row in dependency_rows:
        source = mapped[row["package_key"]]
        for target_key in dependency_targets(row["dependencies"]):
            target_row = selected_by_key.get(target_key)
            target = mapped.get(target_key)
            if (
                target_row is None
                or target is None
                or target.identity() not in adjacency[source.identity()]
            ):
                fail(
                    "dependency manifest edge is absent from the exact "
                    "Cargo.lock graph"
                )


def parse_archives(
    data: bytes,
    registry_checksums: Mapping[str, str],
    label: str = REGISTRY_ARCHIVES_NAME,
) -> tuple[bytes, list[dict[str, str]], int]:
    data, rows = parse_table(data, label, ARCHIVE_HEADER, MAX_PACKAGES)
    observed: set[str] = set()
    roles: set[str] = set()
    previous = ""
    total = 0
    for ordinal, row in enumerate(rows, 1):
        uint(row["ordinal"], ordinal, ordinal, "archive ordinal")
        key = require_hex(row["package_key"], 64, "archive package key")
        if key <= previous or key in observed or key not in registry_checksums:
            fail("archive package keys are unordered, duplicate, or non-registry")
        previous = key
        observed.add(key)
        if package_key(row["name"], row["version"], row["source_locator"]) != key:
            fail("archive package key mismatch")
        if row["source_locator"] != CRATES_IO_SOURCE:
            fail("archive source locator is not canonical")
        checksum = require_hex(row["lock_checksum"], 64, "archive lock checksum")
        if checksum != registry_checksums[key]:
            fail("archive checksum differs from its dependency row")
        if require_hex(row["archive_sha256"], 64, "archive SHA-256") != checksum:
            fail("archive SHA-256 differs from Cargo.lock checksum")
        total += uint(row["archive_bytes"], 1, MAX_FILE_BYTES, "archive bytes")
        if total > MAX_TOTAL_BYTES:
            fail("registry archives exceed their aggregate byte bound")
        role = row["archive_role"]
        if role != registry_archive_role(key) or role in roles:
            fail("archive role is not unique and derived from its package key")
        roles.add(role)
    if observed != set(registry_checksums):
        fail("archive sidecar does not cover every registry package")
    return data, rows, total


def parse_archive_bindings(values: Sequence[str]) -> dict[str, Path]:
    bindings: dict[str, Path] = {}
    for value in values:
        key, separator, raw_path = value.partition("=")
        if not separator:
            fail("registry archive input is not PACKAGE_KEY=/absolute/file.crate")
        key = require_hex(key, 64, "registry archive package key")
        path = Path(raw_path)
        if (
            key in bindings
            or not path.is_absolute()
            or not path.name.endswith(".crate")
        ):
            fail("registry archive inputs are duplicate or not absolute .crate files")
        bindings[key] = path
    return bindings


def verify_archive_inputs(
    rows: Sequence[Mapping[str, str]], bindings: Mapping[str, Path]
) -> None:
    expected = {row["package_key"] for row in rows}
    if set(bindings) != expected:
        fail("real registry archive inputs do not exactly cover the archive sidecar")
    identities: set[tuple[int, int]] = set()
    total = 0
    for row in rows:
        key = row["package_key"]
        length, digest, identity = hash_regular_path(
            bindings[key],
            MAX_FILE_BYTES,
            label=f"registry archive {key}",
            single_link=True,
        )
        if identity in identities:
            fail("registry archive inputs alias one physical inode")
        identities.add(identity)
        total += length
        if total > MAX_TOTAL_BYTES:
            fail("real registry archives exceed their aggregate byte bound")
        if length != int(row["archive_bytes"]) or digest != row["archive_sha256"]:
            fail("real registry archive bytes differ from their authenticated row")


def source_identity(source: bytes) -> str:
    return domain_hash(SOURCE_DOMAIN, [(SOURCE_SNAPSHOT_NAME, source)])


def dependency_identity(source: bytes, lock: bytes, deps: bytes, archives: bytes) -> str:
    return domain_hash(
        DEPENDENCY_DOMAIN,
        [
            (SOURCE_SNAPSHOT_NAME, source),
            (CARGO_LOCK_NAME, lock),
            (DEPENDENCY_MANIFEST_NAME, deps),
            (REGISTRY_ARCHIVES_NAME, archives),
        ],
    )


def provenance_identity(rows: Sequence[tuple[str, str]]) -> str:
    if [key for key, _ in rows] != PROVENANCE_KEYS[:-1]:
        fail("provenance preimage keys are not in the closed order")
    try:
        fields = [(key, value.encode("ascii")) for key, value in rows]
    except UnicodeEncodeError as error:
        fail(f"provenance preimage is not ASCII: {error}")
    return domain_hash(PROVENANCE_DOMAIN, fields)


def receipt_bytes(rows: Sequence[tuple[str, str]]) -> bytes:
    if [key for key, _ in rows] != PROVENANCE_KEYS:
        fail("provenance receipt keys are not in the closed order")
    if any(
        not value or any(char in value for char in "\t\r\n\x00")
        for _, value in rows
    ):
        fail("provenance receipt contains an unsafe value")
    try:
        return "".join(f"{key}\t{value}\n" for key, value in rows).encode("ascii")
    except UnicodeEncodeError as error:
        fail(f"provenance receipt is not ASCII: {error}")
    raise AssertionError("unreachable")


def parse_receipt(
    data: bytes, label: str = PROVENANCE_NAME
) -> tuple[bytes, dict[str, str]]:
    if not 0 < len(data) <= 64 * 1024:
        fail(f"{label} is outside its closed byte bound")
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        fail(f"{label} is not ASCII: {error}")
    if not data.endswith(b"\n") or len(lines) != len(PROVENANCE_KEYS):
        fail(f"{label} row count/newline is invalid")
    output: dict[str, str] = {}
    for line, key in zip(lines, PROVENANCE_KEYS, strict=True):
        fields = line.split("\t")
        if len(fields) != 2 or fields[0] != key or not fields[1]:
            fail(f"{label} expected key {key!r}")
        output[key] = fields[1]
    if receipt_bytes(list(output.items())) != data:
        fail(f"{label} is not canonical")
    return data, output
