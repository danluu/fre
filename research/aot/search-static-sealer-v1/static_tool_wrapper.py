#!/usr/bin/env python3
"""Exact rustc/linker wrapper for the static AOT construction transcript.

The wrapper is intended to be passed to Cargo and rustc through inherited
anonymous descriptors (``/dev/fd/N`` on Darwin and ``/proc/self/fd/N`` on
Linux).  It loads the preregistered sealer core from authenticated bytes,
executes the selected tool through that core's kernel-attested boundary, and
writes one exclusive invocation receipt.  A linker invocation additionally
copies every explicit object/archive input to held anonymous storage and
rewrites the invocation to those descriptors before the linker can run.
"""

from __future__ import annotations

import hashlib
import ctypes
import json
import os
import platform
import re
import stat
import struct
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA = "fre.aot.search-static-tool-invocation.v1"
HEX64 = frozenset("0123456789abcdef")
CONTROL_PREFIX = "FRE_STATIC_ATTEST_"
MAXIMUM_SOURCE_BYTES = 4 * 1024 * 1024
MAXIMUM_TOOL_OUTPUT_BYTES = 1 << 30
MAXIMUM_TOOL_SECONDS = 2 * 60 * 60
LINK_INPUT_FD_BASE = 128
EXTERNAL_CANDIDATE_OBJECT = re.compile(
    r"^external-search-(?:0|[1-9][0-9]*)-"
    r"(?:implementation|family-glue)\.o$"
)
BUILD_SCRIPT_SIDECAR_SCHEMA = (
    "fre.aot.search-static-build-script-launch.v1"
)


class Refusal(RuntimeError):
    """An invocation differs from the exact static construction contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode()


def canonical_sha(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(byte in HEX64 for byte in value)
    )


def descriptor_path(path: Path) -> int | None:
    prefix = (
        "/dev/fd/"
        if platform.system() == "Darwin"
        else "/proc/self/fd/"
        if platform.system() == "Linux"
        else ""
    )
    encoded = str(path)
    if not prefix or not encoded.startswith(prefix):
        return None
    suffix = encoded[len(prefix) :]
    require(
        suffix.isascii()
        and suffix.isdecimal()
        and suffix == str(int(suffix))
        and int(suffix) >= 3,
        "inherited descriptor path is noncanonical",
    )
    return int(suffix)


def held_descriptor_bytes(
    descriptor: int, path: Path, maximum: int
) -> bytes:
    status = os.fstat(descriptor)
    require(
        stat.S_ISREG(status.st_mode)
        and 0 < status.st_size <= maximum,
        f"not one bounded held regular file: {path}",
    )
    output = bytearray()
    offset = 0
    while offset < status.st_size:
        encoded = os.pread(
            descriptor,
            min(1024 * 1024, status.st_size - offset),
            offset,
        )
        require(bool(encoded), f"held file ended early: {path}")
        output.extend(encoded)
        offset += len(encoded)
    after = os.fstat(descriptor)
    require(
        (status.st_dev, status.st_ino, status.st_size)
        == (after.st_dev, after.st_ino, after.st_size)
        and status.st_size == len(output),
        f"held file size or identity changed: {path}",
    )
    return bytes(output)


def held_bytes(path: Path, maximum: int) -> bytes:
    inherited = descriptor_path(path)
    if inherited is not None:
        return held_descriptor_bytes(inherited, path, maximum)
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        return held_descriptor_bytes(descriptor, path, maximum)
    finally:
        os.close(descriptor)


def darwin_cdhash_from_macho(path: Path) -> str:
    """Derive the arm64 Mach-O CodeDirectory CDHash without another tool."""

    encoded = held_bytes(path, 1 << 31)
    require(
        len(encoded) >= 32,
        "Mach-O executable is too short for a code signature",
    )
    magic = struct.unpack_from("<I", encoded, 0)[0]
    require(
        magic == 0xFEEDFACF,
        "attested build-script executable is not one little-endian Mach-O64",
    )
    commands = struct.unpack_from("<I", encoded, 16)[0]
    command_bytes = struct.unpack_from("<I", encoded, 20)[0]
    require(
        commands > 0
        and 32 + command_bytes <= len(encoded),
        "Mach-O load-command table changed",
    )
    offset = 32
    signature: tuple[int, int] | None = None
    for _ in range(commands):
        require(offset + 8 <= len(encoded), "Mach-O load command is truncated")
        command, size = struct.unpack_from("<II", encoded, offset)
        require(
            size >= 8
            and size % 4 == 0
            and offset + size <= 32 + command_bytes,
            "Mach-O load command size changed",
        )
        if command == 0x1D:
            require(
                signature is None and size >= 16,
                "Mach-O has a duplicated/truncated code signature",
            )
            signature = struct.unpack_from("<II", encoded, offset + 8)
        offset += size
    require(
        offset == 32 + command_bytes and signature is not None,
        "Mach-O code-signature command is absent",
    )
    signature_offset, signature_bytes = signature
    require(
        signature_bytes >= 12
        and signature_offset + signature_bytes <= len(encoded),
        "Mach-O embedded signature is out of bounds",
    )
    magic, total, count = struct.unpack_from(
        ">III", encoded, signature_offset
    )
    require(
        magic == 0xFADE0CC0
        and total <= signature_bytes
        and total >= 12 + count * 8,
        "Mach-O embedded signature superblob changed",
    )
    code_directories: list[bytes] = []
    for index in range(count):
        slot, relative = struct.unpack_from(
            ">II", encoded, signature_offset + 12 + index * 8
        )
        if slot not in {0, 0x1000}:
            continue
        blob = signature_offset + relative
        require(
            blob + 8 <= signature_offset + total,
            "CodeDirectory index is out of bounds",
        )
        directory_magic, length = struct.unpack_from(">II", encoded, blob)
        require(
            directory_magic == 0xFADE0C02
            and length >= 44
            and blob + length <= signature_offset + total,
            "CodeDirectory blob changed",
        )
        code_directories.append(encoded[blob : blob + length])
    require(
        len(code_directories) == 1,
        "Mach-O must contain one primary CodeDirectory",
    )
    directory = code_directories[0]
    hash_type = directory[37]
    require(
        hash_type in {1, 2, 3},
        "CodeDirectory hash algorithm changed",
    )
    digest = (
        hashlib.sha1(directory).digest()
        if hash_type == 1
        else hashlib.sha256(directory).digest()
    )
    return digest[:20].hex()


def load_sealer(environment: Mapping[str, str]) -> dict[str, Any]:
    path = Path(required_environment(environment, "SEALER_SOURCE"))
    expected = required_sha(environment, "SEALER_SOURCE_SHA256")
    encoded = held_bytes(path, MAXIMUM_SOURCE_BYTES)
    require(
        hashlib.sha256(encoded).hexdigest() == expected,
        "sealer source identity changed",
    )
    namespace: dict[str, Any] = {
        "__name__": "fre_static_sealer_held",
        "__file__": str(path),
    }
    exec(compile(encoded, str(path), "exec"), namespace)
    return namespace


def required_environment(
    environment: Mapping[str, str], suffix: str
) -> str:
    value = environment.get(f"{CONTROL_PREFIX}{suffix}")
    require(
        isinstance(value, str) and bool(value) and "\0" not in value,
        f"missing wrapper control {suffix}",
    )
    return value


def required_sha(environment: Mapping[str, str], suffix: str) -> str:
    value = required_environment(environment, suffix)
    require(is_sha256(value), f"invalid wrapper SHA-256 control {suffix}")
    return value


def parse_identity(environment: Mapping[str, str], role: str) -> dict[str, str]:
    encoded = required_environment(
        environment, f"{role.upper()}_EXECUTION_IDENTITY"
    )
    identity = json.loads(encoded)
    require(
        isinstance(identity, dict)
        and canonical_bytes(identity).decode() == encoded,
        f"{role} execution identity is not canonical",
    )
    return identity


def controlled_descriptors(
    environment: Mapping[str, str], suffix: str
) -> tuple[int, ...]:
    value = required_environment(environment, suffix)
    if value == "-":
        return ()
    fields = value.split(",")
    require(
        bool(fields)
        and all(field.isascii() and field.isdecimal() for field in fields),
        "inherited descriptor list is malformed",
    )
    descriptors = tuple(int(field) for field in fields)
    require(
        len(set(descriptors)) == len(descriptors)
        and all(descriptor >= 3 for descriptor in descriptors),
        "inherited descriptor list is duplicated or unsafe",
    )
    for descriptor in descriptors:
        os.fstat(descriptor)
    return descriptors


def wrapper_role(
    environment: Mapping[str, str], launcher_path: Path
) -> str:
    current = os.path.normpath(launcher_path)
    rustc = os.path.normpath(
        required_environment(environment, "RUSTC_WRAPPER_PATH")
    )
    linker = os.path.normpath(
        required_environment(environment, "LINKER_WRAPPER_PATH")
    )
    require(rustc != linker, "wrapper descriptor paths are not disjoint")
    if current == rustc:
        return "rustc"
    if current == linker:
        return "linker"
    if (
        Path(current).name.startswith("build_script_build-")
        or Path(current).name == "build-script-build"
    ):
        return "build-script"
    raise Refusal("wrapper was not executed through a preregistered descriptor")


def build_script_paths(arguments: Sequence[str]) -> tuple[Path, Path, Path] | None:
    def option(name: str) -> str | None:
        try:
            return arguments[arguments.index(name) + 1]
        except (ValueError, IndexError):
            return None

    if option("--crate-name") != "build_script_build":
        return None
    require(
        option("--crate-type") == "bin"
        and option("--out-dir") is not None,
        "build-script rustc output contract changed",
    )
    extra = None
    for index, argument in enumerate(arguments[:-1]):
        if argument == "-C" and arguments[index + 1].startswith(
            "extra-filename="
        ):
            require(extra is None, "duplicated build-script extra filename")
            extra = arguments[index + 1].split("=", 1)[1]
    require(
        isinstance(extra, str)
        and extra.startswith("-")
        and "/" not in extra,
        "build-script extra filename changed",
    )
    output = Path(option("--out-dir")) / f"build_script_build{extra}"
    return (
        output,
        Path(f"{output}.fre-attested-real"),
        Path(f"{output}.fre-attested.json"),
    )


def build_script_execution_identity(
    path: Path, digest: str, sealer: Mapping[str, Any]
) -> dict[str, str]:
    if platform.system() == "Darwin":
        return sealer["execution_identity"](
            "darwin-suspended-cdhash-v1",
            darwin_cdhash_from_macho(path),
        )
    if platform.system() == "Linux":
        return sealer["execution_identity"](
            "linux-sealed-memfd-v1", digest
        )
    raise Refusal("build scripts require Darwin or Linux")


def write_exclusive(path: Path, encoded: bytes, mode: int) -> None:
    require(
        path.is_absolute() and not path.exists(),
        f"exclusive publication target already exists: {path}",
    )
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        mode,
    )
    try:
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            require(written > 0, "exclusive publication write stalled")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_build_script(
    arguments: Sequence[str],
    launcher_bytes: bytes,
    launcher_sha256: str,
    wrapper_sha256: str,
    sealer: Mapping[str, Any],
) -> dict[str, Any] | None:
    paths = build_script_paths(arguments)
    if paths is None:
        return None
    output, tool, sidecar = paths
    require(
        output.is_absolute()
        and output.is_file()
        and not output.is_symlink()
        and not tool.exists()
        and not sidecar.exists(),
        "build-script output is absent or publication target exists",
    )
    os.rename(output, tool)
    tool_sha256 = sealer["file_sha"](tool)
    payload = {
        "launcher_sha256": launcher_sha256,
        "wrapper_source_sha256": wrapper_sha256,
        "tool_path": str(tool),
        "tool_sha256": tool_sha256,
        "execution_identity": build_script_execution_identity(
            tool, tool_sha256, sealer
        ),
        "rustc_arguments_sha256": canonical_sha(list(arguments)),
    }
    envelope = {
        "schema": BUILD_SCRIPT_SIDECAR_SCHEMA,
        "payload_sha256": canonical_sha(payload),
        "payload": payload,
    }
    sidecar_bytes = canonical_bytes(envelope) + b"\n"
    write_exclusive(sidecar, sidecar_bytes, 0o400)
    write_exclusive(output, launcher_bytes, 0o500)
    return {
        "sidecar_path": str(sidecar),
        "sidecar_sha256": hashlib.sha256(sidecar_bytes).hexdigest(),
        **payload,
    }


def load_build_script_publication(
    executable: Path,
    expected_launcher_sha256: str,
    expected_wrapper_sha256: str,
) -> dict[str, Any]:
    require(
        executable.is_absolute(),
        "build-script launcher path is not absolute",
    )
    if executable.name == "build-script-build":
        candidates = sorted(
            path
            for path in executable.parent.iterdir()
            if path.name.startswith("build_script_build-")
            and path.name.endswith(".fre-attested.json")
            and path.is_file()
            and not path.is_symlink()
        )
        require(
            len(candidates) == 1,
            "Cargo build-script alias does not have one exact publication",
        )
        sidecar = candidates[0]
    else:
        sidecar = Path(f"{executable}.fre-attested.json")
    suffix = ".fre-attested.json"
    require(
        sidecar.name.endswith(suffix),
        "build-script publication sidecar name changed",
    )
    published_name = sidecar.name[: -len(suffix)]
    published_launcher = sidecar.with_name(published_name)
    published_tool = sidecar.with_name(
        f"{published_name}.fre-attested-real"
    )
    require(
        (
            executable == published_launcher
            or executable.name == "build-script-build"
        )
        and executable.parent == sidecar.parent,
        "build-script launcher is outside its exact publication",
    )
    encoded = held_bytes(sidecar, 64 * 1024)
    root = json.loads(encoded)
    require(
        isinstance(root, dict)
        and set(root) == {"schema", "payload_sha256", "payload"}
        and root["schema"] == BUILD_SCRIPT_SIDECAR_SCHEMA
        and isinstance(root["payload"], dict)
        and set(root["payload"])
        == {
            "launcher_sha256",
            "wrapper_source_sha256",
            "tool_path",
            "tool_sha256",
            "execution_identity",
            "rustc_arguments_sha256",
        }
        and canonical_sha(root["payload"]) == root["payload_sha256"]
        and root["payload"]["wrapper_source_sha256"]
        == expected_wrapper_sha256
        and root["payload"]["launcher_sha256"]
        == expected_launcher_sha256
        and root["payload"]["tool_path"]
        == str(published_tool)
        and is_sha256(root["payload"]["tool_sha256"])
        and is_sha256(root["payload"]["rustc_arguments_sha256"]),
        "build-script publication sidecar changed",
    )
    return {
        "sidecar_path": str(sidecar),
        "sidecar_sha256": hashlib.sha256(encoded).hexdigest(),
        **root["payload"],
    }


def loaded_image_paths() -> set[Path]:
    if platform.system() == "Darwin":
        library = ctypes.CDLL(None)
        library._dyld_image_count.argtypes = []
        library._dyld_image_count.restype = ctypes.c_uint32
        library._dyld_get_image_name.argtypes = [ctypes.c_uint32]
        library._dyld_get_image_name.restype = ctypes.c_char_p
        output = set()
        for index in range(library._dyld_image_count()):
            encoded = library._dyld_get_image_name(index)
            require(encoded is not None, "loaded-image path is absent")
            path = Path(os.fsdecode(encoded))
            if path.is_absolute() and path.exists():
                output.add(path.resolve(strict=True))
        return output
    if platform.system() == "Linux":
        output = set()
        for line in Path("/proc/self/maps").read_text(
            encoding="utf-8"
        ).splitlines():
            fields = line.split(maxsplit=5)
            if len(fields) == 6 and fields[5].startswith("/"):
                encoded = fields[5].removesuffix(" (deleted)")
                path = Path(encoded)
                if path.exists():
                    output.add(path.resolve(strict=True))
        require(bool(output), "Linux loaded-image set is empty")
        return output
    raise Refusal("loaded-image closure requires Darwin or Linux")


def python_runtime_receipt(
    environment: Mapping[str, str],
) -> dict[str, Any]:
    require(
        sys.flags.isolated == 1
        and sys.flags.no_site == 1
        and sys.flags.ignore_environment == 1
        and sys.flags.no_user_site == 1,
        "native launcher did not force isolated no-site Python",
    )
    path = Path(required_environment(environment, "PYTHON_RUNTIME_PATH"))
    expected = required_sha(environment, "PYTHON_RUNTIME_SHA256")
    require(
        path.is_absolute()
        and path.resolve(strict=True) in loaded_image_paths()
        and hashlib.sha256(
            held_bytes(path.resolve(strict=True), 1 << 31)
        ).hexdigest()
        == expected,
        "loaded Python runtime identity changed",
    )
    identity = json.loads(
        required_environment(
            environment, "PYTHON_RUNTIME_EXECUTION_IDENTITY"
        )
    )
    mechanism = (
        "darwin-loaded-image-sha256-v1"
        if platform.system() == "Darwin"
        else "linux-loaded-image-sha256-v1"
    )
    require(
        identity == {"mechanism": mechanism, "sha256": expected}
        and canonical_bytes(identity).decode()
        == required_environment(
            environment, "PYTHON_RUNTIME_EXECUTION_IDENTITY"
        ),
        "Python runtime execution identity changed",
    )
    return {
        "path": str(path.resolve(strict=True)),
        "sha256": expected,
        "execution_identity": identity,
        "flags": ["-I", "-S", "-E"],
    }


def child_environment(
    environment: Mapping[str, str], *, preserve_controls: bool
) -> dict[str, str]:
    stripped = {
        key: value
        for key, value in environment.items()
        if preserve_controls or not key.startswith(CONTROL_PREFIX)
    }
    require(
        bool(stripped)
        and all(
            key
            and "=" not in key
            and "\0" not in key
            and "\0" not in value
            for key, value in stripped.items()
        ),
        "tool environment is malformed",
    )
    return dict(sorted(stripped.items()))


def split_wl(argument: str) -> list[str]:
    require(argument.startswith("-Wl,"), "not one driver linker option")
    fields = argument[4:].split(",")
    require(
        bool(fields) and all(bool(field) for field in fields),
        "empty nested linker option",
    )
    forbidden = {
        "-filelist",
        "filelist",
        "--filelist",
        "-T",
        "--script",
        "--version-script",
        "-plugin",
        "--plugin",
        "-load",
        "--dynamic-linker",
        "-dynamic-linker",
        "-rpath",
        "--rpath",
        "-R",
        "-L",
        "-l",
        "-F",
        "-framework",
        "-weak_framework",
        "-syslibroot",
        "-sectcreate",
        "-order_file",
        "-alias_list",
        "-dylib_file",
        "-force_load",
        "--whole-archive",
    }
    require(
        not any(
            field.startswith("@")
            or field in forbidden
            or field.startswith("--script=")
            or field.startswith("--version-script=")
            or field.startswith("--plugin=")
            or field.startswith("-plugin=")
            or field.startswith("--dynamic-linker=")
            for field in fields
        ),
        "opaque or injectable nested linker input is forbidden",
    )
    index = 0
    while index < len(fields):
        field = fields[index]
        if field in {
            "-dead_strip",
            "-reproducible",
            "--as-needed",
            "--no-as-needed",
            "-Bstatic",
            "-Bdynamic",
            "--eh-frame-hdr",
            "--gc-sections",
            "--build-id=none",
            "-fatal_warnings",
        }:
            index += 1
            continue
        if field in {"-z", "z"}:
            require(
                index + 1 < len(fields)
                and fields[index + 1] in {"noexecstack", "relro", "now"},
                "unknown -z linker policy",
            )
            index += 2
            continue
        if field == "-segprot":
            require(
                index + 3 < len(fields)
                and fields[index + 1] in {"__TEXT", "__FRE_CONST"}
                and all(
                    value in {"r", "rx"}
                    for value in fields[index + 2 : index + 4]
                ),
                "unknown segment-protection linker policy",
            )
            index += 4
            continue
        if field in {"-map", "-Map", "Map"}:
            require(
                index + 1 < len(fields)
                and Path(fields[index + 1]).is_absolute(),
                "link map option lacks one absolute output",
            )
            index += 2
            continue
        if field.startswith(("-Map=", "Map=")):
            require(
                Path(field.split("=", 1)[1]).is_absolute(),
                "link map option lacks one absolute output",
            )
            index += 1
            continue
        raise Refusal(f"unknown nested linker option is forbidden: {field}")
    return fields


def link_operand_kinds(
    arguments: Sequence[str],
) -> tuple[dict[int, tuple[Path, str]], int, list[dict[str, Any]]]:
    """Return explicit file operands, the output operand, and symbolic inputs."""

    explicit: dict[int, tuple[Path, str]] = {}
    output_index = -1
    symbolic: list[dict[str, Any]] = []
    consumes_one = {
        "-arch",
        "-framework",
        "-weak_framework",
        "-rpath",
        "-install_name",
        "-compatibility_version",
        "-current_version",
        "-target",
        "--target",
        "--sysroot",
        "-isysroot",
    }
    harmless_exact = {
        "-nodefaultlibs",
        "-pie",
        "-shared",
        "-static",
        "-nostdlib",
        "-rdynamic",
        "--eh-frame-hdr",
        "--gc-sections",
        "--as-needed",
        "--no-as-needed",
    }
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        require(argument and "\0" not in argument, "empty linker token")
        require(
            not argument.startswith("@"),
            "linker response files are forbidden",
        )
        if argument == "-o":
            require(
                output_index < 0 and index + 1 < len(arguments),
                "linker output option changed",
            )
            output_index = index + 1
            index += 2
            continue
        if argument in consumes_one:
            require(index + 1 < len(arguments), "linker option lacks operand")
            operand = arguments[index + 1]
            require(
                operand and not operand.startswith("@"),
                "linker option operand changed",
            )
            if argument in {"-framework", "-weak_framework"}:
                symbolic.append(
                    {
                        "argument_index": index,
                        "kind": argument.lstrip("-"),
                        "value": operand,
                    }
                )
            elif argument in {
                "-rpath",
                "--sysroot",
                "-isysroot",
            }:
                require(
                    Path(operand).is_absolute(),
                    f"{argument} operand is not absolute",
                )
                symbolic.append(
                    {
                        "argument_index": index,
                        "kind": argument.lstrip("-"),
                        "value": operand,
                    }
                )
            index += 2
            continue
        if argument in {
            "-Wl,-exported_symbols_list",
            "-Wl,-unexported_symbols_list",
        }:
            require(
                index + 1 < len(arguments)
                and arguments[index + 1].startswith("-Wl,"),
                "symbol-list option lacks one explicit input",
            )
            encoded_path = arguments[index + 1][4:]
            require(
                "," not in encoded_path and Path(encoded_path).is_absolute(),
                "symbol-list input is not one absolute path",
            )
            explicit[index + 1] = (Path(encoded_path), "-Wl,")
            index += 2
            continue
        if argument.startswith("-Wl,"):
            split_wl(argument)
            index += 1
            continue
        if argument.startswith(("-l", "-L", "-F")):
            require(len(argument) > 2, "empty linker search/library option")
            symbolic.append(
                {
                    "argument_index": index,
                    "kind": {
                        "-l": "library",
                        "-L": "library-search",
                        "-F": "framework-search",
                    }[argument[:2]],
                    "value": argument[2:],
                }
            )
            index += 1
            continue
        if argument.startswith("--sysroot="):
            value = argument.split("=", 1)[1]
            require(
                bool(value) and Path(value).is_absolute(),
                "inline sysroot is not one absolute path",
            )
            symbolic.append(
                {
                    "argument_index": index,
                    "kind": "sysroot",
                    "value": value,
                }
            )
            index += 1
            continue
        if argument.startswith("-fuse-ld"):
            raise Refusal("opaque linker substitution is forbidden")
        if (
            argument
            in harmless_exact
            | {"-m64", "-m32", "-pthread", "-s", "-dynamiclib"}
            or argument.startswith("-mmacosx-version-min=")
        ):
            index += 1
            continue
        if argument.startswith("-"):
            raise Refusal(f"unknown linker option is forbidden: {argument}")
        path = Path(argument)
        require(path.is_absolute(), f"relative linker operand is forbidden: {argument}")
        explicit[index] = (path, "")
        index += 1
    require(output_index >= 0, "linker invocation lacks one output")
    explicit.pop(output_index, None)
    return explicit, output_index, symbolic


def held_link_arguments(
    arguments: Sequence[str],
    sealer: Mapping[str, Any],
    held_link_root: Path,
) -> tuple[
    list[str],
    list[dict[str, Any]],
    list[dict[str, Any]],
    tuple[int, ...],
    Path,
]:
    explicit, output_index, symbolic = link_operand_kinds(arguments)
    output = Path(arguments[output_index])
    require(
        output.is_absolute() and not output.exists(),
        "link output must be one absent absolute path",
    )
    rewritten = list(arguments)
    rows: list[dict[str, Any]] = []
    descriptors: list[int] = []
    invocation_root: Path | None = None
    prefix = "/dev/fd" if platform.system() == "Darwin" else "/proc/self/fd"
    for ordinal, token_index in enumerate(sorted(explicit)):
        original, token_prefix = explicit[token_index]
        name = original.name
        kind = (
            "symbol-list"
            if token_prefix == "-Wl,"
            else "object"
            if name.endswith(".o")
            else "archive"
            if name.endswith((".a", ".rlib"))
            else "dynamic-library"
            if name.endswith(".dylib") or ".so" in name
            else "text-stub"
            if name.endswith(".tbd")
            else ""
        )
        require(bool(kind), f"unknown explicit linker input kind: {original}")
        if kind == "object" and EXTERNAL_CANDIDATE_OBJECT.fullmatch(name):
            if invocation_root is None:
                require(
                    held_link_root.is_absolute()
                    and held_link_root.is_dir()
                    and not held_link_root.is_symlink(),
                    "held candidate-link root changed",
                )
                invocation_root = held_link_root / str(os.getpid())
                invocation_root.mkdir(mode=0o700)
                require(
                    invocation_root.lstat().st_mode & 0o777 == 0o700,
                    "held candidate-link invocation directory changed",
                )
            encoded = sealer["regular_file"](
                original, MAXIMUM_TOOL_OUTPUT_BYTES
            )
            digest = hashlib.sha256(encoded).hexdigest()
            held_path = invocation_root / name
            write_exclusive(held_path, encoded, 0o400)
            require(
                not held_path.is_symlink()
                and held_path.lstat().st_mode & 0o777 == 0o400
                and hashlib.sha256(
                    held_bytes(held_path, MAXIMUM_TOOL_OUTPUT_BYTES)
                ).hexdigest()
                == digest,
                "held candidate-link alias changed",
            )
            rewritten[token_index] = f"{token_prefix}{held_path}"
            rows.append(
                {
                    "ordinal": ordinal,
                    "argument_index": token_index,
                    "path": str(original),
                    "sha256": digest,
                    "bytes": len(encoded),
                    "kind": kind,
                    "held_argument": rewritten[token_index],
                }
            )
            continue
        source = sealer["open_regular_fd"](original)
        try:
            digest = sealer["file_sha_fd"](source)
            held = sealer["sealed_copy_descriptor"](
                source, digest, executable=False
            )
        finally:
            os.close(source)
        deterministic = LINK_INPUT_FD_BASE + ordinal
        try:
            os.fstat(deterministic)
        except OSError:
            pass
        else:
            os.close(held)
            raise Refusal("deterministic link-input descriptor is occupied")
        os.dup2(held, deterministic, inheritable=True)
        os.close(held)
        descriptors.append(deterministic)
        rewritten[token_index] = (
            f"{token_prefix}{prefix}/{deterministic}"
        )
        rows.append(
            {
                "ordinal": ordinal,
                "argument_index": token_index,
                "path": str(original),
                "sha256": digest,
                "bytes": os.fstat(deterministic).st_size,
                "kind": kind,
                "held_argument": rewritten[token_index],
            }
        )
    return rewritten, rows, symbolic, tuple(descriptors), output


def write_receipt(directory: Path, payload: Mapping[str, Any]) -> str:
    require(directory.is_absolute(), "receipt directory is not absolute")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    directory_fd = os.open(directory, flags)
    try:
        encoded_payload = canonical_bytes(payload)
        envelope = {
            "schema": SCHEMA,
            "payload_sha256": hashlib.sha256(encoded_payload).hexdigest(),
            "payload": payload,
        }
        encoded = canonical_bytes(envelope) + b"\n"
        stem = canonical_sha(
            {
                "role": payload["role"],
                "wrapper_pid": payload["lineage"]["wrapper_pid"],
                "arguments_sha256": payload["arguments_sha256"],
            }
        )
        name = f"{payload['role']}-{stem}.json"
        descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
            dir_fd=directory_fd,
        )
        try:
            offset = 0
            while offset < len(encoded):
                written = os.write(descriptor, encoded[offset:])
                require(written > 0, "receipt write made no progress")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return hashlib.sha256(encoded).hexdigest()
    finally:
        os.close(directory_fd)


def run(argv: Sequence[str], environment: Mapping[str, str]) -> int:
    require(len(argv) >= 1, "wrapper argv is empty")
    wrapper_bytes = held_bytes(Path(__file__), MAXIMUM_SOURCE_BYTES)
    wrapper_sha256 = hashlib.sha256(wrapper_bytes).hexdigest()
    require(
        Path(__file__).is_absolute()
        and os.path.normpath(__file__)
        == os.path.normpath(
            required_environment(environment, "WRAPPER_SCRIPT_PATH")
        )
        and wrapper_sha256
        == required_sha(environment, "WRAPPER_SOURCE_SHA256"),
        "executed wrapper source identity changed",
    )
    launcher_path = Path(argv[0])
    launcher_bytes = held_bytes(launcher_path, MAXIMUM_SOURCE_BYTES)
    launcher_sha256 = hashlib.sha256(launcher_bytes).hexdigest()
    require(
        launcher_sha256 == required_sha(environment, "LAUNCHER_SHA256"),
        "executed native launcher identity changed",
    )
    launcher_identity = parse_identity(environment, "launcher")
    if platform.system() == "Linux":
        require(
            launcher_identity
            == {
                "mechanism": "linux-stopped-proc-exe-sha256-v1",
                "sha256": launcher_sha256,
            },
            "Linux native launcher execution identity changed",
        )
    else:
        require(
            launcher_identity
            == {
                "mechanism": "darwin-suspended-cdhash-v1",
                "cdhash": darwin_cdhash_from_macho(launcher_path),
            },
            "Darwin native launcher execution identity changed",
        )
    runtime = python_runtime_receipt(environment)
    sealer = load_sealer(environment)
    role = wrapper_role(environment, launcher_path)
    build_script_publication = None
    if role == "build-script":
        build_script_publication = load_build_script_publication(
            launcher_path, launcher_sha256, wrapper_sha256
        )
        tool_path = Path(build_script_publication["tool_path"])
        tool_sha256 = build_script_publication["tool_sha256"]
        identity = build_script_publication["execution_identity"]
    else:
        tool_path = Path(
            required_environment(environment, f"{role.upper()}_PATH")
        )
        tool_sha256 = required_sha(
            environment, f"{role.upper()}_SHA256"
        )
        identity = parse_identity(environment, role)
    if role == "rustc":
        require(
            len(argv) >= 2 and argv[1] == str(tool_path),
            "Cargo selected a rustc outside the attested tool identity",
        )
        original_arguments = list(argv[2:])
        executed_arguments = original_arguments
        input_rows: list[dict[str, Any]] = []
        tool_fds = controlled_descriptors(
            environment, "RUSTC_CHILD_FDS"
        )
        symbolic_inputs: list[dict[str, Any]] = []
        output_path: Path | None = None
    elif role == "linker":
        original_arguments = list(argv[1:])
        (
            executed_arguments,
            input_rows,
            symbolic_inputs,
            held_inputs,
            output_path,
        ) = held_link_arguments(
            original_arguments,
            sealer,
            Path(required_environment(environment, "HELD_LINK_ROOT")),
        )
        tool_fds = held_inputs
    else:
        original_arguments = list(argv[1:])
        executed_arguments = original_arguments
        input_rows = []
        symbolic_inputs = []
        output_path = None
        tool_fds = controlled_descriptors(
            environment, "BUILD_SCRIPT_CHILD_FDS"
        )
    exact_environment = child_environment(
        environment, preserve_controls=role in {"rustc", "build-script"}
    )
    child: list[int] = []
    try:
        result = sealer["run_sealed"](
            executable=tool_path,
            expected_sha256=tool_sha256,
            expected_execution_identity=identity,
            arguments=executed_arguments,
            inherited_descriptors=tool_fds,
            maximum=MAXIMUM_TOOL_OUTPUT_BYTES,
            timeout_seconds=MAXIMUM_TOOL_SECONDS,
            environment=exact_environment,
            on_spawn=child.append,
        )
        require(len(child) == 1, "attested tool lineage is incomplete")
        output = None
        if output_path is not None and result.returncode == 0:
            output = {
                "path": str(output_path),
                "sha256": sealer["file_sha"](output_path),
                "bytes": output_path.stat().st_size,
            }
        if role == "rustc" and result.returncode == 0:
            build_script_publication = publish_build_script(
                original_arguments,
                launcher_bytes,
                launcher_sha256,
                wrapper_sha256,
                sealer,
            )
        payload = {
            "role": role,
            "launcher": {
                "path": str(launcher_path),
                "sha256": launcher_sha256,
                "execution_identity": launcher_identity,
            },
            "python_runtime": runtime,
            "wrapper_source_sha256": wrapper_sha256,
            "sealer_source_sha256": required_sha(
                environment, "SEALER_SOURCE_SHA256"
            ),
            "tool": {
                "path": str(tool_path),
                "sha256": tool_sha256,
                "execution_identity": identity,
            },
            "lineage": {
                "parent_pid": os.getppid(),
                "wrapper_pid": os.getpid(),
                "tool_pid": child[0],
            },
            "arguments": original_arguments,
            "arguments_sha256": canonical_sha(original_arguments),
            "executed_arguments": executed_arguments,
            "executed_arguments_sha256": canonical_sha(executed_arguments),
            "environment": exact_environment,
            "environment_sha256": canonical_sha(exact_environment),
            "input_rows": input_rows,
            "input_rows_sha256": canonical_sha(input_rows),
            "symbolic_inputs": symbolic_inputs,
            "symbolic_inputs_sha256": canonical_sha(symbolic_inputs),
            "build_script_publication": build_script_publication,
            "output": output,
            "returncode": result.returncode,
            "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
            "stdout_bytes": len(result.stdout),
            "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
            "stderr_bytes": len(result.stderr),
        }
        write_receipt(
            Path(required_environment(environment, "RECEIPT_DIR")),
            payload,
        )
        sys.stdout.buffer.write(result.stdout)
        sys.stdout.buffer.flush()
        sys.stderr.buffer.write(result.stderr)
        sys.stderr.buffer.flush()
        return result.returncode
    finally:
        if role == "linker":
            for descriptor in tool_fds:
                os.close(descriptor)


def main() -> None:
    try:
        returncode = run(sys.argv[1:], dict(os.environ))
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        json.JSONDecodeError,
        Refusal,
    ) as error:
        print(f"fre-static-tool-wrapper: {error}", file=sys.stderr)
        raise SystemExit(127) from error
    raise SystemExit(returncode)


if __name__ == "__main__":
    main()
