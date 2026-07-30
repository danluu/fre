#!/usr/bin/env python3
"""Post-link authority derivation and atomic static-runner shard execution."""

from __future__ import annotations

import ctypes
import fcntl
import hashlib
import json
import os
import platform
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


SPEC_SCHEMA = "fre.aot.search-static-deployment-spec.v1"
AUTHORITY_RECEIPT_SCHEMA = "fre.aot.search-static-authority-receipt.v1"
SHARD_RECEIPT_SCHEMA = "fre.aot.search-static-shard-receipt.v1"
BUILD_CLOSURE_SCHEMA = "fre.aot.search-static-build-closure.v1"
LINK_CLOSURE_SCHEMA = "fre.aot.search-static-link-closure.v1"
RUNNER_SOURCE_DOMAIN = b"FRE-EXTERNAL-REGEX-STATIC-RUNNER-SOURCE\0\x01"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
CANONICAL_UINT = re.compile(r"(?:0|[1-9][0-9]*)\Z")

SOURCE_AUTHORITY_FIELDS = {
    "backend_source_identity_sha256",
    "emitter_auditor_identity_sha256",
    "compiler_source_identity_sha256",
    "object_contract_identity_sha256",
    "build_recipe_identity_sha256",
    "runtime_source_identity_sha256",
    "public_facade_source_identity_sha256",
}
FILE_AUTHORITY_FIELDS = {
    "compiler_binary_identity_sha256",
    "compiler_invocation_identity_sha256",
    "target_spec_identity_sha256",
    "build_environment_identity_sha256",
    "dependency_lock_identity_sha256",
    "linker_identity_sha256",
    "link_invocation_identity_sha256",
    "runtime_artifact_identity_sha256",
    "public_facade_artifact_identity_sha256",
}
CANONICAL_AUTHORITY_FIELDS = {
    "production_family_identity_sha256",
    "static_abi_identity_sha256",
    "output_contract_identity_sha256",
    "link_interface_identity_sha256",
}
BUILD_RECEIPT_FIELDS = {
    "schema",
    "identity_sha256",
    "runner_revision",
    "runner_source_sha256",
    "target_os",
    "target_arch",
    "backend_name",
    "backend_tag",
    "compiler_identity",
    "manifest_identity",
    "family_selector",
    "minimum_window_bytes",
    "portable_prefix_candidate_starts",
    "plan_identity",
    "analyzer_identity",
    "evidence_identity",
    "timing_permitted",
    "object_candidate_manifest_schema",
    "object_candidate_manifest_sha256",
    "object_candidate_count",
    "fixture_manifest_schema",
    "fixture_manifest_sha256",
    "canonical_byte_escaped_sources",
    "candidates",
}
BUILD_CLOSURE_FIELDS = {
    "scope",
    "platform",
    "repo_revision",
    "runner_source_sha256",
    "policy_source_sha256",
    "identity_sha256",
    "candidate_manifest_sha256",
    "build_receipt_sha256",
    "binary_sha256",
    "link_map_sha256",
    "link_invocation_sha256",
    "compiler_binary_sha256",
    "linker_sha256",
    "target_spec_sha256",
    "build_environment_sha256",
    "dependency_lock_sha256",
    "runtime_artifact_sha256",
    "public_facade_artifact_sha256",
    "cargo_binary_sha256",
    "rustc_binary_sha256",
    "cargo_version_sha256",
    "rustc_version_sha256",
    "command",
    "environment",
}
LINK_CLOSURE_FIELDS = {
    "scope",
    "platform",
    "real_linker_sha256",
    "linker_wrapper_sha256",
    "output_path",
    "output_sha256",
    "link_map_path",
    "link_map_sha256",
    "arguments",
    "arguments_sha256",
    "inputs",
}
SHARD_PAYLOAD_FIELDS = {
    "deployment_spec_sha256",
    "authority_receipt_path",
    "authority_receipt_sha256",
    "scope",
    "platform",
    "fixture_manifest_sha256",
    "binary_sha256_before",
    "binary_sha256_after",
    "shard",
    "shards",
    "raw_path",
    "raw_sha256",
}


class Refusal(RuntimeError):
    """A deployment input differs from its frozen pre-result specification."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def canonical_sha(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def open_regular_fd(path: Path, maximum: int = 1 << 31) -> int:
    absolute = path.absolute()
    require(
        absolute.is_absolute()
        and all(component not in {"", ".", ".."} for component in absolute.parts[1:]),
        f"file path is not canonical: {path}",
    )
    directory_flags = (
        os.O_RDONLY
        | os.O_CLOEXEC
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = (
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    )
    directory = -1
    try:
        directory = os.open("/", directory_flags)
        for component in absolute.parts[1:-1]:
            child = os.open(component, directory_flags, dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(
            absolute.parts[-1], file_flags, dir_fd=directory
        )
    except OSError as error:
        raise Refusal(f"cannot open exact nonsymlink file {path}: {error}") from error
    finally:
        if directory >= 0:
            os.close(directory)
    try:
        status = os.fstat(descriptor)
        require(
            stat.S_ISREG(status.st_mode)
            and 0 < status.st_size <= maximum,
            f"not one bounded regular file: {path}",
        )
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def regular_file(path: Path, maximum: int = 1 << 31) -> bytes:
    descriptor = open_regular_fd(path, maximum)
    try:
        status = os.fstat(descriptor)
        output = bytearray()
        offset = 0
        while offset < status.st_size:
            encoded = os.pread(
                descriptor,
                min(1024 * 1024, status.st_size - offset),
                offset,
            )
            require(bool(encoded), "opened file ended before its stat size")
            output.extend(encoded)
            offset += len(encoded)
        after = os.fstat(descriptor)
        require(
            (status.st_dev, status.st_ino, status.st_size)
            == (after.st_dev, after.st_ino, after.st_size),
            f"opened file changed while reading: {path}",
        )
        return bytes(output)
    finally:
        os.close(descriptor)


def file_sha(path: Path, maximum: int = 1 << 31) -> str:
    return hashlib.sha256(regular_file(path, maximum)).hexdigest()


def file_sha_fd(descriptor: int, maximum: int = 1 << 31) -> str:
    status = os.fstat(descriptor)
    require(
        stat.S_ISREG(status.st_mode)
        and 0 < status.st_size <= maximum,
        "opened file is not one bounded regular file",
    )
    digest = hashlib.sha256()
    offset = 0
    while offset < status.st_size:
        encoded = os.pread(
            descriptor, min(1024 * 1024, status.st_size - offset), offset
        )
        require(bool(encoded), "opened file ended before its stat size")
        digest.update(encoded)
        offset += len(encoded)
    return digest.hexdigest()


def open_hashed_executable(
    path: Path, expected_sha256: str
) -> tuple[int, os.stat_result]:
    descriptor = open_regular_fd(path)
    try:
        opened = os.fstat(descriptor)
        require(
            stat.S_ISREG(opened.st_mode)
            and opened.st_mode & 0o111 != 0
            and file_sha_fd(descriptor) == expected_sha256,
            f"opened executable identity changed: {path}",
        )
        return descriptor, opened
    except BaseException:
        os.close(descriptor)
        raise


def sealed_copy_descriptor(
    source: int, expected_sha256: str, *, executable: bool
) -> int:
    require(
        file_sha_fd(source) == expected_sha256,
        "sealed-copy source identity changed",
    )
    system = platform.system()
    temporary_path: str | None = None
    if system == "Linux":
        require(
            hasattr(os, "memfd_create")
            and hasattr(os, "MFD_ALLOW_SEALING"),
            "Linux sealed memfd support is unavailable",
        )
        descriptor = os.memfd_create(
            "fre-static-sealed",
            os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
        )
    elif system == "Darwin":
        descriptor, temporary_path = tempfile.mkstemp(
            prefix="fre-static-sealed."
        )
    else:
        raise Refusal("sealed copy requires Darwin or Linux")
    try:
        status = os.fstat(source)
        offset = 0
        while offset < status.st_size:
            encoded = os.pread(
                source,
                min(1024 * 1024, status.st_size - offset),
                offset,
            )
            require(bool(encoded), "sealed-copy source ended early")
            written = 0
            while written < len(encoded):
                count = os.pwrite(
                    descriptor,
                    encoded[written:],
                    offset + written,
                )
                require(count > 0, "sealed-copy write made no progress")
                written += count
            offset += len(encoded)
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o500 if executable else 0o400)
        require(
            file_sha_fd(descriptor) == expected_sha256
            and file_sha_fd(source) == expected_sha256,
            "sealed copy differs from its held source",
        )
        if system == "Linux":
            required_seals = (
                fcntl.F_SEAL_WRITE
                | fcntl.F_SEAL_GROW
                | fcntl.F_SEAL_SHRINK
                | fcntl.F_SEAL_SEAL
            )
            fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, required_seals)
            require(
                fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
                & required_seals
                == required_seals,
                "Linux memfd seals differ from policy",
            )
        else:
            require(
                temporary_path is not None,
                "Darwin sealed-copy path is absent",
            )
            flags = os.O_RDONLY | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            read_only = os.open(temporary_path, flags)
            try:
                require(
                    fcntl.fcntl(read_only, fcntl.F_GETFL)
                    & os.O_ACCMODE
                    == os.O_RDONLY
                    and file_sha_fd(read_only) == expected_sha256,
                    "Darwin held copy did not reopen read-only",
                )
                os.unlink(temporary_path)
                temporary_path = None
                os.close(descriptor)
                descriptor = read_only
                read_only = -1
            finally:
                if read_only >= 0:
                    os.close(read_only)
        return descriptor
    except BaseException:
        os.close(descriptor)
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass
        raise


def open_sealed_input(path: Path, expected_sha256: str) -> int:
    source = open_regular_fd(path)
    try:
        return sealed_copy_descriptor(
            source, expected_sha256, executable=False
        )
    finally:
        os.close(source)


def canonical_relative(value: str) -> bool:
    return (
        bool(value)
        and not value.startswith("/")
        and "\\" not in value
        and all(part not in {"", ".", ".."} for part in value.split("/"))
    )


def load_envelope(
    path: Path, schema: str, maximum: int = 2 * 1024 * 1024
) -> tuple[dict[str, Any], str]:
    encoded = regular_file(path, maximum)
    root = json.loads(encoded)
    require(
        isinstance(root, dict)
        and set(root) == {"schema", "payload_sha256", "payload"}
        and root["schema"] == schema
        and isinstance(root["payload"], dict)
        and canonical_sha(root["payload"]) == root["payload_sha256"],
        f"envelope changed: {path}",
    )
    return root, hashlib.sha256(encoded).hexdigest()


def write_envelope(path: Path, schema: str, payload: Mapping[str, Any]) -> str:
    root = {
        "schema": schema,
        "payload_sha256": canonical_sha(payload),
        "payload": payload,
    }
    encoded = (
        json.dumps(root, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode()
    atomic_write(path, encoded)
    return hashlib.sha256(encoded).hexdigest()


def atomic_write(path: Path, encoded: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def resolve_regular(root: Path, relative: str, maximum: int = 1 << 31) -> Path:
    require(canonical_relative(relative), f"noncanonical artifact path: {relative}")
    canonical_root = root.resolve(strict=True)
    path = canonical_root / relative
    descriptor = open_regular_fd(path, maximum)
    os.close(descriptor)
    return path


def source_set_sha(repo: Path, entries: Sequence[str], domain: str) -> str:
    require(
        list(entries) == sorted(set(entries)) and bool(entries),
        f"source set is not an exact sorted file list: {domain}",
    )
    files: dict[str, Path] = {}
    canonical_repo = repo.resolve(strict=True)
    for entry in entries:
        try:
            path = resolve_regular(
                canonical_repo, entry, 16 * 1024 * 1024
            )
        except Refusal as error:
            raise Refusal(
                f"source entry is not one exact file: {entry}: {error}"
            ) from error
        files[entry] = path
    digest = hashlib.sha256()
    digest.update(domain.encode())
    digest.update(b"\0\x01")
    for name, path in sorted(files.items()):
        encoded = regular_file(path, 16 * 1024 * 1024)
        digest.update(name.encode())
        digest.update(b"\0")
        digest.update(len(encoded).to_bytes(8, "little"))
        digest.update(encoded)
    return digest.hexdigest()


def runner_source_sha(repo: Path) -> str:
    runner = repo / "research/aot/external-regex-1.12.4/static-runner"
    names = regular_file(runner / "runner-source-files.txt", 64 * 1024).decode()
    require(names.endswith("\n"), "runner source manifest is not terminated")
    entries = names.splitlines()
    require(entries == sorted(set(entries)) and bool(entries), "runner sources changed")
    digest = hashlib.sha256()
    digest.update(RUNNER_SOURCE_DOMAIN)
    for name in entries:
        require(canonical_relative(name), "runner source path changed")
        encoded = regular_file(runner / name, 2 * 1024 * 1024)
        digest.update(name.encode())
        digest.update(b"\0")
        digest.update(len(encoded).to_bytes(8, "little"))
        digest.update(encoded)
    return digest.hexdigest()


def parse_inspect(encoded: bytes) -> dict[str, str]:
    rows: dict[str, str] = {}
    for line in encoded.decode().splitlines():
        key, separator, value = line.partition("=")
        require(separator == "=" and key and key not in rows, "inspect output changed")
        rows[key] = value
    required = {
        "linked",
        "timing_permitted",
        "identity_sha256",
        "runner_source_sha256",
        "backend",
        "family_selector",
        "object_candidate_manifest_schema",
        "object_candidate_manifest_sha256",
        "linked_object_candidates",
        "candidates",
        "fixtures",
        "correctness",
    }
    require(set(rows) == required, "inspect receipt fields changed")
    return rows


def run_checked(arguments: Sequence[str], maximum: int = 32 * 1024 * 1024) -> bytes:
    result = subprocess.run(
        list(arguments),
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"},
    )
    require(result.returncode == 0, f"command failed: {arguments[0]}")
    require(not result.stderr, f"command wrote stderr: {arguments[0]}")
    require(0 < len(result.stdout) <= maximum, f"command output changed: {arguments[0]}")
    return result.stdout


def execution_identity(
    mechanism: str, value: str
) -> dict[str, str]:
    if mechanism == "linux-sealed-memfd-v1":
        require(HEX64.fullmatch(value) is not None, "Linux execution hash changed")
        return {"mechanism": mechanism, "sha256": value}
    if mechanism == "darwin-suspended-cdhash-v1":
        require(
            HEX40.fullmatch(value) is not None and value != "0" * 40,
            "Darwin execution CDHash changed",
        )
        return {"mechanism": mechanism, "cdhash": value}
    raise Refusal("unsupported sealed-execution mechanism")


def darwin_process_cdhash(pid: int) -> str:
    require(
        platform.system() == "Darwin"
        and isinstance(pid, int)
        and pid > 0,
        "Darwin process CDHash request changed",
    )
    library = ctypes.CDLL(None, use_errno=True)
    library.csops.argtypes = [
        ctypes.c_int,
        ctypes.c_uint,
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    library.csops.restype = ctypes.c_int
    digest = (ctypes.c_ubyte * 20)()
    require(
        library.csops(pid, 5, digest, len(digest)) == 0,
        f"Darwin process CDHash query failed: {ctypes.get_errno()}",
    )
    encoded = bytes(digest).hex()
    require(
        HEX40.fullmatch(encoded) is not None
        and encoded != "0" * 40,
        "Darwin process CDHash is empty",
    )
    return encoded


def darwin_spawn_suspended(
    *,
    executable: Path,
    arguments: Sequence[str],
    expected_cdhash: str,
    stdout_descriptor: int,
    stderr_descriptor: int,
    inherited_descriptors: Sequence[int],
    environment: Mapping[str, str],
) -> int:
    require(platform.system() == "Darwin", "Darwin spawn used on another OS")
    library = ctypes.CDLL(None, use_errno=True)
    opaque = ctypes.c_void_p
    integer = ctypes.c_int
    opaque_pointer = ctypes.POINTER(opaque)
    char_array = ctypes.POINTER(ctypes.c_char_p)
    library.posix_spawnattr_init.argtypes = [opaque_pointer]
    library.posix_spawnattr_init.restype = integer
    library.posix_spawnattr_setflags.argtypes = [
        opaque_pointer,
        ctypes.c_short,
    ]
    library.posix_spawnattr_setflags.restype = integer
    library.posix_spawnattr_destroy.argtypes = [opaque_pointer]
    library.posix_spawnattr_destroy.restype = integer
    library.posix_spawn_file_actions_init.argtypes = [opaque_pointer]
    library.posix_spawn_file_actions_init.restype = integer
    library.posix_spawn_file_actions_adddup2.argtypes = [
        opaque_pointer,
        integer,
        integer,
    ]
    library.posix_spawn_file_actions_adddup2.restype = integer
    library.posix_spawn_file_actions_addinherit_np.argtypes = [
        opaque_pointer,
        integer,
    ]
    library.posix_spawn_file_actions_addinherit_np.restype = integer
    library.posix_spawn_file_actions_destroy.argtypes = [opaque_pointer]
    library.posix_spawn_file_actions_destroy.restype = integer
    library.posix_spawn.argtypes = [
        ctypes.POINTER(integer),
        ctypes.c_char_p,
        opaque_pointer,
        opaque_pointer,
        char_array,
        char_array,
    ]
    library.posix_spawn.restype = integer
    attributes = opaque()
    actions = opaque()
    initialized_attributes = False
    initialized_actions = False
    child = 0

    def succeeded(result: int, operation: str) -> None:
        require(result == 0, f"Darwin {operation} failed: {result}")

    try:
        succeeded(
            library.posix_spawnattr_init(ctypes.byref(attributes)),
            "spawn attribute initialization",
        )
        initialized_attributes = True
        succeeded(
            library.posix_spawnattr_setflags(
                ctypes.byref(attributes), 0x0080 | 0x0400
            ),
            "suspended spawn configuration",
        )
        succeeded(
            library.posix_spawn_file_actions_init(ctypes.byref(actions)),
            "spawn file-action initialization",
        )
        initialized_actions = True
        succeeded(
            library.posix_spawn_file_actions_adddup2(
                ctypes.byref(actions), stdout_descriptor, 1
            ),
            "stdout binding",
        )
        succeeded(
            library.posix_spawn_file_actions_adddup2(
                ctypes.byref(actions), stderr_descriptor, 2
            ),
            "stderr binding",
        )
        for descriptor in inherited_descriptors:
            succeeded(
                library.posix_spawn_file_actions_addinherit_np(
                    ctypes.byref(actions), descriptor
                ),
                "sealed input inheritance",
            )
        encoded_arguments = [
            str(executable).encode(),
            *(argument.encode() for argument in arguments),
        ]
        argv = (ctypes.c_char_p * (len(encoded_arguments) + 1))(
            *encoded_arguments, None
        )
        encoded_environment = [
            f"{key}={value}".encode()
            for key, value in sorted(environment.items())
        ]
        environment = (
            ctypes.c_char_p * (len(encoded_environment) + 1)
        )(*encoded_environment, None)
        child_value = integer()
        succeeded(
            library.posix_spawn(
                ctypes.byref(child_value),
                str(executable).encode(),
                ctypes.byref(actions),
                ctypes.byref(attributes),
                argv,
                environment,
            ),
            "suspended spawn",
        )
        child = child_value.value
        require(
            darwin_process_cdhash(child) == expected_cdhash,
            "kernel-attested Darwin executable CDHash changed",
        )
        os.kill(child, signal.SIGCONT)
        result = child
        child = 0
        return result
    finally:
        if child:
            try:
                os.killpg(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(child, 0)
            except ChildProcessError:
                pass
        if initialized_actions:
            library.posix_spawn_file_actions_destroy(ctypes.byref(actions))
        if initialized_attributes:
            library.posix_spawnattr_destroy(ctypes.byref(attributes))


def drain_bounded_child(
    *,
    poll: Any,
    terminate: Any,
    stdout_descriptor: int,
    stderr_descriptor: int,
    output: Any,
    maximum: int,
    timeout_seconds: int,
) -> tuple[int, bytes]:
    selector = selectors.DefaultSelector()
    os.set_blocking(stdout_descriptor, False)
    os.set_blocking(stderr_descriptor, False)
    selector.register(stdout_descriptor, selectors.EVENT_READ, "stdout")
    selector.register(stderr_descriptor, selectors.EVENT_READ, "stderr")
    stdout_bytes = 0
    stderr = bytearray()
    returncode: int | None = None
    deadline = time.monotonic() + timeout_seconds
    try:
        while selector.get_map() or returncode is None:
            require(
                time.monotonic() < deadline,
                "sealed command exceeded time bound",
            )
            for key, _ in selector.select(0.05):
                encoded = os.read(key.fd, 64 * 1024)
                if not encoded:
                    selector.unregister(key.fd)
                    continue
                if key.data == "stdout":
                    stdout_bytes += len(encoded)
                    require(
                        stdout_bytes <= maximum,
                        "sealed stdout exceeded bound",
                    )
                    output.write(encoded)
                else:
                    require(
                        len(stderr) + len(encoded) <= maximum,
                        "sealed stderr exceeded bound",
                    )
                    stderr.extend(encoded)
            if returncode is None:
                returncode = poll()
        output.flush()
        return returncode, bytes(stderr)
    except BaseException:
        terminate()
        raise
    finally:
        selector.close()


def run_sealed(
    *,
    executable: Path,
    expected_sha256: str,
    expected_execution_identity: Mapping[str, str],
    arguments: Sequence[str],
    stdout: Any | None = None,
    inherited_descriptors: Sequence[int] = (),
    maximum: int = 32 * 1024 * 1024,
    timeout_seconds: int = 600,
    environment: Mapping[str, str] | None = None,
    on_spawn: Callable[[int], None] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    require(
        0 < maximum <= 1 << 34
        and 0 < timeout_seconds <= 24 * 60 * 60,
        "sealed execution bounds changed",
    )
    child_environment = (
        {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
        if environment is None
        else dict(environment)
    )
    require(
        bool(child_environment)
        and all(
            isinstance(key, str)
            and key
            and "=" not in key
            and "\0" not in key
            and isinstance(value, str)
            and "\0" not in value
            for key, value in child_environment.items()
        ),
        "sealed execution environment changed",
    )
    descriptor, opened = open_hashed_executable(executable, expected_sha256)
    execution_descriptor = -1
    owned_stdout = tempfile.TemporaryFile() if stdout is None else None
    output = owned_stdout if owned_stdout is not None else stdout
    stdout_read, stdout_write = os.pipe()
    stderr_read, stderr_write = os.pipe()
    try:
        require(output is not None, "sealed execution lacks stdout")
        system = platform.system()
        if system == "Linux":
            require(
                expected_execution_identity
                == execution_identity(
                    "linux-sealed-memfd-v1", expected_sha256
                ),
                "Linux sealed-execution identity changed",
            )
            execution_descriptor = sealed_copy_descriptor(
                descriptor, expected_sha256, executable=True
            )
            fd_path = f"/proc/self/fd/{execution_descriptor}"
            process = subprocess.Popen(
                [str(executable), *arguments],
                executable=fd_path,
                stdin=subprocess.DEVNULL,
                stdout=stdout_write,
                stderr=stderr_write,
                env=child_environment,
                pass_fds=(
                    execution_descriptor,
                    *inherited_descriptors,
                ),
                start_new_session=True,
            )
            try:
                if on_spawn is not None:
                    on_spawn(process.pid)
            except BaseException:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                raise
            os.close(stdout_write)
            stdout_write = -1
            os.close(stderr_write)
            stderr_write = -1

            def poll_linux() -> int | None:
                return process.poll()

            def terminate_linux() -> None:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                process.wait()

            returncode, stderr = drain_bounded_child(
                poll=poll_linux,
                terminate=terminate_linux,
                stdout_descriptor=stdout_read,
                stderr_descriptor=stderr_read,
                output=output,
                maximum=maximum,
                timeout_seconds=timeout_seconds,
            )
        elif system == "Darwin":
            require(
                set(expected_execution_identity) == {"mechanism", "cdhash"}
                and expected_execution_identity["mechanism"]
                == "darwin-suspended-cdhash-v1"
                and HEX40.fullmatch(expected_execution_identity["cdhash"])
                is not None,
                "Darwin sealed-execution identity changed",
            )
            child = darwin_spawn_suspended(
                executable=executable,
                arguments=arguments,
                expected_cdhash=expected_execution_identity["cdhash"],
                stdout_descriptor=stdout_write,
                stderr_descriptor=stderr_write,
                inherited_descriptors=inherited_descriptors,
                environment=child_environment,
            )
            try:
                if on_spawn is not None:
                    on_spawn(child)
            except BaseException:
                try:
                    os.killpg(child, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(child, 0)
                except ChildProcessError:
                    pass
                raise
            os.close(stdout_write)
            stdout_write = -1
            os.close(stderr_write)
            stderr_write = -1
            child_status: int | None = None

            def poll_darwin() -> int | None:
                nonlocal child_status
                if child_status is not None:
                    return os.waitstatus_to_exitcode(child_status)
                waited, status = os.waitpid(child, os.WNOHANG)
                if waited == child:
                    child_status = status
                    return os.waitstatus_to_exitcode(status)
                return None

            def terminate_darwin() -> None:
                nonlocal child_status
                if child_status is None:
                    try:
                        os.killpg(child, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        _, child_status = os.waitpid(child, 0)
                    except ChildProcessError:
                        child_status = 0

            returncode, stderr = drain_bounded_child(
                poll=poll_darwin,
                terminate=terminate_darwin,
                stdout_descriptor=stdout_read,
                stderr_descriptor=stderr_read,
                output=output,
                maximum=maximum,
                timeout_seconds=timeout_seconds,
            )
        else:
            raise Refusal("sealed execution requires Darwin or Linux")
        require(
            file_sha_fd(descriptor) == expected_sha256
            and (
                system != "Linux"
                or file_sha_fd(execution_descriptor) == expected_sha256
            )
            and (opened.st_dev, opened.st_ino)
            == (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino),
            "opened executable changed during sealed execution",
        )
        if owned_stdout is None:
            stdout_bytes = b""
        else:
            owned_stdout.seek(0)
            stdout_bytes = owned_stdout.read(maximum + 1)
            require(
                len(stdout_bytes) <= maximum,
                "sealed stdout exceeded bound",
            )
        return subprocess.CompletedProcess(
            [str(executable), *arguments],
            returncode,
            stdout_bytes,
            stderr,
        )
    finally:
        for pipe in (stdout_read, stdout_write, stderr_read, stderr_write):
            if pipe >= 0:
                os.close(pipe)
        if owned_stdout is not None:
            owned_stdout.close()
        if execution_descriptor >= 0:
            os.close(execution_descriptor)
        os.close(descriptor)


def run_checked_sealed(
    *,
    executable: Path,
    expected_sha256: str,
    expected_execution_identity: Mapping[str, str],
    arguments: Sequence[str],
    inherited_descriptors: Sequence[int] = (),
    maximum: int = 32 * 1024 * 1024,
    timeout_seconds: int = 600,
    environment: Mapping[str, str] | None = None,
    on_spawn: Callable[[int], None] | None = None,
) -> bytes:
    result = run_sealed(
        executable=executable,
        expected_sha256=expected_sha256,
        expected_execution_identity=expected_execution_identity,
        arguments=arguments,
        inherited_descriptors=inherited_descriptors,
        maximum=maximum,
        timeout_seconds=timeout_seconds,
        environment=environment,
        on_spawn=on_spawn,
    )
    require(result.returncode == 0, f"sealed command failed: {executable}")
    require(not result.stderr, f"sealed command wrote stderr: {executable}")
    require(
        0 < len(result.stdout) <= maximum,
        f"sealed command output changed: {executable}",
    )
    return result.stdout


def stable_linux_cpu_payload(encoded: bytes) -> dict[str, Any]:
    stable_fields = {
        "architecture",
        "cpu architecture",
        "cpu implementer",
        "cpu part",
        "cpu revision",
        "cpu variant",
        "features",
        "flags",
        "model",
        "model name",
        "vendor_id",
    }
    processors = 0
    identities: set[tuple[tuple[str, str], ...]] = set()
    for block in encoded.decode(errors="strict").strip().split("\n\n"):
        fields: dict[str, str] = {}
        for line in block.splitlines():
            key, separator, value = line.partition(":")
            if separator != ":":
                continue
            normalized = key.strip().lower()
            if normalized == "processor":
                processors += 1
            elif normalized in stable_fields:
                fields[normalized] = " ".join(value.split())
        if fields:
            identities.add(tuple(sorted(fields.items())))
    require(processors > 0 and bool(identities), "Linux CPU identity is incomplete")
    return {
        "logical_processors": processors,
        "identities": [dict(identity) for identity in sorted(identities)],
    }


def stable_darwin_cpu_payload(encoded: bytes) -> dict[str, Any]:
    exact_fields = {
        "hw.byteorder",
        "hw.cachelinesize",
        "hw.l1dcachesize",
        "hw.l1icachesize",
        "hw.l2cachesize",
        "hw.l3cachesize",
        "hw.logicalcpu",
        "hw.machine",
        "hw.model",
        "hw.ncpu",
        "hw.pagesize",
        "hw.physicalcpu",
        "machdep.cpu.brand_string",
    }
    fields: dict[str, str] = {}
    for line in encoded.decode(errors="strict").splitlines():
        key, separator, value = line.partition(":")
        if separator != ":":
            continue
        key = key.strip()
        if key in exact_fields or key.startswith("hw.optional."):
            fields[key] = " ".join(value.split())
    require(
        fields.get("hw.machine") == "arm64"
        and "hw.model" in fields
        and "hw.ncpu" in fields,
        "Darwin CPU identity is incomplete",
    )
    return fields


def host_receipts(platform_label: str) -> dict[str, str]:
    uname = platform.uname()
    host = {
        "platform_label": platform_label,
        "system": uname.system,
        "node": uname.node,
        "machine": uname.machine,
    }
    kernel = {
        "system": uname.system,
        "release": uname.release,
        "version": uname.version,
    }
    if Path("/proc/cpuinfo").is_file():
        cpu_payload = stable_linux_cpu_payload(
            regular_file(Path("/proc/cpuinfo"), 4 * 1024 * 1024)
        )
    else:
        exact = run_checked(
            [
                "/usr/sbin/sysctl",
                "hw.machine",
                "hw.model",
                "hw.ncpu",
                "hw.physicalcpu",
                "hw.logicalcpu",
                "hw.byteorder",
                "hw.pagesize",
                "hw.cachelinesize",
                "hw.l1icachesize",
                "hw.l1dcachesize",
                "hw.l2cachesize",
                "hw.l3cachesize",
                "machdep.cpu.brand_string",
            ],
            maximum=64 * 1024,
        )
        cpu_payload = stable_darwin_cpu_payload(
            exact
            + run_checked(
                ["/usr/sbin/sysctl", "-a"], maximum=16 * 1024 * 1024
            )
        )
    return {
        "host_identity_sha256": canonical_sha(host),
        "cpu_identity_sha256": canonical_sha(cpu_payload),
        "kernel_identity_sha256": canonical_sha(kernel),
    }


def object_receipts(
    build_receipt: Mapping[str, Any],
    out_dir: Path,
    candidate_manifest: Mapping[str, Any],
) -> dict[str, str]:
    candidates = build_receipt["candidates"]
    require(isinstance(candidates, list) and bool(candidates), "empty object receipt")
    manifest_payload = candidate_manifest.get("payload")
    require(
        isinstance(manifest_payload, dict)
        and isinstance(manifest_payload.get("candidates"), list)
        and len(manifest_payload["candidates"]) == len(candidates),
        "object-candidate manifest differs from build receipt",
    )
    object_rows = []
    payload_rows = []
    compile_rows = []
    for index, (candidate, projected) in enumerate(
        zip(candidates, manifest_payload["candidates"], strict=True)
    ):
        require(
            isinstance(candidate, dict)
            and set(candidate)
            == {
                "semantic_candidate_sha256",
                "literal_hex",
                "compile_identity",
                "implementation_sha256",
                "glue_sha256",
            },
            "candidate build receipt fields changed",
        )
        require(
            isinstance(projected, dict)
            and candidate["semantic_candidate_sha256"]
            == projected.get("semantic_candidate_sha256")
            and candidate["literal_hex"] == projected.get("literal_hex"),
            "built candidate differs from exact source-only projection",
        )
        implementation = resolve_regular(
            out_dir, f"external-search-{index}-implementation.o"
        )
        glue = resolve_regular(out_dir, f"external-search-{index}-family-glue.o")
        require(
            file_sha(implementation) == candidate["implementation_sha256"]
            and file_sha(glue) == candidate["glue_sha256"]
            and HEX64.fullmatch(candidate["compile_identity"]) is not None,
            "candidate object/compile receipt changed",
        )
        object_rows.append(candidate)
        payload_rows.append(candidate["implementation_sha256"])
        compile_rows.append(candidate["compile_identity"])
    return {
        "object_set_identity_sha256": canonical_sha(object_rows),
        "static_payload_identity_sha256": canonical_sha(payload_rows),
        "compiler_receipt_set_identity_sha256": canonical_sha(compile_rows),
    }


def artifact_file_path(
    deployment: Mapping[str, Any],
    field: str,
    roots: Mapping[str, Path],
) -> Path:
    descriptor = deployment["artifact_files"][field]
    require(
        isinstance(descriptor, dict)
        and set(descriptor) == {"root", "path"}
        and descriptor["root"] in roots,
        f"artifact descriptor changed: {field}",
    )
    return resolve_regular(roots[descriptor["root"]], descriptor["path"])


def validate_link_closure(
    *,
    path: Path,
    scope: str,
    platform_label: str,
    deployment: Mapping[str, Any],
    artifact_paths: Mapping[str, Path],
    derived: Mapping[str, str],
    binary_path: Path,
    binary_sha256: str,
    link_map: Path,
    link_map_sha256: str,
    build_receipt: Mapping[str, Any],
) -> str:
    receipt, receipt_sha256 = load_envelope(
        path, LINK_CLOSURE_SCHEMA, 32 * 1024 * 1024
    )
    payload = receipt["payload"]
    require(set(payload) == LINK_CLOSURE_FIELDS, "link closure fields changed")
    arguments = payload["arguments"]
    inputs = payload["inputs"]
    require(
        payload["scope"] == scope
        and payload["platform"] == platform_label
        and payload["real_linker_sha256"] == derived["linker_identity_sha256"]
        and payload["linker_wrapper_sha256"]
        == deployment["linker_wrapper_sha256"]
        and Path(payload["output_path"]).resolve(strict=True)
        == binary_path.resolve(strict=True)
        and payload["output_sha256"] == binary_sha256
        and Path(payload["link_map_path"]).resolve(strict=True)
        == link_map.resolve(strict=True)
        and payload["link_map_sha256"] == link_map_sha256
        and isinstance(arguments, list)
        and bool(arguments)
        and all(isinstance(argument, str) and argument for argument in arguments)
        and not any(argument.startswith("@") for argument in arguments)
        and canonical_sha(arguments) == payload["arguments_sha256"]
        and isinstance(inputs, list)
        and bool(inputs),
        "link closure header differs from final image",
    )
    input_rows: dict[tuple[str, str], str] = {}
    for row in inputs:
        require(
            isinstance(row, dict)
            and set(row) == {"role", "path", "sha256"}
            and isinstance(row["role"], str)
            and isinstance(row["path"], str)
            and HEX64.fullmatch(row["sha256"]) is not None,
            "link input receipt changed",
        )
        input_path = Path(row["path"]).resolve(strict=True)
        require(
            any(str(input_path) in argument for argument in arguments),
            "claimed link input is absent from actual invocation",
        )
        require(file_sha(input_path) == row["sha256"], "linked input changed")
        key = (row["role"], row["sha256"])
        require(key not in input_rows, "linked input receipt is duplicated")
        input_rows[key] = str(input_path)
    required = {
        ("runtime", derived["runtime_artifact_identity_sha256"]),
        ("public-facade", derived["public_facade_artifact_identity_sha256"]),
    }
    for candidate in build_receipt["candidates"]:
        required.add(("external-implementation", candidate["implementation_sha256"]))
        required.add(("external-glue", candidate["glue_sha256"]))
    require(
        required <= set(input_rows),
        "final link invocation omits a required static artifact",
    )
    require(
        any(str(link_map.resolve(strict=True)) in argument for argument in arguments),
        "actual link invocation omits the authenticated link map",
    )
    require(
        file_sha(artifact_paths["linker_identity_sha256"])
        == payload["real_linker_sha256"],
        "actual linker differs from link receipt",
    )
    return receipt_sha256


def validate_build_closure(
    *,
    path: Path,
    scope: str,
    platform_label: str,
    repo: Path,
    policy: Any,
    identity: Mapping[str, Any],
    identity_sha256: str,
    candidate_manifest_sha256: str,
    build_sha256: str,
    binary_sha256: str,
    link_map_sha256: str,
    link_invocation_sha256: str,
    artifact_paths: Mapping[str, Path],
    derived: Mapping[str, str],
) -> None:
    receipt, _ = load_envelope(path, BUILD_CLOSURE_SCHEMA, 8 * 1024 * 1024)
    payload = receipt["payload"]
    require(set(payload) == BUILD_CLOSURE_FIELDS, "build closure fields changed")
    command = payload["command"]
    environment = payload["environment"]
    require(
        payload["scope"] == scope
        and payload["platform"] == platform_label
        and payload["repo_revision"] == identity["runner"]["source_commit"]
        and payload["runner_source_sha256"] == derived["runner_source_sha256"]
        and payload["policy_source_sha256"]
        == file_sha(Path(policy.__file__).resolve(), 2 * 1024 * 1024)
        and payload["identity_sha256"] == identity_sha256
        and payload["candidate_manifest_sha256"] == candidate_manifest_sha256
        and payload["build_receipt_sha256"] == build_sha256
        and payload["binary_sha256"] == binary_sha256
        and payload["link_map_sha256"] == link_map_sha256
        and payload["link_invocation_sha256"] == link_invocation_sha256
        and payload["compiler_binary_sha256"]
        == derived["compiler_binary_identity_sha256"]
        and payload["linker_sha256"] == derived["linker_identity_sha256"]
        and payload["target_spec_sha256"] == derived["target_spec_identity_sha256"]
        and payload["build_environment_sha256"]
        == derived["build_environment_identity_sha256"]
        and payload["dependency_lock_sha256"]
        == derived["dependency_lock_identity_sha256"]
        and payload["runtime_artifact_sha256"]
        == derived["runtime_artifact_identity_sha256"]
        and payload["public_facade_artifact_sha256"]
        == derived["public_facade_artifact_identity_sha256"]
        and isinstance(command, list)
        and len(command) >= 3
        and command[1:3] == ["build", "--locked"]
        and "--release" in command
        and "--offline" in command
        and isinstance(environment, dict)
        and environment.get("FRE_EXTERNAL_SEARCH_STATIC_IDENTITY")
        and environment.get("FRE_EXTERNAL_SEARCH_OBJECT_CANDIDATE_MANIFEST")
        and environment.get("FRE_EXTERNAL_SEARCH_RUNNER_REVISION")
        == identity["runner"]["source_commit"],
        "build closure differs from exact construction",
    )
    for field, receipt_field in (
        ("compiler_binary_identity_sha256", "compiler_binary_sha256"),
        ("target_spec_identity_sha256", "target_spec_sha256"),
        ("build_environment_identity_sha256", "build_environment_sha256"),
        ("dependency_lock_identity_sha256", "dependency_lock_sha256"),
        ("runtime_artifact_identity_sha256", "runtime_artifact_sha256"),
        ("public_facade_artifact_identity_sha256", "public_facade_artifact_sha256"),
    ):
        require(
            file_sha(artifact_paths[field]) == payload[receipt_field],
            f"build closure artifact changed: {field}",
        )
    static_runner_lock = static_runner_dependency_lock(repo)
    require(
        static_runner_lock
        == artifact_paths["dependency_lock_identity_sha256"].resolve(
            strict=True
        ),
        "build closure does not bind the static runner dependency lock",
    )


def static_runner_dependency_lock(repo: Path) -> Path:
    return (
        repo
        / "research"
        / "aot"
        / "external-regex-1.12.4"
        / "static-runner"
        / "Cargo.lock"
    ).resolve(strict=True)


def load_spec_deployment(
    *,
    spec_path: Path,
    expected_spec_sha256: str,
    policy: Any,
    scope: str,
    platform_label: str,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    spec, spec_sha256 = load_envelope(spec_path, SPEC_SCHEMA)
    require(spec_sha256 == expected_spec_sha256, "deployment spec identity changed")
    payload = spec["payload"]
    require(
        payload["policy_source_sha256"]
        == file_sha(Path(policy.__file__).resolve(), 2 * 1024 * 1024),
        "evidence policy source changed",
    )
    require(
        scope in payload["deployments"]
        and platform_label in payload["deployments"][scope],
        "deployment scope/platform is not preregistered",
    )
    deployment = payload["deployments"][scope][platform_label]
    require(
        set(deployment["expected_authority"]) == set(policy.AUTHORITY_FIELDS),
        "expected authority fields changed",
    )
    expected_mechanism = (
        "darwin-suspended-cdhash-v1"
        if deployment["platform_key"] == "macos_aarch64"
        else "linux-sealed-memfd-v1"
    )
    execution_identities = deployment["execution_identities"]
    require(
        set(execution_identities) == {"binary", "nm"}
        and execution_identities["binary"]["mechanism"]
        == expected_mechanism
        and execution_identities["nm"]["mechanism"] == expected_mechanism
        and HEX64.fullmatch(deployment["nm_sha256"]) is not None,
        "sealed-execution deployment identity changed",
    )
    shard_limits = deployment["shard_limits"]
    require(
        set(shard_limits) == {"maximum_output_bytes", "timeout_seconds"}
        and isinstance(shard_limits["maximum_output_bytes"], int)
        and 0 < shard_limits["maximum_output_bytes"] <= 1 << 34
        and isinstance(shard_limits["timeout_seconds"], int)
        and 0 < shard_limits["timeout_seconds"] <= 24 * 60 * 60,
        "shard execution bounds changed",
    )
    return payload, deployment, spec_sha256


def derive_authority(
    *,
    policy: Any,
    expected_spec_sha256: str,
    spec_path: Path,
    scope: str,
    platform_label: str,
    repo: Path,
    identity_path: Path,
    candidate_manifest_path: Path,
    build_receipt_path: Path,
    binary_path: Path,
    target: Path,
    closure: Path,
    fixture_root: Path,
) -> tuple[dict[str, Any], dict[str, str]]:
    payload, deployment, spec_sha256 = load_spec_deployment(
        spec_path=spec_path,
        expected_spec_sha256=expected_spec_sha256,
        policy=policy,
        scope=scope,
        platform_label=platform_label,
    )
    expected = deployment["expected_authority"]
    fixture_manifest = fixture_root.resolve(strict=True) / "manifest.json"
    require(
        file_sha(fixture_manifest, 2 * 1024 * 1024)
        == deployment["fixture_manifest_sha256"],
        "fixture manifest changed",
    )
    identity_bytes = regular_file(identity_path, 2 * 1024 * 1024)
    identity = json.loads(identity_bytes)
    identity_sha256 = hashlib.sha256(identity_bytes).hexdigest()
    require(
        identity_sha256 == deployment["identity_sha256"],
        "runner identity changed",
    )
    build_bytes = regular_file(build_receipt_path, 8 * 1024 * 1024)
    build_receipt = json.loads(build_bytes)
    build_sha256 = hashlib.sha256(build_bytes).hexdigest()
    candidate_manifest_bytes = regular_file(
        candidate_manifest_path, 8 * 1024 * 1024
    )
    candidate_manifest = json.loads(candidate_manifest_bytes)
    candidate_manifest_sha256 = hashlib.sha256(candidate_manifest_bytes).hexdigest()
    expected_target_os = {
        "macos_aarch64": "macos",
        "linux_aarch64": "linux",
    }[deployment["platform_key"]]
    require(
        build_sha256 == deployment["build_receipt_sha256"]
        and set(build_receipt) == BUILD_RECEIPT_FIELDS
        and build_receipt["schema"]
        == "fre.aot.external-regex-1.12.4-static-runner-build-receipt.v1"
        and build_receipt["identity_sha256"] == identity_sha256
        and build_receipt["runner_revision"] == identity["runner"]["source_commit"]
        and build_receipt["runner_source_sha256"]
        == identity["runner"]["source_set_sha256"]
        and build_receipt["backend_tag"] == identity["static_pipeline"]["backend_tag"]
        and build_receipt["backend_name"] == identity["static_pipeline"]["backend_name"]
        and build_receipt["target_os"] == expected_target_os
        and build_receipt["target_arch"] == "aarch64"
        and build_receipt["compiler_identity"]
        == identity["static_pipeline"]["compiler_identity"]
        and build_receipt["family_selector"]
        == identity["auto_routing"]["family_selector"]
        and build_receipt["minimum_window_bytes"]
        == identity["auto_routing"]["minimum_window_bytes"]
        and build_receipt["portable_prefix_candidate_starts"]
        == identity["auto_routing"]["portable_prefix_candidate_starts"]
        and build_receipt["plan_identity"] == identity["auto_routing"]["plan_identity"]
        and build_receipt["analyzer_identity"]
        == identity["auto_routing"]["analyzer_identity"]
        and build_receipt["evidence_identity"]
        == identity["auto_routing"]["evidence_identity"]
        and build_receipt["manifest_identity"]
        == identity["platform_artifacts"][deployment["platform_key"]][
            "manifest_identity"
        ]
        and build_receipt["object_candidate_manifest_sha256"]
        == identity["object_candidates"]["manifest_sha256"]
        and candidate_manifest_sha256
        == build_receipt["object_candidate_manifest_sha256"]
        and candidate_manifest_sha256 == deployment["candidate_manifest_sha256"]
        and candidate_manifest["schema"]
        == build_receipt["object_candidate_manifest_schema"]
        and canonical_sha(candidate_manifest["payload"])
        == candidate_manifest["payload_sha256"]
        and candidate_manifest["payload"]["candidate_count"]
        == build_receipt["object_candidate_count"]
        and build_receipt["fixture_manifest_schema"]
        == identity["external_evidence"]["fixture_manifest_schema"]
        and build_receipt["fixture_manifest_sha256"]
        == identity["external_evidence"]["fixture_manifest_sha256"]
        and build_receipt["fixture_manifest_sha256"]
        == deployment["fixture_manifest_sha256"]
        and build_receipt["canonical_byte_escaped_sources"] is True
        and identity["object_candidates"]["source_construction"]
        == "canonical-byte-escaped-exact"
        and build_receipt["object_candidate_count"]
        == identity["object_candidates"]["candidate_count"]
        and len(build_receipt["candidates"])
        == build_receipt["object_candidate_count"]
        and build_receipt["timing_permitted"] is True,
        "build receipt and sealed identity differ",
    )
    build_out = build_receipt_path.parent
    derived = object_receipts(build_receipt, build_out, candidate_manifest)
    link_map = resolve_regular(build_out, "linked-image.map", 64 * 1024 * 1024)
    link_map_sha256 = file_sha(link_map, 64 * 1024 * 1024)
    require(
        link_map_sha256 == deployment["link_map_sha256"],
        "final-image link map changed",
    )
    binary_sha256 = file_sha(binary_path)
    require(binary_sha256 == deployment["binary_sha256"], "runner binary changed")
    roots = {
        "repo": repo.resolve(strict=True),
        "target": target.resolve(strict=True),
        "closure": closure.resolve(strict=True),
        "build_out": build_out.resolve(strict=True),
    }
    require(
        set(deployment["artifact_files"]) == FILE_AUTHORITY_FIELDS,
        "deployment artifact closure fields changed",
    )
    for field in SOURCE_AUTHORITY_FIELDS:
        derived[field] = source_set_sha(
            roots["repo"],
            payload["source_sets"][field],
            f"FRE-STATIC-SEALER-{field}",
        )
    artifact_paths = {
        field: artifact_file_path(deployment, field, roots)
        for field in FILE_AUTHORITY_FIELDS
    }
    for field, path in artifact_paths.items():
        derived[field] = file_sha(path)
    for field in CANONICAL_AUTHORITY_FIELDS:
        derived[field] = canonical_sha(deployment["canonical_authority"][field])
    derived.update(
        {
            "runner_identity_sha256": identity_sha256,
            "runner_source_sha256": runner_source_sha(roots["repo"]),
            "runner_binary_identity_sha256": binary_sha256,
            "backend_policy_identity_sha256": policy.BACKEND_POLICY_IDENTITY_SHA256,
            "aot_wire_contract_identity_sha256": (
                policy.AOT_WIRE_CONTRACT_IDENTITY_SHA256
            ),
            "linked_artifact_identity_sha256": binary_sha256,
            "public_facade_route_identity_sha256": (
                policy.PUBLIC_FACADE_ROUTE_IDENTITY_SHA256
            ),
        }
    )
    require(
        derived["runner_source_sha256"] == build_receipt["runner_source_sha256"],
        "runner source set differs from build receipt",
    )
    nm_path = resolve_regular(
        roots[deployment["nm"]["root"]], deployment["nm"]["path"]
    )
    nm_sha256 = file_sha(nm_path)
    require(nm_sha256 == deployment["nm_sha256"], "nm executable changed")
    binary_descriptor = open_sealed_input(binary_path, binary_sha256)
    try:
        binary_descriptor_path = (
            f"/dev/fd/{binary_descriptor}"
            if platform.system() == "Darwin"
            else f"/proc/self/fd/{binary_descriptor}"
        )
        symbols = run_checked_sealed(
            executable=nm_path,
            expected_sha256=nm_sha256,
            expected_execution_identity=deployment[
                "execution_identities"
            ]["nm"],
            arguments=["-g", binary_descriptor_path],
            inherited_descriptors=(binary_descriptor,),
        )
        require(
            file_sha_fd(binary_descriptor) == binary_sha256,
            "binary changed during sealed symbol inspection",
        )
    finally:
        os.close(binary_descriptor)
    derived["symbol_receipt_identity_sha256"] = hashlib.sha256(symbols).hexdigest()
    inspect = run_checked_sealed(
        executable=binary_path,
        expected_sha256=binary_sha256,
        expected_execution_identity=deployment["execution_identities"][
            "binary"
        ],
        arguments=["inspect", str(fixture_root)],
    )
    inspect_fields = parse_inspect(inspect)
    require(
        inspect_fields["linked"] == "true"
        and inspect_fields["timing_permitted"] == "true"
        and inspect_fields["identity_sha256"] == identity_sha256
        and inspect_fields["runner_source_sha256"]
        == derived["runner_source_sha256"]
        and inspect_fields["backend"]
        == f"{build_receipt['backend_name']} tag={build_receipt['backend_tag']}"
        and inspect_fields["family_selector"] == str(build_receipt["family_selector"])
        and inspect_fields["object_candidate_manifest_sha256"]
        == build_receipt["object_candidate_manifest_sha256"]
        and inspect_fields["linked_object_candidates"]
        == str(build_receipt["object_candidate_count"])
        and inspect_fields["candidates"]
        == str(identity["external_evidence"]["candidate_count"])
        and inspect_fields["fixtures"]
        == str(identity["external_evidence"]["fixture_count"])
        and inspect_fields["correctness"] == "pass",
        "inspect receipt differs from build/identity",
    )
    derived["facade_adoption_receipt_identity_sha256"] = hashlib.sha256(
        inspect
    ).hexdigest()
    link_invocation_sha256 = validate_link_closure(
        path=artifact_paths["link_invocation_identity_sha256"],
        scope=scope,
        platform_label=platform_label,
        deployment=deployment,
        artifact_paths=artifact_paths,
        derived=derived,
        binary_path=binary_path,
        binary_sha256=binary_sha256,
        link_map=link_map,
        link_map_sha256=link_map_sha256,
        build_receipt=build_receipt,
    )
    require(
        link_invocation_sha256 == derived["link_invocation_identity_sha256"],
        "link invocation receipt identity changed",
    )
    validate_build_closure(
        path=artifact_paths["compiler_invocation_identity_sha256"],
        scope=scope,
        platform_label=platform_label,
        repo=roots["repo"],
        policy=policy,
        identity=identity,
        identity_sha256=identity_sha256,
        candidate_manifest_sha256=candidate_manifest_sha256,
        build_sha256=build_sha256,
        binary_sha256=binary_sha256,
        link_map_sha256=link_map_sha256,
        link_invocation_sha256=link_invocation_sha256,
        artifact_paths=artifact_paths,
        derived=derived,
    )
    derived.update(host_receipts(platform_label))
    derived["deployment_bundle_identity_sha256"] = canonical_sha(
        {
            "scope": scope,
            "platform": platform_label,
            "identity_sha256": identity_sha256,
            "build_receipt_sha256": build_sha256,
            "candidate_manifest_sha256": candidate_manifest_sha256,
            "link_map_sha256": link_map_sha256,
            "nm_sha256": nm_sha256,
            "execution_identities": deployment["execution_identities"],
            "shard_limits": deployment["shard_limits"],
            "fixture_manifest_sha256": deployment["fixture_manifest_sha256"],
            "binary_sha256": binary_sha256,
            "inspect_sha256": derived[
                "facade_adoption_receipt_identity_sha256"
            ],
            "symbols_sha256": derived["symbol_receipt_identity_sha256"],
            "derived_authority": derived,
        }
    )
    authority = {
        "platform": platform_label,
        **derived,
        "host_isa_capabilities": deployment["host_isa_capabilities"],
        "target_isa_policy": payload["target_isa_policy"],
        "backend_name": build_receipt["backend_name"],
        "backend_tag": str(build_receipt["backend_tag"]),
        "construction_timed": "false",
        "publication_timed": "false",
        "link_adoption_timed": "false",
        "jit_publication": "false",
        "dynamic_code_generation": "false",
    }
    authority["production_family_authority_sha256"] = policy.canonical_sha(
        policy.production_authority_payload(authority)
    )
    require(
        set(authority) == set(policy.AUTHORITY_FIELDS),
        "derived authority fields changed",
    )
    policy.validate_identity_row(platform_label, authority, "sealer")
    require(authority == expected, "derived authority differs from frozen spec")
    closure_payload = {
        "deployment_spec_sha256": spec_sha256,
        "scope": scope,
        "platform": platform_label,
        "authority": authority,
        "fixture_manifest_sha256": deployment["fixture_manifest_sha256"],
        "identity_sha256": identity_sha256,
        "build_receipt_sha256": build_sha256,
        "candidate_manifest_sha256": candidate_manifest_sha256,
        "link_map_sha256": link_map_sha256,
        "binary_path": str(binary_path.resolve(strict=True)),
        "binary_sha256": binary_sha256,
        "fixture_root": str(fixture_root.resolve(strict=True)),
        "inspect_sha256": hashlib.sha256(inspect).hexdigest(),
        "symbol_receipt_sha256": hashlib.sha256(symbols).hexdigest(),
        "binary_execution_identity": deployment["execution_identities"][
            "binary"
        ],
        "shard_limits": deployment["shard_limits"],
    }
    return closure_payload, authority


def seal_authority(output: Path, **arguments: Any) -> str:
    payload, _ = derive_authority(**arguments)
    return write_envelope(output, AUTHORITY_RECEIPT_SCHEMA, payload)


def load_authority_receipt(
    path: Path,
    spec_path: Path,
    expected_spec_sha256: str,
    policy: Any,
) -> tuple[dict[str, Any], str]:
    receipt, receipt_sha256 = load_envelope(
        path, AUTHORITY_RECEIPT_SCHEMA, 8 * 1024 * 1024
    )
    payload = receipt["payload"]
    require(
        set(payload)
        == {
            "deployment_spec_sha256",
            "scope",
            "platform",
            "authority",
            "fixture_manifest_sha256",
            "identity_sha256",
            "build_receipt_sha256",
            "candidate_manifest_sha256",
            "link_map_sha256",
            "binary_path",
            "binary_sha256",
            "fixture_root",
            "inspect_sha256",
            "symbol_receipt_sha256",
            "binary_execution_identity",
            "shard_limits",
        }
        and payload["deployment_spec_sha256"] == expected_spec_sha256,
        "authority receipt uses another deployment spec",
    )
    _, deployment, _ = load_spec_deployment(
        spec_path=spec_path,
        expected_spec_sha256=expected_spec_sha256,
        policy=policy,
        scope=payload["scope"],
        platform_label=payload["platform"],
    )
    expected_authority = deployment["expected_authority"]
    require(
        payload["authority"] == expected_authority
        and payload["fixture_manifest_sha256"]
        == deployment["fixture_manifest_sha256"]
        and payload["identity_sha256"] == deployment["identity_sha256"]
        and payload["build_receipt_sha256"]
        == deployment["build_receipt_sha256"]
        and payload["candidate_manifest_sha256"]
        == deployment["candidate_manifest_sha256"]
        and payload["link_map_sha256"] == deployment["link_map_sha256"]
        and payload["binary_sha256"] == deployment["binary_sha256"]
        and payload["identity_sha256"]
        == expected_authority["runner_identity_sha256"]
        and payload["binary_sha256"]
        == expected_authority["runner_binary_identity_sha256"]
        == expected_authority["linked_artifact_identity_sha256"]
        and payload["inspect_sha256"]
        == expected_authority["facade_adoption_receipt_identity_sha256"]
        and payload["symbol_receipt_sha256"]
        == expected_authority["symbol_receipt_identity_sha256"]
        and payload["binary_execution_identity"]
        == deployment["execution_identities"]["binary"]
        and payload["shard_limits"] == deployment["shard_limits"],
        "authority receipt differs from preregistered deployment",
    )
    policy.validate_identity_row(
        payload["platform"], payload["authority"], "authority receipt"
    )
    return receipt, receipt_sha256


def parse_uint(value: str, label: str) -> int:
    require(CANONICAL_UINT.fullmatch(value) is not None, f"{label} is not canonical")
    return int(value)


def run_shard(
    *,
    policy: Any,
    spec_path: Path,
    expected_spec_sha256: str,
    authority_receipt_path: Path,
    shard: str,
    shards: str,
    raw_output: Path,
    shard_receipt_output: Path,
) -> str:
    authority_receipt, authority_receipt_sha256 = load_authority_receipt(
        authority_receipt_path, spec_path, expected_spec_sha256, policy
    )
    require(
        not raw_output.exists() and not shard_receipt_output.exists(),
        "shard outputs already exist",
    )
    authority = authority_receipt["payload"]
    shard_number = parse_uint(shard, "shard")
    shard_count = parse_uint(shards, "shards")
    require(
        shard_count > 0 and shard_number < shard_count,
        "invalid shard coordinates",
    )
    binary = Path(authority["binary_path"])
    fixture_root = Path(authority["fixture_root"])
    require(
        file_sha(binary) == authority["binary_sha256"]
        and file_sha(fixture_root / "manifest.json", 2 * 1024 * 1024)
        == authority["fixture_manifest_sha256"],
        "binary or fixture changed before shard launch",
    )
    live_host = host_receipts(authority["platform"])
    for field, value in live_host.items():
        require(
            authority["authority"][field] == value,
            f"live host changed before shard launch: {field}",
        )
    raw_output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{raw_output.name}.", dir=raw_output.parent
    )
    binary_before = authority["binary_sha256"]
    try:
        with os.fdopen(descriptor, "wb") as output:
            result = run_sealed(
                executable=binary,
                expected_sha256=authority["binary_sha256"],
                expected_execution_identity=authority[
                    "binary_execution_identity"
                ],
                arguments=[
                    "run",
                    str(fixture_root),
                    str(shard_number),
                    str(shard_count),
                ],
                stdout=output,
                maximum=authority["shard_limits"]["maximum_output_bytes"],
                timeout_seconds=authority["shard_limits"][
                    "timeout_seconds"
                ],
            )
            output.flush()
            os.fsync(output.fileno())
        require(result.returncode == 0, "runner shard failed")
        require(not result.stderr, "runner shard wrote stderr")
        binary_after = authority["binary_sha256"]
        require(
            file_sha(authority_receipt_path, 8 * 1024 * 1024)
            == authority_receipt_sha256,
            "authority receipt changed during shard execution",
        )
        raw_sha256 = file_sha(Path(temporary), 1 << 34)
        os.replace(temporary, raw_output)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    payload = {
        "deployment_spec_sha256": expected_spec_sha256,
        "authority_receipt_path": str(authority_receipt_path.resolve(strict=True)),
        "authority_receipt_sha256": authority_receipt_sha256,
        "scope": authority["scope"],
        "platform": authority["platform"],
        "fixture_manifest_sha256": authority["fixture_manifest_sha256"],
        "binary_sha256_before": binary_before,
        "binary_sha256_after": binary_after,
        "shard": shard_number,
        "shards": shard_count,
        "raw_path": str(raw_output.resolve(strict=True)),
        "raw_sha256": raw_sha256,
    }
    return write_envelope(shard_receipt_output, SHARD_RECEIPT_SCHEMA, payload)


def authenticate_shard_receipts(
    paths: Sequence[Path],
    spec_path: Path,
    expected_spec_sha256: str,
    policy: Any,
) -> tuple[dict[str, Any], list[Path]]:
    require(bool(paths), "no shard receipts")
    common_authority: dict[str, Any] | None = None
    shard_count: int | None = None
    coordinates: set[int] = set()
    raw_paths: list[Path] = []
    unique_raw_paths: set[Path] = set()
    for path in paths:
        receipt, _ = load_envelope(path, SHARD_RECEIPT_SCHEMA, 2 * 1024 * 1024)
        payload = receipt["payload"]
        require(
            set(payload) == SHARD_PAYLOAD_FIELDS
            and payload["deployment_spec_sha256"] == expected_spec_sha256
            and isinstance(payload["shards"], int)
            and payload["shards"] > 0,
            "shard receipt uses another deployment spec",
        )
        authority_path = Path(payload["authority_receipt_path"])
        authority_receipt, authority_sha256 = load_authority_receipt(
            authority_path, spec_path, expected_spec_sha256, policy
        )
        require(
            authority_sha256 == payload["authority_receipt_sha256"],
            "shard authority receipt changed",
        )
        authority = authority_receipt["payload"]
        if common_authority is None:
            common_authority = authority
            shard_count = payload["shards"]
        require(
            authority == common_authority
            and payload["scope"] == authority["scope"]
            and payload["platform"] == authority["platform"]
            and payload["fixture_manifest_sha256"]
            == authority["fixture_manifest_sha256"]
            and payload["shards"] == shard_count
            and payload["binary_sha256_before"] == authority["binary_sha256"]
            and payload["binary_sha256_after"] == authority["binary_sha256"],
            "shard receipt closure differs",
        )
        coordinate = payload["shard"]
        require(
            isinstance(coordinate, int)
            and 0 <= coordinate < payload["shards"]
            and coordinate not in coordinates,
            "shard coordinate is invalid or duplicated",
        )
        coordinates.add(coordinate)
        raw_path = Path(payload["raw_path"]).resolve(strict=True)
        require(raw_path not in unique_raw_paths, "raw shard path is duplicated")
        unique_raw_paths.add(raw_path)
        require(file_sha(raw_path, 1 << 34) == payload["raw_sha256"], "raw CSV changed")
        raw_paths.append(raw_path)
    require(
        shard_count is not None
        and coordinates == set(range(shard_count)),
        "shard receipt set is incomplete",
    )
    assert common_authority is not None
    return common_authority, raw_paths
