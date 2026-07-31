#!/bin/bash

# Shared fail-closed helpers for the C5 qualification tools. Callers enable
# errexit, nounset, and pipefail before sourcing this file.

fre_c5_die() {
    printf 'c5-qualification: %s\n' "$*" >&2
    exit 1
}

fre_c5_require_hex() {
    local value=$1
    local digits=$2
    local label=$3
    [[ ${#value} -eq $digits && $value != *[!0-9a-f]* ]] ||
        fre_c5_die "$label must be exactly $digits lowercase hexadecimal digits"
}

fre_c5_require_nonzero_sha256() {
    local value=$1
    local label=$2
    fre_c5_require_hex "$value" 64 "$label"
    [[ $value != 0000000000000000000000000000000000000000000000000000000000000000 ]] ||
        fre_c5_die "$label must not be zero"
}

fre_c5_require_bounded_positive_decimal() {
    local value=$1
    local maximum=$2
    local label=$3
    [[ $maximum =~ ^[1-9][0-9]*$ ]] ||
        fre_c5_die "internal maximum is invalid for $label"
    [[ $value =~ ^[1-9][0-9]*$ &&
        ${#value} -le ${#maximum} ]] ||
        fre_c5_die "$label must be a positive decimal at most $maximum"
    if [[ ${#value} -eq ${#maximum} && $value -gt $maximum ]]; then
        fre_c5_die "$label must be a positive decimal at most $maximum"
    fi
}

fre_c5_sha256() {
    /usr/bin/shasum -a 256 -- "$1" | /usr/bin/awk '{ print $1 }'
}

fre_c5_physical_closure_fingerprint() {
    local closure_kind=$1
    local root=$2
    /usr/bin/env -i \
        LC_ALL=C \
        TZ=UTC \
        PATH=/usr/bin:/bin \
        /usr/bin/python3 -I -B - "$closure_kind" "$root" <<'PY'
import hashlib
import os
import stat
import sys

kind = sys.argv[1]
root = os.fsencode(sys.argv[2])
digest = hashlib.sha256()
if kind == "rust-toolchain-v2":
    label = "toolchain"
    digest.update(b"FRE-RUST-TOOLCHAIN-CLOSURE\0\x02")
    maximum_entries = 16_384
elif kind == "cargo-registry-v1":
    label = "Cargo registry"
    digest.update(b"FRE-CARGO-REGISTRY-CLOSURE\0\x01")
    maximum_entries = 100_000
else:
    raise SystemExit("unknown physical closure kind")
maximum_depth = 64
maximum_path_bytes = 4_096
maximum_file_bytes = 1_073_741_824
maximum_total_file_bytes = 4_294_967_296
entry_count = 1
total_file_bytes = 0

if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
    raise SystemExit("closure fingerprinting requires O_NOFOLLOW and O_DIRECTORY")


def add(value: bytes) -> None:
    digest.update(len(value).to_bytes(8, "big"))
    digest.update(value)


def identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def require_same(
    before: os.stat_result,
    after: os.stat_result,
    description: str,
) -> None:
    if identity(before) != identity(after):
        raise SystemExit(f"{label} {description} changed during fingerprint")


def visit(directory_fd: int, relative: bytes) -> None:
    global entry_count, total_file_bytes
    directory_before = os.fstat(directory_fd)
    if not stat.S_ISDIR(directory_before.st_mode):
        raise SystemExit(f"{label} directory became a non-directory")
    names = []
    with os.scandir(directory_fd) as scanner:
        for entry in scanner:
            names.append(os.fsencode(entry.name))
            if len(names) > maximum_entries:
                raise SystemExit(f"{label} directory exceeds entry limit")
    require_same(
        directory_before,
        os.fstat(directory_fd),
        "directory enumeration",
    )
    names.sort()
    for name in names:
        child_relative = name if not relative else relative + b"/" + name
        entry_count += 1
        if entry_count > maximum_entries:
            raise SystemExit(f"{label} closure exceeds entry limit")
        if child_relative.count(b"/") + 1 > maximum_depth:
            raise SystemExit(f"{label} closure exceeds depth limit")
        if len(child_relative) > maximum_path_bytes:
            raise SystemExit(f"{label} closure path exceeds byte limit")
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(metadata.st_mode):
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            child_fd = os.open(name, flags, dir_fd=directory_fd)
            try:
                opened = os.fstat(child_fd)
                require_same(metadata, opened, os.fsdecode(child_relative))
                if not stat.S_ISDIR(opened.st_mode):
                    raise SystemExit(f"{label} directory became a non-directory")
                digest.update(b"D")
                add(child_relative)
                digest.update(stat.S_IMODE(opened.st_mode).to_bytes(4, "big"))
                visit(child_fd, child_relative)
            finally:
                os.close(child_fd)
        elif stat.S_ISREG(metadata.st_mode):
            flags = os.O_RDONLY | os.O_NOFOLLOW
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            descriptor = os.open(name, flags, dir_fd=directory_fd)
            try:
                before = os.fstat(descriptor)
                require_same(metadata, before, os.fsdecode(child_relative))
                if not stat.S_ISREG(before.st_mode):
                    raise SystemExit(f"{label} file became nonregular")
                if before.st_nlink != 1:
                    raise SystemExit(
                        f"{label} file has multiple hard links: "
                        f"{os.fsdecode(child_relative)}"
                    )
                if before.st_size > maximum_file_bytes:
                    raise SystemExit(
                        f"{label} file exceeds byte limit: "
                        f"{os.fsdecode(child_relative)}"
                    )
                total_file_bytes += before.st_size
                if total_file_bytes > maximum_total_file_bytes:
                    raise SystemExit(f"{label} closure exceeds total byte limit")
                digest.update(b"F")
                add(child_relative)
                digest.update(stat.S_IMODE(before.st_mode).to_bytes(4, "big"))
                digest.update(before.st_size.to_bytes(8, "big"))
                remaining = before.st_size
                while remaining:
                    chunk = os.read(descriptor, min(remaining, 1024 * 1024))
                    if not chunk:
                        raise SystemExit(
                            f"{label} file had a short read: "
                            f"{os.fsdecode(child_relative)}"
                        )
                    remaining -= len(chunk)
                    digest.update(chunk)
                if os.read(descriptor, 1):
                    raise SystemExit(
                        f"{label} file grew during read: "
                        f"{os.fsdecode(child_relative)}"
                    )
                require_same(
                    before,
                    os.fstat(descriptor),
                    os.fsdecode(child_relative),
                )
            finally:
                os.close(descriptor)
        else:
            raise SystemExit(
                f"{label} contains a symlink or special object: "
                f"{os.fsdecode(child_relative)}"
            )
    require_same(directory_before, os.fstat(directory_fd), "directory")


root_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
if hasattr(os, "O_CLOEXEC"):
    root_flags |= os.O_CLOEXEC
root_fd = os.open(root, root_flags)
try:
    root_metadata = os.fstat(root_fd)
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise SystemExit(f"{label} root is not a directory")
    digest.update(b"D")
    add(b"")
    digest.update(stat.S_IMODE(root_metadata.st_mode).to_bytes(4, "big"))
    visit(root_fd, b"")
finally:
    os.close(root_fd)
digest.update(b"Z")
digest.update(entry_count.to_bytes(8, "big"))
digest.update(total_file_bytes.to_bytes(8, "big"))
print(f"{digest.hexdigest()}\t{entry_count}\t{total_file_bytes}")
PY
}

fre_c5_toolchain_closure_fingerprint() {
    fre_c5_physical_closure_fingerprint rust-toolchain-v2 "$1"
}

fre_c5_cargo_registry_closure_fingerprint() {
    fre_c5_physical_closure_fingerprint cargo-registry-v1 "$1"
}

fre_c5_require_regular() {
    local path=$1
    local label=$2
    [[ -f $path && ! -L $path ]] ||
        fre_c5_die "$label must be a regular non-symlink file: $path"
}

fre_c5_require_file_bytes() {
    local path=$1
    local maximum=$2
    local label=$3
    local size
    fre_c5_require_regular "$path" "$label"
    [[ $maximum =~ ^[1-9][0-9]*$ ]] ||
        fre_c5_die "internal byte cap is invalid for $label"
    size=$(stat -f '%z' -- "$path") ||
        fre_c5_die "cannot determine byte size for $label"
    [[ $size =~ ^(0|[1-9][0-9]*)$ && $size -le $maximum ]] ||
        fre_c5_die "$label exceeds byte cap $maximum"
}

fre_c5_require_text_bounds() {
    local path=$1
    local maximum_bytes=$2
    local maximum_line_bytes=$3
    local maximum_lines=$4
    local label=$5
    fre_c5_require_file_bytes "$path" "$maximum_bytes" "$label"
    [[ $maximum_line_bytes =~ ^[1-9][0-9]*$ &&
        $maximum_lines =~ ^[1-9][0-9]*$ ]] ||
        fre_c5_die "internal text cap is invalid for $label"
    awk -v maximum_line_bytes="$maximum_line_bytes" \
        -v maximum_lines="$maximum_lines" '
        length($0) > maximum_line_bytes { bad = 1; exit }
        NR > maximum_lines { bad = 1; exit }
        END { exit bad ? 1 : 0 }
    ' "$path" ||
        fre_c5_die "$label exceeds line-length or line-count cap"
}

fre_c5_require_registry_or_path_lockfile() {
    local lock=$1
    local label=$2
    fre_c5_require_text_bounds "$lock" 1048576 8192 16384 "$label"
    awk -v label="$label" '
        function finish_package(    checksum_value) {
            if (!in_package) return
            if (source_count == 0) {
                if (checksum_count != 0) bad = 1
            } else if (source_count == 1 &&
                       source_value ~ /^registry[+][^"]+$/) {
                if (checksum_count != 1) {
                    bad = 1
                } else {
                    checksum_value = checksum_line
                    sub(/^checksum = "/, "", checksum_value)
                    sub(/"$/, "", checksum_value)
                    if (length(checksum_value) != 64 ||
                        checksum_value ~ /[^0-9a-f]/) bad = 1
                }
            } else {
                print label ": non-registry dependency source: " \
                    source_value > "/dev/stderr"
                bad = 1
            }
        }
        /^\[\[package\]\]$/ {
            finish_package()
            in_package = 1
            source_count = 0
            checksum_count = 0
            source_value = ""
            checksum_line = ""
            packages++
            next
        }
        /^[[:space:]]*source[[:space:]]*=/ {
            if (!in_package || $0 !~ /^source = "[^"]+"$/) {
                bad = 1
            } else {
                source_count++
                source_value = $0
                sub(/^source = "/, "", source_value)
                sub(/"$/, "", source_value)
            }
            next
        }
        /^[[:space:]]*checksum[[:space:]]*=/ {
            if (!in_package ||
                $0 !~ /^checksum = "[0-9a-f]+"/ ||
                $0 !~ /"$/) {
                bad = 1
            } else {
                checksum_count++
                checksum_line = $0
            }
            next
        }
        index($0, "\r") != 0 { bad = 1 }
        END {
            finish_package()
            if (packages == 0 || bad) exit 1
        }
    ' "$lock" ||
        fre_c5_die "$label must contain only canonical registry and path dependencies"
}

fre_c5_canonical_directory() {
    local path=$1
    [[ $path == /* && -d $path && ! -L $path ]] ||
        fre_c5_die "directory must be absolute, existing, and non-symlink: $path"
    local canonical
    canonical=$(CDPATH= cd -P -- "$path" && pwd -P) ||
        fre_c5_die "cannot resolve directory: $path"
    [[ $canonical == "$path" ]] ||
        fre_c5_die "directory must already be canonical: $path"
    printf '%s\n' "$canonical"
}

fre_c5_require_absolute_path_value() {
    local value=$1
    local label=$2
    [[ $value == /* && ${#value} -le 1024 &&
        $value != *$'\t'* && $value != *$'\n'* && $value != *$'\r'* ]] ||
        fre_c5_die "$label must be a bounded absolute path without TSV controls"
}

fre_c5_canonical_regular_file() {
    local path=$1
    local label=$2
    [[ $path == /* ]] ||
        fre_c5_die "$label path must be absolute"
    fre_c5_require_regular "$path" "$label"
    local parent base canonical_parent
    parent=${path%/*}
    base=${path##*/}
    [[ -n $parent && -n $base && $base != . && $base != .. ]] ||
        fre_c5_die "$label path is malformed"
    canonical_parent=$(fre_c5_canonical_directory "$parent")
    [[ $canonical_parent/$base == "$path" ]] ||
        fre_c5_die "$label path must already be canonical"
    [[ $(stat -f '%l' -- "$path") == 1 ]] ||
        fre_c5_die "$label must not be multiply linked"
    printf '%s\n' "$path"
}

fre_c5_owned_directory_identity() {
    local path=$1
    local label=$2
    local canonical owner current identity
    [[ $path == /* && -d $path && ! -L $path ]] ||
        fre_c5_die "$label must be an absolute physical directory"
    canonical=$(CDPATH= cd -P -- "$path" && pwd -P) ||
        fre_c5_die "cannot resolve $label"
    [[ $canonical == "$path" ]] ||
        fre_c5_die "$label must already be canonical"
    owner=$(stat -f '%u' -- "$path") ||
        fre_c5_die "cannot determine $label owner"
    current=$(/usr/bin/id -u) ||
        fre_c5_die "cannot determine current user identity"
    [[ $owner == "$current" ]] ||
        fre_c5_die "$label is not owned by the current user"
    identity=$(stat -f '%d:%i:%u' -- "$path") ||
        fre_c5_die "cannot determine $label identity"
    [[ $identity =~ ^[0-9]+:[0-9]+:[0-9]+$ ]] ||
        fre_c5_die "$label has a malformed physical identity"
    printf '%s\n' "$identity"
}

fre_c5_cleanup_owned_directory() {
    local path=$1
    local expected_identity=$2
    local namespace_prefix=$3
    local label=$4
    /usr/bin/env -i \
        LC_ALL=C \
        TZ=UTC \
        PATH=/usr/bin:/bin \
        /usr/bin/python3 -I -B - \
        "$path" "$expected_identity" "$namespace_prefix" "$label" <<'PY'
import os
import stat
import sys

path = os.fsencode(sys.argv[1])
expected_identity = sys.argv[2]
namespace_prefix = os.fsencode(sys.argv[3])
label = sys.argv[4]
maximum_entries = 500_000
maximum_depth = 128
entries = 0

if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
    raise SystemExit(f"{label}: cleanup requires O_NOFOLLOW and O_DIRECTORY")
try:
    expected_device_text, expected_inode_text, expected_owner_text = (
        expected_identity.split(":")
    )
    expected_device = int(expected_device_text)
    expected_inode = int(expected_inode_text)
    expected_owner = int(expected_owner_text)
except (ValueError, TypeError) as error:
    raise SystemExit(f"{label}: malformed recorded directory identity") from error
if (
    not path.startswith(b"/")
    or not namespace_prefix.startswith(b"/")
    or namespace_prefix == b"/"
    or not namespace_prefix.endswith(b".")
    or not path.startswith(namespace_prefix)
):
    raise SystemExit(f"{label}: cleanup path is outside its exact namespace")
suffix = path[len(namespace_prefix) :]
if len(suffix) != 6 or any(
    byte not in b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    for byte in suffix
):
    raise SystemExit(f"{label}: cleanup path has a malformed namespace suffix")
parent = os.path.dirname(path)
name = os.path.basename(path)
if not parent or not name or b"/" in name:
    raise SystemExit(f"{label}: cleanup path is malformed")

directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
if hasattr(os, "O_CLOEXEC"):
    directory_flags |= os.O_CLOEXEC
parent_fd = os.open(parent, directory_flags)


def same_root(metadata: os.stat_result) -> bool:
    return (
        metadata.st_dev == expected_device
        and metadata.st_ino == expected_inode
        and metadata.st_uid == expected_owner
        and stat.S_ISDIR(metadata.st_mode)
    )


def clear_directory(directory_fd: int, depth: int, root_device: int) -> None:
    global entries
    if depth > maximum_depth:
        raise SystemExit(f"{label}: cleanup tree exceeds depth limit")
    before = os.fstat(directory_fd)
    if not stat.S_ISDIR(before.st_mode) or before.st_dev != root_device:
        raise SystemExit(f"{label}: cleanup directory crossed a device boundary")
    os.fchmod(directory_fd, stat.S_IMODE(before.st_mode) | 0o700)
    names = []
    with os.scandir(directory_fd) as scanner:
        for entry in scanner:
            names.append(os.fsencode(entry.name))
            entries += 1
            if entries > maximum_entries:
                raise SystemExit(f"{label}: cleanup tree exceeds entry limit")
    names.sort()
    for child_name in names:
        metadata = os.stat(
            child_name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        if stat.S_ISDIR(metadata.st_mode):
            if metadata.st_dev != root_device:
                raise SystemExit(
                    f"{label}: cleanup refuses a nested device boundary"
                )
            child_fd = os.open(child_name, directory_flags, dir_fd=directory_fd)
            try:
                opened = os.fstat(child_fd)
                if (
                    opened.st_dev != metadata.st_dev
                    or opened.st_ino != metadata.st_ino
                    or not stat.S_ISDIR(opened.st_mode)
                ):
                    raise SystemExit(
                        f"{label}: cleanup child directory changed before open"
                    )
                clear_directory(child_fd, depth + 1, root_device)
            finally:
                os.close(child_fd)
            after = os.stat(
                child_name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            if (
                after.st_dev != metadata.st_dev
                or after.st_ino != metadata.st_ino
                or not stat.S_ISDIR(after.st_mode)
            ):
                raise SystemExit(
                    f"{label}: cleanup child directory changed before removal"
                )
            os.rmdir(child_name, dir_fd=directory_fd)
        else:
            os.unlink(child_name, dir_fd=directory_fd)


try:
    root_metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not same_root(root_metadata):
        raise SystemExit(f"{label}: cleanup root differs from its recorded identity")
    root_fd = os.open(name, directory_flags, dir_fd=parent_fd)
    try:
        opened_root = os.fstat(root_fd)
        if not same_root(opened_root):
            raise SystemExit(
                f"{label}: cleanup root changed while its descriptor was opened"
            )
        if expected_owner != os.geteuid():
            raise SystemExit(f"{label}: cleanup root is not owned by this user")
        clear_directory(root_fd, 0, opened_root.st_dev)
        if not same_root(os.fstat(root_fd)):
            raise SystemExit(f"{label}: cleanup root changed during traversal")
    finally:
        os.close(root_fd)
    final_root = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not same_root(final_root):
        raise SystemExit(f"{label}: cleanup root changed before final removal")
    os.rmdir(name, dir_fd=parent_fd)
finally:
    os.close(parent_fd)
PY
}

fre_c5_snapshot_pinned_file() {
    local source=$1
    local expected_sha=$2
    local maximum_bytes=$3
    local label=$4
    local destination=$5
    local source_size destination_size
    source=$(fre_c5_canonical_regular_file "$source" "$label")
    fre_c5_require_nonzero_sha256 "$expected_sha" "expected $label SHA-256"
    fre_c5_require_file_bytes "$source" "$maximum_bytes" "$label"
    source_size=$(stat -f '%z' -- "$source") ||
        fre_c5_die "cannot determine $label byte size"
    [[ $source_size -gt 0 ]] || fre_c5_die "$label must not be empty"
    [[ $(fre_c5_sha256 "$source") == "$expected_sha" ]] ||
        fre_c5_die "$label differs from externally expected SHA-256"
    [[ ! -e $destination && ! -L $destination ]] ||
        fre_c5_die "$label snapshot destination must not exist"
    /bin/cp -p -- "$source" "$destination" ||
        fre_c5_die "cannot snapshot $label"
    fre_c5_require_regular "$destination" "$label snapshot"
    [[ $(stat -f '%l' -- "$destination") == 1 ]] ||
        fre_c5_die "$label snapshot must not be multiply linked"
    destination_size=$(stat -f '%z' -- "$destination") ||
        fre_c5_die "cannot determine $label snapshot byte size"
    [[ $destination_size == "$source_size" &&
        $(fre_c5_sha256 "$destination") == "$expected_sha" ]] ||
        fre_c5_die "$label snapshot differs from external identity"
    [[ $(fre_c5_sha256 "$source") == "$expected_sha" ]] ||
        fre_c5_die "$label changed while being snapshotted"
}

fre_c5_require_no_archive_attribute_overrides() {
    local repository=$1
    local attributes configured config_status
    attributes=$(git -C "$repository" rev-parse --git-path info/attributes) ||
        fre_c5_die "cannot resolve repository info/attributes path"
    case $attributes in
        /*) ;;
        *) attributes=$repository/$attributes ;;
    esac
    [[ ! -e $attributes && ! -L $attributes ]] ||
        fre_c5_die "repository contains an info/attributes archive override"
    if configured=$(
        git -C "$repository" config --local --get-all core.attributesFile
    ); then
        fre_c5_die "repository config contains a core.attributesFile override"
    else
        config_status=$?
        [[ $config_status == 1 ]] ||
            fre_c5_die "cannot inspect repository core.attributesFile setting"
    fi
}

fre_c5_require_exact_git_snapshot() {
    local repository=$1
    local commit=$2
    local snapshot=$3
    repository=$(fre_c5_canonical_directory "$repository")
    snapshot=$(fre_c5_canonical_directory "$snapshot")
    fre_c5_require_hex "$commit" 40 "snapshot commit"
    /usr/bin/env -i \
        LC_ALL=C \
        TZ=UTC \
        PATH=/usr/bin:/bin \
        GIT_NO_REPLACE_OBJECTS=1 \
        GIT_CONFIG_NOSYSTEM=1 \
        GIT_CONFIG_GLOBAL=/dev/null \
        /usr/bin/python3 -I -B - "$repository" "$commit" "$snapshot" <<'PY'
import hashlib
import os
import stat
import subprocess
import sys

repository = os.fsencode(sys.argv[1])
commit = sys.argv[2]
snapshot = os.fsencode(sys.argv[3])
maximum_entries = 100_000
maximum_depth = 128
maximum_path_bytes = 4_096
maximum_file_bytes = 1_073_741_824
maximum_total_file_bytes = 4_294_967_296
maximum_tree_record_bytes = maximum_path_bytes + 256

if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
    raise SystemExit("exact Git snapshot verification requires O_NOFOLLOW and O_DIRECTORY")


def identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def display(path: bytes) -> str:
    return os.fsdecode(path)


def require_safe_path(path: bytes, label: str) -> None:
    if (
        not path
        or path.startswith(b"/")
        or len(path) > maximum_path_bytes
        or b"\t" in path
        or b"\n" in path
        or b"\r" in path
    ):
        raise SystemExit(f"{label} has an unsafe path")
    components = path.split(b"/")
    if (
        len(components) > maximum_depth
        or any(component in (b"", b".", b"..") for component in components)
    ):
        raise SystemExit(f"{label} has an unsafe path: {display(path)}")


def enumerate_materialized() -> tuple[tuple[int, ...], dict[bytes, tuple], int]:
    entries: dict[bytes, tuple] = {}
    total_file_bytes = 0
    root_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        root_flags |= os.O_CLOEXEC
    root_fd = os.open(snapshot, root_flags)

    def visit(directory_fd: int, relative: bytes) -> None:
        nonlocal total_file_bytes
        directory_before = os.fstat(directory_fd)
        if not stat.S_ISDIR(directory_before.st_mode):
            raise SystemExit("materialized snapshot directory became a non-directory")
        names = []
        with os.scandir(directory_fd) as scanner:
            for entry in scanner:
                names.append(os.fsencode(entry.name))
                if len(names) > maximum_entries:
                    raise SystemExit("materialized snapshot directory exceeds entry limit")
        if identity(directory_before) != identity(os.fstat(directory_fd)):
            raise SystemExit("materialized snapshot directory changed during enumeration")
        names.sort()
        for name in names:
            child_relative = name if not relative else relative + b"/" + name
            require_safe_path(child_relative, "materialized snapshot")
            if len(entries) >= maximum_entries:
                raise SystemExit("materialized snapshot exceeds entry limit")
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                if hasattr(os, "O_CLOEXEC"):
                    flags |= os.O_CLOEXEC
                child_fd = os.open(name, flags, dir_fd=directory_fd)
                try:
                    opened = os.fstat(child_fd)
                    if identity(metadata) != identity(opened):
                        raise SystemExit(
                            f"materialized snapshot directory changed: "
                            f"{display(child_relative)}"
                        )
                    entries[child_relative] = ("directory", identity(opened))
                    visit(child_fd, child_relative)
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(metadata.st_mode):
                if metadata.st_nlink != 1:
                    raise SystemExit(
                        f"materialized snapshot file has multiple hard links: "
                        f"{display(child_relative)}"
                    )
                if metadata.st_size > maximum_file_bytes:
                    raise SystemExit(
                        f"materialized snapshot file exceeds byte limit: "
                        f"{display(child_relative)}"
                    )
                total_file_bytes += metadata.st_size
                if total_file_bytes > maximum_total_file_bytes:
                    raise SystemExit("materialized snapshot exceeds total byte limit")
                entries[child_relative] = (
                    "file",
                    bool(stat.S_IMODE(metadata.st_mode) & 0o111),
                    metadata.st_size,
                    identity(metadata),
                )
            else:
                raise SystemExit(
                    f"materialized snapshot contains a symlink or special object: "
                    f"{display(child_relative)}"
                )
        if identity(directory_before) != identity(os.fstat(directory_fd)):
            raise SystemExit("materialized snapshot directory changed during enumeration")

    try:
        root_before = os.fstat(root_fd)
        if not stat.S_ISDIR(root_before.st_mode):
            raise SystemExit("materialized snapshot root is not a directory")
        visit(root_fd, b"")
        if identity(root_before) != identity(os.fstat(root_fd)):
            raise SystemExit("materialized snapshot root changed during enumeration")
        return identity(root_before), entries, total_file_bytes
    finally:
        os.close(root_fd)


def nul_records(stream):
    buffered = b""
    while True:
        chunk = stream.read(65_536)
        if not chunk:
            break
        buffered += chunk
        while True:
            separator = buffered.find(b"\0")
            if separator < 0:
                if len(buffered) > maximum_tree_record_bytes:
                    raise SystemExit("Git tree record exceeds byte limit")
                break
            record = buffered[:separator]
            buffered = buffered[separator + 1 :]
            if len(record) > maximum_tree_record_bytes:
                raise SystemExit("Git tree record exceeds byte limit")
            yield record
    if buffered:
        raise SystemExit("Git tree listing lacks a terminating NUL")


def load_expected() -> tuple[dict[bytes, tuple], int, str]:
    environment = {
        "LC_ALL": "C",
        "TZ": "UTC",
        "PATH": "/usr/bin:/bin",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
    }
    process = subprocess.Popen(
        [
            "/usr/bin/git",
            "-c",
            "core.attributesFile=/dev/null",
            "-C",
            os.fsdecode(repository),
            "ls-tree",
            "-r",
            "-t",
            "-l",
            "-z",
            "--full-tree",
            commit,
        ],
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if process.stdout is None:
        process.kill()
        process.wait()
        raise SystemExit("cannot read the expected Git tree")
    expected: dict[bytes, tuple] = {}
    total_file_bytes = 0
    object_algorithm = ""
    try:
        for record in nul_records(process.stdout):
            if len(expected) >= maximum_entries:
                raise SystemExit("expected Git tree exceeds entry limit")
            try:
                metadata, path = record.split(b"\t", 1)
            except ValueError as error:
                raise SystemExit("malformed expected Git tree record") from error
            require_safe_path(path, "expected Git tree")
            fields = metadata.split()
            if len(fields) != 4:
                raise SystemExit("malformed expected Git tree metadata")
            mode, object_type, object_id, size_field = fields
            try:
                object_id_text = object_id.decode("ascii")
            except UnicodeDecodeError as error:
                raise SystemExit("malformed expected Git object identity") from error
            if (
                len(object_id_text) not in (40, 64)
                or any(character not in "0123456789abcdef" for character in object_id_text)
            ):
                raise SystemExit("malformed expected Git object identity")
            algorithm = "sha1" if len(object_id_text) == 40 else "sha256"
            if object_algorithm and object_algorithm != algorithm:
                raise SystemExit("expected Git tree mixes object hash algorithms")
            object_algorithm = algorithm
            if path in expected:
                raise SystemExit(f"duplicate expected Git path: {display(path)}")
            if mode == b"040000" and object_type == b"tree" and size_field == b"-":
                expected[path] = ("directory",)
            elif (
                mode in (b"100644", b"100755")
                and object_type == b"blob"
                and size_field.isdigit()
            ):
                size = int(size_field)
                if size > maximum_file_bytes:
                    raise SystemExit(
                        f"expected Git blob exceeds byte limit: {display(path)}"
                    )
                total_file_bytes += size
                if total_file_bytes > maximum_total_file_bytes:
                    raise SystemExit("expected Git tree exceeds total byte limit")
                expected[path] = (
                    "file",
                    mode == b"100755",
                    size,
                    object_id_text,
                )
            else:
                raise SystemExit(
                    f"expected Git tree contains a non-regular entry: {display(path)}"
                )
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.wait()
    if process.returncode != 0:
        raise SystemExit("cannot enumerate the expected Git tree")
    if not expected or not object_algorithm:
        raise SystemExit("expected Git tree is empty")
    return expected, total_file_bytes, object_algorithm


root_identity, materialized, materialized_bytes = enumerate_materialized()
expected, expected_bytes, object_algorithm = load_expected()
if materialized_bytes != expected_bytes:
    raise SystemExit("materialized snapshot total byte count differs from expected Git tree")
if materialized.keys() != expected.keys():
    missing = sorted(expected.keys() - materialized.keys())
    extra = sorted(materialized.keys() - expected.keys())
    if missing:
        raise SystemExit(
            f"materialized snapshot omits expected Git path: {display(missing[0])}"
        )
    raise SystemExit(
        f"materialized snapshot has a path outside the Git tree: {display(extra[0])}"
    )
for path in sorted(expected):
    expected_entry = expected[path]
    materialized_entry = materialized[path]
    if expected_entry[0] != materialized_entry[0]:
        raise SystemExit(f"materialized snapshot type differs: {display(path)}")
    if expected_entry[0] == "file" and (
        expected_entry[1] != materialized_entry[1]
        or expected_entry[2] != materialized_entry[2]
    ):
        raise SystemExit(
            f"materialized snapshot mode or size differs: {display(path)}"
        )

root_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
if hasattr(os, "O_CLOEXEC"):
    root_flags |= os.O_CLOEXEC
root_fd = os.open(snapshot, root_flags)
try:
    if identity(os.fstat(root_fd)) != root_identity:
        raise SystemExit("materialized snapshot root changed before hashing")
    for path in sorted(expected):
        expected_entry = expected[path]
        if expected_entry[0] != "file":
            continue
        components = path.split(b"/")
        directory_fd = os.dup(root_fd)
        try:
            for component in components[:-1]:
                flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                if hasattr(os, "O_CLOEXEC"):
                    flags |= os.O_CLOEXEC
                child_fd = os.open(component, flags, dir_fd=directory_fd)
                os.close(directory_fd)
                directory_fd = child_fd
            flags = os.O_RDONLY | os.O_NOFOLLOW
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            descriptor = os.open(components[-1], flags, dir_fd=directory_fd)
            try:
                before = os.fstat(descriptor)
                if identity(before) != materialized[path][3]:
                    raise SystemExit(
                        f"materialized snapshot file changed before hashing: "
                        f"{display(path)}"
                    )
                digest = hashlib.new(object_algorithm)
                digest.update(f"blob {before.st_size}\0".encode("ascii"))
                remaining = before.st_size
                while remaining:
                    chunk = os.read(descriptor, min(remaining, 1024 * 1024))
                    if not chunk:
                        raise SystemExit(
                            f"materialized snapshot file had a short read: "
                            f"{display(path)}"
                        )
                    remaining -= len(chunk)
                    digest.update(chunk)
                if os.read(descriptor, 1):
                    raise SystemExit(
                        f"materialized snapshot file grew while hashing: "
                        f"{display(path)}"
                    )
                if identity(os.fstat(descriptor)) != identity(before):
                    raise SystemExit(
                        f"materialized snapshot file changed while hashing: "
                        f"{display(path)}"
                    )
                if digest.hexdigest() != expected_entry[3]:
                    raise SystemExit(
                        f"materialized snapshot blob differs from Git: {display(path)}"
                    )
            finally:
                os.close(descriptor)
        finally:
            os.close(directory_fd)
finally:
    os.close(root_fd)

root_identity_after, materialized_after, materialized_bytes_after = (
    enumerate_materialized()
)
if (
    root_identity_after != root_identity
    or materialized_after != materialized
    or materialized_bytes_after != materialized_bytes
):
    raise SystemExit("materialized snapshot changed during exact Git verification")
PY
}

fre_c5_require_new_output_path() {
    local output=$1
    [[ $output == /* && ! -e $output && ! -L $output ]] ||
        fre_c5_die "output must be an absolute nonexistent path: $output"
    local parent base canonical_parent
    parent=${output%/*}
    base=${output##*/}
    [[ -n $parent && -n $base && $base != . && $base != .. ]] ||
        fre_c5_die "unsafe output path: $output"
    canonical_parent=$(fre_c5_canonical_directory "$parent")
    [[ $canonical_parent/$base == "$output" ]] ||
        fre_c5_die "output parent must already be canonical: $output"
}

fre_c5_benchmark_source_sha256() {
    local source_root=$1
    local benchmark=$source_root/crates/fre-aot-count-compiler/benchmarks/c5-qualified-vs-portable
    local manifest=$benchmark/benchmark-source-files-v2.txt
    local name previous= count=0
    fre_c5_require_text_bounds \
        "$manifest" 4096 256 64 "benchmark source manifest"
    while IFS= read -r name || [[ -n $name ]]; do
        [[ $name =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ &&
            $name != */../* && $name != ../* && $name != */.. &&
            $name != */./* && $name != ./* ]] ||
            fre_c5_die "unsafe benchmark source manifest path"
        [[ -z $previous || $previous < $name ]] ||
            fre_c5_die "benchmark source manifest is not strictly sorted and unique"
        previous=$name
        count=$((count + 1))
        fre_c5_require_regular "$benchmark/$name" "benchmark source"
    done < "$manifest"
    [[ $count == 21 ]] ||
        fre_c5_die "benchmark source manifest must contain exactly 21 files"
    (
        cd "$benchmark"
        {
            printf 'FRE-AOT-COUNT-C5-QUALIFIED-BENCHMARK-SOURCE\000\002'
            while IFS= read -r name || [[ -n $name ]]; do
                printf '%s\000' "$name"
                /bin/cat -- "$name"
            done < benchmark-source-files-v2.txt
        } | /usr/bin/shasum -a 256 | /usr/bin/awk '{ print $1 }'
    )
}

fre_c5_render_promoted_support() {
    local candidate_support=$1
    local bundle_manifest_sha256=$2
    local output=$3
    fre_c5_require_regular "$candidate_support" "candidate support source"
    fre_c5_require_nonzero_sha256 \
        "$bundle_manifest_sha256" "promotion bundle manifest SHA-256"
    awk -v digest="$bundle_manifest_sha256" '
        BEGIN {
            zero_atom = "const C5_PROMOTION_BUNDLE_MANIFEST_SHA256_V2: [u8; 32] = [0; 32];"
        }
        $0 == zero_atom {
            replacements++
            print "const C5_PROMOTION_BUNDLE_MANIFEST_SHA256_V2: [u8; 32] = ["
            for (row = 0; row < 2; row++) {
                printf "    "
                for (column = 0; column < 16; column++) {
                    byte_index = row * 16 + column
                    printf "0x%s,", substr(digest, byte_index * 2 + 1, 2)
                    if (column != 15) printf " "
                }
                printf "\n"
            }
            print "];"
            next
        }
        { print }
        END { if (replacements != 1) exit 1 }
    ' "$candidate_support" > "$output" ||
        fre_c5_die "candidate support source lacks one exact all-zero C5 promotion atom"
}

fre_c5_require_subject() {
    local repository=$1
    local expected_commit=$2
    local expected_tree=$3
    local expected_source=$4
    local require_clean=$5
    local actual_commit actual_tree actual_source dirty

    fre_c5_require_hex "$expected_commit" 40 "expected commit"
    fre_c5_require_hex "$expected_tree" 40 "expected tree"
    fre_c5_require_nonzero_sha256 "$expected_source" "expected benchmark source SHA-256"
    repository=$(fre_c5_canonical_directory "$repository")
    [[ -f $repository/.git || -d $repository/.git ]] ||
        fre_c5_die "repository has no .git control path"

    actual_commit=$(git -C "$repository" rev-parse --verify HEAD) ||
        fre_c5_die "cannot resolve repository HEAD"
    actual_tree=$(git -C "$repository" rev-parse --verify 'HEAD^{tree}') ||
        fre_c5_die "cannot resolve repository tree"
    [[ $actual_commit == "$expected_commit" ]] ||
        fre_c5_die "HEAD differs from externally expected commit"
    [[ $actual_tree == "$expected_tree" ]] ||
        fre_c5_die "tree differs from externally expected tree"
    actual_source=$(fre_c5_benchmark_source_sha256 "$repository")
    [[ $actual_source == "$expected_source" ]] ||
        fre_c5_die "benchmark source differs from externally expected identity"
    if [[ $require_clean == true ]]; then
        dirty=$(git -C "$repository" status --porcelain=v1 --untracked-files=all)
        [[ -z $dirty ]] || fre_c5_die "subject repository is not clean"
    fi
}

fre_c5_tsv_value() {
    local file=$1
    local key=$2
    local count value
    count=$(awk -F '	' -v key="$key" '$1 == key { count++ } END { print count + 0 }' "$file")
    [[ $count == 1 ]] || fre_c5_die "$file must contain exactly one $key field"
    value=$(awk -F '	' -v key="$key" '$1 == key { print $2 }' "$file")
    [[ -n $value ]] || fre_c5_die "$file has an empty $key field"
    printf '%s\n' "$value"
}

fre_c5_require_tsv_value() {
    local file=$1
    local key=$2
    local expected=$3
    local actual
    actual=$(fre_c5_tsv_value "$file" "$key")
    [[ $actual == "$expected" ]] ||
        fre_c5_die "$file $key mismatch: expected $expected, got $actual"
}

fre_c5_validate_tsv() {
    local file=$1
    fre_c5_require_regular "$file" "TSV"
    awk -F '	' '
        NF != 2 || $1 !~ /^[a-z][a-z0-9_]*$/ || $2 == "" { exit 1 }
        seen[$1]++ { exit 1 }
        index($0, "\r") != 0 { exit 1 }
        END { if (NR == 0) exit 1 }
    ' "$file" || fre_c5_die "invalid or duplicate-key TSV: $file"
}

fre_c5_require_exact_tsv_keys() {
    local file=$1
    local label=$2
    local expected actual
    expected=$(/bin/cat)
    actual=$(awk -F '	' '{ print $1 }' "$file") ||
        fre_c5_die "cannot read $label key inventory"
    [[ $actual == "$expected" ]] ||
        fre_c5_die "$label does not match its exact ordered key inventory"
}

fre_c5_require_readonly_segment_report() {
    local report=$1
    fre_c5_require_regular "$report" "Mach-O load-command report"
    awk '$1 == "cmd" && $2 == "LC_UUID" { count++ }
         END { exit count == 1 ? 0 : 1 }' "$report" ||
        fre_c5_die "binary must contain exactly one content-hash LC_UUID load command"
    awk '
        /^Load command / {
            if (in_target && saw_max && saw_init) valid++
            in_target = saw_max = saw_init = 0
            next
        }
        $1 == "segname" && $2 == "__FRE_CONST" { in_target = 1; next }
        in_target && $1 == "maxprot" && $2 == "0x00000001" { saw_max = 1; next }
        in_target && $1 == "initprot" && $2 == "0x00000001" { saw_init = 1; next }
        END {
            if (in_target && saw_max && saw_init) valid++
            exit valid == 1 ? 0 : 1
        }
    ' "$report" || fre_c5_die "binary lacks one exact immutable __FRE_CONST R--/R-- segment"
}

fre_c5_require_no_llvm_dependency() {
    local report=$1
    fre_c5_require_regular "$report" "dependency report"
    awk '
        /^TREE	/ { next }
        {
            name = $1
            if (name ~ /^(llvm|llvm-sys|inkwell|cranelift)(-|$)/) {
                print "forbidden compiler dependency: " name > "/dev/stderr"
                bad = 1
            }
        }
        END { exit bad ? 1 : 0 }
    ' "$report" || fre_c5_die "dependency graph contains an LLVM or substitute compiler backend"
}

fre_c5_require_candidate_feature_isolation() {
    local report=$1
    fre_c5_require_regular "$report" "dependency report"
    awk -F '	' '
        $0 == "TREE	workspace-runtime-features" {
            section = "workspace"
            next
        }
        $0 == "TREE	qualification-runtime-features" {
            section = "qualification"
            next
        }
        $0 == "TREE	qualification-runtime-reverse" {
            section = "reverse"
            next
        }
        /^TREE	/ {
            section = ""
            next
        }
        section == "workspace" {
            workspace_lines++
            if ($1 !~ /^fre-aot-static-runtime v/ || $2 != "default" ||
                index($0, "c5-qualification-private-v2") != 0) bad = 1
            next
        }
        section == "qualification" {
            qualification_lines++
            if ($1 !~ /^fre-aot-static-runtime v/ ||
                $2 != "c5-qualification-private-v2,default,linked-count-v2") {
                bad = 1
            }
            next
        }
        section == "reverse" {
            reverse_lines++
            if (reverse_lines == 1) {
                if ($1 !~ /^fre-aot-static-runtime v/ ||
                    $2 != "c5-qualification-private-v2,default,linked-count-v2") {
                    bad = 1
                }
            } else if (reverse_lines == 2) {
                if ($1 !~ /^fre-aot-count-qualified-benchmark v/ || $2 != "") {
                    bad = 1
                }
            } else {
                bad = 1
            }
            next
        }
        END {
            if (workspace_lines != 1 || qualification_lines != 1 ||
                reverse_lines != 2) bad = 1
            exit bad ? 1 : 0
        }
    ' "$report" ||
        fre_c5_die "private C5 qualification feature escaped its standalone benchmark graph"
}

fre_c5_require_production_symbol_gate() {
    local report=$1
    fre_c5_require_text_bounds "$report" 1024 256 8 \
        "production private-symbol gate"
    fre_c5_validate_tsv "$report"
    fre_c5_require_tsv_value "$report" schema \
        fre-aot-count-c5-production-symbol-gate-v1
    fre_c5_require_tsv_value "$report" no-features absent
    fre_c5_require_tsv_value "$report" linked-count absent
    fre_c5_require_tsv_value "$report" hardware-matrix absent
    fre_c5_require_tsv_value "$report" all-features present-audit-only
}
