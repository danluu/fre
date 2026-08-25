#!/usr/bin/env python3
"""Compare env-absent ordinary build artifacts without archive timestamps."""

from __future__ import annotations

import argparse
import hashlib
import subprocess
from pathlib import Path


ORDINARY_SUFFIXES = (
    "_fast_exists.o",
    "_fast_exists.program",
    "_fast_span.o",
    "_fast_span.program",
    "_optimizing_exists.o",
    "_optimizing_exists.program",
    "_optimizing_span.o",
    "_optimizing_span.program",
    "_optimizing_grep_count.o",
)
ARCHIVE_NAME = "libfre_ripgrep_aot_objects.a"
REGISTRY_NAME = "registry.rs"
ARCHIVE_METADATA_MEMBERS = frozenset(
    {
        "/",
        "//",
        "/SYM64/",
        "__.SYMDEF",
        "__.SYMDEF SORTED",
    }
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ordinary_payloads(out_dir: Path) -> dict[str, bytes]:
    payloads = {
        path.name: path.read_bytes()
        for path in out_dir.iterdir()
        if path.is_file() and path.name.endswith(ORDINARY_SUFFIXES)
    }
    if not payloads:
        raise ValueError(f"{out_dir}: no ordinary generated payloads")
    return payloads


def archive_members(ar: str, out_dir: Path) -> list[tuple[str, bytes]]:
    archive = out_dir / ARCHIVE_NAME
    listing = subprocess.run(
        [ar, "t", archive],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.decode("utf-8", "strict").splitlines()
    if not listing:
        raise ValueError(f"{archive}: empty member list")
    return [
        (
            name,
            subprocess.run(
                [ar, "p", archive, name],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).stdout,
        )
        for name in listing
    ]


def canonical_archive_digest(members: list[tuple[str, bytes]]) -> str:
    state = hashlib.sha256()
    state.update(b"FRE-RIPGREP-AOT-THIN-LOGICAL-ARCHIVE\0\x01")
    state.update(len(members).to_bytes(8, "little"))
    for name, payload in members:
        encoded = name.encode("utf-8")
        state.update(len(encoded).to_bytes(8, "little"))
        state.update(encoded)
        state.update(len(payload).to_bytes(8, "little"))
        state.update(payload)
    return state.hexdigest()


def verify_archive_closure(
    label: str,
    ordinary: dict[str, bytes],
    members: list[tuple[str, bytes]],
) -> None:
    object_payloads = {
        name: payload for name, payload in ordinary.items() if name.endswith(".o")
    }
    names = [name for name, _ in members]
    if len(names) != len(set(names)):
        raise ValueError(f"{label}: archive repeats a member name")
    ordinary_names = {name for name in names if name not in ARCHIVE_METADATA_MEMBERS}
    if ordinary_names != set(object_payloads):
        raise ValueError(f"{label}: archive/object member list mismatch")
    for name, payload in members:
        if name in ARCHIVE_METADATA_MEMBERS:
            continue
        if payload != object_payloads[name]:
            raise ValueError(f"{label}: archive member payload differs for {name}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("base_out_dir", type=Path)
    parser.add_argument("candidate_out_dir", type=Path)
    parser.add_argument("--ar", default="ar")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    base_registry = (args.base_out_dir / REGISTRY_NAME).read_bytes()
    candidate_registry = (args.candidate_out_dir / REGISTRY_NAME).read_bytes()
    if base_registry != candidate_registry:
        raise ValueError("ordinary generated registry differs byte-for-byte")

    base_payloads = ordinary_payloads(args.base_out_dir)
    candidate_payloads = ordinary_payloads(args.candidate_out_dir)
    if base_payloads.keys() != candidate_payloads.keys():
        raise ValueError("ordinary generated payload filename set differs")
    for name in sorted(base_payloads):
        if base_payloads[name] != candidate_payloads[name]:
            raise ValueError(f"ordinary generated payload differs for {name}")

    base_members = archive_members(args.ar, args.base_out_dir)
    candidate_members = archive_members(args.ar, args.candidate_out_dir)
    verify_archive_closure("base", base_payloads, base_members)
    verify_archive_closure("candidate", candidate_payloads, candidate_members)
    if base_members != candidate_members:
        raise ValueError("logical archive member order or payload differs")

    print(f"registry_sha256={digest(base_registry)}")
    print(f"ordinary_payload_count={len(base_payloads)}")
    print(f"logical_archive_sha256={canonical_archive_digest(base_members)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
