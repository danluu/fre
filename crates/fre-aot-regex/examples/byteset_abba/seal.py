#!/usr/bin/env python3
"""Atomically seal opaque ABBA outputs without parsing timing fields."""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path


FILES = (
    "metadata-candidate.tsv",
    "01-parent-upstream-native.tsv",
    "02-candidate-native-upstream.tsv",
    "03-candidate-upstream-native.tsv",
    "04-parent-native-upstream.tsv",
)


def fail(message: str) -> None:
    raise SystemExit(f"collection sealing failed: {message}")


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: seal.py OUTPUT_DIRECTORY")
    output = Path(sys.argv[1]).resolve()
    if not output.is_dir():
        fail("output directory is absent")
    if (output / "SEALED_PHASES.sha256").exists() or (output / "COLLECTION_COMPLETE").exists():
        fail("output is already sealed")
    lines: list[str] = []
    for relative in FILES:
        path = output / relative
        if not path.is_file() or path.stat().st_size == 0:
            fail(f"missing or empty opaque phase {relative}")
        lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {relative}\n")
    manifest_temporary = output / ".SEALED_PHASES.sha256.tmp"
    complete_temporary = output / ".COLLECTION_COMPLETE.tmp"
    manifest_temporary.write_text("".join(lines), encoding="utf-8")
    complete_temporary.write_text(
        "all_metadata_and_abba_phases_sealed_before_timing_parse=true\n",
        encoding="utf-8",
    )
    os.replace(manifest_temporary, output / "SEALED_PHASES.sha256")
    os.replace(complete_temporary, output / "COLLECTION_COMPLETE")


if __name__ == "__main__":
    main()
