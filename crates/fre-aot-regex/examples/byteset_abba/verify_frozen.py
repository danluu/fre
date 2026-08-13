#!/usr/bin/env python3
"""Verify every frozen qualification input without executing any of it."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(f"frozen-input verification failed: {message}")


def main() -> None:
    if len(sys.argv) != 3:
        fail("usage: verify_frozen.py SHA256SUMS ROOT")
    manifest = Path(sys.argv[1]).resolve()
    root = Path(sys.argv[2]).resolve()
    if not manifest.is_file() or not root.is_dir():
        fail("manifest or root is absent")
    seen: set[str] = set()
    for line_number, raw_line in enumerate(
        manifest.read_text(encoding="utf-8").splitlines(), 1
    ):
        if not raw_line:
            continue
        digest, separator, relative = raw_line.partition("  ")
        if separator != "  " or len(digest) != 64:
            fail(f"malformed manifest line {line_number}")
        try:
            int(digest, 16)
        except ValueError:
            fail(f"non-hex digest on line {line_number}")
        if relative in seen or relative.startswith(("/", "../")) or "/../" in relative:
            fail(f"unsafe or duplicate path on line {line_number}")
        seen.add(relative)
        path = (root / relative).resolve()
        try:
            path.relative_to(root)
        except ValueError:
            fail(f"path escapes root on line {line_number}")
        if not path.is_file():
            fail(f"missing {relative}")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != digest:
            fail(f"digest mismatch for {relative}")
    if not seen:
        fail("empty manifest")
    print(f"verified {len(seen)} frozen inputs")


if __name__ == "__main__":
    main()
