#!/usr/bin/env python3
"""Create the controlled source archive before building the sealed runner."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import analyze_v26_gate as gate
from seal_v26_gate import git_object_id, publish_git_archive


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        source_commit = gate.lowercase_hex(
            args.source_commit, 40, "source commit"
        )
        source_tree = gate.lowercase_hex(args.source_tree, 40, "source tree")
        if git_object_id(
            args.repository, f"{source_commit}^{{commit}}", "source commit"
        ) != source_commit or git_object_id(
            args.repository, f"{source_commit}^{{tree}}", "source tree"
        ) != source_tree:
            raise gate.GateError("requested source commit/tree does not match Git")
        archive_file = publish_git_archive(
            args.repository, source_commit, source_tree, args.output
        )
        source_set_sha256 = gate.archive_runner_source_set_sha256(archive_file)
        json.dump(
            {
                "schema": "fre-search-v26-development-gate-source-archive-v1",
                "source_commit": source_commit,
                "source_tree": source_tree,
                "source_archive_sha256": archive_file.sha256,
                "runner_source_set_sha256": source_set_sha256,
                "bytes": len(archive_file.data),
            },
            sys.stdout,
            sort_keys=True,
            separators=(",", ":"),
        )
        sys.stdout.write("\n")
        return 0
    except gate.GateError as error:
        sys.stderr.write(f"source preparation refused: {error}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
