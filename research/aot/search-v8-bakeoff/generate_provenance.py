#!/usr/bin/env python3
"""Close independently produced Search V8 provenance sidecars into a receipt."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from provenance_common import (
    BUNDLE_POLICY,
    CARGO_LOCK_NAME,
    CARGO_LOCK_POLICY,
    DEPENDENCY_MANIFEST_NAME,
    DEPENDENCY_MANIFEST_SCHEMA,
    PROVENANCE_KEYS,
    PROVENANCE_NAME,
    PROVENANCE_SCHEMA,
    REGISTRY_ARCHIVES_NAME,
    REGISTRY_ARCHIVES_SCHEMA,
    SEARCH_LOCK_PATH,
    SEARCH_ROOT_MANIFEST_ROLE,
    SEARCH_ROOT_NAME,
    SEARCH_ROOT_SOURCE,
    SEARCH_ROOT_VERSION,
    SOURCE_SNAPSHOT_NAME,
    SOURCE_SNAPSHOT_SCHEMA,
    ProvenanceError,
    bind_lock_packages,
    create_bundle,
    dependency_identity,
    fail,
    parse_archive_bindings,
    parse_archives,
    parse_cargo_lock,
    parse_dependencies,
    parse_source,
    provenance_identity,
    read_regular_path,
    receipt_bytes,
    require_hex,
    require_search_root,
    search_root_key,
    sha256,
    source_identity,
    verify_archive_inputs,
)

TARGET = "aarch64-apple-darwin"
PROFILE = "release"
KINDS = "normal+build"
MATERIALIZATION = "externally-rederived-exact-git-object-sidecar-v2"
EXTERNAL_GIT_BOUNDARY = "external-reviewer-authenticates-git-and-cargo-derivation-v1"
ARCHIVE_POLICY = "descriptor-bound-real-crate-by-package-key-v1"
PATH_POLICY = "derived-bundle-roles-and-percent-encoded-repository-paths-v2"


def arguments(values: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--snapshot-git-tool-sha256", required=True)
    parser.add_argument("--source-snapshot", required=True, type=Path)
    parser.add_argument("--cargo-lock", required=True, type=Path)
    parser.add_argument("--dependency-manifest", required=True, type=Path)
    parser.add_argument("--registry-archives", required=True, type=Path)
    parser.add_argument(
        "--registry-archive",
        action="append",
        default=[],
        metavar="PACKAGE_KEY=/ABSOLUTE/FILE.crate",
    )
    parser.add_argument("--target", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args(values)


def generate(options: argparse.Namespace) -> str:
    commit = require_hex(options.expected_commit, 40, "expected commit")
    tree = require_hex(options.expected_tree, 40, "expected tree")
    git_sha = require_hex(
        options.snapshot_git_tool_sha256, 64, "snapshot Git tool SHA-256"
    )
    if options.target != TARGET or options.profile != PROFILE:
        fail(f"provenance requires target={TARGET} profile={PROFILE}")

    source = read_regular_path(
        options.source_snapshot, label="independently derived source snapshot"
    )
    source, source_rows, source_content_bytes = parse_source(source)
    lock = read_regular_path(options.cargo_lock, label="exact Cargo.lock")
    lock_packages, lock_package_count = parse_cargo_lock(lock)
    deps = read_regular_path(
        options.dependency_manifest, label="independently derived dependency manifest"
    )
    deps, dep_rows, graph, path_count, registry_count = parse_dependencies(deps)
    root_key = require_search_root(dep_rows, graph)
    bind_lock_packages(lock_packages, dep_rows)

    source_paths = {row["path"] for row in source_rows}
    for exact_path, description in [
        (SEARCH_LOCK_PATH, "Search V8 Cargo.lock"),
        (
            SEARCH_ROOT_MANIFEST_ROLE.removeprefix("repo:"),
            "Search V8 root manifest",
        ),
    ]:
        if exact_path not in source_paths:
            fail(f"{description} is absent from the source snapshot")
    lock_rows = [row for row in source_rows if row["path"] == SEARCH_LOCK_PATH]
    if (
        len(lock_rows) != 1
        or int(lock_rows[0]["bytes"]) != len(lock)
        or lock_rows[0]["sha256"] != sha256(lock)
    ):
        fail("Cargo.lock bytes are not the exact Search V8 source-snapshot blob")
    if any(
        row["manifest_role"].removeprefix("repo:") not in source_paths
        for row in dep_rows
        if row["source_kind"] == "path"
    ):
        fail("path dependency manifest is absent from the source snapshot")

    registry_checksums = {
        row["package_key"]: row["lock_checksum"]
        for row in dep_rows
        if row["source_kind"] == "registry"
    }
    archives = read_regular_path(
        options.registry_archives,
        label="independently derived registry archive manifest",
    )
    archives, archive_rows, archive_content_bytes = parse_archives(
        archives, registry_checksums
    )
    archive_bindings = parse_archive_bindings(options.registry_archive)
    verify_archive_inputs(archive_rows, archive_bindings)

    closure = dependency_identity(source, lock, deps, archives)
    preimage = [
        ("schema", PROVENANCE_SCHEMA),
        ("git_object_format", "sha1"),
        ("subject_commit", commit),
        ("subject_tree", tree),
        ("subject_dirty_state", "externally-asserted-clean"),
        ("external_git_derivation_boundary", EXTERNAL_GIT_BOUNDARY),
        ("source_materialization", MATERIALIZATION),
        ("snapshot_git_tool_sha256", git_sha),
        ("source_snapshot_role", SOURCE_SNAPSHOT_NAME),
        ("source_snapshot_schema", SOURCE_SNAPSHOT_SCHEMA),
        ("source_snapshot_file_sha256", sha256(source)),
        ("source_snapshot_identity_sha256", source_identity(source)),
        ("source_snapshot_entries", str(len(source_rows))),
        ("source_snapshot_content_bytes", str(source_content_bytes)),
        ("cargo_lock_source_role", f"repo:{SEARCH_LOCK_PATH}"),
        ("cargo_lock_bundle_role", CARGO_LOCK_NAME),
        ("cargo_lock_sha256", sha256(lock)),
        ("cargo_lock_schema", "4"),
        ("cargo_lock_parser_policy", CARGO_LOCK_POLICY),
        ("cargo_lock_package_count", str(lock_package_count)),
        ("dependency_manifest_role", DEPENDENCY_MANIFEST_NAME),
        ("dependency_manifest_schema", DEPENDENCY_MANIFEST_SCHEMA),
        ("dependency_manifest_sha256", sha256(deps)),
        ("dependency_package_count", str(len(dep_rows))),
        ("path_dependency_package_count", str(path_count)),
        ("registry_dependency_package_count", str(registry_count)),
        ("root_package_key", root_key),
        ("root_package_name", SEARCH_ROOT_NAME),
        ("root_package_version", SEARCH_ROOT_VERSION),
        ("root_package_source", SEARCH_ROOT_SOURCE),
        ("root_package_manifest_role", SEARCH_ROOT_MANIFEST_ROLE),
        ("registry_archives_role", REGISTRY_ARCHIVES_NAME),
        ("registry_archives_schema", REGISTRY_ARCHIVES_SCHEMA),
        ("registry_archives_sha256", sha256(archives)),
        ("dependency_archive_count", str(len(archive_rows))),
        ("dependency_archive_content_bytes", str(archive_content_bytes)),
        ("registry_archive_input_policy", ARCHIVE_POLICY),
        ("dependency_closure_sha256", closure),
        ("cargo_target", TARGET),
        ("cargo_profile", PROFILE),
        ("cargo_dependency_kinds", KINDS),
        ("bundle_file_policy", BUNDLE_POLICY),
        ("logical_path_policy", PATH_POLICY),
    ]
    if root_key != search_root_key():
        fail("Search V8 root key drifted from its exact identity")
    if [key for key, _ in preimage] != PROVENANCE_KEYS[:-1]:
        fail("generator receipt keys drifted from the closed schema")
    identity = provenance_identity(preimage)
    receipt = receipt_bytes([*preimage, ("source_provenance_sha256", identity)])
    create_bundle(
        options.output,
        {
            SOURCE_SNAPSHOT_NAME: source,
            CARGO_LOCK_NAME: lock,
            DEPENDENCY_MANIFEST_NAME: deps,
            REGISTRY_ARCHIVES_NAME: archives,
            PROVENANCE_NAME: receipt,
        },
    )
    return identity


def main(values: Sequence[str]) -> int:
    try:
        print(generate(arguments(values)))
    except ProvenanceError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
