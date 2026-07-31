#!/usr/bin/env python3
"""Verify Search V8 provenance against independently rederived sidecars."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Mapping, Sequence

from provenance_common import (
    BUNDLE_POLICY,
    CARGO_LOCK_NAME,
    CARGO_LOCK_POLICY,
    DEPENDENCY_MANIFEST_NAME,
    DEPENDENCY_MANIFEST_SCHEMA,
    MAX_PACKAGES,
    MAX_SOURCE_ROWS,
    MAX_TOTAL_BYTES,
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
    dependency_identity,
    fail,
    parse_archive_bindings,
    parse_archives,
    parse_cargo_lock,
    parse_dependencies,
    parse_receipt,
    parse_source,
    provenance_identity,
    read_bundle_bound,
    read_regular_path_bound,
    require_hex,
    require_search_root,
    search_root_key,
    sha256,
    source_identity,
    uint,
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
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--expected-provenance-sha256", required=True)
    parser.add_argument("--expected-snapshot-git-tool-sha256", required=True)
    parser.add_argument("--rederived-source-snapshot", required=True, type=Path)
    parser.add_argument("--rederived-cargo-lock", required=True, type=Path)
    parser.add_argument("--rederived-dependency-manifest", required=True, type=Path)
    parser.add_argument("--rederived-registry-archives", required=True, type=Path)
    parser.add_argument(
        "--registry-archive",
        action="append",
        default=[],
        metavar="PACKAGE_KEY=/ABSOLUTE/FILE.crate",
    )
    return parser.parse_args(values)


def require_equal(
    retained: bytes,
    rederived: Path,
    role: str,
    retained_identities: set[tuple[int, int]],
) -> bytes:
    independently_rederived, identity = read_regular_path_bound(
        rederived, label=f"independently rederived {role}"
    )
    if identity in retained_identities:
        fail(f"independently rederived {role} aliases a retained bundle role")
    if retained != independently_rederived:
        fail(f"retained {role} differs from independent rederivation")
    return retained


def verify_fixed_receipt(
    receipt: Mapping[str, str],
    commit: str,
    tree: str,
    identity: str,
    git_tool_sha256: str,
) -> None:
    expected = {
        "schema": PROVENANCE_SCHEMA,
        "git_object_format": "sha1",
        "subject_commit": commit,
        "subject_tree": tree,
        "subject_dirty_state": "externally-asserted-clean",
        "external_git_derivation_boundary": EXTERNAL_GIT_BOUNDARY,
        "source_materialization": MATERIALIZATION,
        "snapshot_git_tool_sha256": git_tool_sha256,
        "source_snapshot_role": SOURCE_SNAPSHOT_NAME,
        "source_snapshot_schema": SOURCE_SNAPSHOT_SCHEMA,
        "cargo_lock_source_role": f"repo:{SEARCH_LOCK_PATH}",
        "cargo_lock_bundle_role": CARGO_LOCK_NAME,
        "cargo_lock_schema": "4",
        "cargo_lock_parser_policy": CARGO_LOCK_POLICY,
        "dependency_manifest_role": DEPENDENCY_MANIFEST_NAME,
        "dependency_manifest_schema": DEPENDENCY_MANIFEST_SCHEMA,
        "root_package_key": search_root_key(),
        "root_package_name": SEARCH_ROOT_NAME,
        "root_package_version": SEARCH_ROOT_VERSION,
        "root_package_source": SEARCH_ROOT_SOURCE,
        "root_package_manifest_role": SEARCH_ROOT_MANIFEST_ROLE,
        "registry_archives_role": REGISTRY_ARCHIVES_NAME,
        "registry_archives_schema": REGISTRY_ARCHIVES_SCHEMA,
        "registry_archive_input_policy": ARCHIVE_POLICY,
        "cargo_target": TARGET,
        "cargo_profile": PROFILE,
        "cargo_dependency_kinds": KINDS,
        "bundle_file_policy": BUNDLE_POLICY,
        "logical_path_policy": PATH_POLICY,
        "source_provenance_sha256": identity,
    }
    for key, value in expected.items():
        if receipt[key] != value:
            fail(f"provenance receipt {key} mismatch")
    for key in [
        "snapshot_git_tool_sha256",
        "source_snapshot_file_sha256",
        "source_snapshot_identity_sha256",
        "cargo_lock_sha256",
        "dependency_manifest_sha256",
        "root_package_key",
        "registry_archives_sha256",
        "dependency_closure_sha256",
        "source_provenance_sha256",
    ]:
        require_hex(receipt[key], 64, key)
    if provenance_identity([(key, receipt[key]) for key in PROVENANCE_KEYS[:-1]]) != identity:
        fail("source provenance identity does not match its ordered receipt")


def verify(options: argparse.Namespace) -> str:
    commit = require_hex(options.expected_commit, 40, "expected commit")
    tree = require_hex(options.expected_tree, 40, "expected tree")
    identity = require_hex(
        options.expected_provenance_sha256, 64, "expected provenance SHA-256"
    )
    git_tool_sha256 = require_hex(
        options.expected_snapshot_git_tool_sha256,
        64,
        "expected snapshot Git tool SHA-256",
    )
    bundle, bundle_identities = read_bundle_bound(options.bundle)
    retained_identities = set(bundle_identities.values())
    _, receipt = parse_receipt(bundle[PROVENANCE_NAME])
    verify_fixed_receipt(receipt, commit, tree, identity, git_tool_sha256)

    source = require_equal(
        bundle[SOURCE_SNAPSHOT_NAME],
        options.rederived_source_snapshot,
        "source snapshot",
        retained_identities,
    )
    source, source_rows, source_content_bytes = parse_source(source)
    lock = require_equal(
        bundle[CARGO_LOCK_NAME],
        options.rederived_cargo_lock,
        "Cargo.lock",
        retained_identities,
    )
    lock_packages, lock_package_count = parse_cargo_lock(lock)
    deps = require_equal(
        bundle[DEPENDENCY_MANIFEST_NAME],
        options.rederived_dependency_manifest,
        "dependency manifest",
        retained_identities,
    )
    deps, dep_rows, graph, path_count, registry_count = parse_dependencies(deps)
    root = require_search_root(dep_rows, graph)
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
    if any(
        row["manifest_role"].removeprefix("repo:") not in source_paths
        for row in dep_rows
        if row["source_kind"] == "path"
    ):
        fail("path dependency manifest is absent from the source snapshot")
    lock_rows = [row for row in source_rows if row["path"] == SEARCH_LOCK_PATH]
    if (
        len(lock_rows) != 1
        or int(lock_rows[0]["bytes"]) != len(lock)
        or lock_rows[0]["sha256"] != sha256(lock)
    ):
        fail("Cargo.lock differs from its exact Search V8 Git-object snapshot row")

    registry_checksums = {
        row["package_key"]: row["lock_checksum"]
        for row in dep_rows
        if row["source_kind"] == "registry"
    }
    archives = require_equal(
        bundle[REGISTRY_ARCHIVES_NAME],
        options.rederived_registry_archives,
        "registry archive manifest",
        retained_identities,
    )
    archives, archive_rows, archive_content_bytes = parse_archives(
        archives, registry_checksums
    )
    archive_bindings = parse_archive_bindings(options.registry_archive)
    verify_archive_inputs(archive_rows, archive_bindings)

    scalar_checks = {
        "source_snapshot_file_sha256": sha256(source),
        "source_snapshot_identity_sha256": source_identity(source),
        "source_snapshot_entries": str(len(source_rows)),
        "source_snapshot_content_bytes": str(source_content_bytes),
        "cargo_lock_sha256": sha256(lock),
        "cargo_lock_package_count": str(lock_package_count),
        "dependency_manifest_sha256": sha256(deps),
        "dependency_package_count": str(len(dep_rows)),
        "path_dependency_package_count": str(path_count),
        "registry_dependency_package_count": str(registry_count),
        "root_package_key": root,
        "registry_archives_sha256": sha256(archives),
        "dependency_archive_count": str(len(archive_rows)),
        "dependency_archive_content_bytes": str(archive_content_bytes),
        "dependency_closure_sha256": dependency_identity(
            source, lock, deps, archives
        ),
    }
    for key, value in scalar_checks.items():
        if receipt[key] != value:
            fail(f"provenance receipt {key} differs from retained bytes")
    uint(receipt["source_snapshot_entries"], 1, MAX_SOURCE_ROWS, "source entries")
    uint(receipt["cargo_lock_package_count"], 1, MAX_PACKAGES, "lock packages")
    uint(receipt["dependency_package_count"], 1, MAX_PACKAGES, "packages")
    uint(
        receipt["dependency_archive_content_bytes"],
        1,
        MAX_TOTAL_BYTES,
        "archives",
    )
    return identity


def main(values: Sequence[str]) -> int:
    try:
        print(f"PASS Search V8 provenance sidecar closure {verify(arguments(values))}")
    except ProvenanceError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
