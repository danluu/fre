#!/usr/bin/env python3
"""Render discovery or timing-sealed Search tag-30 runner identities."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any, BinaryIO, Mapping, Sequence


DIRECTORY_RELATIVE = "research/aot/search-tag30-qualification-runner"
TEMPLATE_NAME = "identity-template-v1.json"
CONTRACT_NAME = "campaign-contract-v1.json"
SOURCE_MANIFEST_NAME = "runner-source-files.txt"
PRIVATE_SOURCE_RELATIVE = (
    "crates/fre-aot-static-runtime/src/search_support/private_rows.rs"
)
IDENTITY_SCHEMA = "fre.aot.search-tag30-qualification-runner-identity.v1"
PREPARED_SCHEMA = "fre.aot.search-tag30-prepared-inputs.v1"
BUILD_RECEIPT_SCHEMA = (
    "fre.aot.search-tag30-qualification-runner-build-receipt.v1"
)
DISCOVERY_AUTHORIZATION_SCHEMA = (
    "fre.aot.search-tag30-qualification-discovery-authorization.v1"
)
CONTRACT_SCHEMA = "fre.aot.search-tag30-qualification-campaign-contract.v1"
CONTRACT_SHA256 = (
    "d39dc02c741a13adc8e0c7c3cc818ffa69e96132af89caf0fef6b5dad6d14333"
)
OBJECT_SCHEMA = "fre.aot.search-tag30-qualification-object-candidates.v1"
OBJECT_SHA256 = (
    "2ba3659c13c0d40da9716bcace03a6e5fd8514bf9932b99f51116da57b1d308b"
)
OBJECT_PAYLOAD_SHA256 = (
    "7363999204f52f66ae93f0c8087fba071e2fbd51eadf84f2e08e45eec06da54e"
)
DISPOSITION_SCHEMA = (
    "fre.aot.search-tag30-qualification-literal-dispositions.v1"
)
DISPOSITION_SHA256 = (
    "a2f2c15e38b21ab664117c2da3011a8059b7e8bf807b9f6fbc00c34ff1c6dcd1"
)
DISPOSITION_PAYLOAD_SHA256 = (
    "abf60247a4a735435ac53be7c614691ae41563dbaf845f6ddb5e8e21e90fcbd0"
)
RUNNER_SOURCE_DOMAIN = (
    b"FRE-SEARCH-TAG30-QUALIFICATION-RUNNER-SOURCE\0\x01"
)
COMPILER_IDENTITY_DOMAIN = (
    b"FRE-SEARCH-TAG30-COMPILER-SOURCE-IDENTITY\0\x01"
)
MAXIMUM_SMALL_FILE = 4 << 20
PRIVATE_CONSTRUCTOR = (
    "SourceQualifiedStaticSearchSpanFamilyV1::private_qualification("
)
PREPARED_FILENAMES = {
    "universal-full.ndjson",
    "universal-timed.ndjson",
    "long-policy-full.ndjson",
    "long-policy-timed.ndjson",
    "object-candidates.json",
    "literal-dispositions.json",
    "projection-summaries.json",
    "prepared-inputs.json",
}
PLATFORMS = {
    "macos_aarch64": {
        "host_id": "local-apple-aarch64-asimd",
        "target_os": "macos",
        "target_arch": "aarch64",
    },
    "linux_aarch64": {
        "host_id": "zstd-eval-c9g-neoverse-v3-aarch64-asimd",
        "target_os": "linux",
        "target_arch": "aarch64",
    },
}
FAMILY_TUPLE_FIELDS = {
    "compiler_version",
    "metadata_version",
    "backend_version",
    "call_abi_schema",
    "exported_symbol_schema",
    "output_kind",
    "architecture",
    "little_endian",
    "pointer_width",
    "target_abi",
    "platform",
    "status_bits",
    "exported_symbol_n_type",
    "required_features",
    "manifest_identity",
    "family_selector",
    "minimum_literal_bytes",
    "maximum_literal_bytes",
    "minimum_window_bytes",
    "portable_prefix_candidate_starts",
}
BUILD_RECEIPT_FIELDS = {
    "schema",
    "identity_sha256",
    "runner_revision",
    "runner_source_sha256",
    "source_archive_sha256",
    "private_family_source_sha256",
    "target_os",
    "target_arch",
    "host_id",
    "backend_name",
    "backend_tag",
    "backend_version",
    "candidate_policy",
    "llvm",
    "compiler_identity",
    "manifest_identity",
    "discovery_authorization_sha256",
    "discovery_build_receipt_sha256",
    "family_selector",
    "minimum_literal_bytes",
    "maximum_literal_bytes",
    "minimum_window_bytes",
    "portable_prefix_candidate_starts",
    "family_tuple",
    "plan_identity",
    "analyzer_identity",
    "evidence_identity",
    "timing_permitted",
    "object_candidate_manifest_schema",
    "object_candidate_manifest_sha256",
    "object_candidate_manifest_payload_sha256",
    "object_candidate_count",
    "literal_dispositions_sha256",
    "literal_dispositions_payload_sha256",
    "literal_disposition_count",
    "prepared_inputs_sha256",
    "prepare_source_sha256",
    "canonical_byte_escaped_sources",
    "candidates",
    "refusals",
}
DISCOVERY_AUTHORIZATION_FIELDS = {
    "contract_schema",
    "campaign_contract_sha256",
    "analyzer_source_sha256",
    "prepared_inputs_sha256",
    "object_candidate_manifest_schema",
    "object_candidate_manifest_sha256",
    "object_candidate_manifest_payload_sha256",
    "literal_dispositions_schema",
    "literal_dispositions_sha256",
    "literal_dispositions_payload_sha256",
    "prepare_source_sha256",
    "discovery_runner_revision",
    "discovery_runner_source_sha256",
    "discovery_source_archive_sha256",
    "discovery_identity_sha256",
    "discovery_private_family_source_sha256",
    "family_common",
    "decision",
    "qualification",
    "targets",
}
DISCOVERY_TARGET_FIELDS = {
    "host_id",
    "target_os",
    "target_arch",
    "manifest_identity",
    "discovery_build_receipt_schema",
    "discovery_build_receipt_sha256",
    "family_tuple",
}
CANDIDATE_RECEIPT_FIELDS = {
    "ordinal",
    "semantic_candidate_sha256",
    "literal_sha256",
    "literal_hex",
    "compile_identity",
    "compile_receipt_sha256",
    "compile_receipt_basename",
    "implementation_object_sha256",
    "glue_object_sha256",
    "implementation_object_basename",
    "glue_object_basename",
    "implementation_symbols",
    "glue_symbol",
}
REFUSAL_RECEIPT_FIELDS = {
    "ordinal",
    "semantic_candidate_sha256",
    "literal_sha256",
    "literal_hex",
    "disposition",
    "compile_receipt_sha256",
    "compile_receipt_basename",
}


class Refusal(RuntimeError):
    """An identity input is incomplete, mutable, or outside the closed schema."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def sha256(encoded: bytes) -> str:
    return hashlib.sha256(encoded).hexdigest()


def is_hex(value: Any, length: int = 64) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def pretty_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode()


def exact_keys(value: Any, fields: set[str], context: str) -> Mapping[str, Any]:
    require(
        isinstance(value, dict) and set(value) == fields,
        f"{context}: fields changed",
    )
    return value


def read_regular(
    path: Path, maximum: int = MAXIMUM_SMALL_FILE, *, readonly: bool = False
) -> bytes:
    metadata = path.lstat()
    require(
        stat.S_ISREG(metadata.st_mode)
        and not path.is_symlink()
        and metadata.st_nlink == 1
        and 0 < metadata.st_size <= maximum
        and (not readonly or metadata.st_mode & 0o222 == 0),
        f"not one bounded, stable regular file: {path}",
    )
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        encoded = bytearray()
        while len(encoded) < before.st_size:
            block = os.read(descriptor, min(1 << 20, before.st_size - len(encoded)))
            require(block != b"", f"short read: {path}")
            encoded.extend(block)
        require(os.read(descriptor, 1) == b"", f"file grew: {path}")
        after = os.fstat(descriptor)
        require(
            (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_nlink,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            == (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_nlink,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ),
            f"file changed while held: {path}",
        )
        return bytes(encoded)
    finally:
        os.close(descriptor)


def file_sha(path: Path) -> str:
    metadata = path.lstat()
    require(
        stat.S_ISREG(metadata.st_mode)
        and not path.is_symlink()
        and metadata.st_nlink == 1
        and metadata.st_size > 0,
        f"not one regular input: {path}",
    )
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1 << 20):
            digest.update(block)
    after = path.stat()
    require(
        (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_nlink,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )
        == (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ),
        f"input changed while hashed: {path}",
    )
    return digest.hexdigest()


def git(repo: Path, *arguments: str) -> bytes:
    process = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    require(
        process.returncode == 0,
        f"git {' '.join(arguments)} refused: "
        f"{process.stderr.decode(errors='replace').strip()}",
    )
    return process.stdout


def authenticate_clean_repo(repo: Path) -> str:
    require(repo.is_absolute(), "repository path must be absolute")
    top = Path(git(repo, "rev-parse", "--show-toplevel").decode().strip())
    require(top == repo, "repository argument is not the exact Git root")
    require(
        git(repo, "status", "--porcelain=v1", "--untracked-files=all") == b"",
        "identity rendering requires a clean checkout",
    )
    revision = git(repo, "rev-parse", "HEAD").decode().strip()
    require(is_hex(revision, 40), "HEAD is not one full Git revision")
    return revision


def archive_sha256(repo: Path, revision: str = "HEAD") -> str:
    process = subprocess.Popen(
        ["git", "-C", str(repo), "archive", "--format=tar", revision],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    require(process.stdout is not None, "git archive stdout is absent")
    digest = hashlib.sha256()
    while block := process.stdout.read(1 << 20):
        digest.update(block)
    stderr = process.stderr.read() if process.stderr is not None else b""
    require(
        process.wait() == 0,
        f"git archive refused: {stderr.decode(errors='replace').strip()}",
    )
    return digest.hexdigest()


def source_set_sha256(directory: Path) -> str:
    manifest = read_regular(directory / SOURCE_MANIFEST_NAME, 1 << 20)
    require(
        manifest.endswith(b"\n") and b"\r" not in manifest,
        "runner source manifest framing changed",
    )
    names = manifest.decode("ascii").splitlines()
    require(
        names == sorted(set(names))
        and all(
            name
            and not name.startswith("/")
            and "\\" not in name
            and all(part not in {"", ".", ".."} for part in name.split("/"))
            for name in names
        ),
        "runner source manifest is not canonical",
    )
    digest = hashlib.sha256(RUNNER_SOURCE_DOMAIN)
    for name in names:
        encoded = read_regular(directory / name, 1 << 20)
        digest.update(name.encode())
        digest.update(b"\0")
        digest.update(len(encoded).to_bytes(8, "little"))
        digest.update(encoded)
    return digest.hexdigest()


def compiler_identity(revision: str, archive: str) -> str:
    return sha256(
        COMPILER_IDENTITY_DOMAIN
        + bytes.fromhex(revision)
        + bytes.fromhex(archive)
    )


def load_contract(directory: Path) -> Mapping[str, Any]:
    encoded = read_regular(directory / CONTRACT_NAME, 128 << 10)
    require(sha256(encoded) == CONTRACT_SHA256, "campaign contract changed")
    contract = json.loads(encoded)
    exact_keys(
        contract,
        {
            "schema",
            "result_blind",
            "rebar_inputs",
            "result_derived_selection",
            "result_derived_exclusions",
            "backend",
            "prepared_inputs",
            "private_family_authority",
            "hosts",
            "sharding",
            "projections",
            "universal_gates",
            "long_policy_gates",
        },
        "campaign contract",
    )
    require(
        contract["schema"] == CONTRACT_SCHEMA
        and contract["result_blind"] is True
        and contract["rebar_inputs"] == []
        and contract["result_derived_selection"] is False
        and contract["result_derived_exclusions"] is False,
        "campaign contract authority changed",
    )
    exact_keys(
        contract["private_family_authority"],
        {
            "state",
            "stage_one",
            "stage_two",
            "source_atom",
            "family_selector",
            "minimum_literal_bytes",
            "maximum_literal_bytes",
            "minimum_window_bytes",
            "portable_prefix_candidate_starts",
            "plan_identity",
            "analyzer_identity",
            "discovery_authorization",
            "evidence_identity",
            "production_authority",
        },
        "private family authority",
    )
    exact_keys(
        contract["backend"],
        {
            "tag",
            "name",
            "version",
            "candidate_policy",
            "family_selector",
            "portable_prefix_candidate_starts",
            "aot_magic_hex",
            "llvm",
        },
        "campaign backend",
    )
    require(
        contract["backend"]
        == {
            "tag": 30,
            "name": "AsimdV17",
            "version": "SEARCH_V17",
            "candidate_policy": 15,
            "family_selector": 13,
            "portable_prefix_candidate_starts": 256,
            "aot_magic_hex": "465245413634001e",
            "llvm": False,
        },
        "campaign backend changed",
    )
    require(
        contract["private_family_authority"]["family_selector"] == 13
        and contract["private_family_authority"]["minimum_literal_bytes"] == 6
        and contract["private_family_authority"]["maximum_literal_bytes"]
        == 32
        and contract["private_family_authority"]["minimum_window_bytes"]
        == 65_536
        and contract["private_family_authority"][
            "portable_prefix_candidate_starts"
        ]
        == 256
        and contract["private_family_authority"]["production_authority"]
        is False,
        "private family envelope changed",
    )
    return contract


def load_template(directory: Path) -> dict[str, Any]:
    template = json.loads(
        read_regular(directory / TEMPLATE_NAME, 128 << 10)
    )
    exact_keys(
        template,
        {
            "schema",
            "campaign_inputs",
            "object_candidates",
            "literal_dispositions",
            "emitter",
            "static_pipeline",
            "auto_routing",
            "static_facade",
            "private_family",
            "platform_artifacts",
            "runner",
            "state",
        },
        "identity template",
    )
    require(template["schema"] == IDENTITY_SCHEMA, "identity template schema changed")
    exact_keys(
        template["campaign_inputs"],
        {
            "contract_schema",
            "contract_sha256",
            "prepared_inputs_schema",
            "prepared_inputs_sha256",
            "prepare_source_sha256",
            "learned_freeze_sha256",
            "learned_generator_sha256",
            "long_policy_freeze_sha256",
            "long_policy_derivation_sha256",
            "selector_contract_sha256",
            "projections",
        },
        "identity campaign inputs",
    )
    exact_keys(
        template["campaign_inputs"]["projections"],
        {
            "universal_full",
            "universal_timed",
            "long_policy_full",
            "long_policy_timed",
        },
        "identity projections",
    )
    for name, projection in template["campaign_inputs"]["projections"].items():
        exact_keys(
            projection,
            {"schema", "rows", "projection_digest", "file_sha256"},
            f"identity projection {name}",
        )
    exact_keys(
        template["object_candidates"],
        {
            "manifest_schema",
            "manifest_sha256",
            "payload_sha256",
            "candidate_count",
            "source_construction",
            "candidate_domain_hex",
        },
        "identity object candidates",
    )
    exact_keys(
        template["literal_dispositions"],
        {
            "schema",
            "sha256",
            "payload_sha256",
            "literal_count",
            "eligible_literal_count",
            "ineligible_literal_count",
        },
        "identity literal dispositions",
    )
    exact_keys(
        template["emitter"],
        {
            "source_commit",
            "backend",
            "backend_tag",
            "aot_magic_hex",
            "candidate_policy",
            "authorization",
            "llvm",
        },
        "identity emitter",
    )
    exact_keys(
        template["static_pipeline"],
        {
            "source_commit",
            "backend_name",
            "backend_tag",
            "compiler_identity",
            "object_formats",
            "link_interface_schema",
        },
        "identity static pipeline",
    )
    exact_keys(
        template["auto_routing"],
        {
            "source_commit",
            "policy_identity",
            "plan_identity",
            "analyzer_identity",
            "evidence_identity",
            "family_selector",
            "minimum_literal_bytes",
            "maximum_literal_bytes",
            "minimum_window_bytes",
            "portable_prefix_candidate_starts",
            "full_window_preflight_authoritative",
        },
        "identity auto routing",
    )
    exact_keys(
        template["static_facade"],
        {
            "source_commit",
            "source_set_sha256",
            "abi",
            "output",
            "jit_publication",
            "construction_in_steady_timing",
            "link_adoption_in_steady_timing",
        },
        "identity static facade",
    )
    exact_keys(
        template["private_family"],
        {
            "source_path",
            "source_sha256",
            "promotion_state",
            "discovery_authorization_schema",
            "discovery_authorization_sha256",
            "family_selector",
            "minimum_literal_bytes",
            "maximum_literal_bytes",
            "minimum_window_bytes",
            "portable_prefix_candidate_starts",
            "evidence_identity_algorithm",
            "evidence_identity_domain_hex",
            "evidence_identity_raw_digest_order",
        },
        "identity private family",
    )
    exact_keys(
        template["platform_artifacts"],
        set(PLATFORMS),
        "identity platform artifacts",
    )
    for key, platform in template["platform_artifacts"].items():
        exact_keys(
            platform,
            {
                "host_id",
                "manifest_identity",
                "discovery_build_receipt_sha256",
            },
            f"identity platform artifact {key}",
        )
    exact_keys(
        template["runner"],
        {
            "source_commit",
            "source_set_sha256",
            "source_archive_sha256",
            "analyzer_source_sha256",
            "controller_source_sha256",
            "prepare_source_sha256",
            "identity_renderer_source_sha256",
            "compiler_family",
            "fixture_oracle",
            "paired_order",
            "repetitions",
            "target_elapsed_ns",
            "calibration_floor_elapsed_ns",
            "calibration_anchor_samples",
            "calibration_iteration_selection",
            "macos_super_class_wait_timeout_ns",
            "minimum_elapsed_ns",
            "calibrate_both_variants",
        },
        "identity runner",
    )
    exact_keys(
        template["state"],
        {
            "heldout_materialized",
            "development_timing_permitted",
            "blocker",
        },
        "identity state",
    )
    dynamic_paths = (
        ("campaign_inputs", "contract_sha256"),
        ("campaign_inputs", "prepared_inputs_sha256"),
        ("campaign_inputs", "prepare_source_sha256"),
        ("emitter", "source_commit"),
        ("static_pipeline", "source_commit"),
        ("static_pipeline", "compiler_identity"),
        ("auto_routing", "source_commit"),
        ("auto_routing", "plan_identity"),
        ("auto_routing", "analyzer_identity"),
        ("auto_routing", "evidence_identity"),
        ("static_facade", "source_commit"),
        ("static_facade", "source_set_sha256"),
        ("private_family", "source_sha256"),
        ("private_family", "promotion_state"),
        ("private_family", "discovery_authorization_sha256"),
        ("runner", "source_commit"),
        ("runner", "source_set_sha256"),
        ("runner", "source_archive_sha256"),
        ("runner", "analyzer_source_sha256"),
        ("runner", "controller_source_sha256"),
        ("runner", "prepare_source_sha256"),
        ("runner", "identity_renderer_source_sha256"),
    )
    require(
        all(template[parent][field] is None for parent, field in dynamic_paths)
        and all(
            value is None
            for platform in template["platform_artifacts"].values()
            for field, value in platform.items()
            if field != "host_id"
        )
        and all(
            projection["file_sha256"] is None
            for projection in template["campaign_inputs"]["projections"].values()
        ),
        "identity template dynamic fields are not null",
    )
    require(
        template["private_family"]["discovery_authorization_schema"]
        == DISCOVERY_AUTHORIZATION_SCHEMA
        and template["private_family"]["evidence_identity_algorithm"]
        == "sha256"
        and template["private_family"]["evidence_identity_raw_digest_order"]
        == [
            "domain_bytes",
            "campaign_contract_sha256",
            "analyzer_source_sha256",
            "discovery_authorization_file_sha256",
        ]
        and template["auto_routing"]["family_selector"] == 13
        and template["auto_routing"]["minimum_literal_bytes"] == 6
        and template["auto_routing"]["maximum_literal_bytes"] == 32
        and template["auto_routing"]["minimum_window_bytes"] == 65_536
        and template["auto_routing"]["portable_prefix_candidate_starts"]
        == 256
        and template["runner"]["repetitions"] == 6
        and template["runner"]["target_elapsed_ns"] == 600_000_000
        and template["runner"]["calibration_floor_elapsed_ns"] == 50_000_000
        and template["runner"]["calibration_anchor_samples"] == 3
        and template["runner"]["calibration_iteration_selection"]
        == "fastest-same-iteration-anchor-per-variant-then-maximum"
        and template["runner"]["macos_super_class_wait_timeout_ns"]
        == 5_000_000_000
        and template["runner"]["minimum_elapsed_ns"] == 400_000_000
        and template["runner"]["calibrate_both_variants"] is True,
        "identity template authority changed",
    )
    return template


def load_prepared_inputs(
    directory: Path, template: Mapping[str, Any]
) -> tuple[Mapping[str, Any], str]:
    require(
        directory.is_absolute() and directory.is_dir(),
        "prepared-input directory must be an absolute directory",
    )
    require(
        {entry.name for entry in os.scandir(directory)} == PREPARED_FILENAMES,
        "prepared-input directory is not the exact closed output set",
    )
    path = directory / "prepared-inputs.json"
    encoded = read_regular(path, 128 << 10, readonly=True)
    file_identity = sha256(encoded)
    root = exact_keys(
        json.loads(encoded),
        {"schema", "payload_sha256", "payload"},
        "prepared inputs",
    )
    payload = root["payload"]
    require(
        root["schema"] == PREPARED_SCHEMA
        and is_hex(root["payload_sha256"])
        and root["payload_sha256"] == sha256(canonical_bytes(payload)),
        "prepared-input envelope changed",
    )
    exact_keys(
        payload,
        {
            "campaign_contract_sha256",
            "campaign_contract_schema",
            "result_blind",
            "inputs",
            "source_authority",
            "projections",
            "projection_summaries",
            "object_candidates",
            "literal_dispositions",
            "backend",
        },
        "prepared-input payload",
    )
    require(
        payload["campaign_contract_sha256"] == CONTRACT_SHA256
        and payload["campaign_contract_schema"] == CONTRACT_SCHEMA
        and payload["result_blind"] is True,
        "prepared inputs bind a different campaign",
    )
    exact_keys(
        payload["inputs"],
        {
            "corpus_files",
            "benchmark_results",
            "rebar_files",
            "network",
            "result_derived_selection",
            "result_derived_exclusions",
        },
        "prepared input sources",
    )
    require(
        payload["inputs"]
        == {
            "corpus_files": [],
            "benchmark_results": [],
            "rebar_files": [],
            "network": False,
            "result_derived_selection": False,
            "result_derived_exclusions": False,
        },
        "prepared inputs are not result-blind",
    )
    exact_keys(
        payload["source_authority"],
        {
            "learned_freeze",
            "learned_generator",
            "long_policy_freeze",
            "long_policy_derivation",
            "selector_contract",
        },
        "prepared source authority",
    )
    for name, authority in payload["source_authority"].items():
        exact_keys(authority, {"path", "sha256"}, f"prepared authority {name}")
        require(
            isinstance(authority["path"], str)
            and is_hex(authority["sha256"]),
            f"prepared authority {name} is malformed",
        )
    require(
        {
            name: authority["sha256"]
            for name, authority in payload["source_authority"].items()
        }
        == {
            "learned_freeze": template["campaign_inputs"][
                "learned_freeze_sha256"
            ],
            "learned_generator": template["campaign_inputs"][
                "learned_generator_sha256"
            ],
            "long_policy_freeze": template["campaign_inputs"][
                "long_policy_freeze_sha256"
            ],
            "long_policy_derivation": template["campaign_inputs"][
                "long_policy_derivation_sha256"
            ],
            "selector_contract": template["campaign_inputs"][
                "selector_contract_sha256"
            ],
        },
        "prepared source authority hashes changed",
    )
    exact_keys(
        payload["projections"],
        {
            "universal_full",
            "universal_timed",
            "long_policy_full",
            "long_policy_timed",
        },
        "prepared projections",
    )
    projection_paths = {
        "universal_full": "universal-full.ndjson",
        "universal_timed": "universal-timed.ndjson",
        "long_policy_full": "long-policy-full.ndjson",
        "long_policy_timed": "long-policy-timed.ndjson",
    }
    for name, expected in template["campaign_inputs"]["projections"].items():
        receipt = payload["projections"][name]
        exact_keys(
            receipt,
            {"path", "schema", "rows", "projection_digest", "file_sha256"},
            f"prepared projection {name}",
        )
        require(
            receipt["path"] == projection_paths[name]
            and receipt["schema"] == expected["schema"]
            and receipt["rows"] == expected["rows"]
            and receipt["projection_digest"] == expected["projection_digest"]
            and is_hex(receipt["file_sha256"])
            and file_sha(directory / receipt["path"]) == receipt["file_sha256"],
            f"prepared projection {name} changed",
        )
    objects = payload["object_candidates"]
    dispositions = payload["literal_dispositions"]
    exact_keys(
        objects,
        {
            "path",
            "schema",
            "file_sha256",
            "payload_sha256",
            "candidate_count",
            "source_construction",
            "candidate_domain_hex",
        },
        "prepared object candidates",
    )
    exact_keys(
        dispositions,
        {
            "path",
            "schema",
            "file_sha256",
            "payload_sha256",
            "literal_count",
            "eligible_literal_count",
            "ineligible_literal_count",
        },
        "prepared literal dispositions",
    )
    require(
        objects["path"] == "object-candidates.json"
        and objects["schema"] == OBJECT_SCHEMA
        and objects["file_sha256"] == OBJECT_SHA256
        and objects["payload_sha256"] == OBJECT_PAYLOAD_SHA256
        and objects["candidate_count"] == 808
        and objects["source_construction"] == "canonical-byte-escaped-exact"
        and objects["candidate_domain_hex"]
        == (
            "4652452d5345415243482d54414733302d5155414c494649434154494f"
            "4e2d43414e4449444154450001"
        )
        and file_sha(directory / objects["path"]) == OBJECT_SHA256
        and dispositions["path"] == "literal-dispositions.json"
        and dispositions["schema"] == DISPOSITION_SCHEMA
        and dispositions["file_sha256"] == DISPOSITION_SHA256
        and dispositions["payload_sha256"] == DISPOSITION_PAYLOAD_SHA256
        and dispositions["literal_count"] == 922
        and dispositions["eligible_literal_count"] == 808
        and dispositions["ineligible_literal_count"] == 114
        and file_sha(directory / dispositions["path"])
        == DISPOSITION_SHA256,
        "prepared object/disposition authority changed",
    )
    summary = payload["projection_summaries"]
    exact_keys(
        summary,
        {"path", "file_sha256"},
        "prepared projection summaries",
    )
    require(
        summary["path"] == "projection-summaries.json"
        and is_hex(summary["file_sha256"])
        and file_sha(directory / summary["path"]) == summary["file_sha256"],
        "prepared projection summaries changed",
    )
    exact_keys(
        payload["backend"],
        {
            "tag",
            "name",
            "version",
            "candidate_policy",
            "family_selector",
            "portable_prefix_candidate_starts",
            "aot_magic_hex",
            "llvm",
        },
        "prepared backend",
    )
    require(
        payload["backend"]
        == {
            "tag": 30,
            "name": "AsimdV17",
            "version": "SEARCH_V17",
            "candidate_policy": 15,
            "family_selector": 13,
            "portable_prefix_candidate_starts": 256,
            "aot_magic_hex": "465245413634001e",
            "llvm": False,
        },
        "prepared backend changed",
    )
    return payload, file_identity


def intent_identity(
    contract: Mapping[str, Any],
    analyzer_sha256: str,
    discovery_authorization_sha256: str,
) -> str:
    identity = exact_keys(
        contract["private_family_authority"]["evidence_identity"],
        {"algorithm", "domain_hex", "raw_digest_order"},
        "private evidence identity",
    )
    domain_hex = identity["domain_hex"]
    require(
        identity["algorithm"] == "sha256"
        and isinstance(domain_hex, str)
        and len(domain_hex) > 0
        and len(domain_hex) % 2 == 0
        and all(character in "0123456789abcdef" for character in domain_hex)
        and identity["raw_digest_order"]
        == [
            "domain_bytes",
            "campaign_contract_sha256",
            "analyzer_source_sha256",
            "discovery_authorization_file_sha256",
        ],
        "private evidence identity formula changed",
    )
    return sha256(
        bytes.fromhex(domain_hex)
        + bytes.fromhex(CONTRACT_SHA256)
        + bytes.fromhex(analyzer_sha256)
        + bytes.fromhex(discovery_authorization_sha256)
    )


def validate_family_tuple(
    value: Any, manifest_identity: str, context: str
) -> Mapping[str, Any]:
    family = exact_keys(value, FAMILY_TUPLE_FIELDS, context)
    integer_fields = FAMILY_TUPLE_FIELDS - {
        "little_endian",
        "manifest_identity",
    }
    require(
        all(
            isinstance(family[field], int)
            and not isinstance(family[field], bool)
            and 0 <= family[field] < 1 << 64
            for field in integer_fields
        )
        and family["little_endian"] is True
        and family["manifest_identity"] == manifest_identity
        and family["backend_version"] == 30
        and family["family_selector"] == 13
        and family["minimum_literal_bytes"] == 6
        and family["maximum_literal_bytes"] == 32
        and family["minimum_window_bytes"] == 65_536
        and family["portable_prefix_candidate_starts"] == 256,
        f"{context}: tuple changed",
    )
    return family


def load_discovery_authorization(
    repo: Path,
    path: Path,
    expected_sha256: str,
    contract: Mapping[str, Any],
    prepared_sha256: str,
    prepare_sha256: str,
    analyzer_sha256: str,
) -> tuple[Mapping[str, Any], str]:
    require(path.is_absolute(), "discovery authorization path must be absolute")
    require(
        is_hex(expected_sha256),
        "reviewed discovery authorization SHA is malformed",
    )
    encoded = read_regular(path, 1 << 20, readonly=True)
    file_identity = sha256(encoded)
    require(
        file_identity == expected_sha256,
        "discovery authorization differs from its reviewed SHA-256",
    )
    root = exact_keys(
        json.loads(encoded),
        {"schema", "payload_sha256", "payload"},
        "discovery authorization",
    )
    payload = exact_keys(
        root["payload"],
        DISCOVERY_AUTHORIZATION_FIELDS,
        "discovery authorization payload",
    )
    authority = exact_keys(
        contract["private_family_authority"]["discovery_authorization"],
        {
            "schema",
            "payload_sha256_rule",
            "decision",
            "qualification",
        },
        "contract discovery authorization",
    )
    require(
        root["schema"] == DISCOVERY_AUTHORIZATION_SCHEMA
        and root["schema"] == authority["schema"]
        and authority["payload_sha256_rule"]
        == (
            "sha256 of compact canonical JSON payload bytes with sorted "
            "object keys, ASCII escaping, and no trailing newline"
        )
        and is_hex(root["payload_sha256"])
        and root["payload_sha256"] == sha256(canonical_bytes(payload)),
        "discovery authorization envelope changed",
    )
    exact_keys(
        payload["family_common"],
        {"backend", "compiler", "wire", "envelope"},
        "discovery family common",
    )
    backend = exact_keys(
        payload["family_common"]["backend"],
        {"name", "tag", "version", "candidate_policy", "llvm"},
        "discovery family backend",
    )
    compiler = exact_keys(
        payload["family_common"]["compiler"],
        {"identity"},
        "discovery family compiler",
    )
    wire = exact_keys(
        payload["family_common"]["wire"],
        {"aot_magic_hex", "static_abi", "output", "link_interface_schema"},
        "discovery family wire",
    )
    envelope = exact_keys(
        payload["family_common"]["envelope"],
        {
            "family_selector",
            "minimum_literal_bytes",
            "maximum_literal_bytes",
            "minimum_window_bytes",
            "portable_prefix_candidate_starts",
        },
        "discovery family envelope",
    )
    decision = exact_keys(
        payload["decision"],
        {
            "private_projection",
            "production_projection",
            "pre_result_intent",
            "analyzer_not_deployment_authority",
            "targets_one_class",
            "rebar_permitted",
            "result_derived_exclusions",
        },
        "discovery decision",
    )
    qualification = exact_keys(
        payload["qualification"],
        {
            "required_fragment_count",
            "required_strata",
            "long_policy_gate_scope",
        },
        "discovery qualification",
    )
    revision = payload["discovery_runner_revision"]
    require(
        payload["contract_schema"] == CONTRACT_SCHEMA
        and payload["campaign_contract_sha256"] == CONTRACT_SHA256
        and payload["analyzer_source_sha256"] == analyzer_sha256
        and payload["prepared_inputs_sha256"] == prepared_sha256
        and payload["object_candidate_manifest_schema"] == OBJECT_SCHEMA
        and payload["object_candidate_manifest_sha256"] == OBJECT_SHA256
        and payload["object_candidate_manifest_payload_sha256"]
        == OBJECT_PAYLOAD_SHA256
        and payload["literal_dispositions_schema"] == DISPOSITION_SCHEMA
        and payload["literal_dispositions_sha256"] == DISPOSITION_SHA256
        and payload["literal_dispositions_payload_sha256"]
        == DISPOSITION_PAYLOAD_SHA256
        and payload["prepare_source_sha256"] == prepare_sha256
        and is_hex(revision, 40)
        and all(
            is_hex(payload[field])
            for field in (
                "discovery_runner_source_sha256",
                "discovery_source_archive_sha256",
                "discovery_identity_sha256",
                "discovery_private_family_source_sha256",
            )
        )
        and compiler["identity"]
        == compiler_identity(
            revision, payload["discovery_source_archive_sha256"]
        )
        and backend
        == {
            "name": "AsimdV17",
            "tag": 30,
            "version": "SEARCH_V17",
            "candidate_policy": 15,
            "llvm": False,
        }
        and wire
        == {
            "aot_magic_hex": "465245413634001e",
            "static_abi": "fre-aot-static-search-span-v1",
            "output": "Span",
            "link_interface_schema": (
                "fre.aot.search-span-family-qualification-final-image-glue.v1"
            ),
        }
        and envelope
        == {
            "family_selector": 13,
            "minimum_literal_bytes": 6,
            "maximum_literal_bytes": 32,
            "minimum_window_bytes": 65_536,
            "portable_prefix_candidate_starts": 256,
        }
        and decision == authority["decision"]
        and qualification == authority["qualification"],
        "discovery authorization identity or decision changed",
    )
    targets = exact_keys(
        payload["targets"], set(PLATFORMS), "discovery targets"
    )
    for key, platform in PLATFORMS.items():
        target = exact_keys(
            targets[key],
            DISCOVERY_TARGET_FIELDS,
            f"discovery target {key}",
        )
        require(
            target["host_id"] == platform["host_id"]
            and target["target_os"] == platform["target_os"]
            and target["target_arch"] == platform["target_arch"]
            and is_hex(target["manifest_identity"])
            and target["discovery_build_receipt_schema"]
            == BUILD_RECEIPT_SCHEMA
            and is_hex(target["discovery_build_receipt_sha256"]),
            f"discovery target {key} changed",
        )
        validate_family_tuple(
            target["family_tuple"],
            target["manifest_identity"],
            f"discovery family tuple {key}",
        )
    historical_archive = archive_sha256(repo, revision)
    require(
        historical_archive == payload["discovery_source_archive_sha256"],
        "discovery source archive differs from authorization",
    )
    require(
        git(repo, "cat-file", "-t", revision) == b"commit\n",
        "discovery revision is not a commit",
    )
    historical_source = git(
        repo, "show", f"{revision}:{PRIVATE_SOURCE_RELATIVE}"
    )
    require(
        sha256(historical_source)
        == payload["discovery_private_family_source_sha256"]
        and historical_source.decode("utf-8").count(PRIVATE_CONSTRUCTOR) == 0,
        "discovery revision did not have an empty private family table",
    )
    return payload, file_identity


def render(
    mode: str,
    repo: Path,
    prepared_directory: Path,
    output: Path,
    discovery_arguments: Sequence[str],
) -> Mapping[str, Any]:
    require(mode in {"discovery", "sealed"}, "unknown render mode")
    revision = authenticate_clean_repo(repo)
    directory = repo / DIRECTORY_RELATIVE
    contract = load_contract(directory)
    template = load_template(directory)
    prepared, prepared_sha256 = load_prepared_inputs(
        prepared_directory, template
    )
    archive = archive_sha256(repo)
    source_set = source_set_sha256(directory)
    analyzer_sha256 = sha256(
        read_regular(directory / "analyze_fragments.py", 1 << 20)
    )
    controller_sha256 = sha256(
        read_regular(directory / "run_shards.py", 1 << 20)
    )
    prepare_sha256 = sha256(
        read_regular(directory / "prepare_inputs.py", 1 << 20)
    )
    renderer_sha256 = sha256(read_regular(Path(__file__).resolve(), 1 << 20))
    private_source_path = repo / PRIVATE_SOURCE_RELATIVE
    private_source = read_regular(private_source_path, 1 << 18)
    private_source_text = private_source.decode("utf-8")
    evidence: str | None = None
    discovery_authorization_sha256: str | None = None
    authorization: Mapping[str, Any] | None = None
    if mode == "discovery":
        require(
            not discovery_arguments
            and private_source_text.count(PRIVATE_CONSTRUCTOR) == 0,
            "discovery mode requires the exact empty private family state",
        )
    else:
        require(
            len(discovery_arguments) == 2,
            "sealed mode requires DISCOVERY_AUTHORIZATION AUTHORIZATION_SHA",
        )
        authorization, discovery_authorization_sha256 = (
            load_discovery_authorization(
                repo,
                Path(discovery_arguments[0]),
                discovery_arguments[1],
                contract,
                prepared_sha256,
                prepare_sha256,
                analyzer_sha256,
            )
        )
        evidence = intent_identity(
            contract,
            analyzer_sha256,
            discovery_authorization_sha256,
        )
        discovery_revision = authorization["discovery_runner_revision"]
        require(
            authorization["discovery_runner_source_sha256"] == source_set,
            "private-only promotion changed the runner source set",
        )
        parents = (
            git(repo, "rev-list", "--parents", "-n", "1", "HEAD")
            .decode()
            .split()
        )
        changed = set(
            git(
                repo,
                "diff-tree",
                "--no-commit-id",
                "--name-only",
                "-r",
                "HEAD",
            )
            .decode()
            .splitlines()
        )
        require(
            parents == [revision, discovery_revision]
            and changed == {PRIVATE_SOURCE_RELATIVE}
            and private_source_text.count(PRIVATE_CONSTRUCTOR) == 2,
            "sealed identity requires one direct, private-source-only promotion commit",
        )
    identity = deepcopy(template)
    identity["campaign_inputs"].update(
        {
            "contract_sha256": CONTRACT_SHA256,
            "prepared_inputs_sha256": prepared_sha256,
            "prepare_source_sha256": prepare_sha256,
        }
    )
    for name, projection in prepared["projections"].items():
        identity["campaign_inputs"]["projections"][name][
            "file_sha256"
        ] = projection["file_sha256"]
    for component in (
        "emitter",
        "static_pipeline",
        "auto_routing",
        "static_facade",
        "runner",
    ):
        identity[component]["source_commit"] = revision
    identity["static_pipeline"]["compiler_identity"] = compiler_identity(
        revision, archive
    )
    identity["auto_routing"].update(
        {
            "plan_identity": CONTRACT_SHA256,
            "analyzer_identity": analyzer_sha256,
            "evidence_identity": evidence,
        }
    )
    identity["static_facade"]["source_set_sha256"] = source_set
    identity["private_family"].update(
        {
            "source_sha256": sha256(private_source),
            "discovery_authorization_sha256": (
                discovery_authorization_sha256
            ),
            "promotion_state": (
                "empty-object-only-discovery"
                if mode == "discovery"
                else "target-conditional-selector-13-private-qualification"
            ),
        }
    )
    for key in PLATFORMS:
        if mode == "sealed":
            require(
                authorization is not None,
                "sealed authorization disappeared",
            )
            target = authorization["targets"][key]
            identity["platform_artifacts"][key].update(
                {
                    "manifest_identity": target["manifest_identity"],
                    "discovery_build_receipt_sha256": target[
                        "discovery_build_receipt_sha256"
                    ],
                }
            )
    identity["runner"].update(
        {
            "source_set_sha256": source_set,
            "source_archive_sha256": archive,
            "analyzer_source_sha256": analyzer_sha256,
            "controller_source_sha256": controller_sha256,
            "prepare_source_sha256": prepare_sha256,
            "identity_renderer_source_sha256": renderer_sha256,
        }
    )
    identity["state"] = {
        "heldout_materialized": False,
        "development_timing_permitted": mode == "sealed",
        "blocker": (
            None
            if mode == "sealed"
            else "target-conditional selector-13 private family source promotion is unresolved"
        ),
    }
    encoded = pretty_bytes(identity)
    descriptor = os.open(
        output,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o444,
    )
    with os.fdopen(descriptor, "wb", closefd=True) as destination:
        destination.write(encoded)
        destination.flush()
        os.fsync(destination.fileno())
    return {
        "schema": IDENTITY_SCHEMA,
        "mode": mode,
        "identity_sha256": sha256(encoded),
        "runner_revision": revision,
        "runner_source_sha256": source_set,
        "source_archive_sha256": archive,
        "prepared_inputs_sha256": prepared_sha256,
        "discovery_authorization_sha256": (
            discovery_authorization_sha256
        ),
        "evidence_identity": evidence,
        "private_family_source_sha256": sha256(private_source),
        "development_timing_permitted": mode == "sealed",
        "output": str(output),
    }


def main(argv: Sequence[str]) -> None:
    require(
        len(argv) >= 4,
        "usage: render_identity.py (discovery|sealed) REPO "
        "PREPARED_INPUT_DIRECTORY [DISCOVERY_AUTHORIZATION AUTHORIZATION_SHA] "
        "NEW_OUTPUT",
    )
    mode = argv[0]
    expected_length = 4 if mode == "discovery" else 6
    require(len(argv) == expected_length, "identity renderer argument count changed")
    repo = Path(argv[1]).resolve(strict=True)
    prepared = Path(argv[2]).resolve(strict=True)
    output = Path(argv[-1]).resolve()
    summary = render(mode, repo, prepared, output, argv[3:-1])
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (
        OSError,
        UnicodeError,
        ValueError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
        Refusal,
    ) as error:
        print(f"search-tag30-render-identity: {error}", file=sys.stderr)
        raise SystemExit(1)
