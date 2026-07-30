#!/usr/bin/env python3
"""Create the exact result-blind inputs for the Search tag-30 campaign."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Iterable, Mapping, Sequence


DIRECTORY_RELATIVE = "research/aot/search-tag30-qualification-runner"
CONTRACT_RELATIVE = f"{DIRECTORY_RELATIVE}/campaign-contract-v1.json"
CONTRACT_SCHEMA = "fre.aot.search-tag30-qualification-campaign-contract.v1"
# Rotated whenever the immutable campaign contract changes.
CONTRACT_SHA256 = (
    "f5a3319b1178ea97766b735bc39b589a6a1a33e8cc9257a947ea9feff7c5f702"
)
LEARNED_FREEZE_RELATIVE = (
    "research/aot/search-tag30-learned-continuation-v1/freeze-v1.json"
)
LEARNED_FREEZE_SHA256 = (
    "367ad3655ec2f70d4a8173f68df76013fdf32dd95e07d1ebeeedb14c580b817f"
)
LEARNED_GENERATOR_RELATIVE = (
    "research/aot/search-tag30-learned-continuation-v1/"
    "generate_projection.py"
)
LEARNED_GENERATOR_SHA256 = (
    "63a32488f9ac108bcc6cc5b245c4bbaea59056703787c3f40244e7b62e0b203e"
)
LONG_FREEZE_RELATIVE = (
    "research/aot/search-tag30-long-input-policy-v1/freeze-v1.json"
)
LONG_FREEZE_SHA256 = (
    "70123d2c2068d9260d3a8d3face867bc01f42dbd91e82a686bf06af11b0babbb"
)
LONG_DERIVATION_RELATIVE = (
    "research/aot/search-tag30-long-input-policy-v1/derive_projection.py"
)
LONG_DERIVATION_SHA256 = (
    "b8690387a15655da415466943ff93726b828146e7c849266aa35907203b03671"
)
SELECTOR_RELATIVE = (
    "research/aot/search-phase-unique-selector-v1/selector-contract-v1.json"
)
SELECTOR_SHA256 = (
    "38ca5ebc1b239b541afcf9eeb679bf8b156c8690e7422a96f69a9457a155daf0"
)
UNIVERSAL_FULL_DIGEST = (
    "0326944c2c95dfd10740d2ea0a72c910dd1a03df8c16e3a2180391d069841480"
)
UNIVERSAL_TIMED_DIGEST = (
    "a92a59554188a82b6e7c49833dda599aa7d87014ae6815ba9fbe0f5502b31a4c"
)
LONG_FULL_DIGEST = (
    "c912b402244ff9814fe6160f9f5a117d7b253af5ff35ee69a78a6250aae94561"
)
LONG_TIMED_DIGEST = (
    "b3093f9fed70fd500852742d18994fce80d4a144cb9b9cbaac4ad0e7f84ccffd"
)
UNIVERSAL_FULL_ROWS = 123_424
UNIVERSAL_TIMED_ROWS = 3_078
LONG_FULL_ROWS = 123_424
LONG_TIMED_ROWS = 1_458
UNIQUE_LITERALS = 922
ELIGIBLE_LITERALS = 808
INELIGIBLE_LITERALS = 114
CANDIDATE_DOMAIN = b"FRE-SEARCH-TAG30-QUALIFICATION-CANDIDATE\0\x01"
OBJECT_SCHEMA = "fre.aot.search-tag30-qualification-object-candidates.v1"
DISPOSITION_SCHEMA = (
    "fre.aot.search-tag30-qualification-literal-dispositions.v1"
)
PREPARED_INPUTS_SCHEMA = "fre.aot.search-tag30-prepared-inputs.v1"
SOURCE_CONSTRUCTION = "canonical-byte-escaped-exact"
MAXIMUM_JSON_LINE = 32 * 1024


class Refusal(RuntimeError):
    """A frozen source, projection, or structural disposition changed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def sha256(encoded: bytes) -> str:
    return hashlib.sha256(encoded).hexdigest()


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def canonical_sha(value: Any) -> str:
    return sha256(canonical_bytes(value))


def pretty_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode()


def regular_file(path: Path, maximum: int = 2 * 1024 * 1024) -> bytes:
    status = path.lstat()
    require(
        stat.S_ISREG(status.st_mode)
        and not path.is_symlink()
        and 0 < status.st_size <= maximum,
        f"not one bounded regular file: {path}",
    )
    return path.read_bytes()


def file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def write_new(path: Path, encoded: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o444,
    )
    with os.fdopen(descriptor, "wb", closefd=True) as output:
        output.write(encoded)
        output.flush()
        os.fsync(output.fileno())


def envelope(schema: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": schema,
        "payload_sha256": canonical_sha(payload),
        "payload": payload,
    }


def load_module(name: str, path: Path, expected_sha256: str) -> ModuleType:
    require(
        sha256(regular_file(path)) == expected_sha256,
        f"{path.name} source changed",
    )
    specification = importlib.util.spec_from_file_location(name, path)
    require(
        specification is not None and specification.loader is not None,
        f"cannot load {path}",
    )
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


def authenticate_repo(repo: Path) -> Mapping[str, Any]:
    exact_files = (
        (LEARNED_FREEZE_RELATIVE, LEARNED_FREEZE_SHA256),
        (LEARNED_GENERATOR_RELATIVE, LEARNED_GENERATOR_SHA256),
        (LONG_FREEZE_RELATIVE, LONG_FREEZE_SHA256),
        (LONG_DERIVATION_RELATIVE, LONG_DERIVATION_SHA256),
        (SELECTOR_RELATIVE, SELECTOR_SHA256),
    )
    for relative, expected in exact_files:
        require(
            sha256(regular_file(repo / relative)) == expected,
            f"frozen input changed: {relative}",
        )
    encoded = regular_file(repo / CONTRACT_RELATIVE, 128 * 1024)
    require(sha256(encoded) == CONTRACT_SHA256, "campaign contract changed")
    contract = json.loads(encoded)
    require(
        isinstance(contract, dict)
        and contract.get("schema") == CONTRACT_SCHEMA
        and contract.get("result_blind") is True
        and contract.get("rebar_inputs") == []
        and contract.get("result_derived_selection") is False
        and contract.get("result_derived_exclusions") is False,
        "campaign contract authority changed",
    )
    return contract


def projection_rows(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("rb") as source:
        for line_number, line in enumerate(source, 1):
            require(
                line.endswith(b"\n")
                and 1 < len(line) <= MAXIMUM_JSON_LINE + 1,
                f"noncanonical projection line {line_number}",
            )
            row = json.loads(line)
            require(
                canonical_bytes(row) + b"\n" == line,
                f"projection row is not canonical: {line_number}",
            )
            yield row


def semantic_identity(literal: bytes) -> str:
    return sha256(CANDIDATE_DOMAIN + literal)


def collect_dispositions(
    full_path: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    seen: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    row_count = 0
    for row in projection_rows(full_path):
        row_count += 1
        require(
            row.get("schema")
            == "fre.aot.search-tag30-learned-continuation-projection.v1",
            "universal projection schema changed",
        )
        literal = bytes.fromhex(row["literal_hex"])
        identity = semantic_identity(literal)
        record = {
            "semantic_candidate_sha256": identity,
            "literal_hex": row["literal_hex"],
            "literal_sha256": row["literal_sha256"],
            "literal_bytes": row["literal_bytes"],
            "selected_offsets": row["selected_offsets"],
            "selector_eligible": row["selector_eligible"],
            "expected_compiler_disposition": row[
                "expected_compiler_disposition"
            ],
        }
        literal_sha = row["literal_sha256"]
        if literal_sha not in seen:
            seen[literal_sha] = record
            order.append(literal_sha)
        else:
            require(
                seen[literal_sha] == record,
                "one literal has inconsistent tag30 disposition",
            )
    require(row_count == UNIVERSAL_FULL_ROWS, "full projection count changed")
    dispositions = [seen[literal_sha] for literal_sha in order]
    eligible = [
        {
            "semantic_candidate_sha256": record[
                "semantic_candidate_sha256"
            ],
            "literal_hex": record["literal_hex"],
            "literal_sha256": record["literal_sha256"],
            "literal_bytes": record["literal_bytes"],
        }
        for record in dispositions
        if record["selector_eligible"]
    ]
    require(
        len(dispositions) == UNIQUE_LITERALS
        and len(eligible) == ELIGIBLE_LITERALS
        and len(dispositions) - len(eligible) == INELIGIBLE_LITERALS
        and all(
            record["expected_compiler_disposition"]
            == (
                "tag30-object"
                if record["selector_eligible"]
                else "structural-refusal"
            )
            for record in dispositions
        ),
        "tag30 literal disposition set changed",
    )
    return dispositions, eligible


def provenance_payload() -> dict[str, Any]:
    return {
        "learned_freeze_sha256": LEARNED_FREEZE_SHA256,
        "learned_generator_sha256": LEARNED_GENERATOR_SHA256,
        "long_policy_freeze_sha256": LONG_FREEZE_SHA256,
        "long_policy_derivation_sha256": LONG_DERIVATION_SHA256,
        "selector_contract_sha256": SELECTOR_SHA256,
        "universal_full_projection_sha256": UNIVERSAL_FULL_DIGEST,
        "universal_timed_projection_sha256": UNIVERSAL_TIMED_DIGEST,
        "long_policy_full_projection_sha256": LONG_FULL_DIGEST,
        "long_policy_timed_projection_sha256": LONG_TIMED_DIGEST,
        "timing_permitted": False,
        "timing_feedback_permitted": False,
        "external_inputs": [],
        "benchmark_results": [],
        "rebar_inputs": [],
        "network": False,
        "result_derived_selection": False,
        "result_derived_exclusions": False,
        "backend_tag": 30,
        "backend_version": "SEARCH_V17",
        "candidate_policy": 15,
        "backend_name": "AsimdV17",
        "aot_magic_hex": "465245413634001e",
        "llvm": False,
        "source_construction": SOURCE_CONSTRUCTION,
        "candidate_domain_hex": CANDIDATE_DOMAIN.hex(),
    }


def projection_receipt(
    path: Path, rows: int, digest: str, schema: str
) -> Mapping[str, Any]:
    return {
        "path": path.name,
        "schema": schema,
        "rows": rows,
        "projection_digest": digest,
        "file_sha256": file_sha(path),
    }


def prepare(repo: Path, output: Path) -> Mapping[str, Any]:
    contract = authenticate_repo(repo)
    require(not output.exists(), f"refusing existing output: {output}")
    learned = load_module(
        "_fre_search_tag30_prepare_learned",
        repo / LEARNED_GENERATOR_RELATIVE,
        LEARNED_GENERATOR_SHA256,
    )
    long_policy = load_module(
        "_fre_search_tag30_prepare_long",
        repo / LONG_DERIVATION_RELATIVE,
        LONG_DERIVATION_SHA256,
    )
    output.mkdir(mode=0o755)
    universal_full = output / "universal-full.ndjson"
    universal_timed = output / "universal-timed.ndjson"
    long_full = output / "long-policy-full.ndjson"
    long_timed = output / "long-policy-timed.ndjson"
    learned_summary = learned.generate(
        repo, universal_full, universal_timed
    )
    long_summary = long_policy.generate(repo, long_full, long_timed)
    require(
        learned_summary["full_projection"]["rows"] == UNIVERSAL_FULL_ROWS
        and learned_summary["full_projection"]["sha256"]
        == UNIVERSAL_FULL_DIGEST
        and learned_summary["timed_projection"]["rows"]
        == UNIVERSAL_TIMED_ROWS
        and learned_summary["timed_projection"]["sha256"]
        == UNIVERSAL_TIMED_DIGEST
        and learned_summary["inputs"]
        == {
            "corpus_files": [],
            "benchmark_results": [],
            "rebar_files": [],
            "network": False,
        },
        "universal projection differs from the tag30 freeze",
    )
    require(
        long_summary["full_projection"]["rows"] == LONG_FULL_ROWS
        and long_summary["full_projection"]["sha256"] == LONG_FULL_DIGEST
        and long_summary["timed_projection"]["rows"] == LONG_TIMED_ROWS
        and long_summary["timed_projection"]["sha256"] == LONG_TIMED_DIGEST
        and long_summary["inputs"]
        == {
            "corpus_files": [],
            "benchmark_results": [],
            "rebar_files": [],
            "network": False,
            "result_derived_selection": False,
            "result_derived_exclusions": False,
        },
        "long-policy projection differs from the tag30 freeze",
    )
    dispositions, eligible = collect_dispositions(universal_full)
    object_payload = provenance_payload()
    object_payload.update(
        {
            "candidate_count": len(eligible),
            "candidates": eligible,
        }
    )
    object_manifest = envelope(OBJECT_SCHEMA, object_payload)
    object_bytes = pretty_bytes(object_manifest)
    object_path = output / "object-candidates.json"
    write_new(object_path, object_bytes)
    disposition_payload = provenance_payload()
    disposition_payload.update(
        {
            "literal_count": len(dispositions),
            "eligible_literal_count": len(eligible),
            "ineligible_literal_count": len(dispositions) - len(eligible),
            "dispositions": dispositions,
        }
    )
    disposition_manifest = envelope(
        DISPOSITION_SCHEMA, disposition_payload
    )
    disposition_bytes = pretty_bytes(disposition_manifest)
    disposition_path = output / "literal-dispositions.json"
    write_new(disposition_path, disposition_bytes)
    summary_path = output / "projection-summaries.json"
    summary_bytes = pretty_bytes(
        {"universal": learned_summary, "long_policy": long_summary}
    )
    write_new(summary_path, summary_bytes)
    projection_schema = (
        "fre.aot.search-tag30-learned-continuation-projection.v1"
    )
    long_schema = "fre.aot.search-tag30-long-input-policy-projection.v1"
    payload = {
        "campaign_contract_sha256": CONTRACT_SHA256,
        "campaign_contract_schema": CONTRACT_SCHEMA,
        "result_blind": True,
        "inputs": {
            "corpus_files": [],
            "benchmark_results": [],
            "rebar_files": [],
            "network": False,
            "result_derived_selection": False,
            "result_derived_exclusions": False,
        },
        "source_authority": {
            "learned_freeze": {
                "path": LEARNED_FREEZE_RELATIVE,
                "sha256": LEARNED_FREEZE_SHA256,
            },
            "learned_generator": {
                "path": LEARNED_GENERATOR_RELATIVE,
                "sha256": LEARNED_GENERATOR_SHA256,
            },
            "long_policy_freeze": {
                "path": LONG_FREEZE_RELATIVE,
                "sha256": LONG_FREEZE_SHA256,
            },
            "long_policy_derivation": {
                "path": LONG_DERIVATION_RELATIVE,
                "sha256": LONG_DERIVATION_SHA256,
            },
            "selector_contract": {
                "path": SELECTOR_RELATIVE,
                "sha256": SELECTOR_SHA256,
            },
        },
        "projections": {
            "universal_full": projection_receipt(
                universal_full,
                UNIVERSAL_FULL_ROWS,
                UNIVERSAL_FULL_DIGEST,
                projection_schema,
            ),
            "universal_timed": projection_receipt(
                universal_timed,
                UNIVERSAL_TIMED_ROWS,
                UNIVERSAL_TIMED_DIGEST,
                projection_schema,
            ),
            "long_policy_full": projection_receipt(
                long_full, LONG_FULL_ROWS, LONG_FULL_DIGEST, long_schema
            ),
            "long_policy_timed": projection_receipt(
                long_timed, LONG_TIMED_ROWS, LONG_TIMED_DIGEST, long_schema
            ),
        },
        "projection_summaries": {
            "path": summary_path.name,
            "file_sha256": sha256(summary_bytes),
        },
        "object_candidates": {
            "path": object_path.name,
            "schema": OBJECT_SCHEMA,
            "file_sha256": sha256(object_bytes),
            "payload_sha256": object_manifest["payload_sha256"],
            "candidate_count": ELIGIBLE_LITERALS,
            "source_construction": SOURCE_CONSTRUCTION,
            "candidate_domain_hex": CANDIDATE_DOMAIN.hex(),
        },
        "literal_dispositions": {
            "path": disposition_path.name,
            "schema": DISPOSITION_SCHEMA,
            "file_sha256": sha256(disposition_bytes),
            "payload_sha256": disposition_manifest["payload_sha256"],
            "literal_count": UNIQUE_LITERALS,
            "eligible_literal_count": ELIGIBLE_LITERALS,
            "ineligible_literal_count": INELIGIBLE_LITERALS,
        },
        "backend": contract["backend"],
    }
    plan = envelope(PREPARED_INPUTS_SCHEMA, payload)
    plan_path = output / "prepared-inputs.json"
    plan_bytes = pretty_bytes(plan)
    write_new(plan_path, plan_bytes)
    for path in output.iterdir():
        require(path.is_file() and not path.is_symlink(), "output set changed")
        path.chmod(0o444)
    directory_descriptor = os.open(
        output, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    )
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)
    return {
        "output": str(output),
        "prepared_inputs_sha256": sha256(plan_bytes),
        "object_candidates_sha256": sha256(object_bytes),
        "literal_dispositions_sha256": sha256(disposition_bytes),
        "universal_full_rows": UNIVERSAL_FULL_ROWS,
        "universal_timed_rows": UNIVERSAL_TIMED_ROWS,
        "long_policy_full_rows": LONG_FULL_ROWS,
        "long_policy_timed_rows": LONG_TIMED_ROWS,
        "unique_literals": UNIQUE_LITERALS,
        "eligible_object_candidates": ELIGIBLE_LITERALS,
        "structural_refusals": INELIGIBLE_LITERALS,
        "rebar_inputs": 0,
        "benchmark_results": 0,
    }


def main(argv: Sequence[str]) -> None:
    require(
        len(argv) == 2,
        "usage: prepare_inputs.py REPO NEW_OUTPUT_DIRECTORY",
    )
    summary = prepare(
        Path(argv[0]).resolve(strict=True), Path(argv[1]).resolve()
    )
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
        print(f"search-tag30-prepare-inputs: {error}", file=sys.stderr)
        raise SystemExit(1)
