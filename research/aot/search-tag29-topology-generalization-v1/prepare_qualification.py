#!/usr/bin/env python3
"""Prepare result-blind tag-29 projection and object-candidate inputs."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Iterable


FREEZE_RELATIVE = (
    "research/aot/search-tag29-topology-generalization-v1/freeze-v1.json"
)
FREEZE_SHA256 = (
    "9f6ba2af9ff7e2296f65dc20b4386d68ddd5ea41837814a1b6b4c3ee2faf4856"
)
GENERATOR_RELATIVE = (
    "research/aot/search-tag29-topology-generalization-v1/"
    "generate_projection.py"
)
GENERATOR_SHA256 = (
    "35aacbca100dde74a2ead493ceab1197c813d37c17d5f4a9d3e62938c3a2b610"
)
SELECTOR_RELATIVE = (
    "research/aot/search-phase-unique-selector-v1/selector-contract-v1.json"
)
SELECTOR_SHA256 = (
    "38ca5ebc1b239b541afcf9eeb679bf8b156c8690e7422a96f69a9457a155daf0"
)
FULL_PROJECTION_DIGEST = (
    "5d548159e8c93d6ddb8d57847e01cc97ea2b661f736b2e8a126df6cd35cf612f"
)
TIMED_PROJECTION_DIGEST = (
    "72d85a032a90e4347be2d537c2ff11bac15016787c055332843f143da72e487f"
)
FULL_ROWS = 123_424
TIMED_ROWS = 3_078
UNIQUE_LITERALS = 922
ELIGIBLE_LITERALS = 808
INELIGIBLE_LITERALS = 114
CANDIDATE_DOMAIN = b"FRE-SEARCH-TAG29-TOPOLOGY-CANDIDATE\0\x01"
OBJECT_SCHEMA = "fre.aot.search-tag29-topology-object-candidates.v1"
DISPOSITION_SCHEMA = "fre.aot.search-tag29-topology-literal-dispositions.v1"
PLAN_SCHEMA = "fre.aot.search-tag29-topology-qualification-plan.v1"


class Refusal(RuntimeError):
    """A frozen input, projection, or structural disposition changed."""


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


def regular_file(path: Path, maximum: int = 512 * 1024 * 1024) -> bytes:
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
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(descriptor, "wb") as output:
        output.write(encoded)
        output.flush()
        os.fsync(output.fileno())


def json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode()


def envelope(schema: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": schema,
        "payload_sha256": canonical_sha(payload),
        "payload": payload,
    }


def load_generator(repo: Path) -> ModuleType:
    generator_path = repo / GENERATOR_RELATIVE
    require(
        sha256(regular_file(generator_path, 2 * 1024 * 1024))
        == GENERATOR_SHA256,
        "topology generator changed",
    )
    specification = importlib.util.spec_from_file_location(
        "_fre_search_tag29_qualification_generator", generator_path
    )
    require(
        specification is not None and specification.loader is not None,
        "cannot load topology generator",
    )
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def authenticate_repo(repo: Path) -> None:
    require(
        sha256(regular_file(repo / FREEZE_RELATIVE)) == FREEZE_SHA256,
        "topology freeze changed",
    )
    require(
        sha256(regular_file(repo / SELECTOR_RELATIVE)) == SELECTOR_SHA256,
        "selector contract changed",
    )


def literal_identity(literal: bytes) -> str:
    return sha256(CANDIDATE_DOMAIN + literal)


def projection_rows(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("rb") as source:
        for line_number, line in enumerate(source, 1):
            require(
                line.endswith(b"\n") and 1 < len(line) <= 16 * 1024,
                f"noncanonical projection line {line_number}",
            )
            row = json.loads(line)
            require(
                canonical_bytes(row) + b"\n" == line,
                f"projection row is not canonical: {line_number}",
            )
            yield row


def collect_dispositions(
    full_path: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    seen: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    row_count = 0
    for row in projection_rows(full_path):
        row_count += 1
        literal = bytes.fromhex(row["literal_hex"])
        identity = literal_identity(literal)
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
        if identity not in seen:
            seen[identity] = record
            order.append(identity)
        else:
            require(
                seen[identity] == record,
                "one literal has inconsistent selector disposition",
            )
    require(row_count == FULL_ROWS, "full projection row count changed")
    dispositions = [seen[identity] for identity in order]
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
                "tag29-object"
                if record["selector_eligible"]
                else "structural-refusal"
            )
            for record in dispositions
        ),
        "unique literal disposition counts changed",
    )
    return dispositions, eligible


def main() -> None:
    require(
        len(sys.argv) == 3,
        "usage: prepare_qualification.py REPO NEW_OUTPUT_DIRECTORY",
    )
    repo = Path(sys.argv[1]).resolve(strict=True)
    output = Path(sys.argv[2])
    require(not output.exists(), f"refusing existing output: {output}")
    authenticate_repo(repo)
    generator = load_generator(repo)
    output.mkdir(mode=0o755)
    full_path = output / "full-projection.ndjson"
    timed_path = output / "timed-projection.ndjson"
    summary = generator.generate(repo, full_path, timed_path)
    require(
        summary["full_projection"]["rows"] == FULL_ROWS
        and summary["full_projection"]["sha256"] == FULL_PROJECTION_DIGEST
        and summary["timed_projection"]["rows"] == TIMED_ROWS
        and summary["timed_projection"]["sha256"]
        == TIMED_PROJECTION_DIGEST
        and summary["inputs"]
        == {
            "corpus_files": [],
            "benchmark_results": [],
            "rebar_files": [],
            "network": False,
        },
        "generated projection differs from the freeze",
    )
    dispositions, eligible = collect_dispositions(full_path)
    object_payload = {
        "freeze_sha256": FREEZE_SHA256,
        "selector_contract_sha256": SELECTOR_SHA256,
        "full_projection_digest": FULL_PROJECTION_DIGEST,
        "timing_permitted": False,
        "timing_feedback_permitted": False,
        "external_inputs": [],
        "benchmark_results": [],
        "rebar_inputs": [],
        "network": False,
        "backend_tag": 29,
        "backend_version": "SEARCH_V16",
        "candidate_policy": 15,
        "backend_name": "AsimdV16",
        "llvm": False,
        "source_construction": "canonical-byte-escaped-exact",
        "candidate_count": len(eligible),
        "candidates": eligible,
    }
    object_manifest = envelope(OBJECT_SCHEMA, object_payload)
    object_bytes = json_bytes(object_manifest)
    object_path = output / "object-candidates.json"
    write_new(object_path, object_bytes)
    disposition_payload = {
        "freeze_sha256": FREEZE_SHA256,
        "selector_contract_sha256": SELECTOR_SHA256,
        "full_projection_digest": FULL_PROJECTION_DIGEST,
        "timing_permitted": False,
        "timing_feedback_permitted": False,
        "external_inputs": [],
        "benchmark_results": [],
        "rebar_inputs": [],
        "network": False,
        "literal_count": len(dispositions),
        "eligible_literal_count": len(eligible),
        "ineligible_literal_count": len(dispositions) - len(eligible),
        "dispositions": dispositions,
    }
    disposition_manifest = envelope(DISPOSITION_SCHEMA, disposition_payload)
    disposition_bytes = json_bytes(disposition_manifest)
    disposition_path = output / "literal-dispositions.json"
    write_new(disposition_path, disposition_bytes)
    summary_bytes = json_bytes(summary)
    summary_path = output / "projection-summary.json"
    write_new(summary_path, summary_bytes)
    plan_payload = {
        "freeze_sha256": FREEZE_SHA256,
        "generator_sha256": GENERATOR_SHA256,
        "selector_contract_sha256": SELECTOR_SHA256,
        "inputs": {
            "corpus_files": [],
            "benchmark_results": [],
            "rebar_files": [],
            "network": False,
            "result_derived_selection": False,
            "result_derived_exclusions": False,
        },
        "backend": {
            "architecture": "aarch64",
            "required_isa": "OS-usable ASIMD",
            "backend_tag": 29,
            "backend_version": "SEARCH_V16",
            "candidate_policy": 15,
            "backend_name": "AsimdV16",
            "aot_magic_hex": "465245413634001d",
            "llvm": False,
        },
        "hosts": {
            "local-apple-aarch64-asimd": "apple-aarch64-asimd",
            "zstd-eval-ec2-aarch64-asimd-sve2-vl16": (
                "c9g-aarch64-asimd-sve2"
            ),
        },
        "full_projection": {
            "path": full_path.name,
            "rows": FULL_ROWS,
            "projection_digest": FULL_PROJECTION_DIGEST,
            "file_sha256": file_sha(full_path),
        },
        "timed_projection": {
            "path": timed_path.name,
            "rows": TIMED_ROWS,
            "projection_digest": TIMED_PROJECTION_DIGEST,
            "file_sha256": file_sha(timed_path),
        },
        "projection_summary": {
            "path": summary_path.name,
            "file_sha256": sha256(summary_bytes),
        },
        "object_candidates": {
            "path": object_path.name,
            "schema": OBJECT_SCHEMA,
            "file_sha256": sha256(object_bytes),
            "payload_sha256": object_manifest["payload_sha256"],
            "candidate_count": ELIGIBLE_LITERALS,
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
        "execution": {
            "full_correctness_rows_per_host": FULL_ROWS,
            "timed_rows_per_host": TIMED_ROWS,
            "timing_repetitions": 6,
            "minimum_elapsed_ns_each_variant": 400_000_000,
            "pairing": (
                "same row and logical CPU, identical iterations, alternating "
                "portable/static order"
            ),
            "cell_ratio": (
                "sort six paired static/portable elapsed ratios; "
                "median=(ratio[2]+ratio[3])/2 without pre-rounding"
            ),
            "cell_gate": "every timed row strictly less than 0.80 on each host",
            "result_derived_exclusions": False,
        },
    }
    plan = envelope(PLAN_SCHEMA, plan_payload)
    plan_bytes = json_bytes(plan)
    plan_path = output / "qualification-plan.json"
    write_new(plan_path, plan_bytes)
    print(
        f"output={output} plan_sha256={sha256(plan_bytes)} "
        f"plan_payload_sha256={plan['payload_sha256']} "
        f"full_rows={FULL_ROWS} timed_rows={TIMED_ROWS} "
        f"unique_literals={UNIQUE_LITERALS} "
        f"eligible_object_candidates={ELIGIBLE_LITERALS} "
        "rebar_inputs=0 benchmark_results=0"
    )


if __name__ == "__main__":
    try:
        main()
    except (
        OSError,
        UnicodeError,
        ValueError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
        Refusal,
    ) as error:
        print(f"search-tag29-qualification-prepare: {error}", file=sys.stderr)
        raise SystemExit(1)
