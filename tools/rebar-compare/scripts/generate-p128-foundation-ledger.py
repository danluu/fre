#!/usr/bin/env python3
"""Generate the P128 Foundation attribution ledger from immutable evidence.

This is a qualification-only generator. Its output contains opaque point IDs,
operation shape, evidence digests, and source-row seals; it deliberately does
not emit benchmark names, patterns, fixture paths, expected values, or timing
measurements. Nothing in the runtime planner or executor imports this file.
"""

import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


SCHEMA = "fre.p128.foundation-attribution-ledger.v1"
CANDIDATE = "088bf4472f803f48c4c42e35641eb7d81f08931f"
TREE = "486e7b387e92757f1fe03c5257b8eff2c0e67b1c"
RUST_COMPARATOR = "rust-regex-1.12.4"
CONTINUATION_PLAN = "aggregate-continuation-program"
EXPECTED_SEMANTIC_PLANS: Dict[Tuple[str, str], str] = {
    ("A", "count"): CONTINUATION_PLAN,
    ("A", "count-spans"): CONTINUATION_PLAN,
    ("B", "count-spans"): CONTINUATION_PLAN,
    ("C", "count-spans"): "aggregate-many-continuation-program",
    ("D", "grep-captures"): "capture-linear-selector-uniform-participation",
    ("D", "count-captures"): "capture-linear-selector-persistent-history",
    ("protected", "count-spans"): CONTINUATION_PLAN,
}
REQUIRED_RECEIPT_KINDS: Dict[Tuple[str, str], str] = {
    ("A", "count"): "single-continuation",
    ("A", "count-spans"): "single-continuation",
    ("B", "count-spans"): "single-continuation",
    ("C", "count-spans"): "multi-continuation",
    ("D", "grep-captures"): "capture-uniform",
    ("D", "count-captures"): "capture-history",
    ("protected", "count-spans"): "single-continuation",
}

# This scope is copied exactly from the authenticated remediation plan. The
# IDs are attribution keys only; they are never an executor or planner input.
SCOPE: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    (
        "A",
        (
            "860cb8f3420b6657fa98cc76",
            "29b93502abeb3b295c5efc89",
            "f7b473ba413cc5a67a9683d3",
            "36c622e839dbbffb9d1c4daf",
            "dcbb8c4c72eaa250fe8f9464",
            "611d58abb3c4b12c64300715",
            "fa2c7c219493095b74039eb1",
            "a2d58eac1687359a4d4d02eb",
            "60d0a3282c3e50d9714eab5c",
            "16303ad3a46dcccf7139edef",
            "7e0e0650149b23f8e932ca15",
            "6dbae718df584fe60567feac",
            "8e4b5bd84654b99cc6229892",
            "e046a3b7f701247587756b0b",
            "cfcbdfcfaba9ec5fbe98ac12",
            "4db00fb4199cf904750f247b",
        ),
    ),
    (
        "B",
        (
            "24b511d8247f02cf384a62cb",
            "649c49fc2e4a6694bd7f2288",
            "70d256e2a7435f68152107da",
            "b8e43885d4cbe69186ebaec0",
            "b03e3093606ac9d5e76e1f4a",
            "883273af5a2acfe7e1535cd8",
        ),
    ),
    (
        "C",
        (
            "f5d2f665c23a014f68b4fd98",
            "f2175454cb586e9c615936b8",
            "63088fbbecf7740eb688dd03",
            "e73a23ea9ba8426d11d42302",
        ),
    ),
    (
        "D",
        (
            "316b893df6c697251fef808a",
            "1392d2f25572eccf26134456",
            "f43803891f368402e52a2440",
            "c514b04dc3b7ff886f56f4d8",
            "43fa59817f1c44d92040848e",
        ),
    ),
    ("protected", ("e860d06df5db074b6a020c4b",)),
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def scope_entries() -> Iterable[Tuple[str, str, bool]]:
    for family, point_ids in SCOPE:
        for point_id in point_ids:
            yield family, point_id, family == "protected"


def source_row_digest(header: List[str], row: Dict[str, str]) -> str:
    # A stable row seal binds the opaque output entry to every source field
    # without copying source names, hashes, expected results, or timings into
    # a runtime-visible ledger field.
    body = "\x1f".join(f"{name}={row[name]}" for name in header).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def build(evidence_dir: Path) -> Dict[str, object]:
    receipt_path = evidence_dir / "FINAL-RECEIPT.json"
    analysis_path = evidence_dir / "analysis.json"
    points_path = evidence_dir / "points.csv"
    schedule_path = evidence_dir / "schedule.json"
    plan_path = evidence_dir / "FRE-U10-RUST-128X-REMEDIATION-PLAN.md"
    amendment_path = evidence_dir / "FRE-P128-PARALLEL-EXECUTION-AMENDMENT-20260725-R1.md"
    for path in (
        receipt_path,
        analysis_path,
        points_path,
        schedule_path,
        plan_path,
        amendment_path,
    ):
        require(path.is_file(), f"missing immutable P128 evidence: {path}")

    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    schedule = json.loads(schedule_path.read_text(encoding="utf-8"))
    require(receipt["candidate_commit"] == CANDIDATE, "receipt candidate differs")
    require(receipt["candidate_tree"] == TREE, "receipt tree differs")
    require(schedule["canonical_sha"] == CANDIDATE, "schedule candidate differs")
    require(schedule["canonical_tree"] == TREE, "schedule tree differs")
    base_schedule = analysis["inputs"]["base_schedule"]
    require(base_schedule["filename"] == "schedule.json", "analysis schedule filename differs")
    require(base_schedule["file_sha256"] == digest(schedule_path), "analysis schedule digest differs")
    require(
        base_schedule["embedded_content_sha256"] == schedule["schedule_sha256"],
        "analysis embedded schedule digest differs",
    )
    require(receipt["analysis_sha256"] == digest(analysis_path), "receipt analysis digest differs")
    require(
        receipt["schedule_sha256"] == schedule["schedule_sha256"],
        "receipt schedule digest differs",
    )

    with points_path.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        require(reader.fieldnames is not None, "points CSV is missing a header")
        header = list(reader.fieldnames)
        point_rows = list(reader)
    point_ids = [row["point_id"] for row in point_rows]
    require(len(point_ids) == len(set(point_ids)), "points.csv contains duplicate point IDs")
    rows = {row["point_id"]: row for row in point_rows}
    analysis_rows = analysis["points"]
    analysis_ids = [point["point_id"] for point in analysis_rows]
    require(len(analysis_ids) == len(set(analysis_ids)), "analysis.json contains duplicate point IDs")
    analysis_points = {point["point_id"]: point for point in analysis_rows}

    records = []
    seen = set()
    for family, point_id, protected in scope_entries():
        require(point_id not in seen, f"duplicate scope point ID {point_id}")
        seen.add(point_id)
        row = rows.get(point_id)
        point = analysis_points.get(point_id)
        require(row is not None, f"scope point {point_id} is absent from points.csv")
        require(point is not None, f"scope point {point_id} is absent from analysis.json")
        require(row["comparator"] == RUST_COMPARATOR, f"scope point {point_id} comparator differs")
        require(point["comparator"] == RUST_COMPARATOR, f"analysis point {point_id} comparator differs")
        require(row["model"] == point["model"], f"scope point {point_id} model differs")
        require(row["boundary"] == point["boundary"], f"scope point {point_id} boundary differs")
        expected_semantic_plan = EXPECTED_SEMANTIC_PLANS.get((family, row["model"]))
        require(expected_semantic_plan is not None, f"scope point {point_id} has no semantic plan")
        required_receipt_kind = REQUIRED_RECEIPT_KINDS.get((family, row["model"]))
        require(required_receipt_kind is not None, f"scope point {point_id} has no receipt kind")
        require(
            point["semantic_candidate_plan"] == expected_semantic_plan,
            f"scope point {point_id} semantic plan differs",
        )
        ratio = 1.0 / point["paired_estimator_reference_over_fre"]
        if protected:
            require(124.0 < ratio < 128.0, f"protected scope point {point_id} is not the expected sibling")
        else:
            require(ratio >= 128.0, f"scope point {point_id} is not a 128x tail point")
        records.append(
            {
                "boundary": row["boundary"],
                "family": family,
                "model": row["model"],
                "point_id": point_id,
                "protected": protected,
                "required_receipt_kind": required_receipt_kind,
                "source_row_sha256": source_row_digest(header, row),
            }
        )

    require(len(records) == 32, "P128 scope must contain exactly 31 points plus one protected sibling")
    require(sum(not record["protected"] for record in records) == 31, "active scope count differs")
    counts = {family: sum(record["family"] == family for record in records) for family in ("A", "B", "C", "D")}
    require(counts == {"A": 16, "B": 6, "C": 4, "D": 5}, "workstream scope counts differ")

    ledger = {
        "candidate_commit": CANDIDATE,
        "candidate_tree": TREE,
        "evidence": {
            "analysis_sha256": digest(analysis_path),
            "parallel_execution_amendment_sha256": digest(amendment_path),
            "plan_sha256": digest(plan_path),
            "points_sha256": digest(points_path),
            "receipt_sha256": digest(receipt_path),
            "schedule_sha256": digest(schedule_path),
        },
        "records": records,
        "schema": SCHEMA,
    }
    ledger["ledger_sha256"] = hashlib.sha256(canonical_bytes(ledger)).hexdigest()
    return ledger


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--check", type=Path)
    args = parser.parse_args()
    if args.out is not None and args.check is not None:
        parser.error("--out and --check are mutually exclusive")
    ledger = build(args.evidence_dir)
    encoded = json.dumps(ledger, indent=2, sort_keys=True) + "\n"
    if args.check is not None:
        require(args.check.read_text(encoding="utf-8") == encoded, "generated ledger differs from checked-in ledger")
    elif args.out is not None:
        args.out.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
