#!/usr/bin/env python3
"""Evaluate the sealed composition interaction gate without exclusions."""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
import pathlib
import statistics
import sys
from typing import Any, Iterable


HERE = pathlib.Path(__file__).resolve().parent
POLICY_PATH = HERE / "policy.json"


def sha256_path(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def geomean(values: Iterable[float]) -> float:
    values = list(values)
    if not values or any(value <= 0 or not math.isfinite(value) for value in values):
        raise ValueError("geomean requires nonempty positive finite values")
    return math.exp(sum(math.log(value) for value in values) / len(values))


def percentile(values: Iterable[float], fraction: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("percentile requires values")
    position = fraction * (len(ordered) - 1)
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def point_key(record: dict[str, Any]) -> tuple[str, str, str]:
    return (record["case_id"], record["tier"], record["operation"])


def group_geomeans(
    ratios: dict[tuple[str, str, str], float],
    metadata: dict[tuple[str, str, str], dict[str, Any]],
    field: str,
    *,
    include_transition: bool = False,
) -> dict[str, float]:
    grouped: dict[str, list[float]] = collections.defaultdict(list)
    for key, ratio in ratios.items():
        meta = metadata[key]
        if meta["transition"] and not include_transition:
            continue
        grouped[str(meta[field])].append(ratio)
    return {group: geomean(values) for group, values in sorted(grouped.items())}


def semantic_projection(receipt: dict[str, Any]) -> list[dict[str, Any]]:
    projected = []
    for wrapped in receipt["records"]:
        item = wrapped["receipt"]
        finite = item["finite"]
        projected.append(
            {
                "facade": wrapped["facade"],
                "case_id": item["case_id"],
                "tier": item["tier"],
                "input_bytes": item["input_bytes"],
                "pattern": item["pattern"],
                "family": item["family"],
                "consuming_class": item["consuming_class"],
                "nullable": item["nullable"],
                "contextual": item["contextual"],
                "native_control": item["native_control"],
                "semantic": item["semantic"],
                "finite": {
                    key: value
                    for key, value in finite.items()
                    if key
                    not in {
                        "reported_warm_work",
                        "exact_work",
                        "exact_probe_steps",
                        "refusal_work",
                        "recovery_limit",
                        "decline_steps",
                    }
                },
            }
        )
    return projected


def sum_setup_numbers(value: Any, field: str) -> int:
    if isinstance(value, dict):
        own = value.get(field, 0)
        if not isinstance(own, int):
            own = 0
        return own + sum(sum_setup_numbers(child, field) for child in value.values())
    if isinstance(value, list):
        return sum(sum_setup_numbers(child, field) for child in value)
    return 0


def analyze(args: argparse.Namespace) -> dict[str, Any]:
    policy = json.loads(POLICY_PATH.read_text())
    timings_path = pathlib.Path(args.timings)
    records = [
        json.loads(line)
        for line in timings_path.read_text().splitlines()
        if line.strip()
    ]
    repetitions = policy["timing"]["repetitions"]
    grouped: dict[tuple[tuple[str, str, str], str, str], list[dict[str, Any]]] = (
        collections.defaultdict(list)
    )
    metadata: dict[tuple[str, str, str], dict[str, Any]] = {}
    for record in records:
        key = point_key(record)
        metadata.setdefault(key, record)
        grouped[(key, record["source"], record["engine"])].append(record)

    failures: list[str] = []
    medians: dict[tuple[tuple[str, str, str], str, str], float] = {}
    checksums: dict[tuple[tuple[str, str, str], str, str], int] = {}
    for group, samples in grouped.items():
        if len(samples) != repetitions:
            failures.append(f"{group} has {len(samples)} samples, expected {repetitions}")
            continue
        sample_checksums = {sample["checksum"] for sample in samples}
        if len(sample_checksums) != 1:
            failures.append(f"{group} checksum changed across repetitions")
            continue
        checksums[group] = next(iter(sample_checksums))
        medians[group] = statistics.median(
            float(sample["ns_per_iteration"]) for sample in samples
        )

    candidate_over_base: dict[tuple[str, str, str], float] = {}
    rust_relative_base: dict[tuple[str, str, str], float] = {}
    rust_relative_candidate: dict[tuple[str, str, str], float] = {}
    rust_control_ratio: dict[tuple[str, str, str], float] = {}
    for key, meta in metadata.items():
        base_fre = medians.get((key, "base", "fre"))
        candidate_fre = medians.get((key, "candidate", "fre"))
        if base_fre is None or candidate_fre is None:
            failures.append(f"{key} missing base/candidate FRE medians")
            continue
        if checksums.get((key, "base", "fre")) != checksums.get(
            (key, "candidate", "fre")
        ):
            failures.append(f"{key} FRE semantic checksum differs base/candidate")
        candidate_over_base[key] = base_fre / candidate_fre
        if meta["comparable_to_rust"]:
            base_rust = medians.get((key, "base", "rust"))
            candidate_rust = medians.get((key, "candidate", "rust"))
            if base_rust is None or candidate_rust is None:
                failures.append(f"{key} missing Rust comparator medians")
                continue
            if checksums.get((key, "base", "rust")) != checksums.get(
                (key, "candidate", "rust")
            ):
                failures.append(f"{key} Rust checksum differs across binaries")
            if checksums.get((key, "candidate", "fre")) != checksums.get(
                (key, "candidate", "rust")
            ):
                failures.append(f"{key} FRE/Rust semantic checksum differs")
            rust_relative_base[key] = base_rust / base_fre
            rust_relative_candidate[key] = candidate_rust / candidate_fre
            rust_control_ratio[key] = base_rust / candidate_rust

    primary = [
        ratio
        for key, ratio in candidate_over_base.items()
        if not metadata[key]["transition"]
    ]
    primary_gm = geomean(primary)
    primary_p10 = percentile(primary, 0.10)
    primary_worst = min(primary)
    candidate_policy = policy["candidate_over_base"]
    if primary_gm < candidate_policy["primary_geomean_min"]:
        failures.append(
            f"candidate/base primary GM {primary_gm:.6f} below "
            f"{candidate_policy['primary_geomean_min']:.6f}"
        )
    if primary_p10 < candidate_policy["primary_p10_min"]:
        failures.append(
            f"candidate/base primary p10 {primary_p10:.6f} below "
            f"{candidate_policy['primary_p10_min']:.6f}"
        )
    if primary_worst < candidate_policy["primary_worst_min"]:
        failures.append(
            f"candidate/base worst {primary_worst:.6f} below "
            f"{candidate_policy['primary_worst_min']:.6f}"
        )

    cohort_gms = group_geomeans(candidate_over_base, metadata, "cohort")
    for cohort, value in cohort_gms.items():
        if value < candidate_policy["steady_cohort_geomean_min"]:
            failures.append(
                f"candidate/base cohort {cohort} GM {value:.6f} below "
                f"{candidate_policy['steady_cohort_geomean_min']:.6f}"
            )
    family_gms = group_geomeans(candidate_over_base, metadata, "family")
    for family, value in family_gms.items():
        if value < candidate_policy["family_geomean_min"]:
            failures.append(
                f"candidate/base family {family} GM {value:.6f} below "
                f"{candidate_policy['family_geomean_min']:.6f}"
            )
    native_values = [
        ratio
        for key, ratio in candidate_over_base.items()
        if metadata[key]["native_control"] and not metadata[key]["transition"]
    ]
    native_gm = geomean(native_values)
    if native_gm < candidate_policy["native_control_geomean_min"]:
        failures.append(
            f"native control GM {native_gm:.6f} below "
            f"{candidate_policy['native_control_geomean_min']:.6f}"
        )
    transition_values = [
        ratio
        for key, ratio in candidate_over_base.items()
        if metadata[key]["transition"]
    ]
    transition_gm = geomean(transition_values)
    if transition_gm < candidate_policy["transition_geomean_min"]:
        failures.append(
            f"transition GM {transition_gm:.6f} below "
            f"{candidate_policy['transition_geomean_min']:.6f}"
        )

    rust_policy = policy["rust_relative"]
    rust_candidate_gm = geomean(rust_relative_candidate.values())
    if rust_candidate_gm < rust_policy["overall_comparable_geomean_min"]:
        failures.append(
            f"candidate Rust/FRE GM {rust_candidate_gm:.6f} below "
            f"{rust_policy['overall_comparable_geomean_min']:.6f}"
        )
    rust_base_cohorts = group_geomeans(rust_relative_base, metadata, "cohort")
    rust_candidate_cohorts = group_geomeans(
        rust_relative_candidate, metadata, "cohort"
    )
    for cohort, absolute_floor in rust_policy[
        "absolute_geomean_min_by_cohort"
    ].items():
        value = rust_candidate_cohorts.get(cohort)
        if value is None:
            failures.append(f"missing Rust-relative cohort {cohort}")
            continue
        if value < absolute_floor:
            failures.append(
                f"candidate Rust/FRE cohort {cohort} GM {value:.6f} below "
                f"{absolute_floor:.6f}"
            )
        relative = value / rust_base_cohorts[cohort]
        if relative < rust_policy["candidate_vs_base_ratio_min_by_cohort"]:
            failures.append(
                f"Rust-relative cohort {cohort} preservation {relative:.6f} below "
                f"{rust_policy['candidate_vs_base_ratio_min_by_cohort']:.6f}"
            )
    rust_control_gm = geomean(rust_control_ratio.values())
    if not (
        rust_policy["rust_control_candidate_over_base_min"]
        <= rust_control_gm
        <= rust_policy["rust_control_candidate_over_base_max"]
    ):
        failures.append(
            f"Rust control base/candidate GM {rust_control_gm:.6f} outside "
            f"[{rust_policy['rust_control_candidate_over_base_min']:.6f}, "
            f"{rust_policy['rust_control_candidate_over_base_max']:.6f}]"
        )

    receipt_report: dict[str, Any] | None = None
    if args.base_receipt and args.candidate_receipt:
        base_receipt_path = pathlib.Path(args.base_receipt)
        candidate_receipt_path = pathlib.Path(args.candidate_receipt)
        base_receipt = json.loads(base_receipt_path.read_text())
        candidate_receipt = json.loads(candidate_receipt_path.read_text())
        semantic_equal = semantic_projection(base_receipt) == semantic_projection(
            candidate_receipt
        )
        if not semantic_equal:
            failures.append("candidate semantic/finite receipt differs from frozen base")
        fields = ["work", "allocated_bytes", "initialized_bytes", "retained_bytes"]
        setup_totals = {
            "base": {
                field: sum_setup_numbers(
                    [record["receipt"]["setup"] for record in base_receipt["records"]],
                    field,
                )
                for field in fields
            },
            "candidate": {
                field: sum_setup_numbers(
                    [
                        record["receipt"]["setup"]
                        for record in candidate_receipt["records"]
                    ],
                    field,
                )
                for field in fields
            },
        }
        retained_base = setup_totals["base"]["retained_bytes"]
        retained_candidate = setup_totals["candidate"]["retained_bytes"]
        setup_ratio = (
            retained_candidate / retained_base
            if retained_base
            else (1.0 if retained_candidate == 0 else math.inf)
        )
        if setup_ratio > policy["receipts"]["candidate_setup_total_over_base_max"]:
            failures.append(
                f"candidate/base setup retained-byte ratio {setup_ratio:.6f} exceeds "
                f"{policy['receipts']['candidate_setup_total_over_base_max']:.6f}"
            )
        receipt_report = {
            "semantic_equal": semantic_equal,
            "base_sha256": sha256_path(base_receipt_path),
            "candidate_sha256": sha256_path(candidate_receipt_path),
            "setup_totals": setup_totals,
            "candidate_over_base_retained_bytes": setup_ratio,
        }

    return {
        "schema": "fre.composition-interaction-gate.analysis.v1",
        "verdict": "PASS" if not failures else "REJECT",
        "failures": failures,
        "counts": {
            "timing_records": len(records),
            "points": len(candidate_over_base),
            "comparable_points": len(rust_relative_candidate),
            "repetitions": repetitions,
        },
        "candidate_over_base": {
            "primary_geomean": primary_gm,
            "primary_p10": primary_p10,
            "primary_worst": primary_worst,
            "cohort_geomeans": cohort_gms,
            "family_geomeans": family_gms,
            "native_control_geomean": native_gm,
            "transition_geomean": transition_gm,
        },
        "rust_relative": {
            "candidate_overall_geomean": rust_candidate_gm,
            "base_cohort_geomeans": rust_base_cohorts,
            "candidate_cohort_geomeans": rust_candidate_cohorts,
            "rust_control_base_over_candidate_geomean": rust_control_gm,
        },
        "receipts": receipt_report,
        "evidence": {
            "timings_sha256": sha256_path(timings_path),
            "policy_sha256": sha256_path(POLICY_PATH),
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timings", required=True)
    parser.add_argument("--base-receipt")
    parser.add_argument("--candidate-receipt")
    parser.add_argument("--out", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = analyze(args)
    output = pathlib.Path(args.out)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["verdict"] == "PASS" else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"fatal: {error}", file=sys.stderr)
        raise
