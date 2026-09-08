#!/usr/bin/env python3
"""Fresh-process paired timing for public_prepared_exists_batch (standard library only)."""

import argparse
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time

SCENARIOS = ("negative", "early", "late", "dense-decoy")
ROUTE_FIELDS = {"route=compiled-prepared", "api=exists-batch-v1", "bulk=native-frozen-loop"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path, help="New JSONL file; refuses overwrite")
    parser.add_argument("--pairs", type=int, default=31)
    parser.add_argument("--target-ms", type=float, default=40)
    parser.add_argument("--timeout-seconds", type=float, default=60)
    args = parser.parse_args()
    if args.pairs < 1 or not 30 <= args.target_ms <= 50 or args.timeout_seconds <= 0:
        parser.error("pairs must be positive, target-ms 30..50, and timeout-seconds positive")
    binaries = {name: getattr(args, name).resolve(strict=True) for name in ("baseline", "candidate")}
    # Artifact append happens outside all measured regions and survives interruption.
    with args.output.open("x", encoding="utf-8") as output:
        def emit(event):
            output.write(json.dumps(event, sort_keys=True) + "\n")
            output.flush()
            os.fsync(output.fileno())

        emit({
            "event": "metadata", "schema": "fre-prepared-exists-pairs-v1",
            "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "host": platform.node(), "platform": platform.platform(),
            "python": sys.version, "cpu_count": os.cpu_count(),
            "pairs": args.pairs, "target_ms": args.target_ms,
            "ratio_convention": "baseline_elapsed_ns / candidate_elapsed_ns; >1 favors candidate",
            "timing_scope": "endpoint internal batch timer; fresh process per sample; startup excluded",
            "co_tenancy": "not controlled; load averages recorded; no timing samples filtered",
            "binaries": {
                name: {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                for name, path in binaries.items()
            },
        })
        failures = []

        def sample(name, cell, iterations, phase, pair):
            command = [str(binaries[name]), cell["scenario"], str(cell["batch"]),
                       str(cell["bytes_per_haystack"]), str(iterations)]
            event = {"event": "sample", "binary": name, **cell, "iterations": iterations,
                     "phase": phase, "pair": pair, "load_average": os.getloadavg()}
            started = time.perf_counter_ns()
            try:
                result = subprocess.run(command, capture_output=True, text=True,
                                        timeout=args.timeout_seconds, check=False)
                event.update(wall_ns=time.perf_counter_ns() - started, returncode=result.returncode,
                             stdout=result.stdout, stderr=result.stderr)
                if result.returncode:
                    raise ValueError(f"endpoint exit {result.returncode}")
                record = json.loads(result.stdout)
                if not isinstance(record, dict):
                    raise ValueError("endpoint receipt is not an object")
                if record.get("schema") != "fre-public-prepared-exists-batch-v1" or record.get("status") != "ok":
                    raise ValueError("missing endpoint success receipt")
                for field, value in {**cell, "iterations": iterations}.items():
                    if record.get(field) != value:
                        raise ValueError(f"endpoint disagrees on {field}")
                if not ROUTE_FIELDS <= set(record.get("route", "").split(",")):
                    raise ValueError("wrong compiled route")
                if not isinstance(record.get("elapsed_ns"), int) or record["elapsed_ns"] <= 0:
                    raise ValueError("invalid elapsed_ns")
                expected = cell["batch"] if cell["scenario"] in ("early", "late") else 0
                if record.get("matches_per_batch") != expected:
                    raise ValueError("wrong exact output count")
                digest = record.get("input_sha256", "")
                if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                    raise ValueError("missing input identity")
                event.update(status="ok", endpoint=record)
            except (OSError, subprocess.SubprocessError, ValueError, TypeError) as error:
                event.update(status="failed", error=str(error),
                             wall_ns=time.perf_counter_ns() - started)
                if isinstance(error, subprocess.TimeoutExpired):
                    event["stdout"] = (error.stdout or b"").decode("utf-8", errors="replace")
                    event["stderr"] = (error.stderr or b"").decode("utf-8", errors="replace")
                failures.append({**cell, "binary": name, "phase": phase, "pair": pair,
                                 "error": str(error)})
                record = None
            emit(event)
            return record

        summaries = []
        cell_index = 0
        for scenario in SCENARIOS:
            for batch in (1, 8, 64):
                for size in (64, 4096, 65536):
                    cell = {"scenario": scenario, "batch": batch, "bytes_per_haystack": size}
                    iterations = 16
                    calibrated = False
                    # Both binaries participate, and use identical iteration counts.
                    for attempt in range(3):
                        probes = [sample(name, cell, iterations, "calibration", attempt)
                                  for name in ("baseline", "candidate")]
                        if any(probe is None for probe in probes):
                            break
                        slowest = max(probe["elapsed_ns"] for probe in probes)
                        if 30_000_000 <= slowest <= 50_000_000 or attempt == 2:
                            calibrated = True
                            break
                        iterations = max(1, min(100_000_000,
                            round(iterations * args.target_ms * 1_000_000 / slowest)))
                    paired = []
                    if calibrated:
                        for pair in range(args.pairs):
                            order = ("baseline", "candidate") if (cell_index + pair) % 2 == 0 else ("candidate", "baseline")
                            results = {name: sample(name, cell, iterations, "measurement", pair)
                                       for name in order}
                            baseline, candidate = results["baseline"], results["candidate"]
                            event = {"event": "pair", **cell, "pair": pair, "order": order}
                            if baseline is None or candidate is None:
                                event.update(status="failed", error="endpoint failure; sample retained")
                            elif any(baseline[key] != candidate[key] for key in
                                     ("input_sha256", "matches_per_batch", "route")):
                                error = "baseline/candidate input, output, or route disagreement"
                                failures.append({**cell, "pair": pair, "error": error})
                                event.update(status="failed", error=error)
                            else:
                                ratio = baseline["elapsed_ns"] / candidate["elapsed_ns"]
                                paired.append((baseline["elapsed_ns"], candidate["elapsed_ns"], ratio))
                                event.update(status="ok", baseline_ns=baseline["elapsed_ns"],
                                             candidate_ns=candidate["elapsed_ns"], ratio=ratio)
                            emit(event)
                    summary = {"event": "cell_summary", **cell, "iterations": iterations,
                               "requested_pairs": args.pairs, "valid_pairs": len(paired),
                               "status": "ok" if len(paired) == args.pairs else "incomplete"}
                    if paired:
                        ratios = [row[2] for row in paired]
                        summary.update(
                            baseline_mean_ns=statistics.mean(row[0] for row in paired),
                            candidate_mean_ns=statistics.mean(row[1] for row in paired),
                            mean_time_ratio=sum(row[0] for row in paired) / sum(row[1] for row in paired),
                            median_pair_ratio=statistics.median(ratios),
                            geometric_mean_pair_ratio=math.exp(statistics.mean(math.log(r) for r in ratios)),
                            min_pair_ratio=min(ratios), max_pair_ratio=max(ratios))
                    emit(summary)
                    summaries.append(summary)
                    print(json.dumps(summary, sort_keys=True), flush=True)
                    cell_index += 1
        complete = not failures and all(row["status"] == "ok" for row in summaries)
        final = {"event": "complete", "status": "ok" if complete else "failed",
                 "cells": len(summaries), "failures": failures,
                 "incomplete_cells": [row for row in summaries if row["status"] != "ok"],
                 "regressing_cells": [row for row in summaries if row.get("mean_time_ratio", 1) < 1]}
        emit(final)
        print(json.dumps(final, sort_keys=True), flush=True)
        return 0 if complete else 1


if __name__ == "__main__":
    raise SystemExit(main())
