#!/usr/bin/env python3
"""Run ripgrep's workloads through the shared FRE/Rust-regex adapter.

The benchmark definitions and canonical `rg` argv/cwd come from ripgrep's
benchsuite. The original sampler is intentionally replaced: this runner checks
output hashes, corpus identity, and exit status, then measures adjacent
fresh-process AB/BA pairs. The default metric is an in-process scan over a
fully preloaded corpus; process wall time is retained as a diagnostic.
"""

import argparse
import csv
import datetime
import hashlib
import json
import math
import os
import pathlib
import platform
import runpy
import statistics
import subprocess
import time


BASELINE_ENGINE = "rust-regex"
CANDIDATE_ENGINES = ("fre", "fre-aot-fast", "fre-aot-optimizing")
DEFAULT_CANDIDATE_ENGINE = "fre"
TIMING_SCOPES = ("preloaded-scan", "process")
DEFAULT_TIMING_SCOPE = "preloaded-scan"
TIMING_PREFIX = "fre-ripgrep-thin-timing-v1"
RESULTS_SCHEMA_VERSION = 3


def parse_args(arguments=None):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--benchsuite",
        required=True,
        type=pathlib.Path,
        help="Path to ripgrep's benchsuite/benchsuite script.",
    )
    parser.add_argument(
        "--corpus-dir",
        required=True,
        type=pathlib.Path,
        help="Directory prepared by benchsuite --download.",
    )
    parser.add_argument(
        "--wrapper",
        type=pathlib.Path,
        default=pathlib.Path("target/release/examples/ripgrep_thin"),
    )
    parser.add_argument(
        "--filter",
        help="Regular expression applied to ripgrep benchmark names.",
    )
    parser.add_argument(
        "--pairs",
        type=int,
        default=6,
        help="Number of adjacent pairs (default: 6).",
    )
    parser.add_argument(
        "--output-dir",
        type=pathlib.Path,
        help="Output directory; defaults under benchmark-results/ripgrep.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Allow writing into an existing output directory.",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume an existing results.json, skipping completed workloads.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=180.0,
        help="Hard timeout for each scan arm (default: 180 seconds).",
    )
    parser.add_argument(
        "--allow-unbuilt-linux",
        action="store_true",
        help=(
            "Run Linux workloads when linux/ is a clone but vmlinux is "
            "absent; this is a source-tree-only deviation from the suite."
        ),
    )
    parser.add_argument(
        "--whole-file",
        action="store_true",
        help=(
            "Pass each file as one haystack and exhaust non-overlapping "
            "match iteration instead of matching one line at a time."
        ),
    )
    parser.add_argument(
        "--candidate-engine",
        choices=CANDIDATE_ENGINES,
        default=DEFAULT_CANDIDATE_ENGINE,
        help=(
            "Candidate compared against rust-regex (default: fre). "
            "The selected wrapper must implement this --engine value."
        ),
    )
    parser.add_argument(
        "--timing-scope",
        choices=TIMING_SCOPES,
        default=DEFAULT_TIMING_SCOPE,
        help=(
            "Time only the in-memory scan after corpus loading and matcher "
            "construction (default: preloaded-scan), or retain the legacy "
            "spawn-through-exit process timing."
        ),
    )
    return parser.parse_args(arguments)


def engine_pair(candidate_engine):
    return (candidate_engine, BASELINE_ENGINE)


def engine_field(engine):
    return engine.replace("-", "_")


def candidate_failure_status(candidate_engine, generic, legacy):
    if candidate_engine == DEFAULT_CANDIDATE_ENGINE:
        return legacy
    return generic


def order_label(order, candidate_engine):
    if candidate_engine == DEFAULT_CANDIDATE_ENGINE:
        return "fre-rust" if order[0] == "fre" else "rust-fre"
    return "--".join(order)


def validate_resume_identity(
    metadata, scan_mode, candidate_engine, timing_scope
):
    existing_scan_mode = metadata.get("scan_mode", "line-is-match")
    if existing_scan_mode != scan_mode:
        raise SystemExit(
            "cannot resume across scan modes: "
            f"existing={existing_scan_mode}, requested={scan_mode}"
        )
    existing_candidate_engine = metadata.get(
        "candidate_engine", DEFAULT_CANDIDATE_ENGINE
    )
    if existing_candidate_engine != candidate_engine:
        raise SystemExit(
            "cannot resume across candidate engines: "
            f"existing={existing_candidate_engine}, "
            f"requested={candidate_engine}"
        )
    existing_baseline_engine = metadata.get("baseline_engine", BASELINE_ENGINE)
    if existing_baseline_engine != BASELINE_ENGINE:
        raise SystemExit(
            "cannot resume across baseline engines: "
            f"existing={existing_baseline_engine}, requested={BASELINE_ENGINE}"
        )
    existing_timing_scope = metadata.get("timing_scope", "process")
    if existing_timing_scope != timing_scope:
        raise SystemExit(
            "cannot resume across timing scopes: "
            f"existing={existing_timing_scope}, requested={timing_scope}"
        )
    return existing_scan_mode, existing_candidate_engine, existing_timing_scope


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def git_value(directory, *arguments):
    completed = subprocess.run(
        ["git", "-C", str(directory), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
        text=True,
    )
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def command_value(*command):
    completed = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
        text=True,
    )
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def corpus_file_metadata(corpus_dir):
    relative_paths = (
        pathlib.Path("subtitles/en.sample.txt"),
        pathlib.Path("subtitles/ru.txt"),
    )
    files = []
    for relative in relative_paths:
        candidate = corpus_dir / relative
        if candidate.is_file():
            stat = candidate.stat()
            files.append(
                {
                    "path": str(relative),
                    "bytes": stat.st_size,
                    "mtime_ns": stat.st_mtime_ns,
                    "sha256": sha256_file(candidate),
                }
            )
    return files


def fingerprint(data):
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "lines": data.count(b"\n"),
    }


def command_for(
    wrapper,
    engine,
    canonical,
    whole_file=False,
    describe_only=False,
    timing_scope=None,
):
    command = [str(wrapper), "--engine", engine]
    if whole_file:
        command.append("--whole-file")
    if describe_only:
        command.append("--describe-only")
    if timing_scope == "preloaded-scan":
        command.append("--report-scan-time")
    command.extend(canonical.cmd[1:])
    return command


def command_environment(canonical):
    environment = os.environ.copy()
    environment.update(canonical.kwargs.get("env", {}))
    return environment


def scan_timing(stderr):
    timing_lines = [
        line
        for line in stderr.splitlines()
        if line.startswith(f"{TIMING_PREFIX}\t")
    ]
    if len(timing_lines) != 1:
        raise ValueError(
            f"expected exactly one {TIMING_PREFIX!r} line, "
            f"found {len(timing_lines)}"
        )
    fields = {}
    for field in timing_lines[0].split("\t")[1:]:
        key, separator, value = field.partition("=")
        if not separator or not key:
            raise ValueError(f"malformed timing field: {field!r}")
        if key in fields:
            raise ValueError(f"duplicate timing field: {key!r}")
        fields[key] = value
    if fields.get("boundary") != "preloaded-corpus-scan":
        raise ValueError(f"unexpected timing boundary: {fields.get('boundary')!r}")
    try:
        elapsed_ns = int(fields["scan_elapsed_ns"])
    except (KeyError, ValueError) as error:
        raise ValueError("invalid scan_elapsed_ns timing field") from error
    if elapsed_ns <= 0:
        raise ValueError("scan_elapsed_ns must be positive")
    corpus_sha256 = fields.get("corpus_sha256", "")
    if len(corpus_sha256) != 64 or any(
        byte not in "0123456789abcdef" for byte in corpus_sha256
    ):
        raise ValueError("invalid corpus_sha256 timing field")
    corpus = {"sha256": corpus_sha256}
    for field in ("corpus_files", "corpus_bytes"):
        try:
            value = int(fields[field])
        except (KeyError, ValueError) as error:
            raise ValueError(f"invalid {field} timing field") from error
        if value < 0:
            raise ValueError(f"{field} must be non-negative")
        corpus[field.removeprefix("corpus_")] = value
    return {"scan_elapsed_ns": elapsed_ns, "corpus": corpus}


def run_process(command, canonical, timeout_seconds, timing_scope):
    started = time.perf_counter_ns()
    try:
        completed = subprocess.run(
            command,
            cwd=canonical.kwargs.get("cwd"),
            env=command_environment(canonical),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        elapsed_ns = time.perf_counter_ns() - started
        return {
            "command": command,
            "elapsed_ns": elapsed_ns,
            "wall_elapsed_ns": elapsed_ns,
            "scan_elapsed_ns": None,
            "corpus": None,
            "timing_error": None,
            "exit_status": None,
            "timed_out": True,
            "stderr": str(error),
            "output": None,
        }
    wall_elapsed_ns = time.perf_counter_ns() - started
    stderr = completed.stderr.decode("utf-8", errors="replace")
    measured_elapsed_ns = wall_elapsed_ns
    measured_scan_elapsed_ns = None
    corpus = None
    timing_error = None
    if timing_scope == "preloaded-scan":
        try:
            timing = scan_timing(stderr)
            measured_scan_elapsed_ns = timing["scan_elapsed_ns"]
            corpus = timing["corpus"]
            measured_elapsed_ns = measured_scan_elapsed_ns
        except ValueError as error:
            timing_error = str(error)
    return {
        "command": command,
        "elapsed_ns": measured_elapsed_ns,
        "wall_elapsed_ns": wall_elapsed_ns,
        "scan_elapsed_ns": measured_scan_elapsed_ns,
        "corpus": corpus,
        "timing_error": timing_error,
        "exit_status": completed.returncode,
        "timed_out": False,
        "stderr": stderr,
        "output": fingerprint(completed.stdout),
    }


def describe(wrapper, engine, canonical, whole_file):
    command = command_for(
        wrapper,
        engine,
        canonical,
        whole_file=whole_file,
        describe_only=True,
    )
    started = time.perf_counter_ns()
    try:
        completed = subprocess.run(
            command,
            cwd=canonical.kwargs.get("cwd"),
            env=command_environment(canonical),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=60,
        )
    except subprocess.TimeoutExpired as error:
        return {
            "command": command,
            "elapsed_ns": time.perf_counter_ns() - started,
            "exit_status": None,
            "timed_out": True,
            "stderr": str(error),
            "output": None,
        }, ""
    result = {
        "command": command,
        "elapsed_ns": time.perf_counter_ns() - started,
        "exit_status": completed.returncode,
        "timed_out": False,
        "stderr": completed.stderr.decode("utf-8", errors="replace"),
        "output": fingerprint(completed.stdout),
    }
    description = completed.stdout.decode("utf-8", errors="replace").strip()
    return result, description


def matching_output(left, right):
    return (
        left["exit_status"] == right["exit_status"]
        and successful_scan_status(left["exit_status"])
        and left["output"] == right["output"]
    )


def matching_corpus(left, right):
    return left.get("corpus") == right.get("corpus")


def successful_scan_status(status):
    return status in (0, 1)


def canonical_rg_command(benchmark):
    commands = [
        command
        for command in benchmark.commands
        if command.binary_name == "rg" and command.name == "rg"
    ]
    if len(commands) != 1:
        raise RuntimeError(
            f"{benchmark.name}: expected one canonical command named rg, "
            f"found {len(commands)}"
        )
    return commands[0]


def median_or_none(values):
    return statistics.median(values) if values else None


def summarize_samples(samples, candidate_engine):
    engines = set(engine_pair(candidate_engine))
    by_pair = {}
    for sample in samples:
        by_pair.setdefault(sample["pair"], {})[sample["engine"]] = sample
    ratios = []
    candidate_first = []
    baseline_first = []
    candidate_wins = 0
    for pair in sorted(by_pair):
        arms = by_pair[pair]
        if set(arms) != engines:
            continue
        ratio = (
            arms[BASELINE_ENGINE]["elapsed_ns"]
            / arms[candidate_engine]["elapsed_ns"]
        )
        ratios.append(ratio)
        if arms[candidate_engine]["position"] == 0:
            candidate_first.append(ratio)
        else:
            baseline_first.append(ratio)
        if (
            arms[candidate_engine]["elapsed_ns"]
            < arms[BASELINE_ENGINE]["elapsed_ns"]
        ):
            candidate_wins += 1
    summary = {
        "candidate_engine": candidate_engine,
        "baseline_engine": BASELINE_ENGINE,
        "paired_median_baseline_over_candidate": median_or_none(ratios),
        "candidate_first_median_baseline_over_candidate": median_or_none(
            candidate_first
        ),
        "baseline_first_median_baseline_over_candidate": median_or_none(
            baseline_first
        ),
        "min_baseline_over_candidate": min(ratios) if ratios else None,
        "max_baseline_over_candidate": max(ratios) if ratios else None,
        "candidate_wins": candidate_wins,
        "pair_count": len(ratios),
        "candidate_median_ns": median_or_none(
            [
                sample["elapsed_ns"]
                for sample in samples
                if sample["engine"] == candidate_engine
            ]
        ),
        "baseline_median_ns": median_or_none(
            [
                sample["elapsed_ns"]
                for sample in samples
                if sample["engine"] == BASELINE_ENGINE
            ]
        ),
    }
    if candidate_engine == DEFAULT_CANDIDATE_ENGINE:
        summary.update(
            {
                "paired_median_rust_over_fre": summary[
                    "paired_median_baseline_over_candidate"
                ],
                "fre_first_median_rust_over_fre": summary[
                    "candidate_first_median_baseline_over_candidate"
                ],
                "rust_first_median_rust_over_fre": summary[
                    "baseline_first_median_baseline_over_candidate"
                ],
                "min_rust_over_fre": summary["min_baseline_over_candidate"],
                "max_rust_over_fre": summary["max_baseline_over_candidate"],
                "fre_wins": summary["candidate_wins"],
                "fre_median_ns": summary["candidate_median_ns"],
                "rust_regex_median_ns": summary["baseline_median_ns"],
            }
        )
    return summary


def summary_value(summary, generic, legacy, candidate_engine):
    value = summary.get(generic)
    if value is None and candidate_engine == DEFAULT_CANDIDATE_ENGINE:
        value = summary.get(legacy)
    return value


def ratio_aggregate(results, candidate_engine):
    ratios = [
        summary_value(
            result["summary"],
            "paired_median_baseline_over_candidate",
            "paired_median_rust_over_fre",
            candidate_engine,
        )
        for result in results
        if result["status"] == "ok"
    ]
    ratios = [ratio for ratio in ratios if ratio is not None]
    if not ratios:
        aggregate = {
            "workloads": 0,
            "candidate_engine": candidate_engine,
            "baseline_engine": BASELINE_ENGINE,
            "geomean_baseline_over_candidate": None,
            "median_baseline_over_candidate": None,
            "candidate_faster_workloads": 0,
        }
    else:
        aggregate = {
            "workloads": len(ratios),
            "candidate_engine": candidate_engine,
            "baseline_engine": BASELINE_ENGINE,
            "geomean_baseline_over_candidate": math.exp(
                statistics.mean(math.log(ratio) for ratio in ratios)
            ),
            "median_baseline_over_candidate": statistics.median(ratios),
            "candidate_faster_workloads": sum(
                ratio > 1.0 for ratio in ratios
            ),
        }
    if candidate_engine == DEFAULT_CANDIDATE_ENGINE:
        aggregate.update(
            {
                "geomean_rust_over_fre": aggregate[
                    "geomean_baseline_over_candidate"
                ],
                "median_rust_over_fre": aggregate[
                    "median_baseline_over_candidate"
                ],
                "fre_faster_workloads": aggregate[
                    "candidate_faster_workloads"
                ],
            }
        )
    return aggregate


def aggregate_results(results, candidate_engine):
    status_counts = {}
    for result in results:
        status = result["status"]
        status_counts[status] = status_counts.get(status, 0) + 1
    return {
        "status_counts": status_counts,
        "candidate_engine": candidate_engine,
        "baseline_engine": BASELINE_ENGINE,
        "all": ratio_aggregate(results, candidate_engine),
        "linux": ratio_aggregate(
            [
                result
                for result in results
                if result["benchmark"].startswith("linux_")
            ],
            candidate_engine,
        ),
        "subtitles": ratio_aggregate(
            [
                result
                for result in results
                if result["benchmark"].startswith("subtitles_")
            ],
            candidate_engine,
        ),
        "subtitles_en": ratio_aggregate(
            [
                result
                for result in results
                if result["benchmark"].startswith("subtitles_en_")
            ],
            candidate_engine,
        ),
        "subtitles_ru": ratio_aggregate(
            [
                result
                for result in results
                if result["benchmark"].startswith("subtitles_ru_")
            ],
            candidate_engine,
        ),
    }


def benchmark_one(args, benchmark, wrapper):
    canonical = canonical_rg_command(benchmark)
    scan_mode = "whole-file-find-iter" if args.whole_file else "line-is-match"
    candidate_engine = args.candidate_engine
    engines = engine_pair(candidate_engine)
    row = {
        "benchmark": benchmark.name,
        "scan_mode": scan_mode,
        "candidate_engine": candidate_engine,
        "baseline_engine": BASELINE_ENGINE,
        "timing_scope": args.timing_scope,
        "pattern": benchmark.pattern,
        "rg_name": canonical.name,
        "rg_argv": canonical.cmd,
        "cwd": canonical.kwargs.get("cwd"),
        "env": canonical.kwargs.get("env", {}),
        "status": None,
        "candidate_description": None,
        "baseline_description": None,
        "descriptions": {},
        "preflight": {},
        "samples": [],
        "summary": {},
        "requested_pairs": args.pairs,
    }

    describe_results = {}
    for engine in (BASELINE_ENGINE, candidate_engine):
        result, description = describe(
            wrapper, engine, canonical, args.whole_file
        )
        row["descriptions"][engine] = description
        row[f"{engine_field(engine)}_description"] = description
        describe_results[engine] = result
    row["candidate_description"] = row["descriptions"][candidate_engine]
    row["baseline_description"] = row["descriptions"][BASELINE_ENGINE]
    if describe_results[BASELINE_ENGINE]["exit_status"] != 0:
        row["status"] = "baseline-error"
        row["preflight"].update(describe_results)
        return row
    if describe_results[candidate_engine]["exit_status"] != 0:
        row["status"] = candidate_failure_status(
            candidate_engine, "candidate-unsupported", "fre-unsupported"
        )
        row["preflight"].update(describe_results)
        return row

    # This is both a semantic preflight and the suite's intended untimed
    # filesystem-cache warmup. Run in the opposite order from pair zero.
    for engine in (BASELINE_ENGINE, candidate_engine):
        result = run_process(
            command_for(
                wrapper,
                engine,
                canonical,
                whole_file=args.whole_file,
                timing_scope=args.timing_scope,
            ),
            canonical,
            timeout_seconds=args.timeout_seconds,
            timing_scope=args.timing_scope,
        )
        row["preflight"][engine] = result
        if result["timed_out"]:
            if engine == BASELINE_ENGINE:
                row["status"] = "baseline-timeout"
            else:
                row["status"] = candidate_failure_status(
                    candidate_engine, "candidate-timeout", "fre-timeout"
                )
            return row
        if not successful_scan_status(result["exit_status"]):
            if engine == BASELINE_ENGINE:
                row["status"] = "baseline-error"
            else:
                row["status"] = candidate_failure_status(
                    candidate_engine,
                    "candidate-unsupported",
                    "fre-unsupported",
                )
            return row
        if result["timing_error"] is not None:
            row["status"] = "timing-protocol-error"
            return row
    if not matching_corpus(
        row["preflight"][candidate_engine],
        row["preflight"][BASELINE_ENGINE],
    ):
        row["status"] = "corpus-mismatch"
        return row
    if not matching_output(
        row["preflight"][candidate_engine],
        row["preflight"][BASELINE_ENGINE],
    ):
        row["status"] = "output-mismatch"
        return row

    expected_output = row["preflight"][BASELINE_ENGINE]["output"]
    for pair in range(args.pairs):
        order = engines if pair % 2 == 0 else tuple(reversed(engines))
        for position, engine in enumerate(order):
            result = run_process(
                command_for(
                    wrapper,
                    engine,
                    canonical,
                    whole_file=args.whole_file,
                    timing_scope=args.timing_scope,
                ),
                canonical,
                timeout_seconds=args.timeout_seconds,
                timing_scope=args.timing_scope,
            )
            sample = {
                "pair": pair,
                "position": position,
                "order": order_label(order, candidate_engine),
                "role": (
                    "baseline" if engine == BASELINE_ENGINE else "candidate"
                ),
                "engine": engine,
                **result,
            }
            row["samples"].append(sample)
            if result["timed_out"]:
                row["status"] = "timed-run-timeout"
                return row
            if result["exit_status"] != row["preflight"][engine]["exit_status"]:
                row["status"] = "timed-run-error"
                return row
            if result["timing_error"] is not None:
                row["status"] = "timing-protocol-error"
                return row
            if result.get("corpus") != row["preflight"][engine].get("corpus"):
                row["status"] = "timed-corpus-mismatch"
                return row
            if result["output"] != expected_output:
                row["status"] = "timed-output-mismatch"
                return row

    row["status"] = "ok"
    row["summary"] = summarize_samples(row["samples"], candidate_engine)
    return row


def write_outputs(output_dir, document):
    candidate_engine = document["metadata"].get(
        "candidate_engine", DEFAULT_CANDIDATE_ENGINE
    )
    document["aggregate"] = aggregate_results(
        document["results"], candidate_engine
    )
    with (output_dir / "results.json").open("w", encoding="utf-8") as target:
        json.dump(document, target, indent=2, sort_keys=True)
        target.write("\n")

    summary_fields = [
        "benchmark",
        "scan_mode",
        "timing_scope",
        "measured_elapsed_field",
        "pattern",
        "status",
        "candidate_engine",
        "baseline_engine",
        "candidate_description",
        "baseline_description",
        "fre_description",
        "output_sha256",
        "output_bytes",
        "output_lines",
        "paired_median_rust_over_fre",
        "fre_first_median_rust_over_fre",
        "rust_first_median_rust_over_fre",
        "min_rust_over_fre",
        "max_rust_over_fre",
        "fre_wins",
        "pair_count",
        "fre_median_ns",
        "rust_regex_median_ns",
        "paired_median_baseline_over_candidate",
        "candidate_first_median_baseline_over_candidate",
        "baseline_first_median_baseline_over_candidate",
        "min_baseline_over_candidate",
        "max_baseline_over_candidate",
        "candidate_wins",
        "candidate_median_ns",
        "baseline_median_ns",
    ]
    with (output_dir / "summary.csv").open(
        "w", encoding="utf-8", newline=""
    ) as target:
        writer = csv.DictWriter(target, summary_fields)
        writer.writeheader()
        for result in document["results"]:
            output = (
                result.get("preflight", {})
                .get(BASELINE_ENGINE, {})
                .get("output")
                or {}
            )
            summary = result.get("summary", {})
            writer.writerow(
                {
                    "benchmark": result["benchmark"],
                    "scan_mode": result.get("scan_mode"),
                    "timing_scope": result.get(
                        "timing_scope",
                        document["metadata"].get("timing_scope", "process"),
                    ),
                    "measured_elapsed_field": (
                        "scan_elapsed_ns"
                        if document["metadata"].get("timing_scope")
                        == "preloaded-scan"
                        else "wall_elapsed_ns"
                    ),
                    "pattern": result["pattern"],
                    "status": result["status"],
                    "candidate_engine": result.get(
                        "candidate_engine", candidate_engine
                    ),
                    "baseline_engine": result.get(
                        "baseline_engine", BASELINE_ENGINE
                    ),
                    "candidate_description": result.get(
                        "candidate_description",
                        result.get("fre_description")
                        if candidate_engine == DEFAULT_CANDIDATE_ENGINE
                        else None,
                    ),
                    "baseline_description": result.get(
                        "baseline_description",
                        result.get("rust_regex_description"),
                    ),
                    "fre_description": result.get("fre_description"),
                    "output_sha256": output.get("sha256"),
                    "output_bytes": output.get("bytes"),
                    "output_lines": output.get("lines"),
                    **summary,
                    "paired_median_baseline_over_candidate": summary_value(
                        summary,
                        "paired_median_baseline_over_candidate",
                        "paired_median_rust_over_fre",
                        candidate_engine,
                    ),
                    "candidate_first_median_baseline_over_candidate": summary_value(
                        summary,
                        "candidate_first_median_baseline_over_candidate",
                        "fre_first_median_rust_over_fre",
                        candidate_engine,
                    ),
                    "baseline_first_median_baseline_over_candidate": summary_value(
                        summary,
                        "baseline_first_median_baseline_over_candidate",
                        "rust_first_median_rust_over_fre",
                        candidate_engine,
                    ),
                    "min_baseline_over_candidate": summary_value(
                        summary,
                        "min_baseline_over_candidate",
                        "min_rust_over_fre",
                        candidate_engine,
                    ),
                    "max_baseline_over_candidate": summary_value(
                        summary,
                        "max_baseline_over_candidate",
                        "max_rust_over_fre",
                        candidate_engine,
                    ),
                    "candidate_wins": summary_value(
                        summary,
                        "candidate_wins",
                        "fre_wins",
                        candidate_engine,
                    ),
                    "candidate_median_ns": summary_value(
                        summary,
                        "candidate_median_ns",
                        "fre_median_ns",
                        candidate_engine,
                    ),
                    "baseline_median_ns": summary_value(
                        summary,
                        "baseline_median_ns",
                        "rust_regex_median_ns",
                        candidate_engine,
                    ),
                }
            )

    raw_fields = [
        "benchmark",
        "scan_mode",
        "timing_scope",
        "measured_elapsed_field",
        "candidate_engine",
        "baseline_engine",
        "pair",
        "position",
        "order",
        "engine",
        "role",
        "elapsed_ns",
        "wall_elapsed_ns",
        "scan_elapsed_ns",
        "timing_error",
        "corpus_sha256",
        "corpus_files",
        "corpus_bytes",
        "exit_status",
        "timed_out",
        "output_sha256",
        "output_bytes",
        "output_lines",
        "command",
        "stderr",
    ]
    with (output_dir / "samples.csv").open(
        "w", encoding="utf-8", newline=""
    ) as target:
        writer = csv.DictWriter(target, raw_fields)
        writer.writeheader()
        for result in document["results"]:
            for sample in result["samples"]:
                output = sample.get("output") or {}
                corpus = sample.get("corpus") or {}
                writer.writerow(
                    {
                        "benchmark": result["benchmark"],
                        "scan_mode": result.get("scan_mode"),
                        "timing_scope": result.get(
                            "timing_scope",
                            document["metadata"].get("timing_scope", "process"),
                        ),
                        "measured_elapsed_field": document["metadata"].get(
                            "measured_elapsed_field", "wall_elapsed_ns"
                        ),
                        "candidate_engine": result.get(
                            "candidate_engine", candidate_engine
                        ),
                        "baseline_engine": result.get(
                            "baseline_engine", BASELINE_ENGINE
                        ),
                        "pair": sample["pair"],
                        "position": sample["position"],
                        "order": sample["order"],
                        "engine": sample["engine"],
                        "role": sample.get(
                            "role",
                            "baseline"
                            if sample["engine"] == BASELINE_ENGINE
                            else "candidate",
                        ),
                        "elapsed_ns": sample["elapsed_ns"],
                        "wall_elapsed_ns": sample.get("wall_elapsed_ns"),
                        "scan_elapsed_ns": sample.get("scan_elapsed_ns"),
                        "timing_error": sample.get("timing_error"),
                        "corpus_sha256": corpus.get("sha256"),
                        "corpus_files": corpus.get("files"),
                        "corpus_bytes": corpus.get("bytes"),
                        "exit_status": sample["exit_status"],
                        "timed_out": sample["timed_out"],
                        "output_sha256": output.get("sha256"),
                        "output_bytes": output.get("bytes"),
                        "output_lines": output.get("lines"),
                        "command": json.dumps(sample["command"]),
                        "stderr": sample["stderr"],
                    }
                )


def main(arguments=None):
    args = parse_args(arguments)
    scan_mode = "whole-file-find-iter" if args.whole_file else "line-is-match"
    candidate_engine = args.candidate_engine
    timing_scope = args.timing_scope
    if args.pairs <= 0:
        raise SystemExit("--pairs must be positive")
    if args.timeout_seconds <= 0:
        raise SystemExit("--timeout-seconds must be positive")
    if args.resume and args.force:
        raise SystemExit("--resume and --force cannot be used together")
    benchsuite = args.benchsuite.resolve()
    corpus_dir = args.corpus_dir.resolve()
    wrapper = args.wrapper.resolve()
    if not benchsuite.is_file():
        raise SystemExit(f"benchsuite not found: {benchsuite}")
    if not wrapper.is_file():
        raise SystemExit(f"wrapper not found: {wrapper}")

    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H%M%SZ"
    )
    output_dir = args.output_dir
    if output_dir is None:
        output_dir = pathlib.Path("benchmark-results/ripgrep") / (
            f"{timestamp}-local"
        )
    output_dir = output_dir.resolve()
    existing_document = None
    if output_dir.exists() and any(output_dir.iterdir()):
        if args.resume:
            results_path = output_dir / "results.json"
            if not results_path.is_file():
                raise SystemExit(
                    f"cannot resume without results.json in {output_dir}"
                )
            with results_path.open(encoding="utf-8") as source:
                existing_document = json.load(source)
        elif not args.force:
            raise SystemExit(
                f"output directory is not empty: {output_dir} "
                "(use --resume or --force)"
            )
    elif args.resume:
        raise SystemExit(f"nothing to resume in {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)

    suite = runpy.run_path(str(benchsuite))
    if args.allow_unbuilt_linux:
        suite["collect_benchmarks"].__globals__["has_linux"] = (
            lambda directory: os.path.isdir(
                os.path.join(directory, suite["LINUX_DIR"])
            )
        )
    benchmarks = suite["collect_benchmarks"](
        str(corpus_dir),
        filter_pat=args.filter,
        allow_missing_commands=True,
        disabled_cmds=[],
        warmup_iter=0,
        bench_iter=0,
    )
    if not benchmarks:
        raise SystemExit(
            "no benchmarks are runnable; prepare corpora with the suite's "
            "--download option"
        )

    repo_root = pathlib.Path(__file__).resolve().parent.parent
    ripgrep_root = benchsuite.parent.parent
    metadata = {
        "results_schema_version": RESULTS_SCHEMA_VERSION,
        "started_utc": timestamp,
        "host": platform.platform(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "rustc": command_value("rustc", "--version", "--verbose"),
        "cargo": command_value("cargo", "--version", "--verbose"),
        "pairs": args.pairs,
        "scan_mode": scan_mode,
        "candidate_engine": candidate_engine,
        "baseline_engine": BASELINE_ENGINE,
        "timing_scope": timing_scope,
        "engine_pair": list(engine_pair(candidate_engine)),
        "comparison_ratio": "baseline elapsed / candidate elapsed",
        "measured_elapsed_field": (
            "scan_elapsed_ns"
            if timing_scope == "preloaded-scan"
            else "wall_elapsed_ns"
        ),
        "sampling_runs": [
            {
                "started_utc": timestamp,
                "pairs": args.pairs,
                "arm_timeout_seconds": args.timeout_seconds,
                "scan_mode": scan_mode,
                "candidate_engine": candidate_engine,
                "baseline_engine": BASELINE_ENGINE,
                "timing_scope": timing_scope,
            }
        ],
        "arm_timeout_seconds": args.timeout_seconds,
        "schedule": "adjacent fresh-process pairs, alternating FRE/Rust order",
        "timing_boundary": (
            "in-process traversal and matching over an owned corpus snapshot; "
            "line boundaries are precomputed and line output is deferred; "
            "line result collection and whole-file span digest/accounting are "
            "included; matcher construction, file discovery/read, output "
            "formatting, and process startup/exit are excluded"
            if timing_scope == "preloaded-scan"
            else "spawn through exit with stdout/stderr drained"
        ),
        "timing_protocol": (
            "fre-ripgrep-thin-timing-v1"
            if timing_scope == "preloaded-scan"
            else None
        ),
        "clock": (
            "std::time::Instant in wrapper"
            if timing_scope == "preloaded-scan"
            else "time.perf_counter_ns in runner"
        ),
        "wall_clock": "time.perf_counter_ns in runner",
        "corpus_identity": (
            "SHA-256 over domain-separated ordered accepted path bytes, file "
            "lengths, and complete file contents; compared across every arm"
            if timing_scope == "preloaded-scan"
            else None
        ),
        "preload_memory_policy": (
            "owned file bytes plus precomputed line ranges and deferred "
            "matching-line records in line mode"
            if timing_scope == "preloaded-scan"
            else None
        ),
        "semantic_check": (
            "exit status plus exhaustive ordered whole-file match-span "
            "digest fingerprint"
            if args.whole_file
            else "exit status plus SHA-256/byte/newline fingerprint"
        ),
        "matcher_operation": (
            "non-overlapping find iteration over each complete file"
            if args.whole_file
            else "is_match independently on each line"
        ),
        "variant_policy": (
            "one canonical suite command named rg per workload; selected "
            "candidate compared with rust-regex"
        ),
        "linux_corpus_policy": (
            "source tree without required kernel build"
            if args.allow_unbuilt_linux
            else "suite default: requires built vmlinux"
        ),
        "benchsuite": str(benchsuite),
        "benchsuite_sha256": sha256_file(benchsuite),
        "ripgrep_commit": git_value(ripgrep_root, "rev-parse", "HEAD"),
        "corpus_dir": str(corpus_dir),
        "corpus_files": corpus_file_metadata(corpus_dir),
        "linux_commit": git_value(corpus_dir / "linux", "rev-parse", "HEAD"),
        "linux_tree_status": git_value(
            corpus_dir / "linux", "status", "--short"
        ),
        "wrapper": str(wrapper),
        "wrapper_sha256": sha256_file(wrapper),
        "wrapper_source_sha256": sha256_file(
            repo_root / "crates/fre/examples/ripgrep_thin.rs"
        ),
        "runner_source_sha256": sha256_file(pathlib.Path(__file__).resolve()),
        "cargo_lock_sha256": sha256_file(repo_root / "Cargo.lock"),
        "fre_commit": git_value(repo_root, "rev-parse", "HEAD"),
        "fre_tree_status": git_value(repo_root, "status", "--short"),
    }
    if existing_document is None:
        document = {"metadata": metadata, "results": []}
    else:
        (
            existing_scan_mode,
            existing_candidate_engine,
            existing_timing_scope,
        ) = validate_resume_identity(
            existing_document["metadata"],
            scan_mode,
            candidate_engine,
            timing_scope,
        )
        document = existing_document
        document["metadata"]["results_schema_version"] = RESULTS_SCHEMA_VERSION
        document["metadata"].setdefault(
            "candidate_engine", existing_candidate_engine
        )
        document["metadata"].setdefault("baseline_engine", BASELINE_ENGINE)
        document["metadata"].setdefault(
            "timing_scope", existing_timing_scope
        )
        document["metadata"].setdefault(
            "engine_pair", list(engine_pair(existing_candidate_engine))
        )
        document["metadata"]["arm_timeout_seconds"] = args.timeout_seconds
        document["metadata"]["runner_source_sha256"] = metadata[
            "runner_source_sha256"
        ]
        document["metadata"].setdefault("resumed_utc", []).append(timestamp)
        if "sampling_runs" not in document["metadata"]:
            document["metadata"]["sampling_runs"] = [
                {
                    "started_utc": document["metadata"]["started_utc"],
                    "pairs": document["metadata"]["pairs"],
                    "arm_timeout_seconds": document["metadata"].get(
                        "arm_timeout_seconds"
                    ),
                    "scan_mode": existing_scan_mode,
                    "candidate_engine": existing_candidate_engine,
                    "baseline_engine": BASELINE_ENGINE,
                    "timing_scope": existing_timing_scope,
                }
            ]
        document["metadata"]["sampling_runs"].append(
            {
                "started_utc": timestamp,
                "pairs": args.pairs,
                "arm_timeout_seconds": args.timeout_seconds,
                "scan_mode": scan_mode,
                "candidate_engine": candidate_engine,
                "baseline_engine": BASELINE_ENGINE,
                "timing_scope": timing_scope,
            }
        )
        document["metadata"].pop("finished_utc", None)

    completed = {result["benchmark"] for result in document["results"]}
    for index, benchmark in enumerate(benchmarks, start=1):
        if benchmark.name in completed:
            print(
                f"[{index}/{len(benchmarks)}] {benchmark.name}: "
                "already complete",
                flush=True,
            )
            continue
        print(
            f"[{index}/{len(benchmarks)}] {benchmark.name}: ",
            end="",
            flush=True,
        )
        result = benchmark_one(args, benchmark, wrapper)
        document["results"].append(result)
        if result["status"] == "ok":
            ratio = result["summary"][
                "paired_median_baseline_over_candidate"
            ]
            label = (
                "Rust/FRE"
                if candidate_engine == DEFAULT_CANDIDATE_ENGINE
                else f"Rust/{candidate_engine}"
            )
            print(f"ok, {label}={ratio:.3f}x", flush=True)
        else:
            print(result["status"], flush=True)
        write_outputs(output_dir, document)

    document["metadata"]["finished_utc"] = datetime.datetime.now(
        datetime.timezone.utc
    ).strftime("%Y-%m-%dT%H%M%SZ")
    write_outputs(output_dir, document)
    print(f"wrote {output_dir}")


if __name__ == "__main__":
    main()
