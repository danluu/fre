#!/usr/bin/env python3
"""Run ripgrep's workloads through the shared FRE/Rust-regex adapter.

The benchmark definitions and canonical `rg` argv/cwd come from ripgrep's
benchsuite. The original sampler is intentionally replaced: this runner checks
output hashes and exit status, then measures adjacent fresh-process AB/BA pairs.
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


ENGINES = ("fre", "rust-regex")


def parse_args():
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
    return parser.parse_args()


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
    wrapper, engine, canonical, whole_file=False, describe_only=False
):
    command = [str(wrapper), "--engine", engine]
    if whole_file:
        command.append("--whole-file")
    if describe_only:
        command.append("--describe-only")
    command.extend(canonical.cmd[1:])
    return command


def command_environment(canonical):
    environment = os.environ.copy()
    environment.update(canonical.kwargs.get("env", {}))
    return environment


def run_process(command, canonical, timeout_seconds):
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
            "exit_status": None,
            "timed_out": True,
            "stderr": str(error),
            "output": None,
        }
    elapsed_ns = time.perf_counter_ns() - started
    return {
        "command": command,
        "elapsed_ns": elapsed_ns,
        "exit_status": completed.returncode,
        "timed_out": False,
        "stderr": completed.stderr.decode("utf-8", errors="replace"),
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


def summarize_samples(samples):
    by_pair = {}
    for sample in samples:
        by_pair.setdefault(sample["pair"], {})[sample["engine"]] = sample
    ratios = []
    fre_first = []
    rust_first = []
    fre_wins = 0
    for pair in sorted(by_pair):
        arms = by_pair[pair]
        if set(arms) != set(ENGINES):
            continue
        ratio = (
            arms["rust-regex"]["elapsed_ns"] / arms["fre"]["elapsed_ns"]
        )
        ratios.append(ratio)
        if arms["fre"]["position"] == 0:
            fre_first.append(ratio)
        else:
            rust_first.append(ratio)
        if arms["fre"]["elapsed_ns"] < arms["rust-regex"]["elapsed_ns"]:
            fre_wins += 1
    return {
        "paired_median_rust_over_fre": median_or_none(ratios),
        "fre_first_median_rust_over_fre": median_or_none(fre_first),
        "rust_first_median_rust_over_fre": median_or_none(rust_first),
        "min_rust_over_fre": min(ratios) if ratios else None,
        "max_rust_over_fre": max(ratios) if ratios else None,
        "fre_wins": fre_wins,
        "pair_count": len(ratios),
        "fre_median_ns": median_or_none(
            [
                sample["elapsed_ns"]
                for sample in samples
                if sample["engine"] == "fre"
            ]
        ),
        "rust_regex_median_ns": median_or_none(
            [
                sample["elapsed_ns"]
                for sample in samples
                if sample["engine"] == "rust-regex"
            ]
        ),
    }


def ratio_aggregate(results):
    ratios = [
        result["summary"]["paired_median_rust_over_fre"]
        for result in results
        if result["status"] == "ok"
    ]
    if not ratios:
        return {
            "workloads": 0,
            "geomean_rust_over_fre": None,
            "median_rust_over_fre": None,
            "fre_faster_workloads": 0,
        }
    return {
        "workloads": len(ratios),
        "geomean_rust_over_fre": math.exp(
            statistics.mean(math.log(ratio) for ratio in ratios)
        ),
        "median_rust_over_fre": statistics.median(ratios),
        "fre_faster_workloads": sum(ratio > 1.0 for ratio in ratios),
    }


def aggregate_results(results):
    status_counts = {}
    for result in results:
        status = result["status"]
        status_counts[status] = status_counts.get(status, 0) + 1
    return {
        "status_counts": status_counts,
        "all": ratio_aggregate(results),
        "linux": ratio_aggregate(
            [
                result
                for result in results
                if result["benchmark"].startswith("linux_")
            ]
        ),
        "subtitles": ratio_aggregate(
            [
                result
                for result in results
                if result["benchmark"].startswith("subtitles_")
            ]
        ),
        "subtitles_en": ratio_aggregate(
            [
                result
                for result in results
                if result["benchmark"].startswith("subtitles_en_")
            ]
        ),
        "subtitles_ru": ratio_aggregate(
            [
                result
                for result in results
                if result["benchmark"].startswith("subtitles_ru_")
            ]
        ),
    }


def benchmark_one(args, benchmark, wrapper):
    canonical = canonical_rg_command(benchmark)
    scan_mode = "whole-file-find-iter" if args.whole_file else "line-is-match"
    row = {
        "benchmark": benchmark.name,
        "scan_mode": scan_mode,
        "pattern": benchmark.pattern,
        "rg_name": canonical.name,
        "rg_argv": canonical.cmd,
        "cwd": canonical.kwargs.get("cwd"),
        "env": canonical.kwargs.get("env", {}),
        "status": None,
        "fre_description": None,
        "rust_regex_description": None,
        "preflight": {},
        "samples": [],
        "summary": {},
        "requested_pairs": args.pairs,
    }

    describe_results = {}
    for engine in ("rust-regex", "fre"):
        result, description = describe(
            wrapper, engine, canonical, args.whole_file
        )
        row[f"{engine.replace('-', '_')}_description"] = description
        describe_results[engine] = result
    if describe_results["rust-regex"]["exit_status"] != 0:
        row["status"] = "baseline-error"
        row["preflight"].update(describe_results)
        return row
    if describe_results["fre"]["exit_status"] != 0:
        row["status"] = "fre-unsupported"
        row["preflight"].update(describe_results)
        return row

    # This is both a semantic preflight and the suite's intended untimed
    # filesystem-cache warmup. Run in the opposite order from pair zero.
    for engine in ("rust-regex", "fre"):
        result = run_process(
            command_for(
                wrapper,
                engine,
                canonical,
                whole_file=args.whole_file,
            ),
            canonical,
            timeout_seconds=args.timeout_seconds,
        )
        row["preflight"][engine] = result
        if result["timed_out"]:
            row["status"] = (
                "fre-timeout" if engine == "fre" else "baseline-timeout"
            )
            return row
        if not successful_scan_status(result["exit_status"]):
            row["status"] = (
                "fre-unsupported" if engine == "fre" else "baseline-error"
            )
            return row
    if not matching_output(
        row["preflight"]["fre"], row["preflight"]["rust-regex"]
    ):
        row["status"] = "output-mismatch"
        return row

    expected_output = row["preflight"]["fre"]["output"]
    for pair in range(args.pairs):
        order = ENGINES if pair % 2 == 0 else tuple(reversed(ENGINES))
        for position, engine in enumerate(order):
            result = run_process(
                command_for(
                    wrapper,
                    engine,
                    canonical,
                    whole_file=args.whole_file,
                ),
                canonical,
                timeout_seconds=args.timeout_seconds,
            )
            sample = {
                "pair": pair,
                "position": position,
                "order": "fre-rust" if order[0] == "fre" else "rust-fre",
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
            if result["output"] != expected_output:
                row["status"] = "timed-output-mismatch"
                return row

    row["status"] = "ok"
    row["summary"] = summarize_samples(row["samples"])
    return row


def write_outputs(output_dir, document):
    document["aggregate"] = aggregate_results(document["results"])
    with (output_dir / "results.json").open("w", encoding="utf-8") as target:
        json.dump(document, target, indent=2, sort_keys=True)
        target.write("\n")

    summary_fields = [
        "benchmark",
        "pattern",
        "status",
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
    ]
    with (output_dir / "summary.csv").open(
        "w", encoding="utf-8", newline=""
    ) as target:
        writer = csv.DictWriter(target, summary_fields)
        writer.writeheader()
        for result in document["results"]:
            output = result.get("preflight", {}).get("fre", {}).get("output") or {}
            writer.writerow(
                {
                    "benchmark": result["benchmark"],
                    "pattern": result["pattern"],
                    "status": result["status"],
                    "fre_description": result.get("fre_description"),
                    "output_sha256": output.get("sha256"),
                    "output_bytes": output.get("bytes"),
                    "output_lines": output.get("lines"),
                    **result.get("summary", {}),
                }
            )

    raw_fields = [
        "benchmark",
        "pair",
        "position",
        "order",
        "engine",
        "elapsed_ns",
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
                writer.writerow(
                    {
                        "benchmark": result["benchmark"],
                        "pair": sample["pair"],
                        "position": sample["position"],
                        "order": sample["order"],
                        "engine": sample["engine"],
                        "elapsed_ns": sample["elapsed_ns"],
                        "exit_status": sample["exit_status"],
                        "timed_out": sample["timed_out"],
                        "output_sha256": output.get("sha256"),
                        "output_bytes": output.get("bytes"),
                        "output_lines": output.get("lines"),
                        "command": json.dumps(sample["command"]),
                        "stderr": sample["stderr"],
                    }
                )


def main():
    args = parse_args()
    scan_mode = "whole-file-find-iter" if args.whole_file else "line-is-match"
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
        "started_utc": timestamp,
        "host": platform.platform(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "rustc": command_value("rustc", "--version", "--verbose"),
        "cargo": command_value("cargo", "--version", "--verbose"),
        "pairs": args.pairs,
        "scan_mode": scan_mode,
        "sampling_runs": [
            {
                "started_utc": timestamp,
                "pairs": args.pairs,
                "arm_timeout_seconds": args.timeout_seconds,
                "scan_mode": scan_mode,
            }
        ],
        "arm_timeout_seconds": args.timeout_seconds,
        "schedule": "adjacent fresh-process pairs, alternating FRE/Rust order",
        "timing_boundary": "spawn through exit with stdout/stderr drained",
        "clock": "time.perf_counter_ns",
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
        "variant_policy": "one canonical suite command named rg per workload",
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
        existing_scan_mode = existing_document["metadata"].get(
            "scan_mode", "line-is-match"
        )
        if existing_scan_mode != scan_mode:
            raise SystemExit(
                "cannot resume across scan modes: "
                f"existing={existing_scan_mode}, requested={scan_mode}"
            )
        document = existing_document
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
                }
            ]
        document["metadata"]["sampling_runs"].append(
            {
                "started_utc": timestamp,
                "pairs": args.pairs,
                "arm_timeout_seconds": args.timeout_seconds,
                "scan_mode": scan_mode,
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
            ratio = result["summary"]["paired_median_rust_over_fre"]
            print(f"ok, Rust/FRE={ratio:.3f}x", flush=True)
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
