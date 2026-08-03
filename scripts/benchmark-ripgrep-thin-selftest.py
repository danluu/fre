#!/usr/bin/env python3
"""Focused protocol tests for benchmark-ripgrep-thin.py."""

import pathlib
import runpy
import types
import unittest


RUNNER = runpy.run_path(
    str(pathlib.Path(__file__).with_name("benchmark-ripgrep-thin.py"))
)


class RipgrepThinRunnerTests(unittest.TestCase):
    def test_preloaded_scan_is_the_default(self):
        args = RUNNER["parse_args"](
            ["--benchsuite", "suite", "--corpus-dir", "corpus"]
        )
        self.assertEqual(args.timing_scope, "preloaded-scan")

    def test_command_requests_wrapper_timing_only_for_preloaded_scan(self):
        canonical = types.SimpleNamespace(
            cmd=["rg", "needle", "sample.txt"], kwargs={}
        )
        preloaded = RUNNER["command_for"](
            pathlib.Path("wrapper"),
            "rust-regex",
            canonical,
            timing_scope="preloaded-scan",
        )
        process = RUNNER["command_for"](
            pathlib.Path("wrapper"),
            "rust-regex",
            canonical,
            timing_scope="process",
        )
        self.assertIn("--report-scan-time", preloaded)
        self.assertNotIn("--report-scan-time", process)

    def test_scan_timing_parses_elapsed_and_corpus_identity(self):
        digest = "ab" * 32
        timing = RUNNER["scan_timing"](
            "diagnostic\n"
            "fre-ripgrep-thin-timing-v1\t"
            "scan_elapsed_ns=123\t"
            "boundary=preloaded-corpus-scan\t"
            "corpus_files=2\tcorpus_bytes=19\t"
            f"corpus_sha256={digest}\n"
        )
        self.assertEqual(timing["scan_elapsed_ns"], 123)
        self.assertEqual(
            timing["corpus"],
            {"sha256": digest, "files": 2, "bytes": 19},
        )

    def test_scan_timing_rejects_missing_duplicate_and_bad_records(self):
        digest = "cd" * 32
        valid = (
            "fre-ripgrep-thin-timing-v1\t"
            "scan_elapsed_ns=123\t"
            "boundary=preloaded-corpus-scan\t"
            "corpus_files=2\tcorpus_bytes=19\t"
            f"corpus_sha256={digest}"
        )
        for record in (
            "",
            f"{valid}\n{valid}",
            valid.replace("scan_elapsed_ns=123", "scan_elapsed_ns=0"),
            valid.replace(digest, "not-a-digest"),
            valid + "\tcorpus_files=3",
        ):
            with self.subTest(record=record):
                with self.assertRaises(ValueError):
                    RUNNER["scan_timing"](record)

    def test_resume_rejects_mixed_timing_scopes(self):
        metadata = {
            "scan_mode": "line-is-match",
            "candidate_engine": "fre-aot-optimizing",
            "baseline_engine": "rust-regex",
            "timing_scope": "process",
        }
        with self.assertRaises(SystemExit):
            RUNNER["validate_resume_identity"](
                metadata,
                "line-is-match",
                "fre-aot-optimizing",
                "preloaded-scan",
            )


if __name__ == "__main__":
    unittest.main()
