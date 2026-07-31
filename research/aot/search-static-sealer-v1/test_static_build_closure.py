#!/usr/bin/env python3
"""Adversarial tests for exact construction-plan closure."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path

import static_build_closure as closure


def h(byte: str) -> str:
    return byte * 64


def link_projection() -> dict[str, object]:
    arguments = [
        "/tmp/external-search-0-implementation.o",
        "/tmp/external-search-0-family-glue.o",
        "/tmp/ordinary.o",
        "-lSystem",
        "-o",
        "/tmp/final",
    ]
    rows = [
        {
            "ordinal": index,
            "argument_index": index,
            "path": arguments[index],
            "sha256": h(str(index + 1)),
            "bytes": 64,
            "kind": "object",
            "held_argument": f"/dev/fd/{128 + index}",
        }
        for index in range(3)
    ]
    symbolic = [
        {
            "argument_index": 3,
            "kind": "library",
            "value": "System",
        }
    ]
    executed = list(arguments)
    for row in rows:
        executed[row["argument_index"]] = row["held_argument"]
    environment = {"LC_ALL": "C", "PATH": "/usr/bin:/bin"}
    return {
        "role": "linker",
        "launcher": {
            "path": "/dev/fd/110",
            "sha256": h("8"),
            "execution_identity": {
                "mechanism": "darwin-suspended-cdhash-v1",
                "cdhash": "8" * 40,
            },
        },
        "python_runtime": {
            "path": "/opt/frozen/Python",
            "sha256": h("9"),
            "execution_identity": {
                "mechanism": "darwin-loaded-image-sha256-v1",
                "sha256": h("9"),
            },
            "flags": ["-I", "-S", "-E"],
        },
        "wrapper_source_sha256": h("a"),
        "sealer_source_sha256": h("b"),
        "tool": {
            "path": "/usr/bin/clang",
            "sha256": h("c"),
            "execution_identity": {
                "mechanism": "darwin-suspended-cdhash-v1",
                "cdhash": "d" * 40,
            },
        },
        "lineage": {
            "parent_pid": 100,
            "wrapper_pid": 101,
            "tool_pid": 102,
        },
        "arguments": arguments,
        "arguments_sha256": closure.canonical_sha(arguments),
        "executed_arguments": executed,
        "executed_arguments_sha256": closure.canonical_sha(executed),
        "environment": environment,
        "environment_sha256": closure.canonical_sha(environment),
        "input_rows": rows,
        "input_rows_sha256": closure.canonical_sha(rows),
        "symbolic_inputs": symbolic,
        "symbolic_inputs_sha256": closure.canonical_sha(symbolic),
        "build_script_publication": None,
        "output": {
            "path": "/tmp/final",
            "sha256": h("e"),
            "bytes": 4096,
        },
        "returncode": 0,
        "stdout_sha256": h("f"),
        "stdout_bytes": 0,
        "stderr_sha256": h("0"),
        "stderr_bytes": 0,
    }


class StaticBuildClosureTests(unittest.TestCase):
    def test_final_candidate_multiset_is_exact_and_ordered(self) -> None:
        row = link_projection()
        required = [
            {
                "path": "/tmp/external-search-0-implementation.o",
                "sha256": h("1"),
                "kind": "object",
            },
            {
                "path": "/tmp/external-search-0-family-glue.o",
                "sha256": h("2"),
                "kind": "object",
            },
        ]
        self.assertIs(
            closure.validate_final_link_candidates(
                [row],
                final_output=Path("/tmp/final"),
                required_candidates=required,
            ),
            row,
        )
        injected = copy.deepcopy(row)
        injected["input_rows"].insert(
            2,
            {
                "ordinal": 2,
                "argument_index": 2,
                "path": "/tmp/external-search-injected.o",
                "sha256": h("9"),
                "bytes": 64,
                "kind": "object",
                "held_argument": "/dev/fd/999",
            },
        )
        with self.assertRaisesRegex(
            closure.Refusal, "candidate input multiset"
        ):
            closure.validate_final_link_candidates(
                [injected],
                final_output=Path("/tmp/final"),
                required_candidates=required,
            )

    def test_plan_comparison_rejects_extra_duplicate_or_changed_row(
        self,
    ) -> None:
        row = closure.normalized_projection(link_projection())
        plan = closure.build_plan([row])
        closure.compare_plan([row], plan)
        with self.assertRaisesRegex(
            closure.Refusal, "differs from preregistration"
        ):
            closure.compare_plan([row, row], plan)
        changed = copy.deepcopy(row)
        changed["arguments"].append("/tmp/injected.o")
        with self.assertRaisesRegex(
            closure.Refusal, "differs from preregistration"
        ):
            closure.compare_plan([changed], plan)

    def test_tool_validation_rejects_dynamic_loader_injection(self) -> None:
        row = link_projection()
        row["environment"]["DYLD_INSERT_LIBRARIES"] = "/tmp/injected"
        row["environment_sha256"] = closure.canonical_sha(
            row["environment"]
        )
        with self.assertRaisesRegex(closure.Refusal, "argv/environment"):
            closure.validate_tool_payload(
                row,
                expected_wrapper_sha256=h("a"),
                expected_sealer_sha256=h("b"),
                expected_launcher={
                    "sha256": row["launcher"]["sha256"],
                    "execution_identity": row["launcher"][
                        "execution_identity"
                    ],
                },
                expected_python_runtime=row["python_runtime"],
                expected_tools={"linker": row["tool"]},
            )

    def test_jobserver_is_the_only_normalized_environment_value(self) -> None:
        environment = {
            "CARGO_MAKEFLAGS": (
                "-j --jobserver-fds=7,8 --jobserver-auth=7,8"
            ),
            "OUT_DIR": "/tmp/exact",
        }
        normalized = closure.normalize_jobserver(environment)
        self.assertEqual(normalized["OUT_DIR"], "/tmp/exact")
        self.assertNotIn("7,8", normalized["CARGO_MAKEFLAGS"])
        malformed = {"CARGO_MAKEFLAGS": "--jobserver-auth=not-fds"}
        with self.assertRaises(closure.Refusal):
            closure.normalize_jobserver(malformed)

    def test_one_published_build_script_can_run_more_than_once(self) -> None:
        publication = {
            "tool_path": "/tmp/build-script.fre-attested-real",
            "tool_sha256": h("1"),
        }
        rustc = {
            "role": "rustc",
            "build_script_publication": publication,
        }
        execution = {
            "role": "build-script",
            "tool": {"path": publication["tool_path"]},
            "build_script_publication": publication,
        }
        closure.validate_build_script_coverage(
            [rustc, execution, copy.deepcopy(execution)]
        )
        changed = copy.deepcopy(execution)
        changed["build_script_publication"]["tool_sha256"] = h("2")
        with self.assertRaisesRegex(closure.Refusal, "coverage"):
            closure.validate_build_script_coverage(
                [rustc, execution, changed]
            )
        with self.assertRaisesRegex(closure.Refusal, "coverage"):
            closure.validate_build_script_coverage([rustc])


if __name__ == "__main__":
    unittest.main()
