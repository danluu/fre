#!/usr/bin/env python3
"""Adversarial tests for exact compiler/linker wrapper construction."""

from __future__ import annotations

import hashlib
import os
import platform
import re
import signal
import shutil
import shlex
import subprocess
import sys
import sysconfig
import tempfile
import unittest
from pathlib import Path

import static_sealer_core as sealer
import static_tool_wrapper as wrapper


class StaticToolWrapperTests(unittest.TestCase):
    def test_native_launcher_forces_isolated_no_site_python(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            launcher = root / "launcher"
            source = (
                Path(wrapper.__file__).with_name(
                    "static_native_launcher.c"
                )
            )
            subprocess.run(
                [
                    "/usr/bin/cc",
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-O2",
                    f"-I{sysconfig.get_config_var('INCLUDEPY')}",
                    str(source),
                    "-o",
                    str(launcher),
                    *shlex.split(
                        sysconfig.get_config_var("LINKFORSHARED") or ""
                    ),
                    *shlex.split(
                        sysconfig.get_config_var("LIBS") or ""
                    ),
                ],
                check=True,
            )
            probe = root / "probe.py"
            probe.write_text(
                "import sys\n"
                "print(sys.flags.isolated, sys.flags.no_site, "
                "sys.flags.ignore_environment)\n"
                "print('|'.join(sys.argv[1:]))\n",
                encoding="utf-8",
            )
            environment = {
                "FRE_STATIC_ATTEST_WRAPPER_SCRIPT_PATH": str(probe),
            }
            monitor_read, monitor_write = os.pipe()
            environment["FRE_STATIC_ATTEST_MONITOR_FD"] = str(
                monitor_write
            )
            process = subprocess.Popen(
                [str(launcher), "first", "second"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                text=True,
                pass_fds=(monitor_write,),
            )
            os.close(monitor_write)
            with os.fdopen(monitor_read, "r", encoding="utf-8") as monitor:
                fields = monitor.readline().rstrip().split(" ", 3)
            self.assertEqual(
                fields,
                [
                    "FRELAUNCH1",
                    str(process.pid),
                    str(os.getpid()),
                    str(launcher),
                ],
            )
            os.kill(process.pid, signal.SIGCONT)
            stdout, stderr = process.communicate(timeout=30)
            self.assertEqual(process.returncode, 0, stderr)
            self.assertEqual(
                stdout.splitlines(),
                ["1 1 1", f"{launcher}|first|second"],
            )
            held_probe = os.open(probe, os.O_RDONLY | os.O_CLOEXEC)
            try:
                held_path = (
                    f"/dev/fd/{held_probe}"
                    if platform.system() == "Darwin"
                    else f"/proc/self/fd/{held_probe}"
                )
                for argument in ("held-first", "held-second"):
                    held_environment = {
                        "FRE_STATIC_ATTEST_WRAPPER_SCRIPT_PATH": (
                            held_path
                        ),
                    }
                    held_read, held_write = os.pipe()
                    held_environment[
                        "FRE_STATIC_ATTEST_MONITOR_FD"
                    ] = str(held_write)
                    held_process = subprocess.Popen(
                        [str(launcher), argument],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        env=held_environment,
                        text=True,
                        pass_fds=(held_probe, held_write),
                    )
                    os.close(held_write)
                    with os.fdopen(
                        held_read, "r", encoding="utf-8"
                    ) as held_monitor:
                        self.assertTrue(
                            held_monitor.readline().startswith(
                                f"FRELAUNCH1 {held_process.pid} "
                            )
                        )
                    os.kill(held_process.pid, signal.SIGCONT)
                    held_stdout, held_stderr = (
                        held_process.communicate(timeout=30)
                    )
                    self.assertEqual(
                        held_process.returncode, 0, held_stderr
                    )
                    self.assertEqual(
                        held_stdout.splitlines(),
                        [
                            "1 1 1",
                            f"{launcher}|{argument}",
                        ],
                    )
            finally:
                os.close(held_probe)
            injected = dict(environment)
            injected["PYTHONPATH"] = str(root)
            refused = subprocess.run(
                [str(launcher)],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=injected,
                text=True,
            )
            self.assertEqual(refused.returncode, 127)
            self.assertIn("ambient", refused.stderr)

    def test_wrapper_source_can_be_read_from_inherited_descriptor(
        self,
    ) -> None:
        with tempfile.TemporaryFile() as held:
            held.write(b"exact held wrapper bytes")
            held.flush()
            prefix = (
                "/dev/fd"
                if platform.system() == "Darwin"
                else "/proc/self/fd"
            )
            path = Path(f"{prefix}/{held.fileno()}")
            self.assertEqual(
                wrapper.held_bytes(path, 1024),
                b"exact held wrapper bytes",
            )
            self.assertEqual(
                os.fstat(held.fileno()).st_size,
                len(b"exact held wrapper bytes"),
            )

    @unittest.skipUnless(
        platform.system() == "Darwin", "Darwin Mach-O CDHash test"
    )
    def test_macho_cdhash_derivation_matches_kernel_tooling(self) -> None:
        executable = Path(sys.executable).resolve(strict=True)
        result = subprocess.run(
            ["/usr/bin/codesign", "-d", "--verbose=4", str(executable)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        expected = re.search(
            rb"^CDHash=([0-9a-f]{40})$", result.stderr, re.M
        )
        self.assertIsNotNone(expected)
        self.assertEqual(
            wrapper.darwin_cdhash_from_macho(executable),
            expected.group(1).decode(),
        )

    def test_rustc_wrapper_publishes_exact_build_script_launcher(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            output_directory = root / "out"
            output_directory.mkdir()
            output = output_directory / "build_script_build-deadbeef"
            shutil.copy(Path(sys.executable).resolve(strict=True), output)
            arguments = [
                "--crate-name",
                "build_script_build",
                "--crate-type",
                "bin",
                "--out-dir",
                str(output_directory),
                "-C",
                "extra-filename=-deadbeef",
            ]
            wrapper_bytes = Path(wrapper.__file__).read_bytes()
            wrapper_sha256 = hashlib.sha256(wrapper_bytes).hexdigest()
            launcher_bytes = b"exact native launcher bytes"
            launcher_sha256 = hashlib.sha256(
                launcher_bytes
            ).hexdigest()
            publication = wrapper.publish_build_script(
                arguments,
                launcher_bytes,
                launcher_sha256,
                wrapper_sha256,
                vars(sealer),
            )
            self.assertIsNotNone(publication)
            self.assertEqual(output.read_bytes(), launcher_bytes)
            self.assertTrue(
                Path(publication["tool_path"]).is_file()
            )
            self.assertEqual(
                wrapper.load_build_script_publication(
                    output, launcher_sha256, wrapper_sha256
                ),
                publication,
            )
            cargo_alias = output_directory / "build-script-build"
            shutil.copy(output, cargo_alias)
            self.assertEqual(
                wrapper.load_build_script_publication(
                    cargo_alias, launcher_sha256, wrapper_sha256
                ),
                publication,
            )

    def test_link_grammar_preserves_exact_ordered_inputs(self) -> None:
        arguments = [
            "/tmp/first.o",
            "/tmp/libsecond.rlib",
            "/tmp/first.o",
            "-lSystem",
            "-arch",
            "arm64",
            "-o",
            "/tmp/output",
            "-Wl,-map,/tmp/output.map",
            "-nodefaultlibs",
        ]
        explicit, output, symbolic = wrapper.link_operand_kinds(arguments)
        self.assertEqual(set(explicit), {0, 1, 2})
        self.assertEqual(output, 7)
        self.assertEqual(
            symbolic,
            [
                {
                    "argument_index": 3,
                    "kind": "library",
                    "value": "System",
                }
            ],
        )

    def test_link_grammar_rejects_opaque_or_injectable_inputs(self) -> None:
        forbidden = [
            "@/tmp/response",
            "-Wl,@/tmp/response",
            "-Wl,-filelist,/tmp/files",
            "-Wl,-T,/tmp/script",
            "-Wl,--script=/tmp/script",
            "-Wl,--plugin=/tmp/plugin",
            "-Wl,--dynamic-linker=/tmp/loader",
            "-Wl,-rpath,/tmp/injected",
            "-fuse-ld=/tmp/other-linker",
            "--unknown-input-bearing-option",
        ]
        for argument in forbidden:
            with self.subTest(argument=argument):
                with self.assertRaises(wrapper.Refusal):
                    wrapper.link_operand_kinds(
                        [
                            "/tmp/input.o",
                            argument,
                            "-o",
                            "/tmp/output",
                        ]
                    )

    def test_link_grammar_accepts_only_frozen_map_and_hardening_forms(
        self,
    ) -> None:
        arguments = [
            "/tmp/input.o",
            "-Wl,-segprot,__TEXT,rx,rx",
            "-Wl,-segprot,__FRE_CONST,r,r",
            "-Wl,-reproducible",
            "-Wl,-map,/tmp/output.map",
            "-Wl,-z,noexecstack",
            "-Wl,--build-id=none",
            "-Wl,-Map,/tmp/output.map",
            "-o",
            "/tmp/output",
        ]
        explicit, output, _ = wrapper.link_operand_kinds(arguments)
        self.assertEqual(set(explicit), {0})
        self.assertEqual(output, 9)

    def test_symbol_list_is_one_explicit_sealable_input(self) -> None:
        arguments = [
            "-Wl,-exported_symbols_list",
            "-Wl,/tmp/exports",
            "/tmp/input.o",
            "-dynamiclib",
            "-o",
            "/tmp/output.dylib",
        ]
        explicit, output, _ = wrapper.link_operand_kinds(arguments)
        self.assertEqual(
            explicit,
            {
                1: (Path("/tmp/exports"), "-Wl,"),
                2: (Path("/tmp/input.o"), ""),
            },
        )
        self.assertEqual(output, 5)

    def test_explicit_link_inputs_are_distinct_held_copies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            first = root / "first.o"
            archive = root / "second.rlib"
            output = root / "output"
            first.write_bytes(b"first object bytes")
            archive.write_bytes(b"archive bytes")
            arguments = [
                str(first),
                str(archive),
                str(first),
                "-o",
                str(output),
            ]
            (
                rewritten,
                rows,
                symbolic,
                descriptors,
                parsed_output,
            ) = wrapper.held_link_arguments(
                arguments, vars(sealer), root
            )
            try:
                self.assertEqual(parsed_output, output)
                self.assertEqual(symbolic, [])
                self.assertEqual(
                    [row["path"] for row in rows],
                    [str(first), str(archive), str(first)],
                )
                self.assertEqual(
                    [row["argument_index"] for row in rows], [0, 1, 2]
                )
                self.assertEqual(len(descriptors), 3)
                self.assertEqual(len(set(descriptors)), 3)
                self.assertEqual(
                    [rewritten[index] for index in range(3)],
                    [row["held_argument"] for row in rows],
                )
                expected_first = hashlib.sha256(
                    b"first object bytes"
                ).hexdigest()
                first.write_bytes(b"mutated after held-copy")
                self.assertEqual(
                    sealer.file_sha_fd(descriptors[0]), expected_first
                )
                self.assertEqual(
                    sealer.file_sha_fd(descriptors[2]), expected_first
                )
            finally:
                for descriptor in descriptors:
                    sealer.os.close(descriptor)

    def test_external_candidate_uses_immutable_named_link_alias(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            held_root = root / "held"
            held_root.mkdir(mode=0o700)
            candidate = root / "external-search-7-family-glue.o"
            output = root / "output"
            candidate.write_bytes(b"candidate object bytes")
            rewritten, rows, symbolic, descriptors, parsed_output = (
                wrapper.held_link_arguments(
                    [str(candidate), "-o", str(output)],
                    vars(sealer),
                    held_root,
                )
            )
            self.assertEqual(parsed_output, output)
            self.assertEqual(symbolic, [])
            self.assertEqual(descriptors, ())
            self.assertEqual(len(rows), 1)
            alias = Path(rows[0]["held_argument"])
            self.assertEqual(rewritten[0], str(alias))
            self.assertEqual(alias.name, candidate.name)
            self.assertTrue(
                alias.resolve(strict=True).is_relative_to(
                    held_root.resolve(strict=True)
                )
            )
            self.assertEqual(alias.stat().st_mode & 0o777, 0o400)
            candidate.write_bytes(b"mutated source object")
            self.assertEqual(alias.read_bytes(), b"candidate object bytes")
            self.assertEqual(
                rows[0]["sha256"],
                hashlib.sha256(b"candidate object bytes").hexdigest(),
            )


if __name__ == "__main__":
    unittest.main()
