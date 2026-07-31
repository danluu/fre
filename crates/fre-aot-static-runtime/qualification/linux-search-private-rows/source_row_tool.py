#!/usr/bin/env python3
"""Strict parser and canonical Rust renderer for one private Search row.

The compiler-produced ``source-row-proposal.tsv`` is inert input. This tool
accepts only its exact proposal-only/private/authority-absent grammar and
renders the complete feature-gated private Rust module. It never edits source.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path


SCHEMA = "fre-aot-linux-search-span-source-row-proposal-v1"
PROMOTION_STATE = "proposal-only"
TABLE_TARGET = "private-qualification-input"
RUNTIME_AUTHORITY = "absent"
QUALIFICATION_FIELD_COUNT = 12
MAX_PROPOSAL_BYTES = 128 << 10
MAX_U16 = (1 << 16) - 1
MAX_U32 = (1 << 32) - 1

HEADER_FIELDS = (
    "schema",
    "promotion_state",
    "table_target",
    "runtime_authority",
    "selector",
    "qualification_field_count",
    "live_literal_bytes",
)
IDENTITY_FIELDS = (
    "manifest_identity",
    "semantic_binding_identity",
    "literal_identity",
    "kir_identity",
    "artifact_identity",
    "binding_identity",
    "compile_identity",
    "object_identity",
    "receipt_identity",
    "expectation_identity",
    "payload_identity",
)
FIELDS = HEADER_FIELDS + IDENTITY_FIELDS

MODULE_PREFIX = """use super::SourceQualifiedStaticSearchSpanRowV1;

/// Literal, source-reviewed private Search-v1 Span qualification rows.
///
/// This module is compiled only by `search-span-qualification-private-v1`.
/// The table begins empty and stays inert unless a qualification promotion
/// replaces this complete file with the canonical renderer's exact projection
/// of one independently measured and reviewed `source-row-proposal.tsv`.
"""
TABLE_DECLARATION = """pub(super) const PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_ROWS_V1:
    &[SourceQualifiedStaticSearchSpanRowV1] = """
MODULE_SUFFIX = """

const _: () = assert!(super::qualification_rows_are_canonical(
    PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_ROWS_V1
));
"""
EMPTY_PRODUCTION_MODULE = b"""use super::SourceQualifiedStaticSearchSpanRowV1;

impl SourceQualifiedStaticSearchSpanRowV1 {
    /// Construct one literal row in this production authority atom.
    ///
    /// Defining the private method in this child module keeps it inaccessible
    /// to the parent support module, `private_rows`, all runtime/routing
    /// siblings, downstream crates, generated build output, and metadata.
    #[allow(
        dead_code,
        clippy::too_many_arguments,
        reason = "the production atom retains this solely for canonical reviewed row construction"
    )]
    const fn production(
        selector: u16,
        live_literal_bytes: u32,
        manifest_identity: [u8; 32],
        semantic_binding_identity: [u8; 32],
        literal_identity: [u8; 32],
        kir_identity: [u8; 32],
        artifact_identity: [u8; 32],
        binding_identity: [u8; 32],
        compile_identity: [u8; 32],
        object_identity: [u8; 32],
        receipt_identity: [u8; 32],
        expectation_identity: [u8; 32],
        payload_identity: [u8; 32],
    ) -> Self {
        Self {
            selector,
            live_literal_bytes,
            manifest_identity: super::SourceQualifiedManifestIdentityV1(manifest_identity),
            semantic_binding_identity: super::SourceQualifiedSemanticBindingIdentityV1(
                semantic_binding_identity,
            ),
            literal_identity: super::SourceQualifiedLiteralIdentityV1(literal_identity),
            kir_identity: super::SourceQualifiedKirIdentityV1(kir_identity),
            artifact_identity: super::SourceQualifiedArtifactIdentityV1(artifact_identity),
            binding_identity: super::SourceQualifiedBindingIdentityV1(binding_identity),
            compile_identity: super::SourceQualifiedCompileIdentityV1(compile_identity),
            object_identity: super::SourceQualifiedObjectIdentityV1(object_identity),
            receipt_identity: super::SourceQualifiedReceiptIdentityV1(receipt_identity),
            expectation_identity: super::SourceQualifiedExpectationIdentityV1(expectation_identity),
            payload_identity: super::SourceQualifiedPayloadIdentityV1(payload_identity),
        }
    }
}

/// Literal, source-reviewed production Search-v1 Span qualification rows.
///
/// No independently authorized Search-v1 Span final image has been promoted
/// for ordinary runtime use. This complete production authority atom therefore
/// begins as, and is compile-time constrained to remain, a canonical empty
/// table.
pub(super) const PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_ROWS_V1:
    &[SourceQualifiedStaticSearchSpanRowV1] = &[];

const _: () = assert!(super::qualification_rows_are_canonical(
    PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_ROWS_V1
));
const _: () = assert!(PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_ROWS_V1.is_empty());
"""


class Refusal(ValueError):
    """The proposed row is not the exact closed grammar."""


@dataclass(frozen=True)
class SourceRowProposal:
    selector: int
    live_literal_bytes: int
    identities: tuple[str, ...]
    canonical_bytes: bytes
    sha256: str

    def identity(self, name: str) -> str:
        return self.identities[IDENTITY_FIELDS.index(name)]


def _read_exact_extent(descriptor: int, size: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = os.read(descriptor, min(remaining, 16 << 10))
        if not chunk:
            raise Refusal("file was truncated during its bounded read")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise Refusal("file grew during its bounded read")
    return b"".join(chunks)


def _stable_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _canonical_decimal(text: str, maximum: int, label: str, *, zero_ok: bool) -> int:
    if not text or any(character < "0" or character > "9" for character in text):
        raise Refusal(f"{label} is not an unsigned decimal")
    if len(text) > 1 and text.startswith("0"):
        raise Refusal(f"{label} is not canonical decimal")
    value = int(text)
    if (value == 0 and not zero_ok) or value > maximum:
        raise Refusal(f"{label} is outside its closed range")
    if str(value) != text:
        raise Refusal(f"{label} is not canonical decimal")
    return value


def _identity(text: str, label: str) -> str:
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise Refusal(f"{label} is not 32-byte lowercase hexadecimal")
    if text == "0" * 64:
        raise Refusal(f"{label} must not be the all-zero identity")
    return text


def render_proposal_tsv(proposal: SourceRowProposal) -> bytes:
    values = (
        SCHEMA,
        PROMOTION_STATE,
        TABLE_TARGET,
        RUNTIME_AUTHORITY,
        str(proposal.selector),
        str(QUALIFICATION_FIELD_COUNT),
        str(proposal.live_literal_bytes),
        *proposal.identities,
    )
    return "".join(
        f"{name}\t{value}\n" for name, value in zip(FIELDS, values)
    ).encode("ascii")


def parse_proposal_bytes(raw: bytes, label: str = "source-row-proposal.tsv") -> SourceRowProposal:
    if not raw or len(raw) > MAX_PROPOSAL_BYTES:
        raise Refusal(f"{label} is empty or exceeds {MAX_PROPOSAL_BYTES} bytes")
    if not raw.endswith(b"\n") or b"\r" in raw or b"\0" in raw:
        raise Refusal(f"{label} is not canonical LF-terminated text")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise Refusal(f"{label} is not ASCII") from error

    lines = text.splitlines()
    if len(lines) != len(FIELDS):
        raise Refusal(f"{label} does not have exactly {len(FIELDS)} fields")
    values: dict[str, str] = {}
    for expected_name, line in zip(FIELDS, lines):
        if line.count("\t") != 1:
            raise Refusal(f"{label}:{expected_name} is not one TSV pair")
        name, value = line.split("\t")
        if name != expected_name or not value:
            raise Refusal(f"{label} has a missing, reordered, or empty {expected_name}")
        values[name] = value

    exact_headers = {
        "schema": SCHEMA,
        "promotion_state": PROMOTION_STATE,
        "table_target": TABLE_TARGET,
        "runtime_authority": RUNTIME_AUTHORITY,
        "qualification_field_count": str(QUALIFICATION_FIELD_COUNT),
    }
    for name, expected in exact_headers.items():
        if values[name] != expected:
            raise Refusal(f"{label}:{name} is not {expected!r}")

    selector = _canonical_decimal(values["selector"], MAX_U16, "selector", zero_ok=True)
    live_literal_bytes = _canonical_decimal(
        values["live_literal_bytes"],
        MAX_U32,
        "live_literal_bytes",
        zero_ok=False,
    )
    identities = tuple(_identity(values[name], name) for name in IDENTITY_FIELDS)
    proposal = SourceRowProposal(
        selector=selector,
        live_literal_bytes=live_literal_bytes,
        identities=identities,
        canonical_bytes=raw,
        sha256=hashlib.sha256(raw).hexdigest(),
    )
    if render_proposal_tsv(proposal) != raw:
        raise Refusal(f"{label} is not the canonical source-row rendering")
    return proposal


def read_proposal(path_text: str) -> SourceRowProposal:
    path = Path(path_text)
    if not path.is_absolute():
        raise Refusal("proposal path must be absolute")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise Refusal(f"cannot inspect proposal: {error}") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size <= 0
        or metadata.st_size > MAX_PROPOSAL_BYTES
    ):
        raise Refusal(
            "proposal must be an owned, mode-0600, bounded, singly linked regular file"
        )
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_NONBLOCK"):
        raise Refusal("proposal reopening requires O_NOFOLLOW and O_NONBLOCK")

    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise Refusal(f"cannot open proposal without following links: {error}") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or _stable_identity(before) != _stable_identity(metadata)
        ):
            raise Refusal("proposal changed while being opened")
        first = _read_exact_extent(descriptor, before.st_size)
        middle = os.fstat(descriptor)
        if _stable_identity(middle) != _stable_identity(before):
            raise Refusal("proposal changed during its first bounded read")
        second = _read_exact_extent(descriptor, before.st_size)
        after = os.fstat(descriptor)
        if _stable_identity(after) != _stable_identity(before) or second != first:
            raise Refusal("proposal changed across its two bounded reads")
    finally:
        os.close(descriptor)
    return parse_proposal_bytes(first, str(path))


def audit_support_source(
    raw: bytes,
    production_raw: bytes,
    label: str = "search_support.rs",
    production_label: str = "production_rows.rs",
) -> str:
    """Require the isolated production-empty and closed-constructor shape."""

    try:
        source = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise Refusal(f"{label} is not ASCII Rust source") from error
    production_module = """mod production_rows;
use production_rows::PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_ROWS_V1;"""
    private_module_gate = """#[cfg(feature = "search-span-qualification-private-v1")]
mod private_rows;
#[cfg(feature = "search-span-qualification-private-v1")]
use private_rows::PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_ROWS_V1;"""
    constructor_gate = re.compile(
        r"""#\[cfg\(feature = "search-span-qualification-private-v1"\)\]
    #\[allow\(
        dead_code,
        clippy::too_many_arguments,
        reason = "the private atom retains this solely for canonical reviewed row construction"
    \)\]
    const fn private_qualification\(""",
        re.MULTILINE,
    )
    checks = (
        (
            source.count(production_module) == 1,
            "isolated production child module is missing or duplicated",
        ),
        (
            "const PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_ROWS_V1" not in source,
            "production authority table remains in the parent support source",
        ),
        (
            source.count("const fn production(") == 0,
            "production constructor escaped its isolated authority atom",
        ),
        (
            source.count(private_module_gate) == 1,
            "private child module is not exactly feature gated",
        ),
        (
            len(constructor_gate.findall(source)) == 1,
            "private constructor is absent, duplicated, public, or not feature gated",
        ),
        (
            source.count("const fn private_qualification(") == 1,
            "private constructor has an ambiguous second definition",
        ),
    )
    for accepted, message in checks:
        if not accepted:
            raise Refusal(f"{label}: {message}")
    if production_raw != EMPTY_PRODUCTION_MODULE:
        raise Refusal(
            f"{production_label}: isolated production atom is not the canonical empty module"
        )
    if production_raw.count(b"    const fn production(") != 1:
        raise Refusal(
            f"{production_label}: production-only constructor is not uniquely child scoped"
        )
    if b"private_qualification" in production_raw:
        raise Refusal(
            f"{production_label}: production atom reached the private constructor domain"
        )
    return hashlib.sha256(raw + b"\0" + production_raw).hexdigest()


def _rust_identity(identity: str) -> str:
    values = [f"0x{identity[index:index + 2]}" for index in range(0, len(identity), 2)]
    lines = []
    for offset in range(0, len(values), 12):
        lines.append("            " + ", ".join(values[offset : offset + 12]) + ",")
    return "[\n" + "\n".join(lines) + "\n        ]"


def render_private_module(proposal: SourceRowProposal | None) -> bytes:
    if proposal is None:
        table = "&[];"
    else:
        arguments = [
            f"        {proposal.selector},",
            f"        {proposal.live_literal_bytes},",
        ]
        for name in IDENTITY_FIELDS:
            rendered = _rust_identity(proposal.identity(name))
            arguments.append("        " + rendered + ",")
        row = "\n".join(arguments)
        table = (
            "&[\n"
            f"    // source-row-proposal.tsv SHA-256: {proposal.sha256}\n"
            "    SourceQualifiedStaticSearchSpanRowV1::private_qualification(\n"
            f"{row}\n"
            "    ),\n"
            "];"
        )
    return (MODULE_PREFIX + TABLE_DECLARATION + table + MODULE_SUFFIX).encode("ascii")


def render_reviewed_private_module(
    proposal: SourceRowProposal,
    expected_sha256: str,
) -> bytes:
    expected = _identity(expected_sha256, "expected proposal SHA-256")
    if proposal.sha256 != expected:
        raise Refusal("proposal digest differs from the independently reviewed identity")
    return render_private_module(proposal)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    canonicalize = commands.add_parser(
        "canonicalize", help="parse and reproduce one exact proposal TSV"
    )
    canonicalize.add_argument("proposal")
    digest = commands.add_parser("sha256", help="parse and hash one exact proposal TSV")
    digest.add_argument("proposal")
    render = commands.add_parser(
        "render-private-module",
        help="render the complete empty or one-row private Rust module",
    )
    render.add_argument("proposal", nargs="?")
    reviewed_render = commands.add_parser(
        "render-reviewed-private-module",
        help="parse once, bind the external SHA-256, and render the private module",
    )
    reviewed_render.add_argument("proposal")
    reviewed_render.add_argument("expected_sha256")
    audit = commands.add_parser(
        "audit-support-source",
        help="verify support plus its isolated immutable production-empty atom",
    )
    audit.add_argument("source")
    audit.add_argument("production_source")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "canonicalize":
            proposal = read_proposal(arguments.proposal)
            sys.stdout.buffer.write(render_proposal_tsv(proposal))
        elif arguments.command == "sha256":
            print(read_proposal(arguments.proposal).sha256)
        elif arguments.command == "render-private-module":
            proposal = read_proposal(arguments.proposal) if arguments.proposal else None
            sys.stdout.buffer.write(render_private_module(proposal))
        elif arguments.command == "render-reviewed-private-module":
            proposal = read_proposal(arguments.proposal)
            sys.stdout.buffer.write(
                render_reviewed_private_module(proposal, arguments.expected_sha256)
            )
        elif arguments.command == "audit-support-source":
            source_path = Path(arguments.source)
            production_path = Path(arguments.production_source)
            if not source_path.is_absolute():
                raise Refusal("support source path must be absolute")
            if not production_path.is_absolute():
                raise Refusal("production source path must be absolute")
            raw = source_path.read_bytes()
            if not raw or len(raw) > (1 << 20):
                raise Refusal("support source is empty or exceeds its source bound")
            production_raw = production_path.read_bytes()
            if not production_raw or len(production_raw) > (1 << 18):
                raise Refusal(
                    "production source is empty or exceeds its source bound"
                )
            print(
                audit_support_source(
                    raw,
                    production_raw,
                    str(source_path),
                    str(production_path),
                )
            )
        else:
            raise AssertionError("argparse admitted an unknown command")
    except (OSError, Refusal) as error:
        print(f"linux-search-private-row: refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
