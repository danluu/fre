#!/usr/bin/env python3
"""Strict production authorization parser and complete Rust atom renderer.

The input is an externally reviewed production authorization, not qualification
evidence and not a source-row proposal. This tool accepts only its exact closed
grammar, binds its independently supplied SHA-256, and writes canonical source
to stdout. It never edits the repository or manufactures authority.
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


SCHEMA = "fre-aot-linux-search-span-production-authorization-v1"
AUTHORIZATION_STATE = "reviewed-production-authorization"
TABLE_TARGET = "production-runtime-authority"
RUNTIME_AUTHORITY = "source-reviewed"
QUALIFICATION_FIELD_COUNT = 12
MAX_AUTHORIZATION_BYTES = 256 << 10
MAX_U16 = (1 << 16) - 1
MAX_U32 = (1 << 32) - 1

HEADER_FIELDS = (
    "schema",
    "authorization_state",
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
PROVENANCE_FIELDS = (
    "private_candidate_commit",
    "private_promotion_commit",
    "private_source_row_proposal_sha256",
    "post_private_evidence_commit",
    "post_private_evidence_tree",
    "post_private_evidence_manifest_sha256",
    "post_private_evidence_receipt_sha256",
    "post_private_evidence_bundle_sha256",
    "post_private_evidence_final_image_sha256",
)
FIELDS = HEADER_FIELDS + IDENTITY_FIELDS + PROVENANCE_FIELDS

PRIVATE_MODULE_PREFIX = """use super::SourceQualifiedStaticSearchSpanRowV1;

/// Literal, source-reviewed private Search-v1 Span qualification rows.
///
/// This module is compiled only by `search-span-qualification-private-v1`.
/// The table begins empty and stays inert unless a qualification promotion
/// replaces this complete file with the canonical renderer's exact projection
/// of one independently measured and reviewed `source-row-proposal.tsv`.
"""
PRIVATE_TABLE_DECLARATION = """pub(super) const PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_ROWS_V1:
    &[SourceQualifiedStaticSearchSpanRowV1] = """
PRIVATE_MODULE_SUFFIX = """

const _: () = assert!(super::qualification_rows_are_canonical(
    PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_ROWS_V1
));
"""
PRODUCTION_MODULE_HEADER = """use super::SourceQualifiedStaticSearchSpanRowV1;

"""
PRODUCTION_CONSTRUCTOR = """impl SourceQualifiedStaticSearchSpanRowV1 {
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

"""
EMPTY_PRODUCTION_MODULE = (
    PRODUCTION_MODULE_HEADER
    + PRODUCTION_CONSTRUCTOR
    + """/// Literal, source-reviewed production Search-v1 Span qualification rows.
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
).encode("ascii")
PROMOTED_PRODUCTION_MODULE_PREFIX = (
    PRODUCTION_MODULE_HEADER
    + PRODUCTION_CONSTRUCTOR
    + """/// Literal, source-reviewed production Search-v1 Span qualification rows.
///
/// This complete file is the canonical projection of one externally
/// SHA-pinned, reviewed production authorization. It is ordinary runtime
/// authority and is not generated by a build script or selected at runtime.
"""
)
PRODUCTION_TABLE_DECLARATION = """pub(super) const PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_ROWS_V1:
    &[SourceQualifiedStaticSearchSpanRowV1] = """
PROMOTED_PRODUCTION_MODULE_SUFFIX = """

const _: () = assert!(super::qualification_rows_are_canonical(
    PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_ROWS_V1
));
const _: () = assert!(PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_ROWS_V1.len() == 1);
"""


class Refusal(ValueError):
    """The input is not the exact closed production-authorization grammar."""


@dataclass(frozen=True)
class ProductionAuthorization:
    selector: int
    live_literal_bytes: int
    identities: tuple[str, ...]
    private_candidate_commit: str
    private_promotion_commit: str
    private_source_row_proposal_sha256: str
    post_private_evidence_commit: str
    post_private_evidence_tree: str
    post_private_evidence_hashes: tuple[str, ...]
    canonical_bytes: bytes
    sha256: str

    def identity(self, name: str) -> str:
        return self.identities[IDENTITY_FIELDS.index(name)]

    def provenance(self, name: str) -> str:
        if name == "private_candidate_commit":
            return self.private_candidate_commit
        if name == "private_promotion_commit":
            return self.private_promotion_commit
        if name == "private_source_row_proposal_sha256":
            return self.private_source_row_proposal_sha256
        if name == "post_private_evidence_commit":
            return self.post_private_evidence_commit
        if name == "post_private_evidence_tree":
            return self.post_private_evidence_tree
        return self.post_private_evidence_hashes[
            PROVENANCE_FIELDS[5:].index(name)
        ]


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


def _canonical_decimal(
    text: str,
    maximum: int,
    label: str,
    *,
    zero_ok: bool,
) -> int:
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


def _hex_identity(text: str, bytes_count: int, label: str) -> str:
    expected_length = bytes_count * 2
    if (
        len(text) != expected_length
        or any(character not in "0123456789abcdef" for character in text)
    ):
        raise Refusal(
            f"{label} is not {bytes_count}-byte lowercase hexadecimal"
        )
    if text == "0" * expected_length:
        raise Refusal(f"{label} must not be the all-zero identity")
    return text


def render_authorization_tsv(
    authorization: ProductionAuthorization,
) -> bytes:
    values = (
        SCHEMA,
        AUTHORIZATION_STATE,
        TABLE_TARGET,
        RUNTIME_AUTHORITY,
        str(authorization.selector),
        str(QUALIFICATION_FIELD_COUNT),
        str(authorization.live_literal_bytes),
        *authorization.identities,
        *(authorization.provenance(name) for name in PROVENANCE_FIELDS),
    )
    return "".join(
        f"{name}\t{value}\n" for name, value in zip(FIELDS, values)
    ).encode("ascii")


def parse_authorization_bytes(
    raw: bytes,
    label: str = "production-authorization.tsv",
) -> ProductionAuthorization:
    if not raw or len(raw) > MAX_AUTHORIZATION_BYTES:
        raise Refusal(
            f"{label} is empty or exceeds {MAX_AUTHORIZATION_BYTES} bytes"
        )
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
            raise Refusal(
                f"{label} has a missing, reordered, or empty {expected_name}"
            )
        values[name] = value

    exact_headers = {
        "schema": SCHEMA,
        "authorization_state": AUTHORIZATION_STATE,
        "table_target": TABLE_TARGET,
        "runtime_authority": RUNTIME_AUTHORITY,
        "qualification_field_count": str(QUALIFICATION_FIELD_COUNT),
    }
    for name, expected in exact_headers.items():
        if values[name] != expected:
            raise Refusal(f"{label}:{name} is not {expected!r}")

    selector = _canonical_decimal(
        values["selector"],
        MAX_U16,
        "selector",
        zero_ok=True,
    )
    live_literal_bytes = _canonical_decimal(
        values["live_literal_bytes"],
        MAX_U32,
        "live_literal_bytes",
        zero_ok=False,
    )
    identities = tuple(
        _hex_identity(values[name], 32, name) for name in IDENTITY_FIELDS
    )
    private_candidate_commit = _hex_identity(
        values["private_candidate_commit"],
        20,
        "private_candidate_commit",
    )
    private_promotion_commit = _hex_identity(
        values["private_promotion_commit"],
        20,
        "private_promotion_commit",
    )
    private_source_row_proposal_sha256 = _hex_identity(
        values["private_source_row_proposal_sha256"],
        32,
        "private_source_row_proposal_sha256",
    )
    post_private_evidence_commit = _hex_identity(
        values["post_private_evidence_commit"],
        20,
        "post_private_evidence_commit",
    )
    post_private_evidence_tree = _hex_identity(
        values["post_private_evidence_tree"],
        20,
        "post_private_evidence_tree",
    )
    post_private_evidence_hashes = tuple(
        _hex_identity(values[name], 32, name)
        for name in PROVENANCE_FIELDS[5:]
    )
    if private_candidate_commit == private_promotion_commit:
        raise Refusal(
            "private promotion must differ from its exact candidate parent"
        )
    if post_private_evidence_commit != private_promotion_commit:
        raise Refusal(
            "post-private evidence must name the exact private promotion commit"
        )

    authorization = ProductionAuthorization(
        selector=selector,
        live_literal_bytes=live_literal_bytes,
        identities=identities,
        private_candidate_commit=private_candidate_commit,
        private_promotion_commit=private_promotion_commit,
        private_source_row_proposal_sha256=(
            private_source_row_proposal_sha256
        ),
        post_private_evidence_commit=post_private_evidence_commit,
        post_private_evidence_tree=post_private_evidence_tree,
        post_private_evidence_hashes=post_private_evidence_hashes,
        canonical_bytes=raw,
        sha256=hashlib.sha256(raw).hexdigest(),
    )
    if render_authorization_tsv(authorization) != raw:
        raise Refusal(
            f"{label} is not the canonical production-authorization rendering"
        )
    return authorization


def read_authorization(path_text: str) -> ProductionAuthorization:
    path = Path(path_text)
    if not path.is_absolute():
        raise Refusal("production authorization path must be absolute")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise Refusal(f"cannot inspect production authorization: {error}") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size <= 0
        or metadata.st_size > MAX_AUTHORIZATION_BYTES
    ):
        raise Refusal(
            "production authorization must be an owned, mode-0600, bounded, "
            "singly linked regular file"
        )
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_NONBLOCK"):
        raise Refusal(
            "production authorization reopening requires O_NOFOLLOW and O_NONBLOCK"
        )

    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise Refusal(
            f"cannot open production authorization without following links: {error}"
        ) from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or _stable_identity(before) != _stable_identity(metadata)
        ):
            raise Refusal("production authorization changed while being opened")
        first = _read_exact_extent(descriptor, before.st_size)
        middle = os.fstat(descriptor)
        if _stable_identity(middle) != _stable_identity(before):
            raise Refusal(
                "production authorization changed during its first bounded read"
            )
        second = _read_exact_extent(descriptor, before.st_size)
        after = os.fstat(descriptor)
        if _stable_identity(after) != _stable_identity(before) or second != first:
            raise Refusal(
                "production authorization changed across its two bounded reads"
            )
    finally:
        os.close(descriptor)
    return parse_authorization_bytes(first, str(path))


def _reviewed(
    authorization: ProductionAuthorization,
    expected_sha256: str,
) -> ProductionAuthorization:
    expected = _hex_identity(
        expected_sha256,
        32,
        "expected production authorization SHA-256",
    )
    if authorization.sha256 != expected:
        raise Refusal(
            "production authorization digest differs from the independent "
            "review boundary"
        )
    return authorization


def _rust_identity(identity: str) -> str:
    values = [
        f"0x{identity[index:index + 2]}"
        for index in range(0, len(identity), 2)
    ]
    lines = []
    for offset in range(0, len(values), 12):
        lines.append(
            "            " + ", ".join(values[offset : offset + 12]) + ","
        )
    return "[\n" + "\n".join(lines) + "\n        ]"


def _render_row_arguments(authorization: ProductionAuthorization) -> str:
    arguments = [
        f"        {authorization.selector},",
        f"        {authorization.live_literal_bytes},",
    ]
    for name in IDENTITY_FIELDS:
        arguments.append(
            "        " + _rust_identity(authorization.identity(name)) + ","
        )
    return "\n".join(arguments)


def render_private_module_from_authorization(
    authorization: ProductionAuthorization,
) -> bytes:
    table = (
        "&[\n"
        "    // source-row-proposal.tsv SHA-256: "
        f"{authorization.private_source_row_proposal_sha256}\n"
        "    SourceQualifiedStaticSearchSpanRowV1::private_qualification(\n"
        f"{_render_row_arguments(authorization)}\n"
        "    ),\n"
        "];"
    )
    return (
        PRIVATE_MODULE_PREFIX
        + PRIVATE_TABLE_DECLARATION
        + table
        + PRIVATE_MODULE_SUFFIX
    ).encode("ascii")


def render_empty_private_module() -> bytes:
    return (
        PRIVATE_MODULE_PREFIX
        + PRIVATE_TABLE_DECLARATION
        + "&[];"
        + PRIVATE_MODULE_SUFFIX
    ).encode("ascii")


def render_production_module(
    authorization: ProductionAuthorization,
) -> bytes:
    table = (
        "&[\n"
        "    // production-authorization.tsv SHA-256: "
        f"{authorization.sha256}\n"
        "    SourceQualifiedStaticSearchSpanRowV1::production(\n"
        f"{_render_row_arguments(authorization)}\n"
        "    ),\n"
        "];"
    )
    return (
        PROMOTED_PRODUCTION_MODULE_PREFIX
        + PRODUCTION_TABLE_DECLARATION
        + table
        + PROMOTED_PRODUCTION_MODULE_SUFFIX
    ).encode("ascii")


def classify_live_production_atom_shape_non_authoritative(raw: bytes) -> str:
    """Classify exact renderer syntax without granting or checking authority.

    This helper exists only so source-layout tests remain meaningful before and
    after the one-file promotion. It neither possesses the reviewed
    authorization nor validates evidence, Git history, or deployment. The
    candidate-rooted verifier must continue to use ``audit_support_source``,
    which accepts only ``EMPTY_PRODUCTION_MODULE``.
    """

    if raw == EMPTY_PRODUCTION_MODULE:
        return "canonical-empty"
    if not raw or len(raw) > (1 << 18) or b"\r" in raw or b"\0" in raw:
        raise Refusal("live production atom is not bounded canonical source")

    prefix = (
        PROMOTED_PRODUCTION_MODULE_PREFIX
        + PRODUCTION_TABLE_DECLARATION
        + "&[\n"
        + "    // production-authorization.tsv SHA-256: "
    ).encode("ascii")
    after_digest = (
        "\n    SourceQualifiedStaticSearchSpanRowV1::production(\n"
    ).encode("ascii")
    suffix = (
        "\n    ),\n];" + PROMOTED_PRODUCTION_MODULE_SUFFIX
    ).encode("ascii")
    if not raw.startswith(prefix) or not raw.endswith(suffix):
        raise Refusal(
            "live production atom is neither canonical empty nor canonical one-row source"
        )

    body = raw[len(prefix) : len(raw) - len(suffix)]
    if len(body) < 64 or body[64 : 64 + len(after_digest)] != after_digest:
        raise Refusal("live production atom has a malformed authorization binding")
    try:
        authorization_sha256 = body[:64].decode("ascii")
        arguments = body[64 + len(after_digest) :].decode("ascii")
    except UnicodeDecodeError as error:
        raise Refusal("live production atom is not ASCII Rust source") from error
    _hex_identity(
        authorization_sha256,
        32,
        "rendered production authorization SHA-256",
    )

    lines = arguments.splitlines()
    if "\n".join(lines) != arguments or len(lines) != 57:
        raise Refusal("live production atom has a noncanonical row layout")

    def rendered_decimal(
        index: int,
        maximum: int,
        label: str,
        *,
        zero_ok: bool,
    ) -> int:
        match = re.fullmatch(r"        (0|[1-9][0-9]*),", lines[index])
        if match is None:
            raise Refusal(f"live production atom has a malformed {label}")
        return _canonical_decimal(
            match.group(1),
            maximum,
            f"rendered {label}",
            zero_ok=zero_ok,
        )

    rendered_decimal(0, MAX_U16, "selector", zero_ok=True)
    rendered_decimal(1, MAX_U32, "live_literal_bytes", zero_ok=False)
    for identity_index, name in enumerate(IDENTITY_FIELDS):
        offset = 2 + identity_index * 5
        block = "\n".join(lines[offset : offset + 5])
        tokens = re.findall(r"0x([0-9a-f]{2})", block)
        if len(tokens) != 32:
            raise Refusal(f"live production atom has a malformed {name}")
        identity = _hex_identity(
            "".join(tokens),
            32,
            f"rendered {name}",
        )
        if block != "        " + _rust_identity(identity) + ",":
            raise Refusal(f"live production atom has a noncanonical {name}")
    return "canonical-one-row"


def audit_support_source(
    raw: bytes,
    production_raw: bytes,
    label: str = "search_support.rs",
    production_label: str = "production_rows.rs",
) -> str:
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
    private_constructor = re.compile(
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
            source.count(private_module_gate) == 1,
            "private child module is not exactly feature gated",
        ),
        (
            "const PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_ROWS_V1"
            not in source,
            "production authority table remains inline",
        ),
        (
            source.count("const fn production(") == 0,
            "production constructor escaped its isolated authority atom",
        ),
        (
            len(private_constructor.findall(source)) == 1
            and source.count("const fn private_qualification(") == 1,
            "private constructor is absent, duplicated, public, or ungated",
        ),
    )
    for accepted, message in checks:
        if not accepted:
            raise Refusal(f"{label}: {message}")
    if production_raw != EMPTY_PRODUCTION_MODULE:
        raise Refusal(
            f"{production_label}: production atom is not canonical empty state"
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


def _bounded_absolute_source(path_text: str, label: str, maximum: int) -> bytes:
    path = Path(path_text)
    if not path.is_absolute():
        raise Refusal(f"{label} path must be absolute")
    raw = path.read_bytes()
    if not raw or len(raw) > maximum:
        raise Refusal(f"{label} is empty or exceeds its source bound")
    return raw


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    canonicalize = commands.add_parser(
        "canonicalize",
        help="parse and reproduce one exact production authorization",
    )
    canonicalize.add_argument("authorization")
    digest = commands.add_parser(
        "sha256",
        help="parse and hash one exact production authorization",
    )
    digest.add_argument("authorization")
    bindings = commands.add_parser(
        "verification-bindings",
        help="emit reviewed commit/tree bindings for the Git verifier",
    )
    bindings.add_argument("authorization")
    bindings.add_argument("expected_sha256")
    render_private = commands.add_parser(
        "render-reviewed-private-module",
        help="derive the exact already-promoted private atom",
    )
    render_private.add_argument("authorization")
    render_private.add_argument("expected_sha256")
    render_production = commands.add_parser(
        "render-reviewed-production-module",
        help="render the one-row production atom after external SHA review",
    )
    render_production.add_argument("authorization")
    render_production.add_argument("expected_sha256")
    commands.add_parser(
        "render-empty-private-module",
        help="render the exact pre-private empty atom",
    )
    commands.add_parser(
        "render-empty-production-module",
        help="render the exact current fail-closed production atom",
    )
    audit = commands.add_parser(
        "audit-support-source",
        help="audit support plus its isolated empty production authority atom",
    )
    audit.add_argument("source")
    audit.add_argument("production_source")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "canonicalize":
            authorization = read_authorization(arguments.authorization)
            sys.stdout.buffer.write(render_authorization_tsv(authorization))
        elif arguments.command == "sha256":
            print(read_authorization(arguments.authorization).sha256)
        elif arguments.command == "verification-bindings":
            authorization = _reviewed(
                read_authorization(arguments.authorization),
                arguments.expected_sha256,
            )
            print(authorization.private_candidate_commit)
            print(authorization.private_promotion_commit)
            print(authorization.post_private_evidence_commit)
            print(authorization.post_private_evidence_tree)
        elif arguments.command == "render-reviewed-private-module":
            authorization = _reviewed(
                read_authorization(arguments.authorization),
                arguments.expected_sha256,
            )
            sys.stdout.buffer.write(
                render_private_module_from_authorization(authorization)
            )
        elif arguments.command == "render-reviewed-production-module":
            authorization = _reviewed(
                read_authorization(arguments.authorization),
                arguments.expected_sha256,
            )
            sys.stdout.buffer.write(render_production_module(authorization))
        elif arguments.command == "render-empty-private-module":
            sys.stdout.buffer.write(render_empty_private_module())
        elif arguments.command == "render-empty-production-module":
            sys.stdout.buffer.write(EMPTY_PRODUCTION_MODULE)
        elif arguments.command == "audit-support-source":
            source = _bounded_absolute_source(
                arguments.source,
                "support source",
                1 << 20,
            )
            production = _bounded_absolute_source(
                arguments.production_source,
                "production source",
                1 << 18,
            )
            print(
                audit_support_source(
                    source,
                    production,
                    arguments.source,
                    arguments.production_source,
                )
            )
        else:
            raise AssertionError("argparse admitted an unknown command")
    except (OSError, Refusal) as error:
        print(f"linux-search-production-row: refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
