#!/usr/bin/env python3
"""Fail-closed lexical policy for benchmark-candidate production source.

This is intentionally a policy guard, not a Rust semantic proof. It rejects
new production decisions that are visibly keyed by raw regex spelling,
benchmark identity or source fingerprints, and rejects reachable constants
whose names advertise an expected semantic answer. Parsed regex structure is
not tainted: dispatch over HIR/model structure is the intended implementation
boundary.
"""

from __future__ import annotations

import posixpath
import re
import subprocess
import sys
from dataclasses import dataclass


POLICY_VERSION = "1"
MAX_SOURCE_BYTES = 8 * 1024 * 1024

# These are model inputs, not benchmark answers. Their definitions and
# unconditional use are allowed; comparing caller-controlled source to one of
# them is still rejected by the exact-source rules below.
MODEL_DEFINITION_CONSTANTS = {
    "tools/rebar-compare/src/lib.rs": {
        "REGEX_REDUX_FLATTEN_PATTERN",
        "REGEX_REDUX_STAGES",
        "REGEX_REDUX_SUBSTITUTIONS",
        "REGEX_REDUX_VARIANTS",
    },
}

# A source fingerprint may key a semantic artifact cache. This allowlist is
# deliberately about the receiver's role, not a whole file or crate. Exact
# comparisons against literals/constants remain forbidden even in a cache.
CACHE_BINDING_RECEIVER = re.compile(
    r"(?:artifact|binding|cache|compiled|identity|receipt|verified)", re.IGNORECASE
)

RAW_NAME = re.compile(
    r"(?:^|_)(?:raw_regex|raw_pattern|regex_source|pattern_source|"
    r"source_regex|source_pattern|regex_text|pattern_text)(?:$|_)",
    re.IGNORECASE,
)
IDENTITY_NAME = re.compile(
    r"(?:^|_)(?:job_id|benchmark_id|benchmark_name|case_name|corpus_name|"
    r"dataset_name|fixture_name|workload_name)(?:$|_)",
    re.IGNORECASE,
)
HASH_NAME = re.compile(
    r"(?:^|_)(?:sha(?:256)?|hash|digest|fingerprint|checksum|source_identity)"
    r"(?:$|_)",
    re.IGNORECASE,
)
EXPECTED_ANSWER_NAME = re.compile(
    r"(?:(?:EXPECTED|GOLDEN|ORACLE)(?:_[A-Z0-9]+)*_"
    r"(?:ANSWER|COUNT|REPORT|RESULT|OUTPUT|VALUE|SPANS?|CAPTURES?)|"
    r"(?:ANSWER|COUNT|REPORT|RESULT|OUTPUT|VALUE|SPANS?|CAPTURES?)"
    r"(?:_[A-Z0-9]+)*_(?:EXPECTED|GOLDEN|ORACLE)|"
    r"KNOWN_(?:ANSWER|COUNT|REPORT|RESULT|OUTPUT)(?:_[A-Z0-9]+)*)"
)
DECLARATION = re.compile(
    r"\b(?:let\s+(?:mut\s+)?|const\s+|static\s+(?:mut\s+)?)"
    r"([A-Za-z_][A-Za-z0-9_]*)[^=;]*=\s*([^;]+);",
    re.DOTALL,
)
CONSTANT_DECLARATION = re.compile(
    r"\b(?:const(?!\s+fn\b)\s+|static\s+(?:mut\s+)?)"
    r"([A-Za-z_][A-Za-z0-9_]*)[^=]*?=\s*([^;]+);",
    re.DOTALL,
)
STRING_SOURCE_DECLARATION = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\s*:\s*"
    r"(?:&\s*(?:'[_A-Za-z][A-Za-z0-9_]*\s*)?)?"
    r"(?:str|String|Cow\s*<[^>]*str|\[\s*(?:String|&\s*str)\s*\])"
)
INCLUDE_FIXTURE = re.compile(
    r"include_(?:str|bytes)!\s*\([^)]*\)",
    re.IGNORECASE | re.DOTALL,
)
IDENTIFIER = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
RAW_STRING_START = re.compile(r"(?:br|rb|r)(#{0,32})\"")


@dataclass(frozen=True)
class Violation:
    path: str
    line: int
    rule: str
    evidence: str

    def fingerprint(self) -> tuple[str, str, str]:
        normalized = re.sub(r"\s+", " ", self.evidence).strip()
        return (self.path, self.rule, normalized)


def die(message: str) -> None:
    print(f"candidate_source_policy_v{POLICY_VERSION}\tresult=ERROR\tdetail={message}", file=sys.stderr)
    raise SystemExit(2)


def git(repo: str, *arguments: str, text: bool = False) -> bytes | str:
    result = subprocess.run(
        ["git", "-C", repo, *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=text,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() if text else result.stderr.decode("utf-8", "replace").strip()
        die(f"git_{arguments[0].replace('-', '_')}_failed:{detail[:160]}")
    return result.stdout


def production_path(path: str, production_crate_paths: set[str]) -> bool:
    if path.endswith(".rs") and path.startswith("crates/") and "/src/" in path:
        # A filename does not prove that Rust excludes a module from candidate
        # execution. In particular, production `*_qualification.rs` modules
        # are candidate code whenever the production module graph reaches
        # them; cfg(test)-only and otherwise unreachable files are not.
        return path in production_crate_paths
    # Every production module in the candidate library is in scope, including
    # modules added after this policy was written. The FRE runner is also
    # candidate-executed code. Other examples are qualification utilities,
    # trusted collectors or reference adapters and do not execute in the
    # candidate process.
    return (
        path.endswith(".rs")
        and path.startswith("tools/rebar-compare/src/")
    ) or path == "tools/rebar-compare/examples/fre_rebar_runner.rs"


def changed_production_paths(
    repo: str, baseline: str, candidate: str
) -> tuple[list[str], set[str]]:
    baseline_crate_paths = production_crate_source_paths(repo, baseline)
    candidate_crate_paths = production_crate_source_paths(repo, candidate)
    newly_reachable = candidate_crate_paths - baseline_crate_paths
    raw = git(
        repo,
        "diff",
        "--name-only",
        "--diff-filter=ACMR",
        "-z",
        baseline,
        candidate,
        "--",
        "crates",
        "tools/rebar-compare",
    )
    assert isinstance(raw, bytes)
    changed = [item.decode("utf-8", "strict") for item in raw.split(b"\0") if item]
    paths = {
        path for path in changed if production_path(path, candidate_crate_paths)
    }
    # A candidate can make an unchanged source file executable merely by
    # changing its parent module declaration. Scan that newly reachable blob
    # even though it does not appear in `git diff --name-only`.
    paths.update(newly_reachable)
    return sorted(paths), newly_reachable


def read_blobs(repo: str, revision: str, paths: list[str]) -> dict[str, str]:
    if any(any(control in path for control in ("\n", "\r", "\t")) for path in paths):
        die("control_character_in_source_path")
    batch_input = b"".join(f"{revision}:{path}\n".encode() for path in paths)
    process = subprocess.run(
        ["git", "-C", repo, "cat-file", "--batch"],
        input=batch_input,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != 0:
        die(f"git_cat_file_failed:{process.stderr.decode('utf-8', 'replace').strip()[:160]}")

    blobs: dict[str, str] = {}
    output = memoryview(process.stdout)
    offset = 0
    for path in paths:
        newline = process.stdout.find(b"\n", offset)
        if newline == -1:
            die(f"missing_source_blob_header:{path}")
        header = process.stdout[offset:newline]
        offset = newline + 1
        fields = header.split()
        if len(fields) == 2 and fields[1] == b"missing":
            continue
        if len(fields) != 3 or fields[1] != b"blob":
            die(f"invalid_source_blob:{path}")
        try:
            size = int(fields[2])
        except ValueError:
            die(f"invalid_source_blob_size:{path}")
        if size > MAX_SOURCE_BYTES:
            die(f"source_file_too_large:{path}")
        end = offset + size
        if end >= len(output) or output[end] != ord("\n"):
            die(f"truncated_source_blob:{path}")
        content = bytes(output[offset:end])
        offset = end + 1
        try:
            blobs[path] = content.decode("utf-8")
        except UnicodeDecodeError:
            die(f"non_utf8_rust_source:{path}")
    return blobs


def lexical_mask(source: str, keep_strings: bool) -> str:
    """Remove comments, and optionally literals, while preserving offsets."""

    output = list(source)
    length = len(source)
    index = 0
    block_depth = 0
    state = "normal"
    raw_hashes = 0

    def blank(at: int) -> None:
        if source[at] != "\n":
            output[at] = " "

    while index < length:
        if state == "line_comment":
            if source[index] == "\n":
                state = "normal"
            else:
                blank(index)
            index += 1
            continue
        if state == "block_comment":
            if source.startswith("/*", index):
                blank(index)
                if index + 1 < length:
                    blank(index + 1)
                block_depth += 1
                index += 2
            elif source.startswith("*/", index):
                blank(index)
                if index + 1 < length:
                    blank(index + 1)
                block_depth -= 1
                index += 2
                if block_depth == 0:
                    state = "normal"
            else:
                blank(index)
                index += 1
            continue
        if state == "string":
            if not keep_strings:
                blank(index)
            if source[index] == "\\":
                if index + 1 < length:
                    if not keep_strings:
                        blank(index + 1)
                    index += 2
            elif source[index] == '"':
                state = "normal"
                index += 1
            else:
                index += 1
            continue
        if state == "raw_string":
            terminator = '"' + ("#" * raw_hashes)
            if source.startswith(terminator, index):
                if not keep_strings:
                    for at in range(index, index + len(terminator)):
                        blank(at)
                index += len(terminator)
                state = "normal"
            else:
                if not keep_strings:
                    blank(index)
                index += 1
            continue
        if state == "char":
            if not keep_strings:
                blank(index)
            if source[index] == "\\" and index + 1 < length:
                if not keep_strings:
                    blank(index + 1)
                index += 2
            elif source[index] == "'":
                state = "normal"
                index += 1
            else:
                index += 1
            continue

        if source.startswith("//", index):
            blank(index)
            blank(index + 1)
            index += 2
            state = "line_comment"
        elif source.startswith("/*", index):
            blank(index)
            blank(index + 1)
            index += 2
            block_depth = 1
            state = "block_comment"
        elif source[index] == '"':
            if not keep_strings:
                blank(index)
            index += 1
            state = "string"
        elif source[index] in {"r", "b"}:
            raw = RAW_STRING_START.match(source, index)
            if raw is None:
                index += 1
                continue
            raw_hashes = len(raw.group(1))
            if not keep_strings:
                for at in range(index, raw.end()):
                    blank(at)
            index = raw.end()
            state = "raw_string"
        elif source[index] == "'":
            # Lifetimes have no closing quote. Only enter char state when a
            # plausible closing quote is nearby.
            closing = source.find("'", index + 1, min(length, index + 12))
            if closing == -1:
                index += 1
            else:
                if not keep_strings:
                    blank(index)
                index += 1
                state = "char"
        else:
            index += 1
    return "".join(output)


def matching(source: str, start: int, opening: str, closing: str) -> int | None:
    depth = 0
    for index in range(start, len(source)):
        if source[index] == opening:
            depth += 1
        elif source[index] == closing:
            depth -= 1
            if depth == 0:
                return index
    return None


def cfg_test_only(expression: str) -> bool:
    compact = re.sub(r"\s+", "", expression)
    if compact == "test":
        return True
    return compact.startswith("all(") and re.search(r"(?:^|[(,])test(?:[,)]|$)", compact) is not None


def remove_test_only_items(source: str) -> str:
    structure = lexical_mask(source, keep_strings=False)
    spans: list[tuple[int, int]] = []
    cursor = 0
    attribute = re.compile(r"#\s*\[\s*cfg\s*\(")
    while True:
        found = attribute.search(structure, cursor)
        if found is None:
            break
        open_paren = structure.find("(", found.start(), found.end())
        close_paren = matching(structure, open_paren, "(", ")")
        if close_paren is None:
            break
        close_bracket = structure.find("]", close_paren + 1)
        if close_bracket == -1:
            break
        cursor = close_bracket + 1
        if not cfg_test_only(structure[open_paren + 1 : close_paren]):
            continue

        item_start = found.start()
        item = close_bracket + 1
        while True:
            whitespace = re.match(r"\s*", structure[item:])
            assert whitespace is not None
            item += whitespace.end()
            if not structure.startswith("#[", item):
                break
            attribute_end = matching(structure, item + 1, "[", "]")
            if attribute_end is None:
                break
            item = attribute_end + 1

        semicolon = structure.find(";", item)
        brace = structure.find("{", item)
        if semicolon != -1 and (brace == -1 or semicolon < brace):
            item_end = semicolon + 1
        elif brace != -1:
            brace_end = matching(structure, brace, "{", "}")
            if brace_end is None:
                item_end = len(source)
            else:
                item_end = brace_end + 1
        else:
            item_end = len(source)
        spans.append((item_start, item_end))
        cursor = item_end

    if not spans:
        return source
    output = list(source)
    for start, end in spans:
        for index in range(start, end):
            if output[index] != "\n":
                output[index] = " "
    return "".join(output)


OUT_OF_LINE_MODULE = re.compile(r"\bmod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;")
ATTRIBUTE_BLOCK = re.compile(r"((?:#\s*\[[^\]]*\]\s*)+)$", re.DOTALL)
PATH_ATTRIBUTE = re.compile(r'#\s*\[\s*path\s*=\s*"([^"\r\n]+)"\s*\]')
INCLUDE_RUST_SOURCE = re.compile(
    r'\binclude!\s*\(\s*"([^"\r\n]+\.rs)"\s*\)', re.DOTALL
)


def tracked_crate_source_paths(repo: str, revision: str) -> list[str]:
    raw = git(repo, "ls-tree", "-r", "--name-only", "-z", revision, "--", "crates")
    assert isinstance(raw, bytes)
    paths = [item.decode("utf-8", "strict") for item in raw.split(b"\0") if item]
    return sorted(
        path
        for path in paths
        if path.endswith(".rs") and path.startswith("crates/") and "/src/" in path
    )


def module_targets(
    parent: str,
    name: str,
    attributes: str,
    tracked: set[str],
) -> set[str]:
    explicit = PATH_ATTRIBUTE.search(attributes)
    if explicit is not None:
        target = posixpath.normpath(
            posixpath.join(posixpath.dirname(parent), explicit.group(1))
        )
        return {target} if target in tracked else set()

    directory = posixpath.dirname(parent)
    basename = posixpath.basename(parent)
    if basename not in {"lib.rs", "main.rs", "mod.rs"}:
        directory = posixpath.join(directory, basename.removesuffix(".rs"))
    candidates = {
        posixpath.join(directory, f"{name}.rs"),
        posixpath.join(directory, name, "mod.rs"),
    }
    resolved = candidates & tracked
    if resolved:
        return resolved

    # An out-of-line declaration nested in an inline module has an additional
    # implicit directory component that this lexical policy does not model.
    # Conservatively retain every same-crate suffix candidate rather than
    # treating an unresolved declaration as evidence that no module exists.
    crate = parent.split("/", 2)[:2]
    crate_prefix = "/".join(crate) + "/src/"
    return {
        path
        for path in tracked
        if path.startswith(crate_prefix)
        and (path.endswith(f"/{name}.rs") or path.endswith(f"/{name}/mod.rs"))
    }


def crate_root(path: str) -> bool:
    before, separator, relative = path.partition("/src/")
    if not separator or not before.startswith("crates/"):
        return False
    fields = relative.split("/")
    if len(fields) == 1:
        return fields[0] in {"lib.rs", "main.rs"}
    if fields[0] != "bin":
        return False
    return (len(fields) == 2 and fields[1].endswith(".rs")) or fields[-1] == "main.rs"


def production_crate_source_paths(repo: str, revision: str) -> set[str]:
    """Return crate source reachable after removing demonstrated test items.

    The graph begins at conventional Rust library and binary roots. Module and
    literal `include!` edges are derived from source after the same cfg(test)
    stripping used by the policy scan. Filenames never determine reachability.
    """

    paths = tracked_crate_source_paths(repo, revision)
    tracked = set(paths)
    blobs = read_blobs(repo, revision, paths)
    edges: dict[str, set[str]] = {path: set() for path in paths}

    for parent, original in blobs.items():
        source = lexical_mask(original, keep_strings=True)
        structure = lexical_mask(original, keep_strings=False)
        production = remove_test_only_items(original)
        production_structure = lexical_mask(production, keep_strings=False)

        for declaration in OUT_OF_LINE_MODULE.finditer(structure):
            attribute_match = ATTRIBUTE_BLOCK.search(source[: declaration.start()])
            attributes = attribute_match.group(1) if attribute_match is not None else ""
            targets = module_targets(parent, declaration.group(1), attributes, tracked)
            if not targets:
                continue
            retained = production_structure[declaration.start() : declaration.end()]
            if retained.strip():
                edges[parent].update(targets)

        production_source = lexical_mask(production, keep_strings=True)
        for included in INCLUDE_RUST_SOURCE.finditer(production_source):
            target = posixpath.normpath(
                posixpath.join(posixpath.dirname(parent), included.group(1))
            )
            if target in tracked:
                edges[parent].add(target)

    reachable = {path for path in paths if crate_root(path)}
    pending = list(reachable)
    while pending:
        parent = pending.pop()
        for target in edges.get(parent, set()):
            if target not in reachable:
                reachable.add(target)
                pending.append(target)
    return reachable


def names_in(expression: str, names: set[str]) -> set[str]:
    if not names:
        return set()
    identifiers = set(IDENTIFIER.findall(expression))
    return identifiers & names


def is_direct_alias(expression: str, names: set[str]) -> bool:
    """Recognize simple bindings that preserve an already-tainted identity."""

    if not names:
        return False
    named = identifier_pattern(names)
    structure = lexical_mask(expression, keep_strings=False)
    return re.fullmatch(
        rf"\s*(?:&\s*(?:mut\s+)?)?(?:\(\s*)*"
        rf"(?:[A-Za-z_][A-Za-z0-9_]*\s*\.\s*)*\b(?:{named})\b"
        rf"(?:\s*\.\s*(?:as_str|as_bytes|as_ref|as_deref|borrow|clone|"
        rf"to_owned|into)\s*\(\s*\))?(?:\s*\))*\s*",
        structure,
    ) is not None


def line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def evidence(source: str, start: int, end: int) -> str:
    excerpt = re.sub(r"\s+", " ", source[start:end]).strip()
    return excerpt[:240]


def add_violation(
    violations: list[Violation], source: str, path: str, match: re.Match[str], rule: str
) -> None:
    violations.append(
        Violation(path, line_number(source, match.start()), rule, evidence(source, match.start(), match.end()))
    )


def exact_counterpart_pattern(constants: set[str], fixtures: set[str]) -> str:
    names = sorted(constants | fixtures, key=len, reverse=True)
    named = "|".join(re.escape(name) for name in names)
    literal = r"(?:b|br|rb|r)?#{0,32}\""
    if named:
        return rf"(?:{literal}|\b(?:{named})\b)"
    return literal


def identifier_pattern(names: set[str]) -> str:
    return "|".join(re.escape(name) for name in sorted(names, key=len, reverse=True))


def scan(path: str, original: str) -> list[Violation]:
    production = remove_test_only_items(original)
    source = lexical_mask(production, keep_strings=True)
    structure = lexical_mask(production, keep_strings=False)
    violations: list[Violation] = []

    constants: set[str] = set()
    expected: set[str] = set()
    fixtures: set[str] = set()
    raw: set[str] = set()
    explicit_raw: set[str] = set()
    identity: set[str] = set()
    fingerprints: set[str] = set()

    for declaration in STRING_SOURCE_DECLARATION.finditer(structure):
        name = declaration.group(1)
        if name.lower() in {"source", "pattern", "patterns", "regex", "regexes"} or RAW_NAME.search(name):
            raw.add(name)

    for name in IDENTIFIER.findall(structure):
        if RAW_NAME.search(name):
            raw.add(name)
            explicit_raw.add(name)
        if IDENTITY_NAME.search(name):
            identity.add(name)

    declarations = list(DECLARATION.finditer(source))
    for declaration in CONSTANT_DECLARATION.finditer(source):
        name, value = declaration.groups()
        constants.add(name)
        if EXPECTED_ANSWER_NAME.search(name) and name not in MODEL_DEFINITION_CONSTANTS.get(path, set()):
            expected.add(name)
        if INCLUDE_FIXTURE.search(value):
            fixtures.add(name)

    changed = True
    while changed:
        changed = False
        for declaration in declarations:
            name, value = declaration.groups()
            for tainted in (raw, explicit_raw, identity, fixtures, fingerprints):
                if name not in tainted and is_direct_alias(value, tainted):
                    tainted.add(name)
                    changed = True
            if INCLUDE_FIXTURE.search(value) and name not in fixtures:
                fixtures.add(name)
                changed = True
            if names_in(value, expected) and name not in expected:
                expected.add(name)
                changed = True
            if names_in(value, raw | fixtures) and HASH_NAME.search(name):
                if name not in fingerprints:
                    fingerprints.add(name)
                    changed = True

    counterpart = exact_counterpart_pattern(constants, fixtures)
    exact_categories = [
        ("raw_regex_source_exact_decision", raw | fixtures),
        ("benchmark_identity_exact_decision", identity),
        ("source_fingerprint_exact_decision", fingerprints),
    ]
    dispatch_categories = [
        ("raw_regex_source_exact_decision", explicit_raw | fixtures),
        ("benchmark_identity_exact_decision", identity),
        ("source_fingerprint_exact_decision", fingerprints),
    ]
    for rule, names in exact_categories:
        if not names:
            continue
        named = identifier_pattern(names)
        forward = re.compile(
            rf"\b(?:{named})\b(?:\s*\.\s*(?:as_str|as_bytes)\s*\(\s*\))?"
            rf"\s*(?:==|!=)\s*{counterpart}",
            re.DOTALL,
        )
        reverse = re.compile(
            rf"{counterpart}\s*(?:==|!=)\s*\b(?:{named})\b",
            re.DOTALL,
        )
        for matched in forward.finditer(source):
            add_violation(violations, source, path, matched, rule)
        for matched in reverse.finditer(source):
            add_violation(violations, source, path, matched, rule)

    fingerprint_inputs = raw | identity | fixtures
    if fingerprint_inputs:
        named = identifier_pattern(fingerprint_inputs)
        hash_call = (
            rf"\b(?=[A-Za-z_][A-Za-z0-9_]*\s*\()"
            rf"(?=[A-Za-z0-9_]*(?:sha|hash|digest|fingerprint|checksum))"
            rf"[A-Za-z_][A-Za-z0-9_]*\s*"
            rf"\([^;{{}}]*\b(?:{named})\b[^;{{}}]*\)"
        )
        forward = re.compile(rf"{hash_call}\s*(?:==|!=)\s*{counterpart}", re.IGNORECASE | re.DOTALL)
        reverse = re.compile(rf"{counterpart}\s*(?:==|!=)\s*{hash_call}", re.IGNORECASE | re.DOTALL)
        for matched in forward.finditer(source):
            add_violation(
                violations,
                source,
                path,
                matched,
                "source_fingerprint_exact_decision",
            )
        for matched in reverse.finditer(source):
            add_violation(
                violations,
                source,
                path,
                matched,
                "source_fingerprint_exact_decision",
            )

    for rule, names in dispatch_categories:
        if not names:
            continue
        named = identifier_pattern(names)
        match_dispatch = re.compile(rf"\bmatch\s+&?\s*(?:[A-Za-z_][A-Za-z0-9_]*\.)*(?:{named})\b")
        for matched in match_dispatch.finditer(structure):
            add_violation(violations, source, path, matched, rule.replace("exact_decision", "match_dispatch"))

    content_names = explicit_raw | identity | fixtures | fingerprints
    if content_names:
        named = identifier_pattern(content_names)
        content_method = re.compile(
            rf"\b(?:{named})\b\s*\.\s*(?:contains|starts_with|ends_with|"
            r"strip_prefix|strip_suffix|find|rfind)\s*\("
        )
        for matched in content_method.finditer(structure):
            add_violation(violations, source, path, matched, "identity_content_dispatch")

        lookup = re.compile(
            rf"\b([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
            rf"(?:get|get_mut|entry|contains_key|binary_search)\s*\(\s*&?\s*(?:{named})\b"
        )
        for matched in lookup.finditer(structure):
            receiver = matched.group(1)
            used = names_in(matched.group(0), content_names)
            if used and used <= fingerprints and CACHE_BINDING_RECEIVER.search(receiver):
                continue
            add_violation(violations, source, path, matched, "identity_keyed_lookup")

    for name in sorted(expected):
        occurrences = list(re.finditer(rf"\b{re.escape(name)}\b", structure))
        # One occurrence is the declaration. Any additional production use
        # makes the advertised expected answer reachable from runtime code.
        if len(occurrences) > 1:
            matched = occurrences[1]
            add_violation(violations, source, path, matched, "reachable_expected_answer_constant")

    unique: dict[tuple[str, str, str], Violation] = {}
    for violation in violations:
        unique.setdefault(violation.fingerprint(), violation)
    return sorted(unique.values(), key=lambda item: (item.path, item.line, item.rule))


def main() -> None:
    if len(sys.argv) != 4:
        die("usage: candidate-source-policy.py REPO BASELINE_SHA CANDIDATE_SHA")
    repo, baseline, candidate = sys.argv[1:]
    paths, newly_reachable = changed_production_paths(repo, baseline, candidate)
    candidate_violations: list[Violation] = []
    baseline_fingerprints: set[tuple[str, str, str]] = set()
    candidate_blobs = read_blobs(repo, candidate, paths)
    baseline_blobs = read_blobs(repo, baseline, paths)

    for path in paths:
        candidate_source = candidate_blobs.get(path)
        if candidate_source is None:
            continue
        candidate_violations.extend(scan(path, candidate_source))
        baseline_source = None if path in newly_reachable else baseline_blobs.get(path)
        if baseline_source is not None:
            baseline_fingerprints.update(item.fingerprint() for item in scan(path, baseline_source))

    new_violations = [
        item for item in candidate_violations if item.fingerprint() not in baseline_fingerprints
    ]
    if new_violations:
        for item in new_violations[:32]:
            print(
                f"candidate_source_policy_v{POLICY_VERSION}\tresult=FAIL\t"
                f"rule={item.rule}\tpath={item.path}\tline={item.line}\t"
                f"evidence={item.evidence}",
                file=sys.stderr,
            )
        if len(new_violations) > 32:
            print(
                f"candidate_source_policy_v{POLICY_VERSION}\tresult=FAIL\t"
                f"additional_violations={len(new_violations) - 32}",
                file=sys.stderr,
            )
        raise SystemExit(1)

    print(
        f"candidate_source_policy_v{POLICY_VERSION}\tresult=PASS\t"
        f"changed_production_files={len(paths)}\t"
        f"newly_reachable_files={len(newly_reachable)}"
    )


if __name__ == "__main__":
    main()
