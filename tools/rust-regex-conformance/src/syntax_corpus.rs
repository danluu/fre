//! Authenticated inventory and first executable slice for the exact
//! `regex-syntax` 0.8.11 package test corpus.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as FmtWrite,
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    process::{Command, Output},
};

use fre_syntax::{
    AdmissionPolicy, AdmissionStatus, CompatibilityProfile, ErrorCategory, ParseError,
    ParseRequest, RustAstRecord, RustProfile, SCHEMA_VERSION, SafetyEnvelope, SourceSpan,
    parse_rust_ast,
};
use regex_syntax::ast::{Ast, Concat, HexLiteralKind, Literal, LiteralKind, Position, Span};
use serde::{Deserialize, Serialize};

use crate::{CandidateIdentity, InventoryError, authenticate_candidate_source, sha256};

/// Schema for the sealed `regex-syntax` package-corpus report.
pub const REGEX_SYNTAX_CORPUS_REPORT_SCHEMA: &str =
    "fre.regex-syntax-0.8.11.package-corpus-report.v1";
/// Complete unit-test definition denominator in the pinned package.
pub const REGEX_SYNTAX_UNIT_DEFINITIONS: usize = 158;
/// Unit tests enabled by the package's default feature set.
pub const REGEX_SYNTAX_DEFAULT_UNIT_TESTS: usize = 147;
/// Unit tests enabled with `--no-default-features`.
pub const REGEX_SYNTAX_NO_DEFAULT_UNIT_TESTS: usize = 144;
/// Rustdoc tests exposed in each authenticated feature mode.
pub const REGEX_SYNTAX_DOCTESTS: usize = 48;
/// Complete unit-definition plus doctest obligation denominator.
pub const REGEX_SYNTAX_CORPUS_OBLIGATIONS: usize = 206;
/// Executable first-slice denominator.
pub const REGEX_SYNTAX_AST_PARSE_TESTS: usize = 29;

const UPSTREAM_REPOSITORY: &str = "https://github.com/rust-lang/regex";
const UPSTREAM_PACKAGE: &str = "regex-syntax";
const UPSTREAM_VERSION: &str = "0.8.11";
const UPSTREAM_REVISION: &str = "140167995737fa11dfe11b8af8b9aa143b790b4e";
const UPSTREAM_CRATE_SHA256: &str =
    "d6f6ff9a378485b298a5286656da665ba74413d36db0979633275d2e708145d4";
const PACKAGE_TREE_INVENTORY_SHA256: &str =
    "26dc1f5688740dc97444ad8feec4e20a1652a613311cf59f120e5fa51eb267e3";
const PACKAGE_FILE_COUNT: usize = 42;
const PACKAGE_BYTES: u64 = 1_682_181;
const UNIT_DEFINITION_IDS_SHA256: &str =
    "7dd0d6edb068963ca4611a37ff2d77353c04a3eea26048a02803fd59bfd60884";
const DEFAULT_UNIT_LIST_SHA256: &str =
    "e9e51f4e102c22ad16116e9cc50d48c764415975b09a20066958b982bc677c75";
const NO_DEFAULT_UNIT_LIST_SHA256: &str =
    "ae9d648cf12f1769413c248c042b972f55476e1d29c81a82d7ab86757d95dbf9";
const DOCTEST_LIST_SHA256: &str =
    "bd8bfe9ab1f9f6b08eb4626ce3826e8a9b48714ac8bb381a81f5530901372e0c";
const OBLIGATION_INVENTORY_SHA256: &str =
    "e6e416c78915b9f339d3dd165d44a0896e2519eac07961c762e3212874609dbe";
const AST_PARSE_PREFIX: &str = "ast::parse::tests::";
const AST_PARSE_IDS_SHA256: &str =
    "4d31a1829c82e76a3387354c9923d36a7305553c4c057723e12bd3f6bbdd4a0e";
const AST_HOLISTIC_CASE_ID: &str = "ast::parse::tests::parse_holistic";
const AST_PERL_CLASS_CASE_ID: &str = "ast::parse::tests::parse_perl_class";
const AST_UNICODE_CLASS_CASE_ID: &str = "ast::parse::tests::parse_unicode_class";
const AST_UNSUPPORTED_BACKREFERENCE_CASE_ID: &str =
    "ast::parse::tests::parse_unsupported_backreference";
const AST_UNSUPPORTED_LOOKAROUND_CASE_ID: &str = "ast::parse::tests::parse_unsupported_lookaround";
const AST_OCTAL_CASE_ID: &str = "ast::parse::tests::parse_octal";
const AST_HEX_TWO_CASE_ID: &str = "ast::parse::tests::parse_hex_two";
const AST_HEX_FOUR_CASE_ID: &str = "ast::parse::tests::parse_hex_four";
const AST_HEX_EIGHT_CASE_ID: &str = "ast::parse::tests::parse_hex_eight";
const AST_HEX_TWO_PASS_EVIDENCE_SHA256: &str =
    "20dcfdb7f815b856f1d9dea92692790fbe327d4f90f266d77d0b44c1f794eef4";
const AST_HEX_FOUR_PASS_EVIDENCE_SHA256: &str =
    "6fcca07ecca25303f991f46cbe535033758fc7e5dbd0b1510b1d3e24c7c2a95a";
const AST_HEX_EIGHT_PASS_EVIDENCE_SHA256: &str =
    "b32686f62b009bdc721c80058eef0b3b128e6094154edf1bd4f3387c7746319d";
const AST_REGRESSION_454_CASE_ID: &str = "ast::parse::tests::regression_454_nest_too_big";
const AST_REGRESSION_455_CASE_ID: &str =
    "ast::parse::tests::regression_455_trailing_dash_ignore_whitespace";
const REGRESSION_454_PATTERN: &str = r"
        2(?:
          [45]\d{3}|
          7(?:
            1[0-267]|
            2[0-289]|
            3[0-29]|
            4[01]|
            5[1-3]|
            6[013]|
            7[0178]|
            91
          )|
          8(?:
            0[125]|
            [139][1-6]|
            2[0157-9]|
            41|
            6[1-35]|
            7[1-5]|
            8[1-8]|
            90
          )|
          9(?:
            0[0-2]|
            1[0-4]|
            2[568]|
            3[3-6]|
            5[5-7]|
            6[0167]|
            7[15]|
            8[0146-9]
          )
        )\d{4}
        ";
const REGRESSION_455_PROBES: [(&str, bool); 8] = [
    ("(?x)[ / - ]", true),
    ("(?x)[ a - ]", true),
    (
        "(?x)[
            a
            - ]
        ",
        true,
    ),
    (
        "(?x)[
            a # wat
            - ]
        ",
        true,
    ),
    ("(?x)[ / -", false),
    ("(?x)[ / - ", false),
    (
        "(?x)[
            / -
        ",
        false,
    ),
    (
        "(?x)[
            / - # wat
        ",
        false,
    ),
];
const UNSUPPORTED_LOOKAROUND_PROBES: [(&str, usize); 4] =
    [("(?=a)", 3), ("(?!a)", 3), ("(?<=a)", 4), ("(?<!a)", 4)];
const UNSUPPORTED_BACKREFERENCE_PROBES: [&str; 2] = [r"\0", r"\9"];
const PERL_CLASS_PROBES: [&str; 8] = [r"\d", r"\D", r"\s", r"\S", r"\w", r"\W", r"\d", r"\dz"];
const UNICODE_CLASS_PROBES: [&str; 19] = [
    r"\pN",
    r"\PN",
    r"\p{N}",
    r"\P{N}",
    r"\p{Greek}",
    r"\p{scx:Katakana}",
    r"\p{scx=Katakana}",
    r"\p{scx!=Katakana}",
    r"\p{:}",
    r"\p{=}",
    r"\p{!=}",
    r"\p",
    r"\p{",
    r"\p{N",
    r"\p{Greek",
    r"\pNz",
    r"\p{Greek}z",
    r"\p\{",
    r"\P\{",
];
const HEX_TWO_ERROR_PROBES: [AstHexErrorProbe; 3] = [
    AstHexErrorProbe::unexpected_eof(r"\xF", 3, 3),
    AstHexErrorProbe::invalid_digit(r"\xG", 2, 3),
    AstHexErrorProbe::invalid_digit(r"\xFG", 3, 4),
];
const HEX_FOUR_ERROR_PROBES: [AstHexErrorProbe; 6] = [
    AstHexErrorProbe::unexpected_eof(r"\uF", 3, 3),
    AstHexErrorProbe::invalid_digit(r"\uG", 2, 3),
    AstHexErrorProbe::invalid_digit(r"\uFG", 3, 4),
    AstHexErrorProbe::invalid_digit(r"\uFFG", 4, 5),
    AstHexErrorProbe::invalid_digit(r"\uFFFG", 5, 6),
    AstHexErrorProbe::invalid_scalar(r"\uD800", 2, 6),
];
const HEX_EIGHT_ERROR_PROBES: [AstHexErrorProbe; 9] = [
    AstHexErrorProbe::unexpected_eof(r"\UF", 3, 3),
    AstHexErrorProbe::invalid_digit(r"\UG", 2, 3),
    AstHexErrorProbe::invalid_digit(r"\UFG", 3, 4),
    AstHexErrorProbe::invalid_digit(r"\UFFG", 4, 5),
    AstHexErrorProbe::invalid_digit(r"\UFFFG", 5, 6),
    AstHexErrorProbe::invalid_digit(r"\UFFFFG", 6, 7),
    AstHexErrorProbe::invalid_digit(r"\UFFFFFG", 7, 8),
    AstHexErrorProbe::invalid_digit(r"\UFFFFFFG", 8, 9),
    AstHexErrorProbe::invalid_digit(r"\UFFFFFFFG", 9, 10),
];
const MAX_PACKAGE_FILE_BYTES: u64 = 2 * 1_048_576;

const UNIT_SOURCE_MODULES: [(&str, &str); 11] = [
    ("src/ast/mod.rs", "ast::tests"),
    ("src/ast/parse.rs", "ast::parse::tests"),
    ("src/ast/print.rs", "ast::print::tests"),
    ("src/error.rs", "error::tests"),
    ("src/hir/literal.rs", "hir::literal::tests"),
    ("src/hir/mod.rs", "hir::tests"),
    ("src/hir/print.rs", "hir::print::tests"),
    ("src/hir/translate.rs", "hir::translate::tests"),
    ("src/lib.rs", "tests"),
    ("src/unicode.rs", "unicode::tests"),
    ("src/utf8.rs", "utf8::tests"),
];

const LIMITATIONS: [&str; 3] = [
    "The FRE AST adapter executes exactly parse_hex_two, parse_hex_four, parse_hex_eight, parse_holistic, parse_octal, parse_perl_class, parse_unicode_class, parse_unsupported_backreference, parse_unsupported_lookaround, and regressions 454/455; the other 18 AST parser identities remain explicit Unsupported dispositions.",
    "The other 147 regex-syntax unit definitions do not yet have FRE adapters and remain explicit Unsupported dispositions.",
    "Rustdoc identities are inventoried independently in both feature modes, but no FRE doctest adapter exists in this slice.",
];

/// One file in the complete published package tree.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexSyntaxPackageFile {
    pub path: String,
    pub mode: String,
    pub bytes: u64,
    pub sha256: String,
}

/// Exact published-package identity and ordered tree inventory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexSyntaxCorpusSourceIdentity {
    pub repository: String,
    pub package: String,
    pub version: String,
    pub revision: String,
    pub crates_io_archive_sha256: String,
    pub package_tree_inventory_sha256: String,
    pub package_files: usize,
    pub package_bytes: u64,
    pub files: Vec<RegexSyntaxPackageFile>,
}

/// Toolchain and exact isolated harness-list evidence used for the inventory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexSyntaxHarnessIdentity {
    pub cargo_release: String,
    pub cargo_executable_sha256: String,
    pub rustc_release: String,
    pub rustc_executable_sha256: String,
    pub unit_definitions: usize,
    pub default_unit_tests: usize,
    pub no_default_unit_tests: usize,
    pub unit_union: usize,
    pub unit_intersection: usize,
    pub default_only_unit_tests: usize,
    pub no_default_only_unit_tests: usize,
    pub default_doctests: usize,
    pub no_default_doctests: usize,
    pub unit_definition_ids_sha256: String,
    pub default_unit_list_sha256: String,
    pub no_default_unit_list_sha256: String,
    pub default_doctest_list_sha256: String,
    pub no_default_doctest_list_sha256: String,
    pub obligation_inventory_sha256: String,
    pub executable_slice: String,
    pub executable_slice_tests: usize,
}

/// Kind of source-defined test obligation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RegexSyntaxCorpusCaseKind {
    Unit,
    Doctest,
}

/// One authenticated source/test-list obligation before execution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexSyntaxCorpusObligation {
    pub case_id: String,
    pub kind: RegexSyntaxCorpusCaseKind,
    pub source_path: String,
    pub source_line: usize,
    pub source_sha256: String,
    pub default_harness_member: bool,
    pub no_default_harness_member: bool,
}

/// Exhaustive outcome for one corpus identity. There is no skipped state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RegexSyntaxCorpusDisposition {
    Pass {
        evidence_sha256: String,
    },
    Mismatch {
        expected: String,
        observed: String,
        evidence_sha256: String,
    },
    Unsupported {
        reason_code: String,
    },
    Fault {
        stage: String,
        reason_code: String,
    },
}

/// One obligation paired with exactly one terminal disposition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexSyntaxCorpusReceipt {
    #[serde(flatten)]
    pub obligation: RegexSyntaxCorpusObligation,
    pub disposition: RegexSyntaxCorpusDisposition,
}

/// Complete terminal cardinalities for the fixed 206-obligation denominator.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexSyntaxCorpusCounts {
    pub pass: usize,
    pub mismatch: usize,
    pub unsupported: usize,
    pub fault: usize,
    pub total: usize,
}

/// Terminal upstream self-test outcome, kept separate from candidate results.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RegexSyntaxOracleDisposition {
    Pass {
        evidence_sha256: String,
    },
    Mismatch {
        expected: String,
        observed: String,
        evidence_sha256: String,
    },
    Fault {
        stage: String,
        reason_code: String,
    },
}

/// One AST parser identity paired with its upstream self-test outcome.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexSyntaxOracleReceipt {
    pub case_id: String,
    pub disposition: RegexSyntaxOracleDisposition,
}

/// Complete outcome counts for the fixed 29-case upstream oracle slice.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexSyntaxOracleCounts {
    pub pass: usize,
    pub mismatch: usize,
    pub fault: usize,
    pub total: usize,
}

/// Upstream package self-test evidence. This is not candidate execution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexSyntaxOracleEvidence {
    pub scope: String,
    pub counts: RegexSyntaxOracleCounts,
    pub receipts: Vec<RegexSyntaxOracleReceipt>,
}

/// Payload authenticated by [`RegexSyntaxCorpusReport::payload_sha256`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexSyntaxCorpusReportPayload {
    pub source: RegexSyntaxCorpusSourceIdentity,
    pub candidate: CandidateIdentity,
    pub harness: RegexSyntaxHarnessIdentity,
    pub upstream_oracle: RegexSyntaxOracleEvidence,
    pub counts: RegexSyntaxCorpusCounts,
    pub receipts: Vec<RegexSyntaxCorpusReceipt>,
    pub limitations: Vec<String>,
}

/// Sealed complete-inventory report for the package's own test corpus.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexSyntaxCorpusReport {
    pub schema: String,
    pub payload_sha256: String,
    pub payload: RegexSyntaxCorpusReportPayload,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum TestOutcome {
    Ok,
    Failed,
    Ignored,
}

/// Authenticate the complete package, inventory both feature-mode harnesses,
/// and execute the AST parser family as separately labelled upstream-oracle
/// evidence. Eleven exact AST obligations additionally execute through FRE.
#[allow(
    clippy::too_many_lines,
    reason = "the transaction keeps package authentication, four harness lists, the oracle execution, and sealed report assembly adjacent"
)]
pub fn build_regex_syntax_corpus_report(
    upstream_package: &Path,
    candidate_path: &Path,
    target_dir: &Path,
) -> Result<RegexSyntaxCorpusReport, InventoryError> {
    let source = authenticate_package(upstream_package)?;
    let candidate = authenticate_candidate_source(candidate_path)?;
    let target_dir = prepare_target_dir(target_dir, upstream_package, candidate_path)?;
    let snapshot = prepare_command_target(&target_dir, "upstream-snapshot")?;
    snapshot_package(upstream_package, &snapshot, &source)?;
    if authenticate_package(&snapshot)? != source {
        return Err(InventoryError::new(
            "regex-syntax owned snapshot differs from authenticated source",
        ));
    }
    reject_ancestor_cargo_configs(&snapshot)?;
    let cargo_home = resolve_cargo_home()?;
    reject_cargo_home_configs(&cargo_home)?;
    let cargo = resolve_tool("cargo")?;
    let rustc = resolve_tool("rustc")?;
    let cargo_release = tool_release(&cargo, "cargo")?;
    let rustc_release = tool_release(&rustc, "rustc")?;
    let cargo_executable_sha256 = hash_tool(&cargo, "cargo")?;
    let rustc_executable_sha256 = hash_tool(&rustc, "rustc")?;

    let default_unit_target = prepare_command_target(&target_dir, "list-default-units")?;
    let default_units = list_tests(
        &snapshot,
        &default_unit_target,
        &cargo_home,
        &cargo,
        &rustc,
        &["test", "--offline", "--locked", "--lib", "--", "--list"],
    )?;
    let no_default_unit_target = prepare_command_target(&target_dir, "list-no-default-units")?;
    let no_default_units = list_tests(
        &snapshot,
        &no_default_unit_target,
        &cargo_home,
        &cargo,
        &rustc,
        &[
            "test",
            "--offline",
            "--locked",
            "--no-default-features",
            "--lib",
            "--",
            "--list",
        ],
    )?;
    let default_doctest_target = prepare_command_target(&target_dir, "list-default-doctests")?;
    let default_doctests = list_tests(
        &snapshot,
        &default_doctest_target,
        &cargo_home,
        &cargo,
        &rustc,
        &["test", "--offline", "--locked", "--doc", "--", "--list"],
    )?;
    let no_default_doctest_target =
        prepare_command_target(&target_dir, "list-no-default-doctests")?;
    let no_default_doctests = list_tests(
        &snapshot,
        &no_default_doctest_target,
        &cargo_home,
        &cargo,
        &rustc,
        &[
            "test",
            "--offline",
            "--locked",
            "--no-default-features",
            "--doc",
            "--",
            "--list",
        ],
    )?;
    authenticate_harness_lists(
        &default_units,
        &no_default_units,
        &default_doctests,
        &no_default_doctests,
    )?;

    let obligations = build_obligations(
        &snapshot,
        &source,
        &default_units,
        &no_default_units,
        &default_doctests,
        &no_default_doctests,
    )?;
    let inventory_hash = hash_json(&obligations, "encode obligation inventory")?;
    if inventory_hash != OBLIGATION_INVENTORY_SHA256 {
        return Err(InventoryError::new(format!(
            "regex-syntax obligation inventory SHA-256 mismatch: {inventory_hash}"
        )));
    }

    let selected = obligations
        .iter()
        .filter(|case| {
            case.kind == RegexSyntaxCorpusCaseKind::Unit
                && case.case_id.starts_with(AST_PARSE_PREFIX)
        })
        .map(|case| case.case_id.clone())
        .collect::<BTreeSet<_>>();
    if selected.len() != REGEX_SYNTAX_AST_PARSE_TESTS
        || selected
            .iter()
            .any(|case_id| !default_units.contains(case_id))
    {
        return Err(InventoryError::new(
            "regex-syntax AST parser slice denominator mismatch",
        ));
    }
    let oracle_target = prepare_command_target(&target_dir, "execute-ast-parse")?;
    let execution = execute_ast_parse_oracle(
        &snapshot,
        &oracle_target,
        &cargo_home,
        &cargo,
        &rustc,
        &selected,
    );
    let upstream_oracle = build_oracle_evidence(&selected, &execution)?;
    if authenticate_package(&snapshot)? != source {
        return Err(InventoryError::new(
            "regex-syntax owned snapshot changed during harness execution",
        ));
    }
    reject_ancestor_cargo_configs(&snapshot)?;
    reject_cargo_home_configs(&cargo_home)?;
    if tool_release(&cargo, "cargo")? != cargo_release
        || tool_release(&rustc, "rustc")? != rustc_release
        || hash_tool(&cargo, "cargo")? != cargo_executable_sha256
        || hash_tool(&rustc, "rustc")? != rustc_executable_sha256
    {
        return Err(InventoryError::new(
            "regex-syntax harness tool identity changed during execution",
        ));
    }
    let receipts = obligations
        .into_iter()
        .map(|obligation| RegexSyntaxCorpusReceipt {
            disposition: disposition_for(&obligation),
            obligation,
        })
        .collect::<Vec<_>>();
    if authenticate_candidate_source(candidate_path)? != candidate {
        return Err(InventoryError::new(
            "regex-syntax candidate changed during harness execution",
        ));
    }
    let counts = RegexSyntaxCorpusCounts::from_receipts(&receipts)?;
    let unit_union = default_units.union(&no_default_units).count();
    let unit_intersection = default_units.intersection(&no_default_units).count();
    let harness = RegexSyntaxHarnessIdentity {
        cargo_release,
        cargo_executable_sha256,
        rustc_release,
        rustc_executable_sha256,
        unit_definitions: REGEX_SYNTAX_UNIT_DEFINITIONS,
        default_unit_tests: default_units.len(),
        no_default_unit_tests: no_default_units.len(),
        unit_union,
        unit_intersection,
        default_only_unit_tests: default_units.difference(&no_default_units).count(),
        no_default_only_unit_tests: no_default_units.difference(&default_units).count(),
        default_doctests: default_doctests.len(),
        no_default_doctests: no_default_doctests.len(),
        unit_definition_ids_sha256: UNIT_DEFINITION_IDS_SHA256.to_owned(),
        default_unit_list_sha256: DEFAULT_UNIT_LIST_SHA256.to_owned(),
        no_default_unit_list_sha256: NO_DEFAULT_UNIT_LIST_SHA256.to_owned(),
        default_doctest_list_sha256: DOCTEST_LIST_SHA256.to_owned(),
        no_default_doctest_list_sha256: DOCTEST_LIST_SHA256.to_owned(),
        obligation_inventory_sha256: inventory_hash,
        executable_slice: AST_PARSE_PREFIX.to_owned(),
        executable_slice_tests: selected.len(),
    };
    let payload = RegexSyntaxCorpusReportPayload {
        source,
        candidate,
        harness,
        upstream_oracle,
        counts,
        receipts,
        limitations: LIMITATIONS.iter().map(|text| (*text).to_owned()).collect(),
    };
    let payload_sha256 = hash_json(&payload, "encode regex-syntax corpus payload")?;
    let report = RegexSyntaxCorpusReport {
        schema: REGEX_SYNTAX_CORPUS_REPORT_SCHEMA.to_owned(),
        payload_sha256,
        payload,
    };
    report.validate()?;
    Ok(report)
}

/// Read and authenticate a complete package-corpus report.
pub fn read_regex_syntax_corpus_report(
    path: &Path,
) -> Result<RegexSyntaxCorpusReport, InventoryError> {
    let bytes = fs::read(path).map_err(|error| {
        InventoryError::new(format!(
            "read regex-syntax corpus report {}: {error}",
            path.display()
        ))
    })?;
    let report: RegexSyntaxCorpusReport = serde_json::from_slice(&bytes).map_err(|error| {
        InventoryError::new(format!(
            "decode regex-syntax corpus report {}: {error}",
            path.display()
        ))
    })?;
    report.validate()?;
    Ok(report)
}

/// Atomically write canonical pretty JSON without replacing prior evidence.
pub fn write_regex_syntax_corpus_report(
    path: &Path,
    report: &RegexSyntaxCorpusReport,
) -> Result<(), InventoryError> {
    report.validate()?;
    if fs::symlink_metadata(path).is_ok() {
        return Err(InventoryError::new(format!(
            "regex-syntax corpus output already exists: {}",
            path.display()
        )));
    }
    let parent = path.parent().ok_or_else(|| {
        InventoryError::new(format!(
            "regex-syntax corpus output has no parent: {}",
            path.display()
        ))
    })?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(|error| {
        InventoryError::new(format!("stat output parent {}: {error}", parent.display()))
    })?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.file_type().is_dir() {
        return Err(InventoryError::new(
            "regex-syntax corpus output parent must be a real directory",
        ));
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| InventoryError::new("invalid regex-syntax corpus output name"))?;
    let temporary = parent.join(format!(".{name}.tmp.{}", std::process::id()));
    let mut output = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|error| InventoryError::new(format!("create {}: {error}", temporary.display())))?;
    let mut bytes = serde_json::to_vec_pretty(report).map_err(|error| {
        InventoryError::new(format!("encode regex-syntax corpus report: {error}"))
    })?;
    bytes.push(b'\n');
    let result = (|| {
        output.write_all(&bytes).map_err(|error| {
            InventoryError::new(format!("write {}: {error}", temporary.display()))
        })?;
        output.sync_all().map_err(|error| {
            InventoryError::new(format!("sync {}: {error}", temporary.display()))
        })?;
        fs::hard_link(&temporary, path).map_err(|error| {
            InventoryError::new(format!(
                "install {} at {} without replacement: {error}",
                temporary.display(),
                path.display()
            ))
        })?;
        fs::remove_file(&temporary).map_err(|error| {
            InventoryError::new(format!(
                "remove installed temporary {}: {error}",
                temporary.display()
            ))
        })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

impl RegexSyntaxCorpusReport {
    /// Validate source identity, the complete denominator, every disposition,
    /// cardinalities, ordering and the payload seal.
    pub fn validate(&self) -> Result<(), InventoryError> {
        if self.schema != REGEX_SYNTAX_CORPUS_REPORT_SCHEMA {
            return Err(InventoryError::new(
                "regex-syntax corpus report schema mismatch",
            ));
        }
        if self.payload_sha256 != hash_json(&self.payload, "encode regex-syntax corpus payload")? {
            return Err(InventoryError::new(
                "regex-syntax corpus payload SHA-256 mismatch",
            ));
        }
        validate_source(&self.payload.source)?;
        validate_candidate(&self.payload.candidate)?;
        validate_harness(&self.payload.harness)?;
        validate_oracle(&self.payload.upstream_oracle)?;
        if self.payload.limitations
            != LIMITATIONS
                .iter()
                .map(|text| (*text).to_owned())
                .collect::<Vec<_>>()
        {
            return Err(InventoryError::new(
                "regex-syntax corpus limitations mismatch",
            ));
        }
        if self.payload.receipts.len() != REGEX_SYNTAX_CORPUS_OBLIGATIONS {
            return Err(InventoryError::new(
                "regex-syntax corpus receipt denominator mismatch",
            ));
        }
        let obligations = self
            .payload
            .receipts
            .iter()
            .map(|receipt| receipt.obligation.clone())
            .collect::<Vec<_>>();
        if obligations
            .windows(2)
            .any(|pair| pair[0].case_id >= pair[1].case_id)
            || hash_json(&obligations, "encode obligation inventory")?
                != OBLIGATION_INVENTORY_SHA256
        {
            return Err(InventoryError::new(
                "regex-syntax corpus obligation inventory mismatch",
            ));
        }
        for receipt in &self.payload.receipts {
            validate_disposition(receipt)?;
        }
        let counts = RegexSyntaxCorpusCounts::from_receipts(&self.payload.receipts)?;
        if self.payload.counts != counts {
            return Err(InventoryError::new(
                "regex-syntax corpus disposition counts mismatch",
            ));
        }
        Ok(())
    }
}

impl RegexSyntaxCorpusCounts {
    fn from_receipts(receipts: &[RegexSyntaxCorpusReceipt]) -> Result<Self, InventoryError> {
        let mut counts = Self::default();
        for receipt in receipts {
            let counter = match receipt.disposition {
                RegexSyntaxCorpusDisposition::Pass { .. } => &mut counts.pass,
                RegexSyntaxCorpusDisposition::Mismatch { .. } => &mut counts.mismatch,
                RegexSyntaxCorpusDisposition::Unsupported { .. } => &mut counts.unsupported,
                RegexSyntaxCorpusDisposition::Fault { .. } => &mut counts.fault,
            };
            *counter = counter
                .checked_add(1)
                .ok_or_else(|| InventoryError::new("regex-syntax corpus count overflow"))?;
        }
        counts.total = counts
            .pass
            .checked_add(counts.mismatch)
            .and_then(|total| total.checked_add(counts.unsupported))
            .and_then(|total| total.checked_add(counts.fault))
            .ok_or_else(|| InventoryError::new("regex-syntax corpus count overflow"))?;
        if counts.total != REGEX_SYNTAX_CORPUS_OBLIGATIONS {
            return Err(InventoryError::new(
                "regex-syntax corpus disposition denominator mismatch",
            ));
        }
        Ok(counts)
    }
}

fn authenticate_package(package: &Path) -> Result<RegexSyntaxCorpusSourceIdentity, InventoryError> {
    let metadata = fs::symlink_metadata(package).map_err(|error| {
        InventoryError::new(format!(
            "stat upstream package {}: {error}",
            package.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(InventoryError::new(
            "regex-syntax package must be a real directory",
        ));
    }
    let mut files = Vec::new();
    collect_package_files(package, package, &mut files)?;
    files.sort_by(|left, right| left.path.cmp(&right.path));
    let package_bytes = files.iter().try_fold(0_u64, |total, file| {
        total
            .checked_add(file.bytes)
            .ok_or_else(|| InventoryError::new("regex-syntax package size overflow"))
    })?;
    let inventory_hash = hash_json(&files, "encode package tree inventory")?;
    if files.len() != PACKAGE_FILE_COUNT
        || package_bytes != PACKAGE_BYTES
        || inventory_hash != PACKAGE_TREE_INVENTORY_SHA256
    {
        return Err(InventoryError::new(format!(
            "regex-syntax package tree mismatch: files={} bytes={} inventory_sha256={inventory_hash}",
            files.len(),
            package_bytes
        )));
    }
    let source = RegexSyntaxCorpusSourceIdentity {
        repository: UPSTREAM_REPOSITORY.to_owned(),
        package: UPSTREAM_PACKAGE.to_owned(),
        version: UPSTREAM_VERSION.to_owned(),
        revision: UPSTREAM_REVISION.to_owned(),
        crates_io_archive_sha256: UPSTREAM_CRATE_SHA256.to_owned(),
        package_tree_inventory_sha256: inventory_hash,
        package_files: files.len(),
        package_bytes,
        files,
    };
    validate_source(&source)?;
    Ok(source)
}

fn collect_package_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<RegexSyntaxPackageFile>,
) -> Result<(), InventoryError> {
    let entries = fs::read_dir(directory).map_err(|error| {
        InventoryError::new(format!(
            "read package directory {}: {error}",
            directory.display()
        ))
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            InventoryError::new(format!("read package directory entry: {error}"))
        })?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            InventoryError::new(format!("stat package entry {}: {error}", path.display()))
        })?;
        if metadata.file_type().is_symlink() {
            return Err(InventoryError::new(format!(
                "regex-syntax package contains symlink: {}",
                path.display()
            )));
        }
        if metadata.file_type().is_dir() {
            collect_package_files(root, &path, files)?;
            continue;
        }
        if !metadata.file_type().is_file() {
            return Err(InventoryError::new(format!(
                "regex-syntax package contains non-regular entry: {}",
                path.display()
            )));
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| InventoryError::new("regex-syntax package entry escaped package root"))?;
        let relative = relative
            .to_str()
            .ok_or_else(|| InventoryError::new("regex-syntax package path is not valid UTF-8"))?;
        if relative == ".cargo-ok" {
            continue;
        }
        if relative.contains('\\') || relative.starts_with('/') || relative.contains("/../") {
            return Err(InventoryError::new(
                "regex-syntax package contains invalid relative path",
            ));
        }
        if metadata.len() > MAX_PACKAGE_FILE_BYTES {
            return Err(InventoryError::new(format!(
                "regex-syntax package file is too large: {relative}"
            )));
        }
        let mode = metadata.permissions().mode() & 0o7777;
        if mode != 0o644 {
            return Err(InventoryError::new(format!(
                "regex-syntax package mode mismatch for {relative}: {mode:04o}"
            )));
        }
        let bytes = fs::read(&path).map_err(|error| {
            InventoryError::new(format!("read package file {}: {error}", path.display()))
        })?;
        files.push(RegexSyntaxPackageFile {
            path: relative.replace('\\', "/"),
            mode: format!("{mode:04o}"),
            bytes: u64::try_from(bytes.len())
                .map_err(|_| InventoryError::new("package file size does not fit u64"))?,
            sha256: sha256(&bytes),
        });
    }
    Ok(())
}

fn snapshot_package(
    source_root: &Path,
    destination_root: &Path,
    source: &RegexSyntaxCorpusSourceIdentity,
) -> Result<(), InventoryError> {
    for file in &source.files {
        let source_path = source_root.join(&file.path);
        let metadata = fs::symlink_metadata(&source_path).map_err(|error| {
            InventoryError::new(format!(
                "stat snapshot source {}: {error}",
                source_path.display()
            ))
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_file()
            || metadata.permissions().mode() & 0o7777 != 0o644
        {
            return Err(InventoryError::new(format!(
                "invalid snapshot source entry: {}",
                source_path.display()
            )));
        }
        let bytes = fs::read(&source_path).map_err(|error| {
            InventoryError::new(format!(
                "read snapshot source {}: {error}",
                source_path.display()
            ))
        })?;
        if u64::try_from(bytes.len()) != Ok(file.bytes) || sha256(&bytes) != file.sha256 {
            return Err(InventoryError::new(format!(
                "snapshot source changed during copy: {}",
                file.path
            )));
        }
        let destination = destination_root.join(&file.path);
        let parent = destination.parent().ok_or_else(|| {
            InventoryError::new(format!("snapshot path has no parent: {}", file.path))
        })?;
        fs::create_dir_all(parent).map_err(|error| {
            InventoryError::new(format!(
                "create snapshot directory {}: {error}",
                parent.display()
            ))
        })?;
        let mut output = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&destination)
            .map_err(|error| {
                InventoryError::new(format!(
                    "create snapshot file {}: {error}",
                    destination.display()
                ))
            })?;
        output.write_all(&bytes).map_err(|error| {
            InventoryError::new(format!(
                "write snapshot file {}: {error}",
                destination.display()
            ))
        })?;
        output.sync_all().map_err(|error| {
            InventoryError::new(format!(
                "sync snapshot file {}: {error}",
                destination.display()
            ))
        })?;
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o644)).map_err(|error| {
            InventoryError::new(format!(
                "set snapshot mode {}: {error}",
                destination.display()
            ))
        })?;
    }
    Ok(())
}

fn reject_ancestor_cargo_configs(package: &Path) -> Result<(), InventoryError> {
    for ancestor in package.ancestors() {
        for name in ["config", "config.toml"] {
            let config = ancestor.join(".cargo").join(name);
            match fs::symlink_metadata(&config) {
                Ok(_) => {
                    return Err(InventoryError::new(format!(
                        "ambient Cargo config is not allowed: {}",
                        config.display()
                    )));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(InventoryError::new(format!(
                        "stat ambient Cargo config {}: {error}",
                        config.display()
                    )));
                }
            }
        }
    }
    Ok(())
}

fn resolve_cargo_home() -> Result<PathBuf, InventoryError> {
    let configured = if let Some(path) = std::env::var_os("CARGO_HOME") {
        PathBuf::from(path)
    } else {
        PathBuf::from(
            std::env::var_os("HOME")
                .ok_or_else(|| InventoryError::new("neither CARGO_HOME nor HOME is set"))?,
        )
        .join(".cargo")
    };
    let metadata = fs::symlink_metadata(&configured).map_err(|error| {
        InventoryError::new(format!("stat Cargo home {}: {error}", configured.display()))
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(InventoryError::new("Cargo home must be a real directory"));
    }
    configured
        .canonicalize()
        .map_err(|error| InventoryError::new(format!("canonicalize Cargo home: {error}")))
}

fn reject_cargo_home_configs(cargo_home: &Path) -> Result<(), InventoryError> {
    for name in ["config", "config.toml"] {
        let config = cargo_home.join(name);
        match fs::symlink_metadata(&config) {
            Ok(_) => {
                return Err(InventoryError::new(format!(
                    "Cargo home config is not allowed: {}",
                    config.display()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(InventoryError::new(format!(
                    "stat Cargo home config {}: {error}",
                    config.display()
                )));
            }
        }
    }
    Ok(())
}

fn validate_source(source: &RegexSyntaxCorpusSourceIdentity) -> Result<(), InventoryError> {
    if source.repository != UPSTREAM_REPOSITORY
        || source.package != UPSTREAM_PACKAGE
        || source.version != UPSTREAM_VERSION
        || source.revision != UPSTREAM_REVISION
        || source.crates_io_archive_sha256 != UPSTREAM_CRATE_SHA256
        || source.package_tree_inventory_sha256 != PACKAGE_TREE_INVENTORY_SHA256
        || source.package_files != PACKAGE_FILE_COUNT
        || source.package_bytes != PACKAGE_BYTES
        || source.files.len() != PACKAGE_FILE_COUNT
        || source
            .files
            .windows(2)
            .any(|pair| pair[0].path >= pair[1].path)
        || source.files.iter().any(|file| {
            file.path.is_empty()
                || file.mode != "0644"
                || file.bytes > MAX_PACKAGE_FILE_BYTES
                || !is_sha256(&file.sha256)
        })
        || hash_json(&source.files, "encode package tree inventory")?
            != PACKAGE_TREE_INVENTORY_SHA256
    {
        return Err(InventoryError::new(
            "regex-syntax corpus source identity mismatch",
        ));
    }
    let bytes = source.files.iter().try_fold(0_u64, |total, file| {
        total
            .checked_add(file.bytes)
            .ok_or_else(|| InventoryError::new("regex-syntax package size overflow"))
    })?;
    if bytes != PACKAGE_BYTES {
        return Err(InventoryError::new(
            "regex-syntax package byte count mismatch",
        ));
    }
    Ok(())
}

fn build_obligations(
    package: &Path,
    source: &RegexSyntaxCorpusSourceIdentity,
    default_units: &BTreeSet<String>,
    no_default_units: &BTreeSet<String>,
    default_doctests: &BTreeSet<String>,
    no_default_doctests: &BTreeSet<String>,
) -> Result<Vec<RegexSyntaxCorpusObligation>, InventoryError> {
    let source_hashes = source
        .files
        .iter()
        .map(|file| (file.path.as_str(), file.sha256.as_str()))
        .collect::<BTreeMap<_, _>>();
    let mut obligations =
        extract_unit_definitions(package, &source_hashes, default_units, no_default_units)?;
    let unit_ids = obligations
        .iter()
        .map(|case| case.case_id.clone())
        .collect::<BTreeSet<_>>();
    if unit_ids.len() != REGEX_SYNTAX_UNIT_DEFINITIONS
        || unit_ids != default_units.union(no_default_units).cloned().collect()
        || hash_line_list(&unit_ids) != UNIT_DEFINITION_IDS_SHA256
    {
        return Err(InventoryError::new(
            "regex-syntax source definitions differ from feature-mode harness union",
        ));
    }
    for case_id in default_doctests {
        let (source_path, source_line) = parse_doctest_id(case_id)?;
        let source_sha256 = source_hashes.get(source_path.as_str()).ok_or_else(|| {
            InventoryError::new(format!(
                "doctest source is absent from package: {source_path}"
            ))
        })?;
        obligations.push(RegexSyntaxCorpusObligation {
            case_id: case_id.clone(),
            kind: RegexSyntaxCorpusCaseKind::Doctest,
            source_path,
            source_line,
            source_sha256: (*source_sha256).to_owned(),
            default_harness_member: true,
            no_default_harness_member: no_default_doctests.contains(case_id),
        });
    }
    obligations.sort_by(|left, right| left.case_id.cmp(&right.case_id));
    if obligations.len() != REGEX_SYNTAX_CORPUS_OBLIGATIONS
        || obligations
            .windows(2)
            .any(|pair| pair[0].case_id == pair[1].case_id)
    {
        return Err(InventoryError::new(
            "regex-syntax complete obligation denominator mismatch",
        ));
    }
    Ok(obligations)
}

fn extract_unit_definitions(
    package: &Path,
    source_hashes: &BTreeMap<&str, &str>,
    default_units: &BTreeSet<String>,
    no_default_units: &BTreeSet<String>,
) -> Result<Vec<RegexSyntaxCorpusObligation>, InventoryError> {
    let mut obligations = Vec::new();
    for (source_path, module) in UNIT_SOURCE_MODULES {
        let bytes = fs::read(package.join(source_path)).map_err(|error| {
            InventoryError::new(format!("read unit source {source_path}: {error}"))
        })?;
        let expected_hash = source_hashes.get(source_path).ok_or_else(|| {
            InventoryError::new(format!(
                "unit source is absent from package inventory: {source_path}"
            ))
        })?;
        if sha256(&bytes).as_str() != *expected_hash {
            return Err(InventoryError::new(format!(
                "unit source changed while extracting definitions: {source_path}"
            )));
        }
        let text = std::str::from_utf8(&bytes).map_err(|error| {
            InventoryError::new(format!("unit source is not UTF-8, {source_path}: {error}"))
        })?;
        let lines = text.lines().collect::<Vec<_>>();
        for (index, line) in lines.iter().enumerate() {
            if line.trim() != "#[test]" {
                continue;
            }
            let mut found = None;
            let search_start = index
                .checked_add(1)
                .ok_or_else(|| InventoryError::new("unit source line overflow"))?;
            for (offset, candidate) in lines.iter().skip(search_start).take(15).enumerate() {
                if let Some(name) = function_name(candidate) {
                    let source_line = index
                        .checked_add(offset)
                        .and_then(|line| line.checked_add(2))
                        .ok_or_else(|| InventoryError::new("unit source line overflow"))?;
                    found = Some((name, source_line));
                    break;
                }
            }
            let attribute_line = index
                .checked_add(1)
                .ok_or_else(|| InventoryError::new("unit source line overflow"))?;
            let (name, source_line) = found.ok_or_else(|| {
                InventoryError::new(format!(
                    "unit #[test] has no nearby function in {source_path}:{attribute_line}"
                ))
            })?;
            let case_id = format!("{module}::{name}");
            obligations.push(RegexSyntaxCorpusObligation {
                default_harness_member: default_units.contains(&case_id),
                no_default_harness_member: no_default_units.contains(&case_id),
                case_id,
                kind: RegexSyntaxCorpusCaseKind::Unit,
                source_path: source_path.to_owned(),
                source_line,
                source_sha256: (*expected_hash).to_owned(),
            });
        }
    }
    Ok(obligations)
}

fn function_name(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    let rest = trimmed.strip_prefix("fn ")?;
    let end = rest
        .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .unwrap_or(rest.len());
    (end != 0).then_some(&rest[..end])
}

fn parse_doctest_id(case_id: &str) -> Result<(String, usize), InventoryError> {
    let (source_path, _) = case_id
        .split_once(" - ")
        .ok_or_else(|| InventoryError::new(format!("invalid rustdoc test identity: {case_id}")))?;
    let marker = "(line ";
    let start = case_id
        .rfind(marker)
        .and_then(|start| start.checked_add(marker.len()))
        .ok_or_else(|| {
            InventoryError::new(format!("rustdoc test identity lacks line: {case_id}"))
        })?;
    let line = case_id
        .get(start..case_id.len().saturating_sub(1))
        .ok_or_else(|| InventoryError::new("invalid rustdoc test line range"))?
        .parse::<usize>()
        .map_err(|error| {
            InventoryError::new(format!("invalid rustdoc test line in {case_id}: {error}"))
        })?;
    if !case_id.ends_with(')') || line == 0 {
        return Err(InventoryError::new(format!(
            "invalid rustdoc test identity: {case_id}"
        )));
    }
    Ok((source_path.to_owned(), line))
}

fn authenticate_harness_lists(
    default_units: &BTreeSet<String>,
    no_default_units: &BTreeSet<String>,
    default_doctests: &BTreeSet<String>,
    no_default_doctests: &BTreeSet<String>,
) -> Result<(), InventoryError> {
    if default_units.len() != REGEX_SYNTAX_DEFAULT_UNIT_TESTS
        || no_default_units.len() != REGEX_SYNTAX_NO_DEFAULT_UNIT_TESTS
        || default_units.union(no_default_units).count() != REGEX_SYNTAX_UNIT_DEFINITIONS
        || default_units.intersection(no_default_units).count() != 133
        || default_units.difference(no_default_units).count() != 14
        || no_default_units.difference(default_units).count() != 11
        || default_doctests.len() != REGEX_SYNTAX_DOCTESTS
        || no_default_doctests.len() != REGEX_SYNTAX_DOCTESTS
        || default_doctests != no_default_doctests
        || hash_line_list(default_units) != DEFAULT_UNIT_LIST_SHA256
        || hash_line_list(no_default_units) != NO_DEFAULT_UNIT_LIST_SHA256
        || hash_line_list(default_doctests) != DOCTEST_LIST_SHA256
        || hash_line_list(no_default_doctests) != DOCTEST_LIST_SHA256
    {
        return Err(InventoryError::new(
            "regex-syntax isolated cargo test lists differ from authenticated inventory",
        ));
    }
    Ok(())
}

fn list_tests(
    package: &Path,
    target: &Path,
    cargo_home: &Path,
    cargo: &Path,
    rustc: &Path,
    args: &[&str],
) -> Result<BTreeSet<String>, InventoryError> {
    let output = cargo_output(package, target, cargo_home, cargo, rustc, args)
        .map_err(|error| InventoryError::new(format!("execute cargo test list: {error}")))?;
    if !output.status.success() {
        return Err(InventoryError::new(format!(
            "cargo test list failed: evidence_sha256={}",
            command_evidence(&output)
        )));
    }
    let stdout = std::str::from_utf8(&output.stdout).map_err(|error| {
        InventoryError::new(format!("cargo test list stdout is not UTF-8: {error}"))
    })?;
    parse_test_list(stdout)
}

fn parse_test_list(stdout: &str) -> Result<BTreeSet<String>, InventoryError> {
    let mut tests = BTreeSet::new();
    for line in stdout.lines() {
        let Some(case_id) = line.strip_suffix(": test") else {
            continue;
        };
        if case_id.is_empty() || !tests.insert(case_id.to_owned()) {
            return Err(InventoryError::new(format!(
                "invalid or duplicate cargo test identity: {case_id:?}"
            )));
        }
    }
    Ok(tests)
}

fn execute_ast_parse_oracle(
    package: &Path,
    target: &Path,
    cargo_home: &Path,
    cargo: &Path,
    rustc: &Path,
    selected: &BTreeSet<String>,
) -> Result<BTreeMap<String, TestOutcome>, String> {
    let output = cargo_output(
        package,
        target,
        cargo_home,
        cargo,
        rustc,
        &[
            "test",
            "--offline",
            "--locked",
            "--lib",
            AST_PARSE_PREFIX,
            "--",
            "--test-threads=1",
        ],
    )
    .map_err(|_| "harness.cargo-exec-failed".to_owned())?;
    let stdout = std::str::from_utf8(&output.stdout)
        .map_err(|_| "harness.test-output-not-utf8".to_owned())?;
    let observed = parse_test_results(stdout)?;
    if observed.keys().any(|case_id| !selected.contains(case_id)) {
        return Err("harness.unexpected-selected-test".to_owned());
    }
    validate_oracle_command_status(output.status.success(), &observed, selected.len())?;
    Ok(observed)
}

fn validate_oracle_command_status(
    success: bool,
    observed: &BTreeMap<String, TestOutcome>,
    expected: usize,
) -> Result<(), String> {
    if success
        && (observed.len() != expected
            || observed.values().any(|outcome| *outcome != TestOutcome::Ok))
    {
        return Err("harness.success-result-set-incomplete".to_owned());
    }
    if !success && observed.values().all(|outcome| *outcome == TestOutcome::Ok) {
        return Err("harness.cargo-test-nonzero-exit".to_owned());
    }
    Ok(())
}

fn parse_test_results(stdout: &str) -> Result<BTreeMap<String, TestOutcome>, String> {
    let mut results = BTreeMap::new();
    for line in stdout.lines() {
        let Some(rest) = line.strip_prefix("test ") else {
            continue;
        };
        let (case_id, outcome) = if let Some(case_id) = rest.strip_suffix(" ... ok") {
            (case_id, TestOutcome::Ok)
        } else if let Some(case_id) = rest.strip_suffix(" ... FAILED") {
            (case_id, TestOutcome::Failed)
        } else if let Some(case_id) = rest.strip_suffix(" ... ignored") {
            (case_id, TestOutcome::Ignored)
        } else {
            continue;
        };
        if results.insert(case_id.to_owned(), outcome).is_some() {
            return Err("harness.duplicate-test-result".to_owned());
        }
    }
    Ok(results)
}

fn build_oracle_evidence(
    selected: &BTreeSet<String>,
    execution: &Result<BTreeMap<String, TestOutcome>, String>,
) -> Result<RegexSyntaxOracleEvidence, InventoryError> {
    let receipts = selected
        .iter()
        .map(|case_id| RegexSyntaxOracleReceipt {
            case_id: case_id.clone(),
            disposition: oracle_disposition_for(case_id, execution),
        })
        .collect::<Vec<_>>();
    let evidence = RegexSyntaxOracleEvidence {
        scope: AST_PARSE_PREFIX.to_owned(),
        counts: RegexSyntaxOracleCounts::from_receipts(&receipts)?,
        receipts,
    };
    validate_oracle(&evidence)?;
    Ok(evidence)
}

fn oracle_disposition_for(
    case_id: &str,
    execution: &Result<BTreeMap<String, TestOutcome>, String>,
) -> RegexSyntaxOracleDisposition {
    let results = match execution {
        Ok(results) => results,
        Err(reason_code) => {
            return RegexSyntaxOracleDisposition::Fault {
                stage: "cargo-test-upstream-ast-parse".to_owned(),
                reason_code: reason_code.clone(),
            };
        }
    };
    match results.get(case_id) {
        Some(TestOutcome::Ok) => RegexSyntaxOracleDisposition::Pass {
            evidence_sha256: outcome_evidence(case_id, TestOutcome::Ok),
        },
        Some(TestOutcome::Failed) => RegexSyntaxOracleDisposition::Mismatch {
            expected: "ok".to_owned(),
            observed: "failed".to_owned(),
            evidence_sha256: outcome_evidence(case_id, TestOutcome::Failed),
        },
        Some(TestOutcome::Ignored) => RegexSyntaxOracleDisposition::Fault {
            stage: "cargo-test-upstream-ast-parse".to_owned(),
            reason_code: "harness.selected-test-ignored".to_owned(),
        },
        None => RegexSyntaxOracleDisposition::Fault {
            stage: "cargo-test-upstream-ast-parse".to_owned(),
            reason_code: "harness.test-result-missing".to_owned(),
        },
    }
}

impl RegexSyntaxOracleCounts {
    fn from_receipts(receipts: &[RegexSyntaxOracleReceipt]) -> Result<Self, InventoryError> {
        let mut counts = Self::default();
        for receipt in receipts {
            let counter = match receipt.disposition {
                RegexSyntaxOracleDisposition::Pass { .. } => &mut counts.pass,
                RegexSyntaxOracleDisposition::Mismatch { .. } => &mut counts.mismatch,
                RegexSyntaxOracleDisposition::Fault { .. } => &mut counts.fault,
            };
            *counter = counter
                .checked_add(1)
                .ok_or_else(|| InventoryError::new("regex-syntax oracle count overflow"))?;
            counts.total = counts
                .total
                .checked_add(1)
                .ok_or_else(|| InventoryError::new("regex-syntax oracle total overflow"))?;
        }
        if counts.total != REGEX_SYNTAX_AST_PARSE_TESTS {
            return Err(InventoryError::new(
                "regex-syntax oracle denominator mismatch",
            ));
        }
        Ok(counts)
    }
}

fn validate_oracle(oracle: &RegexSyntaxOracleEvidence) -> Result<(), InventoryError> {
    if oracle.scope != AST_PARSE_PREFIX || oracle.receipts.len() != REGEX_SYNTAX_AST_PARSE_TESTS {
        return Err(InventoryError::new("regex-syntax oracle scope mismatch"));
    }
    let ids = oracle
        .receipts
        .iter()
        .map(|receipt| receipt.case_id.clone())
        .collect::<BTreeSet<_>>();
    if ids.len() != oracle.receipts.len()
        || oracle
            .receipts
            .windows(2)
            .any(|pair| pair[0].case_id >= pair[1].case_id)
        || ids
            .iter()
            .any(|case_id| !case_id.starts_with(AST_PARSE_PREFIX))
        || hash_line_list(&ids) != AST_PARSE_IDS_SHA256
    {
        return Err(InventoryError::new(
            "regex-syntax oracle identity inventory mismatch",
        ));
    }
    for receipt in &oracle.receipts {
        let valid = match &receipt.disposition {
            RegexSyntaxOracleDisposition::Pass { evidence_sha256 } => {
                evidence_sha256 == &outcome_evidence(&receipt.case_id, TestOutcome::Ok)
            }
            RegexSyntaxOracleDisposition::Mismatch {
                expected,
                observed,
                evidence_sha256,
            } => {
                expected == "ok"
                    && observed == "failed"
                    && evidence_sha256 == &outcome_evidence(&receipt.case_id, TestOutcome::Failed)
            }
            RegexSyntaxOracleDisposition::Fault { stage, reason_code } => {
                stage == "cargo-test-upstream-ast-parse" && is_harness_fault(reason_code)
            }
        };
        if !valid {
            return Err(InventoryError::new(format!(
                "invalid regex-syntax oracle disposition for {}",
                receipt.case_id
            )));
        }
    }
    let counts = RegexSyntaxOracleCounts::from_receipts(&oracle.receipts)?;
    if counts != oracle.counts {
        return Err(InventoryError::new("regex-syntax oracle counts mismatch"));
    }
    Ok(())
}

fn is_harness_fault(reason_code: &str) -> bool {
    matches!(
        reason_code,
        "harness.cargo-exec-failed"
            | "harness.cargo-test-nonzero-exit"
            | "harness.test-output-not-utf8"
            | "harness.unexpected-selected-test"
            | "harness.success-result-set-incomplete"
            | "harness.duplicate-test-result"
            | "harness.selected-test-ignored"
            | "harness.test-result-missing"
    )
}

fn disposition_for(obligation: &RegexSyntaxCorpusObligation) -> RegexSyntaxCorpusDisposition {
    if obligation.kind == RegexSyntaxCorpusCaseKind::Doctest {
        return RegexSyntaxCorpusDisposition::Unsupported {
            reason_code: "fre-adapter.doctest-not-implemented".to_owned(),
        };
    }
    if obligation.case_id.starts_with(AST_PARSE_PREFIX) {
        if is_supported_ast_case(&obligation.case_id) {
            return execute_ast_case(&obligation.case_id);
        }
        return RegexSyntaxCorpusDisposition::Unsupported {
            reason_code: "fre-adapter.ast-parse-not-implemented".to_owned(),
        };
    }
    RegexSyntaxCorpusDisposition::Unsupported {
        reason_code: "fre-adapter.unit-family-not-implemented".to_owned(),
    }
}

#[derive(Debug)]
struct AstMismatch {
    expected: String,
    observed: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AstHexCase {
    Two,
    Four,
    Eight,
}

impl AstHexCase {
    fn label(self) -> &'static str {
        match self {
            Self::Two => "hex-two",
            Self::Four => "hex-four",
            Self::Eight => "hex-eight",
        }
    }

    fn success_limit(self) -> u32 {
        match self {
            Self::Two => 256,
            Self::Four | Self::Eight => 65_536,
        }
    }

    fn success_pattern(self, value: u32) -> String {
        match self {
            Self::Two => format!(r"\x{value:02x}"),
            Self::Four => format!(r"\u{value:04x}"),
            Self::Eight => format!(r"\U{value:08x}"),
        }
    }

    fn literal_kind(self) -> HexLiteralKind {
        match self {
            Self::Two => HexLiteralKind::X,
            Self::Four => HexLiteralKind::UnicodeShort,
            Self::Eight => HexLiteralKind::UnicodeLong,
        }
    }

    fn literal_evidence_label(self) -> &'static str {
        match self {
            Self::Two => "HexFixed(X)",
            Self::Four => "HexFixed(UnicodeShort)",
            Self::Eight => "HexFixed(UnicodeLong)",
        }
    }

    fn error_probes(self) -> &'static [AstHexErrorProbe] {
        match self {
            Self::Two => &HEX_TWO_ERROR_PROBES,
            Self::Four => &HEX_FOUR_ERROR_PROBES,
            Self::Eight => &HEX_EIGHT_ERROR_PROBES,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AstHexErrorKind {
    UnexpectedEof,
    InvalidDigit,
    InvalidScalar,
}

impl AstHexErrorKind {
    fn upstream(self) -> regex_syntax::ast::ErrorKind {
        match self {
            Self::UnexpectedEof => regex_syntax::ast::ErrorKind::EscapeUnexpectedEof,
            Self::InvalidDigit => regex_syntax::ast::ErrorKind::EscapeHexInvalidDigit,
            Self::InvalidScalar => regex_syntax::ast::ErrorKind::EscapeHexInvalid,
        }
    }

    fn evidence_label(self) -> &'static str {
        match self {
            Self::UnexpectedEof => "EscapeUnexpectedEof",
            Self::InvalidDigit => "EscapeHexInvalidDigit",
            Self::InvalidScalar => "EscapeHexInvalid",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AstHexErrorProbe {
    pattern: &'static str,
    kind: AstHexErrorKind,
    span_start: usize,
    span_end: usize,
}

impl AstHexErrorProbe {
    const fn unexpected_eof(pattern: &'static str, span_start: usize, span_end: usize) -> Self {
        Self {
            pattern,
            kind: AstHexErrorKind::UnexpectedEof,
            span_start,
            span_end,
        }
    }

    const fn invalid_digit(pattern: &'static str, span_start: usize, span_end: usize) -> Self {
        Self {
            pattern,
            kind: AstHexErrorKind::InvalidDigit,
            span_start,
            span_end,
        }
    }

    const fn invalid_scalar(pattern: &'static str, span_start: usize, span_end: usize) -> Self {
        Self {
            pattern,
            kind: AstHexErrorKind::InvalidScalar,
            span_start,
            span_end,
        }
    }
}

fn is_supported_ast_case(case_id: &str) -> bool {
    matches!(
        case_id,
        AST_HOLISTIC_CASE_ID
            | AST_OCTAL_CASE_ID
            | AST_HEX_TWO_CASE_ID
            | AST_HEX_FOUR_CASE_ID
            | AST_HEX_EIGHT_CASE_ID
            | AST_PERL_CLASS_CASE_ID
            | AST_UNICODE_CLASS_CASE_ID
            | AST_UNSUPPORTED_BACKREFERENCE_CASE_ID
            | AST_UNSUPPORTED_LOOKAROUND_CASE_ID
            | AST_REGRESSION_454_CASE_ID
            | AST_REGRESSION_455_CASE_ID
    )
}

fn execute_ast_case(case_id: &str) -> RegexSyntaxCorpusDisposition {
    let execution = match case_id {
        AST_HOLISTIC_CASE_ID => catch_unwind(AssertUnwindSafe(run_ast_holistic)),
        AST_OCTAL_CASE_ID => catch_unwind(AssertUnwindSafe(run_ast_octal)),
        AST_HEX_TWO_CASE_ID => catch_unwind(AssertUnwindSafe(run_ast_hex_two)),
        AST_HEX_FOUR_CASE_ID => catch_unwind(AssertUnwindSafe(run_ast_hex_four)),
        AST_HEX_EIGHT_CASE_ID => catch_unwind(AssertUnwindSafe(run_ast_hex_eight)),
        AST_PERL_CLASS_CASE_ID => catch_unwind(AssertUnwindSafe(run_ast_perl_class)),
        AST_UNICODE_CLASS_CASE_ID => catch_unwind(AssertUnwindSafe(run_ast_unicode_class)),
        AST_UNSUPPORTED_BACKREFERENCE_CASE_ID => {
            catch_unwind(AssertUnwindSafe(run_ast_unsupported_backreference))
        }
        AST_UNSUPPORTED_LOOKAROUND_CASE_ID => {
            catch_unwind(AssertUnwindSafe(run_ast_unsupported_lookaround))
        }
        AST_REGRESSION_454_CASE_ID => catch_unwind(AssertUnwindSafe(run_ast_regression_454)),
        AST_REGRESSION_455_CASE_ID => catch_unwind(AssertUnwindSafe(run_ast_regression_455)),
        _ => unreachable!("caller checked supported AST case"),
    };
    match execution {
        Ok(Ok(())) => RegexSyntaxCorpusDisposition::Pass {
            evidence_sha256: ast_case_pass_evidence(case_id),
        },
        Ok(Err(mismatch)) => {
            let evidence_sha256 =
                ast_mismatch_evidence(case_id, &mismatch.expected, &mismatch.observed);
            RegexSyntaxCorpusDisposition::Mismatch {
                expected: mismatch.expected,
                observed: mismatch.observed,
                evidence_sha256,
            }
        }
        Err(_) => RegexSyntaxCorpusDisposition::Fault {
            stage: "fre-ast-adapter".to_owned(),
            reason_code: "candidate.adapter-panicked".to_owned(),
        },
    }
}

fn run_ast_holistic() -> Result<(), AstMismatch> {
    let first_pattern = "]";
    let first_expected = Ast::literal(Literal {
        span: ast_span(0, 1),
        kind: LiteralKind::Verbatim,
        c: ']',
    });
    let first = execute_ast_assertion(first_pattern, &first_expected, "verbatim-right-bracket")?;
    validate_ast_record(&first, first_pattern, &RustProfile::regex_1_12_4())?;

    let second_pattern = r"\\\.\+\*\?\(\)\|\[\]\{\}\^\$\#\&\-\~";
    let metacharacters = [
        '\\', '.', '+', '*', '?', '(', ')', '|', '[', ']', '{', '}', '^', '$', '#', '&', '-', '~',
    ];
    let asts = metacharacters
        .into_iter()
        .enumerate()
        .map(|(index, c)| {
            let start = index.saturating_mul(2);
            Ast::literal(Literal {
                span: ast_span(start, start.saturating_add(2)),
                kind: LiteralKind::Meta,
                c,
            })
        })
        .collect();
    let second_expected = Ast::concat(Concat {
        span: ast_span(0, 36),
        asts,
    });
    let second = execute_ast_assertion(
        second_pattern,
        &second_expected,
        "escaped-metacharacters-with-exact-spans",
    )?;
    validate_ast_record(&second, second_pattern, &RustProfile::regex_1_12_4())
}

fn run_ast_unsupported_backreference() -> Result<(), AstMismatch> {
    for (index, pattern) in UNSUPPORTED_BACKREFERENCE_PROBES.into_iter().enumerate() {
        let expected_upstream = regex_syntax::ast::parse::Parser::new()
            .parse(pattern)
            .expect_err("authenticated backreference probe must be rejected upstream");
        if expected_upstream.kind() != &regex_syntax::ast::ErrorKind::UnsupportedBackreference
            || expected_upstream.span() != &ast_span(0, pattern.len())
            || expected_upstream.pattern() != pattern
        {
            return Err(AstMismatch {
                expected: format!(
                    "backreference-probe-{index}: upstream UnsupportedBackreference span=0..{} pattern={pattern:?}",
                    pattern.len(),
                ),
                observed: format!("backreference-probe-{index}: {expected_upstream:?}"),
            });
        }

        let profile = CompatibilityProfile::RustText(RustProfile::regex_1_12_4());
        let observed = parse_rust_ast(ParseRequest::rust(pattern, profile.clone()))
            .expect_err("FRE must reject authenticated backreference probe");
        validate_ast_error(
            &observed,
            &expected_upstream,
            pattern,
            &profile,
            &format!("backreference-probe-{index}"),
        )?;
    }
    Ok(())
}

fn run_ast_octal() -> Result<(), AstMismatch> {
    let mut patterns: Vec<String> = (0..511).map(|value| format!(r"\{value:o}")).collect();
    patterns.extend([r"\778".to_owned(), r"\7777".to_owned(), r"\8".to_owned()]);

    for (index, pattern) in patterns.iter().enumerate() {
        let expected = regex_syntax::ast::parse::ParserBuilder::new()
            .octal(true)
            .build()
            .parse(pattern);
        let mut rust_profile = RustProfile::regex_1_12_4();
        rust_profile.options.octal = true;
        let profile = CompatibilityProfile::RustText(rust_profile.clone());
        let observed = parse_rust_ast(ParseRequest::rust(pattern, profile.clone()));
        match (expected, observed) {
            (Ok(expected_ast), Ok(record)) => {
                if record.ast != expected_ast {
                    return Err(AstMismatch {
                        expected: format!("octal-probe-{index}: Ok({expected_ast:?})"),
                        observed: format!("octal-probe-{index}: Ok({:?})", record.ast),
                    });
                }
                validate_ast_record(&record, pattern, &rust_profile)?;
            }
            (Err(expected_error), Err(observed_error)) => validate_ast_error(
                &observed_error,
                &expected_error,
                pattern,
                &profile,
                &format!("octal-probe-{index}"),
            )?,
            (Ok(expected_ast), Err(observed_error)) => {
                return Err(AstMismatch {
                    expected: format!("octal-probe-{index}: Ok({expected_ast:?})"),
                    observed: format!("octal-probe-{index}: Err({observed_error:?})"),
                });
            }
            (Err(expected_error), Ok(record)) => {
                return Err(AstMismatch {
                    expected: format!("octal-probe-{index}: Err({expected_error:?})"),
                    observed: format!("octal-probe-{index}: Ok({:?})", record.ast),
                });
            }
        }
    }
    Ok(())
}

fn run_ast_hex_two() -> Result<(), AstMismatch> {
    run_ast_hex_case(AstHexCase::Two)
}

fn run_ast_hex_four() -> Result<(), AstMismatch> {
    run_ast_hex_case(AstHexCase::Four)
}

fn run_ast_hex_eight() -> Result<(), AstMismatch> {
    run_ast_hex_case(AstHexCase::Eight)
}

fn run_ast_hex_case(case: AstHexCase) -> Result<(), AstMismatch> {
    for value in 0..case.success_limit() {
        let Some(c) = char::from_u32(value) else {
            continue;
        };
        let pattern = case.success_pattern(value);
        let expected = Ast::literal(Literal {
            span: ast_span(0, pattern.len()),
            kind: LiteralKind::HexFixed(case.literal_kind()),
            c,
        });
        let assertion = format!("{}-success-{value}", case.label());

        match regex_syntax::ast::parse::Parser::new().parse(&pattern) {
            Ok(upstream_ast) if upstream_ast == expected => {}
            Ok(upstream_ast) => {
                return Err(AstMismatch {
                    expected: format!("{assertion}: authenticated upstream Ok({expected:?})"),
                    observed: format!("{assertion}: authenticated upstream Ok({upstream_ast:?})"),
                });
            }
            Err(upstream_error) => {
                return Err(AstMismatch {
                    expected: format!("{assertion}: authenticated upstream Ok({expected:?})"),
                    observed: format!(
                        "{assertion}: authenticated upstream Err({upstream_error:?})"
                    ),
                });
            }
        }

        let record = execute_ast_assertion(&pattern, &expected, &assertion)?;
        validate_ast_record(&record, &pattern, &RustProfile::regex_1_12_4())?;
    }

    for (index, probe) in case.error_probes().iter().enumerate() {
        run_ast_hex_error_probe(case, index, *probe)?;
    }
    Ok(())
}

fn run_ast_hex_error_probe(
    case: AstHexCase,
    index: usize,
    probe: AstHexErrorProbe,
) -> Result<(), AstMismatch> {
    let assertion = format!("{}-error-{index}", case.label());
    let expected_kind = probe.kind.upstream();
    let expected_span = ast_span(probe.span_start, probe.span_end);
    let expected_upstream = match regex_syntax::ast::parse::Parser::new().parse(probe.pattern) {
        Err(error) if ast_hex_error_matches(&error, probe) => error,
        outcome => {
            return Err(AstMismatch {
                expected: format!(
                    "{assertion}: authenticated upstream Err(kind={expected_kind:?}, span={expected_span:?}, pattern={:?})",
                    probe.pattern,
                ),
                observed: format!("{assertion}: authenticated upstream {outcome:?}"),
            });
        }
    };

    let profile = CompatibilityProfile::RustText(RustProfile::regex_1_12_4());
    match parse_rust_ast(ParseRequest::rust(probe.pattern, profile.clone())) {
        Err(observed) => validate_ast_error(
            &observed,
            &expected_upstream,
            probe.pattern,
            &profile,
            &assertion,
        ),
        Ok(record) => Err(AstMismatch {
            expected: format!("{assertion}: Err({expected_upstream:?})"),
            observed: format!("{assertion}: Ok({:?})", record.ast),
        }),
    }
}

fn ast_hex_error_matches(error: &regex_syntax::ast::Error, probe: AstHexErrorProbe) -> bool {
    error.kind() == &probe.kind.upstream()
        && error.span() == &ast_span(probe.span_start, probe.span_end)
        && error.pattern() == probe.pattern
}

fn run_ast_perl_class() -> Result<(), AstMismatch> {
    for (index, pattern) in PERL_CLASS_PROBES.into_iter().enumerate() {
        execute_ast_equivalence_probe(pattern, &format!("perl-class-probe-{index}"))?;
    }
    Ok(())
}

fn run_ast_unicode_class() -> Result<(), AstMismatch> {
    for (index, pattern) in UNICODE_CLASS_PROBES.into_iter().enumerate() {
        execute_ast_equivalence_probe(pattern, &format!("unicode-class-probe-{index}"))?;
    }
    Ok(())
}

fn execute_ast_equivalence_probe(pattern: &str, assertion: &str) -> Result<(), AstMismatch> {
    let rust_profile = RustProfile::regex_1_12_4();
    let profile = CompatibilityProfile::RustText(rust_profile.clone());
    let expected = regex_syntax::ast::parse::Parser::new().parse(pattern);
    let observed = parse_rust_ast(ParseRequest::rust(pattern, profile.clone()));
    match (expected, observed) {
        (Ok(expected_ast), Ok(record)) => {
            validate_ast_success(&record, &expected_ast, pattern, &rust_profile, assertion)
        }
        (Err(expected_error), Err(observed_error)) => validate_ast_error(
            &observed_error,
            &expected_error,
            pattern,
            &profile,
            assertion,
        ),
        (Ok(expected_ast), Err(observed_error)) => Err(AstMismatch {
            expected: format!("{assertion}: Ok({expected_ast:?})"),
            observed: format!("{assertion}: Err({observed_error:?})"),
        }),
        (Err(expected_error), Ok(record)) => Err(AstMismatch {
            expected: format!("{assertion}: Err({expected_error:?})"),
            observed: format!("{assertion}: Ok({:?})", record.ast),
        }),
    }
}

fn run_ast_unsupported_lookaround() -> Result<(), AstMismatch> {
    for (index, (pattern, end)) in UNSUPPORTED_LOOKAROUND_PROBES.into_iter().enumerate() {
        let expected_upstream = regex_syntax::ast::parse::Parser::new()
            .parse(pattern)
            .expect_err("authenticated look-around probe must be rejected upstream");
        if expected_upstream.kind() != &regex_syntax::ast::ErrorKind::UnsupportedLookAround
            || expected_upstream.span() != &ast_span(0, end)
            || expected_upstream.pattern() != pattern
        {
            return Err(AstMismatch {
                expected: format!(
                    "lookaround-probe-{index}: upstream UnsupportedLookAround span=0..{end} pattern={pattern:?}"
                ),
                observed: format!("lookaround-probe-{index}: {expected_upstream:?}"),
            });
        }

        let profile = CompatibilityProfile::RustText(RustProfile::regex_1_12_4());
        let observed = parse_rust_ast(ParseRequest::rust(pattern, profile.clone()))
            .expect_err("FRE must reject authenticated look-around probe");
        validate_ast_error(
            &observed,
            &expected_upstream,
            pattern,
            &profile,
            &format!("lookaround-probe-{index}"),
        )?;
    }
    Ok(())
}

fn validate_ast_error(
    observed: &ParseError,
    expected_upstream: &regex_syntax::ast::Error,
    pattern: &str,
    profile: &CompatibilityProfile,
    assertion: &str,
) -> Result<(), AstMismatch> {
    let expected_span = SourceSpan {
        start: u64::try_from(expected_upstream.span().start.offset).unwrap_or(u64::MAX),
        end: u64::try_from(expected_upstream.span().end.offset).unwrap_or(u64::MAX),
    };
    let valid = observed.schema_version == SCHEMA_VERSION
        && observed.profile.as_ref() == profile
        && observed.category == ErrorCategory::UpstreamRustSyntax
        && observed.span == Some(expected_span)
        && observed.message == expected_upstream.to_string()
        && expected_upstream.pattern() == pattern;
    if valid {
        Ok(())
    } else {
        Err(AstMismatch {
            expected: format!(
                "{assertion}: schema={SCHEMA_VERSION} profile={profile:?} category=UpstreamRustSyntax span={expected_span:?} message={:?}",
                expected_upstream.to_string(),
            ),
            observed: format!("{assertion}: {observed:?}"),
        })
    }
}

fn run_ast_regression_454() -> Result<(), AstMismatch> {
    execute_ast_outcome_probe(REGRESSION_454_PATTERN, 50, true, "regression-454")
}

fn run_ast_regression_455() -> Result<(), AstMismatch> {
    for (index, (pattern, expected_ok)) in REGRESSION_455_PROBES.into_iter().enumerate() {
        execute_ast_outcome_probe(
            pattern,
            RustProfile::regex_1_12_4().options.nest_limit,
            expected_ok,
            &format!("regression-455-probe-{index}"),
        )?;
    }
    Ok(())
}

fn execute_ast_outcome_probe(
    pattern: &str,
    nest_limit: u32,
    expected_ok: bool,
    assertion: &str,
) -> Result<(), AstMismatch> {
    let mut rust_profile = RustProfile::regex_1_12_4();
    rust_profile.options.nest_limit = nest_limit;
    let profile = CompatibilityProfile::RustText(rust_profile.clone());
    match parse_rust_ast(ParseRequest::rust(pattern, profile)) {
        Ok(record) if expected_ok => validate_ast_record(&record, pattern, &rust_profile),
        Err(_) if !expected_ok => Ok(()),
        Ok(record) => Err(AstMismatch {
            expected: format!("{assertion}: Err(_)"),
            observed: format!("{assertion}: Ok({:?})", record.ast),
        }),
        Err(error) => Err(AstMismatch {
            expected: format!("{assertion}: Ok(_)"),
            observed: format!("{assertion}: Err({error:?})"),
        }),
    }
}

fn execute_ast_assertion(
    pattern: &str,
    expected: &Ast,
    assertion: &str,
) -> Result<RustAstRecord, AstMismatch> {
    let profile = CompatibilityProfile::RustText(RustProfile::regex_1_12_4());
    let record =
        parse_rust_ast(ParseRequest::rust(pattern, profile)).map_err(|error| AstMismatch {
            expected: format!("{assertion}: Ok({expected:?})"),
            observed: format!("{assertion}: Err({error:?})"),
        })?;
    if &record.ast != expected {
        return Err(AstMismatch {
            expected: format!("{assertion}: {expected:?}"),
            observed: format!("{assertion}: {:?}", record.ast),
        });
    }
    Ok(record)
}

fn validate_ast_success(
    record: &RustAstRecord,
    expected: &Ast,
    pattern: &str,
    rust_profile: &RustProfile,
    assertion: &str,
) -> Result<(), AstMismatch> {
    if &record.ast != expected {
        return Err(AstMismatch {
            expected: format!("{assertion}: Ok({expected:?})"),
            observed: format!("{assertion}: Ok({:?})", record.ast),
        });
    }
    validate_ast_record(record, pattern, rust_profile)
}

fn validate_ast_record(
    record: &RustAstRecord,
    pattern: &str,
    rust_profile: &RustProfile,
) -> Result<(), AstMismatch> {
    let expected_profile = CompatibilityProfile::RustText(rust_profile.clone());
    let bytes = u64::try_from(pattern.len()).unwrap_or(u64::MAX);
    let source_units = bytes.saturating_add(1);
    let nodes = bytes
        .checked_mul(2)
        .and_then(|nodes| nodes.checked_add(2))
        .unwrap_or(u64::MAX);
    let nesting = source_units.min(u64::from(rust_profile.options.nest_limit).saturating_add(1));
    let stack = nesting;
    let work = source_units.saturating_mul(512);
    let valid = record.key.schema_version == SCHEMA_VERSION
        && record.key.pattern.as_bytes() == pattern.as_bytes()
        && record.key.profile == expected_profile
        && record.key.admission == AdmissionPolicy::default()
        && record.key.safety == SafetyEnvelope::default()
        && record.admission_status == AdmissionStatus::UpstreamOraclePending
        && record.reserved_ast_nodes == nodes
        && record.reserved_max_nesting == nesting
        && record.reserved_parser_stack == stack
        && record.reserved_parse_work == work;
    if valid {
        Ok(())
    } else {
        Err(AstMismatch {
            expected: format!(
                "FRE AST record schema={SCHEMA_VERSION} pattern={pattern:?} nodes={nodes} nesting={nesting} stack={stack} work={work}"
            ),
            observed: format!("{record:?}"),
        })
    }
}

fn ast_span(start: usize, end: usize) -> Span {
    Span::new(
        Position::new(start, 1, start.saturating_add(1)),
        Position::new(end, 1, end.saturating_add(1)),
    )
}

fn ast_case_pass_evidence(case_id: &str) -> String {
    let mut contract = format!(
        "fre.regex-syntax.ast-adapter.v1\ncase={case_id}\nparser=fre-syntax+pinned-regex-syntax-0.8.11\n"
    );
    match case_id {
        AST_HOLISTIC_CASE_ID => contract.push_str(
            "assertion-1=verbatim-right-bracket-span-0-1\nassertion-1-reservation=nodes:2,nesting:2,stack:2,work:1024\nassertion-2=18-escaped-metacharacters-exact-spans-0-36\nassertion-2-reservation=nodes:37,nesting:37,stack:37,work:18944\n",
        ),
        AST_UNSUPPORTED_BACKREFERENCE_CASE_ID => {
            for (index, pattern) in UNSUPPORTED_BACKREFERENCE_PROBES.into_iter().enumerate() {
                writeln!(
                    contract,
                    "probe-{index}=sha256:{},bytes:{},expected:error:UnsupportedBackreference,span:0..{}",
                    sha256(pattern.as_bytes()),
                    pattern.len(),
                    pattern.len(),
                )
                .expect("writing to a String cannot fail");
            }
        }
        AST_UNSUPPORTED_LOOKAROUND_CASE_ID => {
            for (index, (pattern, end)) in UNSUPPORTED_LOOKAROUND_PROBES.into_iter().enumerate() {
                writeln!(
                    contract,
                    "probe-{index}=sha256:{},bytes:{},expected:error:UnsupportedLookAround,span:0..{end}",
                    sha256(pattern.as_bytes()),
                    pattern.len(),
                )
                .expect("writing to a String cannot fail");
            }
        }
        AST_PERL_CLASS_CASE_ID => {
            for (index, pattern) in PERL_CLASS_PROBES.into_iter().enumerate() {
                writeln!(
                    contract,
                    "probe-{index}=sha256:{},bytes:{},expected:upstream-exact-success",
                    sha256(pattern.as_bytes()),
                    pattern.len(),
                )
                .expect("writing to a String cannot fail");
            }
        }
        AST_UNICODE_CLASS_CASE_ID => {
            for (index, pattern) in UNICODE_CLASS_PROBES.into_iter().enumerate() {
                writeln!(
                    contract,
                    "probe-{index}=sha256:{},bytes:{},expected:upstream-exact-result",
                    sha256(pattern.as_bytes()),
                    pattern.len(),
                )
                .expect("writing to a String cannot fail");
            }
        }
        AST_OCTAL_CASE_ID => {
            for value in 0..511 {
                let pattern = format!(r"\{value:o}");
                writeln!(
                    contract,
                    "probe-{value}=sha256:{},bytes:{},octal:true,expected:ok",
                    sha256(pattern.as_bytes()),
                    pattern.len(),
                )
                .expect("writing to a String cannot fail");
            }
            for (index, pattern) in [r"\778", r"\7777", r"\8"].into_iter().enumerate() {
                writeln!(
                    contract,
                    "edge-probe-{index}=sha256:{},bytes:{},octal:true,expected:{}",
                    sha256(pattern.as_bytes()),
                    pattern.len(),
                    if pattern == r"\8" { "err" } else { "ok" },
                )
                .expect("writing to a String cannot fail");
            }
        }
        AST_HEX_TWO_CASE_ID => write_ast_hex_evidence(&mut contract, AstHexCase::Two),
        AST_HEX_FOUR_CASE_ID => write_ast_hex_evidence(&mut contract, AstHexCase::Four),
        AST_HEX_EIGHT_CASE_ID => write_ast_hex_evidence(&mut contract, AstHexCase::Eight),
        AST_REGRESSION_454_CASE_ID => {
            writeln!(
                contract,
                "probe=sha256:{},bytes:{},nest-limit:50,expected:ok",
                sha256(REGRESSION_454_PATTERN.as_bytes()),
                REGRESSION_454_PATTERN.len(),
            )
            .expect("writing to a String cannot fail");
        }
        AST_REGRESSION_455_CASE_ID => {
            for (index, (pattern, expected_ok)) in REGRESSION_455_PROBES.into_iter().enumerate() {
                writeln!(
                    contract,
                    "probe-{index}=sha256:{},bytes:{},nest-limit:250,expected:{}",
                    sha256(pattern.as_bytes()),
                    pattern.len(),
                    if expected_ok { "ok" } else { "err" },
                )
                .expect("writing to a String cannot fail");
            }
        }
        _ => unreachable!("pass evidence requires a supported AST case"),
    }
    sha256(contract.as_bytes())
}

fn write_ast_hex_evidence(contract: &mut String, case: AstHexCase) {
    writeln!(
        contract,
        "authenticated-generator={},range:0..{},skip:non-Rust-char,success-kind:{}",
        case.label(),
        case.success_limit(),
        case.literal_evidence_label(),
    )
    .expect("writing to a String cannot fail");
    for value in 0..case.success_limit() {
        let Some(c) = char::from_u32(value) else {
            continue;
        };
        let pattern = case.success_pattern(value);
        writeln!(
            contract,
            "success-{value}=sha256:{},bytes:{},span:0..{},kind:{},scalar:U+{:04X}",
            sha256(pattern.as_bytes()),
            pattern.len(),
            pattern.len(),
            case.literal_evidence_label(),
            u32::from(c),
        )
        .expect("writing to a String cannot fail");
    }
    for (index, probe) in case.error_probes().iter().enumerate() {
        writeln!(
            contract,
            "error-{index}=sha256:{},bytes:{},expected:error:{},span:{}..{}",
            sha256(probe.pattern.as_bytes()),
            probe.pattern.len(),
            probe.kind.evidence_label(),
            probe.span_start,
            probe.span_end,
        )
        .expect("writing to a String cannot fail");
    }
}

fn fixed_ast_hex_pass_evidence(case_id: &str) -> Option<&'static str> {
    match case_id {
        AST_HEX_TWO_CASE_ID => Some(AST_HEX_TWO_PASS_EVIDENCE_SHA256),
        AST_HEX_FOUR_CASE_ID => Some(AST_HEX_FOUR_PASS_EVIDENCE_SHA256),
        AST_HEX_EIGHT_CASE_ID => Some(AST_HEX_EIGHT_PASS_EVIDENCE_SHA256),
        _ => None,
    }
}

fn ast_mismatch_evidence(case_id: &str, expected: &str, observed: &str) -> String {
    sha256(
        format!(
            "fre.regex-syntax.ast-adapter.mismatch.v1\ncase={case_id}\nexpected={expected}\nobserved={observed}\n"
        )
        .as_bytes(),
    )
}

fn validate_disposition(receipt: &RegexSyntaxCorpusReceipt) -> Result<(), InventoryError> {
    let obligation = &receipt.obligation;
    if obligation.case_id.is_empty()
        || obligation.source_path.is_empty()
        || obligation.source_line == 0
        || !is_sha256(&obligation.source_sha256)
        || (!obligation.default_harness_member && !obligation.no_default_harness_member)
    {
        return Err(InventoryError::new(format!(
            "invalid regex-syntax obligation {}",
            obligation.case_id
        )));
    }
    let valid = match (&obligation.kind, &receipt.disposition) {
        (
            RegexSyntaxCorpusCaseKind::Doctest,
            RegexSyntaxCorpusDisposition::Unsupported { reason_code },
        ) => {
            obligation.default_harness_member
                && obligation.no_default_harness_member
                && reason_code == "fre-adapter.doctest-not-implemented"
        }
        (
            RegexSyntaxCorpusCaseKind::Unit,
            RegexSyntaxCorpusDisposition::Pass { evidence_sha256 },
        ) if is_supported_ast_case(&obligation.case_id) => {
            obligation.default_harness_member
                && obligation.no_default_harness_member
                && evidence_sha256 == &ast_case_pass_evidence(&obligation.case_id)
                && fixed_ast_hex_pass_evidence(&obligation.case_id)
                    .is_none_or(|fixed| evidence_sha256 == fixed)
        }
        (
            RegexSyntaxCorpusCaseKind::Unit,
            RegexSyntaxCorpusDisposition::Mismatch {
                expected,
                observed,
                evidence_sha256,
            },
        ) if is_supported_ast_case(&obligation.case_id) => {
            !expected.is_empty()
                && !observed.is_empty()
                && expected.len() <= 65_536
                && observed.len() <= 65_536
                && evidence_sha256
                    == &ast_mismatch_evidence(&obligation.case_id, expected, observed)
        }
        (
            RegexSyntaxCorpusCaseKind::Unit,
            RegexSyntaxCorpusDisposition::Fault { stage, reason_code },
        ) if is_supported_ast_case(&obligation.case_id) => {
            stage == "fre-ast-adapter" && reason_code == "candidate.adapter-panicked"
        }
        (
            RegexSyntaxCorpusCaseKind::Unit,
            RegexSyntaxCorpusDisposition::Unsupported { reason_code },
        ) if obligation.case_id.starts_with(AST_PARSE_PREFIX) => {
            !is_supported_ast_case(&obligation.case_id)
                && obligation.default_harness_member
                && reason_code == "fre-adapter.ast-parse-not-implemented"
        }
        (
            RegexSyntaxCorpusCaseKind::Unit,
            RegexSyntaxCorpusDisposition::Unsupported { reason_code },
        ) => {
            !obligation.case_id.starts_with(AST_PARSE_PREFIX)
                && reason_code == "fre-adapter.unit-family-not-implemented"
        }
        _ => false,
    };
    if !valid {
        return Err(InventoryError::new(format!(
            "invalid regex-syntax disposition for {}",
            obligation.case_id
        )));
    }
    Ok(())
}

fn validate_harness(harness: &RegexSyntaxHarnessIdentity) -> Result<(), InventoryError> {
    if harness.cargo_release.is_empty()
        || harness.rustc_release.is_empty()
        || !is_sha256(&harness.cargo_executable_sha256)
        || !is_sha256(&harness.rustc_executable_sha256)
        || harness
            .cargo_release
            .bytes()
            .chain(harness.rustc_release.bytes())
            .any(|byte| byte.is_ascii_control())
        || harness.unit_definitions != REGEX_SYNTAX_UNIT_DEFINITIONS
        || harness.default_unit_tests != REGEX_SYNTAX_DEFAULT_UNIT_TESTS
        || harness.no_default_unit_tests != REGEX_SYNTAX_NO_DEFAULT_UNIT_TESTS
        || harness.unit_union != REGEX_SYNTAX_UNIT_DEFINITIONS
        || harness.unit_intersection != 133
        || harness.default_only_unit_tests != 14
        || harness.no_default_only_unit_tests != 11
        || harness.default_doctests != REGEX_SYNTAX_DOCTESTS
        || harness.no_default_doctests != REGEX_SYNTAX_DOCTESTS
        || harness.unit_definition_ids_sha256 != UNIT_DEFINITION_IDS_SHA256
        || harness.default_unit_list_sha256 != DEFAULT_UNIT_LIST_SHA256
        || harness.no_default_unit_list_sha256 != NO_DEFAULT_UNIT_LIST_SHA256
        || harness.default_doctest_list_sha256 != DOCTEST_LIST_SHA256
        || harness.no_default_doctest_list_sha256 != DOCTEST_LIST_SHA256
        || harness.obligation_inventory_sha256 != OBLIGATION_INVENTORY_SHA256
        || harness.executable_slice != AST_PARSE_PREFIX
        || harness.executable_slice_tests != REGEX_SYNTAX_AST_PARSE_TESTS
    {
        return Err(InventoryError::new(
            "regex-syntax harness identity mismatch",
        ));
    }
    Ok(())
}

fn validate_candidate(candidate: &CandidateIdentity) -> Result<(), InventoryError> {
    if candidate.revision.len() != 40
        || candidate.tree.len() != 40
        || !candidate
            .revision
            .bytes()
            .chain(candidate.tree.bytes())
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || !candidate.tracked_and_untracked_worktree_clean
    {
        return Err(InventoryError::new(
            "regex-syntax corpus candidate identity invalid",
        ));
    }
    Ok(())
}

fn prepare_target_dir(
    target: &Path,
    package: &Path,
    candidate: &Path,
) -> Result<PathBuf, InventoryError> {
    fs::create_dir_all(target).map_err(|error| {
        InventoryError::new(format!(
            "create target directory {}: {error}",
            target.display()
        ))
    })?;
    let metadata = fs::symlink_metadata(target).map_err(|error| {
        InventoryError::new(format!(
            "stat target directory {}: {error}",
            target.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(InventoryError::new(
            "regex-syntax corpus target must be a real directory",
        ));
    }
    if fs::read_dir(target)
        .map_err(|error| {
            InventoryError::new(format!(
                "read target directory {}: {error}",
                target.display()
            ))
        })?
        .next()
        .is_some()
    {
        return Err(InventoryError::new(
            "regex-syntax corpus target must be empty",
        ));
    }
    let target = target
        .canonicalize()
        .map_err(|error| InventoryError::new(format!("canonicalize target directory: {error}")))?;
    for protected in [package, candidate] {
        let protected = protected.canonicalize().map_err(|error| {
            InventoryError::new(format!("canonicalize protected source: {error}"))
        })?;
        if target.starts_with(&protected) || protected.starts_with(&target) {
            return Err(InventoryError::new(
                "regex-syntax target must be disjoint from source worktrees",
            ));
        }
    }
    Ok(target)
}

fn prepare_command_target(root: &Path, name: &str) -> Result<PathBuf, InventoryError> {
    if name.is_empty() || name.contains('/') || name.contains('\\') || name == "." || name == ".." {
        return Err(InventoryError::new(
            "invalid regex-syntax command target name",
        ));
    }
    let target = root.join(name);
    fs::create_dir(&target).map_err(|error| {
        InventoryError::new(format!(
            "create fresh command target {}: {error}",
            target.display()
        ))
    })?;
    let metadata = fs::symlink_metadata(&target).map_err(|error| {
        InventoryError::new(format!("stat command target {}: {error}", target.display()))
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(InventoryError::new(
            "regex-syntax command target must be a real directory",
        ));
    }
    let target = target
        .canonicalize()
        .map_err(|error| InventoryError::new(format!("canonicalize command target: {error}")))?;
    if target.parent() != Some(root) || !target.starts_with(root) {
        return Err(InventoryError::new(
            "regex-syntax command target escaped target root",
        ));
    }
    if fs::read_dir(&target)
        .map_err(|error| InventoryError::new(format!("read command target: {error}")))?
        .next()
        .is_some()
    {
        return Err(InventoryError::new(
            "regex-syntax command target must be empty",
        ));
    }
    Ok(target)
}

fn cargo_output(
    package: &Path,
    target: &Path,
    cargo_home: &Path,
    cargo: &Path,
    rustc: &Path,
    args: &[&str],
) -> std::io::Result<Output> {
    let mut command = Command::new(cargo);
    for (key, _) in std::env::vars_os() {
        let Some(key_text) = key.to_str() else {
            continue;
        };
        if matches!(
            key_text,
            "RUSTC"
                | "RUSTC_WRAPPER"
                | "RUSTC_WORKSPACE_WRAPPER"
                | "RUSTDOC"
                | "RUSTFLAGS"
                | "RUSTDOCFLAGS"
                | "CARGO_ENCODED_RUSTFLAGS"
        ) || key_text.starts_with("RUSTC_")
            || key_text.starts_with("CARGO_BUILD_")
            || key_text.starts_with("CARGO_PROFILE_")
            || key_text.starts_with("CARGO_TARGET_")
        {
            command.env_remove(key);
        }
    }
    command
        .args(args)
        .current_dir(package)
        .env("CARGO_HOME", cargo_home)
        .env("CARGO_TARGET_DIR", target)
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_TERM_COLOR", "never")
        .env("RUSTC", rustc)
        .output()
}

fn resolve_tool(tool: &str) -> Result<PathBuf, InventoryError> {
    let path = std::env::var_os("PATH")
        .ok_or_else(|| InventoryError::new("PATH is absent while resolving harness tools"))?;
    let current = std::env::current_dir()
        .map_err(|error| InventoryError::new(format!("read current directory: {error}")))?;
    for directory in std::env::split_paths(&path) {
        let directory = if directory.is_absolute() {
            directory
        } else {
            current.join(directory)
        };
        let candidate = directory.join(tool);
        let Ok(metadata) = fs::metadata(&candidate) else {
            continue;
        };
        if metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 {
            return Ok(candidate);
        }
    }
    Err(InventoryError::new(format!(
        "cannot resolve executable {tool:?} from PATH"
    )))
}

fn tool_release(tool: &Path, name: &str) -> Result<String, InventoryError> {
    let output = Command::new(tool)
        .arg("--version")
        .output()
        .map_err(|error| InventoryError::new(format!("execute {name} --version: {error}")))?;
    if !output.status.success() {
        return Err(InventoryError::new(format!("{name} --version failed")));
    }
    let release = std::str::from_utf8(&output.stdout)
        .map_err(|error| InventoryError::new(format!("{name} version is not UTF-8: {error}")))?
        .trim()
        .to_owned();
    if release.is_empty() || release.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(InventoryError::new(format!("invalid {name} version")));
    }
    Ok(release)
}

fn hash_tool(tool: &Path, name: &str) -> Result<String, InventoryError> {
    let bytes = fs::read(tool).map_err(|error| {
        InventoryError::new(format!(
            "read resolved {name} executable {}: {error}",
            tool.display()
        ))
    })?;
    Ok(sha256(&bytes))
}

fn hash_line_list(values: &BTreeSet<String>) -> String {
    let mut bytes = Vec::new();
    for value in values {
        bytes.extend_from_slice(value.as_bytes());
        bytes.push(b'\n');
    }
    sha256(&bytes)
}

fn outcome_evidence(case_id: &str, outcome: TestOutcome) -> String {
    hash_json(&(case_id, outcome), "encode test outcome evidence")
        .expect("serializing strings and a fieldless enum cannot fail")
}

fn command_evidence(output: &Output) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&output.stdout);
    bytes.push(0);
    bytes.extend_from_slice(&output.stderr);
    sha256(&bytes)
}

fn hash_json(value: &impl Serialize, context: &str) -> Result<String, InventoryError> {
    serde_json::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| InventoryError::new(format!("{context}: {error}")))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cargo_test_lists_without_summary_lines() {
        let parsed = parse_test_list(
            "ast::parse::tests::alpha: test\n\
             ast::parse::tests::beta: test\n\n\
             2 tests, 0 benchmarks\n",
        )
        .unwrap();
        assert_eq!(
            parsed,
            [
                "ast::parse::tests::alpha".to_owned(),
                "ast::parse::tests::beta".to_owned(),
            ]
            .into_iter()
            .collect()
        );
    }

    #[test]
    fn parses_every_terminal_test_outcome() {
        let parsed = parse_test_results(
            "running 3 tests\n\
             test ast::parse::tests::alpha ... ok\n\
             test ast::parse::tests::beta ... FAILED\n\
             test ast::parse::tests::gamma ... ignored\n",
        )
        .unwrap();
        assert_eq!(parsed["ast::parse::tests::alpha"], TestOutcome::Ok);
        assert_eq!(parsed["ast::parse::tests::beta"], TestOutcome::Failed);
        assert_eq!(parsed["ast::parse::tests::gamma"], TestOutcome::Ignored);
    }

    #[test]
    fn nonzero_oracle_command_cannot_report_only_passes() {
        let observed = [
            ("ast::parse::tests::alpha".to_owned(), TestOutcome::Ok),
            ("ast::parse::tests::beta".to_owned(), TestOutcome::Ok),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            validate_oracle_command_status(false, &observed, 2),
            Err("harness.cargo-test-nonzero-exit".to_owned())
        );
    }

    #[test]
    fn parses_rustdoc_identity_with_an_empty_item_name() {
        assert_eq!(
            parse_doctest_id("src/lib.rs - (line 39)").unwrap(),
            ("src/lib.rs".to_owned(), 39)
        );
    }

    #[test]
    fn no_default_only_definition_remains_a_real_adapter_obligation() {
        let obligation = RegexSyntaxCorpusObligation {
            case_id: "tests::word_char_disabled_error".to_owned(),
            kind: RegexSyntaxCorpusCaseKind::Unit,
            source_path: "src/lib.rs".to_owned(),
            source_line: 1,
            source_sha256: "0".repeat(64),
            default_harness_member: false,
            no_default_harness_member: true,
        };
        assert_eq!(
            disposition_for(&obligation),
            RegexSyntaxCorpusDisposition::Unsupported {
                reason_code: "fre-adapter.unit-family-not-implemented".to_owned(),
            }
        );
    }

    #[test]
    fn holistic_candidate_pass_requires_the_fre_ast_adapter() {
        let case_id = "ast::parse::tests::parse_holistic";
        let obligation = RegexSyntaxCorpusObligation {
            case_id: case_id.to_owned(),
            kind: RegexSyntaxCorpusCaseKind::Unit,
            source_path: "src/ast/parse.rs".to_owned(),
            source_line: 1,
            source_sha256: "0".repeat(64),
            default_harness_member: true,
            no_default_harness_member: true,
        };
        let execution = Ok([(case_id.to_owned(), TestOutcome::Ok)]
            .into_iter()
            .collect());
        assert!(matches!(
            oracle_disposition_for(case_id, &execution),
            RegexSyntaxOracleDisposition::Pass { .. }
        ));
        let disposition = disposition_for(&obligation);
        assert_eq!(
            disposition,
            RegexSyntaxCorpusDisposition::Pass {
                evidence_sha256: ast_case_pass_evidence(AST_HOLISTIC_CASE_ID),
            }
        );
        let receipt = RegexSyntaxCorpusReceipt {
            obligation,
            disposition,
        };
        validate_disposition(&receipt).expect("exact FRE AST pass evidence");

        let mut corrupt = receipt;
        corrupt.disposition = RegexSyntaxCorpusDisposition::Pass {
            evidence_sha256: "0".repeat(64),
        };
        assert!(validate_disposition(&corrupt).is_err());
    }

    #[test]
    fn authenticated_ast_added_cases_execute_their_complete_outcome_sets() {
        for case_id in [
            AST_OCTAL_CASE_ID,
            AST_HEX_TWO_CASE_ID,
            AST_HEX_FOUR_CASE_ID,
            AST_HEX_EIGHT_CASE_ID,
            AST_PERL_CLASS_CASE_ID,
            AST_UNICODE_CLASS_CASE_ID,
            AST_UNSUPPORTED_BACKREFERENCE_CASE_ID,
            AST_UNSUPPORTED_LOOKAROUND_CASE_ID,
            AST_REGRESSION_454_CASE_ID,
            AST_REGRESSION_455_CASE_ID,
        ] {
            let disposition = execute_ast_case(case_id);
            assert_eq!(
                disposition,
                RegexSyntaxCorpusDisposition::Pass {
                    evidence_sha256: ast_case_pass_evidence(case_id),
                }
            );
            validate_disposition(&RegexSyntaxCorpusReceipt {
                obligation: RegexSyntaxCorpusObligation {
                    case_id: case_id.to_owned(),
                    kind: RegexSyntaxCorpusCaseKind::Unit,
                    source_path: "src/ast/parse.rs".to_owned(),
                    source_line: 1,
                    source_sha256: "0".repeat(64),
                    default_harness_member: true,
                    no_default_harness_member: true,
                },
                disposition,
            })
            .expect("supported AST regression receipt");
        }
    }

    #[test]
    fn class_escape_adapters_reject_success_and_error_semantic_drift() {
        let profile = RustProfile::regex_1_12_4();
        let pattern = r"\d";
        let expected = regex_syntax::ast::parse::Parser::new()
            .parse(pattern)
            .expect("Perl class probe parses");
        let mut observed = parse_rust_ast(ParseRequest::rust(
            pattern,
            CompatibilityProfile::RustText(profile.clone()),
        ))
        .expect("FRE Perl class probe parses");
        validate_ast_success(&observed, &expected, pattern, &profile, "unaltered")
            .expect("exact success semantics");
        observed.ast = Ast::empty(ast_span(0, 0));
        assert!(
            validate_ast_success(&observed, &expected, pattern, &profile, "mutated-ast").is_err()
        );

        let pattern = r"\p{";
        let expected = regex_syntax::ast::parse::Parser::new()
            .parse(pattern)
            .expect_err("unterminated Unicode class is rejected");
        let rust_profile = CompatibilityProfile::RustText(profile);
        let mut observed = parse_rust_ast(ParseRequest::rust(pattern, rust_profile.clone()))
            .expect_err("FRE rejects unterminated Unicode class");
        validate_ast_error(&observed, &expected, pattern, &rust_profile, "unaltered")
            .expect("exact error semantics");
        observed.message.push('!');
        assert!(
            validate_ast_error(
                &observed,
                &expected,
                pattern,
                &rust_profile,
                "mutated-error"
            )
            .is_err()
        );
    }

    #[test]
    fn hex_probe_inventories_and_evidence_are_fixed() {
        for (case_id, case, successes, errors, fixed_evidence) in [
            (
                AST_HEX_TWO_CASE_ID,
                AstHexCase::Two,
                256,
                3,
                AST_HEX_TWO_PASS_EVIDENCE_SHA256,
            ),
            (
                AST_HEX_FOUR_CASE_ID,
                AstHexCase::Four,
                63_488,
                6,
                AST_HEX_FOUR_PASS_EVIDENCE_SHA256,
            ),
            (
                AST_HEX_EIGHT_CASE_ID,
                AstHexCase::Eight,
                63_488,
                9,
                AST_HEX_EIGHT_PASS_EVIDENCE_SHA256,
            ),
        ] {
            assert_eq!(
                (0..case.success_limit()).filter_map(char::from_u32).count(),
                successes,
            );
            assert_eq!(case.error_probes().len(), errors);
            assert_eq!(ast_case_pass_evidence(case_id), fixed_evidence);
            assert_eq!(fixed_ast_hex_pass_evidence(case_id), Some(fixed_evidence));
        }
    }

    #[test]
    fn hex_adapter_rejects_ast_and_source_error_semantic_drift() {
        let pattern = r"\U00000041";
        let expected = Ast::literal(Literal {
            span: ast_span(0, pattern.len()),
            kind: LiteralKind::HexFixed(HexLiteralKind::UnicodeLong),
            c: 'A',
        });
        let record = execute_ast_assertion(pattern, &expected, "exact-long-hex")
            .expect("exact long-hex AST");
        for mutation in [
            Ast::literal(Literal {
                span: ast_span(0, pattern.len()),
                kind: LiteralKind::HexFixed(HexLiteralKind::UnicodeLong),
                c: 'B',
            }),
            Ast::literal(Literal {
                span: ast_span(0, pattern.len().saturating_sub(1)),
                kind: LiteralKind::HexFixed(HexLiteralKind::UnicodeLong),
                c: 'A',
            }),
            Ast::literal(Literal {
                span: ast_span(0, pattern.len()),
                kind: LiteralKind::HexFixed(HexLiteralKind::UnicodeShort),
                c: 'A',
            }),
        ] {
            assert_ne!(record.ast, mutation, "AST semantic drift must not qualify");
        }

        let probe = HEX_FOUR_ERROR_PROBES[5];
        let error = regex_syntax::ast::parse::Parser::new()
            .parse(probe.pattern)
            .expect_err("surrogate escape must be rejected");
        assert!(ast_hex_error_matches(&error, probe));

        let mut wrong_kind = probe;
        wrong_kind.kind = AstHexErrorKind::InvalidDigit;
        assert!(!ast_hex_error_matches(&error, wrong_kind));
        let mut wrong_span = probe;
        wrong_span.span_start = wrong_span.span_start.saturating_add(1);
        assert!(!ast_hex_error_matches(&error, wrong_span));
        let mut wrong_pattern = probe;
        wrong_pattern.pattern = r"\uD801";
        assert!(!ast_hex_error_matches(&error, wrong_pattern));
    }

    #[test]
    fn lookaround_adapter_rejects_error_semantic_drift() {
        let pattern = "(?<=a)";
        let expected_upstream = regex_syntax::ast::parse::Parser::new()
            .parse(pattern)
            .expect_err("look-around must be rejected");
        let profile = CompatibilityProfile::RustText(RustProfile::regex_1_12_4());
        let observed = parse_rust_ast(ParseRequest::rust(pattern, profile.clone()))
            .expect_err("FRE must reject look-around");
        validate_ast_error(
            &observed,
            &expected_upstream,
            pattern,
            &profile,
            "unaltered",
        )
        .expect("exact FRE error must match pinned upstream semantics");

        let mut mutations = Vec::new();
        let mut wrong_schema = observed.clone();
        wrong_schema.schema_version = wrong_schema.schema_version.saturating_add(1);
        mutations.push(wrong_schema);
        let mut wrong_category = observed.clone();
        wrong_category.category = ErrorCategory::InvalidConfiguration;
        mutations.push(wrong_category);
        let mut wrong_profile = observed.clone();
        wrong_profile.profile =
            Box::new(CompatibilityProfile::RustBytes(RustProfile::regex_1_12_4()));
        mutations.push(wrong_profile);
        let mut wrong_span = observed.clone();
        wrong_span.span = Some(SourceSpan { start: 0, end: 3 });
        mutations.push(wrong_span);
        let mut wrong_message = observed.clone();
        wrong_message.message.push('!');
        mutations.push(wrong_message);

        for mutation in mutations {
            assert!(
                validate_ast_error(&mutation, &expected_upstream, pattern, &profile, "mutated",)
                    .is_err(),
                "semantic drift must not qualify: {mutation:?}",
            );
        }
    }

    #[test]
    fn research_manifest_matches_fixed_contract() {
        let manifest: serde_json::Value = serde_json::from_str(include_str!(
            "../../../research/regex-syntax-0.8.11-package-corpus.json"
        ))
        .unwrap();
        assert_eq!(
            manifest["schema"],
            "fre.regex-syntax.package-corpus-inventory.v1"
        );
        assert_eq!(manifest["package"]["version"], UPSTREAM_VERSION);
        assert_eq!(manifest["package"]["revision"], UPSTREAM_REVISION);
        assert_eq!(
            manifest["package"]["tree_inventory_sha256"],
            PACKAGE_TREE_INVENTORY_SHA256
        );
        assert_eq!(
            manifest["inventory"]["unit_definitions"],
            REGEX_SYNTAX_UNIT_DEFINITIONS
        );
        assert_eq!(
            manifest["inventory"]["obligations"],
            REGEX_SYNTAX_CORPUS_OBLIGATIONS
        );
        assert_eq!(
            manifest["inventory"]["obligation_inventory_sha256"],
            OBLIGATION_INVENTORY_SHA256
        );
        assert_eq!(
            manifest["vertical_slice"]["upstream_oracle_tests"],
            REGEX_SYNTAX_AST_PARSE_TESTS
        );
    }
}
