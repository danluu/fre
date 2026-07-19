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
    AdmissionPolicy, AdmissionStatus, CanonicalPattern, CompatibilityProfile, ErrorCategory,
    ParseError, ParseRequest, RustAstOptions, RustAstRecord, RustProfile, SCHEMA_VERSION,
    SafetyEnvelope, SourceSpan, parse, parse_rust_ast, parse_rust_ast_with_options,
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
const AST_PRINT_PREFIX: &str = "ast::print::tests::";
const HIR_PRINT_PREFIX: &str = "hir::print::tests::";
const HIR_TRANSLATE_PREFIX: &str = "hir::translate::tests::";
const AST_PARSE_IDS_SHA256: &str =
    "4d31a1829c82e76a3387354c9923d36a7305553c4c057723e12bd3f6bbdd4a0e";
const AST_NEST_LIMIT_CASE_ID: &str = "ast::parse::tests::parse_nest_limit";
const AST_COMMENTS_CASE_ID: &str = "ast::parse::tests::parse_comments";
const AST_HOLISTIC_CASE_ID: &str = "ast::parse::tests::parse_holistic";
const AST_IGNORE_WHITESPACE_CASE_ID: &str = "ast::parse::tests::parse_ignore_whitespace";
const AST_NEWLINES_CASE_ID: &str = "ast::parse::tests::parse_newlines";
const AST_ALTERNATE_CASE_ID: &str = "ast::parse::tests::parse_alternate";
const AST_UNCOUNTED_REPETITION_CASE_ID: &str = "ast::parse::tests::parse_uncounted_repetition";
const AST_GROUP_CASE_ID: &str = "ast::parse::tests::parse_group";
const AST_CAPTURE_NAME_CASE_ID: &str = "ast::parse::tests::parse_capture_name";
const AST_FLAGS_CASE_ID: &str = "ast::parse::tests::parse_flags";
const AST_FLAG_CASE_ID: &str = "ast::parse::tests::parse_flag";
const AST_SET_CLASS_CASE_ID: &str = "ast::parse::tests::parse_set_class";
const AST_SET_CLASS_OPEN_CASE_ID: &str = "ast::parse::tests::parse_set_class_open";
const AST_MAYBE_ASCII_CLASS_CASE_ID: &str = "ast::parse::tests::maybe_parse_ascii_class";
const AST_COUNTED_REPETITION_CASE_ID: &str = "ast::parse::tests::parse_counted_repetition";
const AST_DECIMAL_CASE_ID: &str = "ast::parse::tests::parse_decimal";
const AST_PRIMITIVE_NON_ESCAPE_CASE_ID: &str = "ast::parse::tests::parse_primitive_non_escape";
const AST_ESCAPE_CASE_ID: &str = "ast::parse::tests::parse_escape";
const AST_HEX_BRACE_CASE_ID: &str = "ast::parse::tests::parse_hex_brace";
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
const AST_PRINT_LITERAL_CASE_ID: &str = "ast::print::tests::print_literal";
const AST_PRINT_DOT_CASE_ID: &str = "ast::print::tests::print_dot";
const AST_PRINT_CONCAT_CASE_ID: &str = "ast::print::tests::print_concat";
const AST_PRINT_ALTERNATION_CASE_ID: &str = "ast::print::tests::print_alternation";
const AST_PRINT_ASSERTION_CASE_ID: &str = "ast::print::tests::print_assertion";
const AST_PRINT_REPETITION_CASE_ID: &str = "ast::print::tests::print_repetition";
const AST_PRINT_FLAGS_CASE_ID: &str = "ast::print::tests::print_flags";
const AST_PRINT_GROUP_CASE_ID: &str = "ast::print::tests::print_group";
const AST_PRINT_CLASS_CASE_ID: &str = "ast::print::tests::print_class";
const HIR_PRINT_LITERAL_CASE_ID: &str = "hir::print::tests::print_literal";
const HIR_PRINT_CLASS_CASE_ID: &str = "hir::print::tests::print_class";
const HIR_PRINT_ANCHOR_CASE_ID: &str = "hir::print::tests::print_anchor";
const HIR_PRINT_WORD_BOUNDARY_CASE_ID: &str = "hir::print::tests::print_word_boundary";
const HIR_PRINT_REPETITION_CASE_ID: &str = "hir::print::tests::print_repetition";
const HIR_PRINT_GROUP_CASE_ID: &str = "hir::print::tests::print_group";
const HIR_PRINT_ALTERNATION_CASE_ID: &str = "hir::print::tests::print_alternation";
const HIR_PRINT_REGRESSION_REPETITION_CONCAT_CASE_ID: &str =
    "hir::print::tests::regression_repetition_concat";
const HIR_PRINT_REGRESSION_REPETITION_ALTERNATION_CASE_ID: &str =
    "hir::print::tests::regression_repetition_alternation";
const HIR_PRINT_REGRESSION_ALTERNATION_CONCAT_CASE_ID: &str =
    "hir::print::tests::regression_alternation_concat";
const HIR_TRANSLATE_EMPTY_CASE_ID: &str = "hir::translate::tests::empty";
const HIR_TRANSLATE_LITERAL_CASE_INSENSITIVE_CASE_ID: &str =
    "hir::translate::tests::literal_case_insensitive";
const HIR_TRANSLATE_ASSERTIONS_CASE_ID: &str = "hir::translate::tests::assertions";
const HIR_TRANSLATE_GROUP_CASE_ID: &str = "hir::translate::tests::group";
const HIR_TRANSLATE_LINE_ANCHORS_CASE_ID: &str = "hir::translate::tests::line_anchors";
const HIR_TRANSLATE_FLAGS_CASE_ID: &str = "hir::translate::tests::flags";
const HIR_TRANSLATE_ESCAPE_CASE_ID: &str = "hir::translate::tests::escape";
const HIR_TRANSLATE_REPETITION_CASE_ID: &str = "hir::translate::tests::repetition";
const HIR_TRANSLATE_CAT_ALT_CASE_ID: &str = "hir::translate::tests::cat_alt";
const HIR_TRANSLATE_CLASS_ASCII_MULTIPLE_CASE_ID: &str =
    "hir::translate::tests::class_ascii_multiple";
const HIR_TRANSLATE_IGNORE_WHITESPACE_CASE_ID: &str = "hir::translate::tests::ignore_whitespace";
const HIR_TRANSLATE_SMART_REPETITION_CASE_ID: &str = "hir::translate::tests::smart_repetition";
const HIR_TRANSLATE_SMART_CONCAT_CASE_ID: &str = "hir::translate::tests::smart_concat";
const HIR_TRANSLATE_SMART_ALTERNATION_CASE_ID: &str = "hir::translate::tests::smart_alternation";
const HIR_TRANSLATE_ANALYSIS_IS_UTF8_CASE_ID: &str = "hir::translate::tests::analysis_is_utf8";
const HIR_TRANSLATE_ANALYSIS_CAPTURES_LEN_CASE_ID: &str =
    "hir::translate::tests::analysis_captures_len";
const HIR_TRANSLATE_ANALYSIS_STATIC_CAPTURES_LEN_CASE_ID: &str =
    "hir::translate::tests::analysis_static_captures_len";
const HIR_TRANSLATE_ANALYSIS_IS_ALL_ASSERTIONS_CASE_ID: &str =
    "hir::translate::tests::analysis_is_all_assertions";
const HIR_TRANSLATE_ANALYSIS_LOOK_SET_PREFIX_ANY_CASE_ID: &str =
    "hir::translate::tests::analysis_look_set_prefix_any";
const HIR_TRANSLATE_ANALYSIS_IS_ANCHORED_CASE_ID: &str =
    "hir::translate::tests::analysis_is_anchored";
const HIR_TRANSLATE_ANALYSIS_IS_ANY_ANCHORED_CASE_ID: &str =
    "hir::translate::tests::analysis_is_any_anchored";
const HIR_TRANSLATE_ANALYSIS_CAN_EMPTY_CASE_ID: &str = "hir::translate::tests::analysis_can_empty";
const HIR_TRANSLATE_ANALYSIS_IS_LITERAL_CASE_ID: &str =
    "hir::translate::tests::analysis_is_literal";
const HIR_TRANSLATE_ANALYSIS_IS_ALTERNATION_LITERAL_CASE_ID: &str =
    "hir::translate::tests::analysis_is_alternation_literal";
const HIR_TRANSLATE_REGRESSION_ALT_EMPTY_CONCAT_CASE_ID: &str =
    "hir::translate::tests::regression_alt_empty_concat";
const HIR_TRANSLATE_REGRESSION_EMPTY_ALT_CASE_ID: &str =
    "hir::translate::tests::regression_empty_alt";
const HIR_TRANSLATE_REGRESSION_SINGLETON_ALT_CASE_ID: &str =
    "hir::translate::tests::regression_singleton_alt";
const INTRINSIC_UNOBSERVABLE_REASON_CODE: &str = "fre-adapter.intrinsic-unobservable";
#[cfg(test)]
const INTRINSIC_UNOBSERVABLE_IDS_SHA256: &str =
    "2ae7e12c554b73dfd74c13f7e20b859f0615f6a2d00523ce0e027e66eec7225d";
/// Exact upstream unit receipts whose asserted state cannot be produced or
/// observed through any current FRE public or hidden syntax adapter.
///
/// This registry is deliberately conservative. Publicly addressable work
/// remains in the normal unsupported backlog even when its adapter has not
/// been implemented yet.
const INTRINSIC_UNOBSERVABLE_CASES: [(&str, &str); 11] = [
    (
        AST_COMMENTS_CASE_ID,
        "private parse_with_comments comment side channel is absent from RustAstRecord",
    ),
    (
        AST_DECIMAL_CASE_ID,
        "private decimal helper result and pre-wrapper error are absent from public parsing",
    ),
    (
        AST_PRIMITIVE_NON_ESCAPE_CASE_ID,
        "private primitive cursor treats bare pipe as a literal before public alternation parsing",
    ),
    (
        AST_SET_CLASS_OPEN_CASE_ID,
        "private partial class and union pair plus cursor position are absent from public parsing",
    ),
    (
        AST_MAYBE_ASCII_CLASS_CASE_ID,
        "private optional ASCII-class probe and rewind state are absent from public parsing",
    ),
    (
        HIR_PRINT_REGRESSION_REPETITION_CONCAT_CASE_ID,
        "constructor-only repetition-over-concat HIR cannot be produced by FRE pattern parsing",
    ),
    (
        HIR_PRINT_REGRESSION_REPETITION_ALTERNATION_CASE_ID,
        "constructor-only repetition-over-alternation HIR cannot be produced by FRE pattern parsing",
    ),
    (
        HIR_PRINT_REGRESSION_ALTERNATION_CONCAT_CASE_ID,
        "constructor-only concat-over-alternation HIR cannot be produced by FRE pattern parsing",
    ),
    (
        HIR_TRANSLATE_REGRESSION_ALT_EMPTY_CONCAT_CASE_ID,
        "constructor-only empty concat AST child cannot be produced by FRE pattern parsing",
    ),
    (
        HIR_TRANSLATE_REGRESSION_EMPTY_ALT_CASE_ID,
        "constructor-only zero-branch alternation AST cannot be produced by FRE pattern parsing",
    ),
    (
        HIR_TRANSLATE_REGRESSION_SINGLETON_ALT_CASE_ID,
        "constructor-only singleton alternation AST cannot be produced by FRE pattern parsing",
    ),
];
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
const NEST_LIMIT_PROBES: [(&str, u32); 20] = [
    ("", 0),
    ("a", 0),
    ("a+", 0),
    ("a+", 1),
    ("(a)+", 1),
    ("a+*", 1),
    ("a+*", 2),
    ("ab", 0),
    ("ab", 1),
    ("abc", 1),
    ("a|b", 0),
    ("a|b", 1),
    ("a|b|c", 1),
    ("[a]", 0),
    ("[a]", 1),
    ("[ab]", 1),
    ("[ab[cd]]", 2),
    ("[ab[cd]]", 3),
    ("[a--b]", 1),
    ("[a--bc]", 2),
];
const IGNORE_WHITESPACE_PROBES: [&str; 8] = [
    "(?x)a b",
    "(?x)a b(?-x)a b",
    "a (?x:a )a ",
    "(?x)( ?P<foo> a )",
    "(?x)(  a )",
    "(?x)(  ?:  a )",
    r"(?x)\x { 53 }",
    r"(?x)\ ",
];
const NEWLINE_PROBES: [&str; 2] = [".\n.", "foobar\nbaz\nquux\n"];
const ALTERNATE_PROBES: [&str; 15] = [
    r"a|b",
    r"(a|b)",
    r"a|b|c",
    r"ax|by|cz",
    r"(ax|by|cz)",
    r"(ax|(by|(cz)))",
    r"|",
    r"||",
    r"a|",
    r"|a",
    r"(|)",
    r"(a|)",
    r"(|a)",
    r"a|b)",
    r"(a|b",
];
const UNCOUNTED_REPETITION_SUCCESS_PROBES: [&str; 10] = [
    r"a*", r"a+", r"a?", r"a??", r"a?", r"a?b", r"a??b", r"ab?", r"(ab)?", r"|a?",
];
const UNCOUNTED_REPETITION_ERROR_PROBES: [AstFixedErrorProbe; 10] = [
    AstFixedErrorProbe::new(r"*", false, AstFixedErrorKind::RepetitionMissing, 0, 0),
    AstFixedErrorProbe::new(r"(?i)*", false, AstFixedErrorKind::RepetitionMissing, 4, 4),
    AstFixedErrorProbe::new(r"(*)", false, AstFixedErrorKind::RepetitionMissing, 1, 1),
    AstFixedErrorProbe::new(r"(?:?)", false, AstFixedErrorKind::RepetitionMissing, 3, 3),
    AstFixedErrorProbe::new(r"+", false, AstFixedErrorKind::RepetitionMissing, 0, 0),
    AstFixedErrorProbe::new(r"?", false, AstFixedErrorKind::RepetitionMissing, 0, 0),
    AstFixedErrorProbe::new(r"(?)", false, AstFixedErrorKind::RepetitionMissing, 1, 1),
    AstFixedErrorProbe::new(r"|*", false, AstFixedErrorKind::RepetitionMissing, 1, 1),
    AstFixedErrorProbe::new(r"|+", false, AstFixedErrorKind::RepetitionMissing, 1, 1),
    AstFixedErrorProbe::new(r"|?", false, AstFixedErrorKind::RepetitionMissing, 1, 1),
];
const COUNTED_REPETITION_DEFAULT_PROBES: [&str; 25] = [
    r"a{5}",
    r"a{5,}",
    r"a{5,9}",
    r"a{5}?",
    r"ab{5}",
    r"ab{5}c",
    r"a{ 5 }",
    r"a{ 5 , 9 }",
    r"\b{5,9}",
    r"(?i){0}",
    r"(?m){1,1}",
    r"a{]}",
    r"a{1,]}",
    r"a{",
    r"a{}",
    r"a{a",
    r"a{9999999999}",
    r"a{9",
    r"a{9,a",
    r"a{9,9999999999}",
    r"a{9,",
    r"a{9,11",
    r"a{2,1}",
    r"{5}",
    r"|{5}",
];
const COUNTED_REPETITION_EMPTY_MIN_PATTERN: &str = r"a{,9}";
const COUNTED_REPETITION_IGNORE_WHITESPACE_PATTERN: &str = r"a{5,9} ?";
const GROUP_PROBES: [&str; 17] = [
    "(?i)", "(?iU)", "(?i-U)", "()", "(a)", "(())", "(?:a)", "(?i:a)", "(?i-U:a)", "(", "(?",
    "(?P", "(?P<", "(a", "(()", ")", "a)",
];
const CAPTURE_NAME_PROBES: [&str; 22] = [
    "(?<a>z)",
    "(?P<a>z)",
    "(?P<abc>z)",
    "(?P<a_1>z)",
    "(?P<a.1>z)",
    "(?P<a[1]>z)",
    "(?P<a¾>)",
    "(?P<名字>)",
    "(?P<",
    "(?P<>z)",
    "(?P<a",
    "(?P<ab",
    "(?P<0a",
    "(?P<~",
    "(?P<abc~",
    "(?P<a>y)(?P<a>z)",
    "(?P<5>)",
    "(?P<5a>)",
    "(?P<¾>)",
    "(?P<¾a>)",
    "(?P<☃>)",
    "(?P<a☃>)",
];
const FLAGS_CONTEXT_PROBES: [(&str, &str); 13] = [
    ("i:", "(?i:a)"),
    ("i)", "(?i)"),
    ("isU:", "(?isU:a)"),
    ("-isU:", "(?-isU:a)"),
    ("i-sU:", "(?i-sU:a)"),
    ("i-sR:", "(?i-sR:a)"),
    ("isU", "(?isU"),
    ("isUa:", "(?isUa:a)"),
    ("isUi:", "(?isUi:a)"),
    ("i-sU-i:", "(?i-sU-i:a)"),
    ("-)", "(?-)"),
    ("i-)", "(?i-)"),
    ("iU-)", "(?iU-)"),
];
const FLAG_CONTEXT_PROBES: [(&str, &str); 9] = [
    ("i", "(?i)"),
    ("m", "(?m)"),
    ("s", "(?s)"),
    ("U", "(?U)"),
    ("u", "(?u)"),
    ("R", "(?R)"),
    ("x", "(?x)"),
    ("a", "(?a)"),
    ("☃", "(?☃)"),
];
const SET_CLASS_DEFAULT_PROBES: [&str; 35] = [
    "[[:alnum:]]",
    "[[[:alnum:]]]",
    "[[:alnum:]&&[:lower:]]",
    "[[:alnum:]--[:lower:]]",
    "[[:alnum:]~~[:lower:]]",
    "[a]",
    r"[a\]]",
    r"[a\-z]",
    "[ab]",
    "[a-]",
    "[-a]",
    r"[\pL]",
    r"[\w]",
    r"[a\wz]",
    "[a-z]",
    "[a-cx-z]",
    r"[\w&&a-cx-z]",
    r"[a-cx-z&&\w]",
    "[a--b--c]",
    "[a~~b~~c]",
    r"[\^&&^]",
    r"[\&&&&]",
    "[&&&&]",
    "[☃-⛄]",
    "[]]",
    r"[]\[]",
    r"[\[]]",
    "[",
    "[[",
    "[[-]",
    "[[[:alnum:]",
    r"[\b]",
    r"[\w-a]",
    r"[a-\w]",
    "[z-a]",
];
const SET_CLASS_IGNORE_WHITESPACE_PROBES: [&str; 2] = ["[a ", "[a- "];
const PRINT_LITERAL_PROBES: [(&str, bool); 18] = [
    ("a", false),
    (r"\[", false),
    (r"\141", true),
    (r"\x61", false),
    (r"\x7F", false),
    (r"\u0061", false),
    (r"\U00000061", false),
    (r"\x{61}", false),
    (r"\x{7F}", false),
    (r"\u{61}", false),
    (r"\U{61}", false),
    (r"\a", false),
    (r"\f", false),
    (r"\t", false),
    (r"\n", false),
    (r"\r", false),
    (r"\v", false),
    (r"(?x)\ ", false),
];
const PRINT_DOT_PROBES: [&str; 1] = ["."];
const PRINT_CONCAT_PROBES: [&str; 3] = ["ab", "abcde", "a(bcd)ef"];
const PRINT_ALTERNATION_PROBES: [&str; 5] = [
    "a|b",
    "a|b|c|d|e",
    "|a|b|c|d|e",
    "|a|b|c|d|e|",
    "a(b|c|d)|e|f",
];
const PRINT_ASSERTION_PROBES: [&str; 6] = [r"^", r"$", r"\A", r"\z", r"\b", r"\B"];
const PRINT_REPETITION_PROBES: [&str; 12] = [
    "a?", "a??", "a*", "a*?", "a+", "a+?", "a{5}", "a{5}?", "a{5,}", "a{5,}?", "a{5,10}",
    "a{5,10}?",
];
const PRINT_FLAGS_PROBES: [&str; 5] = ["(?i)", "(?-i)", "(?s-i)", "(?-si)", "(?siUmux)"];
const PRINT_GROUP_PROBES: [&str; 4] = ["(?i:a)", "(?P<foo>a)", "(?<foo>a)", "(a)"];
const PRINT_CLASS_PROBES: [&str; 57] = [
    r"[abc]",
    r"[a-z]",
    r"[^a-z]",
    r"[a-z0-9]",
    r"[-a-z0-9]",
    r"[-a-z0-9]",
    r"[a-z0-9---]",
    r"[a-z&&m-n]",
    r"[[a-z&&m-n]]",
    r"[a-z--m-n]",
    r"[a-z~~m-n]",
    r"[a-z[0-9]]",
    r"[a-z[^0-9]]",
    r"\d",
    r"\D",
    r"\s",
    r"\S",
    r"\w",
    r"\W",
    r"[[:alnum:]]",
    r"[[:^alnum:]]",
    r"[[:alpha:]]",
    r"[[:^alpha:]]",
    r"[[:ascii:]]",
    r"[[:^ascii:]]",
    r"[[:blank:]]",
    r"[[:^blank:]]",
    r"[[:cntrl:]]",
    r"[[:^cntrl:]]",
    r"[[:digit:]]",
    r"[[:^digit:]]",
    r"[[:graph:]]",
    r"[[:^graph:]]",
    r"[[:lower:]]",
    r"[[:^lower:]]",
    r"[[:print:]]",
    r"[[:^print:]]",
    r"[[:punct:]]",
    r"[[:^punct:]]",
    r"[[:space:]]",
    r"[[:^space:]]",
    r"[[:upper:]]",
    r"[[:^upper:]]",
    r"[[:word:]]",
    r"[[:^word:]]",
    r"[[:xdigit:]]",
    r"[[:^xdigit:]]",
    r"\pL",
    r"\PL",
    r"\p{L}",
    r"\P{L}",
    r"\p{X=Y}",
    r"\P{X=Y}",
    r"\p{X:Y}",
    r"\P{X:Y}",
    r"\p{X!=Y}",
    r"\P{X!=Y}",
];
type HirPrintProbe = (&'static str, &'static str, bool);
const HIR_PRINT_LITERAL_PROBES: [HirPrintProbe; 5] = [
    ("a", "a", false),
    (r"\xff", "\u{FF}", false),
    (r"\xff", "\u{FF}", true),
    (r"(?-u)\xff", r"(?-u:\xFF)", true),
    ("☃", "☃", false),
];
const HIR_PRINT_CLASS_PROBES: [HirPrintProbe; 19] = [
    (r"[a]", "a", false),
    (r"[ab]", r"[ab]", false),
    (r"[a-z]", r"[a-z]", false),
    (r"[a-z--b-c--x-y]", r"[ad-wz]", false),
    (r"[^\x01-\u{10FFFF}]", "\u{0}", false),
    (r"[-]", r"\-", false),
    (r"[☃-⛄]", r"[☃-⛄]", false),
    (r"(?-u)[a]", "a", false),
    (r"(?-u)[ab]", r"(?-u:[ab])", false),
    (r"(?-u)[a-z]", r"(?-u:[a-z])", false),
    (r"(?-u)[a-\xFF]", r"(?-u:[a-\xFF])", true),
    (r"[\[]", r"\[", false),
    (r"[Z-_]", r"[Z-_]", false),
    (r"[Z-_--Z]", r"[\[-_]", false),
    (r"(?-u)[\[]", r"\[", true),
    (r"(?-u)[Z-_]", r"(?-u:[Z-_])", true),
    (r"(?-u)[Z-_--Z]", r"(?-u:[\[-_])", true),
    (r"\P{any}", r"[a&&b]", false),
    (r"(?-u)[^\x00-\xFF]", r"[a&&b]", true),
];
const HIR_PRINT_ANCHOR_PROBES: [HirPrintProbe; 4] = [
    (r"^", r"\A", false),
    (r"$", r"\z", false),
    (r"(?m)^", r"(?m:^)", false),
    (r"(?m)$", r"(?m:$)", false),
];
const HIR_PRINT_WORD_BOUNDARY_PROBES: [HirPrintProbe; 4] = [
    (r"\b", r"\b", false),
    (r"\B", r"\B", false),
    (r"(?-u)\b", r"(?-u:\b)", false),
    (r"(?-u)\B", r"(?-u:\B)", true),
];
const HIR_PRINT_REPETITION_PROBES: [HirPrintProbe; 25] = [
    ("a?", "a?", false),
    ("a??", "a??", false),
    ("(?U)a?", "a??", false),
    ("a*", "a*", false),
    ("a*?", "a*?", false),
    ("(?U)a*", "a*?", false),
    ("a+", "a+", false),
    ("a+?", "a+?", false),
    ("(?U)a+", "a+?", false),
    ("a{1}", "a", false),
    ("a{2}", "a{2}", false),
    ("a{1,}", "a+", false),
    ("a{1,5}", "a{1,5}", false),
    ("a{1}?", "a", false),
    ("a{2}?", "a{2}", false),
    ("a{1,}?", "a+?", false),
    ("a{1,5}?", "a{1,5}?", false),
    ("(?U)a{1}", "a", false),
    ("(?U)a{2}", "a{2}", false),
    ("(?U)a{1,}", "a+?", false),
    ("(?U)a{1,5}", "a{1,5}?", false),
    ("a{0}", "(?:)", false),
    ("(?:ab){0}", "(?:)", false),
    (r"\p{any}{0}", "(?:)", false),
    (r"\P{any}{0}", "(?:)", false),
];
const HIR_PRINT_GROUP_PROBES: [HirPrintProbe; 7] = [
    ("()", "((?:))", false),
    ("(?P<foo>)", "(?P<foo>(?:))", false),
    ("(?:)", "(?:)", false),
    ("(a)", "(a)", false),
    ("(?P<foo>a)", "(?P<foo>a)", false),
    ("(?:a)", "a", false),
    ("((((a))))", "((((a))))", false),
];
const HIR_PRINT_ALTERNATION_PROBES: [HirPrintProbe; 7] = [
    ("|", "(?:(?:)|(?:))", false),
    ("||", "(?:(?:)|(?:)|(?:))", false),
    ("a|b", "[ab]", false),
    ("ab|cd", "(?:(?:ab)|(?:cd))", false),
    ("a|b|c", "[a-c]", false),
    ("ab|cd|ef", "(?:(?:ab)|(?:cd)|(?:ef))", false),
    ("foo|bar|quux", "(?:(?:foo)|(?:bar)|(?:quux))", false),
];
type HirTranslateProbe = (&'static str, bool);
const HIR_TRANSLATE_EMPTY_PROBES: [HirTranslateProbe; 11] = [
    ("", false),
    ("(?i)", false),
    ("()", false),
    ("(?:)", false),
    ("(?P<wat>)", false),
    ("|", false),
    ("()|()", false),
    ("(|b)", false),
    ("(a|)", false),
    ("(a||c)", false),
    ("(||)", false),
];
const HIR_TRANSLATE_LITERAL_CASE_INSENSITIVE_PROBES: [HirTranslateProbe; 13] = [
    ("(?i)a", false),
    ("(?i:a)", false),
    ("a(?i)a(?-i)a", false),
    ("(?i)ab@c", false),
    ("(?i)β", false),
    ("(?i-u)a", false),
    ("(?-u)a(?i)a(?-i)a", false),
    ("(?i-u)ab@c", false),
    ("(?i-u)a", true),
    ("(?i-u)\x61", true),
    (r"(?i-u)\x61", true),
    (r"(?i-u)\xFF", true),
    ("(?i-u)β", false),
];
const HIR_TRANSLATE_ASSERTION_PROBES: [HirTranslateProbe; 12] = [
    ("^", false),
    ("$", false),
    (r"\A", false),
    (r"\z", false),
    ("(?m)^", false),
    ("(?m)$", false),
    (r"(?m)\A", false),
    (r"(?m)\z", false),
    (r"\b", false),
    (r"\B", false),
    (r"(?-u)\b", false),
    (r"(?-u)\B", false),
];
const HIR_TRANSLATE_GROUP_PROBES: [HirTranslateProbe; 15] = [
    ("(a)", false),
    ("(a)(b)", false),
    ("(a)|(b)", false),
    ("(?P<foo>)", false),
    ("(?P<foo>a)", false),
    ("(?P<foo>a)(?P<bar>b)", false),
    ("(?:)", false),
    ("(?:a)", false),
    ("(?:a)(b)", false),
    ("(a)(?:b)(c)", false),
    ("(a)(?P<foo>b)(c)", false),
    ("()", false),
    ("((?i))", false),
    ("((?x))", false),
    ("(((?x)))", false),
];
const HIR_TRANSLATE_LINE_ANCHOR_PROBES: [HirTranslateProbe; 16] = [
    ("^", false),
    ("$", false),
    (r"\A", false),
    (r"\z", false),
    (r"(?m)\A", false),
    (r"(?m)\z", false),
    ("(?m)^", false),
    ("(?m)$", false),
    (r"(?R)\A", false),
    (r"(?R)\z", false),
    ("(?R)^", false),
    ("(?R)$", false),
    (r"(?Rm)\A", false),
    (r"(?Rm)\z", false),
    ("(?Rm)^", false),
    ("(?Rm)$", false),
];
const HIR_TRANSLATE_FLAGS_PROBES: [HirTranslateProbe; 10] = [
    ("(?i:a)a", false),
    ("(?i-u:a)β", false),
    ("(?:(?i-u)a)b", false),
    ("((?i-u)a)b", false),
    ("(?i)(?-i:a)a", false),
    ("(?im)a^", false),
    ("(?im)a^(?i-m)a^", false),
    ("(?U)a*a*?(?-U)a*a*?", false),
    ("(?:a(?i)a)a", false),
    ("(?i)(?:a(?-i)a)a", false),
];
const HIR_TRANSLATE_ESCAPE_PROBES: [HirTranslateProbe; 1] =
    [(r"\\\.\+\*\?\(\)\|\[\]\{\}\^\$\#", false)];
const HIR_TRANSLATE_REPETITION_PROBES: [HirTranslateProbe; 15] = [
    ("a?", false),
    ("a*", false),
    ("a+", false),
    ("a??", false),
    ("a*?", false),
    ("a+?", false),
    ("a{1}", false),
    ("a{1,}", false),
    ("a{1,2}", false),
    ("a{1}?", false),
    ("a{1,}?", false),
    ("a{1,2}?", false),
    ("ab?", false),
    ("(ab)?", false),
    ("a|b?", false),
];
const HIR_TRANSLATE_CAT_ALT_PROBES: [HirTranslateProbe; 8] = [
    ("(^$)", false),
    ("^|$", false),
    (r"^|$|\b", false),
    (r"^$|$\b|\b\B", false),
    ("(^|$)", false),
    (r"(^|$|\b)", false),
    (r"(^$|$\b|\b\B)", false),
    (r"(^$|($\b|(\b\B)))", false),
];
const HIR_TRANSLATE_CLASS_ASCII_MULTIPLE_PROBES: [HirTranslateProbe; 2] = [
    ("[[:alnum:][:^ascii:]]", false),
    ("(?-u)[[:alnum:][:^ascii:]]", true),
];
const HIR_TRANSLATE_IGNORE_WHITESPACE_PROBES: [HirTranslateProbe; 9] = [
    (r"(?x)\12 3", false),
    (r"(?x)\x { 53 }", false),
    (
        r"(?x)\x # comment
{ # comment
    53 # comment
} #comment",
        false,
    ),
    (r"(?x)\x 53", false),
    (
        r"(?x)\x # comment
        53 # comment",
        false,
    ),
    (r"(?x)\x5 3", false),
    (
        r"(?x)\p # comment
{ # comment
    Separator # comment
} # comment",
        false,
    ),
    (
        r"(?x)a # comment
{ # comment
    5 # comment
    , # comment
    10 # comment
} # comment",
        false,
    ),
    (r"(?x)a\  # hi there", false),
];
const HIR_TRANSLATE_SMART_REPETITION_PROBES: [HirTranslateProbe; 3] =
    [(r"a{0}", false), (r"a{1}", false), (r"\B{32111}", false)];
const HIR_TRANSLATE_SMART_CONCAT_PROBES: [HirTranslateProbe; 7] = [
    ("", false),
    ("(?:)", false),
    ("abc", false),
    ("(?:foo)(?:bar)", false),
    ("quux(?:foo)(?:bar)baz", false),
    ("foo(?:bar^baz)quux", false),
    ("foo(?:ba(?:r^b)az)quux", false),
];
const HIR_TRANSLATE_SMART_ALTERNATION_PROBES: [HirTranslateProbe; 8] = [
    ("(?:foo)|(?:bar)", false),
    ("quux|(?:abc|def|xyz)|baz", false),
    ("quux|(?:abc|(?:def|mno)|xyz)|baz", false),
    ("a|b|c|d|e|f|x|y|z", false),
    ("[A-Z]foo|[A-Z]quux", false),
    ("[A-Z][A-Z]|[A-Z]quux", false),
    ("[A-Z][A-Z]|[A-Z][A-Z]quux", false),
    ("[A-Z]foo|[A-Z]foobar", false),
];
const HIR_TRANSLATE_ANALYSIS_IS_UTF8_PROBES: [HirTranslateProbe; 16] = [
    (r"a", true),
    (r"ab", true),
    (r"(?-u)a", true),
    (r"(?-u)ab", true),
    (r"\xFF", true),
    (r"\xFF\xFF", true),
    (r"[^a]", true),
    (r"[^a][^a]", true),
    (r"\b", true),
    (r"\B", true),
    (r"(?-u)\b", true),
    (r"(?-u)\B", true),
    (r"(?-u)\xFF", true),
    (r"(?-u)\xFF\xFF", true),
    (r"(?-u)[^a]", true),
    (r"(?-u)[^a][^a]", true),
];
const HIR_TRANSLATE_ANALYSIS_CAPTURES_LEN_PROBES: [HirTranslateProbe; 13] = [
    (r"a", false),
    (r"(?:a)", false),
    (r"(?i-u:a)", false),
    (r"(?i-u)a", false),
    (r"(a)", false),
    (r"(?P<foo>a)", false),
    (r"()", false),
    (r"()a", false),
    (r"(a)+", false),
    (r"(a)(b)", false),
    (r"(a)|(b)", false),
    (r"((a))", false),
    (r"([a&&b])", false),
];
const HIR_TRANSLATE_ANALYSIS_STATIC_CAPTURES_LEN_PROBES: [HirTranslateProbe; 27] = [
    (r"", false),
    (r"foo|bar", false),
    (r"(foo)|bar", false),
    (r"foo|(bar)", false),
    (r"(foo|bar)", false),
    (r"(a|b|c|d|e|f)", false),
    (r"(a)|(b)|(c)|(d)|(e)|(f)", false),
    (r"(a)(b)|(c)(d)|(e)(f)", false),
    (r"(a)(b)(c)(d)(e)(f)", false),
    (r"(a)(b)(extra)|(a)(b)()", false),
    (r"(a)(b)((?:extra)?)", false),
    (r"(a)(b)(extra)?", false),
    (r"(foo)|(bar)", false),
    (r"(foo)(bar)", false),
    (r"(foo)+(bar)", false),
    (r"(foo)*(bar)", false),
    (r"(foo)?{0}", false),
    (r"(foo)?{1}", false),
    (r"(foo){1}", false),
    (r"(foo){1,}", false),
    (r"(foo){1,}?", false),
    (r"(foo){1,}??", false),
    (r"(foo){0,}", false),
    (r"(foo)(?:bar)", false),
    (r"(foo(?:bar)+)(?:baz(boo))", false),
    (r"(?P<bar>foo)(?:bar)(bal|loon)", false),
    (r#"<(a)[^>]+href="([^"]+)"|<(img)[^>]+src="([^"]+)""#, false),
];
const HIR_TRANSLATE_ANALYSIS_IS_ALL_ASSERTIONS_PROBES: [HirTranslateProbe; 11] = [
    (r"\b", false),
    (r"\B", false),
    (r"^", false),
    (r"$", false),
    (r"\A", false),
    (r"\z", false),
    (r"$^\z\A\b\B", false),
    (r"$|^|\z|\A|\b|\B", false),
    (r"^$|$^", false),
    (r"((\b)+())*^", false),
    (r"^a", false),
];
const HIR_TRANSLATE_ANALYSIS_LOOK_SET_PREFIX_ANY_PROBES: [HirTranslateProbe; 1] =
    [(r"(?-u)(?i:(?:\b|_)win(?:32|64|dows)?(?:\b|_))", false)];
const HIR_TRANSLATE_ANALYSIS_IS_ANCHORED_PROBES: [HirTranslateProbe; 48] = [
    (r"^", false),
    (r"$", false),
    (r"^^", false),
    (r"$$", false),
    (r"^$", false),
    (r"^$", false),
    (r"^foo", false),
    (r"foo$", false),
    (r"^foo|^bar", false),
    (r"foo$|bar$", false),
    (r"^(foo|bar)", false),
    (r"(foo|bar)$", false),
    (r"^+", false),
    (r"$+", false),
    (r"^++", false),
    (r"$++", false),
    (r"(^)+", false),
    (r"($)+", false),
    (r"$^", false),
    (r"$^", false),
    (r"$^|^$", false),
    (r"$^|^$", false),
    (r"\b^", false),
    (r"$\b", false),
    (r"^(?m:^)", false),
    (r"(?m:$)$", false),
    (r"(?m:^)^", false),
    (r"$(?m:$)", false),
    (r"(?m)^", false),
    (r"(?m)$", false),
    (r"(?m:^$)|$^", false),
    (r"(?m:^$)|$^", false),
    (r"$^|(?m:^$)", false),
    (r"$^|(?m:^$)", false),
    (r"a^", false),
    (r"$a", false),
    (r"a^", false),
    (r"$a", false),
    (r"^foo|bar", false),
    (r"foo|bar$", false),
    (r"^*", false),
    (r"$*", false),
    (r"^*+", false),
    (r"$*+", false),
    (r"^+*", false),
    (r"$+*", false),
    (r"(^)*", false),
    (r"($)*", false),
];
const HIR_TRANSLATE_ANALYSIS_IS_ANY_ANCHORED_PROBES: [HirTranslateProbe; 8] = [
    (r"^", false),
    (r"$", false),
    (r"\A", false),
    (r"\z", false),
    (r"(?m)^", false),
    (r"(?m)$", false),
    (r"$", false),
    (r"^", false),
];
const HIR_TRANSLATE_ANALYSIS_CAN_EMPTY_PROBES: [HirTranslateProbe; 38] = [
    (r"", true),
    (r"()", true),
    (r"()*", true),
    (r"()+", true),
    (r"()?", true),
    (r"a*", true),
    (r"a?", true),
    (r"a{0}", true),
    (r"a{0,}", true),
    (r"a{0,1}", true),
    (r"a{0,10}", true),
    (r"\pL*", true),
    (r"a*|b", true),
    (r"b|a*", true),
    (r"a|", true),
    (r"|a", true),
    (r"a||b", true),
    (r"a*a?(abcd)*", true),
    (r"^", true),
    (r"$", true),
    (r"(?m)^", true),
    (r"(?m)$", true),
    (r"\A", true),
    (r"\z", true),
    (r"\B", true),
    (r"(?-u)\B", true),
    (r"\b", true),
    (r"(?-u)\b", true),
    (r"a+", true),
    (r"a{1}", true),
    (r"a{1,}", true),
    (r"a{1,2}", true),
    (r"a{1,10}", true),
    (r"b|a", true),
    (r"a*a+(abcd)*", true),
    (r"\P{any}", true),
    (r"[a--a]", true),
    (r"[a&&b]", true),
];
const HIR_TRANSLATE_ANALYSIS_IS_LITERAL_PROBES: [HirTranslateProbe; 16] = [
    (r"a", false),
    (r"ab", false),
    (r"abc", false),
    (r"(?m)abc", false),
    (r"(?:a)", false),
    (r"foo(?:a)", false),
    (r"(?:a)foo", false),
    (r"[a]", false),
    (r"", false),
    (r"^", false),
    (r"a|b", false),
    (r"(a)", false),
    (r"a+", false),
    (r"foo(a)", false),
    (r"(a)foo", false),
    (r"[ab]", false),
];
const HIR_TRANSLATE_ANALYSIS_IS_ALTERNATION_LITERAL_PROBES: [HirTranslateProbe; 27] = [
    (r"a", false),
    (r"ab", false),
    (r"abc", false),
    (r"(?m)abc", false),
    (r"foo|bar", false),
    (r"foo|bar|baz", false),
    (r"[a]", false),
    (r"(?:ab)|cd", false),
    (r"ab|(?:cd)", false),
    (r"", false),
    (r"^", false),
    (r"(a)", false),
    (r"a+", false),
    (r"foo(a)", false),
    (r"(a)foo", false),
    (r"[ab]", false),
    (r"[ab]|b", false),
    (r"a|[ab]", false),
    (r"(a)|b", false),
    (r"a|(b)", false),
    (r"a|b", false),
    (r"a|b|c", false),
    (r"[a]|b", false),
    (r"a|[b]", false),
    (r"(?:a)|b", false),
    (r"a|(?:b)", false),
    (r"(?:z|xx)@|xx", false),
];
const ESCAPE_SUCCESS_PROBES: [&str; 24] = [
    r"\|",
    r"\a",
    r"\f",
    r"\t",
    r"\n",
    r"\r",
    r"\v",
    r"\A",
    r"\z",
    r"\b",
    r"\b{start}",
    r"\b{end}",
    r"\b{start-half}",
    r"\b{end-half}",
    r"\<",
    r"\>",
    r"\B",
    r"\!",
    r"\@",
    r"\%",
    "\\\"",
    r"\'",
    r"\/",
    r"\ ",
];
const ESCAPE_ERROR_PROBES: [AstFixedErrorProbe; 9] = [
    AstFixedErrorProbe::new(r"\e", false, AstFixedErrorKind::EscapeUnrecognized, 0, 2),
    AstFixedErrorProbe::new(r"\y", false, AstFixedErrorKind::EscapeUnrecognized, 0, 2),
    AstFixedErrorProbe::new(
        r"\b{",
        false,
        AstFixedErrorKind::SpecialWordOrRepetitionUnexpectedEof,
        0,
        3,
    ),
    AstFixedErrorProbe::new(
        r"\b{ ",
        true,
        AstFixedErrorKind::SpecialWordOrRepetitionUnexpectedEof,
        0,
        4,
    ),
    AstFixedErrorProbe::new(
        r"\b{ ",
        false,
        AstFixedErrorKind::RepetitionCountUnclosed,
        2,
        4,
    ),
    AstFixedErrorProbe::new(
        r"\b{foo",
        false,
        AstFixedErrorKind::SpecialWordBoundaryUnclosed,
        2,
        6,
    ),
    AstFixedErrorProbe::new(
        r"\b{foo!}",
        false,
        AstFixedErrorKind::SpecialWordBoundaryUnclosed,
        2,
        6,
    ),
    AstFixedErrorProbe::new(
        r"\b{foo}",
        false,
        AstFixedErrorKind::SpecialWordBoundaryUnrecognized,
        3,
        6,
    ),
    AstFixedErrorProbe::new(r"\", false, AstFixedErrorKind::EscapeUnexpectedEof, 0, 1),
];
const HEX_BRACE_SUCCESS_PROBES: [&str; 5] = [
    r"\u{26c4}",
    r"\U{26c4}",
    r"\x{26c4}",
    r"\x{26C4}",
    r"\x{10fFfF}",
];
const HEX_BRACE_ERROR_PROBES: [AstFixedErrorProbe; 8] = [
    AstFixedErrorProbe::new(r"\x", false, AstFixedErrorKind::EscapeUnexpectedEof, 2, 2),
    AstFixedErrorProbe::new(r"\x{", false, AstFixedErrorKind::EscapeUnexpectedEof, 2, 3),
    AstFixedErrorProbe::new(
        r"\x{FF",
        false,
        AstFixedErrorKind::EscapeUnexpectedEof,
        2,
        5,
    ),
    AstFixedErrorProbe::new(r"\x{}", false, AstFixedErrorKind::EscapeHexEmpty, 2, 4),
    AstFixedErrorProbe::new(
        r"\x{FGF}",
        false,
        AstFixedErrorKind::EscapeHexInvalidDigit,
        4,
        5,
    ),
    AstFixedErrorProbe::new(
        r"\x{FFFFFF}",
        false,
        AstFixedErrorKind::EscapeHexInvalid,
        3,
        9,
    ),
    AstFixedErrorProbe::new(
        r"\x{D800}",
        false,
        AstFixedErrorKind::EscapeHexInvalid,
        3,
        7,
    ),
    AstFixedErrorProbe::new(
        r"\x{FFFFFFFFF}",
        false,
        AstFixedErrorKind::EscapeHexInvalid,
        3,
        12,
    ),
];
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
    "The FRE AST adapter executes exactly parse_alternate, parse_capture_name, parse_counted_repetition, parse_escape, parse_flag, parse_flags, parse_group, parse_hex_brace, parse_hex_two, parse_hex_four, parse_hex_eight, parse_holistic, parse_ignore_whitespace, parse_nest_limit, parse_newlines, parse_octal, parse_perl_class, parse_uncounted_repetition, parse_unicode_class, parse_unsupported_backreference, parse_unsupported_lookaround, and regressions 454/455; the other 5 AST parser identities remain explicit Unsupported dispositions.",
    "Eleven exact upstream unit receipts are statically classified intrinsic-unobservable because their asserted private cursor/side-channel or constructor-only AST/HIR state is absent from every current FRE public and hidden syntax adapter; all other unsupported unit receipts remain an addressable implementation backlog.",
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
    if intrinsic_unobservable_reason(&obligation.case_id).is_some() {
        return RegexSyntaxCorpusDisposition::Unsupported {
            reason_code: INTRINSIC_UNOBSERVABLE_REASON_CODE.to_owned(),
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
    if obligation.case_id.starts_with(AST_PRINT_PREFIX) {
        if is_supported_ast_print_case(&obligation.case_id) {
            return execute_ast_print_case(&obligation.case_id);
        }
        return RegexSyntaxCorpusDisposition::Unsupported {
            reason_code: "fre-adapter.ast-print-not-implemented".to_owned(),
        };
    }
    if obligation.case_id.starts_with(HIR_PRINT_PREFIX) {
        if is_supported_hir_print_case(&obligation.case_id) {
            return execute_hir_print_case(&obligation.case_id);
        }
        return RegexSyntaxCorpusDisposition::Unsupported {
            reason_code: "fre-adapter.hir-print-not-implemented".to_owned(),
        };
    }
    if obligation.case_id.starts_with(HIR_TRANSLATE_PREFIX) {
        if is_supported_hir_translate_case(&obligation.case_id) {
            return execute_hir_translate_case(&obligation.case_id);
        }
        return RegexSyntaxCorpusDisposition::Unsupported {
            reason_code: "fre-adapter.hir-translate-not-implemented".to_owned(),
        };
    }
    RegexSyntaxCorpusDisposition::Unsupported {
        reason_code: "fre-adapter.unit-family-not-implemented".to_owned(),
    }
}

fn intrinsic_unobservable_reason(case_id: &str) -> Option<&'static str> {
    INTRINSIC_UNOBSERVABLE_CASES
        .iter()
        .find_map(|(intrinsic_id, reason)| (*intrinsic_id == case_id).then_some(*reason))
}

#[derive(Debug)]
struct AstMismatch {
    expected: String,
    observed: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AstFixedErrorKind {
    RepetitionMissing,
    EscapeUnrecognized,
    SpecialWordOrRepetitionUnexpectedEof,
    RepetitionCountUnclosed,
    SpecialWordBoundaryUnclosed,
    SpecialWordBoundaryUnrecognized,
    EscapeUnexpectedEof,
    EscapeHexEmpty,
    EscapeHexInvalidDigit,
    EscapeHexInvalid,
}

impl AstFixedErrorKind {
    fn upstream(self) -> regex_syntax::ast::ErrorKind {
        match self {
            Self::RepetitionMissing => regex_syntax::ast::ErrorKind::RepetitionMissing,
            Self::EscapeUnrecognized => regex_syntax::ast::ErrorKind::EscapeUnrecognized,
            Self::SpecialWordOrRepetitionUnexpectedEof => {
                regex_syntax::ast::ErrorKind::SpecialWordOrRepetitionUnexpectedEof
            }
            Self::RepetitionCountUnclosed => regex_syntax::ast::ErrorKind::RepetitionCountUnclosed,
            Self::SpecialWordBoundaryUnclosed => {
                regex_syntax::ast::ErrorKind::SpecialWordBoundaryUnclosed
            }
            Self::SpecialWordBoundaryUnrecognized => {
                regex_syntax::ast::ErrorKind::SpecialWordBoundaryUnrecognized
            }
            Self::EscapeUnexpectedEof => regex_syntax::ast::ErrorKind::EscapeUnexpectedEof,
            Self::EscapeHexEmpty => regex_syntax::ast::ErrorKind::EscapeHexEmpty,
            Self::EscapeHexInvalidDigit => regex_syntax::ast::ErrorKind::EscapeHexInvalidDigit,
            Self::EscapeHexInvalid => regex_syntax::ast::ErrorKind::EscapeHexInvalid,
        }
    }

    fn evidence_label(self) -> &'static str {
        match self {
            Self::RepetitionMissing => "RepetitionMissing",
            Self::EscapeUnrecognized => "EscapeUnrecognized",
            Self::SpecialWordOrRepetitionUnexpectedEof => "SpecialWordOrRepetitionUnexpectedEof",
            Self::RepetitionCountUnclosed => "RepetitionCountUnclosed",
            Self::SpecialWordBoundaryUnclosed => "SpecialWordBoundaryUnclosed",
            Self::SpecialWordBoundaryUnrecognized => "SpecialWordBoundaryUnrecognized",
            Self::EscapeUnexpectedEof => "EscapeUnexpectedEof",
            Self::EscapeHexEmpty => "EscapeHexEmpty",
            Self::EscapeHexInvalidDigit => "EscapeHexInvalidDigit",
            Self::EscapeHexInvalid => "EscapeHexInvalid",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AstFixedErrorProbe {
    pattern: &'static str,
    ignore_whitespace: bool,
    kind: AstFixedErrorKind,
    span_start: usize,
    span_end: usize,
}

impl AstFixedErrorProbe {
    const fn new(
        pattern: &'static str,
        ignore_whitespace: bool,
        kind: AstFixedErrorKind,
        span_start: usize,
        span_end: usize,
    ) -> Self {
        Self {
            pattern,
            ignore_whitespace,
            kind,
            span_start,
            span_end,
        }
    }
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
        AST_NEST_LIMIT_CASE_ID
            | AST_HOLISTIC_CASE_ID
            | AST_IGNORE_WHITESPACE_CASE_ID
            | AST_NEWLINES_CASE_ID
            | AST_ALTERNATE_CASE_ID
            | AST_UNCOUNTED_REPETITION_CASE_ID
            | AST_COUNTED_REPETITION_CASE_ID
            | AST_GROUP_CASE_ID
            | AST_CAPTURE_NAME_CASE_ID
            | AST_FLAGS_CASE_ID
            | AST_FLAG_CASE_ID
            | AST_SET_CLASS_CASE_ID
            | AST_ESCAPE_CASE_ID
            | AST_HEX_BRACE_CASE_ID
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

fn is_supported_ast_print_case(case_id: &str) -> bool {
    matches!(
        case_id,
        AST_PRINT_LITERAL_CASE_ID
            | AST_PRINT_DOT_CASE_ID
            | AST_PRINT_CONCAT_CASE_ID
            | AST_PRINT_ALTERNATION_CASE_ID
            | AST_PRINT_ASSERTION_CASE_ID
            | AST_PRINT_REPETITION_CASE_ID
            | AST_PRINT_FLAGS_CASE_ID
            | AST_PRINT_GROUP_CASE_ID
            | AST_PRINT_CLASS_CASE_ID
    )
}

fn is_supported_hir_print_case(case_id: &str) -> bool {
    matches!(
        case_id,
        HIR_PRINT_LITERAL_CASE_ID
            | HIR_PRINT_CLASS_CASE_ID
            | HIR_PRINT_ANCHOR_CASE_ID
            | HIR_PRINT_WORD_BOUNDARY_CASE_ID
            | HIR_PRINT_REPETITION_CASE_ID
            | HIR_PRINT_GROUP_CASE_ID
            | HIR_PRINT_ALTERNATION_CASE_ID
    )
}

fn is_supported_hir_translate_case(case_id: &str) -> bool {
    matches!(
        case_id,
        HIR_TRANSLATE_EMPTY_CASE_ID
            | HIR_TRANSLATE_LITERAL_CASE_INSENSITIVE_CASE_ID
            | HIR_TRANSLATE_ASSERTIONS_CASE_ID
            | HIR_TRANSLATE_GROUP_CASE_ID
            | HIR_TRANSLATE_LINE_ANCHORS_CASE_ID
            | HIR_TRANSLATE_FLAGS_CASE_ID
            | HIR_TRANSLATE_ESCAPE_CASE_ID
            | HIR_TRANSLATE_REPETITION_CASE_ID
            | HIR_TRANSLATE_CAT_ALT_CASE_ID
            | HIR_TRANSLATE_CLASS_ASCII_MULTIPLE_CASE_ID
            | HIR_TRANSLATE_IGNORE_WHITESPACE_CASE_ID
            | HIR_TRANSLATE_SMART_REPETITION_CASE_ID
            | HIR_TRANSLATE_SMART_CONCAT_CASE_ID
            | HIR_TRANSLATE_SMART_ALTERNATION_CASE_ID
            | HIR_TRANSLATE_ANALYSIS_IS_UTF8_CASE_ID
            | HIR_TRANSLATE_ANALYSIS_CAPTURES_LEN_CASE_ID
            | HIR_TRANSLATE_ANALYSIS_STATIC_CAPTURES_LEN_CASE_ID
            | HIR_TRANSLATE_ANALYSIS_IS_ALL_ASSERTIONS_CASE_ID
            | HIR_TRANSLATE_ANALYSIS_LOOK_SET_PREFIX_ANY_CASE_ID
            | HIR_TRANSLATE_ANALYSIS_IS_ANCHORED_CASE_ID
            | HIR_TRANSLATE_ANALYSIS_IS_ANY_ANCHORED_CASE_ID
            | HIR_TRANSLATE_ANALYSIS_CAN_EMPTY_CASE_ID
            | HIR_TRANSLATE_ANALYSIS_IS_LITERAL_CASE_ID
            | HIR_TRANSLATE_ANALYSIS_IS_ALTERNATION_LITERAL_CASE_ID
    )
}

fn execute_ast_case(case_id: &str) -> RegexSyntaxCorpusDisposition {
    let execution = match case_id {
        AST_NEST_LIMIT_CASE_ID => catch_unwind(AssertUnwindSafe(run_ast_nest_limit)),
        AST_HOLISTIC_CASE_ID => catch_unwind(AssertUnwindSafe(run_ast_holistic)),
        AST_IGNORE_WHITESPACE_CASE_ID => catch_unwind(AssertUnwindSafe(run_ast_ignore_whitespace)),
        AST_NEWLINES_CASE_ID => catch_unwind(AssertUnwindSafe(run_ast_newlines)),
        AST_ALTERNATE_CASE_ID => catch_unwind(AssertUnwindSafe(run_ast_alternate)),
        AST_UNCOUNTED_REPETITION_CASE_ID => {
            catch_unwind(AssertUnwindSafe(run_ast_uncounted_repetition))
        }
        AST_COUNTED_REPETITION_CASE_ID => {
            catch_unwind(AssertUnwindSafe(run_ast_counted_repetition))
        }
        AST_GROUP_CASE_ID => catch_unwind(AssertUnwindSafe(run_ast_group)),
        AST_CAPTURE_NAME_CASE_ID => catch_unwind(AssertUnwindSafe(run_ast_capture_name)),
        AST_FLAGS_CASE_ID => catch_unwind(AssertUnwindSafe(run_ast_flags)),
        AST_FLAG_CASE_ID => catch_unwind(AssertUnwindSafe(run_ast_flag)),
        AST_SET_CLASS_CASE_ID => catch_unwind(AssertUnwindSafe(run_ast_set_class)),
        AST_ESCAPE_CASE_ID => catch_unwind(AssertUnwindSafe(run_ast_escape)),
        AST_HEX_BRACE_CASE_ID => catch_unwind(AssertUnwindSafe(run_ast_hex_brace)),
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

fn execute_ast_print_case(case_id: &str) -> RegexSyntaxCorpusDisposition {
    let execution = catch_unwind(AssertUnwindSafe(|| run_ast_print_case(case_id)));
    match execution {
        Ok(Ok(())) => RegexSyntaxCorpusDisposition::Pass {
            evidence_sha256: ast_print_pass_evidence(case_id),
        },
        Ok(Err(mismatch)) => RegexSyntaxCorpusDisposition::Mismatch {
            evidence_sha256: ast_print_mismatch_evidence(
                case_id,
                &mismatch.expected,
                &mismatch.observed,
            ),
            expected: mismatch.expected,
            observed: mismatch.observed,
        },
        Err(_) => RegexSyntaxCorpusDisposition::Fault {
            stage: "fre-ast-print-adapter".to_owned(),
            reason_code: "candidate.adapter-panicked".to_owned(),
        },
    }
}

fn execute_hir_print_case(case_id: &str) -> RegexSyntaxCorpusDisposition {
    let execution = catch_unwind(AssertUnwindSafe(|| run_hir_print_case(case_id)));
    match execution {
        Ok(Ok(())) => RegexSyntaxCorpusDisposition::Pass {
            evidence_sha256: hir_print_pass_evidence(case_id),
        },
        Ok(Err(mismatch)) => RegexSyntaxCorpusDisposition::Mismatch {
            evidence_sha256: hir_print_mismatch_evidence(
                case_id,
                &mismatch.expected,
                &mismatch.observed,
            ),
            expected: mismatch.expected,
            observed: mismatch.observed,
        },
        Err(_) => RegexSyntaxCorpusDisposition::Fault {
            stage: "fre-hir-print-adapter".to_owned(),
            reason_code: "candidate.adapter-panicked".to_owned(),
        },
    }
}

fn execute_hir_translate_case(case_id: &str) -> RegexSyntaxCorpusDisposition {
    let execution = catch_unwind(AssertUnwindSafe(|| run_hir_translate_case(case_id)));
    match execution {
        Ok(Ok(())) => RegexSyntaxCorpusDisposition::Pass {
            evidence_sha256: hir_translate_pass_evidence(case_id),
        },
        Ok(Err(mismatch)) => RegexSyntaxCorpusDisposition::Mismatch {
            evidence_sha256: hir_translate_mismatch_evidence(
                case_id,
                &mismatch.expected,
                &mismatch.observed,
            ),
            expected: mismatch.expected,
            observed: mismatch.observed,
        },
        Err(_) => RegexSyntaxCorpusDisposition::Fault {
            stage: "fre-hir-translate-adapter".to_owned(),
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

fn run_ast_nest_limit() -> Result<(), AstMismatch> {
    for (index, (pattern, nest_limit)) in NEST_LIMIT_PROBES.into_iter().enumerate() {
        let mut profile = RustProfile::regex_1_12_4();
        profile.options.nest_limit = nest_limit;
        execute_ast_profile_equivalence_probe(pattern, &profile, &format!("nest-limit-{index}"))?;
    }
    Ok(())
}

fn run_ast_ignore_whitespace() -> Result<(), AstMismatch> {
    run_ast_equivalence_set(&IGNORE_WHITESPACE_PROBES, "ignore-whitespace")
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

fn run_ast_newlines() -> Result<(), AstMismatch> {
    for (index, pattern) in NEWLINE_PROBES.into_iter().enumerate() {
        execute_ast_equivalence_probe(pattern, &format!("newlines-probe-{index}"))?;
    }
    Ok(())
}

fn run_ast_alternate() -> Result<(), AstMismatch> {
    for (index, pattern) in ALTERNATE_PROBES.into_iter().enumerate() {
        execute_ast_equivalence_probe(pattern, &format!("alternate-probe-{index}"))?;
    }
    Ok(())
}

fn run_ast_uncounted_repetition() -> Result<(), AstMismatch> {
    for (index, pattern) in UNCOUNTED_REPETITION_SUCCESS_PROBES.into_iter().enumerate() {
        execute_ast_equivalence_probe(pattern, &format!("uncounted-repetition-success-{index}"))?;
    }
    for (index, probe) in UNCOUNTED_REPETITION_ERROR_PROBES.into_iter().enumerate() {
        execute_ast_fixed_error_probe(probe, &format!("uncounted-repetition-error-{index}"))?;
    }
    Ok(())
}

fn run_ast_counted_repetition() -> Result<(), AstMismatch> {
    for (index, pattern) in COUNTED_REPETITION_DEFAULT_PROBES.into_iter().enumerate() {
        execute_ast_equivalence_probe(pattern, &format!("counted-repetition-default-{index}"))?;
    }

    let mut whitespace_profile = RustProfile::regex_1_12_4();
    whitespace_profile.options.ignore_whitespace = true;
    execute_ast_profile_equivalence_probe(
        COUNTED_REPETITION_IGNORE_WHITESPACE_PATTERN,
        &whitespace_profile,
        "counted-repetition-ignore-whitespace",
    )?;

    execute_ast_options_equivalence_probe(
        COUNTED_REPETITION_EMPTY_MIN_PATTERN,
        &RustProfile::regex_1_12_4(),
        RustAstOptions {
            empty_min_range: true,
        },
        "counted-repetition-empty-min-range",
    )
}

fn run_ast_group() -> Result<(), AstMismatch> {
    run_ast_equivalence_set(&GROUP_PROBES, "group")
}

fn run_ast_capture_name() -> Result<(), AstMismatch> {
    run_ast_equivalence_set(&CAPTURE_NAME_PROBES, "capture-name")
}

fn run_ast_flags() -> Result<(), AstMismatch> {
    run_ast_context_equivalence_set(&FLAGS_CONTEXT_PROBES, "flags")
}

fn run_ast_flag() -> Result<(), AstMismatch> {
    run_ast_context_equivalence_set(&FLAG_CONTEXT_PROBES, "flag")
}

fn run_ast_set_class() -> Result<(), AstMismatch> {
    run_ast_equivalence_set(&SET_CLASS_DEFAULT_PROBES, "set-class-default")?;
    let mut profile = RustProfile::regex_1_12_4();
    profile.options.ignore_whitespace = true;
    for (index, pattern) in SET_CLASS_IGNORE_WHITESPACE_PROBES.into_iter().enumerate() {
        execute_ast_profile_equivalence_probe(
            pattern,
            &profile,
            &format!("set-class-ignore-whitespace-{index}"),
        )?;
    }
    Ok(())
}

fn run_ast_print_case(case_id: &str) -> Result<(), AstMismatch> {
    match case_id {
        AST_PRINT_LITERAL_CASE_ID => {
            for (index, (pattern, octal)) in PRINT_LITERAL_PROBES.into_iter().enumerate() {
                execute_ast_print_probe(pattern, octal, &format!("print-literal-{index}"))?;
            }
            Ok(())
        }
        AST_PRINT_DOT_CASE_ID => run_ast_print_equivalence_set(&PRINT_DOT_PROBES, "print-dot"),
        AST_PRINT_CONCAT_CASE_ID => {
            run_ast_print_equivalence_set(&PRINT_CONCAT_PROBES, "print-concat")
        }
        AST_PRINT_ALTERNATION_CASE_ID => {
            run_ast_print_equivalence_set(&PRINT_ALTERNATION_PROBES, "print-alternation")
        }
        AST_PRINT_ASSERTION_CASE_ID => {
            run_ast_print_equivalence_set(&PRINT_ASSERTION_PROBES, "print-assertion")
        }
        AST_PRINT_REPETITION_CASE_ID => {
            run_ast_print_equivalence_set(&PRINT_REPETITION_PROBES, "print-repetition")
        }
        AST_PRINT_FLAGS_CASE_ID => {
            run_ast_print_equivalence_set(&PRINT_FLAGS_PROBES, "print-flags")
        }
        AST_PRINT_GROUP_CASE_ID => {
            run_ast_print_equivalence_set(&PRINT_GROUP_PROBES, "print-group")
        }
        AST_PRINT_CLASS_CASE_ID => {
            run_ast_print_equivalence_set(&PRINT_CLASS_PROBES, "print-class")
        }
        _ => unreachable!("caller checked supported AST print case"),
    }
}

fn run_ast_print_equivalence_set(probes: &[&str], label: &str) -> Result<(), AstMismatch> {
    for (index, pattern) in probes.iter().copied().enumerate() {
        execute_ast_print_probe(pattern, false, &format!("{label}-{index}"))?;
    }
    Ok(())
}

fn execute_ast_print_probe(pattern: &str, octal: bool, assertion: &str) -> Result<(), AstMismatch> {
    let mut rust_profile = RustProfile::regex_1_12_4();
    rust_profile.options.octal = octal;
    let compatibility = CompatibilityProfile::RustText(rust_profile.clone());
    let mut builder = regex_syntax::ast::parse::ParserBuilder::new();
    builder
        .nest_limit(rust_profile.options.nest_limit)
        .octal(octal)
        .ignore_whitespace(rust_profile.options.ignore_whitespace);
    let expected = builder
        .build()
        .parse(pattern)
        .map_err(|error| AstMismatch {
            expected: format!("{assertion}: authenticated upstream parse succeeds"),
            observed: format!("{assertion}: upstream parse error {error:?}"),
        })?;
    let record = parse_rust_ast(ParseRequest::rust(pattern, compatibility)).map_err(|error| {
        AstMismatch {
            expected: format!("{assertion}: FRE parse succeeds with exact upstream AST"),
            observed: format!("{assertion}: FRE parse error {error:?}"),
        }
    })?;
    validate_ast_success_with_options(
        &record,
        &expected,
        pattern,
        &rust_profile,
        RustAstOptions::default(),
        assertion,
    )?;
    let mut printed = String::new();
    regex_syntax::ast::print::Printer::new()
        .print(&record.ast, &mut printed)
        .map_err(|error| AstMismatch {
            expected: format!("{assertion}: printer succeeds with {pattern:?}"),
            observed: format!("{assertion}: printer error {error:?}"),
        })?;
    if printed == pattern {
        Ok(())
    } else {
        Err(AstMismatch {
            expected: format!("{assertion}: {pattern:?}"),
            observed: format!("{assertion}: {printed:?}"),
        })
    }
}

fn run_hir_print_case(case_id: &str) -> Result<(), AstMismatch> {
    let (probes, label) = hir_print_probes(case_id);
    for (index, (given, expected, bytes)) in probes.iter().copied().enumerate() {
        execute_hir_print_probe(given, expected, bytes, &format!("{label}-{index}"))?;
    }
    Ok(())
}

fn hir_print_probes(case_id: &str) -> (&'static [HirPrintProbe], &'static str) {
    match case_id {
        HIR_PRINT_LITERAL_CASE_ID => (&HIR_PRINT_LITERAL_PROBES[..], "hir-print-literal"),
        HIR_PRINT_CLASS_CASE_ID => (&HIR_PRINT_CLASS_PROBES[..], "hir-print-class"),
        HIR_PRINT_ANCHOR_CASE_ID => (&HIR_PRINT_ANCHOR_PROBES[..], "hir-print-anchor"),
        HIR_PRINT_WORD_BOUNDARY_CASE_ID => (
            &HIR_PRINT_WORD_BOUNDARY_PROBES[..],
            "hir-print-word-boundary",
        ),
        HIR_PRINT_REPETITION_CASE_ID => (&HIR_PRINT_REPETITION_PROBES[..], "hir-print-repetition"),
        HIR_PRINT_GROUP_CASE_ID => (&HIR_PRINT_GROUP_PROBES[..], "hir-print-group"),
        HIR_PRINT_ALTERNATION_CASE_ID => {
            (&HIR_PRINT_ALTERNATION_PROBES[..], "hir-print-alternation")
        }
        _ => unreachable!("caller checked supported HIR print case"),
    }
}

fn execute_hir_print_probe(
    given: &str,
    expected_print: &str,
    bytes: bool,
    assertion: &str,
) -> Result<(), AstMismatch> {
    let rust_profile = RustProfile::regex_1_12_4();
    let compatibility = if bytes {
        CompatibilityProfile::RustBytes(rust_profile.clone())
    } else {
        CompatibilityProfile::RustText(rust_profile.clone())
    };
    let mut builder = regex_syntax::ParserBuilder::new();
    builder
        .nest_limit(rust_profile.options.nest_limit)
        .octal(rust_profile.options.octal)
        .utf8(!bytes)
        .ignore_whitespace(rust_profile.options.ignore_whitespace)
        .case_insensitive(rust_profile.options.case_insensitive)
        .multi_line(rust_profile.options.multi_line)
        .dot_matches_new_line(rust_profile.options.dot_matches_new_line)
        .crlf(rust_profile.options.crlf)
        .line_terminator(rust_profile.options.line_terminator)
        .swap_greed(rust_profile.options.swap_greed)
        .unicode(rust_profile.options.unicode);
    let expected_hir = builder.build().parse(given).map_err(|error| AstMismatch {
        expected: format!("{assertion}: authenticated upstream HIR parse succeeds"),
        observed: format!("{assertion}: upstream HIR parse error {error:?}"),
    })?;
    let record =
        parse(ParseRequest::rust(given, compatibility.clone())).map_err(|error| AstMismatch {
            expected: format!("{assertion}: FRE HIR parse succeeds"),
            observed: format!("{assertion}: FRE HIR parse error {error:?}"),
        })?;
    let CanonicalPattern::Rust(parsed) = &record.pattern else {
        return Err(AstMismatch {
            expected: format!("{assertion}: FRE Rust canonical HIR"),
            observed: format!("{assertion}: {:?}", record.pattern),
        });
    };
    let identity_valid = record.key.schema_version == SCHEMA_VERSION
        && record.key.pattern.as_bytes() == given.as_bytes()
        && record.key.profile == compatibility
        && record.key.admission == AdmissionPolicy::default()
        && record.key.safety == SafetyEnvelope::default()
        && record.admission_status == AdmissionStatus::UpstreamOraclePending;
    if !identity_valid || parsed.hir != expected_hir {
        return Err(AstMismatch {
            expected: format!("{assertion}: exact FRE record and HIR {expected_hir:?}"),
            observed: format!("{assertion}: {record:?}"),
        });
    }
    let mut printed = String::new();
    regex_syntax::hir::print::Printer::new()
        .print(&parsed.hir, &mut printed)
        .map_err(|error| AstMismatch {
            expected: format!("{assertion}: HIR printer succeeds with {expected_print:?}"),
            observed: format!("{assertion}: HIR printer error {error:?}"),
        })?;
    if printed != expected_print {
        return Err(AstMismatch {
            expected: format!("{assertion}: {expected_print:?}"),
            observed: format!("{assertion}: {printed:?}"),
        });
    }
    builder
        .build()
        .parse(&printed)
        .map_err(|error| AstMismatch {
            expected: format!("{assertion}: printed HIR reparses"),
            observed: format!("{assertion}: reparse error {error:?}"),
        })?;
    Ok(())
}

fn run_hir_translate_case(case_id: &str) -> Result<(), AstMismatch> {
    let (probes, label) = hir_translate_probes(case_id);
    for (index, (pattern, bytes)) in probes.iter().copied().enumerate() {
        execute_hir_translate_probe(pattern, bytes, &format!("{label}-{index}"))?;
    }
    Ok(())
}

fn hir_translate_probes(case_id: &str) -> (&'static [HirTranslateProbe], &'static str) {
    match case_id {
        HIR_TRANSLATE_EMPTY_CASE_ID => (&HIR_TRANSLATE_EMPTY_PROBES, "hir-translate-empty"),
        HIR_TRANSLATE_LITERAL_CASE_INSENSITIVE_CASE_ID => (
            &HIR_TRANSLATE_LITERAL_CASE_INSENSITIVE_PROBES,
            "hir-translate-literal-case-insensitive",
        ),
        HIR_TRANSLATE_ASSERTIONS_CASE_ID => {
            (&HIR_TRANSLATE_ASSERTION_PROBES, "hir-translate-assertions")
        }
        HIR_TRANSLATE_GROUP_CASE_ID => (&HIR_TRANSLATE_GROUP_PROBES, "hir-translate-group"),
        HIR_TRANSLATE_LINE_ANCHORS_CASE_ID => (
            &HIR_TRANSLATE_LINE_ANCHOR_PROBES,
            "hir-translate-line-anchors",
        ),
        HIR_TRANSLATE_FLAGS_CASE_ID => (&HIR_TRANSLATE_FLAGS_PROBES, "hir-translate-flags"),
        HIR_TRANSLATE_ESCAPE_CASE_ID => (&HIR_TRANSLATE_ESCAPE_PROBES, "hir-translate-escape"),
        HIR_TRANSLATE_REPETITION_CASE_ID => {
            (&HIR_TRANSLATE_REPETITION_PROBES, "hir-translate-repetition")
        }
        HIR_TRANSLATE_CAT_ALT_CASE_ID => (&HIR_TRANSLATE_CAT_ALT_PROBES, "hir-translate-cat-alt"),
        HIR_TRANSLATE_CLASS_ASCII_MULTIPLE_CASE_ID => (
            &HIR_TRANSLATE_CLASS_ASCII_MULTIPLE_PROBES,
            "hir-translate-class-ascii-multiple",
        ),
        HIR_TRANSLATE_IGNORE_WHITESPACE_CASE_ID => (
            &HIR_TRANSLATE_IGNORE_WHITESPACE_PROBES,
            "hir-translate-ignore-whitespace",
        ),
        HIR_TRANSLATE_SMART_REPETITION_CASE_ID => (
            &HIR_TRANSLATE_SMART_REPETITION_PROBES,
            "hir-translate-smart-repetition",
        ),
        HIR_TRANSLATE_SMART_CONCAT_CASE_ID => (
            &HIR_TRANSLATE_SMART_CONCAT_PROBES,
            "hir-translate-smart-concat",
        ),
        HIR_TRANSLATE_SMART_ALTERNATION_CASE_ID => (
            &HIR_TRANSLATE_SMART_ALTERNATION_PROBES,
            "hir-translate-smart-alternation",
        ),
        HIR_TRANSLATE_ANALYSIS_IS_UTF8_CASE_ID => (
            &HIR_TRANSLATE_ANALYSIS_IS_UTF8_PROBES,
            "hir-translate-analysis-is-utf8",
        ),
        HIR_TRANSLATE_ANALYSIS_CAPTURES_LEN_CASE_ID => (
            &HIR_TRANSLATE_ANALYSIS_CAPTURES_LEN_PROBES,
            "hir-translate-analysis-captures-len",
        ),
        HIR_TRANSLATE_ANALYSIS_STATIC_CAPTURES_LEN_CASE_ID => (
            &HIR_TRANSLATE_ANALYSIS_STATIC_CAPTURES_LEN_PROBES,
            "hir-translate-analysis-static-captures-len",
        ),
        HIR_TRANSLATE_ANALYSIS_IS_ALL_ASSERTIONS_CASE_ID => (
            &HIR_TRANSLATE_ANALYSIS_IS_ALL_ASSERTIONS_PROBES,
            "hir-translate-analysis-is-all-assertions",
        ),
        HIR_TRANSLATE_ANALYSIS_LOOK_SET_PREFIX_ANY_CASE_ID => (
            &HIR_TRANSLATE_ANALYSIS_LOOK_SET_PREFIX_ANY_PROBES,
            "hir-translate-analysis-look-set-prefix-any",
        ),
        HIR_TRANSLATE_ANALYSIS_IS_ANCHORED_CASE_ID => (
            &HIR_TRANSLATE_ANALYSIS_IS_ANCHORED_PROBES,
            "hir-translate-analysis-is-anchored",
        ),
        HIR_TRANSLATE_ANALYSIS_IS_ANY_ANCHORED_CASE_ID => (
            &HIR_TRANSLATE_ANALYSIS_IS_ANY_ANCHORED_PROBES,
            "hir-translate-analysis-is-any-anchored",
        ),
        HIR_TRANSLATE_ANALYSIS_CAN_EMPTY_CASE_ID => (
            &HIR_TRANSLATE_ANALYSIS_CAN_EMPTY_PROBES,
            "hir-translate-analysis-can-empty",
        ),
        HIR_TRANSLATE_ANALYSIS_IS_LITERAL_CASE_ID => (
            &HIR_TRANSLATE_ANALYSIS_IS_LITERAL_PROBES,
            "hir-translate-analysis-is-literal",
        ),
        HIR_TRANSLATE_ANALYSIS_IS_ALTERNATION_LITERAL_CASE_ID => (
            &HIR_TRANSLATE_ANALYSIS_IS_ALTERNATION_LITERAL_PROBES,
            "hir-translate-analysis-is-alternation-literal",
        ),
        _ => unreachable!("caller checked supported HIR translate case"),
    }
}

fn execute_hir_translate_probe(
    pattern: &str,
    bytes: bool,
    assertion: &str,
) -> Result<(), AstMismatch> {
    let mut rust_profile = RustProfile::regex_1_12_4();
    rust_profile.options.octal = true;
    let compatibility = if bytes {
        CompatibilityProfile::RustBytes(rust_profile.clone())
    } else {
        CompatibilityProfile::RustText(rust_profile.clone())
    };
    let mut builder = regex_syntax::ParserBuilder::new();
    builder
        .nest_limit(rust_profile.options.nest_limit)
        .octal(true)
        .utf8(!bytes)
        .ignore_whitespace(rust_profile.options.ignore_whitespace)
        .case_insensitive(rust_profile.options.case_insensitive)
        .multi_line(rust_profile.options.multi_line)
        .dot_matches_new_line(rust_profile.options.dot_matches_new_line)
        .crlf(rust_profile.options.crlf)
        .line_terminator(rust_profile.options.line_terminator)
        .swap_greed(rust_profile.options.swap_greed)
        .unicode(rust_profile.options.unicode);
    let expected_hir = builder
        .build()
        .parse(pattern)
        .map_err(|error| AstMismatch {
            expected: format!("{assertion}: authenticated upstream HIR translation succeeds"),
            observed: format!("{assertion}: upstream HIR translation error {error:?}"),
        })?;
    let record =
        parse(ParseRequest::rust(pattern, compatibility.clone())).map_err(|error| AstMismatch {
            expected: format!("{assertion}: FRE HIR translation succeeds"),
            observed: format!("{assertion}: FRE HIR translation error {error:?}"),
        })?;
    let CanonicalPattern::Rust(parsed) = &record.pattern else {
        return Err(AstMismatch {
            expected: format!("{assertion}: FRE Rust canonical HIR"),
            observed: format!("{assertion}: {:?}", record.pattern),
        });
    };
    let identity_valid = record.key.schema_version == SCHEMA_VERSION
        && record.key.pattern.as_bytes() == pattern.as_bytes()
        && record.key.profile == compatibility
        && record.key.admission == AdmissionPolicy::default()
        && record.key.safety == SafetyEnvelope::default()
        && record.admission_status == AdmissionStatus::UpstreamOraclePending;
    let properties_match = parsed.hir.properties() == expected_hir.properties();
    if identity_valid && parsed.hir == expected_hir && properties_match {
        Ok(())
    } else {
        Err(AstMismatch {
            expected: format!("{assertion}: exact FRE record and HIR {expected_hir:?}"),
            observed: format!("{assertion}: {record:?}"),
        })
    }
}

fn run_ast_equivalence_set(probes: &[&str], label: &str) -> Result<(), AstMismatch> {
    for (index, pattern) in probes.iter().copied().enumerate() {
        execute_ast_equivalence_probe(pattern, &format!("{label}-probe-{index}"))?;
    }
    Ok(())
}

fn run_ast_context_equivalence_set(
    probes: &[(&str, &str)],
    label: &str,
) -> Result<(), AstMismatch> {
    for (index, (_, public_pattern)) in probes.iter().copied().enumerate() {
        execute_ast_equivalence_probe(public_pattern, &format!("{label}-context-{index}"))?;
    }
    Ok(())
}

fn run_ast_escape() -> Result<(), AstMismatch> {
    for (index, pattern) in ESCAPE_SUCCESS_PROBES.into_iter().enumerate() {
        execute_ast_equivalence_probe(pattern, &format!("escape-success-{index}"))?;
    }
    for (index, probe) in ESCAPE_ERROR_PROBES.into_iter().enumerate() {
        execute_ast_fixed_error_probe(probe, &format!("escape-error-{index}"))?;
    }
    Ok(())
}

fn run_ast_hex_brace() -> Result<(), AstMismatch> {
    for (index, pattern) in HEX_BRACE_SUCCESS_PROBES.into_iter().enumerate() {
        execute_ast_equivalence_probe(pattern, &format!("hex-brace-success-{index}"))?;
    }
    for (index, probe) in HEX_BRACE_ERROR_PROBES.into_iter().enumerate() {
        execute_ast_fixed_error_probe(probe, &format!("hex-brace-error-{index}"))?;
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
    execute_ast_profile_equivalence_probe(pattern, &RustProfile::regex_1_12_4(), assertion)
}

fn execute_ast_profile_equivalence_probe(
    pattern: &str,
    rust_profile: &RustProfile,
    assertion: &str,
) -> Result<(), AstMismatch> {
    execute_ast_options_equivalence_probe(
        pattern,
        rust_profile,
        RustAstOptions::default(),
        assertion,
    )
}

fn execute_ast_options_equivalence_probe(
    pattern: &str,
    rust_profile: &RustProfile,
    ast_options: RustAstOptions,
    assertion: &str,
) -> Result<(), AstMismatch> {
    let profile = CompatibilityProfile::RustText(rust_profile.clone());
    let mut builder = regex_syntax::ast::parse::ParserBuilder::new();
    builder
        .nest_limit(rust_profile.options.nest_limit)
        .octal(rust_profile.options.octal)
        .ignore_whitespace(rust_profile.options.ignore_whitespace)
        .empty_min_range(ast_options.empty_min_range);
    let expected = builder.build().parse(pattern);
    let observed =
        parse_rust_ast_with_options(ParseRequest::rust(pattern, profile.clone()), ast_options);
    match (expected, observed) {
        (Ok(expected_ast), Ok(record)) => validate_ast_success_with_options(
            &record,
            &expected_ast,
            pattern,
            rust_profile,
            ast_options,
            assertion,
        ),
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

fn execute_ast_fixed_error_probe(
    probe: AstFixedErrorProbe,
    assertion: &str,
) -> Result<(), AstMismatch> {
    let mut rust_profile = RustProfile::regex_1_12_4();
    rust_profile.options.ignore_whitespace = probe.ignore_whitespace;
    let profile = CompatibilityProfile::RustText(rust_profile);
    let mut builder = regex_syntax::ast::parse::ParserBuilder::new();
    builder.ignore_whitespace(probe.ignore_whitespace);
    let expected = match builder.build().parse(probe.pattern) {
        Err(error) => error,
        Ok(ast) => {
            return Err(AstMismatch {
                expected: format!(
                    "{assertion}: authenticated upstream Err({}, span={}..{})",
                    probe.kind.evidence_label(),
                    probe.span_start,
                    probe.span_end,
                ),
                observed: format!("{assertion}: authenticated upstream Ok({ast:?})"),
            });
        }
    };
    if !ast_fixed_error_matches(&expected, probe) {
        return Err(AstMismatch {
            expected: format!(
                "{assertion}: authenticated upstream Err({}, span={}..{}, pattern={:?})",
                probe.kind.evidence_label(),
                probe.span_start,
                probe.span_end,
                probe.pattern,
            ),
            observed: format!("{assertion}: authenticated upstream Err({expected:?})"),
        });
    }
    let observed = match parse_rust_ast(ParseRequest::rust(probe.pattern, profile.clone())) {
        Err(error) => error,
        Ok(record) => {
            return Err(AstMismatch {
                expected: format!("{assertion}: Err({expected:?})"),
                observed: format!("{assertion}: Ok({:?})", record.ast),
            });
        }
    };
    validate_ast_error(&observed, &expected, probe.pattern, &profile, assertion)
}

fn ast_fixed_error_matches(error: &regex_syntax::ast::Error, probe: AstFixedErrorProbe) -> bool {
    error.kind() == &probe.kind.upstream()
        && error.span() == &ast_span(probe.span_start, probe.span_end)
        && error.pattern() == probe.pattern
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

#[cfg(test)]
fn validate_ast_success(
    record: &RustAstRecord,
    expected: &Ast,
    pattern: &str,
    rust_profile: &RustProfile,
    assertion: &str,
) -> Result<(), AstMismatch> {
    validate_ast_success_with_options(
        record,
        expected,
        pattern,
        rust_profile,
        RustAstOptions::default(),
        assertion,
    )
}

fn validate_ast_success_with_options(
    record: &RustAstRecord,
    expected: &Ast,
    pattern: &str,
    rust_profile: &RustProfile,
    ast_options: RustAstOptions,
    assertion: &str,
) -> Result<(), AstMismatch> {
    if &record.ast != expected {
        return Err(AstMismatch {
            expected: format!("{assertion}: Ok({expected:?})"),
            observed: format!("{assertion}: Ok({:?})", record.ast),
        });
    }
    validate_ast_record_with_options(record, pattern, rust_profile, ast_options)
}

fn validate_ast_record(
    record: &RustAstRecord,
    pattern: &str,
    rust_profile: &RustProfile,
) -> Result<(), AstMismatch> {
    validate_ast_record_with_options(record, pattern, rust_profile, RustAstOptions::default())
}

fn validate_ast_record_with_options(
    record: &RustAstRecord,
    pattern: &str,
    rust_profile: &RustProfile,
    ast_options: RustAstOptions,
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
        && record.ast_options == ast_options
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
                "FRE AST record schema={SCHEMA_VERSION} pattern={pattern:?} ast-options={ast_options:?} nodes={nodes} nesting={nesting} stack={stack} work={work}"
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
        AST_NEST_LIMIT_CASE_ID | AST_IGNORE_WHITESPACE_CASE_ID | AST_NEWLINES_CASE_ID => {
            write_ast_frontend_profile_evidence(&mut contract, case_id);
        }
        AST_HOLISTIC_CASE_ID => contract.push_str(
            "assertion-1=verbatim-right-bracket-span-0-1\nassertion-1-reservation=nodes:2,nesting:2,stack:2,work:1024\nassertion-2=18-escaped-metacharacters-exact-spans-0-36\nassertion-2-reservation=nodes:37,nesting:37,stack:37,work:18944\n",
        ),
        AST_ALTERNATE_CASE_ID => write_ast_equivalence_evidence(
            &mut contract,
            &ALTERNATE_PROBES,
            "upstream-exact-result",
        ),
        AST_GROUP_CASE_ID | AST_CAPTURE_NAME_CASE_ID | AST_FLAGS_CASE_ID | AST_FLAG_CASE_ID => {
            write_ast_group_family_evidence(&mut contract, case_id);
        }
        AST_SET_CLASS_CASE_ID => write_ast_set_class_evidence(&mut contract),
        AST_UNCOUNTED_REPETITION_CASE_ID => write_ast_uncounted_repetition_evidence(&mut contract),
        AST_COUNTED_REPETITION_CASE_ID => write_ast_counted_repetition_evidence(&mut contract),
        AST_ESCAPE_CASE_ID => {
            write_ast_equivalence_evidence(
                &mut contract,
                &ESCAPE_SUCCESS_PROBES,
                "upstream-exact-success",
            );
            write_ast_fixed_error_evidence(&mut contract, &ESCAPE_ERROR_PROBES);
        }
        AST_HEX_BRACE_CASE_ID => {
            write_ast_equivalence_evidence(
                &mut contract,
                &HEX_BRACE_SUCCESS_PROBES,
                "upstream-exact-success",
            );
            write_ast_fixed_error_evidence(&mut contract, &HEX_BRACE_ERROR_PROBES);
        }
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
        AST_PERL_CLASS_CASE_ID => write_ast_equivalence_evidence(
            &mut contract,
            &PERL_CLASS_PROBES,
            "upstream-exact-success",
        ),
        AST_UNICODE_CLASS_CASE_ID => write_ast_equivalence_evidence(
            &mut contract,
            &UNICODE_CLASS_PROBES,
            "upstream-exact-result",
        ),
        AST_OCTAL_CASE_ID => write_ast_octal_evidence(&mut contract),
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

fn ast_print_pass_evidence(case_id: &str) -> String {
    let mut contract = format!(
        "fre.regex-syntax.ast-print-adapter.v1\ncase={case_id}\nparser=fre-syntax\nprinter=pinned-regex-syntax-0.8.11\n"
    );
    if case_id == AST_PRINT_LITERAL_CASE_ID {
        for (index, (pattern, octal)) in PRINT_LITERAL_PROBES.into_iter().enumerate() {
            write_ast_print_probe_evidence(&mut contract, index, pattern, octal);
        }
    } else {
        let probes = ast_print_default_probes(case_id);
        for (index, pattern) in probes.iter().copied().enumerate() {
            write_ast_print_probe_evidence(&mut contract, index, pattern, false);
        }
    }
    sha256(contract.as_bytes())
}

fn ast_print_default_probes(case_id: &str) -> &'static [&'static str] {
    match case_id {
        AST_PRINT_DOT_CASE_ID => &PRINT_DOT_PROBES,
        AST_PRINT_CONCAT_CASE_ID => &PRINT_CONCAT_PROBES,
        AST_PRINT_ALTERNATION_CASE_ID => &PRINT_ALTERNATION_PROBES,
        AST_PRINT_ASSERTION_CASE_ID => &PRINT_ASSERTION_PROBES,
        AST_PRINT_REPETITION_CASE_ID => &PRINT_REPETITION_PROBES,
        AST_PRINT_FLAGS_CASE_ID => &PRINT_FLAGS_PROBES,
        AST_PRINT_GROUP_CASE_ID => &PRINT_GROUP_PROBES,
        AST_PRINT_CLASS_CASE_ID => &PRINT_CLASS_PROBES,
        _ => unreachable!("caller selected a default-profile AST print case"),
    }
}

fn write_ast_print_probe_evidence(contract: &mut String, index: usize, pattern: &str, octal: bool) {
    writeln!(
        contract,
        "probe-{index}=sha256:{},bytes:{},octal:{octal},expected:exact-roundtrip",
        sha256(pattern.as_bytes()),
        pattern.len(),
    )
    .expect("writing to a String cannot fail");
}

fn hir_print_pass_evidence(case_id: &str) -> String {
    let mut contract = format!(
        "fre.regex-syntax.hir-print-adapter.v1\ncase={case_id}\nparser=fre-syntax\nprinter=pinned-regex-syntax-0.8.11\n"
    );
    let (probes, _) = hir_print_probes(case_id);
    for (index, (given, expected, bytes)) in probes.iter().copied().enumerate() {
        writeln!(
            contract,
            "probe-{index}=given-sha256:{},given-bytes:{},expected-sha256:{},expected-bytes:{},bytes-profile:{bytes},expected:exact-hir-and-print",
            sha256(given.as_bytes()),
            given.len(),
            sha256(expected.as_bytes()),
            expected.len(),
        )
        .expect("writing to a String cannot fail");
    }
    sha256(contract.as_bytes())
}

fn hir_translate_pass_evidence(case_id: &str) -> String {
    let mut contract = format!(
        "fre.regex-syntax.hir-translate-adapter.v1\ncase={case_id}\nparser=fre-syntax+pinned-regex-syntax-0.8.11\nast-octal=true\n"
    );
    let (probes, _) = hir_translate_probes(case_id);
    for (index, (pattern, bytes)) in probes.iter().copied().enumerate() {
        writeln!(
            contract,
            "probe-{index}=sha256:{},bytes:{},bytes-profile:{bytes},expected:exact-hir",
            sha256(pattern.as_bytes()),
            pattern.len(),
        )
        .expect("writing to a String cannot fail");
    }
    sha256(contract.as_bytes())
}

fn write_ast_equivalence_evidence(contract: &mut String, probes: &[&str], expected: &str) {
    for (index, pattern) in probes.iter().copied().enumerate() {
        writeln!(
            contract,
            "probe-{index}=sha256:{},bytes:{},expected:{expected}",
            sha256(pattern.as_bytes()),
            pattern.len(),
        )
        .expect("writing to a String cannot fail");
    }
}

fn write_ast_frontend_profile_evidence(contract: &mut String, case_id: &str) {
    match case_id {
        AST_NEST_LIMIT_CASE_ID => write_ast_nest_limit_evidence(contract),
        AST_IGNORE_WHITESPACE_CASE_ID => write_ast_equivalence_evidence(
            contract,
            &IGNORE_WHITESPACE_PROBES,
            "upstream-exact-success",
        ),
        AST_NEWLINES_CASE_ID => {
            write_ast_equivalence_evidence(contract, &NEWLINE_PROBES, "upstream-exact-success");
        }
        _ => unreachable!("caller selected a frontend-profile case"),
    }
}

fn write_ast_nest_limit_evidence(contract: &mut String) {
    for (index, (pattern, nest_limit)) in NEST_LIMIT_PROBES.into_iter().enumerate() {
        writeln!(
            contract,
            "probe-{index}=sha256:{},bytes:{},nest-limit:{nest_limit},expected:upstream-exact-result",
            sha256(pattern.as_bytes()),
            pattern.len(),
        )
        .expect("writing to a String cannot fail");
    }
}

fn write_ast_set_class_evidence(contract: &mut String) {
    write_ast_equivalence_evidence(contract, &SET_CLASS_DEFAULT_PROBES, "upstream-exact-result");
    for (index, pattern) in SET_CLASS_IGNORE_WHITESPACE_PROBES.into_iter().enumerate() {
        writeln!(
            contract,
            "ignore-whitespace-{index}=sha256:{},bytes:{},expected:upstream-exact-error",
            sha256(pattern.as_bytes()),
            pattern.len(),
        )
        .expect("writing to a String cannot fail");
    }
}

fn write_ast_uncounted_repetition_evidence(contract: &mut String) {
    write_ast_equivalence_evidence(
        contract,
        &UNCOUNTED_REPETITION_SUCCESS_PROBES,
        "upstream-exact-success",
    );
    write_ast_fixed_error_evidence(contract, &UNCOUNTED_REPETITION_ERROR_PROBES);
}

fn write_ast_counted_repetition_evidence(contract: &mut String) {
    write_ast_equivalence_evidence(
        contract,
        &COUNTED_REPETITION_DEFAULT_PROBES,
        "upstream-exact-result",
    );
    writeln!(
        contract,
        "empty-min-range=sha256:{},bytes:{},empty-min-range:true,expected:upstream-exact-success",
        sha256(COUNTED_REPETITION_EMPTY_MIN_PATTERN.as_bytes()),
        COUNTED_REPETITION_EMPTY_MIN_PATTERN.len(),
    )
    .expect("writing to a String cannot fail");
    writeln!(
        contract,
        "ignore-whitespace=sha256:{},bytes:{},ignore-whitespace:true,expected:upstream-exact-success",
        sha256(COUNTED_REPETITION_IGNORE_WHITESPACE_PATTERN.as_bytes()),
        COUNTED_REPETITION_IGNORE_WHITESPACE_PATTERN.len(),
    )
    .expect("writing to a String cannot fail");
}

fn write_ast_group_family_evidence(contract: &mut String, case_id: &str) {
    match case_id {
        AST_GROUP_CASE_ID => {
            write_ast_equivalence_evidence(contract, &GROUP_PROBES, "upstream-exact-result");
        }
        AST_CAPTURE_NAME_CASE_ID => {
            write_ast_equivalence_evidence(contract, &CAPTURE_NAME_PROBES, "upstream-exact-result");
        }
        AST_FLAGS_CASE_ID => {
            write_ast_context_evidence(contract, &FLAGS_CONTEXT_PROBES);
        }
        AST_FLAG_CASE_ID => {
            write_ast_context_evidence(contract, &FLAG_CONTEXT_PROBES);
        }
        _ => unreachable!("caller selected a group-family case"),
    }
}

fn write_ast_context_evidence(contract: &mut String, probes: &[(&str, &str)]) {
    for (index, (source_pattern, public_pattern)) in probes.iter().copied().enumerate() {
        writeln!(
            contract,
            "context-{index}=source-sha256:{},source-bytes:{},public-sha256:{},public-bytes:{},source-offset:2,expected:upstream-exact-result",
            sha256(source_pattern.as_bytes()),
            source_pattern.len(),
            sha256(public_pattern.as_bytes()),
            public_pattern.len(),
        )
        .expect("writing to a String cannot fail");
    }
}

fn write_ast_octal_evidence(contract: &mut String) {
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

fn write_ast_fixed_error_evidence(contract: &mut String, probes: &[AstFixedErrorProbe]) {
    for (index, probe) in probes.iter().copied().enumerate() {
        writeln!(
            contract,
            "error-probe-{index}=sha256:{},bytes:{},ignore-whitespace:{},expected:error:{},span:{}..{}",
            sha256(probe.pattern.as_bytes()),
            probe.pattern.len(),
            probe.ignore_whitespace,
            probe.kind.evidence_label(),
            probe.span_start,
            probe.span_end,
        )
        .expect("writing to a String cannot fail");
    }
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

fn ast_print_mismatch_evidence(case_id: &str, expected: &str, observed: &str) -> String {
    sha256(
        format!(
            "fre.regex-syntax.ast-print-adapter.mismatch.v1\ncase={case_id}\nexpected={expected}\nobserved={observed}\n"
        )
        .as_bytes(),
    )
}

fn hir_print_mismatch_evidence(case_id: &str, expected: &str, observed: &str) -> String {
    sha256(
        format!(
            "fre.regex-syntax.hir-print-adapter.mismatch.v1\ncase={case_id}\nexpected={expected}\nobserved={observed}\n"
        )
        .as_bytes(),
    )
}

fn hir_translate_mismatch_evidence(case_id: &str, expected: &str, observed: &str) -> String {
    sha256(
        format!(
            "fre.regex-syntax.hir-translate-adapter.mismatch.v1\ncase={case_id}\nexpected={expected}\nobserved={observed}\n"
        )
        .as_bytes(),
    )
}

fn is_supported_syntax_adapter_case(case_id: &str) -> bool {
    is_supported_ast_case(case_id)
        || is_supported_ast_print_case(case_id)
        || is_supported_hir_print_case(case_id)
        || is_supported_hir_translate_case(case_id)
}

fn syntax_case_pass_evidence(case_id: &str) -> String {
    if is_supported_ast_case(case_id) {
        ast_case_pass_evidence(case_id)
    } else if is_supported_ast_print_case(case_id) {
        ast_print_pass_evidence(case_id)
    } else if is_supported_hir_print_case(case_id) {
        hir_print_pass_evidence(case_id)
    } else {
        hir_translate_pass_evidence(case_id)
    }
}

fn syntax_case_mismatch_evidence(case_id: &str, expected: &str, observed: &str) -> String {
    if is_supported_ast_case(case_id) {
        ast_mismatch_evidence(case_id, expected, observed)
    } else if is_supported_ast_print_case(case_id) {
        ast_print_mismatch_evidence(case_id, expected, observed)
    } else if is_supported_hir_print_case(case_id) {
        hir_print_mismatch_evidence(case_id, expected, observed)
    } else {
        hir_translate_mismatch_evidence(case_id, expected, observed)
    }
}

fn syntax_case_fault_stage(case_id: &str) -> &'static str {
    if is_supported_ast_case(case_id) {
        "fre-ast-adapter"
    } else if is_supported_ast_print_case(case_id) {
        "fre-ast-print-adapter"
    } else if is_supported_hir_print_case(case_id) {
        "fre-hir-print-adapter"
    } else {
        "fre-hir-translate-adapter"
    }
}

fn valid_unsupported_unit_disposition(
    obligation: &RegexSyntaxCorpusObligation,
    reason_code: &str,
) -> bool {
    let case_id = obligation.case_id.as_str();
    if intrinsic_unobservable_reason(case_id).is_some() {
        return reason_code == INTRINSIC_UNOBSERVABLE_REASON_CODE;
    }
    if case_id.starts_with(AST_PARSE_PREFIX) {
        return !is_supported_ast_case(case_id)
            && obligation.default_harness_member
            && reason_code == "fre-adapter.ast-parse-not-implemented";
    }
    if case_id.starts_with(AST_PRINT_PREFIX) {
        return !is_supported_ast_print_case(case_id)
            && obligation.default_harness_member
            && reason_code == "fre-adapter.ast-print-not-implemented";
    }
    if case_id.starts_with(HIR_PRINT_PREFIX) {
        return !is_supported_hir_print_case(case_id)
            && obligation.default_harness_member
            && reason_code == "fre-adapter.hir-print-not-implemented";
    }
    if case_id.starts_with(HIR_TRANSLATE_PREFIX) {
        return !is_supported_hir_translate_case(case_id)
            && reason_code == "fre-adapter.hir-translate-not-implemented";
    }
    reason_code == "fre-adapter.unit-family-not-implemented"
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
        ) if is_supported_syntax_adapter_case(&obligation.case_id) => {
            obligation.default_harness_member
                && obligation.no_default_harness_member
                && evidence_sha256 == &syntax_case_pass_evidence(&obligation.case_id)
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
        ) if is_supported_syntax_adapter_case(&obligation.case_id) => {
            !expected.is_empty()
                && !observed.is_empty()
                && expected.len() <= 65_536
                && observed.len() <= 65_536
                && evidence_sha256
                    == &syntax_case_mismatch_evidence(&obligation.case_id, expected, observed)
        }
        (
            RegexSyntaxCorpusCaseKind::Unit,
            RegexSyntaxCorpusDisposition::Fault { stage, reason_code },
        ) if is_supported_syntax_adapter_case(&obligation.case_id) => {
            stage == syntax_case_fault_stage(&obligation.case_id)
                && reason_code == "candidate.adapter-panicked"
        }
        (
            RegexSyntaxCorpusCaseKind::Unit,
            RegexSyntaxCorpusDisposition::Unsupported { reason_code },
        ) => valid_unsupported_unit_disposition(obligation, reason_code),
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
            AST_NEST_LIMIT_CASE_ID,
            AST_NEWLINES_CASE_ID,
            AST_IGNORE_WHITESPACE_CASE_ID,
            AST_ALTERNATE_CASE_ID,
            AST_UNCOUNTED_REPETITION_CASE_ID,
            AST_COUNTED_REPETITION_CASE_ID,
            AST_GROUP_CASE_ID,
            AST_CAPTURE_NAME_CASE_ID,
            AST_FLAGS_CASE_ID,
            AST_FLAG_CASE_ID,
            AST_SET_CLASS_CASE_ID,
            AST_ESCAPE_CASE_ID,
            AST_HEX_BRACE_CASE_ID,
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
    fn authenticated_ast_print_cases_execute_all_111_public_roundtrips() {
        assert_eq!(PRINT_LITERAL_PROBES.len(), 18);
        assert_eq!(PRINT_DOT_PROBES.len(), 1);
        assert_eq!(PRINT_CONCAT_PROBES.len(), 3);
        assert_eq!(PRINT_ALTERNATION_PROBES.len(), 5);
        assert_eq!(PRINT_ASSERTION_PROBES.len(), 6);
        assert_eq!(PRINT_REPETITION_PROBES.len(), 12);
        assert_eq!(PRINT_FLAGS_PROBES.len(), 5);
        assert_eq!(PRINT_GROUP_PROBES.len(), 4);
        assert_eq!(PRINT_CLASS_PROBES.len(), 57);
        for case_id in [
            AST_PRINT_LITERAL_CASE_ID,
            AST_PRINT_DOT_CASE_ID,
            AST_PRINT_CONCAT_CASE_ID,
            AST_PRINT_ALTERNATION_CASE_ID,
            AST_PRINT_ASSERTION_CASE_ID,
            AST_PRINT_REPETITION_CASE_ID,
            AST_PRINT_FLAGS_CASE_ID,
            AST_PRINT_GROUP_CASE_ID,
            AST_PRINT_CLASS_CASE_ID,
        ] {
            let disposition = execute_ast_print_case(case_id);
            assert_eq!(
                disposition,
                RegexSyntaxCorpusDisposition::Pass {
                    evidence_sha256: ast_print_pass_evidence(case_id),
                }
            );
            validate_disposition(&RegexSyntaxCorpusReceipt {
                obligation: RegexSyntaxCorpusObligation {
                    case_id: case_id.to_owned(),
                    kind: RegexSyntaxCorpusCaseKind::Unit,
                    source_path: "src/ast/print.rs".to_owned(),
                    source_line: 1,
                    source_sha256: "0".repeat(64),
                    default_harness_member: true,
                    no_default_harness_member: true,
                },
                disposition,
            })
            .expect("supported AST print receipt");
        }
    }

    #[test]
    fn authenticated_hir_print_cases_execute_all_71_source_observable_outcomes() {
        assert_eq!(HIR_PRINT_LITERAL_PROBES.len(), 5);
        assert_eq!(HIR_PRINT_CLASS_PROBES.len(), 19);
        assert_eq!(HIR_PRINT_ANCHOR_PROBES.len(), 4);
        assert_eq!(HIR_PRINT_WORD_BOUNDARY_PROBES.len(), 4);
        assert_eq!(HIR_PRINT_REPETITION_PROBES.len(), 25);
        assert_eq!(HIR_PRINT_GROUP_PROBES.len(), 7);
        assert_eq!(HIR_PRINT_ALTERNATION_PROBES.len(), 7);
        for case_id in [
            HIR_PRINT_LITERAL_CASE_ID,
            HIR_PRINT_CLASS_CASE_ID,
            HIR_PRINT_ANCHOR_CASE_ID,
            HIR_PRINT_WORD_BOUNDARY_CASE_ID,
            HIR_PRINT_REPETITION_CASE_ID,
            HIR_PRINT_GROUP_CASE_ID,
            HIR_PRINT_ALTERNATION_CASE_ID,
        ] {
            let disposition = execute_hir_print_case(case_id);
            assert_eq!(
                disposition,
                RegexSyntaxCorpusDisposition::Pass {
                    evidence_sha256: hir_print_pass_evidence(case_id),
                }
            );
            validate_disposition(&RegexSyntaxCorpusReceipt {
                obligation: RegexSyntaxCorpusObligation {
                    case_id: case_id.to_owned(),
                    kind: RegexSyntaxCorpusCaseKind::Unit,
                    source_path: "src/hir/print.rs".to_owned(),
                    source_line: 1,
                    source_sha256: "0".repeat(64),
                    default_harness_member: true,
                    no_default_harness_member: true,
                },
                disposition,
            })
            .expect("supported HIR print receipt");
        }

        for intrinsic in [
            HIR_PRINT_REGRESSION_REPETITION_CONCAT_CASE_ID,
            HIR_PRINT_REGRESSION_REPETITION_ALTERNATION_CASE_ID,
            HIR_PRINT_REGRESSION_ALTERNATION_CONCAT_CASE_ID,
        ] {
            assert!(!is_supported_hir_print_case(intrinsic));
        }
    }

    #[test]
    fn authenticated_hir_translate_cases_execute_all_130_public_outcomes() {
        assert_eq!(HIR_TRANSLATE_EMPTY_PROBES.len(), 11);
        assert_eq!(HIR_TRANSLATE_LITERAL_CASE_INSENSITIVE_PROBES.len(), 13);
        assert_eq!(HIR_TRANSLATE_ASSERTION_PROBES.len(), 12);
        assert_eq!(HIR_TRANSLATE_GROUP_PROBES.len(), 15);
        assert_eq!(HIR_TRANSLATE_LINE_ANCHOR_PROBES.len(), 16);
        assert_eq!(HIR_TRANSLATE_FLAGS_PROBES.len(), 10);
        assert_eq!(HIR_TRANSLATE_ESCAPE_PROBES.len(), 1);
        assert_eq!(HIR_TRANSLATE_REPETITION_PROBES.len(), 15);
        assert_eq!(HIR_TRANSLATE_CAT_ALT_PROBES.len(), 8);
        assert_eq!(HIR_TRANSLATE_CLASS_ASCII_MULTIPLE_PROBES.len(), 2);
        assert_eq!(HIR_TRANSLATE_IGNORE_WHITESPACE_PROBES.len(), 9);
        assert_eq!(HIR_TRANSLATE_SMART_REPETITION_PROBES.len(), 3);
        assert_eq!(HIR_TRANSLATE_SMART_CONCAT_PROBES.len(), 7);
        assert_eq!(HIR_TRANSLATE_SMART_ALTERNATION_PROBES.len(), 8);
        assert_eq!(
            [
                HIR_TRANSLATE_EMPTY_PROBES.len(),
                HIR_TRANSLATE_LITERAL_CASE_INSENSITIVE_PROBES.len(),
                HIR_TRANSLATE_ASSERTION_PROBES.len(),
                HIR_TRANSLATE_GROUP_PROBES.len(),
                HIR_TRANSLATE_LINE_ANCHOR_PROBES.len(),
                HIR_TRANSLATE_FLAGS_PROBES.len(),
                HIR_TRANSLATE_ESCAPE_PROBES.len(),
                HIR_TRANSLATE_REPETITION_PROBES.len(),
                HIR_TRANSLATE_CAT_ALT_PROBES.len(),
                HIR_TRANSLATE_CLASS_ASCII_MULTIPLE_PROBES.len(),
                HIR_TRANSLATE_IGNORE_WHITESPACE_PROBES.len(),
                HIR_TRANSLATE_SMART_REPETITION_PROBES.len(),
                HIR_TRANSLATE_SMART_CONCAT_PROBES.len(),
                HIR_TRANSLATE_SMART_ALTERNATION_PROBES.len(),
            ]
            .into_iter()
            .sum::<usize>(),
            130,
        );
        for case_id in [
            HIR_TRANSLATE_EMPTY_CASE_ID,
            HIR_TRANSLATE_LITERAL_CASE_INSENSITIVE_CASE_ID,
            HIR_TRANSLATE_ASSERTIONS_CASE_ID,
            HIR_TRANSLATE_GROUP_CASE_ID,
            HIR_TRANSLATE_LINE_ANCHORS_CASE_ID,
            HIR_TRANSLATE_FLAGS_CASE_ID,
            HIR_TRANSLATE_ESCAPE_CASE_ID,
            HIR_TRANSLATE_REPETITION_CASE_ID,
            HIR_TRANSLATE_CAT_ALT_CASE_ID,
            HIR_TRANSLATE_CLASS_ASCII_MULTIPLE_CASE_ID,
            HIR_TRANSLATE_IGNORE_WHITESPACE_CASE_ID,
            HIR_TRANSLATE_SMART_REPETITION_CASE_ID,
            HIR_TRANSLATE_SMART_CONCAT_CASE_ID,
            HIR_TRANSLATE_SMART_ALTERNATION_CASE_ID,
        ] {
            let disposition = execute_hir_translate_case(case_id);
            assert_eq!(
                disposition,
                RegexSyntaxCorpusDisposition::Pass {
                    evidence_sha256: hir_translate_pass_evidence(case_id),
                },
            );
            validate_disposition(&RegexSyntaxCorpusReceipt {
                obligation: RegexSyntaxCorpusObligation {
                    case_id: case_id.to_owned(),
                    kind: RegexSyntaxCorpusCaseKind::Unit,
                    source_path: "src/hir/translate.rs".to_owned(),
                    source_line: 1,
                    source_sha256: "0".repeat(64),
                    default_harness_member: true,
                    no_default_harness_member: true,
                },
                disposition,
            })
            .expect("supported HIR translate receipt");
        }
    }

    #[test]
    fn authenticated_hir_property_cases_execute_all_205_public_outcomes() {
        let cases = [
            (
                HIR_TRANSLATE_ANALYSIS_IS_UTF8_CASE_ID,
                HIR_TRANSLATE_ANALYSIS_IS_UTF8_PROBES.len(),
            ),
            (
                HIR_TRANSLATE_ANALYSIS_CAPTURES_LEN_CASE_ID,
                HIR_TRANSLATE_ANALYSIS_CAPTURES_LEN_PROBES.len(),
            ),
            (
                HIR_TRANSLATE_ANALYSIS_STATIC_CAPTURES_LEN_CASE_ID,
                HIR_TRANSLATE_ANALYSIS_STATIC_CAPTURES_LEN_PROBES.len(),
            ),
            (
                HIR_TRANSLATE_ANALYSIS_IS_ALL_ASSERTIONS_CASE_ID,
                HIR_TRANSLATE_ANALYSIS_IS_ALL_ASSERTIONS_PROBES.len(),
            ),
            (
                HIR_TRANSLATE_ANALYSIS_LOOK_SET_PREFIX_ANY_CASE_ID,
                HIR_TRANSLATE_ANALYSIS_LOOK_SET_PREFIX_ANY_PROBES.len(),
            ),
            (
                HIR_TRANSLATE_ANALYSIS_IS_ANCHORED_CASE_ID,
                HIR_TRANSLATE_ANALYSIS_IS_ANCHORED_PROBES.len(),
            ),
            (
                HIR_TRANSLATE_ANALYSIS_IS_ANY_ANCHORED_CASE_ID,
                HIR_TRANSLATE_ANALYSIS_IS_ANY_ANCHORED_PROBES.len(),
            ),
            (
                HIR_TRANSLATE_ANALYSIS_CAN_EMPTY_CASE_ID,
                HIR_TRANSLATE_ANALYSIS_CAN_EMPTY_PROBES.len(),
            ),
            (
                HIR_TRANSLATE_ANALYSIS_IS_LITERAL_CASE_ID,
                HIR_TRANSLATE_ANALYSIS_IS_LITERAL_PROBES.len(),
            ),
            (
                HIR_TRANSLATE_ANALYSIS_IS_ALTERNATION_LITERAL_CASE_ID,
                HIR_TRANSLATE_ANALYSIS_IS_ALTERNATION_LITERAL_PROBES.len(),
            ),
        ];
        assert_eq!(
            cases.iter().map(|(_, outcomes)| outcomes).sum::<usize>(),
            205,
        );
        for (case_id, _) in cases {
            let disposition = execute_hir_translate_case(case_id);
            assert_eq!(
                disposition,
                RegexSyntaxCorpusDisposition::Pass {
                    evidence_sha256: hir_translate_pass_evidence(case_id),
                },
            );
            validate_disposition(&RegexSyntaxCorpusReceipt {
                obligation: RegexSyntaxCorpusObligation {
                    case_id: case_id.to_owned(),
                    kind: RegexSyntaxCorpusCaseKind::Unit,
                    source_path: "src/hir/translate.rs".to_owned(),
                    source_line: 1,
                    source_sha256: "0".repeat(64),
                    default_harness_member: true,
                    no_default_harness_member: true,
                },
                disposition,
            })
            .expect("supported HIR property receipt");
        }
    }

    #[test]
    fn intrinsic_unobservable_registry_is_exact_and_cannot_mask_addressable_work() {
        let registered: BTreeMap<_, _> = INTRINSIC_UNOBSERVABLE_CASES.into_iter().collect();
        assert_eq!(registered.len(), INTRINSIC_UNOBSERVABLE_CASES.len());
        let mut registered_ids = String::new();
        for case_id in registered.keys() {
            writeln!(registered_ids, "{case_id}").expect("writing to a String cannot fail");
        }
        assert_eq!(
            sha256(registered_ids.as_bytes()),
            INTRINSIC_UNOBSERVABLE_IDS_SHA256,
        );
        for (case_id, reason) in registered {
            assert!(!reason.is_empty());
            assert!(!is_supported_syntax_adapter_case(case_id));
            let source_path = if case_id.starts_with(AST_PARSE_PREFIX) {
                "src/ast/parse.rs"
            } else if case_id.starts_with(HIR_PRINT_PREFIX) {
                "src/hir/print.rs"
            } else {
                "src/hir/translate.rs"
            };
            let obligation = RegexSyntaxCorpusObligation {
                case_id: case_id.to_owned(),
                kind: RegexSyntaxCorpusCaseKind::Unit,
                source_path: source_path.to_owned(),
                source_line: 1,
                source_sha256: "0".repeat(64),
                default_harness_member: true,
                no_default_harness_member: true,
            };
            let disposition = disposition_for(&obligation);
            assert_eq!(
                disposition,
                RegexSyntaxCorpusDisposition::Unsupported {
                    reason_code: INTRINSIC_UNOBSERVABLE_REASON_CODE.to_owned(),
                },
            );
            validate_disposition(&RegexSyntaxCorpusReceipt {
                obligation,
                disposition,
            })
            .expect("exact intrinsic receipt must validate");
        }

        assert!(intrinsic_unobservable_reason("ast::tests::ast_size").is_none());
        assert!(intrinsic_unobservable_reason("hir::translate::tests::empty").is_none());
        assert!(intrinsic_unobservable_reason("utf8::tests::bmp").is_none());
    }

    #[test]
    fn parser_option_family_covers_public_outcomes_but_not_comment_side_channel() {
        assert_eq!(NEST_LIMIT_PROBES.len(), 20);
        assert_eq!(IGNORE_WHITESPACE_PROBES.len(), 8);
        run_ast_nest_limit().expect("all 20 pinned nest-limit outcomes match exactly");
        run_ast_ignore_whitespace().expect("all 8 pinned ignore-whitespace outcomes match exactly");

        let comments_pattern = "(?x)\n# This is comment 1.\nfoo # This is comment 2.\n  # This is comment 3.\nbar\n# This is comment 4.";
        let expected = regex_syntax::ast::parse::Parser::new()
            .parse_with_comments(comments_pattern)
            .expect("the pinned comment pattern parses with comments");
        let observed = parse_rust_ast(ParseRequest::rust(
            comments_pattern,
            CompatibilityProfile::RustText(RustProfile::regex_1_12_4()),
        ))
        .expect("FRE parses the AST portion of the comment pattern");
        assert_eq!(expected.ast, observed.ast);
        assert_eq!(expected.comments.len(), 4);
        assert!(!is_supported_ast_case(AST_COMMENTS_CASE_ID));
    }

    #[test]
    fn set_class_covers_every_public_outcome_and_private_helpers_stay_intrinsic() {
        assert_eq!(SET_CLASS_DEFAULT_PROBES.len(), 35);
        assert_eq!(SET_CLASS_IGNORE_WHITESPACE_PROBES.len(), 2);
        run_ast_set_class().expect("all 37 pinned class-set outcomes match exactly");

        let open_source = "[a]";
        let public_open = regex_syntax::ast::parse::Parser::new()
            .parse(open_source)
            .expect("the complete public class parses");
        let private_open_projection = Ast::class_bracketed(regex_syntax::ast::ClassBracketed {
            span: ast_span(0, 1),
            negated: false,
            kind: regex_syntax::ast::ClassSet::union(regex_syntax::ast::ClassSetUnion {
                span: ast_span(1, 1),
                items: vec![],
            }),
        });
        assert_ne!(public_open, private_open_projection);
        assert!(!is_supported_ast_case(AST_SET_CLASS_OPEN_CASE_ID));

        let ascii_source = "[:alnum:]";
        let public_ascii = regex_syntax::ast::parse::Parser::new()
            .parse(ascii_source)
            .expect("the unwrapped private ASCII-class source parses as literals");
        let wrapped_ascii = regex_syntax::ast::parse::Parser::new()
            .parse("[[:alnum:]]")
            .expect("the wrapped ASCII class parses");
        let private_ascii_span_projection =
            Ast::class_bracketed(regex_syntax::ast::ClassBracketed {
                span: ast_span(0, 11),
                negated: false,
                kind: regex_syntax::ast::ClassSet::Item(regex_syntax::ast::ClassSetItem::Ascii(
                    regex_syntax::ast::ClassAscii {
                        span: ast_span(0, 9),
                        kind: regex_syntax::ast::ClassAsciiKind::Alnum,
                        negated: false,
                    },
                )),
            });
        assert_ne!(public_ascii, wrapped_ascii);
        assert_ne!(wrapped_ascii, private_ascii_span_projection);
        assert!(!is_supported_ast_case(AST_MAYBE_ASCII_CLASS_CASE_ID));
    }

    #[test]
    fn group_family_covers_every_pinned_outcome_and_context_mapping() {
        assert_eq!(GROUP_PROBES.len(), 17);
        assert_eq!(CAPTURE_NAME_PROBES.len(), 22);
        assert_eq!(FLAGS_CONTEXT_PROBES.len(), 13);
        assert_eq!(FLAG_CONTEXT_PROBES.len(), 9);
        run_ast_group().expect("all 17 pinned group outcomes match exactly");
        run_ast_capture_name().expect("all 22 pinned capture-name outcomes match exactly");
        run_ast_flags().expect("all 13 pinned private flags outcomes match in public contexts");
        run_ast_flag().expect("all 9 pinned private flag outcomes match in public contexts");

        for (source_pattern, public_pattern) in FLAGS_CONTEXT_PROBES {
            let expected = if source_pattern.ends_with(':') {
                format!("(?{source_pattern}a)")
            } else {
                format!("(?{source_pattern}")
            };
            assert_eq!(public_pattern, expected);
        }
        for (source_pattern, public_pattern) in FLAG_CONTEXT_PROBES {
            assert_eq!(public_pattern, format!("(?{source_pattern})"));
        }

        let duplicate = regex_syntax::ast::parse::Parser::new()
            .parse("(?isUi:a)")
            .expect_err("duplicate flag is rejected in the public context");
        assert_eq!(duplicate.span(), &ast_span(5, 6));
        assert_eq!(
            duplicate.kind(),
            &regex_syntax::ast::ErrorKind::FlagDuplicate {
                original: ast_span(2, 3),
            }
        );
        let repeated_negation = regex_syntax::ast::parse::Parser::new()
            .parse("(?i-sU-i:a)")
            .expect_err("repeated flag negation is rejected in the public context");
        assert_eq!(repeated_negation.span(), &ast_span(6, 7));
        assert_eq!(
            repeated_negation.kind(),
            &regex_syntax::ast::ErrorKind::FlagRepeatedNegation {
                original: ast_span(3, 4),
            }
        );
        let unicode_flag = regex_syntax::ast::parse::Parser::new()
            .parse("(?☃)")
            .expect_err("a multibyte unknown flag is rejected");
        assert_eq!(
            unicode_flag.span(),
            &Span::new(Position::new(2, 1, 3), Position::new(5, 1, 4))
        );
        assert_eq!(
            unicode_flag.kind(),
            &regex_syntax::ast::ErrorKind::FlagUnrecognized
        );
    }

    #[test]
    fn group_family_rejects_ast_and_error_semantic_drift() {
        let success_pattern = CAPTURE_NAME_PROBES[7];
        let profile = RustProfile::regex_1_12_4();
        let expected = regex_syntax::ast::parse::Parser::new()
            .parse(success_pattern)
            .expect("Unicode capture name parses");
        let mut observed = parse_rust_ast(ParseRequest::rust(
            success_pattern,
            CompatibilityProfile::RustText(profile.clone()),
        ))
        .expect("FRE parses the Unicode capture name");
        validate_ast_success(&observed, &expected, success_pattern, &profile, "unaltered")
            .expect("exact Unicode capture AST and byte/column spans");
        observed.ast = Ast::empty(ast_span(0, 0));
        assert!(
            validate_ast_success(
                &observed,
                &expected,
                success_pattern,
                &profile,
                "mutated-ast",
            )
            .is_err()
        );

        let error_pattern = CAPTURE_NAME_PROBES[15];
        let expected = regex_syntax::ast::parse::Parser::new()
            .parse(error_pattern)
            .expect_err("duplicate capture name is rejected");
        let compatibility = CompatibilityProfile::RustText(profile);
        let mut observed = parse_rust_ast(ParseRequest::rust(error_pattern, compatibility.clone()))
            .expect_err("FRE rejects duplicate capture names");
        validate_ast_error(
            &observed,
            &expected,
            error_pattern,
            &compatibility,
            "unaltered",
        )
        .expect("exact duplicate-name error/original-span semantics");
        observed.message.push('!');
        assert!(
            validate_ast_error(
                &observed,
                &expected,
                error_pattern,
                &compatibility,
                "mutated-message",
            )
            .is_err()
        );
    }

    #[test]
    fn uncounted_repetition_covers_all_pinned_outcomes_and_rejects_drift() {
        assert_eq!(UNCOUNTED_REPETITION_SUCCESS_PROBES.len(), 10);
        assert_eq!(UNCOUNTED_REPETITION_ERROR_PROBES.len(), 10);
        run_ast_uncounted_repetition().expect("all 20 pinned uncounted outcomes match exactly");

        let pattern = UNCOUNTED_REPETITION_SUCCESS_PROBES[8];
        let profile = RustProfile::regex_1_12_4();
        let expected = regex_syntax::ast::parse::Parser::new()
            .parse(pattern)
            .expect("group repetition parses");
        let mut observed = parse_rust_ast(ParseRequest::rust(
            pattern,
            CompatibilityProfile::RustText(profile.clone()),
        ))
        .expect("FRE parses group repetition");
        validate_ast_success(&observed, &expected, pattern, &profile, "unaltered")
            .expect("exact nested repetition semantics");
        observed.ast = Ast::empty(ast_span(0, 0));
        assert!(
            validate_ast_success(&observed, &expected, pattern, &profile, "mutated-ast").is_err()
        );

        let probe = UNCOUNTED_REPETITION_ERROR_PROBES[3];
        let error = regex_syntax::ast::parse::Parser::new()
            .parse(probe.pattern)
            .expect_err("missing repetition operand is rejected");
        assert!(ast_fixed_error_matches(&error, probe));
        let mut wrong_span = probe;
        wrong_span.span_start = wrong_span.span_start.saturating_sub(1);
        assert!(!ast_fixed_error_matches(&error, wrong_span));
    }

    #[test]
    fn counted_repetition_covers_ast_only_option_and_decimal_stays_intrinsic() {
        assert_eq!(COUNTED_REPETITION_DEFAULT_PROBES.len(), 25);
        run_ast_counted_repetition().expect("all 27 pinned counted-repetition outcomes match");
        assert!(is_supported_ast_case(AST_COUNTED_REPETITION_CASE_ID));

        let pattern = COUNTED_REPETITION_EMPTY_MIN_PATTERN;
        let expected_with_option = regex_syntax::ast::parse::ParserBuilder::new()
            .empty_min_range(true)
            .build()
            .parse(pattern)
            .expect("pinned empty-min-range option accepts the counted repetition");
        let default_error = regex_syntax::ast::parse::Parser::new()
            .parse(pattern)
            .expect_err("the default profile rejects an empty lower bound");
        assert_eq!(
            default_error.kind(),
            &regex_syntax::ast::ErrorKind::RepetitionCountDecimalEmpty
        );
        let fre_error = parse_rust_ast(ParseRequest::rust(
            pattern,
            CompatibilityProfile::RustText(RustProfile::regex_1_12_4()),
        ))
        .expect_err("the FRE default AST profile also rejects an empty lower bound");
        validate_ast_error(
            &fre_error,
            &default_error,
            pattern,
            &CompatibilityProfile::RustText(RustProfile::regex_1_12_4()),
            "default-empty-min-range",
        )
        .expect("FRE exactly matches the representable default profile");
        let record = parse_rust_ast_with_options(
            ParseRequest::rust(
                pattern,
                CompatibilityProfile::RustText(RustProfile::regex_1_12_4()),
            ),
            RustAstOptions {
                empty_min_range: true,
            },
        )
        .expect("the explicit AST-only profile accepts an empty lower bound");
        assert_eq!(record.ast, expected_with_option);
        assert_eq!(
            record.ast_options,
            RustAstOptions {
                empty_min_range: true,
            }
        );
        assert!(matches!(
            record.ast,
            Ast::Repetition(ref repetition)
                if repetition.op.kind
                    == regex_syntax::ast::RepetitionKind::Range(
                        regex_syntax::ast::RepetitionRange::Bounded(0, 9)
                    )
        ));

        let mut drifted = record;
        drifted.ast_options = RustAstOptions::default();
        assert!(
            validate_ast_record_with_options(
                &drifted,
                pattern,
                &RustProfile::regex_1_12_4(),
                RustAstOptions {
                    empty_min_range: true,
                },
            )
            .is_err(),
            "AST-only option drift must invalidate the conformance record",
        );

        let decimal_context = "a{}";
        let contextual_error = regex_syntax::ast::parse::Parser::new()
            .parse(decimal_context)
            .expect_err("empty counted decimal is rejected");
        assert_eq!(
            contextual_error.kind(),
            &regex_syntax::ast::ErrorKind::RepetitionCountDecimalEmpty
        );
        assert_ne!(
            contextual_error.kind(),
            &regex_syntax::ast::ErrorKind::DecimalEmpty,
            "the public wrapper transforms the private parse_decimal error",
        );
        assert!(!is_supported_ast_case(AST_DECIMAL_CASE_ID));
    }

    #[test]
    fn escape_family_covers_all_pinned_outcomes_and_rejects_semantic_drift() {
        assert_eq!(ESCAPE_SUCCESS_PROBES.len(), 24);
        assert_eq!(ESCAPE_ERROR_PROBES.len(), 9);
        assert_eq!(HEX_BRACE_SUCCESS_PROBES.len(), 5);
        assert_eq!(HEX_BRACE_ERROR_PROBES.len(), 8);
        run_ast_escape().expect("all 33 pinned escape outcomes match exactly");
        run_ast_hex_brace().expect("all 13 pinned braced-hex outcomes match exactly");

        let success_pattern = HEX_BRACE_SUCCESS_PROBES[4];
        let profile = RustProfile::regex_1_12_4();
        let expected = regex_syntax::ast::parse::Parser::new()
            .parse(success_pattern)
            .expect("maximum scalar braced hex parses");
        let mut observed = parse_rust_ast(ParseRequest::rust(
            success_pattern,
            CompatibilityProfile::RustText(profile.clone()),
        ))
        .expect("FRE parses maximum scalar braced hex");
        validate_ast_success(&observed, &expected, success_pattern, &profile, "unaltered")
            .expect("exact braced-hex AST semantics");
        observed.ast = Ast::empty(ast_span(0, 0));
        assert!(
            validate_ast_success(
                &observed,
                &expected,
                success_pattern,
                &profile,
                "mutated-ast",
            )
            .is_err()
        );

        let probe = ESCAPE_ERROR_PROBES[3];
        let mut builder = regex_syntax::ast::parse::ParserBuilder::new();
        builder.ignore_whitespace(probe.ignore_whitespace);
        let error = builder
            .build()
            .parse(probe.pattern)
            .expect_err("ignore-whitespace boundary probe is rejected");
        assert!(ast_fixed_error_matches(&error, probe));
        let mut wrong_kind = probe;
        wrong_kind.kind = AstFixedErrorKind::EscapeUnexpectedEof;
        assert!(!ast_fixed_error_matches(&error, wrong_kind));
        let mut wrong_span = probe;
        wrong_span.span_end = wrong_span.span_end.saturating_sub(1);
        assert!(!ast_fixed_error_matches(&error, wrong_span));
        let mut wrong_pattern = probe;
        wrong_pattern.pattern = r"\b{";
        assert!(!ast_fixed_error_matches(&error, wrong_pattern));
    }

    #[test]
    fn primitive_vertical_bar_internal_outcome_is_not_falsely_admitted() {
        let pattern = "|";
        let internal_test_expected = Ast::literal(Literal {
            span: ast_span(0, 1),
            kind: LiteralKind::Verbatim,
            c: '|',
        });
        let upstream_public = regex_syntax::ast::parse::Parser::new()
            .parse(pattern)
            .expect("a bare alternation parses through the public surface");
        assert_ne!(upstream_public, internal_test_expected);
        let observed = parse_rust_ast(ParseRequest::rust(
            pattern,
            CompatibilityProfile::RustText(RustProfile::regex_1_12_4()),
        ))
        .expect("FRE delegates the public parser surface");
        assert_eq!(observed.ast, upstream_public);
        assert_ne!(observed.ast, internal_test_expected);
        assert!(!is_supported_ast_case(AST_PRIMITIVE_NON_ESCAPE_CASE_ID));
    }

    #[test]
    fn structural_composition_adapters_cover_exact_upstream_outcome_sets_and_reject_drift() {
        assert_eq!(NEWLINE_PROBES, [".\n.", "foobar\nbaz\nquux\n"]);
        assert_eq!(
            ALTERNATE_PROBES,
            [
                r"a|b",
                r"(a|b)",
                r"a|b|c",
                r"ax|by|cz",
                r"(ax|by|cz)",
                r"(ax|(by|(cz)))",
                r"|",
                r"||",
                r"a|",
                r"|a",
                r"(|)",
                r"(a|)",
                r"(|a)",
                r"a|b)",
                r"(a|b",
            ]
        );
        run_ast_newlines().expect("all pinned newline outcomes match exactly");
        run_ast_alternate().expect("all pinned alternation outcomes match exactly");

        let profile = RustProfile::regex_1_12_4();
        let pattern = NEWLINE_PROBES[0];
        let expected = regex_syntax::ast::parse::Parser::new()
            .parse(pattern)
            .expect("pinned newline probe parses");
        let mut observed = parse_rust_ast(ParseRequest::rust(
            pattern,
            CompatibilityProfile::RustText(profile.clone()),
        ))
        .expect("FRE newline probe parses");
        validate_ast_success(&observed, &expected, pattern, &profile, "unaltered")
            .expect("exact newline AST and position semantics");
        observed.ast = Ast::empty(ast_span(0, 0));
        assert!(
            validate_ast_success(&observed, &expected, pattern, &profile, "mutated-ast").is_err()
        );

        let pattern = ALTERNATE_PROBES[13];
        let expected = regex_syntax::ast::parse::Parser::new()
            .parse(pattern)
            .expect_err("pinned unmatched-closing-group probe is rejected");
        let compatibility = CompatibilityProfile::RustText(profile);
        let mut observed = parse_rust_ast(ParseRequest::rust(pattern, compatibility.clone()))
            .expect_err("FRE rejects the unmatched-closing-group probe");
        validate_ast_error(&observed, &expected, pattern, &compatibility, "unaltered")
            .expect("exact alternation error semantics");
        observed.span = Some(SourceSpan { start: 0, end: 1 });
        assert!(
            validate_ast_error(
                &observed,
                &expected,
                pattern,
                &compatibility,
                "mutated-span"
            )
            .is_err()
        );
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
