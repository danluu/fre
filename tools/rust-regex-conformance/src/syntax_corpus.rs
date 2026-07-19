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
const HIR_LITERAL_PREFIX: &str = "hir::literal::tests::";
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
const HIR_LITERAL_LITERAL_CASE_ID: &str = "hir::literal::tests::literal";
const HIR_LITERAL_CLASS_CASE_ID: &str = "hir::literal::tests::class";
const HIR_LITERAL_LOOK_CASE_ID: &str = "hir::literal::tests::look";
const HIR_LITERAL_REPETITION_CASE_ID: &str = "hir::literal::tests::repetition";
const HIR_LITERAL_CONCAT_CASE_ID: &str = "hir::literal::tests::concat";
const HIR_LITERAL_ALTERNATION_CASE_ID: &str = "hir::literal::tests::alternation";
const HIR_LITERAL_IMPOSSIBLE_CASE_ID: &str = "hir::literal::tests::impossible";
const HIR_LITERAL_ANYTHING_CASE_ID: &str = "hir::literal::tests::anything";
const HIR_LITERAL_ANYTHING_SMALL_LIMITS_CASE_ID: &str =
    "hir::literal::tests::anything_small_limits";
const HIR_LITERAL_EMPTY_CASE_ID: &str = "hir::literal::tests::empty";
const HIR_LITERAL_ODDS_AND_ENDS_CASE_ID: &str = "hir::literal::tests::odds_and_ends";
const HIR_LITERAL_HOLMES_CASE_ID: &str = "hir::literal::tests::holmes";
const HIR_LITERAL_HOLMES_ALT_CASE_ID: &str = "hir::literal::tests::holmes_alt";
const HIR_CLASS_CASE_FOLD_UNICODE_CASE_ID: &str = "hir::tests::class_case_fold_unicode";
const HIR_CLASS_CASE_FOLD_BYTES_CASE_ID: &str = "hir::tests::class_case_fold_bytes";
const HIR_CLASS_NEGATE_UNICODE_CASE_ID: &str = "hir::tests::class_negate_unicode";
const HIR_CLASS_NEGATE_BYTES_CASE_ID: &str = "hir::tests::class_negate_bytes";
const HIR_CLASS_UNION_UNICODE_CASE_ID: &str = "hir::tests::class_union_unicode";
const HIR_CLASS_UNION_BYTES_CASE_ID: &str = "hir::tests::class_union_bytes";
const HIR_CLASS_INTERSECT_UNICODE_CASE_ID: &str = "hir::tests::class_intersect_unicode";
const HIR_CLASS_INTERSECT_BYTES_CASE_ID: &str = "hir::tests::class_intersect_bytes";
const HIR_CLASS_DIFFERENCE_UNICODE_CASE_ID: &str = "hir::tests::class_difference_unicode";
const HIR_CLASS_DIFFERENCE_BYTES_CASE_ID: &str = "hir::tests::class_difference_bytes";
const HIR_CLASS_SYMMETRIC_DIFFERENCE_UNICODE_CASE_ID: &str =
    "hir::tests::class_symmetric_difference_unicode";
const HIR_CLASS_SYMMETRIC_DIFFERENCE_BYTES_CASE_ID: &str =
    "hir::tests::class_symmetric_difference_bytes";
const HIR_CLASS_CANONICALIZE_UNICODE_CASE_ID: &str = "hir::tests::class_canonicalize_unicode";
const HIR_CLASS_CANONICALIZE_BYTES_CASE_ID: &str = "hir::tests::class_canonicalize_bytes";
const HIR_CLASS_RANGE_CANONICAL_UNICODE_CASE_ID: &str = "hir::tests::class_range_canonical_unicode";
const HIR_CLASS_RANGE_CANONICAL_BYTES_CASE_ID: &str = "hir::tests::class_range_canonical_bytes";
const HIR_LOOK_SET_ITER_CASE_ID: &str = "hir::tests::look_set_iter";
const HIR_LOOK_SET_DEBUG_CASE_ID: &str = "hir::tests::look_set_debug";
const HIR_NO_STACK_OVERFLOW_ON_DROP_CASE_ID: &str = "hir::tests::no_stack_overflow_on_drop";
const UTF8_BMP_CASE_ID: &str = "utf8::tests::bmp";
const UTF8_CODEPOINTS_NO_SURROGATES_CASE_ID: &str = "utf8::tests::codepoints_no_surrogates";
const UTF8_REVERSE_CASE_ID: &str = "utf8::tests::reverse";
const UTF8_SINGLE_CODEPOINT_CASE_ID: &str = "utf8::tests::single_codepoint_one_sequence";
const UTF8_DOCTEST_SEQUENCES_CASE_ID: &str = "src/utf8.rs - utf8::Utf8Sequences (line 263)";
const TOP_ESCAPE_META_CASE_ID: &str = "tests::escape_meta";
const TOP_WORD_BYTE_CASE_ID: &str = "tests::word_byte";
const TOP_WORD_CHAR_CASE_ID: &str = "tests::word_char";
const TOP_DOCTEST_PARSE_CASE_ID: &str = "src/lib.rs - (line 39)";
const TOP_DOCTEST_META_CASE_ID: &str = "src/lib.rs - is_meta_character (line 248)";
const TOP_DOCTEST_ESCAPEABLE_CASE_ID: &str = "src/lib.rs - is_escapeable_character (line 291)";
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
const HIR_TRANSLATE_CAT_CLASS_FLATTENED_CASE_ID: &str =
    "hir::translate::tests::cat_class_flattened";
const HIR_TRANSLATE_CLASS_BRACKETED_CASE_ID: &str = "hir::translate::tests::class_bracketed";
const HIR_TRANSLATE_CLASS_BRACKETED_UNION_CASE_ID: &str =
    "hir::translate::tests::class_bracketed_union";
const HIR_TRANSLATE_CLASS_BRACKETED_NESTED_CASE_ID: &str =
    "hir::translate::tests::class_bracketed_nested";
const HIR_TRANSLATE_CLASS_BRACKETED_INTERSECT_CASE_ID: &str =
    "hir::translate::tests::class_bracketed_intersect";
const HIR_TRANSLATE_CLASS_BRACKETED_INTERSECT_NEGATE_CASE_ID: &str =
    "hir::translate::tests::class_bracketed_intersect_negate";
const HIR_TRANSLATE_CLASS_BRACKETED_DIFFERENCE_CASE_ID: &str =
    "hir::translate::tests::class_bracketed_difference";
const HIR_TRANSLATE_CLASS_BRACKETED_SYMMETRIC_DIFFERENCE_CASE_ID: &str =
    "hir::translate::tests::class_bracketed_symmetric_difference";
const HIR_TRANSLATE_LITERAL_CASE_ID: &str = "hir::translate::tests::literal";
const HIR_TRANSLATE_DOT_CASE_ID: &str = "hir::translate::tests::dot";
const HIR_TRANSLATE_CLASS_ASCII_CASE_ID: &str = "hir::translate::tests::class_ascii";
const HIR_TRANSLATE_CLASS_PERL_ASCII_CASE_ID: &str = "hir::translate::tests::class_perl_ascii";
const HIR_TRANSLATE_CLASS_PERL_UNICODE_CASE_ID: &str = "hir::translate::tests::class_perl_unicode";
const HIR_TRANSLATE_CLASS_UNICODE_GENCAT_CASE_ID: &str =
    "hir::translate::tests::class_unicode_gencat";
const HIR_TRANSLATE_CLASS_UNICODE_SCRIPT_CASE_ID: &str =
    "hir::translate::tests::class_unicode_script";
const HIR_TRANSLATE_CLASS_UNICODE_AGE_CASE_ID: &str = "hir::translate::tests::class_unicode_age";
const HIR_TRANSLATE_CLASS_UNICODE_ANY_EMPTY_CASE_ID: &str =
    "hir::translate::tests::class_unicode_any_empty";
const HIR_TRANSLATE_REGRESSION_ALT_EMPTY_CONCAT_CASE_ID: &str =
    "hir::translate::tests::regression_alt_empty_concat";
const HIR_TRANSLATE_REGRESSION_EMPTY_ALT_CASE_ID: &str =
    "hir::translate::tests::regression_empty_alt";
const HIR_TRANSLATE_REGRESSION_SINGLETON_ALT_CASE_ID: &str =
    "hir::translate::tests::regression_singleton_alt";
const HIR_TRANSLATE_REGRESSION_FUZZ_MATCH_CASE_ID: &str =
    "hir::translate::tests::regression_fuzz_match";
const HIR_TRANSLATE_REGRESSION_FUZZ_DIFFERENCE_CASE_ID: &str =
    "hir::translate::tests::regression_fuzz_difference1";
const HIR_DOCTEST_EXTRACT_PREFIX_CASE_ID: &str =
    "src/hir/literal.rs - hir::literal::Extractor (line 103)";
const HIR_DOCTEST_EXTRACT_SUFFIX_CASE_ID: &str =
    "src/hir/literal.rs - hir::literal::Extractor (line 128)";
const HIR_DOCTEST_LIMIT_CLASS_CASE_ID: &str =
    "src/hir/literal.rs - hir::literal::Extractor::limit_class (line 237)";
const HIR_DOCTEST_LIMIT_REPEAT_CASE_ID: &str =
    "src/hir/literal.rs - hir::literal::Extractor::limit_repeat (line 274)";
const HIR_DOCTEST_LIMIT_LITERAL_LEN_CASE_ID: &str =
    "src/hir/literal.rs - hir::literal::Extractor::limit_literal_len (line 311)";
const HIR_DOCTEST_LIMIT_TOTAL_CASE_ID: &str =
    "src/hir/literal.rs - hir::literal::Extractor::limit_total (line 353)";
const HIR_DOCTEST_SEQ_CASE_ID: &str = "src/hir/literal.rs - hir::literal::Seq (line 707)";
const HIR_DOCTEST_SEQ_CROSS_FORWARD_BASIC_CASE_ID: &str =
    "src/hir/literal.rs - hir::literal::Seq::cross_forward (line 875)";
const HIR_DOCTEST_SEQ_CROSS_FORWARD_INFINITE_OTHER_CASE_ID: &str =
    "src/hir/literal.rs - hir::literal::Seq::cross_forward (line 902)";
const HIR_DOCTEST_SEQ_CROSS_FORWARD_EMPTY_CASE_ID: &str =
    "src/hir/literal.rs - hir::literal::Seq::cross_forward (line 926)";
const HIR_DOCTEST_SEQ_CROSS_FORWARD_INFINITE_SELF_CASE_ID: &str =
    "src/hir/literal.rs - hir::literal::Seq::cross_forward (line 943)";
const HIR_DOCTEST_SEQ_CROSS_REVERSE_BASIC_CASE_ID: &str =
    "src/hir/literal.rs - hir::literal::Seq::cross_reverse (line 1014)";
const HIR_DOCTEST_SEQ_CROSS_REVERSE_INFINITE_OTHER_CASE_ID: &str =
    "src/hir/literal.rs - hir::literal::Seq::cross_reverse (line 1041)";
const HIR_DOCTEST_SEQ_CROSS_REVERSE_EMPTY_CASE_ID: &str =
    "src/hir/literal.rs - hir::literal::Seq::cross_reverse (line 1065)";
const HIR_DOCTEST_SEQ_CROSS_REVERSE_INFINITE_SELF_CASE_ID: &str =
    "src/hir/literal.rs - hir::literal::Seq::cross_reverse (line 1082)";
const HIR_DOCTEST_SEQ_UNION_BASIC_CASE_ID: &str =
    "src/hir/literal.rs - hir::literal::Seq::union (line 1187)";
const HIR_DOCTEST_SEQ_UNION_INFINITE_CASE_ID: &str =
    "src/hir/literal.rs - hir::literal::Seq::union (line 1204)";
const HIR_DOCTEST_SEQ_UNION_EMPTY_BASIC_CASE_ID: &str =
    "src/hir/literal.rs - hir::literal::Seq::union_into_empty (line 1258)";
const HIR_DOCTEST_SEQ_UNION_EMPTY_NO_SPLICE_CASE_ID: &str =
    "src/hir/literal.rs - hir::literal::Seq::union_into_empty (line 1274)";
const HIR_DOCTEST_SEQ_DEDUP_CASE_ID: &str =
    "src/hir/literal.rs - hir::literal::Seq::dedup (line 1329)";
const HIR_DOCTEST_SEQ_SORT_CASE_ID: &str =
    "src/hir/literal.rs - hir::literal::Seq::sort (line 1369)";
const HIR_DOCTEST_SEQ_REVERSE_LITERALS_CASE_ID: &str =
    "src/hir/literal.rs - hir::literal::Seq::reverse_literals (line 1392)";
const HIR_DOCTEST_SEQ_MINIMIZE_PREFIX_CASE_ID: &str =
    "src/hir/literal.rs - hir::literal::Seq::minimize_by_preference (line 1423)";
const HIR_DOCTEST_SEQ_MINIMIZE_EMPTY_CASE_ID: &str =
    "src/hir/literal.rs - hir::literal::Seq::minimize_by_preference (line 1442)";
const HIR_DOCTEST_SEQ_KEEP_FIRST_CASE_ID: &str =
    "src/hir/literal.rs - hir::literal::Seq::keep_first_bytes (line 1475)";
const HIR_DOCTEST_SEQ_KEEP_LAST_CASE_ID: &str =
    "src/hir/literal.rs - hir::literal::Seq::keep_last_bytes (line 1503)";
const HIR_DOCTEST_SEQ_COMMON_PREFIX_CASE_ID: &str =
    "src/hir/literal.rs - hir::literal::Seq::longest_common_prefix (line 1611)";
const HIR_DOCTEST_SEQ_COMMON_SUFFIX_CASE_ID: &str =
    "src/hir/literal.rs - hir::literal::Seq::longest_common_suffix (line 1664)";
const HIR_DOCTEST_SEQ_OPTIMIZE_PREFIX_CASE_ID: &str =
    "src/hir/literal.rs - hir::literal::Seq::optimize_for_prefix_by_preference (line 1752)";
const HIR_DOCTEST_SEQ_OPTIMIZE_INFINITE_CASE_ID: &str =
    "src/hir/literal.rs - hir::literal::Seq::optimize_for_prefix_by_preference (line 1778)";
const HIR_DOCTEST_SEQ_OPTIMIZE_SPACE_CASE_ID: &str =
    "src/hir/literal.rs - hir::literal::Seq::optimize_for_prefix_by_preference (line 1806)";
const HIR_DOCTEST_HIR_LITERAL_BYTES_CASE_ID: &str = "src/hir/mod.rs - hir::Hir::literal (line 305)";
const HIR_DOCTEST_HIR_LITERAL_CHAR_CASE_ID: &str = "src/hir/mod.rs - hir::Hir::literal (line 332)";
const HIR_DOCTEST_HIR_CONCAT_CASE_ID: &str = "src/hir/mod.rs - hir::Hir::concat (line 421)";
const HIR_DOCTEST_HIR_ALTERNATION_CLASS_CASE_ID: &str =
    "src/hir/mod.rs - hir::Hir::alternation (line 520)";
const HIR_DOCTEST_HIR_ALTERNATION_PREFIX_CASE_ID: &str =
    "src/hir/mod.rs - hir::Hir::alternation (line 540)";
const HIR_DOCTEST_HIR_DOT_CASE_ID: &str = "src/hir/mod.rs - hir::Hir::dot (line 649)";
const HIR_DOCTEST_CLASS_MINIMUM_LEN_CASE_ID: &str =
    "src/hir/mod.rs - hir::Class::minimum_len (line 926)";
const HIR_DOCTEST_CLASS_MAXIMUM_LEN_CASE_ID: &str =
    "src/hir/mod.rs - hir::Class::maximum_len (line 970)";
const HIR_DOCTEST_PROPERTIES_IS_UTF8_CASE_ID: &str =
    "src/hir/mod.rs - hir::Properties::is_utf8 (line 2094)";
const HIR_DOCTEST_PROPERTIES_CAPTURES_LEN_CASE_ID: &str =
    "src/hir/mod.rs - hir::Properties::explicit_captures_len (line 2155)";
const HIR_DOCTEST_PROPERTIES_STATIC_CAPTURES_LEN_CASE_ID: &str =
    "src/hir/mod.rs - hir::Properties::static_explicit_captures_len (line 2183)";
const HIR_DOCTEST_PROPERTIES_UNION_NEVER_CASE_ID: &str =
    "src/hir/mod.rs - hir::Properties::union (line 2255)";
const HIR_DOCTEST_PROPERTIES_UNION_UNBOUNDED_CASE_ID: &str =
    "src/hir/mod.rs - hir::Properties::union (line 2285)";
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HirClassOperation {
    CaseFold,
    Negate,
    Union,
    Intersect,
    Difference,
    SymmetricDifference,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HirUnicodeClassProbe {
    left: &'static [(char, char)],
    right: &'static [(char, char)],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HirBytesClassProbe {
    left: &'static [(u8, u8)],
    right: &'static [(u8, u8)],
}

impl HirUnicodeClassProbe {
    const fn new(left: &'static [(char, char)], right: &'static [(char, char)]) -> Self {
        Self { left, right }
    }
}

impl HirBytesClassProbe {
    const fn new(left: &'static [(u8, u8)], right: &'static [(u8, u8)]) -> Self {
        Self { left, right }
    }
}
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
const HIR_TRANSLATE_CAT_CLASS_FLATTENED_PROBES: [HirTranslateProbe; 4] = [
    (r"[a-z]|[A-Z]", false),
    (
        r"(?x)
                \p{Lowercase_Letter}
                |\p{Uppercase_Letter}
                |\p{Titlecase_Letter}
                |\p{Modifier_Letter}
                |\p{Other_Letter}
            ",
        false,
    ),
    (r"[Δδ]|(?-u:[\x90-\xFF])|[Λλ]", true),
    (r"[a-z]|(?-u:[\x90-\xFF])|[A-Z]", true),
];
const HIR_TRANSLATE_CLASS_BRACKETED_PROBES: [HirTranslateProbe; 50] = [
    ("[a]", false),
    ("[ab]", false),
    ("[^[a]]", false),
    ("[a-z]", false),
    ("[a-fd-h]", false),
    ("[a-fg-m]", false),
    (r"[\x00]", false),
    (r"[\n]", false),
    ("[\n]", false),
    (r"[\d]", false),
    (r"[\pZ]", false),
    (r"[\p{separator}]", false),
    (r"[^\D]", false),
    (r"[^\PZ]", false),
    (r"[^\P{separator}]", false),
    (r"(?i)[^\D]", false),
    (r"(?i)[^\P{greek}]", false),
    ("(?-u)[a]", false),
    (r"(?-u)[\x00]", false),
    (r"(?-u)[\xFF]", true),
    ("(?i)[a]", false),
    ("(?i)[k]", false),
    ("(?i)[β]", false),
    ("(?i-u)[k]", false),
    ("[^a]", false),
    (r"[^\x00]", false),
    ("(?-u)[^a]", true),
    (r"[^\d]", false),
    (r"[^\pZ]", false),
    (r"[^\p{separator}]", false),
    (r"(?i)[^\p{greek}]", false),
    (r"(?i)[\P{greek}]", false),
    (r"[\[]", false),
    (r"[&]", false),
    (r"[\&]", false),
    (r"[\&\&]", false),
    (r"[\x00-&]", false),
    (r"[&-\xFF]", false),
    (r"[~]", false),
    (r"[\~]", false),
    (r"[\~\~]", false),
    (r"[\x00-~]", false),
    (r"[~-\xFF]", false),
    (r"[-]", false),
    (r"[\-]", false),
    (r"[\-\-]", false),
    (r"[\x00-\-]", false),
    (r"[\--\xFF]", false),
    (r"[^\s\S]", false),
    (r"(?-u)[^\s\S]", true),
];
const HIR_TRANSLATE_CLASS_BRACKETED_ERROR_PROBES: [HirTranslateProbe; 1] = [("(?-u)[^a]", false)];
const HIR_TRANSLATE_CLASS_BRACKETED_UNION_PROBES: [HirTranslateProbe; 8] = [
    (r"[a-zA-Z]", false),
    (r"[a\pZb]", false),
    (r"[\pZ\p{Greek}]", false),
    (r"[\p{age:3.0}\pZ\p{Greek}]", false),
    (r"[[[\p{age:3.0}\pZ]\p{Greek}][\p{Cyrillic}]]", false),
    (r"(?i)[\p{age:3.0}\pZ\p{Greek}]", false),
    (r"[^\p{age:3.0}\pZ\p{Greek}]", false),
    (r"(?i)[^\p{age:3.0}\pZ\p{Greek}]", false),
];
const HIR_TRANSLATE_CLASS_BRACKETED_NESTED_PROBES: [HirTranslateProbe; 11] = [
    (r"[a[^c]]", false),
    (r"[a-b[^c]]", false),
    (r"[a-c[^c]]", false),
    (r"[^a[^c]]", false),
    (r"[^a-b[^c]]", false),
    (r"(?i)[a[^c]]", false),
    (r"(?i)[a-b[^c]]", false),
    (r"(?i)[^a[^c]]", false),
    (r"(?i)[^a-b[^c]]", false),
    (r"[^a-c[^c]]", false),
    (r"(?i)[^a-c[^c]]", false),
];
const HIR_TRANSLATE_CLASS_BRACKETED_INTERSECT_PROBES: [HirTranslateProbe; 33] = [
    ("[abc&&b-c]", false),
    ("[abc&&[b-c]]", false),
    ("[[abc]&&[b-c]]", false),
    ("[a-z&&b-y&&c-x]", false),
    ("[c-da-b&&a-d]", false),
    ("[a-d&&c-da-b]", false),
    (r"[a-z&&a-c]", false),
    (r"[[a-z&&a-c]]", false),
    (r"[^[a-z&&a-c]]", false),
    ("(?-u)[abc&&b-c]", false),
    ("(?-u)[abc&&[b-c]]", false),
    ("(?-u)[[abc]&&[b-c]]", false),
    ("(?-u)[a-z&&b-y&&c-x]", false),
    ("(?-u)[c-da-b&&a-d]", false),
    ("(?-u)[a-d&&c-da-b]", false),
    ("(?i)[abc&&b-c]", false),
    ("(?i)[abc&&[b-c]]", false),
    ("(?i)[[abc]&&[b-c]]", false),
    ("(?i)[a-z&&b-y&&c-x]", false),
    ("(?i)[c-da-b&&a-d]", false),
    ("(?i)[a-d&&c-da-b]", false),
    ("(?i-u)[abc&&b-c]", false),
    ("(?i-u)[abc&&[b-c]]", false),
    ("(?i-u)[[abc]&&[b-c]]", false),
    ("(?i-u)[a-z&&b-y&&c-x]", false),
    ("(?i-u)[c-da-b&&a-d]", false),
    ("(?i-u)[a-d&&c-da-b]", false),
    (r"[\^&&^]", false),
    (r"[]&&\]]", false),
    (r"[-&&-]", false),
    (r"[\&&&&]", false),
    (r"[\&&&\&]", false),
    (r"[a-w&&[^c-g]z]", false),
];
const HIR_TRANSLATE_CLASS_BRACKETED_INTERSECT_NEGATE_PROBES: [HirTranslateProbe; 10] = [
    (r"[^\w&&\d]", false),
    (r"[^[a-z&&a-c]]", false),
    (r"[^[\w&&\d]]", false),
    (r"[^[^\w&&\d]]", false),
    (r"[[[^\w]&&[^\d]]]", false),
    (r"(?-u)[^\w&&\d]", true),
    (r"(?-u)[^[a-z&&a-c]]", true),
    (r"(?-u)[^[\w&&\d]]", true),
    (r"(?-u)[^[^\w&&\d]]", true),
    (r"(?-u)[[[^\w]&&[^\d]]]", true),
];
const HIR_TRANSLATE_CLASS_BRACKETED_DIFFERENCE_PROBES: [HirTranslateProbe; 2] = [
    (r"[\pL--[:ascii:]]", false),
    (r"(?-u)[[:alpha:]--[:lower:]]", false),
];
const HIR_TRANSLATE_CLASS_BRACKETED_SYMMETRIC_DIFFERENCE_PROBES: [HirTranslateProbe; 3] = [
    (r"[\p{sc:Greek}~~\p{scx:Greek}]", false),
    (r"[a-g~~c-j]", false),
    (r"(?-u)[a-g~~c-j]", false),
];
const HIR_TRANSLATE_LITERAL_PROBES: [HirTranslateProbe; 9] = [
    ("a", false),
    ("(?-u)a", false),
    ("☃", false),
    ("abcd", false),
    ("(?-u)a", true),
    ("(?-u)\x61", true),
    (r"(?-u)\x61", true),
    (r"(?-u)\xFF", true),
    ("(?-u)☃", false),
];
const HIR_TRANSLATE_LITERAL_ERROR_PROBES: [HirTranslateProbe; 1] = [(r"(?-u)\xFF", false)];
const HIR_TRANSLATE_DOT_PROBES: [HirTranslateProbe; 8] = [
    (".", false),
    ("(?R).", false),
    ("(?s).", false),
    ("(?Rs).", false),
    ("(?-u).", true),
    ("(?R-u).", true),
    ("(?s-u).", true),
    ("(?Rs-u).", true),
];
const HIR_TRANSLATE_DOT_ERROR_PROBES: [HirTranslateProbe; 4] = [
    ("(?-u).", false),
    ("(?R-u).", false),
    ("(?s-u).", false),
    ("(?Rs-u).", false),
];
const HIR_TRANSLATE_CLASS_ASCII_PROBES: [HirTranslateProbe; 18] = [
    ("[[:alnum:]]", false),
    ("[[:alpha:]]", false),
    ("[[:ascii:]]", false),
    ("[[:blank:]]", false),
    ("[[:cntrl:]]", false),
    ("[[:digit:]]", false),
    ("[[:graph:]]", false),
    ("[[:lower:]]", false),
    ("[[:print:]]", false),
    ("[[:punct:]]", false),
    ("[[:space:]]", false),
    ("[[:upper:]]", false),
    ("[[:word:]]", false),
    ("[[:xdigit:]]", false),
    ("[[:^lower:]]", false),
    ("(?i)[[:lower:]]", false),
    ("(?-u)[[:lower:]]", false),
    ("(?i-u)[[:lower:]]", false),
];
const HIR_TRANSLATE_CLASS_ASCII_ERROR_PROBES: [HirTranslateProbe; 2] =
    [("(?-u)[[:^lower:]]", false), ("(?i-u)[[:^lower:]]", false)];
const HIR_TRANSLATE_CLASS_PERL_ASCII_PROBES: [HirTranslateProbe; 12] = [
    (r"(?-u)\d", false),
    (r"(?-u)\s", false),
    (r"(?-u)\w", false),
    (r"(?i-u)\d", false),
    (r"(?i-u)\s", false),
    (r"(?i-u)\w", false),
    (r"(?-u)\D", true),
    (r"(?-u)\S", true),
    (r"(?-u)\W", true),
    (r"(?i-u)\D", true),
    (r"(?i-u)\S", true),
    (r"(?i-u)\W", true),
];
const HIR_TRANSLATE_CLASS_PERL_ASCII_ERROR_PROBES: [HirTranslateProbe; 6] = [
    (r"(?-u)\D", false),
    (r"(?-u)\S", false),
    (r"(?-u)\W", false),
    (r"(?i-u)\D", false),
    (r"(?i-u)\S", false),
    (r"(?i-u)\W", false),
];
const HIR_TRANSLATE_CLASS_PERL_UNICODE_PROBES: [HirTranslateProbe; 12] = [
    (r"\d", false),
    (r"\s", false),
    (r"\w", false),
    (r"(?i)\d", false),
    (r"(?i)\s", false),
    (r"(?i)\w", false),
    (r"\D", false),
    (r"\S", false),
    (r"\W", false),
    (r"(?i)\D", false),
    (r"(?i)\S", false),
    (r"(?i)\W", false),
];
const HIR_TRANSLATE_CLASS_UNICODE_GENCAT_PROBES: [HirTranslateProbe; 18] = [
    (r"\pZ", false),
    (r"\pz", false),
    (r"\p{Separator}", false),
    (r"\p{se      PaRa ToR}", false),
    (r"\p{gc:Separator}", false),
    (r"\p{gc=Separator}", false),
    (r"\p{gc!=Separator}", false),
    (r"\p{Other}", false),
    (r"\pC", false),
    (r"\PZ", false),
    (r"\P{separator}", false),
    (r"\P{gc!=separator}", false),
    (r"\p{any}", false),
    (r"\p{assigned}", false),
    (r"\p{ascii}", false),
    (r"\p{gc:any}", false),
    (r"\p{gc:assigned}", false),
    (r"\p{gc:ascii}", false),
];
const HIR_TRANSLATE_CLASS_UNICODE_GENCAT_ERROR_PROBES: [HirTranslateProbe; 5] = [
    (r"(?-u)\pZ", false),
    (r"(?-u)\p{Separator}", false),
    (r"\pE", false),
    (r"\p{Foo}", false),
    (r"\p{gc:Foo}", false),
];
const HIR_TRANSLATE_CLASS_UNICODE_SCRIPT_PROBES: [HirTranslateProbe; 3] = [
    (r"\p{Greek}", false),
    (r"(?i)\p{Greek}", false),
    (r"(?i)\P{Greek}", false),
];
const HIR_TRANSLATE_CLASS_UNICODE_SCRIPT_ERROR_PROBES: [HirTranslateProbe; 2] =
    [(r"\p{sc:Foo}", false), (r"\p{scx:Foo}", false)];
const HIR_TRANSLATE_CLASS_UNICODE_AGE_PROBES: [HirTranslateProbe; 0] = [];
const HIR_TRANSLATE_CLASS_UNICODE_AGE_ERROR_PROBES: [HirTranslateProbe; 1] =
    [(r"\p{age:Foo}", false)];
const HIR_TRANSLATE_CLASS_UNICODE_ANY_EMPTY_PROBES: [HirTranslateProbe; 1] = [(r"\P{any}", false)];
const HIR_TRANSLATE_REGRESSION_FUZZ_MATCH_PATTERN: &str = "[(\u{6} \0-\u{afdf5}]  \0 ";
const HIR_TRANSLATE_REGRESSION_FUZZ_MATCH_PROBES: [HirTranslateProbe; 1] =
    [(HIR_TRANSLATE_REGRESSION_FUZZ_MATCH_PATTERN, false)];
const HIR_TRANSLATE_REGRESSION_FUZZ_DIFFERENCE_PROBES: [HirTranslateProbe; 1] = [(
    r"\W\W|\W[^\v--\W\W\P{Script_Extensions:Pau_Cin_Hau}\u10A1A1-\U{3E3E3}--~~~~--~~~~~~~~------~~~~~~--~~~~~~]*",
    false,
)];
const HIR_DOCTEST_CLASS_MINIMUM_LEN_PROBES: [&str; 6] =
    [r"", r"^$\b\B", r"a*", r"[a&&b]", r"\w", r"\p{Cyrillic}"];
const HIR_DOCTEST_CLASS_MAXIMUM_LEN_PROBES: [&str; 6] =
    [r"", r"^$\b\B", r"[a&&b]", r"x{2,10}", r"x{2,}", r"\w"];
const HIR_DOCTEST_PROPERTIES_UNION_NEVER_PROBES: [&str; 3] = [r"ab?c?", r"[a&&b]", r"wxy?z?"];
const HIR_DOCTEST_PROPERTIES_UNION_UNBOUNDED_PROBES: [&str; 3] = [r"ab?c?", r"a+", r"wxy?z?"];
type UnicodeClassCanonicalizeProbe = (&'static [(char, char)], &'static [(char, char)]);
type BytesClassCanonicalizeProbe = (&'static [(u8, u8)], &'static [(u8, u8)]);

const HIR_CLASS_CANONICALIZE_UNICODE_PROBES: &[UnicodeClassCanonicalizeProbe] = &[
    (&[('a', 'c'), ('x', 'z')], &[('a', 'c'), ('x', 'z')]),
    (&[('x', 'z'), ('a', 'c')], &[('a', 'c'), ('x', 'z')]),
    (&[('x', 'z'), ('w', 'y')], &[('w', 'z')]),
    (
        &[
            ('c', 'f'),
            ('a', 'g'),
            ('d', 'j'),
            ('a', 'c'),
            ('m', 'p'),
            ('l', 's'),
        ],
        &[('a', 'j'), ('l', 's')],
    ),
    (&[('x', 'z'), ('u', 'w')], &[('u', 'z')]),
    (
        &[('\0', '\u{10FFFF}'), ('\0', '\u{10FFFF}')],
        &[('\0', '\u{10FFFF}')],
    ),
    (&[('a', 'a'), ('b', 'b')], &[('a', 'b')]),
];
const HIR_CLASS_CANONICALIZE_BYTES_PROBES: &[BytesClassCanonicalizeProbe] = &[
    (&[(b'a', b'c'), (b'x', b'z')], &[(b'a', b'c'), (b'x', b'z')]),
    (&[(b'x', b'z'), (b'a', b'c')], &[(b'a', b'c'), (b'x', b'z')]),
    (&[(b'x', b'z'), (b'w', b'y')], &[(b'w', b'z')]),
    (
        &[
            (b'c', b'f'),
            (b'a', b'g'),
            (b'd', b'j'),
            (b'a', b'c'),
            (b'm', b'p'),
            (b'l', b's'),
        ],
        &[(b'a', b'j'), (b'l', b's')],
    ),
    (&[(b'x', b'z'), (b'u', b'w')], &[(b'u', b'z')]),
    (&[(b'\0', b'\xFF'), (b'\0', b'\xFF')], &[(b'\0', b'\xFF')]),
    // The pinned source intentionally repeats this assertion.
    (&[(b'\0', b'\xFF'), (b'\0', b'\xFF')], &[(b'\0', b'\xFF')]),
    (&[(b'a', b'a'), (b'b', b'b')], &[(b'a', b'b')]),
];
const HIR_LITERAL_LITERAL_PROBES: [&str; 17] = [
    "a",
    "aaaaa",
    "(?i-u)a",
    "(?i-u)ab",
    "ab(?i-u)c",
    r"(?-u:\xFF)",
    "☃",
    "(?i)☃",
    "☃☃☃☃☃",
    "Δ",
    "δ",
    "(?i)Δ",
    "(?i)δ",
    "(?i)S",
    "(?i)s",
    "(?i)ſ",
    "ͱͳͷΐάέήίΰαβγδεζηθικλμνξοπρςστυφχψωϊϋ",
];
const HIR_LITERAL_CLASS_PROBES: [&str; 4] = ["[abc]", "a[123]b", "[εδ]", r"(?i)[εδ]"];
const HIR_LITERAL_LOOK_PROBES: [&str; 25] = [
    r"a\Ab",
    r"a\zb",
    r"a(?m:^)b",
    r"a(?m:$)b",
    r"a\bb",
    r"a\Bb",
    r"a(?-u:\b)b",
    r"a(?-u:\B)b",
    r"^ab",
    r"$ab",
    r"(?m:^)ab",
    r"(?m:$)ab",
    r"\bab",
    r"\Bab",
    r"(?-u:\b)ab",
    r"(?-u:\B)ab",
    r"ab^",
    r"ab$",
    r"ab(?m:^)",
    r"ab(?m:$)",
    r"ab\b",
    r"ab\B",
    r"ab(?-u:\b)",
    r"ab(?-u:\B)",
    r"^aZ*b",
];
const HIR_LITERAL_REPETITION_PROBES: [&str; 35] = [
    r"a?",
    r"a??",
    r"a*",
    r"a*?",
    r"a+",
    r"(a+)+",
    r"aZ{0}b",
    r"aZ?b",
    r"aZ??b",
    r"aZ*b",
    r"aZ*?b",
    r"aZ+b",
    r"aZ+?b",
    r"aZ{2}b",
    r"aZ{2,3}b",
    r"(abc)?",
    r"(abc)??",
    r"a*b",
    r"a*?b",
    r"ab+",
    r"a*b+",
    r"a*b*c",
    r"(a+)?(b+)?c",
    r"(a+|)(b+|)c",
    r"a*b*c*",
    r"a*b*c+",
    r"a*b+c",
    r"a*b+c*",
    r"ab*",
    r"ab*c",
    r"ab+",
    r"ab+c",
    r"z*azb",
    r"[ab]{3}",
    r"[ab]{3,4}",
];
const HIR_LITERAL_CONCAT_PROBES: [&str; 5] = [
    r"abc()xyz",
    r"(abc)(xyz)",
    r"abc()mno()xyz",
    r"abc[a&&b]xyz",
    r"abc[a&&b]*xyz",
];
const HIR_LITERAL_ALTERNATION_PROBES: [&str; 17] = [
    r"abc|mno|xyz",
    r"abc|mZ*o|xyz",
    r"abc|M[a&&b]N|xyz",
    r"abc|M[a&&b]*N|xyz",
    r"(?:|aa)aaa",
    r"(?:|aa)(?:aaa)*",
    r"(?:|aa)(?:aaa)*?",
    r"a|b*",
    r"a|b+",
    r"a*b|c",
    r"a|(?:b|c*)",
    r"(a|b)*c|(a|ab)*c",
    r"(ab|cd)(ef|gh)",
    r"(ab|cd)(ef|gh)(ij|kl)",
    r"(ab){2}",
    r"(ab){2,3}",
    r"(ab){2,}",
];
const HIR_LITERAL_IMPOSSIBLE_PROBES: [&str; 10] = [
    r"[a&&b]",
    r"a[a&&b]",
    r"[a&&b]b",
    r"a[a&&b]b",
    r"a|[a&&b]|b",
    r"a|c[a&&b]|b",
    r"a|[a&&b]d|b",
    r"a|c[a&&b]d|b",
    r"[a&&b]*",
    r"M[a&&b]*N",
];
const HIR_LITERAL_ANYTHING_PROBES: [&str; 18] = [
    r".",
    r"(?s).",
    r"[A-Za-z]",
    r"[A-Z]",
    r"[A-Z]{0}",
    r"[A-Z]?",
    r"[A-Z]*",
    r"[A-Z]+",
    r"1[A-Z]",
    r"1[A-Z]2",
    r"[A-Z]+123",
    r"[A-Z]+123[A-Z]+",
    r"1|[A-Z]|3",
    r"1|2[A-Z]|3",
    r"1|[A-Z]2|3",
    r"1|2[A-Z]3|4",
    r"(?:|1)[A-Z]2",
    r"a.z",
];
const HIR_LITERAL_ANYTHING_SMALL_LIMITS_PROBES: [&str; 2] =
    [r"[ab]{3}{3}", r"ab|cd|ef|gh|ij|kl|mn|op|qr|st|uv|wx|yz"];
const HIR_LITERAL_EMPTY_PROBES: [&str; 9] = [
    r"",
    r"^",
    r"$",
    r"(?m:^)",
    r"(?m:$)",
    r"\b",
    r"\B",
    r"(?-u:\b)",
    r"(?-u:\B)",
];
const HIR_LITERAL_ODDS_AND_ENDS_PROBES: [&str; 10] = [
    r".a",
    r"a.",
    r"a|.",
    r".|a",
    r"M[ou]'?am+[ae]r .*([AEae]l[- ])?[GKQ]h?[aeu]+([dtz][dhz]?)+af[iy]",
    r"fn is_([A-Z]+)|fn as_([A-Z]+)",
    r"foo[A-Z]+bar[A-Z]+quux",
    r"[A-Z]+bar[A-Z]+",
    r"(?m)^Sherlock Holmes|Sherlock Holmes$",
    r"\bs(?:[ab])",
];
const HIR_LITERAL_HOLMES_PROBES: [&str; 1] = [r"(?i)Holmes"];
const HIR_LITERAL_HOLMES_ALT_PROBES: [&str; 1] =
    [r"(?i)Sherlock|Holmes|Watson|Irene|Adler|John|Baker"];
const HIR_CLASS_CASE_FOLD_UNICODE_PROBES: [HirUnicodeClassProbe; 8] = [
    HirUnicodeClassProbe::new(
        &[
            ('C', 'F'),
            ('A', 'G'),
            ('D', 'J'),
            ('A', 'C'),
            ('M', 'P'),
            ('L', 'S'),
            ('c', 'f'),
        ],
        &[],
    ),
    HirUnicodeClassProbe::new(&[('A', 'Z')], &[]),
    HirUnicodeClassProbe::new(&[('a', 'z')], &[]),
    HirUnicodeClassProbe::new(&[('A', 'A'), ('_', '_')], &[]),
    HirUnicodeClassProbe::new(&[('A', 'A'), ('=', '=')], &[]),
    HirUnicodeClassProbe::new(&[('\x00', '\x10')], &[]),
    HirUnicodeClassProbe::new(&[('k', 'k')], &[]),
    HirUnicodeClassProbe::new(&[('@', '@')], &[]),
];
const HIR_CLASS_CASE_FOLD_BYTES_PROBES: [HirBytesClassProbe; 8] = [
    HirBytesClassProbe::new(
        &[
            (b'C', b'F'),
            (b'A', b'G'),
            (b'D', b'J'),
            (b'A', b'C'),
            (b'M', b'P'),
            (b'L', b'S'),
            (b'c', b'f'),
        ],
        &[],
    ),
    HirBytesClassProbe::new(&[(b'A', b'Z')], &[]),
    HirBytesClassProbe::new(&[(b'a', b'z')], &[]),
    HirBytesClassProbe::new(&[(b'A', b'A'), (b'_', b'_')], &[]),
    HirBytesClassProbe::new(&[(b'A', b'A'), (b'=', b'=')], &[]),
    HirBytesClassProbe::new(&[(b'\x00', b'\x10')], &[]),
    HirBytesClassProbe::new(&[(b'k', b'k')], &[]),
    HirBytesClassProbe::new(&[(b'@', b'@')], &[]),
];
const HIR_CLASS_NEGATE_UNICODE_PROBES: [HirUnicodeClassProbe; 12] = [
    HirUnicodeClassProbe::new(&[('a', 'a')], &[]),
    HirUnicodeClassProbe::new(&[('a', 'a'), ('b', 'b')], &[]),
    HirUnicodeClassProbe::new(&[('a', 'c'), ('x', 'z')], &[]),
    HirUnicodeClassProbe::new(&[('\x00', 'a')], &[]),
    HirUnicodeClassProbe::new(&[('a', '\u{10FFFF}')], &[]),
    HirUnicodeClassProbe::new(&[('\x00', '\u{10FFFF}')], &[]),
    HirUnicodeClassProbe::new(&[], &[]),
    HirUnicodeClassProbe::new(&[('\x00', '\u{10FFFD}'), ('\u{10FFFF}', '\u{10FFFF}')], &[]),
    HirUnicodeClassProbe::new(&[('\x00', '\u{D7FF}')], &[]),
    HirUnicodeClassProbe::new(&[('\x00', '\u{D7FE}')], &[]),
    HirUnicodeClassProbe::new(&[('\u{E000}', '\u{10FFFF}')], &[]),
    HirUnicodeClassProbe::new(&[('\u{E001}', '\u{10FFFF}')], &[]),
];
const HIR_CLASS_NEGATE_BYTES_PROBES: [HirBytesClassProbe; 8] = [
    HirBytesClassProbe::new(&[(b'a', b'a')], &[]),
    HirBytesClassProbe::new(&[(b'a', b'a'), (b'b', b'b')], &[]),
    HirBytesClassProbe::new(&[(b'a', b'c'), (b'x', b'z')], &[]),
    HirBytesClassProbe::new(&[(b'\x00', b'a')], &[]),
    HirBytesClassProbe::new(&[(b'a', b'\xFF')], &[]),
    HirBytesClassProbe::new(&[(b'\x00', b'\xFF')], &[]),
    HirBytesClassProbe::new(&[], &[]),
    HirBytesClassProbe::new(&[(b'\x00', b'\xFD'), (b'\xFF', b'\xFF')], &[]),
];
const HIR_CLASS_UNION_UNICODE_PROBES: [HirUnicodeClassProbe; 1] = [HirUnicodeClassProbe::new(
    &[('a', 'g'), ('m', 't'), ('A', 'C')],
    &[('a', 'z')],
)];
const HIR_CLASS_UNION_BYTES_PROBES: [HirBytesClassProbe; 1] = [HirBytesClassProbe::new(
    &[(b'a', b'g'), (b'm', b't'), (b'A', b'C')],
    &[(b'a', b'z')],
)];
const HIR_CLASS_INTERSECT_UNICODE_PROBES: [HirUnicodeClassProbe; 14] = [
    HirUnicodeClassProbe::new(&[], &[('a', 'a')]),
    HirUnicodeClassProbe::new(&[('a', 'a')], &[('a', 'a')]),
    HirUnicodeClassProbe::new(&[('a', 'a')], &[('b', 'b')]),
    HirUnicodeClassProbe::new(&[('a', 'a')], &[('a', 'c')]),
    HirUnicodeClassProbe::new(&[('a', 'b')], &[('a', 'c')]),
    HirUnicodeClassProbe::new(&[('a', 'b')], &[('b', 'c')]),
    HirUnicodeClassProbe::new(&[('a', 'b')], &[('c', 'd')]),
    HirUnicodeClassProbe::new(&[('b', 'c')], &[('a', 'd')]),
    HirUnicodeClassProbe::new(&[('a', 'b'), ('d', 'e'), ('g', 'h')], &[('a', 'h')]),
    HirUnicodeClassProbe::new(
        &[('a', 'b'), ('d', 'e'), ('g', 'h')],
        &[('a', 'b'), ('d', 'e'), ('g', 'h')],
    ),
    HirUnicodeClassProbe::new(&[('a', 'b'), ('g', 'h')], &[('d', 'e'), ('k', 'l')]),
    HirUnicodeClassProbe::new(&[('a', 'b'), ('d', 'e'), ('g', 'h')], &[('h', 'h')]),
    HirUnicodeClassProbe::new(
        &[('a', 'b'), ('e', 'f'), ('i', 'j')],
        &[('c', 'd'), ('g', 'h'), ('k', 'l')],
    ),
    HirUnicodeClassProbe::new(
        &[('a', 'b'), ('c', 'd'), ('e', 'f')],
        &[('b', 'c'), ('d', 'e'), ('f', 'g')],
    ),
];
const HIR_CLASS_INTERSECT_BYTES_PROBES: [HirBytesClassProbe; 14] = [
    HirBytesClassProbe::new(&[], &[(b'a', b'a')]),
    HirBytesClassProbe::new(&[(b'a', b'a')], &[(b'a', b'a')]),
    HirBytesClassProbe::new(&[(b'a', b'a')], &[(b'b', b'b')]),
    HirBytesClassProbe::new(&[(b'a', b'a')], &[(b'a', b'c')]),
    HirBytesClassProbe::new(&[(b'a', b'b')], &[(b'a', b'c')]),
    HirBytesClassProbe::new(&[(b'a', b'b')], &[(b'b', b'c')]),
    HirBytesClassProbe::new(&[(b'a', b'b')], &[(b'c', b'd')]),
    HirBytesClassProbe::new(&[(b'b', b'c')], &[(b'a', b'd')]),
    HirBytesClassProbe::new(&[(b'a', b'b'), (b'd', b'e'), (b'g', b'h')], &[(b'a', b'h')]),
    HirBytesClassProbe::new(
        &[(b'a', b'b'), (b'd', b'e'), (b'g', b'h')],
        &[(b'a', b'b'), (b'd', b'e'), (b'g', b'h')],
    ),
    HirBytesClassProbe::new(&[(b'a', b'b'), (b'g', b'h')], &[(b'd', b'e'), (b'k', b'l')]),
    HirBytesClassProbe::new(&[(b'a', b'b'), (b'd', b'e'), (b'g', b'h')], &[(b'h', b'h')]),
    HirBytesClassProbe::new(
        &[(b'a', b'b'), (b'e', b'f'), (b'i', b'j')],
        &[(b'c', b'd'), (b'g', b'h'), (b'k', b'l')],
    ),
    HirBytesClassProbe::new(
        &[(b'a', b'b'), (b'c', b'd'), (b'e', b'f')],
        &[(b'b', b'c'), (b'd', b'e'), (b'f', b'g')],
    ),
];
const HIR_CLASS_DIFFERENCE_UNICODE_PROBES: [HirUnicodeClassProbe; 12] = [
    HirUnicodeClassProbe::new(&[('a', 'a')], &[('a', 'a')]),
    HirUnicodeClassProbe::new(&[('a', 'a')], &[]),
    HirUnicodeClassProbe::new(&[], &[('a', 'a')]),
    HirUnicodeClassProbe::new(&[('a', 'z')], &[('a', 'a')]),
    HirUnicodeClassProbe::new(&[('a', 'z')], &[('z', 'z')]),
    HirUnicodeClassProbe::new(&[('a', 'z')], &[('m', 'm')]),
    HirUnicodeClassProbe::new(&[('a', 'c'), ('g', 'i'), ('r', 't')], &[('a', 'z')]),
    HirUnicodeClassProbe::new(&[('a', 'c'), ('g', 'i'), ('r', 't')], &[('d', 'v')]),
    HirUnicodeClassProbe::new(
        &[('a', 'c'), ('g', 'i'), ('r', 't')],
        &[('b', 'g'), ('s', 'u')],
    ),
    HirUnicodeClassProbe::new(
        &[('a', 'c'), ('g', 'i'), ('r', 't')],
        &[('b', 'd'), ('e', 'g'), ('s', 'u')],
    ),
    HirUnicodeClassProbe::new(&[('x', 'z')], &[('a', 'c'), ('e', 'g'), ('s', 'u')]),
    HirUnicodeClassProbe::new(&[('a', 'z')], &[('a', 'c'), ('e', 'g'), ('s', 'u')]),
];
const HIR_CLASS_DIFFERENCE_BYTES_PROBES: [HirBytesClassProbe; 12] = [
    HirBytesClassProbe::new(&[(b'a', b'a')], &[(b'a', b'a')]),
    HirBytesClassProbe::new(&[(b'a', b'a')], &[]),
    HirBytesClassProbe::new(&[], &[(b'a', b'a')]),
    HirBytesClassProbe::new(&[(b'a', b'z')], &[(b'a', b'a')]),
    HirBytesClassProbe::new(&[(b'a', b'z')], &[(b'z', b'z')]),
    HirBytesClassProbe::new(&[(b'a', b'z')], &[(b'm', b'm')]),
    HirBytesClassProbe::new(&[(b'a', b'c'), (b'g', b'i'), (b'r', b't')], &[(b'a', b'z')]),
    HirBytesClassProbe::new(&[(b'a', b'c'), (b'g', b'i'), (b'r', b't')], &[(b'd', b'v')]),
    HirBytesClassProbe::new(
        &[(b'a', b'c'), (b'g', b'i'), (b'r', b't')],
        &[(b'b', b'g'), (b's', b'u')],
    ),
    HirBytesClassProbe::new(
        &[(b'a', b'c'), (b'g', b'i'), (b'r', b't')],
        &[(b'b', b'd'), (b'e', b'g'), (b's', b'u')],
    ),
    HirBytesClassProbe::new(&[(b'x', b'z')], &[(b'a', b'c'), (b'e', b'g'), (b's', b'u')]),
    HirBytesClassProbe::new(&[(b'a', b'z')], &[(b'a', b'c'), (b'e', b'g'), (b's', b'u')]),
];
const HIR_CLASS_SYMMETRIC_DIFFERENCE_UNICODE_PROBES: [HirUnicodeClassProbe; 1] =
    [HirUnicodeClassProbe::new(&[('a', 'm')], &[('g', 't')])];
const HIR_CLASS_SYMMETRIC_DIFFERENCE_BYTES_PROBES: [HirBytesClassProbe; 1] =
    [HirBytesClassProbe::new(&[(b'a', b'm')], &[(b'g', b't')])];
#[cfg(test)]
const HIR_CLASS_OPERATION_CASES: [(&str, usize, bool, bool); 12] = [
    (
        HIR_CLASS_CASE_FOLD_UNICODE_CASE_ID,
        HIR_CLASS_CASE_FOLD_UNICODE_PROBES.len(),
        true,
        false,
    ),
    (
        HIR_CLASS_CASE_FOLD_BYTES_CASE_ID,
        HIR_CLASS_CASE_FOLD_BYTES_PROBES.len(),
        true,
        true,
    ),
    (
        HIR_CLASS_NEGATE_UNICODE_CASE_ID,
        HIR_CLASS_NEGATE_UNICODE_PROBES.len(),
        true,
        true,
    ),
    (
        HIR_CLASS_NEGATE_BYTES_CASE_ID,
        HIR_CLASS_NEGATE_BYTES_PROBES.len(),
        true,
        true,
    ),
    (
        HIR_CLASS_UNION_UNICODE_CASE_ID,
        HIR_CLASS_UNION_UNICODE_PROBES.len(),
        true,
        true,
    ),
    (
        HIR_CLASS_UNION_BYTES_CASE_ID,
        HIR_CLASS_UNION_BYTES_PROBES.len(),
        true,
        true,
    ),
    (
        HIR_CLASS_INTERSECT_UNICODE_CASE_ID,
        HIR_CLASS_INTERSECT_UNICODE_PROBES.len(),
        true,
        true,
    ),
    (
        HIR_CLASS_INTERSECT_BYTES_CASE_ID,
        HIR_CLASS_INTERSECT_BYTES_PROBES.len(),
        true,
        true,
    ),
    (
        HIR_CLASS_DIFFERENCE_UNICODE_CASE_ID,
        HIR_CLASS_DIFFERENCE_UNICODE_PROBES.len(),
        true,
        true,
    ),
    (
        HIR_CLASS_DIFFERENCE_BYTES_CASE_ID,
        HIR_CLASS_DIFFERENCE_BYTES_PROBES.len(),
        true,
        true,
    ),
    (
        HIR_CLASS_SYMMETRIC_DIFFERENCE_UNICODE_CASE_ID,
        HIR_CLASS_SYMMETRIC_DIFFERENCE_UNICODE_PROBES.len(),
        true,
        true,
    ),
    (
        HIR_CLASS_SYMMETRIC_DIFFERENCE_BYTES_CASE_ID,
        HIR_CLASS_SYMMETRIC_DIFFERENCE_BYTES_PROBES.len(),
        true,
        true,
    ),
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
        if is_supported_hir_doctest_case(&obligation.case_id) {
            return execute_hir_doctest_case(&obligation.case_id);
        }
        return RegexSyntaxCorpusDisposition::Unsupported {
            reason_code: "fre-adapter.doctest-not-implemented".to_owned(),
        };
    }
    if intrinsic_unobservable_reason(&obligation.case_id).is_some() {
        return RegexSyntaxCorpusDisposition::Unsupported {
            reason_code: INTRINSIC_UNOBSERVABLE_REASON_CODE.to_owned(),
        };
    }
    if is_supported_utf8_case(&obligation.case_id) {
        return execute_utf8_case(&obligation.case_id);
    }
    if is_supported_top_level_case(&obligation.case_id) {
        return execute_top_level_case(&obligation.case_id);
    }
    if is_supported_hir_misc_case(&obligation.case_id) {
        return execute_hir_misc_case(&obligation.case_id);
    }
    if is_supported_hir_class_operation_case(&obligation.case_id) {
        return execute_hir_class_operation_case(&obligation.case_id);
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
    if obligation.case_id.starts_with(HIR_LITERAL_PREFIX) {
        if is_supported_hir_literal_case(&obligation.case_id) {
            return execute_hir_literal_case(&obligation.case_id);
        }
        return RegexSyntaxCorpusDisposition::Unsupported {
            reason_code: "fre-adapter.hir-literal-not-implemented".to_owned(),
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

fn is_supported_hir_literal_case(case_id: &str) -> bool {
    matches!(
        case_id,
        HIR_LITERAL_LITERAL_CASE_ID
            | HIR_LITERAL_CLASS_CASE_ID
            | HIR_LITERAL_LOOK_CASE_ID
            | HIR_LITERAL_REPETITION_CASE_ID
            | HIR_LITERAL_CONCAT_CASE_ID
            | HIR_LITERAL_ALTERNATION_CASE_ID
            | HIR_LITERAL_IMPOSSIBLE_CASE_ID
            | HIR_LITERAL_ANYTHING_CASE_ID
            | HIR_LITERAL_ANYTHING_SMALL_LIMITS_CASE_ID
            | HIR_LITERAL_EMPTY_CASE_ID
            | HIR_LITERAL_ODDS_AND_ENDS_CASE_ID
            | HIR_LITERAL_HOLMES_CASE_ID
            | HIR_LITERAL_HOLMES_ALT_CASE_ID
    )
}

fn is_supported_hir_class_operation_case(case_id: &str) -> bool {
    matches!(
        case_id,
        HIR_CLASS_CASE_FOLD_UNICODE_CASE_ID
            | HIR_CLASS_CASE_FOLD_BYTES_CASE_ID
            | HIR_CLASS_NEGATE_UNICODE_CASE_ID
            | HIR_CLASS_NEGATE_BYTES_CASE_ID
            | HIR_CLASS_UNION_UNICODE_CASE_ID
            | HIR_CLASS_UNION_BYTES_CASE_ID
            | HIR_CLASS_INTERSECT_UNICODE_CASE_ID
            | HIR_CLASS_INTERSECT_BYTES_CASE_ID
            | HIR_CLASS_DIFFERENCE_UNICODE_CASE_ID
            | HIR_CLASS_DIFFERENCE_BYTES_CASE_ID
            | HIR_CLASS_SYMMETRIC_DIFFERENCE_UNICODE_CASE_ID
            | HIR_CLASS_SYMMETRIC_DIFFERENCE_BYTES_CASE_ID
    )
}

fn is_supported_hir_misc_case(case_id: &str) -> bool {
    matches!(
        case_id,
        HIR_CLASS_CANONICALIZE_UNICODE_CASE_ID
            | HIR_CLASS_CANONICALIZE_BYTES_CASE_ID
            | HIR_CLASS_RANGE_CANONICAL_UNICODE_CASE_ID
            | HIR_CLASS_RANGE_CANONICAL_BYTES_CASE_ID
            | HIR_LOOK_SET_ITER_CASE_ID
            | HIR_LOOK_SET_DEBUG_CASE_ID
            | HIR_NO_STACK_OVERFLOW_ON_DROP_CASE_ID
    )
}

fn is_supported_utf8_case(case_id: &str) -> bool {
    matches!(
        case_id,
        UTF8_BMP_CASE_ID
            | UTF8_CODEPOINTS_NO_SURROGATES_CASE_ID
            | UTF8_REVERSE_CASE_ID
            | UTF8_SINGLE_CODEPOINT_CASE_ID
    )
}

fn is_supported_top_level_case(case_id: &str) -> bool {
    matches!(
        case_id,
        TOP_ESCAPE_META_CASE_ID | TOP_WORD_BYTE_CASE_ID | TOP_WORD_CHAR_CASE_ID
    )
}

fn is_supported_top_level_doctest_case(case_id: &str) -> bool {
    matches!(
        case_id,
        TOP_DOCTEST_PARSE_CASE_ID | TOP_DOCTEST_META_CASE_ID | TOP_DOCTEST_ESCAPEABLE_CASE_ID
    )
}

fn is_supported_hir_doctest_case(case_id: &str) -> bool {
    matches!(
        case_id,
        HIR_DOCTEST_EXTRACT_PREFIX_CASE_ID
            | HIR_DOCTEST_EXTRACT_SUFFIX_CASE_ID
            | HIR_DOCTEST_LIMIT_CLASS_CASE_ID
            | HIR_DOCTEST_LIMIT_REPEAT_CASE_ID
            | HIR_DOCTEST_LIMIT_LITERAL_LEN_CASE_ID
            | HIR_DOCTEST_LIMIT_TOTAL_CASE_ID
            | HIR_DOCTEST_CLASS_MINIMUM_LEN_CASE_ID
            | HIR_DOCTEST_CLASS_MAXIMUM_LEN_CASE_ID
            | HIR_DOCTEST_PROPERTIES_IS_UTF8_CASE_ID
            | HIR_DOCTEST_PROPERTIES_CAPTURES_LEN_CASE_ID
            | HIR_DOCTEST_PROPERTIES_STATIC_CAPTURES_LEN_CASE_ID
            | HIR_DOCTEST_PROPERTIES_UNION_NEVER_CASE_ID
            | HIR_DOCTEST_PROPERTIES_UNION_UNBOUNDED_CASE_ID
    ) || case_id == UTF8_DOCTEST_SEQUENCES_CASE_ID
        || is_supported_top_level_doctest_case(case_id)
        || is_supported_hir_seq_doctest_case(case_id)
        || is_supported_hir_constructor_doctest_case(case_id)
}

fn is_supported_hir_seq_doctest_case(case_id: &str) -> bool {
    matches!(
        case_id,
        HIR_DOCTEST_SEQ_CASE_ID
            | HIR_DOCTEST_SEQ_CROSS_FORWARD_BASIC_CASE_ID
            | HIR_DOCTEST_SEQ_CROSS_FORWARD_INFINITE_OTHER_CASE_ID
            | HIR_DOCTEST_SEQ_CROSS_FORWARD_EMPTY_CASE_ID
            | HIR_DOCTEST_SEQ_CROSS_FORWARD_INFINITE_SELF_CASE_ID
            | HIR_DOCTEST_SEQ_CROSS_REVERSE_BASIC_CASE_ID
            | HIR_DOCTEST_SEQ_CROSS_REVERSE_INFINITE_OTHER_CASE_ID
            | HIR_DOCTEST_SEQ_CROSS_REVERSE_EMPTY_CASE_ID
            | HIR_DOCTEST_SEQ_CROSS_REVERSE_INFINITE_SELF_CASE_ID
            | HIR_DOCTEST_SEQ_UNION_BASIC_CASE_ID
            | HIR_DOCTEST_SEQ_UNION_INFINITE_CASE_ID
            | HIR_DOCTEST_SEQ_UNION_EMPTY_BASIC_CASE_ID
            | HIR_DOCTEST_SEQ_UNION_EMPTY_NO_SPLICE_CASE_ID
            | HIR_DOCTEST_SEQ_DEDUP_CASE_ID
            | HIR_DOCTEST_SEQ_SORT_CASE_ID
            | HIR_DOCTEST_SEQ_REVERSE_LITERALS_CASE_ID
            | HIR_DOCTEST_SEQ_MINIMIZE_PREFIX_CASE_ID
            | HIR_DOCTEST_SEQ_MINIMIZE_EMPTY_CASE_ID
            | HIR_DOCTEST_SEQ_KEEP_FIRST_CASE_ID
            | HIR_DOCTEST_SEQ_KEEP_LAST_CASE_ID
            | HIR_DOCTEST_SEQ_COMMON_PREFIX_CASE_ID
            | HIR_DOCTEST_SEQ_COMMON_SUFFIX_CASE_ID
            | HIR_DOCTEST_SEQ_OPTIMIZE_PREFIX_CASE_ID
            | HIR_DOCTEST_SEQ_OPTIMIZE_INFINITE_CASE_ID
            | HIR_DOCTEST_SEQ_OPTIMIZE_SPACE_CASE_ID
    )
}

fn is_supported_hir_constructor_doctest_case(case_id: &str) -> bool {
    matches!(
        case_id,
        HIR_DOCTEST_HIR_LITERAL_BYTES_CASE_ID
            | HIR_DOCTEST_HIR_LITERAL_CHAR_CASE_ID
            | HIR_DOCTEST_HIR_CONCAT_CASE_ID
            | HIR_DOCTEST_HIR_ALTERNATION_CLASS_CASE_ID
            | HIR_DOCTEST_HIR_ALTERNATION_PREFIX_CASE_ID
            | HIR_DOCTEST_HIR_DOT_CASE_ID
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
            | HIR_TRANSLATE_CAT_CLASS_FLATTENED_CASE_ID
            | HIR_TRANSLATE_CLASS_BRACKETED_CASE_ID
            | HIR_TRANSLATE_CLASS_BRACKETED_UNION_CASE_ID
            | HIR_TRANSLATE_CLASS_BRACKETED_NESTED_CASE_ID
            | HIR_TRANSLATE_CLASS_BRACKETED_INTERSECT_CASE_ID
            | HIR_TRANSLATE_CLASS_BRACKETED_INTERSECT_NEGATE_CASE_ID
            | HIR_TRANSLATE_CLASS_BRACKETED_DIFFERENCE_CASE_ID
            | HIR_TRANSLATE_CLASS_BRACKETED_SYMMETRIC_DIFFERENCE_CASE_ID
            | HIR_TRANSLATE_LITERAL_CASE_ID
            | HIR_TRANSLATE_DOT_CASE_ID
            | HIR_TRANSLATE_CLASS_ASCII_CASE_ID
            | HIR_TRANSLATE_CLASS_PERL_ASCII_CASE_ID
            | HIR_TRANSLATE_CLASS_PERL_UNICODE_CASE_ID
            | HIR_TRANSLATE_CLASS_UNICODE_GENCAT_CASE_ID
            | HIR_TRANSLATE_CLASS_UNICODE_SCRIPT_CASE_ID
            | HIR_TRANSLATE_CLASS_UNICODE_AGE_CASE_ID
            | HIR_TRANSLATE_CLASS_UNICODE_ANY_EMPTY_CASE_ID
            | HIR_TRANSLATE_REGRESSION_FUZZ_MATCH_CASE_ID
            | HIR_TRANSLATE_REGRESSION_FUZZ_DIFFERENCE_CASE_ID
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

fn execute_hir_literal_case(case_id: &str) -> RegexSyntaxCorpusDisposition {
    let execution = catch_unwind(AssertUnwindSafe(|| run_hir_literal_case(case_id)));
    match execution {
        Ok(Ok(())) => RegexSyntaxCorpusDisposition::Pass {
            evidence_sha256: hir_literal_pass_evidence(case_id),
        },
        Ok(Err(mismatch)) => RegexSyntaxCorpusDisposition::Mismatch {
            evidence_sha256: hir_literal_mismatch_evidence(
                case_id,
                &mismatch.expected,
                &mismatch.observed,
            ),
            expected: mismatch.expected,
            observed: mismatch.observed,
        },
        Err(_) => RegexSyntaxCorpusDisposition::Fault {
            stage: "fre-hir-literal-adapter".to_owned(),
            reason_code: "candidate.adapter-panicked".to_owned(),
        },
    }
}

fn execute_hir_class_operation_case(case_id: &str) -> RegexSyntaxCorpusDisposition {
    let execution = catch_unwind(AssertUnwindSafe(|| run_hir_class_operation_case(case_id)));
    match execution {
        Ok(Ok(())) => RegexSyntaxCorpusDisposition::Pass {
            evidence_sha256: hir_class_operation_pass_evidence(case_id),
        },
        Ok(Err(mismatch)) => RegexSyntaxCorpusDisposition::Mismatch {
            evidence_sha256: hir_class_operation_mismatch_evidence(
                case_id,
                &mismatch.expected,
                &mismatch.observed,
            ),
            expected: mismatch.expected,
            observed: mismatch.observed,
        },
        Err(_) => RegexSyntaxCorpusDisposition::Fault {
            stage: "fre-hir-class-operation-adapter".to_owned(),
            reason_code: "candidate.adapter-panicked".to_owned(),
        },
    }
}

fn execute_hir_misc_case(case_id: &str) -> RegexSyntaxCorpusDisposition {
    let execution = catch_unwind(AssertUnwindSafe(|| run_hir_misc_case(case_id)));
    match execution {
        Ok(Ok(())) => RegexSyntaxCorpusDisposition::Pass {
            evidence_sha256: hir_misc_pass_evidence(case_id),
        },
        Ok(Err(mismatch)) => RegexSyntaxCorpusDisposition::Mismatch {
            evidence_sha256: hir_misc_mismatch_evidence(
                case_id,
                &mismatch.expected,
                &mismatch.observed,
            ),
            expected: mismatch.expected,
            observed: mismatch.observed,
        },
        Err(_) => RegexSyntaxCorpusDisposition::Fault {
            stage: "fre-hir-misc-adapter".to_owned(),
            reason_code: "candidate.adapter-panicked".to_owned(),
        },
    }
}

fn execute_utf8_case(case_id: &str) -> RegexSyntaxCorpusDisposition {
    let execution = catch_unwind(AssertUnwindSafe(|| run_utf8_case(case_id)));
    match execution {
        Ok(Ok(())) => RegexSyntaxCorpusDisposition::Pass {
            evidence_sha256: utf8_pass_evidence(case_id),
        },
        Ok(Err(mismatch)) => RegexSyntaxCorpusDisposition::Mismatch {
            evidence_sha256: utf8_mismatch_evidence(
                case_id,
                &mismatch.expected,
                &mismatch.observed,
            ),
            expected: mismatch.expected,
            observed: mismatch.observed,
        },
        Err(_) => RegexSyntaxCorpusDisposition::Fault {
            stage: "fre-utf8-adapter".to_owned(),
            reason_code: "candidate.adapter-panicked".to_owned(),
        },
    }
}

fn execute_top_level_case(case_id: &str) -> RegexSyntaxCorpusDisposition {
    let execution = catch_unwind(AssertUnwindSafe(|| run_top_level_case(case_id)));
    match execution {
        Ok(Ok(())) => RegexSyntaxCorpusDisposition::Pass {
            evidence_sha256: top_level_pass_evidence(case_id),
        },
        Ok(Err(mismatch)) => RegexSyntaxCorpusDisposition::Mismatch {
            evidence_sha256: top_level_mismatch_evidence(
                case_id,
                &mismatch.expected,
                &mismatch.observed,
            ),
            expected: mismatch.expected,
            observed: mismatch.observed,
        },
        Err(_) => RegexSyntaxCorpusDisposition::Fault {
            stage: "fre-top-level-syntax-adapter".to_owned(),
            reason_code: "candidate.adapter-panicked".to_owned(),
        },
    }
}

fn execute_hir_doctest_case(case_id: &str) -> RegexSyntaxCorpusDisposition {
    let execution = catch_unwind(AssertUnwindSafe(|| run_hir_doctest_case(case_id)));
    match execution {
        Ok(Ok(())) => RegexSyntaxCorpusDisposition::Pass {
            evidence_sha256: hir_doctest_pass_evidence(case_id),
        },
        Ok(Err(mismatch)) => RegexSyntaxCorpusDisposition::Mismatch {
            evidence_sha256: hir_doctest_mismatch_evidence(
                case_id,
                &mismatch.expected,
                &mismatch.observed,
            ),
            expected: mismatch.expected,
            observed: mismatch.observed,
        },
        Err(_) => RegexSyntaxCorpusDisposition::Fault {
            stage: "fre-hir-doctest-adapter".to_owned(),
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

fn run_hir_literal_case(case_id: &str) -> Result<(), AstMismatch> {
    let (probes, label, limit_total) = hir_literal_probes(case_id);
    for (index, pattern) in probes.iter().copied().enumerate() {
        execute_hir_literal_probe(pattern, limit_total, &format!("{label}-{index}"))?;
    }
    if case_id == HIR_LITERAL_HOLMES_CASE_ID {
        execute_hir_literal_holmes_probe(probes[0], label)?;
    } else if case_id == HIR_LITERAL_HOLMES_ALT_CASE_ID {
        execute_hir_literal_holmes_alt_probe(probes[0], label)?;
    }
    Ok(())
}

fn hir_literal_probes(case_id: &str) -> (&'static [&'static str], &'static str, Option<usize>) {
    match case_id {
        HIR_LITERAL_LITERAL_CASE_ID => (&HIR_LITERAL_LITERAL_PROBES, "hir-literal-literal", None),
        HIR_LITERAL_CLASS_CASE_ID => (&HIR_LITERAL_CLASS_PROBES, "hir-literal-class", None),
        HIR_LITERAL_LOOK_CASE_ID => (&HIR_LITERAL_LOOK_PROBES, "hir-literal-look", None),
        HIR_LITERAL_REPETITION_CASE_ID => (
            &HIR_LITERAL_REPETITION_PROBES,
            "hir-literal-repetition",
            None,
        ),
        HIR_LITERAL_CONCAT_CASE_ID => (&HIR_LITERAL_CONCAT_PROBES, "hir-literal-concat", None),
        HIR_LITERAL_ALTERNATION_CASE_ID => (
            &HIR_LITERAL_ALTERNATION_PROBES,
            "hir-literal-alternation",
            None,
        ),
        HIR_LITERAL_IMPOSSIBLE_CASE_ID => (
            &HIR_LITERAL_IMPOSSIBLE_PROBES,
            "hir-literal-impossible",
            None,
        ),
        HIR_LITERAL_ANYTHING_CASE_ID => {
            (&HIR_LITERAL_ANYTHING_PROBES, "hir-literal-anything", None)
        }
        HIR_LITERAL_ANYTHING_SMALL_LIMITS_CASE_ID => (
            &HIR_LITERAL_ANYTHING_SMALL_LIMITS_PROBES,
            "hir-literal-anything-small-limits",
            Some(10),
        ),
        HIR_LITERAL_EMPTY_CASE_ID => (&HIR_LITERAL_EMPTY_PROBES, "hir-literal-empty", None),
        HIR_LITERAL_ODDS_AND_ENDS_CASE_ID => (
            &HIR_LITERAL_ODDS_AND_ENDS_PROBES,
            "hir-literal-odds-and-ends",
            None,
        ),
        HIR_LITERAL_HOLMES_CASE_ID => (&HIR_LITERAL_HOLMES_PROBES, "hir-literal-holmes", None),
        HIR_LITERAL_HOLMES_ALT_CASE_ID => (
            &HIR_LITERAL_HOLMES_ALT_PROBES,
            "hir-literal-holmes-alt",
            None,
        ),
        _ => unreachable!("caller checked supported HIR literal case"),
    }
}

fn execute_hir_literal_probe(
    pattern: &str,
    limit_total: Option<usize>,
    assertion: &str,
) -> Result<(), AstMismatch> {
    let rust_profile = RustProfile::regex_1_12_4();
    let compatibility = CompatibilityProfile::RustBytes(rust_profile);
    let expected_hir = regex_syntax::ParserBuilder::new()
        .utf8(false)
        .build()
        .parse(pattern)
        .map_err(|error| AstMismatch {
            expected: format!("{assertion}: authenticated upstream HIR parse succeeds"),
            observed: format!("{assertion}: upstream HIR parse error {error:?}"),
        })?;
    let record =
        parse(ParseRequest::rust(pattern, compatibility.clone())).map_err(|error| AstMismatch {
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
        && record.key.pattern.as_bytes() == pattern.as_bytes()
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
    for (kind, kind_label) in [
        (regex_syntax::hir::literal::ExtractKind::Prefix, "prefix"),
        (regex_syntax::hir::literal::ExtractKind::Suffix, "suffix"),
    ] {
        let mut expected_extractor = regex_syntax::hir::literal::Extractor::new();
        expected_extractor.kind(kind.clone());
        if let Some(limit) = limit_total {
            expected_extractor.limit_total(limit);
        }
        let expected = expected_extractor.extract(&expected_hir);
        let mut observed_extractor = regex_syntax::hir::literal::Extractor::new();
        observed_extractor.kind(kind);
        if let Some(limit) = limit_total {
            observed_extractor.limit_total(limit);
        }
        let observed = observed_extractor.extract(&parsed.hir);
        if observed != expected {
            return Err(AstMismatch {
                expected: format!("{assertion}: {kind_label} extraction {expected:?}"),
                observed: format!("{assertion}: {kind_label} extraction {observed:?}"),
            });
        }
    }
    Ok(())
}

fn extract_hir_literal_sequence(
    hir: &regex_syntax::hir::Hir,
    kind: regex_syntax::hir::literal::ExtractKind,
) -> regex_syntax::hir::literal::Seq {
    regex_syntax::hir::literal::Extractor::new()
        .kind(kind)
        .extract(hir)
}

fn execute_hir_literal_holmes_probe(pattern: &str, assertion: &str) -> Result<(), AstMismatch> {
    let (expected_hir, observed_hir) = exact_hir_pair(pattern, assertion)?;
    let mut expected_prefixes = extract_hir_literal_sequence(
        &expected_hir,
        regex_syntax::hir::literal::ExtractKind::Prefix,
    );
    let mut expected_suffixes = extract_hir_literal_sequence(
        &expected_hir,
        regex_syntax::hir::literal::ExtractKind::Suffix,
    );
    let mut observed_prefixes = extract_hir_literal_sequence(
        &observed_hir,
        regex_syntax::hir::literal::ExtractKind::Prefix,
    );
    let mut observed_suffixes = extract_hir_literal_sequence(
        &observed_hir,
        regex_syntax::hir::literal::ExtractKind::Suffix,
    );
    expected_prefixes.keep_first_bytes(3);
    expected_suffixes.keep_last_bytes(3);
    expected_prefixes.minimize_by_preference();
    expected_suffixes.minimize_by_preference();
    observed_prefixes.keep_first_bytes(3);
    observed_suffixes.keep_last_bytes(3);
    observed_prefixes.minimize_by_preference();
    observed_suffixes.minimize_by_preference();
    let expected = (expected_prefixes, expected_suffixes);
    let observed = (observed_prefixes, observed_suffixes);
    if observed == expected {
        Ok(())
    } else {
        Err(AstMismatch {
            expected: format!("{assertion}: exact three-byte minimized sequences {expected:?}"),
            observed: format!("{assertion}: {observed:?}"),
        })
    }
}

fn execute_hir_literal_holmes_alt_probe(pattern: &str, assertion: &str) -> Result<(), AstMismatch> {
    let (expected_hir, observed_hir) = exact_hir_pair(pattern, assertion)?;
    let mut expected = extract_hir_literal_sequence(
        &expected_hir,
        regex_syntax::hir::literal::ExtractKind::Prefix,
    );
    let mut observed = extract_hir_literal_sequence(
        &observed_hir,
        regex_syntax::hir::literal::ExtractKind::Prefix,
    );
    let initial_nonempty =
        expected.len().is_some_and(|len| len > 0) && observed.len().is_some_and(|len| len > 0);
    expected.optimize_for_prefix_by_preference();
    observed.optimize_for_prefix_by_preference();
    let optimized_nonempty =
        expected.len().is_some_and(|len| len > 0) && observed.len().is_some_and(|len| len > 0);
    if initial_nonempty && optimized_nonempty && observed == expected {
        Ok(())
    } else {
        Err(AstMismatch {
            expected: format!("{assertion}: nonempty exact optimized prefix sequence {expected:?}"),
            observed: format!("{assertion}: initial-nonempty={initial_nonempty}, {observed:?}"),
        })
    }
}

fn run_hir_class_operation_case(case_id: &str) -> Result<(), AstMismatch> {
    if let Some((probes, operation, label)) = hir_unicode_class_operation_probes(case_id) {
        for (index, probe) in probes.iter().copied().enumerate() {
            execute_hir_unicode_class_operation_probe(
                probe,
                operation,
                &format!("{label}-{index}"),
            )?;
        }
        return Ok(());
    }
    let (probes, operation, label) = hir_bytes_class_operation_probes(case_id)
        .expect("caller checked supported HIR class operation case");
    for (index, probe) in probes.iter().copied().enumerate() {
        execute_hir_bytes_class_operation_probe(probe, operation, &format!("{label}-{index}"))?;
    }
    Ok(())
}

fn hir_unicode_class_operation_probes(
    case_id: &str,
) -> Option<(
    &'static [HirUnicodeClassProbe],
    HirClassOperation,
    &'static str,
)> {
    match case_id {
        HIR_CLASS_CASE_FOLD_UNICODE_CASE_ID => Some((
            &HIR_CLASS_CASE_FOLD_UNICODE_PROBES,
            HirClassOperation::CaseFold,
            "hir-class-case-fold-unicode",
        )),
        HIR_CLASS_NEGATE_UNICODE_CASE_ID => Some((
            &HIR_CLASS_NEGATE_UNICODE_PROBES,
            HirClassOperation::Negate,
            "hir-class-negate-unicode",
        )),
        HIR_CLASS_UNION_UNICODE_CASE_ID => Some((
            &HIR_CLASS_UNION_UNICODE_PROBES,
            HirClassOperation::Union,
            "hir-class-union-unicode",
        )),
        HIR_CLASS_INTERSECT_UNICODE_CASE_ID => Some((
            &HIR_CLASS_INTERSECT_UNICODE_PROBES,
            HirClassOperation::Intersect,
            "hir-class-intersect-unicode",
        )),
        HIR_CLASS_DIFFERENCE_UNICODE_CASE_ID => Some((
            &HIR_CLASS_DIFFERENCE_UNICODE_PROBES,
            HirClassOperation::Difference,
            "hir-class-difference-unicode",
        )),
        HIR_CLASS_SYMMETRIC_DIFFERENCE_UNICODE_CASE_ID => Some((
            &HIR_CLASS_SYMMETRIC_DIFFERENCE_UNICODE_PROBES,
            HirClassOperation::SymmetricDifference,
            "hir-class-symmetric-difference-unicode",
        )),
        _ => None,
    }
}

fn hir_bytes_class_operation_probes(
    case_id: &str,
) -> Option<(
    &'static [HirBytesClassProbe],
    HirClassOperation,
    &'static str,
)> {
    match case_id {
        HIR_CLASS_CASE_FOLD_BYTES_CASE_ID => Some((
            &HIR_CLASS_CASE_FOLD_BYTES_PROBES,
            HirClassOperation::CaseFold,
            "hir-class-case-fold-bytes",
        )),
        HIR_CLASS_NEGATE_BYTES_CASE_ID => Some((
            &HIR_CLASS_NEGATE_BYTES_PROBES,
            HirClassOperation::Negate,
            "hir-class-negate-bytes",
        )),
        HIR_CLASS_UNION_BYTES_CASE_ID => Some((
            &HIR_CLASS_UNION_BYTES_PROBES,
            HirClassOperation::Union,
            "hir-class-union-bytes",
        )),
        HIR_CLASS_INTERSECT_BYTES_CASE_ID => Some((
            &HIR_CLASS_INTERSECT_BYTES_PROBES,
            HirClassOperation::Intersect,
            "hir-class-intersect-bytes",
        )),
        HIR_CLASS_DIFFERENCE_BYTES_CASE_ID => Some((
            &HIR_CLASS_DIFFERENCE_BYTES_PROBES,
            HirClassOperation::Difference,
            "hir-class-difference-bytes",
        )),
        HIR_CLASS_SYMMETRIC_DIFFERENCE_BYTES_CASE_ID => Some((
            &HIR_CLASS_SYMMETRIC_DIFFERENCE_BYTES_PROBES,
            HirClassOperation::SymmetricDifference,
            "hir-class-symmetric-difference-bytes",
        )),
        _ => None,
    }
}

fn unicode_class_pattern(ranges: &[(char, char)]) -> String {
    if ranges.is_empty() {
        return r"[\p{Greek}&&\P{Greek}]".to_owned();
    }
    let mut pattern = String::from("[");
    for &(start, end) in ranges {
        write!(
            pattern,
            r"\x{{{:X}}}-\x{{{:X}}}",
            u32::from(start),
            u32::from(end)
        )
        .expect("writing to a String cannot fail");
    }
    pattern.push(']');
    pattern
}

fn bytes_class_pattern(ranges: &[(u8, u8)]) -> String {
    if ranges.is_empty() {
        return "(?-u:[a&&b])".to_owned();
    }
    let mut pattern = String::from("(?-u:[");
    for &(start, end) in ranges {
        write!(pattern, r"\x{start:02X}-\x{end:02X}").expect("writing to a String cannot fail");
    }
    pattern.push_str("])");
    pattern
}

fn exact_hir_pair(
    pattern: &str,
    assertion: &str,
) -> Result<(regex_syntax::hir::Hir, regex_syntax::hir::Hir), AstMismatch> {
    let compatibility = CompatibilityProfile::RustBytes(RustProfile::regex_1_12_4());
    let expected_hir = regex_syntax::ParserBuilder::new()
        .utf8(false)
        .build()
        .parse(pattern)
        .map_err(|error| AstMismatch {
            expected: format!("{assertion}: authenticated upstream HIR parse succeeds"),
            observed: format!("{assertion}: upstream HIR parse error {error:?}"),
        })?;
    let record =
        parse(ParseRequest::rust(pattern, compatibility.clone())).map_err(|error| AstMismatch {
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
        && record.key.pattern.as_bytes() == pattern.as_bytes()
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
    Ok((expected_hir, parsed.hir.clone()))
}

fn unicode_class_from_hir(
    hir: &regex_syntax::hir::Hir,
    assertion: &str,
) -> Result<regex_syntax::hir::ClassUnicode, AstMismatch> {
    match hir.kind() {
        regex_syntax::hir::HirKind::Class(regex_syntax::hir::Class::Unicode(class)) => {
            Ok(class.clone())
        }
        regex_syntax::hir::HirKind::Class(regex_syntax::hir::Class::Bytes(class))
            if class.iter().next().is_none() =>
        {
            Ok(regex_syntax::hir::ClassUnicode::empty())
        }
        regex_syntax::hir::HirKind::Literal(literal) => {
            let text = std::str::from_utf8(&literal.0).map_err(|error| AstMismatch {
                expected: format!("{assertion}: one Unicode literal scalar"),
                observed: format!("{assertion}: literal UTF-8 error {error:?}"),
            })?;
            let mut chars = text.chars();
            let Some(c) = chars.next() else {
                return Err(AstMismatch {
                    expected: format!("{assertion}: one Unicode literal scalar"),
                    observed: format!("{assertion}: empty literal"),
                });
            };
            if chars.next().is_some() {
                return Err(AstMismatch {
                    expected: format!("{assertion}: one Unicode literal scalar"),
                    observed: format!("{assertion}: multi-scalar literal {text:?}"),
                });
            }
            Ok(regex_syntax::hir::ClassUnicode::new([
                regex_syntax::hir::ClassUnicodeRange::new(c, c),
            ]))
        }
        kind => Err(AstMismatch {
            expected: format!("{assertion}: Unicode class or singleton literal"),
            observed: format!("{assertion}: {kind:?}"),
        }),
    }
}

fn bytes_class_from_hir(
    hir: &regex_syntax::hir::Hir,
    assertion: &str,
) -> Result<regex_syntax::hir::ClassBytes, AstMismatch> {
    match hir.kind() {
        regex_syntax::hir::HirKind::Class(regex_syntax::hir::Class::Bytes(class)) => {
            Ok(class.clone())
        }
        regex_syntax::hir::HirKind::Class(regex_syntax::hir::Class::Unicode(class))
            if class.iter().next().is_none() =>
        {
            Ok(regex_syntax::hir::ClassBytes::empty())
        }
        regex_syntax::hir::HirKind::Literal(literal) if literal.0.len() == 1 => {
            let byte = literal.0[0];
            Ok(regex_syntax::hir::ClassBytes::new([
                regex_syntax::hir::ClassBytesRange::new(byte, byte),
            ]))
        }
        kind => Err(AstMismatch {
            expected: format!("{assertion}: bytes class or singleton literal"),
            observed: format!("{assertion}: {kind:?}"),
        }),
    }
}

fn execute_hir_unicode_class_operation_probe(
    probe: HirUnicodeClassProbe,
    operation: HirClassOperation,
    assertion: &str,
) -> Result<(), AstMismatch> {
    let left_pattern = unicode_class_pattern(probe.left);
    let (expected_left_hir, observed_left_hir) =
        exact_hir_pair(&left_pattern, &format!("{assertion}-left"))?;
    let direct_left = regex_syntax::hir::ClassUnicode::new(
        probe
            .left
            .iter()
            .copied()
            .map(|(start, end)| regex_syntax::hir::ClassUnicodeRange::new(start, end)),
    );
    let mut expected = unicode_class_from_hir(&expected_left_hir, assertion)?;
    let mut observed = unicode_class_from_hir(&observed_left_hir, assertion)?;
    if expected != direct_left || observed != direct_left {
        return Err(AstMismatch {
            expected: format!("{assertion}: source operand {direct_left:?}"),
            observed: format!("{assertion}: upstream={expected:?}, FRE={observed:?}"),
        });
    }
    if matches!(operation, HirClassOperation::CaseFold) {
        expected.case_fold_simple();
        observed.case_fold_simple();
    } else if matches!(operation, HirClassOperation::Negate) {
        expected.negate();
        observed.negate();
    } else {
        let right_pattern = unicode_class_pattern(probe.right);
        let (expected_right_hir, observed_right_hir) =
            exact_hir_pair(&right_pattern, &format!("{assertion}-right"))?;
        let direct_right = regex_syntax::hir::ClassUnicode::new(
            probe
                .right
                .iter()
                .copied()
                .map(|(start, end)| regex_syntax::hir::ClassUnicodeRange::new(start, end)),
        );
        let expected_right = unicode_class_from_hir(&expected_right_hir, assertion)?;
        let observed_right = unicode_class_from_hir(&observed_right_hir, assertion)?;
        if expected_right != direct_right || observed_right != direct_right {
            return Err(AstMismatch {
                expected: format!("{assertion}: source operand {direct_right:?}"),
                observed: format!(
                    "{assertion}: upstream={expected_right:?}, FRE={observed_right:?}"
                ),
            });
        }
        apply_unicode_class_operation(&mut expected, &expected_right, operation);
        apply_unicode_class_operation(&mut observed, &observed_right, operation);
    }
    if observed == expected {
        Ok(())
    } else {
        Err(AstMismatch {
            expected: format!("{assertion}: {operation:?} {expected:?}"),
            observed: format!("{assertion}: {operation:?} {observed:?}"),
        })
    }
}

fn apply_unicode_class_operation(
    left: &mut regex_syntax::hir::ClassUnicode,
    right: &regex_syntax::hir::ClassUnicode,
    operation: HirClassOperation,
) {
    match operation {
        HirClassOperation::Union => left.union(right),
        HirClassOperation::Intersect => left.intersect(right),
        HirClassOperation::Difference => left.difference(right),
        HirClassOperation::SymmetricDifference => left.symmetric_difference(right),
        HirClassOperation::CaseFold | HirClassOperation::Negate => {
            unreachable!("unary class operation handled by caller")
        }
    }
}

fn execute_hir_bytes_class_operation_probe(
    probe: HirBytesClassProbe,
    operation: HirClassOperation,
    assertion: &str,
) -> Result<(), AstMismatch> {
    let left_pattern = bytes_class_pattern(probe.left);
    let (expected_left_hir, observed_left_hir) =
        exact_hir_pair(&left_pattern, &format!("{assertion}-left"))?;
    let direct_left = regex_syntax::hir::ClassBytes::new(
        probe
            .left
            .iter()
            .copied()
            .map(|(start, end)| regex_syntax::hir::ClassBytesRange::new(start, end)),
    );
    let mut expected = bytes_class_from_hir(&expected_left_hir, assertion)?;
    let mut observed = bytes_class_from_hir(&observed_left_hir, assertion)?;
    if expected != direct_left || observed != direct_left {
        return Err(AstMismatch {
            expected: format!("{assertion}: source operand {direct_left:?}"),
            observed: format!("{assertion}: upstream={expected:?}, FRE={observed:?}"),
        });
    }
    if matches!(operation, HirClassOperation::CaseFold) {
        expected.case_fold_simple();
        observed.case_fold_simple();
    } else if matches!(operation, HirClassOperation::Negate) {
        expected.negate();
        observed.negate();
    } else {
        let right_pattern = bytes_class_pattern(probe.right);
        let (expected_right_hir, observed_right_hir) =
            exact_hir_pair(&right_pattern, &format!("{assertion}-right"))?;
        let direct_right = regex_syntax::hir::ClassBytes::new(
            probe
                .right
                .iter()
                .copied()
                .map(|(start, end)| regex_syntax::hir::ClassBytesRange::new(start, end)),
        );
        let expected_right = bytes_class_from_hir(&expected_right_hir, assertion)?;
        let observed_right = bytes_class_from_hir(&observed_right_hir, assertion)?;
        if expected_right != direct_right || observed_right != direct_right {
            return Err(AstMismatch {
                expected: format!("{assertion}: source operand {direct_right:?}"),
                observed: format!(
                    "{assertion}: upstream={expected_right:?}, FRE={observed_right:?}"
                ),
            });
        }
        apply_bytes_class_operation(&mut expected, &expected_right, operation);
        apply_bytes_class_operation(&mut observed, &observed_right, operation);
    }
    if observed == expected {
        Ok(())
    } else {
        Err(AstMismatch {
            expected: format!("{assertion}: {operation:?} {expected:?}"),
            observed: format!("{assertion}: {operation:?} {observed:?}"),
        })
    }
}

fn apply_bytes_class_operation(
    left: &mut regex_syntax::hir::ClassBytes,
    right: &regex_syntax::hir::ClassBytes,
    operation: HirClassOperation,
) {
    match operation {
        HirClassOperation::Union => left.union(right),
        HirClassOperation::Intersect => left.intersect(right),
        HirClassOperation::Difference => left.difference(right),
        HirClassOperation::SymmetricDifference => left.symmetric_difference(right),
        HirClassOperation::CaseFold | HirClassOperation::Negate => {
            unreachable!("unary class operation handled by caller")
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the exhaustive match mirrors seven independently identified public HIR unit tests"
)]
fn run_hir_misc_case(case_id: &str) -> Result<(), AstMismatch> {
    use regex_syntax::hir::{
        Capture, ClassBytes, ClassBytesRange, ClassUnicode, ClassUnicodeRange, Hir, HirKind, Look,
        LookSet, Repetition,
    };

    match case_id {
        HIR_CLASS_RANGE_CANONICAL_UNICODE_CASE_ID => {
            let range = ClassUnicodeRange::new('\u{00FF}', '\0');
            hir_doctest_assert_eq(case_id, "start", &'\0', &range.start())?;
            hir_doctest_assert_eq(case_id, "end", &'\u{00FF}', &range.end())?;
            let (_, observed) = exact_text_hir_pair(r"[\x{0}-\x{FF}]", case_id)?;
            let observed = unicode_class_from_hir(&observed, case_id)?;
            hir_doctest_assert_eq(
                case_id,
                "fre-hir-binding",
                &ClassUnicode::new([range]),
                &observed,
            )?;
        }
        HIR_CLASS_RANGE_CANONICAL_BYTES_CASE_ID => {
            let range = ClassBytesRange::new(b'\xFF', b'\0');
            hir_doctest_assert_eq(case_id, "start", &b'\0', &range.start())?;
            hir_doctest_assert_eq(case_id, "end", &b'\xFF', &range.end())?;
            let (_, observed) = exact_hir_pair(r"(?-u:[\x00-\xFF])", case_id)?;
            let observed = bytes_class_from_hir(&observed, case_id)?;
            hir_doctest_assert_eq(
                case_id,
                "fre-hir-binding",
                &ClassBytes::new([range]),
                &observed,
            )?;
        }
        HIR_CLASS_CANONICALIZE_UNICODE_CASE_ID => {
            for (index, &(input, expected)) in
                HIR_CLASS_CANONICALIZE_UNICODE_PROBES.iter().enumerate()
            {
                let class = ClassUnicode::new(
                    input
                        .iter()
                        .copied()
                        .map(|(start, end)| ClassUnicodeRange::new(start, end)),
                );
                let observed_ranges = class
                    .iter()
                    .map(|range| (range.start(), range.end()))
                    .collect::<Vec<_>>();
                hir_doctest_assert_eq(
                    case_id,
                    &format!("source-assertion-{index}"),
                    &expected,
                    &observed_ranges.as_slice(),
                )?;
                let pattern = unicode_class_pattern(input);
                let (_, observed_hir) =
                    exact_text_hir_pair(&pattern, &format!("{case_id}-{index}"))?;
                let observed_class = unicode_class_from_hir(&observed_hir, case_id)?;
                hir_doctest_assert_eq(
                    case_id,
                    &format!("fre-hir-binding-{index}"),
                    &class,
                    &observed_class,
                )?;
            }
        }
        HIR_CLASS_CANONICALIZE_BYTES_CASE_ID => {
            for (index, &(input, expected)) in
                HIR_CLASS_CANONICALIZE_BYTES_PROBES.iter().enumerate()
            {
                let class = ClassBytes::new(
                    input
                        .iter()
                        .copied()
                        .map(|(start, end)| ClassBytesRange::new(start, end)),
                );
                let observed_ranges = class
                    .iter()
                    .map(|range| (range.start(), range.end()))
                    .collect::<Vec<_>>();
                hir_doctest_assert_eq(
                    case_id,
                    &format!("source-assertion-{index}"),
                    &expected,
                    &observed_ranges.as_slice(),
                )?;
                let pattern = bytes_class_pattern(input);
                let (_, observed_hir) = exact_hir_pair(&pattern, &format!("{case_id}-{index}"))?;
                let observed_class = bytes_class_from_hir(&observed_hir, case_id)?;
                hir_doctest_assert_eq(
                    case_id,
                    &format!("fre-hir-binding-{index}"),
                    &class,
                    &observed_class,
                )?;
            }
        }
        HIR_LOOK_SET_ITER_CASE_ID => {
            hir_doctest_assert_eq(case_id, "empty", &0, &LookSet::empty().iter().count())?;
            hir_doctest_assert_eq(case_id, "full", &18, &LookSet::full().iter().count())?;
            let set = LookSet::empty()
                .insert(Look::StartLF)
                .insert(Look::WordUnicode);
            hir_doctest_assert_eq(case_id, "two", &2, &set.iter().count())?;
            let set = LookSet::empty().insert(Look::StartLF);
            hir_doctest_assert_eq(case_id, "one-start", &1, &set.iter().count())?;
            let set = LookSet::empty().insert(Look::WordAsciiNegate);
            hir_doctest_assert_eq(case_id, "one-word", &1, &set.iter().count())?;
            let _ = exact_text_hir_pair(r"(?m:^)|\b", case_id)?;
        }
        HIR_LOOK_SET_DEBUG_CASE_ID => {
            hir_doctest_assert_eq(
                case_id,
                "empty",
                &"∅".to_owned(),
                &format!("{:?}", LookSet::empty()),
            )?;
            hir_doctest_assert_eq(
                case_id,
                "full",
                &"Az^$rRbB𝛃𝚩<>〈〉◁▷◀▶".to_owned(),
                &format!("{:?}", LookSet::full()),
            )?;
            let _ = exact_text_hir_pair(r"(?m:^)|\b", case_id)?;
        }
        HIR_NO_STACK_OVERFLOW_ON_DROP_CASE_ID => {
            let (_, seed) = exact_text_hir_pair("a", case_id)?;
            let joined = std::thread::Builder::new()
                .stack_size(16 << 10)
                .spawn(move || {
                    let mut expr = seed;
                    for _ in 0..100 {
                        expr = Hir::capture(Capture {
                            index: 1,
                            name: None,
                            sub: Box::new(expr),
                        });
                        expr = Hir::repetition(Repetition {
                            min: 0,
                            max: Some(1),
                            greedy: true,
                            sub: Box::new(expr),
                        });
                    }
                    !matches!(*expr.kind(), HirKind::Empty)
                })
                .map_err(|error| AstMismatch {
                    expected: format!("{case_id}: 16KiB-stack worker starts"),
                    observed: format!("{case_id}: {error:?}"),
                })?
                .join()
                .map_err(|_| AstMismatch {
                    expected: format!("{case_id}: bounded public HIR drops without stack overflow"),
                    observed: format!("{case_id}: worker panicked"),
                })?;
            hir_doctest_assert_eq(case_id, "non-empty", &true, &joined)?;
        }
        _ => unreachable!("caller checked supported HIR misc case"),
    }
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "the exhaustive match mirrors four unit tests and one public UTF-8 doctest"
)]
fn run_utf8_case(case_id: &str) -> Result<(), AstMismatch> {
    use regex_syntax::utf8::{Utf8Range, Utf8Sequence, Utf8Sequences};

    let rutf8 = |start, end| Utf8Range { start, end };
    match case_id {
        UTF8_CODEPOINTS_NO_SURROGATES_CASE_ID => {
            let ranges = [
                ('\0', '\u{FFFF}'),
                ('\0', '\u{10FFFF}'),
                ('\0', '\u{10FFFE}'),
                ('\u{80}', '\u{10FFFF}'),
                ('\u{D7FF}', '\u{E000}'),
            ];
            for (index, (start, end)) in ranges.into_iter().enumerate() {
                let seqs = Utf8Sequences::new(start, end).collect::<Vec<_>>();
                for codepoint in 0xD800..0xE000 {
                    let bytes = encode_surrogate_codepoint(codepoint);
                    if seqs.iter().any(|sequence| sequence.matches(&bytes)) {
                        return Err(AstMismatch {
                            expected: format!("{case_id}-{index}: no encoded surrogate matches"),
                            observed: format!(
                                "{case_id}-{index}: U+{codepoint:04X} matched by {seqs:?}"
                            ),
                        });
                    }
                }
            }
            let _ = exact_text_hir_pair(r"[\x{D7FF}-\x{E000}]", case_id)?;
        }
        UTF8_SINGLE_CODEPOINT_CASE_ID => {
            for codepoint in 0..=0x10_FFFF {
                let Some(c) = char::from_u32(codepoint) else {
                    continue;
                };
                let count = Utf8Sequences::new(c, c).count();
                if count != 1 {
                    return Err(AstMismatch {
                        expected: format!("{case_id}: U+{codepoint:04X} has one sequence"),
                        observed: format!("{case_id}: {count}"),
                    });
                }
            }
            for pattern in [r"\x{0}", r"\x{80}", r"\x{10FFFF}"] {
                let _ = exact_text_hir_pair(pattern, case_id)?;
            }
        }
        UTF8_BMP_CASE_ID => {
            use Utf8Sequence::{One, Three, Two};
            let observed = Utf8Sequences::new('\0', '\u{FFFF}').collect::<Vec<_>>();
            let expected = vec![
                One(rutf8(0x00, 0x7F)),
                Two([rutf8(0xC2, 0xDF), rutf8(0x80, 0xBF)]),
                Three([rutf8(0xE0, 0xE0), rutf8(0xA0, 0xBF), rutf8(0x80, 0xBF)]),
                Three([rutf8(0xE1, 0xEC), rutf8(0x80, 0xBF), rutf8(0x80, 0xBF)]),
                Three([rutf8(0xED, 0xED), rutf8(0x80, 0x9F), rutf8(0x80, 0xBF)]),
                Three([rutf8(0xEE, 0xEF), rutf8(0x80, 0xBF), rutf8(0x80, 0xBF)]),
            ];
            hir_doctest_assert_eq(case_id, "bmp-sequences", &expected, &observed)?;
            let _ = exact_text_hir_pair(r"[\x{0}-\x{FFFF}]", case_id)?;
        }
        UTF8_REVERSE_CASE_ID => {
            use Utf8Sequence::{Four, One, Three, Two};
            let mut one = One(rutf8(0xA, 0xB));
            one.reverse();
            hir_doctest_assert_eq(case_id, "one", &[rutf8(0xA, 0xB)][..], one.as_slice())?;
            let mut two = Two([rutf8(0xA, 0xB), rutf8(0xB, 0xC)]);
            two.reverse();
            hir_doctest_assert_eq(
                case_id,
                "two",
                &[rutf8(0xB, 0xC), rutf8(0xA, 0xB)][..],
                two.as_slice(),
            )?;
            let mut three = Three([rutf8(0xA, 0xB), rutf8(0xB, 0xC), rutf8(0xC, 0xD)]);
            three.reverse();
            hir_doctest_assert_eq(
                case_id,
                "three",
                &[rutf8(0xC, 0xD), rutf8(0xB, 0xC), rutf8(0xA, 0xB)][..],
                three.as_slice(),
            )?;
            let mut four = Four([
                rutf8(0xA, 0xB),
                rutf8(0xB, 0xC),
                rutf8(0xC, 0xD),
                rutf8(0xD, 0xE),
            ]);
            four.reverse();
            hir_doctest_assert_eq(
                case_id,
                "four",
                &[
                    rutf8(0xD, 0xE),
                    rutf8(0xC, 0xD),
                    rutf8(0xB, 0xC),
                    rutf8(0xA, 0xB),
                ][..],
                four.as_slice(),
            )?;
            let _ = exact_text_hir_pair("☃", case_id)?;
        }
        UTF8_DOCTEST_SEQUENCES_CASE_ID => {
            let sequences = Utf8Sequences::new('\0', '\u{FFFF}').collect::<Vec<_>>();
            for (index, (bytes, expected)) in [
                (&[0x61][..], true),
                (&[0xE2, 0x98, 0x83][..], true),
                (&[0xF0, 0x90, 0x8D, 0x88][..], false),
                (&[0xED, 0xA0, 0x80][..], false),
                (&[0xFF, 0xFF][..], false),
            ]
            .into_iter()
            .enumerate()
            {
                let observed = sequences.iter().any(|sequence| sequence.matches(bytes));
                hir_doctest_assert_eq(
                    case_id,
                    &format!("source-assertion-{index}"),
                    &expected,
                    &observed,
                )?;
            }
            let _ = exact_text_hir_pair(r"[\x{0}-\x{FFFF}]", case_id)?;
        }
        _ => unreachable!("caller checked supported UTF-8 case"),
    }
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "the exhaustive match mirrors three unit tests and three public doctests"
)]
fn run_top_level_case(case_id: &str) -> Result<(), AstMismatch> {
    match case_id {
        TOP_ESCAPE_META_CASE_ID => {
            let original = r"\.+*?()|[]{}^$#&-~";
            let observed = regex_syntax::escape(original);
            let expected = r"\\\.\+\*\?\(\)\|\[\]\{\}\^\$\#\&\-\~".to_owned();
            hir_doctest_assert_eq(case_id, "source-assertion", &expected, &observed)?;

            let (_, fre_hir) = exact_text_hir_pair(&observed, case_id)?;
            let expected_hir = regex_syntax::hir::Hir::literal(original.as_bytes());
            hir_doctest_assert_eq(case_id, "fre-literal-binding", &expected_hir, &fre_hir)?;
        }
        TOP_WORD_BYTE_CASE_ID => {
            for (index, (byte, expected)) in [(b'a', true), (b'-', false)].into_iter().enumerate() {
                let observed = regex_syntax::is_word_byte(byte);
                hir_doctest_assert_eq(
                    case_id,
                    &format!("source-assertion-{index}"),
                    &expected,
                    &observed,
                )?;
            }
            let (_, fre_hir) = exact_hir_pair(r"(?-u:\w)", case_id)?;
            let class = bytes_class_from_hir(&fre_hir, case_id)?;
            for (index, byte) in [b'a', b'-'].into_iter().enumerate() {
                let expected = regex_syntax::is_word_byte(byte);
                let observed = class
                    .iter()
                    .any(|range| range.start() <= byte && byte <= range.end());
                hir_doctest_assert_eq(
                    case_id,
                    &format!("fre-class-membership-{index}"),
                    &expected,
                    &observed,
                )?;
            }
        }
        TOP_WORD_CHAR_CASE_ID => {
            let probes = [
                ('a', true),
                ('à', true),
                ('β', true),
                ('\u{11011}', true),
                ('\u{11611}', true),
                ('\u{11711}', true),
                ('\u{17828}', true),
                ('\u{1B1B1}', true),
                ('\u{16E40}', true),
                ('-', false),
                ('☃', false),
            ];
            let (_, fre_hir) = exact_text_hir_pair(r"\w", case_id)?;
            let class = unicode_class_from_hir(&fre_hir, case_id)?;
            for (index, (scalar, expected)) in probes.into_iter().enumerate() {
                let public_observed = regex_syntax::is_word_character(scalar);
                hir_doctest_assert_eq(
                    case_id,
                    &format!("source-assertion-{index}"),
                    &expected,
                    &public_observed,
                )?;
                let fre_observed = class
                    .iter()
                    .any(|range| range.start() <= scalar && scalar <= range.end());
                hir_doctest_assert_eq(
                    case_id,
                    &format!("fre-class-membership-{index}"),
                    &expected,
                    &fre_observed,
                )?;
            }
        }
        TOP_DOCTEST_PARSE_CASE_ID => {
            let (_, fre_hir) = exact_text_hir_pair("a|b", case_id)?;
            let expected = regex_syntax::hir::Hir::alternation(vec![
                regex_syntax::hir::Hir::literal("a".as_bytes()),
                regex_syntax::hir::Hir::literal("b".as_bytes()),
            ]);
            hir_doctest_assert_eq(case_id, "source-assertion", &expected, &fre_hir)?;
        }
        TOP_DOCTEST_META_CASE_ID => {
            for (index, (scalar, expected)) in [
                ('?', true),
                ('-', true),
                ('&', true),
                ('#', true),
                ('%', false),
                ('/', false),
                ('!', false),
                ('"', false),
                ('e', false),
            ]
            .into_iter()
            .enumerate()
            {
                let observed = regex_syntax::is_meta_character(scalar);
                hir_doctest_assert_eq(
                    case_id,
                    &format!("source-assertion-{index}"),
                    &expected,
                    &observed,
                )?;
            }
            let pattern = regex_syntax::escape(r#"?-&#%/!"e"#);
            let _ = exact_text_hir_pair(&pattern, case_id)?;
        }
        TOP_DOCTEST_ESCAPEABLE_CASE_ID => {
            for (index, (scalar, expected)) in [
                ('?', true),
                ('-', true),
                ('&', true),
                ('#', true),
                ('%', true),
                ('/', true),
                ('!', true),
                ('"', true),
                ('e', false),
            ]
            .into_iter()
            .enumerate()
            {
                let observed = regex_syntax::is_escapeable_character(scalar);
                hir_doctest_assert_eq(
                    case_id,
                    &format!("source-assertion-{index}"),
                    &expected,
                    &observed,
                )?;
            }
            let pattern = regex_syntax::escape(r#"?-&#%/!"e"#);
            let _ = exact_text_hir_pair(&pattern, case_id)?;
        }
        _ => unreachable!("caller checked supported top-level syntax case"),
    }
    Ok(())
}

fn encode_surrogate_codepoint(codepoint: u32) -> [u8; 3] {
    debug_assert!((0xD800..0xE000).contains(&codepoint));
    [
        u8::try_from(codepoint >> 12 & 0x0F).expect("surrogate prefix nibble fits") | 0b1110_0000,
        u8::try_from(codepoint >> 6 & 0x3F).expect("surrogate middle bits fit") | 0b1000_0000,
        u8::try_from(codepoint & 0x3F).expect("surrogate suffix bits fit") | 0b1000_0000,
    ]
}

fn run_hir_doctest_case(case_id: &str) -> Result<(), AstMismatch> {
    if case_id == UTF8_DOCTEST_SEQUENCES_CASE_ID {
        return run_utf8_case(case_id);
    }
    if is_supported_top_level_doctest_case(case_id) {
        return run_top_level_case(case_id);
    }
    if is_supported_hir_constructor_doctest_case(case_id) {
        return run_hir_constructor_doctest_case(case_id);
    }
    if is_supported_hir_seq_doctest_case(case_id) {
        return run_hir_seq_doctest_case(case_id);
    }
    if let Some(pattern) = hir_extractor_doctest_pattern(case_id) {
        let (expected_hir, observed_hir) = exact_text_hir_pair(pattern, case_id)?;
        let expected = hir_extractor_doctest_sequences(case_id, &expected_hir);
        let observed = hir_extractor_doctest_sequences(case_id, &observed_hir);
        return if observed == expected {
            Ok(())
        } else {
            Err(AstMismatch {
                expected: format!("{case_id}: exact public extractor sequences {expected:?}"),
                observed: format!("{case_id}: {observed:?}"),
            })
        };
    }
    match case_id {
        HIR_DOCTEST_CLASS_MINIMUM_LEN_CASE_ID => {
            run_hir_doctest_property_probes(&HIR_DOCTEST_CLASS_MINIMUM_LEN_PROBES, case_id)
        }
        HIR_DOCTEST_CLASS_MAXIMUM_LEN_CASE_ID => {
            run_hir_doctest_property_probes(&HIR_DOCTEST_CLASS_MAXIMUM_LEN_PROBES, case_id)
        }
        HIR_DOCTEST_PROPERTIES_IS_UTF8_CASE_ID => {
            run_hir_translate_case(HIR_TRANSLATE_ANALYSIS_IS_UTF8_CASE_ID)
        }
        HIR_DOCTEST_PROPERTIES_CAPTURES_LEN_CASE_ID => {
            run_hir_translate_case(HIR_TRANSLATE_ANALYSIS_CAPTURES_LEN_CASE_ID)
        }
        HIR_DOCTEST_PROPERTIES_STATIC_CAPTURES_LEN_CASE_ID => {
            run_hir_translate_case(HIR_TRANSLATE_ANALYSIS_STATIC_CAPTURES_LEN_CASE_ID)
        }
        HIR_DOCTEST_PROPERTIES_UNION_NEVER_CASE_ID => {
            run_hir_doctest_properties_union(&HIR_DOCTEST_PROPERTIES_UNION_NEVER_PROBES, case_id)
        }
        HIR_DOCTEST_PROPERTIES_UNION_UNBOUNDED_CASE_ID => run_hir_doctest_properties_union(
            &HIR_DOCTEST_PROPERTIES_UNION_UNBOUNDED_PROBES,
            case_id,
        ),
        _ => unreachable!("caller checked supported HIR doctest case"),
    }
}

fn hir_doctest_assert_eq<T: std::fmt::Debug + PartialEq + ?Sized>(
    case_id: &str,
    label: &str,
    expected: &T,
    observed: &T,
) -> Result<(), AstMismatch> {
    if observed == expected {
        Ok(())
    } else {
        Err(AstMismatch {
            expected: format!("{case_id}/{label}: {expected:?}"),
            observed: format!("{case_id}/{label}: {observed:?}"),
        })
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the exhaustive match mirrors six independently identified public doctests"
)]
fn run_hir_constructor_doctest_case(case_id: &str) -> Result<(), AstMismatch> {
    use regex_syntax::hir::{
        Class, ClassBytes, ClassBytesRange, ClassUnicode, ClassUnicodeRange, Dot, Hir, HirKind,
        Literal,
    };

    match case_id {
        HIR_DOCTEST_HIR_LITERAL_BYTES_CASE_ID => {
            let (_, observed) = exact_text_hir_pair("☃", case_id)?;
            let literals = vec![
                Hir::literal([0xE2]),
                Hir::literal([0x98]),
                Hir::literal([0x83]),
            ];
            hir_doctest_assert_eq(
                case_id,
                "individual-literals-not-utf8",
                &true,
                &literals.iter().all(|hir| !hir.properties().is_utf8()),
            )?;
            let concat = Hir::concat(literals);
            hir_doctest_assert_eq(
                case_id,
                "concat-is-utf8",
                &true,
                &concat.properties().is_utf8(),
            )?;
            let expected = HirKind::Literal(Literal(Box::from("☃".as_bytes())));
            hir_doctest_assert_eq(case_id, "literal-kind", &expected, concat.kind())?;
            hir_doctest_assert_eq(case_id, "fre-hir-binding", &observed, &concat)?;
        }
        HIR_DOCTEST_HIR_LITERAL_CHAR_CASE_ID => {
            let (_, observed) = exact_text_hir_pair("☃", case_id)?;
            let ch = '☃';
            let got = Hir::literal(ch.encode_utf8(&mut [0; 4]).as_bytes());
            let expected = HirKind::Literal(Literal(Box::from("☃".as_bytes())));
            hir_doctest_assert_eq(case_id, "literal-kind", &expected, got.kind())?;
            hir_doctest_assert_eq(case_id, "fre-hir-binding", &observed, &got)?;
        }
        HIR_DOCTEST_HIR_CONCAT_CASE_ID => {
            let (_, observed) = exact_text_hir_pair("abcxyz", case_id)?;
            let hir = Hir::concat(vec![
                Hir::concat(vec![
                    Hir::literal([b'a']),
                    Hir::literal([b'b']),
                    Hir::literal([b'c']),
                ]),
                Hir::concat(vec![
                    Hir::literal([b'x']),
                    Hir::literal([b'y']),
                    Hir::literal([b'z']),
                ]),
            ]);
            let expected = Hir::literal("abcxyz".as_bytes());
            hir_doctest_assert_eq(case_id, "flattened-concat", &expected, &hir)?;
            hir_doctest_assert_eq(case_id, "fre-hir-binding", &observed, &hir)?;
        }
        HIR_DOCTEST_HIR_ALTERNATION_CLASS_CASE_ID => {
            let (_, observed) = exact_text_hir_pair("[a-f]", case_id)?;
            let hir = Hir::alternation(vec![
                Hir::literal([b'a']),
                Hir::literal([b'b']),
                Hir::literal([b'c']),
                Hir::literal([b'd']),
                Hir::literal([b'e']),
                Hir::literal([b'f']),
            ]);
            let expected = Hir::class(Class::Unicode(ClassUnicode::new([ClassUnicodeRange::new(
                'a', 'f',
            )])));
            hir_doctest_assert_eq(case_id, "class-simplification", &expected, &hir)?;
            hir_doctest_assert_eq(case_id, "fre-hir-binding", &observed, &hir)?;
        }
        HIR_DOCTEST_HIR_ALTERNATION_PREFIX_CASE_ID => {
            let (_, observed) = exact_text_hir_pair(r"abc(?:[A-Z]|[a-z])", case_id)?;
            let upper = Hir::class(Class::Unicode(ClassUnicode::new([ClassUnicodeRange::new(
                'A', 'Z',
            )])));
            let lower = Hir::class(Class::Unicode(ClassUnicode::new([ClassUnicodeRange::new(
                'a', 'z',
            )])));
            let hir = Hir::alternation(vec![
                Hir::concat(vec![Hir::literal("abc".as_bytes()), upper.clone()]),
                Hir::concat(vec![Hir::literal("abc".as_bytes()), lower.clone()]),
            ]);
            let expected = Hir::concat(vec![
                Hir::literal("abc".as_bytes()),
                Hir::alternation(vec![upper, lower]),
            ]);
            hir_doctest_assert_eq(case_id, "common-prefix", &expected, &hir)?;
            hir_doctest_assert_eq(case_id, "fre-hir-binding", &observed, &hir)?;
        }
        HIR_DOCTEST_HIR_DOT_CASE_ID => {
            let (_, observed) = exact_hir_pair(r"(?s-u:.)", case_id)?;
            let hir = Hir::dot(Dot::AnyByte);
            let expected = Hir::class(Class::Bytes(ClassBytes::new([ClassBytesRange::new(
                0x00, 0xFF,
            )])));
            hir_doctest_assert_eq(case_id, "any-byte-class", &expected, &hir)?;
            hir_doctest_assert_eq(case_id, "fre-hir-binding", &observed, &hir)?;
        }
        _ => unreachable!("caller checked supported HIR constructor doctest case"),
    }
    Ok(())
}

fn hir_constructor_doctest_binding_pattern(case_id: &str) -> &'static str {
    match case_id {
        HIR_DOCTEST_HIR_LITERAL_BYTES_CASE_ID | HIR_DOCTEST_HIR_LITERAL_CHAR_CASE_ID => "☃",
        HIR_DOCTEST_HIR_CONCAT_CASE_ID => "abcxyz",
        HIR_DOCTEST_HIR_ALTERNATION_CLASS_CASE_ID => "[a-f]",
        HIR_DOCTEST_HIR_ALTERNATION_PREFIX_CASE_ID => r"abc(?:[A-Z]|[a-z])",
        HIR_DOCTEST_HIR_DOT_CASE_ID => r"(?s-u:.)",
        _ => unreachable!("caller checked supported HIR constructor doctest case"),
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the exhaustive match mirrors 25 small, independently identified public doctests"
)]
fn run_hir_seq_doctest_case(case_id: &str) -> Result<(), AstMismatch> {
    use regex_syntax::hir::literal::{Literal, Seq};

    let pattern = hir_seq_doctest_binding_pattern(case_id);
    let _ = exact_text_hir_pair(pattern, case_id)?;

    macro_rules! require_eq {
        ($label:literal, $expected:expr, $observed:expr) => {{
            let expected = $expected;
            let observed = $observed;
            if observed != expected {
                return Err(AstMismatch {
                    expected: format!("{case_id}/{}: {expected:?}", $label),
                    observed: format!("{case_id}/{}: {observed:?}", $label),
                });
            }
        }};
    }

    match case_id {
        HIR_DOCTEST_SEQ_CASE_ID => {
            let mut seq = Seq::new([
                "farm",
                "appliance",
                "faraway",
                "apple",
                "fare",
                "gap",
                "applicant",
                "applaud",
            ]);
            seq.keep_first_bytes(3);
            seq.minimize_by_preference();
            let expected = Seq::from_iter([
                Literal::inexact("far"),
                Literal::inexact("app"),
                Literal::exact("gap"),
            ]);
            require_eq!("simplified-sequence", expected, seq);
        }
        HIR_DOCTEST_SEQ_CROSS_FORWARD_BASIC_CASE_ID => {
            let mut seq1 = Seq::from_iter([Literal::exact("foo"), Literal::inexact("bar")]);
            let mut seq2 = Seq::from_iter([Literal::inexact("quux"), Literal::exact("baz")]);
            seq1.cross_forward(&mut seq2);
            require_eq!("other-drained", Some(0), seq2.len());
            require_eq!(
                "cross-product",
                Seq::from_iter([
                    Literal::inexact("fooquux"),
                    Literal::exact("foobaz"),
                    Literal::inexact("bar"),
                ]),
                seq1
            );
        }
        HIR_DOCTEST_SEQ_CROSS_FORWARD_INFINITE_OTHER_CASE_ID => {
            let mut seq1 = Seq::from_iter([Literal::exact("foo"), Literal::inexact("bar")]);
            let mut seq2 = Seq::infinite();
            seq1.cross_forward(&mut seq2);
            require_eq!(
                "infinite-other-makes-inexact",
                Seq::from_iter([Literal::inexact("foo"), Literal::inexact("bar"),]),
                seq1
            );
        }
        HIR_DOCTEST_SEQ_CROSS_FORWARD_EMPTY_CASE_ID => {
            let mut seq1 = Seq::from_iter([
                Literal::exact("foo"),
                Literal::exact(""),
                Literal::inexact("bar"),
            ]);
            let mut seq2 = Seq::infinite();
            seq1.cross_forward(&mut seq2);
            require_eq!("empty-infected", false, seq1.is_finite());
        }
        HIR_DOCTEST_SEQ_CROSS_FORWARD_INFINITE_SELF_CASE_ID => {
            let mut seq1 = Seq::infinite();
            let mut seq2 = Seq::from_iter([Literal::exact("foo"), Literal::inexact("bar")]);
            seq1.cross_forward(&mut seq2);
            require_eq!("self-remains-infinite", false, seq1.is_finite());
            require_eq!("other-drained", Some(0), seq2.len());
        }
        HIR_DOCTEST_SEQ_CROSS_REVERSE_BASIC_CASE_ID => {
            let mut seq1 = Seq::from_iter([Literal::exact("foo"), Literal::inexact("bar")]);
            let mut seq2 = Seq::from_iter([Literal::inexact("quux"), Literal::exact("baz")]);
            seq1.cross_reverse(&mut seq2);
            require_eq!("other-drained", Some(0), seq2.len());
            require_eq!(
                "cross-product",
                Seq::from_iter([
                    Literal::inexact("quuxfoo"),
                    Literal::inexact("bar"),
                    Literal::exact("bazfoo"),
                ]),
                seq1
            );
        }
        HIR_DOCTEST_SEQ_CROSS_REVERSE_INFINITE_OTHER_CASE_ID => {
            let mut seq1 = Seq::from_iter([Literal::exact("foo"), Literal::inexact("bar")]);
            let mut seq2 = Seq::infinite();
            seq1.cross_reverse(&mut seq2);
            require_eq!(
                "infinite-other-makes-inexact",
                Seq::from_iter([Literal::inexact("foo"), Literal::inexact("bar"),]),
                seq1
            );
        }
        HIR_DOCTEST_SEQ_CROSS_REVERSE_EMPTY_CASE_ID => {
            let mut seq1 = Seq::from_iter([
                Literal::exact("foo"),
                Literal::exact(""),
                Literal::inexact("bar"),
            ]);
            let mut seq2 = Seq::infinite();
            seq1.cross_reverse(&mut seq2);
            require_eq!("empty-infected", false, seq1.is_finite());
        }
        HIR_DOCTEST_SEQ_CROSS_REVERSE_INFINITE_SELF_CASE_ID => {
            let mut seq1 = Seq::infinite();
            let mut seq2 = Seq::from_iter([Literal::exact("foo"), Literal::inexact("bar")]);
            seq1.cross_reverse(&mut seq2);
            require_eq!("self-remains-infinite", false, seq1.is_finite());
            require_eq!("other-drained", Some(0), seq2.len());
        }
        HIR_DOCTEST_SEQ_UNION_BASIC_CASE_ID => {
            let mut seq1 = Seq::new(["foo", "bar"]);
            let mut seq2 = Seq::new(["bar", "quux", "foo"]);
            seq1.union(&mut seq2);
            require_eq!("other-drained", Some(0), seq2.len());
            require_eq!(
                "preference-order-union",
                Seq::new(["foo", "bar", "quux", "foo"]),
                seq1
            );
        }
        HIR_DOCTEST_SEQ_UNION_INFINITE_CASE_ID => {
            let mut seq1 = Seq::infinite();
            require_eq!("initial-infinite", None, seq1.len());
            let mut seq2 = Seq::new(["bar", "quux", "foo"]);
            seq1.union(&mut seq2);
            require_eq!("remains-infinite", None, seq1.len());
            require_eq!("other-drained", Some(0), seq2.len());
        }
        HIR_DOCTEST_SEQ_UNION_EMPTY_BASIC_CASE_ID => {
            let mut seq1 = Seq::new(["a", "", "f", ""]);
            let mut seq2 = Seq::new(["foo"]);
            seq1.union_into_empty(&mut seq2);
            require_eq!("other-drained", Some(0), seq2.len());
            require_eq!("first-empty-splice", Seq::new(["a", "foo", "f"]), seq1);
        }
        HIR_DOCTEST_SEQ_UNION_EMPTY_NO_SPLICE_CASE_ID => {
            let mut seq1 = Seq::new(["foo", "bar"]);
            let mut seq2 = Seq::new(["bar", "quux", "foo"]);
            seq1.union_into_empty(&mut seq2);
            require_eq!("no-empty-no-splice", Seq::new(["foo", "bar"]), seq1);
            require_eq!("other-drained", Some(0), seq2.len());
        }
        HIR_DOCTEST_SEQ_DEDUP_CASE_ID => {
            let mut seq = Seq::from_iter([Literal::exact("foo"), Literal::inexact("foo")]);
            seq.dedup();
            require_eq!(
                "inexact-wins",
                Seq::from_iter([Literal::inexact("foo")]),
                seq
            );
        }
        HIR_DOCTEST_SEQ_SORT_CASE_ID => {
            let mut seq = Seq::new(["foo", "quux", "bar"]);
            seq.sort();
            require_eq!("lexicographic", Seq::new(["bar", "foo", "quux"]), seq);
        }
        HIR_DOCTEST_SEQ_REVERSE_LITERALS_CASE_ID => {
            let mut seq = Seq::new(["oof", "rab"]);
            seq.reverse_literals();
            require_eq!("reversed", Seq::new(["foo", "bar"]), seq);
        }
        HIR_DOCTEST_SEQ_MINIMIZE_PREFIX_CASE_ID => {
            let mut seq = Seq::new(["sam", "samwise"]);
            seq.minimize_by_preference();
            require_eq!(
                "short-first",
                Seq::from_iter([Literal::inexact("sam")]),
                seq
            );
            let mut seq = Seq::new(["samwise", "sam"]);
            seq.minimize_by_preference();
            require_eq!("long-first", Seq::new(["samwise", "sam"]), seq);
        }
        HIR_DOCTEST_SEQ_MINIMIZE_EMPTY_CASE_ID => {
            let mut seq = Seq::new(["foo", "bar", "", "quux", "fox"]);
            seq.minimize_by_preference();
            require_eq!(
                "middle-empty",
                Seq::from_iter([
                    Literal::exact("foo"),
                    Literal::exact("bar"),
                    Literal::inexact(""),
                ]),
                seq
            );
            let mut seq = Seq::new(["", "foo", "quux", "fox"]);
            seq.minimize_by_preference();
            require_eq!("leading-empty", Seq::from_iter([Literal::inexact("")]), seq);
        }
        HIR_DOCTEST_SEQ_KEEP_FIRST_CASE_ID => {
            let mut seq = Seq::new(["a", "foo", "quux"]);
            seq.keep_first_bytes(2);
            require_eq!(
                "first-two",
                Seq::from_iter([
                    Literal::exact("a"),
                    Literal::inexact("fo"),
                    Literal::inexact("qu"),
                ]),
                seq
            );
        }
        HIR_DOCTEST_SEQ_KEEP_LAST_CASE_ID => {
            let mut seq = Seq::new(["a", "foo", "quux"]);
            seq.keep_last_bytes(2);
            require_eq!(
                "last-two",
                Seq::from_iter([
                    Literal::exact("a"),
                    Literal::inexact("oo"),
                    Literal::inexact("ux"),
                ]),
                seq
            );
        }
        HIR_DOCTEST_SEQ_COMMON_PREFIX_CASE_ID => {
            let prefix = |seq: Seq| seq.longest_common_prefix().map(<[u8]>::to_vec);
            require_eq!(
                "fo",
                Some(b"fo".to_vec()),
                prefix(Seq::new(["foo", "foobar", "fo"]))
            );
            require_eq!(
                "foo",
                Some(b"foo".to_vec()),
                prefix(Seq::new(["foo", "foo"]))
            );
            require_eq!(
                "none-shared",
                Some(Vec::<u8>::new()),
                prefix(Seq::new(["foo", "bar"]))
            );
            require_eq!(
                "empty-literal",
                Some(Vec::<u8>::new()),
                prefix(Seq::new([""]))
            );
            require_eq!("infinite", None, prefix(Seq::infinite()));
            require_eq!("empty", None, prefix(Seq::empty()));
        }
        HIR_DOCTEST_SEQ_COMMON_SUFFIX_CASE_ID => {
            let suffix = |seq: Seq| seq.longest_common_suffix().map(<[u8]>::to_vec);
            require_eq!(
                "of",
                Some(b"of".to_vec()),
                suffix(Seq::new(["oof", "raboof", "of"]))
            );
            require_eq!(
                "foo",
                Some(b"foo".to_vec()),
                suffix(Seq::new(["foo", "foo"]))
            );
            require_eq!(
                "none-shared",
                Some(Vec::<u8>::new()),
                suffix(Seq::new(["foo", "bar"]))
            );
            require_eq!(
                "empty-literal",
                Some(Vec::<u8>::new()),
                suffix(Seq::new([""]))
            );
            require_eq!("infinite", None, suffix(Seq::infinite()));
            require_eq!("empty", None, suffix(Seq::empty()));
        }
        HIR_DOCTEST_SEQ_OPTIMIZE_PREFIX_CASE_ID => {
            let mut seq = Seq::new(["samantha", "sam", "samwise", "frodo"]);
            seq.optimize_for_prefix_by_preference();
            require_eq!(
                "optimized",
                Seq::from_iter([
                    Literal::exact("samantha"),
                    Literal::exact("sam"),
                    Literal::exact("frodo"),
                ]),
                seq
            );
        }
        HIR_DOCTEST_SEQ_OPTIMIZE_INFINITE_CASE_ID => {
            let mut seq = Seq::new(["samantha", "", "sam", "samwise", "frodo"]);
            seq.optimize_for_prefix_by_preference();
            require_eq!("empty-disables-prefilter", false, seq.is_finite());
        }
        HIR_DOCTEST_SEQ_OPTIMIZE_SPACE_CASE_ID => {
            let mut seq = Seq::new(["samantha", " ", "sam", "frodo"]);
            seq.optimize_for_prefix_by_preference();
            require_eq!("space-can-remain-finite", true, seq.is_finite());
        }
        _ => unreachable!("caller checked supported HIR Seq doctest case"),
    }
    Ok(())
}

fn hir_seq_doctest_binding_pattern(case_id: &str) -> &'static str {
    match case_id {
        HIR_DOCTEST_SEQ_CASE_ID => r"(?:farm|appliance|faraway|apple|fare|gap|applicant|applaud)",
        HIR_DOCTEST_SEQ_CROSS_FORWARD_BASIC_CASE_ID
        | HIR_DOCTEST_SEQ_CROSS_FORWARD_INFINITE_OTHER_CASE_ID
        | HIR_DOCTEST_SEQ_CROSS_FORWARD_EMPTY_CASE_ID
        | HIR_DOCTEST_SEQ_CROSS_FORWARD_INFINITE_SELF_CASE_ID
        | HIR_DOCTEST_SEQ_CROSS_REVERSE_BASIC_CASE_ID
        | HIR_DOCTEST_SEQ_CROSS_REVERSE_INFINITE_OTHER_CASE_ID
        | HIR_DOCTEST_SEQ_CROSS_REVERSE_EMPTY_CASE_ID
        | HIR_DOCTEST_SEQ_CROSS_REVERSE_INFINITE_SELF_CASE_ID => r"(?:foo|bar|quux|baz)",
        HIR_DOCTEST_SEQ_UNION_BASIC_CASE_ID
        | HIR_DOCTEST_SEQ_UNION_INFINITE_CASE_ID
        | HIR_DOCTEST_SEQ_UNION_EMPTY_NO_SPLICE_CASE_ID => r"(?:foo|bar|quux)",
        HIR_DOCTEST_SEQ_UNION_EMPTY_BASIC_CASE_ID => r"(?:a||f|foo)",
        HIR_DOCTEST_SEQ_DEDUP_CASE_ID => r"(?:foo|foo)",
        HIR_DOCTEST_SEQ_SORT_CASE_ID => r"(?:foo|quux|bar)",
        HIR_DOCTEST_SEQ_REVERSE_LITERALS_CASE_ID => r"(?:oof|rab)",
        HIR_DOCTEST_SEQ_MINIMIZE_PREFIX_CASE_ID => r"(?:sam|samwise)",
        HIR_DOCTEST_SEQ_MINIMIZE_EMPTY_CASE_ID => r"(?:foo|bar||quux|fox)",
        HIR_DOCTEST_SEQ_KEEP_FIRST_CASE_ID | HIR_DOCTEST_SEQ_KEEP_LAST_CASE_ID => r"(?:a|foo|quux)",
        HIR_DOCTEST_SEQ_COMMON_PREFIX_CASE_ID => r"(?:foo|foobar|fo|bar)",
        HIR_DOCTEST_SEQ_COMMON_SUFFIX_CASE_ID => r"(?:oof|raboof|of|foo|bar)",
        HIR_DOCTEST_SEQ_OPTIMIZE_PREFIX_CASE_ID
        | HIR_DOCTEST_SEQ_OPTIMIZE_INFINITE_CASE_ID
        | HIR_DOCTEST_SEQ_OPTIMIZE_SPACE_CASE_ID => r"(?:samantha|sam|samwise|frodo| )",
        _ => unreachable!("caller checked supported HIR Seq doctest case"),
    }
}

fn hir_extractor_doctest_pattern(case_id: &str) -> Option<&'static str> {
    match case_id {
        HIR_DOCTEST_EXTRACT_PREFIX_CASE_ID => Some(r"(a|b|c)(x|y|z)[A-Z]+foo"),
        HIR_DOCTEST_EXTRACT_SUFFIX_CASE_ID => Some(r"foo|[A-Z]+bar"),
        HIR_DOCTEST_LIMIT_CLASS_CASE_ID => Some(r"[0-9]"),
        HIR_DOCTEST_LIMIT_REPEAT_CASE_ID => Some(r"(abc){8}"),
        HIR_DOCTEST_LIMIT_LITERAL_LEN_CASE_ID => Some(r"(abc){2}{2}{2}"),
        HIR_DOCTEST_LIMIT_TOTAL_CASE_ID => Some(r"[ab]{2}{2}"),
        _ => None,
    }
}

fn hir_extractor_doctest_sequences(
    case_id: &str,
    hir: &regex_syntax::hir::Hir,
) -> Vec<regex_syntax::hir::literal::Seq> {
    use regex_syntax::hir::literal::{ExtractKind, Extractor};

    let default = || Extractor::new().extract(hir);
    match case_id {
        HIR_DOCTEST_EXTRACT_PREFIX_CASE_ID => vec![default()],
        HIR_DOCTEST_EXTRACT_SUFFIX_CASE_ID => {
            vec![Extractor::new().kind(ExtractKind::Suffix).extract(hir)]
        }
        HIR_DOCTEST_LIMIT_CLASS_CASE_ID => {
            vec![default(), Extractor::new().limit_class(4).extract(hir)]
        }
        HIR_DOCTEST_LIMIT_REPEAT_CASE_ID => {
            vec![default(), Extractor::new().limit_repeat(4).extract(hir)]
        }
        HIR_DOCTEST_LIMIT_LITERAL_LEN_CASE_ID => vec![
            default(),
            Extractor::new().limit_literal_len(14).extract(hir),
        ],
        HIR_DOCTEST_LIMIT_TOTAL_CASE_ID => {
            vec![default(), Extractor::new().limit_total(10).extract(hir)]
        }
        _ => unreachable!("caller checked extractor doctest case"),
    }
}

fn exact_text_hir_pair(
    pattern: &str,
    assertion: &str,
) -> Result<(regex_syntax::hir::Hir, regex_syntax::hir::Hir), AstMismatch> {
    let compatibility = CompatibilityProfile::RustText(RustProfile::regex_1_12_4());
    let expected_hir = regex_syntax::parse(pattern).map_err(|error| AstMismatch {
        expected: format!("{assertion}: authenticated upstream HIR parse succeeds"),
        observed: format!("{assertion}: upstream HIR parse error {error:?}"),
    })?;
    let record =
        parse(ParseRequest::rust(pattern, compatibility.clone())).map_err(|error| AstMismatch {
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
        && record.key.pattern.as_bytes() == pattern.as_bytes()
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
    Ok((expected_hir, parsed.hir.clone()))
}

fn run_hir_doctest_property_probes(probes: &[&str], assertion: &str) -> Result<(), AstMismatch> {
    for (index, pattern) in probes.iter().copied().enumerate() {
        let (expected, observed) = exact_text_hir_pair(pattern, &format!("{assertion}-{index}"))?;
        if observed.properties() != expected.properties() {
            return Err(AstMismatch {
                expected: format!(
                    "{assertion}-{index}: properties {:?}",
                    expected.properties()
                ),
                observed: format!(
                    "{assertion}-{index}: properties {:?}",
                    observed.properties()
                ),
            });
        }
    }
    Ok(())
}

fn run_hir_doctest_properties_union(probes: &[&str], assertion: &str) -> Result<(), AstMismatch> {
    let mut expected_hirs = Vec::new();
    let mut observed_hirs = Vec::new();
    for (index, pattern) in probes.iter().copied().enumerate() {
        let (expected, observed) = exact_text_hir_pair(pattern, &format!("{assertion}-{index}"))?;
        expected_hirs.push(expected);
        observed_hirs.push(observed);
    }
    let expected = regex_syntax::hir::Properties::union(
        expected_hirs.iter().map(regex_syntax::hir::Hir::properties),
    );
    let observed = regex_syntax::hir::Properties::union(
        observed_hirs.iter().map(regex_syntax::hir::Hir::properties),
    );
    if observed == expected {
        Ok(())
    } else {
        Err(AstMismatch {
            expected: format!("{assertion}: unioned properties {expected:?}"),
            observed: format!("{assertion}: unioned properties {observed:?}"),
        })
    }
}

fn run_hir_translate_case(case_id: &str) -> Result<(), AstMismatch> {
    if case_id == HIR_TRANSLATE_REGRESSION_FUZZ_MATCH_CASE_ID {
        return execute_hir_translate_fuzz_match_probe();
    }
    let (probes, label) = hir_translate_probes(case_id);
    for (index, (pattern, bytes)) in probes.iter().copied().enumerate() {
        execute_hir_translate_probe(pattern, bytes, &format!("{label}-{index}"))?;
    }
    for (index, (pattern, bytes)) in hir_translate_error_probes(case_id)
        .iter()
        .copied()
        .enumerate()
    {
        execute_hir_translate_error_probe(pattern, bytes, &format!("{label}-error-{index}"))?;
    }
    Ok(())
}

fn hir_translate_probes(case_id: &str) -> (&'static [HirTranslateProbe], &'static str) {
    if let Some(probes) = hir_translate_class_probes(case_id) {
        return probes;
    }
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
        HIR_TRANSLATE_REGRESSION_FUZZ_DIFFERENCE_CASE_ID => (
            &HIR_TRANSLATE_REGRESSION_FUZZ_DIFFERENCE_PROBES,
            "hir-translate-regression-fuzz-difference",
        ),
        HIR_TRANSLATE_REGRESSION_FUZZ_MATCH_CASE_ID => (
            &HIR_TRANSLATE_REGRESSION_FUZZ_MATCH_PROBES,
            "hir-translate-regression-fuzz-match",
        ),
        _ => unreachable!("caller checked supported HIR translate case"),
    }
}

fn hir_translate_class_probes(
    case_id: &str,
) -> Option<(&'static [HirTranslateProbe], &'static str)> {
    if let Some(probes) = hir_translate_enabled_class_probes(case_id) {
        return Some(probes);
    }
    match case_id {
        HIR_TRANSLATE_CAT_CLASS_FLATTENED_CASE_ID => Some((
            &HIR_TRANSLATE_CAT_CLASS_FLATTENED_PROBES,
            "hir-translate-cat-class-flattened",
        )),
        HIR_TRANSLATE_CLASS_BRACKETED_CASE_ID => Some((
            &HIR_TRANSLATE_CLASS_BRACKETED_PROBES,
            "hir-translate-class-bracketed",
        )),
        HIR_TRANSLATE_CLASS_BRACKETED_UNION_CASE_ID => Some((
            &HIR_TRANSLATE_CLASS_BRACKETED_UNION_PROBES,
            "hir-translate-class-bracketed-union",
        )),
        HIR_TRANSLATE_CLASS_BRACKETED_NESTED_CASE_ID => Some((
            &HIR_TRANSLATE_CLASS_BRACKETED_NESTED_PROBES,
            "hir-translate-class-bracketed-nested",
        )),
        HIR_TRANSLATE_CLASS_BRACKETED_INTERSECT_CASE_ID => Some((
            &HIR_TRANSLATE_CLASS_BRACKETED_INTERSECT_PROBES,
            "hir-translate-class-bracketed-intersect",
        )),
        HIR_TRANSLATE_CLASS_BRACKETED_INTERSECT_NEGATE_CASE_ID => Some((
            &HIR_TRANSLATE_CLASS_BRACKETED_INTERSECT_NEGATE_PROBES,
            "hir-translate-class-bracketed-intersect-negate",
        )),
        HIR_TRANSLATE_CLASS_BRACKETED_DIFFERENCE_CASE_ID => Some((
            &HIR_TRANSLATE_CLASS_BRACKETED_DIFFERENCE_PROBES,
            "hir-translate-class-bracketed-difference",
        )),
        HIR_TRANSLATE_CLASS_BRACKETED_SYMMETRIC_DIFFERENCE_CASE_ID => Some((
            &HIR_TRANSLATE_CLASS_BRACKETED_SYMMETRIC_DIFFERENCE_PROBES,
            "hir-translate-class-bracketed-symmetric-difference",
        )),
        _ => None,
    }
}

fn hir_translate_enabled_class_probes(
    case_id: &str,
) -> Option<(&'static [HirTranslateProbe], &'static str)> {
    match case_id {
        HIR_TRANSLATE_LITERAL_CASE_ID => {
            Some((&HIR_TRANSLATE_LITERAL_PROBES, "hir-translate-literal"))
        }
        HIR_TRANSLATE_DOT_CASE_ID => Some((&HIR_TRANSLATE_DOT_PROBES, "hir-translate-dot")),
        HIR_TRANSLATE_CLASS_ASCII_CASE_ID => Some((
            &HIR_TRANSLATE_CLASS_ASCII_PROBES,
            "hir-translate-class-ascii",
        )),
        HIR_TRANSLATE_CLASS_PERL_ASCII_CASE_ID => Some((
            &HIR_TRANSLATE_CLASS_PERL_ASCII_PROBES,
            "hir-translate-class-perl-ascii",
        )),
        HIR_TRANSLATE_CLASS_PERL_UNICODE_CASE_ID => Some((
            &HIR_TRANSLATE_CLASS_PERL_UNICODE_PROBES,
            "hir-translate-class-perl-unicode",
        )),
        HIR_TRANSLATE_CLASS_UNICODE_GENCAT_CASE_ID => Some((
            &HIR_TRANSLATE_CLASS_UNICODE_GENCAT_PROBES,
            "hir-translate-class-unicode-gencat",
        )),
        HIR_TRANSLATE_CLASS_UNICODE_SCRIPT_CASE_ID => Some((
            &HIR_TRANSLATE_CLASS_UNICODE_SCRIPT_PROBES,
            "hir-translate-class-unicode-script",
        )),
        HIR_TRANSLATE_CLASS_UNICODE_AGE_CASE_ID => Some((
            &HIR_TRANSLATE_CLASS_UNICODE_AGE_PROBES,
            "hir-translate-class-unicode-age",
        )),
        HIR_TRANSLATE_CLASS_UNICODE_ANY_EMPTY_CASE_ID => Some((
            &HIR_TRANSLATE_CLASS_UNICODE_ANY_EMPTY_PROBES,
            "hir-translate-class-unicode-any-empty",
        )),
        _ => None,
    }
}

fn hir_translate_error_probes(case_id: &str) -> &'static [HirTranslateProbe] {
    match case_id {
        HIR_TRANSLATE_CLASS_BRACKETED_CASE_ID => &HIR_TRANSLATE_CLASS_BRACKETED_ERROR_PROBES,
        HIR_TRANSLATE_LITERAL_CASE_ID => &HIR_TRANSLATE_LITERAL_ERROR_PROBES,
        HIR_TRANSLATE_DOT_CASE_ID => &HIR_TRANSLATE_DOT_ERROR_PROBES,
        HIR_TRANSLATE_CLASS_ASCII_CASE_ID => &HIR_TRANSLATE_CLASS_ASCII_ERROR_PROBES,
        HIR_TRANSLATE_CLASS_PERL_ASCII_CASE_ID => &HIR_TRANSLATE_CLASS_PERL_ASCII_ERROR_PROBES,
        HIR_TRANSLATE_CLASS_UNICODE_GENCAT_CASE_ID => {
            &HIR_TRANSLATE_CLASS_UNICODE_GENCAT_ERROR_PROBES
        }
        HIR_TRANSLATE_CLASS_UNICODE_SCRIPT_CASE_ID => {
            &HIR_TRANSLATE_CLASS_UNICODE_SCRIPT_ERROR_PROBES
        }
        HIR_TRANSLATE_CLASS_UNICODE_AGE_CASE_ID => &HIR_TRANSLATE_CLASS_UNICODE_AGE_ERROR_PROBES,
        _ => &[],
    }
}

fn hir_translate_context(bytes: bool) -> (RustProfile, CompatibilityProfile) {
    let mut rust_profile = RustProfile::regex_1_12_4();
    rust_profile.options.octal = true;
    let compatibility = if bytes {
        CompatibilityProfile::RustBytes(rust_profile.clone())
    } else {
        CompatibilityProfile::RustText(rust_profile.clone())
    };
    (rust_profile, compatibility)
}

fn hir_translate_builder(rust_profile: &RustProfile, bytes: bool) -> regex_syntax::ParserBuilder {
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
    builder
}

fn execute_hir_translate_probe(
    pattern: &str,
    bytes: bool,
    assertion: &str,
) -> Result<(), AstMismatch> {
    let (rust_profile, compatibility) = hir_translate_context(bytes);
    let builder = hir_translate_builder(&rust_profile, bytes);
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

fn execute_hir_translate_fuzz_match_probe() -> Result<(), AstMismatch> {
    let pattern = HIR_TRANSLATE_REGRESSION_FUZZ_MATCH_PATTERN;
    let assertion = "hir-translate-regression-fuzz-match";
    let mut rust_profile = RustProfile::regex_1_12_4();
    rust_profile.options.octal = false;
    rust_profile.options.ignore_whitespace = true;
    rust_profile.options.swap_greed = true;
    let compatibility = CompatibilityProfile::RustText(rust_profile.clone());
    let expected_hir = regex_syntax::ParserBuilder::new()
        .octal(false)
        .utf8(true)
        .ignore_whitespace(true)
        .case_insensitive(false)
        .multi_line(false)
        .dot_matches_new_line(false)
        .swap_greed(true)
        .unicode(true)
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
    if identity_valid && parsed.hir == expected_hir {
        Ok(())
    } else {
        Err(AstMismatch {
            expected: format!("{assertion}: exact custom-profile HIR {expected_hir:?}"),
            observed: format!("{assertion}: {record:?}"),
        })
    }
}

fn execute_hir_translate_error_probe(
    pattern: &str,
    bytes: bool,
    assertion: &str,
) -> Result<(), AstMismatch> {
    let (rust_profile, compatibility) = hir_translate_context(bytes);
    let expected = match hir_translate_builder(&rust_profile, bytes)
        .build()
        .parse(pattern)
    {
        Err(error) => error,
        Ok(hir) => {
            return Err(AstMismatch {
                expected: format!("{assertion}: authenticated upstream translation error"),
                observed: format!("{assertion}: upstream translated to {hir:?}"),
            });
        }
    };
    let observed = match parse(ParseRequest::rust(pattern, compatibility.clone())) {
        Err(error) => error,
        Ok(record) => {
            return Err(AstMismatch {
                expected: format!("{assertion}: FRE translation error matching {expected:?}"),
                observed: format!("{assertion}: FRE parsed {record:?}"),
            });
        }
    };
    let (expected_pattern, span) = match &expected {
        regex_syntax::Error::Parse(error) => (error.pattern(), error.span()),
        regex_syntax::Error::Translate(error) => (error.pattern(), error.span()),
        _ => {
            return Err(AstMismatch {
                expected: format!("{assertion}: pinned parse or translate error"),
                observed: format!("{assertion}: {expected:?}"),
            });
        }
    };
    let expected_span = SourceSpan {
        start: u64::try_from(span.start.offset).unwrap_or(u64::MAX),
        end: u64::try_from(span.end.offset).unwrap_or(u64::MAX),
    };
    let valid = expected_pattern == pattern
        && observed.schema_version == SCHEMA_VERSION
        && observed.profile.as_ref() == &compatibility
        && observed.category == ErrorCategory::UpstreamRustSyntax
        && observed.span == Some(expected_span)
        && observed.message == expected.to_string();
    if valid {
        Ok(())
    } else {
        Err(AstMismatch {
            expected: format!(
                "{assertion}: schema={SCHEMA_VERSION} profile={compatibility:?} category=UpstreamRustSyntax span={expected_span:?} message={:?}",
                expected.to_string(),
            ),
            observed: format!("{assertion}: {observed:?}"),
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

fn hir_literal_pass_evidence(case_id: &str) -> String {
    let mut contract = format!(
        "fre.regex-syntax.hir-literal-adapter.v1\ncase={case_id}\nparser=fre-syntax+pinned-regex-syntax-0.8.11\nprofile=rust-bytes\nextract=prefix+suffix\n"
    );
    let (probes, _, limit_total) = hir_literal_probes(case_id);
    for (index, pattern) in probes.iter().copied().enumerate() {
        writeln!(
            contract,
            "probe-{index}=sha256:{},bytes:{},limit-total:{},expected:exact-hir-and-literal-sequences",
            sha256(pattern.as_bytes()),
            pattern.len(),
            limit_total.map_or_else(|| "default".to_owned(), |limit| limit.to_string()),
        )
        .expect("writing to a String cannot fail");
    }
    sha256(contract.as_bytes())
}

fn hir_class_operation_pass_evidence(case_id: &str) -> String {
    let mut contract = format!(
        "fre.regex-syntax.hir-class-operation-adapter.v1\ncase={case_id}\nparser=fre-syntax+pinned-regex-syntax-0.8.11\nprofile=rust-bytes\n"
    );
    if let Some((probes, operation, _)) = hir_unicode_class_operation_probes(case_id) {
        writeln!(contract, "operation={operation:?}\nclass=unicode")
            .expect("writing to a String cannot fail");
        for (index, probe) in probes.iter().copied().enumerate() {
            write_hir_class_operation_evidence(
                &mut contract,
                index,
                &unicode_class_pattern(probe.left),
                &unicode_class_pattern(probe.right),
                operation,
            );
        }
    } else {
        let (probes, operation, _) = hir_bytes_class_operation_probes(case_id)
            .expect("caller checked supported HIR class operation case");
        writeln!(contract, "operation={operation:?}\nclass=bytes")
            .expect("writing to a String cannot fail");
        for (index, probe) in probes.iter().copied().enumerate() {
            write_hir_class_operation_evidence(
                &mut contract,
                index,
                &bytes_class_pattern(probe.left),
                &bytes_class_pattern(probe.right),
                operation,
            );
        }
    }
    sha256(contract.as_bytes())
}

fn hir_misc_pass_evidence(case_id: &str) -> String {
    let mut contract = format!(
        "fre.regex-syntax.hir-misc-adapter.v1\ncase={case_id}\nparser=fre-syntax+pinned-regex-syntax-0.8.11\nexpected=exact-public-hir-unit-semantics\n"
    );
    match case_id {
        HIR_CLASS_CANONICALIZE_UNICODE_CASE_ID => {
            for (index, &(input, expected)) in
                HIR_CLASS_CANONICALIZE_UNICODE_PROBES.iter().enumerate()
            {
                let pattern = unicode_class_pattern(input);
                writeln!(
                    contract,
                    "probe-{index}=pattern-sha256:{},pattern-bytes:{},expected:{expected:?}",
                    sha256(pattern.as_bytes()),
                    pattern.len(),
                )
                .expect("writing to a String cannot fail");
            }
        }
        HIR_CLASS_CANONICALIZE_BYTES_CASE_ID => {
            for (index, &(input, expected)) in
                HIR_CLASS_CANONICALIZE_BYTES_PROBES.iter().enumerate()
            {
                let pattern = bytes_class_pattern(input);
                writeln!(
                    contract,
                    "probe-{index}=pattern-sha256:{},pattern-bytes:{},expected:{expected:?}",
                    sha256(pattern.as_bytes()),
                    pattern.len(),
                )
                .expect("writing to a String cannot fail");
            }
        }
        HIR_CLASS_RANGE_CANONICAL_UNICODE_CASE_ID => {
            contract.push_str("input=U+00FF..U+0000\nexpected=U+0000..U+00FF\n");
        }
        HIR_CLASS_RANGE_CANONICAL_BYTES_CASE_ID => {
            contract.push_str("input=FF..00\nexpected=00..FF\n");
        }
        HIR_LOOK_SET_ITER_CASE_ID => {
            contract.push_str(
                "assertions=empty:0,full:18,startlf+wordunicode:2,startlf:1,word-ascii-negate:1\n",
            );
        }
        HIR_LOOK_SET_DEBUG_CASE_ID => {
            contract.push_str("assertions=empty:∅,full:Az^$rRbB𝛃𝚩<>〈〉◁▷◀▶\n");
        }
        HIR_NO_STACK_OVERFLOW_ON_DROP_CASE_ID => {
            contract.push_str("seed=exact-fre-hir:a\npublic-depth=200\nworker-stack=16384\n");
        }
        _ => unreachable!("caller checked supported HIR misc case"),
    }
    sha256(contract.as_bytes())
}

fn utf8_pass_evidence(case_id: &str) -> String {
    let assertions = match case_id {
        UTF8_CODEPOINTS_NO_SURROGATES_CASE_ID => "five-ranges-times-2048-surrogate-encodings",
        UTF8_SINGLE_CODEPOINT_CASE_ID => "every-valid-scalar-has-one-sequence",
        UTF8_BMP_CASE_ID => "exact-six-sequence-bmp-decomposition",
        UTF8_REVERSE_CASE_ID => "one-two-three-four-byte-sequence-reversal",
        UTF8_DOCTEST_SEQUENCES_CASE_ID => "five-public-bmp-membership-examples",
        _ => unreachable!("caller checked supported UTF-8 case"),
    };
    sha256(
        format!(
            "fre.regex-syntax.utf8-adapter.v1\ncase={case_id}\nparser=fre-syntax+pinned-regex-syntax-0.8.11\nassertions={assertions}\nexpected=exact-public-utf8-sequence-semantics\n"
        )
        .as_bytes(),
    )
}

fn top_level_pass_evidence(case_id: &str) -> String {
    let assertions = match case_id {
        TOP_ESCAPE_META_CASE_ID => "one-exact-escape-and-fre-literal-binding",
        TOP_WORD_BYTE_CASE_ID => "two-public-byte-word-and-fre-class-membership",
        TOP_WORD_CHAR_CASE_ID => "eleven-public-unicode-word-and-fre-class-membership",
        TOP_DOCTEST_PARSE_CASE_ID => "one-public-parse-hir-and-exact-fre-hir",
        TOP_DOCTEST_META_CASE_ID => "nine-public-meta-character-and-fre-literal-binding",
        TOP_DOCTEST_ESCAPEABLE_CASE_ID => {
            "nine-public-escapeable-character-and-fre-literal-binding"
        }
        _ => unreachable!("caller checked supported top-level syntax case"),
    };
    sha256(
        format!(
            "fre.regex-syntax.top-level-adapter.v1\ncase={case_id}\nparser=fre-syntax+pinned-regex-syntax-0.8.11\nassertions={assertions}\nexpected=exact-public-top-level-semantics\n"
        )
        .as_bytes(),
    )
}

fn write_hir_class_operation_evidence(
    contract: &mut String,
    index: usize,
    left: &str,
    right: &str,
    operation: HirClassOperation,
) {
    writeln!(
        contract,
        "probe-{index}=left-sha256:{},left-bytes:{},right-sha256:{},right-bytes:{},operation:{operation:?},expected:exact-hir-source-operands-and-public-operation",
        sha256(left.as_bytes()),
        left.len(),
        sha256(right.as_bytes()),
        right.len(),
    )
    .expect("writing to a String cannot fail");
}

fn hir_doctest_pass_evidence(case_id: &str) -> String {
    if case_id == UTF8_DOCTEST_SEQUENCES_CASE_ID {
        return utf8_pass_evidence(case_id);
    }
    if is_supported_top_level_doctest_case(case_id) {
        return top_level_pass_evidence(case_id);
    }
    let mut contract = format!(
        "fre.regex-syntax.hir-doctest-adapter.v1\ncase={case_id}\nparser=fre-syntax+pinned-regex-syntax-0.8.11\nexpected=exact-public-doctest-semantics\n"
    );
    if let Some(pattern) = hir_extractor_doctest_pattern(case_id) {
        writeln!(
            contract,
            "pattern=sha256:{},bytes:{}\nadapter=literal-extractor",
            sha256(pattern.as_bytes()),
            pattern.len(),
        )
        .expect("writing to a String cannot fail");
    } else if is_supported_hir_constructor_doctest_case(case_id) {
        let pattern = hir_constructor_doctest_binding_pattern(case_id);
        writeln!(
            contract,
            "pattern=sha256:{},bytes:{}\nadapter=hir-smart-constructor",
            sha256(pattern.as_bytes()),
            pattern.len(),
        )
        .expect("writing to a String cannot fail");
    } else if is_supported_hir_seq_doctest_case(case_id) {
        let pattern = hir_seq_doctest_binding_pattern(case_id);
        writeln!(
            contract,
            "pattern=sha256:{},bytes:{}\nadapter=literal-seq-public-operation",
            sha256(pattern.as_bytes()),
            pattern.len(),
        )
        .expect("writing to a String cannot fail");
    } else if case_id == HIR_DOCTEST_PROPERTIES_IS_UTF8_CASE_ID {
        writeln!(
            contract,
            "bound-unit-evidence={}",
            hir_translate_pass_evidence(HIR_TRANSLATE_ANALYSIS_IS_UTF8_CASE_ID),
        )
        .expect("writing to a String cannot fail");
    } else if case_id == HIR_DOCTEST_PROPERTIES_CAPTURES_LEN_CASE_ID {
        writeln!(
            contract,
            "bound-unit-evidence={}",
            hir_translate_pass_evidence(HIR_TRANSLATE_ANALYSIS_CAPTURES_LEN_CASE_ID),
        )
        .expect("writing to a String cannot fail");
    } else if case_id == HIR_DOCTEST_PROPERTIES_STATIC_CAPTURES_LEN_CASE_ID {
        writeln!(
            contract,
            "bound-unit-evidence={}",
            hir_translate_pass_evidence(HIR_TRANSLATE_ANALYSIS_STATIC_CAPTURES_LEN_CASE_ID),
        )
        .expect("writing to a String cannot fail");
    } else {
        for (index, pattern) in hir_doctest_property_patterns(case_id)
            .iter()
            .copied()
            .enumerate()
        {
            writeln!(
                contract,
                "pattern-{index}=sha256:{},bytes:{}",
                sha256(pattern.as_bytes()),
                pattern.len(),
            )
            .expect("writing to a String cannot fail");
        }
    }
    sha256(contract.as_bytes())
}

fn hir_doctest_property_patterns(case_id: &str) -> &'static [&'static str] {
    match case_id {
        HIR_DOCTEST_CLASS_MINIMUM_LEN_CASE_ID => &HIR_DOCTEST_CLASS_MINIMUM_LEN_PROBES,
        HIR_DOCTEST_CLASS_MAXIMUM_LEN_CASE_ID => &HIR_DOCTEST_CLASS_MAXIMUM_LEN_PROBES,
        HIR_DOCTEST_PROPERTIES_UNION_NEVER_CASE_ID => &HIR_DOCTEST_PROPERTIES_UNION_NEVER_PROBES,
        HIR_DOCTEST_PROPERTIES_UNION_UNBOUNDED_CASE_ID => {
            &HIR_DOCTEST_PROPERTIES_UNION_UNBOUNDED_PROBES
        }
        _ => &[],
    }
}

fn hir_translate_pass_evidence(case_id: &str) -> String {
    let profile_contract = if case_id == HIR_TRANSLATE_REGRESSION_FUZZ_MATCH_CASE_ID {
        "ast-octal=false,ignore-whitespace=true,swap-greed=true"
    } else {
        "ast-octal=true"
    };
    let mut contract = format!(
        "fre.regex-syntax.hir-translate-adapter.v1\ncase={case_id}\nparser=fre-syntax+pinned-regex-syntax-0.8.11\n{profile_contract}\n"
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
    for (index, (pattern, bytes)) in hir_translate_error_probes(case_id)
        .iter()
        .copied()
        .enumerate()
    {
        writeln!(
            contract,
            "error-probe-{index}=sha256:{},bytes:{},bytes-profile:{bytes},expected:exact-upstream-error",
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

fn hir_literal_mismatch_evidence(case_id: &str, expected: &str, observed: &str) -> String {
    sha256(
        format!(
            "fre.regex-syntax.hir-literal-adapter.mismatch.v1\ncase={case_id}\nexpected={expected}\nobserved={observed}\n"
        )
        .as_bytes(),
    )
}

fn hir_class_operation_mismatch_evidence(case_id: &str, expected: &str, observed: &str) -> String {
    sha256(
        format!(
            "fre.regex-syntax.hir-class-operation-adapter.mismatch.v1\ncase={case_id}\nexpected={expected}\nobserved={observed}\n"
        )
        .as_bytes(),
    )
}

fn hir_misc_mismatch_evidence(case_id: &str, expected: &str, observed: &str) -> String {
    sha256(
        format!(
            "fre.regex-syntax.hir-misc-adapter.mismatch.v1\ncase={case_id}\nexpected={expected}\nobserved={observed}\n"
        )
        .as_bytes(),
    )
}

fn utf8_mismatch_evidence(case_id: &str, expected: &str, observed: &str) -> String {
    sha256(
        format!(
            "fre.regex-syntax.utf8-adapter.mismatch.v1\ncase={case_id}\nexpected={expected}\nobserved={observed}\n"
        )
        .as_bytes(),
    )
}

fn top_level_mismatch_evidence(case_id: &str, expected: &str, observed: &str) -> String {
    sha256(
        format!(
            "fre.regex-syntax.top-level-adapter.mismatch.v1\ncase={case_id}\nexpected={expected}\nobserved={observed}\n"
        )
        .as_bytes(),
    )
}

fn hir_doctest_mismatch_evidence(case_id: &str, expected: &str, observed: &str) -> String {
    sha256(
        format!(
            "fre.regex-syntax.hir-doctest-adapter.mismatch.v1\ncase={case_id}\nexpected={expected}\nobserved={observed}\n"
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
        || is_supported_hir_literal_case(case_id)
        || is_supported_utf8_case(case_id)
        || is_supported_top_level_case(case_id)
        || is_supported_hir_misc_case(case_id)
        || is_supported_hir_class_operation_case(case_id)
        || is_supported_hir_translate_case(case_id)
}

fn syntax_case_pass_evidence(case_id: &str) -> String {
    if is_supported_ast_case(case_id) {
        ast_case_pass_evidence(case_id)
    } else if is_supported_ast_print_case(case_id) {
        ast_print_pass_evidence(case_id)
    } else if is_supported_hir_print_case(case_id) {
        hir_print_pass_evidence(case_id)
    } else if is_supported_hir_literal_case(case_id) {
        hir_literal_pass_evidence(case_id)
    } else if is_supported_utf8_case(case_id) {
        utf8_pass_evidence(case_id)
    } else if is_supported_top_level_case(case_id) {
        top_level_pass_evidence(case_id)
    } else if is_supported_hir_misc_case(case_id) {
        hir_misc_pass_evidence(case_id)
    } else if is_supported_hir_class_operation_case(case_id) {
        hir_class_operation_pass_evidence(case_id)
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
    } else if is_supported_hir_literal_case(case_id) {
        hir_literal_mismatch_evidence(case_id, expected, observed)
    } else if is_supported_utf8_case(case_id) {
        utf8_mismatch_evidence(case_id, expected, observed)
    } else if is_supported_top_level_case(case_id) {
        top_level_mismatch_evidence(case_id, expected, observed)
    } else if is_supported_hir_misc_case(case_id) {
        hir_misc_mismatch_evidence(case_id, expected, observed)
    } else if is_supported_hir_class_operation_case(case_id) {
        hir_class_operation_mismatch_evidence(case_id, expected, observed)
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
    } else if is_supported_hir_literal_case(case_id) {
        "fre-hir-literal-adapter"
    } else if is_supported_utf8_case(case_id) {
        "fre-utf8-adapter"
    } else if is_supported_top_level_case(case_id) {
        "fre-top-level-syntax-adapter"
    } else if is_supported_hir_misc_case(case_id) {
        "fre-hir-misc-adapter"
    } else if is_supported_hir_class_operation_case(case_id) {
        "fre-hir-class-operation-adapter"
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
    if case_id.starts_with(HIR_LITERAL_PREFIX) {
        return !is_supported_hir_literal_case(case_id)
            && reason_code == "fre-adapter.hir-literal-not-implemented";
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
            RegexSyntaxCorpusDisposition::Pass { evidence_sha256 },
        ) if is_supported_hir_doctest_case(&obligation.case_id) => {
            obligation.default_harness_member
                && obligation.no_default_harness_member
                && evidence_sha256 == &hir_doctest_pass_evidence(&obligation.case_id)
        }
        (
            RegexSyntaxCorpusCaseKind::Doctest,
            RegexSyntaxCorpusDisposition::Mismatch {
                expected,
                observed,
                evidence_sha256,
            },
        ) if is_supported_hir_doctest_case(&obligation.case_id) => {
            !expected.is_empty()
                && !observed.is_empty()
                && expected.len() <= 65_536
                && observed.len() <= 65_536
                && evidence_sha256
                    == &hir_doctest_mismatch_evidence(&obligation.case_id, expected, observed)
        }
        (
            RegexSyntaxCorpusCaseKind::Doctest,
            RegexSyntaxCorpusDisposition::Fault { stage, reason_code },
        ) if is_supported_hir_doctest_case(&obligation.case_id) => {
            stage == "fre-hir-doctest-adapter" && reason_code == "candidate.adapter-panicked"
        }
        (
            RegexSyntaxCorpusCaseKind::Doctest,
            RegexSyntaxCorpusDisposition::Unsupported { reason_code },
        ) => {
            !is_supported_hir_doctest_case(&obligation.case_id)
                && obligation.default_harness_member
                && obligation.no_default_harness_member
                && reason_code == "fre-adapter.doctest-not-implemented"
        }
        (
            RegexSyntaxCorpusCaseKind::Unit,
            RegexSyntaxCorpusDisposition::Pass { evidence_sha256 },
        ) if is_supported_syntax_adapter_case(&obligation.case_id) => {
            (obligation.default_harness_member || obligation.no_default_harness_member)
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
    fn authenticated_hir_literal_cases_execute_all_152_public_outcomes() {
        let cases = [
            (
                HIR_LITERAL_LITERAL_CASE_ID,
                HIR_LITERAL_LITERAL_PROBES.len(),
            ),
            (HIR_LITERAL_CLASS_CASE_ID, HIR_LITERAL_CLASS_PROBES.len()),
            (HIR_LITERAL_LOOK_CASE_ID, HIR_LITERAL_LOOK_PROBES.len()),
            (
                HIR_LITERAL_REPETITION_CASE_ID,
                HIR_LITERAL_REPETITION_PROBES.len(),
            ),
            (HIR_LITERAL_CONCAT_CASE_ID, HIR_LITERAL_CONCAT_PROBES.len()),
            (
                HIR_LITERAL_ALTERNATION_CASE_ID,
                HIR_LITERAL_ALTERNATION_PROBES.len(),
            ),
            (
                HIR_LITERAL_IMPOSSIBLE_CASE_ID,
                HIR_LITERAL_IMPOSSIBLE_PROBES.len(),
            ),
            (
                HIR_LITERAL_ANYTHING_CASE_ID,
                HIR_LITERAL_ANYTHING_PROBES.len(),
            ),
            (
                HIR_LITERAL_ANYTHING_SMALL_LIMITS_CASE_ID,
                HIR_LITERAL_ANYTHING_SMALL_LIMITS_PROBES.len(),
            ),
            (HIR_LITERAL_EMPTY_CASE_ID, HIR_LITERAL_EMPTY_PROBES.len()),
            (
                HIR_LITERAL_ODDS_AND_ENDS_CASE_ID,
                HIR_LITERAL_ODDS_AND_ENDS_PROBES.len(),
            ),
        ];
        assert_eq!(
            cases.iter().map(|(_, outcomes)| outcomes).sum::<usize>(),
            152,
        );
        for (case_id, _) in cases {
            let disposition = execute_hir_literal_case(case_id);
            assert_eq!(
                disposition,
                RegexSyntaxCorpusDisposition::Pass {
                    evidence_sha256: hir_literal_pass_evidence(case_id),
                },
            );
            validate_disposition(&RegexSyntaxCorpusReceipt {
                obligation: RegexSyntaxCorpusObligation {
                    case_id: case_id.to_owned(),
                    kind: RegexSyntaxCorpusCaseKind::Unit,
                    source_path: "src/hir/literal.rs".to_owned(),
                    source_line: 1,
                    source_sha256: "0".repeat(64),
                    default_harness_member: true,
                    no_default_harness_member: true,
                },
                disposition,
            })
            .expect("supported HIR literal receipt");
        }
    }

    #[test]
    fn authenticated_hir_class_operations_execute_all_92_public_outcomes() {
        assert_eq!(
            HIR_CLASS_OPERATION_CASES
                .iter()
                .map(|(_, outcomes, _, _)| outcomes)
                .sum::<usize>(),
            92,
        );
        for (case_id, _, default_member, no_default_member) in HIR_CLASS_OPERATION_CASES {
            let disposition = execute_hir_class_operation_case(case_id);
            assert_eq!(
                disposition,
                RegexSyntaxCorpusDisposition::Pass {
                    evidence_sha256: hir_class_operation_pass_evidence(case_id),
                },
            );
            validate_disposition(&RegexSyntaxCorpusReceipt {
                obligation: RegexSyntaxCorpusObligation {
                    case_id: case_id.to_owned(),
                    kind: RegexSyntaxCorpusCaseKind::Unit,
                    source_path: "src/hir/mod.rs".to_owned(),
                    source_line: 1,
                    source_sha256: "0".repeat(64),
                    default_harness_member: default_member,
                    no_default_harness_member: no_default_member,
                },
                disposition,
            })
            .expect("supported HIR class-operation receipt");
        }
    }

    #[test]
    fn authenticated_hir_misc_cases_execute_all_27_public_assertions() {
        let cases = [
            (HIR_CLASS_RANGE_CANONICAL_UNICODE_CASE_ID, 2),
            (HIR_CLASS_RANGE_CANONICAL_BYTES_CASE_ID, 2),
            (
                HIR_CLASS_CANONICALIZE_UNICODE_CASE_ID,
                HIR_CLASS_CANONICALIZE_UNICODE_PROBES.len(),
            ),
            (
                HIR_CLASS_CANONICALIZE_BYTES_CASE_ID,
                HIR_CLASS_CANONICALIZE_BYTES_PROBES.len(),
            ),
            (HIR_LOOK_SET_ITER_CASE_ID, 5),
            (HIR_LOOK_SET_DEBUG_CASE_ID, 2),
            (HIR_NO_STACK_OVERFLOW_ON_DROP_CASE_ID, 1),
        ];
        assert_eq!(
            cases
                .iter()
                .map(|(_, assertions)| assertions)
                .sum::<usize>(),
            27,
        );
        for (case_id, _) in cases {
            let disposition = execute_hir_misc_case(case_id);
            assert_eq!(
                disposition,
                RegexSyntaxCorpusDisposition::Pass {
                    evidence_sha256: hir_misc_pass_evidence(case_id),
                },
            );
            validate_disposition(&RegexSyntaxCorpusReceipt {
                obligation: RegexSyntaxCorpusObligation {
                    case_id: case_id.to_owned(),
                    kind: RegexSyntaxCorpusCaseKind::Unit,
                    source_path: "src/hir/mod.rs".to_owned(),
                    source_line: 1,
                    source_sha256: "0".repeat(64),
                    default_harness_member: true,
                    no_default_harness_member: true,
                },
                disposition,
            })
            .expect("supported HIR misc receipt");
        }
    }

    #[test]
    fn authenticated_utf8_cases_execute_all_5_public_identities() {
        for case_id in [
            UTF8_BMP_CASE_ID,
            UTF8_CODEPOINTS_NO_SURROGATES_CASE_ID,
            UTF8_REVERSE_CASE_ID,
            UTF8_SINGLE_CODEPOINT_CASE_ID,
        ] {
            let disposition = execute_utf8_case(case_id);
            assert_eq!(
                disposition,
                RegexSyntaxCorpusDisposition::Pass {
                    evidence_sha256: utf8_pass_evidence(case_id),
                },
            );
            validate_disposition(&RegexSyntaxCorpusReceipt {
                obligation: RegexSyntaxCorpusObligation {
                    case_id: case_id.to_owned(),
                    kind: RegexSyntaxCorpusCaseKind::Unit,
                    source_path: "src/utf8.rs".to_owned(),
                    source_line: 1,
                    source_sha256: "0".repeat(64),
                    default_harness_member: true,
                    no_default_harness_member: true,
                },
                disposition,
            })
            .expect("supported UTF-8 unit receipt");
        }
        let disposition = execute_hir_doctest_case(UTF8_DOCTEST_SEQUENCES_CASE_ID);
        assert_eq!(
            disposition,
            RegexSyntaxCorpusDisposition::Pass {
                evidence_sha256: utf8_pass_evidence(UTF8_DOCTEST_SEQUENCES_CASE_ID),
            },
        );
        validate_disposition(&RegexSyntaxCorpusReceipt {
            obligation: RegexSyntaxCorpusObligation {
                case_id: UTF8_DOCTEST_SEQUENCES_CASE_ID.to_owned(),
                kind: RegexSyntaxCorpusCaseKind::Doctest,
                source_path: "src/utf8.rs".to_owned(),
                source_line: 1,
                source_sha256: "0".repeat(64),
                default_harness_member: true,
                no_default_harness_member: true,
            },
            disposition,
        })
        .expect("supported UTF-8 doctest receipt");
    }

    #[test]
    fn authenticated_top_level_cases_execute_all_6_public_identities() {
        for case_id in [
            TOP_ESCAPE_META_CASE_ID,
            TOP_WORD_BYTE_CASE_ID,
            TOP_WORD_CHAR_CASE_ID,
        ] {
            let disposition = execute_top_level_case(case_id);
            assert_eq!(
                disposition,
                RegexSyntaxCorpusDisposition::Pass {
                    evidence_sha256: top_level_pass_evidence(case_id),
                },
            );
            validate_disposition(&RegexSyntaxCorpusReceipt {
                obligation: RegexSyntaxCorpusObligation {
                    case_id: case_id.to_owned(),
                    kind: RegexSyntaxCorpusCaseKind::Unit,
                    source_path: "src/lib.rs".to_owned(),
                    source_line: 1,
                    source_sha256: "0".repeat(64),
                    default_harness_member: true,
                    no_default_harness_member: case_id != TOP_WORD_CHAR_CASE_ID,
                },
                disposition,
            })
            .expect("supported top-level unit receipt");
        }
        for case_id in [
            TOP_DOCTEST_PARSE_CASE_ID,
            TOP_DOCTEST_META_CASE_ID,
            TOP_DOCTEST_ESCAPEABLE_CASE_ID,
        ] {
            let disposition = execute_hir_doctest_case(case_id);
            assert_eq!(
                disposition,
                RegexSyntaxCorpusDisposition::Pass {
                    evidence_sha256: top_level_pass_evidence(case_id),
                },
            );
            validate_disposition(&RegexSyntaxCorpusReceipt {
                obligation: RegexSyntaxCorpusObligation {
                    case_id: case_id.to_owned(),
                    kind: RegexSyntaxCorpusCaseKind::Doctest,
                    source_path: "src/lib.rs".to_owned(),
                    source_line: 1,
                    source_sha256: "0".repeat(64),
                    default_harness_member: true,
                    no_default_harness_member: true,
                },
                disposition,
            })
            .expect("supported top-level doctest receipt");
        }
    }

    #[test]
    fn authenticated_hir_robustness_cases_execute_all_5_public_outcomes() {
        let literal_cases = [
            (HIR_LITERAL_HOLMES_CASE_ID, 1, true, false),
            (HIR_LITERAL_HOLMES_ALT_CASE_ID, 2, true, false),
        ];
        let translate_cases = [
            (HIR_TRANSLATE_REGRESSION_FUZZ_MATCH_CASE_ID, 1, true, true),
            (
                HIR_TRANSLATE_REGRESSION_FUZZ_DIFFERENCE_CASE_ID,
                1,
                true,
                false,
            ),
        ];
        assert_eq!(
            literal_cases
                .iter()
                .chain(translate_cases.iter())
                .map(|(_, outcomes, _, _)| outcomes)
                .sum::<usize>(),
            5,
        );
        for (case_id, _, default_member, no_default_member) in literal_cases {
            let disposition = execute_hir_literal_case(case_id);
            assert_eq!(
                disposition,
                RegexSyntaxCorpusDisposition::Pass {
                    evidence_sha256: hir_literal_pass_evidence(case_id),
                },
            );
            validate_disposition(&RegexSyntaxCorpusReceipt {
                obligation: RegexSyntaxCorpusObligation {
                    case_id: case_id.to_owned(),
                    kind: RegexSyntaxCorpusCaseKind::Unit,
                    source_path: "src/hir/literal.rs".to_owned(),
                    source_line: 1,
                    source_sha256: "0".repeat(64),
                    default_harness_member: default_member,
                    no_default_harness_member: no_default_member,
                },
                disposition,
            })
            .expect("supported HIR literal-robustness receipt");
        }
        for (case_id, _, default_member, no_default_member) in translate_cases {
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
                    default_harness_member: default_member,
                    no_default_harness_member: no_default_member,
                },
                disposition,
            })
            .expect("supported HIR translate-robustness receipt");
        }
    }

    #[test]
    fn authenticated_hir_doctest_cases_execute_all_13_public_examples() {
        let cases = [
            HIR_DOCTEST_EXTRACT_PREFIX_CASE_ID,
            HIR_DOCTEST_EXTRACT_SUFFIX_CASE_ID,
            HIR_DOCTEST_LIMIT_CLASS_CASE_ID,
            HIR_DOCTEST_LIMIT_REPEAT_CASE_ID,
            HIR_DOCTEST_LIMIT_LITERAL_LEN_CASE_ID,
            HIR_DOCTEST_LIMIT_TOTAL_CASE_ID,
            HIR_DOCTEST_CLASS_MINIMUM_LEN_CASE_ID,
            HIR_DOCTEST_CLASS_MAXIMUM_LEN_CASE_ID,
            HIR_DOCTEST_PROPERTIES_IS_UTF8_CASE_ID,
            HIR_DOCTEST_PROPERTIES_CAPTURES_LEN_CASE_ID,
            HIR_DOCTEST_PROPERTIES_STATIC_CAPTURES_LEN_CASE_ID,
            HIR_DOCTEST_PROPERTIES_UNION_NEVER_CASE_ID,
            HIR_DOCTEST_PROPERTIES_UNION_UNBOUNDED_CASE_ID,
        ];
        assert_eq!(cases.len(), 13);
        for case_id in cases {
            let disposition = execute_hir_doctest_case(case_id);
            assert_eq!(
                disposition,
                RegexSyntaxCorpusDisposition::Pass {
                    evidence_sha256: hir_doctest_pass_evidence(case_id),
                },
            );
            validate_disposition(&RegexSyntaxCorpusReceipt {
                obligation: RegexSyntaxCorpusObligation {
                    case_id: case_id.to_owned(),
                    kind: RegexSyntaxCorpusCaseKind::Doctest,
                    source_path: if case_id.starts_with("src/hir/literal.rs") {
                        "src/hir/literal.rs"
                    } else {
                        "src/hir/mod.rs"
                    }
                    .to_owned(),
                    source_line: 1,
                    source_sha256: "0".repeat(64),
                    default_harness_member: true,
                    no_default_harness_member: true,
                },
                disposition,
            })
            .expect("supported HIR doctest receipt");
        }
    }

    #[test]
    fn authenticated_hir_seq_doctests_execute_all_25_public_examples() {
        let cases = [
            HIR_DOCTEST_SEQ_CASE_ID,
            HIR_DOCTEST_SEQ_CROSS_FORWARD_BASIC_CASE_ID,
            HIR_DOCTEST_SEQ_CROSS_FORWARD_INFINITE_OTHER_CASE_ID,
            HIR_DOCTEST_SEQ_CROSS_FORWARD_EMPTY_CASE_ID,
            HIR_DOCTEST_SEQ_CROSS_FORWARD_INFINITE_SELF_CASE_ID,
            HIR_DOCTEST_SEQ_CROSS_REVERSE_BASIC_CASE_ID,
            HIR_DOCTEST_SEQ_CROSS_REVERSE_INFINITE_OTHER_CASE_ID,
            HIR_DOCTEST_SEQ_CROSS_REVERSE_EMPTY_CASE_ID,
            HIR_DOCTEST_SEQ_CROSS_REVERSE_INFINITE_SELF_CASE_ID,
            HIR_DOCTEST_SEQ_UNION_BASIC_CASE_ID,
            HIR_DOCTEST_SEQ_UNION_INFINITE_CASE_ID,
            HIR_DOCTEST_SEQ_UNION_EMPTY_BASIC_CASE_ID,
            HIR_DOCTEST_SEQ_UNION_EMPTY_NO_SPLICE_CASE_ID,
            HIR_DOCTEST_SEQ_DEDUP_CASE_ID,
            HIR_DOCTEST_SEQ_SORT_CASE_ID,
            HIR_DOCTEST_SEQ_REVERSE_LITERALS_CASE_ID,
            HIR_DOCTEST_SEQ_MINIMIZE_PREFIX_CASE_ID,
            HIR_DOCTEST_SEQ_MINIMIZE_EMPTY_CASE_ID,
            HIR_DOCTEST_SEQ_KEEP_FIRST_CASE_ID,
            HIR_DOCTEST_SEQ_KEEP_LAST_CASE_ID,
            HIR_DOCTEST_SEQ_COMMON_PREFIX_CASE_ID,
            HIR_DOCTEST_SEQ_COMMON_SUFFIX_CASE_ID,
            HIR_DOCTEST_SEQ_OPTIMIZE_PREFIX_CASE_ID,
            HIR_DOCTEST_SEQ_OPTIMIZE_INFINITE_CASE_ID,
            HIR_DOCTEST_SEQ_OPTIMIZE_SPACE_CASE_ID,
        ];
        assert_eq!(cases.len(), 25);
        for case_id in cases {
            let disposition = execute_hir_doctest_case(case_id);
            assert_eq!(
                disposition,
                RegexSyntaxCorpusDisposition::Pass {
                    evidence_sha256: hir_doctest_pass_evidence(case_id),
                },
            );
            validate_disposition(&RegexSyntaxCorpusReceipt {
                obligation: RegexSyntaxCorpusObligation {
                    case_id: case_id.to_owned(),
                    kind: RegexSyntaxCorpusCaseKind::Doctest,
                    source_path: "src/hir/literal.rs".to_owned(),
                    source_line: 1,
                    source_sha256: "0".repeat(64),
                    default_harness_member: true,
                    no_default_harness_member: true,
                },
                disposition,
            })
            .expect("supported HIR Seq doctest receipt");
        }
    }

    #[test]
    fn authenticated_hir_constructor_doctests_execute_all_6_public_examples() {
        let cases = [
            HIR_DOCTEST_HIR_LITERAL_BYTES_CASE_ID,
            HIR_DOCTEST_HIR_LITERAL_CHAR_CASE_ID,
            HIR_DOCTEST_HIR_CONCAT_CASE_ID,
            HIR_DOCTEST_HIR_ALTERNATION_CLASS_CASE_ID,
            HIR_DOCTEST_HIR_ALTERNATION_PREFIX_CASE_ID,
            HIR_DOCTEST_HIR_DOT_CASE_ID,
        ];
        assert_eq!(cases.len(), 6);
        for case_id in cases {
            let disposition = execute_hir_doctest_case(case_id);
            assert_eq!(
                disposition,
                RegexSyntaxCorpusDisposition::Pass {
                    evidence_sha256: hir_doctest_pass_evidence(case_id),
                },
            );
            validate_disposition(&RegexSyntaxCorpusReceipt {
                obligation: RegexSyntaxCorpusObligation {
                    case_id: case_id.to_owned(),
                    kind: RegexSyntaxCorpusCaseKind::Doctest,
                    source_path: "src/hir/mod.rs".to_owned(),
                    source_line: 1,
                    source_sha256: "0".repeat(64),
                    default_harness_member: true,
                    no_default_harness_member: true,
                },
                disposition,
            })
            .expect("supported HIR constructor doctest receipt");
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
    fn authenticated_hir_class_algebra_cases_execute_all_122_public_outcomes() {
        let cases = [
            (
                HIR_TRANSLATE_CAT_CLASS_FLATTENED_CASE_ID,
                HIR_TRANSLATE_CAT_CLASS_FLATTENED_PROBES.len(),
            ),
            (
                HIR_TRANSLATE_CLASS_BRACKETED_CASE_ID,
                HIR_TRANSLATE_CLASS_BRACKETED_PROBES.len()
                    + HIR_TRANSLATE_CLASS_BRACKETED_ERROR_PROBES.len(),
            ),
            (
                HIR_TRANSLATE_CLASS_BRACKETED_UNION_CASE_ID,
                HIR_TRANSLATE_CLASS_BRACKETED_UNION_PROBES.len(),
            ),
            (
                HIR_TRANSLATE_CLASS_BRACKETED_NESTED_CASE_ID,
                HIR_TRANSLATE_CLASS_BRACKETED_NESTED_PROBES.len(),
            ),
            (
                HIR_TRANSLATE_CLASS_BRACKETED_INTERSECT_CASE_ID,
                HIR_TRANSLATE_CLASS_BRACKETED_INTERSECT_PROBES.len(),
            ),
            (
                HIR_TRANSLATE_CLASS_BRACKETED_INTERSECT_NEGATE_CASE_ID,
                HIR_TRANSLATE_CLASS_BRACKETED_INTERSECT_NEGATE_PROBES.len(),
            ),
            (
                HIR_TRANSLATE_CLASS_BRACKETED_DIFFERENCE_CASE_ID,
                HIR_TRANSLATE_CLASS_BRACKETED_DIFFERENCE_PROBES.len(),
            ),
            (
                HIR_TRANSLATE_CLASS_BRACKETED_SYMMETRIC_DIFFERENCE_CASE_ID,
                HIR_TRANSLATE_CLASS_BRACKETED_SYMMETRIC_DIFFERENCE_PROBES.len(),
            ),
        ];
        assert_eq!(
            cases.iter().map(|(_, outcomes)| outcomes).sum::<usize>(),
            122,
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
            .expect("supported HIR class-algebra receipt");
        }
    }

    #[test]
    fn authenticated_hir_enabled_class_cases_execute_all_102_public_outcomes() {
        let cases = [
            (HIR_TRANSLATE_LITERAL_CASE_ID, 10, true, true),
            (HIR_TRANSLATE_DOT_CASE_ID, 12, true, true),
            (HIR_TRANSLATE_CLASS_ASCII_CASE_ID, 20, true, true),
            (HIR_TRANSLATE_CLASS_PERL_ASCII_CASE_ID, 18, true, true),
            (HIR_TRANSLATE_CLASS_PERL_UNICODE_CASE_ID, 12, true, false),
            (HIR_TRANSLATE_CLASS_UNICODE_GENCAT_CASE_ID, 23, true, false),
            (HIR_TRANSLATE_CLASS_UNICODE_SCRIPT_CASE_ID, 5, true, false),
            (HIR_TRANSLATE_CLASS_UNICODE_AGE_CASE_ID, 1, true, false),
            (
                HIR_TRANSLATE_CLASS_UNICODE_ANY_EMPTY_CASE_ID,
                1,
                true,
                false,
            ),
        ];
        assert_eq!(
            cases
                .iter()
                .map(|(_, outcomes, _, _)| outcomes)
                .sum::<usize>(),
            102,
        );
        for (case_id, _, default_member, no_default_member) in cases {
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
                    default_harness_member: default_member,
                    no_default_harness_member: no_default_member,
                },
                disposition,
            })
            .expect("supported enabled HIR class receipt");
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
