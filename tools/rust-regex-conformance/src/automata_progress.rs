//! Executable scheduling and strict-gain contracts for the authenticated
//! `regex-automata` package-suite inventory.
//!
//! The inventory deliberately has no pass disposition. This module keeps that
//! property: only an adapter function that is compiled into this crate and is
//! actually invoked can produce a pass receipt. The initial registry is empty,
//! so the first report is an honest zero-pass baseline and a deterministic
//! assignment, not an inferred compatibility claim.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
    process::Command,
};

use fre::{
    PlanKind, PlanSelection, PortableBuilder, PortableRegex, PortableRegexSet, RustProfile,
    SearchAccounting, SearchLimits, SearchWindow,
};
use regex_automata::{
    HalfMatch, Input, MatchKind,
    dfa::{Automaton, OverlappingState, dense},
    util::look::{Look, LookMatcher},
};
use serde::{Deserialize, Serialize};

use crate::automata_corpus::{
    REGEX_AUTOMATA_LOOK_MODE_MAX_MATRIX_JSON_BYTES,
    start_mode::{REGEX_AUTOMATA_START_MODE_MAX_REPORT_BYTES, RegexAutomataStartModeMatrixReport},
};

use crate::{
    CandidateIdentity, InventoryError, RegexAutomataCorpusReport, RegexAutomataHarnessKind,
    RegexAutomataLookModeDisposition, RegexAutomataLookModeMatrix, RegexAutomataLookModeReceipt,
    RegexAutomataObligation, authenticate_candidate_source, sha256,
};

mod search_cluster;
mod start_map;
mod state_codec;
mod suffix_literal_count;
mod unicode_word_look;
mod word_look;

pub use search_cluster::{
    REGEX_AUTOMATA_SEARCH_CLUSTER_REPORT_SCHEMA, build_regex_automata_search_cluster_report,
    validate_regex_automata_search_cluster_strict_gain,
};
pub use start_map::{
    REGEX_AUTOMATA_START_MAP_REPORT_SCHEMA, build_regex_automata_start_map_report,
    validate_regex_automata_start_map_strict_gain,
};
pub use state_codec::{
    REGEX_AUTOMATA_STATE_CODEC_REPORT_SCHEMA, build_regex_automata_state_codec_report,
    validate_regex_automata_state_codec_strict_gain,
};
pub use suffix_literal_count::{
    REGEX_AUTOMATA_SUFFIX_LITERAL_COUNT_REPORT_SCHEMA,
    build_regex_automata_suffix_literal_count_report,
    validate_regex_automata_suffix_literal_count_strict_gain,
};
pub use unicode_word_look::{
    REGEX_AUTOMATA_UNICODE_WORD_LOOK_REPORT_SCHEMA, build_regex_automata_unicode_word_look_report,
    validate_regex_automata_unicode_word_look_strict_gain,
};
pub use word_look::{
    REGEX_AUTOMATA_ASCII_WORD_LOOK_REPORT_SCHEMA, build_regex_automata_ascii_word_look_report,
    validate_regex_automata_ascii_word_look_strict_gain,
};

/// Complete candidate coverage report over every feature-mode membership.
pub const REGEX_AUTOMATA_ADAPTER_REPORT_SCHEMA: &str =
    "fre.regex-automata-0.4.14.adapter-report.v3";
/// Report schema for the exact 30-mode `util::look` execution expansion.
pub const REGEX_AUTOMATA_ALL_MODE_LOOK_REPORT_SCHEMA: &str =
    "fre.regex-automata-0.4.14.adapter-report.v4";
const PREVIOUS_REGEX_AUTOMATA_ADAPTER_REPORT_SCHEMA: &str =
    "fre.regex-automata-0.4.14.adapter-report.v2";
const LEGACY_REGEX_AUTOMATA_ADAPTER_REPORT_SCHEMA: &str =
    "fre.regex-automata-0.4.14.adapter-report.v1";
/// One immutable source-work assignment derived from a complete report.
pub const REGEX_AUTOMATA_GAP_ASSIGNMENT_SCHEMA: &str =
    "fre.regex-automata-0.4.14.gap-assignment.v1";

const INVENTORY_UNSUPPORTED_REASON: &str = "fre-adapter.regex-automata-member-not-implemented";
const ASSIGNMENT_TARGET_LIMIT: usize = 16;
const REGEX_AUTOMATA_PROGRESS_MAX_FILE_BYTES: usize = 8 * 1_048_576;
const LOOK_MODE_MATRIX_MEMBER_COMPACT_BYTES: usize = b",\"look_mode_matrix\":".len();
const START_MODE_MATRIX_MEMBER_COMPACT_BYTES: usize = b",\"start_mode_matrix\":".len();
const START_MODE_BASELINE_MEMBER_COMPACT_BYTES: usize = b",\"start_mode_baseline\":".len();
// Adapter reports use compact JSON so embedding changes the old, matrix-free
// envelope by exactly one member prefix plus the matrix's compact encoding.
// Matrix validation independently caps that encoding at 24 MiB.
const REGEX_AUTOMATA_ADAPTER_REPORT_MAX_FILE_BYTES: usize = REGEX_AUTOMATA_PROGRESS_MAX_FILE_BYTES
    + LOOK_MODE_MATRIX_MEMBER_COMPACT_BYTES
    + REGEX_AUTOMATA_LOOK_MODE_MAX_MATRIX_JSON_BYTES
    + START_MODE_MATRIX_MEMBER_COMPACT_BYTES
    + REGEX_AUTOMATA_START_MODE_MAX_REPORT_BYTES
    + START_MODE_BASELINE_MEMBER_COMPACT_BYTES
    + REGEX_AUTOMATA_PROGRESS_MAX_FILE_BYTES;
const LEGACY_REPORT_LIMITATIONS: [&str; 2] = [
    "A pass is emitted only after an exact registered adapter function executes successfully; absent registrations remain unsupported.",
    "One unique harness/case adapter disposition is projected across every authenticated feature-mode membership for that same identity.",
];
const DOCTEST_ONLY_REPORT_LIMITATIONS: [&str; 3] = [
    "A pass requires an exact mode/case execution receipt from a compiled registry membership and exhaustive execution of the authenticated upstream assertion inventory.",
    "No result is projected across build modes; a mode without its own compiled execution remains unsupported.",
    "The current bridge compiles only the package-default doctest mode; vcs-all-features doctest memberships remain unsupported until separately compiled and executed.",
];
const MIXED_DEFAULT_REPORT_LIMITATIONS: [&str; 3] = [
    "A pass requires an exact mode/case execution receipt from a compiled registry membership and exhaustive execution of the authenticated upstream assertion inventory.",
    "No result is projected across build modes; a mode without its own compiled execution remains unsupported.",
    "The current bridge compiles only package-default doctest and unit memberships; VCS feature-mode memberships remain unsupported until separately compiled and executed.",
];
const ALL_MODE_LOOK_REPORT_LIMITATIONS: [&str; 3] = [
    "A pass requires an exact mode/case execution receipt from a compiled registry membership and exhaustive execution of the authenticated upstream assertion inventory.",
    "No result is projected across build modes; every added util::look membership is linked to its own authenticated feature-mode compilation and direct unit-test execution.",
    "All 30 authenticated regex-automata unit modes execute the same four sealed util::look cases; every other inventory membership remains unsupported unless independently compiled and executed.",
];

const COMPILED_MODE_ID: &str = "package-default-doctest";
const COMPILED_UNIT_MODE_ID: &str = "package-default-unit";
const AUTOMATON_SOURCE_PATH: &str = "src/dfa/automaton.rs";
const AUTOMATON_SOURCE_SHA256: &str =
    "a2af61cdfb7f16a8419a25ccb3ae250afe736ff397c7a3101c8a77781d096a9b";
const LOOK_SOURCE_PATH: &str = "src/util/look.rs";
const LOOK_SOURCE_SHA256: &str = "fca6dac7bf7b3b975f177db91e122af89e1510b3664d04210ca8b84738a08305";
pub(super) const REGEX_SOURCE_PATH: &str = "src/dfa/regex.rs";
pub(super) const REGEX_SOURCE_SHA256: &str =
    "567c7a59ca194117986f1818c092b31f825e860fb1b2c55c7de87de97eebb787";
const LOOK_FULL_SPAN_SHA256: &str =
    "7d4a1ac128aa3df29bab8bece1cd9481df88abfdb31ee7086668503f48eead84";
const LOOK_TARGET_IDENTITIES_SHA256: &str =
    "053675c6955c5ca165db98bf1a684105cbb59176b1893ab9b022a4d98fd16c9b";
const LOOK_BASE_REVISION: &str = "dfdba9d2848d7d228d53bffcefe7843fbe6307c9";
const LOOK_BASE_TREE: &str = "5434af1bf92b264f46149fa50dcf533503212133";
const LOOK_ALL_MODE_PREDECESSOR_REVISION: &str = "6512b9510b11a458e2c2e2cc5b90973a33f92a48";
const LOOK_ALL_MODE_PREDECESSOR_TREE: &str = "b1ee85dba9114d10112cf29b7ec87d70665709e3";
const LOOK_ALL_MODE_TARGET_IDENTITIES_SHA256: &str =
    "ab829c5294f23107c12eddfb24dbf31060da7ca1fb0967264a3e6fc5562129df";
const LOOK_ALL_MODE_NEW_IDENTITIES_SHA256: &str =
    "89d980ec919ef2d85dc051720e43c6afc913aca0ca8da2be8f4595ab2ff94e70";
const LOOK_ALL_MODE_FINAL_UNSUPPORTED_SHA256: &str =
    "aef97899de5d6d023ff2092f2226b06c9efec48c43b5dfeb4444c5a36ccc2678";
const LOOK_ALL_MODE_UNCHANGED_IDENTITIES_SHA256: &str =
    "2488d9b966096fd99371073de627f5d144ff4e0a166edcd63e73acdb55b1043b";
const PATTERN_LEN_CASE: &str =
    "src/dfa/automaton.rs - dfa::automaton::Automaton::pattern_len (line 800)";
const PATTERN_LEN_MANY_CASE: &str =
    "src/dfa/automaton.rs - dfa::automaton::Automaton::pattern_len (line 820)";
const IS_SPECIAL_STATE_CASE: &str =
    "src/dfa/automaton.rs - dfa::automaton::Automaton::is_special_state (line 416)";
const IS_START_STATE_CASE: &str =
    "src/dfa/automaton.rs - dfa::automaton::Automaton::is_start_state (line 648)";
const MATCH_LEN_CASE: &str =
    "src/dfa/automaton.rs - dfa::automaton::Automaton::match_len (line 869)";
const PATTERN_LEN_ALWAYS_CASE: &str =
    "src/dfa/automaton.rs - dfa::automaton::Automaton::pattern_len (line 810)";
const TRY_SEARCH_OVERLAPPING_FWD_CASE: &str =
    "src/dfa/automaton.rs - dfa::automaton::Automaton::try_search_overlapping_fwd (line 1553)";
const TRY_SEARCH_FWD_CASE: &str =
    "src/dfa/automaton.rs - dfa::automaton::Automaton::try_search_fwd (line 1209)";
const TRY_SEARCH_FWD_BOUNDS_CASE: &str =
    "src/dfa/automaton.rs - dfa::automaton::Automaton::try_search_fwd (line 1267)";
const LOOK_END_LINE_CASE: &str = "util::look::tests::look_matches_end_line";
const LOOK_END_TEXT_CASE: &str = "util::look::tests::look_matches_end_text";
const LOOK_START_LINE_CASE: &str = "util::look::tests::look_matches_start_line";
const LOOK_START_TEXT_CASE: &str = "util::look::tests::look_matches_start_text";

/// Candidate disposition for one exact feature-mode membership.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RegexAutomataAdapterDisposition {
    Pass { evidence_sha256: String },
    Unsupported { reason_code: String },
    Fault { stage: String, reason_code: String },
}

/// One result bound to an exact inventory obligation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataAdapterReceipt {
    pub mode_id: String,
    pub harness: RegexAutomataHarnessKind,
    pub case_id: String,
    pub disposition: RegexAutomataAdapterDisposition,
}

/// One assertion parsed from an exact authenticated upstream rustdoc span.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataAssertionContract {
    pub assertion_id: String,
    pub source_line: usize,
    pub source_line_sha256: String,
    pub expected_observation: String,
}

/// Exact upstream source and exhaustive assertion inventory for one doctest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataSourceContract {
    pub source_path: String,
    pub source_sha256: String,
    pub span_start_line: usize,
    pub span_end_line: usize,
    pub source_span_sha256: String,
    pub assertion_inventory_sha256: String,
    pub assertions: Vec<RegexAutomataAssertionContract>,
}

/// The one Cargo feature/harness mode in which an adapter actually executed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataModeExecution {
    pub mode_id: String,
    pub harness: RegexAutomataHarnessKind,
    pub default_features: bool,
    pub all_features: bool,
    pub features: Vec<String>,
    pub dependency_package: String,
    pub dependency_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode_evidence_sha256: Option<String>,
}

/// Both sides of one explicitly bound upstream assertion execution.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataAssertionExecution {
    pub assertion_id: String,
    pub upstream_observation: String,
    pub fre_observation: String,
}

/// Auditable evidence for one exact feature-mode membership. The pass
/// disposition's evidence SHA-256 is the canonical hash of this entire value.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataExecutionReceipt {
    pub mode: RegexAutomataModeExecution,
    pub harness: RegexAutomataHarnessKind,
    pub case_id: String,
    pub source: RegexAutomataSourceContract,
    pub assertion_executions: Vec<RegexAutomataAssertionExecution>,
}

/// Complete result cardinalities.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataAdapterCounts {
    pub pass: usize,
    pub unsupported: usize,
    pub fault: usize,
    pub total: usize,
}

/// Payload covered by [`RegexAutomataAdapterReport::payload_sha256`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataAdapterReportPayload {
    pub inventory_payload_sha256: String,
    pub obligation_inventory_sha256: String,
    pub candidate: CandidateIdentity,
    pub counts: RegexAutomataAdapterCounts,
    pub receipts: Vec<RegexAutomataAdapterReceipt>,
    #[serde(default)]
    pub execution_receipts: Vec<RegexAutomataExecutionReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub look_mode_matrix: Option<RegexAutomataLookModeMatrix>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_mode_matrix: Option<Box<RegexAutomataStartModeMatrixReport>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_mode_baseline: Option<Box<RegexAutomataAdapterReport>>,
    pub limitations: Vec<String>,
}

/// Complete adapter report. Its denominator is always the inventory's exact
/// 3,842 feature-mode memberships.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataAdapterReport {
    pub schema: String,
    pub payload_sha256: String,
    pub payload: RegexAutomataAdapterReportPayload,
}

/// All feature-mode memberships for one independently implementable case.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataGapTarget {
    pub harness: RegexAutomataHarnessKind,
    pub case_id: String,
    pub mode_ids: Vec<String>,
}

/// Deterministic work packet for one pending package-suite family.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataGapAssignment {
    pub schema: String,
    pub attempt_id: String,
    pub slot: usize,
    pub base: String,
    pub baseline_report_sha256: String,
    pub baseline_payload_sha256: String,
    pub inventory_payload_sha256: String,
    pub obligation_inventory_sha256: String,
    pub family: String,
    pub targets: Vec<RegexAutomataGapTarget>,
    pub targets_sha256: String,
}

/// Strict-gain summary returned only after all no-regression checks pass.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegexAutomataStrictGain {
    pub family: String,
    pub gained_unique_cases: usize,
    pub gained_mode_memberships: usize,
    pub previous_pass: usize,
    pub current_pass: usize,
}

type AdapterFunction =
    fn(&AdapterContext<'_>) -> Result<Vec<RegexAutomataAssertionExecution>, String>;

#[derive(Clone, Copy, Eq, PartialEq)]
struct AssertionSpec {
    assertion_id: &'static str,
    source_line: usize,
    source_line_sha256: &'static str,
    expected_observation: &'static str,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct SourceContractSpec {
    source_path: &'static str,
    source_sha256: &'static str,
    span_start_line: usize,
    span_end_line: usize,
    source_span: &'static str,
    source_span_sha256: &'static str,
    assertion_inventory_sha256: &'static str,
    assertions: &'static [AssertionSpec],
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct TrySearchFwdBoundsVector {
    pattern: &'static str,
    haystack: &'static str,
    range_start: usize,
    range_end: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LookKind {
    StartLine,
    EndLine,
    StartText,
    EndText,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LookAssertionVector {
    assertion_id: &'static str,
    haystack: &'static str,
    at: usize,
    expected: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct LookCaseSpec {
    case_id: &'static str,
    kind: LookKind,
    pattern: &'static str,
    source: SourceContractSpec,
    vectors: &'static [LookAssertionVector],
}

struct AdapterContext<'a> {
    mode: &'a RegexAutomataModeExecution,
}

#[derive(Clone, Copy)]
struct RegisteredAdapter {
    mode_id: &'static str,
    harness: RegexAutomataHarnessKind,
    case_id: &'static str,
    source: SourceContractSpec,
    run: AdapterFunction,
}

#[derive(Serialize)]
struct RegistryManifestEntry<'a> {
    mode_id: &'a str,
    harness: RegexAutomataHarnessKind,
    case_id: &'a str,
    source: RegexAutomataSourceContract,
    observer_id: &'static str,
}

const PATTERN_LEN_ASSERTIONS: &[AssertionSpec] = &[AssertionSpec {
    assertion_id: "pattern-len-never-match-zero",
    source_line: 804,
    source_line_sha256: "3b7e88058c1a1fa94a3e1d8f128b2ff7ed129588f2eb3bd590c2282b2498adf9",
    expected_observation: "usize:0",
}];
const PATTERN_LEN_MANY_ASSERTIONS: &[AssertionSpec] = &[AssertionSpec {
    assertion_id: "pattern-len-many-three",
    source_line: 824,
    source_line_sha256: "e666e42f7d3083264808f23a7f3cc609521cb456f6ac2c0c5849434cfade1c25",
    expected_observation: "usize:3",
}];
const IS_SPECIAL_STATE_ASSERTIONS: &[AssertionSpec] = &[
    AssertionSpec {
        assertion_id: "special-alpha-pattern",
        source_line: 479,
        source_line_sha256: "6b3249670a94041d8abcbb5546a0419968e8dc0252068ab1a586333e19fb0fa8",
        expected_observation: "usize:0",
    },
    AssertionSpec {
        assertion_id: "special-alpha-offset",
        source_line: 480,
        source_line_sha256: "d8ccef8020510ae2c8fa4b14c5c519292daf2bf80286c5d5690272a7be42d880",
        expected_observation: "usize:10",
    },
    AssertionSpec {
        assertion_id: "special-eoi-pattern",
        source_line: 489,
        source_line_sha256: "6b3249670a94041d8abcbb5546a0419968e8dc0252068ab1a586333e19fb0fa8",
        expected_observation: "usize:0",
    },
    AssertionSpec {
        assertion_id: "special-eoi-offset",
        source_line: 490,
        source_line_sha256: "d13192f290c03a1cfae4194b17587819d6cbd1d09b3ab229619395805cd0e5c5",
        expected_observation: "usize:15",
    },
    AssertionSpec {
        assertion_id: "special-many-head-pattern",
        source_line: 498,
        source_line_sha256: "7bcf380536f373b32ee34eb7869ed5745c5c94853f14ca23f7645bbd0a1cfaf4",
        expected_observation: "usize:1",
    },
    AssertionSpec {
        assertion_id: "special-many-head-offset",
        source_line: 499,
        source_line_sha256: "58a12a90be71949903c00cdcb1b10a65779b5c31ec8c1bee6db49a195a84e8fd",
        expected_observation: "usize:3",
    },
    AssertionSpec {
        assertion_id: "special-many-middle-pattern",
        source_line: 501,
        source_line_sha256: "6b3249670a94041d8abcbb5546a0419968e8dc0252068ab1a586333e19fb0fa8",
        expected_observation: "usize:0",
    },
    AssertionSpec {
        assertion_id: "special-many-middle-offset",
        source_line: 502,
        source_line_sha256: "a18a1e55f769c74ebef06b3b77094b7079a65f40c7427ad4a323be7d286c1e1e",
        expected_observation: "usize:7",
    },
    AssertionSpec {
        assertion_id: "special-many-tail-pattern",
        source_line: 504,
        source_line_sha256: "7bcf380536f373b32ee34eb7869ed5745c5c94853f14ca23f7645bbd0a1cfaf4",
        expected_observation: "usize:1",
    },
    AssertionSpec {
        assertion_id: "special-many-tail-offset",
        source_line: 505,
        source_line_sha256: "f890c2127dafdef9733747c70b250262373e413e9772292ece317df540076029",
        expected_observation: "usize:5",
    },
];
const IS_START_STATE_ASSERTIONS: &[AssertionSpec] = &[
    AssertionSpec {
        assertion_id: "start-prefix-pattern",
        source_line: 727,
        source_line_sha256: "6b3249670a94041d8abcbb5546a0419968e8dc0252068ab1a586333e19fb0fa8",
        expected_observation: "usize:0",
    },
    AssertionSpec {
        assertion_id: "start-prefix-offset",
        source_line: 728,
        source_line_sha256: "d13192f290c03a1cfae4194b17587819d6cbd1d09b3ab229619395805cd0e5c5",
        expected_observation: "usize:15",
    },
    AssertionSpec {
        assertion_id: "start-no-prefix-pattern",
        source_line: 733,
        source_line_sha256: "6b3249670a94041d8abcbb5546a0419968e8dc0252068ab1a586333e19fb0fa8",
        expected_observation: "usize:0",
    },
    AssertionSpec {
        assertion_id: "start-no-prefix-offset",
        source_line: 734,
        source_line_sha256: "d13192f290c03a1cfae4194b17587819d6cbd1d09b3ab229619395805cd0e5c5",
        expected_observation: "usize:15",
    },
    AssertionSpec {
        assertion_id: "start-wrong-prefix-none",
        source_line: 738,
        source_line_sha256: "5da41fff987b44ef31e7dde327d08810b7ef0844074ea010a91316ed9ef990cb",
        expected_observation: "half-match:none",
    },
];
const MATCH_LEN_ASSERTIONS: &[AssertionSpec] = &[
    AssertionSpec {
        assertion_id: "match-len-is-match",
        source_line: 889,
        source_line_sha256: "9512b440c7d6eff01d10cc8ae6b092054bd37e21f5cc6e6aefddb8515dfc4b61",
        expected_observation: "bool:true",
    },
    AssertionSpec {
        assertion_id: "match-len-count",
        source_line: 890,
        source_line_sha256: "15bc72b327319af2fa9539f13f0ab5c52962b74ad70ce84a53c6c005716800b6",
        expected_observation: "usize:3",
    },
    AssertionSpec {
        assertion_id: "match-len-pattern-first",
        source_line: 893,
        source_line_sha256: "a8ba7fc12f6f698efc043aab033bb19b525bd698b3131763fdc8f7d43a2bdba9",
        expected_observation: "usize:3",
    },
    AssertionSpec {
        assertion_id: "match-len-pattern-second",
        source_line: 894,
        source_line_sha256: "c48b79a8ca0e69647ab9c3abba962f585d1ab6534b7e818da3b62c1ac7ae614b",
        expected_observation: "usize:0",
    },
    AssertionSpec {
        assertion_id: "match-len-pattern-third",
        source_line: 895,
        source_line_sha256: "2e87ea91642f8ad9c9d1d5a98d3a170bd140a4144d58ea1798ee61caf5a5c467",
        expected_observation: "usize:1",
    },
];
const PATTERN_LEN_ALWAYS_ASSERTIONS: &[AssertionSpec] = &[AssertionSpec {
    assertion_id: "pattern-len-always-match-one",
    source_line: 814,
    source_line_sha256: "49178ef715e91c23eae56c7523f0dec2e7391b634d12920f3ecf74d7b3a819e5",
    expected_observation: "usize:1",
}];
const TRY_SEARCH_OVERLAPPING_FWD_ASSERTIONS: &[AssertionSpec] = &[
    AssertionSpec {
        assertion_id: "overlap-fwd-earliest",
        source_line: 1568,
        source_line_sha256: "a3a1bc37ecfc2e6db340ee89694d2647844350529d1e278478b666352206a713",
        expected_observation: "half-match:some:pattern=1:offset=4",
    },
    AssertionSpec {
        assertion_id: "overlap-fwd-next",
        source_line: 1577,
        source_line_sha256: "a3a1bc37ecfc2e6db340ee89694d2647844350529d1e278478b666352206a713",
        expected_observation: "half-match:some:pattern=0:offset=4",
    },
];
const TRY_SEARCH_FWD_ASSERTIONS: &[AssertionSpec] = &[
    AssertionSpec {
        assertion_id: "try-search-fwd-foo-digits",
        source_line: 1214,
        source_line_sha256: "70a54c1802196923425dc9837c82c5fe2b5e2b879e45c7d7cec2797a39f95411",
        expected_observation: "half-match:some:pattern=0:offset=8",
    },
    AssertionSpec {
        assertion_id: "try-search-fwd-leftmost-first",
        source_line: 1221,
        source_line_sha256: "5e5c9f3ab5a9a805d5c96a396780de77d1b202364584d5c86b4d1f37032c8b67",
        expected_observation: "half-match:some:pattern=0:offset=3",
    },
];
const TRY_SEARCH_FWD_BOUNDS_ASSERTIONS: &[AssertionSpec] = &[
    AssertionSpec {
        assertion_id: "try-search-fwd-bounds-subslice",
        source_line: 1283,
        source_line_sha256: "4fe1a4118cc23d46ae3c8d9f6a2321f9ac189c31e1e0b030d22eb0ff836509e5",
        expected_observation: "half-match:some:pattern=0:offset=3",
    },
    AssertionSpec {
        assertion_id: "try-search-fwd-bounds-context",
        source_line: 1292,
        source_line_sha256: "4fe1a4118cc23d46ae3c8d9f6a2321f9ac189c31e1e0b030d22eb0ff836509e5",
        expected_observation: "half-match:none",
    },
];
const TRY_SEARCH_FWD_BOUNDS_VECTOR: TrySearchFwdBoundsVector = TrySearchFwdBoundsVector {
    pattern: r"(?-u)\b[0-9]{3}\b",
    haystack: "foo123bar",
    range_start: 3,
    range_end: 6,
};

const LOOK_FULL_SOURCE_SPAN: &str = include_str!("fixtures/look-tests-1700-1767.txt");
const LOOK_TARGET_IDENTITIES: &str = concat!(
    "package-default-unit\tunit\tutil::look::tests::look_matches_end_line\n",
    "package-default-unit\tunit\tutil::look::tests::look_matches_end_text\n",
    "package-default-unit\tunit\tutil::look::tests::look_matches_start_line\n",
    "package-default-unit\tunit\tutil::look::tests::look_matches_start_text\n",
);

macro_rules! look_assertion {
    ($id:literal, $line:literal, $sha:literal, $expected:literal) => {
        AssertionSpec {
            assertion_id: $id,
            source_line: $line,
            source_line_sha256: $sha,
            expected_observation: $expected,
        }
    };
}

macro_rules! look_vector {
    ($id:literal, $haystack:literal, $at:literal, $expected:literal) => {
        LookAssertionVector {
            assertion_id: $id,
            haystack: $haystack,
            at: $at,
            expected: $expected,
        }
    };
}

const LOOK_START_LINE_ASSERTIONS: &[AssertionSpec] = &[
    look_assertion!(
        "start-line-01",
        1713,
        "377dfed8f74dbe76733e82eed63b286d848175afe150f159854e895d736694e8",
        "bool:true"
    ),
    look_assertion!(
        "start-line-02",
        1714,
        "7b2cfa46bc12bb41f8dd64a5a3f45e0603c5976d41eda5fea32a80208c63fde3",
        "bool:true"
    ),
    look_assertion!(
        "start-line-03",
        1715,
        "b42d9fdef3267e00e4e2dd9db9e1bc1db76fbec9e55717474236e2118574a966",
        "bool:true"
    ),
    look_assertion!(
        "start-line-04",
        1716,
        "cc0496799a38779e4a93d2e1dbf3f89d7f41cde7a21bc0d07cf3ae710799290d",
        "bool:true"
    ),
    look_assertion!(
        "start-line-05",
        1717,
        "14b0b97ccabd2878376f3a74775e207a7b556a63a5bdec8c726c032e778a9525",
        "bool:true"
    ),
    look_assertion!(
        "start-line-06",
        1719,
        "6ab89399ee98889064e395fd85629964a999a957fbb752245e5d66acaf487c9c",
        "bool:false"
    ),
    look_assertion!(
        "start-line-07",
        1720,
        "db5782d607b536a50e01ae79fc3a8fed05c2d99add15f883936b76075e70efca",
        "bool:false"
    ),
];
const LOOK_START_LINE_VECTORS: &[LookAssertionVector] = &[
    look_vector!("start-line-01", "", 0, true),
    look_vector!("start-line-02", "\n", 0, true),
    look_vector!("start-line-03", "\n", 1, true),
    look_vector!("start-line-04", "a", 0, true),
    look_vector!("start-line-05", "\na", 1, true),
    look_vector!("start-line-06", "a", 1, false),
    look_vector!("start-line-07", "a\na", 1, false),
];

const LOOK_END_LINE_ASSERTIONS: &[AssertionSpec] = &[
    look_assertion!(
        "end-line-01",
        1727,
        "377dfed8f74dbe76733e82eed63b286d848175afe150f159854e895d736694e8",
        "bool:true"
    ),
    look_assertion!(
        "end-line-02",
        1728,
        "b42d9fdef3267e00e4e2dd9db9e1bc1db76fbec9e55717474236e2118574a966",
        "bool:true"
    ),
    look_assertion!(
        "end-line-03",
        1729,
        "e9135de67b9945051bbbb48b42c7443029de4a65e359146986f7c38182ee287b",
        "bool:true"
    ),
    look_assertion!(
        "end-line-04",
        1730,
        "a88d87906229d739eb4b3fffd47c7f364a57a5eb4060ede6ff73476aaee482c8",
        "bool:true"
    ),
    look_assertion!(
        "end-line-05",
        1731,
        "0c025b0926008a9be12f52a21ea90eb1f4ce1df9895af7027f85a8f63ad60bf5",
        "bool:true"
    ),
    look_assertion!(
        "end-line-06",
        1733,
        "77a69a1cba2710948745e169c85a459bb230077bdebf5d3209cb8483877f254c",
        "bool:false"
    ),
    look_assertion!(
        "end-line-07",
        1734,
        "3d696539cf90acd95b83dd8c5402da3d3812f0ed8e63003bcacfb3bbfa65579d",
        "bool:false"
    ),
    look_assertion!(
        "end-line-08",
        1735,
        "dd8b6b9a75a9c6ac1c16e96cf3439fa6554e4a0448273cef0acc5bfae8947170",
        "bool:false"
    ),
    look_assertion!(
        "end-line-09",
        1736,
        "edc6f359cf4db83bed32bc0e0910c10f0f540a770dc47b8abf2c22d17bf1501a",
        "bool:false"
    ),
];
const LOOK_END_LINE_VECTORS: &[LookAssertionVector] = &[
    look_vector!("end-line-01", "", 0, true),
    look_vector!("end-line-02", "\n", 1, true),
    look_vector!("end-line-03", "\na", 0, true),
    look_vector!("end-line-04", "\na", 2, true),
    look_vector!("end-line-05", "a\na", 1, true),
    look_vector!("end-line-06", "a", 0, false),
    look_vector!("end-line-07", "\na", 1, false),
    look_vector!("end-line-08", "a\na", 0, false),
    look_vector!("end-line-09", "a\na", 2, false),
];

const LOOK_START_TEXT_ASSERTIONS: &[AssertionSpec] = &[
    look_assertion!(
        "start-text-01",
        1743,
        "377dfed8f74dbe76733e82eed63b286d848175afe150f159854e895d736694e8",
        "bool:true"
    ),
    look_assertion!(
        "start-text-02",
        1744,
        "7b2cfa46bc12bb41f8dd64a5a3f45e0603c5976d41eda5fea32a80208c63fde3",
        "bool:true"
    ),
    look_assertion!(
        "start-text-03",
        1745,
        "cc0496799a38779e4a93d2e1dbf3f89d7f41cde7a21bc0d07cf3ae710799290d",
        "bool:true"
    ),
    look_assertion!(
        "start-text-04",
        1747,
        "3a7f74fdd5456c3de6a8bfd94b09e3c4372fbc872dbaa86d3a4d4737501c4e8e",
        "bool:false"
    ),
    look_assertion!(
        "start-text-05",
        1748,
        "3d696539cf90acd95b83dd8c5402da3d3812f0ed8e63003bcacfb3bbfa65579d",
        "bool:false"
    ),
    look_assertion!(
        "start-text-06",
        1749,
        "6ab89399ee98889064e395fd85629964a999a957fbb752245e5d66acaf487c9c",
        "bool:false"
    ),
    look_assertion!(
        "start-text-07",
        1750,
        "db5782d607b536a50e01ae79fc3a8fed05c2d99add15f883936b76075e70efca",
        "bool:false"
    ),
];
const LOOK_START_TEXT_VECTORS: &[LookAssertionVector] = &[
    look_vector!("start-text-01", "", 0, true),
    look_vector!("start-text-02", "\n", 0, true),
    look_vector!("start-text-03", "a", 0, true),
    look_vector!("start-text-04", "\n", 1, false),
    look_vector!("start-text-05", "\na", 1, false),
    look_vector!("start-text-06", "a", 1, false),
    look_vector!("start-text-07", "a\na", 1, false),
];

const LOOK_END_TEXT_ASSERTIONS: &[AssertionSpec] = &[
    look_assertion!(
        "end-text-01",
        1757,
        "377dfed8f74dbe76733e82eed63b286d848175afe150f159854e895d736694e8",
        "bool:true"
    ),
    look_assertion!(
        "end-text-02",
        1758,
        "b42d9fdef3267e00e4e2dd9db9e1bc1db76fbec9e55717474236e2118574a966",
        "bool:true"
    ),
    look_assertion!(
        "end-text-03",
        1759,
        "a88d87906229d739eb4b3fffd47c7f364a57a5eb4060ede6ff73476aaee482c8",
        "bool:true"
    ),
    look_assertion!(
        "end-text-04",
        1761,
        "5c5d4f64bdd5b41dc02c36db4fe0c5a294da9d1fb35552e4ac0ed8b40d554540",
        "bool:false"
    ),
    look_assertion!(
        "end-text-05",
        1762,
        "db5782d607b536a50e01ae79fc3a8fed05c2d99add15f883936b76075e70efca",
        "bool:false"
    ),
    look_assertion!(
        "end-text-06",
        1763,
        "77a69a1cba2710948745e169c85a459bb230077bdebf5d3209cb8483877f254c",
        "bool:false"
    ),
    look_assertion!(
        "end-text-07",
        1764,
        "3d696539cf90acd95b83dd8c5402da3d3812f0ed8e63003bcacfb3bbfa65579d",
        "bool:false"
    ),
    look_assertion!(
        "end-text-08",
        1765,
        "dd8b6b9a75a9c6ac1c16e96cf3439fa6554e4a0448273cef0acc5bfae8947170",
        "bool:false"
    ),
    look_assertion!(
        "end-text-09",
        1766,
        "edc6f359cf4db83bed32bc0e0910c10f0f540a770dc47b8abf2c22d17bf1501a",
        "bool:false"
    ),
];
const LOOK_END_TEXT_VECTORS: &[LookAssertionVector] = &[
    look_vector!("end-text-01", "", 0, true),
    look_vector!("end-text-02", "\n", 1, true),
    look_vector!("end-text-03", "\na", 2, true),
    look_vector!("end-text-04", "\na", 0, false),
    look_vector!("end-text-05", "a\na", 1, false),
    look_vector!("end-text-06", "a", 0, false),
    look_vector!("end-text-07", "\na", 1, false),
    look_vector!("end-text-08", "a\na", 0, false),
    look_vector!("end-text-09", "a\na", 2, false),
];

const LOOK_START_LINE_SOURCE_SPAN: &str = r#"    #[test]
    fn look_matches_start_line() {
        let look = Look::StartLF;

        assert!(testlook!(look, "", 0));
        assert!(testlook!(look, "\n", 0));
        assert!(testlook!(look, "\n", 1));
        assert!(testlook!(look, "a", 0));
        assert!(testlook!(look, "\na", 1));

        assert!(!testlook!(look, "a", 1));
        assert!(!testlook!(look, "a\na", 1));
    }
"#;
const LOOK_END_LINE_SOURCE_SPAN: &str = r#"    #[test]
    fn look_matches_end_line() {
        let look = Look::EndLF;

        assert!(testlook!(look, "", 0));
        assert!(testlook!(look, "\n", 1));
        assert!(testlook!(look, "\na", 0));
        assert!(testlook!(look, "\na", 2));
        assert!(testlook!(look, "a\na", 1));

        assert!(!testlook!(look, "a", 0));
        assert!(!testlook!(look, "\na", 1));
        assert!(!testlook!(look, "a\na", 0));
        assert!(!testlook!(look, "a\na", 2));
    }
"#;
const LOOK_START_TEXT_SOURCE_SPAN: &str = r#"    #[test]
    fn look_matches_start_text() {
        let look = Look::Start;

        assert!(testlook!(look, "", 0));
        assert!(testlook!(look, "\n", 0));
        assert!(testlook!(look, "a", 0));

        assert!(!testlook!(look, "\n", 1));
        assert!(!testlook!(look, "\na", 1));
        assert!(!testlook!(look, "a", 1));
        assert!(!testlook!(look, "a\na", 1));
    }
"#;
const LOOK_END_TEXT_SOURCE_SPAN: &str = r#"    #[test]
    fn look_matches_end_text() {
        let look = Look::End;

        assert!(testlook!(look, "", 0));
        assert!(testlook!(look, "\n", 1));
        assert!(testlook!(look, "\na", 2));

        assert!(!testlook!(look, "\na", 0));
        assert!(!testlook!(look, "a\na", 1));
        assert!(!testlook!(look, "a", 0));
        assert!(!testlook!(look, "\na", 1));
        assert!(!testlook!(look, "a\na", 0));
        assert!(!testlook!(look, "a\na", 2));
    }
"#;

const LOOK_START_LINE_SOURCE: SourceContractSpec = SourceContractSpec {
    source_path: LOOK_SOURCE_PATH,
    source_sha256: LOOK_SOURCE_SHA256,
    span_start_line: 1709,
    span_end_line: 1721,
    source_span: LOOK_START_LINE_SOURCE_SPAN,
    source_span_sha256: "0fa8cd8b1e6235cb8d2e55af690d3dbd5bbd04327a6c2999948111ab70ba6bcc",
    assertion_inventory_sha256: "a7437eaf5a12a7b85ccfaa5e0bce44661254c4082ac9dbe20866a6f363894995",
    assertions: LOOK_START_LINE_ASSERTIONS,
};
const LOOK_END_LINE_SOURCE: SourceContractSpec = SourceContractSpec {
    source_path: LOOK_SOURCE_PATH,
    source_sha256: LOOK_SOURCE_SHA256,
    span_start_line: 1723,
    span_end_line: 1737,
    source_span: LOOK_END_LINE_SOURCE_SPAN,
    source_span_sha256: "a51c9ed353e6dc78a266e37d247570e5d201ce1e681ad667375097c5e816b0e5",
    assertion_inventory_sha256: "4bd75d51227505183e3504c0dd5b279a7e1111e98b5fd20f77749d371cb280c7",
    assertions: LOOK_END_LINE_ASSERTIONS,
};
const LOOK_START_TEXT_SOURCE: SourceContractSpec = SourceContractSpec {
    source_path: LOOK_SOURCE_PATH,
    source_sha256: LOOK_SOURCE_SHA256,
    span_start_line: 1739,
    span_end_line: 1751,
    source_span: LOOK_START_TEXT_SOURCE_SPAN,
    source_span_sha256: "e079a9104f429305c5e613c0b025a1f1b39f7d1eed6702fe2426239a88cf6bc3",
    assertion_inventory_sha256: "4609e1c99a84ed463c0026893e60ba4abc82147a86178d9a47db2427b9ee578f",
    assertions: LOOK_START_TEXT_ASSERTIONS,
};
const LOOK_END_TEXT_SOURCE: SourceContractSpec = SourceContractSpec {
    source_path: LOOK_SOURCE_PATH,
    source_sha256: LOOK_SOURCE_SHA256,
    span_start_line: 1753,
    span_end_line: 1767,
    source_span: LOOK_END_TEXT_SOURCE_SPAN,
    source_span_sha256: "6af248fac72ca90b58753b6554be9c92e3c886d827c629d8fcb8d5fbb0e71ccb",
    assertion_inventory_sha256: "46ecf1705053e21af088502624e82140fbdcdc1aa546d1176bacd1be1878abe4",
    assertions: LOOK_END_TEXT_ASSERTIONS,
};

const LOOK_END_LINE: LookCaseSpec = LookCaseSpec {
    case_id: LOOK_END_LINE_CASE,
    kind: LookKind::EndLine,
    pattern: r"(?m:$)",
    source: LOOK_END_LINE_SOURCE,
    vectors: LOOK_END_LINE_VECTORS,
};
const LOOK_END_TEXT: LookCaseSpec = LookCaseSpec {
    case_id: LOOK_END_TEXT_CASE,
    kind: LookKind::EndText,
    pattern: r"\z",
    source: LOOK_END_TEXT_SOURCE,
    vectors: LOOK_END_TEXT_VECTORS,
};
const LOOK_START_LINE: LookCaseSpec = LookCaseSpec {
    case_id: LOOK_START_LINE_CASE,
    kind: LookKind::StartLine,
    pattern: r"(?m:^)",
    source: LOOK_START_LINE_SOURCE,
    vectors: LOOK_START_LINE_VECTORS,
};
const LOOK_START_TEXT: LookCaseSpec = LookCaseSpec {
    case_id: LOOK_START_TEXT_CASE,
    kind: LookKind::StartText,
    pattern: r"\A",
    source: LOOK_START_TEXT_SOURCE,
    vectors: LOOK_START_TEXT_VECTORS,
};
const LOOK_CASES: &[LookCaseSpec] = &[
    LOOK_END_LINE,
    LOOK_END_TEXT,
    LOOK_START_LINE,
    LOOK_START_TEXT,
];

const PATTERN_LEN_SOURCE: SourceContractSpec = SourceContractSpec {
    source_path: AUTOMATON_SOURCE_PATH,
    source_sha256: AUTOMATON_SOURCE_SHA256,
    span_start_line: 800,
    span_end_line: 806,
    source_span: concat!(
        "    /// ```\n",
        "    /// use regex_automata::dfa::{Automaton, dense::DFA};\n",
        "    ///\n",
        "    /// let dfa: DFA<Vec<u32>> = DFA::never_match()?;\n",
        "    /// assert_eq!(dfa.pattern_len(), 0);\n",
        "    /// # Ok::<(), Box<dyn std::error::Error>>(())\n",
        "    /// ```\n",
    ),
    source_span_sha256: "f57f6c9927950180823c7d9f981ec01aad1fda3e6ded8abc317892aa1aa95ca7",
    assertion_inventory_sha256: "7c56b2f92e4e226ae4be923582b0ef39d808755f169964a021ca831973b2542f",
    assertions: PATTERN_LEN_ASSERTIONS,
};

const PATTERN_LEN_MANY_SOURCE: SourceContractSpec = SourceContractSpec {
    source_path: AUTOMATON_SOURCE_PATH,
    source_sha256: AUTOMATON_SOURCE_SHA256,
    span_start_line: 820,
    span_end_line: 826,
    source_span: concat!(
        "    /// ```\n",
        "    /// use regex_automata::dfa::{Automaton, dense::DFA};\n",
        "    ///\n",
        "    /// let dfa = DFA::new_many(&[\"[0-9]+\", \"[a-z]+\", \"[A-Z]+\"])?;\n",
        "    /// assert_eq!(dfa.pattern_len(), 3);\n",
        "    /// # Ok::<(), Box<dyn std::error::Error>>(())\n",
        "    /// ```\n",
    ),
    source_span_sha256: "2ac68b5dc2bacb471037216f1f24c05b593142de2662cbc97d8b7ff669122aa6",
    assertion_inventory_sha256: "eb96e6199e8e9f78b3b233e418c889e8b462b51f80bee1fed1ae6f6e49645027",
    assertions: PATTERN_LEN_MANY_ASSERTIONS,
};

const IS_SPECIAL_STATE_SOURCE: SourceContractSpec = SourceContractSpec {
    source_path: AUTOMATON_SOURCE_PATH,
    source_sha256: AUTOMATON_SOURCE_SHA256,
    span_start_line: 416,
    span_end_line: 508,
    source_span: r#"    /// ```
    /// use regex_automata::{
    ///     dfa::{Automaton, dense},
    ///     HalfMatch, MatchError, Input,
    /// };
    ///
    /// fn find<A: Automaton>(
    ///     dfa: &A,
    ///     haystack: &[u8],
    /// ) -> Result<Option<HalfMatch>, MatchError> {
    ///     // The start state is determined by inspecting the position and the
    ///     // initial bytes of the haystack. Note that start states can never
    ///     // be match states (since DFAs in this crate delay matches by 1
    ///     // byte), so we don't need to check if the start state is a match.
    ///     let mut state = dfa.start_state_forward(&Input::new(haystack))?;
    ///     let mut last_match = None;
    ///     // Walk all the bytes in the haystack. We can quit early if we see
    ///     // a dead or a quit state. The former means the automaton will
    ///     // never transition to any other state. The latter means that the
    ///     // automaton entered a condition in which its search failed.
    ///     for (i, &b) in haystack.iter().enumerate() {
    ///         state = dfa.next_state(state, b);
    ///         if dfa.is_special_state(state) {
    ///             if dfa.is_match_state(state) {
    ///                 last_match = Some(HalfMatch::new(
    ///                     dfa.match_pattern(state, 0),
    ///                     i,
    ///                 ));
    ///             } else if dfa.is_dead_state(state) {
    ///                 return Ok(last_match);
    ///             } else if dfa.is_quit_state(state) {
    ///                 // It is possible to enter into a quit state after
    ///                 // observing a match has occurred. In that case, we
    ///                 // should return the match instead of an error.
    ///                 if last_match.is_some() {
    ///                     return Ok(last_match);
    ///                 }
    ///                 return Err(MatchError::quit(b, i));
    ///             }
    ///             // Implementors may also want to check for start or accel
    ///             // states and handle them differently for performance
    ///             // reasons. But it is not necessary for correctness.
    ///         }
    ///     }
    ///     // Matches are always delayed by 1 byte, so we must explicitly walk
    ///     // the special "EOI" transition at the end of the search.
    ///     state = dfa.next_eoi_state(state);
    ///     if dfa.is_match_state(state) {
    ///         last_match = Some(HalfMatch::new(
    ///             dfa.match_pattern(state, 0),
    ///             haystack.len(),
    ///         ));
    ///     }
    ///     Ok(last_match)
    /// }
    ///
    /// // We use a greedy '+' operator to show how the search doesn't just
    /// // stop once a match is detected. It continues extending the match.
    /// // Using '[a-z]+?' would also work as expected and stop the search
    /// // early. Greediness is built into the automaton.
    /// let dfa = dense::DFA::new(r"[a-z]+")?;
    /// let haystack = "123 foobar 4567".as_bytes();
    /// let mat = find(&dfa, haystack)?.unwrap();
    /// assert_eq!(mat.pattern().as_usize(), 0);
    /// assert_eq!(mat.offset(), 10);
    ///
    /// // Here's another example that tests our handling of the special EOI
    /// // transition. This will fail to find a match if we don't call
    /// // 'next_eoi_state' at the end of the search since the match isn't
    /// // found until the final byte in the haystack.
    /// let dfa = dense::DFA::new(r"[0-9]{4}")?;
    /// let haystack = "123 foobar 4567".as_bytes();
    /// let mat = find(&dfa, haystack)?.unwrap();
    /// assert_eq!(mat.pattern().as_usize(), 0);
    /// assert_eq!(mat.offset(), 15);
    ///
    /// // And note that our search implementation above automatically works
    /// // with multi-DFAs. Namely, `dfa.match_pattern(match_state, 0)` selects
    /// // the appropriate pattern ID for us.
    /// let dfa = dense::DFA::new_many(&[r"[a-z]+", r"[0-9]+"])?;
    /// let haystack = "123 foobar 4567".as_bytes();
    /// let mat = find(&dfa, haystack)?.unwrap();
    /// assert_eq!(mat.pattern().as_usize(), 1);
    /// assert_eq!(mat.offset(), 3);
    /// let mat = find(&dfa, &haystack[3..])?.unwrap();
    /// assert_eq!(mat.pattern().as_usize(), 0);
    /// assert_eq!(mat.offset(), 7);
    /// let mat = find(&dfa, &haystack[10..])?.unwrap();
    /// assert_eq!(mat.pattern().as_usize(), 1);
    /// assert_eq!(mat.offset(), 5);
    ///
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
"#,
    source_span_sha256: "8791249d073357db5a2d099416ef15264be37289e39f02ea02e255e63903402e",
    assertion_inventory_sha256: "d5dbea2c7bb486f8ada05df07d57ab0019b245467152138db78440d196de5001",
    assertions: IS_SPECIAL_STATE_ASSERTIONS,
};

const IS_START_STATE_SOURCE: SourceContractSpec = SourceContractSpec {
    source_path: AUTOMATON_SOURCE_PATH,
    source_sha256: AUTOMATON_SOURCE_SHA256,
    span_start_line: 648,
    span_end_line: 741,
    source_span: r#"    /// ```
    /// use regex_automata::{
    ///     dfa::{Automaton, dense},
    ///     HalfMatch, MatchError, Input,
    /// };
    ///
    /// fn find_byte(slice: &[u8], at: usize, byte: u8) -> Option<usize> {
    ///     // Would be faster to use the memchr crate, but this is still
    ///     // faster than running through the DFA.
    ///     slice[at..].iter().position(|&b| b == byte).map(|i| at + i)
    /// }
    ///
    /// fn find<A: Automaton>(
    ///     dfa: &A,
    ///     haystack: &[u8],
    ///     prefix_byte: Option<u8>,
    /// ) -> Result<Option<HalfMatch>, MatchError> {
    ///     // See the Automaton::is_special_state example for similar code
    ///     // with more comments.
    ///
    ///     let mut state = dfa.start_state_forward(&Input::new(haystack))?;
    ///     let mut last_match = None;
    ///     let mut pos = 0;
    ///     while pos < haystack.len() {
    ///         let b = haystack[pos];
    ///         state = dfa.next_state(state, b);
    ///         pos += 1;
    ///         if dfa.is_special_state(state) {
    ///             if dfa.is_match_state(state) {
    ///                 last_match = Some(HalfMatch::new(
    ///                     dfa.match_pattern(state, 0),
    ///                     pos - 1,
    ///                 ));
    ///             } else if dfa.is_dead_state(state) {
    ///                 return Ok(last_match);
    ///             } else if dfa.is_quit_state(state) {
    ///                 // It is possible to enter into a quit state after
    ///                 // observing a match has occurred. In that case, we
    ///                 // should return the match instead of an error.
    ///                 if last_match.is_some() {
    ///                     return Ok(last_match);
    ///                 }
    ///                 return Err(MatchError::quit(b, pos - 1));
    ///             } else if dfa.is_start_state(state) {
    ///                 // If we're in a start state and know all matches begin
    ///                 // with a particular byte, then we can quickly skip to
    ///                 // candidate matches without running the DFA through
    ///                 // every byte inbetween.
    ///                 if let Some(prefix_byte) = prefix_byte {
    ///                     pos = match find_byte(haystack, pos, prefix_byte) {
    ///                         Some(pos) => pos,
    ///                         None => break,
    ///                     };
    ///                 }
    ///             }
    ///         }
    ///     }
    ///     // Matches are always delayed by 1 byte, so we must explicitly walk
    ///     // the special "EOI" transition at the end of the search.
    ///     state = dfa.next_eoi_state(state);
    ///     if dfa.is_match_state(state) {
    ///         last_match = Some(HalfMatch::new(
    ///             dfa.match_pattern(state, 0),
    ///             haystack.len(),
    ///         ));
    ///     }
    ///     Ok(last_match)
    /// }
    ///
    /// // In this example, it's obvious that all occurrences of our pattern
    /// // begin with 'Z', so we pass in 'Z'. Note also that we need to
    /// // enable start state specialization, or else it won't be possible to
    /// // detect start states during a search. ('is_start_state' would always
    /// // return false.)
    /// let dfa = dense::DFA::builder()
    ///     .configure(dense::DFA::config().specialize_start_states(true))
    ///     .build(r"Z[a-z]+")?;
    /// let haystack = "123 foobar Zbaz quux".as_bytes();
    /// let mat = find(&dfa, haystack, Some(b'Z'))?.unwrap();
    /// assert_eq!(mat.pattern().as_usize(), 0);
    /// assert_eq!(mat.offset(), 15);
    ///
    /// // But note that we don't need to pass in a prefix byte. If we don't,
    /// // then the search routine does no acceleration.
    /// let mat = find(&dfa, haystack, None)?.unwrap();
    /// assert_eq!(mat.pattern().as_usize(), 0);
    /// assert_eq!(mat.offset(), 15);
    ///
    /// // However, if we pass an incorrect byte, then the prefix search will
    /// // result in incorrect results.
    /// assert_eq!(find(&dfa, haystack, Some(b'X'))?, None);
    ///
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
"#,
    source_span_sha256: "43143172a82349b0c205eee7d61ef4f127012919b62e0c33c6c586beb5e14aa4",
    assertion_inventory_sha256: "fed3bec39108bfae17f9f5170c169cf0de3c66670352ed725dc1ffd3fa504ca0",
    assertions: IS_START_STATE_ASSERTIONS,
};

const MATCH_LEN_SOURCE: SourceContractSpec = SourceContractSpec {
    source_path: AUTOMATON_SOURCE_PATH,
    source_sha256: AUTOMATON_SOURCE_SHA256,
    span_start_line: 869,
    span_end_line: 898,
    source_span: r#"    /// ```
    /// # if cfg!(miri) { return Ok(()); } // miri takes too long
    /// use regex_automata::{dfa::{Automaton, dense}, Input, MatchKind};
    ///
    /// let dfa = dense::Builder::new()
    ///     .configure(dense::Config::new().match_kind(MatchKind::All))
    ///     .build_many(&[
    ///         r"[[:word:]]+", r"[a-z]+", r"[A-Z]+", r"[[:^space:]]+",
    ///     ])?;
    /// let haystack = "@bar".as_bytes();
    ///
    /// // The start state is determined by inspecting the position and the
    /// // initial bytes of the haystack.
    /// let mut state = dfa.start_state_forward(&Input::new(haystack))?;
    /// // Walk all the bytes in the haystack.
    /// for &b in haystack {
    ///     state = dfa.next_state(state, b);
    /// }
    /// state = dfa.next_eoi_state(state);
    ///
    /// assert!(dfa.is_match_state(state));
    /// assert_eq!(dfa.match_len(state), 3);
    /// // The following calls are guaranteed to not panic since `match_len`
    /// // returned `3` above.
    /// assert_eq!(dfa.match_pattern(state, 0).as_usize(), 3);
    /// assert_eq!(dfa.match_pattern(state, 1).as_usize(), 0);
    /// assert_eq!(dfa.match_pattern(state, 2).as_usize(), 1);
    ///
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
"#,
    source_span_sha256: "f8d8b88c939146ffab3a6180a2d3bfa668463730dba85af983d797d26db79f10",
    assertion_inventory_sha256: "ab04b7447cb12c209123dbb45466abd842e72e3549b0304c5dd23dfc8bd3571d",
    assertions: MATCH_LEN_ASSERTIONS,
};

const PATTERN_LEN_ALWAYS_SOURCE: SourceContractSpec = SourceContractSpec {
    source_path: AUTOMATON_SOURCE_PATH,
    source_sha256: AUTOMATON_SOURCE_SHA256,
    span_start_line: 810,
    span_end_line: 816,
    source_span: r"    /// ```
    /// use regex_automata::dfa::{Automaton, dense::DFA};
    ///
    /// let dfa: DFA<Vec<u32>> = DFA::always_match()?;
    /// assert_eq!(dfa.pattern_len(), 1);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
",
    source_span_sha256: "e95e40b73e1b4df140cc92eb4815737f2e466a2d3aff609950121036e71898e5",
    assertion_inventory_sha256: "f96d81e05b74c6921a2d9aa789fde5cbb1680230d59ab145f5b8616e89c9b642",
    assertions: PATTERN_LEN_ALWAYS_ASSERTIONS,
};

const TRY_SEARCH_OVERLAPPING_FWD_SOURCE: SourceContractSpec = SourceContractSpec {
    source_path: AUTOMATON_SOURCE_PATH,
    source_sha256: AUTOMATON_SOURCE_SHA256,
    span_start_line: 1553,
    span_end_line: 1580,
    source_span: r#"    /// ```
    /// # if cfg!(miri) { return Ok(()); } // miri takes too long
    /// use regex_automata::{
    ///     dfa::{Automaton, OverlappingState, dense},
    ///     HalfMatch, Input, MatchKind,
    /// };
    ///
    /// let dfa = dense::Builder::new()
    ///     .configure(dense::Config::new().match_kind(MatchKind::All))
    ///     .build_many(&[r"[[:word:]]+$", r"[[:^space:]]+$"])?;
    /// let haystack = "@foo";
    /// let mut state = OverlappingState::start();
    ///
    /// let expected = Some(HalfMatch::must(1, 4));
    /// dfa.try_search_overlapping_fwd(&Input::new(haystack), &mut state)?;
    /// assert_eq!(expected, state.get_match());
    ///
    /// // The first pattern also matches at the same position, so re-running
    /// // the search will yield another match. Notice also that the first
    /// // pattern is returned after the second. This is because the second
    /// // pattern begins its match before the first, is therefore an earlier
    /// // match and is thus reported first.
    /// let expected = Some(HalfMatch::must(0, 4));
    /// dfa.try_search_overlapping_fwd(&Input::new(haystack), &mut state)?;
    /// assert_eq!(expected, state.get_match());
    ///
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
"#,
    source_span_sha256: "0473de999fa57fa4182ead88a4124200bfc6d9b3702ab3fc0eb6c07db79ca7a3",
    assertion_inventory_sha256: "da04daa73e64d56ecb6d5750ef65624a215c0ce74fd7f8bd83ce25bdda51af56",
    assertions: TRY_SEARCH_OVERLAPPING_FWD_ASSERTIONS,
};

const TRY_SEARCH_FWD_SOURCE: SourceContractSpec = SourceContractSpec {
    source_path: AUTOMATON_SOURCE_PATH,
    source_sha256: AUTOMATON_SOURCE_SHA256,
    span_start_line: 1209,
    span_end_line: 1224,
    source_span: concat!(
        "    /// ```\n",
        "    /// use regex_automata::{dfa::{Automaton, dense}, HalfMatch, Input};\n",
        "    ///\n",
        "    /// let dfa = dense::DFA::new(\"foo[0-9]+\")?;\n",
        "    /// let expected = Some(HalfMatch::must(0, 8));\n",
        "    /// assert_eq!(expected, dfa.try_search_fwd(&Input::new(b\"foo12345\"))?);\n",
        "    ///\n",
        "    /// // Even though a match is found after reading the first byte (`a`),\n",
        "    /// // the leftmost first match semantics demand that we find the earliest\n",
        "    /// // match that prefers earlier parts of the pattern over latter parts.\n",
        "    /// let dfa = dense::DFA::new(\"abc|a\")?;\n",
        "    /// let expected = Some(HalfMatch::must(0, 3));\n",
        "    /// assert_eq!(expected, dfa.try_search_fwd(&Input::new(b\"abc\"))?);\n",
        "    ///\n",
        "    /// # Ok::<(), Box<dyn std::error::Error>>(())\n",
        "    /// ```\n",
    ),
    source_span_sha256: "c431055ba7bc0ea80c3ce8629af0257eef415609ade8341825c0490a6b06dc7e",
    assertion_inventory_sha256: "91005984a3b82958c524a4308e97308e1e0906b2b2cf303768d296b5f9d2f038",
    assertions: TRY_SEARCH_FWD_ASSERTIONS,
};

const TRY_SEARCH_FWD_BOUNDS_SOURCE: SourceContractSpec = SourceContractSpec {
    source_path: AUTOMATON_SOURCE_PATH,
    source_sha256: AUTOMATON_SOURCE_SHA256,
    span_start_line: 1267,
    span_end_line: 1295,
    source_span: r#"    /// ```
    /// use regex_automata::{dfa::{Automaton, dense}, HalfMatch, Input};
    ///
    /// // N.B. We disable Unicode here so that we use a simple ASCII word
    /// // boundary. Alternatively, we could enable heuristic support for
    /// // Unicode word boundaries.
    /// let dfa = dense::DFA::new(r"(?-u)\b[0-9]{3}\b")?;
    /// let haystack = "foo123bar".as_bytes();
    ///
    /// // Since we sub-slice the haystack, the search doesn't know about the
    /// // larger context and assumes that `123` is surrounded by word
    /// // boundaries. And of course, the match position is reported relative
    /// // to the sub-slice as well, which means we get `3` instead of `6`.
    /// let input = Input::new(&haystack[3..6]);
    /// let expected = Some(HalfMatch::must(0, 3));
    /// let got = dfa.try_search_fwd(&input)?;
    /// assert_eq!(expected, got);
    ///
    /// // But if we provide the bounds of the search within the context of the
    /// // entire haystack, then the search can take the surrounding context
    /// // into account. (And if we did find a match, it would be reported
    /// // as a valid offset into `haystack` instead of its sub-slice.)
    /// let input = Input::new(haystack).range(3..6);
    /// let expected = None;
    /// let got = dfa.try_search_fwd(&input)?;
    /// assert_eq!(expected, got);
    ///
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
"#,
    source_span_sha256: "7a107341165090031ae322427e59560ed3a9f895aba49896557a7610a50f0530",
    assertion_inventory_sha256: "2bbe88fc6fc55dc9ee186d0b84b09019c1fd0515dd99802ae250ec21726a5d08",
    assertions: TRY_SEARCH_FWD_BOUNDS_ASSERTIONS,
};

// Each registration is one actual compiled membership. In particular, there
// is intentionally no all-features registration: this binary is built with
// regex-automata's package defaults, so relabelling this execution as the VCS
// all-features mode is structurally rejected.
const PATTERN_LEN_ADAPTER: RegisteredAdapter = RegisteredAdapter {
    mode_id: COMPILED_MODE_ID,
    harness: RegexAutomataHarnessKind::Doctest,
    case_id: PATTERN_LEN_CASE,
    source: PATTERN_LEN_SOURCE,
    run: run_pattern_len_never_match,
};
const PATTERN_LEN_MANY_ADAPTER: RegisteredAdapter = RegisteredAdapter {
    mode_id: COMPILED_MODE_ID,
    harness: RegexAutomataHarnessKind::Doctest,
    case_id: PATTERN_LEN_MANY_CASE,
    source: PATTERN_LEN_MANY_SOURCE,
    run: run_pattern_len_many,
};
const IS_SPECIAL_STATE_ADAPTER: RegisteredAdapter = RegisteredAdapter {
    mode_id: COMPILED_MODE_ID,
    harness: RegexAutomataHarnessKind::Doctest,
    case_id: IS_SPECIAL_STATE_CASE,
    source: IS_SPECIAL_STATE_SOURCE,
    run: run_is_special_state,
};
const IS_START_STATE_ADAPTER: RegisteredAdapter = RegisteredAdapter {
    mode_id: COMPILED_MODE_ID,
    harness: RegexAutomataHarnessKind::Doctest,
    case_id: IS_START_STATE_CASE,
    source: IS_START_STATE_SOURCE,
    run: run_is_start_state,
};
const MATCH_LEN_ADAPTER: RegisteredAdapter = RegisteredAdapter {
    mode_id: COMPILED_MODE_ID,
    harness: RegexAutomataHarnessKind::Doctest,
    case_id: MATCH_LEN_CASE,
    source: MATCH_LEN_SOURCE,
    run: run_match_len,
};
const PATTERN_LEN_ALWAYS_ADAPTER: RegisteredAdapter = RegisteredAdapter {
    mode_id: COMPILED_MODE_ID,
    harness: RegexAutomataHarnessKind::Doctest,
    case_id: PATTERN_LEN_ALWAYS_CASE,
    source: PATTERN_LEN_ALWAYS_SOURCE,
    run: run_pattern_len_always,
};
const TRY_SEARCH_OVERLAPPING_FWD_ADAPTER: RegisteredAdapter = RegisteredAdapter {
    mode_id: COMPILED_MODE_ID,
    harness: RegexAutomataHarnessKind::Doctest,
    case_id: TRY_SEARCH_OVERLAPPING_FWD_CASE,
    source: TRY_SEARCH_OVERLAPPING_FWD_SOURCE,
    run: run_try_search_overlapping_fwd,
};
const TRY_SEARCH_FWD_ADAPTER: RegisteredAdapter = RegisteredAdapter {
    mode_id: COMPILED_MODE_ID,
    harness: RegexAutomataHarnessKind::Doctest,
    case_id: TRY_SEARCH_FWD_CASE,
    source: TRY_SEARCH_FWD_SOURCE,
    run: run_try_search_fwd,
};
const TRY_SEARCH_FWD_BOUNDS_ADAPTER: RegisteredAdapter = RegisteredAdapter {
    mode_id: COMPILED_MODE_ID,
    harness: RegexAutomataHarnessKind::Doctest,
    case_id: TRY_SEARCH_FWD_BOUNDS_CASE,
    source: TRY_SEARCH_FWD_BOUNDS_SOURCE,
    run: run_try_search_fwd_bounds,
};
const LOOK_END_LINE_ADAPTER: RegisteredAdapter = RegisteredAdapter {
    mode_id: COMPILED_UNIT_MODE_ID,
    harness: RegexAutomataHarnessKind::Unit,
    case_id: LOOK_END_LINE_CASE,
    source: LOOK_END_LINE_SOURCE,
    run: run_look_end_line,
};
const LOOK_END_TEXT_ADAPTER: RegisteredAdapter = RegisteredAdapter {
    mode_id: COMPILED_UNIT_MODE_ID,
    harness: RegexAutomataHarnessKind::Unit,
    case_id: LOOK_END_TEXT_CASE,
    source: LOOK_END_TEXT_SOURCE,
    run: run_look_end_text,
};
const LOOK_START_LINE_ADAPTER: RegisteredAdapter = RegisteredAdapter {
    mode_id: COMPILED_UNIT_MODE_ID,
    harness: RegexAutomataHarnessKind::Unit,
    case_id: LOOK_START_LINE_CASE,
    source: LOOK_START_LINE_SOURCE,
    run: run_look_start_line,
};
const LOOK_START_TEXT_ADAPTER: RegisteredAdapter = RegisteredAdapter {
    mode_id: COMPILED_UNIT_MODE_ID,
    harness: RegexAutomataHarnessKind::Unit,
    case_id: LOOK_START_TEXT_CASE,
    source: LOOK_START_TEXT_SOURCE,
    run: run_look_start_text,
};

// This predecessor registry is independent of every report being verified.
// Its separately sealed manifest prevents a prior report from authorizing a
// smaller replay set by downgrading one of its historical passes.
const PREDECESSOR_REGISTERED_ADAPTERS: &[RegisteredAdapter] = &[
    PATTERN_LEN_ADAPTER,
    PATTERN_LEN_MANY_ADAPTER,
    IS_SPECIAL_STATE_ADAPTER,
    IS_START_STATE_ADAPTER,
    MATCH_LEN_ADAPTER,
    PATTERN_LEN_ALWAYS_ADAPTER,
    TRY_SEARCH_OVERLAPPING_FWD_ADAPTER,
    TRY_SEARCH_FWD_ADAPTER,
    TRY_SEARCH_FWD_BOUNDS_ADAPTER,
];
const PREDECESSOR_REGISTRY_MANIFEST_SHA256: &str =
    "9fe47d0442a4c9339c404ca0e5ef7d162f506e5c0f2caa446a4629e9d5b4d8fe";
const REGISTERED_ADAPTERS: &[RegisteredAdapter] = &[
    PATTERN_LEN_ADAPTER,
    PATTERN_LEN_MANY_ADAPTER,
    IS_SPECIAL_STATE_ADAPTER,
    IS_START_STATE_ADAPTER,
    MATCH_LEN_ADAPTER,
    PATTERN_LEN_ALWAYS_ADAPTER,
    TRY_SEARCH_OVERLAPPING_FWD_ADAPTER,
    TRY_SEARCH_FWD_ADAPTER,
    TRY_SEARCH_FWD_BOUNDS_ADAPTER,
    LOOK_END_LINE_ADAPTER,
    LOOK_END_TEXT_ADAPTER,
    LOOK_START_LINE_ADAPTER,
    LOOK_START_TEXT_ADAPTER,
];

fn run_pattern_len_never_match(
    context: &AdapterContext<'_>,
) -> Result<Vec<RegexAutomataAssertionExecution>, String> {
    require_compiled_mode(context)?;
    let upstream: dense::DFA<Vec<u32>> =
        dense::DFA::never_match().map_err(|error| format!("upstream-build:{error}"))?;
    let fre = PortableRegexSet::new(std::iter::empty::<&str>())
        .map_err(|error| format!("fre-build:{error}"))?;
    Ok(vec![RegexAutomataAssertionExecution {
        assertion_id: PATTERN_LEN_ASSERTIONS[0].assertion_id.to_owned(),
        upstream_observation: format!("usize:{}", upstream.pattern_len()),
        fre_observation: format!("usize:{}", fre.patterns().len()),
    }])
}

fn run_pattern_len_many(
    context: &AdapterContext<'_>,
) -> Result<Vec<RegexAutomataAssertionExecution>, String> {
    require_compiled_mode(context)?;
    let patterns = ["[0-9]+", "[a-z]+", "[A-Z]+"];
    let upstream =
        dense::DFA::new_many(&patterns).map_err(|error| format!("upstream-build:{error}"))?;
    let fre = PortableRegexSet::new(patterns).map_err(|error| format!("fre-build:{error}"))?;
    Ok(vec![RegexAutomataAssertionExecution {
        assertion_id: PATTERN_LEN_MANY_ASSERTIONS[0].assertion_id.to_owned(),
        upstream_observation: format!("usize:{}", upstream.pattern_len()),
        fre_observation: format!("usize:{}", fre.patterns().len()),
    }])
}

fn assertion_execution(
    assertion: &AssertionSpec,
    upstream_observation: String,
    fre_observation: String,
) -> RegexAutomataAssertionExecution {
    RegexAutomataAssertionExecution {
        assertion_id: assertion.assertion_id.to_owned(),
        upstream_observation,
        fre_observation,
    }
}

fn usize_execution(
    assertion: &AssertionSpec,
    upstream: usize,
    fre: usize,
) -> RegexAutomataAssertionExecution {
    assertion_execution(
        assertion,
        format!("usize:{upstream}"),
        format!("usize:{fre}"),
    )
}

fn upstream_special_find<A: Automaton>(
    dfa: &A,
    haystack: &[u8],
) -> Result<Option<HalfMatch>, String> {
    let mut state = dfa
        .start_state_forward(&Input::new(haystack))
        .map_err(|error| format!("upstream-special-start:{error}"))?;
    let mut last_match = None;
    for (index, &byte) in haystack.iter().enumerate() {
        state = dfa.next_state(state, byte);
        if dfa.is_special_state(state) {
            if dfa.is_match_state(state) {
                last_match = Some(HalfMatch::new(dfa.match_pattern(state, 0), index));
            } else if dfa.is_dead_state(state) {
                return Ok(last_match);
            } else if dfa.is_quit_state(state) {
                if last_match.is_some() {
                    return Ok(last_match);
                }
                return Err(format!("upstream-special-quit:{byte}:{index}"));
            }
        }
    }
    state = dfa.next_eoi_state(state);
    if dfa.is_match_state(state) {
        last_match = Some(HalfMatch::new(dfa.match_pattern(state, 0), haystack.len()));
    }
    Ok(last_match)
}

fn fre_earliest_match(
    patterns: &[&str],
    haystack: &[u8],
) -> Result<Option<(usize, usize, usize)>, String> {
    let mut best: Option<(usize, usize, usize)> = None;
    for (pattern_id, pattern) in patterns.iter().enumerate() {
        let matched = PortableRegex::new(*pattern)
            .map_err(|error| format!("fre-build-pattern-{pattern_id}:{error}"))?
            .find(haystack, SearchLimits::unlimited())
            .map_err(|error| format!("fre-search-pattern-{pattern_id}:{error}"))?
            .0;
        let Some(matched) = matched else {
            continue;
        };
        let candidate = (pattern_id, matched.start(), matched.end());
        if match best {
            None => true,
            Some(current) => (candidate.1, candidate.0) < (current.1, current.0),
        } {
            best = Some(candidate);
        }
    }
    Ok(best)
}

fn required_upstream_match(
    matched: Option<HalfMatch>,
    label: &str,
) -> Result<(usize, usize), String> {
    matched
        .map(|matched| (matched.pattern().as_usize(), matched.offset()))
        .ok_or_else(|| format!("upstream-{label}-missing-match"))
}

fn required_fre_match(
    matched: Option<(usize, usize, usize)>,
    label: &str,
) -> Result<(usize, usize), String> {
    matched
        .map(|(pattern, _, end)| (pattern, end))
        .ok_or_else(|| format!("fre-{label}-missing-match"))
}

fn run_is_special_state(
    context: &AdapterContext<'_>,
) -> Result<Vec<RegexAutomataAssertionExecution>, String> {
    require_compiled_mode(context)?;
    let haystack = b"123 foobar 4567";

    let upstream_alpha = required_upstream_match(
        upstream_special_find(
            &dense::DFA::new(r"[a-z]+").map_err(|error| format!("upstream-alpha:{error}"))?,
            haystack,
        )?,
        "special-alpha",
    )?;
    let fre_alpha =
        required_fre_match(fre_earliest_match(&[r"[a-z]+"], haystack)?, "special-alpha")?;

    let upstream_eoi = required_upstream_match(
        upstream_special_find(
            &dense::DFA::new(r"[0-9]{4}").map_err(|error| format!("upstream-eoi:{error}"))?,
            haystack,
        )?,
        "special-eoi",
    )?;
    let fre_eoi = required_fre_match(fre_earliest_match(&[r"[0-9]{4}"], haystack)?, "special-eoi")?;

    let patterns = [r"[a-z]+", r"[0-9]+"];
    let upstream_many_dfa =
        dense::DFA::new_many(&patterns).map_err(|error| format!("upstream-many:{error}"))?;
    let upstream_many_head = required_upstream_match(
        upstream_special_find(&upstream_many_dfa, haystack)?,
        "special-many-head",
    )?;
    let upstream_many_middle = required_upstream_match(
        upstream_special_find(&upstream_many_dfa, &haystack[3..])?,
        "special-many-middle",
    )?;
    let upstream_many_tail = required_upstream_match(
        upstream_special_find(&upstream_many_dfa, &haystack[10..])?,
        "special-many-tail",
    )?;
    let fre_many_head = required_fre_match(
        fre_earliest_match(&patterns, haystack)?,
        "special-many-head",
    )?;
    let fre_many_middle = required_fre_match(
        fre_earliest_match(&patterns, &haystack[3..])?,
        "special-many-middle",
    )?;
    let fre_many_tail = required_fre_match(
        fre_earliest_match(&patterns, &haystack[10..])?,
        "special-many-tail",
    )?;

    let pairs = [
        (upstream_alpha, fre_alpha),
        (upstream_eoi, fre_eoi),
        (upstream_many_head, fre_many_head),
        (upstream_many_middle, fre_many_middle),
        (upstream_many_tail, fre_many_tail),
    ];
    let mut executions = Vec::with_capacity(IS_SPECIAL_STATE_ASSERTIONS.len());
    for (index, (upstream, fre)) in pairs.into_iter().enumerate() {
        let pattern_index = index
            .checked_mul(2)
            .ok_or_else(|| "special-state-assertion-index-overflow".to_owned())?;
        let offset_index = pattern_index
            .checked_add(1)
            .ok_or_else(|| "special-state-assertion-index-overflow".to_owned())?;
        let pattern_assertion = IS_SPECIAL_STATE_ASSERTIONS
            .get(pattern_index)
            .ok_or_else(|| "special-state-pattern-assertion-missing".to_owned())?;
        let offset_assertion = IS_SPECIAL_STATE_ASSERTIONS
            .get(offset_index)
            .ok_or_else(|| "special-state-offset-assertion-missing".to_owned())?;
        executions.push(usize_execution(pattern_assertion, upstream.0, fre.0));
        executions.push(usize_execution(offset_assertion, upstream.1, fre.1));
    }
    Ok(executions)
}

fn upstream_start_state_find<A: Automaton>(
    dfa: &A,
    haystack: &[u8],
    prefix_byte: Option<u8>,
) -> Result<Option<HalfMatch>, String> {
    let mut state = dfa
        .start_state_forward(&Input::new(haystack))
        .map_err(|error| format!("upstream-start-state-start:{error}"))?;
    let mut last_match = None;
    let mut position = 0;
    while position < haystack.len() {
        let byte = haystack[position];
        state = dfa.next_state(state, byte);
        let observed_position = position;
        position = position
            .checked_add(1)
            .ok_or_else(|| "upstream-start-state-position-overflow".to_owned())?;
        if dfa.is_special_state(state) {
            if dfa.is_match_state(state) {
                last_match = Some(HalfMatch::new(
                    dfa.match_pattern(state, 0),
                    observed_position,
                ));
            } else if dfa.is_dead_state(state) {
                return Ok(last_match);
            } else if dfa.is_quit_state(state) {
                if last_match.is_some() {
                    return Ok(last_match);
                }
                return Err(format!(
                    "upstream-start-state-quit:{byte}:{observed_position}",
                ));
            } else if dfa.is_start_state(state)
                && let Some(prefix_byte) = prefix_byte
            {
                let Some(relative) = haystack[position..]
                    .iter()
                    .position(|&candidate| candidate == prefix_byte)
                else {
                    break;
                };
                position = position
                    .checked_add(relative)
                    .ok_or_else(|| "upstream-start-state-skip-overflow".to_owned())?;
            }
        }
    }
    state = dfa.next_eoi_state(state);
    if dfa.is_match_state(state) {
        last_match = Some(HalfMatch::new(dfa.match_pattern(state, 0), haystack.len()));
    }
    Ok(last_match)
}

fn fre_prefix_find(
    pattern: &str,
    haystack: &[u8],
    prefix_byte: Option<u8>,
) -> Result<Option<(usize, usize, usize)>, String> {
    let start = match prefix_byte {
        None => 0,
        Some(prefix) => match haystack.iter().position(|&byte| byte == prefix) {
            Some(start) => start,
            None => return Ok(None),
        },
    };
    let matched = PortableRegex::new(pattern)
        .map_err(|error| format!("fre-prefix-build:{error}"))?
        .find_at(haystack, start, SearchLimits::unlimited())
        .map_err(|error| format!("fre-prefix-search:{error}"))?
        .0;
    Ok(matched.map(|matched| (0, matched.start(), matched.end())))
}

fn run_is_start_state(
    context: &AdapterContext<'_>,
) -> Result<Vec<RegexAutomataAssertionExecution>, String> {
    require_compiled_mode(context)?;
    let dfa = dense::DFA::builder()
        .configure(dense::DFA::config().specialize_start_states(true))
        .build(r"Z[a-z]+")
        .map_err(|error| format!("upstream-start-state-build:{error}"))?;
    let haystack = b"123 foobar Zbaz quux";

    let upstream_prefix = required_upstream_match(
        upstream_start_state_find(&dfa, haystack, Some(b'Z'))?,
        "start-prefix",
    )?;
    let fre_prefix = required_fre_match(
        fre_prefix_find(r"Z[a-z]+", haystack, Some(b'Z'))?,
        "start-prefix",
    )?;
    let upstream_none = required_upstream_match(
        upstream_start_state_find(&dfa, haystack, None)?,
        "start-no-prefix",
    )?;
    let fre_none = required_fre_match(
        fre_prefix_find(r"Z[a-z]+", haystack, None)?,
        "start-no-prefix",
    )?;
    let upstream_wrong = upstream_start_state_find(&dfa, haystack, Some(b'X'))?;
    let fre_wrong = fre_prefix_find(r"Z[a-z]+", haystack, Some(b'X'))?;

    Ok(vec![
        usize_execution(
            &IS_START_STATE_ASSERTIONS[0],
            upstream_prefix.0,
            fre_prefix.0,
        ),
        usize_execution(
            &IS_START_STATE_ASSERTIONS[1],
            upstream_prefix.1,
            fre_prefix.1,
        ),
        usize_execution(&IS_START_STATE_ASSERTIONS[2], upstream_none.0, fre_none.0),
        usize_execution(&IS_START_STATE_ASSERTIONS[3], upstream_none.1, fre_none.1),
        assertion_execution(
            &IS_START_STATE_ASSERTIONS[4],
            upstream_half_match(upstream_wrong),
            tuple_half_match(fre_wrong),
        ),
    ])
}

fn run_match_len(
    context: &AdapterContext<'_>,
) -> Result<Vec<RegexAutomataAssertionExecution>, String> {
    require_compiled_mode(context)?;
    let patterns = [r"[[:word:]]+", r"[a-z]+", r"[A-Z]+", r"[[:^space:]]+"];
    let haystack = b"@bar";
    let upstream = dense::Builder::new()
        .configure(dense::Config::new().match_kind(MatchKind::All))
        .build_many(&patterns)
        .map_err(|error| format!("upstream-match-len-build:{error}"))?;
    let mut state = upstream
        .start_state_forward(&Input::new(haystack))
        .map_err(|error| format!("upstream-match-len-start:{error}"))?;
    for &byte in haystack {
        state = upstream.next_state(state, byte);
    }
    state = upstream.next_eoi_state(state);
    let upstream_is_match = upstream.is_match_state(state);
    let upstream_len = upstream.match_len(state);
    let upstream_patterns = (0..upstream_len)
        .map(|index| upstream.match_pattern(state, index).as_usize())
        .collect::<Vec<_>>();

    let mut fre_matches = Vec::new();
    for (pattern_id, pattern) in patterns.iter().enumerate() {
        let matched = PortableRegex::new(*pattern)
            .map_err(|error| format!("fre-match-len-build-{pattern_id}:{error}"))?
            .find(haystack, SearchLimits::unlimited())
            .map_err(|error| format!("fre-match-len-search-{pattern_id}:{error}"))?
            .0;
        if let Some(matched) = matched.filter(|matched| matched.end() == haystack.len()) {
            fre_matches.push((matched.start(), pattern_id));
        }
    }
    fre_matches.sort_unstable();
    let fre_patterns = fre_matches
        .iter()
        .map(|&(_, pattern_id)| pattern_id)
        .collect::<Vec<_>>();

    if upstream_patterns.len() != 3 || fre_patterns.len() != 3 {
        return Err("match-len-observed-cardinality-mismatch".to_owned());
    }
    Ok(vec![
        assertion_execution(
            &MATCH_LEN_ASSERTIONS[0],
            format!("bool:{upstream_is_match}"),
            format!("bool:{}", !fre_patterns.is_empty()),
        ),
        usize_execution(&MATCH_LEN_ASSERTIONS[1], upstream_len, fre_patterns.len()),
        usize_execution(
            &MATCH_LEN_ASSERTIONS[2],
            upstream_patterns[0],
            fre_patterns[0],
        ),
        usize_execution(
            &MATCH_LEN_ASSERTIONS[3],
            upstream_patterns[1],
            fre_patterns[1],
        ),
        usize_execution(
            &MATCH_LEN_ASSERTIONS[4],
            upstream_patterns[2],
            fre_patterns[2],
        ),
    ])
}

fn run_pattern_len_always(
    context: &AdapterContext<'_>,
) -> Result<Vec<RegexAutomataAssertionExecution>, String> {
    require_compiled_mode(context)?;
    let upstream: dense::DFA<Vec<u32>> =
        dense::DFA::always_match().map_err(|error| format!("upstream-always:{error}"))?;
    let fre = PortableRegexSet::new([""]).map_err(|error| format!("fre-always:{error}"))?;
    Ok(vec![usize_execution(
        &PATTERN_LEN_ALWAYS_ASSERTIONS[0],
        upstream.pattern_len(),
        fre.patterns().len(),
    )])
}

fn tuple_half_match(matched: Option<(usize, usize, usize)>) -> String {
    match matched {
        None => "half-match:none".to_owned(),
        Some((pattern, _, end)) => {
            format!("half-match:some:pattern={pattern}:offset={end}")
        }
    }
}

fn run_try_search_overlapping_fwd(
    context: &AdapterContext<'_>,
) -> Result<Vec<RegexAutomataAssertionExecution>, String> {
    require_compiled_mode(context)?;
    let patterns = [r"[[:word:]]+$", r"[[:^space:]]+$"];
    let haystack = b"@foo";
    let upstream = dense::Builder::new()
        .configure(dense::Config::new().match_kind(MatchKind::All))
        .build_many(&patterns)
        .map_err(|error| format!("upstream-overlap-build:{error}"))?;
    let mut state = OverlappingState::start();
    upstream
        .try_search_overlapping_fwd(&Input::new(haystack), &mut state)
        .map_err(|error| format!("upstream-overlap-first:{error}"))?;
    let upstream_first = state.get_match();
    upstream
        .try_search_overlapping_fwd(&Input::new(haystack), &mut state)
        .map_err(|error| format!("upstream-overlap-second:{error}"))?;
    let upstream_second = state.get_match();

    let mut fre_matches = Vec::new();
    for (pattern_id, pattern) in patterns.iter().enumerate() {
        let matched = PortableRegex::new(*pattern)
            .map_err(|error| format!("fre-overlap-build-{pattern_id}:{error}"))?
            .find(haystack, SearchLimits::unlimited())
            .map_err(|error| format!("fre-overlap-search-{pattern_id}:{error}"))?
            .0;
        if let Some(matched) = matched.filter(|matched| matched.end() == haystack.len()) {
            fre_matches.push((pattern_id, matched.start(), matched.end()));
        }
    }
    fre_matches.sort_unstable_by_key(|&(pattern, start, _)| (start, pattern));
    if fre_matches.len() != 2 {
        return Err("fre-overlap-cardinality-mismatch".to_owned());
    }
    Ok(vec![
        assertion_execution(
            &TRY_SEARCH_OVERLAPPING_FWD_ASSERTIONS[0],
            upstream_half_match(upstream_first),
            tuple_half_match(Some(fre_matches[0])),
        ),
        assertion_execution(
            &TRY_SEARCH_OVERLAPPING_FWD_ASSERTIONS[1],
            upstream_half_match(upstream_second),
            tuple_half_match(Some(fre_matches[1])),
        ),
    ])
}

fn run_try_search_fwd(
    context: &AdapterContext<'_>,
) -> Result<Vec<RegexAutomataAssertionExecution>, String> {
    require_compiled_mode(context)?;
    let upstream_first = dense::DFA::new("foo[0-9]+")
        .map_err(|error| format!("upstream-build-first:{error}"))?
        .try_search_fwd(&Input::new(b"foo12345"))
        .map_err(|error| format!("upstream-search-first:{error}"))?;
    let fre_first = PortableRegex::new("foo[0-9]+")
        .map_err(|error| format!("fre-build-first:{error}"))?
        .find(b"foo12345", SearchLimits::unlimited())
        .map_err(|error| format!("fre-search-first:{error}"))?
        .0;

    let upstream_second = dense::DFA::new("abc|a")
        .map_err(|error| format!("upstream-build-second:{error}"))?
        .try_search_fwd(&Input::new(b"abc"))
        .map_err(|error| format!("upstream-search-second:{error}"))?;
    let fre_second = PortableRegex::new("abc|a")
        .map_err(|error| format!("fre-build-second:{error}"))?
        .find(b"abc", SearchLimits::unlimited())
        .map_err(|error| format!("fre-search-second:{error}"))?
        .0;

    Ok(vec![
        RegexAutomataAssertionExecution {
            assertion_id: TRY_SEARCH_FWD_ASSERTIONS[0].assertion_id.to_owned(),
            upstream_observation: upstream_half_match(upstream_first),
            fre_observation: fre_half_match(fre_first),
        },
        RegexAutomataAssertionExecution {
            assertion_id: TRY_SEARCH_FWD_ASSERTIONS[1].assertion_id.to_owned(),
            upstream_observation: upstream_half_match(upstream_second),
            fre_observation: fre_half_match(fre_second),
        },
    ])
}

fn run_try_search_fwd_bounds(
    context: &AdapterContext<'_>,
) -> Result<Vec<RegexAutomataAssertionExecution>, String> {
    require_compiled_mode(context)?;
    let vector = TRY_SEARCH_FWD_BOUNDS_VECTOR;
    let haystack = vector.haystack.as_bytes();
    let upstream = dense::DFA::new(vector.pattern)
        .map_err(|error| format!("upstream-bounds-build:{error}"))?;
    let fre =
        PortableRegex::new(vector.pattern).map_err(|error| format!("fre-bounds-build:{error}"))?;

    let upstream_subslice = upstream
        .try_search_fwd(&Input::new(&haystack[vector.range_start..vector.range_end]))
        .map_err(|error| format!("upstream-bounds-subslice:{error}"))?;
    let fre_subslice = fre
        .find(
            &haystack[vector.range_start..vector.range_end],
            SearchLimits::unlimited(),
        )
        .map_err(|error| format!("fre-bounds-subslice:{error}"))?
        .0;

    let upstream_context = upstream
        .try_search_fwd(&Input::new(haystack).range(vector.range_start..vector.range_end))
        .map_err(|error| format!("upstream-bounds-context:{error}"))?;
    let fre_context = fre
        .find_window(
            haystack,
            SearchWindow::new(vector.range_start, vector.range_end),
            SearchLimits::unlimited(),
        )
        .map_err(|error| format!("fre-bounds-context:{error}"))?
        .0;

    Ok(vec![
        assertion_execution(
            &TRY_SEARCH_FWD_BOUNDS_ASSERTIONS[0],
            upstream_half_match(upstream_subslice),
            fre_half_match(fre_subslice),
        ),
        assertion_execution(
            &TRY_SEARCH_FWD_BOUNDS_ASSERTIONS[1],
            upstream_half_match(upstream_context),
            fre_half_match(fre_context),
        ),
    ])
}

fn run_look_end_line(
    context: &AdapterContext<'_>,
) -> Result<Vec<RegexAutomataAssertionExecution>, String> {
    run_look_case(context, LOOK_END_LINE)
}

fn run_look_end_text(
    context: &AdapterContext<'_>,
) -> Result<Vec<RegexAutomataAssertionExecution>, String> {
    run_look_case(context, LOOK_END_TEXT)
}

fn run_look_start_line(
    context: &AdapterContext<'_>,
) -> Result<Vec<RegexAutomataAssertionExecution>, String> {
    run_look_case(context, LOOK_START_LINE)
}

fn run_look_start_text(
    context: &AdapterContext<'_>,
) -> Result<Vec<RegexAutomataAssertionExecution>, String> {
    run_look_case(context, LOOK_START_TEXT)
}

fn run_look_case(
    context: &AdapterContext<'_>,
    case: LookCaseSpec,
) -> Result<Vec<RegexAutomataAssertionExecution>, String> {
    require_compiled_mode(context)?;
    run_look_case_observer(case)
}

fn run_look_case_observer(
    case: LookCaseSpec,
) -> Result<Vec<RegexAutomataAssertionExecution>, String> {
    run_look_case_observer_inner(case, true)
}

fn run_look_case_matrix_observer(
    case: LookCaseSpec,
) -> Result<Vec<RegexAutomataAssertionExecution>, String> {
    run_look_case_observer_inner(case, false)
}

fn run_look_case_observer_inner(
    case: LookCaseSpec,
    execute_local_upstream: bool,
) -> Result<Vec<RegexAutomataAssertionExecution>, String> {
    const MAX_WORK: u64 = 18;
    const MAX_SCRATCH_BYTES: usize = 8 * 1024 * 1024;

    validate_look_case_spec(case).map_err(|error| format!("look-case-contract:{error}"))?;
    let look = match case.kind {
        LookKind::StartLine => Look::StartLF,
        LookKind::EndLine => Look::EndLF,
        LookKind::StartText => Look::Start,
        LookKind::EndText => Look::End,
    };
    let fre = PortableBuilder::new(case.pattern)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .map_err(|error| format!("look-fre-build:{error}"))?;
    validate_look_fre_plan(&fre)?;

    let mut executions = Vec::with_capacity(case.vectors.len());
    for vector in case.vectors {
        let haystack = vector.haystack.as_bytes();
        // The package-default registry executes its in-process upstream
        // matcher. For another Cargo mode, the separately authenticated exact
        // unit-test artifact is the upstream authority, so this observer must
        // not project the conformance binary's default feature graph onto it.
        let upstream = if execute_local_upstream {
            LookMatcher::default().matches(look, haystack, vector.at)
        } else {
            vector.expected
        };
        let (matched, accounting) = fre
            .find_window(
                haystack,
                SearchWindow::new(vector.at, vector.at),
                SearchLimits {
                    max_work: MAX_WORK,
                    max_scratch_bytes: MAX_SCRATCH_BYTES,
                },
            )
            .map_err(|error| format!("look-fre-search:{error}"))?;
        let observed_span = matched.map(|matched| (matched.start(), matched.end()));
        let expected_span = vector.expected.then_some((vector.at, vector.at));
        let observed = observed_span.is_some();
        let (expected_work, expected_transition_work) =
            if vector.expected { (18, 4) } else { (17, 3) };
        let expected_initialized_bytes = if usize::BITS == 64 { 96 } else { 56 };
        let exact_accounting = matches!(
            accounting,
            SearchAccounting::K0(accounting)
                if accounting.work() == expected_work
                    && accounting.setup_work() == 14
                    && accounting.transition_work() == expected_transition_work
                    && accounting.scratch_bytes() <= MAX_SCRATCH_BYTES
                    && accounting.boundaries() == 1
                    && !accounting.setup().reused()
                    && accounting.setup().allocated_bytes()
                        == accounting.setup().retained_bytes()
                    && accounting.setup().retained_bytes() == accounting.scratch_bytes()
                    && accounting.setup().initialized_bytes() == expected_initialized_bytes
        );
        if !exact_accounting
            || upstream != vector.expected
            || observed_span != expected_span
            || observed != vector.expected
        {
            return Err("look-triple-agreement-mismatch".to_owned());
        }
        executions.push(RegexAutomataAssertionExecution {
            assertion_id: vector.assertion_id.to_owned(),
            upstream_observation: format!("bool:{upstream}"),
            fre_observation: format!("bool:{observed}"),
        });
    }
    Ok(executions)
}

fn validate_look_fre_plan(fre: &PortableRegex) -> Result<(), String> {
    let build = fre.build_report();
    if build.plan != PlanKind::K0
        || fre.runtime_implementation_id() != "k0"
        || build.states != 2
        || build.edges != 1
        || build
            .lowering
            .as_ref()
            .is_none_or(|lowering| lowering.states() != 2 || lowering.edges() != 1)
    {
        return Err("look-fre-non-k0-plan".to_owned());
    }
    Ok(())
}

fn registry_report_limitations(registry: &[RegisteredAdapter]) -> &'static [&'static str] {
    if registry
        .iter()
        .any(|adapter| adapter.mode_id == COMPILED_UNIT_MODE_ID)
    {
        MIXED_DEFAULT_REPORT_LIMITATIONS.as_slice()
    } else {
        DOCTEST_ONLY_REPORT_LIMITATIONS.as_slice()
    }
}

/// Execute every registered adapter and retain every unregistered obligation
/// as unsupported.
pub fn build_regex_automata_adapter_report(
    inventory: &RegexAutomataCorpusReport,
    candidate: CandidateIdentity,
) -> Result<RegexAutomataAdapterReport, InventoryError> {
    build_adapter_report_with_registry(inventory, candidate, REGISTERED_ADAPTERS)
}

fn build_adapter_report_with_registry(
    inventory: &RegexAutomataCorpusReport,
    candidate: CandidateIdentity,
    registry: &[RegisteredAdapter],
) -> Result<RegexAutomataAdapterReport, InventoryError> {
    inventory.validate()?;
    validate_candidate(&candidate)?;
    let inventory_identities = inventory
        .payload
        .obligations
        .iter()
        .map(obligation_membership_identity)
        .collect::<BTreeSet<_>>();
    let mut registered = BTreeMap::new();
    for adapter in registry {
        validate_registered_adapter(inventory, adapter)?;
        let key = (
            adapter.mode_id.to_owned(),
            adapter.harness,
            adapter.case_id.to_owned(),
        );
        if !inventory_identities.contains(&key) || registered.insert(key, adapter).is_some() {
            return Err(InventoryError::new(
                "regex-automata adapter registry has a foreign or duplicate membership",
            ));
        }
    }
    let mut outcomes = BTreeMap::new();
    let mut execution_receipts = Vec::new();
    for (identity, adapter) in registered {
        let mode = mode_execution(inventory, adapter.mode_id)?;
        let disposition = match catch_unwind(AssertUnwindSafe(|| execute_adapter(adapter, &mode))) {
            Ok(Ok(receipt)) => {
                let evidence_sha256 =
                    hash_json(&receipt, "encode regex-automata execution receipt")?;
                execution_receipts.push(receipt);
                RegexAutomataAdapterDisposition::Pass { evidence_sha256 }
            }
            Ok(Err(reason)) => RegexAutomataAdapterDisposition::Fault {
                stage: "adapter".to_owned(),
                reason_code: normalized_reason(&reason),
            },
            Err(_) => RegexAutomataAdapterDisposition::Fault {
                stage: "adapter".to_owned(),
                reason_code: "adapter-panic".to_owned(),
            },
        };
        outcomes.insert(identity, disposition);
    }
    let receipts = inventory
        .payload
        .obligations
        .iter()
        .map(|obligation| RegexAutomataAdapterReceipt {
            mode_id: obligation.mode_id.clone(),
            harness: obligation.harness,
            case_id: obligation.case_id.clone(),
            disposition: outcomes
                .get(&obligation_membership_identity(obligation))
                .cloned()
                .unwrap_or_else(|| RegexAutomataAdapterDisposition::Unsupported {
                    reason_code: INVENTORY_UNSUPPORTED_REASON.to_owned(),
                }),
        })
        .collect::<Vec<_>>();
    let counts = adapter_counts(&receipts);
    let payload = RegexAutomataAdapterReportPayload {
        inventory_payload_sha256: inventory.payload_sha256.clone(),
        obligation_inventory_sha256: inventory
            .payload
            .harness
            .obligation_inventory_sha256
            .clone(),
        candidate,
        counts,
        receipts,
        execution_receipts,
        look_mode_matrix: None,
        start_mode_matrix: None,
        start_mode_baseline: None,
        limitations: registry_report_limitations(registry)
            .iter()
            .map(|text| (*text).to_owned())
            .collect(),
    };
    let report = RegexAutomataAdapterReport {
        schema: if registry
            .iter()
            .any(|adapter| adapter.mode_id == COMPILED_UNIT_MODE_ID)
        {
            REGEX_AUTOMATA_ADAPTER_REPORT_SCHEMA
        } else {
            PREVIOUS_REGEX_AUTOMATA_ADAPTER_REPORT_SCHEMA
        }
        .to_owned(),
        payload_sha256: hash_json(&payload, "encode regex-automata adapter payload")?,
        payload,
    };
    report.validate_structure(inventory)?;
    Ok(report)
}

/// Deterministically select the first pending family and a bounded slice of
/// unique cases. All memberships for each selected case travel together.
pub fn schedule_regex_automata_gap(
    inventory: &RegexAutomataCorpusReport,
    baseline: &RegexAutomataAdapterReport,
    attempt_id: &str,
    slot: usize,
) -> Result<RegexAutomataGapAssignment, InventoryError> {
    inventory.validate()?;
    baseline.validate(inventory)?;
    if !token(attempt_id) || slot > 255 {
        return Err(InventoryError::new(
            "invalid regex-automata assignment identity",
        ));
    }
    let clusters = pending_clusters(baseline)?;
    let (family, mut targets) = clusters
        .into_iter()
        .next()
        .ok_or_else(|| InventoryError::new("regex-automata package suite is complete"))?;
    targets.truncate(ASSIGNMENT_TARGET_LIMIT);
    let targets_sha256 = hash_json(&targets, "encode regex-automata gap targets")?;
    let assignment = RegexAutomataGapAssignment {
        schema: REGEX_AUTOMATA_GAP_ASSIGNMENT_SCHEMA.to_owned(),
        attempt_id: attempt_id.to_owned(),
        slot,
        base: baseline.payload.candidate.revision.clone(),
        baseline_report_sha256: hash_json(baseline, "encode baseline report")?,
        baseline_payload_sha256: baseline.payload_sha256.clone(),
        inventory_payload_sha256: inventory.payload_sha256.clone(),
        obligation_inventory_sha256: inventory
            .payload
            .harness
            .obligation_inventory_sha256
            .clone(),
        family,
        targets,
        targets_sha256,
    };
    assignment.validate(inventory, baseline)?;
    Ok(assignment)
}

/// Require an exact-denominator, no-regression gain inside the assigned
/// cluster. Unassigned dispositions are immutable.
pub fn validate_regex_automata_strict_gain(
    inventory: &RegexAutomataCorpusReport,
    previous: &RegexAutomataAdapterReport,
    current: &RegexAutomataAdapterReport,
    assignment: &RegexAutomataGapAssignment,
) -> Result<RegexAutomataStrictGain, InventoryError> {
    inventory.validate()?;
    previous.validate_for_gain(inventory)?;
    validate_regex_automata_adapter_execution(inventory, current)?;
    assignment.validate(inventory, previous)?;
    if previous.payload.candidate.revision == current.payload.candidate.revision
        || previous.payload.candidate.tree == current.payload.candidate.tree
    {
        return Err(InventoryError::new(
            "regex-automata strict gain lacks a distinct candidate commit/tree",
        ));
    }
    let assigned = assignment
        .targets
        .iter()
        .flat_map(|target| {
            target
                .mode_ids
                .iter()
                .map(|mode_id| (mode_id.clone(), target.harness, target.case_id.clone()))
        })
        .collect::<BTreeSet<_>>();
    let (gained_unique_cases, gained_mode_memberships) = gain_vectors(
        &previous.payload.receipts,
        &current.payload.receipts,
        &assigned,
    )?;
    if current.payload.counts.fault != 0 {
        return Err(InventoryError::new(
            "regex-automata candidate strict gain contains a fault",
        ));
    }
    Ok(RegexAutomataStrictGain {
        family: assignment.family.clone(),
        gained_unique_cases,
        gained_mode_memberships,
        previous_pass: previous.payload.counts.pass,
        current_pass: current.payload.counts.pass,
    })
}

/// Validate the one sealed four-membership `util::look` assignment rooted at
/// the reviewed nine-pass `dfdba9d2` report. This does not alter or bypass the
/// lexicographic scheduler for any other assignment: its authority is the
/// exact base, target identity seal and compiled execution registry below.
pub fn validate_regex_automata_look_strict_gain(
    inventory: &RegexAutomataCorpusReport,
    previous: &RegexAutomataAdapterReport,
    current: &RegexAutomataAdapterReport,
) -> Result<RegexAutomataStrictGain, InventoryError> {
    inventory.validate()?;
    previous.validate_for_gain(inventory)?;
    validate_regex_automata_adapter_execution(inventory, current)?;
    validate_look_fixture()?;
    if previous.payload.candidate.revision != LOOK_BASE_REVISION
        || previous.payload.candidate.tree != LOOK_BASE_TREE
        || !previous
            .payload
            .candidate
            .tracked_and_untracked_worktree_clean
        || previous.payload.counts
            != (RegexAutomataAdapterCounts {
                pass: 9,
                unsupported: 3_833,
                fault: 0,
                total: 3_842,
            })
        || current.payload.candidate.revision == previous.payload.candidate.revision
        || current.payload.candidate.tree == previous.payload.candidate.tree
        || current.payload.counts
            != (RegexAutomataAdapterCounts {
                pass: 13,
                unsupported: 3_829,
                fault: 0,
                total: 3_842,
            })
    {
        return Err(InventoryError::new(
            "regex-automata look gain identity or cardinality mismatch",
        ));
    }
    let assigned = LOOK_CASES
        .iter()
        .map(|case| {
            (
                COMPILED_UNIT_MODE_ID.to_owned(),
                RegexAutomataHarnessKind::Unit,
                case.case_id.to_owned(),
            )
        })
        .collect::<BTreeSet<_>>();
    let (gained_unique_cases, gained_mode_memberships) = gain_vectors(
        &previous.payload.receipts,
        &current.payload.receipts,
        &assigned,
    )?;
    if (gained_unique_cases, gained_mode_memberships) != (4, 4) {
        return Err(InventoryError::new(
            "regex-automata look gain is not exact four-membership progress",
        ));
    }
    Ok(RegexAutomataStrictGain {
        family: "unit-util".to_owned(),
        gained_unique_cases,
        gained_mode_memberships,
        previous_pass: previous.payload.counts.pass,
        current_pass: current.payload.counts.pass,
    })
}

/// Extend the exact thirteen-pass predecessor with independently compiled and
/// executed receipts for the remaining 29 unit modes. The historical
/// package-default receipts are retained byte-for-byte; labels are never
/// projected from one Cargo feature mode to another.
pub fn build_regex_automata_all_mode_look_report(
    inventory: &RegexAutomataCorpusReport,
    previous: &RegexAutomataAdapterReport,
    matrix: RegexAutomataLookModeMatrix,
    candidate: CandidateIdentity,
) -> Result<RegexAutomataAdapterReport, InventoryError> {
    inventory.validate()?;
    validate_all_mode_look_predecessor(inventory, previous)?;
    validate_all_mode_matrix(inventory, &matrix)?;
    validate_candidate(&candidate)?;
    if candidate.revision == previous.payload.candidate.revision
        || candidate.tree == previous.payload.candidate.tree
    {
        return Err(InventoryError::new(
            "regex-automata all-mode look candidate is not distinct",
        ));
    }

    let assigned = new_mode_look_identities(inventory)?;
    let mode_receipts = matrix
        .payload
        .receipts
        .iter()
        .map(|receipt| (receipt.mode_id.as_str(), receipt))
        .collect::<BTreeMap<_, _>>();
    let mut receipts = previous.payload.receipts.clone();
    let mut executions = previous.payload.execution_receipts.clone();
    for receipt in &mut receipts {
        let identity = (
            receipt.mode_id.clone(),
            receipt.harness,
            receipt.case_id.clone(),
        );
        if !assigned.contains(&identity) {
            continue;
        }
        let mode_receipt = mode_receipts
            .get(receipt.mode_id.as_str())
            .ok_or_else(|| InventoryError::new("look mode lacks execution evidence"))?;
        if !matches!(
            mode_receipt.disposition,
            RegexAutomataLookModeDisposition::Available { .. }
        ) {
            return Err(InventoryError::new(format!(
                "look mode {} is explicitly unavailable",
                receipt.mode_id,
            )));
        }
        let case = reviewed_look_case(&receipt.case_id)
            .ok_or_else(|| InventoryError::new("look target has an unreviewed case"))?;
        let assertion_executions =
            match catch_unwind(AssertUnwindSafe(|| run_look_case_matrix_observer(case))) {
                Ok(Ok(executions)) => executions,
                Ok(Err(reason)) => {
                    return Err(InventoryError::new(format!(
                        "look observer rejected {}: {}",
                        receipt.case_id,
                        normalized_reason(&reason),
                    )));
                }
                Err(_) => return Err(InventoryError::new("look observer panicked")),
            };
        let execution = RegexAutomataExecutionReceipt {
            mode: matrix_mode_execution(inventory, matrix.payload_sha256.as_str(), mode_receipt)?,
            harness: RegexAutomataHarnessKind::Unit,
            case_id: receipt.case_id.clone(),
            source: source_contract(&case.source),
            assertion_executions,
        };
        let evidence_sha256 = hash_json(&execution, "encode all-mode look execution")?;
        receipt.disposition = RegexAutomataAdapterDisposition::Pass { evidence_sha256 };
        executions.push(execution);
    }
    let executions = order_execution_receipts(&receipts, executions, "all-mode look report")?;
    let counts = adapter_counts(&receipts);
    let payload = RegexAutomataAdapterReportPayload {
        inventory_payload_sha256: inventory.payload_sha256.clone(),
        obligation_inventory_sha256: inventory
            .payload
            .harness
            .obligation_inventory_sha256
            .clone(),
        candidate,
        counts,
        receipts,
        execution_receipts: executions,
        look_mode_matrix: Some(matrix),
        start_mode_matrix: None,
        start_mode_baseline: None,
        limitations: ALL_MODE_LOOK_REPORT_LIMITATIONS
            .iter()
            .map(|text| (*text).to_owned())
            .collect(),
    };
    let report = RegexAutomataAdapterReport {
        schema: REGEX_AUTOMATA_ALL_MODE_LOOK_REPORT_SCHEMA.to_owned(),
        payload_sha256: hash_json(&payload, "encode all-mode look report payload")?,
        payload,
    };
    validate_all_mode_look_execution(inventory, &report)?;
    Ok(report)
}

/// Require the exact 13 -> 129 transition with all 3,713 non-target
/// dispositions unchanged, bound to the clean checkout that built this
/// verifier and whose sole parent is the authenticated predecessor.
pub fn validate_regex_automata_all_mode_look_strict_gain(
    inventory: &RegexAutomataCorpusReport,
    previous: &RegexAutomataAdapterReport,
    current: &RegexAutomataAdapterReport,
    candidate_path: &Path,
) -> Result<RegexAutomataStrictGain, InventoryError> {
    validate_all_mode_look_predecessor(inventory, previous)?;
    let authenticated_candidate = authenticate_candidate_source(candidate_path)?;
    let checkout = candidate_checkout_provenance(candidate_path)?;
    validate_all_mode_candidate_provenance(
        &current.payload.candidate,
        &authenticated_candidate,
        &checkout.tree,
        &checkout.revision_and_parents,
        &previous.payload.candidate.revision,
    )?;
    validate_regex_automata_all_mode_look_strict_gain_against_candidate(
        inventory,
        previous,
        current,
        &authenticated_candidate,
    )
}

fn validate_regex_automata_all_mode_look_strict_gain_against_candidate(
    inventory: &RegexAutomataCorpusReport,
    previous: &RegexAutomataAdapterReport,
    current: &RegexAutomataAdapterReport,
    authenticated_candidate: &CandidateIdentity,
) -> Result<RegexAutomataStrictGain, InventoryError> {
    validate_all_mode_look_predecessor(inventory, previous)?;
    validate_all_mode_look_execution(inventory, current)?;
    if current.payload.counts
        != (RegexAutomataAdapterCounts {
            pass: 129,
            unsupported: 3_713,
            fault: 0,
            total: 3_842,
        })
        || current.payload.candidate.revision == previous.payload.candidate.revision
        || current.payload.candidate.tree == previous.payload.candidate.tree
        || current.payload.candidate != *authenticated_candidate
    {
        return Err(InventoryError::new(
            "regex-automata all-mode look gain identity or cardinality mismatch",
        ));
    }
    let assigned = new_mode_look_identities(inventory)?;
    let (gained_unique_cases, gained_mode_memberships) = gain_vectors(
        &previous.payload.receipts,
        &current.payload.receipts,
        &assigned,
    )?;
    if (gained_unique_cases, gained_mode_memberships) != (4, 116) {
        return Err(InventoryError::new(
            "regex-automata all-mode look gain is not exact 116-membership progress",
        ));
    }
    Ok(RegexAutomataStrictGain {
        family: "unit-util".to_owned(),
        gained_unique_cases,
        gained_mode_memberships,
        previous_pass: previous.payload.counts.pass,
        current_pass: current.payload.counts.pass,
    })
}

fn validate_all_mode_candidate_provenance(
    reported: &CandidateIdentity,
    authenticated: &CandidateIdentity,
    authenticated_tree: &str,
    revision_and_parents: &str,
    expected_parent: &str,
) -> Result<(), InventoryError> {
    validate_candidate(reported)?;
    validate_candidate(authenticated)?;
    let mut commits = revision_and_parents.split_ascii_whitespace();
    if reported != authenticated
        || authenticated.tree != authenticated_tree
        || commits.next() != Some(authenticated.revision.as_str())
        || commits.next() != Some(expected_parent)
        || commits.next().is_some()
    {
        return Err(InventoryError::new(
            "all-mode look candidate checkout revision/tree/parent mismatch",
        ));
    }
    Ok(())
}

struct CandidateCheckoutProvenance {
    tree: String,
    revision_and_parents: String,
}

fn candidate_checkout_provenance(
    candidate_path: &Path,
) -> Result<CandidateCheckoutProvenance, InventoryError> {
    let status = strict_candidate_git_output(
        candidate_path,
        &["status", "--porcelain=v1", "--untracked-files=all"],
        REGEX_AUTOMATA_PROGRESS_MAX_FILE_BYTES,
    )?;
    if !status.is_empty() {
        return Err(InventoryError::new(
            "all-mode look candidate checkout is dirty",
        ));
    }
    let tree = strict_candidate_git_output(
        candidate_path,
        &["rev-parse", "--verify", "HEAD^{tree}"],
        64,
    )?;
    let revision_and_parents = strict_candidate_git_output(
        candidate_path,
        &["rev-list", "--parents", "-n", "1", "HEAD^{commit}"],
        256,
    )?;
    Ok(CandidateCheckoutProvenance {
        tree,
        revision_and_parents,
    })
}

fn strict_candidate_git_output(
    candidate_path: &Path,
    args: &[&str],
    maximum_output_bytes: usize,
) -> Result<String, InventoryError> {
    let output = Command::new("/usr/bin/git")
        .arg("--no-replace-objects")
        .arg("-C")
        .arg(candidate_path)
        .args(args)
        .env_clear()
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .output()
        .map_err(|error| InventoryError::new(format!("run candidate Git: {error}")))?;
    if !output.status.success()
        || !output.stderr.is_empty()
        || output.stdout.len() > maximum_output_bytes
    {
        return Err(InventoryError::new(
            "cannot authenticate all-mode look candidate checkout",
        ));
    }
    String::from_utf8(output.stdout)
        .map(|line| line.trim().to_owned())
        .map_err(|_| InventoryError::new("candidate Git output is not UTF-8"))
}

fn validate_all_mode_look_predecessor(
    inventory: &RegexAutomataCorpusReport,
    previous: &RegexAutomataAdapterReport,
) -> Result<(), InventoryError> {
    validate_regex_automata_adapter_execution(inventory, previous)?;
    if previous.schema != REGEX_AUTOMATA_ADAPTER_REPORT_SCHEMA
        || previous.payload.candidate.revision != LOOK_ALL_MODE_PREDECESSOR_REVISION
        || previous.payload.candidate.tree != LOOK_ALL_MODE_PREDECESSOR_TREE
        || !previous
            .payload
            .candidate
            .tracked_and_untracked_worktree_clean
        || previous.payload.counts
            != (RegexAutomataAdapterCounts {
                pass: 13,
                unsupported: 3_829,
                fault: 0,
                total: 3_842,
            })
        || previous.payload.look_mode_matrix.is_some()
    {
        return Err(InventoryError::new(
            "regex-automata all-mode look predecessor authority mismatch",
        ));
    }
    Ok(())
}

fn validate_all_mode_matrix(
    inventory: &RegexAutomataCorpusReport,
    matrix: &RegexAutomataLookModeMatrix,
) -> Result<(), InventoryError> {
    matrix.validate()?;
    if matrix.payload.source != inventory.payload.source
        || matrix.payload.harness.inventory_payload_sha256 != inventory.payload_sha256
        || matrix.payload.harness.inventory_obligation_sha256
            != inventory.payload.harness.obligation_inventory_sha256
        || matrix.payload.harness.inventory_harness_sha256
            != hash_json(
                &inventory.payload.harness,
                "encode regex-automata inventory harness",
            )?
        || matrix.payload.counts.modes != 30
        || matrix.payload.counts.available_modes != 30
        || matrix.payload.counts.unavailable_modes != 0
        || matrix.payload.counts.tests_per_mode != 4
        || matrix.payload.counts.available_test_memberships != 120
        || matrix.payload.counts.total_test_memberships != 120
    {
        return Err(InventoryError::new(
            "regex-automata look-mode matrix is not an exact available 30-mode execution",
        ));
    }
    let target_modes = all_mode_look_identities(inventory)?
        .into_iter()
        .map(|(mode_id, _, _)| mode_id)
        .collect::<BTreeSet<_>>();
    let observed_modes = matrix
        .payload
        .receipts
        .iter()
        .map(|receipt| receipt.mode_id.clone())
        .collect::<BTreeSet<_>>();
    if target_modes.len() != 30 || observed_modes != target_modes {
        return Err(InventoryError::new(
            "regex-automata look-mode matrix mode set mismatch",
        ));
    }
    for receipt in &matrix.payload.receipts {
        let mode = inventory
            .payload
            .modes
            .iter()
            .find(|mode| mode.id == receipt.mode_id)
            .ok_or_else(|| InventoryError::new("look-mode matrix mode is absent"))?;
        if mode.harness != RegexAutomataHarnessKind::Unit
            || receipt.harness != mode.harness
            || receipt.default_features != mode.default_features
            || receipt.all_features != mode.all_features
            || receipt.features != mode.features
            || receipt.inventory_members != mode.members
            || receipt.inventory_member_ids_sha256 != mode.member_ids_sha256
            || !matches!(
                receipt.disposition,
                RegexAutomataLookModeDisposition::Available { .. }
            )
        {
            return Err(InventoryError::new(
                "regex-automata look-mode matrix differs from inventory mode",
            ));
        }
    }
    Ok(())
}

fn matrix_mode_execution(
    inventory: &RegexAutomataCorpusReport,
    matrix_payload_sha256: &str,
    receipt: &RegexAutomataLookModeReceipt,
) -> Result<RegexAutomataModeExecution, InventoryError> {
    let mode = inventory
        .payload
        .modes
        .iter()
        .find(|mode| mode.id == receipt.mode_id)
        .ok_or_else(|| InventoryError::new("matrix execution mode is absent"))?;
    if receipt.harness != RegexAutomataHarnessKind::Unit
        || mode.harness != receipt.harness
        || mode.default_features != receipt.default_features
        || mode.all_features != receipt.all_features
        || mode.features != receipt.features
        || mode.members != receipt.inventory_members
        || mode.member_ids_sha256 != receipt.inventory_member_ids_sha256
        || !matches!(
            receipt.disposition,
            RegexAutomataLookModeDisposition::Available { .. }
        )
    {
        return Err(InventoryError::new(
            "matrix execution mode identity mismatch",
        ));
    }
    Ok(RegexAutomataModeExecution {
        mode_id: mode.id.clone(),
        harness: mode.harness,
        default_features: mode.default_features,
        all_features: mode.all_features,
        features: mode.features.clone(),
        dependency_package: "regex-automata".to_owned(),
        dependency_version: "0.4.14".to_owned(),
        mode_evidence_sha256: Some(hash_json(
            &(matrix_payload_sha256, receipt),
            "encode matrix-bound look-mode receipt",
        )?),
    })
}

fn validate_all_mode_look_execution(
    inventory: &RegexAutomataCorpusReport,
    report: &RegexAutomataAdapterReport,
) -> Result<(), InventoryError> {
    report.validate_structure(inventory)?;
    if report.schema != REGEX_AUTOMATA_ALL_MODE_LOOK_REPORT_SCHEMA {
        return Err(InventoryError::new(
            "regex-automata report is not an all-mode look report",
        ));
    }
    Ok(())
}

fn validate_all_mode_look_execution_after_structure(
    inventory: &RegexAutomataCorpusReport,
    report: &RegexAutomataAdapterReport,
) -> Result<(), InventoryError> {
    if report.schema != REGEX_AUTOMATA_ALL_MODE_LOOK_REPORT_SCHEMA {
        return Err(InventoryError::new(
            "regex-automata report is not an all-mode look report",
        ));
    }
    validate_execution_receipt_order(report)?;
    let matrix = report
        .payload
        .look_mode_matrix
        .as_ref()
        .ok_or_else(|| InventoryError::new("all-mode look report lacks its matrix"))?;
    validate_all_mode_matrix(inventory, matrix)?;
    let predecessor = build_adapter_report_with_registry(
        inventory,
        CandidateIdentity {
            revision: LOOK_ALL_MODE_PREDECESSOR_REVISION.to_owned(),
            tree: LOOK_ALL_MODE_PREDECESSOR_TREE.to_owned(),
            tracked_and_untracked_worktree_clean: true,
        },
        REGISTERED_ADAPTERS,
    )?;
    validate_all_mode_look_predecessor(inventory, &predecessor)?;
    if report.payload.candidate.revision == LOOK_ALL_MODE_PREDECESSOR_REVISION
        || report.payload.candidate.tree == LOOK_ALL_MODE_PREDECESSOR_TREE
        || report.payload.counts
            != (RegexAutomataAdapterCounts {
                pass: 129,
                unsupported: 3_713,
                fault: 0,
                total: 3_842,
            })
    {
        return Err(InventoryError::new(
            "all-mode look candidate identity or counts mismatch",
        ));
    }

    let assigned = new_mode_look_identities(inventory)?;
    for ((old, current), obligation) in predecessor
        .payload
        .receipts
        .iter()
        .zip(&report.payload.receipts)
        .zip(&inventory.payload.obligations)
    {
        let identity = obligation_membership_identity(obligation);
        if assigned.contains(&identity) {
            if !matches!(
                current.disposition,
                RegexAutomataAdapterDisposition::Pass { .. }
            ) {
                return Err(InventoryError::new(
                    "all-mode look target did not become a pass",
                ));
            }
        } else if current != old {
            return Err(InventoryError::new(
                "all-mode look report changed a non-target disposition",
            ));
        }
    }
    validate_all_mode_transition_seals(report, &assigned)?;

    validate_all_mode_look_receipts(inventory, report, matrix, &predecessor, &assigned)
}

fn validate_all_mode_look_receipts(
    inventory: &RegexAutomataCorpusReport,
    report: &RegexAutomataAdapterReport,
    matrix: &RegexAutomataLookModeMatrix,
    predecessor: &RegexAutomataAdapterReport,
    assigned: &BTreeSet<(String, RegexAutomataHarnessKind, String)>,
) -> Result<(), InventoryError> {
    let matrix_receipts = matrix
        .payload
        .receipts
        .iter()
        .map(|receipt| (receipt.mode_id.as_str(), receipt))
        .collect::<BTreeMap<_, _>>();
    let predecessor_executions = predecessor
        .payload
        .execution_receipts
        .iter()
        .map(|execution| {
            (
                (
                    execution.mode.mode_id.clone(),
                    execution.harness,
                    execution.case_id.clone(),
                ),
                execution,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut executions = BTreeMap::new();
    for execution in &report.payload.execution_receipts {
        let identity = (
            execution.mode.mode_id.clone(),
            execution.harness,
            execution.case_id.clone(),
        );
        if executions.insert(identity.clone(), execution).is_some() {
            return Err(InventoryError::new(
                "duplicate all-mode look execution receipt",
            ));
        }
        if assigned.contains(&identity) {
            let mode_receipt = matrix_receipts
                .get(execution.mode.mode_id.as_str())
                .ok_or_else(|| InventoryError::new("execution lacks a matrix mode"))?;
            let case = reviewed_look_case(&execution.case_id)
                .ok_or_else(|| InventoryError::new("execution has an unreviewed look case"))?;
            let expected_assertions = run_look_case_matrix_observer(case)
                .map_err(|reason| InventoryError::new(normalized_reason(&reason)))?;
            if execution.mode
                != matrix_mode_execution(inventory, matrix.payload_sha256.as_str(), mode_receipt)?
                || execution.harness != RegexAutomataHarnessKind::Unit
                || execution.source != source_contract(&case.source)
                || execution.assertion_executions != expected_assertions
            {
                return Err(InventoryError::new(
                    "all-mode look execution evidence mismatch",
                ));
            }
        } else if predecessor_executions.get(&identity) != Some(&execution) {
            return Err(InventoryError::new(
                "all-mode look report altered or added non-target execution evidence",
            ));
        }
    }
    if executions.len() != 129
        || predecessor_executions
            .keys()
            .any(|identity| !executions.contains_key(identity))
        || assigned
            .iter()
            .any(|identity| !executions.contains_key(identity))
    {
        return Err(InventoryError::new(
            "all-mode look execution evidence denominator mismatch",
        ));
    }
    for receipt in &report.payload.receipts {
        let identity = (
            receipt.mode_id.clone(),
            receipt.harness,
            receipt.case_id.clone(),
        );
        match &receipt.disposition {
            RegexAutomataAdapterDisposition::Pass { evidence_sha256 } => {
                let execution = executions.get(&identity).ok_or_else(|| {
                    InventoryError::new("all-mode look pass lacks execution evidence")
                })?;
                if hash_json(*execution, "encode all-mode look execution")? != *evidence_sha256 {
                    return Err(InventoryError::new(
                        "all-mode look pass evidence seal mismatch",
                    ));
                }
            }
            RegexAutomataAdapterDisposition::Unsupported { .. } => {
                if executions.contains_key(&identity) {
                    return Err(InventoryError::new(
                        "unsupported membership has all-mode execution evidence",
                    ));
                }
            }
            RegexAutomataAdapterDisposition::Fault { .. } => {
                return Err(InventoryError::new("all-mode look report contains a fault"));
            }
        }
    }
    Ok(())
}

fn report_limitations(schema: &str) -> Result<&'static [&'static str], InventoryError> {
    if schema == REGEX_AUTOMATA_ADAPTER_REPORT_SCHEMA {
        Ok(MIXED_DEFAULT_REPORT_LIMITATIONS.as_slice())
    } else if schema == REGEX_AUTOMATA_ALL_MODE_LOOK_REPORT_SCHEMA {
        Ok(ALL_MODE_LOOK_REPORT_LIMITATIONS.as_slice())
    } else if schema == REGEX_AUTOMATA_ASCII_WORD_LOOK_REPORT_SCHEMA {
        Ok(word_look::ASCII_WORD_LOOK_REPORT_LIMITATIONS.as_slice())
    } else if schema == REGEX_AUTOMATA_UNICODE_WORD_LOOK_REPORT_SCHEMA {
        Ok(unicode_word_look::UNICODE_WORD_LOOK_REPORT_LIMITATIONS.as_slice())
    } else if schema == REGEX_AUTOMATA_START_MAP_REPORT_SCHEMA {
        Ok(start_map::START_MAP_REPORT_LIMITATIONS.as_slice())
    } else if schema == REGEX_AUTOMATA_SUFFIX_LITERAL_COUNT_REPORT_SCHEMA {
        Ok(suffix_literal_count::SUFFIX_LITERAL_COUNT_REPORT_LIMITATIONS.as_slice())
    } else if schema == REGEX_AUTOMATA_SEARCH_CLUSTER_REPORT_SCHEMA {
        Ok(search_cluster::SEARCH_CLUSTER_REPORT_LIMITATIONS.as_slice())
    } else if schema == REGEX_AUTOMATA_STATE_CODEC_REPORT_SCHEMA {
        Ok(state_codec::STATE_CODEC_REPORT_LIMITATIONS.as_slice())
    } else if schema == crate::automata_corpus::start_mode::REGEX_AUTOMATA_START_MODE_REPORT_SCHEMA
    {
        Ok(crate::automata_corpus::start_mode::START_MODE_REPORT_LIMITATIONS.as_slice())
    } else if schema == PREVIOUS_REGEX_AUTOMATA_ADAPTER_REPORT_SCHEMA {
        Ok(DOCTEST_ONLY_REPORT_LIMITATIONS.as_slice())
    } else if schema == LEGACY_REGEX_AUTOMATA_ADAPTER_REPORT_SCHEMA {
        Ok(LEGACY_REPORT_LIMITATIONS.as_slice())
    } else {
        Err(InventoryError::new(
            "regex-automata adapter report schema mismatch",
        ))
    }
}

impl RegexAutomataAdapterReport {
    /// Validate the full inventory identity, candidate identity, exact receipt
    /// order, per-case consistency, counts and payload seal.
    pub fn validate(&self, inventory: &RegexAutomataCorpusReport) -> Result<(), InventoryError> {
        self.validate_structure(inventory)
    }

    fn validate_structure(
        &self,
        inventory: &RegexAutomataCorpusReport,
    ) -> Result<(), InventoryError> {
        inventory.validate()?;
        let limitations = report_limitations(self.schema.as_str())?;
        let expected_payload_sha256 = if self.schema == LEGACY_REGEX_AUTOMATA_ADAPTER_REPORT_SCHEMA
        {
            hash_json(
                &LegacyAdapterPayload {
                    inventory_payload_sha256: &self.payload.inventory_payload_sha256,
                    obligation_inventory_sha256: &self.payload.obligation_inventory_sha256,
                    candidate: &self.payload.candidate,
                    counts: &self.payload.counts,
                    receipts: &self.payload.receipts,
                    limitations: &self.payload.limitations,
                },
                "encode legacy regex-automata adapter payload",
            )?
        } else {
            hash_json(&self.payload, "encode regex-automata adapter payload")?
        };
        if self.payload_sha256 != expected_payload_sha256
            || self.payload.inventory_payload_sha256 != inventory.payload_sha256
            || self.payload.obligation_inventory_sha256
                != inventory.payload.harness.obligation_inventory_sha256
            || self.payload.limitations
                != limitations
                    .iter()
                    .map(|text| (*text).to_owned())
                    .collect::<Vec<_>>()
        {
            return Err(InventoryError::new(
                "regex-automata adapter report identity mismatch",
            ));
        }
        validate_adapter_report_size_contract(self)?;
        validate_candidate(&self.payload.candidate)?;
        if self.payload.receipts.len() != inventory.payload.obligations.len() {
            return Err(InventoryError::new(
                "regex-automata adapter receipt denominator mismatch",
            ));
        }
        for (receipt, obligation) in self
            .payload
            .receipts
            .iter()
            .zip(&inventory.payload.obligations)
        {
            if receipt.mode_id != obligation.mode_id
                || receipt.harness != obligation.harness
                || receipt.case_id != obligation.case_id
            {
                return Err(InventoryError::new(
                    "regex-automata adapter receipt identity/order mismatch",
                ));
            }
            validate_disposition(&receipt.disposition)?;
        }
        if self.payload.counts != adapter_counts(&self.payload.receipts) {
            return Err(InventoryError::new(
                "regex-automata adapter disposition counts mismatch",
            ));
        }
        if self.schema != REGEX_AUTOMATA_ALL_MODE_LOOK_REPORT_SCHEMA
            && self.schema != REGEX_AUTOMATA_ASCII_WORD_LOOK_REPORT_SCHEMA
            && self.schema != REGEX_AUTOMATA_UNICODE_WORD_LOOK_REPORT_SCHEMA
            && self.schema != REGEX_AUTOMATA_START_MAP_REPORT_SCHEMA
            && self.schema != REGEX_AUTOMATA_SUFFIX_LITERAL_COUNT_REPORT_SCHEMA
            && self.schema != REGEX_AUTOMATA_SEARCH_CLUSTER_REPORT_SCHEMA
            && self.schema != REGEX_AUTOMATA_STATE_CODEC_REPORT_SCHEMA
            && self.schema
                != crate::automata_corpus::start_mode::REGEX_AUTOMATA_START_MODE_REPORT_SCHEMA
            && self.payload.look_mode_matrix.is_some()
        {
            return Err(InventoryError::new(
                "legacy regex-automata report unexpectedly embeds a look-mode matrix",
            ));
        }
        if self.schema
            == crate::automata_corpus::start_mode::REGEX_AUTOMATA_START_MODE_REPORT_SCHEMA
            || self.schema == REGEX_AUTOMATA_STATE_CODEC_REPORT_SCHEMA
        {
            if self.payload.start_mode_matrix.is_none()
                || self.payload.start_mode_baseline.is_none()
            {
                return Err(InventoryError::new(
                    "start-mode report lacks its baseline or execution matrix",
                ));
            }
        } else if self.payload.start_mode_matrix.is_some()
            || self.payload.start_mode_baseline.is_some()
        {
            return Err(InventoryError::new(
                "non-start-mode report unexpectedly embeds start-mode evidence",
            ));
        }
        validate_report_execution_after_structure(inventory, self)
    }

    fn validate_for_gain(
        &self,
        inventory: &RegexAutomataCorpusReport,
    ) -> Result<(), InventoryError> {
        self.validate_structure(inventory)?;
        if self.schema == PREVIOUS_REGEX_AUTOMATA_ADAPTER_REPORT_SCHEMA {
            validate_regex_automata_predecessor_execution(inventory, self)?;
        } else if self.schema == REGEX_AUTOMATA_ADAPTER_REPORT_SCHEMA
            || self.schema == REGEX_AUTOMATA_ALL_MODE_LOOK_REPORT_SCHEMA
            || self.schema == REGEX_AUTOMATA_ASCII_WORD_LOOK_REPORT_SCHEMA
            || self.schema == REGEX_AUTOMATA_UNICODE_WORD_LOOK_REPORT_SCHEMA
            || self.schema == REGEX_AUTOMATA_START_MAP_REPORT_SCHEMA
            || self.schema == REGEX_AUTOMATA_SUFFIX_LITERAL_COUNT_REPORT_SCHEMA
            || self.schema == REGEX_AUTOMATA_SEARCH_CLUSTER_REPORT_SCHEMA
            || self.schema == REGEX_AUTOMATA_STATE_CODEC_REPORT_SCHEMA
            || self.schema
                == crate::automata_corpus::start_mode::REGEX_AUTOMATA_START_MODE_REPORT_SCHEMA
        {
            return Err(InventoryError::new(
                "current regex-automata report cannot serve as this transition's predecessor",
            ));
        }
        Ok(())
    }
}

fn validate_report_execution_after_structure(
    inventory: &RegexAutomataCorpusReport,
    report: &RegexAutomataAdapterReport,
) -> Result<(), InventoryError> {
    if report.schema == LEGACY_REGEX_AUTOMATA_ADAPTER_REPORT_SCHEMA {
        if !report.payload.execution_receipts.is_empty()
            || report.payload.counts.pass != 0
            || report.payload.counts.fault != 0
            || report.payload.receipts.iter().any(|receipt| {
                !matches!(
                    &receipt.disposition,
                    RegexAutomataAdapterDisposition::Unsupported { reason_code }
                        if reason_code == INVENTORY_UNSUPPORTED_REASON
                )
            })
        {
            return Err(InventoryError::new(
                "legacy regex-automata report is not a zero-pass baseline",
            ));
        }
        return Ok(());
    }
    if report.schema == REGEX_AUTOMATA_ALL_MODE_LOOK_REPORT_SCHEMA {
        return validate_all_mode_look_execution_after_structure(inventory, report);
    }
    if report.schema == REGEX_AUTOMATA_ASCII_WORD_LOOK_REPORT_SCHEMA {
        return word_look::validate_ascii_word_look_execution_after_structure(inventory, report);
    }
    if report.schema == REGEX_AUTOMATA_UNICODE_WORD_LOOK_REPORT_SCHEMA {
        return unicode_word_look::validate_unicode_word_look_execution_after_structure(
            inventory, report,
        );
    }
    if report.schema == REGEX_AUTOMATA_START_MAP_REPORT_SCHEMA {
        return start_map::validate_start_map_execution_after_structure(inventory, report);
    }
    if report.schema == REGEX_AUTOMATA_SUFFIX_LITERAL_COUNT_REPORT_SCHEMA {
        return suffix_literal_count::validate_suffix_literal_count_execution_after_structure(
            inventory, report,
        );
    }
    if report.schema == REGEX_AUTOMATA_SEARCH_CLUSTER_REPORT_SCHEMA {
        return search_cluster::validate_search_cluster_execution_after_structure(
            inventory, report,
        );
    }
    if report.schema == REGEX_AUTOMATA_STATE_CODEC_REPORT_SCHEMA {
        return state_codec::validate_state_codec_execution_after_structure(inventory, report);
    }
    if report.schema == crate::automata_corpus::start_mode::REGEX_AUTOMATA_START_MODE_REPORT_SCHEMA
    {
        return crate::automata_corpus::start_mode::validate_start_mode_report_after_structure(
            inventory, report,
        );
    }
    validate_execution_receipt_set(inventory, report, report_registry(report.schema.as_str())?)?;
    Ok(())
}

/// Re-run the independently sealed predecessor registry. The expected replay
/// set is never derived from dispositions in the report under review.
fn validate_regex_automata_predecessor_execution(
    inventory: &RegexAutomataCorpusReport,
    report: &RegexAutomataAdapterReport,
) -> Result<(), InventoryError> {
    report.validate_structure(inventory)?;
    if report.schema != PREVIOUS_REGEX_AUTOMATA_ADAPTER_REPORT_SCHEMA {
        return Err(InventoryError::new(
            "legacy regex-automata baseline has no executable passes",
        ));
    }
    validate_predecessor_registry_manifest(PREDECESSOR_REGISTERED_ADAPTERS)?;
    let reproduced = build_adapter_report_with_registry(
        inventory,
        report.payload.candidate.clone(),
        PREDECESSOR_REGISTERED_ADAPTERS,
    )?;
    validate_predecessor_report_authority(report, &reproduced)
}

fn validate_predecessor_report_authority(
    report: &RegexAutomataAdapterReport,
    reproduced: &RegexAutomataAdapterReport,
) -> Result<(), InventoryError> {
    validate_predecessor_registry_manifest(PREDECESSOR_REGISTERED_ADAPTERS)?;
    let expected_passes = PREDECESSOR_REGISTERED_ADAPTERS
        .iter()
        .map(|adapter| (adapter.mode_id, adapter.harness, adapter.case_id))
        .collect::<BTreeSet<_>>();
    let observed_passes = report
        .payload
        .receipts
        .iter()
        .filter(|receipt| {
            matches!(
                receipt.disposition,
                RegexAutomataAdapterDisposition::Pass { .. }
            )
        })
        .map(|receipt| {
            (
                receipt.mode_id.as_str(),
                receipt.harness,
                receipt.case_id.as_str(),
            )
        })
        .collect::<BTreeSet<_>>();
    if observed_passes != expected_passes || report != reproduced {
        return Err(InventoryError::new(
            "prior regex-automata report differs from authenticated predecessor registry",
        ));
    }
    Ok(())
}

/// Re-run every compiled adapter membership and require exact receipt/report
/// equality. This prevents a JSON author from manufacturing a plausible pass.
fn validate_regex_automata_adapter_execution(
    inventory: &RegexAutomataCorpusReport,
    report: &RegexAutomataAdapterReport,
) -> Result<(), InventoryError> {
    report.validate_structure(inventory)?;
    if report.schema != REGEX_AUTOMATA_ADAPTER_REPORT_SCHEMA {
        return Err(InventoryError::new(
            "legacy regex-automata baseline has no executable passes",
        ));
    }
    let reproduced = build_adapter_report_with_registry(
        inventory,
        report.payload.candidate.clone(),
        REGISTERED_ADAPTERS,
    )?;
    if &reproduced != report {
        return Err(InventoryError::new(
            "regex-automata report differs from compiled mode-bound execution",
        ));
    }
    Ok(())
}

impl RegexAutomataGapAssignment {
    /// Validate that this assignment is the exact deterministic current
    /// cluster derived from its bound complete baseline report.
    pub fn validate(
        &self,
        inventory: &RegexAutomataCorpusReport,
        baseline: &RegexAutomataAdapterReport,
    ) -> Result<(), InventoryError> {
        inventory.validate()?;
        baseline.validate(inventory)?;
        if self.schema != REGEX_AUTOMATA_GAP_ASSIGNMENT_SCHEMA
            || !token(&self.attempt_id)
            || self.slot > 255
            || self.base != baseline.payload.candidate.revision
            || self.baseline_report_sha256 != hash_json(baseline, "encode baseline report")?
            || self.baseline_payload_sha256 != baseline.payload_sha256
            || self.inventory_payload_sha256 != inventory.payload_sha256
            || self.obligation_inventory_sha256
                != inventory.payload.harness.obligation_inventory_sha256
            || self.targets.is_empty()
            || self.targets.len() > ASSIGNMENT_TARGET_LIMIT
            || self.targets.windows(2).any(|pair| pair[0] >= pair[1])
            || self.targets_sha256 != hash_json(&self.targets, "encode regex-automata gap targets")?
        {
            return Err(InventoryError::new(
                "invalid regex-automata gap assignment identity",
            ));
        }
        let clusters = pending_clusters(baseline)?;
        let (family, mut expected) = clusters
            .into_iter()
            .next()
            .ok_or_else(|| InventoryError::new("assignment baseline has no pending cases"))?;
        expected.truncate(ASSIGNMENT_TARGET_LIMIT);
        if self.family != family || self.targets != expected {
            return Err(InventoryError::new(
                "regex-automata assignment is not the next exact pending cluster",
            ));
        }
        Ok(())
    }
}

/// Read and validate a complete adapter report.
pub fn read_regex_automata_adapter_report(
    path: &Path,
    inventory: &RegexAutomataCorpusReport,
) -> Result<RegexAutomataAdapterReport, InventoryError> {
    let bytes = read_owned_regular(
        path,
        REGEX_AUTOMATA_ADAPTER_REPORT_MAX_FILE_BYTES,
        "regex-automata adapter report",
    )?;
    let report = serde_json::from_slice(&bytes).map_err(|error| {
        InventoryError::new(format!("decode regex-automata adapter report: {error}"))
    })?;
    RegexAutomataAdapterReport::validate(&report, inventory)?;
    Ok(report)
}

/// Read and validate an assignment against its complete baseline.
pub fn read_regex_automata_gap_assignment(
    path: &Path,
    inventory: &RegexAutomataCorpusReport,
    baseline: &RegexAutomataAdapterReport,
) -> Result<RegexAutomataGapAssignment, InventoryError> {
    let bytes = read_owned_regular(
        path,
        REGEX_AUTOMATA_PROGRESS_MAX_FILE_BYTES,
        "regex-automata gap assignment",
    )?;
    let assignment = serde_json::from_slice(&bytes).map_err(|error| {
        InventoryError::new(format!("decode regex-automata gap assignment: {error}"))
    })?;
    RegexAutomataGapAssignment::validate(&assignment, inventory, baseline)?;
    Ok(assignment)
}

/// Atomically publish a complete report without replacing evidence.
pub fn write_regex_automata_adapter_report(
    path: &Path,
    report: &RegexAutomataAdapterReport,
    inventory: &RegexAutomataCorpusReport,
) -> Result<(), InventoryError> {
    if report.schema == REGEX_AUTOMATA_ALL_MODE_LOOK_REPORT_SCHEMA {
        validate_all_mode_look_execution(inventory, report)?;
    } else if report.schema == REGEX_AUTOMATA_ASCII_WORD_LOOK_REPORT_SCHEMA
        || report.schema == REGEX_AUTOMATA_UNICODE_WORD_LOOK_REPORT_SCHEMA
        || report.schema == REGEX_AUTOMATA_START_MAP_REPORT_SCHEMA
        || report.schema == REGEX_AUTOMATA_SUFFIX_LITERAL_COUNT_REPORT_SCHEMA
        || report.schema == REGEX_AUTOMATA_SEARCH_CLUSTER_REPORT_SCHEMA
        || report.schema == REGEX_AUTOMATA_STATE_CODEC_REPORT_SCHEMA
        || report.schema
            == crate::automata_corpus::start_mode::REGEX_AUTOMATA_START_MODE_REPORT_SCHEMA
    {
        report.validate_structure(inventory)?;
    } else {
        validate_regex_automata_adapter_execution(inventory, report)?;
    }
    write_new_json(
        path,
        report,
        REGEX_AUTOMATA_ADAPTER_REPORT_MAX_FILE_BYTES,
        false,
        "regex-automata adapter report",
    )
}

/// Atomically publish one assignment without replacement.
pub fn write_regex_automata_gap_assignment(
    path: &Path,
    assignment: &RegexAutomataGapAssignment,
    inventory: &RegexAutomataCorpusReport,
    baseline: &RegexAutomataAdapterReport,
) -> Result<(), InventoryError> {
    assignment.validate(inventory, baseline)?;
    write_new_json(
        path,
        assignment,
        REGEX_AUTOMATA_PROGRESS_MAX_FILE_BYTES,
        true,
        "regex-automata gap assignment",
    )
}

fn pending_clusters(
    report: &RegexAutomataAdapterReport,
) -> Result<BTreeMap<String, Vec<RegexAutomataGapTarget>>, InventoryError> {
    let mut cases: BTreeMap<(RegexAutomataHarnessKind, String), BTreeSet<String>> = BTreeMap::new();
    for receipt in &report.payload.receipts {
        if matches!(
            receipt.disposition,
            RegexAutomataAdapterDisposition::Unsupported { .. }
        ) {
            cases
                .entry((receipt.harness, receipt.case_id.clone()))
                .or_default()
                .insert(receipt.mode_id.clone());
        }
    }
    let mut clusters: BTreeMap<String, Vec<RegexAutomataGapTarget>> = BTreeMap::new();
    for ((harness, case_id), mode_ids) in cases {
        let family = case_family(harness, &case_id)?;
        clusters
            .entry(family)
            .or_default()
            .push(RegexAutomataGapTarget {
                harness,
                case_id,
                mode_ids: mode_ids.into_iter().collect(),
            });
    }
    Ok(clusters)
}

fn case_family(harness: RegexAutomataHarnessKind, case_id: &str) -> Result<String, InventoryError> {
    let component = match harness {
        RegexAutomataHarnessKind::Unit | RegexAutomataHarnessKind::Integration => {
            case_id.split("::").next()
        }
        RegexAutomataHarnessKind::Doctest => case_id
            .strip_prefix("src/")
            .and_then(|rest| rest.split(" - ").next())
            .and_then(|source_path| source_path.split('/').next())
            .map(|component| component.strip_suffix(".rs").unwrap_or(component)),
    }
    .ok_or_else(|| InventoryError::new("cannot classify regex-automata case family"))?;
    if component.is_empty()
        || !component
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(InventoryError::new(
            "invalid regex-automata family component",
        ));
    }
    let harness = match harness {
        RegexAutomataHarnessKind::Unit => "unit",
        RegexAutomataHarnessKind::Integration => "integration",
        RegexAutomataHarnessKind::Doctest => "doctest",
    };
    Ok(format!("{harness}-{component}"))
}

fn obligation_membership_identity(
    obligation: &RegexAutomataObligation,
) -> (String, RegexAutomataHarnessKind, String) {
    (
        obligation.mode_id.clone(),
        obligation.harness,
        obligation.case_id.clone(),
    )
}

fn adapter_receipt_identity(
    receipt: &RegexAutomataAdapterReceipt,
) -> (String, RegexAutomataHarnessKind, String) {
    (
        receipt.mode_id.clone(),
        receipt.harness,
        receipt.case_id.clone(),
    )
}

fn execution_receipt_identity(
    receipt: &RegexAutomataExecutionReceipt,
) -> (String, RegexAutomataHarnessKind, String) {
    (
        receipt.mode.mode_id.clone(),
        receipt.harness,
        receipt.case_id.clone(),
    )
}

fn order_execution_receipts(
    receipts: &[RegexAutomataAdapterReceipt],
    executions: Vec<RegexAutomataExecutionReceipt>,
    label: &str,
) -> Result<Vec<RegexAutomataExecutionReceipt>, InventoryError> {
    let mut by_identity = BTreeMap::new();
    for execution in executions {
        if by_identity
            .insert(execution_receipt_identity(&execution), execution)
            .is_some()
        {
            return Err(InventoryError::new(format!(
                "duplicate {label} execution receipt",
            )));
        }
    }
    let mut ordered = Vec::with_capacity(by_identity.len());
    for receipt in receipts {
        if matches!(
            receipt.disposition,
            RegexAutomataAdapterDisposition::Pass { .. }
        ) {
            ordered.push(
                by_identity
                    .remove(&adapter_receipt_identity(receipt))
                    .ok_or_else(|| {
                        InventoryError::new(format!(
                            "{label} pass lacks its canonical execution receipt",
                        ))
                    })?,
            );
        }
    }
    if !by_identity.is_empty() {
        return Err(InventoryError::new(format!(
            "{label} has non-pass execution evidence",
        )));
    }
    Ok(ordered)
}

fn validate_execution_receipt_order(
    report: &RegexAutomataAdapterReport,
) -> Result<(), InventoryError> {
    let mut executions = report.payload.execution_receipts.iter();
    for receipt in &report.payload.receipts {
        if !matches!(
            receipt.disposition,
            RegexAutomataAdapterDisposition::Pass { .. }
        ) {
            continue;
        }
        let execution = executions.next().ok_or_else(|| {
            InventoryError::new("regex-automata pass lacks ordered execution evidence")
        })?;
        if execution_receipt_identity(execution) != adapter_receipt_identity(receipt) {
            return Err(InventoryError::new(
                "regex-automata execution receipt identity/order mismatch",
            ));
        }
    }
    if executions.next().is_some() {
        return Err(InventoryError::new(
            "regex-automata report has excess ordered execution evidence",
        ));
    }
    Ok(())
}

fn require_compiled_mode(context: &AdapterContext<'_>) -> Result<(), String> {
    if compiled_mode_id(context.mode.harness) != Some(context.mode.mode_id.as_str())
        || !context.mode.default_features
        || context.mode.all_features
        || !context.mode.features.is_empty()
        || context.mode.dependency_package != "regex-automata"
        || context.mode.dependency_version != "0.4.14"
    {
        return Err("compiled-mode-mismatch".to_owned());
    }
    Ok(())
}

const fn compiled_mode_id(harness: RegexAutomataHarnessKind) -> Option<&'static str> {
    match harness {
        RegexAutomataHarnessKind::Doctest => Some(COMPILED_MODE_ID),
        RegexAutomataHarnessKind::Unit => Some(COMPILED_UNIT_MODE_ID),
        RegexAutomataHarnessKind::Integration => None,
    }
}

fn upstream_half_match(matched: Option<regex_automata::HalfMatch>) -> String {
    match matched {
        None => "half-match:none".to_owned(),
        Some(matched) => format!(
            "half-match:some:pattern={}:offset={}",
            matched.pattern().as_usize(),
            matched.offset()
        ),
    }
}

fn fre_half_match(matched: Option<fre::Match>) -> String {
    match matched {
        None => "half-match:none".to_owned(),
        Some(matched) => format!("half-match:some:pattern=0:offset={}", matched.end()),
    }
}

fn mode_execution(
    inventory: &RegexAutomataCorpusReport,
    mode_id: &str,
) -> Result<RegexAutomataModeExecution, InventoryError> {
    let mut matching = inventory
        .payload
        .modes
        .iter()
        .filter(|mode| mode.id == mode_id);
    let mode = matching
        .next()
        .ok_or_else(|| InventoryError::new("compiled regex-automata mode is absent"))?;
    if matching.next().is_some()
        || compiled_mode_id(mode.harness) != Some(mode_id)
        || !mode.default_features
        || mode.all_features
        || !mode.features.is_empty()
    {
        return Err(InventoryError::new(
            "compiled regex-automata mode identity mismatch",
        ));
    }
    Ok(RegexAutomataModeExecution {
        mode_id: mode.id.clone(),
        harness: mode.harness,
        default_features: mode.default_features,
        all_features: mode.all_features,
        features: mode.features.clone(),
        dependency_package: "regex-automata".to_owned(),
        dependency_version: "0.4.14".to_owned(),
        mode_evidence_sha256: None,
    })
}

fn same_adapter_function(left: AdapterFunction, right: AdapterFunction) -> bool {
    std::ptr::fn_addr_eq(left, right)
}

fn adapter_observer_id(adapter: &RegisteredAdapter) -> Result<&'static str, InventoryError> {
    let observer = if adapter.case_id == PATTERN_LEN_CASE
        && same_adapter_function(adapter.run, run_pattern_len_never_match)
    {
        "run-pattern-len-never-match-v1"
    } else if adapter.case_id == PATTERN_LEN_MANY_CASE
        && same_adapter_function(adapter.run, run_pattern_len_many)
    {
        "run-pattern-len-many-v1"
    } else if adapter.case_id == IS_SPECIAL_STATE_CASE
        && same_adapter_function(adapter.run, run_is_special_state)
    {
        "run-is-special-state-v1"
    } else if adapter.case_id == IS_START_STATE_CASE
        && same_adapter_function(adapter.run, run_is_start_state)
    {
        "run-is-start-state-v1"
    } else if adapter.case_id == MATCH_LEN_CASE && same_adapter_function(adapter.run, run_match_len)
    {
        "run-match-len-v1"
    } else if adapter.case_id == PATTERN_LEN_ALWAYS_CASE
        && same_adapter_function(adapter.run, run_pattern_len_always)
    {
        "run-pattern-len-always-v1"
    } else if adapter.case_id == TRY_SEARCH_OVERLAPPING_FWD_CASE
        && same_adapter_function(adapter.run, run_try_search_overlapping_fwd)
    {
        "run-try-search-overlapping-fwd-v1"
    } else if adapter.case_id == TRY_SEARCH_FWD_CASE
        && same_adapter_function(adapter.run, run_try_search_fwd)
    {
        "run-try-search-fwd-v1"
    } else if adapter.case_id == TRY_SEARCH_FWD_BOUNDS_CASE
        && same_adapter_function(adapter.run, run_try_search_fwd_bounds)
    {
        "run-try-search-fwd-bounds-v1"
    } else if adapter.case_id == LOOK_END_LINE_CASE
        && same_adapter_function(adapter.run, run_look_end_line)
    {
        "run-look-end-line-k0-v1"
    } else if adapter.case_id == LOOK_END_TEXT_CASE
        && same_adapter_function(adapter.run, run_look_end_text)
    {
        "run-look-end-text-k0-v1"
    } else if adapter.case_id == LOOK_START_LINE_CASE
        && same_adapter_function(adapter.run, run_look_start_line)
    {
        "run-look-start-line-k0-v1"
    } else if adapter.case_id == LOOK_START_TEXT_CASE
        && same_adapter_function(adapter.run, run_look_start_text)
    {
        "run-look-start-text-k0-v1"
    } else {
        return Err(InventoryError::new(
            "regex-automata adapter observer binding mismatch",
        ));
    };
    Ok(observer)
}

fn reviewed_adapter(case_id: &str) -> Option<RegisteredAdapter> {
    match case_id {
        PATTERN_LEN_CASE => Some(PATTERN_LEN_ADAPTER),
        PATTERN_LEN_MANY_CASE => Some(PATTERN_LEN_MANY_ADAPTER),
        IS_SPECIAL_STATE_CASE => Some(IS_SPECIAL_STATE_ADAPTER),
        IS_START_STATE_CASE => Some(IS_START_STATE_ADAPTER),
        MATCH_LEN_CASE => Some(MATCH_LEN_ADAPTER),
        PATTERN_LEN_ALWAYS_CASE => Some(PATTERN_LEN_ALWAYS_ADAPTER),
        TRY_SEARCH_OVERLAPPING_FWD_CASE => Some(TRY_SEARCH_OVERLAPPING_FWD_ADAPTER),
        TRY_SEARCH_FWD_CASE => Some(TRY_SEARCH_FWD_ADAPTER),
        TRY_SEARCH_FWD_BOUNDS_CASE => Some(TRY_SEARCH_FWD_BOUNDS_ADAPTER),
        LOOK_END_LINE_CASE => Some(LOOK_END_LINE_ADAPTER),
        LOOK_END_TEXT_CASE => Some(LOOK_END_TEXT_ADAPTER),
        LOOK_START_LINE_CASE => Some(LOOK_START_LINE_ADAPTER),
        LOOK_START_TEXT_CASE => Some(LOOK_START_TEXT_ADAPTER),
        _ => None,
    }
}

fn registry_manifest_sha256(registry: &[RegisteredAdapter]) -> Result<String, InventoryError> {
    let manifest = registry
        .iter()
        .map(|adapter| {
            Ok(RegistryManifestEntry {
                mode_id: adapter.mode_id,
                harness: adapter.harness,
                case_id: adapter.case_id,
                source: source_contract(&adapter.source),
                observer_id: adapter_observer_id(adapter)?,
            })
        })
        .collect::<Result<Vec<_>, InventoryError>>()?;
    hash_json(&manifest, "encode regex-automata registry manifest")
}

fn validate_predecessor_registry_manifest(
    registry: &[RegisteredAdapter],
) -> Result<(), InventoryError> {
    let observed = registry_manifest_sha256(registry)?;
    if observed != PREDECESSOR_REGISTRY_MANIFEST_SHA256 {
        return Err(InventoryError::new(format!(
            "regex-automata predecessor registry manifest mismatch: {observed}",
        )));
    }
    Ok(())
}

fn validate_registered_adapter(
    inventory: &RegexAutomataCorpusReport,
    adapter: &RegisteredAdapter,
) -> Result<(), InventoryError> {
    let expected = reviewed_adapter(adapter.case_id)
        .ok_or_else(|| InventoryError::new("regex-automata adapter has an unreviewed case"))?;
    if adapter.mode_id != expected.mode_id
        || adapter.harness != expected.harness
        || adapter.source != expected.source
        || !same_adapter_function(adapter.run, expected.run)
    {
        return Err(InventoryError::new(
            "regex-automata adapter registration binding mismatch",
        ));
    }
    let _ = adapter_observer_id(adapter)?;
    let _ = mode_execution(inventory, adapter.mode_id)?;
    let file = inventory
        .payload
        .source
        .files
        .iter()
        .find(|file| file.path == adapter.source.source_path)
        .ok_or_else(|| InventoryError::new("adapter upstream source file is absent"))?;
    if file.sha256 != adapter.source.source_sha256 || file.mode != "0644" {
        return Err(InventoryError::new(
            "adapter upstream source file identity mismatch",
        ));
    }
    validate_source_spec(&adapter.source)?;
    if adapter.case_id == TRY_SEARCH_FWD_BOUNDS_CASE {
        validate_try_search_fwd_bounds_vector(&adapter.source, TRY_SEARCH_FWD_BOUNDS_VECTOR)?;
    } else if let Some(case) = reviewed_look_case(adapter.case_id) {
        validate_look_fixture()?;
        validate_look_case_spec(case)?;
    }
    Ok(())
}

fn validate_try_search_fwd_bounds_vector(
    source: &SourceContractSpec,
    vector: TrySearchFwdBoundsVector,
) -> Result<(), InventoryError> {
    if source != &TRY_SEARCH_FWD_BOUNDS_SOURCE
        || vector.pattern.is_empty()
        || vector.pattern.contains(['"', '\n', '\r', '\0'])
        || vector.haystack.is_empty()
        || !vector
            .haystack
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric())
        || vector.range_start >= vector.range_end
        || vector.range_end > vector.haystack.len()
    {
        return Err(InventoryError::new(
            "try-search-fwd bounds vector is structurally invalid",
        ));
    }
    let relative_end = vector
        .range_end
        .checked_sub(vector.range_start)
        .ok_or_else(|| InventoryError::new("try-search-fwd bounds vector underflow"))?;
    let required_lines = [
        format!(
            "    /// let dfa = dense::DFA::new(r\"{}\")?;\n",
            vector.pattern,
        ),
        format!(
            "    /// let haystack = \"{}\".as_bytes();\n",
            vector.haystack,
        ),
        format!(
            "    /// let input = Input::new(&haystack[{}..{}]);\n",
            vector.range_start, vector.range_end,
        ),
        format!("    /// let expected = Some(HalfMatch::must(0, {relative_end}));\n",),
        format!(
            "    /// let input = Input::new(haystack).range({}..{});\n",
            vector.range_start, vector.range_end,
        ),
        "    /// let expected = None;\n".to_owned(),
    ];
    if required_lines
        .iter()
        .any(|line| source.source_span.matches(line).count() != 1)
    {
        return Err(InventoryError::new(
            "try-search-fwd bounds vector is not bound to the upstream span",
        ));
    }
    Ok(())
}

fn reviewed_look_case(case_id: &str) -> Option<LookCaseSpec> {
    LOOK_CASES
        .iter()
        .find(|case| case.case_id == case_id)
        .copied()
}

fn validate_look_fixture() -> Result<(), InventoryError> {
    validate_look_fixture_parts(
        LOOK_FULL_SOURCE_SPAN,
        LOOK_CASES,
        LOOK_TARGET_IDENTITIES_SHA256,
    )
}

fn all_mode_look_identities(
    inventory: &RegexAutomataCorpusReport,
) -> Result<BTreeSet<(String, RegexAutomataHarnessKind, String)>, InventoryError> {
    validate_look_fixture()?;
    let case_ids = LOOK_CASES
        .iter()
        .map(|case| case.case_id)
        .collect::<BTreeSet<_>>();
    let obligation_identities = inventory
        .payload
        .obligations
        .iter()
        .map(|obligation| {
            (
                obligation.mode_id.as_str(),
                obligation.harness,
                obligation.case_id.as_str(),
            )
        })
        .collect::<BTreeSet<_>>();
    let unit_modes = inventory
        .payload
        .modes
        .iter()
        .filter(|mode| {
            mode.harness == RegexAutomataHarnessKind::Unit
                && case_ids.iter().all(|case_id| {
                    obligation_identities.contains(&(
                        mode.id.as_str(),
                        RegexAutomataHarnessKind::Unit,
                        *case_id,
                    ))
                })
        })
        .collect::<Vec<_>>();
    if unit_modes.len() != 30 {
        return Err(InventoryError::new(
            "regex-automata look unit-mode denominator mismatch",
        ));
    }
    let identities = unit_modes
        .iter()
        .flat_map(|mode| {
            LOOK_CASES.iter().map(|case| {
                (
                    mode.id.clone(),
                    RegexAutomataHarnessKind::Unit,
                    case.case_id.to_owned(),
                )
            })
        })
        .collect::<BTreeSet<_>>();
    let mut canonical = String::new();
    for (mode_id, harness, case_id) in &identities {
        if *harness != RegexAutomataHarnessKind::Unit {
            return Err(InventoryError::new(
                "regex-automata look target contains a non-unit membership",
            ));
        }
        canonical.push_str(mode_id);
        canonical.push_str("\tunit\t");
        canonical.push_str(case_id);
        canonical.push('\n');
    }
    if identities.len() != 120
        || sha256(canonical.as_bytes()) != LOOK_ALL_MODE_TARGET_IDENTITIES_SHA256
    {
        return Err(InventoryError::new(
            "regex-automata all-mode look target seal mismatch",
        ));
    }
    Ok(identities)
}

fn new_mode_look_identities(
    inventory: &RegexAutomataCorpusReport,
) -> Result<BTreeSet<(String, RegexAutomataHarnessKind, String)>, InventoryError> {
    let identities = all_mode_look_identities(inventory)?
        .into_iter()
        .filter(|(mode_id, _, _)| mode_id != COMPILED_UNIT_MODE_ID)
        .collect::<BTreeSet<_>>();
    let mut canonical = String::new();
    for (mode_id, _, case_id) in &identities {
        canonical.push_str(mode_id);
        canonical.push_str("\tunit\t");
        canonical.push_str(case_id);
        canonical.push('\n');
    }
    if identities.len() != 116
        || sha256(canonical.as_bytes()) != LOOK_ALL_MODE_NEW_IDENTITIES_SHA256
    {
        return Err(InventoryError::new(
            "regex-automata new-mode look target seal mismatch",
        ));
    }
    Ok(identities)
}

fn validate_all_mode_transition_seals(
    report: &RegexAutomataAdapterReport,
    assigned: &BTreeSet<(String, RegexAutomataHarnessKind, String)>,
) -> Result<(), InventoryError> {
    let mut unsupported = Vec::new();
    let mut unchanged = Vec::new();
    for receipt in &report.payload.receipts {
        let identity = (
            receipt.mode_id.clone(),
            receipt.harness,
            receipt.case_id.clone(),
        );
        if !assigned.contains(&identity) {
            unchanged.push(format!(
                "{}\t{}\t{}\n",
                receipt.mode_id,
                harness_name(receipt.harness),
                receipt.case_id,
            ));
        }
        if let RegexAutomataAdapterDisposition::Unsupported { reason_code } = &receipt.disposition {
            unsupported.push(format!(
                "{}\t{}\t{}\tunsupported\t{}\n",
                receipt.mode_id,
                harness_name(receipt.harness),
                receipt.case_id,
                reason_code,
            ));
        }
    }
    unsupported.sort_unstable();
    unchanged.sort_unstable();
    if unsupported.len() != 3_713
        || sha256(unsupported.concat().as_bytes()) != LOOK_ALL_MODE_FINAL_UNSUPPORTED_SHA256
        || unchanged.len() != 3_726
        || sha256(unchanged.concat().as_bytes()) != LOOK_ALL_MODE_UNCHANGED_IDENTITIES_SHA256
    {
        return Err(InventoryError::new(
            "regex-automata all-mode final disposition seal mismatch",
        ));
    }
    Ok(())
}

const fn harness_name(harness: RegexAutomataHarnessKind) -> &'static str {
    match harness {
        RegexAutomataHarnessKind::Unit => "unit",
        RegexAutomataHarnessKind::Integration => "integration",
        RegexAutomataHarnessKind::Doctest => "doctest",
    }
}

fn validate_look_fixture_parts(
    full_span: &str,
    cases: &[LookCaseSpec],
    target_identities_sha256: &str,
) -> Result<(), InventoryError> {
    if full_span.len() != 1_955
        || full_span.split_inclusive('\n').count() != 68
        || !full_span.ends_with('\n')
        || full_span.contains(['\0', '\r'])
        || sha256(full_span.as_bytes()) != LOOK_FULL_SPAN_SHA256
        || cases.len() != 4
    {
        return Err(InventoryError::new(
            "look upstream fixture identity mismatch",
        ));
    }
    let mut target_identities = String::new();
    for case in cases {
        target_identities.push_str(COMPILED_UNIT_MODE_ID);
        target_identities.push_str("\tunit\t");
        target_identities.push_str(case.case_id);
        target_identities.push('\n');
    }
    if target_identities != LOOK_TARGET_IDENTITIES
        || sha256(target_identities.as_bytes()) != target_identities_sha256
        || target_identities_sha256 != LOOK_TARGET_IDENTITIES_SHA256
    {
        return Err(InventoryError::new("look target identity seal mismatch"));
    }

    let lines = full_span.split_inclusive('\n').collect::<Vec<_>>();
    let mut assertion_lines = BTreeSet::new();
    for case in cases {
        validate_look_case_spec(*case)?;
        let start = case
            .source
            .span_start_line
            .checked_sub(1700)
            .ok_or_else(|| InventoryError::new("look source span starts before fixture"))?;
        let end = case
            .source
            .span_end_line
            .checked_sub(1700)
            .and_then(|offset| offset.checked_add(1))
            .ok_or_else(|| InventoryError::new("look source span end overflow"))?;
        let observed = lines
            .get(start..end)
            .ok_or_else(|| InventoryError::new("look source span exceeds fixture"))?
            .concat();
        if observed != case.source.source_span {
            return Err(InventoryError::new("look case span is not in full fixture"));
        }
        for assertion in case.source.assertions {
            if !assertion_lines.insert(assertion.source_line) {
                return Err(InventoryError::new("duplicate look assertion source line"));
            }
        }
    }
    let discovered = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.contains("assert"))
        .map(|(offset, _)| {
            1_700_usize
                .checked_add(offset)
                .ok_or_else(|| InventoryError::new("look assertion source line overflow"))
        })
        .collect::<Result<BTreeSet<_>, InventoryError>>()?;
    if discovered.len() != 32 || assertion_lines != discovered {
        return Err(InventoryError::new(
            "look fixture assertion partition is incomplete",
        ));
    }
    Ok(())
}

fn validate_look_case_spec(case: LookCaseSpec) -> Result<(), InventoryError> {
    let expected = reviewed_look_case(case.case_id)
        .ok_or_else(|| InventoryError::new("unreviewed look case"))?;
    let expected_binding = match case.kind {
        LookKind::StartLine => (r"(?m:^)", LOOK_START_LINE_CASE),
        LookKind::EndLine => (r"(?m:$)", LOOK_END_LINE_CASE),
        LookKind::StartText => (r"\A", LOOK_START_TEXT_CASE),
        LookKind::EndText => (r"\z", LOOK_END_TEXT_CASE),
    };
    if case != expected
        || (case.pattern, case.case_id) != expected_binding
        || case.vectors.len() != case.source.assertions.len()
        || case.vectors.is_empty()
    {
        return Err(InventoryError::new("look case binding mismatch"));
    }
    let mut assertion_ids = BTreeSet::new();
    for (vector, assertion) in case.vectors.iter().zip(case.source.assertions) {
        let source_offset = assertion
            .source_line
            .checked_sub(case.source.span_start_line)
            .ok_or_else(|| InventoryError::new("look assertion precedes its source span"))?;
        let source_line = case
            .source
            .source_span
            .split_inclusive('\n')
            .nth(source_offset)
            .ok_or_else(|| InventoryError::new("look assertion exceeds its source span"))?;
        if vector.assertion_id != assertion.assertion_id
            || vector.at > vector.haystack.len()
            || assertion.expected_observation != format!("bool:{}", vector.expected)
            || source_line != render_look_assertion(vector)?
            || !assertion_ids.insert(vector.assertion_id)
        {
            return Err(InventoryError::new("look assertion vector mismatch"));
        }
    }
    Ok(())
}

fn render_look_assertion(vector: &LookAssertionVector) -> Result<String, InventoryError> {
    let haystack = match vector.haystack {
        "" => r#""""#,
        "\n" => r#""\n""#,
        "a" => r#""a""#,
        "\na" => r#""\na""#,
        "a\na" => r#""a\na""#,
        _ => return Err(InventoryError::new("unreviewed look assertion haystack")),
    };
    let negation = if vector.expected { "" } else { "!" };
    Ok(format!(
        "        assert!({negation}testlook!(look, {haystack}, {}));\n",
        vector.at,
    ))
}

fn validate_source_spec(source: &SourceContractSpec) -> Result<(), InventoryError> {
    let authenticated_source = matches!(
        (source.source_path, source.source_sha256),
        (AUTOMATON_SOURCE_PATH, AUTOMATON_SOURCE_SHA256)
            | (LOOK_SOURCE_PATH, LOOK_SOURCE_SHA256)
            | (start_map::SOURCE_PATH, start_map::SOURCE_SHA256)
            | (REGEX_SOURCE_PATH, REGEX_SOURCE_SHA256)
    );
    if !authenticated_source
        || source.span_start_line == 0
        || source.span_end_line < source.span_start_line
        || !source.source_span.ends_with('\n')
        || source.source_span.contains(['\0', '\r'])
        || sha256(source.source_span.as_bytes()) != source.source_span_sha256
        || !hex(source.source_span_sha256, 64)
        || !hex(source.assertion_inventory_sha256, 64)
        || source.assertions.is_empty()
    {
        return Err(InventoryError::new(
            "regex-automata upstream source-span contract mismatch",
        ));
    }
    let expected_lines = source
        .span_end_line
        .checked_sub(source.span_start_line)
        .and_then(|lines| lines.checked_add(1))
        .ok_or_else(|| InventoryError::new("regex-automata source-span line overflow"))?;
    let lines = source.source_span.split_inclusive('\n').collect::<Vec<_>>();
    if lines.len() != expected_lines {
        return Err(InventoryError::new(
            "regex-automata upstream source-span line count mismatch",
        ));
    }
    let mut discovered = Vec::new();
    for (offset, line) in lines.iter().enumerate() {
        let source_line = source
            .span_start_line
            .checked_add(offset)
            .ok_or_else(|| InventoryError::new("regex-automata source line overflow"))?;
        if line.contains("assert") {
            discovered.push((source_line, sha256(line.as_bytes())));
        }
    }
    if discovered.len() != source.assertions.len() {
        return Err(InventoryError::new(
            "regex-automata upstream assertion inventory is incomplete",
        ));
    }
    let assertions = source_contract(source).assertions;
    if hash_json(&assertions, "encode upstream assertion inventory")?
        != source.assertion_inventory_sha256
    {
        return Err(InventoryError::new(
            "regex-automata upstream assertion inventory seal mismatch",
        ));
    }
    for ((line, line_sha256), assertion) in discovered.iter().zip(source.assertions) {
        if *line != assertion.source_line
            || line_sha256 != assertion.source_line_sha256
            || !token(assertion.assertion_id)
            || !bounded_text(assertion.expected_observation, 256)
        {
            return Err(InventoryError::new(
                "regex-automata upstream assertion binding mismatch",
            ));
        }
    }
    Ok(())
}

fn source_contract(source: &SourceContractSpec) -> RegexAutomataSourceContract {
    RegexAutomataSourceContract {
        source_path: source.source_path.to_owned(),
        source_sha256: source.source_sha256.to_owned(),
        span_start_line: source.span_start_line,
        span_end_line: source.span_end_line,
        source_span_sha256: source.source_span_sha256.to_owned(),
        assertion_inventory_sha256: source.assertion_inventory_sha256.to_owned(),
        assertions: source
            .assertions
            .iter()
            .map(|assertion| RegexAutomataAssertionContract {
                assertion_id: assertion.assertion_id.to_owned(),
                source_line: assertion.source_line,
                source_line_sha256: assertion.source_line_sha256.to_owned(),
                expected_observation: assertion.expected_observation.to_owned(),
            })
            .collect(),
    }
}

fn execute_adapter(
    adapter: &RegisteredAdapter,
    mode: &RegexAutomataModeExecution,
) -> Result<RegexAutomataExecutionReceipt, String> {
    if adapter.mode_id != mode.mode_id || adapter.harness != mode.harness {
        return Err("adapter-mode-binding-mismatch".to_owned());
    }
    let assertion_executions = (adapter.run)(&AdapterContext { mode })?;
    validate_assertion_executions(adapter.source.assertions, &assertion_executions)?;
    Ok(RegexAutomataExecutionReceipt {
        mode: mode.clone(),
        harness: adapter.harness,
        case_id: adapter.case_id.to_owned(),
        source: source_contract(&adapter.source),
        assertion_executions,
    })
}

fn validate_assertion_executions(
    expected: &[AssertionSpec],
    actual: &[RegexAutomataAssertionExecution],
) -> Result<(), String> {
    if actual.len() != expected.len() {
        return Err("assertion-execution-count-mismatch".to_owned());
    }
    for (expected, actual) in expected.iter().zip(actual) {
        if actual.assertion_id != expected.assertion_id
            || !bounded_text(&actual.upstream_observation, 256)
            || !bounded_text(&actual.fre_observation, 256)
            || actual.upstream_observation != expected.expected_observation
            || actual.fre_observation != expected.expected_observation
        {
            return Err("assertion-execution-binding-mismatch".to_owned());
        }
    }
    Ok(())
}

fn report_registry(schema: &str) -> Result<&'static [RegisteredAdapter], InventoryError> {
    match schema {
        PREVIOUS_REGEX_AUTOMATA_ADAPTER_REPORT_SCHEMA => Ok(PREDECESSOR_REGISTERED_ADAPTERS),
        REGEX_AUTOMATA_ADAPTER_REPORT_SCHEMA => Ok(REGISTERED_ADAPTERS),
        _ => Err(InventoryError::new(
            "regex-automata report schema has no execution registry",
        )),
    }
}

fn validate_execution_receipt_set(
    inventory: &RegexAutomataCorpusReport,
    report: &RegexAutomataAdapterReport,
    registry: &[RegisteredAdapter],
) -> Result<(), InventoryError> {
    let mut executions = BTreeMap::new();
    for execution in &report.payload.execution_receipts {
        let key = (
            execution.mode.mode_id.clone(),
            execution.harness,
            execution.case_id.clone(),
        );
        let adapter = registry
            .iter()
            .find(|adapter| {
                (adapter.mode_id, adapter.harness, adapter.case_id)
                    == (key.0.as_str(), key.1, key.2.as_str())
            })
            .ok_or_else(|| InventoryError::new("foreign regex-automata execution receipt"))?;
        validate_registered_adapter(inventory, adapter)?;
        let expected_mode = mode_execution(inventory, adapter.mode_id)?;
        if execution.mode != expected_mode
            || execution.harness != adapter.harness
            || execution.case_id != adapter.case_id
            || execution.source != source_contract(&adapter.source)
            || validate_assertion_executions(
                adapter.source.assertions,
                &execution.assertion_executions,
            )
            .is_err()
            || executions
                .insert(
                    key,
                    hash_json(execution, "encode regex-automata execution receipt")?,
                )
                .is_some()
        {
            return Err(InventoryError::new(
                "invalid or duplicate regex-automata execution receipt",
            ));
        }
    }
    let mut passed = 0_usize;
    for receipt in &report.payload.receipts {
        let key = (
            receipt.mode_id.clone(),
            receipt.harness,
            receipt.case_id.clone(),
        );
        match &receipt.disposition {
            RegexAutomataAdapterDisposition::Pass { evidence_sha256 } => {
                passed = passed
                    .checked_add(1)
                    .ok_or_else(|| InventoryError::new("regex-automata pass count overflow"))?;
                if executions.get(&key) != Some(evidence_sha256) {
                    return Err(InventoryError::new(
                        "regex-automata pass lacks its exact execution receipt",
                    ));
                }
            }
            RegexAutomataAdapterDisposition::Unsupported { .. }
            | RegexAutomataAdapterDisposition::Fault { .. } => {
                if executions.contains_key(&key) {
                    return Err(InventoryError::new(
                        "non-pass regex-automata membership has execution evidence",
                    ));
                }
            }
        }
    }
    if passed != executions.len() {
        return Err(InventoryError::new(
            "regex-automata execution receipt cardinality mismatch",
        ));
    }
    Ok(())
}

fn adapter_counts(receipts: &[RegexAutomataAdapterReceipt]) -> RegexAutomataAdapterCounts {
    RegexAutomataAdapterCounts {
        pass: receipts
            .iter()
            .filter(|receipt| {
                matches!(
                    receipt.disposition,
                    RegexAutomataAdapterDisposition::Pass { .. }
                )
            })
            .count(),
        unsupported: receipts
            .iter()
            .filter(|receipt| {
                matches!(
                    receipt.disposition,
                    RegexAutomataAdapterDisposition::Unsupported { .. }
                )
            })
            .count(),
        fault: receipts
            .iter()
            .filter(|receipt| {
                matches!(
                    receipt.disposition,
                    RegexAutomataAdapterDisposition::Fault { .. }
                )
            })
            .count(),
        total: receipts.len(),
    }
}

fn validate_disposition(
    disposition: &RegexAutomataAdapterDisposition,
) -> Result<(), InventoryError> {
    match disposition {
        RegexAutomataAdapterDisposition::Pass { evidence_sha256 } => {
            if !hex(evidence_sha256, 64) {
                return Err(InventoryError::new("invalid regex-automata pass evidence"));
            }
        }
        RegexAutomataAdapterDisposition::Unsupported { reason_code } => {
            if reason_code != INVENTORY_UNSUPPORTED_REASON {
                return Err(InventoryError::new(
                    "invalid regex-automata unsupported reason",
                ));
            }
        }
        RegexAutomataAdapterDisposition::Fault { stage, reason_code } => {
            if !token(stage) || !token(reason_code) {
                return Err(InventoryError::new("invalid regex-automata fault"));
            }
        }
    }
    Ok(())
}

fn validate_candidate(candidate: &CandidateIdentity) -> Result<(), InventoryError> {
    if !hex(&candidate.revision, 40)
        || !hex(&candidate.tree, 40)
        || !candidate.tracked_and_untracked_worktree_clean
    {
        return Err(InventoryError::new(
            "invalid regex-automata candidate identity",
        ));
    }
    Ok(())
}

#[derive(Serialize)]
struct LegacyAdapterPayload<'a> {
    inventory_payload_sha256: &'a str,
    obligation_inventory_sha256: &'a str,
    candidate: &'a CandidateIdentity,
    counts: &'a RegexAutomataAdapterCounts,
    receipts: &'a [RegexAutomataAdapterReceipt],
    limitations: &'a [String],
}

#[derive(Serialize)]
struct AdapterReportEnvelope<'a> {
    schema: &'a str,
    payload_sha256: &'a str,
    payload: AdapterPayloadEnvelope<'a>,
}

#[derive(Serialize)]
struct AdapterPayloadEnvelope<'a> {
    inventory_payload_sha256: &'a str,
    obligation_inventory_sha256: &'a str,
    candidate: &'a CandidateIdentity,
    counts: &'a RegexAutomataAdapterCounts,
    receipts: &'a [RegexAutomataAdapterReceipt],
    execution_receipts: &'a [RegexAutomataExecutionReceipt],
    limitations: &'a [String],
}

fn validate_adapter_report_size_contract(
    report: &RegexAutomataAdapterReport,
) -> Result<(), InventoryError> {
    let envelope = AdapterReportEnvelope {
        schema: &report.schema,
        payload_sha256: &report.payload_sha256,
        payload: AdapterPayloadEnvelope {
            inventory_payload_sha256: &report.payload.inventory_payload_sha256,
            obligation_inventory_sha256: &report.payload.obligation_inventory_sha256,
            candidate: &report.payload.candidate,
            counts: &report.payload.counts,
            receipts: &report.payload.receipts,
            execution_receipts: &report.payload.execution_receipts,
            limitations: &report.payload.limitations,
        },
    };
    let envelope_bytes = serde_json::to_vec(&envelope)
        .map_err(|error| InventoryError::new(format!("encode adapter envelope: {error}")))?;
    require_file_size(
        envelope_bytes.len(),
        REGEX_AUTOMATA_PROGRESS_MAX_FILE_BYTES,
        "regex-automata adapter envelope",
    )?;
    let report_bytes = serde_json::to_vec(report)
        .map_err(|error| InventoryError::new(format!("encode adapter report: {error}")))?;
    require_file_size(
        report_bytes.len(),
        REGEX_AUTOMATA_ADAPTER_REPORT_MAX_FILE_BYTES,
        "regex-automata adapter report",
    )
}

fn normalized_reason(reason: &str) -> String {
    let normalized = reason
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || byte == b'-' {
                char::from(byte.to_ascii_lowercase())
            } else {
                '-'
            }
        })
        .collect::<String>();
    let normalized = normalized.trim_matches('-');
    if token(normalized) {
        normalized.to_owned()
    } else {
        "adapter-error".to_owned()
    }
}

fn bounded_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value.contains('\0')
        && !value.contains('\r')
        && value
            .chars()
            .all(|character| character == '\n' || !character.is_control())
}

fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hash_json(value: &impl Serialize, context: &str) -> Result<String, InventoryError> {
    serde_json::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| InventoryError::new(format!("{context}: {error}")))
}

fn require_file_size(
    json_bytes: usize,
    maximum_file_bytes: usize,
    label: &str,
) -> Result<(), InventoryError> {
    if json_bytes
        .checked_add(1)
        .is_none_or(|file_bytes| file_bytes > maximum_file_bytes)
    {
        return Err(InventoryError::new(format!(
            "{label} exceeds its maximum file size",
        )));
    }
    Ok(())
}

fn read_owned_regular(
    path: &Path,
    maximum_file_bytes: usize,
    label: &str,
) -> Result<Vec<u8>, InventoryError> {
    let maximum_u64 = u64::try_from(maximum_file_bytes)
        .map_err(|_| InventoryError::new(format!("{label} size limit does not fit u64")))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| InventoryError::new(format!("stat {}: {error}", path.display())))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.uid() != unsafe_free_euid()
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > maximum_u64
    {
        return Err(InventoryError::new(format!("unsafe {label}")));
    }
    let mut input = fs::File::open(path)
        .map_err(|error| InventoryError::new(format!("open {}: {error}", path.display())))?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .map_err(|_| InventoryError::new(format!("{label} length does not fit usize")))?,
    );
    Read::by_ref(&mut input)
        .take(maximum_u64.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| InventoryError::new(format!("read {}: {error}", path.display())))?;
    if bytes.len() > maximum_file_bytes || u64::try_from(bytes.len()) != Ok(metadata.len()) {
        return Err(InventoryError::new(format!(
            "{label} changed while being read"
        )));
    }
    Ok(bytes)
}

fn encode_bounded_json(
    value: &impl Serialize,
    maximum_file_bytes: usize,
    pretty: bool,
    label: &str,
) -> Result<Vec<u8>, InventoryError> {
    let mut bytes = if pretty {
        serde_json::to_vec_pretty(value)
    } else {
        serde_json::to_vec(value)
    }
    .map_err(|error| InventoryError::new(format!("encode {label}: {error}")))?;
    require_file_size(bytes.len(), maximum_file_bytes, label)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn write_new_json(
    path: &Path,
    value: &impl Serialize,
    maximum_file_bytes: usize,
    pretty: bool,
    label: &str,
) -> Result<(), InventoryError> {
    let bytes = encode_bounded_json(value, maximum_file_bytes, pretty, label)?;
    if fs::symlink_metadata(path).is_ok() {
        return Err(InventoryError::new(format!(
            "output exists: {}",
            path.display()
        )));
    }
    let parent = path
        .parent()
        .ok_or_else(|| InventoryError::new("output has no parent"))?;
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|error| InventoryError::new(format!("stat {}: {error}", parent.display())))?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.file_type().is_dir()
        || parent_metadata.uid() != unsafe_free_euid()
    {
        return Err(InventoryError::new("unsafe progress output directory"));
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| InventoryError::new("invalid progress output name"))?;
    let temporary = parent.join(format!(".{name}.tmp.{}", std::process::id()));
    let mut output = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|error| InventoryError::new(format!("create output: {error}")))?;
    let result = (|| {
        output
            .write_all(&bytes)
            .map_err(|error| InventoryError::new(format!("write output: {error}")))?;
        output
            .sync_all()
            .map_err(|error| InventoryError::new(format!("sync output: {error}")))?;
        fs::hard_link(&temporary, path)
            .map_err(|error| InventoryError::new(format!("install output: {error}")))?;
        fs::remove_file(&temporary)
            .map_err(|error| InventoryError::new(format!("remove temporary: {error}")))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn unsafe_free_euid() -> u32 {
    static EUID: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *EUID.get_or_init(|| {
        std::process::Command::new("/usr/bin/id")
            .arg("-u")
            .env_clear()
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| {
                std::str::from_utf8(&output.stdout)
                    .ok()?
                    .trim()
                    .parse::<u32>()
                    .ok()
            })
            .unwrap_or(u32::MAX)
    })
}

fn gain_vectors(
    previous: &[RegexAutomataAdapterReceipt],
    current: &[RegexAutomataAdapterReceipt],
    assigned: &BTreeSet<(String, RegexAutomataHarnessKind, String)>,
) -> Result<(usize, usize), InventoryError> {
    if previous.len() != current.len() {
        return Err(InventoryError::new("strict-gain denominator changed"));
    }
    let mut unique = BTreeSet::new();
    let mut memberships = 0_usize;
    for (old, new) in previous.iter().zip(current) {
        if (old.mode_id.as_str(), old.harness, old.case_id.as_str())
            != (new.mode_id.as_str(), new.harness, new.case_id.as_str())
        {
            return Err(InventoryError::new("strict-gain receipt identity changed"));
        }
        let identity = (old.mode_id.clone(), old.harness, old.case_id.clone());
        let old_pass = matches!(
            old.disposition,
            RegexAutomataAdapterDisposition::Pass { .. }
        );
        let new_pass = matches!(
            new.disposition,
            RegexAutomataAdapterDisposition::Pass { .. }
        );
        if old_pass && !new_pass {
            return Err(InventoryError::new("strict-gain pass loss"));
        }
        if !assigned.contains(&identity) && old.disposition != new.disposition {
            return Err(InventoryError::new("strict-gain unassigned change"));
        }
        if assigned.contains(&identity) && !old_pass && new_pass {
            unique.insert((identity.1, identity.2));
            memberships = memberships
                .checked_add(1)
                .ok_or_else(|| InventoryError::new("strict-gain count overflow"))?;
        }
    }
    if unique.is_empty() {
        return Err(InventoryError::new("strict-gain has no assigned gain"));
    }
    Ok((unique.len(), memberships))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(revision: char, tree: char) -> CandidateIdentity {
        CandidateIdentity {
            revision: revision.to_string().repeat(40),
            tree: tree.to_string().repeat(40),
            tracked_and_untracked_worktree_clean: true,
        }
    }

    fn receipt(
        mode: &str,
        case: &str,
        disposition: RegexAutomataAdapterDisposition,
    ) -> RegexAutomataAdapterReceipt {
        RegexAutomataAdapterReceipt {
            mode_id: mode.to_owned(),
            harness: RegexAutomataHarnessKind::Unit,
            case_id: case.to_owned(),
            disposition,
        }
    }

    fn predecessor_report_fixture() -> RegexAutomataAdapterReport {
        let mode = compiled_mode();
        let execution_receipts = PREDECESSOR_REGISTERED_ADAPTERS
            .iter()
            .map(|adapter| execute_adapter(adapter, &mode).unwrap())
            .collect::<Vec<_>>();
        let evidence = execution_receipts
            .iter()
            .map(|execution| {
                (
                    execution.case_id.as_str(),
                    hash_json(execution, "encode predecessor test execution").unwrap(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let receipts = PREDECESSOR_REGISTERED_ADAPTERS
            .iter()
            .map(|adapter| RegexAutomataAdapterReceipt {
                mode_id: adapter.mode_id.to_owned(),
                harness: adapter.harness,
                case_id: adapter.case_id.to_owned(),
                disposition: RegexAutomataAdapterDisposition::Pass {
                    evidence_sha256: evidence[adapter.case_id].clone(),
                },
            })
            .collect::<Vec<_>>();
        let payload = RegexAutomataAdapterReportPayload {
            inventory_payload_sha256: "1".repeat(64),
            obligation_inventory_sha256: "2".repeat(64),
            candidate: candidate('a', 'b'),
            counts: adapter_counts(&receipts),
            receipts,
            execution_receipts,
            look_mode_matrix: None,
            start_mode_matrix: None,
            start_mode_baseline: None,
            limitations: DOCTEST_ONLY_REPORT_LIMITATIONS
                .iter()
                .map(|text| (*text).to_owned())
                .collect(),
        };
        RegexAutomataAdapterReport {
            schema: PREVIOUS_REGEX_AUTOMATA_ADAPTER_REPORT_SCHEMA.to_owned(),
            payload_sha256: hash_json(&payload, "encode predecessor test payload").unwrap(),
            payload,
        }
    }

    fn reseal_report(report: &mut RegexAutomataAdapterReport) {
        report.payload.counts = adapter_counts(&report.payload.receipts);
        report.payload_sha256 =
            hash_json(&report.payload, "re-encode adversarial test payload").unwrap();
    }

    fn authenticated_exact_036_evidence() -> (RegexAutomataCorpusReport, RegexAutomataAdapterReport)
    {
        const INVENTORY_FILE_SHA256: &str =
            "b6c4ff208f546f2b45d9a37d1f5508680d0c2a6e29c0e59df9f4b96f1dcdfbe2";
        const REPORT_FILE_SHA256: &str =
            "c6304c387772d756e8394e39faf015b6243e1e406175ea3a9871aa4eebee6910";
        let evidence = std::env::var_os("FRE_REGEX_AUTOMATA_AUTHENTICATED_EVIDENCE_DIR")
            .map(std::path::PathBuf::from)
            .expect("set FRE_REGEX_AUTOMATA_AUTHENTICATED_EVIDENCE_DIR");
        let inventory_bytes = fs::read(evidence.join("regex-automata-inventory.json")).unwrap();
        let report_bytes = fs::read(evidence.join("regex-automata.json")).unwrap();
        assert_eq!(sha256(&inventory_bytes), INVENTORY_FILE_SHA256);
        assert_eq!(sha256(&report_bytes), REPORT_FILE_SHA256);
        (
            serde_json::from_slice(&inventory_bytes).unwrap(),
            serde_json::from_slice(&report_bytes).unwrap(),
        )
    }

    fn authenticated_look_mode_matrix() -> RegexAutomataLookModeMatrix {
        let path = std::env::var_os("FRE_REGEX_AUTOMATA_LOOK_MODE_MATRIX")
            .map(std::path::PathBuf::from)
            .expect("set FRE_REGEX_AUTOMATA_LOOK_MODE_MATRIX");
        let bytes = fs::read(path).unwrap();
        let matrix: RegexAutomataLookModeMatrix = serde_json::from_slice(&bytes).unwrap();
        matrix.validate().unwrap();
        matrix
    }

    #[test]
    fn authenticated_predecessor_manifest_replays_exact_nine() {
        validate_predecessor_registry_manifest(PREDECESSOR_REGISTERED_ADAPTERS).unwrap();
        let previous = predecessor_report_fixture();
        validate_predecessor_report_authority(&previous, &previous).unwrap();
        assert_eq!(previous.payload.counts.pass, 9);
        assert_eq!(previous.payload.counts.unsupported, 0);
        assert_eq!(previous.payload.execution_receipts.len(), 9);
    }

    #[test]
    fn execution_receipts_are_a_canonical_ordered_vector() {
        let authentic = predecessor_report_fixture();
        validate_execution_receipt_order(&authentic).unwrap();
        let expected = authentic.payload.execution_receipts.clone();

        let mut reordered = authentic.clone();
        reordered.payload.execution_receipts.swap(0, 1);
        reseal_report(&mut reordered);
        assert!(validate_execution_receipt_order(&reordered).is_err());

        let restored = order_execution_receipts(
            &reordered.payload.receipts,
            reordered.payload.execution_receipts,
            "reorder test",
        )
        .unwrap();
        assert_eq!(restored, expected);
    }

    #[test]
    fn all_mode_candidate_provenance_rejects_resealed_oids_and_wrong_parents() {
        let parent = "a".repeat(40);
        let authenticated = candidate('b', 'c');
        let exact = format!("{} {parent}", authenticated.revision);
        validate_all_mode_candidate_provenance(
            &authenticated,
            &authenticated,
            &authenticated.tree,
            &exact,
            &parent,
        )
        .unwrap();

        let forged_revision = candidate('d', 'c');
        assert!(
            validate_all_mode_candidate_provenance(
                &forged_revision,
                &authenticated,
                &authenticated.tree,
                &exact,
                &parent,
            )
            .is_err(),
        );
        let forged_tree = candidate('b', 'd');
        assert!(
            validate_all_mode_candidate_provenance(
                &forged_tree,
                &authenticated,
                &authenticated.tree,
                &exact,
                &parent,
            )
            .is_err(),
        );
        assert!(
            validate_all_mode_candidate_provenance(
                &authenticated,
                &authenticated,
                &"d".repeat(40),
                &exact,
                &parent,
            )
            .is_err(),
        );
        for invalid_parents in [
            authenticated.revision.clone(),
            format!("{} {}", authenticated.revision, "e".repeat(40)),
            format!("{} {parent} {}", authenticated.revision, "f".repeat(40),),
            format!("{} malformed", authenticated.revision),
        ] {
            assert!(
                validate_all_mode_candidate_provenance(
                    &authenticated,
                    &authenticated,
                    &authenticated.tree,
                    &invalid_parents,
                    &parent,
                )
                .is_err(),
            );
        }
    }

    #[test]
    fn progress_json_size_limits_include_the_wire_newline() {
        assert_eq!(
            REGEX_AUTOMATA_ADAPTER_REPORT_MAX_FILE_BYTES,
            32 * 1_048_576 + LOOK_MODE_MATRIX_MEMBER_COMPACT_BYTES,
        );
        let value = BTreeMap::from([("key", "value")]);
        let mut expected = serde_json::to_vec_pretty(&value).unwrap();
        expected.push(b'\n');
        assert_eq!(
            encode_bounded_json(&value, expected.len(), true, "boundary test").unwrap(),
            expected,
        );
        assert!(encode_bounded_json(&value, expected.len() - 1, true, "boundary test").is_err(),);
    }

    #[test]
    fn progress_reader_and_writer_enforce_the_same_inclusive_boundary() {
        let root = std::env::temp_dir().join(format!(
            "fre-automata-progress-size-test-{}",
            std::process::id(),
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();

        let value = BTreeMap::from([("key", "value")]);
        let mut expected = serde_json::to_vec_pretty(&value).unwrap();
        expected.push(b'\n');
        let exact = root.join("exact.json");
        write_new_json(
            &exact,
            &value,
            expected.len(),
            true,
            "boundary test artifact",
        )
        .unwrap();
        assert_eq!(
            read_owned_regular(&exact, expected.len(), "boundary test artifact").unwrap(),
            expected,
        );

        let rejected = root.join("rejected.json");
        assert!(
            write_new_json(
                &rejected,
                &value,
                expected.len() - 1,
                true,
                "boundary test artifact",
            )
            .is_err(),
        );
        assert!(!rejected.exists());
        assert!(
            !root
                .join(format!(".rejected.json.tmp.{}", std::process::id(),))
                .exists(),
        );

        let oversized = root.join("oversized.json");
        fs::write(&oversized, vec![b'x'; expected.len() + 1]).unwrap();
        assert!(read_owned_regular(&oversized, expected.len(), "boundary test artifact").is_err(),);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn report_schema_selects_only_its_exact_execution_registry() {
        let previous = report_registry(PREVIOUS_REGEX_AUTOMATA_ADAPTER_REPORT_SCHEMA).unwrap();
        let current = report_registry(REGEX_AUTOMATA_ADAPTER_REPORT_SCHEMA).unwrap();
        for (observed, expected) in previous.iter().zip(PREDECESSOR_REGISTERED_ADAPTERS) {
            assert_eq!(observed.mode_id, expected.mode_id);
            assert_eq!(observed.harness, expected.harness);
            assert_eq!(observed.case_id, expected.case_id);
            assert!(same_adapter_function(observed.run, expected.run));
        }
        for (observed, expected) in current.iter().zip(REGISTERED_ADAPTERS) {
            assert_eq!(observed.mode_id, expected.mode_id);
            assert_eq!(observed.harness, expected.harness);
            assert_eq!(observed.case_id, expected.case_id);
            assert!(same_adapter_function(observed.run, expected.run));
        }
        assert_eq!(previous.len(), 9);
        assert_eq!(current.len(), 13);
        assert!(
            previous
                .iter()
                .all(|adapter| adapter.mode_id == COMPILED_MODE_ID),
        );
        assert_eq!(
            current
                .iter()
                .filter(|adapter| adapter.mode_id == COMPILED_UNIT_MODE_ID)
                .count(),
            4,
        );
        assert!(report_registry(LEGACY_REGEX_AUTOMATA_ADAPTER_REPORT_SCHEMA).is_err());
    }

    #[test]
    #[ignore = "requires the sealed exact-036 regex-automata evidence directory"]
    fn authenticated_exact_036_inventory_derives_exact_dfd_nine_pass_predecessor() {
        let (inventory, report) = authenticated_exact_036_evidence();
        assert_eq!(
            report.payload.candidate,
            CandidateIdentity {
                revision: "03651e7efa58a4ca7ee5f58a15295a51a88027a0".to_owned(),
                tree: "5d1d2633c3a6c5d555c65298039da07a775efdf2".to_owned(),
                tracked_and_untracked_worktree_clean: true,
            },
        );
        assert_eq!(
            (
                report.payload.counts.pass,
                report.payload.counts.unsupported,
                report.payload.counts.fault,
                report.payload.counts.total,
            ),
            (8, 3834, 0, 3842),
        );
        report.validate_structure(&inventory).unwrap();
        let dfd = CandidateIdentity {
            revision: LOOK_BASE_REVISION.to_owned(),
            tree: LOOK_BASE_TREE.to_owned(),
            tracked_and_untracked_worktree_clean: true,
        };
        let previous =
            build_adapter_report_with_registry(&inventory, dfd, PREDECESSOR_REGISTERED_ADAPTERS)
                .unwrap();
        validate_regex_automata_predecessor_execution(&inventory, &previous).unwrap();
        assert_eq!(
            (
                previous.payload.counts.pass,
                previous.payload.counts.unsupported,
                previous.payload.counts.fault,
                previous.payload.counts.total,
            ),
            (9, 3833, 0, 3842),
        );
        let expected = PREDECESSOR_REGISTERED_ADAPTERS
            .iter()
            .map(|adapter| (adapter.mode_id, adapter.harness, adapter.case_id))
            .collect::<BTreeSet<_>>();
        let observed = previous
            .payload
            .receipts
            .iter()
            .filter(|receipt| {
                matches!(
                    receipt.disposition,
                    RegexAutomataAdapterDisposition::Pass { .. }
                )
            })
            .map(|receipt| {
                (
                    receipt.mode_id.as_str(),
                    receipt.harness,
                    receipt.case_id.as_str(),
                )
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(observed, expected);
    }

    fn assert_exact_look_report_seals(
        previous: &RegexAutomataAdapterReport,
        current: &RegexAutomataAdapterReport,
    ) {
        assert_eq!(
            previous.payload_sha256,
            "e6e42fbb27c0f9be371c47cefcad455940b60516a0b9b188105c06b91fd3a56c",
        );
        assert_eq!(
            hash_json(previous, "encode exact nine-pass predecessor").unwrap(),
            "ca0c28984a2d5d8d15daea5302327df9b647f2f30d87dd87481ba8ffcd6a3657",
        );
        assert_eq!(
            current.payload_sha256,
            "c23a3f239ce4932835e8428f5e1ed4e5e56cdf4af544eeee1cfbabbd2d9a735c",
        );
        assert_eq!(
            hash_json(current, "encode exact thirteen-pass current report").unwrap(),
            "476d87115ac01256cc5eb20338d6725998165a12c44a20585fd90340fafffdf2",
        );
        assert_eq!(
            (&previous.payload.counts, &current.payload.counts),
            (
                &RegexAutomataAdapterCounts {
                    pass: 9,
                    unsupported: 3_833,
                    fault: 0,
                    total: 3_842,
                },
                &RegexAutomataAdapterCounts {
                    pass: 13,
                    unsupported: 3_829,
                    fault: 0,
                    total: 3_842,
                },
            ),
        );
    }

    fn assert_exact_look_receipt_delta(
        previous: &RegexAutomataAdapterReport,
        current: &RegexAutomataAdapterReport,
    ) {
        let changed = previous
            .payload
            .receipts
            .iter()
            .zip(&current.payload.receipts)
            .filter(|(old, new)| old.disposition != new.disposition)
            .map(|(_, receipt)| {
                (
                    receipt.mode_id.as_str(),
                    receipt.harness,
                    receipt.case_id.as_str(),
                )
            })
            .collect::<Vec<_>>();
        let expected_changed = LOOK_CASES
            .iter()
            .map(|case| {
                (
                    COMPILED_UNIT_MODE_ID,
                    RegexAutomataHarnessKind::Unit,
                    case.case_id,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(changed, expected_changed);
        assert_eq!(
            previous
                .payload
                .receipts
                .iter()
                .zip(&current.payload.receipts)
                .filter(|(old, new)| old.disposition == new.disposition)
                .count(),
            3_838,
        );
        let look_case_ids = LOOK_CASES
            .iter()
            .map(|case| case.case_id)
            .collect::<BTreeSet<_>>();
        let retained_other_modes = current.payload.receipts.iter().filter(|receipt| {
            look_case_ids.contains(receipt.case_id.as_str())
                && (receipt.mode_id != COMPILED_UNIT_MODE_ID
                    || receipt.harness != RegexAutomataHarnessKind::Unit)
        });
        assert_eq!(retained_other_modes.clone().count(), 116);
        assert!(retained_other_modes.clone().all(|receipt| matches!(
            receipt.disposition,
            RegexAutomataAdapterDisposition::Unsupported { .. }
        )));
        assert_eq!(
            current
                .payload
                .execution_receipts
                .iter()
                .filter(|execution| look_case_ids.contains(execution.case_id.as_str()))
                .map(|execution| execution.assertion_executions.len())
                .sum::<usize>(),
            32,
        );
    }

    #[test]
    #[ignore = "requires the sealed exact-036 regex-automata evidence directory"]
    fn authenticated_exact_dfd_look_gain_is_thirteen_with_no_other_change() {
        const IMPLEMENTATION_REVISION: &str = "57e621c95eaa93091baebf39c202209737fd04f6";
        const IMPLEMENTATION_TREE: &str = "450dd4b6c98f87dfb33365f022dfb9a788c3f96c";
        let (inventory, _) = authenticated_exact_036_evidence();
        let previous = build_adapter_report_with_registry(
            &inventory,
            CandidateIdentity {
                revision: LOOK_BASE_REVISION.to_owned(),
                tree: LOOK_BASE_TREE.to_owned(),
                tracked_and_untracked_worktree_clean: true,
            },
            PREDECESSOR_REGISTERED_ADAPTERS,
        )
        .unwrap();
        let candidate = CandidateIdentity {
            revision: IMPLEMENTATION_REVISION.to_owned(),
            tree: IMPLEMENTATION_TREE.to_owned(),
            tracked_and_untracked_worktree_clean: true,
        };
        let current = build_regex_automata_adapter_report(&inventory, candidate.clone()).unwrap();
        let duplicate = build_regex_automata_adapter_report(&inventory, candidate).unwrap();
        assert_eq!(current, duplicate);
        assert_exact_look_report_seals(&previous, &current);
        assert_exact_look_receipt_delta(&previous, &current);
        let gain =
            validate_regex_automata_look_strict_gain(&inventory, &previous, &current).unwrap();
        assert_eq!(gain.family, "unit-util");
        assert_eq!(
            (
                gain.gained_unique_cases,
                gain.gained_mode_memberships,
                gain.previous_pass,
                gain.current_pass,
            ),
            (4, 4, 9, 13),
        );

        let mut relabeled = current;
        relabeled.schema = PREVIOUS_REGEX_AUTOMATA_ADAPTER_REPORT_SCHEMA.to_owned();
        relabeled.payload.limitations = DOCTEST_ONLY_REPORT_LIMITATIONS
            .iter()
            .map(|text| (*text).to_owned())
            .collect();
        reseal_report(&mut relabeled);
        assert!(relabeled.validate_structure(&inventory).is_err());
    }

    #[test]
    #[ignore = "requires exact-036 inventory and a separately executed 30-mode matrix"]
    fn authenticated_all_mode_look_gain_is_exact_129_and_fails_closed() {
        let (inventory, _) = authenticated_exact_036_evidence();
        let previous = build_adapter_report_with_registry(
            &inventory,
            CandidateIdentity {
                revision: LOOK_ALL_MODE_PREDECESSOR_REVISION.to_owned(),
                tree: LOOK_ALL_MODE_PREDECESSOR_TREE.to_owned(),
                tracked_and_untracked_worktree_clean: true,
            },
            REGISTERED_ADAPTERS,
        )
        .unwrap();
        let matrix = authenticated_look_mode_matrix();
        let current = build_regex_automata_all_mode_look_report(
            &inventory,
            &previous,
            matrix,
            candidate('e', 'f'),
        )
        .unwrap();
        assert_eq!(
            current.payload.counts,
            RegexAutomataAdapterCounts {
                pass: 129,
                unsupported: 3_713,
                fault: 0,
                total: 3_842,
            },
        );
        validate_execution_receipt_order(&current).unwrap();
        assert_eq!(current.payload.execution_receipts.len(), 129);
        let assigned = new_mode_look_identities(&inventory).unwrap();
        validate_all_mode_transition_seals(&current, &assigned).unwrap();
        let gain = validate_regex_automata_all_mode_look_strict_gain_against_candidate(
            &inventory,
            &previous,
            &current,
            &current.payload.candidate,
        )
        .unwrap();
        assert_eq!(
            (
                gain.gained_unique_cases,
                gain.gained_mode_memberships,
                gain.previous_pass,
                gain.current_pass,
            ),
            (4, 116, 13, 129),
        );

        assert_all_mode_look_tamper_rejections(&inventory, &current, &assigned);
    }

    fn assert_all_mode_look_tamper_rejections(
        inventory: &RegexAutomataCorpusReport,
        current: &RegexAutomataAdapterReport,
        assigned: &BTreeSet<(String, RegexAutomataHarnessKind, String)>,
    ) {
        let first_target = assigned.iter().next().unwrap().clone();
        let mut reordered = current.clone();
        reordered.payload.execution_receipts.swap(0, 1);
        reseal_report(&mut reordered);
        assert!(reordered.validate(inventory).is_err());

        let mut downgraded = current.clone();
        downgraded
            .payload
            .receipts
            .iter_mut()
            .find(|receipt| {
                (
                    receipt.mode_id.as_str(),
                    receipt.harness,
                    receipt.case_id.as_str(),
                ) == (
                    first_target.0.as_str(),
                    first_target.1,
                    first_target.2.as_str(),
                )
            })
            .unwrap()
            .disposition = RegexAutomataAdapterDisposition::Unsupported {
            reason_code: INVENTORY_UNSUPPORTED_REASON.to_owned(),
        };
        downgraded.payload.execution_receipts.retain(|execution| {
            (
                execution.mode.mode_id.as_str(),
                execution.harness,
                execution.case_id.as_str(),
            ) != (
                first_target.0.as_str(),
                first_target.1,
                first_target.2.as_str(),
            )
        });
        reseal_report(&mut downgraded);
        assert!(downgraded.validate(inventory).is_err());

        let mut evidence_swap = current.clone();
        let execution = evidence_swap
            .payload
            .execution_receipts
            .iter_mut()
            .find(|execution| {
                (
                    execution.mode.mode_id.as_str(),
                    execution.harness,
                    execution.case_id.as_str(),
                ) == (
                    first_target.0.as_str(),
                    first_target.1,
                    first_target.2.as_str(),
                )
            })
            .unwrap();
        execution.mode.mode_evidence_sha256 = Some("0".repeat(64));
        reseal_report(&mut evidence_swap);
        assert!(evidence_swap.validate(inventory).is_err());

        let mut non_target = current.clone();
        let receipt = non_target
            .payload
            .receipts
            .iter_mut()
            .find(|receipt| {
                !assigned.contains(&(
                    receipt.mode_id.clone(),
                    receipt.harness,
                    receipt.case_id.clone(),
                )) && matches!(
                    receipt.disposition,
                    RegexAutomataAdapterDisposition::Unsupported { .. }
                )
            })
            .unwrap();
        receipt.disposition = RegexAutomataAdapterDisposition::Pass {
            evidence_sha256: "1".repeat(64),
        };
        reseal_report(&mut non_target);
        assert!(non_target.validate(inventory).is_err());
    }

    #[test]
    fn predecessor_authority_rejects_resealed_pass_downgrades() {
        let authentic = predecessor_report_fixture();
        for case_id in PREDECESSOR_REGISTERED_ADAPTERS
            .iter()
            .map(|adapter| adapter.case_id)
        {
            let mut downgraded = authentic.clone();
            downgraded
                .payload
                .receipts
                .iter_mut()
                .find(|receipt| receipt.case_id == case_id)
                .unwrap()
                .disposition = RegexAutomataAdapterDisposition::Unsupported {
                reason_code: INVENTORY_UNSUPPORTED_REASON.to_owned(),
            };
            downgraded
                .payload
                .execution_receipts
                .retain(|execution| execution.case_id != case_id);
            reseal_report(&mut downgraded);
            assert_eq!(
                downgraded.payload_sha256,
                hash_json(&downgraded.payload, "verify downgraded test seal").unwrap(),
            );
            assert_eq!(downgraded.payload.counts.pass, 8);
            assert!(validate_predecessor_report_authority(&downgraded, &authentic).is_err(),);
        }
    }

    #[test]
    fn predecessor_authority_rejects_registry_and_evidence_substitution() {
        let stale_three = [
            PATTERN_LEN_ADAPTER,
            PATTERN_LEN_MANY_ADAPTER,
            TRY_SEARCH_FWD_ADAPTER,
        ];
        assert!(validate_predecessor_registry_manifest(&stale_three).is_err());

        for omitted in 0..PREDECESSOR_REGISTERED_ADAPTERS.len() {
            let mut missing = PREDECESSOR_REGISTERED_ADAPTERS.to_vec();
            missing.remove(omitted);
            assert!(validate_predecessor_registry_manifest(&missing).is_err());
        }

        let mut reordered = PREDECESSOR_REGISTERED_ADAPTERS.to_vec();
        reordered.swap(0, 1);
        assert!(validate_predecessor_registry_manifest(&reordered).is_err());

        let mut foreign = PREDECESSOR_REGISTERED_ADAPTERS.to_vec();
        foreign[7] = RegisteredAdapter {
            case_id: "src/dfa/automaton.rs - foreign (line 1)",
            ..TRY_SEARCH_FWD_ADAPTER
        };
        assert!(validate_predecessor_registry_manifest(&foreign).is_err());

        let mut wrong_observer = PREDECESSOR_REGISTERED_ADAPTERS.to_vec();
        wrong_observer[0] = RegisteredAdapter {
            run: run_pattern_len_many,
            ..PATTERN_LEN_ADAPTER
        };
        assert!(validate_predecessor_registry_manifest(&wrong_observer).is_err());

        let mut current_only = PREDECESSOR_REGISTERED_ADAPTERS.to_vec();
        current_only.push(LOOK_END_LINE_ADAPTER);
        assert!(validate_predecessor_registry_manifest(&current_only).is_err());

        let authentic = predecessor_report_fixture();
        let mut altered = authentic.clone();
        let execution = &mut altered.payload.execution_receipts[0];
        execution.assertion_executions[0].fre_observation = "usize:99".to_owned();
        let changed_evidence = hash_json(execution, "encode altered test execution").unwrap();
        altered
            .payload
            .receipts
            .iter_mut()
            .find(|receipt| receipt.case_id == execution.case_id)
            .unwrap()
            .disposition = RegexAutomataAdapterDisposition::Pass {
            evidence_sha256: changed_evidence,
        };
        reseal_report(&mut altered);
        assert_eq!(
            altered.payload_sha256,
            hash_json(&altered.payload, "verify altered test seal").unwrap(),
        );
        assert!(validate_predecessor_report_authority(&altered, &authentic).is_err());
    }

    #[test]
    fn strict_gain_rejects_unassigned_change_and_pass_loss() {
        let unsupported = RegexAutomataAdapterDisposition::Unsupported {
            reason_code: INVENTORY_UNSUPPORTED_REASON.to_owned(),
        };
        let pass = RegexAutomataAdapterDisposition::Pass {
            evidence_sha256: "a".repeat(64),
        };
        let old = vec![
            receipt("m0", "dfa::a", unsupported.clone()),
            receipt("m0", "nfa::b", pass.clone()),
        ];
        let mut current = old.clone();
        current[0].disposition = pass.clone();
        let assigned = BTreeSet::from([(
            "m0".to_owned(),
            RegexAutomataHarnessKind::Unit,
            "dfa::a".to_owned(),
        )]);
        assert_eq!(gain_vectors(&old, &current, &assigned).unwrap(), (1, 1));
        let mut foreign = current.clone();
        foreign[1].disposition = unsupported.clone();
        assert!(gain_vectors(&old, &foreign, &assigned).is_err());
        let mut unassigned = old.clone();
        unassigned[1].disposition = RegexAutomataAdapterDisposition::Pass {
            evidence_sha256: "b".repeat(64),
        };
        assert!(gain_vectors(&old, &unassigned, &assigned).is_err());
    }

    #[test]
    #[ignore = "requires the sealed exact-036 regex-automata evidence directory"]
    fn authenticated_assignment_accepts_only_the_line_1267_membership() {
        const TARGETS_SHA256: &str =
            "9915623138f2f8044f42cd95c2e1e46194dcaeebdcae08a99f9677c3b1e41275";
        let (inventory, baseline) = authenticated_exact_036_evidence();

        let assignment =
            schedule_regex_automata_gap(&inventory, &baseline, "g0-doctest-dfa-line1267-51a-r1", 0)
                .unwrap();
        assert_eq!(assignment.family, "doctest-dfa");
        assert_eq!(assignment.targets.len(), 16);
        assert_eq!(
            assignment
                .targets
                .iter()
                .map(|target| target.mode_ids.len())
                .sum::<usize>(),
            24,
        );
        assert_eq!(assignment.targets_sha256, TARGETS_SHA256);
        assert_eq!(assignment.targets[14].case_id, TRY_SEARCH_FWD_BOUNDS_CASE);
        assert_eq!(
            assignment.targets[14].mode_ids,
            [COMPILED_MODE_ID, "vcs-all-features-doctest"],
        );

        let current = build_adapter_report_with_registry(
            &inventory,
            candidate('d', 'e'),
            PREDECESSOR_REGISTERED_ADAPTERS,
        )
        .unwrap();
        let changed = baseline
            .payload
            .receipts
            .iter()
            .zip(&current.payload.receipts)
            .filter(|(old, new)| old.disposition != new.disposition)
            .map(|(_, new)| (new.mode_id.as_str(), new.harness, new.case_id.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(
            changed,
            [(
                COMPILED_MODE_ID,
                RegexAutomataHarnessKind::Doctest,
                TRY_SEARCH_FWD_BOUNDS_CASE,
            )],
        );
        assert_eq!(
            (
                baseline.payload.counts.pass,
                baseline.payload.counts.unsupported,
                baseline.payload.counts.fault,
                baseline.payload.counts.total,
            ),
            (8, 3834, 0, 3842),
        );
        assert_eq!(
            (
                current.payload.counts.pass,
                current.payload.counts.unsupported,
                current.payload.counts.fault,
                current.payload.counts.total,
            ),
            (9, 3833, 0, 3842),
        );
        assert!(
            PREDECESSOR_REGISTERED_ADAPTERS
                .iter()
                .any(|adapter| adapter.case_id == TRY_SEARCH_FWD_BOUNDS_CASE),
        );
        let assigned = assignment
            .targets
            .iter()
            .flat_map(|target| {
                target
                    .mode_ids
                    .iter()
                    .map(|mode_id| (mode_id.clone(), target.harness, target.case_id.clone()))
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            gain_vectors(
                &baseline.payload.receipts,
                &current.payload.receipts,
                &assigned,
            )
            .unwrap(),
            (1, 1),
        );
    }

    #[test]
    fn scheduler_family_and_case_memberships_are_deterministic() {
        assert_eq!(
            case_family(RegexAutomataHarnessKind::Unit, "dfa::dense::roundtrip").unwrap(),
            "unit-dfa",
        );
        assert_eq!(
            case_family(
                RegexAutomataHarnessKind::Doctest,
                "src/meta/regex.rs - meta::Regex (line 10)",
            )
            .unwrap(),
            "doctest-meta",
        );
        assert_eq!(
            case_family(RegexAutomataHarnessKind::Doctest, "src/lib.rs - (line 124)").unwrap(),
            "doctest-lib",
        );
        assert!(case_family(RegexAutomataHarnessKind::Unit, "bad family::x").is_err());
        assert!(validate_candidate(&candidate('a', 'b')).is_ok());
        assert!(validate_candidate(&candidate('g', 'b')).is_err());
    }

    fn compiled_mode() -> RegexAutomataModeExecution {
        RegexAutomataModeExecution {
            mode_id: COMPILED_MODE_ID.to_owned(),
            harness: RegexAutomataHarnessKind::Doctest,
            default_features: true,
            all_features: false,
            features: Vec::new(),
            dependency_package: "regex-automata".to_owned(),
            dependency_version: "0.4.14".to_owned(),
            mode_evidence_sha256: None,
        }
    }

    fn compiled_unit_mode() -> RegexAutomataModeExecution {
        RegexAutomataModeExecution {
            mode_id: COMPILED_UNIT_MODE_ID.to_owned(),
            harness: RegexAutomataHarnessKind::Unit,
            default_features: true,
            all_features: false,
            features: Vec::new(),
            dependency_package: "regex-automata".to_owned(),
            dependency_version: "0.4.14".to_owned(),
            mode_evidence_sha256: None,
        }
    }

    fn wrong_pattern_len(
        context: &AdapterContext<'_>,
    ) -> Result<Vec<RegexAutomataAssertionExecution>, String> {
        require_compiled_mode(context)?;
        let upstream = dense::Builder::new()
            .build_many(&["a", "b"])
            .map_err(|error| error.to_string())?;
        let fre = PortableRegexSet::new(["a", "b"]).map_err(|error| error.to_string())?;
        Ok(vec![RegexAutomataAssertionExecution {
            assertion_id: PATTERN_LEN_ASSERTIONS[0].assertion_id.to_owned(),
            upstream_observation: format!("usize:{}", upstream.pattern_len()),
            fre_observation: format!("usize:{}", fre.patterns().len()),
        }])
    }

    fn omitted_second_assertion(
        context: &AdapterContext<'_>,
    ) -> Result<Vec<RegexAutomataAssertionExecution>, String> {
        let mut executions = run_try_search_fwd(context)?;
        executions.pop();
        Ok(executions)
    }

    fn omitted_bounds_assertion(
        context: &AdapterContext<'_>,
    ) -> Result<Vec<RegexAutomataAssertionExecution>, String> {
        let mut executions = run_try_search_fwd_bounds(context)?;
        executions.pop();
        Ok(executions)
    }

    fn wrong_pattern_len_many(
        context: &AdapterContext<'_>,
    ) -> Result<Vec<RegexAutomataAssertionExecution>, String> {
        require_compiled_mode(context)?;
        let upstream = dense::DFA::new_many(&["a", "b"]).map_err(|error| error.to_string())?;
        let fre = PortableRegexSet::new(["a", "b"]).map_err(|error| error.to_string())?;
        Ok(vec![RegexAutomataAssertionExecution {
            assertion_id: PATTERN_LEN_MANY_ASSERTIONS[0].assertion_id.to_owned(),
            upstream_observation: format!("usize:{}", upstream.pattern_len()),
            fre_observation: format!("usize:{}", fre.patterns().len()),
        }])
    }

    fn omitted_pattern_len_many(
        context: &AdapterContext<'_>,
    ) -> Result<Vec<RegexAutomataAssertionExecution>, String> {
        require_compiled_mode(context)?;
        Ok(Vec::new())
    }

    #[test]
    fn exact_upstream_spans_bind_every_assertion() {
        const CHANGED_ASSERTION: &[AssertionSpec] = &[AssertionSpec {
            source_line: 823,
            ..PATTERN_LEN_MANY_ASSERTIONS[0]
        }];

        validate_source_spec(&PATTERN_LEN_SOURCE).unwrap();
        validate_source_spec(&PATTERN_LEN_MANY_SOURCE).unwrap();
        validate_source_spec(&IS_SPECIAL_STATE_SOURCE).unwrap();
        validate_source_spec(&IS_START_STATE_SOURCE).unwrap();
        validate_source_spec(&MATCH_LEN_SOURCE).unwrap();
        validate_source_spec(&PATTERN_LEN_ALWAYS_SOURCE).unwrap();
        validate_source_spec(&TRY_SEARCH_OVERLAPPING_FWD_SOURCE).unwrap();
        validate_source_spec(&TRY_SEARCH_FWD_SOURCE).unwrap();
        validate_source_spec(&TRY_SEARCH_FWD_BOUNDS_SOURCE).unwrap();
        validate_source_spec(&LOOK_END_LINE_SOURCE).unwrap();
        validate_source_spec(&LOOK_END_TEXT_SOURCE).unwrap();
        validate_source_spec(&LOOK_START_LINE_SOURCE).unwrap();
        validate_source_spec(&LOOK_START_TEXT_SOURCE).unwrap();
        validate_look_fixture().unwrap();
        validate_try_search_fwd_bounds_vector(
            &TRY_SEARCH_FWD_BOUNDS_SOURCE,
            TRY_SEARCH_FWD_BOUNDS_VECTOR,
        )
        .unwrap();

        let mut changed_span = PATTERN_LEN_SOURCE;
        changed_span.source_span = "    /// changed\n";
        assert!(validate_source_spec(&changed_span).is_err());

        let mut changed_hash = PATTERN_LEN_SOURCE;
        changed_hash.source_span_sha256 =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert!(validate_source_spec(&changed_hash).is_err());

        let mut omitted_inventory = TRY_SEARCH_FWD_SOURCE;
        omitted_inventory.assertions = &TRY_SEARCH_FWD_ASSERTIONS[..1];
        assert!(validate_source_spec(&omitted_inventory).is_err());

        let mut misbound_line = PATTERN_LEN_MANY_SOURCE;
        misbound_line.assertions = CHANGED_ASSERTION;
        assert!(validate_source_spec(&misbound_line).is_err());

        let mut wrong_span = PATTERN_LEN_MANY_SOURCE;
        wrong_span.source_span = PATTERN_LEN_SOURCE.source_span;
        assert!(validate_source_spec(&wrong_span).is_err());

        for changed in [
            TrySearchFwdBoundsVector {
                pattern: "[0-9]{3}",
                ..TRY_SEARCH_FWD_BOUNDS_VECTOR
            },
            TrySearchFwdBoundsVector {
                haystack: "foo123baz",
                ..TRY_SEARCH_FWD_BOUNDS_VECTOR
            },
            TrySearchFwdBoundsVector {
                range_start: 2,
                ..TRY_SEARCH_FWD_BOUNDS_VECTOR
            },
            TrySearchFwdBoundsVector {
                range_end: 7,
                ..TRY_SEARCH_FWD_BOUNDS_VECTOR
            },
        ] {
            assert!(
                validate_try_search_fwd_bounds_vector(&TRY_SEARCH_FWD_BOUNDS_SOURCE, changed)
                    .is_err()
            );
        }
    }

    #[test]
    fn look_fixture_authority_rejects_every_named_mutation_class() {
        validate_look_fixture().unwrap();
        assert_eq!(
            sha256(LOOK_TARGET_IDENTITIES.as_bytes()),
            LOOK_TARGET_IDENTITIES_SHA256
        );

        let mut changed_fixture = LOOK_FULL_SOURCE_SPAN.to_owned();
        changed_fixture.replace_range(0..1, "M");
        assert!(
            validate_look_fixture_parts(
                &changed_fixture,
                LOOK_CASES,
                LOOK_TARGET_IDENTITIES_SHA256,
            )
            .is_err()
        );
        assert!(
            validate_look_fixture_parts(
                LOOK_FULL_SOURCE_SPAN,
                &LOOK_CASES[..3],
                LOOK_TARGET_IDENTITIES_SHA256,
            )
            .is_err()
        );

        let mut duplicate = LOOK_CASES.to_vec();
        duplicate[1] = duplicate[0];
        assert!(
            validate_look_fixture_parts(
                LOOK_FULL_SOURCE_SPAN,
                &duplicate,
                LOOK_TARGET_IDENTITIES_SHA256,
            )
            .is_err()
        );
        let mut reordered = LOOK_CASES.to_vec();
        reordered.swap(0, 1);
        assert!(
            validate_look_fixture_parts(
                LOOK_FULL_SOURCE_SPAN,
                &reordered,
                LOOK_TARGET_IDENTITIES_SHA256,
            )
            .is_err()
        );

        let mut flipped_vectors = LOOK_END_LINE_VECTORS.to_vec();
        flipped_vectors[0].expected = false;
        let flipped = LookCaseSpec {
            vectors: Box::leak(flipped_vectors.into_boxed_slice()),
            ..LOOK_END_LINE
        };
        assert!(validate_look_case_spec(flipped).is_err());

        let mut wrong_at_vectors = LOOK_END_LINE_VECTORS.to_vec();
        wrong_at_vectors[0].at = 1;
        let wrong_at = LookCaseSpec {
            vectors: Box::leak(wrong_at_vectors.into_boxed_slice()),
            ..LOOK_END_LINE
        };
        assert!(validate_look_case_spec(wrong_at).is_err());
        assert!(
            validate_look_case_spec(LookCaseSpec {
                pattern: r"\z",
                ..LOOK_END_LINE
            })
            .is_err()
        );
        assert!(
            validate_look_case_spec(LookCaseSpec {
                kind: LookKind::EndText,
                ..LOOK_END_LINE
            })
            .is_err()
        );

        let non_k0 = PortableRegex::new("a").unwrap();
        assert!(validate_look_fre_plan(&non_k0).is_err());
    }

    #[test]
    fn look_observers_execute_all_thirty_two_assertions_only_in_default_unit_mode() {
        let mode = compiled_unit_mode();
        let adapters = [
            LOOK_END_LINE_ADAPTER,
            LOOK_END_TEXT_ADAPTER,
            LOOK_START_LINE_ADAPTER,
            LOOK_START_TEXT_ADAPTER,
        ];
        let executions = adapters
            .iter()
            .map(|adapter| execute_adapter(adapter, &mode).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            executions
                .iter()
                .map(|execution| execution.assertion_executions.len())
                .collect::<Vec<_>>(),
            [9, 9, 7, 7],
        );
        assert_eq!(
            executions
                .iter()
                .map(|execution| execution.assertion_executions.len())
                .sum::<usize>(),
            32,
        );

        let mut relabeled_mode = mode;
        relabeled_mode.mode_id = "vcs-all-features-unit".to_owned();
        relabeled_mode.default_features = false;
        relabeled_mode.all_features = true;
        let relabeled = RegisteredAdapter {
            mode_id: "vcs-all-features-unit",
            ..LOOK_END_LINE_ADAPTER
        };
        assert_eq!(
            execute_adapter(&relabeled, &relabeled_mode).unwrap_err(),
            "compiled-mode-mismatch",
        );
    }

    #[test]
    fn look_execution_receipts_reject_omission_duplicate_reorder_and_flip() {
        let mode = compiled_unit_mode();
        let authentic = run_look_end_line(&AdapterContext { mode: &mode }).unwrap();
        validate_assertion_executions(LOOK_END_LINE_ASSERTIONS, &authentic).unwrap();

        let mut omitted = authentic.clone();
        omitted.pop();
        assert_eq!(
            validate_assertion_executions(LOOK_END_LINE_ASSERTIONS, &omitted).unwrap_err(),
            "assertion-execution-count-mismatch",
        );

        let mut duplicated = authentic.clone();
        duplicated.push(authentic[0].clone());
        assert_eq!(
            validate_assertion_executions(LOOK_END_LINE_ASSERTIONS, &duplicated).unwrap_err(),
            "assertion-execution-count-mismatch",
        );

        let mut reordered = authentic.clone();
        reordered.swap(0, 1);
        assert_eq!(
            validate_assertion_executions(LOOK_END_LINE_ASSERTIONS, &reordered).unwrap_err(),
            "assertion-execution-binding-mismatch",
        );

        let mut flipped = authentic;
        flipped[0].upstream_observation = "bool:false".to_owned();
        flipped[0].fre_observation = "bool:false".to_owned();
        assert_eq!(
            validate_assertion_executions(LOOK_END_LINE_ASSERTIONS, &flipped).unwrap_err(),
            "assertion-execution-binding-mismatch",
        );
    }

    #[test]
    fn look_k0_true_boundary_requires_the_exact_finite_work_limit() {
        let fre = PortableBuilder::new(LOOK_START_TEXT.pattern)
            .profile(RustProfile::rebar_1_12_4())
            .unicode(false)
            .plan_selection(PlanSelection::ForceK0)
            .build()
            .unwrap();
        validate_look_fre_plan(&fre).unwrap();
        let vector = LOOK_START_TEXT_VECTORS[0];
        assert!(vector.expected);
        assert!(
            fre.find_window(
                vector.haystack.as_bytes(),
                SearchWindow::new(vector.at, vector.at),
                SearchLimits {
                    max_work: 17,
                    max_scratch_bytes: 8 * 1024 * 1024,
                },
            )
            .is_err(),
        );
        let (matched, accounting) = fre
            .find_window(
                vector.haystack.as_bytes(),
                SearchWindow::new(vector.at, vector.at),
                SearchLimits {
                    max_work: 18,
                    max_scratch_bytes: 8 * 1024 * 1024,
                },
            )
            .unwrap();
        assert_eq!(
            matched.map(|matched| (matched.start(), matched.end())),
            Some((0, 0))
        );
        let SearchAccounting::K0(accounting) = accounting else {
            panic!("forced look plan did not return K0 accounting")
        };
        assert_eq!(accounting.work(), 18);
        let retained = accounting.scratch_bytes();
        assert!(retained > 0);
        assert!(
            fre.find_window(
                vector.haystack.as_bytes(),
                SearchWindow::new(vector.at, vector.at),
                SearchLimits {
                    max_work: 18,
                    max_scratch_bytes: retained - 1,
                },
            )
            .is_err(),
        );
    }

    #[test]
    fn observers_execute_exact_assertions_and_reject_misbinding_or_omission() {
        let mode = compiled_mode();
        for adapter in REGISTERED_ADAPTERS {
            let adapter_mode = if adapter.harness == RegexAutomataHarnessKind::Unit {
                compiled_unit_mode()
            } else {
                mode.clone()
            };
            execute_adapter(adapter, &adapter_mode).unwrap();
        }

        let misbound = RegisteredAdapter {
            run: wrong_pattern_len,
            ..REGISTERED_ADAPTERS[0]
        };
        assert_eq!(
            execute_adapter(&misbound, &mode).unwrap_err(),
            "assertion-execution-binding-mismatch",
        );

        let omitted = RegisteredAdapter {
            run: omitted_second_assertion,
            ..TRY_SEARCH_FWD_ADAPTER
        };
        assert_eq!(
            execute_adapter(&omitted, &mode).unwrap_err(),
            "assertion-execution-count-mismatch",
        );

        let wrong_expected = RegisteredAdapter {
            run: wrong_pattern_len_many,
            ..REGISTERED_ADAPTERS[1]
        };
        assert_eq!(
            execute_adapter(&wrong_expected, &mode).unwrap_err(),
            "assertion-execution-binding-mismatch",
        );

        let omitted_many = RegisteredAdapter {
            run: omitted_pattern_len_many,
            ..REGISTERED_ADAPTERS[1]
        };
        assert_eq!(
            execute_adapter(&omitted_many, &mode).unwrap_err(),
            "assertion-execution-count-mismatch",
        );

        let omitted_bounds = RegisteredAdapter {
            run: omitted_bounds_assertion,
            ..TRY_SEARCH_FWD_BOUNDS_ADAPTER
        };
        assert_eq!(
            execute_adapter(&omitted_bounds, &mode).unwrap_err(),
            "assertion-execution-count-mismatch",
        );
    }

    #[test]
    fn batched_dfa_observers_bind_all_twenty_three_assertions() {
        let mode = compiled_mode();
        let adapters = [
            IS_SPECIAL_STATE_ADAPTER,
            IS_START_STATE_ADAPTER,
            MATCH_LEN_ADAPTER,
            PATTERN_LEN_ALWAYS_ADAPTER,
            TRY_SEARCH_OVERLAPPING_FWD_ADAPTER,
        ];
        let executions = adapters
            .iter()
            .map(|adapter| execute_adapter(adapter, &mode).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            executions
                .iter()
                .map(|execution| execution.assertion_executions.len())
                .collect::<Vec<_>>(),
            vec![10, 5, 5, 1, 2],
        );
        assert_eq!(
            executions
                .iter()
                .map(|execution| execution.case_id.as_str())
                .collect::<Vec<_>>(),
            vec![
                IS_SPECIAL_STATE_CASE,
                IS_START_STATE_CASE,
                MATCH_LEN_CASE,
                PATTERN_LEN_ALWAYS_CASE,
                TRY_SEARCH_OVERLAPPING_FWD_CASE,
            ],
        );
    }

    #[test]
    fn mode_agnostic_execution_cannot_be_relabeled() {
        let mut relabeled_mode = compiled_mode();
        relabeled_mode.mode_id = "vcs-all-features-doctest".to_owned();
        relabeled_mode.default_features = false;
        relabeled_mode.all_features = true;
        let relabeled = RegisteredAdapter {
            mode_id: "vcs-all-features-doctest",
            ..REGISTERED_ADAPTERS[0]
        };
        assert_eq!(
            execute_adapter(&relabeled, &relabeled_mode).unwrap_err(),
            "compiled-mode-mismatch",
        );

        let relabeled_bounds = RegisteredAdapter {
            mode_id: "vcs-all-features-doctest",
            ..TRY_SEARCH_FWD_BOUNDS_ADAPTER
        };
        assert_eq!(
            execute_adapter(&relabeled_bounds, &relabeled_mode).unwrap_err(),
            "compiled-mode-mismatch",
        );
    }
}
