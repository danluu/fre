//! Authenticated package-default execution for the six Unicode word-look unit
//! tests that follow the sealed 129-membership `util::look` report.
//!
//! This is deliberately a successor protocol. It never enlarges the registry
//! used to reproduce the historical v3/v4 reports, so old evidence remains
//! byte-stable and independently replayable.

use std::collections::{BTreeMap, BTreeSet};

use fre::{
    PlanSelection, PortableBuilder, PortableRegex, RustProfile, SearchAccounting, SearchLimits,
    SearchWindow,
};
use regex_automata::util::look::{Look, LookMatcher};

use super::{
    COMPILED_UNIT_MODE_ID, INVENTORY_UNSUPPORTED_REASON, LOOK_SOURCE_PATH, LOOK_SOURCE_SHA256,
    REGEX_AUTOMATA_ASCII_WORD_LOOK_REPORT_SCHEMA, RegexAutomataAdapterCounts,
    RegexAutomataAdapterDisposition, RegexAutomataAdapterReport, RegexAutomataAdapterReportPayload,
    RegexAutomataAssertionContract, RegexAutomataAssertionExecution, RegexAutomataCorpusReport,
    RegexAutomataExecutionReceipt, RegexAutomataHarnessKind, RegexAutomataModeExecution,
    RegexAutomataSourceContract, RegexAutomataStrictGain, adapter_counts, gain_vectors, hash_json,
    mode_execution, obligation_membership_identity, order_execution_receipts, validate_candidate,
    validate_execution_receipt_order, validate_look_fre_plan,
};
use crate::{CandidateIdentity, InventoryError};

/// Report schema for the exact package-default six-case Unicode word-look gain.
pub const REGEX_AUTOMATA_UNICODE_WORD_LOOK_REPORT_SCHEMA: &str =
    "fre.regex-automata-0.4.14.adapter-report.v6";

pub(super) const UNICODE_WORD_LOOK_REPORT_LIMITATIONS: [&str; 3] = [
    "A pass requires direct triple agreement between the authenticated upstream LookMatcher assertion, a forced-K0 FRE search at the exact empty window, and the sealed expected observation.",
    "Only six package-default Unicode word-look unit memberships are added; no result is projected across Cargo feature modes.",
    "The predecessor 135-membership ASCII word-look report, including its compiled-mode matrix and every non-target disposition, is retained exactly.",
];

const PREDECESSOR_REVISION: &str = "119c1a3c2b1b53a3e80dcdbc9dc637ee5c843e11";
const PREDECESSOR_TREE: &str = "088c1ee0e444bfff59a8a8ca956df93d51408b3b";
const PREDECESSOR_PAYLOAD_SHA256: &str =
    "57338888329628d69daac44c533f6d501fbd5f983e27ac003a94d8f6810da2ac";
const FIXTURE: &str = include_str!("../fixtures/look-unicode-word-tests-v1.txt");
const FIXTURE_SHA256: &str = "011d5ded55f3d446f797e8799471a025b367fffe734daaf4947c9638f98be4bc";
const TARGET_IDENTITIES_SHA256: &str =
    "308c1de620e97cf9a213f4f92c2e622282b65189fba8565d3683732a32dadbbe";
const MAX_WORK: u64 = 18;
const MAX_SCRATCH_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UnicodeWordLookKind {
    Word,
    WordNegate,
    WordStart,
    WordEnd,
    WordStartHalf,
    WordEndHalf,
}

#[derive(Clone, Copy)]
struct CaseAuthority {
    case_id: &'static str,
    function_name: &'static str,
    assertion_prefix: &'static str,
    kind: UnicodeWordLookKind,
    pattern: &'static str,
    span_start_line: usize,
    span_end_line: usize,
    span_sha256: &'static str,
    assertion_inventory_sha256: &'static str,
}

const AUTHORITIES: [CaseAuthority; 6] = [
    CaseAuthority {
        case_id: "util::look::tests::look_matches_word_unicode",
        function_name: "look_matches_word_unicode",
        assertion_prefix: "word-unicode",
        kind: UnicodeWordLookKind::Word,
        pattern: r"\b",
        span_start_line: 1_769,
        span_end_line: 1_819,
        span_sha256: "2f386cfd22475e17593f0cbf0976aa9e16d345708ed75ec67fbc7530725031cf",
        assertion_inventory_sha256: "52920d59789d1b60427743139e0c5b040cca5186d6076b13fe21277d42666736",
    },
    CaseAuthority {
        case_id: "util::look::tests::look_matches_word_unicode_negate",
        function_name: "look_matches_word_unicode_negate",
        assertion_prefix: "word-unicode-negate",
        kind: UnicodeWordLookKind::WordNegate,
        pattern: r"\B",
        span_start_line: 1_874,
        span_end_line: 1_931,
        span_sha256: "4b7ae3464586c0b67a46c81bc722ecbe82bb4fc6d898b879b2ec79387a15128d",
        assertion_inventory_sha256: "8069684e22be86f73096d33c0f424477feeecab3ce17ce32bb020a090b8f445a",
    },
    CaseAuthority {
        case_id: "util::look::tests::look_matches_word_end_unicode",
        function_name: "look_matches_word_end_unicode",
        assertion_prefix: "word-end-unicode",
        kind: UnicodeWordLookKind::WordEnd,
        pattern: r"\b{end}",
        span_start_line: 2_147,
        span_end_line: 2_198,
        span_sha256: "7708bfa38d58938eb50189abbc0b6e3591b8236df6f4257aa0a342c5ba2e687a",
        assertion_inventory_sha256: "840d2c41465772c14d658f7a878d273245295b9c8f80460bdadc5cc9d2588476",
    },
    CaseAuthority {
        case_id: "util::look::tests::look_matches_word_end_half_unicode",
        function_name: "look_matches_word_end_half_unicode",
        assertion_prefix: "word-end-half-unicode",
        kind: UnicodeWordLookKind::WordEndHalf,
        pattern: r"\b{end-half}",
        span_start_line: 2_361,
        span_end_line: 2_412,
        span_sha256: "9a6ab849fc791faaa874dd537cdcfe19a237abdc8eaa2278babc19f86c64588e",
        assertion_inventory_sha256: "f82e5ea84994470fe9a2cb63901559e603cc5cb749f7c71e04b69c766d1f26a2",
    },
    CaseAuthority {
        case_id: "util::look::tests::look_matches_word_start_unicode",
        function_name: "look_matches_word_start_unicode",
        assertion_prefix: "word-start-unicode",
        kind: UnicodeWordLookKind::WordStart,
        pattern: r"\b{start}",
        span_start_line: 2_094,
        span_end_line: 2_145,
        span_sha256: "1f12d804f8918363e7551292ad5d82d14a6f5fb3b74f3956ba1ece5999749cb7",
        assertion_inventory_sha256: "4c8857e0d0a2f9a6ab2c56d877df3dd43caae76a5c69ca2f42561dcf462aac76",
    },
    CaseAuthority {
        case_id: "util::look::tests::look_matches_word_start_half_unicode",
        function_name: "look_matches_word_start_half_unicode",
        assertion_prefix: "word-start-half-unicode",
        kind: UnicodeWordLookKind::WordStartHalf,
        pattern: r"\b{start-half}",
        span_start_line: 2_308,
        span_end_line: 2_359,
        span_sha256: "2d018b676a477e571f6b9b750fa69ab44b93577266ffe04cdccaf3e6f0bb93c8",
        assertion_inventory_sha256: "fa45e90fc464d0d29b00982a20213151be744c5bc78e7466d1f20a2d7c562cd6",
    },
];

#[derive(Clone, Debug, Eq, PartialEq)]
struct AssertionVector {
    assertion_id: String,
    haystack: Vec<u8>,
    at: usize,
    expected: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedCase {
    authority_index: usize,
    source: RegexAutomataSourceContract,
    vectors: Vec<AssertionVector>,
}

/// Extend the exact 135-pass report with the six independently executed
/// package-default Unicode word-look memberships.
pub fn build_regex_automata_unicode_word_look_report(
    inventory: &RegexAutomataCorpusReport,
    previous: &RegexAutomataAdapterReport,
    candidate: CandidateIdentity,
) -> Result<RegexAutomataAdapterReport, InventoryError> {
    validate_predecessor(inventory, previous)?;
    validate_candidate(&candidate)?;
    if candidate.revision == PREDECESSOR_REVISION || candidate.tree == PREDECESSOR_TREE {
        return Err(InventoryError::new(
            "Unicode word-look candidate is not distinct from its predecessor",
        ));
    }
    let cases = parse_cases()?;
    let targets = target_identities(inventory)?;
    let mode = mode_execution(inventory, COMPILED_UNIT_MODE_ID)?;
    let mut receipts = previous.payload.receipts.clone();
    let mut execution_receipts = previous.payload.execution_receipts.clone();
    let mut observed_targets = BTreeSet::new();
    for receipt in &mut receipts {
        let identity = (
            receipt.mode_id.clone(),
            receipt.harness,
            receipt.case_id.clone(),
        );
        if !targets.contains(&identity) {
            continue;
        }
        let case = cases
            .iter()
            .find(|case| authority(case).case_id == receipt.case_id)
            .ok_or_else(|| InventoryError::new("Unicode word-look target lacks its parsed case"))?;
        let execution = execute_case(case, &mode)?;
        let evidence_sha256 = hash_json(&execution, "encode Unicode word-look execution")?;
        receipt.disposition = RegexAutomataAdapterDisposition::Pass { evidence_sha256 };
        execution_receipts.push(execution);
        observed_targets.insert(identity);
    }
    if observed_targets != targets {
        return Err(InventoryError::new(
            "Unicode word-look inventory target denominator mismatch",
        ));
    }
    let execution_receipts =
        order_execution_receipts(&receipts, execution_receipts, "Unicode word-look report")?;
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
        look_mode_matrix: previous.payload.look_mode_matrix.clone(),
        limitations: UNICODE_WORD_LOOK_REPORT_LIMITATIONS
            .iter()
            .map(|text| (*text).to_owned())
            .collect(),
    };
    let report = RegexAutomataAdapterReport {
        schema: REGEX_AUTOMATA_UNICODE_WORD_LOOK_REPORT_SCHEMA.to_owned(),
        payload_sha256: hash_json(&payload, "encode Unicode word-look report payload")?,
        payload,
    };
    validate_unicode_word_look_execution_after_structure(inventory, &report)?;
    Ok(report)
}

/// Require an exact 135 -> 141 transition with every non-target receipt and
/// execution preserved from the authenticated predecessor.
pub fn validate_regex_automata_unicode_word_look_strict_gain(
    inventory: &RegexAutomataCorpusReport,
    previous: &RegexAutomataAdapterReport,
    current: &RegexAutomataAdapterReport,
) -> Result<RegexAutomataStrictGain, InventoryError> {
    validate_predecessor(inventory, previous)?;
    current.validate_structure(inventory)?;
    if current.schema != REGEX_AUTOMATA_UNICODE_WORD_LOOK_REPORT_SCHEMA {
        return Err(InventoryError::new(
            "current report is not an Unicode word-look report",
        ));
    }
    let targets = target_identities(inventory)?;
    let (gained_unique_cases, gained_mode_memberships) = gain_vectors(
        &previous.payload.receipts,
        &current.payload.receipts,
        &targets,
    )?;
    if (gained_unique_cases, gained_mode_memberships) != (6, 6) {
        return Err(InventoryError::new(
            "Unicode word-look gain is not exact six-membership progress",
        ));
    }
    Ok(RegexAutomataStrictGain {
        family: "unit-util".to_owned(),
        gained_unique_cases,
        gained_mode_memberships,
        previous_pass: 135,
        current_pass: 141,
    })
}

pub(super) fn validate_unicode_word_look_execution_after_structure(
    inventory: &RegexAutomataCorpusReport,
    report: &RegexAutomataAdapterReport,
) -> Result<(), InventoryError> {
    if report.schema != REGEX_AUTOMATA_UNICODE_WORD_LOOK_REPORT_SCHEMA
        || report.payload.counts
            != (RegexAutomataAdapterCounts {
                pass: 141,
                unsupported: 3_701,
                fault: 0,
                total: 3_842,
            })
        || report.payload.candidate.revision == PREDECESSOR_REVISION
        || report.payload.candidate.tree == PREDECESSOR_TREE
        || !report
            .payload
            .candidate
            .tracked_and_untracked_worktree_clean
    {
        return Err(InventoryError::new(
            "Unicode word-look candidate identity or cardinality mismatch",
        ));
    }
    validate_execution_receipt_order(report)?;
    let targets = target_identities(inventory)?;
    let previous = reconstruct_predecessor(report, &targets)?;
    validate_predecessor(inventory, &previous)?;
    let cases = parse_cases()?;
    let mode = mode_execution(inventory, COMPILED_UNIT_MODE_ID)?;
    let previous_executions = previous
        .payload
        .execution_receipts
        .iter()
        .map(|execution| (execution_identity(execution), execution))
        .collect::<BTreeMap<_, _>>();
    let current_executions = report
        .payload
        .execution_receipts
        .iter()
        .map(|execution| (execution_identity(execution), execution))
        .collect::<BTreeMap<_, _>>();
    if previous_executions.len() != 135 || current_executions.len() != 141 {
        return Err(InventoryError::new(
            "Unicode word-look execution denominator mismatch",
        ));
    }
    for (identity, execution) in &previous_executions {
        if current_executions.get(identity) != Some(execution) {
            return Err(InventoryError::new(
                "Unicode word-look report changed retained execution evidence",
            ));
        }
    }
    for identity in &targets {
        let execution = current_executions.get(identity).ok_or_else(|| {
            InventoryError::new("Unicode word-look target lacks execution evidence")
        })?;
        let case = cases
            .iter()
            .find(|case| authority(case).case_id == identity.2)
            .ok_or_else(|| {
                InventoryError::new("Unicode word-look target lacks source authority")
            })?;
        let expected = execute_case(case, &mode)?;
        if *execution != &expected {
            return Err(InventoryError::new(
                "Unicode word-look execution evidence mismatch",
            ));
        }
        let receipt = report
            .payload
            .receipts
            .iter()
            .find(|receipt| {
                (
                    receipt.mode_id.as_str(),
                    receipt.harness,
                    receipt.case_id.as_str(),
                ) == (identity.0.as_str(), identity.1, identity.2.as_str())
            })
            .ok_or_else(|| InventoryError::new("Unicode word-look target receipt is absent"))?;
        let expected_hash = hash_json(execution, "encode Unicode word-look execution")?;
        if !matches!(
            &receipt.disposition,
            RegexAutomataAdapterDisposition::Pass { evidence_sha256 }
                if *evidence_sha256 == expected_hash
        ) {
            return Err(InventoryError::new(
                "Unicode word-look pass is not bound to its execution receipt",
            ));
        }
    }
    Ok(())
}

fn validate_predecessor(
    inventory: &RegexAutomataCorpusReport,
    report: &RegexAutomataAdapterReport,
) -> Result<(), InventoryError> {
    report.validate_structure(inventory)?;
    if report.schema != REGEX_AUTOMATA_ASCII_WORD_LOOK_REPORT_SCHEMA
        || report.payload.counts
            != (RegexAutomataAdapterCounts {
                pass: 135,
                unsupported: 3_707,
                fault: 0,
                total: 3_842,
            })
        || report.payload.candidate.revision != PREDECESSOR_REVISION
        || report.payload.candidate.tree != PREDECESSOR_TREE
        || report.payload_sha256 != PREDECESSOR_PAYLOAD_SHA256
        || !report
            .payload
            .candidate
            .tracked_and_untracked_worktree_clean
    {
        return Err(InventoryError::new(
            "Unicode word-look predecessor authority mismatch",
        ));
    }
    Ok(())
}

fn reconstruct_predecessor(
    report: &RegexAutomataAdapterReport,
    targets: &BTreeSet<(String, RegexAutomataHarnessKind, String)>,
) -> Result<RegexAutomataAdapterReport, InventoryError> {
    let mut previous = report.clone();
    previous.schema.clear();
    previous
        .schema
        .push_str(REGEX_AUTOMATA_ASCII_WORD_LOOK_REPORT_SCHEMA);
    PREDECESSOR_REVISION.clone_into(&mut previous.payload.candidate.revision);
    PREDECESSOR_TREE.clone_into(&mut previous.payload.candidate.tree);
    previous.payload.limitations =
        crate::automata_progress::word_look::ASCII_WORD_LOOK_REPORT_LIMITATIONS
            .iter()
            .map(|text| (*text).to_owned())
            .collect();
    for receipt in &mut previous.payload.receipts {
        let identity = (
            receipt.mode_id.clone(),
            receipt.harness,
            receipt.case_id.clone(),
        );
        if targets.contains(&identity) {
            receipt.disposition = RegexAutomataAdapterDisposition::Unsupported {
                reason_code: INVENTORY_UNSUPPORTED_REASON.to_owned(),
            };
        }
    }
    previous
        .payload
        .execution_receipts
        .retain(|execution| !targets.contains(&execution_identity(execution)));
    previous.payload.counts = adapter_counts(&previous.payload.receipts);
    previous.payload_sha256 = hash_json(
        &previous.payload,
        "encode reconstructed all-mode look payload",
    )?;
    if previous.payload_sha256 != PREDECESSOR_PAYLOAD_SHA256 {
        return Err(InventoryError::new(
            "reconstructed predecessor payload SHA-256 mismatch",
        ));
    }
    Ok(previous)
}

fn execution_identity(
    execution: &RegexAutomataExecutionReceipt,
) -> (String, RegexAutomataHarnessKind, String) {
    (
        execution.mode.mode_id.clone(),
        execution.harness,
        execution.case_id.clone(),
    )
}

fn target_identities(
    inventory: &RegexAutomataCorpusReport,
) -> Result<BTreeSet<(String, RegexAutomataHarnessKind, String)>, InventoryError> {
    validate_fixture()?;
    let identities = AUTHORITIES
        .iter()
        .map(|authority| {
            (
                COMPILED_UNIT_MODE_ID.to_owned(),
                RegexAutomataHarnessKind::Unit,
                authority.case_id.to_owned(),
            )
        })
        .collect::<BTreeSet<_>>();
    let mut canonical = String::new();
    for (mode_id, _, case_id) in &identities {
        canonical.push_str(mode_id);
        canonical.push_str("\tunit\t");
        canonical.push_str(case_id);
        canonical.push('\n');
    }
    let inventory_identities = inventory
        .payload
        .obligations
        .iter()
        .map(obligation_membership_identity)
        .collect::<BTreeSet<_>>();
    if identities.len() != 6
        || crate::sha256(canonical.as_bytes()) != TARGET_IDENTITIES_SHA256
        || !identities.is_subset(&inventory_identities)
    {
        return Err(InventoryError::new(
            "Unicode word-look target identity seal mismatch",
        ));
    }
    Ok(identities)
}

fn parse_cases() -> Result<Vec<ParsedCase>, InventoryError> {
    validate_fixture()?;
    AUTHORITIES
        .iter()
        .enumerate()
        .map(|(authority_index, authority)| parse_case(authority_index, authority))
        .collect()
}

fn validate_fixture() -> Result<(), InventoryError> {
    if FIXTURE.len() != 12_866
        || FIXTURE.split_inclusive('\n').count() != 317
        || !FIXTURE.ends_with('\n')
        || FIXTURE.contains(['\0', '\r'])
        || crate::sha256(FIXTURE.as_bytes()) != FIXTURE_SHA256
    {
        return Err(InventoryError::new(
            "Unicode word-look fixture identity mismatch",
        ));
    }
    for authority in AUTHORITIES {
        let signature = format!("    fn {}() {{", authority.function_name);
        if FIXTURE.matches(&signature).count() != 1 {
            return Err(InventoryError::new(
                "Unicode word-look fixture function denominator mismatch",
            ));
        }
    }
    Ok(())
}

fn parse_case(
    authority_index: usize,
    authority: &CaseAuthority,
) -> Result<ParsedCase, InventoryError> {
    let function_marker = format!("    fn {}() {{\n", authority.function_name);
    let function_start = FIXTURE
        .find(&function_marker)
        .ok_or_else(|| InventoryError::new("Unicode word-look fixture lacks case marker"))?;
    let start = FIXTURE[..function_start]
        .rfind("    #[test]\n")
        .ok_or_else(|| InventoryError::new("Unicode word-look fixture lacks test marker"))?;
    let tail = &FIXTURE[start..];
    let close = tail
        .find("\n    }\n")
        .and_then(|offset| offset.checked_add("\n    }\n".len()))
        .ok_or_else(|| InventoryError::new("Unicode word-look fixture lacks case terminator"))?;
    let source_span = &tail[..close];
    let expected_lines = authority
        .span_end_line
        .checked_sub(authority.span_start_line)
        .and_then(|count| count.checked_add(1))
        .ok_or_else(|| InventoryError::new("Unicode word-look source line range overflow"))?;
    if source_span.split_inclusive('\n').count() != expected_lines
        || crate::sha256(source_span.as_bytes()) != authority.span_sha256
    {
        return Err(InventoryError::new(
            "Unicode word-look source-span authority mismatch",
        ));
    }
    let mut assertions = Vec::new();
    let mut vectors = Vec::new();
    for (offset, line) in source_span.split_inclusive('\n').enumerate() {
        let Some((haystack, at, expected)) = parse_assertion(line)? else {
            continue;
        };
        let ordinal = assertions
            .len()
            .checked_add(1)
            .ok_or_else(|| InventoryError::new("Unicode word-look assertion count overflow"))?;
        let assertion_id = format!("{}-{ordinal:02}", authority.assertion_prefix);
        let source_line = authority
            .span_start_line
            .checked_add(offset)
            .ok_or_else(|| InventoryError::new("Unicode word-look source line overflow"))?;
        assertions.push(RegexAutomataAssertionContract {
            assertion_id: assertion_id.clone(),
            source_line,
            source_line_sha256: crate::sha256(line.as_bytes()),
            expected_observation: format!("bool:{expected}"),
        });
        vectors.push(AssertionVector {
            assertion_id,
            haystack,
            at,
            expected,
        });
    }
    let assertion_inventory_sha256 =
        hash_json(&assertions, "encode Unicode word-look assertion inventory")?;
    if assertions.len() != vectors.len()
        || assertions.is_empty()
        || assertion_inventory_sha256 != authority.assertion_inventory_sha256
    {
        return Err(InventoryError::new(
            "Unicode word-look assertion inventory mismatch",
        ));
    }
    Ok(ParsedCase {
        authority_index,
        source: RegexAutomataSourceContract {
            source_path: LOOK_SOURCE_PATH.to_owned(),
            source_sha256: LOOK_SOURCE_SHA256.to_owned(),
            span_start_line: authority.span_start_line,
            span_end_line: authority.span_end_line,
            source_span_sha256: authority.span_sha256.to_owned(),
            assertion_inventory_sha256,
            assertions,
        },
        vectors,
    })
}

fn parse_assertion(line: &str) -> Result<Option<(Vec<u8>, usize, bool)>, InventoryError> {
    let trimmed = line.trim();
    let (tail, expected) = if let Some(tail) = trimmed.strip_prefix("assert!(testlook!(look, ") {
        (tail, true)
    } else if let Some(tail) = trimmed.strip_prefix("assert!(!testlook!(look, ") {
        (tail, false)
    } else {
        return Ok(None);
    };
    let body = tail
        .strip_suffix("));")
        .ok_or_else(|| InventoryError::new("Unicode word-look assertion suffix mismatch"))?;
    let split = body
        .rfind(", ")
        .ok_or_else(|| InventoryError::new("Unicode word-look assertion lacks offset"))?;
    let (literal, offset) = body.split_at(split);
    let at = offset[2..]
        .parse::<usize>()
        .map_err(|_| InventoryError::new("Unicode word-look assertion offset is invalid"))?;
    let haystack = serde_json::from_str::<String>(literal)
        .map_err(|_| InventoryError::new("Unicode word-look haystack literal is invalid"))?
        .into_bytes();
    if at > haystack.len() {
        return Err(InventoryError::new(
            "Unicode word-look assertion offset exceeds haystack",
        ));
    }
    Ok(Some((haystack, at, expected)))
}

fn authority(case: &ParsedCase) -> &'static CaseAuthority {
    &AUTHORITIES[case.authority_index]
}

fn execute_case(
    case: &ParsedCase,
    mode: &RegexAutomataModeExecution,
) -> Result<RegexAutomataExecutionReceipt, InventoryError> {
    if mode.mode_id != COMPILED_UNIT_MODE_ID
        || mode.harness != RegexAutomataHarnessKind::Unit
        || !mode.default_features
        || mode.all_features
    {
        return Err(InventoryError::new(
            "Unicode word-look execution mode mismatch",
        ));
    }
    let authority = authority(case);
    let look = match authority.kind {
        UnicodeWordLookKind::Word => Look::WordUnicode,
        UnicodeWordLookKind::WordNegate => Look::WordUnicodeNegate,
        UnicodeWordLookKind::WordStart => Look::WordStartUnicode,
        UnicodeWordLookKind::WordEnd => Look::WordEndUnicode,
        UnicodeWordLookKind::WordStartHalf => Look::WordStartHalfUnicode,
        UnicodeWordLookKind::WordEndHalf => Look::WordEndHalfUnicode,
    };
    let fre = PortableBuilder::new(authority.pattern)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(true)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .map_err(|error| InventoryError::new(format!("Unicode word-look FRE build: {error}")))?;
    validate_look_fre_plan(&fre).map_err(InventoryError::new)?;
    let mut assertion_executions = Vec::with_capacity(case.vectors.len());
    for vector in &case.vectors {
        assertion_executions.push(execute_vector(&fre, look, vector)?);
    }
    if assertion_executions.len() != case.source.assertions.len()
        || assertion_executions
            .iter()
            .zip(&case.source.assertions)
            .any(|(execution, assertion)| {
                execution.assertion_id != assertion.assertion_id
                    || execution.upstream_observation != assertion.expected_observation
                    || execution.fre_observation != assertion.expected_observation
            })
    {
        return Err(InventoryError::new(
            "Unicode word-look assertion execution binding mismatch",
        ));
    }
    Ok(RegexAutomataExecutionReceipt {
        mode: mode.clone(),
        harness: RegexAutomataHarnessKind::Unit,
        case_id: authority.case_id.to_owned(),
        source: case.source.clone(),
        assertion_executions,
    })
}

fn execute_vector(
    fre: &PortableRegex,
    look: Look,
    vector: &AssertionVector,
) -> Result<RegexAutomataAssertionExecution, InventoryError> {
    let upstream = LookMatcher::default().matches(look, &vector.haystack, vector.at);
    let expected_work: u64 = if vector.expected { 18 } else { 17 };
    let one_below_work = expected_work
        .checked_sub(1)
        .ok_or_else(|| InventoryError::new("Unicode word-look work bound underflow"))?;
    let (matched, accounting) = fre
        .find_window(
            &vector.haystack,
            SearchWindow::new(vector.at, vector.at),
            SearchLimits {
                max_work: MAX_WORK,
                max_scratch_bytes: MAX_SCRATCH_BYTES,
            },
        )
        .map_err(|error| InventoryError::new(format!("Unicode word-look FRE search: {error}")))?;
    let observed_span = matched.map(|matched| (matched.start(), matched.end()));
    let expected_span = vector.expected.then_some((vector.at, vector.at));
    let expected_transition_work = if vector.expected { 4 } else { 3 };
    let expected_initialized_bytes = if usize::BITS == 64 { 96 } else { 56 };
    let exact_accounting = matches!(
        &accounting,
        SearchAccounting::K0(accounting)
            if accounting.work() == expected_work
                && accounting.setup_work() == 14
                && accounting.transition_work() == expected_transition_work
                && accounting.boundaries() == 1
                && accounting.scratch_bytes() <= MAX_SCRATCH_BYTES
                && !accounting.setup().reused()
                && accounting.setup().allocated_bytes() == accounting.setup().retained_bytes()
                && accounting.setup().retained_bytes() == accounting.scratch_bytes()
                && accounting.setup().initialized_bytes() == expected_initialized_bytes
    );
    let one_below = fre.find_window(
        &vector.haystack,
        SearchWindow::new(vector.at, vector.at),
        SearchLimits {
            max_work: one_below_work,
            max_scratch_bytes: MAX_SCRATCH_BYTES,
        },
    );
    let exact_one_below_refusal = matches!(
        one_below,
        Err(fre::SearchError::K0(
            fre::K0SearchError::WorkLimitExceeded {
                limit,
                consumed,
                requested,
                position,
            }
        )) if limit == one_below_work
            && consumed == one_below_work
            && requested == 1
            && position == vector.at
    );
    let (exact_match, exact_accounting_value) = fre
        .find_window(
            &vector.haystack,
            SearchWindow::new(vector.at, vector.at),
            SearchLimits {
                max_work: expected_work,
                max_scratch_bytes: MAX_SCRATCH_BYTES,
            },
        )
        .map_err(|error| {
            InventoryError::new(format!("Unicode word-look exact-limit search: {error}"))
        })?;
    if upstream != vector.expected
        || observed_span != expected_span
        || !exact_accounting
        || !exact_one_below_refusal
        || exact_match != matched
        || exact_accounting_value != accounting
    {
        return Err(InventoryError::new(
            "Unicode word-look triple agreement or resource bound mismatch",
        ));
    }
    Ok(RegexAutomataAssertionExecution {
        assertion_id: vector.assertion_id.clone(),
        upstream_observation: format!("bool:{upstream}"),
        fre_observation: format!("bool:{}", observed_span.is_some()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unicode_word_look_fixture_is_complete_and_exact() {
        validate_fixture().unwrap();
        let cases = parse_cases().unwrap();
        assert_eq!(cases.len(), 6);
        assert_eq!(
            cases
                .iter()
                .map(|case| case.vectors.len())
                .collect::<Vec<_>>(),
            [31, 31, 32, 32, 32, 32],
        );
        assert_eq!(
            cases.iter().map(|case| case.vectors.len()).sum::<usize>(),
            190,
        );
    }

    #[test]
    fn unicode_word_look_parser_rejects_non_assertion_shapes() {
        assert!(
            parse_assertion("assert!(testlook!(look, \"a\", 0));")
                .unwrap()
                .is_some()
        );
        assert!(
            parse_assertion("assert!(!testlook!(look, \"a\", 1));")
                .unwrap()
                .is_some()
        );
        assert!(
            parse_assertion("// assert!(testlook!(look, \"a\", 0));")
                .unwrap()
                .is_none()
        );
        assert!(
            parse_assertion("assert!(testlook!(other, \"a\", 0));")
                .unwrap()
                .is_none()
        );
        assert!(parse_assertion("assert!(testlook!(look, \"a\", x));").is_err());
        assert!(parse_assertion("assert!(testlook!(look, \"a\", 2));").is_err());
    }

    #[test]
    fn unicode_word_look_observers_execute_all_190_assertions() {
        let mode = RegexAutomataModeExecution {
            mode_id: COMPILED_UNIT_MODE_ID.to_owned(),
            harness: RegexAutomataHarnessKind::Unit,
            default_features: true,
            all_features: false,
            features: Vec::new(),
            dependency_package: "regex-automata".to_owned(),
            dependency_version: "0.4.14".to_owned(),
            mode_evidence_sha256: None,
        };
        let cases = parse_cases().unwrap();
        let executions = cases
            .iter()
            .map(|case| execute_case(case, &mode).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            executions
                .iter()
                .map(|execution| execution.assertion_executions.len())
                .sum::<usize>(),
            190,
        );
        assert!(executions.iter().all(|execution| {
            execution
                .assertion_executions
                .iter()
                .all(|assertion| assertion.upstream_observation == assertion.fre_observation)
        }));
    }

    #[test]
    fn unicode_word_look_observers_cover_invalid_bytes_and_utf8_interiors() {
        let haystacks = [
            Vec::new(),
            vec![b'_', b'9', 0xFF, 0xFE, b'a'],
            "𝛃".as_bytes().to_vec(),
        ];
        for authority in AUTHORITIES {
            let look = match authority.kind {
                UnicodeWordLookKind::Word => Look::WordUnicode,
                UnicodeWordLookKind::WordNegate => Look::WordUnicodeNegate,
                UnicodeWordLookKind::WordStart => Look::WordStartUnicode,
                UnicodeWordLookKind::WordEnd => Look::WordEndUnicode,
                UnicodeWordLookKind::WordStartHalf => Look::WordStartHalfUnicode,
                UnicodeWordLookKind::WordEndHalf => Look::WordEndHalfUnicode,
            };
            let fre = PortableBuilder::new(authority.pattern)
                .profile(RustProfile::rebar_1_12_4())
                .unicode(true)
                .plan_selection(PlanSelection::ForceK0)
                .build()
                .unwrap();
            for haystack in &haystacks {
                for at in 0..=haystack.len() {
                    let expected = LookMatcher::default().matches(look, haystack, at);
                    let vector = AssertionVector {
                        assertion_id: "supplemental-byte-boundary".to_owned(),
                        haystack: haystack.clone(),
                        at,
                        expected,
                    };
                    execute_vector(&fre, look, &vector).unwrap();
                }
            }
        }
    }

    #[test]
    fn unicode_word_look_transition_contract_rejects_stale_or_malformed_identity() {
        assert_eq!(
            PREDECESSOR_REVISION,
            "119c1a3c2b1b53a3e80dcdbc9dc637ee5c843e11"
        );
        assert_eq!(PREDECESSOR_TREE, "088c1ee0e444bfff59a8a8ca956df93d51408b3b");
        assert_eq!(PREDECESSOR_PAYLOAD_SHA256.len(), 64);
        assert_ne!(
            PREDECESSOR_REVISION,
            "3bae1dac5e5d06de56aab0310b373d4d3af3a36b"
        );
        assert_ne!(PREDECESSOR_TREE, "254f84cdc256cadaa18f89babb9f81b437225518");
        assert_eq!(TARGET_IDENTITIES_SHA256.len(), 64);
        assert!(
            UNICODE_WORD_LOOK_REPORT_LIMITATIONS
                .iter()
                .any(|text| text.contains("135-membership"))
        );
    }

    #[test]
    fn unicode_word_look_target_set_is_exactly_six_unique_authorities() {
        let ids = AUTHORITIES
            .iter()
            .map(|authority| authority.case_id)
            .collect::<BTreeSet<_>>();
        assert_eq!(ids.len(), 6);
        assert_eq!(AUTHORITIES.len(), 6);
        assert!(AUTHORITIES.iter().all(|authority| {
            authority.pattern.contains("\\b") || authority.pattern.contains("\\B")
        }));
    }
}
