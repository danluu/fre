//! Authenticated package-default execution for the six ASCII word-look unit
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
    ALL_MODE_LOOK_REPORT_LIMITATIONS, COMPILED_UNIT_MODE_ID, INVENTORY_UNSUPPORTED_REASON,
    LOOK_SOURCE_PATH, LOOK_SOURCE_SHA256, REGEX_AUTOMATA_ALL_MODE_LOOK_REPORT_SCHEMA,
    RegexAutomataAdapterCounts, RegexAutomataAdapterDisposition, RegexAutomataAdapterReport,
    RegexAutomataAdapterReportPayload, RegexAutomataAssertionContract,
    RegexAutomataAssertionExecution, RegexAutomataCorpusReport, RegexAutomataExecutionReceipt,
    RegexAutomataHarnessKind, RegexAutomataModeExecution, RegexAutomataSourceContract,
    RegexAutomataStrictGain, adapter_counts, gain_vectors, hash_json, mode_execution,
    obligation_membership_identity, order_execution_receipts, validate_candidate,
    validate_execution_receipt_order, validate_look_fre_plan,
};
use crate::{CandidateIdentity, InventoryError};

/// Report schema for the exact package-default six-case ASCII word-look gain.
pub const REGEX_AUTOMATA_ASCII_WORD_LOOK_REPORT_SCHEMA: &str =
    "fre.regex-automata-0.4.14.adapter-report.v5";

pub(super) const ASCII_WORD_LOOK_REPORT_LIMITATIONS: [&str; 3] = [
    "A pass requires direct triple agreement between the authenticated upstream LookMatcher assertion, a forced-K0 FRE search at the exact empty window, and the sealed expected observation.",
    "Only six package-default ASCII word-look unit memberships are added; no result is projected across Cargo feature modes.",
    "The predecessor 129-membership all-mode look report, including its compiled-mode matrix and every non-target disposition, is retained exactly.",
];

const PREDECESSOR_REVISION: &str = "3bae1dac5e5d06de56aab0310b373d4d3af3a36b";
const PREDECESSOR_TREE: &str = "254f84cdc256cadaa18f89babb9f81b437225518";
const PREDECESSOR_PAYLOAD_SHA256: &str =
    "68f99dcab8ad2d16555977799e730ee29f75ba8419aeb1abc7b88145c739f493";
const FIXTURE: &str = include_str!("../fixtures/look-ascii-word-tests-v1.txt");
const FIXTURE_SHA256: &str = "86271cfb8c542d5811f86db1016b9286eecc1c99f52dfd491da0dcb675a725a1";
const TARGET_IDENTITIES_SHA256: &str =
    "b5a07f562eda77091b465625b06167ad3d856fac2c076910676e1779d4a2bf8c";
const MAX_WORK: u64 = 18;
const MAX_SCRATCH_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AsciiWordLookKind {
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
    kind: AsciiWordLookKind,
    pattern: &'static str,
    span_start_line: usize,
    span_end_line: usize,
    span_sha256: &'static str,
    assertion_inventory_sha256: &'static str,
}

const AUTHORITIES: [CaseAuthority; 6] = [
    CaseAuthority {
        case_id: "util::look::tests::look_matches_word_ascii",
        function_name: "look_matches_word_ascii",
        assertion_prefix: "word-ascii",
        kind: AsciiWordLookKind::Word,
        pattern: r"(?-u:\b)",
        span_start_line: 1_821,
        span_end_line: 1_872,
        span_sha256: "9139e8466ad196a8cac8e2ef89dfce47dd9b6cf0eb89a1590d5d058c6a0d9efe",
        assertion_inventory_sha256: "b271fab91eb8a2ecefbefe353e66639dbfa52061214f2e16ddbe289117b5123a",
    },
    CaseAuthority {
        case_id: "util::look::tests::look_matches_word_ascii_negate",
        function_name: "look_matches_word_ascii_negate",
        assertion_prefix: "word-ascii-negate",
        kind: AsciiWordLookKind::WordNegate,
        pattern: r"(?-u:\B)",
        span_start_line: 1_933,
        span_end_line: 1_984,
        span_sha256: "69609e7522c9136b26322c77f5c6ad4c3c5b72323b26816eb8d321184da0927f",
        assertion_inventory_sha256: "323af4021825a18b0bc2c50a80f9b2e66ec8da65e77884458edeb51a7d7fb5c1",
    },
    CaseAuthority {
        case_id: "util::look::tests::look_matches_word_end_ascii",
        function_name: "look_matches_word_end_ascii",
        assertion_prefix: "word-end-ascii",
        kind: AsciiWordLookKind::WordEnd,
        pattern: r"(?-u:\b{end})",
        span_start_line: 2_040,
        span_end_line: 2_092,
        span_sha256: "cddf5cb7306209ed1e61375f1efbeac8945470164dd980b7bb7d5015b9dbf2a3",
        assertion_inventory_sha256: "249a68d18495fa0e2a77dd0b65b485176edf9f463bf152d9d0bc9e56b7aa1948",
    },
    CaseAuthority {
        case_id: "util::look::tests::look_matches_word_end_half_ascii",
        function_name: "look_matches_word_end_half_ascii",
        assertion_prefix: "word-end-half-ascii",
        kind: AsciiWordLookKind::WordEndHalf,
        pattern: r"(?-u:\b{end-half})",
        span_start_line: 2_254,
        span_end_line: 2_306,
        span_sha256: "ce8cbad7f01edf0eb309dd6a9f5944e301adfce0e8cd485d038e6507409a65f9",
        assertion_inventory_sha256: "54f959d253aa6027aa487fe6e4c68c250819d9f17c1a4921a2c8510ad686ad96",
    },
    CaseAuthority {
        case_id: "util::look::tests::look_matches_word_start_ascii",
        function_name: "look_matches_word_start_ascii",
        assertion_prefix: "word-start-ascii",
        kind: AsciiWordLookKind::WordStart,
        pattern: r"(?-u:\b{start})",
        span_start_line: 1_986,
        span_end_line: 2_038,
        span_sha256: "a84eb5576776135e00400c6b94af59ff12bfa37f984f3564651614e48c0fbe3a",
        assertion_inventory_sha256: "6ac854d43e75fde335eaf6df2146488b4b46f300ed221ddf290d1ff48d8aa241",
    },
    CaseAuthority {
        case_id: "util::look::tests::look_matches_word_start_half_ascii",
        function_name: "look_matches_word_start_half_ascii",
        assertion_prefix: "word-start-half-ascii",
        kind: AsciiWordLookKind::WordStartHalf,
        pattern: r"(?-u:\b{start-half})",
        span_start_line: 2_200,
        span_end_line: 2_252,
        span_sha256: "46fb3b6d1dce2185bb00be7d8ada2fa00d70e32786dec3dbb9c7b92aa0ec7bf7",
        assertion_inventory_sha256: "80b92331a571cde075fdd592a4feab482f6f25b8194c156b1f3a958e5238f9f0",
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

/// Extend the exact 129-pass report with the six independently executed
/// package-default ASCII word-look memberships.
pub fn build_regex_automata_ascii_word_look_report(
    inventory: &RegexAutomataCorpusReport,
    previous: &RegexAutomataAdapterReport,
    candidate: CandidateIdentity,
) -> Result<RegexAutomataAdapterReport, InventoryError> {
    validate_predecessor(inventory, previous)?;
    validate_candidate(&candidate)?;
    if candidate.revision == PREDECESSOR_REVISION || candidate.tree == PREDECESSOR_TREE {
        return Err(InventoryError::new(
            "ASCII word-look candidate is not distinct from its predecessor",
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
            .ok_or_else(|| InventoryError::new("ASCII word-look target lacks its parsed case"))?;
        let execution = execute_case(case, &mode)?;
        let evidence_sha256 = hash_json(&execution, "encode ASCII word-look execution")?;
        receipt.disposition = RegexAutomataAdapterDisposition::Pass { evidence_sha256 };
        execution_receipts.push(execution);
        observed_targets.insert(identity);
    }
    if observed_targets != targets {
        return Err(InventoryError::new(
            "ASCII word-look inventory target denominator mismatch",
        ));
    }
    let execution_receipts =
        order_execution_receipts(&receipts, execution_receipts, "ASCII word-look report")?;
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
        start_mode_matrix: None,
        start_mode_baseline: None,
        limitations: ASCII_WORD_LOOK_REPORT_LIMITATIONS
            .iter()
            .map(|text| (*text).to_owned())
            .collect(),
    };
    let report = RegexAutomataAdapterReport {
        schema: REGEX_AUTOMATA_ASCII_WORD_LOOK_REPORT_SCHEMA.to_owned(),
        payload_sha256: hash_json(&payload, "encode ASCII word-look report payload")?,
        payload,
    };
    validate_ascii_word_look_execution_after_structure(inventory, &report)?;
    Ok(report)
}

/// Require an exact 129 -> 135 transition with every non-target receipt and
/// execution preserved from the authenticated predecessor.
pub fn validate_regex_automata_ascii_word_look_strict_gain(
    inventory: &RegexAutomataCorpusReport,
    previous: &RegexAutomataAdapterReport,
    current: &RegexAutomataAdapterReport,
) -> Result<RegexAutomataStrictGain, InventoryError> {
    validate_predecessor(inventory, previous)?;
    current.validate_structure(inventory)?;
    if current.schema != REGEX_AUTOMATA_ASCII_WORD_LOOK_REPORT_SCHEMA {
        return Err(InventoryError::new(
            "current report is not an ASCII word-look report",
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
            "ASCII word-look gain is not exact six-membership progress",
        ));
    }
    Ok(RegexAutomataStrictGain {
        family: "unit-util".to_owned(),
        gained_unique_cases,
        gained_mode_memberships,
        previous_pass: 129,
        current_pass: 135,
    })
}

pub(super) fn validate_ascii_word_look_execution_after_structure(
    inventory: &RegexAutomataCorpusReport,
    report: &RegexAutomataAdapterReport,
) -> Result<(), InventoryError> {
    if report.schema != REGEX_AUTOMATA_ASCII_WORD_LOOK_REPORT_SCHEMA
        || report.payload.counts
            != (RegexAutomataAdapterCounts {
                pass: 135,
                unsupported: 3_707,
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
            "ASCII word-look candidate identity or cardinality mismatch",
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
    if previous_executions.len() != 129 || current_executions.len() != 135 {
        return Err(InventoryError::new(
            "ASCII word-look execution denominator mismatch",
        ));
    }
    for (identity, execution) in &previous_executions {
        if current_executions.get(identity) != Some(execution) {
            return Err(InventoryError::new(
                "ASCII word-look report changed retained execution evidence",
            ));
        }
    }
    for identity in &targets {
        let execution = current_executions.get(identity).ok_or_else(|| {
            InventoryError::new("ASCII word-look target lacks execution evidence")
        })?;
        let case = cases
            .iter()
            .find(|case| authority(case).case_id == identity.2)
            .ok_or_else(|| InventoryError::new("ASCII word-look target lacks source authority"))?;
        let expected = execute_case(case, &mode)?;
        if *execution != &expected {
            return Err(InventoryError::new(
                "ASCII word-look execution evidence mismatch",
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
            .ok_or_else(|| InventoryError::new("ASCII word-look target receipt is absent"))?;
        let expected_hash = hash_json(execution, "encode ASCII word-look execution")?;
        if !matches!(
            &receipt.disposition,
            RegexAutomataAdapterDisposition::Pass { evidence_sha256 }
                if *evidence_sha256 == expected_hash
        ) {
            return Err(InventoryError::new(
                "ASCII word-look pass is not bound to its execution receipt",
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
    if report.schema != REGEX_AUTOMATA_ALL_MODE_LOOK_REPORT_SCHEMA
        || report.payload_sha256 != PREDECESSOR_PAYLOAD_SHA256
        || report.payload.candidate
            != (CandidateIdentity {
                revision: PREDECESSOR_REVISION.to_owned(),
                tree: PREDECESSOR_TREE.to_owned(),
                tracked_and_untracked_worktree_clean: true,
            })
        || report.payload.counts
            != (RegexAutomataAdapterCounts {
                pass: 129,
                unsupported: 3_713,
                fault: 0,
                total: 3_842,
            })
    {
        return Err(InventoryError::new(
            "ASCII word-look predecessor authority mismatch",
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
        .push_str(REGEX_AUTOMATA_ALL_MODE_LOOK_REPORT_SCHEMA);
    previous.payload.candidate = CandidateIdentity {
        revision: PREDECESSOR_REVISION.to_owned(),
        tree: PREDECESSOR_TREE.to_owned(),
        tracked_and_untracked_worktree_clean: true,
    };
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
    previous.payload.limitations = ALL_MODE_LOOK_REPORT_LIMITATIONS
        .iter()
        .map(|text| (*text).to_owned())
        .collect();
    previous.payload_sha256 = hash_json(
        &previous.payload,
        "encode reconstructed all-mode look payload",
    )?;
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
            "ASCII word-look target identity seal mismatch",
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
    if FIXTURE.len() != 12_846
        || FIXTURE.split_inclusive('\n').count() != 316
        || !FIXTURE.ends_with('\n')
        || FIXTURE.contains(['\0', '\r'])
        || crate::sha256(FIXTURE.as_bytes()) != FIXTURE_SHA256
    {
        return Err(InventoryError::new(
            "ASCII word-look fixture identity mismatch",
        ));
    }
    for authority in AUTHORITIES {
        let signature = format!("    fn {}() {{", authority.function_name);
        if FIXTURE.matches(&signature).count() != 1 {
            return Err(InventoryError::new(
                "ASCII word-look fixture function denominator mismatch",
            ));
        }
    }
    Ok(())
}

fn parse_case(
    authority_index: usize,
    authority: &CaseAuthority,
) -> Result<ParsedCase, InventoryError> {
    let marker = format!("    #[test]\n    fn {}() {{\n", authority.function_name);
    let start = FIXTURE
        .find(&marker)
        .ok_or_else(|| InventoryError::new("ASCII word-look fixture lacks case marker"))?;
    let tail = &FIXTURE[start..];
    let close = tail
        .find("\n    }\n")
        .and_then(|offset| offset.checked_add("\n    }\n".len()))
        .ok_or_else(|| InventoryError::new("ASCII word-look fixture lacks case terminator"))?;
    let source_span = &tail[..close];
    let expected_lines = authority
        .span_end_line
        .checked_sub(authority.span_start_line)
        .and_then(|count| count.checked_add(1))
        .ok_or_else(|| InventoryError::new("ASCII word-look source line range overflow"))?;
    if source_span.split_inclusive('\n').count() != expected_lines
        || crate::sha256(source_span.as_bytes()) != authority.span_sha256
    {
        return Err(InventoryError::new(
            "ASCII word-look source-span authority mismatch",
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
            .ok_or_else(|| InventoryError::new("ASCII word-look assertion count overflow"))?;
        let assertion_id = format!("{}-{ordinal:02}", authority.assertion_prefix);
        let source_line = authority
            .span_start_line
            .checked_add(offset)
            .ok_or_else(|| InventoryError::new("ASCII word-look source line overflow"))?;
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
        hash_json(&assertions, "encode ASCII word-look assertion inventory")?;
    if assertions.len() != vectors.len()
        || assertions.is_empty()
        || assertion_inventory_sha256 != authority.assertion_inventory_sha256
    {
        return Err(InventoryError::new(
            "ASCII word-look assertion inventory mismatch",
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
        .ok_or_else(|| InventoryError::new("ASCII word-look assertion suffix mismatch"))?;
    let split = body
        .rfind(", ")
        .ok_or_else(|| InventoryError::new("ASCII word-look assertion lacks offset"))?;
    let (literal, offset) = body.split_at(split);
    let at = offset[2..]
        .parse::<usize>()
        .map_err(|_| InventoryError::new("ASCII word-look assertion offset is invalid"))?;
    let haystack = serde_json::from_str::<String>(literal)
        .map_err(|_| InventoryError::new("ASCII word-look haystack literal is invalid"))?
        .into_bytes();
    if at > haystack.len() {
        return Err(InventoryError::new(
            "ASCII word-look assertion offset exceeds haystack",
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
            "ASCII word-look execution mode mismatch",
        ));
    }
    let authority = authority(case);
    let look = match authority.kind {
        AsciiWordLookKind::Word => Look::WordAscii,
        AsciiWordLookKind::WordNegate => Look::WordAsciiNegate,
        AsciiWordLookKind::WordStart => Look::WordStartAscii,
        AsciiWordLookKind::WordEnd => Look::WordEndAscii,
        AsciiWordLookKind::WordStartHalf => Look::WordStartHalfAscii,
        AsciiWordLookKind::WordEndHalf => Look::WordEndHalfAscii,
    };
    let mut assertion_executions = Vec::with_capacity(case.vectors.len());
    for vector in &case.vectors {
        // Each assertion authenticates its own cold proof publication before
        // the exact warm and one-below calls. Reusing one plan across vectors
        // would make accounting depend on fixture order.
        let fre = PortableBuilder::new(authority.pattern)
            .profile(RustProfile::rebar_1_12_4())
            .unicode(false)
            .plan_selection(PlanSelection::ForceK0)
            .build()
            .map_err(|error| InventoryError::new(format!("ASCII word-look FRE build: {error}")))?;
        validate_look_fre_plan(&fre).map_err(InventoryError::new)?;
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
            "ASCII word-look assertion execution binding mismatch",
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
        .ok_or_else(|| InventoryError::new("ASCII word-look work bound underflow"))?;
    let (cold_matched, cold_accounting) = fre
        .find_window(
            &vector.haystack,
            SearchWindow::new(vector.at, vector.at),
            SearchLimits::unlimited(),
        )
        .map_err(|error| {
            InventoryError::new(format!("ASCII word-look FRE cold search: {error}"))
        })?;
    let (matched, accounting) = fre
        .find_window(
            &vector.haystack,
            SearchWindow::new(vector.at, vector.at),
            SearchLimits {
                max_work: MAX_WORK,
                max_scratch_bytes: MAX_SCRATCH_BYTES,
            },
        )
        .map_err(|error| InventoryError::new(format!("ASCII word-look FRE search: {error}")))?;
    let observed_span = matched.map(|matched| (matched.start(), matched.end()));
    let expected_span = vector.expected.then_some((vector.at, vector.at));
    let expected_transition_work = if vector.expected { 4 } else { 3 };
    let expected_initialized_bytes = if usize::BITS == 64 { 96 } else { 56 };
    let exact_cold_accounting = match (&cold_accounting, &accounting) {
        (SearchAccounting::K0(cold), SearchAccounting::K0(warm)) => {
            let proof_bytes = cold
                .setup()
                .allocated_bytes()
                .checked_sub(warm.setup().allocated_bytes());
            let transition_delta = cold.transition_work().checked_sub(warm.transition_work());
            proof_bytes
                .zip(transition_delta)
                .is_some_and(|(proof_bytes, transition_delta)| {
                    proof_bytes > 0
                        && cold.setup_work() == warm.setup_work() + 1
                        && cold.work().checked_sub(warm.work())
                            == 1_u64.checked_add(transition_delta)
                        && cold.boundaries() == warm.boundaries()
                        && !cold.setup().reused()
                        && cold.setup().retained_bytes() == warm.setup().retained_bytes()
                        && cold
                            .setup()
                            .initialized_bytes()
                            .checked_sub(warm.setup().initialized_bytes())
                            == Some(proof_bytes)
                        && cold.scratch_bytes().checked_sub(warm.scratch_bytes())
                            == Some(proof_bytes)
                })
        }
        _ => false,
    };
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
            InventoryError::new(format!("ASCII word-look exact-limit search: {error}"))
        })?;
    if upstream != vector.expected
        || cold_matched != matched
        || observed_span != expected_span
        || !exact_cold_accounting
        || !exact_accounting
        || !exact_one_below_refusal
        || exact_match != matched
        || exact_accounting_value != accounting
    {
        return Err(InventoryError::new(
            "ASCII word-look triple agreement or resource bound mismatch",
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
    fn ascii_word_look_fixture_is_complete_and_exact() {
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
    fn ascii_word_look_parser_rejects_non_assertion_shapes() {
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
    fn ascii_word_look_observers_execute_all_190_assertions() {
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
    fn ascii_word_look_observers_cover_invalid_bytes_and_utf8_interiors() {
        let haystacks = [
            Vec::new(),
            vec![b'_', b'9', 0xFF, 0xFE, b'a'],
            "𝛃".as_bytes().to_vec(),
        ];
        for authority in AUTHORITIES {
            let look = match authority.kind {
                AsciiWordLookKind::Word => Look::WordAscii,
                AsciiWordLookKind::WordNegate => Look::WordAsciiNegate,
                AsciiWordLookKind::WordStart => Look::WordStartAscii,
                AsciiWordLookKind::WordEnd => Look::WordEndAscii,
                AsciiWordLookKind::WordStartHalf => Look::WordStartHalfAscii,
                AsciiWordLookKind::WordEndHalf => Look::WordEndHalfAscii,
            };
            for haystack in &haystacks {
                for at in 0..=haystack.len() {
                    let fre = PortableBuilder::new(authority.pattern)
                        .profile(RustProfile::rebar_1_12_4())
                        .unicode(false)
                        .plan_selection(PlanSelection::ForceK0)
                        .build()
                        .unwrap();
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
}
