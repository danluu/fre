//! Authenticated package-default execution for the first genuinely
//! FRE-observable unit identity after the sealed 145-membership report.
//!
//! Earlier unsupported unit identities cover upstream-specific trait object
//! safety, DFA configuration, serialization and internal representation.
//! They are deliberately left unsupported. This module begins at the first
//! direct regex search assertion: a Rebar-discovered suffix-literal iteration
//! regression whose exact span and count are both observable through FRE's
//! public portable iterator.

use std::collections::{BTreeMap, BTreeSet};

use fre::{
    K0SearchError, PlanSelection, PortableBuilder, PortableFindIterError, PortableFindIterLimits,
    PortableRegex, RustProfile, SearchAccounting, SearchError, SearchLimits, SearchSessionLimits,
};
use regex_automata::meta::Regex as UpstreamRegex;

use super::{
    COMPILED_UNIT_MODE_ID, INVENTORY_UNSUPPORTED_REASON, RegexAutomataAdapterCounts,
    RegexAutomataAdapterDisposition, RegexAutomataAdapterReport, RegexAutomataAdapterReportPayload,
    RegexAutomataAssertionContract, RegexAutomataAssertionExecution, RegexAutomataCorpusReport,
    RegexAutomataExecutionReceipt, RegexAutomataHarnessKind, RegexAutomataModeExecution,
    RegexAutomataSourceContract, RegexAutomataStrictGain, adapter_counts, gain_vectors, hash_json,
    mode_execution, obligation_membership_identity, order_execution_receipts,
    start_map::{REGEX_AUTOMATA_START_MAP_REPORT_SCHEMA, START_MAP_REPORT_LIMITATIONS},
    validate_candidate, validate_execution_receipt_order,
};
use crate::{CandidateIdentity, InventoryError};

/// Report schema for the exact package-default suffix-literal iteration gain.
pub const REGEX_AUTOMATA_SUFFIX_LITERAL_COUNT_REPORT_SCHEMA: &str =
    "fre.regex-automata-0.4.14.adapter-report.v10";

pub(super) const SUFFIX_LITERAL_COUNT_REPORT_LIMITATIONS: [&str; 3] = [
    "A pass requires exact upstream/FRE agreement on the sole full match span and non-overlapping iterator count under bounded execution.",
    "Only the package-default meta::regex::tests::regression_suffix_literal_count membership is added; upstream-only API and representation tests remain unsupported.",
    "The predecessor 145-membership start-map report, including every prior execution receipt and its compiled-mode matrix, is retained exactly.",
];

const PREDECESSOR_REVISION: &str = "0ca8e30ae6fd2684e6e563c0da16d0078c5667c4";
const PREDECESSOR_TREE: &str = "dd32884fd7dc590a98fac16301aba76d6127f218";
const PREDECESSOR_PAYLOAD_SHA256: &str =
    "abed75cf301d4675034edb5414b958ae85046b22cdc53b3dfcf3f1ea721941eb";
const CASE_ID: &str = "meta::regex::tests::regression_suffix_literal_count";
const REJECTED_OBJECT_SAFE_CASE_ID: &str = "dfa::automaton::tests::object_safe";
const TARGET_IDENTITIES_SHA256: &str =
    "f0f1cb4ba12d26a3ecd7680dfb4f18a3bd5d56cf1fd0541cf1085b93e4078bad";
const SOURCE_PATH: &str = "src/meta/regex.rs";
const SOURCE_SHA256: &str = "92295ff6a6b1e0e6d19fc1fe29679fa5681973160ee61e043d29bf29f44a65b5";
const SOURCE_SPAN: &str = r#"    // I found this in the course of building out the benchmark suite for
    // rebar.
    #[test]
    fn regression_suffix_literal_count() {
        let _ = env_logger::try_init();

        let re = Regex::new(r"[a-zA-Z]+ing").unwrap();
        assert_eq!(1, re.find_iter("tingling").count());
    }
"#;
const SOURCE_SPAN_SHA256: &str = "a04a8fc69cfc42857ad84ca8dc9725ed0fd87569b715dcc17748f54c3f0649cb";
const ASSERTION_LINE_SHA256: &str =
    "33f0c07041bd1f61b850dede1914bc2b83613fd592950b1df2212e2daf53ecc8";
const ASSERTION_INVENTORY_SHA256: &str =
    "84b697cedfeb026338d3d4cd3483d98a136e785e1a360f6ac1dd141389e77863";
const PATTERN: &str = r"[a-zA-Z]+ing";
const HAYSTACK: &[u8] = b"tingling";
const EXPECTED_SPANS: [(usize, usize); 1] = [(0, 8)];
const MAX_SEARCH_CALLS: usize = 2;
const MAX_SEARCH_WORK: u64 = 349;
const MAX_SCRATCH_BYTES: usize = 8 * 1024 * 1024;
// Fixed after direct execution and checked by the observer test.
const EXPECTED_FIRST_WORK: u64 = 349;
const EXPECTED_TAIL_WORK: u64 = 29;
const EXPECTED_MINIMUM_FIRST_WORK: u64 = 348;
const EXPECTED_ITER_WORK: u64 = 102;

/// Extend the exact 145-pass report with one independently executed unit
/// membership.
pub fn build_regex_automata_suffix_literal_count_report(
    inventory: &RegexAutomataCorpusReport,
    previous: &RegexAutomataAdapterReport,
    candidate: CandidateIdentity,
) -> Result<RegexAutomataAdapterReport, InventoryError> {
    validate_predecessor(inventory, previous)?;
    validate_candidate(&candidate)?;
    if candidate.revision == PREDECESSOR_REVISION || candidate.tree == PREDECESSOR_TREE {
        return Err(InventoryError::new(
            "suffix-literal candidate is not distinct from its predecessor",
        ));
    }
    let target = target_identity(inventory)?;
    let execution =
        execute_suffix_literal_count(&mode_execution(inventory, COMPILED_UNIT_MODE_ID)?)?;
    let evidence_sha256 = hash_json(&execution, "encode suffix-literal execution")?;
    let mut receipts = previous.payload.receipts.clone();
    let mut changed = 0_usize;
    for receipt in &mut receipts {
        if (
            receipt.mode_id.as_str(),
            receipt.harness,
            receipt.case_id.as_str(),
        ) != (target.0.as_str(), target.1, target.2.as_str())
        {
            continue;
        }
        if !matches!(
            &receipt.disposition,
            RegexAutomataAdapterDisposition::Unsupported { reason_code }
                if reason_code == INVENTORY_UNSUPPORTED_REASON
        ) {
            return Err(InventoryError::new(
                "suffix-literal predecessor target is not unsupported",
            ));
        }
        receipt.disposition = RegexAutomataAdapterDisposition::Pass {
            evidence_sha256: evidence_sha256.clone(),
        };
        changed = changed
            .checked_add(1)
            .ok_or_else(|| InventoryError::new("suffix-literal target count overflow"))?;
    }
    if changed != 1 {
        return Err(InventoryError::new(
            "suffix-literal inventory target denominator mismatch",
        ));
    }
    let mut execution_receipts = previous.payload.execution_receipts.clone();
    execution_receipts.push(execution);
    let execution_receipts =
        order_execution_receipts(&receipts, execution_receipts, "suffix-literal count report")?;
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
        limitations: SUFFIX_LITERAL_COUNT_REPORT_LIMITATIONS
            .iter()
            .map(|text| (*text).to_owned())
            .collect(),
    };
    let report = RegexAutomataAdapterReport {
        schema: REGEX_AUTOMATA_SUFFIX_LITERAL_COUNT_REPORT_SCHEMA.to_owned(),
        payload_sha256: hash_json(&payload, "encode suffix-literal report payload")?,
        payload,
    };
    validate_suffix_literal_count_execution_after_structure(inventory, &report)?;
    Ok(report)
}

/// Require an exact 145 -> 146 transition with no pass loss and no non-target
/// disposition change.
pub fn validate_regex_automata_suffix_literal_count_strict_gain(
    inventory: &RegexAutomataCorpusReport,
    previous: &RegexAutomataAdapterReport,
    current: &RegexAutomataAdapterReport,
) -> Result<RegexAutomataStrictGain, InventoryError> {
    validate_predecessor(inventory, previous)?;
    current.validate_structure(inventory)?;
    if current.schema != REGEX_AUTOMATA_SUFFIX_LITERAL_COUNT_REPORT_SCHEMA {
        return Err(InventoryError::new(
            "current report is not a suffix-literal count report",
        ));
    }
    let targets = BTreeSet::from([target_identity(inventory)?]);
    let (gained_unique_cases, gained_mode_memberships) = gain_vectors(
        &previous.payload.receipts,
        &current.payload.receipts,
        &targets,
    )?;
    if (gained_unique_cases, gained_mode_memberships) != (1, 1)
        || previous.payload.counts.pass != 145
        || current.payload.counts.pass != 146
    {
        return Err(InventoryError::new(
            "suffix-literal gain is not exact one-membership progress",
        ));
    }
    Ok(RegexAutomataStrictGain {
        family: "unit-meta-regex".to_owned(),
        gained_unique_cases,
        gained_mode_memberships,
        previous_pass: 145,
        current_pass: 146,
    })
}

pub(super) fn validate_suffix_literal_count_execution_after_structure(
    inventory: &RegexAutomataCorpusReport,
    report: &RegexAutomataAdapterReport,
) -> Result<(), InventoryError> {
    if report.schema != REGEX_AUTOMATA_SUFFIX_LITERAL_COUNT_REPORT_SCHEMA
        || report.payload.counts
            != (RegexAutomataAdapterCounts {
                pass: 146,
                unsupported: 3_696,
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
            "suffix-literal candidate identity or cardinality mismatch",
        ));
    }
    validate_execution_receipt_order(report)?;
    let target = target_identity(inventory)?;
    let previous = reconstruct_predecessor(report, &target)?;
    validate_predecessor(inventory, &previous)?;
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
    if previous.payload.execution_receipts.len() != 145
        || report.payload.execution_receipts.len() != 146
        || previous_executions.len() != 145
        || current_executions.len() != 146
    {
        return Err(InventoryError::new(
            "suffix-literal execution denominator mismatch",
        ));
    }
    for (identity, execution) in &previous_executions {
        if current_executions.get(identity) != Some(execution) {
            return Err(InventoryError::new(
                "suffix-literal report changed retained execution evidence",
            ));
        }
    }
    let execution = current_executions
        .get(&target)
        .ok_or_else(|| InventoryError::new("suffix-literal execution evidence is absent"))?;
    let expected =
        execute_suffix_literal_count(&mode_execution(inventory, COMPILED_UNIT_MODE_ID)?)?;
    if *execution != &expected {
        return Err(InventoryError::new(
            "suffix-literal execution evidence mismatch",
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
            ) == (target.0.as_str(), target.1, target.2.as_str())
        })
        .ok_or_else(|| InventoryError::new("suffix-literal target receipt is absent"))?;
    let expected_hash = hash_json(execution, "encode suffix-literal execution")?;
    if !matches!(
        &receipt.disposition,
        RegexAutomataAdapterDisposition::Pass { evidence_sha256 }
            if *evidence_sha256 == expected_hash
    ) {
        return Err(InventoryError::new(
            "suffix-literal pass is not bound to its execution receipt",
        ));
    }
    Ok(())
}

fn validate_predecessor(
    inventory: &RegexAutomataCorpusReport,
    report: &RegexAutomataAdapterReport,
) -> Result<(), InventoryError> {
    report.validate_structure(inventory)?;
    if report.schema != REGEX_AUTOMATA_START_MAP_REPORT_SCHEMA
        || report.payload_sha256 != PREDECESSOR_PAYLOAD_SHA256
        || report.payload.candidate
            != (CandidateIdentity {
                revision: PREDECESSOR_REVISION.to_owned(),
                tree: PREDECESSOR_TREE.to_owned(),
                tracked_and_untracked_worktree_clean: true,
            })
        || report.payload.counts
            != (RegexAutomataAdapterCounts {
                pass: 145,
                unsupported: 3_697,
                fault: 0,
                total: 3_842,
            })
    {
        return Err(InventoryError::new(
            "suffix-literal predecessor authority mismatch",
        ));
    }
    Ok(())
}

fn reconstruct_predecessor(
    report: &RegexAutomataAdapterReport,
    target: &(String, RegexAutomataHarnessKind, String),
) -> Result<RegexAutomataAdapterReport, InventoryError> {
    let mut previous = report.clone();
    REGEX_AUTOMATA_START_MAP_REPORT_SCHEMA.clone_into(&mut previous.schema);
    previous.payload.candidate = CandidateIdentity {
        revision: PREDECESSOR_REVISION.to_owned(),
        tree: PREDECESSOR_TREE.to_owned(),
        tracked_and_untracked_worktree_clean: true,
    };
    for receipt in &mut previous.payload.receipts {
        if (
            receipt.mode_id.as_str(),
            receipt.harness,
            receipt.case_id.as_str(),
        ) == (target.0.as_str(), target.1, target.2.as_str())
        {
            receipt.disposition = RegexAutomataAdapterDisposition::Unsupported {
                reason_code: INVENTORY_UNSUPPORTED_REASON.to_owned(),
            };
        }
    }
    previous
        .payload
        .execution_receipts
        .retain(|execution| execution_identity(execution) != *target);
    previous.payload.counts = adapter_counts(&previous.payload.receipts);
    previous.payload.limitations = START_MAP_REPORT_LIMITATIONS
        .iter()
        .map(|text| (*text).to_owned())
        .collect();
    previous.payload_sha256 =
        hash_json(&previous.payload, "encode reconstructed start-map payload")?;
    if previous.payload_sha256 != PREDECESSOR_PAYLOAD_SHA256 {
        return Err(InventoryError::new(
            "reconstructed suffix-literal predecessor payload SHA-256 mismatch",
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

fn target_identity(
    inventory: &RegexAutomataCorpusReport,
) -> Result<(String, RegexAutomataHarnessKind, String), InventoryError> {
    validate_source_authority(inventory)?;
    let identity = (
        COMPILED_UNIT_MODE_ID.to_owned(),
        RegexAutomataHarnessKind::Unit,
        CASE_ID.to_owned(),
    );
    let canonical = format!("{}\tunit\t{}\n", identity.0, identity.2);
    let inventory_identities = inventory
        .payload
        .obligations
        .iter()
        .map(obligation_membership_identity)
        .collect::<BTreeSet<_>>();
    if crate::sha256(canonical.as_bytes()) != TARGET_IDENTITIES_SHA256
        || !inventory_identities.contains(&identity)
    {
        return Err(InventoryError::new(
            "suffix-literal target identity seal mismatch",
        ));
    }
    Ok(identity)
}

fn source_contract() -> Result<RegexAutomataSourceContract, InventoryError> {
    validate_fixture()?;
    Ok(RegexAutomataSourceContract {
        source_path: SOURCE_PATH.to_owned(),
        source_sha256: SOURCE_SHA256.to_owned(),
        span_start_line: 3_697,
        span_end_line: 3_705,
        source_span_sha256: SOURCE_SPAN_SHA256.to_owned(),
        assertion_inventory_sha256: ASSERTION_INVENTORY_SHA256.to_owned(),
        assertions: assertions(),
    })
}

fn assertions() -> Vec<RegexAutomataAssertionContract> {
    vec![RegexAutomataAssertionContract {
        assertion_id: "suffix-literal-find-iter-count".to_owned(),
        source_line: 3_704,
        source_line_sha256: ASSERTION_LINE_SHA256.to_owned(),
        expected_observation: "usize:1".to_owned(),
    }]
}

fn validate_source_authority(inventory: &RegexAutomataCorpusReport) -> Result<(), InventoryError> {
    validate_fixture()?;
    let mut files = inventory
        .payload
        .source
        .files
        .iter()
        .filter(|file| file.path == SOURCE_PATH);
    let file = files
        .next()
        .ok_or_else(|| InventoryError::new("suffix-literal source file is absent"))?;
    if files.next().is_some() || file.sha256 != SOURCE_SHA256 || file.mode != "0644" {
        return Err(InventoryError::new(
            "suffix-literal source file identity mismatch",
        ));
    }
    Ok(())
}

fn validate_fixture() -> Result<(), InventoryError> {
    if CASE_ID == REJECTED_OBJECT_SAFE_CASE_ID
        || SOURCE_SPAN.split_inclusive('\n').count() != 9
        || !SOURCE_SPAN.ends_with('\n')
        || SOURCE_SPAN.contains(['\0', '\r'])
        || crate::sha256(SOURCE_SPAN.as_bytes()) != SOURCE_SPAN_SHA256
        || hash_json(&assertions(), "encode suffix-literal assertion inventory")?
            != ASSERTION_INVENTORY_SHA256
    {
        return Err(InventoryError::new(
            "suffix-literal source authority mismatch",
        ));
    }
    Ok(())
}

fn execution_limits(max_search_calls: usize) -> PortableFindIterLimits {
    PortableFindIterLimits {
        session: SearchSessionLimits {
            max_setup_work: 2_000_000,
            max_scratch_bytes: MAX_SCRATCH_BYTES,
        },
        search: SearchLimits {
            max_work: MAX_SEARCH_WORK,
            max_scratch_bytes: MAX_SCRATCH_BYTES,
        },
        max_search_calls,
    }
}

fn validate_execution_mode(mode: &RegexAutomataModeExecution) -> Result<(), InventoryError> {
    if mode.mode_id != COMPILED_UNIT_MODE_ID
        || mode.harness != RegexAutomataHarnessKind::Unit
        || !mode.default_features
        || mode.all_features
        || !mode.features.is_empty()
    {
        return Err(InventoryError::new(
            "suffix-literal execution mode mismatch",
        ));
    }
    Ok(())
}

fn validate_direct_search(fre: &PortableRegex) -> Result<(), InventoryError> {
    let limits = SearchLimits {
        max_work: MAX_SEARCH_WORK,
        max_scratch_bytes: MAX_SCRATCH_BYTES,
    };
    let (first_match, first_accounting) = fre
        .find(HAYSTACK, limits)
        .map_err(|error| InventoryError::new(format!("suffix-literal FRE first: {error}")))?;
    let (tail_match, tail_accounting) = fre
        .find_at(HAYSTACK, EXPECTED_SPANS[0].1, limits)
        .map_err(|error| InventoryError::new(format!("suffix-literal FRE tail: {error}")))?;
    let SearchAccounting::K0(first_accounting) = first_accounting else {
        return Err(InventoryError::new("suffix-literal first search is not K0"));
    };
    let SearchAccounting::K0(tail_accounting) = tail_accounting else {
        return Err(InventoryError::new("suffix-literal tail search is not K0"));
    };
    let first_work = first_accounting.work();
    let tail_work = tail_accounting.work();
    if first_match.map(|matched| (matched.start(), matched.end())) != Some(EXPECTED_SPANS[0])
        || tail_match.is_some()
        || first_work != EXPECTED_FIRST_WORK
        || tail_work != EXPECTED_TAIL_WORK
    {
        return Err(InventoryError::new(format!(
            "suffix-literal direct search mismatch: first={first_work} tail={tail_work}",
        )));
    }
    // A fresh plan can admit the smaller workspace tier at this exact bound,
    // while the unlimited search above chooses the more capable cold tier.
    // Authenticate both adaptive outcomes instead of comparing cold and warm
    // accounting from the same plan owner.
    let exact_fre = PortableBuilder::new(PATTERN)
        .profile(RustProfile::regex_1_12_4())
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .map_err(|error| InventoryError::new(format!("suffix-literal exact build: {error}")))?;
    let (exact_match, exact_accounting) = exact_fre
        .find(
            HAYSTACK,
            SearchLimits {
                max_work: EXPECTED_MINIMUM_FIRST_WORK,
                max_scratch_bytes: MAX_SCRATCH_BYTES,
            },
        )
        .map_err(|error| InventoryError::new(format!("suffix-literal exact search: {error}")))?;
    let SearchAccounting::K0(exact_accounting) = exact_accounting else {
        return Err(InventoryError::new("suffix-literal exact search is not K0"));
    };
    if exact_match.map(|matched| (matched.start(), matched.end())) != Some(EXPECTED_SPANS[0])
        || exact_accounting.work() != EXPECTED_MINIMUM_FIRST_WORK
    {
        return Err(InventoryError::new(format!(
            "suffix-literal exact-bound mismatch: accounting={exact_accounting:?}",
        )));
    }
    let one_below = EXPECTED_MINIMUM_FIRST_WORK
        .checked_sub(1)
        .ok_or_else(|| InventoryError::new("suffix-literal first work underflow"))?;
    let one_below_fre = PortableBuilder::new(PATTERN)
        .profile(RustProfile::regex_1_12_4())
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .map_err(|error| InventoryError::new(format!("suffix-literal one-below build: {error}")))?;
    if !matches!(
        one_below_fre.find(
            HAYSTACK,
            SearchLimits {
                max_work: one_below,
                max_scratch_bytes: MAX_SCRATCH_BYTES,
            },
        ),
        Err(SearchError::K0(K0SearchError::WorkLimitExceeded {
            limit,
            consumed,
            requested,
            ..
        })) if limit == one_below
            && consumed.checked_add(requested).is_some_and(|needed| needed > limit)
    ) {
        return Err(InventoryError::new(
            "suffix-literal one-below search work did not fail closed",
        ));
    }
    Ok(())
}

fn collect_exact_iteration(fre: &PortableRegex) -> Result<Vec<(usize, usize)>, InventoryError> {
    let mut iter = fre
        .find_iter(HAYSTACK, execution_limits(MAX_SEARCH_CALLS))
        .map_err(|error| InventoryError::new(format!("suffix-literal FRE iterator: {error}")))?;
    let mut spans = Vec::new();
    for result in iter.by_ref() {
        let matched = result.map_err(|error| {
            InventoryError::new(format!("suffix-literal FRE iteration: {error}"))
        })?;
        spans.push((matched.start(), matched.end()));
    }
    let accounting = iter.accounting();
    if spans.as_slice() != EXPECTED_SPANS
        || accounting.search_calls != MAX_SEARCH_CALLS
        || accounting.matches != EXPECTED_SPANS.len()
        || accounting.suppressed_empty != 0
        || accounting.utf8_progress_byte_probes != 0
        || accounting.utf8_progress_work != 0
        || accounting.work_or_linear_terms != EXPECTED_ITER_WORK
    {
        return Err(InventoryError::new(format!(
            "suffix-literal iteration accounting mismatch: spans={spans:?} accounting={accounting:?}",
        )));
    }
    Ok(spans)
}

fn validate_one_below_iteration(fre: &PortableRegex) -> Result<(), InventoryError> {
    let one_below_limit = MAX_SEARCH_CALLS
        .checked_sub(1)
        .ok_or_else(|| InventoryError::new("suffix-literal search-call underflow"))?;
    let mut one_below = fre
        .find_iter(HAYSTACK, execution_limits(one_below_limit))
        .map_err(|error| {
            InventoryError::new(format!("suffix-literal one-below iterator: {error}"))
        })?;
    let first = one_below.next();
    let refusal = one_below.next();
    if !matches!(first, Some(Ok(matched)) if (matched.start(), matched.end()) == EXPECTED_SPANS[0])
        || !matches!(
            refusal,
            Some(Err(PortableFindIterError::SearchCallLimit { needed, limit }))
                if needed == MAX_SEARCH_CALLS && limit == one_below_limit
        )
        || one_below.next().is_some()
    {
        return Err(InventoryError::new(
            "suffix-literal one-below iterator limit did not fail closed",
        ));
    }
    Ok(())
}

fn execute_suffix_literal_count(
    mode: &RegexAutomataModeExecution,
) -> Result<RegexAutomataExecutionReceipt, InventoryError> {
    validate_execution_mode(mode)?;
    let upstream = UpstreamRegex::new(PATTERN)
        .map_err(|error| InventoryError::new(format!("suffix-literal upstream build: {error}")))?;
    let upstream_spans = upstream
        .find_iter(HAYSTACK)
        .map(|matched| (matched.start(), matched.end()))
        .collect::<Vec<_>>();
    let fre = PortableBuilder::new(PATTERN)
        .profile(RustProfile::regex_1_12_4())
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .map_err(|error| InventoryError::new(format!("suffix-literal FRE build: {error}")))?;
    validate_direct_search(&fre)?;
    let fre_spans = collect_exact_iteration(&fre)?;
    validate_one_below_iteration(&fre)?;
    if upstream_spans.as_slice() != EXPECTED_SPANS || fre_spans.as_slice() != EXPECTED_SPANS {
        return Err(InventoryError::new(format!(
            "suffix-literal semantic mismatch: upstream={upstream_spans:?} fre={fre_spans:?}",
        )));
    }
    Ok(RegexAutomataExecutionReceipt {
        mode: mode.clone(),
        harness: RegexAutomataHarnessKind::Unit,
        case_id: CASE_ID.to_owned(),
        source: source_contract()?,
        assertion_executions: vec![RegexAutomataAssertionExecution {
            assertion_id: "suffix-literal-find-iter-count".to_owned(),
            upstream_observation: format!("usize:{}", upstream_spans.len()),
            fre_observation: format!("usize:{}", fre_spans.len()),
        }],
    })
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{DirBuilderExt, MetadataExt},
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;
    use crate::automata_progress::RegexAutomataAdapterReceipt;

    fn compiled_mode() -> RegexAutomataModeExecution {
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

    #[test]
    fn suffix_literal_fixture_is_exact_and_rejects_object_safe_substitution() {
        validate_fixture().unwrap();
        assert_ne!(CASE_ID, REJECTED_OBJECT_SAFE_CASE_ID);
        assert_eq!(source_contract().unwrap().assertions.len(), 1);
    }

    #[test]
    fn suffix_literal_observer_checks_span_count_and_one_below_limit() {
        execute_suffix_literal_count(&compiled_mode()).unwrap();
    }

    #[test]
    fn suffix_literal_transition_identity_is_exact_v10() {
        assert_eq!(
            REGEX_AUTOMATA_SUFFIX_LITERAL_COUNT_REPORT_SCHEMA,
            "fre.regex-automata-0.4.14.adapter-report.v10"
        );
        assert_eq!(PREDECESSOR_REVISION.len(), 40);
        assert_eq!(PREDECESSOR_TREE.len(), 40);
        assert_eq!(PREDECESSOR_PAYLOAD_SHA256.len(), 64);
        assert!(
            SUFFIX_LITERAL_COUNT_REPORT_LIMITATIONS
                .iter()
                .any(|text| text.contains("145-membership"))
        );
    }

    #[test]
    #[ignore = "requires authenticated external inventory and start-map-v9 report fixtures"]
    fn authenticated_v9_v10_transition_rejects_persistent_resealed_mutations() {
        let inventory_path = authenticated_fixture(
            "FRE_SUFFIX_INVENTORY",
            "b6c4ff208f546f2b45d9a37d1f5508680d0c2a6e29c0e59df9f4b96f1dcdfbe2",
            0o444,
        );
        let predecessor_path = authenticated_fixture(
            "FRE_SUFFIX_V9",
            "04a0e968da1aac0dfe2c80d105cfe75f147d0f4ba1f8126c48413ed760551c78",
            0o400,
        );
        let inventory = crate::read_regex_automata_corpus_report(&inventory_path).unwrap();
        let predecessor =
            crate::read_regex_automata_adapter_report(&predecessor_path, &inventory).unwrap();
        let current = build_regex_automata_suffix_literal_count_report(
            &inventory,
            &predecessor,
            CandidateIdentity {
                revision: std::env::var("FRE_SUFFIX_FINAL_REVISION").unwrap(),
                tree: std::env::var("FRE_SUFFIX_FINAL_TREE").unwrap(),
                tracked_and_untracked_worktree_clean: true,
            },
        )
        .unwrap();
        validate_predecessor(&inventory, &predecessor).unwrap();
        validate_regex_automata_suffix_literal_count_strict_gain(
            &inventory,
            &predecessor,
            &current,
        )
        .unwrap();
        assert_eq!(current.payload.counts.pass, 146);
        assert_eq!(current.payload.execution_receipts.len(), 146);

        assert_predecessor_mutations_rejected(&inventory, &predecessor);
        assert_retained_mutations_rejected(&inventory, &predecessor, &current);
        assert_target_mutations_rejected(&inventory, &predecessor, &current);
        assert_matrix_and_source_mutations_rejected(&inventory, &predecessor, &current);
        assert_writer_path(&inventory, &current);
    }

    fn assert_predecessor_mutations_rejected(
        inventory: &RegexAutomataCorpusReport,
        predecessor: &RegexAutomataAdapterReport,
    ) {
        let mut wrong_revision = predecessor.clone();
        wrong_revision.payload.candidate.revision = "0".repeat(40);
        reseal(&mut wrong_revision);
        assert!(validate_predecessor(inventory, &wrong_revision).is_err());

        let mut wrong_tree = predecessor.clone();
        wrong_tree.payload.candidate.tree = "1".repeat(40);
        reseal(&mut wrong_tree);
        assert!(validate_predecessor(inventory, &wrong_tree).is_err());
    }

    fn assert_retained_mutations_rejected(
        inventory: &RegexAutomataCorpusReport,
        predecessor: &RegexAutomataAdapterReport,
        current: &RegexAutomataAdapterReport,
    ) {
        let retained_identity = (
            COMPILED_UNIT_MODE_ID,
            RegexAutomataHarnessKind::Unit,
            "util::look::tests::look_matches_end_line",
        );
        let mut changed_receipt = current.clone();
        let RegexAutomataAdapterDisposition::Pass { evidence_sha256 } =
            &mut exact_receipt_mut(&mut changed_receipt, retained_identity).disposition
        else {
            panic!("retained receipt is not a pass");
        };
        *evidence_sha256 = "2".repeat(64);
        reseal(&mut changed_receipt);
        assert_current_rejected(inventory, predecessor, &changed_receipt);

        let mut changed_execution = current.clone();
        let changed_evidence = {
            let execution = exact_execution_mut(&mut changed_execution, retained_identity);
            execution.assertion_executions[0]
                .fre_observation
                .push_str(":resealed");
            hash_json(execution, "encode changed retained suffix execution").unwrap()
        };
        bind_receipt_evidence(&mut changed_execution, retained_identity, changed_evidence);
        reseal(&mut changed_execution);
        assert_current_rejected(inventory, predecessor, &changed_execution);
    }

    fn assert_target_mutations_rejected(
        inventory: &RegexAutomataCorpusReport,
        predecessor: &RegexAutomataAdapterReport,
        current: &RegexAutomataAdapterReport,
    ) {
        let target_identity = target_identity_ref();
        let mut wrong_identity = current.clone();
        exact_execution_mut(&mut wrong_identity, target_identity)
            .case_id
            .push_str("::wrong");
        reseal(&mut wrong_identity);
        assert_current_rejected(inventory, predecessor, &wrong_identity);

        let mut changed_execution = current.clone();
        let changed_evidence = {
            let execution = exact_execution_mut(&mut changed_execution, target_identity);
            execution.assertion_executions[0].fre_observation = "usize:2".to_owned();
            hash_json(execution, "encode changed target suffix execution").unwrap()
        };
        bind_receipt_evidence(&mut changed_execution, target_identity, changed_evidence);
        reseal(&mut changed_execution);
        assert_current_rejected(inventory, predecessor, &changed_execution);

        let mut missing = current.clone();
        missing
            .payload
            .execution_receipts
            .retain(|execution| execution_identity_ref(execution) != target_identity);
        reseal(&mut missing);
        assert_current_rejected(inventory, predecessor, &missing);

        let mut duplicate = current.clone();
        let execution = exact_execution_mut(&mut duplicate, target_identity).clone();
        duplicate.payload.execution_receipts.push(execution);
        reseal(&mut duplicate);
        assert_current_rejected(inventory, predecessor, &duplicate);
    }

    fn assert_matrix_and_source_mutations_rejected(
        inventory: &RegexAutomataCorpusReport,
        predecessor: &RegexAutomataAdapterReport,
        current: &RegexAutomataAdapterReport,
    ) {
        let mut changed_matrix = current.clone();
        changed_matrix.payload.look_mode_matrix = None;
        reseal(&mut changed_matrix);
        assert_current_rejected(inventory, predecessor, &changed_matrix);

        let target_identity = target_identity_ref();
        let mut malformed_source = current.clone();
        let changed_evidence = {
            let execution = exact_execution_mut(&mut malformed_source, target_identity);
            execution.source.source_sha256 = "3".repeat(64);
            hash_json(execution, "encode malformed suffix source execution").unwrap()
        };
        bind_receipt_evidence(&mut malformed_source, target_identity, changed_evidence);
        reseal(&mut malformed_source);
        assert_current_rejected(inventory, predecessor, &malformed_source);
    }

    fn assert_writer_path(
        inventory: &RegexAutomataCorpusReport,
        current: &RegexAutomataAdapterReport,
    ) {
        let mut invalid = current.clone();
        invalid.payload.limitations[0].push('x');
        reseal(&mut invalid);
        let mut output = AuditOutputDirectory::create();
        let positive = output.path.join("positive.json");
        let negative = output.path.join("negative.json");
        assert_absent(&positive);
        assert_absent(&negative);
        crate::write_regex_automata_adapter_report(&positive, current, inventory).unwrap();
        assert!(
            crate::write_regex_automata_adapter_report(&negative, &invalid, inventory).is_err()
        );
        assert_absent(&negative);
        fs::remove_file(&positive).unwrap();
        fs::remove_dir(&output.path).unwrap();
        let removed = output.path.clone();
        output.armed = false;
        assert_absent(&removed);
    }

    fn authenticated_fixture(variable: &str, expected_sha256: &str, mode: u32) -> PathBuf {
        let path = PathBuf::from(std::env::var(variable).expect("authenticated fixture path"));
        let metadata = fs::symlink_metadata(&path).expect("stat authenticated fixture");
        assert!(!metadata.file_type().is_symlink());
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.uid(), 501);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.mode() & 0o777, mode);
        assert_eq!(
            crate::sha256(&fs::read(&path).expect("read authenticated fixture")),
            expected_sha256,
        );
        path
    }

    fn reseal(report: &mut RegexAutomataAdapterReport) {
        report.payload.counts = adapter_counts(&report.payload.receipts);
        report.payload_sha256 =
            hash_json(&report.payload, "encode adversarial suffix payload").unwrap();
    }

    fn assert_current_rejected(
        inventory: &RegexAutomataCorpusReport,
        predecessor: &RegexAutomataAdapterReport,
        current: &RegexAutomataAdapterReport,
    ) {
        assert!(current.validate_structure(inventory).is_err());
        assert!(
            validate_regex_automata_suffix_literal_count_strict_gain(
                inventory,
                predecessor,
                current,
            )
            .is_err()
        );
    }

    const fn target_identity_ref() -> (&'static str, RegexAutomataHarnessKind, &'static str) {
        (
            COMPILED_UNIT_MODE_ID,
            RegexAutomataHarnessKind::Unit,
            CASE_ID,
        )
    }

    fn receipt_identity_ref(
        receipt: &RegexAutomataAdapterReceipt,
    ) -> (&str, RegexAutomataHarnessKind, &str) {
        (&receipt.mode_id, receipt.harness, &receipt.case_id)
    }

    fn execution_identity_ref(
        execution: &RegexAutomataExecutionReceipt,
    ) -> (&str, RegexAutomataHarnessKind, &str) {
        (
            &execution.mode.mode_id,
            execution.harness,
            &execution.case_id,
        )
    }

    fn exact_receipt_mut<'a>(
        report: &'a mut RegexAutomataAdapterReport,
        identity: (&str, RegexAutomataHarnessKind, &str),
    ) -> &'a mut RegexAutomataAdapterReceipt {
        assert_eq!(
            report
                .payload
                .receipts
                .iter()
                .filter(|receipt| receipt_identity_ref(receipt) == identity)
                .count(),
            1,
        );
        report
            .payload
            .receipts
            .iter_mut()
            .find(|receipt| receipt_identity_ref(receipt) == identity)
            .unwrap()
    }

    fn exact_execution_mut<'a>(
        report: &'a mut RegexAutomataAdapterReport,
        identity: (&str, RegexAutomataHarnessKind, &str),
    ) -> &'a mut RegexAutomataExecutionReceipt {
        assert_eq!(
            report
                .payload
                .execution_receipts
                .iter()
                .filter(|execution| execution_identity_ref(execution) == identity)
                .count(),
            1,
        );
        report
            .payload
            .execution_receipts
            .iter_mut()
            .find(|execution| execution_identity_ref(execution) == identity)
            .unwrap()
    }

    fn bind_receipt_evidence(
        report: &mut RegexAutomataAdapterReport,
        identity: (&str, RegexAutomataHarnessKind, &str),
        changed_evidence: String,
    ) {
        let RegexAutomataAdapterDisposition::Pass { evidence_sha256 } =
            &mut exact_receipt_mut(report, identity).disposition
        else {
            panic!("suffix receipt is not a pass");
        };
        *evidence_sha256 = changed_evidence;
    }

    struct AuditOutputDirectory {
        path: PathBuf,
        armed: bool,
    }

    impl AuditOutputDirectory {
        fn create() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock precedes Unix epoch")
                .as_nanos();
            for attempt in 0..16_u8 {
                let path = std::env::temp_dir().join(format!(
                    "fre-suffix-v10-audit-{}-{nonce}-{attempt}",
                    std::process::id(),
                ));
                let mut builder = fs::DirBuilder::new();
                builder.mode(0o700);
                match builder.create(&path) {
                    Ok(()) => {
                        let metadata = fs::symlink_metadata(&path).unwrap();
                        assert!(!metadata.file_type().is_symlink());
                        assert!(metadata.file_type().is_dir());
                        assert_eq!(metadata.uid(), 501);
                        assert_eq!(metadata.mode() & 0o777, 0o700);
                        return Self { path, armed: true };
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("create private suffix audit directory: {error}"),
                }
            }
            panic!("could not allocate a unique private suffix audit directory");
        }
    }

    impl Drop for AuditOutputDirectory {
        fn drop(&mut self) {
            if !self.armed {
                return;
            }
            for name in ["positive.json", "negative.json"] {
                let _ = fs::remove_file(self.path.join(name));
            }
            let _ = fs::remove_dir(&self.path);
        }
    }

    fn assert_absent(path: &Path) {
        let error = fs::symlink_metadata(path).expect_err("path unexpectedly exists");
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    }
}
