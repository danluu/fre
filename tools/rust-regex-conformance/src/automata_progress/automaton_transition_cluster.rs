//! Authenticated package-default execution for the public DFA byte and EOI
//! transition examples, layered over the exact state-codec adapter report.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
};

use fre::{K0SearchError, PlanKind, PortableRegex, SearchAccounting, SearchError, SearchLimits};
use regex_automata::{
    Input,
    dfa::{Automaton as _, dense},
};

use super::state_codec::{
    REGEX_AUTOMATA_STATE_CODEC_REPORT_SCHEMA, STATE_CODEC_REPORT_LIMITATIONS,
};
use super::{
    AUTOMATON_SOURCE_PATH, AUTOMATON_SOURCE_SHA256, AssertionSpec, COMPILED_MODE_ID,
    INVENTORY_UNSUPPORTED_REASON, RegexAutomataAdapterCounts, RegexAutomataAdapterDisposition,
    RegexAutomataAdapterReport, RegexAutomataAdapterReportPayload, RegexAutomataAssertionExecution,
    RegexAutomataCorpusReport, RegexAutomataExecutionReceipt, RegexAutomataHarnessKind,
    RegexAutomataModeExecution, RegexAutomataStrictGain, SourceContractSpec, adapter_counts,
    gain_vectors, hash_json, mode_execution, obligation_membership_identity, source_contract,
    validate_assertion_executions, validate_candidate, validate_source_spec,
};
use crate::{CandidateIdentity, InventoryError, sha256};

/// Successor schema for two package-default public transition examples.
pub const REGEX_AUTOMATA_TRANSITION_CLUSTER_REPORT_SCHEMA: &str =
    "fre.regex-automata-0.4.14.adapter-report.transition-cluster.v2";

pub(super) const TRANSITION_CLUSTER_REPORT_LIMITATIONS: [&str; 3] = [
    "A pass requires direct upstream DFA byte/EOI walking to agree with FRE's bounded K0 existence result, including exact/repeat accounting and typed one-below work and scratch refusals.",
    "Only the package-default next_state and next_eoi_state doctest memberships are added; no result is projected into the VCS all-features mode.",
    "The exact 269-pass state-codec predecessor, including both codec gains, its embedded baseline and execution matrix, and all 153 direct execution receipts, is retained exactly.",
];

const PREDECESSOR_REVISION: &str = "7c877d16a30a41404a93c5c6b0507dc849242d46";
const PREDECESSOR_TREE: &str = "6c2a81a77f77c2b830444d4dce377dd965ef4a5f";
const PREDECESSOR_PAYLOAD_SHA256: &str =
    "c220eaf2745f48383f3bf0e14e0a4f027d8b248866560acffcaeb53e75d8a732";
const TARGET_IDENTITIES_SHA256: &str =
    "7e41a4d7926bb7009c0e334ce52cb74b65b17468435eff38680b4d11ac0be941";

const PATTERN: &str = r"[a-z]+r";
const HAYSTACK: &[u8] = b"bar";
const NEXT_STATE_CASE: &str =
    "src/dfa/automaton.rs - dfa::automaton::Automaton::next_state (line 128)";
const NEXT_EOI_CASE: &str =
    "src/dfa/automaton.rs - dfa::automaton::Automaton::next_eoi_state (line 203)";

const NEXT_STATE_ASSERTIONS: &[AssertionSpec] = &[AssertionSpec {
    assertion_id: "next-state-final-match",
    source_line: 144,
    source_line_sha256: "9512b440c7d6eff01d10cc8ae6b092054bd37e21f5cc6e6aefddb8515dfc4b61",
    expected_observation: "bool:true",
}];
const NEXT_EOI_ASSERTIONS: &[AssertionSpec] = &[AssertionSpec {
    assertion_id: "next-eoi-final-match",
    source_line: 224,
    source_line_sha256: "9512b440c7d6eff01d10cc8ae6b092054bd37e21f5cc6e6aefddb8515dfc4b61",
    expected_observation: "bool:true",
}];

const NEXT_STATE_SOURCE: SourceContractSpec = SourceContractSpec {
    source_path: AUTOMATON_SOURCE_PATH,
    source_sha256: AUTOMATON_SOURCE_SHA256,
    span_start_line: 128,
    span_end_line: 147,
    source_span: include_str!("../fixtures/dfa-automaton-next-state-v1.txt"),
    source_span_sha256: "b418f6eb6f1a0027d56ee5e35b535ebf2db04c56236676650abb4c5c180c4868",
    assertion_inventory_sha256: "13be84114a4f43971531a85aad93da9a5bd85fc33ae6959faaa0df366d4cdd83",
    assertions: NEXT_STATE_ASSERTIONS,
};
const NEXT_EOI_SOURCE: SourceContractSpec = SourceContractSpec {
    source_path: AUTOMATON_SOURCE_PATH,
    source_sha256: AUTOMATON_SOURCE_SHA256,
    span_start_line: 203,
    span_end_line: 227,
    source_span: include_str!("../fixtures/dfa-automaton-next-eoi-state-v1.txt"),
    source_span_sha256: "9a1280e9d6414aa4c52ec4c09e9a5a5e756694138407ad5ba98329ee3775d663",
    assertion_inventory_sha256: "89e73d59611ed4360065e4ba617dbfd5111766cdc14a05f660de2996e5e558a8",
    assertions: NEXT_EOI_ASSERTIONS,
};

#[derive(Clone, Copy)]
struct TransitionCase {
    case_id: &'static str,
    source: SourceContractSpec,
}

const CASES: [TransitionCase; 2] = [
    TransitionCase {
        case_id: NEXT_STATE_CASE,
        source: NEXT_STATE_SOURCE,
    },
    TransitionCase {
        case_id: NEXT_EOI_CASE,
        source: NEXT_EOI_SOURCE,
    },
];

/// Extend the exact state-codec report with two independently executed
/// transition memberships.
pub fn build_regex_automata_transition_cluster_report(
    inventory: &RegexAutomataCorpusReport,
    previous: &RegexAutomataAdapterReport,
    candidate: CandidateIdentity,
) -> Result<RegexAutomataAdapterReport, InventoryError> {
    validate_predecessor(inventory, previous)?;
    validate_candidate(&candidate)?;
    if candidate.revision == PREDECESSOR_REVISION || candidate.tree == PREDECESSOR_TREE {
        return Err(InventoryError::new(
            "transition-cluster candidate is not distinct from its predecessor",
        ));
    }
    let targets = target_identities(inventory)?;
    let mode = mode_execution(inventory, COMPILED_MODE_ID)?;
    let mut receipts = previous.payload.receipts.clone();
    let mut executions = previous.payload.execution_receipts.clone();
    let mut observed = BTreeSet::new();
    for receipt in &mut receipts {
        let identity = (
            receipt.mode_id.clone(),
            receipt.harness,
            receipt.case_id.clone(),
        );
        if !targets.contains(&identity) {
            continue;
        }
        if !matches!(
            &receipt.disposition,
            RegexAutomataAdapterDisposition::Unsupported { reason_code }
                if reason_code == INVENTORY_UNSUPPORTED_REASON
        ) {
            return Err(InventoryError::new(
                "transition-cluster predecessor target is not unsupported",
            ));
        }
        let execution = execute_case(case_by_id(&receipt.case_id)?, &mode)?;
        let evidence_sha256 = hash_json(&execution, "encode transition-cluster execution")?;
        receipt.disposition = RegexAutomataAdapterDisposition::Pass { evidence_sha256 };
        executions.push(execution);
        observed.insert(identity);
    }
    if observed != targets {
        return Err(InventoryError::new(
            "transition-cluster inventory target denominator mismatch",
        ));
    }
    let execution_receipts = order_transition_executions(&receipts, executions)?;
    let payload = RegexAutomataAdapterReportPayload {
        inventory_payload_sha256: inventory.payload_sha256.clone(),
        obligation_inventory_sha256: inventory
            .payload
            .harness
            .obligation_inventory_sha256
            .clone(),
        candidate,
        counts: adapter_counts(&receipts),
        receipts,
        execution_receipts,
        look_mode_matrix: previous.payload.look_mode_matrix.clone(),
        start_mode_matrix: previous.payload.start_mode_matrix.clone(),
        start_mode_baseline: previous.payload.start_mode_baseline.clone(),
        limitations: TRANSITION_CLUSTER_REPORT_LIMITATIONS
            .iter()
            .map(|text| (*text).to_owned())
            .collect(),
    };
    let report = RegexAutomataAdapterReport {
        schema: REGEX_AUTOMATA_TRANSITION_CLUSTER_REPORT_SCHEMA.to_owned(),
        payload_sha256: hash_json(&payload, "encode transition-cluster report payload")?,
        payload,
    };
    validate_transition_cluster_execution_after_structure(inventory, &report)?;
    Ok(report)
}

/// Require exact monotonic 269 -> 271 progress.
pub fn validate_regex_automata_transition_cluster_strict_gain(
    inventory: &RegexAutomataCorpusReport,
    previous: &RegexAutomataAdapterReport,
    current: &RegexAutomataAdapterReport,
) -> Result<RegexAutomataStrictGain, InventoryError> {
    validate_predecessor(inventory, previous)?;
    current.validate_structure(inventory)?;
    if current.schema != REGEX_AUTOMATA_TRANSITION_CLUSTER_REPORT_SCHEMA {
        return Err(InventoryError::new(
            "current report is not a transition-cluster report",
        ));
    }
    let targets = target_identities(inventory)?;
    let (unique, memberships) = gain_vectors(
        &previous.payload.receipts,
        &current.payload.receipts,
        &targets,
    )?;
    if (unique, memberships) != (2, 2) {
        return Err(InventoryError::new(
            "transition-cluster gain is not exact two-membership progress",
        ));
    }
    Ok(RegexAutomataStrictGain {
        family: "doctest-dfa-automaton-transition".to_owned(),
        gained_unique_cases: unique,
        gained_mode_memberships: memberships,
        previous_pass: 269,
        current_pass: 271,
    })
}

pub(super) fn validate_transition_cluster_execution_after_structure(
    inventory: &RegexAutomataCorpusReport,
    report: &RegexAutomataAdapterReport,
) -> Result<(), InventoryError> {
    if report.schema != REGEX_AUTOMATA_TRANSITION_CLUSTER_REPORT_SCHEMA
        || report.payload.counts
            != (RegexAutomataAdapterCounts {
                pass: 271,
                unsupported: 3_571,
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
            "transition-cluster candidate identity or cardinality mismatch",
        ));
    }
    if order_transition_executions(
        &report.payload.receipts,
        report.payload.execution_receipts.clone(),
    )? != report.payload.execution_receipts
    {
        return Err(InventoryError::new(
            "transition-cluster execution receipt order mismatch",
        ));
    }
    let targets = target_identities(inventory)?;
    let previous = reconstruct_predecessor(report, &targets)?;
    validate_predecessor(inventory, &previous)?;
    let mode = mode_execution(inventory, COMPILED_MODE_ID)?;
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
    if previous_executions.len() != 153 || current_executions.len() != 155 {
        return Err(InventoryError::new(
            "transition-cluster execution denominator mismatch",
        ));
    }
    for (identity, execution) in &previous_executions {
        if current_executions.get(identity) != Some(execution) {
            return Err(InventoryError::new(
                "transition-cluster changed retained execution evidence",
            ));
        }
    }
    for identity in &targets {
        let execution = current_executions.get(identity).ok_or_else(|| {
            InventoryError::new("transition-cluster target lacks execution evidence")
        })?;
        let expected = execute_case(case_by_id(&identity.2)?, &mode)?;
        if *execution != &expected {
            return Err(InventoryError::new(
                "transition-cluster execution differs from direct replay",
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
            .ok_or_else(|| InventoryError::new("transition-cluster target receipt is absent"))?;
        let expected_hash = hash_json(*execution, "encode transition-cluster execution")?;
        if !matches!(
            &receipt.disposition,
            RegexAutomataAdapterDisposition::Pass { evidence_sha256 }
                if *evidence_sha256 == expected_hash
        ) {
            return Err(InventoryError::new(
                "transition-cluster pass is not bound to its execution receipt",
            ));
        }
    }
    Ok(())
}

fn validate_predecessor(
    inventory: &RegexAutomataCorpusReport,
    previous: &RegexAutomataAdapterReport,
) -> Result<(), InventoryError> {
    previous.validate_structure(inventory)?;
    if previous.schema != REGEX_AUTOMATA_STATE_CODEC_REPORT_SCHEMA
        || previous.payload_sha256 != PREDECESSOR_PAYLOAD_SHA256
        || previous.payload.candidate
            != (CandidateIdentity {
                revision: PREDECESSOR_REVISION.to_owned(),
                tree: PREDECESSOR_TREE.to_owned(),
                tracked_and_untracked_worktree_clean: true,
            })
        || previous.payload.counts
            != (RegexAutomataAdapterCounts {
                pass: 269,
                unsupported: 3_573,
                fault: 0,
                total: 3_842,
            })
    {
        return Err(InventoryError::new(
            "transition-cluster predecessor authority mismatch",
        ));
    }
    Ok(())
}

fn reconstruct_predecessor(
    report: &RegexAutomataAdapterReport,
    targets: &BTreeSet<(String, RegexAutomataHarnessKind, String)>,
) -> Result<RegexAutomataAdapterReport, InventoryError> {
    let mut previous = report.clone();
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
    previous.payload.candidate = CandidateIdentity {
        revision: PREDECESSOR_REVISION.to_owned(),
        tree: PREDECESSOR_TREE.to_owned(),
        tracked_and_untracked_worktree_clean: true,
    };
    previous.payload.counts = adapter_counts(&previous.payload.receipts);
    previous.payload.limitations = STATE_CODEC_REPORT_LIMITATIONS
        .iter()
        .map(|text| (*text).to_owned())
        .collect();
    REGEX_AUTOMATA_STATE_CODEC_REPORT_SCHEMA.clone_into(&mut previous.schema);
    previous.payload_sha256 = hash_json(
        &previous.payload,
        "encode reconstructed state-codec predecessor payload",
    )?;
    if previous.payload_sha256 != PREDECESSOR_PAYLOAD_SHA256 {
        return Err(InventoryError::new(
            "reconstructed transition-cluster state-codec predecessor payload SHA-256 mismatch",
        ));
    }
    Ok(previous)
}

fn order_transition_executions(
    receipts: &[super::RegexAutomataAdapterReceipt],
    executions: Vec<RegexAutomataExecutionReceipt>,
) -> Result<Vec<RegexAutomataExecutionReceipt>, InventoryError> {
    let mut by_identity = BTreeMap::new();
    for execution in executions {
        if by_identity
            .insert(execution_identity(&execution), execution)
            .is_some()
        {
            return Err(InventoryError::new(
                "duplicate transition-cluster execution receipt",
            ));
        }
    }
    let mut ordered = Vec::with_capacity(by_identity.len());
    for receipt in receipts {
        let identity = (
            receipt.mode_id.clone(),
            receipt.harness,
            receipt.case_id.clone(),
        );
        let Some(execution) = by_identity.remove(&identity) else {
            continue;
        };
        if !matches!(
            receipt.disposition,
            RegexAutomataAdapterDisposition::Pass { .. }
        ) {
            return Err(InventoryError::new(
                "transition-cluster execution belongs to a non-pass receipt",
            ));
        }
        ordered.push(execution);
    }
    if !by_identity.is_empty() {
        return Err(InventoryError::new(
            "transition-cluster execution identity is absent from receipts",
        ));
    }
    Ok(ordered)
}

fn target_identities(
    inventory: &RegexAutomataCorpusReport,
) -> Result<BTreeSet<(String, RegexAutomataHarnessKind, String)>, InventoryError> {
    validate_source_authority(inventory)?;
    let case_ids = CASES
        .iter()
        .map(|case| case.case_id)
        .collect::<BTreeSet<_>>();
    if case_ids.len() != CASES.len() {
        return Err(InventoryError::new(
            "transition-cluster case identity duplication",
        ));
    }
    let targets = inventory
        .payload
        .obligations
        .iter()
        .filter(|obligation| {
            obligation.mode_id == COMPILED_MODE_ID
                && obligation.harness == RegexAutomataHarnessKind::Doctest
                && case_ids.contains(obligation.case_id.as_str())
        })
        .map(obligation_membership_identity)
        .collect::<BTreeSet<_>>();
    let mut canonical = String::new();
    for (mode, _, case) in &targets {
        writeln!(&mut canonical, "{mode}\tdoctest\t{case}")
            .map_err(|_| InventoryError::new("encode transition target identity"))?;
    }
    if targets.len() != 2 || sha256(canonical.as_bytes()) != TARGET_IDENTITIES_SHA256 {
        return Err(InventoryError::new(
            "transition-cluster target identity seal mismatch",
        ));
    }
    Ok(targets)
}

fn validate_source_authority(inventory: &RegexAutomataCorpusReport) -> Result<(), InventoryError> {
    let mut files = inventory
        .payload
        .source
        .files
        .iter()
        .filter(|file| file.path == AUTOMATON_SOURCE_PATH);
    let file = files
        .next()
        .ok_or_else(|| InventoryError::new("automaton source file is absent"))?;
    if files.next().is_some() || file.sha256 != AUTOMATON_SOURCE_SHA256 || file.mode != "0644" {
        return Err(InventoryError::new(
            "automaton transition source file identity mismatch",
        ));
    }
    for case in CASES {
        validate_source_spec(&case.source)?;
    }
    Ok(())
}

fn case_by_id(case_id: &str) -> Result<TransitionCase, InventoryError> {
    CASES
        .iter()
        .copied()
        .find(|case| case.case_id == case_id)
        .ok_or_else(|| InventoryError::new("unreviewed transition-cluster case"))
}

fn execute_case(
    case: TransitionCase,
    mode: &RegexAutomataModeExecution,
) -> Result<RegexAutomataExecutionReceipt, InventoryError> {
    require_mode(mode)?;
    validate_source_spec(&case.source)?;
    let upstream = upstream_transition_result(HAYSTACK)?;
    let fre = fre_transition_result(HAYSTACK)?;
    let assertion = case.source.assertions[0];
    let assertions = vec![RegexAutomataAssertionExecution {
        assertion_id: assertion.assertion_id.to_owned(),
        upstream_observation: format!("bool:{upstream}"),
        fre_observation: format!("bool:{fre}"),
    }];
    validate_assertion_executions(case.source.assertions, &assertions).map_err(|reason| {
        InventoryError::new(format!("transition-cluster {}: {reason}", case.case_id))
    })?;
    Ok(RegexAutomataExecutionReceipt {
        mode: mode.clone(),
        harness: RegexAutomataHarnessKind::Doctest,
        case_id: case.case_id.to_owned(),
        source: source_contract(&case.source),
        assertion_executions: assertions,
    })
}

fn upstream_transition_result(haystack: &[u8]) -> Result<bool, InventoryError> {
    let dfa = dense::DFA::new(PATTERN)
        .map_err(|error| InventoryError::new(format!("build upstream transition DFA: {error}")))?;
    let mut state = dfa
        .start_state_forward(&Input::new(haystack))
        .map_err(|error| InventoryError::new(format!("start upstream transition DFA: {error}")))?;
    for &byte in haystack {
        state = dfa.next_state(state, byte);
    }
    if haystack == HAYSTACK && dfa.is_match_state(state) {
        return Err(InventoryError::new(
            "upstream transition example matched before its EOI transition",
        ));
    }
    state = dfa.next_eoi_state(state);
    let matched = dfa.is_match_state(state);
    if haystack == HAYSTACK && !matched {
        return Err(InventoryError::new(
            "upstream transition example lost delayed-EOI semantics",
        ));
    }
    Ok(matched)
}

fn fre_transition_result(haystack: &[u8]) -> Result<bool, InventoryError> {
    let regex = PortableRegex::new(PATTERN)
        .map_err(|error| InventoryError::new(format!("build FRE transition regex: {error}")))?;
    if regex.build_report().plan != PlanKind::K0 {
        return Err(InventoryError::new(
            "FRE transition witness did not select the K0 automaton",
        ));
    }
    let (observed, accounting) = regex
        .is_match(haystack, SearchLimits::unlimited())
        .map_err(|error| InventoryError::new(format!("run FRE transition regex: {error}")))?;
    let SearchAccounting::K0(accounting) = accounting else {
        return Err(InventoryError::new(
            "FRE transition witness returned non-K0 accounting",
        ));
    };
    let work = accounting.work();
    let scratch = accounting.scratch_bytes();
    let exact_limits = SearchLimits {
        max_work: work,
        max_scratch_bytes: scratch,
    };
    let exact = regex
        .is_match(haystack, exact_limits)
        .map_err(|error| InventoryError::new(format!("exact FRE transition regex: {error}")))?;
    let repeated = regex
        .is_match(haystack, exact_limits)
        .map_err(|error| InventoryError::new(format!("repeat FRE transition regex: {error}")))?;
    if exact != (observed, SearchAccounting::K0(accounting)) || repeated != exact {
        return Err(InventoryError::new(
            "FRE transition exact/repeat accounting mismatch",
        ));
    }
    let one_below_work = work
        .checked_sub(1)
        .ok_or_else(|| InventoryError::new("FRE transition work underflow"))?;
    if !matches!(
        regex.is_match(
            haystack,
            SearchLimits {
                max_work: one_below_work,
                max_scratch_bytes: scratch,
            },
        ),
        Err(SearchError::K0(K0SearchError::WorkLimitExceeded {
            limit,
            consumed,
            requested,
            ..
        })) if limit == one_below_work
            && consumed.checked_add(requested).is_some_and(|needed| needed > limit)
    ) {
        return Err(InventoryError::new(
            "FRE transition one-below work limit did not fail closed",
        ));
    }
    let one_below_scratch = scratch
        .checked_sub(1)
        .ok_or_else(|| InventoryError::new("FRE transition scratch underflow"))?;
    if !matches!(
        regex.is_match(
            haystack,
            SearchLimits {
                max_work: work,
                max_scratch_bytes: one_below_scratch,
            },
        ),
        Err(SearchError::K0(K0SearchError::ResourceLimit {
            needed,
            limit,
            ..
        })) if needed == scratch && limit == one_below_scratch
    ) {
        return Err(InventoryError::new(
            "FRE transition one-below scratch limit did not fail closed",
        ));
    }
    Ok(observed)
}

fn require_mode(mode: &RegexAutomataModeExecution) -> Result<(), InventoryError> {
    if mode.mode_id != COMPILED_MODE_ID
        || mode.harness != RegexAutomataHarnessKind::Doctest
        || !mode.default_features
        || mode.all_features
        || !mode.features.is_empty()
        || mode.dependency_package != "regex-automata"
        || mode.dependency_version != "0.4.14"
    {
        return Err(InventoryError::new(
            "transition-cluster compiled mode mismatch",
        ));
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::MetadataExt, path::PathBuf};

    use super::*;

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

    #[test]
    fn both_transition_examples_are_exact_and_repeatable() {
        let mode = compiled_mode();
        for case in CASES {
            assert_eq!(
                execute_case(case, &mode).unwrap(),
                execute_case(case, &mode).unwrap()
            );
        }
    }

    #[test]
    fn transition_witness_is_not_a_fixed_true_result() {
        for (haystack, expected) in [(b"car".as_slice(), true), (b"baz".as_slice(), false)] {
            assert_eq!(upstream_transition_result(haystack).unwrap(), expected);
            assert_eq!(fre_transition_result(haystack).unwrap(), expected);
        }
    }

    #[test]
    fn transition_observer_rejects_mode_relabel() {
        let mut mode = compiled_mode();
        mode.mode_id = "vcs-all-features-doctest".to_owned();
        assert!(execute_case(CASES[0], &mode).is_err());
    }

    #[test]
    fn transition_cluster_identity_is_exact_current_successor() {
        assert_eq!(
            REGEX_AUTOMATA_TRANSITION_CLUSTER_REPORT_SCHEMA,
            "fre.regex-automata-0.4.14.adapter-report.transition-cluster.v2",
        );
        assert_eq!(CASES.len(), 2);
        assert_eq!(PREDECESSOR_REVISION.len(), 40);
        assert_eq!(PREDECESSOR_TREE.len(), 40);
        assert_eq!(PREDECESSOR_PAYLOAD_SHA256.len(), 64);
        assert!(
            TRANSITION_CLUSTER_REPORT_LIMITATIONS
                .iter()
                .any(|text| text.contains("269-pass state-codec")),
        );
    }

    #[test]
    #[ignore = "requires authenticated external inventory and state-codec report fixtures"]
    fn authenticated_state_codec_transition_is_exact_repeatable_and_fail_closed() {
        let inventory_path = authenticated_fixture(
            "FRE_TRANSITION_INVENTORY",
            "b6c4ff208f546f2b45d9a37d1f5508680d0c2a6e29c0e59df9f4b96f1dcdfbe2",
            0o444,
        );
        let predecessor_path = authenticated_fixture(
            "FRE_TRANSITION_STATE_CODEC",
            "58343bb0bf69bb1de8f3847b6e46e4dd67967e3f323ee447f251076e4a108d25",
            0o400,
        );
        let inventory = crate::read_regex_automata_corpus_report(&inventory_path).unwrap();
        let predecessor =
            crate::read_regex_automata_adapter_report(&predecessor_path, &inventory).unwrap();
        let candidate = CandidateIdentity {
            revision: std::env::var("FRE_TRANSITION_FINAL_REVISION").unwrap(),
            tree: std::env::var("FRE_TRANSITION_FINAL_TREE").unwrap(),
            tracked_and_untracked_worktree_clean: true,
        };
        let current = build_regex_automata_transition_cluster_report(
            &inventory,
            &predecessor,
            candidate.clone(),
        )
        .unwrap();
        let repeated =
            build_regex_automata_transition_cluster_report(&inventory, &predecessor, candidate)
                .unwrap();

        assert_eq!(current, repeated);
        assert_eq!(current.payload.counts.pass, 271);
        assert_eq!(current.payload.counts.unsupported, 3_571);
        assert_eq!(current.payload.execution_receipts.len(), 155);
        assert_eq!(
            reconstruct_predecessor(&current, &target_identities(&inventory).unwrap()).unwrap(),
            predecessor,
        );
        let gain = validate_regex_automata_transition_cluster_strict_gain(
            &inventory,
            &predecessor,
            &current,
        )
        .unwrap();
        assert_eq!(
            (gain.gained_unique_cases, gain.gained_mode_memberships),
            (2, 2),
        );
        assert_eq!((gain.previous_pass, gain.current_pass), (269, 271));

        let mut retained_mutation = current.clone();
        mutate_execution_and_reseal(
            &mut retained_mutation,
            (
                "package-default-unit",
                RegexAutomataHarnessKind::Unit,
                "util::determinize::state::tests::prop_read_write_varu32",
            ),
        );
        assert_current_rejected(&inventory, &predecessor, &retained_mutation);

        let mut target_mutation = current.clone();
        mutate_execution_and_reseal(
            &mut target_mutation,
            (
                COMPILED_MODE_ID,
                RegexAutomataHarnessKind::Doctest,
                NEXT_STATE_CASE,
            ),
        );
        assert_current_rejected(&inventory, &predecessor, &target_mutation);

        let mut missing_target = current.clone();
        missing_target
            .payload
            .execution_receipts
            .retain(|execution| {
                execution_identity_ref(execution)
                    != (
                        COMPILED_MODE_ID,
                        RegexAutomataHarnessKind::Doctest,
                        NEXT_STATE_CASE,
                    )
            });
        reseal(&mut missing_target);
        assert_current_rejected(&inventory, &predecessor, &missing_target);

        let mut missing_matrix = current.clone();
        missing_matrix.payload.look_mode_matrix = None;
        reseal(&mut missing_matrix);
        assert_current_rejected(&inventory, &predecessor, &missing_matrix);

        let mut missing_start_matrix = current.clone();
        missing_start_matrix.payload.start_mode_matrix = None;
        reseal(&mut missing_start_matrix);
        assert_current_rejected(&inventory, &predecessor, &missing_start_matrix);

        let mut missing_start_baseline = current.clone();
        missing_start_baseline.payload.start_mode_baseline = None;
        reseal(&mut missing_start_baseline);
        assert_current_rejected(&inventory, &predecessor, &missing_start_baseline);
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

    fn mutate_execution_and_reseal(
        report: &mut RegexAutomataAdapterReport,
        identity: (&str, RegexAutomataHarnessKind, &str),
    ) {
        let evidence_sha256 = {
            let execution = report
                .payload
                .execution_receipts
                .iter_mut()
                .find(|execution| execution_identity_ref(execution) == identity)
                .expect("exact execution identity");
            execution.assertion_executions[0]
                .fre_observation
                .push_str(":resealed");
            hash_json(execution, "encode adversarial transition execution").unwrap()
        };
        let receipt = report
            .payload
            .receipts
            .iter_mut()
            .find(|receipt| {
                (
                    receipt.mode_id.as_str(),
                    receipt.harness,
                    receipt.case_id.as_str(),
                ) == identity
            })
            .expect("exact receipt identity");
        receipt.disposition = RegexAutomataAdapterDisposition::Pass { evidence_sha256 };
        reseal(report);
    }

    fn execution_identity_ref(
        execution: &RegexAutomataExecutionReceipt,
    ) -> (&str, RegexAutomataHarnessKind, &str) {
        (
            execution.mode.mode_id.as_str(),
            execution.harness,
            execution.case_id.as_str(),
        )
    }

    fn reseal(report: &mut RegexAutomataAdapterReport) {
        report.payload.counts = adapter_counts(&report.payload.receipts);
        report.payload_sha256 =
            hash_json(&report.payload, "encode adversarial transition payload").unwrap();
    }

    fn assert_current_rejected(
        inventory: &RegexAutomataCorpusReport,
        predecessor: &RegexAutomataAdapterReport,
        current: &RegexAutomataAdapterReport,
    ) {
        assert!(current.validate_structure(inventory).is_err());
        assert!(
            validate_regex_automata_transition_cluster_strict_gain(
                inventory,
                predecessor,
                current,
            )
            .is_err(),
        );
    }
}
