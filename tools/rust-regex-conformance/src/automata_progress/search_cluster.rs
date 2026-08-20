//! Exact public `dfa::regex::Regex` search examples layered on the immutable
//! 146-pass suffix-literal report. Historical registries and evidence remain
//! unchanged.

use std::collections::{BTreeMap, BTreeSet};

use fre::{PortableFindIterLimits, PortableRegex, PortableRegexSet};
use regex_automata::dfa::regex::Regex as UpstreamRegex;

use super::{
    AssertionSpec, COMPILED_MODE_ID, INVENTORY_UNSUPPORTED_REASON, REGEX_SOURCE_PATH,
    REGEX_SOURCE_SHA256, RegexAutomataAdapterCounts, RegexAutomataAdapterDisposition,
    RegexAutomataAdapterReport, RegexAutomataAdapterReportPayload, RegexAutomataAssertionExecution,
    RegexAutomataCorpusReport, RegexAutomataExecutionReceipt, RegexAutomataHarnessKind,
    RegexAutomataModeExecution, RegexAutomataStrictGain, SourceContractSpec, adapter_counts,
    gain_vectors, hash_json, mode_execution, obligation_membership_identity,
    order_execution_receipts, source_contract,
    suffix_literal_count::{
        REGEX_AUTOMATA_SUFFIX_LITERAL_COUNT_REPORT_SCHEMA, SUFFIX_LITERAL_COUNT_REPORT_LIMITATIONS,
    },
    validate_assertion_executions, validate_candidate, validate_execution_receipt_order,
    validate_source_spec,
};
use crate::{CandidateIdentity, InventoryError, sha256};

/// Successor schema for five package-default `dfa::regex::Regex` examples.
pub const REGEX_AUTOMATA_SEARCH_CLUSTER_REPORT_SCHEMA: &str =
    "fre.regex-automata-0.4.14.adapter-report.v11";

pub(super) const SEARCH_CLUSTER_REPORT_LIMITATIONS: [&str; 3] = [
    "A pass requires direct agreement between the authenticated upstream dfa::regex::Regex public API and the corresponding bounded FRE public API, including every exact match range.",
    "Only five package-default non-look doctest memberships are added; no result is projected across Cargo feature modes.",
    "The exact 146-membership suffix-literal v10 predecessor, including its look-mode matrix and every non-target disposition and execution, is retained exactly.",
];

const PREDECESSOR_REVISION: &str = "89c50b3b425a64c8cb68e310ba299d3604e32a32";
const PREDECESSOR_TREE: &str = "b4670430e78bf5ef96c5ca8b0811568c16191061";
const PREDECESSOR_PAYLOAD_SHA256: &str =
    "33bf94f3530d63ac9dcdddd2c2e4e857ec373cb470781a677535c61344043d43";
const TARGET_IDENTITIES_SHA256: &str =
    "197caf970abe6d03c664fc9641f97e872686ac1fbedabf82c2e40f28fccfcf85";

const NEW_CASE: &str = "src/dfa/regex.rs - dfa::regex::Regex::new (line 191)";
const IS_MATCH_CASE: &str = "src/dfa/regex.rs - dfa::regex::Regex<A>::is_match (line 348)";
const FIND_CASE: &str = "src/dfa/regex.rs - dfa::regex::Regex<A>::find (line 386)";
const FIND_ITER_CASE: &str = "src/dfa/regex.rs - dfa::regex::Regex<A>::find_iter (line 422)";
const PATTERN_LEN_CASE: &str = "src/dfa/regex.rs - dfa::regex::Regex<A>::pattern_len (line 571)";

const NEW_ASSERTIONS: &[AssertionSpec] = &[AssertionSpec {
    assertion_id: "regex-new-find",
    source_line: 195,
    source_line_sha256: "6398a3847e88a7834391f61671487f4e1e2f8e02f87cad9fcc24efd81feb05c8",
    expected_observation: "match:some:pattern=0:start=3:end=14",
}];
const IS_MATCH_ASSERTIONS: &[AssertionSpec] = &[
    AssertionSpec {
        assertion_id: "regex-is-match-true",
        source_line: 352,
        source_line_sha256: "01b0db5eebf4a8e8ea541a92e0d8474dfc8dc2b5b29584988b4d3cb75b3747ea",
        expected_observation: "bool:true",
    },
    AssertionSpec {
        assertion_id: "regex-is-match-false",
        source_line: 353,
        source_line_sha256: "58c3bec001ace9900a806e352faf228a282dfa547158f49a054a3b213ddf37d6",
        expected_observation: "bool:false",
    },
];
const FIND_ASSERTIONS: &[AssertionSpec] = &[
    AssertionSpec {
        assertion_id: "regex-find-greedy",
        source_line: 391,
        source_line_sha256: "70c6016282f821e96c432c0d7782e799e1431e5122f07c6687e8e9eac70a66b5",
        expected_observation: "match:some:pattern=0:start=3:end=11",
    },
    AssertionSpec {
        assertion_id: "regex-find-leftmost-first",
        source_line: 398,
        source_line_sha256: "b04d2e59d19a6379ebbeb14fb0b70c037def34f6d5f186d064ab805da498e35e",
        expected_observation: "match:some:pattern=0:start=0:end=3",
    },
];
const FIND_ITER_ASSERTIONS: &[AssertionSpec] = &[AssertionSpec {
    assertion_id: "regex-find-iter-three",
    source_line: 428,
    source_line_sha256: "2090216387be891912dd0a13092b2fe8a49fb454b79b880379223710cda4b699",
    expected_observation: "matches:0@0..4,0@5..10,0@11..17",
}];
const PATTERN_LEN_ASSERTIONS: &[AssertionSpec] = &[AssertionSpec {
    assertion_id: "regex-pattern-len-three",
    source_line: 576,
    source_line_sha256: "a118e42a386a024b6923c285bf0143a7df9375c064932e7894ba254e4579c13d",
    expected_observation: "usize:3",
}];

const NEW_SOURCE: SourceContractSpec = SourceContractSpec {
    source_path: REGEX_SOURCE_PATH,
    source_sha256: REGEX_SOURCE_SHA256,
    span_start_line: 191,
    span_end_line: 200,
    source_span: include_str!("../fixtures/dfa-regex-new-v1.txt"),
    source_span_sha256: "520efddde1a3f9d5c82f41e5591f516c80763623cba94132b7fea55fe44f5844",
    assertion_inventory_sha256: "b2c18d09990cf485be6044643f27ae49ddd911708e96489edfd18c7a713584e4",
    assertions: NEW_ASSERTIONS,
};
const IS_MATCH_SOURCE: SourceContractSpec = SourceContractSpec {
    source_path: REGEX_SOURCE_PATH,
    source_sha256: REGEX_SOURCE_SHA256,
    span_start_line: 348,
    span_end_line: 355,
    source_span: include_str!("../fixtures/dfa-regex-is-match-v1.txt"),
    source_span_sha256: "25230eeabc643d8adffc9e74d5d63adf38b4b9415647eacc1c7e1c36141e7d3f",
    assertion_inventory_sha256: "752fe64490375ce1a7fd4844f26f66dfa68d8e37f4ec1d2c65921afaf787adae",
    assertions: IS_MATCH_ASSERTIONS,
};
const FIND_SOURCE: SourceContractSpec = SourceContractSpec {
    source_path: REGEX_SOURCE_PATH,
    source_sha256: REGEX_SOURCE_SHA256,
    span_start_line: 386,
    span_end_line: 400,
    source_span: include_str!("../fixtures/dfa-regex-find-v1.txt"),
    source_span_sha256: "58606e07c63c42b92e5bd15917019f110f5638a84a2aac7c755400d45b1b6fa4",
    assertion_inventory_sha256: "acd72d54639993b70519880149a42b994dbcc93c4fa288f97eda8aec1de37d11",
    assertions: FIND_ASSERTIONS,
};
const FIND_ITER_SOURCE: SourceContractSpec = SourceContractSpec {
    source_path: REGEX_SOURCE_PATH,
    source_sha256: REGEX_SOURCE_SHA256,
    span_start_line: 422,
    span_end_line: 434,
    source_span: include_str!("../fixtures/dfa-regex-find-iter-v1.txt"),
    source_span_sha256: "46e74ba2cbee0f46c8491e6e5792dd8d9a8b8e0cbf25dd131cd4b9956d6f3381",
    assertion_inventory_sha256: "9996ea47fdbc1eaf7bbc2a9b05e7c687362564e1634f93f702635312248f0ebf",
    assertions: FIND_ITER_ASSERTIONS,
};
const PATTERN_LEN_SOURCE: SourceContractSpec = SourceContractSpec {
    source_path: REGEX_SOURCE_PATH,
    source_sha256: REGEX_SOURCE_SHA256,
    span_start_line: 571,
    span_end_line: 578,
    source_span: include_str!("../fixtures/dfa-regex-pattern-len-v1.txt"),
    source_span_sha256: "19a85d753f2d0e213e884a22ebae2c34a89d16b295e9ce276ed54339b6787f92",
    assertion_inventory_sha256: "c4102ab55c71b4ba1aacd598f8bde2be9f7db15da227505f1c9b70fa99010ee4",
    assertions: PATTERN_LEN_ASSERTIONS,
};

const SOURCES: [(&str, SourceContractSpec); 5] = [
    (NEW_CASE, NEW_SOURCE),
    (IS_MATCH_CASE, IS_MATCH_SOURCE),
    (FIND_CASE, FIND_SOURCE),
    (FIND_ITER_CASE, FIND_ITER_SOURCE),
    (PATTERN_LEN_CASE, PATTERN_LEN_SOURCE),
];

/// Extend exact suffix-literal v10 with five genuine public-API observations.
pub fn build_regex_automata_search_cluster_report(
    inventory: &RegexAutomataCorpusReport,
    previous: &RegexAutomataAdapterReport,
    candidate: CandidateIdentity,
) -> Result<RegexAutomataAdapterReport, InventoryError> {
    validate_predecessor(inventory, previous)?;
    validate_candidate(&candidate)?;
    if candidate.revision == PREDECESSOR_REVISION || candidate.tree == PREDECESSOR_TREE {
        return Err(InventoryError::new(
            "search-cluster candidate is not distinct from its predecessor",
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
        let execution = execute_case(&receipt.case_id, &mode)?;
        let evidence_sha256 = hash_json(&execution, "encode search-cluster execution")?;
        receipt.disposition = RegexAutomataAdapterDisposition::Pass { evidence_sha256 };
        executions.push(execution);
        observed.insert(identity);
    }
    if observed != targets {
        return Err(InventoryError::new(
            "search-cluster inventory target denominator mismatch",
        ));
    }
    let execution_receipts =
        order_execution_receipts(&receipts, executions, "search-cluster report")?;
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
        start_mode_matrix: None,
        start_mode_baseline: None,
        limitations: SEARCH_CLUSTER_REPORT_LIMITATIONS
            .iter()
            .map(|text| (*text).to_owned())
            .collect(),
    };
    let report = RegexAutomataAdapterReport {
        schema: REGEX_AUTOMATA_SEARCH_CLUSTER_REPORT_SCHEMA.to_owned(),
        payload_sha256: hash_json(&payload, "encode search-cluster report payload")?,
        payload,
    };
    validate_search_cluster_execution_after_structure(inventory, &report)?;
    Ok(report)
}

/// Require an exact monotonic 146 -> 151 transition.
pub fn validate_regex_automata_search_cluster_strict_gain(
    inventory: &RegexAutomataCorpusReport,
    previous: &RegexAutomataAdapterReport,
    current: &RegexAutomataAdapterReport,
) -> Result<RegexAutomataStrictGain, InventoryError> {
    validate_predecessor(inventory, previous)?;
    current.validate_structure(inventory)?;
    if current.schema != REGEX_AUTOMATA_SEARCH_CLUSTER_REPORT_SCHEMA {
        return Err(InventoryError::new(
            "current report is not a search-cluster report",
        ));
    }
    let targets = target_identities(inventory)?;
    let (unique, memberships) = gain_vectors(
        &previous.payload.receipts,
        &current.payload.receipts,
        &targets,
    )?;
    if (unique, memberships) != (5, 5) {
        return Err(InventoryError::new(
            "search-cluster gain is not exact five-membership progress",
        ));
    }
    Ok(RegexAutomataStrictGain {
        family: "doctest-dfa-regex".to_owned(),
        gained_unique_cases: unique,
        gained_mode_memberships: memberships,
        previous_pass: 146,
        current_pass: 151,
    })
}

pub(super) fn validate_search_cluster_execution_after_structure(
    inventory: &RegexAutomataCorpusReport,
    report: &RegexAutomataAdapterReport,
) -> Result<(), InventoryError> {
    if report.schema != REGEX_AUTOMATA_SEARCH_CLUSTER_REPORT_SCHEMA
        || report.payload.counts
            != (RegexAutomataAdapterCounts {
                pass: 151,
                unsupported: 3_691,
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
            "search-cluster candidate identity or cardinality mismatch",
        ));
    }
    validate_execution_receipt_order(report)?;
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
    if previous_executions.len() != 146 || current_executions.len() != 151 {
        return Err(InventoryError::new(
            "search-cluster execution denominator mismatch",
        ));
    }
    for (identity, execution) in &previous_executions {
        if current_executions.get(identity) != Some(execution) {
            return Err(InventoryError::new(
                "search-cluster changed retained execution evidence",
            ));
        }
    }
    for identity in &targets {
        let execution = current_executions
            .get(identity)
            .ok_or_else(|| InventoryError::new("search-cluster target lacks execution evidence"))?;
        if *execution != &execute_case(&identity.2, &mode)? {
            return Err(InventoryError::new(
                "search-cluster target execution differs from direct replay",
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
    if previous.schema != REGEX_AUTOMATA_SUFFIX_LITERAL_COUNT_REPORT_SCHEMA
        || previous.payload_sha256 != PREDECESSOR_PAYLOAD_SHA256
        || previous.payload.candidate
            != (CandidateIdentity {
                revision: PREDECESSOR_REVISION.to_owned(),
                tree: PREDECESSOR_TREE.to_owned(),
                tracked_and_untracked_worktree_clean: true,
            })
        || previous.payload.counts
            != (RegexAutomataAdapterCounts {
                pass: 146,
                unsupported: 3_696,
                fault: 0,
                total: 3_842,
            })
    {
        return Err(InventoryError::new(
            "search-cluster predecessor authority mismatch",
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
    previous.payload.limitations = SUFFIX_LITERAL_COUNT_REPORT_LIMITATIONS
        .iter()
        .map(|text| (*text).to_owned())
        .collect();
    REGEX_AUTOMATA_SUFFIX_LITERAL_COUNT_REPORT_SCHEMA.clone_into(&mut previous.schema);
    previous.payload_sha256 = hash_json(&previous.payload, "reconstruct v10 predecessor payload")?;
    Ok(previous)
}

fn target_identities(
    inventory: &RegexAutomataCorpusReport,
) -> Result<BTreeSet<(String, RegexAutomataHarnessKind, String)>, InventoryError> {
    for (_, source) in SOURCES {
        validate_source_spec(&source)?;
    }
    let cases = SOURCES
        .iter()
        .map(|(case, _)| *case)
        .collect::<BTreeSet<_>>();
    let targets = inventory
        .payload
        .obligations
        .iter()
        .filter(|obligation| {
            obligation.mode_id == COMPILED_MODE_ID
                && obligation.harness == RegexAutomataHarnessKind::Doctest
                && cases.contains(obligation.case_id.as_str())
        })
        .map(obligation_membership_identity)
        .collect::<BTreeSet<_>>();
    let mut identities = targets
        .iter()
        .map(|(mode, _, case)| format!("{mode}\tdoctest\t{case}\n"))
        .collect::<Vec<_>>();
    identities.sort_unstable();
    if targets.len() != 5 || sha256(identities.concat().as_bytes()) != TARGET_IDENTITIES_SHA256 {
        return Err(InventoryError::new(
            "search-cluster target identity seal mismatch",
        ));
    }
    Ok(targets)
}

fn execute_case(
    case_id: &str,
    mode: &RegexAutomataModeExecution,
) -> Result<RegexAutomataExecutionReceipt, InventoryError> {
    require_mode(mode)?;
    let (source, assertions) = match case_id {
        NEW_CASE => (NEW_SOURCE, execute_new()?),
        IS_MATCH_CASE => (IS_MATCH_SOURCE, execute_is_match()?),
        FIND_CASE => (FIND_SOURCE, execute_find()?),
        FIND_ITER_CASE => (FIND_ITER_SOURCE, execute_find_iter()?),
        PATTERN_LEN_CASE => (PATTERN_LEN_SOURCE, execute_pattern_len()?),
        _ => return Err(InventoryError::new("unreviewed search-cluster case")),
    };
    validate_assertion_executions(source.assertions, &assertions)
        .map_err(|reason| InventoryError::new(format!("search-cluster {case_id}: {reason}")))?;
    Ok(RegexAutomataExecutionReceipt {
        mode: mode.clone(),
        harness: RegexAutomataHarnessKind::Doctest,
        case_id: case_id.to_owned(),
        source: source_contract(&source),
        assertion_executions: assertions,
    })
}

fn execute_new() -> Result<Vec<RegexAutomataAssertionExecution>, InventoryError> {
    let pattern = "foo[0-9]+bar";
    let haystack = b"zzzfoo12345barzzz";
    let upstream = UpstreamRegex::new(pattern)
        .map_err(upstream_build)?
        .find(haystack);
    let fre = fre_find(pattern, haystack)?;
    Ok(vec![observation(
        &NEW_ASSERTIONS[0],
        upstream_match(upstream),
        fre_match(fre),
    )])
}

fn execute_is_match() -> Result<Vec<RegexAutomataAssertionExecution>, InventoryError> {
    let pattern = "foo[0-9]+bar";
    let upstream = UpstreamRegex::new(pattern).map_err(upstream_build)?;
    let fre = PortableRegex::new(pattern).map_err(fre_build)?;
    let vectors = [b"foo12345bar".as_slice(), b"foobar".as_slice()];
    let mut executions = Vec::new();
    for (assertion, haystack) in IS_MATCH_ASSERTIONS.iter().zip(vectors) {
        let upstream_observed = upstream.is_match(haystack);
        let fre_observed = fre.is_match(haystack);
        executions.push(observation(
            assertion,
            format!("bool:{upstream_observed}"),
            format!("bool:{fre_observed}"),
        ));
    }
    Ok(executions)
}

fn execute_find() -> Result<Vec<RegexAutomataAssertionExecution>, InventoryError> {
    let vectors = [
        ("foo[0-9]+", b"zzzfoo12345zzz".as_slice()),
        ("abc|a", b"abc".as_slice()),
    ];
    let mut executions = Vec::new();
    for (assertion, (pattern, haystack)) in FIND_ASSERTIONS.iter().zip(vectors) {
        let upstream = UpstreamRegex::new(pattern)
            .map_err(upstream_build)?
            .find(haystack);
        let fre = fre_find(pattern, haystack)?;
        executions.push(observation(
            assertion,
            upstream_match(upstream),
            fre_match(fre),
        ));
    }
    Ok(executions)
}

fn execute_find_iter() -> Result<Vec<RegexAutomataAssertionExecution>, InventoryError> {
    let pattern = "foo[0-9]+";
    let haystack = b"foo1 foo12 foo123";
    let upstream = UpstreamRegex::new(pattern)
        .map_err(upstream_build)?
        .find_iter(haystack)
        .map(|matched| (matched.pattern().as_usize(), matched.start(), matched.end()))
        .collect::<Vec<_>>();
    let fre = PortableRegex::new(pattern)
        .map_err(fre_build)?
        .find_iter(haystack, PortableFindIterLimits::unlimited())
        .map_err(fre_search)?
        .map(|matched| {
            matched
                .map(|matched| (0, matched.start(), matched.end()))
                .map_err(fre_search)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(vec![observation(
        &FIND_ITER_ASSERTIONS[0],
        matches_observation(&upstream),
        matches_observation(&fre),
    )])
}

fn execute_pattern_len() -> Result<Vec<RegexAutomataAssertionExecution>, InventoryError> {
    let patterns = [r"[a-z]+", r"[0-9]+", r"\w+"];
    let upstream = UpstreamRegex::new_many(&patterns).map_err(upstream_build)?;
    let fre = PortableRegexSet::new(patterns).map_err(fre_build)?;
    Ok(vec![observation(
        &PATTERN_LEN_ASSERTIONS[0],
        format!("usize:{}", upstream.pattern_len()),
        format!("usize:{}", fre.len()),
    )])
}

fn fre_find(pattern: &str, haystack: &[u8]) -> Result<Option<fre::Match>, InventoryError> {
    Ok(PortableRegex::new(pattern)
        .map_err(fre_build)?
        .find(haystack))
}

fn upstream_match(matched: Option<regex_automata::Match>) -> String {
    matched.map_or_else(
        || "match:none".to_owned(),
        |matched| {
            format!(
                "match:some:pattern={}:start={}:end={}",
                matched.pattern().as_usize(),
                matched.start(),
                matched.end(),
            )
        },
    )
}

fn fre_match(matched: Option<fre::Match>) -> String {
    matched.map_or_else(
        || "match:none".to_owned(),
        |matched| {
            format!(
                "match:some:pattern=0:start={}:end={}",
                matched.start(),
                matched.end(),
            )
        },
    )
}

fn matches_observation(matches: &[(usize, usize, usize)]) -> String {
    let body = matches
        .iter()
        .map(|(pattern, start, end)| format!("{pattern}@{start}..{end}"))
        .collect::<Vec<_>>()
        .join(",");
    format!("matches:{body}")
}

fn upstream_build(error: impl std::fmt::Display) -> InventoryError {
    InventoryError::new(format!("build upstream dfa::regex::Regex: {error}"))
}

fn fre_build(error: impl std::fmt::Display) -> InventoryError {
    InventoryError::new(format!("build FRE public regex API: {error}"))
}

fn fre_search(error: impl std::fmt::Display) -> InventoryError {
    InventoryError::new(format!("search FRE public regex API: {error}"))
}

fn observation(
    assertion: &AssertionSpec,
    upstream: String,
    fre: String,
) -> RegexAutomataAssertionExecution {
    RegexAutomataAssertionExecution {
        assertion_id: assertion.assertion_id.to_owned(),
        upstream_observation: upstream,
        fre_observation: fre,
    }
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
        return Err(InventoryError::new("search-cluster compiled mode mismatch"));
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
    fn exact_sources_and_all_seven_assertions_execute() {
        let mode = compiled_mode();
        let executions = SOURCES
            .iter()
            .map(|(case, _)| execute_case(case, &mode).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            executions
                .iter()
                .map(|execution| execution.assertion_executions.len())
                .collect::<Vec<_>>(),
            vec![1, 2, 2, 1, 1],
        );
        for (_, source) in SOURCES {
            validate_source_spec(&source).unwrap();
        }
    }

    #[test]
    fn public_api_observers_reject_mode_relabel() {
        let mut mode = compiled_mode();
        mode.mode_id = "vcs-all-features-doctest".to_owned();
        assert!(execute_case(NEW_CASE, &mode).is_err());
    }

    #[test]
    fn all_five_public_api_observers_are_repeatable() {
        let mode = compiled_mode();
        for (case, _) in SOURCES {
            assert_eq!(
                execute_case(case, &mode).unwrap(),
                execute_case(case, &mode).unwrap(),
            );
        }
    }

    #[test]
    fn search_cluster_transition_identity_is_exact_v11() {
        assert_eq!(
            REGEX_AUTOMATA_SEARCH_CLUSTER_REPORT_SCHEMA,
            "fre.regex-automata-0.4.14.adapter-report.v11",
        );
        assert_eq!(PREDECESSOR_REVISION.len(), 40);
        assert_eq!(PREDECESSOR_TREE.len(), 40);
        assert_eq!(PREDECESSOR_PAYLOAD_SHA256.len(), 64);
        assert!(
            SEARCH_CLUSTER_REPORT_LIMITATIONS
                .iter()
                .any(|text| text.contains("146-membership")),
        );
    }

    #[test]
    #[ignore = "requires authenticated external inventory and suffix-literal-v10 report fixtures"]
    fn authenticated_v10_v11_transition_is_exact_repeatable_and_fail_closed() {
        let inventory_path = authenticated_fixture(
            "FRE_SEARCH_CLUSTER_INVENTORY",
            "b6c4ff208f546f2b45d9a37d1f5508680d0c2a6e29c0e59df9f4b96f1dcdfbe2",
            0o444,
        );
        let predecessor_path = authenticated_fixture(
            "FRE_SEARCH_CLUSTER_V10",
            "a47d004a6ba16045119dea1d915d068ed1f4fb86cc93534da8fb90ef798f5bee",
            0o400,
        );
        let inventory = crate::read_regex_automata_corpus_report(&inventory_path).unwrap();
        let predecessor =
            crate::read_regex_automata_adapter_report(&predecessor_path, &inventory).unwrap();
        let candidate = CandidateIdentity {
            revision: std::env::var("FRE_SEARCH_CLUSTER_FINAL_REVISION").unwrap(),
            tree: std::env::var("FRE_SEARCH_CLUSTER_FINAL_TREE").unwrap(),
            tracked_and_untracked_worktree_clean: true,
        };
        let current =
            build_regex_automata_search_cluster_report(&inventory, &predecessor, candidate.clone())
                .unwrap();
        let repeated =
            build_regex_automata_search_cluster_report(&inventory, &predecessor, candidate)
                .unwrap();

        assert_eq!(current, repeated);
        assert_eq!(current.payload.counts.pass, 151);
        assert_eq!(current.payload.counts.unsupported, 3_691);
        assert_eq!(current.payload.execution_receipts.len(), 151);
        assert_eq!(
            reconstruct_predecessor(&current, &target_identities(&inventory).unwrap()).unwrap(),
            predecessor,
        );
        let gain =
            validate_regex_automata_search_cluster_strict_gain(&inventory, &predecessor, &current)
                .unwrap();
        assert_eq!(
            (gain.gained_unique_cases, gain.gained_mode_memberships),
            (5, 5),
        );
        assert_eq!((gain.previous_pass, gain.current_pass), (146, 151));

        let mut retained_mutation = current.clone();
        mutate_execution_and_reseal(
            &mut retained_mutation,
            (
                COMPILED_MODE_ID,
                RegexAutomataHarnessKind::Doctest,
                "src/dfa/automaton.rs - dfa::automaton::Automaton::pattern_len (line 800)",
            ),
        );
        assert_current_rejected(&inventory, &predecessor, &retained_mutation);

        let mut target_mutation = current.clone();
        mutate_execution_and_reseal(
            &mut target_mutation,
            (
                COMPILED_MODE_ID,
                RegexAutomataHarnessKind::Doctest,
                NEW_CASE,
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
                        NEW_CASE,
                    )
            });
        reseal(&mut missing_target);
        assert_current_rejected(&inventory, &predecessor, &missing_target);

        let mut missing_matrix = current.clone();
        missing_matrix.payload.look_mode_matrix = None;
        reseal(&mut missing_matrix);
        assert_current_rejected(&inventory, &predecessor, &missing_matrix);

        let predecessor_identity = CandidateIdentity {
            revision: PREDECESSOR_REVISION.to_owned(),
            tree: PREDECESSOR_TREE.to_owned(),
            tracked_and_untracked_worktree_clean: true,
        };
        assert!(
            build_regex_automata_search_cluster_report(
                &inventory,
                &predecessor,
                predecessor_identity,
            )
            .is_err(),
        );
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
            hash_json(execution, "encode adversarial search-cluster execution").unwrap()
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
            hash_json(&report.payload, "encode adversarial search-cluster payload").unwrap();
    }

    fn assert_current_rejected(
        inventory: &RegexAutomataCorpusReport,
        predecessor: &RegexAutomataAdapterReport,
        current: &RegexAutomataAdapterReport,
    ) {
        assert!(current.validate_structure(inventory).is_err());
        assert!(
            validate_regex_automata_search_cluster_strict_gain(inventory, predecessor, current,)
                .is_err(),
        );
    }
}
