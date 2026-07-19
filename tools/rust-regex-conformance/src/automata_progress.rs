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
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
};

use fre::{PortableRegex, PortableRegexSet, SearchLimits};
use regex_automata::{
    Input,
    dfa::{Automaton, dense},
};
use serde::{Deserialize, Serialize};

use crate::{
    CandidateIdentity, InventoryError, RegexAutomataCorpusReport, RegexAutomataHarnessKind,
    RegexAutomataObligation, sha256,
};

/// Complete candidate coverage report over every feature-mode membership.
pub const REGEX_AUTOMATA_ADAPTER_REPORT_SCHEMA: &str =
    "fre.regex-automata-0.4.14.adapter-report.v2";
const LEGACY_REGEX_AUTOMATA_ADAPTER_REPORT_SCHEMA: &str =
    "fre.regex-automata-0.4.14.adapter-report.v1";
/// One immutable source-work assignment derived from a complete report.
pub const REGEX_AUTOMATA_GAP_ASSIGNMENT_SCHEMA: &str =
    "fre.regex-automata-0.4.14.gap-assignment.v1";

const INVENTORY_UNSUPPORTED_REASON: &str = "fre-adapter.regex-automata-member-not-implemented";
const ASSIGNMENT_TARGET_LIMIT: usize = 16;
const LEGACY_REPORT_LIMITATIONS: [&str; 2] = [
    "A pass is emitted only after an exact registered adapter function executes successfully; absent registrations remain unsupported.",
    "One unique harness/case adapter disposition is projected across every authenticated feature-mode membership for that same identity.",
];
const REPORT_LIMITATIONS: [&str; 3] = [
    "A pass requires an exact mode/case execution receipt from a compiled registry membership and exhaustive execution of the authenticated upstream assertion inventory.",
    "No result is projected across build modes; a mode without its own compiled execution remains unsupported.",
    "The current bridge compiles only the package-default doctest mode; vcs-all-features doctest memberships remain unsupported until separately compiled and executed.",
];

const COMPILED_MODE_ID: &str = "package-default-doctest";
const AUTOMATON_SOURCE_PATH: &str = "src/dfa/automaton.rs";
const AUTOMATON_SOURCE_SHA256: &str =
    "a2af61cdfb7f16a8419a25ccb3ae250afe736ff397c7a3101c8a77781d096a9b";
const PATTERN_LEN_CASE: &str =
    "src/dfa/automaton.rs - dfa::automaton::Automaton::pattern_len (line 800)";
const TRY_SEARCH_FWD_CASE: &str =
    "src/dfa/automaton.rs - dfa::automaton::Automaton::try_search_fwd (line 1209)";

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

const PATTERN_LEN_ASSERTIONS: &[AssertionSpec] = &[AssertionSpec {
    assertion_id: "pattern-len-never-match-zero",
    source_line: 804,
    source_line_sha256: "3b7e88058c1a1fa94a3e1d8f128b2ff7ed129588f2eb3bd590c2282b2498adf9",
    expected_observation: "usize:0",
}];
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

// Each registration is one actual compiled membership. In particular, there
// is intentionally no all-features registration: this binary is built with
// regex-automata's package defaults, so relabelling this execution as the VCS
// all-features mode is structurally rejected.
const REGISTERED_ADAPTERS: &[RegisteredAdapter] = &[
    RegisteredAdapter {
        mode_id: COMPILED_MODE_ID,
        harness: RegexAutomataHarnessKind::Doctest,
        case_id: PATTERN_LEN_CASE,
        source: PATTERN_LEN_SOURCE,
        run: run_pattern_len_never_match,
    },
    RegisteredAdapter {
        mode_id: COMPILED_MODE_ID,
        harness: RegexAutomataHarnessKind::Doctest,
        case_id: TRY_SEARCH_FWD_CASE,
        source: TRY_SEARCH_FWD_SOURCE,
        run: run_try_search_fwd,
    },
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
        limitations: REPORT_LIMITATIONS
            .iter()
            .map(|text| (*text).to_owned())
            .collect(),
    };
    let report = RegexAutomataAdapterReport {
        schema: REGEX_AUTOMATA_ADAPTER_REPORT_SCHEMA.to_owned(),
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
        let limitations = if self.schema == REGEX_AUTOMATA_ADAPTER_REPORT_SCHEMA {
            REPORT_LIMITATIONS.as_slice()
        } else if self.schema == LEGACY_REGEX_AUTOMATA_ADAPTER_REPORT_SCHEMA {
            LEGACY_REPORT_LIMITATIONS.as_slice()
        } else {
            return Err(InventoryError::new(
                "regex-automata adapter report schema mismatch",
            ));
        };
        let expected_payload_sha256 = if self.schema == REGEX_AUTOMATA_ADAPTER_REPORT_SCHEMA {
            hash_json(&self.payload, "encode regex-automata adapter payload")?
        } else {
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
        if self.schema == LEGACY_REGEX_AUTOMATA_ADAPTER_REPORT_SCHEMA {
            if !self.payload.execution_receipts.is_empty()
                || self.payload.counts.pass != 0
                || self.payload.counts.fault != 0
                || self.payload.receipts.iter().any(|receipt| {
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
        validate_execution_receipt_set(inventory, self)?;
        Ok(())
    }

    fn validate_for_gain(
        &self,
        inventory: &RegexAutomataCorpusReport,
    ) -> Result<(), InventoryError> {
        self.validate_structure(inventory)?;
        if self.schema == REGEX_AUTOMATA_ADAPTER_REPORT_SCHEMA {
            validate_regex_automata_adapter_execution(inventory, self)?;
        }
        Ok(())
    }
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
    let bytes = read_owned_regular(path)?;
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
    let bytes = read_owned_regular(path)?;
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
    validate_regex_automata_adapter_execution(inventory, report)?;
    write_new_json(path, report)
}

/// Atomically publish one assignment without replacement.
pub fn write_regex_automata_gap_assignment(
    path: &Path,
    assignment: &RegexAutomataGapAssignment,
    inventory: &RegexAutomataCorpusReport,
    baseline: &RegexAutomataAdapterReport,
) -> Result<(), InventoryError> {
    assignment.validate(inventory, baseline)?;
    write_new_json(path, assignment)
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

fn require_compiled_mode(context: &AdapterContext<'_>) -> Result<(), String> {
    if context.mode.mode_id != COMPILED_MODE_ID
        || context.mode.harness != RegexAutomataHarnessKind::Doctest
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
    if mode_id != COMPILED_MODE_ID {
        return Err(InventoryError::new(
            "regex-automata adapter mode is not this binary's compiled mode",
        ));
    }
    let mut matching = inventory
        .payload
        .modes
        .iter()
        .filter(|mode| mode.id == mode_id);
    let mode = matching
        .next()
        .ok_or_else(|| InventoryError::new("compiled regex-automata mode is absent"))?;
    if matching.next().is_some()
        || mode.harness != RegexAutomataHarnessKind::Doctest
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
    })
}

fn validate_registered_adapter(
    inventory: &RegexAutomataCorpusReport,
    adapter: &RegisteredAdapter,
) -> Result<(), InventoryError> {
    let expected_source = match adapter.case_id {
        PATTERN_LEN_CASE => PATTERN_LEN_SOURCE,
        TRY_SEARCH_FWD_CASE => TRY_SEARCH_FWD_SOURCE,
        _ => {
            return Err(InventoryError::new(
                "regex-automata adapter has an unreviewed case",
            ));
        }
    };
    if adapter.mode_id != COMPILED_MODE_ID
        || adapter.harness != RegexAutomataHarnessKind::Doctest
        || adapter.source != expected_source
    {
        return Err(InventoryError::new(
            "regex-automata adapter registration binding mismatch",
        ));
    }
    let _ = mode_execution(inventory, adapter.mode_id)?;
    let file = inventory
        .payload
        .source
        .files
        .iter()
        .find(|file| file.path == adapter.source.source_path)
        .ok_or_else(|| InventoryError::new("adapter upstream source file is absent"))?;
    if file.sha256 != adapter.source.source_sha256
        || file.sha256 != AUTOMATON_SOURCE_SHA256
        || file.mode != "0644"
    {
        return Err(InventoryError::new(
            "adapter upstream source file identity mismatch",
        ));
    }
    validate_source_spec(&adapter.source)?;
    Ok(())
}

fn validate_source_spec(source: &SourceContractSpec) -> Result<(), InventoryError> {
    if source.source_path != AUTOMATON_SOURCE_PATH
        || source.source_sha256 != AUTOMATON_SOURCE_SHA256
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

fn validate_execution_receipt_set(
    inventory: &RegexAutomataCorpusReport,
    report: &RegexAutomataAdapterReport,
) -> Result<(), InventoryError> {
    let mut executions = BTreeMap::new();
    for execution in &report.payload.execution_receipts {
        let key = (
            execution.mode.mode_id.clone(),
            execution.harness,
            execution.case_id.clone(),
        );
        let adapter = REGISTERED_ADAPTERS
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

fn read_owned_regular(path: &Path) -> Result<Vec<u8>, InventoryError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| InventoryError::new(format!("stat {}: {error}", path.display())))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.uid() != unsafe_free_euid()
        || metadata.nlink() != 1
        || metadata.len() > 8 * 1_048_576
    {
        return Err(InventoryError::new(
            "unsafe regex-automata progress artifact",
        ));
    }
    fs::read(path).map_err(|error| InventoryError::new(format!("read {}: {error}", path.display())))
}

fn write_new_json(path: &Path, value: &impl Serialize) -> Result<(), InventoryError> {
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
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| InventoryError::new(format!("encode output: {error}")))?;
    bytes.push(b'\n');
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

    #[test]
    fn exact_upstream_spans_bind_every_assertion() {
        validate_source_spec(&PATTERN_LEN_SOURCE).unwrap();
        validate_source_spec(&TRY_SEARCH_FWD_SOURCE).unwrap();

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
    }

    #[test]
    fn observers_execute_exact_assertions_and_reject_misbinding_or_omission() {
        let mode = compiled_mode();
        execute_adapter(&REGISTERED_ADAPTERS[0], &mode).unwrap();
        execute_adapter(&REGISTERED_ADAPTERS[1], &mode).unwrap();

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
            ..REGISTERED_ADAPTERS[1]
        };
        assert_eq!(
            execute_adapter(&omitted, &mode).unwrap_err(),
            "assertion-execution-count-mismatch",
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
    }
}
