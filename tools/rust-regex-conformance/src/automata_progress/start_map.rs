use std::collections::{BTreeMap, BTreeSet};

use fre_kernels::{
    ByteStartClass as StartClass, ByteStartDirection as Direction, ByteStartMap,
    ByteStartMapBuildError as BuildError, ByteStartMapBuildLimits as BuildLimits,
    ByteStartMapLookupError as LookupError, ByteStartMapLookupLimits as LookupLimits,
    ByteStartMapResource as Resource,
};

use super::{
    AdapterContext, AssertionSpec, COMPILED_UNIT_MODE_ID, INVENTORY_UNSUPPORTED_REASON, Input,
    REGEX_AUTOMATA_UNICODE_WORD_LOOK_REPORT_SCHEMA, RegexAutomataAdapterCounts,
    RegexAutomataAdapterDisposition, RegexAutomataAdapterReport, RegexAutomataAdapterReportPayload,
    RegexAutomataAssertionExecution, RegexAutomataCorpusReport, RegexAutomataExecutionReceipt,
    RegexAutomataHarnessKind, RegexAutomataStrictGain, RegisteredAdapter, SourceContractSpec,
    adapter_counts, execute_adapter, gain_vectors, hash_json, mode_execution,
    obligation_membership_identity, order_execution_receipts, unicode_word_look,
    validate_candidate, validate_execution_receipt_order, validate_source_spec,
};
use crate::{CandidateIdentity, InventoryError};

/// Report schema for the exact package-default four-case start-map gain.
///
/// Versions 7 and 8 are intentionally left available for two independently
/// qualified v6 successor families that were active when this protocol was
/// composed.
pub const REGEX_AUTOMATA_START_MAP_REPORT_SCHEMA: &str =
    "fre.regex-automata-0.4.14.adapter-report.v9";

pub(super) const START_MAP_REPORT_LIMITATIONS: [&str; 3] = [
    "A pass requires direct agreement between authenticated Config boundary selection, the sealed upstream StartByteMap theorem, and an exact-limit FRE byte-start-map lookup.",
    "Only four package-default util::start unit memberships are added; no result is projected across Cargo feature modes.",
    "The predecessor 141-membership Unicode word-look report, including its compiled-mode matrix and every non-target disposition and execution receipt, is retained exactly.",
];

const PREDECESSOR_REVISION: &str = "9d47b9c98ba546d0fab1b32aecefd4e2d4424567";
const PREDECESSOR_TREE: &str = "d0741326dc04efe237fdff43a639ee57e37dd011";
const PREDECESSOR_PAYLOAD_SHA256: &str =
    "d3a56bee79c7d157db60c11f7cdf10b1f815b0f8d51ab7ba50132e3b2ce80e63";
const TARGET_IDENTITIES_SHA256: &str =
    "c6cc9815e7adbe3f197140b82236642cc845fd10c784d7f413dbf6566d999986";

pub(super) const SOURCE_PATH: &str = "src/util/start.rs";
pub(super) const SOURCE_SHA256: &str =
    "1ab2dec7c452ae943118cd1c3b6becc84afba1fbb8b6894d81ef7d65141d95ab";

const START_FWD_DONE_RANGE_CASE: &str = "util::start::tests::start_fwd_done_range";
const START_REV_DONE_RANGE_CASE: &str = "util::start::tests::start_rev_done_range";
const START_FWD_CASE: &str = "util::start::tests::start_fwd";
const START_REV_CASE: &str = "util::start::tests::start_rev";

const START_FWD_DONE_RANGE_ASSERTIONS: &[AssertionSpec] = &[AssertionSpec {
    assertion_id: "start-fwd-done-range-text",
    source_line: 419,
    source_line_sha256: "480f12c6e2eda405e74fff8a57d323e3499043ec7b31fcce8004a3dfd6f1cf81",
    expected_observation: "start:text",
}];
const START_REV_DONE_RANGE_ASSERTIONS: &[AssertionSpec] = &[AssertionSpec {
    assertion_id: "start-rev-done-range-text",
    source_line: 429,
    source_line_sha256: "480f12c6e2eda405e74fff8a57d323e3499043ec7b31fcce8004a3dfd6f1cf81",
    expected_observation: "start:text",
}];
const START_FWD_ASSERTIONS: &[AssertionSpec] = &[
    AssertionSpec {
        assertion_id: "start-fwd-empty-text",
        source_line: 443,
        source_line_sha256: "93c637a68d35b2be73d61ce89edf4ba4fae7c678f78eb59670695e3572dd5fda",
        expected_observation: "start:text",
    },
    AssertionSpec {
        assertion_id: "start-fwd-zero-text",
        source_line: 444,
        source_line_sha256: "4f69edfb114207c9a770a181e825332243340b1cc9307f7f503c9dd17e562f9a",
        expected_observation: "start:text",
    },
    AssertionSpec {
        assertion_id: "start-fwd-newline-zero-text",
        source_line: 445,
        source_line_sha256: "60184c22803c7d4715daeae84fa76fc336518a889e782cfe5b905996ceef5314",
        expected_observation: "start:text",
    },
    AssertionSpec {
        assertion_id: "start-fwd-line-lf",
        source_line: 447,
        source_line_sha256: "678d11edde6b3ac7548b8337f5334364e6cd2ea820c3b1fc2c32ddcf0a96e16d",
        expected_observation: "start:line-lf",
    },
    AssertionSpec {
        assertion_id: "start-fwd-line-cr",
        source_line: 449,
        source_line_sha256: "4de651af1669a2a3ae59dc896b49237ed96e28324bc03b8adcd1a3ca3f6a5c4a",
        expected_observation: "start:line-cr",
    },
    AssertionSpec {
        assertion_id: "start-fwd-word-byte",
        source_line: 451,
        source_line_sha256: "8e1430a9e8928321562655f08ca47e772e43845ef542dc9ee4f528117a42997a",
        expected_observation: "start:word-byte",
    },
    AssertionSpec {
        assertion_id: "start-fwd-non-word-byte",
        source_line: 453,
        source_line_sha256: "887298586e5dbf0ba05d1f30332d71866f28fd20cd4240db508916469eac3578",
        expected_observation: "start:non-word-byte",
    },
];
const START_REV_ASSERTIONS: &[AssertionSpec] = &[
    AssertionSpec {
        assertion_id: "start-rev-empty-text",
        source_line: 467,
        source_line_sha256: "93c637a68d35b2be73d61ce89edf4ba4fae7c678f78eb59670695e3572dd5fda",
        expected_observation: "start:text",
    },
    AssertionSpec {
        assertion_id: "start-rev-end-text",
        source_line: 468,
        source_line_sha256: "4f69edfb114207c9a770a181e825332243340b1cc9307f7f503c9dd17e562f9a",
        expected_observation: "start:text",
    },
    AssertionSpec {
        assertion_id: "start-rev-newline-end-text",
        source_line: 469,
        source_line_sha256: "b9d1eba309dfb5aaa97b72b5eb9bb01c57df31f24821385eb63e7618526ed5c0",
        expected_observation: "start:text",
    },
    AssertionSpec {
        assertion_id: "start-rev-line-lf",
        source_line: 471,
        source_line_sha256: "fcaa5c96b9f5f6b28cd9378d562173f5788787ba0bf750c4d1bf9e44fed5a4d3",
        expected_observation: "start:line-lf",
    },
    AssertionSpec {
        assertion_id: "start-rev-line-cr",
        source_line: 473,
        source_line_sha256: "11fa1ea9fbb73a7785716fab8e18cf997f09150346d44d87368b4daba7715459",
        expected_observation: "start:line-cr",
    },
    AssertionSpec {
        assertion_id: "start-rev-word-byte",
        source_line: 475,
        source_line_sha256: "abf07a2d9021ef2bc5dea322d50c80c4e86c72ff9f77a0473fe7b3db490757c9",
        expected_observation: "start:word-byte",
    },
    AssertionSpec {
        assertion_id: "start-rev-non-word-byte",
        source_line: 477,
        source_line_sha256: "f6f7552fdb210db8a1fee845900327496ebc4e6323ec0afd742aa80619647ec9",
        expected_observation: "start:non-word-byte",
    },
];

const START_FWD_DONE_RANGE_SOURCE: SourceContractSpec = SourceContractSpec {
    source_path: SOURCE_PATH,
    source_sha256: SOURCE_SHA256,
    span_start_line: 412,
    span_end_line: 420,
    source_span: r#"    #[test]
    fn start_fwd_done_range() {
        let smap = StartByteMap::new(&LookMatcher::default());
        let input = Input::new("").range(1..0);
        let config = Config::from_input_forward(&input);
        let start =
            config.get_look_behind().map_or(Start::Text, |b| smap.get(b));
        assert_eq!(Start::Text, start);
    }
"#,
    source_span_sha256: "5d0a25f679637415a0f46ace169710dd8b40ad8f645ae820e74ae63262f3d5d6",
    assertion_inventory_sha256: "f0305d22ea1ddb6d4f42f00017f91b1b8f97f678ff4eba2eea85dbe23d6c4d0c",
    assertions: START_FWD_DONE_RANGE_ASSERTIONS,
};
const START_REV_DONE_RANGE_SOURCE: SourceContractSpec = SourceContractSpec {
    source_path: SOURCE_PATH,
    source_sha256: SOURCE_SHA256,
    span_start_line: 422,
    span_end_line: 430,
    source_span: r#"    #[test]
    fn start_rev_done_range() {
        let smap = StartByteMap::new(&LookMatcher::default());
        let input = Input::new("").range(1..0);
        let config = Config::from_input_reverse(&input);
        let start =
            config.get_look_behind().map_or(Start::Text, |b| smap.get(b));
        assert_eq!(Start::Text, start);
    }
"#,
    source_span_sha256: "6b46ce5ff8117f13d05dc39a1f3310f3ff3f0430d8d53fce2fb08523b0c8333f",
    assertion_inventory_sha256: "33e97918ff3e02a969229a3a47b13fce632d7ad2b6092c5193c488b2c4773ceb",
    assertions: START_REV_DONE_RANGE_ASSERTIONS,
};
const START_FWD_SOURCE: SourceContractSpec = SourceContractSpec {
    source_path: SOURCE_PATH,
    source_sha256: SOURCE_SHA256,
    span_start_line: 432,
    span_end_line: 454,
    source_span: r#"    #[test]
    fn start_fwd() {
        let f = |haystack, start, end| {
            let smap = StartByteMap::new(&LookMatcher::default());
            let input = Input::new(haystack).range(start..end);
            let config = Config::from_input_forward(&input);
            let start =
                config.get_look_behind().map_or(Start::Text, |b| smap.get(b));
            start
        };

        assert_eq!(Start::Text, f("", 0, 0));
        assert_eq!(Start::Text, f("abc", 0, 3));
        assert_eq!(Start::Text, f("\nabc", 0, 3));

        assert_eq!(Start::LineLF, f("\nabc", 1, 3));

        assert_eq!(Start::LineCR, f("\rabc", 1, 3));

        assert_eq!(Start::WordByte, f("abc", 1, 3));

        assert_eq!(Start::NonWordByte, f(" abc", 1, 3));
    }
"#,
    source_span_sha256: "32fd4caf1625baec83c51c67bd1a2efe625caa7c453201cfed3c1f4807b4aa6c",
    assertion_inventory_sha256: "4fa6e3a67f3e8db496604eaae24112f21497d2f125b78a4dc08de8af6d734583",
    assertions: START_FWD_ASSERTIONS,
};
const START_REV_SOURCE: SourceContractSpec = SourceContractSpec {
    source_path: SOURCE_PATH,
    source_sha256: SOURCE_SHA256,
    span_start_line: 456,
    span_end_line: 478,
    source_span: r#"    #[test]
    fn start_rev() {
        let f = |haystack, start, end| {
            let smap = StartByteMap::new(&LookMatcher::default());
            let input = Input::new(haystack).range(start..end);
            let config = Config::from_input_reverse(&input);
            let start =
                config.get_look_behind().map_or(Start::Text, |b| smap.get(b));
            start
        };

        assert_eq!(Start::Text, f("", 0, 0));
        assert_eq!(Start::Text, f("abc", 0, 3));
        assert_eq!(Start::Text, f("abc\n", 0, 4));

        assert_eq!(Start::LineLF, f("abc\nz", 0, 3));

        assert_eq!(Start::LineCR, f("abc\rz", 0, 3));

        assert_eq!(Start::WordByte, f("abc", 0, 2));

        assert_eq!(Start::NonWordByte, f("abc ", 0, 3));
    }
"#,
    source_span_sha256: "103ddf5dea403463250722bd86698ec7c3ded206766c95a43c8633c6c05d0cfb",
    assertion_inventory_sha256: "f390cf143d32fb77c25ebfc4db641a660f1f7de9f6bb3521ad2fdd1940b2e81a",
    assertions: START_REV_ASSERTIONS,
};

pub(super) const START_FWD_DONE_RANGE_ADAPTER: RegisteredAdapter = RegisteredAdapter {
    mode_id: COMPILED_UNIT_MODE_ID,
    harness: RegexAutomataHarnessKind::Unit,
    case_id: START_FWD_DONE_RANGE_CASE,
    source: START_FWD_DONE_RANGE_SOURCE,
    run: run_start_fwd_done_range,
};
pub(super) const START_REV_DONE_RANGE_ADAPTER: RegisteredAdapter = RegisteredAdapter {
    mode_id: COMPILED_UNIT_MODE_ID,
    harness: RegexAutomataHarnessKind::Unit,
    case_id: START_REV_DONE_RANGE_CASE,
    source: START_REV_DONE_RANGE_SOURCE,
    run: run_start_rev_done_range,
};
pub(super) const START_FWD_ADAPTER: RegisteredAdapter = RegisteredAdapter {
    mode_id: COMPILED_UNIT_MODE_ID,
    harness: RegexAutomataHarnessKind::Unit,
    case_id: START_FWD_CASE,
    source: START_FWD_SOURCE,
    run: run_start_fwd,
};
pub(super) const START_REV_ADAPTER: RegisteredAdapter = RegisteredAdapter {
    mode_id: COMPILED_UNIT_MODE_ID,
    harness: RegexAutomataHarnessKind::Unit,
    case_id: START_REV_CASE,
    source: START_REV_SOURCE,
    run: run_start_rev,
};

const ADAPTERS: [RegisteredAdapter; 4] = [
    START_FWD_DONE_RANGE_ADAPTER,
    START_REV_DONE_RANGE_ADAPTER,
    START_FWD_ADAPTER,
    START_REV_ADAPTER,
];

/// Extend the exact 141-pass v6 report with four independently executed
/// package-default start-map memberships.
pub fn build_regex_automata_start_map_report(
    inventory: &RegexAutomataCorpusReport,
    previous: &RegexAutomataAdapterReport,
    candidate: CandidateIdentity,
) -> Result<RegexAutomataAdapterReport, InventoryError> {
    validate_predecessor(inventory, previous)?;
    validate_candidate(&candidate)?;
    if candidate.revision == PREDECESSOR_REVISION || candidate.tree == PREDECESSOR_TREE {
        return Err(InventoryError::new(
            "start-map candidate is not distinct from its predecessor",
        ));
    }
    validate_start_sources(inventory)?;
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
        let adapter = ADAPTERS
            .iter()
            .find(|adapter| adapter.case_id == receipt.case_id)
            .ok_or_else(|| InventoryError::new("start-map target lacks its adapter"))?;
        let execution = execute_adapter(adapter, &mode)
            .map_err(|error| InventoryError::new(format!("start-map execution: {error}")))?;
        let evidence_sha256 = hash_json(&execution, "encode start-map execution")?;
        receipt.disposition = RegexAutomataAdapterDisposition::Pass { evidence_sha256 };
        execution_receipts.push(execution);
        observed_targets.insert(identity);
    }
    if observed_targets != targets {
        return Err(InventoryError::new(
            "start-map inventory target denominator mismatch",
        ));
    }
    let execution_receipts =
        order_execution_receipts(&receipts, execution_receipts, "start-map report")?;
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
        limitations: START_MAP_REPORT_LIMITATIONS
            .iter()
            .map(|text| (*text).to_owned())
            .collect(),
    };
    let report = RegexAutomataAdapterReport {
        schema: REGEX_AUTOMATA_START_MAP_REPORT_SCHEMA.to_owned(),
        payload_sha256: hash_json(&payload, "encode start-map report payload")?,
        payload,
    };
    validate_start_map_execution_after_structure(inventory, &report)?;
    Ok(report)
}

/// Require the exact 141 -> 145 transition with every non-target receipt and
/// execution preserved from the authenticated v6 predecessor.
pub fn validate_regex_automata_start_map_strict_gain(
    inventory: &RegexAutomataCorpusReport,
    previous: &RegexAutomataAdapterReport,
    current: &RegexAutomataAdapterReport,
) -> Result<RegexAutomataStrictGain, InventoryError> {
    validate_predecessor(inventory, previous)?;
    current.validate_structure(inventory)?;
    if current.schema != REGEX_AUTOMATA_START_MAP_REPORT_SCHEMA {
        return Err(InventoryError::new(
            "current report is not a start-map report",
        ));
    }
    let targets = target_identities(inventory)?;
    let (gained_unique_cases, gained_mode_memberships) = gain_vectors(
        &previous.payload.receipts,
        &current.payload.receipts,
        &targets,
    )?;
    if (gained_unique_cases, gained_mode_memberships) != (4, 4)
        || previous.payload.counts.pass != 141
        || current.payload.counts.pass != 145
    {
        return Err(InventoryError::new(
            "start-map gain is not exact four-membership progress",
        ));
    }
    Ok(RegexAutomataStrictGain {
        family: "unit-util".to_owned(),
        gained_unique_cases,
        gained_mode_memberships,
        previous_pass: 141,
        current_pass: 145,
    })
}

pub(super) fn validate_start_map_execution_after_structure(
    inventory: &RegexAutomataCorpusReport,
    report: &RegexAutomataAdapterReport,
) -> Result<(), InventoryError> {
    if report.schema != REGEX_AUTOMATA_START_MAP_REPORT_SCHEMA
        || report.payload.counts
            != (RegexAutomataAdapterCounts {
                pass: 145,
                unsupported: 3_697,
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
            "start-map candidate identity or cardinality mismatch",
        ));
    }
    validate_execution_receipt_order(report)?;
    validate_start_sources(inventory)?;
    let targets = target_identities(inventory)?;
    let previous = reconstruct_predecessor(report, &targets)?;
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
    if previous.payload.execution_receipts.len() != 141
        || report.payload.execution_receipts.len() != 145
        || previous_executions.len() != 141
        || current_executions.len() != 145
    {
        return Err(InventoryError::new(
            "start-map execution denominator mismatch",
        ));
    }
    for (identity, execution) in &previous_executions {
        if current_executions.get(identity) != Some(execution) {
            return Err(InventoryError::new(
                "start-map report changed retained execution evidence",
            ));
        }
    }
    let mode = mode_execution(inventory, COMPILED_UNIT_MODE_ID)?;
    for identity in &targets {
        let execution = current_executions
            .get(identity)
            .ok_or_else(|| InventoryError::new("start-map target lacks execution evidence"))?;
        let adapter = ADAPTERS
            .iter()
            .find(|adapter| adapter.case_id == identity.2)
            .ok_or_else(|| InventoryError::new("start-map target lacks source authority"))?;
        let expected = execute_adapter(adapter, &mode)
            .map_err(|error| InventoryError::new(format!("start-map replay: {error}")))?;
        if *execution != &expected {
            return Err(InventoryError::new("start-map execution evidence mismatch"));
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
            .ok_or_else(|| InventoryError::new("start-map target receipt is absent"))?;
        let expected_hash = hash_json(execution, "encode start-map execution")?;
        if !matches!(
            &receipt.disposition,
            RegexAutomataAdapterDisposition::Pass { evidence_sha256 }
                if *evidence_sha256 == expected_hash
        ) {
            return Err(InventoryError::new(
                "start-map pass is not bound to its execution receipt",
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
    if report.schema != REGEX_AUTOMATA_UNICODE_WORD_LOOK_REPORT_SCHEMA
        || report.payload.counts
            != (RegexAutomataAdapterCounts {
                pass: 141,
                unsupported: 3_701,
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
            "start-map predecessor authority mismatch",
        ));
    }
    Ok(())
}

fn reconstruct_predecessor(
    report: &RegexAutomataAdapterReport,
    targets: &BTreeSet<(String, RegexAutomataHarnessKind, String)>,
) -> Result<RegexAutomataAdapterReport, InventoryError> {
    let mut previous = report.clone();
    REGEX_AUTOMATA_UNICODE_WORD_LOOK_REPORT_SCHEMA.clone_into(&mut previous.schema);
    PREDECESSOR_REVISION.clone_into(&mut previous.payload.candidate.revision);
    PREDECESSOR_TREE.clone_into(&mut previous.payload.candidate.tree);
    previous.payload.limitations = unicode_word_look::UNICODE_WORD_LOOK_REPORT_LIMITATIONS
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
        "encode reconstructed Unicode word-look payload",
    )?;
    if previous.payload_sha256 != PREDECESSOR_PAYLOAD_SHA256 {
        return Err(InventoryError::new(
            "reconstructed start-map predecessor payload SHA-256 mismatch",
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
    let identities = ADAPTERS
        .iter()
        .map(|adapter| {
            (
                adapter.mode_id.to_owned(),
                adapter.harness,
                adapter.case_id.to_owned(),
            )
        })
        .collect::<BTreeSet<_>>();
    let mut canonical = String::new();
    for (mode_id, harness, case_id) in &identities {
        if *harness != RegexAutomataHarnessKind::Unit {
            return Err(InventoryError::new(
                "start-map target contains a non-unit membership",
            ));
        }
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
    if identities.len() != 4
        || crate::sha256(canonical.as_bytes()) != TARGET_IDENTITIES_SHA256
        || !identities.is_subset(&inventory_identities)
    {
        return Err(InventoryError::new(
            "start-map target identity seal mismatch",
        ));
    }
    Ok(identities)
}

fn validate_start_sources(inventory: &RegexAutomataCorpusReport) -> Result<(), InventoryError> {
    let file = inventory
        .payload
        .source
        .files
        .iter()
        .find(|file| file.path == SOURCE_PATH)
        .ok_or_else(|| InventoryError::new("start-map upstream source file is absent"))?;
    if file.sha256 != SOURCE_SHA256 || file.mode != "0644" {
        return Err(InventoryError::new(
            "start-map upstream source file identity mismatch",
        ));
    }
    for adapter in ADAPTERS {
        validate_source_spec(&adapter.source)?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct Vector {
    assertion_id: &'static str,
    direction: Direction,
    haystack: &'static [u8],
    start: usize,
    end: usize,
}

fn run_start_fwd_done_range(
    context: &AdapterContext<'_>,
) -> Result<Vec<RegexAutomataAssertionExecution>, String> {
    run_vectors(
        context,
        &[Vector {
            assertion_id: START_FWD_DONE_RANGE_ASSERTIONS[0].assertion_id,
            direction: Direction::Forward,
            haystack: b"",
            start: 1,
            end: 0,
        }],
    )
}

fn run_start_rev_done_range(
    context: &AdapterContext<'_>,
) -> Result<Vec<RegexAutomataAssertionExecution>, String> {
    run_vectors(
        context,
        &[Vector {
            assertion_id: START_REV_DONE_RANGE_ASSERTIONS[0].assertion_id,
            direction: Direction::Reverse,
            haystack: b"",
            start: 1,
            end: 0,
        }],
    )
}

fn run_start_fwd(
    context: &AdapterContext<'_>,
) -> Result<Vec<RegexAutomataAssertionExecution>, String> {
    run_vectors(
        context,
        &[
            vector(&START_FWD_ASSERTIONS[0], Direction::Forward, b"", 0, 0),
            vector(&START_FWD_ASSERTIONS[1], Direction::Forward, b"abc", 0, 3),
            vector(&START_FWD_ASSERTIONS[2], Direction::Forward, b"\nabc", 0, 3),
            vector(&START_FWD_ASSERTIONS[3], Direction::Forward, b"\nabc", 1, 3),
            vector(&START_FWD_ASSERTIONS[4], Direction::Forward, b"\rabc", 1, 3),
            vector(&START_FWD_ASSERTIONS[5], Direction::Forward, b"abc", 1, 3),
            vector(&START_FWD_ASSERTIONS[6], Direction::Forward, b" abc", 1, 3),
        ],
    )
}

fn run_start_rev(
    context: &AdapterContext<'_>,
) -> Result<Vec<RegexAutomataAssertionExecution>, String> {
    run_vectors(
        context,
        &[
            vector(&START_REV_ASSERTIONS[0], Direction::Reverse, b"", 0, 0),
            vector(&START_REV_ASSERTIONS[1], Direction::Reverse, b"abc", 0, 3),
            vector(&START_REV_ASSERTIONS[2], Direction::Reverse, b"abc\n", 0, 4),
            vector(
                &START_REV_ASSERTIONS[3],
                Direction::Reverse,
                b"abc\nz",
                0,
                3,
            ),
            vector(
                &START_REV_ASSERTIONS[4],
                Direction::Reverse,
                b"abc\rz",
                0,
                3,
            ),
            vector(&START_REV_ASSERTIONS[5], Direction::Reverse, b"abc", 0, 2),
            vector(&START_REV_ASSERTIONS[6], Direction::Reverse, b"abc ", 0, 3),
        ],
    )
}

const fn vector(
    assertion: &AssertionSpec,
    direction: Direction,
    haystack: &'static [u8],
    start: usize,
    end: usize,
) -> Vector {
    Vector {
        assertion_id: assertion.assertion_id,
        direction,
        haystack,
        start,
        end,
    }
}

fn run_vectors(
    context: &AdapterContext<'_>,
    vectors: &[Vector],
) -> Result<Vec<RegexAutomataAssertionExecution>, String> {
    require_unit_mode(context)?;
    let map = build_exact_map()?;
    vectors
        .iter()
        .map(|vector| {
            let input = Input::new(vector.haystack).range(vector.start..vector.end);
            let config = match vector.direction {
                Direction::Forward => {
                    regex_automata::util::start::Config::from_input_forward(&input)
                }
                Direction::Reverse => {
                    regex_automata::util::start::Config::from_input_reverse(&input)
                }
            };
            let upstream = config
                .get_look_behind()
                .map_or(StartClass::Text, classify_default_start);
            let fre = exact_lookup(&map, vector)?;
            Ok(RegexAutomataAssertionExecution {
                assertion_id: vector.assertion_id.to_owned(),
                upstream_observation: observation(upstream).to_owned(),
                fre_observation: observation(fre).to_owned(),
            })
        })
        .collect()
}

fn build_exact_map() -> Result<ByteStartMap, String> {
    let required = ByteStartMap::build_requirements();
    let exact = BuildLimits {
        max_work: required.work,
        max_scratch_bytes: required.scratch_bytes,
        max_persistent_bytes: required.persistent_bytes,
        max_peak_bytes: required.peak_bytes,
    };
    let one_below = [
        (
            BuildLimits {
                max_work: required
                    .work
                    .checked_sub(1)
                    .ok_or_else(|| "start-map build work underflow".to_owned())?,
                ..exact
            },
            Resource::BuildWork,
            required.work,
        ),
        (
            BuildLimits {
                max_scratch_bytes: required
                    .scratch_bytes
                    .checked_sub(1)
                    .ok_or_else(|| "start-map scratch underflow".to_owned())?,
                ..exact
            },
            Resource::ScratchBytes,
            required.scratch_bytes,
        ),
        (
            BuildLimits {
                max_persistent_bytes: required
                    .persistent_bytes
                    .checked_sub(1)
                    .ok_or_else(|| "start-map persistent underflow".to_owned())?,
                ..exact
            },
            Resource::PersistentBytes,
            required.persistent_bytes,
        ),
        (
            BuildLimits {
                max_peak_bytes: required
                    .peak_bytes
                    .checked_sub(1)
                    .ok_or_else(|| "start-map peak underflow".to_owned())?,
                ..exact
            },
            Resource::PeakBytes,
            required.peak_bytes,
        ),
    ];
    for (limits, expected_resource, needed) in one_below {
        let limit = needed
            .checked_sub(1)
            .ok_or_else(|| "start-map build limit underflow".to_owned())?;
        if !matches!(
            ByteStartMap::build(b'\n', limits),
            Err(BuildError::ResourceLimit {
                resource,
                needed: observed_needed,
                limit: observed_limit,
            }) if resource == expected_resource
                && observed_needed == needed
                && observed_limit == limit
        ) {
            return Err("start-map build one-below contract mismatch".to_owned());
        }
    }
    let map = ByteStartMap::build(b'\n', exact)
        .map_err(|error| format!("fre-start-map-exact-build:{error}"))?;
    if map.build_accounting() != required {
        return Err("start-map exact build accounting mismatch".to_owned());
    }
    Ok(map)
}

fn exact_lookup(map: &ByteStartMap, vector: &Vector) -> Result<StartClass, String> {
    let required = map
        .lookup_requirements(
            vector.haystack.len(),
            vector.direction,
            vector.start,
            vector.end,
        )
        .map_err(|error| format!("fre-start-map-requirements:{error}"))?;
    let exact = LookupLimits {
        max_input_bytes: required.input_bytes,
        max_work: required.prospective_work,
        max_random_access_bytes: required.random_access_bytes,
    };
    let work_limit = required
        .prospective_work
        .checked_sub(1)
        .ok_or_else(|| "start-map lookup work underflow".to_owned())?;
    if !matches!(
        map.lookup(
            vector.haystack,
            vector.direction,
            vector.start,
            vector.end,
            LookupLimits {
                max_work: work_limit,
                ..exact
            },
        ),
        Err(LookupError::ResourceLimit {
            resource: Resource::LookupWork,
            needed,
            limit,
        }) if needed == required.prospective_work && limit == work_limit
    ) {
        return Err("start-map lookup one-below work contract mismatch".to_owned());
    }
    if required.random_access_bytes > 0 {
        let random_limit = required
            .random_access_bytes
            .checked_sub(1)
            .ok_or_else(|| "start-map random-access underflow".to_owned())?;
        if !matches!(
            map.lookup(
                vector.haystack,
                vector.direction,
                vector.start,
                vector.end,
                LookupLimits {
                    max_random_access_bytes: random_limit,
                    ..exact
                },
            ),
            Err(LookupError::ResourceLimit {
                resource: Resource::RandomAccessBytes,
                needed,
                limit,
            }) if needed == required.random_access_bytes && limit == random_limit
        ) {
            return Err("start-map lookup one-below random-access contract mismatch".to_owned());
        }
    }
    let result = map
        .lookup(
            vector.haystack,
            vector.direction,
            vector.start,
            vector.end,
            exact,
        )
        .map_err(|error| format!("fre-start-map-exact-lookup:{error}"))?;
    if result.accounting != required
        || result.accounting.actual_work > result.accounting.prospective_work
    {
        return Err("start-map exact lookup accounting mismatch".to_owned());
    }
    Ok(result.class)
}

fn classify_default_start(byte: u8) -> StartClass {
    if byte == b'\n' {
        StartClass::LineLf
    } else if byte == b'\r' {
        StartClass::LineCr
    } else if byte == b'_' || byte.is_ascii_alphanumeric() {
        StartClass::WordByte
    } else {
        StartClass::NonWordByte
    }
}

const fn observation(class: StartClass) -> &'static str {
    match class {
        StartClass::NonWordByte => "start:non-word-byte",
        StartClass::WordByte => "start:word-byte",
        StartClass::Text => "start:text",
        StartClass::LineLf => "start:line-lf",
        StartClass::LineCr => "start:line-cr",
        StartClass::CustomLineTerminator => "start:custom-line-terminator",
    }
}

fn require_unit_mode(context: &AdapterContext<'_>) -> Result<(), String> {
    if context.mode.mode_id != COMPILED_UNIT_MODE_ID
        || context.mode.harness != RegexAutomataHarnessKind::Unit
        || !context.mode.default_features
        || context.mode.all_features
        || !context.mode.features.is_empty()
        || context.mode.dependency_package != "regex-automata"
        || context.mode.dependency_version != "0.4.14"
    {
        return Err("compiled-unit-mode-mismatch".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::MetadataExt, path::PathBuf};

    use crate::CandidateIdentity;
    use crate::automata_progress::{
        COMPILED_MODE_ID, RegexAutomataAdapterDisposition, RegexAutomataAdapterReceipt,
        RegexAutomataAdapterReport, RegexAutomataExecutionReceipt, RegexAutomataModeExecution,
        adapter_counts, execute_adapter, hash_json, validate_source_spec,
    };

    use super::{
        COMPILED_UNIT_MODE_ID, PREDECESSOR_PAYLOAD_SHA256, PREDECESSOR_REVISION, PREDECESSOR_TREE,
        REGEX_AUTOMATA_START_MAP_REPORT_SCHEMA, RegexAutomataHarnessKind, START_FWD_ADAPTER,
        START_FWD_DONE_RANGE_ADAPTER, START_FWD_DONE_RANGE_CASE, START_MAP_REPORT_LIMITATIONS,
        START_REV_ADAPTER, START_REV_DONE_RANGE_ADAPTER, build_regex_automata_start_map_report,
        validate_predecessor, validate_regex_automata_start_map_strict_gain,
    };

    fn unit_mode() -> RegexAutomataModeExecution {
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

    fn doctest_mode() -> RegexAutomataModeExecution {
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
    fn source_contracts_and_all_sixteen_assertions_execute() {
        let adapters = [
            START_FWD_DONE_RANGE_ADAPTER,
            START_REV_DONE_RANGE_ADAPTER,
            START_FWD_ADAPTER,
            START_REV_ADAPTER,
        ];
        let mode = unit_mode();
        let mut assertion_count = 0;
        for adapter in adapters {
            validate_source_spec(&adapter.source).unwrap();
            let receipt = execute_adapter(&adapter, &mode).unwrap();
            assertion_count += receipt.assertion_executions.len();
        }
        assert_eq!(16, assertion_count);
    }

    #[test]
    fn unit_observers_reject_doctest_mode() {
        let error = execute_adapter(&START_FWD_ADAPTER, &doctest_mode()).unwrap_err();
        assert_eq!("adapter-mode-binding-mismatch", error);
    }

    #[test]
    fn transition_identity_is_exact_and_leaves_v7_v8_unclaimed() {
        assert_eq!(
            REGEX_AUTOMATA_START_MAP_REPORT_SCHEMA,
            "fre.regex-automata-0.4.14.adapter-report.v9"
        );
        assert_eq!(PREDECESSOR_REVISION.len(), 40);
        assert_eq!(PREDECESSOR_TREE.len(), 40);
        assert_eq!(PREDECESSOR_PAYLOAD_SHA256.len(), 64);
        assert!(
            START_MAP_REPORT_LIMITATIONS
                .iter()
                .any(|text| text.contains("141-membership"))
        );
    }

    #[test]
    #[ignore = "requires authenticated external inventory and v6 report fixtures"]
    fn authenticated_v6_v9_transition_rejects_persistent_resealed_mutations() {
        let inventory_path = authenticated_fixture(
            "FRE_START_MAP_INVENTORY",
            "b6c4ff208f546f2b45d9a37d1f5508680d0c2a6e29c0e59df9f4b96f1dcdfbe2",
            0o444,
        );
        let predecessor_path = authenticated_fixture(
            "FRE_START_MAP_V6",
            "fd146a77b0376fd6fff2a6c29ef61cd92b96a259e38a4e02ec670ecbdfb676f9",
            0o400,
        );
        let inventory = crate::read_regex_automata_corpus_report(&inventory_path).unwrap();
        let predecessor =
            crate::read_regex_automata_adapter_report(&predecessor_path, &inventory).unwrap();
        let current = build_regex_automata_start_map_report(
            &inventory,
            &predecessor,
            CandidateIdentity {
                revision: std::env::var("FRE_START_MAP_FINAL_REVISION").unwrap(),
                tree: std::env::var("FRE_START_MAP_FINAL_TREE").unwrap(),
                tracked_and_untracked_worktree_clean: true,
            },
        )
        .unwrap();
        validate_predecessor(&inventory, &predecessor).unwrap();
        validate_regex_automata_start_map_strict_gain(&inventory, &predecessor, &current).unwrap();
        assert_eq!(current.payload.counts.pass, 145);
        assert_eq!(current.payload.execution_receipts.len(), 145);

        let mut stale_predecessor = predecessor.clone();
        stale_predecessor.payload.candidate.revision = "0".repeat(40);
        reseal(&mut stale_predecessor);
        assert!(validate_predecessor(&inventory, &stale_predecessor).is_err());

        let mut changed_limitations = current.clone();
        changed_limitations.payload.limitations[0].push('x');
        reseal(&mut changed_limitations);
        assert_current_rejected(&inventory, &predecessor, &changed_limitations);

        let mut changed_matrix = current.clone();
        changed_matrix.payload.look_mode_matrix = None;
        reseal(&mut changed_matrix);
        assert_current_rejected(&inventory, &predecessor, &changed_matrix);

        assert_retained_resealed_mutations_rejected(&inventory, &predecessor, &current);
        assert_target_resealed_mutations_rejected(&inventory, &predecessor, &current);
    }

    fn assert_retained_resealed_mutations_rejected(
        inventory: &super::RegexAutomataCorpusReport,
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
            hash_json(execution, "encode changed retained start-map execution").unwrap()
        };
        let RegexAutomataAdapterDisposition::Pass { evidence_sha256 } =
            &mut exact_receipt_mut(&mut changed_execution, retained_identity).disposition
        else {
            panic!("retained receipt is not a pass");
        };
        *evidence_sha256 = changed_evidence;
        reseal(&mut changed_execution);
        assert_current_rejected(inventory, predecessor, &changed_execution);
    }

    fn assert_target_resealed_mutations_rejected(
        inventory: &super::RegexAutomataCorpusReport,
        predecessor: &RegexAutomataAdapterReport,
        current: &RegexAutomataAdapterReport,
    ) {
        let target_identity = (
            COMPILED_UNIT_MODE_ID,
            RegexAutomataHarnessKind::Unit,
            START_FWD_DONE_RANGE_CASE,
        );
        let mut changed_target = current.clone();
        let changed_evidence = {
            let execution = exact_execution_mut(&mut changed_target, target_identity);
            execution.assertion_executions[0].fre_observation = "start:word-byte".to_owned();
            hash_json(execution, "encode changed target start-map execution").unwrap()
        };
        let RegexAutomataAdapterDisposition::Pass { evidence_sha256 } =
            &mut exact_receipt_mut(&mut changed_target, target_identity).disposition
        else {
            panic!("target receipt is not a pass");
        };
        *evidence_sha256 = changed_evidence;
        reseal(&mut changed_target);
        assert_current_rejected(inventory, predecessor, &changed_target);

        let mut missing_target = current.clone();
        missing_target
            .payload
            .execution_receipts
            .retain(|execution| execution_identity_ref(execution) != target_identity);
        reseal(&mut missing_target);
        assert_current_rejected(inventory, predecessor, &missing_target);

        let mut duplicate_target = current.clone();
        let duplicate = exact_execution_mut(&mut duplicate_target, target_identity).clone();
        duplicate_target.payload.execution_receipts.push(duplicate);
        reseal(&mut duplicate_target);
        assert_current_rejected(inventory, predecessor, &duplicate_target);
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
            hash_json(&report.payload, "encode adversarial start-map payload").unwrap();
    }

    fn assert_current_rejected(
        inventory: &super::RegexAutomataCorpusReport,
        predecessor: &RegexAutomataAdapterReport,
        current: &RegexAutomataAdapterReport,
    ) {
        assert!(current.validate_structure(inventory).is_err());
        assert!(
            validate_regex_automata_start_map_strict_gain(inventory, predecessor, current).is_err()
        );
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
}
