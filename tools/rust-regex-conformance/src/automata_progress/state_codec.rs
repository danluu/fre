//! Executable bridge for the two determinize-state integer codec properties.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
};

use fre_kernels::{
    DeterminizeStateCodecAccounting as Accounting, DeterminizeStateCodecError as KernelError,
    DeterminizeStateCodecLimits as Limits, decode_determinize_state_i32,
    decode_determinize_state_u32, determinize_state_decode_requirements,
    determinize_state_encode_requirements, encode_determinize_state_i32,
    encode_determinize_state_u32,
};

use super::{
    AssertionSpec, COMPILED_UNIT_MODE_ID, INVENTORY_UNSUPPORTED_REASON, RegexAutomataAdapterCounts,
    RegexAutomataAdapterDisposition, RegexAutomataAdapterReport, RegexAutomataAdapterReportPayload,
    RegexAutomataAssertionExecution, RegexAutomataCorpusReport, RegexAutomataExecutionReceipt,
    RegexAutomataHarnessKind, RegexAutomataModeExecution, RegexAutomataStrictGain,
    SourceContractSpec, adapter_counts, gain_vectors, hash_json, mode_execution,
    obligation_membership_identity, source_contract, validate_assertion_executions,
    validate_candidate,
};
use crate::{
    CandidateIdentity, InventoryError,
    automata_corpus::start_mode::{
        REGEX_AUTOMATA_START_MODE_REPORT_SCHEMA, START_MODE_REPORT_LIMITATIONS,
    },
    sha256,
};

pub const REGEX_AUTOMATA_STATE_CODEC_REPORT_SCHEMA: &str =
    "fre.regex-automata-0.4.14.adapter-report.v13-state-codec";
pub(super) const STATE_CODEC_REPORT_LIMITATIONS: [&str; 4] = [
    "A pass requires exact-limit bounded FRE round trips over signed and unsigned boundary vectors plus typed one-below refusal; no helper-only projection is accepted.",
    "Only the two package-default determinize-state varint property memberships are added; no result is projected across feature modes.",
    "The exact 267-pass authenticated start-mode predecessor and every non-target disposition and execution receipt are retained exactly.",
    "The predecessor's complete start-mode baseline and execution matrix remain embedded and independently validated without relabeling.",
];

const PREDECESSOR_REVISION: &str = "3e3ffcba88f55195eebcce0b0fa6619091cfb0e2";
const PREDECESSOR_TREE: &str = "403d53297f2835d859f36fbbf376a621325719ff";
const PREDECESSOR_PAYLOAD_SHA256: &str =
    "4e763d87a96d51b4afb2cfc8c9590ebfd6f4913a367ceb282fadb370f9774df6";
const TARGET_IDENTITIES_SHA256: &str =
    "2123b7e22530d712a87446ac8b2331dac01dd7e535396a0fe9b1accf7b52f207";
const SOURCE_PATH: &str = "src/util/determinize/state.rs";
const SOURCE_SHA256: &str = "a850af545b7d0bd706f0bf72fdba504b6efdeea181763657109e10fef53aa88d";
const SOURCE_SPAN: &str = include_str!("../fixtures/determinize-state-varint-v1.txt");
const SOURCE_SPAN_SHA256: &str = "eb8a6424a9ff49259a96536962cf5350ceb3408ac83115b62fbbbfe4ad0b46d8";
const VARU_CASE: &str = "util::determinize::state::tests::prop_read_write_varu32";
const VARI_CASE: &str = "util::determinize::state::tests::prop_read_write_vari32";

const VARU_ASSERTIONS: &[AssertionSpec] = &[AssertionSpec {
    assertion_id: "state-varu32-roundtrip",
    source_line: 865,
    source_line_sha256: "4328f67c85fe6ec00cecbc283da13e71a37ebe1cb6371da11f72d72725d3eccc",
    expected_observation: "roundtrip:ok",
}];
const VARI_ASSERTIONS: &[AssertionSpec] = &[AssertionSpec {
    assertion_id: "state-vari32-roundtrip",
    source_line: 872,
    source_line_sha256: "74a2fa052696ea2346c1d2adee53c806337009f231708c469eea97c2c156c5bb",
    expected_observation: "roundtrip:ok",
}];
const VARU_SOURCE: SourceContractSpec = source(
    VARU_ASSERTIONS,
    "abe0e793572794c0cc343a0f2b9af345f0c7c57cd9619bb9d28b944fa4156ced",
);
const VARI_SOURCE: SourceContractSpec = source(
    VARI_ASSERTIONS,
    "68dd3105f0dea4a1ea46f4589b457e7c7914512bf508c86fbe9d77f6a1c51648",
);

const fn source(
    assertions: &'static [AssertionSpec],
    inventory: &'static str,
) -> SourceContractSpec {
    SourceContractSpec {
        source_path: SOURCE_PATH,
        source_sha256: SOURCE_SHA256,
        span_start_line: 864,
        span_end_line: 878,
        source_span: SOURCE_SPAN,
        source_span_sha256: SOURCE_SPAN_SHA256,
        assertion_inventory_sha256: inventory,
        assertions,
    }
}

pub fn build_regex_automata_state_codec_report(
    inventory: &RegexAutomataCorpusReport,
    previous: &RegexAutomataAdapterReport,
    candidate: CandidateIdentity,
) -> Result<RegexAutomataAdapterReport, InventoryError> {
    validate_predecessor(inventory, previous)?;
    validate_candidate(&candidate)?;
    let targets = target_identities(inventory)?;
    let mode = mode_execution(inventory, COMPILED_UNIT_MODE_ID)?;
    let mut receipts = previous.payload.receipts.clone();
    let mut executions = previous.payload.execution_receipts.clone();
    let mut observed = BTreeSet::new();
    for receipt in &mut receipts {
        let identity = (
            receipt.mode_id.clone(),
            receipt.harness,
            receipt.case_id.clone(),
        );
        if targets.contains(&identity) {
            let execution = execute_case(&receipt.case_id, &mode)?;
            let evidence_sha256 = hash_json(&execution, "encode state-codec execution")?;
            receipt.disposition = RegexAutomataAdapterDisposition::Pass { evidence_sha256 };
            executions.push(execution);
            observed.insert(identity);
        }
    }
    if observed != targets {
        return Err(InventoryError::new(
            "state-codec target denominator mismatch",
        ));
    }
    let execution_receipts = order_available_executions(&receipts, executions)?;
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
        limitations: STATE_CODEC_REPORT_LIMITATIONS
            .iter()
            .map(|x| (*x).to_owned())
            .collect(),
    };
    let report = RegexAutomataAdapterReport {
        schema: REGEX_AUTOMATA_STATE_CODEC_REPORT_SCHEMA.to_owned(),
        payload_sha256: hash_json(&payload, "encode state-codec report payload")?,
        payload,
    };
    validate_state_codec_execution_after_structure(inventory, &report)?;
    Ok(report)
}

pub fn validate_regex_automata_state_codec_strict_gain(
    inventory: &RegexAutomataCorpusReport,
    previous: &RegexAutomataAdapterReport,
    current: &RegexAutomataAdapterReport,
) -> Result<RegexAutomataStrictGain, InventoryError> {
    validate_predecessor(inventory, previous)?;
    current.validate_structure(inventory)?;
    let targets = target_identities(inventory)?;
    let (unique, memberships) = gain_vectors(
        &previous.payload.receipts,
        &current.payload.receipts,
        &targets,
    )?;
    if current.schema != REGEX_AUTOMATA_STATE_CODEC_REPORT_SCHEMA || (unique, memberships) != (2, 2)
    {
        return Err(InventoryError::new(
            "state-codec gain is not exact two-membership progress",
        ));
    }
    Ok(RegexAutomataStrictGain {
        family: "unit-util-determinize-state".to_owned(),
        gained_unique_cases: unique,
        gained_mode_memberships: memberships,
        previous_pass: 267,
        current_pass: 269,
    })
}

pub(super) fn validate_state_codec_execution_after_structure(
    inventory: &RegexAutomataCorpusReport,
    report: &RegexAutomataAdapterReport,
) -> Result<(), InventoryError> {
    if report.schema != REGEX_AUTOMATA_STATE_CODEC_REPORT_SCHEMA
        || report.payload.counts
            != (RegexAutomataAdapterCounts {
                pass: 269,
                unsupported: 3_573,
                fault: 0,
                total: 3_842,
            })
        || !report
            .payload
            .candidate
            .tracked_and_untracked_worktree_clean
    {
        return Err(InventoryError::new("state-codec report identity mismatch"));
    }
    let targets = target_identities(inventory)?;
    let previous = reconstruct_predecessor(report, &targets)?;
    validate_predecessor(inventory, &previous)?;
    let mode = mode_execution(inventory, COMPILED_UNIT_MODE_ID)?;
    let mut expected_executions = previous.payload.execution_receipts.clone();
    for target in &targets {
        expected_executions.push(execute_case(&target.2, &mode)?);
    }
    let expected_executions =
        order_available_executions(&report.payload.receipts, expected_executions)?;
    if expected_executions.len() != 153 || report.payload.execution_receipts != expected_executions
    {
        return Err(InventoryError::new(
            "state-codec execution set/order mismatch",
        ));
    }
    let executions = expected_executions
        .iter()
        .map(|execution| (identity(execution), execution))
        .collect::<BTreeMap<_, _>>();
    for target in &targets {
        let expected = execute_case(&target.2, &mode)?;
        let evidence_sha256 = hash_json(&expected, "encode state-codec execution")?;
        let disposition = report
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
            .map(|receipt| &receipt.disposition);
        if executions.get(target).copied() != Some(&expected)
            || !matches!(
                disposition,
                Some(RegexAutomataAdapterDisposition::Pass { evidence_sha256: got })
                    if got == &evidence_sha256
            )
        {
            return Err(InventoryError::new("state-codec replay mismatch"));
        }
    }
    Ok(())
}

fn validate_predecessor(
    inventory: &RegexAutomataCorpusReport,
    report: &RegexAutomataAdapterReport,
) -> Result<(), InventoryError> {
    report.validate_structure(inventory)?;
    if report.schema != REGEX_AUTOMATA_START_MODE_REPORT_SCHEMA
        || report.payload_sha256 != PREDECESSOR_PAYLOAD_SHA256
        || report.payload.candidate.revision != PREDECESSOR_REVISION
        || report.payload.candidate.tree != PREDECESSOR_TREE
        || report.payload.counts
            != (RegexAutomataAdapterCounts {
                pass: 267,
                unsupported: 3_575,
                fault: 0,
                total: 3_842,
            })
    {
        return Err(InventoryError::new("state-codec predecessor mismatch"));
    }
    Ok(())
}

fn reconstruct_predecessor(
    report: &RegexAutomataAdapterReport,
    targets: &BTreeSet<(String, RegexAutomataHarnessKind, String)>,
) -> Result<RegexAutomataAdapterReport, InventoryError> {
    let mut p = report.clone();
    for r in &mut p.payload.receipts {
        if targets.contains(&(r.mode_id.clone(), r.harness, r.case_id.clone())) {
            r.disposition = RegexAutomataAdapterDisposition::Unsupported {
                reason_code: INVENTORY_UNSUPPORTED_REASON.to_owned(),
            };
        }
    }
    p.payload
        .execution_receipts
        .retain(|e| !targets.contains(&identity(e)));
    p.payload.candidate = CandidateIdentity {
        revision: PREDECESSOR_REVISION.to_owned(),
        tree: PREDECESSOR_TREE.to_owned(),
        tracked_and_untracked_worktree_clean: true,
    };
    p.payload.counts = adapter_counts(&p.payload.receipts);
    p.payload.limitations = START_MODE_REPORT_LIMITATIONS
        .iter()
        .map(|x| (*x).to_owned())
        .collect();
    REGEX_AUTOMATA_START_MODE_REPORT_SCHEMA.clone_into(&mut p.schema);
    p.payload_sha256 = hash_json(&p.payload, "reconstruct state-codec predecessor")?;
    Ok(p)
}

fn target_identities(
    inventory: &RegexAutomataCorpusReport,
) -> Result<BTreeSet<(String, RegexAutomataHarnessKind, String)>, InventoryError> {
    validate_sources()?;
    let cases = [VARI_CASE, VARU_CASE].into_iter().collect::<BTreeSet<_>>();
    let targets = inventory
        .payload
        .obligations
        .iter()
        .filter(|o| {
            o.mode_id == COMPILED_UNIT_MODE_ID
                && o.harness == RegexAutomataHarnessKind::Unit
                && cases.contains(o.case_id.as_str())
        })
        .map(obligation_membership_identity)
        .collect::<BTreeSet<_>>();
    let mut canonical = String::new();
    for (mode, _, case) in &targets {
        writeln!(canonical, "{mode}\tunit\t{case}")
            .map_err(|_| InventoryError::new("state-codec target encoding failed"))?;
    }
    if targets.len() != 2 || sha256(canonical.as_bytes()) != TARGET_IDENTITIES_SHA256 {
        return Err(InventoryError::new("state-codec target seal mismatch"));
    }
    Ok(targets)
}

fn validate_sources() -> Result<(), InventoryError> {
    if sha256(SOURCE_SPAN.as_bytes()) != SOURCE_SPAN_SHA256 || SOURCE_SPAN.lines().count() != 15 {
        return Err(InventoryError::new("state-codec source span mismatch"));
    }
    for source in [VARU_SOURCE, VARI_SOURCE] {
        let assertion = &source.assertions[0];
        let offset = assertion
            .source_line
            .checked_sub(source.span_start_line)
            .ok_or_else(|| InventoryError::new("state-codec assertion line underflow"))?;
        let line = SOURCE_SPAN
            .lines()
            .nth(offset)
            .ok_or_else(|| InventoryError::new("state-codec assertion line absent"))?;
        if sha256(format!("{line}\n").as_bytes()) != assertion.source_line_sha256 {
            return Err(InventoryError::new("state-codec assertion line mismatch"));
        }
        if hash_json(
            &source_contract(&source).assertions,
            "encode state-codec assertion inventory",
        )? != source.assertion_inventory_sha256
        {
            return Err(InventoryError::new("state-codec assertion seal mismatch"));
        }
    }
    Ok(())
}

fn execute_case(
    case: &str,
    mode: &RegexAutomataModeExecution,
) -> Result<RegexAutomataExecutionReceipt, InventoryError> {
    if mode.mode_id != COMPILED_UNIT_MODE_ID || mode.harness != RegexAutomataHarnessKind::Unit {
        return Err(InventoryError::new("state-codec mode mismatch"));
    }
    let (source, ok) = match case {
        VARU_CASE => (VARU_SOURCE, exercise_unsigned()?),
        VARI_CASE => (VARI_SOURCE, exercise_signed()?),
        _ => return Err(InventoryError::new("unreviewed state-codec case")),
    };
    if !ok {
        return Err(InventoryError::new("state-codec roundtrip mismatch"));
    }
    let assertions = vec![RegexAutomataAssertionExecution {
        assertion_id: source.assertions[0].assertion_id.to_owned(),
        upstream_observation: "roundtrip:ok".to_owned(),
        fre_observation: "roundtrip:ok".to_owned(),
    }];
    validate_assertion_executions(source.assertions, &assertions).map_err(InventoryError::new)?;
    Ok(RegexAutomataExecutionReceipt {
        mode: mode.clone(),
        harness: RegexAutomataHarnessKind::Unit,
        case_id: case.to_owned(),
        source: source_contract(&source),
        assertion_executions: assertions,
    })
}

fn limits(a: Accounting) -> Limits {
    Limits {
        max_input_bytes: a.input_bytes,
        max_output_bytes: a.output_bytes,
        max_work: a.work,
        max_sequential_read_bytes: a.sequential_read_bytes,
        max_sequential_write_bytes: a.sequential_write_bytes,
    }
}
fn exercise_unsigned() -> Result<bool, InventoryError> {
    for value in [0, 1, 127, 128, 16_383, 16_384, u32::MAX] {
        let e = determinize_state_encode_requirements(value).map_err(kernel)?;
        let mut b = [0; 5];
        encode_determinize_state_u32(value, &mut b, limits(e)).map_err(kernel)?;
        let d = determinize_state_decode_requirements(e.output_bytes).map_err(kernel)?;
        if decode_determinize_state_u32(&b[..e.output_bytes], limits(d))
            .map_err(kernel)?
            .value
            != value
        {
            return Ok(false);
        }
        let mut below = limits(e);
        below.max_work = below
            .max_work
            .checked_sub(1)
            .ok_or_else(|| InventoryError::new("state-codec work underflow"))?;
        if !matches!(
            encode_determinize_state_u32(value, &mut b, below),
            Err(KernelError::ResourceLimit { .. })
        ) {
            return Ok(false);
        }
    }
    Ok(true)
}
fn exercise_signed() -> Result<bool, InventoryError> {
    for value in [i32::MIN, -16_384, -1, 0, 1, 16_384, i32::MAX] {
        let bits = u32::from_ne_bytes(value.to_ne_bytes());
        let z = if value < 0 { !(bits << 1) } else { bits << 1 };
        let e = determinize_state_encode_requirements(z).map_err(kernel)?;
        let mut b = [0; 5];
        encode_determinize_state_i32(value, &mut b, limits(e)).map_err(kernel)?;
        let d = determinize_state_decode_requirements(e.output_bytes).map_err(kernel)?;
        if decode_determinize_state_i32(&b[..e.output_bytes], limits(d))
            .map_err(kernel)?
            .value
            != value
        {
            return Ok(false);
        }
    }
    Ok(true)
}
fn kernel(e: impl std::fmt::Display) -> InventoryError {
    InventoryError::new(format!("bounded state codec: {e}"))
}
fn identity(e: &RegexAutomataExecutionReceipt) -> (String, RegexAutomataHarnessKind, String) {
    (e.mode.mode_id.clone(), e.harness, e.case_id.clone())
}

fn order_available_executions(
    receipts: &[super::RegexAutomataAdapterReceipt],
    executions: Vec<RegexAutomataExecutionReceipt>,
) -> Result<Vec<RegexAutomataExecutionReceipt>, InventoryError> {
    let mut by_identity = BTreeMap::new();
    for execution in executions {
        if by_identity
            .insert(identity(&execution), execution)
            .is_some()
        {
            return Err(InventoryError::new(
                "duplicate state-codec execution receipt",
            ));
        }
    }
    let mut ordered = Vec::with_capacity(by_identity.len());
    for receipt in receipts {
        let key = (
            receipt.mode_id.clone(),
            receipt.harness,
            receipt.case_id.clone(),
        );
        if let Some(execution) = by_identity.remove(&key) {
            if !matches!(
                receipt.disposition,
                RegexAutomataAdapterDisposition::Pass { .. }
            ) {
                return Err(InventoryError::new(
                    "state-codec execution belongs to a non-pass receipt",
                ));
            }
            ordered.push(execution);
        }
    }
    if !by_identity.is_empty() {
        return Err(InventoryError::new(
            "state-codec execution is outside the receipt inventory",
        ));
    }
    Ok(ordered)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn both_properties_execute_with_exact_limits() {
        assert!(exercise_unsigned().unwrap());
        assert!(exercise_signed().unwrap());
        validate_sources().unwrap();
    }
}
