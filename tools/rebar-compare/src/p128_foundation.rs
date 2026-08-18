//! Immutable P128 Foundation attribution, kept outside all planner and
//! executor routing.
//!
//! This module loads only the generated opaque-ID ledger. A caller may bind a
//! structural receipt *after* an operation has completed, but no lifecycle,
//! selector, builder, or reducer imports the ledger or accepts a point ID.

use std::collections::{BTreeMap, BTreeSet};

use fre::{AggregateOperationCounterValue, AggregateOperationHotCounterReceipt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    CompareError, CurrentFreAggregateCounterReceiptStatus,
    CurrentFreAggregateOperationCounterResult, CurrentFreAggregateOperationLifecycle,
};

/// Generated ledger schema for the authenticated P128 scope.
pub const P128_FOUNDATION_LEDGER_SCHEMA: &str = "fre.p128.foundation-attribution-ledger.v1";
/// Post-operation receipt envelope schema.
pub const P128_FOUNDATION_COUNTER_RECORD_SCHEMA: &str =
    "fre.p128.foundation-forced-counter-record.v1";
/// Exact source candidate authenticated by the baseline receipt and schedule.
pub const P128_FOUNDATION_CANDIDATE: &str = "088bf4472f803f48c4c42e35641eb7d81f08931f";
/// Exact source tree authenticated by the baseline receipt and schedule.
pub const P128_FOUNDATION_TREE: &str = "486e7b387e92757f1fe03c5257b8eff2c0e67b1c";

const LEDGER_JSON: &str = include_str!("../p128-foundation-ledger-v1.json");
const LEDGER_SHA256: &str = "a4f065a86d50415276c487f629a9368db4554bed0a8cdf6e2b4ea6738d290d17";
const EVIDENCE_DIGESTS: [(&str, &str); 6] = [
    (
        "analysis_sha256",
        "e3ffaa4a6dd6ef70b511efc80ca73b406f5857a546f288be633f334e89912fc6",
    ),
    (
        "parallel_execution_amendment_sha256",
        "ff7e8bf1d243ea431cd7eab163ce9502bbdb3428011e95639b18255f24f23220",
    ),
    (
        "plan_sha256",
        "a9a538f6f282922b1594223784c726b5693b2cd866d75a304e479dd53f8aeee4",
    ),
    (
        "points_sha256",
        "06961958a4de807717dbd40e1ee8a0058d6b0787f5864172d71cb4c9a21ba496",
    ),
    (
        "receipt_sha256",
        "cb0a178453a890813d20007139eb12bc63e17df4ac1f2881a9967163542a06b4",
    ),
    (
        "schedule_sha256",
        "33b36c609ac4f1910f741499ab6460ffe8897db80abf408107d6376f21040d40",
    ),
];

/// Immutable generated P128 scope ledger.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct P128FoundationLedger {
    /// Candidate source commit pinned by the baseline evidence.
    candidate_commit: String,
    /// Candidate source tree pinned by the baseline evidence.
    candidate_tree: String,
    /// Digests of all immutable source evidence consumed by the generator.
    evidence: BTreeMap<String, String>,
    /// Canonical compact-JSON digest of this ledger excluding this field.
    ledger_sha256: String,
    /// Exactly 31 tail points and one protected sibling, in plan order.
    records: Vec<P128FoundationLedgerRecord>,
    /// Versioned ledger schema.
    schema: String,
}

/// One opaque P128 attribution slot. It deliberately does not contain a
/// benchmark name, fixture, expected output, source pattern, or timing value.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct P128FoundationLedgerRecord {
    /// Public-operation boundary class from the immutable evidence.
    boundary: String,
    /// Plan workstream family or its protected sibling marker.
    family: String,
    /// Operation model required for a later forced receipt.
    model: String,
    /// Opaque immutable point identifier.
    point_id: String,
    /// Whether this is the protected non-tail sibling.
    protected: bool,
    /// Native receipt surface required by this scoped point. This is a
    /// qualification-only contract, never an execution input.
    required_receipt_kind: P128FoundationReceiptKind,
    /// Digest sealing the complete source points-row without copying its
    /// benchmark/timing fields into the runtime-visible ledger.
    source_row_sha256: String,
}

/// Native post-operation evidence required for an immutable P128 slot.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum P128FoundationReceiptKind {
    /// One aggregate continuation operation has a sealed P/A receipt today.
    SingleContinuation,
    /// The later multi-pattern executor must publish its own sealed receipt.
    MultiContinuation,
    /// The later capture-stream uniform route must publish its own receipt.
    CaptureUniform,
    /// The later capture-history route must publish its own receipt.
    CaptureHistory,
}

impl P128FoundationLedgerRecord {
    /// Opaque immutable point identifier.
    #[must_use]
    pub fn point_id(&self) -> &str {
        &self.point_id
    }

    /// Public operation boundary associated with this slot.
    #[must_use]
    pub fn boundary(&self) -> &str {
        &self.boundary
    }

    /// Operation model associated with this slot.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Native receipt kind required to bind this slot.
    #[must_use]
    pub const fn required_receipt_kind(&self) -> P128FoundationReceiptKind {
        self.required_receipt_kind
    }
}

impl P128FoundationLedger {
    /// Load and authenticate the checked-in generated ledger.
    ///
    /// # Errors
    ///
    /// Returns an error if the generated file no longer seals the authenticated
    /// candidate, evidence, scope, or canonical ledger bytes.
    pub fn load() -> Result<Self, CompareError> {
        Self::from_json(LEDGER_JSON)
    }

    /// Parse and authenticate a ledger representation. This exists for
    /// qualification tooling and tamper tests; it is not used by selectors.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, incomplete, or
    /// out-of-scope ledger data.
    pub fn from_json(input: &str) -> Result<Self, CompareError> {
        let raw: Value = serde_json::from_str(input)
            .map_err(|error| CompareError::new(format!("parse P128 ledger: {error}")))?;
        let ledger: Self = serde_json::from_value(raw.clone())
            .map_err(|error| CompareError::new(format!("decode P128 ledger: {error}")))?;
        let mut sealed = raw;
        let Value::Object(object) = &mut sealed else {
            return Err(CompareError::new("P128 ledger must be a JSON object"));
        };
        let reported = object
            .remove("ledger_sha256")
            .and_then(|value| value.as_str().map(str::to_owned))
            .ok_or_else(|| CompareError::new("P128 ledger has no digest"))?;
        let computed = canonical_json_sha256(&sealed)?;
        if reported != computed || ledger.ledger_sha256 != computed || computed != LEDGER_SHA256 {
            return Err(CompareError::new(
                "P128 ledger canonical digest does not match its immutable seal",
            ));
        }
        ledger.validate()?;
        Ok(ledger)
    }

    /// Look up one opaque attribution slot without exposing any benchmark or
    /// fixture metadata.
    #[must_use]
    pub fn record(&self, point_id: &str) -> Option<&P128FoundationLedgerRecord> {
        self.records
            .iter()
            .find(|record| record.point_id == point_id)
    }

    /// Bind an already-finished continuation counter receipt to one ledger
    /// slot. This happens strictly after route selection and execution; the
    /// point ID is never passed to an executor or selector.
    ///
    /// # Errors
    ///
    /// Returns an error if the ledger, slot, reducer kind, or sealed receipt
    /// is not authentic.
    fn bind_continuation_counter_record(
        &self,
        point_id: &str,
        observation: P128FoundationAggregateCounterObservation,
    ) -> Result<P128FoundationCounterRecord, CompareError> {
        self.validate()?;
        let point = self
            .record(point_id)
            .cloned()
            .ok_or_else(|| CompareError::new("P128 counter record uses an unknown point ID"))?;
        if point.boundary != observation.boundary.as_str() {
            return Err(CompareError::new(
                "P128 counter observation does not match the immutable first/steady boundary",
            ));
        }
        let (session_id, observation_sequence, receipt) =
            observation.into_continuation_receipt()?;
        if !receipt.closes() {
            return Err(CompareError::new(
                "P128 counter record requires a sealed continuation receipt",
            ));
        }
        if !single_continuation_matches(&point, receipt.value) {
            return Err(CompareError::new(
                "P128 counter receipt reducer does not match its immutable model slot",
            ));
        }
        P128FoundationCounterRecord::new(
            self.ledger_sha256.clone(),
            point,
            session_id,
            observation_sequence,
            receipt,
        )
    }

    fn validate(&self) -> Result<(), CompareError> {
        if self.schema != P128_FOUNDATION_LEDGER_SCHEMA
            || self.candidate_commit != P128_FOUNDATION_CANDIDATE
            || self.candidate_tree != P128_FOUNDATION_TREE
            || self.ledger_sha256 != LEDGER_SHA256
        {
            return Err(CompareError::new(
                "P128 ledger candidate identity or schema differs from its authenticated scope",
            ));
        }
        if self.canonical_digest()? != self.ledger_sha256 {
            return Err(CompareError::new(
                "P128 ledger fields no longer match their canonical immutable seal",
            ));
        }
        if self.records.len() != 32 {
            return Err(CompareError::new(
                "P128 ledger must contain exactly 32 records",
            ));
        }
        for (key, digest) in EVIDENCE_DIGESTS {
            if self.evidence.get(key).map(String::as_str) != Some(digest) {
                return Err(CompareError::new(
                    "P128 ledger evidence digest differs from the authenticated source",
                ));
            }
        }
        if self.evidence.len() != EVIDENCE_DIGESTS.len() {
            return Err(CompareError::new(
                "P128 ledger contains an unexpected evidence digest",
            ));
        }

        let mut ids = BTreeSet::new();
        let mut families = BTreeMap::new();
        let mut protected = 0_usize;
        for record in &self.records {
            if !ids.insert(record.point_id.as_str()) || !is_hex(&record.point_id, 24) {
                return Err(CompareError::new(
                    "P128 ledger point IDs must be unique 24-character lowercase hex values",
                ));
            }
            if !is_hex(&record.source_row_sha256, 64)
                || !matches!(
                    record.boundary.as_str(),
                    "first-public-operation" | "steady-public-operation"
                )
                || !matches!(
                    record.model.as_str(),
                    "count" | "count-spans" | "count-captures" | "grep-captures"
                )
                || !matches!(record.family.as_str(), "A" | "B" | "C" | "D" | "protected")
                || (record.protected != (record.family == "protected"))
                || Some(record.required_receipt_kind)
                    != expected_receipt_kind(&record.family, &record.model)
            {
                return Err(CompareError::new(
                    "P128 ledger record has an invalid immutable attribution shape",
                ));
            }
            let family_count = families.entry(record.family.as_str()).or_insert(0_usize);
            *family_count = family_count
                .checked_add(1)
                .ok_or_else(|| CompareError::new("P128 ledger family count overflow"))?;
            protected = protected
                .checked_add(usize::from(record.protected))
                .ok_or_else(|| CompareError::new("P128 ledger protected count overflow"))?;
        }
        let expected = BTreeMap::from([
            ("A", 16_usize),
            ("B", 6_usize),
            ("C", 4_usize),
            ("D", 5_usize),
            ("protected", 1_usize),
        ]);
        if families != expected || protected != 1 {
            return Err(CompareError::new(
                "P128 ledger family counts or protected sibling differ from the immutable scope",
            ));
        }
        Ok(())
    }

    fn canonical_digest(&self) -> Result<String, CompareError> {
        let mut value = serde_json::to_value(self)
            .map_err(|error| CompareError::new(format!("encode P128 ledger: {error}")))?;
        let Value::Object(object) = &mut value else {
            return Err(CompareError::new(
                "P128 ledger cannot encode as a JSON object",
            ));
        };
        object.remove("ledger_sha256");
        canonical_json_sha256(&value)
    }

    /// Start a qualification collection that rejects duplicate point bindings
    /// and reusing one native receipt for multiple opaque IDs.
    ///
    /// # Errors
    ///
    /// Returns an error if this generated ledger is no longer authentic.
    pub fn into_counter_collection(self) -> Result<P128FoundationCounterCollection, CompareError> {
        self.validate()?;
        Ok(P128FoundationCounterCollection {
            ledger: self,
            records: Vec::new(),
            next_session_id: 0,
        })
    }
}

/// One mutable qualification collection. Its observations are immutable once
/// added, and it deliberately has no route-selection API.
#[derive(Debug)]
pub struct P128FoundationCounterCollection {
    ledger: P128FoundationLedger,
    records: Vec<P128FoundationCounterRecord>,
    next_session_id: usize,
}

impl P128FoundationCounterCollection {
    /// Open one diagnostic aggregate session owned by this collection. The
    /// generated session/observation identity prevents a cloned observation
    /// from being attributed to more than one opaque point.
    ///
    /// # Errors
    ///
    /// Returns an error only if the collection cannot represent another
    /// session identity.
    pub fn aggregate_counter_session(
        &mut self,
        lifecycle: CurrentFreAggregateOperationLifecycle,
    ) -> Result<P128FoundationAggregateCounterSession, CompareError> {
        self.next_session_id = self
            .next_session_id
            .checked_add(1)
            .ok_or_else(|| CompareError::new("P128 counter collection session ID overflow"))?;
        Ok(P128FoundationAggregateCounterSession::new(
            lifecycle,
            self.next_session_id,
        ))
    }

    /// Bind one completed observation to its opaque slot exactly once.
    ///
    /// # Errors
    ///
    /// Returns an error for duplicate point IDs, receipt reuse, wrong boundary,
    /// missing native evidence, or any malformed nested receipt.
    pub fn bind(
        &mut self,
        point_id: &str,
        observation: P128FoundationAggregateCounterObservation,
    ) -> Result<&P128FoundationCounterRecord, CompareError> {
        if self
            .records
            .iter()
            .any(|record| record.point.point_id == point_id)
        {
            return Err(CompareError::new(
                "P128 counter collection already contains this opaque point ID",
            ));
        }
        let record = self
            .ledger
            .bind_continuation_counter_record(point_id, observation)?;
        if self.records.iter().any(|existing| {
            existing.session_id == record.session_id
                && existing.observation_sequence == record.observation_sequence
        }) {
            return Err(CompareError::new(
                "P128 counter collection cannot reuse one completed observation for multiple point IDs",
            ));
        }
        self.records.push(record);
        Ok(self
            .records
            .last()
            .expect("P128 counter collection retained its newly bound record"))
    }

    /// Completed immutable records in insertion order.
    #[must_use]
    pub fn records(&self) -> &[P128FoundationCounterRecord] {
        &self.records
    }
}

/// Immutable public-operation boundary assigned by a diagnostic-only session.
/// It is derived from the session call order rather than supplied by a caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum P128FoundationOperationBoundary {
    /// First completed public operation on a retained lifecycle.
    First,
    /// Any later completed public operation on that same lifecycle.
    Steady,
}

impl P128FoundationOperationBoundary {
    const fn as_str(self) -> &'static str {
        match self {
            Self::First => "first-public-operation",
            Self::Steady => "steady-public-operation",
        }
    }
}

/// Owns a reusable aggregate lifecycle and assigns its first/steady boundary
/// after each completed diagnostic operation. It accepts neither a ledger ID
/// nor benchmark, fixture, result, hash, or timing metadata.
#[derive(Debug)]
pub struct P128FoundationAggregateCounterSession {
    lifecycle: Box<CurrentFreAggregateOperationLifecycle>,
    session_id: usize,
    completed_operations: usize,
}

impl P128FoundationAggregateCounterSession {
    /// Start a post-operation counter session around one already-built shell.
    #[must_use]
    fn new(lifecycle: CurrentFreAggregateOperationLifecycle, session_id: usize) -> Self {
        Self {
            lifecycle: Box::new(lifecycle),
            session_id,
            completed_operations: 0,
        }
    }

    /// Execute the retained shell and return a boundary-authenticated
    /// observation after completion.
    ///
    /// # Errors
    ///
    /// Returns the shell's exact input/operation error without attaching a
    /// point or changing route selection.
    pub fn execute(
        &mut self,
        haystack: &[u8],
    ) -> Result<P128FoundationAggregateCounterObservation, CompareError> {
        let boundary = if self.completed_operations == 0 {
            P128FoundationOperationBoundary::First
        } else {
            P128FoundationOperationBoundary::Steady
        };
        let result = Box::new(self.lifecycle.execute_with_counters(haystack)?);
        self.completed_operations = self
            .completed_operations
            .checked_add(1)
            .ok_or_else(|| CompareError::new("P128 counter session call count overflow"))?;
        Ok(P128FoundationAggregateCounterObservation {
            boundary,
            session_id: self.session_id,
            sequence: self.completed_operations,
            result,
        })
    }
}

/// One completed aggregate counter observation whose public boundary cannot be
/// caller-forged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P128FoundationAggregateCounterObservation {
    boundary: P128FoundationOperationBoundary,
    session_id: usize,
    sequence: usize,
    result: Box<CurrentFreAggregateOperationCounterResult>,
}

impl P128FoundationAggregateCounterObservation {
    /// Derived first/steady boundary for this completed observation.
    #[must_use]
    pub const fn boundary(&self) -> P128FoundationOperationBoundary {
        self.boundary
    }

    /// Value-only result of the already-completed operation.
    #[must_use]
    pub const fn value(&self) -> u64 {
        self.result.value()
    }

    fn into_continuation_receipt(
        self,
    ) -> Result<(usize, usize, AggregateOperationHotCounterReceipt), CompareError> {
        let receipt = match self.result.receipt_status() {
            CurrentFreAggregateCounterReceiptStatus::Continuation(receipt) => {
                receipt.as_ref().clone()
            }
            CurrentFreAggregateCounterReceiptStatus::DirectSelectedPlan => {
                return Err(CompareError::new(
                    "P128 point requires a native continuation counter receipt, but the completed operation published no bindable value-operation receipt",
                ));
            }
            CurrentFreAggregateCounterReceiptStatus::IncumbentProjectionForUnreceiptedSweep => {
                return Err(CompareError::new(
                    "P128 point requires physical sweep evidence, but the diagnostic only published an incumbent counter projection",
                ));
            }
            CurrentFreAggregateCounterReceiptStatus::MissingMultiPlanReceipt => {
                return Err(CompareError::new(
                    "P128 point requires a native multi-pattern receipt that Foundation does not fabricate",
                ));
            }
        };
        if u64::try_from(receipt.value.value()).ok() != Some(self.result.value()) {
            return Err(CompareError::new(
                "P128 continuation receipt value differs from its completed shell result",
            ));
        }
        Ok((self.session_id, self.sequence, receipt))
    }
}

/// Immutable post-operation attribution record for a continuation hot-counter
/// receipt. Capture and build-many executors will bind their own receipt
/// variants in their scoped Foundation interfaces; this type never invents a
/// counter for an executor that has not published one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P128FoundationCounterRecord {
    /// Counter-record envelope schema.
    pub schema: &'static str,
    /// Generated ledger seal used for the point lookup.
    pub ledger_sha256: String,
    /// Opaque slot selected after the operation finished.
    pub point: P128FoundationLedgerRecord,
    /// Collection-owned diagnostic session identity.
    session_id: usize,
    /// Completed operation sequence within that diagnostic session.
    observation_sequence: usize,
    /// Immutable selected-route continuation hot-counter receipt.
    pub receipt: Box<AggregateOperationHotCounterReceipt>,
    authentication: P128FoundationCounterRecordAuthentication,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct P128FoundationCounterRecordAuthentication {
    schema: &'static str,
    ledger_sha256: String,
    point: P128FoundationLedgerRecord,
    session_id: usize,
    observation_sequence: usize,
    receipt_fingerprint: [u8; 32],
}

impl P128FoundationCounterRecord {
    fn new(
        ledger_sha256: String,
        point: P128FoundationLedgerRecord,
        session_id: usize,
        observation_sequence: usize,
        receipt: AggregateOperationHotCounterReceipt,
    ) -> Result<Self, CompareError> {
        if !receipt.closes() || !single_continuation_matches(&point, receipt.value) {
            return Err(CompareError::new(
                "P128 counter record cannot seal an incompatible operation receipt",
            ));
        }
        let schema = P128_FOUNDATION_COUNTER_RECORD_SCHEMA;
        Ok(Self {
            authentication: P128FoundationCounterRecordAuthentication {
                schema,
                ledger_sha256: ledger_sha256.clone(),
                point: point.clone(),
                session_id,
                observation_sequence,
                receipt_fingerprint: counter_receipt_fingerprint(&receipt),
            },
            schema,
            ledger_sha256,
            point,
            session_id,
            observation_sequence,
            receipt: Box::new(receipt),
        })
    }

    /// Recheck the immutable ledger association and the nested exact counter
    /// receipt. Any mutation of a public record field makes this return false.
    #[must_use]
    pub fn closes(&self) -> bool {
        self.schema == P128_FOUNDATION_COUNTER_RECORD_SCHEMA
            && self.ledger_sha256 == LEDGER_SHA256
            && self.authentication
                == (P128FoundationCounterRecordAuthentication {
                    schema: self.schema,
                    ledger_sha256: self.ledger_sha256.clone(),
                    point: self.point.clone(),
                    session_id: self.session_id,
                    observation_sequence: self.observation_sequence,
                    receipt_fingerprint: counter_receipt_fingerprint(&self.receipt),
                })
            && self.receipt.closes()
            && single_continuation_matches(&self.point, self.receipt.value)
    }
}

/// Load the immutable P128 Foundation scope ledger.
///
/// # Errors
///
/// Returns an error if the checked-in generated ledger is tampered with or no
/// longer matches the authenticated evidence.
pub fn p128_foundation_ledger() -> Result<P128FoundationLedger, CompareError> {
    P128FoundationLedger::load()
}

fn single_continuation_matches(
    point: &P128FoundationLedgerRecord,
    value: AggregateOperationCounterValue,
) -> bool {
    point.required_receipt_kind == P128FoundationReceiptKind::SingleContinuation
        && matches!(
            (point.model.as_str(), value),
            ("count", AggregateOperationCounterValue::Count(_))
                | ("count-spans", AggregateOperationCounterValue::SpanSum(_))
        )
}

fn expected_receipt_kind(family: &str, model: &str) -> Option<P128FoundationReceiptKind> {
    match (family, model) {
        ("A", "count" | "count-spans") | ("B" | "protected", "count-spans") => {
            Some(P128FoundationReceiptKind::SingleContinuation)
        }
        ("C", "count-spans") => Some(P128FoundationReceiptKind::MultiContinuation),
        ("D", "grep-captures") => Some(P128FoundationReceiptKind::CaptureUniform),
        ("D", "count-captures") => Some(P128FoundationReceiptKind::CaptureHistory),
        _ => None,
    }
}

fn counter_receipt_fingerprint(receipt: &AggregateOperationHotCounterReceipt) -> [u8; 32] {
    // The nested receipt independently seals its route certificate, actual
    // accounting, reducer value, and projected counters. This compact outer
    // fingerprint binds that whole receipt to one attribution record without
    // retaining a second stack-heavy clone.
    Sha256::digest(format!("{receipt:?}").as_bytes()).into()
}

fn is_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn canonical_json_sha256(value: &Value) -> Result<String, CompareError> {
    let mut encoded = Vec::new();
    append_canonical_json(&mut encoded, value)?;
    encoded.push(b'\n');
    Ok(format!("{:x}", Sha256::digest(encoded)))
}

fn append_canonical_json(target: &mut Vec<u8>, value: &Value) -> Result<(), CompareError> {
    match value {
        Value::Null => target.extend_from_slice(b"null"),
        Value::Bool(true) => target.extend_from_slice(b"true"),
        Value::Bool(false) => target.extend_from_slice(b"false"),
        Value::Number(number) => target.extend_from_slice(number.to_string().as_bytes()),
        Value::String(string) => serde_json::to_writer(&mut *target, string)
            .map_err(|error| CompareError::new(format!("encode P128 ledger string: {error}")))?,
        Value::Array(values) => {
            target.push(b'[');
            for (index, item) in values.iter().enumerate() {
                if index > 0 {
                    target.push(b',');
                }
                append_canonical_json(target, item)?;
            }
            target.push(b']');
        }
        Value::Object(values) => {
            target.push(b'{');
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    target.push(b',');
                }
                serde_json::to_writer(&mut *target, key).map_err(|error| {
                    CompareError::new(format!("encode P128 ledger key: {error}"))
                })?;
                target.push(b':');
                append_canonical_json(target, &values[key])?;
            }
            target.push(b'}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        build_current_fre_complete_match_count_lifecycle,
        current_fre_rebar_aggregate_operation_lifecycle,
    };

    fn native_continuation_count_lifecycle(
        pattern: &str,
        haystack_len: usize,
    ) -> CurrentFreAggregateOperationLifecycle {
        let policy = crate::RunLimits::default();
        let regex = crate::current_fre_rebar_aggregate_builder(pattern, false, false)
            .plan_selection(crate::AggregatePlanSelection::ForceContinuation)
            .build_count()
            .expect("forced native count continuation");
        let limits = crate::count_run_limits_with_policy(haystack_len, &regex, &policy)
            .expect("native count continuation limits");
        CurrentFreAggregateOperationLifecycle {
            model: crate::CurrentFreAggregateOperationModel::Count,
            plan: "p128-test-native-continuation-count",
            haystack_len,
            inner: crate::CurrentFreAggregateOperationInner::CountSingle(regex, limits),
        }
    }

    #[test]
    fn generated_ledger_closes_all_31_tail_points_and_protected_sibling() {
        let ledger = p128_foundation_ledger().expect("generated ledger closes");
        assert_eq!(ledger.records.len(), 32);
        assert_eq!(
            ledger
                .records
                .iter()
                .filter(|record| !record.protected)
                .count(),
            31
        );
        assert_eq!(
            ledger
                .records
                .iter()
                .filter(|record| record.protected)
                .count(),
            1
        );
        assert_eq!(ledger.ledger_sha256, LEDGER_SHA256);
        assert_eq!(
            ledger
                .records
                .iter()
                .filter(|record| {
                    record.required_receipt_kind == P128FoundationReceiptKind::SingleContinuation
                })
                .count(),
            23
        );
        assert_eq!(
            ledger
                .records
                .iter()
                .filter(|record| {
                    record.required_receipt_kind == P128FoundationReceiptKind::MultiContinuation
                })
                .count(),
            4
        );
        assert_eq!(
            ledger
                .records
                .iter()
                .filter(|record| {
                    record.required_receipt_kind == P128FoundationReceiptKind::CaptureUniform
                })
                .count(),
            4
        );
        assert_eq!(
            ledger
                .records
                .iter()
                .filter(|record| {
                    record.required_receipt_kind == P128FoundationReceiptKind::CaptureHistory
                })
                .count(),
            1
        );
        for record in &ledger.records {
            assert_eq!(ledger.record(&record.point_id), Some(record));
        }
    }

    #[test]
    fn generated_ledger_rejects_even_one_tampered_attribution_field() {
        let tampered =
            LEDGER_JSON.replacen("860cb8f3420b6657fa98cc76", "860cb8f3420b6657fa98cc77", 1);
        assert!(P128FoundationLedger::from_json(&tampered).is_err());
    }

    #[test]
    fn post_operation_binding_seals_only_matching_opaque_slots() {
        let patterns = [r"(?:a+b|a)".to_owned()];
        let haystack = b"aaaabaaaa";
        let formal_lifecycle = build_current_fre_complete_match_count_lifecycle(
            &patterns,
            false,
            false,
            haystack.len(),
        )
        .expect("continuation lifecycle");
        assert_eq!(formal_lifecycle.plan(), "aggregate-continuation-program");
        let mut formal_collection = p128_foundation_ledger()
            .expect("ledger")
            .into_counter_collection()
            .expect("authenticated collection");
        let mut formal_session = formal_collection
            .aggregate_counter_session(formal_lifecycle)
            .expect("formal counter session");
        let formal_first = formal_session
            .execute(haystack)
            .expect("formal complete-spans operation");
        // A continuation-planned Spans artifact is not a native Count
        // operation receipt. Binding it here would invent cross-operation
        // evidence even though the materialized value itself is exact.
        assert!(matches!(
            formal_first.result.receipt_status(),
            CurrentFreAggregateCounterReceiptStatus::DirectSelectedPlan
        ));
        let error = formal_collection
            .bind("f7b473ba413cc5a67a9683d3", formal_first)
            .expect_err("complete-spans Count must not fabricate a value-count receipt");
        assert!(
            error
                .to_string()
                .contains("published no bindable value-operation receipt")
        );

        let lifecycle = native_continuation_count_lifecycle(patterns[0].as_str(), haystack.len());
        let mut collection = p128_foundation_ledger()
            .expect("ledger")
            .into_counter_collection()
            .expect("authenticated collection");
        let mut session = collection
            .aggregate_counter_session(lifecycle)
            .expect("counter session");
        let first = session
            .execute(haystack)
            .expect("first completed operation");
        assert_eq!(first.boundary(), P128FoundationOperationBoundary::First);
        assert!(
            collection
                .bind("860cb8f3420b6657fa98cc76", first.clone())
                .is_err()
        );
        assert!(
            collection
                .bind("f7b473ba413cc5a67a9683d3", first.clone())
                .expect("matching first count slot")
                .closes()
        );
        assert!(collection.bind("fa2c7c219493095b74039eb1", first).is_err());

        let steady = session
            .execute(haystack)
            .expect("steady completed operation");
        assert_eq!(steady.boundary(), P128FoundationOperationBoundary::Steady);
        assert!(
            collection
                .bind("860cb8f3420b6657fa98cc76", steady)
                .expect("matching steady count slot")
                .closes()
        );
        assert_eq!(collection.records().len(), 2);
    }

    #[test]
    fn future_multi_and_capture_slots_are_typed_and_refuse_fabricated_counters() {
        let patterns = ["a+".to_owned(), "b+".to_owned()];
        let haystack = b"aaa bbb";
        let lifecycle = current_fre_rebar_aggregate_operation_lifecycle(
            "count-spans",
            &patterns,
            false,
            false,
            haystack.len(),
        )
        .expect("multi lifecycle");
        let ledger = p128_foundation_ledger().expect("ledger");
        assert_eq!(
            ledger
                .record("f5d2f665c23a014f68b4fd98")
                .expect("C slot")
                .required_receipt_kind(),
            P128FoundationReceiptKind::MultiContinuation
        );
        assert_eq!(
            ledger
                .record("316b893df6c697251fef808a")
                .expect("D grep slot")
                .required_receipt_kind(),
            P128FoundationReceiptKind::CaptureUniform
        );
        assert_eq!(
            ledger
                .record("43fa59817f1c44d92040848e")
                .expect("D count slot")
                .required_receipt_kind(),
            P128FoundationReceiptKind::CaptureHistory
        );
        let mut collection = ledger
            .into_counter_collection()
            .expect("authenticated collection");
        let mut session = collection
            .aggregate_counter_session(lifecycle)
            .expect("counter session");
        let first = session
            .execute(haystack)
            .expect("completed multi operation");
        assert!(matches!(
            first.result.receipt_status(),
            CurrentFreAggregateCounterReceiptStatus::MissingMultiPlanReceipt
        ));
        assert!(collection.bind("f5d2f665c23a014f68b4fd98", first).is_err());
    }

    #[test]
    fn direct_single_route_is_explicitly_distinguished_from_missing_receipts() {
        let patterns = ["aba".to_owned()];
        let haystack = b"ababaaba";
        let lifecycle = build_current_fre_complete_match_count_lifecycle(
            &patterns,
            false,
            false,
            haystack.len(),
        )
        .expect("direct lifecycle");
        assert_eq!(lifecycle.plan(), "aggregate-continuation-program");

        let result = lifecycle
            .execute_with_counters(haystack)
            .expect("complete-spans completed operation");
        assert_eq!(result.value(), lifecycle.execute(haystack).unwrap());
        assert_eq!(result.continuation_receipt(), None);
        assert!(matches!(
            result.receipt_status(),
            CurrentFreAggregateCounterReceiptStatus::DirectSelectedPlan
        ));
    }

    #[test]
    fn incumbent_projection_cannot_close_a_p128_sweep_point() {
        let observation = P128FoundationAggregateCounterObservation {
            boundary: P128FoundationOperationBoundary::First,
            session_id: 7,
            sequence: 1,
            result: Box::new(CurrentFreAggregateOperationCounterResult {
                value: 2,
                receipt_status:
                    CurrentFreAggregateCounterReceiptStatus::IncumbentProjectionForUnreceiptedSweep,
            }),
        };
        let error = observation.into_continuation_receipt().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("diagnostic only published an incumbent counter projection")
        );
    }

    #[test]
    fn held_out_shell_shapes_keep_value_and_counter_semantics_identical() {
        for (model, pattern, haystack) in [
            ("count", r"(?:ab+|a)", b"abbb a ab".as_slice()),
            ("count-spans", r"(?:xy+z|x)", b"xyyzx xyzz".as_slice()),
        ] {
            let patterns = [pattern.to_owned()];
            let lifecycle = if model == "count" {
                build_current_fre_complete_match_count_lifecycle(
                    &patterns,
                    false,
                    false,
                    haystack.len(),
                )
            } else {
                current_fre_rebar_aggregate_operation_lifecycle(
                    model,
                    &patterns,
                    false,
                    false,
                    haystack.len(),
                )
            }
            .expect("held-out continuation lifecycle");
            assert_eq!(lifecycle.plan(), "aggregate-continuation-program");
            let ordinary = lifecycle.execute(haystack).expect("ordinary value");
            let counters = lifecycle
                .execute_with_counters(haystack)
                .expect("counter value");
            assert_eq!(counters.value(), ordinary);
            assert_eq!(counters.continuation_receipt(), None);
            assert!(matches!(
                counters.receipt_status(),
                CurrentFreAggregateCounterReceiptStatus::DirectSelectedPlan
            ));

            let shortened = &haystack[..haystack.len() - 1];
            assert_eq!(
                lifecycle.execute(shortened).unwrap_err().to_string(),
                lifecycle
                    .execute_with_counters(shortened)
                    .unwrap_err()
                    .to_string()
            );
        }
    }
}
