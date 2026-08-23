//! Shared ordered-many native reducers for equal uniform capture projection.
//!
//! Every source is parsed and proved independently under one Rust profile
//! before the capture-free ordered-many compiler is selected. The final
//! reducer is therefore authorized only when every source has the same
//! positive capture-participation multiplier.

use core::{fmt, num::NonZeroU64};

use fre_lower::{
    UniformCaptureParticipationDecline, UniformCaptureParticipationDisposition,
    UniformCaptureParticipationError, UniformCaptureParticipationLimits,
    UniformCaptureParticipationReceipt, analyze_uniform_capture_participation,
};
use fre_syntax::{CanonicalPattern, CompatibilityProfile, ParseError, ParseRequest, RustProfile};
use sha2::{Digest, Sha256};

use crate::{
    CompiledRegex, EngineKind, EntryAbi, ORDERED_MANY_AOT_RECEIPT_VERSION,
    OrderedManyAotCompileDecline, OrderedManyAotCompileDisposition, OrderedManyAotCompileError,
    OrderedManyAotCompileRequest, OrderedManyAotReceipt, OrderedManyCompileError,
    OrderedManyPatternId, PREPARED_CAPABILITY_ORDERED_NFA_V15, PreparedAggregateExports,
    PreparedAggregateStrategy, SlowAotLimits, Target, UniformCaptureReducerCompileError,
    UniformCaptureReducerDomain, UniformCaptureReducerOperation,
    uniform_capture::append_native_uniform_capture_reducer_to_count_aggregate,
};

/// Receipt schema for one shared equal-multiplier capture reducer.
pub const SHARED_UNIFORM_CAPTURE_REDUCER_AOT_RECEIPT_VERSION: u32 = 1;

/// The sole safe refusals from shared equal-multiplier preselection or the
/// selected ordered-many native aggregate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SharedUniformCaptureReducerAotCompileDecline {
    /// One source has no positive uniform-participation theorem.
    Participation {
        row: usize,
        pattern_id: OrderedManyPatternId,
        reason: UniformCaptureParticipationDecline,
    },
    /// Every source was uniform, but the per-match multipliers differ.
    UnequalMultiplier {
        row: usize,
        pattern_id: OrderedManyPatternId,
        expected: NonZeroU64,
        actual: NonZeroU64,
    },
    /// The exact combined semantic graph has no supported native V15 view.
    Unsupported,
    /// The immutable combined graph exceeds its explicit native-data cap.
    NativeDataBytes { limit: usize, required: usize },
    /// Every authenticated combined object exceeds its explicit object cap.
    ObjectBytes { limit: usize, required: usize },
}

/// Terminal failure before a shared capture reducer is published.
#[derive(Debug)]
#[non_exhaustive]
pub enum SharedUniformCaptureReducerAotCompileError {
    Parse {
        row: usize,
        pattern_id: OrderedManyPatternId,
        source: ParseError,
    },
    NonRustPattern {
        row: usize,
        pattern_id: OrderedManyPatternId,
    },
    Participation {
        row: usize,
        pattern_id: OrderedManyPatternId,
        source: UniformCaptureParticipationError,
    },
    MultiplierOverflow {
        row: usize,
        pattern_id: OrderedManyPatternId,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    AllocationFailed {
        structure: &'static str,
        entries: usize,
    },
    OrderedMany(OrderedManyAotCompileError),
    Finalization(UniformCaptureReducerCompileError),
    Authentication(SharedUniformCaptureReducerAotAuthenticationError),
}

impl fmt::Display for SharedUniformCaptureReducerAotCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse {
                row,
                pattern_id,
                source,
            } => write!(
                formatter,
                "shared uniform-capture source row {row} id {} failed to parse: {source}",
                pattern_id.get(),
            ),
            Self::NonRustPattern { row, pattern_id } => write!(
                formatter,
                "shared uniform-capture Rust source row {row} id {} produced a non-Rust tree",
                pattern_id.get(),
            ),
            Self::Participation {
                row,
                pattern_id,
                source,
            } => write!(
                formatter,
                "shared uniform-capture source row {row} id {} proof failed: {source}",
                pattern_id.get(),
            ),
            Self::MultiplierOverflow { row, pattern_id } => write!(
                formatter,
                "shared uniform-capture source row {row} id {} multiplier does not fit u64",
                pattern_id.get(),
            ),
            Self::ArithmeticOverflow { computation } => write!(
                formatter,
                "shared uniform-capture overflow computing {computation}",
            ),
            Self::AllocationFailed { structure, entries } => write!(
                formatter,
                "shared uniform-capture could not reserve {entries} entries for {structure}",
            ),
            Self::OrderedMany(source) => {
                write!(formatter, "shared uniform-capture aggregate: {source}")
            }
            Self::Finalization(source) => {
                write!(formatter, "shared uniform-capture finalization: {source}")
            }
            Self::Authentication(source) => source.fmt(formatter),
        }
    }
}

impl std::error::Error for SharedUniformCaptureReducerAotCompileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Parse { source, .. } => Some(source),
            Self::Participation { source, .. } => Some(source),
            Self::OrderedMany(source) => Some(source),
            Self::Finalization(source) => Some(source),
            Self::Authentication(source) => Some(source),
            Self::NonRustPattern { .. }
            | Self::MultiplierOverflow { .. }
            | Self::ArithmeticOverflow { .. }
            | Self::AllocationFailed { .. } => None,
        }
    }
}

/// Why an immutable shared capture artifact no longer authenticates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SharedUniformCaptureReducerAotAuthenticationError {
    Schema,
    ProfileIdentity,
    SourceShape,
    ProofIdentity,
    ProofMultiplier,
    ProofBinding,
    OperationDomain,
    AggregateReceipt,
    AggregateRoute,
    ObjectIdentity,
    CountSymbol,
    ReducerSymbol,
    NativeClosure,
}

impl fmt::Display for SharedUniformCaptureReducerAotAuthenticationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "shared uniform-capture reducer authentication failed: {self:?}",
        )
    }
}

impl std::error::Error for SharedUniformCaptureReducerAotAuthenticationError {}

/// Compiler-issued source/proof and final native closure identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedUniformCaptureReducerAotReceipt {
    schema_version: u32,
    rows: usize,
    pattern_bytes: usize,
    ordered_sources_sha256: [u8; 32],
    profile_identity_sha256: [u8; 32],
    source_proof_bindings_sha256: Box<[[u8; 32]]>,
    source_proofs: Box<[UniformCaptureParticipationReceipt]>,
    operation: UniformCaptureReducerOperation,
    domain: UniformCaptureReducerDomain,
    multiplier: NonZeroU64,
    proof_identity_sha256: [u8; 32],
    program_sha256: [u8; 32],
    aggregate_object_sha256: [u8; 32],
    object_sha256: [u8; 32],
    count_symbol_sha256: [u8; 32],
    reducer_symbol_sha256: [u8; 32],
    target: Target,
    line_terminator: u8,
    aggregate_strategy: PreparedAggregateStrategy,
    required_prepare_capabilities: u64,
}

impl SharedUniformCaptureReducerAotReceipt {
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }
    #[must_use]
    pub const fn rows(&self) -> usize {
        self.rows
    }
    #[must_use]
    pub const fn pattern_bytes(&self) -> usize {
        self.pattern_bytes
    }
    #[must_use]
    pub const fn ordered_sources_sha256(&self) -> [u8; 32] {
        self.ordered_sources_sha256
    }
    #[must_use]
    pub const fn profile_identity_sha256(&self) -> [u8; 32] {
        self.profile_identity_sha256
    }
    #[must_use]
    pub fn source_proof_bindings_sha256(&self) -> &[[u8; 32]] {
        &self.source_proof_bindings_sha256
    }
    #[must_use]
    pub fn source_proofs(&self) -> &[UniformCaptureParticipationReceipt] {
        &self.source_proofs
    }
    #[must_use]
    pub const fn operation(&self) -> UniformCaptureReducerOperation {
        self.operation
    }
    #[must_use]
    pub const fn domain(&self) -> UniformCaptureReducerDomain {
        self.domain
    }
    #[must_use]
    pub const fn multiplier(&self) -> NonZeroU64 {
        self.multiplier
    }
    #[must_use]
    pub const fn proof_identity_sha256(&self) -> [u8; 32] {
        self.proof_identity_sha256
    }
    #[must_use]
    pub const fn program_sha256(&self) -> [u8; 32] {
        self.program_sha256
    }
    #[must_use]
    pub const fn aggregate_object_sha256(&self) -> [u8; 32] {
        self.aggregate_object_sha256
    }
    #[must_use]
    pub const fn object_sha256(&self) -> [u8; 32] {
        self.object_sha256
    }
    #[must_use]
    pub const fn count_symbol_sha256(&self) -> [u8; 32] {
        self.count_symbol_sha256
    }
    #[must_use]
    pub const fn reducer_symbol_sha256(&self) -> [u8; 32] {
        self.reducer_symbol_sha256
    }
    #[must_use]
    pub const fn target(&self) -> Target {
        self.target
    }
    #[must_use]
    pub const fn line_terminator(&self) -> u8 {
        self.line_terminator
    }
    #[must_use]
    pub const fn aggregate_strategy(&self) -> PreparedAggregateStrategy {
        self.aggregate_strategy
    }
    #[must_use]
    pub const fn required_prepare_capabilities(&self) -> u64 {
        self.required_prepare_capabilities
    }

    /// Recheck the source/proof seal and exact helper-free final closure.
    pub fn authenticate(
        &self,
        profile: &RustProfile,
        compiled: &CompiledRegex,
        reducer_symbol: &str,
    ) -> Result<(), SharedUniformCaptureReducerAotAuthenticationError> {
        if self.schema_version != SHARED_UNIFORM_CAPTURE_REDUCER_AOT_RECEIPT_VERSION {
            return Err(SharedUniformCaptureReducerAotAuthenticationError::Schema);
        }
        let profile_sha256 = sha256(profile.identity_string().as_bytes());
        if profile_sha256 != self.profile_identity_sha256 {
            return Err(SharedUniformCaptureReducerAotAuthenticationError::ProfileIdentity);
        }
        if self.rows == 0
            || self.rows != self.source_proofs.len()
            || self.rows != self.source_proof_bindings_sha256.len()
            || self.pattern_bytes == 0
            || self.ordered_sources_sha256 == [0; 32]
            || self.aggregate_object_sha256 == [0; 32]
            || self.source_proof_bindings_sha256.contains(&[0; 32])
        {
            return Err(SharedUniformCaptureReducerAotAuthenticationError::SourceShape);
        }
        for proof in &self.source_proofs {
            if !proof.identity().authenticates_current() {
                return Err(SharedUniformCaptureReducerAotAuthenticationError::ProofIdentity);
            }
            let multiplier = u64::try_from(proof.participating_groups_per_match().get())
                .ok()
                .and_then(NonZeroU64::new);
            if multiplier != Some(self.multiplier) {
                return Err(SharedUniformCaptureReducerAotAuthenticationError::ProofMultiplier);
            }
        }
        let actual_proof_identity = composite_proof_identity(
            self.profile_identity_sha256,
            self.ordered_sources_sha256,
            self.program_sha256,
            self.aggregate_object_sha256,
            self.multiplier,
            &self.source_proof_bindings_sha256,
        )?;
        if actual_proof_identity != self.proof_identity_sha256 {
            return Err(SharedUniformCaptureReducerAotAuthenticationError::ProofBinding);
        }
        if self.operation.domain() != self.domain {
            return Err(SharedUniformCaptureReducerAotAuthenticationError::OperationDomain);
        }
        authenticate_final_aggregate(self, compiled, reducer_symbol)
    }
}

/// One shared semantic program and its whole-operation capture reducer.
#[derive(Clone, Debug)]
pub struct SharedUniformCaptureReducerAotArtifact {
    compiled: CompiledRegex,
    profile: RustProfile,
    reducer_symbol: String,
    receipt: SharedUniformCaptureReducerAotReceipt,
}

impl SharedUniformCaptureReducerAotArtifact {
    #[must_use]
    pub const fn compiled(&self) -> &CompiledRegex {
        &self.compiled
    }
    #[must_use]
    pub const fn profile(&self) -> &RustProfile {
        &self.profile
    }
    #[must_use]
    pub fn reducer_symbol(&self) -> &str {
        &self.reducer_symbol
    }
    #[must_use]
    pub const fn receipt(&self) -> &SharedUniformCaptureReducerAotReceipt {
        &self.receipt
    }

    pub fn authenticate(&self) -> Result<(), SharedUniformCaptureReducerAotAuthenticationError> {
        self.receipt
            .authenticate(&self.profile, &self.compiled, &self.reducer_symbol)
    }

    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        CompiledRegex,
        RustProfile,
        String,
        SharedUniformCaptureReducerAotReceipt,
    ) {
        (
            self.compiled,
            self.profile,
            self.reducer_symbol,
            self.receipt,
        )
    }
}

/// Transactional shared capture selection.
#[derive(Clone, Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "boxing would add an allocation after a selected compiler transaction"
)]
pub enum SharedUniformCaptureReducerAotCompileDisposition {
    Compiled(SharedUniformCaptureReducerAotArtifact),
    Declined(SharedUniformCaptureReducerAotCompileDecline),
}

impl SharedUniformCaptureReducerAotCompileDisposition {
    #[must_use]
    pub const fn compiled(&self) -> Option<&SharedUniformCaptureReducerAotArtifact> {
        match self {
            Self::Compiled(artifact) => Some(artifact),
            Self::Declined(_) => None,
        }
    }
    #[must_use]
    pub const fn decline(&self) -> Option<SharedUniformCaptureReducerAotCompileDecline> {
        match self {
            Self::Compiled(_) => None,
            Self::Declined(decline) => Some(*decline),
        }
    }
    #[must_use]
    pub fn into_compiled(self) -> Option<SharedUniformCaptureReducerAotArtifact> {
        match self {
            Self::Compiled(artifact) => Some(artifact),
            Self::Declined(_) => None,
        }
    }
}

/// Prove one equal positive multiplier across independently parsed sources,
/// then compile the full shared Count portfolio and append one native capture
/// projection wrapper.
///
/// Semantic proof and unequal-multiplier refusals are reported before shared
/// automaton construction. After admission, only the ordered-many compiler's
/// explicit Unsupported/NativeDataBytes/ObjectBytes disposition is a safe
/// decline. Every parse, proof resource, allocation, lowering, object and
/// authentication failure is terminal.
pub fn compile_shared_uniform_capture_reducer_aot_reported(
    request: OrderedManyAotCompileRequest,
    operation: UniformCaptureReducerOperation,
    participation_limits: UniformCaptureParticipationLimits,
    slow_aot_limits: SlowAotLimits,
) -> Result<
    SharedUniformCaptureReducerAotCompileDisposition,
    SharedUniformCaptureReducerAotCompileError,
> {
    let row_count = request.rows.len();
    let pattern_bytes = precheck_source_envelope(&request)?;
    let profile = request.profile.clone();
    let profile_identity_sha256 = sha256(profile.identity_string().as_bytes());
    let compatibility = CompatibilityProfile::RustBytes(profile.clone());
    let mut source_proofs = Vec::new();
    source_proofs.try_reserve_exact(row_count).map_err(|_| {
        SharedUniformCaptureReducerAotCompileError::AllocationFailed {
            structure: "source proofs",
            entries: row_count,
        }
    })?;
    let mut source_proof_bindings = Vec::new();
    source_proof_bindings
        .try_reserve_exact(row_count)
        .map_err(
            |_| SharedUniformCaptureReducerAotCompileError::AllocationFailed {
                structure: "source proof bindings",
                entries: row_count,
            },
        )?;
    let mut expected_multiplier = None;
    let mut source_identity = Sha256::new();
    source_identity.update(b"fre.ordered-many-aot.sources.v1\0");
    source_identity.update(to_u64(row_count, "source row count identity")?.to_le_bytes());

    for (row, source) in request.rows.iter().enumerate() {
        let pattern_id = source.pattern_id();
        source_identity.update(to_u64(row, "source ordinal identity")?.to_le_bytes());
        source_identity.update(pattern_id.get().to_le_bytes());
        source_identity
            .update(to_u64(source.pattern().len(), "source length identity")?.to_le_bytes());
        source_identity.update(source.pattern().as_bytes());

        let parsed = fre_syntax::parse(ParseRequest::rust(
            source.pattern().to_owned(),
            compatibility.clone(),
        ))
        .map_err(|source| SharedUniformCaptureReducerAotCompileError::Parse {
            row,
            pattern_id,
            source,
        })?;
        let CanonicalPattern::Rust(parsed) = parsed.pattern else {
            return Err(SharedUniformCaptureReducerAotCompileError::NonRustPattern {
                row,
                pattern_id,
            });
        };
        let disposition = analyze_uniform_capture_participation(&parsed, participation_limits)
            .map_err(
                |source| SharedUniformCaptureReducerAotCompileError::Participation {
                    row,
                    pattern_id,
                    source,
                },
            )?;
        let proof = match disposition {
            UniformCaptureParticipationDisposition::Proven(proof) => proof,
            UniformCaptureParticipationDisposition::Declined(reason) => {
                return Ok(SharedUniformCaptureReducerAotCompileDisposition::Declined(
                    SharedUniformCaptureReducerAotCompileDecline::Participation {
                        row,
                        pattern_id,
                        reason,
                    },
                ));
            }
        };
        let multiplier = u64::try_from(proof.participating_groups_per_match().get())
            .ok()
            .and_then(NonZeroU64::new)
            .ok_or(
                SharedUniformCaptureReducerAotCompileError::MultiplierOverflow { row, pattern_id },
            )?;
        if let Some(expected) = expected_multiplier {
            if expected != multiplier {
                return Ok(SharedUniformCaptureReducerAotCompileDisposition::Declined(
                    SharedUniformCaptureReducerAotCompileDecline::UnequalMultiplier {
                        row,
                        pattern_id,
                        expected,
                        actual: multiplier,
                    },
                ));
            }
        } else {
            expected_multiplier = Some(multiplier);
        }
        source_proof_bindings.push(source_proof_binding(
            row,
            pattern_id,
            source.pattern().as_bytes(),
            profile_identity_sha256,
            proof,
        )?);
        source_proofs.push(proof);
    }

    let ordered_sources_sha256: [u8; 32] = source_identity.finalize().into();
    let expected_multiplier =
        expected_multiplier.ok_or(SharedUniformCaptureReducerAotCompileError::OrderedMany(
            OrderedManyAotCompileError::EmptyPatternSet,
        ))?;
    let max_object_bytes = request.limits.compile.max_object_bytes;
    let disposition = crate::compile_ordered_many_aot_reported(
        request,
        PreparedAggregateExports::COUNT,
        slow_aot_limits,
    )
    .map_err(SharedUniformCaptureReducerAotCompileError::OrderedMany)?;
    let ordered = match disposition {
        OrderedManyAotCompileDisposition::Compiled(artifact) => artifact,
        OrderedManyAotCompileDisposition::Declined(decline) => {
            let decline = match decline {
                OrderedManyAotCompileDecline::Unsupported => {
                    SharedUniformCaptureReducerAotCompileDecline::Unsupported
                }
                OrderedManyAotCompileDecline::NativeDataBytes { limit, required } => {
                    SharedUniformCaptureReducerAotCompileDecline::NativeDataBytes {
                        limit,
                        required,
                    }
                }
                OrderedManyAotCompileDecline::ObjectBytes { limit, required } => {
                    SharedUniformCaptureReducerAotCompileDecline::ObjectBytes { limit, required }
                }
            };
            return Ok(SharedUniformCaptureReducerAotCompileDisposition::Declined(
                decline,
            ));
        }
    };
    let (aggregate, aggregate_profile, ordered_receipt) = ordered.into_parts();
    authenticate_ordered_transaction(
        &profile,
        &aggregate_profile,
        row_count,
        pattern_bytes,
        ordered_sources_sha256,
        &ordered_receipt,
        &aggregate,
    )?;
    let aggregate_object_sha256 = ordered_receipt.object_sha256;
    let proof_identity_sha256 = composite_proof_identity(
        profile_identity_sha256,
        ordered_sources_sha256,
        ordered_receipt.program_sha256,
        aggregate_object_sha256,
        expected_multiplier,
        &source_proof_bindings,
    )
    .map_err(SharedUniformCaptureReducerAotCompileError::Authentication)?;
    let finalized = append_native_uniform_capture_reducer_to_count_aggregate(
        aggregate,
        operation,
        expected_multiplier,
        proof_identity_sha256,
        max_object_bytes,
    )
    .map_err(SharedUniformCaptureReducerAotCompileError::Finalization)?;
    let compiled = finalized.compiled;
    let reducer_symbol = finalized.reducer_symbol;
    let compiler = compiled.receipt();
    let receipt = SharedUniformCaptureReducerAotReceipt {
        schema_version: SHARED_UNIFORM_CAPTURE_REDUCER_AOT_RECEIPT_VERSION,
        rows: row_count,
        pattern_bytes,
        ordered_sources_sha256,
        profile_identity_sha256,
        source_proof_bindings_sha256: source_proof_bindings.into_boxed_slice(),
        source_proofs: source_proofs.into_boxed_slice(),
        operation,
        domain: operation.domain(),
        multiplier: expected_multiplier,
        proof_identity_sha256,
        program_sha256: compiler.program_sha256,
        aggregate_object_sha256,
        object_sha256: compiler.object_sha256,
        count_symbol_sha256: finalized.count_symbol_sha256,
        reducer_symbol_sha256: sha256(reducer_symbol.as_bytes()),
        target: compiler.target,
        line_terminator: compiler.line_terminator,
        aggregate_strategy: finalized.aggregate_strategy,
        required_prepare_capabilities: compiler.required_prepare_capabilities,
    };
    let artifact = SharedUniformCaptureReducerAotArtifact {
        compiled,
        profile,
        reducer_symbol,
        receipt,
    };
    artifact
        .authenticate()
        .map_err(SharedUniformCaptureReducerAotCompileError::Authentication)?;
    Ok(SharedUniformCaptureReducerAotCompileDisposition::Compiled(
        artifact,
    ))
}

#[allow(
    clippy::too_many_arguments,
    reason = "the ordered transaction binds each independent input identity"
)]
fn authenticate_ordered_transaction(
    expected_profile: &RustProfile,
    actual_profile: &RustProfile,
    rows: usize,
    pattern_bytes: usize,
    ordered_sources_sha256: [u8; 32],
    receipt: &OrderedManyAotReceipt,
    compiled: &CompiledRegex,
) -> Result<(), SharedUniformCaptureReducerAotCompileError> {
    if expected_profile != actual_profile
        || receipt.schema_version != ORDERED_MANY_AOT_RECEIPT_VERSION
        || receipt.rows != rows
        || receipt.pattern_bytes != pattern_bytes
        || receipt.ordered_sources_sha256 != ordered_sources_sha256
        || receipt.exports != PreparedAggregateExports::COUNT
        || receipt.program_sha256 != compiled.receipt().program_sha256
        || receipt.object_sha256 != compiled.receipt().object_sha256
        || receipt.object_sha256 != sha256(compiled.object())
        || Some(receipt.aggregate_strategy) != compiled.module().prepared_aggregate_strategy()
    {
        return Err(SharedUniformCaptureReducerAotCompileError::Authentication(
            SharedUniformCaptureReducerAotAuthenticationError::AggregateReceipt,
        ));
    }
    Ok(())
}

fn authenticate_final_aggregate(
    receipt: &SharedUniformCaptureReducerAotReceipt,
    compiled: &CompiledRegex,
    reducer_symbol: &str,
) -> Result<(), SharedUniformCaptureReducerAotAuthenticationError> {
    let compiler = compiled.receipt();
    let module = compiled.module();
    if compiler.program_sha256 != receipt.program_sha256
        || compiled.program().artifact_identity() != receipt.program_sha256
        || compiler.target != receipt.target
        || module.target() != receipt.target
        || compiler.line_terminator != receipt.line_terminator
        || compiled.program().line_terminator() != receipt.line_terminator
    {
        return Err(SharedUniformCaptureReducerAotAuthenticationError::AggregateReceipt);
    }
    if compiled.object().is_empty()
        || compiler.object_bytes != compiled.object().len()
        || compiler.object_sha256 != receipt.object_sha256
        || sha256(compiled.object()) != receipt.object_sha256
    {
        return Err(SharedUniformCaptureReducerAotAuthenticationError::ObjectIdentity);
    }
    let ordered = receipt.aggregate_strategy == PreparedAggregateStrategy::NativeOrderedNfaFused;
    if !matches!(
        receipt.aggregate_strategy,
        PreparedAggregateStrategy::NativeFused | PreparedAggregateStrategy::NativeOrderedNfaFused
    ) || compiler.prepared_aggregate_exports != PreparedAggregateExports::COUNT
        || module.prepared_aggregate_exports() != PreparedAggregateExports::COUNT
        || compiler.prepared_aggregate_strategy != Some(receipt.aggregate_strategy)
        || module.prepared_aggregate_strategy() != Some(receipt.aggregate_strategy)
        || compiler.required_prepare_capabilities != receipt.required_prepare_capabilities
        || module.required_prepare_capabilities() != receipt.required_prepare_capabilities
        || compiler.runtime_helper_required
        || module.required_runtime_symbols().next().is_some()
        || module
            .required_runtime_program()
            .is_none_or(|(_, bytes)| bytes == 0)
        || (ordered
            && (compiler.engine != EngineKind::OrderedNfa
                || compiler.entry_abi != EntryAbi::PreparedScalarReduceV1
                || module.prepared_bulk_strategy().is_some()
                || module.prepared_entry_symbol().is_some()
                || module.prepared_span_fill_symbol().is_some()
                || receipt.required_prepare_capabilities != PREPARED_CAPABILITY_ORDERED_NFA_V15))
        || (!ordered
            && (receipt.required_prepare_capabilities != 0
                || module.prepared_bulk_strategy().is_some()))
    {
        return Err(SharedUniformCaptureReducerAotAuthenticationError::AggregateRoute);
    }
    let count_symbol = module
        .prepared_count_symbol()
        .ok_or(SharedUniformCaptureReducerAotAuthenticationError::CountSymbol)?;
    if sha256(count_symbol.as_bytes()) != receipt.count_symbol_sha256
        || (ordered && count_symbol != module.entry_symbol())
    {
        return Err(SharedUniformCaptureReducerAotAuthenticationError::CountSymbol);
    }
    if sha256(reducer_symbol.as_bytes()) != receipt.reducer_symbol_sha256
        || reducer_symbol == count_symbol
        || reducer_symbol == module.entry_symbol()
    {
        return Err(SharedUniformCaptureReducerAotAuthenticationError::ReducerSymbol);
    }
    module
        .authenticate_native_uniform_capture_reducer(
            receipt.operation.native_domain(),
            receipt.multiplier.get(),
            receipt.program_sha256,
            receipt.proof_identity_sha256,
            reducer_symbol,
        )
        .map_err(|_| SharedUniformCaptureReducerAotAuthenticationError::NativeClosure)
}

fn source_proof_binding(
    row: usize,
    pattern_id: OrderedManyPatternId,
    source: &[u8],
    profile_identity_sha256: [u8; 32],
    proof: UniformCaptureParticipationReceipt,
) -> Result<[u8; 32], SharedUniformCaptureReducerAotCompileError> {
    let identity = proof.identity();
    let mut digest = Sha256::new();
    digest.update(b"fre-aot-regex/shared-uniform-capture-source-proof/v1\0");
    update_field(
        &mut digest,
        0,
        &to_u64(row, "proof source ordinal")?.to_le_bytes(),
    )?;
    update_field(&mut digest, 1, &pattern_id.get().to_le_bytes())?;
    update_field(&mut digest, 2, source)?;
    update_field(&mut digest, 3, &profile_identity_sha256)?;
    update_field(&mut digest, 4, &identity.algorithm_version().to_le_bytes())?;
    update_field(&mut digest, 5, &identity.accounting_version().to_le_bytes())?;
    update_field(
        &mut digest,
        6,
        &to_u64(proof.minimum_match_bytes().get(), "minimum match bytes")?.to_le_bytes(),
    )?;
    update_field(
        &mut digest,
        7,
        &to_u64(
            proof.participating_user_captures(),
            "participating captures",
        )?
        .to_le_bytes(),
    )?;
    update_field(
        &mut digest,
        8,
        &to_u64(
            proof.participating_groups_per_match().get(),
            "participating groups",
        )?
        .to_le_bytes(),
    )?;
    update_field(
        &mut digest,
        9,
        &to_u64(proof.canonical_capture_annotations(), "capture annotations")?.to_le_bytes(),
    )?;
    update_field(&mut digest, 10, &proof.work().to_le_bytes())?;
    update_field(
        &mut digest,
        11,
        &to_u64(proof.peak_stack_items(), "proof stack peak")?.to_le_bytes(),
    )?;
    Ok(digest.finalize().into())
}

fn composite_proof_identity(
    profile_identity_sha256: [u8; 32],
    ordered_sources_sha256: [u8; 32],
    program_sha256: [u8; 32],
    aggregate_object_sha256: [u8; 32],
    multiplier: NonZeroU64,
    source_bindings: &[[u8; 32]],
) -> Result<[u8; 32], SharedUniformCaptureReducerAotAuthenticationError> {
    let mut digest = Sha256::new();
    digest.update(b"fre-aot-regex/shared-uniform-capture-proof-binding/v1\0");
    update_auth_field(&mut digest, 0, &profile_identity_sha256)?;
    update_auth_field(&mut digest, 1, &ordered_sources_sha256)?;
    update_auth_field(&mut digest, 2, &program_sha256)?;
    update_auth_field(&mut digest, 3, &aggregate_object_sha256)?;
    update_auth_field(&mut digest, 4, &multiplier.get().to_le_bytes())?;
    let source_count = u64::try_from(source_bindings.len())
        .map_err(|_| SharedUniformCaptureReducerAotAuthenticationError::ProofBinding)?;
    update_auth_field(&mut digest, 5, &source_count.to_le_bytes())?;
    for (row, binding) in source_bindings.iter().enumerate() {
        let tag = u64::try_from(row)
            .ok()
            .and_then(|row| row.checked_add(6))
            .ok_or(SharedUniformCaptureReducerAotAuthenticationError::ProofBinding)?;
        update_auth_field(&mut digest, tag, binding)?;
    }
    Ok(digest.finalize().into())
}

fn precheck_source_envelope(
    request: &OrderedManyAotCompileRequest,
) -> Result<usize, SharedUniformCaptureReducerAotCompileError> {
    if request.rows.is_empty() {
        return Err(SharedUniformCaptureReducerAotCompileError::OrderedMany(
            OrderedManyAotCompileError::EmptyPatternSet,
        ));
    }
    if request.rows.len() > request.limits.max_rows {
        return Err(SharedUniformCaptureReducerAotCompileError::OrderedMany(
            OrderedManyAotCompileError::Planning(OrderedManyCompileError::RowsLimit {
                needed: request.rows.len(),
                limit: request.limits.max_rows,
            }),
        ));
    }
    let mut pattern_bytes = 0_usize;
    for (row, source) in request.rows.iter().enumerate() {
        pattern_bytes = pattern_bytes.checked_add(source.pattern().len()).ok_or(
            SharedUniformCaptureReducerAotCompileError::ArithmeticOverflow {
                computation: "source byte sum",
            },
        )?;
        if pattern_bytes > request.limits.max_pattern_bytes {
            return Err(SharedUniformCaptureReducerAotCompileError::OrderedMany(
                OrderedManyAotCompileError::Planning(OrderedManyCompileError::PatternBytesLimit {
                    row,
                    pattern_id: source.pattern_id(),
                    needed: pattern_bytes,
                    limit: request.limits.max_pattern_bytes,
                }),
            ));
        }
    }
    Ok(pattern_bytes)
}

fn update_field(
    digest: &mut Sha256,
    tag: u64,
    value: &[u8],
) -> Result<(), SharedUniformCaptureReducerAotCompileError> {
    let length = to_u64(value.len(), "proof field length")?;
    digest.update(tag.to_le_bytes());
    digest.update(length.to_le_bytes());
    digest.update(value);
    Ok(())
}

fn update_auth_field(
    digest: &mut Sha256,
    tag: u64,
    value: &[u8],
) -> Result<(), SharedUniformCaptureReducerAotAuthenticationError> {
    let length = u64::try_from(value.len())
        .map_err(|_| SharedUniformCaptureReducerAotAuthenticationError::ProofBinding)?;
    digest.update(tag.to_le_bytes());
    digest.update(length.to_le_bytes());
    digest.update(value);
    Ok(())
}

fn to_u64(
    value: usize,
    computation: &'static str,
) -> Result<u64, SharedUniformCaptureReducerAotCompileError> {
    u64::try_from(value)
        .map_err(|_| SharedUniformCaptureReducerAotCompileError::ArithmeticOverflow { computation })
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
