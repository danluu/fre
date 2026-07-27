//! Planner-disabled compiled facade for fixed-width Rust byte programs.

#![allow(
    clippy::large_enum_variant,
    clippy::result_large_err,
    reason = "authenticated refusal receipts and exact prospective accounting stay by value so failure paths never allocate"
)]

use core::{fmt, mem::size_of, ops::Range};

use fre_exact_alloc::ExactVec;
use fre_kernels::{
    ASCII_NARROW_BYTES, AsciiByteSet, AsciiSelection, DispatchPolicy, SimdDispatchContext,
    UnsupportedRequiredFeatures,
};
use fre_syntax::{
    CanonicalPattern, CompatibilityProfile, ParseError, ParseRequest, ParseSummary, RustProfile,
};
use regex_syntax::hir::{Class, ClassBytes, Hir, HirKind};

use super::{
    ACCOUNTING_ID, ACCOUNTING_VERSION, ALGORITHM_VERSION, HotByteAtom, HotByteProgram,
    HotByteProgramSet, HotKernelPreparationError, SlotAdmission, route_contract,
};
use crate::operation_session::receipt::{
    OPERATION_SESSION_ACCOUNTING_ID, OPERATION_SESSION_ACCOUNTING_VERSION,
    OPERATION_SESSION_ALGORITHM_VERSION,
};
use crate::operation_session::{
    OperationSession, OperationSessionAdmission, OperationSessionAttemptError,
    OperationSessionAttemptReceipt, OperationSessionAttemptRequest,
    OperationSessionConstructionLimits, OperationSessionError, OperationSessionInvocation,
    OperationSessionLeaf, OperationSessionReducer, OperationSessionResetLimits,
    OperationSessionRouteIdentity, OperationSessionRunLimits, OperationSessionTerminal,
};

/// Fixed-program compiler algorithm version.
pub const HOT_BYTE_PROGRAM_ALGORITHM_VERSION: u32 = 1;
/// Fixed-program compiler accounting version.
pub const HOT_BYTE_PROGRAM_ACCOUNTING_VERSION: u32 = 1;
/// Stable fixed-program compiler accounting identity.
pub const HOT_BYTE_PROGRAM_ACCOUNTING_ID: &str = "fre.hot-byte-program.facade.v1";
/// The receipt begins with an already-produced canonical HIR. Parser work,
/// allocations, and peak coexistence belong to the syntax owner.
pub(super) const HOT_BYTE_DESCRIPTOR_ACCOUNTING_BOUNDARY: &str =
    "fre.hot-byte-program.post-canonical-hir-descriptor.v1";

const PLAN_HASH_DOMAIN: &[u8] = b"fre.hot-byte-program.plan.v1";
// Building the reusable lookup performs 128 nibble-column membership probes,
// binds two narrow/wide leaves, and exposes two selection receipts. Static
// profiles reconstruct those receipts without per-classifier storage.
const CLASSIFIER_BUILD_WORK: u64 = 128 + 2 + 2;
const CLASSIFIER_BINDING_WORK: u64 = 4;
const DESCRIPTOR_ALLOCATION_WORK: u64 = 1;
const HARD_MAX_WORK: u64 = 64 * 1_048_576;
const HARD_MAX_PROGRAMS: usize = 4_096;
const HARD_MAX_ATOMS: usize = 65_536;
const HARD_MAX_ATOMS_PER_PROGRAM: usize = 4_096;
const HARD_MAX_LITERAL_BYTES: usize = 4 * 1_048_576;
const HARD_MAX_COMPARISON_WIDTH: usize = 8 * 1_048_576;

/// Construction-time dispatch policy for eligible ASCII class atoms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HotByteDispatch {
    /// Keep every class atom on the scalar leaf.
    Scalar,
    /// Retain one classifier selected from a single captured host snapshot for
    /// every ASCII class run wide enough to consume a fixed SIMD block.
    Runtime(DispatchPolicy),
}

impl Default for HotByteDispatch {
    fn default() -> Self {
        Self::Runtime(DispatchPolicy::Auto)
    }
}

/// Componentwise descriptor-construction policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HotByteBuildLimits {
    /// Maximum accounted descriptor proof and materialization work.
    pub max_work: u64,
    /// Maximum ordered fixed programs after structural expansion.
    pub max_programs: usize,
    /// Maximum total normalized atoms.
    pub max_atoms: usize,
    /// Maximum normalized atoms in one program.
    pub max_atoms_per_program: usize,
    /// Maximum aggregate literal bytes retained across expanded programs.
    pub max_literal_bytes: usize,
    /// Maximum aggregate comparison width across expanded programs.
    pub max_comparison_width: usize,
    /// Maximum exact persistent descriptor allocation bytes.
    pub max_persistent_bytes: usize,
    /// Maximum temporary descriptor scratch bytes.
    pub max_scratch_bytes: usize,
    /// Maximum descriptor construction peak bytes.
    pub max_peak_bytes: usize,
    /// Maximum exact descriptor allocation attempts.
    pub max_allocation_attempts: usize,
}

impl Default for HotByteBuildLimits {
    fn default() -> Self {
        Self {
            max_work: 16 * 1_048_576,
            max_programs: 4_096,
            max_atoms: 65_536,
            max_atoms_per_program: 4_096,
            max_literal_bytes: 4 * 1_048_576,
            max_comparison_width: 8 * 1_048_576,
            max_persistent_bytes: 16 * 1_048_576,
            max_scratch_bytes: 0,
            max_peak_bytes: 16 * 1_048_576,
            max_allocation_attempts: 131_073,
        }
    }
}

impl HotByteBuildLimits {
    /// Exact limits for one already-derived construction prospective.
    #[must_use]
    pub const fn exact(prospective: HotByteBuildAccounting) -> Self {
        Self {
            max_work: prospective.work,
            max_programs: prospective.programs,
            max_atoms: prospective.atoms,
            max_atoms_per_program: prospective.max_atoms_per_program,
            max_literal_bytes: prospective.literal_bytes,
            max_comparison_width: prospective.comparison_width,
            max_persistent_bytes: prospective.persistent_bytes,
            max_scratch_bytes: prospective.scratch_bytes,
            max_peak_bytes: prospective.peak_bytes,
            max_allocation_attempts: prospective.allocation_attempts,
        }
    }

    const fn first_refusal(
        self,
        prospective: HotByteBuildAccounting,
    ) -> Option<HotByteBuildResource> {
        if prospective.work > self.max_work {
            Some(HotByteBuildResource::Work)
        } else if prospective.programs > self.max_programs {
            Some(HotByteBuildResource::Programs)
        } else if prospective.atoms > self.max_atoms {
            Some(HotByteBuildResource::Atoms)
        } else if prospective.max_atoms_per_program > self.max_atoms_per_program {
            Some(HotByteBuildResource::AtomsPerProgram)
        } else if prospective.literal_bytes > self.max_literal_bytes {
            Some(HotByteBuildResource::LiteralBytes)
        } else if prospective.comparison_width > self.max_comparison_width {
            Some(HotByteBuildResource::ComparisonWidth)
        } else if prospective.persistent_bytes > self.max_persistent_bytes {
            Some(HotByteBuildResource::PersistentBytes)
        } else if prospective.scratch_bytes > self.max_scratch_bytes {
            Some(HotByteBuildResource::ScratchBytes)
        } else if prospective.peak_bytes > self.max_peak_bytes {
            Some(HotByteBuildResource::PeakBytes)
        } else if prospective.allocation_attempts > self.max_allocation_attempts {
            Some(HotByteBuildResource::AllocationAttempts)
        } else {
            None
        }
    }
}

/// First-refusal construction resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HotByteBuildResource {
    Work,
    Programs,
    Atoms,
    AtomsPerProgram,
    LiteralBytes,
    ComparisonWidth,
    PersistentBytes,
    ScratchBytes,
    PeakBytes,
    AllocationAttempts,
}

/// Structural reason a parsed Rust byte regex cannot use this forced route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HotByteIneligibility {
    /// Unicode syntax mode is outside the byte-program proof.
    UnicodeEnabled,
    /// A look assertion consumes no byte and requires surrounding context.
    LookAssertion,
    /// A Unicode scalar class is not a one-byte predicate.
    UnicodeClass,
    /// A byte class is empty and therefore has no successful program.
    EmptyByteClass,
    /// A repetition is variable-width or unbounded.
    VariableRepetition,
    /// At least one prioritized expansion can match an empty span.
    EmptyMatch,
}

/// Descriptor build failure before artifact publication.
#[derive(Debug)]
pub enum HotByteBuildError {
    Syntax(ParseError),
    Ineligible(HotByteIneligibility),
    Refused {
        resource: HotByteBuildResource,
        prospective: HotByteBuildAccounting,
    },
    StructuralCeiling {
        resource: HotByteBuildResource,
        observed: u128,
        maximum: u128,
    },
    ArithmeticOverflow,
    AllocationFailed {
        ordinal: usize,
    },
    Dispatch(UnsupportedRequiredFeatures),
    InternalInvariant(&'static str),
}

impl fmt::Display for HotByteBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(error) => write!(formatter, "hot byte syntax: {error}"),
            Self::Ineligible(reason) => {
                write!(
                    formatter,
                    "hot byte route is structurally ineligible: {reason:?}"
                )
            }
            Self::Refused { resource, .. } => {
                write!(
                    formatter,
                    "hot byte descriptor construction refused {resource:?}"
                )
            }
            Self::StructuralCeiling {
                resource,
                observed,
                maximum,
            } => write!(
                formatter,
                "hot byte descriptor structural ceiling {resource:?}: observed {observed}, maximum {maximum}"
            ),
            Self::ArithmeticOverflow => {
                formatter.write_str("hot byte descriptor construction arithmetic overflow")
            }
            Self::AllocationFailed { ordinal } => {
                write!(
                    formatter,
                    "hot byte descriptor exact allocation {ordinal} failed"
                )
            }
            Self::Dispatch(error) => write!(formatter, "hot byte SIMD dispatch: {error}"),
            Self::InternalInvariant(detail) => {
                write!(formatter, "hot byte internal invariant: {detail}")
            }
        }
    }
}

impl std::error::Error for HotByteBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Syntax(error) => Some(error),
            Self::Dispatch(error) => Some(error),
            _ => None,
        }
    }
}

/// Complete descriptor construction accounting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HotByteBuildAccounting {
    pub work: u64,
    pub hir_nodes: u64,
    pub programs: usize,
    pub atoms: usize,
    pub max_atoms_per_program: usize,
    pub literal_atoms: usize,
    pub literal_bytes: usize,
    pub class_ranges: usize,
    pub class_members: usize,
    pub comparison_width: usize,
    pub simd_classifiers: usize,
    pub persistent_bytes: usize,
    pub scratch_bytes: usize,
    pub peak_bytes: usize,
    pub initialized_bytes: usize,
    pub allocation_attempts: usize,
}

/// Closed descriptor construction evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HotByteBuildReceipt {
    algorithm_version: u32,
    accounting_version: u32,
    accounting_id: &'static str,
    accounting_boundary: &'static str,
    profile: RustProfile,
    dispatch: HotByteDispatch,
    limits: HotByteBuildLimits,
    syntax: ParseSummary,
    plan_id: [u8; 16],
    prospective: HotByteBuildAccounting,
    actual: HotByteBuildAccounting,
}

impl HotByteBuildReceipt {
    #[must_use]
    pub const fn accounting_boundary(&self) -> &'static str {
        self.accounting_boundary
    }

    #[must_use]
    pub const fn plan_id(&self) -> [u8; 16] {
        self.plan_id
    }

    #[must_use]
    pub const fn dispatch(&self) -> HotByteDispatch {
        self.dispatch
    }

    #[must_use]
    pub const fn limits(&self) -> HotByteBuildLimits {
        self.limits
    }

    #[must_use]
    pub const fn syntax(&self) -> &ParseSummary {
        &self.syntax
    }

    #[must_use]
    pub const fn prospective(&self) -> HotByteBuildAccounting {
        self.prospective
    }

    #[must_use]
    pub const fn actual(&self) -> HotByteBuildAccounting {
        self.actual
    }

    #[must_use]
    pub fn closes(&self) -> bool {
        self.algorithm_version == HOT_BYTE_PROGRAM_ALGORITHM_VERSION
            && self.accounting_version == HOT_BYTE_PROGRAM_ACCOUNTING_VERSION
            && self.accounting_id == HOT_BYTE_PROGRAM_ACCOUNTING_ID
            && self.accounting_boundary == HOT_BYTE_DESCRIPTOR_ACCOUNTING_BOUNDARY
            && !self.profile.options.unicode
            && self.plan_id != [0; 16]
            && self.prospective == self.actual
            && self.limits.first_refusal(self.prospective).is_none()
            && self.prospective.programs > 0
            && self.prospective.atoms >= self.prospective.programs
            && self.prospective.max_atoms_per_program > 0
            && self.prospective.comparison_width >= self.prospective.programs
            && self.prospective.scratch_bytes == 0
            && self.prospective.peak_bytes == self.prospective.persistent_bytes
            && self.prospective.initialized_bytes <= self.prospective.persistent_bytes
    }
}

/// Builder for one planner-disabled fixed byte-program artifact.
#[derive(Clone, Debug)]
pub struct HotByteProgramBuilder {
    pattern: String,
    profile: RustProfile,
    dispatch: HotByteDispatch,
    limits: HotByteBuildLimits,
}

impl HotByteProgramBuilder {
    #[must_use]
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            profile: RustProfile::rebar_1_12_4(),
            dispatch: HotByteDispatch::default(),
            limits: HotByteBuildLimits::default(),
        }
    }

    #[must_use]
    pub fn profile(mut self, profile: RustProfile) -> Self {
        self.profile = profile;
        self
    }

    #[must_use]
    pub fn unicode(mut self, enabled: bool) -> Self {
        self.profile.options.unicode = enabled;
        self
    }

    #[must_use]
    pub const fn dispatch(mut self, dispatch: HotByteDispatch) -> Self {
        self.dispatch = dispatch;
        self
    }

    #[must_use]
    pub const fn limits(mut self, limits: HotByteBuildLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Parse for convenience, then enter the explicitly post-canonical-HIR
    /// descriptor transaction.
    ///
    /// The returned receipt does not claim parser work, allocation, scratch,
    /// or peak bytes. Callers that need one encompassing construction receipt
    /// must retain the separate `fre-syntax` parse-attempt receipt.
    pub fn build(self) -> Result<HotByteProgramArtifact, HotByteBuildError> {
        self.build_with_allocation_fault(None)
    }

    fn build_with_allocation_fault(
        self,
        allocation_failure_ordinal: Option<usize>,
    ) -> Result<HotByteProgramArtifact, HotByteBuildError> {
        if self.profile.options.unicode {
            return Err(HotByteBuildError::Ineligible(
                HotByteIneligibility::UnicodeEnabled,
            ));
        }
        let dispatch_context = match self.dispatch {
            HotByteDispatch::Scalar => None,
            HotByteDispatch::Runtime(_) => Some(SimdDispatchContext::capture()),
        };
        let parsed = fre_syntax::parse(ParseRequest::rust(
            self.pattern,
            CompatibilityProfile::RustBytes(self.profile.clone()),
        ))
        .map_err(HotByteBuildError::Syntax)?;
        let syntax = parsed.summary;
        let CanonicalPattern::Rust(rust) = parsed.pattern else {
            return Err(HotByteBuildError::InternalInvariant(
                "Rust byte parse did not produce Rust HIR",
            ));
        };
        compile_hir(
            &rust.hir,
            self.profile,
            syntax,
            self.dispatch,
            dispatch_context,
            self.limits,
            allocation_failure_ordinal,
        )
    }
}

/// Immutable compiled fixed byte-program artifact.
#[derive(Debug)]
pub struct HotByteProgramArtifact {
    programs: ExactVec<HotByteProgram>,
    comparison_width: usize,
    atom_visits: usize,
    receipt: HotByteBuildReceipt,
}

impl HotByteProgramArtifact {
    #[must_use]
    pub const fn build_receipt(&self) -> &HotByteBuildReceipt {
        &self.receipt
    }

    #[must_use]
    pub const fn plan_id(&self) -> [u8; 16] {
        self.receipt.plan_id
    }

    #[must_use]
    pub const fn program_count(&self) -> usize {
        self.programs.len()
    }

    /// Return the retained one-time selection for one exact class atom.
    #[must_use]
    pub fn classifier_selection(
        &self,
        program_ordinal: usize,
        atom_ordinal: usize,
    ) -> Option<AsciiSelection> {
        self.programs
            .get(program_ordinal)?
            .atoms
            .get(atom_ordinal)?
            .selection()
    }

    /// Exact four-slot admission with only the hot workspace populated.
    #[must_use]
    pub const fn session_admission(&self) -> OperationSessionAdmission {
        OperationSessionAdmission {
            search: crate::operation_session::search::SlotAdmission {
                frontier_cells: 0,
                next_frontier_cells: 0,
                generation_cells: 0,
                candidate_cells: 0,
                cache_cells: 0,
                history_cells: 0,
            },
            hot: SlotAdmission {
                state_cells: self.programs.len(),
                generation_cells: 1,
                candidate_cells: self.programs.len(),
                cache_cells: 0,
                history_cells: 0,
            },
            multi_capture: crate::operation_session::multi_capture::SlotAdmission {
                frontier_cells: 0,
                next_frontier_cells: 0,
                generation_cells: 0,
                tagged_candidate_cells: 0,
                tagged_cache_cells: 0,
                history_cells: 0,
                participation_cells: 0,
            },
            grep: crate::operation_session::grep::SlotAdmission {
                line_state_cells: 0,
                generation_cells: 0,
                candidate_cells: 0,
                cache_cells: 0,
                history_cells: 0,
            },
        }
    }

    /// Allocate one caller-owned session at exact construction limits.
    pub fn new_session(&self) -> Result<OperationSession, OperationSessionError> {
        let admission = self.session_admission();
        let prospective = OperationSession::prospective(&admission)?;
        OperationSession::try_new(
            admission,
            OperationSessionConstructionLimits::exact(&prospective),
        )
    }

    /// Complete source-independent run envelope for one range.
    pub fn prospective(
        &self,
        range: Range<usize>,
    ) -> Result<
        crate::operation_session::OperationSessionExecutionProspective,
        HotKernelPreparationError,
    > {
        self.view().prospective(range)
    }

    /// Execute Count with exact reset and run limits.
    pub fn count(
        &self,
        session: &mut OperationSession,
        source: &[u8],
        range: Range<usize>,
    ) -> Result<OperationSessionAttemptReceipt, HotByteRunError> {
        self.execute_exact(session, source, range, OperationSessionReducer::Count)
    }

    /// Execute `SpanSum` with exact reset and run limits.
    pub fn span_sum(
        &self,
        session: &mut OperationSession,
        source: &[u8],
        range: Range<usize>,
    ) -> Result<OperationSessionAttemptReceipt, HotByteRunError> {
        self.execute_exact(session, source, range, OperationSessionReducer::SpanSum)
    }

    /// Execute with caller-supplied componentwise limits.
    pub fn execute_with_limits(
        &self,
        session: &mut OperationSession,
        source: &[u8],
        range: Range<usize>,
        reducer: OperationSessionReducer,
        limits: HotByteRunLimits,
    ) -> Result<OperationSessionAttemptReceipt, HotByteRunError> {
        let programs = self.view();
        let prospective = programs
            .prospective(range.clone())
            .map_err(HotByteRunError::Preparation)?;
        let (source_identity, order_identity, fallback_identity) = route_contract(reducer);
        let identity = OperationSessionRouteIdentity {
            session_accounting_id: OPERATION_SESSION_ACCOUNTING_ID,
            session_algorithm_version: OPERATION_SESSION_ALGORITHM_VERSION,
            session_accounting_version: OPERATION_SESSION_ACCOUNTING_VERSION,
            leaf: OperationSessionLeaf::Hot,
            reducer,
            compiled_plan_id: self.plan_id(),
            source_identity,
            order_identity,
            fallback_identity,
            leaf_algorithm_version: ALGORITHM_VERSION,
            leaf_accounting_version: ACCOUNTING_VERSION,
            leaf_accounting_id: ACCOUNTING_ID,
        };
        let request = OperationSessionAttemptRequest::new_trusted(
            identity,
            OperationSessionInvocation {
                haystack_len: source.len(),
                range,
                required_generations: 1,
            },
            prospective,
            limits.reset,
            limits.run,
            self.plan_id(),
        )
        .map_err(HotByteRunError::Request)?;
        let mut forced = session.forced_hot();
        let prepared = match reducer {
            OperationSessionReducer::Count => {
                forced.prepare_count_byte_programs(request, source, programs)
            }
            OperationSessionReducer::SpanSum => {
                forced.prepare_span_sum_byte_programs(request, source, programs)
            }
            OperationSessionReducer::Participation => {
                return Err(HotByteRunError::UnsupportedReducer);
            }
        }
        .map_err(HotByteRunError::Preparation)?;
        prepared.run().map_err(HotByteRunError::Attempt)
    }

    fn execute_exact(
        &self,
        session: &mut OperationSession,
        source: &[u8],
        range: Range<usize>,
        reducer: OperationSessionReducer,
    ) -> Result<OperationSessionAttemptReceipt, HotByteRunError> {
        let prospective = self
            .prospective(range.clone())
            .map_err(HotByteRunError::Preparation)?;
        let reset = session
            .reset_prospective(OperationSessionLeaf::Hot, 1)
            .map_err(HotByteRunError::Session)?;
        let reset = OperationSessionResetLimits::exact(&reset)
            .ok_or(HotByteRunError::ResetLimitOverflow)?;
        self.execute_with_limits(
            session,
            source,
            range,
            reducer,
            HotByteRunLimits {
                reset,
                run: OperationSessionRunLimits::exact(prospective),
            },
        )
    }

    fn view(&self) -> HotByteProgramSet<'_> {
        HotByteProgramSet::from_validated(
            self.plan_id(),
            self.programs.as_slice(),
            self.comparison_width,
            self.atom_visits,
        )
    }
}

/// Complete componentwise reset and execution limits for one call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HotByteRunLimits {
    pub reset: OperationSessionResetLimits,
    pub run: OperationSessionRunLimits,
}

/// Forced facade execution failure.
#[derive(Debug)]
pub enum HotByteRunError {
    Preparation(HotKernelPreparationError),
    Session(OperationSessionError),
    Request(OperationSessionTerminal),
    Attempt(OperationSessionAttemptError),
    ResetLimitOverflow,
    UnsupportedReducer,
}

impl fmt::Display for HotByteRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Preparation(error) => write!(formatter, "hot byte preparation: {error:?}"),
            Self::Session(error) => write!(formatter, "hot byte session: {error:?}"),
            Self::Request(terminal) => write!(formatter, "hot byte request: {terminal:?}"),
            Self::Attempt(error) => write!(formatter, "hot byte attempt: {error:?}"),
            Self::ResetLimitOverflow => {
                formatter.write_str("hot byte exact reset limit conversion overflow")
            }
            Self::UnsupportedReducer => {
                formatter.write_str("hot byte route supports only Count and SpanSum")
            }
        }
    }
}

impl std::error::Error for HotByteRunError {}

#[derive(Clone, Copy)]
enum BorrowedAtom<'a> {
    Literal(&'a [u8]),
    Class(&'a ClassBytes),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LastAtom {
    Literal,
    Class {
        membership: [u64; 4],
        repetitions: usize,
    },
}

#[derive(Default)]
struct ProgramStats {
    atoms: usize,
    literal_atoms: usize,
    literal_bytes: usize,
    class_ranges: usize,
    class_members: usize,
    width: usize,
    simd_classifiers: usize,
    last: Option<LastAtom>,
}

impl ProgramStats {
    fn observe(
        &mut self,
        atom: BorrowedAtom<'_>,
        dispatch: HotByteDispatch,
        meter: &mut WorkMeter,
    ) -> Result<(), HotByteBuildError> {
        match atom {
            BorrowedAtom::Literal(bytes) => {
                self.finish_last(dispatch, meter)?;
                meter.charge(1)?;
                meter.charge_usize(bytes.len())?;
                self.atoms = checked_add(self.atoms, 1)?;
                self.literal_atoms = checked_add(self.literal_atoms, 1)?;
                self.literal_bytes = checked_add(self.literal_bytes, bytes.len())?;
                self.width = checked_add(self.width, bytes.len())?;
                self.last = Some(LastAtom::Literal);
            }
            BorrowedAtom::Class(class) => {
                let (membership, ranges, members) = class_membership(class, meter)?;
                self.class_ranges = checked_add(self.class_ranges, ranges)?;
                self.class_members = checked_add(self.class_members, members)?;
                self.width = checked_add(self.width, 1)?;
                if let Some(LastAtom::Class {
                    membership: previous,
                    repetitions,
                }) = self.last
                {
                    if membership_equal(previous, membership, meter)? {
                        self.last = Some(LastAtom::Class {
                            membership,
                            repetitions: checked_add(repetitions, 1)?,
                        });
                    } else {
                        self.finish_last(dispatch, meter)?;
                        self.atoms = checked_add(self.atoms, 1)?;
                        self.last = Some(LastAtom::Class {
                            membership,
                            repetitions: 1,
                        });
                    }
                } else {
                    self.finish_last(dispatch, meter)?;
                    self.atoms = checked_add(self.atoms, 1)?;
                    self.last = Some(LastAtom::Class {
                        membership,
                        repetitions: 1,
                    });
                }
            }
        }
        Ok(())
    }

    fn finish(
        mut self,
        dispatch: HotByteDispatch,
        meter: &mut WorkMeter,
    ) -> Result<Self, HotByteBuildError> {
        self.finish_last(dispatch, meter)?;
        Ok(self)
    }

    fn finish_last(
        &mut self,
        dispatch: HotByteDispatch,
        meter: &mut WorkMeter,
    ) -> Result<(), HotByteBuildError> {
        if let Some(LastAtom::Class {
            membership,
            repetitions,
        }) = self.last
            && classifier_eligible(membership, repetitions, dispatch, meter)?
        {
            self.simd_classifiers = checked_add(self.simd_classifiers, 1)?;
        }
        Ok(())
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one transaction keeps exact analysis, first refusal, materialization, and receipt closure adjacent"
)]
fn compile_hir(
    hir: &Hir,
    profile: RustProfile,
    syntax: ParseSummary,
    dispatch: HotByteDispatch,
    dispatch_context: Option<SimdDispatchContext>,
    limits: HotByteBuildLimits,
    allocation_failure_ordinal: Option<usize>,
) -> Result<HotByteProgramArtifact, HotByteBuildError> {
    let mut analysis_meter = WorkMeter::with_hard_limit(HARD_MAX_WORK);
    let programs = expansion_count(hir, &mut analysis_meter)?;
    let expansion_work = analysis_meter.work;
    if programs == 0 {
        return Err(HotByteBuildError::Ineligible(
            HotByteIneligibility::EmptyByteClass,
        ));
    }
    let mut accounting = HotByteBuildAccounting {
        programs,
        hir_nodes: syntax.hir_nodes,
        ..HotByteBuildAccounting::default()
    };
    accounting.work = analysis_meter.work;
    enforce_hard_ceiling_usize(HotByteBuildResource::Programs, programs, HARD_MAX_PROGRAMS)?;
    let minimum_width = hir.properties().minimum_len().unwrap_or(0);
    let maximum_width = hir
        .properties()
        .maximum_len()
        .ok_or(HotByteBuildError::Ineligible(
            HotByteIneligibility::VariableRepetition,
        ))?;
    let comparison_lower_bound = checked_mul(minimum_width, programs)?;
    if maximum_width > HARD_MAX_COMPARISON_WIDTH
        || comparison_lower_bound > HARD_MAX_COMPARISON_WIDTH
    {
        let observed = u128::try_from(maximum_width.max(comparison_lower_bound))
            .map_err(|_| HotByteBuildError::ArithmeticOverflow)?;
        let maximum = u128::try_from(HARD_MAX_COMPARISON_WIDTH)
            .map_err(|_| HotByteBuildError::ArithmeticOverflow)?;
        return Err(HotByteBuildError::StructuralCeiling {
            resource: HotByteBuildResource::ComparisonWidth,
            observed,
            maximum,
        });
    }
    for ordinal in 0..programs {
        let mut stats = ProgramStats::default();
        visit_nth(hir, ordinal, &mut analysis_meter, &mut |atom, meter| {
            stats.observe(atom, dispatch, meter)
        })?;
        let stats = stats.finish(dispatch, &mut analysis_meter)?;
        if stats.atoms == 0 || stats.width == 0 {
            return Err(HotByteBuildError::Ineligible(
                HotByteIneligibility::EmptyMatch,
            ));
        }
        accounting.atoms = checked_add(accounting.atoms, stats.atoms)?;
        accounting.max_atoms_per_program = accounting.max_atoms_per_program.max(stats.atoms);
        accounting.literal_atoms = checked_add(accounting.literal_atoms, stats.literal_atoms)?;
        accounting.literal_bytes = checked_add(accounting.literal_bytes, stats.literal_bytes)?;
        accounting.class_ranges = checked_add(accounting.class_ranges, stats.class_ranges)?;
        accounting.class_members = checked_add(accounting.class_members, stats.class_members)?;
        accounting.comparison_width = checked_add(accounting.comparison_width, stats.width)?;
        accounting.simd_classifiers =
            checked_add(accounting.simd_classifiers, stats.simd_classifiers)?;
        accounting.work = analysis_meter.work;
        enforce_structural_hard_ceilings(accounting)?;
    }

    let program_table_bytes = checked_mul(programs, size_of::<HotByteProgram>())?;
    let atom_capacity = checked_mul(programs, accounting.max_atoms_per_program)?;
    let atom_storage_bytes = checked_mul(atom_capacity, size_of::<HotByteAtom>())?;
    accounting.persistent_bytes = checked_add(
        checked_add(
            checked_add(size_of::<HotByteProgramArtifact>(), program_table_bytes)?,
            atom_storage_bytes,
        )?,
        accounting.literal_bytes,
    )?;
    accounting.scratch_bytes = 0;
    accounting.peak_bytes = accounting.persistent_bytes;
    accounting.initialized_bytes = checked_add(
        checked_add(
            checked_add(size_of::<HotByteProgramArtifact>(), program_table_bytes)?,
            checked_mul(accounting.atoms, size_of::<HotByteAtom>())?,
        )?,
        accounting.literal_bytes,
    )?;
    accounting.allocation_attempts =
        checked_add(checked_add(1, programs)?, accounting.literal_atoms)?;

    let materialization_structural_work = analysis_meter
        .work
        .checked_sub(expansion_work)
        .ok_or(HotByteBuildError::ArithmeticOverflow)?;
    let descriptor_allocations = u64::try_from(accounting.allocation_attempts)
        .map_err(|_| HotByteBuildError::ArithmeticOverflow)?;
    let hash_work = plan_hash_work(accounting)?;
    accounting.work = analysis_meter
        .work
        .checked_add(materialization_structural_work)
        .and_then(|work| work.checked_add(descriptor_allocations * DESCRIPTOR_ALLOCATION_WORK))
        .and_then(|work| {
            work.checked_add(
                u64::try_from(accounting.atoms.checked_add(accounting.programs)?).ok()?,
            )
        })
        .and_then(|work| {
            work.checked_add(
                u64::try_from(accounting.simd_classifiers)
                    .ok()?
                    .checked_mul(CLASSIFIER_BUILD_WORK.checked_add(CLASSIFIER_BINDING_WORK)?)?,
            )
        })
        .and_then(|work| work.checked_add(hash_work))
        .ok_or(HotByteBuildError::ArithmeticOverflow)?;
    enforce_hard_ceiling_u64(HotByteBuildResource::Work, accounting.work, HARD_MAX_WORK)?;

    if let Some(resource) = limits.first_refusal(accounting) {
        return Err(HotByteBuildError::Refused {
            resource,
            prospective: accounting,
        });
    }

    let mut actual_meter = WorkMeter {
        work: analysis_meter.work,
        allocation_attempts: 0,
        hard_limit: Some(HARD_MAX_WORK),
        allocation_failure_ordinal,
    };
    let mut retained = allocate_exact(programs, &mut actual_meter)?;
    for ordinal in 0..programs {
        let mut atoms = allocate_exact(accounting.max_atoms_per_program, &mut actual_meter)?;
        let mut width = 0_usize;
        visit_nth(hir, ordinal, &mut actual_meter, &mut |atom, meter| {
            materialize_atom(&mut atoms, &mut width, atom, meter)
        })?;
        install_classifiers(&mut atoms, dispatch, dispatch_context, &mut actual_meter)?;
        actual_meter.charge_usize(atoms.len())?;
        let program = HotByteProgram::from_exact_atoms(atoms, width)
            .map_err(|_| HotByteBuildError::InternalInvariant("materialized program invalid"))?;
        retained
            .try_push(program)
            .unwrap_or_else(|_| unreachable!("program count was precomputed"));
    }
    let plan_id = structural_plan_id(retained.as_slice(), &mut actual_meter)?;
    actual_meter.charge_usize(retained.len())?;
    let validated = HotByteProgramSet::try_new(plan_id, retained.as_slice())
        .map_err(|_| HotByteBuildError::InternalInvariant("program set validation failed"))?;
    if validated.comparison_width != accounting.comparison_width
        || validated.atom_visits != accounting.atoms
    {
        return Err(HotByteBuildError::InternalInvariant(
            "program set validated totals differ from construction accounting",
        ));
    }
    if actual_meter.work != accounting.work {
        return Err(HotByteBuildError::InternalInvariant(
            "descriptor prospective and actual work differ",
        ));
    }
    if actual_meter.allocation_attempts != accounting.allocation_attempts {
        return Err(HotByteBuildError::InternalInvariant(
            "descriptor allocation-attempt accounting differs",
        ));
    }
    let actual = accounting;
    let receipt = HotByteBuildReceipt {
        algorithm_version: HOT_BYTE_PROGRAM_ALGORITHM_VERSION,
        accounting_version: HOT_BYTE_PROGRAM_ACCOUNTING_VERSION,
        accounting_id: HOT_BYTE_PROGRAM_ACCOUNTING_ID,
        accounting_boundary: HOT_BYTE_DESCRIPTOR_ACCOUNTING_BOUNDARY,
        profile,
        dispatch,
        limits,
        syntax,
        plan_id,
        prospective: accounting,
        actual,
    };
    if !receipt.closes() {
        return Err(HotByteBuildError::InternalInvariant(
            "descriptor construction receipt did not close",
        ));
    }
    Ok(HotByteProgramArtifact {
        comparison_width: validated.comparison_width,
        atom_visits: validated.atom_visits,
        programs: retained,
        receipt,
    })
}

fn expansion_count(hir: &Hir, meter: &mut WorkMeter) -> Result<usize, HotByteBuildError> {
    meter.charge(1)?;
    match hir.kind() {
        HirKind::Empty | HirKind::Literal(_) => Ok(1),
        HirKind::Class(Class::Bytes(class)) => {
            if class.ranges().is_empty() {
                Ok(0)
            } else {
                Ok(1)
            }
        }
        HirKind::Class(Class::Unicode(_)) => Err(HotByteBuildError::Ineligible(
            HotByteIneligibility::UnicodeClass,
        )),
        HirKind::Look(_) => Err(HotByteBuildError::Ineligible(
            HotByteIneligibility::LookAssertion,
        )),
        HirKind::Capture(capture) => expansion_count(&capture.sub, meter),
        HirKind::Concat(children) => {
            let mut count = 1_usize;
            for child in children {
                count = checked_mul(count, expansion_count(child, meter)?)?;
            }
            Ok(count)
        }
        HirKind::Alternation(children) => {
            let mut count = 0_usize;
            for child in children {
                count = checked_add(count, expansion_count(child, meter)?)?;
            }
            Ok(count)
        }
        HirKind::Repetition(repetition) => {
            if repetition.max != Some(repetition.min) {
                return Err(HotByteBuildError::Ineligible(
                    HotByteIneligibility::VariableRepetition,
                ));
            }
            let child = expansion_count(&repetition.sub, meter)?;
            checked_pow(
                child,
                usize::try_from(repetition.min)
                    .map_err(|_| HotByteBuildError::ArithmeticOverflow)?,
            )
        }
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "checked expansion counts and loop indices prove every suffix index, division, remainder, and copy offset"
)]
fn visit_nth<'a>(
    hir: &'a Hir,
    ordinal: usize,
    meter: &mut WorkMeter,
    emit: &mut impl FnMut(BorrowedAtom<'a>, &mut WorkMeter) -> Result<(), HotByteBuildError>,
) -> Result<(), HotByteBuildError> {
    meter.charge(1)?;
    match hir.kind() {
        HirKind::Empty => Ok(()),
        HirKind::Literal(literal) => emit(BorrowedAtom::Literal(&literal.0), meter),
        HirKind::Class(Class::Bytes(class)) => {
            if class.ranges().is_empty() {
                Err(HotByteBuildError::Ineligible(
                    HotByteIneligibility::EmptyByteClass,
                ))
            } else {
                emit(BorrowedAtom::Class(class), meter)
            }
        }
        HirKind::Class(Class::Unicode(_)) => Err(HotByteBuildError::Ineligible(
            HotByteIneligibility::UnicodeClass,
        )),
        HirKind::Look(_) => Err(HotByteBuildError::Ineligible(
            HotByteIneligibility::LookAssertion,
        )),
        HirKind::Capture(capture) => visit_nth(&capture.sub, ordinal, meter, emit),
        HirKind::Alternation(children) => {
            let mut remaining = ordinal;
            for child in children {
                let count = expansion_count(child, meter)?;
                if remaining < count {
                    return visit_nth(child, remaining, meter, emit);
                }
                remaining = remaining
                    .checked_sub(count)
                    .ok_or(HotByteBuildError::ArithmeticOverflow)?;
            }
            Err(HotByteBuildError::InternalInvariant(
                "alternation ordinal exceeds expansion count",
            ))
        }
        HirKind::Concat(children) => {
            let mut remaining = ordinal;
            for (index, child) in children.iter().enumerate() {
                let mut suffix = 1_usize;
                for later in &children[index + 1..] {
                    suffix = checked_mul(suffix, expansion_count(later, meter)?)?;
                }
                let child_count = expansion_count(child, meter)?;
                let child_ordinal = if suffix == 0 { 0 } else { remaining / suffix };
                if child_ordinal >= child_count {
                    return Err(HotByteBuildError::InternalInvariant(
                        "concat ordinal exceeds child expansion count",
                    ));
                }
                visit_nth(child, child_ordinal, meter, emit)?;
                if suffix != 0 {
                    remaining %= suffix;
                }
            }
            Ok(())
        }
        HirKind::Repetition(repetition) => {
            if repetition.max != Some(repetition.min) {
                return Err(HotByteBuildError::Ineligible(
                    HotByteIneligibility::VariableRepetition,
                ));
            }
            let copies = usize::try_from(repetition.min)
                .map_err(|_| HotByteBuildError::ArithmeticOverflow)?;
            let child_count = expansion_count(&repetition.sub, meter)?;
            let mut remaining = ordinal;
            for copy in 0..copies {
                let suffix = checked_pow(child_count, copies - copy - 1)?;
                let child_ordinal = if suffix == 0 { 0 } else { remaining / suffix };
                if child_ordinal >= child_count {
                    return Err(HotByteBuildError::InternalInvariant(
                        "repetition ordinal exceeds child expansion count",
                    ));
                }
                visit_nth(&repetition.sub, child_ordinal, meter, emit)?;
                if suffix != 0 {
                    remaining %= suffix;
                }
            }
            Ok(())
        }
    }
}

fn materialize_atom(
    atoms: &mut ExactVec<HotByteAtom>,
    width: &mut usize,
    atom: BorrowedAtom<'_>,
    meter: &mut WorkMeter,
) -> Result<(), HotByteBuildError> {
    match atom {
        BorrowedAtom::Literal(bytes) => {
            meter.charge(1)?;
            meter.charge_usize(bytes.len())?;
            let mut retained = allocate_exact(bytes.len(), meter)?;
            for byte in bytes {
                retained
                    .try_push(*byte)
                    .unwrap_or_else(|_| unreachable!("literal capacity was precomputed"));
            }
            let width_increment = retained.len();
            atoms
                .try_push(
                    HotByteAtom::literal(retained)
                        .map_err(|_| HotByteBuildError::InternalInvariant("empty literal atom"))?,
                )
                .unwrap_or_else(|_| unreachable!("normalized atom bound was precomputed"));
            *width = checked_add(*width, width_increment)?;
        }
        BorrowedAtom::Class(class) => {
            let (membership, _, _) = class_membership(class, meter)?;
            *width = checked_add(*width, 1)?;
            let coalesced = if let Some(HotByteAtom::ByteClass {
                membership: previous,
                repetitions,
                ..
            }) = atoms.as_mut_slice().last_mut()
            {
                if membership_equal(*previous, membership, meter)? {
                    *repetitions = checked_add(*repetitions, 1)?;
                    true
                } else {
                    false
                }
            } else {
                false
            };
            if coalesced {
                return Ok(());
            }
            atoms
                .try_push(HotByteAtom::byte_class(membership, 1, None).map_err(|_| {
                    HotByteBuildError::InternalInvariant("invalid scalar class atom")
                })?)
                .unwrap_or_else(|_| unreachable!("normalized atom bound was precomputed"));
        }
    }
    Ok(())
}

fn install_classifiers(
    atoms: &mut ExactVec<HotByteAtom>,
    dispatch: HotByteDispatch,
    context: Option<SimdDispatchContext>,
    meter: &mut WorkMeter,
) -> Result<(), HotByteBuildError> {
    for atom in atoms.as_mut_slice() {
        let HotByteAtom::ByteClass {
            membership,
            repetitions,
            classifier: _,
        } = atom
        else {
            continue;
        };
        if !classifier_eligible(*membership, *repetitions, dispatch, meter)? {
            continue;
        }
        meter.charge(CLASSIFIER_BUILD_WORK)?;
        let HotByteDispatch::Runtime(policy) = dispatch else {
            unreachable!("scalar dispatch is never classifier eligible");
        };
        let context = context.ok_or(HotByteBuildError::InternalInvariant(
            "runtime dispatch lost its captured context",
        ))?;
        let selected = context
            .ascii_byte_set_classifier(
                AsciiByteSet::from_words([membership[0], membership[1]]),
                policy,
            )
            .map_err(HotByteBuildError::Dispatch)?;
        // Charge the constructor's two ASCII-upper-word checks and two exact
        // low-word set-binding comparisons separately from selection work.
        meter.charge(4)?;
        *atom =
            HotByteAtom::byte_class(*membership, *repetitions, Some(selected)).map_err(|_| {
                HotByteBuildError::InternalInvariant("classifier membership binding failed")
            })?;
    }
    Ok(())
}

fn classifier_eligible(
    membership: [u64; 4],
    repetitions: usize,
    dispatch: HotByteDispatch,
    meter: &mut WorkMeter,
) -> Result<bool, HotByteBuildError> {
    // Evaluate and charge all four gates without data-dependent
    // short-circuiting so prospective and actual work are identical.
    meter.charge(4)?;
    let runtime = matches!(dispatch, HotByteDispatch::Runtime(_));
    let wide_enough = repetitions >= ASCII_NARROW_BYTES;
    let upper_two_empty = membership[2] == 0;
    let upper_three_empty = membership[3] == 0;
    Ok(runtime && wide_enough && upper_two_empty && upper_three_empty)
}

fn membership_equal(
    left: [u64; 4],
    right: [u64; 4],
    meter: &mut WorkMeter,
) -> Result<bool, HotByteBuildError> {
    meter.charge(4)?;
    let word0 = left[0] == right[0];
    let word1 = left[1] == right[1];
    let word2 = left[2] == right[2];
    let word3 = left[3] == right[3];
    Ok(word0 && word1 && word2 && word3)
}

fn class_membership(
    class: &ClassBytes,
    meter: &mut WorkMeter,
) -> Result<([u64; 4], usize, usize), HotByteBuildError> {
    let mut membership = [0_u64; 4];
    let mut ranges = 0_usize;
    let mut members = 0_usize;
    for range in class.ranges() {
        meter.charge(1)?;
        ranges = checked_add(ranges, 1)?;
        for byte in range.start()..=range.end() {
            meter.charge(1)?;
            members = checked_add(members, 1)?;
            let index = usize::from(byte);
            membership[index >> 6] |= 1_u64 << (index & 63);
        }
    }
    Ok((membership, ranges, members))
}

fn plan_hash_work(accounting: HotByteBuildAccounting) -> Result<u64, HotByteBuildError> {
    let class_atoms = accounting
        .atoms
        .checked_sub(accounting.literal_atoms)
        .ok_or(HotByteBuildError::ArithmeticOverflow)?;
    let bytes = PLAN_HASH_DOMAIN
        .len()
        .checked_add(size_of::<usize>())
        .and_then(|value| {
            value.checked_add(
                accounting
                    .programs
                    .checked_mul(2_usize.checked_mul(size_of::<usize>())?)?,
            )
        })
        .and_then(|value| value.checked_add(accounting.atoms))
        .and_then(|value| value.checked_add(accounting.literal_bytes))
        .and_then(|value| {
            value.checked_add(
                class_atoms.checked_mul(
                    4_usize
                        .checked_mul(size_of::<u64>())?
                        .checked_add(size_of::<usize>())?,
                )?,
            )
        })
        .ok_or(HotByteBuildError::ArithmeticOverflow)?;
    u64::try_from(bytes).map_err(|_| HotByteBuildError::ArithmeticOverflow)
}

fn structural_plan_id(
    programs: &[HotByteProgram],
    meter: &mut WorkMeter,
) -> Result<[u8; 16], HotByteBuildError> {
    let mut hash = PlanHash::new();
    hash.update(PLAN_HASH_DOMAIN, meter)?;
    hash.update_usize(programs.len(), meter)?;
    for program in programs {
        hash.update_usize(program.width, meter)?;
        hash.update_usize(program.atom_count, meter)?;
        for atom in &program.atoms {
            match atom {
                HotByteAtom::Literal(bytes) => {
                    hash.update(&[0], meter)?;
                    hash.update(bytes, meter)?;
                }
                HotByteAtom::ByteClass {
                    membership,
                    repetitions,
                    ..
                } => {
                    hash.update(&[1], meter)?;
                    for word in membership {
                        hash.update(&word.to_le_bytes(), meter)?;
                    }
                    hash.update_usize(*repetitions, meter)?;
                }
            }
        }
    }
    Ok(hash.finish())
}

#[derive(Default)]
struct WorkMeter {
    work: u64,
    allocation_attempts: usize,
    hard_limit: Option<u64>,
    allocation_failure_ordinal: Option<usize>,
}

impl WorkMeter {
    const fn with_hard_limit(hard_limit: u64) -> Self {
        Self {
            work: 0,
            allocation_attempts: 0,
            hard_limit: Some(hard_limit),
            allocation_failure_ordinal: None,
        }
    }

    fn charge(&mut self, amount: u64) -> Result<(), HotByteBuildError> {
        let next = self
            .work
            .checked_add(amount)
            .ok_or(HotByteBuildError::ArithmeticOverflow)?;
        if self.hard_limit.is_some_and(|limit| next > limit) {
            return Err(HotByteBuildError::StructuralCeiling {
                resource: HotByteBuildResource::Work,
                observed: u128::from(next),
                maximum: u128::from(self.hard_limit.unwrap_or(u64::MAX)),
            });
        }
        self.work = next;
        Ok(())
    }

    fn charge_usize(&mut self, amount: usize) -> Result<(), HotByteBuildError> {
        self.charge(u64::try_from(amount).map_err(|_| HotByteBuildError::ArithmeticOverflow)?)
    }
}

fn enforce_hard_ceiling_u64(
    resource: HotByteBuildResource,
    observed: u64,
    maximum: u64,
) -> Result<(), HotByteBuildError> {
    if observed > maximum {
        Err(HotByteBuildError::StructuralCeiling {
            resource,
            observed: u128::from(observed),
            maximum: u128::from(maximum),
        })
    } else {
        Ok(())
    }
}

fn enforce_hard_ceiling_usize(
    resource: HotByteBuildResource,
    observed: usize,
    maximum: usize,
) -> Result<(), HotByteBuildError> {
    if observed > maximum {
        Err(HotByteBuildError::StructuralCeiling {
            resource,
            observed: u128::try_from(observed)
                .map_err(|_| HotByteBuildError::ArithmeticOverflow)?,
            maximum: u128::try_from(maximum).map_err(|_| HotByteBuildError::ArithmeticOverflow)?,
        })
    } else {
        Ok(())
    }
}

fn enforce_structural_hard_ceilings(
    observed: HotByteBuildAccounting,
) -> Result<(), HotByteBuildError> {
    enforce_hard_ceiling_usize(HotByteBuildResource::Atoms, observed.atoms, HARD_MAX_ATOMS)?;
    enforce_hard_ceiling_usize(
        HotByteBuildResource::AtomsPerProgram,
        observed.max_atoms_per_program,
        HARD_MAX_ATOMS_PER_PROGRAM,
    )?;
    enforce_hard_ceiling_usize(
        HotByteBuildResource::LiteralBytes,
        observed.literal_bytes,
        HARD_MAX_LITERAL_BYTES,
    )?;
    enforce_hard_ceiling_usize(
        HotByteBuildResource::ComparisonWidth,
        observed.comparison_width,
        HARD_MAX_COMPARISON_WIDTH,
    )
}

fn allocate_exact<T>(
    capacity: usize,
    meter: &mut WorkMeter,
) -> Result<ExactVec<T>, HotByteBuildError> {
    meter.charge(DESCRIPTOR_ALLOCATION_WORK)?;
    meter.allocation_attempts = checked_add(meter.allocation_attempts, 1)?;
    let ordinal = meter.allocation_attempts;
    if meter.allocation_failure_ordinal == Some(ordinal) {
        return Err(HotByteBuildError::AllocationFailed { ordinal });
    }
    ExactVec::try_with_capacity(capacity)
        .map_err(|_| HotByteBuildError::AllocationFailed { ordinal })
}

struct PlanHash {
    first: u64,
    second: u64,
}

impl PlanHash {
    const fn new() -> Self {
        Self {
            first: 0xcbf2_9ce4_8422_2325,
            second: 0x8422_2325_cbf2_9ce4,
        }
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the plan identity deliberately uses wrapping fixed-width mixing"
    )]
    fn update(&mut self, bytes: &[u8], meter: &mut WorkMeter) -> Result<(), HotByteBuildError> {
        meter.charge_usize(bytes.len())?;
        for byte in bytes {
            self.first ^= u64::from(*byte);
            self.first = self.first.wrapping_mul(0x0000_0100_0000_01b3);
            self.second ^= u64::from(*byte).wrapping_add(self.first.rotate_left(17));
            self.second = self.second.wrapping_mul(0x9e37_79b1_85eb_ca87);
        }
        Ok(())
    }

    fn update_usize(
        &mut self,
        value: usize,
        meter: &mut WorkMeter,
    ) -> Result<(), HotByteBuildError> {
        self.update(&value.to_le_bytes(), meter)
    }

    fn finish(self) -> [u8; 16] {
        let mut output = [0_u8; 16];
        output[..8].copy_from_slice(&self.first.to_le_bytes());
        output[8..].copy_from_slice(&self.second.to_le_bytes());
        if output == [0; 16] {
            output[0] = 1;
        }
        output
    }
}

fn checked_add(left: usize, right: usize) -> Result<usize, HotByteBuildError> {
    left.checked_add(right)
        .ok_or(HotByteBuildError::ArithmeticOverflow)
}

fn checked_mul(left: usize, right: usize) -> Result<usize, HotByteBuildError> {
    left.checked_mul(right)
        .ok_or(HotByteBuildError::ArithmeticOverflow)
}

fn checked_pow(mut base: usize, mut exponent: usize) -> Result<usize, HotByteBuildError> {
    let mut value = 1_usize;
    while exponent != 0 {
        if exponent & 1 != 0 {
            value = checked_mul(value, base)?;
        }
        exponent >>= 1;
        if exponent != 0 {
            base = checked_mul(base, base)?;
        }
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operation_session::{OperationSessionAttemptReceipt, OperationSessionValue};
    #[cfg(not(feature = "static-dispatch"))]
    use fre_kernels::{Feature, FeatureSet};

    const SIMD_PATTERN: &str = r"[ab]{16}xy";
    type LimitLowerer = (HotByteBuildResource, fn(&mut HotByteBuildLimits));

    fn profile(dot_matches_new_line: bool) -> RustProfile {
        // The pinned Rebar constructor fixes dot-newline off. Use the honest
        // high-level RegexBuilder identity only for the dot-newline-on
        // adversary; all other cases retain the exact Rebar profile.
        let mut profile = if dot_matches_new_line {
            RustProfile::regex_1_12_4()
        } else {
            RustProfile::rebar_1_12_4()
        };
        profile.options.unicode = false;
        profile.options.dot_matches_new_line = dot_matches_new_line;
        profile
    }

    fn builder(pattern: &str, dispatch: HotByteDispatch) -> HotByteProgramBuilder {
        HotByteProgramBuilder::new(pattern)
            .profile(profile(false))
            .dispatch(dispatch)
    }

    fn reference(
        pattern: &str,
        profile: &RustProfile,
        source: &[u8],
        range: Range<usize>,
    ) -> (u64, u64) {
        let mut builder = regex::bytes::RegexBuilder::new(pattern);
        builder
            .case_insensitive(profile.options.case_insensitive)
            .multi_line(profile.options.multi_line)
            .dot_matches_new_line(profile.options.dot_matches_new_line)
            .crlf(profile.options.crlf)
            .line_terminator(profile.options.line_terminator)
            .swap_greed(profile.options.swap_greed)
            .ignore_whitespace(profile.options.ignore_whitespace)
            .unicode(profile.options.unicode)
            .octal(profile.options.octal)
            .nest_limit(profile.options.nest_limit);
        let regex = builder.build().expect("reference regex");
        let mut count = 0_u64;
        let mut span_sum = 0_u64;
        for selected in regex.find_iter(&source[range]) {
            count = count.checked_add(1).expect("small reference count");
            span_sum = span_sum
                .checked_add(u64::try_from(selected.len()).expect("small reference span"))
                .expect("small reference span sum");
        }
        (count, span_sum)
    }

    fn execute_both(
        artifact: &HotByteProgramArtifact,
        source: &[u8],
        range: Range<usize>,
    ) -> (
        OperationSessionAttemptReceipt,
        OperationSessionAttemptReceipt,
    ) {
        let mut count_session = artifact.new_session().expect("exact count session");
        let count = artifact
            .count(&mut count_session, source, range.clone())
            .expect("count execution");
        let mut span_session = artifact.new_session().expect("exact span session");
        let span = artifact
            .span_sum(&mut span_session, source, range)
            .expect("span-sum execution");
        assert!(count.closes());
        assert!(span.closes());
        assert_eq!(count.actual.allocations, 0);
        assert_eq!(span.actual.allocations, 0);
        (count, span)
    }

    fn assert_semantics(
        pattern: &str,
        profile: RustProfile,
        dispatch: HotByteDispatch,
        source: &[u8],
        range: Range<usize>,
    ) {
        let expected = reference(pattern, &profile, source, range.clone());
        let artifact = HotByteProgramBuilder::new(pattern)
            .profile(profile)
            .dispatch(dispatch)
            .build()
            .expect("hot-byte artifact");
        let (count, span) = execute_both(&artifact, source, range);
        assert_eq!(count.value, Some(OperationSessionValue::Count(expected.0)));
        assert_eq!(span.value, Some(OperationSessionValue::SpanSum(expected.1)));
    }

    const fn compatible_test_policy() -> DispatchPolicy {
        #[cfg(feature = "static-dispatch")]
        {
            DispatchPolicy::Auto
        }
        #[cfg(not(feature = "static-dispatch"))]
        {
            DispatchPolicy::Portable
        }
    }

    #[test]
    fn facade_preserves_priority_cartesian_expansion_lf_and_malformed_bytes() {
        let _guard = super::super::hot_kernel_test_guard();
        let first_short = format!("(?:{}|{}b)", "a".repeat(16), "a".repeat(16));
        let first_short_source = format!("{}b", "a".repeat(16));
        assert_semantics(
            &first_short,
            profile(false),
            HotByteDispatch::Runtime(compatible_test_policy()),
            first_short_source.as_bytes(),
            0..first_short_source.len(),
        );

        let cartesian = r"(?:[ab]{16}|[cd]{16}q)(?:x|yz)";
        let source = b"aaaaaaaaaaaaaaaax ccccccccccccccccqyz";
        assert_semantics(
            cartesian,
            profile(false),
            HotByteDispatch::Runtime(compatible_test_policy()),
            source,
            0..source.len(),
        );

        let dot_source = b"aaaaaaa\naaaaaaaa";
        assert_semantics(
            r".{16}",
            profile(false),
            HotByteDispatch::Runtime(compatible_test_policy()),
            dot_source,
            0..dot_source.len(),
        );
        assert_semantics(
            r".{16}",
            profile(true),
            HotByteDispatch::Runtime(compatible_test_policy()),
            dot_source,
            0..dot_source.len(),
        );

        let malformed = [0xff_u8; 16];
        let scalar_non_ascii = builder(
            r"[\x80-\xFF]{16}",
            HotByteDispatch::Runtime(compatible_test_policy()),
        )
        .build()
        .expect("non-ASCII scalar artifact");
        assert_eq!(
            scalar_non_ascii.build_receipt().actual().simd_classifiers,
            0
        );
        let expected = reference(
            r"[\x80-\xFF]{16}",
            &profile(false),
            &malformed,
            0..malformed.len(),
        );
        let (count, span) = execute_both(&scalar_non_ascii, &malformed, 0..malformed.len());
        assert_eq!(count.value, Some(OperationSessionValue::Count(expected.0)));
        assert_eq!(span.value, Some(OperationSessionValue::SpanSum(expected.1)));
    }

    #[cfg(not(feature = "static-dispatch"))]
    #[test]
    fn scalar_portable_and_auto_match_at_simd_boundaries_and_unaligned_ranges() {
        let _guard = super::super::hot_kernel_test_guard();
        for width in [15_usize, 16, 31, 32, 33] {
            let pattern = format!(r"[ab]{{{width}}}");
            let source = vec![b'a'; width];
            for dispatch in [
                HotByteDispatch::Scalar,
                HotByteDispatch::Runtime(DispatchPolicy::Portable),
                HotByteDispatch::Runtime(DispatchPolicy::Auto),
            ] {
                assert_semantics(&pattern, profile(false), dispatch, &source, 0..source.len());
            }
        }

        let mut unaligned = vec![b'x'];
        unaligned.extend_from_slice(&[b'a'; 33]);
        for dispatch in [
            HotByteDispatch::Scalar,
            HotByteDispatch::Runtime(DispatchPolicy::Portable),
            HotByteDispatch::Runtime(DispatchPolicy::Auto),
        ] {
            assert_semantics(
                r"[ab]{33}",
                profile(false),
                dispatch,
                &unaligned,
                1..unaligned.len(),
            );
        }

        let portable = builder(
            r"[ab]{16}",
            HotByteDispatch::Runtime(DispatchPolicy::Portable),
        )
        .build()
        .expect("portable classifier");
        let selection = portable
            .classifier_selection(0, 0)
            .expect("retained classifier selection");
        assert_eq!(selection.narrow().policy, DispatchPolicy::Portable);
        assert_eq!(selection.wide().policy, DispatchPolicy::Portable);

        let auto = builder(r"[ab]{32}", HotByteDispatch::Runtime(DispatchPolicy::Auto))
            .build()
            .expect("auto classifier");
        let auto_selection = auto.classifier_selection(0, 0).expect("auto selection");
        let selected_features = auto_selection
            .narrow()
            .required
            .union(auto_selection.wide().required);
        for policy in [
            DispatchPolicy::AllowOnly(selected_features),
            DispatchPolicy::Require(selected_features),
        ] {
            let artifact = builder(r"[ab]{32}", HotByteDispatch::Runtime(policy))
                .build()
                .expect("host-selected feature policy");
            assert!(artifact.classifier_selection(0, 0).is_some());
        }

        let unsupported = if cfg!(target_arch = "x86_64") {
            Feature::ArmNeon
        } else {
            Feature::X86Sse2
        };
        let error = builder(
            r"[ab]{32}",
            HotByteDispatch::Runtime(DispatchPolicy::Require(FeatureSet::of(unsupported))),
        )
        .build()
        .expect_err("opposite-architecture feature is unavailable");
        assert!(matches!(error, HotByteBuildError::Dispatch(_)));
    }

    #[test]
    fn construction_receipt_is_exact_and_every_one_below_limit_is_complete() {
        let _guard = super::super::hot_kernel_test_guard();
        let artifact = builder(
            SIMD_PATTERN,
            HotByteDispatch::Runtime(compatible_test_policy()),
        )
        .build()
        .expect("baseline construction");
        let prospective = artifact.build_receipt().prospective();
        assert_eq!(prospective, artifact.build_receipt().actual());
        assert_eq!(prospective.programs, 1);
        assert_eq!(prospective.atoms, 2);
        assert_eq!(prospective.max_atoms_per_program, 2);
        assert_eq!(prospective.literal_atoms, 1);
        assert_eq!(prospective.literal_bytes, 2);
        assert_eq!(prospective.class_ranges, 16);
        assert_eq!(prospective.class_members, 32);
        assert_eq!(prospective.comparison_width, 18);
        assert_eq!(prospective.simd_classifiers, 1);
        assert_eq!(prospective.allocation_attempts, 3);
        assert!(artifact.build_receipt().closes());

        let exact = HotByteBuildLimits::exact(prospective);
        let cases: [LimitLowerer; 9] = [
            (HotByteBuildResource::Work, |limits| limits.max_work -= 1),
            (HotByteBuildResource::Programs, |limits| {
                limits.max_programs -= 1;
            }),
            (HotByteBuildResource::Atoms, |limits| limits.max_atoms -= 1),
            (HotByteBuildResource::AtomsPerProgram, |limits| {
                limits.max_atoms_per_program -= 1;
            }),
            (HotByteBuildResource::LiteralBytes, |limits| {
                limits.max_literal_bytes -= 1;
            }),
            (HotByteBuildResource::ComparisonWidth, |limits| {
                limits.max_comparison_width -= 1;
            }),
            (HotByteBuildResource::PersistentBytes, |limits| {
                limits.max_persistent_bytes -= 1;
            }),
            (HotByteBuildResource::PeakBytes, |limits| {
                limits.max_peak_bytes -= 1;
            }),
            (HotByteBuildResource::AllocationAttempts, |limits| {
                limits.max_allocation_attempts -= 1;
            }),
        ];
        for (expected_resource, lower) in cases {
            let mut one_below = exact;
            lower(&mut one_below);
            let error = builder(
                SIMD_PATTERN,
                HotByteDispatch::Runtime(compatible_test_policy()),
            )
            .limits(one_below)
            .build()
            .expect_err("one-below construction must refuse");
            match error {
                HotByteBuildError::Refused {
                    resource,
                    prospective: refused,
                } => {
                    assert_eq!(resource, expected_resource);
                    assert_eq!(refused, prospective);
                }
                other => panic!("unexpected one-below result: {other:?}"),
            }
        }
    }

    #[test]
    fn classifier_build_charges_132_plus_separate_four_word_binding_proof() {
        let _guard = super::super::hot_kernel_test_guard();
        let scalar = builder(SIMD_PATTERN, HotByteDispatch::Scalar)
            .build()
            .expect("scalar baseline");
        let runtime = builder(
            SIMD_PATTERN,
            HotByteDispatch::Runtime(compatible_test_policy()),
        )
        .build()
        .expect("runtime classifier");
        assert_eq!(scalar.build_receipt().actual().simd_classifiers, 0);
        assert_eq!(runtime.build_receipt().actual().simd_classifiers, 1);
        let added = runtime
            .build_receipt()
            .actual()
            .work
            .checked_sub(scalar.build_receipt().actual().work)
            .expect("runtime work includes scalar proof");
        assert_eq!(
            added,
            CLASSIFIER_BUILD_WORK + CLASSIFIER_BINDING_WORK,
            "classifier construction and descriptor binding are distinct"
        );
        assert_eq!(added - CLASSIFIER_BINDING_WORK, 132);

        let prospective = runtime.build_receipt().prospective();
        let mut one_below = HotByteBuildLimits::exact(prospective);
        one_below.max_work -= 1;
        match builder(
            SIMD_PATTERN,
            HotByteDispatch::Runtime(compatible_test_policy()),
        )
        .limits(one_below)
        .build()
        .expect_err("one-below classifier construction work refuses")
        {
            HotByteBuildError::Refused {
                resource: HotByteBuildResource::Work,
                prospective: refused,
            } => assert_eq!(refused, prospective),
            other => panic!("unexpected classifier work refusal: {other:?}"),
        }
    }

    #[test]
    fn low_configurable_limit_refusal_contains_the_complete_prospective() {
        let _guard = super::super::hot_kernel_test_guard();
        let pattern = r"(?:[ab]{16}|[cd]{16})";
        let baseline = builder(pattern, HotByteDispatch::Runtime(compatible_test_policy()))
            .build()
            .expect("two-program baseline");
        let complete = baseline.build_receipt().prospective();
        let mut limits = HotByteBuildLimits::exact(complete);
        limits.max_programs = 1;
        match builder(pattern, HotByteDispatch::Runtime(compatible_test_policy()))
            .limits(limits)
            .build()
            .expect_err("program limit refuses")
        {
            HotByteBuildError::Refused {
                resource: HotByteBuildResource::Programs,
                prospective,
            } => assert_eq!(prospective, complete),
            other => panic!("unexpected complete-limit result: {other:?}"),
        }
    }

    #[test]
    fn every_exact_descriptor_allocation_failure_reports_its_ordinal() {
        let _guard = super::super::hot_kernel_test_guard();
        let baseline = builder(
            SIMD_PATTERN,
            HotByteDispatch::Runtime(compatible_test_policy()),
        )
        .build()
        .expect("baseline construction");
        let attempts = baseline.build_receipt().actual().allocation_attempts;
        assert_eq!(attempts, 3);
        for ordinal in 1..=attempts {
            let error = builder(
                SIMD_PATTERN,
                HotByteDispatch::Runtime(compatible_test_policy()),
            )
            .build_with_allocation_fault(Some(ordinal))
            .expect_err("injected exact allocation failure");
            assert!(matches!(
                error,
                HotByteBuildError::AllocationFailed { ordinal: actual }
                    if actual == ordinal
            ));
        }
    }

    #[test]
    fn facade_has_zero_steady_allocations_and_linear_authenticated_counters() {
        let _guard = super::super::hot_kernel_test_guard();
        let artifact = builder(
            r"[ab]{16}",
            HotByteDispatch::Runtime(compatible_test_policy()),
        )
        .build()
        .expect("SIMD artifact");
        let short = [b'a'; 64];
        let long = [b'a'; 128];
        let mut short_session = artifact.new_session().expect("short session");
        let short_receipt = artifact
            .count(&mut short_session, &short, 0..short.len())
            .expect("short execution");
        let mut long_session = artifact.new_session().expect("long session");
        let long_receipt = artifact
            .count(&mut long_session, &long, 0..long.len())
            .expect("long execution");
        assert_eq!(short_receipt.value, Some(OperationSessionValue::Count(4)));
        assert_eq!(long_receipt.value, Some(OperationSessionValue::Count(8)));
        assert_eq!(
            long_receipt.actual.source_accesses,
            short_receipt.actual.source_accesses * 2
        );
        assert_eq!(
            long_receipt.actual.transitions,
            short_receipt.actual.transitions * 2
        );
        assert_eq!(
            long_receipt.actual.candidates,
            short_receipt.actual.candidates * 2
        );

        let mut session = artifact.new_session().expect("steady session");
        let region =
            stats_alloc::Region::new(super::super::super::OPERATION_SESSION_TEST_ALLOCATOR);
        for _ in 0..4 {
            let receipt = artifact
                .count(&mut session, &short, 0..short.len())
                .expect("steady execution");
            assert!(receipt.closes());
            assert_eq!(receipt.actual.allocations, 0);
        }
        assert_eq!(region.change(), stats_alloc::Stats::default());
    }
}
