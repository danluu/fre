//! Hot-kernel-lane-owned fixed storage and forced entry hooks.

#![allow(
    clippy::large_enum_variant,
    clippy::large_types_passed_by_value,
    reason = "the exact descriptor owns one inline non-forgeable classifier without a hidden allocation or lifetime dependency"
)]

use core::ops::Range;

use fre_exact_alloc::ExactVec;
use fre_kernels::{ASCII_NARROW_BYTES, ASCII_WIDE_BYTES, AsciiByteSetClassifier, AsciiSelection};

mod facade;

pub use facade::{
    HOT_BYTE_PROGRAM_ACCOUNTING_ID, HOT_BYTE_PROGRAM_ACCOUNTING_VERSION,
    HOT_BYTE_PROGRAM_ALGORITHM_VERSION, HotByteBuildAccounting, HotByteBuildError,
    HotByteBuildLimits, HotByteBuildReceipt, HotByteBuildResource, HotByteDispatch,
    HotByteIneligibility, HotByteProgramArtifact, HotByteProgramBuilder, HotByteRunError,
    HotByteRunLimits,
};

use super::{
    OperationSession, OperationSessionAttempt, OperationSessionAttemptError,
    OperationSessionAttemptRequest, OperationSessionError, OperationSessionInvocation,
    OperationSessionLeaf, OperationSessionLeafCounters, OperationSessionReducer,
    OperationSessionResetActual, OperationSessionResetProspective, OperationSessionStorageActual,
    OperationSessionStorageProspective, SessionLeafSlot, allocate_zeroed_cells, apply_leaf_reset,
    begin_forced_slot, derive_layout_id, leaf_reset_prospective, measured_storage_actual,
    storage_prospective, tag_layout_id,
};

#[cfg(test)]
use super::receipt::{
    OPERATION_SESSION_ACCOUNTING_ID, OPERATION_SESSION_ACCOUNTING_VERSION,
    OPERATION_SESSION_ALGORITHM_VERSION,
};
#[cfg(test)]
use super::{
    OperationSessionAdmission, OperationSessionConstructionLimits,
    OperationSessionExecutionProspective, OperationSessionResetLimits, OperationSessionResource,
    OperationSessionRouteIdentity, OperationSessionRunLimits, OperationSessionTerminal,
    OperationSessionValue,
};

/// Hot slot algorithm version.
pub const ALGORITHM_VERSION: u32 = 1;
/// Hot slot accounting version.
pub const ACCOUNTING_VERSION: u32 = 1;
/// Stable hot slot accounting identity.
pub const ACCOUNTING_ID: &str = "fre.operation-session.hot.v1";
pub(crate) const COUNT_SOURCE_IDENTITY: &str = "fre.operation-session.hot.count.byte-range.v1";
pub(crate) const COUNT_ORDER_IDENTITY: &str =
    "fre.operation-session.hot.count.leftmost-nonoverlap-pattern-order.v1";
pub(crate) const COUNT_FALLBACK_IDENTITY: &str =
    "fre.operation-session.hot.count.no-post-source-fallback.v1";
pub(crate) const SPAN_SUM_SOURCE_IDENTITY: &str =
    "fre.operation-session.hot.span-sum.byte-range.v1";
pub(crate) const SPAN_SUM_ORDER_IDENTITY: &str =
    "fre.operation-session.hot.span-sum.leftmost-nonoverlap-pattern-order.v1";
pub(crate) const SPAN_SUM_FALLBACK_IDENTITY: &str =
    "fre.operation-session.hot.span-sum.no-post-source-fallback.v1";
pub(crate) const PARTICIPATION_SOURCE_IDENTITY: &str =
    "fre.operation-session.hot.participation.byte-range.v1";
pub(crate) const PARTICIPATION_ORDER_IDENTITY: &str =
    "fre.operation-session.hot.participation.source-pattern-order.v1";
pub(crate) const PARTICIPATION_FALLBACK_IDENTITY: &str =
    "fre.operation-session.hot.participation.unsupported-pre-source.v1";
const LAYOUT_SEED: [u8; 16] = *b"fre.hot.v1\0\0\0\0\0\0";

/// One immutable atom retained by a prevalidated fixed byte program.
#[derive(Debug)]
pub(crate) enum HotByteAtom {
    /// Compare one nonempty, exactly allocated literal byte sequence.
    Literal(ExactVec<u8>),
    /// Compare exactly `repetitions` bytes against a 256-bit membership set.
    ByteClass {
        /// Four little-endian 64-bit membership words indexed by byte value.
        membership: [u64; 4],
        /// Exact, nonzero number of consecutive class bytes.
        repetitions: usize,
        /// One-time selected ASCII classifier. `None` means the scalar leaf is
        /// required, including every non-ASCII class.
        classifier: Option<AsciiByteSetClassifier>,
    },
}

impl HotByteAtom {
    fn literal(bytes: ExactVec<u8>) -> Result<Self, HotKernelPreparationError> {
        if bytes.is_empty() {
            return Err(HotKernelPreparationError::EmptyLiteral);
        }
        Ok(Self::Literal(bytes))
    }

    fn byte_class(
        membership: [u64; 4],
        repetitions: usize,
        classifier: Option<AsciiByteSetClassifier>,
    ) -> Result<Self, HotKernelPreparationError> {
        if repetitions == 0 {
            return Err(HotKernelPreparationError::ZeroClassRepetitions);
        }
        if let Some(classifier) = classifier {
            if membership[2] != 0 || membership[3] != 0 {
                return Err(HotKernelPreparationError::ClassifierOnNonAsciiClass);
            }
            if classifier.set().words() != [membership[0], membership[1]] {
                return Err(HotKernelPreparationError::ClassifierSetMismatch);
            }
        }
        Ok(Self::ByteClass {
            membership,
            repetitions,
            classifier,
        })
    }

    fn width(&self) -> Result<usize, HotKernelPreparationError> {
        match self {
            Self::Literal(bytes) if bytes.is_empty() => {
                Err(HotKernelPreparationError::EmptyLiteral)
            }
            Self::Literal(bytes) => Ok(bytes.len()),
            Self::ByteClass { repetitions: 0, .. } => {
                Err(HotKernelPreparationError::ZeroClassRepetitions)
            }
            Self::ByteClass { repetitions, .. } => Ok(*repetitions),
        }
    }

    const fn selection(&self) -> Option<AsciiSelection> {
        match self {
            Self::Literal(_) => None,
            Self::ByteClass { classifier, .. } => match classifier {
                Some(classifier) => Some(classifier.selection()),
                None => None,
            },
        }
    }
}

/// One nonempty fixed byte program retained by a compiled artifact.
#[derive(Debug)]
pub(crate) struct HotByteProgram {
    atoms: ExactVec<HotByteAtom>,
    width: usize,
    atom_count: usize,
}

impl HotByteProgram {
    /// Validate a fixed program before it can be used by a hot operation.
    #[cfg(test)]
    pub(crate) fn try_new(
        atoms: impl IntoIterator<Item = HotByteAtom>,
    ) -> Result<Self, HotKernelPreparationError> {
        let atoms = atoms.into_iter().collect::<Vec<_>>();
        if atoms.is_empty() {
            return Err(HotKernelPreparationError::EmptyProgram);
        }
        let mut width = 0_usize;
        for atom in &atoms {
            width = width
                .checked_add(atom.width()?)
                .ok_or(HotKernelPreparationError::WidthOverflow)?;
        }
        let atom_count = atoms.len();
        let mut exact = ExactVec::try_with_capacity(atom_count)
            .map_err(|_| HotKernelPreparationError::AllocationFailed)?;
        for atom in atoms {
            exact
                .try_push(atom)
                .unwrap_or_else(|_| unreachable!("exact atom capacity was precomputed"));
        }
        Ok(Self {
            atoms: exact,
            width,
            atom_count,
        })
    }

    fn from_exact_atoms(
        atoms: ExactVec<HotByteAtom>,
        expected_width: usize,
    ) -> Result<Self, HotKernelPreparationError> {
        if atoms.is_empty() {
            return Err(HotKernelPreparationError::EmptyProgram);
        }
        let mut width = 0_usize;
        for atom in &atoms {
            width = width
                .checked_add(atom.width()?)
                .ok_or(HotKernelPreparationError::WidthOverflow)?;
        }
        if width != expected_width {
            return Err(HotKernelPreparationError::WidthMismatch {
                expected: expected_width,
                actual: width,
            });
        }
        Ok(Self {
            atom_count: atoms.len(),
            atoms,
            width,
        })
    }
}

/// Ordered fixed byte programs retained by a compiled artifact.
///
/// At a common start position the earliest program in this slice wins. The
/// executor then advances past the chosen nonempty span, preserving
/// leftmost-nonoverlapping reduction without allocating a match vector.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HotByteProgramSet<'a> {
    /// Immutable compiled-artifact identity for these exact ordered programs.
    compiled_plan_id: [u8; 16],
    programs: &'a [HotByteProgram],
    comparison_width: usize,
    atom_visits: usize,
}

impl<'a> HotByteProgramSet<'a> {
    /// Validate an ordered nonempty program set once at compiled-artifact time.
    pub(crate) fn try_new(
        compiled_plan_id: [u8; 16],
        programs: &'a [HotByteProgram],
    ) -> Result<Self, HotKernelPreparationError> {
        if compiled_plan_id == [0; 16] {
            return Err(HotKernelPreparationError::ZeroCompiledPlanId);
        }
        if programs.is_empty() {
            return Err(HotKernelPreparationError::EmptyProgramSet);
        }
        let mut comparison_width = 0_usize;
        let mut atom_visits = 0_usize;
        for program in programs {
            // A `HotByteProgram` is only constructible through `try_new`, but
            // retain this check so a future in-module representation change
            // cannot make an empty match progress silently.
            if program.width == 0 {
                return Err(HotKernelPreparationError::EmptyProgram);
            }
            let _ = u64::try_from(program.width)
                .map_err(|_| HotKernelPreparationError::WidthOverflow)?;
            comparison_width = comparison_width
                .checked_add(program.width)
                .ok_or(HotKernelPreparationError::WidthOverflow)?;
            atom_visits = atom_visits
                .checked_add(program.atom_count)
                .ok_or(HotKernelPreparationError::WidthOverflow)?;
        }
        let _ =
            u64::try_from(programs.len()).map_err(|_| HotKernelPreparationError::WidthOverflow)?;
        let _ = u64::try_from(comparison_width)
            .map_err(|_| HotKernelPreparationError::WidthOverflow)?;
        Ok(Self {
            compiled_plan_id,
            programs,
            comparison_width,
            atom_visits,
        })
    }

    /// Recreate the already-validated view retained by the compiled artifact.
    ///
    /// The facade calls `try_new` exactly once before publication and retains
    /// these authenticated totals. Steady calls therefore borrow the exact
    /// same program allocation without replaying descriptor proof work.
    fn from_validated(
        compiled_plan_id: [u8; 16],
        programs: &'a [HotByteProgram],
        comparison_width: usize,
        atom_visits: usize,
    ) -> Self {
        debug_assert_ne!(compiled_plan_id, [0; 16]);
        debug_assert!(!programs.is_empty());
        Self {
            compiled_plan_id,
            programs,
            comparison_width,
            atom_visits,
        }
    }

    /// Derive the complete source-independent execution envelope for `range`.
    ///
    /// The calculation is constant-space and touches neither source bytes nor
    /// session storage. It charges two workspace writes per program, one
    /// termination check per candidate boundary, three setup actions per
    /// program (descriptor lookup plus two workspace writes), one ordered
    /// program check and atom traversal per candidate, and every possible byte
    /// comparison.
    pub(crate) fn prospective(
        &self,
        range: Range<usize>,
    ) -> Result<super::OperationSessionExecutionProspective, HotKernelPreparationError> {
        let range_len = range
            .end
            .checked_sub(range.start)
            .ok_or(HotKernelPreparationError::InvalidRange)?;
        let range_len =
            u64::try_from(range_len).map_err(|_| HotKernelPreparationError::ProspectiveOverflow)?;
        let programs = u64::try_from(self.programs.len())
            .map_err(|_| HotKernelPreparationError::ProspectiveOverflow)?;
        let comparison_width = u64::try_from(self.comparison_width)
            .map_err(|_| HotKernelPreparationError::ProspectiveOverflow)?;
        let atom_visits = u64::try_from(self.atom_visits)
            .map_err(|_| HotKernelPreparationError::ProspectiveOverflow)?;
        let setup = programs
            .checked_mul(3)
            .ok_or(HotKernelPreparationError::ProspectiveOverflow)?;
        let cursor_branches = range_len
            .checked_add(1)
            .ok_or(HotKernelPreparationError::ProspectiveOverflow)?;
        let program_checks = range_len
            .checked_mul(programs)
            .ok_or(HotKernelPreparationError::ProspectiveOverflow)?;
        let atom_traversals = range_len
            .checked_mul(atom_visits)
            .ok_or(HotKernelPreparationError::ProspectiveOverflow)?;
        let comparisons = range_len
            .checked_mul(comparison_width)
            .ok_or(HotKernelPreparationError::ProspectiveOverflow)?;
        let work = setup
            .checked_add(cursor_branches)
            .and_then(|value| value.checked_add(program_checks))
            .and_then(|value| value.checked_add(atom_traversals))
            .and_then(|value| value.checked_add(comparisons))
            .ok_or(HotKernelPreparationError::ProspectiveOverflow)?;
        Ok(super::OperationSessionExecutionProspective {
            work,
            source_accesses: comparisons,
            transitions: comparisons,
            candidates: range_len,
            cache_misses: 0,
            history_nodes: 0,
            line_domains: 0,
            output_events: range_len,
            selected_span_bytes: range_len,
            participation_entries: 0,
            allocations: 0,
        })
    }
}

/// Source-independent preparation refusal for a fixed byte program.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HotKernelPreparationError {
    /// The descriptor did not carry a nonzero immutable compiled-plan ID.
    ZeroCompiledPlanId,
    /// A program had no atoms.
    EmptyProgram,
    /// A literal atom was empty.
    EmptyLiteral,
    /// A class atom had zero repetitions.
    ZeroClassRepetitions,
    /// The ordered program set was empty.
    EmptyProgramSet,
    /// A checked structural width could not be represented.
    WidthOverflow,
    /// The materializer's declared width differed from the checked atoms.
    WidthMismatch { expected: usize, actual: usize },
    /// A fallible exact descriptor allocation failed.
    AllocationFailed,
    /// A retained classifier was attached to a class containing non-ASCII
    /// members.
    ClassifierOnNonAsciiClass,
    /// A retained classifier's set differed from the exact class membership.
    ClassifierSetMismatch,
    /// The caller gave an inverted source range.
    InvalidRange,
    /// A checked execution-envelope dimension overflowed.
    ProspectiveOverflow,
    /// The request's declared source length did not bind the supplied bytes.
    SourceLengthMismatch {
        /// Length authenticated by the request.
        declared: usize,
        /// Actual supplied source length.
        actual: usize,
    },
    /// The request did not contain the exact derived byte-program envelope.
    ProspectiveMismatch,
    /// The admitted state workspace could not hold all program widths.
    StateWorkspaceTooSmall {
        /// Required cells.
        needed: usize,
        /// Admitted cells.
        available: usize,
    },
    /// The admitted candidate workspace could not hold all ordered ordinals.
    CandidateWorkspaceTooSmall {
        /// Required cells.
        needed: usize,
        /// Admitted cells.
        available: usize,
    },
}

/// Explicit fixed capacities for the hot-kernel leaf.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlotAdmission {
    /// State cells.
    pub state_cells: usize,
    /// Generation-mark cells.
    pub generation_cells: usize,
    /// Candidate cells.
    pub candidate_cells: usize,
    /// Persistent cache cells.
    pub cache_cells: usize,
    /// Persistent history cells.
    pub history_cells: usize,
}

#[derive(Debug)]
#[allow(
    dead_code,
    reason = "the common seal owns exact buffers before the H lane installs kernel semantics"
)]
pub(crate) struct Slot {
    state: ExactVec<u64>,
    generation: ExactVec<u64>,
    candidates: ExactVec<u64>,
    cache: ExactVec<u64>,
    history: ExactVec<u64>,
    counters: OperationSessionLeafCounters,
    layout_id: [u8; 16],
}

impl super::private::Sealed for Slot {}

impl SessionLeafSlot for Slot {
    const LEAF: OperationSessionLeaf = OperationSessionLeaf::Hot;
    type Admission = SlotAdmission;

    fn prospective(
        admission: &Self::Admission,
    ) -> Result<OperationSessionStorageProspective, OperationSessionError> {
        storage_prospective(
            &[
                admission.generation_cells,
                admission.cache_cells,
                admission.history_cells,
            ],
            &[admission.state_cells, admission.candidate_cells],
            admission.generation_cells,
        )
    }

    fn try_new(
        admission: Self::Admission,
        prospective: &OperationSessionStorageProspective,
    ) -> Result<(Self, OperationSessionStorageActual), OperationSessionError> {
        let state = allocate_zeroed_cells(admission.state_cells)?;
        let generation = allocate_zeroed_cells(admission.generation_cells)?;
        let candidates = allocate_zeroed_cells(admission.candidate_cells)?;
        let cache = allocate_zeroed_cells(admission.cache_cells)?;
        let history = allocate_zeroed_cells(admission.history_cells)?;
        let layout_id = tag_layout_id(
            Self::LEAF,
            derive_layout_id(
                LAYOUT_SEED,
                &[
                    admission.state_cells,
                    admission.generation_cells,
                    admission.candidate_cells,
                    admission.cache_cells,
                    admission.history_cells,
                ],
            )?,
        );
        let actual = measured_storage_actual(
            &[&generation, &cache, &history],
            &[&state, &candidates],
            &generation,
        )?;
        debug_assert_eq!(actual.build_work, prospective.build_work);
        Ok((
            Self {
                state,
                generation,
                candidates,
                cache,
                history,
                counters: OperationSessionLeafCounters::default(),
                layout_id,
            },
            actual,
        ))
    }

    fn layout_id(&self) -> [u8; 16] {
        self.layout_id
    }

    fn generation_capacity(&self) -> usize {
        self.generation.capacity()
    }

    fn counters(&self) -> OperationSessionLeafCounters {
        self.counters
    }

    fn reset_prospective(
        &self,
        required_generations: u64,
    ) -> Result<OperationSessionResetProspective, OperationSessionError> {
        leaf_reset_prospective(
            Self::LEAF,
            self.counters,
            self.generation.capacity(),
            required_generations,
        )
    }

    fn apply_reset(
        &mut self,
        prospective: &OperationSessionResetProspective,
    ) -> OperationSessionResetActual {
        apply_leaf_reset(&mut self.generation, &mut self.counters, prospective)
    }
}

pub(crate) const fn route_contract(
    reducer: OperationSessionReducer,
) -> (&'static str, &'static str, &'static str) {
    match reducer {
        OperationSessionReducer::Count => (
            COUNT_SOURCE_IDENTITY,
            COUNT_ORDER_IDENTITY,
            COUNT_FALLBACK_IDENTITY,
        ),
        OperationSessionReducer::SpanSum => (
            SPAN_SUM_SOURCE_IDENTITY,
            SPAN_SUM_ORDER_IDENTITY,
            SPAN_SUM_FALLBACK_IDENTITY,
        ),
        OperationSessionReducer::Participation => (
            PARTICIPATION_SOURCE_IDENTITY,
            PARTICIPATION_ORDER_IDENTITY,
            PARTICIPATION_FALLBACK_IDENTITY,
        ),
    }
}

pub(crate) const fn supports(reducer: OperationSessionReducer) -> bool {
    matches!(
        reducer,
        OperationSessionReducer::Count | OperationSessionReducer::SpanSum
    )
}

pub(crate) fn invocation_closes(
    _reducer: OperationSessionReducer,
    invocation: &OperationSessionInvocation,
) -> bool {
    invocation.is_valid()
}

impl OperationSession {
    /// Hot-kernel forced entry view.
    pub fn forced_hot(&mut self) -> ForcedHot<'_> {
        ForcedHot { session: self }
    }

    #[allow(
        dead_code,
        reason = "predeclared operation-session seal hook consumed by later reviewed leaf facade"
    )]
    #[allow(
        clippy::result_large_err,
        reason = "sealed errors return authenticated terminal receipts by value without failure-path allocation"
    )]
    fn begin_hot(
        &mut self,
        mut request: OperationSessionAttemptRequest,
        reducer: OperationSessionReducer,
    ) -> Result<OperationSessionAttempt<'_, Slot>, OperationSessionAttemptError> {
        request.bind_reducer(reducer);
        let all_before = self.all_counters();
        begin_forced_slot(&self.construction, all_before, &mut self.hot, request)
    }
}

/// Hot-kernel forced entry view.
#[derive(Debug)]
pub struct ForcedHot<'a> {
    #[allow(
        dead_code,
        reason = "predeclared operation-session seal hook consumed by later reviewed leaf facade"
    )]
    pub(crate) session: &'a mut OperationSession,
}

/// One-shot, session-bound admission for a fixed byte-program operation.
///
/// Constructing this token is explicitly pre-operation artifact/input
/// preparation: malformed descriptors, exact source binding, the derived
/// envelope, and fixed workspace capacity are checked before an attempt or
/// reset exists. The token retains the only mutable `ForcedHot` borrow, its
/// exact request, source, descriptor, and range; it cannot be cloned, moved to
/// another session, or invoked with substituted inputs. Calling [`Self::run`]
/// is the operation entry and returns only common authenticated attempt
/// receipts.
#[derive(Debug)]
#[allow(
    dead_code,
    reason = "the leaf-local prepared kernel remains unavailable until its reviewed facade is wired"
)]
pub(crate) struct HotByteProgramRun<'run, 'session, 'input> {
    forced: &'run mut ForcedHot<'session>,
    state: HotByteProgramRunState<'input>,
}

#[derive(Debug)]
#[allow(
    dead_code,
    reason = "the leaf-local prepared kernel remains unavailable until its reviewed facade is wired"
)]
enum HotByteProgramRunState<'input> {
    /// All leaf-local preparation has passed and the exact inputs are bound.
    Ready {
        request: OperationSessionAttemptRequest,
        source: &'input [u8],
        range: Range<usize>,
        programs: HotByteProgramSet<'input>,
        reducer: OperationSessionReducer,
    },
    /// Existing common preflight must win before preparation can reject.
    ForwardCommon {
        request: OperationSessionAttemptRequest,
        reducer: OperationSessionReducer,
    },
    /// A descriptor plan differs from an otherwise canonical request.
    ForwardDescriptorMismatch {
        request: OperationSessionAttemptRequest,
        descriptor_plan_id: [u8; 16],
        reducer: OperationSessionReducer,
    },
}

#[allow(
    dead_code,
    reason = "the leaf-local prepared kernel remains unavailable until its reviewed facade is wired"
)]
impl HotByteProgramRun<'_, '_, '_> {
    /// Enter the common authenticated operation transaction exactly once.
    #[allow(
        clippy::result_large_err,
        reason = "the sealed attempt terminal stays by value so a steady refusal never allocates"
    )]
    pub(crate) fn run(
        self,
    ) -> Result<super::OperationSessionAttemptReceipt, OperationSessionAttemptError> {
        match self.state {
            HotByteProgramRunState::ForwardCommon { request, reducer } => {
                let result = begin_prepared_byte_programs(self.forced, request, reducer);
                let Err(error) = result else {
                    unreachable!("exclusive common preflight state cannot change before run")
                };
                Err(error)
            }
            HotByteProgramRunState::ForwardDescriptorMismatch {
                mut request,
                descriptor_plan_id,
                reducer,
            } => {
                // The original public identity was canonical during
                // preparation. Replacing only its attempted plan ID preserves
                // the private trusted plan ID, so common preflight emits the
                // existing closed pre-reset route-mismatch receipt.
                request.identity.compiled_plan_id = descriptor_plan_id;
                let result = begin_prepared_byte_programs(self.forced, request, reducer);
                let Err(error) = result else {
                    unreachable!("descriptor plan mismatch must fail common preflight")
                };
                Err(error)
            }
            HotByteProgramRunState::Ready {
                request,
                source,
                range,
                programs,
                reducer,
            } => {
                let mut attempt = begin_prepared_byte_programs(self.forced, request, reducer)?;
                prepare_workspace(&mut attempt, programs)?;
                execute_byte_programs(&mut attempt, source, range, programs)?;
                match reducer {
                    OperationSessionReducer::Count => attempt.finish_count(),
                    OperationSessionReducer::SpanSum => attempt.finish_span_sum(),
                    OperationSessionReducer::Participation => {
                        unreachable!("byte-program core does not implement participation")
                    }
                }
            }
        }
    }
}

#[allow(
    clippy::result_large_err,
    reason = "the sealed attempt terminal stays by value so a steady refusal never allocates"
)]
#[allow(
    dead_code,
    reason = "the leaf-local prepared kernel remains unavailable until its reviewed facade is wired"
)]
fn begin_prepared_byte_programs<'borrow>(
    forced: &'borrow mut ForcedHot<'_>,
    request: OperationSessionAttemptRequest,
    reducer: OperationSessionReducer,
) -> Result<OperationSessionAttempt<'borrow, Slot>, OperationSessionAttemptError> {
    match reducer {
        OperationSessionReducer::Count => forced.begin_count(request),
        OperationSessionReducer::SpanSum => forced.begin_span_sum(request),
        OperationSessionReducer::Participation => {
            unreachable!("byte-program core does not implement participation")
        }
    }
}

#[allow(
    dead_code,
    reason = "predeclared operation-session seal hook consumed by later reviewed leaf facade"
)]
#[allow(
    clippy::result_large_err,
    reason = "the authenticated terminal receipt stays by value so a steady refusal never allocates"
)]
impl<'session> ForcedHot<'session> {
    #[allow(
        clippy::result_large_err,
        reason = "sealed errors return authenticated terminal receipts by value without failure-path allocation"
    )]
    pub(crate) fn begin_count(
        &mut self,
        request: OperationSessionAttemptRequest,
    ) -> Result<OperationSessionAttempt<'_, Slot>, OperationSessionAttemptError> {
        self.session
            .begin_hot(request, OperationSessionReducer::Count)
    }

    #[allow(
        clippy::result_large_err,
        reason = "sealed errors return authenticated terminal receipts by value without failure-path allocation"
    )]
    pub(crate) fn begin_span_sum(
        &mut self,
        request: OperationSessionAttemptRequest,
    ) -> Result<OperationSessionAttempt<'_, Slot>, OperationSessionAttemptError> {
        self.session
            .begin_hot(request, OperationSessionReducer::SpanSum)
    }

    /// Prepare a Count byte-program operation before any attempt/reset exists.
    ///
    /// This is an artifact/input capability constructor, not an operation
    /// entry. Its typed failures are therefore intentionally receipt-free and
    /// leave session counters and storage untouched. Any existing common
    /// identity, invocation, reducer, or run-limit terminal is forwarded to
    /// [`HotByteProgramRun::run`] so the common authenticated receipt keeps
    /// precedence. The runtime facade must retain the descriptor with its
    /// immutable compiled artifact and select capabilities before calling it.
    pub(crate) fn prepare_count_byte_programs<'run, 'input>(
        &'run mut self,
        request: OperationSessionAttemptRequest,
        source: &'input [u8],
        programs: HotByteProgramSet<'input>,
    ) -> Result<HotByteProgramRun<'run, 'session, 'input>, HotKernelPreparationError> {
        self.prepare_byte_program_run(request, source, programs, OperationSessionReducer::Count)
    }

    /// Prepare a `SpanSum` byte-program operation before any attempt/reset.
    ///
    /// See [`Self::prepare_count_byte_programs`] for the pre-operation and
    /// integration boundary.
    pub(crate) fn prepare_span_sum_byte_programs<'run, 'input>(
        &'run mut self,
        request: OperationSessionAttemptRequest,
        source: &'input [u8],
        programs: HotByteProgramSet<'input>,
    ) -> Result<HotByteProgramRun<'run, 'session, 'input>, HotKernelPreparationError> {
        self.prepare_byte_program_run(request, source, programs, OperationSessionReducer::SpanSum)
    }

    fn prepare_byte_program_run<'run, 'input>(
        &'run mut self,
        request: OperationSessionAttemptRequest,
        source: &'input [u8],
        programs: HotByteProgramSet<'input>,
        reducer: OperationSessionReducer,
    ) -> Result<HotByteProgramRun<'run, 'session, 'input>, HotKernelPreparationError> {
        // The pure common preflight has the authoritative terminal ordering.
        // Its exclusive session borrow means a forwarding token cannot observe
        // different state before `run` consumes it.
        let mut common_request = request.clone();
        common_request.bind_reducer(reducer);
        let expected_identity = super::expected_route_identity::<Slot>(&common_request);
        if super::preflight_attempt::<Slot>(
            &self.session.construction,
            &self.session.hot,
            &common_request,
            expected_identity,
        )
        .is_some()
        {
            return Ok(HotByteProgramRun {
                forced: self,
                state: HotByteProgramRunState::ForwardCommon { request, reducer },
            });
        }

        // `preflight_attempt` established that the caller's public identity
        // is canonical. A distinct immutable descriptor plan can now be
        // represented truthfully as the existing attempted route mismatch.
        if programs.compiled_plan_id != request.trusted_compiled_plan_id() {
            return Ok(HotByteProgramRun {
                forced: self,
                state: HotByteProgramRunState::ForwardDescriptorMismatch {
                    request,
                    descriptor_plan_id: programs.compiled_plan_id,
                    reducer,
                },
            });
        }

        let invocation = &request.invocation;
        if invocation.haystack_len != source.len() {
            return Err(HotKernelPreparationError::SourceLengthMismatch {
                declared: invocation.haystack_len,
                actual: source.len(),
            });
        }
        // Common preflight already proved the declared range valid. Exact
        // source-length binding therefore proves it valid for this source.
        let range = invocation.range.clone();
        let prospective = programs.prospective(range.clone())?;
        if request.prospective != prospective {
            return Err(HotKernelPreparationError::ProspectiveMismatch);
        }
        let required = programs.programs.len();
        let state_cells = self.session.hot.state.as_slice().len();
        if state_cells < required {
            return Err(HotKernelPreparationError::StateWorkspaceTooSmall {
                needed: required,
                available: state_cells,
            });
        }
        let candidate_cells = self.session.hot.candidates.as_slice().len();
        if candidate_cells < required {
            return Err(HotKernelPreparationError::CandidateWorkspaceTooSmall {
                needed: required,
                available: candidate_cells,
            });
        }
        Ok(HotByteProgramRun {
            forced: self,
            state: HotByteProgramRunState::Ready {
                request,
                source,
                range,
                programs,
                reducer,
            },
        })
    }

    #[allow(
        clippy::result_large_err,
        reason = "sealed errors return authenticated terminal receipts by value without failure-path allocation"
    )]
    pub(crate) fn begin_participation(
        &mut self,
        request: OperationSessionAttemptRequest,
    ) -> Result<OperationSessionAttempt<'_, Slot>, OperationSessionAttemptError> {
        self.session
            .begin_hot(request, OperationSessionReducer::Participation)
    }
}

#[allow(
    clippy::result_large_err,
    reason = "the authenticated terminal receipt stays by value so a steady refusal never allocates"
)]
#[allow(
    dead_code,
    reason = "the leaf-local prepared kernel remains unavailable until its reviewed facade is wired"
)]
fn prepare_workspace(
    attempt: &mut OperationSessionAttempt<'_, Slot>,
    programs: HotByteProgramSet<'_>,
) -> Result<(), OperationSessionAttemptError> {
    for ordinal in 0..programs.programs.len() {
        // Charge the descriptor lookup/conversion and both fixed-buffer writes
        // before touching either descriptor or workspace storage.
        attempt.meter_work(3)?;
        let program = programs
            .programs
            .get(ordinal)
            .expect("prepared program ordinal stays in the retained descriptor");
        let encoded_ordinal =
            u64::try_from(ordinal).expect("validated program count is representable as u64");
        let encoded_width =
            u64::try_from(program.width).expect("validated program width is representable as u64");
        let slot = attempt.selected_slot();
        slot.state.as_mut_slice()[ordinal] = encoded_width;
        slot.candidates.as_mut_slice()[ordinal] = encoded_ordinal;
    }
    Ok(())
}

#[allow(
    clippy::result_large_err,
    reason = "the authenticated terminal receipt stays by value so a steady refusal never allocates"
)]
#[allow(
    dead_code,
    reason = "the leaf-local prepared kernel remains unavailable until its reviewed facade is wired"
)]
fn execute_byte_programs(
    attempt: &mut OperationSessionAttempt<'_, Slot>,
    source: &[u8],
    range: Range<usize>,
    programs: HotByteProgramSet<'_>,
) -> Result<(), OperationSessionAttemptError> {
    let mut cursor = range.start;
    loop {
        // Charge the cursor termination branch before inspecting the range.
        attempt.meter_work(1)?;
        if cursor >= range.end {
            break;
        }
        attempt.meter_candidates(1)?;
        let remaining = range
            .end
            .checked_sub(cursor)
            .expect("prepared cursor remains within the validated range");
        let mut selected_end = None;
        for workspace_ordinal in 0..programs.programs.len() {
            // Charge the ordered-program lookup and short-range branch before
            // reading the admitted workspace or descriptor.
            attempt.meter_work(1)?;
            let expected_ordinal = u64::try_from(workspace_ordinal)
                .expect("validated program count is representable as u64");
            let (recorded_ordinal, recorded_width) = {
                let slot = attempt.selected_slot();
                (
                    slot.candidates.as_slice()[workspace_ordinal],
                    slot.state.as_slice()[workspace_ordinal],
                )
            };
            let program = programs
                .programs
                .get(workspace_ordinal)
                .expect("prepared program ordinal stays in the retained descriptor");
            let expected_width = u64::try_from(program.width)
                .expect("validated program width is representable as u64");
            debug_assert_eq!(recorded_ordinal, expected_ordinal);
            debug_assert_eq!(recorded_width, expected_width);
            if program.width > remaining {
                continue;
            }
            if byte_program_matches(attempt, source, cursor, program)? {
                let end = cursor
                    .checked_add(program.width)
                    .expect("validated program width stays within the selected range");
                attempt.emit_span(cursor, end, None)?;
                selected_end = Some(end);
                break;
            }
        }
        cursor = match selected_end {
            Some(end) => end,
            None => cursor
                .checked_add(1)
                .expect("cursor below the validated range end advances by one"),
        };
    }
    Ok(())
}

#[allow(
    clippy::result_large_err,
    reason = "the authenticated terminal receipt stays by value so a steady refusal never allocates"
)]
#[allow(
    dead_code,
    reason = "the leaf-local prepared kernel remains unavailable until its reviewed facade is wired"
)]
fn byte_program_matches(
    attempt: &mut OperationSessionAttempt<'_, Slot>,
    source: &[u8],
    start: usize,
    program: &HotByteProgram,
) -> Result<bool, OperationSessionAttemptError> {
    let mut position = start;
    for atom_ordinal in 0..program.atom_count {
        // Meter atom traversal before dereferencing, copying, or branching on
        // the descriptor atom. `HotByteAtom` is intentionally not `Copy`.
        attempt.meter_work(1)?;
        let atom = program
            .atoms
            .get(atom_ordinal)
            .expect("validated atom ordinal stays in the retained descriptor");
        match atom {
            HotByteAtom::Literal(literal) => {
                for byte_ordinal in 0..literal.len() {
                    charge_byte_comparison(attempt)?;
                    let expected = literal
                        .get(byte_ordinal)
                        .expect("literal ordinal stays within its validated width");
                    let actual = source[position];
                    if actual != *expected {
                        return Ok(false);
                    }
                    position = position
                        .checked_add(1)
                        .expect("validated literal byte stays within selected range");
                }
            }
            HotByteAtom::ByteClass {
                membership,
                repetitions,
                classifier,
            } => {
                let mut remaining = *repetitions;
                if let Some(classifier) = classifier {
                    while remaining >= ASCII_WIDE_BYTES {
                        charge_byte_comparisons(attempt, ASCII_WIDE_BYTES)?;
                        let end = position
                            .checked_add(ASCII_WIDE_BYTES)
                            .expect("prepared SIMD block remains within the selected range");
                        let block: &[u8; ASCII_WIDE_BYTES] = source[position..end]
                            .try_into()
                            .expect("the exact SIMD block width was checked");
                        if classifier.classify_32(block).member_mask() != u32::MAX {
                            return Ok(false);
                        }
                        position = end;
                        remaining = remaining
                            .checked_sub(ASCII_WIDE_BYTES)
                            .expect("wide block does not exceed remaining class width");
                    }
                    while remaining >= ASCII_NARROW_BYTES {
                        charge_byte_comparisons(attempt, ASCII_NARROW_BYTES)?;
                        let end = position
                            .checked_add(ASCII_NARROW_BYTES)
                            .expect("prepared SIMD block remains within the selected range");
                        let block: &[u8; ASCII_NARROW_BYTES] = source[position..end]
                            .try_into()
                            .expect("the exact SIMD block width was checked");
                        if classifier.classify_16(block).member_mask() != u16::MAX {
                            return Ok(false);
                        }
                        position = end;
                        remaining = remaining
                            .checked_sub(ASCII_NARROW_BYTES)
                            .expect("narrow block does not exceed remaining class width");
                    }
                }
                for _ in 0..remaining {
                    charge_byte_comparison(attempt)?;
                    let actual = source[position];
                    if !byte_class_contains(membership, actual) {
                        return Ok(false);
                    }
                    position = position
                        .checked_add(1)
                        .expect("validated class byte stays within selected range");
                }
            }
        }
    }
    Ok(true)
}

#[allow(
    clippy::result_large_err,
    reason = "the authenticated terminal receipt stays by value so a steady refusal never allocates"
)]
#[allow(
    dead_code,
    reason = "the leaf-local prepared kernel remains unavailable until its reviewed facade is wired"
)]
fn charge_byte_comparison(
    attempt: &mut OperationSessionAttempt<'_, Slot>,
) -> Result<(), OperationSessionAttemptError> {
    charge_byte_comparisons(attempt, 1)
}

#[allow(
    clippy::result_large_err,
    reason = "the authenticated terminal receipt stays by value so a steady refusal never allocates"
)]
fn charge_byte_comparisons(
    attempt: &mut OperationSessionAttempt<'_, Slot>,
    comparisons: usize,
) -> Result<(), OperationSessionAttemptError> {
    // Each meter precedes the corresponding comparison/source access. A
    // refusal therefore occurs before the next source block is observed.
    let comparisons =
        u64::try_from(comparisons).expect("fixed SIMD comparison width is representable");
    attempt.meter_work(comparisons)?;
    attempt.meter_source_accesses(comparisons)?;
    attempt.meter_transitions(comparisons)
}

#[allow(
    dead_code,
    reason = "the leaf-local prepared kernel remains unavailable until its reviewed facade is wired"
)]
fn byte_class_contains(membership: &[u64; 4], byte: u8) -> bool {
    let index = usize::from(byte);
    membership[index >> 6] & (1_u64 << (index & 63)) != 0
}

#[cfg(test)]
impl Slot {
    pub(super) fn test_set_counters(&mut self, counters: OperationSessionLeafCounters) {
        self.counters = counters;
    }

    pub(super) fn test_fill_canary(&mut self, seed: u64) {
        for (ordinal, values) in [
            &mut self.state,
            &mut self.generation,
            &mut self.candidates,
            &mut self.cache,
            &mut self.history,
        ]
        .into_iter()
        .enumerate()
        {
            for (index, value) in values.as_mut_slice().iter_mut().enumerate() {
                *value = seed
                    .wrapping_add(u64::try_from(ordinal).expect("small ordinal") << 32)
                    .wrapping_add(u64::try_from(index).expect("test capacity"));
            }
        }
    }

    pub(super) fn test_snapshot(&self) -> super::TestSlotSnapshot {
        super::TestSlotSnapshot {
            capacities: vec![
                self.state.capacity(),
                self.generation.capacity(),
                self.candidates.capacity(),
                self.cache.capacity(),
                self.history.capacity(),
            ],
            contents: vec![
                self.state.as_slice().to_vec(),
                self.generation.as_slice().to_vec(),
                self.candidates.as_slice().to_vec(),
                self.cache.as_slice().to_vec(),
                self.history.as_slice().to_vec(),
            ],
        }
    }
}

#[cfg(test)]
fn test_admission(state_cells: usize, candidate_cells: usize) -> OperationSessionAdmission {
    OperationSessionAdmission {
        search: super::search::SlotAdmission {
            frontier_cells: 0,
            next_frontier_cells: 0,
            generation_cells: 0,
            candidate_cells: 0,
            cache_cells: 0,
            history_cells: 0,
        },
        hot: SlotAdmission {
            state_cells,
            generation_cells: 2,
            candidate_cells,
            cache_cells: 0,
            history_cells: 0,
        },
        multi_capture: super::multi_capture::SlotAdmission {
            frontier_cells: 0,
            next_frontier_cells: 0,
            generation_cells: 0,
            tagged_candidate_cells: 0,
            tagged_cache_cells: 0,
            history_cells: 0,
            participation_cells: 0,
        },
        grep: super::grep::SlotAdmission {
            line_state_cells: 0,
            generation_cells: 0,
            candidate_cells: 0,
            cache_cells: 0,
            history_cells: 0,
        },
    }
}

#[cfg(test)]
fn test_session(state_cells: usize, candidate_cells: usize) -> OperationSession {
    let admission = test_admission(state_cells, candidate_cells);
    let prospective = OperationSession::prospective(&admission).expect("bounded admission");
    OperationSession::try_new(
        admission,
        OperationSessionConstructionLimits::exact(&prospective),
    )
    .expect("exact admission")
}

#[cfg(test)]
const TEST_PLAN_ID: [u8; 16] = [0x5a; 16];

#[cfg(test)]
fn test_request(
    reducer: OperationSessionReducer,
    source: &[u8],
    range: Range<usize>,
    prospective: OperationSessionExecutionProspective,
    run_limits: OperationSessionRunLimits,
) -> OperationSessionAttemptRequest {
    let (source_identity, order_identity, fallback_identity) = route_contract(reducer);
    let identity = OperationSessionRouteIdentity {
        session_accounting_id: OPERATION_SESSION_ACCOUNTING_ID,
        session_algorithm_version: OPERATION_SESSION_ALGORITHM_VERSION,
        session_accounting_version: OPERATION_SESSION_ACCOUNTING_VERSION,
        leaf: OperationSessionLeaf::Hot,
        reducer,
        compiled_plan_id: TEST_PLAN_ID,
        source_identity,
        order_identity,
        fallback_identity,
        leaf_algorithm_version: ALGORITHM_VERSION,
        leaf_accounting_version: ACCOUNTING_VERSION,
        leaf_accounting_id: ACCOUNTING_ID,
    };
    OperationSessionAttemptRequest::new_trusted(
        identity,
        OperationSessionInvocation {
            haystack_len: source.len(),
            range,
            required_generations: 1,
        },
        prospective,
        OperationSessionResetLimits {
            max_work: u64::MAX,
            max_clear_cells: usize::MAX,
            max_clear_bytes: usize::MAX,
        },
        run_limits,
        TEST_PLAN_ID,
    )
    .expect("trusted test request")
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "byte is masked into a fixed 256-bit test membership table"
)]
fn test_membership(bytes: &[u8]) -> [u64; 4] {
    let mut membership = [0_u64; 4];
    for byte in bytes {
        let index = usize::from(*byte);
        membership[index >> 6] |= 1_u64 << (index & 63);
    }
    membership
}

#[cfg(test)]
fn test_literal(bytes: &[u8]) -> HotByteAtom {
    let mut retained = ExactVec::try_with_capacity(bytes.len()).expect("small exact test literal");
    for byte in bytes {
        retained
            .try_push(*byte)
            .unwrap_or_else(|_| unreachable!("test literal capacity is exact"));
    }
    HotByteAtom::literal(retained).unwrap_or_else(|error| {
        if bytes.is_empty() {
            // The malformed-descriptor test deliberately bypasses the public
            // constructor to exercise program validation.
            HotByteAtom::Literal(ExactVec::default())
        } else {
            panic!("test literal construction failed: {error:?}")
        }
    })
}

#[cfg(test)]
fn test_class(membership: [u64; 4], repetitions: usize) -> HotByteAtom {
    HotByteAtom::byte_class(membership, repetitions, None).expect("valid scalar test class")
}

#[cfg(test)]
fn assert_count(receipt: &super::OperationSessionAttemptReceipt, expected: u64) {
    assert_eq!(receipt.value, Some(OperationSessionValue::Count(expected)));
    assert_eq!(receipt.actual.allocations, 0);
    assert!(receipt.closes());
}

#[cfg(test)]
fn assert_span_sum(receipt: &super::OperationSessionAttemptReceipt, expected: u64) {
    assert_eq!(
        receipt.value,
        Some(OperationSessionValue::SpanSum(expected))
    );
    assert_eq!(receipt.actual.allocations, 0);
    assert!(receipt.closes());
}

#[cfg(test)]
static HOT_KERNEL_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
fn hot_kernel_test_guard() -> std::sync::MutexGuard<'static, ()> {
    HOT_KERNEL_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[test]
fn byte_programs_preserve_leftmost_ordered_nonoverlap_count_and_span_sum() {
    let _guard = hot_kernel_test_guard();
    let foo = HotByteProgram::try_new([test_literal(b"foo")]).expect("nonempty foo");
    let bar = HotByteProgram::try_new([test_literal(b"bar")]).expect("nonempty bar");
    let ordered = [foo, bar];
    let programs = HotByteProgramSet::try_new(TEST_PLAN_ID, &ordered).expect("ordered programs");
    let source = b"foo xx bar foo";
    let prospective = programs
        .prospective(0..source.len())
        .expect("bounded prospective");

    let mut count_session = test_session(2, 2);
    let count = {
        let mut forced = count_session.forced_hot();
        forced
            .prepare_count_byte_programs(
                test_request(
                    OperationSessionReducer::Count,
                    source,
                    0..source.len(),
                    prospective,
                    OperationSessionRunLimits::exact(prospective),
                ),
                source,
                programs,
            )
            .expect("count preparation succeeds")
            .run()
            .expect("count succeeds")
    };
    assert_count(&count, 3);

    let mut span_session = test_session(2, 2);
    let span_sum = {
        let mut forced = span_session.forced_hot();
        forced
            .prepare_span_sum_byte_programs(
                test_request(
                    OperationSessionReducer::SpanSum,
                    source,
                    0..source.len(),
                    prospective,
                    OperationSessionRunLimits::exact(prospective),
                ),
                source,
                programs,
            )
            .expect("span sum preparation succeeds")
            .run()
            .expect("span sum succeeds")
    };
    assert_span_sum(&span_sum, 9);
}

#[test]
fn byte_programs_preserve_program_order_class_membership_ranges_and_malformed_bytes() {
    let _guard = hot_kernel_test_guard();
    let short = HotByteProgram::try_new([test_literal(b"fo")]).expect("nonempty short literal");
    let long = HotByteProgram::try_new([test_literal(b"foo")]).expect("nonempty long literal");
    let short_first = [short, long];
    let short_first =
        HotByteProgramSet::try_new(TEST_PLAN_ID, &short_first).expect("ordered alternatives");
    let source = b"foofoo";
    let prospective = short_first
        .prospective(0..source.len())
        .expect("bounded prospective");
    let mut session = test_session(2, 2);
    let receipt = {
        let mut forced = session.forced_hot();
        forced
            .prepare_span_sum_byte_programs(
                test_request(
                    OperationSessionReducer::SpanSum,
                    source,
                    0..source.len(),
                    prospective,
                    OperationSessionRunLimits::exact(prospective),
                ),
                source,
                short_first,
            )
            .expect("ordered span sum preparation")
            .run()
            .expect("ordered span sum")
    };
    assert_span_sum(&receipt, 4);

    let class =
        HotByteProgram::try_new([test_class(test_membership(&[0xff]), 1)]).expect("nonempty class");
    let classes = [class];
    let classes = HotByteProgramSet::try_new(TEST_PLAN_ID, &classes).expect("class program");
    let malformed = [b'x', 0xff, b'y', 0xff, b'z'];
    let prospective = classes
        .prospective(1..4)
        .expect("bounded malformed prospective");
    let mut session = test_session(1, 1);
    let receipt = {
        let mut forced = session.forced_hot();
        forced
            .prepare_count_byte_programs(
                test_request(
                    OperationSessionReducer::Count,
                    &malformed,
                    1..4,
                    prospective,
                    OperationSessionRunLimits::exact(prospective),
                ),
                &malformed,
                classes,
            )
            .expect("malformed byte classification preparation")
            .run()
            .expect("malformed byte classification")
    };
    assert_count(&receipt, 2);
}

#[test]
fn byte_program_workspace_preparation_and_run_limits_refuse_before_reset_or_source() {
    let _guard = hot_kernel_test_guard();
    let program = HotByteProgram::try_new([test_literal(b"needle")]).expect("nonempty program");
    let programs = [program];
    let programs = HotByteProgramSet::try_new(TEST_PLAN_ID, &programs).expect("program set");
    let source = b"needle";
    let prospective = programs
        .prospective(0..source.len())
        .expect("bounded prospective");

    let mut state_one_below = test_session(0, 1);
    let before = state_one_below.counters(OperationSessionLeaf::Hot);
    let error = {
        let mut forced = state_one_below.forced_hot();
        forced
            .prepare_count_byte_programs(
                test_request(
                    OperationSessionReducer::Count,
                    source,
                    0..source.len(),
                    prospective,
                    OperationSessionRunLimits::exact(prospective),
                ),
                source,
                programs,
            )
            .expect_err("one-below state capacity refuses")
    };
    assert_eq!(
        error,
        HotKernelPreparationError::StateWorkspaceTooSmall {
            needed: 1,
            available: 0,
        }
    );
    assert_eq!(state_one_below.counters(OperationSessionLeaf::Hot), before);

    let mut candidate_one_below = test_session(1, 0);
    let before = candidate_one_below.counters(OperationSessionLeaf::Hot);
    let error = {
        let mut forced = candidate_one_below.forced_hot();
        forced
            .prepare_count_byte_programs(
                test_request(
                    OperationSessionReducer::Count,
                    source,
                    0..source.len(),
                    prospective,
                    OperationSessionRunLimits::exact(prospective),
                ),
                source,
                programs,
            )
            .expect_err("one-below candidate capacity refuses")
    };
    assert_eq!(
        error,
        HotKernelPreparationError::CandidateWorkspaceTooSmall {
            needed: 1,
            available: 0,
        }
    );
    assert_eq!(
        candidate_one_below.counters(OperationSessionLeaf::Hot),
        before
    );

    let mut run_one_below = test_session(1, 1);
    let before = run_one_below.counters(OperationSessionLeaf::Hot);
    let mut one_below = OperationSessionRunLimits::exact(prospective);
    one_below.max_work = prospective.work.checked_sub(1).expect("positive work");
    let error = {
        let mut forced = run_one_below.forced_hot();
        let mut request = test_request(
            OperationSessionReducer::Count,
            source,
            0..source.len(),
            prospective,
            one_below,
        );
        // This source mismatch would be a typed preparation failure only when
        // common preflight passes. The one-below common terminal must win.
        request.invocation.haystack_len = source.len().checked_add(1).expect("small source");
        forced
            .prepare_count_byte_programs(request, source, programs)
            .expect("common one-below run-limit terminal must forward")
            .run()
            .expect_err("one-below run limit refuses")
    };
    let OperationSessionAttemptError::Refused(receipt) = error else {
        panic!("expected closed pre-source run refusal");
    };
    assert_eq!(
        receipt.terminal,
        OperationSessionTerminal::Refused(OperationSessionResource::ExecutionWork)
    );
    assert_eq!(
        receipt.actual,
        super::OperationSessionExecutionActual::default()
    );
    assert!(receipt.reset.prospective.is_none());
    assert!(receipt.closes());
    assert_eq!(run_one_below.counters(OperationSessionLeaf::Hot), before);
}

#[test]
fn byte_programs_require_exact_source_binding_and_exact_prospective() {
    let _guard = hot_kernel_test_guard();
    let program = HotByteProgram::try_new([test_literal(b"a")]).expect("nonempty program");
    let programs = [program];
    let programs = HotByteProgramSet::try_new(TEST_PLAN_ID, &programs).expect("program set");
    let source = b"a";
    let prospective = programs
        .prospective(0..source.len())
        .expect("bounded prospective");
    let mut session = test_session(1, 1);
    let before = session.counters(OperationSessionLeaf::Hot);
    let mut request = test_request(
        OperationSessionReducer::Count,
        source,
        0..source.len(),
        prospective,
        OperationSessionRunLimits::exact(prospective),
    );
    request.invocation.haystack_len = source.len().checked_add(1).expect("small source");
    let error = {
        let mut forced = session.forced_hot();
        forced
            .prepare_count_byte_programs(request, source, programs)
            .expect_err("length binding refuses")
    };
    assert_eq!(
        error,
        HotKernelPreparationError::SourceLengthMismatch {
            declared: 2,
            actual: 1,
        }
    );
    assert_eq!(session.counters(OperationSessionLeaf::Hot), before);

    let mut session = test_session(1, 1);
    let before = session.counters(OperationSessionLeaf::Hot);
    let mut inexact = prospective;
    inexact.source_accesses = inexact
        .source_accesses
        .checked_sub(1)
        .expect("positive literal source bound");
    let error = {
        let mut forced = session.forced_hot();
        forced
            .prepare_count_byte_programs(
                test_request(
                    OperationSessionReducer::Count,
                    source,
                    0..source.len(),
                    inexact,
                    OperationSessionRunLimits::exact(inexact),
                ),
                source,
                programs,
            )
            .expect_err("inexact prospective refuses")
    };
    assert!(matches!(
        error,
        HotKernelPreparationError::ProspectiveMismatch
    ));
    assert_eq!(session.counters(OperationSessionLeaf::Hot), before);
}

#[test]
fn byte_programs_refuse_same_width_substituted_descriptor_plan_before_reset() {
    let _guard = hot_kernel_test_guard();
    let program = HotByteProgram::try_new([test_literal(b"a")]).expect("nonempty program");
    let programs = [program];
    let substituted_plan_id = [0x6b; 16];
    let programs = HotByteProgramSet::try_new(substituted_plan_id, &programs)
        .expect("nonzero substituted descriptor plan");
    let source = b"a";
    let prospective = programs
        .prospective(0..source.len())
        .expect("bounded prospective");
    let mut session = test_session(1, 1);
    let before = session.counters(OperationSessionLeaf::Hot);
    let error = {
        let mut forced = session.forced_hot();
        forced
            .prepare_count_byte_programs(
                test_request(
                    OperationSessionReducer::Count,
                    source,
                    0..source.len(),
                    prospective,
                    OperationSessionRunLimits::exact(prospective),
                ),
                source,
                programs,
            )
            .expect("descriptor mismatch must forward to the common receipt path")
            .run()
            .expect_err("substituted plan refuses")
    };
    let OperationSessionAttemptError::Refused(receipt) = error else {
        panic!("expected closed pre-reset descriptor refusal");
    };
    assert_eq!(receipt.terminal, OperationSessionTerminal::IdentityMismatch);
    assert_eq!(
        receipt.actual,
        super::OperationSessionExecutionActual::default()
    );
    assert!(receipt.reset.prospective.is_none());
    assert!(receipt.closes());
    assert_eq!(session.counters(OperationSessionLeaf::Hot), before);
}

#[test]
fn byte_program_descriptors_reject_empty_atoms_and_zero_plan_identity() {
    let _guard = hot_kernel_test_guard();
    assert!(matches!(
        HotByteProgram::try_new([test_literal(b"")]),
        Err(HotKernelPreparationError::EmptyLiteral)
    ));
    let program = HotByteProgram::try_new([test_literal(b"a")]).expect("nonempty program");
    let programs = [program];
    assert!(matches!(
        HotByteProgramSet::try_new([0; 16], &programs),
        Err(HotKernelPreparationError::ZeroCompiledPlanId)
    ));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the allocation and doubling assertions share one serialized allocator region"
)]
fn byte_programs_have_zero_steady_allocations_and_doubling_source_counters() {
    let _guard = hot_kernel_test_guard();
    let program = HotByteProgram::try_new([test_literal(b"z")]).expect("nonempty program");
    let programs = [program];
    let programs = HotByteProgramSet::try_new(TEST_PLAN_ID, &programs).expect("program set");
    let short = b"aaaaaaaa";
    let long = b"aaaaaaaaaaaaaaaa";

    let short_prospective = programs
        .prospective(0..short.len())
        .expect("short prospective");
    let mut short_session = test_session(1, 1);
    let short_receipt = {
        let mut forced = short_session.forced_hot();
        forced
            .prepare_count_byte_programs(
                test_request(
                    OperationSessionReducer::Count,
                    short,
                    0..short.len(),
                    short_prospective,
                    OperationSessionRunLimits::exact(short_prospective),
                ),
                short,
                programs,
            )
            .expect("short no-match preparation")
            .run()
            .expect("short no-match")
    };
    assert_count(&short_receipt, 0);

    let long_prospective = programs
        .prospective(0..long.len())
        .expect("long prospective");
    let mut long_session = test_session(1, 1);
    let long_receipt = {
        let mut forced = long_session.forced_hot();
        forced
            .prepare_count_byte_programs(
                test_request(
                    OperationSessionReducer::Count,
                    long,
                    0..long.len(),
                    long_prospective,
                    OperationSessionRunLimits::exact(long_prospective),
                ),
                long,
                programs,
            )
            .expect("long no-match preparation")
            .run()
            .expect("long no-match")
    };
    assert_count(&long_receipt, 0);
    assert_eq!(
        long_receipt.actual.source_accesses,
        short_receipt
            .actual
            .source_accesses
            .checked_mul(2)
            .expect("small doubling")
    );
    assert_eq!(
        long_receipt.actual.transitions,
        short_receipt
            .actual
            .transitions
            .checked_mul(2)
            .expect("small doubling")
    );
    assert_eq!(
        long_receipt.actual.candidates,
        short_receipt
            .actual
            .candidates
            .checked_mul(2)
            .expect("small doubling")
    );

    let repeated_prospective = programs
        .prospective(0..short.len())
        .expect("bounded repeated prospective");
    let requests = core::array::from_fn::<_, 4, _>(|_| {
        test_request(
            OperationSessionReducer::Count,
            short,
            0..short.len(),
            repeated_prospective,
            OperationSessionRunLimits::exact(repeated_prospective),
        )
    });
    let mut repeated_session = test_session(1, 1);
    let (receipts, allocation_change) = {
        let region = stats_alloc::Region::new(super::OPERATION_SESSION_TEST_ALLOCATOR);
        let receipts = requests.map(|request| {
            let mut forced = repeated_session.forced_hot();
            forced
                .prepare_count_byte_programs(request, short, programs)
                .expect("repeated no-match preparation")
                .run()
                .expect("repeated no-match")
        });
        (receipts, region.change())
    };
    assert_eq!(allocation_change, stats_alloc::Stats::default());
    for receipt in &receipts {
        assert_count(receipt, 0);
    }
}
