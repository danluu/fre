//! Forced, bounded whole-operation reducers over prioritized automata.
//!
//! This layer deliberately consumes already-lowered automaton facts. It does
//! not parse syntax, recognize particular expressions, or choose an execution
//! route after seeing source bytes. Every prepared plan owns the automaton and
//! the accept-action sidecar that its route was proved against.

// Rust 1.74 does not understand lint-reason attribute syntax. The few
// complexity allowances below are kept on the individual audited functions.
#![allow(clippy::allow_attributes_without_reason)]

use core::{fmt, marker::PhantomData, mem::size_of};

use crate::{k0::zero_width_edge_enabled, plan::plan_index, Automaton, StateRole};

const BYTE_VALUES: usize = 256;
const NO_DFA_STATE: u32 = u32::MAX;
const NO_TAGGED_EDGE: u32 = u32::MAX;

/// Accounting identity for the preparation and direct-execution ledgers.
pub const PRIORITY_ACCOUNTING_ID: &str = "fre-automata.priority-preparation.v6";

/// A stable source-pattern ordinal attached to an accept state.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PatternOrdinal(u32);

impl PatternOrdinal {
    /// Construct an ordinal in source-pattern order.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Return the source-pattern ordinal.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Capabilities proved for an accept action.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ActionCapabilities(u8);

impl ActionCapabilities {
    /// The terminal may report a selected match.
    pub const MATCH: Self = Self(1);
    /// The terminal may participate in direct whole-operation reducers.
    pub const DIRECT_REDUCE: Self = Self(2);
    /// The terminal retains the ordinal/action information needed by a future
    /// ordered Build-Many facade.
    pub const BUILD_MANY: Self = Self(4);

    /// No action capability.
    #[must_use]
    pub const fn none() -> Self {
        Self(0)
    }

    /// All capabilities understood by this version.
    #[must_use]
    pub const fn all() -> Self {
        Self(Self::MATCH.0 | Self::DIRECT_REDUCE.0 | Self::BUILD_MANY.0)
    }

    /// Combine two capability sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether every bit in `required` is present.
    #[must_use]
    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }
}

/// Immutable action metadata for one accept state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PatternAction {
    ordinal: PatternOrdinal,
    capabilities: ActionCapabilities,
}

/// One selected whole-match action observed by a forced priority route.
///
/// This is a copy-only entry in the explicit, pre-reserved Build-Many trace.
/// Ordinary direct reduction never allocates trace storage; callers opt into
/// the separately admitted trace route when they need ordinal diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PriorityMatch {
    ordinal: PatternOrdinal,
    start: usize,
    end: usize,
}

impl PriorityMatch {
    pub(crate) const fn from_parts(ordinal: PatternOrdinal, start: usize, end: usize) -> Self {
        Self {
            ordinal,
            start,
            end,
        }
    }

    /// Source-pattern ordinal selected for this match.
    #[must_use]
    pub const fn ordinal(self) -> PatternOrdinal {
        self.ordinal
    }

    /// Inclusive start of the selected half-open span.
    #[must_use]
    pub const fn start(self) -> usize {
        self.start
    }

    /// Exclusive end of the selected half-open span.
    #[must_use]
    pub const fn end(self) -> usize {
        self.end
    }
}

impl PatternAction {
    /// Bind a source ordinal and its proved capabilities.
    #[must_use]
    pub const fn new(ordinal: PatternOrdinal, capabilities: ActionCapabilities) -> Self {
        Self {
            ordinal,
            capabilities,
        }
    }

    /// Source-pattern ordinal selected at this terminal.
    #[must_use]
    pub const fn ordinal(self) -> PatternOrdinal {
        self.ordinal
    }

    /// Capabilities proved for this terminal.
    #[must_use]
    pub const fn capabilities(self) -> ActionCapabilities {
        self.capabilities
    }
}

/// Canonical proof of match-length behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MatchLengthProof {
    /// No path from the start state can reach an accept state.
    Empty,
    /// No finite maximum was proved.
    Unbounded,
    /// Every match is between these inclusive byte lengths.
    Finite {
        minimum_bytes: usize,
        maximum_bytes: usize,
    },
    /// Every match has this exact byte length.
    Exact(usize),
}

impl MatchLengthProof {
    const fn maximum(self) -> Option<usize> {
        match self {
            Self::Empty => Some(0),
            Self::Unbounded => None,
            Self::Finite { maximum_bytes, .. } => Some(maximum_bytes),
            Self::Exact(bytes) => Some(bytes),
        }
    }

    const fn exact(self) -> Option<usize> {
        match self {
            Self::Exact(bytes) => Some(bytes),
            Self::Empty | Self::Unbounded | Self::Finite { .. } => None,
        }
    }
}

/// Progress rule after a selected empty match.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum EmptyMatchProgress {
    /// Advance one arbitrary byte, visiting the terminal boundary once.
    Byte,
    /// Advance by a decoded Unicode scalar boundary.
    ///
    /// Priority preparation currently refuses this mode instead of silently
    /// substituting byte progress.
    UnicodeScalar,
}

/// The exact execution route selected before source bytes are observed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ForcedExecution {
    /// Reverse-row topologically ordered sparse priority evaluation.
    Sparse,
    /// Fully materialized ordered-subset deterministic automaton.
    FullDfa,
    /// Bounded ordered-subset transition cache populated by source bytes.
    LazyDfa,
    /// Finite-route policy: a proved finite width uses a static reducer ring;
    /// otherwise preparation selects an authenticated per-input,
    /// sparse-equivalent fallback.
    FiniteHorizon,
}

/// Concrete kernel authenticated beneath an explicit forced execution route.
///
/// Full and lazy requests retain their classic fixed-width DFA kernels where
/// that proof is available. Variable-width or boundary-sensitive requests use
/// the tagged reverse kernel instead; this is intentionally visible to
/// consumers rather than being reported as an ordinary DFA run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PriorityExecutionKernel {
    SparseReverse,
    FiniteHorizonReverse,
    /// A finite-route request that falls back to the sparse reverse kernel.
    ///
    /// Its preflight authenticates the input length and retains one suffix
    /// slot per source boundary because the pattern's match width is
    /// unbounded. It is deliberately not a finite-memory static-horizon
    /// kernel: its prospective execution bounds equal the sparse route.
    InputBoundedReverse,
    FullDfa,
    LazyDfa,
    FullTaggedReverse,
    LazyTaggedReverse,
}

/// Target capabilities supplied independently of source contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
// The booleans intentionally mirror independently deployable requested-route
// capabilities rather than encoding mutually exclusive states. `sparse` also
// authorizes concrete routes that execute the reverse-row sparse substrate.
#[allow(clippy::struct_excessive_bools)]
pub struct PriorityTarget {
    /// Requested sparse route, its concrete sparse reverse kernel, and the
    /// sparse reverse substrate used by concrete fallback kernels.
    pub sparse: bool,
    /// Requested `FullDfa` route and its classic fixed-width DFA kernel.
    pub full_dfa: bool,
    /// Requested `LazyDfa` route and its classic fixed-width DFA kernel.
    pub lazy_dfa: bool,
    /// Requested `FiniteHorizon` policy and, together with `sparse`, its
    /// input-bounded sparse-equivalent fallback substrate.
    pub finite_horizon: bool,
    pub actions: ActionCapabilities,
}

impl PriorityTarget {
    /// A portable target supporting every route in this module.
    #[must_use]
    pub const fn portable() -> Self {
        Self {
            sparse: true,
            full_dfa: true,
            lazy_dfa: true,
            finite_horizon: true,
            actions: ActionCapabilities::all(),
        }
    }

    /// Whether this target admits the requested public route.
    #[must_use]
    pub const fn supports_execution(self, execution: ForcedExecution) -> bool {
        match execution {
            ForcedExecution::Sparse => self.sparse,
            ForcedExecution::FullDfa => self.full_dfa,
            ForcedExecution::LazyDfa => self.lazy_dfa,
            ForcedExecution::FiniteHorizon => self.finite_horizon,
        }
    }

    /// Whether this target declares every substrate used by `kernel`.
    ///
    /// A requested route alone is insufficient because preparation can select
    /// a concrete fallback or variable-width tagged kernel beneath it.
    #[must_use]
    pub const fn supports_kernel(self, kernel: PriorityExecutionKernel) -> bool {
        match kernel {
            PriorityExecutionKernel::SparseReverse => self.sparse,
            PriorityExecutionKernel::FiniteHorizonReverse => self.finite_horizon,
            PriorityExecutionKernel::InputBoundedReverse => self.finite_horizon && self.sparse,
            PriorityExecutionKernel::FullDfa => self.full_dfa,
            PriorityExecutionKernel::LazyDfa => self.lazy_dfa,
            PriorityExecutionKernel::FullTaggedReverse => self.full_dfa && self.sparse,
            PriorityExecutionKernel::LazyTaggedReverse => self.lazy_dfa && self.sparse,
        }
    }
}

impl PriorityExecutionKernel {
    /// Whether this concrete route is the per-input sparse-equivalent
    /// fallback selected beneath a `FiniteHorizon` request.
    #[must_use]
    pub const fn is_sparse_equivalent_fallback(self) -> bool {
        matches!(self, Self::InputBoundedReverse)
    }
}

/// A preparation resource with an independent hard limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PreparationResource {
    PatternTerminals,
    DfaStates,
    TransitionCells,
    SubsetItems,
    TaggedDispatchStates,
    TaggedDispatchCells,
    TaggedCandidateItems,
    Work,
    PersistentBytes,
    PeakBytes,
    AllocationAttempts,
}

impl fmt::Display for PreparationResource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::PatternTerminals => "pattern terminals",
            Self::DfaStates => "DFA states",
            Self::TransitionCells => "transition cells",
            Self::SubsetItems => "DFA subset items",
            Self::TaggedDispatchStates => "tagged dispatch states",
            Self::TaggedDispatchCells => "tagged dispatch cells",
            Self::TaggedCandidateItems => "tagged candidate items",
            Self::Work => "preparation work",
            Self::PersistentBytes => "persistent bytes",
            Self::PeakBytes => "preparation peak bytes",
            Self::AllocationAttempts => "allocation attempts",
        };
        formatter.write_str(name)
    }
}

/// Hard limits for one forced preparation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparationLimits {
    pub max_pattern_terminals: usize,
    pub max_dfa_states: usize,
    pub max_transition_cells: usize,
    pub max_subset_items: usize,
    /// Persistent state descriptors for a tagged variable-width route.
    pub max_tagged_dispatch_states: usize,
    /// Persistent static dispatch cells for a tagged variable-width route.
    pub max_tagged_dispatch_cells: usize,
    /// Persistent ordered candidate entries for a tagged variable-width route.
    pub max_tagged_candidate_items: usize,
    pub max_work: u64,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
    pub max_allocation_attempts: usize,
}

impl PreparationLimits {
    /// Disable caller-selected limits while retaining checked arithmetic and
    /// the `u32` representation boundary.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_pattern_terminals: usize::MAX,
            max_dfa_states: usize::MAX,
            max_transition_cells: usize::MAX,
            max_subset_items: usize::MAX,
            max_tagged_dispatch_states: usize::MAX,
            max_tagged_dispatch_cells: usize::MAX,
            max_tagged_candidate_items: usize::MAX,
            max_work: u64::MAX,
            max_persistent_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
            max_allocation_attempts: usize::MAX,
        }
    }
}

impl Default for PreparationLimits {
    fn default() -> Self {
        Self {
            max_pattern_terminals: 1_000_000,
            max_dfa_states: 65_536,
            max_transition_cells: 16_777_216,
            max_subset_items: 16_777_216,
            // Tagged priority dispatch has one descriptor per lowered state;
            // retain a bounded 128K envelope for the authenticated large
            // whole-automata rows without changing classic DFA policy.
            max_tagged_dispatch_states: 131_072,
            max_tagged_dispatch_cells: 16_777_216,
            max_tagged_candidate_items: 16_777_216,
            max_work: 1_000_000_000,
            max_persistent_bytes: 536_870_912,
            max_peak_bytes: 805_306_368,
            max_allocation_attempts: 100_000_000,
        }
    }
}

/// Exact successful preparation accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparationAccounting {
    pub prospective: PreparationProspective,
    pub pattern_terminals: usize,
    pub dfa_states: usize,
    pub transition_cells: usize,
    pub subset_items: usize,
    /// Exact persistent tagged-dispatch state descriptors.
    pub tagged_dispatch_states: usize,
    /// Exact persistent tagged-dispatch cells.
    pub tagged_dispatch_cells: usize,
    /// Exact persistent tagged ordered-candidate entries.
    pub tagged_candidate_items: usize,
    pub work: u64,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
    pub allocation_attempts: usize,
}

/// Construction bounds sealed before a prepared route is returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparationProspective {
    pub pattern_terminals: usize,
    pub dfa_states: usize,
    pub transition_cells: usize,
    pub subset_items: usize,
    /// Source-independent tagged-dispatch state capacity.
    pub tagged_dispatch_states: usize,
    /// Source-independent tagged-dispatch cell capacity.
    pub tagged_dispatch_cells: usize,
    /// Source-independent tagged ordered-candidate capacity.
    pub tagged_candidate_items: usize,
    pub work: u64,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
    pub allocation_attempts: usize,
}

/// A semantic, structural, arithmetic, allocation, or bounded refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PreparationError {
    ActionTableLength {
        states: usize,
        actions: usize,
    },
    MissingAcceptAction {
        state: usize,
    },
    ActionOnNonAccept {
        state: usize,
    },
    MissingActionCapability {
        state: usize,
        required: ActionCapabilities,
        available: ActionCapabilities,
    },
    NonCanonicalPatternOrder {
        state: usize,
        earlier_edge: usize,
        earlier_maximum: PatternOrdinal,
        later_edge: usize,
        later_minimum: PatternOrdinal,
    },
    UnsupportedTarget {
        execution: ForcedExecution,
    },
    /// The requested route was allowed, but its selected concrete kernel was
    /// not declared by the target.
    UnsupportedTargetKernel {
        execution: ForcedExecution,
        kernel: PriorityExecutionKernel,
    },
    UnsupportedTargetAction {
        required: ActionCapabilities,
        available: ActionCapabilities,
    },
    UnsupportedUnicodeEmptyProgress,
    InvalidFiniteLengthProof {
        minimum_bytes: usize,
        maximum_bytes: usize,
    },
    MatchLengthProofMismatch {
        declared: MatchLengthProof,
        intrinsic: MatchLengthProof,
    },
    MissingFiniteHorizonProof,
    DfaRequiresExactLength,
    DfaRequiresNonEmptyMatch,
    DfaRequiresZeroWidthFreeAutomaton {
        state: usize,
    },
    DfaRequiresByteDeterminism {
        state: usize,
        byte: u8,
    },
    ResourceLimit {
        resource: PreparationResource,
        needed: usize,
        limit: usize,
    },
    WorkLimit {
        needed: u64,
        limit: u64,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    AllocationFailed {
        bytes: usize,
    },
    InternalInvariant {
        detail: &'static str,
    },
}

impl fmt::Display for PreparationError {
    #[allow(
        clippy::too_many_lines,
        reason = "each terminal preparation failure retains a distinct exact diagnostic"
    )]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ActionTableLength { states, actions } => {
                write!(
                    formatter,
                    "automaton has {states} states but {actions} accept-action slots"
                )
            }
            Self::MissingAcceptAction { state } => {
                write!(formatter, "accept state {state} has no pattern action")
            }
            Self::ActionOnNonAccept { state } => {
                write!(formatter, "non-accept state {state} has a pattern action")
            }
            Self::MissingActionCapability {
                state,
                required,
                available,
            } => write!(
                formatter,
                "accept state {state} has capabilities {available:?}, missing {required:?}"
            ),
            Self::NonCanonicalPatternOrder {
                state,
                earlier_edge,
                earlier_maximum,
                later_edge,
                later_minimum,
            } => write!(
                formatter,
                "state {state} orders edge {earlier_edge} reaching through ordinal {} before edge {later_edge} reaching ordinal {}",
                earlier_maximum.get(),
                later_minimum.get()
            ),
            Self::UnsupportedTarget { execution } => {
                write!(
                    formatter,
                    "target does not support forced route {execution:?}"
                )
            }
            Self::UnsupportedTargetKernel { execution, kernel } => write!(
                formatter,
                "target does not support concrete kernel {kernel:?} selected for forced route {execution:?}"
            ),
            Self::UnsupportedTargetAction {
                required,
                available,
            } => write!(
                formatter,
                "target action capabilities {available:?} do not contain {required:?}"
            ),
            Self::UnsupportedUnicodeEmptyProgress => {
                formatter.write_str("Unicode-scalar empty progress is not implemented")
            }
            Self::InvalidFiniteLengthProof {
                minimum_bytes,
                maximum_bytes,
            } => write!(
                formatter,
                "finite match-length proof has minimum {minimum_bytes} above maximum {maximum_bytes}"
            ),
            Self::MatchLengthProofMismatch {
                declared,
                intrinsic,
            } => write!(
                formatter,
                "declared match-length proof {declared:?} disagrees with intrinsic automaton proof {intrinsic:?}"
            ),
            Self::MissingFiniteHorizonProof => {
                formatter.write_str(
                    "static finite-horizon execution requires a finite match-length proof",
                )
            }
            Self::DfaRequiresExactLength => {
                formatter.write_str("DFA direct reduction requires an exact match-length proof")
            }
            Self::DfaRequiresNonEmptyMatch => {
                formatter.write_str("classic DFA direct reduction refuses an empty matching language")
            }
            Self::DfaRequiresZeroWidthFreeAutomaton { state } => write!(
                formatter,
                "DFA direct reduction refuses zero-width/split state {state}"
            ),
            Self::DfaRequiresByteDeterminism { state, byte } => write!(
                formatter,
                "DFA direct reduction sees overlapping transitions at state {state} for byte {byte:#04x}"
            ),
            Self::ResourceLimit {
                resource,
                needed,
                limit,
            } => write!(
                formatter,
                "preparation needs {needed} {resource}, exceeding {limit}"
            ),
            Self::WorkLimit { needed, limit } => write!(
                formatter,
                "preparation needs {needed} work, exceeding {limit}"
            ),
            Self::ArithmeticOverflow { computation } => {
                write!(
                    formatter,
                    "arithmetic overflow while computing {computation}"
                )
            }
            Self::AllocationFailed { bytes } => {
                write!(formatter, "failed to allocate {bytes} preparation bytes")
            }
            Self::InternalInvariant { detail } => {
                write!(formatter, "priority preparation invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for PreparationError {}

/// Canonical lowered facts consumed by forced priority preparation.
#[derive(Clone, Debug)]
pub struct PriorityAutomataFacts {
    automaton: Automaton,
    actions: Box<[Option<PatternAction>]>,
    match_length: MatchLengthProof,
    empty_progress: EmptyMatchProgress,
}

impl PriorityAutomataFacts {
    /// Bind a validated automaton to its exact state-indexed action sidecar and
    /// canonical length/progress proofs.
    #[must_use]
    pub fn new(
        automaton: Automaton,
        actions: Vec<Option<PatternAction>>,
        match_length: MatchLengthProof,
        empty_progress: EmptyMatchProgress,
    ) -> Self {
        Self {
            automaton,
            actions: actions.into_boxed_slice(),
            match_length,
            empty_progress,
        }
    }

    /// Prepare exactly `execution`; this function never chooses another route.
    pub fn prepare_forced<O: DirectReduceValue>(
        self,
        execution: ForcedExecution,
        target: PriorityTarget,
        limits: PreparationLimits,
    ) -> Result<PreparedPriorityAutomaton<O>, PreparationError> {
        prepare::<O>(
            self,
            execution,
            target,
            limits,
            ActionCapabilities::MATCH.union(ActionCapabilities::DIRECT_REDUCE),
        )
    }

    /// Prepare one exact route for an ordered multi-pattern value reducer.
    ///
    /// Unlike [`Self::prepare_forced`], this requires every terminal and the
    /// target to retain the `BUILD_MANY` action capability. The extra gate
    /// prevents a caller from presenting an ordinary single-pattern direct
    /// reducer as an ordinal-preserving multi-pattern artifact.
    pub fn prepare_build_many_forced<O: DirectReduceValue>(
        self,
        execution: ForcedExecution,
        target: PriorityTarget,
        limits: PreparationLimits,
    ) -> Result<PreparedPriorityAutomaton<O>, PreparationError> {
        prepare::<O>(
            self,
            execution,
            target,
            limits,
            ActionCapabilities::MATCH
                .union(ActionCapabilities::DIRECT_REDUCE)
                .union(ActionCapabilities::BUILD_MANY),
        )
    }
}

mod direct_sealed {
    pub trait Sealed {}
}

/// A sealed typed direct whole-operation reducer.
pub trait DirectReduceValue: direct_sealed::Sealed {
    /// Complete reducer output.
    type Output: Clone;

    #[doc(hidden)]
    fn zero() -> Self::Output;

    #[doc(hidden)]
    fn append(
        value: Self::Output,
        start: usize,
        end: usize,
        ordinal: PatternOrdinal,
    ) -> Result<Self::Output, ReduceError>;

    #[doc(hidden)]
    fn prepend(
        value: Self::Output,
        start: usize,
        end: usize,
        ordinal: PatternOrdinal,
    ) -> Result<Self::Output, ReduceError>;
}

/// Count selected non-overlapping matches.
#[derive(Clone, Copy, Debug, Default)]
pub struct DirectCount;

impl direct_sealed::Sealed for DirectCount {}

impl DirectReduceValue for DirectCount {
    type Output = u64;

    fn zero() -> Self::Output {
        0
    }

    fn append(
        value: Self::Output,
        _start: usize,
        _end: usize,
        _ordinal: PatternOrdinal,
    ) -> Result<Self::Output, ReduceError> {
        value.checked_add(1).ok_or(ReduceError::OutputOverflow {
            output: "match count",
        })
    }

    fn prepend(
        value: Self::Output,
        start: usize,
        end: usize,
        ordinal: PatternOrdinal,
    ) -> Result<Self::Output, ReduceError> {
        Self::append(value, start, end, ordinal)
    }
}

/// Sum selected non-overlapping match lengths.
#[derive(Clone, Copy, Debug, Default)]
pub struct DirectSpanSum;

impl direct_sealed::Sealed for DirectSpanSum {}

impl DirectReduceValue for DirectSpanSum {
    type Output = u64;

    fn zero() -> Self::Output {
        0
    }

    fn append(
        value: Self::Output,
        start: usize,
        end: usize,
        _ordinal: PatternOrdinal,
    ) -> Result<Self::Output, ReduceError> {
        let length = end
            .checked_sub(start)
            .ok_or(ReduceError::InternalInvariant {
                detail: "selected match end precedes its start",
            })?;
        let length = u64::try_from(length).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "selected match length conversion",
        })?;
        value
            .checked_add(length)
            .ok_or(ReduceError::OutputOverflow {
                output: "matched-byte sum",
            })
    }

    fn prepend(
        value: Self::Output,
        start: usize,
        end: usize,
        ordinal: PatternOrdinal,
    ) -> Result<Self::Output, ReduceError> {
        Self::append(value, start, end, ordinal)
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default)]
struct DirectTrace;

#[cfg(test)]
impl direct_sealed::Sealed for DirectTrace {}

#[cfg(test)]
impl DirectReduceValue for DirectTrace {
    type Output = Vec<(u32, usize, usize)>;

    fn zero() -> Self::Output {
        Vec::new()
    }

    fn append(
        mut value: Self::Output,
        start: usize,
        end: usize,
        ordinal: PatternOrdinal,
    ) -> Result<Self::Output, ReduceError> {
        value.push((ordinal.get(), start, end));
        Ok(value)
    }

    fn prepend(
        mut value: Self::Output,
        start: usize,
        end: usize,
        ordinal: PatternOrdinal,
    ) -> Result<Self::Output, ReduceError> {
        value.insert(0, (ordinal.get(), start, end));
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DfaTransition {
    next: u32,
    action: Option<PatternAction>,
}

#[derive(Clone, Debug)]
struct FullDfa {
    subsets: Box<[Box<[u32]>]>,
    transitions: Box<[DfaTransition]>,
}

#[derive(Clone, Debug)]
enum SparseEvaluation {
    Acyclic(Box<[u32]>),
    Cyclic,
}

/// One inclusive, run-length encoded static byte-dispatch interval.
///
/// `first_edge` is an ordered candidate *start*, not an outcome.  A tagged
/// execution still checks every later compatible edge against the current
/// reverse row, so a lower-priority overlap remains available when an earlier
/// candidate cannot complete at this boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TaggedDispatchInterval {
    byte_start: u8,
    byte_end: u8,
    first_edge: u32,
}

/// A half-open range into a route-owned static table.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct TaggedDispatchRange {
    start: u32,
    end: u32,
}

/// Exact persistent tagged program resources, kept separate from classic DFA
/// accounting so a tagged route cannot be represented as a zero-cost sparse
/// fallback.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct TaggedProgramResources {
    states: usize,
    cells: usize,
    candidates: usize,
}

/// Fully materialized static ordered-candidate dispatch for a variable-width
/// priority route.  The RLE table is source-independent and is consulted only
/// for consuming states; assertions and candidate outcomes stay dynamic.
#[derive(Clone, Debug)]
struct FullTaggedTransducer {
    evaluation: SparseEvaluation,
    state_intervals: Box<[TaggedDispatchRange]>,
    intervals: Box<[TaggedDispatchInterval]>,
    resources: TaggedProgramResources,
}

/// Lazy tagged route layout.  State edge ranges are persistent, while the
/// byte-to-first-candidate mapping is populated in a bounded execution cache.
#[derive(Clone, Debug)]
struct LazyTaggedTransducer {
    evaluation: SparseEvaluation,
    state_edges: Box<[TaggedDispatchRange]>,
    resources: TaggedProgramResources,
}

#[derive(Clone, Debug)]
enum PreparedRoute {
    Sparse {
        evaluation: SparseEvaluation,
    },
    FullDfa(FullDfa),
    FullTransducer(FullTaggedTransducer),
    LazyDfa,
    LazyTransducer(LazyTaggedTransducer),
    FiniteHorizon {
        maximum_match_bytes: usize,
        evaluation: SparseEvaluation,
    },
    /// A finite-route request with no static match-width bound. It falls back
    /// to sparse suffix storage bounded by the per-run input length.
    InputBoundedSparseFallback {
        evaluation: SparseEvaluation,
    },
}

impl PreparedRoute {
    /// Concrete executor selected by this unpublished route.
    const fn kernel(&self) -> PriorityExecutionKernel {
        match self {
            Self::Sparse { .. } => PriorityExecutionKernel::SparseReverse,
            Self::FiniteHorizon { .. } => PriorityExecutionKernel::FiniteHorizonReverse,
            Self::InputBoundedSparseFallback { .. } => PriorityExecutionKernel::InputBoundedReverse,
            Self::FullDfa(_) => PriorityExecutionKernel::FullDfa,
            Self::LazyDfa => PriorityExecutionKernel::LazyDfa,
            Self::FullTransducer(_) => PriorityExecutionKernel::FullTaggedReverse,
            Self::LazyTransducer(_) => PriorityExecutionKernel::LazyTaggedReverse,
        }
    }
}

/// An immutable forced plan with a statically selected direct output.
#[derive(Clone, Debug)]
pub struct PreparedPriorityAutomaton<O: DirectReduceValue> {
    automaton: Automaton,
    actions: Box<[Option<PatternAction>]>,
    exact_match_bytes: Option<usize>,
    /// Build-Many follows Rust's iterator suppression rule for an empty
    /// terminal immediately after a consuming selected match. Standalone
    /// direct priority routes retain their independently established byte
    /// progress contract.
    build_many_empty_progress: bool,
    route: PreparedRoute,
    preparation: PreparationAccounting,
    operation: PhantomData<O>,
}

impl<O: DirectReduceValue> PreparedPriorityAutomaton<O> {
    /// Exact route fixed before execution.
    #[must_use]
    pub const fn execution(&self) -> ForcedExecution {
        match &self.route {
            PreparedRoute::Sparse { .. } => ForcedExecution::Sparse,
            PreparedRoute::FullDfa(_) | PreparedRoute::FullTransducer(_) => {
                ForcedExecution::FullDfa
            }
            PreparedRoute::LazyDfa | PreparedRoute::LazyTransducer(_) => ForcedExecution::LazyDfa,
            PreparedRoute::FiniteHorizon { .. }
            | PreparedRoute::InputBoundedSparseFallback { .. } => ForcedExecution::FiniteHorizon,
        }
    }

    /// Concrete pre-source kernel selected for this forced route.
    #[must_use]
    pub const fn kernel(&self) -> PriorityExecutionKernel {
        self.route.kernel()
    }

    /// Exact statically retained reducer suffix width, when this plan uses a
    /// finite ring. A per-input sparse fallback deliberately has no static
    /// retention bound.
    #[must_use]
    pub const fn static_reducer_retention_bytes(&self) -> Option<usize> {
        match &self.route {
            PreparedRoute::FiniteHorizon {
                maximum_match_bytes,
                ..
            } => Some(*maximum_match_bytes),
            PreparedRoute::Sparse { .. }
            | PreparedRoute::InputBoundedSparseFallback { .. }
            | PreparedRoute::FullDfa(_)
            | PreparedRoute::FullTransducer(_)
            | PreparedRoute::LazyDfa
            | PreparedRoute::LazyTransducer(_) => None,
        }
    }

    /// Exact successful construction ledger.
    #[must_use]
    pub const fn preparation_accounting(&self) -> PreparationAccounting {
        self.preparation
    }

    /// Compute source-independent run bounds and exact scratch preflight.
    pub fn prospective(
        &self,
        haystack_bytes: usize,
        limits: DirectReduceLimits,
    ) -> Result<ExecutionProspective, ReduceError> {
        prospective(self, haystack_bytes, limits)
    }

    /// Execute only the route fixed by [`PriorityAutomataFacts::prepare_forced`].
    ///
    /// A resource failure is terminal and returns no partial reducer value.
    pub fn execute_forced(
        &self,
        haystack: &[u8],
        limits: DirectReduceLimits,
    ) -> Result<DirectReduceReport<O::Output>, ReduceError> {
        execute(self, haystack, limits)
    }

    /// Execute the Build-Many sparse route and retain its admitted ordinal
    /// trace in non-overlapping source order.
    ///
    /// Trace storage is preflighted from the existing match-event bound before
    /// any source byte is read. Ordinary direct reducers remain allocation-free
    /// with respect to trace output; this explicit API exists only for a
    /// forced Build-Many semantic oracle.
    pub fn execute_forced_trace(
        &self,
        haystack: &[u8],
        limits: DirectReduceLimits,
    ) -> Result<DirectReduceTraceReport<O::Output>, ReduceError> {
        if self.execution() != ForcedExecution::Sparse {
            return Err(ReduceError::TraceRequiresSparseRoute {
                execution: self.execution(),
            });
        }
        if !self.build_many_empty_progress {
            return Err(ReduceError::TraceRequiresBuildManyRoute);
        }
        execute_sparse_trace(self, haystack, limits)
    }
}

/// Per-run hard limits. Route choice is not among these fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectReduceLimits {
    pub max_work: u64,
    pub max_scratch_bytes: usize,
    pub max_boundary_rows: usize,
    pub max_match_events: usize,
    pub max_dfa_states: usize,
    pub max_dfa_cells: usize,
    pub max_subset_items: usize,
    /// Static tagged-dispatch state descriptors admitted for this run.
    pub max_tagged_dispatch_states: usize,
    /// Static tagged-dispatch cells admitted for this run.
    pub max_tagged_dispatch_cells: usize,
    /// Static tagged ordered-candidate entries admitted for this run.
    pub max_tagged_candidate_items: usize,
    /// Preallocated direct-mapped cells for a lazy tagged route.
    pub max_tagged_cache_cells: usize,
    pub max_allocation_attempts: usize,
}

impl DirectReduceLimits {
    /// Disable caller-selected limits while retaining checked arithmetic.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_work: u64::MAX,
            max_scratch_bytes: usize::MAX,
            max_boundary_rows: usize::MAX,
            max_match_events: usize::MAX,
            max_dfa_states: usize::MAX,
            max_dfa_cells: usize::MAX,
            max_subset_items: usize::MAX,
            max_tagged_dispatch_states: usize::MAX,
            max_tagged_dispatch_cells: usize::MAX,
            max_tagged_candidate_items: usize::MAX,
            max_tagged_cache_cells: usize::MAX,
            max_allocation_attempts: usize::MAX,
        }
    }
}

impl Default for DirectReduceLimits {
    fn default() -> Self {
        Self {
            max_work: 1_000_000_000,
            max_scratch_bytes: 536_870_912,
            max_boundary_rows: 134_217_729,
            max_match_events: 134_217_729,
            max_dfa_states: 65_536,
            max_dfa_cells: 16_777_216,
            max_subset_items: 16_777_216,
            // Keep the runtime admission envelope aligned with preparation:
            // static tagged descriptors are checked again before source work.
            max_tagged_dispatch_states: 131_072,
            max_tagged_dispatch_cells: 16_777_216,
            max_tagged_candidate_items: 16_777_216,
            max_tagged_cache_cells: 16_777_216,
            max_allocation_attempts: 16,
        }
    }
}

/// Complete source-independent bounds and the exact scratch admitted before
/// any source byte is read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionProspective {
    /// Tagged Build-Many routes bind their immutable construction-selected
    /// execution architecture here. Ordinary priority plans use `None`.
    pub tagged_execution_class: Option<crate::tagged_many::TaggedManyExecutionClass>,
    pub work_upper_bound: u64,
    pub scratch_bytes: usize,
    pub boundary_rows: usize,
    pub match_events_upper_bound: usize,
    pub dfa_states_capacity: usize,
    pub dfa_cells_capacity: usize,
    pub subset_items_capacity: usize,
    /// Exact owner-tagged state evaluations admitted for Build-Many.
    pub tagged_state_evaluations_upper_bound: usize,
    /// Exact owner-tagged physical edge visits admitted for Build-Many.
    pub tagged_edge_visits_upper_bound: usize,
    /// Per-row owner-tagged outcome-map capacity, including the empty map.
    pub tagged_map_capacity: usize,
    /// Per-row owner-tagged outcome-group capacity.
    pub tagged_group_capacity: usize,
    /// Cumulative owner-tagged outcome-group publications admitted for a run.
    pub tagged_group_publications_upper_bound: usize,
    /// Number of source-ordered owners represented by the tagged plan.
    pub tagged_owner_capacity: usize,
    /// Exact static tagged-dispatch states admitted for ordinary tagged routes.
    pub tagged_dispatch_states_capacity: usize,
    /// Exact static tagged-dispatch cells admitted for ordinary tagged routes.
    pub tagged_dispatch_cells_capacity: usize,
    /// Exact tagged ordered-candidate entries admitted for ordinary tagged routes.
    pub tagged_candidate_items_capacity: usize,
    /// Exact lazy tagged cache cells admitted before ordinary tagged execution.
    pub tagged_cache_cells_capacity: usize,
    pub allocation_attempts: usize,
}

/// Exact successful execution counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionActual {
    pub work: u64,
    pub scratch_bytes: usize,
    pub source_bytes: usize,
    pub boundary_rows: usize,
    pub sparse_root_evaluations: usize,
    pub sparse_closure_visits: usize,
    pub sparse_edge_visits: usize,
    /// Reverse boundary rows fused directly into a suffix reducer.
    pub suffix_reducer_steps: usize,
    pub dfa_transitions: usize,
    pub dfa_states: usize,
    pub dfa_cells: usize,
    pub subset_items: usize,
    /// Exact static tagged-dispatch states used by this route.
    pub tagged_dispatch_states: usize,
    /// Exact static tagged-dispatch cells used by this route.
    pub tagged_dispatch_cells: usize,
    /// Exact static tagged ordered-candidate entries used by this route.
    pub tagged_candidate_items: usize,
    /// Exact dynamic lazy-tagged cache cells allocated before source work.
    pub tagged_cache_cells: usize,
    /// Tagged reverse-row state evaluations.
    pub tagged_state_evaluations: usize,
    /// Tagged static-candidate and dynamic-outcome edge visits.
    pub tagged_edge_visits: usize,
    pub tagged_cache_hits: usize,
    pub tagged_cache_misses: usize,
    pub tagged_cache_inserts: usize,
    pub tagged_cache_evictions: usize,
    /// Owner-tagged Build-Many map publications.
    pub tagged_map_publications: usize,
    /// Owner-tagged Build-Many group publications.
    pub tagged_group_publications: usize,
    /// Peak owner-tagged Build-Many maps.
    pub tagged_peak_maps: usize,
    /// Peak owner-tagged Build-Many groups.
    pub tagged_peak_groups: usize,
    pub lazy_cache_hits: usize,
    pub lazy_cache_misses: usize,
    pub lazy_cache_inserts: usize,
    pub lazy_cache_evictions: usize,
    pub match_events: usize,
    pub empty_match_events: usize,
    /// Exact total bytes in the selected, non-overlapping match sequence.
    pub selected_span_bytes: u64,
    pub selected_ordinal_sum: u64,
    pub generation_resets: usize,
    pub allocation_attempts: usize,
}

impl ExecutionActual {
    pub(crate) const fn zero(source_bytes: usize) -> Self {
        Self {
            work: 0,
            scratch_bytes: 0,
            source_bytes,
            boundary_rows: 0,
            sparse_root_evaluations: 0,
            sparse_closure_visits: 0,
            sparse_edge_visits: 0,
            suffix_reducer_steps: 0,
            dfa_transitions: 0,
            dfa_states: 0,
            dfa_cells: 0,
            subset_items: 0,
            tagged_dispatch_states: 0,
            tagged_dispatch_cells: 0,
            tagged_candidate_items: 0,
            tagged_cache_cells: 0,
            tagged_state_evaluations: 0,
            tagged_edge_visits: 0,
            tagged_cache_hits: 0,
            tagged_cache_misses: 0,
            tagged_cache_inserts: 0,
            tagged_cache_evictions: 0,
            tagged_map_publications: 0,
            tagged_group_publications: 0,
            tagged_peak_maps: 0,
            tagged_peak_groups: 0,
            lazy_cache_hits: 0,
            lazy_cache_misses: 0,
            lazy_cache_inserts: 0,
            lazy_cache_evictions: 0,
            match_events: 0,
            empty_match_events: 0,
            selected_span_bytes: 0,
            selected_ordinal_sum: 0,
            generation_resets: 0,
            allocation_attempts: 0,
        }
    }
}

/// Complete direct-reducer value and its P/A ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectReduceReport<T> {
    output: T,
    prospective: ExecutionProspective,
    actual: ExecutionActual,
}

impl<T> DirectReduceReport<T> {
    pub(crate) const fn from_parts(
        output: T,
        prospective: ExecutionProspective,
        actual: &ExecutionActual,
    ) -> Self {
        Self {
            output,
            prospective,
            actual: *actual,
        }
    }

    /// Complete reducer output.
    #[must_use]
    pub fn output(&self) -> &T {
        &self.output
    }

    /// Source-independent bounds admitted before execution.
    #[must_use]
    pub const fn prospective(&self) -> ExecutionProspective {
        self.prospective
    }

    /// Exact successful counters.
    #[must_use]
    pub const fn actual(&self) -> ExecutionActual {
        self.actual
    }

    /// Consume the report and return its reducer value.
    #[must_use]
    pub fn into_output(self) -> T {
        self.output
    }
}

/// An admitted direct-reducer report plus its ordered Build-Many trace.
///
/// The trace capacity is included in the report's prospective scratch and
/// allocation accounting. It is available only through the sparse
/// Build-Many semantic-oracle route.
#[derive(Debug, Eq, PartialEq)]
pub struct DirectReduceTraceReport<T> {
    report: DirectReduceReport<T>,
    untraced_prospective: ExecutionProspective,
    matches: Vec<PriorityMatch>,
}

impl<T> DirectReduceTraceReport<T> {
    pub(crate) const fn from_parts(
        report: DirectReduceReport<T>,
        untraced_prospective: ExecutionProspective,
        matches: Vec<PriorityMatch>,
    ) -> Self {
        Self {
            report,
            untraced_prospective,
            matches,
        }
    }

    /// The ordinary direct-reducer receipt, including trace storage charges.
    #[must_use]
    pub const fn report(&self) -> &DirectReduceReport<T> {
        &self.report
    }

    /// The exact sparse execution reservation before the trace sidecar was
    /// added. This lets a receipt authenticate the trace allocation, bounded
    /// storage, forward scan, and prepaid copy work without traversing its
    /// entries.
    #[must_use]
    pub const fn untraced_prospective(&self) -> ExecutionProspective {
        self.untraced_prospective
    }

    /// The exact number of pre-reserved trace entries.
    #[must_use]
    pub const fn trace_capacity(&self) -> usize {
        self.untraced_prospective.match_events_upper_bound
    }

    /// Selected pattern ordinals and spans in source order.
    #[must_use]
    pub fn matches(&self) -> &[PriorityMatch] {
        &self.matches
    }

    /// Verify the trace sidecar against its base and traced execution
    /// reservations in constant time.
    ///
    /// The selected span and ordinal totals are accumulated by the same
    /// metered emission that pushes each private trace entry. Keeping this
    /// check O(1) prevents a second uncharged traversal after an exact-work
    /// execution has completed.
    #[must_use]
    pub fn closes(&self) -> bool {
        let trace_capacity = self.trace_capacity();
        let trace_bytes = trace_capacity.checked_mul(size_of::<PriorityMatch>());
        let trace_work = match self.untraced_prospective.tagged_execution_class {
            // TaggedManyPlan retains its existing trace-only reservation
            // contract: its execution already performs the forward selection
            // scan as part of the tagged plan itself.
            Some(_) => u64::try_from(trace_capacity)
                .ok()
                .and_then(|work| work.checked_add(1)),
            // Ordinary sparse Build-Many reuses the admitted suffix slot for
            // roots and performs an explicit full forward selection scan.
            None => u64::try_from(self.untraced_prospective.boundary_rows)
                .ok()
                .and_then(|work| {
                    u64::try_from(trace_capacity)
                        .ok()
                        .and_then(|copies| work.checked_add(copies))
                })
                .and_then(|work| work.checked_add(1)),
        };
        let traced = self.report.prospective();
        let actual = self.report.actual();
        traced.tagged_execution_class == self.untraced_prospective.tagged_execution_class
            && traced.boundary_rows == self.untraced_prospective.boundary_rows
            && traced.match_events_upper_bound == self.untraced_prospective.match_events_upper_bound
            && traced.dfa_states_capacity == self.untraced_prospective.dfa_states_capacity
            && traced.dfa_cells_capacity == self.untraced_prospective.dfa_cells_capacity
            && traced.subset_items_capacity == self.untraced_prospective.subset_items_capacity
            && traced.tagged_dispatch_states_capacity
                == self.untraced_prospective.tagged_dispatch_states_capacity
            && traced.tagged_dispatch_cells_capacity
                == self.untraced_prospective.tagged_dispatch_cells_capacity
            && traced.tagged_candidate_items_capacity
                == self.untraced_prospective.tagged_candidate_items_capacity
            && traced.tagged_cache_cells_capacity
                == self.untraced_prospective.tagged_cache_cells_capacity
            && traced.tagged_state_evaluations_upper_bound
                == self
                    .untraced_prospective
                    .tagged_state_evaluations_upper_bound
            && traced.tagged_edge_visits_upper_bound
                == self.untraced_prospective.tagged_edge_visits_upper_bound
            && traced.tagged_map_capacity == self.untraced_prospective.tagged_map_capacity
            && traced.tagged_group_capacity == self.untraced_prospective.tagged_group_capacity
            && traced.tagged_group_publications_upper_bound
                == self
                    .untraced_prospective
                    .tagged_group_publications_upper_bound
            && traced.tagged_owner_capacity == self.untraced_prospective.tagged_owner_capacity
            && trace_bytes
                .and_then(|bytes| self.untraced_prospective.scratch_bytes.checked_add(bytes))
                == Some(traced.scratch_bytes)
            && self.untraced_prospective.allocation_attempts.checked_add(1)
                == Some(traced.allocation_attempts)
            && trace_work
                .and_then(|work| self.untraced_prospective.work_upper_bound.checked_add(work))
                == Some(traced.work_upper_bound)
            && self.matches.capacity() == trace_capacity
            && self.matches.len() == actual.match_events
            && actual.match_events <= trace_capacity
            && actual.scratch_bytes == traced.scratch_bytes
            && actual.allocation_attempts == traced.allocation_attempts
            && actual.work <= traced.work_upper_bound
    }

    /// Consume the receipt and its independently admitted trace.
    #[must_use]
    pub fn into_parts(self) -> (DirectReduceReport<T>, Vec<PriorityMatch>) {
        (self.report, self.matches)
    }
}

/// A terminal forced-execution error. No variant contains a partial value.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReduceError {
    /// An ordinal trace is currently defined only for the sparse route,
    /// whose forward reducer visits selected actions in source order.
    TraceRequiresSparseRoute {
        execution: ForcedExecution,
    },
    /// An ordinal trace requires the capability-gated Build-Many route.
    TraceRequiresBuildManyRoute,
    ScratchLimit {
        needed: usize,
        limit: usize,
    },
    BoundaryRowsLimit {
        needed: usize,
        limit: usize,
    },
    MatchEventsLimit {
        needed: usize,
        limit: usize,
    },
    DfaStatesLimit {
        needed: usize,
        limit: usize,
    },
    DfaCellsLimit {
        needed: usize,
        limit: usize,
    },
    SubsetItemsLimit {
        needed: usize,
        limit: usize,
    },
    TaggedDispatchStatesLimit {
        needed: usize,
        limit: usize,
    },
    TaggedDispatchCellsLimit {
        needed: usize,
        limit: usize,
    },
    TaggedCandidateItemsLimit {
        needed: usize,
        limit: usize,
    },
    TaggedCacheCellsLimit {
        needed: usize,
        limit: usize,
    },
    AllocationAttemptsLimit {
        needed: usize,
        limit: usize,
    },
    WorkLimit {
        consumed: u64,
        requested: u64,
        limit: u64,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    OutputOverflow {
        output: &'static str,
    },
    AllocationFailed {
        bytes: usize,
    },
    FiniteHorizonProofViolated {
        start: usize,
        end: usize,
        maximum_bytes: usize,
    },
    InternalInvariant {
        detail: &'static str,
    },
}

impl fmt::Display for ReduceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TraceRequiresSparseRoute { execution } => write!(
                formatter,
                "priority match trace requires sparse execution, not {execution:?}"
            ),
            Self::TraceRequiresBuildManyRoute => {
                formatter.write_str("priority match trace requires a Build-Many prepared route")
            }
            Self::ScratchLimit { needed, limit } => {
                write!(
                    formatter,
                    "execution needs {needed} scratch bytes, limit is {limit}"
                )
            }
            Self::BoundaryRowsLimit { needed, limit } => {
                write!(
                    formatter,
                    "execution needs {needed} boundary rows, limit is {limit}"
                )
            }
            Self::MatchEventsLimit { needed, limit } => write!(
                formatter,
                "execution may need {needed} match events, limit is {limit}"
            ),
            Self::DfaStatesLimit { needed, limit } => {
                write!(formatter, "lazy DFA needs state {needed}, limit is {limit}")
            }
            Self::DfaCellsLimit { needed, limit } => {
                write!(formatter, "lazy DFA needs cell {needed}, limit is {limit}")
            }
            Self::SubsetItemsLimit { needed, limit } => {
                write!(
                    formatter,
                    "lazy DFA needs {needed} subset items, limit is {limit}"
                )
            }
            Self::TaggedDispatchStatesLimit { needed, limit } => write!(
                formatter,
                "tagged dispatch needs {needed} states, limit is {limit}"
            ),
            Self::TaggedDispatchCellsLimit { needed, limit } => write!(
                formatter,
                "tagged dispatch needs {needed} cells, limit is {limit}"
            ),
            Self::TaggedCandidateItemsLimit { needed, limit } => write!(
                formatter,
                "tagged dispatch needs {needed} candidate items, limit is {limit}"
            ),
            Self::TaggedCacheCellsLimit { needed, limit } => write!(
                formatter,
                "lazy tagged dispatch needs {needed} cache cells, limit is {limit}"
            ),
            Self::AllocationAttemptsLimit { needed, limit } => write!(
                formatter,
                "execution needs {needed} allocation attempts, limit is {limit}"
            ),
            Self::WorkLimit {
                consumed,
                requested,
                limit,
            } => write!(
                formatter,
                "execution work limit {limit} exceeded: {consumed} consumed, {requested} requested"
            ),
            Self::ArithmeticOverflow { computation } => {
                write!(
                    formatter,
                    "arithmetic overflow while computing {computation}"
                )
            }
            Self::OutputOverflow { output } => {
                write!(formatter, "{output} cannot fit its public output type")
            }
            Self::AllocationFailed { bytes } => {
                write!(
                    formatter,
                    "failed to allocate {bytes} execution scratch bytes"
                )
            }
            Self::FiniteHorizonProofViolated {
                start,
                end,
                maximum_bytes,
            } => write!(
                formatter,
                "selected span {start}..{end} exceeds proved horizon {maximum_bytes}"
            ),
            Self::InternalInvariant { detail } => {
                write!(formatter, "priority execution invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for ReduceError {}

struct PreparationMeter {
    limit: u64,
    consumed: u64,
    allocation_limit: usize,
    allocations: usize,
}

impl PreparationMeter {
    const fn new(limit: u64, allocation_limit: usize) -> Self {
        Self {
            limit,
            consumed: 0,
            allocation_limit,
            allocations: 0,
        }
    }

    fn charge(&mut self, amount: u64) -> Result<(), PreparationError> {
        let needed =
            self.consumed
                .checked_add(amount)
                .ok_or(PreparationError::ArithmeticOverflow {
                    computation: "preparation work",
                })?;
        if needed > self.limit {
            return Err(PreparationError::WorkLimit {
                needed,
                limit: self.limit,
            });
        }
        self.consumed = needed;
        Ok(())
    }

    fn allocation(&mut self) -> Result<(), PreparationError> {
        let needed =
            self.allocations
                .checked_add(1)
                .ok_or(PreparationError::ArithmeticOverflow {
                    computation: "preparation allocation attempts",
                })?;
        if needed > self.allocation_limit {
            return Err(PreparationError::ResourceLimit {
                resource: PreparationResource::AllocationAttempts,
                needed,
                limit: self.allocation_limit,
            });
        }
        self.allocations = needed;
        Ok(())
    }
}

// Keeping certification, resource gates and table publication in one
// transaction makes the preparation P/A ledger auditable.
#[allow(clippy::too_many_lines)]
fn prepare<O: DirectReduceValue>(
    facts: PriorityAutomataFacts,
    execution: ForcedExecution,
    target: PriorityTarget,
    limits: PreparationLimits,
    required_actions: ActionCapabilities,
) -> Result<PreparedPriorityAutomaton<O>, PreparationError> {
    if !target.supports_execution(execution) {
        return Err(PreparationError::UnsupportedTarget { execution });
    }
    if !target.actions.contains(required_actions) {
        return Err(PreparationError::UnsupportedTargetAction {
            required: required_actions,
            available: target.actions,
        });
    }
    if facts.empty_progress == EmptyMatchProgress::UnicodeScalar {
        return Err(PreparationError::UnsupportedUnicodeEmptyProgress);
    }
    if let MatchLengthProof::Finite {
        minimum_bytes,
        maximum_bytes,
    } = facts.match_length
    {
        if minimum_bytes > maximum_bytes {
            return Err(PreparationError::InvalidFiniteLengthProof {
                minimum_bytes,
                maximum_bytes,
            });
        }
    }

    let states = facts.automaton.stats().states();
    if facts.actions.len() != states {
        return Err(PreparationError::ActionTableLength {
            states,
            actions: facts.actions.len(),
        });
    }

    let mut meter = PreparationMeter::new(limits.max_work, limits.max_allocation_attempts);
    let mut terminal_count = 0usize;
    for (state, (&role, action)) in facts
        .automaton
        .roles
        .iter()
        .zip(facts.actions.iter())
        .enumerate()
    {
        meter.charge(1)?;
        match (role, action) {
            (StateRole::Accept, Some(action)) => {
                terminal_count =
                    terminal_count
                        .checked_add(1)
                        .ok_or(PreparationError::ArithmeticOverflow {
                            computation: "pattern terminal count",
                        })?;
                if !action.capabilities().contains(required_actions) {
                    return Err(PreparationError::MissingActionCapability {
                        state,
                        required: required_actions,
                        available: action.capabilities(),
                    });
                }
            }
            (StateRole::Accept, None) => {
                return Err(PreparationError::MissingAcceptAction { state });
            }
            (_, Some(_)) => {
                return Err(PreparationError::ActionOnNonAccept { state });
            }
            (_, None) => {}
        }
    }
    check_preparation_usize(
        PreparationResource::PatternTerminals,
        terminal_count,
        limits.max_pattern_terminals,
    )?;
    let action_bytes = facts
        .actions
        .len()
        .checked_mul(size_of::<Option<PatternAction>>())
        .ok_or(PreparationError::ArithmeticOverflow {
            computation: "accept-action sidecar bytes",
        })?;
    let base_persistent = facts
        .automaton
        .stats()
        .storage_bytes()
        .checked_add(action_bytes)
        .ok_or(PreparationError::ArithmeticOverflow {
            computation: "base prepared-plan bytes",
        })?;
    check_preparation_usize(
        PreparationResource::PersistentBytes,
        base_persistent,
        limits.max_persistent_bytes,
    )?;
    let (intrinsic_match_length, match_length_peak) = derive_match_length(
        &facts.automaton,
        &mut meter,
        base_persistent,
        limits.max_peak_bytes,
    )?;
    if intrinsic_match_length != facts.match_length {
        return Err(PreparationError::MatchLengthProofMismatch {
            declared: facts.match_length,
            intrinsic: intrinsic_match_length,
        });
    }
    // Match-length vectors have been dropped before pattern-order analysis
    // starts. Gate the latter's two simultaneously-live vectors separately
    // instead of adding their footprints.
    let pattern_order_peak = base_persistent
        .checked_add(pattern_order_analysis_bytes(states)?)
        .ok_or(PreparationError::ArithmeticOverflow {
            computation: "pattern-order analysis peak bytes",
        })?;
    check_preparation_usize(
        PreparationResource::PeakBytes,
        pattern_order_peak,
        limits.max_peak_bytes,
    )?;
    validate_pattern_order(&facts.automaton, &facts.actions, &mut meter)?;
    let analysis_peak = match_length_peak.max(pattern_order_peak);

    // Classify the concrete executor before allocating/building any
    // route-specific table. A forced route is a policy family, while the
    // concrete kernel can require an additional substrate capability.
    let kernel = match execution {
        ForcedExecution::Sparse => PriorityExecutionKernel::SparseReverse,
        ForcedExecution::FiniteHorizon => match intrinsic_match_length.maximum() {
            Some(_) => PriorityExecutionKernel::FiniteHorizonReverse,
            None => PriorityExecutionKernel::InputBoundedReverse,
        },
        ForcedExecution::FullDfa | ForcedExecution::LazyDfa => {
            let classic = dfa_domain_is_classic_exact_nonempty(
                &facts.automaton,
                intrinsic_match_length,
                &mut meter,
            )?;
            match (execution, classic) {
                (ForcedExecution::FullDfa, true) => PriorityExecutionKernel::FullDfa,
                (ForcedExecution::LazyDfa, true) => PriorityExecutionKernel::LazyDfa,
                (ForcedExecution::FullDfa, false) => PriorityExecutionKernel::FullTaggedReverse,
                (ForcedExecution::LazyDfa, false) => PriorityExecutionKernel::LazyTaggedReverse,
                _ => unreachable!("only FullDfa and LazyDfa reach tagged classification"),
            }
        }
    };
    if !target.supports_kernel(kernel) {
        return Err(PreparationError::UnsupportedTargetKernel { execution, kernel });
    }

    let (
        route,
        dfa_states,
        transition_cells,
        subset_items,
        tagged_dispatch_states,
        tagged_dispatch_cells,
        tagged_candidate_items,
        route_bytes,
        route_peak,
    ) = match kernel {
        PriorityExecutionKernel::SparseReverse => {
            let (evaluation, build_peak) = build_sparse_evaluation(
                &facts.automaton,
                &mut meter,
                base_persistent,
                limits.max_peak_bytes,
            )?;
            let route_bytes = sparse_evaluation_bytes(&evaluation)?;
            (
                PreparedRoute::Sparse { evaluation },
                0,
                0,
                0,
                0,
                0,
                0,
                route_bytes,
                build_peak,
            )
        }
        PriorityExecutionKernel::FiniteHorizonReverse => {
            let (evaluation, build_peak) = build_sparse_evaluation(
                &facts.automaton,
                &mut meter,
                base_persistent,
                limits.max_peak_bytes,
            )?;
            let route_bytes = sparse_evaluation_bytes(&evaluation)?;
            let maximum_match_bytes =
                intrinsic_match_length
                    .maximum()
                    .ok_or(PreparationError::InternalInvariant {
                        detail: "finite kernel was selected without a finite match width",
                    })?;
            (
                PreparedRoute::FiniteHorizon {
                    maximum_match_bytes,
                    evaluation,
                },
                0,
                0,
                0,
                0,
                0,
                0,
                route_bytes,
                build_peak,
            )
        }
        PriorityExecutionKernel::InputBoundedReverse => {
            let (evaluation, build_peak) = build_sparse_evaluation(
                &facts.automaton,
                &mut meter,
                base_persistent,
                limits.max_peak_bytes,
            )?;
            let route_bytes = sparse_evaluation_bytes(&evaluation)?;
            (
                PreparedRoute::InputBoundedSparseFallback { evaluation },
                0,
                0,
                0,
                0,
                0,
                0,
                route_bytes,
                build_peak,
            )
        }
        PriorityExecutionKernel::FullDfa => {
            let (full, build_peak) = build_full_dfa(
                &facts.automaton,
                &facts.actions,
                limits,
                &mut meter,
                base_persistent,
            )?;
            let dfa_states = full.subsets.len();
            let transition_cells = full.transitions.len();
            let subset_items = full.subsets.iter().try_fold(0usize, |total, subset| {
                total
                    .checked_add(subset.len())
                    .ok_or(PreparationError::ArithmeticOverflow {
                        computation: "full DFA subset item count",
                    })
            })?;
            let route_bytes = full_dfa_bytes(&full)?;
            (
                PreparedRoute::FullDfa(full),
                dfa_states,
                transition_cells,
                subset_items,
                0,
                0,
                0,
                route_bytes,
                build_peak,
            )
        }
        PriorityExecutionKernel::LazyDfa => {
            (PreparedRoute::LazyDfa, 0, 0, 0, 0, 0, 0, 0, base_persistent)
        }
        PriorityExecutionKernel::FullTaggedReverse => {
            let (transducer, build_peak) = build_full_tagged_transducer(
                &facts.automaton,
                limits,
                &mut meter,
                base_persistent,
            )?;
            let resources = transducer.resources;
            let route_bytes = full_tagged_transducer_bytes(&transducer)?;
            (
                PreparedRoute::FullTransducer(transducer),
                0,
                0,
                0,
                resources.states,
                resources.cells,
                resources.candidates,
                route_bytes,
                build_peak,
            )
        }
        PriorityExecutionKernel::LazyTaggedReverse => {
            let (transducer, build_peak) = build_lazy_tagged_transducer(
                &facts.automaton,
                limits,
                &mut meter,
                base_persistent,
            )?;
            let resources = transducer.resources;
            let route_bytes = lazy_tagged_transducer_bytes(&transducer)?;
            (
                PreparedRoute::LazyTransducer(transducer),
                0,
                0,
                0,
                resources.states,
                resources.cells,
                resources.candidates,
                route_bytes,
                build_peak,
            )
        }
    };
    debug_assert_eq!(route.kernel(), kernel);

    check_preparation_usize(
        PreparationResource::DfaStates,
        dfa_states,
        limits.max_dfa_states,
    )?;
    check_preparation_usize(
        PreparationResource::TransitionCells,
        transition_cells,
        limits.max_transition_cells,
    )?;
    check_preparation_usize(
        PreparationResource::SubsetItems,
        subset_items,
        limits.max_subset_items,
    )?;
    check_preparation_usize(
        PreparationResource::TaggedDispatchStates,
        tagged_dispatch_states,
        limits.max_tagged_dispatch_states,
    )?;
    check_preparation_usize(
        PreparationResource::TaggedDispatchCells,
        tagged_dispatch_cells,
        limits.max_tagged_dispatch_cells,
    )?;
    check_preparation_usize(
        PreparationResource::TaggedCandidateItems,
        tagged_candidate_items,
        limits.max_tagged_candidate_items,
    )?;
    let persistent_bytes =
        base_persistent
            .checked_add(route_bytes)
            .ok_or(PreparationError::ArithmeticOverflow {
                computation: "prepared-plan persistent bytes",
            })?;
    check_preparation_usize(
        PreparationResource::PersistentBytes,
        persistent_bytes,
        limits.max_persistent_bytes,
    )?;
    let peak_bytes = analysis_peak.max(route_peak).max(persistent_bytes);
    check_preparation_usize(
        PreparationResource::PeakBytes,
        peak_bytes,
        limits.max_peak_bytes,
    )?;

    let prospective = PreparationProspective {
        pattern_terminals: terminal_count,
        dfa_states,
        transition_cells,
        subset_items,
        tagged_dispatch_states,
        tagged_dispatch_cells,
        tagged_candidate_items,
        work: meter.consumed,
        persistent_bytes,
        peak_bytes,
        allocation_attempts: meter.allocations,
    };
    let preparation = PreparationAccounting {
        prospective,
        pattern_terminals: terminal_count,
        dfa_states,
        transition_cells,
        subset_items,
        tagged_dispatch_states,
        tagged_dispatch_cells,
        tagged_candidate_items,
        work: meter.consumed,
        persistent_bytes,
        peak_bytes,
        allocation_attempts: meter.allocations,
    };
    Ok(PreparedPriorityAutomaton {
        automaton: facts.automaton,
        actions: facts.actions,
        exact_match_bytes: intrinsic_match_length.exact(),
        build_many_empty_progress: required_actions.contains(ActionCapabilities::BUILD_MANY),
        route,
        preparation,
        operation: PhantomData,
    })
}

fn check_preparation_usize(
    resource: PreparationResource,
    needed: usize,
    limit: usize,
) -> Result<(), PreparationError> {
    if needed > limit {
        return Err(PreparationError::ResourceLimit {
            resource,
            needed,
            limit,
        });
    }
    Ok(())
}

fn pattern_order_analysis_bytes(states: usize) -> Result<usize, PreparationError> {
    states
        .checked_mul(size_of::<Option<PatternOrdinal>>())
        .and_then(|bytes| bytes.checked_mul(2))
        .ok_or(PreparationError::ArithmeticOverflow {
            computation: "pattern-order analysis scratch bytes",
        })
}

fn validate_pattern_order(
    automaton: &Automaton,
    actions: &[Option<PatternAction>],
    meter: &mut PreparationMeter,
) -> Result<(), PreparationError> {
    let states = automaton.stats().states();
    let mut minimum = allocate_preparation_slots(states, None::<PatternOrdinal>, meter)?;
    let mut maximum = allocate_preparation_slots(states, None::<PatternOrdinal>, meter)?;
    for state in 0..states {
        if let Some(action) = actions[state] {
            minimum[state] = Some(action.ordinal());
            maximum[state] = Some(action.ordinal());
        }
    }
    for _ in 0..states {
        let mut changed = false;
        for state in 0..states {
            meter.charge(1)?;
            let state_u32 =
                u32::try_from(state).map_err(|_| PreparationError::ArithmeticOverflow {
                    computation: "pattern-order state conversion",
                })?;
            for edge in automaton.state_edges(state_u32) {
                meter.charge(1)?;
                let target = plan_index(automaton.edge_targets[edge]);
                if let Some(candidate) = minimum[target] {
                    if minimum[state].map_or(true, |current| candidate < current) {
                        minimum[state] = Some(candidate);
                        changed = true;
                    }
                }
                if let Some(candidate) = maximum[target] {
                    if maximum[state].map_or(true, |current| candidate > current) {
                        maximum[state] = Some(candidate);
                        changed = true;
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }

    for state in 0..states {
        let state_u32 = u32::try_from(state).map_err(|_| PreparationError::ArithmeticOverflow {
            computation: "pattern-order validation state conversion",
        })?;
        let mut previous = None::<(usize, PatternOrdinal)>;
        for edge in automaton.state_edges(state_u32) {
            meter.charge(1)?;
            let target = plan_index(automaton.edge_targets[edge]);
            let (Some(current_minimum), Some(current_maximum)) = (minimum[target], maximum[target])
            else {
                continue;
            };
            if let Some((earlier_edge, earlier_maximum)) = previous {
                if earlier_maximum > current_minimum {
                    return Err(PreparationError::NonCanonicalPatternOrder {
                        state,
                        earlier_edge,
                        earlier_maximum,
                        later_edge: edge,
                        later_minimum: current_minimum,
                    });
                }
            }
            previous = Some((edge, current_maximum));
        }
    }
    Ok(())
}

// A Kahn proof is deliberately kept distinct from the cyclic analysis below.
// The queue is also the forward order used by both length DPs, so a fully
// acyclic plan never needs a convergence pass.  That matters for the large,
// forward-built plans whose reverse fixed point would otherwise take one pass
// per state.
enum AcyclicMatchLength {
    Proven {
        proof: MatchLengthProof,
        peak_bytes: usize,
    },
    Cyclic {
        peak_bytes: usize,
    },
}

fn derive_match_length(
    automaton: &Automaton,
    meter: &mut PreparationMeter,
    base_persistent: usize,
    peak_limit: usize,
) -> Result<(MatchLengthProof, usize), PreparationError> {
    match derive_acyclic_match_length(automaton, meter, base_persistent, peak_limit)? {
        AcyclicMatchLength::Proven { proof, peak_bytes } => Ok((proof, peak_bytes)),
        AcyclicMatchLength::Cyclic { peak_bytes } => {
            derive_match_length_cyclic(automaton, meter, base_persistent, peak_limit, peak_bytes)
        }
    }
}

#[allow(
    clippy::too_many_lines,
    clippy::needless_range_loop,
    reason = "Kahn queue indices are both graph-state identities and the exact bounded preparation ledger"
)]
fn derive_acyclic_match_length(
    automaton: &Automaton,
    meter: &mut PreparationMeter,
    base_persistent: usize,
    peak_limit: usize,
) -> Result<AcyclicMatchLength, PreparationError> {
    let states = automaton.stats().states();
    let indegree_bytes = preparation_slots_bytes::<usize>(states)?;
    let order_bytes = preparation_slots_bytes::<u32>(states)?;
    let mut live_scratch = indegree_bytes;
    let mut peak_bytes = check_analysis_peak(base_persistent, live_scratch, peak_limit)?;
    let mut indegree = allocate_preparation_slots(states, 0usize, meter)?;

    for state in 0..states {
        meter.charge(1)?;
        let state_u32 = u32::try_from(state).map_err(|_| PreparationError::ArithmeticOverflow {
            computation: "match-length topological state conversion",
        })?;
        for edge in automaton.state_edges(state_u32) {
            meter.charge(1)?;
            let target = plan_index(automaton.edge_targets[edge]);
            indegree[target] =
                indegree[target]
                    .checked_add(1)
                    .ok_or(PreparationError::ArithmeticOverflow {
                        computation: "match-length topological indegree",
                    })?;
        }
    }

    live_scratch =
        live_scratch
            .checked_add(order_bytes)
            .ok_or(PreparationError::ArithmeticOverflow {
                computation: "match-length topological queue bytes",
            })?;
    peak_bytes = peak_bytes.max(check_analysis_peak(
        base_persistent,
        live_scratch,
        peak_limit,
    )?);
    let mut order = allocate_preparation_slots(states, 0u32, meter)?;
    let mut order_len = 0usize;
    for state in 0..states {
        meter.charge(1)?;
        if indegree[state] != 0 {
            continue;
        }
        order[order_len] =
            u32::try_from(state).map_err(|_| PreparationError::ArithmeticOverflow {
                computation: "match-length topological queue state conversion",
            })?;
        order_len = order_len
            .checked_add(1)
            .ok_or(PreparationError::ArithmeticOverflow {
                computation: "match-length topological queue length",
            })?;
    }

    let mut cursor = 0usize;
    while cursor < order_len {
        meter.charge(1)?;
        let state = order[cursor];
        cursor = cursor
            .checked_add(1)
            .ok_or(PreparationError::ArithmeticOverflow {
                computation: "match-length topological queue cursor",
            })?;
        for edge in automaton.state_edges(state) {
            meter.charge(1)?;
            let target = plan_index(automaton.edge_targets[edge]);
            indegree[target] =
                indegree[target]
                    .checked_sub(1)
                    .ok_or(PreparationError::InternalInvariant {
                        detail: "match-length topological indegree underflowed",
                    })?;
            if indegree[target] == 0 {
                order[order_len] = automaton.edge_targets[edge];
                order_len =
                    order_len
                        .checked_add(1)
                        .ok_or(PreparationError::ArithmeticOverflow {
                            computation: "match-length topological queue publication length",
                        })?;
            }
        }
    }
    if order_len != states {
        return Ok(AcyclicMatchLength::Cyclic { peak_bytes });
    }

    // The indegree ledger is no longer live once Kahn has published the full
    // order. Reuse its allocation for the minimum pass; the maximum pass is
    // allocated only after minimum has been dropped. This keeps the reported
    // peak equal to the largest simultaneously-live analysis footprint.
    drop(indegree);
    let minimum_bytes = preparation_slots_bytes::<usize>(states)?;
    live_scratch =
        order_bytes
            .checked_add(minimum_bytes)
            .ok_or(PreparationError::ArithmeticOverflow {
                computation: "match-length topological minimum bytes",
            })?;
    peak_bytes = peak_bytes.max(check_analysis_peak(
        base_persistent,
        live_scratch,
        peak_limit,
    )?);
    let mut minimum = allocate_preparation_slots(states, usize::MAX, meter)?;
    minimum[plan_index(automaton.start)] = 0;
    for &state_u32 in &order {
        meter.charge(1)?;
        let state = plan_index(state_u32);
        if minimum[state] == usize::MAX {
            continue;
        }
        let weight = usize::from(automaton.roles[state] == StateRole::Consume);
        let candidate =
            minimum[state]
                .checked_add(weight)
                .ok_or(PreparationError::ArithmeticOverflow {
                    computation: "minimum match length",
                })?;
        for edge in automaton.state_edges(state_u32) {
            meter.charge(1)?;
            let target = plan_index(automaton.edge_targets[edge]);
            if candidate < minimum[target] {
                minimum[target] = candidate;
            }
        }
    }
    let mut minimum_accept = usize::MAX;
    let mut found = false;
    for (state, &role) in automaton.roles.iter().enumerate() {
        if role == StateRole::Accept && minimum[state] != usize::MAX {
            minimum_accept = minimum_accept.min(minimum[state]);
            found = true;
        }
    }
    if !found {
        return Ok(AcyclicMatchLength::Proven {
            proof: MatchLengthProof::Empty,
            peak_bytes,
        });
    }

    drop(minimum);
    let maximum_bytes = preparation_slots_bytes::<Option<usize>>(states)?;
    live_scratch =
        order_bytes
            .checked_add(maximum_bytes)
            .ok_or(PreparationError::ArithmeticOverflow {
                computation: "match-length topological maximum bytes",
            })?;
    peak_bytes = peak_bytes.max(check_analysis_peak(
        base_persistent,
        live_scratch,
        peak_limit,
    )?);
    let mut maximum = allocate_preparation_slots(states, None::<usize>, meter)?;
    maximum[plan_index(automaton.start)] = Some(0);
    for &state_u32 in &order {
        meter.charge(1)?;
        let state = plan_index(state_u32);
        let Some(length) = maximum[state] else {
            continue;
        };
        let weight = usize::from(automaton.roles[state] == StateRole::Consume);
        let candidate = length
            .checked_add(weight)
            .ok_or(PreparationError::ArithmeticOverflow {
                computation: "maximum match length",
            })?;
        for edge in automaton.state_edges(state_u32) {
            meter.charge(1)?;
            let target = plan_index(automaton.edge_targets[edge]);
            if maximum[target].map_or(true, |prior| candidate > prior) {
                maximum[target] = Some(candidate);
            }
        }
    }
    let mut maximum_accept = 0usize;
    for (state, &role) in automaton.roles.iter().enumerate() {
        if role == StateRole::Accept {
            if let Some(length) = maximum[state] {
                maximum_accept = maximum_accept.max(length);
            }
        }
    }
    let proof = if minimum_accept == maximum_accept {
        MatchLengthProof::Exact(minimum_accept)
    } else {
        MatchLengthProof::Finite {
            minimum_bytes: minimum_accept,
            maximum_bytes: maximum_accept,
        }
    };
    Ok(AcyclicMatchLength::Proven { proof, peak_bytes })
}

// A frame is deliberately explicit rather than recursive: preparation accepts
// graphs close to its fixed resource limits, so SCC discovery must not consume
// an unbounded call stack.
#[derive(Clone, Copy)]
struct MatchLengthDfsFrame {
    state: u32,
    next_edge: usize,
}

fn match_length_live_bytes(
    slots: &[usize],
    computation: &'static str,
) -> Result<usize, PreparationError> {
    slots.iter().try_fold(0usize, |total, &bytes| {
        total
            .checked_add(bytes)
            .ok_or(PreparationError::ArithmeticOverflow { computation })
    })
}

// Reachability, finite-width and positive-cycle certification share one
// bounded linear graph-analysis ledger for a graph Kahn cannot prove acyclic.
//
// Only states both reachable from start and coreachable to an accept can
// affect a match. Kosaraju's two iterative passes find SCCs in that relevant
// graph. An internal edge from a Consume state is exactly a positive cycle:
// within an SCC its target can return to the source, and every other cycle is
// zero-width. Collapsing those zero-width SCCs leaves a DAG, where ordinary
// forward dynamic programs derive the exact finite minimum and maximum.
#[allow(
    clippy::arithmetic_side_effects,
    clippy::needless_range_loop,
    clippy::too_many_lines,
    reason = "the iterative SCC/condensation passes use checked capacity and index arithmetic to retain an exact bounded ledger"
)]
fn derive_match_length_cyclic(
    automaton: &Automaton,
    meter: &mut PreparationMeter,
    base_persistent: usize,
    peak_limit: usize,
    prior_peak_bytes: usize,
) -> Result<(MatchLengthProof, usize), PreparationError> {
    let states = automaton.stats().states();
    let edges = automaton.stats().edges();
    let states_plus_one = states
        .checked_add(1)
        .ok_or(PreparationError::ArithmeticOverflow {
            computation: "match-length reverse offset length",
        })?;
    let reachable_bytes = preparation_slots_bytes::<bool>(states)?;
    let traversal_stack_bytes = preparation_slots_bytes::<u32>(states)?;
    let reverse_offsets_bytes = preparation_slots_bytes::<usize>(states_plus_one)?;
    let reverse_cursor_bytes = preparation_slots_bytes::<usize>(states)?;
    let reverse_edges_bytes = preparation_slots_bytes::<u32>(edges)?;
    let coreachable_bytes = preparation_slots_bytes::<bool>(states)?;
    let order_bytes = preparation_slots_bytes::<u32>(states)?;
    let dfs_frames_bytes = preparation_slots_bytes::<MatchLengthDfsFrame>(states)?;
    let component_bytes = preparation_slots_bytes::<u32>(states)?;

    let mut peak_bytes = prior_peak_bytes;
    let forward_live = match_length_live_bytes(
        &[reachable_bytes, traversal_stack_bytes],
        "match-length forward traversal live bytes",
    )?;
    peak_bytes = peak_bytes.max(check_analysis_peak(
        base_persistent,
        forward_live,
        peak_limit,
    )?);
    let mut reachable = allocate_preparation_slots(states, false, meter)?;
    let mut traversal_stack = allocate_preparation_slots(states, 0u32, meter)?;
    let start = plan_index(automaton.start);
    reachable[start] = true;
    traversal_stack[0] = automaton.start;
    let mut traversal_len = 1usize;
    while traversal_len != 0 {
        meter.charge(1)?;
        traversal_len =
            traversal_len
                .checked_sub(1)
                .ok_or(PreparationError::InternalInvariant {
                    detail: "match-length forward traversal underflowed",
                })?;
        let state_u32 = traversal_stack[traversal_len];
        for edge in automaton.state_edges(state_u32) {
            meter.charge(1)?;
            let target_u32 = automaton.edge_targets[edge];
            let target = plan_index(target_u32);
            if reachable[target] {
                continue;
            }
            if traversal_len == traversal_stack.len() {
                return Err(PreparationError::InternalInvariant {
                    detail: "match-length forward traversal exceeded state capacity",
                });
            }
            reachable[target] = true;
            traversal_stack[traversal_len] = target_u32;
            traversal_len =
                traversal_len
                    .checked_add(1)
                    .ok_or(PreparationError::ArithmeticOverflow {
                        computation: "match-length forward traversal length",
                    })?;
        }
    }

    // Coreachability needs an explicit predecessor CSR. Build it once and
    // retain it for the reverse SCC pass below.
    let reverse_build_live = match_length_live_bytes(
        &[
            reachable_bytes,
            traversal_stack_bytes,
            reverse_offsets_bytes,
            reverse_cursor_bytes,
            reverse_edges_bytes,
        ],
        "match-length reverse CSR live bytes",
    )?;
    peak_bytes = peak_bytes.max(check_analysis_peak(
        base_persistent,
        reverse_build_live,
        peak_limit,
    )?);
    let mut reverse_offsets = allocate_preparation_slots(states_plus_one, 0usize, meter)?;
    for state in 0..states {
        meter.charge(1)?;
        let state_u32 = u32::try_from(state).map_err(|_| PreparationError::ArithmeticOverflow {
            computation: "match-length reverse CSR state conversion",
        })?;
        for edge in automaton.state_edges(state_u32) {
            meter.charge(1)?;
            let target = plan_index(automaton.edge_targets[edge]);
            let end = target
                .checked_add(1)
                .ok_or(PreparationError::ArithmeticOverflow {
                    computation: "match-length reverse CSR target offset",
                })?;
            reverse_offsets[end] = reverse_offsets[end].checked_add(1).ok_or(
                PreparationError::ArithmeticOverflow {
                    computation: "match-length reverse CSR indegree",
                },
            )?;
        }
    }
    for state in 1..states_plus_one {
        meter.charge(1)?;
        reverse_offsets[state] = reverse_offsets[state]
            .checked_add(reverse_offsets[state - 1])
            .ok_or(PreparationError::ArithmeticOverflow {
                computation: "match-length reverse CSR offset",
            })?;
    }
    let mut reverse_cursor = allocate_preparation_slots(states, 0usize, meter)?;
    for state in 0..states {
        meter.charge(1)?;
        reverse_cursor[state] = reverse_offsets[state];
    }
    let mut reverse_edges = allocate_preparation_slots(edges, 0u32, meter)?;
    for state in 0..states {
        meter.charge(1)?;
        let state_u32 = u32::try_from(state).map_err(|_| PreparationError::ArithmeticOverflow {
            computation: "match-length reverse CSR source conversion",
        })?;
        for edge in automaton.state_edges(state_u32) {
            meter.charge(1)?;
            let target = plan_index(automaton.edge_targets[edge]);
            let slot = reverse_cursor[target];
            reverse_edges[slot] = state_u32;
            reverse_cursor[target] =
                slot.checked_add(1)
                    .ok_or(PreparationError::ArithmeticOverflow {
                        computation: "match-length reverse CSR cursor",
                    })?;
        }
    }
    drop(reverse_cursor);

    let backward_live = match_length_live_bytes(
        &[
            reachable_bytes,
            traversal_stack_bytes,
            reverse_offsets_bytes,
            reverse_edges_bytes,
            coreachable_bytes,
        ],
        "match-length backward traversal live bytes",
    )?;
    peak_bytes = peak_bytes.max(check_analysis_peak(
        base_persistent,
        backward_live,
        peak_limit,
    )?);
    let mut coreachable = allocate_preparation_slots(states, false, meter)?;
    traversal_len = 0;
    for (state, &role) in automaton.roles.iter().enumerate() {
        meter.charge(1)?;
        if role != StateRole::Accept {
            continue;
        }
        if traversal_len == traversal_stack.len() {
            return Err(PreparationError::InternalInvariant {
                detail: "match-length backward traversal exceeded state capacity",
            });
        }
        coreachable[state] = true;
        traversal_stack[traversal_len] =
            u32::try_from(state).map_err(|_| PreparationError::ArithmeticOverflow {
                computation: "match-length backward traversal state conversion",
            })?;
        traversal_len =
            traversal_len
                .checked_add(1)
                .ok_or(PreparationError::ArithmeticOverflow {
                    computation: "match-length backward traversal length",
                })?;
    }
    while traversal_len != 0 {
        meter.charge(1)?;
        traversal_len =
            traversal_len
                .checked_sub(1)
                .ok_or(PreparationError::InternalInvariant {
                    detail: "match-length backward traversal underflowed",
                })?;
        let state = plan_index(traversal_stack[traversal_len]);
        for &source_u32 in &reverse_edges[reverse_offsets[state]..reverse_offsets[state + 1]] {
            meter.charge(1)?;
            let source = plan_index(source_u32);
            if coreachable[source] {
                continue;
            }
            if traversal_len == traversal_stack.len() {
                return Err(PreparationError::InternalInvariant {
                    detail: "match-length backward traversal exceeded state capacity",
                });
            }
            coreachable[source] = true;
            traversal_stack[traversal_len] = source_u32;
            traversal_len =
                traversal_len
                    .checked_add(1)
                    .ok_or(PreparationError::ArithmeticOverflow {
                        computation: "match-length backward traversal length",
                    })?;
        }
    }
    if !coreachable[start] {
        return Ok((MatchLengthProof::Empty, peak_bytes));
    }

    // Retain the intersection as `reachable`, then reuse `coreachable` for
    // the first-pass visited bitset. This keeps the SCC peak bounded without
    // hiding an allocation from the ledger.
    let mut relevant_states = 0usize;
    for state in 0..states {
        meter.charge(1)?;
        let relevant = reachable[state] && coreachable[state];
        reachable[state] = relevant;
        coreachable[state] = false;
        if relevant {
            relevant_states =
                relevant_states
                    .checked_add(1)
                    .ok_or(PreparationError::ArithmeticOverflow {
                        computation: "match-length relevant state count",
                    })?;
        }
    }
    if relevant_states == 0 {
        return Err(PreparationError::InternalInvariant {
            detail: "coreachable start produced no relevant match-length state",
        });
    }
    drop(traversal_stack);

    let first_scc_live = match_length_live_bytes(
        &[
            reachable_bytes,
            reverse_offsets_bytes,
            reverse_edges_bytes,
            coreachable_bytes,
            order_bytes,
            dfs_frames_bytes,
        ],
        "match-length forward SCC live bytes",
    )?;
    peak_bytes = peak_bytes.max(check_analysis_peak(
        base_persistent,
        first_scc_live,
        peak_limit,
    )?);
    let mut finish_order = allocate_preparation_slots(states, 0u32, meter)?;
    let mut dfs_frames = allocate_preparation_slots(
        states,
        MatchLengthDfsFrame {
            state: 0,
            next_edge: 0,
        },
        meter,
    )?;
    let mut finish_len = 0usize;
    for root in 0..states {
        meter.charge(1)?;
        if !reachable[root] || coreachable[root] {
            continue;
        }
        let root_u32 = u32::try_from(root).map_err(|_| PreparationError::ArithmeticOverflow {
            computation: "match-length forward SCC root conversion",
        })?;
        coreachable[root] = true;
        dfs_frames[0] = MatchLengthDfsFrame {
            state: root_u32,
            next_edge: automaton.state_edges(root_u32).start,
        };
        let mut frame_len = 1usize;
        while frame_len != 0 {
            meter.charge(1)?;
            let frame = frame_len - 1;
            let state_u32 = dfs_frames[frame].state;
            let end = automaton.state_edges(state_u32).end;
            let edge = dfs_frames[frame].next_edge;
            if edge == end {
                if finish_len == finish_order.len() {
                    return Err(PreparationError::InternalInvariant {
                        detail: "match-length finish order exceeded state capacity",
                    });
                }
                finish_order[finish_len] = state_u32;
                finish_len =
                    finish_len
                        .checked_add(1)
                        .ok_or(PreparationError::ArithmeticOverflow {
                            computation: "match-length finish order length",
                        })?;
                frame_len =
                    frame_len
                        .checked_sub(1)
                        .ok_or(PreparationError::InternalInvariant {
                            detail: "match-length DFS frame underflowed",
                        })?;
                continue;
            }
            if edge > end {
                return Err(PreparationError::InternalInvariant {
                    detail: "match-length DFS edge cursor exceeded its state range",
                });
            }
            dfs_frames[frame].next_edge =
                edge.checked_add(1)
                    .ok_or(PreparationError::ArithmeticOverflow {
                        computation: "match-length DFS edge cursor",
                    })?;
            meter.charge(1)?;
            let target_u32 = automaton.edge_targets[edge];
            let target = plan_index(target_u32);
            if !reachable[target] || coreachable[target] {
                continue;
            }
            if frame_len == dfs_frames.len() {
                return Err(PreparationError::InternalInvariant {
                    detail: "match-length DFS exceeded state capacity",
                });
            }
            coreachable[target] = true;
            dfs_frames[frame_len] = MatchLengthDfsFrame {
                state: target_u32,
                next_edge: automaton.state_edges(target_u32).start,
            };
            frame_len = frame_len
                .checked_add(1)
                .ok_or(PreparationError::ArithmeticOverflow {
                    computation: "match-length DFS frame length",
                })?;
        }
    }
    if finish_len != relevant_states {
        return Err(PreparationError::InternalInvariant {
            detail: "match-length forward SCC pass omitted a relevant state",
        });
    }

    drop(coreachable);
    let second_scc_live = match_length_live_bytes(
        &[
            reachable_bytes,
            reverse_offsets_bytes,
            reverse_edges_bytes,
            order_bytes,
            dfs_frames_bytes,
            component_bytes,
        ],
        "match-length reverse SCC live bytes",
    )?;
    peak_bytes = peak_bytes.max(check_analysis_peak(
        base_persistent,
        second_scc_live,
        peak_limit,
    )?);
    let mut components = allocate_preparation_slots(states, NO_DFA_STATE, meter)?;
    let mut component_count = 0usize;
    for order_index in (0..finish_len).rev() {
        meter.charge(1)?;
        let root_u32 = finish_order[order_index];
        let root = plan_index(root_u32);
        if components[root] != NO_DFA_STATE {
            continue;
        }
        let component_id =
            u32::try_from(component_count).map_err(|_| PreparationError::ArithmeticOverflow {
                computation: "match-length SCC identifier",
            })?;
        if component_id == NO_DFA_STATE {
            return Err(PreparationError::ArithmeticOverflow {
                computation: "match-length SCC identifier sentinel",
            });
        }
        components[root] = component_id;
        dfs_frames[0] = MatchLengthDfsFrame {
            state: root_u32,
            next_edge: 0,
        };
        let mut frame_len = 1usize;
        while frame_len != 0 {
            meter.charge(1)?;
            frame_len = frame_len
                .checked_sub(1)
                .ok_or(PreparationError::InternalInvariant {
                    detail: "match-length reverse SCC frame underflowed",
                })?;
            let state = plan_index(dfs_frames[frame_len].state);
            for &source_u32 in &reverse_edges[reverse_offsets[state]..reverse_offsets[state + 1]] {
                meter.charge(1)?;
                let source = plan_index(source_u32);
                if !reachable[source] || components[source] != NO_DFA_STATE {
                    continue;
                }
                if frame_len == dfs_frames.len() {
                    return Err(PreparationError::InternalInvariant {
                        detail: "match-length reverse SCC exceeded state capacity",
                    });
                }
                components[source] = component_id;
                dfs_frames[frame_len] = MatchLengthDfsFrame {
                    state: source_u32,
                    next_edge: 0,
                };
                frame_len =
                    frame_len
                        .checked_add(1)
                        .ok_or(PreparationError::ArithmeticOverflow {
                            computation: "match-length reverse SCC frame length",
                        })?;
            }
        }
        component_count =
            component_count
                .checked_add(1)
                .ok_or(PreparationError::ArithmeticOverflow {
                    computation: "match-length SCC count",
                })?;
    }
    if component_count == 0 {
        return Err(PreparationError::InternalInvariant {
            detail: "match-length SCC pass produced no component",
        });
    }

    // A consuming internal edge belongs to a positive cycle precisely because
    // SCC membership supplies a zero-or-more-edge return path. Conversely,
    // every internal edge of a remaining SCC is zero-width, so collapsing it
    // cannot change a finite match length.
    for state in 0..states {
        meter.charge(1)?;
        if !reachable[state] || automaton.roles[state] != StateRole::Consume {
            continue;
        }
        let component = components[state];
        if component == NO_DFA_STATE {
            return Err(PreparationError::InternalInvariant {
                detail: "relevant consuming state lacks an SCC identifier",
            });
        }
        let state_u32 = u32::try_from(state).map_err(|_| PreparationError::ArithmeticOverflow {
            computation: "match-length positive-cycle state conversion",
        })?;
        for edge in automaton.state_edges(state_u32) {
            meter.charge(1)?;
            let target = plan_index(automaton.edge_targets[edge]);
            if reachable[target] && components[target] == component {
                return Ok((MatchLengthProof::Unbounded, peak_bytes));
            }
        }
    }

    // The reverse graph and DFS workspaces are no longer live. Group states
    // by component to traverse each condensation edge once during Kahn and the
    // two exact-length DP passes.
    drop(reverse_offsets);
    drop(reverse_edges);
    drop(finish_order);
    drop(dfs_frames);
    let components_plus_one =
        component_count
            .checked_add(1)
            .ok_or(PreparationError::ArithmeticOverflow {
                computation: "match-length condensation offset length",
            })?;
    let component_offsets_bytes = preparation_slots_bytes::<usize>(components_plus_one)?;
    let component_states_bytes = preparation_slots_bytes::<u32>(relevant_states)?;
    let component_cursor_bytes = preparation_slots_bytes::<usize>(component_count)?;
    let condensation_group_live = match_length_live_bytes(
        &[
            reachable_bytes,
            component_bytes,
            component_offsets_bytes,
            component_states_bytes,
            component_cursor_bytes,
        ],
        "match-length condensation grouping live bytes",
    )?;
    peak_bytes = peak_bytes.max(check_analysis_peak(
        base_persistent,
        condensation_group_live,
        peak_limit,
    )?);
    let mut component_offsets = allocate_preparation_slots(components_plus_one, 0usize, meter)?;
    for state in 0..states {
        meter.charge(1)?;
        if !reachable[state] {
            continue;
        }
        let component = plan_index(components[state]);
        if component >= component_count {
            return Err(PreparationError::InternalInvariant {
                detail: "relevant state has an invalid SCC identifier",
            });
        }
        let next = component
            .checked_add(1)
            .ok_or(PreparationError::ArithmeticOverflow {
                computation: "match-length condensation component offset",
            })?;
        component_offsets[next] =
            component_offsets[next]
                .checked_add(1)
                .ok_or(PreparationError::ArithmeticOverflow {
                    computation: "match-length condensation component size",
                })?;
    }
    for component in 1..components_plus_one {
        meter.charge(1)?;
        component_offsets[component] = component_offsets[component]
            .checked_add(component_offsets[component - 1])
            .ok_or(PreparationError::ArithmeticOverflow {
                computation: "match-length condensation offset",
            })?;
    }
    let mut indegree = allocate_preparation_slots(component_count, 0usize, meter)?;
    for component in 0..component_count {
        meter.charge(1)?;
        indegree[component] = component_offsets[component];
    }
    let mut component_states = allocate_preparation_slots(relevant_states, 0u32, meter)?;
    for state in 0..states {
        meter.charge(1)?;
        if !reachable[state] {
            continue;
        }
        let component = plan_index(components[state]);
        let slot = indegree[component];
        if slot >= component_states.len() {
            return Err(PreparationError::InternalInvariant {
                detail: "match-length condensation state cursor exceeded capacity",
            });
        }
        component_states[slot] =
            u32::try_from(state).map_err(|_| PreparationError::ArithmeticOverflow {
                computation: "match-length condensation state conversion",
            })?;
        indegree[component] = slot
            .checked_add(1)
            .ok_or(PreparationError::ArithmeticOverflow {
                computation: "match-length condensation state cursor",
            })?;
    }
    for entry in &mut indegree {
        meter.charge(1)?;
        *entry = 0;
    }

    let component_queue_bytes = preparation_slots_bytes::<u32>(component_count)?;
    let component_order_bytes = preparation_slots_bytes::<u32>(component_count)?;
    let condensation_topological_live = match_length_live_bytes(
        &[
            condensation_group_live,
            component_queue_bytes,
            component_order_bytes,
        ],
        "match-length condensation topological live bytes",
    )?;
    peak_bytes = peak_bytes.max(check_analysis_peak(
        base_persistent,
        condensation_topological_live,
        peak_limit,
    )?);
    let mut component_queue = allocate_preparation_slots(component_count, 0u32, meter)?;
    let mut component_order = allocate_preparation_slots(component_count, 0u32, meter)?;
    for component in 0..component_count {
        meter.charge(1)?;
        for &state_u32 in
            &component_states[component_offsets[component]..component_offsets[component + 1]]
        {
            meter.charge(1)?;
            for edge in automaton.state_edges(state_u32) {
                meter.charge(1)?;
                let target = plan_index(automaton.edge_targets[edge]);
                if !reachable[target] {
                    continue;
                }
                let target_component = plan_index(components[target]);
                if target_component == component {
                    continue;
                }
                indegree[target_component] = indegree[target_component].checked_add(1).ok_or(
                    PreparationError::ArithmeticOverflow {
                        computation: "match-length condensation indegree",
                    },
                )?;
            }
        }
    }
    let mut queue_len = 0usize;
    for component in 0..component_count {
        meter.charge(1)?;
        if indegree[component] != 0 {
            continue;
        }
        component_queue[queue_len] =
            u32::try_from(component).map_err(|_| PreparationError::ArithmeticOverflow {
                computation: "match-length condensation queue conversion",
            })?;
        queue_len = queue_len
            .checked_add(1)
            .ok_or(PreparationError::ArithmeticOverflow {
                computation: "match-length condensation queue length",
            })?;
    }
    let mut queue_cursor = 0usize;
    let mut component_order_len = 0usize;
    while queue_cursor < queue_len {
        meter.charge(1)?;
        let component = plan_index(component_queue[queue_cursor]);
        queue_cursor = queue_cursor
            .checked_add(1)
            .ok_or(PreparationError::ArithmeticOverflow {
                computation: "match-length condensation queue cursor",
            })?;
        component_order[component_order_len] =
            u32::try_from(component).map_err(|_| PreparationError::ArithmeticOverflow {
                computation: "match-length condensation order conversion",
            })?;
        component_order_len =
            component_order_len
                .checked_add(1)
                .ok_or(PreparationError::ArithmeticOverflow {
                    computation: "match-length condensation order length",
                })?;
        for &state_u32 in
            &component_states[component_offsets[component]..component_offsets[component + 1]]
        {
            meter.charge(1)?;
            for edge in automaton.state_edges(state_u32) {
                meter.charge(1)?;
                let target = plan_index(automaton.edge_targets[edge]);
                if !reachable[target] {
                    continue;
                }
                let target_component = plan_index(components[target]);
                if target_component == component {
                    continue;
                }
                indegree[target_component] = indegree[target_component].checked_sub(1).ok_or(
                    PreparationError::InternalInvariant {
                        detail: "match-length condensation indegree underflowed",
                    },
                )?;
                if indegree[target_component] != 0 {
                    continue;
                }
                if queue_len == component_queue.len() {
                    return Err(PreparationError::InternalInvariant {
                        detail: "match-length condensation queue exceeded component capacity",
                    });
                }
                component_queue[queue_len] = u32::try_from(target_component).map_err(|_| {
                    PreparationError::ArithmeticOverflow {
                        computation: "match-length condensation queue publication",
                    }
                })?;
                queue_len =
                    queue_len
                        .checked_add(1)
                        .ok_or(PreparationError::ArithmeticOverflow {
                            computation: "match-length condensation queue publication length",
                        })?;
            }
        }
    }
    if component_order_len != component_count {
        return Err(PreparationError::InternalInvariant {
            detail: "zero-width SCC condensation retained a cycle",
        });
    }
    drop(component_queue);

    let minimum_bytes = preparation_slots_bytes::<usize>(component_count)?;
    let condensation_minimum_live = match_length_live_bytes(
        &[
            condensation_group_live,
            component_order_bytes,
            minimum_bytes,
        ],
        "match-length condensation minimum live bytes",
    )?;
    peak_bytes = peak_bytes.max(check_analysis_peak(
        base_persistent,
        condensation_minimum_live,
        peak_limit,
    )?);
    let mut minimum = allocate_preparation_slots(component_count, usize::MAX, meter)?;
    let start_component = plan_index(components[start]);
    minimum[start_component] = 0;
    for &component_u32 in &component_order[..component_order_len] {
        meter.charge(1)?;
        let component = plan_index(component_u32);
        let length = minimum[component];
        if length == usize::MAX {
            return Err(PreparationError::InternalInvariant {
                detail: "relevant SCC is unreachable in condensation minimum DP",
            });
        }
        for &state_u32 in
            &component_states[component_offsets[component]..component_offsets[component + 1]]
        {
            meter.charge(1)?;
            let state = plan_index(state_u32);
            let candidate = length
                .checked_add(usize::from(automaton.roles[state] == StateRole::Consume))
                .ok_or(PreparationError::ArithmeticOverflow {
                    computation: "minimum match length",
                })?;
            for edge in automaton.state_edges(state_u32) {
                meter.charge(1)?;
                let target = plan_index(automaton.edge_targets[edge]);
                if !reachable[target] {
                    continue;
                }
                let target_component = plan_index(components[target]);
                if target_component != component && candidate < minimum[target_component] {
                    minimum[target_component] = candidate;
                }
            }
        }
    }
    let mut minimum_accept = usize::MAX;
    let mut found_accept = false;
    for (state, &role) in automaton.roles.iter().enumerate() {
        meter.charge(1)?;
        if role != StateRole::Accept || !reachable[state] {
            continue;
        }
        let length = minimum[plan_index(components[state])];
        if length == usize::MAX {
            return Err(PreparationError::InternalInvariant {
                detail: "relevant accept is unreachable in condensation minimum DP",
            });
        }
        minimum_accept = minimum_accept.min(length);
        found_accept = true;
    }
    if !found_accept {
        return Err(PreparationError::InternalInvariant {
            detail: "coreachable start had no relevant accept",
        });
    }
    drop(minimum);

    let maximum_bytes = preparation_slots_bytes::<Option<usize>>(component_count)?;
    let condensation_maximum_live = match_length_live_bytes(
        &[
            condensation_group_live,
            component_order_bytes,
            maximum_bytes,
        ],
        "match-length condensation maximum live bytes",
    )?;
    peak_bytes = peak_bytes.max(check_analysis_peak(
        base_persistent,
        condensation_maximum_live,
        peak_limit,
    )?);
    let mut maximum = allocate_preparation_slots(component_count, None::<usize>, meter)?;
    maximum[start_component] = Some(0);
    for &component_u32 in &component_order[..component_order_len] {
        meter.charge(1)?;
        let component = plan_index(component_u32);
        let length = maximum[component].ok_or(PreparationError::InternalInvariant {
            detail: "relevant SCC is unreachable in condensation maximum DP",
        })?;
        for &state_u32 in
            &component_states[component_offsets[component]..component_offsets[component + 1]]
        {
            meter.charge(1)?;
            let state = plan_index(state_u32);
            let candidate = length
                .checked_add(usize::from(automaton.roles[state] == StateRole::Consume))
                .ok_or(PreparationError::ArithmeticOverflow {
                    computation: "maximum match length",
                })?;
            for edge in automaton.state_edges(state_u32) {
                meter.charge(1)?;
                let target = plan_index(automaton.edge_targets[edge]);
                if !reachable[target] {
                    continue;
                }
                let target_component = plan_index(components[target]);
                if target_component != component
                    && maximum[target_component].map_or(true, |prior| candidate > prior)
                {
                    maximum[target_component] = Some(candidate);
                }
            }
        }
    }
    let mut maximum_accept = 0usize;
    for (state, &role) in automaton.roles.iter().enumerate() {
        meter.charge(1)?;
        if role != StateRole::Accept || !reachable[state] {
            continue;
        }
        let length =
            maximum[plan_index(components[state])].ok_or(PreparationError::InternalInvariant {
                detail: "relevant accept is unreachable in condensation maximum DP",
            })?;
        maximum_accept = maximum_accept.max(length);
    }

    if minimum_accept == maximum_accept {
        Ok((MatchLengthProof::Exact(minimum_accept), peak_bytes))
    } else {
        Ok((
            MatchLengthProof::Finite {
                minimum_bytes: minimum_accept,
                maximum_bytes: maximum_accept,
            },
            peak_bytes,
        ))
    }
}

fn preparation_slots_bytes<T>(length: usize) -> Result<usize, PreparationError> {
    length
        .checked_mul(size_of::<T>())
        .ok_or(PreparationError::ArithmeticOverflow {
            computation: "preparation analysis allocation bytes",
        })
}

fn check_analysis_peak(
    base_persistent: usize,
    live_scratch: usize,
    peak_limit: usize,
) -> Result<usize, PreparationError> {
    let peak_bytes =
        base_persistent
            .checked_add(live_scratch)
            .ok_or(PreparationError::ArithmeticOverflow {
                computation: "analysis peak bytes",
            })?;
    check_preparation_usize(PreparationResource::PeakBytes, peak_bytes, peak_limit)?;
    Ok(peak_bytes)
}

fn allocate_preparation_slots<T: Clone>(
    length: usize,
    value: T,
    meter: &mut PreparationMeter,
) -> Result<Vec<T>, PreparationError> {
    let bytes = preparation_slots_bytes::<T>(length)?;
    let mut slots = Vec::new();
    meter.allocation()?;
    slots
        .try_reserve_exact(length)
        .map_err(|_| PreparationError::AllocationFailed { bytes })?;
    slots.resize(length, value);
    if slots.capacity() != length {
        return Err(PreparationError::AllocationFailed {
            bytes: slots.capacity().saturating_mul(size_of::<T>()),
        });
    }
    Ok(slots)
}

// Split states depend only on the current boundary row, while consume states
// depend only on the next row. Publishing one reverse topological split order
// turns every acyclic sparse boundary into one priority-preserving pass. The
// explicit cyclic tag retains the pre-existing bounded DFS semantics.
fn populate_sparse_split_queue(
    automaton: &Automaton,
    indegree: &mut [usize],
    queue: &mut [u32],
    meter: &mut PreparationMeter,
) -> Result<(usize, usize), PreparationError> {
    let mut split_count = 0usize;
    for (state, &role) in automaton.roles.iter().enumerate() {
        meter.charge(1)?;
        if role != StateRole::Split {
            continue;
        }
        split_count = split_count
            .checked_add(1)
            .ok_or(PreparationError::ArithmeticOverflow {
                computation: "sparse split-state count",
            })?;
        let state = u32::try_from(state).map_err(|_| PreparationError::ArithmeticOverflow {
            computation: "sparse split-state conversion",
        })?;
        for edge in automaton.state_edges(state) {
            meter.charge(1)?;
            let target = plan_index(automaton.edge_targets[edge]);
            if automaton.roles[target] == StateRole::Split {
                indegree[target] = indegree[target].checked_add(1).ok_or(
                    PreparationError::ArithmeticOverflow {
                        computation: "sparse split indegree",
                    },
                )?;
            }
        }
    }

    let mut queue_len = 0usize;
    for (state, (&role, &degree)) in automaton.roles.iter().zip(indegree.iter()).enumerate() {
        meter.charge(1)?;
        if role == StateRole::Split && degree == 0 {
            queue[queue_len] =
                u32::try_from(state).map_err(|_| PreparationError::ArithmeticOverflow {
                    computation: "sparse queue state conversion",
                })?;
            queue_len = queue_len
                .checked_add(1)
                .ok_or(PreparationError::ArithmeticOverflow {
                    computation: "sparse queue length",
                })?;
        }
    }

    let mut queue_cursor = 0usize;
    while queue_cursor < queue_len {
        meter.charge(1)?;
        let state = queue[queue_cursor];
        queue_cursor = queue_cursor
            .checked_add(1)
            .ok_or(PreparationError::ArithmeticOverflow {
                computation: "sparse queue cursor",
            })?;
        for edge in automaton.state_edges(state) {
            meter.charge(1)?;
            let target = plan_index(automaton.edge_targets[edge]);
            if automaton.roles[target] != StateRole::Split {
                continue;
            }
            indegree[target] =
                indegree[target]
                    .checked_sub(1)
                    .ok_or(PreparationError::InternalInvariant {
                        detail: "sparse split indegree underflowed",
                    })?;
            if indegree[target] == 0 {
                queue[queue_len] = automaton.edge_targets[edge];
                queue_len =
                    queue_len
                        .checked_add(1)
                        .ok_or(PreparationError::ArithmeticOverflow {
                            computation: "sparse queue publication length",
                        })?;
            }
        }
    }
    Ok((split_count, queue_len))
}

fn build_sparse_evaluation(
    automaton: &Automaton,
    meter: &mut PreparationMeter,
    base_persistent: usize,
    peak_limit: usize,
) -> Result<(SparseEvaluation, usize), PreparationError> {
    let states = automaton.stats().states();
    let indegree_bytes = preparation_slots_bytes::<usize>(states)?;
    let index_bytes = preparation_slots_bytes::<u32>(states)?;
    let cyclic_live_bytes =
        indegree_bytes
            .checked_add(index_bytes)
            .ok_or(PreparationError::ArithmeticOverflow {
                computation: "sparse cycle-analysis live bytes",
            })?;
    let cyclic_peak = check_analysis_peak(base_persistent, cyclic_live_bytes, peak_limit)?;

    let mut indegree = allocate_preparation_slots(states, 0usize, meter)?;
    let mut queue = allocate_preparation_slots(states, 0u32, meter)?;
    let (split_count, queue_len) =
        populate_sparse_split_queue(automaton, &mut indegree, &mut queue, meter)?;
    if queue_len != split_count {
        return Ok((SparseEvaluation::Cyclic, cyclic_peak));
    }

    let acyclic_live_bytes =
        cyclic_live_bytes
            .checked_add(index_bytes)
            .ok_or(PreparationError::ArithmeticOverflow {
                computation: "sparse evaluation-order live bytes",
            })?;
    let acyclic_peak = check_analysis_peak(base_persistent, acyclic_live_bytes, peak_limit)?;
    let mut order = allocate_preparation_slots(states, 0u32, meter)?;
    let mut order_len = 0usize;
    for state in 0..states {
        meter.charge(1)?;
        if automaton.roles[state] != StateRole::Split {
            order[order_len] =
                u32::try_from(state).map_err(|_| PreparationError::ArithmeticOverflow {
                    computation: "sparse base-state conversion",
                })?;
            order_len = order_len
                .checked_add(1)
                .ok_or(PreparationError::ArithmeticOverflow {
                    computation: "sparse evaluation-order length",
                })?;
        }
    }
    for &state in queue[..queue_len].iter().rev() {
        meter.charge(1)?;
        order[order_len] = state;
        order_len = order_len
            .checked_add(1)
            .ok_or(PreparationError::ArithmeticOverflow {
                computation: "sparse split-order length",
            })?;
    }
    if order_len != states {
        return Err(PreparationError::InternalInvariant {
            detail: "sparse evaluation order omitted a state",
        });
    }
    Ok((
        SparseEvaluation::Acyclic(order.into_boxed_slice()),
        acyclic_peak,
    ))
}

fn sparse_evaluation_bytes(evaluation: &SparseEvaluation) -> Result<usize, PreparationError> {
    match evaluation {
        SparseEvaluation::Acyclic(order) => preparation_slots_bytes::<u32>(order.len()),
        SparseEvaluation::Cyclic => Ok(0),
    }
}

fn check_tagged_preparation_resources(
    resources: TaggedProgramResources,
    limits: PreparationLimits,
) -> Result<(), PreparationError> {
    check_preparation_usize(
        PreparationResource::TaggedDispatchStates,
        resources.states,
        limits.max_tagged_dispatch_states,
    )?;
    check_preparation_usize(
        PreparationResource::TaggedDispatchCells,
        resources.cells,
        limits.max_tagged_dispatch_cells,
    )?;
    check_preparation_usize(
        PreparationResource::TaggedCandidateItems,
        resources.candidates,
        limits.max_tagged_candidate_items,
    )
}

fn tagged_range_bytes(count: usize) -> Result<usize, PreparationError> {
    preparation_slots_bytes::<TaggedDispatchRange>(count)
}

fn full_tagged_dispatch_bytes(
    resources: TaggedProgramResources,
) -> Result<usize, PreparationError> {
    tagged_range_bytes(resources.states)?
        .checked_add(preparation_slots_bytes::<TaggedDispatchInterval>(
            resources.cells,
        )?)
        .ok_or(PreparationError::ArithmeticOverflow {
            computation: "full tagged dispatch persistent bytes",
        })
}

fn lazy_tagged_dispatch_bytes(
    resources: TaggedProgramResources,
) -> Result<usize, PreparationError> {
    tagged_range_bytes(resources.states)
}

fn full_tagged_transducer_bytes(
    transducer: &FullTaggedTransducer,
) -> Result<usize, PreparationError> {
    sparse_evaluation_bytes(&transducer.evaluation)?
        .checked_add(full_tagged_dispatch_bytes(transducer.resources)?)
        .ok_or(PreparationError::ArithmeticOverflow {
            computation: "full tagged transducer persistent bytes",
        })
}

fn lazy_tagged_transducer_bytes(
    transducer: &LazyTaggedTransducer,
) -> Result<usize, PreparationError> {
    sparse_evaluation_bytes(&transducer.evaluation)?
        .checked_add(lazy_tagged_dispatch_bytes(transducer.resources)?)
        .ok_or(PreparationError::ArithmeticOverflow {
            computation: "lazy tagged transducer persistent bytes",
        })
}

fn first_tagged_edges(
    automaton: &Automaton,
    state: u32,
    meter: &mut PreparationMeter,
) -> Result<[u32; BYTE_VALUES], PreparationError> {
    let mut first = [NO_TAGGED_EDGE; BYTE_VALUES];
    for edge in automaton.state_edges(state) {
        meter.charge(1)?;
        let edge_u32 = u32::try_from(edge).map_err(|_| PreparationError::ArithmeticOverflow {
            computation: "tagged candidate edge conversion",
        })?;
        for byte in automaton.byte_starts[edge]..=automaton.byte_ends[edge] {
            meter.charge(1)?;
            let slot = &mut first[usize::from(byte)];
            if *slot == NO_TAGGED_EDGE {
                *slot = edge_u32;
            }
        }
    }
    Ok(first)
}

fn count_full_tagged_intervals(
    first: &[u32; BYTE_VALUES],
    meter: &mut PreparationMeter,
) -> Result<(usize, usize), PreparationError> {
    let mut cursor = 0usize;
    let mut cells = 0usize;
    let mut candidates = 0usize;
    while cursor < BYTE_VALUES {
        meter.charge(1)?;
        let first_edge = first[cursor];
        let mut end = cursor
            .checked_add(1)
            .ok_or(PreparationError::ArithmeticOverflow {
                computation: "tagged interval cursor",
            })?;
        while end < BYTE_VALUES && first[end] == first_edge {
            meter.charge(1)?;
            end = end
                .checked_add(1)
                .ok_or(PreparationError::ArithmeticOverflow {
                    computation: "tagged interval end",
                })?;
        }
        cells = cells
            .checked_add(1)
            .ok_or(PreparationError::ArithmeticOverflow {
                computation: "tagged dispatch interval count",
            })?;
        candidates = candidates
            .checked_add(usize::from(first_edge != NO_TAGGED_EDGE))
            .ok_or(PreparationError::ArithmeticOverflow {
                computation: "tagged candidate entry count",
            })?;
        cursor = end;
    }
    Ok((cells, candidates))
}

fn analyze_full_tagged_resources(
    automaton: &Automaton,
    meter: &mut PreparationMeter,
) -> Result<TaggedProgramResources, PreparationError> {
    let states = automaton.stats().states();
    let mut resources = TaggedProgramResources {
        states,
        ..TaggedProgramResources::default()
    };
    for state_index in 0..states {
        meter.charge(1)?;
        if automaton.roles[state_index] != StateRole::Consume {
            continue;
        }
        let state =
            u32::try_from(state_index).map_err(|_| PreparationError::ArithmeticOverflow {
                computation: "full tagged dispatch state conversion",
            })?;
        let first = first_tagged_edges(automaton, state, meter)?;
        let (cells, candidates) = count_full_tagged_intervals(&first, meter)?;
        resources.cells =
            resources
                .cells
                .checked_add(cells)
                .ok_or(PreparationError::ArithmeticOverflow {
                    computation: "full tagged dispatch cell count",
                })?;
        resources.candidates = resources.candidates.checked_add(candidates).ok_or(
            PreparationError::ArithmeticOverflow {
                computation: "full tagged candidate count",
            },
        )?;
    }
    Ok(resources)
}

fn analyze_lazy_tagged_resources(
    automaton: &Automaton,
    meter: &mut PreparationMeter,
) -> Result<TaggedProgramResources, PreparationError> {
    let states = automaton.stats().states();
    let mut resources = TaggedProgramResources {
        states,
        cells: states,
        candidates: 0,
    };
    for state_index in 0..states {
        meter.charge(1)?;
        if automaton.roles[state_index] != StateRole::Consume {
            continue;
        }
        let state =
            u32::try_from(state_index).map_err(|_| PreparationError::ArithmeticOverflow {
                computation: "lazy tagged dispatch state conversion",
            })?;
        for _ in automaton.state_edges(state) {
            meter.charge(1)?;
            resources.candidates = resources.candidates.checked_add(1).ok_or(
                PreparationError::ArithmeticOverflow {
                    computation: "lazy tagged candidate count",
                },
            )?;
        }
    }
    Ok(resources)
}

#[allow(clippy::too_many_lines)]
fn build_full_tagged_transducer(
    automaton: &Automaton,
    limits: PreparationLimits,
    meter: &mut PreparationMeter,
    base_persistent: usize,
) -> Result<(FullTaggedTransducer, usize), PreparationError> {
    let (evaluation, evaluation_peak) =
        build_sparse_evaluation(automaton, meter, base_persistent, limits.max_peak_bytes)?;
    let evaluation_bytes = sparse_evaluation_bytes(&evaluation)?;
    let resources = analyze_full_tagged_resources(automaton, meter)?;
    check_tagged_preparation_resources(resources, limits)?;
    let dispatch_bytes = full_tagged_dispatch_bytes(resources)?;
    let route_bytes = evaluation_bytes.checked_add(dispatch_bytes).ok_or(
        PreparationError::ArithmeticOverflow {
            computation: "full tagged route bytes",
        },
    )?;
    let persistent =
        base_persistent
            .checked_add(route_bytes)
            .ok_or(PreparationError::ArithmeticOverflow {
                computation: "full tagged persistent bytes",
            })?;
    check_preparation_usize(
        PreparationResource::PersistentBytes,
        persistent,
        limits.max_persistent_bytes,
    )?;
    let dispatch_base = base_persistent.checked_add(evaluation_bytes).ok_or(
        PreparationError::ArithmeticOverflow {
            computation: "full tagged dispatch base bytes",
        },
    )?;
    let dispatch_peak = check_analysis_peak(dispatch_base, dispatch_bytes, limits.max_peak_bytes)?;

    let mut state_intervals =
        allocate_preparation_slots(resources.states, TaggedDispatchRange::default(), meter)?;
    let mut intervals = allocate_preparation_slots(
        resources.cells,
        TaggedDispatchInterval {
            byte_start: 0,
            byte_end: 0,
            first_edge: NO_TAGGED_EDGE,
        },
        meter,
    )?;
    let mut interval_len = 0usize;
    let mut candidate_len = 0usize;
    for (state_index, state_interval) in state_intervals.iter_mut().enumerate() {
        meter.charge(1)?;
        let range_start = interval_len;
        if automaton.roles[state_index] == StateRole::Consume {
            let state =
                u32::try_from(state_index).map_err(|_| PreparationError::ArithmeticOverflow {
                    computation: "full tagged fill state conversion",
                })?;
            let first = first_tagged_edges(automaton, state, meter)?;
            let mut cursor = 0usize;
            while cursor < BYTE_VALUES {
                meter.charge(1)?;
                let first_edge = first[cursor];
                let mut end =
                    cursor
                        .checked_add(1)
                        .ok_or(PreparationError::ArithmeticOverflow {
                            computation: "full tagged fill interval cursor",
                        })?;
                while end < BYTE_VALUES && first[end] == first_edge {
                    meter.charge(1)?;
                    end = end
                        .checked_add(1)
                        .ok_or(PreparationError::ArithmeticOverflow {
                            computation: "full tagged fill interval end",
                        })?;
                }
                let slot =
                    intervals
                        .get_mut(interval_len)
                        .ok_or(PreparationError::InternalInvariant {
                            detail: "full tagged interval analysis undercounted publication",
                        })?;
                *slot = TaggedDispatchInterval {
                    byte_start: u8::try_from(cursor).map_err(|_| {
                        PreparationError::InternalInvariant {
                            detail: "full tagged interval start exceeded byte domain",
                        }
                    })?,
                    byte_end: u8::try_from(end.checked_sub(1).ok_or(
                        PreparationError::InternalInvariant {
                            detail: "full tagged interval had no byte",
                        },
                    )?)
                    .map_err(|_| PreparationError::InternalInvariant {
                        detail: "full tagged interval end exceeded byte domain",
                    })?,
                    first_edge,
                };
                interval_len =
                    interval_len
                        .checked_add(1)
                        .ok_or(PreparationError::ArithmeticOverflow {
                            computation: "full tagged interval publication length",
                        })?;
                candidate_len = candidate_len
                    .checked_add(usize::from(first_edge != NO_TAGGED_EDGE))
                    .ok_or(PreparationError::ArithmeticOverflow {
                        computation: "full tagged candidate publication length",
                    })?;
                cursor = end;
            }
        }
        *state_interval = TaggedDispatchRange {
            start: u32::try_from(range_start).map_err(|_| {
                PreparationError::ArithmeticOverflow {
                    computation: "full tagged interval start conversion",
                }
            })?,
            end: u32::try_from(interval_len).map_err(|_| PreparationError::ArithmeticOverflow {
                computation: "full tagged interval end conversion",
            })?,
        };
    }
    if interval_len != resources.cells || candidate_len != resources.candidates {
        return Err(PreparationError::InternalInvariant {
            detail: "full tagged dispatch analysis disagreed with publication",
        });
    }
    Ok((
        FullTaggedTransducer {
            evaluation,
            state_intervals: state_intervals.into_boxed_slice(),
            intervals: intervals.into_boxed_slice(),
            resources,
        },
        evaluation_peak.max(dispatch_peak),
    ))
}

fn build_lazy_tagged_transducer(
    automaton: &Automaton,
    limits: PreparationLimits,
    meter: &mut PreparationMeter,
    base_persistent: usize,
) -> Result<(LazyTaggedTransducer, usize), PreparationError> {
    let (evaluation, evaluation_peak) =
        build_sparse_evaluation(automaton, meter, base_persistent, limits.max_peak_bytes)?;
    let evaluation_bytes = sparse_evaluation_bytes(&evaluation)?;
    let resources = analyze_lazy_tagged_resources(automaton, meter)?;
    check_tagged_preparation_resources(resources, limits)?;
    let dispatch_bytes = lazy_tagged_dispatch_bytes(resources)?;
    let route_bytes = evaluation_bytes.checked_add(dispatch_bytes).ok_or(
        PreparationError::ArithmeticOverflow {
            computation: "lazy tagged route bytes",
        },
    )?;
    let persistent =
        base_persistent
            .checked_add(route_bytes)
            .ok_or(PreparationError::ArithmeticOverflow {
                computation: "lazy tagged persistent bytes",
            })?;
    check_preparation_usize(
        PreparationResource::PersistentBytes,
        persistent,
        limits.max_persistent_bytes,
    )?;
    let dispatch_base = base_persistent.checked_add(evaluation_bytes).ok_or(
        PreparationError::ArithmeticOverflow {
            computation: "lazy tagged dispatch base bytes",
        },
    )?;
    let dispatch_peak = check_analysis_peak(dispatch_base, dispatch_bytes, limits.max_peak_bytes)?;

    let mut state_edges =
        allocate_preparation_slots(resources.states, TaggedDispatchRange::default(), meter)?;
    for (state_index, slot) in state_edges.iter_mut().enumerate() {
        meter.charge(1)?;
        let state =
            u32::try_from(state_index).map_err(|_| PreparationError::ArithmeticOverflow {
                computation: "lazy tagged fill state conversion",
            })?;
        let edges = automaton.state_edges(state);
        *slot = TaggedDispatchRange {
            start: u32::try_from(edges.start).map_err(|_| {
                PreparationError::ArithmeticOverflow {
                    computation: "lazy tagged edge start conversion",
                }
            })?,
            end: u32::try_from(edges.end).map_err(|_| PreparationError::ArithmeticOverflow {
                computation: "lazy tagged edge end conversion",
            })?,
        };
    }
    Ok((
        LazyTaggedTransducer {
            evaluation,
            state_edges: state_edges.into_boxed_slice(),
            resources,
        },
        evaluation_peak.max(dispatch_peak),
    ))
}

/// Whether the requested DFA route can use its classic fixed-width byte-table
/// kernel.
///
/// A negative result is not a preparation refusal: the caller publishes the
/// separately bounded priority-tagged transducer instead. Arithmetic and
/// resource failures still remain terminal before a route can be returned.
fn dfa_domain_is_classic_exact_nonempty(
    automaton: &Automaton,
    match_length: MatchLengthProof,
    meter: &mut PreparationMeter,
) -> Result<bool, PreparationError> {
    if matches!(match_length, MatchLengthProof::Empty) {
        return Err(PreparationError::DfaRequiresNonEmptyMatch);
    }
    if matches!(
        match_length,
        MatchLengthProof::Exact(0)
            | MatchLengthProof::Finite {
                minimum_bytes: 0,
                ..
            }
    ) {
        return Ok(false);
    }
    let Some(exact_bytes) = match_length.exact() else {
        return Ok(false);
    };
    debug_assert_ne!(exact_bytes, 0);
    match validate_dfa_domain(automaton, meter) {
        Ok(()) => Ok(true),
        Err(
            PreparationError::DfaRequiresZeroWidthFreeAutomaton { .. }
            | PreparationError::DfaRequiresByteDeterminism { .. },
        ) => Ok(false),
        Err(error) => Err(error),
    }
}

fn validate_dfa_domain(
    automaton: &Automaton,
    meter: &mut PreparationMeter,
) -> Result<(), PreparationError> {
    for (state, &role) in automaton.roles.iter().enumerate() {
        meter.charge(1)?;
        match role {
            StateRole::Split => {
                return Err(PreparationError::DfaRequiresZeroWidthFreeAutomaton { state });
            }
            StateRole::Accept => {}
            StateRole::Consume => {
                let mut claimed = [false; BYTE_VALUES];
                let state =
                    u32::try_from(state).map_err(|_| PreparationError::ArithmeticOverflow {
                        computation: "DFA validation state conversion",
                    })?;
                for edge in automaton.state_edges(state) {
                    meter.charge(1)?;
                    let start = automaton.byte_starts[edge];
                    let end = automaton.byte_ends[edge];
                    for byte in start..=end {
                        meter.charge(1)?;
                        let slot = &mut claimed[usize::from(byte)];
                        if *slot {
                            return Err(PreparationError::DfaRequiresByteDeterminism {
                                state: plan_index(state),
                                byte,
                            });
                        }
                        *slot = true;
                    }
                }
            }
        }
    }
    Ok(())
}

struct FullBuildLedger {
    base_bytes: usize,
    subset_descriptors: usize,
    subset_items: usize,
    cells: usize,
    peak_bytes: usize,
    limits: PreparationLimits,
}

impl FullBuildLedger {
    const fn new(base_bytes: usize, limits: PreparationLimits) -> Self {
        Self {
            base_bytes,
            subset_descriptors: 0,
            subset_items: 0,
            cells: 0,
            peak_bytes: base_bytes,
            limits,
        }
    }

    fn route_bytes(
        subset_descriptors: usize,
        subset_items: usize,
        cells: usize,
    ) -> Result<usize, PreparationError> {
        subset_descriptors
            .checked_mul(size_of::<Box<[u32]>>())
            .and_then(|bytes| {
                subset_items
                    .checked_mul(size_of::<u32>())
                    .and_then(|items| bytes.checked_add(items))
            })
            .and_then(|bytes| {
                cells
                    .checked_mul(size_of::<DfaTransition>())
                    .and_then(|cell_bytes| bytes.checked_add(cell_bytes))
            })
            .ok_or(PreparationError::ArithmeticOverflow {
                computation: "full DFA builder bytes",
            })
    }

    fn observe(
        &mut self,
        descriptors: usize,
        items: usize,
        cells: usize,
        temporary_bytes: usize,
    ) -> Result<(), PreparationError> {
        let route = Self::route_bytes(descriptors, items, cells)?;
        let persistent =
            self.base_bytes
                .checked_add(route)
                .ok_or(PreparationError::ArithmeticOverflow {
                    computation: "full DFA builder persistent bytes",
                })?;
        check_preparation_usize(
            PreparationResource::PersistentBytes,
            persistent,
            self.limits.max_persistent_bytes,
        )?;
        let live = persistent.checked_add(temporary_bytes).ok_or(
            PreparationError::ArithmeticOverflow {
                computation: "full DFA builder live bytes",
            },
        )?;
        check_preparation_usize(
            PreparationResource::PeakBytes,
            live,
            self.limits.max_peak_bytes,
        )?;
        self.peak_bytes = self.peak_bytes.max(live);
        Ok(())
    }

    fn add_cells(&mut self, count: usize) -> Result<(), PreparationError> {
        let cells = self
            .cells
            .checked_add(count)
            .ok_or(PreparationError::ArithmeticOverflow {
                computation: "full DFA builder cell count",
            })?;
        self.observe(self.subset_descriptors, self.subset_items, cells, 0)?;
        self.cells = cells;
        Ok(())
    }

    fn add_subset(&mut self, items: usize) -> Result<(), PreparationError> {
        let descriptors =
            self.subset_descriptors
                .checked_add(1)
                .ok_or(PreparationError::ArithmeticOverflow {
                    computation: "full DFA builder subset descriptors",
                })?;
        let subset_items =
            self.subset_items
                .checked_add(items)
                .ok_or(PreparationError::ArithmeticOverflow {
                    computation: "full DFA builder subset items",
                })?;
        self.observe(descriptors, subset_items, self.cells, 0)?;
        self.subset_descriptors = descriptors;
        self.subset_items = subset_items;
        Ok(())
    }

    fn observe_temporary(&mut self, bytes: usize) -> Result<(), PreparationError> {
        self.observe(
            self.subset_descriptors,
            self.subset_items,
            self.cells,
            bytes,
        )
    }

    fn observe_outer_allocation(
        &mut self,
        allocation_bytes: usize,
        other_temporary_bytes: usize,
    ) -> Result<(), PreparationError> {
        let temporary_bytes = allocation_bytes.checked_add(other_temporary_bytes).ok_or(
            PreparationError::ArithmeticOverflow {
                computation: "full DFA outer allocation live bytes",
            },
        )?;
        self.observe_temporary(temporary_bytes)
    }
}

fn build_full_dfa(
    automaton: &Automaton,
    actions: &[Option<PatternAction>],
    limits: PreparationLimits,
    meter: &mut PreparationMeter,
    base_persistent: usize,
) -> Result<(FullDfa, usize), PreparationError> {
    let mut ledger = FullBuildLedger::new(base_persistent, limits);
    ledger.observe_outer_allocation(size_of::<Box<[u32]>>(), 0)?;
    ledger.add_subset(0)?;
    let mut subsets = Vec::<Box<[u32]>>::new();
    reserve_preparation(&mut subsets, 1, size_of::<Box<[u32]>>(), meter)?;
    subsets.push(Box::new([]));
    let mut transitions = Vec::<DfaTransition>::new();
    let mut state_index = 0usize;

    while state_index < subsets.len() {
        let cells_after_state = state_index
            .checked_add(1)
            .and_then(|states| states.checked_mul(BYTE_VALUES))
            .ok_or(PreparationError::ArithmeticOverflow {
                computation: "full DFA transition cell count",
            })?;
        check_preparation_usize(
            PreparationResource::TransitionCells,
            cells_after_state,
            limits.max_transition_cells,
        )?;
        let new_transition_bytes = cells_after_state
            .checked_mul(size_of::<DfaTransition>())
            .ok_or(PreparationError::ArithmeticOverflow {
                computation: "full DFA transition growth bytes",
            })?;
        ledger.observe_outer_allocation(new_transition_bytes, 0)?;
        ledger.add_cells(BYTE_VALUES)?;
        reserve_preparation(
            &mut transitions,
            BYTE_VALUES,
            size_of::<DfaTransition>(),
            meter,
        )?;

        for byte_value in 0..BYTE_VALUES {
            meter.charge(1)?;
            let byte =
                u8::try_from(byte_value).map_err(|_| PreparationError::InternalInvariant {
                    detail: "DFA byte table index exceeded u8",
                })?;
            let (next_subset, action) = deterministic_step(
                automaton,
                actions,
                &subsets[state_index],
                byte,
                meter,
                &mut ledger,
            )?;
            let next = if action.is_some() {
                0
            } else {
                intern_full_subset(&mut subsets, next_subset, limits, meter, &mut ledger)?
            };
            transitions.push(DfaTransition { next, action });
        }
        state_index = state_index
            .checked_add(1)
            .ok_or(PreparationError::ArithmeticOverflow {
                computation: "full DFA builder state index",
            })?;
    }

    if subsets.capacity() != subsets.len() || transitions.capacity() != transitions.len() {
        return Err(PreparationError::AllocationFailed {
            bytes: full_builder_retained_bytes(
                &subsets,
                subsets.capacity(),
                transitions.capacity(),
            )?,
        });
    }
    Ok((
        FullDfa {
            subsets: subsets.into_boxed_slice(),
            transitions: transitions.into_boxed_slice(),
        },
        ledger.peak_bytes,
    ))
}

fn deterministic_step(
    automaton: &Automaton,
    actions: &[Option<PatternAction>],
    subset: &[u32],
    byte: u8,
    meter: &mut PreparationMeter,
    ledger: &mut FullBuildLedger,
) -> Result<(Vec<u32>, Option<PatternAction>), PreparationError> {
    let candidate_slots =
        subset
            .len()
            .checked_add(1)
            .ok_or(PreparationError::ArithmeticOverflow {
                computation: "full DFA candidate slots",
            })?;
    let temporary_bytes = candidate_slots
        .checked_add(candidate_slots)
        .and_then(|slots| slots.checked_mul(size_of::<u32>()))
        .ok_or(PreparationError::ArithmeticOverflow {
            computation: "full DFA transition temporary bytes",
        })?;
    ledger.observe_temporary(temporary_bytes)?;
    let mut candidates = Vec::new();
    reserve_preparation(
        &mut candidates,
        subset.len().saturating_add(1),
        size_of::<u32>(),
        meter,
    )?;
    candidates.extend_from_slice(subset);
    if automaton.roles[plan_index(automaton.start)] == StateRole::Consume
        && !candidates.contains(&automaton.start)
    {
        meter.charge(u64::try_from(candidates.len()).map_err(|_| {
            PreparationError::ArithmeticOverflow {
                computation: "DFA start dedup work conversion",
            }
        })?)?;
        candidates.push(automaton.start);
    }

    let mut next = Vec::new();
    reserve_preparation(&mut next, candidates.len(), size_of::<u32>(), meter)?;
    for state in candidates {
        meter.charge(1)?;
        let mut target = None;
        for edge in automaton.state_edges(state) {
            meter.charge(1)?;
            if automaton.byte_starts[edge] <= byte && byte <= automaton.byte_ends[edge] {
                target = Some(automaton.edge_targets[edge]);
                break;
            }
        }
        let Some(target) = target else {
            continue;
        };
        match automaton.roles[plan_index(target)] {
            StateRole::Accept => {
                let action =
                    actions[plan_index(target)].ok_or(PreparationError::InternalInvariant {
                        detail: "validated accept state lost its action",
                    })?;
                return Ok((Vec::new(), Some(action)));
            }
            StateRole::Consume => {
                let duplicate = next.iter().any(|&member| {
                    // This comparison is separately charged below.
                    member == target
                });
                meter.charge(u64::try_from(next.len()).map_err(|_| {
                    PreparationError::ArithmeticOverflow {
                        computation: "DFA subset dedup work conversion",
                    }
                })?)?;
                if !duplicate {
                    next.push(target);
                }
            }
            StateRole::Split => {
                return Err(PreparationError::InternalInvariant {
                    detail: "DFA domain validation admitted a split target",
                });
            }
        }
    }
    Ok((next, None))
}

// Owning `proposed` makes its capacity part of the exact temporary-allocation
// ledger and prevents a caller from retaining that charged allocation.
#[allow(clippy::needless_pass_by_value)]
fn intern_full_subset(
    subsets: &mut Vec<Box<[u32]>>,
    proposed: Vec<u32>,
    limits: PreparationLimits,
    meter: &mut PreparationMeter,
    ledger: &mut FullBuildLedger,
) -> Result<u32, PreparationError> {
    for (index, existing) in subsets.iter().enumerate() {
        meter.charge(1)?;
        if existing.len() == proposed.len() {
            meter.charge(u64::try_from(existing.len()).map_err(|_| {
                PreparationError::ArithmeticOverflow {
                    computation: "DFA subset comparison work conversion",
                }
            })?)?;
            if existing.as_ref() == proposed {
                return u32::try_from(index).map_err(|_| PreparationError::ArithmeticOverflow {
                    computation: "full DFA state index conversion",
                });
            }
        }
    }

    let needed_states =
        subsets
            .len()
            .checked_add(1)
            .ok_or(PreparationError::ArithmeticOverflow {
                computation: "full DFA state count",
            })?;
    check_preparation_usize(
        PreparationResource::DfaStates,
        needed_states,
        limits.max_dfa_states,
    )?;
    if u32::try_from(needed_states).is_err() {
        return Err(PreparationError::ResourceLimit {
            resource: PreparationResource::DfaStates,
            needed: needed_states,
            limit: usize::try_from(u32::MAX).unwrap_or(usize::MAX),
        });
    }
    let current_items = subsets.iter().try_fold(0usize, |total, subset| {
        total
            .checked_add(subset.len())
            .ok_or(PreparationError::ArithmeticOverflow {
                computation: "full DFA subset item count",
            })
    })?;
    let needed_items =
        current_items
            .checked_add(proposed.len())
            .ok_or(PreparationError::ArithmeticOverflow {
                computation: "full DFA subset item insertion",
            })?;
    check_preparation_usize(
        PreparationResource::SubsetItems,
        needed_items,
        limits.max_subset_items,
    )?;
    let proposed_bytes = proposed.capacity().checked_mul(size_of::<u32>()).ok_or(
        PreparationError::ArithmeticOverflow {
            computation: "full DFA proposed subset bytes",
        },
    )?;
    let new_descriptor_bytes = needed_states.checked_mul(size_of::<Box<[u32]>>()).ok_or(
        PreparationError::ArithmeticOverflow {
            computation: "full DFA descriptor growth bytes",
        },
    )?;
    ledger.observe_outer_allocation(new_descriptor_bytes, proposed_bytes)?;
    ledger.add_subset(proposed.len())?;
    ledger.observe_temporary(proposed_bytes)?;
    reserve_preparation(subsets, 1, size_of::<Box<[u32]>>(), meter)?;
    meter.allocation()?;
    let mut exact = Vec::new();
    exact
        .try_reserve_exact(proposed.len())
        .map_err(|_| PreparationError::AllocationFailed {
            bytes: proposed.len().saturating_mul(size_of::<u32>()),
        })?;
    if exact.capacity() != proposed.len() {
        return Err(PreparationError::AllocationFailed {
            bytes: exact.capacity().saturating_mul(size_of::<u32>()),
        });
    }
    exact.extend_from_slice(&proposed);
    let index = subsets.len();
    subsets.push(exact.into_boxed_slice());
    u32::try_from(index).map_err(|_| PreparationError::ArithmeticOverflow {
        computation: "full DFA state index conversion",
    })
}

fn full_dfa_bytes(full: &FullDfa) -> Result<usize, PreparationError> {
    let descriptors = full
        .subsets
        .len()
        .checked_mul(size_of::<Box<[u32]>>())
        .ok_or(PreparationError::ArithmeticOverflow {
            computation: "full DFA subset descriptor bytes",
        })?;
    let items = full
        .subsets
        .iter()
        .try_fold(0usize, |total, subset| {
            total
                .checked_add(subset.len())
                .ok_or(PreparationError::ArithmeticOverflow {
                    computation: "full DFA subset items",
                })
        })?
        .checked_mul(size_of::<u32>())
        .ok_or(PreparationError::ArithmeticOverflow {
            computation: "full DFA subset bytes",
        })?;
    let cells = full
        .transitions
        .len()
        .checked_mul(size_of::<DfaTransition>())
        .ok_or(PreparationError::ArithmeticOverflow {
            computation: "full DFA transition bytes",
        })?;
    descriptors
        .checked_add(items)
        .and_then(|bytes| bytes.checked_add(cells))
        .ok_or(PreparationError::ArithmeticOverflow {
            computation: "full DFA persistent bytes",
        })
}

fn reserve_preparation<T>(
    vector: &mut Vec<T>,
    additional: usize,
    element_bytes: usize,
    meter: &mut PreparationMeter,
) -> Result<(), PreparationError> {
    let expected_capacity =
        vector
            .len()
            .checked_add(additional)
            .ok_or(PreparationError::ArithmeticOverflow {
                computation: "preparation reserve capacity",
            })?;
    meter.allocation()?;
    vector
        .try_reserve_exact(additional)
        .map_err(|_| PreparationError::AllocationFailed {
            bytes: vector
                .len()
                .saturating_add(additional)
                .saturating_mul(element_bytes),
        })?;
    if vector.capacity() != expected_capacity {
        return Err(PreparationError::AllocationFailed {
            bytes: vector.capacity().saturating_mul(element_bytes),
        });
    }
    Ok(())
}

fn full_builder_retained_bytes(
    subsets: &[Box<[u32]>],
    subset_capacity: usize,
    transition_capacity: usize,
) -> Result<usize, PreparationError> {
    let descriptors = subset_capacity.checked_mul(size_of::<Box<[u32]>>()).ok_or(
        PreparationError::ArithmeticOverflow {
            computation: "full DFA retained descriptor bytes",
        },
    )?;
    let items = subsets
        .iter()
        .try_fold(0usize, |total, subset| {
            total
                .checked_add(subset.len())
                .ok_or(PreparationError::ArithmeticOverflow {
                    computation: "full DFA retained subset items",
                })
        })?
        .checked_mul(size_of::<u32>())
        .ok_or(PreparationError::ArithmeticOverflow {
            computation: "full DFA retained subset bytes",
        })?;
    let cells = transition_capacity
        .checked_mul(size_of::<DfaTransition>())
        .ok_or(PreparationError::ArithmeticOverflow {
            computation: "full DFA retained transition bytes",
        })?;
    descriptors
        .checked_add(items)
        .and_then(|bytes| bytes.checked_add(cells))
        .ok_or(PreparationError::ArithmeticOverflow {
            computation: "full DFA retained builder bytes",
        })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AnchoredOutcome {
    end: usize,
    action: PatternAction,
}

#[derive(Clone)]
struct SuffixValue<T: Clone> {
    output: T,
    matches: usize,
    empty_matches: usize,
    span_bytes: u64,
    ordinal_sum: u64,
}

impl<T: Clone> SuffixValue<T> {
    const fn zero(output: T) -> Self {
        Self {
            output,
            matches: 0,
            empty_matches: 0,
            span_bytes: 0,
            ordinal_sum: 0,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct LazyCell {
    state: u32,
    byte: u8,
    transition: DfaTransition,
}

impl Default for LazyCell {
    fn default() -> Self {
        Self {
            state: NO_DFA_STATE,
            byte: 0,
            transition: DfaTransition {
                next: NO_DFA_STATE,
                action: None,
            },
        }
    }
}

struct ExecutionMeter {
    limit: u64,
    consumed: u64,
}

impl ExecutionMeter {
    const fn new(limit: u64) -> Self {
        Self { limit, consumed: 0 }
    }

    fn charge(&mut self, requested: u64) -> Result<(), ReduceError> {
        let next = self
            .consumed
            .checked_add(requested)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "execution work",
            })?;
        if next > self.limit {
            return Err(ReduceError::WorkLimit {
                consumed: self.consumed,
                requested,
                limit: self.limit,
            });
        }
        self.consumed = next;
        Ok(())
    }
}

// Route-specific scratch, work, DFA and allocation bounds stay adjacent to
// their pre-source gates.
#[allow(clippy::too_many_lines)]
fn prospective<O: DirectReduceValue>(
    plan: &PreparedPriorityAutomaton<O>,
    haystack_bytes: usize,
    limits: DirectReduceLimits,
) -> Result<ExecutionProspective, ReduceError> {
    let boundary_rows = haystack_bytes
        .checked_add(1)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "execution boundary rows",
        })?;
    if boundary_rows > limits.max_boundary_rows {
        return Err(ReduceError::BoundaryRowsLimit {
            needed: boundary_rows,
            limit: limits.max_boundary_rows,
        });
    }
    let match_events_upper_bound = boundary_rows;
    let states = plan.automaton.stats().states();
    let edges = plan.automaton.stats().edges();
    let zero_width_edges = plan.automaton.stats().zero_width_edges();

    let (
        scratch_bytes,
        dfa_states_capacity,
        dfa_cells_capacity,
        subset_items_capacity,
        tagged_dispatch_states_capacity,
        tagged_dispatch_cells_capacity,
        tagged_candidate_items_capacity,
        tagged_cache_cells_capacity,
        allocation_attempts,
        work_upper_bound,
    ) = match &plan.route {
        PreparedRoute::Sparse { evaluation } => {
            let suffixes = boundary_rows
                .checked_mul(size_of::<SuffixValue<O::Output>>())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "sparse suffix-value bytes",
                })?;
            let (scratch, allocations, work) = sparse_execution_bounds(
                evaluation,
                states,
                edges,
                zero_width_edges,
                boundary_rows,
                boundary_rows,
                suffixes,
            )?;
            (scratch, 0, 0, 0, 0, 0, 0, 0, allocations, work)
        }
        PreparedRoute::FiniteHorizon {
            maximum_match_bytes,
            evaluation,
        } => {
            let ring_entries = boundary_rows.min(maximum_match_bytes.checked_add(2).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "finite-horizon ring entries",
                },
            )?);
            let ring = ring_entries
                .checked_mul(size_of::<SuffixValue<O::Output>>())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "finite-horizon reducer ring bytes",
                })?;
            let (scratch, allocations, work) = sparse_execution_bounds(
                evaluation,
                states,
                edges,
                zero_width_edges,
                boundary_rows,
                ring_entries,
                ring,
            )?;
            (scratch, 0, 0, 0, 0, 0, 0, 0, allocations, work)
        }
        PreparedRoute::InputBoundedSparseFallback { evaluation } => {
            // No static width proof exists, so every input boundary retains a
            // suffix value. This is intentionally the sparse-equivalent
            // input-bounded P ledger rather than an invented fixed horizon.
            let suffixes = boundary_rows
                .checked_mul(size_of::<SuffixValue<O::Output>>())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "input-bounded suffix-value bytes",
                })?;
            let (scratch, allocations, work) = sparse_execution_bounds(
                evaluation,
                states,
                edges,
                zero_width_edges,
                boundary_rows,
                boundary_rows,
                suffixes,
            )?;
            (scratch, 0, 0, 0, 0, 0, 0, 0, allocations, work)
        }
        PreparedRoute::FullDfa(full) => {
            let subset_items = full.subsets.iter().try_fold(0usize, |total, subset| {
                total
                    .checked_add(subset.len())
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "full DFA run subset items",
                    })
            })?;
            if full.subsets.len() > limits.max_dfa_states {
                return Err(ReduceError::DfaStatesLimit {
                    needed: full.subsets.len(),
                    limit: limits.max_dfa_states,
                });
            }
            if full.transitions.len() > limits.max_dfa_cells {
                return Err(ReduceError::DfaCellsLimit {
                    needed: full.transitions.len(),
                    limit: limits.max_dfa_cells,
                });
            }
            if subset_items > limits.max_subset_items {
                return Err(ReduceError::SubsetItemsLimit {
                    needed: subset_items,
                    limit: limits.max_subset_items,
                });
            }
            let work = u64::try_from(haystack_bytes)
                .map_err(|_| ReduceError::ArithmeticOverflow {
                    computation: "full DFA work conversion",
                })?
                .checked_mul(3)
                .and_then(|value| value.checked_add(1))
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "full DFA work upper bound",
                })?;
            (
                0,
                full.subsets.len(),
                full.transitions.len(),
                subset_items,
                0,
                0,
                0,
                0,
                0,
                work,
            )
        }
        PreparedRoute::FullTransducer(transducer) => {
            let (scratch, allocations, work) = full_tagged_execution_bounds::<O>(
                transducer,
                states,
                edges,
                zero_width_edges,
                boundary_rows,
                limits,
            )?;
            (
                scratch,
                0,
                0,
                0,
                transducer.resources.states,
                transducer.resources.cells,
                transducer.resources.candidates,
                0,
                allocations,
                work,
            )
        }
        PreparedRoute::LazyTransducer(transducer) => {
            let (scratch, cache_cells, allocations, work) = lazy_tagged_execution_bounds::<O>(
                transducer,
                haystack_bytes,
                states,
                edges,
                zero_width_edges,
                boundary_rows,
                limits,
            )?;
            (
                scratch,
                0,
                0,
                0,
                transducer.resources.states,
                transducer.resources.cells,
                transducer.resources.candidates,
                cache_cells,
                allocations,
                work,
            )
        }
        PreparedRoute::LazyDfa => {
            let dfa_states_capacity = boundary_rows.min(limits.max_dfa_states);
            if dfa_states_capacity == 0 {
                return Err(ReduceError::DfaStatesLimit {
                    needed: 1,
                    limit: 0,
                });
            }
            let dfa_cells_capacity = haystack_bytes.min(limits.max_dfa_cells);
            if haystack_bytes != 0 && dfa_cells_capacity == 0 {
                return Err(ReduceError::DfaCellsLimit {
                    needed: 1,
                    limit: 0,
                });
            }
            let maximum_items =
                dfa_states_capacity
                    .checked_mul(states)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "lazy DFA subset item upper bound",
                    })?;
            let subset_items_capacity = maximum_items.min(limits.max_subset_items);
            let scratch = lazy_scratch(
                states,
                dfa_states_capacity,
                dfa_cells_capacity,
                subset_items_capacity,
            )?;
            let bytes =
                u64::try_from(haystack_bytes).map_err(|_| ReduceError::ArithmeticOverflow {
                    computation: "lazy DFA input length conversion",
                })?;
            let states_u64 =
                u64::try_from(states).map_err(|_| ReduceError::ArithmeticOverflow {
                    computation: "lazy DFA state count conversion",
                })?;
            let cells_u64 =
                u64::try_from(dfa_cells_capacity).map_err(|_| ReduceError::ArithmeticOverflow {
                    computation: "lazy DFA cell capacity conversion",
                })?;
            let dfa_states_u64 = u64::try_from(dfa_states_capacity).map_err(|_| {
                ReduceError::ArithmeticOverflow {
                    computation: "lazy DFA capacity conversion",
                }
            })?;
            let setup_slots = dfa_states_capacity
                .checked_add(1)
                .and_then(|value| value.checked_add(subset_items_capacity))
                .and_then(|value| value.checked_add(dfa_cells_capacity))
                .and_then(|value| value.checked_add(states))
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "lazy DFA setup slots",
                })?;
            let setup_work =
                u64::try_from(setup_slots).map_err(|_| ReduceError::ArithmeticOverflow {
                    computation: "lazy DFA setup work conversion",
                })?;
            let per_byte = cells_u64
                .checked_add(
                    states_u64
                        .checked_mul(
                            states_u64
                                .checked_add(u64::try_from(edges).map_err(|_| {
                                    ReduceError::ArithmeticOverflow {
                                        computation: "lazy DFA edge conversion",
                                    }
                                })?)
                                .ok_or(ReduceError::ArithmeticOverflow {
                                    computation: "lazy DFA build work",
                                })?,
                        )
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "lazy DFA subset work",
                        })?,
                )
                .and_then(|value| {
                    dfa_states_u64
                        .checked_mul(states_u64.checked_add(1)?)
                        .and_then(|subset_work| value.checked_add(subset_work))
                })
                .and_then(|value| value.checked_add(4))
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "lazy DFA work per byte",
                })?;
            let work = bytes
                .checked_mul(per_byte)
                .and_then(|value| value.checked_add(setup_work))
                .and_then(|value| value.checked_add(1))
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "lazy DFA work upper bound",
                })?;
            (
                scratch,
                dfa_states_capacity,
                dfa_cells_capacity,
                subset_items_capacity,
                0,
                0,
                0,
                0,
                4,
                work,
            )
        }
    };

    if scratch_bytes > limits.max_scratch_bytes {
        return Err(ReduceError::ScratchLimit {
            needed: scratch_bytes,
            limit: limits.max_scratch_bytes,
        });
    }
    if allocation_attempts > limits.max_allocation_attempts {
        return Err(ReduceError::AllocationAttemptsLimit {
            needed: allocation_attempts,
            limit: limits.max_allocation_attempts,
        });
    }
    if match_events_upper_bound > limits.max_match_events {
        return Err(ReduceError::MatchEventsLimit {
            needed: match_events_upper_bound,
            limit: limits.max_match_events,
        });
    }
    if work_upper_bound > limits.max_work {
        return Err(ReduceError::WorkLimit {
            consumed: 0,
            requested: work_upper_bound,
            limit: limits.max_work,
        });
    }
    Ok(ExecutionProspective {
        tagged_execution_class: None,
        work_upper_bound,
        scratch_bytes,
        boundary_rows,
        match_events_upper_bound,
        dfa_states_capacity,
        dfa_cells_capacity,
        subset_items_capacity,
        tagged_state_evaluations_upper_bound: 0,
        tagged_edge_visits_upper_bound: 0,
        tagged_map_capacity: 0,
        tagged_group_capacity: 0,
        tagged_group_publications_upper_bound: 0,
        tagged_owner_capacity: 0,
        tagged_dispatch_states_capacity,
        tagged_dispatch_cells_capacity,
        tagged_candidate_items_capacity,
        tagged_cache_cells_capacity,
        allocation_attempts,
    })
}

/// Add the fixed reservation, a complete forward selection scan, and one copy
/// charge per possible selected match for the explicit Build-Many trace. The
/// roots reuse the ordinary sparse suffix allocation slot.
fn trace_prospective(
    mut prospective: ExecutionProspective,
    limits: DirectReduceLimits,
) -> Result<ExecutionProspective, ReduceError> {
    let trace_bytes = prospective
        .match_events_upper_bound
        .checked_mul(size_of::<PriorityMatch>())
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "priority trace bytes",
        })?;
    prospective.scratch_bytes = prospective.scratch_bytes.checked_add(trace_bytes).ok_or(
        ReduceError::ArithmeticOverflow {
            computation: "priority trace scratch bytes",
        },
    )?;
    prospective.allocation_attempts =
        prospective
            .allocation_attempts
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "priority trace allocation attempts",
            })?;
    let trace_work = u64::try_from(prospective.boundary_rows)
        .map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "priority trace boundary-scan work",
        })?
        .checked_add(
            u64::try_from(prospective.match_events_upper_bound).map_err(|_| {
                ReduceError::ArithmeticOverflow {
                    computation: "priority trace match-event work",
                }
            })?,
        )
        .and_then(|work| work.checked_add(1))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "priority trace work",
        })?;
    prospective.work_upper_bound = prospective.work_upper_bound.checked_add(trace_work).ok_or(
        ReduceError::ArithmeticOverflow {
            computation: "priority trace total work",
        },
    )?;
    if prospective.scratch_bytes > limits.max_scratch_bytes {
        return Err(ReduceError::ScratchLimit {
            needed: prospective.scratch_bytes,
            limit: limits.max_scratch_bytes,
        });
    }
    if prospective.allocation_attempts > limits.max_allocation_attempts {
        return Err(ReduceError::AllocationAttemptsLimit {
            needed: prospective.allocation_attempts,
            limit: limits.max_allocation_attempts,
        });
    }
    if prospective.work_upper_bound > limits.max_work {
        return Err(ReduceError::WorkLimit {
            consumed: 0,
            requested: prospective.work_upper_bound,
            limit: limits.max_work,
        });
    }
    Ok(prospective)
}

fn check_tagged_execution_resources(
    resources: TaggedProgramResources,
    limits: DirectReduceLimits,
) -> Result<(), ReduceError> {
    if resources.states > limits.max_tagged_dispatch_states {
        return Err(ReduceError::TaggedDispatchStatesLimit {
            needed: resources.states,
            limit: limits.max_tagged_dispatch_states,
        });
    }
    if resources.cells > limits.max_tagged_dispatch_cells {
        return Err(ReduceError::TaggedDispatchCellsLimit {
            needed: resources.cells,
            limit: limits.max_tagged_dispatch_cells,
        });
    }
    if resources.candidates > limits.max_tagged_candidate_items {
        return Err(ReduceError::TaggedCandidateItemsLimit {
            needed: resources.candidates,
            limit: limits.max_tagged_candidate_items,
        });
    }
    Ok(())
}

fn full_tagged_execution_bounds<O: DirectReduceValue>(
    transducer: &FullTaggedTransducer,
    states: usize,
    edges: usize,
    zero_width_edges: usize,
    boundary_rows: usize,
    limits: DirectReduceLimits,
) -> Result<(usize, usize, u64), ReduceError> {
    check_tagged_execution_resources(transducer.resources, limits)?;
    let suffixes = boundary_rows
        .checked_mul(size_of::<SuffixValue<O::Output>>())
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "full tagged suffix-value bytes",
        })?;
    let (scratch, allocations, sparse_work) = sparse_execution_bounds(
        &transducer.evaluation,
        states,
        edges,
        zero_width_edges,
        boundary_rows,
        boundary_rows,
        suffixes,
    )?;
    let rows = u64::try_from(boundary_rows).map_err(|_| ReduceError::ArithmeticOverflow {
        computation: "full tagged boundary-row conversion",
    })?;
    let intervals =
        u64::try_from(transducer.resources.cells).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "full tagged dispatch-cell conversion",
        })?;
    let lookup_multiplier = match &transducer.evaluation {
        SparseEvaluation::Acyclic(_) => 1usize,
        SparseEvaluation::Cyclic => states,
    };
    let lookup_multiplier =
        u64::try_from(lookup_multiplier).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "full tagged lookup multiplier conversion",
        })?;
    let dispatch_work = rows
        .checked_mul(intervals)
        .and_then(|value| value.checked_mul(lookup_multiplier))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "full tagged dispatch lookup work",
        })?;
    let work = sparse_work
        .checked_add(dispatch_work)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "full tagged execution work",
        })?;
    Ok((scratch, allocations, work))
}

fn lazy_tagged_execution_bounds<O: DirectReduceValue>(
    transducer: &LazyTaggedTransducer,
    haystack_bytes: usize,
    states: usize,
    edges: usize,
    zero_width_edges: usize,
    boundary_rows: usize,
    limits: DirectReduceLimits,
) -> Result<(usize, usize, usize, u64), ReduceError> {
    check_tagged_execution_resources(transducer.resources, limits)?;
    // The caller-selected positive cache bound is part of the pre-source P
    // ledger. A smaller table remains semantically sound because it caches
    // only static candidate starts; it can only increase bounded eviction.
    let cache_cells = haystack_bytes.min(limits.max_tagged_cache_cells);
    if haystack_bytes != 0 && cache_cells == 0 {
        return Err(ReduceError::TaggedCacheCellsLimit {
            needed: 1,
            limit: limits.max_tagged_cache_cells,
        });
    }
    let suffixes = boundary_rows
        .checked_mul(size_of::<SuffixValue<O::Output>>())
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "lazy tagged suffix-value bytes",
        })?;
    let (sparse_scratch, sparse_allocations, sparse_work) = sparse_execution_bounds(
        &transducer.evaluation,
        states,
        edges,
        zero_width_edges,
        boundary_rows,
        boundary_rows,
        suffixes,
    )?;
    let cache_bytes = cache_cells.checked_mul(size_of::<LazyTaggedCell>()).ok_or(
        ReduceError::ArithmeticOverflow {
            computation: "lazy tagged cache bytes",
        },
    )?;
    let scratch =
        sparse_scratch
            .checked_add(cache_bytes)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "lazy tagged execution scratch",
            })?;
    let allocations = sparse_allocations
        .checked_add(usize::from(cache_cells != 0))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "lazy tagged execution allocations",
        })?;
    let rows = u64::try_from(boundary_rows).map_err(|_| ReduceError::ArithmeticOverflow {
        computation: "lazy tagged boundary-row conversion",
    })?;
    let states = u64::try_from(states).map_err(|_| ReduceError::ArithmeticOverflow {
        computation: "lazy tagged state conversion",
    })?;
    let edges = u64::try_from(edges).map_err(|_| ReduceError::ArithmeticOverflow {
        computation: "lazy tagged edge conversion",
    })?;
    // Every consuming state can probe once, miss, and scan its static edge
    // range before the ordinary dynamic outcome scan.  Direct mapping may
    // evict on every probe, so no hit-rate assumption appears in the bound.
    let lookup_multiplier = match &transducer.evaluation {
        SparseEvaluation::Acyclic(_) => 1u64,
        SparseEvaluation::Cyclic => states,
    };
    let cache_work_per_lookup =
        states
            .checked_add(edges)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "lazy tagged cache work per row",
            })?;
    let cache_lookup_work = rows
        .checked_mul(lookup_multiplier)
        .and_then(|value| value.checked_mul(cache_work_per_lookup))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "lazy tagged cache work",
        })?;
    let cache_setup_work =
        u64::try_from(cache_cells).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "lazy tagged cache setup conversion",
        })?;
    let work = sparse_work
        .checked_add(cache_lookup_work)
        .and_then(|value| value.checked_add(cache_setup_work))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "lazy tagged execution work",
        })?;
    Ok((scratch, cache_cells, allocations, work))
}

fn sparse_row_scratch(states: usize) -> Result<usize, ReduceError> {
    states
        .checked_mul(size_of::<Option<AnchoredOutcome>>())
        .and_then(|bytes| bytes.checked_mul(2))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "sparse outcome-row bytes",
        })
}

fn cyclic_sparse_row_scratch(states: usize, stack_slots: usize) -> Result<usize, ReduceError> {
    let stamps = states
        .checked_mul(size_of::<u64>())
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "cyclic sparse generation-stamp bytes",
        })?;
    let outcomes = sparse_row_scratch(states)?;
    let stack =
        stack_slots
            .checked_mul(size_of::<u32>())
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "cyclic sparse closure-stack bytes",
            })?;
    stamps
        .checked_add(outcomes)
        .and_then(|bytes| bytes.checked_add(stack))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "cyclic sparse row scratch bytes",
        })
}

fn sparse_execution_bounds(
    evaluation: &SparseEvaluation,
    states: usize,
    edges: usize,
    zero_width_edges: usize,
    rows: usize,
    reducer_storage_slots: usize,
    reducer_storage_bytes: usize,
) -> Result<(usize, usize, u64), ReduceError> {
    match evaluation {
        SparseEvaluation::Acyclic(_) => {
            let scratch = sparse_row_scratch(states)?
                .checked_add(reducer_storage_bytes)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "acyclic sparse execution scratch",
                })?;
            let work = sparse_work_upper(states, edges, rows, reducer_storage_slots)?;
            Ok((scratch, 3, work))
        }
        SparseEvaluation::Cyclic => {
            let stack_slots =
                zero_width_edges
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "cyclic sparse stack slots",
                    })?;
            let scratch = cyclic_sparse_row_scratch(states, stack_slots)?
                .checked_add(reducer_storage_bytes)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "cyclic sparse execution scratch",
                })?;
            let setup_slots = states
                .checked_mul(3)
                .and_then(|value| value.checked_add(stack_slots))
                .and_then(|value| value.checked_add(reducer_storage_slots))
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "cyclic sparse setup slots",
                })?;
            let work = cyclic_sparse_work_upper(states, edges, rows, setup_slots)?;
            Ok((scratch, 5, work))
        }
    }
}

fn sparse_work_upper(
    states: usize,
    edges: usize,
    rows: usize,
    reducer_storage_slots: usize,
) -> Result<u64, ReduceError> {
    let states = u64::try_from(states).map_err(|_| ReduceError::ArithmeticOverflow {
        computation: "sparse state count conversion",
    })?;
    let edges = u64::try_from(edges).map_err(|_| ReduceError::ArithmeticOverflow {
        computation: "sparse edge count conversion",
    })?;
    let rows = u64::try_from(rows).map_err(|_| ReduceError::ArithmeticOverflow {
        computation: "sparse row count conversion",
    })?;
    let reducer_storage_slots =
        u64::try_from(reducer_storage_slots).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "sparse reducer storage conversion",
        })?;
    let per_row = states
        .checked_add(edges)
        .and_then(|value| value.checked_add(2))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "sparse work per row",
        })?;
    let loop_work = rows
        .checked_mul(per_row)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "sparse loop work",
        })?;
    let setup = states
        .checked_mul(2)
        .and_then(|value| value.checked_add(reducer_storage_slots))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "sparse setup work upper bound",
        })?;
    loop_work
        .checked_add(setup)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "sparse work upper bound",
        })
}

fn cyclic_sparse_work_upper(
    states: usize,
    edges: usize,
    rows: usize,
    setup_slots: usize,
) -> Result<u64, ReduceError> {
    let states = u64::try_from(states).map_err(|_| ReduceError::ArithmeticOverflow {
        computation: "cyclic sparse state count conversion",
    })?;
    let edges = u64::try_from(edges).map_err(|_| ReduceError::ArithmeticOverflow {
        computation: "cyclic sparse edge count conversion",
    })?;
    let rows = u64::try_from(rows).map_err(|_| ReduceError::ArithmeticOverflow {
        computation: "cyclic sparse row count conversion",
    })?;
    let setup_slots = u64::try_from(setup_slots).map_err(|_| ReduceError::ArithmeticOverflow {
        computation: "cyclic sparse setup conversion",
    })?;
    let per_root = states
        .checked_add(
            edges
                .checked_mul(2)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "cyclic sparse edge work per root",
                })?,
        )
        .and_then(|value| value.checked_add(2))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "cyclic sparse work per root",
        })?;
    let per_row = states
        .checked_mul(per_root)
        .and_then(|value| value.checked_add(2))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "cyclic sparse work per row",
        })?;
    rows.checked_mul(per_row)
        .and_then(|value| value.checked_add(setup_slots))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "cyclic sparse work upper bound",
        })
}

fn lazy_scratch(
    automaton_states: usize,
    dfa_states: usize,
    cells: usize,
    subset_items: usize,
) -> Result<usize, ReduceError> {
    let offsets = dfa_states
        .checked_add(1)
        .and_then(|count| count.checked_mul(size_of::<usize>()))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "lazy DFA state-offset bytes",
        })?;
    let items =
        subset_items
            .checked_mul(size_of::<u32>())
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "lazy DFA subset-item bytes",
            })?;
    let cells =
        cells
            .checked_mul(size_of::<LazyCell>())
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "lazy DFA cell bytes",
            })?;
    let temporary =
        automaton_states
            .checked_mul(size_of::<u32>())
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "lazy DFA temporary-subset bytes",
            })?;
    offsets
        .checked_add(items)
        .and_then(|bytes| bytes.checked_add(cells))
        .and_then(|bytes| bytes.checked_add(temporary))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "lazy DFA scratch bytes",
        })
}

fn execute<O: DirectReduceValue>(
    plan: &PreparedPriorityAutomaton<O>,
    haystack: &[u8],
    limits: DirectReduceLimits,
) -> Result<DirectReduceReport<O::Output>, ReduceError> {
    // This is the route/resource gate. No source byte is read above it.
    let prospective = prospective(plan, haystack.len(), limits)?;
    let (output, actual) = match &plan.route {
        PreparedRoute::Sparse { .. } => execute_sparse::<O>(plan, haystack, limits, prospective)?,
        PreparedRoute::FiniteHorizon {
            maximum_match_bytes,
            ..
        } => execute_finite::<O>(plan, haystack, limits, prospective, *maximum_match_bytes)?,
        PreparedRoute::InputBoundedSparseFallback { .. } => {
            execute_input_bounded_sparse_fallback::<O>(plan, haystack, limits, prospective)?
        }
        PreparedRoute::FullDfa(full) => {
            execute_full_dfa::<O>(plan, full, haystack, limits, prospective)?
        }
        PreparedRoute::FullTransducer(_) | PreparedRoute::LazyTransducer(_) => {
            execute_priority_tagged_transducer::<O>(plan, haystack, limits, prospective)?
        }
        PreparedRoute::LazyDfa => execute_lazy_dfa::<O>(plan, haystack, limits, prospective)?,
    };
    finish_execution_report(haystack.len(), output, prospective, actual)
}

fn finish_execution_report<T>(
    haystack_bytes: usize,
    output: T,
    prospective: ExecutionProspective,
    mut actual: ExecutionActual,
) -> Result<DirectReduceReport<T>, ReduceError> {
    if actual.work > prospective.work_upper_bound {
        return Err(ReduceError::InternalInvariant {
            detail: "actual work exceeded its published upper bound",
        });
    }
    actual.source_bytes = haystack_bytes;
    actual.scratch_bytes = prospective.scratch_bytes;
    actual.allocation_attempts = prospective.allocation_attempts;
    let source_span_upper_bound =
        u64::try_from(haystack_bytes).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "source span upper-bound conversion",
        })?;
    if prospective.tagged_execution_class.is_some()
        || actual.boundary_rows > prospective.boundary_rows
        || actual.match_events > prospective.match_events_upper_bound
        || actual.suffix_reducer_steps > prospective.boundary_rows
        || actual.selected_span_bytes > source_span_upper_bound
        || actual.dfa_states > prospective.dfa_states_capacity
        || actual.dfa_cells > prospective.dfa_cells_capacity
        || actual.subset_items > prospective.subset_items_capacity
        // Ordinary priority routes may use B's tagged reverse execution and
        // therefore legitimately report tagged state/edge activity. C's
        // owner/map/group counters remain exclusive to Build-Many and must
        // stay zero here; their state/edge bounds are not B route bounds.
        || actual.tagged_map_publications != 0
        || actual.tagged_group_publications != 0
        || actual.tagged_peak_maps != 0
        || actual.tagged_peak_groups != 0
        || actual.tagged_dispatch_states > prospective.tagged_dispatch_states_capacity
        || actual.tagged_dispatch_cells > prospective.tagged_dispatch_cells_capacity
        || actual.tagged_candidate_items > prospective.tagged_candidate_items_capacity
        || actual.tagged_cache_cells > prospective.tagged_cache_cells_capacity
        || actual.allocation_attempts > prospective.allocation_attempts
    {
        return Err(ReduceError::InternalInvariant {
            detail: "execution actual counters exceeded prospective bounds",
        });
    }
    Ok(DirectReduceReport {
        output,
        prospective,
        actual,
    })
}

struct AcyclicSparseWorkspace {
    current: Box<[Option<AnchoredOutcome>]>,
    next: Box<[Option<AnchoredOutcome>]>,
}

impl AcyclicSparseWorkspace {
    fn new(states: usize, scratch_bytes: usize) -> Result<Self, ReduceError> {
        Ok(Self {
            current: allocate_execution_slots(states, None, scratch_bytes)?,
            next: allocate_execution_slots(states, None, scratch_bytes)?,
        })
    }
}

struct CyclicSparseWorkspace {
    stamps: Box<[u64]>,
    generation: u64,
    current: Box<[Option<AnchoredOutcome>]>,
    next: Box<[Option<AnchoredOutcome>]>,
    stack: Box<[u32]>,
    stack_len: usize,
}

impl CyclicSparseWorkspace {
    fn new(states: usize, stack_slots: usize, scratch_bytes: usize) -> Result<Self, ReduceError> {
        Ok(Self {
            stamps: allocate_execution_slots(states, 0, scratch_bytes)?,
            generation: 0,
            current: allocate_execution_slots(states, None, scratch_bytes)?,
            next: allocate_execution_slots(states, None, scratch_bytes)?,
            stack: allocate_execution_slots(stack_slots, 0, scratch_bytes)?,
            stack_len: 0,
        })
    }

    fn push(&mut self, state: u32) -> Result<(), ReduceError> {
        let slot = self
            .stack
            .get_mut(self.stack_len)
            .ok_or(ReduceError::InternalInvariant {
                detail: "cyclic sparse closure exceeded its proved edge bound",
            })?;
        *slot = state;
        self.stack_len = self
            .stack_len
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "cyclic sparse closure stack length",
            })?;
        Ok(())
    }

    fn pop(&mut self) -> Option<u32> {
        self.stack_len = self.stack_len.checked_sub(1)?;
        self.stack.get(self.stack_len).copied()
    }
}

/// Static candidate lookup is deliberately narrower than a transition: it
/// may identify the first compatible edge, but it never receives a reverse
/// outcome or an assertion result to cache.
trait TaggedCandidateDispatcher {
    fn first_edge(
        &mut self,
        automaton: &Automaton,
        state: u32,
        byte: u8,
        meter: &mut ExecutionMeter,
        actual: &mut ExecutionActual,
    ) -> Result<Option<usize>, ReduceError>;
}

struct FullTaggedDispatcher<'a> {
    transducer: &'a FullTaggedTransducer,
}

impl TaggedCandidateDispatcher for FullTaggedDispatcher<'_> {
    fn first_edge(
        &mut self,
        automaton: &Automaton,
        state: u32,
        byte: u8,
        meter: &mut ExecutionMeter,
        _actual: &mut ExecutionActual,
    ) -> Result<Option<usize>, ReduceError> {
        let state_index = plan_index(state);
        let range = *self.transducer.state_intervals.get(state_index).ok_or(
            ReduceError::InternalInvariant {
                detail: "full tagged dispatch lost a state interval range",
            },
        )?;
        let start = plan_index(range.start);
        let end = plan_index(range.end);
        if start > end || end > self.transducer.intervals.len() {
            return Err(ReduceError::InternalInvariant {
                detail: "full tagged dispatch state interval range is invalid",
            });
        }
        for interval in &self.transducer.intervals[start..end] {
            meter.charge(1)?;
            if interval.byte_start <= byte && byte <= interval.byte_end {
                if interval.first_edge == NO_TAGGED_EDGE {
                    return Ok(None);
                }
                let first_edge = plan_index(interval.first_edge);
                let state_edges = automaton.state_edges(state);
                if first_edge < state_edges.start || first_edge >= state_edges.end {
                    return Err(ReduceError::InternalInvariant {
                        detail: "full tagged dispatch candidate escaped its state",
                    });
                }
                return Ok(Some(first_edge));
            }
        }
        Err(ReduceError::InternalInvariant {
            detail: "full tagged dispatch omitted a byte interval",
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct LazyTaggedCell {
    state: u32,
    byte: u8,
    first_edge: u32,
}

impl Default for LazyTaggedCell {
    fn default() -> Self {
        Self {
            state: NO_TAGGED_EDGE,
            byte: 0,
            first_edge: NO_TAGGED_EDGE,
        }
    }
}

struct LazyTaggedCache {
    cells: Box<[LazyTaggedCell]>,
}

impl LazyTaggedCache {
    fn new(prospective: ExecutionProspective) -> Result<Self, ReduceError> {
        let cells = if prospective.tagged_cache_cells_capacity == 0 {
            Box::new([])
        } else {
            allocate_execution_slots(
                prospective.tagged_cache_cells_capacity,
                LazyTaggedCell::default(),
                prospective.scratch_bytes,
            )?
        };
        Ok(Self { cells })
    }
}

struct LazyTaggedDispatcher<'a> {
    transducer: &'a LazyTaggedTransducer,
    cache: LazyTaggedCache,
}

fn increment_tagged_edge_visits(actual: &mut ExecutionActual) -> Result<(), ReduceError> {
    actual.tagged_edge_visits =
        actual
            .tagged_edge_visits
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "tagged edge visits",
            })?;
    Ok(())
}

impl TaggedCandidateDispatcher for LazyTaggedDispatcher<'_> {
    fn first_edge(
        &mut self,
        automaton: &Automaton,
        state: u32,
        byte: u8,
        meter: &mut ExecutionMeter,
        actual: &mut ExecutionActual,
    ) -> Result<Option<usize>, ReduceError> {
        if self.cache.cells.is_empty() {
            return Err(ReduceError::InternalInvariant {
                detail: "lazy tagged dispatch probed an empty cache",
            });
        }
        let state_index = plan_index(state);
        let range = *self.transducer.state_edges.get(state_index).ok_or(
            ReduceError::InternalInvariant {
                detail: "lazy tagged dispatch lost a state edge range",
            },
        )?;
        let start = plan_index(range.start);
        let end = plan_index(range.end);
        if start > end || end > automaton.stats().edges() {
            return Err(ReduceError::InternalInvariant {
                detail: "lazy tagged dispatch state edge range is invalid",
            });
        }
        let cache_index = (state_index ^ usize::from(byte))
            .checked_rem(self.cache.cells.len())
            .ok_or(ReduceError::InternalInvariant {
                detail: "lazy tagged dispatch cache length became zero",
            })?;
        meter.charge(1)?;
        let cell = &mut self.cache.cells[cache_index];
        if cell.state == state && cell.byte == byte {
            actual.tagged_cache_hits =
                actual
                    .tagged_cache_hits
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "lazy tagged cache hits",
                    })?;
            return Ok((cell.first_edge != NO_TAGGED_EDGE).then(|| plan_index(cell.first_edge)));
        }
        actual.tagged_cache_misses =
            actual
                .tagged_cache_misses
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "lazy tagged cache misses",
                })?;
        let mut first_edge = NO_TAGGED_EDGE;
        for edge in start..end {
            meter.charge(1)?;
            increment_tagged_edge_visits(actual)?;
            if automaton.byte_starts[edge] <= byte && byte <= automaton.byte_ends[edge] {
                first_edge = u32::try_from(edge).map_err(|_| ReduceError::ArithmeticOverflow {
                    computation: "lazy tagged candidate edge conversion",
                })?;
                break;
            }
        }
        if cell.state != NO_TAGGED_EDGE {
            actual.tagged_cache_evictions = actual.tagged_cache_evictions.checked_add(1).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "lazy tagged cache evictions",
                },
            )?;
        }
        *cell = LazyTaggedCell {
            state,
            byte,
            first_edge,
        };
        actual.tagged_cache_inserts =
            actual
                .tagged_cache_inserts
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "lazy tagged cache inserts",
                })?;
        Ok((first_edge != NO_TAGGED_EDGE).then(|| plan_index(first_edge)))
    }
}

fn tagged_consume_outcome<O: DirectReduceValue>(
    plan: &PreparedPriorityAutomaton<O>,
    state: u32,
    byte: u8,
    next: &[Option<AnchoredOutcome>],
    dispatcher: &mut dyn TaggedCandidateDispatcher,
    meter: &mut ExecutionMeter,
    actual: &mut ExecutionActual,
) -> Result<Option<AnchoredOutcome>, ReduceError> {
    let Some(first_edge) = dispatcher.first_edge(&plan.automaton, state, byte, meter, actual)?
    else {
        return Ok(None);
    };
    let state_edges = plan.automaton.state_edges(state);
    if first_edge < state_edges.start || first_edge >= state_edges.end {
        return Err(ReduceError::InternalInvariant {
            detail: "tagged dispatch candidate escaped its state",
        });
    }
    for edge in first_edge..state_edges.end {
        meter.charge(1)?;
        increment_tagged_edge_visits(actual)?;
        if plan.automaton.byte_starts[edge] <= byte && byte <= plan.automaton.byte_ends[edge] {
            let target = plan_index(plan.automaton.edge_targets[edge]);
            if let Some(outcome) = next.get(target).copied().flatten() {
                return Ok(Some(outcome));
            }
        }
    }
    Ok(None)
}

/// Execute an unbounded-match finite-route request as an authenticated sparse
/// fallback. The input length bounds its full suffix window, so its execution
/// prospective is intentionally identical to the sparse route rather than to
/// the static finite-horizon ring.
fn execute_input_bounded_sparse_fallback<O: DirectReduceValue>(
    plan: &PreparedPriorityAutomaton<O>,
    haystack: &[u8],
    limits: DirectReduceLimits,
    prospective: ExecutionProspective,
) -> Result<(O::Output, ExecutionActual), ReduceError> {
    if !matches!(
        &plan.route,
        PreparedRoute::InputBoundedSparseFallback { .. }
    ) {
        return Err(ReduceError::InternalInvariant {
            detail: "input-bounded executor received another prepared route",
        });
    }
    execute_sparse(plan, haystack, limits, prospective)
}

fn execute_sparse<O: DirectReduceValue>(
    plan: &PreparedPriorityAutomaton<O>,
    haystack: &[u8],
    limits: DirectReduceLimits,
    prospective: ExecutionProspective,
) -> Result<(O::Output, ExecutionActual), ReduceError> {
    let (PreparedRoute::Sparse { evaluation }
    | PreparedRoute::InputBoundedSparseFallback { evaluation }) = &plan.route
    else {
        return Err(ReduceError::InternalInvariant {
            detail: "sparse-like executor received another prepared route",
        });
    };
    execute_reverse_row_transducer(plan, haystack, limits, prospective, evaluation)
}

#[allow(
    clippy::too_many_lines,
    reason = "the dedicated trace path keeps preflight, B's row walkers, and C's forward selection transaction adjacent"
)]
fn execute_sparse_trace<O: DirectReduceValue>(
    plan: &PreparedPriorityAutomaton<O>,
    haystack: &[u8],
    limits: DirectReduceLimits,
) -> Result<DirectReduceTraceReport<O::Output>, ReduceError> {
    let PreparedRoute::Sparse { evaluation } = &plan.route else {
        return Err(ReduceError::InternalInvariant {
            detail: "sparse trace executor received another prepared route",
        });
    };
    let untraced_prospective = prospective(plan, haystack.len(), limits)?;
    let traced_prospective = trace_prospective(untraced_prospective, limits)?;
    if size_of::<Option<AnchoredOutcome>>() > size_of::<SuffixValue<O::Output>>()
        || core::mem::align_of::<Option<AnchoredOutcome>>()
            > core::mem::align_of::<SuffixValue<O::Output>>()
    {
        return Err(ReduceError::InternalInvariant {
            detail: "sparse trace roots do not fit the admitted suffix slot",
        });
    }

    let rows = traced_prospective.boundary_rows;
    let states = plan.automaton.stats().states();
    let stack_slots = plan
        .automaton
        .stats()
        .zero_width_edges()
        .checked_add(1)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "cyclic sparse trace stack slots",
        })?;
    let setup_slots = match evaluation {
        SparseEvaluation::Acyclic(_) => states.checked_mul(2),
        SparseEvaluation::Cyclic => states
            .checked_mul(3)
            .and_then(|value| value.checked_add(stack_slots)),
    }
    .and_then(|value| value.checked_add(rows))
    .ok_or(ReduceError::ArithmeticOverflow {
        computation: "sparse trace setup slots",
    })?;
    let mut meter = ExecutionMeter::new(limits.max_work);
    meter.charge(
        u64::try_from(setup_slots).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "sparse trace setup work conversion",
        })?,
    )?;
    let mut actual = ExecutionActual::zero(haystack.len());
    let mut roots = allocate_execution_slots(
        rows,
        None::<AnchoredOutcome>,
        traced_prospective.scratch_bytes,
    )?;
    meter.charge(1)?;
    let mut trace = reserve_execution_trace(
        untraced_prospective.match_events_upper_bound,
        traced_prospective.scratch_bytes,
    )?;
    {
        let mut observe =
            |position, outcome, meter: &mut ExecutionMeter, _actual: &mut ExecutionActual| {
                // This is the same per-row charge as B's suffix reducer. The
                // admitted suffix slot is instead used to retain C's selected
                // roots for one separately prepaid forward scan.
                meter.charge(1)?;
                roots[position] = outcome;
                Ok(())
            };
        match evaluation {
            SparseEvaluation::Acyclic(order) => {
                let mut workspace =
                    AcyclicSparseWorkspace::new(states, traced_prospective.scratch_bytes)?;
                walk_acyclic_sparse_rows(
                    plan,
                    haystack,
                    order,
                    &mut workspace,
                    &mut meter,
                    &mut actual,
                    &mut observe,
                )?;
            }
            SparseEvaluation::Cyclic => {
                let mut workspace = CyclicSparseWorkspace::new(
                    states,
                    stack_slots,
                    traced_prospective.scratch_bytes,
                )?;
                walk_cyclic_sparse_rows(
                    plan,
                    haystack,
                    &mut workspace,
                    &mut meter,
                    &mut actual,
                    &mut observe,
                )?;
            }
        }
    }

    let mut output = O::zero();
    let mut next_eligible = 0usize;
    let mut suppress_empty_at = None::<usize>;
    // Meter every boundary in the independently admitted forward scan. The
    // eligibility gate keeps the old non-overlap selection semantics without
    // skipping the rows that the trace prospective has reserved work for.
    for position in 0..rows {
        meter.charge(1)?;
        if position < next_eligible {
            continue;
        }
        let Some(outcome) = roots[position] else {
            continue;
        };
        if outcome.end < position || outcome.end > haystack.len() {
            return Err(ReduceError::InternalInvariant {
                detail: "sparse trace outcome escaped its source boundaries",
            });
        }
        if plan.build_many_empty_progress
            && outcome.end == position
            && suppress_empty_at == Some(position)
        {
            continue;
        }
        meter.charge(1)?;
        record_match(&mut actual, outcome, position, limits.max_match_events)?;
        output = O::append(output, position, outcome.end, outcome.action.ordinal())?;
        trace.push(PriorityMatch::from_parts(
            outcome.action.ordinal(),
            position,
            outcome.end,
        ));
        if outcome.end > position {
            next_eligible = outcome.end;
            if plan.build_many_empty_progress {
                suppress_empty_at = Some(outcome.end);
            }
        }
    }
    actual.work = meter.consumed;
    let report = finish_execution_report(haystack.len(), output, traced_prospective, actual)?;
    let trace_report = DirectReduceTraceReport::from_parts(report, untraced_prospective, trace);
    if !trace_report.closes() {
        return Err(ReduceError::InternalInvariant {
            detail: "sparse trace report disagrees with its preflighted reservation",
        });
    }
    Ok(trace_report)
}

fn execute_priority_tagged_transducer<O: DirectReduceValue>(
    plan: &PreparedPriorityAutomaton<O>,
    haystack: &[u8],
    limits: DirectReduceLimits,
    prospective: ExecutionProspective,
) -> Result<(O::Output, ExecutionActual), ReduceError> {
    match &plan.route {
        PreparedRoute::FullTransducer(transducer) => {
            let mut dispatcher = FullTaggedDispatcher { transducer };
            execute_tagged_reverse_row_transducer(
                plan,
                haystack,
                limits,
                prospective,
                &transducer.evaluation,
                &mut dispatcher,
                0,
            )
        }
        PreparedRoute::LazyTransducer(transducer) => {
            let cache = LazyTaggedCache::new(prospective)?;
            let cache_slots = cache.cells.len();
            let mut dispatcher = LazyTaggedDispatcher { transducer, cache };
            execute_tagged_reverse_row_transducer(
                plan,
                haystack,
                limits,
                prospective,
                &transducer.evaluation,
                &mut dispatcher,
                cache_slots,
            )
        }
        _ => Err(ReduceError::InternalInvariant {
            detail: "priority transducer executor received another prepared route",
        }),
    }
}

/// Execute a tagged reverse-row route after its static program (and, for the
/// lazy route, its bounded candidate cache) has been selected before source
/// work.  Assertions and reverse outcomes are intentionally evaluated only
/// inside the row walkers below.
#[allow(clippy::too_many_arguments)]
fn execute_tagged_reverse_row_transducer<O: DirectReduceValue>(
    plan: &PreparedPriorityAutomaton<O>,
    haystack: &[u8],
    limits: DirectReduceLimits,
    prospective: ExecutionProspective,
    evaluation: &SparseEvaluation,
    dispatcher: &mut dyn TaggedCandidateDispatcher,
    cache_setup_slots: usize,
) -> Result<(O::Output, ExecutionActual), ReduceError> {
    let rows = prospective.boundary_rows;
    let mut meter = ExecutionMeter::new(limits.max_work);
    let mut actual = ExecutionActual::zero(haystack.len());
    actual.tagged_dispatch_states = prospective.tagged_dispatch_states_capacity;
    actual.tagged_dispatch_cells = prospective.tagged_dispatch_cells_capacity;
    actual.tagged_candidate_items = prospective.tagged_candidate_items_capacity;
    actual.tagged_cache_cells = prospective.tagged_cache_cells_capacity;
    let states = plan.automaton.stats().states();
    let stack_slots = plan
        .automaton
        .stats()
        .zero_width_edges()
        .checked_add(1)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "cyclic tagged stack slots",
        })?;
    let setup_slots = match evaluation {
        SparseEvaluation::Acyclic(_) => states.checked_mul(2),
        SparseEvaluation::Cyclic => states
            .checked_mul(3)
            .and_then(|value| value.checked_add(stack_slots)),
    }
    .and_then(|value| value.checked_add(rows))
    .and_then(|value| value.checked_add(cache_setup_slots))
    .ok_or(ReduceError::ArithmeticOverflow {
        computation: "tagged transducer setup slots",
    })?;
    meter.charge(
        u64::try_from(setup_slots).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "tagged transducer setup work conversion",
        })?,
    )?;
    let zero = SuffixValue::zero(O::zero());
    let mut suffixes = allocate_execution_slots(rows, zero.clone(), prospective.scratch_bytes)?;
    let mut final_value = zero;
    let mut observe =
        |position, outcome, meter: &mut ExecutionMeter, actual: &mut ExecutionActual| {
            meter.charge(1)?;
            actual.suffix_reducer_steps = actual.suffix_reducer_steps.checked_add(1).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "tagged suffix reducer steps",
                },
            )?;
            let value = sparse_suffix_value::<O>(&suffixes, haystack.len(), position, outcome)?;
            suffixes[position] = value.clone();
            if position == 0 {
                final_value = value;
            }
            Ok(())
        };
    match evaluation {
        SparseEvaluation::Acyclic(order) => {
            let mut workspace = AcyclicSparseWorkspace::new(states, prospective.scratch_bytes)?;
            walk_acyclic_tagged_rows(
                plan,
                haystack,
                order,
                &mut workspace,
                dispatcher,
                &mut meter,
                &mut actual,
                &mut observe,
            )?;
        }
        SparseEvaluation::Cyclic => {
            let mut workspace =
                CyclicSparseWorkspace::new(states, stack_slots, prospective.scratch_bytes)?;
            walk_cyclic_tagged_rows(
                plan,
                haystack,
                &mut workspace,
                dispatcher,
                &mut meter,
                &mut actual,
                &mut observe,
            )?;
        }
    }
    if final_value.matches > limits.max_match_events {
        return Err(ReduceError::MatchEventsLimit {
            needed: final_value.matches,
            limit: limits.max_match_events,
        });
    }
    actual.match_events = final_value.matches;
    actual.empty_match_events = final_value.empty_matches;
    actual.selected_span_bytes = final_value.span_bytes;
    actual.selected_ordinal_sum = final_value.ordinal_sum;
    actual.work = meter.consumed;
    Ok((final_value.output, actual))
}

/// Evaluate one bounded ordered, priority-tagged reverse-row transducer.
///
/// Terminal actions carry the source priority tag.  Split edges are evaluated
/// in their canonical order against the original boundary, so a dynamic
/// assertion is never mistaken for a source-free DFA transition.
fn execute_reverse_row_transducer<O: DirectReduceValue>(
    plan: &PreparedPriorityAutomaton<O>,
    haystack: &[u8],
    limits: DirectReduceLimits,
    prospective: ExecutionProspective,
    evaluation: &SparseEvaluation,
) -> Result<(O::Output, ExecutionActual), ReduceError> {
    let rows = prospective.boundary_rows;
    let mut meter = ExecutionMeter::new(limits.max_work);
    let mut actual = ExecutionActual::zero(haystack.len());
    let states = plan.automaton.stats().states();
    let stack_slots = plan
        .automaton
        .stats()
        .zero_width_edges()
        .checked_add(1)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "cyclic sparse stack slots",
        })?;
    let setup_slots = match evaluation {
        SparseEvaluation::Acyclic(_) => states.checked_mul(2),
        SparseEvaluation::Cyclic => states
            .checked_mul(3)
            .and_then(|value| value.checked_add(stack_slots)),
    }
    .and_then(|value| value.checked_add(rows))
    .ok_or(ReduceError::ArithmeticOverflow {
        computation: "sparse setup slots",
    })?;
    meter.charge(
        u64::try_from(setup_slots).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "sparse setup work conversion",
        })?,
    )?;
    let zero = SuffixValue::zero(O::zero());
    let mut suffixes = allocate_execution_slots(rows, zero.clone(), prospective.scratch_bytes)?;
    let mut final_value = zero;
    let mut observe =
        |position, outcome, meter: &mut ExecutionMeter, actual: &mut ExecutionActual| {
            meter.charge(1)?;
            actual.suffix_reducer_steps = actual.suffix_reducer_steps.checked_add(1).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "sparse suffix reducer steps",
                },
            )?;
            let value = sparse_suffix_value::<O>(&suffixes, haystack.len(), position, outcome)?;
            suffixes[position] = value.clone();
            if position == 0 {
                final_value = value;
            }
            Ok(())
        };
    match evaluation {
        SparseEvaluation::Acyclic(order) => {
            let mut workspace = AcyclicSparseWorkspace::new(states, prospective.scratch_bytes)?;
            walk_acyclic_sparse_rows(
                plan,
                haystack,
                order,
                &mut workspace,
                &mut meter,
                &mut actual,
                &mut observe,
            )?;
        }
        SparseEvaluation::Cyclic => {
            let mut workspace =
                CyclicSparseWorkspace::new(states, stack_slots, prospective.scratch_bytes)?;
            walk_cyclic_sparse_rows(
                plan,
                haystack,
                &mut workspace,
                &mut meter,
                &mut actual,
                &mut observe,
            )?;
        }
    }
    if final_value.matches > limits.max_match_events {
        return Err(ReduceError::MatchEventsLimit {
            needed: final_value.matches,
            limit: limits.max_match_events,
        });
    }
    actual.match_events = final_value.matches;
    actual.empty_match_events = final_value.empty_matches;
    actual.selected_span_bytes = final_value.span_bytes;
    actual.selected_ordinal_sum = final_value.ordinal_sum;
    actual.work = meter.consumed;
    Ok((final_value.output, actual))
}

fn sparse_suffix_value<O: DirectReduceValue>(
    suffixes: &[SuffixValue<O::Output>],
    haystack_len: usize,
    position: usize,
    outcome: Option<AnchoredOutcome>,
) -> Result<SuffixValue<O::Output>, ReduceError> {
    let Some(outcome) = outcome else {
        return if position == haystack_len {
            Ok(SuffixValue::zero(O::zero()))
        } else {
            let next = position
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "sparse suffix next position",
                })?;
            Ok(suffixes[next].clone())
        };
    };
    let length = outcome
        .end
        .checked_sub(position)
        .ok_or(ReduceError::InternalInvariant {
            detail: "sparse anchored outcome ends before its start",
        })?;
    let base = if outcome.end == position {
        if position == haystack_len {
            SuffixValue::zero(O::zero())
        } else {
            let next = position
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "sparse empty-match next position",
                })?;
            suffixes[next].clone()
        }
    } else {
        suffixes
            .get(outcome.end)
            .ok_or(ReduceError::InternalInvariant {
                detail: "sparse anchored outcome exceeds the suffix table",
            })?
            .clone()
    };
    Ok(SuffixValue {
        output: O::prepend(base.output, position, outcome.end, outcome.action.ordinal())?,
        matches: base
            .matches
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "sparse suffix match events",
            })?,
        empty_matches: base
            .empty_matches
            .checked_add(usize::from(outcome.end == position))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "sparse suffix empty events",
            })?,
        span_bytes: base
            .span_bytes
            .checked_add(
                u64::try_from(length).map_err(|_| ReduceError::ArithmeticOverflow {
                    computation: "sparse suffix selected span conversion",
                })?,
            )
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "sparse suffix selected span bytes",
            })?,
        ordinal_sum: base
            .ordinal_sum
            .checked_add(u64::from(outcome.action.ordinal().get()))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "sparse suffix ordinal sum",
            })?,
    })
}

fn execute_finite<O: DirectReduceValue>(
    plan: &PreparedPriorityAutomaton<O>,
    haystack: &[u8],
    limits: DirectReduceLimits,
    prospective: ExecutionProspective,
    maximum_bytes: usize,
) -> Result<(O::Output, ExecutionActual), ReduceError> {
    let rows = prospective.boundary_rows;
    let ring_len = finite_execution_ring_len(rows, maximum_bytes)?;
    let mut meter = ExecutionMeter::new(limits.max_work);
    let mut actual = ExecutionActual::zero(haystack.len());
    let PreparedRoute::FiniteHorizon { evaluation, .. } = &plan.route else {
        return Err(ReduceError::InternalInvariant {
            detail: "finite executor received another prepared route",
        });
    };
    let states = plan.automaton.stats().states();
    let stack_slots = plan
        .automaton
        .stats()
        .zero_width_edges()
        .checked_add(1)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "cyclic finite stack slots",
        })?;
    let setup_slots = match evaluation {
        SparseEvaluation::Acyclic(_) => states.checked_mul(2),
        SparseEvaluation::Cyclic => states
            .checked_mul(3)
            .and_then(|value| value.checked_add(stack_slots)),
    }
    .and_then(|value| value.checked_add(ring_len))
    .ok_or(ReduceError::ArithmeticOverflow {
        computation: "finite setup slots",
    })?;
    meter.charge(
        u64::try_from(setup_slots).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "finite setup work conversion",
        })?,
    )?;
    let zero = SuffixValue::zero(O::zero());
    let mut ring = allocate_execution_slots(ring_len, zero.clone(), prospective.scratch_bytes)?;
    let mut final_value = zero;
    let mut observe =
        |position, outcome, meter: &mut ExecutionMeter, actual: &mut ExecutionActual| {
            meter.charge(1)?;
            actual.suffix_reducer_steps = actual.suffix_reducer_steps.checked_add(1).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "finite suffix reducer steps",
                },
            )?;
            let value = finite_suffix_value::<O>(
                &ring,
                ring_len,
                haystack.len(),
                position,
                outcome,
                maximum_bytes,
            )?;
            let slot = finite_ring_slot(position, ring_len)?;
            ring[slot] = value.clone();
            if position == 0 {
                final_value = value;
            }
            Ok(())
        };
    match evaluation {
        SparseEvaluation::Acyclic(order) => {
            let mut workspace = AcyclicSparseWorkspace::new(states, prospective.scratch_bytes)?;
            walk_acyclic_sparse_rows(
                plan,
                haystack,
                order,
                &mut workspace,
                &mut meter,
                &mut actual,
                &mut observe,
            )?;
        }
        SparseEvaluation::Cyclic => {
            let mut workspace =
                CyclicSparseWorkspace::new(states, stack_slots, prospective.scratch_bytes)?;
            walk_cyclic_sparse_rows(
                plan,
                haystack,
                &mut workspace,
                &mut meter,
                &mut actual,
                &mut observe,
            )?;
        }
    }
    if final_value.matches > limits.max_match_events {
        return Err(ReduceError::MatchEventsLimit {
            needed: final_value.matches,
            limit: limits.max_match_events,
        });
    }
    actual.match_events = final_value.matches;
    actual.empty_match_events = final_value.empty_matches;
    actual.selected_span_bytes = final_value.span_bytes;
    actual.selected_ordinal_sum = final_value.ordinal_sum;
    actual.work = meter.consumed;
    Ok((final_value.output, actual))
}

fn finite_execution_ring_len(rows: usize, maximum_bytes: usize) -> Result<usize, ReduceError> {
    Ok(rows.min(
        maximum_bytes
            .checked_add(2)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "finite reducer ring length",
            })?,
    ))
}

fn finite_suffix_value<O: DirectReduceValue>(
    ring: &[SuffixValue<O::Output>],
    ring_len: usize,
    haystack_len: usize,
    position: usize,
    outcome: Option<AnchoredOutcome>,
    maximum_bytes: usize,
) -> Result<SuffixValue<O::Output>, ReduceError> {
    let Some(outcome) = outcome else {
        return if position == haystack_len {
            Ok(SuffixValue::zero(O::zero()))
        } else {
            let next = position
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "finite suffix next position",
                })?;
            Ok(ring[finite_ring_slot(next, ring_len)?].clone())
        };
    };
    let length = outcome
        .end
        .checked_sub(position)
        .ok_or(ReduceError::InternalInvariant {
            detail: "finite anchored outcome ends before its start",
        })?;
    if length > maximum_bytes {
        return Err(ReduceError::FiniteHorizonProofViolated {
            start: position,
            end: outcome.end,
            maximum_bytes,
        });
    }
    let base = if outcome.end == position {
        if position == haystack_len {
            SuffixValue::zero(O::zero())
        } else {
            let next = position
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "finite empty-match next position",
                })?;
            ring[finite_ring_slot(next, ring_len)?].clone()
        }
    } else {
        ring[finite_ring_slot(outcome.end, ring_len)?].clone()
    };
    Ok(SuffixValue {
        output: O::prepend(base.output, position, outcome.end, outcome.action.ordinal())?,
        matches: base
            .matches
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "finite reducer match events",
            })?,
        empty_matches: base
            .empty_matches
            .checked_add(usize::from(outcome.end == position))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "finite reducer empty events",
            })?,
        span_bytes: base
            .span_bytes
            .checked_add(
                u64::try_from(length).map_err(|_| ReduceError::ArithmeticOverflow {
                    computation: "finite reducer selected span conversion",
                })?,
            )
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "finite reducer selected span bytes",
            })?,
        ordinal_sum: base
            .ordinal_sum
            .checked_add(u64::from(outcome.action.ordinal().get()))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "finite reducer ordinal sum",
            })?,
    })
}

fn finite_ring_slot(position: usize, ring_len: usize) -> Result<usize, ReduceError> {
    position
        .checked_rem(ring_len)
        .ok_or(ReduceError::InternalInvariant {
            detail: "finite reducer ring is empty",
        })
}

fn walk_acyclic_sparse_rows<O, F>(
    plan: &PreparedPriorityAutomaton<O>,
    haystack: &[u8],
    evaluation_order: &[u32],
    workspace: &mut AcyclicSparseWorkspace,
    meter: &mut ExecutionMeter,
    actual: &mut ExecutionActual,
    mut observe: F,
) -> Result<(), ReduceError>
where
    O: DirectReduceValue,
    F: FnMut(
        usize,
        Option<AnchoredOutcome>,
        &mut ExecutionMeter,
        &mut ExecutionActual,
    ) -> Result<(), ReduceError>,
{
    if evaluation_order.len() != plan.automaton.stats().states() {
        return Err(ReduceError::InternalInvariant {
            detail: "sparse evaluation order has the wrong state count",
        });
    }
    for position in (0..=haystack.len()).rev() {
        meter.charge(1)?;
        actual.boundary_rows =
            actual
                .boundary_rows
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "sparse boundary rows",
                })?;
        let byte = haystack.get(position).copied();
        for &state in evaluation_order {
            meter.charge(1)?;
            actual.sparse_root_evaluations = actual.sparse_root_evaluations.checked_add(1).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "sparse root evaluations",
                },
            )?;
            actual.sparse_closure_visits = actual.sparse_closure_visits.checked_add(1).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "sparse closure visits",
                },
            )?;
            let index = plan_index(state);
            let outcome = match plan.automaton.roles[index] {
                StateRole::Accept => {
                    let action = plan.actions[index].ok_or(ReduceError::InternalInvariant {
                        detail: "validated sparse accept lost its action",
                    })?;
                    Some(AnchoredOutcome {
                        end: position,
                        action,
                    })
                }
                StateRole::Consume => {
                    let mut selected = None;
                    if let Some(byte) = byte {
                        for edge in plan.automaton.state_edges(state) {
                            meter.charge(1)?;
                            actual.sparse_edge_visits = actual
                                .sparse_edge_visits
                                .checked_add(1)
                                .ok_or(ReduceError::ArithmeticOverflow {
                                    computation: "sparse edge visits",
                                })?;
                            if plan.automaton.byte_starts[edge] <= byte
                                && byte <= plan.automaton.byte_ends[edge]
                            {
                                let target = plan_index(plan.automaton.edge_targets[edge]);
                                if let Some(outcome) = workspace.next[target] {
                                    selected = Some(outcome);
                                    break;
                                }
                            }
                        }
                    }
                    selected
                }
                StateRole::Split => {
                    let mut selected = None;
                    for edge in plan.automaton.state_edges(state) {
                        meter.charge(1)?;
                        actual.sparse_edge_visits = actual
                            .sparse_edge_visits
                            .checked_add(1)
                            .ok_or(ReduceError::ArithmeticOverflow {
                                computation: "sparse edge visits",
                            })?;
                        let enabled = zero_width_edge_enabled(
                            &plan.automaton,
                            plan.automaton.edge_kinds[edge],
                            haystack,
                            position,
                        )
                        .map_err(|_| ReduceError::InternalInvariant {
                            detail: "validated zero-width assertion evaluation failed",
                        })?;
                        if enabled {
                            let target = plan_index(plan.automaton.edge_targets[edge]);
                            if let Some(outcome) = workspace.current[target] {
                                selected = Some(outcome);
                                break;
                            }
                        }
                    }
                    selected
                }
            };
            workspace.current[index] = outcome;
        }
        let root = workspace.current[plan_index(plan.automaton.start)];
        observe(position, root, meter, actual)?;
        core::mem::swap(&mut workspace.current, &mut workspace.next);
    }
    Ok(())
}

fn walk_cyclic_sparse_rows<O, F>(
    plan: &PreparedPriorityAutomaton<O>,
    haystack: &[u8],
    workspace: &mut CyclicSparseWorkspace,
    meter: &mut ExecutionMeter,
    actual: &mut ExecutionActual,
    mut observe: F,
) -> Result<(), ReduceError>
where
    O: DirectReduceValue,
    F: FnMut(
        usize,
        Option<AnchoredOutcome>,
        &mut ExecutionMeter,
        &mut ExecutionActual,
    ) -> Result<(), ReduceError>,
{
    for position in (0..=haystack.len()).rev() {
        meter.charge(1)?;
        actual.boundary_rows =
            actual
                .boundary_rows
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "cyclic sparse boundary rows",
                })?;
        let byte = haystack.get(position).copied();
        for state in 0..plan.automaton.stats().states() {
            next_cyclic_sparse_generation(workspace, meter, actual)?;
            actual.sparse_root_evaluations = actual.sparse_root_evaluations.checked_add(1).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "cyclic sparse root evaluations",
                },
            )?;
            let state = u32::try_from(state).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "cyclic sparse root state conversion",
            })?;
            workspace.current[plan_index(state)] = evaluate_cyclic_sparse_root(
                plan, haystack, position, byte, state, workspace, meter, actual,
            )?;
        }
        let root = workspace.current[plan_index(plan.automaton.start)];
        observe(position, root, meter, actual)?;
        core::mem::swap(&mut workspace.current, &mut workspace.next);
    }
    Ok(())
}

fn next_cyclic_sparse_generation(
    workspace: &mut CyclicSparseWorkspace,
    meter: &mut ExecutionMeter,
    actual: &mut ExecutionActual,
) -> Result<(), ReduceError> {
    if workspace.generation == u64::MAX {
        meter.charge(u64::try_from(workspace.stamps.len()).map_err(|_| {
            ReduceError::ArithmeticOverflow {
                computation: "cyclic sparse generation reset work conversion",
            }
        })?)?;
        workspace.stamps.fill(0);
        workspace.generation = 0;
        actual.generation_resets =
            actual
                .generation_resets
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "cyclic sparse generation reset count",
                })?;
    }
    workspace.generation =
        workspace
            .generation
            .checked_add(1)
            .ok_or(ReduceError::InternalInvariant {
                detail: "cyclic sparse generation increment was not preflighted",
            })?;
    Ok(())
}

// Cyclic zero-width graphs retain the bounded root-local DFS used before the
// acyclic whole-row executor was introduced.
#[allow(clippy::too_many_arguments)]
fn evaluate_cyclic_sparse_root<O: DirectReduceValue>(
    plan: &PreparedPriorityAutomaton<O>,
    haystack: &[u8],
    position: usize,
    byte: Option<u8>,
    root: u32,
    workspace: &mut CyclicSparseWorkspace,
    meter: &mut ExecutionMeter,
    actual: &mut ExecutionActual,
) -> Result<Option<AnchoredOutcome>, ReduceError> {
    workspace.stack_len = 0;
    workspace.push(root)?;
    while let Some(state) = workspace.pop() {
        meter.charge(1)?;
        actual.sparse_closure_visits =
            actual
                .sparse_closure_visits
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "cyclic sparse closure visits",
                })?;
        let index = plan_index(state);
        if workspace.stamps[index] == workspace.generation {
            continue;
        }
        workspace.stamps[index] = workspace.generation;
        match plan.automaton.roles[index] {
            StateRole::Accept => {
                let action = plan.actions[index].ok_or(ReduceError::InternalInvariant {
                    detail: "validated cyclic sparse accept lost its action",
                })?;
                return Ok(Some(AnchoredOutcome {
                    end: position,
                    action,
                }));
            }
            StateRole::Consume => {
                let Some(byte) = byte else {
                    continue;
                };
                for edge in plan.automaton.state_edges(state) {
                    meter.charge(1)?;
                    actual.sparse_edge_visits = actual.sparse_edge_visits.checked_add(1).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "cyclic sparse edge visits",
                        },
                    )?;
                    if plan.automaton.byte_starts[edge] <= byte
                        && byte <= plan.automaton.byte_ends[edge]
                    {
                        let target = plan_index(plan.automaton.edge_targets[edge]);
                        if let Some(outcome) = workspace.next[target] {
                            return Ok(Some(outcome));
                        }
                    }
                }
            }
            StateRole::Split => {
                for edge in plan.automaton.state_edges(state).rev() {
                    meter.charge(1)?;
                    actual.sparse_edge_visits = actual.sparse_edge_visits.checked_add(1).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "cyclic sparse edge visits",
                        },
                    )?;
                    let enabled = zero_width_edge_enabled(
                        &plan.automaton,
                        plan.automaton.edge_kinds[edge],
                        haystack,
                        position,
                    )
                    .map_err(|_| ReduceError::InternalInvariant {
                        detail: "validated cyclic zero-width assertion evaluation failed",
                    })?;
                    if enabled {
                        workspace.push(plan.automaton.edge_targets[edge])?;
                    }
                }
            }
        }
    }
    Ok(None)
}

fn increment_tagged_state_evaluations(actual: &mut ExecutionActual) -> Result<(), ReduceError> {
    actual.tagged_state_evaluations =
        actual
            .tagged_state_evaluations
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "tagged state evaluations",
            })?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn walk_acyclic_tagged_rows<O, F>(
    plan: &PreparedPriorityAutomaton<O>,
    haystack: &[u8],
    evaluation_order: &[u32],
    workspace: &mut AcyclicSparseWorkspace,
    dispatcher: &mut dyn TaggedCandidateDispatcher,
    meter: &mut ExecutionMeter,
    actual: &mut ExecutionActual,
    mut observe: F,
) -> Result<(), ReduceError>
where
    O: DirectReduceValue,
    F: FnMut(
        usize,
        Option<AnchoredOutcome>,
        &mut ExecutionMeter,
        &mut ExecutionActual,
    ) -> Result<(), ReduceError>,
{
    if evaluation_order.len() != plan.automaton.stats().states() {
        return Err(ReduceError::InternalInvariant {
            detail: "tagged evaluation order has the wrong state count",
        });
    }
    for position in (0..=haystack.len()).rev() {
        meter.charge(1)?;
        actual.boundary_rows =
            actual
                .boundary_rows
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "tagged acyclic boundary rows",
                })?;
        let byte = haystack.get(position).copied();
        for &state in evaluation_order {
            meter.charge(1)?;
            increment_tagged_state_evaluations(actual)?;
            let index = plan_index(state);
            let outcome = match plan.automaton.roles[index] {
                StateRole::Accept => {
                    let action = plan.actions[index].ok_or(ReduceError::InternalInvariant {
                        detail: "validated tagged accept lost its action",
                    })?;
                    Some(AnchoredOutcome {
                        end: position,
                        action,
                    })
                }
                StateRole::Consume => match byte {
                    Some(byte) => tagged_consume_outcome(
                        plan,
                        state,
                        byte,
                        &workspace.next,
                        dispatcher,
                        meter,
                        actual,
                    )?,
                    None => None,
                },
                StateRole::Split => {
                    let mut selected = None;
                    for edge in plan.automaton.state_edges(state) {
                        meter.charge(1)?;
                        increment_tagged_edge_visits(actual)?;
                        let enabled = zero_width_edge_enabled(
                            &plan.automaton,
                            plan.automaton.edge_kinds[edge],
                            haystack,
                            position,
                        )
                        .map_err(|_| ReduceError::InternalInvariant {
                            detail: "validated tagged zero-width assertion evaluation failed",
                        })?;
                        if enabled {
                            let target = plan_index(plan.automaton.edge_targets[edge]);
                            if let Some(outcome) = workspace.current[target] {
                                selected = Some(outcome);
                                break;
                            }
                        }
                    }
                    selected
                }
            };
            workspace.current[index] = outcome;
        }
        let root = workspace.current[plan_index(plan.automaton.start)];
        observe(position, root, meter, actual)?;
        core::mem::swap(&mut workspace.current, &mut workspace.next);
    }
    Ok(())
}

fn walk_cyclic_tagged_rows<O, F>(
    plan: &PreparedPriorityAutomaton<O>,
    haystack: &[u8],
    workspace: &mut CyclicSparseWorkspace,
    dispatcher: &mut dyn TaggedCandidateDispatcher,
    meter: &mut ExecutionMeter,
    actual: &mut ExecutionActual,
    mut observe: F,
) -> Result<(), ReduceError>
where
    O: DirectReduceValue,
    F: FnMut(
        usize,
        Option<AnchoredOutcome>,
        &mut ExecutionMeter,
        &mut ExecutionActual,
    ) -> Result<(), ReduceError>,
{
    for position in (0..=haystack.len()).rev() {
        meter.charge(1)?;
        actual.boundary_rows =
            actual
                .boundary_rows
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "tagged cyclic boundary rows",
                })?;
        let byte = haystack.get(position).copied();
        for state in 0..plan.automaton.stats().states() {
            next_cyclic_sparse_generation(workspace, meter, actual)?;
            let state = u32::try_from(state).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "tagged cyclic root state conversion",
            })?;
            workspace.current[plan_index(state)] = evaluate_cyclic_tagged_root(
                plan, haystack, position, byte, state, workspace, dispatcher, meter, actual,
            )?;
        }
        let root = workspace.current[plan_index(plan.automaton.start)];
        observe(position, root, meter, actual)?;
        core::mem::swap(&mut workspace.current, &mut workspace.next);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn evaluate_cyclic_tagged_root<O: DirectReduceValue>(
    plan: &PreparedPriorityAutomaton<O>,
    haystack: &[u8],
    position: usize,
    byte: Option<u8>,
    root: u32,
    workspace: &mut CyclicSparseWorkspace,
    dispatcher: &mut dyn TaggedCandidateDispatcher,
    meter: &mut ExecutionMeter,
    actual: &mut ExecutionActual,
) -> Result<Option<AnchoredOutcome>, ReduceError> {
    workspace.stack_len = 0;
    workspace.push(root)?;
    while let Some(state) = workspace.pop() {
        meter.charge(1)?;
        increment_tagged_state_evaluations(actual)?;
        let index = plan_index(state);
        if workspace.stamps[index] == workspace.generation {
            continue;
        }
        workspace.stamps[index] = workspace.generation;
        match plan.automaton.roles[index] {
            StateRole::Accept => {
                let action = plan.actions[index].ok_or(ReduceError::InternalInvariant {
                    detail: "validated cyclic tagged accept lost its action",
                })?;
                return Ok(Some(AnchoredOutcome {
                    end: position,
                    action,
                }));
            }
            StateRole::Consume => {
                let Some(byte) = byte else {
                    continue;
                };
                if let Some(outcome) = tagged_consume_outcome(
                    plan,
                    state,
                    byte,
                    &workspace.next,
                    dispatcher,
                    meter,
                    actual,
                )? {
                    return Ok(Some(outcome));
                }
            }
            StateRole::Split => {
                for edge in plan.automaton.state_edges(state).rev() {
                    meter.charge(1)?;
                    increment_tagged_edge_visits(actual)?;
                    let enabled = zero_width_edge_enabled(
                        &plan.automaton,
                        plan.automaton.edge_kinds[edge],
                        haystack,
                        position,
                    )
                    .map_err(|_| ReduceError::InternalInvariant {
                        detail: "validated cyclic tagged zero-width assertion evaluation failed",
                    })?;
                    if enabled {
                        workspace.push(plan.automaton.edge_targets[edge])?;
                    }
                }
            }
        }
    }
    Ok(None)
}

fn record_match(
    actual: &mut ExecutionActual,
    outcome: AnchoredOutcome,
    start: usize,
    max_match_events: usize,
) -> Result<(), ReduceError> {
    if actual.match_events == max_match_events {
        return Err(ReduceError::MatchEventsLimit {
            needed: actual.match_events.saturating_add(1),
            limit: max_match_events,
        });
    }
    actual.match_events =
        actual
            .match_events
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "match events",
            })?;
    actual.empty_match_events = actual
        .empty_match_events
        .checked_add(usize::from(outcome.end == start))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "empty match events",
        })?;
    let span_bytes = outcome
        .end
        .checked_sub(start)
        .ok_or(ReduceError::InternalInvariant {
            detail: "selected match end precedes its start",
        })?;
    actual.selected_span_bytes = actual
        .selected_span_bytes
        .checked_add(
            u64::try_from(span_bytes).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "selected span byte conversion",
            })?,
        )
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "selected span bytes",
        })?;
    actual.selected_ordinal_sum = actual
        .selected_ordinal_sum
        .checked_add(u64::from(outcome.action.ordinal().get()))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "selected ordinal sum",
        })?;
    Ok(())
}

fn allocate_execution_slots<T: Clone>(
    length: usize,
    value: T,
    total_bytes: usize,
) -> Result<Box<[T]>, ReduceError> {
    let mut slots = Vec::new();
    slots
        .try_reserve_exact(length)
        .map_err(|_| ReduceError::AllocationFailed { bytes: total_bytes })?;
    slots.resize(length, value);
    if slots.capacity() != length {
        return Err(ReduceError::AllocationFailed {
            bytes: slots.capacity().saturating_mul(size_of::<T>()),
        });
    }
    Ok(slots.into_boxed_slice())
}

fn reserve_execution_trace(
    length: usize,
    total_bytes: usize,
) -> Result<Vec<PriorityMatch>, ReduceError> {
    let mut trace = Vec::new();
    trace
        .try_reserve_exact(length)
        .map_err(|_| ReduceError::AllocationFailed { bytes: total_bytes })?;
    if trace.capacity() != length {
        return Err(ReduceError::AllocationFailed {
            bytes: trace.capacity().saturating_mul(size_of::<PriorityMatch>()),
        });
    }
    Ok(trace)
}

fn execute_full_dfa<O: DirectReduceValue>(
    plan: &PreparedPriorityAutomaton<O>,
    full: &FullDfa,
    haystack: &[u8],
    limits: DirectReduceLimits,
    prospective: ExecutionProspective,
) -> Result<(O::Output, ExecutionActual), ReduceError> {
    let exact_bytes = plan
        .exact_match_bytes
        .ok_or(ReduceError::InternalInvariant {
            detail: "full DFA lost its exact match-length proof",
        })?;
    let mut meter = ExecutionMeter::new(limits.max_work);
    let mut actual = ExecutionActual::zero(haystack.len());
    actual.boundary_rows = prospective.boundary_rows;
    actual.dfa_states = full.subsets.len();
    actual.dfa_cells = full.transitions.len();
    actual.subset_items = prospective.subset_items_capacity;
    let mut output = O::zero();
    let mut state = 0u32;
    for (position, &byte) in haystack.iter().enumerate() {
        meter.charge(1)?;
        actual.dfa_transitions =
            actual
                .dfa_transitions
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "full DFA transitions",
                })?;
        let cell = plan_index(state)
            .checked_mul(BYTE_VALUES)
            .and_then(|base| base.checked_add(usize::from(byte)))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "full DFA transition index",
            })?;
        let transition = *full
            .transitions
            .get(cell)
            .ok_or(ReduceError::InternalInvariant {
                detail: "full DFA transition index exceeded its table",
            })?;
        if let Some(action) = transition.action {
            let end = position
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "full DFA match end",
                })?;
            let start = end
                .checked_sub(exact_bytes)
                .ok_or(ReduceError::InternalInvariant {
                    detail: "full DFA accepted before the exact match length",
                })?;
            meter.charge(1)?;
            record_match(
                &mut actual,
                AnchoredOutcome { end, action },
                start,
                limits.max_match_events,
            )?;
            output = O::append(output, start, end, action.ordinal())?;
            state = 0;
        } else {
            state = transition.next;
        }
    }
    meter.charge(1)?;
    actual.work = meter.consumed;
    Ok((output, actual))
}

struct LazyCache {
    state_offsets: Box<[usize]>,
    subset_items: Box<[u32]>,
    cells: Box<[LazyCell]>,
    temporary: Box<[u32]>,
    state_len: usize,
    item_len: usize,
    cell_len: usize,
    next_evict: usize,
}

impl LazyCache {
    fn new(
        automaton_states: usize,
        prospective: ExecutionProspective,
    ) -> Result<Self, ReduceError> {
        let mut state_offsets = allocate_execution_slots(
            prospective.dfa_states_capacity.checked_add(1).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "lazy DFA offset slots",
                },
            )?,
            0usize,
            prospective.scratch_bytes,
        )?;
        state_offsets[0] = 0;
        state_offsets[1] = 0;
        Ok(Self {
            state_offsets,
            subset_items: allocate_execution_slots(
                prospective.subset_items_capacity,
                0u32,
                prospective.scratch_bytes,
            )?,
            cells: allocate_execution_slots(
                prospective.dfa_cells_capacity,
                LazyCell::default(),
                prospective.scratch_bytes,
            )?,
            temporary: allocate_execution_slots(automaton_states, 0u32, prospective.scratch_bytes)?,
            state_len: 1,
            item_len: 0,
            cell_len: 0,
            next_evict: 0,
        })
    }
}

fn execute_lazy_dfa<O: DirectReduceValue>(
    plan: &PreparedPriorityAutomaton<O>,
    haystack: &[u8],
    limits: DirectReduceLimits,
    prospective: ExecutionProspective,
) -> Result<(O::Output, ExecutionActual), ReduceError> {
    let exact_bytes = plan
        .exact_match_bytes
        .ok_or(ReduceError::InternalInvariant {
            detail: "lazy DFA lost its exact match-length proof",
        })?;
    let setup_slots = prospective
        .dfa_states_capacity
        .checked_add(1)
        .and_then(|value| value.checked_add(prospective.subset_items_capacity))
        .and_then(|value| value.checked_add(prospective.dfa_cells_capacity))
        .and_then(|value| value.checked_add(plan.automaton.stats().states()))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "lazy DFA setup slots",
        })?;
    let mut meter = ExecutionMeter::new(limits.max_work);
    meter.charge(
        u64::try_from(setup_slots).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "lazy DFA setup work conversion",
        })?,
    )?;
    let mut cache = LazyCache::new(plan.automaton.stats().states(), prospective)?;
    let mut actual = ExecutionActual::zero(haystack.len());
    actual.boundary_rows = prospective.boundary_rows;
    let mut output = O::zero();
    let mut state = 0u32;
    for (position, &byte) in haystack.iter().enumerate() {
        let transition = lazy_transition(plan, &mut cache, state, byte, &mut meter, &mut actual)?;
        actual.dfa_transitions =
            actual
                .dfa_transitions
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "lazy DFA transitions",
                })?;
        if let Some(action) = transition.action {
            let end = position
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "lazy DFA match end",
                })?;
            let start = end
                .checked_sub(exact_bytes)
                .ok_or(ReduceError::InternalInvariant {
                    detail: "lazy DFA accepted before the exact match length",
                })?;
            meter.charge(1)?;
            record_match(
                &mut actual,
                AnchoredOutcome { end, action },
                start,
                limits.max_match_events,
            )?;
            output = O::append(output, start, end, action.ordinal())?;
            state = 0;
        } else {
            state = transition.next;
        }
    }
    meter.charge(1)?;
    actual.dfa_states = cache.state_len;
    actual.dfa_cells = cache.cell_len;
    actual.subset_items = cache.item_len;
    actual.work = meter.consumed;
    Ok((output, actual))
}

// One transition transaction keeps ordered subset construction, cache policy
// and exact counters inseparable.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn lazy_transition<O: DirectReduceValue>(
    plan: &PreparedPriorityAutomaton<O>,
    cache: &mut LazyCache,
    state: u32,
    byte: u8,
    meter: &mut ExecutionMeter,
    actual: &mut ExecutionActual,
) -> Result<DfaTransition, ReduceError> {
    for cell in &cache.cells[..cache.cell_len] {
        meter.charge(1)?;
        if cell.state == state && cell.byte == byte {
            actual.lazy_cache_hits =
                actual
                    .lazy_cache_hits
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "lazy DFA cache hits",
                    })?;
            return Ok(cell.transition);
        }
    }
    actual.lazy_cache_misses =
        actual
            .lazy_cache_misses
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "lazy DFA cache misses",
            })?;

    let state_index = plan_index(state);
    if state_index >= cache.state_len {
        return Err(ReduceError::InternalInvariant {
            detail: "lazy DFA referenced an unpublished state",
        });
    }
    let next_state_index = state_index
        .checked_add(1)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "lazy DFA state-offset successor",
        })?;
    let subset_start = cache.state_offsets[state_index];
    let subset_end = cache.state_offsets[next_state_index];
    let subset_len =
        subset_end
            .checked_sub(subset_start)
            .ok_or(ReduceError::InternalInvariant {
                detail: "lazy DFA state offsets decrease",
            })?;
    let mut temporary_len = 0usize;
    let mut action = None;
    let start_present = cache.subset_items[subset_start..subset_end]
        .iter()
        .any(|&member| {
            // Charged immediately below as a complete scan.
            member == plan.automaton.start
        });
    meter.charge(
        u64::try_from(subset_len).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "lazy DFA start dedup conversion",
        })?,
    )?;
    let candidate_count = subset_len.checked_add(usize::from(!start_present)).ok_or(
        ReduceError::ArithmeticOverflow {
            computation: "lazy DFA candidate count",
        },
    )?;
    for candidate_index in 0..candidate_count {
        let candidate = if candidate_index < subset_len {
            let item_index = subset_start.checked_add(candidate_index).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "lazy DFA candidate item index",
                },
            )?;
            cache.subset_items[item_index]
        } else {
            plan.automaton.start
        };
        meter.charge(1)?;
        let mut target = None;
        for edge in plan.automaton.state_edges(candidate) {
            meter.charge(1)?;
            if plan.automaton.byte_starts[edge] <= byte && byte <= plan.automaton.byte_ends[edge] {
                target = Some(plan.automaton.edge_targets[edge]);
                break;
            }
        }
        let Some(target) = target else {
            continue;
        };
        match plan.automaton.roles[plan_index(target)] {
            StateRole::Accept => {
                action = Some(plan.actions[plan_index(target)].ok_or(
                    ReduceError::InternalInvariant {
                        detail: "lazy DFA accept lost its action",
                    },
                )?);
                break;
            }
            StateRole::Consume => {
                let duplicate = cache.temporary[..temporary_len].contains(&target);
                meter.charge(u64::try_from(temporary_len).map_err(|_| {
                    ReduceError::ArithmeticOverflow {
                        computation: "lazy DFA dedup conversion",
                    }
                })?)?;
                if !duplicate {
                    let slot = cache.temporary.get_mut(temporary_len).ok_or(
                        ReduceError::InternalInvariant {
                            detail: "lazy DFA temporary subset exceeded automaton states",
                        },
                    )?;
                    *slot = target;
                    temporary_len =
                        temporary_len
                            .checked_add(1)
                            .ok_or(ReduceError::ArithmeticOverflow {
                                computation: "lazy DFA temporary subset length",
                            })?;
                }
            }
            StateRole::Split => {
                return Err(ReduceError::InternalInvariant {
                    detail: "lazy DFA encountered a refused split state",
                });
            }
        }
    }

    let next = if action.is_some() {
        0
    } else {
        intern_lazy_subset(cache, temporary_len, meter)?
    };
    let transition = DfaTransition { next, action };
    let cell_index = if cache.cell_len < cache.cells.len() {
        let index = cache.cell_len;
        cache.cell_len = cache
            .cell_len
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "lazy DFA cell count",
            })?;
        index
    } else {
        actual.lazy_cache_evictions =
            actual
                .lazy_cache_evictions
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "lazy DFA cache evictions",
                })?;
        let index = cache.next_evict;
        cache.next_evict = cache
            .next_evict
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "lazy DFA eviction cursor",
            })?
            .checked_rem(cache.cells.len())
            .ok_or(ReduceError::InternalInvariant {
                detail: "lazy DFA eviction requires a non-empty cell cache",
            })?;
        index
    };
    cache.cells[cell_index] = LazyCell {
        state,
        byte,
        transition,
    };
    actual.lazy_cache_inserts =
        actual
            .lazy_cache_inserts
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "lazy DFA cache inserts",
            })?;
    actual.dfa_cells = cache.cell_len;
    Ok(transition)
}

fn intern_lazy_subset(
    cache: &mut LazyCache,
    temporary_len: usize,
    meter: &mut ExecutionMeter,
) -> Result<u32, ReduceError> {
    let proposed = &cache.temporary[..temporary_len];
    for state in 0..cache.state_len {
        meter.charge(1)?;
        let start = cache.state_offsets[state];
        let next_state = state
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "lazy DFA comparison state successor",
            })?;
        let end = cache.state_offsets[next_state];
        let existing_len = end
            .checked_sub(start)
            .ok_or(ReduceError::InternalInvariant {
                detail: "lazy DFA comparison offsets decrease",
            })?;
        if existing_len == temporary_len {
            meter.charge(u64::try_from(temporary_len).map_err(|_| {
                ReduceError::ArithmeticOverflow {
                    computation: "lazy DFA subset comparison conversion",
                }
            })?)?;
            if cache.subset_items[start..end] == *proposed {
                return u32::try_from(state).map_err(|_| ReduceError::ArithmeticOverflow {
                    computation: "lazy DFA state conversion",
                });
            }
        }
    }

    let needed_states = cache
        .state_len
        .checked_add(1)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "lazy DFA state count",
        })?;
    if needed_states > cache.state_offsets.len().saturating_sub(1) {
        return Err(ReduceError::DfaStatesLimit {
            needed: needed_states,
            limit: cache.state_offsets.len().saturating_sub(1),
        });
    }
    let needed_items =
        cache
            .item_len
            .checked_add(temporary_len)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "lazy DFA subset items",
            })?;
    if needed_items > cache.subset_items.len() {
        return Err(ReduceError::SubsetItemsLimit {
            needed: needed_items,
            limit: cache.subset_items.len(),
        });
    }
    cache.subset_items[cache.item_len..needed_items].copy_from_slice(proposed);
    let state = cache.state_len;
    cache.state_offsets[state] = cache.item_len;
    let next_state = state
        .checked_add(1)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "lazy DFA publication state successor",
        })?;
    cache.state_offsets[next_state] = needed_items;
    cache.item_len = needed_items;
    cache.state_len = needed_states;
    u32::try_from(state).map_err(|_| ReduceError::ArithmeticOverflow {
        computation: "lazy DFA state conversion",
    })
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::{
        derive_match_length, ActionCapabilities, DirectCount, DirectReduceLimits, DirectTrace,
        EmptyMatchProgress, ExecutionProspective, ForcedExecution, MatchLengthProof, PatternAction,
        PatternOrdinal, PreparationError, PreparationLimits, PreparationMeter, PreparationResource,
        PriorityAutomataFacts, PriorityTarget, ReduceError,
    };
    use crate::{Automaton, CompileLimits, EdgeKind, RawPlan, StateRole};

    fn action(ordinal: u32) -> PatternAction {
        PatternAction::new(PatternOrdinal::new(ordinal), ActionCapabilities::all())
    }

    fn literal() -> PriorityAutomataFacts {
        let automaton = Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![StateRole::Consume, StateRole::Consume, StateRole::Accept],
                edge_offsets: vec![0, 1, 2, 2],
                edge_targets: vec![1, 2],
                edge_kinds: vec![EdgeKind::ByteRange; 2],
                byte_starts: vec![b'a', b'b'],
                byte_ends: vec![b'a', b'b'],
            },
            CompileLimits::default(),
        )
        .unwrap();
        PriorityAutomataFacts::new(
            automaton,
            vec![None, None, Some(action(0))],
            MatchLengthProof::Exact(2),
            EmptyMatchProgress::Byte,
        )
    }

    #[allow(clippy::arithmetic_side_effects)]
    fn exact_literal(bytes: &[u8]) -> PriorityAutomataFacts {
        let mut roles = vec![StateRole::Consume; bytes.len()];
        roles.push(StateRole::Accept);
        let mut edge_offsets = Vec::with_capacity(bytes.len() + 2);
        let mut edge_targets = Vec::with_capacity(bytes.len());
        edge_offsets.push(0);
        for index in 0..bytes.len() {
            edge_targets.push(u32::try_from(index + 1).unwrap());
            edge_offsets.push(u32::try_from(index + 1).unwrap());
        }
        edge_offsets.push(u32::try_from(bytes.len()).unwrap());
        let mut actions = vec![None; bytes.len()];
        actions.push(Some(action(0)));
        let automaton = Automaton::from_raw(
            RawPlan {
                start: 0,
                roles,
                edge_offsets,
                edge_targets,
                edge_kinds: vec![EdgeKind::ByteRange; bytes.len()],
                byte_starts: bytes.to_vec(),
                byte_ends: bytes.to_vec(),
            },
            CompileLimits::default(),
        )
        .unwrap();
        PriorityAutomataFacts::new(
            automaton,
            actions,
            MatchLengthProof::Exact(bytes.len()),
            EmptyMatchProgress::Byte,
        )
    }

    fn words(max_len: usize) -> Vec<Vec<u8>> {
        let mut words = vec![Vec::new()];
        let mut frontier = vec![Vec::new()];
        for _ in 0..max_len {
            let mut next = Vec::new();
            for prefix in frontier {
                for byte in [b'a', b'b'] {
                    let mut word = prefix.clone();
                    word.push(byte);
                    words.push(word.clone());
                    next.push(word);
                }
            }
            frontier = next;
        }
        words
    }

    fn long_first() -> PriorityAutomataFacts {
        let automaton = Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Accept,
                    StateRole::Consume,
                    StateRole::Accept,
                ],
                edge_offsets: vec![0, 2, 3, 4, 4, 5, 5],
                edge_targets: vec![1, 4, 2, 3, 5],
                edge_kinds: vec![
                    EdgeKind::Epsilon,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                ],
                byte_starts: vec![0, 0, b'a', b'b', b'a'],
                byte_ends: vec![0, 0, b'a', b'b', b'a'],
            },
            CompileLimits::default(),
        )
        .unwrap();
        PriorityAutomataFacts::new(
            automaton,
            vec![None, None, None, Some(action(0)), None, Some(action(0))],
            MatchLengthProof::Finite {
                minimum_bytes: 1,
                maximum_bytes: 2,
            },
            EmptyMatchProgress::Byte,
        )
    }

    fn consuming_and_empty(consuming_first: bool) -> PriorityAutomataFacts {
        let (root_targets, consume_ordinal, empty_ordinal) = if consuming_first {
            ([1, 3], 0, 1)
        } else {
            ([3, 1], 1, 0)
        };
        let automaton = Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Accept,
                    StateRole::Accept,
                ],
                edge_offsets: vec![0, 2, 3, 3, 3],
                edge_targets: vec![root_targets[0], root_targets[1], 2],
                edge_kinds: vec![EdgeKind::Epsilon, EdgeKind::Epsilon, EdgeKind::ByteRange],
                byte_starts: vec![0, 0, b'a'],
                byte_ends: vec![0, 0, b'a'],
            },
            CompileLimits::default(),
        )
        .unwrap();
        PriorityAutomataFacts::new(
            automaton,
            vec![
                None,
                None,
                Some(action(consume_ordinal)),
                Some(action(empty_ordinal)),
            ],
            MatchLengthProof::Finite {
                minimum_bytes: 0,
                maximum_bytes: 1,
            },
            EmptyMatchProgress::Byte,
        )
    }

    fn exact_execution_limits(prospective: ExecutionProspective) -> DirectReduceLimits {
        DirectReduceLimits {
            max_work: prospective.work_upper_bound,
            max_scratch_bytes: prospective.scratch_bytes,
            max_boundary_rows: prospective.boundary_rows,
            max_match_events: prospective.match_events_upper_bound,
            max_dfa_states: prospective.dfa_states_capacity,
            max_dfa_cells: prospective.dfa_cells_capacity,
            max_subset_items: prospective.subset_items_capacity,
            max_tagged_dispatch_states: prospective.tagged_dispatch_states_capacity,
            max_tagged_dispatch_cells: prospective.tagged_dispatch_cells_capacity,
            max_tagged_candidate_items: prospective.tagged_candidate_items_capacity,
            max_tagged_cache_cells: prospective.tagged_cache_cells_capacity,
            max_allocation_attempts: prospective.allocation_attempts,
        }
    }

    fn trace(
        source: PriorityAutomataFacts,
        route: ForcedExecution,
        haystack: &[u8],
    ) -> Vec<(u32, usize, usize)> {
        source
            .prepare_forced::<DirectTrace>(
                route,
                PriorityTarget::portable(),
                PreparationLimits::unlimited(),
            )
            .unwrap()
            .execute_forced(haystack, DirectReduceLimits::unlimited())
            .unwrap()
            .into_output()
    }

    #[allow(clippy::arithmetic_side_effects)]
    fn long_acyclic_branch(long_bytes: usize) -> Automaton {
        assert!(long_bytes > 0);
        let slow_first = 3usize;
        let slow_accept = slow_first + long_bytes;
        let states = slow_accept + 1;
        let mut roles = Vec::with_capacity(states);
        roles.extend([StateRole::Split, StateRole::Consume, StateRole::Accept]);
        roles.extend(core::iter::repeat(StateRole::Consume).take(long_bytes));
        roles.push(StateRole::Accept);

        let mut edge_offsets = Vec::with_capacity(states + 1);
        let mut edge_targets = Vec::with_capacity(long_bytes + 3);
        let mut edge_kinds = Vec::with_capacity(long_bytes + 3);
        let mut byte_starts = Vec::with_capacity(long_bytes + 3);
        let mut byte_ends = Vec::with_capacity(long_bytes + 3);
        edge_offsets.push(0);
        for state in 0..states {
            match state {
                0 => {
                    edge_targets.extend([1, u32::try_from(slow_first).unwrap()]);
                    edge_kinds.extend([EdgeKind::Epsilon, EdgeKind::Epsilon]);
                    byte_starts.extend([0, 0]);
                    byte_ends.extend([0, 0]);
                }
                1 => {
                    edge_targets.push(2);
                    edge_kinds.push(EdgeKind::ByteRange);
                    byte_starts.push(b'a');
                    byte_ends.push(b'a');
                }
                state if (slow_first..slow_accept).contains(&state) => {
                    edge_targets.push(u32::try_from(state + 1).unwrap());
                    edge_kinds.push(EdgeKind::ByteRange);
                    byte_starts.push(b'a');
                    byte_ends.push(b'a');
                }
                _ => {}
            }
            edge_offsets.push(u32::try_from(edge_targets.len()).unwrap());
        }
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles,
                edge_offsets,
                edge_targets,
                edge_kinds,
                byte_starts,
                byte_ends,
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    #[allow(clippy::arithmetic_side_effects)]
    fn zero_width_scc_then_literal(zero_width_states: usize) -> Automaton {
        assert!(zero_width_states >= 2);
        let consume = zero_width_states;
        let accept = consume + 1;
        let mut roles = vec![StateRole::Split; zero_width_states];
        roles.extend([StateRole::Consume, StateRole::Accept]);

        let mut edge_offsets = Vec::with_capacity(roles.len() + 1);
        let mut edge_targets = Vec::with_capacity(zero_width_states + 2);
        let mut edge_kinds = Vec::with_capacity(zero_width_states + 2);
        let mut byte_starts = Vec::with_capacity(zero_width_states + 2);
        let mut byte_ends = Vec::with_capacity(zero_width_states + 2);
        edge_offsets.push(0);
        for state in 0..roles.len() {
            match state {
                0 => {
                    edge_targets.extend([1, u32::try_from(consume).unwrap()]);
                    edge_kinds.extend([EdgeKind::Epsilon, EdgeKind::Epsilon]);
                    byte_starts.extend([0, 0]);
                    byte_ends.extend([0, 0]);
                }
                state if state < zero_width_states => {
                    let next = if state + 1 == zero_width_states {
                        0
                    } else {
                        state + 1
                    };
                    edge_targets.push(u32::try_from(next).unwrap());
                    edge_kinds.push(EdgeKind::Epsilon);
                    byte_starts.push(0);
                    byte_ends.push(0);
                }
                state if state == consume => {
                    edge_targets.push(u32::try_from(accept).unwrap());
                    edge_kinds.push(EdgeKind::ByteRange);
                    byte_starts.push(b'a');
                    byte_ends.push(b'a');
                }
                _ => {}
            }
            edge_offsets.push(u32::try_from(edge_targets.len()).unwrap());
        }
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles,
                edge_offsets,
                edge_targets,
                edge_kinds,
                byte_starts,
                byte_ends,
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn positive_consuming_cycle() -> Automaton {
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![StateRole::Split, StateRole::Consume, StateRole::Accept],
                edge_offsets: vec![0, 1, 3, 3],
                edge_targets: vec![1, 1, 2],
                edge_kinds: vec![EdgeKind::Epsilon, EdgeKind::ByteRange, EdgeKind::ByteRange],
                byte_starts: vec![0, b'a', b'b'],
                byte_ends: vec![0, b'a', b'b'],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    #[allow(clippy::arithmetic_side_effects)]
    fn assert_match_length_exact_ledgers(
        automaton: &Automaton,
        expected: MatchLengthProof,
    ) -> (u64, usize, usize) {
        let mut probe = PreparationMeter::new(u64::MAX, usize::MAX);
        let (proof, peak_bytes) =
            derive_match_length(automaton, &mut probe, 0, usize::MAX).unwrap();
        assert_eq!(proof, expected);
        let work = probe.consumed;
        let allocations = probe.allocations;
        assert!(work > 0);
        assert!(allocations > 0);
        assert!(peak_bytes > 0);

        let mut exact = PreparationMeter::new(work, allocations);
        assert_eq!(
            derive_match_length(automaton, &mut exact, 0, peak_bytes).unwrap(),
            (expected, peak_bytes)
        );
        assert_eq!((exact.consumed, exact.allocations), (work, allocations));

        let mut one_below_work = PreparationMeter::new(work - 1, allocations);
        assert!(matches!(
            derive_match_length(automaton, &mut one_below_work, 0, peak_bytes),
            Err(PreparationError::WorkLimit { needed, limit }) if needed == work && limit == work - 1
        ));
        let mut one_below_peak = PreparationMeter::new(work, allocations);
        assert!(matches!(
            derive_match_length(automaton, &mut one_below_peak, 0, peak_bytes - 1),
            Err(PreparationError::ResourceLimit {
                resource: PreparationResource::PeakBytes,
                needed,
                limit,
            }) if needed == peak_bytes && limit == peak_bytes - 1
        ));
        let mut one_below_allocations = PreparationMeter::new(work, allocations - 1);
        assert!(matches!(
            derive_match_length(automaton, &mut one_below_allocations, 0, peak_bytes),
            Err(PreparationError::ResourceLimit {
                resource: PreparationResource::AllocationAttempts,
                needed,
                limit,
            }) if needed == allocations && limit == allocations - 1
        ));
        (work, allocations, peak_bytes)
    }

    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn acyclic_match_length_uses_kahn_order_with_exact_one_below_ledgers() {
        const LONG_BYTES: usize = 4_096;
        let automaton = long_acyclic_branch(LONG_BYTES);
        let mut probe = PreparationMeter::new(u64::MAX, usize::MAX);
        let (proof, peak_bytes) =
            derive_match_length(&automaton, &mut probe, 0, usize::MAX).unwrap();
        assert_eq!(
            proof,
            MatchLengthProof::Finite {
                minimum_bytes: 1,
                maximum_bytes: LONG_BYTES,
            }
        );
        let work = probe.consumed;
        let allocations = probe.allocations;
        let state_count = u64::try_from(automaton.stats().states()).unwrap();
        assert!(
            work < state_count * 16,
            "acyclic Kahn analysis unexpectedly did more than linear work: {work} for {state_count} states"
        );

        let mut exact = PreparationMeter::new(work, allocations);
        assert_eq!(
            derive_match_length(&automaton, &mut exact, 0, peak_bytes).unwrap(),
            (proof, peak_bytes)
        );
        assert_eq!((exact.consumed, exact.allocations), (work, allocations));

        let mut one_below_work = PreparationMeter::new(work - 1, allocations);
        assert!(matches!(
            derive_match_length(&automaton, &mut one_below_work, 0, peak_bytes),
            Err(PreparationError::WorkLimit { needed, limit }) if needed == work && limit == work - 1
        ));
        let mut one_below_peak = PreparationMeter::new(work, allocations);
        assert!(matches!(
            derive_match_length(&automaton, &mut one_below_peak, 0, peak_bytes - 1),
            Err(PreparationError::ResourceLimit {
                resource: PreparationResource::PeakBytes,
                needed,
                limit,
            }) if needed == peak_bytes && limit == peak_bytes - 1
        ));
        let mut one_below_allocations = PreparationMeter::new(work, allocations - 1);
        assert!(matches!(
            derive_match_length(
                &automaton,
                &mut one_below_allocations,
                0,
                peak_bytes
            ),
            Err(PreparationError::ResourceLimit {
                resource: PreparationResource::AllocationAttempts,
                needed,
                limit,
            }) if needed == allocations && limit == allocations - 1
        ));
    }

    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn cyclic_zero_width_scc_is_linear_and_closes_exact_ledgers() {
        const ZERO_WIDTH_STATES: usize = 4_096;
        let automaton = zero_width_scc_then_literal(ZERO_WIDTH_STATES);
        let (work, _, _) =
            assert_match_length_exact_ledgers(&automaton, MatchLengthProof::Exact(1));
        let graph_size = u64::try_from(
            automaton
                .stats()
                .states()
                .checked_add(automaton.stats().edges())
                .unwrap(),
        )
        .unwrap();
        assert!(
            work < graph_size * 96,
            "cyclic zero-width analysis unexpectedly exceeded a linear work envelope: {work} for graph size {graph_size}"
        );
    }

    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn build_many_sparse_trace_preserves_priority_empty_suppression_and_exact_limits() {
        let plan = consuming_and_empty(true)
            .prepare_build_many_forced::<DirectCount>(
                ForcedExecution::Sparse,
                PriorityTarget::portable(),
                PreparationLimits::unlimited(),
            )
            .unwrap();
        let probe = plan
            .execute_forced_trace(b"a", DirectReduceLimits::unlimited())
            .unwrap();
        let base = probe.untraced_prospective();
        let traced = probe.report().prospective();
        assert!(probe.closes());
        assert_eq!(*probe.report().output(), 1);
        assert_eq!(
            probe
                .matches()
                .iter()
                .map(|selected| (selected.ordinal().get(), selected.start(), selected.end()))
                .collect::<Vec<_>>(),
            vec![(0, 0, 1)]
        );
        assert_eq!(
            plan.prospective(1, DirectReduceLimits::unlimited())
                .unwrap(),
            base
        );
        assert_eq!(
            traced.scratch_bytes,
            base.scratch_bytes + base.match_events_upper_bound * size_of::<super::PriorityMatch>()
        );
        assert_eq!(traced.allocation_attempts, base.allocation_attempts + 1);
        assert_eq!(
            traced.work_upper_bound,
            base.work_upper_bound
                + u64::try_from(base.boundary_rows + base.match_events_upper_bound + 1).unwrap()
        );
        assert_eq!(probe.report().actual().suffix_reducer_steps, 0);

        let exact = exact_execution_limits(traced);
        let exact_report = plan.execute_forced_trace(b"a", exact).unwrap();
        assert!(exact_report.closes());
        assert_eq!(exact_report.matches(), probe.matches());
        assert_eq!(exact_report.report().output(), probe.report().output());

        let below_work = DirectReduceLimits {
            max_work: exact.max_work - 1,
            ..exact
        };
        assert!(matches!(
            plan.execute_forced_trace(b"a", below_work),
            Err(ReduceError::WorkLimit {
                consumed: 0,
                requested,
                limit,
            }) if requested == exact.max_work && limit + 1 == exact.max_work
        ));
        let below_scratch = DirectReduceLimits {
            max_scratch_bytes: exact.max_scratch_bytes - 1,
            ..exact
        };
        assert!(matches!(
            plan.execute_forced_trace(b"a", below_scratch),
            Err(ReduceError::ScratchLimit { needed, limit })
                if needed == exact.max_scratch_bytes && limit + 1 == exact.max_scratch_bytes
        ));
        let below_allocations = DirectReduceLimits {
            max_allocation_attempts: exact.max_allocation_attempts - 1,
            ..exact
        };
        assert!(matches!(
            plan.execute_forced_trace(b"a", below_allocations),
            Err(ReduceError::AllocationAttemptsLimit { needed, limit })
                if needed == exact.max_allocation_attempts
                    && limit + 1 == exact.max_allocation_attempts
        ));

        let empty_first = consuming_and_empty(false)
            .prepare_build_many_forced::<DirectCount>(
                ForcedExecution::Sparse,
                PriorityTarget::portable(),
                PreparationLimits::unlimited(),
            )
            .unwrap()
            .execute_forced_trace(b"a", DirectReduceLimits::unlimited())
            .unwrap();
        assert!(empty_first.closes());
        assert_eq!(*empty_first.report().output(), 2);
        assert_eq!(
            empty_first
                .matches()
                .iter()
                .map(|selected| (selected.ordinal().get(), selected.start(), selected.end()))
                .collect::<Vec<_>>(),
            vec![(0, 0, 0), (0, 1, 1)]
        );
    }

    #[test]
    fn build_many_sparse_trace_uses_cyclic_reverse_rows_without_suffix_reduction() {
        let automaton = zero_width_scc_then_literal(2);
        let mut actions = vec![None; automaton.stats().states()];
        let last = actions.len() - 1;
        actions[last] = Some(action(0));
        let report = PriorityAutomataFacts::new(
            automaton,
            actions,
            MatchLengthProof::Exact(1),
            EmptyMatchProgress::Byte,
        )
        .prepare_build_many_forced::<DirectCount>(
            ForcedExecution::Sparse,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .unwrap()
        .execute_forced_trace(b"aaa", DirectReduceLimits::unlimited())
        .unwrap();
        assert!(report.closes());
        assert_eq!(*report.report().output(), 3);
        assert_eq!(report.report().actual().suffix_reducer_steps, 0);
        assert_eq!(
            report
                .matches()
                .iter()
                .map(|selected| (selected.ordinal().get(), selected.start(), selected.end()))
                .collect::<Vec<_>>(),
            vec![(0, 0, 1), (0, 1, 2), (0, 2, 3)]
        );
    }

    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn build_many_sparse_trace_charges_every_forward_boundary() {
        let plan = exact_literal(b"aaa")
            .prepare_build_many_forced::<DirectCount>(
                ForcedExecution::Sparse,
                PriorityTarget::portable(),
                PreparationLimits::unlimited(),
            )
            .unwrap();
        let haystack = b"aaaaaa";
        let ordinary = plan
            .execute_forced(haystack, DirectReduceLimits::unlimited())
            .unwrap();
        let traced = plan
            .execute_forced_trace(haystack, DirectReduceLimits::unlimited())
            .unwrap();
        assert!(traced.closes());
        assert_eq!(*ordinary.output(), 2);
        assert_eq!(*traced.report().output(), 2);
        let trace_delta = u64::try_from(traced.untraced_prospective().boundary_rows).unwrap()
            + u64::try_from(traced.matches().len()).unwrap()
            + 1;
        assert_eq!(
            traced.report().actual().work,
            ordinary.actual().work + trace_delta
        );
    }

    #[test]
    fn relevant_positive_consuming_cycle_is_unbounded_and_closes_exact_ledgers() {
        let automaton = positive_consuming_cycle();
        assert_match_length_exact_ledgers(&automaton, MatchLengthProof::Unbounded);
    }

    #[test]
    #[allow(clippy::arithmetic_side_effects)]
    fn test_only_sink_proves_complete_ordered_span_sequence_parity() {
        for pattern in words(3) {
            for haystack in words(5) {
                let expected = if pattern.is_empty() {
                    (0..=haystack.len())
                        .map(|position| (0, position, position))
                        .collect::<Vec<_>>()
                } else {
                    let mut expected = Vec::new();
                    let mut position = 0;
                    while position + pattern.len() <= haystack.len() {
                        if haystack[position..].starts_with(&pattern) {
                            expected.push((0, position, position + pattern.len()));
                            position += pattern.len();
                        } else {
                            position += 1;
                        }
                    }
                    expected
                };
                let routes: &[ForcedExecution] = if pattern.is_empty() {
                    &[ForcedExecution::Sparse, ForcedExecution::FiniteHorizon]
                } else {
                    &[
                        ForcedExecution::Sparse,
                        ForcedExecution::FiniteHorizon,
                        ForcedExecution::FullDfa,
                        ForcedExecution::LazyDfa,
                    ]
                };
                for &route in routes {
                    assert_eq!(
                        trace(exact_literal(&pattern), route, &haystack),
                        expected,
                        "{route:?}/{pattern:?}/{haystack:?}"
                    );
                }
            }
        }

        let literal_expected = vec![(0, 1, 3), (0, 3, 5), (0, 6, 8)];
        for route in [
            ForcedExecution::Sparse,
            ForcedExecution::FiniteHorizon,
            ForcedExecution::FullDfa,
            ForcedExecution::LazyDfa,
        ] {
            assert_eq!(
                trace(literal(), route, b"zababzab"),
                literal_expected,
                "{route:?}"
            );
        }

        let priority_expected = vec![(0, 0, 2), (0, 2, 4), (0, 4, 5)];
        for route in [ForcedExecution::Sparse, ForcedExecution::FiniteHorizon] {
            assert_eq!(
                trace(long_first(), route, b"ababa"),
                priority_expected,
                "{route:?}"
            );
        }
    }
}
