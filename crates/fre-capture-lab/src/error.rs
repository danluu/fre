//! Typed admission and execution failures.

use core::fmt;

use crate::profile::CaptureProfile;

/// Independently limited resource dimensions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceKind {
    /// AST nodes admitted at compilation.
    AstNodes,
    /// AST nesting depth.
    AstDepth,
    /// User capture groups.
    Captures,
    /// Expansion of counted repetition.
    RepeatExpansion,
    /// Thompson instructions.
    States,
    /// Unresolved Thompson patch entries.
    PatchEntries,
    /// Metered compiler operations.
    CompileWork,
    /// Conservative immutable program bytes.
    ProgramBytes,
    /// State visits during one search.
    StateVisits,
    /// Capture-slot copies in the inline executor.
    SlotCopies,
    /// Persistent history nodes.
    HistoryNodes,
    /// Persistent history reconstruction steps.
    HistoryWalk,
    /// Conservative executor scratch bytes.
    ScratchBytes,
    /// Searches in an aggregate iteration.
    Searches,
    /// Results in an aggregate iteration.
    Results,
    /// Total state visits in aggregate iteration.
    AggregateStateVisits,
    /// Total capture-slot copies in aggregate iteration.
    AggregateSlotCopies,
    /// Total history nodes in aggregate iteration.
    AggregateHistoryNodes,
    /// Total persistent history reconstruction steps in aggregate iteration.
    AggregateHistoryWalk,
    /// Capture group entries inspected by an aggregate reducer.
    CaptureEvents,
    /// Participating capture groups accumulated by an aggregate reducer.
    CaptureCount,
}

/// A checked compiler admission failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuildError {
    /// A limit would be exceeded.
    Resource {
        /// Limited dimension.
        kind: ResourceKind,
        /// Required amount, when representable.
        required: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// Arithmetic required to prove a bound overflowed.
    BoundOverflow(ResourceKind),
    /// Heap reservation failed after resource admission.
    Allocation(ResourceKind),
    /// The AST violates the laboratory's structural contract.
    InvalidAst(&'static str),
    /// A typed semantic profile exists but has not passed its oracle gate.
    ProfilePending(CaptureProfile),
}

/// A checked execution refusal or fault.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SearchError {
    /// A limit would be exceeded.
    Resource {
        /// Limited dimension.
        kind: ResourceKind,
        /// Required amount, when representable.
        required: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// Arithmetic required to prove a bound overflowed.
    BoundOverflow(ResourceKind),
    /// Heap reservation failed after resource admission.
    Allocation(ResourceKind),
    /// The logical window is not contained in the haystack.
    InvalidWindow,
    /// A non-empty-only reducer selected an empty match.
    EmptyMatch,
    /// The immutable program failed an internal invariant check.
    InvalidProgram,
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "capture-lab build error: {self:?}")
    }
}

impl std::error::Error for BuildError {}

impl fmt::Display for SearchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "capture-lab search error: {self:?}")
    }
}

impl std::error::Error for SearchError {}
