//! Checked validation and execution errors.

use core::fmt;

/// A resource whose checked limit was exceeded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceKind {
    /// AST nodes.
    AstNodes,
    /// AST nesting depth.
    AstDepth,
    /// Compiled program states.
    ProgramStates,
    /// A finite or minimum repetition bound.
    RepeatBound,
    /// Number of independent progress guards.
    GuardCount,
    /// Guarded recurrence configurations.
    GuardedConfigurations,
    /// Guarded recurrence memo and explicit work-stack bytes.
    GuardedBytes,
    /// Addressable input boundaries.
    Boundaries,
    /// Full dynamic-programming cells.
    TableCells,
    /// Packed decision-log bytes.
    LogBytes,
    /// Instrumented semantic work units.
    Work,
    /// Returned match count.
    OutputMatches,
    /// A byte-size calculation.
    Bytes,
    /// Random-access executor scratch bytes.
    RandomAccessBytes,
    /// Resident word-rounded decision-log bytes.
    ResidentLogBytes,
    /// Pre-reserved returned-span bytes.
    OutputBytes,
}

/// Validation, resource or internal-consistency failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Alternation requires at least one branch.
    EmptyAlternation,
    /// A repetition body requires at least one ordered atom.
    EmptyRepeatBody,
    /// A repetition maximum was below its minimum.
    InvalidRepeatRange,
    /// A checked resource limit was exceeded.
    ResourceLimit {
        /// Limited resource.
        kind: ResourceKind,
        /// Required amount, saturated only when arithmetic itself overflowed.
        required: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// The compiler produced an unexpected same-boundary cycle.
    SameBoundaryCycle,
    /// A candidate's recorded successful path could not be replayed.
    InvalidDecisionLog,
    /// The host allocator rejected a preflighted reservation.
    AllocationFailed {
        /// Buffer whose reservation failed.
        kind: ResourceKind,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyAlternation => f.write_str("empty alternation"),
            Self::EmptyRepeatBody => f.write_str("empty repetition body"),
            Self::InvalidRepeatRange => f.write_str("repetition maximum is below minimum"),
            Self::ResourceLimit {
                kind,
                required,
                limit,
            } => write!(
                f,
                "resource limit for {kind:?}: required {required}, limit {limit}"
            ),
            Self::SameBoundaryCycle => f.write_str("same-boundary program cycle"),
            Self::InvalidDecisionLog => f.write_str("invalid decision log"),
            Self::AllocationFailed { kind } => {
                write!(f, "allocator rejected reservation for {kind:?}")
            }
        }
    }
}

impl std::error::Error for Error {}
