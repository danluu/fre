use core::fmt;

use regex_syntax::hir::Look;

/// A semantic feature outside the exact production subset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Unsupported {
    /// Unicode scalar classes require a variable-width UTF-8 construction.
    UnicodeClass,
    /// Captures are not erased by this capture-free operation boundary.
    Capture,
    /// Unicode word assertion forms other than the positive boundary and
    /// CRLF-aware line assertions are not yet admitted by the continuation
    /// engine.
    Look(Look),
}

impl fmt::Display for Unsupported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnicodeClass => f.write_str("Unicode scalar class"),
            Self::Capture => f.write_str("capture annotation"),
            Self::Look(look) => write!(f, "look assertion {look:?}"),
        }
    }
}

/// A separately limited compiler or executor resource.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Resource {
    HirNodes,
    HirDepth,
    HirStackItems,
    LiteralBytes,
    ClassRanges,
    LookAssertions,
    RepeatBound,
    ProgramStates,
    TemporaryStates,
    ProgramBytes,
    CompileWork,
    Boundaries,
    TableCells,
    RandomAccessBytes,
    ScratchBytes,
    LogBytes,
    SequentialBytes,
    MatchEvents,
    OutputMatches,
    OutputBytes,
    SpanSum,
    PeakBytes,
    ExecutionWork,
}

/// Typed refusal from compilation or whole-operation admission.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    Unsupported(Unsupported),
    ResourceLimit {
        resource: Resource,
        required: usize,
        limit: usize,
    },
    ArithmeticOverflow {
        resource: Resource,
    },
    AllocationFailed {
        resource: Resource,
        items: usize,
    },
    InvalidRange {
        start: usize,
        end: usize,
        haystack_len: usize,
    },
    /// Exact Unicode word-boundary iteration over malformed UTF-8 is outside
    /// the continuation table's static assertion model.
    InvalidUtf8ForUnicodeWordBoundary,
    InvalidRepetition,
    EmptyAlternation,
    SameBoundaryCycle,
    InternalInvariant(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(feature) => write!(f, "unsupported aggregate feature: {feature}"),
            Self::ResourceLimit {
                resource,
                required,
                limit,
            } => write!(
                f,
                "aggregate resource {resource:?} requires {required}, limit is {limit}"
            ),
            Self::ArithmeticOverflow { resource } => {
                write!(f, "arithmetic overflow for aggregate resource {resource:?}")
            }
            Self::AllocationFailed { resource, items } => write!(
                f,
                "allocator refused {items} items for aggregate resource {resource:?}"
            ),
            Self::InvalidRange {
                start,
                end,
                haystack_len,
            } => write!(
                f,
                "invalid operation range {start}..{end} for haystack length {haystack_len}"
            ),
            Self::InvalidUtf8ForUnicodeWordBoundary => {
                f.write_str("Unicode word boundary requires valid UTF-8 input")
            }
            Self::InvalidRepetition => f.write_str("invalid repetition bounds"),
            Self::EmptyAlternation => f.write_str("empty alternation"),
            Self::SameBoundaryCycle => f.write_str("compiled program has a same-boundary cycle"),
            Self::InternalInvariant(detail) => {
                write!(f, "aggregate internal invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for Error {}

pub(crate) fn add(left: usize, right: usize, resource: Resource) -> Result<usize, Error> {
    left.checked_add(right)
        .ok_or(Error::ArithmeticOverflow { resource })
}

pub(crate) fn mul(left: usize, right: usize, resource: Resource) -> Result<usize, Error> {
    left.checked_mul(right)
        .ok_or(Error::ArithmeticOverflow { resource })
}

pub(crate) fn enforce(required: usize, limit: usize, resource: Resource) -> Result<(), Error> {
    if required > limit {
        return Err(Error::ResourceLimit {
            resource,
            required,
            limit,
        });
    }
    Ok(())
}
