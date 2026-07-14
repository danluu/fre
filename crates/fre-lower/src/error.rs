use core::fmt;

use fre_automata::CompileError;
use regex_syntax::hir::Look;

/// A lowering-specific bounded resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LowerResource {
    Work,
    StackItems,
    States,
    Edges,
    StorageBytes,
    ValidationWork,
}

impl fmt::Display for LowerResource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Work => "lowering work",
            Self::StackItems => "explicit stack items",
            Self::States => "automaton states",
            Self::Edges => "automaton edges",
            Self::StorageBytes => "automaton storage bytes",
            Self::ValidationWork => "automaton validation work",
        })
    }
}

/// A semantic feature for which this lowering stage has no exact certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum UnsupportedFeature {
    /// A Unicode scalar class requires a variable-width UTF-8 lowering.
    UnicodeClass,
    /// Only whole-haystack start and end assertions are currently represented.
    LookAssertion(Look),
    /// K0 has no capture-preserving output path yet.
    CaptureSensitiveOperation,
    /// K0 only certifies unbounded loops with a positive minimum body length.
    UncertifiedUnboundedRepetition,
}

impl fmt::Display for UnsupportedFeature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnicodeClass => f.write_str(
                "Unicode scalar class (variable-width UTF-8 lowering is not implemented)",
            ),
            Self::LookAssertion(look) => {
                write!(
                    f,
                    "look assertion {look:?} (only Start and End are implemented)"
                )
            }
            Self::CaptureSensitiveOperation => {
                f.write_str("capture-sensitive operation (capture preservation is not implemented)")
            }
            Self::UncertifiedUnboundedRepetition => f.write_str(
                "unbounded repetition whose body lacks a certified positive minimum byte length",
            ),
        }
    }
}

/// A checked lowering failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum LowerError {
    Unsupported(UnsupportedFeature),
    ResourceLimit {
        resource: LowerResource,
        needed: u64,
        limit: u64,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    AllocationFailed {
        structure: &'static str,
        additional: usize,
    },
    InternalInvariant {
        detail: &'static str,
    },
    Automata(CompileError),
}

impl fmt::Display for LowerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(feature) => write!(f, "unsupported lowering feature: {feature}"),
            Self::ResourceLimit {
                resource,
                needed,
                limit,
            } => write!(
                f,
                "lowering needs {needed} {resource}, exceeding limit {limit}"
            ),
            Self::ArithmeticOverflow { computation } => {
                write!(f, "arithmetic overflow while computing {computation}")
            }
            Self::AllocationFailed {
                structure,
                additional,
            } => write!(
                f,
                "failed to reserve {additional} additional items for {structure}"
            ),
            Self::InternalInvariant { detail } => {
                write!(f, "lowering internal invariant failed: {detail}")
            }
            Self::Automata(error) => write!(f, "emitted automaton was rejected: {error}"),
        }
    }
}

impl std::error::Error for LowerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Automata(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CompileError> for LowerError {
    fn from(value: CompileError) -> Self {
        Self::Automata(value)
    }
}
