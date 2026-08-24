use core::fmt;

/// Bounded compiler resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompileResource {
    DfaStates,
    DfaTransitions,
    ProgramBytes,
    CodeBytes,
    ObjectBytes,
    Work,
}

/// Deterministic object-production failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObjectError {
    UnsupportedTarget,
    ArithmeticOverflow(&'static str),
    InvalidModule(&'static str),
    /// Fallible compiler scratch or artifact allocation was refused.
    ///
    /// This is distinct from a malformed module so optional optimizing
    /// candidates can decline memory pressure without hiding structural
    /// compiler failures.
    Allocation(&'static str),
    Resource {
        resource: CompileResource,
        limit: usize,
        required: usize,
    },
}

impl fmt::Display for ObjectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedTarget => formatter.write_str("unsupported AOT object target"),
            Self::ArithmeticOverflow(site) => {
                write!(formatter, "object arithmetic overflow at {site}")
            }
            Self::InvalidModule(detail) => write!(formatter, "invalid compiled module: {detail}"),
            Self::Allocation(site) => write!(formatter, "object allocation failed at {site}"),
            Self::Resource {
                resource,
                limit,
                required,
            } => write!(
                formatter,
                "object resource {resource:?} requires {required}, limit is {limit}"
            ),
        }
    }
}

impl std::error::Error for ObjectError {}

/// General compiler failure.
#[derive(Debug)]
pub enum CompileError {
    Syntax(fre_syntax::ParseError),
    Lower(fre_lower::LowerError),
    Automaton(fre_automata::CompileError),
    Search(fre_automata::SearchError),
    Object(ObjectError),
    Resource {
        resource: CompileResource,
        limit: usize,
        required: usize,
    },
    StateExplosion {
        limit: usize,
        discovered: usize,
    },
    InvalidWindow {
        start: usize,
        end: usize,
        haystack_len: usize,
    },
    PreparedAggregateRequiresSpan {
        actual: crate::OutputContract,
    },
    PreparedScalarOperationRequiresSingleExport {
        actual: crate::PreparedAggregateExports,
    },
    InternalInvariant(&'static str),
}

impl fmt::Display for CompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(error) => write!(formatter, "syntax error: {error}"),
            Self::Lower(error) => write!(formatter, "lowering error: {error}"),
            Self::Automaton(error) => write!(formatter, "automaton error: {error}"),
            Self::Search(error) => write!(formatter, "portable search error: {error}"),
            Self::Object(error) => write!(formatter, "object error: {error}"),
            Self::Resource {
                resource,
                limit,
                required,
            } => write!(
                formatter,
                "compiler resource {resource:?} requires {required}, limit is {limit}"
            ),
            Self::StateExplosion { limit, discovered } => write!(
                formatter,
                "ordered determinization discovered {discovered} states, limit is {limit}"
            ),
            Self::InvalidWindow {
                start,
                end,
                haystack_len,
            } => write!(
                formatter,
                "invalid search window {start}..{end} for haystack length {haystack_len}"
            ),
            Self::PreparedAggregateRequiresSpan { actual } => write!(
                formatter,
                "prepared Count/SpanSum exports require Span output, got {actual:?}"
            ),
            Self::PreparedScalarOperationRequiresSingleExport { actual } => write!(
                formatter,
                "prepared scalar operation requires exactly one Count, SpanSum, or GrepCount export, got {actual:?}"
            ),
            Self::InternalInvariant(detail) => {
                write!(formatter, "compiler internal invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for CompileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Syntax(error) => Some(error),
            Self::Lower(error) => Some(error),
            Self::Automaton(error) => Some(error),
            Self::Search(error) => Some(error),
            Self::Object(error) => Some(error),
            Self::Resource { .. }
            | Self::StateExplosion { .. }
            | Self::InvalidWindow { .. }
            | Self::PreparedAggregateRequiresSpan { .. }
            | Self::PreparedScalarOperationRequiresSingleExport { .. }
            | Self::InternalInvariant(_) => None,
        }
    }
}

/// Failure from the opt-in independent Exists-batch compiler API.
#[derive(Debug)]
#[non_exhaustive]
pub enum IndependentExistsBatchCompileError {
    RequiresExists {
        actual: crate::OutputContract,
    },
    Compile(CompileError),
}

impl fmt::Display for IndependentExistsBatchCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequiresExists { actual } => write!(
                formatter,
                "independent Exists-batch export requires Exists output, got {actual:?}"
            ),
            Self::Compile(error) => fmt::Display::fmt(error, formatter),
        }
    }
}

impl std::error::Error for IndependentExistsBatchCompileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RequiresExists { .. } => None,
            Self::Compile(error) => Some(error),
        }
    }
}

impl From<CompileError> for IndependentExistsBatchCompileError {
    fn from(value: CompileError) -> Self {
        Self::Compile(value)
    }
}

impl From<fre_syntax::ParseError> for CompileError {
    fn from(value: fre_syntax::ParseError) -> Self {
        Self::Syntax(value)
    }
}

impl From<fre_lower::LowerError> for CompileError {
    fn from(value: fre_lower::LowerError) -> Self {
        Self::Lower(value)
    }
}

impl From<fre_automata::CompileError> for CompileError {
    fn from(value: fre_automata::CompileError) -> Self {
        Self::Automaton(value)
    }
}

impl From<fre_automata::SearchError> for CompileError {
    fn from(value: fre_automata::SearchError) -> Self {
        Self::Search(value)
    }
}

impl From<ObjectError> for CompileError {
    fn from(value: ObjectError) -> Self {
        Self::Object(value)
    }
}
