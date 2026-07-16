use core::fmt;

use crate::{CompatibilityProfile, Re2Surface, ResourceKind};

/// Half-open byte offsets into the original pattern.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SourceSpan {
    pub start: u64,
    pub end: u64,
}

/// Stable top-level error categories. Upstream diagnostic text is preserved in
/// [`ParseError::message`] but is not parsed to infer a fake exact category.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ErrorCategory {
    InvalidPatternEncoding,
    UpstreamRustSyntax,
    UpstreamRustCompiledTooBig {
        limit: u64,
    },
    Re2Syntax {
        /// Numeric `RE2::ErrorCode` at the pinned revision.
        code: u8,
        /// Exact public `error_arg()` bytes.
        argument_bytes: Vec<u8>,
    },
    FreResourceLimit {
        resource: ResourceKind,
        limit: u64,
        observed: u64,
    },
    StrictQualificationFailure {
        resource: ResourceKind,
        limit: u64,
        observed: u64,
    },
    UnsupportedNotYetImplemented {
        surface: Re2Surface,
    },
    InvalidConfiguration,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ParseError {
    pub schema_version: u32,
    pub profile: Box<CompatibilityProfile>,
    pub category: ErrorCategory,
    pub span: Option<SourceSpan>,
    pub message: String,
}

impl ParseError {
    pub(crate) fn new(
        profile: CompatibilityProfile,
        category: ErrorCategory,
        message: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: crate::SCHEMA_VERSION,
            profile: Box::new(profile),
            category,
            span: None,
            message: message.into(),
        }
    }

    pub(crate) fn with_span(mut self, span: SourceSpan) -> Self {
        self.span = Some(span);
        self
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.category, self.message)
    }
}

impl std::error::Error for ParseError {}

/// Failure from the pinned Rust `RegexSetBuilder` construction boundary.
///
/// Syntax failures retain the exact source-order pattern index. Aggregate NFA
/// size-limit failures have no pattern index, matching `regex` 1.12.4.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RustRegexSetAdmissionError {
    pub pattern: Option<usize>,
    pub source: ParseError,
}

impl fmt::Display for RustRegexSetAdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(pattern) = self.pattern {
            write!(
                f,
                "Rust regex set pattern {pattern} failed: {}",
                self.source
            )
        } else {
            write!(f, "Rust regex set admission failed: {}", self.source)
        }
    }
}

impl std::error::Error for RustRegexSetAdmissionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}
