use core::fmt;

use crate::{
    CompatibilityProfile, ParseAttemptActual, ParseAttemptReceipt, ParseAttemptTerminal,
    ParseRequest, Re2Surface, ResourceKind, SCHEMA_VERSION,
};

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
    /// Legacy exact-upstream compiled-size diagnostic.
    ///
    /// Native-size admission no longer emits this category. It remains in the
    /// public enum so callers compiled against the earlier schema can continue
    /// to name and deserialize the variant while migrating to FRE resource
    /// limits.
    #[deprecated(
        since = "0.1.0",
        note = "FRE size_limit now reports native representation limits"
    )]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ParseAttemptFailurePhase {
    UnsupportedProfile,
    SourceAdmission,
    RustPipeline,
}

/// Terminal receipt-bearing Rust syntax failure.
///
/// The exact original request is retained inline and is never reconstructed
/// from a digest or cloned after the underlying failure. The source, request,
/// and receipt fields are private so a caller cannot splice a different
/// terminal into an otherwise valid receipt.
#[derive(Debug)]
pub struct ParseAttemptError {
    source: ParseError,
    request: ParseRequest,
    receipt: ParseAttemptReceipt,
    phase: ParseAttemptFailurePhase,
}

impl ParseAttemptError {
    pub(crate) fn new(
        request: ParseRequest,
        source: ParseError,
        receipt: ParseAttemptReceipt,
        phase: ParseAttemptFailurePhase,
    ) -> Self {
        Self {
            source,
            request,
            receipt,
            phase,
        }
    }

    /// Exact original owned request, including the sole retained pattern
    /// allocation.
    #[must_use]
    pub const fn request(&self) -> &ParseRequest {
        &self.request
    }

    /// Typed syntax/configuration/resource terminal.
    #[must_use]
    pub const fn source(&self) -> &ParseError {
        &self.source
    }

    /// Identity/P/cumulative-A/terminal receipt at failure.
    #[must_use]
    pub const fn receipt(&self) -> &ParseAttemptReceipt {
        &self.receipt
    }

    /// Consume the wrapper without cloning the underlying diagnostic.
    #[must_use]
    pub fn into_source(self) -> ParseError {
        self.source
    }

    /// Consume every exact terminal component without allocating or copying
    /// pattern bytes.
    #[must_use]
    pub fn into_parts(self) -> (ParseRequest, ParseError, ParseAttemptReceipt) {
        (self.request, self.source, self.receipt)
    }

    /// Authenticate the private source/request pairing and its terminal phase.
    #[must_use]
    pub fn closes(&self) -> bool {
        if self.receipt.terminal != ParseAttemptTerminal::Failure
            || !self.receipt.authenticates_request(&self.request)
            || self.source.schema_version != SCHEMA_VERSION
            || self.source.profile.as_ref() != self.request.profile()
        {
            return false;
        }
        let actual = self.receipt.actual;
        match self.phase {
            ParseAttemptFailurePhase::UnsupportedProfile => {
                self.receipt.prospective.is_none()
                    && actual == ParseAttemptActual::default()
                    && matches!(self.request.profile(), CompatibilityProfile::Re2(_))
                    && matches!(self.source.category, ErrorCategory::InvalidConfiguration)
            }
            ParseAttemptFailurePhase::SourceAdmission => {
                self.receipt.prospective.is_some()
                    && actual == ParseAttemptActual::default()
                    && matches!(
                        self.source.category,
                        ErrorCategory::FreResourceLimit {
                            resource: ResourceKind::PatternBytes | ResourceKind::ParseWork,
                            ..
                        } | ErrorCategory::StrictQualificationFailure {
                            resource: ResourceKind::PatternBytes | ResourceKind::ParseWork,
                            ..
                        }
                    )
            }
            ParseAttemptFailurePhase::RustPipeline => {
                self.receipt.prospective.is_some()
                    && actual.source_admission_checks == 1
                    && if actual.configuration_checks == 0 {
                        actual.opaque_parser_invocations == 0
                            && actual.observed_work == 0
                            && matches!(self.source.category, ErrorCategory::InvalidConfiguration)
                    } else {
                        actual.configuration_checks == 1 && actual.opaque_parser_invocations >= 1
                    }
            }
        }
    }
}

impl fmt::Display for ParseAttemptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.source, formatter)
    }
}

impl std::error::Error for ParseAttemptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Legacy result wrapper for Rust regex-set admission.
///
/// The compatibility shim now checks local syntax/configuration in source
/// order. Native aggregate representation limits are enforced by the FRE set
/// builder that owns the selected artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RustRegexSetAdmissionError {
    pub pattern: Option<usize>,
    pub source: ParseError,
}

#[allow(deprecated)]
impl fmt::Display for RustRegexSetAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(pattern) = self.pattern {
            write!(
                formatter,
                "Rust regex set pattern {pattern} failed local admission: {}",
                self.source
            )
        } else {
            write!(
                formatter,
                "Rust regex set local admission failed: {}",
                self.source
            )
        }
    }
}

#[allow(deprecated)]
impl std::error::Error for RustRegexSetAdmissionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}
