//! Compatibility-profile and syntax boundary for FRE.
//!
//! This crate deliberately does not contain automata construction or matching.
//! It freezes every syntax-affecting input before lowering and ensures that
//! syntax traversal is bounded and iterative.

#![forbid(unsafe_code)]

mod admission;
mod error;
mod parsed;
mod profile;
mod re2;
mod rust;

pub use admission::{
    AdmissionPolicy, QuotaBounded, ResourceKind, SafetyEnvelope, StrictAdmission, SyntaxQuotas,
};
pub use error::{ErrorCategory, ParseError, RustRegexSetAdmissionError, SourceSpan};
/// Direct, pinned RE2 syntax types retained by [`CanonicalPattern::Re2`].
pub use fre_re2_syntax as re2_syntax;
pub use parsed::{
    AdmissionStatus, CacheKey, CanonicalPattern, ParseRecord, ParseRequest, ParseSummary,
    PatternBytes, Re2Literal, Re2Parsed, RustAstRecord, RustParsed, SCHEMA_VERSION,
};
pub use profile::{
    CompatibilityProfile, InputKind, PackageIdentity, PackageVersion, Re2Encoding, Re2Options,
    Re2Profile, Re2Syntax, RustConstructor, RustMatchKind, RustOptions, RustProfile,
    RustUnicodeFeatures, UnicodeVersion, UpstreamRevision,
};
pub use re2::{Re2Capability, Re2CapabilityStatus, Re2Surface, re2_surface_inventory};

/// Parses one pattern under an immutable, versioned compatibility profile.
///
/// Rust profiles use the pinned `regex-syntax` parser. RE2 profiles use the
/// independent source-mapped parser in `fre-re2-syntax`; its remaining typed
/// incomplete surfaces and constructor-admission boundary stay explicit.
///
/// # Errors
///
/// Returns a canonical [`ParseError`] for pattern/configuration errors,
/// explicit quota exhaustion, strict-mode qualification failure, or a RE2
/// surface that has not yet been implemented and conformance-qualified.
pub fn parse(request: ParseRequest) -> Result<ParseRecord, ParseError> {
    request.validate_and_charge_source()?;
    match request.profile() {
        CompatibilityProfile::RustText(_) | CompatibilityProfile::RustBytes(_) => {
            rust::parse_rust(request, true)
        }
        CompatibilityProfile::Re2(_) => re2::parse_re2(request),
    }
}

/// Parses one Rust pattern into the exact pinned `regex-syntax` 0.8.11 AST.
///
/// This source-addressable conformance boundary prospectively reserves
/// conservative byte-derived bounds for every parser allocation/work
/// dimension before invoking the upstream parser. Normal FRE compilation
/// should use [`parse`], which additionally lowers to HIR.
///
/// # Errors
///
/// Returns a canonical [`ParseError`] for an invalid profile or pattern, or
/// when any prospective parser reservation exceeds the selected quota/safety
/// envelope.
#[doc(hidden)]
pub fn parse_rust_ast(request: ParseRequest) -> Result<RustAstRecord, ParseError> {
    request.validate_and_charge_source()?;
    match request.profile() {
        CompatibilityProfile::RustText(_) | CompatibilityProfile::RustBytes(_) => {
            rust::parse_rust_ast(request)
        }
        CompatibilityProfile::Re2(_) => Err(ParseError::new(
            request.profile().clone(),
            ErrorCategory::InvalidConfiguration,
            "Rust AST parsing requires a Rust profile",
        )),
    }
}

/// Applies the exact pinned `regex` 1.12.4 aggregate constructor admission to
/// a complete source-ordered set.
///
/// Unlike independent single-pattern construction, this uses one
/// `MatchKind::All`, capture-free Thompson NFA and one compiled-size limit for
/// all patterns. Syntax failures retain their source-order pattern index;
/// compiled-size failures are aggregate and therefore unindexed.
///
/// # Errors
///
/// Returns [`RustRegexSetAdmissionError`] for an invalid profile, the first
/// syntax-invalid pattern in pinned upstream order, or an aggregate compiled
/// NFA that exceeds the configured high-level size limit.
pub fn validate_rust_regex_set_admission<P: AsRef<str>>(
    patterns: &[P],
    profile: &CompatibilityProfile,
) -> Result<(), RustRegexSetAdmissionError> {
    rust::validate_regex_set_admission(patterns, profile)
}

/// Parses one constituent after its exact complete set has already passed
/// [`validate_rust_regex_set_admission`].
///
/// This entry point deliberately skips only the *single-regex* compiled-size
/// check. A set caller must not substitute that capture-bearing check for the
/// capture-free aggregate check. Source quotas, pinned profile validation,
/// syntax parsing and every FRE admission bound remain enforced.
#[doc(hidden)]
pub fn parse_rust_regex_set_constituent(request: ParseRequest) -> Result<ParseRecord, ParseError> {
    request.validate_and_charge_source()?;
    match request.profile() {
        CompatibilityProfile::RustText(_) | CompatibilityProfile::RustBytes(_) => {
            rust::parse_rust(request, false)
        }
        CompatibilityProfile::Re2(_) => Err(ParseError::new(
            request.profile().clone(),
            ErrorCategory::InvalidConfiguration,
            "Rust regex set constituent parsing requires a Rust profile",
        )),
    }
}
