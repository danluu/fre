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
pub use error::{ErrorCategory, ParseError, SourceSpan};
/// Direct, pinned RE2 syntax types retained by [`CanonicalPattern::Re2`].
pub use fre_re2_syntax as re2_syntax;
pub use parsed::{
    AdmissionStatus, CacheKey, CanonicalPattern, ParseRecord, ParseRequest, ParseSummary,
    PatternBytes, Re2Literal, Re2Parsed, RustParsed, SCHEMA_VERSION,
};
pub use profile::{
    CompatibilityProfile, InputKind, Re2Encoding, Re2Options, Re2Profile, Re2Syntax, RustOptions,
    RustProfile, UnicodeVersion, UpstreamRevision,
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
            rust::parse_rust(request)
        }
        CompatibilityProfile::Re2(_) => re2::parse_re2(request),
    }
}
