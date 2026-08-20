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
pub use error::{ErrorCategory, ParseAttemptError, ParseError, SourceSpan};
/// Direct, pinned RE2 syntax types retained by [`CanonicalPattern::Re2`].
pub use fre_re2_syntax as re2_syntax;
pub use parsed::{
    AdmissionStatus, CacheKey, CanonicalPattern, PARSE_ATTEMPT_ACCOUNTING_VERSION,
    PARSE_ATTEMPT_ALGORITHM_VERSION, ParseAttempt, ParseAttemptActual,
    ParseAttemptDeclaredFallback, ParseAttemptIdentity, ParseAttemptProspective,
    ParseAttemptReceipt, ParseAttemptTerminal, ParseRecord, ParseRequest, ParseSummary,
    PatternBytes, Re2Literal, Re2Parsed, RustAstRecord, RustParsed, SCHEMA_VERSION,
};
pub use profile::{
    CompatibilityProfile, InputKind, PackageIdentity, PackageVersion, Re2Encoding, Re2Options,
    Re2Profile, Re2Syntax, RustAstOptions, RustConstructor, RustMatchKind, RustOptions,
    RustProfile, RustUnicodeFeatures, UnicodeVersion, UpstreamRevision,
};
pub use re2::{Re2Capability, Re2CapabilityStatus, Re2Surface, re2_surface_inventory};

/// Parses one pattern under an immutable, versioned compatibility profile.
///
/// Rust profiles use the pinned `regex-syntax` parser. RE2 profiles use the
/// independent source-mapped parser in `fre-re2-syntax`; its remaining typed
/// incomplete surfaces and downstream FRE program-construction boundary stay
/// explicit. Exact RE2 `max_mem` threshold parity is not promised.
///
/// # Errors
///
/// Returns a canonical [`ParseError`] for pattern/configuration errors,
/// explicit quota exhaustion, strict-mode qualification failure, or a RE2
/// surface that has not yet been implemented and conformance-qualified.
pub fn parse(request: ParseRequest) -> Result<ParseRecord, ParseError> {
    if matches!(
        request.profile(),
        CompatibilityProfile::RustText(_) | CompatibilityProfile::RustBytes(_)
    ) {
        parse_attempt(request)
            .map(ParseAttempt::into_record)
            .map_err(ParseAttemptError::into_source)
    } else {
        request.validate_and_charge_source()?;
        re2::parse_re2(request)
    }
}

/// Parses one Rust pattern with a closed identity/P/A/terminal receipt.
///
/// The original owned [`ParseRequest`] moves directly into the successful
/// [`CacheKey`]. On error, the same request allocation is retained by
/// [`ParseAttemptError`]; pattern bytes are never cloned or reconstructed.
/// RE2 parsing remains available through [`parse`], while this
/// construction-transaction entry point fails before P for an RE2 profile.
///
/// # Errors
///
/// Returns a receipt-bearing terminal with the exact typed [`ParseError`],
/// exact original request, and cumulative actual counters through the last
/// admitted syntax effect.
#[allow(
    clippy::result_large_err,
    reason = "the exact owned request and receipt stay inline because boxing after a parser failure would add an unbudgeted allocation"
)]
pub fn parse_attempt(request: ParseRequest) -> Result<ParseAttempt, ParseAttemptError> {
    if matches!(request.profile(), CompatibilityProfile::Re2(_)) {
        let receipt = ParseAttemptReceipt::unsupported_profile(&request);
        let source = ParseError::new(
            request.profile().clone(),
            ErrorCategory::InvalidConfiguration,
            "receipt-bearing parse attempts require a Rust syntax profile",
        );
        return Err(ParseAttemptError::new(
            request,
            source,
            receipt,
            error::ParseAttemptFailurePhase::UnsupportedProfile,
        ));
    }

    let mut receipt = ParseAttemptReceipt::rust(&request);
    if let Err(source) = request.validate_and_charge_source() {
        return Err(ParseAttemptError::new(
            request,
            source,
            receipt,
            error::ParseAttemptFailurePhase::SourceAdmission,
        ));
    }
    receipt.actual.source_admission_checks = 1;

    let output = match rust::parse_rust_attempt(&request, &mut receipt.actual) {
        Ok(output) => output,
        Err(source) => {
            return Err(ParseAttemptError::new(
                request,
                source,
                receipt,
                error::ParseAttemptFailurePhase::RustPipeline,
            ));
        }
    };
    let (pattern, profile, admission, safety, attempt_source_owner) = request.into_parts();
    let record = ParseRecord {
        key: CacheKey {
            schema_version: SCHEMA_VERSION,
            pattern,
            profile,
            admission,
            safety,
            attempt_source_owner,
        },
        admission_status: output.admission_status,
        summary: output.summary,
        pattern: CanonicalPattern::Rust(RustParsed { hir: output.hir }),
    };
    Ok(ParseAttempt::new(record, receipt))
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
    parse_rust_ast_with_options(request, RustAstOptions::default())
}

/// Parses one Rust pattern with options exposed only by the pinned AST parser.
///
/// This is a source-addressable conformance boundary. AST-only options are
/// retained in [`RustAstRecord`] and never affect normal HIR parsing through
/// [`parse`].
///
/// # Errors
///
/// Returns the same errors as [`parse_rust_ast`].
#[doc(hidden)]
pub fn parse_rust_ast_with_options(
    request: ParseRequest,
    ast_options: RustAstOptions,
) -> Result<RustAstRecord, ParseError> {
    request.validate_and_charge_source()?;
    match request.profile() {
        CompatibilityProfile::RustText(_) | CompatibilityProfile::RustBytes(_) => {
            rust::parse_rust_ast(request, ast_options)
        }
        CompatibilityProfile::Re2(_) => Err(ParseError::new(
            request.profile().clone(),
            ErrorCategory::InvalidConfiguration,
            "Rust AST parsing requires a Rust profile",
        )),
    }
}
