//! Authenticated, read-only handoff from the portable exact-literal plan.
//!
//! This module does not compile, publish, or execute native code. It exposes
//! only an opaque borrow proving that the original source, complete Rust-byte
//! profile, selected report, and live retained literal still describe the
//! same exact-literal search plan.

use core::fmt;

use fre_syntax::{
    AdmissionStatus, CompatibilityProfile, PackageIdentity, RustConstructor, RustMatchKind,
    RustProfile, RustUnicodeFeatures, UnicodeVersion, UpstreamRevision,
};
use sha2::{Digest, Sha256};

use crate::{
    BuildLimits, BuildReport, PlanKind, PlanSelection, PortablePlan, PortableRegex,
    default_portable_build_limits,
};

/// Stable schema for the facade-owned exact-literal Search AOT binding.
pub const SEARCH_EXACT_LITERAL_AOT_SEMANTIC_BINDING_SCHEMA_VERSION: u32 = 2;
/// Fixed facade construction policy admitted by the V1 Search AOT handoff.
pub const SEARCH_EXACT_LITERAL_AOT_FIXED_BUILD_POLICY_VERSION: u32 = 1;

const BINDING_DOMAIN: &[u8] = b"fre.search.exact-literal-aot-semantic-binding.v2\0";

/// Canonical semantic identity of one facade-selected exact-literal plan.
///
/// The identity binds the original pattern source, live literal bytes,
/// complete Rust-byte profile, the fixed default construction policy,
/// automatic plan selection, and every public exact-plan build-report field.
/// It does not authorize a target, backend, object format, linker, or runtime;
/// those belong to a separate compiler manifest and receipt.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SearchExactLiteralAotSemanticBindingIdentity([u8; 32]);

impl SearchExactLiteralAotSemanticBindingIdentity {
    /// Canonical SHA-256 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SearchExactLiteralAotSemanticBindingIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "SearchExactLiteralAotSemanticBindingIdentity({self})"
        )
    }
}

impl fmt::Display for SearchExactLiteralAotSemanticBindingIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Opaque compiler input borrowed from the live portable exact-literal plan.
///
/// Private fields prevent callers from pairing arbitrary literal bytes with a
/// facade report. Construction rechecks the plan/report relationship and
/// computes the binding once without allocating.
pub struct SearchExactLiteralAotCandidate<'a> {
    source: &'a str,
    literal: &'a [u8],
    profile: &'a RustProfile,
    build_limits: BuildLimits,
    selection: PlanSelection,
    report: &'a BuildReport,
    semantic_binding_identity: SearchExactLiteralAotSemanticBindingIdentity,
    semantic_identity_bytes_hashed: u64,
}

impl fmt::Debug for SearchExactLiteralAotCandidate<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SearchExactLiteralAotCandidate")
            .field("source", &self.source)
            .field("literal", &self.literal)
            .field("profile", &self.profile)
            .field("build_limits", &self.build_limits)
            .field("selection", &self.selection)
            .field("report", &self.report)
            .field("semantic_binding_identity", &self.semantic_binding_identity)
            .field(
                "semantic_identity_bytes_hashed",
                &self.semantic_identity_bytes_hashed,
            )
            .finish_non_exhaustive()
    }
}

impl<'a> SearchExactLiteralAotCandidate<'a> {
    /// Original regular-expression source retained by the facade.
    #[must_use]
    pub const fn source(&self) -> &'a str {
        self.source
    }

    /// Literal bytes borrowed directly from the selected live plan.
    #[must_use]
    pub const fn literal(&self) -> &'a [u8] {
        self.literal
    }

    /// Complete Rust-byte compatibility profile used for parsing.
    #[must_use]
    pub const fn profile(&self) -> &'a RustProfile {
        self.profile
    }

    /// Exact construction-limit policy used by the facade.
    #[must_use]
    pub const fn build_limits(&self) -> BuildLimits {
        self.build_limits
    }

    /// Plan-selection policy used by the facade.
    #[must_use]
    pub const fn selection(&self) -> PlanSelection {
        self.selection
    }

    /// Authenticated public build report for the selected plan.
    #[must_use]
    pub const fn build_report(&self) -> &'a BuildReport {
        self.report
    }

    /// Canonical source/profile/plan binding.
    #[must_use]
    pub const fn semantic_binding_identity(&self) -> SearchExactLiteralAotSemanticBindingIdentity {
        self.semantic_binding_identity
    }

    /// Exact canonical bytes fed into the binding hash.
    #[must_use]
    pub const fn semantic_identity_bytes_hashed(&self) -> u64 {
        self.semantic_identity_bytes_hashed
    }
}

impl PortableRegex {
    /// Borrow an authenticated exact-literal Search AOT compiler candidate.
    ///
    /// Returns `None` unless the immutable facade still has its exact live
    /// literal plan and every independently retained report field agrees with
    /// that plan, source, profile, and construction policy. This method does
    /// not emit code or inspect the host.
    #[must_use]
    pub fn exact_literal_search_aot_candidate(&self) -> Option<SearchExactLiteralAotCandidate<'_>> {
        let PortablePlan::ExactLiteral(literal) = &self.plan else {
            return None;
        };
        let CompatibilityProfile::RustBytes(profile) = &self.profile else {
            return None;
        };
        if self.limits != default_portable_build_limits(profile)
            || self.selection != PlanSelection::Auto
        {
            return None;
        }
        let report = &self.report;
        let charged_persistent_bytes = self
            .source
            .len()
            .checked_add(report.capture_name_storage_bytes)?
            .checked_add(literal.storage_bytes())?;
        if report.profile != self.profile
            || report.plan != PlanKind::ExactLiteral
            || report.source_storage_bytes != self.source.len()
            || report.plan_storage_bytes != literal.storage_bytes()
            || report.charged_persistent_bytes != charged_persistent_bytes
            || report.persistent_byte_limit != self.limits.max_persistent_bytes
            || report.states != 0
            || report.edges != 0
            || report.lowering.is_some()
            || report.required_literal.is_some()
            || report.forward_anchored.is_some()
            || report.minimum_match_bytes != Some(literal.needle().len())
            || literal.storage_bytes() != literal.needle().len()
        {
            return None;
        }
        let (identity, bytes_hashed) = semantic_binding_identity(
            &self.source,
            literal.needle(),
            profile,
            self.selection,
            report,
        )?;
        Some(SearchExactLiteralAotCandidate {
            source: &self.source,
            literal: literal.needle(),
            profile,
            build_limits: self.limits,
            selection: self.selection,
            report,
            semantic_binding_identity: identity,
            semantic_identity_bytes_hashed: bytes_hashed,
        })
    }
}

fn semantic_binding_identity(
    source: &str,
    literal: &[u8],
    profile: &RustProfile,
    selection: PlanSelection,
    report: &BuildReport,
) -> Option<(SearchExactLiteralAotSemanticBindingIdentity, u64)> {
    let mut encoder = BindingEncoder::new();
    encoder.raw(BINDING_DOMAIN)?;
    encoder.u32(SEARCH_EXACT_LITERAL_AOT_SEMANTIC_BINDING_SCHEMA_VERSION);
    encoder.u32(SEARCH_EXACT_LITERAL_AOT_FIXED_BUILD_POLICY_VERSION);
    encoder.bytes(source.as_bytes())?;
    encoder.bytes(literal)?;
    encode_rust_profile(&mut encoder, profile)?;
    encoder.u8(match selection {
        PlanSelection::Auto => 0,
        PlanSelection::ForceRequiredLiteral => 1,
        PlanSelection::ForceForwardAnchored => 2,
        PlanSelection::ForceK0 => 3,
    });
    encode_build_report(&mut encoder, report)?;
    let (identity, bytes_hashed) = encoder.finish()?;
    Some((
        SearchExactLiteralAotSemanticBindingIdentity(identity),
        bytes_hashed,
    ))
}

fn encode_build_report(encoder: &mut BindingEncoder, report: &BuildReport) -> Option<()> {
    encoder.u8(0); // CompatibilityProfile::RustBytes.
    encoder.u8(match report.admission {
        AdmissionStatus::StrictChecked => 0,
        AdmissionStatus::QuotaChecked => 1,
    });
    let syntax = &report.syntax;
    encoder.u64(syntax.hir_nodes);
    encoder.u64(syntax.max_depth);
    encoder.u64(syntax.parse_work);
    encoder.u64(syntax.literal_bytes);
    encoder.u64(syntax.class_ranges);
    encoder.u64(syntax.captures);
    encoder.u64(syntax.repetitions);
    encode_option_u32(encoder, syntax.largest_finite_repeat);
    encoder.boolean(syntax.guarantees_valid_utf8_nonempty);
    encoder.u8(0); // PlanKind::ExactLiteral.
    encoder.u64(report.planner_work);
    encoder.boolean(report.lowering.is_some());
    encoder.usize(report.states)?;
    encoder.usize(report.edges)?;
    encoder.usize(report.plan_storage_bytes)?;
    encoder.usize(report.source_storage_bytes)?;
    encoder.usize(report.capture_name_storage_bytes)?;
    encoder.usize(report.charged_persistent_bytes)?;
    encoder.usize(report.persistent_byte_limit)?;
    encoder.usize(report.captures_len)?;
    encode_option_usize(encoder, report.static_captures_len)?;
    encode_option_usize(encoder, report.minimum_match_bytes)?;
    encoder.boolean(report.required_literal.is_some());
    encoder.boolean(report.forward_anchored.is_some());
    Some(())
}

fn encode_option_u32(encoder: &mut BindingEncoder, value: Option<u32>) {
    match value {
        Some(value) => {
            encoder.u8(1);
            encoder.u32(value);
        }
        None => encoder.u8(0),
    }
}

fn encode_option_usize(encoder: &mut BindingEncoder, value: Option<usize>) -> Option<()> {
    if let Some(value) = value {
        encoder.u8(1);
        encoder.usize(value)
    } else {
        encoder.u8(0);
        Some(())
    }
}

fn encode_upstream_revision(
    encoder: &mut BindingEncoder,
    revision: UpstreamRevision,
) -> Option<()> {
    let tag = match revision {
        UpstreamRevision::RustRegex1_12_4_7b96fdc => 0,
        UpstreamRevision::RustRegexAutomata0_4_14_5e195de => 1,
        UpstreamRevision::RustRegexSyntax0_8_11_1401679 => 2,
        UpstreamRevision::Rebar463d00f => 3,
        UpstreamRevision::Re2_972a15c => 4,
    };
    encoder.u8(tag);
    encoder.string(revision.commit())
}

fn encode_package_identity(encoder: &mut BindingEncoder, identity: PackageIdentity) -> Option<()> {
    encoder.u16(identity.version.major);
    encoder.u16(identity.version.minor);
    encoder.u16(identity.version.patch);
    encoder.string(identity.checksum)?;
    encode_upstream_revision(encoder, identity.vcs_revision)
}

fn encode_unicode_version(encoder: &mut BindingEncoder, version: UnicodeVersion) {
    encoder.u16(version.major);
    encoder.u16(version.minor);
    encoder.u16(version.patch);
}

fn encode_unicode_features(
    encoder: &mut BindingEncoder,
    features: RustUnicodeFeatures,
) -> Option<()> {
    let tag = if features == RustUnicodeFeatures::NONE {
        0
    } else if features == RustUnicodeFeatures::ALL {
        1
    } else if features == RustUnicodeFeatures::AGE {
        2
    } else if features == RustUnicodeFeatures::BOOL {
        3
    } else if features == RustUnicodeFeatures::CASE {
        4
    } else if features == RustUnicodeFeatures::GENCAT {
        5
    } else if features == RustUnicodeFeatures::PERL {
        6
    } else if features == RustUnicodeFeatures::SCRIPT {
        7
    } else if features == RustUnicodeFeatures::SEGMENT {
        8
    } else {
        return None;
    };
    encoder.u8(tag);
    Some(())
}

fn encode_match_kind(encoder: &mut BindingEncoder, match_kind: RustMatchKind) {
    match match_kind {
        RustMatchKind::LeftmostFirst => encoder.u8(0),
    }
}

#[allow(
    clippy::too_many_arguments,
    clippy::fn_params_excessive_bools,
    reason = "the fields exactly mirror one authenticated Rust constructor identity"
)]
fn encode_rust_constructor_common(
    encoder: &mut BindingEncoder,
    size_limit: u64,
    dfa_size_limit: u64,
    text_syntax_utf8: bool,
    bytes_syntax_utf8: bool,
    text_utf8_empty: bool,
    bytes_utf8_empty: bool,
    match_kind: RustMatchKind,
) {
    encoder.u64(size_limit);
    encoder.u64(dfa_size_limit);
    encoder.boolean(text_syntax_utf8);
    encoder.boolean(bytes_syntax_utf8);
    encoder.boolean(text_utf8_empty);
    encoder.boolean(bytes_utf8_empty);
    encode_match_kind(encoder, match_kind);
}

fn encode_rust_constructor(
    encoder: &mut BindingEncoder,
    constructor: &RustConstructor,
) -> Option<()> {
    match constructor {
        RustConstructor::RegexBuilder {
            size_limit,
            dfa_size_limit,
            text_syntax_utf8,
            bytes_syntax_utf8,
            text_utf8_empty,
            bytes_utf8_empty,
            match_kind,
        } => {
            encoder.u8(0);
            encode_rust_constructor_common(
                encoder,
                *size_limit,
                *dfa_size_limit,
                *text_syntax_utf8,
                *bytes_syntax_utf8,
                *text_utf8_empty,
                *bytes_utf8_empty,
                *match_kind,
            );
            Some(())
        }
        RustConstructor::RegexSetBuilder {
            size_limit,
            dfa_size_limit,
            text_syntax_utf8,
            bytes_syntax_utf8,
            text_utf8_empty,
            bytes_utf8_empty,
            match_kind,
        } => {
            encoder.u8(1);
            encode_rust_constructor_common(
                encoder,
                *size_limit,
                *dfa_size_limit,
                *text_syntax_utf8,
                *bytes_syntax_utf8,
                *text_utf8_empty,
                *bytes_utf8_empty,
                *match_kind,
            );
            Some(())
        }
        RustConstructor::RebarMeta {
            rebar_revision,
            regex_default_features,
            regex_logging,
            regex_perf_dfa_full,
            regex_automata_default_features,
            syntax_utf8,
            utf8_empty,
            match_kind,
            build_many_ordered,
            thompson_nfa_size_limit,
            admission_status,
        } => {
            encoder.u8(2);
            encode_upstream_revision(encoder, *rebar_revision)?;
            encoder.boolean(*regex_default_features);
            encoder.boolean(*regex_logging);
            encoder.boolean(*regex_perf_dfa_full);
            encoder.boolean(*regex_automata_default_features);
            encoder.boolean(*syntax_utf8);
            encoder.boolean(*utf8_empty);
            encode_match_kind(encoder, *match_kind);
            encoder.boolean(*build_many_ordered);
            encoder.u64(*thompson_nfa_size_limit);
            encoder.u8(match *admission_status {
                AdmissionStatus::StrictChecked => 0,
                AdmissionStatus::QuotaChecked => 1,
            });
            Some(())
        }
    }
}

fn encode_rust_profile(encoder: &mut BindingEncoder, profile: &RustProfile) -> Option<()> {
    encode_package_identity(encoder, profile.regex)?;
    encode_package_identity(encoder, profile.regex_automata)?;
    encode_package_identity(encoder, profile.regex_syntax)?;
    encode_unicode_version(encoder, profile.unicode);
    encode_unicode_features(encoder, profile.unicode_features)?;
    encode_rust_constructor(encoder, &profile.constructor)?;
    encoder.boolean(profile.options.case_insensitive);
    encoder.boolean(profile.options.multi_line);
    encoder.boolean(profile.options.dot_matches_new_line);
    encoder.boolean(profile.options.crlf);
    encoder.u8(profile.options.line_terminator);
    encoder.boolean(profile.options.swap_greed);
    encoder.boolean(profile.options.ignore_whitespace);
    encoder.boolean(profile.options.unicode);
    encoder.boolean(profile.options.octal);
    encoder.u32(profile.options.nest_limit);
    Some(())
}

struct BindingEncoder {
    digest: Sha256,
    bytes_hashed: Option<u64>,
}

impl BindingEncoder {
    fn new() -> Self {
        Self {
            digest: Sha256::new(),
            bytes_hashed: Some(0),
        }
    }

    fn raw(&mut self, bytes: &[u8]) -> Option<()> {
        self.bytes_hashed = Some(
            self.bytes_hashed?
                .checked_add(u64::try_from(bytes.len()).ok()?)?,
        );
        self.digest.update(bytes);
        Some(())
    }

    fn bytes(&mut self, bytes: &[u8]) -> Option<()> {
        self.usize(bytes.len())?;
        self.raw(bytes)
    }

    fn string(&mut self, value: &str) -> Option<()> {
        self.bytes(value.as_bytes())
    }

    fn boolean(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    fn u8(&mut self, value: u8) {
        self.digest.update([value]);
        self.bytes_hashed = self.bytes_hashed.and_then(|bytes| bytes.checked_add(1));
    }

    fn u16(&mut self, value: u16) {
        self.digest.update(value.to_le_bytes());
        self.bytes_hashed = self.bytes_hashed.and_then(|bytes| bytes.checked_add(2));
    }

    fn u32(&mut self, value: u32) {
        self.digest.update(value.to_le_bytes());
        self.bytes_hashed = self.bytes_hashed.and_then(|bytes| bytes.checked_add(4));
    }

    fn u64(&mut self, value: u64) {
        self.digest.update(value.to_le_bytes());
        self.bytes_hashed = self.bytes_hashed.and_then(|bytes| bytes.checked_add(8));
    }

    fn usize(&mut self, value: usize) -> Option<()> {
        self.u64(u64::try_from(value).ok()?);
        Some(())
    }

    fn finish(self) -> Option<([u8; 32], u64)> {
        Some((self.digest.finalize().into(), self.bytes_hashed?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PortableBuilder;

    #[test]
    fn default_exact_literal_candidate_is_stable_and_authenticated() {
        let regex = PortableBuilder::new("needle").build().unwrap();
        let first = regex.exact_literal_search_aot_candidate().unwrap();
        let second = regex.exact_literal_search_aot_candidate().unwrap();

        assert_eq!(first.source(), "needle");
        assert_eq!(first.literal(), b"needle");
        assert_eq!(
            first.build_limits(),
            default_portable_build_limits(first.profile())
        );
        assert_eq!(first.selection(), PlanSelection::Auto);
        assert_eq!(
            first.semantic_binding_identity(),
            second.semantic_binding_identity()
        );
        assert_eq!(
            first.semantic_identity_bytes_hashed(),
            second.semantic_identity_bytes_hashed()
        );
    }

    #[test]
    fn candidate_refuses_nondefault_build_policy_and_nonexact_plan() {
        let limits = BuildLimits {
            max_persistent_bytes: BuildLimits::default()
                .max_persistent_bytes
                .checked_add(1)
                .unwrap(),
            ..BuildLimits::default()
        };
        let nondefault = PortableBuilder::new("needle")
            .limits(limits)
            .build()
            .unwrap();
        assert!(nondefault.exact_literal_search_aot_candidate().is_none());

        let nonexact = PortableBuilder::new("foo|bar").build().unwrap();
        assert!(nonexact.exact_literal_search_aot_candidate().is_none());
    }

    #[test]
    fn candidate_refuses_a_report_that_no_longer_matches_the_live_plan() {
        let mut regex = PortableBuilder::new("needle").build().unwrap();
        regex.report.minimum_match_bytes = Some(0);
        assert!(regex.exact_literal_search_aot_candidate().is_none());
    }
}
