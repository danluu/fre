//! Theorem-gated Rust text facade for finite UTF-8 literal languages.

use core::fmt;

use fre_syntax::{CanonicalPattern, ParseError, ParseRequest, ParseSummary};

use crate::{
    BuildError, BuildLimits, BuildReport, CompatibilityProfile, Match, PlanSelection,
    PortableBuilder, PortableRegex, RustProfile, SearchAccounting, SearchError, SearchLimits,
    finite,
};

/// Construction evidence for the first sound Rust text execution slice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortableTextBuildReport {
    /// Public text profile proved before portable execution is constructed.
    pub profile: CompatibilityProfile,
    /// Bounded `RustText` syntax traversal.
    pub text_syntax: ParseSummary,
    /// Independently parsed `RustBytes` proof-side syntax traversal.
    pub bytes_syntax: ParseSummary,
    /// Ordered finite-language cardinality proved equal under both profiles.
    pub finite_words: usize,
    /// Sum of byte lengths across the proved ordered language.
    pub finite_word_bytes: usize,
    /// Honest report for the internal portable byte executor.
    pub portable: BuildReport,
}

/// Failure to establish or construct the finite-language text equivalence
/// certificate.
#[derive(Debug)]
#[non_exhaustive]
pub enum PortableTextBuildError {
    /// `RustText` parsing rejected the pattern.
    TextSyntax(ParseError),
    /// The independent `RustBytes` proof parse rejected the pattern.
    BytesProofSyntax(ParseError),
    /// Checked finite-language extraction could not complete.
    FiniteProof(BuildError),
    /// At least one profile is not a finite language under the configured
    /// literal-set limits.
    NonFiniteLanguage,
    /// `RustText` and `RustBytes` produced different ordered finite languages.
    ProfileLanguageMismatch,
    /// A proved word is not valid UTF-8, so byte matching cannot stand in for
    /// text matching.
    InvalidUtf8Word,
    /// The certified byte-equivalent language could not be constructed by the
    /// portable executor.
    Portable(BuildError),
    /// An impossible profile or arithmetic state was observed.
    InternalInvariant(&'static str),
}

impl fmt::Display for PortableTextBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TextSyntax(error) => write!(formatter, "Rust text syntax failed: {error}"),
            Self::BytesProofSyntax(error) => {
                write!(formatter, "Rust bytes proof syntax failed: {error}")
            }
            Self::FiniteProof(error) => write!(formatter, "finite-language proof failed: {error}"),
            Self::NonFiniteLanguage => formatter.write_str(
                "pattern is outside the finite UTF-8 language proved by the text facade",
            ),
            Self::ProfileLanguageMismatch => formatter.write_str(
                "Rust text and bytes profiles produced different ordered finite languages",
            ),
            Self::InvalidUtf8Word => {
                formatter.write_str("finite byte language contains an invalid UTF-8 word")
            }
            Self::Portable(error) => write!(formatter, "portable executor build failed: {error}"),
            Self::InternalInvariant(detail) => {
                write!(formatter, "text facade invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for PortableTextBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TextSyntax(error) | Self::BytesProofSyntax(error) => Some(error),
            Self::FiniteProof(error) | Self::Portable(error) => Some(error),
            Self::NonFiniteLanguage
            | Self::ProfileLanguageMismatch
            | Self::InvalidUtf8Word
            | Self::InternalInvariant(_) => None,
        }
    }
}

/// Builder for the first certified Rust `Regex` text slice.
///
/// Admission requires both pinned `RustText` and `RustBytes` parsers to produce
/// the same ordered finite language and every word to be valid UTF-8. UTF-8's
/// self-synchronizing encoding then proves that searching a valid `&str` with
/// the existing byte executor cannot begin or end inside a scalar. Assertions,
/// unbounded repetition and every other language outside that proof are
/// rejected instead of silently delegated.
#[derive(Clone, Debug)]
pub struct PortableTextBuilder {
    pattern: String,
    profile: RustProfile,
    limits: BuildLimits,
    selection: PlanSelection,
}

impl PortableTextBuilder {
    /// Start from pinned Rust `regex::RegexBuilder` defaults.
    #[must_use]
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            profile: RustProfile::default(),
            limits: BuildLimits::default(),
            selection: PlanSelection::Auto,
        }
    }

    /// Replace the complete pinned Rust profile.
    #[must_use]
    pub fn profile(mut self, profile: RustProfile) -> Self {
        self.profile = profile;
        self
    }

    /// Set the Rust text facade's Unicode mode.
    #[must_use]
    pub fn unicode(mut self, enabled: bool) -> Self {
        self.profile.options.unicode = enabled;
        self
    }

    /// Replace every checked construction limit.
    #[must_use]
    pub const fn limits(mut self, limits: BuildLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Force an internal portable plan for differential testing.
    #[must_use]
    pub const fn plan_selection(mut self, selection: PlanSelection) -> Self {
        self.selection = selection;
        self
    }

    /// Prove text/bytes finite-language equivalence and build the immutable
    /// text matcher.
    ///
    /// # Errors
    ///
    /// Returns [`PortableTextBuildError`] when syntax is invalid, the pattern
    /// is outside the proof slice, proof limits are exhausted, profiles
    /// disagree or portable construction fails.
    pub fn build(self) -> Result<PortableTextRegex, PortableTextBuildError> {
        let text_profile = CompatibilityProfile::RustText(self.profile.clone());
        let text = fre_syntax::parse(
            ParseRequest::rust(self.pattern.clone(), text_profile.clone())
                .with_admission(self.limits.admission)
                .with_safety_envelope(self.limits.syntax_safety),
        )
        .map_err(PortableTextBuildError::TextSyntax)?;
        let text_syntax = text.summary.clone();
        let CanonicalPattern::Rust(text_pattern) = text.pattern else {
            return Err(PortableTextBuildError::InternalInvariant(
                "RustText parse produced a non-Rust pattern",
            ));
        };

        let bytes_profile = CompatibilityProfile::RustBytes(self.profile.clone());
        let bytes = fre_syntax::parse(
            ParseRequest::rust(self.pattern.clone(), bytes_profile)
                .with_admission(self.limits.admission)
                .with_safety_envelope(self.limits.syntax_safety),
        )
        .map_err(PortableTextBuildError::BytesProofSyntax)?;
        let bytes_syntax = bytes.summary.clone();
        let CanonicalPattern::Rust(bytes_pattern) = bytes.pattern else {
            return Err(PortableTextBuildError::InternalInvariant(
                "RustBytes proof parse produced a non-Rust pattern",
            ));
        };

        let text_language = finite::extract(
            &text_pattern.hir,
            self.limits.literal_set.max_patterns,
            self.limits.literal_set.max_pattern_bytes,
            0,
            self.limits.max_planner_work,
        )
        .map_err(PortableTextBuildError::FiniteProof)?
        .words
        .ok_or(PortableTextBuildError::NonFiniteLanguage)?;
        let bytes_language = finite::extract(
            &bytes_pattern.hir,
            self.limits.literal_set.max_patterns,
            self.limits.literal_set.max_pattern_bytes,
            0,
            self.limits.max_planner_work,
        )
        .map_err(PortableTextBuildError::FiniteProof)?
        .words
        .ok_or(PortableTextBuildError::NonFiniteLanguage)?;
        if text_language != bytes_language {
            return Err(PortableTextBuildError::ProfileLanguageMismatch);
        }
        if text_language
            .iter()
            .any(|word| core::str::from_utf8(word).is_err())
        {
            return Err(PortableTextBuildError::InvalidUtf8Word);
        }
        let finite_word_bytes = text_language
            .iter()
            .try_fold(0_usize, |total, word| total.checked_add(word.len()))
            .ok_or(PortableTextBuildError::InternalInvariant(
                "finite language byte count overflow",
            ))?;
        let finite_words = text_language.len();

        let inner = PortableBuilder::new(self.pattern)
            .profile(self.profile)
            .limits(self.limits)
            .plan_selection(self.selection)
            .build()
            .map_err(PortableTextBuildError::Portable)?;
        let report = PortableTextBuildReport {
            profile: text_profile.clone(),
            text_syntax,
            bytes_syntax,
            finite_words,
            finite_word_bytes,
            portable: inner.build_report().clone(),
        };
        Ok(PortableTextRegex {
            profile: text_profile,
            inner,
            report,
        })
    }
}

/// Immutable matcher for the certified finite Rust text slice.
#[derive(Debug)]
pub struct PortableTextRegex {
    profile: CompatibilityProfile,
    inner: PortableRegex,
    report: PortableTextBuildReport,
}

impl PortableTextRegex {
    /// Construct with pinned Rust text defaults and checked default limits.
    ///
    /// # Errors
    ///
    /// Returns [`PortableTextBuildError`] under the same conditions as
    /// [`PortableTextBuilder::build`].
    pub fn new(pattern: impl Into<String>) -> Result<Self, PortableTextBuildError> {
        PortableTextBuilder::new(pattern).build()
    }

    /// Exact public `RustText` profile certified at construction.
    #[must_use]
    pub const fn profile(&self) -> &CompatibilityProfile {
        &self.profile
    }

    /// Text/bytes equivalence and internal portable construction evidence.
    #[must_use]
    pub const fn build_report(&self) -> &PortableTextBuildReport {
        &self.report
    }

    /// Whether a selected match exists in a valid UTF-8 haystack.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] if checked search limits refuse execution.
    pub fn is_match(
        &self,
        haystack: &str,
        limits: SearchLimits,
    ) -> Result<(bool, SearchAccounting), SearchError> {
        self.inner.is_match(haystack.as_bytes(), limits)
    }

    /// Return the selected leftmost-first match in byte offsets.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] if checked search limits refuse execution.
    pub fn find(
        &self,
        haystack: &str,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, SearchAccounting), SearchError> {
        self.inner.find(haystack.as_bytes(), limits)
    }

    /// Return the selected match end in bytes without exposing its start.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] if checked search limits refuse execution.
    pub fn selected_end(
        &self,
        haystack: &str,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        self.inner.selected_end(haystack.as_bytes(), limits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finite_unicode_languages_match_pinned_rust_text() {
        let patterns = ["雪", "(?:é|東京|a)", "[éß]", "(?i:a)", ""];
        let haystacks = ["", "z雪z", "x東京é", "ßA", "🦀aé東京"];
        for pattern in patterns {
            let fre = PortableTextRegex::new(pattern)
                .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error:?}"));
            assert!(matches!(fre.profile(), CompatibilityProfile::RustText(_)));
            assert!(fre.build_report().finite_words > 0);
            let upstream = regex::Regex::new(pattern).expect("pinned Rust text accepts fixture");
            for haystack in haystacks {
                let expected = upstream
                    .find(haystack)
                    .map(|matched| (matched.start(), matched.end()));
                let (actual, _) = fre
                    .find(haystack, SearchLimits::unlimited())
                    .expect("FRE text search executes");
                assert_eq!(
                    actual.map(|matched| (matched.start(), matched.end())),
                    expected,
                    "pattern={pattern:?} haystack={haystack:?}"
                );
                let (exists, _) = fre
                    .is_match(haystack, SearchLimits::unlimited())
                    .expect("FRE text existence executes");
                let (end, _) = fre
                    .selected_end(haystack, SearchLimits::unlimited())
                    .expect("FRE text end executes");
                assert_eq!(exists, expected.is_some());
                assert_eq!(end, expected.map(|(_, end)| end));
            }
        }
    }

    #[test]
    fn nonfinite_and_profile_divergent_languages_are_refused() {
        assert!(matches!(
            PortableTextRegex::new("a+").expect_err("unbounded repetition is outside slice"),
            PortableTextBuildError::NonFiniteLanguage
        ));
        assert!(matches!(
            PortableTextRegex::new(".").expect_err("Unicode dot is outside finite slice"),
            PortableTextBuildError::NonFiniteLanguage
        ));
        assert!(matches!(
            PortableTextRegex::new("(?-u:\\xFF)")
                .expect_err("invalid UTF-8 text language is rejected"),
            PortableTextBuildError::TextSyntax(_)
        ));
    }
}
