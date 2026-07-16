//! Theorem-gated Rust text facade for byte-equivalent UTF-8 languages.

use core::fmt;

use fre_syntax::{CanonicalPattern, ParseError, ParseRequest, ParseSummary};
use regex_syntax::hir::{Look, LookSet};

use crate::{
    BuildError, BuildLimits, BuildReport, CompatibilityProfile, Match, PlanSelection,
    PortableBuilder, PortableRegex, RustProfile, SearchAccounting, SearchError, SearchLimits,
    SearchWindow, finite,
};

/// Construction evidence for the first sound Rust text execution slices.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortableTextBuildReport {
    /// Public text profile proved before portable execution is constructed.
    pub profile: CompatibilityProfile,
    /// Bounded `RustText` syntax traversal.
    pub text_syntax: ParseSummary,
    /// Independently parsed `RustBytes` proof-side syntax traversal.
    pub bytes_syntax: ParseSummary,
    /// Exact theorem that permits byte execution for this text matcher.
    pub proof: PortableTextProof,
    /// Honest report for the internal portable byte executor.
    pub portable: BuildReport,
}

/// Auditable theorem used to equate the public text operation with the
/// internal byte executor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PortableTextProof {
    /// Both profiles enumerate the same ordered finite UTF-8 language.
    FiniteLanguage { words: usize, word_bytes: usize },
    /// Both profiles produced an identical HIR whose non-empty matches are
    /// valid UTF-8. A nullable HIR is admitted only when every look assertion
    /// is false inside a valid scalar, so byte search cannot publish an empty
    /// match at a non-text boundary.
    IdenticalUtf8Hir {
        minimum_match_bytes: usize,
        has_look_assertions: bool,
        /// Every nullable assertion path is false inside a valid UTF-8 scalar.
        empty_match_utf8_boundary_safe: bool,
    },
}

/// Failure to establish or construct a text-equivalence certificate.
#[derive(Debug)]
#[non_exhaustive]
pub enum PortableTextBuildError {
    /// `RustText` parsing rejected the pattern.
    TextSyntax(ParseError),
    /// The independent `RustBytes` proof parse rejected the pattern.
    BytesProofSyntax(ParseError),
    /// Checked finite-language extraction could not complete.
    FiniteProof(BuildError),
    /// The profiles are outside both bounded text-equivalence proof slices.
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
                "pattern is outside the UTF-8 equivalence slices proved by the text facade",
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

/// Checked failure from one contextual Rust text window search.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PortableTextSearchError {
    /// A byte window was not ordered, in bounds, and on UTF-8 scalar
    /// boundaries in the original text haystack.
    InvalidUtf8Window {
        start: usize,
        end: usize,
        haystack_len: usize,
    },
    /// The certified internal byte executor refused the search.
    Search(SearchError),
}

impl fmt::Display for PortableTextSearchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUtf8Window {
                start,
                end,
                haystack_len,
            } => write!(
                formatter,
                "invalid UTF-8 text window [{start}, {end}) for haystack length {haystack_len}",
            ),
            Self::Search(error) => write!(formatter, "text search failed: {error}"),
        }
    }
}

impl std::error::Error for PortableTextSearchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidUtf8Window { .. } => None,
            Self::Search(error) => Some(error),
        }
    }
}

impl From<SearchError> for PortableTextSearchError {
    fn from(value: SearchError) -> Self {
        Self::Search(value)
    }
}

/// Builder for the first certified Rust `Regex` text slices.
///
/// Finite admission requires both pinned `RustText` and `RustBytes` parsers to
/// produce the same ordered language and every word to be valid UTF-8. The
/// non-finite slice requires identical HIRs whose matches are valid UTF-8 and
/// either positive minimum width or only UTF-8-boundary-safe assertions when
/// nullable. UTF-8's self-synchronizing encoding then proves that a match
/// cannot begin or end inside a scalar. Every language outside these proofs is
/// rejected instead of silently delegated.
#[derive(Clone, Debug)]
pub struct PortableTextBuilder {
    pattern: String,
    profile: RustProfile,
    limits: BuildLimits,
    selection: PlanSelection,
    set_admitted: bool,
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
            set_admitted: false,
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

    /// Set case-insensitive mode for the complete pattern before parsing.
    ///
    /// Inline `i` flag groups may still override this setting locally, just as
    /// they do in the pinned Rust text builder.
    #[must_use]
    pub fn case_insensitive(mut self, enabled: bool) -> Self {
        self.profile.options.case_insensitive = enabled;
        self
    }

    /// Set multiline mode for `^` and `$` before parsing.
    #[must_use]
    pub fn multi_line(mut self, enabled: bool) -> Self {
        self.profile.options.multi_line = enabled;
        self
    }

    /// Set whether `.` matches the configured line terminator.
    #[must_use]
    pub fn dot_matches_new_line(mut self, enabled: bool) -> Self {
        self.profile.options.dot_matches_new_line = enabled;
        self
    }

    /// Set CRLF mode for the complete pattern before parsing.
    ///
    /// Inline `R` flag groups may still override this setting locally, just as
    /// they do in the pinned Rust text builder.
    #[must_use]
    pub fn crlf(mut self, enabled: bool) -> Self {
        self.profile.options.crlf = enabled;
        self
    }

    /// Swap greedy and lazy repetition semantics before parsing.
    #[must_use]
    pub fn swap_greed(mut self, enabled: bool) -> Self {
        self.profile.options.swap_greed = enabled;
        self
    }

    /// Set verbose mode before parsing, ignoring unescaped pattern whitespace
    /// and treating `#` as the start of a line comment.
    #[must_use]
    pub fn ignore_whitespace(mut self, enabled: bool) -> Self {
        self.profile.options.ignore_whitespace = enabled;
        self
    }

    /// Enable or disable octal escape syntax before parsing.
    #[must_use]
    pub fn octal(mut self, enabled: bool) -> Self {
        self.profile.options.octal = enabled;
        self
    }

    /// Set the parser's abstract-syntax-tree nesting limit.
    #[must_use]
    pub fn nest_limit(mut self, limit: u32) -> Self {
        self.profile.options.nest_limit = limit;
        self
    }

    /// Set the byte recognized by multiline `^` and `$` assertions.
    #[must_use]
    pub fn line_terminator(mut self, line_terminator: u8) -> Self {
        self.profile.options.line_terminator = line_terminator;
        self
    }

    /// Set the pinned high-level builder's approximate compiled-regex limit.
    ///
    /// Admission uses the pinned text constructor configuration before FRE's
    /// independent equivalence proof and plan selection.
    #[must_use]
    pub fn size_limit(mut self, bytes: usize) -> Self {
        if let fre_syntax::RustConstructor::RegexBuilder { size_limit, .. } =
            &mut self.profile.constructor
        {
            *size_limit = u64::try_from(bytes).unwrap_or(u64::MAX);
        }
        self
    }

    /// Set the pinned high-level builder's lazy-DFA cache capacity identity.
    ///
    /// Portable execution does not use that cache, but the value remains part
    /// of the authenticated compatibility identity and constructor admission.
    #[must_use]
    pub fn dfa_size_limit(mut self, bytes: usize) -> Self {
        if let fre_syntax::RustConstructor::RegexBuilder { dfa_size_limit, .. } =
            &mut self.profile.constructor
        {
            *dfa_size_limit = u64::try_from(bytes).unwrap_or(u64::MAX);
        }
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

    /// Use the already-completed aggregate Rust-set constructor admission.
    pub(crate) const fn after_set_admission(mut self) -> Self {
        self.set_admitted = true;
        self
    }

    /// Prove one text/bytes equivalence theorem and build the immutable text
    /// matcher.
    ///
    /// # Errors
    ///
    /// Returns [`PortableTextBuildError`] when syntax is invalid, the pattern
    /// is outside the proof slice, proof limits are exhausted, profiles
    /// disagree or portable construction fails.
    pub fn build(self) -> Result<PortableTextRegex, PortableTextBuildError> {
        let text_profile = CompatibilityProfile::RustText(self.profile.clone());
        let text_request = ParseRequest::rust(self.pattern.clone(), text_profile.clone())
            .with_admission(self.limits.admission)
            .with_safety_envelope(self.limits.syntax_safety);
        let text = if self.set_admitted {
            fre_syntax::parse_rust_regex_set_constituent(text_request)
        } else {
            fre_syntax::parse(text_request)
        }
        .map_err(PortableTextBuildError::TextSyntax)?;
        let text_syntax = text.summary.clone();
        let CanonicalPattern::Rust(text_pattern) = text.pattern else {
            return Err(PortableTextBuildError::InternalInvariant(
                "RustText parse produced a non-Rust pattern",
            ));
        };

        let bytes_profile = CompatibilityProfile::RustBytes(self.profile.clone());
        let bytes_request = ParseRequest::rust(self.pattern.clone(), bytes_profile)
            .with_admission(self.limits.admission)
            .with_safety_envelope(self.limits.syntax_safety);
        let bytes = if self.set_admitted {
            fre_syntax::parse_rust_regex_set_constituent(bytes_request)
        } else {
            fre_syntax::parse(bytes_request)
        }
        .map_err(PortableTextBuildError::BytesProofSyntax)?;
        let bytes_syntax = bytes.summary.clone();
        let CanonicalPattern::Rust(bytes_pattern) = bytes.pattern else {
            return Err(PortableTextBuildError::InternalInvariant(
                "RustBytes proof parse produced a non-Rust pattern",
            ));
        };

        let proof = prove_equivalence(
            &text_pattern.hir,
            &bytes_pattern.hir,
            self.profile.options.line_terminator,
            &self.limits,
        )?;

        let inner = PortableBuilder::new(self.pattern)
            .profile(self.profile)
            .limits(self.limits)
            .plan_selection(self.selection)
            .after_set_admission_if(self.set_admitted)
            .build()
            .map_err(PortableTextBuildError::Portable)?;
        let report = PortableTextBuildReport {
            profile: text_profile.clone(),
            text_syntax,
            bytes_syntax,
            proof,
            portable: inner.build_report().clone(),
        };
        Ok(PortableTextRegex {
            profile: text_profile,
            inner,
            report,
        })
    }
}

fn prove_equivalence(
    text: &regex_syntax::hir::Hir,
    bytes: &regex_syntax::hir::Hir,
    line_terminator: u8,
    limits: &BuildLimits,
) -> Result<PortableTextProof, PortableTextBuildError> {
    let text_language = finite::extract(
        text,
        limits.literal_set.max_patterns,
        limits.literal_set.max_pattern_bytes,
        0,
        limits.max_planner_work,
    )
    .map_err(PortableTextBuildError::FiniteProof)?
    .words;
    let bytes_language = finite::extract(
        bytes,
        limits.literal_set.max_patterns,
        limits.literal_set.max_pattern_bytes,
        0,
        limits.max_planner_work,
    )
    .map_err(PortableTextBuildError::FiniteProof)?
    .words;
    match (text_language, bytes_language) {
        (Some(text_language), Some(bytes_language)) => {
            finite_equivalence(&text_language, &bytes_language)
        }
        (None, None) => hir_equivalence(text, bytes, line_terminator),
        (Some(_), None) | (None, Some(_)) => Err(PortableTextBuildError::ProfileLanguageMismatch),
    }
}

fn finite_equivalence(
    text: &[Vec<u8>],
    bytes: &[Vec<u8>],
) -> Result<PortableTextProof, PortableTextBuildError> {
    if text != bytes {
        return Err(PortableTextBuildError::ProfileLanguageMismatch);
    }
    if text.iter().any(|word| core::str::from_utf8(word).is_err()) {
        return Err(PortableTextBuildError::InvalidUtf8Word);
    }
    let word_bytes = text
        .iter()
        .try_fold(0_usize, |total, word| total.checked_add(word.len()))
        .ok_or(PortableTextBuildError::InternalInvariant(
            "finite language byte count overflow",
        ))?;
    Ok(PortableTextProof::FiniteLanguage {
        words: text.len(),
        word_bytes,
    })
}

fn hir_equivalence(
    text: &regex_syntax::hir::Hir,
    bytes: &regex_syntax::hir::Hir,
    line_terminator: u8,
) -> Result<PortableTextProof, PortableTextBuildError> {
    let properties = text.properties();
    let minimum_match_bytes = properties
        .minimum_len()
        .ok_or(PortableTextBuildError::NonFiniteLanguage)?;
    let look_set = properties.look_set();
    let has_look_assertions = !look_set.is_empty();
    let empty_match_utf8_boundary_safe =
        minimum_match_bytes > 0 || looks_are_utf8_boundary_safe(look_set, line_terminator);
    if text != bytes || !properties.is_utf8() || !empty_match_utf8_boundary_safe {
        return Err(PortableTextBuildError::NonFiniteLanguage);
    }
    Ok(PortableTextProof::IdenticalUtf8Hir {
        minimum_match_bytes,
        has_look_assertions,
        empty_match_utf8_boundary_safe,
    })
}

fn looks_are_utf8_boundary_safe(looks: LookSet, line_terminator: u8) -> bool {
    looks.iter().all(|look| match look {
        Look::StartLF | Look::EndLF => line_terminator.is_ascii(),
        Look::Start
        | Look::End
        | Look::StartCRLF
        | Look::EndCRLF
        | Look::WordAscii
        | Look::WordStartAscii
        | Look::WordEndAscii
        | Look::WordUnicode
        | Look::WordUnicodeNegate
        | Look::WordStartUnicode
        | Look::WordEndUnicode
        | Look::WordStartHalfUnicode
        | Look::WordEndHalfUnicode => true,
        Look::WordAsciiNegate | Look::WordStartHalfAscii | Look::WordEndHalfAscii => false,
    })
}

/// Immutable matcher for the certified Rust text slices.
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

    /// Search a byte range whose endpoints are scalar boundaries while
    /// assertions retain their original-haystack context.
    ///
    /// # Errors
    ///
    /// Returns [`PortableTextSearchError::InvalidUtf8Window`] unless both
    /// endpoints are ordered, in bounds, and UTF-8 scalar boundaries. Other
    /// checked search refusals are returned as
    /// [`PortableTextSearchError::Search`].
    pub fn find_window(
        &self,
        haystack: &str,
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, SearchAccounting), PortableTextSearchError> {
        let start = window.start();
        let end = window.end();
        if start > end
            || end > haystack.len()
            || !haystack.is_char_boundary(start)
            || !haystack.is_char_boundary(end)
        {
            return Err(PortableTextSearchError::InvalidUtf8Window {
                start,
                end,
                haystack_len: haystack.len(),
            });
        }
        self.inner
            .find_window(haystack.as_bytes(), window, limits)
            .map_err(PortableTextSearchError::Search)
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
            assert!(matches!(
                fre.build_report().proof,
                PortableTextProof::FiniteLanguage { words, .. } if words > 0
            ));
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
    fn utf8_safe_repetition_and_assertions_match_pinned_rust_text() {
        let patterns = [
            "a+",
            "(?:é|東京)+",
            ".",
            "[^x]+",
            "^a+",
            r"\b\w+\b",
            r"^",
            r"(?m:$)",
            r"\b",
            r"(?-u:\b)",
            r"(?-u:\b{start})",
            r"(?-u:\b{end})",
            "a*",
            ".*",
            "a{2,4}",
        ];
        let haystacks = ["", "é", "東京é", "xxaaaz", "🦀 rust 東京", "aaaaa"];
        for pattern in patterns {
            let fre = PortableTextRegex::new(pattern)
                .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error:?}"));
            assert!(matches!(
                fre.build_report().proof,
                PortableTextProof::IdenticalUtf8Hir { .. }
            ));
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
            }
        }
    }

    #[test]
    fn normalized_nullable_atom_repetitions_match_complete_text_iteration() {
        fn spans(regex: &PortableTextRegex, haystack: &str) -> Vec<(usize, usize)> {
            let mut spans = Vec::new();
            let mut start = 0;
            let mut last_match_end = None;
            loop {
                let (matched, _) = regex
                    .find_window(
                        haystack,
                        SearchWindow::new(start, haystack.len()),
                        SearchLimits::unlimited(),
                    )
                    .expect("normalized nullable text search executes");
                let Some(matched) = matched else {
                    break;
                };
                if matched.is_empty() && last_match_end == Some(matched.end()) {
                    let Some(character) = haystack[start..].chars().next() else {
                        break;
                    };
                    start = start.saturating_add(character.len_utf8());
                    continue;
                }
                spans.push((matched.start(), matched.end()));
                start = matched.end();
                last_match_end = Some(matched.end());
            }
            spans
        }

        let patterns = [
            "(a*)*",
            "(a*)+",
            "([ab]*)*",
            "([^b]*)*",
            "X(.?){0,}Y",
            "X(.?){8,}Y",
            "(?:(?:.?)*?)=",
            "(?:(?:.?)*)=",
        ];
        let haystacks = [
            "",
            "a",
            "aaaaaax",
            "ababab",
            "aaaabcde",
            "X1234567Y",
            "a=b=c",
            "🦀=東京=",
        ];
        for pattern in patterns {
            let fre = PortableTextRegex::new(pattern)
                .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error:?}"));
            let lowering = fre
                .build_report()
                .portable
                .lowering
                .expect("normalized nullable shape selects K0");
            assert_eq!(lowering.normalized_nullable_repetitions(), 1);
            let upstream = regex::Regex::new(pattern).expect("pinned Rust text accepts fixture");
            for haystack in haystacks {
                let expected = upstream
                    .find_iter(haystack)
                    .map(|matched| (matched.start(), matched.end()))
                    .collect::<Vec<_>>();
                assert_eq!(
                    spans(&fre, haystack),
                    expected,
                    "pattern={pattern:?}, haystack={haystack:?}"
                );
            }
        }
    }

    #[test]
    fn utf8_safe_repetition_is_proved_and_unproved_shapes_are_refused() {
        let repeated = PortableTextRegex::new("a+").expect("positive UTF-8 repetition is proved");
        assert_eq!(
            repeated.build_report().proof,
            PortableTextProof::IdenticalUtf8Hir {
                minimum_match_bytes: 1,
                has_look_assertions: false,
                empty_match_utf8_boundary_safe: true,
            }
        );
        assert!(matches!(
            PortableTextRegex::new("(?-u:\\B)")
                .expect_err("ASCII negation can match inside a UTF-8 scalar"),
            PortableTextBuildError::NonFiniteLanguage
        ));
        assert!(matches!(
            PortableTextRegex::new("(?-u:\\xFF)")
                .expect_err("invalid UTF-8 text language is rejected"),
            PortableTextBuildError::TextSyntax(_)
        ));
    }

    #[test]
    fn zero_count_capture_does_not_break_text_construction() {
        let pattern = "(a){0}(a)";
        let fre = PortableTextRegex::new(pattern)
            .unwrap_or_else(|error| panic!("zero-count capture must compile: {error:?}"));
        assert_eq!(fre.inner.captures_len(), 3);
        assert_eq!(fre.inner.static_captures_len(), Some(2));
        assert_eq!(
            fre.inner.capture_names().collect::<Vec<_>>(),
            vec![None, None, None]
        );
        let upstream = regex::Regex::new(pattern).expect("pinned Rust text accepts fixture");
        assert_eq!(upstream.captures_len(), 3);
        assert_eq!(upstream.static_captures_len(), Some(2));
        let haystack = "a";
        let expected = upstream
            .find(haystack)
            .map(|matched| (matched.start(), matched.end()));
        let (actual, _) = fre
            .find(haystack, SearchLimits::unlimited())
            .expect("FRE text search executes");
        assert_eq!(
            actual.map(|matched| (matched.start(), matched.end())),
            expected
        );
    }

    #[test]
    fn contextual_text_windows_require_scalar_boundaries_and_keep_anchor_context() {
        let haystack = "éa";
        let regex = PortableTextRegex::new(r"^a|a$").unwrap();
        let (matched, _) = regex
            .find_window(
                haystack,
                SearchWindow::new("é".len(), haystack.len()),
                SearchLimits::unlimited(),
            )
            .unwrap();
        assert_eq!(
            matched.map(|matched| (matched.start(), matched.end())),
            Some((2, 3))
        );

        for window in [
            SearchWindow::new(1, haystack.len()),
            SearchWindow::new(0, 1),
            SearchWindow::new(3, 2),
            SearchWindow::new(0, 4),
        ] {
            assert!(matches!(
                regex.find_window(haystack, window, SearchLimits::unlimited()),
                Err(PortableTextSearchError::InvalidUtf8Window { .. })
            ));
        }
    }
}
