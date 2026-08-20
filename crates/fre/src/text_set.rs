//! Bounded Rust-text regex-set composition with proved UTF-8 semantics.

use core::{fmt, mem::size_of};

use fre_syntax::RustProfile;

use crate::set::build_set_session_vector;
use crate::{
    PortableRegexSetBuildLimits, PortableRegexSetExecutionError, PortableRegexSetExecutionReport,
    PortableRegexSetRunLimits, PortableRegexSetSessionError, PortableRegexSetSessionLimits,
    PortableRegexSetSessionSetupReport, PortableSetMatches, PortableTextBuildError,
    PortableTextBuildReport, PortableTextBuilder, PortableTextRegex, PortableTextSearchSession,
    SearchLimits,
};

/// Stable schema for portable Rust-text regex-set construction reports.
pub const PORTABLE_TEXT_REGEX_SET_EXPLAIN_SCHEMA_VERSION: u32 = 1;

/// Auditable construction facts for a portable Rust-text regex set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortableTextRegexSetBuildReport {
    pub schema_version: u32,
    pub profile: RustProfile,
    pub limits: PortableRegexSetBuildLimits,
    pub patterns: usize,
    pub pattern_bytes: usize,
    pub source_capacity_bytes: usize,
    pub regex_capacity_bytes: usize,
    pub matcher_source_bytes: usize,
    pub capture_name_storage_bytes: usize,
    pub plan_storage_bytes: usize,
    pub charged_persistent_bytes: usize,
}

/// Typed Rust-text set construction refusal. No partial set is published.
#[derive(Debug)]
#[non_exhaustive]
pub enum PortableTextRegexSetBuildError {
    PatternLimit {
        needed: usize,
        limit: usize,
    },
    PatternBytesLimit {
        needed: usize,
        limit: usize,
    },
    PersistentLimit {
        needed: usize,
        limit: usize,
    },
    AllocationFailed {
        structure: &'static str,
        additional: usize,
    },
    Pattern {
        index: usize,
        source: PortableTextBuildError,
    },
    /// The pinned aggregate Rust text-set constructor rejected the complete
    /// set before FRE-specific proof and planning.
    UpstreamAdmission {
        source: fre_syntax::ParseError,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
}

impl fmt::Display for PortableTextRegexSetBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PatternLimit { needed, limit } => write!(
                formatter,
                "portable text regex set needs {needed} patterns, limit is {limit}"
            ),
            Self::PatternBytesLimit { needed, limit } => write!(
                formatter,
                "portable text regex set needs {needed} pattern bytes, limit is {limit}"
            ),
            Self::PersistentLimit { needed, limit } => write!(
                formatter,
                "portable text regex set retains {needed} charged bytes, limit is {limit}"
            ),
            Self::AllocationFailed {
                structure,
                additional,
            } => write!(
                formatter,
                "failed to reserve {additional} entries for portable text regex set {structure}"
            ),
            Self::Pattern { index, source } => {
                write!(
                    formatter,
                    "portable text regex set pattern {index} failed: {source}"
                )
            }
            Self::UpstreamAdmission { source } => {
                write!(
                    formatter,
                    "pinned Rust text regex set admission failed: {source}"
                )
            }
            Self::ArithmeticOverflow { computation } => write!(
                formatter,
                "portable text regex set overflow computing {computation}"
            ),
        }
    }
}

impl std::error::Error for PortableTextRegexSetBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Pattern { source, .. } => Some(source),
            Self::UpstreamAdmission { source } => Some(source),
            _ => None,
        }
    }
}

/// Borrowing builder that proves every text pattern before set publication.
#[derive(Clone, Debug)]
pub struct PortableTextRegexSetBuilder<'a> {
    patterns: &'a [String],
    profile: RustProfile,
    limits: PortableRegexSetBuildLimits,
}

impl<'a> PortableTextRegexSetBuilder<'a> {
    /// Start a Rust-text set from pattern sources in stable ID order.
    #[must_use]
    pub fn new(patterns: &'a [String]) -> Self {
        Self {
            patterns,
            profile: RustProfile::default(),
            limits: PortableRegexSetBuildLimits::default(),
        }
    }

    /// Select the complete pinned Rust release and builder-option identity.
    #[must_use]
    pub fn profile(mut self, profile: RustProfile) -> Self {
        self.profile = profile;
        self
    }

    /// Set Unicode mode before proving every pattern.
    #[must_use]
    pub fn unicode(mut self, enabled: bool) -> Self {
        self.profile.options.unicode = enabled;
        self
    }

    /// Set case-insensitive mode before proving every pattern.
    #[must_use]
    pub fn case_insensitive(mut self, enabled: bool) -> Self {
        self.profile.options.case_insensitive = enabled;
        self
    }

    /// Set multiline mode for `^` and `$` in every pattern.
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

    /// Set CRLF mode before proving every pattern.
    #[must_use]
    pub fn crlf(mut self, enabled: bool) -> Self {
        self.profile.options.crlf = enabled;
        self
    }

    /// Swap greedy and lazy repetition semantics in every pattern.
    #[must_use]
    pub fn swap_greed(mut self, enabled: bool) -> Self {
        self.profile.options.swap_greed = enabled;
        self
    }

    /// Set verbose parsing mode in every pattern.
    #[must_use]
    pub fn ignore_whitespace(mut self, enabled: bool) -> Self {
        self.profile.options.ignore_whitespace = enabled;
        self
    }

    /// Enable or disable octal escapes in every pattern.
    #[must_use]
    pub fn octal(mut self, enabled: bool) -> Self {
        self.profile.options.octal = enabled;
        self
    }

    /// Set the syntax nesting limit in every pattern.
    #[must_use]
    pub fn nest_limit(mut self, limit: u32) -> Self {
        self.profile.options.nest_limit = limit;
        self
    }

    /// Set the byte recognized by multiline anchors in every pattern.
    #[must_use]
    pub fn line_terminator(mut self, line_terminator: u8) -> Self {
        self.profile.options.line_terminator = line_terminator;
        self
    }

    /// Set the pinned high-level text-set builder's aggregate compiled-NFA
    /// limit.
    #[must_use]
    pub fn size_limit(mut self, bytes: usize) -> Self {
        if let fre_syntax::RustConstructor::RegexBuilder { size_limit, .. } =
            &mut self.profile.constructor
        {
            *size_limit = u64::try_from(bytes).unwrap_or(u64::MAX);
        }
        self
    }

    /// Set the pinned high-level builder's lazy-DFA cache identity.
    #[must_use]
    pub fn dfa_size_limit(mut self, bytes: usize) -> Self {
        if let fre_syntax::RustConstructor::RegexBuilder { dfa_size_limit, .. } =
            &mut self.profile.constructor
        {
            *dfa_size_limit = u64::try_from(bytes).unwrap_or(u64::MAX);
        }
        self
    }

    /// Replace all set-wide and per-pattern construction limits.
    #[must_use]
    pub const fn limits(mut self, limits: PortableRegexSetBuildLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Prove and compile every pattern, then atomically publish the set.
    ///
    /// # Errors
    ///
    /// Returns a set resource refusal, allocation failure, or the exact
    /// indexed text-proof/build failure from the first rejected pattern.
    #[allow(
        clippy::too_many_lines,
        reason = "one transaction keeps bounded preflight, proof, accounting and publication ordered"
    )]
    pub fn build(self) -> Result<PortableTextRegexSet, PortableTextRegexSetBuildError> {
        let pattern_count = self.patterns.len();
        enforce(pattern_count, self.limits.max_patterns, |needed, limit| {
            PortableTextRegexSetBuildError::PatternLimit { needed, limit }
        })?;
        let pattern_bytes = self.patterns.iter().try_fold(0_usize, |total, pattern| {
            checked_add(total, pattern.len(), "pattern byte sum")
        })?;
        enforce(
            pattern_bytes,
            self.limits.max_pattern_bytes,
            |needed, limit| PortableTextRegexSetBuildError::PatternBytesLimit { needed, limit },
        )?;

        let upstream_profile = fre_syntax::CompatibilityProfile::RustText(self.profile.clone());
        fre_syntax::validate_rust_regex_set_admission(self.patterns, &upstream_profile)
            .map_err(map_upstream_admission)?;

        let source_slots = checked_mul::<String>(pattern_count, "source vector slots")?;
        let regex_slots = checked_mul::<PortableTextRegex>(pattern_count, "matcher vector slots")?;
        let logical_persistent = checked_sum(
            [source_slots, pattern_bytes, regex_slots, pattern_bytes],
            "logical persistent bytes",
        )?;
        enforce_persistent(logical_persistent, self.limits.max_persistent_bytes)?;

        let mut patterns = Vec::new();
        patterns.try_reserve_exact(pattern_count).map_err(|_| {
            PortableTextRegexSetBuildError::AllocationFailed {
                structure: "pattern vector",
                additional: pattern_count,
            }
        })?;
        let mut regexes = Vec::new();
        regexes.try_reserve_exact(pattern_count).map_err(|_| {
            PortableTextRegexSetBuildError::AllocationFailed {
                structure: "matcher vector",
                additional: pattern_count,
            }
        })?;
        let source_slot_capacity =
            capacity_bytes::<String>(patterns.capacity(), "pattern vector capacity bytes")?;
        let regex_capacity_bytes = capacity_bytes::<PortableTextRegex>(
            regexes.capacity(),
            "matcher vector capacity bytes",
        )?;
        enforce_persistent(
            checked_add(
                source_slot_capacity,
                regex_capacity_bytes,
                "initial retained capacity bytes",
            )?,
            self.limits.max_persistent_bytes,
        )?;

        let mut source_buffer_capacity = 0_usize;
        let mut matcher_source_bytes = 0_usize;
        let mut capture_name_storage_bytes = 0_usize;
        let mut plan_storage_bytes = 0_usize;
        for (index, pattern) in self.patterns.iter().enumerate() {
            let mut owned_pattern = String::new();
            owned_pattern
                .try_reserve_exact(pattern.len())
                .map_err(|_| PortableTextRegexSetBuildError::AllocationFailed {
                    structure: "pattern source bytes",
                    additional: pattern.len(),
                })?;
            owned_pattern.push_str(pattern);
            source_buffer_capacity = checked_add(
                source_buffer_capacity,
                owned_pattern.capacity(),
                "pattern source capacity sum",
            )?;

            let regex = PortableTextBuilder::new(pattern.as_str())
                .profile(self.profile.clone())
                .limits(self.limits.pattern)
                .after_set_admission()
                .build()
                .map_err(|source| PortableTextRegexSetBuildError::Pattern { index, source })?;
            let portable = &regex.build_report().portable;
            plan_storage_bytes = checked_add(
                plan_storage_bytes,
                portable.plan_storage_bytes,
                "plan storage byte sum",
            )?;
            matcher_source_bytes = checked_add(
                matcher_source_bytes,
                portable.source_storage_bytes,
                "matcher source byte sum",
            )?;
            capture_name_storage_bytes = checked_add(
                capture_name_storage_bytes,
                portable.capture_name_storage_bytes,
                "capture-name storage byte sum",
            )?;
            let charged = checked_sum(
                [
                    source_slot_capacity,
                    source_buffer_capacity,
                    regex_capacity_bytes,
                    matcher_source_bytes,
                    capture_name_storage_bytes,
                    plan_storage_bytes,
                ],
                "charged persistent bytes",
            )?;
            enforce_persistent(charged, self.limits.max_persistent_bytes)?;
            patterns.push(owned_pattern);
            regexes.push(regex);
        }

        let source_capacity_bytes = checked_add(
            source_slot_capacity,
            source_buffer_capacity,
            "complete source capacity bytes",
        )?;
        let charged_persistent_bytes = checked_sum(
            [
                source_capacity_bytes,
                regex_capacity_bytes,
                matcher_source_bytes,
                capture_name_storage_bytes,
                plan_storage_bytes,
            ],
            "complete charged persistent bytes",
        )?;
        let report = PortableTextRegexSetBuildReport {
            schema_version: PORTABLE_TEXT_REGEX_SET_EXPLAIN_SCHEMA_VERSION,
            profile: self.profile,
            limits: self.limits,
            patterns: pattern_count,
            pattern_bytes,
            source_capacity_bytes,
            regex_capacity_bytes,
            matcher_source_bytes,
            capture_name_storage_bytes,
            plan_storage_bytes,
            charged_persistent_bytes,
        };
        Ok(PortableTextRegexSet {
            patterns,
            regexes,
            report,
        })
    }
}

fn map_upstream_admission(
    error: fre_syntax::RustRegexSetAdmissionError,
) -> PortableTextRegexSetBuildError {
    if let Some(index) = error.pattern {
        PortableTextRegexSetBuildError::Pattern {
            index,
            source: PortableTextBuildError::TextSyntax(error.source),
        }
    } else {
        PortableTextRegexSetBuildError::UpstreamAdmission {
            source: error.source,
        }
    }
}

/// Immutable set of independently proved portable Rust-text matchers.
pub struct PortableTextRegexSet {
    patterns: Vec<String>,
    regexes: Vec<PortableTextRegex>,
    report: PortableTextRegexSetBuildReport,
}

impl Clone for PortableTextRegexSet {
    fn clone(&self) -> Self {
        PortableTextRegexSetBuilder::new(&self.patterns)
            .profile(self.report.profile.clone())
            .limits(self.report.limits)
            .build()
            .unwrap_or_else(|error| {
                panic!("previously admitted portable text regex set could not be cloned: {error}")
            })
    }
}

impl fmt::Debug for PortableTextRegexSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "PortableTextRegexSet({:?})", self.patterns())
    }
}

impl PortableTextRegexSet {
    /// Construct a set with pinned Rust-text defaults and default limits.
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`PortableTextRegexSetBuilder::build`].
    pub fn new<I, S>(patterns: I) -> Result<Self, PortableTextRegexSetBuildError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let limits = PortableRegexSetBuildLimits::default();
        let mut source = patterns.into_iter();
        let (lower_bound, upper_bound) = source.size_hint();
        let hinted_patterns = upper_bound.unwrap_or(lower_bound).min(limits.max_patterns);
        let mut owned = Vec::new();
        owned.try_reserve_exact(hinted_patterns).map_err(|_| {
            PortableTextRegexSetBuildError::AllocationFailed {
                structure: "generic constructor pattern vector",
                additional: hinted_patterns,
            }
        })?;
        let mut pattern_bytes = 0_usize;
        for pattern in source.by_ref() {
            let needed_patterns = checked_add(owned.len(), 1, "generic constructor pattern count")?;
            enforce(needed_patterns, limits.max_patterns, |needed, limit| {
                PortableTextRegexSetBuildError::PatternLimit { needed, limit }
            })?;
            let pattern = pattern.as_ref();
            let needed_pattern_bytes = checked_add(
                pattern_bytes,
                pattern.len(),
                "generic constructor pattern byte sum",
            )?;
            enforce(
                needed_pattern_bytes,
                limits.max_pattern_bytes,
                |needed, limit| PortableTextRegexSetBuildError::PatternBytesLimit { needed, limit },
            )?;
            if owned.len() == owned.capacity() {
                let remaining = limits.max_patterns.saturating_sub(owned.len());
                let additional = owned.len().max(1).min(remaining);
                owned.try_reserve_exact(additional).map_err(|_| {
                    PortableTextRegexSetBuildError::AllocationFailed {
                        structure: "generic constructor pattern vector",
                        additional,
                    }
                })?;
            }
            let mut copied = String::new();
            copied.try_reserve_exact(pattern.len()).map_err(|_| {
                PortableTextRegexSetBuildError::AllocationFailed {
                    structure: "generic constructor pattern source",
                    additional: pattern.len(),
                }
            })?;
            copied.push_str(pattern);
            owned.push(copied);
            pattern_bytes = needed_pattern_bytes;
        }
        PortableTextRegexSetBuilder::new(&owned).build()
    }

    /// Construct the valid empty set, which never matches.
    #[must_use]
    pub fn empty() -> Self {
        PortableTextRegexSetBuilder::new(&[])
            .build()
            .expect("the empty text set requires no allocation or pattern construction")
    }

    /// Number of patterns in stable ID order.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.regexes.len()
    }

    /// Whether the set has no patterns.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.regexes.is_empty()
    }

    /// Original pattern sources in stable ID order.
    #[must_use]
    pub fn patterns(&self) -> &[String] {
        &self.patterns
    }

    /// Complete set-wide construction accounting.
    #[must_use]
    pub const fn build_report(&self) -> &PortableTextRegexSetBuildReport {
        &self.report
    }

    /// Construct one reusable Exists-only session for every proved text
    /// constituent.
    ///
    /// The session vector and all fixed-capacity endpoint-capable K0 payloads
    /// are charged as one transaction before publication. Their cache capacity
    /// cannot grow during later searches. A failure drops every already-made
    /// private constituent session. No source positions or results are
    /// retained between calls.
    ///
    /// # Errors
    ///
    /// Returns a set-session limit, allocation failure, or indexed matcher
    /// setup refusal.
    pub fn search_session(
        &self,
        limits: PortableRegexSetSessionLimits,
    ) -> Result<PortableTextRegexSetSearchSession<'_>, PortableRegexSetSessionError> {
        let (sessions, setup) = build_set_session_vector(
            self.regexes.len(),
            limits,
            "text-set session vector",
            |index, residual| {
                self.regexes[index].fixed_endpoint_search_session(residual)
            },
            PortableTextSearchSession::workspace_setup_accounting,
        )?;
        Ok(PortableTextRegexSetSearchSession {
            owner: self,
            sessions,
            setup,
        })
    }

    /// Text proof and construction report for one constituent pattern ID.
    #[must_use]
    pub fn pattern_build_report(&self, index: usize) -> Option<&PortableTextBuildReport> {
        self.regexes.get(index).map(PortableTextRegex::build_report)
    }

    /// Whether any pattern matches a valid UTF-8 haystack.
    ///
    /// # Errors
    ///
    /// Returns a set limit or indexed matcher refusal.
    pub fn is_match(
        &self,
        haystack: &str,
        limits: PortableRegexSetRunLimits,
    ) -> Result<(bool, PortableRegexSetExecutionReport), PortableRegexSetExecutionError> {
        self.is_match_at(haystack, 0, limits)
    }

    /// Whether any pattern matches the full haystack without constructing set
    /// or constituent execution reports.
    ///
    /// This operation deliberately has unlimited execution resources. Use
    /// [`Self::is_match`] when finite work, scratch, or pattern-count limits
    /// must be enforced.
    #[inline(always)]
    pub fn is_match_value_unlimited(
        &self,
        haystack: &str,
    ) -> Result<bool, PortableRegexSetExecutionError> {
        self.is_match_value_at_unlimited(haystack, 0)
    }

    /// Whether any pattern matches at or after byte offset `start`, retaining
    /// complete original-haystack context for assertions.
    ///
    /// As in pinned Rust `RegexSet::is_match_at`, an offset inside a UTF-8
    /// scalar is valid and advances to the next possible text match boundary.
    ///
    /// # Errors
    ///
    /// Returns an invalid start, set limit, or indexed matcher refusal.
    pub fn is_match_at(
        &self,
        haystack: &str,
        start: usize,
        limits: PortableRegexSetRunLimits,
    ) -> Result<(bool, PortableRegexSetExecutionReport), PortableRegexSetExecutionError> {
        let search_start = validate_text_start(haystack, start)?;
        let mut total_work = 0_u64;
        let mut searched = 0_usize;
        for (index, regex) in self.regexes.iter().enumerate() {
            let search_count = enforce_search_count(index, limits.max_pattern_searches)?;
            let (matched, work) =
                search_one(regex, index, haystack, search_start, limits, total_work)?;
            total_work = work;
            searched = search_count;
            if matched {
                return Ok((
                    true,
                    PortableRegexSetExecutionReport {
                        start,
                        patterns_searched: searched,
                        matched_patterns: 1,
                        work: total_work,
                        output_capacity_bytes: 0,
                    },
                ));
            }
        }
        Ok((
            false,
            PortableRegexSetExecutionReport {
                start,
                patterns_searched: searched,
                matched_patterns: 0,
                work: total_work,
                output_capacity_bytes: 0,
            },
        ))
    }

    /// Whether any pattern matches at or after `start` without constructing
    /// set or constituent execution reports.
    ///
    /// This normalizes an interior UTF-8 offset once, preserves complete
    /// original-haystack assertion context and short-circuits in source
    /// order. This operation deliberately has unlimited execution resources.
    /// Use [`Self::is_match_at`] when finite work, scratch, or pattern-count
    /// limits must be enforced.
    #[inline(always)]
    pub fn is_match_value_at_unlimited(
        &self,
        haystack: &str,
        start: usize,
    ) -> Result<bool, PortableRegexSetExecutionError> {
        self.is_match_value_at_unlimited_inner(haystack, start)
    }

    #[inline(never)]
    fn is_match_value_at_unlimited_inner(
        &self,
        haystack: &str,
        start: usize,
    ) -> Result<bool, PortableRegexSetExecutionError> {
        let search_start = validate_text_start(haystack, start)?;
        for (index, regex) in self.regexes.iter().enumerate() {
            let matched = if text_set_constituent_value_route_is_direct(regex) {
                regex.is_match_value_at(haystack, search_start, SearchLimits::unlimited())
            } else {
                regex
                    .is_match_at(haystack, search_start, SearchLimits::unlimited())
                    .map(|(matched, _)| matched)
            }
            .map_err(|source| PortableRegexSetExecutionError::Pattern {
                index,
                total_work_before: 0,
                remaining_total_work: u64::MAX,
                source,
            })?;
            if matched {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Return every matching pattern ID in ascending source order.
    ///
    /// # Errors
    ///
    /// Returns a set limit, allocation failure, or indexed matcher refusal.
    /// No partial match set is published.
    pub fn matches(
        &self,
        haystack: &str,
        limits: PortableRegexSetRunLimits,
    ) -> Result<PortableSetMatches, PortableRegexSetExecutionError> {
        self.matches_at(haystack, 0, limits)
    }

    /// Return every matching pattern ID at or after byte offset `start`, with
    /// assertions evaluated against the original haystack.
    ///
    /// # Errors
    ///
    /// Returns an invalid start, set limit, allocation failure, or indexed
    /// matcher refusal. No partial match set is published.
    pub fn matches_at(
        &self,
        haystack: &str,
        start: usize,
        limits: PortableRegexSetRunLimits,
    ) -> Result<PortableSetMatches, PortableRegexSetExecutionError> {
        let search_start = validate_text_start(haystack, start)?;
        enforce_output_bytes(self.len(), limits.max_output_bytes)?;
        let mut flags = Vec::new();
        flags.try_reserve_exact(self.len()).map_err(|_| {
            PortableRegexSetExecutionError::AllocationFailed {
                structure: "text set match flags",
                additional: self.len(),
            }
        })?;
        enforce_output_bytes(flags.capacity(), limits.max_output_bytes)?;
        flags.resize(self.len(), 0_u8);

        let mut total_work = 0_u64;
        let mut matched_patterns = 0_usize;
        for (index, regex) in self.regexes.iter().enumerate() {
            let _ = enforce_search_count(index, limits.max_pattern_searches)?;
            let (matched, work) =
                search_one(regex, index, haystack, search_start, limits, total_work)?;
            total_work = work;
            if matched {
                let needed = matched_patterns.checked_add(1).ok_or(
                    PortableRegexSetExecutionError::ArithmeticOverflow {
                        computation: "matched text pattern count",
                    },
                )?;
                if needed > limits.max_output_matches {
                    return Err(PortableRegexSetExecutionError::OutputMatchesLimit {
                        needed,
                        limit: limits.max_output_matches,
                    });
                }
                flags[index] = 1;
                matched_patterns = needed;
            }
        }
        let report = PortableRegexSetExecutionReport {
            start,
            patterns_searched: self.len(),
            matched_patterns,
            work: total_work,
            output_capacity_bytes: flags.capacity(),
        };
        Ok(PortableSetMatches::from_flags_and_report(flags, report))
    }
}

impl Default for PortableTextRegexSet {
    fn default() -> Self {
        Self::empty()
    }
}

/// Reusable Exists-only sessions for every constituent of one text regex set.
#[derive(Debug)]
pub struct PortableTextRegexSetSearchSession<'r> {
    owner: &'r PortableTextRegexSet,
    sessions: Vec<PortableTextSearchSession<'r>>,
    setup: PortableRegexSetSessionSetupReport,
}

impl PortableTextRegexSetSearchSession<'_> {
    /// Exact one-time descriptor and workspace construction facts.
    #[must_use]
    pub const fn setup_report(&self) -> PortableRegexSetSessionSetupReport {
        self.setup
    }

    /// Number of constituent sessions in stable pattern-ID order.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Whether the originating set was empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Original pattern sources in stable ID order.
    #[must_use]
    pub fn patterns(&self) -> &[String] {
        self.owner.patterns()
    }

    /// Whether any pattern matches the full haystack while reusing all
    /// constituent workspaces.
    pub fn is_match(
        &mut self,
        haystack: &str,
        limits: PortableRegexSetRunLimits,
    ) -> Result<(bool, PortableRegexSetExecutionReport), PortableRegexSetExecutionError> {
        self.is_match_at(haystack, 0, limits)
    }

    /// Whether any pattern matches the full haystack without constructing a
    /// set or constituent execution report on the unlimited-work success
    /// path.
    ///
    /// Finite aggregate work, constituent work, or constituent scratch limits
    /// retain the accounted constituent route so their exact cumulative work
    /// and refusal semantics remain unchanged. Pattern-search limits are
    /// enforced directly in both routes.
    #[inline(always)]
    pub fn is_match_value(
        &mut self,
        haystack: &str,
        limits: PortableRegexSetRunLimits,
    ) -> Result<bool, PortableRegexSetExecutionError> {
        self.is_match_value_at(haystack, 0, limits)
    }

    /// Whether any pattern matches at or after `start` while preserving text
    /// boundary normalization and reusing all constituent workspaces.
    pub fn is_match_at(
        &mut self,
        haystack: &str,
        start: usize,
        limits: PortableRegexSetRunLimits,
    ) -> Result<(bool, PortableRegexSetExecutionReport), PortableRegexSetExecutionError> {
        let search_start = validate_text_start(haystack, start)?;
        let mut total_work = 0_u64;
        let mut searched = 0_usize;
        for (index, session) in self.sessions.iter_mut().enumerate() {
            let search_count = enforce_search_count(index, limits.max_pattern_searches)?;
            let (matched, work) = search_one_session_normalized(
                session,
                index,
                haystack,
                search_start,
                limits,
                total_work,
            )?;
            total_work = work;
            searched = search_count;
            if matched {
                return Ok((
                    true,
                    PortableRegexSetExecutionReport {
                        start,
                        patterns_searched: searched,
                        matched_patterns: 1,
                        work: total_work,
                        output_capacity_bytes: 0,
                    },
                ));
            }
        }
        Ok((
            false,
            PortableRegexSetExecutionReport {
                start,
                patterns_searched: searched,
                matched_patterns: 0,
                work: total_work,
                output_capacity_bytes: 0,
            },
        ))
    }

    /// Whether any pattern matches at or after `start` without constructing a
    /// set or constituent execution report on the unlimited-work success
    /// path.
    ///
    /// This normalizes an interior UTF-8 offset exactly once, preserves
    /// original-haystack assertion context and short-circuits in source order.
    /// Calls with any finite work or scratch limit retain the exact
    /// cumulative-work loop from [`Self::is_match_at`], while omitting only
    /// its final report. The fully unlimited route also bypasses constituent
    /// accounting when the constituent plan can do so without regressing its
    /// assertion-heavy K0 path.
    #[inline(always)]
    pub fn is_match_value_at(
        &mut self,
        haystack: &str,
        start: usize,
        limits: PortableRegexSetRunLimits,
    ) -> Result<bool, PortableRegexSetExecutionError> {
        let search_start = validate_text_start(haystack, start)?;
        if !text_set_value_route_is_unlimited(limits) {
            return self.is_match_value_at_accounted_normalized(haystack, search_start, limits);
        }

        for (index, session) in self.sessions.iter_mut().enumerate() {
            let _ = enforce_search_count(index, limits.max_pattern_searches)?;
            let regex = &self.owner.regexes[index];
            let matched = if text_set_constituent_value_route_is_direct(regex) {
                session.is_match_value_at_normalized(haystack, search_start, limits.pattern)
            } else {
                session
                    .is_match_accounted_at_normalized(haystack, search_start, limits.pattern)
                    .map(|(matched, _)| matched)
            }
            .map_err(|source| PortableRegexSetExecutionError::Pattern {
                index,
                total_work_before: 0,
                remaining_total_work: u64::MAX,
                source,
            })?;
            if matched {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn is_match_value_at_accounted_normalized(
        &mut self,
        haystack: &str,
        search_start: usize,
        limits: PortableRegexSetRunLimits,
    ) -> Result<bool, PortableRegexSetExecutionError> {
        let mut total_work = 0_u64;
        for (index, session) in self.sessions.iter_mut().enumerate() {
            let _ = enforce_search_count(index, limits.max_pattern_searches)?;
            let (matched, work) = search_one_session_normalized(
                session,
                index,
                haystack,
                search_start,
                limits,
                total_work,
            )?;
            total_work = work;
            if matched {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Return every matching pattern ID while reusing all constituent
    /// workspaces.
    pub fn matches(
        &mut self,
        haystack: &str,
        limits: PortableRegexSetRunLimits,
    ) -> Result<PortableSetMatches, PortableRegexSetExecutionError> {
        self.matches_at(haystack, 0, limits)
    }

    /// Return every matching pattern ID at or after `start` while preserving
    /// text boundary normalization and reusing all constituent workspaces.
    pub fn matches_at(
        &mut self,
        haystack: &str,
        start: usize,
        limits: PortableRegexSetRunLimits,
    ) -> Result<PortableSetMatches, PortableRegexSetExecutionError> {
        let search_start = validate_text_start(haystack, start)?;
        enforce_output_bytes(self.len(), limits.max_output_bytes)?;
        let mut flags = Vec::new();
        flags.try_reserve_exact(self.len()).map_err(|_| {
            PortableRegexSetExecutionError::AllocationFailed {
                structure: "text session set match flags",
                additional: self.len(),
            }
        })?;
        enforce_output_bytes(flags.capacity(), limits.max_output_bytes)?;
        flags.resize(self.len(), 0_u8);

        let mut total_work = 0_u64;
        let mut matched_patterns = 0_usize;
        for (index, session) in self.sessions.iter_mut().enumerate() {
            let _ = enforce_search_count(index, limits.max_pattern_searches)?;
            let (matched, work) = search_one_session_normalized(
                session,
                index,
                haystack,
                search_start,
                limits,
                total_work,
            )?;
            total_work = work;
            if matched {
                let needed = matched_patterns.checked_add(1).ok_or(
                    PortableRegexSetExecutionError::ArithmeticOverflow {
                        computation: "matched text session pattern count",
                    },
                )?;
                if needed > limits.max_output_matches {
                    return Err(PortableRegexSetExecutionError::OutputMatchesLimit {
                        needed,
                        limit: limits.max_output_matches,
                    });
                }
                flags[index] = 1;
                matched_patterns = needed;
            }
        }
        let report = PortableRegexSetExecutionReport {
            start,
            patterns_searched: self.len(),
            matched_patterns,
            work: total_work,
            output_capacity_bytes: flags.capacity(),
        };
        Ok(PortableSetMatches::from_flags_and_report(flags, report))
    }
}

fn search_one(
    regex: &PortableTextRegex,
    index: usize,
    haystack: &str,
    start: usize,
    limits: PortableRegexSetRunLimits,
    total_work_before: u64,
) -> Result<(bool, u64), PortableRegexSetExecutionError> {
    let remaining_total_work = limits.max_total_work.checked_sub(total_work_before).ok_or(
        PortableRegexSetExecutionError::ArithmeticOverflow {
            computation: "remaining total text-set execution work",
        },
    )?;
    let pattern_limits = SearchLimits {
        max_work: limits.pattern.max_work.min(remaining_total_work),
        max_scratch_bytes: limits.pattern.max_scratch_bytes,
    };
    let (matched, accounting) =
        regex
            .is_match_at(haystack, start, pattern_limits)
            .map_err(|source| PortableRegexSetExecutionError::Pattern {
                index,
                total_work_before,
                remaining_total_work,
                source,
            })?;
    let work = accounting.work_or_linear_terms();
    let total_work = total_work_before.checked_add(work).ok_or(
        PortableRegexSetExecutionError::ArithmeticOverflow {
            computation: "total text-set execution work",
        },
    )?;
    if total_work > limits.max_total_work {
        return Err(PortableRegexSetExecutionError::ArithmeticOverflow {
            computation: "text matcher exceeded delegated work limit",
        });
    }
    Ok((matched, total_work))
}

fn search_one_session_normalized(
    session: &mut PortableTextSearchSession<'_>,
    index: usize,
    haystack: &str,
    start: usize,
    limits: PortableRegexSetRunLimits,
    total_work_before: u64,
) -> Result<(bool, u64), PortableRegexSetExecutionError> {
    let remaining_total_work = limits.max_total_work.checked_sub(total_work_before).ok_or(
        PortableRegexSetExecutionError::ArithmeticOverflow {
            computation: "remaining total text-session execution work",
        },
    )?;
    let pattern_limits = SearchLimits {
        max_work: limits.pattern.max_work.min(remaining_total_work),
        max_scratch_bytes: limits.pattern.max_scratch_bytes,
    };
    let (matched, accounting) = session
        .is_match_accounted_at_normalized(haystack, start, pattern_limits)
        .map_err(|source| PortableRegexSetExecutionError::Pattern {
            index,
            total_work_before,
            remaining_total_work,
            source,
        })?;
    let work = accounting.work_or_linear_terms();
    let total_work = total_work_before.checked_add(work).ok_or(
        PortableRegexSetExecutionError::ArithmeticOverflow {
            computation: "total text-session execution work",
        },
    )?;
    if total_work > limits.max_total_work {
        return Err(PortableRegexSetExecutionError::ArithmeticOverflow {
            computation: "text session matcher exceeded delegated work limit",
        });
    }
    Ok((matched, total_work))
}

fn validate_text_start(
    haystack: &str,
    start: usize,
) -> Result<usize, PortableRegexSetExecutionError> {
    if start > haystack.len() {
        return Err(PortableRegexSetExecutionError::InvalidStart {
            start,
            haystack_len: haystack.len(),
        });
    }
    Ok(crate::text::next_text_boundary(haystack, start))
}

fn enforce_search_count(
    index: usize,
    limit: usize,
) -> Result<usize, PortableRegexSetExecutionError> {
    let needed =
        index
            .checked_add(1)
            .ok_or(PortableRegexSetExecutionError::ArithmeticOverflow {
                computation: "text-set pattern search count",
            })?;
    if needed > limit {
        return Err(PortableRegexSetExecutionError::PatternSearchLimit { needed, limit });
    }
    Ok(needed)
}

fn enforce_output_bytes(needed: usize, limit: usize) -> Result<(), PortableRegexSetExecutionError> {
    if needed > limit {
        return Err(PortableRegexSetExecutionError::OutputBytesLimit { needed, limit });
    }
    Ok(())
}

const fn text_set_value_route_is_unlimited(limits: PortableRegexSetRunLimits) -> bool {
    limits.max_total_work == u64::MAX
        && limits.pattern.max_work == u64::MAX
        && limits.pattern.max_scratch_bytes == usize::MAX
}

fn text_set_constituent_value_route_is_direct(regex: &PortableTextRegex) -> bool {
    let report = regex.build_report();
    report.portable.plan != crate::PlanKind::K0
        || matches!(
            &report.proof,
            crate::PortableTextProof::IdenticalUtf8Hir {
                has_look_assertions: false,
                ..
            }
        )
}

fn enforce<E>(needed: usize, limit: usize, error: impl FnOnce(usize, usize) -> E) -> Result<(), E> {
    if needed > limit {
        return Err(error(needed, limit));
    }
    Ok(())
}

fn enforce_persistent(needed: usize, limit: usize) -> Result<(), PortableTextRegexSetBuildError> {
    enforce(needed, limit, |needed, limit| {
        PortableTextRegexSetBuildError::PersistentLimit { needed, limit }
    })
}

fn checked_add(
    left: usize,
    right: usize,
    computation: &'static str,
) -> Result<usize, PortableTextRegexSetBuildError> {
    left.checked_add(right)
        .ok_or(PortableTextRegexSetBuildError::ArithmeticOverflow { computation })
}

fn checked_sum<const N: usize>(
    values: [usize; N],
    computation: &'static str,
) -> Result<usize, PortableTextRegexSetBuildError> {
    values.into_iter().try_fold(0_usize, |total, value| {
        total
            .checked_add(value)
            .ok_or(PortableTextRegexSetBuildError::ArithmeticOverflow { computation })
    })
}

fn checked_mul<T>(
    count: usize,
    computation: &'static str,
) -> Result<usize, PortableTextRegexSetBuildError> {
    count
        .checked_mul(size_of::<T>())
        .ok_or(PortableTextRegexSetBuildError::ArithmeticOverflow { computation })
}

fn capacity_bytes<T>(
    capacity: usize,
    computation: &'static str,
) -> Result<usize, PortableTextRegexSetBuildError> {
    capacity
        .checked_mul(size_of::<T>())
        .ok_or(PortableTextRegexSetBuildError::ArithmeticOverflow { computation })
}
