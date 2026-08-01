//! Bounded Rust-byte regex-set composition with exact pattern-ID semantics.

use core::{fmt, mem::size_of};

use fre_syntax::RustProfile;

use crate::{
    BuildError, BuildLimits, BuildReport, PortableBuilder, PortableRegex, SearchError,
    SearchLimits, SearchWindow,
};

/// Stable schema for portable regex-set construction and execution reports.
pub const PORTABLE_REGEX_SET_EXPLAIN_SCHEMA_VERSION: u32 = 4;

/// Complete construction limits for one portable Rust-byte set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortableRegexSetBuildLimits {
    /// Maximum number of independently compiled patterns.
    pub max_patterns: usize,
    /// Maximum sum of source bytes across every pattern.
    pub max_pattern_bytes: usize,
    /// Maximum charged retained bytes for source storage, matcher slots and
    /// the logical plan storage reported by each matcher.
    pub max_persistent_bytes: usize,
    /// Complete per-pattern construction limits.
    pub pattern: BuildLimits,
}

impl Default for PortableRegexSetBuildLimits {
    fn default() -> Self {
        Self {
            max_patterns: 4_096,
            max_pattern_bytes: 16 * 1_048_576,
            max_persistent_bytes: 256 * 1_048_576,
            pattern: BuildLimits::default(),
        }
    }
}

/// Auditable construction facts for a portable regex set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortableRegexSetBuildReport {
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

/// Typed construction refusal. No partial set is published.
#[derive(Debug)]
#[non_exhaustive]
pub enum PortableRegexSetBuildError {
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
        source: BuildError,
    },
    /// The pinned aggregate Rust-set constructor rejected the complete set.
    UpstreamAdmission {
        source: fre_syntax::ParseError,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
}

impl fmt::Display for PortableRegexSetBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PatternLimit { needed, limit } => {
                write!(
                    f,
                    "portable regex set needs {needed} patterns, limit is {limit}"
                )
            }
            Self::PatternBytesLimit { needed, limit } => write!(
                f,
                "portable regex set needs {needed} pattern bytes, limit is {limit}"
            ),
            Self::PersistentLimit { needed, limit } => write!(
                f,
                "portable regex set retains {needed} charged bytes, limit is {limit}"
            ),
            Self::AllocationFailed {
                structure,
                additional,
            } => write!(
                f,
                "failed to reserve {additional} entries for portable regex set {structure}"
            ),
            Self::Pattern { index, source } => {
                write!(f, "portable regex set pattern {index} failed: {source}")
            }
            Self::UpstreamAdmission { source } => {
                write!(f, "pinned Rust regex set admission failed: {source}")
            }
            Self::ArithmeticOverflow { computation } => {
                write!(f, "portable regex set overflow computing {computation}")
            }
        }
    }
}

impl std::error::Error for PortableRegexSetBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Pattern { source, .. } => Some(source),
            Self::UpstreamAdmission { source } => Some(source),
            _ => None,
        }
    }
}

/// Borrowing builder that preflights the complete source set before compiling.
#[derive(Clone, Debug)]
pub struct PortableRegexSetBuilder<'a> {
    patterns: &'a [String],
    profile: RustProfile,
    limits: PortableRegexSetBuildLimits,
}

impl<'a> PortableRegexSetBuilder<'a> {
    /// Start a Rust-byte set from pattern sources in stable ID order.
    #[must_use]
    pub fn new(patterns: &'a [String]) -> Self {
        Self {
            patterns,
            profile: RustProfile::regex_set_1_12_4(),
            limits: PortableRegexSetBuildLimits::default(),
        }
    }

    /// Select the complete pinned Rust release and builder-option identity.
    #[must_use]
    pub fn profile(mut self, profile: RustProfile) -> Self {
        self.profile = profile.into_regex_set_builder();
        self
    }

    /// Set the Rust bytes facade's Unicode mode before parsing every pattern.
    #[must_use]
    pub fn unicode(mut self, enabled: bool) -> Self {
        self.profile.options.unicode = enabled;
        self
    }

    /// Set case-insensitive mode before parsing every pattern.
    ///
    /// Inline `i` flag groups may still override this setting locally, just as
    /// they do in the pinned Rust bytes set builder.
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

    /// Set whether `.` matches the configured line terminator in every
    /// pattern.
    #[must_use]
    pub fn dot_matches_new_line(mut self, enabled: bool) -> Self {
        self.profile.options.dot_matches_new_line = enabled;
        self
    }

    /// Set CRLF mode for every pattern before parsing.
    ///
    /// Inline `R` flag groups may still override this setting locally, just
    /// as they do in the pinned Rust bytes set builder.
    #[must_use]
    pub fn crlf(mut self, enabled: bool) -> Self {
        self.profile.options.crlf = enabled;
        self
    }

    /// Swap greedy and lazy repetition semantics before parsing every pattern.
    ///
    /// Inline `U` flag groups may still override this setting locally, just as
    /// they do in the pinned Rust bytes set builder.
    #[must_use]
    pub fn swap_greed(mut self, enabled: bool) -> Self {
        self.profile.options.swap_greed = enabled;
        self
    }

    /// Set verbose mode for every pattern before parsing, ignoring unescaped
    /// pattern whitespace and treating `#` as the start of a line comment.
    #[must_use]
    pub fn ignore_whitespace(mut self, enabled: bool) -> Self {
        self.profile.options.ignore_whitespace = enabled;
        self
    }

    /// Enable or disable octal escape syntax in every pattern before parsing.
    #[must_use]
    pub fn octal(mut self, enabled: bool) -> Self {
        self.profile.options.octal = enabled;
        self
    }

    /// Set the parser's abstract-syntax-tree nesting limit for every pattern.
    #[must_use]
    pub fn nest_limit(mut self, limit: u32) -> Self {
        self.profile.options.nest_limit = limit;
        self
    }

    /// Set the byte recognized by multiline `^` and `$` in every pattern.
    #[must_use]
    pub fn line_terminator(mut self, line_terminator: u8) -> Self {
        self.profile.options.line_terminator = line_terminator;
        self
    }

    /// Set the pinned high-level set builder's approximate compiled-regex
    /// limit for the combined capture-free program.
    ///
    /// Unlike a single-pattern builder, this limit is evaluated once across
    /// every pattern after each constituent passes FRE's syntax and plan
    /// admission. It is never approximated as an independent per-pattern
    /// limit.
    #[must_use]
    pub fn size_limit(mut self, bytes: usize) -> Self {
        if let fre_syntax::RustConstructor::RegexSetBuilder { size_limit, .. } =
            &mut self.profile.constructor
        {
            *size_limit = u64::try_from(bytes).unwrap_or(u64::MAX);
        }
        self
    }

    /// Set the pinned high-level builder's lazy-DFA cache capacity identity
    /// for every pattern.
    ///
    /// FRE's portable plans do not use this upstream cache. Each constituent
    /// matcher still retains the configured value while enforcing FRE's
    /// independent construction and execution limits. The distinct direct-
    /// Rebar constructor profile has no corresponding high-level option and
    /// is left unchanged.
    #[must_use]
    pub fn dfa_size_limit(mut self, bytes: usize) -> Self {
        if let fre_syntax::RustConstructor::RegexSetBuilder { dfa_size_limit, .. } =
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

    /// Compile every pattern independently and publish one immutable set.
    ///
    /// Empty sets are valid and never match. Pattern IDs always correspond to
    /// source order, including duplicate patterns.
    ///
    /// # Errors
    ///
    /// Returns a set-wide resource refusal, allocation failure, or the exact
    /// indexed [`BuildError`] from the first pattern that fails.
    #[allow(
        clippy::too_many_lines,
        reason = "one construction transaction keeps preflight, fallible allocation, indexed compilation and publication ordered"
    )]
    pub fn build(&self) -> Result<PortableRegexSet, PortableRegexSetBuildError> {
        let pattern_count = self.patterns.len();
        enforce(pattern_count, self.limits.max_patterns, |needed, limit| {
            PortableRegexSetBuildError::PatternLimit { needed, limit }
        })?;
        let pattern_bytes = self.patterns.iter().try_fold(0_usize, |total, pattern| {
            checked_add(total, pattern.len(), "pattern byte sum")
        })?;
        enforce(
            pattern_bytes,
            self.limits.max_pattern_bytes,
            |needed, limit| PortableRegexSetBuildError::PatternBytesLimit { needed, limit },
        )?;

        let upstream_profile = fre_syntax::CompatibilityProfile::RustBytes(self.profile.clone());
        fre_syntax::validate_rust_regex_set_admission(self.patterns, &upstream_profile)
            .map_err(map_upstream_admission)?;

        let source_slots = checked_mul::<String>(pattern_count, "source vector slots")?;
        let regex_slots = checked_mul::<PortableRegex>(pattern_count, "matcher vector slots")?;
        let logical_persistent = checked_sum(
            [source_slots, pattern_bytes, regex_slots, pattern_bytes],
            "logical persistent bytes",
        )?;
        enforce_persistent(logical_persistent, self.limits.max_persistent_bytes)?;

        let mut patterns = Vec::new();
        patterns.try_reserve_exact(pattern_count).map_err(|_| {
            PortableRegexSetBuildError::AllocationFailed {
                structure: "pattern vector",
                additional: pattern_count,
            }
        })?;
        let mut regexes = Vec::new();
        regexes.try_reserve_exact(pattern_count).map_err(|_| {
            PortableRegexSetBuildError::AllocationFailed {
                structure: "matcher vector",
                additional: pattern_count,
            }
        })?;
        let source_slot_capacity =
            capacity_bytes::<String>(patterns.capacity(), "pattern vector capacity bytes")?;
        let regex_capacity_bytes =
            capacity_bytes::<PortableRegex>(regexes.capacity(), "matcher vector capacity bytes")?;
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
                .map_err(|_| PortableRegexSetBuildError::AllocationFailed {
                    structure: "pattern source bytes",
                    additional: pattern.len(),
                })?;
            owned_pattern.push_str(pattern);
            source_buffer_capacity = checked_add(
                source_buffer_capacity,
                owned_pattern.capacity(),
                "pattern source capacity sum",
            )?;

            let regex = PortableBuilder::new(pattern.as_str())
                .set_constituent_profile(self.profile.clone())
                .limits(self.limits.pattern)
                .after_set_admission()
                .build()
                .map_err(|source| PortableRegexSetBuildError::Pattern { index, source })?;
            plan_storage_bytes = checked_add(
                plan_storage_bytes,
                regex.build_report().plan_storage_bytes,
                "plan storage byte sum",
            )?;
            matcher_source_bytes = checked_add(
                matcher_source_bytes,
                regex.build_report().source_storage_bytes,
                "matcher source byte sum",
            )?;
            capture_name_storage_bytes = checked_add(
                capture_name_storage_bytes,
                regex.build_report().capture_name_storage_bytes,
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
        let report = PortableRegexSetBuildReport {
            schema_version: PORTABLE_REGEX_SET_EXPLAIN_SCHEMA_VERSION,
            profile: self.profile.clone(),
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
        Ok(PortableRegexSet {
            patterns,
            regexes,
            report,
        })
    }
}

fn map_upstream_admission(
    error: fre_syntax::RustRegexSetAdmissionError,
) -> PortableRegexSetBuildError {
    if let Some(index) = error.pattern {
        PortableRegexSetBuildError::Pattern {
            index,
            source: BuildError::Syntax(error.source),
        }
    } else {
        PortableRegexSetBuildError::UpstreamAdmission {
            source: error.source,
        }
    }
}

/// Immutable set of independently admitted portable Rust-byte matchers.
pub struct PortableRegexSet {
    patterns: Vec<String>,
    regexes: Vec<PortableRegex>,
    report: PortableRegexSetBuildReport,
}

impl Clone for PortableRegexSet {
    /// Rebuild an equivalent immutable set under its original profile and
    /// construction limits.
    ///
    /// Some certified native matchers deliberately do not expose `Clone`, so
    /// the set replays its already-admitted deterministic construction instead
    /// of weakening those plan-level ownership contracts.
    fn clone(&self) -> Self {
        PortableRegexSetBuilder::new(&self.patterns)
            .profile(self.report.profile.clone())
            .limits(self.report.limits)
            .build()
            .unwrap_or_else(|error| {
                panic!("previously admitted portable regex set could not be cloned: {error}")
            })
    }
}

impl fmt::Debug for PortableRegexSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "PortableRegexSet({:?})", self.patterns())
    }
}

impl PortableRegexSet {
    /// Construct a set with pinned Rust-byte defaults and default limits.
    ///
    /// Like the pinned Rust bytes `RegexSet::new` API, this accepts any
    /// iterator whose items can be viewed as pattern strings. FRE consumes the
    /// iterator in source order and refuses pattern-count or aggregate-source
    /// limits before copying the item that crosses the limit.
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`PortableRegexSetBuilder::build`].
    pub fn new<I, S>(patterns: I) -> Result<Self, PortableRegexSetBuildError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let limits = PortableRegexSetBuildLimits::default();
        let mut patterns = patterns.into_iter();
        let (lower_bound, upper_bound) = patterns.size_hint();
        let hinted_patterns = upper_bound.unwrap_or(lower_bound).min(limits.max_patterns);
        let mut owned = Vec::new();
        owned.try_reserve_exact(hinted_patterns).map_err(|_| {
            PortableRegexSetBuildError::AllocationFailed {
                structure: "generic constructor pattern vector",
                additional: hinted_patterns,
            }
        })?;

        let mut pattern_bytes = 0_usize;
        for pattern in patterns.by_ref() {
            let needed_patterns = checked_add(owned.len(), 1, "generic constructor pattern count")?;
            enforce(needed_patterns, limits.max_patterns, |needed, limit| {
                PortableRegexSetBuildError::PatternLimit { needed, limit }
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
                |needed, limit| PortableRegexSetBuildError::PatternBytesLimit { needed, limit },
            )?;

            if owned.len() == owned.capacity() {
                let remaining = limits.max_patterns.saturating_sub(owned.len());
                let additional = owned.len().max(1).min(remaining);
                owned.try_reserve_exact(additional).map_err(|_| {
                    PortableRegexSetBuildError::AllocationFailed {
                        structure: "generic constructor pattern vector",
                        additional,
                    }
                })?;
            }
            let mut copied = String::new();
            copied.try_reserve_exact(pattern.len()).map_err(|_| {
                PortableRegexSetBuildError::AllocationFailed {
                    structure: "generic constructor pattern source",
                    additional: pattern.len(),
                }
            })?;
            copied.push_str(pattern);
            owned.push(copied);
            pattern_bytes = needed_pattern_bytes;
        }
        PortableRegexSetBuilder::new(&owned).build()
    }

    /// Construct the valid empty set, which never matches.
    #[must_use]
    pub fn empty() -> Self {
        PortableRegexSetBuilder::new(&[])
            .build()
            .expect("the empty set requires no allocation or pattern construction")
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
    pub const fn build_report(&self) -> &PortableRegexSetBuildReport {
        &self.report
    }

    /// Construction report for one constituent pattern ID.
    #[must_use]
    pub fn pattern_build_report(&self, index: usize) -> Option<&BuildReport> {
        self.regexes.get(index).map(PortableRegex::build_report)
    }

    /// Whether any pattern matches the full haystack.
    ///
    /// This stops after the first matching pattern.
    ///
    /// # Errors
    ///
    /// Returns a set limit or indexed matcher refusal.
    pub fn is_match(
        &self,
        haystack: &[u8],
        limits: PortableRegexSetRunLimits,
    ) -> Result<(bool, PortableRegexSetExecutionReport), PortableRegexSetExecutionError> {
        self.is_match_at(haystack, 0, limits)
    }

    /// Whether any pattern matches at or after `start`, retaining the complete
    /// original-haystack context for assertions.
    ///
    /// # Errors
    ///
    /// Returns an invalid range, set limit, or indexed matcher refusal.
    pub fn is_match_at(
        &self,
        haystack: &[u8],
        start: usize,
        limits: PortableRegexSetRunLimits,
    ) -> Result<(bool, PortableRegexSetExecutionReport), PortableRegexSetExecutionError> {
        validate_start(start, haystack.len())?;
        let window = SearchWindow::new(start, haystack.len());
        let mut total_work = 0_u64;
        let mut searched = 0_usize;
        for (index, regex) in self.regexes.iter().enumerate() {
            let search_count = enforce_search_count(index, limits.max_pattern_searches)?;
            let (matched, work) = search_one(regex, index, haystack, window, limits, total_work)?;
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

    /// Return every matching pattern ID in ascending source order.
    ///
    /// # Errors
    ///
    /// Returns a set limit or indexed matcher refusal. No partial match set is
    /// published.
    pub fn matches(
        &self,
        haystack: &[u8],
        limits: PortableRegexSetRunLimits,
    ) -> Result<PortableSetMatches, PortableRegexSetExecutionError> {
        self.matches_at(haystack, 0, limits)
    }

    /// Return every matching pattern ID at or after `start`, with assertions
    /// evaluated against the original haystack.
    ///
    /// # Errors
    ///
    /// Returns an invalid range, set limit, allocation failure, or indexed
    /// matcher refusal. No partial match set is published.
    pub fn matches_at(
        &self,
        haystack: &[u8],
        start: usize,
        limits: PortableRegexSetRunLimits,
    ) -> Result<PortableSetMatches, PortableRegexSetExecutionError> {
        validate_start(start, haystack.len())?;
        enforce_output_bytes(self.len(), limits.max_output_bytes)?;
        let mut flags = Vec::new();
        flags.try_reserve_exact(self.len()).map_err(|_| {
            PortableRegexSetExecutionError::AllocationFailed {
                structure: "match flags",
                additional: self.len(),
            }
        })?;
        enforce_output_bytes(flags.capacity(), limits.max_output_bytes)?;
        flags.resize(self.len(), 0_u8);

        let window = SearchWindow::new(start, haystack.len());
        let mut total_work = 0_u64;
        let mut matched_patterns = 0_usize;
        for (index, regex) in self.regexes.iter().enumerate() {
            let _ = enforce_search_count(index, limits.max_pattern_searches)?;
            let (matched, work) = search_one(regex, index, haystack, window, limits, total_work)?;
            total_work = work;
            if matched {
                let needed = matched_patterns.checked_add(1).ok_or(
                    PortableRegexSetExecutionError::ArithmeticOverflow {
                        computation: "matched pattern count",
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
        Ok(PortableSetMatches { flags, report })
    }

    /// Set every matching pattern's caller-owned flag at or after `start`.
    ///
    /// This is the bounded caller-buffer counterpart to [`Self::matches_at`]
    /// and the pinned Rust bytes set's hidden `matches_read_at` API. Successful
    /// searches only change matching slots from `false` to `true`: existing
    /// flags and any tail beyond [`Self::len`] remain untouched. The returned
    /// boolean reports whether this execution matched, independent of flags
    /// that were already set by an earlier execution.
    ///
    /// Caller-owned storage is not charged against
    /// [`PortableRegexSetRunLimits::max_output_bytes`], and the execution
    /// report consequently records zero owned output-capacity bytes.
    ///
    /// # Errors
    ///
    /// Returns an invalid range, an undersized caller buffer, a set limit, or
    /// an indexed matcher refusal. Capacity and range errors are checked
    /// before mutation. On a later execution error, flags for preceding
    /// successfully matched pattern IDs remain set, matching the incremental
    /// nature of the upstream caller-buffer API.
    pub fn matches_read_at(
        &self,
        match_flags: &mut [bool],
        haystack: &[u8],
        start: usize,
        limits: PortableRegexSetRunLimits,
    ) -> Result<(bool, PortableRegexSetExecutionReport), PortableRegexSetExecutionError> {
        validate_start(start, haystack.len())?;
        if match_flags.len() < self.len() {
            return Err(PortableRegexSetExecutionError::MatchBufferTooSmall {
                needed: self.len(),
                available: match_flags.len(),
            });
        }

        let window = SearchWindow::new(start, haystack.len());
        let mut total_work = 0_u64;
        let mut matched_patterns = 0_usize;
        for (index, regex) in self.regexes.iter().enumerate() {
            let _ = enforce_search_count(index, limits.max_pattern_searches)?;
            let (matched, work) = search_one(regex, index, haystack, window, limits, total_work)?;
            total_work = work;
            if matched {
                let needed = matched_patterns.checked_add(1).ok_or(
                    PortableRegexSetExecutionError::ArithmeticOverflow {
                        computation: "matched pattern count",
                    },
                )?;
                if needed > limits.max_output_matches {
                    return Err(PortableRegexSetExecutionError::OutputMatchesLimit {
                        needed,
                        limit: limits.max_output_matches,
                    });
                }
                match_flags[index] = true;
                matched_patterns = needed;
            }
        }
        let report = PortableRegexSetExecutionReport {
            start,
            patterns_searched: self.len(),
            matched_patterns,
            work: total_work,
            output_capacity_bytes: 0,
        };
        Ok((matched_patterns != 0, report))
    }

    /// Backward-compatible alias for [`Self::matches_read_at`].
    pub fn read_matches_at(
        &self,
        match_flags: &mut [bool],
        haystack: &[u8],
        start: usize,
        limits: PortableRegexSetRunLimits,
    ) -> Result<(bool, PortableRegexSetExecutionReport), PortableRegexSetExecutionError> {
        self.matches_read_at(match_flags, haystack, start, limits)
    }
}

impl Default for PortableRegexSet {
    fn default() -> Self {
        Self::empty()
    }
}

/// Complete deterministic limits for one set search.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortableRegexSetRunLimits {
    /// Complete limits passed to each individual matcher, further tightened by
    /// the remaining set-wide work budget.
    pub pattern: SearchLimits,
    /// Maximum number of constituent matchers that may be invoked.
    pub max_pattern_searches: usize,
    /// Maximum sum of charged matcher work or checked native linear terms.
    pub max_total_work: u64,
    /// Maximum number of matching pattern IDs that may be returned.
    pub max_output_matches: usize,
    /// Maximum retained byte capacity of the match-ID flag buffer.
    pub max_output_bytes: usize,
}

impl PortableRegexSetRunLimits {
    /// Limits that accept every representable set execution.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            pattern: SearchLimits::unlimited(),
            max_pattern_searches: usize::MAX,
            max_total_work: u64::MAX,
            max_output_matches: usize::MAX,
            max_output_bytes: usize::MAX,
        }
    }
}

impl Default for PortableRegexSetRunLimits {
    fn default() -> Self {
        Self {
            pattern: SearchLimits::default(),
            max_pattern_searches: 4_096,
            max_total_work: 100_000_000,
            max_output_matches: 4_096,
            max_output_bytes: 4 * 1_048_576,
        }
    }
}

/// Exact set-level execution accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortableRegexSetExecutionReport {
    pub start: usize,
    pub patterns_searched: usize,
    pub matched_patterns: usize,
    pub work: u64,
    pub output_capacity_bytes: usize,
}

/// Typed whole-set execution refusal. No partial match set is published.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PortableRegexSetExecutionError {
    InvalidStart {
        start: usize,
        haystack_len: usize,
    },
    MatchBufferTooSmall {
        needed: usize,
        available: usize,
    },
    PatternSearchLimit {
        needed: usize,
        limit: usize,
    },
    OutputMatchesLimit {
        needed: usize,
        limit: usize,
    },
    OutputBytesLimit {
        needed: usize,
        limit: usize,
    },
    AllocationFailed {
        structure: &'static str,
        additional: usize,
    },
    Pattern {
        index: usize,
        total_work_before: u64,
        remaining_total_work: u64,
        source: SearchError,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
}

impl fmt::Display for PortableRegexSetExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidStart {
                start,
                haystack_len,
            } => write!(
                f,
                "portable regex set start {start} exceeds haystack length {haystack_len}"
            ),
            Self::MatchBufferTooSmall { needed, available } => write!(
                f,
                "portable regex set needs {needed} caller match flags, only {available} are \
                 available"
            ),
            Self::PatternSearchLimit { needed, limit } => write!(
                f,
                "portable regex set needs {needed} pattern searches, limit is {limit}"
            ),
            Self::OutputMatchesLimit { needed, limit } => write!(
                f,
                "portable regex set needs {needed} output matches, limit is {limit}"
            ),
            Self::OutputBytesLimit { needed, limit } => write!(
                f,
                "portable regex set needs {needed} output bytes, limit is {limit}"
            ),
            Self::AllocationFailed {
                structure,
                additional,
            } => write!(
                f,
                "failed to reserve {additional} entries for portable regex set {structure}"
            ),
            Self::Pattern {
                index,
                total_work_before,
                remaining_total_work,
                source,
            } => write!(
                f,
                "portable regex set pattern {index} failed after {total_work_before} work with \
                 {remaining_total_work} set work remaining: {source}"
            ),
            Self::ArithmeticOverflow { computation } => {
                write!(f, "portable regex set overflow computing {computation}")
            }
        }
    }
}

impl std::error::Error for PortableRegexSetExecutionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Pattern { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Set of matching pattern IDs and its complete execution accounting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortableSetMatches {
    flags: Vec<u8>,
    report: PortableRegexSetExecutionReport,
}

impl PortableSetMatches {
    pub(crate) const fn from_flags_and_report(
        flags: Vec<u8>,
        report: PortableRegexSetExecutionReport,
    ) -> Self {
        Self { flags, report }
    }

    /// Whether at least one pattern matched.
    #[must_use]
    pub const fn matched_any(&self) -> bool {
        self.report.matched_patterns != 0
    }

    /// Whether every pattern matched. This is vacuously true for an empty set.
    #[must_use]
    pub fn matched_all(&self) -> bool {
        self.report.matched_patterns == self.flags.len()
    }

    /// Whether the pattern at `index` matched.
    ///
    /// # Panics
    ///
    /// Panics when `index` is not a pattern ID in the originating set, matching
    /// the pinned Rust `SetMatches` contract.
    #[must_use]
    pub fn matched(&self, index: usize) -> bool {
        self.flags[index] != 0
    }

    /// Total number of patterns in the originating set, not match count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.flags.len()
    }

    /// Whether the originating set was empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.flags.is_empty()
    }

    /// Number of pattern IDs that matched.
    #[must_use]
    pub const fn matched_count(&self) -> usize {
        self.report.matched_patterns
    }

    /// Complete set-level execution accounting.
    #[must_use]
    pub const fn report(&self) -> PortableRegexSetExecutionReport {
        self.report
    }

    /// Iterate over matching IDs in ascending order.
    #[must_use]
    pub fn iter(&self) -> PortableSetMatchesIter<'_> {
        PortableSetMatchesIter {
            flags: &self.flags,
            front: 0,
            back: self.flags.len(),
        }
    }
}

impl IntoIterator for PortableSetMatches {
    type IntoIter = PortableSetMatchesIntoIter;
    type Item = usize;

    fn into_iter(self) -> Self::IntoIter {
        let back = self.flags.len();
        PortableSetMatchesIntoIter {
            flags: self.flags,
            front: 0,
            back,
        }
    }
}

impl<'a> IntoIterator for &'a PortableSetMatches {
    type IntoIter = PortableSetMatchesIter<'a>;
    type Item = usize;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Borrowed ascending iterator over matching pattern IDs.
#[derive(Clone, Debug)]
pub struct PortableSetMatchesIter<'a> {
    flags: &'a [u8],
    front: usize,
    back: usize,
}

impl Iterator for PortableSetMatchesIter<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        while self.front < self.back {
            let index = self.front;
            self.front = self.front.saturating_add(1);
            if self.flags[index] != 0 {
                return Some(index);
            }
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.back.saturating_sub(self.front)))
    }
}

impl DoubleEndedIterator for PortableSetMatchesIter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        while self.front < self.back {
            self.back = self.back.saturating_sub(1);
            if self.flags[self.back] != 0 {
                return Some(self.back);
            }
        }
        None
    }
}

impl core::iter::FusedIterator for PortableSetMatchesIter<'_> {}

/// Owned ascending iterator over matching pattern IDs.
#[derive(Debug)]
pub struct PortableSetMatchesIntoIter {
    flags: Vec<u8>,
    front: usize,
    back: usize,
}

impl Iterator for PortableSetMatchesIntoIter {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        while self.front < self.back {
            let index = self.front;
            self.front = self.front.saturating_add(1);
            if self.flags[index] != 0 {
                return Some(index);
            }
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.back.saturating_sub(self.front)))
    }
}

impl DoubleEndedIterator for PortableSetMatchesIntoIter {
    fn next_back(&mut self) -> Option<Self::Item> {
        while self.front < self.back {
            self.back = self.back.saturating_sub(1);
            if self.flags[self.back] != 0 {
                return Some(self.back);
            }
        }
        None
    }
}

impl core::iter::FusedIterator for PortableSetMatchesIntoIter {}

fn search_one(
    regex: &PortableRegex,
    index: usize,
    haystack: &[u8],
    window: SearchWindow,
    limits: PortableRegexSetRunLimits,
    total_work_before: u64,
) -> Result<(bool, u64), PortableRegexSetExecutionError> {
    let remaining_total_work = limits.max_total_work.checked_sub(total_work_before).ok_or(
        PortableRegexSetExecutionError::ArithmeticOverflow {
            computation: "remaining total execution work",
        },
    )?;
    let pattern_limits = SearchLimits {
        max_work: limits.pattern.max_work.min(remaining_total_work),
        max_scratch_bytes: limits.pattern.max_scratch_bytes,
    };
    let (matched, accounting) = regex
        .is_match_window(haystack, window, pattern_limits)
        .map_err(|source| PortableRegexSetExecutionError::Pattern {
            index,
            total_work_before,
            remaining_total_work,
            source,
        })?;
    let work = accounting.work_or_linear_terms();
    let total_work = total_work_before.checked_add(work).ok_or(
        PortableRegexSetExecutionError::ArithmeticOverflow {
            computation: "total execution work",
        },
    )?;
    if total_work > limits.max_total_work {
        return Err(PortableRegexSetExecutionError::ArithmeticOverflow {
            computation: "matcher exceeded delegated work limit",
        });
    }
    Ok((matched, total_work))
}

fn validate_start(start: usize, haystack_len: usize) -> Result<(), PortableRegexSetExecutionError> {
    if start > haystack_len {
        return Err(PortableRegexSetExecutionError::InvalidStart {
            start,
            haystack_len,
        });
    }
    Ok(())
}

fn enforce_search_count(
    index: usize,
    limit: usize,
) -> Result<usize, PortableRegexSetExecutionError> {
    let needed =
        index
            .checked_add(1)
            .ok_or(PortableRegexSetExecutionError::ArithmeticOverflow {
                computation: "pattern search count",
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

fn enforce<E>(needed: usize, limit: usize, error: impl FnOnce(usize, usize) -> E) -> Result<(), E> {
    if needed > limit {
        return Err(error(needed, limit));
    }
    Ok(())
}

fn enforce_persistent(needed: usize, limit: usize) -> Result<(), PortableRegexSetBuildError> {
    enforce(needed, limit, |needed, limit| {
        PortableRegexSetBuildError::PersistentLimit { needed, limit }
    })
}

fn checked_add(
    left: usize,
    right: usize,
    computation: &'static str,
) -> Result<usize, PortableRegexSetBuildError> {
    left.checked_add(right)
        .ok_or(PortableRegexSetBuildError::ArithmeticOverflow { computation })
}

fn checked_sum<const N: usize>(
    values: [usize; N],
    computation: &'static str,
) -> Result<usize, PortableRegexSetBuildError> {
    values.into_iter().try_fold(0_usize, |total, value| {
        checked_add(total, value, computation)
    })
}

fn checked_mul<T>(
    count: usize,
    computation: &'static str,
) -> Result<usize, PortableRegexSetBuildError> {
    count
        .checked_mul(size_of::<T>())
        .ok_or(PortableRegexSetBuildError::ArithmeticOverflow { computation })
}

fn capacity_bytes<T>(
    capacity: usize,
    computation: &'static str,
) -> Result<usize, PortableRegexSetBuildError> {
    capacity
        .checked_mul(size_of::<T>())
        .ok_or(PortableRegexSetBuildError::ArithmeticOverflow { computation })
}
