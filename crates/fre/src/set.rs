//! Bounded Rust-byte regex-set composition with exact pattern-ID semantics.

use core::{fmt, mem::size_of};

use fre_kernels::{
    LiteralSetBuildAccounting, LiteralSetBuildLimits, LiteralSetPlan, Window as LiteralWindow,
};
use fre_syntax::RustProfile;

use crate::{
    BuildError, BuildLimits, BuildReport, PortableBuilder, PortablePlan, PortableRegex,
    PortableSearchSession, SearchError, SearchLimits, SearchSessionLimits,
    SearchSessionSetupAccounting, SearchWindow, rust_profile_size_limit,
    set_rust_profile_size_limit,
};

/// Stable schema for portable regex-set construction and execution reports.
pub const PORTABLE_REGEX_SET_EXPLAIN_SCHEMA_VERSION: u32 = 7;

/// Stable schema for reusable regex-set session construction reports.
pub const PORTABLE_REGEX_SET_SESSION_SCHEMA_VERSION: u32 = 1;

/// Complete construction limits for one portable Rust-byte set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortableRegexSetBuildLimits {
    /// Maximum number of independently compiled patterns.
    pub max_patterns: usize,
    /// Maximum sum of source bytes across every pattern.
    pub max_pattern_bytes: usize,
    /// Maximum charged retained bytes for source storage, matcher slots,
    /// constituent plan storage and any optional fused existence sidecar.
    /// The mandatory independently executable set may still be published
    /// when only the optional sidecar exceeds the residual budget.
    pub max_persistent_bytes: usize,
    /// Complete per-pattern construction limits. For byte sets, the nested
    /// `literal_set` limits also bound the optional set-wide fused suffix
    /// existence sidecar. Text sets do not construct that sidecar.
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
    /// Sum of constituent matcher plan storage. The optional fused existence
    /// sidecar is reported separately below.
    pub plan_storage_bytes: usize,
    /// Complete construction receipt for the optional exact-literal suffix
    /// existence sidecar. Its pattern and byte counts exclude source-order
    /// constituent zero. `None` records either structural ineligibility or a
    /// fail-open construction/resource refusal.
    pub fused_literal_set_build: Option<LiteralSetBuildAccounting>,
    /// Kernel-reported logical plan payload bytes for the optional
    /// exact-literal suffix existence sidecar. Zero means construction
    /// declined or the set shape was ineligible; this is not an
    /// allocator-footprint measurement.
    pub fused_literal_set_storage_bytes: usize,
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
    /// Legacy exact-upstream aggregate-admission failure.
    ///
    /// Native-size set construction no longer emits this variant.
    #[deprecated(
        since = "0.1.0",
        note = "aggregate size_limit now reports PersistentLimit"
    )]
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
            #[allow(deprecated)]
            Self::UpstreamAdmission { source } => {
                write!(f, "legacy upstream regex set admission failed: {source}")
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
            #[allow(deprecated)]
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
        let profile = RustProfile::regex_set_1_12_4();
        let mut limits = PortableRegexSetBuildLimits::default();
        if let Some(limit) = rust_profile_size_limit(&profile) {
            limits.max_persistent_bytes = limit;
        }
        Self {
            patterns,
            profile,
            limits,
        }
    }

    /// Select the complete pinned Rust release and builder-option identity.
    #[must_use]
    pub fn profile(mut self, profile: RustProfile) -> Self {
        self.profile = profile.into_regex_set_builder();
        self.limits.max_persistent_bytes = rust_profile_size_limit(&self.profile)
            .unwrap_or(PortableRegexSetBuildLimits::default().max_persistent_bytes);
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

    /// Set the native retained-byte ceiling for the complete compiled set.
    #[must_use]
    pub fn size_limit(mut self, bytes: usize) -> Self {
        set_rust_profile_size_limit(&mut self.profile, bytes);
        self.limits.max_persistent_bytes = bytes;
        self
    }

    /// Retain the Rust-like lazy-DFA cache option. FRE has no corresponding
    /// cache, so this does not change native construction or execution.
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
        if matches!(
            &self.profile.constructor,
            fre_syntax::RustConstructor::RegexSetBuilder { .. }
        ) {
            set_rust_profile_size_limit(&mut self.profile, limits.max_persistent_bytes);
        }
        self
    }

    /// Compile every pattern independently and publish one immutable set.
    ///
    /// Empty sets are valid and never match. Pattern IDs always correspond to
    /// source order, including duplicate patterns. A set of at least eight
    /// positive exact literals additionally attempts one fused full-haystack
    /// existence plan for every constituent after pattern zero. Its
    /// construction and persistent limits are inherited from the configured
    /// constituent literal-set limits and the residual aggregate byte budget;
    /// any refusal simply retains the independent matcher implementation.
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
        let incumbent_charged_persistent_bytes = checked_sum(
            [
                source_capacity_bytes,
                regex_capacity_bytes,
                matcher_source_bytes,
                capture_name_storage_bytes,
                plan_storage_bytes,
            ],
            "complete charged persistent bytes",
        )?;
        enforce_persistent(
            incumbent_charged_persistent_bytes,
            self.limits.max_persistent_bytes,
        )?;
        let remaining_persistent_bytes = self
            .limits
            .max_persistent_bytes
            .checked_sub(incumbent_charged_persistent_bytes)
            .expect("the mandatory set charge was enforced before computing residual bytes");
        let fused_literal_set = try_build_fused_exact_literal_exists(
            &regexes,
            self.limits.pattern.literal_set,
            remaining_persistent_bytes,
        );
        let fused_literal_set_build = fused_literal_set
            .as_ref()
            .map(|fused| fused.plan.build_accounting());
        let fused_literal_set_storage_bytes =
            fused_literal_set_build.map_or(0, |build| build.persistent_bytes);
        let charged_persistent_bytes = checked_add(
            incumbent_charged_persistent_bytes,
            fused_literal_set_storage_bytes,
            "complete charged persistent bytes with fused literal set",
        )?;
        enforce_persistent(charged_persistent_bytes, self.limits.max_persistent_bytes)?;
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
            fused_literal_set_build,
            fused_literal_set_storage_bytes,
            charged_persistent_bytes,
        };
        Ok(PortableRegexSet {
            patterns,
            regexes,
            fused_literal_set,
            report,
        })
    }
}

/// Immutable set of independently admitted portable Rust-byte matchers.
pub struct PortableRegexSet {
    patterns: Vec<String>,
    regexes: Vec<PortableRegex>,
    fused_literal_set: Option<FusedExactLiteralExists>,
    report: PortableRegexSetBuildReport,
}

#[derive(Clone, Debug)]
struct FusedExactLiteralExists {
    plan: LiteralSetPlan,
    origin_first_bytes: [u64; 4],
}

impl FusedExactLiteralExists {
    #[inline(always)]
    fn origin_may_match(&self, haystack: &[u8]) -> bool {
        let Some(&byte) = haystack.first() else {
            return false;
        };
        let word = usize::from(byte) / u64::BITS as usize;
        let bit = usize::from(byte) % u64::BITS as usize;
        self.origin_first_bytes[word] & (1_u64 << bit) != 0
    }
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

    /// Construct one reusable Exists-only session for every constituent.
    ///
    /// The complete descriptor vector and all fixed-capacity K0 endpoint
    /// workspace payloads are charged before the session is published. Their
    /// cache capacity cannot grow during later searches. Native constituents
    /// retain a direct immutable binding and no workspace. A construction
    /// failure drops every already-created private constituent session.
    ///
    /// # Errors
    ///
    /// Returns a set-session limit, allocation failure, or indexed matcher
    /// setup refusal.
    pub fn search_session(
        &self,
        limits: PortableRegexSetSessionLimits,
    ) -> Result<PortableRegexSetSearchSession<'_>, PortableRegexSetSessionError> {
        let (sessions, setup) = build_set_session_vector(
            self.regexes.len(),
            limits,
            "byte-set session vector",
            |index, residual| {
                self.regexes[index].fixed_endpoint_search_session(residual)
            },
            PortableSearchSession::workspace_setup_accounting,
        )?;
        Ok(PortableRegexSetSearchSession {
            owner: self,
            sessions,
            setup,
        })
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

    /// Whether any pattern matches the full haystack without constructing set
    /// or constituent execution reports.
    ///
    /// This operation deliberately has unlimited execution resources. Sets
    /// that retained an all-positive exact-literal suffix sidecar may use a
    /// leading-byte-gated origin probe, then search pattern zero independently
    /// and use the sidecar after those misses. Short inputs whose leading byte
    /// could begin a literal retain source-ordered constituent execution.
    /// Ranged, accounted, session and all-ID APIs always execute every
    /// independent constituent. Use [`Self::is_match`] when finite work,
    /// scratch, or pattern-count limits must be enforced.
    #[inline(always)]
    pub fn is_match_value_unlimited(
        &self,
        haystack: &[u8],
    ) -> Result<bool, PortableRegexSetExecutionError> {
        if let Some(fused) = &self.fused_literal_set {
            let origin_may_match = fused.origin_may_match(haystack);
            if origin_may_match && haystack.len() < FUSED_LITERAL_SET_ORIGIN_PROBE_MIN_BYTES {
                return self.is_match_value_at_unlimited(haystack, 0);
            }
            // Preserve the cheapest common positive case before entering the
            // aggregate automaton. The sidecar's construction eligibility
            // proves that every constituent is one positive exact literal.
            if origin_may_match {
                for regex in &self.regexes {
                    let PortablePlan::ExactLiteral(literal) = &regex.plan else {
                        unreachable!("the fused suffix admits only exact literals");
                    };
                    if haystack.starts_with(literal.needle()) {
                        return Ok(true);
                    }
                }
            }
            let first = is_match_window_value_unlimited(
                &self.regexes[0],
                haystack,
                SearchWindow::new(0, haystack.len()),
            )
            .map_err(|source| PortableRegexSetExecutionError::Pattern {
                index: 0,
                total_work_before: 0,
                remaining_total_work: u64::MAX,
                source,
            })?;
            if first {
                return Ok(true);
            }
            let executor = fused
                .plan
                .ordinary_executor()
                .expect("the fused suffix plan retains only positive exact literals");
            return Ok(executor
                .exists_window_value(haystack, LiteralWindow::full(haystack))
                .expect("a complete-haystack fused literal-set window is valid"));
        }
        self.is_match_value_at_unlimited(haystack, 0)
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

    /// Whether any pattern matches at or after `start` without constructing set
    /// or constituent execution reports.
    ///
    /// This preserves original-haystack assertion context and source-order
    /// short circuiting. This operation deliberately has unlimited execution
    /// resources. Use [`Self::is_match_at`] when finite work, scratch, or
    /// pattern-count limits must be enforced.
    #[inline(always)]
    pub fn is_match_value_at_unlimited(
        &self,
        haystack: &[u8],
        start: usize,
    ) -> Result<bool, PortableRegexSetExecutionError> {
        self.is_match_value_at_unlimited_inner(haystack, start)
    }

    #[inline(never)]
    fn is_match_value_at_unlimited_inner(
        &self,
        haystack: &[u8],
        start: usize,
    ) -> Result<bool, PortableRegexSetExecutionError> {
        validate_start(start, haystack.len())?;
        let window = SearchWindow::new(start, haystack.len());
        for (index, regex) in self.regexes.iter().enumerate() {
            let matched =
                is_match_window_value_unlimited(regex, haystack, window).map_err(|source| {
                    PortableRegexSetExecutionError::Pattern {
                        index,
                        total_work_before: 0,
                        remaining_total_work: u64::MAX,
                        source,
                    }
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

    /// Set matching IDs in caller-owned flags without constructing set or
    /// constituent execution reports on the unlimited-resource path.
    ///
    /// Successful searches have the same incremental mutation semantics as
    /// [`Self::matches_read_at`]: only matching slots are changed from
    /// `false` to `true`, any caller-owned tail remains untouched, and the
    /// returned boolean describes this execution rather than flags retained
    /// from an earlier call.
    ///
    /// Calls with any finite set or constituent limit retain the exact
    /// accounted implementation, including cumulative work, partial flag
    /// mutation, and refusal precedence. The value route is selected only
    /// when every field equals [`PortableRegexSetRunLimits::unlimited`].
    ///
    /// # Errors
    ///
    /// Returns the same invalid range, undersized buffer, set limit, or
    /// indexed matcher refusal as [`Self::matches_read_at`].
    #[inline(always)]
    pub fn matches_read_at_value(
        &self,
        match_flags: &mut [bool],
        haystack: &[u8],
        start: usize,
        limits: PortableRegexSetRunLimits,
    ) -> Result<bool, PortableRegexSetExecutionError> {
        if start > haystack.len() {
            return Err(PortableRegexSetExecutionError::InvalidStart {
                start,
                haystack_len: haystack.len(),
            });
        }
        if match_flags.len() < self.len() {
            return Err(PortableRegexSetExecutionError::MatchBufferTooSmall {
                needed: self.len(),
                available: match_flags.len(),
            });
        }
        if self.is_empty() {
            return Ok(false);
        }
        if limits != PortableRegexSetRunLimits::unlimited() {
            return self
                .matches_read_at(match_flags, haystack, start, limits)
                .map(|(matched, _report)| matched);
        }
        let window = SearchWindow::new(start, haystack.len());
        let mut any = false;
        for (index, regex) in self.regexes.iter().enumerate() {
            let matched = regex
                .is_match_window_value(haystack, window, SearchLimits::unlimited())
                .map_err(|source| PortableRegexSetExecutionError::Pattern {
                    index,
                    total_work_before: 0,
                    remaining_total_work: u64::MAX,
                    source,
                })?;
            if matched {
                match_flags[index] = true;
                any = true;
            }
        }
        Ok(any)
    }

    /// Backward-compatible spelling matching [`Self::read_matches_at`].
    #[inline(always)]
    pub fn read_matches_at_value(
        &self,
        match_flags: &mut [bool],
        haystack: &[u8],
        start: usize,
        limits: PortableRegexSetRunLimits,
    ) -> Result<bool, PortableRegexSetExecutionError> {
        self.matches_read_at_value(match_flags, haystack, start, limits)
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

/// Reusable Exists-only sessions for every constituent of one byte regex set.
///
/// The owner is borrowed immutably while each constituent workspace is
/// borrowed mutably through this aggregate, preventing concurrent reuse of
/// the same session state. No source bytes, positions, or results are retained
/// between calls.
#[derive(Debug)]
pub struct PortableRegexSetSearchSession<'r> {
    owner: &'r PortableRegexSet,
    sessions: Vec<PortableSearchSession<'r>>,
    setup: PortableRegexSetSessionSetupReport,
}

impl PortableRegexSetSearchSession<'_> {
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
        haystack: &[u8],
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
        haystack: &[u8],
        limits: PortableRegexSetRunLimits,
    ) -> Result<bool, PortableRegexSetExecutionError> {
        self.is_match_value_at(haystack, 0, limits)
    }

    /// Whether any pattern matches at or after `start` while reusing all
    /// constituent workspaces.
    pub fn is_match_at(
        &mut self,
        haystack: &[u8],
        start: usize,
        limits: PortableRegexSetRunLimits,
    ) -> Result<(bool, PortableRegexSetExecutionReport), PortableRegexSetExecutionError> {
        validate_start(start, haystack.len())?;
        let window = SearchWindow::new(start, haystack.len());
        let mut total_work = 0_u64;
        let mut searched = 0_usize;
        for (index, session) in self.sessions.iter_mut().enumerate() {
            let search_count = enforce_search_count(index, limits.max_pattern_searches)?;
            let (matched, work) =
                search_one_session(session, index, haystack, window, limits, total_work)?;
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
    /// This preserves original-haystack assertion context and source-order
    /// short circuiting. Calls with any finite work or scratch limit retain
    /// the exact cumulative-work loop from [`Self::is_match_at`], while
    /// omitting only its final report; only calls whose constituent and
    /// aggregate resource ceilings are all unlimited also bypass constituent
    /// accounting.
    #[inline(always)]
    pub fn is_match_value_at(
        &mut self,
        haystack: &[u8],
        start: usize,
        limits: PortableRegexSetRunLimits,
    ) -> Result<bool, PortableRegexSetExecutionError> {
        if !set_value_route_is_unlimited(limits) {
            return self.is_match_value_at_accounted(haystack, start, limits);
        }

        validate_start(start, haystack.len())?;
        let window = SearchWindow::new(start, haystack.len());
        for (index, session) in self.sessions.iter_mut().enumerate() {
            let _ = enforce_search_count(index, limits.max_pattern_searches)?;
            let matched = session
                .is_match_window_value(haystack, window, limits.pattern)
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

    fn is_match_value_at_accounted(
        &mut self,
        haystack: &[u8],
        start: usize,
        limits: PortableRegexSetRunLimits,
    ) -> Result<bool, PortableRegexSetExecutionError> {
        validate_start(start, haystack.len())?;
        let window = SearchWindow::new(start, haystack.len());
        let mut total_work = 0_u64;
        for (index, session) in self.sessions.iter_mut().enumerate() {
            let _ = enforce_search_count(index, limits.max_pattern_searches)?;
            let (matched, work) =
                search_one_session(session, index, haystack, window, limits, total_work)?;
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
        haystack: &[u8],
        limits: PortableRegexSetRunLimits,
    ) -> Result<PortableSetMatches, PortableRegexSetExecutionError> {
        self.matches_at(haystack, 0, limits)
    }

    /// Return every matching pattern ID at or after `start` while reusing all
    /// constituent workspaces.
    pub fn matches_at(
        &mut self,
        haystack: &[u8],
        start: usize,
        limits: PortableRegexSetRunLimits,
    ) -> Result<PortableSetMatches, PortableRegexSetExecutionError> {
        validate_start(start, haystack.len())?;
        enforce_output_bytes(self.len(), limits.max_output_bytes)?;
        let mut flags = Vec::new();
        flags.try_reserve_exact(self.len()).map_err(|_| {
            PortableRegexSetExecutionError::AllocationFailed {
                structure: "session match flags",
                additional: self.len(),
            }
        })?;
        enforce_output_bytes(flags.capacity(), limits.max_output_bytes)?;
        flags.resize(self.len(), 0_u8);

        let window = SearchWindow::new(start, haystack.len());
        let mut total_work = 0_u64;
        let mut matched_patterns = 0_usize;
        for (index, session) in self.sessions.iter_mut().enumerate() {
            let _ = enforce_search_count(index, limits.max_pattern_searches)?;
            let (matched, work) =
                search_one_session(session, index, haystack, window, limits, total_work)?;
            total_work = work;
            if matched {
                let needed = matched_patterns.checked_add(1).ok_or(
                    PortableRegexSetExecutionError::ArithmeticOverflow {
                        computation: "session matched pattern count",
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

    /// Set matching IDs in caller-owned flags while reusing all constituent
    /// workspaces.
    pub fn matches_read_at(
        &mut self,
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
        for (index, session) in self.sessions.iter_mut().enumerate() {
            let _ = enforce_search_count(index, limits.max_pattern_searches)?;
            let (matched, work) =
                search_one_session(session, index, haystack, window, limits, total_work)?;
            total_work = work;
            if matched {
                let needed = matched_patterns.checked_add(1).ok_or(
                    PortableRegexSetExecutionError::ArithmeticOverflow {
                        computation: "session matched pattern count",
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

    /// Backward-compatible spelling matching the immutable set facade.
    pub fn read_matches_at(
        &mut self,
        match_flags: &mut [bool],
        haystack: &[u8],
        start: usize,
        limits: PortableRegexSetRunLimits,
    ) -> Result<(bool, PortableRegexSetExecutionReport), PortableRegexSetExecutionError> {
        self.matches_read_at(match_flags, haystack, start, limits)
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

/// Hard limits for constructing one reusable byte- or text-set search
/// session.
///
/// The aggregate limits cover the complete session vector plus every
/// constituent matcher workspace. Each constituent is constructed under the
/// smaller of `pattern` and the aggregate budget remaining in source order.
/// Publication is admitted against the actual retained capacity after each
/// fallible allocation; allocators may transiently reserve more before a
/// rejected construction is dropped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortableRegexSetSessionLimits {
    /// Per-constituent reusable-workspace limits.
    pub pattern: SearchSessionLimits,
    /// Maximum number of constituent session slots.
    pub max_pattern_sessions: usize,
    /// Maximum vector-initialization plus constituent workspace setup work.
    pub max_total_setup_work: u64,
    /// Maximum retained session-vector capacity plus constituent workspace
    /// payload bytes.
    pub max_total_retained_bytes: usize,
}

impl PortableRegexSetSessionLimits {
    /// Limits that accept every representable set-session construction.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            pattern: SearchSessionLimits::unlimited(),
            max_pattern_sessions: usize::MAX,
            max_total_setup_work: u64::MAX,
            max_total_retained_bytes: usize::MAX,
        }
    }
}

impl Default for PortableRegexSetSessionLimits {
    fn default() -> Self {
        Self {
            pattern: SearchSessionLimits::default(),
            max_pattern_sessions: 4_096,
            max_total_setup_work: 100_000_000,
            max_total_retained_bytes: 256 * 1_048_576,
        }
    }
}

/// Exact one-time construction facts for a reusable regex-set session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortableRegexSetSessionSetupReport {
    pub schema_version: u32,
    pub limits: PortableRegexSetSessionLimits,
    pub pattern_sessions: usize,
    /// Actual retained byte capacity of the session descriptor vector.
    pub session_capacity_bytes: usize,
    /// One logical descriptor initialization per constituent.
    pub session_initialization_work: u64,
    /// Sum of exact constituent workspace construction work.
    pub workspace_setup_work: u64,
    /// Sum of heap payload allocated by constituent workspace construction.
    /// This excludes the separately reported session-vector capacity.
    pub workspace_allocated_bytes: usize,
    /// Sum of payload bytes initialized by constituent workspace construction.
    /// This excludes initialization of the session-vector descriptors.
    pub workspace_initialized_bytes: usize,
    /// Sum of payload bytes retained by constituent workspaces.
    pub workspace_retained_bytes: usize,
    /// Session-vector initialization plus constituent setup work.
    pub charged_setup_work: u64,
    /// Session-vector capacity plus constituent retained payload bytes.
    pub charged_retained_bytes: usize,
}

/// Typed refusal while constructing a reusable byte- or text-set session.
#[derive(Debug)]
#[non_exhaustive]
pub enum PortableRegexSetSessionError {
    PatternSessionLimit {
        needed: usize,
        limit: usize,
    },
    SetupWorkLimit {
        needed: u64,
        limit: u64,
    },
    RetainedBytesLimit {
        needed: usize,
        limit: usize,
    },
    AllocationFailed {
        structure: &'static str,
        additional: usize,
    },
    Pattern {
        /// Stable source-order ID of the constituent that refused setup.
        index: usize,
        /// Exact descriptor and workspace setup work completed for preceding
        /// constituents. This excludes every unpublished descriptor.
        total_setup_work_before: u64,
        /// Descriptor-initialization work reserved for this constituent and
        /// every later unpublished constituent.
        reserved_session_initialization_work: u64,
        /// Aggregate workspace work remaining after reserving unpublished
        /// descriptor initialization.
        remaining_setup_work: u64,
        /// Workspace work actually delegated after applying the per-pattern
        /// limit.
        delegated_setup_work: u64,
        /// Actual vector capacity and preceding workspace bytes retained when
        /// this constituent's setup began.
        total_retained_bytes_before: usize,
        /// Aggregate retained-byte budget remaining at this constituent.
        remaining_retained_bytes: usize,
        /// Scratch bytes actually delegated after applying the per-pattern
        /// limit.
        delegated_retained_bytes: usize,
        source: SearchError,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    InternalInvariant {
        detail: &'static str,
    },
}

impl fmt::Display for PortableRegexSetSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PatternSessionLimit { needed, limit } => write!(
                formatter,
                "portable regex set session needs {needed} pattern slots, limit is {limit}"
            ),
            Self::SetupWorkLimit { needed, limit } => write!(
                formatter,
                "portable regex set session needs {needed} setup work, limit is {limit}"
            ),
            Self::RetainedBytesLimit { needed, limit } => write!(
                formatter,
                "portable regex set session retains {needed} bytes, limit is {limit}"
            ),
            Self::AllocationFailed {
                structure,
                additional,
            } => write!(
                formatter,
                "failed to reserve {additional} entries for regex set {structure}"
            ),
            Self::Pattern {
                index,
                total_setup_work_before,
                reserved_session_initialization_work,
                remaining_setup_work,
                delegated_setup_work,
                total_retained_bytes_before,
                remaining_retained_bytes,
                delegated_retained_bytes,
                source,
            } => write!(
                formatter,
                "portable regex set session pattern {index} failed after {total_setup_work_before} \
                 completed setup work and {total_retained_bytes_before} retained bytes; \
                 {reserved_session_initialization_work} descriptor setup work remained reserved, \
                 leaving {remaining_setup_work} aggregate workspace work and \
                 {remaining_retained_bytes} aggregate bytes, of which {delegated_setup_work} work \
                 and {delegated_retained_bytes} bytes were delegated: {source}"
            ),
            Self::ArithmeticOverflow { computation } => write!(
                formatter,
                "portable regex set session overflow computing {computation}"
            ),
            Self::InternalInvariant { detail } => {
                write!(
                    formatter,
                    "portable regex set session invariant failed: {detail}"
                )
            }
        }
    }
}

impl std::error::Error for PortableRegexSetSessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Pattern { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Exact set-level execution accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortableRegexSetExecutionReport {
    pub start: usize,
    pub patterns_searched: usize,
    pub matched_patterns: usize,
    /// Checked sum of operation-specific existence work from every searched
    /// constituent matcher.
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

pub(crate) fn build_set_session_vector<T>(
    pattern_count: usize,
    limits: PortableRegexSetSessionLimits,
    structure: &'static str,
    mut build: impl FnMut(usize, SearchSessionLimits) -> Result<T, SearchError>,
    setup_accounting: impl Fn(&T) -> Option<SearchSessionSetupAccounting>,
) -> Result<(Vec<T>, PortableRegexSetSessionSetupReport), PortableRegexSetSessionError> {
    if pattern_count > limits.max_pattern_sessions {
        return Err(PortableRegexSetSessionError::PatternSessionLimit {
            needed: pattern_count,
            limit: limits.max_pattern_sessions,
        });
    }
    let session_initialization_work = u64::try_from(pattern_count).map_err(|_| {
        PortableRegexSetSessionError::ArithmeticOverflow {
            computation: "session vector initialization work",
        }
    })?;
    if session_initialization_work > limits.max_total_setup_work {
        return Err(PortableRegexSetSessionError::SetupWorkLimit {
            needed: session_initialization_work,
            limit: limits.max_total_setup_work,
        });
    }
    let logical_session_bytes = pattern_count.checked_mul(size_of::<T>()).ok_or(
        PortableRegexSetSessionError::ArithmeticOverflow {
            computation: "session vector logical bytes",
        },
    )?;
    if logical_session_bytes > limits.max_total_retained_bytes {
        return Err(PortableRegexSetSessionError::RetainedBytesLimit {
            needed: logical_session_bytes,
            limit: limits.max_total_retained_bytes,
        });
    }

    // Keep every descriptor private until the receipt closes. Any error below
    // drops this local vector and every already-constructed constituent
    // session; no partially initialized aggregate can be observed.
    let mut sessions = Vec::new();
    sessions.try_reserve_exact(pattern_count).map_err(|_| {
        PortableRegexSetSessionError::AllocationFailed {
            structure,
            additional: pattern_count,
        }
    })?;
    let session_capacity_bytes = sessions.capacity().checked_mul(size_of::<T>()).ok_or(
        PortableRegexSetSessionError::ArithmeticOverflow {
            computation: "session vector capacity bytes",
        },
    )?;
    if session_capacity_bytes > limits.max_total_retained_bytes {
        return Err(PortableRegexSetSessionError::RetainedBytesLimit {
            needed: session_capacity_bytes,
            limit: limits.max_total_retained_bytes,
        });
    }

    let mut charged_setup_work = 0_u64;
    let mut charged_retained_bytes = session_capacity_bytes;
    let mut workspace_setup_work = 0_u64;
    let mut workspace_allocated_bytes = 0_usize;
    let mut workspace_initialized_bytes = 0_usize;
    let mut workspace_retained_bytes = 0_usize;
    for index in 0..pattern_count {
        let initialized_descriptors = u64::try_from(index).map_err(|_| {
            PortableRegexSetSessionError::ArithmeticOverflow {
                computation: "initialized session descriptor count",
            }
        })?;
        let reserved_session_initialization_work = session_initialization_work
            .checked_sub(initialized_descriptors)
            .ok_or(PortableRegexSetSessionError::InternalInvariant {
                detail: "initialized descriptor count exceeded the session vector",
            })?;
        let setup_work_with_reservation = charged_setup_work
            .checked_add(reserved_session_initialization_work)
            .ok_or(PortableRegexSetSessionError::ArithmeticOverflow {
                computation: "completed and reserved set-session setup work",
            })?;
        let remaining_setup_work = limits
            .max_total_setup_work
            .checked_sub(setup_work_with_reservation)
            .ok_or(PortableRegexSetSessionError::InternalInvariant {
                detail: "completed and reserved setup work exceeded its aggregate limit",
            })?;
        let remaining_retained_bytes = limits
            .max_total_retained_bytes
            .checked_sub(charged_retained_bytes)
            .ok_or(PortableRegexSetSessionError::InternalInvariant {
                detail: "charged retained bytes exceeded their aggregate limit",
            })?;
        let residual = SearchSessionLimits {
            max_setup_work: limits.pattern.max_setup_work.min(remaining_setup_work),
            max_scratch_bytes: limits
                .pattern
                .max_scratch_bytes
                .min(remaining_retained_bytes),
        };
        let session =
            build(index, residual).map_err(|source| PortableRegexSetSessionError::Pattern {
                index,
                total_setup_work_before: charged_setup_work,
                reserved_session_initialization_work,
                remaining_setup_work,
                delegated_setup_work: residual.max_setup_work,
                total_retained_bytes_before: charged_retained_bytes,
                remaining_retained_bytes,
                delegated_retained_bytes: residual.max_scratch_bytes,
                source,
            })?;
        if let Some(setup) = setup_accounting(&session) {
            if setup.work() > residual.max_setup_work
                || setup.retained_bytes() > residual.max_scratch_bytes
            {
                return Err(PortableRegexSetSessionError::InternalInvariant {
                    detail: "constituent setup exceeded its residual admission",
                });
            }
            charged_setup_work = charged_setup_work.checked_add(setup.work()).ok_or(
                PortableRegexSetSessionError::ArithmeticOverflow {
                    computation: "charged set-session setup work",
                },
            )?;
            charged_retained_bytes = charged_retained_bytes
                .checked_add(setup.retained_bytes())
                .ok_or(PortableRegexSetSessionError::ArithmeticOverflow {
                    computation: "charged set-session retained bytes",
                })?;
            workspace_setup_work = workspace_setup_work.checked_add(setup.work()).ok_or(
                PortableRegexSetSessionError::ArithmeticOverflow {
                    computation: "constituent workspace setup work sum",
                },
            )?;
            workspace_allocated_bytes = workspace_allocated_bytes
                .checked_add(setup.allocated_bytes())
                .ok_or(PortableRegexSetSessionError::ArithmeticOverflow {
                    computation: "constituent workspace allocated byte sum",
                })?;
            workspace_initialized_bytes = workspace_initialized_bytes
                .checked_add(setup.initialized_bytes())
                .ok_or(PortableRegexSetSessionError::ArithmeticOverflow {
                    computation: "constituent workspace initialized byte sum",
                })?;
            workspace_retained_bytes = workspace_retained_bytes
                .checked_add(setup.retained_bytes())
                .ok_or(PortableRegexSetSessionError::ArithmeticOverflow {
                    computation: "constituent workspace retained byte sum",
                })?;
        }
        sessions.push(session);
        charged_setup_work = charged_setup_work.checked_add(1).ok_or(
            PortableRegexSetSessionError::ArithmeticOverflow {
                computation: "initialized set-session descriptor work",
            },
        )?;
    }
    if sessions.len() != pattern_count
        || sessions.capacity().checked_mul(size_of::<T>()) != Some(session_capacity_bytes)
        || charged_setup_work
            != session_initialization_work
                .checked_add(workspace_setup_work)
                .ok_or(PortableRegexSetSessionError::ArithmeticOverflow {
                    computation: "set-session setup closure",
                })?
        || charged_retained_bytes
            != session_capacity_bytes
                .checked_add(workspace_retained_bytes)
                .ok_or(PortableRegexSetSessionError::ArithmeticOverflow {
                    computation: "set-session retained-byte closure",
                })?
        || charged_setup_work > limits.max_total_setup_work
        || charged_retained_bytes > limits.max_total_retained_bytes
    {
        return Err(PortableRegexSetSessionError::InternalInvariant {
            detail: "published set-session setup receipt did not close",
        });
    }
    let report = PortableRegexSetSessionSetupReport {
        schema_version: PORTABLE_REGEX_SET_SESSION_SCHEMA_VERSION,
        limits,
        pattern_sessions: pattern_count,
        session_capacity_bytes,
        session_initialization_work,
        workspace_setup_work,
        workspace_allocated_bytes,
        workspace_initialized_bytes,
        workspace_retained_bytes,
        charged_setup_work,
        charged_retained_bytes,
    };
    Ok((sessions, report))
}

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

fn search_one_session(
    session: &mut PortableSearchSession<'_>,
    index: usize,
    haystack: &[u8],
    window: SearchWindow,
    limits: PortableRegexSetRunLimits,
    total_work_before: u64,
) -> Result<(bool, u64), PortableRegexSetExecutionError> {
    let remaining_total_work = limits.max_total_work.checked_sub(total_work_before).ok_or(
        PortableRegexSetExecutionError::ArithmeticOverflow {
            computation: "remaining total session execution work",
        },
    )?;
    let pattern_limits = SearchLimits {
        max_work: limits.pattern.max_work.min(remaining_total_work),
        max_scratch_bytes: limits.pattern.max_scratch_bytes,
    };
    let (matched, accounting) = session
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
            computation: "total session execution work",
        },
    )?;
    if total_work > limits.max_total_work {
        return Err(PortableRegexSetExecutionError::ArithmeticOverflow {
            computation: "session matcher exceeded delegated work limit",
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

const fn set_value_route_is_unlimited(limits: PortableRegexSetRunLimits) -> bool {
    limits.max_total_work == u64::MAX
        && limits.pattern.max_work == u64::MAX
        && limits.pattern.max_scratch_bytes == usize::MAX
}

// Below 128 bytes, a possible literal prefix is cheaper to resolve with the
// already retained source-ordered exact finders than with an O(K) origin probe
// followed by aggregate setup. A leading-byte impossibility still takes the
// fused route at every length.
const FUSED_LITERAL_SET_ORIGIN_PROBE_MIN_BYTES: usize = 128;

#[inline(always)]
fn is_match_window_value_unlimited(
    regex: &PortableRegex,
    haystack: &[u8],
    window: SearchWindow,
) -> Result<bool, SearchError> {
    if let PortablePlan::ExactLiteral(literal) = &regex.plan
        && let Some(executor) = literal.ordinary_executor()
    {
        return executor
            .exists_window_value(haystack, LiteralWindow::new(window.start(), window.end()))
            .map_err(SearchError::from);
    }
    regex.is_match_window_value(haystack, window, SearchLimits::unlimited())
}

#[cold]
#[inline(never)]
fn try_build_fused_exact_literal_exists(
    regexes: &[PortableRegex],
    mut limits: LiteralSetBuildLimits,
    remaining_persistent_bytes: usize,
) -> Option<FusedExactLiteralExists> {
    if regexes.len() < 8 {
        return None;
    }
    let PortablePlan::ExactLiteral(first) = &regexes[0].plan else {
        return None;
    };
    if first.needle().is_empty() {
        return None;
    }
    let mut origin_first_bytes = [0_u64; 4];
    record_first_byte(&mut origin_first_bytes, first.needle()[0]);
    let suffix = &regexes[1..];
    let mut needles = Vec::new();
    needles.try_reserve_exact(suffix.len()).ok()?;
    for regex in suffix {
        let PortablePlan::ExactLiteral(literal) = &regex.plan else {
            return None;
        };
        let needle = literal.needle();
        if needle.is_empty() {
            return None;
        }
        record_first_byte(&mut origin_first_bytes, needle[0]);
        needles.push(needle);
    }
    limits.max_persistent_bytes = limits.max_persistent_bytes.min(remaining_persistent_bytes);
    let plan = LiteralSetPlan::new_stable_borrowed(&needles, limits).ok()?;
    Some(FusedExactLiteralExists {
        plan,
        origin_first_bytes,
    })
}

fn record_first_byte(words: &mut [u64; 4], byte: u8) {
    let word = usize::from(byte) / u64::BITS as usize;
    let bit = usize::from(byte) % u64::BITS as usize;
    words[word] |= 1_u64 << bit;
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
