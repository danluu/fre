//! Independently compiled AOT regex sets with caller-owned result bits.
//!
//! Set membership is deliberately separate from ordered-many selection. Every
//! source row owns a complete [`crate::OutputContract::Exists`] program, and a
//! successful run reports every matching source ordinal. Duplicate patterns
//! therefore retain distinct bits.

use core::fmt;
use std::iter::FusedIterator;
use std::sync::atomic::{AtomicU64, Ordering};

use fre_automata::Automaton;
use fre_lower::{LowerLimits, OperationSemantics};
use fre_syntax::{
    CanonicalPattern, CompatibilityProfile, ParseRequest, RustConstructor, RustMatchKind,
    RustProfile,
};
use sha2::{Digest, Sha256};

use crate::{
    CompileError, CompileMode, DeterminizeLimits, MatchResult, OutputContract, ProgramWorkspace,
    SearchWindow,
    finite_language::{NativeExactSingletonAnalysis, NativeFiniteLanguageCandidate},
    program::CompiledProgram,
};

const REGEX_SET_IDENTITY_DOMAIN: &[u8] = b"FRE-AOT-REGEX-SET\0";
const REGEX_SET_IDENTITY_VERSION: u32 = 1;
const OUTPUT_WORD_BITS: usize = 64;
static NEXT_REGEX_SET_INSTANCE: AtomicU64 = AtomicU64::new(1);

/// Stable digest of one ordered regex-set semantic artifact.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct RegexSetArtifactIdentity([u8; 32]);

impl RegexSetArtifactIdentity {
    /// Return the SHA-256 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Copy the SHA-256 bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RegexSetIdentity {
    artifact: RegexSetArtifactIdentity,
    instance: u64,
}

/// Hard limits for one independently compiled AOT regex set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegexSetCompileLimits {
    /// Maximum number of source patterns. This is a resource limit, not a
    /// representation ceiling, and may be raised beyond 128.
    pub max_patterns: usize,
    /// Maximum sum of source bytes in source order.
    pub max_pattern_bytes: usize,
    /// Per-pattern Thompson lowering and validation limits.
    pub lower: LowerLimits,
    /// Per-pattern ordered determinization limits.
    pub determinize: DeterminizeLimits,
    /// Maximum stable semantic-program bytes for any one pattern.
    pub max_program_bytes_per_pattern: usize,
    /// Maximum sum of stable semantic-program bytes for the complete set.
    pub max_total_program_bytes: usize,
}

impl Default for RegexSetCompileLimits {
    fn default() -> Self {
        Self {
            max_patterns: 4_096,
            max_pattern_bytes: 16 * 1_048_576,
            lower: LowerLimits::default(),
            determinize: DeterminizeLimits::default(),
            max_program_bytes_per_pattern: 256 * 1_048_576,
            max_total_program_bytes: 512 * 1_048_576,
        }
    }
}

/// Complete source-ordered request for one Rust byte-regex set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegexSetCompileRequest {
    pub patterns: Vec<String>,
    pub profile: RustProfile,
    pub mode: CompileMode,
    pub limits: RegexSetCompileLimits,
}

impl RegexSetCompileRequest {
    /// Construct a pinned high-level Rust byte-regex set request.
    #[must_use]
    pub fn new(patterns: Vec<String>) -> Self {
        let profile = RustProfile::regex_set_1_12_4();
        let mut limits = RegexSetCompileLimits::default();
        if let Some(limit) = profile_size_limit(&profile) {
            limits.max_total_program_bytes = limit;
        }
        Self {
            patterns,
            profile,
            mode: CompileMode::Optimizing,
            limits,
        }
    }

    /// Select a high-level Rust profile. A single-regex constructor stamp is
    /// normalized to its corresponding set constructor.
    #[must_use]
    pub fn profile(mut self, profile: RustProfile) -> Self {
        self.profile = profile.into_regex_set_builder();
        self.limits.max_total_program_bytes = profile_size_limit(&self.profile)
            .unwrap_or(RegexSetCompileLimits::default().max_total_program_bytes);
        self
    }

    /// Set the maximum aggregate bytes in FRE's stable compiled programs.
    #[must_use]
    pub fn size_limit(mut self, bytes: usize) -> Self {
        set_profile_size_limit(&mut self.profile, bytes);
        self.limits.max_total_program_bytes = bytes;
        self
    }

    /// Retain the Rust-like lazy-DFA cache option. FRE's AOT programs do not
    /// have such a cache, so this does not change compilation or execution.
    #[must_use]
    pub fn dfa_size_limit(mut self, bytes: usize) -> Self {
        if let RustConstructor::RegexSetBuilder { dfa_size_limit, .. } =
            &mut self.profile.constructor
        {
            *dfa_size_limit = u64::try_from(bytes).unwrap_or(u64::MAX);
        }
        self
    }

    /// Select the semantic compilation mode for every independent pattern.
    #[must_use]
    pub const fn mode(mut self, mode: CompileMode) -> Self {
        self.mode = mode;
        self
    }

    /// Select explicit construction limits.
    #[must_use]
    pub const fn limits(mut self, limits: RegexSetCompileLimits) -> Self {
        self.limits = limits;
        if matches!(
            &self.profile.constructor,
            RustConstructor::RegexSetBuilder { .. }
        ) {
            set_profile_size_limit(&mut self.profile, limits.max_total_program_bytes);
        }
        self
    }
}

fn profile_size_limit(profile: &RustProfile) -> Option<usize> {
    match &profile.constructor {
        RustConstructor::RegexBuilder { size_limit, .. }
        | RustConstructor::RegexSetBuilder { size_limit, .. } => {
            Some(usize::try_from(*size_limit).unwrap_or(usize::MAX))
        }
        RustConstructor::RebarMeta { .. } => None,
    }
}

const fn set_profile_size_limit(profile: &mut RustProfile, bytes: usize) {
    match &mut profile.constructor {
        RustConstructor::RegexBuilder { size_limit, .. }
        | RustConstructor::RegexSetBuilder { size_limit, .. } => {
            // Every Rust 1.93 target pointer width fits in `u64`, so this is
            // equivalent to the former saturating conversion and is const.
            *size_limit = bytes as u64;
        }
        RustConstructor::RebarMeta { .. } => {}
    }
}

/// Aggregate dimensions of one successfully compiled regex set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegexSetProgramStats {
    pub patterns: usize,
    pub pattern_bytes: usize,
    pub serialized_program_bytes: usize,
    pub required_words: usize,
}

/// Failure before a regex-set program is published.
#[derive(Debug)]
#[non_exhaustive]
pub enum RegexSetCompileError {
    PatternLimit {
        needed: usize,
        limit: usize,
    },
    PatternBytesLimit {
        pattern: usize,
        needed: usize,
        limit: usize,
    },
    UnsupportedProfile {
        requirement: &'static str,
    },
    /// Legacy exact-upstream aggregate-admission failure.
    ///
    /// Native-size compilation no longer emits this variant.
    #[deprecated(
        since = "0.1.0",
        note = "aggregate size_limit now reports TotalProgramBytesLimit"
    )]
    AggregateAdmission {
        source: fre_syntax::ParseError,
    },
    /// First indexed constituent compilation failure.
    Pattern {
        pattern: usize,
        source: CompileError,
    },
    TotalProgramBytesLimit {
        pattern: usize,
        needed: usize,
        limit: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    AllocationFailed {
        structure: &'static str,
        entries: usize,
    },
    NonExactCapacity {
        structure: &'static str,
        requested: usize,
        actual: usize,
    },
    InternalInvariant(&'static str),
}

impl fmt::Display for RegexSetCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PatternLimit { needed, limit } => write!(
                formatter,
                "regex-set compilation needs {needed} patterns, limit is {limit}"
            ),
            Self::PatternBytesLimit {
                pattern,
                needed,
                limit,
            } => write!(
                formatter,
                "regex-set pattern {pattern} raises source bytes to {needed}, limit is {limit}"
            ),
            Self::UnsupportedProfile { requirement } => {
                write!(formatter, "unsupported regex-set profile: {requirement}")
            }
            #[allow(deprecated)]
            Self::AggregateAdmission { source } => {
                write!(formatter, "legacy regex-set aggregate admission: {source}")
            }
            Self::Pattern { pattern, source } => {
                write!(formatter, "regex-set pattern {pattern}: {source}")
            }
            Self::TotalProgramBytesLimit {
                pattern,
                needed,
                limit,
            } => write!(
                formatter,
                "regex-set pattern {pattern} raises stable program bytes to {needed}, limit is {limit}"
            ),
            Self::ArithmeticOverflow { computation } => {
                write!(formatter, "regex-set overflow computing {computation}")
            }
            Self::AllocationFailed { structure, entries } => write!(
                formatter,
                "regex-set could not reserve {entries} entries for {structure}"
            ),
            Self::NonExactCapacity {
                structure,
                requested,
                actual,
            } => write!(
                formatter,
                "regex-set {structure} requested exact capacity {requested}, allocator exposed {actual}"
            ),
            Self::InternalInvariant(detail) => {
                write!(formatter, "regex-set invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for RegexSetCompileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Pattern { source, .. } => Some(source),
            #[allow(deprecated)]
            Self::AggregateAdmission { source } => Some(source),
            Self::PatternLimit { .. }
            | Self::PatternBytesLimit { .. }
            | Self::UnsupportedProfile { .. }
            | Self::TotalProgramBytesLimit { .. }
            | Self::ArithmeticOverflow { .. }
            | Self::AllocationFailed { .. }
            | Self::NonExactCapacity { .. }
            | Self::InternalInvariant(_) => None,
        }
    }
}

/// Immutable target-neutral regex-set program.
///
/// The row vector retains its exact source-length capacity. Clones retain the
/// process-local lineage identity as well as every row program's clone
/// lineage, while an independent recompilation receives a new local lineage.
#[derive(Clone, Debug)]
pub struct RegexSetProgram {
    rows: Vec<CompiledProgram>,
    identity: RegexSetIdentity,
    profile: RustProfile,
    mode: CompileMode,
    stats: RegexSetProgramStats,
}

impl RegexSetProgram {
    /// Number of source patterns. Zero is valid and never matches.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether this set has no source patterns.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Exact number of caller-owned `u64` words required by a fill.
    #[must_use]
    pub const fn required_words(&self) -> usize {
        self.stats.required_words
    }

    /// Ordered stable semantic artifact identity.
    #[must_use]
    pub const fn artifact_identity(&self) -> RegexSetArtifactIdentity {
        self.identity.artifact
    }

    /// Aggregate compilation dimensions.
    #[must_use]
    pub const fn stats(&self) -> RegexSetProgramStats {
        self.stats
    }

    /// Rust byte-regex set profile used for aggregate and constituent
    /// admission.
    #[must_use]
    pub const fn profile(&self) -> &RustProfile {
        &self.profile
    }

    /// Per-pattern semantic compilation mode.
    #[must_use]
    pub const fn mode(&self) -> CompileMode {
        self.mode
    }

    /// Prepare one reusable workspace per pattern and private publication
    /// staging words. All retained vectors have exact logical capacity.
    pub fn prepare_session(
        &self,
        limits: RegexSetSessionLimits,
    ) -> Result<RegexSetSession, RegexSetPrepareError> {
        self.validate_program_shape()
            .map_err(RegexSetPrepareError::ProgramShape)?;
        if self.rows.len() > limits.max_workspace_rows {
            return Err(RegexSetPrepareError::WorkspaceRowsLimit {
                needed: self.rows.len(),
                limit: limits.max_workspace_rows,
            });
        }
        if self.required_words() > limits.max_staging_words {
            return Err(RegexSetPrepareError::StagingWordsLimit {
                needed: self.required_words(),
                limit: limits.max_staging_words,
            });
        }

        let mut workspaces = reserve_exact_prepare(self.rows.len(), "program workspaces")?;
        for (pattern, program) in self.rows.iter().enumerate() {
            let workspace = program
                .prepare_workspace()
                .map_err(|source| RegexSetPrepareError::PatternWorkspace { pattern, source })?;
            workspaces.push(workspace);
        }
        validate_exact_capacity_prepare(
            workspaces.capacity(),
            self.rows.len(),
            "program workspaces",
        )?;

        let mut staging = reserve_exact_prepare(self.required_words(), "staging words")?;
        staging.resize(self.required_words(), 0_u64);
        validate_exact_capacity_prepare(
            staging.capacity(),
            self.required_words(),
            "staging words",
        )?;

        Ok(RegexSetSession {
            identity: self.identity,
            pattern_count: self.rows.len(),
            required_words: self.required_words(),
            max_source_bytes: limits.max_source_bytes,
            workspaces,
            staging,
        })
    }

    /// Fill every matching source-index bit using a prepared reusable session.
    ///
    /// `output.len()` must equal [`Self::required_words`]; truncation is never
    /// implicit. Bit `i` corresponds to source pattern `i`, so ascending set
    /// IDs are the natural bit order. The final word's unused high bits are
    /// zero on success. The caller buffer is not changed on any error.
    pub fn fill_matches_with_session(
        &self,
        session: &mut RegexSetSession,
        haystack: &[u8],
        window: SearchWindow,
        output: &mut [u64],
    ) -> Result<RegexSetFillReport, RegexSetRunError> {
        self.preflight(session, haystack.len(), window, output.len())?;

        session.staging.fill(0);
        let mut matched_count = 0usize;
        for (pattern, (program, workspace)) in self
            .rows
            .iter()
            .zip(session.workspaces.iter_mut())
            .enumerate()
        {
            let matched = program
                .search_optimized_with_workspace(haystack, window, workspace)
                .map_err(|source| RegexSetRunError::PatternSearch { pattern, source })?;
            let MatchResult::Exists(matched) = matched else {
                return Err(RegexSetRunError::InternalInvariant(
                    "regex-set row lost its Exists output contract",
                ));
            };
            if matched {
                let word = pattern / OUTPUT_WORD_BITS;
                let bit = pattern % OUTPUT_WORD_BITS;
                let slot =
                    session
                        .staging
                        .get_mut(word)
                        .ok_or(RegexSetRunError::InternalInvariant(
                            "matching pattern exceeded the staging bitset",
                        ))?;
                *slot |= 1_u64 << bit;
                matched_count =
                    matched_count
                        .checked_add(1)
                        .ok_or(RegexSetRunError::ArithmeticOverflow {
                            computation: "matched pattern count",
                        })?;
            }
        }

        if let Some(last) = session.staging.last_mut() {
            *last &= tail_mask(self.rows.len());
        }
        output.copy_from_slice(&session.staging);
        Ok(RegexSetFillReport {
            matched_count,
            word_count: self.required_words(),
        })
    }

    /// Validate and iterate a completed result bitset in ascending source-ID
    /// order without allocating.
    pub fn matching_pattern_ids<'bits>(
        &self,
        bits: &'bits [u64],
    ) -> Result<RegexSetPatternIds<'bits>, RegexSetOutputError> {
        if bits.len() != self.required_words() {
            return Err(RegexSetOutputError::WordCount {
                expected: self.required_words(),
                actual: bits.len(),
            });
        }
        if let Some(&last) = bits.last() {
            let allowed = tail_mask(self.rows.len());
            if last & !allowed != 0 {
                let word =
                    bits.len()
                        .checked_sub(1)
                        .ok_or(RegexSetOutputError::ArithmeticOverflow {
                            computation: "tail word index",
                        })?;
                return Err(RegexSetOutputError::NonZeroTailBits {
                    word,
                    value: last,
                    allowed_mask: allowed,
                });
            }
        }
        let remaining = bits.iter().try_fold(0usize, |total, word| {
            let ones = usize::try_from(word.count_ones()).map_err(|_| {
                RegexSetOutputError::ArithmeticOverflow {
                    computation: "set-bit population",
                }
            })?;
            total
                .checked_add(ones)
                .ok_or(RegexSetOutputError::ArithmeticOverflow {
                    computation: "set-bit population sum",
                })
        })?;
        Ok(RegexSetPatternIds {
            words: bits,
            pattern_count: self.rows.len(),
            word_index: 0,
            current: bits.first().copied().unwrap_or(0),
            remaining,
        })
    }

    fn validate_program_shape(&self) -> Result<(), RegexSetProgramShapeError> {
        if self.rows.capacity() != self.rows.len() {
            return Err(RegexSetProgramShapeError {
                structure: "compiled rows",
                expected: self.rows.len(),
                actual: self.rows.capacity(),
            });
        }
        let expected_words = required_words(self.rows.len()).ok_or(RegexSetProgramShapeError {
            structure: "required output words",
            expected: self.stats.required_words,
            actual: usize::MAX,
        })?;
        if self.stats.patterns != self.rows.len() || self.stats.required_words != expected_words {
            return Err(RegexSetProgramShapeError {
                structure: "program statistics",
                expected: self.rows.len(),
                actual: self.stats.patterns,
            });
        }
        Ok(())
    }

    fn preflight(
        &self,
        session: &RegexSetSession,
        haystack_len: usize,
        window: SearchWindow,
        output_words: usize,
    ) -> Result<(), RegexSetRunError> {
        self.validate_program_shape()
            .map_err(RegexSetRunError::ProgramShape)?;
        if self.identity != session.identity {
            return Err(RegexSetRunError::SessionProgramMismatch {
                expected_artifact: self.identity.artifact,
                actual_artifact: session.identity.artifact,
                clone_lineage_matches: self.identity.instance == session.identity.instance,
            });
        }
        validate_session_shape(session, self.rows.len(), self.required_words())?;
        if output_words != self.required_words() {
            return Err(RegexSetRunError::OutputWordCount {
                expected: self.required_words(),
                actual: output_words,
            });
        }
        if haystack_len > session.max_source_bytes {
            return Err(RegexSetRunError::SourceBytesLimit {
                needed: haystack_len,
                limit: session.max_source_bytes,
            });
        }
        if window.start() > window.end() || window.end() > haystack_len {
            return Err(RegexSetRunError::InvalidWindow {
                start: window.start(),
                end: window.end(),
                haystack_len,
            });
        }
        for (pattern, (program, workspace)) in
            self.rows.iter().zip(session.workspaces.iter()).enumerate()
        {
            program
                .authenticate_workspace(workspace)
                .map_err(|source| RegexSetRunError::PatternWorkspace { pattern, source })?;
        }
        Ok(())
    }
}

/// Limits applied while preparing and reusing a regex-set session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegexSetSessionLimits {
    /// Maximum independently prepared row workspaces.
    pub max_workspace_rows: usize,
    /// Maximum private staging words.
    pub max_staging_words: usize,
    /// Maximum complete haystack length accepted by a run.
    pub max_source_bytes: usize,
}

impl RegexSetSessionLimits {
    /// Disable caller-selected limits while retaining checked arithmetic and
    /// exact-capacity allocation.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_workspace_rows: usize::MAX,
            max_staging_words: usize::MAX,
            max_source_bytes: usize::MAX,
        }
    }
}

impl Default for RegexSetSessionLimits {
    fn default() -> Self {
        Self {
            max_workspace_rows: 4_096,
            max_staging_words: 64,
            max_source_bytes: 128 * 1_048_576,
        }
    }
}

/// Failure while preparing exact reusable set storage.
#[derive(Debug)]
#[non_exhaustive]
pub enum RegexSetPrepareError {
    WorkspaceRowsLimit {
        needed: usize,
        limit: usize,
    },
    StagingWordsLimit {
        needed: usize,
        limit: usize,
    },
    PatternWorkspace {
        pattern: usize,
        source: CompileError,
    },
    AllocationFailed {
        structure: &'static str,
        entries: usize,
    },
    NonExactCapacity {
        structure: &'static str,
        requested: usize,
        actual: usize,
    },
    ProgramShape(RegexSetProgramShapeError),
}

impl fmt::Display for RegexSetPrepareError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkspaceRowsLimit { needed, limit } => write!(
                formatter,
                "regex-set session needs {needed} row workspaces, limit is {limit}"
            ),
            Self::StagingWordsLimit { needed, limit } => write!(
                formatter,
                "regex-set session needs {needed} staging words, limit is {limit}"
            ),
            Self::PatternWorkspace { pattern, source } => {
                write!(formatter, "regex-set pattern {pattern} workspace: {source}")
            }
            Self::AllocationFailed { structure, entries } => write!(
                formatter,
                "regex-set session could not reserve {entries} entries for {structure}"
            ),
            Self::NonExactCapacity {
                structure,
                requested,
                actual,
            } => write!(
                formatter,
                "regex-set session {structure} requested exact capacity {requested}, allocator exposed {actual}"
            ),
            Self::ProgramShape(source) => write!(formatter, "regex-set program shape: {source}"),
        }
    }
}

impl std::error::Error for RegexSetPrepareError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PatternWorkspace { source, .. } => Some(source),
            Self::ProgramShape(source) => Some(source),
            Self::WorkspaceRowsLimit { .. }
            | Self::StagingWordsLimit { .. }
            | Self::AllocationFailed { .. }
            | Self::NonExactCapacity { .. } => None,
        }
    }
}

/// Reusable, allocation-free warm execution state.
#[derive(Debug)]
pub struct RegexSetSession {
    identity: RegexSetIdentity,
    pattern_count: usize,
    required_words: usize,
    max_source_bytes: usize,
    workspaces: Vec<ProgramWorkspace>,
    staging: Vec<u64>,
}

impl RegexSetSession {
    /// Number of independently prepared workspaces.
    #[must_use]
    pub const fn pattern_count(&self) -> usize {
        self.pattern_count
    }

    /// Exact number of private publication words.
    #[must_use]
    pub const fn required_words(&self) -> usize {
        self.required_words
    }

    /// Maximum admitted complete haystack length.
    #[must_use]
    pub const fn max_source_bytes(&self) -> usize {
        self.max_source_bytes
    }
}

/// Compact report for one complete transactional fill.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegexSetFillReport {
    matched_count: usize,
    word_count: usize,
}

impl RegexSetFillReport {
    /// Number of matching source pattern IDs.
    #[must_use]
    pub const fn matched_count(self) -> usize {
        self.matched_count
    }

    /// Number of caller words published by the successful transaction.
    #[must_use]
    pub const fn word_count(self) -> usize {
        self.word_count
    }

    /// Whether at least one pattern matched.
    #[must_use]
    pub const fn any(self) -> bool {
        self.matched_count != 0
    }
}

/// Failure during a prepared set run. The caller output remains unchanged.
#[derive(Debug)]
#[non_exhaustive]
pub enum RegexSetRunError {
    SessionProgramMismatch {
        expected_artifact: RegexSetArtifactIdentity,
        actual_artifact: RegexSetArtifactIdentity,
        clone_lineage_matches: bool,
    },
    ProgramShape(RegexSetProgramShapeError),
    SessionShape {
        structure: &'static str,
        expected: usize,
        actual: usize,
    },
    OutputWordCount {
        expected: usize,
        actual: usize,
    },
    SourceBytesLimit {
        needed: usize,
        limit: usize,
    },
    InvalidWindow {
        start: usize,
        end: usize,
        haystack_len: usize,
    },
    PatternWorkspace {
        pattern: usize,
        source: CompileError,
    },
    PatternSearch {
        pattern: usize,
        source: CompileError,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    InternalInvariant(&'static str),
}

impl fmt::Display for RegexSetRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SessionProgramMismatch {
                clone_lineage_matches,
                ..
            } => write!(
                formatter,
                "regex-set session belongs to another program (clone lineage match: {clone_lineage_matches})"
            ),
            Self::ProgramShape(source) => write!(formatter, "regex-set program shape: {source}"),
            Self::SessionShape {
                structure,
                expected,
                actual,
            } => write!(
                formatter,
                "regex-set session {structure} has shape {actual}, expected {expected}"
            ),
            Self::OutputWordCount { expected, actual } => write!(
                formatter,
                "regex-set output has {actual} words, exactly {expected} required"
            ),
            Self::SourceBytesLimit { needed, limit } => write!(
                formatter,
                "regex-set run needs {needed} source bytes, limit is {limit}"
            ),
            Self::InvalidWindow {
                start,
                end,
                haystack_len,
            } => write!(
                formatter,
                "invalid regex-set window {start}..{end} for haystack length {haystack_len}"
            ),
            Self::PatternWorkspace { pattern, source } => {
                write!(formatter, "regex-set pattern {pattern} workspace: {source}")
            }
            Self::PatternSearch { pattern, source } => {
                write!(formatter, "regex-set pattern {pattern} search: {source}")
            }
            Self::ArithmeticOverflow { computation } => {
                write!(formatter, "regex-set run overflow computing {computation}")
            }
            Self::InternalInvariant(detail) => {
                write!(formatter, "regex-set run invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for RegexSetRunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ProgramShape(source) => Some(source),
            Self::PatternWorkspace { source, .. } | Self::PatternSearch { source, .. } => {
                Some(source)
            }
            Self::SessionProgramMismatch { .. }
            | Self::SessionShape { .. }
            | Self::OutputWordCount { .. }
            | Self::SourceBytesLimit { .. }
            | Self::InvalidWindow { .. }
            | Self::ArithmeticOverflow { .. }
            | Self::InternalInvariant(_) => None,
        }
    }
}

/// Validation failure for a standalone completed output bitset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RegexSetOutputError {
    WordCount {
        expected: usize,
        actual: usize,
    },
    NonZeroTailBits {
        word: usize,
        value: u64,
        allowed_mask: u64,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
}

impl fmt::Display for RegexSetOutputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WordCount { expected, actual } => write!(
                formatter,
                "regex-set result has {actual} words, exactly {expected} required"
            ),
            Self::NonZeroTailBits {
                word,
                value,
                allowed_mask,
            } => write!(
                formatter,
                "regex-set result word {word} is {value:#x}, allowed tail mask is {allowed_mask:#x}"
            ),
            Self::ArithmeticOverflow { computation } => {
                write!(
                    formatter,
                    "regex-set result overflow computing {computation}"
                )
            }
        }
    }
}

impl std::error::Error for RegexSetOutputError {}

/// Allocation-free ascending iterator over matching source pattern IDs.
#[derive(Clone, Debug)]
pub struct RegexSetPatternIds<'bits> {
    words: &'bits [u64],
    pattern_count: usize,
    word_index: usize,
    current: u64,
    remaining: usize,
}

impl Iterator for RegexSetPatternIds<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.current != 0 {
                let bit = usize::try_from(self.current.trailing_zeros()).ok()?;
                self.current &= self.current.checked_sub(1)?;
                self.remaining = self.remaining.checked_sub(1)?;
                let pattern = self
                    .word_index
                    .checked_mul(OUTPUT_WORD_BITS)?
                    .checked_add(bit)?;
                return (pattern < self.pattern_count).then_some(pattern);
            }
            self.word_index = self.word_index.checked_add(1)?;
            self.current = self.words.get(self.word_index).copied().unwrap_or(0);
            if self.word_index >= self.words.len() {
                return None;
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for RegexSetPatternIds<'_> {}
impl FusedIterator for RegexSetPatternIds<'_> {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegexSetProgramShapeError {
    pub structure: &'static str,
    pub expected: usize,
    pub actual: usize,
}

impl fmt::Display for RegexSetProgramShapeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} has shape {}, expected {}",
            self.structure, self.actual, self.expected
        )
    }
}

impl std::error::Error for RegexSetProgramShapeError {}

/// Compile a complete Rust byte-regex set from independently executable
/// existence programs.
///
/// Syntax is parsed once per source row and the aggregate size limit is
/// applied directly to FRE's stable compiled programs.
pub fn compile_regex_set(
    request: RegexSetCompileRequest,
) -> Result<RegexSetProgram, RegexSetCompileError> {
    Ok(compile_regex_set_internal(request, None)?.program)
}

pub(crate) struct RegexSetExact64CompileParts {
    pub(crate) program: RegexSetProgram,
    pub(crate) witnesses: Vec<Option<Vec<u8>>>,
    pub(crate) witness_decline: Option<RegexSetExact64WitnessDecline>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RegexSetExact64WitnessDecline {
    RowNotExactSingleton { pattern: usize },
    LiteralBytes { needed: u64, limit: u64 },
}

pub(crate) fn compile_regex_set_with_exact64_witnesses(
    request: RegexSetCompileRequest,
    max_literal_bytes: usize,
) -> Result<RegexSetExact64CompileParts, RegexSetCompileError> {
    let RegexSetCompileParts {
        program,
        witnesses,
        witness_decline,
    } = compile_regex_set_internal(request, Some(max_literal_bytes))?;
    let witnesses = witnesses.ok_or(RegexSetCompileError::InternalInvariant(
        "exact64 regex-set compilation omitted its witness table",
    ))?;
    Ok(RegexSetExact64CompileParts {
        program,
        witnesses,
        witness_decline,
    })
}

struct RegexSetCompileParts {
    program: RegexSetProgram,
    witnesses: Option<Vec<Option<Vec<u8>>>>,
    witness_decline: Option<RegexSetExact64WitnessDecline>,
}

#[allow(
    clippy::too_many_lines,
    reason = "aggregate admission, exact row allocation, optional authenticated witness capture, indexed compilation, and identity publication form one transaction"
)]
fn compile_regex_set_internal(
    request: RegexSetCompileRequest,
    exact64_max_literal_bytes: Option<usize>,
) -> Result<RegexSetCompileParts, RegexSetCompileError> {
    let RegexSetCompileRequest {
        patterns,
        profile,
        mode,
        mut limits,
    } = request;
    let profile = profile.into_regex_set_builder();
    validate_profile(&profile)?;
    if let Some(profile_limit) = profile_size_limit(&profile) {
        limits.max_total_program_bytes = limits.max_total_program_bytes.min(profile_limit);
    }
    let pattern_count = patterns.len();
    if pattern_count > limits.max_patterns {
        return Err(RegexSetCompileError::PatternLimit {
            needed: pattern_count,
            limit: limits.max_patterns,
        });
    }
    let mut pattern_bytes = 0usize;
    for (pattern, source) in patterns.iter().enumerate() {
        pattern_bytes = pattern_bytes.checked_add(source.len()).ok_or(
            RegexSetCompileError::ArithmeticOverflow {
                computation: "source byte sum",
            },
        )?;
        if pattern_bytes > limits.max_pattern_bytes {
            return Err(RegexSetCompileError::PatternBytesLimit {
                pattern,
                needed: pattern_bytes,
                limit: limits.max_pattern_bytes,
            });
        }
    }
    let required_words =
        required_words(pattern_count).ok_or(RegexSetCompileError::ArithmeticOverflow {
            computation: "required output words",
        })?;
    let compatibility = CompatibilityProfile::RustBytes(profile.clone());

    let mut rows = reserve_exact_compile(pattern_count, "compiled rows")?;
    let mut witnesses = exact64_max_literal_bytes
        .map(|_| reserve_exact_compile(pattern_count, "exact64 literal witnesses"))
        .transpose()?;
    let mut witness_decline = None;
    let mut exact64_literal_bytes = 0usize;
    let line_terminator = profile.options.line_terminator;
    let mut total_program_bytes = 0usize;
    for (pattern, source) in patterns.into_iter().enumerate() {
        let parsed = fre_syntax::parse(ParseRequest::rust(source, compatibility.clone()))
            .map_err(CompileError::from)
            .map_err(|source| RegexSetCompileError::Pattern { pattern, source })?;
        let CanonicalPattern::Rust(parsed) = parsed.pattern else {
            return Err(RegexSetCompileError::Pattern {
                pattern,
                source: CompileError::InternalInvariant(
                    "Rust byte set request produced a non-Rust syntax tree",
                ),
            });
        };
        let raw =
            fre_lower::lower_raw_general(&parsed, OperationSemantics::CaptureFree, limits.lower)
                .map_err(CompileError::from)
                .map_err(|source| RegexSetCompileError::Pattern { pattern, source })?
                .into_plan();
        let automaton = Automaton::from_raw(raw.clone(), limits.lower.automata)
            .map_err(CompileError::from)
            .map_err(|source| RegexSetCompileError::Pattern { pattern, source })?
            .with_line_terminator(line_terminator);
        let program = CompiledProgram::build(
            raw,
            automaton,
            OutputContract::Exists,
            mode,
            limits.determinize,
            limits.max_program_bytes_per_pattern,
        )
        .map_err(|source| RegexSetCompileError::Pattern { pattern, source })?;
        let program_bytes = program
            .serialized_len()
            .map_err(|source| RegexSetCompileError::Pattern { pattern, source })?;
        total_program_bytes = total_program_bytes.checked_add(program_bytes).ok_or(
            RegexSetCompileError::ArithmeticOverflow {
                computation: "stable semantic-program byte sum",
            },
        )?;
        if total_program_bytes > limits.max_total_program_bytes {
            return Err(RegexSetCompileError::TotalProgramBytesLimit {
                pattern,
                needed: total_program_bytes,
                limit: limits.max_total_program_bytes,
            });
        }
        if let Some(witnesses) = &mut witnesses {
            let witness = if matches!(
                witness_decline,
                Some(RegexSetExact64WitnessDecline::RowNotExactSingleton { .. })
            ) {
                None
            } else if matches!(
                witness_decline,
                Some(RegexSetExact64WitnessDecline::LiteralBytes { .. })
            ) {
                let exact = NativeFiniteLanguageCandidate::preflight_exact_singleton_checked(
                    &parsed,
                    OutputContract::Exists,
                )
                .map_err(CompileError::from)
                .map_err(|source| RegexSetCompileError::Pattern { pattern, source })?;
                if !exact {
                    witness_decline =
                        Some(RegexSetExact64WitnessDecline::RowNotExactSingleton { pattern });
                }
                None
            } else {
                let limit =
                    exact64_max_literal_bytes.ok_or(RegexSetCompileError::InternalInvariant(
                        "exact64 witness table lacked its literal-byte ceiling",
                    ))?;
                let remaining = limit.checked_sub(exact64_literal_bytes).ok_or(
                    RegexSetCompileError::InternalInvariant(
                        "exact64 literal-byte census exceeded its ceiling",
                    ),
                )?;
                let witness = match NativeFiniteLanguageCandidate::analyze_exact_singleton_checked(
                    &parsed,
                    OutputContract::Exists,
                    remaining,
                ) {
                    Ok(result) => result,
                    Err(source) => {
                        return Err(RegexSetCompileError::Pattern {
                            pattern,
                            source: CompileError::from(source),
                        });
                    }
                };
                match witness {
                    NativeExactSingletonAnalysis::Proven(literal) => {
                        let needed = exact64_literal_bytes.checked_add(literal.len()).ok_or(
                            RegexSetCompileError::ArithmeticOverflow {
                                computation: "exact64 literal byte sum",
                            },
                        )?;
                        if needed > limit {
                            let needed = u64::try_from(needed).map_err(|_| {
                                RegexSetCompileError::ArithmeticOverflow {
                                    computation: "exact64 literal byte requirement",
                                }
                            })?;
                            let limit = u64::try_from(limit).map_err(|_| {
                                RegexSetCompileError::ArithmeticOverflow {
                                    computation: "exact64 literal byte limit",
                                }
                            })?;
                            witness_decline =
                                Some(RegexSetExact64WitnessDecline::LiteralBytes { needed, limit });
                            None
                        } else {
                            exact64_literal_bytes = needed;
                            Some(literal)
                        }
                    }
                    NativeExactSingletonAnalysis::Declined => {
                        witness_decline =
                            Some(RegexSetExact64WitnessDecline::RowNotExactSingleton { pattern });
                        None
                    }
                    NativeExactSingletonAnalysis::LiteralBytesLimit {
                        needed,
                        limit: proof_limit,
                    } => {
                        let expected_limit = u64::try_from(remaining).map_err(|_| {
                            RegexSetCompileError::ArithmeticOverflow {
                                computation: "exact64 remaining literal byte limit",
                            }
                        })?;
                        if proof_limit != expected_limit || needed <= proof_limit {
                            return Err(RegexSetCompileError::InternalInvariant(
                                "exact64 fact refusal did not authenticate its byte ceiling",
                            ));
                        }
                        let retained = u64::try_from(exact64_literal_bytes).map_err(|_| {
                            RegexSetCompileError::ArithmeticOverflow {
                                computation: "exact64 retained literal bytes",
                            }
                        })?;
                        let aggregate_needed = retained.checked_add(needed).ok_or(
                            RegexSetCompileError::ArithmeticOverflow {
                                computation: "exact64 refused literal byte sum",
                            },
                        )?;
                        let aggregate_limit = u64::try_from(limit).map_err(|_| {
                            RegexSetCompileError::ArithmeticOverflow {
                                computation: "exact64 aggregate literal byte limit",
                            }
                        })?;
                        witness_decline = Some(RegexSetExact64WitnessDecline::LiteralBytes {
                            needed: aggregate_needed,
                            limit: aggregate_limit,
                        });
                        None
                    }
                }
            };
            witnesses.push(witness);
        }
        rows.push(program);
    }
    if rows.len() != pattern_count {
        return Err(RegexSetCompileError::InternalInvariant(
            "compiled row table lost source order",
        ));
    }
    validate_exact_capacity_compile(rows.capacity(), pattern_count, "compiled rows")?;
    if let Some(witnesses) = &witnesses {
        if witnesses.len() != pattern_count {
            return Err(RegexSetCompileError::InternalInvariant(
                "exact64 witness table lost source order",
            ));
        }
        validate_exact_capacity_compile(
            witnesses.capacity(),
            pattern_count,
            "exact64 literal witnesses",
        )?;
    }
    let artifact = semantic_identity(&rows)?;
    let instance = next_instance()?;
    Ok(RegexSetCompileParts {
        program: RegexSetProgram {
            rows,
            identity: RegexSetIdentity { artifact, instance },
            profile,
            mode,
            stats: RegexSetProgramStats {
                patterns: pattern_count,
                pattern_bytes,
                serialized_program_bytes: total_program_bytes,
                required_words,
            },
        },
        witnesses,
        witness_decline,
    })
}

fn validate_profile(profile: &RustProfile) -> Result<(), RegexSetCompileError> {
    let compatible = matches!(
        &profile.constructor,
        RustConstructor::RegexSetBuilder {
            bytes_syntax_utf8: false,
            bytes_utf8_empty: false,
            match_kind: RustMatchKind::LeftmostFirst,
            ..
        }
    );
    if compatible {
        Ok(())
    } else {
        Err(RegexSetCompileError::UnsupportedProfile {
            requirement: "high-level leftmost-first Rust byte RegexSet with byte-progress empty matches",
        })
    }
}

fn semantic_identity(
    rows: &[CompiledProgram],
) -> Result<RegexSetArtifactIdentity, RegexSetCompileError> {
    let count =
        u64::try_from(rows.len()).map_err(|_| RegexSetCompileError::ArithmeticOverflow {
            computation: "artifact row count",
        })?;
    let mut digest = Sha256::new();
    digest.update(REGEX_SET_IDENTITY_DOMAIN);
    digest.update(REGEX_SET_IDENTITY_VERSION.to_le_bytes());
    digest.update(count.to_le_bytes());
    for (ordinal, row) in rows.iter().enumerate() {
        let ordinal =
            u64::try_from(ordinal).map_err(|_| RegexSetCompileError::ArithmeticOverflow {
                computation: "artifact source ordinal",
            })?;
        digest.update(ordinal.to_le_bytes());
        digest.update(row.artifact_identity());
    }
    Ok(RegexSetArtifactIdentity(digest.finalize().into()))
}

fn next_instance() -> Result<u64, RegexSetCompileError> {
    NEXT_REGEX_SET_INSTANCE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |identity| {
            identity.checked_add(1)
        })
        .map_err(|_| RegexSetCompileError::InternalInvariant("set instance identity exhausted"))
}

fn required_words(patterns: usize) -> Option<usize> {
    let complete = patterns / OUTPUT_WORD_BITS;
    if patterns.is_multiple_of(OUTPUT_WORD_BITS) {
        Some(complete)
    } else {
        complete.checked_add(1)
    }
}

fn tail_mask(patterns: usize) -> u64 {
    let tail = patterns % OUTPUT_WORD_BITS;
    if tail == 0 {
        u64::MAX
    } else {
        (1_u64 << tail).saturating_sub(1)
    }
}

fn validate_session_shape(
    session: &RegexSetSession,
    expected_patterns: usize,
    expected_words: usize,
) -> Result<(), RegexSetRunError> {
    let shapes = [
        ("pattern count", expected_patterns, session.pattern_count),
        ("required words", expected_words, session.required_words),
        (
            "workspace length",
            expected_patterns,
            session.workspaces.len(),
        ),
        (
            "workspace capacity",
            expected_patterns,
            session.workspaces.capacity(),
        ),
        ("staging length", expected_words, session.staging.len()),
        (
            "staging capacity",
            expected_words,
            session.staging.capacity(),
        ),
    ];
    for (structure, expected, actual) in shapes {
        if actual != expected {
            return Err(RegexSetRunError::SessionShape {
                structure,
                expected,
                actual,
            });
        }
    }
    Ok(())
}

fn reserve_exact_compile<T>(
    entries: usize,
    structure: &'static str,
) -> Result<Vec<T>, RegexSetCompileError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(entries)
        .map_err(|_| RegexSetCompileError::AllocationFailed { structure, entries })?;
    validate_exact_capacity_compile(values.capacity(), entries, structure)?;
    Ok(values)
}

fn validate_exact_capacity_compile(
    actual: usize,
    requested: usize,
    structure: &'static str,
) -> Result<(), RegexSetCompileError> {
    if actual != requested {
        return Err(RegexSetCompileError::NonExactCapacity {
            structure,
            requested,
            actual,
        });
    }
    Ok(())
}

fn reserve_exact_prepare<T>(
    entries: usize,
    structure: &'static str,
) -> Result<Vec<T>, RegexSetPrepareError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(entries)
        .map_err(|_| RegexSetPrepareError::AllocationFailed { structure, entries })?;
    validate_exact_capacity_prepare(values.capacity(), entries, structure)?;
    Ok(values)
}

fn validate_exact_capacity_prepare(
    actual: usize,
    requested: usize,
    structure: &'static str,
) -> Result<(), RegexSetPrepareError> {
    if actual != requested {
        return Err(RegexSetPrepareError::NonExactCapacity {
            structure,
            requested,
            actual,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        RegexSetCompileRequest, RegexSetRunError, RegexSetSessionLimits, compile_regex_set,
        required_words, tail_mask,
    };
    use crate::{CompileMode, SearchWindow};

    #[test]
    fn bit_geometry_is_exact_at_word_boundaries() {
        assert_eq!(Some(0), required_words(0));
        assert_eq!(Some(1), required_words(1));
        assert_eq!(Some(1), required_words(64));
        assert_eq!(Some(2), required_words(65));
        assert_eq!(u64::MAX, tail_mask(0));
        assert_eq!(u64::MAX, tail_mask(64));
        assert_eq!(1, tail_mask(65));
    }

    #[test]
    fn every_row_workspace_is_authenticated_before_execution() {
        let program = compile_regex_set(
            RegexSetCompileRequest::new(vec!["a".to_owned(), "b".to_owned(), "c".to_owned()])
                .mode(CompileMode::Fast),
        )
        .unwrap();
        let mut session = program
            .prepare_session(RegexSetSessionLimits::unlimited())
            .unwrap();
        // Row zero remains valid. A runner that authenticated only the outer
        // set identity would begin executing it before discovering that the
        // later row workspaces were exchanged.
        session.workspaces.swap(1, 2);
        let sentinel = 0xfeed_face_dead_beef;
        let mut output = [sentinel];
        assert!(matches!(
            program.fill_matches_with_session(
                &mut session,
                b"a",
                SearchWindow::new(0, 1),
                &mut output,
            ),
            Err(RegexSetRunError::PatternWorkspace { pattern: 1, .. })
        ));
        assert_eq!([sentinel], output);
    }
}
