//! Receipt-correct packed reducers for small ordered literal sets.
//!
//! The retained owner is entirely FRE controlled. It contains one
//! length-prefixed copy of the ordered patterns, fixed metadata, a fixed
//! first-byte-to-pattern map and one already-dispatched ASCII classifier.
//! Construction publishes that owner through one exact fallible allocation.
//! The operation walks candidate starts monotonically, verifies pattern IDs in
//! source order and never allocates.
//!
//! This kernel intentionally knows nothing about Unicode boundaries. It
//! implements ordered, nonempty byte strings. A facade may bind either
//! Unicode-off byte semantics or a separately proved set of complete UTF-8
//! words to that byte-string contract.

use core::{fmt, mem::size_of};

use fre_exact_alloc::{CopyError, try_box_preserve};
use fre_simd_kernels::{
    AsciiByteSet, AsciiByteSetClassifier, AsciiSelection, DispatchPolicy, SimdDispatchContext,
};

use crate::ordered_literal_aggregate::{IterationSemantics, MatchSemantics, Operation};

const CACHE_FORMAT_VERSION: u32 = 2;
const LENGTH_PREFIX_BYTES: usize = size_of::<u64>();
const IDENTITY_CAPACITY_BYTES: usize = LENGTH_PREFIX_BYTES
    + CERTIFIED_MAX_PATTERNS * LENGTH_PREFIX_BYTES
    + CERTIFIED_MAX_TOTAL_PATTERN_BYTES;
const CLASSIFIER_BUILD_WORK: usize = 128;
const SIMD_BLOCK_BYTES: usize = 32;

/// Smallest admitted ordered set. Singletons already have a stronger direct
/// literal implementation.
pub const CERTIFIED_MIN_PATTERNS: usize = 2;
/// Absolute theorem bound, independent of caller limits.
pub const CERTIFIED_MAX_PATTERNS: usize = 16;
/// Smallest admitted literal. One-byte sets are deliberately left to the
/// existing byte-class reducers until separately qualified.
pub const CERTIFIED_MIN_PATTERN_BYTES: usize = 2;
/// Absolute theorem bound, independent of caller limits.
pub const CERTIFIED_MAX_PATTERN_BYTES: usize = 32;
/// Absolute theorem bound, independent of caller limits.
pub const CERTIFIED_MAX_TOTAL_PATTERN_BYTES: usize = 512;
/// Stable FRE-owned strategy identity.
pub const ALGORITHM_ID: &str = "ordered-literal-aggregate.packed-first-byte-stream.v2";
/// Stable count-plan identity.
pub const COUNT_PLAN_ID: &str = "ordered-literal-aggregate.count.packed-first-byte-stream.v2";
/// Stable span-sum-plan identity.
pub const SPAN_SUM_PLAN_ID: &str = "ordered-literal-aggregate.span-sum.packed-first-byte-stream.v2";
/// Version of the success-or-failure construction protocol.
pub const BUILD_ATTEMPT_ALGORITHM_VERSION: u32 = 1;
/// Version of the partial-actual construction ledger.
pub const BUILD_ATTEMPT_ACCOUNTING_VERSION: u32 = 2;

/// Boundary contract owned by this byte-string kernel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundarySemantics {
    /// Every alternative is nonempty. Character-boundary validity, when
    /// required, is proved and bound by the caller.
    NonemptyByteStrings,
}

/// Exact matching semantics represented by the cache identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Semantics {
    pub match_semantics: MatchSemantics,
    pub iteration_semantics: IterationSemantics,
    pub boundary_semantics: BoundarySemantics,
}

const SEMANTICS: Semantics = Semantics {
    match_semantics: MatchSemantics::LeftmostFirst,
    iteration_semantics: IterationSemantics::NonOverlapping,
    boundary_semantics: BoundarySemantics::NonemptyByteStrings,
};

/// Collision-free process-local semantic identity for one packed plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheIdentity<'a> {
    pub algorithm_id: &'static str,
    pub plan_id: &'static str,
    pub operation: Operation,
    pub cache_format_version: u32,
    pub implementation_kind: &'static str,
    pub identity_scope: &'static str,
    pub target_arch: &'static str,
    pub runtime_minimum_haystack_bytes: usize,
    pub semantics: Semantics,
    pub classifier_selection: AsciiSelection,
    pub certified_min_patterns: usize,
    pub certified_max_patterns: usize,
    pub certified_min_pattern_bytes: usize,
    pub certified_max_pattern_bytes: usize,
    pub certified_max_total_pattern_bytes: usize,
    pub encoded_patterns: &'a [u8],
}

/// Copyable operation and native-classifier identity. Pattern bytes remain in
/// [`CacheIdentity`] and may be authenticated separately by an owning facade.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationIdentity {
    pub algorithm_id: &'static str,
    pub plan_id: &'static str,
    pub operation: Operation,
    pub cache_format_version: u32,
    pub implementation_kind: &'static str,
    pub identity_scope: &'static str,
    pub target_arch: &'static str,
    pub runtime_minimum_haystack_bytes: usize,
    pub semantics: Semantics,
    pub classifier_selection: AsciiSelection,
    pub certified_min_patterns: usize,
    pub certified_max_patterns: usize,
    pub certified_min_pattern_bytes: usize,
    pub certified_max_pattern_bytes: usize,
    pub certified_max_total_pattern_bytes: usize,
}

impl CacheIdentity<'_> {
    /// Drop only the borrowed pattern encoding while preserving the complete
    /// operation and native-classifier identity.
    #[must_use]
    pub const fn operation_identity(self) -> OperationIdentity {
        OperationIdentity {
            algorithm_id: self.algorithm_id,
            plan_id: self.plan_id,
            operation: self.operation,
            cache_format_version: self.cache_format_version,
            implementation_kind: self.implementation_kind,
            identity_scope: self.identity_scope,
            target_arch: self.target_arch,
            runtime_minimum_haystack_bytes: self.runtime_minimum_haystack_bytes,
            semantics: self.semantics,
            classifier_selection: self.classifier_selection,
            certified_min_patterns: self.certified_min_patterns,
            certified_max_patterns: self.certified_max_patterns,
            certified_min_pattern_bytes: self.certified_min_pattern_bytes,
            certified_max_pattern_bytes: self.certified_max_pattern_bytes,
            certified_max_total_pattern_bytes: self.certified_max_total_pattern_bytes,
        }
    }
}

/// Caller limits for one packed construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    pub max_patterns: usize,
    pub max_pattern_bytes: usize,
    pub max_total_pattern_bytes: usize,
    pub max_identity_bytes: usize,
    pub max_build_work: usize,
    pub max_build_peak_bytes: usize,
    pub max_persistent_bytes: usize,
}

impl BuildLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_patterns: usize::MAX,
            max_pattern_bytes: usize::MAX,
            max_total_pattern_bytes: usize::MAX,
            max_identity_bytes: usize::MAX,
            max_build_work: usize::MAX,
            max_build_peak_bytes: usize::MAX,
            max_persistent_bytes: usize::MAX,
        }
    }
}

impl Default for BuildLimits {
    fn default() -> Self {
        Self {
            max_patterns: CERTIFIED_MAX_PATTERNS,
            max_pattern_bytes: CERTIFIED_MAX_PATTERN_BYTES,
            max_total_pattern_bytes: CERTIFIED_MAX_TOTAL_PATTERN_BYTES,
            max_identity_bytes: 4 * 1024,
            max_build_work: 4 * 1024 * 1024,
            max_build_peak_bytes: 16 * 1024 * 1024,
            max_persistent_bytes: 1024 * 1024,
        }
    }
}

/// Prospective and published accounting for one packed plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    pub patterns: usize,
    pub pattern_bytes: usize,
    pub max_pattern_bytes: usize,
    pub min_pattern_bytes: usize,
    pub max_first_byte_bucket_patterns: usize,
    pub max_first_byte_bucket_pattern_bytes: usize,
    pub identity_bytes: usize,
    pub identity_capacity_bytes: usize,
    pub build_work_upper_bound: u64,
    pub build_peak_upper_bound: usize,
    pub persistent_bytes: usize,
    pub simd_minimum_haystack_bytes: usize,
}

/// Immutable identity and caller envelope for one construction attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAttemptIdentity {
    pub algorithm_id: &'static str,
    pub plan_id: &'static str,
    pub operation: Operation,
    pub limits: BuildLimits,
    pub algorithm_version: u32,
    pub accounting_version: u32,
}

/// Exact effects committed through the last completed construction step.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BuildAttemptActual {
    pub work: u64,
    pub allocations: usize,
    pub allocated_bytes: usize,
    pub copied_bytes: usize,
    pub initialized_bytes: usize,
    pub live_persistent_bytes: usize,
    pub live_scratch_bytes: usize,
    pub peak_bytes: usize,
}

/// One closed successful or failed construction receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAttemptReceipt {
    identity: BuildAttemptIdentity,
    actual: BuildAttemptActual,
    accounting: Option<BuildAccounting>,
    published: bool,
}

impl BuildAttemptReceipt {
    #[must_use]
    pub const fn identity(&self) -> BuildAttemptIdentity {
        self.identity
    }

    #[must_use]
    pub const fn actual(&self) -> BuildAttemptActual {
        self.actual
    }

    #[must_use]
    pub const fn accounting(&self) -> Option<BuildAccounting> {
        self.accounting
    }

    #[must_use]
    pub const fn published(&self) -> bool {
        self.published
    }

    #[must_use]
    pub fn contains_actual(&self) -> bool {
        let work_fits = u64::try_from(self.identity.limits.max_build_work)
            .map_or(true, |limit| self.actual.work <= limit);
        self.identity.algorithm_id == ALGORITHM_ID
            && self.identity.algorithm_version == BUILD_ATTEMPT_ALGORITHM_VERSION
            && self.identity.accounting_version == BUILD_ATTEMPT_ACCOUNTING_VERSION
            && work_fits
            && self.actual.live_persistent_bytes <= self.identity.limits.max_persistent_bytes
            && self.actual.peak_bytes <= self.identity.limits.max_build_peak_bytes
            && self.actual.live_scratch_bytes == 0
            && self.actual.copied_bytes <= self.actual.initialized_bytes
            && self.actual.peak_bytes
                >= self
                    .actual
                    .live_persistent_bytes
                    .saturating_add(self.actual.live_scratch_bytes)
    }

    fn closes_success(&self, operation: Operation, accounting: BuildAccounting) -> bool {
        self.published
            && self.identity.operation == operation
            && self.identity.plan_id
                == match operation {
                    Operation::Count => COUNT_PLAN_ID,
                    Operation::SpanSum => SPAN_SUM_PLAN_ID,
                }
            && self.accounting == Some(accounting)
            && self.contains_actual()
            && self.actual.work <= accounting.build_work_upper_bound
            && self.actual.allocations == 1
            && self.actual.live_persistent_bytes == accounting.persistent_bytes
            && self.actual.peak_bytes <= accounting.build_peak_upper_bound
    }

    fn closes_failure(&self) -> bool {
        !self.published && self.accounting.is_none() && self.contains_actual()
    }
}

/// Limits checked before touching one operation's source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceLimits {
    pub max_work: u64,
    pub max_match_events: usize,
    pub max_count: u64,
    pub max_span_sum: u64,
    pub max_reducer_steps: usize,
    pub max_scratch_bytes: usize,
    pub max_peak_bytes: usize,
}

impl ReduceLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_work: u64::MAX,
            max_match_events: usize::MAX,
            max_count: u64::MAX,
            max_span_sum: u64::MAX,
            max_reducer_steps: usize::MAX,
            max_scratch_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for ReduceLimits {
    fn default() -> Self {
        Self {
            max_work: 16 * 1024 * 1024 * 1024,
            max_match_events: 128 * 1024 * 1024,
            max_count: 128 * 1024 * 1024,
            max_span_sum: 128 * 1024 * 1024,
            max_reducer_steps: 128 * 1024 * 1024 + 1,
            max_scratch_bytes: 0,
            max_peak_bytes: 2 * 1024 * 1024,
        }
    }
}

/// Complete source-independent envelope for one reduction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceUpperBounds {
    pub haystack_bytes: usize,
    pub candidate_positions: usize,
    /// Retained for compatibility with the former restarted iterator theorem.
    /// The monotone FRE-owned stream never revisits a suffix.
    pub restart_tail_positions: usize,
    pub examined_positions: usize,
    pub work_per_position: usize,
    /// Retained for compatibility. The monotone stream has no iterator setup.
    pub iterator_setup_work: usize,
    pub source_byte_reads: usize,
    pub pattern_checks: usize,
    pub work: u64,
    pub match_events: usize,
    pub count: u64,
    pub span_sum: u64,
    pub reducer_steps: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

/// Successful operation counters.
///
/// Prefix equality is intentionally left optimized. As with the existing
/// dependency-owned Two-Way primitive, its opaque early exits are charged at
/// the prospective source-read envelope in the successful actual receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceActualCounters {
    pub match_events: u64,
    /// Candidate events plus the final exhausted-stream observation.
    pub iterator_next_calls: usize,
    pub count: Option<u64>,
    pub span_sum: Option<u64>,
    pub classified_positions: usize,
    pub candidate_events: usize,
    pub pattern_checks: usize,
    pub source_byte_reads: usize,
    pub work: u64,
    pub scratch_bytes: usize,
    pub peak_bytes: usize,
}

/// Successful reduction certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceAccounting<'a> {
    pub identity: CacheIdentity<'a>,
    pub upper_bounds: ReduceUpperBounds,
    pub actual: ReduceActualCounters,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountResult<'a> {
    pub count: u64,
    pub accounting: ReduceAccounting<'a>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanSumResult<'a> {
    pub span_sum: u64,
    pub accounting: ReduceAccounting<'a>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BuildError {
    EmptyPatternSet,
    EmptyPattern {
        index: usize,
    },
    ProofRefused {
        fact: &'static str,
        needed: usize,
        certified_limit: usize,
    },
    PatternLimit {
        needed: usize,
        limit: usize,
    },
    PatternBytesLimit {
        needed: usize,
        limit: usize,
    },
    TotalPatternBytesLimit {
        needed: usize,
        limit: usize,
    },
    IdentityLimit {
        needed: usize,
        limit: usize,
    },
    WorkLimit {
        needed: usize,
        limit: usize,
    },
    BuildPeakLimit {
        needed: usize,
        limit: usize,
    },
    PersistentLimit {
        needed: usize,
        limit: usize,
    },
    UnsupportedTargetOrShape,
    AllocationFailed {
        additional: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "packed ordered-literal build refusal: {self:?}")
    }
}

impl std::error::Error for BuildError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BuildFailureKind {
    EmptyPatternSet,
    EmptyPattern,
    ProofRefused,
    PatternLimit,
    PatternBytesLimit,
    TotalPatternBytesLimit,
    IdentityLimit,
    WorkLimit,
    BuildPeakLimit,
    PersistentLimit,
    UnsupportedTargetOrShape,
    AllocationFailed,
    ArithmeticOverflow,
}

impl BuildFailureKind {
    const fn from_error(error: &BuildError) -> Self {
        match error {
            BuildError::EmptyPatternSet => Self::EmptyPatternSet,
            BuildError::EmptyPattern { .. } => Self::EmptyPattern,
            BuildError::ProofRefused { .. } => Self::ProofRefused,
            BuildError::PatternLimit { .. } => Self::PatternLimit,
            BuildError::PatternBytesLimit { .. } => Self::PatternBytesLimit,
            BuildError::TotalPatternBytesLimit { .. } => Self::TotalPatternBytesLimit,
            BuildError::IdentityLimit { .. } => Self::IdentityLimit,
            BuildError::WorkLimit { .. } => Self::WorkLimit,
            BuildError::BuildPeakLimit { .. } => Self::BuildPeakLimit,
            BuildError::PersistentLimit { .. } => Self::PersistentLimit,
            BuildError::UnsupportedTargetOrShape => Self::UnsupportedTargetOrShape,
            BuildError::AllocationFailed { .. } => Self::AllocationFailed,
            BuildError::ArithmeticOverflow { .. } => Self::ArithmeticOverflow,
        }
    }
}

/// Terminal construction failure with its immutable partial actuals.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildAttemptError {
    source: BuildError,
    receipt: BuildAttemptReceipt,
    seal: BuildFailureKind,
}

impl BuildAttemptError {
    fn new(source: BuildError, identity: BuildAttemptIdentity, actual: BuildAttemptActual) -> Self {
        let seal = BuildFailureKind::from_error(&source);
        Self {
            source,
            receipt: BuildAttemptReceipt {
                identity,
                actual,
                accounting: None,
                published: false,
            },
            seal,
        }
    }

    #[must_use]
    pub const fn source(&self) -> &BuildError {
        &self.source
    }

    #[must_use]
    pub const fn receipt(&self) -> &BuildAttemptReceipt {
        &self.receipt
    }

    #[must_use]
    pub fn closes(&self) -> bool {
        self.seal == BuildFailureKind::from_error(&self.source) && self.receipt.closes_failure()
    }

    #[must_use]
    pub fn into_source(self) -> BuildError {
        self.source
    }
}

impl fmt::Display for BuildAttemptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source.fmt(formatter)
    }
}

impl std::error::Error for BuildAttemptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReduceError {
    WorkLimit { needed: u64, limit: u64 },
    MatchEventsLimit { needed: usize, limit: usize },
    CountLimit { needed: u64, limit: u64 },
    SpanSumLimit { needed: u64, limit: u64 },
    ReducerStepsLimit { needed: usize, limit: usize },
    ScratchLimit { needed: usize, limit: usize },
    PeakLimit { needed: usize, limit: usize },
    ArithmeticOverflow { computation: &'static str },
    InternalInvariant { detail: &'static str },
}

impl fmt::Display for ReduceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "packed ordered-literal reduce refusal: {self:?}")
    }
}

impl std::error::Error for ReduceError {}

#[derive(Clone, Copy, Debug)]
struct PatternMeta {
    offset: u16,
    length: u8,
}

impl PatternMeta {
    const EMPTY: Self = Self {
        offset: 0,
        length: 0,
    };
}

#[derive(Debug)]
struct PackedOwner {
    classifier: AsciiByteSetClassifier,
    has_non_ascii_first_byte: bool,
    first_byte_patterns: [u16; 256],
    patterns: [PatternMeta; CERTIFIED_MAX_PATTERNS],
    encoded_patterns: [u8; IDENTITY_CAPACITY_BYTES],
    encoded_len: u16,
}

impl PackedOwner {
    fn encoded_patterns(&self) -> &[u8] {
        let len = usize::from(self.encoded_len);
        &self.encoded_patterns[..len]
    }

    fn pattern(&self, id: usize) -> &[u8] {
        let meta = self.patterns[id];
        let start = usize::from(meta.offset);
        let end = start
            .checked_add(usize::from(meta.length))
            .expect("certified pattern extent fits the fixed identity");
        &self.encoded_patterns[start..end]
    }
}

#[derive(Debug)]
struct PlanCore {
    owner: Box<PackedOwner>,
    build: BuildAccounting,
}

/// Non-`Clone`, count-specialized packed plan.
#[derive(Debug)]
pub struct PackedOrderedLiteralCountPlan {
    core: PlanCore,
}

/// Non-`Clone`, span-specialized packed plan.
#[derive(Debug)]
pub struct PackedOrderedLiteralSpanSumPlan {
    core: PlanCore,
}

/// Successful count-plan construction and its closed receipt.
#[derive(Debug)]
pub struct CountBuildAttempt {
    plan: PackedOrderedLiteralCountPlan,
    receipt: BuildAttemptReceipt,
}

impl CountBuildAttempt {
    #[must_use]
    pub const fn plan(&self) -> &PackedOrderedLiteralCountPlan {
        &self.plan
    }

    #[must_use]
    pub const fn receipt(&self) -> &BuildAttemptReceipt {
        &self.receipt
    }

    #[must_use]
    pub fn closes(&self) -> bool {
        self.receipt
            .closes_success(Operation::Count, self.plan.build_accounting())
    }

    #[must_use]
    pub fn into_parts(self) -> (PackedOrderedLiteralCountPlan, BuildAttemptReceipt) {
        (self.plan, self.receipt)
    }

    #[must_use]
    pub fn into_plan(self) -> PackedOrderedLiteralCountPlan {
        self.plan
    }
}

/// Successful span-sum-plan construction and its closed receipt.
#[derive(Debug)]
pub struct SpanSumBuildAttempt {
    plan: PackedOrderedLiteralSpanSumPlan,
    receipt: BuildAttemptReceipt,
}

impl SpanSumBuildAttempt {
    #[must_use]
    pub const fn plan(&self) -> &PackedOrderedLiteralSpanSumPlan {
        &self.plan
    }

    #[must_use]
    pub const fn receipt(&self) -> &BuildAttemptReceipt {
        &self.receipt
    }

    #[must_use]
    pub fn closes(&self) -> bool {
        self.receipt
            .closes_success(Operation::SpanSum, self.plan.build_accounting())
    }

    #[must_use]
    pub fn into_parts(self) -> (PackedOrderedLiteralSpanSumPlan, BuildAttemptReceipt) {
        (self.plan, self.receipt)
    }

    #[must_use]
    pub fn into_plan(self) -> PackedOrderedLiteralSpanSumPlan {
        self.plan
    }
}

impl PackedOrderedLiteralCountPlan {
    pub fn build<P: AsRef<[u8]>>(patterns: &[P], limits: BuildLimits) -> Result<Self, BuildError> {
        Self::build_with_dispatch(SimdDispatchContext::capture(), patterns, limits)
    }

    /// Build from one caller-captured capability snapshot.
    pub fn build_with_dispatch<P: AsRef<[u8]>>(
        dispatch: SimdDispatchContext,
        patterns: &[P],
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        Self::build_attempt_with_dispatch(dispatch, patterns, limits)
            .map(CountBuildAttempt::into_plan)
            .map_err(BuildAttemptError::into_source)
    }

    #[allow(
        clippy::result_large_err,
        reason = "the terminal receipt remains inline so failed allocation reporting cannot allocate"
    )]
    pub fn build_attempt<P: AsRef<[u8]>>(
        patterns: &[P],
        limits: BuildLimits,
    ) -> Result<CountBuildAttempt, BuildAttemptError> {
        Self::build_attempt_with_dispatch(SimdDispatchContext::capture(), patterns, limits)
    }

    /// Build with one caller-captured capability snapshot and retain the
    /// complete success-or-failure receipt.
    #[allow(
        clippy::result_large_err,
        reason = "the terminal receipt remains inline so failed allocation reporting cannot allocate"
    )]
    pub fn build_attempt_with_dispatch<P: AsRef<[u8]>>(
        dispatch: SimdDispatchContext,
        patterns: &[P],
        limits: BuildLimits,
    ) -> Result<CountBuildAttempt, BuildAttemptError> {
        let identity = build_attempt_identity(Operation::Count, limits);
        PlanCore::build_attempt(patterns, limits, size_of::<Self>(), identity, dispatch).map(
            |(core, receipt)| CountBuildAttempt {
                plan: Self { core },
                receipt,
            },
        )
    }

    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.core.build
    }

    #[must_use]
    pub fn cache_identity(&self) -> CacheIdentity<'_> {
        self.core.identity(Operation::Count)
    }

    #[inline]
    pub fn count<'a>(
        &'a self,
        haystack: &[u8],
        limits: ReduceLimits,
    ) -> Result<CountResult<'a>, ReduceError> {
        let outcome = self.core.reduce::<false>(haystack, limits)?;
        Ok(CountResult {
            count: outcome.count,
            accounting: ReduceAccounting {
                identity: self.cache_identity(),
                upper_bounds: outcome.upper,
                actual: outcome.actual,
            },
        })
    }
}

impl PackedOrderedLiteralSpanSumPlan {
    pub fn build<P: AsRef<[u8]>>(patterns: &[P], limits: BuildLimits) -> Result<Self, BuildError> {
        Self::build_with_dispatch(SimdDispatchContext::capture(), patterns, limits)
    }

    /// Build from one caller-captured capability snapshot.
    pub fn build_with_dispatch<P: AsRef<[u8]>>(
        dispatch: SimdDispatchContext,
        patterns: &[P],
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        Self::build_attempt_with_dispatch(dispatch, patterns, limits)
            .map(SpanSumBuildAttempt::into_plan)
            .map_err(BuildAttemptError::into_source)
    }

    #[allow(
        clippy::result_large_err,
        reason = "the terminal receipt remains inline so failed allocation reporting cannot allocate"
    )]
    pub fn build_attempt<P: AsRef<[u8]>>(
        patterns: &[P],
        limits: BuildLimits,
    ) -> Result<SpanSumBuildAttempt, BuildAttemptError> {
        Self::build_attempt_with_dispatch(SimdDispatchContext::capture(), patterns, limits)
    }

    /// Build with one caller-captured capability snapshot and retain the
    /// complete success-or-failure receipt.
    #[allow(
        clippy::result_large_err,
        reason = "the terminal receipt remains inline so failed allocation reporting cannot allocate"
    )]
    pub fn build_attempt_with_dispatch<P: AsRef<[u8]>>(
        dispatch: SimdDispatchContext,
        patterns: &[P],
        limits: BuildLimits,
    ) -> Result<SpanSumBuildAttempt, BuildAttemptError> {
        let identity = build_attempt_identity(Operation::SpanSum, limits);
        PlanCore::build_attempt(patterns, limits, size_of::<Self>(), identity, dispatch).map(
            |(core, receipt)| SpanSumBuildAttempt {
                plan: Self { core },
                receipt,
            },
        )
    }

    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.core.build
    }

    #[must_use]
    pub fn cache_identity(&self) -> CacheIdentity<'_> {
        self.core.identity(Operation::SpanSum)
    }

    #[inline]
    pub fn span_sum<'a>(
        &'a self,
        haystack: &[u8],
        limits: ReduceLimits,
    ) -> Result<SpanSumResult<'a>, ReduceError> {
        let outcome = self.core.reduce::<true>(haystack, limits)?;
        Ok(SpanSumResult {
            span_sum: outcome.span_sum,
            accounting: ReduceAccounting {
                identity: self.cache_identity(),
                upper_bounds: outcome.upper,
                actual: outcome.actual,
            },
        })
    }
}

const fn build_attempt_identity(operation: Operation, limits: BuildLimits) -> BuildAttemptIdentity {
    BuildAttemptIdentity {
        algorithm_id: ALGORITHM_ID,
        plan_id: match operation {
            Operation::Count => COUNT_PLAN_ID,
            Operation::SpanSum => SPAN_SUM_PLAN_ID,
        },
        operation,
        limits,
        algorithm_version: BUILD_ATTEMPT_ALGORITHM_VERSION,
        accounting_version: BUILD_ATTEMPT_ACCOUNTING_VERSION,
    }
}

impl PlanCore {
    fn identity(&self, operation: Operation) -> CacheIdentity<'_> {
        CacheIdentity {
            algorithm_id: ALGORITHM_ID,
            plan_id: match operation {
                Operation::Count => COUNT_PLAN_ID,
                Operation::SpanSum => SPAN_SUM_PLAN_ID,
            },
            operation,
            cache_format_version: CACHE_FORMAT_VERSION,
            implementation_kind: "FRE-owned monotone first-byte SIMD candidate stream with ordered verification",
            identity_scope: "process-local semantic identity with authenticated classifier receipt",
            target_arch: std::env::consts::ARCH,
            runtime_minimum_haystack_bytes: SIMD_BLOCK_BYTES,
            semantics: SEMANTICS,
            classifier_selection: self.owner.classifier.selection(),
            certified_min_patterns: CERTIFIED_MIN_PATTERNS,
            certified_max_patterns: CERTIFIED_MAX_PATTERNS,
            certified_min_pattern_bytes: CERTIFIED_MIN_PATTERN_BYTES,
            certified_max_pattern_bytes: CERTIFIED_MAX_PATTERN_BYTES,
            certified_max_total_pattern_bytes: CERTIFIED_MAX_TOTAL_PATTERN_BYTES,
            encoded_patterns: self.owner.encoded_patterns(),
        }
    }

    #[allow(
        clippy::result_large_err,
        clippy::too_many_lines,
        reason = "the failed attempt carries the exact inline receipt, and the source-to-fixed-owner transaction remains adjacent for accounting audit"
    )]
    fn build_attempt<P: AsRef<[u8]>>(
        patterns: &[P],
        limits: BuildLimits,
        inline_bytes: usize,
        identity: BuildAttemptIdentity,
        dispatch: SimdDispatchContext,
    ) -> Result<(Self, BuildAttemptReceipt), BuildAttemptError> {
        let (preflight, mut actual) = preflight(patterns, limits, inline_bytes)
            .map_err(|failure| BuildAttemptError::new(failure.source, identity, failure.actual))?;

        let mut encoded_patterns = [0_u8; IDENTITY_CAPACITY_BYTES];
        let mut pattern_meta = [PatternMeta::EMPTY; CERTIFIED_MAX_PATTERNS];
        let mut first_byte_patterns = [0_u16; 256];
        let mut first_byte_pattern_bytes = [0_usize; 256];
        let mut max_first_byte_bucket_patterns = 0_usize;
        let mut max_first_byte_bucket_pattern_bytes = 0_usize;
        let mut has_non_ascii_first_byte = false;
        let count = u64::try_from(patterns.len()).map_err(|_| {
            attempt_error(
                BuildError::ArithmeticOverflow {
                    computation: "identity pattern count",
                },
                identity,
                actual,
            )
        })?;
        encoded_patterns[..LENGTH_PREFIX_BYTES].copy_from_slice(&count.to_le_bytes());
        let mut cursor = LENGTH_PREFIX_BYTES;
        let mut ascii_words = [0_u64; 2];
        for (index, pattern) in patterns.iter().enumerate() {
            let bytes = pattern.as_ref();
            let length = u64::try_from(bytes.len()).map_err(|_| {
                attempt_error(
                    BuildError::ArithmeticOverflow {
                        computation: "identity pattern length",
                    },
                    identity,
                    actual,
                )
            })?;
            let prefix_end = cursor.checked_add(LENGTH_PREFIX_BYTES).ok_or_else(|| {
                attempt_error(
                    BuildError::ArithmeticOverflow {
                        computation: "identity length-prefix end",
                    },
                    identity,
                    actual,
                )
            })?;
            encoded_patterns[cursor..prefix_end].copy_from_slice(&length.to_le_bytes());
            let bytes_end = prefix_end.checked_add(bytes.len()).ok_or_else(|| {
                attempt_error(
                    BuildError::ArithmeticOverflow {
                        computation: "identity pattern end",
                    },
                    identity,
                    actual,
                )
            })?;
            encoded_patterns[prefix_end..bytes_end].copy_from_slice(bytes);
            pattern_meta[index] = PatternMeta {
                offset: u16::try_from(prefix_end).map_err(|_| {
                    attempt_error(
                        BuildError::ArithmeticOverflow {
                            computation: "pattern identity offset",
                        },
                        identity,
                        actual,
                    )
                })?,
                length: u8::try_from(bytes.len()).map_err(|_| {
                    attempt_error(
                        BuildError::ArithmeticOverflow {
                            computation: "pattern length metadata",
                        },
                        identity,
                        actual,
                    )
                })?,
            };
            let first = bytes[0];
            let bit = 1_u16
                .checked_shl(u32::try_from(index).map_err(|_| {
                    attempt_error(
                        BuildError::ArithmeticOverflow {
                            computation: "pattern map bit",
                        },
                        identity,
                        actual,
                    )
                })?)
                .ok_or_else(|| {
                    attempt_error(
                        BuildError::ArithmeticOverflow {
                            computation: "pattern map bit",
                        },
                        identity,
                        actual,
                    )
                })?;
            first_byte_patterns[usize::from(first)] |= bit;
            max_first_byte_bucket_patterns = max_first_byte_bucket_patterns.max(
                usize::try_from(first_byte_patterns[usize::from(first)].count_ones())
                    .expect("u16 population count always fits a supported usize"),
            );
            first_byte_pattern_bytes[usize::from(first)] = first_byte_pattern_bytes
                [usize::from(first)]
            .checked_add(bytes.len())
            .ok_or_else(|| {
                attempt_error(
                    BuildError::ArithmeticOverflow {
                        computation: "first-byte bucket pattern bytes",
                    },
                    identity,
                    actual,
                )
            })?;
            max_first_byte_bucket_pattern_bytes = max_first_byte_bucket_pattern_bytes
                .max(first_byte_pattern_bytes[usize::from(first)]);
            if first < 128 {
                let word = usize::from(first / 64);
                let shift = u32::from(first % 64);
                ascii_words[word] |= 1_u64 << shift;
            } else {
                has_non_ascii_first_byte = true;
            }
            cursor = bytes_end;
        }
        if cursor != preflight.identity_bytes {
            return Err(attempt_error(
                BuildError::ArithmeticOverflow {
                    computation: "identity encoded length invariant",
                },
                identity,
                actual,
            ));
        }
        actual.work = preflight.build_work;
        actual.copied_bytes = preflight.identity_bytes;
        actual.initialized_bytes = size_of::<PackedOwner>();
        let classifier = dispatch
            .ascii_byte_set_classifier(AsciiByteSet::from_words(ascii_words), DispatchPolicy::Auto)
            .map_err(|_| attempt_error(BuildError::UnsupportedTargetOrShape, identity, actual))?;
        let owner = PackedOwner {
            classifier,
            has_non_ascii_first_byte,
            first_byte_patterns,
            patterns: pattern_meta,
            encoded_patterns,
            encoded_len: u16::try_from(cursor).map_err(|_| {
                attempt_error(
                    BuildError::ArithmeticOverflow {
                        computation: "identity encoded length metadata",
                    },
                    identity,
                    actual,
                )
            })?,
        };
        let owner = allocate_owner(owner).map_err(|(_, _owner)| {
            attempt_error(
                BuildError::AllocationFailed {
                    additional: size_of::<PackedOwner>(),
                },
                identity,
                actual,
            )
        })?;
        actual.allocations = 1;
        actual.allocated_bytes = size_of::<PackedOwner>();
        actual.initialized_bytes = actual
            .initialized_bytes
            .checked_add(inline_bytes)
            .ok_or_else(|| {
                attempt_error(
                    BuildError::ArithmeticOverflow {
                        computation: "published initialized bytes",
                    },
                    identity,
                    actual,
                )
            })?;
        actual.live_persistent_bytes = preflight.persistent_bytes;
        actual.peak_bytes = preflight.peak_bytes;
        let build = BuildAccounting {
            patterns: patterns.len(),
            pattern_bytes: preflight.pattern_bytes,
            max_pattern_bytes: preflight.max_pattern_bytes,
            min_pattern_bytes: preflight.min_pattern_bytes,
            max_first_byte_bucket_patterns,
            max_first_byte_bucket_pattern_bytes,
            identity_bytes: preflight.identity_bytes,
            identity_capacity_bytes: IDENTITY_CAPACITY_BYTES,
            build_work_upper_bound: preflight.build_work,
            build_peak_upper_bound: preflight.peak_bytes,
            persistent_bytes: preflight.persistent_bytes,
            simd_minimum_haystack_bytes: SIMD_BLOCK_BYTES,
        };
        let receipt = BuildAttemptReceipt {
            identity,
            actual,
            accounting: Some(build),
            published: true,
        };
        let core = Self { owner, build };
        if !receipt.closes_success(identity.operation, core.build) {
            return Err(attempt_error(
                BuildError::ArithmeticOverflow {
                    computation: "successful construction receipt closure",
                },
                identity,
                actual,
            ));
        }
        Ok((core, receipt))
    }

    fn preflight_reduce<const SPAN_SUM: bool>(
        &self,
        haystack_len: usize,
        limits: ReduceLimits,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        let candidate_positions = if haystack_len < self.build.min_pattern_bytes {
            0
        } else {
            haystack_len
                .checked_sub(self.build.min_pattern_bytes)
                .and_then(|remaining| remaining.checked_add(1))
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "candidate positions",
                })?
        };
        let pattern_checks = candidate_positions
            .checked_mul(self.build.max_first_byte_bucket_patterns)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "pattern checks",
            })?;
        let verification_reads = candidate_positions
            .checked_mul(self.build.max_first_byte_bucket_pattern_bytes)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "verification source reads",
            })?;
        let fixed_source_reads_per_position = 2_usize
            .checked_add(usize::from(self.owner.has_non_ascii_first_byte))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "fixed source reads per position",
            })?;
        let source_byte_reads = candidate_positions
            .checked_mul(fixed_source_reads_per_position)
            .and_then(|reads| reads.checked_add(verification_reads))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "source byte reads",
            })?;
        let work_per_position = self
            .build
            .max_first_byte_bucket_pattern_bytes
            .checked_add(self.build.max_first_byte_bucket_patterns)
            .and_then(|work| work.checked_add(4))
            .and_then(|work| work.checked_add(fixed_source_reads_per_position))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "work per position",
            })?;
        let work_usize = candidate_positions
            .checked_mul(work_per_position)
            .and_then(|work| work.checked_add(1))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "packed operation work",
            })?;
        let work = u64::try_from(work_usize).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "packed operation work as u64",
        })?;
        let match_events = haystack_len
            .checked_div(self.build.min_pattern_bytes)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "event quotient",
            })?;
        let count = u64::try_from(match_events).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "count upper bound",
        })?;
        let span_sum =
            u64::try_from(haystack_len).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "span-sum upper bound",
            })?;
        let reducer_steps =
            candidate_positions
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "reducer steps",
                })?;
        let upper = ReduceUpperBounds {
            haystack_bytes: haystack_len,
            candidate_positions,
            restart_tail_positions: 0,
            examined_positions: candidate_positions,
            work_per_position,
            iterator_setup_work: 0,
            source_byte_reads,
            pattern_checks,
            work,
            match_events,
            count,
            span_sum,
            reducer_steps,
            scratch_bytes: 0,
            persistent_bytes: self.build.persistent_bytes,
            peak_bytes: self.build.persistent_bytes,
        };
        check_reduce(upper, SPAN_SUM, limits)?;
        Ok(upper)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the monotone block/tail traversal and its exact counters remain in one auditable operation"
    )]
    fn reduce<const SPAN_SUM: bool>(
        &self,
        haystack: &[u8],
        limits: ReduceLimits,
    ) -> Result<ReduceOutcome, ReduceError> {
        let upper = self.preflight_reduce::<SPAN_SUM>(haystack.len(), limits)?;
        let candidate_positions = upper.candidate_positions;
        let mut block_start = 0_usize;
        let mut consumed_through = 0_usize;
        let mut candidate_events = 0_usize;
        let mut pattern_checks = 0_usize;
        let mut match_events = 0_u64;
        let mut span_sum = 0_u64;

        while block_start
            .checked_add(SIMD_BLOCK_BYTES)
            .is_some_and(|end| end <= candidate_positions)
        {
            let block_end = block_start.checked_add(SIMD_BLOCK_BYTES).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "SIMD block end",
                },
            )?;
            let block: &[u8; SIMD_BLOCK_BYTES] = haystack[block_start..block_end]
                .try_into()
                .map_err(|_| ReduceError::InternalInvariant {
                    detail: "complete candidate block lost its fixed extent",
                })?;
            let classified = self.owner.classifier.classify_32(block);
            let mut candidates = classified.member_mask();
            if self.owner.has_non_ascii_first_byte {
                let mut non_ascii = !classified.ascii_mask();
                while non_ascii != 0 {
                    let lane = non_ascii.trailing_zeros();
                    non_ascii &= non_ascii.wrapping_sub(1);
                    let lane_usize =
                        usize::try_from(lane).map_err(|_| ReduceError::ArithmeticOverflow {
                            computation: "non-ASCII candidate lane",
                        })?;
                    if self.owner.first_byte_patterns[usize::from(block[lane_usize])] != 0 {
                        candidates |= 1_u32 << lane;
                    }
                }
            }
            self.consume_candidate_mask::<SPAN_SUM>(
                haystack,
                block_start,
                candidates,
                &mut consumed_through,
                &mut candidate_events,
                &mut pattern_checks,
                &mut match_events,
                &mut span_sum,
            )?;
            block_start = block_end;
        }
        while block_start < candidate_positions {
            let byte = haystack[block_start];
            if self.owner.first_byte_patterns[usize::from(byte)] != 0 {
                candidate_events =
                    candidate_events
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "actual candidate events",
                        })?;
                self.consume_candidate::<SPAN_SUM>(
                    haystack,
                    block_start,
                    &mut consumed_through,
                    &mut pattern_checks,
                    &mut match_events,
                    &mut span_sum,
                )?;
            }
            block_start = block_start
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "scalar candidate cursor",
                })?;
        }

        let iterator_next_calls =
            candidate_events
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "candidate stream calls",
                })?;
        let count = match_events;
        let candidate_control_work =
            candidate_events
                .checked_mul(2)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "actual candidate control work",
                })?;
        let actual_work_usize = candidate_positions
            .checked_add(upper.source_byte_reads)
            .and_then(|work| work.checked_add(pattern_checks))
            .and_then(|work| work.checked_add(candidate_control_work))
            .and_then(|work| work.checked_add(iterator_next_calls))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual packed operation work",
            })?;
        let actual_work =
            u64::try_from(actual_work_usize).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "actual packed operation work as u64",
            })?;
        let actual = ReduceActualCounters {
            match_events,
            iterator_next_calls,
            count: Some(count),
            span_sum: SPAN_SUM.then_some(span_sum),
            classified_positions: candidate_positions,
            candidate_events,
            pattern_checks,
            source_byte_reads: upper.source_byte_reads,
            work: actual_work,
            scratch_bytes: 0,
            peak_bytes: self.build.persistent_bytes,
        };
        debug_assert!(match_events <= upper.count);
        debug_assert!(span_sum <= upper.span_sum);
        debug_assert!(candidate_events <= upper.candidate_positions);
        debug_assert!(pattern_checks <= upper.pattern_checks);
        Ok(ReduceOutcome {
            count,
            span_sum,
            upper,
            actual,
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the hot monotone reducer keeps its scalar counters borrowed and allocation-free"
    )]
    fn consume_candidate_mask<const SPAN_SUM: bool>(
        &self,
        haystack: &[u8],
        block_start: usize,
        mut candidates: u32,
        consumed_through: &mut usize,
        candidate_events: &mut usize,
        pattern_checks: &mut usize,
        match_events: &mut u64,
        span_sum: &mut u64,
    ) -> Result<(), ReduceError> {
        while candidates != 0 {
            let lane = candidates.trailing_zeros();
            candidates &= candidates.wrapping_sub(1);
            let start = block_start
                .checked_add(usize::try_from(lane).map_err(|_| {
                    ReduceError::ArithmeticOverflow {
                        computation: "candidate lane",
                    }
                })?)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "candidate start",
                })?;
            *candidate_events =
                candidate_events
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "actual candidate events",
                    })?;
            self.consume_candidate::<SPAN_SUM>(
                haystack,
                start,
                consumed_through,
                pattern_checks,
                match_events,
                span_sum,
            )?;
        }
        Ok(())
    }

    fn consume_candidate<const SPAN_SUM: bool>(
        &self,
        haystack: &[u8],
        start: usize,
        consumed_through: &mut usize,
        pattern_checks: &mut usize,
        match_events: &mut u64,
        span_sum: &mut u64,
    ) -> Result<(), ReduceError> {
        if start < *consumed_through {
            return Ok(());
        }
        let mut pattern_bits = self.owner.first_byte_patterns[usize::from(haystack[start])];
        while pattern_bits != 0 {
            let id = pattern_bits.trailing_zeros();
            pattern_bits &= pattern_bits.wrapping_sub(1);
            *pattern_checks =
                pattern_checks
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "actual pattern checks",
                    })?;
            let id = usize::try_from(id).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "pattern ID",
            })?;
            let pattern = self.owner.pattern(id);
            let end = start
                .checked_add(pattern.len())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "matched end",
                })?;
            if end <= haystack.len() && haystack[start..end] == *pattern {
                *match_events =
                    match_events
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "actual match events",
                        })?;
                if SPAN_SUM {
                    *span_sum = span_sum
                        .checked_add(u64::try_from(pattern.len()).map_err(|_| {
                            ReduceError::ArithmeticOverflow {
                                computation: "matched width as u64",
                            }
                        })?)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "actual span sum",
                        })?;
                }
                *consumed_through = end;
                break;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct BuildPreflight {
    pattern_bytes: usize,
    max_pattern_bytes: usize,
    min_pattern_bytes: usize,
    identity_bytes: usize,
    build_work: u64,
    persistent_bytes: usize,
    peak_bytes: usize,
}

struct PreflightFailure {
    source: BuildError,
    actual: BuildAttemptActual,
}

#[allow(
    clippy::too_many_lines,
    reason = "proof caps, caller limits and exact prospective construction accounting are deliberately ordered in one source-free preflight"
)]
fn preflight<P: AsRef<[u8]>>(
    patterns: &[P],
    limits: BuildLimits,
    inline_bytes: usize,
) -> Result<(BuildPreflight, BuildAttemptActual), PreflightFailure> {
    let mut actual = BuildAttemptActual::default();
    if limits.max_build_work == 0 {
        return Err(PreflightFailure {
            source: BuildError::WorkLimit {
                needed: 1,
                limit: limits.max_build_work,
            },
            actual,
        });
    }
    actual.work = 1;
    if patterns.is_empty() {
        return Err(PreflightFailure {
            source: BuildError::EmptyPatternSet,
            actual,
        });
    }
    if patterns.len() < CERTIFIED_MIN_PATTERNS {
        return Err(PreflightFailure {
            source: BuildError::ProofRefused {
                fact: "pattern count minimum",
                needed: patterns.len(),
                certified_limit: CERTIFIED_MIN_PATTERNS,
            },
            actual,
        });
    }
    if patterns.len() > CERTIFIED_MAX_PATTERNS {
        return Err(PreflightFailure {
            source: BuildError::ProofRefused {
                fact: "pattern count",
                needed: patterns.len(),
                certified_limit: CERTIFIED_MAX_PATTERNS,
            },
            actual,
        });
    }
    if patterns.len() > limits.max_patterns {
        return Err(PreflightFailure {
            source: BuildError::PatternLimit {
                needed: patterns.len(),
                limit: limits.max_patterns,
            },
            actual,
        });
    }
    let census_work = patterns.len().checked_add(1).ok_or(PreflightFailure {
        source: BuildError::ArithmeticOverflow {
            computation: "set proof and pattern length census work",
        },
        actual,
    })?;
    if census_work > limits.max_build_work {
        return Err(PreflightFailure {
            source: BuildError::WorkLimit {
                needed: census_work,
                limit: limits.max_build_work,
            },
            actual,
        });
    }

    let mut pattern_bytes = 0_usize;
    let mut max_pattern_bytes = 0_usize;
    let mut min_pattern_bytes = usize::MAX;
    for (index, pattern) in patterns.iter().enumerate() {
        actual.work = actual.work.checked_add(1).ok_or(PreflightFailure {
            source: BuildError::ArithmeticOverflow {
                computation: "pattern length census work",
            },
            actual,
        })?;
        let bytes = pattern.as_ref();
        if bytes.is_empty() {
            return Err(PreflightFailure {
                source: BuildError::EmptyPattern { index },
                actual,
            });
        }
        if bytes.len() < CERTIFIED_MIN_PATTERN_BYTES {
            return Err(PreflightFailure {
                source: BuildError::ProofRefused {
                    fact: "literal width minimum",
                    needed: bytes.len(),
                    certified_limit: CERTIFIED_MIN_PATTERN_BYTES,
                },
                actual,
            });
        }
        if bytes.len() > CERTIFIED_MAX_PATTERN_BYTES {
            return Err(PreflightFailure {
                source: BuildError::ProofRefused {
                    fact: "literal width",
                    needed: bytes.len(),
                    certified_limit: CERTIFIED_MAX_PATTERN_BYTES,
                },
                actual,
            });
        }
        if bytes.len() > limits.max_pattern_bytes {
            return Err(PreflightFailure {
                source: BuildError::PatternBytesLimit {
                    needed: bytes.len(),
                    limit: limits.max_pattern_bytes,
                },
                actual,
            });
        }
        pattern_bytes = pattern_bytes
            .checked_add(bytes.len())
            .ok_or(PreflightFailure {
                source: BuildError::ArithmeticOverflow {
                    computation: "total pattern bytes",
                },
                actual,
            })?;
        max_pattern_bytes = max_pattern_bytes.max(bytes.len());
        min_pattern_bytes = min_pattern_bytes.min(bytes.len());
    }
    if pattern_bytes > CERTIFIED_MAX_TOTAL_PATTERN_BYTES {
        return Err(PreflightFailure {
            source: BuildError::ProofRefused {
                fact: "total literal bytes",
                needed: pattern_bytes,
                certified_limit: CERTIFIED_MAX_TOTAL_PATTERN_BYTES,
            },
            actual,
        });
    }
    if pattern_bytes > limits.max_total_pattern_bytes {
        return Err(PreflightFailure {
            source: BuildError::TotalPatternBytesLimit {
                needed: pattern_bytes,
                limit: limits.max_total_pattern_bytes,
            },
            actual,
        });
    }
    let identity_bytes =
        LENGTH_PREFIX_BYTES
            .checked_add(patterns.len().checked_mul(LENGTH_PREFIX_BYTES).ok_or(
                PreflightFailure {
                    source: BuildError::ArithmeticOverflow {
                        computation: "identity prefixes",
                    },
                    actual,
                },
            )?)
            .and_then(|bytes| bytes.checked_add(pattern_bytes))
            .ok_or(PreflightFailure {
                source: BuildError::ArithmeticOverflow {
                    computation: "identity bytes",
                },
                actual,
            })?;
    if identity_bytes > limits.max_identity_bytes {
        return Err(PreflightFailure {
            source: BuildError::IdentityLimit {
                needed: identity_bytes,
                limit: limits.max_identity_bytes,
            },
            actual,
        });
    }
    let build_work_usize = patterns
        .len()
        .checked_add(1)
        .and_then(|work| work.checked_add(size_of::<PackedOwner>()))
        .and_then(|work| work.checked_add(identity_bytes))
        .and_then(|work| work.checked_add(CLASSIFIER_BUILD_WORK))
        .ok_or(PreflightFailure {
            source: BuildError::ArithmeticOverflow {
                computation: "build work",
            },
            actual,
        })?;
    if build_work_usize > limits.max_build_work {
        return Err(PreflightFailure {
            source: BuildError::WorkLimit {
                needed: build_work_usize,
                limit: limits.max_build_work,
            },
            actual,
        });
    }
    let persistent_bytes =
        inline_bytes
            .checked_add(size_of::<PackedOwner>())
            .ok_or(PreflightFailure {
                source: BuildError::ArithmeticOverflow {
                    computation: "persistent bytes",
                },
                actual,
            })?;
    if persistent_bytes > limits.max_persistent_bytes {
        return Err(PreflightFailure {
            source: BuildError::PersistentLimit {
                needed: persistent_bytes,
                limit: limits.max_persistent_bytes,
            },
            actual,
        });
    }
    let peak_bytes = persistent_bytes;
    if peak_bytes > limits.max_build_peak_bytes {
        return Err(PreflightFailure {
            source: BuildError::BuildPeakLimit {
                needed: peak_bytes,
                limit: limits.max_build_peak_bytes,
            },
            actual,
        });
    }
    let build_work = u64::try_from(build_work_usize).map_err(|_| PreflightFailure {
        source: BuildError::ArithmeticOverflow {
            computation: "build work as u64",
        },
        actual,
    })?;
    Ok((
        BuildPreflight {
            pattern_bytes,
            max_pattern_bytes,
            min_pattern_bytes,
            identity_bytes,
            build_work,
            persistent_bytes,
            peak_bytes,
        },
        actual,
    ))
}

fn attempt_error(
    source: BuildError,
    identity: BuildAttemptIdentity,
    actual: BuildAttemptActual,
) -> BuildAttemptError {
    BuildAttemptError::new(source, identity, actual)
}

fn check_reduce(
    upper: ReduceUpperBounds,
    check_span: bool,
    limits: ReduceLimits,
) -> Result<(), ReduceError> {
    if upper.work > limits.max_work {
        return Err(ReduceError::WorkLimit {
            needed: upper.work,
            limit: limits.max_work,
        });
    }
    if upper.match_events > limits.max_match_events {
        return Err(ReduceError::MatchEventsLimit {
            needed: upper.match_events,
            limit: limits.max_match_events,
        });
    }
    if upper.count > limits.max_count {
        return Err(ReduceError::CountLimit {
            needed: upper.count,
            limit: limits.max_count,
        });
    }
    if check_span && upper.span_sum > limits.max_span_sum {
        return Err(ReduceError::SpanSumLimit {
            needed: upper.span_sum,
            limit: limits.max_span_sum,
        });
    }
    if upper.reducer_steps > limits.max_reducer_steps {
        return Err(ReduceError::ReducerStepsLimit {
            needed: upper.reducer_steps,
            limit: limits.max_reducer_steps,
        });
    }
    if upper.scratch_bytes > limits.max_scratch_bytes {
        return Err(ReduceError::ScratchLimit {
            needed: upper.scratch_bytes,
            limit: limits.max_scratch_bytes,
        });
    }
    if upper.peak_bytes > limits.max_peak_bytes {
        return Err(ReduceError::PeakLimit {
            needed: upper.peak_bytes,
            limit: limits.max_peak_bytes,
        });
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct ReduceOutcome {
    count: u64,
    span_sum: u64,
    upper: ReduceUpperBounds,
    actual: ReduceActualCounters,
}

#[allow(
    clippy::result_large_err,
    reason = "fallible exact publication must preserve the fixed owner without allocating an error"
)]
fn allocate_owner(owner: PackedOwner) -> Result<Box<PackedOwner>, (CopyError, PackedOwner)> {
    #[cfg(test)]
    if build_allocation_probe::take_failure() {
        return Err((CopyError::AllocationFailed, owner));
    }
    try_box_preserve(owner)
}

#[cfg(test)]
mod build_allocation_probe {
    use std::cell::Cell;

    thread_local! {
        static FAIL_NEXT: Cell<bool> = const { Cell::new(false) };
    }

    pub(super) struct Guard;

    impl Drop for Guard {
        fn drop(&mut self) {
            FAIL_NEXT.with(|fail| fail.set(false));
        }
    }

    pub(super) fn fail_next() -> Guard {
        FAIL_NEXT.with(|fail| fail.set(true));
        Guard
    }

    pub(super) fn take_failure() -> bool {
        FAIL_NEXT.with(|fail| fail.replace(false))
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use regex::bytes::RegexBuilder;

    use super::{
        BuildError, BuildLimits, PackedOrderedLiteralCountPlan, PackedOrderedLiteralSpanSumPlan,
        ReduceError, ReduceLimits, build_allocation_probe,
    };

    fn source(patterns: &[Vec<u8>]) -> String {
        let mut source = String::from("(?:");
        for (index, pattern) in patterns.iter().enumerate() {
            if index != 0 {
                source.push('|');
            }
            for &byte in pattern {
                write!(&mut source, "\\x{byte:02X}").unwrap();
            }
        }
        source.push(')');
        source
    }

    fn words(alphabet: &[u8], maximum_len: usize) -> Vec<Vec<u8>> {
        let mut all = vec![Vec::new()];
        let mut level = vec![Vec::new()];
        for _ in 0..maximum_len {
            let mut next = Vec::new();
            for prefix in &level {
                for &byte in alphabet {
                    let mut word = prefix.clone();
                    word.push(byte);
                    next.push(word);
                }
            }
            all.extend(next.iter().cloned());
            level = next;
        }
        all
    }

    fn pattern_lists(universe: &[Vec<u8>], maximum_len: usize) -> Vec<Vec<Vec<u8>>> {
        let mut all = Vec::new();
        let mut level = vec![Vec::new()];
        for _ in 0..maximum_len {
            let mut next = Vec::new();
            for prefix in &level {
                for pattern in universe {
                    let mut list = prefix.clone();
                    list.push(pattern.clone());
                    next.push(list);
                }
            }
            all.extend(next.iter().cloned());
            level = next;
        }
        all
    }

    #[test]
    fn ordered_prefix_duplicate_and_arbitrary_bytes_match_regex() {
        let languages = [
            vec![b"aa".to_vec(), b"aab".to_vec()],
            vec![b"aab".to_vec(), b"aa".to_vec()],
            vec![b"aa".to_vec(), b"aa".to_vec()],
            vec![b"\xFF\x00".to_vec(), b"\xFF\x00\x80".to_vec()],
        ];
        let haystacks: &[&[u8]] = &[b"", b"a", b"aaa", b"aaaaab", b"\xFF\x00\xFF\x00\x80"];
        for patterns in languages {
            let regex = RegexBuilder::new(&source(&patterns))
                .unicode(false)
                .build()
                .unwrap();
            let count =
                PackedOrderedLiteralCountPlan::build(&patterns, BuildLimits::unlimited()).unwrap();
            let span = PackedOrderedLiteralSpanSumPlan::build(&patterns, BuildLimits::unlimited())
                .unwrap();
            for haystack in haystacks {
                let expected_count = u64::try_from(regex.find_iter(haystack).count()).unwrap();
                let expected_span = regex
                    .find_iter(haystack)
                    .map(|matched| u64::try_from(matched.end() - matched.start()).unwrap())
                    .sum::<u64>();
                assert_eq!(
                    count
                        .count(haystack, ReduceLimits::unlimited())
                        .unwrap()
                        .count,
                    expected_count
                );
                assert_eq!(
                    span.span_sum(haystack, ReduceLimits::unlimited())
                        .unwrap()
                        .span_sum,
                    expected_span
                );
            }
        }
    }

    #[test]
    fn exhaustive_nonempty_languages_match_upstream() {
        let universe = vec![
            b"aa".to_vec(),
            b"ab".to_vec(),
            b"\xFFa".to_vec(),
            b"aaa".to_vec(),
            b"aab".to_vec(),
        ];
        let languages = pattern_lists(&universe, 3)
            .into_iter()
            .filter(|patterns| patterns.len() >= super::CERTIFIED_MIN_PATTERNS);
        let haystacks = words(b"\x00a\xFF", 4);
        for patterns in languages {
            let regex = RegexBuilder::new(&source(&patterns))
                .unicode(false)
                .build()
                .unwrap();
            let packed_count =
                PackedOrderedLiteralCountPlan::build(&patterns, BuildLimits::unlimited()).unwrap();
            let packed_span =
                PackedOrderedLiteralSpanSumPlan::build(&patterns, BuildLimits::unlimited())
                    .unwrap();
            for haystack in &haystacks {
                let expected_count = u64::try_from(regex.find_iter(haystack).count()).unwrap();
                let expected_span = regex
                    .find_iter(haystack)
                    .map(|matched| u64::try_from(matched.end() - matched.start()).unwrap())
                    .sum::<u64>();
                assert_eq!(
                    packed_count
                        .count(haystack, ReduceLimits::unlimited())
                        .unwrap()
                        .count,
                    expected_count,
                    "patterns={patterns:?}, haystack={haystack:?}"
                );
                assert_eq!(
                    packed_span
                        .span_sum(haystack, ReduceLimits::unlimited())
                        .unwrap()
                        .span_sum,
                    expected_span,
                    "patterns={patterns:?}, haystack={haystack:?}"
                );
            }
        }
    }

    #[test]
    fn nonempty_utf8_words_are_profile_neutral_bytes() {
        let patterns = ["∞".as_bytes(), "✓".as_bytes()];
        let haystack = "--∞--✓--∞--".as_bytes();
        let count =
            PackedOrderedLiteralCountPlan::build(&patterns, BuildLimits::unlimited()).unwrap();
        let span =
            PackedOrderedLiteralSpanSumPlan::build(&patterns, BuildLimits::unlimited()).unwrap();
        assert_eq!(
            count
                .count(haystack, ReduceLimits::unlimited())
                .unwrap()
                .count,
            3
        );
        assert_eq!(
            span.span_sum(haystack, ReduceLimits::unlimited())
                .unwrap()
                .span_sum,
            9
        );
        assert_eq!(
            count.cache_identity().semantics.boundary_semantics,
            super::BoundarySemantics::NonemptyByteStrings
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the exact/one-below matrix keeps every packed limit and receipt visible"
    )]
    fn every_nonzero_limit_has_exact_and_one_below_behavior() {
        let patterns = [b"ab".as_slice(), b"abc".as_slice(), b"\xFF\x00".as_slice()];
        let baseline =
            PackedOrderedLiteralCountPlan::build_attempt(&patterns, BuildLimits::unlimited())
                .unwrap();
        assert!(baseline.closes());
        let (baseline, receipt) = baseline.into_parts();
        assert!(receipt.contains_actual());
        let build = baseline.build_accounting();
        let exact = BuildLimits {
            max_patterns: build.patterns,
            max_pattern_bytes: build.max_pattern_bytes,
            max_total_pattern_bytes: build.pattern_bytes,
            max_identity_bytes: build.identity_bytes,
            max_build_work: usize::try_from(build.build_work_upper_bound).unwrap(),
            max_build_peak_bytes: build.build_peak_upper_bound,
            max_persistent_bytes: build.persistent_bytes,
        };
        assert!(
            PackedOrderedLiteralCountPlan::build_attempt(&patterns, exact)
                .unwrap()
                .closes()
        );
        let build_cases = [
            BuildLimits {
                max_patterns: exact.max_patterns - 1,
                ..exact
            },
            BuildLimits {
                max_pattern_bytes: exact.max_pattern_bytes - 1,
                ..exact
            },
            BuildLimits {
                max_total_pattern_bytes: exact.max_total_pattern_bytes - 1,
                ..exact
            },
            BuildLimits {
                max_identity_bytes: exact.max_identity_bytes - 1,
                ..exact
            },
            BuildLimits {
                max_build_work: exact.max_build_work - 1,
                ..exact
            },
            BuildLimits {
                max_build_peak_bytes: exact.max_build_peak_bytes - 1,
                ..exact
            },
            BuildLimits {
                max_persistent_bytes: exact.max_persistent_bytes - 1,
                ..exact
            },
        ];
        for limits in build_cases {
            let failure = PackedOrderedLiteralCountPlan::build_attempt(&patterns, limits)
                .expect_err("one-below build limit must refuse");
            assert!(failure.closes(), "{failure:?}");
        }

        let haystack = b"abcab\xFF\x00";
        let result = baseline.count(haystack, ReduceLimits::unlimited()).unwrap();
        let upper = result.accounting.upper_bounds;
        let reduce_exact = ReduceLimits {
            max_work: upper.work,
            max_match_events: upper.match_events,
            max_count: upper.count,
            max_span_sum: u64::MAX,
            max_reducer_steps: upper.reducer_steps,
            max_scratch_bytes: upper.scratch_bytes,
            max_peak_bytes: upper.peak_bytes,
        };
        baseline.count(haystack, reduce_exact).unwrap();
        assert!(matches!(
            baseline.count(
                haystack,
                ReduceLimits {
                    max_work: reduce_exact.max_work - 1,
                    ..reduce_exact
                }
            ),
            Err(ReduceError::WorkLimit { .. })
        ));
        assert!(matches!(
            baseline.count(
                haystack,
                ReduceLimits {
                    max_match_events: reduce_exact.max_match_events - 1,
                    ..reduce_exact
                }
            ),
            Err(ReduceError::MatchEventsLimit { .. })
        ));
        assert!(matches!(
            baseline.count(
                haystack,
                ReduceLimits {
                    max_count: reduce_exact.max_count - 1,
                    ..reduce_exact
                }
            ),
            Err(ReduceError::CountLimit { .. })
        ));
        assert!(matches!(
            baseline.count(
                haystack,
                ReduceLimits {
                    max_reducer_steps: reduce_exact.max_reducer_steps - 1,
                    ..reduce_exact
                }
            ),
            Err(ReduceError::ReducerStepsLimit { .. })
        ));
        assert!(matches!(
            baseline.count(
                haystack,
                ReduceLimits {
                    max_peak_bytes: reduce_exact.max_peak_bytes - 1,
                    ..reduce_exact
                }
            ),
            Err(ReduceError::PeakLimit { .. })
        ));

        let span_plan =
            PackedOrderedLiteralSpanSumPlan::build(&patterns, BuildLimits::unlimited()).unwrap();
        let span = span_plan
            .span_sum(haystack, ReduceLimits::unlimited())
            .unwrap();
        assert!(matches!(
            span_plan.span_sum(
                haystack,
                ReduceLimits {
                    max_span_sum: span.accounting.upper_bounds.span_sum - 1,
                    ..ReduceLimits::unlimited()
                }
            ),
            Err(ReduceError::SpanSumLimit { .. })
        ));
    }

    #[test]
    fn failed_owner_allocation_has_a_closed_partial_receipt() {
        let patterns = [b"ab".as_slice(), b"cd".as_slice()];
        let _guard = build_allocation_probe::fail_next();
        let failure =
            PackedOrderedLiteralCountPlan::build_attempt(&patterns, BuildLimits::unlimited())
                .unwrap_err();
        assert!(matches!(
            failure.source(),
            BuildError::AllocationFailed { additional }
                if *additional == size_of::<super::PackedOwner>()
        ));
        assert!(failure.closes());
        let actual = failure.receipt().actual();
        assert_eq!(actual.allocations, 0);
        assert_eq!(actual.allocated_bytes, 0);
        assert_eq!(actual.copied_bytes, 28);
        assert_eq!(actual.live_persistent_bytes, 0);
        assert_eq!(actual.peak_bytes, 0);
    }

    #[test]
    fn theorem_refuses_count_width_and_total_outside_absolute_bounds() {
        assert!(matches!(
            PackedOrderedLiteralCountPlan::build::<&[u8]>(&[], BuildLimits::unlimited()),
            Err(BuildError::EmptyPatternSet)
        ));
        assert!(matches!(
            PackedOrderedLiteralCountPlan::build(&[b"ab".as_slice()], BuildLimits::unlimited()),
            Err(BuildError::ProofRefused {
                fact: "pattern count minimum",
                ..
            })
        ));
        assert!(matches!(
            PackedOrderedLiteralCountPlan::build(
                &[b"a".as_slice(), b"bc".as_slice()],
                BuildLimits::unlimited()
            ),
            Err(BuildError::ProofRefused {
                fact: "literal width minimum",
                ..
            })
        ));
        let too_many = vec![b"aa".as_slice(); super::CERTIFIED_MAX_PATTERNS + 1];
        assert!(matches!(
            PackedOrderedLiteralCountPlan::build(&too_many, BuildLimits::unlimited()),
            Err(BuildError::ProofRefused {
                fact: "pattern count",
                ..
            })
        ));
        let too_wide = vec![b'a'; super::CERTIFIED_MAX_PATTERN_BYTES + 1];
        assert!(matches!(
            PackedOrderedLiteralCountPlan::build(
                &[too_wide.as_slice(), b"bc".as_slice()],
                BuildLimits::unlimited()
            ),
            Err(BuildError::ProofRefused {
                fact: "literal width",
                ..
            })
        ));
        let wide = vec![b'a'; super::CERTIFIED_MAX_PATTERN_BYTES];
        let too_large = vec![wide.as_slice(); super::CERTIFIED_MAX_PATTERNS];
        PackedOrderedLiteralCountPlan::build(&too_large, BuildLimits::unlimited()).unwrap();
    }

    #[test]
    fn set_shape_refusals_and_zero_work_limits_have_closed_receipts() {
        let too_many = vec![b"aa".as_slice(); super::CERTIFIED_MAX_PATTERNS + 1];
        let shape_failure =
            PackedOrderedLiteralCountPlan::build_attempt(&too_many, BuildLimits::unlimited())
                .unwrap_err();
        assert!(matches!(
            shape_failure.source(),
            BuildError::ProofRefused {
                fact: "pattern count",
                ..
            }
        ));
        assert!(shape_failure.closes());
        assert_eq!(shape_failure.receipt().actual().work, 1);

        let zero_work_failure = PackedOrderedLiteralCountPlan::build_attempt(
            &[b"ab".as_slice(), b"cd".as_slice()],
            BuildLimits {
                max_build_work: 0,
                ..BuildLimits::unlimited()
            },
        )
        .unwrap_err();
        assert!(matches!(
            zero_work_failure.source(),
            BuildError::WorkLimit {
                needed: 1,
                limit: 0
            }
        ));
        assert!(zero_work_failure.closes());
        assert_eq!(zero_work_failure.receipt().actual().work, 0);
    }

    #[test]
    fn operation_receipt_is_bounded_and_allocation_free() {
        let patterns = [b"Sherlock".as_slice(), b"Holmes".as_slice()];
        let plan =
            PackedOrderedLiteralCountPlan::build(&patterns, BuildLimits::unlimited()).unwrap();
        let build = plan.build_accounting();
        assert_eq!(build.max_first_byte_bucket_patterns, 1);
        assert_eq!(build.max_first_byte_bucket_pattern_bytes, b"Sherlock".len());
        let result = plan
            .count(
                b"Sherlock and Holmes and Sherlock",
                ReduceLimits::unlimited(),
            )
            .unwrap();
        let upper = result.accounting.upper_bounds;
        let actual = result.accounting.actual;
        assert_eq!(result.count, 3);
        assert_eq!(actual.scratch_bytes, 0);
        assert_eq!(actual.span_sum, None);
        assert_eq!(upper.scratch_bytes, 0);
        assert_eq!(upper.pattern_checks, upper.candidate_positions);
        assert_eq!(
            upper.source_byte_reads,
            upper
                .candidate_positions
                .checked_mul(b"Sherlock".len() + 2)
                .unwrap()
        );
        assert_eq!(actual.classified_positions, upper.candidate_positions);
        assert!(actual.candidate_events <= upper.candidate_positions);
        assert!(actual.pattern_checks <= upper.pattern_checks);
        assert_eq!(actual.source_byte_reads, upper.source_byte_reads);
        assert!(actual.work <= upper.work);
        assert_eq!(upper.restart_tail_positions, 0);
        assert_eq!(upper.iterator_setup_work, 0);
    }
}
