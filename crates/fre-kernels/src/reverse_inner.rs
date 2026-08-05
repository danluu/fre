//! Required-literal reduction for ordered alternatives of
//! `UNICODE_CLASS+ ASCII_LITERAL UNICODE_CLASS+`.
//!
//! Admission requires the same canonical Unicode scalar class on both sides
//! of every alternative, greedy nonempty repetitions, and one nonempty ASCII
//! literal per branch whose scalars all belong to the class. For any maximal
//! class run containing a literal strictly inside the run, greedy backtracking
//! can select a viable literal occurrence and both repetitions together cover
//! the complete run. Every successful alternative therefore has the same
//! whole-match span: that maximal run. Source-order priority can change an
//! internal path or capture, but not count or matched-byte sum.
//!
//! Sparse mixed-Unicode classes with multiple distinct literal-leading bytes
//! first scan their union, then verify the one literal bound to the observed
//! root.
//! Existence and earliest-end projections prove an exact literal with only
//! its immediately preceding and following class scalars. Earliest-end keeps
//! the best accepting end while scanning every later literal start that can
//! still beat it. Selected-span and aggregate operations retain maximal-run
//! recovery because their observable result is the complete greedy run.
//! Dense false-root samples, or repeated exact roots whose complete class runs
//! prove non-accepting, certify a fallback boundary and resume the incumbent
//! independent `memmem` streams after the proved prefix. Other plans use
//! those streams directly. A candidate's maximal run is
//! recovered with bounded reverse and forward UTF-8 decoding. The strict
//! interior is searched from `run_start + 1`, rather than by consuming a
//! non-overlapping occurrence iterator. That detail is required for overlap
//! completeness: class `a`, literal `aa`, and run `aaaa` has its only viable
//! occurrence at offset one. Candidate runs are disjoint, so scalar decoding
//! is linear in source bytes; the fixed number of literal streams contributes
//! another linear factor.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "all resource and index arithmetic is checked before use; bitmap shifts use proved 0..=63 operands"
)]

use core::{fmt, mem::size_of};

use fre_exact_alloc::{CopyError, ExactBoxOrUsize, ExactVec, copy_exact};
use fre_simd_kernels::{
    ASCII_NONMEMBER_RUN_MAX_CLASSIFICATION_OVERHEAD, ASCII_NONMEMBER_RUN_SCANNER_BUILD_WORK,
    AsciiByteSet, AsciiByteSetNonMemberScanner, DispatchPolicy, SimdDispatchContext,
};
use memchr::memmem::{Finder, FinderBuilder};

use crate::{DirectBuildAttempt, DirectBuildAttemptActual, DirectBuildAttemptError, Window};

/// Stable identity of the admitted theorem and physical reducer.
pub const PLAN_ID: &str = "reverse-inner.unicode-class-plus-ascii-literal-class-plus.v1";
/// Physical identity of the sparse-mixed-Unicode adaptive literal-union form.
pub const UNION_PLAN_ID: &str =
    "reverse-inner.sparse-mixed-unicode-class-plus-adaptive-literal-union.v1";
/// Accounting schema of the independent reusable finder form.
pub const ACCOUNTING_ID: &str = "reverse-inner.independent-finder-accounting.v1";
/// Accounting schema of the adaptive literal-union plus incumbent form.
pub const UNION_ACCOUNTING_ID: &str =
    "reverse-inner.adaptive-first-byte-union-accounting.v1";
/// Stable identity of complete non-overlapping match counting.
pub const COUNT_OPERATION_ID: &str = "reverse-inner.count.maximal-unicode-class-run.v1";
/// Stable identity of complete matched-byte summation.
pub const SPAN_SUM_OPERATION_ID: &str = "reverse-inner.span-sum.maximal-unicode-class-run.v1";
/// Stable identity of existence-only ordinary search.
pub const EXISTS_OPERATION_ID: &str = "reverse-inner.exists.maximal-unicode-class-run.v1";
/// Stable identity of selected leftmost-first ordinary search.
pub const SEARCH_OPERATION_ID: &str = "reverse-inner.search.maximal-unicode-class-run.v1";
/// Stable identity of earliest accepting-end ordinary search.
pub const SHORTEST_SEARCH_OPERATION_ID: &str =
    "reverse-inner.shortest.maximal-unicode-class-run.v1";
/// Hard inline bound for independently retained literal streams.
pub const MAX_LITERALS: usize = 16;
/// Auto admission ceiling for the Unicode class's exact ASCII population.
pub const MAX_ADMITTED_ASCII_SCALARS: usize = 64;
/// Auto admission ceiling for the Unicode class's exact non-ASCII population.
///
/// This is one quarter of the 1,111,936 valid non-ASCII Unicode scalar values.
/// It excludes broad complements while retaining genuinely sparse mixed classes.
pub const MAX_ADMITTED_NON_ASCII_SCALARS: usize = 277_984;

const SURROGATE_START: u32 = 0xD800;
const SURROGATE_END: u32 = 0xDFFF;

const BUILD_FIXED_WORK: usize = 16;
const BUILD_RANGE_WORK: usize = 4;
const BUILD_LITERAL_FIXED_WORK: usize = 3;
const BUILD_LITERAL_BYTE_WORK: usize = 5;
const REDUCE_FIXED_WORK: usize = 16;
const FINDER_CALL_WORK: usize = 4;
const RUN_WORK: usize = 8;
const MATCH_WORK: usize = 4;
const MEMBERSHIP_WORK: usize = 2;
const UNION_MASK_BUILD_WORK_PER_LITERAL: usize = 2;
const UNION_LITERAL_CHECK_WORK: usize = 1;
const UNION_ROOT_CANDIDATE_WORK: usize = 1;
const UNION_EXACT_CANDIDATE_WORK: usize = 1;
const UNION_FALLBACK_WORK: usize = 1;
const UNION_PROVED_RUN_SAMPLES_BEFORE_FALLBACK: usize = 2;

/// Complete operation selected before source access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Count,
    SpanSum,
    Exists,
    Search,
    Shortest,
}

/// UTF-8, priority, greediness, and iteration contract proved by admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Semantics {
    /// Rust byte-regex Unicode scalar classes with `utf8(false)`. Invalid
    /// encodings never belong to the class and each invalid byte is a barrier.
    RustBytesUnicodeUtf8False,
}

/// Stable semantic and physical identity for one selected operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each theorem premise is independently authenticated at the facade boundary"
)]
pub struct OperationIdentity {
    pub plan_id: &'static str,
    pub accounting_id: &'static str,
    pub operation_id: &'static str,
    pub operation: Operation,
    pub semantics: Semantics,
    pub source_ranges: usize,
    pub literal_count: usize,
    pub literal_bytes: usize,
    /// Source-order-sensitive fingerprint of literal lengths and bytes.
    pub literal_fingerprint: u64,
    pub unicode: bool,
    pub greedy: bool,
    pub leftmost_first: bool,
    pub non_overlapping: bool,
}

/// Limits checked before any persistent allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    pub max_source_ranges: usize,
    pub max_literals: usize,
    pub max_literal_bytes: usize,
    pub max_total_literal_bytes: usize,
    pub max_build_work: usize,
    pub max_scratch_bytes: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl BuildLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_source_ranges: usize::MAX,
            max_literals: usize::MAX,
            max_literal_bytes: usize::MAX,
            max_total_literal_bytes: usize::MAX,
            max_build_work: usize::MAX,
            max_scratch_bytes: usize::MAX,
            max_persistent_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for BuildLimits {
    fn default() -> Self {
        Self {
            max_source_ranges: 1 << 16,
            max_literals: MAX_LITERALS,
            max_literal_bytes: 1 << 16,
            max_total_literal_bytes: 1 << 20,
            max_build_work: 1 << 24,
            max_scratch_bytes: 0,
            max_persistent_bytes: 1 << 24,
            max_peak_bytes: 1 << 24,
        }
    }
}

/// Auditable exact-capacity construction certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    pub source_ranges: usize,
    pub retained_non_ascii_ranges: usize,
    pub retained_range_capacity: usize,
    pub ascii_scalars: usize,
    pub non_ascii_scalars: usize,
    pub class_scalars: usize,
    pub literal_count: usize,
    pub literal_bytes: usize,
    pub literal_fingerprint: u64,
    pub distinct_literal_first_bytes: usize,
    pub adaptive_union: bool,
    pub work: usize,
    pub allocations: usize,
    pub allocated_bytes: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

/// Limits checked from source-free full-window bounds before source access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceLimits {
    pub max_input_bytes: usize,
    pub max_union_scan_calls: usize,
    pub max_union_classifications: usize,
    pub max_union_root_candidates: usize,
    pub max_union_verification_bytes: usize,
    pub max_union_exact_candidates: usize,
    pub max_union_fallbacks: usize,
    pub max_finder_calls: usize,
    pub max_finder_scanned_bytes: usize,
    pub max_decode_byte_checks: usize,
    pub max_membership_tests: usize,
    pub max_range_comparisons: usize,
    pub max_run_events: usize,
    pub max_match_events: usize,
    pub max_count: u64,
    pub max_span_sum: u64,
    pub max_work: usize,
    pub max_scratch_bytes: usize,
    pub max_peak_bytes: usize,
}

impl ReduceLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_input_bytes: usize::MAX,
            max_union_scan_calls: usize::MAX,
            max_union_classifications: usize::MAX,
            max_union_root_candidates: usize::MAX,
            max_union_verification_bytes: usize::MAX,
            max_union_exact_candidates: usize::MAX,
            max_union_fallbacks: usize::MAX,
            max_finder_calls: usize::MAX,
            max_finder_scanned_bytes: usize::MAX,
            max_decode_byte_checks: usize::MAX,
            max_membership_tests: usize::MAX,
            max_range_comparisons: usize::MAX,
            max_run_events: usize::MAX,
            max_match_events: usize::MAX,
            max_count: u64::MAX,
            max_span_sum: u64::MAX,
            max_work: usize::MAX,
            max_scratch_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for ReduceLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 512 << 20,
            max_union_scan_calls: 1 << 30,
            max_union_classifications: 32 << 30,
            max_union_root_candidates: 1 << 30,
            max_union_verification_bytes: 64 << 30,
            max_union_exact_candidates: 1 << 30,
            max_union_fallbacks: 1,
            max_finder_calls: 1 << 31,
            max_finder_scanned_bytes: 64 << 30,
            max_decode_byte_checks: 4 << 30,
            max_membership_tests: 1 << 30,
            max_range_comparisons: 64 << 30,
            max_run_events: 1 << 30,
            max_match_events: 1 << 30,
            max_count: 1 << 30,
            max_span_sum: u64::MAX,
            max_work: 128 << 30,
            max_scratch_bytes: 0,
            max_peak_bytes: 1 << 24,
        }
    }
}

/// Source-free full-window resource envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceUpperBounds {
    pub input_bytes: usize,
    pub union_scan_calls: usize,
    pub union_classifications: usize,
    pub union_root_candidates: usize,
    pub union_verification_bytes: usize,
    pub union_exact_candidates: usize,
    pub union_fallbacks: usize,
    pub literal_occurrence_positions: usize,
    pub outer_finder_calls: usize,
    pub inner_finder_calls: usize,
    pub finder_calls: usize,
    pub finder_scanned_bytes: usize,
    pub decode_byte_checks: usize,
    pub membership_tests: usize,
    pub range_comparisons: usize,
    pub run_events: usize,
    pub match_events: usize,
    pub count: u64,
    pub span_sum: u64,
    pub work: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

/// Exact structural counters observed by one completed reduction.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReduceActualCounters {
    pub input_bytes: usize,
    pub union_scan_calls: usize,
    pub union_classifications: usize,
    pub union_root_candidates: usize,
    pub union_verification_bytes: usize,
    pub union_exact_candidates: usize,
    pub union_fallbacks: usize,
    pub outer_finder_calls: usize,
    pub inner_finder_calls: usize,
    pub finder_calls: usize,
    pub finder_scanned_bytes: usize,
    pub outer_candidates: usize,
    pub inner_candidates: usize,
    pub decode_byte_checks: usize,
    pub membership_tests: usize,
    pub range_comparisons: usize,
    pub run_events: usize,
    pub match_events: usize,
    pub count: u64,
    pub span_sum: u64,
    pub work: usize,
    pub scratch_bytes: usize,
}

/// Complete execution certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceAccounting {
    pub identity: OperationIdentity,
    pub window: Window,
    pub upper_bounds: ReduceUpperBounds,
    pub actual: ReduceActualCounters,
}

/// Limits checked from a complete source-independent envelope before search.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchLimits {
    pub max_work_upper_bound: u64,
    pub max_scratch_bytes: usize,
}

impl SearchLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_work_upper_bound: u64::MAX,
            max_scratch_bytes: usize::MAX,
        }
    }
}

impl Default for SearchLimits {
    fn default() -> Self {
        Self {
            max_work_upper_bound: 128_u64 << 30,
            max_scratch_bytes: 0,
        }
    }
}

/// Ordinary search reuses the reducer's complete envelope and exact counters.
pub type SearchAccounting = ReduceAccounting;

/// Ordinary search has the reducer's checked window, limit, and invariant errors.
pub type SearchError = ReduceError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountResult {
    pub count: u64,
    pub accounting: ReduceAccounting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanSumResult {
    pub span_sum: u64,
    pub accounting: ReduceAccounting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SearchProjection {
    Exists,
    Selected,
    EarliestEnd,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UnionCandidate {
    start: usize,
    matching_mask: u16,
    shortest_index: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UnionNext {
    Candidate(UnionCandidate),
    Exhausted,
    DenseFallback { resume_start: usize },
}

/// Semantic refusal or checked construction-resource failure.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BuildError {
    EmptyClass,
    ReversedRange {
        start: char,
        end: char,
    },
    NonCanonicalRanges,
    EmptyLiteralSet,
    TooManyLiterals {
        needed: usize,
        limit: usize,
    },
    EmptyLiteral {
        index: usize,
    },
    NonAsciiLiteral {
        index: usize,
        byte: u8,
    },
    LiteralScalarOutsideClass {
        index: usize,
        byte: u8,
    },
    SourceRangesLimit {
        needed: usize,
        limit: usize,
    },
    LiteralBytesLimit {
        needed: usize,
        limit: usize,
    },
    TotalLiteralBytesLimit {
        needed: usize,
        limit: usize,
    },
    WorkLimit {
        needed: usize,
        limit: usize,
    },
    ScratchLimit {
        needed: usize,
        limit: usize,
    },
    PersistentLimit {
        needed: usize,
        limit: usize,
    },
    PeakLimit {
        needed: usize,
        limit: usize,
    },
    AllocationFailed {
        structure: &'static str,
        bytes: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "reverse-inner build failed: {self:?}")
    }
}

impl std::error::Error for BuildError {}

/// Checked execution refusal. No partial aggregate is published.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReduceError {
    InvalidWindow {
        start: usize,
        end: usize,
        haystack_len: usize,
    },
    InputBytesLimit {
        needed: usize,
        limit: usize,
    },
    UnionScanCallsLimit {
        needed: usize,
        limit: usize,
    },
    UnionClassificationsLimit {
        needed: usize,
        limit: usize,
    },
    UnionRootCandidatesLimit {
        needed: usize,
        limit: usize,
    },
    UnionVerificationBytesLimit {
        needed: usize,
        limit: usize,
    },
    UnionExactCandidatesLimit {
        needed: usize,
        limit: usize,
    },
    UnionFallbacksLimit {
        needed: usize,
        limit: usize,
    },
    FinderCallsLimit {
        needed: usize,
        limit: usize,
    },
    FinderScannedBytesLimit {
        needed: usize,
        limit: usize,
    },
    DecodeByteChecksLimit {
        needed: usize,
        limit: usize,
    },
    MembershipTestsLimit {
        needed: usize,
        limit: usize,
    },
    RangeComparisonsLimit {
        needed: usize,
        limit: usize,
    },
    RunEventsLimit {
        needed: usize,
        limit: usize,
    },
    MatchEventsLimit {
        needed: usize,
        limit: usize,
    },
    CountLimit {
        needed: u64,
        limit: u64,
    },
    SpanSumLimit {
        needed: u64,
        limit: u64,
    },
    WorkLimit {
        needed: usize,
        limit: usize,
    },
    ScratchLimit {
        needed: usize,
        limit: usize,
    },
    PeakLimit {
        needed: usize,
        limit: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    AccountingInvariant {
        resource: &'static str,
        actual: u64,
        upper: u64,
    },
}

impl fmt::Display for ReduceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "reverse-inner reduction failed: {self:?}")
    }
}

impl std::error::Error for ReduceError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ScalarRange {
    start: u32,
    end: u32,
}

#[derive(Debug)]
struct UnionState {
    first_byte_masks: [u16; 128],
    scanner: AsciiByteSetNonMemberScanner,
}

/// Owned, deliberately non-`Clone` plan.
#[derive(Debug)]
pub struct ReverseInnerPlan {
    ascii: [u64; 2],
    non_ascii: ExactVec<ScalarRange>,
    finders: ExactVec<Finder<'static>>,
    union_state: ExactBoxOrUsize<UnionState>,
    build: BuildAccounting,
}

impl ReverseInnerPlan {
    /// Build from one canonical scalar class and source-ordered literals.
    pub fn build<I>(ranges: I, literals: &[&[u8]], limits: BuildLimits) -> Result<Self, BuildError>
    where
        I: ExactSizeIterator<Item = (char, char)> + Clone,
    {
        Self::build_attempt_with_dispatch(
            SimdDispatchContext::capture(),
            ranges,
            literals,
            limits,
        )
            .map(DirectBuildAttempt::into_plan)
            .map_err(DirectBuildAttemptError::into_source)
    }

    /// Build while retaining exact successful or partial terminal effects.
    #[allow(
        clippy::too_many_lines,
        reason = "validation, exact-capacity allocations, publication, and terminal effects remain one auditable transaction"
    )]
    pub fn build_attempt<I>(
        ranges: I,
        literals: &[&[u8]],
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<BuildError>>
    where
        I: ExactSizeIterator<Item = (char, char)> + Clone,
    {
        Self::build_attempt_with_dispatch(
            SimdDispatchContext::capture(),
            ranges,
            literals,
            limits,
        )
    }

    #[allow(
        clippy::too_many_lines,
        reason = "validation, exact-capacity allocations, dispatch binding, publication, and terminal effects remain one auditable transaction"
    )]
    fn build_attempt_with_dispatch<I>(
        dispatch: SimdDispatchContext,
        ranges: I,
        literals: &[&[u8]],
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<BuildError>>
    where
        I: ExactSizeIterator<Item = (char, char)> + Clone,
    {
        let mut actual = DirectBuildAttemptActual::default();
        let result = (|| {
            let source_ranges = ranges.len();
            if source_ranges == 0 {
                return Err(BuildError::EmptyClass);
            }
            enforce_build(
                source_ranges,
                limits.max_source_ranges,
                BuildResource::SourceRanges,
            )?;
            if literals.is_empty() {
                return Err(BuildError::EmptyLiteralSet);
            }
            let literal_limit = limits.max_literals.min(MAX_LITERALS);
            if literals.len() > literal_limit {
                return Err(BuildError::TooManyLiterals {
                    needed: literals.len(),
                    limit: literal_limit,
                });
            }

            let mut ascii = [0_u64; 2];
            let mut retained_non_ascii_ranges = 0_usize;
            let mut ascii_scalars = 0_usize;
            let mut class_scalars = 0_usize;
            let mut previous_end = None::<u32>;
            let mut work = BUILD_FIXED_WORK;
            for (start, end) in ranges.clone() {
                if start > end {
                    return Err(BuildError::ReversedRange { start, end });
                }
                let start = u32::from(start);
                let end = u32::from(end);
                if previous_end.is_some_and(|previous| start <= previous.saturating_add(1)) {
                    return Err(BuildError::NonCanonicalRanges);
                }
                previous_end = Some(end);
                work = checked_add_build(work, BUILD_RANGE_WORK, "range validation work")?;
                class_scalars = checked_add_build(
                    class_scalars,
                    valid_scalar_population(start, end)?,
                    "Unicode class scalar population",
                )?;
                if start <= 0x7F {
                    let ascii_end = end.min(0x7F);
                    insert_ascii_range(&mut ascii, start, ascii_end)?;
                    ascii_scalars = checked_add_build(
                        ascii_scalars,
                        usize::try_from(ascii_end - start + 1).map_err(|_| {
                            BuildError::ArithmeticOverflow {
                                computation: "ASCII scalar population",
                            }
                        })?,
                        "ASCII scalar population",
                    )?;
                }
                if end > 0x7F {
                    retained_non_ascii_ranges = checked_add_build(
                        retained_non_ascii_ranges,
                        1,
                        "retained non-ASCII range count",
                    )?;
                }
            }
            let non_ascii_scalars = class_scalars.checked_sub(ascii_scalars).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "non-ASCII scalar population",
                },
            )?;
            if ascii_scalars.checked_add(non_ascii_scalars) != Some(class_scalars) {
                return Err(BuildError::ArithmeticOverflow {
                    computation: "partitioned Unicode class scalar population",
                });
            }

            let mut literal_bytes = 0_usize;
            let mut literal_fingerprint = 0xcbf2_9ce4_8422_2325_u64;
            let mut literal_first_words = [0_u64; 2];
            let mut distinct_literal_first_bytes = 0_usize;
            for (index, literal) in literals.iter().enumerate() {
                if literal.is_empty() {
                    return Err(BuildError::EmptyLiteral { index });
                }
                if literal.len() > limits.max_literal_bytes {
                    return Err(BuildError::LiteralBytesLimit {
                        needed: literal.len(),
                        limit: limits.max_literal_bytes,
                    });
                }
                literal_bytes =
                    checked_add_build(literal_bytes, literal.len(), "literal byte total")?;
                for &byte in *literal {
                    if !byte.is_ascii() {
                        return Err(BuildError::NonAsciiLiteral { index, byte });
                    }
                    if !ascii_contains(ascii, byte) {
                        return Err(BuildError::LiteralScalarOutsideClass { index, byte });
                    }
                    literal_fingerprint ^= u64::from(byte);
                    literal_fingerprint = literal_fingerprint.wrapping_mul(0x100_0000_01b3);
                }
                literal_fingerprint ^=
                    u64::try_from(literal.len()).map_err(|_| BuildError::ArithmeticOverflow {
                        computation: "literal length fingerprint",
                    })?;
                literal_fingerprint = literal_fingerprint.wrapping_mul(0x100_0000_01b3);
                let byte_work = literal.len().checked_mul(BUILD_LITERAL_BYTE_WORK).ok_or(
                    BuildError::ArithmeticOverflow {
                        computation: "literal byte build work",
                    },
                )?;
                work = work
                    .checked_add(BUILD_LITERAL_FIXED_WORK)
                    .and_then(|value| value.checked_add(byte_work))
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "literal build work",
                    })?;
                let first = literal[0];
                let word = usize::from(first / 64);
                let bit = 1_u64 << (first % 64);
                if literal_first_words[word] & bit == 0 {
                    literal_first_words[word] |= bit;
                    distinct_literal_first_bytes = checked_add_build(
                        distinct_literal_first_bytes,
                        1,
                        "distinct literal first bytes",
                    )?;
                }
            }
            if literal_bytes > limits.max_total_literal_bytes {
                return Err(BuildError::TotalLiteralBytesLimit {
                    needed: literal_bytes,
                    limit: limits.max_total_literal_bytes,
                });
            }
            let adaptive_union = literals.len() >= 2
                && retained_non_ascii_ranges != 0
                && non_ascii_scalars != 0
                && non_ascii_scalars <= MAX_ADMITTED_NON_ASCII_SCALARS
                && ascii_scalars <= MAX_ADMITTED_ASCII_SCALARS
                && distinct_literal_first_bytes == literals.len();
            if adaptive_union {
                let mask_work = literals
                    .len()
                    .checked_mul(UNION_MASK_BUILD_WORK_PER_LITERAL)
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "literal-union mask construction work",
                    })?;
                work = work
                    .checked_add(ASCII_NONMEMBER_RUN_SCANNER_BUILD_WORK)
                    .and_then(|value| value.checked_add(mask_work))
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "literal-union construction work",
                    })?;
            }
            actual.work = u64::try_from(work).map_err(|_| BuildError::ArithmeticOverflow {
                computation: "build work as u64",
            })?;
            enforce_build(work, limits.max_build_work, BuildResource::Work)?;

            let range_capacity_bytes = source_ranges.checked_mul(size_of::<ScalarRange>()).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "range capacity bytes",
                },
            )?;
            let finder_capacity_bytes = literals
                .len()
                .checked_mul(size_of::<Finder<'static>>())
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "finder capacity bytes",
                })?;
            let union_state_bytes = usize::from(adaptive_union)
                .checked_mul(size_of::<UnionState>())
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "literal-union state bytes",
                })?;
            let allocated_bytes = range_capacity_bytes
                .checked_add(finder_capacity_bytes)
                .and_then(|value| value.checked_add(literal_bytes))
                .and_then(|value| value.checked_add(union_state_bytes))
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "persistent allocated bytes",
                })?;
            let allocations = usize::from(source_ranges != 0)
                .checked_add(usize::from(!literals.is_empty()))
                .and_then(|value| value.checked_add(literals.len()))
                .and_then(|value| value.checked_add(usize::from(adaptive_union)))
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "persistent allocation count",
                })?;
            let persistent_bytes = size_of::<Self>().checked_add(allocated_bytes).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "persistent plan bytes",
                },
            )?;
            let scratch_bytes = 0_usize;
            let peak_bytes = persistent_bytes;
            enforce_build(
                scratch_bytes,
                limits.max_scratch_bytes,
                BuildResource::Scratch,
            )?;
            enforce_build(
                persistent_bytes,
                limits.max_persistent_bytes,
                BuildResource::Persistent,
            )?;
            enforce_build(peak_bytes, limits.max_peak_bytes, BuildResource::Peak)?;

            let mut non_ascii = ExactVec::try_with_capacity(source_ranges).map_err(|error| {
                allocation_error("Unicode scalar ranges", range_capacity_bytes, error)
            })?;
            record_allocation(&mut actual, range_capacity_bytes)?;
            for (start, end) in ranges {
                let start = u32::from(start);
                let end = u32::from(end);
                if end > 0x7F {
                    non_ascii
                        .try_push(ScalarRange {
                            start: start.max(0x80),
                            end,
                        })
                        .map_err(|_| BuildError::ArithmeticOverflow {
                            computation: "exact non-ASCII range capacity",
                        })?;
                    record_initialization(&mut actual, size_of::<ScalarRange>(), true)?;
                }
            }

            let mut finders = ExactVec::try_with_capacity(literals.len()).map_err(|error| {
                allocation_error("literal finder array", finder_capacity_bytes, error)
            })?;
            record_allocation(&mut actual, finder_capacity_bytes)?;
            for literal in literals {
                let owned = copy_exact(literal)
                    .map_err(|error| allocation_error("literal bytes", literal.len(), error))?;
                record_allocation(&mut actual, literal.len())?;
                record_initialization(&mut actual, literal.len(), true)?;
                let finder = FinderBuilder::new().build_forward_owned(owned.into_boxed_slice());
                finders
                    .try_push(finder)
                    .map_err(|_| BuildError::ArithmeticOverflow {
                        computation: "exact finder capacity",
                    })?;
                record_initialization(&mut actual, size_of::<Finder<'static>>(), false)?;
            }

            let union_state = if adaptive_union {
                let mut first_byte_masks = [0_u16; 128];
                for (index, literal) in literals.iter().enumerate() {
                    let shift = u32::try_from(index).map_err(|_| {
                        BuildError::ArithmeticOverflow {
                            computation: "literal-union mask shift",
                        }
                    })?;
                    let bit = 1_u16.checked_shl(shift).ok_or(
                        BuildError::ArithmeticOverflow {
                            computation: "literal-union mask bit",
                        },
                    )?;
                    first_byte_masks[usize::from(literal[0])] |= bit;
                }
                let scanner = dispatch
                    .ascii_byte_set_nonmember_scanner(
                        AsciiByteSet::from_words(literal_first_words),
                        DispatchPolicy::Auto,
                    )
                    .expect("automatic literal-union dispatch retains a scalar fallback");
                let state = ExactBoxOrUsize::try_from_boxed(UnionState {
                    first_byte_masks,
                    scanner,
                })
                .map_err(|error| {
                    allocation_error("literal-union state", union_state_bytes, error)
                })?;
                record_allocation(&mut actual, union_state_bytes)?;
                record_initialization(&mut actual, union_state_bytes, false)?;
                state
            } else {
                ExactBoxOrUsize::try_from_usize(0)
                    .expect("zero is an exact inline literal-union tag")
            };

            actual.initialized_bytes = actual
                .initialized_bytes
                .checked_add(size_of::<Self>())
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "published plan initialized bytes",
                })?;
            actual.live_persistent_bytes = persistent_bytes;
            actual.peak_bytes = actual.peak_bytes.max(persistent_bytes);
            debug_assert_eq!(actual.allocations, allocations);
            debug_assert_eq!(actual.allocated_bytes, allocated_bytes);
            let build = BuildAccounting {
                source_ranges,
                retained_non_ascii_ranges,
                retained_range_capacity: source_ranges,
                ascii_scalars,
                non_ascii_scalars,
                class_scalars,
                literal_count: literals.len(),
                literal_bytes,
                literal_fingerprint,
                distinct_literal_first_bytes,
                adaptive_union,
                work,
                allocations,
                allocated_bytes,
                scratch_bytes,
                persistent_bytes,
                peak_bytes,
            };
            Ok(Self {
                ascii,
                non_ascii,
                finders,
                union_state,
                build,
            })
        })();
        match result {
            Ok(plan) => Ok(DirectBuildAttempt::new(plan, actual)),
            Err(source) => {
                actual.live_persistent_bytes = 0;
                Err(DirectBuildAttemptError::new(source, actual))
            }
        }
    }

    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.build
    }

    #[must_use]
    pub const fn count_identity(&self) -> OperationIdentity {
        self.identity(Operation::Count)
    }

    #[must_use]
    pub const fn span_sum_identity(&self) -> OperationIdentity {
        self.identity(Operation::SpanSum)
    }

    #[must_use]
    pub const fn search_identity(&self) -> OperationIdentity {
        self.identity(Operation::Search)
    }

    #[must_use]
    pub const fn exists_identity(&self) -> OperationIdentity {
        self.identity(Operation::Exists)
    }

    #[must_use]
    pub const fn shortest_identity(&self) -> OperationIdentity {
        self.identity(Operation::Shortest)
    }

    #[must_use]
    pub const fn plan_id(&self) -> &'static str {
        if self.build.adaptive_union {
            UNION_PLAN_ID
        } else {
            PLAN_ID
        }
    }

    fn union_state(&self) -> Option<&UnionState> {
        self.union_state.boxed()
    }

    const fn identity(&self, operation: Operation) -> OperationIdentity {
        OperationIdentity {
            plan_id: self.plan_id(),
            accounting_id: if self.build.adaptive_union {
                UNION_ACCOUNTING_ID
            } else {
                ACCOUNTING_ID
            },
            operation_id: match operation {
                Operation::Count => COUNT_OPERATION_ID,
                Operation::SpanSum => SPAN_SUM_OPERATION_ID,
                Operation::Exists => EXISTS_OPERATION_ID,
                Operation::Search => SEARCH_OPERATION_ID,
                Operation::Shortest => SHORTEST_SEARCH_OPERATION_ID,
            },
            operation,
            semantics: Semantics::RustBytesUnicodeUtf8False,
            source_ranges: self.build.source_ranges,
            literal_count: self.build.literal_count,
            literal_bytes: self.build.literal_bytes,
            literal_fingerprint: self.build.literal_fingerprint,
            unicode: true,
            greedy: true,
            leftmost_first: true,
            non_overlapping: true,
        }
    }

    /// Publish the source-free reduction and selected-search full-window
    /// envelope. Adaptive-union existence and earliest-end receipts add their
    /// adjacent-scalar proof envelope before checking search limits.
    pub fn full_window_upper_bounds(
        &self,
        input_bytes: usize,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        derive_upper_bounds(self.build, &self.finders, input_bytes)
    }

    pub fn count(&self, haystack: &[u8], limits: ReduceLimits) -> Result<CountResult, ReduceError> {
        self.count_in(haystack, Window::full(haystack), limits)
    }

    pub fn count_in(
        &self,
        haystack: &[u8],
        window: Window,
        limits: ReduceLimits,
    ) -> Result<CountResult, ReduceError> {
        let upper = self.preflight(haystack, window, Operation::Count, limits)?;
        let actual = self.execute(haystack, window, Operation::Count, upper)?;
        Ok(CountResult {
            count: actual.count,
            accounting: ReduceAccounting {
                identity: self.count_identity(),
                window,
                upper_bounds: upper,
                actual,
            },
        })
    }

    pub fn span_sum(
        &self,
        haystack: &[u8],
        limits: ReduceLimits,
    ) -> Result<SpanSumResult, ReduceError> {
        self.span_sum_in(haystack, Window::full(haystack), limits)
    }

    pub fn span_sum_in(
        &self,
        haystack: &[u8],
        window: Window,
        limits: ReduceLimits,
    ) -> Result<SpanSumResult, ReduceError> {
        let upper = self.preflight(haystack, window, Operation::SpanSum, limits)?;
        let actual = self.execute(haystack, window, Operation::SpanSum, upper)?;
        Ok(SpanSumResult {
            span_sum: actual.span_sum,
            accounting: ReduceAccounting {
                identity: self.span_sum_identity(),
                window,
                upper_bounds: upper,
                actual,
            },
        })
    }

    /// Find the selected leftmost-first span in the complete haystack.
    pub fn find(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting), SearchError> {
        self.find_in(haystack, Window::full(haystack), limits)
    }

    /// Find the selected leftmost-first span wholly inside `window`.
    pub fn find_in(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting), SearchError> {
        self.search_in(
            haystack,
            window,
            limits,
            SearchProjection::Selected,
            Operation::Search,
        )
    }

    /// Report whether a match exists in the complete haystack.
    pub fn is_match(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(bool, SearchAccounting), SearchError> {
        self.is_match_in(haystack, Window::full(haystack), limits)
    }

    /// Report whether a match exists wholly inside `window`.
    pub fn is_match_in(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<(bool, SearchAccounting), SearchError> {
        let (matched, accounting) = self.search_in(
            haystack,
            window,
            limits,
            SearchProjection::Exists,
            Operation::Exists,
        )?;
        Ok((matched.is_some(), accounting))
    }

    /// Return the first accepting end offset in the complete haystack.
    pub fn shortest(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        self.shortest_in(haystack, Window::full(haystack), limits)
    }

    /// Return the first accepting end offset wholly inside `window`.
    pub fn shortest_in(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        let (matched, accounting) =
            self.search_in(
                haystack,
                window,
                limits,
                SearchProjection::EarliestEnd,
                Operation::Shortest,
            )?;
        Ok((matched.map(|(_, end)| end), accounting))
    }

    fn search_in(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
        projection: SearchProjection,
        operation: Operation,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting), SearchError> {
        let upper = self.search_preflight(haystack, window, limits, projection)?;
        let (matched, actual) = self.execute_search(haystack, window, projection, upper)?;
        debug_assert!(matches!(
            (projection, operation),
            (SearchProjection::Selected, Operation::Search)
                | (SearchProjection::Exists, Operation::Exists)
                | (SearchProjection::EarliestEnd, Operation::Shortest)
        ));
        Ok((
            matched,
            SearchAccounting {
                identity: self.identity(operation),
                window,
                upper_bounds: upper,
                actual,
            },
        ))
    }

    fn search_preflight(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
        projection: SearchProjection,
    ) -> Result<ReduceUpperBounds, SearchError> {
        if window.start() > window.end() || window.end() > haystack.len() {
            return Err(ReduceError::InvalidWindow {
                start: window.start(),
                end: window.end(),
                haystack_len: haystack.len(),
            });
        }
        let input_bytes =
            window
                .end()
                .checked_sub(window.start())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "search window byte length",
                })?;
        let mut upper = derive_upper_bounds(self.build, &self.finders, input_bytes)?;
        if self.build.adaptive_union && projection != SearchProjection::Selected {
            expand_union_endpoint_upper_bounds(
                &mut upper,
                input_bytes,
                self.build.retained_non_ascii_ranges,
            )?;
        }
        let work_upper_bound = u64::try_from(upper.work).unwrap_or(u64::MAX);
        if work_upper_bound > limits.max_work_upper_bound {
            return Err(ReduceError::WorkLimit {
                needed: upper.work,
                limit: usize::try_from(limits.max_work_upper_bound).unwrap_or(usize::MAX),
            });
        }
        enforce_reduce(
            upper.scratch_bytes,
            limits.max_scratch_bytes,
            ReduceResource::Scratch,
        )?;
        Ok(upper)
    }

    fn preflight(
        &self,
        haystack: &[u8],
        window: Window,
        operation: Operation,
        limits: ReduceLimits,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        if window.start() > window.end() || window.end() > haystack.len() {
            return Err(ReduceError::InvalidWindow {
                start: window.start(),
                end: window.end(),
                haystack_len: haystack.len(),
            });
        }
        let input_bytes =
            window
                .end()
                .checked_sub(window.start())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "window byte length",
                })?;
        let upper = derive_upper_bounds(self.build, &self.finders, input_bytes)?;
        enforce_reduce(
            upper.input_bytes,
            limits.max_input_bytes,
            ReduceResource::InputBytes,
        )?;
        enforce_reduce(
            upper.union_scan_calls,
            limits.max_union_scan_calls,
            ReduceResource::UnionScanCalls,
        )?;
        enforce_reduce(
            upper.union_classifications,
            limits.max_union_classifications,
            ReduceResource::UnionClassifications,
        )?;
        enforce_reduce(
            upper.union_root_candidates,
            limits.max_union_root_candidates,
            ReduceResource::UnionRootCandidates,
        )?;
        enforce_reduce(
            upper.union_verification_bytes,
            limits.max_union_verification_bytes,
            ReduceResource::UnionVerificationBytes,
        )?;
        enforce_reduce(
            upper.union_exact_candidates,
            limits.max_union_exact_candidates,
            ReduceResource::UnionExactCandidates,
        )?;
        enforce_reduce(
            upper.union_fallbacks,
            limits.max_union_fallbacks,
            ReduceResource::UnionFallbacks,
        )?;
        enforce_reduce(
            upper.finder_calls,
            limits.max_finder_calls,
            ReduceResource::FinderCalls,
        )?;
        enforce_reduce(
            upper.finder_scanned_bytes,
            limits.max_finder_scanned_bytes,
            ReduceResource::FinderScannedBytes,
        )?;
        enforce_reduce(
            upper.decode_byte_checks,
            limits.max_decode_byte_checks,
            ReduceResource::DecodeByteChecks,
        )?;
        enforce_reduce(
            upper.membership_tests,
            limits.max_membership_tests,
            ReduceResource::MembershipTests,
        )?;
        enforce_reduce(
            upper.range_comparisons,
            limits.max_range_comparisons,
            ReduceResource::RangeComparisons,
        )?;
        enforce_reduce(
            upper.run_events,
            limits.max_run_events,
            ReduceResource::RunEvents,
        )?;
        enforce_reduce(
            upper.match_events,
            limits.max_match_events,
            ReduceResource::MatchEvents,
        )?;
        if upper.count > limits.max_count {
            return Err(ReduceError::CountLimit {
                needed: upper.count,
                limit: limits.max_count,
            });
        }
        if operation == Operation::SpanSum && upper.span_sum > limits.max_span_sum {
            return Err(ReduceError::SpanSumLimit {
                needed: upper.span_sum,
                limit: limits.max_span_sum,
            });
        }
        enforce_reduce(upper.work, limits.max_work, ReduceResource::Work)?;
        enforce_reduce(
            upper.scratch_bytes,
            limits.max_scratch_bytes,
            ReduceResource::Scratch,
        )?;
        enforce_reduce(
            upper.peak_bytes,
            limits.max_peak_bytes,
            ReduceResource::Peak,
        )?;
        Ok(upper)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the monotone literal streams, maximal-run validation, and cumulative exact counters are kept adjacent"
    )]
    fn execute(
        &self,
        haystack: &[u8],
        window: Window,
        operation: Operation,
        upper: ReduceUpperBounds,
    ) -> Result<ReduceActualCounters, ReduceError> {
        let actual = ReduceActualCounters {
            input_bytes: upper.input_bytes,
            work: REDUCE_FIXED_WORK,
            ..ReduceActualCounters::default()
        };
        if self.union_state().is_some() {
            self.execute_union(haystack, window, operation, upper, actual)
        } else {
            self.execute_independent_from(
                haystack,
                window,
                operation,
                upper,
                window.start(),
                actual,
            )
        }
    }

    fn next_union_candidate(
        &self,
        haystack: &[u8],
        mut scan_start: usize,
        scan_ceiling: usize,
        verification_ceiling: usize,
        actual: &mut ReduceActualCounters,
    ) -> Result<UnionNext, ReduceError> {
        let state = self
            .union_state()
            .ok_or(ReduceError::AccountingInvariant {
                resource: "literal-union state",
                actual: 0,
                upper: 1,
            })?;
        let mut previous_scanned_through = scan_start;
        while scan_start < scan_ceiling {
            let source = haystack.get(scan_start..scan_ceiling).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "literal-union scan window",
                },
            )?;
            actual.union_scan_calls = checked_add_reduce(
                actual.union_scan_calls,
                1,
                "literal-union scan calls",
            )?;
            let scanned = state.scanner.scan_forward(source);
            actual.union_classifications = checked_add_reduce(
                actual.union_classifications,
                scanned.examined_bytes(),
                "literal-union classifications",
            )?;
            actual.work = checked_add_reduce(
                actual.work,
                scanned.examined_bytes(),
                "literal-union classification work",
            )?;
            if scanned.nonmember_run_len() == source.len() {
                return Ok(UnionNext::Exhausted);
            }
            let candidate_start = scan_start
                .checked_add(scanned.nonmember_run_len())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "literal-union candidate start",
                })?;
            let byte = *haystack.get(candidate_start).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "literal-union candidate byte",
                },
            )?;
            let candidate_mask = *state.first_byte_masks.get(usize::from(byte)).ok_or(
                ReduceError::AccountingInvariant {
                    resource: "literal-union ASCII candidate byte",
                    actual: u64::from(byte),
                    upper: 0x7f,
                },
            )?;
            if candidate_mask == 0 {
                return Err(ReduceError::AccountingInvariant {
                    resource: "literal-union candidate mask",
                    actual: 0,
                    upper: 1,
                });
            }
            actual.union_root_candidates = checked_add_reduce(
                actual.union_root_candidates,
                1,
                "literal-union root candidates",
            )?;
            actual.work = checked_add_reduce(
                actual.work,
                UNION_ROOT_CANDIDATE_WORK,
                "literal-union root candidate work",
            )?;

            let mut matching_mask = 0_u16;
            let mut shortest = None::<(usize, usize)>;
            let mut verification_work = 0_usize;
            let mut unchecked_mask = candidate_mask;
            while unchecked_mask != 0 {
                let shift = unchecked_mask.trailing_zeros();
                let index = usize::try_from(shift).map_err(|_| {
                    ReduceError::ArithmeticOverflow {
                        computation: "literal-union candidate index",
                    }
                })?;
                let bit = 1_u16.checked_shl(shift).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "literal-union candidate mask bit",
                    },
                )?;
                unchecked_mask &= !bit;
                let finder = self.finders.get(index).ok_or(
                    ReduceError::AccountingInvariant {
                        resource: "literal-union candidate finder",
                        actual: u64::try_from(index).unwrap_or(u64::MAX),
                        upper: u64::try_from(self.finders.len()).unwrap_or(u64::MAX),
                    },
                )?;
                verification_work = checked_add_reduce(
                    verification_work,
                    UNION_LITERAL_CHECK_WORK,
                    "literal-union local literal-check work",
                )?;
                actual.work = checked_add_reduce(
                    actual.work,
                    UNION_LITERAL_CHECK_WORK,
                    "literal-union literal-check work",
                )?;
                let needle = finder.needle();
                let candidate_end = candidate_start.checked_add(needle.len()).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "literal-union verification end",
                    },
                )?;
                if candidate_end > verification_ceiling {
                    continue;
                }
                let candidate = haystack.get(candidate_start..candidate_end).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "literal-union verification window",
                    },
                )?;
                actual.union_verification_bytes = checked_add_reduce(
                    actual.union_verification_bytes,
                    needle.len(),
                    "literal-union verification bytes",
                )?;
                verification_work = checked_add_reduce(
                    verification_work,
                    needle.len(),
                    "literal-union local verification work",
                )?;
                actual.work = checked_add_reduce(
                    actual.work,
                    needle.len(),
                    "literal-union verification work",
                )?;
                if candidate == needle {
                    matching_mask |= bit;
                    // Simultaneously exact needles at one start are identical
                    // through the shorter length. The shortest therefore has
                    // the earliest possible following-scalar endpoint; source
                    // order remains the tie-break because masks are ascending.
                    let replace_shortest = shortest
                        .is_none_or(|(_, old_length)| needle.len() < old_length);
                    if replace_shortest {
                        shortest = Some((index, needle.len()));
                    }
                }
            }

            if matching_mask != 0 {
                let (shortest_index, _) = shortest.ok_or(
                    ReduceError::AccountingInvariant {
                        resource: "literal-union shortest exact candidate",
                        actual: 0,
                        upper: 1,
                    },
                )?;
                let shortest_index = u8::try_from(shortest_index).map_err(|_| {
                    ReduceError::ArithmeticOverflow {
                        computation: "literal-union shortest candidate index",
                    }
                })?;
                actual.union_exact_candidates = checked_add_reduce(
                    actual.union_exact_candidates,
                    1,
                    "literal-union exact candidates",
                )?;
                actual.outer_candidates = checked_add_reduce(
                    actual.outer_candidates,
                    1,
                    "literal-union outer candidates",
                )?;
                actual.work = checked_add_reduce(
                    actual.work,
                    UNION_EXACT_CANDIDATE_WORK,
                    "literal-union exact candidate work",
                )?;
                return Ok(UnionNext::Candidate(UnionCandidate {
                    start: candidate_start,
                    matching_mask,
                    shortest_index,
                }));
            }

            let resume_start = candidate_start.checked_add(1).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "literal-union false-candidate progress",
                },
            )?;
            let local_span = resume_start.checked_sub(previous_scanned_through).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "literal-union rejection sample span",
                },
            )?;
            if verification_work > local_span {
                actual.union_fallbacks = checked_add_reduce(
                    actual.union_fallbacks,
                    1,
                    "literal-union fallbacks",
                )?;
                actual.work = checked_add_reduce(
                    actual.work,
                    UNION_FALLBACK_WORK,
                    "literal-union fallback work",
                )?;
                return Ok(UnionNext::DenseFallback { resume_start });
            }
            previous_scanned_through = resume_start;
            scan_start = resume_start;
        }
        Ok(UnionNext::Exhausted)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "adaptive union traversal, certified fallback, and exact counters remain adjacent"
    )]
    fn execute_union(
        &self,
        haystack: &[u8],
        window: Window,
        operation: Operation,
        upper: ReduceUpperBounds,
        mut actual: ReduceActualCounters,
    ) -> Result<ReduceActualCounters, ReduceError> {
        let mut cursor = window.start();
        let mut unproductive_run_samples = 0_usize;
        loop {
            let candidate = match self.next_union_candidate(
                haystack,
                cursor,
                window.end(),
                window.end(),
                &mut actual,
            )? {
                UnionNext::Candidate(candidate) => candidate,
                UnionNext::Exhausted => {
                    actual.finder_calls = actual
                        .outer_finder_calls
                        .checked_add(actual.inner_finder_calls)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "literal-union total finder calls",
                        })?;
                    verify_actual(actual, upper)?;
                    return Ok(actual);
                }
                UnionNext::DenseFallback { resume_start } => {
                    return self.execute_independent_from(
                        haystack,
                        window,
                        operation,
                        upper,
                        resume_start,
                        actual,
                    );
                }
            };
            let candidate_index = usize::try_from(candidate.matching_mask.trailing_zeros())
                .map_err(|_| ReduceError::ArithmeticOverflow {
                    computation: "literal-union first matching index",
                })?;
            let candidate_finder = self.finders.get(candidate_index).ok_or(
                ReduceError::AccountingInvariant {
                    resource: "literal-union matching finder",
                    actual: u64::try_from(candidate_index).unwrap_or(u64::MAX),
                    upper: u64::try_from(self.finders.len()).unwrap_or(u64::MAX),
                },
            )?;
            let candidate_end = candidate
                .start
                .checked_add(candidate_finder.needle().len())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "literal-union candidate end",
                })?;
            let run_start =
                self.scan_run_backward(haystack, window.start(), candidate.start, &mut actual)?;
            let run_end =
                self.scan_run_forward(haystack, candidate_end, window.end(), &mut actual)?;
            actual.run_events = checked_add_reduce(
                actual.run_events,
                1,
                "literal-union candidate run count",
            )?;
            actual.work = checked_add_reduce(
                actual.work,
                RUN_WORK,
                "literal-union candidate run work",
            )?;

            let mut matched = false;
            let mut strict_mask = candidate.matching_mask;
            while strict_mask != 0 {
                let shift = strict_mask.trailing_zeros();
                let index = usize::try_from(shift).map_err(|_| {
                    ReduceError::ArithmeticOverflow {
                        computation: "literal-union strict candidate index",
                    }
                })?;
                let bit = 1_u16.checked_shl(shift).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "literal-union strict mask bit",
                    },
                )?;
                strict_mask &= !bit;
                let finder = self.finders.get(index).ok_or(
                    ReduceError::AccountingInvariant {
                        resource: "literal-union strict candidate finder",
                        actual: u64::try_from(index).unwrap_or(u64::MAX),
                        upper: u64::try_from(self.finders.len()).unwrap_or(u64::MAX),
                    },
                )?;
                let end = candidate.start.checked_add(finder.needle().len()).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "literal-union strict candidate end",
                    },
                )?;
                if candidate.start > run_start && end < run_end {
                    matched = true;
                    break;
                }
            }
            if !matched {
                let interior_start = run_start.checked_add(1).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "literal-union strict run interior start",
                    },
                )?;
                if interior_start < run_end {
                    for finder in &self.finders {
                        if find_strict_inner_candidate(
                            finder,
                            haystack,
                            interior_start,
                            run_end,
                            &mut actual,
                        )?
                        .is_some_and(|(_, end)| end < run_end)
                        {
                            matched = true;
                            break;
                        }
                    }
                }
            }

            if matched {
                unproductive_run_samples = 0;
                actual.match_events = checked_add_reduce(
                    actual.match_events,
                    1,
                    "literal-union match event count",
                )?;
                actual.count = actual.count.checked_add(1).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "literal-union match count",
                    },
                )?;
                if operation == Operation::SpanSum {
                    let width = run_end.checked_sub(run_start).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "literal-union matched run width",
                        },
                    )?;
                    actual.span_sum = actual
                        .span_sum
                        .checked_add(u64::try_from(width).map_err(|_| {
                            ReduceError::ArithmeticOverflow {
                                computation: "literal-union matched run width as u64",
                            }
                        })?)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "literal-union matched byte sum",
                        })?;
                }
                actual.work = checked_add_reduce(
                    actual.work,
                    MATCH_WORK,
                    "literal-union match work",
                )?;
            } else {
                unproductive_run_samples = checked_add_reduce(
                    unproductive_run_samples,
                    1,
                    "literal-union unproductive run samples",
                )?;
                if unproductive_run_samples < UNION_PROVED_RUN_SAMPLES_BEFORE_FALLBACK {
                    cursor = run_end;
                    continue;
                }
                actual.union_fallbacks = checked_add_reduce(
                    actual.union_fallbacks,
                    1,
                    "literal-union proved-run fallbacks",
                )?;
                actual.work = checked_add_reduce(
                    actual.work,
                    UNION_FALLBACK_WORK,
                    "literal-union proved-run fallback work",
                )?;
                return self.execute_independent_from(
                    haystack,
                    window,
                    operation,
                    upper,
                    run_end,
                    actual,
                );
            }
            cursor = run_end;
        }
    }

    fn execute_independent_from(
        &self,
        haystack: &[u8],
        window: Window,
        operation: Operation,
        upper: ReduceUpperBounds,
        resume_start: usize,
        mut actual: ReduceActualCounters,
    ) -> Result<ReduceActualCounters, ReduceError> {
        let mut cursors = [resume_start; MAX_LITERALS];
        let mut cached = [None::<usize>; MAX_LITERALS];
        let mut exhausted = [false; MAX_LITERALS];

        loop {
            for (index, finder) in self.finders.iter().enumerate() {
                if cached[index].is_some() || exhausted[index] {
                    continue;
                }
                let cursor = cursors[index].max(window.start());
                let remaining =
                    window
                        .end()
                        .checked_sub(cursor)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "outer finder remaining bytes",
                        })?;
                if remaining < finder.needle().len() {
                    exhausted[index] = true;
                    continue;
                }
                let search =
                    haystack
                        .get(cursor..window.end())
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "outer finder search window",
                        })?;
                let relative = find_and_charge(finder, search, false, &mut actual)?;
                if let Some(relative) = relative {
                    let absolute =
                        cursor
                            .checked_add(relative)
                            .ok_or(ReduceError::ArithmeticOverflow {
                                computation: "outer finder absolute candidate",
                            })?;
                    cached[index] = Some(absolute);
                    cursors[index] =
                        absolute
                            .checked_add(1)
                            .ok_or(ReduceError::ArithmeticOverflow {
                                computation: "overlapping outer finder progress",
                            })?;
                    actual.outer_candidates =
                        checked_add_reduce(actual.outer_candidates, 1, "outer candidate count")?;
                } else {
                    exhausted[index] = true;
                }
            }

            let Some((candidate_index, candidate_start)) = cached
                .iter()
                .take(self.finders.len())
                .enumerate()
                .filter_map(|(index, candidate)| candidate.map(|start| (index, start)))
                .min_by_key(|&(index, start)| (start, index))
            else {
                break;
            };
            let candidate_end = candidate_start
                .checked_add(self.finders[candidate_index].needle().len())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "candidate literal end",
                })?;
            let run_start =
                self.scan_run_backward(haystack, window.start(), candidate_start, &mut actual)?;
            let run_end =
                self.scan_run_forward(haystack, candidate_end, window.end(), &mut actual)?;
            actual.run_events = checked_add_reduce(actual.run_events, 1, "candidate run count")?;
            actual.work = checked_add_reduce(actual.work, RUN_WORK, "candidate run work")?;

            let interior_start =
                run_start
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "strict run interior start",
                    })?;
            let mut matched = false;
            if interior_start < run_end {
                for finder in &self.finders {
                    let remaining = run_end.checked_sub(interior_start).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "strict run interior bytes",
                        },
                    )?;
                    if remaining < finder.needle().len() {
                        continue;
                    }
                    let search = haystack.get(interior_start..run_end).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "strict interior finder window",
                        },
                    )?;
                    if let Some(relative) = find_and_charge(finder, search, true, &mut actual)? {
                        actual.inner_candidates = checked_add_reduce(
                            actual.inner_candidates,
                            1,
                            "inner literal candidate count",
                        )?;
                        let start = interior_start.checked_add(relative).ok_or(
                            ReduceError::ArithmeticOverflow {
                                computation: "inner literal absolute start",
                            },
                        )?;
                        let end = start.checked_add(finder.needle().len()).ok_or(
                            ReduceError::ArithmeticOverflow {
                                computation: "inner literal absolute end",
                            },
                        )?;
                        if end < run_end {
                            matched = true;
                            break;
                        }
                    }
                }
            }

            if matched {
                actual.match_events =
                    checked_add_reduce(actual.match_events, 1, "match event count")?;
                actual.count =
                    actual
                        .count
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "match count",
                        })?;
                if operation == Operation::SpanSum {
                    let width =
                        run_end
                            .checked_sub(run_start)
                            .ok_or(ReduceError::ArithmeticOverflow {
                                computation: "matched run width",
                            })?;
                    actual.span_sum = actual
                        .span_sum
                        .checked_add(u64::try_from(width).map_err(|_| {
                            ReduceError::ArithmeticOverflow {
                                computation: "matched run width as u64",
                            }
                        })?)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "matched byte sum",
                        })?;
                }
                actual.work = checked_add_reduce(actual.work, MATCH_WORK, "match work")?;
            }

            for index in 0..self.finders.len() {
                let discarded = cached[index].is_some_and(|start| start < run_end);
                if discarded {
                    cached[index] = None;
                }
                cursors[index] = cursors[index].max(run_end);
                if discarded && cursors[index] < window.end() {
                    exhausted[index] = false;
                }
            }
        }

        actual.finder_calls = actual
            .outer_finder_calls
            .checked_add(actual.inner_finder_calls)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "total finder calls",
            })?;
        verify_actual(actual, upper)?;
        Ok(actual)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the early-stop search mirrors the proved monotone reducer traversal while keeping its exact counters adjacent"
    )]
    fn execute_search(
        &self,
        haystack: &[u8],
        window: Window,
        projection: SearchProjection,
        upper: ReduceUpperBounds,
    ) -> Result<(Option<(usize, usize)>, ReduceActualCounters), SearchError> {
        let actual = ReduceActualCounters {
            input_bytes: upper.input_bytes,
            work: REDUCE_FIXED_WORK,
            ..ReduceActualCounters::default()
        };
        if self.union_state().is_some() {
            if projection == SearchProjection::Selected {
                self.execute_union_search(haystack, window, projection, upper, actual)
            } else {
                self.execute_union_endpoint_search(
                    haystack,
                    window,
                    projection,
                    upper,
                    actual,
                )
            }
        } else {
            self.execute_independent_search_from(
                haystack,
                window,
                projection,
                upper,
                window.start(),
                actual,
            )
        }
    }

    fn prove_union_endpoint_candidate(
        &self,
        haystack: &[u8],
        window: Window,
        candidate: UnionCandidate,
        actual: &mut ReduceActualCounters,
    ) -> Result<Option<(usize, usize)>, SearchError> {
        if candidate.start <= window.start() {
            return Ok(None);
        }
        // Admission proves every ASCII literal scalar belongs to the class.
        // Only the scalar immediately on each side remains to be proved; no
        // byte elsewhere in the surrounding maximal run can affect these
        // endpoint projections.
        let preceding = decode_previous_scalar(haystack, window.start(), candidate.start)?;
        charge_decode(preceding.byte_checks, actual)?;
        let Some(preceding_scalar) = preceding.scalar else {
            return Ok(None);
        };
        if preceding.width == 0 || !self.contains(preceding_scalar, actual)? {
            return Ok(None);
        }

        let shortest_index = usize::from(candidate.shortest_index);
        let finder = self.finders.get(shortest_index).ok_or(
            ReduceError::AccountingInvariant {
                resource: "literal-union endpoint finder",
                actual: u64::try_from(shortest_index).unwrap_or(u64::MAX),
                upper: u64::try_from(self.finders.len()).unwrap_or(u64::MAX),
            },
        )?;
        let literal_end = candidate
            .start
            .checked_add(finder.needle().len())
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "literal-union endpoint literal end",
            })?;
        if literal_end >= window.end() {
            return Ok(None);
        }
        let following_bytes = haystack.get(literal_end..window.end()).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "literal-union endpoint following window",
            },
        )?;
        let following = decode_scalar(following_bytes);
        charge_decode(following.byte_checks, actual)?;
        let Some(following_scalar) = following.scalar else {
            return Ok(None);
        };
        if following.width == 0 || !self.contains(following_scalar, actual)? {
            return Ok(None);
        }

        let start = candidate.start.checked_sub(preceding.width).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "literal-union endpoint accepting start",
            },
        )?;
        let end = literal_end.checked_add(following.width).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "literal-union endpoint accepting end",
            },
        )?;
        Ok(Some((start, end)))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the fallback preserves the checked window, projection, retained endpoint, and cumulative accounting"
    )]
    fn execute_union_endpoint_fallback(
        &self,
        haystack: &[u8],
        window: Window,
        projection: SearchProjection,
        upper: ReduceUpperBounds,
        resume_start: usize,
        best: Option<(usize, usize)>,
        actual: ReduceActualCounters,
    ) -> Result<(Option<(usize, usize)>, ReduceActualCounters), SearchError> {
        let (fallback, actual) = self.execute_independent_search_from(
            haystack,
            window,
            projection,
            upper,
            resume_start,
            actual,
        )?;
        let selected = match (best, fallback) {
            (Some(old), Some(new)) => Some(if (new.1, new.0) < (old.1, old.0) {
                new
            } else {
                old
            }),
            (Some(old), None) => Some(old),
            (None, Some(new)) => Some(new),
            (None, None) => None,
        };
        if fallback.is_some() {
            finish_search_execution(selected, actual, upper)
        } else {
            finish_union_endpoint_execution(selected, actual, upper)
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the monotone endpoint proof, earliest-end cutoff, and certified fallback remain adjacent"
    )]
    fn execute_union_endpoint_search(
        &self,
        haystack: &[u8],
        window: Window,
        projection: SearchProjection,
        upper: ReduceUpperBounds,
        mut actual: ReduceActualCounters,
    ) -> Result<(Option<(usize, usize)>, ReduceActualCounters), SearchError> {
        debug_assert!(projection != SearchProjection::Selected);
        let mut cursor = window.start();
        let mut best = None::<(usize, usize)>;
        let mut unproductive_candidate_samples = 0_usize;
        loop {
            let ceiling = best.map_or(window.end(), |(_, end)| end);
            if cursor >= ceiling {
                return finish_union_endpoint_execution(best, actual, upper);
            }
            let candidate = match self.next_union_candidate(
                haystack,
                cursor,
                ceiling,
                window.end(),
                &mut actual,
            )? {
                UnionNext::Candidate(candidate) => candidate,
                UnionNext::Exhausted => {
                    return finish_union_endpoint_execution(best, actual, upper);
                }
                UnionNext::DenseFallback { resume_start } => {
                    return self.execute_union_endpoint_fallback(
                        haystack,
                        window,
                        projection,
                        upper,
                        resume_start,
                        best,
                        actual,
                    );
                }
            };
            let resume_start = candidate.start.checked_add(1).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "literal-union endpoint overlapping progress",
                },
            )?;
            let proved = self.prove_union_endpoint_candidate(
                haystack,
                window,
                candidate,
                &mut actual,
            )?;
            if let Some(matched) = proved {
                if projection == SearchProjection::Exists {
                    return finish_union_endpoint_execution(Some(matched), actual, upper);
                }
                best = Some(best.map_or(matched, |old| {
                    if (matched.1, matched.0) < (old.1, old.0) {
                        matched
                    } else {
                        old
                    }
                }));
                unproductive_candidate_samples = 0;
                cursor = resume_start;
                continue;
            }

            unproductive_candidate_samples = checked_add_reduce(
                unproductive_candidate_samples,
                1,
                "literal-union endpoint unproductive candidate samples",
            )?;
            if unproductive_candidate_samples
                < UNION_PROVED_RUN_SAMPLES_BEFORE_FALLBACK
            {
                cursor = resume_start;
                continue;
            }
            actual.union_fallbacks = checked_add_reduce(
                actual.union_fallbacks,
                1,
                "literal-union endpoint proof fallbacks",
            )?;
            actual.work = checked_add_reduce(
                actual.work,
                UNION_FALLBACK_WORK,
                "literal-union endpoint proof fallback work",
            )?;
            return self.execute_union_endpoint_fallback(
                haystack,
                window,
                projection,
                upper,
                resume_start,
                best,
                actual,
            );
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "adaptive union search, shortest semantics, and certified fallback remain adjacent"
    )]
    fn execute_union_search(
        &self,
        haystack: &[u8],
        window: Window,
        projection: SearchProjection,
        upper: ReduceUpperBounds,
        mut actual: ReduceActualCounters,
    ) -> Result<(Option<(usize, usize)>, ReduceActualCounters), SearchError> {
        let mut cursor = window.start();
        let mut unproductive_run_samples = 0_usize;
        loop {
            let candidate = match self.next_union_candidate(
                haystack,
                cursor,
                window.end(),
                window.end(),
                &mut actual,
            )? {
                UnionNext::Candidate(candidate) => candidate,
                UnionNext::Exhausted => {
                    return finish_search_execution(None, actual, upper);
                }
                UnionNext::DenseFallback { resume_start } => {
                    return self.execute_independent_search_from(
                        haystack,
                        window,
                        projection,
                        upper,
                        resume_start,
                        actual,
                    );
                }
            };
            let candidate_index = usize::try_from(candidate.matching_mask.trailing_zeros())
                .map_err(|_| ReduceError::ArithmeticOverflow {
                    computation: "search literal-union first matching index",
                })?;
            let candidate_finder = self.finders.get(candidate_index).ok_or(
                ReduceError::AccountingInvariant {
                    resource: "search literal-union matching finder",
                    actual: u64::try_from(candidate_index).unwrap_or(u64::MAX),
                    upper: u64::try_from(self.finders.len()).unwrap_or(u64::MAX),
                },
            )?;
            let candidate_end = candidate
                .start
                .checked_add(candidate_finder.needle().len())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "search literal-union candidate end",
                })?;
            let run_start =
                self.scan_run_backward(haystack, window.start(), candidate.start, &mut actual)?;
            let run_end =
                self.scan_run_forward(haystack, candidate_end, window.end(), &mut actual)?;
            actual.run_events = checked_add_reduce(
                actual.run_events,
                1,
                "search literal-union candidate run count",
            )?;
            actual.work = checked_add_reduce(
                actual.work,
                RUN_WORK,
                "search literal-union candidate run work",
            )?;

            let mut accepting_end = None::<usize>;
            if projection != SearchProjection::EarliestEnd {
                let mut strict_mask = candidate.matching_mask;
                while strict_mask != 0 {
                    let shift = strict_mask.trailing_zeros();
                    let index = usize::try_from(shift).map_err(|_| {
                        ReduceError::ArithmeticOverflow {
                            computation: "search literal-union strict candidate index",
                        }
                    })?;
                    let bit = 1_u16.checked_shl(shift).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "search literal-union strict mask bit",
                        },
                    )?;
                    strict_mask &= !bit;
                    let finder = self.finders.get(index).ok_or(
                        ReduceError::AccountingInvariant {
                            resource: "search literal-union strict candidate finder",
                            actual: u64::try_from(index).unwrap_or(u64::MAX),
                            upper: u64::try_from(self.finders.len()).unwrap_or(u64::MAX),
                        },
                    )?;
                    let end = candidate.start.checked_add(finder.needle().len()).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "search literal-union strict candidate end",
                        },
                    )?;
                    if candidate.start > run_start && end < run_end {
                        accepting_end = Some(run_end);
                        break;
                    }
                }
            }

            let interior_start = run_start.checked_add(1).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "search literal-union strict run interior start",
                },
            )?;
            if accepting_end.is_none() && interior_start < run_end {
                for finder in &self.finders {
                    let Some((_, literal_end)) = find_strict_inner_candidate(
                        finder,
                        haystack,
                        interior_start,
                        run_end,
                        &mut actual,
                    )?
                    else {
                        continue;
                    };
                    if literal_end >= run_end {
                        continue;
                    }
                    if projection != SearchProjection::EarliestEnd {
                        accepting_end = Some(run_end);
                        break;
                    }
                    let following = haystack.get(literal_end..run_end).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "search literal-union shortest following scalar window",
                        },
                    )?;
                    let decoded = decode_scalar(following);
                    charge_decode(decoded.byte_checks, &mut actual)?;
                    if decoded.scalar.is_none() || decoded.width == 0 {
                        return Err(ReduceError::AccountingInvariant {
                            resource: "search literal-union shortest following class scalar",
                            actual: 0,
                            upper: 1,
                        });
                    }
                    let end = literal_end.checked_add(decoded.width).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "search literal-union shortest accepting end",
                        },
                    )?;
                    accepting_end = Some(accepting_end.map_or(end, |old| old.min(end)));
                }
            }

            if let Some(end) = accepting_end {
                actual.match_events = checked_add_reduce(
                    actual.match_events,
                    1,
                    "search literal-union match event count",
                )?;
                actual.count = 1;
                actual.work = checked_add_reduce(
                    actual.work,
                    MATCH_WORK,
                    "search literal-union match work",
                )?;
                return finish_search_execution(Some((run_start, end)), actual, upper);
            }
            unproductive_run_samples = checked_add_reduce(
                unproductive_run_samples,
                1,
                "search literal-union unproductive run samples",
            )?;
            if unproductive_run_samples < UNION_PROVED_RUN_SAMPLES_BEFORE_FALLBACK {
                cursor = run_end;
                continue;
            }
            actual.union_fallbacks = checked_add_reduce(
                actual.union_fallbacks,
                1,
                "search literal-union proved-run fallbacks",
            )?;
            actual.work = checked_add_reduce(
                actual.work,
                UNION_FALLBACK_WORK,
                "search literal-union proved-run fallback work",
            )?;
            return self.execute_independent_search_from(
                haystack,
                window,
                projection,
                upper,
                run_end,
                actual,
            );
        }
    }

    fn execute_independent_search_from(
        &self,
        haystack: &[u8],
        window: Window,
        projection: SearchProjection,
        upper: ReduceUpperBounds,
        resume_start: usize,
        mut actual: ReduceActualCounters,
    ) -> Result<(Option<(usize, usize)>, ReduceActualCounters), SearchError> {
        let mut cursors = [resume_start; MAX_LITERALS];
        let mut cached = [None::<usize>; MAX_LITERALS];
        let mut exhausted = [false; MAX_LITERALS];

        loop {
            for (index, finder) in self.finders.iter().enumerate() {
                if cached[index].is_some() || exhausted[index] {
                    continue;
                }
                let cursor = cursors[index].max(window.start());
                let remaining = window.end().checked_sub(cursor).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "search outer finder remaining bytes",
                    },
                )?;
                if remaining < finder.needle().len() {
                    exhausted[index] = true;
                    continue;
                }
                let search = haystack.get(cursor..window.end()).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "search outer finder window",
                    },
                )?;
                let relative = find_and_charge(finder, search, false, &mut actual)?;
                if let Some(relative) = relative {
                    let absolute = cursor.checked_add(relative).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "search outer candidate offset",
                        },
                    )?;
                    cached[index] = Some(absolute);
                    cursors[index] = absolute.checked_add(1).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "search overlapping outer progress",
                        },
                    )?;
                    actual.outer_candidates = checked_add_reduce(
                        actual.outer_candidates,
                        1,
                        "search outer candidate count",
                    )?;
                } else {
                    exhausted[index] = true;
                }
            }

            let Some((candidate_index, candidate_start)) = cached
                .iter()
                .take(self.finders.len())
                .enumerate()
                .filter_map(|(index, candidate)| candidate.map(|start| (index, start)))
                .min_by_key(|&(index, start)| (start, index))
            else {
                return finish_search_execution(None, actual, upper);
            };
            let candidate_end = candidate_start
                .checked_add(self.finders[candidate_index].needle().len())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "search candidate literal end",
                })?;
            let run_start =
                self.scan_run_backward(haystack, window.start(), candidate_start, &mut actual)?;
            let run_end =
                self.scan_run_forward(haystack, candidate_end, window.end(), &mut actual)?;
            actual.run_events =
                checked_add_reduce(actual.run_events, 1, "search candidate run count")?;
            actual.work = checked_add_reduce(actual.work, RUN_WORK, "search candidate run work")?;

            let interior_start =
                run_start
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "search strict run interior start",
                    })?;
            let mut accepting_end = None::<usize>;
            if projection != SearchProjection::EarliestEnd
                && candidate_start > run_start
                && candidate_end < run_end
            {
                // The globally earliest retained occurrence is already
                // strict interior. Run recovery proves both required class
                // scalars, so selected-span/existence search needs no second
                // literal scan. Earliest-end still compares every literal.
                accepting_end = Some(run_end);
            } else if interior_start < run_end {
                for finder in &self.finders {
                    let remaining = run_end.checked_sub(interior_start).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "search strict run interior bytes",
                        },
                    )?;
                    if remaining < finder.needle().len() {
                        continue;
                    }
                    let search = haystack.get(interior_start..run_end).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "search strict interior finder window",
                        },
                    )?;
                    if let Some(relative) = find_and_charge(finder, search, true, &mut actual)? {
                        actual.inner_candidates = checked_add_reduce(
                            actual.inner_candidates,
                            1,
                            "search inner literal candidate count",
                        )?;
                        let start = interior_start.checked_add(relative).ok_or(
                            ReduceError::ArithmeticOverflow {
                                computation: "search inner literal start",
                            },
                        )?;
                        let literal_end = start.checked_add(finder.needle().len()).ok_or(
                            ReduceError::ArithmeticOverflow {
                                computation: "search inner literal end",
                            },
                        )?;
                        if literal_end < run_end {
                            if projection != SearchProjection::EarliestEnd {
                                accepting_end = Some(run_end);
                                break;
                            }
                            let following = haystack.get(literal_end..run_end).ok_or(
                                ReduceError::ArithmeticOverflow {
                                    computation: "shortest following scalar window",
                                },
                            )?;
                            let decoded = decode_scalar(following);
                            charge_decode(decoded.byte_checks, &mut actual)?;
                            if decoded.scalar.is_none() || decoded.width == 0 {
                                return Err(ReduceError::AccountingInvariant {
                                    resource: "shortest following class scalar",
                                    actual: 0,
                                    upper: 1,
                                });
                            }
                            let end = literal_end.checked_add(decoded.width).ok_or(
                                ReduceError::ArithmeticOverflow {
                                    computation: "shortest accepting end",
                                },
                            )?;
                            accepting_end = Some(accepting_end.map_or(end, |old| old.min(end)));
                        }
                    }
                }
            }

            if let Some(end) = accepting_end {
                actual.match_events =
                    checked_add_reduce(actual.match_events, 1, "search match event count")?;
                actual.count = 1;
                actual.work = checked_add_reduce(actual.work, MATCH_WORK, "search match work")?;
                return finish_search_execution(Some((run_start, end)), actual, upper);
            }

            for index in 0..self.finders.len() {
                let discarded = cached[index].is_some_and(|start| start < run_end);
                if discarded {
                    cached[index] = None;
                }
                cursors[index] = cursors[index].max(run_end);
                if discarded && cursors[index] < window.end() {
                    exhausted[index] = false;
                }
            }
        }
    }

    fn scan_run_backward(
        &self,
        haystack: &[u8],
        floor: usize,
        mut end: usize,
        actual: &mut ReduceActualCounters,
    ) -> Result<usize, ReduceError> {
        while end > floor {
            let decoded = decode_previous_scalar(haystack, floor, end)?;
            charge_decode(decoded.byte_checks, actual)?;
            let Some(scalar) = decoded.scalar else {
                break;
            };
            if !self.contains(scalar, actual)? {
                break;
            }
            end = end
                .checked_sub(decoded.width)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "reverse scalar progress",
                })?;
        }
        Ok(end)
    }

    fn scan_run_forward(
        &self,
        haystack: &[u8],
        mut start: usize,
        ceiling: usize,
        actual: &mut ReduceActualCounters,
    ) -> Result<usize, ReduceError> {
        while start < ceiling {
            let bytes = haystack
                .get(start..ceiling)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "forward scalar decode window",
                })?;
            let decoded = decode_scalar(bytes);
            charge_decode(decoded.byte_checks, actual)?;
            let Some(scalar) = decoded.scalar else {
                break;
            };
            if !self.contains(scalar, actual)? {
                break;
            }
            start = start
                .checked_add(decoded.width)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "forward scalar progress",
                })?;
        }
        Ok(start)
    }

    fn contains(
        &self,
        scalar: u32,
        actual: &mut ReduceActualCounters,
    ) -> Result<bool, ReduceError> {
        actual.membership_tests =
            checked_add_reduce(actual.membership_tests, 1, "membership tests")?;
        actual.work = checked_add_reduce(actual.work, MEMBERSHIP_WORK, "membership work")?;
        if scalar <= 0x7F {
            actual.range_comparisons =
                checked_add_reduce(actual.range_comparisons, 1, "ASCII membership comparison")?;
            return Ok(ascii_contains(
                self.ascii,
                u8::try_from(scalar).map_err(|_| ReduceError::ArithmeticOverflow {
                    computation: "ASCII scalar conversion",
                })?,
            ));
        }
        let mut low = 0_usize;
        let mut high = self.non_ascii.len();
        while low < high {
            actual.range_comparisons =
                checked_add_reduce(actual.range_comparisons, 1, "range comparisons")?;
            let middle = low + (high - low) / 2;
            let range = self.non_ascii[middle];
            if scalar < range.start {
                high = middle;
            } else if scalar > range.end {
                low = middle
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "range binary-search progress",
                    })?;
            } else {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[derive(Clone, Copy)]
enum BuildResource {
    SourceRanges,
    Work,
    Scratch,
    Persistent,
    Peak,
}

fn enforce_build(needed: usize, limit: usize, resource: BuildResource) -> Result<(), BuildError> {
    if needed <= limit {
        return Ok(());
    }
    Err(match resource {
        BuildResource::SourceRanges => BuildError::SourceRangesLimit { needed, limit },
        BuildResource::Work => BuildError::WorkLimit { needed, limit },
        BuildResource::Scratch => BuildError::ScratchLimit { needed, limit },
        BuildResource::Persistent => BuildError::PersistentLimit { needed, limit },
        BuildResource::Peak => BuildError::PeakLimit { needed, limit },
    })
}

#[derive(Clone, Copy)]
enum ReduceResource {
    InputBytes,
    UnionScanCalls,
    UnionClassifications,
    UnionRootCandidates,
    UnionVerificationBytes,
    UnionExactCandidates,
    UnionFallbacks,
    FinderCalls,
    FinderScannedBytes,
    DecodeByteChecks,
    MembershipTests,
    RangeComparisons,
    RunEvents,
    MatchEvents,
    Work,
    Scratch,
    Peak,
}

fn enforce_reduce(
    needed: usize,
    limit: usize,
    resource: ReduceResource,
) -> Result<(), ReduceError> {
    if needed <= limit {
        return Ok(());
    }
    Err(match resource {
        ReduceResource::InputBytes => ReduceError::InputBytesLimit { needed, limit },
        ReduceResource::UnionScanCalls => ReduceError::UnionScanCallsLimit { needed, limit },
        ReduceResource::UnionClassifications => {
            ReduceError::UnionClassificationsLimit { needed, limit }
        }
        ReduceResource::UnionRootCandidates => {
            ReduceError::UnionRootCandidatesLimit { needed, limit }
        }
        ReduceResource::UnionVerificationBytes => {
            ReduceError::UnionVerificationBytesLimit { needed, limit }
        }
        ReduceResource::UnionExactCandidates => {
            ReduceError::UnionExactCandidatesLimit { needed, limit }
        }
        ReduceResource::UnionFallbacks => ReduceError::UnionFallbacksLimit { needed, limit },
        ReduceResource::FinderCalls => ReduceError::FinderCallsLimit { needed, limit },
        ReduceResource::FinderScannedBytes => {
            ReduceError::FinderScannedBytesLimit { needed, limit }
        }
        ReduceResource::DecodeByteChecks => ReduceError::DecodeByteChecksLimit { needed, limit },
        ReduceResource::MembershipTests => ReduceError::MembershipTestsLimit { needed, limit },
        ReduceResource::RangeComparisons => ReduceError::RangeComparisonsLimit { needed, limit },
        ReduceResource::RunEvents => ReduceError::RunEventsLimit { needed, limit },
        ReduceResource::MatchEvents => ReduceError::MatchEventsLimit { needed, limit },
        ReduceResource::Work => ReduceError::WorkLimit { needed, limit },
        ReduceResource::Scratch => ReduceError::ScratchLimit { needed, limit },
        ReduceResource::Peak => ReduceError::PeakLimit { needed, limit },
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "the source-free proof keeps every named resource term in one auditable derivation"
)]
fn derive_upper_bounds(
    build: BuildAccounting,
    finders: &[Finder<'static>],
    input_bytes: usize,
) -> Result<ReduceUpperBounds, ReduceError> {
    let (
        union_scan_calls,
        union_classifications,
        union_root_candidates,
        union_verification_bytes,
        union_exact_candidates,
        union_fallbacks,
        union_work,
    ) = if build.adaptive_union {
        let calls = input_bytes
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "literal-union scan calls",
            })?;
        let classifications = calls
            .checked_mul(ASCII_NONMEMBER_RUN_MAX_CLASSIFICATION_OVERHEAD)
            .and_then(|overhead| input_bytes.checked_add(overhead))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "literal-union classifications",
            })?;
        let verification_bytes = input_bytes.checked_mul(build.literal_bytes).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "literal-union verification bytes",
            },
        )?;
        let literal_checks = input_bytes.checked_mul(build.literal_count).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "literal-union literal checks",
            },
        )?;
        let work = classifications
            .checked_add(verification_bytes)
            .and_then(|value| {
                value.checked_add(literal_checks.checked_mul(UNION_LITERAL_CHECK_WORK)?)
            })
            .and_then(|value| {
                value.checked_add(
                    input_bytes.checked_mul(UNION_ROOT_CANDIDATE_WORK)?,
                )
            })
            .and_then(|value| {
                value.checked_add(
                    input_bytes.checked_mul(UNION_EXACT_CANDIDATE_WORK)?,
                )
            })
            .and_then(|value| value.checked_add(UNION_FALLBACK_WORK))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "literal-union work",
            })?;
        (
            calls,
            classifications,
            input_bytes,
            verification_bytes,
            input_bytes,
            1,
            work,
        )
    } else {
        (0, 0, 0, 0, 0, 0, 0)
    };
    let mut literal_occurrence_positions = 0_usize;
    let mut outer_finder_calls = 0_usize;
    let mut outer_finder_scanned_bytes = 0_usize;
    for finder in finders {
        let literal_bytes = finder.needle().len();
        let positions = input_bytes
            .checked_sub(literal_bytes)
            .map_or(0, |remaining| remaining.saturating_add(1));
        literal_occurrence_positions = checked_add_reduce(
            literal_occurrence_positions,
            positions,
            "literal occurrence positions",
        )?;
        outer_finder_calls = checked_add_reduce(
            outer_finder_calls,
            positions.saturating_add(1),
            "outer finder calls",
        )?;
        let overlap_service = positions
            .checked_mul(literal_bytes.saturating_sub(1))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "outer overlapping finder service",
            })?;
        outer_finder_scanned_bytes = outer_finder_scanned_bytes
            .checked_add(input_bytes)
            .and_then(|value| value.checked_add(overlap_service))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "outer finder scanned bytes",
            })?;
    }
    let run_events = literal_occurrence_positions.min(input_bytes);
    let inner_finder_calls =
        run_events
            .checked_mul(finders.len())
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "inner finder calls",
            })?;
    let finder_calls = outer_finder_calls.checked_add(inner_finder_calls).ok_or(
        ReduceError::ArithmeticOverflow {
            computation: "total finder calls",
        },
    )?;
    // Candidate maximal runs are disjoint. Each literal's strict-interior
    // searches therefore cover at most N bytes in total.
    let inner_finder_scanned_bytes =
        input_bytes
            .checked_mul(finders.len())
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "inner finder scanned bytes",
            })?;
    let finder_scanned_bytes = outer_finder_scanned_bytes
        .checked_add(inner_finder_scanned_bytes)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "total finder scanned bytes",
        })?;
    // Reverse decoding may inspect a lead/continuation sequence twice while
    // validating it. Eight byte checks per source byte safely covers both
    // directions, malformed prefixes, and the fixed literal holes.
    let decode_byte_checks =
        input_bytes
            .checked_mul(16)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "decode byte-check bound",
            })?;
    // A nonmember scalar can terminate candidate runs on both sides. Member
    // scalars belong to one disjoint run, so two tests per input byte is a
    // complete source-independent bound.
    let membership_tests = input_bytes
        .checked_mul(2)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "membership-test bound",
        })?;
    let comparisons_per_membership =
        binary_search_comparison_bound(build.retained_non_ascii_ranges).max(1);
    let range_comparisons = membership_tests
        .checked_mul(comparisons_per_membership)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "range-comparison bound",
        })?;
    let match_events = run_events;
    let count = u64::try_from(match_events).map_err(|_| ReduceError::ArithmeticOverflow {
        computation: "count upper bound as u64",
    })?;
    let span_sum = u64::try_from(input_bytes).map_err(|_| ReduceError::ArithmeticOverflow {
        computation: "span-sum upper bound as u64",
    })?;
    let work = REDUCE_FIXED_WORK
        .checked_add(union_work)
        .and_then(|value| value.checked_add(finder_scanned_bytes))
        .and_then(|value| value.checked_add(finder_calls.checked_mul(FINDER_CALL_WORK)?))
        .and_then(|value| value.checked_add(decode_byte_checks))
        .and_then(|value| value.checked_add(membership_tests.checked_mul(MEMBERSHIP_WORK)?))
        .and_then(|value| value.checked_add(range_comparisons))
        .and_then(|value| value.checked_add(run_events.checked_mul(RUN_WORK)?))
        .and_then(|value| value.checked_add(match_events.checked_mul(MATCH_WORK)?))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "total reduction work",
        })?;
    Ok(ReduceUpperBounds {
        input_bytes,
        union_scan_calls,
        union_classifications,
        union_root_candidates,
        union_verification_bytes,
        union_exact_candidates,
        union_fallbacks,
        literal_occurrence_positions,
        outer_finder_calls,
        inner_finder_calls,
        finder_calls,
        finder_scanned_bytes,
        decode_byte_checks,
        membership_tests,
        range_comparisons,
        run_events,
        match_events,
        count,
        span_sum,
        work,
        scratch_bytes: 0,
        persistent_bytes: build.persistent_bytes,
        peak_bytes: build.persistent_bytes,
    })
}

fn expand_union_endpoint_upper_bounds(
    upper: &mut ReduceUpperBounds,
    input_bytes: usize,
    retained_non_ascii_ranges: usize,
) -> Result<(), ReduceError> {
    // Every exact union root can inspect at most one previous scalar (eight
    // byte checks) and one following scalar (four byte checks). The complete
    // independent envelope remains available for a certified fallback, so
    // these endpoint probes are conservatively additive.
    let endpoint_decode_byte_checks = input_bytes.checked_mul(12).ok_or(
        ReduceError::ArithmeticOverflow {
            computation: "literal-union endpoint decode byte-check bound",
        },
    )?;
    let endpoint_membership_tests = input_bytes.checked_mul(2).ok_or(
        ReduceError::ArithmeticOverflow {
            computation: "literal-union endpoint membership-test bound",
        },
    )?;
    let comparisons_per_membership =
        binary_search_comparison_bound(retained_non_ascii_ranges).max(1);
    let endpoint_range_comparisons = endpoint_membership_tests
        .checked_mul(comparisons_per_membership)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "literal-union endpoint range-comparison bound",
        })?;
    let endpoint_work = endpoint_decode_byte_checks
        .checked_add(
            endpoint_membership_tests
                .checked_mul(MEMBERSHIP_WORK)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "literal-union endpoint membership work",
                })?,
        )
        .and_then(|value| value.checked_add(endpoint_range_comparisons))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "literal-union endpoint work",
        })?;

    upper.decode_byte_checks = checked_add_reduce(
        upper.decode_byte_checks,
        endpoint_decode_byte_checks,
        "search decode byte-check bound",
    )?;
    upper.membership_tests = checked_add_reduce(
        upper.membership_tests,
        endpoint_membership_tests,
        "search membership-test bound",
    )?;
    upper.range_comparisons = checked_add_reduce(
        upper.range_comparisons,
        endpoint_range_comparisons,
        "search range-comparison bound",
    )?;
    upper.work = checked_add_reduce(
        upper.work,
        endpoint_work,
        "search work bound",
    )?;
    Ok(())
}

fn find_strict_inner_candidate(
    finder: &Finder<'_>,
    haystack: &[u8],
    interior_start: usize,
    run_end: usize,
    actual: &mut ReduceActualCounters,
) -> Result<Option<(usize, usize)>, ReduceError> {
    let remaining = run_end.checked_sub(interior_start).ok_or(
        ReduceError::ArithmeticOverflow {
            computation: "strict run interior bytes",
        },
    )?;
    if remaining < finder.needle().len() {
        return Ok(None);
    }
    let search = haystack.get(interior_start..run_end).ok_or(
        ReduceError::ArithmeticOverflow {
            computation: "strict interior finder window",
        },
    )?;
    let Some(relative) = find_and_charge(finder, search, true, actual)? else {
        return Ok(None);
    };
    actual.inner_candidates = checked_add_reduce(
        actual.inner_candidates,
        1,
        "inner literal candidate count",
    )?;
    let start = interior_start.checked_add(relative).ok_or(
        ReduceError::ArithmeticOverflow {
            computation: "inner literal absolute start",
        },
    )?;
    let end = start.checked_add(finder.needle().len()).ok_or(
        ReduceError::ArithmeticOverflow {
            computation: "inner literal absolute end",
        },
    )?;
    Ok(Some((start, end)))
}

fn find_and_charge(
    finder: &Finder<'_>,
    search: &[u8],
    inner: bool,
    actual: &mut ReduceActualCounters,
) -> Result<Option<usize>, ReduceError> {
    if inner {
        actual.inner_finder_calls =
            checked_add_reduce(actual.inner_finder_calls, 1, "inner finder calls")?;
    } else {
        actual.outer_finder_calls =
            checked_add_reduce(actual.outer_finder_calls, 1, "outer finder calls")?;
    }
    actual.work = checked_add_reduce(actual.work, FINDER_CALL_WORK, "finder call work")?;
    let found = finder.find(search);
    let service =
        match found {
            Some(relative) => relative.checked_add(finder.needle().len()).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "successful finder service",
                },
            )?,
            None => search.len(),
        };
    actual.finder_scanned_bytes =
        checked_add_reduce(actual.finder_scanned_bytes, service, "finder scanned bytes")?;
    actual.work = checked_add_reduce(actual.work, service, "finder scanned work")?;
    Ok(found)
}

fn charge_decode(byte_checks: usize, actual: &mut ReduceActualCounters) -> Result<(), ReduceError> {
    actual.decode_byte_checks =
        checked_add_reduce(actual.decode_byte_checks, byte_checks, "decode byte checks")?;
    actual.work = checked_add_reduce(actual.work, byte_checks, "decode work")?;
    Ok(())
}

fn verify_actual(
    actual: ReduceActualCounters,
    upper: ReduceUpperBounds,
) -> Result<(), ReduceError> {
    verify("input bytes", actual.input_bytes, upper.input_bytes)?;
    verify(
        "literal-union scan calls",
        actual.union_scan_calls,
        upper.union_scan_calls,
    )?;
    verify(
        "literal-union classifications",
        actual.union_classifications,
        upper.union_classifications,
    )?;
    verify(
        "literal-union root candidates",
        actual.union_root_candidates,
        upper.union_root_candidates,
    )?;
    verify(
        "literal-union verification bytes",
        actual.union_verification_bytes,
        upper.union_verification_bytes,
    )?;
    verify(
        "literal-union exact candidates",
        actual.union_exact_candidates,
        upper.union_exact_candidates,
    )?;
    verify(
        "literal-union fallbacks",
        actual.union_fallbacks,
        upper.union_fallbacks,
    )?;
    verify(
        "outer finder calls",
        actual.outer_finder_calls,
        upper.outer_finder_calls,
    )?;
    verify(
        "inner finder calls",
        actual.inner_finder_calls,
        upper.inner_finder_calls,
    )?;
    verify("finder calls", actual.finder_calls, upper.finder_calls)?;
    verify(
        "finder scanned bytes",
        actual.finder_scanned_bytes,
        upper.finder_scanned_bytes,
    )?;
    verify(
        "decode byte checks",
        actual.decode_byte_checks,
        upper.decode_byte_checks,
    )?;
    verify(
        "membership tests",
        actual.membership_tests,
        upper.membership_tests,
    )?;
    verify(
        "range comparisons",
        actual.range_comparisons,
        upper.range_comparisons,
    )?;
    verify("run events", actual.run_events, upper.run_events)?;
    verify("match events", actual.match_events, upper.match_events)?;
    verify("count", actual.count, upper.count)?;
    verify("span sum", actual.span_sum, upper.span_sum)?;
    verify("work", actual.work, upper.work)?;
    verify("scratch bytes", actual.scratch_bytes, upper.scratch_bytes)
}

fn finish_search_execution(
    matched: Option<(usize, usize)>,
    mut actual: ReduceActualCounters,
    upper: ReduceUpperBounds,
) -> Result<(Option<(usize, usize)>, ReduceActualCounters), SearchError> {
    actual.finder_calls = actual
        .outer_finder_calls
        .checked_add(actual.inner_finder_calls)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "search total finder calls",
        })?;
    verify_actual(actual, upper)?;
    Ok((matched, actual))
}

fn finish_union_endpoint_execution(
    matched: Option<(usize, usize)>,
    mut actual: ReduceActualCounters,
    upper: ReduceUpperBounds,
) -> Result<(Option<(usize, usize)>, ReduceActualCounters), SearchError> {
    if matched.is_some() {
        actual.match_events = checked_add_reduce(
            actual.match_events,
            1,
            "literal-union endpoint match event count",
        )?;
        actual.count = 1;
        actual.work = checked_add_reduce(
            actual.work,
            MATCH_WORK,
            "literal-union endpoint match work",
        )?;
    }
    finish_search_execution(matched, actual, upper)
}

fn verify<T>(resource: &'static str, actual: T, upper: T) -> Result<(), ReduceError>
where
    T: Copy + Ord + TryInto<u64>,
{
    if actual <= upper {
        return Ok(());
    }
    Err(ReduceError::AccountingInvariant {
        resource,
        actual: actual
            .try_into()
            .map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "actual accounting value as u64",
            })?,
        upper: upper
            .try_into()
            .map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "upper accounting value as u64",
            })?,
    })
}

fn record_allocation(
    actual: &mut DirectBuildAttemptActual,
    bytes: usize,
) -> Result<(), BuildError> {
    if bytes == 0 {
        return Ok(());
    }
    actual.allocations =
        actual
            .allocations
            .checked_add(1)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "actual allocation count",
            })?;
    actual.allocated_bytes =
        actual
            .allocated_bytes
            .checked_add(bytes)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "actual allocated bytes",
            })?;
    actual.live_persistent_bytes =
        actual
            .live_persistent_bytes
            .checked_add(bytes)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "actual live persistent bytes",
            })?;
    actual.peak_bytes = actual.peak_bytes.max(actual.live_persistent_bytes);
    Ok(())
}

fn record_initialization(
    actual: &mut DirectBuildAttemptActual,
    bytes: usize,
    copied: bool,
) -> Result<(), BuildError> {
    actual.initialized_bytes =
        actual
            .initialized_bytes
            .checked_add(bytes)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "actual initialized bytes",
            })?;
    if copied {
        actual.copied_bytes =
            actual
                .copied_bytes
                .checked_add(bytes)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "actual copied bytes",
                })?;
    }
    Ok(())
}

fn allocation_error(structure: &'static str, bytes: usize, _error: CopyError) -> BuildError {
    BuildError::AllocationFailed { structure, bytes }
}

fn insert_ascii_range(words: &mut [u64; 2], start: u32, end: u32) -> Result<(), BuildError> {
    let first = usize::try_from(start / 64).map_err(|_| BuildError::ArithmeticOverflow {
        computation: "ASCII range first word",
    })?;
    let last = usize::try_from(end / 64).map_err(|_| BuildError::ArithmeticOverflow {
        computation: "ASCII range last word",
    })?;
    for (word, target) in words
        .iter_mut()
        .enumerate()
        .take(last.saturating_add(1))
        .skip(first)
    {
        let low = if word == first { start & 63 } else { 0 };
        let high = if word == last { end & 63 } else { 63 };
        *target |= (u64::MAX << low) & (u64::MAX >> (63 - high));
    }
    Ok(())
}

fn ascii_contains(words: [u64; 2], byte: u8) -> bool {
    let word = usize::from(byte) >> 6;
    let bit = u32::from(byte) & 63;
    words[word] & (1_u64 << bit) != 0
}

fn valid_scalar_population(start: u32, end: u32) -> Result<usize, BuildError> {
    let population = end
        .checked_sub(start)
        .and_then(|width| width.checked_add(1))
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "Unicode range scalar population",
        })?;
    let surrogate_start = start.max(SURROGATE_START);
    let surrogate_end = end.min(SURROGATE_END);
    let surrogate_population = if surrogate_start <= surrogate_end {
        surrogate_end - surrogate_start + 1
    } else {
        0
    };
    let valid_population = population.checked_sub(surrogate_population).ok_or(
        BuildError::ArithmeticOverflow {
            computation: "Unicode range valid scalar population",
        },
    )?;
    usize::try_from(valid_population).map_err(|_| {
        BuildError::ArithmeticOverflow {
            computation: "Unicode range scalar population as usize",
        }
    })
}

fn checked_add_build(
    left: usize,
    right: usize,
    computation: &'static str,
) -> Result<usize, BuildError> {
    left.checked_add(right)
        .ok_or(BuildError::ArithmeticOverflow { computation })
}

fn checked_add_reduce(
    left: usize,
    right: usize,
    computation: &'static str,
) -> Result<usize, ReduceError> {
    left.checked_add(right)
        .ok_or(ReduceError::ArithmeticOverflow { computation })
}

const fn binary_search_comparison_bound(mut ranges: usize) -> usize {
    let mut comparisons = 0_usize;
    while ranges != 0 {
        comparisons = comparisons.saturating_add(1);
        ranges /= 2;
    }
    comparisons
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DecodedScalar {
    scalar: Option<u32>,
    width: usize,
    byte_checks: usize,
}

fn decode_previous_scalar(
    haystack: &[u8],
    floor: usize,
    end: usize,
) -> Result<DecodedScalar, ReduceError> {
    let last = end.checked_sub(1).ok_or(ReduceError::ArithmeticOverflow {
        computation: "previous scalar final byte",
    })?;
    let last_byte = *haystack.get(last).ok_or(ReduceError::ArithmeticOverflow {
        computation: "previous scalar final-byte read",
    })?;
    if last_byte <= 0x7F {
        return Ok(DecodedScalar {
            scalar: Some(u32::from(last_byte)),
            width: 1,
            byte_checks: 1,
        });
    }
    if !is_continuation(last_byte) {
        return Ok(invalid_scalar(1));
    }

    let minimum = end.saturating_sub(4).max(floor);
    let mut lead = last;
    let mut prefix_checks = 1_usize;
    while lead > minimum {
        lead = lead.checked_sub(1).ok_or(ReduceError::ArithmeticOverflow {
            computation: "previous scalar lead search",
        })?;
        prefix_checks = checked_add_reduce(prefix_checks, 1, "reverse lead byte checks")?;
        let byte = *haystack.get(lead).ok_or(ReduceError::ArithmeticOverflow {
            computation: "previous scalar lead-byte read",
        })?;
        if is_continuation(byte) {
            continue;
        }
        let bytes = haystack
            .get(lead..end)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "previous scalar candidate window",
            })?;
        let decoded = decode_scalar(bytes);
        let byte_checks = prefix_checks.checked_add(decoded.byte_checks).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "reverse scalar byte checks",
            },
        )?;
        if decoded.scalar.is_some() && decoded.width == bytes.len() {
            return Ok(DecodedScalar {
                byte_checks,
                ..decoded
            });
        }
        return Ok(invalid_scalar(byte_checks));
    }
    Ok(invalid_scalar(prefix_checks))
}

fn decode_scalar(bytes: &[u8]) -> DecodedScalar {
    let Some(&first) = bytes.first() else {
        return invalid_scalar(0);
    };
    if first <= 0x7F {
        return DecodedScalar {
            scalar: Some(u32::from(first)),
            width: 1,
            byte_checks: 1,
        };
    }
    if (0xC2..=0xDF).contains(&first) {
        let Some(&second) = bytes.get(1) else {
            return invalid_scalar(bytes.len().min(2));
        };
        if !is_continuation(second) {
            return invalid_scalar(2);
        }
        return DecodedScalar {
            scalar: Some((u32::from(first & 0x1F) << 6) | u32::from(second & 0x3F)),
            width: 2,
            byte_checks: 2,
        };
    }
    if (0xE0..=0xEF).contains(&first) {
        let Some(&second) = bytes.get(1) else {
            return invalid_scalar(bytes.len().min(3));
        };
        let second_ok = match first {
            0xE0 => (0xA0..=0xBF).contains(&second),
            0xED => (0x80..=0x9F).contains(&second),
            _ => is_continuation(second),
        };
        if !second_ok {
            return invalid_scalar(2);
        }
        let Some(&third) = bytes.get(2) else {
            return invalid_scalar(bytes.len().min(3));
        };
        if !is_continuation(third) {
            return invalid_scalar(3);
        }
        return DecodedScalar {
            scalar: Some(
                (u32::from(first & 0x0F) << 12)
                    | (u32::from(second & 0x3F) << 6)
                    | u32::from(third & 0x3F),
            ),
            width: 3,
            byte_checks: 3,
        };
    }
    if (0xF0..=0xF4).contains(&first) {
        let Some(&second) = bytes.get(1) else {
            return invalid_scalar(bytes.len().min(4));
        };
        let second_ok = match first {
            0xF0 => (0x90..=0xBF).contains(&second),
            0xF4 => (0x80..=0x8F).contains(&second),
            _ => is_continuation(second),
        };
        if !second_ok {
            return invalid_scalar(2);
        }
        let Some(&third) = bytes.get(2) else {
            return invalid_scalar(bytes.len().min(4));
        };
        if !is_continuation(third) {
            return invalid_scalar(3);
        }
        let Some(&fourth) = bytes.get(3) else {
            return invalid_scalar(bytes.len().min(4));
        };
        if !is_continuation(fourth) {
            return invalid_scalar(4);
        }
        return DecodedScalar {
            scalar: Some(
                (u32::from(first & 0x07) << 18)
                    | (u32::from(second & 0x3F) << 12)
                    | (u32::from(third & 0x3F) << 6)
                    | u32::from(fourth & 0x3F),
            ),
            width: 4,
            byte_checks: 4,
        };
    }
    invalid_scalar(1)
}

const fn invalid_scalar(byte_checks: usize) -> DecodedScalar {
    DecodedScalar {
        scalar: None,
        width: 1,
        byte_checks,
    }
}

const fn is_continuation(byte: u8) -> bool {
    byte & 0xC0 == 0x80
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use memchr::memmem::Finder;
    use regex::bytes::{Regex, RegexBuilder};

    use super::{
        ACCOUNTING_ID, BuildError, BuildLimits, COUNT_OPERATION_ID, EXISTS_OPERATION_ID,
        MAX_ADMITTED_NON_ASCII_SCALARS, PLAN_ID, ReduceError, ReduceLimits, ReverseInnerPlan,
        SEARCH_OPERATION_ID, SHORTEST_SEARCH_OPERATION_ID, SPAN_SUM_OPERATION_ID, SearchLimits,
        ScalarRange, UNION_ACCOUNTING_ID, UNION_PLAN_ID, UnionState,
    };
    use crate::{DirectBuildAttemptActual, Window};

    const ASCII_LETTERS: [(char, char); 2] = [('A', 'Z'), ('a', 'z')];
    const SMALL_CLASS: [(char, char); 2] = [('a', 'b'), ('λ', 'λ')];
    const SMALL_LITERALS: [&[u8]; 2] = [b"aa", b"b"];
    const SMALL_PATTERN: &str = r"(?:[abλ]+aa[abλ]+|[abλ]+b[abλ]+)";

    fn plan(ranges: &[(char, char)], literals: &[&[u8]]) -> ReverseInnerPlan {
        ReverseInnerPlan::build(ranges.iter().copied(), literals, BuildLimits::unlimited())
            .expect("eligible reverse-inner plan")
    }

    fn oracle(pattern: &str) -> Regex {
        RegexBuilder::new(pattern)
            .unicode(true)
            .build()
            .expect("oracle regex")
    }

    fn oracle_aggregates(regex: &Regex, haystack: &[u8]) -> (u64, u64) {
        regex
            .find_iter(haystack)
            .fold((0_u64, 0_u64), |(count, sum), matched| {
                (
                    count.checked_add(1).expect("small oracle count"),
                    sum.checked_add(
                        u64::try_from(matched.end() - matched.start()).expect("small oracle width"),
                    )
                    .expect("small oracle sum"),
                )
            })
    }

    fn assert_matches_oracle(plan: &ReverseInnerPlan, regex: &Regex, haystack: &[u8]) {
        let expected = oracle_aggregates(regex, haystack);
        let expected_find = regex
            .find(haystack)
            .map(|matched| (matched.start(), matched.end()));
        let expected_shortest = regex.shortest_match(haystack);
        let count = plan
            .count(haystack, ReduceLimits::unlimited())
            .expect("count reduction");
        let span_sum = plan
            .span_sum(haystack, ReduceLimits::unlimited())
            .expect("span-sum reduction");
        let (found, search) = plan
            .find(haystack, SearchLimits::unlimited())
            .expect("ordinary search");
        let (exists, exists_search) = plan
            .is_match(haystack, SearchLimits::unlimited())
            .expect("existence search");
        let (shortest, shortest_search) = plan
            .shortest(haystack, SearchLimits::unlimited())
            .expect("shortest search");
        assert_eq!(
            (count.count, span_sum.span_sum),
            expected,
            "haystack={haystack:?}"
        );
        assert_eq!(count.accounting.identity.operation_id, COUNT_OPERATION_ID);
        assert_eq!(
            span_sum.accounting.identity.operation_id,
            SPAN_SUM_OPERATION_ID
        );
        assert_eq!(found, expected_find, "find haystack={haystack:?}");
        assert_eq!(exists, expected_find.is_some(), "exists haystack={haystack:?}");
        assert_eq!(shortest, expected_shortest, "shortest haystack={haystack:?}");
        assert_eq!(search.identity.operation_id, SEARCH_OPERATION_ID);
        assert_eq!(exists_search.identity.operation_id, EXISTS_OPERATION_ID);
        assert_eq!(
            shortest_search.identity.operation_id,
            SHORTEST_SEARCH_OPERATION_ID
        );
    }

    #[test]
    fn overlap_complete_strict_interior_and_near_misses() {
        let plan = plan(&[('a', 'a')], &[b"aa"]);
        let regex = oracle(r"a+aaa+");
        for haystack in [
            b"".as_slice(),
            b"a",
            b"aa",
            b"aaa",
            b"aaaa",
            b"aaaaa",
            b"xaaaax",
            b"aaaxaaaa",
            b"aaaa\xffaaaa",
        ] {
            assert_matches_oracle(&plan, &regex, haystack);
        }
        let accepted = plan
            .span_sum(b"aaaa", ReduceLimits::unlimited())
            .expect("overlapping interior candidate");
        assert_eq!(accepted.span_sum, 4);
        assert_eq!(accepted.accounting.actual.match_events, 1);
    }

    #[test]
    fn factored_tom_shape_matches_maximal_letter_runs() {
        let plan = plan(&ASCII_LETTERS, &[b"herloc", b"olme"]);
        let regex = oracle(r"(?:[A-Za-z]+herloc[A-Za-z]+|[A-Za-z]+olme[A-Za-z]+)");
        for haystack in [
            b"sherlock holmes".as_slice(),
            b"herlocx xherloc xherlocy",
            b"olmes xolme xolmey",
            b"sherlock\xffholmes",
            b"--sherlock--holmes--",
            b"sherloc holme",
        ] {
            assert_matches_oracle(&plan, &regex, haystack);
        }
    }

    #[test]
    fn exhaustive_small_token_language_matches_regex_oracle() {
        fn visit(
            depth: usize,
            maximum: usize,
            tokens: &[&[u8]],
            haystack: &mut Vec<u8>,
            plan: &ReverseInnerPlan,
            regex: &Regex,
        ) {
            assert_matches_oracle(plan, regex, haystack);
            if depth == maximum {
                return;
            }
            for token in tokens {
                let old_len = haystack.len();
                haystack.extend_from_slice(token);
                visit(depth + 1, maximum, tokens, haystack, plan, regex);
                haystack.truncate(old_len);
            }
        }

        let plan = plan(&SMALL_CLASS, &SMALL_LITERALS);
        let regex = oracle(SMALL_PATTERN);
        let tokens: [&[u8]; 5] = [b"a", b"b", b"x", "λ".as_bytes(), b"\xff"];
        let mut haystack = Vec::new();
        visit(0, 6, &tokens, &mut haystack, &plan, &regex);
    }

    #[test]
    fn exhaustive_union_endpoint_languages_match_regex_oracle() {
        fn exercise(literals: &[&[u8]], pattern: &str) {
            fn visit(
                depth: usize,
                maximum: usize,
                tokens: &[&[u8]],
                haystack: &mut Vec<u8>,
                plan: &ReverseInnerPlan,
                regex: &Regex,
            ) {
                let expected_exists = regex.is_match(haystack);
                let expected_shortest = regex.shortest_match(haystack);
                let (exists, _) = plan
                    .is_match(haystack, SearchLimits::unlimited())
                    .expect("exhaustive endpoint existence");
                let (shortest, _) = plan
                    .shortest(haystack, SearchLimits::unlimited())
                    .expect("exhaustive endpoint shortest");
                assert_eq!(exists, expected_exists, "haystack={haystack:?}");
                assert_eq!(shortest, expected_shortest, "haystack={haystack:?}");
                if depth == maximum {
                    return;
                }
                for token in tokens {
                    let old_len = haystack.len();
                    haystack.extend_from_slice(token);
                    visit(depth + 1, maximum, tokens, haystack, plan, regex);
                    haystack.truncate(old_len);
                }
            }

            let ranges = [('a', 'd'), ('λ', 'λ')];
            let plan = plan(&ranges, literals);
            assert!(plan.build_accounting().adaptive_union);
            let regex = oracle(pattern);
            let tokens: [&[u8]; 8] = [
                b"a",
                b"b",
                b"c",
                b"d",
                "λ".as_bytes(),
                "β".as_bytes(),
                b"\xff",
                b"\x80",
            ];
            let mut haystack = Vec::new();
            visit(0, 4, &tokens, &mut haystack, &plan, &regex);
        }

        exercise(
            &[b"abc".as_slice(), b"b".as_slice()],
            r"(?:[a-dλ]+abc[a-dλ]+|[a-dλ]+b[a-dλ]+)",
        );
        exercise(
            &[b"a".as_slice(), b"bcd".as_slice()],
            r"(?:[a-dλ]+a[a-dλ]+|[a-dλ]+bcd[a-dλ]+)",
        );
        exercise(
            &[b"abc".as_slice(), b"ab".as_slice(), b"b".as_slice()],
            r"(?:[a-dλ]+abc[a-dλ]+|[a-dλ]+ab[a-dλ]+|[a-dλ]+b[a-dλ]+)",
        );
    }

    #[test]
    fn deterministic_random_bytes_match_regex_oracle() {
        let plan = plan(&SMALL_CLASS, &SMALL_LITERALS);
        let regex = oracle(SMALL_PATTERN);
        let tokens: [&[u8]; 8] = [
            b"a",
            b"b",
            b"x",
            b"-",
            "λ".as_bytes(),
            "β".as_bytes(),
            b"\xff",
            b"\x80",
        ];
        let mut state = 0x4d59_5df4_d0f3_3173_u64;
        for case in 0..4_096_usize {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let token_count = usize::try_from(state & 63).expect("small token count");
            let mut haystack = Vec::new();
            for _ in 0..token_count {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let index =
                    usize::try_from(state % u64::try_from(tokens.len()).expect("small token set"))
                        .expect("small token index");
                haystack.extend_from_slice(tokens[index]);
            }
            let expected = oracle_aggregates(&regex, &haystack);
            let count = plan
                .count(&haystack, ReduceLimits::unlimited())
                .unwrap_or_else(|error| panic!("case {case} count failed: {error:?}"));
            let sum = plan
                .span_sum(&haystack, ReduceLimits::unlimited())
                .unwrap_or_else(|error| panic!("case {case} sum failed: {error:?}"));
            assert_eq!(
                (count.count, sum.span_sum),
                expected,
                "case={case} haystack={haystack:?}"
            );
        }
    }

    #[test]
    fn byte_windows_include_split_utf8_and_invalid_boundaries() {
        let plan = plan(&SMALL_CLASS, &SMALL_LITERALS);
        let regex = oracle(SMALL_PATTERN);
        let haystack = b"\xff\x80\xce\xbbaab\xce\xbbxbaaab\xce\xbb\xff";
        for start in 0..=haystack.len() {
            for end in start..=haystack.len() {
                let expected = oracle_aggregates(&regex, &haystack[start..end]);
                let window = Window::new(start, end);
                let count = plan
                    .count_in(haystack, window, ReduceLimits::unlimited())
                    .expect("window count");
                let sum = plan
                    .span_sum_in(haystack, window, ReduceLimits::unlimited())
                    .expect("window span sum");
                let expected_find = regex
                    .find(&haystack[start..end])
                    .map(|matched| (start + matched.start(), start + matched.end()));
                let expected_shortest = regex
                    .shortest_match(&haystack[start..end])
                    .map(|matched_end| start + matched_end);
                let (found, _) = plan
                    .find_in(haystack, window, SearchLimits::unlimited())
                    .expect("window search");
                let (exists, _) = plan
                    .is_match_in(haystack, window, SearchLimits::unlimited())
                    .expect("window existence search");
                let (shortest, _) = plan
                    .shortest_in(haystack, window, SearchLimits::unlimited())
                    .expect("window shortest search");
                assert_eq!(
                    (count.count, sum.span_sum),
                    expected,
                    "window={start}..{end}"
                );
                assert_eq!(found, expected_find, "find window={start}..{end}");
                assert_eq!(exists, expected_find.is_some(), "exists window={start}..{end}");
                assert_eq!(
                    shortest, expected_shortest,
                    "shortest window={start}..{end}"
                );
            }
        }
        assert!(matches!(
            plan.count_in(
                haystack,
                Window::new(2, haystack.len() + 1),
                ReduceLimits::unlimited()
            ),
            Err(ReduceError::InvalidWindow { .. })
        ));
    }

    #[test]
    fn invalid_utf8_is_a_nonmember_barrier() {
        let ranges = [('A', 'Z'), ('a', 'z'), ('λ', 'λ')];
        let plan = plan(&ranges, &[b"herloc"]);
        let regex = oracle(r"[A-Za-zλ]+herloc[A-Za-zλ]+");
        for haystack in [
            b"\xffsherlock\x80".as_slice(),
            b"sher\xfflock",
            b"\xf0\x80\x80\x80sherlock",
            b"\xed\xa0\x80sherlock\xce\xbb",
            b"\xce\xbbsherlock\xce\xbb",
            b"\xce\x80sherlock",
            b"sherlock\xce",
        ] {
            assert_matches_oracle(&plan, &regex, haystack);
        }
    }

    #[test]
    fn search_is_plan_local_and_observes_same_address_mutation() {
        let aa = plan(&[('a', 'b')], &[b"aa"]);
        let bb = plan(&[('a', 'b')], &[b"bb"]);
        let mut haystack = b"xaaabx".to_vec();
        let address = haystack.as_ptr();

        let (aa_before, aa_receipt) = aa
            .find(&haystack, SearchLimits::unlimited())
            .expect("aa before mutation");
        let (bb_before, bb_receipt) = bb
            .find(&haystack, SearchLimits::unlimited())
            .expect("bb before mutation");
        assert_eq!(aa_before, Some((1, 5)));
        assert_eq!(bb_before, None);
        assert_ne!(
            aa_receipt.identity.literal_fingerprint,
            bb_receipt.identity.literal_fingerprint
        );

        haystack[1..5].copy_from_slice(b"abbb");
        assert_eq!(haystack.as_ptr(), address);
        let (aa_after, _) = aa
            .find(&haystack, SearchLimits::unlimited())
            .expect("aa after mutation");
        let (bb_after, _) = bb
            .find(&haystack, SearchLimits::unlimited())
            .expect("bb after mutation");
        assert_eq!(aa_after, None);
        assert_eq!(bb_after, Some((1, 5)));
    }

    #[test]
    fn build_receipt_exact_limits_and_one_below() {
        let literals: [&[u8]; 2] = [b"herloc", b"olme"];
        let baseline = ReverseInnerPlan::build_attempt(
            ASCII_LETTERS.iter().copied(),
            &literals,
            BuildLimits::unlimited(),
        )
        .expect("baseline build");
        let build = baseline.into_plan().build_accounting();
        let exact = BuildLimits {
            max_source_ranges: build.source_ranges,
            max_literals: build.literal_count,
            max_literal_bytes: 6,
            max_total_literal_bytes: build.literal_bytes,
            max_build_work: build.work,
            max_scratch_bytes: build.scratch_bytes,
            max_persistent_bytes: build.persistent_bytes,
            max_peak_bytes: build.peak_bytes,
        };
        let attempt =
            ReverseInnerPlan::build_attempt(ASCII_LETTERS.iter().copied(), &literals, exact)
                .expect("exact-limit build");
        let (plan, actual) = attempt.into_parts();
        assert_eq!(plan.build_accounting(), build);
        assert_eq!(actual.work, u64::try_from(build.work).unwrap());
        assert_eq!(actual.allocations, build.allocations);
        assert_eq!(actual.allocated_bytes, build.allocated_bytes);
        assert_eq!(actual.live_persistent_bytes, build.persistent_bytes);
        assert_eq!(actual.peak_bytes, build.peak_bytes);

        let work_error = ReverseInnerPlan::build_attempt(
            ASCII_LETTERS.iter().copied(),
            &literals,
            BuildLimits {
                max_build_work: build.work - 1,
                ..exact
            },
        )
        .expect_err("one-below work must fail");
        assert_eq!(
            work_error.source(),
            &BuildError::WorkLimit {
                needed: build.work,
                limit: build.work - 1
            }
        );
        assert_eq!(work_error.actual().work, u64::try_from(build.work).unwrap());
        assert_eq!(work_error.actual().allocations, 0);

        assert!(matches!(
            ReverseInnerPlan::build(
                ASCII_LETTERS.iter().copied(),
                &literals,
                BuildLimits {
                    max_persistent_bytes: build.persistent_bytes - 1,
                    ..exact
                }
            ),
            Err(BuildError::PersistentLimit { .. })
        ));
    }

    #[test]
    fn adaptive_union_build_receipt_exact_limits_and_atomic_one_below() {
        let baseline = ReverseInnerPlan::build_attempt(
            SMALL_CLASS.iter().copied(),
            &SMALL_LITERALS,
            BuildLimits::unlimited(),
        )
        .expect("baseline adaptive-union build");
        let build = baseline.into_plan().build_accounting();
        assert!(build.adaptive_union);
        assert_eq!(build.allocations, build.literal_count + 3);
        assert_eq!(build.scratch_bytes, 0);
        let expected_allocated_bytes = build
            .source_ranges
            .checked_mul(size_of::<ScalarRange>())
            .and_then(|bytes| {
                build
                    .literal_count
                    .checked_mul(size_of::<Finder<'static>>())
                    .and_then(|finder_bytes| bytes.checked_add(finder_bytes))
            })
            .and_then(|bytes| bytes.checked_add(build.literal_bytes))
            .and_then(|bytes| bytes.checked_add(size_of::<UnionState>()))
            .expect("small exact allocation receipt");
        assert_eq!(build.allocated_bytes, expected_allocated_bytes);
        let expected_copied_bytes = build
            .retained_non_ascii_ranges
            .checked_mul(size_of::<ScalarRange>())
            .and_then(|bytes| bytes.checked_add(build.literal_bytes))
            .expect("small exact copied-byte receipt");

        let exact = BuildLimits {
            max_source_ranges: build.source_ranges,
            max_literals: build.literal_count,
            max_literal_bytes: 2,
            max_total_literal_bytes: build.literal_bytes,
            max_build_work: build.work,
            max_scratch_bytes: build.scratch_bytes,
            max_persistent_bytes: build.persistent_bytes,
            max_peak_bytes: build.peak_bytes,
        };
        let attempt = ReverseInnerPlan::build_attempt(
            SMALL_CLASS.iter().copied(),
            &SMALL_LITERALS,
            exact,
        )
        .expect("exact adaptive-union build limits");
        let (plan, actual) = attempt.into_parts();
        assert_eq!(plan.build_accounting(), build);
        assert_eq!(actual.work, u64::try_from(build.work).unwrap());
        assert_eq!(actual.allocations, build.literal_count + 3);
        assert_eq!(actual.allocated_bytes, build.allocated_bytes);
        assert_eq!(actual.copied_bytes, expected_copied_bytes);
        assert_eq!(actual.live_persistent_bytes, build.persistent_bytes);
        assert_eq!(actual.peak_bytes, build.peak_bytes);

        let assert_preallocation_failure = |actual: DirectBuildAttemptActual| {
            assert_eq!(actual.work, u64::try_from(build.work).unwrap());
            assert_eq!(actual.allocations, 0);
            assert_eq!(actual.allocated_bytes, 0);
            assert_eq!(actual.copied_bytes, 0);
            assert_eq!(actual.initialized_bytes, 0);
            assert_eq!(actual.live_persistent_bytes, 0);
            assert_eq!(actual.peak_bytes, 0);
        };

        let work_error = ReverseInnerPlan::build_attempt(
            SMALL_CLASS.iter().copied(),
            &SMALL_LITERALS,
            BuildLimits {
                max_build_work: build.work - 1,
                ..exact
            },
        )
        .expect_err("one-below adaptive-union work must fail");
        assert_eq!(
            work_error.source(),
            &BuildError::WorkLimit {
                needed: build.work,
                limit: build.work - 1,
            }
        );
        assert_preallocation_failure(work_error.actual());

        let persistent_error = ReverseInnerPlan::build_attempt(
            SMALL_CLASS.iter().copied(),
            &SMALL_LITERALS,
            BuildLimits {
                max_persistent_bytes: build.persistent_bytes - 1,
                ..exact
            },
        )
        .expect_err("one-below adaptive-union persistent bytes must fail");
        assert_eq!(
            persistent_error.source(),
            &BuildError::PersistentLimit {
                needed: build.persistent_bytes,
                limit: build.persistent_bytes - 1,
            }
        );
        assert_preallocation_failure(persistent_error.actual());

        let peak_error = ReverseInnerPlan::build_attempt(
            SMALL_CLASS.iter().copied(),
            &SMALL_LITERALS,
            BuildLimits {
                max_peak_bytes: build.peak_bytes - 1,
                ..exact
            },
        )
        .expect_err("one-below adaptive-union peak bytes must fail");
        assert_eq!(
            peak_error.source(),
            &BuildError::PeakLimit {
                needed: build.peak_bytes,
                limit: build.peak_bytes - 1,
            }
        );
        assert_preallocation_failure(peak_error.actual());
    }

    fn exact_reduce_limits(upper: super::ReduceUpperBounds) -> ReduceLimits {
        ReduceLimits {
            max_input_bytes: upper.input_bytes,
            max_union_scan_calls: upper.union_scan_calls,
            max_union_classifications: upper.union_classifications,
            max_union_root_candidates: upper.union_root_candidates,
            max_union_verification_bytes: upper.union_verification_bytes,
            max_union_exact_candidates: upper.union_exact_candidates,
            max_union_fallbacks: upper.union_fallbacks,
            max_finder_calls: upper.finder_calls,
            max_finder_scanned_bytes: upper.finder_scanned_bytes,
            max_decode_byte_checks: upper.decode_byte_checks,
            max_membership_tests: upper.membership_tests,
            max_range_comparisons: upper.range_comparisons,
            max_run_events: upper.run_events,
            max_match_events: upper.match_events,
            max_count: upper.count,
            max_span_sum: upper.span_sum,
            max_work: upper.work,
            max_scratch_bytes: upper.scratch_bytes,
            max_peak_bytes: upper.peak_bytes,
        }
    }

    #[test]
    fn reduce_receipt_exact_limits_and_one_below() {
        let plan = plan(&SMALL_CLASS, &SMALL_LITERALS);
        let haystack = b"\xff\xce\xbbaaab\xce\xbb-xbaaabx-\x80aaaa";
        let upper = plan
            .full_window_upper_bounds(haystack.len())
            .expect("full-window bounds");
        let exact = exact_reduce_limits(upper);
        let count = plan.count(haystack, exact).expect("exact-limit count");
        let sum = plan
            .span_sum(haystack, exact)
            .expect("exact-limit span sum");
        let expected = oracle_aggregates(&oracle(SMALL_PATTERN), haystack);
        assert_eq!((count.count, sum.span_sum), expected);
        assert_eq!(count.accounting.upper_bounds, upper);
        assert_eq!(sum.accounting.upper_bounds, upper);

        assert!(matches!(
            plan.count(
                haystack,
                ReduceLimits {
                    max_union_scan_calls: upper.union_scan_calls - 1,
                    ..exact
                }
            ),
            Err(ReduceError::UnionScanCallsLimit { .. })
        ));
        assert!(matches!(
            plan.count(
                haystack,
                ReduceLimits {
                    max_union_classifications: upper.union_classifications - 1,
                    ..exact
                }
            ),
            Err(ReduceError::UnionClassificationsLimit { .. })
        ));
        assert!(matches!(
            plan.count(
                haystack,
                ReduceLimits {
                    max_union_root_candidates: upper.union_root_candidates - 1,
                    ..exact
                }
            ),
            Err(ReduceError::UnionRootCandidatesLimit { .. })
        ));
        assert!(matches!(
            plan.count(
                haystack,
                ReduceLimits {
                    max_union_verification_bytes: upper.union_verification_bytes - 1,
                    ..exact
                }
            ),
            Err(ReduceError::UnionVerificationBytesLimit { .. })
        ));
        assert!(matches!(
            plan.count(
                haystack,
                ReduceLimits {
                    max_union_exact_candidates: upper.union_exact_candidates - 1,
                    ..exact
                }
            ),
            Err(ReduceError::UnionExactCandidatesLimit { .. })
        ));
        assert!(matches!(
            plan.count(
                haystack,
                ReduceLimits {
                    max_union_fallbacks: upper.union_fallbacks - 1,
                    ..exact
                }
            ),
            Err(ReduceError::UnionFallbacksLimit { .. })
        ));

        assert!(matches!(
            plan.count(
                haystack,
                ReduceLimits {
                    max_finder_calls: upper.finder_calls - 1,
                    ..exact
                }
            ),
            Err(ReduceError::FinderCallsLimit { .. })
        ));
        assert!(matches!(
            plan.span_sum(
                haystack,
                ReduceLimits {
                    max_work: upper.work - 1,
                    ..exact
                }
            ),
            Err(ReduceError::WorkLimit { .. })
        ));
    }

    #[test]
    fn union_endpoint_proof_skips_maximal_run_recovery_and_keeps_global_shortest() {
        let ranges = [('a', 'z'), ('λ', 'λ')];
        let literals: [&[u8]; 2] = [b"abcdef", b"b"];
        let plan = plan(&ranges, &literals);
        let regex = oracle(
            r"(?:[a-zλ]+abcdef[a-zλ]+|[a-zλ]+b[a-zλ]+)",
        );
        assert!(plan.build_accounting().adaptive_union);

        let mut haystack = Vec::new();
        for _ in 0..512 {
            haystack.extend_from_slice("λ".as_bytes());
        }
        let literal_start = haystack.len();
        haystack.extend_from_slice(b"abcdef");
        for _ in 0..512 {
            haystack.extend_from_slice("λ".as_bytes());
        }

        let (exists, exists_accounting) = plan
            .is_match(&haystack, SearchLimits::unlimited())
            .expect("endpoint existence");
        assert!(exists);
        assert_eq!(exists_accounting.actual.run_events, 0);
        assert_eq!(exists_accounting.actual.finder_calls, 0);

        let (shortest, shortest_accounting) = plan
            .shortest(&haystack, SearchLimits::unlimited())
            .expect("endpoint shortest");
        assert_eq!(shortest, regex.shortest_match(&haystack));
        assert_eq!(shortest, Some(literal_start + 3));
        assert_eq!(shortest_accounting.actual.run_events, 0);
        assert_eq!(shortest_accounting.actual.finder_calls, 0);
        assert_eq!(shortest_accounting.actual.union_exact_candidates, 2);

        let (found, selected_accounting) = plan
            .find(&haystack, SearchLimits::unlimited())
            .expect("selected maximal run");
        assert_eq!(found, Some((0, haystack.len())));
        assert_eq!(
            found,
            regex
                .find(&haystack)
                .map(|matched| (matched.start(), matched.end()))
        );
        assert!(selected_accounting.actual.run_events > 0);
        assert!(selected_accounting.actual.decode_byte_checks > 1_000);
    }

    #[test]
    fn union_endpoint_search_bounds_are_exact_affine_and_limit_checked() {
        let ranges = [('a', 'z'), ('λ', 'λ')];
        let literals: [&[u8]; 2] = [b"abcdef", b"b"];
        let plan = plan(&ranges, &literals);
        assert!(plan.build_accounting().adaptive_union);

        let mut work = [0_usize; 3];
        for (index, length) in [256_usize, 512, 1_024].into_iter().enumerate() {
            let haystack = vec![b'-'; length];
            let (exists, exists_accounting) = plan
                .is_match(&haystack, SearchLimits::unlimited())
                .expect("affine endpoint existence");
            let (shortest, shortest_accounting) = plan
                .shortest(&haystack, SearchLimits::unlimited())
                .expect("affine endpoint shortest");
            assert!(!exists);
            assert_eq!(shortest, None);
            assert_eq!(
                exists_accounting.upper_bounds,
                shortest_accounting.upper_bounds
            );
            let upper = exists_accounting.upper_bounds;
            assert_eq!(upper.decode_byte_checks, 28 * length);
            assert_eq!(upper.membership_tests, 4 * length);
            assert_eq!(upper.range_comparisons, 4 * length);
            assert_eq!(exists_accounting.actual.run_events, 0);
            assert_eq!(shortest_accounting.actual.run_events, 0);
            work[index] = upper.work;
        }
        let first_delta = work[1] - work[0];
        let second_delta = work[2] - work[1];
        assert_eq!(second_delta, 2 * first_delta);

        let haystack = vec![b'-'; 1_024];
        let (_, accounting) = plan
            .shortest(&haystack, SearchLimits::unlimited())
            .expect("endpoint bound receipt");
        let exact_work = u64::try_from(accounting.upper_bounds.work)
            .expect("endpoint work bound as u64");
        let exact = SearchLimits {
            max_work_upper_bound: exact_work,
            max_scratch_bytes: accounting.upper_bounds.scratch_bytes,
        };
        plan.shortest(&haystack, exact)
            .expect("exact endpoint search limits");
        assert!(matches!(
            plan.shortest(
                &haystack,
                SearchLimits {
                    max_work_upper_bound: exact_work - 1,
                    ..exact
                }
            ),
            Err(ReduceError::WorkLimit { .. })
        ));
    }

    #[test]
    fn sparse_mixed_multi_literal_plan_uses_union_and_certified_fallback() {
        let plan = plan(&SMALL_CLASS, &SMALL_LITERALS);
        let build = plan.build_accounting();
        assert!(build.adaptive_union);
        assert_eq!(build.distinct_literal_first_bytes, 2);
        assert_eq!(plan.count_identity().plan_id, UNION_PLAN_ID);
        assert_eq!(plan.count_identity().accounting_id, UNION_ACCOUNTING_ID);

        let absent = plan
            .count(b"xxxxxxxxxxxxxxxx", ReduceLimits::unlimited())
            .expect("union absent reduction");
        assert_eq!(absent.accounting.actual.union_scan_calls, 1);
        assert_eq!(absent.accounting.actual.union_fallbacks, 0);
        assert_eq!(absent.accounting.actual.outer_finder_calls, 0);

        let fallback = plan
            .count(b"axaxaxaxax", ReduceLimits::unlimited())
            .expect("certified dense-decoy fallback");
        assert_eq!(fallback.accounting.actual.union_fallbacks, 1);
        assert!(fallback.accounting.actual.outer_finder_calls > 0);

        let exact_decoys = plan
            .count(b"b-b-b-b-b", ReduceLimits::unlimited())
            .expect("certified exact-root decoy fallback");
        assert_eq!(exact_decoys.accounting.actual.union_fallbacks, 1);
        assert_eq!(exact_decoys.accounting.actual.union_exact_candidates, 2);
        assert!(exact_decoys.accounting.actual.outer_finder_calls > 0);
    }

    #[test]
    fn adaptive_union_admission_uses_exact_sparse_scalar_and_unique_root_boundaries() {
        let ascii_64 = plan(&[('\0', '?'), ('λ', 'λ')], &[b"0", b"1"]);
        assert_eq!(ascii_64.build_accounting().ascii_scalars, 64);
        assert_eq!(ascii_64.build_accounting().non_ascii_scalars, 1);
        assert!(ascii_64.build_accounting().adaptive_union);

        let ascii_65 = plan(&[('\0', '@'), ('λ', 'λ')], &[b"0", b"1"]);
        assert_eq!(ascii_65.build_accounting().ascii_scalars, 65);
        assert_eq!(ascii_65.build_accounting().non_ascii_scalars, 1);
        assert!(!ascii_65.build_accounting().adaptive_union);

        let no_non_ascii = plan(&[('\0', '?')], &[b"0", b"1"]);
        assert_eq!(no_non_ascii.build_accounting().non_ascii_scalars, 0);
        assert!(!no_non_ascii.build_accounting().adaptive_union);

        let exact_non_ascii_cap = plan(
            &[('a', 'b'), ('\u{10000}', '\u{53DDF}')],
            &[b"a", b"b"],
        );
        assert_eq!(
            exact_non_ascii_cap.build_accounting().non_ascii_scalars,
            MAX_ADMITTED_NON_ASCII_SCALARS
        );
        assert_eq!(
            exact_non_ascii_cap.build_accounting().class_scalars,
            exact_non_ascii_cap.build_accounting().ascii_scalars
                + exact_non_ascii_cap.build_accounting().non_ascii_scalars
        );
        assert!(exact_non_ascii_cap.build_accounting().adaptive_union);

        let one_over_non_ascii_cap = plan(
            &[('a', 'b'), ('\u{10000}', '\u{53DE0}')],
            &[b"a", b"b"],
        );
        assert_eq!(
            one_over_non_ascii_cap
                .build_accounting()
                .non_ascii_scalars,
            MAX_ADMITTED_NON_ASCII_SCALARS + 1
        );
        assert!(!one_over_non_ascii_cap.build_accounting().adaptive_union);

        let near_universal = plan(
            &[('\0', '?'), ('\u{80}', '\u{10FFFF}')],
            &[b"0", b"1"],
        );
        assert_eq!(near_universal.build_accounting().ascii_scalars, 64);
        assert_eq!(
            near_universal.build_accounting().non_ascii_scalars,
            1_111_936
        );
        assert_eq!(near_universal.build_accounting().class_scalars, 1_112_000);
        assert!(!near_universal.build_accounting().adaptive_union);

        let common_root = plan(&SMALL_CLASS, &[b"aa", b"ab"]);
        assert_eq!(common_root.build_accounting().distinct_literal_first_bytes, 1);
        assert!(!common_root.build_accounting().adaptive_union);
    }

    fn assert_all_operations_fallback_to_later_match(
        plan: &ReverseInnerPlan,
        haystack: &[u8],
        expected_span: (usize, usize),
        expected_shortest: usize,
    ) {
        let count = plan
            .count(haystack, ReduceLimits::unlimited())
            .expect("fallback count");
        assert_eq!(count.count, 1);
        assert!(count.accounting.actual.union_fallbacks > 0);
        let span = plan
            .span_sum(haystack, ReduceLimits::unlimited())
            .expect("fallback span sum");
        assert_eq!(
            span.span_sum,
            u64::try_from(expected_span.1 - expected_span.0).unwrap()
        );
        assert!(span.accounting.actual.union_fallbacks > 0);
        let (found, find_accounting) = plan
            .find(haystack, SearchLimits::unlimited())
            .expect("fallback find");
        assert_eq!(found, Some(expected_span));
        assert!(find_accounting.actual.union_fallbacks > 0);
        let (matched, exists_accounting) = plan
            .is_match(haystack, SearchLimits::unlimited())
            .expect("fallback existence");
        assert!(matched);
        assert!(exists_accounting.actual.union_fallbacks > 0);
        let (shortest, shortest_accounting) = plan
            .shortest(haystack, SearchLimits::unlimited())
            .expect("fallback shortest");
        assert_eq!(shortest, Some(expected_shortest));
        assert!(shortest_accounting.actual.union_fallbacks > 0);
    }

    #[test]
    fn false_root_fallback_preserves_later_viable_literal_in_same_run() {
        let plan = plan(&SMALL_CLASS, &SMALL_LITERALS);
        let count = plan
            .count(b"abbb", ReduceLimits::unlimited())
            .expect("false-root fallback count");
        assert_eq!(count.accounting.actual.union_root_candidates, 1);
        assert_eq!(count.accounting.actual.union_exact_candidates, 0);
        assert_eq!(count.accounting.actual.union_fallbacks, 1);
        assert_all_operations_fallback_to_later_match(&plan, b"abbb", (0, 4), 3);
    }

    #[test]
    fn two_unproductive_runs_fallback_preserves_later_viable_run() {
        let plan = plan(&SMALL_CLASS, &SMALL_LITERALS);
        let count = plan
            .count(b"b-b-abbb", ReduceLimits::unlimited())
            .expect("proved-run fallback count");
        assert_eq!(count.accounting.actual.union_exact_candidates, 2);
        assert_eq!(count.accounting.actual.union_fallbacks, 1);
        assert_all_operations_fallback_to_later_match(&plan, b"b-b-abbb", (4, 8), 7);
    }

    #[test]
    fn sixteen_way_common_root_uses_independent_finder_plan() {
        let literals: [&[u8]; 16] = [
            b"aa", b"ab", b"ac", b"ad", b"ae", b"af", b"ag", b"ah", b"ai", b"aj",
            b"ak", b"al", b"am", b"an", b"ao", b"ap",
        ];
        let plan = plan(&[('a', 'p'), ('λ', 'λ')], &literals);
        let build = plan.build_accounting();
        assert_eq!(build.literal_count, 16);
        assert_eq!(build.distinct_literal_first_bytes, 1);
        assert!(!build.adaptive_union);
        assert_eq!(plan.count_identity().plan_id, PLAN_ID);
        assert_eq!(plan.count_identity().accounting_id, ACCOUNTING_ID);
        let upper = plan.full_window_upper_bounds(256).expect("incumbent bounds");
        assert_eq!(upper.union_scan_calls, 0);
        assert_eq!(upper.union_root_candidates, 0);
        assert_eq!(upper.union_verification_bytes, 0);
    }

    #[test]
    fn union_calls_are_plan_local_and_observe_same_address_mutation() {
        let aa = plan(&SMALL_CLASS, &[b"aa", b"ba"]);
        let bb = plan(&SMALL_CLASS, &[b"bb", b"ab"]);
        let mut haystack = b"xaaabx".to_vec();
        let address = haystack.as_ptr();

        let (aa_before, aa_receipt) = aa
            .find(&haystack, SearchLimits::unlimited())
            .expect("aa union before mutation");
        let (bb_before, bb_receipt) = bb
            .find(&haystack, SearchLimits::unlimited())
            .expect("bb union before mutation");
        assert_eq!(aa_before, Some((1, 5)));
        assert_eq!(bb_before, None);
        assert_ne!(
            aa_receipt.identity.literal_fingerprint,
            bb_receipt.identity.literal_fingerprint
        );
        assert_eq!(aa_receipt.identity.plan_id, UNION_PLAN_ID);
        assert_eq!(bb_receipt.identity.plan_id, UNION_PLAN_ID);
        assert!(
            aa.is_match(&haystack, SearchLimits::unlimited())
                .expect("aa union endpoint before mutation")
                .0
        );
        assert_eq!(
            aa.shortest(&haystack, SearchLimits::unlimited())
                .expect("aa union shortest before mutation")
                .0,
            Some(5)
        );
        assert!(
            !bb.is_match(&haystack, SearchLimits::unlimited())
                .expect("bb union endpoint before mutation")
                .0
        );
        assert_eq!(
            bb.shortest(&haystack, SearchLimits::unlimited())
                .expect("bb union shortest before mutation")
                .0,
            None
        );

        haystack[1..5].copy_from_slice(b"abbb");
        assert_eq!(haystack.as_ptr(), address);
        assert_eq!(
            aa.find(&haystack, SearchLimits::unlimited())
                .expect("aa union after mutation")
                .0,
            None
        );
        assert_eq!(
            bb.find(&haystack, SearchLimits::unlimited())
                .expect("bb union after mutation")
                .0,
            Some((1, 5))
        );
        assert!(
            !aa.is_match(&haystack, SearchLimits::unlimited())
                .expect("aa union endpoint after mutation")
                .0
        );
        assert_eq!(
            aa.shortest(&haystack, SearchLimits::unlimited())
                .expect("aa union shortest after mutation")
                .0,
            None
        );
        assert!(
            bb.is_match(&haystack, SearchLimits::unlimited())
                .expect("bb union endpoint after mutation")
                .0
        );
        assert_eq!(
            bb.shortest(&haystack, SearchLimits::unlimited())
                .expect("bb union shortest after mutation")
                .0,
            Some(5)
        );
    }

    #[test]
    fn construction_refuses_unsound_shapes() {
        assert!(matches!(
            ReverseInnerPlan::build(
                core::iter::empty::<(char, char)>(),
                &[b"a"],
                BuildLimits::unlimited()
            ),
            Err(BuildError::EmptyClass)
        ));
        assert!(matches!(
            ReverseInnerPlan::build([('a', 'z')].into_iter(), &[], BuildLimits::unlimited()),
            Err(BuildError::EmptyLiteralSet)
        ));
        assert!(matches!(
            ReverseInnerPlan::build([('a', 'z')].into_iter(), &[b""], BuildLimits::unlimited()),
            Err(BuildError::EmptyLiteral { .. })
        ));
        assert!(matches!(
            ReverseInnerPlan::build(
                [('a', 'z')].into_iter(),
                &["λ".as_bytes()],
                BuildLimits::unlimited()
            ),
            Err(BuildError::NonAsciiLiteral { .. })
        ));
        assert!(matches!(
            ReverseInnerPlan::build([('a', 'z')].into_iter(), &[b"A"], BuildLimits::unlimited()),
            Err(BuildError::LiteralScalarOutsideClass { .. })
        ));
        assert!(matches!(
            ReverseInnerPlan::build(
                [('a', 'z'), ('z', 'λ')].into_iter(),
                &[b"a"],
                BuildLimits::unlimited()
            ),
            Err(BuildError::NonCanonicalRanges)
        ));
    }
}
